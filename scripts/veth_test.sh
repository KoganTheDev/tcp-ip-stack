#!/usr/bin/env bash
#
# Drives epoll-server over a real AF_PACKET socket, against a peer in its own
# network namespace connected by a veth pair.
#
# This is the integration test the unit suite cannot be: RawPacketChannel is all
# syscalls, so the only way to know it works is to run it against a real kernel.
# Unlike a LAN test it is repeatable, self-contained, and cannot disturb anything
# outside its own namespace - so run this before ever pointing the stack at a
# real network.
#
# veth is also a genuinely stricter test of one thing than a real NIC: it does no
# MAC filtering of its own, so every frame on the link is delivered and the
# stack's own L2 destination filter is what has to reject the irrelevant ones.
#
# Requires root (CAP_NET_RAW plus namespace and interface creation), and
# ip / ethtool / ping / nc. Run from anywhere:
#
#     sudo scripts/veth_test.sh
#
set -uo pipefail

NS=stacktest
HOST_IF=vstack0
PEER_IF=vstack1
PEER_IP=10.9.0.1
STACK_IP=10.9.0.2
PORT=8080
LOG=$(mktemp /tmp/veth_test_server.XXXXXX.log)
SERVER_PID=""

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$REPO_ROOT/epoll-server/epoll-server"

passes=0
failures=0

pass() { echo "  PASS  $1"; passes=$((passes + 1)); }
fail() { echo "  FAIL  $1"; failures=$((failures + 1)); }
check() { if [ "$1" = "0" ]; then pass "$2"; else fail "$2"; fi; }

cleanup()
{
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    # deleting the namespace takes the peer interface with it; deleting the host
    # side takes both halves of the pair if the namespace is already gone
    ip netns del "$NS" 2>/dev/null
    ip link del "$HOST_IF" 2>/dev/null
    rm -f "$LOG"
}
trap cleanup EXIT

# --- preflight -------------------------------------------------------------

if [ "$(id -u)" != "0" ]; then
    echo "This needs root: it creates a network namespace and a veth pair, and opens an AF_PACKET socket." >&2
    exit 1
fi

for tool in ip ethtool ping nc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        echo "On Debian/Ubuntu: apt-get install -y iproute2 ethtool iputils-ping netcat-openbsd" >&2
        exit 1
    fi
done

if [ ! -x "$SERVER" ]; then
    echo "Building epoll-server..."
    if ! make -C "$REPO_ROOT/epoll-server" >/dev/null; then
        echo "Build failed." >&2
        exit 1
    fi
fi

# --- set up the link -------------------------------------------------------

cleanup 2>/dev/null   # clear anything a previous interrupted run left behind
SERVER_PID=""

echo "Setting up $HOST_IF <-> $PEER_IF (peer $PEER_IP in namespace $NS, stack answers for $STACK_IP)"
ip netns add "$NS" || { echo "could not create namespace" >&2; exit 1; }
ip link add "$HOST_IF" type veth peer name "$PEER_IF" || { echo "could not create veth pair" >&2; exit 1; }
ip link set "$PEER_IF" netns "$NS"
ip link set "$HOST_IF" up
ip -n "$NS" link set "$PEER_IF" up
ip -n "$NS" addr add "$PEER_IP/24" dev "$PEER_IF"

# Disable checksum offload on BOTH ends. This is not optional and it is not
# papering over a stack bug.
#
# A veth pair never leaves the host, so the kernel skips computing transport
# checksums (the skb carries CHECKSUM_PARTIAL and the peer's stack is trusted to
# skip verifying them). Our stack does verify them, correctly, and so drops every
# TCP and UDP segment as corrupt. ICMP is not offloaded, which produces the
# giveaway symptom: ping works while TCP and UDP silently fail.
#
# Turning offload off makes the kernel put real checksums on the wire, which is
# what a physical NIC talking to another machine does anyway.
ethtool -K "$HOST_IF" tx off rx off >/dev/null 2>&1
ip netns exec "$NS" ethtool -K "$PEER_IF" tx off rx off >/dev/null 2>&1

HOST_MAC=$(ip -br link show "$HOST_IF" | awk '{print $3}')
echo "  $HOST_IF hardware address: $HOST_MAC"

# --- run -------------------------------------------------------------------

"$SERVER" --transport nic --device "$HOST_IF" --ip "$STACK_IP" --port "$PORT" >"$LOG" 2>&1 &
SERVER_PID=$!

# wait for it to report itself ready rather than sleeping a guessed interval
for _ in $(seq 1 50); do
    if grep -q "listening on TCP port" "$LOG" 2>/dev/null; then break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Server exited during startup:" >&2
        cat "$LOG" >&2
        exit 1
    fi
    sleep 0.1
done

if ! grep -q "listening on TCP port" "$LOG"; then
    echo "Server did not become ready:" >&2
    cat "$LOG" >&2
    exit 1
fi

echo
echo "Checks:"

grep -q "transport=nic device=$HOST_IF ip=$STACK_IP" "$LOG"
check $? "server started on $HOST_IF over AF_PACKET"

ip netns exec "$NS" ping -c 2 -W 2 "$STACK_IP" >/dev/null 2>&1
check $? "peer can ping the stack (our ICMP echo reply, not the kernel's)"

# The peer learned our MAC from our own ARP reply. It must be the interface's
# real hardware address - that is what lets the NIC filter for us and makes
# promiscuous mode unnecessary.
learned=$(ip netns exec "$NS" ip neigh show "$STACK_IP" | grep -o 'lladdr [0-9a-f:]*' | awk '{print $2}')
if [ "$learned" = "$HOST_MAC" ]; then
    pass "peer resolved $STACK_IP to the interface's real MAC ($learned)"
else
    fail "peer resolved $STACK_IP to '$learned', expected '$HOST_MAC'"
fi

echo -n "tcp-echo-probe" | timeout 10 ip netns exec "$NS" nc -q 1 "$STACK_IP" "$PORT" > /tmp/echo.out 2>/dev/null
if [ "$(cat /tmp/echo.out 2>/dev/null)" = "tcp-echo-probe" ]; then
    pass "TCP handshake, echo and close round-tripped exactly"
else
    fail "TCP echo returned '$(cat /tmp/echo.out 2>/dev/null)', expected 'tcp-echo-probe'"
fi
rm -f /tmp/echo.out

# A UDP datagram to a port nothing is bound to should draw ICMP port
# unreachable, and must not disturb the stack.
echo "x" | timeout 5 ip netns exec "$NS" nc -u -w 1 "$STACK_IP" 9999 >/dev/null 2>&1
ip netns exec "$NS" ping -c 1 -W 2 "$STACK_IP" >/dev/null 2>&1
check $? "stack still healthy after a UDP datagram to an unbound port"

if grep -q "bad checksum" "$LOG"; then
    fail "the log reports bad checksums - is checksum offload still enabled on the veth pair?"
else
    pass "no checksum rejections (offload is off, so real checksums are on the wire)"
fi

if ip -br link show "$HOST_IF" | grep -q PROMISC; then
    fail "$HOST_IF is in promiscuous mode - this stack must never need it"
else
    pass "no promiscuous mode on $HOST_IF"
fi

kill -0 "$SERVER_PID" 2>/dev/null
check $? "server survived the whole run"

echo
echo "$passes passed, $failures failed"
if [ "$failures" -ne 0 ]; then
    echo
    echo "Server log:"
    sed 's/^/  /' "$LOG"
    exit 1
fi
exit 0
