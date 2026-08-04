#!/usr/bin/env bash
#
# Drives this stack as a ROUTER between two networks that cannot otherwise
# reach each other.
#
#   namespace hostA            this stack (host)           namespace hostB
#   10.9.2.10/24  <--veth-->  10.9.2.1 | 10.9.3.1  <--veth-->  10.9.3.10/24
#                              vrtA0        vrtB0
#
# Neither namespace has a route to the other except through us, and the host
# kernel owns no address on either network - so every packet that crosses is
# one this stack forwarded itself. That is the whole point: it is not enough to
# show traffic arriving, it has to be traffic that could not have arrived any
# other way.
#
# What this proves that the unit tests cannot: a real Linux TCP stack at each
# end, real ICMP from a real traceroute, and a forwarding path that has to get
# the TTL, the checksum and the egress interface right or the kernel at the far
# end rejects it.
#
# Requires root (namespaces, veth, AF_PACKET) plus ip, ethtool, nc, traceroute.
#
#     sudo scripts/router_test.sh
#
set -uo pipefail

NS_A=rtrhostA
NS_B=rtrhostB
IF_A=vrtA0        # host end, on A's network
IF_B=vrtB0        # host end, on B's network
PEER_A=vrtA1      # inside NS_A
PEER_B=vrtB1      # inside NS_B

NET_A=10.9.2
NET_B=10.9.3
ROUTER_A=$NET_A.1     # this stack, on A's side
ROUTER_B=$NET_B.1     # this stack, on B's side
HOST_A=$NET_A.10
HOST_B=$NET_B.10
PORT=8080

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$REPO_ROOT/epoll-server/epoll-server"
LOG=$(mktemp /tmp/router_test.XXXXXX.log)
SERVER_PID=""

passes=0
failures=0
pass() { echo "  PASS  $1"; passes=$((passes + 1)); }
fail() { echo "  FAIL  $1"; failures=$((failures + 1)); }

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    ip netns del "$NS_A" 2>/dev/null
    ip netns del "$NS_B" 2>/dev/null
    ip link del "$IF_A" 2>/dev/null
    ip link del "$IF_B" 2>/dev/null
    rm -f "$LOG"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "This test needs root (namespaces, veth, AF_PACKET)." >&2
    exit 1
fi

for tool in ip ethtool nc; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        echo "On Debian/Ubuntu: apt-get install -y iproute2 ethtool netcat-openbsd" >&2
        exit 1
    fi
done

if [ ! -x "$SERVER" ]; then
    echo "Building epoll-server..."
    make -C "$REPO_ROOT/epoll-server" >/dev/null || { echo "Build failed." >&2; exit 1; }
fi

cleanup 2>/dev/null
SERVER_PID=""

echo "Setting up two segments either side of this stack:"
echo "  $HOST_A/24 (ns $NS_A) <-> $ROUTER_A [ stack ] $ROUTER_B <-> $HOST_B/24 (ns $NS_B)"

ip netns add "$NS_A" || { echo "could not create $NS_A" >&2; exit 1; }
ip netns add "$NS_B" || { echo "could not create $NS_B" >&2; exit 1; }
ip link add "$IF_A" type veth peer name "$PEER_A" || { echo "could not create veth A" >&2; exit 1; }
ip link add "$IF_B" type veth peer name "$PEER_B" || { echo "could not create veth B" >&2; exit 1; }
ip link set "$PEER_A" netns "$NS_A"
ip link set "$PEER_B" netns "$NS_B"

# Checksum offload off on every end. A veth pair never leaves the host, so the
# kernel skips computing transport checksums and this stack correctly rejects
# every segment as corrupt. Turning it off puts real checksums on the wire,
# which is what makes this a test of the checksum code rather than of nothing.
for pair in "$IF_A" "$IF_B"; do
    ethtool -K "$pair" tx off rx off >/dev/null 2>&1 || true
done
ip netns exec "$NS_A" ethtool -K "$PEER_A" tx off rx off >/dev/null 2>&1 || true
ip netns exec "$NS_B" ethtool -K "$PEER_B" tx off rx off >/dev/null 2>&1 || true

ip link set "$IF_A" up
ip link set "$IF_B" up

ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_A" ip link set "$PEER_A" up
ip netns exec "$NS_A" ip addr add "$HOST_A/24" dev "$PEER_A"
# A's only way to B is through us - and its only way to anywhere else, so a
# destination this router has no route for actually reaches us to be reported
# on. Without the default route A's own kernel would reject such an address
# locally and the unreachable test below would prove nothing about this stack.
ip netns exec "$NS_A" ip route add "$NET_B.0/24" via "$ROUTER_A"
ip netns exec "$NS_A" ip route add default via "$ROUTER_A"

ip netns exec "$NS_B" ip link set lo up
ip netns exec "$NS_B" ip link set "$PEER_B" up
ip netns exec "$NS_B" ip addr add "$HOST_B/24" dev "$PEER_B"
ip netns exec "$NS_B" ip route add "$NET_A.0/24" via "$ROUTER_B"

# The host kernel deliberately owns NO address on either network. If it did, it
# would answer the ARP and route the traffic itself, and this test would pass
# while proving nothing about the code under test.

echo
echo "Starting the stack in router mode..."
"$SERVER" --transport nic --device "$IF_A" --ip "$ROUTER_A" --prefix 24 \
          --second-device "$IF_B" --second-ip "$ROUTER_B" --second-prefix 24 \
          --port "$PORT" >"$LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
    if grep -q "listening on TCP port" "$LOG" 2>/dev/null; then break; fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Server exited during startup:" >&2
        cat "$LOG" >&2
        exit 1
    fi
    sleep 0.1
done

if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "Server is not running:" >&2; cat "$LOG" >&2; exit 1
fi

echo
echo "Checks:"

if grep -q "router mode" "$LOG"; then
    pass "started with two interfaces and forwarding enabled"
else
    fail "router mode was not reported at startup"
fi

# Each side can reach the router's own address on its own segment. This is the
# stack answering for itself, not forwarding - the baseline that tells a
# forwarding failure apart from a link that was never up.
if ip netns exec "$NS_A" ping -c1 -W2 "$ROUTER_A" >/dev/null 2>&1; then
    pass "host A can reach the router's address on its segment"
else
    fail "host A cannot reach $ROUTER_A"
fi
if ip netns exec "$NS_B" ping -c1 -W2 "$ROUTER_B" >/dev/null 2>&1; then
    pass "host B can reach the router's address on its segment"
else
    fail "host B cannot reach $ROUTER_B"
fi

# The real test: A reaching B. Nothing else on the machine can carry this.
if ip netns exec "$NS_A" ping -c2 -W2 "$HOST_B" >/dev/null 2>&1; then
    pass "host A can ping host B THROUGH this stack (ICMP forwarded both ways)"
else
    fail "host A cannot reach host B - forwarding is not working"
fi

if ip netns exec "$NS_B" ping -c2 -W2 "$HOST_A" >/dev/null 2>&1; then
    pass "and host B can ping host A, so forwarding works in both directions"
else
    fail "host B cannot reach host A"
fi

# A real Linux TCP stack at each end. The handshake, the data and the close all
# cross the forwarding path, and every segment has to arrive with its checksum
# intact or the far kernel discards it.
MESSAGE="forwarded-by-the-stack-$$"
ip netns exec "$NS_B" timeout 10 nc -l -p 9090 >/tmp/router_recv.$$ 2>/dev/null &
NC_PID=$!
sleep 0.5
if echo "$MESSAGE" | ip netns exec "$NS_A" timeout 5 nc -w2 "$HOST_B" 9090 >/dev/null 2>&1; then
    sleep 0.5
    if grep -q "$MESSAGE" /tmp/router_recv.$$ 2>/dev/null; then
        pass "a TCP connection between two real kernels traversed the forwarding path intact"
    else
        fail "the TCP connection completed but the data did not arrive intact"
    fi
else
    fail "could not open a TCP connection from host A to host B"
fi
kill "$NC_PID" 2>/dev/null
rm -f /tmp/router_recv.$$

# The router still terminates its OWN connections while relaying other traffic.
# A router is not a special kind of program - it is a stack with more than one
# interface and permission to pass packets on.
ECHO_MESSAGE="echo-from-A-$$"
REPLY=$(echo "$ECHO_MESSAGE" | ip netns exec "$NS_A" timeout 5 nc -w2 "$ROUTER_A" "$PORT" 2>/dev/null)
if [ "$REPLY" = "$ECHO_MESSAGE" ]; then
    pass "and still serves its own TCP echo on the same interfaces it is routing between"
else
    fail "the echo server stopped working in router mode (got: $REPLY)"
fi

# traceroute names the hop that discarded each probe, which is exactly what
# Time Exceeded code 0 is for. Without the TTL decrement there would be no
# expiry to report; without the ICMP there would be a silent star.
if command -v traceroute >/dev/null 2>&1; then
    TRACE=$(ip netns exec "$NS_A" traceroute -n -w1 -q1 -m4 "$HOST_B" 2>/dev/null)
    if echo "$TRACE" | grep -q "$ROUTER_A"; then
        pass "traceroute from A shows this stack as the first hop (Time Exceeded code 0)"
    else
        fail "traceroute did not show $ROUTER_A as a hop; got:"
        echo "$TRACE" | sed "s/^/          /"
    fi
else
    echo "  SKIP  traceroute not installed"
fi

# An address with no route must be reported, not swallowed. This is the other
# error only a router sends.
# Captured first rather than piped straight into grep: this script runs under
# `set -o pipefail`, and ping exits non-zero on 100% loss - so `ping | grep -q`
# reports failure even when grep matched, which is exactly how this check
# managed to fail while the stack was answering correctly.
UNREACHABLE_OUTPUT=$(ip netns exec "$NS_A" ping -c1 -W2 203.0.113.9 2>&1 || true)
if echo "$UNREACHABLE_OUTPUT" | grep -qiE "unreachable"; then
    pass "an unroutable destination draws Destination Unreachable rather than silence"
else
    fail "no ICMP unreachable for a destination with no route; ping said:"
    echo "$UNREACHABLE_OUTPUT" | sed "s/^/          /"
fi

if ip link show "$IF_A" 2>/dev/null | grep -q PROMISC; then
    fail "$IF_A was left in promiscuous mode"
else
    pass "no promiscuous mode needed on either interface"
fi

if kill -0 "$SERVER_PID" 2>/dev/null; then
    pass "the router survived the whole run"
else
    fail "the router died during the run"
    tail -20 "$LOG" >&2
fi

echo
echo "$passes passed, $failures failed"
[ "$failures" -eq 0 ] || exit 1
exit 0
