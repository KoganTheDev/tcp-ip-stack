#!/usr/bin/env bash
#
# Drives the http-get demonstrator through every layer this project implements,
# against real server software rather than against another copy of itself.
#
# The peer namespace runs dnsmasq (a real DHCP server AND a real DNS server) and
# a real HTTP server. This stack starts with no address at all and has to:
#
#     DHCP  - discover, request, and accept a lease, taking its address, mask,
#             gateway and DNS servers from it
#     DNS   - resolve a name that only exists in dnsmasq's config
#     ARP   - resolve the next hop, which for the off-link case is the gateway
#             rather than the server
#     TCP   - handshake, send a request, read a response, half-close
#
# That is the whole point of testing it this way: dnsmasq and the HTTP server
# have never heard of this codebase, so nothing here can pass by two copies of
# the same bug agreeing with each other - which is exactly how the checksum bug
# in the README survived a fully passing unit suite.
#
# Requires root (namespaces, veth, AF_PACKET) plus ip, dnsmasq, python3.
#
#     sudo scripts/http_get_test.sh
#
set -uo pipefail

NS=httptest
HOST_IF=vhttp0
PEER_IF=vhttp1
PEER_IP=10.9.1.1
DHCP_RANGE_START=10.9.1.50
DHCP_RANGE_END=10.9.1.60
# Served by dnsmasq from an address on a DIFFERENT network, reachable only
# through the peer acting as a router - so a successful fetch proves next-hop
# selection worked, not just that two neighbours can talk.
OFFLINK_IP=192.168.88.10
OFFLINK_NET=192.168.88.0/24
TEST_NAME=demo.stacktest
HTTP_PORT=8080
BODY_MARKER="stack-fetched-this-body"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT="$REPO_ROOT/http-get/http-get"

WORKDIR=$(mktemp -d /tmp/http_get_test.XXXXXX)
CLIENT_LOG="$WORKDIR/client.log"
DNSMASQ_PID=""
HTTP_PID=""

passes=0
failures=0

pass() { echo "  PASS  $1"; passes=$((passes + 1)); }
fail() { echo "  FAIL  $1"; failures=$((failures + 1)); }

cleanup() {
    [ -n "$DNSMASQ_PID" ] && kill "$DNSMASQ_PID" 2>/dev/null
    [ -n "$HTTP_PID" ] && kill "$HTTP_PID" 2>/dev/null
    ip netns pids "$NS" 2>/dev/null | while read -r pid; do kill "$pid" 2>/dev/null; done
    ip netns del "$NS" 2>/dev/null
    ip link del "$HOST_IF" 2>/dev/null
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

if [ "$(id -u)" -ne 0 ]; then
    echo "This test needs root (namespaces, veth, AF_PACKET)." >&2
    exit 1
fi

for tool in ip dnsmasq python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool" >&2
        echo "On Debian/Ubuntu: apt-get install -y iproute2 dnsmasq python3" >&2
        exit 1
    fi
done

if [ ! -x "$CLIENT" ]; then
    echo "Building http-get..."
    if ! make -C "$REPO_ROOT/http-get" >/dev/null; then
        echo "Build failed." >&2
        exit 1
    fi
fi

# --- the link ---------------------------------------------------------------

echo "Setting up $HOST_IF <-> $PEER_IF (peer $PEER_IP in namespace $NS)"

ip netns add "$NS" || { echo "could not create namespace" >&2; exit 1; }
ip link add "$HOST_IF" type veth peer name "$PEER_IF" || { echo "could not create veth" >&2; exit 1; }
ip link set "$PEER_IF" netns "$NS"

# Checksum offload has to go. With it on, the kernel hands us frames whose
# checksum fields were never filled in - the NIC would have done it - so this
# stack correctly rejects every one of them. Turning it off puts real checksums
# on the wire, which is the only way this test says anything about the checksum
# code.
ethtool -K "$HOST_IF" tx off rx off >/dev/null 2>&1 || true
ip netns exec "$NS" ethtool -K "$PEER_IF" tx off rx off >/dev/null 2>&1 || true

ip link set "$HOST_IF" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$PEER_IF" up
ip netns exec "$NS" ip addr add "$PEER_IP/24" dev "$PEER_IF"

# The peer is a router: it owns the off-link address on a loopback alias and
# forwards for it, so reaching that address requires going through it.
ip netns exec "$NS" ip addr add "$OFFLINK_IP/32" dev lo
ip netns exec "$NS" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$NS" ip route add "$OFFLINK_NET" dev lo 2>/dev/null || true

# The host end must NOT have an address. If the kernel owned one on this
# network it would answer the ARP and the TCP itself, and this stack would
# never see the traffic it is supposed to be handling.

# --- real servers in the peer namespace -------------------------------------

cat > "$WORKDIR/dnsmasq.conf" <<EOF
interface=$PEER_IF
bind-interfaces
except-interface=lo
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,2m
dhcp-option=option:router,$PEER_IP
dhcp-option=option:dns-server,$PEER_IP
# The name under test resolves to the OFF-LINK address, so a successful fetch
# exercises DNS and next-hop selection together.
address=/$TEST_NAME/$OFFLINK_IP
no-hosts
no-resolv
log-facility=$WORKDIR/dnsmasq.log
pid-file=$WORKDIR/dnsmasq.pid
EOF

ip netns exec "$NS" dnsmasq --conf-file="$WORKDIR/dnsmasq.conf" --keep-in-foreground &
DNSMASQ_PID=$!
sleep 1

if ! kill -0 "$DNSMASQ_PID" 2>/dev/null; then
    echo "dnsmasq failed to start:" >&2
    cat "$WORKDIR/dnsmasq.log" >&2 2>/dev/null
    exit 1
fi

mkdir -p "$WORKDIR/www"
echo "$BODY_MARKER" > "$WORKDIR/www/index.html"
ip netns exec "$NS" python3 -m http.server "$HTTP_PORT" \
    --bind "$OFFLINK_IP" --directory "$WORKDIR/www" >"$WORKDIR/http.log" 2>&1 &
HTTP_PID=$!
sleep 1

if ! kill -0 "$HTTP_PID" 2>/dev/null; then
    echo "HTTP server failed to start:" >&2
    cat "$WORKDIR/http.log" >&2
    exit 1
fi

# --- the run ----------------------------------------------------------------

echo
echo "Fetching http://$TEST_NAME:$HTTP_PORT/index.html with no address configured..."
echo

timeout 40 "$CLIENT" \
    --transport nic --device "$HOST_IF" \
    --dhcp --timeout 30 \
    "$TEST_NAME:$HTTP_PORT/index.html" >"$CLIENT_LOG" 2>&1
CLIENT_RC=$?

echo "--- client output ---"
cat "$CLIENT_LOG"
echo "---------------------"
echo
echo "Checks:"

if [ $CLIENT_RC -eq 0 ]; then
    pass "http-get exited cleanly"
else
    fail "http-get exited with status $CLIENT_RC"
fi

# Each stage has to be visible in the output, so a pass means every layer ran
# rather than something short-circuiting to a lucky answer.
if grep -qE "^DHCP     10\.9\.1\.(5[0-9]|60)/24" "$CLIENT_LOG"; then
    pass "took a DHCP lease from dnsmasq's pool"
else
    fail "no DHCP lease in range $DHCP_RANGE_START-$DHCP_RANGE_END"
fi

if grep -q "gateway $PEER_IP" "$CLIENT_LOG"; then
    pass "applied the gateway from DHCP option 3"
else
    fail "gateway from DHCP was not applied"
fi

if grep -q "DNS via  $PEER_IP" "$CLIENT_LOG"; then
    pass "took the DNS server from DHCP option 6"
else
    fail "DNS server from DHCP was not applied"
fi

if grep -q "DNS      $TEST_NAME is $OFFLINK_IP" "$CLIENT_LOG"; then
    pass "resolved $TEST_NAME to $OFFLINK_IP against a real DNS server"
else
    fail "did not resolve $TEST_NAME"
fi

if grep -q "TCP      established" "$CLIENT_LOG"; then
    pass "TCP handshake completed with an off-link server via the gateway"
else
    fail "TCP handshake did not complete"
fi

if grep -q "200 OK" "$CLIENT_LOG"; then
    pass "server returned 200 OK"
else
    fail "no 200 OK in the response"
fi

if grep -q "$BODY_MARKER" "$CLIENT_LOG"; then
    pass "response body arrived intact"
else
    fail "response body missing or corrupted"
fi

# The HTTP server logs the request it saw, which is the independent check that
# what this stack sent was a well-formed HTTP/1.1 request and not merely bytes
# that happened to elicit a response.
if grep -q "GET /index.html HTTP/1.1" "$WORKDIR/http.log"; then
    pass "the server logged a well-formed HTTP/1.1 request"
else
    fail "the server did not log the expected request line"
fi

if ip link show "$HOST_IF" 2>/dev/null | grep -q PROMISC; then
    fail "$HOST_IF was left in promiscuous mode"
else
    pass "no promiscuous mode on $HOST_IF"
fi

echo
echo "$passes passed, $failures failed"
[ "$failures" -eq 0 ] || exit 1
exit 0
