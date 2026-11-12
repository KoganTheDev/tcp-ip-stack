#!/usr/bin/env bash
#
# Drives the real epoll-server, running on THIS repo's stack over an AF_PACKET
# socket, with tools/loadgen from a network namespace on the other end of a veth
# pair. The client side is the Linux kernel's TCP, so every connection has an
# independent implementation on the far end; a wrong echo, a reset or a stall
# from our stack shows up as a loadgen error and fails the run.
#
# Set up the way scripts/veth_test.sh does it (same namespace/veth shape, same
# checksum-offload reasoning - see the comment there), minus the off-link and
# promiscuous-mode checks, which that script already owns.
#
# Phases, each writing a JSON report into $OUT_DIR:
#   burst      LOADTEST_BURST_CONNECTIONS connections, all concurrent
#   sustained  LOADTEST_DURATION seconds of steady churn
#   netem      a shorter burst with `tc qdisc netem` loss and delay on both ends
#              of the link (set LOADTEST_NETEM="" to skip). If the kernel has no
#              sch_netem the phase is skipped with a warning, unless
#              LOADTEST_NETEM_REQUIRED=1.
#
# Requires root and ip / ethtool / ping / tc (iproute2). Needs a built
# epoll-server and loadgen:
#
#     make -C epoll-server
#     cmake --preset release && cmake --build --preset release --target loadgen
#     sudo scripts/loadtest_netns.sh
#
# Environment (all optional):
#   LOADGEN                     path to the loadgen binary (default build/release/loadgen)
#   OUT_DIR                     where the JSON reports go (default ./loadtest-results)
#   LOADTEST_BURST_CONNECTIONS  default 200
#   LOADTEST_DURATION           sustained seconds, default 60
#   LOADTEST_NETEM              netem parameters, default "loss 1% delay 5ms 2ms"
#   LOADTEST_NETEM_REQUIRED     1 to fail rather than skip when netem is unavailable
#
set -uo pipefail

NS=loadtest
HOST_IF=vload0
PEER_IF=vload1
PEER_IP=10.9.1.1
STACK_IP=10.9.1.2
PORT=8080

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER="$REPO_ROOT/epoll-server/epoll-server"
LOADGEN="${LOADGEN:-$REPO_ROOT/build/release/loadgen}"
OUT_DIR="${OUT_DIR:-$PWD/loadtest-results}"
BURST_CONNECTIONS="${LOADTEST_BURST_CONNECTIONS:-200}"
DURATION="${LOADTEST_DURATION:-60}"
NETEM="${LOADTEST_NETEM-loss 1% delay 5ms 2ms}"
NETEM_REQUIRED="${LOADTEST_NETEM_REQUIRED:-0}"

LOG=$(mktemp /tmp/loadtest_server.XXXXXX.log)
SERVER_PID=""
failures=0

cleanup()
{
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
    fi
    ip netns del "$NS" 2>/dev/null
    ip link del "$HOST_IF" 2>/dev/null
    rm -f "$LOG"
}
trap cleanup EXIT

if [ "$(id -u)" != "0" ]; then
    echo "This needs root: it creates a network namespace and a veth pair, and opens an AF_PACKET socket." >&2
    exit 1
fi
for tool in ip ethtool ping tc; do
    command -v "$tool" >/dev/null 2>&1 || { echo "Missing required tool: $tool" >&2; exit 1; }
done
[ -x "$SERVER" ] || { echo "Build epoll-server first: make -C epoll-server" >&2; exit 1; }
[ -x "$LOADGEN" ] || { echo "Build loadgen first (see the header of this script); looked for $LOADGEN" >&2; exit 1; }
mkdir -p "$OUT_DIR" || exit 1

cleanup 2>/dev/null
SERVER_PID=""

echo "Setting up $HOST_IF <-> $PEER_IF (client $PEER_IP in namespace $NS, stack answers for $STACK_IP)"
ip netns add "$NS" || { echo "could not create namespace" >&2; exit 1; }
ip link add "$HOST_IF" type veth peer name "$PEER_IF" || { echo "could not create veth pair" >&2; exit 1; }
ip link set "$PEER_IF" netns "$NS"
ip link set "$HOST_IF" up
ip -n "$NS" link set "$PEER_IF" up
ip -n "$NS" addr add "$PEER_IP/24" dev "$PEER_IF"
# Real checksums on the wire: see veth_test.sh for why this is not optional.
ethtool -K "$HOST_IF" tx off rx off >/dev/null 2>&1
ip netns exec "$NS" ethtool -K "$PEER_IF" tx off rx off >/dev/null 2>&1

"$SERVER" --transport nic --device "$HOST_IF" --ip "$STACK_IP" --prefix 24 --port "$PORT" >"$LOG" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 50); do
    grep -q "listening on TCP port" "$LOG" 2>/dev/null && break
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Server exited during startup:" >&2
        cat "$LOG" >&2
        exit 1
    fi
    sleep 0.1
done
grep -q "listening on TCP port" "$LOG" || { echo "Server did not become ready:" >&2; cat "$LOG" >&2; exit 1; }

ip netns exec "$NS" ping -c 2 -W 2 "$STACK_IP" >/dev/null 2>&1 || { echo "peer cannot ping the stack" >&2; exit 1; }

# run_phase NAME LOADGEN_ARGS...: runs loadgen inside the namespace, writes the
# JSON report, prints a summary, and counts a nonzero exit as a failure.
run_phase()
{
    local name=$1
    shift
    echo
    echo "== $name: loadgen $*"
    if ! ip netns exec "$NS" "$LOADGEN" --host "$STACK_IP" --port "$PORT" "$@" --json >"$OUT_DIR/$name.json" \
        2>"$OUT_DIR/$name.stderr"; then
        echo "  FAIL  $name (loadgen reported errors; stderr below)"
        sed 's/^/    /' "$OUT_DIR/$name.stderr"
        failures=$((failures + 1))
    else
        echo "  PASS  $name"
    fi
    # the numbers that matter, straight from the JSON
    grep -E '"(connections_per_s|throughput_mib_per_s)"|"round_trip"' "$OUT_DIR/$name.json" | sed 's/^ */    /'
    echo "    errors: $(grep '"errors"' "$OUT_DIR/$name.json" | sed 's/^ *"errors": //')"
}

run_phase burst --connections "$BURST_CONNECTIONS" --concurrency "$BURST_CONNECTIONS" --size 4096 --rounds 3 \
    --timeout-ms 20000
run_phase sustained --duration "$DURATION" --concurrency 50 --rate 100 --size 2048 --rounds 10 --threads 2 \
    --timeout-ms 20000

if [ -n "$NETEM" ]; then
    # Both ends, so loss and delay apply in both directions. Word-splitting
    # of $NETEM into tc arguments is the point.
    # shellcheck disable=SC2086
    if tc qdisc add dev "$HOST_IF" root netem $NETEM 2>/dev/null &&
        ip netns exec "$NS" tc qdisc add dev "$PEER_IF" root netem $NETEM 2>/dev/null; then
        # A lost SYN is retried after a second, so the connect phase needs room.
        run_phase netem --connections 100 --concurrency 100 --size 4096 --rounds 3 --timeout-ms 60000
        tc qdisc del dev "$HOST_IF" root 2>/dev/null
    elif [ "$NETEM_REQUIRED" = "1" ]; then
        echo "FAIL  netem requested ($NETEM) but tc could not install it (no sch_netem?)" >&2
        failures=$((failures + 1))
    else
        echo
        echo "::warning::netem phase skipped - tc could not install a netem qdisc (no sch_netem in this kernel?)"
    fi
fi

echo
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL  the server died during the run; its log:"
    sed 's/^/  /' "$LOG"
    failures=$((failures + 1))
fi
if grep -q "bad checksum" "$LOG"; then
    echo "FAIL  the server log reports bad checksums - is checksum offload still enabled on the veth pair?"
    failures=$((failures + 1))
fi
cp "$LOG" "$OUT_DIR/server.log" 2>/dev/null

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed; reports in $OUT_DIR"
    exit 1
fi
echo "all phases passed; reports in $OUT_DIR"
