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
# When a phase fails, what it leaves in $OUT_DIR is meant to be enough to debug
# it without a rerun on the CI machine:
#   NAME.json / NAME.stderr  loadgen's report; stderr lists every failed
#                            connection by source port, phase (connect, round N,
#                            close) and the echo bytes it was still waiting for
#   NAME.pcap                headers of every frame of the phase, captured in
#                            the namespace (kept only when the phase fails;
#                            needs tcpdump, skipped with a warning without it)
#   NAME-debug.*             the same phase run again on a fresh server with
#                            LOG_LEVEL=DEBUG (its log gzipped as
#                            NAME-debug.server.log.gz), with its own capture.
#                            The first failure is the one that counts; the rerun
#                            is evidence only and does not change the result.
#   server.log               the server's log for the whole run, at INFO
#
# Requires root and ip / ethtool / ping / tc (iproute2); tcpdump is optional.
# Needs a built epoll-server and loadgen:
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
#   LOADTEST_DEBUG_RERUN        0 to skip the LOG_LEVEL=DEBUG rerun of a failed phase
#   LOADTEST_PCAP_SNAPLEN       bytes captured per frame, default 128 (headers
#                               with options; the payload is loadgen's and known)
#
# The kernel baseline at the end needs `make -C epoll-server KERNEL=1`; without
# it that step is skipped with a warning.
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
DEBUG_RERUN="${LOADTEST_DEBUG_RERUN:-1}"
PCAP_SNAPLEN="${LOADTEST_PCAP_SNAPLEN:-128}"

LOG=$(mktemp /tmp/loadtest_server.XXXXXX.log)
SERVER_PID=""
CAPTURE_PID=""
HAVE_TCPDUMP=0
failures=0

stop_capture()
{
    if [ -n "$CAPTURE_PID" ]; then
        # SIGINT, so tcpdump flushes and closes the file properly
        kill -INT "$CAPTURE_PID" 2>/dev/null
        wait "$CAPTURE_PID" 2>/dev/null
        CAPTURE_PID=""
    fi
}

stop_server()
{
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
        SERVER_PID=""
    fi
}

cleanup()
{
    stop_capture
    stop_server
    ip netns del "$NS" 2>/dev/null
    ip link del "$HOST_IF" 2>/dev/null
    # Kept whatever the outcome, and also when the script stops early.
    [ -d "$OUT_DIR" ] && cp "$LOG" "$OUT_DIR/server.log" 2>/dev/null
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
if command -v tcpdump >/dev/null 2>&1; then
    HAVE_TCPDUMP=1
else
    echo "::warning::tcpdump not installed - a failed phase will have no packet capture"
fi
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

# start_server LOGFILE [LOG_LEVEL]: starts epoll-server on the veth, logging to
# LOGFILE at LOG_LEVEL (the logger's own variable; INFO unless given), and waits
# until it is listening. Exits the script if it does not come up.
start_server()
{
    local logfile=$1 level=${2:-INFO}
    LOG_LEVEL="$level" "$SERVER" --transport nic --device "$HOST_IF" --ip "$STACK_IP" --prefix 24 --port "$PORT" \
        >"$logfile" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 50); do
        grep -q "listening on TCP port" "$logfile" 2>/dev/null && return 0
        if ! kill -0 "$SERVER_PID" 2>/dev/null; then
            echo "Server exited during startup:" >&2
            cat "$logfile" >&2
            exit 1
        fi
        sleep 0.1
    done
    echo "Server did not become ready:" >&2
    cat "$logfile" >&2
    exit 1
}

# start_capture FILE: headers of every frame on the namespace's end of the
# veth, until stop_capture. The namespace end, because that is the wire as the
# kernel client sees it - after netem on our side, before netem on its own.
start_capture()
{
    local file=$1
    [ "$HAVE_TCPDUMP" = "1" ] || return 0
    # -Z root: Debian and Ubuntu build tcpdump to drop to its own user before
    # opening the file, which could not write into the root-owned $OUT_DIR.
    ip netns exec "$NS" tcpdump -Z root -i "$PEER_IF" -s "$PCAP_SNAPLEN" -U -w "$file" tcp port "$PORT" \
        2>"$file.tcpdump.log" &
    CAPTURE_PID=$!
    # tcpdump says "listening on" once the capture is open; frames before that
    # would be missed.
    for _ in $(seq 1 50); do
        grep -q "listening on" "$file.tcpdump.log" 2>/dev/null && break
        sleep 0.1
    done
}

start_server "$LOG"

ip netns exec "$NS" ping -c 2 -W 2 "$STACK_IP" >/dev/null 2>&1 || { echo "peer cannot ping the stack" >&2; exit 1; }

# loadgen_once NAME LOADGEN_ARGS...: one loadgen run inside the namespace, its
# JSON and stderr in $OUT_DIR/NAME.*, with a capture alongside. Returns
# loadgen's status; keeps the capture only if it failed.
loadgen_once()
{
    local name=$1
    shift
    local status=0
    start_capture "$OUT_DIR/$name.pcap"
    ip netns exec "$NS" "$LOADGEN" --host "$STACK_IP" --port "$PORT" "$@" --json >"$OUT_DIR/$name.json" \
        2>"$OUT_DIR/$name.stderr" || status=$?
    stop_capture
    rm -f "$OUT_DIR/$name.pcap.tcpdump.log"
    [ "$status" -eq 0 ] && rm -f "$OUT_DIR/$name.pcap"
    return "$status"
}

# debug_rerun NAME LOADGEN_ARGS...: the failed phase again, on a fresh server
# logging at DEBUG, so the evidence has the stack's own account of every
# segment next to the capture. A fresh server rather than the running one: the
# log level is read at startup, and a fresh server also tells apart a failure
# that needs the earlier phases' leftovers (SYN-cookie mode, say) from one that
# does not. The main server's log is kept, and it is restarted afterwards for
# the phases still to come.
debug_rerun()
{
    local name=$1
    shift
    [ "$DEBUG_RERUN" = "1" ] || return 0
    # A server that died stays dead, for the check at the end to report.
    kill -0 "$SERVER_PID" 2>/dev/null || return 0
    echo "  rerunning $name on a fresh server at LOG_LEVEL=DEBUG (evidence only)"
    cat "$LOG" >>"$LOG.kept"
    stop_server
    start_server "$OUT_DIR/$name-debug.server.log" DEBUG
    if loadgen_once "$name-debug" "$@"; then
        echo "  the DEBUG rerun of $name passed - an intermittent failure, or one that needs the earlier phases"
    else
        echo "  the DEBUG rerun of $name failed too; see $name-debug.*"
    fi
    stop_server
    gzip -f "$OUT_DIR/$name-debug.server.log"
    start_server "$LOG"
    cat "$LOG.kept" "$LOG" >"$LOG.joined" 2>/dev/null && mv "$LOG.joined" "$LOG"
    rm -f "$LOG.kept"
}

# The JSON lines shown in a phase's console summary: rates, connect latency and
# round-trip latency, the last also split into the first round and the rest (a
# slow first round with fast later ones means connection setup, not the data path).
SUMMARY_KEYS='"(connections_per_s|throughput_mib_per_s|connect|round_trip|round_trip_first|round_trip_rest)"'

# print_stats: asks the server for its stats line (SIGUSR1, answered on the
# reactor thread, so it can lag by a loop pass) and prints the one that comes
# back. The counters are cumulative over the server's life, so a phase's own
# share is the difference from the line printed after the phase before it. Waits
# up to 2 s for a new line, and says so if none arrives (an older server, or one
# that has died) rather than printing a stale one.
print_stats()
{
    local before line
    before=$(grep -c 'stats: ' "$LOG" 2>/dev/null)
    kill -USR1 "$SERVER_PID" 2>/dev/null || { echo "    (no stats: the server is not running)"; return; }
    for _ in $(seq 1 20); do
        [ "$(grep -c 'stats: ' "$LOG" 2>/dev/null)" -gt "$before" ] && break
        sleep 0.1
    done
    if [ "$(grep -c 'stats: ' "$LOG" 2>/dev/null)" -gt "$before" ]; then
        line=$(grep 'stats: ' "$LOG" | tail -n 1)
        echo "    ${line#*stats: }"
    else
        echo "    (no stats line came back within 2 s)"
    fi
}

# run_phase NAME LOADGEN_ARGS...: runs loadgen inside the namespace, writes the
# JSON report, prints a summary, and counts a nonzero exit as a failure - after
# which the capture is kept and the phase is rerun at DEBUG (see the header).
run_phase()
{
    local name=$1
    shift
    echo
    echo "== $name: loadgen $*"
    if ! loadgen_once "$name" "$@"; then
        echo "  FAIL  $name (loadgen reported errors; stderr below)"
        sed 's/^/    /' "$OUT_DIR/$name.stderr"
        failures=$((failures + 1))
        # the numbers that matter, straight from the JSON
        grep -E "$SUMMARY_KEYS" "$OUT_DIR/$name.json" | sed 's/^ */    /'
        echo "    errors: $(grep '"errors"' "$OUT_DIR/$name.json" | sed 's/^ *"errors": //')"
        print_stats
        debug_rerun "$name" "$@"
        return
    fi
    echo "  PASS  $name"
    grep -E "$SUMMARY_KEYS" "$OUT_DIR/$name.json" | sed 's/^ */    /'
    echo "    errors: $(grep '"errors"' "$OUT_DIR/$name.json" | sed 's/^ *"errors": //')"
    print_stats
}

BURST_ARGS=(--connections "$BURST_CONNECTIONS" --concurrency "$BURST_CONNECTIONS" --size 4096 --rounds 3
    --timeout-ms 20000)
run_phase burst "${BURST_ARGS[@]}"
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
        ip netns exec "$NS" tc qdisc del dev "$PEER_IF" root 2>/dev/null
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

# json_us FILE KEY FIELD: a latency figure (microseconds) from loadgen's JSON,
# e.g. json_us burst.json round_trip p90. Empty if it is not there.
json_us()
{
    grep "\"$2\":" "$1" | sed -n "s/.*\"$3\": \([0-9]*\).*/\1/p" | head -n 1
}

# kernel_baseline: the burst again, against the same server logic on kernel
# sockets (epoll-server built with KERNEL=1) at the same address and port, so
# the Linux TCP stack's own numbers for this client and this veth are on the
# page next to ours. The question it answers is whether a latency is ours or
# the machine's. Run last, not right after the burst: the server is replaced
# for it, and the sustained and netem phases are meant to follow the burst on
# one server (the SYN-cookie state a burst leaves behind is part of what they
# test). The kernel owns STACK_IP only while this runs; ours is stopped first,
# or both would answer ARP and SYNs for it. Never fails the run: a missing
# binary or a failed phase is a warning.
kernel_baseline()
{
    local kernel_server="$REPO_ROOT/epoll-server/epoll-server-kernel"
    if [ ! -x "$kernel_server" ]; then
        echo "::warning::no kernel baseline - build it with: make -C epoll-server KERNEL=1"
        return 0
    fi
    echo
    echo "== burst-kernel: the same burst against epoll-server on kernel sockets"
    stop_server
    ip addr add "$STACK_IP/24" dev "$HOST_IF" 2>/dev/null
    local klog="$OUT_DIR/kernel-server.log"
    "$kernel_server" --port "$PORT" >"$klog" 2>&1 &
    SERVER_PID=$!
    local ready=0
    for _ in $(seq 1 50); do
        if grep -q "listening on TCP port" "$klog" 2>/dev/null; then
            ready=1
            break
        fi
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.1
    done
    if [ "$ready" = "1" ] && loadgen_once burst-kernel "${BURST_ARGS[@]}"; then
        local u50 u90 k50 k90
        u50=$(json_us "$OUT_DIR/burst.json" round_trip p50)
        u90=$(json_us "$OUT_DIR/burst.json" round_trip p90)
        k50=$(json_us "$OUT_DIR/burst-kernel.json" round_trip p50)
        k90=$(json_us "$OUT_DIR/burst-kernel.json" round_trip p90)
        echo "  round_trip (us)    p50        p90"
        echo "    ustack       $(printf '%8s %10s' "${u50:-?}" "${u90:-?}")"
        echo "    kernel       $(printf '%8s %10s' "${k50:-?}" "${k90:-?}")"
        if [ -n "$u90" ] && [ -n "$k90" ] && [ "$k90" -gt 0 ]; then
            awk -v u="$u90" -v k="$k90" 'BEGIN { printf "    p90 ratio ustack/kernel: %.1fx\n", u / k }'
            if [ "$u90" -gt $((k90 * 3)) ]; then
                echo "::warning::ustack burst round_trip p90 ($u90 us) is more than 3x the kernel's ($k90 us)"
            fi
        fi
    else
        echo "::warning::the kernel baseline did not run (server not ready, or loadgen failed); see $klog and burst-kernel.stderr"
    fi
    stop_server
    ip addr del "$STACK_IP/24" dev "$HOST_IF" 2>/dev/null
}
kernel_baseline

if [ "$failures" -ne 0 ]; then
    echo "$failures check(s) failed; reports in $OUT_DIR"
    exit 1
fi
echo "all phases passed; reports in $OUT_DIR"
