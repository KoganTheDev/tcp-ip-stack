#!/bin/sh
# Run by the global build gate (~/.claude/hooks/dev-build-gate.sh) before Claude can finish a turn.
# Build and test are timed separately so that a gate timeout shows where the
# time went. `make all` is the build `make test` depends on (cmake --build
# --preset debug), and `make test` then only runs build/debug/run_tests. The
# tests have a per-test watchdog (tests/src/test_watchdog.cpp) that aborts a
# hung test with backtraces.
cd "$(dirname "$0")/.." || exit 1

t0=$(date +%s)
make all || { echo "verify: build FAILED after $(( $(date +%s) - t0 ))s"; exit 1; }
t1=$(date +%s)
echo "verify: build took $((t1 - t0))s"

make test
status=$?
t2=$(date +%s)
echo "verify: tests took $((t2 - t1))s (exit $status), total $((t2 - t0))s"
exit $status
