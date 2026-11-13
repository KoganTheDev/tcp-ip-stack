#!/bin/sh
# Run by the global build gate (~/.claude/hooks/dev-build-gate.sh) before Claude can finish a turn.
cd "$(dirname "$0")/.." || exit 1
make test
