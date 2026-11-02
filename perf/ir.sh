#!/bin/sh
# Deterministic counters for `ghidorah call binary_load` on the large fixture.
# Prints callgrind instructions (Ir) and a memcheck heap-allocation count. No clock.
# Usage: cargo build --release -p ghidorah && perf/ir.sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
bin="$root/target/release/ghidorah"
fix="$root/fixtures/bin"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
req="{\"path\":\"$fix/large.gcc-O2\"}"
valgrind --tool=callgrind --callgrind-out-file="$work/cg.out" \
  "$bin" call binary_load "$req" --root "$fix" 2>&1 >/dev/null | grep 'Collected' | sed 's/^==[0-9]*== *//' | sed 's/^/callgrind /'
valgrind --tool=memcheck "$bin" call binary_load "$req" --root "$fix" 2>&1 >/dev/null \
  | grep 'total heap usage' | sed 's/^==[0-9]*== *//'
