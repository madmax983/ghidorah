#!/bin/sh
# Deterministic cost of `binary_load` on a fixture: instructions (callgrind) and heap allocations
# (memcheck summary). No clock is read. Needs valgrind and a release build of `ghidorah`.
# Usage: perf/ir.sh [fixture]   (default: fixtures/bin/large.gcc-O2)
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
bin="$root/target/release/ghidorah"
fixture=${1:-fixtures/bin/large.gcc-O2}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
run() {
    rm -rf "$work/proj"
    (cd "$work" && valgrind "$@" "$bin" call binary_load "{\"path\":\"$fixture\"}" \
        --root "$root" --project-root "$work/proj" >/dev/null)
}
ir=$(run --tool=callgrind --callgrind-out-file="$work/cg.out" 2>&1 | sed -n 's/.*Collected : //p')
allocs=$(run --tool=memcheck 2>&1 | sed -n 's/.*total heap usage: \([0-9,]*\) allocs.*/\1/p')
echo "fixture=$fixture"
echo "instructions=$ir"
echo "allocs=$allocs"
