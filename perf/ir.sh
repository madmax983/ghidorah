#!/bin/sh
# Deterministic counters for `ghidorah call binary_load` on the large fixture.
# Prints callgrind instructions (Ir) and memcheck heap-allocation counts. No clock.
# Each run uses a private XDG_DATA_HOME, so the result does not depend on earlier runs.
#   cold: the project does not exist (load, analysis, project write).
#   warm: the project exists (snapshot read, snapshot write at close).
# Set IR_FOCUS to a grep pattern to also print the self Ir of the functions that match it.
# Usage: cargo build --release -p ghidorah && [IR_FOCUS=Sha256] perf/ir.sh
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
bin="$root/target/release/ghidorah"
fix="$root/fixtures/bin"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
req="{\"path\":\"$fix/large.gcc-O2\"}"
count() { # label, state (cold|warm), then the command
  label=$1; state=$2; shift 2
  for tool in callgrind memcheck; do
    export XDG_DATA_HOME="$work/$label-$tool"
    rm -rf "$XDG_DATA_HOME"
    if [ "$state" = warm ]; then "$@" >/dev/null; fi
    if [ "$tool" = callgrind ]; then
      valgrind --tool=callgrind --callgrind-out-file="$work/cg.out" "$@" 2>&1 >/dev/null \
        | grep 'Collected' | sed 's/^==[0-9]*== *//' | sed "s/^/$label callgrind /"
      if [ -n "${IR_FOCUS:-}" ]; then
        callgrind_annotate "$work/cg.out" 2>/dev/null | grep -E "^ *[0-9,]+ .*($IR_FOCUS)" \
          | sed 's/ \[.*//' | sed "s/^ */$label self /" || true
      fi
    else
      valgrind --tool=memcheck "$@" 2>&1 >/dev/null \
        | grep 'total heap usage' | sed 's/^==[0-9]*== *//' | sed "s/^/$label /"
    fi
  done
}
count cold cold "$bin" call binary_load "$req" --root "$fix"
count warm warm "$bin" call binary_load "$req" --root "$fix"
