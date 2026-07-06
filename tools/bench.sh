#!/bin/bash
ARCA_ROOT=$(cd "$(dirname "$0")/.." && pwd)
RESULT_DIR="$ARCA_ROOT/bench_results"
RUNS=${1:-2}
SECS=${2:-10}

mkdir -p "$RESULT_DIR"
cleanup() { sudo kill $(pidof arca workload 2>/dev/null) 2>/dev/null; sudo rm -f /sys/fs/bpf/task_class_map; sleep 1; }
export LD_LIBRARY_PATH=/tmp/opencode/scx-build/build/obj/libbpf

echo "=== CFS vs ARCA ($RUNS runs x ${SECS}s) ==="

for i in $(seq 1 $RUNS); do
    cleanup
    "$ARCA_ROOT/bin/workload" "$SECS" > "$RESULT_DIR/cfs_$i.txt"
    echo -n "CFS #$i:  "
    grep "Interactive avg" "$RESULT_DIR/cfs_$i.txt" | head -1
    grep "p99" "$RESULT_DIR/cfs_$i.txt" | head -1
done

for i in $(seq 1 $RUNS); do
    cleanup
    cd "$ARCA_ROOT" && "$ARCA_ROOT/bin/arca" > /dev/null 2>&1 &
    sleep 4
    "$ARCA_ROOT/bin/workload" "$SECS" > "$RESULT_DIR/arca_$i.txt"
    echo -n "ARCA #$i: "
    grep "Interactive avg" "$RESULT_DIR/arca_$i.txt" | head -1
    grep "p99" "$RESULT_DIR/arca_$i.txt" | head -1
    cleanup
done

cleanup
echo "Done. Results: $RESULT_DIR/"
