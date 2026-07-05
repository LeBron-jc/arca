#!/bin/bash
ARCA_ROOT="/home/cuijian/arca"
RESULT_DIR="$ARCA_ROOT/bench_results"
RUNS=${1:-3}
SECS=${2:-10}

mkdir -p "$RESULT_DIR"
cleanup() { kill $(pidof arca workload 2>/dev/null) 2>/dev/null; rm -f /sys/fs/bpf/task_class_map; sleep 1; }
export LD_LIBRARY_PATH=/tmp/opencode/scx-build/build/obj/libbpf

echo "=== ARCA Benchmark ($RUNS runs x ${SECS}s) ==="
echo ""

echo "--- CFS baseline ---"
for i in $(seq 1 $RUNS); do
    cleanup
    "$ARCA_ROOT/bin/workload" "$SECS" > "$RESULT_DIR/cfs_${i}.txt"
    echo -n "CFS #$i: "; grep "Interactive avg latency" "$RESULT_DIR/cfs_${i}.txt"
done

echo ""
echo "--- ARCA (sched_ext) ---"
for i in $(seq 1 $RUNS); do
    cleanup
    cd "$ARCA_ROOT" && "$ARCA_ROOT/bin/arca" > /dev/null 2>&1 &
    sleep 3
    "$ARCA_ROOT/bin/workload" "$SECS" > "$RESULT_DIR/arca_${i}.txt"
    echo -n "ARCA #$i: "; grep "Interactive avg latency" "$RESULT_DIR/arca_${i}.txt"
    cleanup
done

cleanup
echo ""
echo "Done. Results: $RESULT_DIR/"
