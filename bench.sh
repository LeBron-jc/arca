#!/bin/bash
ARCA_ROOT="/home/cuijian/arca"
RESULT_DIR="$ARCA_ROOT/bench_results"
RUNS=${1:-3}
SECS=${2:-10}

mkdir -p "$RESULT_DIR"
cleanup() { kill $(pidof arca workload 2>/dev/null) 2>/dev/null; rm -f /sys/fs/bpf/task_class_map; sleep 1; }

export LD_LIBRARY_PATH=/tmp/opencode/scx-build/build/obj/libbpf
make -C "$ARCA_ROOT" -s workload arca

echo "=== ARCA Benchmark ($RUNS runs x ${SECS}s) ==="
echo ""

# CFS
echo "--- CFS baseline ---"
for i in $(seq 1 $RUNS); do
    cleanup
    "$ARCA_ROOT/workload" "$SECS" > "$RESULT_DIR/cfs_${i}.txt"
    echo -n "CFS #$i: "
    grep "Interactive avg latency" "$RESULT_DIR/cfs_${i}.txt"
done

# ARCA
echo ""
echo "--- ARCA (sched_ext) ---"
for i in $(seq 1 $RUNS); do
    cleanup
    "$ARCA_ROOT/arca" > /dev/null 2>&1 &
    sleep 2
    "$ARCA_ROOT/workload" "$SECS" > "$RESULT_DIR/arca_${i}.txt"
    echo -n "ARCA #$i: "
    grep "Interactive avg latency" "$RESULT_DIR/arca_${i}.txt"
    cleanup
done

echo ""
echo "=== Summary ==="
printf "%-10s %s\n" "Run" "Interactive Latency (us)"
echo "-------------------------"
for i in $(seq 1 $RUNS); do
    cfs_lat=$(grep "Interactive avg latency" "$RESULT_DIR/cfs_${i}.txt" | grep -oP '[\d.]+' | tail -1)
    arca_lat=$(grep "Interactive avg latency" "$RESULT_DIR/arca_${i}.txt" | grep -oP '[\d.]+' | tail -1)
    printf "CFS  #%d  %s us\n" $i "$cfs_lat"
    printf "ARCA #%d  %s us\n" $i "$arca_lat"
done

cleanup
echo ""
echo "ARCA agent log sample:"
grep "ARCA.*events" "$ARCA_ROOT/arca" 2>/dev/null || echo "(run 'sudo ./arca &' manually to see live output)"
