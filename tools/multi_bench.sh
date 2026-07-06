#!/bin/bash
set -e

ROOT=$(cd "$(dirname "$0")/.." && pwd)
RESULT_DIR="$ROOT/bench_results"
LD_PATH="/tmp/opencode/scx-build/build/obj/libbpf"
SECS=${1:-10}

mkdir -p "$RESULT_DIR"
make -C "$ROOT" -s

cleanup() {
    sudo kill $(pidof arca workload 2>/dev/null) 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/task_class_map 2>/dev/null || true
    sleep 1
}

run() {
    local profile="$1" label="$2"
    echo ""
    echo "═══ $label ($profile) ═══"

    for i in 1 2; do
        cleanup
        sudo "$ROOT/bin/workload" -p "$profile" "$SECS" > "$RESULT_DIR/${profile}_cfs_$i.txt" 2>/dev/null
        echo -n "  CFS #$i:  "
        grep "Interactive avg\|p50\|p95\|p99" "$RESULT_DIR/${profile}_cfs_$i.txt" | head -4 | paste -sd'| '

        cleanup
        sudo LD_LIBRARY_PATH="$LD_PATH" "$ROOT/bin/arca" > /dev/null 2>&1 &
        sleep 4
        sudo "$ROOT/bin/workload" -p "$profile" "$SECS" > "$RESULT_DIR/${profile}_arca_$i.txt" 2>/dev/null
        echo -n "  ARCA #$i: "
        grep "Interactive avg\|p50\|p95\|p99" "$RESULT_DIR/${profile}_arca_$i.txt" | head -4 | paste -sd'| '
        cleanup
    done
}

echo "ARCA Multi-Scenario Benchmark"
echo ""

run "web"   "Web Server"
run "db"    "Database"
run "batch" "Batch Proc"
run "mixed" "Mixed"

echo ""
echo "═══ Summary (Interactive Latency) ═══"
printf "%-8s %-8s %-8s %-8s %-8s\n" "Profile" "Metric" "CFS" "ARCA" "Diff"
for p in web db batch mixed; do
    cfs_avg=$(grep -h "Interactive avg" "$RESULT_DIR/${p}_cfs_"*.txt 2>/dev/null | grep -oP '[\d.]+' | awk '{s+=$1;n++}END{printf "%.0f",s/n}')
    arca_avg=$(grep -h "Interactive avg" "$RESULT_DIR/${p}_arca_"*.txt 2>/dev/null | grep -oP '[\d.]+' | awk '{s+=$1;n++}END{printf "%.0f",s/n}')
    diff="N/A"
    [ "$cfs_avg" != "0" ] && [ "$arca_avg" != "0" ] && diff=$(awk "BEGIN{printf \"%+.0f%%\",($cfs_avg-$arca_avg)*100/$cfs_avg}")
    printf "%-8s %-8s %-8s %-8s %-8s\n" "$p" "avg" "${cfs_avg}us" "${arca_avg}us" "$diff"

    cfs_p99=$(grep -h "p99(us)" "$RESULT_DIR/${p}_cfs_"*.txt 2>/dev/null | grep -oP '[\d.]+' | head -1)
    arca_p99=$(grep -h "p99(us)" "$RESULT_DIR/${p}_arca_"*.txt 2>/dev/null | grep -oP '[\d.]+' | head -1)
    diff99="N/A"
    [ -n "$cfs_p99" ] && [ -n "$arca_p99" ] && [ "$cfs_p99" != "0" ] && diff99=$(awk "BEGIN{printf \"%+.0f%%\",($cfs_p99-$arca_p99)*100/$cfs_p99}")
    printf "%-8s %-8s %-8s %-8s %-8s\n" "$p" "p99" "${cfs_p99}us" "${arca_p99}us" "$diff99"
done

echo ""
echo "Results: $RESULT_DIR/"
cleanup
