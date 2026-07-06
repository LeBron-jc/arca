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
        grep "Interactive avg" "$RESULT_DIR/${profile}_cfs_$i.txt"

        cleanup
        sudo LD_LIBRARY_PATH="$LD_PATH" "$ROOT/bin/arca" > /dev/null 2>&1 &
        sleep 4
        sudo "$ROOT/bin/workload" -p "$profile" "$SECS" > "$RESULT_DIR/${profile}_arca_$i.txt" 2>/dev/null
        echo -n "  ARCA #$i: "
        grep "Interactive avg" "$RESULT_DIR/${profile}_arca_$i.txt"
        cleanup
    done
}

echo "ARCA Multi-Scenario Benchmark"
echo "Profiles: web(2C+6I) db(3C+3I+2B) batch(4C+1I+3B) mixed(4C+2I+2B)"
echo ""

run "web"   "Web Server"
run "db"    "Database"
run "batch" "Batch Proc"
run "mixed" "Mixed "

echo ""
echo "═══ Summary ═══"
printf "%-8s %-10s %-10s %s\n" "Profile" "CFS(us)" "ARCA(us)" "Diff"
for p in web db batch mixed; do
    cfs=$(grep -h "Interactive avg" "$RESULT_DIR/${p}_cfs_"*.txt 2>/dev/null | grep -oP '[\d.]+' 2>/dev/null | awk '{s+=$1;n++}END{printf "%.0f",s/n}' || echo 0)
    arca=$(grep -h "Interactive avg" "$RESULT_DIR/${p}_arca_"*.txt 2>/dev/null | grep -oP '[\d.]+' 2>/dev/null | awk '{s+=$1;n++}END{printf "%.0f",s/n}' || echo 0)
    diff="N/A"
    [ "$cfs" != "0" ] && [ "$arca" != "0" ] && diff=$(awk "BEGIN{printf \"%+.0f%%\",($cfs-$arca)*100/$cfs}")
    printf "%-8s %-10s %-10s %s\n" "$p" "${cfs}us" "${arca}us" "$diff"
done

echo ""
echo "Results: $RESULT_DIR/"
cleanup
