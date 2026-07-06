#!/bin/bash
# ARCA One-click Start
ROOT=$(cd "$(dirname "$0")" && pwd)
LD_PATH="/tmp/opencode/scx-build/build/obj/libbpf"

cleanup() {
    sudo kill $(pidof arca 2>/dev/null) 2>/dev/null || true
    sudo rm -f /sys/fs/bpf/task_class_map 2>/dev/null || true
}

case "${1:-start}" in
start)
    cleanup; sleep 1
    echo "[ARCA] Starting..."
    cd "$ROOT"
    sudo LD_LIBRARY_PATH="$LD_PATH" ./bin/arca
    ;;

stop)
    echo "[ARCA] Stopping..."
    sudo kill $(pidof arca 2>/dev/null) 2>/dev/null || true
    sleep 1
    echo "[ARCA] State: $(sudo cat /sys/kernel/sched_ext/state 2>/dev/null || echo stopped)"
    ;;

status)
    echo "ARCA process: $(pidof arca || echo none)"
    echo "SCX state:    $(sudo cat /sys/kernel/sched_ext/state 2>/dev/null || echo disabled)"
    echo "Pinned maps:  $(sudo ls /sys/fs/bpf/ 2>/dev/null || echo none)"
    ;;

restart)
    "$0" stop
    sleep 1
    "$0" start
    ;;

*)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac
