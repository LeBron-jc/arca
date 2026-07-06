#!/bin/bash
set -e

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; NC='\033[0m'
BOLD='\033[1m'
info()  { echo -e "${GRN}[+]${NC} $*"; }
warn()  { echo -e "${YLW}[!]${NC} $*"; }
err()   { echo -e "${RED}[x]${NC} $*"; exit 1; }

ROOT=$(cd "$(dirname "$0")" && pwd)
BUILD_DIR=/tmp/arca-build
PREFIX=$BUILD_DIR/local
KERNEL_SRC=/lib/modules/$(uname -r)/build

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║     ARCA - Adaptive Resource Control Agent               ║"
echo "║     One-click deploy for openEuler 24.03 LTS-SP4        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Step 1: System check ──────────────────────────────────
info "Step 1/5: System check"
KVER=$(uname -r)
[ "$(id -u)" = "0" ] || warn "Not running as root, BPF loading will need sudo"
echo "  Kernel: $KVER"
echo "  Arch:   $(uname -m)"
echo "  CPUs:   $(nproc)"
echo "  Memory: $(free -h | awk '/Mem:/{print $2}')"
echo "  OS:     $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || echo unknown)"

# check sched_ext support
if [ -d /sys/kernel/sched_ext ]; then
    info "sched_ext: supported"
else
    err "sched_ext not available in kernel, please upgrade to 6.6+"
fi

# ── Step 2: Check/install tools ──────────────────────────
info "Step 2/5: Toolchain check"

need_build=0
CLANG=""; BPFTOOL=""; LIBBPF_A=""

# check for pre-built tools in known locations
if [ -f /tmp/opencode/scx-build/local/usr/bin/clang ]; then
    CLANG=/tmp/opencode/scx-build/local/usr/bin/clang
    CLANGXX=/tmp/opencode/scx-build/local/usr/bin/clang++
    BPFTOOL=/tmp/opencode/scx-build/bpftool/bpftool
    LIBBPF_A=/tmp/opencode/scx-build/build/obj/libbpf/libbpf.a
    info "Using existing toolchain at /tmp/opencode/scx-build/"
fi

# check system clang
if [ -z "$CLANG" ] && which clang &>/dev/null; then
    CLANG=$(which clang)
    CLANGXX=$(which clang++)
    info "Using system clang: $CLANG"
fi

# check system bpftool
if [ -z "$BPFTOOL" ] && which bpftool &>/dev/null; then
    BPFTOOL=$(which bpftool)
    info "Using system bpftool: $BPFTOOL"
fi

# if missing, try to install via dnf
if [ -z "$CLANG" ] || [ -z "$BPFTOOL" ]; then
    warn "Missing tools, attempting to install..."
    if [ "$(id -u)" = "0" ]; then
        dnf install -y clang libbpf-devel bpftool gcc gcc-c++ elfutils-libelf-devel zlib-devel 2>/dev/null || true
        CLANG=$(which clang 2>/dev/null || echo "")
        CLANGXX=$(which clang++ 2>/dev/null || echo "")
        BPFTOOL=$(which bpftool 2>/dev/null || echo "")
    else
        warn "Not root, cannot install via dnf. Ensure clang, bpftool, libbpf-devel are installed."
    fi
fi

# final check
[ -n "$CLANG" ] || err "clang not found"
[ -n "$BPFTOOL" ] || err "bpftool not found"
[ -n "$CLANGXX" ] || CLANGXX="${CLANG}++"
info "CLANG:    $CLANG"
info "CLANGXX:  $CLANGXX"
info "BPFTOOL:  $BPFTOOL"

# ── Step 3: Generate vmlinux.h ──────────────────────────
info "Step 3/5: Generate vmlinux.h"

VMLINUX_H="$BUILD_DIR/include/vmlinux.h"
mkdir -p "$(dirname "$VMLINUX_H")"

if [ -f "$VMLINUX_H" ]; then
    info "vmlinux.h exists, skipping generation"
else
    VMLINUX_BTF=$(ls /sys/kernel/btf/vmlinux /boot/vmlinux-$(uname -r) 2>/dev/null | head -1)
    if [ -z "$VMLINUX_BTF" ]; then
        # try to find vmlinux from kernel-devel
        VMLINUX_BTF=$KERNEL_SRC/vmlinux
        [ -f "$VMLINUX_BTF" ] || err "Cannot find vmlinux BTF, install kernel-devel"
    fi
    info "Generating vmlinux.h from $VMLINUX_BTF..."
    $BPFTOOL btf dump file "$VMLINUX_BTF" format c > "$VMLINUX_H"
    info "Generated: $VMLINUX_H ($(wc -c < $VMLINUX_H) bytes)"
fi

# ── Step 4: Build libbpf ────────────────────────────────
info "Step 4/5: Build libbpf"

if [ -n "$LIBBPF_A" ] && [ -f "$LIBBPF_A" ]; then
    info "libbpf already built: $LIBBPF_A"
else
    LIBBPF_SRC=$KERNEL_SRC/tools/lib/bpf
    LIBBPF_OUT=$BUILD_DIR/libbpf

    [ -d "$LIBBPF_SRC" ] || err "kernel-devel not found at $KERNEL_SRC"

    info "Building libbpf from kernel source..."
    mkdir -p "$LIBBPF_OUT"
    make -C "$LIBBPF_SRC" OUTPUT="$LIBBPF_OUT" \
        EXTRA_CFLAGS='-g -O0 -fPIC' \
        DESTDIR="$BUILD_DIR" prefix= all install_headers -j$(nproc) 2>&1 | tail -1

    LIBBPF_A="$LIBBPF_OUT/libbpf.a"
    info "libbpf built: $LIBBPF_A"
fi

# ── Step 5: Build ARCA ──────────────────────────────────
info "Step 5/5: Build ARCA"

make -C "$ROOT" clean 2>/dev/null || true

# Update Makefile variables
CLANG_PATH=$CLANG BPFTOOL_PATH=$BPFTOOL LIBBPF_PATH=$LIBBPF_A VMLINUX_PATH=$VMLINUX_H \
    make -C "$ROOT" -j$(nproc) \
    CLANG="$CLANG" \
    CLANGXX="$CLANGXX" \
    BPFTOOL="$BPFTOOL"

info "Build complete!"

# ── Summary ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
echo -e "${GRN}  ARCA deployment successful!${NC}"
echo ""
echo "  Run:"
echo "    cd $ROOT && sudo ./bin/arca"
echo ""
echo "  Benchmark:"
echo "    sudo $ROOT/tools/bench.sh"
echo ""
echo "  Files:"
echo "    bin/arca        - main agent binary"
echo "    bin/workload    - workload generator"
echo "    tools/bench.sh  - benchmark script"
echo "    arca.conf       - configuration"
echo -e "${BOLD}══════════════════════════════════════════════════════════${NC}"
