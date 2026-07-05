KERNEL_SRC := /lib/modules/$(shell uname -r)/build
CLANG     := /tmp/opencode/scx-build/local/usr/bin/clang
CLANGXX   := /tmp/opencode/scx-build/local/usr/bin/clang++
BPFTOOL   := /tmp/opencode/scx-build/bpftool/bpftool
LD_LIBS   := /tmp/opencode/scx-build/local/usr/lib64
LOCAL_PFX := /tmp/opencode/scx-build/local

BUILD_DIR   := /tmp/opencode/scx-build/build
SCX_INC     := $(KERNEL_SRC)/tools/sched_ext/include
SCX_BPF_INC := $(SCX_INC)/bpf-compat
TOOLS_INC   := $(KERNEL_SRC)/tools/include
TOOLS_UAPI  := $(TOOLS_INC)/uapi
GEN_INC     := $(KERNEL_SRC)/include/generated
VMLINUX_H   := $(BUILD_DIR)/include/vmlinux.h
VMLINUX_DIR := $(dir $(VMLINUX_H))
LIBBPF_A    := $(BUILD_DIR)/obj/libbpf/libbpf.a
LIBBPF_INC  := $(BUILD_DIR)/include
CLANG_INC   := $(LD_LIBS)/clang/17/include

INC := -I./include -I./skills/cpu -I./skills/network -I./skills/resource -I./skills/security

CXXFLAGS := -std=c++11 -g -O2 -Wall $(INC) \
	-I$(LOCAL_PFX)/usr/include \
	-I$(LOCAL_PFX)/usr/include/c++/12 \
	-I$(LOCAL_PFX)/usr/include/c++/12/x86_64-openEuler-linux \
	-I/usr/include -I$(LIBBPF_INC) -I$(GEN_INC) \
	-I$(KERNEL_SRC)/tools/lib -I$(TOOLS_INC) -I$(TOOLS_UAPI) -I$(SCX_INC)

CFLAGS_C := -g -O2 -rdynamic -Wall -DHAVE_GENHDR $(INC) \
	-I$(LIBBPF_INC) -I$(GEN_INC) -I$(KERNEL_SRC)/tools/lib \
	-I$(TOOLS_INC) -I$(TOOLS_UAPI) -I$(SCX_INC)

LDFLAGS := -L$(LOCAL_PFX)/usr/lib64 -L$(BUILD_DIR)/obj/libbpf \
	-Wl,-rpath,$(LOCAL_PFX)/usr/lib64

BPF_BASE := -g -O2 -Wall -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 -mlittle-endian \
	$(INC) -I$(VMLINUX_DIR) \
	-idirafter $(CLANG_INC) -idirafter /usr/local/include -idirafter /usr/include

all: bin/arca bin/workload

bin:
	mkdir -p bin

$(VMLINUX_H):
	$(error vmlinux.h missing, build scx_simple first)

# ---- eBPF objects ----
skills/cpu/arca_trace.bpf.o: skills/cpu/arca_trace.bpf.c include/arca.h $(VMLINUX_H)
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANG) $(BPF_BASE) -c $< -o $@

skills/network/network_trace.bpf.o: skills/network/network_trace.bpf.c $(VMLINUX_H)
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANG) $(BPF_BASE) -c $< -o $@

skills/network/network_skill.skel.h: skills/network/network_trace.bpf.o
	$(BPFTOOL) gen object /tmp/net_t1.o $<
	$(BPFTOOL) gen object /tmp/net_t2.o /tmp/net_t1.o
	$(BPFTOOL) gen object /tmp/net_t3.o /tmp/net_t2.o
	$(BPFTOOL) gen skeleton /tmp/net_t3.o name network_skill > $@

skills/security/security_trace.bpf.o: skills/security/security_trace.bpf.c $(VMLINUX_H)
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANG) $(BPF_BASE) -c $< -o $@

skills/security/security_skill.skel.h: skills/security/security_trace.bpf.o
	$(BPFTOOL) gen object /tmp/sec_t1.o $<
	$(BPFTOOL) gen object /tmp/sec_t2.o /tmp/sec_t1.o
	$(BPFTOOL) gen object /tmp/sec_t3.o /tmp/sec_t2.o
	$(BPFTOOL) gen skeleton /tmp/sec_t3.o name security_skill > $@

skills/cpu/arca_sched.bpf.o: skills/cpu/arca_sched.bpf.c include/arca.h include/arca_sched.h $(VMLINUX_H)
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANG) $(BPF_BASE) \
		-I$(SCX_INC) -I$(SCX_BPF_INC) -I$(TOOLS_UAPI) \
		-I$(KERNEL_SRC)/../../include \
		-c $< -o $@

skills/cpu/arca_sched.bpf.skel.h: skills/cpu/arca_sched.bpf.o
	$(BPFTOOL) gen object /tmp/scx_t1.o $<
	$(BPFTOOL) gen object /tmp/scx_t2.o /tmp/scx_t1.o
	$(BPFTOOL) gen object /tmp/scx_t3.o /tmp/scx_t2.o
	$(BPFTOOL) gen skeleton /tmp/scx_t3.o name arca_sched > $@

# ---- C objects ----
skills/cpu/arca_scx_ops.o: skills/cpu/arca_scx_ops.c skills/cpu/arca_sched.bpf.skel.h include/arca.h
	gcc $(CFLAGS_C) -c $< -o $@

# ---- C++ objects ----
skills/cpu/cpu_skill.o: skills/cpu/cpu_skill.cpp skills/cpu/cpu_skill.h include/skill.h include/config.h include/arca.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

skills/network/network_skill.o: skills/network/network_skill.cpp skills/network/network_skill.h include/skill.h skills/network/network_skill.skel.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

skills/resource/resource_skill.o: skills/resource/resource_skill.cpp skills/resource/resource_skill.h include/skill.h include/config.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

skills/security/security_skill.o: skills/security/security_skill.cpp skills/security/security_skill.h include/skill.h skills/security/security_skill.skel.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

src/arca.o: src/arca.cpp include/*.h skills/*/**.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

# ---- link ----
SRCS := src/arca.o
SRCS += skills/cpu/cpu_skill.o skills/cpu/arca_scx_ops.o
SRCS += skills/network/network_skill.o
SRCS += skills/resource/resource_skill.o
SRCS += skills/security/security_skill.o

bin/arca: $(SRCS) $(LIBBPF_A) | bin
	gcc -o $@ $(SRCS) $(LIBBPF_A) $(LDFLAGS) -lelf -lz -lstdc++

bin/workload: tools/workload.c | bin
	gcc -O2 -o $@ $< -lpthread -lm

clean:
	rm -f skills/*/*.o skills/*/*.bpf.o skills/*/*.skel.h
	rm -f /tmp/net_t*.o /tmp/sec_t*.o /tmp/scx_t*.o
	rm -rf bin

.PHONY: all clean
