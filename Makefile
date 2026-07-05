KERNEL_SRC := /lib/modules/$(shell uname -r)/build
CLANG := /tmp/opencode/scx-build/local/usr/bin/clang
CLANGXX := /tmp/opencode/scx-build/local/usr/bin/clang++
BPFTOOL := /tmp/opencode/scx-build/bpftool/bpftool
LD_LIBS := /tmp/opencode/scx-build/local/usr/lib64
LOCAL_PREFIX := /tmp/opencode/scx-build/local

BUILD_DIR := /tmp/opencode/scx-build/build
SCX_INC  := $(KERNEL_SRC)/tools/sched_ext/include
SCX_BPF_INC := $(SCX_INC)/bpf-compat
TOOLS_INC := $(KERNEL_SRC)/tools/include
TOOLS_UAPI := $(TOOLS_INC)/uapi
GEN_INC := $(KERNEL_SRC)/include/generated
VMLINUX_H := $(BUILD_DIR)/include/vmlinux.h
VMLINUX_DIR := $(dir $(VMLINUX_H))
LIBBPF_A := $(BUILD_DIR)/obj/libbpf/libbpf.a
LIBBPF_INCLUDE := $(BUILD_DIR)/include
CLANG_INC := $(LD_LIBS)/clang/17/include

CXXFLAGS := -std=c++11 -g -O2 -Wall \
	-I. -I$(LOCAL_PREFIX)/usr/include \
	-I$(LOCAL_PREFIX)/usr/include/c++/12 \
	-I$(LOCAL_PREFIX)/usr/include/c++/12/x86_64-openEuler-linux \
	-I/usr/include \
	-I$(LIBBPF_INCLUDE) -I$(GEN_INC) -I$(KERNEL_SRC)/tools/lib \
	-I$(TOOLS_INC) -I$(TOOLS_UAPI) -I$(SCX_INC)

CFLAGS_C := -g -O2 -rdynamic -Wall -DHAVE_GENHDR \
	-I$(LIBBPF_INCLUDE) -I$(GEN_INC) -I$(KERNEL_SRC)/tools/lib \
	-I$(TOOLS_INC) -I$(TOOLS_UAPI) -I$(SCX_INC) -I.

LDFLAGS := -L$(LOCAL_PREFIX)/usr/lib64 \
	-L$(BUILD_DIR)/obj/libbpf \
	-Wl,-rpath,$(LOCAL_PREFIX)/usr/lib64

BPF_BASE := -g -O2 -Wall -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 -mlittle-endian \
	-I$(VMLINUX_DIR) \
	-idirafter $(CLANG_INC) \
	-idirafter /usr/local/include -idirafter /usr/include

all: arca workload arca_trace.bpf.o

$(VMLINUX_H):
	$(error vmlinux.h missing, build scx_simple first)

# ---- eBPF objects ----
arca_trace.bpf.o: arca_trace.bpf.c arca.h $(VMLINUX_H)
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANG) $(BPF_BASE) -c $< -o $@

network_trace.bpf.o: network_trace.bpf.c $(VMLINUX_H)
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANG) $(BPF_BASE) -c $< -o $@

network_skill.skel.h: network_trace.bpf.o
	$(BPFTOOL) gen object net_trace.l1.o $<
	$(BPFTOOL) gen object net_trace.l2.o net_trace.l1.o
	$(BPFTOOL) gen object net_trace.l3.o net_trace.l2.o
	$(BPFTOOL) gen skeleton net_trace.l3.o name network_skill > $@

security_trace.bpf.o: security_trace.bpf.c $(VMLINUX_H)
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANG) $(BPF_BASE) -c $< -o $@

security_skill.skel.h: security_trace.bpf.o
	$(BPFTOOL) gen object sec_trace.l1.o $<
	$(BPFTOOL) gen object sec_trace.l2.o sec_trace.l1.o
	$(BPFTOOL) gen object sec_trace.l3.o sec_trace.l2.o
	$(BPFTOOL) gen skeleton sec_trace.l3.o name security_skill > $@

arca_sched.bpf.o: arca_sched.bpf.c arca.h arca_sched.h $(VMLINUX_H)
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANG) $(BPF_BASE) \
		-I$(SCX_INC) -I$(SCX_BPF_INC) -I$(TOOLS_UAPI) \
		-I$(KERNEL_SRC)/../../include \
		-c $< -o $@

arca_sched.bpf.skel.h: arca_sched.bpf.o
	$(BPFTOOL) gen object scx.l1.o $<
	$(BPFTOOL) gen object scx.l2.o scx.l1.o
	$(BPFTOOL) gen object scx.l3.o scx.l2.o
	$(BPFTOOL) gen skeleton scx.l3.o name arca_sched > $@

# ---- C objects ----
arca_scx_ops.o: arca_scx_ops.c arca_sched.bpf.skel.h arca.h
	gcc $(CFLAGS_C) -c $< -o $@

# ---- C++ objects ----
cpu_skill.o: cpu_skill.cpp cpu_skill.h skill.h arca.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

network_skill.o: network_skill.cpp network_skill.h skill.h network_skill.skel.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

resource_skill.o: resource_skill.cpp resource_skill.h skill.h config.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

security_skill.o: security_skill.cpp security_skill.h skill.h security_skill.skel.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

arca.o: arca.cpp skill.h skill_manager.h cpu_skill.h network_skill.h resource_skill.h security_skill.h dashboard.h config.h
	LD_LIBRARY_PATH=$(LD_LIBS) $(CLANGXX) $(CXXFLAGS) -c $< -o $@

# ---- link ----
arca: arca.o cpu_skill.o network_skill.o resource_skill.o security_skill.o arca_scx_ops.o $(LIBBPF_A)
	gcc -o $@ $^ $(LDFLAGS) -lelf -lz -lstdc++

workload: workload.c
	gcc -O2 -o $@ $< -lpthread -lm

clean:
	rm -f *.o *.bpf.o *.l1.o *.l2.o *.l3.o
	rm -f arca_sched.bpf.skel.h network_skill.skel.h security_skill.skel.h
	rm -f arca workload arca_sched arca_agent arca_agent_v2

.PHONY: all clean
