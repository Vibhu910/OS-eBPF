# =============================================================================
#  Unified Makefile — OS-eBPF Tracers
#  Build Options:
#    make sched    — build scheduler_deep_tracer
#    make vm       — build vm_tracer
#    make help     — show this help message
#    make clean    — remove all build artifacts
#    make clean-sched — remove scheduler tracer artifacts only
#    make clean-vm    — remove vm tracer artifacts only
# =============================================================================

# ── tools ─────────────────────────────────────────────────────────────────────
ARCH     := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CLANG    := clang
BPFTOOL  := bpftool
CC       := gcc

# ── flags ─────────────────────────────────────────────────────────────────────
BPF_CFLAGS   := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
                -I/usr/include/$(shell uname -m)-linux-gnu -I.
USER_CFLAGS  := -g -O2 -Wall
USER_LDFLAGS := -lbpf -lelf -lz

# ── shared vmlinux.h (generated once, used by both) ───────────────────────────
VMLINUX_H := vmlinux.h

# ── phony targets ─────────────────────────────────────────────────────────────
.PHONY: all sched vm clean clean-sched clean-vm help

# ── default target: show help ─────────────────────────────────────────────────
all: help

# =============================================================================
#  BUILD TARGETS
# =============================================================================

# ── shared vmlinux.h (generated once, used by both) ───────────────────────────
$(VMLINUX_H):
	@echo "[*] Generating $(VMLINUX_H) from running kernel BTF..."
	@ls /sys/kernel/btf/vmlinux > /dev/null 2>&1 || \
	    (echo "ERROR: /sys/kernel/btf/vmlinux not found — kernel BTF not enabled" && exit 1)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "[+] $(VMLINUX_H) ready ($(shell wc -l < $(VMLINUX_H)) lines)"

# ── scheduler tracer ──────────────────────────────────────────────────────────
scheduler_deep_tracer.bpf.o: scheduler_deep_tracer.bpf.c $(VMLINUX_H)
	@echo "[*] Compiling scheduler BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[+] scheduler BPF object ready"

scheduler_deep_tracer.skel.h: scheduler_deep_tracer.bpf.o
	@echo "[*] Generating scheduler skeleton header..."
	$(BPFTOOL) gen skeleton $< > $@
	@echo "[+] scheduler skeleton ready"

scheduler_deep_tracer: scheduler_deep_tracer.c scheduler_deep_tracer.skel.h
	@echo "[*] Compiling scheduler user-space loader..."
	$(CC) $(USER_CFLAGS) $< $(USER_LDFLAGS) -o $@
	@echo "[+] scheduler_deep_tracer binary ready"
	@echo "[✓] Scheduler tracer built — run with: sudo ./scheduler_deep_tracer [duration_seconds]"

sched: scheduler_deep_tracer

# ── vm tracer ─────────────────────────────────────────────────────────────────
vm_tracer.bpf.o: vm_tracer.bpf.c $(VMLINUX_H)
	@echo "[*] Compiling vm BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[+] vm BPF object ready"

vm_tracer.skel.h: vm_tracer.bpf.o
	@echo "[*] Generating vm tracer skeleton header..."
	$(BPFTOOL) gen skeleton $< > $@
	@echo "[+] vm skeleton ready"

vm_tracer: vm_tracer.c vm_tracer.skel.h
	@echo "[*] Compiling vm tracer user-space loader..."
	$(CC) $(USER_CFLAGS) $< $(USER_LDFLAGS) -o $@
	@echo "[+] vm_tracer binary ready"
	@echo "[✓] VM tracer built — run with: sudo ./vm_tracer [-p <pid> | -c <command>]"

vm: vm_tracer

# =============================================================================
#  CLEAN TARGETS
# =============================================================================

clean-sched:
	@echo "[*] Cleaning scheduler tracer artifacts..."
	rm -f scheduler_deep_tracer.bpf.o scheduler_deep_tracer.skel.h \
	      scheduler_deep_tracer
	@echo "[+] Scheduler artifacts removed"

clean-vm:
	@echo "[*] Cleaning vm tracer artifacts..."
	rm -f vm_tracer.bpf.o vm_tracer.skel.h vm_tracer
	@echo "[+] VM artifacts removed"

clean: clean-sched clean-vm
	@echo "[*] Removing shared artifacts..."
	rm -f $(VMLINUX_H)
	@echo "[+] All clean"

# =============================================================================
#  HELP
# =============================================================================

help:
	@echo ""
	@echo "  OS-eBPF Tracer — Unified Makefile"
	@echo "  ════════════════════════════════════════════════════════════"
	@echo ""
	@echo "  BUILD OPTIONS"
	@echo "    make sched         Build scheduler_deep_tracer"
	@echo "    make vm            Build vm_tracer"
	@echo ""
	@echo "  CLEAN OPTIONS"
	@echo "    make clean         Remove all build artifacts"
	@echo "    make clean-sched   Remove scheduler tracer artifacts only"
	@echo "    make clean-vm      Remove vm tracer artifacts only"
	@echo ""
	@echo "  USAGE"
	@echo "    make sched         # Build scheduler tracer"
	@echo "    make vm            # Build VM tracer"
	@echo "    make help          # Show this help message"
	@echo ""
	@echo "  REQUIREMENTS"
	@echo "    - clang, llvm"
	@echo "    - libbpf-dev"
	@echo "    - bpftool"
	@echo "    - linux-headers"
	@echo "    - kernel with BTF support"
	@echo ""
