# Makefile for scheduler_deep_tracer
# Requires: clang, llvm, libbpf-dev, bpftool, linux-headers, linux kernel with BTF

# ── tunables ────────────────────────────────────────────────────────────────
TARGET       := scheduler_deep_tracer
BPF_SRC      := $(TARGET).bpf.c
USER_SRC     := $(TARGET).c
BPF_OBJ      := $(TARGET).bpf.o
SKEL_HDR     := $(TARGET).skel.h
USER_BIN     := $(TARGET)

ARCH         := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
VMLINUX_H    := vmlinux.h

# ── tools ───────────────────────────────────────────────────────────────────
CLANG        := clang
BPFTOOL      := bpftool
CC           := gcc

# ── flags ───────────────────────────────────────────────────────────────────
BPF_CFLAGS   := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
                -I/usr/include/$(shell uname -m)-linux-gnu \
                -I.

USER_CFLAGS  := -g -O2 -Wall
USER_LDFLAGS := -lbpf -lelf -lz

# ── default target ──────────────────────────────────────────────────────────
.PHONY: all clean

all: $(USER_BIN)

# Step 1: Generate vmlinux.h from the running kernel's BTF
$(VMLINUX_H):
	@echo "[*] Generating $(VMLINUX_H) from kernel BTF..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
	@echo "[+] $(VMLINUX_H) generated"

# Step 2: Compile the BPF kernel-side program to BPF bytecode
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H)
	@echo "[*] Compiling BPF program..."
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "[+] $(BPF_OBJ) compiled"

# Step 3: Generate the skeleton header from the BPF object
$(SKEL_HDR): $(BPF_OBJ)
	@echo "[*] Generating BPF skeleton header..."
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL_HDR)
	@echo "[+] $(SKEL_HDR) generated"

# Step 4: Compile and link the user-space loader
$(USER_BIN): $(USER_SRC) $(SKEL_HDR)
	@echo "[*] Compiling user-space loader..."
	$(CC) $(USER_CFLAGS) $(USER_SRC) $(USER_LDFLAGS) -o $(USER_BIN)
	@echo "[+] $(USER_BIN) built — run with: sudo ./$(USER_BIN) [duration_seconds]"

# ── cleanup ─────────────────────────────────────────────────────────────────
clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(VMLINUX_H) $(USER_BIN)
