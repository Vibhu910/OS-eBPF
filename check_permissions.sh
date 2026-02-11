#!/bin/bash
# Permission checker for eBPF programs
# Run this script on your Linux VM to diagnose permission issues

echo "=========================================="
echo "eBPF Permission & Configuration Checker"
echo "=========================================="
echo ""

# 1. Check if running as root/sudo
echo "[1] Checking user permissions..."
if [ "$EUID" -eq 0 ]; then
    echo "  ✓ Running as root"
else
    echo "  ✗ NOT running as root (current user: $(whoami))"
    echo "  → Solution: Run with 'sudo' or switch to root"
fi
echo ""

# 2. Check kernel version
echo "[2] Checking kernel version..."
KERNEL=$(uname -r)
echo "  Kernel: $KERNEL"
KERNEL_MAJOR=$(echo $KERNEL | cut -d. -f1)
KERNEL_MINOR=$(echo $KERNEL | cut -d. -f2)
if [ "$KERNEL_MAJOR" -ge 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ]); then
    echo "  ✓ Kernel version >= 5.8 (good for eBPF)"
else
    echo "  ⚠ Kernel version < 5.8 (may have limited eBPF support)"
fi
echo ""

# 3. Check BTF support
echo "[3] Checking BTF (BPF Type Format) support..."
if [ -f /sys/kernel/btf/vmlinux ]; then
    SIZE=$(ls -lh /sys/kernel/btf/vmlinux | awk '{print $5}')
    echo "  ✓ BTF available: /sys/kernel/btf/vmlinux ($SIZE)"
else
    echo "  ✗ BTF NOT available: /sys/kernel/btf/vmlinux not found"
    echo "  → Solution: Recompile kernel with CONFIG_DEBUG_INFO_BTF=y"
    echo "  → Or use a distribution kernel that includes BTF (Ubuntu 20.04+, Fedora 33+)"
fi
echo ""

# 4. Check BPF filesystem
echo "[4] Checking BPF filesystem..."
if mountpoint -q /sys/fs/bpf 2>/dev/null; then
    echo "  ✓ BPF filesystem mounted at /sys/fs/bpf"
elif [ -d /sys/fs/bpf ]; then
    echo "  ⚠ /sys/fs/bpf exists but may not be mounted"
    echo "  → Try: sudo mount -t bpf none /sys/fs/bpf"
else
    echo "  ✗ BPF filesystem not found"
    echo "  → Solution: sudo mount -t bpf none /sys/fs/bpf"
fi
echo ""

# 5. Check unprivileged BPF setting
echo "[5] Checking unprivileged_bpf_disabled setting..."
if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
    VALUE=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
    case $VALUE in
        0)
            echo "  ✓ Unprivileged BPF: ENABLED (0)"
            echo "    → Non-root users can use BPF"
            ;;
        1)
            echo "  ⚠ Unprivileged BPF: DISABLED (1)"
            echo "    → Only root can use BPF (this is OK if using sudo)"
            ;;
        2)
            echo "  ⚠ Unprivileged BPF: PERMANENTLY DISABLED (2)"
            echo "    → Only root can use BPF (this is OK if using sudo)"
            ;;
    esac
else
    echo "  ⚠ Cannot read unprivileged_bpf_disabled (may be old kernel)"
fi
echo ""

# 6. Check SELinux/AppArmor
echo "[6] Checking security modules..."
if command -v getenforce &> /dev/null; then
    SELINUX=$(getenforce 2>/dev/null)
    if [ "$SELINUX" = "Enforcing" ]; then
        echo "  ⚠ SELinux is Enforcing (may block BPF)"
        echo "  → Check: sudo ausearch -m avc -ts recent | grep bpf"
        echo "  → May need to set SELinux to permissive: sudo setenforce 0"
    elif [ "$SELINUX" = "Permissive" ]; then
        echo "  ✓ SELinux is Permissive"
    else
        echo "  ✓ SELinux is Disabled"
    fi
else
    echo "  → SELinux not found"
fi

if [ -d /sys/kernel/security/apparmor ]; then
    echo "  → AppArmor detected (check profiles if issues occur)"
fi
echo ""

# 7. Check required tools
echo "[7] Checking required tools..."
TOOLS=("clang" "bpftool" "gcc")
MISSING=0
for tool in "${TOOLS[@]}"; do
    if command -v $tool &> /dev/null; then
        VERSION=$($tool --version 2>/dev/null | head -1)
        echo "  ✓ $tool: installed"
    else
        echo "  ✗ $tool: NOT installed"
        MISSING=1
    fi
done

if [ $MISSING -eq 1 ]; then
    echo ""
    echo "  → Install missing tools:"
    echo "    Ubuntu/Debian: sudo apt-get install clang llvm libbpf-dev bpftool linux-headers-\$(uname -r)"
    echo "    Fedora/RHEL: sudo dnf install clang llvm libbpf-devel bpftool kernel-devel"
fi
echo ""

# 8. Check libbpf
echo "[8] Checking libbpf library..."
if ldconfig -p 2>/dev/null | grep -q libbpf; then
    echo "  ✓ libbpf library found"
else
    echo "  ✗ libbpf library NOT found"
    echo "  → Install: sudo apt-get install libbpf-dev (Ubuntu/Debian)"
    echo "  → Or: sudo dnf install libbpf-devel (Fedora/RHEL)"
fi
echo ""

# 9. Test BPF syscall
echo "[9] Testing BPF syscall access..."
if [ "$EUID" -eq 0 ]; then
    # Try a simple BPF operation as root
    if command -v bpftool &> /dev/null; then
        if bpftool version &> /dev/null; then
            echo "  ✓ bpftool can execute (BPF syscall accessible)"
        else
            echo "  ✗ bpftool failed (BPF syscall may be blocked)"
        fi
    else
        echo "  ⚠ Cannot test (bpftool not installed)"
    fi
else
    echo "  → Skipping (run as root to test BPF syscall)"
fi
echo ""

# 10. Summary
echo "=========================================="
echo "Summary & Recommendations"
echo "=========================================="
echo ""
echo "To run eBPF tracers, ensure:"
echo "  1. Run with: sudo ./vm_tracer -c 'ls -la'"
echo "  2. Kernel has BTF support (check [3] above)"
echo "  3. All required tools installed (check [7] above)"
echo ""
echo "If error -13 persists:"
echo "  - Verify you're using 'sudo'"
echo "  - Check SELinux/AppArmor logs"
echo "  - Ensure kernel >= 5.8 with BTF enabled"
echo "  - Try: sudo mount -t bpf none /sys/fs/bpf"
echo ""
