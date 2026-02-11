#!/bin/bash
# Debug script for eBPF error -13
# Run this on your Linux VM to get detailed error information

echo "=========================================="
echo "eBPF Error -13 Debugging Script"
echo "=========================================="
echo ""

# 1. Check AppArmor denials
echo "[1] Checking AppArmor denials..."
if command -v aa-status &> /dev/null; then
    DENIALS=$(sudo dmesg | grep -i "apparmor.*denied" | tail -10)
    if [ -n "$DENIALS" ]; then
        echo "  ⚠ AppArmor denials found:"
        echo "$DENIALS" | sed 's/^/    /'
        echo ""
        echo "  → Try: sudo aa-complain /path/to/vm_tracer"
        echo "  → Or check: sudo dmesg | grep -i apparmor"
    else
        echo "  ✓ No recent AppArmor denials"
    fi
else
    echo "  → AppArmor tools not available"
fi
echo ""

# 2. Check kernel messages
echo "[2] Checking kernel messages for BPF errors..."
BPF_ERRORS=$(sudo dmesg | grep -i "bpf\|ebpf" | tail -20)
if [ -n "$BPF_ERRORS" ]; then
    echo "  Recent BPF-related kernel messages:"
    echo "$BPF_ERRORS" | sed 's/^/    /'
else
    echo "  ✓ No recent BPF errors in kernel log"
fi
echo ""

# 3. Check system logs
echo "[3] Checking system logs..."
if [ -f /var/log/syslog ]; then
    SYSLOG_BPF=$(grep -i "bpf\|ebpf" /var/log/syslog 2>/dev/null | tail -10)
    if [ -n "$SYSLOG_BPF" ]; then
        echo "  Recent syslog entries:"
        echo "$SYSLOG_BPF" | sed 's/^/    /'
    fi
elif [ -f /var/log/messages ]; then
    MSG_BPF=$(grep -i "bpf\|ebpf" /var/log/messages 2>/dev/null | tail -10)
    if [ -n "$MSG_BPF" ]; then
        echo "  Recent messages log entries:"
        echo "$MSG_BPF" | sed 's/^/    /'
    fi
fi
echo ""

# 4. Test BPF program loading with verbose output
echo "[4] Testing BPF program load with verbose libbpf..."
echo "  → This will show detailed error information"
echo ""
echo "  Run this command to see detailed errors:"
echo "    sudo LIBBPF_LOG_LEVEL=2 ./vm_tracer -c 'ls' 2>&1 | head -50"
echo ""

# 5. Check BPF program features
echo "[5] Checking if BPF program uses restricted features..."
if [ -f vm_tracer.bpf.o ]; then
    echo "  Analyzing vm_tracer.bpf.o..."
    if command -v readelf &> /dev/null; then
        echo "  BPF program sections:"
        readelf -S vm_tracer.bpf.o 2>/dev/null | grep -E "^\s*\[" | head -20
    fi
    
    if command -v bpftool &> /dev/null; then
        echo ""
        echo "  → Try loading manually to see detailed error:"
        echo "    sudo bpftool prog load vm_tracer.bpf.o /sys/fs/bpf/vm_tracer"
    fi
else
    echo "  ⚠ vm_tracer.bpf.o not found (build first with 'make vm')"
fi
echo ""

# 6. Check capabilities
echo "[6] Checking process capabilities..."
if command -v getcap &> /dev/null; then
    if [ -f ./vm_tracer ]; then
        CAPS=$(getcap ./vm_tracer 2>/dev/null)
        if [ -n "$CAPS" ]; then
            echo "  File capabilities: $CAPS"
        else
            echo "  → No file capabilities set"
        fi
    fi
fi
echo ""

# 7. Check cgroup v2 (some BPF features require it)
echo "[7] Checking cgroup configuration..."
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "  ✓ cgroup v2 detected"
    CONTROLLERS=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)
    echo "  Controllers: $CONTROLLERS"
else
    echo "  → cgroup v1 or not mounted (usually OK for basic BPF)"
fi
echo ""

# 8. Check kernel config for BPF features
echo "[8] Checking kernel BPF configuration..."
if [ -f /proc/config.gz ]; then
    echo "  Checking kernel config..."
    if zgrep -q "CONFIG_BPF=y" /proc/config.gz 2>/dev/null; then
        echo "  ✓ CONFIG_BPF=y"
    else
        echo "  ✗ CONFIG_BPF not enabled"
    fi
    
    if zgrep -q "CONFIG_BPF_SYSCALL=y" /proc/config.gz 2>/dev/null; then
        echo "  ✓ CONFIG_BPF_SYSCALL=y"
    else
        echo "  ✗ CONFIG_BPF_SYSCALL not enabled"
    fi
    
    if zgrep -q "CONFIG_BPF_JIT=y" /proc/config.gz 2>/dev/null; then
        echo "  ✓ CONFIG_BPF_JIT=y"
    else
        echo "  ✗ CONFIG_BPF_JIT not enabled"
    fi
else
    echo "  → /proc/config.gz not available (check /boot/config-$(uname -r))"
fi
echo ""

# 9. Recommendations
echo "=========================================="
echo "Troubleshooting Steps"
echo "=========================================="
echo ""
echo "1. Run with verbose libbpf logging:"
echo "   sudo LIBBPF_LOG_LEVEL=2 ./vm_tracer -c 'ls' 2>&1"
echo ""
echo "2. Check AppArmor status:"
echo "   sudo aa-status"
echo "   sudo dmesg | grep -i apparmor | tail -20"
echo ""
echo "3. Try putting vm_tracer in complain mode:"
echo "   sudo aa-complain $(pwd)/vm_tracer"
echo ""
echo "4. Check kernel messages in real-time:"
echo "   sudo dmesg -w"
echo "   (Then in another terminal, run: sudo ./vm_tracer -c 'ls')"
echo ""
echo "5. Verify the BPF object was built correctly:"
echo "   file vm_tracer.bpf.o"
echo "   bpftool prog load vm_tracer.bpf.o /sys/fs/bpf/test"
echo ""
echo "6. Check if it's a specific BPF program feature:"
echo "   bpftool feature probe"
echo ""
