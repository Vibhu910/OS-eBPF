#!/bin/bash
# Example workloads for testing the eBPF tracer

set -e

[ $# -eq 0 ] && {
    echo "Usage: $0 [workload_number]"
    echo "  1 - CPU-intensive (scheduling)"
    echo "  2 - Memory-intensive (page faults)"
    echo "  3 - File I/O (VFS/d_entry)"
    echo "  4 - Process creation (fork/exec)"
    echo "  5 - mmap operations"
    echo "  6 - Combined workload"
    exit 0
}

workload_cpu() {
    echo "Workload 1: CPU-intensive (4 processes)"
    for i in {1..4}; do (while true; do :; done) & done
    sleep 5
    killall -9 bash 2>/dev/null || true
}

workload_memory() {
    echo "Workload 2: Memory-intensive"
    python3 << 'EOF'
import mmap
for i in range(10):
    mem = mmap.mmap(-1, 10 * 1024 * 1024)
    for j in range(0, len(mem), 4096):
        mem[j] = 0
    mem.close()
EOF
}

workload_io() {
    echo "Workload 3: File I/O operations"
    mkdir -p /tmp/tracer_test
    for i in {1..100}; do
        echo "test $i" > "/tmp/tracer_test/file_$i"
        cat "/tmp/tracer_test/file_$i" > /dev/null
    done
    rm -rf /tmp/tracer_test
}

workload_processes() {
    echo "Workload 4: Process creation"
    for i in {1..20}; do
        ls -la /tmp > /dev/null &
        ps aux | head -5 > /dev/null &
    done
    wait
}

workload_mmap() {
    echo "Workload 5: mmap operations"
    python3 << 'EOF'
import mmap, os
with open('/tmp/mmap_test', 'w+b') as f:
    f.write(b'0' * (1024 * 1024))
    mm = mmap.mmap(f.fileno(), 0)
    mm[0:100] = b'X' * 100
    mm.close()
os.unlink('/tmp/mmap_test')
EOF
}

workload_combined() {
    echo "Workload 6: Combined"
    workload_cpu & CPU_PID=$!
    workload_memory & MEM_PID=$!
    workload_io & IO_PID=$!
    wait $CPU_PID $MEM_PID $IO_PID 2>/dev/null || true
}

case "$1" in
    1) workload_cpu ;;
    2) workload_memory ;;
    3) workload_io ;;
    4) workload_processes ;;
    5) workload_mmap ;;
    6) workload_combined ;;
    *) echo "Invalid workload: $1"; exit 1 ;;
esac

echo "Workload completed!"
