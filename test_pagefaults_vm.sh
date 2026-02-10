#!/bin/bash
# Automation for Requirement 3: Page Faults and VM Operations
# Tests: Virtual addresses of page faults, VM area changes (mmap, etc.)
# Usage: sudo ./test_pagefaults_vm.sh ["command"] [output_file]
# Default: ls -laR /usr (forks and generates page faults)

set -e

[ "$EUID" -ne 0 ] && { echo "Error: Run as root (use sudo)"; exit 1; }
command -v bpftrace &> /dev/null || { echo "Error: Install bpftrace: sudo apt-get install bpftrace"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMAND="${1:-ls -laR /usr 2>/dev/null | head -100}"
OUTPUT_FILE=${2:-"pagefaults_vm_trace.txt"}

echo "=== Requirement 3: Page Faults & VM Operations ==="
echo "Tracing: Virtual addresses of page faults, VM area changes"
echo "Test command: $COMMAND"
echo "Output: $OUTPUT_FILE"
echo ""

bpftrace "${SCRIPT_DIR}/pagefault_vm_tracer.bt" > "$OUTPUT_FILE" 2>&1 &
TRACER_PID=$!
sleep 1

echo "Running command..."
eval "$COMMAND"

sleep 1
kill $TRACER_PID 2>/dev/null || true
wait $TRACER_PID 2>/dev/null || true

echo ""
echo "Trace saved to: $OUTPUT_FILE"
echo "Total events: $(wc -l < "$OUTPUT_FILE")"
echo ""
echo "Event breakdown:"
grep -c "PAGE_FAULT" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  Page faults: " $1}' || echo "  Page faults: 0"
grep -c "MMAP\|MUNMAP\|MPROTECT\|BRK" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  VM operations: " $1}' || echo "  VM operations: 0"
grep -c "FORK\|EXIT\|EXEC" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  Process lifecycle: " $1}' || echo "  Process lifecycle: 0"
