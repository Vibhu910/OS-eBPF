#!/bin/bash
# Automation for Requirement 1 & 2: Scheduling and Queue Operations
# Tests: Process scheduling with vruntime, ready/wait queues, process lifecycle
# Usage: sudo ./test_scheduling_queues.sh [duration_seconds] [output_file]

set -e

[ "$EUID" -ne 0 ] && { echo "Error: Run as root (use sudo)"; exit 1; }
command -v bpftrace &> /dev/null || { echo "Error: Install bpftrace: sudo apt-get install bpftrace"; exit 1; }
command -v stress &> /dev/null || { echo "Error: Install stress: sudo apt-get install stress"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DURATION=${1:-5}
OUTPUT_FILE=${2:-"scheduling_queues_trace.txt"}

echo "=== Requirement 1 & 2: Scheduling & Queue Operations ==="
echo "Tracing: Process scheduling with vruntime, ready/wait queues, process lifecycle"
echo "Test command: stress -i 3 -c 3 -m 3"
echo "Duration: ${DURATION} seconds"
echo "Output: $OUTPUT_FILE"
echo ""

# Try to start tracer and capture errors
bpftrace "${SCRIPT_DIR}/scheduler_queue_tracer.bt" > "$OUTPUT_FILE" 2>&1 &
TRACER_PID=$!
sleep 2

# Check if tracer process is still running
if ! kill -0 $TRACER_PID 2>/dev/null; then
    echo "Error: Tracer failed to start. Checking for errors..."
    echo ""
    if [ -f "$OUTPUT_FILE" ]; then
        cat "$OUTPUT_FILE"
    fi
    echo ""
    echo "Troubleshooting:"
    echo "1. Check if bpftrace is installed: bpftrace --version"
    echo "2. Check if kernel headers are installed: ls /usr/src/linux-headers-\$(uname -r)"
    echo "3. Try running bpftrace directly: sudo bpftrace ${SCRIPT_DIR}/scheduler_queue_tracer.bt"
    exit 1
fi

echo "Running stress..."
stress -i 3 -c 3 -m 3 --timeout ${DURATION}s

sleep 1
kill $TRACER_PID 2>/dev/null || true
wait $TRACER_PID 2>/dev/null || true

echo ""
echo "Trace saved to: $OUTPUT_FILE"
echo "Total events: $(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)"
echo ""
echo "Event breakdown:"
grep -c "SCHED_SWITCH\|WAKEUP\|MIGRATE" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  Scheduling: " $1}' || echo "  Scheduling: 0"
grep -c "FORK\|EXIT\|EXEC" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  Lifecycle: " $1}' || echo "  Lifecycle: 0"
