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

bpftrace "${SCRIPT_DIR}/scheduler_queue_tracer.bt" > "$OUTPUT_FILE" 2>&1 &
TRACER_PID=$!
sleep 1

echo "Running stress..."
stress -i 3 -c 3 -m 3 --timeout ${DURATION}s

sleep 1
kill $TRACER_PID 2>/dev/null || true
wait $TRACER_PID 2>/dev/null || true

echo ""
echo "Trace saved to: $OUTPUT_FILE"
echo "Total events: $(wc -l < "$OUTPUT_FILE")"
echo ""
echo "Event breakdown:"
grep -c "SCHED_SWITCH\|WAKEUP\|MIGRATE" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  Scheduling: " $1}' || echo "  Scheduling: 0"
grep -c "SCHED_STAT_RUNTIME" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  Vruntime: " $1}' || echo "  Vruntime: 0"
grep -c "ENQUEUE\|DEQUEUE" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  Queue ops: " $1}' || echo "  Queue ops: 0"
grep -c "WAIT_EVENT\|WAKE_UP_PROCESS" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  Wait queue: " $1}' || echo "  Wait queue: 0"
grep -c "FORK\|EXIT\|EXEC" "$OUTPUT_FILE" 2>/dev/null | awk '{print "  Lifecycle: " $1}' || echo "  Lifecycle: 0"
