#!/bin/bash
# test_scheduling_queues.sh - improved
set -euo pipefail

[ "$EUID" -ne 0 ] && { echo "Error: Run as root (use sudo)"; exit 1; }
command -v bpftrace >/dev/null || { echo "Error: Install bpftrace: sudo apt-get install bpftrace"; exit 1; }
command -v stress >/dev/null || { echo "Error: Install stress: sudo apt-get install stress"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DURATION=${1:-5}
OUTPUT_FILE=${2:-"scheduling_queues_trace.txt"}

BT_FILE="${SCRIPT_DIR}/scheduler_queue_tracer.bt"
if [ ! -f "$BT_FILE" ]; then
    echo "Error: missing tracer file: $BT_FILE"
    exit 1
fi

echo "=== Requirement 1 & 2: Scheduling & Queue Operations ==="
echo "Tracing: Process scheduling with vruntime (requires libbpf), ready/wait queues, process lifecycle"
echo "Test command: stress -i 3 -c 3 -m 3"
echo "Duration: ${DURATION} seconds"
echo "Output: $OUTPUT_FILE"
echo ""

# Ensure output file is empty
: > "$OUTPUT_FILE"

# Start tracer, redirect stdout->file and stderr->file.err so we can show both
TRACE_STDOUT="$OUTPUT_FILE"
TRACE_STDERR="${OUTPUT_FILE}.err"

# Start bpftrace in background, capture stdout/stderr
echo "Starting tracer..."
# Run bpftrace and capture pid
# Use -v to get verbose verifier info into stderr if it fails
/usr/bin/env bpftrace "$BT_FILE" > "$TRACE_STDOUT" 2> "$TRACE_STDERR" &
TRACER_PID=$!
sleep 1

# Check tracer alive shortly after start
if ! kill -0 "$TRACER_PID" 2>/dev/null; then
    echo "Error: Tracer failed to start. Dumping log files..."
    echo "----- $TRACE_STDOUT -----"
    [ -s "$TRACE_STDOUT" ] && sed -n '1,200p' "$TRACE_STDOUT" || echo "(no stdout)"
    echo "----- $TRACE_STDERR -----"
    [ -s "$TRACE_STDERR" ] && sed -n '1,200p' "$TRACE_STDERR" || echo "(no stderr)"
    echo ""
    echo "Troubleshooting tips:"
    echo "  1) Run with verbosity: sudo bpftrace -v $BT_FILE"
    echo "  2) Check bpftrace works: sudo bpftrace -e 'tracepoint:sched:sched_switch { printf(\"ok\\n\"); exit(); }'"
    echo "  3) If tracer printed preprocessor/verifier messages, paste the .err file here"
    exit 1
fi

echo "Tracer started (pid $TRACER_PID). Running stress workload..."

# run workload (will exit after timeout)
stress -i 3 -c 3 -m 3 --timeout "${DURATION}s"

# give tracer a moment to flush
sleep 1

echo "Stopping tracer (pid $TRACER_PID)..."
kill "$TRACER_PID" 2>/dev/null || true
wait "$TRACER_PID" 2>/dev/null || true

echo ""
echo "Trace saved to: $OUTPUT_FILE"
echo "stderr (verifier / errors) -> $TRACE_STDERR"
echo "Total events: $(wc -l < "$OUTPUT_FILE" 2>/dev/null || echo 0)"
echo ""
echo "Event breakdown:"
printf "  Scheduling: %s\n" "$(grep -c -E 'SCHED_SWITCH|WAKEUP|MIGRATE' "$OUTPUT_FILE" 2>/dev/null || echo 0)"
printf "  Lifecycle:  %s\n" "$(grep -c -E 'FORK|EXIT|EXEC' "$OUTPUT_FILE" 2>/dev/null || echo 0)"

# If there were errors recorded to stderr, show first 60 lines to help debugging
if [ -s "$TRACE_STDERR" ]; then
    echo ""
    echo "===== bpftrace stderr (first 60 lines) ====="
    sed -n '1,60p' "$TRACE_STDERR"
    echo "============================================"
fi

exit 0
