#!/bin/bash
# Trace a specific command from start to finish
# Usage: ./trace_process.sh "command [args]" [output_file]

set -e

[ "$EUID" -ne 0 ] && { echo "Error: Run as root (use sudo)"; exit 1; }
command -v bpftrace &> /dev/null || { echo "Error: Install bpftrace: sudo apt-get install bpftrace"; exit 1; }
[ $# -lt 1 ] && { echo "Usage: $0 \"command [args]\" [output_file]"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMAND="$1"
OUTPUT_FILE=${2:-""}

echo "Tracing: $COMMAND"
[ -n "$OUTPUT_FILE" ] && echo "Output: $OUTPUT_FILE"
echo ""

if [ -n "$OUTPUT_FILE" ]; then
    bpftrace -c "$COMMAND" "${SCRIPT_DIR}/kernel_tracer.bt" > "$OUTPUT_FILE" 2>&1 &
else
    bpftrace -c "$COMMAND" "${SCRIPT_DIR}/kernel_tracer.bt" &
fi

TRACER_PID=$!
sleep 1
eval "$COMMAND"
sleep 1
kill $TRACER_PID 2>/dev/null || true
wait $TRACER_PID 2>/dev/null || true

[ -n "$OUTPUT_FILE" ] && echo "Trace saved to: $OUTPUT_FILE"
