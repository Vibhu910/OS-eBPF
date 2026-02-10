#!/bin/bash
# Helper script to run the kernel tracer
# Usage: ./run_tracer.sh [PID] [output_file]

set -e

[ "$EUID" -ne 0 ] && { echo "Error: Run as root (use sudo)"; exit 1; }
command -v bpftrace &> /dev/null || { echo "Error: Install bpftrace: sudo apt-get install bpftrace"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID=${1:-0}
OUTPUT_FILE=${2:-""}

echo "Starting kernel tracer... PID filter: ${PID:-'all'}"
[ -n "$OUTPUT_FILE" ] && echo "Output: $OUTPUT_FILE"
echo "Press Ctrl+C to stop"
echo ""

CMD="bpftrace"
[ "$PID" -gt 0 ] && CMD="$CMD -p $PID"
[ -n "$OUTPUT_FILE" ] && CMD="$CMD | tee $OUTPUT_FILE"

eval "$CMD ${SCRIPT_DIR}/kernel_tracer.bt"
