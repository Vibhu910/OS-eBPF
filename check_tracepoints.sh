#!/bin/bash
# Check which tracepoints are available on the system

echo "Checking available tracepoints..."
echo ""

echo "Scheduler tracepoints:"
bpftrace -l 'tracepoint:sched:*' 2>/dev/null | head -20 || echo "Error listing tracepoints"

echo ""
echo "Checking specific tracepoints we need:"
for tp in "sched:sched_switch" "sched:sched_wakeup" "sched:sched_wakeup_new" "sched:sched_migrate_task" "sched:sched_process_fork" "sched:sched_process_exit" "sched:sched_process_exec" "sched:sched_stat_runtime"; do
    if bpftrace -l "tracepoint:$tp" 2>/dev/null | grep -q "$tp"; then
        echo "  ✅ $tp - Available"
    else
        echo "  ❌ $tp - NOT Available"
    fi
done
