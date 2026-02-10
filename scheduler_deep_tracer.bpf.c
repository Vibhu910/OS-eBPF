// SPDX-License-Identifier: GPL-2.0
// scheduler_deep_tracer.bpf.c
// Traces CFS scheduler internals: se.vruntime, weights, load, queue state
// Requires: libbpf + CO-RE (kernel BTF support)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─────────────────────────────────────────────
//  Shared event struct (kernel → user space)
// ─────────────────────────────────────────────
#define TASK_COMM_LEN 16
#define FILENAME_LEN  64

// Event type tags
#define EVT_SWITCH      1   // context switch
#define EVT_WAKEUP      2   // moved to ready queue
#define EVT_WAKEUP_NEW  3   // brand-new task woken
#define EVT_MIGRATE     4   // migrated between CPUs
#define EVT_FORK        5   // process forked
#define EVT_EXIT        6   // process exited / zombied
#define EVT_EXEC        7   // execve called
#define EVT_WAIT        8   // task blocked (entering wait queue)

struct sched_event {
    __u64  timestamp_ns;
    __u32  event_type;
    __s32  cpu;

    // ── primary task ──
    __u32  pid;
    __u32  tgid;
    char   comm[TASK_COMM_LEN];
    __s32  prio;          // dynamic priority
    __s32  static_prio;   // nice-based static priority
    __s32  normal_prio;   // normalised priority

    // ── CFS sched_entity fields ──
    __u64  vruntime;          // se.vruntime  (virtual runtime, ns)
    __u64  exec_start;        // se.exec_start
    __u64  sum_exec_runtime;  // se.sum_exec_runtime (total CPU time, ns)
    __u64  prev_sum_exec_runtime; // se.prev_sum_exec_runtime
    __s64  vlag;              // se.vlag (lag = avg_vruntime - vruntime)
    __u64  slice;             // se.slice (current time slice, ns)

    // ── load_weight ──
    __u64  load_weight;   // se.load.weight
    __u32  load_inv_weight; // se.load.inv_weight

    // ── CFS run queue snapshot (of the CPU this task is on) ──
    __u64  cfs_min_vruntime;      // cfs_rq->min_vruntime
    __u64  cfs_avg_vruntime;      // cfs_rq->avg_vruntime (kernel ≥ 6.6)
    __u32  cfs_nr_running;        // cfs_rq->nr_running
    __u32  cfs_h_nr_running;      // cfs_rq->h_nr_running
    __u64  cfs_exec_clock;        // cfs_rq->exec_clock

    // ── secondary task (for SWITCH prev / FORK parent / MIGRATE) ──
    __u32  prev_pid;
    __u32  prev_tgid;
    char   prev_comm[TASK_COMM_LEN];
    __s32  prev_prio;
    __u64  prev_vruntime;
    __u64  prev_sum_exec;       // prev task's se.sum_exec_runtime
    __u64  prev_load_weight;

    // ── MIGRATE fields ──
    __s32  orig_cpu;
    __s32  dest_cpu;

    // ── EXEC / FORK extra ──
    __u32  child_pid;
    char   filename[FILENAME_LEN];

    // ── task state ──
    __u32  task_state;    // TASK_RUNNING=0, TASK_INTERRUPTIBLE=1, etc.
};

// Ring-buffer map – user space reads events from here
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); // 16 MB
} events SEC(".maps");

// ─────────────────────────────────────────────
//  Helper: fill CFS fields from task_struct
// ─────────────────────────────────────────────
static __always_inline void fill_se(struct sched_event *e,
                                    struct task_struct *t)
{
    e->pid         = BPF_CORE_READ(t, pid);
    e->tgid        = BPF_CORE_READ(t, tgid);
    e->prio        = BPF_CORE_READ(t, prio);
    e->static_prio = BPF_CORE_READ(t, static_prio);
    e->normal_prio = BPF_CORE_READ(t, normal_prio);
    bpf_core_read_str(e->comm, sizeof(e->comm), &t->comm);

    // sched_entity
    e->vruntime              = BPF_CORE_READ(t, se.vruntime);
    e->exec_start            = BPF_CORE_READ(t, se.exec_start);
    e->sum_exec_runtime      = BPF_CORE_READ(t, se.sum_exec_runtime);
    e->prev_sum_exec_runtime = BPF_CORE_READ(t, se.prev_sum_exec_runtime);
    e->load_weight           = BPF_CORE_READ(t, se.load.weight);
    e->load_inv_weight       = BPF_CORE_READ(t, se.load.inv_weight);

    // vlag and slice – only present on newer kernels; CO-RE returns 0 if absent
    e->vlag  = BPF_CORE_READ(t, se.vlag);
    e->slice = BPF_CORE_READ(t, se.slice);

    // cfs_rq that owns this sched_entity
    struct cfs_rq *cfs = BPF_CORE_READ(t, se.cfs_rq);
    if (cfs) {
        e->cfs_min_vruntime  = BPF_CORE_READ(cfs, min_vruntime);
        e->cfs_nr_running    = BPF_CORE_READ(cfs, nr_running);
        e->cfs_h_nr_running  = BPF_CORE_READ(cfs, h_nr_running);
        e->cfs_exec_clock    = BPF_CORE_READ(cfs, exec_clock);
        // avg_vruntime added in ~6.6; CO-RE silently gives 0 on older kernels
        e->cfs_avg_vruntime  = BPF_CORE_READ(cfs, avg_vruntime);
    }

    e->task_state = BPF_CORE_READ(t, __state);
}

static __always_inline void fill_prev_se(struct sched_event *e,
                                         struct task_struct *t)
{
    e->prev_pid          = BPF_CORE_READ(t, pid);
    e->prev_tgid         = BPF_CORE_READ(t, tgid);
    e->prev_prio         = BPF_CORE_READ(t, prio);
    e->prev_vruntime     = BPF_CORE_READ(t, se.vruntime);
    e->prev_sum_exec     = BPF_CORE_READ(t, se.sum_exec_runtime);
    e->prev_load_weight  = BPF_CORE_READ(t, se.load.weight);
    bpf_core_read_str(e->prev_comm, sizeof(e->prev_comm), &t->comm);
}

// ─────────────────────────────────────────────
//  1.  Context switch  (sched_switch)
//      Shows BOTH the outgoing (prev) and incoming (next) task's CFS state
// ─────────────────────────────────────────────
SEC("tp_btf/sched_switch")
int BPF_PROG(handle_sched_switch,
             bool preempt,
             struct task_struct *prev,
             struct task_struct *next)
{
    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_SWITCH;
    e->cpu          = bpf_get_smp_processor_id();

    // next (incoming – will run)
    fill_se(e, next);

    // prev (outgoing – going to wait or ready queue)
    fill_prev_se(e, prev);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  2.  Task wakeup → moved to ready (run) queue
// ─────────────────────────────────────────────
SEC("tp_btf/sched_wakeup")
int BPF_PROG(handle_wakeup, struct task_struct *p)
{
    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_WAKEUP;
    e->cpu          = bpf_get_smp_processor_id();

    fill_se(e, p);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  3.  New task woken for the first time
// ─────────────────────────────────────────────
SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(handle_wakeup_new, struct task_struct *p)
{
    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_WAKEUP_NEW;
    e->cpu          = bpf_get_smp_processor_id();

    fill_se(e, p);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  4.  Task migration between CPUs
// ─────────────────────────────────────────────
SEC("tp_btf/sched_migrate_task")
int BPF_PROG(handle_migrate,
             struct task_struct *p,
             int dest_cpu)
{
    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_MIGRATE;
    e->cpu          = bpf_get_smp_processor_id();
    e->orig_cpu     = bpf_get_smp_processor_id();
    e->dest_cpu     = dest_cpu;

    fill_se(e, p);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  5.  Fork
// ─────────────────────────────────────────────
SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork,
             struct task_struct *parent,
             struct task_struct *child)
{
    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_FORK;
    e->cpu          = bpf_get_smp_processor_id();

    // Fill child as the main task
    fill_se(e, child);
    // Parent info in prev_ fields
    fill_prev_se(e, parent);
    e->child_pid = BPF_CORE_READ(child, pid);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  6.  Exit / zombie
// ─────────────────────────────────────────────
SEC("tp_btf/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *p)
{
    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_EXIT;
    e->cpu          = bpf_get_smp_processor_id();

    fill_se(e, p);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  7.  Exec
// ─────────────────────────────────────────────
SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec,
             struct task_struct *p,
             pid_t old_pid,
             struct linux_binprm *bprm)
{
    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_EXEC;
    e->cpu          = bpf_get_smp_processor_id();

    fill_se(e, p);

    if (bprm)
        bpf_core_read_str(e->filename, sizeof(e->filename),
                          &bprm->filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  8.  Block / enter wait queue
//      Fires on schedule() when the current task is NOT TASK_RUNNING,
//      meaning it is about to be removed from the run queue and placed
//      on a wait queue (sleep, I/O wait, mutex wait, etc.)
// ─────────────────────────────────────────────
SEC("kprobe/dequeue_task_fair")
int BPF_KPROBE(handle_dequeue, struct rq *rq, struct task_struct *p, int flags)
{
    // Only report if the task is blocking (not just being preempted)
    unsigned int state = BPF_CORE_READ(p, __state);
    if (state == 0) return 0; // TASK_RUNNING = preemption, skip

    struct sched_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVT_WAIT;
    e->cpu          = bpf_get_smp_processor_id();

    fill_se(e, p);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
