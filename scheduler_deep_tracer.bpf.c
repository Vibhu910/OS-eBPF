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
    __u64  cfs_load_weight;       // cfs_rq->load.weight (total load weight)

    // ── Additional CFS sched_entity fields ──
    __u8   on_rq;                 // se.on_rq (is task on run queue)
    __u64  last_update_rq_clock; // se.last_update_rq_clock

    // ── Wait queue information ──
    __u64  wait_queue_head_addr;  // Address of wait_queue_head (identifies which queue)
    __u32  wait_queue_flags;      // Wait queue flags
    __u8   wait_queue_type;        // 0=unknown, 1=I/O, 2=mutex, 3=semaphore, 4=sleep, 5=other

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

// Scratch map to track wait queue information per task
// Maps: pid -> wait_queue_info
struct wait_queue_info {
    __u64  wait_queue_head_addr;
    __u8   wait_queue_type;
    __u32  wait_queue_flags;
    __u64  timestamp_ns;
};
struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u32);   // pid
    __type(value, struct wait_queue_info);
} wait_queue_map SEC(".maps");

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

    // Additional sched_entity fields
    e->on_rq = BPF_CORE_READ(t, se.on_rq);
    e->last_update_rq_clock = BPF_CORE_READ(t, se.last_update_rq_clock);

    // cfs_rq that owns this sched_entity
    struct cfs_rq *cfs = BPF_CORE_READ(t, se.cfs_rq);
    if (cfs) {
        e->cfs_min_vruntime  = BPF_CORE_READ(cfs, min_vruntime);
        e->cfs_nr_running    = BPF_CORE_READ(cfs, nr_running);
        e->cfs_h_nr_running  = BPF_CORE_READ(cfs, h_nr_running);
        e->cfs_exec_clock    = BPF_CORE_READ(cfs, exec_clock);
        e->cfs_load_weight    = BPF_CORE_READ(cfs, load.weight);
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

    // Get wait queue information if available
    __u32 pid = BPF_CORE_READ(p, pid);
    struct wait_queue_info *wq_info = bpf_map_lookup_elem(&wait_queue_map, &pid);
    if (wq_info) {
        e->wait_queue_head_addr = wq_info->wait_queue_head_addr;
        e->wait_queue_type      = wq_info->wait_queue_type;
        e->wait_queue_flags     = wq_info->wait_queue_flags;
        // Clean up the map entry
        bpf_map_delete_elem(&wait_queue_map, &pid);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ─────────────────────────────────────────────
//  9.  Prepare to wait - captures wait queue head
//      This is called before a task enters a wait queue
// ─────────────────────────────────────────────
SEC("kprobe/prepare_to_wait")
int BPF_KPROBE(handle_prepare_to_wait,
               struct wait_queue_head *wq,
               struct wait_queue_entry *wq_entry,
               int state)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info wq_info = {};
    wq_info.wait_queue_head_addr = (__u64)wq;
    wq_info.wait_queue_type = 0; // Unknown - will be set by specific probes
    wq_info.wait_queue_flags = 0;
    wq_info.timestamp_ns = bpf_ktime_get_ns();
    
    // Try to read wait queue flags if available
    // Note: wait_queue_head structure varies by kernel version
    // We'll set type based on which probe called prepare_to_wait
    
    bpf_map_update_elem(&wait_queue_map, &pid, &wq_info, BPF_ANY);
    return 0;
}

SEC("kprobe/prepare_to_wait_exclusive")
int BPF_KPROBE(handle_prepare_to_wait_exclusive,
               struct wait_queue_head *wq,
               struct wait_queue_entry *wq_entry,
               int state)
{
    // Same as prepare_to_wait but for exclusive waits
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info wq_info = {};
    wq_info.wait_queue_head_addr = (__u64)wq;
    wq_info.wait_queue_type = 0; // Unknown - will be set by specific probes
    wq_info.wait_queue_flags = 0;
    wq_info.timestamp_ns = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&wait_queue_map, &pid, &wq_info, BPF_ANY);
    return 0;
}

// ─────────────────────────────────────────────
//  10. Mutex lock - identifies mutex wait queues
// ─────────────────────────────────────────────
SEC("kprobe/mutex_lock")
int BPF_KPROBE(handle_mutex_lock, void *lock)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info *wq_info = bpf_map_lookup_elem(&wait_queue_map, &pid);
    if (wq_info) {
        wq_info->wait_queue_type = 2; // MUTEX
        bpf_map_update_elem(&wait_queue_map, &pid, wq_info, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/__mutex_lock_slowpath")
int BPF_KPROBE(handle_mutex_lock_slowpath, void *lock)
{
    // Mutex slow path - definitely a mutex wait
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info *wq_info = bpf_map_lookup_elem(&wait_queue_map, &pid);
    if (wq_info) {
        wq_info->wait_queue_type = 2; // MUTEX
        bpf_map_update_elem(&wait_queue_map, &pid, wq_info, BPF_ANY);
    }
    return 0;
}

// ─────────────────────────────────────────────
//  11. I/O wait - identifies I/O wait queues
// ─────────────────────────────────────────────
SEC("kprobe/__wait_on_bit")
int BPF_KPROBE(handle_wait_on_bit,
               void *word,
               int bit,
               unsigned mode,
               unsigned timeout)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info *wq_info = bpf_map_lookup_elem(&wait_queue_map, &pid);
    if (wq_info) {
        wq_info->wait_queue_type = 1; // I/O
        bpf_map_update_elem(&wait_queue_map, &pid, wq_info, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/wait_on_page_bit")
int BPF_KPROBE(handle_wait_on_page_bit, void *page, int bit_nr)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info *wq_info = bpf_map_lookup_elem(&wait_queue_map, &pid);
    if (wq_info) {
        wq_info->wait_queue_type = 1; // I/O
        bpf_map_update_elem(&wait_queue_map, &pid, wq_info, BPF_ANY);
    }
    return 0;
}

// ─────────────────────────────────────────────
//  12. Semaphore wait - identifies semaphore wait queues
// ─────────────────────────────────────────────
SEC("kprobe/down")
int BPF_KPROBE(handle_down, void *sem)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info *wq_info = bpf_map_lookup_elem(&wait_queue_map, &pid);
    if (wq_info) {
        wq_info->wait_queue_type = 3; // SEMAPHORE
        bpf_map_update_elem(&wait_queue_map, &pid, wq_info, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/__down")
int BPF_KPROBE(handle_down_slowpath, void *sem)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info *wq_info = bpf_map_lookup_elem(&wait_queue_map, &pid);
    if (wq_info) {
        wq_info->wait_queue_type = 3; // SEMAPHORE
        bpf_map_update_elem(&wait_queue_map, &pid, wq_info, BPF_ANY);
    }
    return 0;
}

// ─────────────────────────────────────────────
//  13. Sleep wait - identifies sleep/timeout wait queues
// ─────────────────────────────────────────────
SEC("kprobe/schedule_timeout")
int BPF_KPROBE(handle_schedule_timeout, long timeout)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info *wq_info = bpf_map_lookup_elem(&wait_queue_map, &pid);
    if (wq_info) {
        wq_info->wait_queue_type = 4; // SLEEP
        bpf_map_update_elem(&wait_queue_map, &pid, wq_info, BPF_ANY);
    }
    return 0;
}

SEC("kprobe/msleep")
int BPF_KPROBE(handle_msleep, unsigned int msecs)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct wait_queue_info *wq_info = bpf_map_lookup_elem(&wait_queue_map, &pid);
    if (wq_info) {
        wq_info->wait_queue_type = 4; // SLEEP
        bpf_map_update_elem(&wait_queue_map, &pid, wq_info, BPF_ANY);
    }
    return 0;
}

// ─────────────────────────────────────────────
//  14. Finish wait - cleanup wait queue tracking
// ─────────────────────────────────────────────
SEC("kprobe/finish_wait")
int BPF_KPROBE(handle_finish_wait,
               struct wait_queue_head *wq,
               struct wait_queue_entry *wq_entry)
{
    // Clean up wait queue info when task finishes waiting
    // Note: This may fire before dequeue_task_fair, so we keep the entry
    // until dequeue_task_fair consumes it
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
