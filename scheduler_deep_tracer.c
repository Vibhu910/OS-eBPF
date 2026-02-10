// scheduler_deep_tracer.c
// User-space loader: opens the BPF object, attaches probes,
// reads the ring buffer, and pretty-prints every event.
//
// Build: see Makefile or README
// Run:   sudo ./scheduler_deep_tracer [duration_seconds]

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "scheduler_deep_tracer.skel.h"

// ── Must mirror the kernel-side struct exactly ──────────────────────────────
#define TASK_COMM_LEN 16
#define FILENAME_LEN  64

#define EVT_SWITCH      1
#define EVT_WAKEUP      2
#define EVT_WAKEUP_NEW  3
#define EVT_MIGRATE     4
#define EVT_FORK        5
#define EVT_EXIT        6
#define EVT_EXEC        7
#define EVT_WAIT        8

struct sched_event {
    unsigned long long timestamp_ns;
    unsigned int       event_type;
    int                cpu;

    unsigned int  pid;
    unsigned int  tgid;
    char          comm[TASK_COMM_LEN];
    int           prio;
    int           static_prio;
    int           normal_prio;

    unsigned long long vruntime;
    unsigned long long exec_start;
    unsigned long long sum_exec_runtime;
    unsigned long long prev_sum_exec_runtime;
    long long          vlag;
    unsigned long long slice;

    unsigned long long load_weight;
    unsigned int       load_inv_weight;

    unsigned long long cfs_min_vruntime;
    unsigned long long cfs_avg_vruntime;
    unsigned int       cfs_nr_running;
    unsigned int       cfs_h_nr_running;
    unsigned long long cfs_exec_clock;

    unsigned int       prev_pid;
    unsigned int       prev_tgid;
    char               prev_comm[TASK_COMM_LEN];
    int                prev_prio;
    unsigned long long prev_vruntime;
    unsigned long long prev_sum_exec_runtime;
    unsigned long long prev_load_weight;

    int  orig_cpu;
    int  dest_cpu;

    unsigned int child_pid;
    char         filename[FILENAME_LEN];

    unsigned int task_state;
};

// ── helpers ─────────────────────────────────────────────────────────────────

static const char *event_name(unsigned int t) {
    switch (t) {
        case EVT_SWITCH:     return "SCHED_SWITCH ";
        case EVT_WAKEUP:     return "WAKEUP       ";
        case EVT_WAKEUP_NEW: return "WAKEUP_NEW   ";
        case EVT_MIGRATE:    return "MIGRATE      ";
        case EVT_FORK:       return "FORK         ";
        case EVT_EXIT:       return "EXIT/ZOMBIE  ";
        case EVT_EXEC:       return "EXEC         ";
        case EVT_WAIT:       return "WAIT_QUEUE   ";
        default:             return "UNKNOWN      ";
    }
}

// Nice name for task_state bitmask
static const char *state_str(unsigned int s) {
    if (s == 0)      return "RUNNING";
    if (s & 0x0001)  return "INTERRUPTIBLE_SLEEP";
    if (s & 0x0002)  return "UNINTERRUPTIBLE_SLEEP";
    if (s & 0x0010)  return "STOPPED";
    if (s & 0x0040)  return "DEAD";
    if (s & 0x0080)  return "ZOMBIE";
    return "OTHER";
}

// Print the CFS sched_entity block for a task
static void print_se_block(const char *prefix,
                            unsigned int pid, unsigned int tgid,
                            const char *comm, int prio,
                            int static_prio, int normal_prio,
                            unsigned long long vruntime,
                            unsigned long long exec_start,
                            unsigned long long sum_exec,
                            unsigned long long prev_sum_exec,
                            long long vlag,
                            unsigned long long slice,
                            unsigned long long lw,
                            unsigned int inv_lw,
                            unsigned int state)
{
    printf("%s  pid=%-6u tgid=%-6u comm=%-16s state=%-22s\n",
           prefix, pid, tgid, comm, state_str(state));
    printf("%s    prio=%d  static_prio=%d  normal_prio=%d\n",
           prefix, prio, static_prio, normal_prio);
    printf("%s    se.vruntime             = %llu ns\n",   prefix, vruntime);
    printf("%s    se.exec_start           = %llu ns\n",   prefix, exec_start);
    printf("%s    se.sum_exec_runtime     = %llu ns  (%.3f ms)\n",
           prefix, sum_exec, sum_exec / 1e6);
    printf("%s    se.prev_sum_exec_runtime= %llu ns\n",   prefix, prev_sum_exec);
    printf("%s    se.vlag                 = %lld ns\n",   prefix, vlag);
    printf("%s    se.slice                = %llu ns  (%.3f ms)\n",
           prefix, slice, slice / 1e6);
    printf("%s    se.load.weight          = %llu\n",      prefix, lw);
    printf("%s    se.load.inv_weight      = %u\n",        prefix, inv_lw);
}

// Print the CFS run-queue snapshot
static void print_cfs_block(const char *prefix, const struct sched_event *e)
{
    printf("%s  [cfs_rq @ cpu%d]\n", prefix, e->cpu);
    printf("%s    cfs_rq.min_vruntime  = %llu ns\n", prefix, e->cfs_min_vruntime);
    printf("%s    cfs_rq.avg_vruntime  = %llu ns\n", prefix, e->cfs_avg_vruntime);
    printf("%s    cfs_rq.nr_running    = %u\n",      prefix, e->cfs_nr_running);
    printf("%s    cfs_rq.h_nr_running  = %u\n",      prefix, e->cfs_h_nr_running);
    printf("%s    cfs_rq.exec_clock    = %llu ns\n", prefix, e->cfs_exec_clock);
    // lag = how far behind/ahead vs min_vruntime
    long long lag = (long long)e->vruntime - (long long)e->cfs_min_vruntime;
    printf("%s    vruntime lag vs min  = %lld ns  (%s)\n",
           prefix, lag, lag > 0 ? "behind avg" : "ahead of avg");
}

// ── ring-buffer callback ─────────────────────────────────────────────────────

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct sched_event *e = data;

    // timestamp as seconds.microseconds
    unsigned long long ts_s  = e->timestamp_ns / 1000000000ULL;
    unsigned long long ts_us = (e->timestamp_ns % 1000000000ULL) / 1000;

    printf("\n");
    printf("┌─ %s  cpu=%-2d  time=%llu.%06llus\n",
           event_name(e->event_type), e->cpu, ts_s, ts_us);

    switch (e->event_type) {

    // ── Context switch ───────────────────────────────────────────────────────
    case EVT_SWITCH:
        printf("│  ▶ NEXT  (going ON cpu)\n");
        print_se_block("│",
            e->pid, e->tgid, e->comm,
            e->prio, e->static_prio, e->normal_prio,
            e->vruntime, e->exec_start, e->sum_exec_runtime,
            e->prev_sum_exec_runtime, e->vlag, e->slice,
            e->load_weight, e->load_inv_weight, e->task_state);
        print_cfs_block("│", e);
        printf("│  ◀ PREV  (going OFF cpu / blocked)\n");
        printf("│    pid=%-6u tgid=%-6u comm=%-16s prio=%d\n",
               e->prev_pid, e->prev_tgid, e->prev_comm, e->prev_prio);
        printf("│    se.vruntime         = %llu ns\n", e->prev_vruntime);
        printf("│    se.sum_exec_runtime = %llu ns  (%.3f ms)\n",
               e->prev_sum_exec_runtime, e->prev_sum_exec_runtime / 1e6);
        printf("│    se.load.weight      = %llu\n", e->prev_load_weight);
        break;

    // ── Wakeup / added to ready queue ───────────────────────────────────────
    case EVT_WAKEUP:
    case EVT_WAKEUP_NEW:
        printf("│  Task added to READY QUEUE (run queue)\n");
        print_se_block("│",
            e->pid, e->tgid, e->comm,
            e->prio, e->static_prio, e->normal_prio,
            e->vruntime, e->exec_start, e->sum_exec_runtime,
            e->prev_sum_exec_runtime, e->vlag, e->slice,
            e->load_weight, e->load_inv_weight, e->task_state);
        print_cfs_block("│", e);
        break;

    // ── Wait queue (blocking) ────────────────────────────────────────────────
    case EVT_WAIT:
        printf("│  Task entering WAIT QUEUE (blocking) — state: %s\n",
               state_str(e->task_state));
        print_se_block("│",
            e->pid, e->tgid, e->comm,
            e->prio, e->static_prio, e->normal_prio,
            e->vruntime, e->exec_start, e->sum_exec_runtime,
            e->prev_sum_exec_runtime, e->vlag, e->slice,
            e->load_weight, e->load_inv_weight, e->task_state);
        print_cfs_block("│", e);
        break;

    // ── Migration ───────────────────────────────────────────────────────────
    case EVT_MIGRATE:
        printf("│  CPU migration: cpu%d → cpu%d\n", e->orig_cpu, e->dest_cpu);
        print_se_block("│",
            e->pid, e->tgid, e->comm,
            e->prio, e->static_prio, e->normal_prio,
            e->vruntime, e->exec_start, e->sum_exec_runtime,
            e->prev_sum_exec_runtime, e->vlag, e->slice,
            e->load_weight, e->load_inv_weight, e->task_state);
        print_cfs_block("│", e);
        break;

    // ── Fork ────────────────────────────────────────────────────────────────
    case EVT_FORK:
        printf("│  PARENT: pid=%-6u comm=%s\n", e->prev_pid, e->prev_comm);
        printf("│    se.vruntime     = %llu ns\n", e->prev_vruntime);
        printf("│    se.load.weight  = %llu\n",    e->prev_load_weight);
        printf("│  CHILD (new task, added to ready queue):\n");
        print_se_block("│",
            e->pid, e->tgid, e->comm,
            e->prio, e->static_prio, e->normal_prio,
            e->vruntime, e->exec_start, e->sum_exec_runtime,
            e->prev_sum_exec_runtime, e->vlag, e->slice,
            e->load_weight, e->load_inv_weight, e->task_state);
        print_cfs_block("│", e);
        break;

    // ── Exit / zombie ───────────────────────────────────────────────────────
    case EVT_EXIT:
        printf("│  Process EXITING / becoming ZOMBIE\n");
        print_se_block("│",
            e->pid, e->tgid, e->comm,
            e->prio, e->static_prio, e->normal_prio,
            e->vruntime, e->exec_start, e->sum_exec_runtime,
            e->prev_sum_exec_runtime, e->vlag, e->slice,
            e->load_weight, e->load_inv_weight, e->task_state);
        printf("│    Total CPU time used: %.3f ms\n",
               e->sum_exec_runtime / 1e6);
        break;

    // ── Exec ────────────────────────────────────────────────────────────────
    case EVT_EXEC:
        printf("│  execve: %s\n", e->filename[0] ? e->filename : "(unknown)");
        print_se_block("│",
            e->pid, e->tgid, e->comm,
            e->prio, e->static_prio, e->normal_prio,
            e->vruntime, e->exec_start, e->sum_exec_runtime,
            e->prev_sum_exec_runtime, e->vlag, e->slice,
            e->load_weight, e->load_inv_weight, e->task_state);
        break;

    default:
        printf("│  (unknown event type %u)\n", e->event_type);
        break;
    }

    printf("└──────────────────────────────────────────────────────────────\n");
    fflush(stdout);
    return 0;
}

// ── signal handling ─────────────────────────────────────────────────────────
static volatile int stop = 0;
static void sig_handler(int sig) { stop = 1; }

// ── main ────────────────────────────────────────────────────────────────────
int main(int argc, char **argv)
{
    int duration = 10;
    if (argc > 1) duration = atoi(argv[1]);

    // Set up libbpf logging (optional: reduce noise by setting to WARN)
    libbpf_set_print(NULL);

    struct scheduler_deep_tracer_bpf *skel = scheduler_deep_tracer_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    int err = scheduler_deep_tracer_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = scheduler_deep_tracer_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    printf("=== Deep Scheduler Tracer ===\n");
    printf("Tracing CFS internals: vruntime, weights, cfs_rq, wait/ready queues\n");
    printf("Duration: %d seconds  (Ctrl-C to stop early)\n\n", duration);

    time_t start = time(NULL);
    while (!stop && (time(NULL) - start) < duration) {
        err = ring_buffer__poll(rb, 100 /*ms*/);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Ring buffer poll error: %d\n", err);
            break;
        }
    }

    printf("\n=== Tracer stopped ===\n");
    ring_buffer__free(rb);

cleanup:
    scheduler_deep_tracer_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}
