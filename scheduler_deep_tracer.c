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
    unsigned long long cfs_load_weight;

    unsigned char      on_rq;
    unsigned long long last_update_rq_clock;

    unsigned long long wait_queue_head_addr;
    unsigned int       wait_queue_flags;
    unsigned char      wait_queue_type;

    unsigned int       prev_pid;
    unsigned int       prev_tgid;
    char               prev_comm[TASK_COMM_LEN];
    int                prev_prio;
    unsigned long long prev_vruntime;
    unsigned long long prev_sum_exec;       // prev task's se.sum_exec_runtime
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

// Wait queue type names
static const char *wait_queue_type_str(unsigned char t) {
    switch (t) {
        case 0: return "UNKNOWN";
        case 1: return "I/O";
        case 2: return "MUTEX";
        case 3: return "SEMAPHORE";
        case 4: return "SLEEP";
        case 5: return "OTHER";
        default: return "UNKNOWN";
    }
}

// Old print functions - kept for reference but not used in tabular format
// Uncomment these if you want to switch back to tree format
/*
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
                            unsigned int state,
                            unsigned char on_rq,
                            unsigned long long last_update_rq_clock)
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
    printf("%s    se.on_rq                = %u\n",       prefix, on_rq);
    printf("%s    se.last_update_rq_clock = %llu ns\n",  prefix, last_update_rq_clock);
}

static void print_cfs_block(const char *prefix, const struct sched_event *e)
{
    printf("%s  [cfs_rq @ cpu%d]\n", prefix, e->cpu);
    printf("%s    cfs_rq.min_vruntime  = %llu ns\n", prefix, e->cfs_min_vruntime);
    printf("%s    cfs_rq.avg_vruntime  = %llu ns\n", prefix, e->cfs_avg_vruntime);
    printf("%s    cfs_rq.nr_running    = %u\n",      prefix, e->cfs_nr_running);
    printf("%s    cfs_rq.h_nr_running  = %u\n",      prefix, e->cfs_h_nr_running);
    printf("%s    cfs_rq.exec_clock    = %llu ns\n", prefix, e->cfs_exec_clock);
    printf("%s    cfs_rq.load.weight   = %llu\n",    prefix, e->cfs_load_weight);
    long long lag = (long long)e->vruntime - (long long)e->cfs_min_vruntime;
    printf("%s    vruntime lag vs min  = %lld ns  (%s)\n",
           prefix, lag, lag > 0 ? "behind avg" : "ahead of avg");
}

static void print_wait_queue_info(const char *prefix, const struct sched_event *e)
{
    if (e->wait_queue_head_addr == 0 && e->wait_queue_type == 0) {
        return;
    }
    printf("%s  [Wait Queue Info]\n", prefix);
    if (e->wait_queue_head_addr != 0) {
        printf("%s    wait_queue_head_addr = 0x%016llx\n", prefix, e->wait_queue_head_addr);
    }
    if (e->wait_queue_type != 0) {
        printf("%s    wait_queue_type      = %s (%u)\n", 
               prefix, wait_queue_type_str(e->wait_queue_type), e->wait_queue_type);
    }
    if (e->wait_queue_flags != 0) {
        printf("%s    wait_queue_flags     = 0x%08x\n", prefix, e->wait_queue_flags);
    }
}
*/

// ── tabular output helpers ──────────────────────────────────────────────────

static int header_printed = 0;

static void print_header(void) {
    if (header_printed) return;
    printf("\n");
    // Main table header
    printf("%-12s %-3s %-12s %-6s %-6s %-16s %-5s %-6s %-15s %-10s %-8s %-6s %-15s %-6s %-15s %-8s %-10s %-12s %-20s\n",
           "EVENT", "CPU", "TIME(s)", "PID", "TGID", "COMM", "PRIO", "STATIC", "VRUNTIME(ns)", "SUM_EXEC", "LOAD_WT", "ON_RQ", "STATE",
           "CFS_NR", "CFS_MIN_VR", "CFS_LD_WT", "PREV_PID", "PREV_VR", "WQ_TYPE", "WQ_ADDR");
    // Separator line
    printf("%-12s %-3s %-12s %-6s %-6s %-16s %-5s %-6s %-15s %-10s %-8s %-6s %-15s %-6s %-15s %-8s %-10s %-12s %-20s\n",
           "-----------", "---", "------------", "------", "------", "----------------", "-----", "------",
           "---------------", "----------", "--------", "------", "---------------", "------", "---------------", "--------", "----------", "------------", "--------------------");
    header_printed = 1;
}

static void print_event_row(const struct sched_event *e) {
    unsigned long long ts_s  = e->timestamp_ns / 1000000000ULL;
    unsigned long long ts_us = (e->timestamp_ns % 1000000000ULL) / 1000;
    char time_str[32];
    snprintf(time_str, sizeof(time_str), "%llu.%06llu", ts_s, ts_us);
    
    char vruntime_str[32];
    // Format vruntime in a more readable way (use scientific notation for large numbers)
    if (e->vruntime > 1000000000ULL) {
        snprintf(vruntime_str, sizeof(vruntime_str), "%.2e", (double)e->vruntime);
    } else {
        snprintf(vruntime_str, sizeof(vruntime_str), "%llu", e->vruntime);
    }
    
    char sum_exec_str[32];
    snprintf(sum_exec_str, sizeof(sum_exec_str), "%.3fms", e->sum_exec_runtime / 1e6);
    
    char cfs_min_vr_str[32];
    if (e->cfs_min_vruntime > 1000000000ULL) {
        snprintf(cfs_min_vr_str, sizeof(cfs_min_vr_str), "%.2e", (double)e->cfs_min_vruntime);
    } else {
        snprintf(cfs_min_vr_str, sizeof(cfs_min_vr_str), "%llu", e->cfs_min_vruntime);
    }
    
    char prev_vr_str[32];
    if (e->prev_pid != 0) {
        if (e->prev_vruntime > 1000000000ULL) {
            snprintf(prev_vr_str, sizeof(prev_vr_str), "%.2e", (double)e->prev_vruntime);
        } else {
            snprintf(prev_vr_str, sizeof(prev_vr_str), "%llu", e->prev_vruntime);
        }
    } else {
        strcpy(prev_vr_str, "-");
    }
    
    char wq_addr_str[32];
    if (e->wait_queue_head_addr != 0) {
        snprintf(wq_addr_str, sizeof(wq_addr_str), "0x%016llx", e->wait_queue_head_addr);
    } else {
        strcpy(wq_addr_str, "-");
    }
    
    // Truncate state string if too long
    char state_short[16];
    const char *state_full = state_str(e->task_state);
    strncpy(state_short, state_full, sizeof(state_short) - 1);
    state_short[sizeof(state_short) - 1] = '\0';
    
    const char *wq_type_str = (e->wait_queue_type != 0) ? wait_queue_type_str(e->wait_queue_type) : "-";
    
    printf("%-12s %-3d %-12s %-6u %-6u %-16.16s %-5d %-6d %-15s %-10s %-8llu %-6u %-15.15s %-6u %-15s %-8llu %-10u %-12s %-20s",
           event_name(e->event_type),
           e->cpu,
           time_str,
           e->pid,
           e->tgid,
           e->comm,
           e->prio,
           e->static_prio,
           vruntime_str,
           sum_exec_str,
           e->load_weight,
           e->on_rq,
           state_short,
           e->cfs_nr_running,
           cfs_min_vr_str,
           e->cfs_load_weight,
           e->prev_pid,
           prev_vr_str,
           wq_type_str,
           wq_addr_str);
    
    // Print extra info on same line if available
    switch (e->event_type) {
        case EVT_SWITCH:
            if (e->prev_pid != 0) {
                printf(" prev:%s", e->prev_comm);
            }
            break;
        case EVT_MIGRATE:
            printf(" cpu%d->cpu%d", e->orig_cpu, e->dest_cpu);
            break;
        case EVT_FORK:
            if (e->child_pid != 0) {
                printf(" child:%u", e->child_pid);
            }
            break;
        case EVT_EXEC:
            if (e->filename[0]) {
                printf(" exec:%s", e->filename);
            }
            break;
    }
    printf("\n");
}

// ── ring-buffer callback ─────────────────────────────────────────────────────

static int handle_event(void *ctx, void *data, size_t sz)
{
    const struct sched_event *e = data;
    
    print_header();
    print_event_row(e);
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
    printf("Duration: %d seconds  (Ctrl-C to stop early)\n", duration);
    printf("Output format: Tabular\n");
    header_printed = 0; // Reset header flag

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
