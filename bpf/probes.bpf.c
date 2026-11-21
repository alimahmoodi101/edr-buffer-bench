// SPDX-License-Identifier: GPL-2.0
/*
 * probes.bpf.c - kernel side of the EDR telemetry pipeline (Part 1).
 *
 * One BPF object contains all three buffer designs. User space picks the
 * design before loading by setting the read-only `design` variable; the
 * verifier then removes the code paths of the other two designs, so there
 * is no runtime cost for the unused ones.
 *
 * Every probe does the same thing:
 *   1. fill an edr_event on the stack
 *   2. (priority design only) apply the low-priority cap / adaptive sampling
 *   3. hand out a global sequence number + timestamp
 *   4. push the event into the chosen buffer; if full, count a drop
 *
 * Because the sequence number is taken BEFORE the push, a full buffer
 * always leaves a gap in the sequence that user space can see.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "event.h"

char LICENSE[] SEC("license") = "GPL";

/* ---- configuration, set by user space before load (src/backend.c) ----- */
const volatile int   design           = DESIGN_FIFO;
const volatile __u32 self_tgid        = 0;   /* never trace the consumer itself */
const volatile __u64 low_cap_bytes    = 0;   /* PRIO: low ring may only fill this much */
const volatile bool  sampling_enabled = false;
const volatile __u32 sample_thr_pct   = 70;  /* start sampling above this fill % */

/* ---- buffers (sizes are overridden by user space) ---------------------- */
struct {                                   /* DESIGN_FIFO */
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb_fifo SEC(".maps");

struct {                                   /* DESIGN_PERCPU */
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} perf_events SEC(".maps");

struct {                                   /* DESIGN_PRIO, high class */
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb_high SEC(".maps");

struct {                                   /* DESIGN_PRIO, low class */
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} rb_low SEC(".maps");

/* Processes the detector has flagged. Their low-priority events are never
 * sampled out. User space fills this via backend_mark_suspicious(). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);   /* tgid */
	__type(value, __u8);
} suspicious SEC(".maps");

/* ---- global counters (in .bss, user space reads them directly) -------- */
__u64 g_seq = 0;
struct edr_kstats kstats = {};

/* ---- helpers ----------------------------------------------------------- */
static __always_inline bool skip_self(void)
{
	return self_tgid && (bpf_get_current_pid_tgid() >> 32) == self_tgid;
}

static __always_inline void fill_common(struct edr_event *e, __u16 type, __u8 prio)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	e->pid  = (__u32)id;
	e->tgid = id >> 32;
	e->uid  = (__u32)bpf_get_current_uid_gid();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->cpu  = bpf_get_smp_processor_id();
	e->type = type;
	e->prio = prio;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/* Adaptive sampling (priority design, low class only).
 * Returns true if this event should be thrown away on purpose. */
static __always_inline bool sample_out(struct edr_event *e)
{
	__u64 cap, used, pct;
	__u32 n;

	if (!sampling_enabled)
		return false;
	if (bpf_map_lookup_elem(&suspicious, &e->tgid))
		return false;                 /* flagged process: keep everything */

	cap  = low_cap_bytes;
	used = bpf_ringbuf_query(&rb_low, BPF_RB_AVAIL_DATA);
	if (!cap)
		return false;
	pct = used * 100 / cap;
	if (pct < sample_thr_pct)
		return false;

	/* stricter as pressure grows: keep 1/2, then 1/4, then 1/8 */
	n = pct >= 90 ? 8 : (pct >= 80 ? 4 : 2);
	return (bpf_get_prandom_u32() % n) != 0;
}

static __always_inline int emit(void *ctx, struct edr_event *e)
{
	__u32 p = e->prio;
	long err;

	if (p >= PRIO_MAX)
		return 0;

	if (design == DESIGN_PRIO && p == PRIO_LOW && sample_out(e)) {
		__sync_fetch_and_add(&kstats.sampled_out[p], 1);
		return 0;                     /* no seq number -> not a "loss" */
	}

	e->seq       = __sync_fetch_and_add(&g_seq, 1) + 1;
	e->class_seq = __sync_fetch_and_add(&kstats.emitted[p], 1) + 1;
	e->ts_ns     = bpf_ktime_get_ns();

	if (design == DESIGN_PERCPU) {
		err = bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU,
					    e, sizeof(*e));
	} else if (design == DESIGN_PRIO) {
		if (p == PRIO_HIGH) {
			err = bpf_ringbuf_output(&rb_high, e, sizeof(*e), 0);
		} else {
			/* low class may not eat the space reserved for high */
			if (low_cap_bytes &&
			    bpf_ringbuf_query(&rb_low, BPF_RB_AVAIL_DATA) + sizeof(*e) + 8 > low_cap_bytes)
				err = -1;
			else
				err = bpf_ringbuf_output(&rb_low, e, sizeof(*e), 0);
		}
	} else {
		err = bpf_ringbuf_output(&rb_fifo, e, sizeof(*e), 0);
	}

	if (err)
		__sync_fetch_and_add(&kstats.drops[p], 1);
	return 0;
}

#define NEW_EVENT(e, type, prio)                 \
	struct edr_event e;                      \
	if (skip_self())                         \
		return 0;                        \
	__builtin_memset(&e, 0, sizeof(e));      \
	fill_common(&e, type, prio)

/* ---- process events ---------------------------------------------------- */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned int off = ctx->__data_loc_filename & 0xFFFF;
	NEW_EVENT(e, EV_EXEC, PRIO_HIGH);
	bpf_probe_read_kernel_str(e.path, sizeof(e.path), (void *)ctx + off);
	return emit(ctx, &e);
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	NEW_EVENT(e, EV_FORK, PRIO_HIGH);
	e.arg1 = ctx->child_pid;
	return emit(ctx, &e);
}

/* ---- privilege changes ------------------------------------------------- */
SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_SETUID, PRIO_HIGH);
	e.arg1 = ctx->args[0];            /* uid */
	return emit(ctx, &e);
}

SEC("tp/syscalls/sys_enter_setreuid")
int handle_setreuid(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_SETUID, PRIO_HIGH);
	e.arg1 = ctx->args[1];            /* euid */
	return emit(ctx, &e);
}

SEC("tp/syscalls/sys_enter_setresuid")
int handle_setresuid(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_SETUID, PRIO_HIGH);
	e.arg1 = ctx->args[1];            /* euid */
	return emit(ctx, &e);
}

/* ---- renames and deletions (several syscalls do the same job) --------- */
SEC("tp/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_RENAME, PRIO_HIGH);
	bpf_probe_read_user_str(e.path, sizeof(e.path), (const char *)ctx->args[1]);
	return emit(ctx, &e);
}

SEC("tp/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_RENAME, PRIO_HIGH);
	bpf_probe_read_user_str(e.path, sizeof(e.path), (const char *)ctx->args[1]);
	return emit(ctx, &e);
}

SEC("tp/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_RENAME, PRIO_HIGH);
	bpf_probe_read_user_str(e.path, sizeof(e.path), (const char *)ctx->args[0]);
	return emit(ctx, &e);
}

SEC("tp/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_UNLINK, PRIO_HIGH);
	bpf_probe_read_user_str(e.path, sizeof(e.path), (const char *)ctx->args[1]);
	return emit(ctx, &e);
}

SEC("tp/syscalls/sys_enter_unlink")
int handle_unlink(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_UNLINK, PRIO_HIGH);
	bpf_probe_read_user_str(e.path, sizeof(e.path), (const char *)ctx->args[0]);
	return emit(ctx, &e);
}

/* ---- high-volume file activity (low priority) ------------------------- */
SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_OPEN, PRIO_LOW);
	bpf_probe_read_user_str(e.path, sizeof(e.path), (const char *)ctx->args[1]);
	e.arg1 = ctx->args[2];            /* open flags */
	return emit(ctx, &e);
}

SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_WRITE, PRIO_LOW);
	e.arg1 = ctx->args[0];            /* fd */
	e.arg2 = ctx->args[2];            /* bytes */
	return emit(ctx, &e);
}

SEC("tp/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx)
{
	NEW_EVENT(e, EV_READ, PRIO_LOW);
	e.arg1 = ctx->args[0];            /* fd */
	e.arg2 = ctx->args[2];            /* bytes */
	return emit(ctx, &e);
}
