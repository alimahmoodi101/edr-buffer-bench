/* SPDX-License-Identifier: GPL-2.0 */
/*
 * event.h - THE shared contract between the kernel probes and every
 * user-space component. Kernel (bpf/) and user space (src/, consumer/,
 * tools/) both include this file, so the struct layout is always identical.
 *
 * DO NOT change field order or sizes without telling the whole group:
 * every log, parser and analysis script depends on it.
 */
#ifndef EDR_EVENT_H
#define EDR_EVENT_H

#ifndef __VMLINUX_H__          /* user space: vmlinux.h is not included */
#include <linux/types.h>
#endif

#define EDR_COMM_LEN 16
#define EDR_PATH_LEN 48        /* paths longer than this are truncated */

/* ---- event types ------------------------------------------------------ */
enum edr_event_type {
	EV_EXEC   = 1,   /* sched_process_exec           path = binary          */
	EV_FORK   = 2,   /* sched_process_fork           arg1 = child pid       */
	EV_OPEN   = 3,   /* sys_enter_openat             path = file, arg1=flags*/
	EV_WRITE  = 4,   /* sys_enter_write              arg1 = fd, arg2 = count*/
	EV_RENAME = 5,   /* sys_enter_renameat2          path = old name        */
	EV_UNLINK = 6,   /* sys_enter_unlinkat           path = file            */
	EV_SETUID = 7,   /* sys_enter_setuid/setreuid/setresuid  arg1 = new uid */
	EV_READ   = 8,   /* sys_enter_read               arg1 = fd, arg2 = count*/
	EV_TYPE_MAX
};

/* ---- priority classes -------------------------------------------------- */
enum edr_prio {
	PRIO_LOW  = 0,   /* open, read, write   - high volume, rarely decisive  */
	PRIO_HIGH = 1,   /* exec, fork, setuid, rename, unlink - attack steps   */
	PRIO_MAX
};

/* ---- buffer designs ---------------------------------------------------- */
enum edr_design {
	DESIGN_FIFO   = 0,   /* one BPF ring buffer shared by all CPUs          */
	DESIGN_PERCPU = 1,   /* BPF perf event array, one buffer per CPU        */
	DESIGN_PRIO   = 2,   /* separate high / low priority ring buffers       */
};

/* ---- the event record (128 bytes, 8-byte aligned) --------------------- */
struct edr_event {
	__u64 seq;        /* global sequence number, assigned in kernel, starts at 1.
	                     A gap in received seq numbers = a lost event.       */
	__u64 class_seq;  /* sequence number within this event's priority class */
	__u64 ts_ns;      /* bpf_ktime_get_ns() == CLOCK_MONOTONIC in user space */
	__u32 pid;        /* thread id                                          */
	__u32 tgid;       /* process id (what `ps` shows as PID)                */
	__u32 ppid;       /* parent process id                                  */
	__u32 uid;        /* real uid of the caller                             */
	__u64 arg1;       /* meaning depends on type, see enum above            */
	__u64 arg2;
	__u32 cpu;        /* CPU the event happened on                          */
	__u16 type;       /* enum edr_event_type                                */
	__u8  prio;       /* enum edr_prio                                      */
	__u8  _pad;
	char  comm[EDR_COMM_LEN];
	char  path[EDR_PATH_LEN];
};
/*
 * Note: path is 48 bytes so the record is exactly 128 bytes, which keeps
 * per-event cost low under burst load. That is enough for the sandbox
 * file names (e.g. "/tmp/edr_sandbox/f_00042.dat"). Longer paths keep
 * their first 47 characters.
 */

/* ---- counters the kernel keeps (read via backend_stats) --------------- */
struct edr_kstats {
	__u64 emitted[PRIO_MAX];      /* seq numbers handed out, per class      */
	__u64 drops[PRIO_MAX];        /* buffer was full -> event lost          */
	__u64 sampled_out[PRIO_MAX];  /* dropped ON PURPOSE by adaptive sampling
	                                 (these do NOT get a seq number, so they
	                                 never show up as gaps)                 */
};

#endif /* EDR_EVENT_H */
