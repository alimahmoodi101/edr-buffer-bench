/* SPDX-License-Identifier: GPL-2.0 */
/*
 * backend.h - the ONLY interface user-space code needs to talk to the
 * kernel probes. The consumer/detector (Part 3/4) and the benchmark harness
 * (Part 5) use this API and never touch eBPF directly.
 *
 * Typical use:
 *
 *     struct backend_opts o = BACKEND_OPTS_DEFAULT;
 *     o.design = DESIGN_PRIO;
 *     struct backend *b = backend_open(&o, my_callback, my_ctx);
 *     while (running) backend_poll(b, 100);
 *     backend_stop(b);          // detach probes: no new events
 *     backend_drain(b);         // read what is still in the buffers
 *     backend_stats(b, &st);
 *     backend_close(b);
 */
#ifndef EDR_BACKEND_H
#define EDR_BACKEND_H

#include <stddef.h>
#include <stdbool.h>
#include "event.h"

struct backend_opts {
	enum edr_design design;
	size_t mem_bytes;       /* TOTAL kernel buffer budget, same for every design.
	                           Must be a power of two, >= 64 KiB. Default 4 MiB. */
	unsigned high_share_div;/* PRIO: high ring = mem / this (default 4 -> 25%) */
	bool   trace_read;      /* attach the read() probe (very high volume)     */
	bool   sampling;        /* adaptive sampling (PRIO design only)           */
	unsigned sample_thr_pct;/* start sampling above this fill level (70)      */
};

#define BACKEND_OPTS_DEFAULT { .design = DESIGN_FIFO, .mem_bytes = 4u << 20, \
	.high_share_div = 4, .trace_read = true, .sampling = false,          \
	.sample_thr_pct = 70 }

/* Called once per received event, in the consumer's thread. Must be fast.
 * Return 0 to continue. */
typedef int (*edr_event_cb)(void *ctx, const struct edr_event *e);

struct edr_stats {
	struct edr_kstats k;       /* kernel counters: emitted, drops, sampled_out */
	__u64 total_emitted;       /* = highest global seq handed out            */
	__u64 received[PRIO_MAX];  /* events delivered to the callback           */
	__u64 user_lost;           /* PERCPU only: lost samples reported by the
	                              perf buffer itself (cross-check for drops) */
};

struct backend;

struct backend *backend_open(const struct backend_opts *o, edr_event_cb cb, void *ctx);
int  backend_poll(struct backend *b, int timeout_ms);  /* >=0 events, <0 error */
int  backend_drain(struct backend *b);                 /* non-blocking read-all */
void backend_stop(struct backend *b);                  /* detach all probes     */
void backend_stats(struct backend *b, struct edr_stats *out);
int  backend_mark_suspicious(struct backend *b, __u32 tgid);
void backend_close(struct backend *b);

const char *design_name(enum edr_design d);
int  design_parse(const char *s, enum edr_design *out);  /* "fifo|percpu|prio" */

#endif
