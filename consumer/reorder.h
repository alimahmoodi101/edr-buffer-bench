/* SPDX-License-Identifier: GPL-2.0 */
/*
 * reorder.h - reorder buffer. Holds events for a short window after they
 * arrive and releases them sorted by global sequence number.
 *
 * Release rule (checked on every push and every flush):
 *   - the smallest held seq is released as soon as it is the next expected
 *     one (no waiting when nothing is missing), or
 *   - once it has been held for `window_ns` (the missing seq is assumed
 *     lost, or later than the window allows).
 * An event that arrives after a larger seq was already released is "late":
 * it is still delivered immediately, and counted.
 */
#ifndef EDR_REORDER_H
#define EDR_REORDER_H

#include <stddef.h>
#include "event.h"

typedef void (*reorder_out_fn)(void *ctx, const struct edr_event *e);

struct reorder_item {
	struct edr_event e;
	__u64 recv_ns;
};

struct reorder {
	struct reorder_item *heap;   /* binary min-heap on e.seq */
	size_t len, cap;
	__u64 window_ns;             /* 0 = pass-through, no reordering */
	__u64 next_seq;              /* smallest seq not released yet */
	reorder_out_fn out;
	void *ctx;
	/* statistics */
	__u64 released, late, timeouts;
	size_t max_len;
};

void reorder_init(struct reorder *r, __u64 window_ns, reorder_out_fn out, void *ctx);
void reorder_push(struct reorder *r, const struct edr_event *e, __u64 now_ns);
void reorder_flush(struct reorder *r, __u64 now_ns);   /* release what is due */
void reorder_flush_all(struct reorder *r);            /* release everything  */
void reorder_free(struct reorder *r);

#endif
