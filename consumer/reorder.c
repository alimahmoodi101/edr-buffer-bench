// SPDX-License-Identifier: GPL-2.0
/* reorder.c - see reorder.h */
#include <stdio.h>
#include <stdlib.h>
#include "reorder.h"

void reorder_init(struct reorder *r, __u64 window_ns, reorder_out_fn out, void *ctx)
{
	*r = (struct reorder){ .window_ns = window_ns, .next_seq = 1,
			       .out = out, .ctx = ctx };
}

static void swap(struct reorder_item *a, struct reorder_item *b)
{
	struct reorder_item t = *a;
	*a = *b;
	*b = t;
}

static void heap_push(struct reorder *r, const struct edr_event *e, __u64 now)
{
	if (r->len == r->cap) {
		r->cap = r->cap ? r->cap * 2 : 4096;
		r->heap = realloc(r->heap, r->cap * sizeof(*r->heap));
		if (!r->heap) {
			perror("reorder: realloc");
			exit(1);
		}
	}
	size_t i = r->len++;
	r->heap[i].e = *e;
	r->heap[i].recv_ns = now;
	while (i > 0) {
		size_t p = (i - 1) / 2;
		if (r->heap[p].e.seq <= r->heap[i].e.seq)
			break;
		swap(&r->heap[p], &r->heap[i]);
		i = p;
	}
	if (r->len > r->max_len)
		r->max_len = r->len;
}

static void heap_pop(struct reorder *r)
{
	size_t i = 0;

	r->heap[0] = r->heap[--r->len];
	for (;;) {
		size_t l = 2 * i + 1, s = i;
		if (l < r->len && r->heap[l].e.seq < r->heap[s].e.seq)
			s = l;
		if (l + 1 < r->len && r->heap[l + 1].e.seq < r->heap[s].e.seq)
			s = l + 1;
		if (s == i)
			break;
		swap(&r->heap[i], &r->heap[s]);
		i = s;
	}
}

static void release(struct reorder *r, const struct edr_event *e)
{
	if (e->seq < r->next_seq)
		r->late++;
	else
		r->next_seq = e->seq + 1;
	r->released++;
	r->out(r->ctx, e);
}

static void drain(struct reorder *r, __u64 now, int force)
{
	while (r->len) {
		struct reorder_item *top = &r->heap[0];
		if (!force && top->e.seq > r->next_seq &&
		    now - top->recv_ns < r->window_ns)
			break;
		if (!force && top->e.seq > r->next_seq)
			r->timeouts++;           /* gave up waiting for a gap */
		struct edr_event e = top->e;
		heap_pop(r);
		release(r, &e);
	}
}

void reorder_push(struct reorder *r, const struct edr_event *e, __u64 now)
{
	if (!r->window_ns || e->seq <= r->next_seq) {
		/* nothing to wait for: deliver at once (late ones too) */
		release(r, e);
		if (r->len)
			drain(r, now, 0);        /* it may unblock held events */
		return;
	}
	heap_push(r, e, now);
}

void reorder_flush(struct reorder *r, __u64 now)
{
	drain(r, now, 0);
}

void reorder_flush_all(struct reorder *r)
{
	drain(r, 0, 1);
}

void reorder_free(struct reorder *r)
{
	free(r->heap);
	r->heap = NULL;
	r->len = r->cap = 0;
}
