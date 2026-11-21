/* SPDX-License-Identifier: GPL-2.0 */
/*
 * consumer.h - the interface between the consumer (Part 3) and the
 * detector (Part 4).
 *
 * The consumer receives events, puts them back into sequence order with the
 * reorder buffer, and calls the detector hooks below. The detector never
 * talks to eBPF or writes files itself: it calls consumer_alert() and
 * consumer_mark_suspicious().
 *
 * HOW PART 4 PLUGS IN: create consumer/detector.c and define the four
 * detector_* functions. consumer.c has empty "weak" default versions, so the
 * consumer builds and runs without a detector, and your definitions replace
 * them automatically at link time. No other file needs to change.
 */
#ifndef EDR_CONSUMER_H
#define EDR_CONSUMER_H

#include <stdbool.h>
#include "event.h"

/* ---- hooks the detector implements (Part 4) ---------------------------- */

/* Called once before the first event. */
void detector_init(void);

/* Called for every event, in sequence order (after the reorder buffer).
 * Gaps in e->seq are lost events. Events from the kernel arrive with
 * e->ts_ns on the same clock as consumer_now_ns(). Must be fast. */
void detector_event(const struct edr_event *e);

/* Called about every 10 ms, also when no events arrive. Use it to expire
 * old state from sliding windows. */
void detector_tick(__u64 now_ns);

/* Called once after the last event. */
void detector_finish(void);

/* ---- services the consumer provides ------------------------------------ */

/* Report a detection. Writes one alerts.csv line
 *     alert_ns,attack,tgid,first_event_ts_ns,first_event_seq
 * with alert_ns = now. attack must be "ransomware", "forkstorm" or "privesc".
 * first_event_* identify the first event of the matched sequence (it is the
 * start of the detection-latency measurement). */
void consumer_alert(const char *attack, __u32 tgid,
		    __u64 first_event_ts_ns, __u64 first_event_seq);

/* Tell the kernel this process looks suspicious: with adaptive sampling on,
 * its low-priority events are never sampled out again. Cheap to call more
 * than once. */
void consumer_mark_suspicious(__u32 tgid);

/* CLOCK_MONOTONIC in nanoseconds (same clock as e->ts_ns). */
__u64 consumer_now_ns(void);

#endif
