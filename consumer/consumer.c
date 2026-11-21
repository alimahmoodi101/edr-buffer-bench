// SPDX-License-Identifier: GPL-2.0
/*
 * edr_consumer - Part 3. Receives events from one buffer design, measures
 * loss and ordering, puts events back in sequence order (reorder buffer),
 * feeds them to the detector (Part 4, see consumer.h) and writes the run's
 * output files (docs/CONTRACT.md section 3):
 *
 *   <out>/summary.json   always
 *   <out>/alerts.csv     always (header only if nothing was detected)
 *   <out>/events.csv     only with --events (slows the consumer down)
 *
 *   sudo ./build/edr_consumer --design prio --mem 4M --duration 30 \
 *        [--sampling] [--no-read] [--reorder-ms 50] [--events] --out results/run/
 *
 * Loss and "out_of_order" are measured on the RAW arrival order, exactly
 * like evdump, so the two tools give comparable numbers.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "backend.h"
#include "consumer.h"
#include "reorder.h"

/* ---- default (empty) detector: Part 4's detector.c replaces these ------- */
__attribute__((weak)) void detector_init(void) {}
__attribute__((weak)) void detector_event(const struct edr_event *e) { (void)e; }
__attribute__((weak)) void detector_tick(__u64 now_ns) { (void)now_ns; }
__attribute__((weak)) void detector_finish(void) {}

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static const char *type_name[EV_TYPE_MAX] = {
	[EV_EXEC] = "exec", [EV_FORK] = "fork", [EV_OPEN] = "open",
	[EV_WRITE] = "write", [EV_RENAME] = "rename", [EV_UNLINK] = "unlink",
	[EV_SETUID] = "setuid", [EV_READ] = "read",
};

/* ---- growable bitmap of received sequence numbers ---------------------- */
struct seqset { unsigned char *bits; __u64 cap, uniq; };

static void seqset_add(struct seqset *s, __u64 seq)
{
	if (seq >= s->cap) {
		__u64 ncap = s->cap ? s->cap : (1 << 20);
		while (ncap <= seq)
			ncap *= 2;
		s->bits = realloc(s->bits, ncap / 8);
		if (!s->bits) { perror("realloc"); exit(1); }
		memset(s->bits + s->cap / 8, 0, (ncap - s->cap) / 8);
		s->cap = ncap;
	}
	if (!(s->bits[seq / 8] & (1 << (seq % 8)))) {
		s->bits[seq / 8] |= 1 << (seq % 8);
		s->uniq++;
	}
}

/* ---- per-process ordering of high-priority events ---------------------- */
/* For every tgid: how many of its HIGH events arrived after one of its own
 * events with a larger seq (raw arrival order). Summed over the processes
 * the detector raised alerts for, this is "ooo_pairs_critical": how
 * scrambled the attack sequences looked before the reorder buffer. */
struct tgid_slot { __u32 key; __u8 alerted; __u64 max_seq, ooo; };  /* key = tgid+1 */
struct tgid_map { struct tgid_slot *s; size_t cap, len; };

static struct tgid_slot *tgid_get(struct tgid_map *m, __u32 tgid)
{
	if (m->len * 10 >= m->cap * 7) {          /* grow at 70% full */
		struct tgid_map n = { calloc(m->cap ? m->cap * 2 : 4096, sizeof(*n.s)),
				      m->cap ? m->cap * 2 : 4096, 0 };
		if (!n.s) { perror("calloc"); exit(1); }
		for (size_t i = 0; i < m->cap; i++) {
			if (!m->s[i].key)
				continue;
			size_t j = (m->s[i].key * 2654435761u) & (n.cap - 1);
			while (n.s[j].key)
				j = (j + 1) & (n.cap - 1);
			n.s[j] = m->s[i];
			n.len++;
		}
		free(m->s);
		*m = n;
	}
	__u32 key = tgid + 1;
	size_t j = (key * 2654435761u) & (m->cap - 1);
	while (m->s[j].key && m->s[j].key != key)
		j = (j + 1) & (m->cap - 1);
	if (!m->s[j].key) {
		m->s[j].key = key;
		m->len++;
	}
	return &m->s[j];
}

/* ---- consumer state ----------------------------------------------------- */
static struct {
	struct backend *b;
	struct reorder ro;
	FILE *events, *alerts;
	struct seqset all, cls[PRIO_MAX];
	__u64 max_seq, out_of_order;
	struct tgid_map tgids;
	__u64 n_alerts;
} C;

__u64 consumer_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

void consumer_alert(const char *attack, __u32 tgid,
		    __u64 first_event_ts_ns, __u64 first_event_seq)
{
	fprintf(C.alerts, "%llu,%s,%u,%llu,%llu\n",
		(unsigned long long)consumer_now_ns(), attack, tgid,
		(unsigned long long)first_event_ts_ns,
		(unsigned long long)first_event_seq);
	fflush(C.alerts);              /* alerts are rare; keep the file current */
	tgid_get(&C.tgids, tgid)->alerted = 1;
	C.n_alerts++;
}

void consumer_mark_suspicious(__u32 tgid)
{
	if (C.b)
		backend_mark_suspicious(C.b, tgid);
}

static void clean(char *dst, const char *src, size_t n)
{
	size_t i;
	for (i = 0; i + 1 < n && src[i]; i++)
		dst[i] = (src[i] == '"' || src[i] == ',' || src[i] == '\n') ? '_' : src[i];
	dst[i] = 0;
}

/* Raw arrival: called by the backend for every event it receives. */
static int on_event(void *ctx, const struct edr_event *e)
{
	__u64 now = consumer_now_ns();
	(void)ctx;

	seqset_add(&C.all, e->seq);
	if (e->prio < PRIO_MAX)
		seqset_add(&C.cls[e->prio], e->class_seq);
	if (e->seq < C.max_seq)
		C.out_of_order++;
	else
		C.max_seq = e->seq;

	if (e->prio == PRIO_HIGH) {
		struct tgid_slot *t = tgid_get(&C.tgids, e->tgid);
		if (e->seq < t->max_seq)
			t->ooo++;
		else
			t->max_seq = e->seq;
	}

	if (C.events) {
		char comm[EDR_COMM_LEN + 1], path[EDR_PATH_LEN + 1];
		const char *tn = e->type < EV_TYPE_MAX && type_name[e->type] ? type_name[e->type] : "?";
		clean(comm, e->comm, sizeof(comm));
		clean(path, e->path, sizeof(path));
		fprintf(C.events, "%llu,%llu,%llu,%llu,%u,%s,%u,%u,%u,%u,%u,%llu,%llu,%s,%s\n",
			(unsigned long long)e->seq, (unsigned long long)e->class_seq,
			(unsigned long long)e->ts_ns, (unsigned long long)now,
			e->cpu, tn, e->prio, e->pid, e->tgid, e->ppid, e->uid,
			(unsigned long long)e->arg1, (unsigned long long)e->arg2, comm, path);
	}

	reorder_push(&C.ro, e, now);
	return 0;
}

/* In-order output of the reorder buffer. */
static void on_ordered(void *ctx, const struct edr_event *e)
{
	(void)ctx;
	detector_event(e);
}

/* ---- helpers ------------------------------------------------------------ */
static size_t parse_size(const char *s)
{
	char *end;
	double v = strtod(s, &end);
	switch (*end) {
	case 'k': case 'K': v *= 1024; break;
	case 'm': case 'M': v *= 1024 * 1024; break;
	case 'g': case 'G': v *= 1024 * 1024 * 1024; break;
	}
	return (size_t)v;
}

static int mkdir_p(const char *path)
{
	char tmp[1024];
	snprintf(tmp, sizeof(tmp), "%s", path);
	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = 0;
		if (mkdir(tmp, 0755) && errno != EEXIST)
			return -1;
		*p = '/';
	}
	return mkdir(tmp, 0755) && errno != EEXIST ? -1 : 0;
}

/* Running under sudo: give the output files back to the real user. */
static void give_back(const char *path)
{
	const char *uid = getenv("SUDO_UID"), *gid = getenv("SUDO_GID");
	if (uid && chown(path, atoi(uid), gid ? atoi(gid) : atoi(uid))) {
		/* not fatal */
	}
}

static FILE *open_out(const char *dir, const char *name, char *path_out, size_t n)
{
	snprintf(path_out, n, "%s/%s", dir, name);
	FILE *f = fopen(path_out, "w");
	if (!f)
		perror(path_out);
	return f;
}

/* user + system CPU time of this process. (Not getrusage(): <sys/resource.h>
 * defines a PRIO_MAX macro that clashes with event.h.) */
static double cpu_seconds(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void usage(const char *p)
{
	fprintf(stderr,
		"usage: sudo %s --out DIR [options]\n"
		"  --design fifo|percpu|prio   buffer design (default fifo)\n"
		"  --mem SIZE                  total kernel buffer memory, power of 2 (default 4M)\n"
		"  --duration SEC              stop after SEC seconds (default: Ctrl-C)\n"
		"  --no-read                   do not trace read()\n"
		"  --sampling                  adaptive sampling (prio design only)\n"
		"  --sample-thr PCT            sampling threshold (default 70)\n"
		"  --reorder-ms MS             reorder window (default 50, 0 = off)\n"
		"  --events                    also write events.csv (slow)\n"
		"  --out DIR                   run folder (created if missing)\n", p);
}

int main(int argc, char **argv)
{
	struct backend_opts o = BACKEND_OPTS_DEFAULT;
	const char *out = NULL;
	double duration = 0, reorder_ms = 50;
	bool want_events = false;
	static char evbuf[1 << 20];
	char path[1100], ev_path[1100] = "", al_path[1100];

	static const struct option lo[] = {
		{"design", 1, 0, 'd'}, {"mem", 1, 0, 'm'}, {"duration", 1, 0, 't'},
		{"no-read", 0, 0, 'R'}, {"sampling", 0, 0, 's'}, {"sample-thr", 1, 0, 'T'},
		{"reorder-ms", 1, 0, 'W'}, {"events", 0, 0, 'e'}, {"out", 1, 0, 'o'},
		{"help", 0, 0, 'h'}, {0}};
	int c;
	while ((c = getopt_long(argc, argv, "d:m:t:RsT:W:eo:h", lo, NULL)) != -1) {
		switch (c) {
		case 'd': if (design_parse(optarg, &o.design)) { usage(argv[0]); return 1; } break;
		case 'm': o.mem_bytes = parse_size(optarg); break;
		case 't': duration = atof(optarg); break;
		case 'R': o.trace_read = false; break;
		case 's': o.sampling = true; break;
		case 'T': o.sample_thr_pct = atoi(optarg); break;
		case 'W': reorder_ms = atof(optarg); break;
		case 'e': want_events = true; break;
		case 'o': out = optarg; break;
		default: usage(argv[0]); return c == 'h' ? 0 : 1;
		}
	}
	if (!out) {
		usage(argv[0]);
		return 1;
	}
	if (o.sampling && o.design != DESIGN_PRIO)
		fprintf(stderr, "edr_consumer: note: --sampling only applies to the prio design\n");
	if (mkdir_p(out)) {
		perror(out);
		return 1;
	}
	give_back(out);

	C.alerts = open_out(out, "alerts.csv", al_path, sizeof(al_path));
	if (!C.alerts)
		return 1;
	fprintf(C.alerts, "alert_ns,attack,tgid,first_event_ts_ns,first_event_seq\n");
	fflush(C.alerts);
	if (want_events) {
		C.events = open_out(out, "events.csv", ev_path, sizeof(ev_path));
		if (!C.events)
			return 1;
		setvbuf(C.events, evbuf, _IOFBF, sizeof(evbuf));
		fprintf(C.events, "seq,class_seq,ts_ns,recv_ns,cpu,type,prio,pid,tgid,ppid,uid,arg1,arg2,comm,path\n");
	}

	struct sigaction sa = { .sa_handler = on_sig };
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	reorder_init(&C.ro, (__u64)(reorder_ms * 1e6), on_ordered, NULL);
	detector_init();

	C.b = backend_open(&o, on_event, NULL);
	if (!C.b)
		return 1;
	fprintf(stderr, "edr_consumer: design=%s mem=%zuK read=%s sampling=%s reorder=%gms -> %s\n",
		design_name(o.design), o.mem_bytes >> 10, o.trace_read ? "on" : "off",
		o.sampling ? "on" : "off", reorder_ms, out);

	double cpu0 = cpu_seconds();
	__u64 t0 = consumer_now_ns(), end = t0 + (__u64)(duration * 1e9);
	while (!stop && (duration <= 0 || consumer_now_ns() < end)) {
		int n = backend_poll(C.b, 10);
		if (n < 0) {
			fprintf(stderr, "edr_consumer: poll error %d\n", n);
			break;
		}
		__u64 now = consumer_now_ns();
		reorder_flush(&C.ro, now);
		detector_tick(now);
	}
	double secs = (consumer_now_ns() - t0) / 1e9;

	/* detach first so nothing new arrives, then read and release leftovers */
	backend_stop(C.b);
	while (backend_drain(C.b) > 0)
		;
	reorder_flush_all(&C.ro);
	detector_tick(consumer_now_ns());
	detector_finish();
	double cpu_s = cpu_seconds() - cpu0;

	struct edr_stats s;
	backend_stats(C.b, &s);
	__u64 recv = s.received[PRIO_LOW] + s.received[PRIO_HIGH];
	__u64 gaps = s.total_emitted - C.all.uniq;
	__u64 gap_c[PRIO_MAX];
	for (int p = 0; p < PRIO_MAX; p++)
		gap_c[p] = s.k.emitted[p] - C.cls[p].uniq;

	__u64 ooo_crit = 0;
	for (size_t i = 0; i < C.tgids.cap; i++)
		if (C.tgids.s[i].key && C.tgids.s[i].alerted)
			ooo_crit += C.tgids.s[i].ooo;

	fprintf(stderr,
		"\n=== %s, %.1fs ===\n"
		"emitted      : %llu  (high %llu, low %llu)  = %.0f ev/s\n"
		"received     : %llu  (high %llu, low %llu)\n"
		"lost (gaps)  : %llu  (high %llu, low %llu)  = %.2f%%\n"
		"kernel drops : high %llu, low %llu\n"
		"sampled out  : high %llu, low %llu\n"
		"out of order : %llu raw (%.2f%%), %llu late after reorder, peak held %zu\n"
		"alerts       : %llu   consumer cpu: %.2fs\n",
		design_name(o.design), secs,
		(unsigned long long)s.total_emitted, (unsigned long long)s.k.emitted[1],
		(unsigned long long)s.k.emitted[0], s.total_emitted / secs,
		(unsigned long long)recv, (unsigned long long)s.received[1],
		(unsigned long long)s.received[0],
		(unsigned long long)gaps, (unsigned long long)gap_c[1], (unsigned long long)gap_c[0],
		s.total_emitted ? 100.0 * gaps / s.total_emitted : 0,
		(unsigned long long)s.k.drops[1], (unsigned long long)s.k.drops[0],
		(unsigned long long)s.k.sampled_out[1], (unsigned long long)s.k.sampled_out[0],
		(unsigned long long)C.out_of_order, recv ? 100.0 * C.out_of_order / recv : 0,
		(unsigned long long)C.ro.late, C.ro.max_len,
		(unsigned long long)C.n_alerts, cpu_s);

	FILE *f = open_out(out, "summary.json", path, sizeof(path));
	if (f) {
		fprintf(f,
			"{\n"
			"  \"design\": \"%s\",\n  \"mem_bytes\": %zu,\n  \"duration_s\": %.3f,\n"
			"  \"trace_read\": %s,\n  \"sampling\": %s,\n"
			"  \"emitted_total\": %llu,\n  \"emitted_high\": %llu,\n  \"emitted_low\": %llu,\n"
			"  \"received_high\": %llu,\n  \"received_low\": %llu,\n"
			"  \"lost_high\": %llu,\n  \"lost_low\": %llu,\n"
			"  \"kernel_drops_high\": %llu,\n  \"kernel_drops_low\": %llu,\n"
			"  \"sampled_out_high\": %llu,\n  \"sampled_out_low\": %llu,\n"
			"  \"perf_lost\": %llu,\n  \"out_of_order\": %llu,\n"
			"  \"ooo_pairs_critical\": %llu,\n  \"consumer_cpu_s\": %.3f,\n"
			"  \"reorder_ms\": %g,\n  \"reorder_late\": %llu,\n"
			"  \"reorder_timeouts\": %llu,\n  \"reorder_peak_held\": %zu,\n"
			"  \"alerts\": %llu\n}\n",
			design_name(o.design), o.mem_bytes, secs,
			o.trace_read ? "true" : "false", o.sampling ? "true" : "false",
			(unsigned long long)s.total_emitted, (unsigned long long)s.k.emitted[1],
			(unsigned long long)s.k.emitted[0],
			(unsigned long long)s.received[1], (unsigned long long)s.received[0],
			(unsigned long long)gap_c[1], (unsigned long long)gap_c[0],
			(unsigned long long)s.k.drops[1], (unsigned long long)s.k.drops[0],
			(unsigned long long)s.k.sampled_out[1], (unsigned long long)s.k.sampled_out[0],
			(unsigned long long)s.user_lost, (unsigned long long)C.out_of_order,
			(unsigned long long)ooo_crit, cpu_s,
			reorder_ms, (unsigned long long)C.ro.late,
			(unsigned long long)C.ro.timeouts, C.ro.max_len,
			(unsigned long long)C.n_alerts);
		fclose(f);
		give_back(path);
	}

	fclose(C.alerts);
	give_back(al_path);
	if (C.events) {
		fclose(C.events);
		give_back(ev_path);
	}
	backend_close(C.b);
	reorder_free(&C.ro);
	return 0;
}
