// SPDX-License-Identifier: GPL-2.0
/*
 * evdump - Part 1 test tool. Loads one buffer design, collects events for a
 * while, then reports what was lost. It proves the kernel side works and
 * produces the standard events.csv / summary.json files (docs/CONTRACT.md),
 * so the analysis owner can start on real data before the consumer exists.
 *
 *   sudo ./build/evdump --design prio --duration 10 --summary -
 *   sudo ./build/evdump --design fifo --print            (watch live events)
 */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "backend.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static const char *type_name[EV_TYPE_MAX] = {
	[EV_EXEC] = "exec", [EV_FORK] = "fork", [EV_OPEN] = "open",
	[EV_WRITE] = "write", [EV_RENAME] = "rename", [EV_UNLINK] = "unlink",
	[EV_SETUID] = "setuid", [EV_READ] = "read",
};

/* growable bitmap: which sequence numbers did we receive? */
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

struct state {
	FILE *csv;
	bool print;
	struct seqset all, cls[PRIO_MAX];
	__u64 max_seq, out_of_order;
};

static __u64 now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void clean(char *dst, const char *src, size_t n)
{
	size_t i;
	for (i = 0; i + 1 < n && src[i]; i++)
		dst[i] = (src[i] == '"' || src[i] == ',' || src[i] == '\n') ? '_' : src[i];
	dst[i] = 0;
}

static int on_event(void *ctx, const struct edr_event *e)
{
	struct state *st = ctx;
	const char *tn = e->type < EV_TYPE_MAX && type_name[e->type] ? type_name[e->type] : "?";

	seqset_add(&st->all, e->seq);
	if (e->prio < PRIO_MAX)
		seqset_add(&st->cls[e->prio], e->class_seq);
	if (e->seq < st->max_seq)
		st->out_of_order++;
	else
		st->max_seq = e->seq;

	if (st->csv) {
		char comm[EDR_COMM_LEN + 1], path[EDR_PATH_LEN + 1];
		clean(comm, e->comm, sizeof(comm));
		clean(path, e->path, sizeof(path));
		fprintf(st->csv, "%llu,%llu,%llu,%llu,%u,%s,%u,%u,%u,%u,%u,%llu,%llu,%s,%s\n",
			(unsigned long long)e->seq, (unsigned long long)e->class_seq,
			(unsigned long long)e->ts_ns, (unsigned long long)now_ns(),
			e->cpu, tn, e->prio, e->pid, e->tgid, e->ppid, e->uid,
			(unsigned long long)e->arg1, (unsigned long long)e->arg2, comm, path);
	}
	if (st->print)
		printf("#%-8llu cpu%u %-6s %s tgid=%-6u ppid=%-6u uid=%-5u %-16.16s %s arg1=%llu\n",
		       (unsigned long long)e->seq, e->cpu, tn, e->prio ? "HIGH" : "low ",
		       e->tgid, e->ppid, e->uid, e->comm, e->path, (unsigned long long)e->arg1);
	return 0;
}

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

static void usage(const char *p)
{
	fprintf(stderr,
		"usage: sudo %s [options]\n"
		"  --design fifo|percpu|prio   buffer design (default fifo)\n"
		"  --mem SIZE                  total kernel buffer memory, power of 2 (default 4M)\n"
		"  --duration SEC              stop after SEC seconds (default: Ctrl-C)\n"
		"  --no-read                   do not trace read() (much less noise)\n"
		"  --sampling                  adaptive sampling (prio design only)\n"
		"  --sample-thr PCT            sampling threshold (default 70)\n"
		"  --csv FILE                  write every event (events.csv format)\n"
		"  --summary FILE|-            write summary.json (- = stdout)\n"
		"  --print                     print events live (slow!)\n", p);
}

int main(int argc, char **argv)
{
	struct backend_opts o = BACKEND_OPTS_DEFAULT;
	struct state st = {0};
	const char *csv_path = NULL, *sum_path = NULL;
	double duration = 0;
	static char csvbuf[1 << 20];

	static const struct option lo[] = {
		{"design", 1, 0, 'd'}, {"mem", 1, 0, 'm'}, {"duration", 1, 0, 't'},
		{"no-read", 0, 0, 'R'}, {"sampling", 0, 0, 's'}, {"sample-thr", 1, 0, 'T'},
		{"csv", 1, 0, 'c'}, {"summary", 1, 0, 'S'}, {"print", 0, 0, 'p'},
		{"help", 0, 0, 'h'}, {0}};
	int c;
	while ((c = getopt_long(argc, argv, "d:m:t:RsT:c:S:ph", lo, NULL)) != -1) {
		switch (c) {
		case 'd': if (design_parse(optarg, &o.design)) { usage(argv[0]); return 1; } break;
		case 'm': o.mem_bytes = parse_size(optarg); break;
		case 't': duration = atof(optarg); break;
		case 'R': o.trace_read = false; break;
		case 's': o.sampling = true; break;
		case 'T': o.sample_thr_pct = atoi(optarg); break;
		case 'c': csv_path = optarg; break;
		case 'S': sum_path = optarg; break;
		case 'p': st.print = true; break;
		default: usage(argv[0]); return c == 'h' ? 0 : 1;
		}
	}

	if (csv_path) {
		st.csv = fopen(csv_path, "w");
		if (!st.csv) { perror(csv_path); return 1; }
		setvbuf(st.csv, csvbuf, _IOFBF, sizeof(csvbuf));
		fprintf(st.csv, "seq,class_seq,ts_ns,recv_ns,cpu,type,prio,pid,tgid,ppid,uid,arg1,arg2,comm,path\n");
	}

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	struct backend *b = backend_open(&o, on_event, &st);
	if (!b)
		return 1;
	fprintf(stderr, "evdump: design=%s mem=%zuK read=%s sampling=%s - collecting%s\n",
		design_name(o.design), o.mem_bytes >> 10, o.trace_read ? "on" : "off",
		o.sampling ? "on" : "off", duration > 0 ? "" : " (Ctrl-C to stop)");

	__u64 t0 = now_ns(), end = t0 + (__u64)(duration * 1e9);
	while (!stop && (duration <= 0 || now_ns() < end)) {
		int n = backend_poll(b, 100);
		if (n < 0) { fprintf(stderr, "poll error %d\n", n); break; }
	}
	double secs = (now_ns() - t0) / 1e9;

	/* detach first so nothing new arrives, then read the leftovers */
	backend_stop(b);
	while (backend_drain(b) > 0)
		;

	struct edr_stats s;
	backend_stats(b, &s);
	__u64 recv = s.received[PRIO_LOW] + s.received[PRIO_HIGH];
	__u64 gaps = s.total_emitted - st.all.uniq;
	__u64 gap_c[PRIO_MAX];
	for (int p = 0; p < PRIO_MAX; p++)
		gap_c[p] = s.k.emitted[p] - st.cls[p].uniq;

	fprintf(stderr,
		"\n=== %s, %.1fs ===\n"
		"emitted      : %llu  (high %llu, low %llu)  = %.0f ev/s\n"
		"received     : %llu  (high %llu, low %llu)\n"
		"lost (gaps)  : %llu  (high %llu, low %llu)  = %.2f%%\n"
		"kernel drops : high %llu, low %llu\n"
		"sampled out  : high %llu, low %llu\n"
		"out of order : %llu (%.2f%% of received)\n",
		design_name(o.design), secs,
		(unsigned long long)s.total_emitted, (unsigned long long)s.k.emitted[1],
		(unsigned long long)s.k.emitted[0], s.total_emitted / secs,
		(unsigned long long)recv, (unsigned long long)s.received[1],
		(unsigned long long)s.received[0],
		(unsigned long long)gaps, (unsigned long long)gap_c[1], (unsigned long long)gap_c[0],
		s.total_emitted ? 100.0 * gaps / s.total_emitted : 0,
		(unsigned long long)s.k.drops[1], (unsigned long long)s.k.drops[0],
		(unsigned long long)s.k.sampled_out[1], (unsigned long long)s.k.sampled_out[0],
		(unsigned long long)st.out_of_order, recv ? 100.0 * st.out_of_order / recv : 0);
	if (o.design == DESIGN_PERCPU)
		fprintf(stderr, "perf lost    : %llu (reported by perf buffer, cross-check)\n",
			(unsigned long long)s.user_lost);
	if (gaps != s.k.drops[0] + s.k.drops[1])
		fprintf(stderr, "note: gaps != kernel drops (difference %lld)\n",
			(long long)gaps - (long long)(s.k.drops[0] + s.k.drops[1]));

	if (sum_path) {
		FILE *f = strcmp(sum_path, "-") ? fopen(sum_path, "w") : stdout;
		if (!f) { perror(sum_path); return 1; }
		fprintf(f,
			"{\n"
			"  \"design\": \"%s\",\n  \"mem_bytes\": %zu,\n  \"duration_s\": %.3f,\n"
			"  \"trace_read\": %s,\n  \"sampling\": %s,\n"
			"  \"emitted_total\": %llu,\n  \"emitted_high\": %llu,\n  \"emitted_low\": %llu,\n"
			"  \"received_high\": %llu,\n  \"received_low\": %llu,\n"
			"  \"lost_high\": %llu,\n  \"lost_low\": %llu,\n"
			"  \"kernel_drops_high\": %llu,\n  \"kernel_drops_low\": %llu,\n"
			"  \"sampled_out_high\": %llu,\n  \"sampled_out_low\": %llu,\n"
			"  \"perf_lost\": %llu,\n  \"out_of_order\": %llu\n}\n",
			design_name(o.design), o.mem_bytes, secs,
			o.trace_read ? "true" : "false", o.sampling ? "true" : "false",
			(unsigned long long)s.total_emitted, (unsigned long long)s.k.emitted[1],
			(unsigned long long)s.k.emitted[0],
			(unsigned long long)s.received[1], (unsigned long long)s.received[0],
			(unsigned long long)gap_c[1], (unsigned long long)gap_c[0],
			(unsigned long long)s.k.drops[1], (unsigned long long)s.k.drops[0],
			(unsigned long long)s.k.sampled_out[1], (unsigned long long)s.k.sampled_out[0],
			(unsigned long long)s.user_lost, (unsigned long long)st.out_of_order);
		if (f != stdout)
			fclose(f);
	}

	if (st.csv)
		fclose(st.csv);
	backend_close(b);
	return 0;
}
