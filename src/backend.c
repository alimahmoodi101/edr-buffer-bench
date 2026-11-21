// SPDX-License-Identifier: GPL-2.0
/*
 * backend.c - loads the BPF probes for one buffer design and delivers
 * events to a callback. See backend.h for the API.
 *
 * Memory budget (kept identical across designs, see docs/CONTRACT.md):
 *   FIFO   : one ring buffer of mem_bytes
 *   PERCPU : mem_bytes / ncpu per CPU (rounded down to a power-of-two
 *            number of pages, as the kernel requires)
 *   PRIO   : high ring = mem/4 ; low ring = mem, but the kernel caps its
 *            fill at mem - mem/4. Usable memory is therefore mem in total.
 *            (Ring sizes must be powers of two, so a 3/4-sized ring cannot
 *            exist; the cap gives the exact split instead.)
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "backend.h"
#include "probes.skel.h"

_Static_assert(sizeof(struct edr_event) == 128, "edr_event must be 128 bytes");

struct backend {
	struct probes_bpf  *skel;
	struct ring_buffer *rb;
	struct perf_buffer *pb;
	edr_event_cb cb;
	void *ctx;
	struct backend_opts o;
	__u64 received[PRIO_MAX];
	__u64 user_lost;
};

const char *design_name(enum edr_design d)
{
	switch (d) {
	case DESIGN_FIFO:   return "fifo";
	case DESIGN_PERCPU: return "percpu";
	case DESIGN_PRIO:   return "prio";
	}
	return "?";
}

int design_parse(const char *s, enum edr_design *out)
{
	if (!strcmp(s, "fifo"))   { *out = DESIGN_FIFO;   return 0; }
	if (!strcmp(s, "percpu")) { *out = DESIGN_PERCPU; return 0; }
	if (!strcmp(s, "prio"))   { *out = DESIGN_PRIO;   return 0; }
	return -EINVAL;
}

static bool is_pow2(size_t x) { return x && !(x & (x - 1)); }

static size_t pow2_floor(size_t x)
{
	size_t p = 1;
	while (p * 2 <= x)
		p *= 2;
	return p;
}

/* ---- callbacks from libbpf --------------------------------------------- */
static int deliver(struct backend *b, const void *data, size_t size)
{
	const struct edr_event *e = data;

	if (size < sizeof(*e))
		return 0;
	if (e->prio < PRIO_MAX)
		b->received[e->prio]++;
	return b->cb ? b->cb(b->ctx, e) : 0;
}

static int on_ring(void *ctx, void *data, size_t size)
{
	return deliver(ctx, data, size);
}

static void on_perf(void *ctx, int cpu, void *data, __u32 size)
{
	(void)cpu;
	deliver(ctx, data, size);
}

static void on_perf_lost(void *ctx, int cpu, __u64 cnt)
{
	(void)cpu;
	((struct backend *)ctx)->user_lost += cnt;
}

static int libbpf_quiet(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, fmt, ap);
}

/* ---- public API -------------------------------------------------------- */
struct backend *backend_open(const struct backend_opts *o, edr_event_cb cb, void *ctx)
{
	struct backend *b;
	size_t page = sysconf(_SC_PAGESIZE);
	size_t mem = o->mem_bytes;
	int ncpu, err;

	if (!is_pow2(mem) || mem < (64u << 10)) {
		fprintf(stderr, "backend: mem_bytes must be a power of two >= 64K\n");
		return NULL;
	}

	libbpf_set_print(libbpf_quiet);

	b = calloc(1, sizeof(*b));
	if (!b)
		return NULL;
	b->o = *o;
	b->cb = cb;
	b->ctx = ctx;

	b->skel = probes_bpf__open();
	if (!b->skel) {
		fprintf(stderr, "backend: failed to open BPF object\n");
		goto fail;
	}

	/* configuration constants (must be set before load) */
	b->skel->rodata->design           = o->design;
	b->skel->rodata->self_tgid        = getpid();
	b->skel->rodata->sampling_enabled = o->sampling && o->design == DESIGN_PRIO;
	b->skel->rodata->sample_thr_pct   = o->sample_thr_pct;

	/* report pids as seen from our own PID namespace (WSL2, containers) */
	{
		struct stat st;
		if (stat("/proc/self/ns/pid", &st) == 0) {
			b->skel->rodata->pidns_dev = st.st_dev;
			b->skel->rodata->pidns_ino = st.st_ino;
		}
	}

	/* size the buffers; unused rings get a single page */
	bpf_map__set_max_entries(b->skel->maps.rb_fifo, page);
	bpf_map__set_max_entries(b->skel->maps.rb_high, page);
	bpf_map__set_max_entries(b->skel->maps.rb_low,  page);

	if (o->design == DESIGN_FIFO) {
		bpf_map__set_max_entries(b->skel->maps.rb_fifo, mem);
	} else if (o->design == DESIGN_PRIO) {
		unsigned div = o->high_share_div ? o->high_share_div : 4;
		size_t high = pow2_floor(mem / div);
		if (high < page)
			high = page;
		bpf_map__set_max_entries(b->skel->maps.rb_high, high);
		bpf_map__set_max_entries(b->skel->maps.rb_low,  mem);
		b->skel->rodata->low_cap_bytes = mem - high;
	}

	if (!o->trace_read)
		bpf_program__set_autoload(b->skel->progs.handle_read, false);

	/* Some syscalls (e.g. rename, unlink) do not exist on ARM64. Skip any
	 * syscall probe whose tracepoint is missing on this machine. */
	{
		const char *roots[] = { "/sys/kernel/tracing/events/syscalls",
					"/sys/kernel/debug/tracing/events/syscalls" };
		const char *root = NULL;
		struct bpf_program *prog;
		char path[256];

		for (size_t i = 0; i < 2 && !root; i++)
			if (access(roots[i], F_OK) == 0)
				root = roots[i];
		bpf_object__for_each_program(prog, b->skel->obj) {
			const char *sec = bpf_program__section_name(prog);
			if (!root || strncmp(sec, "tp/syscalls/", 12))
				continue;
			snprintf(path, sizeof(path), "%s/%s", root, sec + 12);
			if (access(path, F_OK) != 0) {
				fprintf(stderr, "backend: note: %s not on this kernel, skipped\n", sec + 12);
				bpf_program__set_autoload(prog, false);
			}
		}
	}

	err = probes_bpf__load(b->skel);
	if (err) {
		fprintf(stderr, "backend: BPF load failed (%d). Run with sudo? "
			"Kernel >= 5.12 with BTF?\n", err);
		goto fail;
	}

	if (o->design == DESIGN_PERCPU) {
		ncpu = libbpf_num_possible_cpus();
		if (ncpu <= 0)
			goto fail;
		size_t pages = pow2_floor(mem / (size_t)ncpu / page);
		if (pages < 1)
			pages = 1;
		b->pb = perf_buffer__new(bpf_map__fd(b->skel->maps.perf_events),
					 pages, on_perf, on_perf_lost, b, NULL);
		if (!b->pb) {
			fprintf(stderr, "backend: perf_buffer__new failed: %s\n", strerror(errno));
			goto fail;
		}
		if (pages * page * ncpu != mem)
			fprintf(stderr, "backend: note: per-CPU buffers use %zu KiB total "
				"(%d CPUs x %zu pages)\n", pages * page * ncpu >> 10, ncpu, pages);
	} else {
		struct bpf_map *first = o->design == DESIGN_PRIO ? b->skel->maps.rb_high
								 : b->skel->maps.rb_fifo;
		b->rb = ring_buffer__new(bpf_map__fd(first), on_ring, b, NULL);
		if (!b->rb) {
			fprintf(stderr, "backend: ring_buffer__new failed: %s\n", strerror(errno));
			goto fail;
		}
		/* high ring is added first, so it is drained first on every poll */
		if (o->design == DESIGN_PRIO &&
		    ring_buffer__add(b->rb, bpf_map__fd(b->skel->maps.rb_low), on_ring, b)) {
			fprintf(stderr, "backend: ring_buffer__add failed\n");
			goto fail;
		}
	}

	err = probes_bpf__attach(b->skel);
	if (err) {
		fprintf(stderr, "backend: attach failed (%d)\n", err);
		goto fail;
	}
	return b;

fail:
	backend_close(b);
	return NULL;
}

int backend_poll(struct backend *b, int timeout_ms)
{
	int n = b->rb ? ring_buffer__poll(b->rb, timeout_ms)
		      : perf_buffer__poll(b->pb, timeout_ms);
	return n == -EINTR ? 0 : n;
}

int backend_drain(struct backend *b)
{
	int n = b->rb ? ring_buffer__consume(b->rb) : perf_buffer__consume(b->pb);
	return n == -EINTR ? 0 : n;
}

void backend_stop(struct backend *b)
{
	if (b && b->skel)
		probes_bpf__detach(b->skel);
}

void backend_stats(struct backend *b, struct edr_stats *out)
{
	memset(out, 0, sizeof(*out));
	out->k             = b->skel->bss->kstats;
	out->total_emitted = b->skel->bss->g_seq;
	memcpy(out->received, b->received, sizeof(out->received));
	out->user_lost     = b->user_lost;
}

int backend_mark_suspicious(struct backend *b, __u32 tgid)
{
	__u8 one = 1;
	return bpf_map__update_elem(b->skel->maps.suspicious, &tgid, sizeof(tgid),
				    &one, sizeof(one), BPF_ANY);
}

void backend_close(struct backend *b)
{
	if (!b)
		return;
	ring_buffer__free(b->rb);
	perf_buffer__free(b->pb);
	probes_bpf__destroy(b->skel);
	free(b);
}
