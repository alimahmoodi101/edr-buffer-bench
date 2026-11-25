// SPDX-License-Identifier: GPL-2.0
//detector.c - Part 4: looks at events (already in seq order) and raises alerts
//rules are the ones in docs/CONTRACT.md section 5
#include <stdbool.h>
#include <string.h>
#include "consumer.h"

#define SEC 1000000000ll

//the limits from the contract
#define RANSOM_N 50
#define RANSOM_WIN (5 * SEC)
#define FORK_N 100
#define FORK_WIN (1 * SEC)
#define PRIV_WIN (2 * SEC)

//table of processes we are keeping an eye on
#define SLOTS 4096
#define STALE (10 * SEC)

struct hit {
	__u64 ts;
	__u64 seq;
};

struct proc {
	bool used;
	__u32 tgid;
	__u64 last_ts;
	bool ransom_done, fork_done, priv_done;
	bool ransom_flag, fork_flag;

	struct hit rn[RANSOM_N];
	unsigned rn_head, rn_cnt;

	struct hit fk[FORK_N];
	unsigned fk_head, fk_cnt;

	bool priv_wait;
	__u64 priv_ts, priv_seq;
};

static struct proc tab[SLOTS];

//find the entry for a tgid. old entries get reused when we need space
static struct proc *get_proc(__u32 tgid, __u64 now, bool create)
{
	size_t start = (tgid * 2654435761u) & (SLOTS - 1);
	size_t i = start;
	struct proc *spare = NULL;

	for (int n = 0; n < 64; n++, i = (i + 1) & (SLOTS - 1)) {
		struct proc *p = &tab[i];
		if (!p->used) {
			if (!spare)
				spare = p;
			break;
		}
		if (p->tgid == tgid) {
			//same number but long ago, so a different process
			if ((long long)(now - p->last_ts) > STALE)
				break;
			p->last_ts = now;
			return p;
		}
		if (!spare && (long long)(now - p->last_ts) > STALE)
			spare = p;
	}
	if (!create)
		return NULL;
	if (!spare)
		spare = &tab[start];
	memset(spare, 0, sizeof(*spare));
	spare->used = true;
	spare->tgid = tgid;
	spare->last_ts = now;
	return spare;
}

//adds one hit to a ring of the last n hits. true if all n happened inside win
static bool burst(struct hit *r, unsigned n, unsigned *head, unsigned *cnt,
		  const struct edr_event *e, long long win, struct hit *first)
{
	r[*head].ts = e->ts_ns;
	r[*head].seq = e->seq;
	*head = (*head + 1) % n;
	if (*cnt < n)
		(*cnt)++;
	if (*cnt < n)
		return false;
	//ring is full, so the oldest hit is the one the head points at
	*first = r[*head];
	return (long long)(e->ts_ns - first->ts) <= win;
}

static void on_rename(const struct edr_event *e)
{
	struct proc *p = get_proc(e->tgid, e->ts_ns, true);
	struct hit first;

	if (p->ransom_done)
		return;
	bool hit = burst(p->rn, RANSOM_N, &p->rn_head, &p->rn_cnt, e, RANSOM_WIN, &first);
	if (!p->ransom_flag && p->rn_cnt >= RANSOM_N / 5) {
		p->ransom_flag = true;
		consumer_mark_suspicious(e->tgid);
	}
	if (!hit)
		return;
	p->ransom_done = true;
	consumer_mark_suspicious(e->tgid);
	consumer_alert("ransomware", e->tgid, first.ts, first.seq);
}

static void on_fork(const struct edr_event *e)
{
	struct proc *p = get_proc(e->tgid, e->ts_ns, true);
	struct hit first;

	if (p->fork_done)
		return;
	bool hit = burst(p->fk, FORK_N, &p->fk_head, &p->fk_cnt, e, FORK_WIN, &first);
	if (!p->fork_flag && p->fk_cnt >= FORK_N / 5) {
		p->fork_flag = true;
		consumer_mark_suspicious(e->tgid);
	}
	if (!hit)
		return;
	p->fork_done = true;
	consumer_mark_suspicious(e->tgid);
	consumer_alert("forkstorm", e->tgid, first.ts, first.seq);
}

//only setuid(0) matters, we remember when it happened
static void on_setuid(const struct edr_event *e)
{
	if (e->arg1 != 0)
		return;
	struct proc *p = get_proc(e->tgid, e->ts_ns, true);
	if (p->priv_done)
		return;
	p->priv_wait = true;
	p->priv_ts = e->ts_ns;
	p->priv_seq = e->seq;
	consumer_mark_suspicious(e->tgid);
}

static bool is_shell(const char *path)
{
	char buf[EDR_PATH_LEN + 1];
	memcpy(buf, path, EDR_PATH_LEN);
	buf[EDR_PATH_LEN] = 0;
	const char *base = strrchr(buf, '/');
	base = base ? base + 1 : buf;
	return !strcmp(base, "sh") || !strcmp(base, "bash") ||
	       !strcmp(base, "dash") || !strcmp(base, "zsh");
}

static void on_exec(const struct edr_event *e)
{
	//we only care if this process did setuid(0) before, so never create an entry here
	struct proc *p = get_proc(e->tgid, e->ts_ns, false);
	if (!p || !p->priv_wait || p->priv_done)
		return;
	if ((long long)(e->ts_ns - p->priv_ts) > PRIV_WIN) {
		p->priv_wait = false;
		return;
	}
	if (!is_shell(e->path))
		return;
	p->priv_done = true;
	p->priv_wait = false;
	consumer_alert("privesc", e->tgid, p->priv_ts, p->priv_seq);
}

void detector_init(void)
{
	memset(tab, 0, sizeof(tab));
}

void detector_event(const struct edr_event *e)
{
	switch (e->type) {
	case EV_RENAME:
	case EV_UNLINK:
		on_rename(e);
		break;
	case EV_FORK:
		on_fork(e);
		break;
	case EV_SETUID:
		on_setuid(e);
		break;
	case EV_EXEC:
		on_exec(e);
		break;
	}
}

//nothing to do here, old entries are reused in get_proc when the table needs room
void detector_tick(__u64 now_ns)
{
	(void)now_ns;
}

void detector_finish(void)
{
}
