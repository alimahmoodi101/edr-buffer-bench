// SPDX-License-Identifier: GPL-2.0
/*
 * edr_noise - Part 2 background noise generator. Produces roughly RATE
 * traced events per second, spread over several worker processes so every
 * CPU sees traffic (this matters for the per-CPU design).
 *
 *   edr_noise --rate 100000 --duration 30 [--workers N]
 *
 * Every operation produces exactly one low-priority event:
 *   15 of every 16 ops: write(64 bytes) to /dev/null    -> EV_WRITE
 *   1 of every 16 ops : openat() of a sandbox file     -> EV_OPEN  (+ close,
 *                                                         which is not traced)
 * --rate 0 means "as fast as possible". The achieved rate is printed to
 * stderr at the end. Note the machine's own background (about 1000 ev/s on
 * an idle WSL box) comes on top of this.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static double now_s(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void worker(int id, double rate, double duration, const char *sandbox,
		   unsigned long long *done_out)
{
	char path[512], buf[64];
	unsigned long long done = 0;
	int devnull = open("/dev/null", O_WRONLY);

	if (devnull < 0) {
		perror("/dev/null");
		_exit(1);
	}
	memset(buf, 'n', sizeof(buf));
	snprintf(path, sizeof(path), "%s/noise/w%d.dat", sandbox, id);
	int fd = open(path, O_WRONLY | O_CREAT, 0644);
	if (fd < 0) {
		perror(path);
		_exit(1);
	}
	close(fd);

	double t0 = now_s(), end = t0 + duration;
	while (!stop) {
		double t = now_s();
		if (t >= end)
			break;
		if (rate > 0) {
			double ahead = done / rate - (t - t0);   /* seconds ahead of plan */
			if (ahead > 0) {
				struct timespec ts = { (time_t)ahead,
						       (long)((ahead - (time_t)ahead) * 1e9) };
				nanosleep(&ts, NULL);
				continue;
			}
		}
		/* a small batch between clock checks */
		for (int i = 0; i < 64; i++, done++) {
			if ((done & 15) == 15) {
				fd = open(path, O_RDONLY);
				if (fd >= 0)
					close(fd);
			} else if (write(devnull, buf, sizeof(buf)) < 0) {
				break;
			}
		}
		*done_out = done;
	}
	*done_out = done;
	_exit(0);
}

int main(int argc, char **argv)
{
	double rate = 10000, duration = 30;
	int workers = (int)sysconf(_SC_NPROCESSORS_ONLN);
	const char *sandbox = getenv("EDR_SANDBOX") ? getenv("EDR_SANDBOX") : "/tmp/edr_sandbox";
	static const struct option lo[] = {
		{"rate", 1, 0, 'r'}, {"duration", 1, 0, 'd'}, {"workers", 1, 0, 'w'},
		{"sandbox", 1, 0, 's'}, {"help", 0, 0, 'h'}, {0}};
	int c;

	while ((c = getopt_long(argc, argv, "r:d:w:s:h", lo, NULL)) != -1) {
		switch (c) {
		case 'r': rate = atof(optarg); break;
		case 'd': duration = atof(optarg); break;
		case 'w': workers = atoi(optarg); break;
		case 's': sandbox = optarg; break;
		default:
			fprintf(stderr,
				"usage: edr_noise --rate EV_PER_SEC --duration SEC [--workers N]\n"
				"  --rate 0 = as fast as possible; workers default = number of CPUs\n");
			return 1;
		}
	}
	if (workers < 1)
		workers = 1;

	char dir[512];
	snprintf(dir, sizeof(dir), "%s", sandbox);
	mkdir(dir, 0755);
	snprintf(dir, sizeof(dir), "%s/noise", sandbox);
	if (mkdir(dir, 0755) && errno != EEXIST) {
		perror(dir);
		return 1;
	}

	/* shared counters so the parent can report the achieved rate */
	unsigned long long *done = mmap(NULL, workers * sizeof(*done),
					PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (done == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	struct sigaction sa = { .sa_handler = on_sig };
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	double t0 = now_s();
	pid_t *pids = calloc(workers, sizeof(*pids));
	for (int i = 0; i < workers; i++) {
		pids[i] = fork();
		if (pids[i] == 0)
			worker(i, rate / workers, duration, sandbox, &done[i]);
		if (pids[i] < 0) {
			perror("fork");
			return 1;
		}
	}
	/* forward Ctrl-C / SIGTERM (e.g. from the harness) to the workers */
	while (wait(NULL) > 0 || errno == EINTR) {
		if (stop)
			for (int i = 0; i < workers; i++)
				kill(pids[i], SIGTERM);
	}
	double secs = now_s() - t0;

	unsigned long long total = 0;
	for (int i = 0; i < workers; i++)
		total += done[i];
	fprintf(stderr, "edr_noise: target %.0f ev/s, achieved %.0f ev/s "
		"(%llu events, %d workers, %.1fs)\n",
		rate, total / secs, total, workers, secs);
	return 0;
}
