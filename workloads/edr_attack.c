// SPDX-License-Identifier: GPL-2.0
/*
 * edr_attack - Part 2 attack simulator. Runs ONE attack and prints one
 * injections.csv line (docs/CONTRACT.md section 3) to stdout:
 *
 *     attack,start_ns,end_ns,tgid
 *
 *   edr_attack ransomware [--files N]     open/read/write/rename N files
 *   edr_attack forkstorm  [--children N]  one parent forks N children
 *   edr_attack privesc                    setuid(0), then exec /bin/sh
 *
 * Every attack runs in a freshly forked child, so the attacker has its own
 * tgid. start_ns is taken just before the fork and end_ns just after the
 * child is reaped, both from CLOCK_MONOTONIC (same clock as the kernel's
 * event timestamps). tgid is the child's PID.
 *
 * Only files under the sandbox directory (default /tmp/edr_sandbox) are
 * touched. Ransomware files are NOT deleted here: deleting them would cause
 * an unlink burst from this process that looks like ransomware itself.
 * workloads/cleanup.sh removes them between runs, when no consumer runs.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define FILE_SIZE 4096

static const char *sandbox = "/tmp/edr_sandbox";
static int n_files = 64;      /* detector threshold is 50 renames in 5 s  */
static int n_children = 128;  /* detector threshold is 100 forks in 1 s   */

static unsigned long long now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (unsigned long long)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

static void die(const char *what)
{
	perror(what);
	exit(1);
}

static void mkdir_p(const char *path)
{
	char tmp[512];
	snprintf(tmp, sizeof(tmp), "%s", path);
	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = 0;
		if (mkdir(tmp, 0755) && errno != EEXIST)
			die(tmp);
		*p = '/';
	}
	if (mkdir(tmp, 0755) && errno != EEXIST)
		die(tmp);
}

/* ---- ransomware --------------------------------------------------------- */
static char rw_dir[512];

/* Runs in the parent BEFORE start_ns: create the victim files. */
static void ransomware_prep(void)
{
	char path[600], buf[FILE_SIZE];

	snprintf(rw_dir, sizeof(rw_dir), "%s/attacks/rw_%d_%llu", sandbox,
		 getpid(), now_ns());
	mkdir_p(rw_dir);
	for (int i = 0; i < FILE_SIZE; i++)
		buf[i] = 'a' + i % 26;
	for (int i = 0; i < n_files; i++) {
		snprintf(path, sizeof(path), "%s/f_%05d.dat", rw_dir, i);
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0)
			die(path);
		if (write(fd, buf, sizeof(buf)) != sizeof(buf))
			die("write");
		close(fd);
	}
}

/* The attack itself: "encrypt" every file in place, then rename it. */
static void ransomware_child(void)
{
	char path[600], newpath[620], buf[FILE_SIZE];

	for (int i = 0; i < n_files; i++) {
		snprintf(path, sizeof(path), "%s/f_%05d.dat", rw_dir, i);
		snprintf(newpath, sizeof(newpath), "%s.locked", path);
		int fd = open(path, O_RDWR);
		if (fd < 0)
			_exit(1);
		ssize_t n = read(fd, buf, sizeof(buf));
		for (ssize_t j = 0; j < n; j++)
			buf[j] ^= 0x5a;
		lseek(fd, 0, SEEK_SET);
		if (n > 0 && write(fd, buf, n) != n)
			_exit(1);
		close(fd);
		if (rename(path, newpath))
			_exit(1);
	}
	_exit(0);
}

/* ---- fork storm ---------------------------------------------------------- */
static void forkstorm_child(void)
{
	int spawned = 0;

	for (int i = 0; i < n_children; i++) {
		pid_t p = fork();
		if (p == 0)
			_exit(0);
		if (p > 0)
			spawned++;
	}
	while (wait(NULL) > 0)
		;
	_exit(spawned == n_children ? 0 : 1);
}

/* ---- privilege escalation ----------------------------------------------- */
static void privesc_child(void)
{
	/* As root this succeeds; as a normal user it fails with EPERM, but the
	 * setuid syscall (and its arg 0) is traced either way. */
	if (setuid(0))
		fprintf(stderr, "edr_attack: note: setuid(0) failed (%s), continuing\n",
			strerror(errno));
	execl("/bin/sh", "sh", "-c", "exit 0", (char *)NULL);
	_exit(127);
}

static void usage(void)
{
	fprintf(stderr,
		"usage: edr_attack ransomware|forkstorm|privesc [options]\n"
		"  --files N      ransomware: number of files (default %d)\n"
		"  --children N   forkstorm: number of children (default %d)\n"
		"  --sandbox DIR  sandbox directory (default %s)\n"
		"Prints one injections.csv line: attack,start_ns,end_ns,tgid\n",
		n_files, n_children, sandbox);
	exit(1);
}

int main(int argc, char **argv)
{
	static const struct option lo[] = {
		{"files", 1, 0, 'f'}, {"children", 1, 0, 'c'},
		{"sandbox", 1, 0, 's'}, {"help", 0, 0, 'h'}, {0}};
	void (*child_fn)(void);
	const char *attack;
	int c, status;

	while ((c = getopt_long(argc, argv, "f:c:s:h", lo, NULL)) != -1) {
		switch (c) {
		case 'f': n_files = atoi(optarg); break;
		case 'c': n_children = atoi(optarg); break;
		case 's': sandbox = optarg; break;
		default: usage();
		}
	}
	if (optind != argc - 1)
		usage();
	attack = argv[optind];

	if (!strcmp(attack, "ransomware")) {
		ransomware_prep();
		child_fn = ransomware_child;
	} else if (!strcmp(attack, "forkstorm")) {
		child_fn = forkstorm_child;
	} else if (!strcmp(attack, "privesc")) {
		child_fn = privesc_child;
	} else {
		usage();
	}

	fflush(stdout);
	unsigned long long start = now_ns();
	pid_t pid = fork();
	if (pid < 0)
		die("fork");
	if (pid == 0)
		child_fn();
	if (waitpid(pid, &status, 0) < 0)
		die("waitpid");
	unsigned long long end = now_ns();

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		fprintf(stderr, "edr_attack: warning: %s child exited with status %d\n",
			attack, WIFEXITED(status) ? WEXITSTATUS(status) : -1);

	printf("%s,%llu,%llu,%d\n", attack, start, end, pid);
	return 0;
}
