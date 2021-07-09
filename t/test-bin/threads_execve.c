/*
 * Check decoding of threads when a non-leader thread invokes execve.
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace/tests/{error_msg,sprintrc,threads-execve}.c which is:
 *   Copyright (c) 2016 Dmitry V. Levin <ldv@strace.io>
 *   Copyright (c) 2016-2020 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <syd/compiler.h>
#include "syd-conf.h"
#include "errno2name.h"
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>

static void perror_msg_and_fail(const char *, ...)
	SYD_GCC_ATTR((format(printf, 1, 2)))
	SYD_GCC_ATTR((noreturn));
/* Print message to stderr, then exit(1). */
static void error_msg_and_fail(const char *, ...)
	SYD_GCC_ATTR((format(printf, 1, 2)))
	SYD_GCC_ATTR((noreturn));
#if 0
/* Print message to stderr, then exit(77). */
static void error_msg_and_skip(const char *, ...)
	SYD_GCC_ATTR((format(printf, 1, 2)))
	SYD_GCC_ATTR((noreturn));
#endif
/* Print message and strerror(errno) to stderr, then exit(77). */
static void perror_msg_and_skip(const char *, ...)
	SYD_GCC_ATTR((format(printf, 1, 2)))
	SYD_GCC_ATTR((noreturn));

enum sprintrc_fmt {
	SPRINTRC_FMT_RAW,
	SPRINTRC_FMT_GREP,
};

/* Print return code and, in case return code is -1, errno information. */
static const char *sprintrc(long rc);
/* sprintrc variant suitable for usage as part of grep pattern. */
/* static const char *sprintrc_grep(long rc); */

#ifdef __NR_nanosleep

# include <errno.h>
# include <pthread.h>
# include <signal.h>
# include <stdio.h>
# include <stdlib.h>
# include <time.h>
# include <unistd.h>

# ifndef PRINT_EXITED
#  define PRINT_EXITED 1
# endif
# ifndef PRINT_SUPERSEDED
#  define PRINT_SUPERSEDED 1
# endif

static pid_t leader;
static pid_t tid;

static void
handler(int signo)
{
}

static unsigned int sigsetsize;
static long
k_sigsuspend(const sigset_t *const set)
{
	return syscall(__NR_rt_sigsuspend, set, sigsetsize);
}

static pid_t
k_gettid(void)
{
	return syscall(__NR_gettid);
}

static void
get_sigsetsize(void)
{
	static const struct sigaction sa = { .sa_handler = handler };
	if (sigaction(SIGUSR1, &sa, NULL))
		perror_msg_and_fail("sigaction");

	sigset_t mask;
	sigemptyset(&mask);
	sigaddset(&mask, SIGUSR1);
	if (sigprocmask(SIG_BLOCK, &mask, NULL))
		perror_msg_and_fail("sigprocmask");

	raise(SIGUSR1);

	sigemptyset(&mask);
	for (sigsetsize = sizeof(mask) / sizeof(long);
	     sigsetsize; sigsetsize >>= 1) {
		long rc = k_sigsuspend(&mask);
		if (!rc)
			error_msg_and_fail("rt_sigsuspend");
		if (EINTR == errno)
			break;
		fprintf(stderr, "%-5d rt_sigsuspend(%p, %u) = %s\n",
			leader, (void *)&mask, sigsetsize, sprintrc(rc));
	}
	if (!sigsetsize)
		perror_msg_and_fail("rt_sigsuspend");
	fprintf(stderr, "%-5d rt_sigsuspend([], %u) = ? ERESTARTNOHAND"
		" (To be restarted if no handler)\n", leader, sigsetsize);
}

enum {
	ACTION_exit = 0,
	ACTION_rt_sigsuspend,
	ACTION_nanosleep,
	NUMBER_OF_ACTIONS
};

static const unsigned int NUMBER_OF_ITERATIONS = 1;
static unsigned int action;
static int fds[2];

static unsigned int
arglen(char **args)
{
	char **p;

	for (p = args; *p; ++p)
		;

	return p - args;
}

static void *
thread(void *arg)
{
	tid = k_gettid();

	static char buf[sizeof(action) * 3];
	sprintf(buf, "%u", action + 1);

	char **argv = arg;
	argv[2] = buf;

	if (read(fds[0], fds, sizeof(fds[0])))
		perror_msg_and_fail("execve");

	struct timespec ts = { .tv_nsec = 100000000 };
	(void) syscall(__NR_clock_nanosleep, CLOCK_REALTIME, 0, &ts, NULL);

	struct timespec ots = { .tv_nsec = 12345 };
	fprintf(stderr, "%-5d nanosleep({tv_sec=0, tv_nsec=%u}, NULL) = 0\n",
		tid, (unsigned int) ots.tv_nsec);

	switch (action % NUMBER_OF_ACTIONS) {
		case ACTION_exit:
			fprintf(stderr,
				"%-5d execve(\"%s\", [\"%s\", \"%s\", \"%s\"]"
				", %p /* %u vars */ <pid changed to %u ...>\n",
				tid, argv[0], argv[0], argv[1], argv[2],
				(void *)environ, arglen(environ), leader);
			break;
		case ACTION_rt_sigsuspend:
			fprintf(stderr,
				"%-5d execve(\"%s\", [\"%s\", \"%s\", \"%s\"]"
				", %p /* %u vars */ <unfinished ...>\n"
				"%-5d <... rt_sigsuspend resumed>) = ?\n",
				tid, argv[0], argv[0], argv[1], argv[2],
				(void *)environ, arglen(environ),
				leader);
			break;
		case ACTION_nanosleep:
			fprintf(stderr,
				"%-5d execve(\"%s\", [\"%s\", \"%s\", \"%s\"]"
				", %p /* %u vars */ <unfinished ...>\n"
				"%-5d <... nanosleep resumed> <unfinished ...>)"
				" = ?\n",
				tid, argv[0], argv[0], argv[1], argv[2],
				(void *)environ, arglen(environ),
				leader);
			break;
	}

# if PRINT_SUPERSEDED
	fprintf(stderr, "%-5d +++ superseded by execve in pid %u +++\n",
		leader, tid);
	printf("%u %u\n", tid, leader);
# endif
	fprintf(stderr, "%-5d <... execve resumed>) = 0\n", leader);

	(void) syscall(__NR_nanosleep, (unsigned long) &ots, 0UL);
	execve(argv[0], argv, environ);
	perror_msg_and_fail("execve");
}

int
main(int ac, char **av)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	leader = getpid();

	if (ac < 3) {
		struct timespec ts = { .tv_nsec = 1 };
		if (syscall(__NR_clock_nanosleep, CLOCK_REALTIME, 0, &ts, NULL))
			perror_msg_and_skip("clock_nanosleep CLOCK_REALTIME");

		get_sigsetsize();
		static char buf[sizeof(sigsetsize) * 3];
		sprintf(buf, "%u", sigsetsize);

		char *argv[] = { av[0], buf, (char *) "0", NULL };
		fprintf(stderr, "%-5d execve(\"%s\", [\"%s\", \"%s\", \"%s\"]"
			", %p /* %u vars */) = 0\n",
			leader, argv[0], argv[0], argv[1], argv[2],
			(void *)environ, arglen(environ));
		execve(argv[0], argv, environ);
		perror_msg_and_fail("execve");
	}

	sigsetsize = atoi(av[1]);
	action = atoi(av[2]);

	if (action >= NUMBER_OF_ACTIONS * NUMBER_OF_ITERATIONS) {
# if PRINT_EXITED
		fprintf(stderr, "%-5d +++ exited with 0 +++\n", leader);
# endif
		return 0;
	}

	if (pipe(fds))
		perror_msg_and_fail("pipe");

	pthread_t t;
	errno = pthread_create(&t, NULL, thread, av);
	if (errno)
		perror_msg_and_fail("pthread_create");

	struct timespec ots = { .tv_sec = 123 };
	sigset_t mask;
	sigemptyset(&mask);

	static char leader_str[sizeof(leader) * 3];
	int leader_str_len =
		snprintf(leader_str, sizeof(leader_str), "%-5d", leader);

	switch (action % NUMBER_OF_ACTIONS) {
		case ACTION_exit:
			fprintf(stderr, "%s exit(42)%*s= ?\n", leader_str,
				(int) sizeof(leader_str) - leader_str_len, " ");
			close(fds[1]);
			(void) syscall(__NR_exit, 42);
			break;
		case ACTION_rt_sigsuspend:
			fprintf(stderr,
				"%s rt_sigsuspend([], %u <unfinished ...>\n",
				leader_str, sigsetsize);
			close(fds[1]);
			(void) k_sigsuspend(&mask);
			break;
		case ACTION_nanosleep:
			fprintf(stderr, "%s nanosleep({tv_sec=%u, tv_nsec=0}"
				",  <unfinished ...>\n",
				leader_str, (unsigned int) ots.tv_sec);
			close(fds[1]);
			(void) syscall(__NR_nanosleep,
				       (unsigned long) &ots, 0UL);
			break;
	}

	return 1;
}

#else

SKIP_MAIN_UNDEFINED("__NR_nanosleep")

#endif

static void
perror_msg_and_fail(const char *fmt, ...)
{
	int err_no = errno;
	va_list p;

	va_start(p, fmt);
	vfprintf(stderr, fmt, p);
	if (err_no)
		fprintf(stderr, ": %s\n", strerror(err_no));
	else
		putc('\n', stderr);
	exit(1);
}

static void
error_msg_and_fail(const char *fmt, ...)
{
	va_list p;

	va_start(p, fmt);
	vfprintf(stderr, fmt, p);
	putc('\n', stderr);
	exit(1);
}

#if 0
static void
error_msg_and_skip(const char *fmt, ...)
{
	va_list p;

	va_start(p, fmt);
	vfprintf(stderr, fmt, p);
	putc('\n', stderr);
	exit(77);
}
#endif

static void
perror_msg_and_skip(const char *fmt, ...)
{
	int err_no = errno;
	va_list p;

	va_start(p, fmt);
	vfprintf(stderr, fmt, p);
	if (err_no)
		fprintf(stderr, ": %s\n", strerror(err_no));
	else
		putc('\n', stderr);
	exit(77);
}

/**
 * Provides pointer to static string buffer with printed return code in format
 * used by strace - with errno and error message.
 *
 * @param rc  Return code.
 * @param fmt Output format. Currently, raw (used for diff matching) and grep
 *            (for extended POSIX regex-based pattern matching) formats are
 *            supported.
 * @return    Pointer to (statically allocated) buffer containing decimal
 *            representation of return code and errno/error message in case @rc
 *            is equal to -1.
 */
static inline const char *
sprintrc_ex(long rc, enum sprintrc_fmt fmt)
{
	static const char *formats[] = {
		[SPRINTRC_FMT_RAW] = "-1 %s (%m)",
		[SPRINTRC_FMT_GREP] = "-1 %s \\(%m\\)",
	};
	static char buf[4096];

	if (rc == 0)
		return "0";

	int ret = (rc == -1)
		? snprintf(buf, sizeof(buf), formats[fmt], errno2name(errno))
		: snprintf(buf, sizeof(buf), "%ld", rc);

	if (ret < 0)
		perror_msg_and_fail("snprintf");
	if ((size_t) ret >= sizeof(buf))
		error_msg_and_fail("snprintf overflow: got %d, expected"
				   " no more than %zu", ret, sizeof(buf));

	return buf;
}

static const char *
sprintrc(long rc)
{
	return sprintrc_ex(rc, SPRINTRC_FMT_RAW);
}

#if 0
static const char *
sprintrc_grep(long rc)
{
	return sprintrc_ex(rc, SPRINTRC_FMT_GREP);
}
#endif
