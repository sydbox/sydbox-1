/*
 * libsyd/proc-TEST.c
 *
 * proc utility tests
 *
 * Copyright (c) 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU General Public License v3 (or later)
 */

#include "check.h"

static void test_setup(void)
{
	int ret = system("mkdir -p -m 700 ./tmp && cp -p ./check-pause './tmp/check-Good Morning'");
	if (ret) fail_msg("failed test_setup");
}

static void test_teardown(void)
{
	int ret = system("rm -fr ./tmp");
	if (ret) fail_msg("failed test_teardown");
}

static void test_proc_ppid(void)
{
	pid_t pid, ppid_real;
	char comm_real[] = "./tmp/check-Good Morning";

	ppid_real = getpid();
	pid = fork();
	if (pid < 0) {
		fail_msg("fork failed: errno:%d %s", errno, strerror(errno));
		return;
	} else if (pid == 0) {
		execl("./tmp/check-Good Morning", comm_real, (char *)NULL);
		_exit(1);
	} else {
		pid_t ppid, cpid = -1;
		int r, status;

		cpid = waitpid(pid, &status, WUNTRACED);
		if (cpid < 0) {
			fail_msg("waitpid failed: errno:%d %s", errno, strerror(errno));
			return;
		} else if (!WIFSTOPPED(status)) {
			fail_msg("process didn't stop: %#x", status);
			return;
		}

		int fd = syd_proc_open(cpid);
		if (fd < 0)
			abort(); /* TODO, fail nice */
		r = syd_proc_ppid(fd, &ppid);
		if (r < 0)
			fail_msg("syd_proc_ppid failed: %d %s", errno, strerror(errno));
		else if (ppid != ppid_real)
			fail_msg("ppid: %d != %d(real)", ppid, ppid_real);

		kill(cpid, SIGKILL);
	}
}

static void test_proc_parents(void)
{
	pid_t pid, ppid_real;
	char comm[] = "./check-pause";

	ppid_real = getpid();
	pid = fork();
	if (pid < 0) {
		fail_msg("fork failed: errno:%d %s", errno, strerror(errno));
		return;
	} else if (pid == 0) {
		execl("./check-pause", comm, (char *)NULL);
		_exit(1);
	} else {
		pid_t ppid, tgid, cpid = -1;
		int r, fd, status;

		cpid = waitpid(pid, &status, WUNTRACED);
		if (cpid < 0) {
			fail_msg("waitpid failed: errno:%d %s", errno, strerror(errno));
			return;
		} else if (!WIFSTOPPED(status)) {
			fail_msg("process didn't stop: %#x", status);
			return;
		}

		fd = syd_proc_open(cpid);
		if (fd < 0)
			abort(); /* TODO, fail nice */
		r = syd_proc_parents(fd, &ppid, &tgid);
		if (r < 0)
			fail_msg("syd_proc_tgid failed: %d %s", errno, strerror(errno));
		else if (ppid != ppid_real)
			fail_msg("ppid: %d != %d(real)", ppid, ppid_real);
		else if (tgid != cpid)
			fail_msg("tgid: %d != %d(real)", tgid, cpid);

		kill(cpid, SIGKILL);
	}
}

static void test_proc_comm(void)
{
	pid_t pid;
	char comm_real[] = "check-pause";

	pid = fork();
	if (pid < 0) {
		fail_msg("fork failed: errno:%d %s", errno, strerror(errno));
		return;
	} else if (pid == 0) {
		execl("./check-pause", comm_real, (char *)NULL);
		_exit(1);
	} else {
		pid_t cpid = -1;
		int r, fd, status;
		char comm[sizeof(comm_real)];
		char comm_trunc[sizeof(comm_real) - 2];
		size_t comm_len = sizeof(comm_real);
		size_t comm_trunc_len = sizeof(comm_real) - 2;

		cpid = waitpid(pid, &status, WUNTRACED);
		if (cpid < 0) {
			fail_msg("waitpid failed: errno:%d %s", errno, strerror(errno));
			return;
		} else if (!WIFSTOPPED(status)) {
			fail_msg("process didn't stop: %#x", status);
			return;
		}

		fd = syd_proc_open(cpid);
		if (fd < 0)
			abort(); /* TODO, fail nice */
		r = syd_proc_comm(fd, comm, comm_len);
		if (r < 0)
			fail_msg("syd_proc_comm failed: %d %s", errno, strerror(errno));
		comm[comm_len - 1] = '\0';
		if ((r = strcmp(comm, comm_real)) != 0)
			fail_msg("comm: strcmp('%s', '%s') = %d", comm, comm_real, r);

		r = syd_proc_comm(fd, comm_trunc, comm_trunc_len);
		if (r < 0)
			fail_msg("syd_proc_comm failed (trunc): %d %s", errno, strerror(errno));
		comm_trunc[comm_trunc_len - 1] = '\0';
		if ((r = strncmp(comm_trunc, comm_real, comm_trunc_len - 1)) != 0)
			fail_msg("comm: strncmp('%s', '%s', %zu) = %d",
				 comm_trunc, comm_real, comm_trunc_len - 1, r);
		else if (comm_trunc[comm_trunc_len - 1] != '\0')
			fail_msg("comm: truncated '%s' not null-terminated: '%c'", comm_trunc, comm_trunc[comm_trunc_len - 1]);
		kill(cpid, SIGKILL);
	}
}

static void test_proc_cmdline(void)
{
	pid_t pid;
	char *const argv[] = {"check-pause", "arg1", "arg2", "arg3", NULL};

	pid = fork();
	if (pid < 0) {
		fail_msg("fork failed: errno:%d %s", errno, strerror(errno));
		return;
	} else if (pid == 0) {
		execv("./check-pause", argv);
		_exit(1);
	} else {
		pid_t cpid = -1;
		int r, fd, status;
		char cmdline_orig[] = "check-pause arg1 arg2 arg3";
		char cmdline_trunc1_orig[] = "check-pause arg1 arg2 ar";
		char cmdline_trunc2_orig[] = "check-pause arg1 arg2 a";
		char cmdline[sizeof(cmdline_orig)];
		char cmdline_trunc1[sizeof(cmdline_trunc1_orig)];
		char cmdline_trunc2[sizeof(cmdline_trunc2_orig)];

		cpid = waitpid(pid, &status, WUNTRACED);
		if (cpid < 0) {
			fail_msg("waitpid failed: errno:%d %s", errno, strerror(errno));
			return;
		} else if (!WIFSTOPPED(status)) {
			fail_msg("process didn't stop: %#x", status);
			return;
		}

		fd = syd_proc_open(cpid);
		if (fd < 0)
			abort(); /* TODO, fail nice */
		r = syd_proc_cmdline(fd, cmdline, sizeof(cmdline));
		if (r < 0)
			fail_msg("syd_proc_cmdline failed: %d %s", errno, strerror(errno));
		cmdline[sizeof(cmdline) - 1] = '\0';
		if ((r = strcmp(cmdline, cmdline_orig)) != 0)
			fail_msg("cmdline: strcmp('%s', '%s') = %d", cmdline, cmdline_orig, r);

		r = syd_proc_cmdline(pid, cmdline_trunc1, sizeof(cmdline) - 2);
		if (r < 0)
			fail_msg("syd_proc_cmdline (trunc1) failed: %d %s",
				 errno, strerror(errno));
		cmdline_trunc1[sizeof(cmdline) - 3] = '\0';
		if ((r = strcmp(cmdline_trunc1, cmdline_trunc1_orig)) != 0)
			fail_msg("cmdline: (trunc1) strcmp('%s', '%s') = %d", cmdline_trunc1, cmdline_trunc1_orig, r);

		r = syd_proc_cmdline(pid, cmdline_trunc2, sizeof(cmdline) - 3);
		if (r < 0)
			fail_msg("syd_proc_cmdline (trunc2) failed: %d %s",
				 errno, strerror(errno));
		cmdline_trunc2[sizeof(cmdline) - 4] = '\0';
		if ((r = strcmp(cmdline_trunc2, cmdline_trunc2_orig)) != 0)
			fail_msg("cmdline: (trunc2) strcmp('%s', '%s') = %d",
				 cmdline_trunc2, cmdline_trunc2_orig, r);
		kill(cpid, SIGKILL);
	}
}

static void test_proc_fd_path(void)
{
	pid_t pid;
	char cwd[PATH_MAX], fd_path[] = "tmp/fd-path.tmp", fd_long[257];
	int pfd[2];

	syd_strlcpy(fd_long, "tmp/", sizeof("tmp/"));
	for (unsigned i = 4; i < 256; i++)
		fd_long[i] = 'x';
	fd_long[256] = '\0';

	if (!getcwd(cwd, PATH_MAX)) {
		fail_msg("getcwd failed: errno:%d %s", errno, strerror(errno));
		return;
	}

	if (pipe(pfd) < 0) {
		fail_msg("pipe failed: errno:%d %s", errno, strerror(errno));
		return;
	}

	pid = fork();
	if (pid < 0) {
		fail_msg("fork failed: errno:%d %s", errno, strerror(errno));
		return;
	} else if (pid == 0) {
		int fdp, fdl;
		ssize_t ret;

		close(pfd[0]);

		fdp = creat(fd_path, 0600);
		if (fdp < 0) {
			perror("creat(path)");
			_exit(2);
		}

		fdl = creat(fd_long, 0600);
		if (fdl < 0) {
			perror("creat(long)");
			_exit(3);
		}

		ret = write(pfd[1], &fdp, sizeof(fdp));
		if (ret != sizeof(fdp)) {
			perror("write(fdp)");
			_exit(4);
		}

		ret = write(pfd[1], &fdl, sizeof(fdl));
		if (ret != sizeof(fdl)) {
			perror("write(fdl)");
			_exit(5);
		}

		kill(getpid(), SIGSTOP);
		_exit(1);
	} else {
		pid_t cpid = -1;
		int fdp, fdl, status;
		int r;
		char *path;
		ssize_t ret;

		close(pfd[1]);

		cpid = waitpid(pid, &status, WUNTRACED);
		if (cpid < 0) {
			fail_msg("waitpid failed: errno:%d %s", errno, strerror(errno));
			return;
		} else if (!WIFSTOPPED(status)) {
			fail_msg("process didn't stop: %#x", status);
			return;
		}

		ret = read(pfd[0], &fdp, sizeof(fdp));
		if (ret != sizeof(fdp)) fail_msg("read fdp failed: errno:%d %s", errno, strerror(errno));
		ret = read(pfd[0], &fdl, sizeof(fdl));
		if (ret != sizeof(fdl)) fail_msg("read fdl failed: errno:%d %s", errno, strerror(errno));

		close(pfd[0]);

		int pfd = syd_proc_open(cpid);
		if (fd < 0)
			abort(); /* TODO, fail nice */
		int pfd_fd = syd_proc_fd_open(pfd);
		if (fd < 0)
			abort(); /* TODO, fail nice */
		path = NULL;
		r = syd_proc_fd_path(pfd_fd, fdp, &path);
		if (r < 0) {
			fail_msg("fdp: syd_proc_fd_path failed: errno:%d %s", -r, strerror(-r));
			goto out;
		}
		if (strncmp(path, cwd, strlen(cwd))) {
			fail_msg("fd_path: path:%s doesn't start with cwd:%s (len:%zu)", path, cwd, strlen(cwd));
			goto out;
		}
		if (strncmp(path + strlen(cwd) + 1, fd_path, sizeof(fd_path))) {
			fail_msg("fd_path: path:%s doesn't end with `%s'", path, fd_path);
			goto out;
		}

		r = syd_proc_fd_path(pfd_fd, fdl, &path);
		if (r < 0) {
			fail_msg("fdl: syd_proc_fd_path failed: errno:%d %s", -r, strerror(-r));
			goto out;
		}
		if (strncmp(path, cwd, strlen(cwd))) {
			fail_msg("fd_long: path:%s doesn't start with cwd:%s (len:%zu)",
				 path, cwd, strlen(cwd));
			goto out;
		}
		if (strncmp(path + strlen(cwd) + 1, fd_long, sizeof(fd_long))) {
			fail_msg("fd_long: path:%s doesn't end with `%s'", path, fd_long);
			goto out;
		}

out:
		if (path)
			free(path);
		kill(cpid, SIGKILL);
	}
}

static void test_fixture_proc(void)
{
	test_fixture_start();

	fixture_setup(test_setup);
	fixture_teardown(test_teardown);

	run_test(test_proc_ppid);
	run_test(test_proc_parents);
	run_test(test_proc_comm);
	run_test(test_proc_cmdline);
	run_test(test_proc_fd_path);

	test_fixture_end();
}

void test_suite_proc(void)
{
	test_fixture_proc();
}
