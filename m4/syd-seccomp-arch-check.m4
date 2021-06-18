dnl m4/syd-seccomp-arch-check.c
dnl
dnl LibSeccomp Architecture Checker
dnl AutoTools AC_RUN_IFELSE Program.
dnl
dnl Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
dnl SPDX-License-Identifier: GPL-2.0-only
dnl
dnl ++ Compile this with:
dnl cc \
dnl   $(pkg-config --cflags libseccomp) \
dnl   syd-seccomp-arch-check.c \
dnl   $(pkg-config --libs libseccomp)
dnl
dnl ++ Run this like:
dnl ./syd-seccomp-arch-check <x86|x86_64|x32|arm|aarch64|...>
dnl
dnl With AutoTools, this file defines
dnl SYD_SECCOMP_ARCH_CHECK
dnl which has the code to pass to
dnl AC_LANG_PROGRAM
dnl and then to
dnl AC_RUN_IFELSE.
dnl
dnl Returns 0 if the architecture is supported
dnl by the system and LibSeccomp.
dnl Returns 1 if an error happens or if the
dnl architecture name is invalid or
dnl architecture is not supported. Prints
dnl short diagnosis on standard error.

m4_define([SYD_SECCOMP_ARCH_CHECK], [[
/*
 * Writes if architecture is valid in the second argument.
 * Return value 0 means succesful detection.
 * > 0 means test process terminated by this signal value.
 * < 0 means one of the seccomp calls in the test process returned this negated
 * errno.
 * The second argument is definitely updated only when return value is 0.
 * Otherwise its state is undefined.
 */
static int syd_seccomp_arch_is_valid(uint32_t arch, bool *result);

static bool syd_seccomp_check_support(uint32_t arch)
{
	int r;
	bool valid = false;
	bool say_arch = true;
	if ((r = syd_seccomp_arch_is_valid(arch, &valid)) != 0) {
		if (say_arch) {
			fprintf(stderr, "! Architecture %#x support check failed: "
			    "%d %s\n", arch, -r, strerror(-r));
			fprintf(stderr, "+ Continuing...");
		}
		if (r == -EINVAL)
			fprintf(stderr, "? Architecture %#x name is \n"
			    "correct?", arch);
		return false;
	} else if (!valid) {
		/* Skip invalid architectures. */
		if (say_arch)
			fprintf(stderr, "- Architecture %#x is not "
			    "supported.\n", arch);
		return false;
	}

	scmp_filter_ctx ctx;
	if ((ctx = seccomp_init(SCMP_ACT_ALLOW)) == NULL) {
		r = -errno;
		fprintf(stderr, "seccomp_init: %d (%s)\n",
			errno, strerror(errno));
		fprintf(stderr, "do not know what to do aborting\n");
		abort();
	}
	int add = seccomp_arch_add(ctx, arch);
	switch (add) {
	case 0:		/* Architecture successfully added. */
		if (say_arch)
			fprintf(stderr, "+ Architecture %#x added.\n",
			    arch);
		return true;
	case -EDOM:	/* Ignore invalid architecture. */
		if (say_arch)
			fprintf(stderr, "! Architecture %#x is not supported.\n",
			    arch);
		return false;
	case -EEXIST:	/* Architecture already present is ok. */
		if (say_arch)
			fprintf(stderr, "+ Architecture %#x is already "
			    "filtered.\n", arch);
		return true;
	default:
		errno = -add;
		fprintf(stderr, "seccomp_arch_add(arch=%#x)\n", arch);
		return false;
	}
}

static int syd_seccomp_arch_is_valid(uint32_t arch, bool *result)
{
	int r;

	if (!result)
		return -ENOMEM;

	pid_t pid = fork();
	if (pid < 0) {
		return -errno;
	} else if (pid == 0) {
		scmp_filter_ctx ctx;
		if (!(ctx = seccomp_init(SCMP_ACT_ALLOW)))
			_exit(errno);
		if ((r = seccomp_arch_add(ctx, arch)) != 0 &&
		    r != -EEXIST)
			_exit(-r);
		if ((r = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM),
					  SCMP_SYS(getpid), 0)) != 0)
			_exit(-r);
		if ((r = seccomp_load(ctx)) != 0)
			_exit(-r);
		_exit(0);
	}

	int status;
restart_waitpid:
	if (waitpid(pid, &status, 0) < 0) {
		if (errno == EINTR)
			goto restart_waitpid;
		return -errno;
	}

	r = 0;
	bool valid = false;
	if (WIFEXITED(status)) {
		r = WEXITSTATUS(status);
		if (r == 0)
			valid = true;
		else if (r == EDOM) /* invalid architecture */
			r = 0; /* valid = false; */
		else
			r = -r; /* negate errno */
	} else if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);
		fprintf(stderr, "architecture test process terminated "
			"with %#x\n", sig);
		r = sig;
	}
	*result = valid;
	return r;
}
]])
