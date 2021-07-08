/*
 * sydbox/syd-run.c
 * SydBox's daemon tools which is also
 * used in the execve() interceptor to grant
 * per-process isolation via containers, chroot et al.
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <limits.h>
#include <getopt.h>
#include <syd/syd.h>
#include "sydconf.h"
#include "xfunc.h"
#include "daemon.h"
#include "dump.h"
#include "util.h"

#ifdef PACKAGE
# undef PACKAGE
#endif
#define PACKAGE "syd-run"

#define cap_last_cap(...) /* nothing */

static void usage(FILE *outfp, int code)
	SYD_GCC_ATTR((noreturn));

int main(int argc, char **argv)
{
	enum {
		/* unshare options */
		OPT_MOUNTPROC = CHAR_MAX + 1,
		OPT_PROPAGATION,
		OPT_SETGROUPS,
		OPT_KEEPCAPS,
		OPT_MONOTONIC,
		OPT_BOOTTIME,
		OPT_MAPUSER,
		OPT_MAPGROUP,
		/* syd options */
		OPT_PIVOT_ROOT,
		OPT_PROFILE,
		OPT_NICE,
		OPT_IONICE,
		OPT_UID,
		OPT_GID,
		OPT_ADD_GID,
		OPT_CLOSE_FDS,
		OPT_RESET_FDS,
		OPT_KEEP_SIGMASK,
	};

	int opt, r, arg;
	char *end;
	long dfd;

	/* sydbox options */
	bool allow_daemonize = false;

	/* unshare option defaults */
	int setgrpcmd = SYD_SETGROUPS_NONE;
	int unshare_flags = 0;
	uid_t mapuser = -1;
	gid_t mapgroup = -1;
	long mapuser_opt = -1;
	long mapgroup_opt = -1;
	// int kill_child_signo = 0; /* 0 means --kill-child was not used */
	const char *procmnt = NULL;
	const char *newroot = NULL;
	const char *newdir = NULL;
	pid_t pid_bind = 0;
	pid_t pid = 0;
	int fds[2];
	int status;
	unsigned long propagation = SYD_UNSHARE_PROPAGATION_DEFAULT;
	int force_uid = 0, force_gid = 0;
	uid_t uid = 0, real_euid = geteuid();
	gid_t gid = 0, real_egid = getegid();
	int keepcaps = 0;
	time_t monotonic = 0;
	time_t boottime = 0;
	int force_monotonic = 0;
	int force_boottime = 0;

	/* Long options are present for compatibility with sydbox-0.
	 * Thus they are not documented!
	 */
	int options_index;
	char *profile_name;
	struct option long_options[] = {
		/* default options */
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{"dump",	no_argument,		NULL,	'd'},

		/* namespaces (containers) */
		{"mount",	optional_argument, NULL, 'm'},
		{"uts",		optional_argument, NULL, 'u'},
		{"ipc",		optional_argument, NULL, 'i'},
		{"net",		optional_argument, NULL, 'N'},
		{"pid",		optional_argument, NULL, 'p'},
		{"user",	optional_argument, NULL, 'U'},
		{"cgroup",	optional_argument, NULL, 'C'},
		{"time",	optional_argument, NULL, 'T'},

		{ "fork",	 no_argument,	    NULL, 'F'},
		/*{ "kill-child",  optional_argument, NULL, '!'},*/
		{"set-parent-death-signal",
			required_argument,		NULL,	'!'},
		{ "mount-proc",  optional_argument, NULL, OPT_MOUNTPROC},
		{ "map-user",	 required_argument, NULL, OPT_MAPUSER},
		{ "map-group",	 required_argument, NULL, OPT_MAPGROUP},
		{ "map-root-user", no_argument,       NULL, 'r'		},
		{ "map-current-user", no_argument,    NULL, 'c'		},
		{ "propagation",required_argument, NULL, OPT_PROPAGATION},
		{ "setgroups",	required_argument, NULL, OPT_SETGROUPS},
		{ "keep-caps",	no_argument,	   NULL, OPT_KEEPCAPS},
		{ "setuid",	required_argument, NULL, 'S'		},
		{ "setgid",	required_argument, NULL, 'G'		},
		{ "root",	required_argument, NULL, 'R'		},
		{ "pivot-root",	required_argument,	NULL,	OPT_PIVOT_ROOT},
		{ "wd",		required_argument, NULL, 'w'		},
		{ "monotonic",	required_argument, NULL, OPT_MONOTONIC},
		{ "boottime",	required_argument, NULL, OPT_BOOTTIME},

		/* daemon tools */
		{"allow-daemonize", no_argument,	NULL,	'+'},
		{"background",	no_argument,		NULL,	'&'},
		{"stdout",	required_argument,	NULL,	'1'},
		{"stderr",	required_argument,	NULL,	'2'},
		{"alias",	required_argument,	NULL,	'A'},
		{"uid",		required_argument,	NULL,	OPT_UID},
		{"gid",		required_argument,	NULL,	OPT_GID},
		{"add-gid",	required_argument,	NULL,	OPT_ADD_GID},
		{"umask",	required_argument,	NULL,	'K'},

		/*
		  environment
		{"env",		required_argument,	NULL,	'E'},
		{"env-var-with-pid",required_argument,	NULL,	'V'},
		*/

		/* resource management */
		{"nice",	required_argument,	NULL,	OPT_NICE},
		{"ionice",	required_argument,	NULL,	OPT_IONICE},

		/* fd/signal management */
		{"close-fds",	optional_argument,	NULL,	OPT_CLOSE_FDS},
		{"reset-fds",	no_argument,		NULL,	OPT_RESET_FDS},
		{"keep-sigmask", no_argument,		NULL,	OPT_KEEP_SIGMASK},
		{"escape-stdout", no_argument,		NULL,	'O'},

		{"test",	no_argument,		NULL,	't'},

		{NULL,		0,		NULL,	0},
	};

	/*
	 * TODO: Consider whether this is necessary or not,
	 * also consider whether it breaks behaviour in the
	 * execve() interceptor. Until then, let's keep
	 * it disabled.
	const struct sigaction sa = { .sa_handler = SIG_DFL };
	if (sigaction(SIGCHLD, &sa, &child_sa) < 0)
		die_errno("sigaction");
	 */

	while ((opt = getopt_long(argc, argv,
				  "hvdmuiNpUCTFrcS:G:R:w:+:&!:1:2:A:K:Ot",
				  long_options, &options_index)) != EOF) {
		switch (opt) {
		case 'h':
			usage(stdout, 0);
		case 'v':
			syd_about(stdout);
			return 0;
#if SYDBOX_HAVE_DUMP_BUILTIN
		case 'd':
			if (!optarg) {
				dump_set_fd(STDERR_FILENO);
			} else if (!strcmp(optarg, "tmp")) {
				dump_set_fd(-42);
			} else {
				errno = 0;
				dfd = strtoul(optarg, &end, 10);
				if ((errno && errno != EINVAL) ||
				    (unsigned long)dfd	> INT_MAX)
				{
					say_errno("Invalid argument for option -d: "
						  "»%s«", optarg);
					usage(stderr, 1);
				} else if (end != strchr(optarg, '\0')) {
					dfd = open(optarg, SYDBOX_DUMP_FLAGS,
						   SYDBOX_DUMP_MODE);
					if (dfd < 0)
						die_errno("Failed to open "
							  "dump file »%s«",
							  optarg);
				}
				dump_set_fd(dfd);
			}
			break;
#else
		case 'd':
			say("dump not supported, compile with --enable-dump");
			usage(stderr, 1);
#endif
		case 'm':
			unshare_flags |= CLONE_NEWNS;
			if (optarg)
				syd_set_ns_target(CLONE_NEWNS, optarg);
			break;
		case 'u':
			unshare_flags |= CLONE_NEWUTS;
			if (optarg)
				syd_set_ns_target(CLONE_NEWUTS, optarg);
			break;
		case 'i':
			unshare_flags |= CLONE_NEWIPC;
			if (optarg)
				syd_set_ns_target(CLONE_NEWIPC, optarg);
			break;
		case 'n':
			unshare_flags |= CLONE_NEWNET;
			if (optarg)
				syd_set_ns_target(CLONE_NEWNET, optarg);
			break;
		case 'p':
			unshare_flags |= CLONE_NEWPID;
			if (optarg)
				syd_set_ns_target(CLONE_NEWPID, optarg);
			break;
		case 'U':
			unshare_flags |= CLONE_NEWUSER;
			if (optarg)
				syd_set_ns_target(CLONE_NEWUSER, optarg);
			break;
		case 'C':
			unshare_flags |= CLONE_NEWCGROUP;
			if (optarg)
				syd_set_ns_target(CLONE_NEWCGROUP, optarg);
			break;
		case 'T':
			unshare_flags |= CLONE_NEWTIME;
			if (optarg)
				syd_set_ns_target(CLONE_NEWTIME, optarg);
			break;
		case OPT_MOUNTPROC:
			unshare_flags |= CLONE_NEWNS;
			procmnt = optarg ? optarg : "/proc";
			break;
		case OPT_MAPUSER:
			errno = 0;
			mapuser_opt = strtoul(optarg, &end, 10);
			if ((errno && errno != EINVAL) ||
			    (unsigned long)mapuser_opt > UID_MAX)
			{
				say_errno("Invalid argument for option --mapuser: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}/* else if (end != strchr(optarg, '\0')) { */
			unshare_flags |= CLONE_NEWUSER;
			mapuser = (uid_t)mapuser_opt;
			break;
		case OPT_MAPGROUP:
			errno = 0;
			mapgroup_opt = strtoul(optarg, &end, 10);
			if ((errno && errno != EINVAL) ||
			    (unsigned long)mapgroup_opt > GID_MAX)
			{
				say_errno("Invalid argument for option --mapgroup: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}/* else if (end != strchr(optarg, '\0')) { */
			unshare_flags |= CLONE_NEWUSER;
			mapgroup = (gid_t)mapgroup_opt;
			break;
		case 'r':
			unshare_flags |= CLONE_NEWUSER;
			mapuser = 0;
			mapgroup = 0;
			break;
		case 'c':
			unshare_flags |= CLONE_NEWUSER;
			mapuser = real_euid;
			mapgroup = real_egid;
			break;
		case OPT_SETGROUPS:
			setgrpcmd = syd_setgroups_toi(optarg);
			if (setgrpcmd < 0) {
				say("unsupported --setgroups argument »%s«", optarg);
				usage(stderr, 1);
			}
			break;
		case OPT_PROPAGATION:
			propagation = syd_parse_propagation(optarg);
			break;
		case OPT_KEEPCAPS:
			keepcaps = 1;
			cap_last_cap(); /* Force last cap to be cached before we fork. */
			break;
		case 'S':
			if ((r = safe_atoi(optarg, &arg) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --setuid option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			uid = (uid_t)arg;
			force_uid = 1;
			break;
		case 'G':
			if ((r = safe_atoi(optarg, &arg) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --setgid option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			gid = (gid_t)arg;
			force_gid = 1;
			break;
		case 'R':
			newroot = optarg;
			break;
		case 'w':
			newdir = optarg;
			break;
		case OPT_MONOTONIC:
			if ((r = safe_atou(optarg, (unsigned *)&monotonic) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --monotonic option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			force_monotonic = 1;
			break;
		case OPT_BOOTTIME:
			if ((r = safe_atou(optarg, (unsigned *)&boottime) < 0)) {
				errno = -r;
				say_errno("Invalid argument for --boottime option: "
					  "»%s«", optarg);
				usage(stderr, 1);
			}
			force_boottime = 1;
			break;
		case 'A':
			set_arg0(xstrdup(optarg));
			break;
		case '&':
			set_background(true);
			allow_daemonize = true;
			break;
		case '!':
			if (parent_death_signal)
				free(parent_death_signal);
			parent_death_signal = xstrdup(optarg);
			break;
		case '1':
			set_redirect_stdout(xstrdup(optarg));
			break;
		case '2':
			set_redirect_stderr(xstrdup(optarg));
			break;
		case 'C':
			set_root_directory(xstrdup(optarg));
			break;
		case 'D':
			set_working_directory(xstrdup(optarg));
			break;
		case 'R':
			c = strchr(optarg, ':');
			if (!c) {
				say_errno("Invalid argument for option "
					  "--pivot-root »%s«", optarg);
				usage(stderr, 1);
			}
			*c = '\0';
			set_pivot_root(optarg, c + 1);
			break;
		case 'i':
			c = strchr(optarg, ':');
			if (!c)
				set_ionice(atoi(optarg), 0);
			else
				set_ionice(atoi(optarg), atoi(c + 1));
			break;
		case 'n':
			set_nice(atoi(optarg));
			break;
		case 'K':
			set_umask(atoi(optarg));
			break;
		case 'u':
			set_uid(atoi(optarg));
			break;
		case 'g':
			set_gid(atoi(optarg));
			break;
		case 'G':
			set_gid_add(atoi(optarg));
			break;
		case 'V':
			set_pid_env_var(optarg);
			break;
		case 'E':
			if (putenv(optarg))
				die_errno("putenv");
			break;
		case 't':
			test_setup();
			say("[>] Checking for libseccomp architectures...");
			/* test_seccomp_arch() returns the number of valid
			 * architectures. */
			opt_t[0] = test_seccomp_arch() == 0 ? EDOM : 0;
			say("[>] Checking for requirements...");
			if (uname(&buf_uts) < 0) {
				say_errno("uname");
			} else {
				say("%s/%s %s %s",
				    buf_uts.sysname,
				    buf_uts.nodename,
				    buf_uts.release,
				    buf_uts.version);
			}
			if (os_release >= KERNEL_VERSION(5,6,0))
				say("[*] Linux kernel is 5.6.0 or newer, good.");
			else
				say("warning: Your Linux kernel is too old "
				    "to support seccomp bpf and seccomp "
				    "user notify. Please update your kernel.");
			opt_t[1] = test_cross_memory_attach(true);
			opt_t[2] = test_proc_mem(true);
			opt_t[3] = test_pidfd(true);
			opt_t[4] = test_seccomp(true);
			r = 0;
			for (i = 0; i < 5; i++) {
				if (opt_t[i] != 0) {
					r = opt_t[i];
					break;
				}
			}
			if (opt_t[0] != 0) {
				say("[!] Failed to detect any valid libseccomp "
				    "architecture.");
				say("[!] This is probably a bug with the "
				    "architecture detection code.");
				say("[!] Please report, thank you.");
			}
			if (opt_t[1] != 0) {
				say("Enable CONFIG_CROSS_MEMORY_ATTACH "
				    "in your kernel configuration "
				    "for cross memory attach to work.");
			}
			if (opt_t[1] != 0 && opt_t[2] != 0) {
				say("warning: Neither cross memory attach "
				    "nor /proc/pid/mem interface is "
				    "available.");
				say("Sandboxing is only supported with bpf "
				    "mode.");
			}
			if (!r)
				say("[>] SydB☮x is supported on this system!");
			exit(r == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
			break;
		case 'P':
			unshare_pid = true;
			break;
		case 'N':
			unshare_net = true;
			break;
		case 'M':
			unshare_mount = true;
			break;
		case 'T':
			unshare_uts = true;
			break;
		case 'I':
			unshare_ipc = true;
			break;
		case 'U':
			unshare_user = true;
			break;
		case 'F':
			if (!optarg) {
				close_fds[0] = 3;
				close_fds[1] = 0;
			} else if (streq(optarg, ":")) {
				close_fds[0] = 3;
				close_fds[1] = 0;
			} else if (startswith(optarg, ":")) {
				close_fds[0] = 3;
				errno = 0;
				opt = strtoul(optarg, &end, 10);
				if ((errno && errno != EINVAL) ||
				    (unsigned long)opt > SYD_PID_MAX)
				{
					say_errno("Invalid argument for option "
						  "--close-fds: »%s«", optarg);
					usage(stderr, 1);
				}
				close_fds[1] = opt;
			} else {
				errno = 0;
				opt = strtoul(optarg, &end, 10);
				if ((errno && errno != EINVAL) ||
				    (unsigned long)opt > SYD_PID_MAX)
				{
					say_errno("Invalid argument for option "
						  "--close-fds: »%s«", optarg);
					usage(stderr, 1);
				}
				close_fds[0] = opt;
				if (end && end[0] == ':') {
					char *rem = end + 1;
					errno = 0;
					opt = strtoul(rem, &end, 10);
					if ((errno && errno != EINVAL) ||
					    (unsigned long)opt > SYD_PID_MAX)
					{
						say_errno("Invalid argument for option "
							  "--close-fds: »%s«", optarg);
						usage(stderr, 1);
					}
					close_fds[1] = opt;
				} else {
					close_fds[1] = 0;
				}
				break;
			}

			if ((close_fds[0] != 0 && close_fds[0] < 3) ||
			    (close_fds[1] != 0 && close_fds[1] < 3)) {
				say_errno("Invalid argument for option "
					  "--close-fds: »%s«", optarg);
				usage(stderr, 1);
			} else if (close_fds[0] > close_fds[1]) {
				/* XOR swap */
				close_fds[0] ^= close_fds[1];
				close_fds[1] ^= close_fds[0];
				close_fds[0] ^= close_fds[1];
			}
			break;
		case OPT_KEEP_SIGMASK:
			keep_sigmask = true;
			break;
		case 'X':
			reset_fds = true;
			break;
		case '+':
			allow_daemonize = true;
			break;
		case 'O':
			escape_stdout = true;
			break;
		default:
			usage(stderr, 1);
		}
	}
}

SYD_GCC_ATTR((noreturn))
void usage(FILE *outfp, int code)

{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION" -- syd's execve() interceptor \n\
usage: "PACKAGE" [-hvdmuiNpUCTFrcOt]\n\
                 [--wd directory] [--root directory]\n\
                 [--mount-proc <directory>]\n\
                 [--pivot-root new-root:put-old]\n\
                 [--uid user-id] [--gid group-id]\n\
                 [--setuid user-id] [--setgid group-id]\n\
                 [--setgroups allow|deny]\n\
                 [--allow-daemonize] [--background]\n\
                 [--ionice class:data] [--nice level]\n\
                 [--set-parent-death-signal signal]\n\
                 [--stdout logfile] [--stderr logfile]\n\
                 [--alias name] [--umask mode]\n\
-h          -- Show usage and exit\n\
-v          -- Show version and exit\n\
\n\
Hey you, out there on the road,\n\
Always doing what you're told,\n\
Can you help me?\n\
\n\
Send bug reports to \"" PACKAGE_BUGREPORT "\"\n\
Attaching poems encourages consideration tremendously.\n");
	exit(code);
}
