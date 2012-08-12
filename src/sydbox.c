/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011, 2012 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Sydbox. sydbox is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * sydbox is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

/*
 * The functions
 *   - sydbox_startup_child()
 *   are based in part upon strace which is:
 *
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "sydbox-defs.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <getopt.h>

#include "macro.h"
#include "util.h"
#ifdef WANT_SECCOMP
#include "seccomp.h"
#endif

/* pink floyd */
#define PINK_FLOYD	"       ..uu.                               \n" \
			"       ?$\"\"`?i           z'              \n" \
			"       `M  .@\"          x\"               \n" \
			"       'Z :#\"  .   .    f 8M              \n" \
			"       '&H?`  :$f U8   <  MP   x#'         \n" \
			"       d#`    XM  $5.  $  M' xM\"          \n" \
			"     .!\">     @  'f`$L:M  R.@!`           \n" \
			"    +`  >     R  X  \"NXF  R\"*L           \n" \
			"        k    'f  M   \"$$ :E  5.           \n" \
			"        %%    `~  \"    `  'K  'M          \n" \
			"            .uH          'E   `h           \n" \
			"         .x*`             X     `          \n" \
			"      .uf`                *                \n" \
			"    .@8     .                              \n" \
			"   'E9F  uf\"          ,     ,             \n" \
			"     9h+\"   $M    eH. 8b. .8    .....     \n" \
			"    .8`     $'   M 'E  `R;'   d?\"\"\"`\"# \n" \
			"   ` E      @    b  d   9R    ?*     @     \n" \
			"     >      K.zM `%%M'   9'    Xf   .f     \n" \
			"    ;       R'          9     M  .=`       \n" \
			"    t                   M     Mx~          \n" \
			"    @                  lR    z\"           \n" \
			"    @                  `   ;\"             \n" \
			"                          `                \n"

sydbox_t *sydbox = NULL;

static void about(void)
{
	printf(PACKAGE"-"VERSION GITVERSION"\n");
}

PINK_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION" -- ptrace based sandbox\n\
usage: "PACKAGE" [-hVv] [-c pathspec...] [-m magic...] {-p pid...}\n\
   or: "PACKAGE" [-hVv] [-c pathspec...] [-m magic...] [-E var=val...] {command [arg...]}\n\
-h          -- Show usage and exit\n\
-V          -- Show version and exit\n\
-v          -- Be verbose, may be repeated\n\
-c pathspec -- path spec to the configuration file, may be repeated\n\
-m magic    -- run a magic command during init, may be repeated\n\
-E var=val  -- put var=val in the environment for command, may be repeated\n\
-E var      -- remove var from the environment for command, may be repeated\n\
\n\
Hey you, out there beyond the wall,\n\
Breaking bottles in the hall,\n\
Can you help me?\n\
\n\
Send bug reports to \"" PACKAGE_BUGREPORT "\"\n\
Attaching poems encourages consideration tremendously.\n");
	exit(code);
}

static void sydbox_init(void)
{
	assert(!sydbox);

	sydbox = xmalloc(sizeof(sydbox_t));
	sydbox->eldest = -1;
	sydbox->exit_code = 0;
	sydbox->wait_execve = 0;
	sydbox->violation = false;
	sydbox->ctx = NULL;
	config_init();
}

static void sydbox_destroy(void)
{
	struct snode *node;

	assert(sydbox);

	/* Free the global configuration */
	free_sandbox(&sydbox->config.child);

	SLIST_FLUSH(node, &sydbox->config.exec_kill_if_match, up, free);
	SLIST_FLUSH(node, &sydbox->config.exec_resume_if_match, up, free);

	SLIST_FLUSH(node, &sydbox->config.filter_exec, up, free);
	SLIST_FLUSH(node, &sydbox->config.filter_read, up, free);
	SLIST_FLUSH(node, &sydbox->config.filter_write, up, free);
	SLIST_FLUSH(node, &sydbox->config.filter_network, up, free_sock_match);

	pink_easy_context_destroy(sydbox->ctx);

	free(sydbox->program_invocation_name);
	free(sydbox);
	sydbox = NULL;

	systable_free();
	log_close();
}

static bool dump_one_process(struct pink_easy_process *current, void *userdata)
{
	pid_t tid = pink_easy_process_get_tid(current);
	pid_t tgid = pink_easy_process_get_tgid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	short flags = pink_easy_process_get_flags(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	struct snode *node;

	fprintf(stderr, "-- Thread ID: %lu\n", (unsigned long)tid);
	if (flags & PINK_EASY_PROCESS_SUSPENDED) {
		fprintf(stderr, "   Thread is suspended at startup!\n");
		return true;
	}
	fprintf(stderr, "   Thread Group ID: %lu\n", tgid > 0 ? (unsigned long)tgid : 0UL);
	fprintf(stderr, "   Comm: %s\n", data->comm);
	fprintf(stderr, "   Cwd: %s\n", data->cwd);
	fprintf(stderr, "   Syscall: {no:%lu abi:%d name:%s}\n", data->sno, abi, pink_syscall_name(data->sno, abi));

	if (!PTR_TO_UINT(userdata))
		return true;

	fprintf(stderr, "--> Sandbox: {exec:%s read:%s write:%s sock:%s}\n",
			sandbox_mode_to_string(data->config.sandbox_exec),
			sandbox_mode_to_string(data->config.sandbox_read),
			sandbox_mode_to_string(data->config.sandbox_write),
			sandbox_mode_to_string(data->config.sandbox_network));
	fprintf(stderr, "    Magic Lock: %s\n", lock_state_to_string(data->config.magic_lock));
	fprintf(stderr, "    Exec Whitelist:\n");
	SLIST_FOREACH(node, &data->config.whitelist_exec, up)
		fprintf(stderr, "      \"%s\"\n", (char *)node->data);
	fprintf(stderr, "    Read Whitelist:\n");
	SLIST_FOREACH(node, &data->config.whitelist_read, up)
		fprintf(stderr, "      \"%s\"\n", (char *)node->data);
	fprintf(stderr, "    Write Whitelist:\n");
	SLIST_FOREACH(node, &data->config.whitelist_write, up)
		fprintf(stderr, "      \"%s\"\n", (char *)node->data);
	/* TODO:  SLIST_FOREACH(node, data->config.whitelist_sock, up) */

	return true;
}

static void sig_user(int signo)
{
	bool cmpl;
	unsigned c;
	struct pink_easy_process_list *list;

	if (!sydbox)
		return;

	cmpl = signo == SIGUSR2;
	list = pink_easy_context_get_process_list(sydbox->ctx);

	fprintf(stderr, "\nReceived SIGUSR%s, dumping %sprocess tree\n",
			cmpl ? "2" : "1",
			cmpl ? "complete " : "");
	c = pink_easy_process_list_walk(list, dump_one_process, UINT_TO_PTR(cmpl));
	fprintf(stderr, "Tracing %u process%s\n", c, c > 1 ? "es" : "");
}

static void sydbox_startup_child(char **argv)
{
	struct stat statbuf;
	const char *filename;
	char pathname[SYDBOX_PATH_MAX];
	int pid = 0;
	struct pink_easy_process *current;

	filename = argv[0];
	if (strchr(filename, '/')) {
		if (strlen(filename) > sizeof pathname - 1) {
			errno = ENAMETOOLONG;
			die_errno(1, "exec");
		}
		strcpy(pathname, filename);
	}
#ifdef SYDBOX_USE_DEBUGGING_EXEC
	/*
	 * Debuggers customarily check the current directory
	 * first regardless of the path but doing that gives
	 * security geeks a panic attack.
	 */
	else if (stat(filename, &statbuf) == 0)
		strcpy(pathname, filename);
#endif /* SYDBOX_USE_DEBUGGING_EXEC */
	else {
		const char *path;
		int m, n, len;

		for (path = getenv("PATH"); path && *path; path += m) {
			const char *colon = strchr(path, ':');
			if (colon) {
				n = colon - path;
				m = n + 1;
			}
			else
				m = n = strlen(path);
			if (n == 0) {
				if (!getcwd(pathname, SYDBOX_PATH_MAX))
					continue;
				len = strlen(pathname);
			}
			else if ((size_t)n > sizeof pathname - 1)
				continue;
			else {
				strncpy(pathname, path, n);
				len = n;
			}
			if (len && pathname[len - 1] != '/')
				pathname[len++] = '/';
			strcpy(pathname + len, filename);
			if (stat(pathname, &statbuf) == 0 &&
			    /* Accept only regular files
			       with some execute bits set.
			       XXX not perfect, might still fail */
			    S_ISREG(statbuf.st_mode) &&
			    (statbuf.st_mode & 0111))
				break;
		}
	}
	if (stat(pathname, &statbuf) < 0) {
		die_errno(1, "Can't stat '%s'", filename);
	}

	pid = fork();
	if (pid == 0) {
#ifdef WANT_SECCOMP
		int r;

		if (sydbox->config.use_seccomp) {
			if ((r = seccomp_init()) < 0) {
				fprintf(stderr, "seccomp_init failed (errno:%d %s)\n",
						-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}

			if ((r = sysinit_seccomp()) < 0) {
				fprintf(stderr, "seccomp_apply failed (errno:%d %s)\n",
						-r, strerror(-r));
				_exit(EXIT_FAILURE);
			}
		}
#endif
		pid = getpid();
		if (!pink_trace_me()) {
			fprintf(stderr, "ptrace(PTRACE_TRACEME, ...) failed (errno:%d %s)\n",
					errno, strerror(errno));
			_exit(EXIT_FAILURE);
		}
		kill(pid, SIGSTOP);

		execv(pathname, argv);
		fprintf(stderr, "execv failed (errno:%d %s)\n", errno, strerror(errno));
		_exit(EXIT_FAILURE);
	}

	current = pink_easy_process_new(sydbox->ctx, pid, -1,
			PINK_EASY_PROCESS_IGNORE_ONE_SIGSTOP);
	if (current == NULL) {
		kill(pid, SIGKILL);
		die_errno(1, "pink_easy_process_new");
	}
}

int main(int argc, char **argv)
{
	int opt, r;
	pid_t pid;
	const char *env;
	struct sigaction sa;

	int ptrace_options;
	enum pink_easy_step ptrace_default_step;

	/* Long options are present for compatibility with sydbox-0.
	 * Thus they are not documented!
	 */
	int options_index;
	char *profile_name;
	struct option long_options[] = {
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'V'},
		{"profile",	required_argument,	NULL,	0},
		{NULL,		0,		NULL,	0},
	};

	/* Initialize Sydbox */
	sydbox_init();

	/* Make sure SIGCHLD has the default action so that waitpid
	   definitely works without losing track of children.  The user
	   should not have given us a bogus state to inherit, but he might
	   have.  Arguably we should detect SIG_IGN here and pass it on
	   to children, but probably noone really needs that.  */
	signal(SIGCHLD, SIG_DFL);

	while ((opt = getopt_long(argc, argv, "hVvc:m:E:", long_options, &options_index)) != EOF) {
		switch (opt) {
		case 0:
			if (streq(long_options[options_index].name, "profile")) {
				profile_name = xmalloc(sizeof(char) * (strlen(optarg) + 1));
				profile_name[0] = SYDBOX_PROFILE_CHAR;
				strcat(profile_name, optarg);
				config_reset();
				config_parse_spec(profile_name);
				free(profile_name);
				break;
			}
			usage(stderr, 1);
		case 'h':
			usage(stdout, 0);
		case 'V':
			about();
			return 0;
		case 'v':
			sydbox->config.log_level++;
			break;
		case 'c':
			config_reset();
			config_parse_spec(optarg);
			break;
		case 'm':
			r = magic_cast_string(NULL, optarg, 0);
			if (r < 0)
				die(1, "invalid magic: `%s': %s", optarg, magic_strerror(r));
			break;
		case 'E':
			if (putenv(optarg))
				die_errno(1, "putenv");
			break;
		default:
			usage(stderr, 1);
		}
	}

	if (optind == argc)
		usage(stderr, 1);

	if ((env = getenv(SYDBOX_CONFIG_ENV))) {
		config_reset();
		config_parse_spec(env);
	}

	pink_easy_init();
	log_init();
	config_done();
	callback_init();
	systable_init();
	sysinit();

	ptrace_options = PINK_TRACE_OPTION_SYSGOOD | PINK_TRACE_OPTION_EXEC;
	ptrace_default_step = PINK_EASY_STEP_SYSCALL;
	if (sydbox->config.follow_fork)
		ptrace_options |= (PINK_TRACE_OPTION_FORK
				| PINK_TRACE_OPTION_VFORK
				| PINK_TRACE_OPTION_CLONE);
	if (sydbox->config.use_seccomp) {
#ifdef WANT_SECCOMP
		ptrace_options |= PINK_TRACE_OPTION_SECCOMP;
		ptrace_default_step = PINK_EASY_STEP_RESUME;
#else
		info("seccomp: not supported, disabling");
		sydbox->config.use_seccomp = false;
#endif
	}

	sydbox->ctx = pink_easy_context_new(ptrace_options, &sydbox->callback_table, NULL, NULL);
	if (sydbox->ctx == NULL)
		die_errno(-1, "pink_easy_context_new");
	pink_easy_context_set_step(sydbox->ctx, ptrace_default_step);

	/* Ignore initial execve(2) related events
	 * 1. PTRACE_EVENT_EXEC
	 * 2. PTRACE_EVENT_SECCOMP (in case seccomp is enabled)
	 * 3. SIGTRAP | 0x80 (stop after execve system call)
	 */
	sydbox->wait_execve = sydbox->config.use_seccomp ? 3 : 2;
	sydbox->program_invocation_name = xstrdup(argv[optind]);

	/* Set useful environment variables for children */
	setenv("SYDBOX_ACTIVE", "1", 1);
	setenv("SYDBOX_VERSION", VERSION, 1);

	/* Poison! */
	if (streq(argv[optind], "/bin/sh"))
		fprintf(stderr, "[01;35m" PINK_FLOYD "[00;00m");

	/* STARTUP_CHILD must be called before the signal handlers get
	   installed below as they are inherited into the spawned process.
	   Also we do not need to be protected by them as during interruption
	   in the STARTUP_CHILD mode we kill the spawned process anyway.  */
	sydbox_startup_child(&argv[optind]);
	pink_easy_interrupt_init(sydbox->config.trace_interrupt);
	r = pink_easy_loop(sydbox->ctx);
	sydbox_destroy();
	return r;
}
