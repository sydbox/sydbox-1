/*
 * sydbox/syd-ipc.c
 *
 * Syd's /dev/sydbox IPC Tool
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "syd-conf.h"

#ifdef PACKAGE
# undef PACKAGE
#endif
#define PACKAGE "syd-ipc"

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <syd/syd.h>

#include "errno2name.h"

static void about(void);
static void usage(FILE *outfp, int code)
	SYD_GCC_ATTR((noreturn));

static void say_errno(const char *fmt, ...);
static void die_errno(const char *fmt, ...);

int syd_ipc_main(int argc, char **argv)
{
	if (argc == 1)
		usage(stderr, 1);

	int opt, options_index;
	struct option long_options[] = {
		/* default options */
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
	};

	while ((opt = getopt_long(argc, argv, "hs63sC:H:vc:o:", long_options,
				  &options_index)) != EOF) {
		switch (opt) {
		case 'h':
			usage(stdout, 0);
			return 0;
		case 'v':
			about();
			syd_about(stdout);
			return 0;
		default:
			usage(stderr, 1);
		}
	}

	if (argc == optind)
		usage(stderr, 1);
	argv += optind;
	argc -= optind;

	int r;
	const char *cmd = argv[0];

	if (!strcmp(cmd, "api")) {
		uint8_t api;
		if ((r = syd_ipc_api(&api)) < 0) {
			errno = -r;
			die_errno("syd_ipc_api");
		}
		printf("%"PRIu8"\n", api);
		system("stat /dev/sydbox/" syd_str(SYDBOX_API_VERSION));
	}


	return EXIT_SUCCESS;
}

static void about(void)
{
	printf(SYD_WARN PACKAGE"-"VERSION GITVERSION SYD_RESET "\n");
}

SYD_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION"\n\
Syd's "SYDBOX_MAGIC_PREFIX" IPC Tool\n\
usage: "PACKAGE" [-hv] {command args...}\n\
\n\
-h                         -- Show usage and exit\n\
-v                         -- Show version and exit\n\
\n\
Commands:\n\
api                        -- Display SydB☮x API Version\n\
check                      -- Check the status of Magic IPC\n\
status [--prompt]          -- Check the status of Sandboxing\n\
                              With »--prompt«, print a short summary version\n\
                              suitable for adding to the Shell Prompt\n\
lock                       -- Lock the SydB☮x Magic IPC\n\
exec_lock                  -- Mark the SydB☮x Magic IPC\n\
                              pending to be locked on next process execution\n\
exec {command args...}     -- Execute a process outside the Sandbox\n\
kill {signal}              -- Send signal to the SydB☮x Execute Process\n\
kill_add_match {wildcard}  -- Add wildcard to the list of Execute Path Kill Patterns\n\
kill_rem_match {wildcard}  -- Remove wildcard from the list of Execute Path Kill Patterns\n\
enable                     -- Enable Write Sandboxing\n\
enable_path                -- ditto\n\
enable_write               -- ditto\n\
enable_exec                -- Enable Exec Sandboxing\n\
enable_read                -- Enable Read Sandboxing\n\
enable_net                 -- Enable Network Sandboxing\n\
disable                    -- Disable Write Sandboxing\n\
disable_path               -- ditto\n\
disable_write              -- ditto\n\
disable_exec               -- Disable Exec Sandboxing\n\
disable_read               -- Disable Read Sandboxing\n\
disable_net                -- Disable Network Sandboxing\n\
enabled                    -- Check whether Write Sandboxing is on\n\
enabled_path               -- ditto\n\
enabled_write              -- ditto\n\
enabled_exec               -- Check whether Exec Sandboxing is on\n\
enabled_read               -- Check whether Read Sandboxing is on\n\
enabled_net                -- Check whether Network Sandboxing is on\n\
allow {args...}            -- Add arguments to the Write Sandbox Allow List\n\
allow_path {args...}       -- ditto\n\
allow_write {args...}      -- ditto\n\
allow_exec {args...}       -- Add arguments to the Exec Sandbox Allow List\n\
allow_read {args...}       -- Add arguments to the Read Sandbox Allow List\n\
allow_net {args...}        -- Add arguments to the Network Sandbox Allow List\n\
disallow {args...}         -- Remove arguments from the Write Sandbox Allow List\n\
disallow_path {args...}    -- ditto\n\
disallow_write {args...}   -- ditto\n\
disallow_exec {args...}    -- Remove arguments from the Exec Sandbox Allow List\n\
disallow_read {args...}    -- Remove arguments from the Read Sandbox Allow List\n\
disallow_net {args...}     -- Remove arguments from the Network Sandbox Allow List\n\
deny {args...}             -- Add arguments to the Write Sandbox Deny List\n\
deny_path {args...}        -- ditto\n\
deny_write {args...}       -- ditto\n\
deny_exec {args...}        -- Add arguments to the Exec Sandbox Deny List\n\
deny_read {args...}        -- Add arguments to the Read Sandbox Deny List\n\
deny_net {args...}         -- Add arguments to the Network Sandbox Deny List\n\
undeny {args...}           -- Remove arguments from the Write Sandbox Deny List\n\
undeney_path {args...}     -- ditto\n\
undeny_write {args...}     -- ditto\n\
undeny_exec {args...}      -- Remove arguments from the Exec Sandbox Deny List\n\
undeny_read {args...}      -- Remove arguments from the Read Sandbox Deny List\n\
undeny_net {args...}       -- Remove arguments from the Network Sandbox Deny List\n\
addfilter {args...}        -- Add arguments to the Write Sandbox Filter List\n\
addfilter_path {args...}   -- ditto\n\
addfilter_write {args...}  -- ditto\n\
addfilter_exec {..args}    -- Add arguments to the Exec Sandbox Filter List\n\
addfilter_read {..args}    -- Add arguments to the Read Sandbox Filter List\n\
addfilter_net {..args}     -- Add arguments to the Network Sandbox Filter List\n\
rmfilter {args...}         -- Remove arguments from the Write Sandbox Filter List\n\
rmfilter_path {args...}    -- ditto\n\
rmfilter_write {args...}   -- ditto\n\
rmfilter_exec {..args}     -- Remove arguments from the Exec Sandbox Filter List\n\
rmfilter_read {..args}     -- Remove arguments from the Read Sandbox Filter List\n\
rmfilter_net {..args}      -- Remove arguments from the Network Sandbox Filter List\n\
use_toolong_hack           -- Try harder to resolve absolute names of too long paths\n\
off_toolong_hack           -- Disable the »toolong hack«\n\
                              Do not try hard to resolve absolute names of\n\
			      too long paths (default)\n\
\n"SYD_HELPME);
	exit(code);
}

static void vsay(FILE *fp, const char *fmt, va_list ap, char level)
{
	static int tty = -1;

	if (tty < 0)
		tty = isatty(STDERR_FILENO) == 1 ? 1 : 0;
	if (tty)
		fputs(SYD_WARN, fp);
	if (fmt[0] != ' ')
		fputs(PACKAGE": ", fp);
	switch (level) {
	case 'b':
		fputs("bug: ", fp);
		break;
	case 'f':
		fputs("fatal: ", fp);
		break;
	case 'w':
		fputs("warning: ", fp);
		break;
	default:
		break;
	}
	vfprintf(stderr, fmt, ap);
	if (tty)
		fputs(SYD_RESET, fp);
}

static void say(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 0);
	va_end(ap);
	fputc('\n', stderr);
}

SYD_GCC_ATTR((unused))
static void say_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'e');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	errno = save_errno;
}

SYD_GCC_ATTR((unused))
static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	fputc('\n', stderr);

	exit(EXIT_FAILURE);
}

static void die_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	exit(EXIT_FAILURE);
}

