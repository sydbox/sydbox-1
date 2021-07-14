/*
 * libsyd/about.c
 *
 * libsyd Library Information
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "config.h"
#include <syd/syd.h>
#include <errno.h>
#include <seccomp.h>

int syd_about(FILE *report_fd)
{
	if (!report_fd)
		return -EINVAL;

	static const struct scmp_version *syd_scmp_version = NULL;
	if (!syd_scmp_version)
		syd_scmp_version = seccomp_version();

	int r = fprintf(report_fd,
			"[0;1;31;91m"
			PACKAGE"-"VERSION GITVERSION
			"[0m\n") < 0 ? -errno : 0;
	if (r < 0)
		return -errno;
	if (syd_scmp_version) {
		r = fprintf(report_fd,
			    "[0;1;31;91mUsing "
			    "[0;1;32;92m"
			    "libseccomp v%u.%u.%u[0m\n",
				syd_scmp_version->major,
				syd_scmp_version->minor,
				syd_scmp_version->micro);
		if (r < 0)
			return -errno;
	}
	fputs("[0;1;31;91mOptions: [0;1;32;92m", report_fd);
#if SYDBOX_HAVE_DUMP_BUILTIN
	fputs("dump:yes ", report_fd);
#else
	fputs("dump:no ", report_fd);
#endif
	fputs("seccomp:yes",
	      report_fd);
	fputs(" ipv6:yes",
	      report_fd);
	fputs(" netlink:yes[0m\n",
	      report_fd);
	fprintf(report_fd, "[0;1;31;91m"
		"Release Codename: "
		"[0;1;36;96m"
		CODENAME"[0m\n\n");
	fprintf(report_fd, "[0;1;35;95m"
		"Compiler Flags: "SYDBOX_CFLAGS"[0m\n");
	fprintf(report_fd, "[0;1;33;93m"
		"Linker Flags: "SYDBOX_LDFLAGS"[0m\n");
	fputs("\n[0;1;32;91m"
	      "Copyright © "
	      "2010, 2011, 2012, 2013, "
	      "2014, 2015, 2018, 2020, "
	      "2021"
	      "[0m\n", report_fd);
	fputs("[0;1;34;91mAlï P☮latel <alïp@exherb☮.☮rg>[0m\n", report_fd);
	fputs("[0;1;32;92m"
	      "SPDX-License-Identifier: "
	      "[0;1;34;94m"
	      "GPL-2.0-only"
	      "[0m\n",
	      report_fd);

	return 0;
}
