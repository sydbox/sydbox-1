/*
 * libsyd/about.c
 *
 * libsyd Library Information
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "config.h"
#include "syd.h"
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
			"[0m") < 0 ? -errno : 0;
	if (r < 0)
		return -errno;
	if (syd_scmp_version) {
		r = fprintf(report_fd,
			    "[0;1;31;91mUsing libseccomp v%u.%u.%u[0m",
				syd_scmp_version->major,
				syd_scmp_version->minor,
				syd_scmp_version->micro);
		if (r < 0)
			return -errno;
	}
	fputs("[0;1;31;91mOptions: ", report_fd);
#if SYDBOX_HAVE_DUMP_BUILTIN
	fputs("dump:yes", report_fd);
#else
	fputs("dump:no", report_fd);
#endif
	fputs("seccomp:yes",
	      report_fd);
	fputs(" ipv6:yes",
	      report_fd);
	fputs(" netlink:yes[0m\n",
	      report_fd);
	fputs("[0;1;32;91mCopyright © 2010, 2011, 2012, 2013, 2014, 2015, 2018, 2020, 2021[0m",
	      report_fd);
	fputs("[0;1;34;91mAlï P☮latel <alïp@exherb☮.☮rg>[0m", report_fd);
	fputs("SPDX-License-Identifier: [0;1;31;91mGPL-2.0-only[0m",
	      report_fd);

	return 0;
}
