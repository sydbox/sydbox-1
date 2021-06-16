/*
 * sydbox/config.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2015, 2018, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "file.h"
#include "macro.h"

static int filename_api(const char *filename, unsigned *api)
{
	const char *ext;

	ext = filename_ext(filename);
	if (!ext)
		return -EINVAL;
	if (!startswith(ext, SYDBOX_FNAME_EXT))
		return -EINVAL;

	ext += STRLEN_LITERAL(SYDBOX_FNAME_EXT);
	return safe_atou(ext, api);
}

void config_init(void)
{
	assert(sydbox);

	memset(&sydbox->config, 0, sizeof(config_t));
	sydbox->config.magic_core_allow = true;

	/* set sane defaults for configuration */
	sydbox->config.use_toolong_hack = false;
	sydbox->config.restrict_general = 0;
	sydbox->config.restrict_ioctl = false;
	sydbox->config.restrict_mmap = false;
	sydbox->config.violation_raise_fail = false;
	sydbox->config.violation_raise_safe = false;
	sydbox->config.allowlist_per_process_directories = true;
	sydbox->config.allowlist_successful_bind = true;
	sydbox->config.allowlist_unsupported_socket_families = true;
	sydbox->config.violation_decision = VIOLATION_DENY;
	sydbox->config.violation_exit_code = -1;
	sydbox->config.box_static.magic_lock = LOCK_UNSET;

	/* initialize default sandbox modes */
	sydbox->config.box_static.mode.sandbox_exec = SANDBOX_OFF;
	sydbox->config.box_static.mode.sandbox_read = SANDBOX_OFF;
	sydbox->config.box_static.mode.sandbox_write = SANDBOX_BPF;
	sydbox->config.box_static.mode.sandbox_network = SANDBOX_BPF;

	/* initialize access control lists */
	sc_map_init_64s(&sydbox->config.proc_pid_auto, 0, 0);

	ACLQ_INIT(&sydbox->config.exec_kill_if_match);
	ACLQ_INIT(&sydbox->config.exec_resume_if_match);
	ACLQ_INIT(&sydbox->config.filter_exec);
	ACLQ_INIT(&sydbox->config.filter_read);
	ACLQ_INIT(&sydbox->config.filter_write);
	ACLQ_INIT(&sydbox->config.filter_network);
	ACLQ_INIT(&sydbox->config.acl_network_connect_auto);
	ACLQ_INIT(&sydbox->config.box_static.acl_exec);
	ACLQ_INIT(&sydbox->config.box_static.acl_read);
	ACLQ_INIT(&sydbox->config.box_static.acl_write);
	ACLQ_INIT(&sydbox->config.box_static.acl_network_bind);
	ACLQ_INIT(&sydbox->config.box_static.acl_network_connect);
}

void config_done(void)
{
	sydbox->config.magic_core_allow = true;
}

void config_parse_file(const char *filename)
{
	int r;
	unsigned api;
	char line[LINE_MAX];
	size_t line_count;
	FILE *fp;

	if (streq(filename, "-")) {
		fp = fdopen(STDIN_FILENO, "r");
		goto fp_open;
	}
	if (filename_api(filename, &api) < 0)
		die("no API information in file name `%s', current API is %u",
		    filename, SYDBOX_API_VERSION);
	if (api != SYDBOX_API_VERSION)
		die("config file name `%s' API mismatch: %u != %u",
		    filename, api, SYDBOX_API_VERSION);

	fp = fopen(filename, "r");
fp_open:
	if (!fp)
		die_errno("fopen(`%s')", filename);

	line_count = 0;
	while (fgets(line, LINE_MAX, fp)) {
		line_count++;
		if (line[0] == '#' || empty_line(line))
			continue;
		truncate_nl(line);
		r = magic_cast_string(NULL, line, 0);
		if (MAGIC_ERROR(r))
			die("invalid magic in file `%s' on line %zu: %s",
			    filename, line_count, magic_strerror(r));
	}

	fclose(fp);
	sydbox->config.magic_core_allow = true;
}

void config_parse_spec(const char *pathspec)
{
	if (pathspec[0] == SYDBOX_PROFILE_CHAR) {
		size_t len;
		char *filename;
		bool has_ext;

		has_ext = endswith(pathspec, SYDBOX_API_EXT);
		pathspec++;
		len = sizeof(DATADIR) + sizeof(PACKAGE); /* /usr/share/sydbox */
		len += strlen(pathspec) + 1; /* profile name */
		if (!has_ext)
			len += STRLEN_LITERAL(SYDBOX_API_EXT) + 1; /* API extension */
		filename = xcalloc(len, sizeof(char));

		strcpy(filename, DATADIR "/" PACKAGE "/");
		strcat(filename, pathspec);
		if (!has_ext) {
			strcat(filename, ".");
			strcat(filename, SYDBOX_API_EXT);
		}

		config_parse_file(filename);
		free(filename);
	} else {
		config_parse_file(pathspec);
	}
}
