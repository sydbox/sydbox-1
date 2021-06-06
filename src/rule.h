/*
 * sydbox/rule.h
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

enum syd_user_action {
	SYD_USER_ACTION_KILL_PROCESS,
	SYD_USER_ACTION_KILL_THREAD,
	SYD_USER_ACTION_TRAP,
	SYD_USER_ACTION_LOG,
	SYD_USER_ACTION_ALLOW,
	SYD_USER_ACTION_LOAD,
};

enum syd_action {
	SYD_ACTION_KILL_PROCESS,
	SYD_ACTION_KILL_THREAD,
	SYD_ACTION_FAULT,
	SYD_ACTION_TRAP,
	SYD_ACTION_LOG,
	SYD_ACTION_ALLOW,
	SYD_ACTION_USER,
};

enum syd_sysset {
	SYSSET_FILE_RD,
	SYSSET_FILE_RW,
	SYSSSET_FILE,
	SYSSET_EXEC,
	SYSSET_NET,
};

struct rule {
	enum syd_action action:3;
	enum syd_user_action user_action:3;

	union {
		enum syd_sysset num_set;
		int num;
	} syscall;
	bool syscall_is_set;

	union {
		int error;
		int retval;
	} trap;

	int signal;

	const char *log;
	const char *command;
	const char *cmdline;

	/* Options for load */
	const char *pathname;
	const char *pathopts;
};
typedef struct rule rule_t;
