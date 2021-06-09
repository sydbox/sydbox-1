/*
 * sydbox/magic.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2020 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"

#include <errno.h>
#include <string.h>

#include "pink.h"

#include "macro.h"
#include "util.h"

struct key {
	const char *name;
	const char *lname;
	unsigned parent;
	enum magic_type type;
	int (*set) (const void *val, syd_process_t *current);
	int (*append) (const void *val, syd_process_t *current);
	int (*remove) (const void *val, syd_process_t *current);
	int (*query) (syd_process_t *current);
	int (*cmd) (const void *val, syd_process_t *current);
};

static const struct key key_table[] = {
	[MAGIC_KEY_NONE] = {
		.lname  = "(none)",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_VERSION] = {
		.name = STRINGIFY(SYDBOX_API_VERSION),
		.lname = STRINGIFY(SYDBOX_API_VERSION),
		.parent = MAGIC_KEY_NONE,
		.type = MAGIC_TYPE_NONE,
	},

	[MAGIC_KEY_CORE] = {
		.name   = "core",
		.lname  = "core",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_CORE_MATCH] = {
		.name   = "match",
		.lname  = "core.match",
		.parent = MAGIC_KEY_CORE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_CORE_SANDBOX] = {
		.name   = "sandbox",
		.lname  = "core.sandbox",
		.parent = MAGIC_KEY_CORE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_CORE_RESTRICT] = {
		.name   = "restrict",
		.lname  = "core.restrict",
		.parent = MAGIC_KEY_CORE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_CORE_WHITELIST] = {
		.name   = "whitelist",
		.lname  = "core.whitelist",
		.parent = MAGIC_KEY_CORE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_CORE_VIOLATION] = {
		.name   = "violation",
		.lname  = "core.violation",
		.parent = MAGIC_KEY_CORE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_CORE_TRACE] = {
		.name   = "trace",
		.lname  = "core.trace",
		.parent = MAGIC_KEY_CORE,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_EXEC] = {
		.name   = "exec",
		.lname  = "exec",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_FILTER] = {
		.name   = "filter",
		.lname  = "filter",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_WHITELIST] = {
		.name   = "whitelist",
		.lname  = "whitelist",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_WHITELIST_NETWORK] = {
		.name   = "network",
		.lname  = "whitelist.network",
		.parent = MAGIC_KEY_WHITELIST,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_BLACKLIST] = {
		.name   = "blacklist",
		.lname  = "blacklist",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_BLACKLIST_NETWORK] = {
		.name   = "network",
		.lname  = "blacklist.network",
		.parent = MAGIC_KEY_BLACKLIST,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_CMD] = {
		.name   = "cmd",
		.lname  = "cmd",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_CORE_MATCH_CASE_SENSITIVE] = {
		.name   = "case_sensitive",
		.lname  = "core.match.case_sensitive",
		.parent = MAGIC_KEY_CORE_MATCH,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_match_case_sensitive,
		.query  = magic_query_match_case_sensitive,
	},
	[MAGIC_KEY_CORE_MATCH_NO_WILDCARD] = {
		.name   = "no_wildcard",
		.lname  = "core.match.no_wildcard",
		.parent = MAGIC_KEY_CORE_MATCH,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_match_no_wildcard,
	},

	[MAGIC_KEY_CORE_SANDBOX_EXEC] = {
		.name   = "exec",
		.lname  = "core.sandbox.exec",
		.parent = MAGIC_KEY_CORE_SANDBOX,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_sandbox_exec,
		.query  = magic_query_sandbox_exec,
	},
	[MAGIC_KEY_CORE_SANDBOX_READ] = {
		.name   = "read",
		.lname  = "core.sandbox.read",
		.parent = MAGIC_KEY_CORE_SANDBOX,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_sandbox_read,
		.query  = magic_query_sandbox_read,
	},
	[MAGIC_KEY_CORE_SANDBOX_WRITE] = {
		.name   = "write",
		.lname  = "core.sandbox.write",
		.parent = MAGIC_KEY_CORE_SANDBOX,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_sandbox_write,
		.query  = magic_query_sandbox_write,
	},
	[MAGIC_KEY_CORE_SANDBOX_NETWORK] = {
		.name   = "network",
		.lname  = "core.sandbox.network",
		.parent = MAGIC_KEY_CORE_SANDBOX,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_sandbox_network,
		.query  = magic_query_sandbox_network,
	},

	[MAGIC_KEY_CORE_RESTRICT_GENERAL] = {
		.name   = "general",
		.lname  = "core.restrict.general",
		.parent = MAGIC_KEY_CORE_RESTRICT,
		.type   = MAGIC_TYPE_INTEGER,
		.set    = magic_set_restrict_general,
		.query  = magic_query_restrict_general,
	},
	[MAGIC_KEY_CORE_RESTRICT_FILE_CONTROL] = {
		.name   = "file_control",
		.lname  = "core.restrict.file_control",
		.parent = MAGIC_KEY_CORE_RESTRICT,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_restrict_fcntl,
		.query  = magic_query_restrict_fcntl,
	},
	[MAGIC_KEY_CORE_RESTRICT_IO_CONTROL] = {
		.name   = "io_control",
		.lname  = "core.restrict.io_control",
		.parent = MAGIC_KEY_CORE_RESTRICT,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_restrict_ioctl,
		.query  = magic_query_restrict_ioctl,
	},
	[MAGIC_KEY_CORE_RESTRICT_MEMORY_MAP] = {
		.name   = "memory_map",
		.lname  = "core.restrict.memory_map",
		.parent = MAGIC_KEY_CORE_RESTRICT,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_restrict_mmap,
		.query  = magic_query_restrict_mmap,
	},
	[MAGIC_KEY_CORE_RESTRICT_SHARED_MEMORY_WRITABLE] = {
		.name   = "shared_memory_writable",
		.lname  = "core.restrict.shared_memory_writable",
		.parent = MAGIC_KEY_CORE_RESTRICT,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_restrict_shm_wr,
		.query  = magic_query_restrict_shm_wr,
	},

	[MAGIC_KEY_CORE_WHITELIST_PER_PROCESS_DIRECTORIES] = {
		.name   = "per_process_directories",
		.lname  = "core.whitelist.per_process_directories",
		.parent = MAGIC_KEY_CORE_WHITELIST,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_whitelist_ppd,
		.query  = magic_query_whitelist_ppd,
	},
	[MAGIC_KEY_CORE_WHITELIST_SUCCESSFUL_BIND] = {
		.name   = "successful_bind",
		.lname  = "core.whitelist.successful_bind",
		.parent = MAGIC_KEY_CORE_WHITELIST,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_whitelist_sb,
		.query  = magic_query_whitelist_sb,
	},
	[MAGIC_KEY_CORE_WHITELIST_UNSUPPORTED_SOCKET_FAMILIES] = {
		.name   = "unsupported_socket_families",
		.lname  = "core.whitelist.unsupported_socket_families",
		.parent = MAGIC_KEY_CORE_WHITELIST,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_whitelist_usf,
		.query  = magic_query_whitelist_usf,
	},

	[MAGIC_KEY_CORE_VIOLATION_DECISION] = {
		.name   = "decision",
		.lname  = "core.violation.decision",
		.parent = MAGIC_KEY_CORE_VIOLATION,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_violation_decision,
	},
	[MAGIC_KEY_CORE_VIOLATION_EXIT_CODE] = {
		.name   = "exit_code",
		.lname  = "core.violation.exit_code",
		.parent = MAGIC_KEY_CORE_VIOLATION,
		.type   = MAGIC_TYPE_INTEGER,
		.set    = magic_set_violation_exit_code,
	},
	[MAGIC_KEY_CORE_VIOLATION_RAISE_FAIL] = {
		.name   = "raise_fail",
		.lname  = "core.violation.raise_fail",
		.parent = MAGIC_KEY_CORE_VIOLATION,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_violation_raise_fail,
		.query  = magic_query_violation_raise_fail,
	},
	[MAGIC_KEY_CORE_VIOLATION_RAISE_SAFE] = {
		.name   = "raise_safe",
		.lname  = "core.violation.raise_safe",
		.parent = MAGIC_KEY_CORE_VIOLATION,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_violation_raise_safe,
		.query  = magic_query_violation_raise_safe,
	},

	[MAGIC_KEY_CORE_TRACE_MAGIC_LOCK] = {
		.name   = "magic_lock",
		.lname  = "core.trace.magic_lock",
		.parent = MAGIC_KEY_CORE_TRACE,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_trace_magic_lock,
	},
	[MAGIC_KEY_CORE_TRACE_USE_TOOLONG_HACK] = {
		.name   = "use_toolong_hack",
		.lname  = "core.trace.use_toolong_hack",
		.parent = MAGIC_KEY_CORE_TRACE,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_trace_use_toolong_hack,
		.query  = magic_query_trace_use_toolong_hack,
	},

	[MAGIC_KEY_EXEC_KILL_IF_MATCH] = {
		.name   = "kill_if_match",
		.lname  = "exec.kill_if_match",
		.parent = MAGIC_KEY_EXEC,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_exec_kill_if_match,
		.remove = magic_remove_exec_kill_if_match,
	},
	[MAGIC_KEY_EXEC_RESUME_IF_MATCH] = {
		.name   = "resume_if_match",
		.lname  = "exec.resume_if_match",
		.parent = MAGIC_KEY_EXEC,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_exec_resume_if_match,
		.remove = magic_remove_exec_resume_if_match,
	},

	[MAGIC_KEY_WHITELIST_EXEC] = {
		.name   = "exec",
		.lname  = "whitelist.exec",
		.parent = MAGIC_KEY_WHITELIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_whitelist_exec,
		.remove = magic_remove_whitelist_exec,
	},
	[MAGIC_KEY_WHITELIST_READ] = {
		.name   = "read",
		.lname  = "whitelist.read",
		.parent = MAGIC_KEY_WHITELIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_whitelist_read,
		.remove = magic_remove_whitelist_read,
	},
	[MAGIC_KEY_WHITELIST_WRITE] = {
		.name   = "write",
		.lname  = "whitelist.write",
		.parent = MAGIC_KEY_WHITELIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_whitelist_write,
		.remove = magic_remove_whitelist_write,
	},
	[MAGIC_KEY_WHITELIST_NETWORK_BIND] = {
		.name   = "bind",
		.lname  = "whitelist.network.bind",
		.parent = MAGIC_KEY_WHITELIST_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_whitelist_network_bind,
		.remove = magic_remove_whitelist_network_bind,
	},
	[MAGIC_KEY_WHITELIST_NETWORK_CONNECT] = {
		.name   = "connect",
		.lname  = "whitelist.network.connect",
		.parent = MAGIC_KEY_WHITELIST_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_whitelist_network_connect,
		.remove = magic_remove_whitelist_network_connect,
	},

	[MAGIC_KEY_BLACKLIST_EXEC] = {
		.name   = "exec",
		.lname  = "blacklist.exec",
		.parent = MAGIC_KEY_BLACKLIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_blacklist_exec,
		.remove = magic_remove_blacklist_exec,
	},
	[MAGIC_KEY_BLACKLIST_READ] = {
		.name   = "read",
		.lname  = "blacklist.read",
		.parent = MAGIC_KEY_BLACKLIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_blacklist_read,
		.remove = magic_remove_blacklist_read,
	},
	[MAGIC_KEY_BLACKLIST_WRITE] = {
		.name   = "write",
		.lname  = "blacklist.write",
		.parent = MAGIC_KEY_BLACKLIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_blacklist_write,
		.remove = magic_remove_blacklist_write,
	},
	[MAGIC_KEY_BLACKLIST_NETWORK_BIND] = {
		.name   = "bind",
		.lname  = "blacklist.network.bind",
		.parent = MAGIC_KEY_BLACKLIST_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_blacklist_network_bind,
		.remove = magic_remove_blacklist_network_bind,
	},
	[MAGIC_KEY_BLACKLIST_NETWORK_CONNECT] = {
		.name   = "connect",
		.lname  = "blacklist.network.connect",
		.parent = MAGIC_KEY_BLACKLIST_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_blacklist_network_connect,
		.remove = magic_remove_blacklist_network_connect,
	},

	[MAGIC_KEY_FILTER_EXEC] = {
		.name   = "exec",
		.lname  = "filter.exec",
		.parent = MAGIC_KEY_FILTER,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_filter_exec,
		.remove = magic_remove_filter_exec,
	},
	[MAGIC_KEY_FILTER_READ] = {
		.name   = "read",
		.lname  = "filter.read",
		.parent = MAGIC_KEY_FILTER,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_filter_read,
		.remove = magic_remove_filter_read,
	},
	[MAGIC_KEY_FILTER_WRITE] = {
		.name   = "write",
		.lname  = "filter.write",
		.parent = MAGIC_KEY_FILTER,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_filter_write,
		.remove = magic_remove_filter_write,
	},
	[MAGIC_KEY_FILTER_NETWORK] = {
		.name   = "network",
		.lname  = "filter.network",
		.parent = MAGIC_KEY_FILTER,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_filter_network,
		.remove = magic_remove_filter_network,
	},

	[MAGIC_KEY_CMD_EXEC] = {
		.name   = "exec",
		.lname  = "cmd.exec",
		.parent = MAGIC_KEY_CMD,
		.type   = MAGIC_TYPE_COMMAND,
		.cmd    = magic_cmd_exec,
	},

	[MAGIC_KEY_INVALID] = {
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_NONE,
	},
};

enum magic_ret magic_check_call(int rval)
{
	switch (rval) {
	case 0:
		if (errno != EAFNOSUPPORT)
			return MAGIC_RET_OK;
		/* fall through (for cases like --disable-ipv6) */
		PINK_GCC_ATTR((fallthrough));
	case EAFNOSUPPORT:
		return MAGIC_RET_NOT_SUPPORTED;
	default:
		return MAGIC_RET_INVALID_VALUE;
	}
}

const char *magic_strerror(int error)
{
	if (error < 0)
		return strerror(-error);

	switch (error) {
	case 0:
		return "success";
	case MAGIC_RET_NOOP:
		return "noop";
	case MAGIC_RET_OK:
		return "ok";
	case MAGIC_RET_TRUE:
		return "true";
	case MAGIC_RET_FALSE:
		return "false";
	case MAGIC_RET_NOT_SUPPORTED:
		return "not supported";
	case MAGIC_RET_INVALID_KEY:
		return "invalid key";
	case MAGIC_RET_INVALID_TYPE:
		return "invalid type";
	case MAGIC_RET_INVALID_VALUE:
		return "invalid value";
	case MAGIC_RET_INVALID_QUERY:
		return "invalid query";
	case MAGIC_RET_INVALID_COMMAND:
		return "invalid command";
	case MAGIC_RET_INVALID_OPERATION:
		return "invalid operation";
	case MAGIC_RET_NOPERM:
		return "no permission";
	case MAGIC_RET_OOM:
		return "out of memory";
	case MAGIC_RET_PROCESS_TERMINATED:
		return "process terminated";
	default:
		return "unknown error";
	}
}

const char *magic_strkey(enum magic_key key)
{
	return (key >= MAGIC_KEY_INVALID)
		? "invalid"
		: key_table[key].lname;
}

unsigned magic_key_parent(enum magic_key key)
{
	return (key >= MAGIC_KEY_INVALID)
		? MAGIC_KEY_INVALID
		: key_table[key].parent;
}

unsigned magic_key_type(enum magic_key key)
{
	return (key >= MAGIC_KEY_INVALID)
		? MAGIC_TYPE_NONE
		: key_table[key].type;
}

unsigned magic_key_lookup(enum magic_key key, const char *nkey, ssize_t len)
{
	if (key >= MAGIC_KEY_INVALID)
		return MAGIC_KEY_INVALID;

	for (unsigned i = 1; i < MAGIC_KEY_INVALID; i++) {
		if (key == key_table[i].parent) {
			if (len < 0) {
				if (streq(nkey, key_table[i].name))
					return i;
			} else {
				if (!strncmp(nkey, key_table[i].name, len))
					return i;
			}
		}
	}

	return MAGIC_KEY_INVALID;
}

static int magic_ok(struct key entry, enum magic_op op)
{
	/* Step 1: Check type */
	switch (op) {
	case MAGIC_OP_SET:
		switch (entry.type) {
		case MAGIC_TYPE_BOOLEAN:
		case MAGIC_TYPE_INTEGER:
		case MAGIC_TYPE_STRING:
			if (entry.set == NULL)
				return MAGIC_RET_INVALID_OPERATION;
			break;
		default:
			return MAGIC_RET_INVALID_TYPE;
		}
		break;
	case MAGIC_OP_QUERY:
		if (entry.query == NULL)
			return MAGIC_RET_INVALID_OPERATION;
		break;
	case MAGIC_OP_APPEND:
	case MAGIC_OP_REMOVE:
		if (entry.type != MAGIC_TYPE_STRING_ARRAY)
			return MAGIC_RET_INVALID_TYPE;
		if (op == MAGIC_OP_APPEND && entry.append == NULL)
			return MAGIC_RET_INVALID_OPERATION;
		if (op == MAGIC_OP_REMOVE && entry.remove == NULL)
			return MAGIC_RET_INVALID_OPERATION;
		break;
	case MAGIC_OP_EXEC:
		if (entry.cmd == NULL)
			return MAGIC_RET_INVALID_OPERATION;
		break;
	}

	/* Step 2: Check access */
	if (!sydbox->config.magic_core_allow) {
		enum magic_key k = entry.parent;
		do {
			if (k == MAGIC_KEY_CORE)
				return MAGIC_RET_NOPERM;
			k = key_table[k].parent;
		} while (k != MAGIC_KEY_NONE);
	}

	return MAGIC_RET_OK;
}

int magic_cast(syd_process_t *current, enum magic_op op, enum magic_key key, const void *val)
{
	int r;
	struct key entry;

	if (key >= MAGIC_KEY_INVALID)
		return MAGIC_RET_INVALID_KEY;

	entry = key_table[key];
	r = magic_ok(entry, op);
	if (r != MAGIC_RET_OK)
		return r;

	switch (op) {
	case MAGIC_OP_SET:
		return entry.set(val, current);
	case MAGIC_OP_QUERY:
		return entry.query(current);
	case MAGIC_OP_APPEND:
		return entry.append(val, current);
	case MAGIC_OP_REMOVE:
		return entry.remove(val, current);
	case MAGIC_OP_EXEC:
		return entry.cmd(val, current);
	default:
		return MAGIC_RET_INVALID_OPERATION;
	}
}

static enum magic_key magic_next_key(const char *magic, enum magic_key key)
{
	int r;

	for (r = MAGIC_KEY_NONE + 1; r < MAGIC_KEY_INVALID; r++) {
		struct key k = key_table[r];

		if (k.parent == key && k.name && startswith(magic, k.name))
			return r;
	}

	return MAGIC_KEY_INVALID;
}

int magic_cast_string(syd_process_t *current, const char *magic, int prefix)
{
	bool bval;
	int ival;
	enum magic_key key;
	enum magic_op op;
	const char *cmd;
	struct key entry;

	if (prefix) {
		if (!startswith(magic, SYDBOX_MAGIC_PREFIX)) {
			/* no magic */
			return MAGIC_RET_NOOP;
		}

		cmd = magic + sizeof(SYDBOX_MAGIC_PREFIX) - 1;
		if (!*cmd) {
			/* magic without command */
			return MAGIC_RET_OK;
		} else if (*cmd != '/') {
			/* no magic, e.g. /dev/sydboxFOO */
			return MAGIC_RET_NOOP;
		} else {
			cmd++; /* Skip the '/' */
		}
	} else {
		cmd = magic;
	}

	/* Figure out the magic command */
	for (key = MAGIC_KEY_NONE;;) {
		key = magic_next_key(cmd, key);
		if (key == MAGIC_KEY_INVALID)
			return MAGIC_RET_INVALID_KEY;

		cmd += strlen(key_table[key].name);
		if (*cmd == '/') {
			if (key_table[key].type != MAGIC_TYPE_OBJECT)
				return MAGIC_RET_INVALID_KEY;
			cmd++;
			continue;
		} else if (*cmd == SYDBOX_MAGIC_SET_CHAR) {
			op = MAGIC_OP_SET;
			break;
		} else if (*cmd == SYDBOX_MAGIC_APPEND_CHAR) {
			op = MAGIC_OP_APPEND;
			break;
		} else if (*cmd == SYDBOX_MAGIC_REMOVE_CHAR) {
			op = MAGIC_OP_REMOVE;
			break;
		} else if (*cmd == SYDBOX_MAGIC_QUERY_CHAR) {
			op = MAGIC_OP_QUERY;
			break;
		} else if (*cmd == SYDBOX_MAGIC_EXEC_CHAR) {
			op = MAGIC_OP_EXEC;
			break;
		} else if (*cmd == 0) {
			if (key_table[key].type == MAGIC_TYPE_NONE) {
				/*
				 * special path.
				 * for example: /dev/sydbox/${majorver}
				 */
				return MAGIC_RET_OK;
			}
			return MAGIC_RET_INVALID_KEY;
		} else {
			return MAGIC_RET_INVALID_KEY;
		}
	}

	cmd++; /* skip operation character */
	entry = key_table[key];
	switch (op) {
	case MAGIC_OP_SET:
		switch (entry.type) {
		case MAGIC_TYPE_BOOLEAN:
			if (parse_boolean(cmd, &bval) < 0)
				return MAGIC_RET_INVALID_VALUE;
			return magic_cast(current, op, key, BOOL_TO_PTR(bval));
		case MAGIC_TYPE_INTEGER:
			if (safe_atoi(cmd, &ival) < 0)
				return MAGIC_RET_INVALID_VALUE;
			return magic_cast(current, op, key, INT_TO_PTR(ival));
		case MAGIC_TYPE_STRING:
			return magic_cast(current, op, key, cmd);
		default:
			return MAGIC_RET_INVALID_TYPE;
		}
	case MAGIC_OP_APPEND:
	case MAGIC_OP_REMOVE:
		return magic_cast(current, op, key, cmd);
	case MAGIC_OP_QUERY:
		return magic_cast(current, op, key, NULL);
	case MAGIC_OP_EXEC:
		return magic_cast(current, op, key, cmd);
	default:
		return MAGIC_RET_INVALID_OPERATION;
	}
}
