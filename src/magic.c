/*
 * sydbox/magic.c
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2020 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-box.h"

#include <stdio.h>
#include <string.h>

struct key {
	const char *name;
	const char *lname;
	unsigned parent;
	enum magic_type type;
	int (*set) (const void *restrict val, syd_process_t *current);
	int (*append) (const void *restrict val, syd_process_t *current);
	int (*remove) (const void *restrict val, syd_process_t *current);
	int (*query) (syd_process_t *current);
	int (*cmd) (const void *restrict val, syd_process_t *current);
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
	[MAGIC_KEY_CORE_ALLOWLIST] = {
		.name   = "allowlist",
		.lname  = "core.allowlist",
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

	[MAGIC_KEY_LOG] = {
		.name   = "log",
		.lname  = "log",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_LOG_NETWORK] = {
		.name   = "network",
		.lname  = "log.network",
		.parent = MAGIC_KEY_LOG,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_LOG_FILE] = {
		.name   = "file",
		.lname  = "log.file",
		.parent = MAGIC_KEY_LOG,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_LOG_FILE_NETWORK] = {
		.name   = "network",
		.lname  = "log.file.network",
		.parent = MAGIC_KEY_LOG_FILE,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_ALLOWLIST] = {
		.name   = "allowlist",
		.lname  = "allowlist",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_ALLOWLIST_NETWORK] = {
		.name   = "network",
		.lname  = "allowlist.network",
		.parent = MAGIC_KEY_ALLOWLIST,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_DENYLIST] = {
		.name   = "denylist",
		.lname  = "denylist",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},
	[MAGIC_KEY_DENYLIST_NETWORK] = {
		.name   = "network",
		.lname  = "denylist.network",
		.parent = MAGIC_KEY_DENYLIST,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_CMD] = {
		.name   = "cmd",
		.lname  = "cmd",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_OBJECT,
	},

	[MAGIC_KEY_KILL] = {
		.name   = "kill",
		.lname  = "kill",
		.parent = MAGIC_KEY_NONE,
		.type   = MAGIC_TYPE_INTEGER,
		.set    = magic_set_kill,
		.query  = magic_get_kill,
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
	[MAGIC_KEY_CORE_RESTRICT_SYS_INFO] = {
		.name   = "system_info",
		.lname  = "core.restrict.system_info",
		.parent = MAGIC_KEY_CORE_RESTRICT,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_restrict_sysinfo,
		.query  = magic_query_restrict_sysinfo,
	},

	[MAGIC_KEY_CORE_RESTRICT_IDENTITY_CHANGE] = {
		.name   = "id_change",
		.lname  = "core.restrict.id_change",
		.parent = MAGIC_KEY_CORE_RESTRICT,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_restrict_id,
		.query  = magic_query_restrict_id,
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

	[MAGIC_KEY_CORE_ALLOWLIST_PER_PROCESS_DIRECTORIES] = {
		.name   = "per_process_directories",
		.lname  = "core.allowlist.per_process_directories",
		.parent = MAGIC_KEY_CORE_ALLOWLIST,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_allowlist_ppd,
		.query  = magic_query_allowlist_ppd,
	},
	[MAGIC_KEY_CORE_ALLOWLIST_SUCCESSFUL_BIND] = {
		.name   = "successful_bind",
		.lname  = "core.allowlist.successful_bind",
		.parent = MAGIC_KEY_CORE_ALLOWLIST,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_allowlist_sb,
		.query  = magic_query_allowlist_sb,
	},
	[MAGIC_KEY_CORE_ALLOWLIST_UNSUPPORTED_SOCKET_FAMILIES] = {
		.name   = "unsupported_socket_families",
		.lname  = "core.allowlist.unsupported_socket_families",
		.parent = MAGIC_KEY_CORE_ALLOWLIST,
		.type   = MAGIC_TYPE_BOOLEAN,
		.set    = magic_set_allowlist_usf,
		.query  = magic_query_allowlist_usf,
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
	[MAGIC_KEY_CORE_TRACE_MEMORY_ACCESS] = {
		.name   = "memory_access",
		.lname  = "core.trace.memory_access",
		.parent = MAGIC_KEY_CORE_TRACE,
		.type   = MAGIC_TYPE_INTEGER,
		.set    = magic_set_trace_memory_access,
		.query  = magic_query_trace_memory_access,
	},
	[MAGIC_KEY_CORE_TRACE_PROGRAM_CHECKSUM] = {
		.name   = "program_checksum",
		.lname  = "core.trace.program_checksum",
		.parent = MAGIC_KEY_CORE_TRACE,
		.type   = MAGIC_TYPE_INTEGER,
		.set    = magic_set_trace_program_checksum,
		.query  = magic_query_trace_program_checksum,
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

	[MAGIC_KEY_ALLOWLIST_EXEC] = {
		.name   = "exec",
		.lname  = "allowlist.exec",
		.parent = MAGIC_KEY_ALLOWLIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_allowlist_exec,
		.remove = magic_remove_allowlist_exec,
	},
	[MAGIC_KEY_ALLOWLIST_READ] = {
		.name   = "read",
		.lname  = "allowlist.read",
		.parent = MAGIC_KEY_ALLOWLIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_allowlist_read,
		.remove = magic_remove_allowlist_read,
	},
	[MAGIC_KEY_ALLOWLIST_WRITE] = {
		.name   = "write",
		.lname  = "allowlist.write",
		.parent = MAGIC_KEY_ALLOWLIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_allowlist_write,
		.remove = magic_remove_allowlist_write,
	},
	[MAGIC_KEY_ALLOWLIST_NETWORK_BIND] = {
		.name   = "bind",
		.lname  = "allowlist.network.bind",
		.parent = MAGIC_KEY_ALLOWLIST_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_allowlist_network_bind,
		.remove = magic_remove_allowlist_network_bind,
	},
	[MAGIC_KEY_ALLOWLIST_NETWORK_CONNECT] = {
		.name   = "connect",
		.lname  = "allowlist.network.connect",
		.parent = MAGIC_KEY_ALLOWLIST_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_allowlist_network_connect,
		.remove = magic_remove_allowlist_network_connect,
	},

	[MAGIC_KEY_DENYLIST_EXEC] = {
		.name   = "exec",
		.lname  = "denylist.exec",
		.parent = MAGIC_KEY_DENYLIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_denylist_exec,
		.remove = magic_remove_denylist_exec,
	},
	[MAGIC_KEY_DENYLIST_READ] = {
		.name   = "read",
		.lname  = "denylist.read",
		.parent = MAGIC_KEY_DENYLIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_denylist_read,
		.remove = magic_remove_denylist_read,
	},
	[MAGIC_KEY_DENYLIST_WRITE] = {
		.name   = "write",
		.lname  = "denylist.write",
		.parent = MAGIC_KEY_DENYLIST,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_denylist_write,
		.remove = magic_remove_denylist_write,
	},
	[MAGIC_KEY_DENYLIST_NETWORK_BIND] = {
		.name   = "bind",
		.lname  = "denylist.network.bind",
		.parent = MAGIC_KEY_DENYLIST_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_denylist_network_bind,
		.remove = magic_remove_denylist_network_bind,
	},
	[MAGIC_KEY_DENYLIST_NETWORK_CONNECT] = {
		.name   = "connect",
		.lname  = "denylist.network.connect",
		.parent = MAGIC_KEY_DENYLIST_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_denylist_network_connect,
		.remove = magic_remove_denylist_network_connect,
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

	[MAGIC_KEY_LOG_EXEC] = {
		.name   = "exec",
		.lname  = "log.exec",
		.parent = MAGIC_KEY_LOG,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_log_exec,
		.remove = magic_remove_log_exec,
	},
	[MAGIC_KEY_LOG_READ] = {
		.name   = "read",
		.lname  = "log.read",
		.parent = MAGIC_KEY_LOG,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_log_read,
		.remove = magic_remove_log_read,
	},
	[MAGIC_KEY_LOG_WRITE] = {
		.name   = "write",
		.lname  = "log.write",
		.parent = MAGIC_KEY_LOG,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_log_write,
		.remove = magic_remove_log_write,
	},
	[MAGIC_KEY_LOG_NETWORK_BIND] = {
		.name   = "bind",
		.lname  = "log.network.bind",
		.parent = MAGIC_KEY_LOG_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_log_network_bind,
		.remove = magic_remove_log_network_bind,
	},
	[MAGIC_KEY_LOG_NETWORK_CONNECT] = {
		.name   = "connect",
		.lname  = "log.network.connect",
		.parent = MAGIC_KEY_LOG_NETWORK,
		.type   = MAGIC_TYPE_STRING_ARRAY,
		.append = magic_append_log_network_connect,
		.remove = magic_remove_log_network_connect,
	},

	[MAGIC_KEY_LOG_FILE_EXEC] = {
		.name   = "exec",
		.lname  = "log.file.exec",
		.parent = MAGIC_KEY_LOG_FILE,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_log_exec_fd,
	},
	[MAGIC_KEY_LOG_FILE_READ] = {
		.name   = "read",
		.lname  = "log.file.read",
		.parent = MAGIC_KEY_LOG_FILE,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_log_read_fd,
	},
	[MAGIC_KEY_LOG_FILE_WRITE] = {
		.name   = "write",
		.lname  = "log.file.write",
		.parent = MAGIC_KEY_LOG_FILE,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_log_write_fd,
	},
	[MAGIC_KEY_LOG_FILE_NETWORK_BIND] = {
		.name   = "bind",
		.lname  = "log.file.network.bind",
		.parent = MAGIC_KEY_LOG_FILE_NETWORK,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_log_network_bind_fd,
	},
	[MAGIC_KEY_LOG_FILE_NETWORK_CONNECT] = {
		.name   = "connect",
		.lname  = "loga.file.network.connect",
		.parent = MAGIC_KEY_LOG_FILE_NETWORK,
		.type   = MAGIC_TYPE_STRING,
		.set    = magic_set_log_network_connect_fd,
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
		SYD_GCC_ATTR((fallthrough));
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
		if (!magic || magic[0] == '\0')
			return MAGIC_RET_INVALID_COMMAND;
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

	if (!cmd || cmd[0] == '\0')
		return MAGIC_RET_INVALID_COMMAND;

	/* Figure out the magic command */
	for (key = MAGIC_KEY_NONE;;) {
		key = magic_next_key(cmd, key);
		if (key == MAGIC_KEY_INVALID)
			return MAGIC_RET_INVALID_KEY;

		dump(DUMP_MAGIC, key, cmd);
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
