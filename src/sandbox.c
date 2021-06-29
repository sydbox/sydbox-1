/*
 * sydbox/sandbox.c
 *
 * Sandboxing utilities
 *
 * Copyright (c) 2010, 2011, 2012, 2013, 2014, 2015, 2018, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "bsd-compat.h"
#include "file.h"
#include "path.h"
#include "pathdecode.h"

static void box_report_violation_path(syd_process_t *current,
				      unsigned arg_index,
				      const char *path)
{
	const char *name = current->sysname;

	switch (arg_index) {
	case 0:
		violation(current, "%s(`%s')", name, path);
		break;
	case 1:
		violation(current, "%s(?, `%s')", name, path);
		break;
	case 2:
		violation(current, "%s(?, ?, `%s')", name, path);
		break;
	case 3:
		violation(current, "%s(?, ?, ?, `%s')", name, path);
		break;
	default:
		violation(current, "%s(?)", name);
		break;
	}
}

static void box_report_violation_path_at(syd_process_t *current,
					 unsigned arg_index,
					 const char *path,
					 const char *prefix)
{
	const char *name = current->sysname;

	switch (arg_index) {
	case 1:
		violation(current, "%s(`%s', prefix=`%s')", name, path, prefix);
		break;
	case 2:
		violation(current, "%s(?, `%s', prefix=`%s')", name, path, prefix);
		break;
	case 3:
		violation(current, "%s(?, ?, '%s', prefix=`%s')", name, path, prefix);
		break;
	default:
		violation(current, "%s(?)", name);
		break;
	}
}

static char *box_name_violation_sock(syd_process_t *current,
				     const syscall_info_t *info,
				     const struct pink_sockaddr *paddr,
				     const char *unix_abspath)
{
	bool abstract;
	char ip[64];
	char *repr;

	switch (paddr->family) {
	case AF_UNIX:
		abstract = path_abstract(paddr->u.sa_un.sun_path);
		if (syd_asprintf(&repr, "%s:%s",
				 abstract ? "unix-abstract" : "unix",
				 abstract ? paddr->u.sa_un.sun_path + 1
					: (unix_abspath ? unix_abspath : paddr->u.sa_un.sun_path)) < 0)
			repr = NULL;
		break;
	case AF_INET:
		inet_ntop(AF_INET, &paddr->u.sa_in.sin_addr, ip, sizeof(ip));
		if (syd_asprintf(&repr, "inet:%s@%d",
				 ip, ntohs(paddr->u.sa_in.sin_port)) < 0)
			repr = NULL;
		break;
	case AF_INET6:
		inet_ntop(AF_INET6, &paddr->u.sa6.sin6_addr, ip, sizeof(ip));
		if (syd_asprintf(&repr, "inet6:%s@%d",
				 ip, ntohs(paddr->u.sa6.sin6_port)) < 0)
			repr = NULL;
		break;
	default:
		repr = NULL;
		break;
	}

	return repr;
}

static void box_report_violation_sock(syd_process_t *current,
				      const syscall_info_t *info,
				      const struct pink_sockaddr *paddr)
{
	const char *f;
	const char *name = current->sysname;

	switch (paddr->family) {
	case AF_UNIX:
		violation(current, "%s(%d, %s)",
			  name,
			  info->ret_fd ? *info->ret_fd : -1,
			  current->repr[info->arg_index]);
		break;
	case AF_INET:
		violation(current, "%s(%d, %s)", name,
			  info->ret_fd ? *info->ret_fd : -1,
			  current->repr[info->arg_index]);
		break;
	case AF_INET6:
		violation(current, "%s(%d, %s)", name,
			  info->ret_fd ? *info->ret_fd : -1,
			  current->repr[info->arg_index]);
		break;
	default:
		f = addrfams_to_string(paddr->family);
		violation(current, "%s(-1, ?:%s)", name, f ? f : "AF_???");
		break;
	}
}

static char *box_resolve_path_special(const char *abspath, pid_t tid)
{
	char *p;
	const char *tail;

	/*
	 * Special case for a couple of special files under /proc
	 */

	p = NULL;
	if (streq(abspath, "/proc/mounts")) {
		/* /proc/mounts -> /proc/$tid/mounts */
		xasprintf(&p, "/proc/%u/mounts", tid);
	} else if (startswith(abspath, "/proc/net")) {
		/* /proc/net/ -> /proc/$tid/net/ */
		tail = abspath + STRLEN_LITERAL("/proc/net");
		xasprintf(&p, "/proc/%u/net%s", tid, tail);
	} else if (startswith(abspath, "/proc/self")) {
		/* /proc/self/ -> /proc/$tid/ */
		tail = abspath + STRLEN_LITERAL("/proc/self");
		xasprintf(&p, "/proc/%u%s", tid, tail);
	}

	return p;
}

static int box_resolve_path_helper(const char *abspath, pid_t tid,
				   unsigned rmode, char **res)
{
	int r;
	char *p;

	p = box_resolve_path_special(abspath, tid);
	r = realpath_mode(p ? p : abspath, rmode, res);
	if (p)
		free(p);

	return r;
}

int box_resolve_path(const char *path, const char *prefix, pid_t tid,
		     unsigned rmode, char **res)
{
	int r;
	char *abspath;

	if (path == NULL && prefix == NULL)
		return -EINVAL;
	if (path == NULL)
		abspath = xstrdup(prefix);
	else if (prefix == NULL)
		abspath = xstrdup(path);
	else
		abspath = path_make_absolute(path, prefix);
	if (!abspath)
		return -errno;

	r = box_resolve_path_helper(abspath, tid, rmode, res);
	free(abspath);
	return r;
}

static bool box_check_access(enum sys_access_mode mode,
			     enum acl_action (*match_func)(enum acl_action defaction,
							   const aclq_t *aclq,
							   const void *needle,
							   struct acl_node **match),
			     const aclq_t *aclq_list[], size_t aclq_list_len,
			     const void *needle)
{
	size_t i;
	enum acl_action acl_mode;

	assert(match_func);
	assert(needle);

	switch (mode) {
	case ACCESS_ALLOWLIST: /* deny by default, allowlist entries */
		acl_mode = ACL_ACTION_ALLOWLIST;
		break;
	case ACCESS_DENYLIST: /* allow by default, denylist entries */
		acl_mode = ACL_ACTION_DENYLIST;
		break;
	default:
		assert_not_reached();
	}

	for (i = 0; i < aclq_list_len; i++) {
		unsigned r;
		r = match_func(acl_mode, aclq_list[i], needle, NULL);
		if (r & ACL_MATCH) {
			r &= ~ACL_MATCH_MASK;
			switch (r) {
			case ACL_ACTION_ALLOWLIST:
				return true; /* access granted */
			case ACL_ACTION_DENYLIST:
				return false; /* access denied */
			default:
				assert_not_reached();
			}
		}
	}

	/* No match */
	switch (mode) {
	case ACCESS_ALLOWLIST:
		if (!sydbox->config.allowlist_per_process_directories)
			return false; /* access denied (default) */
		else if (procmatch(&sydbox->config.proc_pid_auto, needle))
			return true; /* access granted (/proc allowlist) */
		else
			return false; /* access denied (/proc did not match) */
	case ACCESS_DENYLIST:
		return true; /* access granted (default) */
	default:
		assert_not_reached();
	}
}

static int box_check_ftype(const char *path, syscall_info_t *info)
{
	int deny_errno, stat_ret;
	short rflags = info->rmode & ~RPATH_MASK;
	struct stat buf;

	assert(info);

	if (!info->syd_mode && !info->ret_statbuf)
		return 0;

	if (info->cache_statbuf) {
		/* use cached status information */
		memcpy(&buf, info->cache_statbuf, sizeof(struct stat));
		stat_ret = 0;
	} else {
		stat_ret = rflags & RPATH_NOFOLLOW ? lstat(path, &buf)
						   : stat(path, &buf);
	}

	if (stat_ret < 0)
		return 0; /* stat() failed, TODO: are we fine returning 0? */

	if (info->ret_statbuf)
		*info->ret_statbuf = buf;

	if (!info->syd_mode)
		return 0;

	deny_errno = 0;

	/*
	 * Note: order may matter, e.g.:
	 *	rmdir($loop-symlink) -> -ELOOP (not ENOTDIR)
	 */
	if (info->syd_mode & SYD_STAT_NOEXIST) {
		/*
		 * stat() has *not* failed which means file exists.
		 */
		deny_errno = EEXIST;
	} else if (info->syd_mode & SYD_STAT_NOFOLLOW && S_ISLNK(buf.st_mode)) {
		/*
		 * System call requires a non-symlink.
		 */
		deny_errno = ELOOP;
	} else if (info->syd_mode & SYD_STAT_ISDIR && !S_ISDIR(buf.st_mode)) {
		/*
		 * System call requires a directory.
		 */
		deny_errno = ENOTDIR;
	} else if (info->syd_mode & SYD_STAT_NOTDIR && S_ISDIR(buf.st_mode)) {
		/*
		 * System call requires a non-directory.
		 */
		deny_errno = EISDIR;
	} else if (info->syd_mode & SYD_STAT_EMPTYDIR) {
		if (!S_ISDIR(buf.st_mode))
			deny_errno = ENOTDIR;
		else if (!empty_dir(path))
			deny_errno = ENOTEMPTY;
	}

	return deny_errno;
}

int box_check_path(syd_process_t *current, syscall_info_t *info)
{
	bool badfd;
	int r, deny_errno, stat_errno;
	pid_t pid;
	char *prefix, *path, *abspath;

	assert(current);
	assert(info);

	pid = current->pid;
	prefix = path = abspath = NULL;
	deny_errno = info->deny_errno ? info->deny_errno : EPERM;

	/* Step 0: check for cached abspath from a previous check */
	if (info->cache_abspath) {
		/* use cached abspath */
		prefix = path = NULL;
		abspath = (char *)info->cache_abspath;
		goto check_access;
	}

	/* Step 1: resolve file descriptor for `at' suffixed functions */
	badfd = false;
	if (info->at_func) {
		r = path_prefix(current, info->arg_index - 1, &prefix);
		if (r == -ESRCH) {
			return -ESRCH;
		} else if (r == -EBADF) {
			/* Using a bad directory for absolute paths is fine!
			 * System call will be denied after path_decode()
			 */
			badfd = true;
		} else if (r < 0) {
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
			return r;
		}
	}

	/* Step 2: read path */
	if (info->arg_index == SYSCALL_ARG_MAX) {
		/* e.g: fchdir */
		path = NULL;
	} else if ((r = path_decode(current, info->arg_index, &path)) < 0) {
		/*
		 * For EFAULT we assume path argument is NULL.
		 * For some `at' suffixed functions, NULL as path
		 * argument may be OK.
		 */
		if (r == -ESRCH) {
			goto out;
		} else if (!(r == -EFAULT && info->at_func && info->null_ok)) {
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
			goto out;
		}
	} else { /* r == 0 */
		/* Careful, we may both have a bad fd and the path may be either
		 * NULL or empty string! */
		if (badfd && (!path || !*path || !path_is_absolute(path))) {
			/* Bad directory for non-absolute path! */
			r = deny(current, EBADF);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s(`%s')",
					  current->sysname,
					  path);
			goto out;
		}
	}

	/* Step 3: resolve path */
	if ((r = box_resolve_path(path, prefix ? prefix : P_CWD(current),
				  pid, info->rmode, &abspath)) < 0) {
		r = deny(current, -r);
		if (sydbox->config.violation_raise_fail)
			violation(current, "%s(`%s')",
				  current->sysname,
				  path);
		goto out;
	}

	/* Step 4: Record absolute path for dump. */
	if (current->repr[info->arg_index])
		free(current->repr[info->arg_index]);
	current->repr[info->arg_index] = syd_strdup(abspath);
	dump(DUMP_SYSENT, current);

	/* Step 5: Check for access by prefix */
	if (info->prefix && !startswith(path, info->prefix))
		goto deny;

	/* Step 6: Check for access */
	enum sys_access_mode access_mode;
	const aclq_t *access_lists[2];
	const aclq_t *access_filter;

check_access:
	if (info->access_mode != ACCESS_0)
		access_mode = info->access_mode;
	else if (sandbox_deny_write(current) || sydbox->permissive)
		access_mode = ACCESS_ALLOWLIST;
	else
		access_mode = ACCESS_DENYLIST;

	if (info->access_list)
		access_lists[0] = info->access_list;
	else
		access_lists[0] = &P_BOX(current)->acl_write;
	access_lists[1] = info->access_list_global;

	if (box_check_access(access_mode, acl_pathmatch, access_lists, 2, abspath)) {
		r = 0;
#if ENABLE_PSYSCALL
		syd_rmem_write(current);
#endif
		goto out;
	}

	if (info->safe && !sydbox->config.violation_raise_safe) {
		/* ignore safe system call */
		r = deny(current, deny_errno);
		goto out;
	}

	/*
	 * Step 7: stat() if required (unless already cached)
	 * Note to security geeks: we ignore TOCTOU issues at various points,
	 * mostly because this is a debugging tool and there isn't a simple
	 * practical solution with ptrace(). This caching case is no exception.
	 */
	if ((stat_errno = box_check_ftype(abspath, info)) != 0) {
		deny_errno = stat_errno;
		if (!sydbox->config.violation_raise_safe) {
			/* ignore safe system call */
			r = deny(current, deny_errno);
			goto out;
		}
	}

	/* Step 8: report violation */
deny:
	r = deny(current, deny_errno);

	if (info->access_filter)
		access_filter = info->access_filter;
	else
		access_filter = &sydbox->config.filter_write;

	if (!acl_match_path(ACL_ACTION_NONE, access_filter, abspath, NULL)) {
		if (info->at_func)
			box_report_violation_path_at(current, info->arg_index,
						     path, prefix);
		else
			box_report_violation_path(current, info->arg_index, path);
	}

out:
	if (prefix)
		free(prefix);
	if (path)
		free(path);
	if (r == 0) {
		if (info->ret_abspath)
			*info->ret_abspath = abspath;
		else if (abspath && !info->cache_abspath)
			free(abspath);
	} else {
		if (abspath && !info->cache_abspath)
			free(abspath);
		if (info->ret_abspath)
			*info->ret_abspath = NULL;
	}
	return r;
}

int box_check_socket(syd_process_t *current, syscall_info_t *info)
{
	int r;
	char *abspath;
	pid_t pid;
	struct pink_sockaddr *psa;

	assert(current);
	assert(info);
	assert(info->deny_errno != 0);
	assert(info->access_mode != ACCESS_0);
	assert(info->access_list);
	assert(info->access_filter);

	pid = current->pid;
	abspath = NULL;
	psa = xmalloc(sizeof(struct pink_sockaddr));

	if ((r = syd_read_socket_address(current, info->sockaddr_in_msghdr,
					 info->arg_index, info->ret_fd,
					 psa)) < 0)
		goto out;

	/* check for supported socket family. */
	switch (psa->family) {
	case AF_UNIX:
	case AF_INET:
	case AF_INET6:
		break;
	case -1: /* NULL! */
		/*
		 * This can happen e.g. when sendto() is called with a socket in
		 * connected state:
		 *	sendto(sockfd, buf, len, flags, NULL, 0);
		 * This is also equal to calling:
		 *	send(sockfd, buf, len, flags);
		 * and we do not sandbox sockets in connected state.
		 *
		 * TODO: ENOTCONN
		 */
		r = 0;
		goto out;
	default:
		if (sydbox->config.allowlist_unsupported_socket_families) {
			/* allow unsupported socket family */
			goto out;
		}
		r = deny(current, EAFNOSUPPORT);
		goto report;
	}

	const aclq_t *access_lists[2];
	access_lists[0] = info->access_list;
	access_lists[1] = info->access_list_global;

	if (psa->family == AF_UNIX && !path_abstract(psa->u.sa_un.sun_path)) {
		/* Non-abstract UNIX socket, resolve the path. */
		r = box_resolve_path(psa->u.sa_un.sun_path,
				     P_CWD(current), pid,
				     info->rmode, &abspath);
		if (r < 0) {
			r = deny(current, -r);
			if (sydbox->config.violation_raise_fail)
				violation(current, "%s()", current->sysname);
			goto out;
		}

		if (box_check_access(info->access_mode, acl_sockmatch_saun,
				     access_lists, 2, abspath)) {
			/* access granted */
			r = 0;
			goto out;
		}
		/* access denied */
	} else {
		if (box_check_access(info->access_mode, acl_sockmatch,
				     access_lists, 2, psa)) {
			/* access granted */
			r = 0;
			goto out;
		}
		/* access denied */
	}

	if (current->repr[info->arg_index])
		free(current->repr[info->arg_index]);
	current->repr[info->arg_index] = box_name_violation_sock(current, info, psa, abspath);
	dump(DUMP_SYSENT, current);

	r = deny(current, info->deny_errno);

	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket */
		if (acl_match_saun(ACL_ACTION_NONE, info->access_filter, abspath, NULL)) {
			/* access violation filtered */
			goto out;
		}
	} else {
		if (acl_match_sock(ACL_ACTION_NONE, info->access_filter, psa, NULL)) {
			/* access violation filtered */
			goto out;
		}
	}

report:
	box_report_violation_sock(current, info, psa);

out:
	if (r == 0) {
		/* Access granted. */
		if (info->ret_abspath)
			*info->ret_abspath = abspath;
		else if (abspath && !info->cache_abspath)
			free(abspath);

		if (info->ret_addr)
			*info->ret_addr = psa;
		else
			free(psa);
	} else {
		free(psa);
		if (abspath && !info->cache_abspath)
			free(abspath);
		if (info->ret_abspath)
			*info->ret_abspath = NULL;
		if (info->ret_addr)
			*info->ret_addr = NULL;
	}

	return r;
}
