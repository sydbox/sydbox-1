/*
 * sydbox/syscall-sock.c
 *
 * Socket related system call handlers
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015, 2018, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydbox.h"
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include "pink.h"
#include "bsd-compat.h"
#include "sockmap.h"
#include "dump.h"
#include "proc.h"

static uint32_t action_simple(int deny_errno, enum sandbox_mode mode)
{
	switch (mode) {
	case SANDBOX_OFF:
		return SCMP_ACT_ALLOW;
	case SANDBOX_BPF:
		return SCMP_ACT_ERRNO(deny_errno);
	case SANDBOX_ALLOW:
		return use_notify() ? SCMP_ACT_NOTIFY : SCMP_ACT_ALLOW;
	case SANDBOX_DENY:
		return use_notify() ? SCMP_ACT_NOTIFY
			: SCMP_ACT_ERRNO(deny_errno);
	default:
		assert_not_reached();
	}
}
static int filter_sock_simple(long sys_num, int deny_errno,
			      enum sandbox_mode mode)
{
	int r;
	uint32_t action = action_simple(deny_errno, mode);

	if (action == sydbox->seccomp_action)
		return 0;

	syd_rule_add_return(sydbox->ctx, action, sys_num, 0);
	return 0;
}

int filter_bind(uint32_t arch)
{
	int r;
	enum sandbox_mode mode = sydbox->config.box_static.mode.sandbox_network;

	if ((r = filter_sock_simple(SCMP_SYS(bind), EADDRNOTAVAIL, mode)) < 0)
		return r;

	return 0;
}

int sys_bind(syd_process_t *current)
{
	int r;
	unsigned long fd;
	char *unix_abspath = NULL;
	struct pink_sockaddr *psa = NULL;
	syscall_info_t info;

	if (sandbox_off_network(current))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;
	info.rmode = RPATH_NOLAST;
	info.deny_errno = EADDRNOTAVAIL;
	if (sandbox_deny_network(current) || sydbox->permissive)
		info.access_mode = ACCESS_ALLOWLIST;
	else
		info.access_mode = ACCESS_DENYLIST;
	info.access_list = &P_BOX(current)->acl_network_bind;
	info.access_filter = &sydbox->config.filter_network;

	if (sydbox->config.allowlist_successful_bind) {
		info.ret_abspath = &unix_abspath;
		info.ret_addr = &psa;
	}

	r = box_check_socket(current, &info);
	if (r < 0)
		goto out;
	if (!sydbox->config.allowlist_successful_bind || !psa)
		goto out;
	if (psa->family != AF_UNIX && psa->family != AF_INET &&
	    psa->family != AF_INET6)
		goto out;

	/*
	 * Access granted.
	 * Read the inode for use in listen() or accept().
	 */
	unsigned long long inode;

	r = syd_read_socket_argument(current, 0, &fd);
	if (r < 0)
		goto out;
	if ((r = proc_socket_inode(current->pid,
				   current->args[0], &inode)) < 0)
		goto out;

	struct sockinfo *si = xmalloc(sizeof(struct sockinfo));
	si->path = unix_abspath;
	si->addr = psa;
	sockmap_add(&P_SOCKMAP(current), inode, si);
	return 0;
out:
	if (sydbox->config.allowlist_successful_bind) {
		if (unix_abspath)
			free(unix_abspath);
		if (psa)
			free(psa);
	}

	return r;
}

static int filter_connect_call(int sysnum, int deny_errno)
{
	int r;
	enum sandbox_mode mode = sydbox->config.box_static.mode.sandbox_network;

	if ((r = filter_sock_simple(sysnum, deny_errno, mode)) < 0)
		return r;
	return 0;
}

static int sys_connect_call(syd_process_t *current, bool sockaddr_in_msghdr,
			    long sysnum, unsigned arg_index, int deny_errno)
{
	syscall_info_t info;

#define sub_connect(p, i)	((i) == 1 && \
				 (sysnum) == SCMP_SYS(connect))
#define sub_recvmsg(p, i)	((i) == 1 && \
				 (sysnum) == SCMP_SYS(recvmsg))
#define sub_sendmsg(p, i)	((i) == 1 && \
				 (sysnum) == SCMP_SYS(sendmsg))
#define sub_sendto(p, i)	((i) == 4 && \
				 (sysnum) == SCMP_SYS(sendto))

	if (sandbox_off_network(current))
		return 0;

	init_sysinfo(&info);
	if (sandbox_deny_network(current) || sydbox->permissive)
		info.access_mode = ACCESS_ALLOWLIST;
	else
		info.access_mode = ACCESS_DENYLIST;
	info.access_list = &P_BOX(current)->acl_network_connect;
	info.access_list_global = &sydbox->config.acl_network_connect_auto;
	info.access_filter = &sydbox->config.filter_network;
	info.rmode = RPATH_NOLAST;
	info.arg_index = arg_index;
	info.deny_errno = deny_errno;
	if (sub_connect(current, arg_index) || sub_sendto(current, arg_index) ||
	    sub_recvmsg(current, arg_index) || sub_sendmsg(current, arg_index))
		info.decode_socketcall = true;
#undef sub_connect
#undef sub_sendto
	info.sockaddr_in_msghdr = sockaddr_in_msghdr;

	return box_check_socket(current, &info);
}

static int sys_socket_inode_lookup(syd_process_t *current, bool read_net_tcp)
{
	int r, port;
	unsigned long long inode;
	const struct sockinfo *info;
	struct sockmatch *match;

	if (sandbox_off_network(current) ||
	    !sydbox->config.allowlist_successful_bind)
		return 0;

	if ((r = proc_socket_inode(current->pid,
				   current->args[0],
				   &inode)) < 0)
		return r;

	info = sockmap_find(&P_SOCKMAP(current), inode);
	if (!info)
		return 0;

	switch (info->addr->family) {
	case AF_UNIX:
		match = sockmatch_new(info);
		break;
	case AF_INET:
		port = ntohs(info->addr->u.sa_in.sin_port);
		/* allowlist bind(0 -> port) for connect() */
		if (!port &&
		    (!read_net_tcp || proc_socket_port(inode, true,
						       &port) < 0))
			return 0;
		match = sockmatch_new(info);
		match->addr.sa_in.port[0] = match->addr.sa_in.port[1] = port;
		break;
	case AF_INET6:
		port = ntohs(info->addr->u.sa6.sin6_port);
		/* allowlist bind(0 -> port) for connect() */
		if (!port &&
		    (!read_net_tcp || proc_socket_port(inode, false,
						       &port) < 0))
			return 0;
		match = sockmatch_new(info);
		match->addr.sa6.port[0] = match->addr.sa6.port[1] = port;
		break;
	default:
		assert_not_reached();
	}
	sockmap_remove(&P_SOCKMAP(current), inode);

	/* allowlist successful bind. */
	struct acl_node *node;
	node = xcalloc(1, sizeof(struct acl_node));
	node->action = ACL_ACTION_ALLOWLIST;
	node->match = match;
	ACLQ_INSERT_TAIL(&sydbox->config.acl_network_connect_auto, node);

	return 0;
}

int filter_connect(uint32_t arch)
{
	return filter_connect_call(SCMP_SYS(connect), ECONNREFUSED);
}

int sys_connect(syd_process_t *current)
{
	return sys_connect_call(current, false, SCMP_SYS(connect),
				1, ECONNREFUSED);
}

int filter_sendto(uint32_t arch)
{
	return filter_connect_call(SCMP_SYS(sendto), ENOTCONN);
}

int sys_sendto(syd_process_t *current)
{
	return sys_connect_call(current, false, SCMP_SYS(sendto), 4, ENOTCONN);
}

int filter_recvmsg(uint32_t arch)
{
	return filter_connect_call(SCMP_SYS(recvmsg), ECONNREFUSED);
}

int sys_recvmsg(syd_process_t *current)
{
	return sys_connect_call(current, true, SCMP_SYS(recvmsg),
				1, ECONNREFUSED);
}

int filter_sendmsg(uint32_t arch)
{
	return filter_connect_call(SCMP_SYS(sendmsg), ENOTCONN);
}

int sys_sendmsg(syd_process_t *current)
{
	return sys_connect_call(current, true, SCMP_SYS(sendmsg), 1, ENOTCONN);
}

int sys_listen(syd_process_t *current)
{
	return sys_socket_inode_lookup(current, false);
}

int sys_accept(syd_process_t *current)
{
	return sys_socket_inode_lookup(current, true);
}

int sys_getsockname(syd_process_t *current)
{
	return sys_socket_inode_lookup(current, true);
}
