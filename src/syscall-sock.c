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
		info.access_mode = ACCESS_WHITELIST;
	else
		info.access_mode = ACCESS_BLACKLIST;
	info.access_list = &P_BOX(current)->acl_network_bind;
	info.access_filter = &sydbox->config.filter_network;

	if (sydbox->config.whitelist_successful_bind) {
		info.ret_abspath = &unix_abspath;
		info.ret_addr = &psa;
	}

	r = box_check_socket(current, &info);
	if (r < 0)
		goto out;
	if (sydbox->config.whitelist_successful_bind && psa &&
	    (psa->family == AF_UNIX || psa->family == AF_INET
#if PINK_HAVE_IPV6
	     || psa->family == AF_INET6
#endif
	    )) {
		/* Access granted.
		 * Read the file descriptor, for use in exit.
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
	}

out:
	if (sydbox->config.whitelist_successful_bind) {
		if (unix_abspath)
			free(unix_abspath);
		if (psa)
			free(psa);
	}

	return r;
}

static int sys_connect_or_sendto(syd_process_t *current, unsigned arg_index)
{
	syscall_info_t info;

#define sub_connect(p, i)	((i) == 1 && \
				 (p)->subcall == PINK_SOCKET_SUBCALL_CONNECT)
#define sub_sendto(p, i)	((i) == 4 && \
				 (p)->subcall == PINK_SOCKET_SUBCALL_SENDTO)

	if (sandbox_off_network(current))
		return 0;

	init_sysinfo(&info);
	if (sandbox_deny_network(current) || sydbox->permissive)
		info.access_mode = ACCESS_WHITELIST;
	else
		info.access_mode = ACCESS_BLACKLIST;
	info.access_list = &P_BOX(current)->acl_network_connect;
	info.access_list_global = &sydbox->config.acl_network_connect_auto;
	info.access_filter = &sydbox->config.filter_network;
	info.rmode = RPATH_NOLAST;
	info.arg_index = arg_index;
	info.deny_errno = ECONNREFUSED;
	if (sub_connect(current, arg_index) || sub_sendto(current, arg_index))
		info.decode_socketcall = true;
#undef sub_connect
#undef sub_sendto

	return box_check_socket(current, &info);
}

int sys_connect(syd_process_t *current)
{
	return sys_connect_or_sendto(current, 1);
}

int sys_sendto(syd_process_t *current)
{
	return sys_connect_or_sendto(current, 4);
}

int sys_accept(syd_process_t *current)
{
	int r, port;
	unsigned long long inode;
	const struct sockinfo *info;
	struct sockmatch *match;

	if (sandbox_off_network(current) ||
	    !sydbox->config.whitelist_successful_bind)
		return 0;

	if ((r = proc_socket_inode(current->pid,
				   current->args[0],
				   &inode)) < 0)
		return r;

	info = sockmap_find(&P_SOCKMAP(current), inode);
	if (!info)
		return 0;
	match = sockmatch_new(info);

	switch (match->family) {
	case AF_UNIX:
		break;
	case AF_INET:
		port = ntohs(info->addr->u.sa_in.sin_port);
		if (!port && (r = proc_socket_port(inode, true, &port)) < 0)
			return 0;
		match->addr.sa_in.port[0] = match->addr.sa_in.port[1] = port;
		break;
	case AF_INET6:
		port = ntohs(info->addr->u.sa6.sin6_port);
		if (!port && (r = proc_socket_port(inode, false, &port)) < 0)
			return 0;
		match->addr.sa6.port[0] = match->addr.sa6.port[1] = port;
		break;
	default:
		assert_not_reached();
	}
	sockmap_remove(&P_SOCKMAP(current), inode);

	/* whitelist bind(0 -> port) for connect() */
	struct acl_node *node;
	node = xcalloc(1, sizeof(struct acl_node));
	node->action = ACL_ACTION_WHITELIST;
	node->match = match;
	ACLQ_INSERT_TAIL(&sydbox->config.acl_network_connect_auto, node);

	return 0;
}

int sys_socketcall(syd_process_t *current)
{
	int r;
	long subcall;

	if (sandbox_off_network(current))
		return 0;

	if ((r = syd_read_socket_subcall(current, &subcall)) < 0)
		return r;

	current->subcall = subcall;
	current->sysname = pink_name_socket_subcall(subcall);

	switch (subcall) {
	case PINK_SOCKET_SUBCALL_BIND:
		return sys_bind(current);
	case PINK_SOCKET_SUBCALL_CONNECT:
		return sys_connect(current);
	case PINK_SOCKET_SUBCALL_SENDTO:
		return sys_sendto(current);
	case PINK_SOCKET_SUBCALL_ACCEPT:
	case PINK_SOCKET_SUBCALL_ACCEPT4:
		return sys_accept(current);
	default:
		return 0;
	}
}

#if 0
int sysx_socketcall(syd_process_t *current)
{
	if (sandbox_off_network(current))
		return 0;

	switch (current->subcall) {
	case PINK_SOCKET_SUBCALL_BIND:
		return sysx_bind(current);
	case PINK_SOCKET_SUBCALL_GETSOCKNAME:
		return sysx_getsockname(current);
	default:
		return 0;
	}
}
#endif
