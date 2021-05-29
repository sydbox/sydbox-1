/*
 * sydbox/syscall-sock.c
 *
 * Socket related system call handlers
 *
 * Copyright (c) 2011, 2012, 2013, 2014, 2015, 2018, 2021 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the 3-clause BSD license
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

int sys_bind(syd_process_t *current)
{
	int r;
	unsigned long fd;
	char *unix_abspath = NULL;
	struct pink_sockaddr *psa = NULL;
	sysinfo_t info;

	if (sandbox_off_network(current))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;
	info.rmode = RPATH_NOLAST;
	info.deny_errno = EADDRNOTAVAIL;
	if (current->subcall == PINK_SOCKET_SUBCALL_BIND)
		info.decode_socketcall = true;
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
		r = syd_read_socket_argument(current, info.decode_socketcall, 0, &fd);
		if (r < 0)
			goto out;
		current->args[0] = fd;
		P_SAVEBIND(current) = xmalloc(sizeof(struct sockinfo));
		P_SAVEBIND(current)->path = unix_abspath;
		P_SAVEBIND(current)->addr = psa;
		current->flags |= SYD_STOP_AT_SYSEXIT;
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

int sysx_bind(syd_process_t *current)
{
	int r;
	long retval;
	struct acl_node *node;
	struct sockmatch *match;

	if (sandbox_off_network(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    !P_SAVEBIND(current))
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		/* ignore failed system call */
		free_sockinfo(P_SAVEBIND(current));
		P_SAVEBIND(current) = NULL;
		return 0;
	}

	/* check for bind() with zero as port argument */
	if (P_SAVEBIND(current)->addr->family == AF_INET &&
	    P_SAVEBIND(current)->addr->u.sa_in.sin_port == 0)
		goto zero;
#if PINK_HAVE_IPV6
	if (P_SAVEBIND(current)->addr->family == AF_INET6 &&
	    P_SAVEBIND(current)->addr->u.sa6.sin6_port == 0)
		goto zero;
#endif

	/* whitelist socket address */
	node = xcalloc(1, sizeof(struct acl_node));
	match = sockmatch_new(P_SAVEBIND(current));
	node->action = ACL_ACTION_WHITELIST;
	node->match = match;
	ACLQ_INSERT_TAIL(&sydbox->config.acl_network_connect_auto, node);
	return 0;
zero:
	/* save sockfd with port 0 for whitelisting */
	sockmap_add(&P_SOCKMAP(current), current->args[0], P_SAVEBIND(current));
	P_SAVEBIND(current) = NULL;
	return 0;
}

static int sys_connect_or_sendto(syd_process_t *current, unsigned arg_index)
{
	sysinfo_t info;

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

int sys_getsockname(syd_process_t *current)
{
	int r;
	bool decode_socketcall;
	unsigned long fd;

	current->args[0] = -1;

	if (sandbox_off_network(current) ||
	    !sydbox->config.whitelist_successful_bind)
		return 0;

	decode_socketcall = !!(current->subcall == PINK_SOCKET_SUBCALL_GETSOCKNAME);
	if ((r = syd_read_socket_argument(current, decode_socketcall, 0, &fd)) < 0)
		return r;

	if (sockmap_find(&P_SOCKMAP(current), fd)) {
		current->args[0] = fd;
		current->flags |= SYD_STOP_AT_SYSEXIT;
	}

	return 0;
}

int sysx_getsockname(syd_process_t *current)
{
	int r;
	bool decode_socketcall;
	unsigned port;
	long retval;
	struct pink_sockaddr psa;
	struct acl_node *node;
	const struct sockinfo *info;
	struct sockmatch *match;

	if (sandbox_off_network(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    current->args[0] < 0)
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		/* ignore failed system call */
		return 0;
	}

	decode_socketcall = !!(current->subcall == PINK_SOCKET_SUBCALL_GETSOCKNAME);
	if ((r = syd_read_socket_address(current, decode_socketcall, 1, NULL, &psa)) < 0) {
		return r;
	}

	info = sockmap_find(&P_SOCKMAP(current), current->args[0]);
	assert(info);
	match = sockmatch_new(info);
	sockmap_remove(&P_SOCKMAP(current), current->args[0]);

	switch (match->family) {
	case AF_INET:
		port = ntohs(psa.u.sa_in.sin_port);
		/* assert(port); */
		match->addr.sa_in.port[0] = match->addr.sa_in.port[1] = port;
		break;
#if PINK_HAVE_IPV6
	case AF_INET6:
		port = ntohs(psa.u.sa6.sin6_port);
		/* assert(port); */
		match->addr.sa6.port[0] = match->addr.sa6.port[1] = port;
		break;
#endif
	default:
		assert_not_reached();
	}

	/* whitelist bind(0 -> port) for connect() */
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

	if ((r = syd_read_socket_subcall(current, true, &subcall)) < 0)
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
	case PINK_SOCKET_SUBCALL_GETSOCKNAME:
		return sys_getsockname(current);
	default:
		return 0;
	}
}

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
