/*
 * sydbox/syscall-sock.c
 *
 * Socket related system call handlers
 *
 * Copyright (c) 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Distributed under the terms of the GNU General Public License v3 or later
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
#include <pinktrace/pink.h>
#include "canonicalize.h"
#include "log.h"

int sys_bind(syd_proc_t *current)
{
	int r;
	unsigned long fd;
	char *unix_abspath;
	struct pink_sockaddr *psa;
	sysinfo_t info;

	if (sandbox_network_off(current))
		return 0;

	init_sysinfo(&info);
	info.arg_index = 1;
	info.can_mode = CAN_ALL_BUT_LAST;
	info.deny_errno = EADDRNOTAVAIL;
	if (current->subcall == PINK_SOCKET_SUBCALL_BIND)
		info.decode_socketcall = true;
	if (sandbox_network_deny(current)) {
		info.access_mode = ACCESS_WHITELIST;
		info.access_list = &current->config.whitelist_network_bind;
	} else {
		info.access_mode = ACCESS_BLACKLIST;
		info.access_list = &current->config.blacklist_network_bind;
	}
	info.access_filter = &sydbox->config.filter_network;

	if (sydbox->config.whitelist_successful_bind) {
		info.ret_abspath = &unix_abspath;
		info.ret_addr = &psa;
	}

	r = box_check_socket(current, &info);

	if (r == 0 && sydbox->config.whitelist_successful_bind) {
		/* Access granted.
		 * Read the file descriptor, for use in exit.
		 */
		r = syd_read_socket_argument(current, info.decode_socketcall,
					     0, &fd);
		if (r < 0)
			return r;
		current->args[0] = fd;

		switch (psa->family) {
		case AF_UNIX:
		case AF_INET:
#if SYDBOX_HAVE_IPV6
		case AF_INET6:
#endif /* SYDBOX_HAVE_IPV6 */
			current->savebind = xmalloc(sizeof(struct sockinfo));
			current->savebind->path = unix_abspath;
			current->savebind->addr = psa;
			/* fall through */
		default:
			return 0;
		}
	}

	if (sydbox->config.whitelist_successful_bind) {
		if (unix_abspath)
			free(unix_abspath);
		if (psa)
			free(psa);
	}

	return 0;
}

int sysx_bind(syd_proc_t *current)
{
	int r;
	long retval;
	struct snode *snode;
	ht_int64_node_t *node;
	struct sockmatch *match;

	if (sandbox_network_off(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    !current->savebind)
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		log_trace("ignoring failed system call");
		free_sockinfo(current->savebind);
		current->savebind = NULL;
		return 0;
	}

	/* check for bind() with zero as port argument */
	if (current->savebind->addr->family == AF_INET &&
	    current->savebind->addr->u.sa_in.sin_port == 0)
		goto zero;
#if SYDBOX_HAVE_IPV6
	if (current->savebind->addr->family == AF_INET6 &&
	    current->savebind->addr->u.sa6.sin6_port == 0)
		goto zero;
#endif

	log_trace("whitelisting socket address");
	snode = xcalloc(1, sizeof(struct snode));
	match = sockmatch_new(current->savebind);
	snode->data = match;
	SLIST_INSERT_HEAD(&sydbox->config.whitelist_network_connect_auto, snode, up);
	return 0;
zero:
	node = hashtable_find(current->sockmap, current->args[0] + 1, 1);
	if (!node)
		die_errno("hashtable_find");
	node->data = current->savebind;
	current->savebind = NULL;
	return 0;
}

int sys_connect(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_network_off(current))
		return 0;

	init_sysinfo(&info);
	info.access_mode = sandbox_network_deny(current)
			   ? ACCESS_WHITELIST
			   : ACCESS_BLACKLIST;
	info.access_list = sandbox_network_deny(current)
			   ? &current->config.whitelist_network_connect
			   : &current->config.blacklist_network_connect;
	info.access_list_global = &sydbox->config.whitelist_network_connect_auto;
	info.access_filter = &sydbox->config.filter_network;
	info.can_mode = CAN_ALL_BUT_LAST;
	info.arg_index = 1;
	info.deny_errno = ECONNREFUSED;
	if (current->subcall == PINK_SOCKET_SUBCALL_CONNECT)
		info.decode_socketcall = true;

	return box_check_socket(current, &info);
}

int sys_sendto(syd_proc_t *current)
{
	sysinfo_t info;

	if (sandbox_network_off(current))
		return 0;

	init_sysinfo(&info);
	info.access_mode = sandbox_network_deny(current)
			   ? ACCESS_WHITELIST
			   : ACCESS_BLACKLIST;
	info.access_list = sandbox_network_deny(current)
			   ? &current->config.whitelist_network_connect
			   : &current->config.blacklist_network_connect;
	info.access_list_global = &sydbox->config.whitelist_network_connect_auto;
	info.access_filter = &sydbox->config.filter_network;
	info.can_mode = CAN_ALL_BUT_LAST;
	info.arg_index = 4;
	info.deny_errno = ECONNREFUSED;
	if (current->subcall == PINK_SOCKET_SUBCALL_SENDTO)
		info.decode_socketcall = true;

	return box_check_socket(current, &info);
}

int sys_getsockname(syd_proc_t *current)
{
	int r;
	bool decode_socketcall;
	unsigned long fd;

	if (sandbox_network_off(current) ||
	    !sydbox->config.whitelist_successful_bind)
		return 0;

	decode_socketcall = !!(current->subcall == PINK_SOCKET_SUBCALL_GETSOCKNAME);
	if ((r = syd_read_socket_argument(current, decode_socketcall, 0, &fd)) < 0)
		return r;

	ht_int64_node_t *node = hashtable_find(current->sockmap, fd + 1, 0);
	if (node)
		current->args[0] = fd;

	return 0;
}

int sysx_getsockname(syd_proc_t *current)
{
	int r;
	bool decode_socketcall;
	unsigned port;
	long retval;
	struct pink_sockaddr psa;
	struct snode *snode;

	if (sandbox_network_off(current) ||
	    !sydbox->config.whitelist_successful_bind ||
	    !current->args[0])
		return 0;

	if ((r = syd_read_retval(current, &retval, NULL)) < 0)
		return r;

	if (retval < 0) {
		log_trace("ignoring failed system call");
		return 0;
	}

	decode_socketcall = !!(current->subcall == PINK_SOCKET_SUBCALL_GETSOCKNAME);
	if ((r = syd_read_socket_address(current, decode_socketcall, 1, NULL, &psa)) < 0)
		return r;

	ht_int64_node_t *node = hashtable_find(current->sockmap,
					       current->args[0] + 1, 0);
	assert(node);
	struct sockinfo *info = node->data;
	struct sockmatch *match = sockmatch_new(info);

	free_sockinfo(info);
	node->key = 0;
	node->data = NULL;

	switch (match->family) {
	case AF_INET:
		port = ntohs(psa.u.sa_in.sin_port);
		/* assert(port); */
		match->addr.sa_in.port[0] = match->addr.sa_in.port[1] = port;
		break;
#if SYDBOX_HAVE_IPV6
	case AF_INET6:
		port = ntohs(psa.u.sa6.sin6_port);
		/* assert(port); */
		match->addr.sa6.port[0] = match->addr.sa6.port[1] = port;
		break;
#endif
	default:
		assert_not_reached();
	}

	log_trace("whitelisting bind(port:0->%u) for connect()", port);
	snode = xcalloc(1, sizeof(struct snode));
	snode->data = match;
	SLIST_INSERT_HEAD(&sydbox->config.whitelist_network_connect_auto, snode, up);
	return 0;
}

int sys_socketcall(syd_proc_t *current)
{
	int r;
	long subcall;

	if (sandbox_network_off(current))
		return 0;

	if ((r = syd_read_socket_subcall(current, true, &subcall)) < 0)
		return r;

	current->subcall = subcall;

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

int sysx_socketcall(syd_proc_t *current)
{
	if (sandbox_network_off(current))
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