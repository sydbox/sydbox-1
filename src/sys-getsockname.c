/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Sydbox. sydbox is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * sydbox is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "sydbox-defs.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"

int sys_getsockname(struct pink_easy_process *current, PINK_GCC_ATTR((unused)) const char *name)
{
	bool decode_socketcall;
	long fd;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data) || !sydbox->config.whitelist_successful_bind)
		return 0;

	decode_socketcall = !!(data->subcall == PINK_SOCKET_SUBCALL_GETSOCKNAME);
	if (!pink_read_socket_argument(tid, abi, data->regs,
				decode_socketcall, 0, &fd)) {
		if (errno != ESRCH) {
			warning("pink_read_socket_argument(%lu, %d, %s, 0) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					decode_socketcall ? "true" : "false",
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	ht_int64_node_t *node = hashtable_find(data->sockmap, fd + 1, 0);
	if (node)
		data->args[0] = fd;

	return 0;
}

int sysx_getsockname(struct pink_easy_process *current, PINK_GCC_ATTR((unused)) const char *name)
{
	bool decode_socketcall;
	unsigned port;
	long retval;
	struct pink_sockaddr psa;
	struct snode *snode;
	sock_match_t *m;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_network_off(data) || !sydbox->config.whitelist_successful_bind || !data->args[0])
		return 0;

	/* Check the return value */
	if (!pink_read_retval(tid, abi, data->regs, &retval, NULL)) {
		if (errno != ESRCH) {
			warning("pink_read_retval(%lu, %d) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (retval == -1) {
		debug("ignoring failed %s() call for process:%lu"
				" [abi:%d name:\"%s\" cwd:\"%s\"]",
				name, (unsigned long)tid, abi,
				data->comm, data->cwd);
		return 0;
	}

	decode_socketcall = !!(data->subcall == PINK_SOCKET_SUBCALL_GETSOCKNAME);
	if (!pink_read_socket_address(tid, abi, data->regs,
				decode_socketcall,
				0, NULL, &psa)) {
		if (errno != ESRCH) {
			warning("pink_read_socket_address(%lu, %d, %s, 0): %d(%s)",
					(unsigned long)tid, abi,
					decode_socketcall ? "true" : "false",
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	ht_int64_node_t *node = hashtable_find(data->sockmap, data->args[0] + 1, 0);
	assert(node);
	sock_info_t *info = node->data;
	sock_match_new_pink(info, &m);

	free_sock_info(info);
	node->key = 0;
	node->data = NULL;

	switch (m->family) {
	case AF_INET:
		port = ntohs(psa.u.sa_in.sin_port);
		/* assert(port); */
		m->match.sa_in.port[0] = m->match.sa_in.port[1] = port;
		break;
#if SYDBOX_HAVE_IPV6
	case AF_INET6:
		port = ntohs(psa.u.sa6.sin6_port);
		/* assert(port); */
		m->match.sa6.port[0] = m->match.sa6.port[1] = port;
		break;
#endif
	default:
		abort();
	}

	snode = xcalloc(1, sizeof(struct snode));
	snode->data = m;
	SLIST_INSERT_HEAD(&data->config.whitelist_network_connect, snode, up);
	return 0;
}
