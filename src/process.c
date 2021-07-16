/*
 * sydbox/process.c
 *
 * Syd's Process Utilities
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-box.h"
#include <sys/mman.h>

SYD_GCC_ATTR((nonnull(1)))
int sandbox_protect(sandbox_t *box, int prot)
{
	return syd_mprotect(box, sizeof(sandbox_t), prot);
}

SYD_GCC_ATTR((nonnull(1)))
void init_sandbox(sandbox_t *box)
{
	/* Be paranoid */
	box->mode.sandbox_exec = SANDBOX_BPF;
	box->mode.sandbox_read = SANDBOX_BPF;
	box->mode.sandbox_write = SANDBOX_BPF;
	box->mode.sandbox_network = SANDBOX_BPF;

	box->magic_lock = LOCK_UNSET;

	ACLQ_INIT(&box->acl_exec);
	ACLQ_INIT(&box->acl_read);
	ACLQ_INIT(&box->acl_write);
	ACLQ_INIT(&box->acl_network_bind);
	ACLQ_INIT(&box->acl_network_connect);
}

SYD_GCC_ATTR((nonnull(1)))
inline void copy_sandbox(sandbox_t *box_dest, sandbox_t *box_src)
{
	struct acl_node *node, *newnode;

	if (!box_src)
		return;

	box_dest->mode.sandbox_exec = box_src->mode.sandbox_exec;
	box_dest->mode.sandbox_read = box_src->mode.sandbox_read;
	box_dest->mode.sandbox_write = box_src->mode.sandbox_write;
	box_dest->mode.sandbox_network = box_src->mode.sandbox_network;

	box_dest->magic_lock = box_src->magic_lock;

	if (ACLQ_FIRST(&box_dest->acl_read) &&
	    !ACLQ_EMPTY(&box_src->acl_read))
		ACLQ_COPY(node,
			  &box_src->acl_read, &box_dest->acl_read,
			  newnode, xstrdup);
	if (ACLQ_FIRST(&box_dest->acl_write) &&
	    !ACLQ_EMPTY(&box_src->acl_write)) {
		ACLQ_COPY(node,
			  &box_src->acl_write, &box_dest->acl_write,
			  newnode, xstrdup);
	}
	if (ACLQ_FIRST(&box_dest->acl_network_bind) &&
	    !ACLQ_EMPTY(&box_src->acl_network_bind))
		ACLQ_COPY(node, &box_src->acl_network_bind,
			  &box_dest->acl_network_bind, newnode, sockmatch_xdup);
	if (ACLQ_FIRST(&box_dest->acl_network_connect) &&
	    !ACLQ_EMPTY(&box_src->acl_network_connect))
		ACLQ_COPY(node, &box_src->acl_network_connect,
			  &box_dest->acl_network_connect, newnode, sockmatch_xdup);
}

inline void reset_sandbox(sandbox_t *box)
{
	struct acl_node *node;

	if (box->acl_exec.tqh_last)
		ACLQ_RESET(node, &box->acl_exec, free);
	if (box->acl_read.tqh_last)
		ACLQ_RESET(node, &box->acl_read, free);
	if (box->acl_write.tqh_last)
		ACLQ_RESET(node, &box->acl_write, free);
	if (box->acl_network_bind.tqh_last)
		ACLQ_RESET(node, &box->acl_network_bind, free_sockmatch);
	if (box->acl_network_connect.tqh_last)
		ACLQ_RESET(node, &box->acl_network_connect, free_sockmatch);
}

inline int new_sandbox(sandbox_t **box_ptr)
{
	sandbox_t *box;

	box = syd_malloc(sizeof(sandbox_t));
	if (!box)
		return -errno;
	init_sandbox(box);

	*box_ptr = box;
	return 0;
}

inline void free_sandbox(sandbox_t *box)
{
	reset_sandbox(box);
	free(box);
}

inline char sandbox_mode_toc(enum sandbox_mode mode)
{
	switch (mode) {
	case SANDBOX_OFF:
		return '_';
	case SANDBOX_BPF:
		return '!';
	case SANDBOX_DENY:
		return '*';
	case SANDBOX_ALLOW:
		return '^';
	default:
		assert_not_reached();
	}
}

inline unsigned short pack_clone_flags(long clone_flags)
{
	unsigned short f = 0;

	if (clone_flags & CLONE_THREAD)
		f |= SYD_CLONE_THREAD;
	if (clone_flags & CLONE_FS)
		f |= SYD_CLONE_FS;
	if (clone_flags & CLONE_FILES)
		f |= SYD_CLONE_FILES;

	return f;
}

inline bool use_notify(void)
{
	if (sydbox->bpf_only)
		return false;

	sandbox_t *box = box_current(NULL);
	enum sandbox_mode mode[] = {
		box->mode.sandbox_read,
		box->mode.sandbox_write,
		box->mode.sandbox_exec,
		box->mode.sandbox_network,
	};

	for (unsigned short i = 0; i < ELEMENTSOF(mode); i++) {
		switch (mode[i]) {
		case SANDBOX_ALLOW:
		case SANDBOX_DENY:
			return true;
		default:
			continue;
		}
	}

	return false;
}

inline uint32_t process_count(void)
{
	return syd_map_size_64v(&sydbox->tree);
}

inline void process_add(syd_process_t *p)
{
	syd_map_put_64v(&sydbox->tree, p->pid, p);
}

inline void process_remove(syd_process_t *p)
{
	syd_map_del_64v(&sydbox->tree, p->pid);
}

inline syd_process_t *process_lookup(pid_t pid)
{
	syd_process_t *p = syd_map_get_64v(&sydbox->tree, pid);
	if (syd_map_found(&sydbox->tree))
		return p;
	return NULL;
}

static char comm[16];
char *process_comm(syd_process_t *p, const char *arg0)
{
	size_t i = 0;
	char *bname = basename(arg0);

	strlcpy(comm + i, bname, strlen(bname) + 1);
	return comm;
#if 0
	sandbox_t *box = box_current(p);
	switch (box->magic_lock) {
	case LOCK_UNSET:
		comm[i++] = '@';
		break;
	case LOCK_PENDING:
		comm[i++] = '#';
		break;
	case LOCK_SET:
		comm[i++] = '*';
		break;
	default:
		assert_not_reached();
	}
	comm[i++] = sandbox_mode_toc(box->mode.sandbox_read);
	comm[i++] = sandbox_mode_toc(box->mode.sandbox_write);
	comm[i++] = sandbox_mode_toc(box->mode.sandbox_exec);
	comm[i++] = sandbox_mode_toc(box->mode.sandbox_network);
#endif
#if 0
	strlcpy(comm + i, basename(arg0), 6);
	if (sydbox->hash[0]) {
		strlcpy(comm + (i + 4), sydbox->hash, 7);
		comm[15] = '\0';
	} else {
		strlcpy(comm + (i + 4), "?syd", sizeof("?syd"));
	}
#endif
}
