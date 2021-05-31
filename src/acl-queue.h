/*
 * sydbox/acl-queue.h
 *
 * ACL queue for sydbox based on TAILQ from <sys/queue.h>
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef ACL_QUEUE_H
#define ACL_QUEUE_H

#include <stdlib.h>
#include "sys-queue.h"
#include "sockmatch.h"
#include "util.h"

enum acl_match {
	ACL_NOMATCH = 0,
	ACL_MATCH = 1,
};
#define ACL_MATCH_MASK (ACL_MATCH | ACL_NOMATCH)

enum acl_action {
	ACL_ACTION_NONE = 2,
	ACL_ACTION_WHITELIST = 4,
	ACL_ACTION_BLACKLIST = 8,
};
static const char *const acl_action_table[] = {
	[ACL_ACTION_NONE] = "none",
	[ACL_ACTION_WHITELIST] = "whitelist",
	[ACL_ACTION_BLACKLIST] = "blacklist",
};
DEFINE_STRING_TABLE_LOOKUP(acl_action, int)

struct acl_node {
	TAILQ_ENTRY(acl_node) link;
	void *match;
	enum acl_action action;
};
TAILQ_HEAD(acl_queue, acl_node);
typedef struct acl_queue aclq_t;

unsigned acl_pathmatch(enum acl_action defaction, const aclq_t *aclq,
		       const void *needle, struct acl_node **match);
unsigned acl_sockmatch(enum acl_action defaction, const aclq_t *aclq,
		       const void *needle, struct acl_node **match);
unsigned acl_sockmatch_saun(enum acl_action defaction, const aclq_t *aclq,
			    const void *needle, struct acl_node **match);
bool acl_match_path(enum acl_action defaction, const aclq_t *aclq,
		    const char *path, const char **match);
bool acl_match_sock(enum acl_action defaction, const aclq_t *aclq,
		    const struct pink_sockaddr *psa, struct sockmatch **match);
bool acl_match_saun(enum acl_action defaction, const aclq_t *aclq,
		    const char *abspath, struct sockmatch **match);
int acl_append_pathmatch(enum acl_action action, const char *pattern, aclq_t *aclq);
int acl_remove_pathmatch(enum acl_action action, const char *pattern, aclq_t *aclq);
int acl_append_sockmatch(enum acl_action action, const char *pattern, aclq_t *aclq);
int acl_remove_sockmatch(enum acl_action action, const char *pattern, aclq_t *aclq);

#define ACLQ_FIRST	TAILQ_FIRST
#define ACLQ_END	TAILQ_END
#define ACLQ_NEXT(elm)	TAILQ_NEXT((elm), link)
#define ACLQ_LAST(head)	TAILQ_LAST((head), acl_node)
#define ACLQ_PREV(elm)	TAILQ_PREV((elm), acl_node, link)
#define ACLQ_EMPTY	TAILQ_EMPTY
#define ACLQ_FOREACH(var, head) \
	TAILQ_FOREACH((var), (head), link)
#define ACLQ_FOREACH_SAFE(var, head, tvar) \
	TAILQ_FOREACH_SAFE((var), (head), link, (tvar))
#define ACLQ_FOREACH_REVERSE(var, head, field) \
	TAILQ_FOREACH_REVERSE((var), (head), acl_node, link)
#define ACLQ_FOREACH_REVERSE_SAFE(var, head, tvar) \
	TAILQ_FOREACH_REVERSE_SAFE((var), (head), acl_node, link, (tvar))
#define ACLQ_INIT	TAILQ_INIT
#define ACLQ_INSERT_HEAD(head, elm) \
	TAILQ_INSERT_HEAD((head), (elm), link)
#define ACLQ_INSERT_TAIL(head, elm) \
	TAILQ_INSERT_TAIL((head), (elm), link)
#define ACLQ_INSERT_AFTER(head, listelm, elm) \
	TAILQ_INSERT_AFTER((head), (listelm), (elm), link)
#define ACLQ_INSERT_BEFORE(listelm, elm) \
	TAILQ_INSERT_BEFORE((head), (elm), link)
#define ACLQ_REMOVE(head, elm) \
	TAILQ_REMOVE((head), (elm), link)

#define ACLQ_COPY(var, head, newhead, newvar, copymatch) \
	do { \
		ACLQ_FOREACH((var), (head)) { \
			(newvar) = xcalloc(1, sizeof(struct acl_node)); \
			(newvar)->action = var->action; \
			(newvar)->match = (copymatch)(var->match); \
			ACLQ_INSERT_TAIL((newhead), (newvar)); \
		} \
	} while (0)

#define ACLQ_FREE(var, head, freematch) \
	do { \
		struct acl_node *tvar; \
		ACLQ_FOREACH_SAFE((var), (head), tvar) { \
			ACLQ_REMOVE((head), (var)); \
			if ((var)->match) \
				(freematch)(var->match); \
			free((var)); \
		} \
	} while (0)

#define ACLQ_RESET(var, head, freematch) \
	do { \
		ACLQ_FREE((var), (head), (freematch)); \
		ACLQ_INIT((head)); \
	} while (0)

#endif
