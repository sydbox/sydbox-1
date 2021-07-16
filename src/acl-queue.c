/*
 * sydbox/acl-queue.c
 *
 * ACL queue for sydbox based on TAILQ from <sys/queue.h>
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "acl-queue.h"

#include <stdlib.h>

#include "pathmatch.h"

static inline unsigned acl_default(enum acl_action defaction,
				   struct acl_node **match_ptr)
{
	if (match_ptr)
		*match_ptr = NULL;
	return defaction | ACL_NOMATCH;
}

static inline unsigned acl_check(enum acl_action defaction,
				 struct acl_node *match_node,
				 struct acl_node **match_ptr)
{
	if (match_node) {
		if (match_ptr)
			*match_ptr = match_node;
		return match_node->action | ACL_MATCH;
	}

	return acl_default(defaction, match_ptr);
}

unsigned acl_pathmatch(enum acl_action defaction, const aclq_t *restrict aclq,
		       const void *needle, struct acl_node **match)
{
	struct acl_node *node, *node_match;
	const char *path = needle;

	if (!aclq || !needle)
		return acl_default(defaction, match);

	/* The last matching pattern decides */
	node_match = NULL;
	ACLQ_FOREACH(node, aclq) {
		if (node->match && pathmatch(node->match, path)) {
			sayv("syd-match: %s ⊆ %s", (const char *)node->match, path);
			node_match = node;
		} /* else {
			sayv("syd-acl-nomatch: %s ⨂ %s", (const char *)node->match, path);
		} */
	}

	return acl_check(defaction, node_match, match);
}

unsigned acl_sockmatch(enum acl_action defaction, const aclq_t *restrict aclq,
		       const void *needle, struct acl_node **match)
{
	struct acl_node *node, *node_match;
	const struct pink_sockaddr *psa = needle;

	if (!aclq || !needle)
		return acl_default(defaction, match);

	/* The last matching pattern decides */
	node_match = NULL;
	ACLQ_FOREACH(node, aclq) {
		if (sockmatch(node->match, psa))
			node_match = node;
	}

	return acl_check(defaction, node_match, match);
}

unsigned acl_sockmatch_saun(enum acl_action defaction, const aclq_t *restrict aclq,
			    const void *needle, struct acl_node **match)
{
	struct acl_node *node, *node_match;
	const char *abspath = needle;

	if (!aclq || !needle)
		return acl_default(defaction, match);

	/* The last matching pattern decides */
	node_match = NULL;
	ACLQ_FOREACH(node, aclq) {
		struct sockmatch *m = node->match;
		if (m->family != AF_UNIX || m->addr.sa_un.abstract)
			continue;
		if (pathmatch(m->addr.sa_un.path, abspath))
			node_match = node;
	}

	return acl_check(defaction, node_match, match);
}

bool acl_match_path(enum acl_action defaction, const aclq_t *restrict aclq,
		    const char *path, const char **match)
{
	unsigned r;
	struct acl_node *node;

	if (!aclq || !path)
		return false;

	r = acl_pathmatch(defaction, aclq, path, &node);
	if (r & ACL_MATCH) {
		if (match)
			*match = node ? node->match : NULL;
		return true;
	}
	return false;
}

bool acl_match_sock(enum acl_action defaction, const aclq_t *restrict aclq,
		    const struct pink_sockaddr *psa, struct sockmatch **match)
{
	unsigned r;
	struct acl_node *node;

	if (!aclq || !psa)
		return false;

	r = acl_sockmatch(defaction, aclq, psa, &node);
	if (r & ACL_MATCH) {
		if (match)
			*match = node ? node->match : NULL;
		return true;
	}
	return false;
}

bool acl_match_saun(enum acl_action defaction, const aclq_t *restrict aclq,
		    const char *abspath, struct sockmatch **match)
{
	enum acl_action r;
	struct acl_node *node;

	if (!aclq || !abspath)
		return false;

	r = acl_sockmatch_saun(defaction, aclq, abspath, &node);
	if (r & ACL_MATCH) {
		if (match)
			*match = node ? node->match : NULL;
		return true;
	}
	return false;
}

int acl_append_pathmatch(enum acl_action action, const char *pattern, aclq_t *aclq)
{
	int c, f;
	char **list = NULL;

	if (!aclq || !pattern || !*pattern)
		return -EINVAL;

	/* Expand path pattern */
	c = f = pathmatch_expand(pattern, &list) - 1;
	for (; c >= 0; c--) {
		struct acl_node *node = xmalloc(sizeof(struct acl_node));
		node->action = action;
		node->match = xstrdup(list[c]);
		ACLQ_INSERT_TAIL(aclq, node);
	}
	//if (list && list[0])
	//	say("match append ok: »%s«", list[0]);

	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return 0;
}

int acl_remove_pathmatch(enum acl_action action, const char *pattern, aclq_t *aclq)
{
	int c, f;
	char **list;
	struct acl_node *node;

	if (!aclq || !pattern || !*pattern)
		return -EINVAL;

	/* Expand path pattern */
	c = f = pathmatch_expand(pattern, &list) - 1;
	for (; c >= 0; c--) {
		struct acl_node *tvar;
		ACLQ_FOREACH_SAFE(node, aclq, tvar) {
			if (node->action == action && streq(node->match, list[c])) {
				ACLQ_REMOVE(aclq, node);
				free(node->match);
				free(node);
				break;
			}
		}
	}

	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return 0;
}

int acl_append_sockmatch(enum acl_action action, const char *pattern, aclq_t *aclq)
{
	int r, save_errno;
	int c, f;
	char **list;
	struct sockmatch *match;
	struct acl_node *node;

	if (!aclq || !pattern || !*pattern)
		return -EINVAL;

	/* Expand network alias */
	r = 0;
	save_errno = 0;
	c = f = sockmatch_expand(pattern, &list) - 1;
	for (; c >= 0; c--) {
		errno = 0;
		if ((r = sockmatch_parse(list[c], &match)) < 0) {
			r = -errno;
			goto out;
		} else if (errno == EAFNOSUPPORT) {
			/* IPv6 support disabled? */
			r = 0;
			save_errno = errno;
			goto out;
		}
		node = xmalloc(sizeof(struct acl_node));
		node->action = action;
		node->match = match;
		ACLQ_INSERT_TAIL(aclq, node);
	}

out:
	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	errno = save_errno;
	return r;
}

int acl_remove_sockmatch(enum acl_action action, const char *pattern, aclq_t *aclq)
{
	int c, f;
	char **list;
	struct sockmatch *match;
	struct acl_node *node;

	if (!aclq || !pattern || !*pattern)
		return -EINVAL;

	/* Expand network alias */
	c = f = sockmatch_expand(pattern, &list) - 1;
	for (; c >= 0; c--) {
		struct acl_node *tvar;
		ACLQ_FOREACH_SAFE(node, aclq, tvar) {
			match = node->match;
			if (match->str && streq(match->str, pattern)) {
				ACLQ_REMOVE(aclq, node);
				free_sockmatch(match);
				free(node);
				break;
			}
		}
	}

	for (; f > 0; f--)
		free(list[f]);
	free(list);

	return 0;
}
