/*
 * sydbox/pathmatch.c
 *
 * Extends wildmatch for sydbox specific use cases.
 *
 * Copyright (c) 2012, 2013, 2015 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "sydconf.h"

#include "pathmatch.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "path.h"
#include "util.h"
#include "wildmatch.h"
#include "xfunc.h"

bool match_case_sensitive = true;
enum no_wildcard match_no_wild = NO_WILDCARD_LITERAL;

void pathmatch_set_case(bool case_sensitive)
{
	match_case_sensitive = case_sensitive;
}

bool pathmatch_get_case(void)
{
	return match_case_sensitive;
}

void pathmatch_set_no_wildcard(enum no_wildcard no_wild)
{
	match_no_wild = no_wild;
}

enum no_wildcard pathmatch_get_no_wildcard(void)
{
	return match_no_wild;
}

int pathmatch_expand(const char *pattern, char ***buf)
{
	ssize_t bufsiz;
	char *s, *p, *cp;
	char **list;
	bool literal = false;

	assert(buf);

	p = xstrdup(pattern);
	if (match_no_wild == NO_WILDCARD_PREFIX && !strpbrk(p, "*?")) {
		cp = xmalloc(sizeof(char) * (strlen(p) + sizeof(WILD3_SUFFIX)));

		/* append WILD3_SUFFIX to p, no wildcard is prefix */
		strcpy(cp, p);
		strcat(cp, WILD3_SUFFIX);

		free(p);

		p = cp;
		literal = true;
	}
	p = path_kill_slashes(p);

	if (literal || endswith(p, WILD3_SUFFIX)) {
		size_t i;

		list = xmalloc(sizeof(char *) * 2);
		s = xstrdup(p);
		i = strrchr(s, '/') - s;
		s[i] = '\0'; /* bare directory first */
		list[0] = xstrdup(s);
		s[i] = '/';
		s[i+3] = '\0'; /* two stars instead of three */
		list[1] = s;
		bufsiz = 2;
	} else {
		list = xmalloc(sizeof(char *));
		list[0] = xstrdup(p);
		bufsiz = 1;
	}

	free(p);
	*buf = list;
	return bufsiz;
}

bool pathmatch(const char *pattern, const char *text)
{
	int r;

	if (match_case_sensitive)
		r = wildmatch(pattern, text);
	else
		r = iwildmatch(pattern, text);

	return r;
}
