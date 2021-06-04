/*
 * sydbox/filter.c
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include "sydbox.h"

#define FILTER_NMEMB_MAX 1048576 /* Allows up to ~42000 filters. */
static int filter_nmemb = 4096;
static int filter_index;

static int filter_grow(void)
{
	if (filter_nmemb + 1024 > FILTER_NMEMB_MAX)
		return -ERANGE;

	filter_nmemb += 1024;
	sydbox->filter = realloc(sydbox->filter,
				 sizeof(struct filter) * filter_nmemb);
	return 0;
}

int filter_init(void)
{
	sydbox->filter = xmalloc(sizeof(struct filter) * filter_nmemb);
	return 0;
}

int filter_free(void)
{
	if (sydbox->filter) {
		free(sydbox->filter);
		sydbox->filter = NULL;
	}
	return 0;
}

int filter_push(struct filter filter)
{
	if (filter_index + 1 >= filter_nmemb && filter_grow() < 0)
		return -ERANGE;

	sydbox->filter[filter_index++] = filter;
	return 0;
}
