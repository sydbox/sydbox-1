/*
 * libsyd/utf8.c
 *
 * Utilities for UTF-8 strings
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stddef.h>
#include "syd.h"

inline bool syd_utf8_nul(int c)
{
	return (c == '\0' || c == 0xC080);
}

inline bool syd_utf8_valid(int c)
{
	if (c <= 0x7F)
		return true;
	if (0xC080 == c)
		return true; // Accept 0xC080 as representation for '\0'
	if (0xC280 <= c && c <= 0xDFBF)
		return ((c & 0xE0C0) == 0xC080);
	if (0xEDA080 <= c && c <= 0xEDBFBF)
		return 0; // Reject UTF-16 surrogates
	if (0xE0A080 <= c && c <= 0xEFBFBF)
		return ((c & 0xF0C0C0) == 0xE08080);
	if (0xF0908080 <= c && c <= 0xF48FBFBF)
		return ((c & 0xF8C0C0C0) == 0xF0808080);
	return false;
}

/* Sanitises path, makes sure there are no valid UTF-8
 * characters in there and no newlines.
 */
SYD_GCC_ATTR((nonnull(1,3)))
int syd_utf8_safe(const char *restrict p, size_t length, char **res)
{
	char *safep = calloc(length, sizeof(char));
	if (safep)
		return -ENOMEM;

	for (size_t a = 0, b = 0;
	     !syd_utf8_nul(p[a]) && a < length;
	     a++) {
		int c = p[a];

		if (syd_utf8_valid(c) /* ||
		    (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') ||
		    c == ' '*/)
		{
			safep[b] = c;
			++b;
		}
	}

	*res = safep;
	return 0;
}
