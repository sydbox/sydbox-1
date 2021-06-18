/*
 * sydbox/hex.h
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon GIT which is GPL-2.0-only
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef HEX_H
#define HEX_H 1

/* The length in bytes and in hex digits of an object name (SHA-1 value). */
#define SYD_SHA1_RAWSZ 20
#define SYD_SHA1_HEXSZ (2 * SYD_SHA1_RAWSZ)
/* The block size of SHA-1. */
#define SYD_SHA1_BLKSZ 64
#define SYD_MAX_HEXSZ SYD_SHA1_HEXSZ

extern const signed char hexval_table[256];
static inline unsigned int hexval(unsigned char c)
{
	return hexval_table[c];
}

/*
 * Convert a binary hash in "unsigned char []" or an object name in
 * "struct object_id *" to its hex equivalent. The `_r` variant is reentrant,
 * and writes the NUL-terminated output to the buffer `out`, which must be at
 * least `SYD_MAX_HEXSZ + 1` bytes, and returns a pointer to out for
 * convenience.
 *
 * The non-`_r` variant returns a static buffer, but uses a ring of 4
 * buffers, making it safe to make multiple calls for a single statement, like:
 *
 *   printf("%s -> %s", hash_to_hex(one), hash_to_hex(two));
 *   printf("%s -> %s", oid_to_hex(one), oid_to_hex(two));
 */
char *hash_to_hex_r(char *buffer, const unsigned char *hash);
char *hash_to_hex(const unsigned char *hash); /* static buffer result! */

#endif
