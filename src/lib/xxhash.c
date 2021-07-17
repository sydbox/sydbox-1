/*
 * libsyd/xxHash.c
 *
 * libsyd xxHash Hash Interface:
 * Display convention is Big Endian, for both 32 and 64 bits algorithms
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon xxHash/xxhsum.c which is:
 *   Copyright (C) 2013-2020 Yann Collet
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include <syd/syd.h>

/* ************************************
 *  Includes
 **************************************/
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>	/* malloc, calloc, free, exit */
#include <string.h>	/* strcmp, memcpy */
#include <stdio.h>	/* fprintf, fopen, ftello64, fread, stdin, stdout, _fileno (when present) */
#include <sys/types.h>	/* stat, stat64, _stat64 */
#include <sys/stat.h>	/* stat, stat64, _stat64 */
#include <time.h>	/* clock_t, clock, CLOCKS_PER_SEC */
#include <assert.h>	/* assert */
#include <errno.h>	/* errno */

#define XXH_INLINE_ALL
#define XXX_FORCE_MEMORY_ACCESS 1
#define XXH_ACCEPT_NULL_INPUT_POINTER 1
//#define XXH_STATIC_LINKING_ONLY   /* *_state_t */
#include "xxhash.h"
#include "cli/xsum_arch.h"
#include "cli/xsum_config.h"
#define XSUM_NO_MAIN
# include "cli/xsum_os_specific.c"

static void syd_hash_xxh64_init(void);
static void syd_hash_xxh32_init(void);
static XXH64_state_t *state64;
static XXH32_state_t *state32;
static bool state64_init;
static bool state32_init;

#define SYD_PATH_TO_HEX_BUFSZ (65536) /* best so far goes over 2G/s with xxh64. */
static char glob_buf[SYD_PATH_TO_HEX_BUFSZ];

#if 0
static unsigned syd_isLittleEndian(void)
{
    const union { XSUM_U32 u; XSUM_U8 c[4]; } one = { 1 };   /* don't use static: performance detrimental  */
    return one.c[0];
}
#endif
#define SYD_HASH_SALT "1984GogoL1984"

SYD_GCC_ATTR((nonnull(1)))
uint32_t syd_name_to_xxh32_hex(const void *restrict buffer, size_t size,
			       uint32_t seed, char *hex)
{
	char *buffer_salted;

	if (asprintf(&buffer_salted, SYD_HASH_SALT"%s"SYD_HASH_SALT, (const char*)buffer) == -1)
		return 0;

	XXH32_hash_t hash = XXH32(buffer_salted, size, seed);

	free(buffer_salted);

	if (hex) {
		hex[0] = '\0';
		sprintf(hex, "%" syd_str(SYD_XXH32_HEXSZ)"x", hash);
	}

	return hash;
}

SYD_GCC_ATTR((nonnull(1,4)))
bool syd_vrfy_xxh32_hex(const void *restrict buffer, size_t size,
			uint32_t seed, const char *hex)
{
	size_t len = strlen(hex);
	if (len != SYD_XXH32_HEXSZ) {
		errno = EINVAL;
		syd_say_errno("strlen(»%s«)=%zu != %d", hex, len,
			      SYD_XXH32_HEXSZ);
		return false;
	}

	char hex_real[SYD_XXH32_HEXSZ+1] = {0};
	uint32_t hash = syd_name_to_xxh32_hex(buffer, size, seed, hex_real);
	if (!strncmp(hex_real, hex, SYD_XXH32_HEXSZ)) {
		syd_say("match: »%s« ⊆ »%s«", (const char *)hex_real, hex);
		return true;
	} else {
		syd_say("nomatch: »%s« ⨂ »%s«", (const char *)hex_real, hex);
		return false;
	}
}

SYD_GCC_ATTR((nonnull(1)))
uint64_t syd_name_to_xxh64_hex(const void *restrict buffer, size_t size,
			       uint64_t seed, char *hex)
{
	char *buffer_salted;

	if (asprintf(&buffer_salted, SYD_HASH_SALT "%s" SYD_HASH_SALT, (const char *)(const char *)buffer) == -1)
		return 0;

	XXH64_hash_t hash = XXH64(buffer_salted, size, seed);

	free(buffer_salted);

	if (hex) {
		hex[0] = '\0';
		sprintf(hex, "%" syd_str(SYD_XXH64_HEXSZ)"lx", hash);
	}

	return hash;
}

SYD_GCC_ATTR((nonnull(1,4)))
bool syd_vrfy_xxh64_hex(const void *restrict buffer, size_t size,
			uint64_t seed, const char *hex)
{
	size_t len = strlen(hex);
	if (len != SYD_XXH64_HEXSZ) {
		errno = EINVAL;
		syd_say_errno("strlen(»%s«)=%zu != %d", hex, len,
			      SYD_XXH64_HEXSZ);
		return false;
	}

	char hex_real[SYD_XXH64_BUFSZ] = {0};
	uint64_t hash = syd_name_to_xxh64_hex(buffer, size, seed, hex_real);
	uint64_t hash_vrfy;
	if (sscanf(hex, "%" syd_str(SYD_XXH64_HEXSZ) "lx", &hash_vrfy) == 1) {
		errno = EINVAL;
		syd_say_errno("sscanf(»%s«)", hex);
		return false;
	}
	if (hash == hash_vrfy) {
		syd_say("match: »%s« ⊆ »%s«", (const char *)buffer, hex);
		return true;
	} else {
		syd_say("nomatch: »%s« ⨂ »%s«", (const char *)buffer, hex);
		return false;
	}
}

SYD_GCC_ATTR((nonnull(1)))
int syd_file_to_xxh64_hex(FILE *file, uint64_t *digest, char *hex)
{
	int r = 0;

	if (!state64_init) {
		syd_hash_xxh64_init();
		state64_init = true;
	}
	if (!state64)
		return -ECANCELED;

	/* Initialize state with selected seed */
	XXH64_hash_t const seed = 1984;
	if (XXH64_reset(state64, seed) == XXH_ERROR)
		return -ENOTRECOVERABLE;

	/* Feed the state with input data, any size, any number of times */
	for (;;) {
		errno = 0;
		ssize_t nread = fread(glob_buf, 1, SYD_PATH_TO_HEX_BUFSZ, file);
		if (errno == EINTR)
			continue;
		if (nread > 0 &&
		    XXH64_update(state64, glob_buf,
				 (unsigned)nread) == XXH_ERROR)
			return -ECANCELED;
		if (nread != SYD_PATH_TO_HEX_BUFSZ) {
			if (ferror(file))
				return -errno;
			else if (feof(file))
				break;
		}
	}

	/* Produce the final hash value */
	XXH64_hash_t const hash = XXH64_digest(state64);

	/* Fill in output parameters */
	if (digest)
		*digest = hash;
	if (hex) {
		hex[0] = '\0';
		sprintf(hex, "%" syd_str(SYD_XXH64_HEXSZ)"lx", hash);
	}

	return 0;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_file_to_xxh32_hex(FILE *file, uint32_t *digest, char *hex)
{
	int r = 0;

	if (!state32_init) {
		syd_hash_xxh32_init();
		state32_init = true;
	}
	if (!state32)
		return -ECANCELED;

	/* Initialize state with selected seed */
	XXH32_hash_t const seed = 2525;
	if (XXH32_reset(state32, seed) == XXH_ERROR)
		return -ENOTRECOVERABLE;

	/* Feed the state with input data, any size, any number of times */
	for (;;) {
		errno = 0;
		ssize_t nread = fread(glob_buf, 1, SYD_PATH_TO_HEX_BUFSZ, file);
		if (XXH32_update(state32, glob_buf,
				 (unsigned)nread) == XXH_ERROR)
			return -ECANCELED;
		if (nread != SYD_PATH_TO_HEX_BUFSZ)
			break;
	}

	/* Produce the final hash value */
	XXH32_hash_t const hash = XXH32_digest(state32);

	/* Fill in output parameters */
	if (digest)
		*digest = hash;
	if (hex) {
		hex[0] = '\0';
		sprintf(hex, "%" syd_str(SYD_XXH32_HEXSZ)"x", hash);
	}

	return 0;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_path_to_xxh64_hex(const char *restrict pathname, uint64_t *digest, char *hex)
{
	FILE *f = fopen(pathname, "r");
	if (!f) {
		int save_errno = errno;
		sprintf(hex, "<open:%d:%s>", save_errno,
			syd_name_errno(save_errno));
		return -save_errno;
	}

	int r = syd_file_to_xxh64_hex(f, digest, hex);

	fclose(f);

	return r;
}

SYD_GCC_ATTR((nonnull(1)))
int syd_path_to_xxh32_hex(const char *restrict pathname, uint32_t *digest, char *hex)
{
	FILE *f = fopen(pathname, "r");
	if (!f) {
		int save_errno = errno;
		sprintf(hex, "<open:%d:%s>", save_errno,
			syd_name_errno(save_errno));
		return -save_errno;
	}

	int r = syd_file_to_xxh32_hex(f, digest, hex);

	fclose(f);

	return r;
}

/*************** CHECKSUM CALCULATION *****************************************/
static void syd_hash_xxh64_init(void)
{
	/* create a hash state, once.
	 * this is *not* thread safe.
	 */
	if (!state64)
		state64 = XXH64_createState();
}

static void syd_hash_xxh32_init(void)
{
	/* create a hash state, once.
	 * this is *not* thread safe.
	 */
	if (!state32)
		state32 = XXH32_createState();
}
