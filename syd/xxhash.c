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
#include "syd.h"

/* ************************************
 *  Includes
 **************************************/
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>     /* malloc, calloc, free, exit */
#include <string.h>     /* strcmp, memcpy */
#include <stdio.h>      /* fprintf, fopen, ftello64, fread, stdin, stdout, _fileno (when present) */
#include <sys/types.h>  /* stat, stat64, _stat64 */
#include <sys/stat.h>   /* stat, stat64, _stat64 */
#include <time.h>       /* clock_t, clock, CLOCKS_PER_SEC */
#include <assert.h>     /* assert */
#include <errno.h>      /* errno */

#define XXH_INLINE_ALL
#define XXX_FORCE_MEMORY_ACCESS 1
#define XXH_ACCEPT_NULL_INPUT_POINTER 1
//#define XXH_STATIC_LINKING_ONLY   /* *_state_t */
#include "xxhash.h"
#include "cli/xsum_arch.h"
#include "cli/xsum_config.h"
#define XSUM_NO_MAIN
# include "cli/xsum_os_specific.c"

#if 0
static unsigned syd_isLittleEndian(void)
{
    const union { XSUM_U32 u; XSUM_U8 c[4]; } one = { 1 };   /* don't use static: performance detrimental  */
    return one.c[0];
}
#endif

SYD_GCC_ATTR((nonnull(1,4)))
uint32_t syd_name_to_xxh32_hex(const void *restrict buffer, size_t size,
			       uint32_t seed, char *hex)
{
	XXH32_hash_t hash = XXH32(buffer, size, seed);

	hex[0] = '\0';
	sprintf(hex, "%" syd_str(SYD_XXH32_ALGO_LEN)"x", hash);

	return hash;
}

SYD_GCC_ATTR((nonnull(1,4)))
uint64_t syd_name_to_xxh64_hex(const void *restrict buffer, size_t size,
			       uint64_t seed, char *hex)
{
	XXH64_hash_t hash = XXH64(buffer, size, seed);

	hex[0] = '\0';
	sprintf(hex, "%" syd_str(SYD_XXH64_ALGO_LEN)"lx", hash);

	return hash;
}
