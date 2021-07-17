/*
 * libsyd/sha1.c
 *
 * libsyd SHA1 Hash Interface
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <syd/syd.h>
#include <syd/sha1dc_syd.h>

static void syd_hash_sha1_init(void);
static void syd_hash_sha1_update(syd_SHA_CTX *ctx, const void *data,
				 size_t len);
SYD_GCC_ATTR((warn_unused_result))
static int syd_hash_sha1_final(syd_SHA_CTX *ctx, unsigned char *hash);

static syd_SHA_CTX glob_ctx;
static unsigned char glob_hash[SYD_SHA1_RAWSZ];
static char glob_hex[SYD_SHA1_HEXSZ + 1];

//#define SYD_PATH_TO_HEX_BUFSIZ (1024*1024) /* not bad, git's default. */
#define SYD_PATH_TO_HEX_BUFSIZ (65536) /* better, sha1dc's default. */
static char glob_buf[SYD_PATH_TO_HEX_BUFSIZ];

SYD_GCC_ATTR((nonnull(1)))
int syd_name_to_sha1_hex(const void *buffer, size_t size,
			 char *hex)
{
	int r;

	syd_hash_sha1_init();
	syd_hash_sha1_update(&glob_ctx, buffer, size);
	r = syd_hash_sha1_final(&glob_ctx, glob_hash);
	syd_strlcpy(hex, syd_hash_to_hex(glob_hash),
		    SYD_SHA1_HEXSZ + 1);
	return r;
}

int syd_file_to_sha1_hex(FILE *file, char *hex)
{
	int r;

	syd_hash_sha1_init();
	r = 0;
	for (;;) {
		errno = 0;
		ssize_t nread = fread(glob_buf, 1, SYD_PATH_TO_HEX_BUFSIZ, file);
		if (errno == EINTR)
			continue;
		if (nread > 0)
			syd_hash_sha1_update(&glob_ctx, glob_buf, (unsigned)nread);
		if (nread != SYD_PATH_TO_HEX_BUFSIZ) {
			if (ferror(file))
				return -errno;
			else if (feof(file))
				break;
		}
	}
	if (r == 0) {
		r = syd_hash_sha1_final(&glob_ctx, glob_hash);
		syd_strlcpy(hex, syd_hash_to_hex(glob_hash),
			    SYD_SHA1_HEXSZ + 1);
	}
	return r;
}

int syd_path_to_sha1_hex(const char *pathname, char *hex)
{
	FILE *f = fopen(pathname, "r");
	if (!f) {
		int save_errno = errno;
		sprintf(hex, "<open:%d:%s>", save_errno,
			syd_name_errno(save_errno));
		return -save_errno;
	}

	int r = syd_file_to_sha1_hex(f, hex);

	fclose(f);

	return r;
}

/*************** CHECKSUM CALCULATION *****************************************/
void syd_hash_sha1_init_ctx(syd_SHA_CTX *ctx)
{
	syd_SHA1_Init(ctx);
	SHA1DCSetSafeHash(ctx, 1);
	SHA1DCSetUseUBC(ctx, 1);
	SHA1DCSetUseDetectColl(ctx, 1);
	SHA1DCSetDetectReducedRoundCollision(ctx, 1);
}

static void syd_hash_sha1_init(void)
{
	syd_hash_sha1_init_ctx(&glob_ctx);
}

static void syd_hash_sha1_update(syd_SHA_CTX *ctx, const void *data,
				 size_t len)
{
	syd_SHA1_Update(ctx, data, len);
}

SYD_GCC_ATTR((warn_unused_result))
static int syd_hash_sha1_final(syd_SHA_CTX *ctx, unsigned char *hash)
{
	return syd_SHA1_Final(hash, ctx) ? 0 : -EKEYREVOKED;
}
/*********** END OF CHECKSUM CALCULATION **************************************/
