/*
 * sydbox/sha1dc_syd.c
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include "sha1dc/lib/sha1.h"
#include "sha1dc/lib/ubc_check.h"
#include "hex.h"
#define syd_SHA1DCInit	SHA1DCInit

bool syd_SHA1DCFinal(unsigned char [20], SHA1_CTX *);
void syd_SHA1DCUpdate(SHA1_CTX *ctx, const void *data, unsigned long len);

#define platform_SHA_CTX SHA1_CTX
#define platform_SHA1_Init syd_SHA1DCInit
#define platform_SHA1_Update syd_SHA1DCUpdate
#define platform_SHA1_Final syd_SHA1DCFinal

#define syd_SHA_CTX		platform_SHA_CTX
#define syd_SHA1_Init		platform_SHA1_Init
#define syd_SHA1_Update		platform_SHA1_Update
#define syd_SHA1_Final		platform_SHA1_Final

void syd_hash_sha1_init_ctx(syd_SHA_CTX *ctx);
void syd_hash_sha1_update(syd_SHA_CTX *ctx, const void *data, size_t len);
int syd_hash_sha1_final(syd_SHA_CTX *ctx, unsigned char *hash)
	SYD_GCC_ATTR((warn_unused_result));
