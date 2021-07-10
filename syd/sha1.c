/*
 * libsyd/sha1.c
 *
 * libsyd SHA1 Hash Interface
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <syd/syd.h>
#include <syd/sha1dc_syd.h>

static syd_SHA_CTX globctx;

int syd_fd_to_sha1_hex(int fd, char *hex)
{
#define PATH_TO_HEX_BUFSIZ (1024*1024)
	/* Avoid this warning.
	 * warning: stack frame size of 1048664 bytes in function 'path_to_hex'
	 * [-Wframe-larger-than=]
	 *
	 * char buf[PATH_TO_HEX_BUFSIZ];
	 */
	syd_hash_sha1_init(&globctx);

	char *buf = malloc(PATH_TO_HEX_BUFSIZ * sizeof(char));
	if (!buf)
		return -ENOMEM;
	ssize_t nread;
	unsigned char hash[SYD_SHA1_RAWSZ];
	int r = 0;
	for (;;) {
		errno = 0;
		nread = read(fd, buf + r, PATH_TO_HEX_BUFSIZ - r);
		if (!nread) {
			r = 0;
			break;
		}
		if (nread > 0)
			r += nread;
		if (errno == EINTR ||
		    (nread > 0 && (size_t)r < PATH_TO_HEX_BUFSIZ)) {
			continue;
		} else if (nread < 0 && r == 0) { /* not partial read */
			int save_errno = errno;
			sprintf(hex, "<read:%d>", save_errno);
			r = -save_errno;
			break;
		}
		syd_hash_sha1_update(&globctx, buf, r);
		r = 0;
	}
	close(fd);
	if (r == 0) {
		if ((r = syd_hash_sha1_final(&globctx, hash)) < 0)
			return r;
		syd_strlcpy(hex, syd_hash_to_hex(hash), SYD_SHA1_HEXSZ + 1);
	}
	free(buf);
	return r;
}

int syd_file_to_sha1_hex(FILE *file, char *hex)
{
	return syd_fd_to_sha1_hex(fileno(file), hex);
}

int syd_path_to_sha1_hex(const char *pathname, char *hex)
{
	int fd = open(pathname, O_RDONLY|O_CLOEXEC|O_LARGEFILE);
	if (fd == -1) {
		int save_errno = errno;
		sprintf(hex, "<open:%d:%s>", save_errno,
			syd_name_errno(save_errno));
		return -save_errno;
	}

	int r = syd_fd_to_sha1_hex(fd, hex);
	close(fd);
	return r;
}

/*************** CHECKSUM CALCULATION *****************************************/
void syd_hash_sha1_init(syd_SHA_CTX *ctx)
{
	syd_SHA1_Init(ctx);
	SHA1DCSetSafeHash(ctx, 1);
	SHA1DCSetUseUBC(ctx, 1);
	SHA1DCSetUseDetectColl(ctx, 1);
	SHA1DCSetDetectReducedRoundCollision(ctx, 1);
}

void syd_hash_sha1_update(syd_SHA_CTX *ctx, const void *data,
				 size_t len)
{
	syd_SHA1_Update(ctx, data, len);
}

SYD_GCC_ATTR((warn_unused_result))
int syd_hash_sha1_final(syd_SHA_CTX *ctx, unsigned char *hash)
{
	return syd_SHA1_Final(hash, ctx) ? 0 : -EKEYREVOKED;
}
/*********** END OF CHECKSUM CALCULATION **************************************/
