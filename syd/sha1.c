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

int syd_fd_to_sha1_hex(int fd, char *hex)
{
#define PATH_TO_HEX_BUFSIZ (1024*1024)
	/* Avoid this warning.
	 * warning: stack frame size of 1048664 bytes in function 'path_to_hex'
	 * [-Wframe-larger-than=]
	 *
	 * char buf[PATH_TO_HEX_BUFSIZ];
	 */
	char *buf = malloc(PATH_TO_HEX_BUFSIZ * sizeof(char));
	if (!buf)
		return -ENOMEM;
	ssize_t nread;
	unsigned char hash[SYD_SHA1_RAWSZ];
	int r = 0;
	syd_SHA_CTX ctx;
	syd_hash_sha1_init(&ctx);
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
		syd_hash_sha1_update(&ctx, buf, r);
		r = 0;
	}
	close(fd);
	if (r == 0) {
		syd_hash_sha1_final(&ctx, hash);
		syd_strlcpy(hex, hash_to_hex(hash), SYD_SHA1_HEXSZ);
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
		sprintf(hex, "<open:%d>", save_errno);
		return -save_errno;
	}

	return syd_fd_to_sha1_hex(fd, hex);
}

/*************** CHECKSUM CALCULATION *****************************************/
void syd_hash_sha1_init(syd_SHA_CTX *ctx)
{
	syd_SHA1_Init(ctx);
}

void syd_hash_sha1_update(syd_SHA_CTX *ctx, const void *data,
				 size_t len)
{
	syd_SHA1_Update(ctx, data, len);
}

bool syd_hash_sha1_final(syd_SHA_CTX *ctx, unsigned char *hash)
{
	return syd_SHA1_Final(hash, ctx);
}
/*********** END OF CHECKSUM CALCULATION **************************************/
