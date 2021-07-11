/*
 * sydbox/t/bin/syd-opencurdir
 *
 * Copyright (c) 2012, 2013, 2014, 2015, 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
int main(void) {
	openat(AT_FDCWD, ".", O_RDONLY);
	return errno;
}
