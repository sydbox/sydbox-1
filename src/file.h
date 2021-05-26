/*
 * sydbox/file.h
 *
 * File related utilities
 *
 * Copyright (c) 2010, 2011, 2012, 2013 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is
 *   Copyright 2010 Lennart Poettering
 * Distributed under the terms of the GNU Lesser General Public License v2.1 or later
 */

#ifndef FILE_H
#define FILE_H 1

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

bool empty_line(const char *s);
char *truncate_nl(char *s);

const char *filename_ext(const char *s);

int basename_copy(const char *path, char *dest, size_t len);
int basename_alloc(const char *path, char **buf);
ssize_t readlink_copy(const char *path, char *dest, size_t len);
ssize_t readlink_alloc(const char *path, char **buf);

int empty_dir(const char *dname);
int utime_reset(const char *path, const struct stat *st);

int read_one_line_file(const char *fn, char **line);

#endif /* !FILE_H */
