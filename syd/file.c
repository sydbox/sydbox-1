/*
 * libsyd/file.c
 *
 * file and path utilities
 *
 * Copyright (c) 2015, 2021 Ali Polatel <alip@exherbo.org>
 * Released under the terms of the GNU General Public License v3 (or later)
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE 1
#endif

#include "syd.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef LIBSYD_MAXSYMLINKS
# if defined(SYMLOOP_MAX)
#  define LIBSYD_MAXSYMLINKS SYMLOOP_MAX
# elif defined(MAXSYMLINKS)
#  define LIBSYD_MAXSYMLINKS MAXSYMLINKS
# else
#  define LIBSYD_MAXSYMLINKS 32
# endif
#endif

static inline int syd_open_path(const char *pathname, int flags)
{
	int fd;

	fd = open(pathname, flags|O_PATH|O_CLOEXEC|O_NOATIME);
	return (fd >= 0) ? fd : -errno;
}

int syd_opendir(const char *dirname)
{
	return syd_open_path(dirname, O_DIRECTORY);
}

int syd_fchdir(int fd)
{
	if (fchdir(fd) < 0)
		return -errno;
	return 0;
}

int syd_fstat(int fd, struct stat *buf)
{
	if (fstat(fd, buf) < 0)
		return -errno;
	return 0;
}

int syd_fstatat(int fd, struct stat *buf, int flags)
{
	if (fstatat(fd, "", buf, AT_EMPTY_PATH|flags) < 0)
		return -errno;
	return 0;
}

/*
 * Returns -EINVAL: This is not /
 *	   -ENOENT: Does not exist e.g: /.../foo
 *	   0      : This _is_ /
 *	   > 0    : This is an absolute path, skip this many characters till '/'
 * Path must not be empty!
 */
int syd_path_root_check(const char *path)
{
	/* Handle quick cases */
	if (path == NULL)
		return -EINVAL;
	if (path[0] != '/')
		return -EINVAL;
	if (path[1] == '\0')
		return 0;

	/* /../../. is OK but /.../ is not. */
	for (unsigned int i = 1, ndot = 0; path[i] != '\0'; i++) {
		if (path[i] == '.') {
			if (++ndot > 2)
				return -ENOENT;
			continue;
		} else if (path[i] != '/') {
			return (i - 1); /* Absolute path */
		} else if (ndot > 0) {
			ndot = 0;
		}
	}

	return 0;
}

static inline int syd_path_root_alloc(char **buf)
{
	char *rpath;

	rpath = malloc(sizeof(char) * 2);
	if (rpath == NULL)
		return -errno;
	rpath[0] = '/';
	rpath[1] = '\0';
	*buf = rpath;

	return 0;
}

/*
 * readlink() which allocates memory and appends zero-byte
 */
ssize_t syd_readlink_alloc(const char *path, char **buf)
{
	int fd;

	if (path == NULL || buf == NULL)
		return -EINVAL;

	fd = syd_open_path(path, O_NOFOLLOW);
	if (fd < 0)
		return fd; /* negated errno */

	int r;
	ssize_t n;
	size_t l = 128;
	char *p = NULL;
	for (;;) {
		char *m;

		m = realloc(p, l * sizeof(char));
		if (m == NULL) {
			close(fd);
			if (p != NULL)
				free(p);
			return -ENOMEM;
		}
		p = m;
		p[0] = '\0';

		n = readlinkat(fd, "", p, l - 1);
		if (n < 0) {
			if (errno != ENAMETOOLONG) {
				r = -errno;
				goto out;
			}
			/* Retry with a larger buffer. */
		} else if ((size_t)n < l - 1) {
			r = 0;
			goto out;
		}

		unsigned long ul = (l * 2);
		if (ul >= INT_MAX) { /* everything has a limit. */
			r = -ENAMETOOLONG;
			goto out;
		}
		l *= 2;
	}
out:
	close(fd);
	if (!r) { /* success */
		p[n] = '\0';
		*buf = p;
		r = ++n;
	} else { /* failure */
		free(p);
	}
	return r;
}

/*
 * Requires absolute path.
 */
int syd_path_stat(const char *path, int mode, bool last_node, struct stat *buf)
{
	int fd, flags, sflags;
	bool nofollow, ignore_noent;
	struct stat sb;

	if (buf == NULL || path == NULL || path[0] != '/')
		return -EINVAL;

	flags = 0;
	sflags = AT_EMPTY_PATH|AT_NO_AUTOMOUNT;
	nofollow = mode & ~SYD_REALPATH_MASK & SYD_REALPATH_NOFOLLOW;
	ignore_noent = last_node && (mode & SYD_REALPATH_NOLAST);
	if (nofollow) {
		flags |= O_NOFOLLOW;
		sflags |= AT_SYMLINK_NOFOLLOW;
	}

#define ignore_last_node(n_errno) (ignore_noent && \
				  ((n_errno) == -ENOENT || (n_errno) == -ELOOP))

	fd = syd_open_path(path, flags);
	if (fd < 0) {
		if (ignore_last_node(fd)) {
			sb.st_mode = 0;
			goto out;
		}
		return fd; /* negated errno */
	}

	if (fstatat(fd, "", &sb, sflags) < 0) {
		int save_errno = -errno;
		if (ignore_last_node(save_errno)) {
			sb.st_mode = 0;
			goto out;
		}
		close(fd);
		return save_errno;
	}

	if (!S_ISLNK(sb.st_mode) || (nofollow && last_node))
		goto out;

	close(fd);

	flags &= ~O_NOFOLLOW;
	fd = syd_open_path(path, flags);
	if (fd < 0) {
		if (mode & SYD_REALPATH_NOLAST) {
			if (last_node) {
				if (nofollow)
					sb.st_mode = 0;
				goto out;
			} else if (fd == -ENOENT || fd == -ELOOP) {
				sb.st_mode = 0;
				goto out;
			}
		} else if (nofollow) { /* SYD_REALPATH_EXIST */
			goto out;
		}
		return fd; /* negated errno */
	}
out:
	if (fd >= 0)
		close(fd);
	*buf = sb;
	return 0;
#undef ignore_last_node
}

int syd_prepath_at(int fd, const char *path, char **buf, int mode)
{
	int r, save_fd = -ENOENT;
	char *left = NULL, *rpath = NULL;

	/* Handle (very) quick cases */
	if (path && path[0] == '\0')
		return -ENOENT;

	/* Validate arguments */
	if (buf == NULL)
		return -EINVAL;
	if (fd < 0 && fd != AT_FDCWD)
		return -EINVAL;

	/* Handle quick cases */
	r = syd_path_root_check(path);
	switch (r) {
	case -ENOENT:
		return -ENOENT;
	case 0: /* This is == '/' */
		return syd_path_root_alloc(buf);
	case -EINVAL:
		r = 0;
		break;
	default: /* >0 absolute path */
		path += r;
		r = 0;
		break;
	}

	return r;
}

#if 0
int syd_realpath_at(int fd, const char *path, char **buf, int mode)
{
	int r, save_fd = -ENOENT;
	char *left = NULL, *rpath = NULL;

	/* Handle (very) quick cases */
	if (path && path[0] == '\0')
		return -ENOENT;

	/* Validate arguments */
	if (buf == NULL)
		return -EINVAL;
	if (fd < 0 && fd != AT_FDCWD)
		return -EINVAL;

	/* Handle quick cases */
	r = syd_path_root_check(path);
	switch (r) {
	case -ENOENT:
		return -ENOENT;
	case 0: /* This is == '/' */
		return syd_path_root_alloc(buf);
	case -EINVAL:
		r = 0;
		break;
	default: /* >0 absolute path */
		path += r;
		r = 0;
		break;
	}

	bool nofollow;
	short flags;
	size_t llen, plen, rlen;

	flags = mode & ~SYD_REALPATH_MASK;
	nofollow = !!(flags & SYD_REALPATH_NOFOLLOW);
	mode &= SYD_REALPATH_MASK;
	plen = strlen(path);

	left = malloc(sizeof(char) * plen);
	if (left == NULL)
		return -errno;
	rpath = malloc(sizeof(char) * (plen + 1));
	if (rpath == NULL) {
		r = -errno;
		goto out;
	}

	if (path[0] == '/') {
		rpath[0] = '/';
		rpath[1] = '\0';
		if (path[1] == '\0') {
			r = 0;
			goto out;
		}
		rlen = 1;
		llen = syd_strlcpy(left, path + 1, plen);
	} else {
		if (fd == AT_FDCWD) {
			save_fd = syd_opendir(".");
			if (r >= 0 || r == -ENOENT) {
				save_fd = r;
			} else {
				r = save_fd; /* negated errno */
				goto out;
			}
		} else if ((r = syd_fchdir(fd)) < 0) {
			goto out;
		}
	}

	if (llen >= plen) {
		r = -ENAMETOOLONG; /* Should not happen */
		goto out;
	}

	/*
	 * Iterate over path components in `left'.
	 */
	for (char *next_token = NULL; llen != 0;) {
		/*
		 * Extract the next path component and adjust `left'
		 * and its length.
		 */
		char *m, *p, *q, *s;
		size_t ntlen, nsymlinks = 0;
		struct stat sb;

		p = strchr(left, '/');
		s = p ? p : left + llen;
		if (next_token == NULL) {
			ntlen = (s - left) + 1;
			next_token = malloc(sizeof(char) * ntlen);
			if (next_token == NULL) {
				r = -errno;
				free(next_token);
				goto out;
			}
		}
		memcpy(next_token, left, s - left);
		next_token[s - left] = '\0';
		llen -= s - left;
		if (p != NULL)
			memmove(left, s + 1, llen + 1);
		if (rpath[rlen - 1] != '/') {
			if (rlen >= plen) {
				plen += (rlen - plen) > 128 ? (rlen - plen) : 128;
				m = realloc(rpath, sizeof(char) * (plen + 1));
				if (m == NULL) {
					r = -errno;
					free(next_token);
					goto out;
				}
				rpath = m;
			}
			rpath[rlen++] = '/';
			rpath[rlen] = '\0';
		}
		if (next_token[0] == '\0') {
			/*
			 * Handle consequential slashes.  The path
			 * before slash shall point to a directory.
			 *
			 * Only the trailing slashes are not covered
			 * by other checks in the loop, but we verify
			 * the prefix for any (rare) "//" or "/\0"
			 * occurrence to not implement lookahead.
			 */
			if ((r = syd_path_stat(rpath, (mode|flags), true, &sb)) < 0) {
				free(next_token);
				goto out;
			}
			if (sb.st_mode == 0 && mode == SYD_REALPATH_NOLAST) {
				r = 0;
				break;
			}
			if (!S_ISDIR(sb.st_mode)) {
				r = -ENOTDIR;
				free(next_token);
				goto out;
			}
			continue;
		} else if (strcmp(next_token, ".") == 0) {
			continue;
		} else if (strcmp(next_token, "..") == 0) {
			/*
			 * Strip the last path component except when we have
			 * single "/"
			 */
			if (rlen > 1) {
				rpath[rlen - 1] = '\0';
				q = strrchr(rpath, '/') + 1;
				*q = '\0';
				rlen = q - rpath;
			}
			continue;
		}
		if (plen <= rlen + ntlen) {
			plen += ntlen;
			m = realloc(rpath, sizeof(char) * (plen + 1));
			if (m == NULL) {
				r = -errno;
				free(next_token);
				goto out;
			}
			rpath = m;
		}

		if (p == NULL || left[strspn(left, "/")] == '\0')
			r = syd_path_stat(rpath, (mode|flags), true, &sb);
		else
			r = syd_path_stat(rpath, (mode|flags), false, &sb);
		if (r < 0) {
			free(next_token);
			goto out;
		}
		if (S_ISLNK(sb.st_mode)) {
			ssize_t slen;
			char *symlink;

			/* FIXME: MAXSYMLINKS is stupid, handle this properly. */
			if (++nsymlinks > LIBSYD_MAXSYMLINKS) {
				r = -ELOOP;
				free(next_token);
				goto out;
			}
			if (!nofollow) {
				slen = syd_readlink_alloc(rpath, &symlink);
				if (slen < 0) {
					r = slen; /* negated errno */
					free(next_token);
					goto out;
				}
				if (symlink[0] == '/') {
					rpath[1] = '\0';
					rlen = 1;
				} else if (rlen > 1) {
					/* Strip the last path component. */
					rpath[rlen - 1] = '\0';
					q = strrchr(rpath, '/') + 1;
					*q = '\0';
					rlen = q - rpath;
				}
			}
			/*
			 * If there are any path components left, then
			 * append them to symlink. The result is placed
			 * in `left'.
			 */
			if (p != NULL) {
				m = realloc(symlink, (slen + llen + 2) * sizeof(char));
				if (m == NULL) {
					r = -errno;
					free(next_token);
					free(symlink);
					goto out;
				}
				symlink = m;

				if (symlink[slen - 1] != '/') {
					symlink[slen] = '/';
					symlink[slen + 1] = 0;
				}
			}
			llen = syd_strlcpy(left, symlink, sizeof(left));
			if (nofollow && p == NULL) {
				r = 0;
				rlen = syd_strlcat(rpath, left, rlen);
				break;
			}
		}
	}

	/*
	 * Remove trailing slash except when the resolved pathname
	 * is a single "/".
	 */
	if (rlen > 1 && rpath[rlen - 1] == '/')
		rpath[rlen - 1] = '\0';

out:
	if (save_fd >= 0) {
		syd_fchdir(save_fd);
		close(save_fd);
	}
	if (left)
		free(left);
	if (r < 0) {
		if (rpath != NULL)
			free(rpath);
	} else {
		*buf = rpath;
	}
	return r;
}
#endif
