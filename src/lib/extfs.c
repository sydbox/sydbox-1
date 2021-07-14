/*
 * libsyd/extfs.c
 *
 * libsyd Utilities for Ext* File Systems
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <errno.h>
#include <sys/ioctl.h>
#include <syd/syd.h>

int syd_extfs_get_compression(const char *filename, bool *compress)
{
	int fd;

	if (!compress)
		return -EINVAL;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;

	unsigned long flags;
	int r = syd_extfs_get_flags(fd, &flags);
	if (r < 0)
		goto out;
	*compress = !!(flags & SYD_EXT2_COMPR_FL);

out:
	close(fd);
	return 0;
}

int syd_extfs_set_compression(const char *filename, bool on)
{
	int fd, r = 0;
	unsigned long flags;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;
	if ((r = syd_extfs_get_flags(fd, &flags)) < 0)
		goto out;
	if (flags & SYD_EXT2_COMPR_FL) {
		if (on)
			return 0;
		flags &= ~SYD_EXT2_COMPR_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	} else if (on) {
		flags |= SYD_EXT2_COMPR_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	}
out:
	close(fd);
	return r;
}

int syd_extfs_get_append_only(const char *filename, bool *appendonly)
{
	int fd;

	if (!appendonly)
		return -EINVAL;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;

	unsigned long flags;
	int r = syd_extfs_get_flags(fd, &flags);
	if (r < 0)
		goto out;
	*appendonly = !!(flags & SYD_EXT2_APPEND_FL);

out:
	close(fd);
	return 0;
}

int syd_extfs_set_append_only(const char *filename, bool on)
{
	int fd, r = 0;
	unsigned long flags;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;
	if ((r = syd_extfs_get_flags(fd, &flags)) < 0)
		goto out;
	if (flags & SYD_EXT2_APPEND_FL) {
		if (on)
			return 0;
		flags &= ~SYD_EXT2_APPEND_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	} else if (on) {
		flags |= SYD_EXT2_APPEND_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	}
out:
	close(fd);
	return r;
}

int syd_extfs_get_undeletable(const char *filename, bool *undeletable)
{
	int fd;

	if (!undeletable)
		return -EINVAL;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;

	unsigned long flags;
	int r = syd_extfs_get_flags(fd, &flags);
	if (r < 0)
		goto out;
	*undeletable = !!(flags & SYD_EXT2_UNRM_FL);

out:
	close(fd);
	return 0;
}

int syd_extfs_set_undeletable(const char *filename, bool on)
{
	int fd, r = 0;
	unsigned long flags;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;
	if ((r = syd_extfs_get_flags(fd, &flags)) < 0)
		goto out;
	if (flags & SYD_EXT2_SECRM_FL) {
		if (on)
			return 0;
		flags &= ~SYD_EXT2_UNRM_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	} else if (on) {
		flags |= SYD_EXT2_UNRM_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	}
out:
	close(fd);
	return r;
}

int syd_extfs_get_secure_delete(const char *filename, bool *sec_delete)
{
	int fd;

	if (!sec_delete)
		return -EINVAL;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;

	unsigned long flags;
	int r = syd_extfs_get_flags(fd, &flags);
	if (r < 0)
		goto out;
	*sec_delete = !!(flags & SYD_EXT2_SECRM_FL);

out:
	close(fd);
	return 0;
}

int syd_extfs_set_secure_delete(const char *filename, bool on)
{
	int fd, r = 0;
	unsigned long flags;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;
	if ((r = syd_extfs_get_flags(fd, &flags)) < 0)
		goto out;
	if (flags & SYD_EXT2_SECRM_FL) {
		if (on)
			return 0;
		flags &= ~SYD_EXT2_SECRM_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	} else if (on) {
		flags |= SYD_EXT2_SECRM_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	}
out:
	close(fd);
	return r;
}

int syd_extfs_get_immutable(const char *filename, bool *immutable)
{
	int fd;

	if (!immutable)
		return -EINVAL;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;

	unsigned long flags;
	int r = syd_extfs_get_flags(fd, &flags);
	if (r < 0)
		goto out;
	*immutable = !!(flags & SYD_EXT2_IMMUTABLE_FL);

out:
	close(fd);
	return 0;
}

int syd_extfs_set_immutable(const char *filename, bool on)
{
	int fd, r = 0;
	unsigned long flags;

	if ((fd = openat(AT_FDCWD, filename, O_RDONLY|O_NONBLOCK)) < 0)
		return -errno;
	if ((r = syd_extfs_get_flags(fd, &flags)) < 0)
		goto out;
	if (flags & SYD_EXT2_IMMUTABLE_FL) {
		if (on)
			return 0;
		flags &= ~SYD_EXT2_IMMUTABLE_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	} else if (on) {
		flags |= SYD_EXT2_IMMUTABLE_FL;
		r = syd_extfs_set_flags(fd, flags);
		goto out;
	}
out:
	close(fd);
	return r;
}

int syd_extfs_get_flags(int fd, unsigned long *flags)
{
	if (!flags)
		return -EINVAL;
	if (ioctl(fd, SYD_EXT2_IOC_GETFLAGS, flags) < 0)
		return -errno;
	return 0;
}

int syd_extfs_set_flags(int fd, unsigned long flags)
{
	if (!flags)
		return 0;
	if (ioctl(fd, SYD_EXT2_IOC_SETFLAGS, &flags) == -1)
		return -errno;
	return 0;
}
