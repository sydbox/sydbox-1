/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2011, 2012 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Sydbox. sydbox is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * sydbox is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "sydbox-defs.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int sys_link(struct pink_easy_process *current, const char *name)
{
	int r;
	sys_info_t info;
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (sandbox_write_off(data))
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.whitelisting = sandbox_write_deny(data);

	r = box_check_path(current, name, &info);
	if (!r && !data->deny) {
		info.create = MUST_CREATE;
		info.index  = 1;
		return box_check_path(current, name, &info);
	}

	return r;
}

int sys_linkat(struct pink_easy_process *current, const char *name)
{
	int r;
	long flags;
	pid_t tid = pink_easy_process_get_tid(current);
	enum pink_abi abi = pink_easy_process_get_abi(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (sandbox_write_off(data))
		return 0;

	/* Check for AT_SYMLINK_FOLLOW */
	if (!pink_read_argument(tid, abi, &data->regs, 4, &flags)) {
		if (errno != ESRCH) {
			warning("pink_read_argument(%lu, %d, 4) failed (errno:%d %s)",
					(unsigned long)tid, abi,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sys_info_t));
	info.at     = true;
	info.resolv = !!(flags & AT_SYMLINK_FOLLOW);
	info.index  = 1;
	info.whitelisting = sandbox_write_deny(data);

	r = box_check_path(current, name, &info);
	if (!r && !data->deny) {
		info.create = MAY_CREATE;
		info.index  = 3;
		return box_check_path(current, name, &info);
	}

	return r;
}
