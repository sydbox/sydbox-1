/*
 * sydbox/sydsys.h
 *
 * SydBox' Default DenyList for modern Linux systems.
 * Report if you find something here that shouldn't be
 * or you know something that is important to be in here.
 * Thanks in advance.
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "HELPME.h"
#include <limits.h>
#include <stdio.h>
static const char *const syd_system_denylist[UINT8_MAX] = {
	/***
	 * LibSyd PATH constants.
	 ***/
	"**/"SYD_PATH_HUSHLOGIN"*",
	"**/"SYD_PATH_HUSHLOGINS"*",
	"**/"SYD_PATH_NOLOGIN"*",
	"**/"SYD_PATH_MAILDIR"/***",
	"**/"SYD_PATH_NOLOGIN"*",
	"**/"SYD_PATH_VAR_NOLOGIN"/***",
	"**/"SYD_PATH_LOGIN"*",
	"**/"SYD_PATH_SHUTDOWN"*",
	"**/"SYD_PATH_POWEROFF"*",
	"**/"SYD_PATH_GSHADOW"*",
	"**/"SYD_PATH_SHADOW_PASSWD"*",

	"**/"SYD_PATH_BTMP"/***",
	"**/"SYD_PATH_OS_RELEASE_ETC"*",
	"**/"SYD_PATH_OS_RELEASE_USR"*",
#if 0
#warning TODO make this a game
#warning The task of the wizard is to turn the NumLock on.
	"**/"SYD_PATH_NUMLOCK_ON"*",
	"**/"SYD_PATH_ADJTIME"*",
	"**/[0-9]+/*comm*",
	"**/uptime*",
#endif
	"**/"SYD_PATH_PROC_CDROMINFO"*",

	"**/"SYD_PATH_FILESYSTEMS"*",
	"**/"SYD_PATH_PROC_SWAPS"*",
	"**/"SYD_PATH_PROC_FILESYSTEMS"*",
	"**/"SYD_PATH_PROC_MOUNTS"*",

	"**/"SYD_PATH_MOUNTED"*",
	"**/"SYD_PATH_MNTTAB"*",

	"**/"SYD_PATH_DEV"/[f-s][a-z][a-z]",
	/***/

	"**/partitions*",
	"**/devices*",
	"**/locks*",
	"**/mountinfo*",
	"**/cap_last_cap*",
	"**/sys/kernel/*boot*/***",
	"**/sys/kernel/*config*/***",
	"**/sys/kernel/*cgroup*/***",
	"**/sys/kernel/*debug*/***",
	"**/sys/kernel/*irq*/***",
	"**/sys/kernel/*fscaps*",
	"**/sys/kernel/*mm*/***",
	"**/sys/kernel/notes*",
	"**/sys/kernel/*event*",
	"**/sys/kernel/*prof*",
	"**/sys/kernel/*rcu*",
	"**/sys/kernel/*sec*",
	"**/sys/kernel/*slab*",
	"**/sys/kernel/*core*",
	"**/sysvipc/***",
	"**/interrupts*",
	"**/softirqs*",
	"**/cmdline*",

	"**/block/***",
	"**/*rtc[0-9]*",
	"**/raw*/***",
	"**/class/***",
	"**/bus/scsi/***",
	"**/dev/char/***",
	"**/dev/log",

	"**/[0-9]*/mountinfo*",
	"**/[0-9]*/uid_map*",
	"**/[0-9]*/gid_map*",
	"**/[0-9]*/limits*",
	"**/[0-9]*/loginuid*",
	"**/[0-9]*/setgroups*",
	"**/[0-9]*/fd/***",
	"**/[0-9]*/attr/current*",
	"**/[0-9]*/attr/exec*",

	"**/boot/***",
	"**/root/***",
	"**/bus/***",
	"**/disk/by-id/***",
	"**/disk/by-label/***",
	"**/disk/by-partlabel/***",
	"**/disk/by-partuuid/***",
	"**/disk/by-path/***",
	"**/disk/by-uuid/***",
	"**/block/***",
	"**/[hs][a-z][a-z][0-9][0-9]*",
	"**/rfkill",
	"**/zfs",
	"**/v4l/***",
	"**/vcs",
	"**/vcs[a-z]",
	"**/vcs[0-9]",
	"**/vcs[a-z][0-9]",
	"**/usb/***",
	"**/tpm*",
	"**/snd/***",
	"**/input/***",
	"**/adsp",
	"**/dri/***",
	"**/dma_heap/***",
	"**/dsp",
	"**/hpet",
	"**/hugepages/***",
	"**/nvram",
	"**/udmabuf",
	"**/uhid",
	"**/i2c-[0-9]*"
	"**/net/***",
	"**/fb[0-9]*",
	"**/sg[0-9]*",
	"**/nvme*",
	"**/hidraw*",
	"**/loop*",
	"**/autofs",
	"**/btrfs-control",
	"**/proc/core*",
	"**/dm*/***",
	"**/fuse",
	"**/mapper/***",
	"**/port",
	"**/ram*",
	"**/u?random",
	"**/usb*",
	"**/vga_arbiter",
	"**/watchdog*",
	"**/zram*",
	"**/crypttab",
	"**/securetty",
	"**/security/***",
	"**/.gnupg*",
	"**/.netrc*",
	"**/.password-store/***",
	"**/id_[dr]sa",
	"**/id_ecdsa",
	"**/id_ecdsa-sk",
	"**/id_ed25519",
	"**/id_ed25519-sk",
	"**/[0-9]+/*arch_status*",
	"**/[0-9]+/*autogroup*",
	"**/[0-9]+/*attr*",
	"**/[0-9]+/*auxv*",
	"**/[0-9]+/*cgroup*",
	"**/[0-9]+/*clear_refs*",
	"**/[0-9]+/*cmdline*",
	"**/[0-9]+/*core*",
	"**/[0-9]+/*cpu*",
	"**/[0-9]+/*environ*",
	"**/[0-9]+/*fdinfo*/***",
	"**/[0-9]+/*map*",
	"**/[0-9]+/*patch*",
	"**/[0-9]+/*personality*",
	"**/[0-9]+/*sched*",
	"**/[0-9]+/*stack*",
	"**/[0-9]+/*net*",
	"**/[0-9]+/*ns*",
	"**/[0-9]+/map_files/***",
	"**/[0-9]*/mem*",
	"**/dev/k?mem*",
	"**/kmem*",
	"**/kmsg*",
	"**/iomem",
	"**/[0-9]+/mounts",
	"**/[0-9]+/io*",
	"**/[0-9]+/oom*",
	"**/[0-9]+/*sys*",
	"**/[0-9]+/task/***",
	"**/[0-9]+/*time*",
	"**/[0-9]+/*chan*",
	"**/proc/config*",
	"**/kallsyms",
	"**/kcore",
	"**/swaps",
	"**/version",
	"**/vmstat",
	"**/fs/***",
	"**/log/*audit*",
	"**/log/*auth*",
	NULL,
};
