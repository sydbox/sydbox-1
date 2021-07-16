/*
 * sydbox/sydsys.h
 *
 * SydBox' Default Allow & Deny Lists for modern Linux systems.
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

static const char *const syd_system_allowlist[UINT8_MAX] = {
	"allowlist/exec+/s?bin/***"
	"allowlist/exec+/usr/s?bin/***",
	"allowlist/exec+/usr/libexec/***",
	"allowlist/exec+/usr/local/s?bin/***",
	"allowlist/read+/etc/***", /* Let the denylist do their job. */
	"allowlist/read+/home/***", /* ditto */
	"allowlist/read+/opt/***",
	"allowlist/read+/usr/***",
	"allowlist/read+"SYD_PATH_PASSWD,
	"allowlist/read+"SYD_PATH_GROUP,
	"allowlist/read+"SYD_PATH_SHELLS,
	"allowlist/read+"SYD_PATH_OS_RELEASE_ETC,
	"allowlist/read+"SYD_PATH_OS_RELEASE_USR,
	"allowlist/read+"SYD_PATH_LOGINDEFS,
	"allowlist/read+"SYD_PATH_WORDS,
	"allowlist/read+"SYD_PATH_WORDS_ALT,
	"allowlist/read+"SYD_PATH_FILESYSTEMS
	"allowlist/read+"SYD_PATH_PROC_SWAPS,
	"allowlist/read+"SYD_PATH_PROC_MOUNTS,
	"allowlist/read+"SYD_PATH_PROC_PARTITIONS,
	"allowlist/read+"SYD_PATH_HUSHLOGIN"*",
	"allowlist/read+"SYD_PATH_HUSHLOGINS"*",
	"allowlist/read+"SYD_PATH_NOLOGIN"*",
	"allowlist/read+"SYD_PATH_NOLOGIN"*",
	"allowlist/read+"SYD_PATH_VAR_NOLOGIN"/***",
	"allowlist/read+"SYD_PATH_FILESYSTEMS"*",
	"allowlist/read+"SYD_PATH_PROC_SWAPS"*",
	"allowlist/read+"SYD_PATH_PROC_FILESYSTEMS"*",
	"allowlist/read+"SYD_PATH_PROC_MOUNTS"*",
	"allowlist/read+/"SYD_PATH_MOUNTED"*",
	"allowlist/read+"SYD_PATH_MNTTAB"*",

	"allowlist/read+/proc",
	"allowlist/read+/proc/[0-9]+/***",
	"allowlist/read+/sys/***",

	"allowlist/read+/lib*/***",
	"allowlist/read+/usr/lib*/***",
	"allowlist/read+/usr/local/lib*/***",

	"allowlist/read+/tmp/***",
	"allowlist/read+"SYD_PATH_TMP"/***",
	"allowlist/read+"SYD_PATH_BTMP"/***",

	"allowlist/write+/dev/stdout",
	"allowlist/write+/dev/stderr",
	"allowlist/write+/dev/zero",
	"allowlist/write+/dev/null",
	"allowlist/write+/dev/full",
	"allowlist/write+/dev/console",
	"allowlist/write+/dev/random",
	"allowlist/write+/dev/urandom",
	"allowlist/write+/dev/ptmx",
	"allowlist/write+/dev/fd/***",
	"allowlist/write+/dev/tty*",
	"allowlist/write+/dev/pty*",
	"allowlist/write+/dev/tts",
	"allowlist/write+/dev/pts/***",
	"allowlist/write+/dev/shm/***",
	"allowlist/write+/selinux/context/***",
	"allowlist/write+/proc/self/attr/***",
	"allowlist/write+/proc/self/fd/***",
	"allowlist/write+/proc/self/task/***",
	"allowlist/write+/tmp/***",
	"allowlist/write+/var/tmp/***",
	"allowlist/write+"SYD_PATH_BTMP"/***",
	"allowlist/write+/var/cache/***",
	"allowlist/write+/dev/stdout",
	"allowlist/network/bind+LOOPBACK@0",
	"allowlist/network/bind+LOOPBACK@1024-65535",
	"allowlist/network/bind+LOOPBACK6@0",
	"allowlist/network/bind+LOOPBACK6@1024-65535",
	"allowlist/network/connect+unix:/var/run/nscd/socket",
	"allowlist/network/connect+unix:/run/nscd/socket",
	"allowlist/network/connect+unix:/var/lib/sss/pipes/nss",
	/* Allow getaddrinfo() with AI_ADDRCONFIG on musl systems */
	"allowlist/network/connect+LOOPBACK@65535",
	"allowlist/network/connect+LOOPBACK6@65535",
	NULL,
};

static const char *const syd_system_denylist[UINT8_MAX] = {
	/***
	 * LibSyd PATH constants.
	 ***/
	"**/"SYD_PATH_SHUTDOWN"*",
	"**/"SYD_PATH_POWEROFF"*",
	"**/"SYD_PATH_GSHADOW"*",
	"**/"SYD_PATH_SHADOW_PASSWD"*",

#if 0
#warning TODO make this a game
#warning The task of the wizard is to turn the NumLock on.
	"**/"SYD_PATH_NUMLOCK_ON"*",
	"**/"SYD_PATH_ADJTIME"*",
	"**/[0-9]+/*comm*",
	"**/uptime*",
	"**/"SYD_PATH_PROC_CDROMINFO"*",
#endif

	"**/"SYD_PATH_DEV"/[f-s][a-z][a-z]",
	"**/"SYD_PATH_DEV"/[f-s][a-z][a-z][0-9]+",
	/***/

	"**/sys/kernel/*boot*/***",
	"**/sys/kernel/*config*/***",
	"**/sys/kernel/notes*",
	"**/sysvipc/***",

	"**/block/***",
	"**/raw*/***",
	"**/class/***",
	"**/bus/scsi/***",

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
	"**/nvram",
	"**/udmabuf",
	"**/uhid",
	"**/i2c-[0-9]*"
	"**/sg[0-9]*",
	"**/nvme*",
	"**/hidraw*",
	"**/loop*",
	"**/autofs",
	"**/btrfs-control",
	"**/proc/core*",
	"**/dm*/***",
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
	"**/[0-9]+/*auxv*",
	"**/[0-9]+/*core*",
	"**/[0-9]+/*stack*",
	"**/[0-9]+/map_files/***",
	"**/[0-9]*/mem*",
	"**/proc/config*",
	"**/k?mem*",
	"**/kmsg*",
	"**/iomem*",
	"**/kallsyms",
	"**/kcore",
	"**/swaps",
	"**/version",
	"**/log/*audit*",
	"**/log/*auth*",
	NULL,

#if 0
	"**/partitions*",
	"**/devices*",
	"**/locks*",
	"**/mountinfo*",
	"**/cap_last_cap*",
	"**/interrupts*",
	"**/softirqs*",
	"**/*rtc[0-9]*",
	"**/dev/char/***",
#endif

#if 0
	"**/sys/kernel/*cgroup*/***",
	"**/sys/kernel/*debug*/***",
	"**/sys/kernel/*irq*/***",
	"**/sys/kernel/*fscaps*",
	"**/sys/kernel/*event*",
	"**/sys/kernel/*mm*/***",
	"**/sys/kernel/*prof*",
	"**/sys/kernel/*rcu*",
	"**/sys/kernel/*sec*",
	"**/sys/kernel/*slab*",
	"**/sys/kernel/*core*",
#endif

#if 0
	"**/[0-9]*/mountinfo*",
	"**/[0-9]*/uid_map*",
	"**/[0-9]*/gid_map*",
	"**/[0-9]*/limits*",
	"**/[0-9]*/loginuid*",
	"**/[0-9]*/setgroups*",
	"**/[0-9]*/fd/***",
	"**/[0-9]*/attr/current*",
	"**/[0-9]*/attr/exec*",
	"**/[0-9]+/*arch_status*",
	"**/[0-9]+/*autogroup*",
	"**/[0-9]+/*attr*",
	"**/[0-9]+/*cgroup*",
	"**/[0-9]+/*clear_refs*",
	"**/[0-9]+/*cpu*",
	"**/[0-9]+/*environ*",
	"**/[0-9]+/*fdinfo*/***",
	"**/[0-9]+/*map*",
	"**/[0-9]+/*patch*",
	"**/[0-9]+/*personality*",
	"**/[0-9]+/*sched*",
	"**/[0-9]+/*net*",
	"**/[0-9]+/*ns*",
	"**/[0-9]+/mounts",
	"**/[0-9]+/io*",
	"**/[0-9]+/oom*",
	"**/[0-9]+/*sys*",
	"**/[0-9]+/task/***",
	"**/[0-9]+/*time*",
	"**/[0-9]+/*chan*",

	"**/hugepages/***",
	"**/net/***",
	"**/fb[0-9]*",
	"**/fuse",
	"**/vmstat",
	"**/fs/***",
#endif
};
