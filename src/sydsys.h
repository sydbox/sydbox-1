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
#include <stdio.h>
static const char *const syd_system_denylist[55] = {
	"**/boot/***",
	"**/root/***",
	"**/autofs",
	"**/btrfs-control",
	"**/core",
	"**/dm*/***",
	"**/fuse",
	"**/k?mem",
	"**/kmsg",
	"**/mapper/***",
	"**/port",
	"**/ram*",
	"**/usb*",
	"**/vga_arbiter",
	"**/watchdog*",
	"**/zram*",
	"**/crypttab",
	"**/g?shadow*",
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
	"**/*map*",
	"**/*stat*",
	"**/map_files/***",
	"**/mem",
	"**/mount*",
	"**/oom*",
	"**/setgroups",
	"**/syscall",
	"**/task",
	"**/proc/config*",
	"**/cpuinfo",
	"**/iomem",
	"**/kallsyms",
	"**/kcore",
	"**/meminfo",
	"**/slabinfo",
	"**/swaps",
	"**/version",
	"**/vmallocinfo",
	"**/vmstat",
	"**/root/***",
	"**/fs/***",
	"**/log/*audit*",
	"**/log/*auth*",
	NULL,
};
