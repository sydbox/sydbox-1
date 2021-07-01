/*
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only
 */


#ifndef SYD_GUARD_RS_H
#define SYD_GUARD_RS_H

#pragma once

/* Generated with cbindgen:0.19.0 */

#if 0
# *********************************************************
# THIS IS A GENERATED FILE! DO NOT EDIT THIS FILE DIRECTLY!
# *********************************************************
#
#endif


#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <seccomp.h>
#include <unistd.h>
#include "syd/compiler.h"

/*
Print SydB☮x version and build details to standard error.
 */
void syd_about(void);

/*
Execute a process under various restrictions and options.
 */
SYD_GCC_ATTR((warn_unused_result))
int32_t syd_execv(const char *command,
                  char **args,
                  const char *alias,
                  const char *workdir,
                  bool verbose,
                  uint32_t uid,
                  uint32_t gid,
                  const char *chroot,
                  bool unshare_pid,
                  bool unshare_net,
                  bool unshare_mount,
                  bool unshare_uts,
                  bool unshare_ipc,
                  bool unshare_user,
                  bool escape_stdout,
                  const uint32_t *supplementary_gids,
                  const char *pid_env_var);

#endif /* SYD_GUARD_RS_H */
