/*
 * libsyd/exec.c
 *
 * libsyd restricted process execution
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

SYD_GCC_ATTR((warn_unused_result))
int32_t syd_execv(const char *command,
                  size_t argc,
                  const char *const *argv,
                  const char *alias,
                  const char *workdir,
                  bool _verbose,
                  uint32_t uid,
                  uint32_t gid,
                  const char *chroot,
                  const char *new_root,
                  const char *put_old,
                  bool unshare_pid,
                  bool unshare_net,
                  bool unshare_mount,
                  bool unshare_uts,
                  bool unshare_ipc,
                  bool unshare_user,
                  int32_t close_fds_beg,
                  int32_t close_fds_end,
                  bool reset_fds,
                  bool keep_sigmask,
                  bool escape_stdout,
                  bool allow_daemonize,
                  bool make_group_leader,
                  const char *parent_death_signal,
                  const uint32_t *supplementary_gids,
                  const char *pid_env_var)
{
	return 0;
}


