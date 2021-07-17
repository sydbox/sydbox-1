/*
 * sydbox/syscall-filter.c
 *
 * Simple seccomp based system call filters
 *
 * Copyright (c) 2013, 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon Tor's sandbox which is
 *   Copyright (c) 2001 Matej Pfajfar.
 *   Copyright (c) 2001-2004, Roger Dingledine.
 *   Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 *   Copyright (c) 2007-2021, The Tor Project, Inc.
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "syd-box.h"
#include "daemon.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/kd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/vt.h>
#include <asm/unistd.h>

#include <sys/types.h>
#include <signal.h>
#ifdef HAVE_ASM_SIGNAL_H
#include <asm/signal.h>
#endif

/*
 * ++ Note on Level 0 and TOCTOU attacks ++
 *
 * Level 0 filter is always applied regardless of the value of
 * the magic command core/restrict/general.
 * This is important to improve the security of the sandbox as
 * circumventing the sandbox by a TOCTOU attack is arguably less likely
 * with these system calls permitted.
 */
static const int allow_list_level0[] = {
#ifdef __SNR__llseek
	SCMP_SYS(_llseek),
#endif
#ifdef __SNR__newselect
	SCMP_SYS(_newselect),
#endif
#ifdef __SNR__sysctl
	SCMP_SYS(_sysctl),
#endif
#ifdef __SNR_accept
	SCMP_SYS(accept),
#endif
#ifdef __SNR_accept4
	SCMP_SYS(accept4),
#endif
#ifdef __SNR_access
	SCMP_SYS(access),
#endif
#ifdef __SNR_acct
	SCMP_SYS(acct),
#endif
#if 0
#ifdef __SNR_add_key
	SCMP_SYS(add_key),
#endif
#ifdef __SNR_adjtimex
	SCMP_SYS(adjtimex),
#endif
#ifdef __SNR_afs_syscall
	SCMP_SYS(afs_syscall),
#endif
#endif
#ifdef __SNR_alarm
	SCMP_SYS(alarm),
#endif
#ifdef __SNR_arch_prctl
	SCMP_SYS(arch_prctl),
#endif
#ifdef __SNR_arm_fadvise64_64
	SCMP_SYS(arm_fadvise64_64),
#endif
#ifdef __SNR_arm_sync_file_range
	SCMP_SYS(arm_sync_file_range),
#endif
#ifdef __SNR_bdflush
	SCMP_SYS(bdflush),
#endif
#ifdef __SNR_bind
	SCMP_SYS(bind),
#endif
#ifdef __SNR_bpf
	SCMP_SYS(bpf),
#endif
#ifdef __SNR_break
	SCMP_SYS(break),
#endif
#ifdef __SNR_breakpoint
	SCMP_SYS(breakpoint),
#endif
#ifdef __SNR_brk
	SCMP_SYS(brk),
#endif
#ifdef __SNR_cachectl
	SCMP_SYS(cachectl),
#endif
#ifdef __SNR_cacheflush
	SCMP_SYS(cacheflush),
#endif
#ifdef __SNR_capget
	SCMP_SYS(capget),
#endif
#ifdef __SNR_capset
	SCMP_SYS(capset),
#endif
#ifdef __SNR_chdir
	SCMP_SYS(chdir),
#endif
#ifdef __SNR_chmod
	SCMP_SYS(chmod),
#endif
#ifdef __SNR_chown
	SCMP_SYS(chown),
#endif
#ifdef __SNR_chown32
	SCMP_SYS(chown32),
#endif
#ifdef __SNR_chroot
	SCMP_SYS(chroot),
#endif
#ifdef __SNR_clock_adjtime
	SCMP_SYS(clock_adjtime),
#endif
#ifdef __SNR_clock_adjtime64
	SCMP_SYS(clock_adjtime64),
#endif
#ifdef __SNR_clock_getres
	SCMP_SYS(clock_getres),
#endif
#ifdef __SNR_clock_getres_time64
	SCMP_SYS(clock_getres_time64),
#endif
#ifdef __SNR_clock_gettime
	SCMP_SYS(clock_gettime),
#endif
#ifdef __SNR_clock_gettime64
	SCMP_SYS(clock_gettime64),
#endif
#ifdef __SNR_clock_nanosleep
	SCMP_SYS(clock_nanosleep),
#endif
#ifdef __SNR_clock_nanosleep_time64
	SCMP_SYS(clock_nanosleep_time64),
#endif
#ifdef __SNR_clock_settime
	SCMP_SYS(clock_settime),
#endif
#ifdef __SNR_clock_settime64
	SCMP_SYS(clock_settime64),
#endif
#ifdef __SNR_clone
	SCMP_SYS(clone),
#endif
#ifdef __SNR_clone3
	SCMP_SYS(clone3),
#endif
#ifdef __SNR_close
	SCMP_SYS(close),
#endif
#ifdef __SNR_connect
	SCMP_SYS(connect),
#endif
#ifdef __SNR_copy_file_range
	SCMP_SYS(copy_file_range),
#endif
#ifdef __SNR_creat
	SCMP_SYS(creat),
#endif
#if 0
#ifdef __SNR_create_module
	SCMP_SYS(create_module),
#endif
#ifdef __SNR_delete_module
	SCMP_SYS(delete_module),
#endif
#endif
#ifdef __SNR_dup
	SCMP_SYS(dup),
#endif
#ifdef __SNR_dup2
	SCMP_SYS(dup2),
#endif
#ifdef __SNR_dup3
	SCMP_SYS(dup3),
#endif
#ifdef __SNR_epoll_create
	SCMP_SYS(epoll_create),
#endif
#ifdef __SNR_epoll_create1
	SCMP_SYS(epoll_create1),
#endif
#ifdef __SNR_epoll_ctl
	SCMP_SYS(epoll_ctl),
#endif
#ifdef __SNR_epoll_ctl_old
	SCMP_SYS(epoll_ctl_old),
#endif
#ifdef __SNR_epoll_pwait
	SCMP_SYS(epoll_pwait),
#endif
#ifdef __SNR_epoll_wait
	SCMP_SYS(epoll_wait),
#endif
#ifdef __SNR_epoll_wait_old
	SCMP_SYS(epoll_wait_old),
#endif
#ifdef __SNR_eventfd
	SCMP_SYS(eventfd),
#endif
#ifdef __SNR_eventfd2
	SCMP_SYS(eventfd2),
#endif
#ifdef __SNR_execve
	SCMP_SYS(execve),
#endif
#ifdef __SNR_execveat
	SCMP_SYS(execveat),
#endif
#ifdef __SNR_exit
	SCMP_SYS(exit),
#endif
#ifdef __SNR_exit_group
	SCMP_SYS(exit_group),
#endif
#ifdef __SNR_faccessat
	SCMP_SYS(faccessat),
#endif
#ifdef __SNR_fadvise64
	SCMP_SYS(fadvise64),
#endif
#ifdef __SNR_fadvise64_64
	SCMP_SYS(fadvise64_64),
#endif
#ifdef __SNR_fallocate
	SCMP_SYS(fallocate),
#endif
#ifdef __SNR_fanotify_init
	SCMP_SYS(fanotify_init),
#endif
#ifdef __SNR_fanotify_mark
	SCMP_SYS(fanotify_mark),
#endif
#ifdef __SNR_fchdir
	SCMP_SYS(fchdir),
#endif
#ifdef __SNR_fchmod
	SCMP_SYS(fchmod),
#endif
#ifdef __SNR_fchmodat
	SCMP_SYS(fchmodat),
#endif
#ifdef __SNR_fchown
	SCMP_SYS(fchown),
#endif
#ifdef __SNR_fchown32
	SCMP_SYS(fchown32),
#endif
#ifdef __SNR_fchownat
	SCMP_SYS(fchownat),
#endif
#ifdef __SNR_fcntl
	SCMP_SYS(fcntl),
#endif
#ifdef __SNR_fcntl64
	SCMP_SYS(fcntl64),
#endif
#ifdef __SNR_fdatasync
	SCMP_SYS(fdatasync),
#endif
#ifdef __SNR_fgetxattr
	SCMP_SYS(fgetxattr),
#endif
#ifdef __SNR_finit_module
	SCMP_SYS(finit_module),
#endif
#ifdef __SNR_flistxattr
	SCMP_SYS(flistxattr),
#endif
#ifdef __SNR_flock
	SCMP_SYS(flock),
#endif
#ifdef __SNR_fork
	SCMP_SYS(fork),
#endif
#ifdef __SNR_fremovexattr
	SCMP_SYS(fremovexattr),
#endif
#ifdef __SNR_fsconfig
	SCMP_SYS(fsconfig),
#endif
#ifdef __SNR_fsetxattr
	SCMP_SYS(fsetxattr),
#endif
#ifdef __SNR_fsmount
	SCMP_SYS(fsmount),
#endif
#ifdef __SNR_fsopen
	SCMP_SYS(fsopen),
#endif
#ifdef __SNR_fspick
	SCMP_SYS(fspick),
#endif
#ifdef __SNR_fstat
	SCMP_SYS(fstat),
#endif
#ifdef __SNR_fstat64
	SCMP_SYS(fstat64),
#endif
#ifdef __SNR_fstatat64
	SCMP_SYS(fstatat64),
#endif
#ifdef __SNR_fstatfs
	SCMP_SYS(fstatfs),
#endif
#ifdef __SNR_fstatfs64
	SCMP_SYS(fstatfs64),
#endif
#ifdef __SNR_fsync
	SCMP_SYS(fsync),
#endif
#ifdef __SNR_ftime
	SCMP_SYS(ftime),
#endif
#ifdef __SNR_ftruncate
	SCMP_SYS(ftruncate),
#endif
#ifdef __SNR_ftruncate64
	SCMP_SYS(ftruncate64),
#endif
#ifdef __SNR_futex
	SCMP_SYS(futex),
#endif
#ifdef __SNR_futex_time64
	SCMP_SYS(futex_time64),
#endif
#ifdef __SNR_futimesat
	SCMP_SYS(futimesat),
#endif
#if 0
#ifdef __SNR_get_kernel_syms
	SCMP_SYS(get_kernel_syms),
#endif
#endif
#ifdef __SNR_get_mempolicy
	SCMP_SYS(get_mempolicy),
#endif
#ifdef __SNR_get_robust_list
	SCMP_SYS(get_robust_list),
#endif
#ifdef __SNR_get_thread_area
	SCMP_SYS(get_thread_area),
#endif
#ifdef __SNR_get_tls
	SCMP_SYS(get_tls),
#endif
#ifdef __SNR_getcpu
	SCMP_SYS(getcpu),
#endif
#ifdef __SNR_getcwd
	SCMP_SYS(getcwd),
#endif
#ifdef __SNR_getdents
	SCMP_SYS(getdents),
#endif
#ifdef __SNR_getdents64
	SCMP_SYS(getdents64),
#endif
#ifdef __SNR_getegid
	SCMP_SYS(getegid),
#endif
#ifdef __SNR_getegid32
	SCMP_SYS(getegid32),
#endif
#ifdef __SNR_geteuid
	SCMP_SYS(geteuid),
#endif
#ifdef __SNR_geteuid32
	SCMP_SYS(geteuid32),
#endif
#ifdef __SNR_getgid
	SCMP_SYS(getgid),
#endif
#ifdef __SNR_getgid32
	SCMP_SYS(getgid32),
#endif
#ifdef __SNR_getgroups
	SCMP_SYS(getgroups),
#endif
#ifdef __SNR_getgroups32
	SCMP_SYS(getgroups32),
#endif
#ifdef __SNR_getitimer
	SCMP_SYS(getitimer),
#endif
#ifdef __SNR_getpeername
	SCMP_SYS(getpeername),
#endif
#ifdef __SNR_getpgid
	SCMP_SYS(getpgid),
#endif
#ifdef __SNR_getpgrp
	SCMP_SYS(getpgrp),
#endif
#ifdef __SNR_getpid
	SCMP_SYS(getpid),
#endif
#ifdef __SNR_getpmsg
	SCMP_SYS(getpmsg),
#endif
#ifdef __SNR_getppid
	SCMP_SYS(getppid),
#endif
#ifdef __SNR_getpriority
	SCMP_SYS(getpriority),
#endif
#ifdef __SNR_getrandom
	SCMP_SYS(getrandom),
#endif
#ifdef __SNR_getresgid
	SCMP_SYS(getresgid),
#endif
#ifdef __SNR_getresgid32
	SCMP_SYS(getresgid32),
#endif
#ifdef __SNR_getresuid
	SCMP_SYS(getresuid),
#endif
#ifdef __SNR_getresuid32
	SCMP_SYS(getresuid32),
#endif
#ifdef __SNR_getrlimit
	SCMP_SYS(getrlimit),
#endif
#ifdef __SNR_getrusage
	SCMP_SYS(getrusage),
#endif
#ifdef __SNR_getsid
	SCMP_SYS(getsid),
#endif
#ifdef __SNR_getsockname
	SCMP_SYS(getsockname),
#endif
#ifdef __SNR_getsockopt
	SCMP_SYS(getsockopt),
#endif
#ifdef __SNR_gettid
	SCMP_SYS(gettid),
#endif
#ifdef __SNR_gettimeofday
	SCMP_SYS(gettimeofday),
#endif
#ifdef __SNR_getuid
	SCMP_SYS(getuid),
#endif
#ifdef __SNR_getuid32
	SCMP_SYS(getuid32),
#endif
#ifdef __SNR_getxattr
	SCMP_SYS(getxattr),
#endif
#if 0
#ifdef __SNR_gtty
	SCMP_SYS(gtty),
#endif
#endif
#ifdef __SNR_idle
	SCMP_SYS(idle),
#endif
#if 0
#ifdef __SNR_init_module
	SCMP_SYS(init_module),
#endif
#endif
#ifdef __SNR_inotify_add_watch
	SCMP_SYS(inotify_add_watch),
#endif
#ifdef __SNR_inotify_init
	SCMP_SYS(inotify_init),
#endif
#ifdef __SNR_inotify_init1
	SCMP_SYS(inotify_init1),
#endif
#ifdef __SNR_inotify_rm_watch
	SCMP_SYS(inotify_rm_watch),
#endif
#ifdef __SNR_io_cancel
	SCMP_SYS(io_cancel),
#endif
#ifdef __SNR_io_destroy
	SCMP_SYS(io_destroy),
#endif
#ifdef __SNR_io_getevents
	SCMP_SYS(io_getevents),
#endif
#ifdef __SNR_io_pgetevents
	SCMP_SYS(io_pgetevents),
#endif
#ifdef __SNR_io_pgetevents_time64
	SCMP_SYS(io_pgetevents_time64),
#endif
#ifdef __SNR_io_setup
	SCMP_SYS(io_setup),
#endif
#ifdef __SNR_io_submit
	SCMP_SYS(io_submit),
#endif
#ifdef __SNR_io_uring_enter
	SCMP_SYS(io_uring_enter),
#endif
#ifdef __SNR_io_uring_register
	SCMP_SYS(io_uring_register),
#endif
#ifdef __SNR_io_uring_setup
	SCMP_SYS(io_uring_setup),
#endif
#ifdef __SNR_ioctl
	SCMP_SYS(ioctl),
#endif
#ifdef __SNR_ioperm
	SCMP_SYS(ioperm),
#endif
#ifdef __SNR_iopl
	SCMP_SYS(iopl),
#endif
#ifdef __SNR_ioprio_get
	SCMP_SYS(ioprio_get),
#endif
#ifdef __SNR_ioprio_set
	SCMP_SYS(ioprio_set),
#endif
#ifdef __SNR_ipc
	SCMP_SYS(ipc),
#endif
#ifdef __SNR_kcmp
	SCMP_SYS(kcmp),
#endif
#if 0
#ifdef __SNR_kexec_file_load
	SCMP_SYS(kexec_file_load),
#endif
#ifdef __SNR_kexec_load
	SCMP_SYS(kexec_load),
#endif
#ifdef __SNR_keyctl
	SCMP_SYS(keyctl),
#endif
#endif
#ifdef __SNR_kill
	SCMP_SYS(kill),
#endif
#ifdef __SNR_lchown
	SCMP_SYS(lchown),
#endif
#ifdef __SNR_lchown32
	SCMP_SYS(lchown32),
#endif
#ifdef __SNR_lgetxattr
	SCMP_SYS(lgetxattr),
#endif
#ifdef __SNR_link
	SCMP_SYS(link),
#endif
#ifdef __SNR_linkat
	SCMP_SYS(linkat),
#endif
#ifdef __SNR_listen
	SCMP_SYS(listen),
#endif
#ifdef __SNR_listxattr
	SCMP_SYS(listxattr),
#endif
#ifdef __SNR_llistxattr
	SCMP_SYS(llistxattr),
#endif
#ifdef __SNR_lock
	SCMP_SYS(lock),
#endif
#ifdef __SNR_lookup_dcookie
	SCMP_SYS(lookup_dcookie),
#endif
#ifdef __SNR_lremovexattr
	SCMP_SYS(lremovexattr),
#endif
#ifdef __SNR_lseek
	SCMP_SYS(lseek),
#endif
#ifdef __SNR_lsetxattr
	SCMP_SYS(lsetxattr),
#endif
#ifdef __SNR_lstat
	SCMP_SYS(lstat),
#endif
#ifdef __SNR_lstat64
	SCMP_SYS(lstat64),
#endif
#ifdef __SNR_madvise
	SCMP_SYS(madvise),
#endif
#ifdef __SNR_mbind
	SCMP_SYS(mbind),
#endif
#ifdef __SNR_membarrier
	SCMP_SYS(membarrier),
#endif
#ifdef __SNR_memfd_create
	SCMP_SYS(memfd_create),
#endif
#ifdef __SNR_migrate_pages
	SCMP_SYS(migrate_pages),
#endif
#ifdef __SNR_mincore
	SCMP_SYS(mincore),
#endif
#ifdef __SNR_mkdir
	SCMP_SYS(mkdir),
#endif
#ifdef __SNR_mkdirat
	SCMP_SYS(mkdirat),
#endif
#ifdef __SNR_mknod
	SCMP_SYS(mknod),
#endif
#ifdef __SNR_mknodat
	SCMP_SYS(mknodat),
#endif
#ifdef __SNR_mlock
	SCMP_SYS(mlock),
#endif
#ifdef __SNR_mlock2
	SCMP_SYS(mlock2),
#endif
#ifdef __SNR_mlockall
	SCMP_SYS(mlockall),
#endif
#ifdef __SNR_mmap
	SCMP_SYS(mmap),
#endif
#ifdef __SNR_mmap2
	SCMP_SYS(mmap2),
#endif
#ifdef __SNR_modify_ldt
	SCMP_SYS(modify_ldt),
#endif
#ifdef __SNR_mount
	SCMP_SYS(mount),
#endif
#ifdef __SNR_move_mount
	SCMP_SYS(move_mount),
#endif
#ifdef __SNR_move_pages
	SCMP_SYS(move_pages),
#endif
#ifdef __SNR_mprotect
	SCMP_SYS(mprotect),
#endif
#ifdef __SNR_mpx
	SCMP_SYS(mpx),
#endif
#ifdef __SNR_mq_getsetattr
	SCMP_SYS(mq_getsetattr),
#endif
#ifdef __SNR_mq_notify
	SCMP_SYS(mq_notify),
#endif
#ifdef __SNR_mq_open
	SCMP_SYS(mq_open),
#endif
#ifdef __SNR_mq_timedreceive
	SCMP_SYS(mq_timedreceive),
#endif
#ifdef __SNR_mq_timedreceive_time64
	SCMP_SYS(mq_timedreceive_time64),
#endif
#ifdef __SNR_mq_timedsend
	SCMP_SYS(mq_timedsend),
#endif
#ifdef __SNR_mq_timedsend_time64
	SCMP_SYS(mq_timedsend_time64),
#endif
#ifdef __SNR_mq_unlink
	SCMP_SYS(mq_unlink),
#endif
#ifdef __SNR_mremap
	SCMP_SYS(mremap),
#endif
#ifdef __SNR_msgctl
	SCMP_SYS(msgctl),
#endif
#ifdef __SNR_msgget
	SCMP_SYS(msgget),
#endif
#ifdef __SNR_msgrcv
	SCMP_SYS(msgrcv),
#endif
#ifdef __SNR_msgsnd
	SCMP_SYS(msgsnd),
#endif
#ifdef __SNR_msync
	SCMP_SYS(msync),
#endif
#ifdef __SNR_multiplexer
	SCMP_SYS(multiplexer),
#endif
#ifdef __SNR_munlock
	SCMP_SYS(munlock),
#endif
#ifdef __SNR_munlockall
	SCMP_SYS(munlockall),
#endif
#ifdef __SNR_munmap
	SCMP_SYS(munmap),
#endif
#ifdef __SNR_name_to_handle_at
	SCMP_SYS(name_to_handle_at),
#endif
#ifdef __SNR_nanosleep
	SCMP_SYS(nanosleep),
#endif
#ifdef __SNR_newfstatat
	SCMP_SYS(newfstatat),
#endif
#if 0
#ifdef __SNR_nfsservctl
	SCMP_SYS(nfsservctl),
#endif
#endif
#ifdef __SNR_nice
	SCMP_SYS(nice),
#endif
#ifdef __SNR_oldfstat
	SCMP_SYS(oldfstat),
#endif
#ifdef __SNR_oldlstat
	SCMP_SYS(oldlstat),
#endif
#ifdef __SNR_oldolduname
	SCMP_SYS(oldolduname),
#endif
#ifdef __SNR_oldstat
	SCMP_SYS(oldstat),
#endif
#ifdef __SNR_olduname
	SCMP_SYS(olduname),
#endif
#ifdef __SNR_oldwait4
	SCMP_SYS(oldwait4),
#endif
#ifdef __SNR_open
	SCMP_SYS(open),
#endif
#ifdef __SNR_open_by_handle_at
	SCMP_SYS(open_by_handle_at),
#endif
#ifdef __SNR_open_tree
	SCMP_SYS(open_tree),
#endif
#ifdef __SNR_openat
	SCMP_SYS(openat),
#endif
#ifdef __SNR_pause
	SCMP_SYS(pause),
#endif
#if 0
#ifdef __SNR_pciconfig_iobase
	SCMP_SYS(pciconfig_iobase),
#endif
#ifdef __SNR_pciconfig_read
	SCMP_SYS(pciconfig_read),
#endif
#ifdef __SNR_pciconfig_write
	SCMP_SYS(pciconfig_write),
#endif
#endif
#ifdef __SNR_perf_event_open
	SCMP_SYS(perf_event_open),
#endif
#ifdef __SNR_personality
	SCMP_SYS(personality),
#endif
#ifdef __SNR_pidfd_open
	SCMP_SYS(pidfd_open),
#endif
#ifdef __SNR_pidfd_send_signal
	SCMP_SYS(pidfd_send_signal),
#endif
#ifdef __SNR_pipe
	SCMP_SYS(pipe),
#endif
#ifdef __SNR_pipe2
	SCMP_SYS(pipe2),
#endif
#ifdef __SNR_pivot_root
	SCMP_SYS(pivot_root),
#endif
#ifdef __SNR_pkey_alloc
	SCMP_SYS(pkey_alloc),
#endif
#ifdef __SNR_pkey_free
	SCMP_SYS(pkey_free),
#endif
#ifdef __SNR_pkey_mprotect
	SCMP_SYS(pkey_mprotect),
#endif
#ifdef __SNR_poll
	SCMP_SYS(poll),
#endif
#ifdef __SNR_ppoll
	SCMP_SYS(ppoll),
#endif
#ifdef __SNR_ppoll_time64
	SCMP_SYS(ppoll_time64),
#endif
#ifdef __SNR_prctl
	SCMP_SYS(prctl),
#endif
#ifdef __SNR_pread64
	SCMP_SYS(pread64),
#endif
#ifdef __SNR_preadv
	SCMP_SYS(preadv),
#endif
#ifdef __SNR_preadv2
	SCMP_SYS(preadv2),
#endif
#ifdef __SNR_prlimit64
	SCMP_SYS(prlimit64),
#endif
#if 0
#ifdef __SNR_process_vm_readv
	SCMP_SYS(process_vm_readv),
#endif
#ifdef __SNR_process_vm_writev
	SCMP_SYS(process_vm_writev),
#endif
#ifdef __SNR_prof
	SCMP_SYS(prof),
#endif
#endif
#ifdef __SNR_profil
	SCMP_SYS(profil),
#endif
#ifdef __SNR_pselect6
	SCMP_SYS(pselect6),
#endif
#ifdef __SNR_pselect6_time64
	SCMP_SYS(pselect6_time64),
#endif
#if 0
#ifdef __SNR_ptrace
	SCMP_SYS(ptrace),
#endif
#endif
#ifdef __SNR_putpmsg
	SCMP_SYS(putpmsg),
#endif
#ifdef __SNR_pwrite64
	SCMP_SYS(pwrite64),
#endif
#ifdef __SNR_pwritev
	SCMP_SYS(pwritev),
#endif
#ifdef __SNR_pwritev2
	SCMP_SYS(pwritev2),
#endif
#if 0
#ifdef __SNR_query_module
	SCMP_SYS(query_module),
#endif
#endif
#ifdef __SNR_quotactl
	SCMP_SYS(quotactl),
#endif
#ifdef __SNR_read
	SCMP_SYS(read),
#endif
#ifdef __SNR_readahead
	SCMP_SYS(readahead),
#endif
#ifdef __SNR_readdir
	SCMP_SYS(readdir),
#endif
#ifdef __SNR_readlink
	SCMP_SYS(readlink),
#endif
#ifdef __SNR_readlinkat
	SCMP_SYS(readlinkat),
#endif
#ifdef __SNR_readv
	SCMP_SYS(readv),
#endif
#if 0
#ifdef __SNR_reboot
	SCMP_SYS(reboot),
#endif
#endif
#ifdef __SNR_recv
	SCMP_SYS(recv),
#endif
#ifdef __SNR_recvfrom
	SCMP_SYS(recvfrom),
#endif
#ifdef __SNR_recvmmsg
	SCMP_SYS(recvmmsg),
#endif
#ifdef __SNR_recvmmsg_time64
	SCMP_SYS(recvmmsg_time64),
#endif
#ifdef __SNR_recvmsg
	SCMP_SYS(recvmsg),
#endif
#ifdef __SNR_remap_file_pages
	SCMP_SYS(remap_file_pages),
#endif
#ifdef __SNR_removexattr
	SCMP_SYS(removexattr),
#endif
#ifdef __SNR_rename
	SCMP_SYS(rename),
#endif
#ifdef __SNR_renameat
	SCMP_SYS(renameat),
#endif
#ifdef __SNR_renameat2
	SCMP_SYS(renameat2),
#endif
#if 0
#ifdef __SNR_request_key
	SCMP_SYS(request_key),
#endif
#endif
#ifdef __SNR_restart_syscall
	SCMP_SYS(restart_syscall),
#endif
#ifdef __SNR_riscv_flush_icache
	SCMP_SYS(riscv_flush_icache),
#endif
#ifdef __SNR_rmdir
	SCMP_SYS(rmdir),
#endif
#ifdef __SNR_rseq
	SCMP_SYS(rseq),
#endif
#ifdef __SNR_rt_sigaction
	SCMP_SYS(rt_sigaction),
#endif
#ifdef __SNR_rt_sigpending
	SCMP_SYS(rt_sigpending),
#endif
#ifdef __SNR_rt_sigprocmask
	SCMP_SYS(rt_sigprocmask),
#endif
#ifdef __SNR_rt_sigqueueinfo
	SCMP_SYS(rt_sigqueueinfo),
#endif
#ifdef __SNR_rt_sigreturn
	SCMP_SYS(rt_sigreturn),
#endif
#ifdef __SNR_rt_sigsuspend
	SCMP_SYS(rt_sigsuspend),
#endif
#ifdef __SNR_rt_sigtimedwait
	SCMP_SYS(rt_sigtimedwait),
#endif
#ifdef __SNR_rt_sigtimedwait_time64
	SCMP_SYS(rt_sigtimedwait_time64),
#endif
#ifdef __SNR_rt_tgsigqueueinfo
	SCMP_SYS(rt_tgsigqueueinfo),
#endif
#ifdef __SNR_rtas
	SCMP_SYS(rtas),
#endif
#ifdef __SNR_s390_guarded_storage
	SCMP_SYS(s390_guarded_storage),
#endif
#ifdef __SNR_s390_pci_mmio_read
	SCMP_SYS(s390_pci_mmio_read),
#endif
#ifdef __SNR_s390_pci_mmio_write
	SCMP_SYS(s390_pci_mmio_write),
#endif
#ifdef __SNR_s390_runtime_instr
	SCMP_SYS(s390_runtime_instr),
#endif
#ifdef __SNR_s390_sthyi
	SCMP_SYS(s390_sthyi),
#endif
#ifdef __SNR_sched_get_priority_max
	SCMP_SYS(sched_get_priority_max),
#endif
#ifdef __SNR_sched_get_priority_min
	SCMP_SYS(sched_get_priority_min),
#endif
#ifdef __SNR_sched_getaffinity
	SCMP_SYS(sched_getaffinity),
#endif
#ifdef __SNR_sched_getattr
	SCMP_SYS(sched_getattr),
#endif
#ifdef __SNR_sched_getparam
	SCMP_SYS(sched_getparam),
#endif
#ifdef __SNR_sched_getscheduler
	SCMP_SYS(sched_getscheduler),
#endif
#ifdef __SNR_sched_rr_get_interval
	SCMP_SYS(sched_rr_get_interval),
#endif
#ifdef __SNR_sched_rr_get_interval_time64
	SCMP_SYS(sched_rr_get_interval_time64),
#endif
#ifdef __SNR_sched_setaffinity
	SCMP_SYS(sched_setaffinity),
#endif
#ifdef __SNR_sched_setattr
	SCMP_SYS(sched_setattr),
#endif
#ifdef __SNR_sched_setparam
	SCMP_SYS(sched_setparam),
#endif
#ifdef __SNR_sched_setscheduler
	SCMP_SYS(sched_setscheduler),
#endif
#ifdef __SNR_sched_yield
	SCMP_SYS(sched_yield),
#endif
#ifdef __SNR_seccomp
	SCMP_SYS(seccomp),
#endif
#if 0
#ifdef __SNR_security
	SCMP_SYS(security),
#endif
#endif
#ifdef __SNR_select
	SCMP_SYS(select),
#endif
#ifdef __SNR_semctl
	SCMP_SYS(semctl),
#endif
#ifdef __SNR_semget
	SCMP_SYS(semget),
#endif
#ifdef __SNR_semop
	SCMP_SYS(semop),
#endif
#ifdef __SNR_semtimedop
	SCMP_SYS(semtimedop),
#endif
#ifdef __SNR_semtimedop_time64
	SCMP_SYS(semtimedop_time64),
#endif
#ifdef __SNR_send
	SCMP_SYS(send),
#endif
#ifdef __SNR_sendfile
	SCMP_SYS(sendfile),
#endif
#ifdef __SNR_sendfile64
	SCMP_SYS(sendfile64),
#endif
#ifdef __SNR_sendmmsg
	SCMP_SYS(sendmmsg),
#endif
#ifdef __SNR_sendmsg
	SCMP_SYS(sendmsg),
#endif
#ifdef __SNR_sendto
	SCMP_SYS(sendto),
#endif
#ifdef __SNR_set_mempolicy
	SCMP_SYS(set_mempolicy),
#endif
#ifdef __SNR_set_robust_list
	SCMP_SYS(set_robust_list),
#endif
#ifdef __SNR_set_thread_area
	SCMP_SYS(set_thread_area),
#endif
#ifdef __SNR_set_tid_address
	SCMP_SYS(set_tid_address),
#endif
#ifdef __SNR_set_tls
	SCMP_SYS(set_tls),
#endif
#ifdef __SNR_setdomainname
	SCMP_SYS(setdomainname),
#endif
#ifdef __SNR_setfsgid
	SCMP_SYS(setfsgid),
#endif
#ifdef __SNR_setfsgid32
	SCMP_SYS(setfsgid32),
#endif
#ifdef __SNR_setfsuid
	SCMP_SYS(setfsuid),
#endif
#ifdef __SNR_setfsuid32
	SCMP_SYS(setfsuid32),
#endif
#ifdef __SNR_setgid
	SCMP_SYS(setgid),
#endif
#ifdef __SNR_setgid32
	SCMP_SYS(setgid32),
#endif
#ifdef __SNR_setgroups
	SCMP_SYS(setgroups),
#endif
#ifdef __SNR_setgroups32
	SCMP_SYS(setgroups32),
#endif
#ifdef __SNR_sethostname
	SCMP_SYS(sethostname),
#endif
#ifdef __SNR_setitimer
	SCMP_SYS(setitimer),
#endif
#ifdef __SNR_setns
	SCMP_SYS(setns),
#endif
#ifdef __SNR_setpgid
	SCMP_SYS(setpgid),
#endif
#ifdef __SNR_setpriority
	SCMP_SYS(setpriority),
#endif
#ifdef __SNR_setregid
	SCMP_SYS(setregid),
#endif
#ifdef __SNR_setregid32
	SCMP_SYS(setregid32),
#endif
#ifdef __SNR_setresgid
	SCMP_SYS(setresgid),
#endif
#ifdef __SNR_setresgid32
	SCMP_SYS(setresgid32),
#endif
#ifdef __SNR_setresuid
	SCMP_SYS(setresuid),
#endif
#ifdef __SNR_setresuid32
	SCMP_SYS(setresuid32),
#endif
#ifdef __SNR_setreuid
	SCMP_SYS(setreuid),
#endif
#ifdef __SNR_setreuid32
	SCMP_SYS(setreuid32),
#endif
#ifdef __SNR_setrlimit
	SCMP_SYS(setrlimit),
#endif
#ifdef __SNR_setsid
	SCMP_SYS(setsid),
#endif
#ifdef __SNR_setsockopt
	SCMP_SYS(setsockopt),
#endif
#ifdef __SNR_settimeofday
	SCMP_SYS(settimeofday),
#endif
#ifdef __SNR_setuid
	SCMP_SYS(setuid),
#endif
#ifdef __SNR_setuid32
	SCMP_SYS(setuid32),
#endif
#ifdef __SNR_setxattr
	SCMP_SYS(setxattr),
#endif
#ifdef __SNR_sgetmask
	SCMP_SYS(sgetmask),
#endif
#ifdef __SNR_shmat
	SCMP_SYS(shmat),
#endif
#ifdef __SNR_shmctl
	SCMP_SYS(shmctl),
#endif
#ifdef __SNR_shmdt
	SCMP_SYS(shmdt),
#endif
#ifdef __SNR_shmget
	SCMP_SYS(shmget),
#endif
#ifdef __SNR_shutdown
	SCMP_SYS(shutdown),
#endif
#ifdef __SNR_sigaction
	SCMP_SYS(sigaction),
#endif
#ifdef __SNR_sigaltstack
	SCMP_SYS(sigaltstack),
#endif
#ifdef __SNR_signal
	SCMP_SYS(signal),
#endif
#ifdef __SNR_signalfd
	SCMP_SYS(signalfd),
#endif
#ifdef __SNR_signalfd4
	SCMP_SYS(signalfd4),
#endif
#ifdef __SNR_sigpending
	SCMP_SYS(sigpending),
#endif
#ifdef __SNR_sigprocmask
	SCMP_SYS(sigprocmask),
#endif
#ifdef __SNR_sigreturn
	SCMP_SYS(sigreturn),
#endif
#ifdef __SNR_sigsuspend
	SCMP_SYS(sigsuspend),
#endif
#ifdef __SNR_socket
	SCMP_SYS(socket),
#endif
#ifdef __SNR_socketcall
	SCMP_SYS(socketcall),
#endif
#ifdef __SNR_socketpair
	SCMP_SYS(socketpair),
#endif
#ifdef __SNR_splice
	SCMP_SYS(splice),
#endif
#ifdef __SNR_spu_create
	SCMP_SYS(spu_create),
#endif
#ifdef __SNR_spu_run
	SCMP_SYS(spu_run),
#endif
#ifdef __SNR_ssetmask
	SCMP_SYS(ssetmask),
#endif
#ifdef __SNR_stat
	SCMP_SYS(stat),
#endif
#ifdef __SNR_stat64
	SCMP_SYS(stat64),
#endif
#ifdef __SNR_statfs
	SCMP_SYS(statfs),
#endif
#ifdef __SNR_statfs64
	SCMP_SYS(statfs64),
#endif
#ifdef __SNR_statx
	SCMP_SYS(statx),
#endif
#ifdef __SNR_stime
	SCMP_SYS(stime),
#endif
#ifdef __SNR_stty
	SCMP_SYS(stty),
#endif
#ifdef __SNR_subpage_prot
	SCMP_SYS(subpage_prot),
#endif
#ifdef __SNR_swapcontext
	SCMP_SYS(swapcontext),
#endif
#if 0
#ifdef __SNR_swapoff
	SCMP_SYS(swapoff),
#endif
#ifdef __SNR_swapon
	SCMP_SYS(swapon),
#endif
#endif
#ifdef __SNR_switch_endian
	SCMP_SYS(switch_endian),
#endif
#ifdef __SNR_symlink
	SCMP_SYS(symlink),
#endif
#ifdef __SNR_symlinkat
	SCMP_SYS(symlinkat),
#endif
#ifdef __SNR_sync
	SCMP_SYS(sync),
#endif
#ifdef __SNR_sync_file_range
	SCMP_SYS(sync_file_range),
#endif
#ifdef __SNR_sync_file_range2
	SCMP_SYS(sync_file_range2),
#endif
#ifdef __SNR_syncfs
	SCMP_SYS(syncfs),
#endif
#ifdef __SNR_sys_debug_setcontext
	SCMP_SYS(sys_debug_setcontext),
#endif
#ifdef __SNR_syscall
	SCMP_SYS(syscall),
#endif
#ifdef __SNR_sysfs
	SCMP_SYS(sysfs),
#endif
#ifdef __SNR_sysinfo
	SCMP_SYS(sysinfo),
#endif
#if 0
#ifdef __SNR_syslog
	SCMP_SYS(syslog),
#endif
#endif
#ifdef __SNR_sysmips
	SCMP_SYS(sysmips),
#endif
#ifdef __SNR_tee
	SCMP_SYS(tee),
#endif
#ifdef __SNR_tgkill
	SCMP_SYS(tgkill),
#endif
#ifdef __SNR_time
	SCMP_SYS(time),
#endif
#ifdef __SNR_timer_create
	SCMP_SYS(timer_create),
#endif
#ifdef __SNR_timer_delete
	SCMP_SYS(timer_delete),
#endif
#ifdef __SNR_timer_getoverrun
	SCMP_SYS(timer_getoverrun),
#endif
#ifdef __SNR_timer_gettime
	SCMP_SYS(timer_gettime),
#endif
#ifdef __SNR_timer_gettime64
	SCMP_SYS(timer_gettime64),
#endif
#ifdef __SNR_timer_settime
	SCMP_SYS(timer_settime),
#endif
#ifdef __SNR_timer_settime64
	SCMP_SYS(timer_settime64),
#endif
#ifdef __SNR_timerfd
	SCMP_SYS(timerfd),
#endif
#ifdef __SNR_timerfd_create
	SCMP_SYS(timerfd_create),
#endif
#ifdef __SNR_timerfd_gettime
	SCMP_SYS(timerfd_gettime),
#endif
#ifdef __SNR_timerfd_gettime64
	SCMP_SYS(timerfd_gettime64),
#endif
#ifdef __SNR_timerfd_settime
	SCMP_SYS(timerfd_settime),
#endif
#ifdef __SNR_timerfd_settime64
	SCMP_SYS(timerfd_settime64),
#endif
#ifdef __SNR_times
	SCMP_SYS(times),
#endif
#ifdef __SNR_tkill
	SCMP_SYS(tkill),
#endif
#ifdef __SNR_truncate
	SCMP_SYS(truncate),
#endif
#ifdef __SNR_truncate64
	SCMP_SYS(truncate64),
#endif
#ifdef __SNR_tuxcall
	SCMP_SYS(tuxcall),
#endif
#ifdef __SNR_ugetrlimit
	SCMP_SYS(ugetrlimit),
#endif
#ifdef __SNR_ulimit
	SCMP_SYS(ulimit),
#endif
#ifdef __SNR_umask
	SCMP_SYS(umask),
#endif
#ifdef __SNR_umount
	SCMP_SYS(umount),
#endif
#ifdef __SNR_umount2
	SCMP_SYS(umount2),
#endif
#ifdef __SNR_uname
	SCMP_SYS(uname),
#endif
#ifdef __SNR_unlink
	SCMP_SYS(unlink),
#endif
#ifdef __SNR_unlinkat
	SCMP_SYS(unlinkat),
#endif
#ifdef __SNR_unshare
	SCMP_SYS(unshare),
#endif
#ifdef __SNR_uselib
	SCMP_SYS(uselib),
#endif
#ifdef __SNR_userfaultfd
	SCMP_SYS(userfaultfd),
#endif
#ifdef __SNR_usr26
	SCMP_SYS(usr26),
#endif
#ifdef __SNR_usr32
	SCMP_SYS(usr32),
#endif
#ifdef __SNR_ustat
	SCMP_SYS(ustat),
#endif
#ifdef __SNR_utime
	SCMP_SYS(utime),
#endif
#ifdef __SNR_utimensat
	SCMP_SYS(utimensat),
#endif
#ifdef __SNR_utimensat_time64
	SCMP_SYS(utimensat_time64),
#endif
#ifdef __SNR_utimes
	SCMP_SYS(utimes),
#endif
#ifdef __SNR_vfork
	SCMP_SYS(vfork),
#endif
#ifdef __SNR_vhangup
	SCMP_SYS(vhangup),
#endif
#if 0
#ifdef __SNR_vm86
	SCMP_SYS(vm86),
#endif
#ifdef __SNR_vm86old
	SCMP_SYS(vm86old),
#endif
#endif
#ifdef __SNR_vmsplice
	SCMP_SYS(vmsplice),
#endif
#if 0
#ifdef __SNR_vserver
	SCMP_SYS(vserver),
#endif
#endif
#ifdef __SNR_wait4
	SCMP_SYS(wait4),
#endif
#ifdef __SNR_waitid
	SCMP_SYS(waitid),
#endif
#ifdef __SNR_waitpid
	SCMP_SYS(waitpid),
#endif
#ifdef __SNR_write
	SCMP_SYS(write),
#endif
#ifdef __SNR_writev
	SCMP_SYS(writev),
#endif
};

#if 0
/* See the individual rules at filter_general_level_0() function for further
 * limitations on set{u,g}id, process_vm_{read,write}v etc. or see the
 * manual page. **/
static const int deny_list_level0[] = {
	/*
	 * SydB☮x denies these system call unconditionally to
	 * restrict potential privilege escalation or to mitigate
	 * the affects after privilege escalation.
	 */
	SCMP_SYS(acct),
	SCMP_SYS(add_key),
	SCMP_SYS(adjtimex),
	SCMP_SYS(afs_syscall),
	SCMP_SYS(chroot),
	SCMP_SYS(finit_module),
	SCMP_SYS(fsmount),
	SCMP_SYS(get_kernel_syms),
	SCMP_SYS(init_module),
	SCMP_SYS(kexec_file_load),
	SCMP_SYS(kexec_load),
	SCMP_SYS(keyctl),
	SCMP_SYS(mount),
	SCMP_SYS(move_mount),
	SCMP_SYS(nfsservctl),
#ifdef __SNR_pidfd_getfd
	SCMP_SYS(pidfd_getfd),
#else
	438, /* __NR_pidfd_getfd */
#endif
	SCMP_SYS(pivot_root),
	SCMP_SYS(pkey_alloc),
	SCMP_SYS(pkey_free),
	SCMP_SYS(pkey_mprotect),
	SCMP_SYS(process_vm_readv),
	SCMP_SYS(process_vm_writev),
	SCMP_SYS(ptrace),
	SCMP_SYS(quotactl),
	SCMP_SYS(reboot),
	SCMP_SYS(request_key),
	SCMP_SYS(security),
	SCMP_SYS(setdomainname),
	SCMP_SYS(sethostname),
	SCMP_SYS(swapoff),
	SCMP_SYS(swapon),
	SCMP_SYS(syslog),
	SCMP_SYS(umount),
	SCMP_SYS(umount2),
	SCMP_SYS(unshare),
	SCMP_SYS(uselib),
	SCMP_SYS(vm86),
	SCMP_SYS(vm86old),
	SCMP_SYS(vserver),
};

static const int allow_list_level0[] = {
	/* Level 0 Safe calls.
	 *
	 * Group 0: process id calls.
	 * Obsoleted by the extensive list.
	 */
#if 0
	SCMP_SYS(gettid),
	SCMP_SYS(getpid),
	SCMP_SYS(getgid),
	SCMP_SYS(geteuid),
	SCMP_SYS(getegid),
	SCMP_SYS(getppid),
	SCMP_SYS(getpgrp),
	SCMP_SYS(getgroups),
	SCMP_SYS(getresuid),
	SCMP_SYS(getresgid),
	SCMP_SYS(getpgid),
	SCMP_SYS(getsid),
#endif

	/* This system calls are enabled
	 * unless there's a seccomp filter of
	 * higher priority such as USER_NOTIFY,
	 * ERRNO or KILL_PROCESS which SydB☮x
	 * applies depending on configuration.
	 *
	 * The default fallback here is to
	 * ERRNO(ENOSYS) if the system call
	 * is not in the list.
	 */
	SCMP_SYS(_llseek),
	SCMP_SYS(_newselect),
	SCMP_SYS(_sysctl),
	SCMP_SYS(accept),
	SCMP_SYS(accept4),
	SCMP_SYS(access),
	SCMP_SYS(alarm),
	SCMP_SYS(arch_prctl),
	SCMP_SYS(bdflush),
	SCMP_SYS(bind),
	SCMP_SYS(bpf),
	SCMP_SYS(break),
	SCMP_SYS(brk),
	SCMP_SYS(capget),
	SCMP_SYS(capset),
	SCMP_SYS(chdir),
	SCMP_SYS(chmod),
	SCMP_SYS(chown),
	SCMP_SYS(chown32),
	SCMP_SYS(clock_adjtime),
	SCMP_SYS(clock_adjtime64),
	SCMP_SYS(clock_getres),
	SCMP_SYS(clock_getres_time64),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(clock_gettime64),
	SCMP_SYS(clock_nanosleep),
	SCMP_SYS(clock_nanosleep_time64),
	SCMP_SYS(clock_settime),
	SCMP_SYS(clock_settime64),
	SCMP_SYS(clone),
	SCMP_SYS(clone3),
	SCMP_SYS(close),
#ifdef __SNR_close_range
	SCMP_SYS(close_range),
#endif
	SCMP_SYS(connect),
	SCMP_SYS(copy_file_range),
	SCMP_SYS(creat),
	SCMP_SYS(create_module),
	SCMP_SYS(delete_module),
	SCMP_SYS(dup),
	SCMP_SYS(dup2),
	SCMP_SYS(dup3),
	SCMP_SYS(epoll_create),
	SCMP_SYS(epoll_create1),
	SCMP_SYS(epoll_ctl),
	SCMP_SYS(epoll_ctl_old),
	SCMP_SYS(epoll_pwait),
#ifdef __SNR_epoll_pwait2
	SCMP_SYS(epoll_pwait2),
#endif
	SCMP_SYS(epoll_wait),
	SCMP_SYS(epoll_wait_old),
	SCMP_SYS(eventfd),
	SCMP_SYS(eventfd2),
	SCMP_SYS(execve),
	SCMP_SYS(execveat),
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(faccessat),
#ifdef __SNR_faccessat2
	SCMP_SYS(faccessat2),
#endif
	SCMP_SYS(fadvise64),
	SCMP_SYS(fadvise64_64),
	SCMP_SYS(fallocate),
	SCMP_SYS(fanotify_init),
	SCMP_SYS(fanotify_mark),
	SCMP_SYS(fchdir),
	SCMP_SYS(fchmod),
	SCMP_SYS(fchmodat),
	SCMP_SYS(fchown),
	SCMP_SYS(fchown32),
	SCMP_SYS(fchownat),
	SCMP_SYS(fcntl),
	SCMP_SYS(fcntl64),
	SCMP_SYS(fdatasync),
	SCMP_SYS(fgetxattr),
	SCMP_SYS(flistxattr),
	SCMP_SYS(flock),
	SCMP_SYS(fork),
	SCMP_SYS(fremovexattr),
	SCMP_SYS(fsconfig),
	SCMP_SYS(fsetxattr),
	SCMP_SYS(fsopen),
	SCMP_SYS(fspick),
	SCMP_SYS(fstat),
	SCMP_SYS(fstat64),
	SCMP_SYS(fstatat64),
	SCMP_SYS(fstatfs),
	SCMP_SYS(fstatfs64),
	SCMP_SYS(fsync),
	SCMP_SYS(ftime),
	SCMP_SYS(ftruncate),
	SCMP_SYS(ftruncate64),
	SCMP_SYS(futex),
	SCMP_SYS(futex_time64),
	SCMP_SYS(futimesat),
	SCMP_SYS(get_mempolicy),
	SCMP_SYS(get_robust_list),
	SCMP_SYS(get_thread_area),
	SCMP_SYS(getcpu),
	SCMP_SYS(getcwd),
	SCMP_SYS(getdents),
	SCMP_SYS(getdents64),
	SCMP_SYS(getegid),
	SCMP_SYS(getegid32),
	SCMP_SYS(geteuid),
	SCMP_SYS(geteuid32),
	SCMP_SYS(getgid),
	SCMP_SYS(getgid32),
	SCMP_SYS(getgroups),
	SCMP_SYS(getgroups32),
	SCMP_SYS(getitimer),
	SCMP_SYS(getpeername),
	SCMP_SYS(getpgid),
	SCMP_SYS(getpgrp),
	SCMP_SYS(getpid),
	SCMP_SYS(getpmsg),
	SCMP_SYS(getppid),
	SCMP_SYS(getpriority),
	SCMP_SYS(getrandom),
	SCMP_SYS(getresgid),
	SCMP_SYS(getresgid32),
	SCMP_SYS(getresuid),
	SCMP_SYS(getresuid32),
	SCMP_SYS(getrlimit),
	SCMP_SYS(getrusage),
	SCMP_SYS(getsid),
	SCMP_SYS(getsockname),
	SCMP_SYS(getsockopt),
	SCMP_SYS(gettid),
	SCMP_SYS(gettimeofday),
	SCMP_SYS(getuid),
	SCMP_SYS(getuid32),
	SCMP_SYS(getxattr),
	SCMP_SYS(gtty),
	SCMP_SYS(idle),
	SCMP_SYS(inotify_add_watch),
	SCMP_SYS(inotify_init),
	SCMP_SYS(inotify_init1),
	SCMP_SYS(inotify_rm_watch),
	SCMP_SYS(io_cancel),
	SCMP_SYS(io_destroy),
	SCMP_SYS(io_getevents),
	SCMP_SYS(io_pgetevents),
	SCMP_SYS(io_pgetevents_time64),
	SCMP_SYS(io_setup),
	SCMP_SYS(io_submit),
	SCMP_SYS(io_uring_enter),
	SCMP_SYS(io_uring_register),
	SCMP_SYS(io_uring_setup),
	SCMP_SYS(ioctl),
	SCMP_SYS(ioperm),
	SCMP_SYS(iopl),
	SCMP_SYS(ioprio_get),
	SCMP_SYS(ioprio_set),
	SCMP_SYS(ipc),
	SCMP_SYS(kcmp),
	SCMP_SYS(kill),
	SCMP_SYS(lchown),
	SCMP_SYS(lchown32),
	SCMP_SYS(lgetxattr),
	SCMP_SYS(link),
	SCMP_SYS(linkat),
	SCMP_SYS(listen),
	SCMP_SYS(listxattr),
	SCMP_SYS(llistxattr),
	SCMP_SYS(lock),
	SCMP_SYS(lookup_dcookie),
	SCMP_SYS(lremovexattr),
	SCMP_SYS(lseek),
	SCMP_SYS(lsetxattr),
	SCMP_SYS(lstat),
	SCMP_SYS(lstat64),
	SCMP_SYS(madvise),
	SCMP_SYS(mbind),
	SCMP_SYS(membarrier),
	SCMP_SYS(migrate_pages),
	SCMP_SYS(mincore),
	SCMP_SYS(mkdir),
	SCMP_SYS(mkdirat),
	SCMP_SYS(mknod),
	SCMP_SYS(mknodat),
	SCMP_SYS(mlock),
	SCMP_SYS(mlock2),
	SCMP_SYS(mlockall),
	SCMP_SYS(mmap),
	SCMP_SYS(mmap2),
	SCMP_SYS(modify_ldt),
	SCMP_SYS(move_pages),
	SCMP_SYS(mprotect),
	SCMP_SYS(mpx),
	SCMP_SYS(mq_getsetattr),
	SCMP_SYS(mq_notify),
	SCMP_SYS(mq_open),
	SCMP_SYS(mq_timedreceive),
	SCMP_SYS(mq_timedreceive_time64),
	SCMP_SYS(mq_timedsend),
	SCMP_SYS(mq_timedsend_time64),
	SCMP_SYS(mq_unlink),
	SCMP_SYS(mremap),
	SCMP_SYS(msgctl),
	SCMP_SYS(msgget),
	SCMP_SYS(msgrcv),
	SCMP_SYS(msgsnd),
	SCMP_SYS(msync),
	SCMP_SYS(munlock),
	SCMP_SYS(munlockall),
	SCMP_SYS(munmap),
	SCMP_SYS(name_to_handle_at),
	SCMP_SYS(nanosleep),
	SCMP_SYS(newfstatat),
	SCMP_SYS(nice),
	SCMP_SYS(oldfstat),
	SCMP_SYS(oldlstat),
	SCMP_SYS(oldolduname),
	SCMP_SYS(oldstat),
	SCMP_SYS(olduname),
	SCMP_SYS(open),
	SCMP_SYS(open_by_handle_at),
	SCMP_SYS(open_tree),
	SCMP_SYS(openat),
#ifdef __SNR_openat2
	SCMP_SYS(openat2),
#endif
	SCMP_SYS(pause),
	SCMP_SYS(perf_event_open),
	SCMP_SYS(personality),
	SCMP_SYS(pipe),
	SCMP_SYS(pipe2),
	SCMP_SYS(poll),
	SCMP_SYS(ppoll),
	SCMP_SYS(ppoll_time64),
	SCMP_SYS(prctl),
	SCMP_SYS(pread64),
	SCMP_SYS(preadv),
	SCMP_SYS(preadv2),
	SCMP_SYS(prlimit64),
#ifdef __SNR_process_madvise
	SCMP_SYS(process_madvise),
#endif
	SCMP_SYS(prof),
	SCMP_SYS(profil),
	SCMP_SYS(pselect6),
	SCMP_SYS(pselect6_time64),
	SCMP_SYS(putpmsg),
	SCMP_SYS(pwrite64),
	SCMP_SYS(pwritev),
	SCMP_SYS(pwritev2),
	SCMP_SYS(query_module),
	SCMP_SYS(read),
	SCMP_SYS(readahead),
	SCMP_SYS(readdir),
	SCMP_SYS(readlink),
	SCMP_SYS(readlinkat),
	SCMP_SYS(readv),
	SCMP_SYS(recvfrom),
	SCMP_SYS(recvmmsg),
	SCMP_SYS(recvmmsg_time64),
	SCMP_SYS(recvmsg),
	SCMP_SYS(remap_file_pages),
	SCMP_SYS(removexattr),
	SCMP_SYS(rename),
	SCMP_SYS(renameat),
	SCMP_SYS(renameat2),
	SCMP_SYS(restart_syscall),
	SCMP_SYS(rmdir),
	SCMP_SYS(rseq),
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(rt_sigpending),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(rt_sigqueueinfo),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(rt_sigsuspend),
	SCMP_SYS(rt_sigtimedwait),
	SCMP_SYS(rt_sigtimedwait_time64),
	SCMP_SYS(rt_tgsigqueueinfo),
	SCMP_SYS(sched_get_priority_max),
	SCMP_SYS(sched_get_priority_min),
	SCMP_SYS(sched_getaffinity),
	SCMP_SYS(sched_getattr),
	SCMP_SYS(sched_getparam),
	SCMP_SYS(sched_getscheduler),
	SCMP_SYS(sched_rr_get_interval),
	SCMP_SYS(sched_rr_get_interval_time64),
	SCMP_SYS(sched_setaffinity),
	SCMP_SYS(sched_setattr),
	SCMP_SYS(sched_setparam),
	SCMP_SYS(sched_setscheduler),
	SCMP_SYS(sched_yield),
	SCMP_SYS(select),
	SCMP_SYS(semctl),
	SCMP_SYS(semget),
	SCMP_SYS(semop),
	SCMP_SYS(semtimedop),
	SCMP_SYS(semtimedop_time64),
	SCMP_SYS(sendfile),
	SCMP_SYS(sendfile64),
	SCMP_SYS(sendmmsg),
	SCMP_SYS(sendmsg),
	SCMP_SYS(sendto),
	SCMP_SYS(set_mempolicy),
	SCMP_SYS(set_robust_list),
	SCMP_SYS(set_thread_area),
	SCMP_SYS(set_tid_address),
	SCMP_SYS(setfsgid),
	SCMP_SYS(setfsgid32),
	SCMP_SYS(setfsuid),
	SCMP_SYS(setfsuid32),
	SCMP_SYS(setgid),
	SCMP_SYS(setgid32),
	SCMP_SYS(setgroups),
	SCMP_SYS(setgroups32),
	SCMP_SYS(setitimer),
	SCMP_SYS(setns),
	SCMP_SYS(setpgid),
	SCMP_SYS(setpriority),
	SCMP_SYS(setregid),
	SCMP_SYS(setregid32),
	SCMP_SYS(setresgid),
	SCMP_SYS(setresgid32),
	SCMP_SYS(setresuid),
	SCMP_SYS(setresuid32),
	SCMP_SYS(setreuid),
	SCMP_SYS(setreuid32),
	SCMP_SYS(setrlimit),
	SCMP_SYS(setsid),
	SCMP_SYS(setsockopt),
	SCMP_SYS(settimeofday),
	SCMP_SYS(setuid),
	SCMP_SYS(setuid32),
	SCMP_SYS(setxattr),
	SCMP_SYS(sgetmask),
	SCMP_SYS(shutdown),
	SCMP_SYS(sigaction),
	SCMP_SYS(sigaltstack),
	SCMP_SYS(signal),
	SCMP_SYS(signalfd),
	SCMP_SYS(signalfd4),
	SCMP_SYS(sigpending),
	SCMP_SYS(sigprocmask),
	SCMP_SYS(sigreturn),
	SCMP_SYS(sigsuspend),
	SCMP_SYS(socket),
	SCMP_SYS(socketcall),
	SCMP_SYS(socketpair),
	SCMP_SYS(splice),
	SCMP_SYS(ssetmask),
	SCMP_SYS(stat),
	SCMP_SYS(stat64),
	SCMP_SYS(statfs),
	SCMP_SYS(statfs64),
	SCMP_SYS(statx),
	SCMP_SYS(stime),
	SCMP_SYS(stty),
	SCMP_SYS(symlink),
	SCMP_SYS(symlinkat),
	SCMP_SYS(sync),
	SCMP_SYS(sync_file_range),
	SCMP_SYS(syncfs),
	SCMP_SYS(sysfs),
	SCMP_SYS(sysinfo),
	SCMP_SYS(syslog),
	SCMP_SYS(tee),
	SCMP_SYS(tgkill),
	SCMP_SYS(time),
	SCMP_SYS(timer_create),
	SCMP_SYS(timer_delete),
	SCMP_SYS(timer_getoverrun),
	SCMP_SYS(timer_gettime),
	SCMP_SYS(timer_gettime64),
	SCMP_SYS(timer_settime),
	SCMP_SYS(timer_settime64),
	SCMP_SYS(timerfd_create),
	SCMP_SYS(timerfd_gettime),
	SCMP_SYS(timerfd_gettime64),
	SCMP_SYS(timerfd_settime),
	SCMP_SYS(timerfd_settime64),
	SCMP_SYS(times),
	SCMP_SYS(tkill),
	SCMP_SYS(truncate),
	SCMP_SYS(truncate64),
	SCMP_SYS(tuxcall),
	SCMP_SYS(ugetrlimit),
	SCMP_SYS(ulimit),
	SCMP_SYS(umask),
	SCMP_SYS(uname),
	SCMP_SYS(unlink),
	SCMP_SYS(unlinkat),
	SCMP_SYS(userfaultfd),
	SCMP_SYS(ustat),
	SCMP_SYS(utime),
	SCMP_SYS(utimensat),
	SCMP_SYS(utimensat_time64),
	SCMP_SYS(utimes),
	SCMP_SYS(vfork),
	SCMP_SYS(vhangup),
	SCMP_SYS(vmsplice),
	SCMP_SYS(wait4),
	SCMP_SYS(waitid),
	SCMP_SYS(waitpid),
	SCMP_SYS(write),
	SCMP_SYS(writev),
};
#endif

static const int filter_gen_level1[] = {
	SCMP_SYS(close),
	SCMP_SYS(dup),
#ifdef __NR_dup2
	SCMP_SYS(dup2),
#endif
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(execve),
#ifdef __NR_execveat
	SCMP_SYS(execveat),
#endif
	SCMP_SYS(arch_prctl),
	SCMP_SYS(getpid),
	SCMP_SYS(set_tid_address),
	SCMP_SYS(pause),
	SCMP_SYS(read),
#ifdef __NR_readv
	SCMP_SYS(readv),
#endif
#ifdef __NR_preadv
	SCMP_SYS(preadv),
#endif
#ifdef __NR_preadv2
	SCMP_SYS(preadv2),
#endif
	SCMP_SYS(write),
#ifdef __NR_writev
	SCMP_SYS(writev),
#endif
#ifdef __NR_pwritev
	SCMP_SYS(pwritev),
#endif
#ifdef __NR_pwritev2
	SCMP_SYS(pwritev2),
#endif
	SCMP_SYS(sigreturn),
	SCMP_SYS(stat),
#ifdef __NR_stat64
	SCMP_SYS(stat64),
#endif
	SCMP_SYS(fstat),
#ifdef __NR_fstat64
	SCMP_SYS(fstat64),
#endif
	SCMP_SYS(lstat),
#ifdef __NR_newfstatat
	SCMP_SYS(newfstatat),
#endif
	SCMP_SYS(brk),
#ifdef __NR_mmap
	SCMP_SYS(mmap),
#endif
#ifdef __NR_mmap2
	SCMP_SYS(mmap2),
#endif
#ifdef __NR_munmap
	SCMP_SYS(munmap),
#endif
};

static const int filter_gen_level2[] = {
	SCMP_SYS(arch_prctl),
	SCMP_SYS(access),
	SCMP_SYS(brk),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(close),
	SCMP_SYS(clone),
	SCMP_SYS(dup),
#ifdef __NR_dup2
	SCMP_SYS(dup2),
#endif
	SCMP_SYS(epoll_create),
	SCMP_SYS(epoll_wait),
#ifdef __NR_epoll_pwait
	SCMP_SYS(epoll_pwait),
#endif
	SCMP_SYS(execve),
#ifdef __NR_execveat
	SCMP_SYS(execveat),
#endif
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(fork),
	SCMP_SYS(vfork),
	SCMP_SYS(clone),
#ifdef __NR_clone3
	SCMP_SYS(clone3),
#endif
#ifdef __NR_eventfd2
	SCMP_SYS(eventfd2),
#endif
#ifdef __NR_pipe2
	SCMP_SYS(pipe2),
#endif
#ifdef __NR_pipe
	SCMP_SYS(pipe),
#endif
	SCMP_SYS(fcntl),
	SCMP_SYS(fstat),
#ifdef __NR_fstat64
	SCMP_SYS(fstat64),
#endif
	SCMP_SYS(fsync),
	SCMP_SYS(futex),
	SCMP_SYS(getdents),
	SCMP_SYS(getdents64),
	SCMP_SYS(getegid),
#ifdef __NR_getegid32
	SCMP_SYS(getegid32),
#endif
	SCMP_SYS(geteuid),
#ifdef __NR_geteuid32
	SCMP_SYS(geteuid32),
#endif
	SCMP_SYS(getgid),
#ifdef __NR_getgid32
	SCMP_SYS(getgid32),
#endif
	SCMP_SYS(getpgrp),
	SCMP_SYS(getpid),
	SCMP_SYS(getppid),
	SCMP_SYS(getpgid),
#ifdef __NR_getrlimit
	SCMP_SYS(getrlimit),
#endif
	SCMP_SYS(gettimeofday),
	SCMP_SYS(gettid),
	SCMP_SYS(getuid),
#ifdef __NR_getuid32
	SCMP_SYS(getuid32),
#endif
	SCMP_SYS(lseek),
#ifdef __NR__llseek
	SCMP_SYS(_llseek),
#endif
	// glob uses this..
	SCMP_SYS(lstat),
	SCMP_SYS(mlockall),
#ifdef __NR_mmap
	SCMP_SYS(mmap),
#endif
#ifdef __NR_mmap2
	SCMP_SYS(mmap2),
#endif
#ifdef __NR_munmap
	SCMP_SYS(munmap),
#endif
#ifdef __NR_nanosleep
	SCMP_SYS(nanosleep),
#endif
	SCMP_SYS(open),
	SCMP_SYS(openat),
/*
 * TODO: This does not work with libseccomp-2.5.1
#ifdef __NR_openat2
	SCMP_SYS(openat2),
#endif
*/
	SCMP_SYS(pause),
#ifdef __NR_preadv
	SCMP_SYS(preadv),
#endif
#ifdef __NR_preadv2
	SCMP_SYS(preadv2),
#endif
#ifdef __NR_prlimit
	SCMP_SYS(prlimit),
#endif
#ifdef __NR_prlimit64
	SCMP_SYS(prlimit64),
#endif
	SCMP_SYS(pselect6),
	SCMP_SYS(read),
	SCMP_SYS(pause),
#ifdef __NR_readv
	SCMP_SYS(readv),
#endif
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(sched_getaffinity),
#ifdef __NR_sched_yield
	SCMP_SYS(sched_yield),
#endif
	SCMP_SYS(sendmsg),
	SCMP_SYS(set_robust_list),
	SCMP_SYS(setpgid),
#ifdef __NR_setrlimit
	SCMP_SYS(setrlimit),
#endif
	SCMP_SYS(shutdown),
#ifdef __NR_sigaltstack
	SCMP_SYS(sigaltstack),
#endif
#ifdef __NR_sigreturn
	SCMP_SYS(sigreturn),
#endif
	SCMP_SYS(stat),
	SCMP_SYS(uname),
	SCMP_SYS(wait4),
	SCMP_SYS(write),
#ifdef __NR_writev
	SCMP_SYS(writev),
#endif
#ifdef __NR_pwritev
	SCMP_SYS(pwritev),
#endif
#ifdef __NR_pwritev2
	SCMP_SYS(pwritev2),
#endif
	SCMP_SYS(exit_group),
	SCMP_SYS(exit),

	SCMP_SYS(madvise),
	SCMP_SYS(membarrier),
	SCMP_SYS(set_tid_address),
	SCMP_SYS(stat),
#ifdef __NR_stat64
	// getaddrinfo uses this..
	SCMP_SYS(stat64),
#endif

#ifdef __NR_getrandom
	SCMP_SYS(getrandom),
#endif

#ifdef __NR_sysinfo
// qsort uses this..
	SCMP_SYS(sysinfo),
#endif
/*
* These socket syscalls are not required on x86_64 and not supported with
* some libseccomp versions (eg: 1.0.1)
*/
#if defined(__i386)
	SCMP_SYS(recv),
	SCMP_SYS(send),
#endif
	// socket syscalls
	SCMP_SYS(bind),
	SCMP_SYS(listen),
	SCMP_SYS(connect),
	SCMP_SYS(getsockname),
#ifdef __NR_getpeername
	SCMP_SYS(getpeername),
#endif
	SCMP_SYS(recvmsg),
	SCMP_SYS(recvfrom),
	SCMP_SYS(sendto),
#ifdef __NR_readlink
	SCMP_SYS(readlink),
#endif
#ifdef __NR_readlinkat
	SCMP_SYS(readlinkat),
#endif
	SCMP_SYS(unlink),
#ifdef __NR_unlinkat
	SCMP_SYS(unlinkat),
#endif
	SCMP_SYS(select),
#ifdef __NR_pselect6
	SCMP_SYS(pselect6),
#endif
	SCMP_SYS(poll),
#ifdef __NR_readlink
	SCMP_SYS(readlink),
#endif
#ifdef __NR_readlinkat
	SCMP_SYS(readlinkat),
#endif
};

static const int filter_gen_level3[] = {
	SCMP_SYS(arch_prctl),
	SCMP_SYS(access),
	SCMP_SYS(brk),
	SCMP_SYS(clock_gettime),
	SCMP_SYS(close),
	SCMP_SYS(clone),
	SCMP_SYS(dup),
#ifdef __NR_dup2
	SCMP_SYS(dup2),
#endif
	SCMP_SYS(epoll_create),
	SCMP_SYS(epoll_wait),
#ifdef __NR_epoll_pwait
	SCMP_SYS(epoll_pwait),
#endif
	SCMP_SYS(execve),
#ifdef __NR_execveat
	SCMP_SYS(execveat),
#endif
	SCMP_SYS(exit),
	SCMP_SYS(exit_group),
	SCMP_SYS(fork),
	SCMP_SYS(vfork),
	SCMP_SYS(clone),
#ifdef __NR_clone3
	SCMP_SYS(clone3),
#endif
#ifdef __NR_eventfd2
	SCMP_SYS(eventfd2),
#endif
#ifdef __NR_pipe2
	SCMP_SYS(pipe2),
#endif
#ifdef __NR_pipe
	SCMP_SYS(pipe),
#endif
	SCMP_SYS(fcntl),
	SCMP_SYS(fstat),
#ifdef __NR_fstat64
	SCMP_SYS(fstat64),
#endif
	SCMP_SYS(fsync),
	SCMP_SYS(futex),
	SCMP_SYS(getdents),
	SCMP_SYS(getdents64),
	SCMP_SYS(getegid),
#ifdef __NR_getegid32
	SCMP_SYS(getegid32),
#endif
	SCMP_SYS(geteuid),
#ifdef __NR_geteuid32
	SCMP_SYS(geteuid32),
#endif
	SCMP_SYS(getgid),
#ifdef __NR_getgid32
	SCMP_SYS(getgid32),
#endif
	SCMP_SYS(getpgrp),
	SCMP_SYS(getpid),
	SCMP_SYS(getppid),
	SCMP_SYS(getpgid),
#ifdef __NR_getrlimit
	SCMP_SYS(getrlimit),
#endif
	SCMP_SYS(gettimeofday),
	SCMP_SYS(gettid),
	SCMP_SYS(getuid),
#ifdef __NR_getuid32
	SCMP_SYS(getuid32),
#endif
	SCMP_SYS(lseek),
#ifdef __NR__llseek
	SCMP_SYS(_llseek),
#endif
	// glob uses this..
	SCMP_SYS(lstat),
	SCMP_SYS(mlockall),
#ifdef __NR_mmap
	SCMP_SYS(mmap),
#endif
#ifdef __NR_mmap2
	SCMP_SYS(mmap2),
#endif
#ifdef __NR_munmap
	SCMP_SYS(munmap),
#endif
#ifdef __NR_nanosleep
	SCMP_SYS(nanosleep),
#endif
	SCMP_SYS(open),
	SCMP_SYS(openat),
#ifdef __NR_preadv
	SCMP_SYS(preadv),
#endif
#ifdef __NR_preadv2
	SCMP_SYS(preadv2),
#endif
#ifdef __NR_prlimit
	SCMP_SYS(prlimit),
#endif
#ifdef __NR_prlimit64
	SCMP_SYS(prlimit64),
#endif
	SCMP_SYS(pselect6),
	SCMP_SYS(read),
#ifdef __NR_readv
	SCMP_SYS(readv),
#endif
	SCMP_SYS(rt_sigaction),
	SCMP_SYS(rt_sigprocmask),
	SCMP_SYS(rt_sigreturn),
	SCMP_SYS(sched_getaffinity),
#ifdef __NR_sched_yield
	SCMP_SYS(sched_yield),
#endif
	SCMP_SYS(sendmsg),
	SCMP_SYS(set_robust_list),
	SCMP_SYS(setpgid),
#ifdef __NR_setrlimit
	SCMP_SYS(setrlimit),
#endif
	SCMP_SYS(shutdown),
#ifdef __NR_sigaltstack
	SCMP_SYS(sigaltstack),
#endif
#ifdef __NR_sigreturn
	SCMP_SYS(sigreturn),
#endif
	SCMP_SYS(stat),
	SCMP_SYS(uname),
	SCMP_SYS(wait4),
	SCMP_SYS(write),
#ifdef __NR_writev
	SCMP_SYS(writev),
#endif
#ifdef __NR_pwritev
	SCMP_SYS(pwritev),
#endif
#ifdef __NR_pwritev2
	SCMP_SYS(pwritev2),
#endif
	SCMP_SYS(exit_group),
	SCMP_SYS(exit),

	SCMP_SYS(madvise),
	SCMP_SYS(membarrier),
	SCMP_SYS(set_tid_address),
	SCMP_SYS(stat),
#ifdef __NR_stat64
	// getaddrinfo uses this..
	SCMP_SYS(stat64),
#endif

#ifdef __NR_getrandom
	SCMP_SYS(getrandom),
#endif

#ifdef __NR_sysinfo
// qsort uses this..
	SCMP_SYS(sysinfo),
#endif
/*
* These socket syscalls are not required on x86_64 and not supported with
* some libseccomp versions (eg: 1.0.1)
*/
#if defined(__i386)
	SCMP_SYS(recv),
	SCMP_SYS(send),
#endif
	// socket syscalls
	SCMP_SYS(bind),
	SCMP_SYS(listen),
	SCMP_SYS(connect),
	SCMP_SYS(getsockname),
#ifdef __NR_getpeername
	SCMP_SYS(getpeername),
#endif
	SCMP_SYS(recvmsg),
	SCMP_SYS(recvfrom),
	SCMP_SYS(sendto),
#ifdef __NR_readlink
	SCMP_SYS(readlink),
#endif
#ifdef __NR_readlinkat
	SCMP_SYS(readlinkat),
#endif
	SCMP_SYS(unlink),
#ifdef __NR_unlinkat
	SCMP_SYS(unlinkat),
#endif
	SCMP_SYS(select),
#ifdef __NR_pselect6
	SCMP_SYS(pselect6),
#endif
	SCMP_SYS(poll),
#ifdef __NR_readlink
	SCMP_SYS(readlink),
#endif
#ifdef __NR_readlinkat
	SCMP_SYS(readlinkat),
#endif
	/* Level 3 additions */
	SCMP_SYS(chmod),
#ifdef __NR_fchmod
	SCMP_SYS(fchmod),
#endif
#ifdef __NR_fchmodat
	SCMP_SYS(fchmodat),
#endif
	SCMP_SYS(chown),
#ifdef __NR_chown32
	SCMP_SYS(chown32),
#endif
	SCMP_SYS(lchown),
#ifdef __NR_lchown32
	SCMP_SYS(lchown32),
#endif
#ifdef __NR_fchownat
	SCMP_SYS(fchownat),
#endif
	SCMP_SYS(creat),
	SCMP_SYS(mkdir),
	SCMP_SYS(mkdirat),
	SCMP_SYS(mknod),
	SCMP_SYS(mknodat),
	SCMP_SYS(rmdir),
	SCMP_SYS(truncate),
#ifdef __NR_truncate64
	SCMP_SYS(truncate64),
#endif
	SCMP_SYS(link),
	SCMP_SYS(linkat),
	SCMP_SYS(unlink),
	SCMP_SYS(unlinkat),
	SCMP_SYS(rename),
	SCMP_SYS(renameat),
#ifdef __NR_renameat2
	SCMP_SYS(renameat2),
#endif
	SCMP_SYS(symlink),
	SCMP_SYS(symlinkat),
	SCMP_SYS(utime),
	SCMP_SYS(utimes),
#ifdef __NR_utimensat
	SCMP_SYS(utimensat),
#endif
#ifdef __NR_futimesat
	SCMP_SYS(futimesat),
#endif
	SCMP_SYS(setxattr),
	SCMP_SYS(lsetxattr),
	SCMP_SYS(removexattr),
	SCMP_SYS(lremovexattr),
/*
 * TODO: This does not work with libseccomp-2.5.1
#ifdef __NR_openat2
	SCMP_SYS(openat2),
#endif
*/
};

bool filter_includes(int sysnum)
{
	size_t max;
	const int *filter;
	static const char *level0_names[] = {
		"execve", "execveat",
		"chdir", "chdirat",
		"clone",
		"clone2",
		"clone3",
		"fork", "vfork",
	};

	switch (sydbox->config.restrict_general) {
	case 0:
		filter = NULL;
		max = 0;
		break; /* Level 0 is checked unconditionally, below */
	case 1:
		filter = filter_gen_level1;
		max = ELEMENTSOF(filter_gen_level1);
		break;
	case 2:
		filter = filter_gen_level2;
		max = ELEMENTSOF(filter_gen_level2);
		break;
	case 3:
		filter = filter_gen_level3;
		max = ELEMENTSOF(filter_gen_level3);
		break;
	default:
		assert_not_reached();
	}

	/* Check Level 0 first */
	for (size_t i = 0; i < ELEMENTSOF(level0_names); i++) {
		int nr = seccomp_syscall_resolve_name(level0_names[i]);
		if (nr == __NR_SCMP_ERROR)
			continue;
		else if (nr < 0) {
			//say("unknown system call:%s for architecture %s, "
			//    "continuing...",
			//    level0_names[i], "native");
			continue;
		} else if (nr == sysnum) {
			return true;
		}
	}

	if (sydbox->config.restrict_general < 1)
		return false;

	for (size_t i = 0; i < max; i++)
		if (sysnum == filter[i])
			return true;
	return false;
}

static int filter_open_readonly(void)
{
	int r;
	uint32_t action;
	enum sandbox_mode mode;

	mode = sydbox->config.box_static.mode.sandbox_read;
	switch (mode) {
	case SANDBOX_OFF:
	case SANDBOX_ALLOW:
		action = SCMP_ACT_ALLOW;
		break;
	case SANDBOX_BPF:
	case SANDBOX_DENY:
		action = SCMP_ACT_ERRNO(EPERM);
		break;
	default:
		assert_not_reached();
	}

	if (action == sydbox->seccomp_action)
		return 0;

	if ((r = rule_add_open_rd(action, SCMP_SYS(open), 1)) < 0)
		return r;
	if ((r = rule_add_open_rd(action, SCMP_SYS(openat), 2)) < 0)
		return r;

	return 0;
}

static int filter_time(void)
{
	int r;
	uint32_t action = SCMP_ACT_ALLOW;

	if (action == sydbox->seccomp_action)
		return 0;

	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
			    SCMP_SYS(time), 1,
			    SCMP_CMP64(0, SCMP_CMP_EQ, 0));

	return 0;
}

static int filter_rt_sigaction(void)
{
	int r;
	int param[] = { SIGINT, SIGTERM, SIGPIPE, SIGUSR1, SIGUSR2, SIGHUP,
		SIGCHLD, SIGSEGV, SIGILL, SIGFPE, SIGBUS, SIGSYS, SIGIO,
#ifdef SIGXFSZ
		SIGXFSZ
#endif
	};
	uint32_t action = SCMP_ACT_ALLOW;

	if (action == sydbox->seccomp_action)
		return 0;

	for (unsigned short i = 0; i < ELEMENTSOF(param); i++) {
		syd_rule_add_return(sydbox->ctx, action,
				    SCMP_SYS(rt_sigaction), 1,
				    SCMP_CMP32(0, SCMP_CMP_EQ, param[i]));
	}

	return 0;
}

static int filter_general_level_0(void)
{
	int r;

#if 0
	/* Note, seccomp returns EEXIST if the rule already exists,
	 * and EACCES when one attempts to add a rule with the same
	 * action as the default action, ie the rule is redundant.
	 * EINVAL is returned when the system call is invalid.
	 * We do not error in these three cases and resume operation.
	 */
	for (unsigned i = 0; i < ELEMENTSOF(deny_list_level0); i++) {
		syd_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(ECANCELED),
			     deny_list_level0[i], 0);
		if (r &&
		    r != -EEXIST &&
		    r != -EACCES &&
		    r != -EINVAL &&
		    r != -EFAULT) {
			char *name;
			name = seccomp_syscall_resolve_num_arch(deny_list_level0[i],
								SCMP_ARCH_NATIVE);
			errno = -r;
			say_errno("Sandbox failed to add syscall index %d (NR=%d) "
				  "name \"%s\" to Level 0. Received libseccomp error",
				  i, deny_list_level0[i],
				  name ? name : "?");
			if (name)
				free(name);
			return r;
		}
	}
#endif
	for (unsigned i = 0; i < ELEMENTSOF(allow_list_level0); i++) {
		syd_rule_add(sydbox->ctx, SCMP_ACT_ALLOW, allow_list_level0[i],
			     0);
		if (r &&
		    r != -EEXIST &&
		    r != -EACCES &&
		    r != -EINVAL &&
		    r != -EFAULT) {
			char *name;
			name = seccomp_syscall_resolve_num_arch(allow_list_level0[i],
								SCMP_ARCH_NATIVE);
			errno = -r;
			say_errno("Sandbox failed to add syscall index %d (NR=%d) "
				  "name \"%s\" to Level 0. Received libseccomp error",
				  i, allow_list_level0[i],
				  name ? name : "?");
			if (name)
				free(name);
			return r;
		}
	}

	/*
	 * ++ Restricting process memory read/write operations.
	 *
	 * This is a defense against possible TOCTOU attacks. The system calls
	 * process_vm_readv and process_vm_writev are never permitted in
	 * SydB☮x. TODO: In addition for user-space sandboxing mode SydB☮x
	 * unconditionally disallows access to /proc/$pid/mem for both read
	 * and write based open calls.
	 */
	/*
	 * FIXME: Load these two calls below outside libseccomp,
	 * as they are not supported yet, hence the __SNR
	 * rather than the __NR ifdef check below.
	 */
#ifdef __SNR_process_madvise
	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EFAULT),
			    __NR_process_madvise, 0);
#endif
#ifdef __SNR_pidfd_getfd
	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
			    __NR_pidfd_getfd, 0);
#endif
	if (use_notify()) {
		/*
		 * Deny pidfd_send_signal() to send any signal which
		 * has the default action of term, core and stop
		 * with ESRCH which denotes the process or process group
		 * does not exist.
		 */
#ifdef __NR_pidfd_send_signal
		const long kill_signals[] = {
			SIGHUP, SIGINT, SIGQUIT, SIGILL,
			SIGABRT, SIGFPE, SIGKILL, SIGSEGV,
			SIGSEGV, SIGPIPE, SIGALRM, SIGTERM,
			SIGUSR1, SIGUSR2, SIGSTOP, SIGTSTP,
			SIGTTIN, SIGTTOU,

			SIGBUS, SIGPOLL, SIGPROF, SIGSYS,
			SIGTRAP, SIGVTALRM, SIGXCPU, SIGXFSZ,

#ifdef SIGIOT
			SIGIOT,
#endif
#ifdef SIGEMT
			SIGEMT,
#endif
#ifdef SIGSTKFLT
			SIGSTKFLT,
#endif
#ifdef SIGIO
			SIGIO,
#endif
#ifdef SIGINFO
			SIGINFO,
#endif
#ifdef SIGLOST
			SIGLOST,
#endif
			LONG_MAX,
		};

		for (size_t i = 0; kill_signals[i] != LONG_MAX; i++) {
			syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(ESRCH),
					    SCMP_SYS(pidfd_send_signal), 1,
					    SCMP_A1_32( SCMP_CMP_EQ,
							kill_signals[i] ));
		}
#endif /* __NR_pidfd_send_signal */

		const pid_t protect_pids[] = {
			sydbox->execve_pid,
			sydbox->sydbox_pid,
			INT_MAX,
		};
		for (size_t i = 0; protect_pids[i] != INT_MAX; i++) {
			pid_t pid = protect_pids[i];
#ifdef __NR_process_vm_readv
			syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
					    SCMP_SYS(process_vm_readv), 1,
					    SCMP_A0_64( SCMP_CMP_EQ,
							pid ));
#endif
#ifdef __NR_process_vm_writev
			syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
					    SCMP_SYS(process_vm_writev), 1,
					    SCMP_A0_64( SCMP_CMP_EQ,
							pid ));
#endif
		}

		static const int kill_calls[] = {
			SCMP_SYS(kill),
			SCMP_SYS(tkill),
		};

		/*
		 * ++ Restricting signal handling between Sydb☮x and the
		 * sandboxed process: SydB☮x permits only SIGCHLD from the
		 * initial child. Other signals sent to SydB☮x's process id
		 * are denied with ESRCH which denotes the process or
		 * process group does not exist. This approach renders the
		 * sandboxing SydB☮x process safe against any unexpected
		 * signals.
		 */
		for (size_t i = 0; i < ELEMENTSOF(kill_calls); i++) {
			syd_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(ESRCH),
				     kill_calls[i], 2,
				     SCMP_A0_64( SCMP_CMP_EQ,
						 sydbox->sydbox_pid ),
				     SCMP_A1_32( SCMP_CMP_NE,
						 SIGCHLD ));
			if (!syd_rule_ok(r)) {
				errno = -r;
				die_errno("kill.%zu: failed to add "
					  "kill protect filter "
					  "for process ID %d "
					  "for system call:%d "
					  "to match !=SIGCHLD for "
					  "ERRNO(EPERM).",
					  i, sydbox->sydbox_pid,
					  kill_calls[i]);
			}
		}
		syd_rule_add(sydbox->ctx, SCMP_ACT_ERRNO(ESRCH),
			     SCMP_SYS(tgkill), 2,
			     SCMP_A1_64( SCMP_CMP_EQ, sydbox->sydbox_pid ),
			     SCMP_A2_32( SCMP_CMP_NE, SIGCHLD ));
		if (!syd_rule_ok(r)) {
			errno = -r;
			die_errno("tgkill: failed to add "
				  "tgkill protect filter "
				  "for process ID %d (sydbox) "
				  "for system call:%d "
				  "to match !=SIGSTOP for ERRNO(EPERM).",
				  sydbox->sydbox_pid, SCMP_SYS(tgkill));
		}
	}

	/*
	 * ++ Restricting system calls with user/group ID arguments.
	 *
	 * Two modes:
	 *
	 * 1. --uid=<uid>, --gid=<gid> command line switches restrict
	 * the user to this user id only. This means the user is in a
	 * cage and can not change to any other user or group or both
	 * user and group depending on the combination of flags.
	 *
	 * 2. set{u,g}id to {user,group} IDs below a certain minimum
	 * are not permitted. This is default unless at least one of
	 * the command line switches --uid or --gid is given in which
	 * case the restrictions for the respective user or group identity
	 * is changed to 1.
	 *
	 * Pick the default minimum IDs using an empirical observation
	 * of /etc/passwd and /etc/group on a recent Exherbo system
	 * of the author. See the excerpts below.
	 *
         * TODO: Make the limits configurable via
	 *       core/trace/restrict_{u,g}id_m{in,ax}.
         *
	 * ++++ Deny Mode:
	 * Deny the system calls with EINVAL which denotes the
	 * {user,group} ID specified in {u,g}id is not valid in
	 * this user namespace.
	 *
	 * The excerpts are files /etc/{passwd,group}.
	 * `alip' is the user name of the author and their
	 * user ID, 1000 is the common beginning number of
	 * user accounts on a Linux system.
	 *
	 * The default restriction is to *never* allow
	 * user ID changes to any user from root to operator,
	 * inclusive, ie 0..11, which gives us the first rule:
	 *
	 * 1. A user may not change their user identity to any
	 *    user identity lower than 12 under SydB☮x unless
	 *    user specified --uid on the command line.
	 *
	 * ++++ /etc/passwd with User ID < 400 @ 2021.06.18 15:38 CEST
	 * 0        root:x:0:0:root
	 * 1        bin:x:1:1:bin
	 * 2        daemon:x:2:2:daemon
	 * 3        adm:x:3:4:adm
	 * 4        lp:x:4:7:lp
	 * 5        sync:x:5:0:sync
	 * 6        shutdown:x:6:0:shutdown
	 * 7        halt:x:7:0:halt
	 * 9        news:x:9:13:news
	 * 10       uucp:x:10:14:uucp
	 * 11       operator:x:11:0:operator
	 * 16       cron:x:16:16:cron services
	 * 22       sshd:x:22:22:SSH Daemon
	 * 70       postgres:x:70:70:PostgreSQL daemon
	 * 72       tcpdump:x:72:72:User for tcpdump
	 * 81       apache:x:81:81:Apache HTTP server
	 * 101      uuidd:x:101:403:UUID generator helper daemon
	 * 102      messagebus:x:102:405:D-Bus system daemon
	 * 103      paludisbuild:x:103:443:Paludis package manager
	 * 123      ntp:x:123:123:NTP daemon
	 * 303      dhcpcd:x:303:303:User for dhcpcd
	 * 399      mlocate:x:399:399:
	 * 972      rrdtool:x:972:995:RRDtool user
	 * 973      pulse:x:973:997:pulseaudio daemon
	 * 975      man:x:975:999:man-db
	 * 976      ldap:x:976:103:OpenLDAP service daemon
	 * 977      ulogd:x:977:977:ulogd.init
	 * 979      pcscd:x:979:105:PCSC smart card daemon user
	 * 980      utmp:x:980:406:skarnet-utmps
	 * 981      clamav:x:981:106:Clam AntiVirus
	 * 982      polkitd:x:982:107:User for polkitd
	 * 983      timidity:x:983:18:Timidity++ daemon
	 * 984      bitlbee:x:984:108:Used by the bitlbee IM to IRC gateway
	 * 985      tor:x:985:109:Tor daemon
	 * 986      privoxy:x:986:110:Privoxy daemon
	 * 987      polipo:x:987:111:Polipo daemon
	 * 988      uptimed:x:988:100:
	 * 989      icecc:x:989:113:icecream daemon
	 * 990      postfix:x:990:115:Postfix services
	 * 991      dovenull:x:991:117:dovecot 2.0 login user
	 * 992      dovecot:x:992:118:dovecot 2.0 user for trusted processes
	 * 993      _smtpq:x:993:119:SMTP queue user
	 * 994      _smtpf:x:994:120:SMTP filter user
	 * 995      _smtpd:x:995:121:SMTP Daemon
	 * 996      znc:x:996:122:Used by the znc IRC Bouncer
	 * 997      nginx:x:997:398:user for nginx HTTP server
	 * 999      wizard:x:999:402:Games-Master
	 * 1000     alip:x:1000:1000:
	 * ++++
	 *
	 * Default restriction for changing group identity is similar to
	 * the default restriction for changing user identity. Here the
	 * restriction is to not permit any change of user identity in
	 * the range root and uucp inclusive. This is [0..14]. The
	 * exception about the command line flag --gid applies.
	 *
	 * ++++ /etc/group with Group ID < 1000 @ 2021.06.18 15:46 CEST
	 * 0        root:x:0:root
	 * 1        bin:x:1:root,bin,daemon
	 * 2        daemon:x:2:root,bin,daemon
	 * 3        sys:x:3:root,bin,adm
	 * 4        adm:x:4:root,adm,daemon
	 * 5        tty:x:5:paludisbuild
	 * 6        disk:x:6:root,adm
	 * 7        lp:x:7:lp
	 * 8        mem:x:8
	 * 9        kmem:x:9
	 * 10       wheel:x:10:root
	 * 11       floppy:x:11:root
	 * 12       mail:x:12
	 * 13       news:x:13:news
	 * 14       uucp:x:14:uucp
	 * 16       cron:x:16:
	 * 17       console:x:17
	 * 18       audio:x:18:
	 * 19       cdrom:x:19:
	 * 20       dialout:x:20
	 * 22       sshd:x:22
	 * 26       tape:x:26:root
	 * 27       video:x:27:root
	 * 70       postgres:x:70
	 * 72       tcpdump:x:72
	 * 80       cdrw:x:80
	 * 81       apache:x:81
	 * 85       usb:x:85:
	 * 100      users:x:100:alip
	 * 101      pulse-rt:x:101
	 * 102      jackuser:x:102
	 * 103      ldap:x:103
	 * 104      scard:x:104
	 * 105      pcscd:x:105
	 * 106      clamav:x:106
	 * 107      polkitd:x:107
	 * 108      bitlbee:x:108
	 * 109      tor:x:109
	 * 110      privoxy:x:110
	 * 111      polipo:x:111
	 * 112      lpadmin:x:112
	 * 113      icecc:x:113
	 * 114      kvm:x:114
	 * 115      postfix:x:115
	 * 116      postdrop:x:116
	 * 117      dovenull:x:117
	 * 118      dovecot:x:118
	 * 119      _smtpq:x:119
	 * 120      _smtpf:x:120
	 * 121      _smtpd:x:121
	 * 122      znc:x:122
	 * 123      ntp:x:123
	 * 303      dhcpcd:x:303
	 * 398      nginx:x:398:
	 * 399      mlocate:x:399
	 * 400      hugepagers:x:400:
	 * 401      input:x:401
	 * 402      games:x:402:alip
	 * 403      uuidd:x:403
	 * 404      plugdev:x:404
	 * 405      messagebus:x:405
	 * 406      utmp:x:406
	 * 443      paludisbuild:x:443
	 * 977      ulogd:x:977
	 * 995      rrdtool:x:995
	 * 996      pulse-access:x:996
	 * 997      pulse:x:997
	 * 999      man:x:999
	 * 1000     alip:x:1000
	 */
	if (magic_query_restrict_id(NULL)) /* on by default */
		goto skip_restrict_id;

#define SYD_UID_MIN 11 /* operator */
	uid_t user_uid = get_uid();
	if (user_uid == 0) {
		syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EINVAL),
				    SCMP_SYS(setuid), 1,
				    SCMP_A0_32( SCMP_CMP_LE, SYD_UID_MIN, SYD_UID_MIN ));
	} else {
		syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
				    SCMP_SYS(setuid), 1,
				    SCMP_A0_32( SCMP_CMP_NE, user_uid, user_uid ));
	}

#define SYD_GID_MIN 14 /* uucp */
	gid_t user_gid = get_gid();
	if (user_gid == 0) {
		syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EINVAL),
				    SCMP_SYS(setgid), 1,
				    SCMP_A0_32( SCMP_CMP_LE, SYD_GID_MIN, SYD_GID_MIN ));
	} else {
		syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
				    SCMP_SYS(setuid), 1,
				    SCMP_A0_32( SCMP_CMP_NE, user_gid, user_gid ));
	}
skip_restrict_id:

	/* Restrict get_random and block GRND_RANDOM to prevent the sandboxed
	 * process from exhausting the system entropy.
	 * This is in place together with the default denylist that prevents
	 * access to /dev/random.
	 */
	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EINVAL),
			    SCMP_SYS(getrandom), 1,
			    SCMP_A2_64( SCMP_CMP_MASKED_EQ,
					GRND_RANDOM, GRND_RANDOM));

	return 0;
}

static int filter_general_level_1(void)
{
	int r;

	for (unsigned i = 0; i < ELEMENTSOF(filter_gen_level1); i++) {
		syd_rule_add(sydbox->ctx, SCMP_ACT_ALLOW, filter_gen_level1[i],
			     0);
		if (r && r != -EEXIST && r != -EACCES && r != -EINVAL) {
			char *name;
			name = seccomp_syscall_resolve_num_arch(filter_gen_level1[i],
								SCMP_ARCH_NATIVE);
			errno = -r;
			say_errno("Sandbox failed to add syscall index %d (NR=%d) "
				  "name \"%s\" to Level 1. Received libseccomp error",
				  i, filter_gen_level1[i],
				  name ? name : "?");
			if (name)
				free(name);
			return r;
		}
	}

	if ((r = filter_open_readonly()) < 0)
		return r;

	return 0;
}

static int filter_general_level_2(void)
{
	int r;

	for (unsigned i = 0; i < ELEMENTSOF(filter_gen_level2); i++) {
		syd_rule_add(sydbox->ctx, SCMP_ACT_ALLOW, filter_gen_level2[i],
			     0);
		if (r && r != -EEXIST && r != -EACCES && r != -EINVAL) {
			char *name;
			name = seccomp_syscall_resolve_num_arch(filter_gen_level2[i],
								SCMP_ARCH_NATIVE);
			errno = -r;
			say_errno("Sandbox failed to add syscall index %d (NR=%d) "
				  "name \"%s\" to Level 2. Received libseccomp error",
				  i, filter_gen_level2[i],
				  name ? name : "?");
			if (name)
				free(name);
			return r;
		}
	}

#ifdef __NR_newfstatat
	// Libc 2.33 uses this syscall to implement both fstat() and stat().
	//
	// The trouble is that to implement fstat(fd, &st), it calls:
	//     newfstatat(fs, "", &st, AT_EMPTY_PATH)
	// We can't detect this usage in particular, because "" is a pointer
	// we don't control.  And we can't just look for AT_EMPTY_PATH, since
	// AT_EMPTY_PATH only has effect when the path string is empty.
	//
	// So our only solution seems to be allowing all fstatat calls, which
	// means that an attacker can stat() anything on the filesystem. That's
	// not a great solution, but I can't find a better one.
	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
			    SCMP_SYS(newfstatat), 0);
#endif

	if ((r = filter_time()) < 0)
		return r;
	if ((r = filter_rt_sigaction()) < 0)
		return r;

	return 0;
}

static int filter_general_level_3(void)
{
	int r;

	for (unsigned i = 0; i < ELEMENTSOF(filter_gen_level3); i++) {
		syd_rule_add(sydbox->ctx, SCMP_ACT_ALLOW, filter_gen_level3[i],
			     0);
		if (r && r != -EEXIST && r != -EACCES && r != -EINVAL) {
			char *name;
			name = seccomp_syscall_resolve_num_arch(filter_gen_level3[i],
								SCMP_ARCH_NATIVE);
			errno = -r;
			say_errno("Sandbox failed to add syscall index %d (NR=%d) "
				  "name \"%s\" to Level 3. Received libseccomp error",
				  i, filter_gen_level3[i],
				  name ? name : "?");
			if (name)
				free(name);
			return r;
		}
	}

#ifdef __NR_newfstatat
	// Libc 2.33 uses this syscall to implement both fstat() and stat().
	//
	// The trouble is that to implement fstat(fd, &st), it calls:
	//     newfstatat(fs, "", &st, AT_EMPTY_PATH)
	// We can't detect this usage in particular, because "" is a pointer
	// we don't control.  And we can't just look for AT_EMPTY_PATH, since
	// AT_EMPTY_PATH only has effect when the path string is empty.
	//
	// So our only solution seems to be allowing all fstatat calls, which
	// means that an attacker can stat() anything on the filesystem. That's
	// not a great solution, but I can't find a better one.
	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
			    SCMP_SYS(newfstatat), 0);
#endif

	if ((r = filter_open_readonly()) < 0)
		return r;
	if ((r = filter_time()) < 0)
		return r;
	if ((r = filter_rt_sigaction()) < 0)
		return r;

	return 0;
}

int filter_general(void)
{
	int r;
	static const int allow_calls[] = {
		SCMP_SYS(exit),
		SCMP_SYS(exit_group),
		SCMP_SYS(arch_prctl),
		SCMP_SYS(membarrier),
		SCMP_SYS(set_tid_address),
		SCMP_SYS(rt_sigprocmask),
	};

	if (sydbox->seccomp_action != SCMP_ACT_ALLOW) {
		for (unsigned int i = 0; i < ELEMENTSOF(allow_calls); i++)
			syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
					    allow_calls[i], 0);
	}

	switch (sydbox->config.restrict_general) {
	case 0:
		break;
	case 1:
		return filter_general_level_1();
	case 2:
		return filter_general_level_2();
	case 3:
		return filter_general_level_3();
	default:
		return -EINVAL;
	}

	/*
	 * Level 0 filter is applied unconditionally
	 * regardless of the current restriction level.
	 */
	if ((r = filter_general_level_0()) < 0)
		return r;

	return 0;
}

static int filter_mmap_restrict_shared(int sys_mmap)
{
	int r;
	uint32_t action = SCMP_ACT_ERRNO(EPERM);

	if (action == sydbox->seccomp_action)
		return 0;

	syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
			    sys_mmap, 2,
			    SCMP_A2_32( SCMP_CMP_MASKED_EQ,
					PROT_WRITE, PROT_WRITE ),
			    SCMP_A3_64( SCMP_CMP_MASKED_EQ,
					MAP_SHARED, MAP_SHARED ));
	return 0;
}

static int filter_mmap_restrict(int sys_mmap)
{
	int r;
	uint32_t action = SCMP_ACT_ALLOW;

	if (action == sydbox->seccomp_action)
		return 0;

	syd_rule_add_return(sydbox->ctx, action,
				  sys_mmap, 2,
				  SCMP_CMP32(2, SCMP_CMP_EQ, PROT_READ),
				  SCMP_CMP64(3, SCMP_CMP_EQ, MAP_PRIVATE));
	syd_rule_add_return(sydbox->ctx, action,
			    sys_mmap, 2,
			    SCMP_CMP32(2, SCMP_CMP_EQ, PROT_NONE),
			    SCMP_CMP64(3, SCMP_CMP_EQ,
				       MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE));
	syd_rule_add_return(sydbox->ctx, action,
			    sys_mmap, 2,
			    SCMP_CMP32(2, SCMP_CMP_EQ,
				       PROT_READ|PROT_WRITE),
			    SCMP_CMP64(3, SCMP_CMP_EQ,
				       MAP_PRIVATE|MAP_ANONYMOUS));
	syd_rule_add_return(sydbox->ctx, action,
			    sys_mmap, 2,
			    SCMP_CMP32(2, SCMP_CMP_EQ,
				       PROT_READ|PROT_WRITE),
			    SCMP_CMP64(3, SCMP_CMP_EQ,
				       MAP_PRIVATE|MAP_ANONYMOUS|MAP_STACK));
	syd_rule_add_return(sydbox->ctx, action,
			    sys_mmap, 2,
			    SCMP_CMP32(2, SCMP_CMP_EQ,
				       PROT_READ|PROT_WRITE),
			    SCMP_CMP64(3, SCMP_CMP_EQ,
				       MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE));
	syd_rule_add_return(sydbox->ctx, action,
			    sys_mmap, 2,
			    SCMP_CMP32(2, SCMP_CMP_EQ,
				       PROT_READ|PROT_WRITE),
			    SCMP_CMP64(3, SCMP_CMP_EQ,
				       MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS));
	syd_rule_add_return(sydbox->ctx, action,
			    sys_mmap, 2,
			    SCMP_CMP32(2, SCMP_CMP_EQ,
				       PROT_READ|PROT_EXEC),
			    SCMP_CMP64(3, SCMP_CMP_EQ,
				       MAP_PRIVATE|MAP_DENYWRITE));
	if (sydbox->seccomp_action != SCMP_ACT_ERRNO(EPERM))
		syd_rule_add_return(sydbox->ctx, SCMP_ACT_ERRNO(EPERM),
				    sys_mmap, 0);
	return 0;
}

int filter_mmap(uint32_t arch)
{
	if (sydbox->config.restrict_shm_wr)
		return filter_mmap_restrict_shared(SCMP_SYS(mmap));
	else if (sydbox->config.restrict_mmap)
		return filter_mmap_restrict(SCMP_SYS(mmap));
	else
		return 0;
}

int filter_mmap2(uint32_t arch)
{
	if (sydbox->config.restrict_shm_wr)
		return filter_mmap_restrict_shared(SCMP_SYS(mmap2));
	else if (sydbox->config.restrict_mmap)
		return filter_mmap_restrict(SCMP_SYS(mmap2));
	else
		return 0;
}

int filter_mprotect(uint32_t arch)
{
	int r;
	uint32_t action;

	action = SCMP_ACT_ERRNO(EPERM);
	if (action == sydbox->seccomp_action)
		return 0;

	r = 0;
	if (sydbox->config.restrict_mmap) {
		syd_rule_add(sydbox->ctx, action,
			     SCMP_SYS(mprotect), 2,
			     SCMP_CMP32(2, SCMP_CMP_NE, PROT_READ),
			     SCMP_CMP32(2, SCMP_CMP_NE, PROT_READ|PROT_WRITE));
	} else if (sydbox->seccomp_action != SCMP_ACT_ALLOW) {
		syd_rule_add(sydbox->ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
	}
	return r == -EEXIST ? 0 : r;
}

int filter_ioctl(uint32_t arch)
{
	static const unsigned long request[] = {
		TCGETS,
		TIOCGLCKTRMIOS,
		TIOCGWINSZ,
		TIOCSWINSZ,
		FIONREAD,
		TIOCINQ,
		TIOCOUTQ,
		TCFLSH,
		TIOCSTI,
		TIOCSCTTY,
		TIOCNOTTY,
		TIOCGPGRP,
		TIOCSPGRP,
		TIOCGSID,
		TIOCEXCL,
		TIOCGEXCL,
		TIOCNXCL,
		TIOCGETD,
		TIOCSETD,
		TIOCPKT,
		TIOCGPKT,
		TIOCSPTLCK,
		TIOCGPTLCK,
		TIOCGPTPEER,
		TIOCGSOFTCAR,
		TIOCSSOFTCAR,
		KDGETLED,
		KDSETLED,
		KDGKBLED,
		KDSKBLED,
		KDGKBTYPE,
		KDGETMODE,
		KDSETMODE,
		KDMKTONE,
		KIOCSOUND,
		GIO_CMAP,
		PIO_CMAP,
		GIO_FONT,
		PIO_FONT,
		GIO_FONTX,
		PIO_FONTX,
		PIO_FONTRESET,
		GIO_SCRNMAP,
		PIO_SCRNMAP,
		GIO_UNISCRNMAP,
		PIO_UNISCRNMAP,
		GIO_UNIMAP,
		PIO_UNIMAP,
		PIO_UNIMAPCLR,
		KDGKBMODE,
		KDSKBMODE,
		KDGKBMETA,
		KDSKBMETA,
		KDGKBENT,
		KDSKBENT,
		KDGKBSENT,
		KDSKBSENT,
		KDGKBDIACR,
		KDGETKEYCODE,
		KDSETKEYCODE,
		KDSIGACCEPT,
		VT_OPENQRY,
		VT_GETMODE,
		VT_SETMODE,
		VT_GETSTATE,
		VT_RELDISP,
		VT_ACTIVATE,
		VT_WAITACTIVE,
		VT_DISALLOCATE,
		VT_RESIZE,
		VT_RESIZEX,
	};

	int r;
	if (sydbox->seccomp_action != SCMP_ACT_ALLOW)
		for (unsigned short i = 0; i < ELEMENTSOF(request); i++)
			syd_rule_add_return(sydbox->ctx, SCMP_ACT_ALLOW,
					    SCMP_SYS(ioctl), 1,
					    SCMP_CMP64(1, SCMP_CMP_EQ,
						       request[i]));
	if (sydbox->config.restrict_ioctl &&
	    sydbox->seccomp_action != SCMP_ACT_ERRNO(EPERM))
		syd_rule_add_return(sydbox->ctx,
				    SCMP_ACT_ERRNO(EPERM),
				    SCMP_SYS(ioctl), 0);
	return 0;
}
