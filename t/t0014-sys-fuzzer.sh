#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test fuzzing system calls under SydBox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=''
export SYDBOX_TEST_OPTIONS

for syscall_name in \
        mmap{,2} mprotect ioctl lstat statx \
        access faccessat{,2} open openat{,2} \
        creat chmod fchmodat chown lchown \
        fchownat mkdir{,at} mknod{,at} \
        rmdir truncate utime utimes utimensat \
        futimesat unlink{,at} link{,at} \
        rename renameat{,2} symlink{,at} \
        execve execveat \
        bind connect sendto listen accept{,4} \
        getsockname sendmsg recvmsg \
        {,l}listxattr {,l}setxattr {,l}removexattr \
        mount umount{,2} \
        acct add_key adjtimex afs_syscall chroot finit_module fsmount \
        get_kernel_syms init_module kexec_file_load kexec_load keyctl \
        memfd_create mount move_mount nfsservctl pidfd_getfd pidfd_open \
        pidfd_send_signal pivot_root pkey_alloc pkey_free pkey_mprotect \
        process_vm_readv process_vm_writev ptrace quotactl reboot request_key \
        seccomp security setdomainname sethostname shmat shmctl shmdt shmget \
        swapoff swapon umount umount2 unshare uselib vm86 vm86old vserver \
        _llseek _newselect _sysctl accept accept4 access alarm arch_prctl \
        bdflush bind bpf break brk capget capset chdir chmod chown chown32 \
        clock_adjtime clock_adjtime64 clock_getres clock_getres_time64 \
        clock_gettime clock_gettime64 clock_nanosleep clock_nanosleep_time64 \
        clock_settime clock_settime64 clone clone3 close close_range connect \
        copy_file_range creat create_module delete_module dup dup2 dup3 \
        epoll_create epoll_create1 epoll_ctl epoll_ctl_old epoll_pwait \
        epoll_pwait2 epoll_wait epoll_wait_old eventfd eventfd2 execve execveat \
        exit exit_group faccessat faccessat2 fadvise64 fadvise64_64 fallocate \
        fanotify_init fanotify_mark fchdir fchmod fchmodat fchown fchown32 \
        fchownat fcntl fcntl64 fdatasync fgetxattr flistxattr flock fork \
        fremovexattr fsconfig fsetxattr fsopen fspick fstat fstat64 fstatat64 \
        fstatfs fstatfs64 fsync ftime ftruncate ftruncate64 futex futex_time64 \
        futimesat get_mempolicy get_robust_list get_thread_area getcpu getcwd \
        getdents getdents64 getegid getegid32 geteuid geteuid32 getgid getgid32 \
        getgroups getgroups32 getitimer getpeername getpgid getpgrp getpid \
        getpmsg getppid getpriority getrandom getresgid getresgid32 getresuid \
        getresuid32 getrlimit getrusage getsid getsockname getsockopt gettid \
        gettimeofday getuid getuid32 getxattr gtty idle inotify_add_watch \
        inotify_init inotify_init1 inotify_rm_watch io_cancel io_destroy \
        io_getevents io_pgetevents io_pgetevents_time64 io_setup io_submit \
        io_uring_enter io_uring_register io_uring_setup ioctl ioperm iopl \
        ioprio_get ioprio_set ipc kcmp kill lchown lchown32 lgetxattr link \
        linkat listen listxattr llistxattr lock lookup_dcookie lremovexattr \
        lseek lsetxattr lstat lstat64 madvise mbind membarrier migrate_pages \
        mincore mkdir mkdirat mknod mknodat mlock mlock2 mlockall mmap mmap2 \
        modify_ldt move_pages mprotect mpx mq_getsetattr mq_notify mq_open \
        mq_timedreceive mq_timedreceive_time64 mq_timedsend mq_timedsend_time64 \
        mq_unlink mremap msgctl msgget msgrcv msgsnd msync munlock munlockall \
        munmap name_to_handle_at nanosleep newfstatat nice oldfstat oldlstat \
        oldolduname oldstat olduname open open_by_handle_at open_tree openat \
        openat2 pause perf_event_open personality pipe pipe2 poll ppoll \
        ppoll_time64 prctl pread64 preadv preadv2 prlimit64 process_madvise prof \
        profil pselect6 pselect6_time64 putpmsg pwrite64 pwritev pwritev2 \
        query_module read readahead readdir readlink readlinkat readv recvfrom \
        recvmmsg recvmmsg_time64 recvmsg remap_file_pages removexattr rename \
        renameat renameat2 restart_syscall rmdir rseq rt_sigaction rt_sigpending \
        rt_sigprocmask rt_sigqueueinfo rt_sigreturn rt_sigsuspend \
        rt_sigtimedwait rt_sigtimedwait_time64 rt_tgsigqueueinfo \
        sched_get_priority_max sched_get_priority_min sched_getaffinity \
        sched_getattr sched_getparam sched_getscheduler sched_rr_get_interval \
        sched_rr_get_interval_time64 sched_setaffinity sched_setattr \
        sched_setparam sched_setscheduler sched_yield select semctl semget semop \
        semtimedop semtimedop_time64 sendfile sendfile64 sendmmsg sendmsg sendto \
        set_mempolicy set_robust_list set_thread_area set_tid_address setfsgid \
        setfsgid32 setfsuid setfsuid32 setgid setgid32 setgroups setgroups32 \
        setitimer setns setpgid setpriority setregid setregid32 setresgid \
        setresgid32 setresuid setresuid32 setreuid setreuid32 setrlimit setsid \
        setsockopt settimeofday setuid setuid32 setxattr sgetmask shutdown \
        sigaction sigaltstack signal signalfd signalfd4 sigpending sigprocmask \
        sigreturn sigsuspend socket socketcall socketpair splice ssetmask stat \
        stat64 statfs statfs64 statx stime stty symlink symlinkat sync \
        sync_file_range syncfs sysfs sysinfo syslog tee tgkill time timer_create \
        timer_delete timer_getoverrun timer_gettime timer_gettime64 \
        timer_settime timer_settime64 timerfd_create timerfd_gettime \
        timerfd_gettime64 timerfd_settime timerfd_settime64 times tkill truncate \
        truncate64 tuxcall ugetrlimit ulimit umask uname unlink unlinkat \
        userfaultfd ustat utime utimensat utimensat_time64 utimes vfork vhangup \
        vmsplice wait4 waitid waitpid write writev; do
    test_expect_success TRINITY \
        "fuzzing $syscall_name does not generate any failures [memory_access:0]" '
    syd \
        -M '0' \
        -c "${TEST_DIRECTORY}/test-data/trinity.syd-2" \
        -m "allowlist/write+${HOMER}/***" \
        -- timeout -k3 15 trinity -q --stats -l off -N64 -c '$syscall_name'
'; done

test_done
