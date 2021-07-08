/* `sysconf', `pathconf', and `confstr' NAME values.  Generic version.
   Copyright (C) 1993-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef SYD_CONFNAME_H
# define SYD_CONFNAME_H 1

/* Values for the NAME argument to `pathconf' and `fpathconf'.  */
enum
  {
    SYD_PC_LINK_MAX,
#define	SYD_PC_LINK_MAX			SYD_PC_LINK_MAX
    SYD_PC_MAX_CANON,
#define	SYD_PC_MAX_CANON			SYD_PC_MAX_CANON
    SYD_PC_MAX_INPUT,
#define	SYD_PC_MAX_INPUT			SYD_PC_MAX_INPUT
    SYD_PC_NAME_MAX,
#define	SYD_PC_NAME_MAX			SYD_PC_NAME_MAX
    SYD_PC_PATH_MAX,
#define	SYD_PC_PATH_MAX			SYD_PC_PATH_MAX
    SYD_PC_PIPE_BUF,
#define	SYD_PC_PIPE_BUF			SYD_PC_PIPE_BUF
    SYD_PC_CHOWN_RESTRICTED,
#define	SYD_PC_CHOWN_RESTRICTED		SYD_PC_CHOWN_RESTRICTED
    SYD_PC_NO_TRUNC,
#define	SYD_PC_NO_TRUNC			SYD_PC_NO_TRUNC
    SYD_PC_VDISABLE,
#define SYD_PC_VDISABLE			SYD_PC_VDISABLE
    SYD_PC_SYNC_IO,
#define	SYD_PC_SYNC_IO			SYD_PC_SYNC_IO
    SYD_PC_ASYNC_IO,
#define	SYD_PC_ASYNC_IO			SYD_PC_ASYNC_IO
    SYD_PC_PRIO_IO,
#define	SYD_PC_PRIO_IO			SYD_PC_PRIO_IO
    SYD_PC_SOCK_MAXBUF,
#define	SYD_PC_SOCK_MAXBUF			SYD_PC_SOCK_MAXBUF
    SYD_PC_FILESIZEBITS,
#define SYD_PC_FILESIZEBITS		SYD_PC_FILESIZEBITS
    SYD_PC_REC_INCR_XFER_SIZE,
#define SYD_PC_REC_INCR_XFER_SIZE		SYD_PC_REC_INCR_XFER_SIZE
    SYD_PC_REC_MAX_XFER_SIZE,
#define SYD_PC_REC_MAX_XFER_SIZE		SYD_PC_REC_MAX_XFER_SIZE
    SYD_PC_REC_MIN_XFER_SIZE,
#define SYD_PC_REC_MIN_XFER_SIZE		SYD_PC_REC_MIN_XFER_SIZE
    SYD_PC_REC_XFER_ALIGN,
#define SYD_PC_REC_XFER_ALIGN		SYD_PC_REC_XFER_ALIGN
    SYD_PC_ALLOC_SIZE_MIN,
#define SYD_PC_ALLOC_SIZE_MIN		SYD_PC_ALLOC_SIZE_MIN
    SYD_PC_SYMLINK_MAX,
#define SYD_PC_SYMLINK_MAX			SYD_PC_SYMLINK_MAX
    SYD_PC_2_SYMLINKS
#define SYD_PC_2_SYMLINKS			SYD_PC_2_SYMLINKS
  };

/* Values for the argument to `sysconf'.  */
enum
  {
    SYD_SC_ARG_MAX,
#define	SYD_SC_ARG_MAX			SYD_SC_ARG_MAX
    SYD_SC_CHILD_MAX,
#define	SYD_SC_CHILD_MAX			SYD_SC_CHILD_MAX
    SYD_SC_CLK_TCK,
#define	SYD_SC_CLK_TCK			SYD_SC_CLK_TCK
    SYD_SC_NGROUPS_MAX,
#define	SYD_SC_NGROUPS_MAX			SYD_SC_NGROUPS_MAX
    SYD_SC_OPEN_MAX,
#define	SYD_SC_OPEN_MAX			SYD_SC_OPEN_MAX
    SYD_SC_STREAM_MAX,
#define	SYD_SC_STREAM_MAX			SYD_SC_STREAM_MAX
    SYD_SC_TZNAME_MAX,
#define	SYD_SC_TZNAME_MAX			SYD_SC_TZNAME_MAX
    SYD_SC_JOB_CONTROL,
#define	SYD_SC_JOB_CONTROL			SYD_SC_JOB_CONTROL
    SYD_SC_SAVED_IDS,
#define	SYD_SC_SAVED_IDS			SYD_SC_SAVED_IDS
    SYD_SC_REALTIME_SIGNALS,
#define	SYD_SC_REALTIME_SIGNALS		SYD_SC_REALTIME_SIGNALS
    SYD_SC_PRIORITYSYD_SCHEDULING,
#define	SYD_SC_PRIORITYSYD_SCHEDULING		SYD_SC_PRIORITYSYD_SCHEDULING
    SYD_SC_TIMERS,
#define	SYD_SC_TIMERS			SYD_SC_TIMERS
    SYD_SC_ASYNCHRONOUS_IO,
#define	SYD_SC_ASYNCHRONOUS_IO		SYD_SC_ASYNCHRONOUS_IO
    SYD_SC_PRIORITIZED_IO,
#define	SYD_SC_PRIORITIZED_IO		SYD_SC_PRIORITIZED_IO
    SYD_SC_SYNCHRONIZED_IO,
#define	SYD_SC_SYNCHRONIZED_IO		SYD_SC_SYNCHRONIZED_IO
    SYD_SC_FSYNC,
#define	SYD_SC_FSYNC			SYD_SC_FSYNC
    SYD_SC_MAPPED_FILES,
#define	SYD_SC_MAPPED_FILES		SYD_SC_MAPPED_FILES
    SYD_SC_MEMLOCK,
#define	SYD_SC_MEMLOCK			SYD_SC_MEMLOCK
    SYD_SC_MEMLOCK_RANGE,
#define	SYD_SC_MEMLOCK_RANGE		SYD_SC_MEMLOCK_RANGE
    SYD_SC_MEMORY_PROTECTION,
#define	SYD_SC_MEMORY_PROTECTION		SYD_SC_MEMORY_PROTECTION
    SYD_SC_MESSAGE_PASSING,
#define	SYD_SC_MESSAGE_PASSING		SYD_SC_MESSAGE_PASSING
    SYD_SC_SEMAPHORES,
#define	SYD_SC_SEMAPHORES			SYD_SC_SEMAPHORES
    SYD_SC_SHARED_MEMORY_OBJECTS,
#define	SYD_SC_SHARED_MEMORY_OBJECTS	SYD_SC_SHARED_MEMORY_OBJECTS
    SYD_SC_AIO_LISTIO_MAX,
#define	SYD_SC_AIO_LISTIO_MAX		SYD_SC_AIO_LISTIO_MAX
    SYD_SC_AIO_MAX,
#define	SYD_SC_AIO_MAX			SYD_SC_AIO_MAX
    SYD_SC_AIO_PRIO_DELTA_MAX,
#define	SYD_SC_AIO_PRIO_DELTA_MAX		SYD_SC_AIO_PRIO_DELTA_MAX
    SYD_SC_DELAYTIMER_MAX,
#define	SYD_SC_DELAYTIMER_MAX		SYD_SC_DELAYTIMER_MAX
    SYD_SC_MQ_OPEN_MAX,
#define	SYD_SC_MQ_OPEN_MAX			SYD_SC_MQ_OPEN_MAX
    SYD_SC_MQ_PRIO_MAX,
#define	SYD_SC_MQ_PRIO_MAX			SYD_SC_MQ_PRIO_MAX
    SYD_SC_VERSION,
#define	SYD_SC_VERSION			SYD_SC_VERSION
    SYD_SC_PAGESIZE,
#define	SYD_SC_PAGESIZE			SYD_SC_PAGESIZE
#define	SYD_SC_PAGE_SIZE			SYD_SC_PAGESIZE
    SYD_SC_RTSIG_MAX,
#define	SYD_SC_RTSIG_MAX			SYD_SC_RTSIG_MAX
    SYD_SC_SEM_NSEMS_MAX,
#define	SYD_SC_SEM_NSEMS_MAX		SYD_SC_SEM_NSEMS_MAX
    SYD_SC_SEM_VALUE_MAX,
#define	SYD_SC_SEM_VALUE_MAX		SYD_SC_SEM_VALUE_MAX
    SYD_SC_SIGQUEUE_MAX,
#define	SYD_SC_SIGQUEUE_MAX		SYD_SC_SIGQUEUE_MAX
    SYD_SC_TIMER_MAX,
#define	SYD_SC_TIMER_MAX			SYD_SC_TIMER_MAX

    /* Values for the argument to `sysconf'
       corresponding to _POSIX2_* symbols.  */
    SYD_SC_BC_BASE_MAX,
#define	SYD_SC_BC_BASE_MAX			SYD_SC_BC_BASE_MAX
    SYD_SC_BC_DIM_MAX,
#define	SYD_SC_BC_DIM_MAX			SYD_SC_BC_DIM_MAX
    SYD_SC_BCSYD_SCALE_MAX,
#define	SYD_SC_BCSYD_SCALE_MAX		SYD_SC_BCSYD_SCALE_MAX
    SYD_SC_BC_STRING_MAX,
#define	SYD_SC_BC_STRING_MAX		SYD_SC_BC_STRING_MAX
    SYD_SC_COLL_WEIGHTS_MAX,
#define	SYD_SC_COLL_WEIGHTS_MAX		SYD_SC_COLL_WEIGHTS_MAX
    SYD_SC_EQUIV_CLASS_MAX,
#define	SYD_SC_EQUIV_CLASS_MAX		SYD_SC_EQUIV_CLASS_MAX
    SYD_SC_EXPR_NEST_MAX,
#define	SYD_SC_EXPR_NEST_MAX		SYD_SC_EXPR_NEST_MAX
    SYD_SC_LINE_MAX,
#define	SYD_SC_LINE_MAX			SYD_SC_LINE_MAX
    SYD_SC_RE_DUP_MAX,
#define	SYD_SC_RE_DUP_MAX			SYD_SC_RE_DUP_MAX
    SYD_SC_CHARCLASS_NAME_MAX,
#define	SYD_SC_CHARCLASS_NAME_MAX		SYD_SC_CHARCLASS_NAME_MAX

    SYD_SC_2_VERSION,
#define	SYD_SC_2_VERSION			SYD_SC_2_VERSION
    SYD_SC_2_C_BIND,
#define	SYD_SC_2_C_BIND			SYD_SC_2_C_BIND
    SYD_SC_2_C_DEV,
#define	SYD_SC_2_C_DEV			SYD_SC_2_C_DEV
    SYD_SC_2_FORT_DEV,
#define	SYD_SC_2_FORT_DEV			SYD_SC_2_FORT_DEV
    SYD_SC_2_FORT_RUN,
#define	SYD_SC_2_FORT_RUN			SYD_SC_2_FORT_RUN
    SYD_SC_2_SW_DEV,
#define	SYD_SC_2_SW_DEV			SYD_SC_2_SW_DEV
    SYD_SC_2_LOCALEDEF,
#define	SYD_SC_2_LOCALEDEF			SYD_SC_2_LOCALEDEF

    SYD_SC_PII,
#define	SYD_SC_PII				SYD_SC_PII
    SYD_SC_PII_XTI,
#define	SYD_SC_PII_XTI			SYD_SC_PII_XTI
    SYD_SC_PII_SOCKET,
#define	SYD_SC_PII_SOCKET			SYD_SC_PII_SOCKET
    SYD_SC_PII_INTERNET,
#define	SYD_SC_PII_INTERNET		SYD_SC_PII_INTERNET
    SYD_SC_PII_OSI,
#define	SYD_SC_PII_OSI			SYD_SC_PII_OSI
    SYD_SC_POLL,
#define	SYD_SC_POLL			SYD_SC_POLL
    SYD_SC_SELECT,
#define	SYD_SC_SELECT			SYD_SC_SELECT
    SYD_SC_UIO_MAXIOV,
#define	SYD_SC_UIO_MAXIOV			SYD_SC_UIO_MAXIOV
    SYD_SC_IOV_MAX = SYD_SC_UIO_MAXIOV,
#define SYD_SC_IOV_MAX			SYD_SC_IOV_MAX
    SYD_SC_PII_INTERNET_STREAM,
#define	SYD_SC_PII_INTERNET_STREAM		SYD_SC_PII_INTERNET_STREAM
    SYD_SC_PII_INTERNET_DGRAM,
#define	SYD_SC_PII_INTERNET_DGRAM		SYD_SC_PII_INTERNET_DGRAM
    SYD_SC_PII_OSI_COTS,
#define	SYD_SC_PII_OSI_COTS		SYD_SC_PII_OSI_COTS
    SYD_SC_PII_OSI_CLTS,
#define	SYD_SC_PII_OSI_CLTS		SYD_SC_PII_OSI_CLTS
    SYD_SC_PII_OSI_M,
#define	SYD_SC_PII_OSI_M			SYD_SC_PII_OSI_M
    SYD_SC_T_IOV_MAX,
#define	SYD_SC_T_IOV_MAX			SYD_SC_T_IOV_MAX

    /* Values according to POSIX 1003.1c (POSIX threads).  */
    SYD_SC_THREADS,
#define	SYD_SC_THREADS			SYD_SC_THREADS
    SYD_SC_THREAD_SAFE_FUNCTIONS,
#define SYD_SC_THREAD_SAFE_FUNCTIONS	SYD_SC_THREAD_SAFE_FUNCTIONS
    SYD_SC_GETGR_R_SIZE_MAX,
#define	SYD_SC_GETGR_R_SIZE_MAX		SYD_SC_GETGR_R_SIZE_MAX
    SYD_SC_GETPW_R_SIZE_MAX,
#define	SYD_SC_GETPW_R_SIZE_MAX		SYD_SC_GETPW_R_SIZE_MAX
    SYD_SC_LOGIN_NAME_MAX,
#define	SYD_SC_LOGIN_NAME_MAX		SYD_SC_LOGIN_NAME_MAX
    SYD_SC_TTY_NAME_MAX,
#define	SYD_SC_TTY_NAME_MAX		SYD_SC_TTY_NAME_MAX
    SYD_SC_THREAD_DESTRUCTOR_ITERATIONS,
#define	SYD_SC_THREAD_DESTRUCTOR_ITERATIONS SYD_SC_THREAD_DESTRUCTOR_ITERATIONS
    SYD_SC_THREAD_KEYS_MAX,
#define	SYD_SC_THREAD_KEYS_MAX		SYD_SC_THREAD_KEYS_MAX
    SYD_SC_THREAD_STACK_MIN,
#define	SYD_SC_THREAD_STACK_MIN		SYD_SC_THREAD_STACK_MIN
    SYD_SC_THREAD_THREADS_MAX,
#define	SYD_SC_THREAD_THREADS_MAX		SYD_SC_THREAD_THREADS_MAX
    SYD_SC_THREAD_ATTR_STACKADDR,
#define	SYD_SC_THREAD_ATTR_STACKADDR	SYD_SC_THREAD_ATTR_STACKADDR
    SYD_SC_THREAD_ATTR_STACKSIZE,
#define	SYD_SC_THREAD_ATTR_STACKSIZE	SYD_SC_THREAD_ATTR_STACKSIZE
    SYD_SC_THREAD_PRIORITYSYD_SCHEDULING,
#define	SYD_SC_THREAD_PRIORITYSYD_SCHEDULING	SYD_SC_THREAD_PRIORITYSYD_SCHEDULING
    SYD_SC_THREAD_PRIO_INHERIT,
#define	SYD_SC_THREAD_PRIO_INHERIT		SYD_SC_THREAD_PRIO_INHERIT
    SYD_SC_THREAD_PRIO_PROTECT,
#define	SYD_SC_THREAD_PRIO_PROTECT		SYD_SC_THREAD_PRIO_PROTECT
    SYD_SC_THREAD_PROCESS_SHARED,
#define	SYD_SC_THREAD_PROCESS_SHARED	SYD_SC_THREAD_PROCESS_SHARED

    SYD_SC_NPROCESSORS_CONF,
#define SYD_SC_NPROCESSORS_CONF		SYD_SC_NPROCESSORS_CONF
    SYD_SC_NPROCESSORS_ONLN,
#define SYD_SC_NPROCESSORS_ONLN		SYD_SC_NPROCESSORS_ONLN
    SYD_SC_PHYS_PAGES,
#define SYD_SC_PHYS_PAGES			SYD_SC_PHYS_PAGES
    SYD_SC_AVPHYS_PAGES,
#define SYD_SC_AVPHYS_PAGES		SYD_SC_AVPHYS_PAGES
    SYD_SC_ATEXIT_MAX,
#define SYD_SC_ATEXIT_MAX			SYD_SC_ATEXIT_MAX
    SYD_SC_PASS_MAX,
#define SYD_SC_PASS_MAX			SYD_SC_PASS_MAX

    SYD_SC_XOPEN_VERSION,
#define SYD_SC_XOPEN_VERSION		SYD_SC_XOPEN_VERSION
    SYD_SC_XOPEN_XCU_VERSION,
#define SYD_SC_XOPEN_XCU_VERSION		SYD_SC_XOPEN_XCU_VERSION
    SYD_SC_XOPEN_UNIX,
#define SYD_SC_XOPEN_UNIX			SYD_SC_XOPEN_UNIX
    SYD_SC_XOPEN_CRYPT,
#define SYD_SC_XOPEN_CRYPT			SYD_SC_XOPEN_CRYPT
    SYD_SC_XOPEN_ENH_I18N,
#define SYD_SC_XOPEN_ENH_I18N		SYD_SC_XOPEN_ENH_I18N
    SYD_SC_XOPEN_SHM,
#define SYD_SC_XOPEN_SHM			SYD_SC_XOPEN_SHM

    SYD_SC_2_CHAR_TERM,
#define SYD_SC_2_CHAR_TERM			SYD_SC_2_CHAR_TERM
    SYD_SC_2_C_VERSION,
#define SYD_SC_2_C_VERSION			SYD_SC_2_C_VERSION
    SYD_SC_2_UPE,
#define SYD_SC_2_UPE			SYD_SC_2_UPE

    SYD_SC_XOPEN_XPG2,
#define SYD_SC_XOPEN_XPG2			SYD_SC_XOPEN_XPG2
    SYD_SC_XOPEN_XPG3,
#define SYD_SC_XOPEN_XPG3			SYD_SC_XOPEN_XPG3
    SYD_SC_XOPEN_XPG4,
#define SYD_SC_XOPEN_XPG4			SYD_SC_XOPEN_XPG4

    SYD_SC_CHAR_BIT,
#define	SYD_SC_CHAR_BIT			SYD_SC_CHAR_BIT
    SYD_SC_CHAR_MAX,
#define	SYD_SC_CHAR_MAX			SYD_SC_CHAR_MAX
    SYD_SC_CHAR_MIN,
#define	SYD_SC_CHAR_MIN			SYD_SC_CHAR_MIN
    SYD_SC_INT_MAX,
#define	SYD_SC_INT_MAX			SYD_SC_INT_MAX
    SYD_SC_INT_MIN,
#define	SYD_SC_INT_MIN			SYD_SC_INT_MIN
    SYD_SC_LONG_BIT,
#define	SYD_SC_LONG_BIT			SYD_SC_LONG_BIT
    SYD_SC_WORD_BIT,
#define	SYD_SC_WORD_BIT			SYD_SC_WORD_BIT
    SYD_SC_MB_LEN_MAX,
#define	SYD_SC_MB_LEN_MAX			SYD_SC_MB_LEN_MAX
    SYD_SC_NZERO,
#define	SYD_SC_NZERO			SYD_SC_NZERO
    SYD_SC_SSIZE_MAX,
#define	SYD_SC_SSIZE_MAX			SYD_SC_SSIZE_MAX
    SYD_SCSYD_SCHAR_MAX,
#define	SYD_SCSYD_SCHAR_MAX			SYD_SCSYD_SCHAR_MAX
    SYD_SCSYD_SCHAR_MIN,
#define	SYD_SCSYD_SCHAR_MIN			SYD_SCSYD_SCHAR_MIN
    SYD_SC_SHRT_MAX,
#define	SYD_SC_SHRT_MAX			SYD_SC_SHRT_MAX
    SYD_SC_SHRT_MIN,
#define	SYD_SC_SHRT_MIN			SYD_SC_SHRT_MIN
    SYD_SC_UCHAR_MAX,
#define	SYD_SC_UCHAR_MAX			SYD_SC_UCHAR_MAX
    SYD_SC_UINT_MAX,
#define	SYD_SC_UINT_MAX			SYD_SC_UINT_MAX
    SYD_SC_ULONG_MAX,
#define	SYD_SC_ULONG_MAX			SYD_SC_ULONG_MAX
    SYD_SC_USHRT_MAX,
#define	SYD_SC_USHRT_MAX			SYD_SC_USHRT_MAX

    SYD_SC_NL_ARGMAX,
#define	SYD_SC_NL_ARGMAX			SYD_SC_NL_ARGMAX
    SYD_SC_NL_LANGMAX,
#define	SYD_SC_NL_LANGMAX			SYD_SC_NL_LANGMAX
    SYD_SC_NL_MSGMAX,
#define	SYD_SC_NL_MSGMAX			SYD_SC_NL_MSGMAX
    SYD_SC_NL_NMAX,
#define	SYD_SC_NL_NMAX			SYD_SC_NL_NMAX
    SYD_SC_NL_SETMAX,
#define	SYD_SC_NL_SETMAX			SYD_SC_NL_SETMAX
    SYD_SC_NL_TEXTMAX,
#define	SYD_SC_NL_TEXTMAX			SYD_SC_NL_TEXTMAX

    SYD_SC_XBS5_ILP32_OFF32,
#define SYD_SC_XBS5_ILP32_OFF32		SYD_SC_XBS5_ILP32_OFF32
    SYD_SC_XBS5_ILP32_OFFBIG,
#define SYD_SC_XBS5_ILP32_OFFBIG		SYD_SC_XBS5_ILP32_OFFBIG
    SYD_SC_XBS5_LP64_OFF64,
#define SYD_SC_XBS5_LP64_OFF64		SYD_SC_XBS5_LP64_OFF64
    SYD_SC_XBS5_LPBIG_OFFBIG,
#define SYD_SC_XBS5_LPBIG_OFFBIG		SYD_SC_XBS5_LPBIG_OFFBIG

    SYD_SC_XOPEN_LEGACY,
#define SYD_SC_XOPEN_LEGACY		SYD_SC_XOPEN_LEGACY
    SYD_SC_XOPEN_REALTIME,
#define SYD_SC_XOPEN_REALTIME		SYD_SC_XOPEN_REALTIME
    SYD_SC_XOPEN_REALTIME_THREADS,
#define SYD_SC_XOPEN_REALTIME_THREADS	SYD_SC_XOPEN_REALTIME_THREADS

    SYD_SC_ADVISORY_INFO,
#define SYD_SC_ADVISORY_INFO		SYD_SC_ADVISORY_INFO
    SYD_SC_BARRIERS,
#define SYD_SC_BARRIERS			SYD_SC_BARRIERS
    SYD_SC_BASE,
#define SYD_SC_BASE			SYD_SC_BASE
    SYD_SC_C_LANG_SUPPORT,
#define SYD_SC_C_LANG_SUPPORT		SYD_SC_C_LANG_SUPPORT
    SYD_SC_C_LANG_SUPPORT_R,
#define SYD_SC_C_LANG_SUPPORT_R		SYD_SC_C_LANG_SUPPORT_R
    SYD_SC_CLOCK_SELECTION,
#define SYD_SC_CLOCK_SELECTION		SYD_SC_CLOCK_SELECTION
    SYD_SC_CPUTIME,
#define SYD_SC_CPUTIME			SYD_SC_CPUTIME
    SYD_SC_THREAD_CPUTIME,
#define SYD_SC_THREAD_CPUTIME		SYD_SC_THREAD_CPUTIME
    SYD_SC_DEVICE_IO,
#define SYD_SC_DEVICE_IO			SYD_SC_DEVICE_IO
    SYD_SC_DEVICE_SPECIFIC,
#define SYD_SC_DEVICE_SPECIFIC		SYD_SC_DEVICE_SPECIFIC
    SYD_SC_DEVICE_SPECIFIC_R,
#define SYD_SC_DEVICE_SPECIFIC_R		SYD_SC_DEVICE_SPECIFIC_R
    SYD_SC_FD_MGMT,
#define SYD_SC_FD_MGMT			SYD_SC_FD_MGMT
    SYD_SC_FIFO,
#define SYD_SC_FIFO			SYD_SC_FIFO
    SYD_SC_PIPE,
#define SYD_SC_PIPE			SYD_SC_PIPE
    SYD_SC_FILE_ATTRIBUTES,
#define SYD_SC_FILE_ATTRIBUTES		SYD_SC_FILE_ATTRIBUTES
    SYD_SC_FILE_LOCKING,
#define SYD_SC_FILE_LOCKING		SYD_SC_FILE_LOCKING
    SYD_SC_FILE_SYSTEM,
#define SYD_SC_FILE_SYSTEM			SYD_SC_FILE_SYSTEM
    SYD_SC_MONOTONIC_CLOCK,
#define SYD_SC_MONOTONIC_CLOCK		SYD_SC_MONOTONIC_CLOCK
    SYD_SC_MULTI_PROCESS,
#define SYD_SC_MULTI_PROCESS		SYD_SC_MULTI_PROCESS
    SYD_SC_SINGLE_PROCESS,
#define SYD_SC_SINGLE_PROCESS		SYD_SC_SINGLE_PROCESS
    SYD_SC_NETWORKING,
#define SYD_SC_NETWORKING			SYD_SC_NETWORKING
    SYD_SC_READER_WRITER_LOCKS,
#define SYD_SC_READER_WRITER_LOCKS		SYD_SC_READER_WRITER_LOCKS
    SYD_SC_SPIN_LOCKS,
#define SYD_SC_SPIN_LOCKS			SYD_SC_SPIN_LOCKS
    SYD_SC_REGEXP,
#define SYD_SC_REGEXP			SYD_SC_REGEXP
    SYD_SC_REGEX_VERSION,
#define SYD_SC_REGEX_VERSION		SYD_SC_REGEX_VERSION
    SYD_SC_SHELL,
#define SYD_SC_SHELL			SYD_SC_SHELL
    SYD_SC_SIGNALS,
#define SYD_SC_SIGNALS			SYD_SC_SIGNALS
    SYD_SC_SPAWN,
#define SYD_SC_SPAWN			SYD_SC_SPAWN
    SYD_SC_SPORADIC_SERVER,
#define SYD_SC_SPORADIC_SERVER		SYD_SC_SPORADIC_SERVER
    SYD_SC_THREAD_SPORADIC_SERVER,
#define SYD_SC_THREAD_SPORADIC_SERVER	SYD_SC_THREAD_SPORADIC_SERVER
    SYD_SC_SYSTEM_DATABASE,
#define SYD_SC_SYSTEM_DATABASE		SYD_SC_SYSTEM_DATABASE
    SYD_SC_SYSTEM_DATABASE_R,
#define SYD_SC_SYSTEM_DATABASE_R		SYD_SC_SYSTEM_DATABASE_R
    SYD_SC_TIMEOUTS,
#define SYD_SC_TIMEOUTS			SYD_SC_TIMEOUTS
    SYD_SC_TYPED_MEMORY_OBJECTS,
#define SYD_SC_TYPED_MEMORY_OBJECTS	SYD_SC_TYPED_MEMORY_OBJECTS
    SYD_SC_USER_GROUPS,
#define SYD_SC_USER_GROUPS			SYD_SC_USER_GROUPS
    SYD_SC_USER_GROUPS_R,
#define SYD_SC_USER_GROUPS_R		SYD_SC_USER_GROUPS_R
    SYD_SC_2_PBS,
#define SYD_SC_2_PBS			SYD_SC_2_PBS
    SYD_SC_2_PBS_ACCOUNTING,
#define SYD_SC_2_PBS_ACCOUNTING		SYD_SC_2_PBS_ACCOUNTING
    SYD_SC_2_PBS_LOCATE,
#define SYD_SC_2_PBS_LOCATE		SYD_SC_2_PBS_LOCATE
    SYD_SC_2_PBS_MESSAGE,
#define SYD_SC_2_PBS_MESSAGE		SYD_SC_2_PBS_MESSAGE
    SYD_SC_2_PBS_TRACK,
#define SYD_SC_2_PBS_TRACK			SYD_SC_2_PBS_TRACK
    SYD_SC_SYMLOOP_MAX,
#define SYD_SC_SYMLOOP_MAX			SYD_SC_SYMLOOP_MAX
    SYD_SC_STREAMS,
#define SYD_SC_STREAMS			SYD_SC_STREAMS
    SYD_SC_2_PBS_CHECKPOINT,
#define SYD_SC_2_PBS_CHECKPOINT		SYD_SC_2_PBS_CHECKPOINT

    SYD_SC_V6_ILP32_OFF32,
#define SYD_SC_V6_ILP32_OFF32		SYD_SC_V6_ILP32_OFF32
    SYD_SC_V6_ILP32_OFFBIG,
#define SYD_SC_V6_ILP32_OFFBIG		SYD_SC_V6_ILP32_OFFBIG
    SYD_SC_V6_LP64_OFF64,
#define SYD_SC_V6_LP64_OFF64		SYD_SC_V6_LP64_OFF64
    SYD_SC_V6_LPBIG_OFFBIG,
#define SYD_SC_V6_LPBIG_OFFBIG		SYD_SC_V6_LPBIG_OFFBIG

    SYD_SC_HOST_NAME_MAX,
#define SYD_SC_HOST_NAME_MAX		SYD_SC_HOST_NAME_MAX
    SYD_SC_TRACE,
#define SYD_SC_TRACE			SYD_SC_TRACE
    SYD_SC_TRACE_EVENT_FILTER,
#define SYD_SC_TRACE_EVENT_FILTER		SYD_SC_TRACE_EVENT_FILTER
    SYD_SC_TRACE_INHERIT,
#define SYD_SC_TRACE_INHERIT		SYD_SC_TRACE_INHERIT
    SYD_SC_TRACE_LOG,
#define SYD_SC_TRACE_LOG			SYD_SC_TRACE_LOG

    SYD_SC_LEVEL1_ICACHE_SIZE,
#define SYD_SC_LEVEL1_ICACHE_SIZE		SYD_SC_LEVEL1_ICACHE_SIZE
    SYD_SC_LEVEL1_ICACHE_ASSOC,
#define SYD_SC_LEVEL1_ICACHE_ASSOC		SYD_SC_LEVEL1_ICACHE_ASSOC
    SYD_SC_LEVEL1_ICACHE_LINESIZE,
#define SYD_SC_LEVEL1_ICACHE_LINESIZE	SYD_SC_LEVEL1_ICACHE_LINESIZE
    SYD_SC_LEVEL1_DCACHE_SIZE,
#define SYD_SC_LEVEL1_DCACHE_SIZE		SYD_SC_LEVEL1_DCACHE_SIZE
    SYD_SC_LEVEL1_DCACHE_ASSOC,
#define SYD_SC_LEVEL1_DCACHE_ASSOC		SYD_SC_LEVEL1_DCACHE_ASSOC
    SYD_SC_LEVEL1_DCACHE_LINESIZE,
#define SYD_SC_LEVEL1_DCACHE_LINESIZE	SYD_SC_LEVEL1_DCACHE_LINESIZE
    SYD_SC_LEVEL2_CACHE_SIZE,
#define SYD_SC_LEVEL2_CACHE_SIZE		SYD_SC_LEVEL2_CACHE_SIZE
    SYD_SC_LEVEL2_CACHE_ASSOC,
#define SYD_SC_LEVEL2_CACHE_ASSOC		SYD_SC_LEVEL2_CACHE_ASSOC
    SYD_SC_LEVEL2_CACHE_LINESIZE,
#define SYD_SC_LEVEL2_CACHE_LINESIZE	SYD_SC_LEVEL2_CACHE_LINESIZE
    SYD_SC_LEVEL3_CACHE_SIZE,
#define SYD_SC_LEVEL3_CACHE_SIZE		SYD_SC_LEVEL3_CACHE_SIZE
    SYD_SC_LEVEL3_CACHE_ASSOC,
#define SYD_SC_LEVEL3_CACHE_ASSOC		SYD_SC_LEVEL3_CACHE_ASSOC
    SYD_SC_LEVEL3_CACHE_LINESIZE,
#define SYD_SC_LEVEL3_CACHE_LINESIZE	SYD_SC_LEVEL3_CACHE_LINESIZE
    SYD_SC_LEVEL4_CACHE_SIZE,
#define SYD_SC_LEVEL4_CACHE_SIZE		SYD_SC_LEVEL4_CACHE_SIZE
    SYD_SC_LEVEL4_CACHE_ASSOC,
#define SYD_SC_LEVEL4_CACHE_ASSOC		SYD_SC_LEVEL4_CACHE_ASSOC
    SYD_SC_LEVEL4_CACHE_LINESIZE,
#define SYD_SC_LEVEL4_CACHE_LINESIZE	SYD_SC_LEVEL4_CACHE_LINESIZE
    /* Leave room here, maybe we need a few more cache levels some day.  */

    SYD_SC_IPV6 = SYD_SC_LEVEL1_ICACHE_SIZE + 50,
#define SYD_SC_IPV6			SYD_SC_IPV6
    SYD_SC_RAW_SOCKETS,
#define SYD_SC_RAW_SOCKETS			SYD_SC_RAW_SOCKETS

    SYD_SC_V7_ILP32_OFF32,
#define SYD_SC_V7_ILP32_OFF32		SYD_SC_V7_ILP32_OFF32
    SYD_SC_V7_ILP32_OFFBIG,
#define SYD_SC_V7_ILP32_OFFBIG		SYD_SC_V7_ILP32_OFFBIG
    SYD_SC_V7_LP64_OFF64,
#define SYD_SC_V7_LP64_OFF64		SYD_SC_V7_LP64_OFF64
    SYD_SC_V7_LPBIG_OFFBIG,
#define SYD_SC_V7_LPBIG_OFFBIG		SYD_SC_V7_LPBIG_OFFBIG

    SYD_SC_SS_REPL_MAX,
#define SYD_SC_SS_REPL_MAX			SYD_SC_SS_REPL_MAX

    SYD_SC_TRACE_EVENT_NAME_MAX,
#define SYD_SC_TRACE_EVENT_NAME_MAX	SYD_SC_TRACE_EVENT_NAME_MAX
    SYD_SC_TRACE_NAME_MAX,
#define SYD_SC_TRACE_NAME_MAX		SYD_SC_TRACE_NAME_MAX
    SYD_SC_TRACE_SYS_MAX,
#define SYD_SC_TRACE_SYS_MAX		SYD_SC_TRACE_SYS_MAX
    SYD_SC_TRACE_USER_EVENT_MAX,
#define SYD_SC_TRACE_USER_EVENT_MAX	SYD_SC_TRACE_USER_EVENT_MAX

    SYD_SC_XOPEN_STREAMS,
#define SYD_SC_XOPEN_STREAMS		SYD_SC_XOPEN_STREAMS

    SYD_SC_THREAD_ROBUST_PRIO_INHERIT,
#define SYD_SC_THREAD_ROBUST_PRIO_INHERIT	SYD_SC_THREAD_ROBUST_PRIO_INHERIT
    SYD_SC_THREAD_ROBUST_PRIO_PROTECT
#define SYD_SC_THREAD_ROBUST_PRIO_PROTECT	SYD_SC_THREAD_ROBUST_PRIO_PROTECT
  };

/* Values for the NAME argument to `confstr'.  */
enum
  {
    SYD_CS_PATH,			/* The default search path.  */
#define SYD_CS_PATH		SYD_CS_PATH

    SYD_CS_V6_WIDTH_RESTRICTED_ENVS,
#define SYD_CS_V6_WIDTH_RESTRICTED_ENVS	SYD_CS_V6_WIDTH_RESTRICTED_ENVS
#define SYD_CS_POSIX_V6_WIDTH_RESTRICTED_ENVS	SYD_CS_V6_WIDTH_RESTRICTED_ENVS

    SYD_CS_GNU_LIBC_VERSION,
#define SYD_CS_GNU_LIBC_VERSION	SYD_CS_GNU_LIBC_VERSION
    SYD_CS_GNU_LIBPTHREAD_VERSION,
#define SYD_CS_GNU_LIBPTHREAD_VERSION	SYD_CS_GNU_LIBPTHREAD_VERSION

    SYD_CS_V5_WIDTH_RESTRICTED_ENVS,
#define SYD_CS_V5_WIDTH_RESTRICTED_ENVS	SYD_CS_V5_WIDTH_RESTRICTED_ENVS
#define SYD_CS_POSIX_V5_WIDTH_RESTRICTED_ENVS	SYD_CS_V5_WIDTH_RESTRICTED_ENVS

    SYD_CS_V7_WIDTH_RESTRICTED_ENVS,
#define SYD_CS_V7_WIDTH_RESTRICTED_ENVS	SYD_CS_V7_WIDTH_RESTRICTED_ENVS
#define SYD_CS_POSIX_V7_WIDTH_RESTRICTED_ENVS	SYD_CS_V7_WIDTH_RESTRICTED_ENVS

    SYD_CS_LFS_CFLAGS = 1000,
#define SYD_CS_LFS_CFLAGS	SYD_CS_LFS_CFLAGS
    SYD_CS_LFS_LDFLAGS,
#define SYD_CS_LFS_LDFLAGS	SYD_CS_LFS_LDFLAGS
    SYD_CS_LFS_LIBS,
#define SYD_CS_LFS_LIBS		SYD_CS_LFS_LIBS
    SYD_CS_LFS_LINTFLAGS,
#define SYD_CS_LFS_LINTFLAGS	SYD_CS_LFS_LINTFLAGS
    SYD_CS_LFS64_CFLAGS,
#define SYD_CS_LFS64_CFLAGS	SYD_CS_LFS64_CFLAGS
    SYD_CS_LFS64_LDFLAGS,
#define SYD_CS_LFS64_LDFLAGS	SYD_CS_LFS64_LDFLAGS
    SYD_CS_LFS64_LIBS,
#define SYD_CS_LFS64_LIBS	SYD_CS_LFS64_LIBS
    SYD_CS_LFS64_LINTFLAGS,
#define SYD_CS_LFS64_LINTFLAGS	SYD_CS_LFS64_LINTFLAGS

    SYD_CS_XBS5_ILP32_OFF32_CFLAGS = 1100,
#define SYD_CS_XBS5_ILP32_OFF32_CFLAGS SYD_CS_XBS5_ILP32_OFF32_CFLAGS
    SYD_CS_XBS5_ILP32_OFF32_LDFLAGS,
#define SYD_CS_XBS5_ILP32_OFF32_LDFLAGS SYD_CS_XBS5_ILP32_OFF32_LDFLAGS
    SYD_CS_XBS5_ILP32_OFF32_LIBS,
#define SYD_CS_XBS5_ILP32_OFF32_LIBS SYD_CS_XBS5_ILP32_OFF32_LIBS
    SYD_CS_XBS5_ILP32_OFF32_LINTFLAGS,
#define SYD_CS_XBS5_ILP32_OFF32_LINTFLAGS SYD_CS_XBS5_ILP32_OFF32_LINTFLAGS
    SYD_CS_XBS5_ILP32_OFFBIG_CFLAGS,
#define SYD_CS_XBS5_ILP32_OFFBIG_CFLAGS SYD_CS_XBS5_ILP32_OFFBIG_CFLAGS
    SYD_CS_XBS5_ILP32_OFFBIG_LDFLAGS,
#define SYD_CS_XBS5_ILP32_OFFBIG_LDFLAGS SYD_CS_XBS5_ILP32_OFFBIG_LDFLAGS
    SYD_CS_XBS5_ILP32_OFFBIG_LIBS,
#define SYD_CS_XBS5_ILP32_OFFBIG_LIBS SYD_CS_XBS5_ILP32_OFFBIG_LIBS
    SYD_CS_XBS5_ILP32_OFFBIG_LINTFLAGS,
#define SYD_CS_XBS5_ILP32_OFFBIG_LINTFLAGS SYD_CS_XBS5_ILP32_OFFBIG_LINTFLAGS
    SYD_CS_XBS5_LP64_OFF64_CFLAGS,
#define SYD_CS_XBS5_LP64_OFF64_CFLAGS SYD_CS_XBS5_LP64_OFF64_CFLAGS
    SYD_CS_XBS5_LP64_OFF64_LDFLAGS,
#define SYD_CS_XBS5_LP64_OFF64_LDFLAGS SYD_CS_XBS5_LP64_OFF64_LDFLAGS
    SYD_CS_XBS5_LP64_OFF64_LIBS,
#define SYD_CS_XBS5_LP64_OFF64_LIBS SYD_CS_XBS5_LP64_OFF64_LIBS
    SYD_CS_XBS5_LP64_OFF64_LINTFLAGS,
#define SYD_CS_XBS5_LP64_OFF64_LINTFLAGS SYD_CS_XBS5_LP64_OFF64_LINTFLAGS
    SYD_CS_XBS5_LPBIG_OFFBIG_CFLAGS,
#define SYD_CS_XBS5_LPBIG_OFFBIG_CFLAGS SYD_CS_XBS5_LPBIG_OFFBIG_CFLAGS
    SYD_CS_XBS5_LPBIG_OFFBIG_LDFLAGS,
#define SYD_CS_XBS5_LPBIG_OFFBIG_LDFLAGS SYD_CS_XBS5_LPBIG_OFFBIG_LDFLAGS
    SYD_CS_XBS5_LPBIG_OFFBIG_LIBS,
#define SYD_CS_XBS5_LPBIG_OFFBIG_LIBS SYD_CS_XBS5_LPBIG_OFFBIG_LIBS
    SYD_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS,
#define SYD_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS SYD_CS_XBS5_LPBIG_OFFBIG_LINTFLAGS

    SYD_CS_POSIX_V6_ILP32_OFF32_CFLAGS,
#define SYD_CS_POSIX_V6_ILP32_OFF32_CFLAGS SYD_CS_POSIX_V6_ILP32_OFF32_CFLAGS
    SYD_CS_POSIX_V6_ILP32_OFF32_LDFLAGS,
#define SYD_CS_POSIX_V6_ILP32_OFF32_LDFLAGS SYD_CS_POSIX_V6_ILP32_OFF32_LDFLAGS
    SYD_CS_POSIX_V6_ILP32_OFF32_LIBS,
#define SYD_CS_POSIX_V6_ILP32_OFF32_LIBS SYD_CS_POSIX_V6_ILP32_OFF32_LIBS
    SYD_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS,
#define SYD_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS SYD_CS_POSIX_V6_ILP32_OFF32_LINTFLAGS
    SYD_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS,
#define SYD_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS SYD_CS_POSIX_V6_ILP32_OFFBIG_CFLAGS
    SYD_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS,
#define SYD_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS SYD_CS_POSIX_V6_ILP32_OFFBIG_LDFLAGS
    SYD_CS_POSIX_V6_ILP32_OFFBIG_LIBS,
#define SYD_CS_POSIX_V6_ILP32_OFFBIG_LIBS SYD_CS_POSIX_V6_ILP32_OFFBIG_LIBS
    SYD_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS,
#define SYD_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS SYD_CS_POSIX_V6_ILP32_OFFBIG_LINTFLAGS
    SYD_CS_POSIX_V6_LP64_OFF64_CFLAGS,
#define SYD_CS_POSIX_V6_LP64_OFF64_CFLAGS SYD_CS_POSIX_V6_LP64_OFF64_CFLAGS
    SYD_CS_POSIX_V6_LP64_OFF64_LDFLAGS,
#define SYD_CS_POSIX_V6_LP64_OFF64_LDFLAGS SYD_CS_POSIX_V6_LP64_OFF64_LDFLAGS
    SYD_CS_POSIX_V6_LP64_OFF64_LIBS,
#define SYD_CS_POSIX_V6_LP64_OFF64_LIBS SYD_CS_POSIX_V6_LP64_OFF64_LIBS
    SYD_CS_POSIX_V6_LP64_OFF64_LINTFLAGS,
#define SYD_CS_POSIX_V6_LP64_OFF64_LINTFLAGS SYD_CS_POSIX_V6_LP64_OFF64_LINTFLAGS
    SYD_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS,
#define SYD_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS SYD_CS_POSIX_V6_LPBIG_OFFBIG_CFLAGS
    SYD_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS,
#define SYD_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS SYD_CS_POSIX_V6_LPBIG_OFFBIG_LDFLAGS
    SYD_CS_POSIX_V6_LPBIG_OFFBIG_LIBS,
#define SYD_CS_POSIX_V6_LPBIG_OFFBIG_LIBS SYD_CS_POSIX_V6_LPBIG_OFFBIG_LIBS
    SYD_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS,
#define SYD_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS SYD_CS_POSIX_V6_LPBIG_OFFBIG_LINTFLAGS

    SYD_CS_POSIX_V7_ILP32_OFF32_CFLAGS,
#define SYD_CS_POSIX_V7_ILP32_OFF32_CFLAGS SYD_CS_POSIX_V7_ILP32_OFF32_CFLAGS
    SYD_CS_POSIX_V7_ILP32_OFF32_LDFLAGS,
#define SYD_CS_POSIX_V7_ILP32_OFF32_LDFLAGS SYD_CS_POSIX_V7_ILP32_OFF32_LDFLAGS
    SYD_CS_POSIX_V7_ILP32_OFF32_LIBS,
#define SYD_CS_POSIX_V7_ILP32_OFF32_LIBS SYD_CS_POSIX_V7_ILP32_OFF32_LIBS
    SYD_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS,
#define SYD_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS SYD_CS_POSIX_V7_ILP32_OFF32_LINTFLAGS
    SYD_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS,
#define SYD_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS SYD_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS
    SYD_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS,
#define SYD_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS SYD_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS
    SYD_CS_POSIX_V7_ILP32_OFFBIG_LIBS,
#define SYD_CS_POSIX_V7_ILP32_OFFBIG_LIBS SYD_CS_POSIX_V7_ILP32_OFFBIG_LIBS
    SYD_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS,
#define SYD_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS SYD_CS_POSIX_V7_ILP32_OFFBIG_LINTFLAGS
    SYD_CS_POSIX_V7_LP64_OFF64_CFLAGS,
#define SYD_CS_POSIX_V7_LP64_OFF64_CFLAGS SYD_CS_POSIX_V7_LP64_OFF64_CFLAGS
    SYD_CS_POSIX_V7_LP64_OFF64_LDFLAGS,
#define SYD_CS_POSIX_V7_LP64_OFF64_LDFLAGS SYD_CS_POSIX_V7_LP64_OFF64_LDFLAGS
    SYD_CS_POSIX_V7_LP64_OFF64_LIBS,
#define SYD_CS_POSIX_V7_LP64_OFF64_LIBS SYD_CS_POSIX_V7_LP64_OFF64_LIBS
    SYD_CS_POSIX_V7_LP64_OFF64_LINTFLAGS,
#define SYD_CS_POSIX_V7_LP64_OFF64_LINTFLAGS SYD_CS_POSIX_V7_LP64_OFF64_LINTFLAGS
    SYD_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS,
#define SYD_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS SYD_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS
    SYD_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS,
#define SYD_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS SYD_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS
    SYD_CS_POSIX_V7_LPBIG_OFFBIG_LIBS,
#define SYD_CS_POSIX_V7_LPBIG_OFFBIG_LIBS SYD_CS_POSIX_V7_LPBIG_OFFBIG_LIBS
    SYD_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS,
#define SYD_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS SYD_CS_POSIX_V7_LPBIG_OFFBIG_LINTFLAGS

    SYD_CS_V6_ENV,
#define SYD_CS_V6_ENV			SYD_CS_V6_ENV
    SYD_CS_V7_ENV
#define SYD_CS_V7_ENV			SYD_CS_V7_ENV
  };

#endif /* !SYD_CONFNAME_H */
