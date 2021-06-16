/*
 * sydbox/dump.h
 *
 * Event dumper using JSON lines
 *
 * Copyright (c) 2014, 2018 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef DUMP_H
#define DUMP_H

#ifndef HAVE_CONFIG_H
# include "config.h"
#endif

#include "syd/syd.h"

#if SYDBOX_DUMP || SYDBOX_HAVE_DUMP_BUILTIN

#include <errno.h>

# define DUMP_FMT  1
# define DUMP_ENV  "SHOEBOX"    /* read pathname from environment variable */
# define DUMP_NAME "sydcore"  /* Default dump name */

# define DUMPF_PROCFS	0x00000100 /* read /proc/$pid/stat */
# define DUMPF_SANDBOX	0x00000200 /* dump process sandbox */

enum dump {
	DUMP_INIT,
#define INSPECT_DUMP_INIT (1ULL << DUMP_INIT)
#define INSPECT_DUMP_ALL INSPECT_DUMP_INIT
	DUMP_CLOSE,
#define INSPECT_DUMP_CLOSE (1ULL << DUMP_CLOSE)
	DUMP_FLUSH,
#define INSPECT_DUMP_FLUSH (1ULL << DUMP_FLUSH)
	DUMP_ASSERT, /* assertion failed */
#define INSPECT_DUMP_ASSERT (1ULL << DUMP_ASSERT)
	DUMP_INTERRUPT, /* interrupted */
#define INSPECT_DUMP_INTERRUPT (1ULL << DUMP_INTERRUPT)
	DUMP_THREAD_NEW, /* new_thread() */
#define INSPECT_DUMP_THREAD_NEW (1ULL << DUMP_THREAD_NEW)
	DUMP_THREAD_FREE, /* free_process() */
#define INSPECT_DUMP_THREAD_FREE (1ULL << DUMP_THREAD_FREE)
	DUMP_STARTUP, /* attached to initial process */
#define INSPECT_DUMP_STARTUP (1ULL << DUMP_STARTUP)
	DUMP_SYSENT, /* violation() */
#define INSPECT_DUMP_SYSENT (1ULL << DUMP_SYSENT)
	DUMP_EXIT, /* sydbox->exit_code was set */
#define INSPECT_DUMP_EXIT (1ULL << DUMP_EXIT)
	DUMP_CHDIR, /* process changed directory */
#define INSPECT_DUMP_CHDIR (1ULL << DUMP_CHDIR)
	DUMP_EXEC, /* process executed another program */
#define INSPECT_DUMP_EXEC (1ULL << DUMP_EXEC)
	DUMP_EXEC_MT, /* multithreaded execve, leader switch */
#define INSPECT_DUMP_EXEC_MT (1ULL << DUMP_EXEC_MT)
	DUMP_ALLOC, /* dump allocations, *alloc(), str*dup() & asprintf() */
#define INSPECT_DUMP_ALLOC (1ULL << DUMP_ALLOC)
	DUMP_MEMORY_ACCESS, /* dump memory accesses */
#define INSPECT_DUMP_MEMORY_ACCESS (1ULL << DUMP_MEMORY_ACCESS)
};

#if SYDBOX_DUMP
# define INSPECT_DEFAULT INSPECT_DUMP_ALL
#elif SYDBOX_HAVE_DUMP_BUILTIN
# define INSPECT_DEFAULT (INSPECT_DUMP_STARTUP |\
			  INSPECT_DUMP_SYSENT |\
			  INSPECT_DUMP_CHDIR |\
			  INSPECT_DUMP_EXEC |\
			  INSPECT_DUMP_EXEC_MT)
#else
# error do not know how to define INSPECT_DEFAULT
#endif

extern unsigned long long dump_inspect;
#define inspected_i(what) ((dump_inspect & (1ULL << what)) != 0)
#define inspected_f(what) ((dump_inspect & (what)) != 0)

void dump(enum dump what, ...);

#else
# define dump(...) /* empty */
# define inspected_i(what) (0)
# define inspected_f(what) (0)
#endif /* SYDBOX_DUMP */

#endif
