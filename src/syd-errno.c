/*
 * sydbox/syd-run.c
 * SydBox's Errno Helper
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <syd/compiler.h>

#include "ansi.h"
#include "errno2name.h"

#ifdef PACKAGE
# undef PACKAGE
#endif
#define PACKAGE "syd-errno"

static void print_errno(const char *arg);
static void print_errno_all(void);

static void about(void);
static void usage(FILE *outfp, int code)
	SYD_GCC_ATTR((noreturn));

static void die(const char *fmt, ...);
static void say_errno(const char *fmt, ...);
static void say(const char *fmt, ...);
static void vsay(FILE *fp, const char *fmt, va_list ap, char level);

int main(int argc, char **argv)
{
	if (argc <= 1)
		usage(stderr, EXIT_FAILURE);
	if (argv[1][0] == '-') {
		if (!strcmp(argv[1], "-h") ||
		    !strcmp(argv[1], "--help"))
			usage(stdout, EXIT_SUCCESS);
		if (!strcmp(argv[1], "-v") ||
		    !strcmp(argv[1], "--version")) {
			about();
			return EXIT_SUCCESS;
		}
	}
	for (size_t i = 1; i < argc; i++) {
		if (!strcasecmp(argv[i], "-"))
			print_errno_all();
		else
			print_errno(argv[i]);
	}
	return EXIT_SUCCESS;
}

static void print_errno(const char *arg)
{
	int val;
	char *name;
	char c = arg[0];
	switch (c) {
	case '\0':
		return;
	case '0': case '1':
	case '2': case '3':
	case '4': case '5':
	case '6': case '7':
	case '8': case '9':
		val = atoi(arg);
		printf("%d\t%s\n", val, errno2name(val));
		break;
	default:
		val = name2errno(arg);
		if (val < 0) {
			errno = -val;
			say_errno("Invalid errno: »%s«", arg);
			return;
		} else {
			printf("%d\t%s\n", val, arg);
		}
		break;
	}
}

static void about(void)
{
	printf(PACKAGE"-"VERSION GITVERSION"\n");
}

SYD_GCC_ATTR((noreturn))
static void usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITVERSION" -- sydbox' errno <-> name converter\n\
usage: "PACKAGE" [-hv] -|errno-name|errno-number...\n\
-h          -- Show usage and exit\n\
-v          -- Show version and exit\n\
\n\
Given an errno number, print its name.\n\
Given an errno name, print its number.\n\
Given `-', print all error numbers defined by the system.\n\
Multiple arguments may be given.\n\
\n\
Hey you, out there on the road,\n\
Always doing what you're told,\n\
Can you help me?\n\
\n\
Send bug reports to \"" PACKAGE_BUGREPORT "\"\n\
Attaching poems encourages consideration tremendously.\n");
	exit(code);
}

static void die(const char *fmt, ...)
{
	va_list ap;
	static int tty = -1;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	fputc('\n', stderr);

	exit(EXIT_FAILURE);
}

static void say_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'e');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	errno = save_errno;
}

static void die_errno(const char *fmt, ...)
{
	int save_errno = errno;
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 'f');
	va_end(ap);
	say(" (errno:%d|%s %s)", save_errno, errno2name(save_errno),
	    strerror(save_errno));

	exit(EXIT_FAILURE);
}

static void say(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(stderr, fmt, ap, 0);
	va_end(ap);
	fputc('\n', stderr);
}

static void vsay(FILE *fp, const char *fmt, va_list ap, char level)
{
	static int tty = -1;

	if (tty < 0)
		tty = isatty(STDERR_FILENO) == 1 ? 1 : 0;
	if (tty)
		fputs(ADM, fp);
	if (fmt[0] != ' ')
		fputs(PACKAGE": ", fp);
	switch (level) {
	case 'b':
		fputs("bug: ", fp);
		break;
	case 'f':
		fputs("fatal: ", fp);
		break;
	case 'w':
		fputs("warning: ", fp);
		break;
	default:
		break;
	}
	vfprintf(stderr, fmt, ap);
	if (tty)
		fputs(AN, fp);
}

static void print_errno_all(void)
{
#define PUTS(e) do { printf("%d\t%s\n", (e), errno2name((e))); } while(0)
#ifdef E2BIG
	PUTS(E2BIG);
#endif
#ifdef EACCES
	PUTS(EACCES);
#endif
#ifdef EADDRINUSE
	PUTS(EADDRINUSE);
#endif
#ifdef EADDRNOTAVAIL
	PUTS(EADDRNOTAVAIL);
#endif
#ifdef EADV
	PUTS(EADV);
#endif
#ifdef EAFNOSUPPORT
	PUTS(EAFNOSUPPORT);
#endif
#ifdef EAGAIN
	PUTS(EAGAIN);
#endif
#ifdef EALREADY
	PUTS(EALREADY);
#endif
#ifdef EBADCOOKIE
	PUTS(EBADCOOKIE);
#endif
#ifdef EBADE
	PUTS(EBADE);
#endif
#ifdef EBADF
	PUTS(EBADF);
#endif
#ifdef EBADFD
	PUTS(EBADFD);
#endif
#ifdef EBADHANDLE
	PUTS(EBADHANDLE);
#endif
#ifdef EBADMSG
	PUTS(EBADMSG);
#endif
#ifdef EBADR
	PUTS(EBADR);
#endif
#ifdef EBADRQC
	PUTS(EBADRQC);
#endif
#ifdef EBADSLT
	PUTS(EBADSLT);
#endif
#ifdef EBADTYPE
	PUTS(EBADTYPE);
#endif
#ifdef EBFONT
	PUTS(EBFONT);
#endif
#ifdef EBUSY
	PUTS(EBUSY);
#endif
#ifdef ECANCELED
	PUTS(ECANCELED);
#endif
#ifdef ECHILD
	PUTS(ECHILD);
#endif
#ifdef ECHRNG
	PUTS(ECHRNG);
#endif
#ifdef ECOMM
	PUTS(ECOMM);
#endif
#ifdef ECONNABORTED
	PUTS(ECONNABORTED);
#endif
#ifdef ECONNREFUSED
	PUTS(ECONNREFUSED);
#endif
#ifdef ECONNRESET
	PUTS(ECONNRESET);
#endif
#ifdef EDEADLK
	PUTS(EDEADLK);
#endif
#ifdef EDESTADDRREQ
	PUTS(EDESTADDRREQ);
#endif
#ifdef EDOM
	PUTS(EDOM);
#endif
#ifdef EDOTDOT
	PUTS(EDOTDOT);
#endif
#ifdef EDQUOT
	PUTS(EDQUOT);
#endif
#ifdef EEXIST
	PUTS(EEXIST);
#endif
#ifdef EFAULT
	PUTS(EFAULT);
#endif
#ifdef EFBIG
	PUTS(EFBIG);
#endif
#ifdef EHOSTDOWN
	PUTS(EHOSTDOWN);
#endif
#ifdef EHOSTUNREACH
	PUTS(EHOSTUNREACH);
#endif
#ifdef EHWPOISON
	PUTS(EHWPOISON);
#endif
#ifdef EIDRM
	PUTS(EIDRM);
#endif
#ifdef EILSEQ
	PUTS(EILSEQ);
#endif
#ifdef EINPROGRESS
	PUTS(EINPROGRESS);
#endif
#ifdef EINTR
	PUTS(EINTR);
#endif
#ifdef EINVAL
	PUTS(EINVAL);
#endif
#ifdef EIO
	PUTS(EIO);
#endif
#ifdef EIOCBQUEUED
	PUTS(EIOCBQUEUED);
#endif
#ifdef EISCONN
	PUTS(EISCONN);
#endif
#ifdef EISDIR
	PUTS(EISDIR);
#endif
#ifdef EISNAM
	PUTS(EISNAM);
#endif
#ifdef EJUKEBOX
	PUTS(EJUKEBOX);
#endif
#ifdef EKEYEXPIRED
	PUTS(EKEYEXPIRED);
#endif
#ifdef EKEYREJECTED
	PUTS(EKEYREJECTED);
#endif
#ifdef EKEYREVOKED
	PUTS(EKEYREVOKED);
#endif
#ifdef EL2HLT
	PUTS(EL2HLT);
#endif
#ifdef EL2NSYNC
	PUTS(EL2NSYNC);
#endif
#ifdef EL3HLT
	PUTS(EL3HLT);
#endif
#ifdef EL3RST
	PUTS(EL3RST);
#endif
#ifdef ELIBACC
	PUTS(ELIBACC);
#endif
#ifdef ELIBBAD
	PUTS(ELIBBAD);
#endif
#ifdef ELIBEXEC
	PUTS(ELIBEXEC);
#endif
#ifdef ELIBMAX
	PUTS(ELIBMAX);
#endif
#ifdef ELIBSCN
	PUTS(ELIBSCN);
#endif
#ifdef ELNRNG
	PUTS(ELNRNG);
#endif
#ifdef ELOOP
	PUTS(ELOOP);
#endif
#ifdef EMEDIUMTYPE
	PUTS(EMEDIUMTYPE);
#endif
#ifdef EMFILE
	PUTS(EMFILE);
#endif
#ifdef EMLINK
	PUTS(EMLINK);
#endif
#ifdef EMSGSIZE
	PUTS(EMSGSIZE);
#endif
#ifdef EMULTIHOP
	PUTS(EMULTIHOP);
#endif
#ifdef ENAMETOOLONG
	PUTS(ENAMETOOLONG);
#endif
#ifdef ENAVAIL
	PUTS(ENAVAIL);
#endif
#ifdef ENETDOWN
	PUTS(ENETDOWN);
#endif
#ifdef ENETRESET
	PUTS(ENETRESET);
#endif
#ifdef ENETUNREACH
	PUTS(ENETUNREACH);
#endif
#ifdef ENFILE
	PUTS(ENFILE);
#endif
#ifdef ENOANO
	PUTS(ENOANO);
#endif
#ifdef ENOBUFS
	PUTS(ENOBUFS);
#endif
#ifdef ENOCSI
	PUTS(ENOCSI);
#endif
#ifdef ENODATA
	PUTS(ENODATA);
#endif
#ifdef ENODEV
	PUTS(ENODEV);
#endif
#ifdef ENOENT
	PUTS(ENOENT);
#endif
#ifdef ENOEXEC
	PUTS(ENOEXEC);
#endif
#ifdef ENOIOCTLCMD
	PUTS(ENOIOCTLCMD);
#endif
#ifdef ENOKEY
	PUTS(ENOKEY);
#endif
#ifdef ENOLCK
	PUTS(ENOLCK);
#endif
#ifdef ENOLINK
	PUTS(ENOLINK);
#endif
#ifdef ENOMEDIUM
	PUTS(ENOMEDIUM);
#endif
#ifdef ENOMEM
	PUTS(ENOMEM);
#endif
#ifdef ENOMSG
	PUTS(ENOMSG);
#endif
#ifdef ENONET
	PUTS(ENONET);
#endif
#ifdef ENOPKG
	PUTS(ENOPKG);
#endif
#ifdef ENOPROTOOPT
	PUTS(ENOPROTOOPT);
#endif
#ifdef ENOSPC
	PUTS(ENOSPC);
#endif
#ifdef ENOSR
	PUTS(ENOSR);
#endif
#ifdef ENOSTR
	PUTS(ENOSTR);
#endif
#ifdef ENOSYS
	PUTS(ENOSYS);
#endif
#ifdef ENOTBLK
	PUTS(ENOTBLK);
#endif
#ifdef ENOTCONN
	PUTS(ENOTCONN);
#endif
#ifdef ENOTDIR
	PUTS(ENOTDIR);
#endif
#ifdef ENOTEMPTY
	PUTS(ENOTEMPTY);
#endif
#ifdef ENOTNAM
	PUTS(ENOTNAM);
#endif
#ifdef ENOTRECOVERABLE
	PUTS(ENOTRECOVERABLE);
#endif
#ifdef ENOTSOCK
	PUTS(ENOTSOCK);
#endif
#ifdef ENOTSUPP
	PUTS(ENOTSUPP);
#endif
#ifdef ENOTSYNC
	PUTS(ENOTSYNC);
#endif
#ifdef ENOTTY
	PUTS(ENOTTY);
#endif
#ifdef ENOTUNIQ
	PUTS(ENOTUNIQ);
#endif
#ifdef ENXIO
	PUTS(ENXIO);
#endif
#ifdef EOPENSTALE
	PUTS(EOPENSTALE);
#endif
#ifdef EOPNOTSUPP
	PUTS(EOPNOTSUPP);
#endif
#ifdef EOVERFLOW
	PUTS(EOVERFLOW);
#endif
#ifdef EOWNERDEAD
	PUTS(EOWNERDEAD);
#endif
#ifdef EPERM
	PUTS(EPERM);
#endif
#ifdef EPFNOSUPPORT
	PUTS(EPFNOSUPPORT);
#endif
#ifdef EPIPE
	PUTS(EPIPE);
#endif
#ifdef EPROBE_DEFER
	PUTS(EPROBE_DEFER);
#endif
#ifdef EPROTO
	PUTS(EPROTO);
#endif
#ifdef EPROTONOSUPPORT
	PUTS(EPROTONOSUPPORT);
#endif
#ifdef EPROTOTYPE
	PUTS(EPROTOTYPE);
#endif
#ifdef ERANGE
	PUTS(ERANGE);
#endif
#ifdef EREMCHG
	PUTS(EREMCHG);
#endif
#ifdef EREMOTE
	PUTS(EREMOTE);
#endif
#ifdef EREMOTEIO
	PUTS(EREMOTEIO);
#endif
#ifdef ERESTART
	PUTS(ERESTART);
#endif
#ifdef ERESTARTNOHAND
	PUTS(ERESTARTNOHAND);
#endif
#ifdef ERESTARTNOINTR
	PUTS(ERESTARTNOINTR);
#endif
#ifdef ERESTARTSYS
	PUTS(ERESTARTSYS);
#endif
#ifdef ERESTART_RESTARTBLOCK
	PUTS(ERESTART_RESTARTBLOCK);
#endif
#ifdef ERFKILL
	PUTS(ERFKILL);
#endif
#ifdef EROFS
	PUTS(EROFS);
#endif
#ifdef ESERVERFAULT
	PUTS(ESERVERFAULT);
#endif
#ifdef ESHUTDOWN
	PUTS(ESHUTDOWN);
#endif
#ifdef ESOCKTNOSUPPORT
	PUTS(ESOCKTNOSUPPORT);
#endif
#ifdef ESPIPE
	PUTS(ESPIPE);
#endif
#ifdef ESRCH
	PUTS(ESRCH);
#endif
#ifdef ESRMNT
	PUTS(ESRMNT);
#endif
#ifdef ESTALE
	PUTS(ESTALE);
#endif
#ifdef ESTRPIPE
	PUTS(ESTRPIPE);
#endif
#ifdef ETIME
	PUTS(ETIME);
#endif
#ifdef ETIMEDOUT
	PUTS(ETIMEDOUT);
#endif
#ifdef ETOOMANYREFS
	PUTS(ETOOMANYREFS);
#endif
#ifdef ETOOSMALL
	PUTS(ETOOSMALL);
#endif
#ifdef ETXTBSY
	PUTS(ETXTBSY);
#endif
#ifdef EUCLEAN
	PUTS(EUCLEAN);
#endif
#ifdef EUNATCH
	PUTS(EUNATCH);
#endif
#ifdef EUSERS
	PUTS(EUSERS);
#endif
#ifdef EXDEV
	PUTS(EXDEV);
#endif
#ifdef EXFULL
	PUTS(EXFULL);
#endif
}
