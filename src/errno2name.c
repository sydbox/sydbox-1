/*
 * sydbox/errno2name.c
 *
 * Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
 * Based in part upon strace/tests/errno2name.c which is:
 *   Copyright (c) 2016 Dmitry V. Levin <ldv@strace.io>
 *   Copyright (c) 2016-2021 The strace developers.
 * All rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stddef.h>
#include <string.h>
#include <errno.h>

#define CASE(x) case x: return #x

const char *
errno2name(int err_no)
{
	switch (err_no) {
	/* names taken from linux/errnoent.h */
#ifdef E2BIG
	CASE(E2BIG);
#endif
#ifdef EACCES
	CASE(EACCES);
#endif
#ifdef EADDRINUSE
	CASE(EADDRINUSE);
#endif
#ifdef EADDRNOTAVAIL
	CASE(EADDRNOTAVAIL);
#endif
#ifdef EADV
	CASE(EADV);
#endif
#ifdef EAFNOSUPPORT
	CASE(EAFNOSUPPORT);
#endif
#ifdef EAGAIN
	CASE(EAGAIN);
#endif
#ifdef EALREADY
	CASE(EALREADY);
#endif
#ifdef EBADCOOKIE
	CASE(EBADCOOKIE);
#endif
#ifdef EBADE
	CASE(EBADE);
#endif
#ifdef EBADF
	CASE(EBADF);
#endif
#ifdef EBADFD
	CASE(EBADFD);
#endif
#ifdef EBADHANDLE
	CASE(EBADHANDLE);
#endif
#ifdef EBADMSG
	CASE(EBADMSG);
#endif
#ifdef EBADR
	CASE(EBADR);
#endif
#ifdef EBADRQC
	CASE(EBADRQC);
#endif
#ifdef EBADSLT
	CASE(EBADSLT);
#endif
#ifdef EBADTYPE
	CASE(EBADTYPE);
#endif
#ifdef EBFONT
	CASE(EBFONT);
#endif
#ifdef EBUSY
	CASE(EBUSY);
#endif
#ifdef ECANCELED
	CASE(ECANCELED);
#endif
#ifdef ECHILD
	CASE(ECHILD);
#endif
#ifdef ECHRNG
	CASE(ECHRNG);
#endif
#ifdef ECOMM
	CASE(ECOMM);
#endif
#ifdef ECONNABORTED
	CASE(ECONNABORTED);
#endif
#ifdef ECONNREFUSED
	CASE(ECONNREFUSED);
#endif
#ifdef ECONNRESET
	CASE(ECONNRESET);
#endif
#ifdef EDEADLK
	CASE(EDEADLK);
#endif
#ifdef EDESTADDRREQ
	CASE(EDESTADDRREQ);
#endif
#ifdef EDOM
	CASE(EDOM);
#endif
#ifdef EDOTDOT
	CASE(EDOTDOT);
#endif
#ifdef EDQUOT
	CASE(EDQUOT);
#endif
#ifdef EEXIST
	CASE(EEXIST);
#endif
#ifdef EFAULT
	CASE(EFAULT);
#endif
#ifdef EFBIG
	CASE(EFBIG);
#endif
#ifdef EHOSTDOWN
	CASE(EHOSTDOWN);
#endif
#ifdef EHOSTUNREACH
	CASE(EHOSTUNREACH);
#endif
#ifdef EHWPOISON
	CASE(EHWPOISON);
#endif
#ifdef EIDRM
	CASE(EIDRM);
#endif
#ifdef EILSEQ
	CASE(EILSEQ);
#endif
#ifdef EINPROGRESS
	CASE(EINPROGRESS);
#endif
#ifdef EINTR
	CASE(EINTR);
#endif
#ifdef EINVAL
	CASE(EINVAL);
#endif
#ifdef EIO
	CASE(EIO);
#endif
#ifdef EIOCBQUEUED
	CASE(EIOCBQUEUED);
#endif
#ifdef EISCONN
	CASE(EISCONN);
#endif
#ifdef EISDIR
	CASE(EISDIR);
#endif
#ifdef EISNAM
	CASE(EISNAM);
#endif
#ifdef EJUKEBOX
	CASE(EJUKEBOX);
#endif
#ifdef EKEYEXPIRED
	CASE(EKEYEXPIRED);
#endif
#ifdef EKEYREJECTED
	CASE(EKEYREJECTED);
#endif
#ifdef EKEYREVOKED
	CASE(EKEYREVOKED);
#endif
#ifdef EL2HLT
	CASE(EL2HLT);
#endif
#ifdef EL2NSYNC
	CASE(EL2NSYNC);
#endif
#ifdef EL3HLT
	CASE(EL3HLT);
#endif
#ifdef EL3RST
	CASE(EL3RST);
#endif
#ifdef ELIBACC
	CASE(ELIBACC);
#endif
#ifdef ELIBBAD
	CASE(ELIBBAD);
#endif
#ifdef ELIBEXEC
	CASE(ELIBEXEC);
#endif
#ifdef ELIBMAX
	CASE(ELIBMAX);
#endif
#ifdef ELIBSCN
	CASE(ELIBSCN);
#endif
#ifdef ELNRNG
	CASE(ELNRNG);
#endif
#ifdef ELOOP
	CASE(ELOOP);
#endif
#ifdef EMEDIUMTYPE
	CASE(EMEDIUMTYPE);
#endif
#ifdef EMFILE
	CASE(EMFILE);
#endif
#ifdef EMLINK
	CASE(EMLINK);
#endif
#ifdef EMSGSIZE
	CASE(EMSGSIZE);
#endif
#ifdef EMULTIHOP
	CASE(EMULTIHOP);
#endif
#ifdef ENAMETOOLONG
	CASE(ENAMETOOLONG);
#endif
#ifdef ENAVAIL
	CASE(ENAVAIL);
#endif
#ifdef ENETDOWN
	CASE(ENETDOWN);
#endif
#ifdef ENETRESET
	CASE(ENETRESET);
#endif
#ifdef ENETUNREACH
	CASE(ENETUNREACH);
#endif
#ifdef ENFILE
	CASE(ENFILE);
#endif
#ifdef ENOANO
	CASE(ENOANO);
#endif
#ifdef ENOBUFS
	CASE(ENOBUFS);
#endif
#ifdef ENOCSI
	CASE(ENOCSI);
#endif
#ifdef ENODATA
	CASE(ENODATA);
#endif
#ifdef ENODEV
	CASE(ENODEV);
#endif
#ifdef ENOENT
	CASE(ENOENT);
#endif
#ifdef ENOEXEC
	CASE(ENOEXEC);
#endif
#ifdef ENOIOCTLCMD
	CASE(ENOIOCTLCMD);
#endif
#ifdef ENOKEY
	CASE(ENOKEY);
#endif
#ifdef ENOLCK
	CASE(ENOLCK);
#endif
#ifdef ENOLINK
	CASE(ENOLINK);
#endif
#ifdef ENOMEDIUM
	CASE(ENOMEDIUM);
#endif
#ifdef ENOMEM
	CASE(ENOMEM);
#endif
#ifdef ENOMSG
	CASE(ENOMSG);
#endif
#ifdef ENONET
	CASE(ENONET);
#endif
#ifdef ENOPKG
	CASE(ENOPKG);
#endif
#ifdef ENOPROTOOPT
	CASE(ENOPROTOOPT);
#endif
#ifdef ENOSPC
	CASE(ENOSPC);
#endif
#ifdef ENOSR
	CASE(ENOSR);
#endif
#ifdef ENOSTR
	CASE(ENOSTR);
#endif
#ifdef ENOSYS
	CASE(ENOSYS);
#endif
#ifdef ENOTBLK
	CASE(ENOTBLK);
#endif
#ifdef ENOTCONN
	CASE(ENOTCONN);
#endif
#ifdef ENOTDIR
	CASE(ENOTDIR);
#endif
#ifdef ENOTEMPTY
	CASE(ENOTEMPTY);
#endif
#ifdef ENOTNAM
	CASE(ENOTNAM);
#endif
#ifdef ENOTRECOVERABLE
	CASE(ENOTRECOVERABLE);
#endif
#ifdef ENOTSOCK
	CASE(ENOTSOCK);
#endif
#ifdef ENOTSUPP
	CASE(ENOTSUPP);
#endif
#ifdef ENOTSYNC
	CASE(ENOTSYNC);
#endif
#ifdef ENOTTY
	CASE(ENOTTY);
#endif
#ifdef ENOTUNIQ
	CASE(ENOTUNIQ);
#endif
#ifdef ENXIO
	CASE(ENXIO);
#endif
#ifdef EOPENSTALE
	CASE(EOPENSTALE);
#endif
#ifdef EOPNOTSUPP
	CASE(EOPNOTSUPP);
#endif
#ifdef EOVERFLOW
	CASE(EOVERFLOW);
#endif
#ifdef EOWNERDEAD
	CASE(EOWNERDEAD);
#endif
#ifdef EPERM
	CASE(EPERM);
#endif
#ifdef EPFNOSUPPORT
	CASE(EPFNOSUPPORT);
#endif
#ifdef EPIPE
	CASE(EPIPE);
#endif
#ifdef EPROBE_DEFER
	CASE(EPROBE_DEFER);
#endif
#ifdef EPROTO
	CASE(EPROTO);
#endif
#ifdef EPROTONOSUPPORT
	CASE(EPROTONOSUPPORT);
#endif
#ifdef EPROTOTYPE
	CASE(EPROTOTYPE);
#endif
#ifdef ERANGE
	CASE(ERANGE);
#endif
#ifdef EREMCHG
	CASE(EREMCHG);
#endif
#ifdef EREMOTE
	CASE(EREMOTE);
#endif
#ifdef EREMOTEIO
	CASE(EREMOTEIO);
#endif
#ifdef ERESTART
	CASE(ERESTART);
#endif
#ifdef ERESTARTNOHAND
	CASE(ERESTARTNOHAND);
#endif
#ifdef ERESTARTNOINTR
	CASE(ERESTARTNOINTR);
#endif
#ifdef ERESTARTSYS
	CASE(ERESTARTSYS);
#endif
#ifdef ERESTART_RESTARTBLOCK
	CASE(ERESTART_RESTARTBLOCK);
#endif
#ifdef ERFKILL
	CASE(ERFKILL);
#endif
#ifdef EROFS
	CASE(EROFS);
#endif
#ifdef ESERVERFAULT
	CASE(ESERVERFAULT);
#endif
#ifdef ESHUTDOWN
	CASE(ESHUTDOWN);
#endif
#ifdef ESOCKTNOSUPPORT
	CASE(ESOCKTNOSUPPORT);
#endif
#ifdef ESPIPE
	CASE(ESPIPE);
#endif
#ifdef ESRCH
	CASE(ESRCH);
#endif
#ifdef ESRMNT
	CASE(ESRMNT);
#endif
#ifdef ESTALE
	CASE(ESTALE);
#endif
#ifdef ESTRPIPE
	CASE(ESTRPIPE);
#endif
#ifdef ETIME
	CASE(ETIME);
#endif
#ifdef ETIMEDOUT
	CASE(ETIMEDOUT);
#endif
#ifdef ETOOMANYREFS
	CASE(ETOOMANYREFS);
#endif
#ifdef ETOOSMALL
	CASE(ETOOSMALL);
#endif
#ifdef ETXTBSY
	CASE(ETXTBSY);
#endif
#ifdef EUCLEAN
	CASE(EUCLEAN);
#endif
#ifdef EUNATCH
	CASE(EUNATCH);
#endif
#ifdef EUSERS
	CASE(EUSERS);
#endif
#ifdef EXDEV
	CASE(EXDEV);
#endif
#ifdef EXFULL
	CASE(EXFULL);
#endif
	default:
		return NULL;
	}
}

#define S(NAME,NUM) do {\
	if (!strcasecmp(name, (NAME))) \
		return (NUM); } while(0)
int name2errno(const char *errname)
{
	const char *name = errname;
#ifdef E2BIG
	S("E2BIG", E2BIG);
#endif
#ifdef EACCES
	S("EACCES", EACCES);
#endif
#ifdef EADDRINUSE
	S("EADDRINUSE", EADDRINUSE);
#endif
#ifdef EADDRNOTAVAIL
	S("EADDRNOTAVAIL", EADDRNOTAVAIL);
#endif
#ifdef EADV
	S("EADV", EADV);
#endif
#ifdef EAFNOSUPPORT
	S("EAFNOSUPPORT", EAFNOSUPPORT);
#endif
#ifdef EAGAIN
	S("EAGAIN", EAGAIN);
#endif
#ifdef EALREADY
	S("EALREADY", EALREADY);
#endif
#ifdef EBADCOOKIE
	S("EBADCOOKIE", EBADCOOKIE);
#endif
#ifdef EBADE
	S("EBADE", EBADE);
#endif
#ifdef EBADF
	S("EBADF", EBADF);
#endif
#ifdef EBADFD
	S("EBADFD", EBADFD);
#endif
#ifdef EBADHANDLE
	S("EBADHANDLE", EBADHANDLE);
#endif
#ifdef EBADMSG
	S("EBADMSG", EBADMSG);
#endif
#ifdef EBADR
	S("EBADR", EBADR);
#endif
#ifdef EBADRQC
	S("EBADRQC", EBADRQC);
#endif
#ifdef EBADSLT
	S("EBADSLT", EBADSLT);
#endif
#ifdef EBADTYPE
	S("EBADTYPE", EBADTYPE);
#endif
#ifdef EBFONT
	S("EBFONT", EBFONT);
#endif
#ifdef EBUSY
	S("EBUSY", EBUSY);
#endif
#ifdef ECANCELED
	S("ECANCELED", ECANCELED);
#endif
#ifdef ECHILD
	S("ECHILD", ECHILD);
#endif
#ifdef ECHRNG
	S("ECHRNG", ECHRNG);
#endif
#ifdef ECOMM
	S("ECOMM", ECOMM);
#endif
#ifdef ECONNABORTED
	S("ECONNABORTED", ECONNABORTED);
#endif
#ifdef ECONNREFUSED
	S("ECONNREFUSED", ECONNREFUSED);
#endif
#ifdef ECONNRESET
	S("ECONNRESET", ECONNRESET);
#endif
#ifdef EDEADLK
	S("EDEADLK", EDEADLK);
#endif
#ifdef EDESTADDRREQ
	S("EDESTADDRREQ", EDESTADDRREQ);
#endif
#ifdef EDOM
	S("EDOM", EDOM);
#endif
#ifdef EDOTDOT
	S("EDOTDOT", EDOTDOT);
#endif
#ifdef EDQUOT
	S("EDQUOT", EDQUOT);
#endif
#ifdef EEXIST
	S("EEXIST", EEXIST);
#endif
#ifdef EFAULT
	S("EFAULT", EFAULT);
#endif
#ifdef EFBIG
	S("EFBIG", EFBIG);
#endif
#ifdef EHOSTDOWN
	S("EHOSTDOWN", EHOSTDOWN);
#endif
#ifdef EHOSTUNREACH
	S("EHOSTUNREACH", EHOSTUNREACH);
#endif
#ifdef EHWPOISON
	S("EHWPOISON", EHWPOISON);
#endif
#ifdef EIDRM
	S("EIDRM", EIDRM);
#endif
#ifdef EILSEQ
	S("EILSEQ", EILSEQ);
#endif
#ifdef EINPROGRESS
	S("EINPROGRESS", EINPROGRESS);
#endif
#ifdef EINTR
	S("EINTR", EINTR);
#endif
#ifdef EINVAL
	S("EINVAL", EINVAL);
#endif
#ifdef EIO
	S("EIO", EIO);
#endif
#ifdef EIOCBQUEUED
	S("EIOCBQUEUED", EIOCBQUEUED);
#endif
#ifdef EISCONN
	S("EISCONN", EISCONN);
#endif
#ifdef EISDIR
	S("EISDIR", EISDIR);
#endif
#ifdef EISNAM
	S("EISNAM", EISNAM);
#endif
#ifdef EJUKEBOX
	S("EJUKEBOX", EJUKEBOX);
#endif
#ifdef EKEYEXPIRED
	S("EKEYEXPIRED", EKEYEXPIRED);
#endif
#ifdef EKEYREJECTED
	S("EKEYREJECTED", EKEYREJECTED);
#endif
#ifdef EKEYREVOKED
	S("EKEYREVOKED", EKEYREVOKED);
#endif
#ifdef EL2HLT
	S("EL2HLT", EL2HLT);
#endif
#ifdef EL2NSYNC
	S("EL2NSYNC", EL2NSYNC);
#endif
#ifdef EL3HLT
	S("EL3HLT", EL3HLT);
#endif
#ifdef EL3RST
	S("EL3RST", EL3RST);
#endif
#ifdef ELIBACC
	S("ELIBACC", ELIBACC);
#endif
#ifdef ELIBBAD
	S("ELIBBAD", ELIBBAD);
#endif
#ifdef ELIBEXEC
	S("ELIBEXEC", ELIBEXEC);
#endif
#ifdef ELIBMAX
	S("ELIBMAX", ELIBMAX);
#endif
#ifdef ELIBSCN
	S("ELIBSCN", ELIBSCN);
#endif
#ifdef ELNRNG
	S("ELNRNG", ELNRNG);
#endif
#ifdef ELOOP
	S("ELOOP", ELOOP);
#endif
#ifdef EMEDIUMTYPE
	S("EMEDIUMTYPE", EMEDIUMTYPE);
#endif
#ifdef EMFILE
	S("EMFILE", EMFILE);
#endif
#ifdef EMLINK
	S("EMLINK", EMLINK);
#endif
#ifdef EMSGSIZE
	S("EMSGSIZE", EMSGSIZE);
#endif
#ifdef EMULTIHOP
	S("EMULTIHOP", EMULTIHOP);
#endif
#ifdef ENAMETOOLONG
	S("ENAMETOOLONG", ENAMETOOLONG);
#endif
#ifdef ENAVAIL
	S("ENAVAIL", ENAVAIL);
#endif
#ifdef ENETDOWN
	S("ENETDOWN", ENETDOWN);
#endif
#ifdef ENETRESET
	S("ENETRESET", ENETRESET);
#endif
#ifdef ENETUNREACH
	S("ENETUNREACH", ENETUNREACH);
#endif
#ifdef ENFILE
	S("ENFILE", ENFILE);
#endif
#ifdef ENOANO
	S("ENOANO", ENOANO);
#endif
#ifdef ENOBUFS
	S("ENOBUFS", ENOBUFS);
#endif
#ifdef ENOCSI
	S("ENOCSI", ENOCSI);
#endif
#ifdef ENODATA
	S("ENODATA", ENODATA);
#endif
#ifdef ENODEV
	S("ENODEV", ENODEV);
#endif
#ifdef ENOENT
	S("ENOENT", ENOENT);
#endif
#ifdef ENOEXEC
	S("ENOEXEC", ENOEXEC);
#endif
#ifdef ENOIOCTLCMD
	S("ENOIOCTLCMD", ENOIOCTLCMD);
#endif
#ifdef ENOKEY
	S("ENOKEY", ENOKEY);
#endif
#ifdef ENOLCK
	S("ENOLCK", ENOLCK);
#endif
#ifdef ENOLINK
	S("ENOLINK", ENOLINK);
#endif
#ifdef ENOMEDIUM
	S("ENOMEDIUM", ENOMEDIUM);
#endif
#ifdef ENOMEM
	S("ENOMEM", ENOMEM);
#endif
#ifdef ENOMSG
	S("ENOMSG", ENOMSG);
#endif
#ifdef ENONET
	S("ENONET", ENONET);
#endif
#ifdef ENOPKG
	S("ENOPKG", ENOPKG);
#endif
#ifdef ENOPROTOOPT
	S("ENOPROTOOPT", ENOPROTOOPT);
#endif
#ifdef ENOSPC
	S("ENOSPC", ENOSPC);
#endif
#ifdef ENOSR
	S("ENOSR", ENOSR);
#endif
#ifdef ENOSTR
	S("ENOSTR", ENOSTR);
#endif
#ifdef ENOSYS
	S("ENOSYS", ENOSYS);
#endif
#ifdef ENOTBLK
	S("ENOTBLK", ENOTBLK);
#endif
#ifdef ENOTCONN
	S("ENOTCONN", ENOTCONN);
#endif
#ifdef ENOTDIR
	S("ENOTDIR", ENOTDIR);
#endif
#ifdef ENOTEMPTY
	S("ENOTEMPTY", ENOTEMPTY);
#endif
#ifdef ENOTNAM
	S("ENOTNAM", ENOTNAM);
#endif
#ifdef ENOTRECOVERABLE
	S("ENOTRECOVERABLE", ENOTRECOVERABLE);
#endif
#ifdef ENOTSOCK
	S("ENOTSOCK", ENOTSOCK);
#endif
#ifdef ENOTSUPP
	S("ENOTSUPP", ENOTSUPP);
#endif
#ifdef ENOTSYNC
	S("ENOTSYNC", ENOTSYNC);
#endif
#ifdef ENOTTY
	S("ENOTTY", ENOTTY);
#endif
#ifdef ENOTUNIQ
	S("ENOTUNIQ", ENOTUNIQ);
#endif
#ifdef ENXIO
	S("ENXIO", ENXIO);
#endif
#ifdef EOPENSTALE
	S("EOPENSTALE", EOPENSTALE);
#endif
#ifdef EOPNOTSUPP
	S("EOPNOTSUPP", EOPNOTSUPP);
#endif
#ifdef EOVERFLOW
	S("EOVERFLOW", EOVERFLOW);
#endif
#ifdef EOWNERDEAD
	S("EOWNERDEAD", EOWNERDEAD);
#endif
#ifdef EPERM
	S("EPERM", EPERM);
#endif
#ifdef EPFNOSUPPORT
	S("EPFNOSUPPORT", EPFNOSUPPORT);
#endif
#ifdef EPIPE
	S("EPIPE", EPIPE);
#endif
#ifdef EPROBE_DEFER
	S("EPROBE_DEFER", EPROBE_DEFER);
#endif
#ifdef EPROTO
	S("EPROTO", EPROTO);
#endif
#ifdef EPROTONOSUPPORT
	S("EPROTONOSUPPORT", EPROTONOSUPPORT);
#endif
#ifdef EPROTOTYPE
	S("EPROTOTYPE", EPROTOTYPE);
#endif
#ifdef ERANGE
	S("ERANGE", ERANGE);
#endif
#ifdef EREMCHG
	S("EREMCHG", EREMCHG);
#endif
#ifdef EREMOTE
	S("EREMOTE", EREMOTE);
#endif
#ifdef EREMOTEIO
	S("EREMOTEIO", EREMOTEIO);
#endif
#ifdef ERESTART
	S("ERESTART", ERESTART);
#endif
#ifdef ERESTARTNOHAND
	S("ERESTARTNOHAND", ERESTARTNOHAND);
#endif
#ifdef ERESTARTNOINTR
	S("ERESTARTNOINTR", ERESTARTNOINTR);
#endif
#ifdef ERESTARTSYS
	S("ERESTARTSYS", ERESTARTSYS);
#endif
#ifdef ERESTART_RESTARTBLOCK
	S("ERESTART_RESTARTBLOCK", ERESTART_RESTARTBLOCK);
#endif
#ifdef ERFKILL
	S("ERFKILL", ERFKILL);
#endif
#ifdef EROFS
	S("EROFS", EROFS);
#endif
#ifdef ESERVERFAULT
	S("ESERVERFAULT", ESERVERFAULT);
#endif
#ifdef ESHUTDOWN
	S("ESHUTDOWN", ESHUTDOWN);
#endif
#ifdef ESOCKTNOSUPPORT
	S("ESOCKTNOSUPPORT", ESOCKTNOSUPPORT);
#endif
#ifdef ESPIPE
	S("ESPIPE", ESPIPE);
#endif
#ifdef ESRCH
	S("ESRCH", ESRCH);
#endif
#ifdef ESRMNT
	S("ESRMNT", ESRMNT);
#endif
#ifdef ESTALE
	S("ESTALE", ESTALE);
#endif
#ifdef ESTRPIPE
	S("ESTRPIPE", ESTRPIPE);
#endif
#ifdef ETIME
	S("ETIME", ETIME);
#endif
#ifdef ETIMEDOUT
	S("ETIMEDOUT", ETIMEDOUT);
#endif
#ifdef ETOOMANYREFS
	S("ETOOMANYREFS", ETOOMANYREFS);
#endif
#ifdef ETOOSMALL
	S("ETOOSMALL", ETOOSMALL);
#endif
#ifdef ETXTBSY
	S("ETXTBSY", ETXTBSY);
#endif
#ifdef EUCLEAN
	S("EUCLEAN", EUCLEAN);
#endif
#ifdef EUNATCH
	S("EUNATCH", EUNATCH);
#endif
#ifdef EUSERS
	S("EUSERS", EUSERS);
#endif
#ifdef EXDEV
	S("EXDEV", EXDEV);
#endif
#ifdef EXFULL
	S("EXFULL", EXFULL);
#endif
	return -EINVAL;
}
