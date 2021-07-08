AM_MAKEFLAGS= --no-print-directory
CLEANFILES= \
	    *~
DEFS+= \
       -DIN_LIBSYD=1 \
       -DGITVERSION=\"$(GITVERSION)\"

lib_LTLIBRARIES = libsyd_@LIBSYD_PC_SLOT@.la
dist_man3_MANS= \
	       doc/man/man3/syd_version.3

libsyd_@LIBSYD_PC_SLOT@_la_SOURCES = \
	about.c \
	debug.c \
	name.c \
	strlcat.c \
	strlcpy.c \
	file.c \
	pidfd.c \
	proc.c \
	state.c \
	time.c \
	unshare.c

# Imported from util-linux' unshare:
libsyd_@LIBSYD_PC_SLOT@_la_SOURCES += \
	all-io.h \
	c.h \
	pathnames.h \
	fileutils.h \
	fileutils.c \
	procutils.h \
	procutils.c \
	statfs_magic.h \
	caputils.h \
	caputils.c \
	syd/robinhood_hash.h
libsyd_@LIBSYD_PC_SLOT@_la_CFLAGS= \
	$(libseccomp_CFLAGS) \
	$(SYDBOX_CFLAGS)
libsyd_@LIBSYD_PC_SLOT@_la_LDFLAGS= \
	$(SYDBOX_LDFLAGS)
libsyd_@LIBSYD_PC_SLOT@_la_LIBS= \
	$(libseccomp_LIBS)

libsyd_includedir = $(includedir)/syd-$(LIBSYD_PC_SLOT)/syd
libsyd_include_HEADERS= \
			confname.h \
			syd.h

noinst_HEADERS= seatest.h check.h compiler.h
syd_check_SOURCES= seatest.c check.c file-TEST.c proc-TEST.c
syd_check_CFLAGS= -I$(srcdir)
syd_check_LDFLAGS= -lrt -lm \
		   $(builddir)/libsyd_@LIBSYD_PC_SLOT@.la \
		   -L$(builddir)/.libs \
		   -lsyd_@LIBSYD_PC_SLOT@

check_PROGRAMS= check-pause syd-check
TESTS= syd-check

.PHONY: check-build
check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_PROGRAMS}
