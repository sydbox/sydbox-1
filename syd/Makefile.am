AM_MAKEFLAGS= --no-print-directory

lib_LTLIBRARIES = libsyd_@LIBSYD_PC_SLOT@.la

libsyd_@LIBSYD_PC_SLOT@_la_SOURCES = \
	strlcat.c \
	strlcpy.c \
	file.c \
	pidfd.c \
	proc.c \
	state.c \
	time.c

libsyd_includedir = $(includedir)/syd-$(LIBSYD_PC_SLOT)/syd
libsyd_include_HEADERS= syd.h

noinst_HEADERS= seatest.h check.h
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
