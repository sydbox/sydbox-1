AM_MAKEFLAGS= --no-print-directory
SUBDIRS= .
EXTRA_DIST = test-skel-0.c test-skel-1.c tests.h headers.h localdecls.h
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov

# Use -DNDEBUG so as not to require sydbox' assert() override
AM_CPPFLAGS = $(DEFS) \
	      -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/src \
	      @SYDBOX_CFLAGS@ -DNDEBUG $(CODE_COVERAGE_CPPFLAGS)
AM_CFLAGS = \
	    `expr $@ : .*-pthread >/dev/null && echo $(PTHREAD_CFLAGS)` \
	    $(CODE_COVERAGE_CFLAGS) \
	    -I$(top_srcdir)/src/lib \
	    -I$(top_srcdir)/src/lib/syd
AM_LDFLAGS = \
	     `expr $@ : .*-static >/dev/null && echo -all-static` \
	     `expr $@ : .*-pthread >/dev/null && echo $(PTHREAD_LIBS)` \
	     $(CODE_COVERAGE_LDFLAGS)

if WANT_PSYSCALL
AM_CFLAGS += $(pinktrace_CFLAGS)
AM_LDFLAGS += $(pinktrace_LIBS)
endif

wildtest_SOURCES= tap.h wildtest.c
wildtest_CFLAGS= \
		 $(AM_CFLAGS) \
		 -DWILD_TEST_ITERATIONS \
		 --include=$(top_srcdir)/src/wildmatch.c
wildtest_CFLAGS+= \
		 -L$(top_builddir)/src/lib/.libs \
		 -lsyd_@LIBSYD_PC_SLOT@

realpath_mode_1_SOURCES= realpath_mode-1.c \
			 $(top_srcdir)/src/errno2name.c \
			 $(top_srcdir)/src/realpath.c \
			 $(top_srcdir)/src/strlcat.c \
			 $(top_srcdir)/src/strlcpy.c \
			 $(top_srcdir)/src/file.c \
			 $(top_srcdir)/src/util.c \
			 $(top_srcdir)/src/xfunc.c
realpath_mode_1_CFLAGS= $(AM_CFLAGS) -DSYDBOX_NDUMP
realpath_mode_1FLAGS= \
		      -L$(top_builddir)/src/lib/.libs \
		      -lsyd_@LIBSYD_PC_SLOT@

sockmatchtest_SOURCES= sockmatchtest.c \
		       $(top_srcdir)/src/errno2name.c \
		       $(top_srcdir)/src/path.c \
		       $(top_srcdir)/src/pathmatch.c \
		       $(top_srcdir)/src/sockmatch.c \
		       $(top_srcdir)/src/util.c \
		       $(top_srcdir)/src/wildmatch.c \
		       $(top_srcdir)/src/xfunc.c
sockmatchtest_CFLAGS= $(AM_CFLAGS) -DSYDBOX_NDUMP
sockmatchtest_LDFLAGS= \
		      -L$(top_builddir)/src/lib/.libs \
		      -lsyd_@LIBSYD_PC_SLOT@

threads_execve_SOURCES= threads_execve.c \
			$(top_srcdir)/src/errno2name.c
threads_execve_CFLAGS= $(AM_CFLAGS) $(PTHREAD_CFLAGS)
threads_execve_LDADD= $(PTHREAD_LIBS)

syddir=$(libexecdir)/$(PACKAGE)/t-$(SYDBOX_API_VERSION)/bin
syd_SCRIPTS= \
	syd-bind-auto-unix-socket.py \
	syd-bind-ipv4-port.py \
	syd-bind-ipv6-port.py \
	syd-connect-ipv4-0.py \
	syd-connect-ipv4.py \
	syd-connect-ipv6-0.py \
	syd-connect-ipv6.py \
	syd-connect-unix.py
syd_PROGRAMS= wildtest realpath_mode-1 sockmatchtest \
	      syd-true syd-true-static syd-true-fork syd-true-fork-static syd-true-pthread \
	      syd-false syd-false-static syd-false-fork syd-false-fork-static syd-false-pthread \
	      syd-abort syd-abort-static syd-abort-fork syd-abort-fork-static \
	      syd-abort-pthread syd-abort-pthread-static syd-fstatat syd-mkdir-p syd-open-static \
	      syd-open-dot threads_execve

check_CFLAGS= $(AM_CFLAGS)
check_LDFLAGS= $(AM_LDFLAGS)
check_SCRIPTS= $(syd_SCRIPTS)
check_PROGRAMS= $(syd_PROGRAMS)
EXTRA_DIST+= $(syd_SCRIPTS)

.PHONY: check-build
check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_PROGRAMS}
