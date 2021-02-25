AM_MAKEFLAGS= --no-print-directory
SUBDIRS= .
EXTRA_DIST = test-skel-0.c test-skel-1.c tests.h headers.h localdecls.h
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov

# Use -DNDEBUG so as not to require sydbox' assert() override
AM_CPPFLAGS = $(DEFS) -I$(top_builddir) -I$(top_srcdir) -I$(top_srcdir)/src
AM_CFLAGS = $(pinktrace_CFLAGS) @SYDBOX_CFLAGS@ -DNDEBUG `expr $@ : .*-pthread >/dev/null && echo -pthread`
AM_LDFLAGS = $(pinktrace_LIBS) `expr $@ : .*-static >/dev/null && echo -all-static`

wildtest_SOURCES= tap.h wildtest.c
wildtest_CFLAGS= \
		 -DWILD_TEST_ITERATIONS \
		 --include=$(top_srcdir)/src/wildmatch.c

realpath_mode_1_SOURCES= realpath_mode-1.c \
			 ../../src/realpath.c \
			 ../../src/strlcat.c \
			 ../../src/strlcpy.c \
			 ../../src/file.c \
			 ../../src/util.c

syddir=$(libexecdir)/$(PACKAGE)/t/test-bin
syd_PROGRAMS= wildtest realpath_mode-1 \
	      syd-true syd-true-static syd-true-fork syd-true-fork-static syd-true-pthread \
	      syd-false syd-false-static syd-false-fork syd-false-fork-static syd-false-pthread \
	      syd-abort syd-abort-static syd-abort-fork syd-abort-fork-static \
	      syd-abort-pthread syd-abort-pthread-static syd-fstatat syd-mkdir-p


check_PROGRAMS= $(syd_PROGRAMS)
