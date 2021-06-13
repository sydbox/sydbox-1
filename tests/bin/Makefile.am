AM_MAKEFLAGS= --no-print-directory
SUBDIRS= .
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST=
noinst_DATA=
noinst_HEADERS=
noinst_SCRIPTS=

sydbox: sydbox.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
CLEANFILES+= sydbox
EXTRA_DIST+= sydbox.in

sydfmt: sydfmt.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
CLEANFILES+= sydfmt
EXTRA_DIST+= sydfmt.in

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITHEAD=\"$(GITHEAD)\"

# Use -DNDEBUG so as not to require sydbox' assert() override
AM_CFLAGS= \
	   -DNDEBUG \
	   -I$(top_builddir) \
	   -I$(top_srcdir) \
	   -I$(top_srcdir)/src \
	   @SYDBOX_CFLAGS@

noinst_HEADERS+= \
		 tap.h \
		 emily.h

realpath_test_SOURCES= \
		       realpath-test.c \
		       ../../src/realpath.c \
		       ../../src/strlcat.c \
		       ../../src/strlcpy.c \
		       ../../src/file.c \
		       ../../src/util.c
realpath_test_CFLAGS= \
		      $(DEFS) \
		      $(AM_CFLAGS) \
		      -I$(top_builddir) \
		      -I$(top_srcdir) \
		      -I$(top_srcdir)/src
realpath_test_LDADD=
realpath_test_LDFLAGS= -no-install

emily_SOURCES= \
	       emily.c \
	       emily-access.c \
	       emily-stat.c \
	       emily-chmod.c \
	       emily-chown.c \
	       emily-open.c \
	       emily-creat.c \
	       emily-mkdir.c \
	       emily-mknod.c \
	       emily-rename.c \
	       emily-rmdir.c \
	       emily-utimensat.c \
	       ../../src/util.c
emily_CFLAGS= \
	      $(DEFS) \
	      $(AM_CFLAGS) \
	      -I$(top_builddir) \
	      -I$(top_srcdir) \
	      -I$(top_srcdir)/src
emily_LDADD=
emily_LDFLAGS= -no-install

unlink_simple_SOURCES= \
		       unlink-simple.c
unlink_simple_CFLAGS= \
		      $(DEFS) \
		      $(AM_CFLAGS)

wildtest_SOURCES= \
		  wildtest.c
wildtest_CFLAGS= \
		 -DWILD_TEST_ITERATIONS \
		 --include=$(top_srcdir)/src/wildmatch.c \
		 $(DEFS) \
		 $(AM_CFLAGS)

check_PROGRAMS= \
		emily \
		realpath-test \
		unlink-simple \
		wildtest

check_SCRIPTS= \
	       sydbox \
	       sydfmt
