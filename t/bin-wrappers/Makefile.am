AM_MAKEFLAGS= --no-print-directory
SUBDIRS= .
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST=

if ENABLE_STATIC
BUILD_EXEC_PREFIX=
else
BUILD_EXEC_PREFIX= $(SHELL) $(top_builddir)/libtool --mode=execute
endif

syd: syd.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 -e 's:@LIBEXECDIR@:$(libexecdir):g' \
			 -e 's:@BUILD_EXEC_PREFIX@:$(BUILD_EXEC_PREFIX):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
EXTRA_DIST+= syd.in

#syd-dump: syd-dump.in Makefile
#	$(AM_V_GEN)
#	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
#			 -e 's:@BINDIR@:$(bindir):g' \
#			 -e 's:@LIBEXECDIR@:$(libexecdir):g' \
#			 -e 's:@BUILD_EXEC_PREFIX@:$(BUILD_EXEC_PREFIX):g' \
#			 < $< > $@
#	$(AM_V_at)chmod +x $@
#EXTRA_DIST+= syd-dump.in

#shoebox: shoebox.in Makefile
#	$(AM_V_GEN)
#	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
#			 -e 's:@BINDIR@:$(bindir):g' \
#			 -e 's:@LIBEXECDIR@:$(libexecdir)/$(PACKAGE):g' \
#			 < $< > $@
#	$(AM_V_at)chmod +x $@
#EXTRA_DIST+= shoebox.in
#
syd-format: syd-format.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
EXTRA_DIST+= syd-format.in

check_SCRIPTS= syd syd-format

syddir=$(libexecdir)/$(PACKAGE)/t-$(SYDBOX_API_VERSION)/bin-wrappers
syd_SCRIPTS= $(check_SCRIPTS)
