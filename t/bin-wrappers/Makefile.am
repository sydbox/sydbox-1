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
BUILD_EXEC_PREFIX= $(top_srcdir)/$(LIBTOOL) --mode=execute --
endif

sydbox: sydbox.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 -e 's:@LIBEXECDIR@:$(libexecdir):g' \
			 -e 's:@BUILD_EXEC_PREFIX@:$(BUILD_EXEC_PREFIX):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
EXTRA_DIST+= sydbox.in

# Not used any more.
# Use sydbox wrapper with SYDBOX_DUMP=1 instead.
sydbox-dump: sydbox-dump.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 -e 's:@LIBEXECDIR@:$(libexecdir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
EXTRA_DIST+= sydbox-dump.in

shoebox: shoebox.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 -e 's:@LIBEXECDIR@:$(libexecdir)/$(PACKAGE):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
EXTRA_DIST+= shoebox.in

sydfmt: sydfmt.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
EXTRA_DIST+= sydfmt.in

check_SCRIPTS= \
	       sydbox \
	       sydbox-dump \
	       shoebox \
	       sydfmt

syddir=$(libexecdir)/$(PACKAGE)/t/bin-wrappers
syd_SCRIPTS= $(check_SCRIPTS)
