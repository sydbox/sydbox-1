AM_MAKEFLAGS= --no-print-directory
SUBDIRS= .

syddir=$(libexecdir)/$(PACKAGE)/t/valgrind
VALGRIND_SRCS= \
	     analyze.sh \
	     valgrind.sh.in
syd_SCRIPTS= analyze.sh \
	     valgrind.sh \
	     ./bin/sydbox \
	     ./bin/sydbox-dump \
	     ./bin/sydfmt \
	     ./bin/shoebox
syd_DATA= default.supp

if ENABLE_STATIC
BUILD_EXEC_PREFIX=
else
BUILD_EXEC_PREFIX= $(LIBTOOL) --mode=execute --
endif

valgrind.sh: valgrind.sh.in Makefile
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e 's:@TOP_BUILDDIR@:$(abs_top_builddir):g' \
			 -e 's:@BINDIR@:$(bindir):g' \
			 -e 's:@LIBEXECDIR@:$(libexecdir):g' \
			 -e 's:@BUILD_EXEC_PREFIX@:$(BUILD_EXEC_PREFIX):g' \
			 < $< > $@
	$(AM_V_at)chmod +x $@
bin/sydbox: valgrind.sh
	$(LN_S) -f ../$< bin/sydbox
bin/sydbox-dump: valgrind.sh
	$(LN_S) -f ../$< bin/sydbox-dump
bin/sydfmt: valgrind.sh
	$(LN_S) -f ../$< bin/sydfmt
bin/shoebox: valgrind.sh
	$(LN_S) -f ../$< bin/shoebox

install-exec-hook:
	$(MKDIR_P) $(DESTDIR)$(syddir)/bin
	$(LN_S) -f ../valgrind.sh $(DESTDIR)$(syddir)/bin/sydbox
	$(LN_S) -f ../valgrind.sh $(DESTDIR)$(syddir)/bin/sydbox-dump
	$(LN_S) -f ../valgrind.sh $(DESTDIR)$(syddir)/bin/sydfmt
	$(LN_S) -f ../valgrind.sh $(DESTDIR)$(syddir)/bin/shoebox

EXTRA_DIST= $(VALGRIND_SRCS) $(syd_DATA)
