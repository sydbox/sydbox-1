AM_MAKEFLAGS= --no-print-directory
BUILT_SOURCES= \
	       syscall_open_ro.lst \
	       syscall_open_syd.h
CLEANFILES= \
	    $(BUILT_SOURCES) \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST=
noinst_HEADERS=

noinst_SCRIPTS= \
		kingbee.py
EXTRA_DIST+= $(noinst_SCRIPTS)

SYD_FCNTL_INCLUDES= \
	$(SYD_INCLUDEDIR)/fcntl.h \
	$(SYD_INCLUDEDIR)/asm/fcntl.h \
	$(SYD_INCLUDEDIR)/asm-generic/fcntl.h \
	$(SYD_INCLUDEDIR)/bits/fcntl.h \
	$(SYD_INCLUDEDIR)/sys/fcntl.h \
	$(SYD_INCLUDEDIR)/linux/fcntl.h

syscall_open_syd.h: Makefile syscall_open_ro.lst syscall_open_syd.h.in
	$(PYTHON) ./syd-syscall-open.py < syscall_open_ro.lst > $@ ||\
		rm $@

syscall_open_ro.lst: Makefile
	$(AM_V_GEN)
	$(AM_V_at)for include in $(SYD_FCNTL_INCLUDES); do \
		test -e "$$include" || continue ; \
		$(EGREP) -h '#[[:space:]]*define[[:space:]]+O_' "$$include" |\
			$(AWK) '{print $$2}' |\
			$(EGREP) -v 'O_ACCMODE|O_RDONLY|O_WRONLY|O_RDWR|O_DIRECTORY|O_PATH|O_TMPFILE|O_TMPFILE_MASK' ;\
	done | $(SORT) -u > "$@" || rm -f "$@"
	$(AM_V_at)sh -c 'test -s "$@" || echo "Failed to generate read-only open flags"'
	$(AM_V_at)sh -c 'test -s "$@" || exit 1'

DEFS+= \
       -DIN_SYDBOX=1 \
       -DDATADIR=\"$(datadir)\" \
       -DGITVERSION=\"$(GITVERSION)\"
AM_CFLAGS= \
	   -I$(top_builddir)/syd \
	   -I$(top_srcdir)/syd \
	   -I$(top_builddir) \
	   -I$(top_srcdir) \
	   $(libseccomp_CFLAGS) \
	   @SYDBOX_CFLAGS@
if WANT_DEBUG
AM_CFLAGS+= $(libunwind_CFLAGS)
endif

AM_CFLAGS+= $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS= $(CODE_COVERAGE_CPPFLAGS)

AM_LFLAGS = -v
AM_YFLAGS = -d

bin_PROGRAMS= sydbox sydfmt
sydbox_CPPFLAGS= -DSYDBOX
sydfmt_CPPFLAGS= -DSYDFMT
noinst_HEADERS+= \
		 acl-queue.h \
		 arch.h \
		 asyd.h \
		 compiler.h \
		 daemon.h \
		 dump.h \
		 errno2name.h \
		 file.h \
		 hex.h \
		 macro.h \
		 path.h \
		 pathlookup.h \
		 pink.h \
		 proc.h \
		 rule.h \
		 pathdecode.h \
		 pathmatch.h \
		 procmatch.h \
		 syscall_open_ro.lst \
		 syscall_open_syd.h \
		 #profile_parser.y \
		 #profile_scanner.l \
		 sc_map.h \
		 sc_map_syd.h \
		 serializer.h \
		 sha1dc/sha1.h \
		 sha1dc/ubc_check.h \
		 syd_seccomp_arch_default.c \
		 sockmatch.h \
		 sockmap.h \
		 util.h \
		 xfunc.h \
		 sydconf.h \
		 sydbox.h
sydbox_SOURCES= \
		 arch.c \
		 daemon.c \
		 errno2name.c \
		 file.c \
		 filter.c \
		 hex.c \
		 path.c \
		 pathlookup.c \
		 pink.c \
		 proc.c \
		 pathdecode.c \
		 pathmatch.c \
		 procmatch.c \
		 sc_map.c \
		 serializer.c \
		 sha1dc/sha1.c \
		 sha1dc/ubc_check.c \
		 sha1dc_syd.c \
		 sockmatch.c \
		 acl-queue.c \
		 util.c \
		 xfunc.c \
		 magic-panic.c \
		 magic-sandbox.c \
		 magic-trace.c \
		 magic-restrict.c \
		 magic-allowlist.c \
		 magic-acl.c \
		 magic-match.c \
		 magic-cmd.c \
		 magic.c \
		 sandbox.c \
		 panic.c \
		 syscall-file.c \
		 syscall-sock.c \
		 syscall-special.c \
		 syscall-filter.c \
		 syscall.c \
		 systable.c \
		 config.c \
		 sydbox.c
sydfmt_SOURCES= \
		sydfmt.c

# Imported from rsync!
noinst_HEADERS+= \
		 wildmatch.h
sydbox_SOURCES+= \
		 wildmatch.c

# Imported from zsh!
noinst_HEADERS+= \
		 toolong.h
sydbox_SOURCES+= \
		 toolong.c

# (partly modified and) imported from FreeBSD's lib/libc/stdlib
noinst_HEADERS+= \
		 bsd-compat.h
sydbox_SOURCES+= \
		 realpath.c \
		 strlcat.c \
		 strlcpy.c

# imported from OpenBSD
noinst_HEADERS+= \
		 sys-queue.h

sydbox_LDFLAGS= -lsyd_@LIBSYD_PC_SLOT@ $(CODE_COVERAGE_LDFLAGS)
sydbox_LDADD= \
	      $(top_builddir)/syd/libsyd_@LIBSYD_PC_SLOT@.la \
	      -L$(top_builddir)/syd/.libs \
	      -lsyd_@LIBSYD_PC_SLOT@ \
	      @SYDBOX_LIBTOOL_FLAGS@ \
	      $(libseccomp_LIBS) \
	      $(CODE_COVERAGE_LIBS)
if WANT_DEBUG
sydbox_LDADD+= $(libunwind_LIBS)
endif

DUMP_SRCS= dump.c
DUMP_COMPILER_FLAGS= $(AM_CFLAGS) -O0 -g -ggdb3
DUMP_PREPROCESSOR_FLAGS= -DSYDBOX_DUMP=1
DUMP_LINKER_LIBRARY_ADD= $(sydbox_LIBADD)
DUMP_LINKER_ADD=
DUMP_LINKER_FLAGS=

syddir=$(libexecdir)/$(PACKAGE)/dump
syd_SCRIPTS= shoebox
syd_PROGRAMS= sydbox-dump

shoebox: shoebox.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@SHOEBOX_VERSION@:$(VERSION)$(GITVERSION):g" \
		$< > $@
	$(AM_V_at)chmod +x $@
CLEANFILES+= shoebox
EXTRA_DIST+= shoebox.in

sydbox_dump_SOURCES=
sydbox_dump_CFLAGS= $(DUMP_COMPILER_FLAGS)
sydbox_dump_CPPFLAGS=
sydbox_dump_LDADD=
sydbox_dump_LDFLAGS=

if SYDBOX_HAVE_DUMP_BUILTIN
sydbox_SOURCES+= $(DUMP_SRCS)
sydbox_LDADD+= $(DUMP_LINKER_ADD)
sydbox_LDFLAGS+= $(DUMP_LINKER_FLAGS)
sydbox_dump_SOURCES+= $(sydbox_SOURCES)
sydbox_dump_CPPFLAGS+= $(sydbox_CPPFLAGS)
sydbox_dump_LDADD+= $(sydbox_LDADD)
sydbox_dump_LDFLAGS+= $(DUMP_LINKER_FLAGS)
else
sydbox_dump_SOURCES+= $(sydbox_SOURCES) $(DUMP_SRCS)
sydbox_dump_CFLAGS+= $(DUMP_COMPILER_FLAGS)
sydbox_dump_CPPFLAGS+= $(DUMP_PREPROCESSOR_FLAGS)
sydbox_dump_LDADD+= $(sydbox_LDADD) $(DUMP_LINKER_ADD)
sydbox_dump_LDFLAGS+= $(DUMP_LINKER_FLAGS)
endif

# Convenience for users, more ugliness for meself...
# PATH=${syddir} cave resolve ...
# to use sydbox-dump
install-data-hook:
	cd $(DESTDIR)$(syddir) && \
		$(LN_S) -f sydbox-dump sydbox

SPARSE=sparse
SPARSE_CPPFLAGS= $(DEFAULT_INCLUDES) \
		 -D__STDC_VERSION__=199901L \
		 -Wbitwise -Wcast-to-as -Wdefault-bitfield-sign \
		 -Wparen-string -Wptr-subtraction-blows \
		 -Wreturn-void -Wshadow -Wtypesign -Wundef \
		 -I$(shell $(CC) -print-file-name=include) \
		 -I$(shell $(CC) -print-file-name=include-fixed)
# Fix this flag for your architecture!
SPARSE_CPPFLAGS+= -D__x86_64__=1

sparse-check:
	for src in $(sydbox_SOURCES); \
	do \
		$(SPARSE) $(DEFS) $(AM_CFLAGS) $(SPARSE_CPPFLAGS) $$src || exit 1; \
	done
.PHONY: sparse-check

cppcheck:
	cppcheck $(sydbox_SOURCES) \
		$(DEFS) -I$(top_builddir) -I$(top_srcdir) \
		--std=c99 --std=posix --enable=all
.PHONY: cppcheck

splint:
	for path in $(sydbox_SOURCES); do \
		echo "SPLINT $$path"; \
		splint +posixlib -D__x86_64__ \
			$(DEFS) \
			-D_GNU_SOURCE \
			-D__signed__=signed \
			-DLINE_MAX=2048 \
			-boolops \
			-nullret \
			-I$(top_builddir) -I$(top_builddir)/syd \
			-I$(top_srcdir) -I$(top_srcdir)/syd \
			$(libseccomp_CFLAGS) \
			$$path; \
	done 2>&1 |\
	tee sydbox-splint.log
