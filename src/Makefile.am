AM_MAKEFLAGS= --no-print-directory
BUILT_SOURCES=
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST=
noinst_HEADERS=

noinst_SCRIPTS= \
		kingbee.py
EXTRA_DIST+= $(noinst_SCRIPTS)

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITVERSION=\"$(GITVERSION)\"
AM_CFLAGS= \
	   -I$(top_builddir)/syd \
	   -I$(top_srcdir)/syd \
	   -I$(top_builddir) \
	   -I$(top_srcdir) \
	   $(pinktrace_CFLAGS) \
	   @SYDBOX_CFLAGS@
if WANT_DEBUG
AM_CFLAGS+= $(libunwind_CFLAGS)
endif

bin_PROGRAMS= sydbox sydfmt
sydbox_CPPFLAGS= -DSYDBOX
sydfmt_CPPFLAGS= -DSYDFMT
noinst_HEADERS+= \
		 acl-queue.h \
		 asyd.h \
		 dump.h \
		 file.h \
		 macro.h \
		 path.h \
		 pathlookup.h \
		 pink.h \
		 proc.h \
		 seccomp.h \
		 pathdecode.h \
		 pathmatch.h \
		 procmatch.h \
		 sockmatch.h \
		 sockmap.h \
		 util.h \
		 xfunc.h \
		 sydhash.h \
		 sydconf.h \
		 sydbox.h
sydbox_SOURCES= \
		 file.c \
		 path.c \
		 pathlookup.c \
		 pink.c \
		 proc.c \
		 pathdecode.c \
		 pathmatch.c \
		 procmatch.c \
		 sockmatch.c \
		 acl-queue.c \
		 util.c \
		 xfunc.c \
		 magic-panic.c \
		 magic-sandbox.c \
		 magic-trace.c \
		 magic-restrict.c \
		 magic-whitelist.c \
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

# http://troydhanson.github.io/uthash/ v1.9.8-223-ge7f4693
noinst_HEADERS+= \
		 uthash.h

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

sydbox_LDFLAGS= -lsyd_@LIBSYD_PC_SLOT@
sydbox_LDADD= -L$(top_builddir)/syd/.libs -lsyd_@LIBSYD_PC_SLOT@ $(pinktrace_LIBS)
if WANT_DEBUG
sydbox_LDADD+= $(libunwind_LIBS)
endif

DUMP_SRCS= $(sydbox_SOURCES) dump.c
DUMP_COMPILER_FLAGS= $(AM_CFLAGS) -O0 -g -ggdb3
DUMP_PREPROCESSOR_FLAGS= -DSYDBOX_DUMP
DUMP_LINKER_LIBRARY_ADD= $(sydbox_LIBADD)
DUMP_LINKER_ADD= $(sydbox_LDADD)
DUMP_LINKER_FLAGS= \
	  -Wl,--wrap=pink_trace_resume \
	  -Wl,--wrap=pink_trace_kill \
	  -Wl,--wrap=pink_trace_singlestep \
	  -Wl,--wrap=pink_trace_syscall \
	  -Wl,--wrap=pink_trace_geteventmsg \
	  -Wl,--wrap=pink_trace_get_regs \
	  -Wl,--wrap=pink_trace_get_regset \
	  -Wl,--wrap=pink_trace_set_regs \
	  -Wl,--wrap=pink_trace_set_regset \
	  -Wl,--wrap=pink_trace_get_siginfo \
	  -Wl,--wrap=pink_trace_setup \
	  -Wl,--wrap=pink_trace_sysemu \
	  -Wl,--wrap=pink_trace_sysemu_singlestep \
	  -Wl,--wrap=pink_trace_attach \
	  -Wl,--wrap=pink_trace_detach \
	  -Wl,--wrap=pink_trace_seize \
	  -Wl,--wrap=pink_trace_interrupt \
	  -Wl,--wrap=pink_trace_listen \
	  -Wl,--wrap=pink_write_syscall

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

sydbox_dump_SOURCES= $(DUMP_SRCS)
sydbox_dump_CFLAGS= $(DUMP_COMPILER_FLAGS)
sydbox_dump_CPPFLAGS= $(DUMP_PREPROCESSOR_FLAGS)
sydbox_dump_LDADD= $(DUMP_LINKER_ADD)
sydbox_dump_LDFLAGS= $(DUMP_LINKER_FLAGS)

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
			$(pinktrace_CFLAGS) \
			$$path; \
	done 2>&1 |\
	tee sydbox-splint.log
