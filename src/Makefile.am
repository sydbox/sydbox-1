AM_MAKEFLAGS= --no-print-directory
BUILT_SOURCES= \
	       syscall_open_ro.lst \
	       syscall_open_syd.h \
	       sydbox_rs.h \
	       lib.rs
CLEANFILES= \
	    $(BUILT_SOURCES) \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST= syscall_open_syd.h.in syd-syscall-open.py sydbox_rs.h
noinst_HEADERS=


CARGO_VERBOSE = $(cargo_verbose_$(V))
cargo_verbose_ = $(cargo_verbose_$(AM_DEFAULT_VERBOSITY))
cargo_verbose_0 =
cargo_verbose_1 = --verbose
CARGO_FLAGS= --$(SYDBOX_CARGO_RELEASE_TYPE) --frozen $(CARGO_VERBOSE)

check-local:
	CARGO_TARGET_DIR=sydbox_rs $(CARGO) test $(CARGO_FLAGS)
clean-local:
	CARGO_TARGET_DIR=sydbox_rs $(CARGO) clean $(CARGO_FLAGS)
install-exec-local:
	CARGO_TARGET_DIR=sydbox_rs $(CARGO) install --path=. --root="$(DESTDIR)/usr" --frozen
	rm -f $(DESTDIR)/usr/.crates.toml
	rm -f $(DESTDIR)/usr/.crates2.json

SYDBOX_RUST_LIB=sydbox_rs/$(SYDBOX_CARGO_RELEASE_TYPE)/libsydbox
SYDBOX_RUST_LIB_STA=$(SYDBOX_RUST_LIB).a
SYDBOX_RUST_LIB_DYN=$(SYDBOX_RUST_LIB).so
CARGO_BUILD_FLAGS= --lib --target-dir $(builddir)/sydbox_rs
CARGO_BUILD_FLAGS+= $(CARGO_FLAGS)
CLEANFILES+= \
	     $(SYDBOX_RUST_LIB_DYN) \
	     $(SYDBOX_RUST_LIB_STA) \
	     sydbox_rs/$(SYDBOX_CARGO_RELEASE_TYPE)/deps

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

OPT_DUMP=
if SYDBOX_HAVE_DUMP_BUILTIN
OPT_DUMP+=yes
else
OPT_DUMP+=no
endif

lib.rs: lib.rs.in
	$(AM_V_GEN)
	$(AM_V_at)chmod -f +w $@ || true
	$(AM_V_at)$(SED) \
		-e "s:@SYD_PACKAGE@:$(PACKAGE):g" \
		-e "s:@SYD_VERSION@:$(VERSION):g" \
		-e "s:@SYD_GITVERSION@:$(GITVERSION):g" \
		-e "s:@DUMP_BUILTIN@:$(OPT_DUMP):g" \
		$< > $@
	$(AM_V_at)chmod -f -w $@ || true

if HAVE_CBINDGEN
# TODO -Z parse-only is nightly only, when it's not
#  add it to RUSTC below.
sydbox_rs.h: lib.rs $(top_builddir)/cbindgen.toml
	$(CBINDGEN) --config $(top_builddir)/cbindgen.toml lib.rs -o $@ || $(RUSTC) lib.rs
endif

$(SYDBOX_RUST_LIB).%: jobs lib.rs
	@mkdir -m700 -p $(builddir)/sydbox_rs
	$(AM_V_GEN)
	$(AM_V_at)$(CARGO) build -j $(JOB_COUNT) $(CARGO_BUILD_FLAGS)
if !ENABLE_STATIC
.libs/libsydbox.so: $(SYDBOX_RUST_LIB_DYN)
	$(AM_V_GEN)
	$(AM_V_at)cp -fp $< $@
endif

syscall_open_syd.h: Makefile syscall_open_ro.lst syscall_open_syd.h.in
	$(PYTHON) ./syd-syscall-open.py < syscall_open_ro.lst > $@ ||\
		rm $@

syscall_open_ro.lst: Makefile
	$(AM_V_GEN)
	$(AM_V_at)for include in $(SYD_FCNTL_INCLUDES); do \
		test -e "$$include" || continue ; \
		$(EGREP) -h '#[[:space:]]*define[[:space:]]+O_' "$$include" |\
			$(AWK) '{print $$2}' |\
			$(EGREP) -v 'O_ACCMODE|O_RDONLY|O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_DIRECTORY|O_EXEC|O_NDELAY|O_PATH|O_RSYNC|O_SEARCH|O_TMPFILE|O_TMPFILE_MASK|O_TTY_INIT' ;\
	done | $(SORT) -u > "$@" || rm -f "$@"
	$(AM_V_at)sh -c 'test -s "$@" || echo "Failed to generate read-only open flags"'
	$(AM_V_at)sh -c 'test -s "$@" || exit 1'

DEFS+= \
       -DIN_SYD=1 \
       -DIN_SYDBOX=1 \
       -DDATADIR=\"$(datadir)\" \
       -DGITVERSION=\"$(GITVERSION)\" \
       -DSYSCONFDIR=\"$(sysconfdir)\"
AM_CFLAGS= \
	   -I$(top_builddir)/syd \
	   -I$(top_srcdir)/syd \
	   -I$(top_builddir) \
	   -I$(top_srcdir) \
	   $(libseccomp_CFLAGS) \
	   @SYDBOX_CFLAGS@

if MAINTAINER_MODE
AM_CFLAGS+= $(SYDBOX_SAFE_CFLAGS) $(SYDBOX_DEV_CFLAGS)
endif

if WANT_DEBUG
AM_CFLAGS+= $(libunwind_CFLAGS)
endif

AM_CFLAGS+= $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS= $(CODE_COVERAGE_CPPFLAGS)

AM_LFLAGS = -v
AM_YFLAGS = -d

bin_PROGRAMS= syd syd-format
syd_CPPFLAGS= -DSYDBOX -DSYD=1
syd_format_CPPFLAGS= -DSYDFMT -DSYD_FORMAT=1
noinst_HEADERS+= \
		 lib.rs \
		 acl-queue.h \
		 arch.h \
		 asyd.h \
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
		 sha1dc_sha1.h \
		 sha1dc_ubc_check.h \
		 sha1dc_syd.h \
		 syd_seccomp_arch_default.c \
		 sydbox_rs.h \
		 sockmatch.h \
		 sockmap.h \
		 util.h \
		 xfunc.h \
		 sydconf.h \
		 sydbox.h
syd_SOURCES= \
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
		 sha1dc_sha1.c \
		 sha1dc_ubc_check.c \
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
		 config.c \
		 sydbox.c
syd_format_SOURCES= \
		syd-format.c

# Imported from rsync!
noinst_HEADERS+= \
		 wildmatch.h
syd_SOURCES+= \
		 wildmatch.c

# Imported from zsh!
noinst_HEADERS+= \
		 toolong.h
syd_SOURCES+= \
		 toolong.c

# (partly modified and) imported from FreeBSD's lib/libc/stdlib
noinst_HEADERS+= \
		 bsd-compat.h
syd_SOURCES+= \
		 realpath.c \
		 strlcat.c \
		 strlcpy.c

# imported from OpenBSD
noinst_HEADERS+= \
		 sys-queue.h

if WANT_PSYSCALL
# imported from psyscall
AM_CFLAGS+= $(pinktrace_CFLAGS)
noinst_HEADERS+= psyscall_syd.h
syd_SOURCES+= psyscall.c psyscall_syd.c
endif

syd_LDFLAGS= -pthread -lpthread -ldl \
	     $(CODE_COVERAGE_LDFLAGS)
syd_LDADD= \
	      $(top_builddir)/syd/libsyd_@LIBSYD_PC_SLOT@.la \
	      -L$(top_builddir)/syd/.libs \
	      -lsyd_@LIBSYD_PC_SLOT@ \
	      @SYDBOX_LIBTOOL_FLAGS@ \
	      $(libseccomp_LIBS) \
	      $(CODE_COVERAGE_LIBS)
syd_LDADD+= $(SYDBOX_RUST_LIB_STA)

if WANT_DEBUG
syd_LDADD+= $(libunwind_LIBS)
endif
if WANT_PSYSCALL
syd_LDADD+= $(pinktrace_LIBS)
endif

DUMP_SRCS= dump.c
DUMP_COMPILER_FLAGS= $(AM_CFLAGS) -O0 -g -ggdb3
DUMP_PREPROCESSOR_FLAGS= -DSYDBOX_DUMP=1
DUMP_LINKER_LIBRARY_ADD= $(syd_LIBADD)
DUMP_LINKER_ADD=
DUMP_LINKER_FLAGS=

syddir=$(libexecdir)/$(PACKAGE)/dump
syd_SCRIPTS= syd-shoebox
syd_PROGRAMS= syd-dump

syd-shoebox: syd-shoebox.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@SHOEBOX_VERSION@:$(VERSION)$(GITVERSION):g" \
		$< > $@
	$(AM_V_at)chmod +x $@
CLEANFILES+= syd-shoebox
EXTRA_DIST+= syd-shoebox.in

syd_dump_SOURCES=
syd_dump_CFLAGS= $(DUMP_COMPILER_FLAGS)
syd_dump_CPPFLAGS=
syd_dump_LDADD=
syd_dump_LDFLAGS=

if SYDBOX_HAVE_DUMP_BUILTIN
syd_SOURCES+= $(DUMP_SRCS)
syd_LDADD+= $(DUMP_LINKER_ADD)
syd_LDFLAGS+= $(DUMP_LINKER_FLAGS)
syd_dump_SOURCES+= $(syd_SOURCES)
syd_dump_CPPFLAGS+= $(syd_CPPFLAGS)
syd_dump_LDADD+= $(syd_LDADD)
syd_dump_LDFLAGS+= $(DUMP_LINKER_FLAGS)
else
syd_dump_SOURCES+= $(syd_SOURCES) $(DUMP_SRCS)
syd_dump_CFLAGS+= $(DUMP_COMPILER_FLAGS)
syd_dump_CPPFLAGS+= $(DUMP_PREPROCESSOR_FLAGS)
syd_dump_LDADD+= $(syd_LDADD) $(DUMP_LINKER_ADD)
syd_dump_LDFLAGS+= $(DUMP_LINKER_FLAGS)
endif

###
# Determine make -j job count to pass to cargo.
# See: https://blog.jgc.org/2015/03/gnu-make-insanity-finding-value-of-j.html
.DEFAULT_GOAL: all
.PHONY: all
all: jobs $(bin_PROGRAMS) $(syd_PROGRAMS)

.PHONY: jobs
jobs: | parallel; @echo >&2 "[0;1;31;91msydb☮x: Make is running $(JOB_COUNT) jobs.[0m"

.PHONY: parallel
parallel: .parallel ; @$(eval JOB_COUNT := $(shell sort -n $< | tail -n 1))
.parallel: FORCE ; @$(MAKE) --no-print-directory par 2>/dev/null >$@ || true
FORCE:

to_n = $(words $2) $(if $(filter-out $1,$(words x $2)),$(call to_n,$1,x $2))

PAR_COUNT :=
par: $(addprefix par-,$(call to_n,32))
par-%: ; @$(eval PAR_COUNT += x)@echo $(words $(PAR_COUNT)) && sleep 1 && false

# Convenience for users, more ugliness for meself...
# PATH=${syddir} cave resolve ...
# to use sydbox-dump
install-data-hook:
	cd $(DESTDIR)$(syddir) && \
		$(LN_S) -f syd-dump syd

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
	for src in $(syd_SOURCES); \
	do \
		$(SPARSE) $(DEFS) $(AM_CFLAGS) $(SPARSE_CPPFLAGS) $$src || exit 1; \
	done
.PHONY: sparse-check

cppcheck:
	cppcheck $(syd_SOURCES) \
		$(DEFS) -I$(top_builddir) -I$(top_srcdir) \
		--std=c99 --std=posix --enable=all
.PHONY: cppcheck

splint:
	for path in $(syd_SOURCES); do \
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
