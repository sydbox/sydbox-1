#H = $(top_builddir)/misc/syd-hilite
AM_MAKEFLAGS= --no-print-directory
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST= \
	    syscall_open_syd.h.in \
	    syscall_open_ro.lst \
	    syscall_open_syd.h \
	    syd-syscall-open.py \
	    Cargo.toml.in
noinst_HEADERS=

BUILT_SOURCES= jobs
.PHONY: jobs
jobs: | parallel

BUILT_SOURCES+= build
.PHONY: build
build: jobs
	@echo >&2 "[0;1;31;91msydb☮x: Make is running $(JOB_COUNT) jobs.[0m"
	$(H) make $(AM_MAKEFLAGS) $(MFLAGS) $(PROGRAMS)

CARGO_VERBOSE = $(cargo_verbose_$(V))
cargo_verbose_ = $(cargo_verbose_$(AM_DEFAULT_VERBOSITY))
cargo_verbose_0 =
cargo_verbose_1 = --verbose
if SYDBOX_CARGO_RELEASE
CARGO_FLAGS= $(CARGO_VERBOSE) --$(SYDBOX_CARGO_RELEASE_TYPE)
else
CARGO_FLAGS= $(CARGO_VERBOSE)
endif

Cargo.toml$(EXEEXT): Cargo.toml.in
	$(AM_V_GEN)
	$(AM_V_at)touch Cargo.toml$(EXEEXT)
	$(AM_V_at)$(SED) \
		-e 's:@SYDBOX_VERSION@:$(VERSION):g' \
		-e 's:@RUST_LIBTYPES@:$(SYDBOX_RUST_LIBTYPES):g' \
		$< > Cargo.toml

.PHONY: audit
CARGO_TARGET_DIR=$(top_builddir)/src/sydbox_rs
export CARGO_TARGET_DIR
audit:
	$(MAKE) Cargo.toml
	$(CARGO) audit
#check-local:
#	$(MAKE) Cargo.toml
#	$(CARGO) test $(CARGO_FLAGS)
#clean-local:
#	$(MAKE) Cargo.toml
#	$(CARGO) clean
# We have no packages with binaries or examples for $(top_builddir)/src/sydbox_rs/ yet.
#install-exec-local:
#	$(MAKE) Cargo.toml
#	$(CARGO) install --path=. --root="$(DESTDIR)/usr/$(target_triplet)"
#	rm -f $(DESTDIR)/usr/$(target_triplet)/.crates.toml
#	rm -f $(DESTDIR)/usr/$(target_triplet)/.crates2.json

##if WANT_SYDBOX_RS
#SYDBOX_RUST_LIB=sydbox_rs/$(SYDBOX_CARGO_RELEASE_TYPE)/libsydbox
#SYDBOX_RUST_LIB_STA=$(SYDBOX_RUST_LIB)_rs/$(SYDBOX_CARGO_RELEASE_TYPE)/lib$(SYDBOX_RUST_LIB).a
#SYDBOX_RUST_LIB_DYN=$(SYDBOX_RUST_LIB)_rs/$(SYDBOX_CARGO_RELEASE_TYPE)/deps/lib$(SYDBOX_RUST_LIB).so
#SYDBOX_RUST_LIBS=\
#		 $(SYDBOX_RUST_LIB_STA)
#CARGO_BUILD_FLAGS= --lib --target-dir $(builddir)/sydbox_rs
#CARGO_BUILD_FLAGS+= $(CARGO_FLAGS)
#lib_LIBS= $(SYDBOX_RUST_LIB_STA)
#BUILT_SOURCES+= $(SYDBOX_RUST_LIB_STA)
##endif

noinst_SCRIPTS= \
		kingbee.py
EXTRA_DIST+= $(noinst_SCRIPTS)

SYD_FCNTL_INCLUDES= \
	$(SYD_INCLUDEDIR)/fcntl.h \
	$(SYD_INCLUDEDIR)/asm/fcntl.h \
	$(SYD_INCLUDEDIR)/asm-generic/fcntl.h \
	$(SYD_INCLUDEDIR)/bits/fcntl.h \
	$(SYD_INCLUDEDIR)/bits/fcntl-linux.h \
	$(SYD_INCLUDEDIR)/sys/fcntl.h \
	$(SYD_INCLUDEDIR)/linux/fcntl.h

OPT_DUMP=
if SYDBOX_HAVE_DUMP_BUILTIN
OPT_DUMP+=yes
else
OPT_DUMP+=no
endif

if WANT_SYDBOX_RS
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
endif

if MAINTAINER_MODE
if HAVE_CBINDGEN
if WANT_SYDBOX_RS
BUILT_SOURCES+= sydbox_rs.h
CLEANFILES+= sydbox_rs.h
# TODO -Z parse-only is nightly only, when it's not
#  add it to RUSTC below.
sydbox_rs.h: $(srcdir)/lib.rs $(srcdir)/cbindgen.toml
	$(CBINDGEN) --config $(srcdir)/cbindgen.toml $(srcdir)/lib.rs -o $@ ||\
		$(RUSTC) $(srcdir)/lib.rs
endif
endif
endif

if WANT_SYDBOX_RS
$(SYDBOX_RUST_LIB_STA): jobs lib.rs
	@mkdir -m700 -p $(builddir)/sydbox_rs/$(SYDBOX_CARGO_RELEASE_TYPE)
	$(AM_V_GEN)
	$(AM_V_at)$(CARGO) build -j $(JOB_COUNT) $(CARGO_BUILD_FLAGS)
endif

if MAINTAINER_MODE
syscall_open_syd.h: Makefile syscall_open_ro.lst syscall_open_syd.h.in
	$(PYTHON) ./syd-syscall-open.py < syscall_open_ro.lst > $@ ||\
		rm $@

syscall_open_ro.lst: Makefile
	$(AM_V_GEN)
	$(AM_V_at)for include in $(SYD_FCNTL_INCLUDES); do \
		test -e "$$include" || continue ; \
		$(EGREP) -h '#[[:space:]]*define[[:space:]]+O_' "$$include" |\
			$(AWK) '{print $$2}' |\
			$(EGREP) -v 'define|O_ACCMODE|O_FSYNC|O_RDONLY|O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_DIRECTORY|O_EXEC|O_NDELAY|O_PATH|O_RSYNC|O_SEARCH|O_TMPFILE|O_TMPFILE_MASK|O_TTY_INIT' ;\
	done | $(SORT) -u > "$@" || rm -f "$@"
	echo O_ASYNC >> "$@"
	$(AM_V_at)sh -c 'test -s "$@" || echo "Failed to generate read-only open flags"'
	$(AM_V_at)sh -c 'test -s "$@" || exit 1'
endif

DEFS+= \
       -DIN_SYD=1 \
       -DIN_SYDBOX=1 \
       -DBINDIR=\"$(bindir)\" \
       -DDATADIR=\"$(datadir)\" \
       -DLIBEXECDIR=\"$(libexecdir)/$(PACKAGE)\" \
       -DSYSCONFDIR=\"$(sysconfdir)\"

syd_SOURCES=

AM_CFLAGS= \
	   -I$(top_builddir)/syd \
	   -I$(top_srcdir)/syd \
	   -I$(top_builddir) \
	   -I$(top_srcdir) \
	   $(libseccomp_CFLAGS) \
	   $(SYDBOX_CFLAGS)

if WANT_GIT
AM_CFLAGS+= $(libgit2_CFLAGS)
endif

if WANT_DEBUG
AM_CFLAGS+= $(libunwind_CFLAGS)
endif

AM_CFLAGS+= $(CODE_COVERAGE_CFLAGS)
AM_CPPFLAGS= $(CODE_COVERAGE_CPPFLAGS)

AM_LFLAGS = -v
AM_YFLAGS = -d

bin_PROGRAMS= syd

# TODO: syd-run
syd_libexecdir=$(libexecdir)/$(PACKAGE)/bin
syd_libexec_PROGRAMS= syd-dump syd-errno syd-format syd-sha1

syd_CPPFLAGS= -DSYDBOX -DSYD=1
syd_errno_CPPFLAGS= -DSYDERR -DSYD_ERRNO=1
syd_format_CPPFLAGS= -DSYDFMT -DSYD_FORMAT=1
noinst_INCLUDE_SRCS= syd_seccomp_arch_default.c
noinst_HEADERS+= \
		 acl-queue.h \
		 arch.h \
		 asyd.h \
		 daemon.h \
		 errno2name.h \
		 dump.h \
		 file.h \
		 macro.h \
		 path.h \
		 pathlookup.h \
		 pink.h \
		 proc.h \
		 rule.h \
		 pathdecode.h \
		 pathmatch.h \
		 procmatch.h \
		 #profile_parser.y \
		 #profile_scanner.l \
		 serializer.h \
		 sockmatch.h \
		 sockmap.h \
		 util.h \
		 xfunc.h \
		 syd-conf.h \
		 syd-box.h
syd_SOURCES+= \
	     syd-box.c \
	     Cargo.toml \
	     sydbox_rs.h \
	     arch.c \
	     daemon.c \
	     errno2name.c \
	     file.c \
	     filter.c \
	     path.c \
	     pathlookup.c \
	     pink.c \
	     proc.c \
	     process.c \
	     pathdecode.c \
	     pathmatch.c \
	     procmatch.c \
	     serializer.c \
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
	     syscall-system.c \
	     syscall.c \
	     config.c

#syd_run_SOURCES= \
#		 syd-run.c \
#		 serializer.c \
#		 serializer.h \
#		 xfunc.h \
#		 xfunc.c \
#		 daemon.h \
#		 daemon.c \
#		 dump.h \
#		 dump.c \
#		 bsd-compat.h \
#		 strlcpy.c \
#		 strlcat.c \
#		 util.h \
#		 util.c
#syd_run_LDFLAGS= \
#		 @SYDBOX_LIBTOOL_FLAGS@ \
#		 $(CODE_COVERAGE_LDFLAGS)
#syd_run_LDADD= \
#		 $(CODE_COVERAGE_LIBS) \
#		 $(libseccomp_LIBS)

# Experimental Rust.
# TODO: To be integrated into libsyd.
if WANT_SYDBOX_RS
syd_SOURCES+= lib.rs $(SYDBOX_RUST_LIB_STA)
endif

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

syd_errno_SOURCES= \
		   errno2name.c \
		   errno2name.h \
		   syd-errno.c
syd_errno_LDFLAGS=\
		  $(CODE_COVERAGE_LDFLAGS) \
		  $(libseccomp_LIBS)
syd_errno_LDADD=\
		@SYDBOX_LIBTOOL_FLAGS@ \
		$(CODE_COVERAGE_LIBS) \
		$(top_builddir)/syd/.libs/libsyd_@LIBSYD_PC_SLOT@.la

syd_format_SOURCES= \
		    syd-format.c
syd_format_LDFLAGS=\
		   $(CODE_COVERAGE_LDFLAGS) \
		   $(libseccomp_LIBS)
syd_format_LDADD=\
		 @SYDBOX_LIBTOOL_FLAGS@ \
		 $(CODE_COVERAGE_LIBS) \
		 $(libseccomp_LIBS) \
		 $(top_builddir)/syd/.libs/libsyd_@LIBSYD_PC_SLOT@.la

syd_sha1_SOURCES= \
		  errno2name.c \
		  errno2name.h \
		  syd-sha1.c
syd_sha1_LDFLAGS=\
		 $(CODE_COVERAGE_LDFLAGS) \
		 $(libseccomp_LIBS)
syd_sha1_LDADD=\
	       @SYDBOX_LIBTOOL_FLAGS@ \
	       $(CODE_COVERAGE_LIBS) \
	       $(libseccomp_LIBS) \
	       $(top_builddir)/syd/.libs/libsyd_@LIBSYD_PC_SLOT@.la

if WANT_PSYSCALL
# imported from psyscall
AM_CFLAGS+= $(pinktrace_CFLAGS)
noinst_HEADERS+= psyscall_syd.h
syd_SOURCES+= psyscall.c psyscall_syd.c
endif

syd_LDFLAGS= -pthread -lpthread -ldl \
	     $(CODE_COVERAGE_LDFLAGS) \
	      $(libseccomp_LIBS)
syd_LDADD= \
	   @SYDBOX_LIBTOOL_FLAGS@ \
	   $(CODE_COVERAGE_LIBS) \
	   $(libseccomp_LIBS) \
	   $(top_builddir)/syd/.libs/libsyd_@LIBSYD_PC_SLOT@.la

if WANT_SYDBOX_RS
syd_LDADD+= $(SYDBOX_RUST_LIB_STA)
endif

if ENABLE_STATIC
else
if WANT_SYDBOX_RS
syd_LDADD+= \
	    -L$(builddir)/sydbox_rs/$(SYDBOX_CARGO_RELEASE_TYPE)/deps \
	    -l$(SYDBOX_RUST_LIB_DYN)
endif
endif

if WANT_SYDBOX_RS
syd_LDADD+= -lsydbox_rs
endif
if WANT_GIT
syd_LDADD+= $(libgit2_LIBS)
endif
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

syd_dumpdir=$(libexecdir)/$(PACKAGE)/dump
bin_SCRIPTS= syd-shoebox

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

#syd-syscall.$(OBJEXT): $(BUILT_SOURCES)
#syd-dump.$(OBJEXT): $(BUILT_SOURCES)
noinst_HEADERS+= $(noinst_INCLUDE_SRCS)

.PHONY: parallel
parallel: .parallel ; @$(eval JOB_COUNT := $(shell sort -n $< | tail -n 1))
.parallel: FORCE ; @$(MAKE) --no-print-directory par 2>/dev/null >$@ || true
FORCE:

to_n = $(words $2) $(if $(filter-out $1,$(words x $2)),$(call to_n,$1,x $2))

PAR_COUNT :=
par: $(addprefix par-,$(call to_n,32))
par-%: ; @$(eval PAR_COUNT += x)@echo $(words $(PAR_COUNT)) && sleep 1 && false

# Convenience for users, more ugliness for meself...
# PATH=${syd_dumpdir} cave resolve ...
# to use syd-dump
install-data-hook:
	cd $(DESTDIR)$(syd_dumpdir) && \
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
	tee syd-splint.log
