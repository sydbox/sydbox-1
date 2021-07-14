#H=$(top_builddir)/misc/syd-hilite
AM_MAKEFLAGS= --no-print-directory
CLEANFILES= \
	    *~
DEFS+= \
       -DIN_LIBSYD=1

BUILT_SOURCES= libsyd.ld
libsyd.ld: libsyd.ld.in
	sed -e 's/@SYD_PC_SLOT@/libsyd_@LIBSYD_PC_SLOT@/' \
		< $< \
		> $@ || rm -f "$@"

BUILT_SOURCES+= jobs
.PHONY: jobs
jobs: | parallel

BUILT_SOURCES+= build
.PHONY: build
build: jobs
	@echo >&2 "[0;1;31;91msydb☮x: Make is running $(JOB_COUNT) jobs.[0m"
	$(H) make $(AM_MAKEFLAGS) $(MFLAGS) libsyd_@LIBSYD_PC_SLOT@.la

.PHONY: parallel
parallel: .parallel ; @$(eval JOB_COUNT := $(shell sort -n $< | tail -n 1))
.parallel: FORCE ; @$(MAKE) --no-print-directory par 2>/dev/null >$@ || true
FORCE:

to_n = $(words $2) $(if $(filter-out $1,$(words x $2)),$(call to_n,$1,x $2))

PAR_COUNT :=
par: $(addprefix par-,$(call to_n,32))
par-%: ; @$(eval PAR_COUNT += x)@echo $(words $(PAR_COUNT)) && sleep 1 && false

lib_LTLIBRARIES = libsyd_@LIBSYD_PC_SLOT@.la
dist_man3_MANS= \
	       doc/man/man3/syd_version.3

libsyd_SRCS = \
	      $(srcdir)/syd/compiler.h \
	      $(srcdir)/syd/syd.h \
	      about.c \
	      debug.c \
	      exec.c \
	      name.c \
	      strlcat.c \
	      file.c \
	      pidfd.c \
	      proc.c \
	      strlcpy.c \
	      state.c \
	      utf8.c \
	      time.c \
	      unshare.c \
	      extfs.c \
	      sha1.c \
	      xxhash.c \
	      tao.c \
	      tarot.c

# SHA1DC
libsyd_SRCS+= \
	      $(srcdir)/sha1dc/lib/sha1.h \
	      $(srcdir)/sha1dc/lib/sha1.c \
	      $(srcdir)/sha1dc/lib/ubc_check.h \
	      $(srcdir)/sha1dc/lib/ubc_check.c \
	      $(srcdir)/syd/sha1dc_syd.h \
	      $(srcdir)/syd/hex.h \
	      sha1dc_syd.c \
	      hex.c

# Robinhood Hash.
# Implemented by Vitaly "_Vi" Shukela in 2017. License = MIT or Apache 2.0
libsyd_SRCS += \
	      $(srcdir)/syd/robinhood_hash.h

# sc_map: simple, efficient hash table
# Copyright 2021 Ozan Tezcan
# BSD-3-Clause.
libsyd_SRCS += \
	$(srcdir)/src/sc_map.h \
	sc_map.c

# Imported from util-linux' unshare:
libsyd_SRCS += \
	      $(srcdir)/syd/all-io.h \
	      c.h \
	      pathnames.h \
	      fileutils.h \
	      fileutils.c \
	      procutils.h \
	      procutils.c \
	      statfs_magic.h \
	      caputils.h \
	      caputils.c
libsyd_@LIBSYD_PC_SLOT@_la_SOURCES= $(libsyd_SRCS)
libsyd_@LIBSYD_PC_SLOT@_la_CFLAGS= \
	$(libseccomp_CFLAGS) \
	-I$(srcdir) \
	-I$(top_srcdir)/xxHash
libsyd_@LIBSYD_PC_SLOT@_la_LDFLAGS= \
	-Wl,--version-script=$(srcdir)/libsyd.ld \
	$(COVERAGE_LDFLAGS) \
	$(libseccomp_LIBS)
libsyd_@LIBSYD_PC_SLOT@_la_LIBS= \
	$(COVERAGE_LIBS) \
	$(libseccomp_LIBS)

libsyd_includedir = $(includedir)/syd-$(LIBSYD_PC_SLOT)/syd
libsyd_include_HEADERS= \
			syd/confname.h \
			syd/sha1dc_syd.h \
			syd/hex.h \
			syd/syd.h

noinst_HEADERS= \
		seatest/src/seatest.h \
		syd/compiler.h \
		check.h \
		macro.h
syd_check_SOURCES= \
		   seatest/src/seatest.c \
		   check.c \
		   file-TEST.c \
		   proc-TEST.c \
		   sha1-TEST.c \
		   $(libsyd_SRCS)

syd_check_CFLAGS= \
		  -I$(srcdir) \
		  -I$(srcdir)/seatest/src \
		  -I$(top_srcdir)/xxHash
		  $(libseccomp_CFLAGS)
syd_check_LDFLAGS= \
		   -lrt -lm $(libseccomp_LIBS) \
		   $(COVERAGE_LDFLAGS) \
		   $(libseccomp_LIBS)
syd_check_LDADD= \
		 $(COVERAGE_LIBS) \
		 $(libseccomp_LIBS) \
		 $(builddir)/.libs/libsyd_@LIBSYD_PC_SLOT@.la

if ENABLE_STATIC
else
syd_check_LDDD= \
		  -L$(builddir)/.libs \
		  -llibsyd_@LIBSYD_PC_SLOT@
endif

syd_checkdir=$(libexecdir)/$(PACKAGE)/t/sha1_samples
syd_check_DATA=\
	       sha1_samples/200d69c3555389e536b57d7f9f95eb1eb5e377a1 \
	       sha1_samples/2d34e230014f5dbd4e9b2344d23bf3fce94fae38 \
	       sha1_samples/48edf6bfd0c00f87d86fd23d67d0351495e106b1 \
	       sha1_samples/50865daa00c7f3f238c774ea13a2f25cbc8ed27a \
	       sha1_samples/5c828d244d745a59ed85bd472bdc6bb4d6ecea89 \
	       sha1_samples/89a91d5421249fbd8cb448ebf5d2b42798e3126c \
	       sha1_samples/8dea5576cecc69b043c937e87ce3d035dfbaf971 \
	       sha1_samples/953edfc0217c405b17f647dbd749d4b09ce8aa49 \
	       sha1_samples/a3e2cc1f7e2e2659b8080a6ec3534c322551f834 \
	       sha1_samples/c325d19b0aa730530c849805a4ce5a5da5bb25d1 \
	       sha1_samples/c8b8d277235110eea01a836b6e9ab9e66d48c90d \
	       sha1_samples/e2a01a5166873953413b502c2fd75620b751e4e8

check_PROGRAMS= check-pause syd-check
TESTS= syd-check

.PHONY: check-build
check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_PROGRAMS}
