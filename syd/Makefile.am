AM_MAKEFLAGS= --no-print-directory
HILITE=$(top_builddir)/misc/syd-hilite
CLEANFILES= \
	    *~
DEFS+= \
       -DIN_LIBSYD=1 \
       -DGITVERSION=\"$(GITVERSION)\"

BUILT_SOURCES= jobs
.PHONY: jobs
jobs: | parallel

BUILT_SOURCES+= build
.PHONY: build
build: jobs
	@echo >&2 "[0;1;31;91msydb☮x: Make is running $(JOB_COUNT) jobs.[0m"
	$(HILITE) $(MAKE) $(AM_MAKEFLAGS) $(MFLAGS) libsyd_@LIBSYD_PC_SLOT@.la

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

libsyd_@LIBSYD_PC_SLOT@_la_SOURCES = \
	about.c \
	debug.c \
	exec.c \
	name.c \
	strlcat.c \
	strlcpy.c \
	file.c \
	pidfd.c \
	proc.c \
	state.c \
	time.c \
	unshare.c

# Robinhood Hash.
# Implemented by Vitaly "_Vi" Shukela in 2017. License = MIT or Apache 2.0
libsyd_@LIBSYD_PC_SLOT@_la_SOURCES += \
	robinhood_hash.h

# sc_map: simple, efficient hash table
# Copyright 2021 Ozan Tezcan
# BSD-3-Clause.
libsyd_@LIBSYD_PC_SLOT@_la_SOURCES += \
	sc_map.h \
	sc_map.c

# Imported from util-linux' unshare:
libsyd_@LIBSYD_PC_SLOT@_la_SOURCES += \
	all-io.h \
	c.h \
	pathnames.h \
	fileutils.h \
	fileutils.c \
	procutils.h \
	procutils.c \
	statfs_magic.h \
	caputils.h \
	caputils.c
libsyd_@LIBSYD_PC_SLOT@_la_CFLAGS= \
	$(libseccomp_CFLAGS) \
	$(SYDBOX_CFLAGS)
libsyd_@LIBSYD_PC_SLOT@_la_LDFLAGS= \
	-Wl,--version-script=$(srcdir)/libsyd.ld \
	$(SYDBOX_LDFLAGS)
libsyd_@LIBSYD_PC_SLOT@_la_LIBS= \
	$(libseccomp_LIBS)

libsyd_includedir = $(includedir)/syd-$(LIBSYD_PC_SLOT)/syd
libsyd_include_HEADERS= \
			confname.h \
			syd.h

noinst_HEADERS= seatest.h check.h compiler.h
syd_check_SOURCES= seatest.c check.c file-TEST.c proc-TEST.c
syd_check_CFLAGS= -I$(srcdir)
syd_check_LDFLAGS= -lrt -lm \
		   $(builddir)/libsyd_@LIBSYD_PC_SLOT@.la \
		   -L$(builddir)/.libs \
		   -lsyd_@LIBSYD_PC_SLOT@

check_PROGRAMS= check-pause syd-check
TESTS= syd-check

.PHONY: check-build
check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_PROGRAMS}
