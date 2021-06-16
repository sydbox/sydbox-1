AM_MAKEFLAGS= --no-print-directory
SUBDIRS= bin-wrappers test-bin test-data valgrind .
CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov \
	    *.log \
	    *.trs
EXTRA_DIST=
check_SCRIPTS=
BUILT_SOURCES=

@CODE_COVERAGE_RULES@

check_SCRIPTS+= \
		test-lib-functions.sh \
		test-lib-sydbox.sh \
		test-runner.sh

test-lib.sh: test-lib.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@TOP_BUILDDIR@:$(abs_top_builddir):g" \
		-e "s:@SYDBOX_HAVE_NEWFSTATAT@:$(HAVE_NEWFSTATAT):g" \
		-e 's:@BINDIR@:$(bindir):g' \
		-e 's:@LIBEXECDIR@:$(libexecdir):g' \
		$< > $@
CLEANFILES+= test-lib.sh
EXTRA_DIST+= test-lib.sh.in
nodist_check_SCRIPTS= test-lib.sh
nodist_syd_SCRIPTS= $(nodist_check_SCRIPTS)

AM_TESTSUITE_SUMMARY_HEADER = ' for $(PACKAGE_STRING)'
TEST_EXTENSIONS= .sh
SH_LOG_COMPILER= $(srcdir)/test-runner.sh
TEST_LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) \
		  $(top_srcdir)/build-aux/tap-driver.sh
SYDBOX_CHECK_OPTIONS=--tee --verbose $(TEST_OPTIONS)
export SYDBOX_CHECK_OPTIONS
TESTS= \
	t0000-basic.sh \
	t0001-path-wildmatch.sh \
	t0002-path-realpath.sh \
	t0003-core-basic.sh \
	t0004-core-seccomp.sh \
	t0005-core-exit.sh \
	t0006-core-abort.sh \
	t0007-core-magic.sh \
	t0008-core-open-read.sh \
	t0009-core-exec.sh \
	t0010-core-chdir.sh \
	t0011-net-netmatch.sh \
	t0012-net-sandbox.sh
check_SCRIPTS+= $(TESTS)

syddir=$(libexecdir)/$(PACKAGE)/t
syd_SCRIPTS= aggregate-results.sh check-non-portable-shell.pl chainlint.sed $(check_SCRIPTS)
syd_DATA= README
EXTRA_DIST+= $(syd_SCRIPTS) $(syd_DATA)

bin_SCRIPTS= sydtest
EXTRA_DIST+= sydtest.sh.in
sydtest: sydtest.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@SYDBOX_MAKE@:$(MAKE):g" \
		-e "s:@SYDBOX_TEST_DIRECTORY@:$(syddir):g" \
		-e "s:@SYDBOX_TEST_DEFOPTS@:$(SYDBOX_TEST_DEFOPTS):g" \
		$< > $@
	$(AM_V_at)chmod +x $@

EXTRA_DIST+= Makefile.test
install-data-local:
	cp Makefile.test $(DESTDIR)$(syddir)/Makefile

.PHONY: check-build
check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_SCRIPTS}
	${MAKE} ${AM_MAKEFLAGS} -C test-bin check-build
