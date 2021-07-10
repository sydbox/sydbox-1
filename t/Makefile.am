AM_MAKEFLAGS= --no-print-directory
SUBDIRS= bin-wrappers bin test-data valgrind .
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
		-e 's:@API_VERSION@:$(SYDBOX_API_VERSION):g' \
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
	t00-basic.sh \
	t01-path-wildmatch.sh \
	t02-path-realpath.sh \
	t03-core-basic.sh \
	t04-core-seccomp.sh \
	t05-core-exit.sh \
	t06-core-abort.sh \
	t07-core-magic.sh \
	t08-core-open-read.sh \
	t09-core-exec.sh \
	t10-core-chdir.sh \
	t11-net-netmatch.sh \
	t12-exec-sandbox.sh \
	t13-net-sandbox.sh \
	t14-sys-fuzzer.sh
check_SCRIPTS+= $(TESTS)

syddir=$(libexecdir)/$(PACKAGE)/t-$(SYDBOX_API_VERSION)
syd_SCRIPTS= aggregate-results.sh check-non-portable-shell.pl chainlint.sed $(check_SCRIPTS)
syd_DATA= README
EXTRA_DIST+= $(syd_SCRIPTS) $(syd_DATA)

bin_SCRIPTS= syd-test
EXTRA_DIST+= syd-test.sh.in
syd-test: syd-test.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@SYDBOX_MAKE@:$(MAKE):g" \
		-e "s:@SYDBOX_TEST_DIRECTORY@:$(syddir):g" \
		-e "s:@SYDBOX_TEST_DEFOPTS@:$(SYDBOX_TEST_DEFOPTS):g" \
		$< > $@
	$(AM_V_at)chmod +x $@

EXTRA_DIST+= Makefile.test
install-data-local:
	$(MKDIR_P) -m755 $(DESTDIR)$(syddir)
	cp Makefile.test $(DESTDIR)$(syddir)/Makefile

.PHONY: check-build
check-build:
	${MAKE} ${AM_MAKEFLAGS} ${check_SCRIPTS}
	${MAKE} ${AM_MAKEFLAGS} -C bin check-build
