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

check_SCRIPTS+= \
		test-lib-functions.sh \
		test-lib-sydbox.sh \
		test-runner.sh

test-lib.sh: test-lib.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@TOP_BUILDDIR@:$(abs_top_builddir):g" \
		-e "s:@PTRACE_SEIZE@:$(PINKTRACE_HAVE_SEIZE):g" \
		-e "s:@PTRACE_SECCOMP@:$(SYDBOX_HAVE_SECCOMP):g" \
		-e "s:@PINK_HAVE_IPV6@:$(PINK_HAVE_IPV6):g" \
		$< > $@
CLEANFILES+= test-lib.sh
EXTRA_DIST+= test-lib.sh.in
nodist_check_SCRIPTS= test-lib.sh
nodist_syd_SCRIPTS= $(nodist_check_SCRIPTS)

TEST_EXTENSIONS= .sh
SH_LOG_COMPILER= $(srcdir)/test-runner.sh
TESTS= \
       t0000-basic.sh \
       t0001-path-wildmatch.sh \
       t0002-path-realpath.sh \
       t0003-core-basic.sh \
       t0004-core-chdir.sh
check_SCRIPTS+= $(TESTS)

syddir=$(libexecdir)/$(PACKAGE)/t
syd_SCRIPTS= aggregate-results.sh check-non-portable-shell.pl $(check_SCRIPTS)
syd_DATA= README
EXTRA_DIST+= $(syd_SCRIPTS) $(syd_DATA)

bin_SCRIPTS= sydtest
EXTRA_DIST+= sydtest.sh.in
sydtest: sydtest.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) \
		-e "s:@SYDBOX_MAKE@:$(MAKE):g" \
		-e "s:@SYDBOX_TEST_DIRECTORY@:$(syddir):g" \
		$< > $@
	$(AM_V_at)chmod +x $@

EXTRA_DIST+= Makefile.test
install-data-local:
	cp Makefile.test $(DESTDIR)$(syddir)/Makefile
