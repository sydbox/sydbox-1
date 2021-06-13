#!/bin/sh
#
# Copyright (c) 2005 Junio C Hamano
#

test_description='Test the very basics part #1.

The rest of the test suite does not check the basic operation of git
plumbing commands to work very carefully.  Their job is to concentrate
on tricky features that caused bugs in the past to detect regression.

This test runs very basic features, like registering things in cache,
writing tree, etc.

Note that this test *deliberately* hard-codes many expected object
IDs.  When object ID computation changes, like in the previous case of
swapping compression and hashing order, the person who is making the
modification *should* take notice and update the test vectors here.
'

. ./test-lib.sh

try_local_xy () {
	local x="local" y="alsolocal" &&
	echo "$x $y"
}

# Check whether the shell supports the "local" keyword. "local" is not
# POSIX-standard, but it is very widely supported by POSIX-compliant
# shells, and we rely on it within Git's test framework.
#
# If your shell fails this test, the results of other tests may be
# unreliable. You may wish to report the problem to the Git mailing
# list <git@vger.kernel.org>, as it could cause us to reconsider
# relying on "local".
test_expect_success 'verify that the running shell supports "local"' '
	x="notlocal" &&
	y="alsonotlocal" &&
	echo "local alsolocal" >expected1 &&
	try_local_xy >actual1 &&
	test_cmp expected1 actual1 &&
	echo "notlocal alsonotlocal" >expected2 &&
	echo "$x $y" >actual2 &&
	test_cmp expected2 actual2
'

################################################################
# Test harness
test_expect_success 'success is reported like this' '
	:
'

_run_sub_test_lib_test_common () {
	neg="$1" name="$2" descr="$3" # stdin is the body of the test code
	shift 3
	mkdir "$name" &&
	(
		# Pretend we're not running under a test harness, whether we
		# are or not. The test-lib output depends on the setting of
		# this variable, so we need a stable setting under which to run
		# the sub-test.
		sane_unset HARNESS_ACTIVE &&
		cd "$name" &&
		write_script "$name.sh" "$TEST_SHELL_PATH" <<-EOF &&
		test_description='$descr (run in sub test-lib)

		This is run in a sub test-lib so that we do not get incorrect
		passing metrics
		'

		# Tell the framework that we are self-testing to make sure
		# it yields a stable result.
		SYDBOX_TEST_FRAMEWORK_SELFTEST=t &&

		# Point to the t/test-lib.sh, which isn't in ../ as usual
		. "\$TEST_DIRECTORY"/test-lib.sh
		EOF
		cat >>"$name.sh" &&
		chmod +x "$name.sh" &&
		export TEST_DIRECTORY &&
		TEST_OUTPUT_DIRECTORY=$(pwd) &&
		export TEST_OUTPUT_DIRECTORY &&
		sane_unset SYDBOX_TEST_FAIL_PREREQS &&
		if test -z "$neg"
		then
			./"$name.sh" "$@" >out 2>err
		else
			! ./"$name.sh" "$@" >out 2>err
		fi
	)
}

run_sub_test_lib_test () {
	_run_sub_test_lib_test_common '' "$@"
}

run_sub_test_lib_test_err () {
	_run_sub_test_lib_test_common '!' "$@"
}

check_sub_test_lib_test () {
	name="$1" # stdin is the expected output from the test
	(
		cd "$name" &&
		! test -s err &&
		sed -e 's/^> //' -e 's/Z$//' >expect &&
		test_cmp expect out
	)
}

check_sub_test_lib_test_err () {
	name="$1" # stdin is the expected output from the test
	# expected error output is in descriptor 3
	(
		cd "$name" &&
		sed -e 's/^> //' -e 's/Z$//' >expect.out &&
		test_cmp expect.out out &&
		sed -e 's/^> //' -e 's/Z$//' <&3 >expect.err &&
		test_cmp expect.err err
	)
}

test_expect_success 'pretend we have a fully passing test suite' '
	run_sub_test_lib_test full-pass "3 passing tests" <<-\EOF &&
	for i in 1 2 3
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test full-pass <<-\EOF
	> ok 1 - passing test #1
	> ok 2 - passing test #2
	> ok 3 - passing test #3
	> # passed all 3 test(s)
	> 1..3
	EOF
'

test_expect_success 'pretend we have a partially passing test suite' '
	run_sub_test_lib_test_err \
		partial-pass "2/3 tests passing" <<-\EOF &&
	test_expect_success "passing test #1" "true"
	test_expect_success "failing test #2" "false"
	test_expect_success "passing test #3" "true"
	test_done
	EOF
	check_sub_test_lib_test partial-pass <<-\EOF
	> ok 1 - passing test #1
	> not ok 2 - failing test #2
	#	false
	> ok 3 - passing test #3
	> # failed 1 among 3 test(s)
	> 1..3
	EOF
'

test_expect_success 'pretend we have a known breakage' '
	run_sub_test_lib_test failing-todo "A failing TODO test" <<-\EOF &&
	test_expect_success "passing test" "true"
	test_expect_failure "pretend we have a known breakage" "false"
	test_done
	EOF
	check_sub_test_lib_test failing-todo <<-\EOF
	> ok 1 - passing test
	> not ok 2 - pretend we have a known breakage # TODO known breakage
	> # still have 1 known breakage(s)
	> # passed all remaining 1 test(s)
	> 1..2
	EOF
'

test_expect_success 'pretend we have fixed a known breakage' '
	run_sub_test_lib_test passing-todo "A passing TODO test" <<-\EOF &&
	test_expect_failure "pretend we have fixed a known breakage" "true"
	test_done
	EOF
	check_sub_test_lib_test passing-todo <<-\EOF
	> ok 1 - pretend we have fixed a known breakage # TODO known breakage vanished
	> # 1 known breakage(s) vanished; please update test(s)
	> 1..1
	EOF
'

test_expect_success 'pretend we have fixed one of two known breakages (run in sub test-lib)' '
	run_sub_test_lib_test partially-passing-todos \
		"2 TODO tests, one passing" <<-\EOF &&
	test_expect_failure "pretend we have a known breakage" "false"
	test_expect_success "pretend we have a passing test" "true"
	test_expect_failure "pretend we have fixed another known breakage" "true"
	test_done
	EOF
	check_sub_test_lib_test partially-passing-todos <<-\EOF
	> not ok 1 - pretend we have a known breakage # TODO known breakage
	> ok 2 - pretend we have a passing test
	> ok 3 - pretend we have fixed another known breakage # TODO known breakage vanished
	> # 1 known breakage(s) vanished; please update test(s)
	> # still have 1 known breakage(s)
	> # passed all remaining 1 test(s)
	> 1..3
	EOF
'

test_expect_success 'pretend we have a pass, fail, and known breakage' '
	run_sub_test_lib_test_err \
		mixed-results1 "mixed results #1" <<-\EOF &&
	test_expect_success "passing test" "true"
	test_expect_success "failing test" "false"
	test_expect_failure "pretend we have a known breakage" "false"
	test_done
	EOF
	check_sub_test_lib_test mixed-results1 <<-\EOF
	> ok 1 - passing test
	> not ok 2 - failing test
	> #	false
	> not ok 3 - pretend we have a known breakage # TODO known breakage
	> # still have 1 known breakage(s)
	> # failed 1 among remaining 2 test(s)
	> 1..3
	EOF
'

test_expect_success 'pretend we have a mix of all possible results' '
	run_sub_test_lib_test_err \
		mixed-results2 "mixed results #2" <<-\EOF &&
	test_expect_success "passing test" "true"
	test_expect_success "passing test" "true"
	test_expect_success "passing test" "true"
	test_expect_success "passing test" "true"
	test_expect_success "failing test" "false"
	test_expect_success "failing test" "false"
	test_expect_success "failing test" "false"
	test_expect_failure "pretend we have a known breakage" "false"
	test_expect_failure "pretend we have a known breakage" "false"
	test_expect_failure "pretend we have fixed a known breakage" "true"
	test_done
	EOF
	check_sub_test_lib_test mixed-results2 <<-\EOF
	> ok 1 - passing test
	> ok 2 - passing test
	> ok 3 - passing test
	> ok 4 - passing test
	> not ok 5 - failing test
	> #	false
	> not ok 6 - failing test
	> #	false
	> not ok 7 - failing test
	> #	false
	> not ok 8 - pretend we have a known breakage # TODO known breakage
	> not ok 9 - pretend we have a known breakage # TODO known breakage
	> ok 10 - pretend we have fixed a known breakage # TODO known breakage vanished
	> # 1 known breakage(s) vanished; please update test(s)
	> # still have 2 known breakage(s)
	> # failed 3 among remaining 7 test(s)
	> 1..10
	EOF
'

test_expect_success 'test --verbose' '
	run_sub_test_lib_test_err \
		t1234-verbose "test verbose" --verbose <<-\EOF &&
	test_expect_success "passing test" true
	test_expect_success "test with output" "echo foo"
	test_expect_success "failing test" false
	test_done
	EOF
	mv t1234-verbose/out t1234-verbose/out+ &&
	grep -v "^Initialized empty" t1234-verbose/out+ >t1234-verbose/out &&
	check_sub_test_lib_test t1234-verbose <<-\EOF
	> expecting success of 1234.1 '\''passing test'\'': true
	> ok 1 - passing test
	> Z
	> expecting success of 1234.2 '\''test with output'\'': echo foo
	> foo
	> ok 2 - test with output
	> Z
	> expecting success of 1234.3 '\''failing test'\'': false
	> not ok 3 - failing test
	> #	false
	> Z
	> # failed 1 among 3 test(s)
	> 1..3
	EOF
'

test_expect_success 'test --verbose-only' '
	run_sub_test_lib_test_err \
		t2345-verbose-only-2 "test verbose-only=2" \
		--verbose-only=2 <<-\EOF &&
	test_expect_success "passing test" true
	test_expect_success "test with output" "echo foo"
	test_expect_success "failing test" false
	test_done
	EOF
	check_sub_test_lib_test t2345-verbose-only-2 <<-\EOF
	> ok 1 - passing test
	> Z
	> expecting success of 2345.2 '\''test with output'\'': echo foo
	> foo
	> ok 2 - test with output
	> Z
	> not ok 3 - failing test
	> #	false
	> # failed 1 among 3 test(s)
	> 1..3
	EOF
'

test_expect_success 'SYDBOX_SKIP_TESTS' '
	(
		SYDBOX_SKIP_TESTS="git.2" && export SYDBOX_SKIP_TESTS &&
		run_sub_test_lib_test git-skip-tests-basic \
			"SYDBOX_SKIP_TESTS" <<-\EOF &&
		for i in 1 2 3
		do
			test_expect_success "passing test #$i" "true"
		done
		test_done
		EOF
		check_sub_test_lib_test git-skip-tests-basic <<-\EOF
		> ok 1 - passing test #1
		> ok 2 # skip passing test #2 (SYDBOX_SKIP_TESTS)
		> ok 3 - passing test #3
		> # passed all 3 test(s)
		> 1..3
		EOF
	)
'

test_expect_success 'SYDBOX_SKIP_TESTS several tests' '
	(
		SYDBOX_SKIP_TESTS="git.2 git.5" && export SYDBOX_SKIP_TESTS &&
		run_sub_test_lib_test git-skip-tests-several \
			"SYDBOX_SKIP_TESTS several tests" <<-\EOF &&
		for i in 1 2 3 4 5 6
		do
			test_expect_success "passing test #$i" "true"
		done
		test_done
		EOF
		check_sub_test_lib_test git-skip-tests-several <<-\EOF
		> ok 1 - passing test #1
		> ok 2 # skip passing test #2 (SYDBOX_SKIP_TESTS)
		> ok 3 - passing test #3
		> ok 4 - passing test #4
		> ok 5 # skip passing test #5 (SYDBOX_SKIP_TESTS)
		> ok 6 - passing test #6
		> # passed all 6 test(s)
		> 1..6
		EOF
	)
'

test_expect_success 'SYDBOX_SKIP_TESTS sh pattern' '
	(
		SYDBOX_SKIP_TESTS="git.[2-5]" && export SYDBOX_SKIP_TESTS &&
		run_sub_test_lib_test git-skip-tests-sh-pattern \
			"SYDBOX_SKIP_TESTS sh pattern" <<-\EOF &&
		for i in 1 2 3 4 5 6
		do
			test_expect_success "passing test #$i" "true"
		done
		test_done
		EOF
		check_sub_test_lib_test git-skip-tests-sh-pattern <<-\EOF
		> ok 1 - passing test #1
		> ok 2 # skip passing test #2 (SYDBOX_SKIP_TESTS)
		> ok 3 # skip passing test #3 (SYDBOX_SKIP_TESTS)
		> ok 4 # skip passing test #4 (SYDBOX_SKIP_TESTS)
		> ok 5 # skip passing test #5 (SYDBOX_SKIP_TESTS)
		> ok 6 - passing test #6
		> # passed all 6 test(s)
		> 1..6
		EOF
	)
'

test_expect_success 'SYDBOX_SKIP_TESTS entire suite' '
	(
		SYDBOX_SKIP_TESTS="git" && export SYDBOX_SKIP_TESTS &&
		run_sub_test_lib_test git-skip-tests-entire-suite \
			"SYDBOX_SKIP_TESTS entire suite" <<-\EOF &&
		for i in 1 2 3
		do
			test_expect_success "passing test #$i" "true"
		done
		test_done
		EOF
		check_sub_test_lib_test git-skip-tests-entire-suite <<-\EOF
		> 1..0 # SKIP skip all tests in git
		EOF
	)
'

test_expect_success 'SYDBOX_SKIP_TESTS does not skip unmatched suite' '
	(
		SYDBOX_SKIP_TESTS="notgit" && export SYDBOX_SKIP_TESTS &&
		run_sub_test_lib_test git-skip-tests-unmatched-suite \
			"SYDBOX_SKIP_TESTS does not skip unmatched suite" <<-\EOF &&
		for i in 1 2 3
		do
			test_expect_success "passing test #$i" "true"
		done
		test_done
		EOF
		check_sub_test_lib_test git-skip-tests-unmatched-suite <<-\EOF
		> ok 1 - passing test #1
		> ok 2 - passing test #2
		> ok 3 - passing test #3
		> # passed all 3 test(s)
		> 1..3
		EOF
	)
'

test_expect_success '--run basic' '
	run_sub_test_lib_test run-basic \
		"--run basic" --run="1,3,5" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-basic <<-\EOF
	> ok 1 - passing test #1
	> ok 2 # skip passing test #2 (--run)
	> ok 3 - passing test #3
	> ok 4 # skip passing test #4 (--run)
	> ok 5 - passing test #5
	> ok 6 # skip passing test #6 (--run)
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run with a range' '
	run_sub_test_lib_test run-range \
		"--run with a range" --run="1-3" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-range <<-\EOF
	> ok 1 - passing test #1
	> ok 2 - passing test #2
	> ok 3 - passing test #3
	> ok 4 # skip passing test #4 (--run)
	> ok 5 # skip passing test #5 (--run)
	> ok 6 # skip passing test #6 (--run)
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run with two ranges' '
	run_sub_test_lib_test run-two-ranges \
		"--run with two ranges" --run="1-2,5-6" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-two-ranges <<-\EOF
	> ok 1 - passing test #1
	> ok 2 - passing test #2
	> ok 3 # skip passing test #3 (--run)
	> ok 4 # skip passing test #4 (--run)
	> ok 5 - passing test #5
	> ok 6 - passing test #6
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run with a left open range' '
	run_sub_test_lib_test run-left-open-range \
		"--run with a left open range" --run="-3" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-left-open-range <<-\EOF
	> ok 1 - passing test #1
	> ok 2 - passing test #2
	> ok 3 - passing test #3
	> ok 4 # skip passing test #4 (--run)
	> ok 5 # skip passing test #5 (--run)
	> ok 6 # skip passing test #6 (--run)
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run with a right open range' '
	run_sub_test_lib_test run-right-open-range \
		"--run with a right open range" --run="4-" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-right-open-range <<-\EOF
	> ok 1 # skip passing test #1 (--run)
	> ok 2 # skip passing test #2 (--run)
	> ok 3 # skip passing test #3 (--run)
	> ok 4 - passing test #4
	> ok 5 - passing test #5
	> ok 6 - passing test #6
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run with basic negation' '
	run_sub_test_lib_test run-basic-neg \
		"--run with basic negation" --run="!3" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-basic-neg <<-\EOF
	> ok 1 - passing test #1
	> ok 2 - passing test #2
	> ok 3 # skip passing test #3 (--run)
	> ok 4 - passing test #4
	> ok 5 - passing test #5
	> ok 6 - passing test #6
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run with two negations' '
	run_sub_test_lib_test run-two-neg \
		"--run with two negations" --run="!3,!6" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-two-neg <<-\EOF
	> ok 1 - passing test #1
	> ok 2 - passing test #2
	> ok 3 # skip passing test #3 (--run)
	> ok 4 - passing test #4
	> ok 5 - passing test #5
	> ok 6 # skip passing test #6 (--run)
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run a range and negation' '
	run_sub_test_lib_test run-range-and-neg \
		"--run a range and negation" --run="-4,!2" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-range-and-neg <<-\EOF
	> ok 1 - passing test #1
	> ok 2 # skip passing test #2 (--run)
	> ok 3 - passing test #3
	> ok 4 - passing test #4
	> ok 5 # skip passing test #5 (--run)
	> ok 6 # skip passing test #6 (--run)
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run range negation' '
	run_sub_test_lib_test run-range-neg \
		"--run range negation" --run="!1-3" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-range-neg <<-\EOF
	> ok 1 # skip passing test #1 (--run)
	> ok 2 # skip passing test #2 (--run)
	> ok 3 # skip passing test #3 (--run)
	> ok 4 - passing test #4
	> ok 5 - passing test #5
	> ok 6 - passing test #6
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run include, exclude and include' '
	run_sub_test_lib_test run-inc-neg-inc \
		"--run include, exclude and include" \
		--run="1-5,!1-3,2" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-inc-neg-inc <<-\EOF
	> ok 1 # skip passing test #1 (--run)
	> ok 2 - passing test #2
	> ok 3 # skip passing test #3 (--run)
	> ok 4 - passing test #4
	> ok 5 - passing test #5
	> ok 6 # skip passing test #6 (--run)
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run include, exclude and include, comma separated' '
	run_sub_test_lib_test run-inc-neg-inc-comma \
		"--run include, exclude and include, comma separated" \
		--run=1-5,!1-3,2 <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-inc-neg-inc-comma <<-\EOF
	> ok 1 # skip passing test #1 (--run)
	> ok 2 - passing test #2
	> ok 3 # skip passing test #3 (--run)
	> ok 4 - passing test #4
	> ok 5 - passing test #5
	> ok 6 # skip passing test #6 (--run)
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run exclude and include' '
	run_sub_test_lib_test run-neg-inc \
		"--run exclude and include" \
		--run="!3-,5" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-neg-inc <<-\EOF
	> ok 1 - passing test #1
	> ok 2 - passing test #2
	> ok 3 # skip passing test #3 (--run)
	> ok 4 # skip passing test #4 (--run)
	> ok 5 - passing test #5
	> ok 6 # skip passing test #6 (--run)
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run empty selectors' '
	run_sub_test_lib_test run-empty-sel \
		"--run empty selectors" \
		--run="1,,3,,,5" <<-\EOF &&
	for i in 1 2 3 4 5 6
	do
		test_expect_success "passing test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-empty-sel <<-\EOF
	> ok 1 - passing test #1
	> ok 2 # skip passing test #2 (--run)
	> ok 3 - passing test #3
	> ok 4 # skip passing test #4 (--run)
	> ok 5 - passing test #5
	> ok 6 # skip passing test #6 (--run)
	> # passed all 6 test(s)
	> 1..6
	EOF
'

test_expect_success '--run substring selector' '
	run_sub_test_lib_test run-substring-selector \
		"--run empty selectors" \
		--run="relevant" <<-\EOF &&
	test_expect_success "relevant test" "true"
	for i in 1 2 3 4 5 6
	do
		test_expect_success "other test #$i" "true"
	done
	test_done
	EOF
	check_sub_test_lib_test run-substring-selector <<-\EOF
	> ok 1 - relevant test
	> ok 2 # skip other test #1 (--run)
	> ok 3 # skip other test #2 (--run)
	> ok 4 # skip other test #3 (--run)
	> ok 5 # skip other test #4 (--run)
	> ok 6 # skip other test #5 (--run)
	> ok 7 # skip other test #6 (--run)
	> # passed all 7 test(s)
	> 1..7
	EOF
'

test_expect_success '--run keyword selection' '
	run_sub_test_lib_test_err run-inv-range-start \
		"--run invalid range start" \
		--run="a-5" <<-\EOF &&
	test_expect_success "passing test #1" "true"
	test_done
	EOF
	check_sub_test_lib_test_err run-inv-range-start \
		<<-\EOF_OUT 3<<-EOF_ERR
	> FATAL: Unexpected exit with code 1
	EOF_OUT
	> error: --run: invalid non-numeric in range start: ${SQ}a-5${SQ}
	EOF_ERR
'

test_expect_success '--run invalid range end' '
	run_sub_test_lib_test_err run-inv-range-end \
		"--run invalid range end" \
		--run="1-z" <<-\EOF &&
	test_expect_success "passing test #1" "true"
	test_done
	EOF
	check_sub_test_lib_test_err run-inv-range-end \
		<<-\EOF_OUT 3<<-EOF_ERR
	> FATAL: Unexpected exit with code 1
	EOF_OUT
	> error: --run: invalid non-numeric in range end: ${SQ}1-z${SQ}
	EOF_ERR
'

test_expect_success 'tests respect prerequisites' '
	run_sub_test_lib_test prereqs "tests respect prereqs" <<-\EOF &&

	test_set_prereq HAVEIT
	test_expect_success HAVEIT "prereq is satisfied" "true"
	test_expect_success "have_prereq works" "
		test_have_prereq HAVEIT
	"
	test_expect_success DONTHAVEIT "prereq not satisfied" "false"

	test_set_prereq HAVETHIS
	test_expect_success HAVETHIS,HAVEIT "multiple prereqs" "true"
	test_expect_success HAVEIT,DONTHAVEIT "mixed prereqs (yes,no)" "false"
	test_expect_success DONTHAVEIT,HAVEIT "mixed prereqs (no,yes)" "false"

	test_done
	EOF

	check_sub_test_lib_test prereqs <<-\EOF
	ok 1 - prereq is satisfied
	ok 2 - have_prereq works
	ok 3 # skip prereq not satisfied (missing DONTHAVEIT)
	ok 4 - multiple prereqs
	ok 5 # skip mixed prereqs (yes,no) (missing DONTHAVEIT of HAVEIT,DONTHAVEIT)
	ok 6 # skip mixed prereqs (no,yes) (missing DONTHAVEIT of DONTHAVEIT,HAVEIT)
	# passed all 6 test(s)
	1..6
	EOF
'

test_expect_success 'tests respect lazy prerequisites' '
	run_sub_test_lib_test lazy-prereqs "respect lazy prereqs" <<-\EOF &&

	test_lazy_prereq LAZY_TRUE true
	test_expect_success LAZY_TRUE "lazy prereq is satisifed" "true"
	test_expect_success !LAZY_TRUE "negative lazy prereq" "false"

	test_lazy_prereq LAZY_FALSE false
	test_expect_success LAZY_FALSE "lazy prereq not satisfied" "false"
	test_expect_success !LAZY_FALSE "negative false prereq" "true"

	test_done
	EOF

	check_sub_test_lib_test lazy-prereqs <<-\EOF
	ok 1 - lazy prereq is satisifed
	ok 2 # skip negative lazy prereq (missing !LAZY_TRUE)
	ok 3 # skip lazy prereq not satisfied (missing LAZY_FALSE)
	ok 4 - negative false prereq
	# passed all 4 test(s)
	1..4
	EOF
'

test_expect_success 'nested lazy prerequisites' '
	run_sub_test_lib_test nested-lazy "nested lazy prereqs" <<-\EOF &&

	test_lazy_prereq NESTED_INNER "
		>inner &&
		rm -f outer
	"
	test_lazy_prereq NESTED_PREREQ "
		>outer &&
		test_have_prereq NESTED_INNER &&
		echo can create new file in cwd >file &&
		test_path_is_file outer &&
		test_path_is_missing inner
	"
	test_expect_success NESTED_PREREQ "evaluate nested prereq" "true"

	test_done
	EOF

	check_sub_test_lib_test nested-lazy <<-\EOF
	ok 1 - evaluate nested prereq
	# passed all 1 test(s)
	1..1
	EOF
'

test_expect_success 'lazy prereqs do not turn off tracing' '
	run_sub_test_lib_test lazy-prereq-and-tracing \
		"lazy prereqs and -x" -v -x <<-\EOF &&
	test_lazy_prereq LAZY true

	test_expect_success lazy "test_have_prereq LAZY && echo trace"

	test_done
	EOF

	grep "echo trace" lazy-prereq-and-tracing/err
'

test_expect_success FIXME 'tests clean up after themselves' '
	run_sub_test_lib_test cleanup "test with cleanup" <<-\EOF &&
	clean=no
	test_expect_success "do cleanup" "
		test_when_finished clean=yes
	"
	test_expect_success "cleanup happened" "
		test $clean = yes
	"
	test_done
	EOF

	check_sub_test_lib_test cleanup <<-\EOF
	ok 1 - do cleanup
	ok 2 - cleanup happened
	# passed all 2 test(s)
	1..2
	EOF
'

test_expect_success FIXME 'tests clean up even on failures' '
	run_sub_test_lib_test_err \
		failing-cleanup "Failing tests with cleanup commands" <<-\EOF &&
	test_expect_success "tests clean up even after a failure" "
		touch clean-after-failure &&
		test_when_finished rm clean-after-failure &&
		(exit 1)
	"
	test_expect_success "failure to clean up causes the test to fail" "
		test_when_finished \"(exit 2)\"
	"
	test_done
	EOF
	check_sub_test_lib_test failing-cleanup <<-\EOF
	> not ok 1 - tests clean up even after a failure
	> #	Z
	> #	touch clean-after-failure &&
	> #	test_when_finished rm clean-after-failure &&
	> #	(exit 1)
	> #	Z
	> not ok 2 - failure to clean up causes the test to fail
	> #	Z
	> #	test_when_finished "(exit 2)"
	> #	Z
	> # failed 2 among 2 test(s)
	> 1..2
	EOF
'

test_expect_success FIXME 'test_atexit is run' '
	run_sub_test_lib_test_err \
		atexit-cleanup "Run atexit commands" -i <<-\EOF &&
	test_expect_success "tests clean up even after a failure" "
		> ../../clean-atexit &&
		test_atexit rm ../../clean-atexit &&
		> ../../also-clean-atexit &&
		test_atexit rm ../../also-clean-atexit &&
		> ../../dont-clean-atexit &&
		(exit 1)
	"
	test_done
	EOF
	test_path_is_file dont-clean-atexit &&
	test_path_is_missing clean-atexit &&
	test_path_is_missing also-clean-atexit
'


#test_set_prereq HAVEIT
#haveit=no
#test_expect_success HAVEIT 'test runs if prerequisite is satisfied' '
#	test_have_prereq HAVEIT &&
#	haveit=yes
#'
#donthaveit=yes
#test_expect_success DONTHAVEIT 'unmet prerequisite causes test to be skipped' '
#	donthaveit=no
#'
#if test $haveit$donthaveit != yesyes
#then
#	say "bug in test framework: prerequisite tags do not work reliably"
#	exit 1
#fi
#
#test_set_prereq HAVETHIS
#haveit=no
#test_expect_success HAVETHIS,HAVEIT 'test runs if prerequisites are satisfied' '
#	test_have_prereq HAVEIT &&
#	test_have_prereq HAVETHIS &&
#	haveit=yes
#'
#donthaveit=yes
#test_expect_success HAVEIT,DONTHAVEIT 'unmet prerequisites causes test to be skipped' '
#	donthaveit=no
#'
#donthaveiteither=yes
#test_expect_success DONTHAVEIT,HAVEIT 'unmet prerequisites causes test to be skipped' '
#	donthaveiteither=no
#'
#if test $haveit$donthaveit$donthaveiteither != yesyesyes
#then
#	say "bug in test framework: multiple prerequisite tags do not work reliably"
#	exit 1
#fi
#
#test_lazy_prereq LAZY_TRUE true
#havetrue=no
#test_expect_success LAZY_TRUE 'test runs if lazy prereq is satisfied' '
#	havetrue=yes
#'
#donthavetrue=yes
#test_expect_success !LAZY_TRUE 'missing lazy prereqs skip tests' '
#	donthavetrue=no
#'
#
#if test "$havetrue$donthavetrue" != yesyes
#then
#    say 'bug in test framework: lazy prerequisites do not work'
#    exit 1
#fi
#
#test_lazy_prereq LAZY_FALSE false
#nothavefalse=no
#test_expect_success !LAZY_FALSE 'negative lazy prereqs checked' '
#nothavefalse=yes
#'
#havefalse=yes
#test_expect_success LAZY_FALSE 'missing negative lazy prereqs will skip' '
#havefalse=no
#'
#
#if test "$nothavefalse$havefalse" != yesyes
#then
#    say 'bug in test framework: negative lazy prerequisites do not work'
#    exit 1
#fi
#
#clean=no
#test_expect_success 'tests clean up after themselves' '
#test_when_finished clean=yes
#'
#
#if test $clean != yes
#then
#    say "bug in test framework: basic cleanup command does not work reliably"
#    exit 1
#fi
#
#test_expect_success 'tests clean up even on failures' "
#test_must_fail run_sub_test_lib_test \
#    failing-cleanup 'Failing tests with cleanup commands' <<-\\EOF &&
#    test_expect_success 'tests clean up even after a failure' '
#    touch clean-after-failure &&
#        test_when_finished rm clean-after-failure &&
#        (exit 1)
#            '
#            test_expect_success 'failure to clean up causes the test to fail' '
#            test_when_finished \"(exit 2)\"
#            '
#            test_done
#            EOF
#            check_sub_test_lib_test failing-cleanup <<-\\EOF
#            > not ok 1 - tests clean up even after a failure
#            > #	Z
#            > #	touch clean-after-failure &&
#                > #	test_when_finished rm clean-after-failure &&
#                > #	(exit 1)
#                            > #	Z
#                            > not ok 2 - failure to clean up causes the test to fail
#                            > #	Z
#                            > #	test_when_finished \"(exit 2)\"
#                            > #	Z
#                            > # failed 2 among 2 test(s)
#                            > 1..2
#                            EOF
#                            "

test_done
