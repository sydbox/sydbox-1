#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the termination return code of sydbox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS -mcore/sandbox/read:allow"
export SYDBOX_TEST_OPTIONS

# These termination exit code checks fails on buildhost only when run via CI.
# The tests pass if you ssh into the buildhost and run the tests manually.
# The NOT_ON_BUILD_HOST prerequisite checks for the job id so we can still
# manually run these tests on the build host.
test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated' '
    test_expect_code 130 sydbox -- syd-abort 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort 15 # SIGTERM
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated (STATIC)' '
    test_expect_code 130 sydbox -- syd-abort-static 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-static 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-static 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-static 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-static 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-static 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-static 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-static 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-static 15 # SIGTERM
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated (FORK)' '
    test_expect_code 130 sydbox -- syd-abort-fork 64 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-fork 64 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-fork 64 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-fork 64 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-fork 64 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-fork 64 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-fork 64 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-fork 64 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-fork 64 15 # SIGTERM
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated (STATIC|FORK)' '
    test_expect_code 130 sydbox -- syd-abort-fork-static 64 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-fork-static 64 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-fork-static 64 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-fork-static 64 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-fork-static 64 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-fork-static 64 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-fork-static 64 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-fork-static 64 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-fork-static 64 15 # SIGTERM
'

test_expect_success 'return 128 + $SIGNUM if tracee is terminated (PTHREAD)' '
    test_expect_code 130 sydbox -- syd-abort-pthread 8 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-pthread 8 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-pthread 8 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-pthread 8 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-pthread 8 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-pthread 8 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-pthread 8 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-pthread 8 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-pthread 8 15 # SIGTERM
'

test_expect_success 'return 128 + $SIGNUM if tracee is terminated (STATIC|PTHREAD)' '
    test_expect_code 130 sydbox -- syd-abort-pthread-static 8 2 && # SIGINT
    test_expect_code 131 sydbox -- syd-abort-pthread-static 8 3 && # SIGQUIT
    test_expect_code 132 sydbox -- syd-abort-pthread-static 8 4 && # SIGILL
    test_expect_code 134 sydbox -- syd-abort-pthread-static 8 6 && # SIGABRT
    test_expect_code 136 sydbox -- syd-abort-pthread-static 8 8 && # SIGFPE
    test_expect_code 139 sydbox -- syd-abort-pthread-static 8 11 && # SIGFPE
    test_expect_code 141 sydbox -- syd-abort-pthread-static 8 13 && # SIGPIPE
    test_expect_code 142 sydbox -- syd-abort-pthread-static 8 14 && # SIGALRM
    test_expect_code 143 sydbox -- syd-abort-pthread-static 8 15 # SIGTERM
'

test_done
