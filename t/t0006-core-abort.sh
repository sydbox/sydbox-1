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
test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated with SIGINT' '
    test_expect_code 130 syd -- syd-abort 2
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated with SIGQUIT' '
    test_expect_code 131 syd -- syd-abort 3
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated with SIGILL' '
    test_expect_code 132 syd -- syd-abort 4
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated with SIGABRT' '
    test_expect_code 134 syd -- syd-abort 6
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated with SIGFPE' '
    test_expect_code 136 syd -- syd-abort 8
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated with SIGSEGV' '
    test_expect_code 139 syd -- syd-abort 11
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated with SIGPIPE' '
    test_expect_code 141 syd -- syd-abort 13
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated with SIGALRM' '
    test_expect_code 142 syd -- syd-abort 14
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if tracee is terminated with SIGTERM' '
    test_expect_code 143 syd -- syd-abort 15
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked tracee is terminated with SIGINT' '
    test_expect_code 130 syd -- syd-abort-static 2
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked tracee is terminated with SIGQUIT' '
    test_expect_code 131 syd -- syd-abort-static 3
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked tracee is terminated with SIGILL' '
    test_expect_code 132 syd -- syd-abort-static 4
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked tracee is terminated with SIGABRT' '
    test_expect_code 134 syd -- syd-abort-static 6
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked tracee is terminated with SIGFPE' '
    test_expect_code 136 syd -- syd-abort-static 8
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked tracee is terminated with SIGSEGV' '
    test_expect_code 139 syd -- syd-abort-static 11
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked tracee is terminated with SIGPIPE' '
    test_expect_code 141 syd -- syd-abort-static 13
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked tracee is terminated with SIGALRM' '
    test_expect_code 142 syd -- syd-abort-static 14
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked tracee is terminated with SIGTERM' '
    test_expect_code 143 syd -- syd-abort-static 15
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if forking tracee is terminated with SIGINT' '
    test_expect_code 130 syd -- syd-abort-fork 2
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if forking tracee is terminated with SIGQUIT' '
    test_expect_code 131 syd -- syd-abort-fork 3
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if forking tracee is terminated with SIGILL' '
    test_expect_code 132 syd -- syd-abort-fork 4
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if forking tracee is terminated with SIGABRT' '
    test_expect_code 134 syd -- syd-abort-fork 6
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if forking tracee is terminated with SIGFPE' '
    test_expect_code 136 syd -- syd-abort-fork 8
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if forking tracee is terminated with SIGSEGV' '
    test_expect_code 139 syd -- syd-abort-fork 11
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if forking tracee is terminated with SIGPIPE' '
    test_expect_code 141 syd -- syd-abort-fork 13
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if forking tracee is terminated with SIGALRM' '
    test_expect_code 142 syd -- syd-abort-fork 14
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if forking tracee is terminated with SIGTERM' '
    test_expect_code 143 syd -- syd-abort-fork 15
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked forking tracee is terminated with SIGINT' '
    test_expect_code 130 syd -- syd-abort-fork-static 2
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked forking tracee is terminated with SIGQUIT' '
    test_expect_code 131 syd -- syd-abort-fork-static 3
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked forking tracee is terminated with SIGILL' '
    test_expect_code 132 syd -- syd-abort-fork-static 4
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked forking tracee is terminated with SIGABRT' '
    test_expect_code 134 syd -- syd-abort-fork-static 6
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked forking tracee is terminated with SIGFPE' '
    test_expect_code 136 syd -- syd-abort-fork-static 8
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked forking tracee is terminated with SIGSEGV' '
    test_expect_code 139 syd -- syd-abort-fork-static 11
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked forking tracee is terminated with SIGPIPE' '
    test_expect_code 141 syd -- syd-abort-fork-static 13
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked forking tracee is terminated with SIGALRM' '
    test_expect_code 142 syd -- syd-abort-fork-static 14
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked forking tracee is terminated with SIGTERM' '
    test_expect_code 143 syd -- syd-abort-fork-static 15
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if multithreaded tracee is terminated with SIGINT' '
    test_expect_code 130 syd -- syd-abort-pthread 2
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if multithreaded tracee is terminated with SIGQUIT' '
    test_expect_code 131 syd -- syd-abort-pthread 3
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if multithreaded tracee is terminated with SIGILL' '
    test_expect_code 132 syd -- syd-abort-pthread 4
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if multithreaded tracee is terminated with SIGABRT' '
    test_expect_code 134 syd -- syd-abort-pthread 6

'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if multithreaded tracee is terminated with SIGFPE' '
    test_expect_code 136 syd -- syd-abort-pthread 8
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if multithreaded tracee is terminated with SIGSEGV' '
    test_expect_code 139 syd -- syd-abort-pthread 11
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if multithreaded tracee is terminated with SIGPIPE' '
    test_expect_code 141 syd -- syd-abort-pthread 13
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if multithreaded tracee is terminated with SIGALRM' '
    test_expect_code 142 syd -- syd-abort-pthread 14
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if multithreaded tracee is terminated with SIGTERM' '
    test_expect_code 143 syd -- syd-abort-pthread 15
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked multithreaded tracee is terminated with SIGINT' '
    test_expect_code 130 syd -- syd-abort-pthread-static 2
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked multithreaded tracee is terminated with SIGQUIT' '
    test_expect_code 131 syd -- syd-abort-pthread-static 3
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked multithreaded tracee is terminated with SIGILL' '
    test_expect_code 132 syd -- syd-abort-pthread-static 4
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked multithreaded tracee is terminated with SIGABRT' '
    test_expect_code 134 syd -- syd-abort-pthread-static 6
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked multithreaded tracee is terminated with SIGFPE' '
    test_expect_code 136 syd -- syd-abort-pthread-static 8
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked multithreaded tracee is terminated with SIGSEGV' '
    test_expect_code 139 syd -- syd-abort-pthread-static 11
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked multithreaded tracee is terminated with SIGPIPE' '
    test_expect_code 141 syd -- syd-abort-pthread-static 13
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked multithreaded tracee is terminated with SIGALRM' '
    test_expect_code 142 syd -- syd-abort-pthread-static 14
'

test_expect_success NOT_ON_BUILD_HOST 'return 128 + $SIGNUM if statically linked multithreaded tracee is terminated with SIGTERM' '
    test_expect_code 143 syd -- syd-abort-pthread-static 15
'

test_done
