#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the exit return code of syd'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS -mcore/sandbox/read:allow"
export SYDBOX_TEST_OPTIONS

test_expect_success 'return success if tracee returns success' '
    syd -- syd-true
'

test_expect_success 'return success if tracee returns success (STATIC)' '
    syd -- syd-true-static
'

test_expect_success 'return success if initial tracee returns success (FORK)' '
    syd -- syd-true-fork ${EXIT_NPROC}
'

test_expect_success 'return success if initial tracee returns success (STATIC|FORK)' '
    syd -- syd-true-fork-static ${EXIT_NPROC}
'

test_expect_success 'return success if initial tracee returns success (PTHREAD)' '
    syd -- syd-true-pthread 32
'

test_expect_success 'return failure if tracee returns failure' '
    test_expect_code 1 syd -- syd-false
'

test_expect_success 'return failure if tracee returns failure (STATIC)' '
    test_expect_code 1 syd -- syd-false-static
'

test_expect_success 'return failure if initial tracee returns failure (FORK)' '
    test_expect_code 1 syd -- syd-false-fork ${EXIT_NPROC}
'

test_expect_success 'return failure if initial tracee returns failure (STATIC|FORK)' '
    test_expect_code 1 syd -- syd-false-fork-static ${EXIT_NPROC}
'

test_expect_success 'return failure if initial tracee returns failure (PTHREAD)' '
    test_expect_code 1 syd -- syd-false-pthread 32
'

test_done
