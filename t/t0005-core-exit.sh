#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the exit return code of sydbox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS="$save_SYDBOX_TEST_OPTIONS -mcore/sandbox/read:allow"
export SYDBOX_TEST_OPTIONS

test_expect_success 'return success if tracee returns success' '
    sydbox -- syd-true
'

test_expect_success 'return success if tracee returns success (STATIC)' '
    sydbox -- syd-true-static
'

test_expect_success 'return success if initial tracee returns success (FORK)' '
    sydbox -- syd-true-fork 64
'

test_expect_success 'return success if initial tracee returns success (STATIC|FORK)' '
    sydbox -- syd-true-fork-static 64
'

test_expect_success 'return success if initial tracee returns success (PTHREAD)' '
    sydbox -- syd-true-pthread 32
'

test_expect_success 'return failure if tracee returns failure' '
    test_expect_code 1 sydbox -- syd-false
'

test_expect_success 'return failure if tracee returns failure (STATIC)' '
    test_expect_code 1 sydbox -- syd-false-static
'

test_expect_success 'return failure if initial tracee returns failure (FORK)' '
    test_expect_code 1 sydbox -- syd-false-fork 64
'

test_expect_success 'return failure if initial tracee returns failure (STATIC|FORK)' '
    test_expect_code 1 sydbox -- syd-false-fork-static 64
'

test_expect_success 'return failure if initial tracee returns failure (PTHREAD)' '
    test_expect_code 1 sydbox -- syd-false-pthread 32
'

test_done
