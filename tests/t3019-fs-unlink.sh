#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox unlink(2)'
. ./test-lib.sh

test_expect_failure setup '
    touch file0 &&
    touch file2 &&
    touch file3
'

test_expect_failure 'deny unlink(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily unlink
'

test_expect_failure 'deny unlink()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily unlink file0 &&
    test_path_is_file file0
'

test_expect_failure 'deny unlink() for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily unlink file1-non-existant
'

test_expect_failure 'allow unlink()' '
    sydbox -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily unlink file2 &&
    test_path_is_missing file2
'

test_expect_failure 'blacklist unlink()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily unlink file3 &&
    test_path_is_file file3
'

test_expect_failure 'blacklist unlink() for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily unlink file4-non-existant
'

test_done
