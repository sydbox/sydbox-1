#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox link(2)'
. ./test-lib.sh

test_expect_failure setup '
    mkdir dir0 &&
    touch dir0/file0 &&
    mkdir dir1 &&
    touch dir1/file1
'

test_expect_failure 'deny link(NULL, NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily link
'

test_expect_failure 'deny link()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/dir0/**" \
        -- emily link dir0/file0 file1-non-existant &&
    test_path_is_missing file1-non-existant
'

test_expect_failure 'allow link()' '
    sydbox -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily link dir0/file0 file2 &&
    test_path_is_file file2
'

test_expect_failure 'denylist link()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily link dir1/file1 file1-non-existant &&
    test_path_is_missing file1-non-existant
'

test_done
