#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chmod()'
. ./test-lib.sh

test_expect_success setup '
    rm -f file-non-existant &&
    touch file0 && chmod 600 file0 &&
    touch file1 && chmod 600 file1 &&
    touch file2 && chmod 600 file2 &&
    touch file3 && chmod 600 file3
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file1 symlink-file1 &&
    ln -sf file3 symlink-file3
'

test_expect_success 'deny chmod(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily chmod
'

test_expect_success 'deny chmod()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily chmod file0 &&
    test_path_is_readable file0 &&
    test_path_is_writable file0
'

test_expect_success 'deny chmod() for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily chmod file-non-existant
'

test_expect_success SYMLINKS 'deny chmod() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily chmod symlink-file1 &&
    test_path_is_readable file1 &&
    test_path_is_writable file1
'

test_expect_success SYMLINKS 'deny chmod() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily chmod symlink-dangling
'

test_expect_success 'allow chmod()' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod file2 &&
    test_path_is_not_readable file2 &&
    test_path_is_not_writable file2
'

test_expect_success SYMLINKS 'allow chmod() for symbolic link' '
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod symlink-file3 &&
    test_path_is_not_readable file3 &&
    test_path_is_not_writable file3
'

test_done
