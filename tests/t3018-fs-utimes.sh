#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox utimes(2)'
. ./test-lib.sh

# No allow tests because of possible noatime, nomtime mount options

test_expect_failure setup '
    touch file0 &&
    touch file1 &&
    touch file2 &&
    touch file3
'

test_expect_failure SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file1 symlink-file1
    ln -sf file3 symlink-file3
'

test_expect_failure 'deny utimes(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily utimes
'

test_expect_failure 'deny utimes()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utimes file0
'

test_expect_failure 'deny utimes() for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utimes file-non-existant
'

test_expect_failure 'deny utimes() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utimes symlink-file1
'

test_expect_failure 'deny utimes() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utimes symlink-dangling
'

test_expect_failure 'blacklist utimes()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily utimes file3
'

test_expect_failure 'blacklist utimes() for non-existant file' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily utimes file-non-existant
'

test_expect_failure 'blacklist utimes() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily utimes symlink-file3
'

test_expect_failure 'blacklist utimes() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily utimes symlink-dangling
'

test_done
