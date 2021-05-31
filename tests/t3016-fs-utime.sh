#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox utime(2)'
. ./test-lib.sh

# No allow tests because of possible noatime, nomtime mount options

test_expect_failure setup '
    touch file0 &&
    touch file1 &&
    touch file3 &&
    touch file5
'

test_expect_failure SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file1 symlink-file1
    ln -sf file5 symlink-file5
'

test_expect_failure 'deny utime(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily utime
'

test_expect_failure 'deny utime()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utime file0
'

test_expect_failure 'deny utime()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utime file-non-existant
'

test_expect_failure 'deny utime() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utime symlink-file1
'

test_expect_failure 'deny utime() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily utime symlink-dangling
'

test_expect_failure 'blacklist utime()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily utime file3
'

test_expect_failure 'blacklist utime()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily utime file4-non-existant
'

test_expect_failure 'blacklist utime() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily utime symlink-file5
'

test_expect_failure 'blacklist utime() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily utime symlink-dangling
'

test_done
