#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

# TODO: Test UMOUNT_NOFOLLOW

test_description='sandbox umount2(2)'
. ./test-lib.sh
prog=t011_umount2

test_expect_failure setup '
    mkdir mnt0 &&
    mkdir mnt2 &&
    mkdir mnt3 &&
    mkdir mnt5
'

test_expect_failure SYMLINKS setup-symlinks '
    ln -sf /non/existant/directory symlink-dangling &&
    ln -sf mnt2 symlink-mnt2
    ln -sf mnt5 symlink-mnt5
'

test_expect_failure 'deny umount2(NULL) with EFAULT' '
    sydbox -ESYDBOX_TEST_EFAULT=1 -- emily umount2
'

test_expect_failure 'deny umount2()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily umount2 mnt0
'

test_expect_failure 'deny umount2() for non-existant directory' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily umount2 mnt1-non-existant
'

test_expect_failure SYMLINKS 'deny umount2() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily umount2 symlink-mnt2
'

test_expect_failure SYMLINKS 'deny umount2() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily umount2 symlink-dangling
'

test_expect_failure 'blacklist umount2()' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily umount2 mnt3
'

test_expect_failure 'blacklist umount2() for non-existant directory' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily umount2 mnt4-non-existant
'

test_expect_failure SYMLINKS 'blacklist umount2() for symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily umount2 symlink-mnt5
'

test_expect_failure SYMLINKS 'blacklist umount2() for dangling symbolic link' '
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily umount2 symlink-dangling
'

test_done
