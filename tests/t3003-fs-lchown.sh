#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox lchown(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'deny lchown(NULL) with EFAULT' '
    sydbox -- emily lchown -e EFAULT
'

test_expect_success_foreach_option SYMLINKS 'deny lchown($symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e EPERM "$l"
'

test_expect_success_foreach_option SYMLINKS 'deny lchown($nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e ENOENT "$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist lchown($symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e EPERM "$l"
'

test_expect_success_foreach_option SYMLINKS 'denylist lchown($nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily lchown -e ENOENT "$f"
'

test_expect_success_foreach_option SYMLINKS 'allowlist lchown($symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily lchown -e ERRNO_0 "$l"
'

test_done
