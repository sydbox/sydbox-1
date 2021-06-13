#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox creat(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'deny creat()' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily creat -e EPERM "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny creat() for dangling symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily creat -e EPERM "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'allowlist creat()' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily creat -e ERRNO_0 "$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success_foreach_option 'denylist creat()' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily creat -e EPERM "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist creat() for dangling symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily creat -e EPERM "$l" &&
    test_path_is_missing "$f"
'

test_done
