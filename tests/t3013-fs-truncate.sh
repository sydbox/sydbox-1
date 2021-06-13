#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox truncate(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_failure 'deny truncate(NULL) with EFAULT' '
    sydbox -- emily truncate -e EFAULT
'

test_expect_failure 'deny truncate()' '
    f="$(unique_file)" &&
    : > "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily truncate -e EPERM "$f" &&
    test_path_is_non_empty "$f"
'

test_expect_failure 'deny truncate() for non-existant file' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily truncate -e EPERM "$f"
'

test_expect_failure SYMLINKS 'deny truncate() for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    echo hey syd > "$f" &&
    ln -sf "$l" "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily truncate -e EPERM "$l" &&
    test_path_is_non_empty "$f"
'

test_expect_failure SYMLINKS 'deny truncate() for dangling symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf no"$l" "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily truncate no"$l"
'

test_expect_failure 'allowlist truncate()' '
    f="$(unique_file)" &&
    echo hello syd > "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily truncate "$f" &&
    test_path_is_empty "$f"
'

test_expect_failure SYMLINKS 'allowlist truncate() for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    echo hello syd > "$f" &&
    ln -sf "$l" "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily truncate -e ERRNO_0 "$l" &&
    test_path_is_empty "$f"
'

test_done
