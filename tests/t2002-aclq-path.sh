#!/bin/sh
# Copyright 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='test acl queue matching (allowlist/denylist)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'deny+allowlist' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny+allowlist (multiple)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m allowlist/write+/foo/bar \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny+allowlist (multiple, last match wins)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'allow+allowlist (last match wins)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'allow+denylist' '
    f="$(unique_file)" &&
    touch "$f" &&
    env UNLINK_EPERM=1 sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'allow+denylist (multiple)' '
    f="$(unique_file)" &&
    touch "$f" &&
    env UNLINK_EPERM=1 sydbox \
        -m core/sandbox/write:allow \
        -m denylist/write+/foo/bar \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'allow+allowlist (last match wins)' '
    f="$(unique_file)" &&
    touch "$f" &&
    env UNLINK_EPERM=1 sydbox \
        -m core/sandbox/write:allow \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_file "$f"
'

test_done
