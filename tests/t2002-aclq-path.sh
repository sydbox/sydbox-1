#!/bin/sh
# Copyright 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='test acl queue matching (whitelist/blacklist)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'deny+whitelist' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny+whitelist (multiple)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m whitelist/write+/foo/bar \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny+whitelist (multiple, last match wins)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'allow+whitelist (last match wins)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'allow+blacklist' '
    f="$(unique_file)" &&
    touch "$f" &&
    env UNLINK_EPERM=1 sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'allow+blacklist (multiple)' '
    f="$(unique_file)" &&
    touch "$f" &&
    env UNLINK_EPERM=1 sydbox \
        -m core/sandbox/write:allow \
        -m blacklist/write+/foo/bar \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'allow+whitelist (last match wins)' '
    f="$(unique_file)" &&
    touch "$f" &&
    env UNLINK_EPERM=1 sydbox \
        -m core/sandbox/write:allow \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- unlink-simple "$f" &&
    test_path_is_file "$f"
'

test_done
