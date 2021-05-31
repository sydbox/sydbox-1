#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox chmod(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'chmod($file) returns ERRNO_0' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox -- emily chmod -e ERRNO_0 -m 000 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success_foreach_option SYMLINKS 'chmod($symlink) returns ERRNO_0' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox -- emily chmod -e ERRNO_0 -m 000 "$l"
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success_foreach_option 'chmod(NULL) returns EFAULT' '
    sydbox -- emily chmod -e EFAULT
'

test_expect_success_foreach_option 'chmod("") returns ENOENT' '
    sydbox -- emily chmod -e ENOENT -m 000 ""
'

test_expect_success_foreach_option 'chmod($nofile) returns ENOENT' '
    f="no-$(unique_file)" &&
    sydbox -- emily chmod -e ENOENT -m 000 "$f"
'

test_expect_success_foreach_option 'chmod($noaccess/$file) returns EACCES' '
    d="no-access-$(unique_dir)" &&
    f="$(unique_file)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    chmod 600 "$d"/"$f" &&
    test_when_finished "chmod 700 $d" && chmod 000 "$d" &&
    sydbox -- emily chmod -e EACCES -m 000 "$d"/"$f" &&
    chmod 700 "$d" &&
    test_path_is_readable "$d"/"$f" &&
    test_path_is_writable "$d"/"$f"
'

test_expect_success_foreach_option 'chmod($nodir/$file) returns ENOTDIR' '
    d="non-$(unique_dir)" &&
    touch "$d" &&
    sydbox -- emily chmod -e ENOTDIR -m 000 "$d"/foo
'

test_expect_success_foreach_option SYMLINKS 'chmod($symlink-self) returns ELOOP' '
    l="self-$(unique_link)" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily chmod -e ELOOP -m 000 "$l"
'

test_expect_success_foreach_option SYMLINKS 'chmod($symlink-circular) returns ELOOP' '
    l0="loop0-$(unique_link)" &&
    l1="loop1-$(unique_link)" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily chmod -e ELOOP -m 000 "$l0"
'

test_expect_success_foreach_option 'deny chmod($file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e EPERM -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'deny chmod($nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e ENOENT -m 000 "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny chmod($symlink)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e EPERM -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny chmod($symlink-dangling)' '
    f="no-$(unique_file)" &&
    l="bad-$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily chmod -e ENOENT -m 000 "$l"
'

test_expect_success_foreach_option 'blacklist chmod($file)' '
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e EPERM -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'blacklist chmod($nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ENOENT -m 000 "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist chmod($symlink)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e EPERM -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist chmod($symlink-dangling)' '
    f="no-$(unique_file)" &&
    l="bad-$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ENOENT -m 000 "$l"
'

test_expect_success_foreach_option 'whitelist chmod($file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ERRNO_0 -m 000 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success_foreach_option SYMLINKS 'whitelist chmod($symlink)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily chmod -e ERRNO_0 -m 000 "$l" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny whitelisted chmod($symlink-outside)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    d="$(unique_dir)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    mkdir "$d" &&
    ln -sf ../"$f" "$d"/"$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/"$d"/**" \
        -- emily chmod -e EPERM -m 000 "$d"/"$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_done
