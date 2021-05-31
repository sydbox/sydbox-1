#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox rmdir(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'rmdir($empty-dir) returns ERRNO_0' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    sydbox -- emily rmdir -e ERRNO_0 "$d" &&
    test_path_is_missing "$d"
'

test_expect_success_foreach_option 'rmdir($noaccess/$empty-dir) returns EACCES' '
    d0="no-access-$(unique_dir)" &&
    d1="$(unique_dir)" &&
    mkdir "$d0" &&
    mkdir "$d0"/"$d1" &&
    chmod 700 "$d0"/"$d1" &&
    test_when_finished "chmod 700 $d0" &&
    chmod 000 "$d0" &&
    sydbox -- emily rmdir -e EACCES "$d0"/"$d1" &&
    chmod 700 "$d0" &&
    test_path_is_dir "$d0"/"$d1"
'

test_expect_success_foreach_option 'rmdir(NULL) returns EFAULT' '
    sydbox -- emily rmdir -e EFAULT
'

test_expect_success_foreach_option 'rmdir($empty-dir/.) returns EINVAL' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    sydbox -- emily rmdir -e EINVAL "$d"/. &&
    test_path_is_dir "$d"
'

test_expect_success_foreach_option SYMLINKS 'rmdir($symlink-self/foo) returns ELOOP' '
    l="self-$(unique_link)" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily rmdir -e ELOOP "$l"/foo
'

test_expect_success_foreach_option SYMLINKS 'rmdir($symlink-circular/foo) returns ELOOP' '
    l0="bad-$(unique_link)" &&
    l1="bad-$(unique_link)" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily rmdir -e ELOOP "$l0"/foo
'

test_expect_success_foreach_option 'rmdir($nodir) returns ENOENT' '
    d="no-$(unique_dir)" &&
    sydbox -- emily rmdir -e ENOENT "$d"
'

test_expect_success_foreach_option 'rmdir($notdir) returns ENOTDIR' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox -- emily rmdir -e ENOTDIR "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option SYMLINKS 'rmdir($symlink-dangling) returns ENOTDIR' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    sydbox -- emily rmdir -e ENOTDIR "$l" &&
    test_path_is_symlink "$l"
'

test_expect_success_foreach_option 'rmdir($not-empty-dir) returns ENOTEMPTY' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    touch "$d"/foo &&
    sydbox -- emily rmdir -e ENOTEMPTY "$d" &&
    test_path_is_dir "$d"
'

test_expect_failure 'deny rmdir()' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily rmdir -e EPERM "$d" &&
    test_path_is_dir "$d"
'

test_expect_failure 'deny rmdir() for non-existant directory' '
    d="no-$(unique_dir)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily rmdir -e EPERM "$d"
'

test_expect_failure 'whitelist rmdir()' '
    d="no-$(unique_dir)" &&
    mkdir "$d" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily rmdir -e ERRNO_0 "$d" &&
    test_path_is_missing "$d"
'

test_expect_failure 'blacklist rmdir()' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily rmdir -e EPERM "$d" &&
    test_path_is_dir "$d"
'

test_expect_failure 'blacklist rmdir() for non-existant directory' '
    d="no-$(unique_dir)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily rmdir -e EPERM "$d"
'

test_done
