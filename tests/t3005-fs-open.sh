#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox open(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'deny open(NULL) with EFAULT' '
    sydbox -- emily open -e EFAULT
'

test_expect_success_foreach_option 'deny open(file, O_RDONLY|O_DIRECTORY) with ENOTDIR' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox -- emily open -e ENOTDIR -m rdonly -D "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny open(symlink-file, O_RDONLY|O_NOFOLLOW) with ELOOP' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f"
    ln -sf "$f" "$l"
    sydbox -- emily open -e ELOOP -m rdonly -F "$l"
'

test_expect_success_foreach_option 'allowlist O_RDONLY' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e ERRNO_0 -m rdonly "$f"
'

test_expect_success_foreach_option SYMLINKS 'allowlist O_RDONLY for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e ERRNO_0 -m rdonly "$l"
'

test_expect_success_foreach_option 'deny O_RDONLY|O_CREAT' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdonly -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny O_RDONLY|O_CREAT for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdonly -c "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny O_RDONLY|O_CREAT|O_EXCL' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdonly -cx "$f" rdonly-creat-excl &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny O_RDONLY|O_CREAT|O_EXCL for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m rdonly -cx "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny O_RDONLY|O_CREAT|O_EXCL for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m rdonly -cx "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny O_WRONLY' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny O_WRONLY for non-existant file' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e ENOENT -m wronly "$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny O_WRONLY for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny O_WRONLY|O_CREAT' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c "$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny O_WRONLY|O_CREAT for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny O_WRONLY|O_CREAT for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny O_WRONLY|O_CREAT for dangling symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -c "$l" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny O_WRONLY|O_CREAT|O_EXCL' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m wronly -cx "$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny O_WRONLY|O_CREAT|O_EXCL for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m wronly -cx "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'allowlist O_WRONLY' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m wronly "$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success_foreach_option 'allowlist O_WRONLY|O_CREAT' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m wronly -c "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'allowlist O_WRONLY|O_CREAT|O_EXCL' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m wronly -cx "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'allowlist O_WRONLY|O_CREAT|O_EXCL for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m wronly -cx "$f"
'

test_expect_success_foreach_option 'deny O_RDWR' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdwr "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny O_RDWR|O_CREAT' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdwr -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny O_RDWR|O_CREAT|O_EXCL' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EPERM -m rdwr -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny O_RDWR|O_CREAT|O_EXCL for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily open -e EEXIST -m rdwr -cx "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'allowlist O_RDWR' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m rdwr "$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success_foreach_option 'allowlist O_RDWR|O_CREAT' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m rdwr -c "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'allowlist O_RDWR|O_CREAT|O_EXCL' '
    f="no-$(unique_file)" &&
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily open -e ERRNO_0 -m rdwr -cx "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'allowlist O_RDWR|O_CREAT|O_EXCL for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m rdwr -cx "$f"
'

test_expect_success_foreach_option 'denylist O_RDONLY|O_CREAT' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m rdonly -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist O_RDONLY|O_CREAT for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m rdonly -c "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'denylist O_RDONLY|O_CREAT|O_EXCL' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m rdonly -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'denylist O_RDONLY|O_CREAT|O_EXCL for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m rdonly -cx "$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist O_RDONLY|O_CREAT|O_EXCL for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m rdonly -cx "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'denylist O_WRONLY' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'denylist O_WRONLY for non-existant file' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e ENOENT -m wronly "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist O_WRONLY for symbolic link' '
    f="$(unique_file)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'denylist O_WRONLY|O_CREAT' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'denylist O_WRONLY|O_CREAT for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist O_WRONLY|O_CREAT for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist O_WRONLY|O_CREAT for dangling symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -c "$l" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'denylist O_WRONLY|O_CREAT|O_EXCL' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EPERM -m wronly -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'denylist O_WRONLY|O_CREAT|O_EXCL for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily open -e EEXIST -m wronly -cx "$f" "3" &&
    test_path_is_empty "$f"
'

test_done
