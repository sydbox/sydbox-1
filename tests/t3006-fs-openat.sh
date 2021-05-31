#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox openat(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'deny openat(AT_FDCWD, NULL) with EFAULT' '
    sydbox -- emily openat -e EFAULT -d cwd
'

test_expect_success_foreach_option 'deny openat(-1) with EBADF' '
    f="no-$(unique_file)" &&
    sydbox -- emily openat -e EBADF -d null -m rdonly "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, file, O_RDONLY|O_DIRECTORY) with ENOTDIR' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox -- emily openat -e ENOTDIR -m rdonly -D -d cwd "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny open(AT_FDCWD, symlink-file, O_RDONLY|O_NOFOLLOW) with ELOOP' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox -- emily openat -e ELOOP -m rdonly -F -d cwd "$l"
'

test_expect_success_foreach_option 'whitelist openat(-1, $abspath, O_RDONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d null "$HOME_RESOLVED"/"$f"
'

test_expect_success_foreach_option 'whitelist openat(AT_FDCWD, $path, O_RDONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d cwd "$f"
'

test_expect_success_foreach_option SYMLINKS 'whitelist openat(AT_FDCWD, $path, O_RDONLY) for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d cwd "$l"
'

test_expect_success_foreach_option 'whitelist openat(fd, $path, O_RDONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d "$HOME" "$f"
'

test_expect_success_foreach_option SYMLINKS 'whitelist openat(fd, $path, O_RDONLY) for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ERRNO_0 -m rdonly -d "$HOME" "$l"
'

test_expect_success_foreach_option 'deny openat(-1, $abspath, O_RDONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d null -c "$HOME_RESOLVED"/"$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d cwd -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d cwd -c "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDONLY|O_CREAT) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(-1, $abspath, O_RDONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d null -cx "$HOME_RESOLVED"/"$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d cwd -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    f="$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(-1, $abspath, O_WRONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d null "$HOME_RESOLVED"/"$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_WRONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_WRONLY) for non-existant file' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ENOENT -m wronly -d cwd "$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(AT_FDCWD, $path, O_WRONLY) for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_WRONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_WRONLY) for non-existant file' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e ENOENT -m wronly -d "$HOME" "$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(fd, $path, O_WRONLY) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(-1, $abspath, O_WRONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d null -c "$HOME_RESOLVED"/"$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c "$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT for existing file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -c "$l" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_WRONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c "$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_WRONLY|O_CREAT for existing file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(fd, $path, O_WRONLY|O_CREAT) for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny openat(fd, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c "$l" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(-1, $abspath, O_WRONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d null -cx "$HOME_RESOLVED"/"$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d cwd -cx "$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m wronly -d cwd -cx "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m wronly -d "$HOME" -cx "$f" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m wronly -d "$HOME" -cx "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'whitelist openat(-1, $abspath, O_WRONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d null "$HOME_RESOLVED"/"$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success_foreach_option 'whitelist openat(AT_FDCWD, $path, O_WRONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d cwd "$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success_foreach_option 'whitelist openat(fd, $path, O_WRONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d "$HOME" "$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success_foreach_option 'whitelist openat(-1, $abspath, O_WRONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d null -c "$HOME_RESOLVED"/"$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d cwd -c "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(fd, $path, O_WRONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d "$HOME" -c "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(-1, $abspath, O_WRONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d null -cx "$HOME_RESOLVED"/"$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d cwd -cx "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d cwd -cx "$f"
'

test_expect_success_foreach_option 'whitelist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m wronly -d "$HOME" -cx "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d "$HOME" -cx "$f"
'

test_expect_success_foreach_option 'deny openat(-1, $abspath, O_RDWR)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d null "$HOME_RESOLVED"/"$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_RDWR)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d cwd "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDWR)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d "$HOME" "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(-1, $abspath, O_RDWR|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d null -c "$HOME_RESOLVED"/"$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_RDWR|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d cwd -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDWR|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d "$HOME" -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(-1, $path, O_RDWR|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d null -cx "$HOME_RESOLVED"/"$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d cwd -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdwr -d cwd -cx "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDWR|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EPERM -m rdwr -d "$HOME" -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'deny openat(fd, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily openat -e EEXIST -m rdwr -d "$HOME" -cx "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'whitelist openat(-1, $abspath, O_RDWR)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d null "$HOME_RESOLVED"/"$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success_foreach_option 'whitelist openat(AT_FDCWD, $path, O_RDWR)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d cwd "$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success_foreach_option 'whitelist openat(fd, $path, O_RDWR)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d "$HOME" "$f" "3" &&
    test_path_is_non_empty "$f"
'

test_expect_success_foreach_option 'whitelist openat(-1, $abspath, O_RDWR|O_CREAT)' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d null -c "$HOME_RESOLVED"/"$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(AT_FDCWD, $path, O_RDWR|O_CREAT)' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d cwd -c "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(fd, $path, O_RDWR|O_CREAT)' '
    f="no-$(unique_file)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d "$HOME" -c "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(-1, $abspath, O_RDWR|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d null -cx "$HOME_RESOLVED"/"$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d cwd -cx "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(AT_FDCWD, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdwr -d cwd -cx "$f"
'

test_expect_success_foreach_option 'whitelist openat(fd, $path, O_RDWR|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    sydbox \
        -ESYDBOX_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ERRNO_0 -m rdwr -d "$HOME" -cx "$f" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'whitelist openat(fd, $path, O_RDWR|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdwr -d "$HOME" -cx "$f"
'

test_expect_success_foreach_option 'blacklist openat(-1, $abspath, O_RDONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d null -c "$HOME_RESOLVED"/"$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d cwd -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d cwd -c "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(fd, $path, O_RDONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(fd, $path, O_RDONLY|O_CREAT) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -c "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(-1, $abspath, O_RDONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d null -cx "$HOME_RESOLVED"/"$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d cwd -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d cwd -cx "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m rdonly -d "$HOME" -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(fd, $path, O_RDONLY|O_CREAT|O_EXCL) for symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m rdonly -d "$HOME" -cx "$l" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(-1, $abspath, O_WRONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d null "$HOME_RESOLVED"/"$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'blacklist openat(AT_FDCWD, $path, O_WRONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'blacklist openat(AT_FDCWD, $path, O_WRONLY) for non-existant file' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ENOENT -m wronly -d cwd "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_WRONLY) for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'blacklist openat(fd, $path, O_WRONLY)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'blacklist openat(fd, $path, O_WRONLY) for non-existant file' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e ENOENT -m wronly -d "$HOME" "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(fd, $path, O_WRONLY) for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'blacklist openat(-1, $abspath, O_WRONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d null -c "$HOME_RESOLVED"/"$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -c "$l" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(fd, $path, O_WRONLY|O_CREAT)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(fd, $path, O_WRONLY|O_CREAT) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(fd, $path, O_WRONLY|O_CREAT) for symbolic link' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c "$l" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist openat(fd, $path, O_WRONLY|O_CREAT) for dangling symbolic link' '
    f="no-$(unique_file)" &&
    l="$(unique_link)" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -c "$l" "3" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(-1, $abspath, O_WRONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d null -cx "$HOME_RESOLVED"/"$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d cwd -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(AT_FDCWD, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d cwd -cx "$f" "3" &&
    test_path_is_empty "$f"
'

test_expect_success_foreach_option 'blacklist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EPERM -m wronly -d "$HOME" -cx "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'blacklist openat(fd, $path, O_WRONLY|O_CREAT|O_EXCL) for existing file' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily openat -e EEXIST -m wronly -d "$HOME" -cx "$f" "3" &&
    test_path_is_empty "$f"
'

test_done
