#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox rename(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'rename($oldpath, $newpath) returns ERRNO_0' '
    old="$(unique_file)" &&
    new="$(unique_file)" &&
    touch "$old" &&
    sydbox -- emily rename -e ERRNO_0 "$old" "$new" &&
    test_path_is_missing "$old" &&
    test_path_is_file "$new"
'

test_expect_success_foreach_option 'rename(NULL, NULL) returns EFAULT' '
    sydbox -- emily rename -e EFAULT
'

test_expect_success_foreach_option 'rename($oldpath, $oldpath/$newpath) returns EINVAL' '
    old="$(unique_dir)" &&
    mkdir "$old" &&
    sydbox -- emily rename -e EINVAL "$old" "$old"/new &&
    test_path_is_dir "$old" &&
    test_path_is_missing "$old"/new
'

test_expect_success_foreach_option 'rename($file, $dir) returns EISDIR' '
    f="$(unique_file)" &&
    d="$(unique_dir)" &&
    touch "$f" &&
    mkdir "$d" &&
    sydbox -- emily rename -e EISDIR "$f" "$d" &&
    test_path_is_file "$f" &&
    test_path_is_dir "$d"
'

test_expect_success_foreach_option SYMLINKS 'rename($symlink, $dir) returns EISDIR' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    d="$(unique_dir)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    mkdir "$d" &&
    sydbox -- emily rename -e EISDIR "$l" "$d" &&
    test_path_is_symlink "$l" &&
    test_path_is_dir "$d"
'

test_expect_success_foreach_option SYMLINKS 'rename($symlink-self, $dir) returns EISDIR' '
    d="$(unique_dir)" &&
    l="self-$(unique_link)" &&
    ln -sf "$l" "$l" &&
    mkdir "$d" &&
    sydbox -- emily rename -e EISDIR "$l" "$d" &&
    test_path_is_symlink "$l" &&
    test_path_is_dir "$d"
'

test_expect_success_foreach_option SYMLINKS 'rename($symlink-self/$file, $newfile) returns ELOOP' '
    f="$(unique_file)" &&
    l="self-$(unique_link)" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily rename -e ELOOP "$l"/file "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'rename($file, $symlink-self/$newfile returns ELOOP' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily rename -e ELOOP "$f" "$l"/newfile &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option SYMLINKS 'rename($symlink-circular/$file, $newfile) returns ELOOP' '
    f="$(unique_file)" &&
    l0="loop0-$(unique_link)" &&
    l1="loop1-$(unique_link)" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily rename -e ELOOP "$l0"/file "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option SYMLINKS 'rename($file, $symlink-circular/$newfile) returns ELOOP' '
    f="$(unique_file)" &&
    l0="loop0-$(unique_link)" &&
    l1="loop1-$(unique_link)" &&
    touch "$f" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily rename -e ELOOP "$f" "$l0"/newfile &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option SYMLINKS 'rename($symlink-self, $newsymlink) returns ERRNO_0' '
    old="self-$(unique_link)" &&
    new="self-$(unique_link)" &&
    ln -sf "$old" "$old" &&
    sydbox -- emily rename -e ERRNO_0 "$old" "$new" &&
    test_path_is_missing "$old" &&
    test_path_is_symlink "$new"
'

test_expect_success_foreach_option SYMLINKS 'rename($file, $symlink-self) returns ERRNO_0' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily rename -e ERRNO_0 "$f" "$l" &&
    test_path_is_missing "$f" &&
    test_path_is_file "$l"
'

test_expect_success_foreach_option SYMLINKS 'rename($symlink-circular, $newsymlink) returns ERRNO_0' '
    l0="loop0-$(unique_link)" &&
    l1="loop1-$(unique_link)" &&
    new="loop-new-$(unique_link)" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily rename -e ERRNO_0 "$l0" "$new" &&
    test_path_is_missing "$l0" &&
    test_path_is_symlink "$l1" &&
    test_path_is_symlink "$new"
'

test_expect_success_foreach_option SYMLINKS 'rename($file, $symlink-circular) returns ERRNO_0' '
    f="$(unique_file)" &&
    l0="loop0-$(unique_link)" &&
    l1="loop1-$(unique_link)" &&
    touch "$f" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "l0" &&
    sydbox -- emily rename -e ERRNO_0 "$f" "$l0" &&
    test_path_is_missing "$f" &&
    test_path_is_file "$l0" &&
    test_path_is_symlink "$l1"
'

test_expect_success_foreach_option 'rename($nofile, $newfile) returns ENOENT' '
    old="no-$(unique_file)" &&
    new="new-$(unique_file)" &&
    sydbox -- emily rename -e ENOENT "$old" "$new" &&
    test_path_is_missing "$old" &&
    test_path_is_missing "$new"
'

test_expect_success_foreach_option 'rename($file, $nodir/$newfile) returns ENOENT' '
    f="$(unique_file)" &&
    d="$(unique_dir)" &&
    touch "$f" &&
    sydbox -- emily rename -e ENOENT "$f" "$d"/newfile &&
    test_path_is_file "$f" &&
    test_path_is_missing "$d"/newfile &&
    test_path_is_missing "$d"
'

test_expect_success_foreach_option 'rename("", $newfile) returns ENOENT' '
    f="$(unique_file)" &&
    sydbox -- emily rename -e ENOENT "" "$f" &&
    test_path_is_missing "$f"
'

test_expect_success_foreach_option 'rename($file, "") returns ENOENT' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox -- emily rename -e ENOENT "$f" "" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'rename("", "") returns ENOENT' '
    sydbox -- emily rename -e ENOENT "" ""
'

test_expect_success_foreach_option 'rename($olddir, $newfile) returns ENOTDIR' '
    d="$(unique_dir)" &&
    f="$(unique_file)" &&
    mkdir "$d" &&
    touch "$f" &&
    sydbox -- emily rename -e ENOTDIR "$d" "$f" &&
    test_path_is_dir "$d" &&
    test_path_is_file "$f"
'

test_expect_success_foreach_option 'rename($olddir, $new-nonempty-dir) returns ENOTEMPTY' '
    d0="$(unique_dir)" &&
    d1="$(unique_dir)" &&
    mkdir "$d0" &&
    mkdir "$d1" &&
    touch "$d1"/file &&
    sydbox -- emily rename -e ENOTEMPTY "$d0" "$d1" &&
    test_path_is_dir "$d0" &&
    test_path_is_dir "$d1" &&
    test_path_is_file "$d1"/file
'

test_done
