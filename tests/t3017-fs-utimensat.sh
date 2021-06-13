#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox utimensat(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'utimensat(AT_FDCWD, $file, 0s, 0) returns ERRNO_0' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox -- emily utimensat -d cwd -t 0 -e ERRNO_0 "$f" &&
    test_path_has_mtime 0 "$f"
'

test_expect_success_foreach_option 'utimensat($dir, $file, 0s, 0) returns ERRNO_0' '
    f="$(unique_file)" &&
    d="$(unique_dir)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    sydbox -- emily utimensat -d "$d" -t 0 -e ERRNO_0 "$f" &&
    test_path_has_mtime 0 "$d"/"$f"
'

test_expect_success_foreach_option SYMLINKS 'utimensat(AT_FDCWD, $symlink, 0s, 0) returns ERRNO_0' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox -- emily utimensat -d cwd -t 0 -e ERRNO_0 "$l"
    test_path_has_mtime 0 "$f"
'

test_expect_success_foreach_option SYMLINKS 'utimensat($dir, $symlink, 0s, 0) returns ERRNO_0' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    d="$(unique_dir)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    ln -sf "$f" "$d"/"$l" &&
    sydbox -- emily utimensat -d "$d" -t 0 -e ERRNO_0 "$l" &&
    test_path_has_mtime 0 "$d"/"$f"
'

# This one is an interesting case.
# Quoting utimensat(2) (release 3.51 of the Linux man-pages project):
#
# EFAULT ...or, dirfd was AT_FDCWD, and pathname is NULL or an invalid address.
test_expect_success_foreach_option 'utimensat(AT_FDCWD, NULL, 0s, 0) returns EFAULT' '
    sydbox -- emily utimensat -d cwd -t 0 -e EFAULT
'

#
# Quoting utimensat(2) (release 3.51 of the Linux man-pages project):
#
# EINVAL pathname is NULL, dirfd is not AT_FDCWD, and flags contains AT_SYMLINK_NOFOLLOW.
#
test_expect_success_foreach_option 'utimensat($dir, NULL, 0s, 0) returns EINVAL' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    sydbox -- emily utimensat -d "$d" -t 0 -n -e EINVAL
'

test_expect_success_foreach_option 'utimensat($badfd, $nofile, 0s, 0) returns EBADF' '
    f="no-$(unique_file)" &&
    sydbox -- emily utimensat -d null -t 0 -e EBADF "$f"
'

# BUGFIX: commit:12965d574111f6c2350192ff6e8dcdc1d24f98d0
# Reason: sydbox aborts due to path_is_absolute() called with NULL argument
# FIXME: Do we have other bugs which may be triggered in case we set
# core/sandbox/write:deny for the tests above? (EFAULT et. al)
test_expect_success_foreach_option 'utimensat($badfd, NULL, 0s, 0) returns EBADF' '
    sydbox -m core/sandbox/write:deny -- emily utimensat -d null -t 0s -e EBADF
'

test_expect_success_foreach_option 'utimensat($badfd, "", 0s, 0) returns ENOENT' '
    sydbox -- emily utimensat -d null -t 0 -e ENOENT ""
'

test_expect_success_foreach_option 'utimensat(AT_FDCWD, "", 0s, 0) returns ENOENT' '
    sydbox -- emily utimensat -d cwd -t 0 -e ENOENT ""
'

test_expect_success_foreach_option 'utimensat($dir, "", 0s, 0) returns ENOENT' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    sydbox -- emily utimensat -d "$d" -t 0 -e ENOENT ""
'

test_expect_success_foreach_option 'utimensat(AT_FDCWD, $nofile, 0s, 0) returns ENOENT' '
    f="no-$(unique_file)" &&
    sydbox -- emily utimensat -d cwd -t 0 -e ENOENT "$f"
'

test_expect_success_foreach_option 'utimensat($dir, $nofile, 0s, 0) returns ENOENT' '
    f="no-$(unique_file)" &&
    d="$(unique_dir)" &&
    mkdir "$d" &&
    sydbox -- emily utimensat -d "$d" -t 0 -e ENOENT "$f"
'

test_expect_success_foreach_option 'utimensat(AT_FDCWD, $noaccess/$file, 0s, 0) returns EACCES' '
    d="no-access-$(unique_dir)" &&
    f="$(unique_file)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    m=$(stat_mtime "$d"/"$f") &&
    test_when_finished "chmod 700 $d" && chmod 000 "$d" &&
    sydbox -- emily utimensat -d cwd -t 0 -e EACCES "$d"/"$f" &&
    chmod 700 "$d" &&
    test_path_has_mtime "$m" "$d"/"$f"
'

# TODO: emily limitation, not easy to test...
#test_expect_success_foreach_option 'utimensat($noaccess, $file, 0s, 0) returns EACCES' '
#    d="no-access-$(unique_dir)" &&
#    f="$(unique_file)" &&
#    mkdir "$d" &&
#    touch "$d"/"$f" &&
#    m=$(stat_mtime "$d"/"$f" &&
#    chmod 000 "$d" &&
#    sydbox -- emily utimensat -d "$d" -t 0 -e EACCES "$f" &&
#    chmod 700 "$d" &&
#    test_path_has_mtime "$m" "$d"/"$f"
#'

test_expect_success_foreach_option 'utimensat(AT_FDCWD, $nodir/$file, 0s, 0) returns ENOTDIR' '
    d="non-$(unique_dir)" &&
    touch "$d" &&
    sydbox -- emily utimensat -d cwd -t 0 -e ENOTDIR "$d"/foo
'

test_expect_success_foreach_option 'utimensat($nodir, $file, 0s, 0) returns ENOTDIR' '
    d="non-$(unique_dir)" &&
    touch "$d" &&
    sydbox -- emily utimensat -d "$d" -t 0 -e ENOTDIR "$d"/foo
'

test_expect_success_foreach_option SYMLINKS 'utimensat(AT_FDCWD, $symlink-self, 0s, 0) returns ELOOP' '
    l="self-$(unique_link)" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily utimensat -d cwd -t 0 -e ELOOP "$l"
'

test_expect_success_foreach_option SYMLINKS 'utimensat($dir, $symlink-self, 0s, 0) returns ELOOP' '
    d="$(unique_dir)" &&
    l="self-$(unique_link)" &&
    mkdir "$d" &&
    (
        cd "$d" &&
        ln -sf "$l" "$l"
    ) &&
    sydbox -- emily utimensat -d "$d" -t 0 -e ELOOP "$l"
'

test_expect_success_foreach_option SYMLINKS 'utimensat(AT_FDCWD, $symlink-circular, 0s, 0) returns ELOOP' '
    l0="loop0-$(unique_link)" &&
    l1="loop1-$(unique_link)" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily utimensat -d cwd -t 0 -e ELOOP "$l0"
'

test_expect_success_foreach_option SYMLINKS 'utimensat($dir, $symlink-circular, 0s, 0) returns ELOOP' '
    d="$(unique_dir)" &&
    l0="loop0-$(unique_link)" &&
    l1="loop1-$(unique_link)" &&
    mkdir "$d" &&
    (
        cd "$d"
        ln -sf "$l0" "$l1" &&
        ln -sf "$l1" "$l0"
    ) &&
    sydbox -- emily utimensat -d "$d" -t 0 -e ELOOP "$l0"
'

test_expect_success_foreach_option 'deny utimensat(-1, $abspath, 0s, 0) with EPERM' '
    f="$(unique_file)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily utimensat -e EPERM -d null -t 0 "$HOME_RESOLVED"/"$f" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'deny utimensat(AT_FDCWD, $file, 0s, 0)' '
    f="$(unique_file)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily utimensat -e EPERM -d cwd -t 0 "$f" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'deny utimensat(AT_FDCWD, $nofile, 0s, 0)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily utimensat -e ENOENT -d cwd -t 0 no"$f"
'

test_expect_success_foreach_option 'deny utimensat(AT_FDCWD, $symlink-file, 0s, 0)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily utimensat -e EPERM -d cwd -t 0 "$l" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'deny utimensat($fd, $file, 0s, 0)' '
    f="$(unique_file)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily utimensat -e EPERM -d "$HOME" -t 0 "$f" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'deny utimensat($fd, $nofile, 0s, 0)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily utimensat -e ENOENT -d cwd -t 0 no"$f"
'

test_expect_success_foreach_option SYMLINKS 'deny utimensat($fd, $symlink-file, 0s, 0)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily utimensat -e EPERM -d cwd -t 0 "$l" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'denylist utimensat(-1, $abspath, 0s, 0)' '
    f="$(unique_file)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e EPERM -d null -t 0 "$HOME_RESOLVED"/"$f" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'denylist utimensat(AT_FDCWD, $file, 0s, 0)' '
    f="$(unique_file)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e EPERM -d cwd -t 0 "$f" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'denylist utimensat(AT_FDCWD, $nofile, 0s, 0)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e ENOENT -d cwd -t 0 no"$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist utimensat(AT_FDCWD, $symlink-file, 0s, 0)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e EPERM -d cwd -t 0 "$l" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'denylist utimensat($fd, $file, 0s, 0)' '
    f="$(unique_file)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e EPERM -d "$HOME" -t 0 "$f" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'denylist utimensat($fd, $nofile, 0s, 0)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e ENOENT -d cwd -t 0 no"$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist utimensat($fd, $symlink-file, 0s, 0)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    m=$(stat_mtime "$f") &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e EPERM -d cwd -t 0 "$l" &&
    test_path_has_mtime "$m" "$f"
'

test_expect_success_foreach_option 'allowlist utimensat(-1, $abspath, 0s, 0)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e ERRNO_0 -d null -t 0 "$HOME_RESOLVED"/"$f" &&
    test_path_has_mtime 0 "$f"
'

test_expect_success_foreach_option 'allowlist utimensat(AT_FDCWD, $file, 0s, 0)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e ERRNO_0 -d cwd -t 0 "$f" &&
    test_path_has_mtime 0 "$f"
'

test_expect_success_foreach_option SYMLINKS 'allowlist utimensat(AT_FDCWD, $symlink-file, 0s, 0)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e ERRNO_0 -d cwd -t 0 "$l" &&
    test_path_has_mtime 0 "$f"
'

test_expect_success_foreach_option 'allowlist utimensat($fd, $file, 0s, 0)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e ERRNO_0 -d "$HOME" -t 0 "$f" &&
    test_path_has_mtime 0 "$f"
'

test_expect_success_foreach_option SYMLINKS 'allowlist utimensat($fd, $symlink-file, 0s, 0)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily utimensat -e ERRNO_0 -d "$HOME" -t 0 "$l" &&
    test_path_has_mtime 0 "$f"
'

test_done
