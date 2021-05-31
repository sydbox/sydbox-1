#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox fchmodat(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'fchmodat(AT_FDCWD, $file) returns ERRNO_0' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ERRNO_0 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success_foreach_option 'fchmodat($dir, $file) returns ERRNO_0' '
    f="$(unique_file)" &&
    d="$(unique_dir)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    chmod 600 "$d"/"$f" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ERRNO_0 "$f" &&
    test_path_is_not_readable "$d"/"$f" &&
    test_path_is_not_writable "$d"/"$f"
'

test_expect_success_foreach_option SYMLINKS 'fchmodat(AT_FDCWD, $symlink) returns ERRNO_0' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ERRNO_0 "$l"
    test_path_is_not_readable "$d"/"$f" &&
    test_path_is_not_writable "$d"/"$f"
'

test_expect_success_foreach_option SYMLINKS 'fchmodat($dir, $symlink) returns ERRNO_0' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    d="$(unique_dir)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    chmod 600 "$d"/"$f" &&
    ln -sf "$f" "$d"/"$l" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ERRNO_0 "$l" &&
    test_path_is_not_readable "$d"/"$f" &&
    test_path_is_not_writable "$d"/"$f"
'

test_expect_success_foreach_option 'fchmodat(AT_FDCWD, NULL) returns EFAULT' '
    sydbox -- emily fchmodat -d cwd -m 000 -e EFAULT
'

test_expect_success_foreach_option 'fchmodat($dir, NULL) returns EFAULT' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e EFAULT
'

test_expect_success_foreach_option 'fchmodat($badfd, $file) returns EBADF' '
    f="no-$(unique_file)" &&
    sydbox -- emily fchmodat -d null -m 000 -e EBADF "$f"
'

test_expect_success_foreach_option 'fchmodat($badfd, "") returns ENOENT' '
    sydbox -- emily fchmodat -d null -m 000 -e ENOENT ""
'

test_expect_success_foreach_option 'fchmodat(AT_FDCWD, "") returns ENOENT' '
    sydbox -- emily fchmodat -d cwd -m 000 -e ENOENT ""
'

test_expect_success_foreach_option 'fchmodat($dir, "") returns ENOENT' '
    d="$(unique_dir)" &&
    mkdir "$d" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ENOENT ""
'

test_expect_success_foreach_option 'fchmodat(AT_FDCWD, $nofile) returns ENOENT' '
    f="no-$(unique_file)" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ENOENT "$f"
'

test_expect_success_foreach_option 'fchmodat($dir, $nofile) returns ENOENT' '
    f="no-$(unique_file)" &&
    d="$(unique_dir)" &&
    mkdir "$d" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ENOENT "$f"
'

test_expect_success_foreach_option 'fchmodat(AT_FDCWD, $noaccess/$file) returns EACCES' '
    d="no-access-$(unique_dir)" &&
    f="$(unique_file)" &&
    mkdir "$d" &&
    touch "$d"/"$f" &&
    chmod 600 "$d"/"$f" &&
    test_when_finished "chmod 700 $d" && chmod 000 "$d" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e EACCES "$d"/"$f" &&
    chmod 700 "$d" &&
    test_path_is_readable "$d"/"$f" &&
    test_path_is_writable "$d"/"$f"
'

# TODO: emily limitation, not easy to test...
#test_expect_success_foreach_option 'fchmodat($noaccess, $file) returns EACCES' '
#    d="no-access-$(unique_dir)" &&
#    f="$(unique_file)" &&
#    mkdir "$d" &&
#    touch "$d"/"$f" &&
#    chmod 600 "$d"/"$f" &&
#    chmod 000 "$d" &&
#    sydbox -- emily fchmodat -d "$d" -m 000 -e EACCES "$f" &&
#    chmod 700 "$d" &&
#    test_path_is_readable "$d"/"$f" &&
#    test_path_is_writable "$d"/"$f"
#'

test_expect_success_foreach_option 'fchmodat(AT_FDCWD, $nodir/$file) returns ENOTDIR' '
    d="non-$(unique_dir)" &&
    touch "$d" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ENOTDIR "$d"/foo
'

test_expect_success_foreach_option 'fchmodat($nodir, $file) returns ENOTDIR' '
    d="non-$(unique_dir)" &&
    touch "$d" &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ENOTDIR "$d"/foo
'

test_expect_success_foreach_option SYMLINKS 'fchmodat(AT_FDCWD, $symlink-self) returns ELOOP' '
    l="self-$(unique_link)" &&
    ln -sf "$l" "$l" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ELOOP "$l"
'

test_expect_success_foreach_option SYMLINKS 'fchmodat($dir, $symlink-self) returns ELOOP' '
    d="$(unique_dir)" &&
    l="self-$(unique_link)" &&
    mkdir "$d" &&
    (
        cd "$d" &&
        ln -sf "$l" "$l"
    ) &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ELOOP "$l"
'

test_expect_success_foreach_option SYMLINKS 'fchmodat(AT_FDCWD, $symlink-circular) returns ELOOP' '
    l0="loop0-$(unique_link)" &&
    l1="loop1-$(unique_link)" &&
    ln -sf "$l0" "$l1" &&
    ln -sf "$l1" "$l0" &&
    sydbox -- emily fchmodat -d cwd -m 000 -e ELOOP "$l0"
'

test_expect_success_foreach_option SYMLINKS 'fchmodat($dir, $symlink-circular) returns ELOOP' '
    d="$(unique_dir)" &&
    l0="loop0-$(unique_link)" &&
    l1="loop1-$(unique_link)" &&
    mkdir "$d" &&
    (
        cd "$d"
        ln -sf "$l0" "$l1" &&
        ln -sf "$l1" "$l0"
    ) &&
    sydbox -- emily fchmodat -d "$d" -m 000 -e ELOOP "$l0"
'

test_expect_success_foreach_option 'deny fchmodat(-1, $abspath) with EPERM' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d null -m 000 "$HOME_RESOLVED"/"$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'deny fchmodat(AT_FDCWD, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'deny fchmodat(AT_FDCWD, $nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e ENOENT -d cwd -m 000 no"$f"
'

test_expect_success_foreach_option 'deny fchmodat(AT_FDCWD, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'deny fchmodat($fd, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d "$HOME" -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'deny fchmodat($fd, $nofile)' '
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e ENOENT -d cwd -m 000 no"$f"
'

test_expect_success_foreach_option SYMLINKS 'deny fchmodat($fd, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'blacklist fchmodat(-1, $abspath)' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d null -m 000 "$HOME_RESOLVED"/"$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'blacklist fchmodat(AT_FDCWD, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'blacklist fchmodat(AT_FDCWD, $nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ENOENT -d cwd -m 000 no"$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist fchmodat(AT_FDCWD, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'blacklist fchmodat($fd, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d "$HOME" -m 000 "$f" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'blacklist fchmodat($fd, $nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ENOENT -d cwd -m 000 no"$f"
'

test_expect_success_foreach_option SYMLINKS 'blacklist fchmodat($fd, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "blacklist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e EPERM -d cwd -m 000 "$l" &&
    test_path_is_readable "$f" &&
    test_path_is_writable "$f"
'

test_expect_success_foreach_option 'whitelist fchmodat(-1, $abspath)' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d null -m 000 "$HOME_RESOLVED"/"$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success_foreach_option 'whitelist fchmodat(AT_FDCWD, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d cwd -m 000 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success_foreach_option SYMLINKS 'whitelist fchmodat(AT_FDCWD, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d cwd -m 000 "$l" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success_foreach_option 'whitelist fchmodat($fd, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d "$HOME" -m 000 "$f" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_expect_success_foreach_option SYMLINKS 'whitelist fchmodat($fd, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_RESOLVED/**" \
        -- emily fchmodat -e ERRNO_0 -d "$HOME" -m 000 "$l" &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_done
