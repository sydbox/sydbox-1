#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

# TODO: AT_SYMLINK_NOFOLLOW checks are missing!

test_description='sandbox fchownat(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'deny fchownat(AT_FDCWD, NULL) with EFAULT' '
    sydbox -- emily fchownat -e EFAULT -d cwd
'

test_expect_success_foreach_option 'deny fchownat(-1, $file) with EBADF' '
    f="no-$(unique_file)" &&
    sydbox -- emily fchownat -e EBADF -d null "$f"
'

test_expect_success_foreach_option 'deny fchownat(-1, $abspath) with EPERM' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d null "$HOME_RESOLVED"/"$f"
'

test_expect_success_foreach_option 'deny fchownat(AT_FDCWD, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d cwd "$f"
'

test_expect_success_foreach_option 'deny fchownat(AT_FDCWD, $nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e ENOENT -d cwd "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny fchownat(AT_FDCWD, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d cwd "$l"
'

test_expect_success_foreach_option 'deny fchownat($fd, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d "$HOME" "$f"
'

test_expect_success_foreach_option 'deny fchownat($fd, $nofile)' '
    f="$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e ENOENT -d cwd "$f"
'

test_expect_success_foreach_option SYMLINKS 'deny fchownat($fd, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily fchownat -e EPERM -d cwd "$l"
'

test_expect_success_foreach_option 'denylist fchownat(-1, $abspath)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d null "$HOME_RESOLVED"/"$f"
'

test_expect_success_foreach_option 'denylist fchownat(AT_FDCWD, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d cwd "$f"
'

test_expect_success_foreach_option 'denylist fchownat(AT_FDCWD, $nofile)' '
    f="$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ENOENT -d cwd "$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist fchownat(AT_FDCWD, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d cwd "$l"
'

test_expect_success_foreach_option 'denylist fchownat($fd, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d "$HOME" "$f"
'

test_expect_success_foreach_option 'denylist fchownat($fd, $nofile)' '
    f="no-$(unique_file)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ENOENT -d cwd "$f"
'

test_expect_success_foreach_option SYMLINKS 'denylist fchownat($fd, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e EPERM -d cwd "$l"
'

test_expect_success_foreach_option 'allowlist fchownat(-1, $abspath)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d null "$HOME_RESOLVED"/"$f"
'

test_expect_success_foreach_option 'allowlist fchownat(AT_FDCWD, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d cwd "$f"
'

test_expect_success_foreach_option SYMLINKS 'allowlist fchownat(AT_FDCWD, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d cwd "$l"
'

test_expect_success_foreach_option 'allowlist fchownat($fd, $file)' '
    f="$(unique_file)" &&
    touch "$f" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d "$HOME" "$f"
'

test_expect_success_foreach_option SYMLINKS 'allowlist fchownat($fd, $symlink-file)' '
    f="$(unique_file)" &&
    l="$(unique_link)" &&
    touch "$f" &&
    ln -sf "$f" "$l" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily fchownat -e ERRNO_0 -d "$HOME" "$l"
'

test_done
