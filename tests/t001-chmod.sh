#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chmod()'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t001_chmod

test_expect_success setup '
    rm -f file-non-existant &&
    touch file0 && chmod 600 file0 &&
    touch file1 && chmod 600 file1 &&
    touch file2 && chmod 600 file2 &&
    touch file3 && chmod 600 file3
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file1 symlink-file1 &&
    ln -sf file3 symlink-file3
'

test_expect_success 'deny chmod()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:deny \
        -- $prog file0 &&
    test_path_is_readable file0 &&
    test_path_is_writable file0
'

test_expect_success 'deny chmod() for non-existant file' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:deny \
        -- $prog file-non-existant
'

test_expect_success SYMLINKS 'deny chmod() for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:deny \
        -- $prog symlink-file1 &&
    test_path_is_readable file1 &&
    test_path_is_writable file1
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny chmod() for symbolic link outside' '
    (
        f="$(mkstemp)"
        s="symlink0-outside"
        test -n "$f" &&
        chmod 600 "$f" &&
        ln -sf "$f" $s &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:deny \
            -m "whitelist/path+$HOME_ABSOLUTE/**" \
            -- $prog $s &&
            test_path_is_readable "$f" &&
            test_path_is_writable "$f"
    )
'

test_expect_success SYMLINKS 'deny chmod() for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:deny \
        -- $prog symlink-dangling
'

test_expect_success 'allow chmod()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:deny \
        -m "whitelist/path+$HOME_ABSOLUTE/**" \
        -- $prog file2 &&
    test_path_is_not_readable file2 &&
    test_path_is_not_writable file2
'

test_expect_success SYMLINKS 'allow chmod() for symbolic link' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:deny \
        -m "whitelist/path+$HOME_ABSOLUTE/**" \
        $prog symlink-file3 &&
    test_path_is_not_readable file3 &&
    test_path_is_not_writable file3
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow chmod() for symbolic link outside' '
    (
        f="$(mkstemp)"
        s="symlink1-outside"
        test -n "$f" &&
        chmod 600 "$f" &&
        ln -sf "$f" $s &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:deny \
            -m "whitelist/path+$TEMPORARY_DIRECTORY/**" \
            $prog $s &&
        test_path_is_not_readable "$f" &&
        test_path_is_not_writable "$f"
    )
'

test_done
