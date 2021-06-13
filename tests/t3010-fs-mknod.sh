#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010, 2012, 2013 Ali Polatel <alip@exherbo.org>
# SPDX-License-Identifier: GPL-2.0-only

test_description='sandbox mknod(2)'
. ./test-lib.sh

SYDBOX_TEST_OPTIONS="
    $SYDBOX_TEST_OPTIONS
    -mcore/violation/raise_fail:1
    -mcore/violation/raise_safe:1
"

test_expect_success_foreach_option 'deny mknod(NULL) with EFAULT' '
    sydbox -- emily mknod -e EFAULT
'

test_expect_success_foreach_option FIFOS 'deny mknod()' '
    p="no-$(unique_fifo)" &&
    test_must_violate sydbox \
        -ESYDBOX_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- emily mknod -e EPERM "$p" &&
    test_path_is_missing "$p"
'

test_expect_success_foreach_option FIFOS 'deny mknod() for existant fifo' '
    p="$(unique_fifo)" &&
    mknod "$p" p &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -- emily mknod -e EEXIST "$p"
'

test_expect_success_foreach_option FIFOS 'allowlist mknod()' '
    p="no-$(unique_fifo)" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily mknod -e ERRNO_0 "$p" &&
    test_path_is_fifo "$p"
'

test_expect_success_foreach_option FIFOS 'allowlist mknod() for existant fifo' '
    p="$(unique_fifo)" &&
    mknod "$p" p
    sydbox \
        -m core/sandbox/write:deny \
        -m "allowlist/write+$HOME_RESOLVED/**" \
        -- emily mknod -e EEXIST "$p"
'

test_expect_success_foreach_option FIFOS 'denylist mknod()' '
    p="no-$(unique_fifo)" &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily mknod -e EPERM "$p" &&
    test_path_is_missing "$p"
'

test_expect_success_foreach_option FIFOS 'deny mknod() for existant fifo' '
    p="$(unique_fifo)" &&
    mknod "$p" p &&
    test_must_violate sydbox \
        -m core/sandbox/write:allow \
        -m "denylist/write+$HOME_RESOLVED/**" \
        -- emily mknod -e EEXIST "$p"
'

test_done
