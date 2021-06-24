#!/bin/sh
# Copyright 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the very basics of sydbox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=
export SYDBOX_TEST_OPTIONS

test_expect_success 'sydbox: compatible --help with sydbox-0' '
    syd --help
'

test_expect_success 'sydbox: compatible --version with sydbox-0' '
    syd --version
'

test_expect_success 'sydfmt: compatible --help with sydfmt-0' '
    syd-format --help
'

test_expect_success 'sydfmt: compatible --version with sydfmt-0' '
    syd-format --version
'

test_done
