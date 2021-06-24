#!/bin/sh
# Copyright 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the very basics of sydbox'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=
export SYDBOX_TEST_OPTIONS

test_expect_success 'sydbox: compatible --help with sydbox-0' '
    sydbox --help
'

test_expect_success 'sydbox: compatible --version with sydbox-0' '
    sydbox --version
'

test_expect_success 'sydfmt: compatible --help with sydfmt-0' '
    sydfmt --help
'

test_expect_success 'sydfmt: compatible --version with sydfmt-0' '
    sydfmt --version
'

test_done
