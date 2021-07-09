#!/bin/sh
# Copyright 2010, 2012, 2014 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='check wildcard matching'
. ./test-lib.sh

test_external_has_tap=1

test_external "wildmatch" wildtest "${TEST_DIRECTORY}"/test-data/wildtest.txt

test_done
