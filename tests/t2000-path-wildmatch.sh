#!/bin/sh
# Copyright 2010, 2012 Ali Polatel <alip@exherbo.org>
# Released under the terms of the 3-clause BSD license

test_description='check wildmatch'
. ./test-lib.sh

test_external_has_tap=1

test_external "wildmatch" wildtest "${TEST_DIRECTORY}"/wildtest.txt

test_done
