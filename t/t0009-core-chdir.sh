#!/bin/sh
# Copyright 2013, 2014 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test child directory tracking'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=
export SYDBOX_TEST_OPTIONS

test_expect_success 'chdir() hook with EEXIST (mkdir -p) [RAISE_SAFE=0]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m core/violation/raise_safe:0 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EEXIST (mkdir -p) [RAISE_SAFE=0]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -m core/violation/raise_safe:1 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    rm -fr "$cdir" &&
    test_expect_code 1 sydbox \
        -m core/sandbox/write:deny \
        -m core/violation/raise_safe:0 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0,WHITELIST]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    rm -fr "$cdir" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m whitelist/write+"$HOMER"/"${cdir}" \
        -m core/violation/raise_safe:0 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EEXIST (mkdir -p) [RAISE_SAFE=0]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m core/violation/raise_safe:0 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EEXIST (mkdir -p) [RAISE_SAFE=1]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    test_must_violate sydbox \
        -m core/sandbox/write:deny \
        -m core/violation/raise_safe:1 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    rm -fr "$cdir" &&
    test_expect_code 1 sydbox \
        -m core/sandbox/write:deny \
        -m core/violation/raise_safe:0 \
        syd-mkdir-p "$cdir"
'

test_expect_success 'chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0,WHITELIST]' '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    rm -fr "$cdir" &&
    sydbox \
        -m core/sandbox/write:deny \
        -m whitelist/write+"$HOMER"/"${cdir}" \
        -m core/violation/raise_safe:0 \
        syd-mkdir-p "$cdir"
'

test_done
