#!/bin/sh
# Copyright 2013, 2014 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test child directory tracking'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=
export SYDBOX_TEST_OPTIONS

for magic_mem_access in 0 1; do
    test_expect_success "chdir() hook with EEXIST (mkdir -p) [RAISE_SAFE=0,memory_access:${magic_mem_access}]" '
        pdir="$(unique_dir)" &&
        mkdir "$pdir" &&
        cdir="${pdir}/$(unique_dir)" &&
        mkdir "$cdir" &&
        syd \
            --memaccess '${magic_mem_access}' \
            -y core/sandbox/write:deny \
            -y core/violation/raise_safe:0 \
            syd-mkdir-p "$cdir"
    '

    test_expect_failure "chdir() hook with EEXIST (mkdir -p) [RAISE_SAFE=0,memory_access:${magic_mem_access}]" '
        pdir="$(unique_dir)" &&
        mkdir "$pdir" &&
        cdir="${pdir}/$(unique_dir)" &&
        mkdir "$cdir" &&
        test_must_violate syd \
            --memaccess '${magic_mem_access}' \
            -y core/sandbox/write:deny \
            -y core/violation/raise_safe:1 \
            syd-mkdir-p "$cdir"
    '

    test_expect_success "chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0,memory_access:${magic_mem_access}]" '
        pdir="$(unique_dir)" &&
        mkdir "$pdir" &&
        cdir="${pdir}/$(unique_dir)" &&
        rm -fr "$cdir" &&
        test_expect_code 1 syd \
            --memaccess '${magic_mem_access}' \
            -y core/sandbox/write:deny \
            -y core/violation/raise_safe:0 \
            syd-mkdir-p "$cdir"
    '

    test_expect_success "chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0,ALLOWLIST,memory_access:${magic_mem_access}]" '
        pdir="$(unique_dir)" &&
        mkdir "$pdir" &&
        cdir="${pdir}/$(unique_dir)" &&
        rm -fr "$cdir" &&
        syd \
            --memaccess '${magic_mem_access}' \
            -y core/sandbox/write:deny \
            -y allowlist/write+"$HOMER"/"${cdir}" \
            -y core/violation/raise_safe:0 \
            syd-mkdir-p "$cdir"
    '

    test_expect_success "chdir() hook with EEXIST (mkdir -p) RAISE_SAFE=0,memory_access:${magic_mem_access}]" '
        pdir="$(unique_dir)" &&
        mkdir "$pdir" &&
        cdir="${pdir}/$(unique_dir)" &&
        mkdir "$cdir" &&
        syd \
            --memaccess '${magic_mem_access}' \
            -y core/sandbox/write:deny \
            -y core/violation/raise_safe:0 \
            syd-mkdir-p "$cdir"
    '

    test_expect_failure "chdir() hook with EEXIST (mkdir -p) [RAISE_SAFE=1,memory_access:${magic_mem_access}]" '
        pdir="$(unique_dir)" &&
        mkdir "$pdir" &&
        cdir="${pdir}/$(unique_dir)" &&
        mkdir "$cdir" &&
        test_must_violate syd \
            --memaccess '${magic_mem_access}' \
            -y core/sandbox/write:deny \
            -y core/violation/raise_safe:1 \
            syd-mkdir-p "$cdir"
    '

    test_expect_success "chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0,memory_access:${magic_mem_access}]" '
        pdir="$(unique_dir)" &&
        mkdir "$pdir" &&
        cdir="${pdir}/$(unique_dir)" &&
        rm -fr "$cdir" &&
        test_expect_code 1 syd \
            --memaccess '${magic_mem_access}' \
            -y core/sandbox/write:deny \
            -y core/violation/raise_safe:0 \
            syd-mkdir-p "$cdir"
    '

    test_expect_success "chdir() hook with EPERM (mkdir -p) [RAISE_SAFE=0,ALLOWLIST,memory_access:${magic_mem_access}]" '
        pdir="$(unique_dir)" &&
        mkdir "$pdir" &&
        cdir="${pdir}/$(unique_dir)" &&
        rm -fr "$cdir" &&
        syd \
            --memaccess '${magic_mem_access}' \
            -y core/sandbox/write:deny \
            -y allowlist/write+"$HOMER"/"${cdir}" \
            -y core/violation/raise_safe:0 \
            syd-mkdir-p "$cdir"
    '
done

test_done
