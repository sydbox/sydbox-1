#!/bin/sh
# Copyright 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the read sandboxing for open of sydbox'
. ./test-lib.sh

for cor_mem_access in 0 1; do
# Note, we use test_must_fail here rather than ! so we know if sydbox exits
# abnormally, eg. segfaults.
    test_expect_success \
        "read sandboxing for open works [memory_access:${cor_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    test_must_fail syd \
        --memaccess '${cor_mem_access}' \
        -y core/sandbox/read:deny \
        -y core/sandbox/write:allow \
        -y core/sandbox/exec:allow \
        -y core/sandbox/network:allow \
        syd-open-static "$cdir"/readme rdonly
'

    test_expect_failure \
        "read sandboxing for open works with allowlist [memory_access:${cor_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    syd \
        --memaccess '${cor_mem_access}' \
        -y core/sandbox/read:deny \
        -y "allowlist/read+/***" \
        syd-open-static "$cdir"/readme rdonly
'
done

test_done
