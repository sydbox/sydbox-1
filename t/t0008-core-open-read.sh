#!/bin/sh
# Copyright 2013, 2014, 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the read sandboxing for open of sydbox'
. ./test-lib.sh

for cor_mem_access in 0 1 2 3; do
# Note, we use test_must_fail here rather than ! so we know if sydbox exits
# abnormally, eg. segfaults.
    test_expect_success \
        "read sandboxing for open works [memory_access:${cor_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    test_must_fail sydbox \
        -M '${cor_mem_access}' \
        -m core/sandbox/read:deny \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:off \
        syd-open-static "$cdir"/readme rdonly
'

    test_expect_success \
        "read sandboxing for open works with allowlist [memory_access:${cor_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    sydbox \
        -M '${cor_mem_access}' \
        -m core/sandbox/read:deny \
        -m "allowlist/read+/***" \
        syd-open-static "$cdir"/readme rdonly
'
done

test_done
