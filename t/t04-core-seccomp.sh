#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the basics of seccomp filters'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=
export SYDBOX_TEST_OPTIONS

test_expect_success 'export bpf options to standard error' '
    env SHOEBOX_PFC= syd --export pfc true 2>out &&
    cat out &&
    test -s out &&
    grep "pseudo filter code start" out &&
    grep "pseudo filter code end" out &&
    grep "invalid architecture action" out
'

test_expect_success 'export bpf options to file' '
    syd --export pfc:out true &&
    cat out &&
    test -s out &&
    grep "pseudo filter code start" out &&
    grep "pseudo filter code end" out &&
    grep "invalid architecture action" out
'

test_expect_success GREP_P 'invalid architecture action is kill ' '
    syd noexec &&
    test_bpf_action "invalid architecture" KILL
'

test_expect_success GREP_P 'default action is allow' '
    syd noexec &&
    test_bpf_action default LOG
'

test_expect_success GREP_P 'default action is allow with --bpf-only' '
    syd -b noexec &&
    test_bpf_action default LOG
'

test_expect_success GREP_P 'default action is allow with read sandboxing bpf' '
    syd \
        -y core/sandbox/read:bpf \
        -y core/sandbox/write:allow \
        -y core/sandbox/exec:allow \
        -y core/sandbox/network:allow \
        noexec &&
    test_bpf_action default LOG
'

test_expect_success GREP_P 'default action is allow with write sandboxing bpf' '
    syd \
        -y core/sandbox/read:allow \
        -y core/sandbox/write:bpf \
        -y core/sandbox/exec:allow \
        -y core/sandbox/network:allow \
        noexec &&
    test_bpf_action default LOG
'

test_expect_success 'default action is allow with exec sandboxing bpf' '
    syd \
        -y core/sandbox/read:allow \
        -y core/sandbox/write:bpf \
        -y core/sandbox/exec:bpf \
        -y core/sandbox/network:allow \
        noexec &&
    test_bpf_action default LOG
'

test_expect_success 'default action is allow with network sandboxing bpf' '
    syd \
        -y core/sandbox/read:allow \
        -y core/sandbox/write:allow \
        -y core/sandbox/exec:allow \
        -y core/sandbox/network:bpf \
        noexec &&
    test_bpf_action default LOG
'

test_done
