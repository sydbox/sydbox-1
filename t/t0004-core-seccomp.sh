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
    test_bpf_action default ALLOW
'

test_expect_success GREP_P 'default action is allow with --bpf-only' '
    syd -b noexec &&
    test_bpf_action default ALLOW
'

test_expect_success GREP_P 'default action is permission denied with Level 1 restrictions' '
    syd -b -m core/restrict/general:1 noexec &&
    test_bpf_action default "ERRNO\(1\)"
'

test_expect_success GREP_P 'default action is permission denied with -b and Level 1 restrictions' '
    syd -b -m core/restrict/general:1 noexec &&
    test_bpf_action default "ERRNO\(1\)"
'

test_expect_success GREP_P 'default action is permission denied with Level 2 restrictions' '
    syd -b -m core/restrict/general:2 noexec &&
    test_bpf_action default "ERRNO\(1\)"
'

test_expect_success GREP_P 'default action is permission denied with -b and Level 2 restrictions' '
    syd -b -m core/restrict/general:2 noexec &&
    test_bpf_action default "ERRNO\(1\)"
'

test_expect_success GREP_P 'default action is permission denied with Level 3 restrictions' '
    syd -b -m core/restrict/general:3 noexec &&
    test_bpf_action default "ERRNO\(1\)"
'

test_expect_success GREP_P 'default action is permission denied with -b and Level 3 restrictions' '
    syd -b -m core/restrict/general:3 noexec &&
    test_bpf_action default "ERRNO\(1\)"
'

test_expect_success GREP_P 'default action is allow with read sandboxing bpf' '
    syd \
        -m core/sandbox/read:bpf \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:off \
        noexec &&
    test_bpf_action default ALLOW
'

test_expect_success GREP_P 'default action is allow with write sandboxing bpf' '
    syd \
        -m core/sandbox/read:off \
        -m core/sandbox/write:bpf \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:off \
        noexec &&
    test_bpf_action default ALLOW
'

test_expect_success 'default action is allow with exec sandboxing bpf' '
    syd \
        -m core/sandbox/read:off \
        -m core/sandbox/write:bpf \
        -m core/sandbox/exec:bpf \
        -m core/sandbox/network:off \
        noexec &&
    test_bpf_action default ALLOW
'

test_expect_success 'default action is allow with network sandboxing bpf' '
    syd \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:bpf \
        noexec &&
    test_bpf_action default ALLOW
'

test_done
