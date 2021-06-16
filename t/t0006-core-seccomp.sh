#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test the basics of seccomp filters'
. ./test-lib.sh

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS=
export SYDBOX_TEST_OPTIONS

test_expect_success 'export bpf options to standard error' '
    sydbox --export pfc true 2>out &&
    cat out &&
    test -s out &&
    grep "pseudo filter code start" out &&
    grep "pseudo filter code end" out &&
    grep "invalid architecture action" out
'

test_expect_success 'export bpf options to file' '
    sydbox --export pfc:out true &&
    cat out &&
    test -s out &&
    grep "pseudo filter code start" out &&
    grep "pseudo filter code end" out &&
    grep "invalid architecture action" out
'

# perl -e '$f=join("",<>); print $& if $f=~/foo\nbar.*\n/m' file
# perl -n000e 'print $& while /^foo.*\nbar.*\n/mg' file

save_SYDBOX_TEST_OPTIONS="$SYDBOX_TEST_OPTIONS"
SYDBOX_TEST_OPTIONS="--export=pfc:bpf.pfc"
export SYDBOX_TEST_OPTIONS

test_expect_success 'invalid architecture action is kill ' '
    rm -f bpf.pfc &&
    sydbox true &&
    test_bpf_action bpf.pfc "invalid architecture" KILL
'

test_expect_success 'default action is allow' '
    rm -f bpf.pfc &&
    sydbox true &&
    test_bpf_action bpf.pfc default ALLOW
'

test_expect_success 'default action is allow with --bpf-only' '
    rm -f bpf.pfc &&
    sydbox -b true &&
    test_bpf_action bpf.pfc default ALLOW
'

test_expect_success 'default action is permission denied with Level 1 restrictions' '
    rm -f bpf.pfc &&
    sydbox -b -m core/restrict/general:1 true &&
    test_bpf_action bpf.pfc default "ERRNO\(1\)"
'

test_expect_success 'default action is permission denied with -b and Level 1 restrictions' '
    rm -f bpf.pfc &&
    sydbox -b -m core/restrict/general:1 true &&
    test_bpf_action bpf.pfc default "ERRNO\(1\)"
'

test_expect_success 'default action is permission denied with Level 2 restrictions' '
    rm -f bpf.pfc &&
    sydbox -b -m core/restrict/general:2 true &&
    test_bpf_action bpf.pfc default "ERRNO\(1\)"
'

test_expect_success 'default action is permission denied with -b and Level 2 restrictions' '
    rm -f bpf.pfc &&
    sydbox -b -m core/restrict/general:2 true &&
    test_bpf_action bpf.pfc default "ERRNO\(1\)"
'

test_expect_success 'default action is permission denied with Level 3 restrictions' '
    rm -f bpf.pfc &&
    sydbox -b -m core/restrict/general:3 true &&
    test_bpf_action bpf.pfc default "ERRNO\(1\)"
'

test_expect_success 'default action is permission denied with -b and Level 3 restrictions' '
    rm -f bpf.pfc &&
    sydbox -b -m core/restrict/general:3 true &&
    test_bpf_action bpf.pfc default "ERRNO\(1\)"
'

test_expect_success 'default action is allow with read sandboxing bpf' '
    rm -f bpf.pfc &&
    sydbox \
        -m core/sandbox/read:bpf \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:off \
        true &&
    test_bpf_action bpf.pfc default ALLOW
'

test_expect_success 'default action is allow with write sandboxing bpf' '
    rm -f bpf.pfc &&
    sydbox \
        -m core/sandbox/read:off \
        -m core/sandbox/write:bpf \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:off \
        true &&
    test_bpf_action bpf.pfc default ALLOW
'

test_expect_failure 'default action is allow with exec sandboxing bpf' '
    test_expect_code 1 sydbox \
        -m core/sandbox/read:off \
        -m core/sandbox/write:bpf \
        -m core/sandbox/exec:bpf \
        -m core/sandbox/network:off \
        true &&
    test_bpf_action bpf.pfc default ALLOW
'

test_expect_success 'default action is allow with network sandboxing bpf' '
    rm -f bpf.pfc &&
    sydbox \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:bpf \
        true &&
    test_bpf_action bpf.pfc default ALLOW
'

test_done
