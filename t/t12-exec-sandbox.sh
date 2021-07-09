#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test execve sandboxing'
. ./test-lib.sh

for ns_mem_access in 0 1; do
    test_expect_success "exec sandboxing = allow [memory_access:${ns_mem_access}]" '
    syd \
        --memaccess '${ns_mem_access}' \
        -y core/sandbox/read:off \
        -y core/sandbox/write:off \
        -y core/sandbox/exec:allow \
        -y core/sandbox/network:off \
        -- \
        sh -c "\"'$TRUE_BIN'\" || exit 7"
'

    test_expect_success "exec sandboxing = deny [memory_access:${ns_mem_access}]" '
    test_expect_code 7 syd \
        --memaccess '${ns_mem_access}' \
        -y core/sandbox/read:off \
        -y core/sandbox/write:off \
        -y core/sandbox/exec:deny \
        -y core/sandbox/network:off \
        -- \
        sh -c "\"'$TRUE_BIN'\" || exit 7"
'

    test_expect_failure "exec sandboxing = allow, denylist with stat [memory_access:${ns_mem_access}]" '
    test_expect_code 7 syd \
        --memaccess '${ns_mem_access}' \
        -y core/sandbox/read:off \
        -y core/sandbox/write:off \
        -y core/sandbox/exec:allow \
        -y core/sandbox/network:off \
        -- \
        sh -c "test -e /dev/sydbox/allowlist/exec+\"'$TRUE_BIN'\"; true || exit 7"
'

    test_expect_success "exec sandboxing = deny, allowlist with stat [memory_access:${ns_mem_access}]" '
    test_expect_code 0 syd \
        --memaccess '${ns_mem_access}' \
        -y core/sandbox/read:off \
        -y core/sandbox/write:off \
        -y core/sandbox/exec:deny \
        -y core/sandbox/network:off \
        -- \
        sh -c "test -e /dev/sydbox/allowlist/exec+\"'$TRUE_BIN'\"; true || exit 7"
'

done

test_done
