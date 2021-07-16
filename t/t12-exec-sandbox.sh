#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test execve sandboxing'
. ./test-lib.sh

for ns_mem_access in 0 1; do
    test_expect_failure "exec sandboxing = allow [memory_access:${ns_mem_access}]" '
    syd \
        --memaccess '${ns_mem_access}' \
        -y core/sandbox/read:allow \
        -y core/sandbox/write:allow \
        -y core/sandbox/exec:allow \
        -y core/sandbox/network:allow \
        -- \
        ./bin/syd-true
'

    test_expect_success "exec sandboxing = deny [memory_access:${ns_mem_access}]" '
    test_expect_code 139 syd \
        --memaccess '${ns_mem_access}' \
        -y core/sandbox/read:allow \
        -y core/sandbox/write:allow \
        -y core/sandbox/exec:deny \
        -y core/sandbox/network:allow \
        -- \
        ./bin/syd-true
'

    test_expect_success "exec sandboxing = allow, denylist with stat [memory_access:${ns_mem_access}]" '
    test_expect_code 2 syd \
        --memaccess '${ns_mem_access}' \
        -y core/sandbox/read:allow \
        -y core/sandbox/write:allow \
        -y core/sandbox/exec:allow \
        -y core/sandbox/network:allow \
        -- \
        sh -c "test -e /dev/sydbox/allowlist/exec+\"$(readlink -f .)/bin/syd-true\";\
                ./bin/syd-true"
'

    test_expect_failure "exec sandboxing = deny, allowlist with stat [memory_access:${ns_mem_access}]" '
    test_expect_code 0 syd \
        --memaccess '${ns_mem_access}' \
        -y core/sandbox/read:allow \
        -y core/sandbox/write:allow \
        -y core/sandbox/exec:deny \
        -y core/sandbox/network:allow \
        -- \
        sh -c "test -e /dev/sydbox/allowlist/exec+\"$(readlink -f .)/bin/syd-true\"; \
                ./bin/syd-true"
'

done

test_done
