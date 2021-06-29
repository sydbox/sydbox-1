#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test execve sandboxing'
. ./test-lib.sh

for ns_mem_access in 0 1; do
    test_expect_success "exec sandboxing = allow [memory_access:${ns_mem_access}]" '
    test_expect_code 1 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:allow \
        -m core/sandbox/network:off \
        sh <<EOF
exec $(type -P false 2>/dev/null)
EOF
'

    test_expect_success "exec sandboxing = deny [memory_access:${ns_mem_access}]" '
    test_expect_code 7 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:deny \
        -m core/sandbox/network:off \
        sh <<EOF
t=$(type -P true 2>/dev/null)
echo >&2 "\$t"
"\$t"
if [[ \$? == 0 ]]; then
    exit 0
else
    exit 7
fi
EOF
'

    test_expect_failure "exec sandboxing = allow, denylist with stat [memory_access:${ns_mem_access}]" '
    test_expect_code 7 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:allow \
        -m core/sandbox/network:off \
        sh <<EOF
test -e /dev/sydbox/denylist/exec+"'$TRUE_BIN'"
"'$TRUE_BIN'"
if [[ \$? == 0 ]]; then
    exit 0
else
    exit 7
fi
EOF
'

    test_expect_success "exec sandboxing = deny, allowlist with stat [memory_access:${ns_mem_access}]" '
    test_expect_code 0 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:deny \
        -m core/sandbox/network:off \
        sh <<EOF
test -e /dev/sydbox/allowlist/exec+"'$TRUE_BIN'"
"'$TRUE_BIN'"
if [[ \$? == 0 ]]; then
    exit 0
else
    exit 7
fi
EOF
'

done

test_done
