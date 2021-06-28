#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test network sandboxing'
. ./test-lib.sh

for ns_mem_access in 0 1; do
    test_expect_failure DIG "network sandboxing = allow [memory_access:${ns_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:allow \
        dig +noall +answer @${PUBLIC_DNS} ${PUBLIC_HOST} > "$cdir"/out &&
    test -s "$cdir"/out
'

    test_expect_failure DIG "network sandboxing = deny [memory_access:${ns_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    test_must_violate syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:deny \
        -m allowlist/network/bind+inet:0.0.0.0@0 \
        -m allowlist/network/bind+LOOPBACK6@0 \
        -m allowlist/network/bind+LOOPBACK@0 \
        -- dig +retry=1 +ignore +noall +answer @${PUBLIC_DNS} ${PUBLIC_HOST}
'

    test_expect_success PY3 \
        "network sandboxing for connect works to deny IPv4 address [memory_access:${ns_mem_access}]" '
    test_expect_code 111 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        syd-connect-ipv4.py
'

    test_expect_success HAVE_IPV6,PY3 \
        "network sandboxing for connect works to deny IPv6 address [memory_access:${ns_mem_access}]" '
    test_expect_code 111 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        syd-connect-ipv6.py
'

    test_expect_success PY3 \
        "network sandboxing for bind works to deny UNIX socket [memory_access:${ns_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    test_expect_code 99 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        syd-connect-unix.py "$pdir"
'

    test_expect_success PY3 \
        "network sandboxing for bind works to deny IPv4 address with port zero [memory_access:${ns_mem_access}]" '
    test_expect_code 99 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        syd-connect-ipv4-0.py
'

    test_expect_success PY3 \
        "network sandboxing for bind works to deny IPv6 address with port zero [memory_access:${ns_mem_access}]" '
    test_expect_code 99 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        syd-connect-ipv6-0.py
'

    test_expect_success PY3 \
        "network sandboxing for bind works to allowlist IPv4 address [memory_access:${ns_mem_access}]" '
    test_expect_code 0 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m allowlist/network/bind+LOOPBACK@65534 \
        syd-bind-ipv4-port.py 65534
'

    test_expect_success PY3 \
        "network sandboxing for bind works to allowlist IPv6 address [memory_access:${ns_mem_access}]" '
    test_expect_code 0 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m allowlist/network/bind+LOOPBACK6@65534 \
        syd-bind-ipv6-port.py 65534
'

# TODO: Continue moving the python3 scripts in HERE docs to test-bin/
    test_expect_success PY3 \
        "network sandboxing for bind works to allowlist IPv4 address with port zero [memory_access:${ns_mem_access}]" '
    test_expect_code 0 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m allowlist/network/bind+LOOPBACK@0 \
        python3 <<EOF
import errno, socket, sys

addr = socket.getaddrinfo("127.0.0.1", 0)[0][4]
probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    probe.bind(addr)
except OSError as e:
    sys.exit(e.errno)
except Exception as e:
    sys.stderr.write("Unexpected exception: %r\n" % e)
    sys.exit(128)
else:
    sys.exit(0)
finally:
   probe.close()
EOF
'

    test_expect_success PY3 \
        "network sandboxing for bind works to allowlist IPv6 address with port zero [memory_access:${ns_mem_access}]" '
    test_expect_code 0 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m allowlist/network/bind+LOOPBACK6@0 \
        python3 <<EOF
import errno, socket, sys

addr = socket.getaddrinfo("::1", 0)[0][4]
probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
try:
    probe.bind(addr)
except OSError as e:
    sys.exit(e.errno)
except Exception as e:
    sys.stderr.write("Unexpected exception: %r\n" % e)
    sys.exit(128)
else:
    sys.exit(0)
finally:
   probe.close()
EOF
'
        test_expect_success PY3 \
        "network sandboxing for bind works to auto-allowlist UNIX socket [memory_access:${ns_mem_access}]" '
pdir="$(unique_dir)" &&
mkdir "$pdir" &&
cd "$pdir" &&
test_expect_code 0 syd \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m "allowlist/network/bind+unix:$HOMER/${pdir}/test.socket" \
        syd-bind-auto-unix-socket.py &&
cd "$HOMER"
'
done

test_done
