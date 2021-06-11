#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test network sandboxing'
. ./test-lib.sh

#test_expect_success DIG 'network sandboxing = off' '
#    pdir="$(unique_dir)" &&
#    mkdir "$pdir" &&
#    cdir="${pdir}/$(unique_dir)" &&
#    mkdir "$cdir" &&
#    touch "$cdir"/readme &&
#    sydbox \
#        -m core/sandbox/read:off \
#        -m core/sandbox/write:off \
#        -m core/sandbox/exec:off \
#        -m core/sandbox/network:off \
#        dig +noall +answer dev.chessmuse.com > "$cdir"/out &&
#        test -s "$cdir"/out
#'
#
#test_expect_success DIG 'network sandboxing = allow' '
#    pdir="$(unique_dir)" &&
#    mkdir "$pdir" &&
#    cdir="${pdir}/$(unique_dir)" &&
#    mkdir "$cdir" &&
#    touch "$cdir"/readme &&
#    sydbox \
#        -m core/sandbox/read:off \
#        -m core/sandbox/write:off \
#        -m core/sandbox/exec:off \
#        -m core/sandbox/network:allow \
#        dig +noall +answer dev.chessmuse.com > "$cdir"/out &&
#    test -s "$cdir"/out
#'
#
## TODO should be test_must_violate rather than test_must_fail
#test_expect_success DIG 'network sandboxing = deny' '
#    pdir="$(unique_dir)" &&
#    mkdir "$pdir" &&
#    cdir="${pdir}/$(unique_dir)" &&
#    mkdir "$cdir" &&
#    touch "$cdir"/readme &&
#    test_must_fail sydbox \
#        -m core/sandbox/read:off \
#        -m core/sandbox/write:off \
#        -m core/sandbox/exec:off \
#        -m core/sandbox/network:deny \
#        dig +noall +answer dev.chessmuse.com
#'

test_expect_success PY3 'network sandboxing for connect works to deny IPv4 address' '
    test_expect_code 111 sydbox \
        -m core/sandbox/network:deny \
        python <<EOF
import errno, socket, sys

addr = socket.getaddrinfo("127.0.0.1", 22)[0][4]
probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    probe.connect(addr)
except OSError as e:
    sys.exit(e.errno)
except Exception as e:
    sys.stderr.write("Unexpected exception: %r\n" % e)
    sys.exit(0)
else:
    sys.exit(0)
finally:
   probe.close()
EOF
'

test_expect_success HAVE_IPV6,PY3 'network sandboxing for connect works to deny IPv6 address' '
    test_expect_code 111 sydbox \
        -m core/sandbox/network:deny \
        python <<EOF
import errno, socket, sys

addr = socket.getaddrinfo("::1", 22)[0][4]
probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
try:
    probe.connect(addr)
except OSError as e:
    if e.errno == errno.ECONNREFUSED:
        sys.stderr.write("OK: connect returned ECONNREFUSED\n")
    sys.exit(e.errno)
except Exception as e:
    sys.stderr.write("Unexpected exception: %r\n" % e)
    sys.exit(0)
else:
    sys.exit(0)
finally:
   probe.close()
EOF
'

test_expect_success PY3 'network sandboxing for bind works to deny IPv4 address with port zero' '
    test_expect_code 99 sydbox \
        -m core/sandbox/network:deny \
        python <<EOF
import errno, socket, sys

addr = socket.getaddrinfo("127.0.0.1", 0)[0][4]
probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    probe.bind(addr)
except OSError as e:
    if e.errno == errno.EADDRNOTAVAIL:
        sys.stderr.write("OK: bind returned EADDRNOTAVAIL\n")
    sys.exit(e.errno)
except Exception as e:
    sys.stderr.write("Unexpected exception: %r\n" % e)
    sys.exit(0)
else:
    sys.exit(0)
finally:
   probe.close()
EOF
'

test_expect_success PY3 'network sandboxing for bind works to whitelist IPv4 address with port zero' '
    test_expect_code 0 sydbox \
        -m core/sandbox/network:deny \
        -m whitelist/network/bind+LOOPBACK@0 \
        python <<EOF
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

test_expect_success PY3 'network sandboxing for bind works to deny IPv6 address with port zero' '
    test_expect_code 99 sydbox \
        -m core/sandbox/network:deny \
        python <<EOF
import errno, socket, sys

addr = socket.getaddrinfo("::1", 0)[0][4]
probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
try:
    probe.bind(addr)
except OSError as e:
    if e.errno == errno.EADDRNOTAVAIL:
        sys.stderr.write("OK: bind returned EADDRNOTAVAIL\n")
    sys.exit(e.errno)
except Exception as e:
    sys.stderr.write("Unexpected exception: %r\n" % e)
    sys.exit(0)
else:
    sys.exit(0)
finally:
   probe.close()
EOF
'

test_expect_success PY3 'network sandboxing for bind works to whitelist IPv6 address with port zero' '
    test_expect_code 0 sydbox \
        -m core/sandbox/network:deny \
        -m whitelist/network/bind+LOOPBACK6@0 \
        python <<EOF
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


test_done