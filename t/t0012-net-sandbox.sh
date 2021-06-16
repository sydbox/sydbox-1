#!/bin/sh
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

test_description='test network sandboxing'
. ./test-lib.sh

for ns_mem_access in 3; do
    test_expect_success DIG "network sandboxing = allow [memory_access:${ns_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    sydbox \
        -M '${ns_mem_access}' \
        -m core/sandbox/read:off \
        -m core/sandbox/write:off \
        -m core/sandbox/exec:off \
        -m core/sandbox/network:allow \
        dig +noall +answer @${PUBLIC_DNS} ${PUBLIC_HOST} > "$cdir"/out &&
    test -s "$cdir"/out
'

    test_expect_success DIG "network sandboxing = deny [memory_access:${ns_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    cdir="${pdir}/$(unique_dir)" &&
    mkdir "$cdir" &&
    touch "$cdir"/readme &&
    test_must_violate sydbox \
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
    test_expect_code 111 sydbox \
        -M '${ns_mem_access}' \
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

    test_expect_success HAVE_IPV6,PY3 \
        "network sandboxing for connect works to deny IPv6 address [memory_access:${ns_mem_access}]" '
    test_expect_code 111 sydbox \
        -M '${ns_mem_access}' \
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

    test_expect_success PY3 \
        "network sandboxing for bind works to deny UNIX socket [memory_access:${ns_mem_access}]" '
    pdir="$(unique_dir)" &&
    mkdir "$pdir" &&
    test_expect_code 99 sydbox \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        python <<EOF
import errno, socket, sys

addr = "$pdir"
probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
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

    test_expect_success PY3 \
        "network sandboxing for bind works to deny IPv4 address with port zero [memory_access:${ns_mem_access}]" '
    test_expect_code 99 sydbox \
        -M '${ns_mem_access}' \
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

    test_expect_success PY3 \
        "network sandboxing for bind works to deny IPv6 address with port zero [memory_access:${ns_mem_access}]" '
    test_expect_code 99 sydbox \
        -M '${ns_mem_access}' \
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

    test_expect_success PY3 \
        "network sandboxing for bind works to allowlist IPv4 address [memory_access:${ns_mem_access}]" '
    test_expect_code 0 sydbox \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m allowlist/network/bind+LOOPBACK@65534 \
        python <<EOF
import errno, socket, sys

addr = socket.getaddrinfo("127.0.0.1", 65534)[0][4]
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
        "network sandboxing for bind works to allowlist IPv6 address [memory_access:${ns_mem_access}]" '
    test_expect_code 0 sydbox \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m allowlist/network/bind+LOOPBACK6@65534 \
        python <<EOF
import errno, socket, sys

addr = socket.getaddrinfo("::1", 65534)[0][4]
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
        "network sandboxing for bind works to allowlist IPv4 address with port zero [memory_access:${ns_mem_access}]" '
    test_expect_code 0 sydbox \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m allowlist/network/bind+LOOPBACK@0 \
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

    test_expect_success PY3 \
        "network sandboxing for bind works to allowlist IPv6 address with port zero [memory_access:${ns_mem_access}]" '
    test_expect_code 0 sydbox \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m allowlist/network/bind+LOOPBACK6@0 \
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
        test_expect_success PY3 \
        "network sandboxing for bind works to auto-allowlist UNIX socket [memory_access:${ns_mem_access}]" '
pdir="$(unique_dir)" &&
mkdir "$pdir" &&
cd "$pdir" &&
test_expect_code 0 sydbox \
        -M '${ns_mem_access}' \
        -m core/sandbox/network:deny \
        -m "allowlist/network/bind+unix:$HOMER/${pdir}/test.socket" \
        python <<EOF
import errno, socket, sys, os

addr = "./test.socket"
probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    probe.bind(addr)
except OSError as e:
    sys.exit(e.errno)
except Exception as e:
    sys.stderr.write("bind: Unexpected exception: %r\n" % e)
    sys.exit(1)
else:
    probe.listen(0)
    pid = os.fork()
    if pid == 0:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.connect(addr)
        except OSError as e:
            os._exit(e.errno)
        except Exception as e:
            sys.stderr.write("connect: Unexpected exception: %r\n" % e)
            os._exit(1)
        else:
            os._exit(0)
    else:
        _, _ = probe.accept()
        pid, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status):
            sys.exit(os.WEXITSTATUS(status))
        elif os.WIFTERMINATED(status):
            sys.exit(-os.WTERMSIG(status))
        else:
            sys.exit(128)
finally:
    probe.close()
EOF
'
done

test_done
