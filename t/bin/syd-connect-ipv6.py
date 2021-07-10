#!/usr/bin/env python3
# coding: utf-8
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

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

