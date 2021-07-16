#!/usr/bin/env python2
# coding: utf-8
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

import errno, socket, sys

addr = sys.argv[1]
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

