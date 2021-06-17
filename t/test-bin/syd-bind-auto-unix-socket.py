#!/usr/bin/env python3
# coding: utf-8
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Released under the terms of the GNU General Public License v2

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
