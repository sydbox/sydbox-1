#!/usr/bin/env python
# coding: utf-8
# I am a king bee, I can buzz all night long!
# sydbox benchmarking script

from __future__ import print_function

import os, sys
import subprocess, timeit
import warnings

# see make_expr()
BEE_HIVE = (
        ("fork and kill parent",
"""
def test():
    ppid = os.getpid()
    pid = os.fork()
    if pid == 0:
        os.kill(ppid, signal.SIGKILL)
    else:
        os.wait()
""", False), # no threads
        ("fork multiple times and kill parent",
"""
def test():
    ppid = os.getpid()
    pid = os.fork()
    if pid == 0:
        pid = os.fork()
        if pid == 0:
            pid = os.fork()
            if pid == 0:
                pid = os.fork()
                if pid == 0:
                    os.kill(ppid, signal.SIGKILL)
                else:
                    os.wait()
            else:
                os.wait()
        else:
            os.wait()
    else:
        os.wait()
""", False), # no threads
        ("stat /dev/null",
"""
def test():
    for i in range(@LOOP_COUNT@):
        os.stat("/dev/null")
"""),
        ("stat /dev/sydbox/1",
"""
def test():
    for i in range(@LOOP_COUNT@):
        try: os.stat("/dev/sydbox/1")
        except: pass
"""),
)

def which(name):
    """ which(1) """
    for path in os.environ['PATH'].split(":"):
        rpath = os.path.join(path, name)
        if os.path.isfile(rpath) and os.access(rpath, os.X_OK):
            return rpath
    return None

def find_sydbox():
    global SYDBOX

    SYDBOX = "./sydbox"
    if not os.path.exists(SYDBOX):
        SYDBOX = which("sydbox")
        if SYDBOX is None:
            raise IOError("you don't seem to have built sydbox yet!")
    print("using sydbox `%s'" % SYDBOX)

VALGRIND = None
VALGRIND_OPTS = []
def find_valgrind():
    global VALGRIND
    global VALGRIND_OPTS

    VALGRIND = which("valgrind")
    if VALGRIND is None:
        warnings.warn("valgrind not found", RuntimeWarning)
    print("using valgrind `%s'" % VALGRIND)

    VALGRIND_OPTS.extend(["--quiet",
                          "--error-exitcode=126",
                          "--leak-check=full",
                          "--track-origins=yes"])

def eval_ext(expr, syd=None, syd_opts=[],
                   valgrind=None, valgrind_opts=[]):
    """ Call python to evaluate an expr, optionally under sydbox """
    args = list()

    if valgrind is not None:
        args.append(valgrind)
        args.extend(valgrind_opts)
        args.append("--")

    if syd is not None:
        args.append(syd)
        args.extend(syd_opts)
        syd_opts.extend([
"-mcore/sandbox/write:deny",
"-mwhitelist/write+/dev/stdout",
"-mwhitelist/write+/dev/stderr",
"-mwhitelist/write+/dev/zero",
"-mwhitelist/write+/dev/null",])
        args.append("--")

    args.append("python")
    args.append("-c")
    args.append(expr)

    r = subprocess.call(args, stdin=sys.stdin,
                              stdout=sys.stdout,
                              stderr=sys.stderr,
                              shell=False)
    if valgrind is None:
        return r

    if r == 126:
        warnings.warn("valgrind error detected executing:", RuntimeWarning)
        warnings.warn("\t%r" % args, RuntimeWarning)

def make_expr(expr, loop_count, thread_count):
    """ Prepare an expression for threading """
    e = \
"""
import os, sys, signal, threading
""" + expr
    e += \
"""
if @THREAD_COUNT@ == 0:
    test()
else:
    for i in range(@THREAD_COUNT@):
        t = threading.Thread(target=test)
        t.start()
"""

    e = e.replace("@LOOP_COUNT@", "%d" % loop_count)
    e = e.replace("@THREAD_COUNT@", "%d" % thread_count)
    return e

def run_test(name, expr, threaded=True):
    expr_once = make_expr(expr, 1, 0)
    if threaded:
        loops = 100
        threads = 10
        expr_loop = make_expr(expr, loops, threads)
    else:
        loops = 1
        threads = 0
        expr_loop = expr_once
    print(">>> Test: %s (%d loops in %d threads)" % (name, loops, threads))

    test_no = 1
    t = timeit.timeit('eval_ext(%r)' % expr_loop,
            setup='from __main__ import eval_ext', number=1)
    print("\t%d: bare: %f sec" % (test_no, t))
    test_no += 1

    for choice in [(0, 0), (0, 1), (1, 0), (1, 1)]:
        opt_seize = "-mcore/trace/use_seize:%d" % choice[0]
        opt_seccomp = "-mcore/trace/use_seccomp:%d" % choice[1]
        t = timeit.timeit('eval_ext(%r, syd=%r, syd_opts=[%r, %r])' % ( expr_loop,
                                                                        SYDBOX,
                                                                        opt_seize,
                                                                        opt_seccomp ),
                          setup='from __main__ import eval_ext',
                          number=1)
        print("\t%d: sydbox [seize:%d, seccomp:%d]: %f sec" % (test_no,
                                                               choice[0],
                                                               choice[1],
                                                               t))
        print("\t%d: sydbox [seize:%d, seccomp:%d]: check with valgrind" %
                (test_no, choice[0], choice[1]))
        eval_ext(expr_once, syd=SYDBOX, syd_opts=[opt_seize, opt_seccomp], valgrind=VALGRIND)
        test_no += 1

def main(argv):
    find_sydbox()
    find_valgrind()

    for bee in BEE_HIVE:
        if len(bee) == 3:
            run_test(bee[0], bee[1], threaded=bee[2])
        else:
            run_test(bee[0], bee[1])

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))