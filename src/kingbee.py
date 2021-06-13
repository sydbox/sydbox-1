#!/usr/bin/env python
# coding: utf-8
# I am a king bee, I can buzz all night long!
# sydbox testing script

from __future__ import print_function

import os, sys, shlex
import re, subprocess, timeit, warnings

SYDBOX_OPTIONS = list()

# see make_expr()
BEE_HIVE = (
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
        ("fork and kill parent",
"""
def test():
    ppid = os.getpid()
    pid = os.fork()
    if pid == 0:
        os.kill(ppid, signal.SIGKILL)
    else:
        os.wait()
"""),
        ("double fork and kill child",
"""
def test():
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    for _ in range(@LOOP_COUNT@):
        rd, wr = os.pipe()
        child = os.fork()
        if child == 0:
            os.write(wr, b"1")
            grandchild = os.fork()
            if grandchild == 0:
                os.stat(b"/dev/null")
            else:
                os.wait()
        else:
            os.read(rd, 1)
            os.kill(child, signal.SIGKILL)
            try:
                os.wait()
            except OSError as exc:
                if exc.errno == errno.ECHILD:
                    pass
                else:
                    raise
""", False), # no threads
        ("SIGKILL rain",
"""
def test():
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    loops = @LOOP_COUNT@
    while loops >= 0:
        pid = os.fork()
        if pid == 0: # child
            child = os.getpid()
            loops = int(@LOOP_COUNT@ / 10)
            while loops >= 0:
                pid = os.fork()
                if pid == 0: # grandchild, kill child.
                    os.kill(child, signal.SIGKILL)
                    sys.exit(0)
                if not (loops & 1):
                    pass # intentionally empty
                else:
                    os.stat("/dev/null")
                os.kill(pid, signal.SIGKILL) # kill grandchild
                loops -= 1
        else: # parent
            try: os.wait()
            except: pass
            loops -= 1
""", False), # no threads
        ("rmdir non-empty directory",
"""
def test():
    import os

    dname = "kingbee.d"
    if not os.path.isdir(dname):
        os.mkdir(dname)
        for i in range(1000000):
            open("%s/kingbee-%d.f" % (dname, i), "a").close()
    try:
        os.rmdir(dname) # fail with ENOTEMPTY!
    except:
        pass
""", False, 1), # no threads, one loop
        ("bind() port zero",
"""
def test():
    import socket

    rd, wr = os.pipe()
    if os.fork():
        os.close(wr)
        port = int(os.read(rd, 64))
        os.close(rd)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", port))
        s.send("syd".encode())
        s.close()
        sys.exit(0)
    else:
        os.close(rd)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("localhost", 0))
        port = s.getsockname()[1]
        os.write(wr, bytes('{}'.format(port), "UTF-8"))
        os.close(wr)
        s.listen(4)
        cli, addr = s.accept()
        data = cli.recv(32).decode()
        cli.close()
        s.close()
        if data.endswith("syd"):
            sys.exit(0)
        sys.exit(1)
""", False, 1), # no threads, one loop
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

    if 'VALGRIND' not in os.environ or os.environ['VALGRIND'] != '0':
        VALGRIND = which("valgrind")
    else:
        VALGRIND = None

    if VALGRIND is None:
        warnings.warn("valgrind not found", RuntimeWarning)
    else:
        print("using valgrind `%s'" % VALGRIND)
        VALGRIND_OPTS.extend(["--quiet",
                              "--error-exitcode=126",
                              "--leak-check=full",
                              "--track-origins=yes"])

GDB = None
GDB_OPTS = []
def find_gdb():
    global GDB
    global GDB_OPTS

    if 'GDB' in os.environ and os.environ['GDB'] != '0':
        GDB = which("cgdb") or which("gdb")
        if GDB is None:
            warnings.warn("gdb not found", RuntimeWarning)
    else:
        GDB = None

    if GDB is not None:
        print("using gdb `%s'" % GDB)
        GDB_OPTS.extend(["--args"])

STRACE = None
STRACE_OPTS = []
def find_strace():
    global STRACE
    global STRACE_OPTS

    if 'STRACE' in os.environ and os.environ['STRACE'] != '0':
        STRACE = which("strace")
        if STRACE is None:
            warnings.warn("strace not found", RuntimeWarning)
    else:
        STRACE = None

    if STRACE is not None:
        print("using strace `%s'" % STRACE)
        STRACE_OPTS.extend(["-f"])
        if os.environ['STRACE'] != '1':
            STRACE_OPTS.extend(shlex.split(os.environ['STRACE']))

def eval_ext(expr,
             syd=None, syd_opts=[],
             gdb=None, gdb_opts=[],
             strace=None, strace_opts=[],
             valgrind=None, valgrind_opts=[]):
    """ Call python to evaluate an expr, optionally under sydbox """
    args = list()

    if gdb is not None or valgrind is not None:
        args.append('libtool')
        args.append('--mode=execute')
        if gdb is not None:
            args.append(gdb)
            args.extend(gdb_opts)
        elif valgrind is not None:
            args.append(valgrind)
            args.extend(valgrind_opts)
            args.append("--")

    if strace is not None and gdb is None and valgrind is None:
        args.append(strace)
        args.extend(strace_opts)
        args.append("--")
    elif syd is not None:
        args.append(syd)
        if SYDBOX_OPTIONS:
            syd_opts.extend(SYDBOX_OPTIONS)
        else:
            syd_opts.extend([
                "-mcore/allowlist/per_process_directories:true",
                "-mcore/allowlist/successful_bind:true",
                "-mcore/allowlist/unsupported_socket_families:true",
                "-mcore/trace/follow_fork:true",
                "-mcore/trace/magic_lock:off",
                "-mcore/sandbox/write:deny",
                "-mcore/sandbox/network:deny",
                "-mallowlist/write+/dev/stdout",
                "-mallowlist/write+/dev/stderr",
                "-mallowlist/write+/dev/zero",
                "-mallowlist/write+/dev/null",
                "-mallowlist/write+%s" % os.path.join(os.path.realpath("."), "kingbee.d", "***"),
                "-mallowlist/network/bind+LOOPBACK@0",
                "-mallowlist/network/connect+unix:/run/nscd/socket",
                "-mallowlist/network/connect+unix:/var/run/nscd/socket",])
        args.extend(syd_opts)
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
import errno, os, sys, signal, multiprocessing
""" + expr
    e += \
"""
if @THREAD_COUNT@ == 0:
    test()
else:
    for i in range(@THREAD_COUNT@):
        t = multiprocessing.Process(target=test)
        t.start()
"""

    e = e.replace("@LOOP_COUNT@", "%d" % loop_count)
    e = e.replace("@THREAD_COUNT@", "%d" % thread_count)
    return e

def run_test(name, expr, loops=100, threaded=True):
    if threaded:
        threads = 10
    else:
        threads = 0
    expr_once = make_expr(expr, 1, 0)
    expr_loop = make_expr(expr, loops, threads)
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
        if STRACE is not None:
            print("\t%d: under strace" % (test_no))
            eval_ext(expr_once, syd=SYDBOX, syd_opts=[opt_seize, opt_seccomp],
                     strace=STRACE, strace_opts=STRACE_OPTS)
            break
        elif GDB is not None:
            print("\t%d: sydbox [seize:%d, seccomp:%d]: under gdb" %
                    (test_no, choice[0], choice[1]))
            eval_ext(expr_once, syd=SYDBOX, syd_opts=[opt_seize, opt_seccomp],
                     gdb=GDB, gdb_opts=GDB_OPTS)
        elif VALGRIND is not None:
            print("\t%d: sydbox [seize:%d, seccomp:%d]: check with valgrind" %
                    (test_no, choice[0], choice[1]))
            eval_ext(expr_once, syd=SYDBOX, syd_opts=[opt_seize, opt_seccomp],
                    valgrind=VALGRIND, valgrind_opts=VALGRIND_OPTS)
        test_no += 1

def main(argv):
    find_sydbox()
    find_gdb()
    find_strace()
    find_valgrind()

    match = None
    if argv:
        seen_dashdash = False
        for arg in argv:
            if arg == '--':
                seen_dashdash = True
                continue
            if match is None and not seen_dashdash:
                p = re.compile(arg, re.UNICODE)
                match = lambda name: p.search(str(name))
                continue
            SYDBOX_OPTIONS.append(arg)
    if match is None:
        match = lambda name: True

    for bee in BEE_HIVE:
        if not match(bee[0]):
            print("skip %r" % bee[0])
            continue
        tail = len(bee)
        if tail == 4:
            run_test(bee[0], bee[1], threaded=bee[2], loops=bee[3])
        elif tail == 3:
            run_test(bee[0], bee[1], threaded=bee[2])
        else:
            run_test(bee[0], bee[1])

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
