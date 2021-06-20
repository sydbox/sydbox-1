#!/usr/bin/env python
# coding: utf-8
# Copyright 2021 Ali Polatel <alip@exherbo.org>
# Based in part upon archivemail which is:
#   Copyright (C) 2002  Paul Rodger <paul@paulrodger.com>,
#             (C) 2006  Peter Poeml <poeml@suse.de>,
#             (C) 2006-2010  Nikolaus Schulz <microschulz@web.de>
# Released under the terms of the GNU General Public License v2

import sys

def check_python_version():
    """Abort if we are running on python < v2.3"""
    too_old_error = "This program requires python v2.3 or greater. " + \
      "Your version of python is:\n%s""" % sys.version
    try:
        version = sys.version_info  # we might not even have this function! :)
        if (version[0] < 2) or (version[0] == 2 and version[1] < 3):
            sys.stderr.write(too_old_error)
            sys.stderr.write("\n")
            sys.exit(1)
    except AttributeError:
        sys.stderr.write(too_old_error)
        sys.stderr.write("\n")
        sys.exit(1)

# define & run this early
check_python_version()

import os

RO_FLAG = ('O_RDONLY',
        'O_RDONLY|O_CLOEXEC',
        'O_RDONLY|O_CLOEXEC|O_DIRECTORY',
        'O_RDONLY|O_CLOEXEC|O_PATH',
        'O_RDONLY|O_LARGEFILE',
        'O_RDONLY|O_LARGEFILE|O_DIRECTORY',
        'O_RDONLY|O_LARGEFILE|O_PATH',
)

f = open("syscall_open_ro.lst", "r")
names = f.read().strip().split("\n")
f.close()

f = open("syscall_open_syd.h.in", "r")
header = f.read()
f.close()

flag_max = 0
flags = []

for name in RO_FLAG:
    flags.append(name + ',')
    flag_max += 1
for name in names:
    for init in RO_FLAG:
        mask = '#ifdef %s\n\t%s|%s,\n#endif' % (name,init,name)
        flags.append(mask)
        flag_max += 1
flags = list(set(flags))
flags.sort()        # sorts normally by alphabetical order
flags.sort(key=len) # sorts by descending length
flags = "\n".join(flags)

OPEN_READONLY_FLAG_MAX = flag_max
OPEN_READONLY_FLAGS = flags

header = header.replace("@OPEN_READONLY_FLAG_MAX@",
        str(OPEN_READONLY_FLAG_MAX))
header = header.replace("@OPEN_READONLY_FLAGS@",
        str(OPEN_READONLY_FLAGS))
sys.stdout.write(header)
sys.stdout.write("\n")
