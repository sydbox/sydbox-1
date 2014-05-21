#!/usr/bin/env python3
# coding: utf-8

import os, sys, signal
import argparse, bz2, json, re, tempfile

sydbox_pid = -1

def match_event(event, pattern = None, match_format = None):
    if pattern is None:
        return True
    try:
        return pattern.match(match_format.format(**event))
    except KeyError:
        return False
    except AttributeError:
        return False

class ShoeBox:
    FORMATS_SUPPORTED = (1,)

    def __init__(self, dump = 'dump.shoebox', flags = 'r'):
        self.dump  = dump
        self.flags = flags

        self.fmt  = None
        self.head = None

    def __enter__(self):
        self.fp = bz2.BZ2File(self.dump, self.flags)
        self.check_format()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.fp.close()
        if exc_type is not None:
            return False # Raise the exception
        return True

    @staticmethod
    def load_line(line):
        return json.loads(line.decode())

    def abspath(self):
        return os.path.abspath(self.dump)

    def check_format(self):
        line = self.fp.readline()
        obj  = ShoeBox.load_line(line)

        if 'id' not in obj:
            self.fp.close()
            raise NotImplementedError("missing id attribute")
        elif obj['id'] != 0:
            self.fp.close()
            raise NotImplementedError("invalid id attribute `%r' for format check" % obj['id'])
        elif 'shoebox' not in obj:
            self.fp.close()
            raise NotImplementedError("missing shoebox attribute")
        elif obj['shoebox'] not in ShoeBox.FORMATS_SUPPORTED:
            self.fp.close()
            raise NotImplementedError("unsupported shoebox format `%r'" % obj['shoebox'])

        self.fmt  = obj['shoebox']
        self.head = self.fp.tell()

    def rewind(self):
        self.fp.seek(self.head, os.SEEK_SET)

    def readlines(self, limit = 0):
        if limit == 0:
            for line in self.fp.readlines():
                yield line
        elif limit > 0:
            for line in self.fp.readlines():
                yield line
                limit -= 1
                if limit == 0:
                    break
        else: # limit < 0
            self.fp.seek(0, os.SEEK_END)
            fpos = self.fp.tell()
            self.fp.seek(max(fpos - (2048 * abs(limit)), self.head), os.SEEK_SET)
            lines = self.fp.readlines()[limit:]
            for line in lines:
                yield line

    def read_events(self, limit = 0):
        for json_line in self.readlines(limit):
            try:
                obj = ShoeBox.load_line(json_line)
            except TypeError as err:
                sys.stderr.write("WTF? %r\n" % json_line)
                raise
            except ValueError as err:
                sys.stderr.write("Unable to parse JSON: %r\n" % err)
                match = re.search('char (?P<char>[0-9]+)', err.message)
                if match is not None:
                    char = int(match.group('char'))
                    bh = max([char - 10, 0])
                    eh = min([char + 10, len(json_line)])
                    hl = json_line[:bh] + '\033[1m\033[91m' + json_line[bh:eh] + '\033[0m' + json_line[eh:]
                else:
                    hl = json_line
                sys.stderr.write(hl)
                raise
            yield obj

    def tree(self, pid, pattern, match_format, quick = False):
        events = []

        for event in self.read_events():
            if 'pid' not in event:
                continue
            if event['pid'] != pid:
                continue
            events.append(event)

        parents = set()

        for event in events:
            if 'process' in event:
                if 'stat' in event['process']:
                    if event['process']['stat'] is None:
                        continue
                    if 'errno' in event['process']['stat']:
                        continue # TODO: warn
                    parents.add(event['process']['stat']['ppid'])
                elif 'syd' in event['process']:
                    if event['process']['syd'] is None:
                        continue # TODO: warn
                    parents.add(event['process']['syd']['ppid'])

        for ppid in parents:
            self.rewind()
            events += self.tree(ppid, None, None, True)

        if quick:
            return events

        events_out = [event for event in events if match_event(event, pattern, match_format)]
        return sorted(events_out, key = lambda event: event['id'])

def command_sydbox(args, rest):
    tmpdir = tempfile.mkdtemp()
    fifo   = os.path.join(tmpdir, 'shoebox.fifo')
    os.mkfifo(fifo, 0o600)

    if args.gdb:
        argv0 = args.gdb[0]
        argv  = args.gdb + [args.path] + rest
    elif args.strace:
        argv0 = args.strace[0]
        argv  = args.strace + [args.path] + rest
    else:
        argv0 = args.path
        argv = [args.path] + rest

    pid = os.fork()
    if pid == 0:
        os.setsid()

        dump_in = open(fifo, 'rb')
        dump_out = bz2.BZ2File(args.dump, 'w')

        dump = os.path.abspath(args.dump)
        sys.stderr.write('pink: dump:%s\n' % dump)

        with dump_in, dump_out:
            for json_line in dump_in:
                dump_out.write(json_line)

        sys.stderr.write('\nno poems? send dump: %s\n' % dump)
        os._exit(0)
    else:
        sys.stderr.write('syd: %r %r\n' % (argv0, argv))
        sys.stderr.write('syd: fifo:%r\n' % fifo)

        os.environ['SHOEBOX'] = fifo
        os.execvp(argv0, argv)
        os._exit(127)

def check_format(f):
    obj = ShoeBox.load_line(f.readline())
    if 'id' in obj and obj['id'] == 0 and 'shoebox' in obj and obj['shoebox'] == 1:
           return True
    raise IOError("Invalid format")

def dump_json(obj, fmt = None):
    if fmt is not None:
        sys.stdout.write(fmt.format(**obj) + "\n")
    else:
        json.dump(obj, sys.stdout, sort_keys = True,
                  indent = 4, separators = (',', ': '))
        sys.stdout.write('\n')

def match_any(patterns, string, flags = 0):
    for p in patterns:
        if p.match(string) is not None:
            return True
    return False

def command_tree(args, rest):
    if args.pattern is None:
        pattern = None
        match_format = None
    else:
        pattern = re.compile(args.pattern, re.UNICODE)
        match_format = args.match

    with ShoeBox(args.dump) as sb:
        events = sb.tree(args.pid, pattern, match_format)
        for event in events:
            dump_json(event, args.format)

def command_show(args, rest):
    if args.pattern is None:
        pattern = None
        match_format = None
    else:
        pattern = re.compile(args.pattern, re.UNICODE)
        match_format = args.match

    limit  = args.limit_match
    events = []
    events_size = 0
    with ShoeBox(args.dump) as sb:
        for event in sb.read_events(args.limit_event):
            if match_event(event, pattern, match_format):
                if limit == 0:
                    dump_json(event, args.format)
                elif limit > 0:
                    dump_json(event, args.format)
                    limit -= 1
                    if limit == 0:
                        break
                else:
                    events.append(event)
                    events_size += 1
                    if events_size > abs(limit):
                        events.pop(0)
    if limit < 0:
        for event in events:
            dump_json(event, args.format)

def main():
    parser = argparse.ArgumentParser(prog='shoebox',
                                     description='Pink hiding in a shoe box',
                                     prefix_chars='+',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     # usage='%(prog)s [options] {command [arg...]}',
                                     epilog='''
Hey you, out there on the road,
Always doing what you're told,
Can you help me?

Send bug reports to "alip@exherbo.org"
Attaching poems encourages consideration tremendously.''')
    parser.add_argument('+gdb',
                        action = 'store_const', const = ['gdb', '--args'],
                        help = 'Run under gdb')
    parser.add_argument('+strace',
                        action = 'store_const', const = ['strace',],
                        help = 'Run under strace')
    parser.add_argument('+dump', default = 'dump.shoebox', help = 'Path to the dump file')
    parser.add_argument('+path', default = 'sydbox-dump', help = 'Path to sydbox')

    subparser = parser.add_subparsers(help = 'command help')

    parser_sydbox = subparser.add_parser('sydbox', add_help = False, help = 'Run command under Shoe Box')
    parser_sydbox.set_defaults(func = command_sydbox)

    parser_show = subparser.add_parser('show', help = 'Show dump')
    parser_show.add_argument('-m', '--match', default = '{pid}', help = 'Match format')
    parser_show.add_argument('-p', '--pattern', help = 'Match pattern (regex)')
    parser_show.add_argument('-f', '--format', default = None, help = 'Format string')
    parser_show.add_argument('-l', '--limit-match', default = 0, type = int, help = 'Limit matches')
    parser_show.add_argument('-L', '--limit-event', default = 0, type = int, help = 'Limit events')
    parser_show.set_defaults(func = command_show)

    parser_tree = subparser.add_parser('tree', help = 'Show process tree')
    parser_tree.add_argument('-f', '--format',
                             metavar = 'FORMAT',
                             default = None,
                             help = 'Format string, default: "%(default)s"')
#    parser_tree.add_argument('-F', '--filter',
#                             type = eval, metavar = 'CODE',
#                             default = 'lambda event: True',
#                             help = 'Filter code, default: "%(default)s"')
    parser_tree.add_argument('-m', '--match', default = '{event_name}', help = 'Match format')
    parser_tree.add_argument('-p', '--pattern', help = 'Match pattern (regex)')
    parser_tree.add_argument('pid', type = int, metavar = 'PID', help = 'PID to match')
    parser_tree.set_defaults(func = command_tree)

    args, rest = parser.parse_known_args()
    return args.func(args, rest)

if __name__ == '__main__':
    sys.exit(main())
