# Sydb☮x

implement basic system call name filters such that:
	- allowlist/syscall+<regex-for-syscall-name>
	- blacklist/syscall+<regex-for-syscall-name>
is possible in config!

## BUILD FAILURES
# Thanks a lot justinkb

16:03 < justinkb> https://github.com/python/cpython/blob/v3.9.5/Lib/test/test_signal.py#L1336
16:11 < justinkb> alip: https://github.com/python/cpython/blob/v3.9.5/Lib/test/test_socketserver.py,
                  guessing it might fail because we 'HAVE_FORKING' (so it isnt skipped) but sydbox is
                  stopping that forking?
07:56 < justinkb> log here (includes the usr2 debug output obviously)
https://github.com/justinkb/temporary/blob/master/1624434686-install-dev-libs_libglvnd-1.3.3:0::x11.out

## IDEAS
- Print (and dump unless both are stderr)
  violations as json lines rather than the custom error message.
- Buildhost: Test builds with --disable-dump
- Use a hash table without memory allocation for the process table.
  This is an idea:
    https://github.com/vi/macro_robinhood_hash
    https://gist.github.com/vi/42c4d7bc854653a17e9085c8831c6dcd
- Add check for struct iovec in configure.ac and use /proc/pid/mem otherwise.
- Avoid unnecessary printf usage in dump.c
- Finish the rework on tests
- SIGUSR2 dumps sydcore
- Use a simpler hashtable instead of using uthash everywhere.
- provide a list of system calls to allowlist/denylist on startup to feed
  to seccomp-bpf filters. An allowlisted system call will be allowed and will
  further be subject to sandbox restrictions. A denylisted system call will
  be denied with ENOSYS directly by seccomp. The user may input a list of
  regular expressions to match system calls for restrictions.
- use allowlist/denylist rather than allowlist/denylist list in syd-2 profiles
- rename the master branch to main
- Currently, the allow sandbox mode uses denylists and the deny sandbox mode use
allowlists. However it's better if both modes use both lists and the first matching
pattern wins.
- Add a UNIX socket interface to receive runtime configuration.
- Abstract Paludis sandboxing system call hooks away from the core loop.

# Sydb☮x (next major)
- Add an intuitive, simple interface to configure basic sandboxing via
configuration and allow calling internal functions or dynamic SO libraries to
use for seccomp-bpf and system call entry/exit hooks. The simple cases can be
handled through configuration however if a system call is traced (e.g: via
SECCOMP_RET_TRACE), it's much more powerful for the user to be able to write a
dynamic library with the functions such as seccomp_init, sys_enter_open,
sys_exit_open and so on. Loading the modules is done via configuration whilst
configuring seccomp filters such as:
  - sys/kill_process+syscall_set[:arg_expr...]
  - sys/kill_thread+syscall_set[:arg_expr...]
  - sys/fault+syscall_set:[:arg_expr...]:error=errno
  - sys/trap+syscall_set[:arg_expr...][:error=errno|:retval=value]
  - sys/log+syscall_set[:arg_expr...]
  - sys/allow+syscall_set[:arg_expr...]
  - sys/user+syscall_set[:arg_expr...][:log=syslog-or-fd][:command=regex][:cmdline=regex][
	:kill_process=signal		|
	:kill_thread=signal		|
	:detach_process=signal		|
	:detach_thread=signal		|
	:trap=errno|retval		|
	:allow				|
	:load=/path/to/profile.so[:profile-options...]
    ]

syscall_set is borrowed from strace see strace(1) with the addition of two sets:
	- %file_rd for read only system calls
	- %file_wr for write only and read/write system calls
	- %exec for execve() and execveat()
	  %net for connect() and bind()
arg_expr is [:arg0..5<cmp_operator><argval_expr>]
The special character _ may be used rather than 0..5 to infer the argument number
from the system call number. This only works for string and network address
arguments.

cmp_operator, ie the comparison operator must be exactly one of:
	Arithmetic values:
		=, !=, >, >=, <, <=,
		&, !& Bitwise AND and Bitwise NOT AND
	String matching: =, !=, =~, !~, =*, !*
	Network address matching: @~, @!

Only arithmetic values can be used with seccomp-bpf rules, string and network
address matching is trace only.

argval_expr must be exactly one of:
	- A simple integer
	- A simple identifier such as O_RDONLY
	- An arithmetic expression including integers and identifiers,
		to be parsed by expr: https://github.com/zserge/expr
		Such as: O_WRONLY|O_RDWR|O_CREAT
		Note, to be able to use identifiers we need to append the list
		of all identifiers to the expression evaluator everytime,
		such as:
		const char *expr_def = "O_WRONLY=1,O_RDWR=2,O_CREAT=64,..., ";
		const char *expr_usr = "O_WRONLY|O_RDWR|O_CREAT";
	- A double quoted string literal, no longer than PATH_MAX
	- A double quoted network address pattern such as inet://127.0.0.0/8 or LOOPBACK for short

If sydbox finds no trace rules in the configuration, it'll act as a seccomp-bpf only sandbox.

Some sample filter rules with this new format:
- Kill processes attempting to set uid to root and log to syslog
	sys/log+/setuid(32?):arg0=0
	sys/kill_process+/setuid(32?):arg0=0
- Allow open and openat system calls which are not write:
	sys/allow+/open(64)?:arg1!&O_WRONLY|O_RDWR|O_CREAT
	sys/allow+/openat:arg2!&O_WRONLY|O_RDWR|O_CREAT
- Deny access to ~/.netrc and ~/.gnupg* and allow access to the rest of $HOME
	sys/trace+%file:arg_=~"/home/[^/]+/\.(gnupg|netrc).*":fault=EPERM
	sys/trace+%file:arg_=*"/home/[^/]+/***":fault=EPERM
- Deny bind to non loopback addresses
	sys/trace+bind:arg_@!"LOOPBACK":fault=EPERM
- Deny external DNS requests and log them to standard error
	sys/trace+%network:arg_@!"inet://0.0.0.0/0@53":log=2:fault=EPERM
	sys/trace+%network:arg_@!"inet6://::/0@53":log=2:fault=EPERM
- Only allow connections through the Tor proxy
	sys/trace+%network:arg_@!"inet://127.0.0.1@9050":fault=EPERM
- Detach from the gpg binary under /usr/bin, seccomp-bpf filters remain valid.
	sys/trace+%exec:arg_="/usr/bin/gpg":detach_process=0
- Load the magic stat internal module for runtime configuration.
  Limit runtime configuration to the initial child only.
  Make sure you do not directly call exec there or it's insecure.
  Consider using the option readonly=true if you only need to read configuration.
  The idea of this is to use with Paludis during package builds with exhereses
  (package compilation definition scripts) to add additional rules before starting
  package builds.
  	sys/trace+%stat:arg_@~"/dev/sydbox/?.*":load=magic_stat:readonly=0:initonly=1
- Mimic Paludis profile
	sys/trace+%file_wr:allow:arg_=~"/dev/(stdout|stderr|zero|(f|n)ull|console|u?random|ptmx)$"
	sys/trace+%file_wr:allow:arg_=~"/dev/(fd|pts|shm)/.*"
	sys/trace+%file_wr:allow:arg_=*"/dev/tty*"
	sys/trace+%file_wr:allow:arg_=*"/selinux/context/***"
	sys/trace+%file_wr:allow:arg_=~"/proc/self/(attr|fd|task)/.*"
	sys/trace+%file_wr:allow:arg_=~"/(tmp|var/tmp|var/cache)/.*"
	sys/trace+%file_wr:fault=EPERM:log=2
	sys/trace+bind:allow:arg_@~"LOOPBACK@0"
	sys/trace+bind:allow:arg_@~"LOOPBACK@1024-65535"
	sys/trace+bind:allow:arg_@~"LOOPBACK6@0"
	sys/trace+bind:allow:arg_@~"LOOPBACK6@1024-65535"
	sys/trace+bind:fault=EPERM:log=2
	sys/trace+connect:allow:arg_@~"unix:/var/run/nscd/socket"
	sys/trace+connect:allow:arg_@~"unix:/run/nscd/socket"
	sys/trace+connect:allow:arg_@~"unix:/var/lib/sss/pipes/nss"
	sys/trace+connect:fault=EPERM:log=2

# Pand☮ra

- box should learn to drop privileges to a different user and group.
- box should learn to change to a different directory such as /var/empty.
- box should learn to chroot.
- box should learn to use namespaces.
- box profile should learn to save a checksum of the binary in the profile.
  (requires PATH traversal?)
- box profile should learn to cryptographically sign the header of the profile
- box profile should learn to upload out.syd-1 to a public location.
- box profile should learn to check the checksum of a binary and download a
  profile from a public location.
- box profile should be able to cryptographically verify the signature in the
  header of a profile downloaded from a public location.
- box should learn to read sydbox magic configuration via TOML format
- generate docs from pandora --help output for docs.rs if it's possible
- add benchmarks with criterion to benchmark certain box invocations.

# People of Interest

1. https://de.wikipedia.org/wiki/Ludwig_Guttmann

# Crates of Interest
1. https://briansmith.org/rustdoc/untrusted/ **TODO**
1. https://crates.io/crates/binfarce **TODO**
1. https://crates.io/crates/pgp **MUST-HAVE**
1. https://crates.io/crates/mimalloc **MUST-HAVE**
1. https://crates.io/crates/nanorand **NICE-TO-HAVE**
1. https://crates.io/crates/stemjail **NICE-TO-HAVE**
1. https://docs.rs/crate/binary-security-check/1.2.3 **NICE-TO-HAVE**
1. https://crates.io/crates/container-pid **NICE-TO-HAVE**
1. https://crates.io/crates/in-container **NICE-TO-HAVE**
1. https://crates.io/crates/secstr **NICE-TO-HAVE**
1. https://crates.io/crates/in-container **RESEARCH**
1. https://crates.io/crates/cocoon **RTFM**
1. https://crates.io/crates/cglue **RTFM**
1. https://crates.io/crates/keyutils **NICE-TO-HAVE** **RTFM**
1. https://crates.io/crates/shuffling-allocator **RTFM**
1. https://crates.io/crates/memsec **RTFM**
1. https://crates.io/crates/shuffling-allocator **FUN**
1. https://crates.io/crates/cmd_lib **FUN**
1. https://crates.io/crates/self_encryptor **FUN**
1. https://docs.rs/crate/binary-security-check/1.2.3 **TODO**
1. https://crates.io/crates/unicode-security
1. https://blog.rust-lang.org/inside-rust/2019/10/03/Keeping-secure-with-cargo-audit-0.9.html
1. https://crates.io/crates/cargo-audit **ADDED**
1. https://crates.io/crates/smol **TODO**
1. https://crates.io/crates/zeroize **TODO**
1. https://crates.io/crates/bincode **TODO**

# Projects of Interest

## LibSodium
**MUST-HAVE**

## CaitSith
### Thanks eternaleye!

[21:51:06] <eternaleye> alip: BTW, have you ever heard of CaitSith?
[21:51:23] <eternaleye> It's a Linux security module that has a somewhat similar style to sydbox, might be fun to take inspiration from
[21:51:38] <eternaleye> In particular, its notion of "domain transitions" is pretty cool
[21:51:47] <eternaleye> http://caitsith.osdn.jp
[21:52:19] <eternaleye> alip: Anyway, I'd highly recommend reading the slides that are linked in there
[21:52:28] <eternaleye> They do a good job of explaining CaitSith's history and philosophy
[21:53:04] <eternaleye> But to explain the main cool thing they have that I think sydbox could steal, it basically assigns a "domain" to each process, and access control rules can key off of that
[21:53:51] <eternaleye> Rules can change the "domain" on exec, and they actually just added a functionality (at my suggestion) to allow domains transitions to occur in response to socket operations as well
[21:54:12] <eternaleye> Which allows for having different rules before/after a service starts listening for requests, etc
[21:54:25] <justinkb> eternaleye: any big performance hit from those flags btw?
[21:54:56] <alip> eternaleye: do you mind if I quote you in sydbox.it/TODO?
[21:55:04] <eternaleye> justinkb: -ggdb3 and -gdwarf-4 only impact debuginfo generation; with splitdebug, there's absolutely no change in perf
[21:55:06] <eternaleye> alip: No problem!
[21:56:02] <eternaleye> But yeah, a cool thing you can do with domains is assign domains based on (prior domain, process invoking exec, program being exec'd)
[21:56:32] <eternaleye> So "bash started by paludis" and "bash started by login" can have completely different policies
[21:57:15] <eternaleye> alip: CaitSith even supports an interactive mode
[21:57:26] <eternaleye> justinkb: Uh, splitdebug does tell gdb where the symbols are
[21:57:39] <eternaleye> It inserts a .gnu.debuglink section or whatever
[21:57:45] <alip> eternaleye: i don't like interactivity but ok
[21:58:15] <eternaleye> alip: No, not interactive as in "human controlled", interactive as in "rule raises a notification that you then approve/deny"
[21:58:25] <eternaleye> More like seccomp notify
[21:58:37] <justinkb> eternaleye: hm, didn't work for me back then, might've been a bug or sth, i'll look into it, cheers
[21:58:40] <eternaleye> Though not quite as clean as it's not an FD per context
[21:59:32] <eternaleye> alip: The same mechanism used for interactivity is also used for its learning mode (similar to pandora profile)
[22:00:43] <eternaleye> alip: Honestly, I kind of think it'd be neat if sydbox could understand CaitSith profiles - they're a pretty clever format
[22:01:53] <eternaleye> They're basically entries of the form `<priority> <operation> <conditions>\n(\t<priority> <conditions> <verdict>)+`
[22:03:38] <eternaleye> alip: Here's an example (simplistic) policy file: http://caitsith.osdn.jp/#3.1.3
[22:04:24] <eternaleye> This makes it so the "execute" operation can only be invoked with the listed programs, at all
[22:04:51] <eternaleye> And transitions to the specified domain for each, so that more specific policies can key off of that
[22:05:13] <eternaleye> Actually, wait, no
[22:05:16] <alip> i had this idea which i started to implement to limit the list of executable files by a list of sha1 checksums.
[22:05:19] <eternaleye> It doesn't have a final "deny"
[22:05:21] <alip> that's similar
[22:03:38] <eternaleye> alip: Here's an example (simplistic) policy file: http://caitsith.osdn.jp/#3.1.3
[22:04:24] <eternaleye> This makes it so the "execute" operation can only be invoked with the listed programs, at all
[22:04:51] <eternaleye> And transitions to the specified domain for each, so that more specific policies can key off of that
[22:05:13] <eternaleye> Actually, wait, no
[22:05:16] <alip> i had this idea which i started to implement to limit the list of executable files by a list of sha1 checksums.
[22:05:19] <eternaleye> It doesn't have a final "deny"
[22:05:21] <alip> that's similar
[22:06:13] <eternaleye> alip: Each operation has its own list of properties that conditions can inspect - here are the ones for `execute`: http://caitsith.osdn.jp/#5.1
[22:06:30] <eternaleye> You could easily extend it with a `path.hash.sha1` attribute
[22:06:40] <alip> sweet.
[22:07:27] <eternaleye> Also, even as is, you can filter by the task's environment and stuff :D
[22:07:36] <eternaleye> Or even its argv
[22:08:00] <eternaleye> "only allow running X on :90 through :99" is entirely expressible :D
[22:08:12] <alip> yeah many stuff are possible i know :)
[22:08:20] <alip> but my top priority is to make sandbox secure first
[22:08:35] <eternaleye> Yup
[22:08:50] <alip> and for that i need to pull quite some tricker being a non-root no fancy kernel features tool
[22:08:59] <eternaleye> More pointing out how nicely extensible the format is, and how many things it already can express
[22:09:17] <alip> yes, all this is very exciting, i'm copying you todo as we speak
[22:09:37] <eternaleye> Plus, if you're using the same format, then there's also the option of leveraging CaitSith if a system has it available :P
[22:09:53] <alip> hehe sandbox brothers
[22:10:40] <eternaleye> Especially if there's a system-wide CaitSith policy that gives `cave perform` a domain you can key off of, based on the package it's building
[22:11:12] <eternaleye> Something like `paludis-build/$CATEGORY/$PN@$PV` or some such
[22:11:46] <eternaleye> After all, CaitSith rules can key off of argv :D
[22:12:05] <alip> sweet +1
[22:13:04] <eternaleye> alip: Also, I think you might find the slides show the author to be a kindred spirit - I think he likes Card Captor Sakura the way you like Pink Floyd, given he's named a bunch of projects after different characters :P
[22:13:37] <eternaleye> Same guy who made the (upstreamed) Tomoyo security module
[22:14:46] <alip> sounds very nice. much obliged. yay more pf for me and more ccs for them.
[22:15:27] <alip> there's the idea that challenges end with the banner that the shell prints so you understand you won :D
[22:15:54] <alip> or a random tao te ching quote if you won a bigger challenge
[22:16:42] <alip> so people can look for different poems under different parts of the system
[22:16:51] <justinkb> should I expect a fix for that too many file descriptors thing before you leave for the week? if not, can you recommend a commit to build from that shouldn't have that issue?
[22:17:12] <alip> i hope to fix that tonight but i dont know the cause yet
[22:17:24] <alip> i'll delay the renaming for now and do that.
