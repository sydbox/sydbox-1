# The ☮ther SⒶndbøx

<table>
<td>
<a href="https://repology.org/project/awesome/versions">
  <img alt="Repology:SydBox"
       src="https://repology.org/badge/version-for-repo/exherbo/sydbox.svg"
       title="Repology:SydBox"
       style="border: 0px; margin: 0px"
  />
</a></td>
<td>
<a href="https://img.shields.io/badge/stability-mature-008000.svg">
  <img alt="stability:pre-release"
       src="https://img.shields.io/badge/stability-pre--release-48c9b0.svg"
       title="Code is fairly settled and is use in production systems.
Backwards-compatibility will be maintained unless serious issues are
discovered and consensus on a better solution is reached."
       style="border: 0px; margin: 0px"
  />
</a></td>
<td>
<a href="https://scan.coverity.com/projects/sydbox">
  <img alt="Coverity:SydBox"
       src="https://scan.coverity.com/projects/sydbox/badge.svg"
       title="Coverity:SydBox"
       style="border: 0px; margin: 0px"
  />
</a></td>
<td>
<a href='https://coveralls.io/gitlab/sydbox/sydbox'>
<img alt='Coverage:SydBox'
     title='Coverage:SydBox'
     style='border: 0px; margin: 0px;'
     src='https://coveralls.io/repos/gitlab/sydbox/sydbox/badge.svg'
/></a></td>
<td>
<a href='https://builds.sr.ht/~alip'>
<img alt='Sourcehut.Builds:SydBox'
     title='Sourcehut.Builds:SydBox'
     style='border: 0px; margin: 0px;'
     src='https://builds.sr.ht/~alip.svg'
/></a></td>
<td>
<a href="https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html">
    <img alt="SPDX-License-Identifier: GPL-2.0-only"
        title="SPDX-License-Identifier: GPL-2.0-only"
        src="https://img.shields.io/badge/License-GPL%20v2-blue.svg"
        style="border: 0px; margin: 0px"
    />
</a></td>
<tr>
<td>
<a href="https://sydbox.exherbo.org">
<img
    src="https://dev.exherbo.org/~alip/images/sydbox160.png"
    alt="SydB☮x"
    title="That cat's something I can't explain!"
    style="border: 0px; margin: 0px"
/></a></td>
<td>
<a href="https://github.com/seccomp/libseccomp">
<img
    src="https://dev.exherbo.org/~alip/images/libseccomp.png"
    alt="LibSecComp"
    title="LibSecComp"
    style="border: 0px; margin: 0px"
/>
</a></td>
<td>
<a href="https://www.exherbo.org/docs/gettingstarted.html">
<img
    src="https://dev.exherbo.org/~alip/images/zebrapig.png"
    alt="ZebraPig"
    title="I AM ZEBRAPIG"
    style="border: 0px; margin: 0px"
/>
</a></td>
<td>
<a href="https://www.gnu.org/philosophy/philosophy.html">
<img
    src="https://dev.exherbo.org/~alip/images/gnu.png"
    alt="Heckert"
    title="Heckert"
    style="border: 0px; margin: 0px"
/>
</td>
<td>
<a href="https://www.kernel.org/category/about.html">
<img
    src="https://dev.exherbo.org/~alip/images/tux.png"
    alt="TuX"
    title="TuX"
    style="border: 0px; margin: 0px"
/>
</a></td>
</td></tr>
</tr></table>

SydB☮x is a [seccomp](http://man7.org/linux/man-pages/man2/seccomp.2.html) based
sandbox for modern [Linux](https://kernel.org) machines to sandbox unwanted process
access to filesystem and network resources.

- sydB☮x written in portable C and licensed GPLv2.
- libsyd is written in portable C and licensed GPLv2.

SydB☮x requires **no root access** and
**no [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html)** rights.
They don't depend on any specific Linux kernel option to function.
The only dependency is [libseccomp](https://github.com/seccomp/libseccomp)
which is available on many different architectures,
including x86, x86\_64, x32, arm, aarch64, mips, mips64...

This makes it very easy for a regular user to use. This is the motto
of SydB☮x: **bring easy, simple, flexible and powerful security to the
Linux user!**

The basic idea of SydB☮x is to run a command under certain restrictions.
These are the seccomp restrictions which restricts system calls and SydB☮x'
command line flags to create new namespaces (**containers**), change user,
change group, add additional groups, change directory, chroot into directory,
change the root mount, and various other daemon options (**cgroups support
is work in progress.**). See the [SydB☮x manual page](https://sydbox.exherbo.org)
for details.

Run SydB☮x without arguments to drop into the SydB☮x shell which is running in a new
pid, user, mount, net, time and cgroup namespace with its home under a temporary
directory under »/tmp«, with read, write, exec and network sandboxing modes set to
»deny« but with **unlocked sandbox status** which is insecure but allows
the user to configure the SydB☮x using the `stat(2)` IPC using the special
»/dev/sydb☮x« device node. See `syd ipc --help` for details. Use `syd ipc lock`
to **switch to secure mode** under SydB☮x or run SydB☮x with `sydbox --lock`.

**Secure Computing Mode**, also known as
»[Seccomp](https://en.wikipedia.org/wiki/Seccomp)« allows the user to define
restrictions on which system calls the command is permitted to run and which argument
values are permitted for the given system call. The restrictions may be applied via two ways.

1. [seccomp-bpf](https://man7.org/linux/man-pages/man2/seccomp.2.html) can be used to apply
simple Secure Computing user filters to run sandboxing fully on kernel space, and
2. [seccomp-notify](https://git.kernel.org/linus/fb3c5386b382d4097476ce9647260fc89b34afdb) functionality can
be used to run sandboxing on kernel space and fallback to user space to dereference pointer
arguments of system calls,

which are one of
- [pathname](https://en.wikipedia.org/wiki/Path_(computing)),
- [UNIX socket address](https://en.wikipedia.org/wiki/Unix_domain_socket),
- [IPv4](https://en.wikipedia.org/wiki/IPv4) or
- [IPv6](https://en.wikipedia.org/wiki/IPv6)
network address -- and make dynamic decisions
using `rsync`-like [wildcards](https://en.wikipedia.org/wiki/Wildcard_character)
such as
[`allowlist/write+/home/sydbox/***`](https://sydbox.exherbo.org/#pattern-matching)
, or
[`allowlist/write+/run/user/*/pulse`](https://sydbox.exherbo.org/#pattern-matching)
for [pathnames](https://en.wikipedia.org/wiki/Path_(computing)),
and using
[CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing)
notation such as
[`allowlist/network/connect+inet:127.0.0.1/8@9050`](https://sydbox.exherbo.org/#address-matching)
, or
[`allowlist/network/connect+inet6:::1/8@9050`](https://sydbox.exherbo.org/#address-matching)
for
[IPv4](https://en.wikipedia.org/wiki/IPv4) and
[IPv6](https://en.wikipedia.org/wiki/IPv6) addresses
and perform an action which is by default denying the system call with an
appropriate error -- which is usually **permission denied**, or
**operation canceled** -- or kill the process running the system call,
or kill all processes at once with
[**SIGKILL**](https://en.wikipedia.org/wiki/Signal_(IPC)#SIGKILL).

See: https://sydbox.exherbo.org

For updates, check out my blog at https://pink.exherbo.org

## Build &amp; Requirements

SydB☮x uses autotools and cargo. To build, simply do `./configure`, `make`, `make -j check`
and `sudo make install`. Make sure you have `cargo` and `cbindgen` under `PATH`.
By default this will produce a statically linked *SydB☮x* binary.
If you want use dynamic linking, give the `--disable-static` option to `./configure`.

Make sure you have `xsltproc` under `PATH` if you want to build the manual page.
You may also browse the manual of the latest version at https://sydbox.exherbo.org.

To use SydB☮x you need a [Linux](https://kernel.org) kernel with version 5.6 or
newer which includes [the secure computing mode](https://en.wikipedia.org/wiki/Seccomp)
with the `SECCOMP_USER_NOTIF_FLAG_CONTINUE` facility,
and the system calls
[pidfd_send_signal](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html),
and [pidfd_getfd](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html).

In addition, it is recommended that you enable the kernel option
`CONFIG_CROSS_MEMORY_ATTACH` so that SydB☮x can use the system calls
[process_vm_readv](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html)
and
[process_vm_writev](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html).
These system calls are available in Linux since 3.2. Note SydB☮x will use the file
`/proc/pid/mem` if these system calls are unavailable or not working so this is
not a hard dependency.

For more information about these requirements, check the following links:
- [kernelnewbies.org/Linux-5.6](https://kernelnewbies.org/Linux_5.6#A_new_pidfd_syscall.2C_pidfd_getfd.282.29)
- [LWN article about pidfd_getfd](https://lwn.net/Articles/808997/)
- `SECCOMP_USER_NOTIF_FLAG_CONTINUE`:
[commit](https://git.kernel.org/linus/fb3c5386b382d4097476ce9647260fc89b34afdb),
[commit](https://git.kernel.org/linus/223e660bc7638d126a0e4fbace4f33f2895788c4), and
[commit](https://git.kernel.org/linus/0eebfed2954f152259cae0ad57b91d3ea92968e8).

## Sandboxing

See the [SydB☮x manual
page](https://dev.exherbo.org/~alip/sydbox/sydbox.html) on more information about
[secure computing mode](https://en.wikipedia.org/wiki/Seccomp) protections. The
parts which are of particular interest to read are:

- [Sandboxing](https://dev.exherbo.org/~alip/sydbox/sydbox.html#sandboxing)
- [core/restrict/general](https://dev.exherbo.org/~alip/sydbox/sydbox.html#core-restrict-general)
- [core/restrict/io_control](https://dev.exherbo.org/~alip/sydbox/sydbox.html#core-restrict-ioctl)
- [core/restrict/memory_map](https://dev.exherbo.org/~alip/sydbox/sydbox.html#core-restrict-mmap)
- [core/restrict/shared_memory_writable](https://dev.exherbo.org/~alip/sydbox/sydbox.html#core-restrict-shm-wr)

## SydB☮x &amp; Pand☮ra

**NOTE:** Pand☮ra is in its early stages of development. To be able to use Pand☮ra
you need **Sydb☮x-2.2.0** or later.

|  .  | @                                                                       |
|-----|:------------------------------------------------------------------------|
| Tar | https://dev.exherbo.org/~alip/sydbox/sydbox-2.2.0.tar.bz2               |
| SHA | https://dev.exherbo.org/~alip/sydbox/sydbox-2.2.0.tar.bz2.sha1sum       |
| GPG | https://dev.exherbo.org/~alip/sydbox/sydbox-2.2.0.tar.bz2.sha1sum.asc   |
| Git | https://git.exherbo.org/git/sydbox-1.git                                |
| Ann | https://pink.exherbo.org/sydbox-v2.0.1/                                 |

- Browse: https://git.exherbo.org/sydbox-1.git/
- Exheres:
  - [sydbox.exlib](https://git.exherbo.org/arbor.git/tree/packages/sys-apps/sydbox/sydbox.exlib)
  - [sydbox-2.2.0.exheres-0](https://git.exherbo.org/arbor.git/tree/packages/sys-apps/sydbox/sydbox-2.2.0.exheres-0)

You can check the build options using `sydbox --version`:

```
$ sydbox --version
sydbox-2.2.0
Options: dump:yes seccomp:yes ipv6:yes netlink:yes
```

To see if your system is supported by **SydB☮x**, use `sydbox ---test`:

```
$ sydbox --test
sydbox: Linux/chesswob 5.12.10
sydbox: [>] Checking for requirements...
sydbox: [*] cross memory attach is functional.
sydbox: [*] /proc/pid/mem interface is functional.
sydbox: [*] pidfd interface is functional.
sydbox: [*] seccomp filters are functional.
sydbox: [>] SydB☮x is supported on this system!
```

To verify **SydB☮x** is working correctly, either use `make -j check` during
installation or use the helper utility `syd-test` to run the installed tests.

# Pand☮ra

https://pandora.exherbo.org

Pand☮ra's Box: A helper for SydB☮x, a ptrace & seccomp based sandbox to make sandboxing practical.
This makes it easy for the end user to use secure computing for practical purposes.

## pandora sandbox

SydB☮x may be configured through the magic path `/dev/sydbox` which is a virtual
path that exists solely for inter-process communication with the sandbox to
configure and extend it. [In
Exherbo](https://exherbo.org/docs/eapi/exheres-for-smarties.html#magic_commands), we
have the command `esandbox` to interface with the sandbox. The subcommand
`pandora sandbox` provides the exact same interface.

**Note**: `pandora sandbox` works as long as the magic lock of Sydb☮x is not
locked either via the magic command `core/trace/magic_lock:on` or via the
command-line option `--lock`. You may also lock the magic command using
`pandora` with `pandora sandbox lock` after which no more sandboxing
commands are permitted.

Here's a list of `pandora sandbox` commands:

### Querying sandbox status
- `check`: Check whether the program is being executed under
  sandboxing.
- `enabled` or `enabled_path`: Check whether path
  sandboxing is enabled.
- `enabled_exec`: Check whether exec sandboxing is enabled.
- `enabled_net`: Check whether network sandboxing is enabled.

### Turning sandboxing on/off
- `enable` or `enable_path`: Enable path sandboxing.
- `disable` or `disable_path`: Disable path sandboxing.
- `enable_exec`: Enable exec sandboxing.
- `disable_exec`: Disable exec sandboxing.
- `enable_net`: Enable network sandboxing.
- `disable_net`: Disable network sandboxing.

#### Whitelisting
- `allow` or `allow_path`: Whitelist a path for path
  sandboxing.  Takes one extra argument which must be an __absolute__ path.
- `disallow` or `disallow_path`: Removes a path from
  the path sandboxing whitelist. Takes one extra argument which must be an
  __absolute__ path.
- `allow_exec`: Whitelist a path for `execve()` sandboxing.  Takes
  one extra argument which must be an __absolute__ path.
- `disallow_exec`: Removes a path from the `execve()` sandboxing whitelist.
Takes one extra argument which must be an __absolute__ path.
- `allow_net`: Whitelist a network address for `bind()` whitelist -
  or for `connect()` whitelist if _--connect_ option is given.
- `disallow_net`: Removes a network address from the `bind()`
  whitelist - or from `connect()` whitelist if _--connect_ option is given.

#### Filtering
- `addfilter` or `addfilter_path`: Add a pattern as
  a path sandboxing filter. Takes one extra argument which is a `fnmatch()` pattern.
- `rmfilter` or `rmfilter_path`: Removes a pattern
  from the path sandboxing filter list. Takes one extra argument which is a
  `fnmatch()` pattern.
- `addfilter_exec`: Add a pattern as a `execve()` sandboxing filter.
  Takes one extra argument which is a `fnmatch()` pattern.
- `rmfilter_exec`: Removes a pattern from the `execve()` sandboxing
  filter list. Takes one extra argument which is a `fnmatch()` pattern.
- `addfilter_net`: Add a network address as a network sandboxing
  filter.  Takes one extra argument which is a network address.
- `rmfilter_net`: Removes a pattern from the network sandboxing
  filter list. Takes one extra argument which is a network address.

#### Miscellaneous commands
- `lock`: Lock magic commands. After calling this none of the
  »sandbox` commands will work. You don«t need to call this, see
  `exec_lock`.
- `exec_lock`: Lock magic commands upon `execve()`.
- `wait_eldest`: By default, sydbox waits for all traced processes
  to exit before exiting. However, this isn't desired in some cases. For example
  when a daemon, like udev, is restarted from within an exheres which will go on its
  execution after installation. This command makes sydbox resume all processes and
  exit after the eldest process has exited.
- `wait_all`: Wait for all processes before exiting. This is the
  default.

### Specifying Network Addresses
Network addresses may be specified in the following forms:

- unix:FNMATCH\_PATTERN
- unix-abstract:FNMATCH\_PATTERN
- inet:ipv4\_address/NETMASK@PORT\_RANGE
- inet6:ipv6\_address/NETMASK@PORT\_RANGE

where /NETMASK can be omitted and PORT\_RANGE can either be a number or two
numbers in the form BEGIN-END. In addition, there are a few network aliases
that are expanded to network addresses. They are listed below:

- LOOPBACK is expanded to inet://127.0.0.0/8
- LOOPBACK6 is expanded to inet6://::1/8
- LOCAL is expanded to four addresses as defined in RFC1918:
  * inet:127.0.0.0/8
  * inet:10.0.0.0/8
  * inet:172.16.0.0/12
  * inet:192.168.0.0/16
- LOCAL6 is expanded to four addresses:
  * inet6:::1
  * inet6:fe80::/7
  * inet6:fc00::/7
  * inet6:fec0::/7

So you may use LOOPBACK@0 instead of inet:127.0.0.0/8@0

## Example 1: Restricted Login Shell

When run without arguments Sydb☮x drops into a restricted login shell.  This is the
default sandboxing profile installed by Sydb☮x and may also be used as basic config
for other applications. It's installed under `$sharedir/sydbox/default.syd-2` where
`$sharedir` is usually `/usr/share`.

**Note**: By default, Sydb☮x allows interacting with the sandbox. Try with
`syd --lock` to disable this for a more real jail experience. Note in this
mode `/dev/sydbox` is inaccessible.

```
$ syd
There is no other day
Let's try it another way
You'll lose your mind and play
Free games for may
See Emily play

I have no name!@sydb☮x /tmp/syd-2-1000-423516-FOBHci $ pandora sandbox check
/dev/sydbox: OK
I have no name!@sydb☮x /tmp/syd-2-1000-423516-FOBHci $ uname -a
☮ sydb☮x 2.2.0 #2 ♡ GNU/Linux
I have no name!@sydb☮x /tmp/syd-2-1000-423516-FOBHci $ hostname
sydb☮x
I have no name!@sydb☮x /tmp/syd-2-1000-423516-FOBHci $ cat /etc/passwd
{"id":5,"ts":1625053319,"pid":520579,"event":{"id":15,"name":"☮☮ps"},"sys":"open","syd":"open(»/etc/passwd«)","comm":"cat","cmd":"cat /etc/passwd ","cwd":"/tmp/syd-2-1000-423516-FOBHci","ppid":423516,"tgid":520579,"proc":{"ppid":423517,"tgid":520579,"cwd":"/tmp/syd-2-1000-423516-FOBHci"}}
cat: /etc/passwd: Operation not permitted
I have no name!@sydb☮x /tmp/syd-2-1000-423516-FOBHci $ cd /tmp
{"id":9,"ts":1625053379,"pid":423517,"event":{"id":15,"name":"☮☮ps"},"sys":"chdir","syd":"chdir(»/tmp«)","comm":"bash","cmd":"bash --rcfile /usr/share/sydbox/sydbox.bashrc -i ","cwd":"/tmp/syd-2-1000-423516-FOBHci","ppid":0,"tgid":423517,"proc":{"ppid":423516,"tgid":423517,"cwd":"/tmp/syd-2-1000-423516-FOBHci"}}
bash: cd: /tmp: Permission denied
I have no name!@sydb☮x /tmp/syd-2-1000-423516-FOBHci $
```

## Example 2: Sandbox Firefox

Step 1: Inspect and gather data about the given process.

In this case, we're going to try with
[https://www.mozilla.org/de/firefox/new/](Firefox).

```
$ pandora profile firefox
```

Browse using firefox for a while, let pandora gather data. The browser is running
under a tracer so it'll run noticably slower.

- use --bin /path/to/sydbox, if sydbox is not in PATH
- use --output firefox.syd-2 to specify an alternative output path for profile.

```
$ $EDITOR out.syd-2
```

Inspect what the browser has been doing.
Enable, disable additional options or turn paths into wildcards such as
`/home/***` to allow home and everything beyond /home
the usual glob characters, `?, *` are supported.

Check [SydB☮x manual page](https://dev.exherbo.org/~alip/sydbox/sydbox.html#pattern-matching) to
learn more on how **PATTERN MATCHING** works.

Enable, disable additional network addresses unless you're using a **SOCKS5 proxy**
which does remote DNS lookups, e.g:

***allowlist/network/connect+inet:127.0.0.1@9050***

for [Tor](https://www.torproject.org/).

Check [SydB☮x manual page](https://dev.exherbo.org/~alip/sydbox/sydbox.html#address-matching) to
learn more on how **ADDRESS MATCHING** works.

```
$ pandora box -c out.syd-2 firefox
```

- Run the browser under secure computing with full protection.
- Check [SydB☮x manual page for a list of system call
  protections.](https://dev.exherbo.org/~alip/sydbox/sydbox.html#sandboxing)
- Check the console for possible access violations over time.

- *Edit the profile file as necessary and update restrictions.*

For instance if you see an access violation such as
```
sydbox: 8< -- Access Violation! --
sydbox: connect(-1, unix:/run/user/1000/pulse/native)
sydbox: proc: AudioIPC Server[754336] (parent:0)
sydbox: cwd: »/home/alip/src/exherbo/sydbox-1«
sydbox: cmdline: »/usr/lib/firefox/firefox «
sydbox: >8 --
sydbox: 8< -- Access Violation! --
sydbox: connect(-1, unix:/var/run/pulse/native)
sydbox: proc: AudioIPC Server[754336] (parent:0)
sydbox: cwd: »/home/alip/src/exherbo/sydbox-1«
sydbox: cmdline: »/usr/lib/firefox/firefox «
sydbox: >8 --
```

This sounds like you're trying to play some audio on your browser. In this case, you
should add an allowlist to your profile `.syd-2` file and restart your browser under
this new profile.

```
allowlist/connect/network+unix:/run/pulse/native
allowlist/connect/network+unix:/var/run/pulse/native
```

Note, sometimes you may have to add a symbolic link rather than the file it is
pointing to, or vice versa, or both.

Last but not least,

**Share your profile with other people and help others use secure computing!**

Here is a Firefox profile edited by yours truly:

https://git.exherbo.org/sydbox-1.git/plain/data/firefox.syd-2

# PinkTrace

If you do not have a very recent Linux version, you may use Sydb☮x-1.2.1 which
requires [Pink's Tracing Library](http://dev.exherbo.org/~alip/pinktrace/api/c/)

**NOTE: SydB☮x-2.0.1 and newer do not use ptrace() but use seccomp user notify
facilities in recent Linux kernels 5.6 and newer. Hence, PinkTrace is no longer a
dependency.**

See: https://pinktrace.exherbo.org

- Exheres:
  - [pinktrace-1.exlib](https://git.exherbo.org/arbor.git/tree/packages/dev-libs/pinktrace/pinktrace.exlib)
  - [pinktrace-scm.exheres-0](https://git.exherbo.org/arbor.git/tree/packages/dev-libs/pinktrace/pinktrace-scm.exheres-0)
- Git: https://git.exherbo.org/git/pinktrace-1.git
- Lightweight [ptrace](http://linux.die.net/man/2/ptrace) wrapper library
  providing a robust API for tracing processes.
- An extensive API reference is available [here](http://dev.exherbo.org/~alip/pinktrace/api/c/).
- Tar: https://dev.exherbo.org/distfiles/pinktrace/pinktrace-0.9.6.tar.bz2
- Git: https://git.exherbo.org/git/pinktrace-1.git

# Bugs
Read [BUGS](https://git.exherbo.org/sydbox-1.git/plain/BUGS).

Below are the details of the author. **Mail is preferred. Attaching poems encourages
consideration tremendously.**

```
Hey you, out there beyond the wall,
Breaking bottles in the hall,
Can you help me?
```

- **Alï Polatel** [alip@exherbo.org](mailto:alip@exherbo.org)
- **Exherbo:** https://git.exherbo.org/dev/alip.git/
- **Github:** https://github.com/alip/
- **Twitter:** https://twitter.com/hayaliali
- **Mastodon:** https://mastodon.online/@alip
- **IRC:** alip at [Libera](https://libera.chat/)

# Git
- **Original Git**: https://git.exherbo.org/sydbox-1.git/
- **Github Mirror**: https://github.com/sydbox/sydbox-1

Github mirror is updated periodically. Feel free to submit an issue or a pull
request there. **Attaching poems encourages consideration tremendously.**

# Documentation

Read the fine manual of [SydB☮x](https://dev.exherbo.org/~alip/sydbox/sydbox.html) and [SydFmt](https://dev.exherbo.org/~alip/sydbox/sydfmt.html).

# Blog Posts

* [Sydb☮x: Stop Skype P2P/Call Home: People Have The Right To Communicate W\o Eavesdropping](https://tinyurl.com/sydbox-stop-skype-call-home)
* [Recent Linux Changes Help Safe & Secure w\o Root](https://tinyurl.com/recent-linux-changes-help-safe)
* [A Study in Sydb☮x](https://tinyurl.com/a-study-in-sydbox)
* [Pink's Tracing Library](https://tinyurl.com/pink-s-tracing-library)
* [Sydb☮x Logo Survey](https://tinyurl.com/sydbox-logo-survey)
* [Sydb☮x: Default Sandbox of Exherbo](https://tinyurl.com/sydbox-default-sandbox-exherbo)
* [Disabling External Commands in Metadata Phase (Exherbo&gt;Gentoo)](https://tinyurl.com/no-commands-in-metadata-phase)
* [ptrace on IA64](https://tinyurl.com/ptrace-on-ia64)
* [Network Sandboxing and /proc (Exherbo&gt;Gentoo)](https://tinyurl.com/network-sandboxing-and-proc)
* [ptrace on FreeBSD](https://tinyurl.com/ptrace-on-freebsd)
* [Running Untrusted Binaries that Access the Network](https://tinyurl.com/running-untrusted-binaries)
* [Proper Network Sandboxing (Exherbo&gt;Gentoo)](https://tinyurl.com/proper-network-sandboxing)
* [Deprecating addpredict (Exherbo&gt;Gentoo)](https://tinyurl.com/deprecating-addpredict-gentoo)

<!-- vim: set tw=80 ft=markdown spell spelllang=en sw=4 sts=4 et : -->
