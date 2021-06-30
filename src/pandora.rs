//
// pandora: Sydbox's Dump Inspector & Profile Writer
// pandora.rs: Main entry point
//
// Copyright (c) 2021 Ali Polatel <alip@exherbo.org>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::iter::FromIterator;
use std::os::unix::fs;
use std::os::unix::io::FromRawFd;
use std::process::Command;

use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{App, Arg, SubCommand};
use serde::{Deserialize, Serialize};

pub mod built_info {
    // The file has been placed there by the build script.
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(u8)]
enum Sandbox {
    Bind,
    Connect,
    Exec,
    Write,
    Read,
}

impl std::fmt::Display for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Bind => write!(f, "allowlist/network/bind"),
            Self::Connect => write!(f, "allowlist/network/connect"),
            Self::Write => write!(f, "allowlist/write"),
            Self::Exec => write!(f, "allowlist/exec"),
            Self::Read => write!(f, "#? allowlist/read"),
        }
    }
}

const DEFAULT: &str = "
core/sandbox/exec:allow
core/sandbox/read:allow
core/sandbox/write:deny
core/sandbox/network:deny

# This is important or our configuration
# below won't work as expected for paths
# under /proc/self.
core/allowlist/per_process_directories:false

core/allowlist/successful_bind:true

# We only passthrough UNIX sockets, UNIX abstract
# sockets, IPv4 and IPv6 addresses. The rest,
# e.g: NETLINK addresses are denied by default.
core/allowlist/unsupported_socket_families:false

core/violation/decision:deny
core/violation/exit_code:-1

# The defaults are not noisy, but the shell
# is allowed to make a bit more noise......
core/violation/raise_fail:false
core/violation/raise_safe:true

core/trace/memory_access:0
core/trace/program_checksum:2

# Try very hard to find a current working
# directory to check the path argument
# with. Otherwise the system call will
# be denied.
core/trace/use_toolong_hack:true

core/restrict/id_change:true
core/restrict/system_info:true
core/restrict/io_control:false
core/restrict/memory_map:false
core/restrict/shared_memory_writable:true
core/restrict/general:0

core/match/case_sensitive:true
core/match/no_wildcard:literal

# Kill programs executed from /home.
# exec/kill_if_match+/home/***

# Use binaries under well-known locations.
# Leave out HOME for now till we have support
# to substitute environment variables in
# configuration.
denylist/exec+/etc/***
denylist/exec+/dev/***
denylist/exec+/proc/***
denylist/exec+/run/***
denylist/exec+/sys/***
denylist/exec+/var/***
denylist/exec+/tmp/***
#denylist/exec+/home/***

# Deny access to potentially dangerous paths.
denylist/read+/boot/***
denylist/read+/root/***

# Restrict /etc
denylist/read+/etc/security/***
denylist/read+/etc/g?shadow*
denylist/read+/etc/passwd*
denylist/read+/etc/group+
denylist/read+/etc/ftpusers
denylist/read+/etc/aliases
denylist/read+/etc/services
denylist/read+/etc/conf.*/***
denylist/read+/etc/init.*/***
denylist/read+/etc/rc.*/***
denylist/read+/etc/system.*/***
denylist/read+/etc/xinet.*/***
denylist/read+/etc/ssl*/***
denylist/read+/etc/mtab
denylist/read+/etc/fstab
denylist/read+/etc/crontab
denylist/read+/etc/cron*/***
denylist/read+/etc/crypttab
denylist/read+/etc/securetty
denylist/read+/etc/pam*/***

# Disable /dev/mem /dev/kmem, /dev/port and /proc/kcore.
denylist/read+/dev/k?mem
denylist/read+/dev/port
denylist/read+/dev/autofs
denylist/read+/dev/btrfs-control
denylist/read+/dev/ram*
# /dev/core -> /proc/kcore
denylist/read+/dev/core
denylist/read+/proc/kcore
denylist/read+/dev/usb*
denylist/read+/dev/vga_arbiter
denylist/read+/dev/watchdog*
denylist/read+/dev/zram*

# /proc/kallsyms exposes the kernel memory space address of many kernel symbols
# (functions, variables, etc...). This information is useful to attackers in
# identifying kernel versions/configurations and in preparing payloads for the
# exploits of kernel space.
denylist/read+/proc/kallsyms

# Disable process memory attach.
denylist/read+/proc/*/mem
denylist/read+/proc/*/*map*
denylist/read+/proc/*/map_files/***
denylist/read+/proc/*/syscall

# More critical paths under proc:
denylist/read+/proc/*/root/***

# No access to system logs
denylist/read+/var/log/***

# Disable tools to get information on the running
# kernel and its configuration.
denylist/read+/dev/kmsg
denylist/read+/proc/cmdline
denylist/read+/proc/config*
denylist/read+/proc/version
denylist/read+/proc/sys/***
denylist/read+/etc/sysctl.conf
denylist/read+/etc/sysctl.d/***

# Deny access to system information.
denylist/read+/proc/cpuinfo
denylist/read+/proc/meminfo
denylist/read+/proc/swaps
denylist/read+/proc/iomem
denylist/read+/proc/slabinfo
denylist/read+/proc/vmallocinfo
denylist/read+/proc/vmstat
denylist/read+/proc/self/auxv
denylist/read+/proc/self/cgroup
denylist/read+/proc/self/cwd
denylist/read+/proc/self/environ
denylist/read+/proc/self/mtab
denylist/read+/proc/self/net/***
denylist/read+/proc/self/ns/***
# Take into account both {numa_,}maps {,s}maps{_rollup}
denylist/read+/proc/self/*map*
denylist/read+/proc/self/map_files/***
denylist/read+/proc/self/mem
denylist/read+/proc/self/mount*
denylist/read+/proc/self/oom*
denylist/read+/proc/self/root
denylist/read+/proc/self/setgroups
# Take into account {sched,}stat{m,us}
denylist/read+/proc/self/*stat*
denylist/read+/proc/self/syscall
denylist/read+/proc/self/task

# More restrictions:
denylist/read+/sys/fs/***

# Fuse could lead to local dos for instance creating file a la /dev/null with
# random content. Moreover they are past problem in the fuse kernel code that
# lead to dos.
# Filesystem created by fuse are not visible by other user including root in
# order to avoid dos. For instance an user that create an infinite depth
# filesystem in order to fool updatedb.
denylist/read+/dev/fuse

# Deny access to Device Mapper data nodes.
denylist/read+/dev/dm*/***
denylist/read+/dev/mapper/***

# Some critical paths under /home
# We leave shell rc files alone except login.
denylist/read+/home/*/.*login*
denylist/read+/home/*/.netrc*
denylist/read+/home/*/.ssh*
denylist/read+/home/*/.gnupg*
denylist/read+/home/*/.password-store/***
denylist/write+/home/*/.*login*
denylist/write+/home/*/.netrc*
# This includes sh, bash, zsh and ssh.
denylist/write+/home/*/.*sh*
denylist/write+/home/*/.gnupg*
denylist/write+/home/*/.password-store/***

# Deny access to config and cache
denylist/read+/home/*/.config*/***
denylist/write+/home/*/.config*/***
denylist/read+/home/*/.cache*/***
denylist/write+/home/*/.cache*/***

# Common mua, editor, browser directories.
denylist/read+/home/*/.emacs*/***
denylist/write+/home/*/.emacs*/***
denylist/read+/home/*/.mutt*/***
denylist/write+/home/*/.mutt*/***
denylist/read+/home/*/.mozilla*/***
denylist/write+/home/*/.mozilla*/***
denylist/read+/home/*/.vim*/***
denylist/write+/home/*/.vim*/***

#
# Allow access to standard paths
#
allowlist/write+/dev/stdout
allowlist/write+/dev/stderr
allowlist/write+/dev/zero
allowlist/write+/dev/null
allowlist/write+/dev/full
allowlist/write+/dev/console
allowlist/write+/dev/random
allowlist/write+/dev/urandom
allowlist/write+/dev/ptmx
allowlist/write+/dev/fd/***
allowlist/write+/dev/tty*
allowlist/write+/dev/pty*
allowlist/write+/dev/tts
allowlist/write+/dev/pts/***
allowlist/write+/dev/shm/***
allowlist/write+/selinux/context/***
allowlist/write+/proc/self/attr/***
allowlist/write+/proc/self/fd/***
allowlist/write+/proc/self/task/***
allowlist/write+/tmp/***
allowlist/write+/var/tmp/***
allowlist/write+/var/cache/***

# Allow access to Tor via IPv{4,6}
allowlist/network/connect+LOOPBACK@9050
allowlist/network/connect+LOOPBACK6@9050

# Partly allow access to the localhost.
allowlist/network/bind+LOOPBACK@0
allowlist/network/bind+LOOPBACK@1024-65535
allowlist/network/bind+LOOPBACK6@0
allowlist/network/bind+LOOPBACK6@1024-65535

allowlist/network/connect+unix:/var/run/nscd/socket
allowlist/network/connect+unix:/run/nscd/socket
allowlist/network/connect+unix:/var/lib/sss/pipes/nss

# Allow getaddrinfo() with AI_ADDRCONFIG on musl systems.
allowlist/network/connect+LOOPBACK@65535
allowlist/network/connect+LOOPBACK6@65535

# Lock configuration
# core/trace/magic_lock:on
";

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
struct EventStruct {
    id: u32,
    //name: String,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
struct ProcessStruct {
    // pid: u32,
// stat: StatStruct,
// syd: SydStruct,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
enum Dump {
    Init {
        id: u32,
        shoebox: u32,
        name: String,
    },
    StartUp {
        id: u32,
        ts: u64,
        cmd: String,
        process: ProcessStruct,
    },
    SysEnt {
        id: u32,
        ts: u64,
        event: EventStruct,
        /*
        pid: u32,
        ppid: u32,
        tgid: u32,
        */
        name: String,
        args: [i64; 6],
        repr: [String; 6],
    },
    ThreadNew {
        id: u32,
    },
    ThreadFree {
        id: u32,
    },
}

fn command_box<'a>(
    bin: &'a str,
    cmd: &mut Vec<&'a str>,
    arch: &Option<Vec<&'a str>>,
    config: &Option<Vec<&'a str>>,
    magic: &Option<Vec<&'a str>>,
    bpf: bool,
    dump: &Option<&'a str>,
    export: &Option<&'a str>,
) -> i32 {
    cmd.insert(0, "--");
    if let Some(ref magic) = magic {
        for item in magic.iter() {
            cmd.insert(0, item);
            cmd.insert(0, "-m");
        }
    }
    if let Some(ref config) = config {
        for item in config.iter() {
            cmd.insert(0, item);
            cmd.insert(0, "-c");
        }
    }
    if let Some(ref arch) = arch {
        for item in arch.iter() {
            cmd.insert(0, item);
            cmd.insert(0, "-a");
        }
    }
    if bpf {
        cmd.insert(0, "-b");
    }
    if let Some(dump_fd) = dump {
        cmd.insert(0, dump_fd);
        cmd.insert(0, "-d");
    }
    if let Some(export_format) = export {
        cmd.insert(0, export_format);
        cmd.insert(0, "--export");
    }
    cmd.insert(0, bin);
    // eprintln!("executing `{:?}'", cmd);
    let cmdline: Vec<CString> = cmd
        .iter()
        .map(|c| CString::new(c.as_bytes()).unwrap())
        .collect();

    match nix::unistd::execvp(&cmdline[0], &cmdline) {
        Ok(_) => 0,
        Err(nix::Error::Sys(errno)) => {
            eprintln!("error executing `{:?}': {}", cmdline, errno);
            1
        }
        Err(error) => {
            eprintln!("error executing `{:?}': {:?}", cmdline, error);
            1
        }
    }
}

fn command_profile<'b>(bin: &'b str, cmd: &[&'b str], output_path: &'b str, path_limit: u8) -> i32 {
    let (fd_rd, fd_rw) = match nix::unistd::pipe() {
        Ok((fd_rd, fd_rw)) => (fd_rd, fd_rw),
        Err(error) => {
            eprintln!("error creating pipe: {}", error);
            return 1;
        }
    };

    let mut child = Command::new(bin)
        .arg("--dry-run")
        .arg("-m")
        .arg("core/sandbox/read:deny")
        .arg("-m")
        .arg("core/sandbox/write:deny")
        .arg("-m")
        .arg("core/sandbox/exec:deny")
        .arg("-m")
        .arg("core/sandbox/network:deny")
        .arg("-m")
        .arg("core/restrict/shared_memory_writable:0")
        .arg("-d")
        .arg(format!("{}", fd_rw))
        .arg("--")
        .args(cmd)
        .spawn()
        .expect("sydb☮x command failed to start");

    nix::unistd::close(fd_rw).expect("failed to close write end of pipe");
    let input = Box::new(std::io::BufReader::new(unsafe {
        std::fs::File::from_raw_fd(fd_rd)
    }));
    let r = do_inspect(input, output_path, path_limit);

    child.wait().expect("failed to wait for sydb☮x");
    eprintln!("success writing output to `{}' dump", output_path);
    eprintln!("Edit the file ẁith your editor as necessary.");
    eprintln!("Then use 'pand☮rⒶ box -c \"{}\" <command>'", output_path);
    eprintln!("To run the command under SydB☮x.");

    r
}

fn command_inspect(input_path: &str, output_path: &str, path_limit: u8) -> i32 {
    let input = open_input(input_path);
    do_inspect(input, output_path, path_limit)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() <= 1 {
        spawn_sydbox_shell(true, true, &vec![]);
        return;
    }

    let arch_values = [
        "native", "x86_64", "x86", "x32", "arm", "aarch64", "mips", "mips64", "ppc", "ppc64",
        "ppc64le", "s390", "s390x", "parisc", "parisc64", "riscv64",
    ];
    let dump_values = ["fd[0-9]+", "path", "tmp"];
    let export_values = ["bpf", "pfc"];
    let matches = App::new(built_info::PKG_NAME)
        .version(built_info::PKG_VERSION)
        .author(built_info::PKG_AUTHORS)
        .about(built_info::PKG_DESCRIPTION)
        .after_help(&*format!(
            "\
If no subcommands are given, Pand☮rⒶ executes a shell with the argument `-l'.
To figure out the shell first the SHELL environment variable is checked.
If this is not set, the default shell is `/bin/sh'.

In login shell mode, if the file `/etc/pandora.syd-2' exists,
Pand☮rⒶ will tell SydB☮x to use this file as configuration.

In login shell mode, SydB☮x uses the PⒶludis profile as the default set of configuration values.
To see this default set of configuration values and white lists of system paths, check:
https://git.exherbo.org/sydbox-1.git/plain/data/paludis.syd-2

Hey you, out there beyond the wall,
Breaking bottles in the hall,
Can you help me?

Send bug reports to {}
Attaching poems encourages consideration tremendously.

License: {}
Homepage: {}
Repository: {}
",
            built_info::PKG_AUTHORS,
            built_info::PKG_LICENSE,
            built_info::PKG_HOMEPAGE,
            built_info::PKG_REPOSITORY,
        ))
        .subcommand(
            SubCommand::with_name("box")
                .about("Execute the given command under sydb☮x")
                .arg(
                    Arg::with_name("bin")
                        .default_value("syd")
                        .required(true)
                        .help("Path to sydb☮x binary")
                        .long("bin")
                        .env("SYDBOX_BIN"),
                )
                .arg(
                    Arg::with_name("config")
                        .required(false)
                        .help("path spec to the configuration file, may be repeated")
                        .short("c")
                        .multiple(true)
                        .number_of_values(1),
                )
                .arg(
                    Arg::with_name("magic")
                        .required(false)
                        .help("run a magic command during init, may be repeated")
                        .short("m")
                        .multiple(true)
                        .number_of_values(1),
                )
                .arg(
                    Arg::with_name("arch")
                        .default_value("native")
                        .required(false)
                        .help("filter system calls for the given architecture, may be repeated")
                        .short("a")
                        .long("arch")
                        .number_of_values(1)
                        .possible_values(&arch_values),
                )
                .arg(
                    Arg::with_name("bpf-only")
                        .required(false)
                        .help("run in bpf only mode, no seccomp user notifications")
                        .short("b"),
                )
                .arg(
                    Arg::with_name("dump")
                        .required(false)
                        .help("dump system call information to the given file descriptor")
                        .short("d")
                        .number_of_values(1)
                        .possible_values(&dump_values),
                )
                .arg(
                    Arg::with_name("export")
                        .required(false)
                        .help("export the seccomp filters to standard error on startup")
                        .long("export")
                        .number_of_values(1)
                        .possible_values(&export_values),
                )
                .arg(
                    Arg::with_name("dry-run")
                        .required(false)
                        .help("run under inspection without denying system calls")
                        .long("dry-run"),
                )
                .arg(
                    Arg::with_name("test")
                        .required(false)
                        .help("test if various runtime requirements are functional and exit")
                        .long("test"),
                )
                .arg(Arg::with_name("cmd").required(true).multiple(true)),
        )
        .subcommand(
            SubCommand::with_name("profile")
                .about("Execute a program under inspection and write a sydb☮x profile")
                .arg(
                    Arg::with_name("bin")
                        .default_value("syd")
                        .required(true)
                        .help("Path to sydb☮x binary")
                        .long("bin")
                        .env("SYDBOX_BIN"),
                )
                .arg(
                    Arg::with_name("output")
                        .default_value("./out.syd-2")
                        .required(true)
                        .help("Path to sydb☮x profile output")
                        .long("output")
                        .short("o")
                        .env("SHOEBOX_OUT"),
                )
                .arg(
                    Arg::with_name("limit")
                        .default_value("7")
                        .required(false)
                        .help("Maximum number of path members before trim, 0 to disable")
                        .long("limit")
                        .short("l"),
                )
                .arg(Arg::with_name("cmd").required(true).multiple(true)),
        )
        .subcommand(
            SubCommand::with_name("inspect")
                .about("Read a sydb☮x core dump and write a sydb☮x profile")
                .arg(
                    Arg::with_name("input")
                        .default_value("./sydcore")
                        .required(true)
                        .help("Path to sydb☮x core dump")
                        .long("input")
                        .short("i")
                        .env("SHOEBOX"),
                )
                .arg(
                    Arg::with_name("output")
                        .default_value("./out.syd-2")
                        .required(true)
                        .help("Path to sydb☮x profile output")
                        .long("output")
                        .short("o")
                        .env("SHOEBOX_OUT"),
                )
                .arg(
                    Arg::with_name("limit")
                        .default_value("7")
                        .required(false)
                        .help("Maximum number of path members before trim, 0 to disable")
                        .long("limit")
                        .short("l"),
                ),
        )
        .subcommand(
            SubCommand::with_name("sandbox")
                .about("Configure Sydb☮x' sandbox using the /dev/sydb☮x magic link")
                .arg(
                    Arg::with_name("cmd")
                        .required(true)
                        .multiple(true)
                        .help("
SydB☮x may be configured through the magic path `/dev/sydb☮x` which is a virtual
path that exists solely for inter-process communication with the sandbox to
configure and extend it. In Exherbo (see: Exheres for Smarties[1]), we
have the command `esandbox` to interface with the sandbox. The subcommand
`pandora sandbox` provides the exact same interface.

**Note**: `pandora sandbox` works as long as the magic lock of Sydb☮x is not
locked either via the magic command `core/trace/magic_lock:on` or via the
command-line option `--lock`. You may also lock the magic command using
`pandora` with `pandora sandbox lock` after which no more sandboxing
commands are permitted.

Here's a list of `pandora sandbox` commands:

# Querying sandbox status
- `check`: Check whether the program is being executed under
  sandboxing.
- `enabled` or `enabled_path`: Check whether path
  sandboxing is enabled.
- `enabled_exec`: Check whether exec sandboxing is enabled.
- `enabled_net`: Check whether network sandboxing is enabled.

# Turning sandboxing on/off
- `enable` or `enable_path`: Enable path sandboxing.
- `disable` or `disable_path`: Disable path sandboxing.
- `enable_exec`: Enable exec sandboxing.
- `disable_exec`: Disable exec sandboxing.
- `enable_net`: Enable network sandboxing.
- `disable_net`: Disable network sandboxing.

# Whitelisting
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

# Filtering
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

# Miscellaneous commands
- `lock`: Lock magic commands. After calling this none of the
  `sandbox` commands will work. You don't need to call this, see
  `exec_lock`.
- `exec_lock`: Lock magic commands upon `execve()`.
- `wait_eldest`: By default, sydb☮x waits for all traced processes
  to exit before exiting. However, this isn't desired in some cases. For example
  when a daemon, like udev, is restarted from within an exheres which will go on its
  execution after installation. This command makes sydb☮x resume all processes and
  exit after the eldest process has exited.
- `wait_all`: Wait for all processes before exiting. This is the
  default.

# Specifying Network Addresses
Network addresses may be specified in the following forms:

- unix:FNMATCH_PATTERN
- unix-abstract:FNMATCH_PATTERN
- inet:ipv4_address/NETMASK@PORT_RANGE
- inet6:ipv6_address/NETMASK@PORT_RANGE

where /NETMASK can be omitted and PORT_RANGE can either be a number or two
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
")
                )
        )
        .subcommand(
            SubCommand::with_name("shell")
                .about("Run SydB☮x' restricted login shell")
                .arg(
                    Arg::with_name("lock")
                        .required(false)
                        .help("Lock /dev/sydb☮x IPC in sandbox")
                        .long("lock")
                        .short("l"),
                )
                .arg(Arg::with_name("args").required(false).multiple(true))
        )
        .get_matches();

    if let Some(ref matches) = matches.subcommand_matches("box") {
        let bin = matches.value_of("bin").unwrap();
        let bpf = matches.is_present("bpf-only");
        let mut cmd: Vec<&str> = matches.values_of("cmd").unwrap().collect();
        let mut dump: Option<&str> = None;
        if let Some(dump_fd) = matches.value_of("dump") {
            dump = Some(dump_fd);
        }
        let mut export: Option<&str> = None;
        if let Some(export_format) = matches.value_of("export") {
            if export_format == "bpf" || export_format == "pfc" {
                export = Some(export_format);
            } else {
                clap::Error::with_description(
                    &format!(
                        "Invalid value `{}' for --export: use bpf, pfc",
                        export_format
                    ),
                    clap::ErrorKind::InvalidValue,
                )
                .exit();
            }
        }
        let arch: Option<Vec<&str>> = matches.values_of("arch").map(|values| values.collect());
        let config: Option<Vec<&str>> = matches.values_of("config").map(|values| values.collect());
        let magic: Option<Vec<&str>> = matches.values_of("magic").map(|values| values.collect());
        std::process::exit(command_box(
            bin, &mut cmd, &arch, &config, &magic, bpf, &dump, &export,
        ));
    } else if let Some(ref matches) = matches.subcommand_matches("sandbox") {
        let cmd: Vec<&str> = matches.values_of("cmd").unwrap().collect();
        esandbox(&cmd);
    } else if let Some(ref matches) = matches.subcommand_matches("shell") {
        let lock: bool = matches.is_present("lock");
        let args: Vec<&str>;
        if matches.is_present("args") {
            args = matches.values_of("args").unwrap().collect();
        } else {
            args = vec![];
        }
        spawn_sydbox_shell(false, lock, &args);
    } else if let Some(ref matches) = matches.subcommand_matches("profile") {
        let bin = matches.value_of("bin").unwrap();
        let out = matches.value_of("output").unwrap();
        let cmd: Vec<&str> = matches.values_of("cmd").unwrap().collect();
        let value = matches.value_of("limit").unwrap();
        let limit = match value.parse::<u8>() {
            Ok(value) => value,
            Err(error) => {
                clap::Error::with_description(
                    &format!("Invalid value `{}' for --limit: {}", value, error),
                    clap::ErrorKind::InvalidValue,
                )
                .exit();
            }
        };
        std::process::exit(command_profile(bin, &cmd, out, limit));
    } else if let Some(ref matches) = matches.subcommand_matches("inspect") {
        let value = matches.value_of("limit").unwrap();
        let limit = match value.parse::<u8>() {
            Ok(value) => value,
            Err(error) => {
                clap::Error::with_description(
                    &format!("Invalid value `{}' for --limit: {}", value, error),
                    clap::ErrorKind::InvalidValue,
                )
                .exit();
            }
        };
        std::process::exit(command_inspect(
            matches.value_of("input").unwrap(),
            matches.value_of("output").unwrap(),
            limit,
        ));
    } else {
        spawn_sydbox_shell(true, false, &vec![]);
    }
}

fn do_inspect(input: Box<dyn std::io::BufRead>, output_path: &str, path_limit: u8) -> i32 {
    let mut output = open_output(output_path);
    let mut magic = std::collections::HashSet::<(Sandbox, String)>::new();
    let mut program_invocation_name = "?".to_string();
    let mut program_command_line = "?".to_string();
    let mut program_startup_time = UNIX_EPOCH;

    for line in input.lines() {
        let serialized = match line {
            Ok(line) if line.is_empty() => {
                break; /* EOF */
            }
            Ok(line) => line,
            Err(error) => {
                eprintln!("failed to read line from input: {}", error);
                return 1;
            }
        };

        let (maybe_program_invocation_name, maybe_program_command_line, maybe_program_startup_time) =
            parse_json_line(&serialized, &mut magic, path_limit);
        if let Some(name) = maybe_program_invocation_name {
            program_invocation_name = name;
        }
        if let Some(line) = maybe_program_command_line {
            program_command_line = line;
        }
        if let Some(time) = maybe_program_startup_time {
            program_startup_time = time;
        }
    }

    /* Step 1: Print out the magic header. */
    let program_startup_datetime = DateTime::<Utc>::from(program_startup_time);
    writeln!(
        &mut output,
        "#
# Sydbox profile generated by Pandora-{}
# Date: {}

###
# Global Defaults
###
core/sandbox/read:off
core/sandbox/write:deny
core/sandbox/exec:deny
core/sandbox/network:deny

# Further restrictions for open(), fcntl() and mmap()
# See sydbox manual page for further details
core/restrict/io_control:false
core/restrict/memory_map:false
core/restrict/shared_memory_writable:false

core/allowlist/per_process_directories:true
core/allowlist/successful_bind:true
core/allowlist/unsupported_socket_families:true

core/violation/decision:deny
core/violation/exit_code:-1
core/violation/raise_fail:false
core/violation/raise_safe:false

core/trace/follow_fork:true
core/trace/use_seccomp:true
core/trace/use_seize:true
core/trace/use_toolong_hack:true

core/match/case_sensitive:true
core/match/no_wildcard:literal

# Safe defaults for system paths
allowlist/write+/dev/stdout
allowlist/write+/dev/stderr
allowlist/write+/dev/zero
allowlist/write+/dev/null
allowlist/write+/dev/full
allowlist/write+/dev/console
allowlist/write+/dev/random
allowlist/write+/dev/urandom
allowlist/write+/dev/ptmx
allowlist/write+/dev/fd/***
allowlist/write+/dev/tty*
allowlist/write+/dev/pty*
allowlist/write+/dev/tts
allowlist/write+/dev/pts
allowlist/write+/dev/pts/***
allowlist/write+/dev/shm/***
allowlist/write+/selinux/context/***
allowlist/write+/proc/self/attr/***
allowlist/write+/proc/self/fd/***
allowlist/write+/proc/self/task/***
allowlist/write+/tmp/***
allowlist/write+/var/tmp/***

# Safe defaults for local network
# This allows bind to all loopback ports.
# Each successful bind is automatically allowlisted for connect with
# core/allowlist/successful_bind:true
allowlist/network/bind+LOOPBACK@0
allowlist/network/bind+LOOPBACK@1024-65535
allowlist/network/bind+LOOPBACK6@0
allowlist/network/bind+LOOPBACK6@1024-65535

allowlist/network/connect+unix:/var/run/nscd/socket
allowlist/network/connect+unix:/run/nscd/socket
allowlist/network/connect+unix:/var/lib/sss/pipes/nss
###

###
# Magic entries generated for:
# Program: `{}'
# Command Line: `{}'
###
",
        built_info::PKG_VERSION,
        program_startup_datetime.format("%Y-%m-%d %H:%M:%S.%f"),
        program_invocation_name,
        program_command_line
    )
    .unwrap_or_else(|_| panic!("failed to print header to output `{}'", output_path));

    /* Step 2: Print out magic entries */
    let mut list = Vec::from_iter(magic);
    list.sort_by_key(|(_, argument)| argument.clone()); /* secondary alphabetical sort. */
    #[allow(clippy::clone_on_copy)]
    list.sort_by_cached_key(|(sandbox, _)| sandbox.clone()); /* primary sandbox sort. */
    for entry in list {
        writeln!(&mut output, "{}+{}", entry.0, entry.1).unwrap_or_else(|_| {
            panic!(
                "failed to print entry `{:?}' to output `{}'",
                entry, output_path
            )
        });
    }

    writeln!(
        &mut output,
        "\n# Lock configuration\ncore/trace/magic_lock:on"
    )
    .unwrap_or_else(|_| panic!("failed to lock configuration for output `{}'", output_path));

    0
}

fn spawn_sydbox_shell(env_shell: bool, magic_lock: bool, args: &Vec<&str>) -> ()
{
    let tmpname = format!("pandora-{}-{}-{}",
        built_info::PKG_VERSION,
        nix::unistd::getuid(),
        nix::unistd::getpid());
    let tmpdir = match tempfile::Builder::new().prefix(&tmpname).tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("[0;1;31;91mFailed to create temporary directory: {}[0m", e);
            return;
        }
    };

    match nix::unistd::chdir(tmpdir.path()) {
        Ok(_) => {
            match fs::symlink("/dev/sydbox", "None") {
                Ok(_) => {
                    magic_stat("/dev/sydbox");
                }
                Err(e) => {
                    eprintln!("[0;1;31;91mFailed to create /dev/SydB☮x symbolic link: {}[0m", e);
                }
            }
        }
        Err(e) => {
            eprintln!("[0;1;31;91mFailed to change directory to temporary directory: {}[0m", e);
        }
    }

    /* TODO: We pass a default flag, mem-access is irrelevant. */
    let lock = if magic_lock { "--lock" } else { "-M0" };

    let home;
    let mut homeargs = Vec::new();
    if let Ok(s) = std::env::var("HOME") {
        home = format!("allowlist/write+{}/***", s);
        homeargs.push("-m");
        homeargs.push(&home);
    }

    let mut default = Vec::new();
    for magic in DEFAULT.split('\n').filter(|&magic|
            !magic.is_empty() &&
            magic.chars().next().unwrap() != '#') {
        default.push("-m");
        default.push(magic);
    }

    let rcname = "/etc/pandora.syd-2";
    let rc = std::path::Path::new(rcname);
    let mut rcargs = Vec::new();
    if rc.exists() {
        rcargs.push("-c");
        rcargs.push(rcname);
    }

    let mut is_bash: bool = false;
    let mut bashrcargs = Vec::new();

    let mut bashrcname = "/usr/share/sydbox/sydbox.bashrc";
    let mut bashrc = std::path::Path::new(bashrcname);
    if bashrc.exists() {
        bashrcargs.push("--rcfile");
        bashrcargs.push(bashrcname);
        is_bash = true;
    }
    bashrcname = "/usr/local/share/sydbox/sydbox.bashrc";
    bashrc = std::path::Path::new(bashrcname);
    if bashrc.exists() {
        bashrcargs.push("--rcfile");
        bashrcargs.push(bashrcname);
        is_bash = true;
    }

    let shell: String;
    if !is_bash && env_shell {
        shell = match std::env::var("SHELL") {
            Ok(s) => s,
            Err(_) => "/bin/bash".to_string(),
        };
    } else {
        shell = "/bin/bash".to_string();
    }

    let mut child = Command::new("syd")
        .args(&default)
        .args(&homeargs)
        .args(&rcargs)
        .arg(lock)
        .arg("--chdir")
        .arg(tmpdir.path())
        .arg("--uid")
        .arg(format!("{}", nix::unistd::getuid()))
        .arg("--gid")
        .arg(format!("{}", nix::unistd::getgid()))
        .arg("--")
        .arg(shell)
        .args(&bashrcargs)
        .arg("-i")
        .args(&*args)
        .spawn()
        .unwrap_or_else(|e| {
            eprintln!("[0;1;31;91mFailed to spawn SydB☮x shell: {}[0m", e);
            eprintln!("[0;1;31;91mIs `syd' in your PATH?[0m");
            std::process::exit(1);
        });
    child.wait().expect("failed to wait for shell");
}

fn magic_stat(path: &str) -> bool
{
    match nix::sys::stat::lstat(path) {
        Ok(_fstat) => {
            println!("{}: [0;1;32;92mOK[0m", path);
            true
        },
        Err(_error) => {
            //eprintln!("{}: {}", path, error);
            println!("{}: [0;1;31;91mLOCKED[0m", path);
            false
        }
    }
}

fn sydbox_internal_net_2(cmd: &str, op: char, argv: &[&str]) -> bool
{
    match op {
        '+' | '-' => {},
        _ => { panic!("invalid operation character {}", op); }
    };

    let mut ok: bool = true;
    for i in 0..argv.len() {
        let addr = argv[i];
        let r = magic_stat(&format!("/dev/sydbox/{}{}{}", cmd, op, addr));
        if !r { ok = false; };
    }
    ok
}

fn sydbox_internal_path_2(cmd: &str, op: char, argv: &[&str]) -> bool
{
    match op {
        '+' | '-' => {},
        _ => { panic!("invalid operation character {}", op); }
    };

    let mut ok: bool = true;
    for i in 0..argv.len() {
        let path = argv[i];
        if path.chars().next().expect("expected absolute path, got empty path") != '/' {
            panic!("sydbox_internal_path_2 expects absolute path, got: {}", path);
        }
        let r = magic_stat(&format!("/dev/sydbox/{}{}{}", cmd, op, path));
        if !r { ok = false; };
    }
    ok
}

fn esandbox(cmd: &Vec<&str>) -> bool
{
    let command = cmd[0];
    match command {
        "check" =>
            magic_stat("/dev/sydbox"),
        "lock" =>
            magic_stat("/dev/sydbox/core/trace/magic_lock:on"),
        "exec_lock" =>
            magic_stat("/dev/sydbox/core/trace/magic_lock:exec"),
        "wait_all" =>
            magic_stat("/dev/sydbox/core/trace/exit_wait_all:true"),
        "wait_eldest" =>
            magic_stat("/dev/sydbox/core/trace/exit_wait_all:false"),
        "enabled"|"enabled_path" =>
            magic_stat("/dev/sydbox/core/sandbox/write?"),
        "enable"|"enable_path" =>
            magic_stat("/dev/sydbox/core/sandbox/write:deny"),
        "disable"|"disable_path" =>
            magic_stat("/dev/sydbox/core/sandbox/write:off"),
        "enabled_exec" =>
            magic_stat("/dev/sydbox/core/sandbox/exec?"),
        "enable_exec" =>
            magic_stat("/dev/sydbox/core/sandbox/exec:deny"),
        "disable_exec" =>
            magic_stat("/dev/sydbox/core/sandbox/exec:off"),
        "enabled_net" =>
            magic_stat("/dev/sydbox/core/sandbox/network?"),
        "enable_net" =>
            magic_stat("/dev/sydbox/core/sandbox/network:deny"),
        "disable_net" =>
            magic_stat("/dev/sydbox/core/sandbox/network:off"),
        "allow"|"allow_path" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("allowlist/write", '+', &cmd[1..])
            }
        },
        "disallow"|"disallow_path" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("allowlist/write", '-', &cmd[1..])
            }
        },
        "allow_exec" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("allowlist/exec", '+', &cmd[1..])
            }
        },
        "disallow_exec" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("allowlist/exec", '-', &cmd[1..])
            }
        },
        "allow_net" => {
            let mut c="allowlist/network/bin";
            let mut i=1;
            if cmd[1] == "--connect" {
                c="allowlist/network/connect";
                i=2;
            };
            sydbox_internal_net_2(c, '+', &cmd[i..])
        },
        "disallow_net" => {
            let mut c="allowlist/network/bin";
            let mut i=1;
            if cmd[1] == "--connect" {
                c="allowlist/network/connect";
                i=2;
            };
            sydbox_internal_net_2(c, '-', &cmd[i..])
        },
        "addfilter"|"addfilter_path" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("filter/write", '+', &cmd[1..])
            }
        },
        "rmfilter"|"rmfilter_path" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("filter/write", '-', &cmd[1..])
            }
        },
        "addfilter_exec" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("filter/exec", '+', &cmd[1..])
            }
        },
        "rmfilter_exec" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("filter/exec", '-', &cmd[1..])
            }
        },
        "addfilter_net" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("filter/network", '+', &cmd[1..])
            }
        },
        "rmfilter_net" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("filter/network", '-', &cmd[1..])
            }
        },
        "exec" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                /* TODO: syd-format exec -- cmd[1..] */
                eprintln!("[0;1;31;91mexec is not implemented yet![0m");
                true
            }
        },
        "kill" => {
            if cmd.len() <= 1 {
                eprintln!("[0;1;31;91m{} takes at least one extra argument[0m",
                          command);
                false
            } else {
                sydbox_internal_path_2("exec/kill_if_match", '+', &cmd[1..])
            }
        },
        _ => { panic!("Unknown command {}", command); },
    }
}

fn parse_json_line(
    serialized: &str,
    magic: &mut std::collections::HashSet<(Sandbox, String)>,
    path_limit: u8,
) -> (Option<String>, Option<String>, Option<SystemTime>) {
    match serde_json::from_str(&serialized)
        .unwrap_or_else(|e| panic!("failed to parse `{}': {}", serialized, e))
    {
        Dump::Init {
            id: 0,
            shoebox: 1,
            name,
            ..
        } => {
            eprintln!("success opening input to parse `{}' dump", name);
            return (Some(name), None, None);
        }
        Dump::StartUp { id: 1, cmd, ts, .. } => {
            return (None, Some(cmd), Some(UNIX_EPOCH + Duration::from_secs(ts)));
        }
        Dump::ThreadNew { id: 5, .. } => {}
        Dump::ThreadFree { id: 6, .. } => {}
        Dump::SysEnt {
            event: EventStruct { id: 8, .. },
            repr,
            name,
            ..
        } if name == "bind" => {
            magic.insert((crate::Sandbox::Bind, repr[1].clone()));
        }
        Dump::SysEnt {
            event: EventStruct { id: 8, .. },
            repr,
            name,
            ..
        } if name == "connect" => {
            magic.insert((crate::Sandbox::Connect, repr[1].clone()));
        }
        Dump::SysEnt {
            event: EventStruct { id: 8, .. },
            repr,
            name,
            ..
        } if name == "sendto" => {
            magic.insert((crate::Sandbox::Connect, repr[4].clone()));
        }
        Dump::SysEnt {
            event: EventStruct { id: 8, .. },
            repr,
            name,
            ..
        } if name == "execve" => {
            magic.insert((crate::Sandbox::Exec, repr[0].clone()));
        }
        Dump::SysEnt {
            event: EventStruct { id: 8, .. },
            args,
            repr,
            name,
            ..
        } => {
            let may_write: bool;
            let mut report_missing_handler = false;
            let mut repr_idx: [usize; 6] = [0; 6];
            if name.ends_with("at") {
                repr_idx[0] = 2;
            } else {
                repr_idx[0] = 1;
            }

            may_write = if name == "open" {
                open_may_write(args[1])
            } else if name == "openat" {
                open_may_write(args[2])
            } else if name == "access" {
                access_may_write(args[1])
            } else if name == "faccessat" {
                access_may_write(args[2])
            } else if name == "rename" {
                repr_idx[1] = 2;
                true
            } else if name == "symlink" {
                repr_idx[0] = 2;
                true
            } else if name == "mkdir" || name == "rmdir" || name == "unlink" {
                true
            } else {
                report_missing_handler = true;
                false
            };

            if report_missing_handler {
                eprintln!("SYS:{:?} {:?} {:?}", name, args, repr);
            }

            for idx in &repr_idx {
                if *idx == 0 || repr[*idx - 1].is_empty() {
                    continue;
                }
                let sandbox = if may_write {
                    Sandbox::Write
                } else {
                    Sandbox::Read
                };
                let argument = trim_path(&filter_proc(&repr[idx - 1]), path_limit);
                if !argument.is_empty() {
                    magic.insert((sandbox, argument));
                }
            }
        }
        _ => {}
    }

    (None, None, None)
}

fn open_input(path_or_stdin: &str) -> Box<dyn std::io::BufRead> {
    match path_or_stdin {
        "-" => Box::new(std::io::BufReader::new(std::io::stdin())),
        path => Box::new(std::io::BufReader::new(
            match OpenOptions::new().read(true).open(path) {
                Ok(file) => file,
                Err(error) => {
                    eprintln!("failed to open file `{}': {}", path, error);
                    std::process::exit(1);
                }
            },
        )),
    }
}

fn open_output(path_or_stdout: &str) -> Box<dyn std::io::Write> {
    match path_or_stdout {
        "-" => Box::new(std::io::BufWriter::new(std::io::stdout())),
        path => Box::new(std::io::BufWriter::new(
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(file) => file,
                Err(error) => {
                    eprintln!("failed to open file `{}': {}", path, error);
                    std::process::exit(1);
                }
            },
        )),
    }
}

fn trim_path(path: &str, limit: u8) -> String {
    if limit == 0 || path == "/" {
        path.to_string()
    } else {
        let members: Vec<&str> = path.split('/').collect();
        let limit = limit as usize;
        if limit > 0 && limit <= members.len() {
            members[0..limit].join("/")
        } else {
            members.join("/")
        }
    }
}

fn filter_proc(path: &str) -> String {
    if path.starts_with("/proc/") {
        if let Some(c) = path.chars().nth(7) {
            if c.is_numeric() {
                return "".to_string();
            }
        }
    }

    path.to_string()
}

fn access_may_write(mode: i64) -> bool {
    (mode as i32) & libc::W_OK != 0
}

fn open_may_write(flags: i64) -> bool {
    let flags: i32 = flags as i32;
    match flags & libc::O_ACCMODE {
        libc::O_WRONLY | libc::O_RDWR => true,
        libc::O_RDONLY => flags & libc::O_CREAT != 0,
        _ => false,
    }
}
