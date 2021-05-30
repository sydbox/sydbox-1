use std::ffi::CString;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::iter::FromIterator;
use std::os::unix::io::FromRawFd;
use std::process::Command;

use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::{App, Arg, SubCommand};
use serde::{Deserialize, Serialize};

use pandora::built_info;

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
            Self::Bind => write!(f, "whitelist/network/bind"),
            Self::Connect => write!(f, "whitelist/network/connect"),
            Self::Write => write!(f, "whitelist/write"),
            Self::Exec => write!(f, "whitelist/exec"),
            Self::Read => write!(f, "#? whitelist/read"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
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
        event: u16,
        /*
        event_name: String,
        pid: u32,
        ppid: u32,
        tgid: u32,
        */
        sysname: String,
        args: [u64; 6],
        repr: [String; 6],
    },
}

fn command_box<'a>(
    bin: &'a str,
    cmd: &mut Vec<&'a str>,
    config: &Option<Vec<&'a str>>,
    magic: &Option<Vec<&'a str>>,
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

fn command_profile<'b>(
    bin: &'b str,
    cmd: &[&'b str],
    output_path: &'b str,
    path_limit: u8,
) -> i32 {
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
        .arg("core/restrict/file_control:0")
        .arg("-m")
        .arg("core/restrict/shared_memory_writable:0")
        .arg("-d")
        .arg(format!("{}", fd_rw))
        .arg("--")
        .args(cmd)
        .spawn()
        .expect("sydbox command failed to start");

    nix::unistd::close(fd_rw).expect("failed to close write end of pipe");
    let input = Box::new(std::io::BufReader::new(unsafe {
        std::fs::File::from_raw_fd(fd_rd)
    }));
    let r = do_inspect(input, output_path, path_limit);

    child.wait().expect("failed to wait for sydbox");

    r
}

fn command_inspect(input_path: &str, output_path: &str, path_limit: u8) -> i32 {
    let input = open_input(input_path);
    do_inspect(input, output_path, path_limit)
}

fn main() {
    let matches = App::new(built_info::PKG_NAME)
        .version(built_info::PKG_VERSION)
        .author(built_info::PKG_AUTHORS)
        .about(built_info::PKG_DESCRIPTION)
        .after_help(&*format!(
            "\
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
                .about("Execute the given command under sydbox")
                .arg(
                    Arg::with_name("bin")
                        .default_value("sydbox")
                        .required(true)
                        .help("Path to sydbox binary")
                        .long("bin")
                        .short("b")
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
                .arg(Arg::with_name("cmd").required(true).multiple(true)),
        )
        .subcommand(
            SubCommand::with_name("profile")
                .about("Execute a program under inspection and write a sydbox profile")
                .arg(
                    Arg::with_name("bin")
                        .default_value("sydbox")
                        .required(true)
                        .help("Path to sydbox binary")
                        .long("bin")
                        .short("b")
                        .env("SYDBOX_BIN"),
                )
                .arg(
                    Arg::with_name("output")
                        .default_value("./out.syd-1")
                        .required(true)
                        .help("Path to sydbox profile output")
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
                .about("Read a sydbox core dump and write a sydbox profile")
                .arg(
                    Arg::with_name("input")
                        .default_value("./sydcore")
                        .required(true)
                        .help("Path to sydbox core dump")
                        .long("input")
                        .short("i")
                        .env("SHOEBOX"),
                )
                .arg(
                    Arg::with_name("output")
                        .default_value("./out.syd-1")
                        .required(true)
                        .help("Path to sydbox profile output")
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
        .get_matches();

    if let Some(ref matches) = matches.subcommand_matches("box") {
        let bin = matches.value_of("bin").unwrap();
        let mut cmd: Vec<&str> = matches.values_of("cmd").unwrap().collect();
        let config: Option<Vec<&str>> = matches.values_of("config").map(|values| values.collect());
        let magic: Option<Vec<&str>> = matches.values_of("magic").map(|values| values.collect());
        std::process::exit(command_box(bin, &mut cmd, &config, &magic));
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
        clap::Error::with_description(
            "No subcommand given, expected one of: box, inspect, profile",
            clap::ErrorKind::InvalidValue,
        )
        .exit();
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
core/restrict/file_control:false
core/restrict/shared_memory_writable:false

core/whitelist/per_process_directories:true
core/whitelist/successful_bind:true
core/whitelist/unsupported_socket_families:true

core/violation/decision:deny
core/violation/exit_code:-1
core/violation/raise_fail:false
core/violation/raise_safe:false

core/trace/follow_fork:true
core/trace/use_seccomp:true
core/trace/use_seize:true
core/trace/use_toolong_hack:true

core/match/case_sensitive:true
core/match/no_wildcard:prefix

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

fn parse_json_line(
    serialized: &str,
    magic: &mut std::collections::HashSet<(Sandbox, String)>,
    path_limit: u8,
) -> (Option<String>, Option<String>, Option<SystemTime>) {
    match serde_json::from_str(&serialized)
        .unwrap_or_else(|_| panic!("failed to parse `{}'", serialized))
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
        Dump::SysEnt {
            event: 10,
            repr,
            sysname,
            ..
        } if sysname == "bind" => {
            magic.insert((crate::Sandbox::Bind, repr[1].clone()));
        }
        Dump::SysEnt {
            event: 10,
            repr,
            sysname,
            ..
        } if sysname == "connect" => {
            magic.insert((crate::Sandbox::Connect, repr[1].clone()));
        }
        Dump::SysEnt {
            event: 10,
            repr,
            sysname,
            ..
        } if sysname == "sendto" => {
            magic.insert((crate::Sandbox::Connect, repr[4].clone()));
        }
        Dump::SysEnt {
            event: 10,
            repr,
            sysname,
            ..
        } if sysname == "execve" => {
            magic.insert((crate::Sandbox::Exec, repr[0].clone()));
        }
        Dump::SysEnt {
            event: 10,
            args,
            repr,
            sysname,
            ..
        } => {
            let may_write: bool;
            let mut report_missing_handler = false;
            let mut repr_idx: [usize; 6] = [0; 6];
            if sysname.ends_with("at") {
                repr_idx[0] = 2;
            } else {
                repr_idx[0] = 1;
            }

            may_write = if sysname == "open" {
                open_may_write(args[1])
            } else if sysname == "openat" {
                open_may_write(args[2])
            } else if sysname == "access" {
                access_may_write(args[1])
            } else if sysname == "faccessat" {
                access_may_write(args[2])
            } else if sysname == "rename" {
                repr_idx[1] = 2;
                true
            } else if sysname == "symlink" {
                repr_idx[0] = 2;
                true
            } else if sysname == "mkdir" || sysname == "rmdir" || sysname == "unlink" {
                true
            } else {
                report_missing_handler = true;
                false
            };

            if report_missing_handler {
                eprintln!("SYS:{:?} {:?} {:?}", sysname, args, repr);
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

fn access_may_write(mode: u64) -> bool {
    (mode as i32) & libc::W_OK != 0
}

fn open_may_write(flags: u64) -> bool {
    let flags: i32 = flags as i32;
    match flags & libc::O_ACCMODE {
        libc::O_WRONLY | libc::O_RDWR => true,
        libc::O_RDONLY => flags & libc::O_CREAT != 0,
        _ => false,
    }
}
