use std::fs::OpenOptions;
use std::io::BufRead;
use std::iter::FromIterator;

use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{Duration, UNIX_EPOCH};

use clap::{App, Arg, SubCommand};
use serde::{Deserialize, Serialize};

use pandora::built_info;

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

fn command_inspect(input_path: &str, output_path: &str) -> i32 {
    let input = open_input(input_path);
    let mut output = open_output(output_path);
    let mut magic = std::collections::HashSet::<String>::new();
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

        match serde_json::from_str(&serialized).expect(&format!("failed to parse `{}'", serialized))
        {
            Dump::Init {
                id: 0,
                shoebox: 1,
                name,
                ..
            } => {
                eprintln!(
                    "success opening input `{}' for parsing `{}' dump to write profile `{}'",
                    input_path, name, output_path
                );
                program_invocation_name = String::from(name);
            }
            Dump::StartUp { id: 1, cmd, ts, .. } => {
                program_command_line = String::from(cmd);
                program_startup_time += Duration::from_secs(ts);
            }
            Dump::SysEnt {
                event: 10,
                repr,
                sysname,
                ..
            } if sysname == "connect" => {
                magic.insert(format!("whitelist/network/connect+{}", repr[1]));
            }
            Dump::SysEnt {
                event: 10,
                repr,
                sysname,
                ..
            } if sysname == "execve" => {
                magic.insert(format!("whitelist/exec+{}", repr[0]));
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

                for idx in 0..6 {
                    let idx = repr_idx[idx];
                    if idx == 0 || repr[idx - 1].is_empty() {
                        continue;
                    }
                    let mut entry = format!(
                        "whitelist/{}+{}",
                        if may_write { "write" } else { "read" },
                        repr[idx - 1]
                    );
                    if !may_write {
                        entry = format!("#? {}", entry);
                    }
                    magic.insert(entry);
                }
            }
            _ => {}
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
    .expect(&format!(
        "failed to print header to output `{}'",
        output_path
    ));

    /* Step 2: Print out magic entries */
    let mut list = Vec::from_iter(magic);
    list.sort(); /* secondary alphabetical sort. */
    list.sort_by_cached_key(|entry| magic_key(entry));
    for entry in list {
        writeln!(&mut output, "{}", entry).expect(&format!(
            "failed to print entry `{}' to output `{}'",
            entry, output_path
        ));
    }

    writeln!(
        &mut output,
        "\n# Lock configuration\ncore/trace/magic_lock:on"
    )
    .expect(&format!(
        "failed to lock configuration for output `{}'",
        output_path
    ));

    0
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
            built_info::PKG_REPOSITORY
        ))
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
                ),
        )
        .get_matches();

    if let Some(ref matches) = matches.subcommand_matches("inspect") {
        std::process::exit(command_inspect(
            matches.value_of("input").unwrap(),
            matches.value_of("output").unwrap(),
        ));
    } else {
        clap::Error::with_description(
            "No subcommand given, expected one of: inspect",
            clap::ErrorKind::InvalidValue,
        )
        .exit();
    }
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

fn magic_key(magic: &str) -> u32 {
    if magic.contains("whitelist/read") {
        100
    } else if magic.contains("whitelist/exec") {
        95
    } else if magic.contains("whitelist/write") {
        5
    } else if magic.contains("whitelist/network") {
        0
    } else {
        100
    }
}
