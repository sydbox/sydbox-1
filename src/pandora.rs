use std::io::BufRead;

use clap::{App, Arg, SubCommand};
use serde::{Deserialize, Serialize};

use pandora::built_info;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct SydStruct {
    flag_STARTUP: bool,
    flag_IGNORE_ONE_SIGSTOP: bool,
    flag_IN_SYSCALL: bool,
    flag_STOP_AT_SYSEXIT: bool,
    flag_IN_CLONE: bool,
    flag_IN_EXECVE: bool,
    flag_KILLED: bool,
    ref_CLONE_THREAD: u32,
    ref_CLONE_FS: u32,
    cwd: Option<String>,
    ppid: u32,
    tgid: u32,
    syscall_abi: u8,
    syscall_name: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct StatStruct {
    pid: Option<u32>,
    ppid: Option<u32>,
    tpgid: Option<u32>,
    pgrp: Option<u32>,
    errno: Option<u32>,
    errno_name: Option<String>,
    /*
    comm: Option<String>,
    state: Option<String>,
    session: Option<u32>,
    tty_nr: Option<u32>,
    nice: Option<u32>,
    num_threads: Option<u32>,
    */
}

#[derive(Serialize, Deserialize, Debug)]
struct ProcessStruct {
    pid: u32,
    syd: Option<SydStruct>,
    stat: Option<StatStruct>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SignalStruct {}

#[derive(Serialize, Deserialize, Debug)]
struct PinkStruct {
    name: String,
    retval: u32,
    errno: u32,
    sysname: Option<String>,
    arg_idx: Option<u32>,
    arg_val: Option<u32>,
    addr: Option<u64>,
    dest: Option<String>,
    len: Option<usize>,
    saddr: Option<String>,
    /*
    signal: Option<SignalStruct>,
    eventmsg: Option<u64>,
    sysnum: Option<u64>,
    */
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Dump {
    Init {
        id: u32,
        shoebox: u32,
    },
    Pink {
        id: u32,
        event: u16,
        time: u32,
        pink: PinkStruct,
    },
    Thread {
        event: u16,
        event_name: String,
        id: u32,
        pid: u32,
        time: u32,
        process: Option<ProcessStruct>,
    },
}

fn command_inspect(core: &str) -> i32 {
    let input = xopen(core);

    for line in input.lines() {
        let serialized = match line {
            Ok(line) if line.is_empty() => {
                return 0;
            },
            Ok(line) => line,
            Err(error) => {
                eprintln!("failed to read line from input: {}", error);
                return 1;
            },
        };
        let dump: Dump =
            serde_json::from_str(&serialized).expect(&format!("failed to parse `{}'", serialized));
    }

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
                    Arg::with_name("core")
                        .default_value("./sydcore")
                        .required(true)
                        .help("Path to sydbox core dump")
                        .long("core")
                        .short("c")
                        .env("SHOEBOX"),
                ),
        )
        .get_matches();

    if let Some(ref matches) = matches.subcommand_matches("inspect") {
        std::process::exit(command_inspect(matches.value_of("core").unwrap()));
    } else {
        clap::Error::with_description(
            "No subcommand given, expected one of: inspect",
            clap::ErrorKind::InvalidValue,
        )
        .exit();
    }
}

fn xopen(path_or_stdin: &str) -> Box<dyn std::io::BufRead> {
    match path_or_stdin {
        "-" => Box::new(std::io::BufReader::new(std::io::stdin())),
        path => Box::new(std::io::BufReader::new(match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) => {
                eprintln!("failed to open file `{}': {}", path, error);
                std::process::exit(1);
            }
        })),
    }
}
