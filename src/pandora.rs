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
    arg_idx: Option<usize>,
    arg_val: Option<u64>,
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
        pid: u32,
        pink: PinkStruct,
        /*
         * event: u16,
         * time: u32,
         */
    },
    Thread {
        id: u32,
        event: u16,
        pid: u32,
        process: Option<ProcessStruct>,
        /* event_name: String,
        time: u32,
        */
    },
}

#[derive(Clone, Debug)]
struct SyscallStruct {
    name: String,
    arg_int: [Option<u64>; 6],
    arg_str: [String; 6],
    /* arg_sock: [SocketAddress; 6], */
}

fn command_inspect(core: &str) -> i32 {
    let input = xopen(core);

    for line in input.lines() {
        let serialized = match line {
            Ok(line) if line.is_empty() => {
                return 0;
            }
            Ok(line) => line,
            Err(error) => {
                eprintln!("failed to read line from input: {}", error);
                return 1;
            }
        };

        let mut call_graph = std::collections::HashMap::<u32, SyscallStruct>::new();
        match serde_json::from_str(&serialized).expect(&format!("failed to parse `{}'", serialized))
        {
            Dump::Init { id: 0, shoebox: 1 } => {
                eprintln!("success opening core file `{}' for parsing", core);
            }
            Dump::Thread { event: 7, .. } => { /* thread_new */ }
            Dump::Thread { event: 8, .. } => { /* thread_free */ }
            Dump::Thread { event: 9, .. } => { /* startup */ }
            Dump::Pink { pid, pink, .. } if !pink.sysname.is_none() && pink.name == "read_syscall" => {
                insert_syscall(&mut call_graph, pid, pink.sysname);
            }
            Dump::Pink { pid, pink, .. }
                if !pink.arg_idx.is_none() && pink.name == "read_argument" =>
            {
                let mut sys = match call_graph.get_mut(&pid) {
                    Some(sys) => sys,
                    None => insert_syscall(&mut call_graph, pid, None)
                };
                sys.arg_int[pink.arg_idx.unwrap()] = pink.arg_val;
            }
            Dump::Pink { pid, pink, .. }
                if !pink.addr.is_none()
                    && !pink.dest.is_none()
                    && pink.name == "read_vm_data_nul" =>
            {
                let mut sys = match call_graph.get_mut(&pid) {
                    Some(sys) => sys,
                    None => insert_syscall(&mut call_graph, pid, None)
                };
                let addr = pink.addr.unwrap();
                for idx in 0..6 {
                    if sys.arg_int[idx].is_none() {
                        continue;
                    } else if sys.arg_int[idx].unwrap() == addr {
                        sys.arg_str[idx] = pink.dest.unwrap();
                        break;
                    }
                }
            }
            Dump::Pink { pink, .. } if pink.name == "read_socket_argument" => {}
            _ => {}
        }
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

fn insert_syscall(map: &mut std::collections::HashMap::<u32, SyscallStruct>,
               pid: u32,
               name: Option<String>) -> &mut SyscallStruct {
    let new = SyscallStruct {
        name: if name.is_none() { "".to_string() } else { name.unwrap() },
        arg_int: [None; 6],
        arg_str: [
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
            "".to_string(),
        ],
    };
    map.insert(pid, new);
    map.get_mut(&pid).unwrap()
}
