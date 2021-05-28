use clap::{App, Arg};
use serde::{Deserialize, Serialize};

use pandora::built_info;

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct Syd {
    flag_STARTUP: bool,
    flag_IGNORE_ONE_SIGSTOP: bool,
    flag_IN_SYSCALL: bool,
    flag_STOP_AT_SYSEXIT: bool,
    flag_IN_CLONE: bool,
    flag_IN_EXECVE: bool,
    flag_KILLED: bool,
    ref_CLONE_THREAD: u32,
    ref_CLONE_FS: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Stat {
    pid: u32,
    /* TODO: Rest of the elements currently unused. */
}

#[derive(Serialize, Deserialize, Debug)]
struct Process {
    pid: u32,
    stat: Option<Stat>,
    syd: Option<Syd>,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Dump {
    Init { id: u32, shoebox: u32 },
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
        .arg(
            Arg::with_name("core")
                .default_value("./sydcore")
                .required(true)
                .help("Path to sydbox core dump")
                .long("core")
                .short("c")
                .env("SHOEBOX"),
        )
        .get_matches();
}
