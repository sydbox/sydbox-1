use std::ffi::CStr;
use std::ffi::OsStr;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::ptr;

use libc;
use libc::{c_ulong, c_void, gid_t, sigset_t, size_t};
use libc::{kill, signal};
use libc::{FD_CLOEXEC, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, MNT_DETACH};
use libc::{SIG_DFL, SIG_SETMASK};
use nix;
use nix::sched::CloneFlags;

use crate::error::ErrorCode as Err;
use crate::run::{ChildInfo, MAX_PID_LEN};

// And at this point we've reached a special time in the life of the
// child. The child must now be considered hamstrung and unable to
// do anything other than syscalls really.
//
// ESPECIALLY YOU CAN NOT DO MEMORY (DE)ALLOCATIONS
//
// See better explanation at:
// https://github.com/rust-lang/rust/blob/c1e865c/src/libstd/sys/unix/process.rs#L202
//

// In particular ChildInfo is passed by refernce here to avoid
// deallocating (parts of) it.
pub unsafe fn child_after_clone(child: &ChildInfo) -> ! {
    let mut epipe = child.error_pipe;

    if child.cfg.death_sig.is_some() {
        child.cfg.death_sig.as_ref().map(|&sig| {
            eprintln!(
                "[0;1;31;91msydb☮x: Setting parent-death signal to `{}'.[0m",
                sig
            );
            if libc::prctl(ffi::PR_SET_PDEATHSIG, sig as c_ulong, 0, 0, 0) != 0 {
                fail(Err::ParentDeathSignal, epipe);
            }
        });
    }

    // Now we must wait until parent set some environment for us. It's mostly
    // for uid_map/gid_map. But also used for attaching debugger and maybe
    // other things
    let mut wbuf = [0u8];
    loop {
        // TODO(tailhook) put some timeout on this pipe?
        let rc = libc::read(child.wakeup_pipe, (&mut wbuf).as_ptr() as *mut c_void, 1);
        if rc == 0 {
            // Parent already dead presumably before we had a chance to
            // set PDEATHSIG, so just send signal ourself in that case
            if let Some(sig) = child.cfg.death_sig {
                kill(libc::getpid(), sig as i32);
                libc::_exit(127);
            } else {
                // In case we wanted to daemonize, just continue
                //
                // TODO(tailhook) not sure it's best thing to do. Maybe parent
                // failed to setup uid/gid map for us. Do we want to check
                // specific options? Or should we just always die?
                break;
            }
        } else if rc < 0 {
            let errno = nix::errno::errno();
            if errno == libc::EINTR as i32 || errno == libc::EAGAIN as i32 {
                continue;
            } else {
                fail(Err::PipeError, errno);
            }
        } else {
            // Do we need to check that exactly one byte is received?
            break;
        }
    }

    // Move error pipe file descriptors in case they clobber stdio
    while epipe < 3 {
        let nerr = libc::fcntl(epipe, F_DUPFD_CLOEXEC, 3);
        if nerr < 0 {
            fail(Err::CreatePipe, epipe);
        }
        epipe = nerr;
    }

    for &(nstype, fd) in child.setns_namespaces {
        match nstype {
            CloneFlags::CLONE_NEWPID => {
                eprintln!("[0;1;31;91msydb☮x: Unsharing pid namespace.[0m");
            }
            CloneFlags::CLONE_NEWNET => {
                eprintln!("[0;1;31;91msydb☮x: Unsharing net namespace.[0m");
            }
            CloneFlags::CLONE_NEWNS => {
                eprintln!("[0;1;31;91msydb☮x: Unsharing mount namespace.[0m");
            }
            CloneFlags::CLONE_NEWUTS => {
                eprintln!("[0;1;31;91msydb☮x: Unsharing uts namespace.[0m");
            }
            CloneFlags::CLONE_NEWIPC => {
                eprintln!("[0;1;31;91msydb☮x: Unsharing ipc namespace.[0m");
            }
            CloneFlags::CLONE_NEWUSER => {
                eprintln!("[0;1;31;91msydb☮x: Unsharing user namespace.[0m");
            }
            _ => {
                eprintln!(
                    "[0;1;31;91msydb☮x: Setting unknown clone flag `{:?}'.[0m",
                    nstype
                );
            }
        };
        if libc::setns(fd, nstype.bits()) != 0 {
            fail(Err::SetNs, epipe);
        }
    }

    if !child.pid_env_vars.is_empty() {
        let mut buf = [0u8; MAX_PID_LEN + 1];
        let data = format_pid_fixed(&mut buf, libc::getpid());
        for &(index, offset) in child.pid_env_vars {
            let slice = CStr::from_ptr(child.environ[index]);
            let osstr = OsStr::from_bytes(slice.to_bytes());
            match osstr.to_str() {
                Some(environ) => {
                    eprintln!(
                        "[0;1;31;91msydb☮x: Add environment variable `{}' with pid.[0m",
                        environ
                    );
                }
                None => {}
            };

            // we know that there are at least MAX_PID_LEN+1 bytes in buffer
            child.environ[index]
                .offset(offset as isize)
                .copy_from(data.as_ptr() as *const libc::c_char, data.len());
        }
    }

    if child.pivot.is_some() {
        child.pivot.as_ref().map(|piv| {
            let mut osstr = OsStr::from_bytes(piv.new_root.to_bytes());
            match osstr.to_str() {
                Some(new_root) => {
                    osstr = OsStr::from_bytes(piv.put_old.to_bytes());
                    match osstr.to_str() {
                        Some(put_old) => {
                            eprintln!("[0;1;31;91msydb☮x: Moving the root of the file system to the directory `{}' and making `{}' the new root file system.[0m", put_old, new_root);
                        },
                        None => {},
                    };
                },
                None => {}
            };

            if ffi::pivot_root(piv.new_root.as_ptr(), piv.put_old.as_ptr()) != 0 {
                fail(Err::ChangeRoot, epipe);
            }

            osstr = OsStr::from_bytes(piv.workdir.to_bytes());
            match osstr.to_str() {
                Some(workdir) => {
                    eprintln!("[0;1;31;91msydb☮x: Changing working directory to `{}'.[0m",
                        workdir);
                },
                None => {},
            };

            if libc::chdir(piv.workdir.as_ptr()) != 0 {
                fail(Err::ChangeRoot, epipe);
            }
            if piv.unmount_old_root {
                if libc::umount2(piv.old_inside.as_ptr(), MNT_DETACH) != 0 {
                    fail(Err::ChangeRoot, epipe);
                }
            }
        });
    }

    if child.chroot.is_some() {
        child.chroot.as_ref().map(|chroot| {
            let slice = unsafe { CStr::from_ptr(chroot.root.as_ptr()) };
            let osstr = OsStr::from_bytes(slice.to_bytes());
            match osstr.to_str() {
                Some(root) => {
                    eprintln!(
                        "[0;1;31;91msydb☮x: Changing root directory to `{}'.[0m",
                        root
                    );
                }
                None => {}
            };
            if libc::chroot(chroot.root.as_ptr()) != 0 {
                fail(Err::ChangeRoot, epipe);
            }
        });
    }
    if child.chroot.is_some() {
        child.chroot.as_ref().map(|chroot| {
            let slice = unsafe { CStr::from_ptr(chroot.workdir.as_ptr()) };
            let osstr = OsStr::from_bytes(slice.to_bytes());
            match osstr.to_str() {
                Some(workdir) => {
                    eprintln!(
                        "[0;1;31;91msydb☮x: Changing working directory to `{}'.[0m",
                        workdir
                    );
                }
                None => {}
            }
            if libc::chdir(chroot.workdir.as_ptr()) != 0 {
                fail(Err::ChangeRoot, epipe);
            }
        });
    }

    if child.keep_caps.is_some() {
        child.keep_caps.as_ref().map(|_| {
            eprintln!("[0;1;31;91msydb☮x: Setting the \"keep capabilities\" flag.[0m");
            // Don't use securebits because on older systems it doesn't work
            if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
                fail(Err::CapSet, epipe);
            }
        });
    }

    if child.cfg.gid.is_some() {
        child.cfg.gid.as_ref().map(|&gid| {
            let egid = libc::getegid();
            if gid != egid {
                eprintln!(
                    "[0;1;31;91msydb☮x: Changing gid from `{}' to `{}'.[0m",
                    egid, gid
                );
                if libc::setgid(gid) != 0 {
                    fail(Err::SetUser, epipe);
                }
            }
        });
    }

    if child.cfg.supplementary_gids.is_some() {
        child.cfg.supplementary_gids.as_ref().map(|groups| {
            let my_gid = libc::getgid();
            let gids: Vec<gid_t> = groups
                .iter()
                .filter(|x| **x != 0 && **x != my_gid)
                .map(|x| *x)
                .collect();
            if gids.len() > 0 {
                let gstr: Vec<String> = gids.iter().map(|x| x.to_string()).collect();
                eprintln!(
                    "[0;1;31;91msydb☮x: Adding supplementary gids `{}'.[0m",
                    gstr.join(",")
                );
                if libc::setgroups(groups.len() as size_t, gids.as_ptr()) != 0 {
                    fail(Err::SetUser, epipe);
                }
            }
        });
    }

    if child.cfg.uid.is_some() {
        child.cfg.uid.as_ref().map(|&uid| {
            let euid = libc::geteuid();
            if uid != euid {
                eprintln!(
                    "[0;1;31;91msydb☮x: Changing uid from `{}' to `{}'.[0m",
                    euid, uid
                );
                if libc::setuid(uid) != 0 {
                    fail(Err::SetUser, epipe);
                }
            }
        });
    }

    child.keep_caps.as_ref().map(|caps| {
        let header = ffi::CapsHeader {
            version: ffi::CAPS_V3,
            pid: 0,
        };
        let data = ffi::CapsData {
            effective_s0: caps[0],
            permitted_s0: caps[0],
            inheritable_s0: caps[0],
            effective_s1: caps[1],
            permitted_s1: caps[1],
            inheritable_s1: caps[1],
        };
        if libc::syscall(libc::SYS_capset, &header, &data) != 0 {
            fail(Err::CapSet, epipe);
        }
        for idx in 0..caps.len() * 32 {
            if caps[(idx >> 5) as usize] & (1 << (idx & 31)) != 0 {
                let rc = libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_RAISE, idx, 0, 0);
                if rc != 0 && nix::errno::errno() == libc::ENOTSUP {
                    // no need to iterate if ambient caps are notsupported
                    break;
                }
            }
        }
    });

    if child.cfg.work_dir.is_some() {
        let osstr = OsStr::from_bytes(child.cfg.work_dir.as_ref().unwrap().to_bytes());
        match osstr.to_str() {
            Some(workdir) => {
                eprintln!(
                    "[0;1;31;91msydb☮x: Changing working directory to `{}'.[0m",
                    workdir
                );
            }
            None => {}
        };
        child.cfg.work_dir.as_ref().map(|dir| {
            if libc::chdir(dir.as_ptr()) != 0 {
                fail(Err::Chdir, epipe);
            }
        });
    }

    for &(dest_fd, src_fd) in child.fds {
        if src_fd == dest_fd {
            let flags = libc::fcntl(src_fd, F_GETFD);
            if flags < 0 || libc::fcntl(src_fd, F_SETFD, flags & !FD_CLOEXEC) < 0 {
                fail(Err::StdioError, epipe);
            }
        } else {
            if libc::dup2(src_fd, dest_fd) < 0 {
                fail(Err::StdioError, epipe);
            }
        }
    }

    for &(start, end) in child.close_fds {
        if start < end {
            for fd in start..end {
                if child.fds.iter().find(|&&(cfd, _)| cfd == fd).is_none() {
                    // Close may fail with ebadf, and it's okay
                    libc::close(fd);
                }
            }
        }
    }

    if child.cfg.restore_sigmask {
        let mut sigmask: sigset_t = mem::zeroed();
        libc::sigemptyset(&mut sigmask);
        libc::pthread_sigmask(SIG_SETMASK, &sigmask, ptr::null_mut());
        for sig in 1..32 {
            signal(sig, SIG_DFL);
        }
    }

    if let Some(callback) = child.pre_exec {
        if let Err(e) = callback() {
            fail_errno(Err::PreExec, e.raw_os_error().unwrap_or(10873289), epipe);
        }
    }

    libc::execve(
        child.filename,
        child.args.as_ptr(),
        // cancelling mutability, it should be fine
        child.environ.as_ptr() as *const *const libc::c_char,
    );
    fail(Err::Exec, epipe);
}

unsafe fn fail(code: Err, output: RawFd) -> ! {
    fail_errno(code, nix::errno::errno(), output)
}
unsafe fn fail_errno(code: Err, errno: i32, output: RawFd) -> ! {
    let bytes = [
        code as u8,
        (errno >> 24) as u8,
        (errno >> 16) as u8,
        (errno >> 8) as u8,
        (errno >> 0) as u8,
        // TODO(tailhook) rustc adds a special sentinel at the end of error
        // code. Do we really need it? Assuming our pipes are always cloexec'd.
    ];
    // Writes less than PIPE_BUF should be atomic. It's also unclear what
    // to do if error happened anyway
    libc::write(output, bytes.as_ptr() as *const c_void, 5);
    libc::_exit(127);
}

fn format_pid_fixed<'a>(buf: &'a mut [u8], pid: libc::pid_t) -> &'a [u8] {
    buf[buf.len() - 1] = 0;
    if pid == 0 {
        buf[buf.len() - 2] = b'0';
        return &buf[buf.len() - 2..];
    } else {
        let mut tmp = pid;
        // can't use stdlib function because that can allocate
        for n in (0..buf.len() - 1).rev() {
            buf[n] = (tmp % 10) as u8 + b'0';
            tmp /= 10;
            if tmp == 0 {
                return &buf[n..];
            }
        }
        unreachable!("can't format pid");
    };
}
/// We don't use functions from nix here because they may allocate memory
/// which we can't to this this module.
mod ffi {
    use libc::{c_char, c_int};

    pub const PR_SET_PDEATHSIG: c_int = 1;
    pub const CAPS_V3: u32 = 0x20080522;

    #[repr(C)]
    pub struct CapsHeader {
        pub version: u32,
        pub pid: i32,
    }

    #[repr(C)]
    pub struct CapsData {
        pub effective_s0: u32,
        pub permitted_s0: u32,
        pub inheritable_s0: u32,
        pub effective_s1: u32,
        pub permitted_s1: u32,
        pub inheritable_s1: u32,
    }

    extern "C" {
        pub fn pivot_root(new_root: *const c_char, put_old: *const c_char) -> c_int;
    }
}

#[cfg(test)]
mod test {
    use super::format_pid_fixed;
    use crate::run::MAX_PID_LEN;
    use rand::{thread_rng, Rng};
    use std::ffi::CStr;

    fn fmt_normal(val: i32) -> String {
        let mut buf = [0u8; MAX_PID_LEN + 1];
        let slice = format_pid_fixed(&mut buf, val);
        return CStr::from_bytes_with_nul(slice)
            .unwrap()
            .to_string_lossy()
            .to_string();
    }
    #[test]
    fn test_format() {
        assert_eq!(fmt_normal(0), "0");
        assert_eq!(fmt_normal(1), "1");
        assert_eq!(fmt_normal(7), "7");
        assert_eq!(fmt_normal(79), "79");
        assert_eq!(fmt_normal(254), "254");
        assert_eq!(fmt_normal(1158), "1158");
        assert_eq!(fmt_normal(77839), "77839");
    }
    #[test]
    fn test_random() {
        for _ in 0..100000 {
            let x = thread_rng().gen();
            if x < 0 {
                continue;
            }
            assert_eq!(fmt_normal(x), format!("{}", x));
        }
    }
}
