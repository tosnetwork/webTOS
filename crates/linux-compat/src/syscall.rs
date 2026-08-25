//! Linux x86-64 syscall dispatch and implementations.
//!
//! Register convention: number in RAX, arguments in RDI, RSI, RDX, R10, R8,
//! R9, result in RAX (negative errno on failure). After a syscall the CPU
//! resumes at NEXT_PC via an external-address exception.

use icicle_cpu::{mem::perm, Cpu, Exception, ExceptionCode, ValueSource, VmExit};

use crate::{
    abi::{self, neg},
    align_up,
    fd::{Backing, Description, FdEntry, StdStream},
    vfs::{Dev, NodeKind},
    LinuxEnv, SigAction,
};

const PAGE_SIZE: u64 = 0x1000;
const PATH_MAX: usize = 4096;
const PID: u64 = 1000;

type SysResult = Result<u64, u64>;

// ── Guest memory access ─────────────────────────────────────────────────────

fn read_mem(cpu: &mut Cpu, addr: u64, len: usize) -> Result<Vec<u8>, u64> {
    let mut buf = vec![0_u8; len];
    cpu.mem
        .read_bytes(addr, &mut buf, perm::NONE)
        .map_err(|_| abi::EFAULT)?;
    Ok(buf)
}

fn write_mem(cpu: &mut Cpu, addr: u64, bytes: &[u8]) -> Result<(), u64> {
    cpu.mem
        .write_bytes(addr, bytes, perm::NONE)
        .map_err(|_| abi::EFAULT)
}

fn read_cstr(cpu: &mut Cpu, addr: u64) -> Result<Vec<u8>, u64> {
    let mut out = Vec::new();
    let mut chunk = [0_u8; 64];
    let mut cursor = addr;
    while out.len() < PATH_MAX {
        // Never read past the current page: the string may end just before
        // an unmapped page and a fixed-size chunk read would fault.
        let to_page_end = (PAGE_SIZE - (cursor & (PAGE_SIZE - 1))) as usize;
        let take = 64.min(PATH_MAX - out.len()).min(to_page_end);
        cpu.mem
            .read_bytes(cursor, &mut chunk[..take], perm::NONE)
            .map_err(|_| abi::EFAULT)?;
        if let Some(nul) = chunk[..take].iter().position(|&b| b == 0) {
            out.extend_from_slice(&chunk[..nul]);
            return Ok(out);
        }
        out.extend_from_slice(&chunk[..take]);
        cursor += take as u64;
    }
    Err(abi::EINVAL)
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub fn handle(env: &mut LinuxEnv, cpu: &mut Cpu) -> Option<VmExit> {
    let nr: u64 = cpu.read_var(env.regs.rax);
    let a0: u64 = cpu.read_var(env.regs.rdi);
    let a1: u64 = cpu.read_var(env.regs.rsi);
    let a2: u64 = cpu.read_var(env.regs.rdx);
    let a3: u64 = cpu.read_var(env.regs.r10);
    let a4: u64 = cpu.read_var(env.regs.r8);
    let a5: u64 = cpu.read_var(env.regs.r9);

    match dispatch(env, cpu, nr, [a0, a1, a2, a3, a4, a5]) {
        Outcome::Ret(result) => {
            let value = match result {
                Ok(v) => v,
                Err(errno) => neg(errno),
            };
            tracing::trace!(
                "[{}:{}] syscall {nr}({a0:#x}, {a1:#x}, {a2:#x}) = {value:#x}",
                env.proc.pid,
                cpu.icount()
            );
            cpu.write_var(env.regs.rax, value);
            // Resume at the instruction after `syscall`.
            let next_pc: u64 = cpu.read_var(cpu.arch.reg_next_pc);
            cpu.exception = Exception::new(ExceptionCode::ExternalAddr, next_pc);
            None
        }
        // The CPU already holds the full state of whichever task runs next
        // (including its pending exception); do not touch RAX.
        Outcome::Switched => {
            tracing::trace!("[{}] resumed after syscall {nr} switch", env.proc.pid);
            None
        }
        Outcome::Exit(exit) => Some(exit),
    }
}

/// Result of dispatching one syscall.
pub(crate) enum Outcome {
    /// Write the value (or negative errno) to RAX and resume after the
    /// syscall instruction.
    Ret(SysResult),
    /// The current task was parked (or replaced); the CPU holds another
    /// task's state.
    Switched,
    /// Stop the whole machine.
    Exit(VmExit),
}

impl From<SysResult> for Outcome {
    fn from(result: SysResult) -> Self {
        Outcome::Ret(result)
    }
}

fn dispatch(env: &mut LinuxEnv, cpu: &mut Cpu, nr: u64, a: [u64; 6]) -> Outcome {
    match nr {
        abi::SYS_EXIT => task_exit(env, cpu, encode_exit_status(a[0]), false),
        abi::SYS_EXIT_GROUP => task_exit(env, cpu, encode_exit_status(a[0]), true),
        abi::SYS_READ => outcome_read(env, cpu, a[0], a[1], a[2]),
        abi::SYS_WRITE => outcome_write(env, cpu, a[0], a[1], a[2]),
        abi::SYS_READV => outcome_vectored(env, cpu, a[0], a[1], a[2], false),
        abi::SYS_WRITEV => outcome_vectored(env, cpu, a[0], a[1], a[2], true),
        abi::SYS_FORK | abi::SYS_VFORK => sys_clone_impl(env, cpu, CloneSpec::fork()),
        abi::SYS_CLONE => sys_clone_impl(env, cpu, CloneSpec::from_clone_args(a)),
        abi::SYS_EXECVE => sys_execve(env, cpu, a[0], a[1], a[2]),
        abi::SYS_WAIT4 => sys_wait4(env, cpu, a[0], a[1], a[2]),
        abi::SYS_PIPE => sys_pipe(env, cpu, a[0], 0).into(),
        abi::SYS_PIPE2 => sys_pipe(env, cpu, a[0], a[1]).into(),
        abi::SYS_FUTEX => sys_futex(env, cpu, a[0], a[1], a[2], a[5]),
        abi::SYS_SCHED_YIELD => sys_yield(env, cpu),
        abi::SYS_KILL => sys_kill(env, cpu, a[0], a[1]),
        abi::SYS_TGKILL => sys_kill(env, cpu, a[1], a[2]),
        abi::SYS_POLL => outcome_poll(env, cpu, a[0], a[1], a[2], false),
        abi::SYS_PPOLL => outcome_poll(env, cpu, a[0], a[1], a[2], true),
        abi::SYS_SENDTO => sys_sendto(env, cpu, a),
        abi::SYS_RECVFROM => sys_recvfrom(env, cpu, a),
        abi::SYS_EPOLL_WAIT | abi::SYS_EPOLL_PWAIT => sys_epoll_wait(env, cpu, a),
        abi::SYS_SELECT => sys_select(env, cpu, a, false),
        abi::SYS_PSELECT6 => sys_select(env, cpu, a, true),
        abi::SYS_SENDFILE => sys_sendfile(env, cpu, a),
        _ => dispatch_simple(env, cpu, nr, a).into(),
    }
}

fn dispatch_simple(env: &mut LinuxEnv, cpu: &mut Cpu, nr: u64, a: [u64; 6]) -> SysResult {
    match nr {
        abi::SYS_PREAD64 => sys_pread(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_PWRITE64 => sys_pwrite(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_OPEN => sys_openat(env, cpu, abi::AT_FDCWD, a[0], a[1], a[2]),
        abi::SYS_CREAT => sys_openat(
            env,
            cpu,
            abi::AT_FDCWD,
            a[0],
            abi::O_WRONLY | abi::O_CREAT | abi::O_TRUNC,
            a[1],
        ),
        abi::SYS_OPENAT => sys_openat(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_CLOSE => env.proc.fds.borrow_mut().close(a[0]).map(|_| 0),
        abi::SYS_LSEEK => sys_lseek(env, a[0], a[1], a[2]),
        abi::SYS_GETDENTS64 => sys_getdents64(env, cpu, a[0], a[1], a[2]),
        abi::SYS_GETDENTS => Err(abi::ENOSYS), // legacy; modern userlands use getdents64
        abi::SYS_STAT => sys_statpath(env, cpu, abi::AT_FDCWD, a[0], a[1], true),
        abi::SYS_LSTAT => sys_statpath(env, cpu, abi::AT_FDCWD, a[0], a[1], false),
        abi::SYS_FSTAT => sys_fstat(env, cpu, a[0], a[1]),
        abi::SYS_NEWFSTATAT => sys_newfstatat(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_STATX => sys_statx(env, cpu, a[0], a[1], a[2], a[4]),
        abi::SYS_ACCESS => sys_faccessat(env, cpu, abi::AT_FDCWD, a[0]),
        abi::SYS_FACCESSAT | abi::SYS_FACCESSAT2 => sys_faccessat(env, cpu, a[0], a[1]),
        abi::SYS_READLINK => sys_readlinkat(env, cpu, abi::AT_FDCWD, a[0], a[1], a[2]),
        abi::SYS_READLINKAT => sys_readlinkat(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_MKDIR => sys_mkdirat(env, cpu, abi::AT_FDCWD, a[0], a[1]),
        abi::SYS_MKDIRAT => sys_mkdirat(env, cpu, a[0], a[1], a[2]),
        abi::SYS_RMDIR => sys_unlinkat(env, cpu, abi::AT_FDCWD, a[0], abi::AT_REMOVEDIR),
        abi::SYS_UNLINK => sys_unlinkat(env, cpu, abi::AT_FDCWD, a[0], 0),
        abi::SYS_UNLINKAT => sys_unlinkat(env, cpu, a[0], a[1], a[2]),
        abi::SYS_RENAME => sys_renameat(env, cpu, abi::AT_FDCWD, a[0], abi::AT_FDCWD, a[1]),
        abi::SYS_RENAMEAT => sys_renameat(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_LINK => sys_linkat(env, cpu, abi::AT_FDCWD, a[0], abi::AT_FDCWD, a[1]),
        abi::SYS_LINKAT => sys_linkat(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_SYMLINK => sys_symlinkat(env, cpu, a[0], abi::AT_FDCWD, a[1]),
        abi::SYS_SYMLINKAT => sys_symlinkat(env, cpu, a[0], a[1], a[2]),
        abi::SYS_CHDIR => sys_chdir(env, cpu, a[0]),
        abi::SYS_FCHDIR => sys_fchdir(env, a[0]),
        abi::SYS_GETCWD => sys_getcwd(env, cpu, a[0], a[1]),
        abi::SYS_CHMOD => sys_chmodat(env, cpu, abi::AT_FDCWD, a[0], a[1]),
        abi::SYS_FCHMODAT => sys_chmodat(env, cpu, a[0], a[1], a[2]),
        abi::SYS_FCHMOD => sys_fchmod(env, a[0], a[1]),
        abi::SYS_CHOWN | abi::SYS_FCHOWNAT => Ok(0), // single-user: uid/gid stay 0
        abi::SYS_UTIMENSAT => sys_utimensat(env, cpu, a),
        abi::SYS_UMASK => {
            let old = env.proc.umask;
            env.proc.umask = (a[0] as u32) & 0o777;
            Ok(old as u64)
        }
        abi::SYS_DUP => sys_dup(env, a[0], 0, false),
        abi::SYS_DUP2 => sys_dup2(env, a[0], a[1], false),
        abi::SYS_DUP3 => {
            if a[0] == a[1] {
                Err(abi::EINVAL)
            } else {
                sys_dup2(env, a[0], a[1], a[2] & abi::O_CLOEXEC != 0)
            }
        }
        abi::SYS_FCNTL => sys_fcntl(env, a[0], a[1], a[2]),
        abi::SYS_IOCTL => sys_ioctl(env, cpu, a[0], a[1], a[2]),
        abi::SYS_FSYNC | abi::SYS_SYNC => Ok(0),

        abi::SYS_SOCKET => sys_socket(env, a[0], a[1], a[2]),
        abi::SYS_CONNECT => sys_connect(env, cpu, a[0], a[1], a[2]),
        abi::SYS_SHUTDOWN => sys_shutdown(env, a[0], a[1]),
        abi::SYS_GETPEERNAME => sys_getpeername(env, cpu, a[0], a[1], a[2]),
        abi::SYS_GETSOCKNAME => {
            // Local addresses are broker-side; report the unspecified addr.
            write_sockaddr_in(
                cpu,
                a[1],
                a[2],
                std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0),
            )?;
            net_of(env, a[0]).map(|_| 0)
        }
        abi::SYS_SETSOCKOPT => net_of(env, a[0]).map(|_| 0),
        abi::SYS_GETSOCKOPT => sys_getsockopt(env, cpu, a),
        abi::SYS_SOCKETPAIR => sys_socketpair(env, cpu, a),
        abi::SYS_BIND => {
            let target = parse_sockaddr_in(cpu, a[1], a[2])?;
            if target.port() == 0 {
                Ok(0) // ephemeral bind: the broker already does this
            } else {
                tracing::warn!("bind to a specific port is not supported (no listeners)");
                Err(abi::EOPNOTSUPP)
            }
        }
        abi::SYS_LISTEN | abi::SYS_ACCEPT | abi::SYS_ACCEPT4 => {
            tracing::warn!("listening sockets are not supported (client-only network)");
            Err(abi::EOPNOTSUPP)
        }
        abi::SYS_SENDMSG | abi::SYS_RECVMSG => {
            tracing::warn!("sendmsg/recvmsg are not implemented yet");
            Err(abi::ENOSYS)
        }
        abi::SYS_EVENTFD => sys_eventfd(env, a[0], 0),
        abi::SYS_EVENTFD2 => sys_eventfd(env, a[0], a[1]),
        abi::SYS_TIMERFD_CREATE => sys_timerfd_create(env, a[0], a[1]),
        abi::SYS_TIMERFD_SETTIME => sys_timerfd_settime(env, cpu, a),
        abi::SYS_TIMERFD_GETTIME => sys_timerfd_gettime(env, cpu, a[0], a[1]),
        abi::SYS_EPOLL_CREATE | abi::SYS_EPOLL_CREATE1 => sys_epoll_create(env, a[1]),
        abi::SYS_EPOLL_CTL => sys_epoll_ctl(env, cpu, a),

        abi::SYS_MMAP => sys_mmap(env, cpu, a),
        abi::SYS_MUNMAP => match cpu.mem.unmap_memory_len(a[0], a[1]) {
            true => Ok(0),
            false => Err(abi::EINVAL),
        },
        abi::SYS_MPROTECT => sys_mprotect(cpu, a[0], a[1], a[2]),
        // Advisory only; taking no action is a valid implementation.
        abi::SYS_MADVISE => Ok(0),
        abi::SYS_BRK => sys_brk(env, cpu, a[0]),

        abi::SYS_RT_SIGACTION => sys_rt_sigaction(env, cpu, a[0], a[1], a[2]),
        abi::SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(env, cpu, a[0], a[1], a[2]),
        // Registration-only, like rt_sigaction: signals are never delivered
        // in this environment, so the alternate stack is recorded and unused.
        abi::SYS_SIGALTSTACK => {
            if a[1] != 0 {
                write_mem(cpu, a[1], &[0_u8; 24])?;
            }
            Ok(0)
        }

        abi::SYS_ARCH_PRCTL => match a[0] {
            abi::ARCH_SET_FS => {
                cpu.write_var(env.regs.fs_offset, a[1]);
                Ok(0)
            }
            abi::ARCH_GET_FS => {
                let fs: u64 = cpu.read_var(env.regs.fs_offset);
                write_mem(cpu, a[1], &fs.to_le_bytes())?;
                Ok(0)
            }
            op => {
                tracing::debug!("arch_prctl: unsupported op {op:#x}");
                Err(abi::EINVAL)
            }
        },

        abi::SYS_UNAME => sys_uname(cpu, a[0]),
        abi::SYS_GETRANDOM => sys_getrandom(env, cpu, a[0], a[1]),
        abi::SYS_CLOCK_GETTIME => sys_clock_gettime(env, cpu, a[1]),
        abi::SYS_CLOCK_GETRES => {
            if a[1] != 0 {
                let res: [u8; 16] = encode_timespec(0, 1);
                write_mem(cpu, a[1], &res)?;
            }
            Ok(0)
        }
        abi::SYS_GETTIMEOFDAY => sys_gettimeofday(env, cpu, a[0]),
        abi::SYS_TIME => {
            let (sec, _) = env.now(cpu);
            if a[0] != 0 {
                write_mem(cpu, a[0], &sec.to_le_bytes())?;
            }
            Ok(sec as u64)
        }
        abi::SYS_NANOSLEEP => sys_nanosleep(env, cpu, a[0]),
        abi::SYS_CLOCK_NANOSLEEP => {
            const TIMER_ABSTIME: u64 = 1;
            if a[1] & TIMER_ABSTIME != 0 {
                let target = read_timespec_at(cpu, a[2])?;
                let now = env.now_nanos(cpu);
                if target > now {
                    env.warp_nanos += target - now;
                }
                Ok(0)
            } else {
                sys_nanosleep(env, cpu, a[2])
            }
        }

        abi::SYS_GETPID | abi::SYS_GETPGRP | abi::SYS_GETPGID => Ok(env.proc.tgid),
        abi::SYS_GETTID => Ok(env.proc.pid),
        abi::SYS_GETPPID => Ok(env.proc.ppid),
        abi::SYS_GETUID | abi::SYS_GETGID | abi::SYS_GETEUID | abi::SYS_GETEGID => Ok(0),
        abi::SYS_GETGROUPS => Ok(0),
        abi::SYS_SETSID => Ok(env.proc.tgid),
        abi::SYS_SET_TID_ADDRESS => {
            env.proc.clear_child_tid = a[0];
            Ok(env.proc.pid)
        }
        abi::SYS_PRLIMIT64 => sys_prlimit64(cpu, a[2], a[3]),
        abi::SYS_SETRLIMIT => Ok(0),

        abi::SYS_SET_ROBUST_LIST | abi::SYS_RSEQ => Err(abi::ENOSYS),
        abi::SYS_RT_SIGRETURN => Err(abi::ENOSYS),

        _ => {
            tracing::warn!("unimplemented syscall {nr} -> ENOSYS");
            Err(abi::ENOSYS)
        }
    }
}

// ── Path helpers ────────────────────────────────────────────────────────────

/// Resolves a `dirfd` to a VFS directory node.
///
/// The kernel ABI treats `dirfd` as a 32-bit int: callers may pass
/// `AT_FDCWD` zero-extended (glibc) or sign-extended (musl), so compare in
/// 32 bits.
fn dir_of(env: &LinuxEnv, dirfd: u64) -> Result<usize, u64> {
    if dirfd as u32 as i32 == abi::AT_FDCWD as u32 as i32 {
        return Ok(env.proc.cwd);
    }
    match env.proc.fds.borrow().get(dirfd)?.desc.borrow().backing {
        Backing::Dir { node, .. } => Ok(node),
        _ => Err(abi::ENOTDIR),
    }
}

fn path_arg(cpu: &mut Cpu, ptr: u64) -> Result<Vec<u8>, u64> {
    read_cstr(cpu, ptr)
}

// ── File I/O ────────────────────────────────────────────────────────────────

fn read_backing(
    env: &mut LinuxEnv,
    desc: &mut Description,
    buf_len: usize,
) -> Result<Vec<u8>, u64> {
    match &mut desc.backing {
        Backing::Std(StdStream::In) => Ok(Vec::new()),
        Backing::Std(_) => Err(abi::EBADF),
        Backing::File { node } => {
            let NodeKind::File(data) = &env.vfs.node(*node).kind else {
                return Err(abi::EIO);
            };
            let start = (desc.offset as usize).min(data.len());
            let end = (start + buf_len).min(data.len());
            let chunk = data[start..end].to_vec();
            desc.offset += chunk.len() as u64;
            Ok(chunk)
        }
        Backing::Dir { .. } => Err(abi::EISDIR),
        // Handled by `outcome_read` before reaching here.
        Backing::Pipe { .. }
        | Backing::SocketPair { .. }
        | Backing::EventFd(_)
        | Backing::TimerFd(_)
        | Backing::Net(_)
        | Backing::Epoll(_) => Err(abi::EINVAL),
        Backing::Dev(dev) => match dev {
            Dev::Null | Dev::Tty => Ok(Vec::new()),
            Dev::Zero => Ok(vec![0; buf_len]),
            Dev::Random => {
                let mut out = vec![0_u8; buf_len];
                for chunk in out.chunks_mut(8) {
                    let bytes = env.next_random().to_le_bytes();
                    chunk.copy_from_slice(&bytes[..chunk.len()]);
                }
                Ok(out)
            }
        },
    }
}

fn write_backing(env: &mut LinuxEnv, desc: &mut Description, bytes: &[u8]) -> Result<u64, u64> {
    if !desc.writable() {
        return Err(abi::EBADF);
    }
    match &mut desc.backing {
        Backing::Std(StdStream::In) => Err(abi::EBADF),
        Backing::Std(_) | Backing::Dev(Dev::Tty) => {
            env.output.extend_from_slice(bytes);
            Ok(bytes.len() as u64)
        }
        Backing::Dev(_) => Ok(bytes.len() as u64),
        Backing::File { node } => {
            let node = *node;
            let NodeKind::File(data) = &mut env.vfs.node_mut(node).kind else {
                return Err(abi::EIO);
            };
            if desc.flags & abi::O_APPEND != 0 {
                desc.offset = data.len() as u64;
            }
            let start = desc.offset as usize;
            if data.len() < start + bytes.len() {
                data.resize(start + bytes.len(), 0);
            }
            data[start..start + bytes.len()].copy_from_slice(bytes);
            desc.offset += bytes.len() as u64;
            Ok(bytes.len() as u64)
        }
        Backing::Dir { .. } => Err(abi::EISDIR),
        // Handled by `outcome_write` before reaching here.
        Backing::Pipe { .. }
        | Backing::SocketPair { .. }
        | Backing::EventFd(_)
        | Backing::TimerFd(_)
        | Backing::Net(_)
        | Backing::Epoll(_) => Err(abi::EINVAL),
    }
}

fn sys_read(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64, count: u64) -> SysResult {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let mut desc = desc.borrow_mut();
    if !desc.readable() {
        return Err(abi::EBADF);
    }
    let count = count.min(0x40_0000) as usize;
    let chunk = read_backing(env, &mut desc, count)?;
    write_mem(cpu, buf, &chunk)?;
    Ok(chunk.len() as u64)
}

fn sys_write(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64, count: u64) -> SysResult {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let mut desc = desc.borrow_mut();
    let count = count.min(0x40_0000) as usize;
    let bytes = read_mem(cpu, buf, count)?;
    write_backing(env, &mut desc, &bytes)
}

fn iter_iov(cpu: &mut Cpu, iov: u64, iovcnt: u64) -> Result<Vec<(u64, u64)>, u64> {
    let iovcnt = iovcnt.min(1024);
    let raw = read_mem(cpu, iov, (iovcnt * 16) as usize)?;
    Ok(raw
        .chunks_exact(16)
        .map(|entry| {
            (
                u64::from_le_bytes(entry[..8].try_into().expect("chunk size")),
                u64::from_le_bytes(entry[8..].try_into().expect("chunk size")),
            )
        })
        .collect())
}

fn sys_pread(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    fd: u64,
    buf: u64,
    count: u64,
    pos: u64,
) -> SysResult {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let mut desc = desc.borrow_mut();
    let Backing::File { .. } = desc.backing else {
        return Err(abi::ESPIPE);
    };
    let saved = desc.offset;
    desc.offset = pos;
    let chunk = read_backing(env, &mut desc, count.min(0x40_0000) as usize);
    desc.offset = saved;
    let chunk = chunk?;
    write_mem(cpu, buf, &chunk)?;
    Ok(chunk.len() as u64)
}

fn sys_pwrite(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    fd: u64,
    buf: u64,
    count: u64,
    pos: u64,
) -> SysResult {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let mut desc = desc.borrow_mut();
    let Backing::File { .. } = desc.backing else {
        return Err(abi::ESPIPE);
    };
    let bytes = read_mem(cpu, buf, count.min(0x40_0000) as usize)?;
    let saved = desc.offset;
    desc.offset = pos;
    let result = write_backing(env, &mut desc, &bytes);
    desc.offset = saved;
    result
}

fn sys_openat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    flags: u64,
    mode: u64,
) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    let base = dir_of(env, dirfd)?;
    let follow = flags & abi::O_NOFOLLOW == 0;
    let resolved = env.vfs.resolve(base, &path, follow)?;

    let node = match resolved.node {
        Some(node) => {
            if flags & abi::O_CREAT != 0 && flags & abi::O_EXCL != 0 {
                return Err(abi::EEXIST);
            }
            node
        }
        None => {
            if flags & abi::O_CREAT == 0 {
                return Err(abi::ENOENT);
            }
            let mode = (mode as u32) & 0o777 & !env.proc.umask;
            env.vfs.create(
                resolved.parent,
                &resolved.name,
                NodeKind::File(Vec::new()),
                mode,
            )?
        }
    };

    let backing = match &env.vfs.node(node).kind {
        NodeKind::Dir(_) => {
            if flags & abi::O_ACCMODE != abi::O_RDONLY {
                return Err(abi::EISDIR);
            }
            Backing::Dir { node, cookie: 0 }
        }
        NodeKind::File(_) => {
            if flags & abi::O_DIRECTORY != 0 {
                return Err(abi::ENOTDIR);
            }
            if flags & abi::O_TRUNC != 0 && flags & abi::O_ACCMODE != abi::O_RDONLY {
                if let NodeKind::File(data) = &mut env.vfs.node_mut(node).kind {
                    data.clear();
                }
            }
            Backing::File { node }
        }
        NodeKind::CharDev(dev) => Backing::Dev(*dev),
        NodeKind::Symlink(_) => return Err(abi::ELOOP), // O_NOFOLLOW on a symlink
    };

    let entry = FdEntry {
        desc: std::rc::Rc::new(std::cell::RefCell::new(Description {
            backing,
            offset: 0,
            flags: flags & (abi::O_ACCMODE | abi::O_APPEND | abi::O_NONBLOCK),
        })),
        cloexec: flags & abi::O_CLOEXEC != 0,
    };
    env.proc.fds.borrow_mut().insert(entry)
}

fn sys_lseek(env: &mut LinuxEnv, fd: u64, offset: u64, whence: u64) -> SysResult {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let mut desc = desc.borrow_mut();
    let size = match &mut desc.backing {
        Backing::File { node } => env.vfs.node(*node).size(),
        Backing::Dir { cookie, .. } => {
            // Directory seeks reset or set the getdents64 cookie.
            if whence == abi::SEEK_SET {
                *cookie = offset;
                return Ok(offset);
            }
            return Err(abi::EINVAL);
        }
        Backing::Dev(_) => 0,
        _ => return Err(abi::ESPIPE),
    };
    let base = match whence {
        abi::SEEK_SET => 0_i64,
        abi::SEEK_CUR => desc.offset as i64,
        abi::SEEK_END => size as i64,
        _ => return Err(abi::EINVAL),
    };
    let target = base.checked_add(offset as i64).ok_or(abi::EINVAL)?;
    if target < 0 {
        return Err(abi::EINVAL);
    }
    desc.offset = target as u64;
    Ok(desc.offset)
}

fn sys_getdents64(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, dirp: u64, count: u64) -> SysResult {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let mut desc = desc.borrow_mut();
    let Backing::Dir { node, cookie } = &mut desc.backing else {
        return Err(abi::ENOTDIR);
    };
    let entries = env.vfs.list(*node)?;
    let mut out: Vec<u8> = Vec::new();
    let mut position = *cookie as usize;
    while position < entries.len() {
        let (name, entry_node) = &entries[position];
        let d_type = env.vfs.node(*entry_node).d_type();
        let remaining = count as usize - out.len();
        match abi::encode_dirent64(
            *entry_node as u64 + 1,
            position as u64 + 1,
            d_type,
            name,
            remaining,
        ) {
            Some(rec) => out.extend_from_slice(&rec),
            None if out.is_empty() => return Err(abi::EINVAL),
            None => break,
        }
        position += 1;
    }
    *cookie = position as u64;
    write_mem(cpu, dirp, &out)?;
    Ok(out.len() as u64)
}

// ── stat family ─────────────────────────────────────────────────────────────

fn stat_of_node(env: &LinuxEnv, node: usize) -> abi::Stat {
    let n = env.vfs.node(node);
    let size = n.size() as i64;
    abi::Stat {
        dev: 1,
        ino: node as u64 + 1,
        nlink: n.nlink,
        mode: n.file_type_bits() | (n.mode & 0o7777),
        uid: 0,
        gid: 0,
        rdev: 0,
        size,
        blksize: 4096,
        blocks: (size + 511) / 512,
        atime_sec: n.mtime_sec,
        mtime_sec: n.mtime_sec,
        ctime_sec: n.mtime_sec,
        ..Default::default()
    }
}

fn stat_of_fd(env: &LinuxEnv, fd: u64) -> Result<abi::Stat, u64> {
    let ofd = env.proc.fds.borrow().get(fd)?.desc.clone();
    let desc = ofd.borrow();
    Ok(match &desc.backing {
        Backing::File { node } | Backing::Dir { node, .. } => stat_of_node(env, *node),
        Backing::Std(_) | Backing::Dev(Dev::Tty) => abi::Stat {
            dev: 1,
            ino: u64::MAX,
            nlink: 1,
            mode: abi::S_IFCHR | 0o620,
            rdev: (136 << 8),
            blksize: 1024,
            ..Default::default()
        },
        Backing::Dev(_) => abi::Stat {
            dev: 1,
            ino: u64::MAX - 1,
            nlink: 1,
            mode: abi::S_IFCHR | 0o666,
            blksize: 4096,
            ..Default::default()
        },
        Backing::Pipe { .. } | Backing::SocketPair { .. } | Backing::Net(_) => abi::Stat {
            dev: 1,
            ino: u64::MAX - 2,
            nlink: 1,
            mode: abi::S_IFIFO | 0o600,
            blksize: 4096,
            ..Default::default()
        },
        // Anonymous inodes (eventfd/timerfd/epoll).
        Backing::EventFd(_) | Backing::TimerFd(_) | Backing::Epoll(_) => abi::Stat {
            dev: 1,
            ino: u64::MAX - 3,
            nlink: 1,
            mode: 0o600,
            blksize: 4096,
            ..Default::default()
        },
    })
}

fn sys_fstat(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64) -> SysResult {
    let stat = stat_of_fd(env, fd)?;
    write_mem(cpu, buf, &stat.encode())?;
    Ok(0)
}

fn sys_statpath(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    buf: u64,
    follow: bool,
) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    let base = dir_of(env, dirfd)?;
    let resolved = env.vfs.resolve(base, &path, follow)?;
    let node = resolved.node.ok_or(abi::ENOENT)?;
    let stat = stat_of_node(env, node);
    write_mem(cpu, buf, &stat.encode())?;
    Ok(0)
}

fn sys_newfstatat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    buf: u64,
    flags: u64,
) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    if path.is_empty() && flags & abi::AT_EMPTY_PATH != 0 {
        return sys_fstat(env, cpu, dirfd, buf);
    }
    let follow = flags & abi::AT_SYMLINK_NOFOLLOW == 0;
    sys_statpath(env, cpu, dirfd, path_ptr, buf, follow)
}

fn sys_statx(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    flags: u64,
    buf: u64,
) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    let stat = if path.is_empty() && flags & abi::AT_EMPTY_PATH != 0 {
        stat_of_fd(env, dirfd)?
    } else {
        let base = dir_of(env, dirfd)?;
        let follow = flags & abi::AT_SYMLINK_NOFOLLOW == 0;
        let resolved = env.vfs.resolve(base, &path, follow)?;
        stat_of_node(env, resolved.node.ok_or(abi::ENOENT)?)
    };

    let mut out = [0_u8; 256];
    let mut put =
        |offset: usize, bytes: &[u8]| out[offset..offset + bytes.len()].copy_from_slice(bytes);
    put(0, &0x7ff_u32.to_le_bytes()); // STATX_BASIC_STATS
    put(4, &(stat.blksize as u32).to_le_bytes());
    put(16, &(stat.nlink as u32).to_le_bytes());
    put(20, &stat.uid.to_le_bytes());
    put(24, &stat.gid.to_le_bytes());
    put(28, &(stat.mode as u16).to_le_bytes());
    put(32, &stat.ino.to_le_bytes());
    put(40, &(stat.size as u64).to_le_bytes());
    put(48, &(stat.blocks as u64).to_le_bytes());
    for (base, sec, nsec) in [
        (64, stat.atime_sec, stat.atime_nsec),
        (96, stat.ctime_sec, stat.ctime_nsec),
        (112, stat.mtime_sec, stat.mtime_nsec),
    ] {
        put(base, &sec.to_le_bytes());
        put(base + 8, &(nsec as u32).to_le_bytes());
    }
    put(136, &1_u32.to_le_bytes()); // dev_major
    write_mem(cpu, buf, &out)?;
    Ok(0)
}

fn sys_faccessat(env: &mut LinuxEnv, cpu: &mut Cpu, dirfd: u64, path_ptr: u64) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    let base = dir_of(env, dirfd)?;
    let resolved = env.vfs.resolve(base, &path, true)?;
    resolved.node.map(|_| 0).ok_or(abi::ENOENT)
}

fn sys_readlinkat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    buf: u64,
    size: u64,
) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    let target = if path == b"/proc/self/exe" {
        env.proc.exe_path.clone()
    } else {
        let base = dir_of(env, dirfd)?;
        let resolved = env.vfs.resolve(base, &path, false)?;
        let node = resolved.node.ok_or(abi::ENOENT)?;
        match &env.vfs.node(node).kind {
            NodeKind::Symlink(target) => target.clone(),
            _ => return Err(abi::EINVAL),
        }
    };
    let n = target.len().min(size as usize);
    write_mem(cpu, buf, &target[..n])?;
    Ok(n as u64)
}

// ── Directory modification ──────────────────────────────────────────────────

fn sys_mkdirat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    mode: u64,
) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    let base = dir_of(env, dirfd)?;
    let resolved = env.vfs.resolve(base, &path, true)?;
    if resolved.node.is_some() {
        return Err(abi::EEXIST);
    }
    let mode = (mode as u32) & 0o777 & !env.proc.umask;
    env.vfs
        .create(
            resolved.parent,
            &resolved.name,
            NodeKind::Dir(Default::default()),
            mode,
        )
        .map(|_| 0)
}

fn sys_unlinkat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    flags: u64,
) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    let base = dir_of(env, dirfd)?;
    let resolved = env.vfs.resolve(base, &path, false)?;
    env.vfs
        .unlink(
            resolved.parent,
            &resolved.name,
            flags & abi::AT_REMOVEDIR != 0,
        )
        .map(|_| 0)
}

fn sys_renameat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    old_dirfd: u64,
    old_ptr: u64,
    new_dirfd: u64,
    new_ptr: u64,
) -> SysResult {
    let old_path = path_arg(cpu, old_ptr)?;
    let new_path = path_arg(cpu, new_ptr)?;
    let old_base = dir_of(env, old_dirfd)?;
    let new_base = dir_of(env, new_dirfd)?;
    let old = env.vfs.resolve(old_base, &old_path, false)?;
    let new = env.vfs.resolve(new_base, &new_path, false)?;
    env.vfs
        .rename(old.parent, &old.name, new.parent, &new.name)
        .map(|_| 0)
}

fn sys_linkat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    old_dirfd: u64,
    old_ptr: u64,
    new_dirfd: u64,
    new_ptr: u64,
) -> SysResult {
    let old_path = path_arg(cpu, old_ptr)?;
    let new_path = path_arg(cpu, new_ptr)?;
    let old_base = dir_of(env, old_dirfd)?;
    let new_base = dir_of(env, new_dirfd)?;
    let old = env.vfs.resolve(old_base, &old_path, true)?;
    let node = old.node.ok_or(abi::ENOENT)?;
    if env.vfs.is_dir(node) {
        return Err(abi::EPERM);
    }
    let new = env.vfs.resolve(new_base, &new_path, false)?;
    if new.node.is_some() {
        return Err(abi::EEXIST);
    }
    env.vfs.link(new.parent, &new.name, node)?;
    Ok(0)
}

fn sys_symlinkat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    target_ptr: u64,
    dirfd: u64,
    path_ptr: u64,
) -> SysResult {
    let target = path_arg(cpu, target_ptr)?;
    let path = path_arg(cpu, path_ptr)?;
    let base = dir_of(env, dirfd)?;
    let resolved = env.vfs.resolve(base, &path, false)?;
    if resolved.node.is_some() {
        return Err(abi::EEXIST);
    }
    env.vfs
        .create(
            resolved.parent,
            &resolved.name,
            NodeKind::Symlink(target),
            0o777,
        )
        .map(|_| 0)
}

fn sys_chdir(env: &mut LinuxEnv, cpu: &mut Cpu, path_ptr: u64) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    let resolved = env.vfs.resolve(env.proc.cwd, &path, true)?;
    let node = resolved.node.ok_or(abi::ENOENT)?;
    if !env.vfs.is_dir(node) {
        return Err(abi::ENOTDIR);
    }
    env.proc.cwd = node;
    Ok(0)
}

fn sys_fchdir(env: &mut LinuxEnv, fd: u64) -> SysResult {
    match env.proc.fds.borrow().get(fd)?.desc.borrow().backing {
        Backing::Dir { node, .. } => {
            env.proc.cwd = node;
            Ok(0)
        }
        _ => Err(abi::ENOTDIR),
    }
}

fn sys_getcwd(env: &mut LinuxEnv, cpu: &mut Cpu, buf: u64, size: u64) -> SysResult {
    let mut path = env.vfs.abs_path_of(env.proc.cwd);
    path.push(0);
    if (size as usize) < path.len() {
        return Err(abi::ERANGE);
    }
    write_mem(cpu, buf, &path)?;
    Ok(path.len() as u64)
}

fn sys_chmodat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    mode: u64,
) -> SysResult {
    let path = path_arg(cpu, path_ptr)?;
    let base = dir_of(env, dirfd)?;
    let resolved = env.vfs.resolve(base, &path, true)?;
    let node = resolved.node.ok_or(abi::ENOENT)?;
    env.vfs.node_mut(node).mode = (mode as u32) & 0o7777;
    Ok(0)
}

fn sys_fchmod(env: &mut LinuxEnv, fd: u64, mode: u64) -> SysResult {
    let node = match env.proc.fds.borrow().get(fd)?.desc.borrow().backing {
        Backing::File { node } | Backing::Dir { node, .. } => node,
        _ => return Ok(0),
    };
    env.vfs.node_mut(node).mode = (mode as u32) & 0o7777;
    Ok(0)
}

// ── Descriptor management ───────────────────────────────────────────────────

fn sys_dup(env: &mut LinuxEnv, fd: u64, min: u64, cloexec: bool) -> SysResult {
    let entry = env.proc.fds.borrow().get(fd)?.clone();
    env.proc.fds.borrow_mut().insert_from(
        min as usize,
        FdEntry {
            desc: entry.desc,
            cloexec,
        },
    )
}

fn sys_dup2(env: &mut LinuxEnv, fd: u64, new_fd: u64, cloexec: bool) -> SysResult {
    let entry = env.proc.fds.borrow().get(fd)?.clone();
    if fd == new_fd {
        return Ok(new_fd);
    }
    env.proc.fds.borrow_mut().insert_at(
        new_fd,
        FdEntry {
            desc: entry.desc,
            cloexec,
        },
    )
}

fn sys_fcntl(env: &mut LinuxEnv, fd: u64, cmd: u64, arg: u64) -> SysResult {
    match cmd {
        abi::F_DUPFD => sys_dup(env, fd, arg, false),
        abi::F_DUPFD_CLOEXEC => sys_dup(env, fd, arg, true),
        abi::F_GETFD => Ok(if env.proc.fds.borrow().get(fd)?.cloexec {
            abi::FD_CLOEXEC
        } else {
            0
        }),
        abi::F_SETFD => {
            env.proc.fds.borrow_mut().get_mut(fd)?.cloexec = arg & abi::FD_CLOEXEC != 0;
            Ok(0)
        }
        abi::F_GETFL => Ok(env.proc.fds.borrow().get(fd)?.desc.borrow().flags),
        abi::F_SETFL => {
            let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
            let mut desc = desc.borrow_mut();
            let keep = desc.flags & abi::O_ACCMODE;
            desc.flags = keep | (arg & (abi::O_APPEND | abi::O_NONBLOCK));
            Ok(0)
        }
        _ => {
            tracing::debug!("fcntl: unsupported cmd {cmd}");
            Err(abi::EINVAL)
        }
    }
}

fn sys_ioctl(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, request: u64, arg: u64) -> SysResult {
    let is_tty = matches!(
        env.proc.fds.borrow().get(fd)?.desc.borrow().backing,
        Backing::Std(StdStream::Out) | Backing::Std(StdStream::Err) | Backing::Dev(Dev::Tty)
    );
    if !is_tty {
        return Err(abi::ENOTTY);
    }
    match request {
        abi::TIOCGWINSZ => {
            let winsize: [u16; 4] = [24, 80, 0, 0];
            let bytes: Vec<u8> = winsize.iter().flat_map(|v| v.to_le_bytes()).collect();
            write_mem(cpu, arg, &bytes)?;
            Ok(0)
        }
        abi::TCGETS => {
            // Sane cooked-mode termios: ICRNL|IXON, OPOST|ONLCR, CS8,
            // ISIG|ICANON|ECHO|ECHOE|ECHOK.
            let mut termios = [0_u8; 36];
            termios[0..4].copy_from_slice(&0x0500_u32.to_le_bytes());
            termios[4..8].copy_from_slice(&0x0005_u32.to_le_bytes());
            termios[8..12].copy_from_slice(&0x00bf_u32.to_le_bytes());
            termios[12..16].copy_from_slice(&0x8a3b_u32.to_le_bytes());
            write_mem(cpu, arg, &termios)?;
            Ok(0)
        }
        abi::TCSETS | abi::TCSETSW | abi::TIOCSWINSZ | abi::TIOCSPGRP => Ok(0),
        abi::TIOCGPGRP => {
            write_mem(cpu, arg, &(PID as u32).to_le_bytes())?;
            Ok(0)
        }
        _ => {
            tracing::debug!("ioctl: unsupported request {request:#x}");
            Err(abi::ENOTTY)
        }
    }
}

/// `poll`/`ppoll` with real readiness for pipes, sockets, eventfd, and
/// timerfd; plain files and streams are always ready. Never blocks: a
/// zero-ready result is returned to the caller (event loops re-poll).
fn sys_poll(env: &mut LinuxEnv, cpu: &mut Cpu, fds_ptr: u64, nfds: u64) -> SysResult {
    const POLLIN: u16 = 0x1;
    const POLLOUT: u16 = 0x4;
    const POLLERR: u16 = 0x8;
    const POLLHUP: u16 = 0x10;
    const POLLNVAL: u16 = 0x20;

    let now = env.now_nanos(cpu);
    let nfds = nfds.min(1024) as usize;
    let mut records = read_mem(cpu, fds_ptr, nfds * 8)?;
    let mut ready = 0_u64;
    for record in records.chunks_exact_mut(8) {
        let fd = i32::from_le_bytes(record[..4].try_into().expect("chunk size"));
        let events = u16::from_le_bytes(record[4..6].try_into().expect("chunk size"));
        let revents = match env.proc.fds.borrow().get(fd as u32 as u64) {
            Err(_) => POLLNVAL,
            Ok(entry) => {
                let desc = entry.desc.borrow();
                let mut bits = 0_u16;
                if events & POLLIN != 0 && desc.readable() && desc_read_ready(&desc, now) {
                    bits |= POLLIN;
                }
                if events & POLLOUT != 0 && desc.writable() && desc_write_ready(&desc) {
                    bits |= POLLOUT;
                }
                if let Backing::Pipe {
                    inner,
                    write_end: false,
                } = &desc.backing
                {
                    if inner.borrow().writers == 0 {
                        bits |= POLLHUP;
                    }
                }
                let _ = POLLERR;
                bits
            }
        };
        record[6..8].copy_from_slice(&revents.to_le_bytes());
        if revents != 0 {
            ready += 1;
        }
    }
    write_mem(cpu, fds_ptr, &records)?;
    Ok(ready)
}

/// Read-readiness of a description at deterministic time `now`.
fn desc_read_ready(desc: &Description, now: u64) -> bool {
    match read_watch_of(desc) {
        Some(watch) => watch.ready(now),
        None => true,
    }
}

/// Write-readiness (pipes/socketpairs can fill; everything else accepts).
fn desc_write_ready(desc: &Description) -> bool {
    match &desc.backing {
        Backing::Pipe {
            inner,
            write_end: true,
        }
        | Backing::SocketPair { tx: inner, .. } => {
            let inner = inner.borrow();
            inner.data.len() < crate::PIPE_CAPACITY || inner.readers == 0
        }
        _ => true,
    }
}

/// The watch that becomes ready when a read on `desc` would make progress;
/// None when reads never block.
fn read_watch_of(desc: &Description) -> Option<crate::proc::Watch> {
    use crate::proc::Watch;
    match &desc.backing {
        Backing::Pipe {
            inner,
            write_end: false,
        } => Some(Watch::PipeReadable(inner.clone())),
        Backing::SocketPair { rx, .. } => Some(Watch::PipeReadable(rx.clone())),
        Backing::EventFd(event) => Some(Watch::Event(event.clone())),
        Backing::TimerFd(timer) => Some(Watch::Timer(timer.clone())),
        Backing::Net(socket) => Some(Watch::NetReadable(socket.clone())),
        _ => None,
    }
}

// ── Memory management ───────────────────────────────────────────────────────

fn prot_to_perm(prot: u64) -> u8 {
    let mut bits = perm::INIT;
    if prot & abi::PROT_READ != 0 {
        bits |= perm::READ;
    }
    if prot & abi::PROT_WRITE != 0 {
        bits |= perm::WRITE;
    }
    if prot & abi::PROT_EXEC != 0 {
        bits |= perm::EXEC;
    }
    bits
}

fn sys_mmap(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    let [addr, len, prot, flags, fd, offset] = a;
    if len == 0 {
        return Err(abi::EINVAL);
    }
    let len = align_up(len, PAGE_SIZE);
    let target = if flags & abi::MAP_FIXED != 0 && addr != 0 {
        let target = addr & !(PAGE_SIZE - 1);
        // MAP_FIXED replaces any existing mapping.
        cpu.mem.unmap_memory_len(target, len);
        target
    } else {
        env.alloc_mmap(len)
    };

    let file_bytes = if flags & abi::MAP_ANONYMOUS == 0 {
        if flags & abi::MAP_SHARED != 0 {
            tracing::warn!("mmap: MAP_SHARED file mappings are not supported");
            return Err(abi::ENOSYS);
        }
        let node = match env.proc.fds.borrow().get(fd)?.desc.borrow().backing {
            Backing::File { node } => node,
            _ => return Err(abi::EBADF),
        };
        let NodeKind::File(data) = &env.vfs.node(node).kind else {
            return Err(abi::EBADF);
        };
        let start = (offset as usize).min(data.len());
        let end = (start + len as usize).min(data.len());
        Some(data[start..end].to_vec())
    } else {
        None
    };

    // Map writable first so file contents can be copied in, then tighten.
    let ok = cpu.mem.map_memory_len(
        target,
        len,
        icicle_cpu::mem::Mapping {
            perm: perm::READ | perm::WRITE | perm::INIT,
            value: 0,
        },
    );
    if !ok {
        return Err(abi::ENOMEM);
    }
    if let Some(bytes) = file_bytes {
        write_mem(cpu, target, &bytes)?;
    }
    let final_perm = prot_to_perm(prot);
    if cpu.mem.update_perm(target, len, final_perm).is_err() {
        return Err(abi::ENOMEM);
    }
    Ok(target)
}

fn sys_mprotect(cpu: &mut Cpu, addr: u64, len: u64, prot: u64) -> SysResult {
    let len = align_up(len, PAGE_SIZE);
    match cpu.mem.update_perm(addr, len, prot_to_perm(prot)) {
        Ok(()) => Ok(0),
        Err(_) => Err(abi::ENOMEM),
    }
}

fn sys_brk(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64) -> SysResult {
    if addr == 0 || addr <= env.proc.brk_end {
        return Ok(env.proc.brk_end);
    }
    let new_end = align_up(addr, PAGE_SIZE);
    let cur_end = align_up(env.proc.brk_end, PAGE_SIZE);
    if new_end > cur_end {
        let ok = cpu.mem.map_memory_len(
            cur_end,
            new_end - cur_end,
            icicle_cpu::mem::Mapping {
                perm: perm::READ | perm::WRITE | perm::INIT,
                value: 0,
            },
        );
        if !ok {
            return Ok(env.proc.brk_end);
        }
    }
    env.proc.brk_end = addr;
    Ok(addr)
}

// ── Signals (registration only; no delivery in a single process) ────────────

fn sys_rt_sigaction(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    signal: u64,
    new: u64,
    old: u64,
) -> SysResult {
    if old != 0 {
        let previous = env
            .proc
            .sigactions
            .get(&signal)
            .copied()
            .unwrap_or_default();
        write_mem(cpu, old, &previous.0)?;
    }
    if new != 0 {
        let bytes = read_mem(cpu, new, 32)?;
        let mut action = SigAction::default();
        action.0.copy_from_slice(&bytes);
        env.proc.sigactions.insert(signal, action);
    }
    Ok(0)
}

fn sys_rt_sigprocmask(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    how: u64,
    new: u64,
    old: u64,
) -> SysResult {
    if old != 0 {
        write_mem(cpu, old, &env.proc.sigmask.to_le_bytes())?;
    }
    if new != 0 {
        let bytes = read_mem(cpu, new, 8)?;
        let mask = u64::from_le_bytes(bytes.try_into().expect("read_mem length"));
        env.proc.sigmask = match how {
            0 => env.proc.sigmask | mask,  // SIG_BLOCK
            1 => env.proc.sigmask & !mask, // SIG_UNBLOCK
            2 => mask,                     // SIG_SETMASK
            _ => return Err(abi::EINVAL),
        };
    }
    Ok(0)
}

// ── Time, identity, misc ────────────────────────────────────────────────────

fn encode_timespec(sec: i64, nsec: i64) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..8].copy_from_slice(&sec.to_le_bytes());
    out[8..].copy_from_slice(&nsec.to_le_bytes());
    out
}

fn sys_clock_gettime(env: &mut LinuxEnv, cpu: &mut Cpu, ts: u64) -> SysResult {
    let (sec, nsec) = env.now(cpu);
    write_mem(cpu, ts, &encode_timespec(sec, nsec))?;
    Ok(0)
}

fn sys_gettimeofday(env: &mut LinuxEnv, cpu: &mut Cpu, tv: u64) -> SysResult {
    if tv != 0 {
        let (sec, nsec) = env.now(cpu);
        let mut out = [0_u8; 16];
        out[..8].copy_from_slice(&sec.to_le_bytes());
        out[8..].copy_from_slice(&(nsec / 1000).to_le_bytes());
        write_mem(cpu, tv, &out)?;
    }
    Ok(0)
}

fn sys_uname(cpu: &mut Cpu, buf: u64) -> SysResult {
    let mut out = [0_u8; 65 * 6];
    for (i, field) in ["Linux", "webtos", "6.6.0-webtos", "#1 webTOS", "x86_64", ""]
        .iter()
        .enumerate()
    {
        let bytes = field.as_bytes();
        out[i * 65..i * 65 + bytes.len()].copy_from_slice(bytes);
    }
    write_mem(cpu, buf, &out)?;
    Ok(0)
}

fn sys_getrandom(env: &mut LinuxEnv, cpu: &mut Cpu, buf: u64, len: u64) -> SysResult {
    let len = len.min(0x1000) as usize;
    let mut out = vec![0_u8; len];
    for chunk in out.chunks_mut(8) {
        let bytes = env.next_random().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    write_mem(cpu, buf, &out)?;
    Ok(len as u64)
}

fn sys_prlimit64(cpu: &mut Cpu, new: u64, old: u64) -> SysResult {
    if old != 0 {
        // RLIM_INFINITY for both current and max.
        write_mem(cpu, old, &[0xff_u8; 16])?;
    }
    let _ = new; // limits are accepted but not enforced
    Ok(0)
}

// ── Processes, threads, and scheduling (milestone 4) ────────────────────────

use crate::proc::{ParkState, ParkedTask, Process, Zombie, ROOT_PID};

/// `syscall` encodes as `0f 05`; rewinding NEXT_PC by its length makes the
/// guest re-execute the instruction, giving blocking syscalls restart
/// semantics (the condition is re-checked on wakeup).
const SYSCALL_INSN_LEN: u64 = 2;

const CLONE_VM: u64 = 0x100;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;

const WNOHANG: u64 = 1;

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;

fn encode_exit_status(code: u64) -> i32 {
    ((code as i32) & 0xff) << 8
}

pub(crate) struct CloneSpec {
    flags: u64,
    new_sp: u64,
    parent_tid: u64,
    child_tid: u64,
    tls: u64,
}

impl CloneSpec {
    pub(crate) fn fork() -> Self {
        Self {
            flags: 0,
            new_sp: 0,
            parent_tid: 0,
            child_tid: 0,
            tls: 0,
        }
    }

    /// x86-64 argument order: flags, new_sp, parent_tid, child_tid, tls.
    pub(crate) fn from_clone_args(a: [u64; 6]) -> Self {
        Self {
            flags: a[0],
            new_sp: a[1],
            parent_tid: a[2],
            child_tid: a[3],
            tls: a[4],
        }
    }
}

/// Prepares the current CPU state so that, when this task is next resumed,
/// it continues after the syscall (`restart = false`) or re-executes it
/// (`restart = true`).
fn prepare_resume(env: &LinuxEnv, cpu: &mut Cpu, restart: bool) {
    let next_pc: u64 = cpu.read_var(cpu.arch.reg_next_pc);
    let resume = if restart {
        next_pc - SYSCALL_INSN_LEN
    } else {
        next_pc
    };
    let _ = &env.regs; // resume state is register-only
    cpu.write_var(cpu.arch.reg_next_pc, resume);
    cpu.write_pc(resume);
    cpu.exception = Exception::new(ExceptionCode::ExternalAddr, resume);
    cpu.pending_exception = None;
    cpu.block_id = u64::MAX;
    cpu.block_offset = 0;
}

/// Parks the current task (CPU snapshot + memory map) with `state`.
fn park_current(env: &mut LinuxEnv, cpu: &mut Cpu, state: ParkState) {
    let snapshot = cpu.snapshot();
    let mem = cpu.mem.take_virtual_mapping();
    let proc = std::mem::replace(&mut env.proc, Process::initial());
    env.sched.parked.push(ParkedTask {
        proc,
        cpu: snapshot,
        mem,
        state,
    });
}

/// Restores the first ready task onto the CPU. Returns false when nothing
/// is runnable.
fn schedule_next(env: &mut LinuxEnv, cpu: &mut Cpu) -> bool {
    let now = env.now_nanos(cpu);
    let index = match env.sched.find_ready(now) {
        Some(index) => index,
        None => match resolve_stall(env, cpu) {
            Some(index) => index,
            None => return false,
        },
    };
    let task = env.sched.parked.remove(index);
    // The instruction counter is global (energy, limits, deterministic
    // time); it must never rewind on a task switch.
    let icount = cpu.icount;
    cpu.mem.restore_virtual_mapping(task.mem);
    cpu.restore(&task.cpu);
    cpu.icount = icount;
    env.proc = task.proc;
    true
}

/// Parks the current task and hands the CPU to the next ready one.
fn block_and_switch(env: &mut LinuxEnv, cpu: &mut Cpu, state: ParkState, restart: bool) -> Outcome {
    prepare_resume(env, cpu, restart);
    park_current(env, cpu, state);
    if schedule_next(env, cpu) {
        Outcome::Switched
    } else {
        tracing::error!("deadlock: every task is blocked; halting");
        env.record_exit(-1);
        Outcome::Exit(VmExit::Deadlock)
    }
}

/// Terminates the current task. Threads disappear silently (after their
/// clear-child-tid futex wake); process main threads become zombies and
/// wake their parent. The root process ends the machine.
fn task_exit(env: &mut LinuxEnv, cpu: &mut Cpu, status: i32, exit_group: bool) -> Outcome {
    // pthread_join waits on this address.
    if env.proc.clear_child_tid != 0 {
        let addr = env.proc.clear_child_tid;
        let _ = write_mem(cpu, addr, &0_u32.to_le_bytes());
        env.sched.futex_wake(addr, u64::MAX);
    }

    let (pid, tgid, ppid) = (env.proc.pid, env.proc.tgid, env.proc.ppid);
    if exit_group {
        // Kill sibling threads (same thread group) that are parked.
        env.sched.parked.retain(|t| t.proc.tgid != tgid);
    }

    let group_leader = pid == tgid;
    if tgid == ROOT_PID && (exit_group || group_leader) {
        env.record_exit(status >> 8);
        tracing::debug!("root process exited with status {status:#x}");
        return Outcome::Exit(VmExit::Halt);
    }

    if group_leader || exit_group {
        env.sched.zombies.push(Zombie {
            pid: tgid,
            ppid,
            status,
        });
    }
    tracing::debug!("task {pid} exited (status {status:#x})");

    if schedule_next(env, cpu) {
        Outcome::Switched
    } else {
        tracing::error!("deadlock: last runnable task exited but the root is still parked");
        env.record_exit(-1);
        Outcome::Exit(VmExit::Deadlock)
    }
}

fn sys_clone_impl(env: &mut LinuxEnv, cpu: &mut Cpu, spec: CloneSpec) -> Outcome {
    let child_pid = env.sched.next_pid();
    let is_thread = spec.flags & CLONE_VM != 0;

    if spec.flags & CLONE_PARENT_SETTID != 0
        && spec.parent_tid != 0
        && write_mem(cpu, spec.parent_tid, &(child_pid as u32).to_le_bytes()).is_err()
    {
        return Outcome::Ret(Err(abi::EFAULT));
    }

    let mut child_proc = if is_thread {
        env.proc.thread_sibling(child_pid)
    } else {
        env.proc.fork_child(child_pid)
    };
    if spec.flags & CLONE_CHILD_CLEARTID != 0 {
        child_proc.clear_child_tid = spec.child_tid;
    }

    // Child memory: threads share the map; forks get a copy-on-write clone.
    let mut child_mem = if is_thread {
        cpu.mem.mapping.clone()
    } else {
        cpu.mem.snapshot_virtual_mapping()
    };

    // Build the child's parked CPU state: RAX = 0, resuming after the
    // syscall, with its own stack/TLS when requested.
    let parent_rax: u64 = cpu.read_var(env.regs.rax);
    let parent_sp: u64 = cpu.read_var(env.regs.rsp);
    let parent_fs: u64 = cpu.read_var(env.regs.fs_offset);
    cpu.write_var(env.regs.rax, 0_u64);
    if spec.new_sp != 0 {
        cpu.write_var(env.regs.rsp, spec.new_sp);
    }
    if spec.flags & CLONE_SETTLS != 0 {
        cpu.write_var(env.regs.fs_offset, spec.tls);
    }
    prepare_resume(env, cpu, false);
    let child_cpu = cpu.snapshot();
    cpu.write_var(env.regs.rax, parent_rax);
    cpu.write_var(env.regs.rsp, parent_sp);
    cpu.write_var(env.regs.fs_offset, parent_fs);

    if spec.flags & CLONE_CHILD_SETTID != 0 && spec.child_tid != 0 {
        let tid_bytes = (child_pid as u32).to_le_bytes();
        if is_thread {
            // Shared address space: write directly.
            let _ = write_mem(cpu, spec.child_tid, &tid_bytes);
        } else {
            // Write into the child's copy-on-write map.
            let parent_map = cpu.mem.take_virtual_mapping();
            cpu.mem.restore_virtual_mapping(child_mem);
            let _ = write_mem(cpu, spec.child_tid, &tid_bytes);
            child_mem = cpu.mem.take_virtual_mapping();
            cpu.mem.restore_virtual_mapping(parent_map);
        }
    }

    // Linux-like ordering: the parent keeps running; the child is parked
    // ready. (With copy-on-write memory this is safe for vfork too.)
    env.sched.parked.push(ParkedTask {
        proc: child_proc,
        cpu: child_cpu,
        mem: child_mem,
        state: ParkState::Ready,
    });
    tracing::debug!(
        "spawned {} {child_pid} from {}",
        if is_thread { "thread" } else { "process" },
        env.proc.tgid,
    );
    Outcome::Ret(Ok(child_pid))
}

/// Reads a NUL-terminated array of string pointers (argv/envp layout).
fn read_string_vec(cpu: &mut Cpu, mut ptr: u64) -> Result<Vec<Vec<u8>>, u64> {
    let mut out = Vec::new();
    if ptr == 0 {
        return Ok(out);
    }
    while out.len() < 4096 {
        let entry = read_mem(cpu, ptr, 8)?;
        let addr = u64::from_le_bytes(entry.try_into().expect("read_mem length"));
        if addr == 0 {
            return Ok(out);
        }
        out.push(read_cstr(cpu, addr)?);
        ptr += 8;
    }
    Err(abi::E2BIG)
}

fn sys_execve(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    path_ptr: u64,
    argv_ptr: u64,
    envp_ptr: u64,
) -> Outcome {
    let (path, argv, envp) = match (|| {
        Ok::<_, u64>((
            path_arg(cpu, path_ptr)?,
            read_string_vec(cpu, argv_ptr)?,
            read_string_vec(cpu, envp_ptr)?,
        ))
    })() {
        Ok(v) => v,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };

    // Validate before the point of no return: the file must exist and be an
    // ELF we could plausibly run.
    let node = match env.vfs.resolve(env.proc.cwd, &path, true) {
        Ok(resolved) => match resolved.node {
            Some(node) => node,
            None => return Outcome::Ret(Err(abi::ENOENT)),
        },
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    match &env.vfs.node(node).kind {
        NodeKind::File(data) if data.len() >= 4 && data[..4] == *b"\x7fELF" => {}
        NodeKind::File(_) => return Outcome::Ret(Err(abi::ENOEXEC)),
        NodeKind::Dir(_) => return Outcome::Ret(Err(abi::EISDIR)),
        _ => return Outcome::Ret(Err(abi::EACCES)),
    }

    // Point of no return: replace the process image.
    env.proc.argv = argv;
    env.proc.envp = envp;
    env.proc.sigactions.clear();
    env.proc.fds.borrow_mut().close_cloexec();

    // The instruction counter must survive the CPU reset inside the loader.
    let icount = cpu.icount;
    let result = env.start_image(cpu, &path);
    cpu.icount = icount;

    match result {
        Ok(()) => {
            // Fresh registers; enter the new image at its entry point.
            let entry = cpu.read_pc();
            cpu.exception = Exception::new(ExceptionCode::ExternalAddr, entry);
            cpu.pending_exception = None;
            cpu.block_id = u64::MAX;
            cpu.block_offset = 0;
            tracing::debug!("pid {} execve {}", env.proc.pid, path.escape_ascii());
            Outcome::Switched
        }
        Err(e) => {
            // The old image is already gone; the process cannot continue.
            tracing::error!("execve failed after commit: {e}");
            task_exit(env, cpu, encode_exit_status(127), true)
        }
    }
}

fn sys_wait4(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    pid: u64,
    status_ptr: u64,
    options: u64,
) -> Outcome {
    let filter = pid as u32 as i32 as i64;
    if filter == 0 || filter < -1 {
        // Process groups are not modeled; treat as "any child".
    }
    let filter = if filter > 0 { filter } else { -1 };

    if let Some(zombie) = env.sched.take_zombie(env.proc.tgid, filter) {
        if status_ptr != 0 {
            if let Err(errno) = write_mem(cpu, status_ptr, &zombie.status.to_le_bytes()) {
                return Outcome::Ret(Err(errno));
            }
        }
        return Outcome::Ret(Ok(zombie.pid));
    }
    if !env.sched.has_child(env.proc.tgid, filter) {
        return Outcome::Ret(Err(abi::ECHILD));
    }
    if options & WNOHANG != 0 {
        return Outcome::Ret(Ok(0));
    }
    block_and_switch(env, cpu, ParkState::WaitChild { pid: filter }, true)
}

fn sys_pipe(env: &mut LinuxEnv, cpu: &mut Cpu, fds_ptr: u64, flags: u64) -> SysResult {
    use crate::fd::PipeInner;

    let inner: crate::fd::PipeRef = std::rc::Rc::new(std::cell::RefCell::new(PipeInner {
        data: Default::default(),
        readers: 1,
        writers: 1,
    }));
    let cloexec = flags & abi::O_CLOEXEC != 0;
    let make = |write_end: bool| FdEntry {
        desc: std::rc::Rc::new(std::cell::RefCell::new(Description {
            backing: Backing::Pipe {
                inner: std::rc::Rc::clone(&inner),
                write_end,
            },
            offset: 0,
            flags: if write_end {
                abi::O_WRONLY
            } else {
                abi::O_RDONLY
            } | (flags & abi::O_NONBLOCK),
        })),
        cloexec,
    };
    let read_fd = env.proc.fds.borrow_mut().insert(make(false))?;
    let write_fd = env.proc.fds.borrow_mut().insert(make(true))?;

    let mut buf = [0_u8; 8];
    buf[..4].copy_from_slice(&(read_fd as u32).to_le_bytes());
    buf[4..].copy_from_slice(&(write_fd as u32).to_le_bytes());
    if let Err(errno) = write_mem(cpu, fds_ptr, &buf) {
        let mut fds = env.proc.fds.borrow_mut();
        let _ = fds.close(read_fd);
        let _ = fds.close(write_fd);
        return Err(errno);
    }
    Ok(0)
}

/// `read` with support for every blocking-capable backing: pipes,
/// socketpairs, eventfd, timerfd, and network sockets. Blocks with restart
/// semantics when nothing is available.
fn outcome_read(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64, count: u64) -> Outcome {
    use crate::proc::Watch;

    let desc = match env.proc.fds.borrow().get(fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    enum Kind {
        Plain,
        Pipe(crate::fd::PipeRef),
        Event(crate::fd::EventFdRef),
        Timer(crate::fd::TimerFdRef),
        Net(crate::fd::NetRef),
    }
    let (kind, nonblock) = {
        let desc = desc.borrow();
        if !desc.readable() {
            return Outcome::Ret(Err(abi::EBADF));
        }
        let nonblock = desc.flags & abi::O_NONBLOCK != 0;
        let kind = match &desc.backing {
            Backing::Pipe {
                inner,
                write_end: false,
            } => Kind::Pipe(std::rc::Rc::clone(inner)),
            Backing::Pipe { .. } => return Outcome::Ret(Err(abi::EBADF)),
            Backing::SocketPair { rx, .. } => Kind::Pipe(std::rc::Rc::clone(rx)),
            Backing::EventFd(event) => Kind::Event(std::rc::Rc::clone(event)),
            Backing::TimerFd(timer) => Kind::Timer(std::rc::Rc::clone(timer)),
            Backing::Net(socket) => Kind::Net(std::rc::Rc::clone(socket)),
            Backing::Epoll(_) => return Outcome::Ret(Err(abi::EINVAL)),
            _ => Kind::Plain,
        };
        (kind, nonblock)
    };

    let would_block = |env: &mut LinuxEnv, cpu: &mut Cpu, watch: Watch| -> Outcome {
        if nonblock {
            return Outcome::Ret(Err(abi::EAGAIN));
        }
        block_and_switch(
            env,
            cpu,
            ParkState::Waiting {
                watches: vec![watch],
                deadline: None,
            },
            true,
        )
    };

    match kind {
        Kind::Plain => Outcome::Ret(sys_read(env, cpu, fd, buf, count)),
        Kind::Pipe(pipe) => {
            let chunk: Vec<u8> = {
                let mut inner = pipe.borrow_mut();
                if inner.data.is_empty() {
                    if inner.writers == 0 {
                        return Outcome::Ret(Ok(0)); // EOF
                    }
                    drop(inner);
                    return would_block(env, cpu, Watch::PipeReadable(pipe));
                }
                let take = (count as usize).min(inner.data.len()).min(0x40_0000);
                inner.data.drain(..take).collect()
            };
            match write_mem(cpu, buf, &chunk) {
                Ok(()) => Outcome::Ret(Ok(chunk.len() as u64)),
                Err(errno) => Outcome::Ret(Err(errno)),
            }
        }
        Kind::Event(event) => {
            if count < 8 {
                return Outcome::Ret(Err(abi::EINVAL));
            }
            let value = {
                let mut inner = event.borrow_mut();
                if inner.count == 0 {
                    drop(inner);
                    return would_block(env, cpu, Watch::Event(event));
                }
                if inner.semaphore {
                    inner.count -= 1;
                    1_u64
                } else {
                    std::mem::take(&mut inner.count)
                }
            };
            match write_mem(cpu, buf, &value.to_le_bytes()) {
                Ok(()) => Outcome::Ret(Ok(8)),
                Err(errno) => Outcome::Ret(Err(errno)),
            }
        }
        Kind::Timer(timer) => {
            if count < 8 {
                return Outcome::Ret(Err(abi::EINVAL));
            }
            let now = env.now_nanos(cpu);
            let expirations = {
                let mut inner = timer.borrow_mut();
                match inner.next_expiry {
                    Some(expiry) if now >= expiry => {
                        match (now - expiry).checked_div(inner.interval) {
                            Some(periods) => {
                                let n = 1 + periods;
                                inner.next_expiry = Some(expiry + n * inner.interval);
                                n
                            }
                            None => {
                                inner.next_expiry = None;
                                1
                            }
                        }
                    }
                    _ => {
                        drop(inner);
                        return would_block(env, cpu, Watch::Timer(timer));
                    }
                }
            };
            match write_mem(cpu, buf, &expirations.to_le_bytes()) {
                Ok(()) => Outcome::Ret(Ok(8)),
                Err(errno) => Outcome::Ret(Err(errno)),
            }
        }
        Kind::Net(socket) => {
            let result = {
                let inner = socket.borrow();
                let Some(handle) = inner.handle else {
                    return Outcome::Ret(Err(abi::ENOTCONN));
                };
                match inner.kind {
                    crate::fd::SocketKind::Tcp => {
                        inner.broker.borrow_mut().tcp_recv(handle, count as usize)
                    }
                    crate::fd::SocketKind::Udp => {
                        match inner
                            .broker
                            .borrow_mut()
                            .udp_recv_from(handle, count as usize)
                        {
                            Ok(Some((bytes, _))) => Ok(crate::net::RecvOutcome::Data(bytes)),
                            Ok(None) => Ok(crate::net::RecvOutcome::WouldBlock),
                            Err(errno) => Err(errno),
                        }
                    }
                }
            };
            match result {
                Ok(crate::net::RecvOutcome::Data(bytes)) => match write_mem(cpu, buf, &bytes) {
                    Ok(()) => Outcome::Ret(Ok(bytes.len() as u64)),
                    Err(errno) => Outcome::Ret(Err(errno)),
                },
                Ok(crate::net::RecvOutcome::Closed) => Outcome::Ret(Ok(0)),
                Ok(crate::net::RecvOutcome::WouldBlock) => {
                    would_block(env, cpu, Watch::NetReadable(socket))
                }
                Err(errno) => Outcome::Ret(Err(errno)),
            }
        }
    }
}

/// `write` counterpart of [`outcome_read`].
fn outcome_write(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64, count: u64) -> Outcome {
    use crate::proc::Watch;

    let desc = match env.proc.fds.borrow().get(fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    enum Kind {
        Plain,
        Pipe(crate::fd::PipeRef),
        Event(crate::fd::EventFdRef),
        Net(crate::fd::NetRef),
    }
    let (kind, nonblock) = {
        let desc = desc.borrow();
        if !desc.writable() {
            return Outcome::Ret(Err(abi::EBADF));
        }
        let nonblock = desc.flags & abi::O_NONBLOCK != 0;
        let kind = match &desc.backing {
            Backing::Pipe {
                inner,
                write_end: true,
            } => Kind::Pipe(std::rc::Rc::clone(inner)),
            Backing::Pipe { .. } => return Outcome::Ret(Err(abi::EBADF)),
            Backing::SocketPair { tx, .. } => Kind::Pipe(std::rc::Rc::clone(tx)),
            Backing::EventFd(event) => Kind::Event(std::rc::Rc::clone(event)),
            Backing::TimerFd(_) | Backing::Epoll(_) => return Outcome::Ret(Err(abi::EINVAL)),
            Backing::Net(socket) => Kind::Net(std::rc::Rc::clone(socket)),
            _ => Kind::Plain,
        };
        (kind, nonblock)
    };

    match kind {
        Kind::Plain => Outcome::Ret(sys_write(env, cpu, fd, buf, count)),
        Kind::Pipe(pipe) => {
            let room = {
                let inner = pipe.borrow();
                if inner.readers == 0 {
                    // Signal delivery is not modeled; report the error.
                    return Outcome::Ret(Err(abi::EPIPE));
                }
                crate::PIPE_CAPACITY.saturating_sub(inner.data.len())
            };
            if room == 0 {
                if nonblock {
                    return Outcome::Ret(Err(abi::EAGAIN));
                }
                return block_and_switch(
                    env,
                    cpu,
                    ParkState::Waiting {
                        watches: vec![Watch::PipeWritable(pipe)],
                        deadline: None,
                    },
                    true,
                );
            }
            let take = (count as usize).min(room).min(0x40_0000);
            let bytes = match read_mem(cpu, buf, take) {
                Ok(bytes) => bytes,
                Err(errno) => return Outcome::Ret(Err(errno)),
            };
            pipe.borrow_mut().data.extend(bytes.iter().copied());
            Outcome::Ret(Ok(take as u64))
        }
        Kind::Event(event) => {
            if count < 8 {
                return Outcome::Ret(Err(abi::EINVAL));
            }
            let bytes = match read_mem(cpu, buf, 8) {
                Ok(bytes) => bytes,
                Err(errno) => return Outcome::Ret(Err(errno)),
            };
            let value = u64::from_le_bytes(bytes.try_into().expect("read_mem length"));
            let mut inner = event.borrow_mut();
            inner.count = inner.count.saturating_add(value);
            Outcome::Ret(Ok(8))
        }
        Kind::Net(socket) => {
            let bytes = match read_mem(cpu, buf, (count as usize).min(0x40_0000)) {
                Ok(bytes) => bytes,
                Err(errno) => return Outcome::Ret(Err(errno)),
            };
            let inner = socket.borrow();
            let Some(handle) = inner.handle else {
                return Outcome::Ret(Err(abi::ENOTCONN));
            };
            let result = match (inner.kind, inner.peer) {
                (crate::fd::SocketKind::Tcp, _) => {
                    inner.broker.borrow_mut().tcp_send(handle, &bytes)
                }
                (crate::fd::SocketKind::Udp, Some(peer)) => {
                    inner.broker.borrow_mut().udp_send_to(handle, peer, &bytes)
                }
                (crate::fd::SocketKind::Udp, None) => Err(abi::EDESTADDRREQ),
            };
            Outcome::Ret(result.map(|n| n as u64))
        }
    }
}

fn sys_futex(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr: u64,
    op: u64,
    val: u64,
    _mask: u64,
) -> Outcome {
    const FUTEX_CMD_MASK: u64 = 0x7f; // strips PRIVATE / CLOCK_REALTIME bits
    match op & FUTEX_CMD_MASK {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let current = match read_mem(cpu, addr, 4) {
                Ok(bytes) => u32::from_le_bytes(bytes.try_into().expect("read_mem length")),
                Err(errno) => return Outcome::Ret(Err(errno)),
            };
            if current != val as u32 {
                return Outcome::Ret(Err(abi::EAGAIN));
            }
            // Timeouts are ignored: time only advances with executed
            // instructions, so a timed wait either wakes or deadlocks.
            block_and_switch(env, cpu, ParkState::Futex { addr, woken: false }, true)
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => Outcome::Ret(Ok(env.sched.futex_wake(addr, val))),
        cmd => {
            tracing::warn!("unimplemented futex op {cmd}");
            Outcome::Ret(Err(abi::ENOSYS))
        }
    }
}

fn sys_yield(env: &mut LinuxEnv, cpu: &mut Cpu) -> Outcome {
    if env.sched.find_ready(env.now_nanos(cpu)).is_none() {
        return Outcome::Ret(Ok(0));
    }
    cpu.write_var(env.regs.rax, 0_u64);
    block_and_switch(env, cpu, ParkState::Ready, false)
}

/// `kill`/`tgkill`. Self-directed fatal signals terminate the caller
/// (handler delivery is not modeled); signals to parked tasks terminate
/// them at once with 128 + signal semantics.
fn sys_kill(env: &mut LinuxEnv, cpu: &mut Cpu, target: u64, signal: u64) -> Outcome {
    let target = target as u32 as i32 as i64;
    if signal == 0 {
        // Existence probe.
        let exists = target == env.proc.tgid as i64
            || env
                .sched
                .parked
                .iter()
                .any(|t| t.proc.tgid as i64 == target);
        return Outcome::Ret(if exists { Ok(0) } else { Err(abi::ESRCH) });
    }
    if target == env.proc.tgid as i64 || target == env.proc.pid as i64 {
        tracing::warn!("task killed itself with signal {signal} (no handler delivery)");
        return task_exit(env, cpu, 128 + signal as i32, true);
    }
    if target <= 0 {
        // Group signals are not modeled.
        return Outcome::Ret(Err(abi::ESRCH));
    }

    let target = target as u64;
    let mut found = false;
    let mut index = 0;
    while index < env.sched.parked.len() {
        if env.sched.parked[index].proc.tgid == target {
            let task = env.sched.parked.remove(index);
            found = true;
            if task.proc.pid == task.proc.tgid {
                env.sched.zombies.push(Zombie {
                    pid: task.proc.tgid,
                    ppid: task.proc.ppid,
                    status: 128 + signal as i32,
                });
            }
        } else {
            index += 1;
        }
    }
    Outcome::Ret(if found { Ok(0) } else { Err(abi::ESRCH) })
}

/// `readv`/`writev` via the pipe-aware single-buffer path: exactly one
/// non-empty segment is processed per call (a short transfer, which POSIX
/// permits; callers loop). This keeps blocking restarts idempotent.
fn outcome_vectored(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    fd: u64,
    iov: u64,
    iovcnt: u64,
    write: bool,
) -> Outcome {
    let entries = match iter_iov(cpu, iov, iovcnt) {
        Ok(entries) => entries,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    for (base, len) in entries {
        if len == 0 {
            continue;
        }
        return if write {
            outcome_write(env, cpu, fd, base, len)
        } else {
            outcome_read(env, cpu, fd, base, len)
        };
    }
    Outcome::Ret(Ok(0))
}

// ── Event loop and networking (milestone 5) ─────────────────────────────────

use crate::fd::{EpollInner, EventFdInner, NetSocket, SocketKind, TimerFdInner};
use crate::proc::Watch;

const AF_UNIX: u64 = 1;
const AF_INET: u64 = 2;
const SOCK_TYPE_MASK: u64 = 0xff;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_NONBLOCK: u64 = 0x800;
const SOCK_CLOEXEC: u64 = 0x8_0000;

const SHUT_WR: u64 = 1;
const SHUT_RDWR: u64 = 2;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const EPOLLIN: u32 = 0x1;
const EPOLLOUT: u32 = 0x4;

/// Resolves a total stall: every task is parked and none is ready. Waits on
/// the host for network readiness, then warps the deterministic clock to
/// the earliest timer deadline. Returns the index of a task that became
/// ready, or None for a true deadlock.
fn resolve_stall(env: &mut LinuxEnv, cpu: &mut Cpu) -> Option<usize> {
    let now = env.now_nanos(cpu);
    let deadline = env.sched.earliest_deadline();

    let handles = env.sched.net_watch_handles();
    if !handles.is_empty() {
        if let Some(broker) = env.net.clone() {
            // Bound the host wait by the nearest guest deadline (nanoseconds
            // of deterministic time map to host wall time here) or a hard
            // cap that keeps a dead network from hanging the machine.
            let cap = std::time::Duration::from_secs(30);
            let timeout = match deadline {
                Some(d) if d > now => std::time::Duration::from_nanos(d - now).min(cap),
                _ => cap,
            };
            let woke = broker.borrow_mut().wait_ready(&handles, timeout);
            if woke {
                if let Some(index) = env.sched.find_ready(now) {
                    return Some(index);
                }
            } else if deadline.is_none() {
                tracing::error!(
                    "network wait timed out after {timeout:?} with no guest timer armed"
                );
                return None;
            }
        }
    }

    // Nothing external woke us: advance deterministic time to the earliest
    // deadline so timeouts and timers fire.
    let deadline = deadline?;
    if deadline > now {
        env.warp_nanos += deadline - now;
        tracing::debug!("time warp: +{} ns (idle until deadline)", deadline - now);
    }
    let now = env.now_nanos(cpu);
    env.sched.find_ready(now)
}

fn parse_sockaddr_in(cpu: &mut Cpu, addr: u64, len: u64) -> Result<std::net::SocketAddrV4, u64> {
    if len < 8 {
        return Err(abi::EINVAL);
    }
    let bytes = read_mem(cpu, addr, 8)?;
    let family = u16::from_le_bytes(bytes[..2].try_into().expect("slice length"));
    if family as u64 != AF_INET {
        return Err(abi::EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes(bytes[2..4].try_into().expect("slice length"));
    let ip = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    Ok(std::net::SocketAddrV4::new(ip, port))
}

fn write_sockaddr_in(
    cpu: &mut Cpu,
    addr_ptr: u64,
    len_ptr: u64,
    addr: std::net::SocketAddrV4,
) -> Result<(), u64> {
    if addr_ptr == 0 {
        return Ok(());
    }
    let mut out = [0_u8; 16];
    out[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    out[2..4].copy_from_slice(&addr.port().to_be_bytes());
    out[4..8].copy_from_slice(&addr.ip().octets());
    write_mem(cpu, addr_ptr, &out)?;
    if len_ptr != 0 {
        write_mem(cpu, len_ptr, &16_u32.to_le_bytes())?;
    }
    Ok(())
}

fn net_of(env: &LinuxEnv, fd: u64) -> Result<crate::fd::NetRef, u64> {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let backing = &desc.borrow().backing;
    match backing {
        Backing::Net(socket) => Ok(socket.clone()),
        _ => Err(abi::ENOTSOCK),
    }
}

fn install_fd(env: &mut LinuxEnv, backing: Backing, flags: u64, cloexec: bool) -> SysResult {
    env.proc.fds.borrow_mut().insert(FdEntry {
        desc: std::rc::Rc::new(std::cell::RefCell::new(Description {
            backing,
            offset: 0,
            flags,
        })),
        cloexec,
    })
}

fn sys_socket(env: &mut LinuxEnv, domain: u64, sock_type: u64, _protocol: u64) -> SysResult {
    let Some(broker) = env.net.clone() else {
        tracing::warn!("socket: network is denied (no broker attached)");
        return Err(abi::EAFNOSUPPORT);
    };
    if domain != AF_INET {
        tracing::warn!("socket: unsupported domain {domain}");
        return Err(abi::EAFNOSUPPORT);
    }
    let kind = match sock_type & SOCK_TYPE_MASK {
        SOCK_STREAM => SocketKind::Tcp,
        SOCK_DGRAM => SocketKind::Udp,
        other => {
            tracing::warn!("socket: unsupported type {other}");
            return Err(abi::EPROTONOSUPPORT);
        }
    };
    let socket = NetSocket {
        broker,
        kind,
        handle: None,
        peer: None,
    };
    let flags = abi::O_RDWR | ((sock_type & SOCK_NONBLOCK != 0) as u64 * abi::O_NONBLOCK);
    install_fd(
        env,
        Backing::Net(std::rc::Rc::new(std::cell::RefCell::new(socket))),
        flags,
        sock_type & SOCK_CLOEXEC != 0,
    )
}

fn sys_connect(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, addr: u64, len: u64) -> SysResult {
    let socket = net_of(env, fd)?;
    let target = parse_sockaddr_in(cpu, addr, len)?;
    let mut inner = socket.borrow_mut();
    match inner.kind {
        SocketKind::Tcp => {
            let handle = inner.broker.borrow_mut().tcp_connect(target)?;
            inner.handle = Some(handle);
        }
        SocketKind::Udp => {
            if inner.handle.is_none() {
                let handle = inner.broker.borrow_mut().udp_open()?;
                inner.handle = Some(handle);
            }
        }
    }
    inner.peer = Some(target);
    Ok(0)
}

fn sys_sendto(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> Outcome {
    let [fd, buf, len, _flags, addr, addrlen] = a;
    if addr == 0 {
        return outcome_write(env, cpu, fd, buf, len);
    }
    let socket = match net_of(env, fd) {
        Ok(socket) => socket,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let target = match parse_sockaddr_in(cpu, addr, addrlen) {
        Ok(target) => target,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let bytes = match read_mem(cpu, buf, (len as usize).min(0x1_0000)) {
        Ok(bytes) => bytes,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let mut inner = socket.borrow_mut();
    if inner.kind != SocketKind::Udp {
        return Outcome::Ret(Err(abi::EOPNOTSUPP));
    }
    let broker = inner.broker.clone();
    if inner.handle.is_none() {
        match broker.borrow_mut().udp_open() {
            Ok(handle) => inner.handle = Some(handle),
            Err(errno) => return Outcome::Ret(Err(errno)),
        }
    }
    let handle = inner.handle.expect("handle set above");
    let result = broker.borrow_mut().udp_send_to(handle, target, &bytes);
    Outcome::Ret(result.map(|n| n as u64))
}

fn sys_recvfrom(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> Outcome {
    let [fd, buf, len, _flags, addr, addrlen] = a;
    let socket = match net_of(env, fd) {
        Ok(socket) => socket,
        // Not a network socket: plain read (recv on a socketpair).
        Err(_) => return outcome_read(env, cpu, fd, buf, len),
    };
    let is_udp = socket.borrow().kind == SocketKind::Udp;
    if !is_udp {
        return outcome_read(env, cpu, fd, buf, len);
    }
    let received = {
        let (broker, handle) = {
            let inner = socket.borrow();
            let Some(handle) = inner.handle else {
                return Outcome::Ret(Err(abi::ENOTCONN));
            };
            (inner.broker.clone(), handle)
        };
        let result = broker.borrow_mut().udp_recv_from(handle, len as usize);
        result
    };
    match received {
        Ok(Some((bytes, from))) => {
            if let Err(errno) = write_mem(cpu, buf, &bytes) {
                return Outcome::Ret(Err(errno));
            }
            if let Err(errno) = write_sockaddr_in(cpu, addr, addrlen, from) {
                return Outcome::Ret(Err(errno));
            }
            Outcome::Ret(Ok(bytes.len() as u64))
        }
        Ok(None) => {
            let nonblock = {
                let desc = env
                    .proc
                    .fds
                    .borrow()
                    .get(fd)
                    .map(|e| e.desc.borrow().flags & abi::O_NONBLOCK != 0)
                    .unwrap_or(false);
                desc
            };
            if nonblock {
                return Outcome::Ret(Err(abi::EAGAIN));
            }
            block_and_switch(
                env,
                cpu,
                ParkState::Waiting {
                    watches: vec![Watch::NetReadable(socket)],
                    deadline: None,
                },
                true,
            )
        }
        Err(errno) => Outcome::Ret(Err(errno)),
    }
}

fn sys_shutdown(env: &mut LinuxEnv, fd: u64, how: u64) -> SysResult {
    let socket = net_of(env, fd)?;
    let inner = socket.borrow();
    if let (SocketKind::Tcp, Some(handle)) = (inner.kind, inner.handle) {
        if how == SHUT_WR || how == SHUT_RDWR {
            inner.broker.borrow_mut().tcp_shutdown_write(handle)?;
        }
    }
    Ok(0)
}

fn sys_getpeername(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, addr: u64, len: u64) -> SysResult {
    let socket = net_of(env, fd)?;
    let peer = socket.borrow().peer.ok_or(abi::ENOTCONN)?;
    write_sockaddr_in(cpu, addr, len, peer)?;
    Ok(0)
}

fn sys_getsockopt(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    let [fd, _level, optname, optval, optlen, _] = a;
    net_of(env, fd)?;
    const SO_ERROR: u64 = 4;
    if optval != 0 {
        // SO_ERROR reads back 0 (no pending error); every other option
        // also reads as a zeroed 32-bit value.
        let _ = optname == SO_ERROR;
        write_mem(cpu, optval, &[0_u8; 4])?;
        if optlen != 0 {
            write_mem(cpu, optlen, &4_u32.to_le_bytes())?;
        }
    }
    Ok(0)
}

fn sys_socketpair(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    let [domain, sock_type, _proto, sv, _, _] = a;
    if domain != AF_UNIX {
        return Err(abi::EAFNOSUPPORT);
    }
    if sock_type & SOCK_TYPE_MASK != SOCK_STREAM {
        return Err(abi::EPROTONOSUPPORT);
    }
    use crate::fd::PipeInner;
    let make_pipe = || {
        std::rc::Rc::new(std::cell::RefCell::new(PipeInner {
            data: Default::default(),
            readers: 1,
            writers: 1,
        }))
    };
    let (ab, ba) = (make_pipe(), make_pipe());
    let cloexec = sock_type & SOCK_CLOEXEC != 0;
    let fd_a = install_fd(
        env,
        Backing::SocketPair {
            rx: ba.clone(),
            tx: ab.clone(),
        },
        abi::O_RDWR,
        cloexec,
    )?;
    let fd_b = install_fd(
        env,
        Backing::SocketPair { rx: ab, tx: ba },
        abi::O_RDWR,
        cloexec,
    )?;
    let mut buf = [0_u8; 8];
    buf[..4].copy_from_slice(&(fd_a as u32).to_le_bytes());
    buf[4..].copy_from_slice(&(fd_b as u32).to_le_bytes());
    write_mem(cpu, sv, &buf)?;
    Ok(0)
}

fn sys_eventfd(env: &mut LinuxEnv, initval: u64, flags: u64) -> SysResult {
    const EFD_SEMAPHORE: u64 = 1;
    let event = EventFdInner {
        count: initval,
        semaphore: flags & EFD_SEMAPHORE != 0,
    };
    install_fd(
        env,
        Backing::EventFd(std::rc::Rc::new(std::cell::RefCell::new(event))),
        abi::O_RDWR | (flags & abi::O_NONBLOCK),
        flags & abi::O_CLOEXEC != 0,
    )
}

fn read_timespec_at(cpu: &mut Cpu, addr: u64) -> Result<u64, u64> {
    let bytes = read_mem(cpu, addr, 16)?;
    let sec = i64::from_le_bytes(bytes[..8].try_into().expect("slice length"));
    let nsec = i64::from_le_bytes(bytes[8..].try_into().expect("slice length"));
    Ok((sec.max(0) as u64) * 1_000_000_000 + nsec.max(0) as u64)
}

fn sys_timerfd_create(env: &mut LinuxEnv, _clockid: u64, flags: u64) -> SysResult {
    install_fd(
        env,
        Backing::TimerFd(std::rc::Rc::new(std::cell::RefCell::new(
            TimerFdInner::default(),
        ))),
        abi::O_RDONLY | (flags & abi::O_NONBLOCK),
        flags & abi::O_CLOEXEC != 0,
    )
}

fn timer_of(env: &LinuxEnv, fd: u64) -> Result<crate::fd::TimerFdRef, u64> {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let backing = &desc.borrow().backing;
    match backing {
        Backing::TimerFd(timer) => Ok(timer.clone()),
        _ => Err(abi::EINVAL),
    }
}

fn sys_timerfd_settime(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    const TFD_TIMER_ABSTIME: u64 = 1;
    let [fd, flags, new_value, old_value, _, _] = a;
    let timer = timer_of(env, fd)?;
    let now = env.now_nanos(cpu);

    if old_value != 0 {
        let inner = timer.borrow();
        let remaining = inner
            .next_expiry
            .map(|e| e.saturating_sub(now))
            .unwrap_or(0);
        let mut out = [0_u8; 32];
        out[..8].copy_from_slice(&((inner.interval / 1_000_000_000) as i64).to_le_bytes());
        out[8..16].copy_from_slice(&((inner.interval % 1_000_000_000) as i64).to_le_bytes());
        out[16..24].copy_from_slice(&((remaining / 1_000_000_000) as i64).to_le_bytes());
        out[24..32].copy_from_slice(&((remaining % 1_000_000_000) as i64).to_le_bytes());
        write_mem(cpu, old_value, &out)?;
    }

    let interval = read_timespec_at(cpu, new_value)?;
    let value = read_timespec_at(cpu, new_value + 16)?;
    // itimerspec = { it_interval, it_value }.
    let (interval, value) = (interval, value);
    let mut inner = timer.borrow_mut();
    if value == 0 {
        inner.next_expiry = None;
    } else {
        inner.next_expiry = Some(if flags & TFD_TIMER_ABSTIME != 0 {
            value
        } else {
            now + value
        });
    }
    inner.interval = interval;
    Ok(0)
}

fn sys_timerfd_gettime(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, curr: u64) -> SysResult {
    let timer = timer_of(env, fd)?;
    let now = env.now_nanos(cpu);
    let inner = timer.borrow();
    let remaining = inner
        .next_expiry
        .map(|e| e.saturating_sub(now))
        .unwrap_or(0);
    let mut out = [0_u8; 32];
    out[..8].copy_from_slice(&((inner.interval / 1_000_000_000) as i64).to_le_bytes());
    out[8..16].copy_from_slice(&((inner.interval % 1_000_000_000) as i64).to_le_bytes());
    out[16..24].copy_from_slice(&((remaining / 1_000_000_000) as i64).to_le_bytes());
    out[24..32].copy_from_slice(&((remaining % 1_000_000_000) as i64).to_le_bytes());
    write_mem(cpu, curr, &out)?;
    Ok(0)
}

fn epoll_of(env: &LinuxEnv, fd: u64) -> Result<crate::fd::EpollRef, u64> {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let backing = &desc.borrow().backing;
    match backing {
        Backing::Epoll(epoll) => Ok(epoll.clone()),
        _ => Err(abi::EINVAL),
    }
}

fn sys_epoll_create(env: &mut LinuxEnv, flags: u64) -> SysResult {
    install_fd(
        env,
        Backing::Epoll(std::rc::Rc::new(std::cell::RefCell::new(
            EpollInner::default(),
        ))),
        abi::O_RDWR,
        flags & abi::O_CLOEXEC != 0,
    )
}

fn sys_epoll_ctl(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    let [epfd, op, fd, event_ptr, _, _] = a;
    let epoll = epoll_of(env, epfd)?;
    // The target must exist (except for DEL of an already-closed fd).
    match op {
        EPOLL_CTL_ADD | EPOLL_CTL_MOD => {
            env.proc.fds.borrow().get(fd)?;
            let bytes = read_mem(cpu, event_ptr, 12)?;
            let events = u32::from_le_bytes(bytes[..4].try_into().expect("slice length"));
            let data = u64::from_le_bytes(bytes[4..12].try_into().expect("slice length"));
            let mut inner = epoll.borrow_mut();
            if op == EPOLL_CTL_ADD && inner.interests.contains_key(&fd) {
                return Err(abi::EEXIST);
            }
            inner.interests.insert(fd, (events, data));
            Ok(0)
        }
        EPOLL_CTL_DEL => {
            epoll
                .borrow_mut()
                .interests
                .remove(&fd)
                .ok_or(abi::ENOENT)?;
            Ok(0)
        }
        _ => Err(abi::EINVAL),
    }
}

fn sys_epoll_wait(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> Outcome {
    let [epfd, events_ptr, max_events, timeout_ms, _, _] = a;
    let epoll = match epoll_of(env, epfd) {
        Ok(epoll) => epoll,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let max_events = (max_events as usize).clamp(1, 256);
    let now = env.now_nanos(cpu);

    // Evaluate readiness for every registered fd.
    let mut ready: Vec<(u32, u64)> = Vec::new();
    let mut watches: Vec<Watch> = Vec::new();
    {
        let inner = epoll.borrow();
        let fds = env.proc.fds.borrow();
        for (&fd, &(events, data)) in inner.interests.iter() {
            let Ok(entry) = fds.get(fd) else { continue };
            let desc = entry.desc.borrow();
            let mut fired = 0_u32;
            if events & EPOLLIN != 0 {
                if desc.readable() && desc_read_ready(&desc, now) {
                    fired |= EPOLLIN;
                } else if let Some(watch) = read_watch_of(&desc) {
                    watches.push(watch);
                }
            }
            if events & EPOLLOUT != 0 && desc.writable() && desc_write_ready(&desc) {
                fired |= EPOLLOUT;
            }
            if fired != 0 && ready.len() < max_events {
                ready.push((fired, data));
            }
        }
    }

    if !ready.is_empty() {
        let mut out = Vec::with_capacity(ready.len() * 12);
        for (events, data) in &ready {
            out.extend_from_slice(&events.to_le_bytes());
            out.extend_from_slice(&data.to_le_bytes());
        }
        if let Err(errno) = write_mem(cpu, events_ptr, &out) {
            return Outcome::Ret(Err(errno));
        }
        return Outcome::Ret(Ok(ready.len() as u64));
    }

    let timeout_ms = timeout_ms as u32 as i32;
    if timeout_ms == 0 {
        return Outcome::Ret(Ok(0));
    }
    let deadline = if timeout_ms > 0 {
        Some(now + timeout_ms as u64 * 1_000_000)
    } else {
        None
    };
    block_and_switch(env, cpu, ParkState::Waiting { watches, deadline }, true)
}

/// `select`/`pselect6` over readable/writable fd sets. Evaluates
/// immediately; blocks with restart semantics when nothing is ready and
/// the timeout allows it.
fn sys_select(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6], timespec: bool) -> Outcome {
    let [nfds, readfds, writefds, exceptfds, timeout_ptr, _] = a;
    let nfds = nfds.min(1024) as usize;
    let words = nfds.div_ceil(64);
    let now = env.now_nanos(cpu);

    let read_set = |cpu: &mut Cpu, ptr: u64| -> Result<Vec<u64>, u64> {
        if ptr == 0 || words == 0 {
            return Ok(vec![0; words]);
        }
        let bytes = read_mem(cpu, ptr, words * 8)?;
        Ok(bytes
            .chunks_exact(8)
            .map(|c| u64::from_le_bytes(c.try_into().expect("chunk size")))
            .collect())
    };
    let (rset, wset) = match (read_set(cpu, readfds), read_set(cpu, writefds)) {
        (Ok(r), Ok(w)) => (r, w),
        _ => return Outcome::Ret(Err(abi::EFAULT)),
    };

    let mut r_out = vec![0_u64; words];
    let mut w_out = vec![0_u64; words];
    let mut count = 0_u64;
    let mut watches: Vec<Watch> = Vec::new();
    {
        let fds = env.proc.fds.borrow();
        for fd in 0..nfds {
            let (word, bit) = (fd / 64, 1_u64 << (fd % 64));
            let want_read = rset.get(word).is_some_and(|w| w & bit != 0);
            let want_write = wset.get(word).is_some_and(|w| w & bit != 0);
            if !want_read && !want_write {
                continue;
            }
            let Ok(entry) = fds.get(fd as u64) else {
                return Outcome::Ret(Err(abi::EBADF));
            };
            let desc = entry.desc.borrow();
            if want_read {
                if desc.readable() && desc_read_ready(&desc, now) {
                    r_out[word] |= bit;
                    count += 1;
                } else if let Some(watch) = read_watch_of(&desc) {
                    watches.push(watch);
                }
            }
            if want_write && desc.writable() && desc_write_ready(&desc) {
                w_out[word] |= bit;
                count += 1;
            }
        }
    }

    let timeout = if timeout_ptr == 0 {
        None
    } else if timespec {
        match read_timespec_at(cpu, timeout_ptr) {
            Ok(nanos) => Some(nanos),
            Err(errno) => return Outcome::Ret(Err(errno)),
        }
    } else {
        // struct timeval { sec, usec }.
        match read_mem(cpu, timeout_ptr, 16) {
            Ok(bytes) => {
                let sec = i64::from_le_bytes(bytes[..8].try_into().expect("slice length"));
                let usec = i64::from_le_bytes(bytes[8..].try_into().expect("slice length"));
                Some((sec.max(0) as u64) * 1_000_000_000 + (usec.max(0) as u64) * 1_000)
            }
            Err(errno) => return Outcome::Ret(Err(errno)),
        }
    };

    if count == 0 && timeout != Some(0) {
        let deadline = timeout.map(|t| now + t);
        return block_and_switch(env, cpu, ParkState::Waiting { watches, deadline }, true);
    }

    let write_set = |cpu: &mut Cpu, ptr: u64, set: &[u64]| -> Result<(), u64> {
        if ptr == 0 {
            return Ok(());
        }
        let bytes: Vec<u8> = set.iter().flat_map(|w| w.to_le_bytes()).collect();
        write_mem(cpu, ptr, &bytes)
    };
    if let Err(errno) = write_set(cpu, readfds, &r_out) {
        return Outcome::Ret(Err(errno));
    }
    if let Err(errno) = write_set(cpu, writefds, &w_out) {
        return Outcome::Ret(Err(errno));
    }
    if exceptfds != 0 {
        let zeros = vec![0_u8; words * 8];
        if let Err(errno) = write_mem(cpu, exceptfds, &zeros) {
            return Outcome::Ret(Err(errno));
        }
    }
    Outcome::Ret(Ok(count))
}

/// `sendfile(out, in, offset_ptr, count)`: copy from a VFS file to any
/// writable fd. Partial copies are returned (callers loop), which keeps
/// blocking restarts idempotent.
fn sys_sendfile(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> Outcome {
    let [out_fd, in_fd, offset_ptr, count, _, _] = a;

    let in_desc = match env.proc.fds.borrow().get(in_fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let (node, base_offset) = {
        let desc = in_desc.borrow();
        match &desc.backing {
            Backing::File { node } => (*node, desc.offset),
            _ => return Outcome::Ret(Err(abi::EINVAL)),
        }
    };
    let offset = if offset_ptr != 0 {
        match read_mem(cpu, offset_ptr, 8) {
            Ok(bytes) => u64::from_le_bytes(bytes.try_into().expect("read_mem length")),
            Err(errno) => return Outcome::Ret(Err(errno)),
        }
    } else {
        base_offset
    };

    let chunk: Vec<u8> = {
        let NodeKind::File(data) = &env.vfs.node(node).kind else {
            return Outcome::Ret(Err(abi::EIO));
        };
        let start = (offset as usize).min(data.len());
        let end = (start + (count as usize).min(0x4_0000)).min(data.len());
        data[start..end].to_vec()
    };
    if chunk.is_empty() {
        return Outcome::Ret(Ok(0));
    }

    // Stage through a scratch buffer in guest memory? Not needed: write
    // directly through the write path by borrowing its backing logic.
    let written = {
        let out_desc = match env.proc.fds.borrow().get(out_fd) {
            Ok(entry) => entry.desc.clone(),
            Err(errno) => return Outcome::Ret(Err(errno)),
        };
        let mut desc = out_desc.borrow_mut();
        if !desc.writable() {
            return Outcome::Ret(Err(abi::EBADF));
        }
        match &desc.backing {
            Backing::Pipe {
                inner,
                write_end: true,
            } => {
                let room = {
                    let pipe = inner.borrow();
                    if pipe.readers == 0 {
                        return Outcome::Ret(Err(abi::EPIPE));
                    }
                    crate::PIPE_CAPACITY.saturating_sub(pipe.data.len())
                };
                if room == 0 {
                    let pipe = inner.clone();
                    drop(desc);
                    return block_and_switch(
                        env,
                        cpu,
                        ParkState::Waiting {
                            watches: vec![Watch::PipeWritable(pipe)],
                            deadline: None,
                        },
                        true,
                    );
                }
                let take = chunk.len().min(room);
                inner
                    .borrow_mut()
                    .data
                    .extend(chunk[..take].iter().copied());
                take
            }
            _ => {
                let take = chunk.len();
                match write_backing(env, &mut desc, &chunk) {
                    Ok(n) => n as usize,
                    Err(errno) => return Outcome::Ret(Err(errno)),
                }
                .min(take)
            }
        }
    };

    if offset_ptr != 0 {
        let next = offset + written as u64;
        if let Err(errno) = write_mem(cpu, offset_ptr, &next.to_le_bytes()) {
            return Outcome::Ret(Err(errno));
        }
    } else {
        in_desc.borrow_mut().offset = offset + written as u64;
    }
    Outcome::Ret(Ok(written as u64))
}

/// Blocking `poll`/`ppoll`: evaluate immediately; when nothing is ready and
/// the timeout permits, park on the watch set (restart semantics re-run the
/// evaluation on wakeup). `timeout_arg` is milliseconds for poll (-1 =
/// infinite) or a timespec pointer for ppoll (0 = infinite).
fn outcome_poll(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    fds_ptr: u64,
    nfds: u64,
    timeout_arg: u64,
    is_ppoll: bool,
) -> Outcome {
    let ready = match sys_poll(env, cpu, fds_ptr, nfds) {
        Ok(ready) => ready,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let now = env.now_nanos(cpu);
    let timeout = if is_ppoll {
        if timeout_arg == 0 {
            None
        } else {
            match read_timespec_at(cpu, timeout_arg) {
                Ok(nanos) => Some(nanos),
                Err(errno) => return Outcome::Ret(Err(errno)),
            }
        }
    } else {
        let ms = timeout_arg as u32 as i32;
        if ms < 0 {
            None
        } else {
            Some(ms as u64 * 1_000_000)
        }
    };
    if ready > 0 || timeout == Some(0) {
        return Outcome::Ret(Ok(ready));
    }

    // Build the watch set from the requested events.
    const POLLIN: u16 = 0x1;
    const POLLOUT: u16 = 0x4;
    let mut watches: Vec<Watch> = Vec::new();
    let records = match read_mem(cpu, fds_ptr, nfds.min(1024) as usize * 8) {
        Ok(records) => records,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    {
        let fds = env.proc.fds.borrow();
        for record in records.chunks_exact(8) {
            let fd = i32::from_le_bytes(record[..4].try_into().expect("chunk size"));
            let events = u16::from_le_bytes(record[4..6].try_into().expect("chunk size"));
            let Ok(entry) = fds.get(fd as u32 as u64) else {
                continue;
            };
            let desc = entry.desc.borrow();
            if events & POLLIN != 0 {
                if let Some(watch) = read_watch_of(&desc) {
                    watches.push(watch);
                }
            }
            if events & POLLOUT != 0 {
                if let Backing::Pipe {
                    inner,
                    write_end: true,
                }
                | Backing::SocketPair { tx: inner, .. } = &desc.backing
                {
                    watches.push(Watch::PipeWritable(inner.clone()));
                }
            }
        }
    }
    let deadline = timeout.map(|t| now + t);
    tracing::debug!(
        "[{}] poll parks: {} watch(es) from {} fd record(s)",
        env.proc.pid,
        watches.len(),
        records.len() / 8
    );
    block_and_switch(env, cpu, ParkState::Waiting { watches, deadline }, true)
}

/// `nanosleep`: sleeping advances the deterministic clock by the requested
/// duration (there is nothing else to wait for).
fn sys_nanosleep(env: &mut LinuxEnv, cpu: &mut Cpu, req: u64) -> SysResult {
    if req != 0 {
        let duration = read_timespec_at(cpu, req)?;
        env.warp_nanos += duration;
    }
    Ok(0)
}

/// `utimensat`: applies the requested modification time to the node.
fn sys_utimensat(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    const UTIME_NOW: i64 = 0x3fff_ffff;
    const UTIME_OMIT: i64 = 0x3fff_fffe;
    let [dirfd, path_ptr, times_ptr, flags, _, _] = a;

    let node = if path_ptr == 0 {
        // futimens form: dirfd is a real fd.
        match env.proc.fds.borrow().get(dirfd)?.desc.borrow().backing {
            Backing::File { node } | Backing::Dir { node, .. } => node,
            _ => return Ok(0), // non-VFS objects have no timestamps
        }
    } else {
        let path = path_arg(cpu, path_ptr)?;
        let base = dir_of(env, dirfd)?;
        let follow = flags & abi::AT_SYMLINK_NOFOLLOW == 0;
        env.vfs
            .resolve(base, &path, follow)?
            .node
            .ok_or(abi::ENOENT)?
    };

    let (now_sec, _) = env.now(cpu);
    // times = [atime, mtime]; only mtime is stored.
    let mtime = if times_ptr == 0 {
        now_sec
    } else {
        let bytes = read_mem(cpu, times_ptr + 16, 16)?;
        let sec = i64::from_le_bytes(bytes[..8].try_into().expect("slice length"));
        let nsec = i64::from_le_bytes(bytes[8..].try_into().expect("slice length"));
        match nsec {
            UTIME_OMIT => return Ok(0),
            UTIME_NOW => now_sec,
            _ => sec,
        }
    };
    env.vfs.node_mut(node).mtime_sec = mtime;
    Ok(0)
}
