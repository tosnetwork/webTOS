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
        abi::SYS_UTIMENSAT => Ok(0),
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

        abi::SYS_MMAP => sys_mmap(env, cpu, a),
        abi::SYS_MUNMAP => match cpu.mem.unmap_memory_len(a[0], a[1]) {
            true => Ok(0),
            false => Err(abi::EINVAL),
        },
        abi::SYS_MPROTECT => sys_mprotect(cpu, a[0], a[1], a[2]),
        abi::SYS_BRK => sys_brk(env, cpu, a[0]),

        abi::SYS_POLL => sys_poll(env, cpu, a[0], a[1]),
        abi::SYS_PPOLL => sys_poll(env, cpu, a[0], a[1]),

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
        abi::SYS_NANOSLEEP | abi::SYS_CLOCK_NANOSLEEP => Ok(0),

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
        // Pipes are handled by `outcome_read` before reaching here.
        Backing::Pipe { .. } => Err(abi::EINVAL),
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
        // Pipes are handled by `outcome_write` before reaching here.
        Backing::Pipe { .. } => Err(abi::EINVAL),
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
        Backing::Std(_) | Backing::Pipe { .. } => return Err(abi::ESPIPE),
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
        Backing::Pipe { .. } => abi::Stat {
            dev: 1,
            ino: u64::MAX - 2,
            nlink: 1,
            mode: abi::S_IFIFO | 0o600,
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

/// `poll`/`ppoll`. Nothing in this environment ever blocks, so readiness is
/// reported immediately: readable/writable descriptors are ready (stdin at
/// EOF is readable — a read returns 0 without blocking), invalid
/// descriptors report POLLNVAL, and timeouts never matter.
fn sys_poll(env: &mut LinuxEnv, cpu: &mut Cpu, fds_ptr: u64, nfds: u64) -> SysResult {
    const POLLIN: u16 = 0x1;
    const POLLOUT: u16 = 0x4;
    const POLLNVAL: u16 = 0x20;

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
                if events & POLLIN != 0 && desc.readable() {
                    bits |= POLLIN;
                }
                if events & POLLOUT != 0 && desc.writable() {
                    bits |= POLLOUT;
                }
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
    let Some(index) = env.sched.find_ready() else {
        return false;
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

    // Parent: resumes after the syscall with the child pid in RAX.
    cpu.write_var(env.regs.rax, child_pid);
    prepare_resume(env, cpu, false);

    // Child memory: threads share the map; forks get a copy-on-write clone.
    let child_mem = if is_thread {
        cpu.mem.mapping.clone()
    } else {
        cpu.mem.snapshot_virtual_mapping()
    };

    park_current(env, cpu, ParkState::Ready);

    // Continue as the child.
    cpu.mem.restore_virtual_mapping(child_mem);
    env.proc = child_proc;
    if spec.new_sp != 0 {
        cpu.write_var(env.regs.rsp, spec.new_sp);
    }
    if spec.flags & CLONE_SETTLS != 0 {
        cpu.write_var(env.regs.fs_offset, spec.tls);
    }
    if spec.flags & CLONE_CHILD_SETTID != 0 && spec.child_tid != 0 {
        let _ = write_mem(cpu, spec.child_tid, &(child_pid as u32).to_le_bytes());
    }
    tracing::debug!(
        "spawned {} {child_pid} from {}",
        if is_thread { "thread" } else { "process" },
        env.proc.ppid,
    );
    Outcome::Ret(Ok(0))
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

/// `read` with pipe support: blocks (with restart) on an empty pipe that
/// still has writers.
fn outcome_read(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64, count: u64) -> Outcome {
    let desc = match env.proc.fds.borrow().get(fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let (pipe, nonblock) = {
        let desc = desc.borrow();
        if !desc.readable() {
            return Outcome::Ret(Err(abi::EBADF));
        }
        match &desc.backing {
            Backing::Pipe {
                inner,
                write_end: false,
            } => (
                Some(std::rc::Rc::clone(inner)),
                desc.flags & abi::O_NONBLOCK != 0,
            ),
            Backing::Pipe { .. } => return Outcome::Ret(Err(abi::EBADF)),
            _ => (None, false),
        }
    };
    let Some(pipe) = pipe else {
        return Outcome::Ret(sys_read(env, cpu, fd, buf, count));
    };

    let chunk: Vec<u8> = {
        let mut inner = pipe.borrow_mut();
        if inner.data.is_empty() {
            if inner.writers == 0 {
                return Outcome::Ret(Ok(0)); // EOF
            }
            if nonblock {
                return Outcome::Ret(Err(abi::EAGAIN));
            }
            drop(inner);
            return block_and_switch(env, cpu, ParkState::PipeRead { pipe }, true);
        }
        let take = (count as usize).min(inner.data.len()).min(0x40_0000);
        inner.data.drain(..take).collect()
    };
    if let Err(errno) = write_mem(cpu, buf, &chunk) {
        return Outcome::Ret(Err(errno));
    }
    Outcome::Ret(Ok(chunk.len() as u64))
}

/// `write` with pipe support: EPIPE with no readers, partial writes when
/// the buffer has some room, blocks (with restart) when it has none.
fn outcome_write(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64, count: u64) -> Outcome {
    let desc = match env.proc.fds.borrow().get(fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let (pipe, nonblock) = {
        let desc = desc.borrow();
        if !desc.writable() {
            return Outcome::Ret(Err(abi::EBADF));
        }
        match &desc.backing {
            Backing::Pipe {
                inner,
                write_end: true,
            } => (
                Some(std::rc::Rc::clone(inner)),
                desc.flags & abi::O_NONBLOCK != 0,
            ),
            Backing::Pipe { .. } => return Outcome::Ret(Err(abi::EBADF)),
            _ => (None, false),
        }
    };
    let Some(pipe) = pipe else {
        return Outcome::Ret(sys_write(env, cpu, fd, buf, count));
    };

    let room = {
        let inner = pipe.borrow();
        if inner.readers == 0 {
            // Signal delivery is not modeled; report the error directly.
            return Outcome::Ret(Err(abi::EPIPE));
        }
        crate::PIPE_CAPACITY.saturating_sub(inner.data.len())
    };
    if room == 0 {
        if nonblock {
            return Outcome::Ret(Err(abi::EAGAIN));
        }
        return block_and_switch(env, cpu, ParkState::PipeWrite { pipe }, true);
    }
    let take = (count as usize).min(room).min(0x40_0000);
    let bytes = match read_mem(cpu, buf, take) {
        Ok(bytes) => bytes,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    pipe.borrow_mut().data.extend(bytes.iter().copied());
    Outcome::Ret(Ok(take as u64))
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
    if env.sched.find_ready().is_none() {
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
