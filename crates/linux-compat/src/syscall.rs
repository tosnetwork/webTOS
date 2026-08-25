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

    if nr == abi::SYS_EXIT || nr == abi::SYS_EXIT_GROUP {
        env.record_exit(a0 as i32);
        tracing::debug!("guest exited with code {}", a0 as i32);
        return Some(VmExit::Halt);
    }

    // A fatal signal the process sends to itself (abort(), raise())
    // terminates it, kernel-style, with 128 + signal. Handler delivery is
    // not implemented, so termination is the honest outcome either way.
    if nr == abi::SYS_KILL || nr == abi::SYS_TGKILL {
        let (pid, signal) = if nr == abi::SYS_KILL {
            (a0, a1)
        } else {
            (a0, a2)
        };
        if pid as u32 as i32 == PID as i32 && signal != 0 {
            tracing::warn!("guest killed itself with signal {signal} (no handler delivery)");
            env.record_exit(128 + signal as i32);
            return Some(VmExit::Halt);
        }
    }

    let result = dispatch(env, cpu, nr, [a0, a1, a2, a3, a4, a5]);
    let value = match result {
        Ok(v) => v,
        Err(errno) => neg(errno),
    };
    tracing::trace!(
        "[{}] syscall {nr}({a0:#x}, {a1:#x}, {a2:#x}) = {value:#x}",
        cpu.icount()
    );
    cpu.write_var(env.regs.rax, value);

    // Resume at the instruction after `syscall`.
    let next_pc: u64 = cpu.read_var(cpu.arch.reg_next_pc);
    cpu.exception = Exception::new(ExceptionCode::ExternalAddr, next_pc);
    None
}

fn dispatch(env: &mut LinuxEnv, cpu: &mut Cpu, nr: u64, a: [u64; 6]) -> SysResult {
    match nr {
        abi::SYS_READ => sys_read(env, cpu, a[0], a[1], a[2]),
        abi::SYS_WRITE => sys_write(env, cpu, a[0], a[1], a[2]),
        abi::SYS_READV => sys_readv(env, cpu, a[0], a[1], a[2]),
        abi::SYS_WRITEV => sys_writev(env, cpu, a[0], a[1], a[2]),
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
        abi::SYS_CLOSE => env.fds.close(a[0]).map(|_| 0),
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
            let old = env.umask;
            env.umask = (a[0] as u32) & 0o777;
            Ok(old as u64)
        }
        abi::SYS_DUP => sys_dup(env, a[0], 0, false),
        abi::SYS_DUP2 => sys_dup2(env, a[0], a[1]),
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

        abi::SYS_GETPID | abi::SYS_GETTID | abi::SYS_GETPGRP => Ok(PID),
        abi::SYS_GETPGID => Ok(PID),
        abi::SYS_GETPPID => Ok(1),
        abi::SYS_GETUID | abi::SYS_GETGID | abi::SYS_GETEUID | abi::SYS_GETEGID => Ok(0),
        abi::SYS_GETGROUPS => Ok(0),
        abi::SYS_SETSID => Ok(PID),
        abi::SYS_SET_TID_ADDRESS => Ok(PID),
        abi::SYS_PRLIMIT64 => sys_prlimit64(cpu, a[2], a[3]),
        abi::SYS_SETRLIMIT => Ok(0),

        // Single-process boundary (milestone 4 work): report honestly.
        abi::SYS_FORK | abi::SYS_VFORK | abi::SYS_CLONE => {
            tracing::warn!("process creation is not supported yet (milestone 4)");
            Err(abi::ENOSYS)
        }
        abi::SYS_EXECVE => {
            tracing::warn!("execve is not supported yet (milestone 4)");
            Err(abi::ENOSYS)
        }
        abi::SYS_WAIT4 => Err(abi::ECHILD),
        abi::SYS_PIPE | abi::SYS_PIPE2 => {
            tracing::warn!("pipes are not supported yet (milestone 4)");
            Err(abi::ENOSYS)
        }
        abi::SYS_KILL | abi::SYS_TGKILL => Err(abi::ESRCH),

        abi::SYS_SET_ROBUST_LIST | abi::SYS_RSEQ | abi::SYS_FUTEX => Err(abi::ENOSYS),
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
        return Ok(env.cwd);
    }
    match env.fds.get(dirfd)?.desc.borrow().backing {
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
    }
}

fn sys_read(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64, count: u64) -> SysResult {
    let desc = env.fds.get(fd)?.desc.clone();
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
    let desc = env.fds.get(fd)?.desc.clone();
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

fn sys_writev(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, iov: u64, iovcnt: u64) -> SysResult {
    let mut total = 0_u64;
    for (base, len) in iter_iov(cpu, iov, iovcnt)? {
        if len == 0 {
            continue;
        }
        total += sys_write(env, cpu, fd, base, len)?;
    }
    Ok(total)
}

fn sys_readv(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, iov: u64, iovcnt: u64) -> SysResult {
    let mut total = 0_u64;
    for (base, len) in iter_iov(cpu, iov, iovcnt)? {
        if len == 0 {
            continue;
        }
        let n = sys_read(env, cpu, fd, base, len)?;
        total += n;
        if n < len {
            break;
        }
    }
    Ok(total)
}

fn sys_pread(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    fd: u64,
    buf: u64,
    count: u64,
    pos: u64,
) -> SysResult {
    let desc = env.fds.get(fd)?.desc.clone();
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
    let desc = env.fds.get(fd)?.desc.clone();
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
            let mode = (mode as u32) & 0o777 & !env.umask;
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
    env.fds.insert(entry)
}

fn sys_lseek(env: &mut LinuxEnv, fd: u64, offset: u64, whence: u64) -> SysResult {
    let desc = env.fds.get(fd)?.desc.clone();
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
        Backing::Std(_) => return Err(abi::ESPIPE),
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
    let desc = env.fds.get(fd)?.desc.clone();
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
    let entry = env.fds.get(fd)?;
    let desc = entry.desc.borrow();
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
        env.exe_path.clone()
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
    let mode = (mode as u32) & 0o777 & !env.umask;
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
    let resolved = env.vfs.resolve(env.cwd, &path, true)?;
    let node = resolved.node.ok_or(abi::ENOENT)?;
    if !env.vfs.is_dir(node) {
        return Err(abi::ENOTDIR);
    }
    env.cwd = node;
    Ok(0)
}

fn sys_fchdir(env: &mut LinuxEnv, fd: u64) -> SysResult {
    match env.fds.get(fd)?.desc.borrow().backing {
        Backing::Dir { node, .. } => {
            env.cwd = node;
            Ok(0)
        }
        _ => Err(abi::ENOTDIR),
    }
}

fn sys_getcwd(env: &mut LinuxEnv, cpu: &mut Cpu, buf: u64, size: u64) -> SysResult {
    let mut path = env.vfs.abs_path_of(env.cwd);
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
    let node = match env.fds.get(fd)?.desc.borrow().backing {
        Backing::File { node } | Backing::Dir { node, .. } => node,
        _ => return Ok(0),
    };
    env.vfs.node_mut(node).mode = (mode as u32) & 0o7777;
    Ok(0)
}

// ── Descriptor management ───────────────────────────────────────────────────

fn sys_dup(env: &mut LinuxEnv, fd: u64, min: u64, cloexec: bool) -> SysResult {
    let entry = env.fds.get(fd)?.clone();
    env.fds.insert_from(
        min as usize,
        FdEntry {
            desc: entry.desc,
            cloexec,
        },
    )
}

fn sys_dup2(env: &mut LinuxEnv, fd: u64, new_fd: u64) -> SysResult {
    let entry = env.fds.get(fd)?.clone();
    if fd == new_fd {
        return Ok(new_fd);
    }
    env.fds.insert_at(
        new_fd,
        FdEntry {
            desc: entry.desc,
            cloexec: false,
        },
    )
}

fn sys_fcntl(env: &mut LinuxEnv, fd: u64, cmd: u64, arg: u64) -> SysResult {
    match cmd {
        abi::F_DUPFD => sys_dup(env, fd, arg, false),
        abi::F_DUPFD_CLOEXEC => sys_dup(env, fd, arg, true),
        abi::F_GETFD => Ok(if env.fds.get(fd)?.cloexec {
            abi::FD_CLOEXEC
        } else {
            0
        }),
        abi::F_SETFD => {
            env.fds.get_mut(fd)?.cloexec = arg & abi::FD_CLOEXEC != 0;
            Ok(0)
        }
        abi::F_GETFL => Ok(env.fds.get(fd)?.desc.borrow().flags),
        abi::F_SETFL => {
            let desc = env.fds.get(fd)?.desc.clone();
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
        env.fds.get(fd)?.desc.borrow().backing,
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
        let revents = match env.fds.get(fd as u32 as u64) {
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
        let node = match env.fds.get(fd)?.desc.borrow().backing {
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
    if addr == 0 || addr <= env.brk_end {
        return Ok(env.brk_end);
    }
    let new_end = align_up(addr, PAGE_SIZE);
    let cur_end = align_up(env.brk_end, PAGE_SIZE);
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
            return Ok(env.brk_end);
        }
    }
    env.brk_end = addr;
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
        let previous = env.sigactions.get(&signal).copied().unwrap_or_default();
        write_mem(cpu, old, &previous.0)?;
    }
    if new != 0 {
        let bytes = read_mem(cpu, new, 32)?;
        let mut action = SigAction::default();
        action.0.copy_from_slice(&bytes);
        env.sigactions.insert(signal, action);
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
        write_mem(cpu, old, &env.sigmask.to_le_bytes())?;
    }
    if new != 0 {
        let bytes = read_mem(cpu, new, 8)?;
        let mask = u64::from_le_bytes(bytes.try_into().expect("read_mem length"));
        env.sigmask = match how {
            0 => env.sigmask | mask,  // SIG_BLOCK
            1 => env.sigmask & !mask, // SIG_UNBLOCK
            2 => mask,                // SIG_SETMASK
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
