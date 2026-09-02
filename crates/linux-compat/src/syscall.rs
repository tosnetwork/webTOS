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
//
// Every host-side copy into or out of guest memory behaves like Linux's
// copy_from_user/copy_to_user: an access that lands on a manifest-backed page
// that is not yet resident fills the page first (warm), or suspends and
// restarts the whole syscall once the chunk arrives (cold). Without this, a
// kernel-side copy would silently read allocator zeros from — or be silently
// clobbered under — a page the guest itself has never touched.

/// Internal sentinel returned through the errno channel when a host-side copy
/// hit a cold manifest-backed page: [`handle`] intercepts it (before any rax
/// write or trace event) and suspends for page delivery; the replayed syscall
/// exception then restarts the handler from scratch. Never guest-visible.
pub(crate) const PAGE_IN_RESTART: u64 = 0x5041_4745; // "PAGE"

/// Makes `[addr, addr+len)` safe for a host-side copy, filling warm lazy pages
/// and suspending (via [`PAGE_IN_RESTART`]) on a cold one. The suspend replays
/// the syscall, so callers must run before the handler commits side effects —
/// which pointer reads at handler entry and result write-backs both satisfy.
fn host_touch(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr: u64,
    len: usize,
    access: crate::pager::AccessKind,
) -> Result<(), u64> {
    if len == 0 || !env.has_lazy_mappings() {
        return Ok(());
    }
    let end = addr.checked_add(len as u64).ok_or(abi::EFAULT)?;
    let mut page = addr & !(PAGE_SIZE - 1);
    while page < end {
        let Some((resident, final_perm)) = env.pager.page_state(env.proc.asid, page) else {
            page = page.saturating_add(PAGE_SIZE);
            continue;
        };
        let required = match access {
            crate::pager::AccessKind::Read => perm::READ,
            crate::pager::AccessKind::Write => perm::WRITE,
            crate::pager::AccessKind::Execute => perm::EXEC,
        };
        if final_perm & required == 0 {
            return Err(abi::EFAULT);
        }
        if !resident {
            match env.pager.resolve(&env.vfs, env.proc.asid, page, access) {
                crate::pager::FaultResolution::Ready {
                    page: resolved,
                    bytes,
                    perm: final_perm,
                } => {
                    if cpu.mem.write_bytes(resolved, &bytes, perm::NONE).is_err()
                        || cpu
                            .mem
                            .update_perm(resolved, PAGE_SIZE, final_perm)
                            .is_err()
                    {
                        return Err(abi::EFAULT);
                    }
                    env.pager.mark_resident(env.proc.asid, resolved, access);
                }
                crate::pager::FaultResolution::Missing(_) => {
                    env.page_in_wait = true;
                    cpu.pending_exception = Some(cpu.exception);
                    return Err(PAGE_IN_RESTART);
                }
                crate::pager::FaultResolution::Invalid(why) => {
                    tracing::error!("host copy page-in refused: {why}");
                    return Err(abi::EIO);
                }
                crate::pager::FaultResolution::NotLazy => {}
            }
        }
        page = page.saturating_add(PAGE_SIZE);
    }
    Ok(())
}

fn read_mem(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64, len: usize) -> Result<Vec<u8>, u64> {
    host_touch(env, cpu, addr, len, crate::pager::AccessKind::Read)?;
    let mut buf = vec![0_u8; len];
    cpu.mem
        .read_bytes(addr, &mut buf, perm::READ)
        .map_err(|_| abi::EFAULT)?;
    Ok(buf)
}

/// [`read_mem`] without the lazy-page fill — for diagnostics that must never
/// suspend, and for callers that have already touched the range.
fn read_mem_raw(cpu: &mut Cpu, addr: u64, len: usize) -> Result<Vec<u8>, u64> {
    let mut buf = vec![0_u8; len];
    cpu.mem
        .read_bytes(addr, &mut buf, perm::NONE)
        .map_err(|_| abi::EFAULT)?;
    Ok(buf)
}

fn write_mem(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64, bytes: &[u8]) -> Result<(), u64> {
    host_touch(env, cpu, addr, bytes.len(), crate::pager::AccessKind::Write)?;
    cpu.mem
        .write_bytes(addr, bytes, perm::WRITE)
        .map_err(|_| abi::EFAULT)
}

/// [`write_mem`] without the lazy-page fill (see [`read_mem_raw`]).
fn write_mem_raw(cpu: &mut Cpu, addr: u64, bytes: &[u8]) -> Result<(), u64> {
    cpu.mem
        .write_bytes(addr, bytes, perm::NONE)
        .map_err(|_| abi::EFAULT)
}

fn read_cstr(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64) -> Result<Vec<u8>, u64> {
    read_cstr_limit(env, cpu, addr, PATH_MAX)
}

/// [`read_cstr`] without the lazy-page fill — diagnostics only.
fn read_cstr_raw(cpu: &mut Cpu, addr: u64) -> Result<Vec<u8>, u64> {
    let mut out = Vec::new();
    let mut chunk = [0_u8; 64];
    let mut cursor = addr;
    while out.len() < PATH_MAX {
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

/// Like [`read_cstr`] with an explicit length cap: argv/envp strings may
/// legally be far longer than a path (the kernel allows 128 KiB each).
fn read_cstr_limit(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr: u64,
    max: usize,
) -> Result<Vec<u8>, u64> {
    let mut out = Vec::new();
    let mut chunk = [0_u8; 64];
    let mut cursor = addr;
    while out.len() < max {
        // Never read past the current page: the string may end just before
        // an unmapped page and a fixed-size chunk read would fault.
        let to_page_end = (PAGE_SIZE - (cursor & (PAGE_SIZE - 1))) as usize;
        let take = 64.min(max - out.len()).min(to_page_end);
        host_touch(env, cpu, cursor, take, crate::pager::AccessKind::Read)?;
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
    env.record_syscall(nr, cpu.icount());
    // Host-only diagnostic for resolving a syscall wrapper back to the exact
    // guest ELF mapping.  This is deliberately opt-in: it is useful when a
    // dynamically linked workload has several libc wrappers for one syscall,
    // while keeping the normal runner and browser surface silent.
    let trace_ip = std::env::var_os("SYSCALL_IP_TRACE").is_some()
        && std::env::var("SYSCALL_IP_TRACE_NR")
            .ok()
            .is_none_or(|numbers| {
                numbers
                    .split(',')
                    .filter_map(|value| value.trim().parse::<u64>().ok())
                    .any(|wanted| wanted == nr)
            });
    if trace_ip {
        eprintln!(
            "[syscall-ip] pid={} ic={} rip={:#x} nr={nr} args=({a0:#x},{a1:#x},{a2:#x},{a3:#x},{a4:#x},{a5:#x})",
            env.proc.pid,
            cpu.icount(),
            cpu.read_pc(),
        );
    }
    // Opt-in result tracing complements SYSCALL_IP_TRACE when diagnosing a
    // guest runtime's feature probe. It is deliberately independent from
    // `tracing` so a user can inspect a small syscall set without emitting a
    // multi-gigabyte instruction/runtime trace. The value is a comma-separated
    // list of syscall numbers, e.g. `41,42,47,51`.
    let trace_result = std::env::var("SYSCALL_RESULT_TRACE_NR")
        .ok()
        .is_some_and(|numbers| {
            numbers
                .split(',')
                .filter_map(|value| value.trim().parse::<u64>().ok())
                .any(|wanted| wanted == nr)
        });
    let trace_entry = env.trace.is_some().then(|| (cpu.icount(), env.proc.pid));

    // A signal whose disposition is the default action and whose default is
    // to terminate kills the task here, before the syscall runs. This is the
    // boundary the interpreter reaches after the scheduler wakes a task that
    // a terminal interrupt made runnable, so `^C` on a program blocked in
    // `read` or `nanosleep` ends it. A task spinning in a compute loop that
    // issues no syscalls is not interrupted; killing that needs a check on
    // the execution path rather than the kernel entry.
    match pending_signal_action(env) {
        SignalExitAction::Terminate(sig) => {
            tracing::debug!("[{}] killed by signal {sig}", env.proc.pid);
            return match task_exit(env, cpu, sig as i32, true) {
                Outcome::Exit(exit) => Some(exit),
                _ => None,
            };
        }
        // A job-control stop taken here re-executes the interrupted syscall
        // when SIGCONT lifts it, which is the restart a blocking read wants.
        SignalExitAction::Stop(sig) => {
            return match stop_thread_group(env, cpu, sig, true) {
                Outcome::Exit(exit) => Some(exit),
                _ => None,
            };
        }
        _ => {}
    }

    match dispatch(env, cpu, nr, [a0, a1, a2, a3, a4, a5]) {
        // A host-side copy hit a cold manifest-backed page: the handler bailed
        // out through the errno channel before committing a result. Suspend for
        // delivery; the replayed syscall exception restarts the handler. No rax
        // write and no trace event — the retried attempt emits the real ones.
        Outcome::Ret(Err(PAGE_IN_RESTART)) => Some(VmExit::Interrupted),
        Outcome::Ret(result) => {
            if trace_result {
                match &result {
                    Ok(value) => eprintln!(
                        "[syscall-result] pid={} ic={} nr={nr} -> {value:#x}",
                        env.proc.pid,
                        cpu.icount()
                    ),
                    Err(errno) => eprintln!(
                        "[syscall-result] pid={} ic={} nr={nr} -> -{errno}",
                        env.proc.pid,
                        cpu.icount()
                    ),
                }
            }
            let value = match result {
                Ok(v) => v,
                Err(errno) => {
                    if std::env::var_os("SYSCALL_ERR_TRACE").is_some() {
                        let path = match nr {
                            2 | abi::SYS_READLINK => read_cstr_raw(cpu, a0).ok(),
                            257 | 262 | abi::SYS_STATX | abi::SYS_READLINKAT => {
                                read_cstr_raw(cpu, a1).ok()
                            }
                            _ => None,
                        }
                        .map(|p| format!(" path={}", p.escape_ascii()))
                        .unwrap_or_default();
                        eprintln!(
                            "[syscall-err] pid={} nr={nr}({a0:#x},{a1:#x},{a2:#x}) -> -{errno}{path}",
                            env.proc.pid
                        );
                    }
                    neg(errno)
                }
            };
            tracing::trace!(
                "[{}:{}] syscall {nr}({a0:#x}, {a1:#x}, {a2:#x}) = {value:#x}",
                env.proc.pid,
                cpu.icount()
            );
            cpu.write_var(env.regs.rax, value);
            if let Some((icount, pid)) = trace_entry {
                env.trace_event(crate::trace::Event::Syscall {
                    icount,
                    pid,
                    nr,
                    args: [a0, a1, a2, a3, a4, a5],
                    ret: crate::trace::SyscallResult::Value(value),
                });
            }
            // Resume at the instruction after `syscall`.
            let next_pc: u64 = cpu.read_var(cpu.arch.reg_next_pc);
            cpu.exception = Exception::new(ExceptionCode::ExternalAddr, next_pc);
            None
        }
        // The CPU already holds the full state of whichever task runs next
        // (including its pending exception); do not touch RAX.
        Outcome::Switched => {
            tracing::trace!("[{}] resumed after syscall {nr} switch", env.proc.pid);
            if let Some((icount, pid)) = trace_entry {
                env.trace_event(crate::trace::Event::Syscall {
                    icount,
                    pid,
                    nr,
                    args: [a0, a1, a2, a3, a4, a5],
                    ret: crate::trace::SyscallResult::Blocked,
                });
            }
            None
        }
        Outcome::Exit(exit) => {
            if let Some((icount, pid)) = trace_entry {
                env.trace_event(crate::trace::Event::Syscall {
                    icount,
                    pid,
                    nr,
                    args: [a0, a1, a2, a3, a4, a5],
                    ret: crate::trace::SyscallResult::NoReturn,
                });
            }
            Some(exit)
        }
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
        abi::SYS_EXIT => {
            if std::env::var_os("THREAD_TRACE").is_some() {
                eprintln!(
                    "[thread] exit pid={} code={} @{}",
                    env.proc.pid,
                    a[0],
                    cpu.icount()
                );
            }
            task_exit(env, cpu, encode_exit_status(a[0]), false)
        }
        abi::SYS_EXIT_GROUP => {
            if std::env::var_os("THREAD_TRACE").is_some() {
                eprintln!(
                    "[thread] exit_group pid={} code={} @{}",
                    env.proc.pid,
                    a[0],
                    cpu.icount()
                );
            }
            task_exit(env, cpu, encode_exit_status(a[0]), true)
        }
        abi::SYS_READ => outcome_read(env, cpu, a[0], a[1], a[2]),
        abi::SYS_PREAD64 => sys_pread(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_WRITE => outcome_write(env, cpu, a[0], a[1], a[2]),
        abi::SYS_PWRITE64 => sys_pwrite(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_FTRUNCATE => sys_ftruncate(env, cpu, a[0], a[1]),
        abi::SYS_READV => outcome_vectored(env, cpu, a[0], a[1], a[2], false),
        abi::SYS_WRITEV => outcome_vectored(env, cpu, a[0], a[1], a[2], true),
        // Terminal-changing ioctls may stop a background process group before
        // they mutate the pty, so they need the scheduler-aware Outcome path.
        // Linux declares ioctl's first argument as `unsigned int fd`.
        // x86-64 callers are allowed to leave the upper half of the argument
        // register unspecified when materialising a narrow integer.  Native
        // runtimes such as Bun's JSC bridge do exactly that: their tagged JS
        // value leaves bits above the low 32-bit fd intact.  The real kernel
        // truncates at the syscall wrapper boundary, so do the same before
        // descriptor lookup instead of treating the tag bits as EBADF.
        abi::SYS_IOCTL => outcome_ioctl(env, cpu, a[0] as u32 as u64, a[1], a[2]),
        abi::SYS_FORK => sys_clone_impl(env, cpu, CloneSpec::fork()),
        abi::SYS_VFORK => sys_clone_impl(env, cpu, CloneSpec::vfork()),
        abi::SYS_CLONE => {
            let r = sys_clone_impl(env, cpu, CloneSpec::from_clone_args(a));
            if std::env::var_os("THREAD_TRACE").is_some() {
                if let Outcome::Ret(Ok(child)) = &r {
                    eprintln!(
                        "[thread] clone parent={} child={child} flags={:#x} @{}",
                        env.proc.pid,
                        a[0],
                        cpu.icount()
                    );
                }
            }
            r
        }
        abi::SYS_CLONE3 => match clone3_spec(env, cpu, a[0], a[1]) {
            Ok(spec) => {
                let flags = spec.flags;
                let r = sys_clone_impl(env, cpu, spec);
                if std::env::var_os("THREAD_TRACE").is_some() {
                    if let Outcome::Ret(Ok(child)) = &r {
                        eprintln!(
                            "[thread] clone3 parent={} child={child} flags={flags:#x} @{}",
                            env.proc.pid,
                            cpu.icount()
                        );
                    }
                }
                r
            }
            Err(errno) => Outcome::Ret(Err(errno)),
        },
        abi::SYS_EXECVE => sys_execve(env, cpu, a[0], a[1], a[2]),
        abi::SYS_WAIT4 => sys_wait4(env, cpu, a[0], a[1], a[2]),
        abi::SYS_PIPE => sys_pipe(env, cpu, a[0], 0).into(),
        abi::SYS_PIPE2 => sys_pipe(env, cpu, a[0], a[1]).into(),
        abi::SYS_FUTEX => sys_futex(env, cpu, a[0], a[1], a[2], a[3]),
        abi::SYS_RT_SIGRETURN => sys_rt_sigreturn(env, cpu),
        // Delivers a signal the new mask just unblocked, so it returns an
        // Outcome rather than a plain result.
        abi::SYS_RT_SIGPROCMASK => sys_rt_sigprocmask(env, cpu, a[0], a[1], a[2]),
        abi::SYS_SCHED_YIELD => sys_yield(env, cpu),
        abi::SYS_KILL => sys_kill(env, cpu, a[0], a[1]),
        abi::SYS_TGKILL => sys_kill(env, cpu, a[1], a[2]),
        // `tkill` addresses a thread directly; `raise` in musl is built on it.
        abi::SYS_TKILL => sys_kill(env, cpu, a[0], a[1]),
        abi::SYS_NANOSLEEP => outcome_nanosleep(env, cpu, a[0], false),
        abi::SYS_CLOCK_NANOSLEEP => {
            const TIMER_ABSTIME: u64 = 1;
            outcome_nanosleep(env, cpu, a[2], a[1] & TIMER_ABSTIME != 0)
        }
        abi::SYS_POLL => outcome_poll(env, cpu, a[0], a[1], a[2], false),
        abi::SYS_PPOLL => outcome_poll(env, cpu, a[0], a[1], a[2], true),
        abi::SYS_SENDTO => sys_sendto(env, cpu, a),
        abi::SYS_RECVFROM => sys_recvfrom(env, cpu, a),
        abi::SYS_SENDMSG => sys_sendmsg(env, cpu, a),
        abi::SYS_SENDMMSG => sys_sendmmsg(env, cpu, a),
        abi::SYS_RECVMSG => sys_recvmsg(env, cpu, a),
        abi::SYS_EPOLL_WAIT | abi::SYS_EPOLL_PWAIT => sys_epoll_wait(env, cpu, a),
        abi::SYS_EPOLL_PWAIT2 => sys_epoll_pwait2(env, cpu, a),
        abi::SYS_SELECT => sys_select(env, cpu, a, false),
        abi::SYS_PSELECT6 => sys_select(env, cpu, a, true),
        abi::SYS_SENDFILE => sys_sendfile(env, cpu, a),
        _ => dispatch_simple(env, cpu, nr, a).into(),
    }
}

fn dispatch_simple(env: &mut LinuxEnv, cpu: &mut Cpu, nr: u64, a: [u64; 6]) -> SysResult {
    match nr {
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
        abi::SYS_CLOSE => {
            let closed = close_fd(env, a[0]);
            // Closing the last descriptor on an unlinked file is when its
            // contents finally become unreachable.
            if closed.is_ok() {
                env.reclaim_unlinked();
            }
            closed.map(|_| 0)
        }
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
        abi::SYS_CHOWN | abi::SYS_LCHOWN | abi::SYS_FCHOWNAT => Ok(0), // single-user: uid/gid stay 0
        abi::SYS_FCHOWN => {
            env.proc.fds.borrow().get(a[0])?; // EBADF still reports honestly
            Ok(0)
        }
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
        abi::SYS_FCNTL => sys_fcntl(env, cpu, a[0], a[1], a[2]),
        abi::SYS_FSYNC | abi::SYS_SYNC => Ok(0),
        // Advisory locking. The guest is a single process with no competing
        // lock holders, so acquiring/releasing always succeeds as a no-op.
        abi::SYS_FLOCK => Ok(0),

        abi::SYS_SOCKET => sys_socket(env, a[0], a[1], a[2]),
        abi::SYS_CONNECT => sys_connect(env, cpu, a[0], a[1], a[2]),
        abi::SYS_SHUTDOWN => sys_shutdown(env, a[0], a[1]),
        abi::SYS_GETPEERNAME => sys_getpeername(env, cpu, a[0], a[1], a[2]),
        abi::SYS_GETSOCKNAME => {
            let socket = net_of(env, a[0])?;
            let (kind, family, handle, broker, local_protocol_id) = {
                let inner = socket.borrow();
                (
                    inner.kind,
                    inner.family,
                    inner.handle,
                    inner.broker.clone(),
                    inner.local_protocol_id,
                )
            };
            if kind == SocketKind::NetlinkRoute {
                // Linux exposes a sockaddr_nl here, including the process
                // port ID assigned by the kernel. Address-discovery clients
                // validate that family before accepting a route dump.
                write_sockaddr_nl(env, cpu, a[1], a[2], local_protocol_id, 0)?;
                return Ok(0);
            }
            let local = match (family, handle) {
                (AF_INET6, Some(handle)) => broker
                    .borrow_mut()
                    .local_addr_v6(handle)
                    .map(std::net::SocketAddr::V6)
                    .unwrap_or_else(|| {
                        std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                            std::net::Ipv6Addr::UNSPECIFIED,
                            0,
                            0,
                            0,
                        ))
                    }),
                (_, Some(handle)) => broker
                    .borrow_mut()
                    .local_addr(handle)
                    .map(std::net::SocketAddr::V4)
                    .unwrap_or_else(|| {
                        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                            std::net::Ipv4Addr::UNSPECIFIED,
                            0,
                        ))
                    }),
                (AF_INET6, None) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                    std::net::Ipv6Addr::UNSPECIFIED,
                    0,
                    0,
                    0,
                )),
                _ => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                    std::net::Ipv4Addr::UNSPECIFIED,
                    0,
                )),
            };
            write_sockaddr(env, cpu, a[1], a[2], local)?;
            Ok(0)
        }
        abi::SYS_SETSOCKOPT => net_of(env, a[0]).map(|_| 0),
        abi::SYS_GETSOCKOPT => sys_getsockopt(env, cpu, a),
        abi::SYS_SOCKETPAIR => sys_socketpair(env, cpu, a),
        abi::SYS_BIND => {
            let socket = net_of(env, a[0])?;
            let (kind, family) = {
                let inner = socket.borrow();
                (inner.kind, inner.family)
            };
            if kind == SocketKind::NetlinkRoute {
                // sockaddr_nl(pid=0, groups=0): kernel-assigned local port
                // and no multicast subscription. The deterministic route view
                // is strictly request/reply, so there is no bind-side state.
                return Ok(0);
            }
            if kind == SocketKind::Unix {
                // A local-domain listener remains inside the guest VFS; it
                // is not a route to the host. Runtime CLIs reserve a private
                // control endpoint before deciding whether a helper needs to
                // connect to it. Validate the sockaddr shape now; listener
                // rendezvous is handled by the local socket path below.
                if a[2] < 3 {
                    return Err(abi::EINVAL);
                }
                let bytes = read_mem(env, cpu, a[1], (a[2] as usize).min(108))?;
                let bound_family =
                    u16::from_le_bytes(bytes[..2].try_into().expect("sockaddr family")) as u64;
                return if bound_family == AF_UNIX {
                    Ok(0)
                } else {
                    Err(abi::EAFNOSUPPORT)
                };
            }
            let port = match family {
                AF_INET => parse_sockaddr_in(env, cpu, a[1], a[2])?.port(),
                AF_INET6 => parse_sockaddr_in6(env, cpu, a[1], a[2])?.port(),
                _ => return Err(abi::EAFNOSUPPORT),
            };
            if port == 0 {
                Ok(0) // ephemeral bind: the broker already does this
            } else {
                tracing::warn!("bind to a specific port is not supported (no listeners)");
                Err(abi::EOPNOTSUPP)
            }
        }
        abi::SYS_LISTEN
            if net_of(env, a[0]).is_ok_and(|socket| socket.borrow().kind == SocketKind::Unix) =>
        {
            // The listener is a guest-local control endpoint. It is not
            // brokered and cannot accept host-originated connections.
            Ok(0)
        }
        abi::SYS_LISTEN | abi::SYS_ACCEPT | abi::SYS_ACCEPT4 => {
            tracing::warn!("listening sockets are not supported (client-only network)");
            Err(abi::EOPNOTSUPP)
        }

        abi::SYS_EVENTFD => sys_eventfd(env, a[0], 0),
        abi::SYS_EVENTFD2 => sys_eventfd(env, a[0], a[1]),
        abi::SYS_INOTIFY_INIT => sys_inotify_init(env, 0),
        abi::SYS_INOTIFY_INIT1 => sys_inotify_init(env, a[0]),
        abi::SYS_INOTIFY_ADD_WATCH => sys_inotify_add_watch(env, cpu, a[0], a[1], a[2]),
        abi::SYS_INOTIFY_RM_WATCH => sys_inotify_rm_watch(env, a[0], a[1]),
        abi::SYS_TIMERFD_CREATE => sys_timerfd_create(env, a[0], a[1]),
        abi::SYS_TIMERFD_SETTIME => sys_timerfd_settime(env, cpu, a),
        abi::SYS_TIMERFD_GETTIME => sys_timerfd_gettime(env, cpu, a[0], a[1]),
        // epoll_create(size) has no flags; epoll_create1(flags) takes them in
        // the first syscall argument. Reading RSI here made CLOEXEC depend on
        // an unrelated stale register and could close the runtime's event
        // loop across exec.
        abi::SYS_EPOLL_CREATE => sys_epoll_create(env, 0),
        abi::SYS_EPOLL_CREATE1 => sys_epoll_create(env, a[0]),
        abi::SYS_EPOLL_CTL => sys_epoll_ctl(env, cpu, a),

        abi::SYS_MMAP => {
            let r = sys_mmap(env, cpu, a);
            if std::env::var_os("MMAP_TRACE").is_some() {
                eprintln!(
                    "[mmap] pid={} addr={:#x} len={:#x} prot={:#x} flags={:#x} -> {:x?}",
                    env.proc.pid, a[0], a[1], a[2], a[3], r
                );
            }
            r
        }
        abi::SYS_MSYNC => {
            sync_shared_range(env, cpu, a[0], align_up(a[1], PAGE_SIZE));
            Ok(0)
        }
        abi::SYS_MUNMAP => {
            // A MAP_SHARED region's contents live in guest pages until they are
            // written back; unmapping is the last chance.
            sync_shared_range(env, cpu, a[0], align_up(a[1], PAGE_SIZE));
            env.shared_maps.retain(|map| {
                map.asid != env.proc.asid
                    || map.addr >= a[0].saturating_add(align_up(a[1], PAGE_SIZE))
                    || map.addr.saturating_add(map.len) <= a[0]
            });
            let ok = cpu.mem.unmap_memory_len(a[0], a[1]);
            if ok {
                env.forget_file_backed_range(env.proc.asid, a[0], align_up(a[1], PAGE_SIZE));
                env.clear_dontfork(
                    env.proc.asid,
                    a[0],
                    a[0].saturating_add(align_up(a[1], PAGE_SIZE)),
                );
                env.pager
                    .unmap(env.proc.asid, a[0], align_up(a[1], PAGE_SIZE));
            }
            if std::env::var_os("MMAP_TRACE").is_some() {
                eprintln!(
                    "[munmap] pid={} addr={:#x} len={:#x} -> {ok}",
                    env.proc.pid, a[0], a[1]
                );
            }
            match ok {
                true => Ok(0),
                false => Err(abi::EINVAL),
            }
        }
        abi::SYS_MPROTECT => sys_mprotect(env, cpu, a[0], a[1], a[2]),
        abi::SYS_MREMAP => sys_mremap(env, cpu, a),
        abi::SYS_MADVISE => sys_madvise(env, cpu, a[0], a[1], a[2]),
        abi::SYS_BRK => sys_brk(env, cpu, a[0]),

        abi::SYS_RT_SIGACTION => sys_rt_sigaction(env, cpu, a[0], a[1], a[2]),
        abi::SYS_SIGALTSTACK => sys_sigaltstack(env, cpu, a[0], a[1]),

        abi::SYS_ARCH_PRCTL => match a[0] {
            abi::ARCH_SET_FS => {
                cpu.write_var(env.regs.fs_offset, a[1]);
                Ok(0)
            }
            abi::ARCH_GET_FS => {
                let fs: u64 = cpu.read_var(env.regs.fs_offset);
                write_mem(env, cpu, a[1], &fs.to_le_bytes())?;
                Ok(0)
            }
            op => {
                tracing::debug!("arch_prctl: unsupported op {op:#x}");
                Err(abi::EINVAL)
            }
        },

        abi::SYS_UNAME => sys_uname(env, cpu, a[0]),
        abi::SYS_GETRANDOM => sys_getrandom(env, cpu, a[0], a[1]),
        abi::SYS_CLOCK_GETTIME => sys_clock_gettime(env, cpu, a[0], a[1]),
        abi::SYS_CLOCK_GETRES => {
            let resolution = clock_resolution_nanos(a[0])?;
            if a[1] != 0 {
                let res: [u8; 16] = encode_timespec(0, resolution);
                write_mem(env, cpu, a[1], &res)?;
            }
            Ok(0)
        }
        abi::SYS_GETTIMEOFDAY => sys_gettimeofday(env, cpu, a[0]),
        abi::SYS_TIME => {
            let (sec, _) = env.now(cpu);
            if a[0] != 0 {
                write_mem(env, cpu, a[0], &sec.to_le_bytes())?;
            }
            Ok(sec as u64)
        }

        abi::SYS_GETPID => Ok(env.proc.tgid),
        abi::SYS_GETPGRP => Ok(env.proc.pgid),
        abi::SYS_GETPGID => sys_getpgid(env, a[0]),
        abi::SYS_SETPGID => sys_setpgid(env, a[0], a[1]),
        abi::SYS_GETTID => Ok(env.proc.pid),
        abi::SYS_GETPPID => Ok(env.proc.ppid),
        abi::SYS_GETCPU => {
            // The deterministic scheduler executes every task on virtual CPU
            // zero. This is the same stable identity published through rseq;
            // callers may omit either output pointer just as on Linux.
            if a[0] != 0 {
                write_mem(env, cpu, a[0], &0_u32.to_le_bytes())?;
            }
            if a[1] != 0 {
                write_mem(env, cpu, a[1], &0_u32.to_le_bytes())?;
            }
            Ok(0)
        }
        abi::SYS_GETUID | abi::SYS_GETEUID => Ok(env.proc.uid as u64),
        abi::SYS_GETGID | abi::SYS_GETEGID => Ok(env.proc.gid as u64),
        abi::SYS_GETGROUPS => Ok(0),
        abi::SYS_SCHED_SETSCHEDULER => sys_sched_setscheduler(env, cpu, a[0], a[1], a[2]),
        abi::SYS_SETSID => {
            // A new session's leader also leads a new process group.
            let tgid = env.proc.tgid;
            set_group_pgid(env, tgid, tgid);
            env.proc.sid = tgid;
            Ok(tgid)
        }
        abi::SYS_SET_TID_ADDRESS => {
            env.proc.clear_child_tid = a[0];
            Ok(env.proc.pid)
        }
        abi::SYS_PRLIMIT64 => sys_prlimit64(env, cpu, a[1], a[2], a[3]),
        abi::SYS_SETRLIMIT => Ok(0),
        abi::SYS_PRCTL => {
            const PR_SET_PDEATHSIG: u64 = 1;
            const PR_GET_PDEATHSIG: u64 = 2;
            const PR_SET_NAME: u64 = 15;
            match a[0] {
                // Thread names are accepted (not displayed anywhere).
                PR_SET_NAME => Ok(0),
                // Parent-death signals are accepted but not delivered: the
                // registering child outliving its parent is not modeled, and
                // spawn preambles (pre_exec) treat a failure here as fatal.
                PR_SET_PDEATHSIG => Ok(0),
                PR_GET_PDEATHSIG => {
                    write_mem(env, cpu, a[1], &0u32.to_le_bytes())?;
                    Ok(0)
                }
                other => {
                    tracing::debug!("prctl: unsupported option {other}");
                    Err(abi::EINVAL)
                }
            }
        }
        // The affinity mask and sysfs online topology are one contract. The
        // deterministic scheduler may time-slice those logical CPUs on one
        // execution engine, just as a host may schedule many runnable threads
        // on fewer physical cores.
        abi::SYS_SCHED_GETAFFINITY => {
            let size = (a[1] as usize).min(128);
            if size < 8 {
                return Err(abi::EINVAL);
            }
            let mut mask = vec![0_u8; size];
            mask[0] = (1_u8 << crate::VIRTUAL_CPU_COUNT) - 1;
            write_mem(env, cpu, a[2], &mask)?;
            Ok(8)
        }

        abi::SYS_SET_ROBUST_LIST => sys_set_robust_list(env, a[0], a[1]),
        abi::SYS_RSEQ => sys_rseq(env, cpu, a[0], a[1], a[2], a[3]),

        abi::SYS_SYSINFO => sys_sysinfo(env, cpu, a[0]),
        abi::SYS_GETRUSAGE => sys_getrusage(env, cpu, a[0] as i64, a[1]),
        abi::SYS_CLOSE_RANGE => sys_close_range(env, a[0], a[1], a[2]),

        _ => {
            tracing::warn!("unimplemented syscall {nr} -> ENOSYS");
            Err(abi::ENOSYS)
        }
    }
}

/// Closes one descriptor and removes its numeric registration from every
/// epoll instance in the process. Linux ties an epoll item to the registered
/// open-file description and removes it when that description is gone; this
/// fd-number model must at least prevent a later fd reuse from inheriting the
/// old interest, edge suppression, or ONESHOT-disabled state.
fn close_fd(env: &mut LinuxEnv, fd: u64) -> Result<(), u64> {
    let epolls: Vec<crate::fd::EpollRef> = {
        let fds = env.proc.fds.borrow();
        fds.iter()
            .filter_map(|(_, entry)| match &entry.desc.borrow().backing {
                Backing::Epoll(epoll) => Some(epoll.clone()),
                _ => None,
            })
            .collect()
    };
    env.proc.fds.borrow_mut().close(fd)?;
    for epoll in epolls {
        let mut inner = epoll.borrow_mut();
        inner.interests.remove(&fd);
        inner.oneshot_disabled.remove(&fd);
        inner.edge_fired.remove(&fd);
    }
    Ok(())
}

/// Applies close-on-exec through the same epoll-aware close path as `close`
/// and `close_range`. Dropping table slots directly would leave registrations
/// keyed by those numeric descriptors behind, so a descriptor allocated by
/// the new image could inherit stale readiness and ONESHOT state.
fn close_cloexec_fds(env: &mut LinuxEnv) {
    let cloexec: Vec<u64> = env
        .proc
        .fds
        .borrow()
        .iter()
        .filter_map(|(fd, entry)| entry.cloexec.then_some(fd))
        .collect();
    for fd in cloexec {
        // The list came from this table and no guest code runs between its
        // creation and the closes, so failure only means an internal bug.
        let closed = close_fd(env, fd);
        debug_assert!(closed.is_ok());
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

fn path_arg(env: &mut LinuxEnv, cpu: &mut Cpu, ptr: u64) -> Result<Vec<u8>, u64> {
    read_cstr(env, cpu, ptr)
}

// ── File I/O ────────────────────────────────────────────────────────────────

/// Creates an inotify instance. `flags` carries `O_NONBLOCK` and `O_CLOEXEC`
/// in the same bits `open` uses.
fn sys_inotify_init(env: &mut LinuxEnv, flags: u64) -> SysResult {
    let inner = std::rc::Rc::new(std::cell::RefCell::new(crate::fd::InotifyInner {
        next_descriptor: 1,
        ..Default::default()
    }));
    env.inotify.push(std::rc::Rc::clone(&inner));
    install_fd(
        env,
        Backing::Inotify(inner),
        abi::O_RDONLY | (flags & abi::O_NONBLOCK),
        flags & abi::O_CLOEXEC != 0,
    )
}

/// Adds or updates a watch. Returns the watch descriptor, which is what a
/// later event carries and what `inotify_rm_watch` takes.
///
/// Watching a path that is already watched updates the existing watch and
/// returns the same descriptor, because the kernel watches an inode and a
/// second request names the same one.
fn sys_inotify_add_watch(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    fd: u64,
    path_ptr: u64,
    mask: u64,
) -> SysResult {
    let path = read_cstr(env, cpu, path_ptr)?;
    let node = env
        .vfs
        .resolve(crate::vfs::ROOT, &path, true)?
        .node
        .ok_or(abi::ENOENT)?;
    // A mask with no event bits watches nothing, which is a request the
    // kernel refuses rather than silently honouring.
    let mask = (mask as u32) & abi::IN_ALL_EVENTS;
    if mask == 0 {
        return Err(abi::EINVAL);
    }
    let inner = inotify_of(env, fd)?;
    let mut inner = inner.borrow_mut();
    if let Some(existing) = inner.watches.iter_mut().find(|watch| watch.node == node) {
        existing.mask = mask;
        existing.path = path;
        return Ok(existing.descriptor as u64);
    }
    let descriptor = inner.next_descriptor;
    inner.next_descriptor += 1;
    inner.watches.push(crate::fd::Watch {
        descriptor,
        node,
        path,
        mask,
    });
    Ok(descriptor as u64)
}

fn sys_inotify_rm_watch(env: &mut LinuxEnv, fd: u64, descriptor: u64) -> SysResult {
    let descriptor = descriptor as u32 as i32;
    let inner = inotify_of(env, fd)?;
    let mut inner = inner.borrow_mut();
    let before = inner.watches.len();
    inner.watches.retain(|watch| watch.descriptor != descriptor);
    if inner.watches.len() == before {
        return Err(abi::EINVAL);
    }
    // Events already queued for a removed watch are dropped: a program that
    // stopped watching asked not to hear about it.
    inner.queue.retain(|event| event.descriptor != descriptor);
    Ok(0)
}

fn inotify_of(env: &LinuxEnv, fd: u64) -> Result<crate::fd::InotifyRef, u64> {
    let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
    let backing = &desc.borrow().backing;
    match backing {
        Backing::Inotify(inner) => Ok(std::rc::Rc::clone(inner)),
        _ => Err(abi::EINVAL),
    }
}

/// Tells every watcher that something happened to `node`, or to `name` inside
/// it when `name` is given.
///
/// Both halves are needed and they are different questions: a program
/// watching a file wants to know the file changed, and a program watching a
/// directory wants to know which entry did. The kernel answers both from one
/// event, distinguished by whether the name field is empty.
pub(crate) fn notify_inotify(env: &mut LinuxEnv, node: usize, name: &[u8], mask: u32, cookie: u32) {
    if env.inotify.is_empty() {
        return;
    }
    // Instances no descriptor holds any more are the registry's own to drop.
    env.inotify
        .retain(|inner| std::rc::Rc::strong_count(inner) > 1);
    for inner in &env.inotify {
        let mut inner = inner.borrow_mut();
        let matched: Vec<(i32, u32)> = inner
            .watches
            .iter()
            .filter(|watch| watch.node == node && watch.mask & mask != 0)
            .map(|watch| (watch.descriptor, mask))
            .collect();
        for (descriptor, mask) in matched {
            if inner.queue.len() >= crate::fd::INOTIFY_QUEUE_LIMIT {
                // Losing events is bad; losing them quietly is worse. The
                // next read says so before it says anything else.
                inner.overflowed = true;
                break;
            }
            inner.queue.push_back(crate::fd::InotifyEvent {
                descriptor,
                mask,
                cookie,
                name: name.to_vec(),
            });
        }
        inner.activity += 1;
    }
}

/// A cookie pairing the two halves of a rename.
fn next_inotify_cookie(env: &mut LinuxEnv) -> u32 {
    env.inotify_cookie = env.inotify_cookie.wrapping_add(1).max(1);
    env.inotify_cookie
}

/// Serialises queued events into the shape a watcher reads:
/// `struct inotify_event { int wd; uint32_t mask, cookie, len; char name[len]; }`
/// with the name NUL-terminated and padded so the next record is aligned.
///
/// The kernel refuses a buffer too small for the first event rather than
/// returning a partial one — a half record is not something a reader can
/// resynchronise from — and returns as many whole events as fit otherwise.
fn read_inotify(inner: &mut crate::fd::InotifyInner, buf_len: usize) -> Result<Vec<u8>, u64> {
    const HEADER: usize = 16;
    // An overflow is announced before the events that survived it, so a
    // reader learns it has a gap before it acts on what came after.
    if inner.overflowed {
        inner.overflowed = false;
        inner.queue.push_front(crate::fd::InotifyEvent {
            descriptor: -1,
            mask: abi::IN_Q_OVERFLOW,
            cookie: 0,
            name: Vec::new(),
        });
    }
    if inner.queue.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    while let Some(event) = inner.queue.front() {
        // The name is NUL-terminated and padded to a multiple of the header's
        // alignment, so the record after it starts where a reader expects.
        let name_len = if event.name.is_empty() {
            0
        } else {
            (event.name.len() + 1).next_multiple_of(16)
        };
        let record = HEADER + name_len;
        if out.is_empty() && record > buf_len {
            // Nothing fits, not even the first. Say so rather than hand back
            // a fragment of a record.
            return Err(abi::EINVAL);
        }
        if out.len() + record > buf_len {
            break;
        }
        let event = inner.queue.pop_front().expect("front was Some");
        out.extend_from_slice(&event.descriptor.to_le_bytes());
        out.extend_from_slice(&event.mask.to_le_bytes());
        out.extend_from_slice(&event.cookie.to_le_bytes());
        out.extend_from_slice(&(name_len as u32).to_le_bytes());
        if name_len > 0 {
            out.extend_from_slice(&event.name);
            out.resize(out.len() + (name_len - event.name.len()), 0);
        }
    }
    inner.activity += 1;
    Ok(out)
}

fn read_backing(
    env: &mut LinuxEnv,
    desc: &mut Description,
    buf_len: usize,
) -> Result<Vec<u8>, ReadBackingError> {
    match &mut desc.backing {
        Backing::Std(StdStream::In) => Ok(Vec::new()),
        Backing::Std(_) => Err(ReadBackingError::Errno(abi::EBADF)),
        Backing::Inotify(inner) => {
            read_inotify(&mut inner.borrow_mut(), buf_len).map_err(ReadBackingError::Errno)
        }
        Backing::File { node } => {
            if env.is_host_secret_node(*node) {
                let secret = env
                    .host_secret_for_node(*node)
                    .ok_or(ReadBackingError::Errno(abi::EACCES))?;
                let start = offset_into(desc.offset, secret.len());
                let end = start.saturating_add(buf_len).min(secret.len());
                let chunk = secret[start..end].to_vec();
                desc.offset += chunk.len() as u64;
                return Ok(chunk);
            }
            let chunk = match env
                .vfs
                .read_node_range(*node, desc.offset, buf_len)
                .map_err(ReadBackingError::Errno)?
            {
                crate::chunk::ReadRange::Ready(bytes) => bytes,
                crate::chunk::ReadRange::Missing(hash) => {
                    return Err(ReadBackingError::Missing(hash));
                }
                crate::chunk::ReadRange::Invalid(_) => {
                    return Err(ReadBackingError::Errno(abi::EIO));
                }
            };
            desc.offset += chunk.len() as u64;
            Ok(chunk)
        }
        Backing::Dir { .. } => Err(ReadBackingError::Errno(abi::EISDIR)),
        // Handled by `outcome_read` before reaching here.
        Backing::Pipe { .. }
        | Backing::SocketPair { .. }
        | Backing::EventFd(_)
        | Backing::TimerFd(_)
        | Backing::Net(_)
        | Backing::PtyMaster(_)
        | Backing::PtySlave(_)
        | Backing::Epoll(_) => Err(ReadBackingError::Errno(abi::EINVAL)),
        Backing::Dev(dev) => match dev {
            Dev::Null | Dev::Tty | Dev::Ptmx => Ok(Vec::new()),
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

enum ReadBackingError {
    Errno(u64),
    Missing(crate::chunk::Hash),
}

impl From<u64> for ReadBackingError {
    fn from(errno: u64) -> Self {
        Self::Errno(errno)
    }
}

fn wait_for_file_chunk(env: &mut LinuxEnv, cpu: &mut Cpu, hash: crate::chunk::Hash) -> Outcome {
    if let Err(why) = env.request_file_chunk(hash) {
        tracing::error!("file page-in refused: {why}");
        return Outcome::Ret(Err(abi::EIO));
    }
    // `Environment::handle_exception` has already consumed this syscall
    // exception. Queue it again so completion re-enters the syscall without
    // advancing RIP or mutating the open-file offset.
    cpu.pending_exception = Some(cpu.exception);
    Outcome::Exit(VmExit::Interrupted)
}

/// Whole-file mutation preserves the immutable base by materializing it once.
/// Fetch one absent chunk per retry so the syscall remains idempotent and the
/// ordinary page-delivery ticket protocol stays the only host boundary.
fn wait_to_materialize(env: &mut LinuxEnv, cpu: &mut Cpu, node: usize) -> Option<Outcome> {
    match env.vfs.first_missing_file_chunk(node) {
        Ok(Some(hash)) => Some(wait_for_file_chunk(env, cpu, hash)),
        Ok(None) => None,
        Err(errno) => Some(Outcome::Ret(Err(errno))),
    }
}

/// Linux `copy_from_user`/`copy_to_user` faults user pages just like a guest
/// load/store. Host-side syscall copies bypass the CPU's softmmu permission
/// checks, so explicitly fill any lazy pages first; otherwise an untouched
/// mapping would silently contribute allocator zeros to `write(2)`.
fn ensure_guest_range(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr: u64,
    len: usize,
    access: crate::pager::AccessKind,
) -> Option<Outcome> {
    match host_touch(env, cpu, addr, len, access) {
        Ok(()) => None,
        // host_touch already armed the suspend state for a cold page.
        Err(PAGE_IN_RESTART) => Some(Outcome::Exit(VmExit::Interrupted)),
        Err(errno) => Some(Outcome::Ret(Err(errno))),
    }
}

fn write_backing(env: &mut LinuxEnv, desc: &mut Description, bytes: &[u8]) -> Result<u64, u64> {
    if !desc.writable() {
        return Err(abi::EBADF);
    }
    match &mut desc.backing {
        Backing::Std(StdStream::In) => Err(abi::EBADF),
        // An inotify instance is something to read from. The kernel refuses
        // a write to one, and a program that tries has misunderstood the fd
        // it is holding rather than asked for something reasonable.
        Backing::Inotify(_) => Err(abi::EBADF),
        Backing::Std(_) | Backing::Dev(Dev::Tty) => {
            env.output.extend_from_slice(bytes);
            Ok(bytes.len() as u64)
        }
        Backing::Dev(_) => Ok(bytes.len() as u64),
        Backing::File { node } => {
            let node = *node;
            if env.is_host_secret_node(node) {
                return Err(abi::EPERM);
            }
            let len = env.vfs.materialize_file(node)?.len();
            if desc.flags & abi::O_APPEND != 0 {
                desc.offset = len as u64;
            }
            let start = guest_size(desc.offset)?;
            let end = start.checked_add(bytes.len()).ok_or(abi::EFBIG)?;
            // Only what the file grows by is charged: overwriting bytes that
            // are already there costs the filesystem nothing. Charged before
            // the write, so a refusal leaves the file untouched.
            if end > len {
                env.vfs.reserve(end - len)?;
            }
            let data = env.vfs.materialize_file(node)?;
            if data.len() < end {
                // A host that cannot find the memory is a full disk to the
                // guest, not an abort of the whole tab.
                data.try_reserve(end - data.len())
                    .map_err(|_| abi::ENOSPC)?;
                data.resize(end, 0);
            }
            data[start..end].copy_from_slice(bytes);
            desc.offset = end as u64;
            // The change reaches a watcher only if something tells it. This
            // is the write path, so it is the one place that knows.
            notify_inotify(env, node, b"", abi::IN_MODIFY, 0);
            Ok(bytes.len() as u64)
        }
        Backing::Dir { .. } => Err(abi::EISDIR),
        // Handled by `outcome_write`/`outcome_read` before reaching here.
        Backing::PtyMaster(_) | Backing::PtySlave(_) => Err(abi::EINVAL),
        Backing::Pipe { .. }
        | Backing::SocketPair { .. }
        | Backing::EventFd(_)
        | Backing::TimerFd(_)
        | Backing::Net(_)
        | Backing::Epoll(_) => Err(abi::EINVAL),
    }
}

fn sys_read(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64, count: u64) -> Outcome {
    let desc = match env.proc.fds.borrow().get(fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let mut desc = desc.borrow_mut();
    if !desc.readable() {
        return Outcome::Ret(Err(abi::EBADF));
    }
    let count = count.min(0x40_0000) as usize;
    let chunk = match read_backing(env, &mut desc, count) {
        Ok(chunk) => chunk,
        Err(ReadBackingError::Errno(errno)) => return Outcome::Ret(Err(errno)),
        Err(ReadBackingError::Missing(hash)) => {
            drop(desc);
            return wait_for_file_chunk(env, cpu, hash);
        }
    };
    match write_mem(env, cpu, buf, &chunk) {
        Ok(()) => Outcome::Ret(Ok(chunk.len() as u64)),
        Err(errno) => Outcome::Ret(Err(errno)),
    }
}

/// Resizes a regular file to `length`, zero-filling any extension. The fd
/// must be open for writing. Used for memfd/tempfile-backed IPC buffers.
fn sys_ftruncate(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, length: u64) -> Outcome {
    const MAX_LEN: u64 = 1 << 30; // 1 GiB guard against a runaway size
    if length > MAX_LEN {
        return Outcome::Ret(Err(abi::EFBIG));
    }
    let desc = match env.proc.fds.borrow().get(fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let desc = desc.borrow();
    if desc.flags & abi::O_ACCMODE == abi::O_RDONLY {
        return Outcome::Ret(Err(abi::EINVAL));
    }
    let Backing::File { node } = desc.backing else {
        return Outcome::Ret(Err(abi::EINVAL));
    };
    if env.is_host_secret_node(node) {
        return Outcome::Ret(Err(abi::EPERM));
    }
    if let Some(outcome) = wait_to_materialize(env, cpu, node) {
        return outcome;
    }
    let len = match env.vfs.materialize_file(node) {
        Ok(data) => data.len(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let length = match guest_size(length) {
        Ok(length) => length,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    if length > len {
        if let Err(errno) = env.vfs.reserve(length - len) {
            return Outcome::Ret(Err(errno));
        }
    }
    let data = match env.vfs.materialize_file(node) {
        Ok(data) => data,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    if length > data.len() && data.try_reserve(length - data.len()).is_err() {
        return Outcome::Ret(Err(abi::ENOSPC));
    }
    data.resize(length, 0);
    Outcome::Ret(Ok(0))
}

/// `sysinfo`: what a runtime asks before deciding how much memory it may use.
/// The numbers come from the guest's own budget rather than the host's, which
/// is the only figure that means anything to a program running in a tab.
fn sys_sysinfo(env: &mut LinuxEnv, cpu: &mut Cpu, ptr: u64) -> SysResult {
    if ptr == 0 {
        return Err(abi::EFAULT);
    }
    let used_pages = cpu.mem.total_pages() as u64;
    let cap_pages = cpu.mem.capacity() as u64;
    let mem_unit = PAGE_SIZE;
    // `struct sysinfo` on x86-64: uptime at 0, three load averages at 8,
    // then totalram at 32.  `procs` is a 16-bit field at 80; totalhigh and
    // freehigh resume 64-bit alignment at 88 and 96.  A previous layout put
    // totalram at 40, leaving it zero. JSC reads totalram to size its initial
    // allocation limit, so that ABI error forced a critical full collection
    // after virtually every allocation during Bun startup.
    let mut buf = [0_u8; 112];
    let mut put = |offset: usize, value: u64| {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    };
    put(0, env.now_nanos(cpu) / 1_000_000_000); // uptime, seconds
    put(32, cap_pages); // totalram, in mem_unit
    put(40, cap_pages.saturating_sub(used_pages)); // freeram
    buf[80..82].copy_from_slice(&1_u16.to_le_bytes()); // procs
    buf[104..108].copy_from_slice(&(mem_unit as u32).to_le_bytes());
    write_mem(env, cpu, ptr, &buf)?;
    Ok(0)
}

/// `getrusage`: a zeroed record with the times this machine can actually
/// account for. Reporting nothing is honest — the fields it would fill are
/// host figures that say nothing about a deterministic guest — and a runtime
/// that reads it wants a successful call more than it wants the numbers.
fn sys_getrusage(env: &mut LinuxEnv, cpu: &mut Cpu, who: i64, ptr: u64) -> SysResult {
    const RUSAGE_SELF: i64 = 0;
    const RUSAGE_CHILDREN: i64 = -1;
    const RUSAGE_THREAD: i64 = 1;
    if !matches!(who, RUSAGE_SELF | RUSAGE_CHILDREN | RUSAGE_THREAD) {
        return Err(abi::EINVAL);
    }
    if ptr == 0 {
        return Err(abi::EFAULT);
    }
    let mut buf = [0_u8; 144];
    // ru_utime: the deterministic clock is the only time this guest has.
    let nanos = env.now_nanos(cpu);
    buf[0..8].copy_from_slice(&(nanos / 1_000_000_000).to_le_bytes());
    buf[8..16].copy_from_slice(&((nanos % 1_000_000_000) / 1_000).to_le_bytes());
    write_mem(env, cpu, ptr, &buf)?;
    Ok(0)
}

/// `close_range`: closes every descriptor in an inclusive range. A runtime
/// uses it before `exec` instead of walking `/proc/self/fd`, so failing it
/// sends the guest down a path that reads a `/proc` this machine does not
/// have.
fn sys_close_range(env: &mut LinuxEnv, first: u64, last: u64, flags: u64) -> SysResult {
    const CLOSE_RANGE_CLOEXEC: u64 = 4;
    if first > last {
        return Err(abi::EINVAL);
    }
    let mut fds = env.proc.fds.borrow_mut();
    let open: Vec<u64> = fds
        .iter()
        .map(|(fd, _)| fd)
        .filter(|fd| *fd >= first && *fd <= last)
        .collect();
    for fd in open {
        if flags & CLOSE_RANGE_CLOEXEC != 0 {
            // Mark rather than close: the descriptors survive until an exec.
            if let Ok(entry) = fds.get_mut(fd) {
                entry.cloexec = true;
            }
        } else {
            drop(fds);
            let _ = close_fd(env, fd);
            fds = env.proc.fds.borrow_mut();
        }
    }
    Ok(0)
}

/// Regenerates a synthesised `/proc` file if `path` names one.
///
/// Only files whose contents this machine actually knows are here. The rest
/// of `/proc` is absent, and absent is a better answer than invented: a
/// runtime that reads a plausible lie about the system will act on it.
///
/// `/proc/self/maps` is the one a language runtime cannot do without — Bun
/// aborts at startup without it, and every debugger reads it.
fn refresh_procfs(env: &mut LinuxEnv, cpu: &mut Cpu, path: &[u8]) {
    let pid = env.proc.pid;
    let self_prefix = format!("/proc/{pid}/");
    let name = if let Some(rest) = path.strip_prefix(b"/proc/self/".as_slice()) {
        rest
    } else if let Some(rest) = path.strip_prefix(self_prefix.as_bytes()) {
        rest
    } else if path == b"/proc/meminfo" {
        b"meminfo".as_slice()
    } else {
        return;
    };

    let content = match name {
        b"maps" => procfs_maps(env, cpu),
        b"statm" => procfs_statm(cpu),
        b"cmdline" => env
            .proc
            .argv
            .iter()
            .flat_map(|a| a.iter().copied().chain(std::iter::once(0)))
            .collect(),
        b"meminfo" => procfs_meminfo(cpu),
        _ => return,
    };

    let full = if path.starts_with(b"/proc/meminfo") {
        b"/proc/meminfo".to_vec()
    } else {
        path.to_vec()
    };
    if env.vfs.take_file_contents(&full).is_some() {
        env.vfs.put_file_contents(&full, content);
    } else {
        let _ = env.add_file(&full, content, 0o444);
    }
}

/// `/proc/self/maps`, from the address space the guest actually has.
fn procfs_maps(env: &mut LinuxEnv, cpu: &mut Cpu) -> Vec<u8> {
    use std::fmt::Write as _;
    let exe = String::from_utf8_lossy(&env.proc.exe_path).into_owned();
    let mut out = String::new();
    // Adjacent ranges with the same permissions are separate entries in the
    // mapping table; procfs coalesces them, and so does this.
    let mut runs: Vec<(u64, u64, u8)> = Vec::new();
    for (start, end, _) in cpu.mem.mapping.iter() {
        let p = cpu.mem.get_perm(start);
        match runs.last_mut() {
            Some((_, last_end, last_perm)) if *last_end + 1 == start && *last_perm == p => {
                *last_end = end;
            }
            _ => runs.push((start, end, p)),
        }
    }
    for (start, end, p) in runs {
        let bit = |b: u8, c: char| if p & b != 0 { c } else { '-' };
        // Private mappings throughout: this machine has no shared ones.
        let _ = writeln!(
            out,
            "{start:012x}-{:012x} {}{}{}p 00000000 00:00 0 {}",
            end.saturating_add(1),
            bit(perm::READ, 'r'),
            bit(perm::WRITE, 'w'),
            bit(perm::EXEC, 'x'),
            if start < 0x1_0000_0000 {
                exe.as_str()
            } else {
                ""
            }
        );
    }
    out.into_bytes()
}

/// `/proc/self/statm`, in pages: total, resident, shared, text, lib, data, dirty.
/// The machine tracks what it has handed out, not the split between those, so
/// the figures it cannot separate are reported as the total rather than
/// invented.
fn procfs_statm(cpu: &Cpu) -> Vec<u8> {
    let pages = cpu.mem.total_pages() as u64;
    format!("{pages} {pages} 0 0 0 {pages} 0\n").into_bytes()
}

/// `/proc/meminfo`, from the guest's budget rather than the host's memory.
fn procfs_meminfo(cpu: &Cpu) -> Vec<u8> {
    let kb = |pages: usize| pages as u64 * 4;
    let total = kb(cpu.mem.capacity());
    let used = kb(cpu.mem.total_pages());
    let free = total.saturating_sub(used);
    format!(
        "MemTotal:       {total:8} kB\nMemFree:        {free:8} kB\nMemAvailable:   {free:8} kB\n"
    )
    .into_bytes()
}

/// Narrows a guest-supplied size to `usize`, refusing what will not fit.
///
/// `usize` is 32 bits in a browser, so `value as usize` silently keeps the low
/// half of a guest value: an `ftruncate` to 4 GiB became a truncate to zero,
/// and a write at offset 2^32 landed at offset zero, on top of the file. A
/// value this host cannot represent cannot be honoured, and `EFBIG` is what a
/// kernel says when a file operation exceeds what it can address.
fn guest_size(value: u64) -> Result<usize, u64> {
    usize::try_from(value).map_err(|_| abi::EFBIG)
}

/// Where a guest offset lands inside a buffer, clamped to its end.
///
/// Compared before narrowing: an offset past what `usize` holds is past the
/// end of anything this host can store, so it reads as end-of-file rather
/// than wrapping around to the beginning.
fn offset_into(offset: u64, len: usize) -> usize {
    if offset >= len as u64 {
        len
    } else {
        offset as usize
    }
}

fn sys_write(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64, count: u64) -> Outcome {
    let count = count.min(0x40_0000) as usize;
    if std::env::var_os("THREAD_TRACE").is_some() && count > 0 && count < 4096 {
        if let Ok(bytes) = read_mem_raw(cpu, buf, count) {
            if bytes.windows(8).any(|w| w == b"panicked") {
                eprintln!(
                    "[panic-write] pid={} fd={fd} len={count} @{}",
                    env.proc.pid,
                    cpu.icount()
                );
            }
        }
    }
    if let Some(outcome) = ensure_guest_range(env, cpu, buf, count, crate::pager::AccessKind::Read)
    {
        return outcome;
    }
    let desc = match env.proc.fds.borrow().get(fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let mut desc = desc.borrow_mut();
    if let Backing::File { node } = desc.backing {
        if let Some(outcome) = wait_to_materialize(env, cpu, node) {
            drop(desc);
            return outcome;
        }
    }
    let bytes = match read_mem(env, cpu, buf, count) {
        Ok(bytes) => bytes,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    Outcome::Ret(write_backing(env, &mut desc, &bytes))
}

fn iter_iov(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    iov: u64,
    iovcnt: u64,
) -> Result<Vec<(u64, u64)>, u64> {
    let iovcnt = iovcnt.min(1024);
    let raw = read_mem(env, cpu, iov, (iovcnt * 16) as usize)?;
    Ok(raw
        .as_chunks::<16>()
        .0
        .iter()
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
) -> Outcome {
    let count = count.min(0x40_0000) as usize;
    if let Some(outcome) = ensure_guest_range(env, cpu, buf, count, crate::pager::AccessKind::Write)
    {
        return outcome;
    }
    let desc = match env.proc.fds.borrow().get(fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let mut desc = desc.borrow_mut();
    let Backing::File { .. } = desc.backing else {
        return Outcome::Ret(Err(abi::ESPIPE));
    };
    let saved = desc.offset;
    desc.offset = pos;
    let chunk = read_backing(env, &mut desc, count);
    desc.offset = saved;
    let chunk = match chunk {
        Ok(chunk) => chunk,
        Err(ReadBackingError::Errno(errno)) => return Outcome::Ret(Err(errno)),
        Err(ReadBackingError::Missing(hash)) => {
            drop(desc);
            return wait_for_file_chunk(env, cpu, hash);
        }
    };
    match write_mem(env, cpu, buf, &chunk) {
        Ok(()) => Outcome::Ret(Ok(chunk.len() as u64)),
        Err(errno) => Outcome::Ret(Err(errno)),
    }
}

fn sys_pwrite(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    fd: u64,
    buf: u64,
    count: u64,
    pos: u64,
) -> Outcome {
    let desc = match env.proc.fds.borrow().get(fd) {
        Ok(entry) => entry.desc.clone(),
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let mut desc = desc.borrow_mut();
    let Backing::File { node } = desc.backing else {
        return Outcome::Ret(Err(abi::ESPIPE));
    };
    if let Some(outcome) = wait_to_materialize(env, cpu, node) {
        drop(desc);
        return outcome;
    }
    let count = count.min(0x40_0000) as usize;
    if let Some(outcome) = ensure_guest_range(env, cpu, buf, count, crate::pager::AccessKind::Read)
    {
        drop(desc);
        return outcome;
    }
    let bytes = match read_mem(env, cpu, buf, count) {
        Ok(bytes) => bytes,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let saved = desc.offset;
    desc.offset = pos;
    let result = write_backing(env, &mut desc, &bytes);
    desc.offset = saved;
    Outcome::Ret(result)
}

fn sys_openat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    flags: u64,
    mode: u64,
) -> SysResult {
    let path = path_arg(env, cpu, path_ptr)?;
    // A few `/proc` files are answered from the machine's own state. They are
    // written into the filesystem at each open rather than being a live
    // backing: a reader gets the snapshot it opened, which is what procfs
    // gives for these anyway.
    refresh_procfs(env, cpu, &path);
    let base = dir_of(env, dirfd)?;
    let follow = flags & abi::O_NOFOLLOW == 0;
    let resolved = env.vfs.resolve(base, &path, follow)?;

    // Access tracking (profiling only): note that a delivered file was actually
    // reached, so the untouched-image fraction can be measured.
    if let (Some(opened), Some(node)) = (env.opened_files.as_mut(), resolved.node) {
        if matches!(
            env.vfs.node(node).kind,
            crate::vfs::NodeKind::File(_) | crate::vfs::NodeKind::ChunkedFile(_)
        ) {
            opened.insert(node);
        }
    }

    // `/dev/tty` is the process's controlling terminal, not a device of its
    // own. When stdio is a host-driven pty, an open must land on that pty:
    // an interactive shell does its job control (tcsetpgrp, tcgetpgrp, window
    // size) through this path, and answering with a generic tty makes those
    // calls silently do nothing — so a program the shell starts never learns
    // the window changed.
    let opens_controlling_tty = resolved.node.is_some_and(|node| {
        matches!(
            env.vfs.node(node).kind,
            crate::vfs::NodeKind::CharDev(crate::vfs::Dev::Tty)
        )
    });
    if opens_controlling_tty {
        if let Some(pty) = env.stdio_pty.clone() {
            {
                let mut inner = pty.borrow_mut();
                inner.slaves += 1;
                inner.slave_ever_opened = true;
                inner.activity += 1;
            }
            let entry = FdEntry {
                desc: std::rc::Rc::new(std::cell::RefCell::new(Description {
                    backing: Backing::PtySlave(pty),
                    offset: 0,
                    flags: flags & (abi::O_ACCMODE | abi::O_APPEND | abi::O_NONBLOCK),
                })),
                cloexec: flags & abi::O_CLOEXEC != 0,
            };
            return env.proc.fds.borrow_mut().insert(entry);
        }
    }

    // `/dev/pts/<id>` slave devices are dynamic (no VFS node): a slave open
    // looks the pty up by id. The parent must be the `/dev/pts` directory and
    // the name a decimal id.
    if resolved.node.is_none() {
        if let Ok(pts_dir) = env.vfs.resolve(crate::vfs::ROOT, b"/dev/pts", true) {
            if pts_dir.node == Some(resolved.parent) {
                if let Ok(id) = std::str::from_utf8(&resolved.name)
                    .unwrap_or("")
                    .parse::<u64>()
                {
                    let pty = env.ptys.get(&id).cloned().ok_or(abi::ENOENT)?;
                    {
                        let mut pty = pty.borrow_mut();
                        pty.slaves += 1;
                        pty.slave_ever_opened = true;
                        pty.activity += 1;
                        // Default the foreground group to the opener until a
                        // controlling process claims it (TIOCSCTTY).
                        if pty.fg_pgrp == 0 {
                            pty.fg_pgrp = env.proc.pgid;
                        }
                    }
                    let entry = FdEntry {
                        desc: std::rc::Rc::new(std::cell::RefCell::new(Description {
                            backing: Backing::PtySlave(pty),
                            offset: 0,
                            flags: flags & (abi::O_ACCMODE | abi::O_APPEND | abi::O_NONBLOCK),
                        })),
                        cloexec: flags & abi::O_CLOEXEC != 0,
                    };
                    return env.proc.fds.borrow_mut().insert(entry);
                }
            }
        }
    }

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
            let created = env.vfs.create(
                resolved.parent,
                &resolved.name,
                NodeKind::File(Vec::new()),
                mode,
            )?;
            // A watcher on the directory wants the entry's name; one on the
            // new file cannot exist yet, since it had nothing to watch.
            notify_inotify(env, resolved.parent, &resolved.name, abi::IN_CREATE, 0);
            created
        }
    };

    let backing = match &env.vfs.node(node).kind {
        NodeKind::Dir(_) => {
            if flags & abi::O_ACCMODE != abi::O_RDONLY {
                return Err(abi::EISDIR);
            }
            Backing::Dir { node, cookie: 0 }
        }
        NodeKind::File(_) | NodeKind::ChunkedFile(_) => {
            if flags & abi::O_DIRECTORY != 0 {
                return Err(abi::ENOTDIR);
            }
            if env.is_host_secret_node(node)
                && (env.host_secret_for_node(node).is_none()
                    || flags & abi::O_ACCMODE != abi::O_RDONLY)
            {
                return Err(abi::EACCES);
            }
            if flags & abi::O_TRUNC != 0 && flags & abi::O_ACCMODE != abi::O_RDONLY {
                // Truncation discards the immutable base view. It does not
                // need to fetch bytes that are being replaced with nothing.
                env.vfs.node_mut(node).kind = NodeKind::File(Vec::new());
            }
            Backing::File { node }
        }
        NodeKind::CharDev(Dev::Ptmx) => {
            // Opening the pty multiplexor allocates a fresh master.
            let id = env.next_pty_id;
            env.next_pty_id += 1;
            let pty = std::rc::Rc::new(std::cell::RefCell::new(crate::fd::Pty::new(id)));
            env.ptys.insert(id, std::rc::Rc::clone(&pty));
            Backing::PtyMaster(pty)
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
        Backing::File { node } if env.is_host_secret_node(*node) => env
            .host_secret_for_node(*node)
            .map(|value| value.len() as u64)
            .ok_or(abi::EACCES)?,
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
        let remaining = count.min(usize::MAX as u64) as usize - out.len();
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
    write_mem(env, cpu, dirp, &out)?;
    Ok(out.len() as u64)
}

// ── stat family ─────────────────────────────────────────────────────────────

fn stat_of_node(env: &LinuxEnv, node: usize) -> abi::Stat {
    let n = env.vfs.node(node);
    let size = env
        .host_secret_for_node(node)
        .map_or_else(|| n.size(), |value| value.len() as u64) as i64;
    abi::Stat {
        dev: 1,
        ino: node as u64 + 1,
        nlink: n.nlink,
        mode: n.file_type_bits() | (n.mode & 0o7777),
        uid: env.proc.uid,
        gid: env.proc.gid,
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
        Backing::Std(_) | Backing::Dev(Dev::Tty) | Backing::PtyMaster(_) | Backing::PtySlave(_) => {
            abi::Stat {
                dev: 1,
                ino: u64::MAX,
                nlink: 1,
                mode: abi::S_IFCHR | 0o620,
                rdev: (136 << 8),
                blksize: 1024,
                ..Default::default()
            }
        }
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
        // Anonymous inodes (eventfd/timerfd/epoll/inotify).
        Backing::EventFd(_) | Backing::TimerFd(_) | Backing::Epoll(_) | Backing::Inotify(_) => {
            abi::Stat {
                dev: 1,
                ino: u64::MAX - 3,
                nlink: 1,
                mode: 0o600,
                blksize: 4096,
                ..Default::default()
            }
        }
    })
}

fn sys_fstat(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, buf: u64) -> SysResult {
    let stat = stat_of_fd(env, fd)?;
    write_mem(env, cpu, buf, &stat.encode())?;
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
    let path = path_arg(env, cpu, path_ptr)?;
    let base = dir_of(env, dirfd)?;
    let resolved = env.vfs.resolve(base, &path, follow)?;
    let stat = match resolved.node {
        Some(node) => stat_of_node(env, node),
        // A pty slave is a kernel-created character device rather than a
        // persistent VFS node. It must nevertheless be visible to path-based
        // stat after a runtime canonicalizes stdin through `/proc/self/fd/0`.
        // Bun performs exactly that sequence before deciding whether to enter
        // its interactive frontend.
        None => stat_of_dynamic_pty(env, resolved.parent, &resolved.name).ok_or(abi::ENOENT)?,
    };
    write_mem(env, cpu, buf, &stat.encode())?;
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
    let path = path_arg(env, cpu, path_ptr)?;
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
    let path = path_arg(env, cpu, path_ptr)?;
    let stat = if path.is_empty() && flags & abi::AT_EMPTY_PATH != 0 {
        stat_of_fd(env, dirfd)?
    } else {
        let base = dir_of(env, dirfd)?;
        let follow = flags & abi::AT_SYMLINK_NOFOLLOW == 0;
        let resolved = env.vfs.resolve(base, &path, follow)?;
        match resolved.node {
            Some(node) => stat_of_node(env, node),
            None => stat_of_dynamic_pty(env, resolved.parent, &resolved.name).ok_or(abi::ENOENT)?,
        }
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
    // stx_rdev_major/minor (kernel offsets 128/132) are what callers use to
    // recognize a character device as a Linux pty (major 136), distinct from
    // stx_dev_major/minor below which names the containing filesystem.
    // Leaving these zero makes every pty fd look like an unrecognized char
    // device to anything that classifies ttys via statx instead of fstat.
    put(128, &((stat.rdev >> 8) as u32).to_le_bytes());
    put(132, &((stat.rdev & 0xff) as u32).to_le_bytes());
    for (base, sec, nsec) in [
        (64, stat.atime_sec, stat.atime_nsec),
        (96, stat.ctime_sec, stat.ctime_nsec),
        (112, stat.mtime_sec, stat.mtime_nsec),
    ] {
        put(base, &sec.to_le_bytes());
        put(base + 8, &(nsec as u32).to_le_bytes());
    }
    put(136, &1_u32.to_le_bytes()); // dev_major
    write_mem(env, cpu, buf, &out)?;
    Ok(0)
}

/// Metadata for a live `/dev/pts/<id>` slave. The VFS deliberately does not
/// materialize a node for every allocated pty, but Linux exposes each one to
/// both `open(2)` and `stat(2)` while its master exists.
fn stat_of_dynamic_pty(env: &LinuxEnv, parent: usize, name: &[u8]) -> Option<abi::Stat> {
    let pts_dir = env.vfs.resolve(crate::vfs::ROOT, b"/dev/pts", true).ok()?;
    if pts_dir.node != Some(parent) {
        return None;
    }
    let id = std::str::from_utf8(name).ok()?.parse::<u64>().ok()?;
    env.ptys.get(&id)?;
    Some(abi::Stat {
        dev: 1,
        // Keep the dynamic device distinguishable from an fd's generic
        // synthetic inode while retaining stable metadata for its lifetime.
        ino: u64::MAX.saturating_sub(id),
        nlink: 1,
        mode: abi::S_IFCHR | 0o620,
        rdev: 136 << 8,
        blksize: 1024,
        ..Default::default()
    })
}

fn sys_faccessat(env: &mut LinuxEnv, cpu: &mut Cpu, dirfd: u64, path_ptr: u64) -> SysResult {
    let path = path_arg(env, cpu, path_ptr)?;
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
    let path = path_arg(env, cpu, path_ptr)?;
    let pid_cwd = format!("/proc/{}/cwd", env.proc.pid);
    let pid_fd_prefix = format!("/proc/{}/fd/", env.proc.pid);
    let target = if path == b"/proc/self/exe" {
        env.proc.exe_path.clone()
    } else if path == b"/proc/self/cwd" || path == pid_cwd.as_bytes() {
        // Runtimes use this procfs symlink to canonicalize their startup
        // directory. It must agree with getcwd(2), not with the advisory
        // PWD environment variable. Answer it directly because this VFS does
        // not materialize every procfs directory as a persistent inode.
        env.vfs.abs_path_of(env.proc.cwd)
    } else if let Some(fd_text) = path
        .strip_prefix(b"/proc/self/fd/")
        .or_else(|| path.strip_prefix(pid_fd_prefix.as_bytes()))
    {
        let fd = std::str::from_utf8(fd_text)
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or(abi::ENOENT)?;
        let fds = env.proc.fds.borrow();
        let desc = fds.get(fd)?.desc.borrow();
        match &desc.backing {
            Backing::File { node } | Backing::Dir { node, .. } => env.vfs.abs_path_of(*node),
            Backing::Std(StdStream::In) => b"/dev/stdin".to_vec(),
            Backing::Std(StdStream::Out) => b"/dev/stdout".to_vec(),
            Backing::Std(StdStream::Err) => b"/dev/stderr".to_vec(),
            Backing::Dev(crate::vfs::Dev::Null) => b"/dev/null".to_vec(),
            Backing::Dev(crate::vfs::Dev::Zero) => b"/dev/zero".to_vec(),
            Backing::Dev(crate::vfs::Dev::Random) => b"/dev/urandom".to_vec(),
            Backing::Dev(crate::vfs::Dev::Ptmx) => b"/dev/ptmx".to_vec(),
            Backing::Dev(crate::vfs::Dev::Tty) | Backing::PtyMaster(_) | Backing::PtySlave(_) => {
                b"/dev/pts/0".to_vec()
            }
            // These kernel-created objects have no namespace path. A stable
            // Linux-style descriptor is sufficient for callers which only
            // need to distinguish an anonymous endpoint from a directory.
            Backing::Pipe { .. } => format!("pipe:[{fd}]").into_bytes(),
            Backing::SocketPair { .. } | Backing::Net(_) => format!("socket:[{fd}]").into_bytes(),
            Backing::EventFd(_) => format!("anon_inode:[eventfd:{fd}]").into_bytes(),
            Backing::TimerFd(_) => format!("anon_inode:[timerfd:{fd}]").into_bytes(),
            Backing::Epoll(_) => format!("anon_inode:[eventpoll:{fd}]").into_bytes(),
            Backing::Inotify(_) => format!("anon_inode:[inotify:{fd}]").into_bytes(),
        }
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
    write_mem(env, cpu, buf, &target[..n])?;
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
    let path = path_arg(env, cpu, path_ptr)?;
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
    let path = path_arg(env, cpu, path_ptr)?;
    let base = dir_of(env, dirfd)?;
    let resolved = env.vfs.resolve(base, &path, false)?;
    let gone = resolved.node;
    let was_dir = gone.is_some_and(|node| env.vfs.is_dir(node));
    env.vfs.unlink(
        resolved.parent,
        &resolved.name,
        flags & abi::AT_REMOVEDIR != 0,
    )?;
    let dir_bit = if was_dir { abi::IN_ISDIR } else { 0 };
    notify_inotify(
        env,
        resolved.parent,
        &resolved.name,
        abi::IN_DELETE | dir_bit,
        0,
    );
    if let Some(node) = gone {
        // The watch on the thing itself outlives the name, so it is told
        // separately that the thing it was watching is gone.
        notify_inotify(env, node, b"", abi::IN_DELETE_SELF, 0);
    }
    // Usually nothing had it open and the bytes go now; when something does,
    // the close reclaims them.
    env.reclaim_unlinked();
    Ok(0)
}

fn sys_renameat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    old_dirfd: u64,
    old_ptr: u64,
    new_dirfd: u64,
    new_ptr: u64,
) -> SysResult {
    let old_path = path_arg(env, cpu, old_ptr)?;
    let new_path = path_arg(env, cpu, new_ptr)?;
    let old_base = dir_of(env, old_dirfd)?;
    let new_base = dir_of(env, new_dirfd)?;
    let old = env.vfs.resolve(old_base, &old_path, false)?;
    let new = env.vfs.resolve(new_base, &new_path, false)?;
    let moved = old.node;
    let was_dir = moved.is_some_and(|node| env.vfs.is_dir(node));
    env.vfs
        .rename(old.parent, &old.name, new.parent, &new.name)?;
    // A rename onto an existing name unlinks what was there; reclaim it the
    // same way `unlinkat` does, so nothing keeps the replaced version alive.
    env.reclaim_unlinked();
    // The two halves share a cookie, which is the only thing that lets a
    // watcher tell a rename from a delete followed by an unrelated create.
    let cookie = next_inotify_cookie(env);
    let dir_bit = if was_dir { abi::IN_ISDIR } else { 0 };
    notify_inotify(
        env,
        old.parent,
        &old.name,
        abi::IN_MOVED_FROM | dir_bit,
        cookie,
    );
    notify_inotify(
        env,
        new.parent,
        &new.name,
        abi::IN_MOVED_TO | dir_bit,
        cookie,
    );
    if let Some(node) = moved {
        notify_inotify(env, node, b"", abi::IN_MOVE_SELF, 0);
    }
    Ok(0)
}

fn sys_linkat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    old_dirfd: u64,
    old_ptr: u64,
    new_dirfd: u64,
    new_ptr: u64,
) -> SysResult {
    let old_path = path_arg(env, cpu, old_ptr)?;
    let new_path = path_arg(env, cpu, new_ptr)?;
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
    let target = path_arg(env, cpu, target_ptr)?;
    let path = path_arg(env, cpu, path_ptr)?;
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
    let path = path_arg(env, cpu, path_ptr)?;
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
    write_mem(env, cpu, buf, &path)?;
    Ok(path.len() as u64)
}

fn sys_chmodat(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    dirfd: u64,
    path_ptr: u64,
    mode: u64,
) -> SysResult {
    let path = path_arg(env, cpu, path_ptr)?;
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
    // dup2/dup3 atomically close an occupied destination before installing
    // the duplicate. Route that implicit close through the epoll cleanup used
    // by close(2), otherwise the replacement can inherit the old descriptor's
    // registration and disabled ONESHOT state.
    if env.proc.fds.borrow().get(new_fd).is_ok() {
        close_fd(env, new_fd)?;
    }
    env.proc.fds.borrow_mut().insert_at(
        new_fd,
        FdEntry {
            desc: entry.desc,
            cloexec,
        },
    )
}

fn sys_fcntl(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, cmd: u64, arg: u64) -> SysResult {
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
        // Advisory record locks: a single guest has no competing lock
        // holders, so setting always succeeds and querying reports unlocked
        // (l_type = F_UNLCK in the caller's struct flock). The open-file-
        // description variants get the same answer — SQLite tries those first.
        abi::F_SETLK | abi::F_SETLKW | abi::F_OFD_SETLK | abi::F_OFD_SETLKW => {
            env.proc.fds.borrow().get(fd)?;
            Ok(0)
        }
        abi::F_GETLK | abi::F_OFD_GETLK => {
            env.proc.fds.borrow().get(fd)?;
            // struct flock: l_type i16 at 0, l_pid i32 at 24. Report the range
            // unlocked, leaving whence/start/len as the caller wrote them.
            write_mem(env, cpu, arg, &abi::F_UNLCK.to_le_bytes())?;
            write_mem(env, cpu, arg + 24, &0u32.to_le_bytes())?;
            Ok(0)
        }
        _ => {
            tracing::debug!("fcntl: unsupported cmd {cmd}");
            Err(abi::EINVAL)
        }
    }
}

/// Drop queued bytes on one or both directions of a pty.
///
/// Which queue is "input" depends on the side asking: the slave reads what
/// the master wrote, and the master reads what the slave wrote.
fn flush_pty(pty: &mut crate::fd::Pty, is_master: bool, input: bool, output: bool) {
    let (incoming, outgoing) = if is_master {
        (&mut pty.s2m, &mut pty.m2s)
    } else {
        (&mut pty.m2s, &mut pty.s2m)
    };
    if input {
        incoming.clear();
    }
    if output {
        outgoing.clear();
    }
    pty.activity += 1;
}

fn outcome_ioctl(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, request: u64, arg: u64) -> Outcome {
    if matches!(
        request,
        abi::TCSETS | abi::TCSETSW | abi::TCSETSF | abi::TIOCSPGRP
    ) {
        let pty = env.proc.fds.borrow().get(fd).ok().and_then(|entry| {
            match &entry.desc.borrow().backing {
                Backing::PtyMaster(pty) | Backing::PtySlave(pty) => Some(std::rc::Rc::clone(pty)),
                _ => None,
            }
        });
        if let Some(pty) = pty {
            if let Some(outcome) = background_tty_ioctl(env, cpu, &pty) {
                return outcome;
            }
        }
    }
    sys_ioctl(env, cpu, fd, request, arg).into()
}

fn sys_ioctl(env: &mut LinuxEnv, cpu: &mut Cpu, fd: u64, request: u64, arg: u64) -> SysResult {
    // General fd ioctls, valid on any descriptor. These must be handled
    // before the tty gate: FIONBIO in particular is how a runtime sets a
    // socket or pipe non-blocking, and returning ENOTTY there breaks it.
    match request {
        abi::FIONBIO => {
            let val = i32::from_le_bytes(read_mem(env, cpu, arg, 4)?.try_into().expect("4 bytes"));
            let desc = env.proc.fds.borrow().get(fd)?.desc.clone();
            let mut desc = desc.borrow_mut();
            if val != 0 {
                desc.flags |= abi::O_NONBLOCK;
            } else {
                desc.flags &= !abi::O_NONBLOCK;
            }
            return Ok(0);
        }
        abi::FIOCLEX => {
            env.proc.fds.borrow_mut().get_mut(fd)?.cloexec = true;
            return Ok(0);
        }
        abi::FIONCLEX => {
            env.proc.fds.borrow_mut().get_mut(fd)?.cloexec = false;
            return Ok(0);
        }
        abi::FIONREAD => {
            let fds = env.proc.fds.borrow();
            let desc = fds.get(fd)?.desc.borrow();
            let n: u32 = match &desc.backing {
                Backing::Pipe {
                    inner,
                    write_end: false,
                } => inner.borrow().data.len() as u32,
                Backing::SocketPair { rx, .. } => rx.borrow().data.len() as u32,
                Backing::Net(socket) => {
                    let socket = socket.borrow();
                    match socket.kind {
                        SocketKind::NetlinkRoute => socket.local_rx.len() as u32,
                        SocketKind::Unix => 0,
                        SocketKind::Tcp | SocketKind::Udp => match socket.handle {
                            Some(handle) => socket
                                .broker
                                .borrow_mut()
                                .pending_read_bytes(handle)?
                                .unwrap_or(0)
                                .min(u32::MAX as usize)
                                as u32,
                            None => 0,
                        },
                    }
                }
                _ => 0,
            };
            drop(desc);
            drop(fds);
            write_mem(env, cpu, arg, &n.to_le_bytes())?;
            return Ok(0);
        }
        _ => {}
    }

    // Pseudoterminal ioctls carry per-pty termios and window size.
    let pty = match &env.proc.fds.borrow().get(fd)?.desc.borrow().backing {
        Backing::PtyMaster(pty) => Some((std::rc::Rc::clone(pty), true)),
        Backing::PtySlave(pty) => Some((std::rc::Rc::clone(pty), false)),
        _ => None,
    };
    if let Some((pty, is_master)) = pty {
        match request {
            // These are ioctls on the `/dev/ptmx` master. A slave fd must
            // reject them with ENOTTY, matching Linux. Keep the endpoint
            // distinction explicit: a program may probe both a terminal slave
            // and a pty allocator while setting up its terminal backend.
            abi::TIOCGPTN if is_master => {
                let id = pty.borrow().id as u32;
                write_mem(env, cpu, arg, &id.to_le_bytes())?;
                return Ok(0);
            }
            abi::TIOCSPTLCK if is_master => return Ok(0), // slave unlock: always unlocked
            abi::TCGETS => {
                let termios = pty.borrow().termios;
                write_mem(env, cpu, arg, &termios)?;
                return Ok(0);
            }
            abi::TCSETS | abi::TCSETSW | abi::TCSETSF => {
                let bytes = read_mem(env, cpu, arg, 36)?;
                let mut pty = pty.borrow_mut();
                pty.termios.copy_from_slice(&bytes);
                // TCSETSF (tcsetattr's TCSAFLUSH) discards input the caller
                // has not read before the new settings take effect, so that
                // keystrokes typed under the old mode are not reinterpreted
                // under the new one.
                if request == abi::TCSETSF {
                    flush_pty(&mut pty, is_master, true, false);
                }
                return Ok(0);
            }
            abi::TCFLSH => {
                // TCIFLUSH = 0, TCOFLUSH = 1, TCIOFLUSH = 2.
                let (input, output) = match arg {
                    0 => (true, false),
                    1 => (false, true),
                    2 => (true, true),
                    _ => return Err(abi::EINVAL),
                };
                flush_pty(&mut pty.borrow_mut(), is_master, input, output);
                return Ok(0);
            }
            abi::TIOCGWINSZ => {
                let ws = pty.borrow().winsize;
                let bytes: Vec<u8> = ws.iter().flat_map(|v| v.to_le_bytes()).collect();
                write_mem(env, cpu, arg, &bytes)?;
                return Ok(0);
            }
            abi::TIOCSWINSZ => {
                let bytes = read_mem(env, cpu, arg, 8)?;
                let pgrp = {
                    let mut pty = pty.borrow_mut();
                    for (i, w) in pty.winsize.iter_mut().enumerate() {
                        *w = u16::from_le_bytes(bytes[2 * i..2 * i + 2].try_into().expect("size"));
                    }
                    pty.activity += 1;
                    pty.fg_pgrp
                };
                // A window-size change notifies the foreground group so a TUI
                // can redraw. SIGWINCH == 28.
                deliver_signal_to_pgrp(env, pgrp, 28);
                return Ok(0);
            }
            abi::TIOCSCTTY => {
                // The caller claims this pty as its controlling terminal and
                // becomes the foreground group.
                let mut pty = pty.borrow_mut();
                pty.fg_pgrp = env.proc.pgid;
                pty.session_id = env.proc.sid;
                return Ok(0);
            }
            abi::TIOCSPGRP => {
                let bytes = read_mem(env, cpu, arg, 4)?;
                pty.borrow_mut().fg_pgrp =
                    u32::from_le_bytes(bytes.try_into().expect("size")) as u64;
                return Ok(0);
            }
            abi::TIOCGPGRP => {
                let pgrp = pty.borrow().fg_pgrp as u32;
                write_mem(env, cpu, arg, &pgrp.to_le_bytes())?;
                return Ok(0);
            }
            abi::TIOCGSID => {
                let sid = pty.borrow().session_id as u32;
                write_mem(env, cpu, arg, &sid.to_le_bytes())?;
                return Ok(0);
            }
            abi::TIOCNOTTY => return Ok(0),
            _ => {
                tracing::debug!("pty ioctl: unsupported request {request:#x}");
                return Err(abi::ENOTTY);
            }
        }
    }

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
            write_mem(env, cpu, arg, &bytes)?;
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
            write_mem(env, cpu, arg, &termios)?;
            Ok(0)
        }
        abi::TCSETS
        | abi::TCSETSW
        | abi::TCSETSF
        | abi::TCFLSH
        | abi::TIOCSWINSZ
        | abi::TIOCSPGRP
        | abi::TIOCSCTTY
        | abi::TIOCNOTTY => Ok(0),
        abi::TIOCGPGRP => {
            write_mem(env, cpu, arg, &(PID as u32).to_le_bytes())?;
            Ok(0)
        }
        abi::TIOCGSID => {
            write_mem(env, cpu, arg, &(env.proc.sid as u32).to_le_bytes())?;
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
    const POLLRDHUP: u16 = 0x2000;

    let now = env.now_nanos(cpu);
    let nfds = nfds.min(1024) as usize;
    let mut records = read_mem(env, cpu, fds_ptr, nfds * 8)?;
    let mut ready = 0_u64;
    for record in records.as_chunks_mut::<8>().0 {
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
                if events & POLLRDHUP != 0 && desc_net_read_closed(&desc) {
                    bits |= POLLRDHUP;
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
    write_mem(env, cpu, fds_ptr, &records)?;
    Ok(ready)
}

/// Read-readiness of a description at deterministic time `now`.
fn desc_read_ready(desc: &Description, now: u64) -> bool {
    match read_watch_of(desc) {
        Some(watch) => watch.ready(now),
        None => true,
    }
}

/// Write-readiness. A host-driven TCP socket becomes writable only after the
/// host reports connect completion (or failure), matching non-blocking Linux.
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
        Backing::Net(socket) if socket.borrow().kind == SocketKind::Tcp => {
            let socket = socket.borrow();
            socket.handle.is_some_and(|handle| {
                !matches!(
                    socket.broker.borrow_mut().tcp_connect_status(handle),
                    crate::net::ConnectStatus::Pending
                )
            })
        }
        _ => true,
    }
}

/// Whether a TCP peer has closed its write half. Linux exposes this separately
/// from ordinary readability through `POLLRDHUP`/`EPOLLRDHUP`.
fn desc_net_read_closed(desc: &Description) -> bool {
    let Backing::Net(socket) = &desc.backing else {
        return false;
    };
    let socket = socket.borrow();
    if socket.kind != SocketKind::Tcp {
        return false;
    }
    socket
        .handle
        .is_some_and(|handle| socket.broker.borrow_mut().tcp_read_closed(handle))
}

/// The readiness source for a descriptor that is not currently writable.
fn write_watch_of(desc: &Description) -> Option<crate::proc::Watch> {
    use crate::proc::Watch;
    match &desc.backing {
        Backing::Pipe {
            inner,
            write_end: true,
        }
        | Backing::SocketPair { tx: inner, .. } => Some(Watch::PipeWritable(inner.clone())),
        Backing::Net(socket) if socket.borrow().kind == SocketKind::Tcp => {
            Some(Watch::NetWritable(socket.clone()))
        }
        _ => None,
    }
}

/// The activity counter of `desc`'s backing (pipes, socketpairs, eventfds):
/// a monotone value that moves on every write/read/close. Zero for backings
/// without one.
fn backing_activity(desc: &Description) -> u64 {
    match &desc.backing {
        Backing::Pipe { inner, .. } => inner.borrow().activity,
        Backing::SocketPair { rx, tx } => rx.borrow().activity + tx.borrow().activity,
        Backing::EventFd(event) => event.borrow().activity,
        Backing::Inotify(inner) => inner.borrow().activity,
        Backing::Net(socket) => socket.borrow().activity_generation(),
        Backing::PtyMaster(pty) | Backing::PtySlave(pty) => pty.borrow().activity,
        _ => 0,
    }
}

/// The watch that fires when `desc`'s activity counter moves; None for
/// backings without a counter.
fn activity_watch_of(desc: &Description) -> Option<crate::proc::Watch> {
    use crate::proc::Watch;
    match &desc.backing {
        Backing::Pipe { inner, .. } => {
            Some(Watch::PipeActivity(inner.clone(), inner.borrow().activity))
        }
        // Either direction of a socketpair re-arms on its own pipe's counter;
        // watch the receive side (sends by the peer land there) and the send
        // side (drains by the peer land there) separately.
        Backing::SocketPair { rx, .. } => {
            Some(Watch::PipeActivity(rx.clone(), rx.borrow().activity))
        }
        Backing::EventFd(event) => {
            Some(Watch::EventActivity(event.clone(), event.borrow().activity))
        }
        Backing::Net(socket) => Some(Watch::NetActivity(
            socket.clone(),
            socket.borrow().activity_generation(),
        )),
        Backing::PtyMaster(pty) | Backing::PtySlave(pty) => {
            Some(Watch::PtyActivity(pty.clone(), pty.borrow().activity))
        }
        _ => None,
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
        Backing::PtyMaster(pty) => Some(Watch::PtyReadable(pty.clone(), true)),
        Backing::PtySlave(pty) => Some(Watch::PtyReadable(pty.clone(), false)),
        Backing::Inotify(inner) => Some(Watch::InotifyReadable(inner.clone())),
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

/// Writes every `MAP_SHARED` mapping overlapping `[addr, addr+len)` back to
/// its file, capped by the file's current length (an `ftruncate` may have
/// shrunk it since the map was made).
fn sync_shared_range(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64, len: u64) {
    let end = addr.saturating_add(len);
    let maps: Vec<crate::SharedMap> = env
        .shared_maps
        .iter()
        .copied()
        .filter(|map| {
            map.asid == env.proc.asid && map.addr < end && map.addr.saturating_add(map.len) > addr
        })
        .collect();
    for map in maps {
        let mut bytes = vec![0_u8; map.len as usize];
        if cpu
            .mem
            .read_bytes(map.addr, &mut bytes, icicle_cpu::mem::perm::NONE)
            .is_err()
        {
            continue;
        }
        let node = env.vfs.node_mut(map.node);
        if let NodeKind::File(data) = &mut node.kind {
            let start = (map.offset as usize).min(data.len());
            let take = bytes.len().min(data.len() - start);
            data[start..start + take].copy_from_slice(&bytes[..take]);
        }
    }
}

fn sys_mmap(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    let [addr, len, prot, flags, fd, offset] = a;
    if len == 0 {
        return Err(abi::EINVAL);
    }
    if flags & abi::MAP_ANONYMOUS == 0 && offset & (PAGE_SIZE - 1) != 0 {
        return Err(abi::EINVAL);
    }
    let len = align_up(len, PAGE_SIZE);
    let target = if flags & abi::MAP_FIXED != 0 && addr != 0 {
        let target = addr & !(PAGE_SIZE - 1);
        // MAP_FIXED replaces any existing mapping.
        cpu.mem.unmap_memory_len(target, len);
        env.pager.unmap(env.proc.asid, target, len);
        env.forget_file_backed_range(env.proc.asid, target, len);
        target
    } else if addr != 0
        && addr & (PAGE_SIZE - 1) == 0
        && cpu
            .mem
            .find_free_memory(icicle_cpu::mem::AllocLayout {
                addr: Some(addr),
                size: len,
                align: PAGE_SIZE,
            })
            .is_ok_and(|found| found == addr)
    {
        // A page-aligned hint whose range is free is honored, exactly as
        // Linux does. Software may legitimately depend on that: JSC hints
        // the addresses of its caged heaps and later derives pointers from
        // where it asked, not only from where it looked.
        addr
    } else {
        // Find an actual free hole at or above the allocation hint; a plain
        // bump allocator collides with existing mappings once the guest
        // reserves large regions (V8's 256 MiB sandbox does exactly this).
        // Hand out 64 KiB-aligned addresses: allocators that want aligned
        // segments (mimalloc probes for 16 KiB alignment) otherwise retry
        // `mmap` a few times and give up, and address space is free here.
        let hint = env.proc.mmap_next.get();
        match cpu.mem.find_free_memory(icicle_cpu::mem::AllocLayout {
            addr: Some(hint),
            size: len,
            align: 0x1_0000,
        }) {
            Ok(target) => {
                env.proc.mmap_next.set(target + len + PAGE_SIZE);
                target
            }
            Err(_) => return Err(abi::ENOMEM),
        }
    };

    let mut lazy_file = None;
    let mut shared_node = None;
    let file_bytes = if flags & abi::MAP_ANONYMOUS == 0 {
        let node = match env.proc.fds.borrow().get(fd)?.desc.borrow().backing {
            Backing::File { node } => node,
            _ => return Err(abi::EBADF),
        };
        if env.is_host_secret_node(node) {
            return Err(abi::ENODEV);
        }
        // A MAP_SHARED file mapping: the pages are filled eagerly and written
        // back to the file at msync/munmap. SQLite's WAL shared-memory file —
        // mapped read/write once per process — is the workload; a plain File
        // node is required (a manifest-backed image is never mapped shared).
        if flags & abi::MAP_SHARED != 0 {
            if !matches!(env.vfs.node(node).kind, NodeKind::File(_)) {
                return Err(abi::ENODEV);
            }
            shared_node = Some(node);
        }
        match &env.vfs.node(node).kind {
            NodeKind::File(data) => {
                let start = offset_into(offset, data.len());
                let end = (start + guest_size(len)?).min(data.len());
                Some(data[start..end].to_vec())
            }
            NodeKind::ChunkedFile(file) => {
                let file_len = file.size.saturating_sub(offset).min(len);
                lazy_file = Some((file.clone(), file_len));
                None
            }
            _ => return Err(abi::EBADF),
        }
    } else {
        None
    };

    // A lazy mapping is initialized but has no access permission, so its first
    // read, write, or instruction fetch reaches the pager. Resident mappings
    // stay writable while their eager bytes are copied.
    let initial_perm = if lazy_file.is_some() {
        perm::INIT
    } else {
        perm::READ | perm::WRITE | perm::INIT
    };
    let ok = cpu.mem.map_memory_len(
        target,
        len,
        icicle_cpu::mem::Mapping {
            perm: initial_perm,
            value: 0,
        },
    );
    if !ok {
        tracing::warn!("mmap: map_memory_len failed for {len:#x} at {target:#x}");
        return Err(abi::ENOMEM);
    }
    if let Some(bytes) = file_bytes {
        write_mem(env, cpu, target, &bytes)?;
    }
    let final_perm = prot_to_perm(prot);
    if let Some(node) = shared_node {
        env.shared_maps.push(crate::SharedMap {
            asid: env.proc.asid,
            addr: target,
            len,
            node,
            offset,
        });
    }
    let file_backed = flags & abi::MAP_ANONYMOUS == 0;
    if file_backed {
        env.record_file_backed_range(env.proc.asid, target, len);
    }
    if let Some((file, file_len)) = lazy_file {
        if file_len > 0 {
            let mapping = crate::pager::FileMapping::new(
                target,
                target + len,
                target,
                offset,
                file_len,
                final_perm,
                0,
                file,
            )
            .map_err(|_| abi::EINVAL)?;
            env.pager.map(env.proc.asid, mapping);
            return Ok(target);
        }
    }
    if let Err(e) = cpu.mem.update_perm(target, len, final_perm) {
        tracing::warn!("mmap: update_perm failed for {len:#x} at {target:#x}: {e:?}");
        return Err(abi::ENOMEM);
    }
    Ok(target)
}

/// Applies the observable part of `madvise(2)`.
///
/// Most advice values are performance hints and may legitimately be ignored.
/// `MADV_DONTNEED` is different: on anonymous private memory Linux guarantees
/// that subsequent reads observe zero-filled pages. Returning success while
/// retaining old bytes leaks one allocation into the next and breaks real
/// allocators (JSC/Bun uses this as its page-discard primitive).
fn restore_executable_file_range(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr: u64,
    len: u64,
) -> Result<bool, u64> {
    let Some(elf_addr) = addr.checked_sub(env.exe_load_offset) else {
        return Ok(false);
    };
    let Some(elf_end) = elf_addr.checked_add(len) else {
        return Err(abi::ENOMEM);
    };
    let resolved = env
        .vfs
        .resolve(env.proc.cwd, &env.proc.exe_path, true)
        .map_err(|_| abi::EINVAL)?;
    let Some(node) = resolved.node else {
        return Ok(false);
    };
    let restored = {
        let file = env.vfs.materialize_file(node).map_err(|_| abi::EINVAL)?;
        if file.len() < 64 || &file[..4] != b"\x7fELF" || file[4] != 2 || file[5] != 1 {
            return Ok(false);
        }
        let u16_at = |at: usize| -> Option<u16> {
            Some(u16::from_le_bytes(file.get(at..at + 2)?.try_into().ok()?))
        };
        let u32_at = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(file.get(at..at + 4)?.try_into().ok()?))
        };
        let u64_at = |at: usize| -> Option<u64> {
            Some(u64::from_le_bytes(file.get(at..at + 8)?.try_into().ok()?))
        };
        let phoff = u64_at(32).ok_or(abi::EINVAL)? as usize;
        let phentsize = u16_at(54).ok_or(abi::EINVAL)? as usize;
        let phnum = u16_at(56).ok_or(abi::EINVAL)? as usize;
        if phentsize < 56 {
            return Err(abi::EINVAL);
        }
        let mut bytes = None;
        for index in 0..phnum {
            let Some(at) = phoff.checked_add(index.saturating_mul(phentsize)) else {
                return Err(abi::EINVAL);
            };
            if u32_at(at) != Some(1) {
                continue; // PT_LOAD
            }
            let file_offset = u64_at(at + 8).ok_or(abi::EINVAL)?;
            let vaddr = u64_at(at + 16).ok_or(abi::EINVAL)?;
            let file_size = u64_at(at + 32).ok_or(abi::EINVAL)?;
            let mem_size = u64_at(at + 40).ok_or(abi::EINVAL)?;
            let Some(segment_end) = vaddr.checked_add(mem_size) else {
                return Err(abi::EINVAL);
            };
            if elf_addr < vaddr || elf_end > segment_end {
                continue;
            }
            let size = usize::try_from(len).map_err(|_| abi::ENOMEM)?;
            let mut image = vec![0_u8; size];
            let file_backed_end = vaddr.saturating_add(file_size);
            let copy_end = elf_end.min(file_backed_end);
            if copy_end > elf_addr {
                let relative = elf_addr - vaddr;
                let source_start = file_offset.checked_add(relative).ok_or(abi::EINVAL)? as usize;
                let copy_len = usize::try_from(copy_end - elf_addr).map_err(|_| abi::ENOMEM)?;
                let source_end = source_start.checked_add(copy_len).ok_or(abi::EINVAL)?;
                let source = file.get(source_start..source_end).ok_or(abi::EINVAL)?;
                image[..copy_len].copy_from_slice(source);
            }
            bytes = Some(image);
            break;
        }
        bytes
    };
    let Some(restored) = restored else {
        return Ok(false);
    };
    cpu.mem
        .write_bytes(addr, &restored, perm::WRITE)
        .map_err(|_| abi::ENOMEM)?;
    Ok(true)
}

fn sys_madvise(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64, len: u64, advice: u64) -> SysResult {
    const MADV_DONTNEED: u64 = 4;
    const MADV_DONTFORK: u64 = 10;
    const MADV_DOFORK: u64 = 11;

    if len == 0 {
        return Ok(0);
    }
    if addr & (PAGE_SIZE - 1) != 0 {
        return Err(abi::EINVAL);
    }
    let len = len
        .checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
        .ok_or(abi::ENOMEM)?;
    let end = addr.checked_add(len).ok_or(abi::ENOMEM)?;

    if advice == MADV_DONTFORK {
        env.set_dontfork(env.proc.asid, addr, end);
        return Ok(0);
    }
    if advice == MADV_DOFORK {
        env.clear_dontfork(env.proc.asid, addr, end);
        return Ok(0);
    }
    if advice != MADV_DONTNEED {
        return match advice {
            // These are content-preserving performance/core-dump hints. The
            // kernel is allowed to take no immediate action, so success with
            // no state change is honest in this execution model.
            0..=3 // NORMAL, RANDOM, SEQUENTIAL, WILLNEED
            | 8 // FREE (the kernel may retain the pages indefinitely)
            | 12..=17 // MERGEABLE..DODUMP
            | 20..=23 // COLD, PAGEOUT, POPULATE_READ/WRITE
            | 25 => Ok(0), // COLLAPSE

            // REMOVE changes the backing store. WIPEONFORK/KEEPONFORK change
            // inherited contents, and DONTNEED_LOCKED has locking
            // preconditions. Unknown advice values are EINVAL too, which real
            // runtimes use as a feature probe.
            _ => Err(abi::EINVAL),
        };
    }

    // A MAP_SHARED mapping must first be reconciled with its mutable backing
    // file. Refuse that case instead of claiming success and substituting
    // zeros for file data. Immutable manifest-backed pages can be discarded
    // safely: make them inaccessible/nonresident and the existing pager will
    // restore their digest-pinned bytes on the next access.
    let touches_shared_file = env.shared_maps.iter().any(|mapping| {
        mapping.asid == env.proc.asid
            && mapping.addr < end
            && mapping.addr.saturating_add(mapping.len) > addr
    });
    if touches_shared_file {
        return Err(abi::EINVAL);
    }

    if env
        .file_backed_ranges
        .iter()
        .any(|mapping| mapping.asid == env.proc.asid && mapping.start <= addr && mapping.end >= end)
    {
        let eager = (addr..end)
            .step_by(PAGE_SIZE as usize)
            .all(|page| env.pager.page_state(env.proc.asid, page).is_none());
        if eager {
            // For an immutable private file mapping, retaining the clean
            // resident bytes is observationally identical to dropping and
            // faulting them back from the same file. This lets runtimes use
            // DONTNEED on read-only image data without requiring an eager
            // backing-file reloader. Writable private mappings may contain
            // dirty COW data and still require the full reload path.
            let writable = (addr..end)
                .step_by(PAGE_SIZE as usize)
                .any(|page| cpu.mem.get_perm(page) & perm::WRITE != 0);
            if !writable {
                return Ok(0);
            }
            if restore_executable_file_range(env, cpu, addr, len)? {
                return Ok(0);
            }
            return Err(abi::EINVAL);
        }
    }

    // `madvise` changes bytes from the host-side syscall implementation, so
    // it cannot take the normal guest-store exception path that the engine
    // uses for self-modifying code.  Detect an overlap *before* changing any
    // page: otherwise a multi-page DONTNEED can zero an initial page and
    // later fail on an executed one, leaving a partially mutated range while
    // its lifted p-code remains live.  Clear the MMU execution marks first;
    // the VM observes `invalidate_icache` after the syscall and atomically
    // drops its lifted-code arena before dispatching another guest block.
    let invalidates_code = (addr..end)
        .step_by(PAGE_SIZE as usize)
        .any(|page| cpu.mem.get_perm(page) & perm::IN_CODE_CACHE != 0);
    if invalidates_code {
        cpu.mem.clear_code_cache();
        cpu.mem.invalidate_icache = true;
    }

    let mut page = addr;
    while page < end {
        if env.pager.page_state(env.proc.asid, page).is_some() {
            cpu.mem
                .update_perm(page, PAGE_SIZE, perm::INIT)
                .map_err(|_| abi::ENOMEM)?;
        } else {
            cpu.mem
                .fill_mem(page, PAGE_SIZE, 0)
                .map_err(|_| abi::ENOMEM)?;
        }
        page += PAGE_SIZE;
    }
    env.pager.discard(env.proc.asid, addr, len);
    Ok(0)
}

/// `mremap`: resizes a mapping. Shrinking truncates in place; growing
/// allocates a fresh region, copies the old contents across, and unmaps the
/// old one (requires MREMAP_MAYMOVE, which allocators pass). Without this,
/// a large realloc returns NULL and Rust guests abort in
/// handle_alloc_error.
fn sys_mremap(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    const MREMAP_MAYMOVE: u64 = 1;
    const MREMAP_FIXED: u64 = 2;
    let [old_addr, old_size, new_size, flags, _new_addr, _] = a;
    if old_addr & (PAGE_SIZE - 1) != 0 || new_size == 0 || old_size == 0 {
        return Err(abi::EINVAL);
    }
    if flags & MREMAP_FIXED != 0 {
        tracing::warn!("mremap: MREMAP_FIXED is not supported");
        return Err(abi::EINVAL);
    }
    let old_size = align_up(old_size, PAGE_SIZE);
    let new_size = align_up(new_size, PAGE_SIZE);
    if new_size <= old_size {
        if new_size < old_size {
            cpu.mem
                .unmap_memory_len(old_addr + new_size, old_size - new_size);
            env.pager
                .unmap(env.proc.asid, old_addr + new_size, old_size - new_size);
            env.clear_dontfork(env.proc.asid, old_addr + new_size, old_addr + old_size);
        }
        return Ok(old_addr);
    }
    if flags & MREMAP_MAYMOVE == 0 {
        // In-place growth is never attempted; the caller must allow a move.
        return Err(abi::ENOMEM);
    }
    let old_was_file_backed = env.file_backed_ranges.iter().any(|mapping| {
        mapping.asid == env.proc.asid
            && mapping.start < old_addr.saturating_add(old_size)
            && mapping.end > old_addr
    });
    let hint = env.proc.mmap_next.get();
    let target = cpu
        .mem
        .find_free_memory(icicle_cpu::mem::AllocLayout {
            addr: Some(hint),
            size: new_size,
            align: PAGE_SIZE,
        })
        .map_err(|_| abi::ENOMEM)?;
    let ok = cpu.mem.map_memory_len(
        target,
        new_size,
        icicle_cpu::mem::Mapping {
            perm: perm::READ | perm::WRITE | perm::INIT,
            value: 0,
        },
    );
    if !ok {
        return Err(abi::ENOMEM);
    }
    let mut buf = vec![0u8; guest_size(old_size).map_err(|_| abi::ENOMEM)?];
    cpu.mem
        .read_bytes(old_addr, &mut buf, perm::NONE)
        .map_err(|_| abi::EFAULT)?;
    write_mem(env, cpu, target, &buf)?;
    cpu.mem.unmap_memory_len(old_addr, old_size);
    env.remap_dontfork(env.proc.asid, old_addr, old_addr + old_size, target);
    env.pager
        .remap(env.proc.asid, old_addr, old_size, target, new_size);
    env.forget_file_backed_range(env.proc.asid, old_addr, old_size);
    if old_was_file_backed {
        env.record_file_backed_range(env.proc.asid, target, new_size);
    }
    let mut page = target;
    while page < target + new_size {
        if let Some((resident, final_perm)) = env.pager.page_state(env.proc.asid, page) {
            let _ = cpu.mem.update_perm(
                page,
                PAGE_SIZE,
                if resident { final_perm } else { perm::INIT },
            );
        }
        page += PAGE_SIZE;
    }
    env.proc.mmap_next.set(target + new_size + PAGE_SIZE);
    Ok(target)
}

fn sys_mprotect(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64, len: u64, prot: u64) -> SysResult {
    let len = align_up(len, PAGE_SIZE);
    let new_perm = prot_to_perm(prot);
    match cpu.mem.update_perm(addr, len, new_perm) {
        Ok(()) => {
            env.pager.protect(env.proc.asid, addr, len, new_perm);
            // `mprotect` must update the recorded final permission without
            // accidentally making an unfetched page accessible.
            for page in env.pager.nonresident_pages(env.proc.asid, addr, len) {
                let _ = cpu.mem.update_perm(page, PAGE_SIZE, perm::INIT);
            }
            Ok(0)
        }
        Err(_) => Err(abi::ENOMEM),
    }
}

fn sys_brk(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64) -> SysResult {
    if addr == 0 || addr <= env.proc.brk_end.get() {
        return Ok(env.proc.brk_end.get());
    }
    let new_end = align_up(addr, PAGE_SIZE);
    let cur_end = align_up(env.proc.brk_end.get(), PAGE_SIZE);
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
            return Ok(env.proc.brk_end.get());
        }
    }
    env.proc.brk_end.set(addr);
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
    // SIGKILL and SIGSTOP cannot be caught, blocked, or ignored; changing
    // their disposition is refused, which is what keeps a forced stop or
    // kill forced.
    if new != 0 && matches!(signal, 9 | 19) {
        return Err(abi::EINVAL);
    }
    if old != 0 {
        let previous = env
            .proc
            .sigactions
            .borrow()
            .get(&signal)
            .copied()
            .unwrap_or_default();
        write_mem(env, cpu, old, &previous.0)?;
    }
    if new != 0 {
        let bytes = read_mem(env, cpu, new, 32)?;
        let mut action = SigAction::default();
        action.0.copy_from_slice(&bytes);
        env.proc.sigactions.borrow_mut().insert(signal, action);
    }
    Ok(0)
}

fn sys_rt_sigprocmask(env: &mut LinuxEnv, cpu: &mut Cpu, how: u64, new: u64, old: u64) -> Outcome {
    if old != 0 {
        if let Err(errno) = write_mem(env, cpu, old, &env.proc.sigmask.to_le_bytes()) {
            return Outcome::Ret(Err(errno));
        }
    }
    if new == 0 {
        return Outcome::Ret(Ok(0));
    }
    let bytes = match read_mem(env, cpu, new, 8) {
        Ok(bytes) => bytes,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let mask = u64::from_le_bytes(bytes.try_into().expect("read_mem length"));
    env.proc.sigmask = match how {
        0 => env.proc.sigmask | mask,  // SIG_BLOCK
        1 => env.proc.sigmask & !mask, // SIG_UNBLOCK
        2 => mask,                     // SIG_SETMASK
        _ => return Outcome::Ret(Err(abi::EINVAL)),
    };
    // A pending signal this call just unblocked is delivered on the way back
    // to userspace, before another guest instruction runs. musl's `raise`
    // depends on this: it blocks every signal around the `tkill`, so the
    // handler runs exactly here — a shell that expects its SIGINT handler to
    // have longjmp'd before `raise` returns would otherwise read the
    // never-delivered result and treat the interrupt as end-of-file.
    match pending_signal_action(env) {
        SignalExitAction::Terminate(sig) => {
            tracing::debug!("[{}] killed by unblocked signal {sig}", env.proc.pid);
            task_exit(env, cpu, sig as i32, true)
        }
        SignalExitAction::Stop(sig) => {
            resume_after_syscall(env, cpu, 0);
            stop_thread_group(env, cpu, sig, false)
        }
        SignalExitAction::Handler => {
            resume_after_syscall(env, cpu, 0);
            deliver_signal(env, cpu);
            Outcome::Switched
        }
        SignalExitAction::None => Outcome::Ret(Ok(0)),
    }
}

// ── Time, identity, misc ────────────────────────────────────────────────────

fn encode_timespec(sec: i64, nsec: i64) -> [u8; 16] {
    let mut out = [0_u8; 16];
    out[..8].copy_from_slice(&sec.to_le_bytes());
    out[8..].copy_from_slice(&nsec.to_le_bytes());
    out
}

const CLOCK_REALTIME: u64 = 0;
const CLOCK_MONOTONIC: u64 = 1;
const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
const CLOCK_MONOTONIC_RAW: u64 = 4;
const CLOCK_REALTIME_COARSE: u64 = 5;
const CLOCK_MONOTONIC_COARSE: u64 = 6;
const CLOCK_BOOTTIME: u64 = 7;
const CLOCK_REALTIME_ALARM: u64 = 8;
const CLOCK_BOOTTIME_ALARM: u64 = 9;

fn sys_clock_gettime(env: &mut LinuxEnv, cpu: &mut Cpu, clock_id: u64, ts: u64) -> SysResult {
    // CPU clocks advance only while the selected thread group executes. They
    // must not inherit either the realtime epoch or host suspension gaps;
    // runtimes use these clocks to budget GC and compilation work.
    let (sec, nsec) = match clock_id {
        CLOCK_REALTIME | CLOCK_REALTIME_ALARM => env.now(cpu),
        CLOCK_REALTIME_COARSE => env.now_coarse(cpu),
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_BOOTTIME | CLOCK_BOOTTIME_ALARM => {
            env.now_monotonic(cpu)
        }
        CLOCK_MONOTONIC_COARSE => env.now_monotonic_coarse(cpu),
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID => {
            let nanos = if clock_id == CLOCK_PROCESS_CPUTIME_ID {
                env.proc.current_group_cpu_nanos(cpu.icount())
            } else {
                env.proc.current_thread_cpu_nanos(cpu.icount())
            };
            (
                (nanos / 1_000_000_000) as i64,
                (nanos % 1_000_000_000) as i64,
            )
        }
        _ => return Err(abi::EINVAL),
    };
    write_mem(env, cpu, ts, &encode_timespec(sec, nsec))?;
    Ok(0)
}

fn clock_resolution_nanos(clock_id: u64) -> Result<i64, u64> {
    match clock_id {
        CLOCK_REALTIME_COARSE | CLOCK_MONOTONIC_COARSE => Ok(1_000_000),
        CLOCK_REALTIME
        | CLOCK_MONOTONIC
        | CLOCK_PROCESS_CPUTIME_ID
        | CLOCK_THREAD_CPUTIME_ID
        | CLOCK_MONOTONIC_RAW
        | CLOCK_BOOTTIME
        | CLOCK_REALTIME_ALARM
        | CLOCK_BOOTTIME_ALARM => Ok(1),
        _ => Err(abi::EINVAL),
    }
}

fn sys_sched_setscheduler(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    pid: u64,
    policy: u64,
    param: u64,
) -> SysResult {
    const SCHED_OTHER: u64 = 0;
    const SCHED_RESET_ON_FORK: u64 = 0x4000_0000;

    // The deterministic scheduler has no priority classes. Linux nevertheless
    // permits an unprivileged runtime to reaffirm SCHED_OTHER with priority
    // zero and request reset-on-fork; Bun does exactly this for its helper
    // threads. Supporting that identity operation is exact. Pretending to
    // implement FIFO/RR/BATCH/IDLE priorities would not be.
    if policy & !SCHED_RESET_ON_FORK != SCHED_OTHER {
        return Err(abi::EINVAL);
    }
    let priority = i32::from_le_bytes(
        read_mem(env, cpu, param, 4)?
            .try_into()
            .expect("sched_param is four bytes"),
    );
    if priority != 0 {
        return Err(abi::EINVAL);
    }

    let pid = pid as i64;
    if pid < 0 {
        return Err(abi::EINVAL);
    }
    let tid = if pid == 0 { env.proc.pid } else { pid as u64 };
    if tid != env.proc.pid && !env.sched.parked.iter().any(|task| task.proc.pid == tid) {
        return Err(abi::ESRCH);
    }
    Ok(0)
}

fn sys_gettimeofday(env: &mut LinuxEnv, cpu: &mut Cpu, tv: u64) -> SysResult {
    if tv != 0 {
        let (sec, nsec) = env.now(cpu);
        let mut out = [0_u8; 16];
        out[..8].copy_from_slice(&sec.to_le_bytes());
        out[8..].copy_from_slice(&(nsec / 1000).to_le_bytes());
        write_mem(env, cpu, tv, &out)?;
    }
    Ok(0)
}

fn sys_uname(env: &mut LinuxEnv, cpu: &mut Cpu, buf: u64) -> SysResult {
    let mut out = [0_u8; 65 * 6];
    for (i, field) in ["Linux", "webtos", "6.6.0-webtos", "#1 webTOS", "x86_64", ""]
        .iter()
        .enumerate()
    {
        let bytes = field.as_bytes();
        out[i * 65..i * 65 + bytes.len()].copy_from_slice(bytes);
    }
    write_mem(env, cpu, buf, &out)?;
    Ok(0)
}

fn sys_getrandom(env: &mut LinuxEnv, cpu: &mut Cpu, buf: u64, len: u64) -> SysResult {
    let len = len.min(0x1000) as usize;
    let mut out = vec![0_u8; len];
    for chunk in out.chunks_mut(8) {
        let bytes = env.next_random().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    write_mem(env, cpu, buf, &out)?;
    Ok(len as u64)
}

fn sys_prlimit64(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    resource: u64,
    new: u64,
    old: u64,
) -> SysResult {
    if old != 0 {
        // Linux resource 7 is RLIMIT_NOFILE. Reporting infinity while the fd
        // table silently rejects descriptor 1024 makes runtimes over-admit
        // sockets and then fail synchronously with an unexpected EMFILE.
        let limit = if resource == 7 {
            crate::fd::FD_LIMIT as u64
        } else {
            u64::MAX
        };
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&limit.to_le_bytes());
        bytes[8..].copy_from_slice(&limit.to_le_bytes());
        write_mem(env, cpu, old, &bytes)?;
    }
    // The execution profile owns fixed limits. Accepting a different new
    // value without storing and enforcing it would be another lie.
    if new != 0 {
        let requested = read_mem(env, cpu, new, 16)?;
        let current = u64::from_le_bytes(requested[..8].try_into().expect("slice length"));
        let maximum = u64::from_le_bytes(requested[8..].try_into().expect("slice length"));
        let enforced = if resource == 7 {
            crate::fd::FD_LIMIT as u64
        } else {
            u64::MAX
        };
        if current != enforced || maximum != enforced {
            return Err(abi::EPERM);
        }
    }
    Ok(0)
}

/// Linux `rseq(2)` registration for the fixed virtual-CPU model.
///
/// A registered thread sees CPU zero for the whole lifetime of its execution:
/// WebTOS serializes guest execution and never migrates a task between
/// virtual CPUs mid-instruction.  That is a real, conservative rseq model —
/// `cpu_id_start == cpu_id` authorizes user-space's fast path, while no hidden
/// host CPU identity leaks into the guest.  We deliberately do not advertise
/// rseq critical-section restart on migration because migration cannot occur
/// in this scheduler.
fn sys_rseq(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr: u64,
    len: u64,
    flags: u64,
    signature: u64,
) -> SysResult {
    const RSEQ_LEN: u64 = 32;
    const RSEQ_FLAG_UNREGISTER: u64 = 1;
    const RSEQ_SIG: u32 = 0x5305_3053;
    const RSEQ_CPU_ID_UNINITIALIZED: u32 = u32::MAX;

    // Linux fixes the ABI size for a given architecture.  Accepting a
    // truncated or future structure would leave fields the caller expects
    // the kernel to own without a defined meaning.
    if len != RSEQ_LEN || addr == 0 || addr & (RSEQ_LEN - 1) != 0 {
        return Err(abi::EINVAL);
    }
    if signature as u32 != RSEQ_SIG || signature >> 32 != 0 {
        return Err(abi::EINVAL);
    }
    if flags & !RSEQ_FLAG_UNREGISTER != 0 {
        return Err(abi::EINVAL);
    }

    if flags == RSEQ_FLAG_UNREGISTER {
        let Some(registration) = env.proc.rseq else {
            return Err(abi::EINVAL);
        };
        if registration.addr != addr || registration.signature != RSEQ_SIG {
            return Err(abi::EINVAL);
        }
        // The two kernel-owned CPU fields become explicitly uninitialized;
        // user-owned rseq_cs/flags are left untouched.
        let mut uninitialized = [0_u8; 8];
        uninitialized[..4].copy_from_slice(&RSEQ_CPU_ID_UNINITIALIZED.to_le_bytes());
        uninitialized[4..].copy_from_slice(&RSEQ_CPU_ID_UNINITIALIZED.to_le_bytes());
        write_mem(env, cpu, addr, &uninitialized)?;
        env.proc.rseq = None;
        return Ok(0);
    }

    if env.proc.rseq.is_some() {
        return Err(abi::EBUSY);
    }
    // Validate both kernel-owned words before changing process state, so an
    // unmapped or read-only user block cannot leave a half-registration.
    let _ = read_mem(env, cpu, addr, 8)?;
    write_mem(env, cpu, addr, &[0; 8])?;
    env.proc.rseq = Some(RseqRegistration {
        addr,
        signature: RSEQ_SIG,
    });
    Ok(0)
}

// ── Processes, threads, and scheduling (milestone 4) ────────────────────────

use crate::proc::{
    ParkState, ParkedTask, Process, RobustListRegistration, RseqRegistration, SignalFrame, Zombie,
    ROOT_PID,
};

/// `syscall` encodes as `0f 05`; rewinding NEXT_PC by its length makes the
/// guest re-execute the instruction, giving blocking syscalls restart
/// semantics (the condition is re-checked on wakeup).
const SYSCALL_INSN_LEN: u64 = 2;

const CLONE_VM: u64 = 0x100;
const CLONE_PIDFD: u64 = 0x1000;
const CLONE_VFORK: u64 = 0x4000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;

const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;

const FUTEX_WAIT: u64 = 0;
const FUTEX_WAKE: u64 = 1;
const FUTEX_WAIT_BITSET: u64 = 9;
const FUTEX_WAKE_BITSET: u64 = 10;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_WAITERS: u32 = 0x8000_0000;

/// Register the x86-64 `struct robust_list_head` for the current thread.
/// The kernel deliberately does not dereference `head` at registration time:
/// it needs to remain usable while a thread tears itself down, so validate
/// only the fixed ABI shape here and perform fault-tolerant traversal at exit.
fn sys_set_robust_list(env: &mut LinuxEnv, head: u64, len: u64) -> SysResult {
    const ROBUST_LIST_HEAD_LEN: u64 = 24;
    if head == 0 || len != ROBUST_LIST_HEAD_LEN {
        return Err(abi::EINVAL);
    }
    env.proc.robust_list = Some(RobustListRegistration { head });
    Ok(0)
}

/// Apply Linux robust-futex owner-death handling for the exiting thread.
/// Every operation is best-effort, as Linux treats an unreadable/corrupt
/// userspace robust list as a faulty userspace list rather than blocking task
/// teardown. The bounded walk prevents hostile guest memory from turning exit
/// into an unbounded host loop.
fn release_robust_futexes(env: &mut LinuxEnv, cpu: &mut Cpu) {
    const MAX_ROBUST_LIST_ENTRIES: usize = 2_048;
    let Some(registration) = env.proc.robust_list.take() else {
        return;
    };
    let tid = env.proc.pid as u32;
    let Ok(head) = read_mem(env, cpu, registration.head, 24) else {
        return;
    };
    let next = u64::from_le_bytes(head[0..8].try_into().expect("head next"));
    let futex_offset = i64::from_le_bytes(head[8..16].try_into().expect("head offset"));
    let pending = u64::from_le_bytes(head[16..24].try_into().expect("head pending"));
    let mut visited = std::collections::HashSet::new();
    let mut mark_owner_dead = |node: u64, env: &mut LinuxEnv, cpu: &mut Cpu| {
        if node == 0 || !visited.insert(node) {
            return;
        }
        let Some(futex_addr) = node.checked_add_signed(futex_offset) else {
            return;
        };
        let Ok(bytes) = read_mem(env, cpu, futex_addr, 4) else {
            return;
        };
        let value = u32::from_le_bytes(bytes.try_into().expect("futex word"));
        if value & FUTEX_TID_MASK != tid {
            return;
        }
        let replacement = (value & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        if write_mem(env, cpu, futex_addr, &replacement.to_le_bytes()).is_ok() {
            env.sched.futex_wake(futex_addr, 1);
        }
    };

    // `list_op_pending` is examined first; libc sets it while modifying the
    // list, so omitting it can strand a mutex exactly during lock acquisition.
    mark_owner_dead(pending, env, cpu);
    let mut node = next;
    for _ in 0..MAX_ROBUST_LIST_ENTRIES {
        if node == 0 || node == registration.head {
            break;
        }
        let Ok(link) = read_mem(env, cpu, node, 8) else {
            break;
        };
        let following = u64::from_le_bytes(link.try_into().expect("robust link"));
        mark_owner_dead(node, env, cpu);
        node = following;
    }
}

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

    /// Bare `vfork`: a fork whose parent suspends until the child execs or
    /// exits.
    pub(crate) fn vfork() -> Self {
        Self {
            flags: CLONE_VFORK,
            ..Self::fork()
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

/// Decodes Linux's extensible `struct clone_args` into the scheduler's one
/// canonical clone representation.
///
/// Version zero is 64 bytes (through `tls`); version one adds `set_tid` and
/// `set_tid_size`, and version two adds `cgroup`. Future zero-filled tail
/// bytes are accepted just like `copy_struct_from_user`, while a non-zero
/// field whose semantics this kernel does not implement fails closed.
fn clone3_spec(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    args_addr: u64,
    size: u64,
) -> Result<CloneSpec, u64> {
    const CLONE_ARGS_SIZE_VER0: usize = 64;
    const CLONE_ARGS_SIZE_VER2: usize = 88;
    const MAX_EXTENSIBLE_STRUCT: usize = PAGE_SIZE as usize;

    let size = usize::try_from(size).map_err(|_| abi::E2BIG)?;
    if size < CLONE_ARGS_SIZE_VER0 {
        return Err(abi::EINVAL);
    }
    if size > MAX_EXTENSIBLE_STRUCT {
        return Err(abi::E2BIG);
    }
    let bytes = read_mem(env, cpu, args_addr, size)?;
    if bytes[CLONE_ARGS_SIZE_VER2.min(size)..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(abi::E2BIG);
    }
    let field = |offset: usize| -> u64 {
        if offset + 8 > size {
            return 0;
        }
        u64::from_le_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("checked clone3 field"),
        )
    };

    let flags = field(0);
    let pidfd = field(8);
    let child_tid = field(16);
    let parent_tid = field(24);
    let exit_signal = field(32);
    let stack = field(40);
    let stack_size = field(48);
    let tls = field(56);
    let set_tid = field(64);
    let set_tid_size = field(72);
    let cgroup = field(80);

    if std::env::var_os("CLONE_TRACE").is_some() {
        eprintln!(
            "[clone3-args] size={size} flags={flags:#x} pidfd={pidfd:#x} child_tid={child_tid:#x} parent_tid={parent_tid:#x} exit_signal={exit_signal} stack={stack:#x} stack_size={stack_size:#x} tls={tls:#x} set_tid={set_tid:#x} set_tid_size={set_tid_size} cgroup={cgroup:#x}"
        );
    }

    // clone3 carries the termination signal separately, unlike legacy clone.
    // Signals outside Linux's 1..64 range and legacy CSIGNAL bits in `flags`
    // would make the same byte sequence ambiguous.
    if flags & 0xff != 0 || exit_signal > 64 {
        return Err(abi::EINVAL);
    }
    // PID-fd allocation, explicit PID selection and cgroup placement require
    // kernel authorities this deterministic userspace kernel does not expose.
    if flags & CLONE_PIDFD != 0
        || set_tid != 0
        || set_tid_size != 0
        || flags & CLONE_INTO_CGROUP != 0
    {
        return Err(abi::EINVAL);
    }
    if (stack == 0) != (stack_size == 0) {
        return Err(abi::EINVAL);
    }
    let new_sp = if stack == 0 {
        0
    } else {
        stack.checked_add(stack_size).ok_or(abi::EINVAL)?
    };

    Ok(CloneSpec {
        flags: flags | exit_signal,
        new_sp,
        parent_tid,
        child_tid,
        tls,
    })
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

/// Points the CPU at the instruction after the current syscall with `rax`
/// already written, so a signal handler entered now snapshots a clean
/// boundary: the state the handler saves (and may `longjmp` away from) is
/// "the syscall returned `rax`", never the middle of the block that issued
/// it — `rt_sigreturn` resuming mid-block would read a temporary the block
/// never wrote.
fn resume_after_syscall(env: &LinuxEnv, cpu: &mut Cpu, rax: u64) {
    cpu.write_var(env.regs.rax, rax);
    let next_pc: u64 = cpu.read_var(cpu.arch.reg_next_pc);
    cpu.exception = Exception::new(ExceptionCode::ExternalAddr, next_pc);
    cpu.write_pc(next_pc);
    cpu.block_id = u64::MAX;
    cpu.block_offset = 0;
}

/// Job-control stop: parks the current task and marks its whole thread
/// group stopped, records the stop for the parent's `wait4(WUNTRACED)`, and
/// raises SIGCHLD there. `restart` chooses what runs when SIGCONT lifts the
/// stop: re-execute the interrupted syscall (a stop taken at kernel entry)
/// or continue after it (a stop the syscall itself concluded, its return
/// value already written).
fn stop_thread_group(env: &mut LinuxEnv, cpu: &mut Cpu, signal: u64, restart: bool) -> Outcome {
    let tgid = env.proc.tgid;
    tracing::debug!("[{}] stopped by signal {signal}", env.proc.pid);
    env.proc.stopped = true;
    if env.proc.pid == tgid {
        env.proc.stop_report = Some(signal);
    }
    for task in &mut env.sched.parked {
        if task.proc.tgid == tgid {
            task.proc.stopped = true;
            if task.proc.pid == tgid {
                task.proc.stop_report = Some(signal);
            }
        }
    }
    let parent = env.proc.ppid;
    notify_parent_sigchld(env, parent);
    block_and_switch(env, cpu, ParkState::Ready, restart)
}

/// Parks the current task (CPU registers) with `state`. The address space
/// stays in the MMU: sibling threads share it, and `schedule_next` swaps
/// it out only when handing the CPU to a different thread group.
fn park_current(env: &mut LinuxEnv, cpu: &mut Cpu, state: ParkState) {
    env.proc.finish_cpu_turn(cpu.icount());
    let snapshot = cpu.snapshot();
    let proc = std::mem::replace(&mut env.proc, Process::initial());
    env.sched.parked.push(ParkedTask {
        proc,
        cpu: snapshot,
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
    // A timed futex wait that reached its deadline without a wake returns
    // -ETIMEDOUT (a wake would have left the pre-set 0 in place).
    let timed_out = matches!(
        &task.state,
        ParkState::Futex { woken: false, deadline: Some(deadline), .. } if now >= *deadline
    );
    // An untimed futex wait is parked at the syscall instruction so that a
    // signal installed with SA_RESTART can replay it.  A real FUTEX_WAKE is
    // different: it completes the admitted wait with zero and must not
    // compare the userspace word again.  Replaying after the waker changes
    // the word turns a successful wake into EAGAIN and breaks runtime worker
    // hand-offs.  Timed waits are already parked after the syscall because
    // their original deadline must not be recomputed.
    let untimed_futex_woken = matches!(
        &task.state,
        ParkState::Futex {
            woken: true,
            deadline: None,
            ..
        }
    );
    // Every wait but vfork's is interruptible: a signal that runs a handler
    // ends the syscall unless the handler asked for it to be restarted.
    let interruptible = !matches!(&task.state, ParkState::VforkDone { .. });
    // Whether the wait itself came good. A syscall whose condition is now
    // satisfied completes when it re-runs, exactly as on Linux, where a
    // signal arriving alongside a wakeup does not turn a successful wait into
    // an error. Only a task woken by the signal alone is a candidate for
    // `EINTR`.
    let condition_ready = env.sched.wait_is_satisfied(&task, now);

    // Address spaces are per thread group: swap only on cross-group
    // switches. The MMU currently holds the previous task's group map
    // (env.proc was replaced by a placeholder when it parked, so the group
    // id travels through `last_group`).
    let prev_group = env.last_group;
    let next_group = task.proc.tgid;
    if prev_group != next_group {
        let map = cpu.mem.take_virtual_mapping();
        // Keep the map only while the group still has runnable members;
        // zombie-only groups never run again.
        if prev_group != 0 && env.sched.group_has_parked(prev_group) {
            env.sched.group_maps.insert(prev_group, map);
        }
        // A group with no parked tasks and no zombie is gone; its map drops.
        match env.sched.group_maps.remove(&next_group) {
            Some(map) => cpu.mem.restore_virtual_mapping(map),
            None => {
                tracing::error!("missing address space for thread group {next_group}");
                return false;
            }
        }
    }
    env.last_group = next_group;

    // The instruction counter is global (energy, limits, deterministic
    // time); it must never rewind on a task switch.
    let icount = cpu.icount;
    let time_offset = cpu.time_offset;
    cpu.restore(&task.cpu);
    cpu.icount = icount;
    cpu.time_offset = time_offset;
    // Lifted block ids are process-local execution cursors, but the lifted
    // code arena is shared by the whole machine. A different task can write
    // to a page that has already been executed (for example JavaScriptCore
    // filling an RWX JIT page); the engine then flushes that shared arena.
    // Parked tasks still carry the old numeric block id in their CPU snapshot.
    // Restoring it after the flush would make an otherwise valid guest PC
    // index a block from the discarded arena. Resume through the current PC
    // instead: the next engine turn finds or re-lifts the block in the live
    // cache. Task switches occur at syscall boundaries, where PC is the
    // architectural restart point, so this does not discard a mid-pcode
    // operation.
    cpu.block_id = u64::MAX;
    cpu.block_offset = 0;
    env.proc = task.proc;
    env.proc.start_cpu_turn(cpu.icount());
    crate::set_current_pid(env.proc.pid);
    x64_engine::vm::set_current_asid(env.proc.asid);
    // SWAP_WATCH=hexaddr: read the 8 bytes at that guest VA in whichever
    // address space is now installed. A value that changes across a swap,
    // with no write hook firing, exposes wrong address-space bookkeeping.
    {
        use std::sync::OnceLock;
        static SWAP_WATCH: OnceLock<Option<u64>> = OnceLock::new();
        let w = SWAP_WATCH.get_or_init(|| {
            std::env::var("SWAP_WATCH")
                .ok()
                .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        });
        if let Some(w) = *w {
            let mut buf = [0u8; 8];
            let _ = cpu.mem.read_bytes(w, &mut buf, perm::NONE);
            eprintln!(
                "[swap] ic={} pid={} tgid={} prev_group={prev_group} val={buf:02x?}",
                cpu.icount(),
                env.proc.pid,
                env.proc.tgid,
            );
        }
    }
    if untimed_futex_woken {
        end_wait_with(env, cpu, 0);
    } else if timed_out {
        cpu.write_var(env.regs.rax, neg(abi::ETIMEDOUT));
    }
    // A task woken with a pending signal enters its handler before resuming
    // whatever it was doing. The syscall was parked to restart, which is what
    // `SA_RESTART` asks for; without that flag the wait has to end instead,
    // with `EINTR`. Rewriting the resume point first means the state the
    // handler snapshots is "the syscall returned -EINTR", so `rt_sigreturn`
    // continues after it rather than running it again.
    if env.proc.pending_signals & !env.proc.sigmask != 0 {
        if interruptible
            && !timed_out
            && !condition_ready
            && signal_restarts_the_syscall(env) == Some(false)
        {
            end_wait_with(env, cpu, neg(abi::EINTR));
        }
        deliver_signal(env, cpu);
    }
    true
}

/// Gives another runnable task a deterministic CPU turn.
///
/// Blocking syscalls already switch tasks through [`block_and_switch`], but
/// native runtimes also use bounded userspace spins while a worker is making
/// progress. A purely cooperative scheduler lets that spinner monopolize the
/// emulated CPU forever. The machine calls this at an instruction-quantum
/// boundary; stable queue order makes the hand-off replayable.
pub(crate) fn preempt_ready(env: &mut LinuxEnv, cpu: &mut Cpu) -> bool {
    let now = env.now_nanos(cpu);
    if env.sched.find_ready(now).is_none() {
        return false;
    }
    park_current(env, cpu, ParkState::Ready);
    // A ready task was observed before the current task was appended, so the
    // stable queue must still contain a schedulable entry.
    assert!(
        schedule_next(env, cpu),
        "ready task disappeared during preemption"
    );
    true
}

/// The terminal's own rule for a process that is not in its foreground
/// group: it may not take the user's input, and with `TOSTOP` set it may not
/// write either. POSIX has the terminal signal the offending process group
/// rather than fail the call, which stops it until a shell moves it to the
/// foreground and the syscall is retried.
///
/// A group that blocks or ignores the signal cannot be stopped by it, so the
/// call fails with `EIO` instead — otherwise it would quietly steal
/// keystrokes from the program the user is actually talking to.
///
/// Returns None when the caller is entitled to the terminal.
fn background_tty_access(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    pty: &crate::fd::PtyRef,
    signal: u64,
) -> Option<Outcome> {
    // No foreground group means no controlling terminal has claimed this pty,
    // and the rule does not apply.
    let foreground = pty.borrow().fg_pgrp;
    if foreground == 0 || foreground == env.proc.pgid {
        return None;
    }
    let bit = 1_u64 << (signal - 1);
    let ignored = env
        .proc
        .sigactions
        .borrow()
        .get(&signal)
        .map(|a| u64::from_le_bytes(a.0[..8].try_into().expect("size")))
        == Some(SIG_IGN);
    if env.proc.sigmask & bit != 0 || ignored {
        return Some(Outcome::Ret(Err(abi::EIO)));
    }
    // Other members of the group stop when they next reach the kernel; this
    // one stops now, with the syscall left to re-run after SIGCONT.
    deliver_signal_to_pgrp(env, env.proc.pgid, signal);
    env.proc.pending_signals &= !bit;
    Some(stop_thread_group(env, cpu, signal, true))
}

/// Terminal-state changes (`tcsetattr` and `tcsetpgrp`) are job-control
/// writes even when `TOSTOP` is clear. POSIX permits the operation when the
/// caller blocks or ignores SIGTTOU; otherwise the whole background process
/// group stops before the ioctl changes anything.
fn background_tty_ioctl(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    pty: &crate::fd::PtyRef,
) -> Option<Outcome> {
    let foreground = pty.borrow().fg_pgrp;
    if foreground == 0 || foreground == env.proc.pgid {
        return None;
    }
    let bit = 1_u64 << (SIGTTOU - 1);
    let ignored = env
        .proc
        .sigactions
        .borrow()
        .get(&SIGTTOU)
        .map(|action| u64::from_le_bytes(action.0[..8].try_into().expect("size")))
        == Some(SIG_IGN);
    if env.proc.sigmask & bit != 0 || ignored {
        return None;
    }
    deliver_signal_to_pgrp(env, env.proc.pgid, SIGTTOU);
    env.proc.pending_signals &= !bit;
    Some(stop_thread_group(env, cpu, SIGTTOU, true))
}

/// Turns a wait that was parked to restart into one that returns `value`.
///
/// A parked task's saved state points the CPU *at* the `syscall` instruction
/// so that resuming re-runs it; `reg_next_pc` was set to the same address.
/// Ending the wait therefore means stepping over the instruction rather than
/// resuming at `reg_next_pc`, which would re-execute the syscall with the
/// return value sitting in `rax` as its number.
fn end_wait_with(env: &LinuxEnv, cpu: &mut Cpu, value: u64) {
    let after = cpu.read_pc() + SYSCALL_INSN_LEN;
    cpu.write_var(env.regs.rax, value);
    let next_pc = cpu.arch.reg_next_pc;
    cpu.write_var(next_pc, after);
    cpu.write_pc(after);
    cpu.exception = Exception::new(ExceptionCode::ExternalAddr, after);
    cpu.pending_exception = None;
    cpu.block_id = u64::MAX;
    cpu.block_offset = 0;
}

/// Whether the signal about to be delivered was installed with `SA_RESTART`.
/// None when nothing will be delivered to a handler — no pending signal, or
/// one whose disposition is the default action or "ignore", neither of which
/// interrupts a syscall on its own.
fn signal_restarts_the_syscall(env: &LinuxEnv) -> Option<bool> {
    const SA_RESTART: u64 = 0x1000_0000;
    let pending = env.proc.pending_signals & !env.proc.sigmask;
    if pending == 0 {
        return None;
    }
    let sig = pending.trailing_zeros() as u64 + 1;
    let action = env.proc.sigactions.borrow().get(&sig).copied()?;
    let handler = u64::from_le_bytes(action.0[0..8].try_into().expect("size"));
    if handler == SIG_DFL || handler == SIG_IGN {
        return None;
    }
    let flags = u64::from_le_bytes(action.0[8..16].try_into().expect("size"));
    Some(flags & SA_RESTART != 0)
}

/// True when the machine's only reason to be idle is a task blocked reading
/// the host-driven stdio pty with no keystrokes queued. An interactive
/// program waiting for the user to type is not a deadlock.
fn blocked_on_terminal_input(env: &LinuxEnv) -> bool {
    env.terminal_input_pending()
}

/// Classifies a total stall: an interactive pause the host can end by typing,
/// or a genuine deadlock. `reason` describes the deadlock for diagnostics.
fn stall_outcome(env: &mut LinuxEnv, reason: &str, dump: bool) -> Outcome {
    if env.network_wait {
        return Outcome::Exit(VmExit::Interrupted);
    }
    if blocked_on_terminal_input(env) {
        env.terminal_input_wait = true;
        return Outcome::Exit(VmExit::Interrupted);
    }
    tracing::error!("deadlock: {reason}");
    if dump {
        dump_parked(env);
    }
    env.record_exit(-1);
    Outcome::Exit(VmExit::Deadlock)
}

/// Puts a ready task back on the CPU after a pause the host was asked to end.
/// Returns false when nothing is runnable yet.
pub(crate) fn resume_parked(env: &mut LinuxEnv, cpu: &mut Cpu) -> bool {
    schedule_next(env, cpu)
}

/// Which wait the host is still owed, when a resume found nothing runnable.
/// `None` means the machine is idle for a reason the host cannot fix, which
/// is a real deadlock.
pub(crate) enum HostWait {
    Terminal,
    Network,
}

pub(crate) fn pending_host_wait(env: &LinuxEnv) -> Option<HostWait> {
    if blocked_on_terminal_input(env) {
        return Some(HostWait::Terminal);
    }
    let host_driven = env
        .net
        .as_ref()
        .is_some_and(|broker| broker.borrow().host_driven());
    if host_driven && !env.sched.net_watch_handles().is_empty() {
        return Some(HostWait::Network);
    }
    None
}

/// Parks the current task and hands the CPU to the next ready one.
fn block_and_switch(env: &mut LinuxEnv, cpu: &mut Cpu, state: ParkState, restart: bool) -> Outcome {
    prepare_resume(env, cpu, restart);
    park_current(env, cpu, state);
    if schedule_next(env, cpu) {
        Outcome::Switched
    } else {
        stall_outcome(env, "every task is blocked; halting", true)
    }
}

/// Logs every parked task's blocking reason and signal state; called only on
/// the fatal deadlock paths so a hang in a real workload is diagnosable.
pub(crate) fn parked_task_snapshot(env: &LinuxEnv) -> Vec<String> {
    env.sched
        .parked
        .iter()
        .map(|task| {
            let state = format_park_state(&task.state);
            format!(
                "pid={} tgid={} ppid={} sigmask={:#x} pending={:#x} state={state}",
                task.proc.pid,
                task.proc.tgid,
                task.proc.ppid,
                task.proc.sigmask,
                task.proc.pending_signals,
            )
        })
        .collect()
}

fn format_park_state(state: &ParkState) -> String {
    match state {
        ParkState::Ready => "Ready".to_string(),
        ParkState::WaitChild { pid, untraced } => {
            format!("WaitChild(pid={pid}, untraced={untraced})")
        }
        ParkState::Futex { addr, deadline, .. } => {
            format!("Futex(addr={addr:#x}, deadline={deadline:?})")
        }
        ParkState::PipeRead { pipe } => {
            let p = pipe.borrow();
            format!(
                "PipeRead(len={}, writers={}, readers={})",
                p.data.len(),
                p.writers,
                p.readers
            )
        }
        ParkState::PipeWrite { pipe } => {
            let p = pipe.borrow();
            format!(
                "PipeWrite(len={}, writers={}, readers={})",
                p.data.len(),
                p.writers,
                p.readers
            )
        }
        ParkState::Waiting { watches, deadline } => {
            let kinds: Vec<String> = watches
                .iter()
                .map(|w| match w {
                    crate::proc::Watch::PipeReadable(p) => {
                        let p = p.borrow();
                        format!("pipeR(len={},w={})", p.data.len(), p.writers)
                    }
                    crate::proc::Watch::PipeWritable(p) => {
                        let p = p.borrow();
                        format!("pipeW(len={},r={})", p.data.len(), p.readers)
                    }
                    crate::proc::Watch::Event(e) => {
                        format!("event(count={})", e.borrow().count)
                    }
                    crate::proc::Watch::InotifyReadable(i) => {
                        format!("inotifyR(queued={})", i.borrow().queue.len())
                    }
                    crate::proc::Watch::InotifyActivity(i, seen) => {
                        format!("inotifyA(now={},seen={seen})", i.borrow().activity)
                    }
                    crate::proc::Watch::Timer(t) => {
                        format!("timer(next={:?})", t.borrow().next_expiry)
                    }
                    crate::proc::Watch::NetReadable(_) => "net-read".to_string(),
                    crate::proc::Watch::NetWritable(_) => "net-write".to_string(),
                    crate::proc::Watch::NetActivity(socket, seen) => format!(
                        "netAct(now={},seen={seen})",
                        socket.borrow().activity_generation()
                    ),
                    crate::proc::Watch::PipeActivity(p, seen) => {
                        format!("pipeAct(now={},seen={seen})", p.borrow().activity)
                    }
                    crate::proc::Watch::EventActivity(e, seen) => {
                        format!("eventAct(now={},seen={seen})", e.borrow().activity)
                    }
                    crate::proc::Watch::PtyReadable(_, m) => format!("ptyR(master={m})"),
                    crate::proc::Watch::PtyActivity(p, seen) => {
                        format!("ptyAct(now={},seen={seen})", p.borrow().activity)
                    }
                    crate::proc::Watch::Always => "always".to_string(),
                })
                .collect();
            format!(
                "Waiting(watches=[{}], deadline={deadline:?})",
                kinds.join(",")
            )
        }
        ParkState::VforkDone { done } => format!("VforkDone(done={})", done.get()),
    }
}

fn dump_parked(env: &LinuxEnv) {
    for task in &env.sched.parked {
        let state = format_park_state(&task.state);
        tracing::error!(
            "  parked pid={} tgid={} ppid={} sigmask={:#x} pending={:#x} state={state}",
            task.proc.pid,
            task.proc.tgid,
            task.proc.ppid,
            task.proc.sigmask,
            task.proc.pending_signals,
        );
    }
    for z in &env.sched.zombies {
        tracing::error!("  zombie pid={} ppid={} status={}", z.pid, z.ppid, z.status);
    }
    // One fd-table dump per thread group (threads share the table).
    let mut seen: Vec<*const ()> = Vec::new();
    for task in &env.sched.parked {
        let table_ptr = std::rc::Rc::as_ptr(&task.proc.fds) as *const ();
        if seen.contains(&table_ptr) {
            continue;
        }
        seen.push(table_ptr);
        tracing::error!("  fd table of tgid={}:", task.proc.tgid);
        for (fd, entry) in task.proc.fds.borrow().iter() {
            let desc = entry.desc.borrow();
            let kind = match &desc.backing {
                Backing::Std(s) => format!("std({s:?})"),
                Backing::File { node } => format!("file(node={node})"),
                Backing::Dir { node, .. } => format!("dir(node={node})"),
                Backing::Dev(d) => format!("dev({d:?})"),
                Backing::Inotify(inner) => {
                    let i = inner.borrow();
                    format!(
                        "inotify(watches={}, queued={})",
                        i.watches.len(),
                        i.queue.len()
                    )
                }
                Backing::Pipe { inner, write_end } => {
                    let p = inner.borrow();
                    format!(
                        "pipe({}, ptr={:p}, len={}, r={}, w={})",
                        if *write_end { "wr" } else { "rd" },
                        std::rc::Rc::as_ptr(inner),
                        p.data.len(),
                        p.readers,
                        p.writers
                    )
                }
                Backing::SocketPair { rx, tx } => format!(
                    "socketpair(rx={:p}, tx={:p})",
                    std::rc::Rc::as_ptr(rx),
                    std::rc::Rc::as_ptr(tx)
                ),
                Backing::EventFd(e) => format!("eventfd(count={})", e.borrow().count),
                Backing::TimerFd(t) => format!("timerfd(next={:?})", t.borrow().next_expiry),
                Backing::Net(n) => {
                    let n = n.borrow();
                    format!(
                        "net({:?}, handle={:?}, peer={:?})",
                        n.kind, n.handle, n.peer
                    )
                }
                Backing::PtyMaster(p) => {
                    let p = p.borrow();
                    format!(
                        "ptymaster(id={}, s2m={}, m2s={})",
                        p.id,
                        p.s2m.len(),
                        p.m2s.len()
                    )
                }
                Backing::PtySlave(p) => {
                    let p = p.borrow();
                    format!(
                        "ptyslave(id={}, s2m={}, m2s={})",
                        p.id,
                        p.s2m.len(),
                        p.m2s.len()
                    )
                }
                Backing::Epoll(ep) => {
                    let ep = ep.borrow();
                    let interests: Vec<String> = ep
                        .interests
                        .iter()
                        .map(|(fd, (ev, _))| format!("{fd}:{ev:#x}"))
                        .collect();
                    let fired: Vec<String> = ep
                        .edge_fired
                        .iter()
                        .map(|(fd, (m, act))| format!("{fd}:{m:#x}@{act}"))
                        .collect();
                    format!(
                        "epoll(interests=[{}], edge_fired=[{}])",
                        interests.join(","),
                        fired.join(",")
                    )
                }
            };
            tracing::error!("    fd {fd}: {kind}");
        }
    }
    let trail: Vec<String> = env
        .syscall_trail
        .iter()
        .map(|(pid, nr, ic)| format!("{pid}:{nr}@{ic}"))
        .collect();
    tracing::error!(
        "  syscall trail (pid:nr@icount, most recent last): {}",
        trail.join(" ")
    );
}

/// Terminates the current task. Threads disappear silently (after their
/// clear-child-tid futex wake); process main threads become zombies and
/// wake their parent. The root process ends the machine.
fn task_exit(env: &mut LinuxEnv, cpu: &mut Cpu, status: i32, exit_group: bool) -> Outcome {
    // An exiting vfork child that never reached execve (e.g. posix_spawn
    // whose exec failed) still releases its suspended parent.
    if let Some(done) = env.proc.vfork_done.take() {
        done.set(true);
    }

    // pthread_join waits on this address.
    if env.proc.clear_child_tid != 0 {
        let addr = env.proc.clear_child_tid;
        let _ = write_mem(env, cpu, addr, &0_u32.to_le_bytes());
        env.sched.futex_wake(addr, u64::MAX);
    }
    release_robust_futexes(env, cpu);

    // An exiting task is never parked, so close its running CPU interval
    // explicitly before the Process value is discarded. This keeps both the
    // departed thread's final clock and the surviving thread group's process
    // clock authoritative.
    env.proc.finish_cpu_turn(cpu.icount());

    let (pid, tgid, ppid) = (env.proc.pid, env.proc.tgid, env.proc.ppid);
    if exit_group {
        // Kill sibling threads (same thread group) that are parked.
        env.sched.parked.retain(|t| t.proc.tgid != tgid);
    }

    let group_leader = pid == tgid;
    if tgid == ROOT_PID && (exit_group || group_leader) {
        // A wait status with no exit byte is a signal death. Report it the
        // way a shell does, as 128 plus the signal, so a caller sees 130 for
        // an interrupt rather than a silent 0.
        let code = if status & 0x7f != 0 {
            128 + (status & 0x7f)
        } else {
            status >> 8
        };
        env.record_exit(code);
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

    // Release this task's descriptor-table handle before looking for a
    // runnable task. Dropping the exiting process's pipe/socket ends now
    // (rather than later, when its `Process` is finally overwritten in
    // `schedule_next`) decrements the peer reader/writer counts, so a parent
    // or sibling blocked on EOF is seen as runnable in this very scheduling
    // decision. Threads share the table through the `Rc`, so replacing the
    // handle only closes descriptors when this was the last reference — a
    // lone thread exiting never closes the process's fds. Without this, a
    // parent reading a child's stdout pipe to EOF deadlocks: the child's
    // write end is still held open when readiness is evaluated.
    env.proc.fds = std::rc::Rc::new(std::cell::RefCell::new(crate::fd::FdTable::new()));

    // A child becoming a zombie raises SIGCHLD in the parent. Async runtimes
    // (tokio) reap children through a SIGCHLD handler that writes a wakeup
    // pipe, so without delivering the signal a parent that spawned a process
    // and is not sitting in `wait4` never learns the child exited.
    if group_leader || exit_group {
        notify_parent_sigchld(env, ppid);
    }

    if schedule_next(env, cpu) {
        Outcome::Switched
    } else {
        stall_outcome(
            env,
            "last runnable task exited but the root is still parked",
            true,
        )
    }
}

/// Marks SIGCHLD pending on a thread of `parent_tgid` so it is delivered when
/// that thread next runs. Chooses a thread that has SIGCHLD unblocked; the
/// disposition table is process-wide, so any such thread can run the handler.
/// Does nothing when the parent installed no SIGCHLD handler (the default
/// disposition for SIGCHLD is to ignore it) or when every thread blocks it.
/// The two signals a process cannot catch, block, or ignore.
const SIGKILL: u64 = 9;
const SIGSTOP: u64 = 19;
/// The highest signal number there is. A pending set is a 64-bit word, so a
/// number above this has no bit to occupy and shifting by it is undefined.
const NSIG: u64 = 64;

/// Terminal-generated job-control signals: a background process group that
/// reads the terminal, and one that writes it while `TOSTOP` is set.
const SIGTTIN: u64 = 21;
const SIGTTOU: u64 = 22;

/// `sa_handler` values with a meaning of their own rather than an address.
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

/// True when the kernel's default action for `signal` is to terminate the
/// process. The signals a process is expected to ignore by default —
/// SIGCHLD, SIGURG, SIGWINCH, SIGCONT — are not in this set, so raising one
/// on a process that installed no handler stays a no-op; nor are the four
/// job-control signals, whose default action is to stop, not to kill.
fn default_action_terminates(signal: u64) -> bool {
    !matches!(signal, 17 | 18 | 19 | 20 | 21 | 22 | 23 | 28)
}

/// True when the kernel's default action for `signal` is to stop the
/// process: SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU.
fn default_action_stops(signal: u64) -> bool {
    matches!(signal, 19..=22)
}

/// Marks `signal` pending on every task in process group `pgrp` that would do
/// something with it: one that installed a handler, or one where the default
/// action is fatal. Used for terminal-generated signals — SIGWINCH on a
/// resize, SIGINT and SIGQUIT from the line discipline. Does nothing when
/// `pgrp` is 0.
pub(crate) fn deliver_signal_to_pgrp(env: &mut LinuxEnv, pgrp: u64, signal: u64) {
    if pgrp == 0 {
        return;
    }
    let bit = 1_u64 << (signal - 1);
    // The mask is not consulted: a signal raised while blocked stays pending
    // until it is unblocked. Only delivery looks at the mask.
    if env.proc.pgid == pgrp && acts_on_signal(&env.proc.sigactions, signal) {
        env.proc.pending_signals |= bit;
    }
    for t in &mut env.sched.parked {
        if t.proc.pgid == pgrp && acts_on_signal(&t.proc.sigactions, signal) {
            t.proc.pending_signals |= bit;
        }
    }
}

/// Whether a process with these dispositions would do anything with `signal`.
///
/// This has to be read from the *target's* table. Reading the sender's is the
/// bug this replaced: a shell that handles SIGINT could not `kill` anything
/// with it, because its own handler made the signal look "already dealt
/// with". Nothing about the sender decides what a signal means to a process.
fn acts_on_signal(
    acts: &std::rc::Rc<std::cell::RefCell<std::collections::HashMap<u64, SigAction>>>,
    signal: u64,
) -> bool {
    // SIGKILL and SIGSTOP cannot be caught or ignored.
    if matches!(signal, SIGKILL | SIGSTOP) {
        return true;
    }
    let acts_by_default = default_action_terminates(signal) || default_action_stops(signal);
    // SIG_IGN discards the signal outright; SIG_DFL (or no entry at all)
    // means the default action, which is worth queueing only when that action
    // is not "ignore".
    match acts.borrow().get(&signal) {
        Some(a) => match u64::from_le_bytes(a.0[..8].try_into().expect("size")) {
            SIG_DFL => acts_by_default,
            SIG_IGN => false,
            _ => true,
        },
        None => acts_by_default,
    }
}

/// Marks `signal` pending on a thread of `tgid`, so the target runs its own
/// handler — or its own default action — when it is next scheduled. Returns
/// whether such a process exists.
///
/// A thread that does not block the signal is preferred, and the group leader
/// among those, because that is the one a debugger or a person watching
/// `wait4` expects to see act.
fn signal_process(env: &mut LinuxEnv, tgid: u64, signal: u64) -> bool {
    if signal == 0 || signal > NSIG {
        return false;
    }
    let bit = 1_u64 << (signal - 1);
    if env.proc.tgid == tgid {
        if acts_on_signal(&env.proc.sigactions, signal) {
            env.proc.pending_signals |= bit;
        }
        return true;
    }
    let mut unblocked: Option<usize> = None;
    let mut fallback: Option<usize> = None;
    let mut exists = false;
    for (i, t) in env.sched.parked.iter().enumerate() {
        if t.proc.tgid != tgid {
            continue;
        }
        exists = true;
        if !acts_on_signal(&t.proc.sigactions, signal) {
            continue;
        }
        let blocked = t.proc.sigmask & bit != 0;
        let leader = t.proc.pid == tgid;
        if !blocked && (leader || unblocked.is_none()) {
            unblocked = Some(i);
            if leader {
                break;
            }
        }
        if blocked && (leader || fallback.is_none()) {
            fallback = Some(i);
        }
    }
    if let Some(i) = unblocked.or(fallback) {
        env.sched.parked[i].proc.pending_signals |= bit;
    }
    exists
}

/// What the lowest pending, unblocked signal calls for at a kernel-exit
/// boundary, taken in signal-number order the way the kernel dequeues them.
enum SignalExitAction {
    /// Nothing deliverable (ignored signals were discarded along the way).
    None,
    /// The lowest deliverable signal has a user handler; enter it with
    /// `deliver_signal`.
    Handler,
    /// The lowest deliverable signal defaults to termination — consumed, so
    /// the caller must carry the death out.
    Terminate(u64),
    /// The lowest deliverable signal defaults to stopping the process —
    /// consumed, so the caller must park the thread group stopped.
    Stop(u64),
}

/// Scans pending, unblocked signals lowest-first: explicitly ignored signals
/// and those whose default action is to ignore are discarded; the first one
/// that would do something decides the action. Called at syscall boundaries
/// — the kernel entry a woken task next reaches, and the exit of a call that
/// just unblocked a pending signal.
fn pending_signal_action(env: &mut LinuxEnv) -> SignalExitAction {
    loop {
        let deliverable = env.proc.pending_signals & !env.proc.sigmask;
        if deliverable == 0 {
            return SignalExitAction::None;
        }
        let sig = deliverable.trailing_zeros() as u64 + 1;
        let bit = 1_u64 << (sig - 1);
        let disposition = env
            .proc
            .sigactions
            .borrow()
            .get(&sig)
            .map(|a| u64::from_le_bytes(a.0[..8].try_into().expect("size")));
        match disposition {
            Some(SIG_IGN) => env.proc.pending_signals &= !bit,
            None | Some(SIG_DFL) => {
                env.proc.pending_signals &= !bit;
                if default_action_terminates(sig) {
                    return SignalExitAction::Terminate(sig);
                }
                if default_action_stops(sig) {
                    return SignalExitAction::Stop(sig);
                }
            }
            Some(_) => return SignalExitAction::Handler,
        }
    }
}

fn notify_parent_sigchld(env: &mut LinuxEnv, parent_tgid: u64) {
    const SIGCHLD: u64 = 17;
    const SIGCHLD_BIT: u64 = 1 << (SIGCHLD - 1);
    // Is a user handler installed for SIGCHLD in the parent group? The
    // disposition table is shared, so read it from any group member.
    let has_handler = env
        .sched
        .parked
        .iter()
        .find(|t| t.proc.tgid == parent_tgid)
        .map(|t| &t.proc.sigactions)
        .or({
            if env.proc.tgid == parent_tgid {
                Some(&env.proc.sigactions)
            } else {
                None
            }
        })
        .is_some_and(|acts| {
            acts.borrow()
                .get(&SIGCHLD)
                .is_some_and(|a| u64::from_le_bytes(a.0[..8].try_into().expect("size")) > 1)
        });
    if !has_handler {
        return;
    }
    // Deliver to a thread that does not block SIGCHLD, preferring the group's
    // main thread. If every thread blocks it the signal is still recorded:
    // blocking defers delivery, it does not discard the signal. Dropping it
    // here lost every SIGCHLD raised inside `posix_spawn`, which blocks all
    // signals for the duration — the parent then waited forever for a child
    // that had already exited.
    let mut unblocked: Option<usize> = None;
    let mut fallback: Option<usize> = None;
    for (i, t) in env.sched.parked.iter().enumerate() {
        if t.proc.tgid != parent_tgid {
            continue;
        }
        let blocked = t.proc.sigmask & SIGCHLD_BIT != 0;
        let main = t.proc.pid == parent_tgid;
        if !blocked && (main || unblocked.is_none()) {
            unblocked = Some(i);
            if main {
                break;
            }
        }
        if blocked && (main || fallback.is_none()) {
            fallback = Some(i);
        }
    }
    if let Some(i) = unblocked.or(fallback) {
        env.sched.parked[i].proc.pending_signals |= SIGCHLD_BIT;
    }
}

/// Redirects the current CPU into the lowest-numbered pending signal's
/// `stack_t { void *ss_sp; int ss_flags; size_t ss_size; }` — with padding,
/// twenty-four bytes: pointer, four-byte flags, four bytes of hole, size.
const STACK_T_LEN: usize = 24;
/// Reported when a handler is running on the alternate stack; never set by a
/// caller.
const SS_ONSTACK: u32 = 1;
/// Set by a caller to take the alternate stack away.
const SS_DISABLE: u32 = 2;
/// The smallest alternate stack the kernel will accept. A handler frame plus
/// what a handler does has to fit, and a stack too small to hold one is worse
/// than none: the fault it was installed to survive happens on it instead.
const MINSIGSTKSZ: u64 = 2048;

/// Registers, queries, or disables the alternate signal stack.
///
/// A runtime installs one so a handler has somewhere to run when the stack it
/// interrupted is the problem. This used to record the request and ignore it,
/// which is the failure mode that matters least until it matters most: the
/// handler runs on the stack that just overflowed.
fn sys_sigaltstack(env: &mut LinuxEnv, cpu: &mut Cpu, new: u64, old: u64) -> SysResult {
    let on_stack = env.proc.altstack_depth > 0;
    if old != 0 {
        let mut out = [0_u8; STACK_T_LEN];
        let (base, size, flags) = match env.proc.altstack {
            Some((base, size)) => (base, size, if on_stack { SS_ONSTACK } else { 0 }),
            None => (0, 0, SS_DISABLE),
        };
        out[0..8].copy_from_slice(&base.to_le_bytes());
        out[8..12].copy_from_slice(&flags.to_le_bytes());
        out[16..24].copy_from_slice(&size.to_le_bytes());
        write_mem(env, cpu, old, &out)?;
    }
    if new == 0 {
        return Ok(0);
    }
    // Changing the stack a handler is currently running on would pull the
    // ground out from under it.
    if on_stack {
        return Err(abi::EPERM);
    }
    let bytes = read_mem(env, cpu, new, STACK_T_LEN)?;
    let base = u64::from_le_bytes(bytes[0..8].try_into().expect("size"));
    let flags = u32::from_le_bytes(bytes[8..12].try_into().expect("size"));
    let size = u64::from_le_bytes(bytes[16..24].try_into().expect("size"));
    if flags & SS_DISABLE != 0 {
        env.proc.altstack = None;
        return Ok(0);
    }
    // Anything other than SS_DISABLE is a flag this kernel does not know, and
    // guessing at it would be worse than saying so.
    if flags & !SS_ONSTACK != 0 {
        return Err(abi::EINVAL);
    }
    if size < MINSIGSTKSZ {
        return Err(abi::ENOMEM);
    }
    if base.checked_add(size).is_none() {
        return Err(abi::EINVAL);
    }
    env.proc.altstack = Some((base, size));
    Ok(0)
}

const RT_UCONTEXT_SIZE: usize = 304;
const RT_SIGINFO_SIZE: usize = 128;
const RT_SIGFRAME_FIXED_SIZE: usize = 8 + RT_UCONTEXT_SIZE + RT_SIGINFO_SIZE;
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
const UC_FP_XSTATE: u64 = 1;

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed signal-frame field"),
    )
}

fn user_canonical(address: u64) -> bool {
    address < 0x0000_8000_0000_0000
}

/// Enter a handler with a Linux-compatible, guest-visible `rt_sigframe`. The
/// interrupted syscall was parked to resume (blocking waits pre-set their
/// return value), so after the handler returns the wait is re-evaluated and,
/// if still not satisfied, simply re-parks. Returns false without consuming
/// anything when the lowest deliverable signal calls for the default fatal
/// action instead of a handler, or when the frame cannot be built.
fn deliver_signal(env: &mut LinuxEnv, cpu: &mut Cpu) -> bool {
    // Only unblocked signals are deliverable; a signal raised while its
    // handler runs (the handler's own mask blocks it) stays pending until
    // `rt_sigreturn` restores the mask. Scanned lowest-first: ignored
    // signals are discarded, and one whose default action is to terminate is
    // left pending — carrying out the death is the syscall boundary's job
    // (`pending_signal_action`), and consuming it here would lose it.
    let (sig, action) = loop {
        let pending = env.proc.pending_signals & !env.proc.sigmask;
        if pending == 0 {
            return false;
        }
        let sig = pending.trailing_zeros() as u64 + 1;
        let bit = 1_u64 << (sig - 1);
        let action = env.proc.sigactions.borrow().get(&sig).copied();
        let handler = action
            .map(|a| u64::from_le_bytes(a.0[0..8].try_into().expect("size")))
            .unwrap_or(SIG_DFL);
        if handler == SIG_DFL && (default_action_terminates(sig) || default_action_stops(sig)) {
            return false;
        }
        env.proc.pending_signals &= !bit;
        if handler != SIG_DFL && handler != SIG_IGN {
            break (sig, action.expect("a real handler implies an action"));
        }
    };
    let bit = 1_u64 << (sig - 1);
    let handler = u64::from_le_bytes(action.0[0..8].try_into().expect("size"));
    let flags = u64::from_le_bytes(action.0[8..16].try_into().expect("size"));
    let restorer = u64::from_le_bytes(action.0[16..24].try_into().expect("size"));
    let sa_mask = u64::from_le_bytes(action.0[24..32].try_into().expect("size"));

    env.trace_event(crate::trace::Event::Signal {
        icount: cpu.icount(),
        pid: env.proc.pid,
        signal: sig,
    });

    // Which stack it goes on is the point of `SA_ONSTACK`: a handler asking
    // for it gets the alternate stack, from its top, because the stack it
    // interrupted may be the thing that faulted. Already running on the
    // alternate stack, it continues down it instead of starting over at the
    // top, which would overwrite the frame of the handler it interrupted.
    const SA_ONSTACK: u64 = 0x0800_0000;
    let interrupted_sp: u64 = cpu.read_var(env.regs.rsp);
    let on_alt = flags & SA_ONSTACK != 0 && env.proc.altstack.is_some();
    let mut stack_top = match (on_alt, env.proc.altstack_depth, env.proc.altstack) {
        (true, 0, Some((base, size))) => base.saturating_add(size),
        _ => interrupted_sp,
    };
    // The red zone belongs to the interrupted frame; the alternate stack has
    // no frame below its top, so there is nothing to skip there.
    if !on_alt || env.proc.altstack_depth > 0 {
        stack_top = stack_top.saturating_sub(128);
    }

    let Some(mut xstate) = icicle_cpu::exec::helpers::x86::standard_xstate_image(cpu, true) else {
        env.proc.pending_signals |= bit;
        return false;
    };
    let xstate_size = xstate.len();
    let extended_size = xstate_size + 4;
    xstate[464..468].copy_from_slice(&FP_XSTATE_MAGIC1.to_le_bytes());
    xstate[468..472].copy_from_slice(&(extended_size as u32).to_le_bytes());
    xstate[472..480].copy_from_slice(&icicle_cpu::exec::helpers::x86::INITIAL_XCR0.to_le_bytes());
    xstate[480..484].copy_from_slice(&(xstate_size as u32).to_le_bytes());

    let Some(fpstate_ptr) = stack_top
        .checked_sub(extended_size as u64)
        .map(|value| value & !63)
    else {
        env.proc.pending_signals |= bit;
        return false;
    };
    let Some(frame_limit) = fpstate_ptr.checked_sub(RT_SIGFRAME_FIXED_SIZE as u64) else {
        env.proc.pending_signals |= bit;
        return false;
    };
    // At handler entry `(rsp + 8) % 16 == 0`; the first word is the restorer
    // return address and the fixed Linux rt_sigframe follows it.
    let Some(frame_base) = frame_limit.checked_sub(8).map(|value| (value & !15) + 8) else {
        env.proc.pending_signals |= bit;
        return false;
    };
    let ucontext_ptr = frame_base + 8;
    let siginfo_ptr = ucontext_ptr + RT_UCONTEXT_SIZE as u64;

    let frame_end = match fpstate_ptr.checked_add(extended_size as u64) {
        Some(value) => value,
        None => {
            env.proc.pending_signals |= bit;
            return false;
        }
    };
    let frame_len = (frame_end - frame_base) as usize;
    if host_touch(
        env,
        cpu,
        frame_base,
        frame_len,
        crate::pager::AccessKind::Write,
    )
    .is_err()
    {
        env.proc.pending_signals |= bit;
        return false;
    }

    let mut fixed = vec![0_u8; RT_SIGFRAME_FIXED_SIZE];
    fixed[..8].copy_from_slice(&restorer.to_le_bytes());
    let uc = &mut fixed[8..8 + RT_UCONTEXT_SIZE];
    put_u64(uc, 0, UC_FP_XSTATE);
    if let Some((base, size)) = env.proc.altstack {
        put_u64(uc, 16, base);
        uc[24..28].copy_from_slice(
            &(if env.proc.altstack_depth > 0 {
                SS_ONSTACK
            } else {
                0
            })
            .to_le_bytes(),
        );
        put_u64(uc, 32, size);
    }

    let csgsfs = u64::from(cpu.read_var::<u16>(env.regs.cs))
        | (u64::from(cpu.read_var::<u16>(env.regs.gs)) << 16)
        | (u64::from(cpu.read_var::<u16>(env.regs.fs)) << 32)
        | (u64::from(cpu.read_var::<u16>(env.regs.ss)) << 48);
    let gregs = [
        cpu.read_var::<u64>(env.regs.r8),
        cpu.read_var::<u64>(env.regs.r9),
        cpu.read_var::<u64>(env.regs.r10),
        cpu.read_var::<u64>(env.regs.r11),
        cpu.read_var::<u64>(env.regs.r12),
        cpu.read_var::<u64>(env.regs.r13),
        cpu.read_var::<u64>(env.regs.r14),
        cpu.read_var::<u64>(env.regs.r15),
        cpu.read_var::<u64>(env.regs.rdi),
        cpu.read_var::<u64>(env.regs.rsi),
        cpu.read_var::<u64>(env.regs.rbp),
        cpu.read_var::<u64>(env.regs.rbx),
        cpu.read_var::<u64>(env.regs.rdx),
        cpu.read_var::<u64>(env.regs.rax),
        cpu.read_var::<u64>(env.regs.rcx),
        interrupted_sp,
        cpu.read_pc(),
        cpu.read_var::<u64>(env.regs.rflags),
        csgsfs,
        0,
        0,
        env.proc.sigmask,
        0,
    ];
    for (index, value) in gregs.into_iter().enumerate() {
        put_u64(uc, 40 + index * 8, value);
    }
    put_u64(uc, 224, fpstate_ptr);
    put_u64(uc, 296, env.proc.sigmask);

    let mut siginfo = [0_u8; RT_SIGINFO_SIZE];
    siginfo[0..4].copy_from_slice(&(sig as u32).to_le_bytes()); // si_signo
    fixed[8 + RT_UCONTEXT_SIZE..].copy_from_slice(&siginfo);

    if write_mem_raw(cpu, frame_base, &fixed).is_err()
        || write_mem_raw(cpu, fpstate_ptr, &xstate).is_err()
        || write_mem_raw(
            cpu,
            fpstate_ptr + xstate_size as u64,
            &FP_XSTATE_MAGIC2.to_le_bytes(),
        )
        .is_err()
    {
        env.proc.pending_signals |= bit;
        return false;
    }

    env.proc.signal_frames.push(SignalFrame {
        frame_base,
        fpstate: fpstate_ptr,
        on_alt,
    });
    if on_alt {
        env.proc.altstack_depth += 1;
    }
    const SA_NODEFER: u64 = 0x4000_0000;
    if flags & SA_NODEFER == 0 {
        env.proc.sigmask |= bit;
    }
    env.proc.sigmask |= sa_mask;

    cpu.write_var(env.regs.rsp, frame_base);
    cpu.write_var(env.regs.rdi, sig);
    cpu.write_var(env.regs.rsi, siginfo_ptr);
    cpu.write_var(env.regs.rdx, ucontext_ptr);
    cpu.write_pc(handler);
    cpu.exception = Exception::new(ExceptionCode::ExternalAddr, handler);
    cpu.pending_exception = None;
    cpu.block_id = u64::MAX;
    cpu.block_offset = 0;
    true
}

fn bad_sigreturn(env: &mut LinuxEnv, cpu: &mut Cpu, why: &str) -> Outcome {
    tracing::debug!("[{}] invalid rt_sigreturn frame: {why}", env.proc.pid);
    task_exit(env, cpu, 11, true)
}

/// `rt_sigreturn`: validate and restore the guest-visible frame. GPR, signal
/// mask and complete user xstate edits made by the handler are authoritative;
/// malformed pointers, sizes, selectors, reserved xstate or MXCSR bits fail
/// closed as a Linux bad frame rather than partially restoring state.
fn sys_rt_sigreturn(env: &mut LinuxEnv, cpu: &mut Cpu) -> Outcome {
    let Some(frame) = env.proc.signal_frames.last().copied() else {
        return bad_sigreturn(env, cpu, "no active frame");
    };
    let rsp = cpu.read_var::<u64>(env.regs.rsp);
    if rsp.checked_sub(8) != Some(frame.frame_base) {
        return bad_sigreturn(
            env,
            cpu,
            "stack pointer does not identify the innermost frame",
        );
    }
    let fixed = match read_mem(env, cpu, frame.frame_base, RT_SIGFRAME_FIXED_SIZE) {
        Ok(bytes) => bytes,
        Err(_) => return bad_sigreturn(env, cpu, "fixed frame is unreadable"),
    };
    let uc = &fixed[8..8 + RT_UCONTEXT_SIZE];
    if get_u64(uc, 224) != frame.fpstate || frame.fpstate & 63 != 0 {
        return bad_sigreturn(env, cpu, "fpstate pointer changed or is misaligned");
    }
    let metadata = match read_mem(env, cpu, frame.fpstate + 464, 20) {
        Ok(bytes) => bytes,
        Err(_) => return bad_sigreturn(env, cpu, "xstate metadata is unreadable"),
    };
    let magic1 = u32::from_le_bytes(metadata[0..4].try_into().unwrap());
    let extended_size = u32::from_le_bytes(metadata[4..8].try_into().unwrap()) as usize;
    let layout_features = u64::from_le_bytes(metadata[8..16].try_into().unwrap());
    let xstate_size = u32::from_le_bytes(metadata[16..20].try_into().unwrap()) as usize;
    let expected_xstate_size = icicle_cpu::exec::helpers::x86::STANDARD_XSTATE_SIZE;
    if magic1 != FP_XSTATE_MAGIC1
        || xstate_size != expected_xstate_size
        || extended_size != expected_xstate_size + 4
        || layout_features != icicle_cpu::exec::helpers::x86::INITIAL_XCR0
    {
        return bad_sigreturn(env, cpu, "xstate metadata does not match the active layout");
    }
    let xstate = match read_mem(env, cpu, frame.fpstate, xstate_size) {
        Ok(bytes) => bytes,
        Err(_) => return bad_sigreturn(env, cpu, "xstate image is unreadable"),
    };
    let trailer = match read_mem(env, cpu, frame.fpstate + xstate_size as u64, 4) {
        Ok(bytes) => bytes,
        Err(_) => return bad_sigreturn(env, cpu, "xstate trailer is unreadable"),
    };
    if u32::from_le_bytes(trailer.try_into().unwrap()) != FP_XSTATE_MAGIC2 {
        return bad_sigreturn(env, cpu, "xstate trailer is invalid");
    }

    let rip = get_u64(uc, 40 + 16 * 8);
    let restored_rsp = get_u64(uc, 40 + 15 * 8);
    if !user_canonical(rip) || !user_canonical(restored_rsp) {
        return bad_sigreturn(env, cpu, "non-canonical user RIP or RSP");
    }
    let csgsfs = get_u64(uc, 40 + 18 * 8);
    let current_csgsfs = u64::from(cpu.read_var::<u16>(env.regs.cs))
        | (u64::from(cpu.read_var::<u16>(env.regs.gs)) << 16)
        | (u64::from(cpu.read_var::<u16>(env.regs.fs)) << 32)
        | (u64::from(cpu.read_var::<u16>(env.regs.ss)) << 48);
    if csgsfs != current_csgsfs {
        return bad_sigreturn(env, cpu, "segment selectors changed");
    }

    if icicle_cpu::exec::helpers::x86::restore_standard_xstate_image(cpu, &xstate, true).is_none() {
        return bad_sigreturn(env, cpu, "xstate validation failed");
    }

    let restored = [
        (env.regs.r8, 0),
        (env.regs.r9, 1),
        (env.regs.r10, 2),
        (env.regs.r11, 3),
        (env.regs.r12, 4),
        (env.regs.r13, 5),
        (env.regs.r14, 6),
        (env.regs.r15, 7),
        (env.regs.rdi, 8),
        (env.regs.rsi, 9),
        (env.regs.rbp, 10),
        (env.regs.rbx, 11),
        (env.regs.rdx, 12),
        (env.regs.rax, 13),
        (env.regs.rcx, 14),
        (env.regs.rsp, 15),
    ];
    for (register, index) in restored {
        cpu.write_var(register, get_u64(uc, 40 + index * 8));
    }
    const USER_RFLAGS: u64 = (1 << 0)
        | (1 << 2)
        | (1 << 4)
        | (1 << 6)
        | (1 << 7)
        | (1 << 8)
        | (1 << 10)
        | (1 << 11)
        | (1 << 16)
        | (1 << 18);
    let current_flags = cpu.read_var::<u64>(env.regs.rflags);
    let requested_flags = get_u64(uc, 40 + 17 * 8);
    cpu.write_var(
        env.regs.rflags,
        (current_flags & !USER_RFLAGS) | (requested_flags & USER_RFLAGS) | 2,
    );
    cpu.write_pc(rip);
    const UNBLOCKABLE: u64 = (1 << (9 - 1)) | (1 << (19 - 1));
    env.proc.sigmask = get_u64(uc, 296) & !UNBLOCKABLE;
    env.proc.signal_frames.pop();
    if frame.on_alt {
        env.proc.altstack_depth = env.proc.altstack_depth.saturating_sub(1);
    }
    cpu.exception = Exception::new(ExceptionCode::ExternalAddr, rip);
    cpu.pending_exception = None;
    cpu.block_id = u64::MAX;
    cpu.block_offset = 0;

    match pending_signal_action(env) {
        SignalExitAction::Terminate(sig) => task_exit(env, cpu, sig as i32, true),
        SignalExitAction::Stop(sig) => stop_thread_group(env, cpu, sig, false),
        SignalExitAction::Handler => {
            deliver_signal(env, cpu);
            Outcome::Switched
        }
        SignalExitAction::None => Outcome::Switched,
    }
}

fn sys_clone_impl(env: &mut LinuxEnv, cpu: &mut Cpu, spec: CloneSpec) -> Outcome {
    let child_pid = env.sched.next_pid();
    // A vfork clone (`CLONE_VM | CLONE_VFORK`, e.g. glibc posix_spawn) sets
    // CLONE_VM but is not a thread: it is a child process that runs to execve
    // or exit. Give it a copy-on-write address space (like fork) rather than
    // sharing the group map — the child only sets up fds and execs, which
    // replaces its memory, so the copy is never mutated concurrently with the
    // parent, and it remains a waitable child rather than a thread sibling.
    let is_thread = spec.flags & CLONE_VM != 0 && spec.flags & CLONE_VFORK == 0;
    if std::env::var_os("CLONE_TRACE").is_some() {
        eprintln!(
            "[clone] parent_pid={} flags={:#x} VM={} VFORK={} THREAD={} -> child_pid={child_pid} is_thread={is_thread}",
            env.proc.pid,
            spec.flags,
            spec.flags & CLONE_VM != 0,
            spec.flags & CLONE_VFORK != 0,
            spec.flags & 0x10000 != 0,
        );
    }

    if spec.flags & CLONE_PARENT_SETTID != 0
        && spec.parent_tid != 0
        && write_mem(env, cpu, spec.parent_tid, &(child_pid as u32).to_le_bytes()).is_err()
    {
        return Outcome::Ret(Err(abi::EFAULT));
    }

    let mut child_proc = if is_thread {
        env.proc.thread_sibling(child_pid)
    } else {
        env.proc.fork_child(child_pid)
    };
    if !is_thread {
        env.pager.fork_space(env.proc.asid, child_proc.asid);
        env.fork_file_backed_ranges(env.proc.asid, child_proc.asid);
    }
    if spec.flags & CLONE_CHILD_CLEARTID != 0 {
        child_proc.clear_child_tid = spec.child_tid;
    }

    // Child memory: threads share the group map (nothing to clone); forks
    // get a copy-on-write clone stored under the child's new group.
    let mut child_mem = if is_thread {
        None
    } else {
        Some(cpu.mem.snapshot_virtual_mapping())
    };
    if let Some(map) = child_mem.take() {
        let parent_map = cpu.mem.take_virtual_mapping();
        cpu.mem.restore_virtual_mapping(map);
        for range in env
            .dontfork_ranges
            .iter()
            .filter(|range| range.asid == env.proc.asid)
        {
            cpu.mem
                .unmap_memory_len(range.start, range.end.saturating_sub(range.start));
        }
        child_mem = Some(cpu.mem.take_virtual_mapping());
        cpu.mem.restore_virtual_mapping(parent_map);
    }

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
        match child_mem.take() {
            None => {
                // Shared address space: write directly.
                let _ = write_mem(env, cpu, spec.child_tid, &tid_bytes);
            }
            Some(map) => {
                // Write into the child's copy-on-write map.
                let parent_map = cpu.mem.take_virtual_mapping();
                cpu.mem.restore_virtual_mapping(map);
                let _ = write_mem(env, cpu, spec.child_tid, &tid_bytes);
                child_mem = Some(cpu.mem.take_virtual_mapping());
                cpu.mem.restore_virtual_mapping(parent_map);
            }
        }
    }

    // A vfork parent suspends until the child execs or exits; the child
    // carries the release flag and fires it from `execve`/`task_exit`.
    let vfork_done = if spec.flags & CLONE_VFORK != 0 {
        let done = std::rc::Rc::new(std::cell::Cell::new(false));
        child_proc.vfork_done = Some(std::rc::Rc::clone(&done));
        Some(done)
    } else {
        None
    };

    if let Some(map) = child_mem {
        env.sched.group_maps.insert(child_pid, map);
    }
    env.sched.parked.push(ParkedTask {
        proc: child_proc,
        cpu: child_cpu,
        state: ParkState::Ready,
    });
    tracing::debug!(
        "spawned {} {child_pid} from {}",
        if is_thread { "thread" } else { "process" },
        env.proc.tgid,
    );

    match vfork_done {
        // Park the parent with its return value (the child pid) pre-set;
        // when the child execs or exits the parent resumes right after the
        // syscall.
        Some(done) => {
            cpu.write_var(env.regs.rax, child_pid);
            block_and_switch(env, cpu, ParkState::VforkDone { done }, false)
        }
        // Linux-like ordering: the parent keeps running; the child is
        // parked ready.
        None => Outcome::Ret(Ok(child_pid)),
    }
}

/// Reads a NUL-terminated array of string pointers (argv/envp layout).
fn read_string_vec(env: &mut LinuxEnv, cpu: &mut Cpu, mut ptr: u64) -> Result<Vec<Vec<u8>>, u64> {
    let mut out = Vec::new();
    if ptr == 0 {
        return Ok(out);
    }
    while out.len() < 4096 {
        let entry = read_mem(env, cpu, ptr, 8)?;
        let addr = u64::from_le_bytes(entry.try_into().expect("read_mem length"));
        if addr == 0 {
            return Ok(out);
        }
        // The kernel's per-string argv/envp limit (MAX_ARG_STRLEN).
        out.push(read_cstr_limit(env, cpu, addr, 128 * 1024)?);
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
            path_arg(env, cpu, path_ptr)?,
            read_string_vec(env, cpu, argv_ptr)?,
            read_string_vec(env, cpu, envp_ptr)?,
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
    let chunked = match &env.vfs.node(node).kind {
        NodeKind::File(data) if data.len() >= 4 && data[..4] == *b"\x7fELF" => false,
        NodeKind::File(_) => return Outcome::Ret(Err(abi::ENOEXEC)),
        NodeKind::ChunkedFile(_) => match env.vfs.read_node_range(node, 0, 4) {
            Ok(crate::chunk::ReadRange::Ready(bytes)) if bytes == b"\x7fELF" => true,
            Ok(crate::chunk::ReadRange::Ready(_)) => return Outcome::Ret(Err(abi::ENOEXEC)),
            Ok(crate::chunk::ReadRange::Missing(hash)) => {
                return wait_for_file_chunk(env, cpu, hash);
            }
            Ok(crate::chunk::ReadRange::Invalid(_)) => return Outcome::Ret(Err(abi::EIO)),
            Err(errno) => return Outcome::Ret(Err(errno)),
        },
        NodeKind::Dir(_) => return Outcome::Ret(Err(abi::EISDIR)),
        _ => return Outcome::Ret(Err(abi::EACCES)),
    };

    if chunked {
        if let Err(why) = crate::lazy_elf::prepare(env, &path, 0) {
            if env.awaiting_page_in() {
                // The old image is still intact. Re-present this syscall once
                // the metadata chunk arrives; only a successful full
                // preflight may pass the point of no return below.
                cpu.pending_exception = Some(cpu.exception);
                return Outcome::Exit(VmExit::Interrupted);
            }
            tracing::warn!("execve preflight refused {}: {why}", path.escape_ascii());
            return Outcome::Ret(Err(if why.starts_with("refused:") {
                abi::EACCES
            } else {
                abi::ENOEXEC
            }));
        }
    }

    // Point of no return: replace the process image.
    env.proc.argv = argv;
    env.proc.envp = envp;
    env.proc.sigactions.borrow_mut().clear();
    env.proc.signal_frames.clear();
    env.proc.altstack = None;
    env.proc.altstack_depth = 0;
    // The new image releases a suspended vfork parent.
    if let Some(done) = env.proc.vfork_done.take() {
        done.set(true);
    }
    close_cloexec_fds(env);

    // The instruction counter must survive the CPU reset inside the loader.
    let icount = cpu.icount;
    let old_asid = env.proc.asid;
    env.proc.asid = crate::alloc_asid();
    x64_engine::vm::set_current_asid(env.proc.asid);
    env.pager.drop_space(old_asid);
    env.drop_file_backed_space(old_asid);
    env.drop_dontfork_space(old_asid);
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
            if let Err(errno) = write_mem(env, cpu, status_ptr, &zombie.status.to_le_bytes()) {
                return Outcome::Ret(Err(errno));
            }
        }
        return Outcome::Ret(Ok(zombie.pid));
    }
    let untraced = options & WUNTRACED != 0;
    // WUNTRACED: a stopped child is reportable the same way an exited one
    // is, with the wait status the job-control encoding (0x7f in the low
    // byte, the stopping signal above it).
    if untraced {
        if let Some((pid, sig)) = env.sched.take_stop_report(env.proc.tgid, filter) {
            let status = ((sig as i32) << 8) | 0x7f;
            if status_ptr != 0 {
                if let Err(errno) = write_mem(env, cpu, status_ptr, &status.to_le_bytes()) {
                    return Outcome::Ret(Err(errno));
                }
            }
            return Outcome::Ret(Ok(pid));
        }
    }
    if !env.sched.has_child(env.proc.tgid, filter) {
        return Outcome::Ret(Err(abi::ECHILD));
    }
    if options & WNOHANG != 0 {
        return Outcome::Ret(Ok(0));
    }
    block_and_switch(
        env,
        cpu,
        ParkState::WaitChild {
            pid: filter,
            untraced,
        },
        true,
    )
}

fn sys_pipe(env: &mut LinuxEnv, cpu: &mut Cpu, fds_ptr: u64, flags: u64) -> SysResult {
    use crate::fd::PipeInner;

    let inner: crate::fd::PipeRef = std::rc::Rc::new(std::cell::RefCell::new(PipeInner {
        activity: 0,
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
    if let Err(errno) = write_mem(env, cpu, fds_ptr, &buf) {
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
        Inotify(crate::fd::InotifyRef),
        Event(crate::fd::EventFdRef),
        Timer(crate::fd::TimerFdRef),
        Net(crate::fd::NetRef),
        Pty(crate::fd::PtyRef, bool),
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
            Backing::Inotify(inner) => Kind::Inotify(std::rc::Rc::clone(inner)),
            Backing::EventFd(event) => Kind::Event(std::rc::Rc::clone(event)),
            Backing::TimerFd(timer) => Kind::Timer(std::rc::Rc::clone(timer)),
            Backing::Net(socket) => Kind::Net(std::rc::Rc::clone(socket)),
            Backing::PtyMaster(pty) => Kind::Pty(std::rc::Rc::clone(pty), true),
            Backing::PtySlave(pty) => Kind::Pty(std::rc::Rc::clone(pty), false),
            Backing::Epoll(_) => return Outcome::Ret(Err(abi::EINVAL)),
            _ => Kind::Plain,
        };
        (kind, nonblock)
    };
    if let Some(outcome) = ensure_guest_range(
        env,
        cpu,
        buf,
        count.min(0x40_0000) as usize,
        crate::pager::AccessKind::Write,
    ) {
        return outcome;
    }

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
        Kind::Plain => sys_read(env, cpu, fd, buf, count),
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
                inner.activity += 1;
                inner.data.drain(..take).collect()
            };
            match write_mem(env, cpu, buf, &chunk) {
                Ok(()) => Outcome::Ret(Ok(chunk.len() as u64)),
                Err(errno) => Outcome::Ret(Err(errno)),
            }
        }
        Kind::Inotify(inotify) => {
            let bytes = {
                let mut inner = inotify.borrow_mut();
                if inner.queue.is_empty() {
                    drop(inner);
                    return would_block(env, cpu, Watch::InotifyReadable(inotify));
                }
                match read_inotify(&mut inner, count.min(0x40_0000) as usize) {
                    Ok(bytes) => bytes,
                    Err(errno) => return Outcome::Ret(Err(errno)),
                }
            };
            match write_mem(env, cpu, buf, &bytes) {
                Ok(()) => Outcome::Ret(Ok(bytes.len() as u64)),
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
                inner.activity += 1;
                if inner.semaphore {
                    inner.count -= 1;
                    1_u64
                } else {
                    std::mem::take(&mut inner.count)
                }
            };
            match write_mem(env, cpu, buf, &value.to_le_bytes()) {
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
                        // How many periods went by while nothing read this.
                        // Across a suspended tab that is a large number, and
                        // the interval is the guest's own — so the next
                        // expiry is computed with arithmetic that cannot
                        // wrap. A wrapped one lands in the past and the timer
                        // fires forever.
                        match (now - expiry).checked_div(inner.interval) {
                            Some(periods) => {
                                let n = periods.saturating_add(1);
                                inner.next_expiry =
                                    Some(expiry.saturating_add(n.saturating_mul(inner.interval)));
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
            match write_mem(env, cpu, buf, &expirations.to_le_bytes()) {
                Ok(()) => Outcome::Ret(Ok(8)),
                Err(errno) => Outcome::Ret(Err(errno)),
            }
        }
        Kind::Net(socket) => {
            // This is deliberately an opt-in, metadata-only diagnostic.  It
            // helps distinguish a transport failure from a higher-level TLS
            // or HTTP failure without ever logging application bytes.
            let trace_tcp = std::env::var_os("SYSCALL_NET_TRACE").is_some()
                && socket.borrow().kind == crate::fd::SocketKind::Tcp;
            // NETLINK_ROUTE is a guest-local request/reply protocol.  Its
            // pending bytes must be consumed exactly once just like a pipe:
            // retaining them made a second recv replay the beginning of an
            // earlier dump, which can make an event loop spin forever or
            // parse one address record twice.
            if socket.borrow().kind == crate::fd::SocketKind::NetlinkRoute {
                let bytes: Vec<u8> = {
                    let mut inner = socket.borrow_mut();
                    let take = count.min(inner.local_rx.len() as u64) as usize;
                    if take == 0 {
                        return Outcome::Ret(Err(abi::EAGAIN));
                    }
                    inner.activity += 1;
                    inner.local_rx.drain(..take).collect()
                };
                return match write_mem(env, cpu, buf, &bytes) {
                    Ok(()) => Outcome::Ret(Ok(bytes.len() as u64)),
                    Err(errno) => Outcome::Ret(Err(errno)),
                };
            }
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
                    crate::fd::SocketKind::Unix => return Outcome::Ret(Err(abi::ENOTCONN)),
                    crate::fd::SocketKind::NetlinkRoute => unreachable!(
                        "guest-local NETLINK_ROUTE reads are handled before broker dispatch"
                    ),
                }
            };
            match result {
                Ok(crate::net::RecvOutcome::Data(bytes)) => {
                    if trace_tcp {
                        eprintln!(
                            "[net] pid={} fd={} tcp recv requested={} received={}",
                            env.proc.pid,
                            fd,
                            count,
                            bytes.len()
                        );
                    }
                    socket.borrow_mut().activity += 1;
                    match write_mem(env, cpu, buf, &bytes) {
                        Ok(()) => Outcome::Ret(Ok(bytes.len() as u64)),
                        Err(errno) => Outcome::Ret(Err(errno)),
                    }
                }
                Ok(crate::net::RecvOutcome::Closed) => {
                    if trace_tcp {
                        eprintln!("[net] pid={} fd={} tcp recv closed", env.proc.pid, fd);
                    }
                    Outcome::Ret(Ok(0))
                }
                Ok(crate::net::RecvOutcome::WouldBlock) => {
                    if trace_tcp {
                        eprintln!("[net] pid={} fd={} tcp recv would-block", env.proc.pid, fd);
                    }
                    would_block(env, cpu, Watch::NetReadable(socket))
                }
                Err(errno) => {
                    if trace_tcp {
                        eprintln!(
                            "[net] pid={} fd={} tcp recv errno={}",
                            env.proc.pid, fd, errno
                        );
                    }
                    Outcome::Ret(Err(errno))
                }
            }
        }
        Kind::Pty(pty, master) => {
            // Reading the terminal from a background process group is the
            // terminal's business, not this descriptor's: SIGTTIN.
            if !master {
                if let Some(outcome) = background_tty_access(env, cpu, &pty, SIGTTIN) {
                    return outcome;
                }
            }
            // A master drains slave output (`s2m`); a slave drains master
            // input (`m2s`). An empty queue is EOF once the other end is gone,
            // otherwise it blocks.
            let chunk: Vec<u8> = {
                let mut inner = pty.borrow_mut();
                let queue_empty = if master {
                    inner.s2m.is_empty()
                } else {
                    inner.m2s.is_empty()
                };
                if queue_empty {
                    let eof = if master {
                        inner.slave_ever_opened && inner.slaves == 0
                    } else {
                        inner.masters == 0
                    };
                    if eof {
                        return Outcome::Ret(Ok(0));
                    }
                    drop(inner);
                    return would_block(env, cpu, Watch::PtyReadable(pty, master));
                }
                inner.activity += 1;
                let queue = if master {
                    &mut inner.s2m
                } else {
                    &mut inner.m2s
                };
                let take = (count as usize).min(queue.len()).min(0x40_0000);
                queue.drain(..take).collect()
            };
            match write_mem(env, cpu, buf, &chunk) {
                Ok(()) => Outcome::Ret(Ok(chunk.len() as u64)),
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
        Pty(crate::fd::PtyRef, bool),
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
            Backing::PtyMaster(pty) => Kind::Pty(std::rc::Rc::clone(pty), true),
            Backing::PtySlave(pty) => Kind::Pty(std::rc::Rc::clone(pty), false),
            _ => Kind::Plain,
        };
        (kind, nonblock)
    };

    match kind {
        Kind::Plain => sys_write(env, cpu, fd, buf, count),
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
            let bytes = match read_mem(env, cpu, buf, take) {
                Ok(bytes) => bytes,
                Err(errno) => return Outcome::Ret(Err(errno)),
            };
            {
                let mut inner = pipe.borrow_mut();
                inner.data.extend(bytes.iter().copied());
                inner.activity += 1;
            }
            Outcome::Ret(Ok(take as u64))
        }
        Kind::Event(event) => {
            if count < 8 {
                return Outcome::Ret(Err(abi::EINVAL));
            }
            let bytes = match read_mem(env, cpu, buf, 8) {
                Ok(bytes) => bytes,
                Err(errno) => return Outcome::Ret(Err(errno)),
            };
            let value = u64::from_le_bytes(bytes.try_into().expect("read_mem length"));
            let mut inner = event.borrow_mut();
            inner.count = inner.count.saturating_add(value);
            inner.activity += 1;
            Outcome::Ret(Ok(8))
        }
        Kind::Net(socket) => {
            let bytes = match read_mem(env, cpu, buf, (count as usize).min(0x40_0000)) {
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
                (crate::fd::SocketKind::Udp, Some(std::net::SocketAddr::V4(peer))) => {
                    inner.broker.borrow_mut().udp_send_to(handle, peer, &bytes)
                }
                (crate::fd::SocketKind::Udp, Some(std::net::SocketAddr::V6(peer))) => inner
                    .broker
                    .borrow_mut()
                    .udp_send_to_v6(handle, peer, &bytes),
                (crate::fd::SocketKind::Udp, None) => Err(abi::EDESTADDRREQ),
                (crate::fd::SocketKind::Unix, _) => Err(abi::ENOTCONN),
                (crate::fd::SocketKind::NetlinkRoute, _) => Err(abi::EOPNOTSUPP),
            };
            if std::env::var_os("SYSCALL_NET_TRACE").is_some()
                && inner.kind == crate::fd::SocketKind::Tcp
            {
                match &result {
                    Ok(sent) => eprintln!(
                        "[net] pid={} fd={} tcp write requested={} sent={}",
                        env.proc.pid,
                        fd,
                        bytes.len(),
                        sent
                    ),
                    Err(errno) => eprintln!(
                        "[net] pid={} fd={} tcp write requested={} errno={}",
                        env.proc.pid,
                        fd,
                        bytes.len(),
                        errno
                    ),
                }
            }
            drop(inner);
            if result.is_ok() {
                socket.borrow_mut().activity += 1;
            }
            Outcome::Ret(result.map(|n| n as u64))
        }
        Kind::Pty(pty, master) => {
            let bytes = match read_mem(env, cpu, buf, (count as usize).min(0x40_0000)) {
                Ok(bytes) => bytes,
                Err(errno) => return Outcome::Ret(Err(errno)),
            };
            // Writing to the terminal from a background group is allowed
            // unless the line discipline asks otherwise with TOSTOP, which is
            // off in the default termios.
            if !master && pty.borrow().tostop() {
                if let Some(outcome) = background_tty_access(env, cpu, &pty, SIGTTOU) {
                    return outcome;
                }
            }
            let mut inner = pty.borrow_mut();
            // A master write is terminal input, which goes through the input
            // line discipline. A slave write is terminal output (into `s2m`),
            // expanding `\n` to `\r\n` when the discipline has OPOST|ONLCR.
            if master {
                let signal = inner.feed_input(&bytes);
                let pgrp = inner.fg_pgrp;
                drop(inner);
                if let Some(sig) = signal {
                    deliver_signal_to_pgrp(env, pgrp, sig);
                }
                let _ = nonblock;
                return Outcome::Ret(Ok(bytes.len() as u64));
            }
            if inner.onlcr() {
                for &b in &bytes {
                    if b == b'\n' {
                        inner.s2m.push_back(b'\r');
                    }
                    inner.s2m.push_back(b);
                }
            } else {
                inner.s2m.extend(bytes.iter().copied());
            }
            inner.activity += 1;
            let _ = nonblock;
            Outcome::Ret(Ok(bytes.len() as u64))
        }
    }
}

fn sys_futex(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr: u64,
    op: u64,
    val: u64,
    timeout_ptr: u64,
) -> Outcome {
    const FUTEX_CMD_MASK: u64 = 0x7f; // strips PRIVATE / CLOCK_REALTIME bits
    match op & FUTEX_CMD_MASK {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            let current = match read_mem(env, cpu, addr, 4) {
                Ok(bytes) => u32::from_le_bytes(bytes.try_into().expect("read_mem length")),
                Err(errno) => return Outcome::Ret(Err(errno)),
            };
            if current != val as u32 {
                return Outcome::Ret(Err(abi::EAGAIN));
            }
            {
                if timeout_ptr == 0 {
                    return block_and_switch(
                        env,
                        cpu,
                        ParkState::Futex {
                            addr,
                            woken: false,
                            deadline: None,
                        },
                        true,
                    );
                }
                // Timed wait: compute the absolute deadline once (a restart
                // would recompute a relative timeout forever), pre-set the
                // woken return value, and resume after the syscall; the
                // scheduler patches -ETIMEDOUT when the deadline fires
                // without a wake.
                let duration = match read_timespec_at(env, cpu, timeout_ptr) {
                    Ok(nanos) => nanos,
                    Err(errno) => return Outcome::Ret(Err(errno)),
                };
                const FUTEX_WAIT_ABSOLUTE: u64 = FUTEX_WAIT_BITSET;
                const FUTEX_CLOCK_REALTIME: u64 = 0x100;
                let now = env.now_nanos(cpu);
                let deadline = if op & FUTEX_CMD_MASK == FUTEX_WAIT_ABSOLUTE {
                    // Absolute deadline. `pthread_cond_timedwait` sets
                    // FUTEX_CLOCK_REALTIME, so the value is on the CLOCK_REALTIME
                    // scale (epoch-based); convert it to the internal monotonic
                    // scale before comparing, or the epoch offset (~1.79e18 ns)
                    // would be charged to the idle time-warp.
                    let abs = if op & FUTEX_CLOCK_REALTIME != 0 {
                        let base = (env.epoch_base_sec as u64).saturating_mul(1_000_000_000);
                        duration.saturating_sub(base)
                    } else {
                        duration
                    };
                    abs.max(now)
                } else {
                    now + duration
                };
                cpu.write_var(env.regs.rax, 0_u64);
                prepare_resume(env, cpu, false);
                park_current(
                    env,
                    cpu,
                    ParkState::Futex {
                        addr,
                        woken: false,
                        deadline: Some(deadline),
                    },
                );
                if schedule_next(env, cpu) {
                    Outcome::Switched
                } else {
                    stall_outcome(env, "timed futex wait with no runnable task", false)
                }
            }
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

/// Sets the pgid of every thread in `tgid` (the current task included).
/// Returns false when no such process exists.
fn set_group_pgid(env: &mut LinuxEnv, tgid: u64, pgid: u64) -> bool {
    let mut found = false;
    if env.proc.tgid == tgid {
        env.proc.pgid = pgid;
        found = true;
    }
    for task in &mut env.sched.parked {
        if task.proc.tgid == tgid {
            task.proc.pgid = pgid;
            found = true;
        }
    }
    found
}

fn sys_getpgid(env: &mut LinuxEnv, pid: u64) -> SysResult {
    if pid == 0 || pid == env.proc.tgid {
        return Ok(env.proc.pgid);
    }
    env.sched
        .parked
        .iter()
        .find(|t| t.proc.tgid == pid)
        .map(|t| t.proc.pgid)
        .ok_or(abi::ESRCH)
}

/// `setpgid(pid, pgid)`: joins (or creates) a process group. Session
/// boundaries are not modeled, so membership checks reduce to existence.
fn sys_setpgid(env: &mut LinuxEnv, pid: u64, pgid: u64) -> SysResult {
    let target = if pid == 0 { env.proc.tgid } else { pid };
    let group = if pgid == 0 { target } else { pgid };
    if set_group_pgid(env, target, group) {
        Ok(0)
    } else {
        Err(abi::ESRCH)
    }
}

/// `kill`, `tkill`, and `tgkill`.
///
/// Every signal but SIGKILL is resolved against the *target's* disposition:
/// the target runs its own handler, or takes its own default action, when it
/// is next scheduled. SIGKILL cannot be caught, blocked, or ignored, so it is
/// the one signal carried out here on the sender's behalf.
fn sys_kill(env: &mut LinuxEnv, cpu: &mut Cpu, target: u64, signal: u64) -> Outcome {
    let target = target as u32 as i32 as i64;
    // The signal number comes from the guest and indexes a bit in a 64-bit
    // pending set. Anything above the last signal has no bit, and shifting by
    // it is undefined rather than merely useless.
    if signal > NSIG {
        return Outcome::Ret(Err(abi::EINVAL));
    }
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
    // A signal a task sends to itself — `raise`, `abort`, a shell aborting
    // its own line — is resolved against the disposition rather than assumed
    // fatal. POSIX requires the handler to have run before `raise` returns,
    // so the return value and resume point are written first: the state the
    // handler snapshots then continues after the syscall instead of
    // repeating it.
    if target == env.proc.tgid as i64 || target == env.proc.pid as i64 {
        let bit = 1_u64 << (signal - 1);
        // A blocked signal is queued even when it is currently ignored: the
        // process may change the disposition before unblocking it. musl's
        // `raise` takes this path always — it blocks every signal around the
        // `tkill` — and the unblocking `rt_sigprocmask` then delivers.
        if env.proc.sigmask & bit != 0 {
            env.proc.pending_signals |= bit;
            return Outcome::Ret(Ok(0));
        }
        let disposition = env
            .proc
            .sigactions
            .borrow()
            .get(&signal)
            .map(|a| u64::from_le_bytes(a.0[..8].try_into().expect("size")));
        return match disposition {
            Some(SIG_IGN) => Outcome::Ret(Ok(0)),
            Some(handler) if handler != SIG_DFL => {
                resume_after_syscall(env, cpu, 0);
                env.proc.pending_signals |= bit;
                deliver_signal(env, cpu);
                Outcome::Switched
            }
            // The default action: terminate, stop for the job-control
            // signals, or ignore for the four signals a process is expected
            // to ignore.
            _ if default_action_terminates(signal) => task_exit(env, cpu, signal as i32, true),
            _ if default_action_stops(signal) => {
                resume_after_syscall(env, cpu, 0);
                stop_thread_group(env, cpu, signal, false)
            }
            _ => Outcome::Ret(Ok(0)),
        };
    }
    // Job-control signals to another process (or group) act on the target's
    // state directly. SIGCONT lifts a stop no matter what the target's
    // disposition says; a stop signal is queued and the target stops at its
    // next kernel entry. Both are resolved before `signal_is_nonfatal`,
    // which would otherwise drop them against the caller's own dispositions.
    const SIGCONT: u64 = 18;
    if signal == SIGCONT || default_action_stops(signal) {
        let stop_bits: u64 = [19_u64, 20, 21, 22]
            .iter()
            .map(|s| 1_u64 << (s - 1))
            .fold(0, |acc, bit| acc | bit);
        let group = |pgid: u64| {
            if target == 0 {
                pgid == env.proc.pgid
            } else {
                pgid == (-target) as u64
            }
        };
        let matches = |proc: &Process| {
            if target <= 0 {
                group(proc.pgid)
            } else {
                proc.tgid == target as u64
            }
        };
        let mut found = false;
        if matches(&env.proc) {
            // The caller is in the target group. It is running, so a stop
            // queues for its next kernel entry; a continue has only pending
            // stop signals to clear.
            found = true;
            if signal == SIGCONT {
                env.proc.pending_signals &= !stop_bits;
            } else {
                env.proc.pending_signals |= 1_u64 << (signal - 1);
            }
        }
        for task in &mut env.sched.parked {
            if !matches(&task.proc) {
                continue;
            }
            found = true;
            if signal == SIGCONT {
                // Continuing clears the stop and any not-yet-taken stop
                // signals; an uncollected stop notice is superseded.
                task.proc.stopped = false;
                task.proc.pending_signals &= !stop_bits;
                task.proc.stop_report = None;
            } else {
                task.proc.pending_signals |= 1_u64 << (signal - 1);
            }
        }
        return Outcome::Ret(if found { Ok(0) } else { Err(abi::ESRCH) });
    }

    // Group target: `-pgid` (or 0 = the caller's own group) fans out to
    // every member process. `-1` (all processes) is not modeled.
    let victims: Vec<u64> = if target == -1 {
        return Outcome::Ret(Err(abi::ESRCH));
    } else if target <= 0 {
        let pgid = if target == 0 {
            env.proc.pgid
        } else {
            (-target) as u64
        };
        let mut tgids: Vec<u64> = env
            .sched
            .parked
            .iter()
            .filter(|t| t.proc.pgid == pgid && t.proc.tgid != env.proc.tgid)
            .map(|t| t.proc.tgid)
            .collect();
        tgids.sort_unstable();
        tgids.dedup();
        if tgids.is_empty() && env.proc.pgid != pgid {
            return Outcome::Ret(Err(abi::ESRCH));
        }
        // The caller's own group is included: its disposition decides what
        // the signal means to it, the same as for any other member.
        tgids
    } else {
        vec![target as u64]
    };

    let mut found = false;
    for target in victims {
        // Every signal but SIGKILL is resolved against the target's own
        // disposition: it runs its handler, or takes its default action, when
        // it is next scheduled. Removing the task here instead would mean a
        // process could never handle a signal another process sent it, which
        // is what used to happen.
        if signal != SIGKILL {
            found |= signal_process(env, target, signal);
            continue;
        }

        // SIGKILL cannot be caught, blocked, or ignored, so it is the one
        // signal the kernel carries out on the sender's behalf.
        let mut hit = false;
        let mut index = 0;
        while index < env.sched.parked.len() {
            if env.sched.parked[index].proc.tgid == target {
                let mut task = env.sched.parked.remove(index);
                hit = true;
                // A forcibly killed vfork child must still release its
                // suspended parent, and the parent still gets SIGCHLD so a
                // self-pipe reaper can collect the zombie.
                if let Some(done) = task.proc.vfork_done.take() {
                    done.set(true);
                }
                if task.proc.pid == task.proc.tgid {
                    env.sched.zombies.push(Zombie {
                        pid: task.proc.tgid,
                        ppid: task.proc.ppid,
                        status: signal as i32,
                    });
                    notify_parent_sigchld(env, task.proc.ppid);
                }
            } else {
                index += 1;
            }
        }
        if hit && !env.sched.group_has_parked(target) {
            env.sched.group_maps.remove(&target);
        }
        found |= hit;
    }
    Outcome::Ret(if found { Ok(0) } else { Err(abi::ESRCH) })
}

/// `readv`/`writev` via the pipe-aware single-buffer path.  Network `writev`
/// is the important exception: TLS and HTTP clients routinely split a single
/// protocol record across several iovecs.  Reporting success after forwarding
/// only the first segment emits a malformed ClientHello, after which a peer
/// correctly closes the connection.  Gather the complete bounded record and
/// admit it once through the same broker path as `sendmsg`.
///
/// Non-network descriptors retain the one-segment short-transfer behavior,
/// which keeps a blocked pipe/PTY restart idempotent.
fn outcome_vectored(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    fd: u64,
    iov: u64,
    iovcnt: u64,
    write: bool,
) -> Outcome {
    let entries = match iter_iov(env, cpu, iov, iovcnt) {
        Ok(entries) => entries,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    if write {
        if let Ok(socket) = net_of(env, fd) {
            let mut bytes = Vec::new();
            for (base, len) in &entries {
                if *len == 0 {
                    continue;
                }
                let remaining = 0x40_0000_usize.saturating_sub(bytes.len());
                if remaining == 0 {
                    return Outcome::Ret(Err(abi::EMSGSIZE));
                }
                let part = match read_mem(env, cpu, *base, (*len as usize).min(remaining)) {
                    Ok(part) => part,
                    Err(errno) => return Outcome::Ret(Err(errno)),
                };
                if part.len() != *len as usize {
                    return Outcome::Ret(Err(abi::EMSGSIZE));
                }
                bytes.extend_from_slice(&part);
            }
            return Outcome::Ret(net_send_bytes(&socket, None, &bytes).map(|count| count as u64));
        }
    }
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
const AF_UNSPEC: u64 = 0;
const AF_INET: u64 = 2;
const AF_INET6: u64 = 10;
const AF_NETLINK: u64 = 16;
const SOCK_TYPE_MASK: u64 = 0xff;
const SOCK_STREAM: u64 = 1;
const SOCK_DGRAM: u64 = 2;
const SOCK_RAW: u64 = 3;
const SOCK_NONBLOCK: u64 = 0x800;
const SOCK_CLOEXEC: u64 = 0x8_0000;

const SHUT_WR: u64 = 1;
const SHUT_RDWR: u64 = 2;

const EPOLL_CTL_ADD: u64 = 1;
const EPOLL_CTL_DEL: u64 = 2;
const EPOLL_CTL_MOD: u64 = 3;
const EPOLLIN: u32 = 0x1;
const EPOLLOUT: u32 = 0x4;
const EPOLLHUP: u32 = 0x10;
const EPOLLRDHUP: u32 = 0x2000;
/// Disable an interest after one delivered event.  Userspace rearms it with
/// `EPOLL_CTL_MOD`; an ordinary readiness transition does not rearm it.
const EPOLLONESHOT: u32 = 0x4000_0000;
/// Edge-triggered: report a fd only on a not-ready→ready transition, not on
/// every wait while it stays ready.
const EPOLLET: u32 = 0x8000_0000;

/// Resolves a total stall: every task is parked and none is ready. Waits on
/// the host for network readiness, then warps the deterministic clock to
/// the earliest timer deadline. Returns the index of a task that became
/// ready, or None for a true deadlock.
fn resolve_stall(env: &mut LinuxEnv, cpu: &mut Cpu) -> Option<usize> {
    let now = env.now_nanos(cpu);

    // Host terminal input: if the guest is blocked reading the stdio pty and
    // the host has queued keystrokes, deliver them and wake. This is what lets
    // an interactive program on a pty make progress instead of deadlocking.
    if !env.stdio_input.is_empty() {
        let bytes: Vec<u8> = env.stdio_input.drain(..).collect();
        env.deliver_terminal_input(&bytes);
        if let Some(index) = env.sched.find_ready(now) {
            return Some(index);
        }
    }

    let deadline = env.sched.earliest_deadline();

    let handles = env.sched.net_watch_handles();
    if !handles.is_empty() {
        if let Some(broker) = env.net.clone() {
            // A host-driven broker owns no transport of its own: the host must
            // run its event loop before guest time may advance, or a socket
            // timeout would fire before the reply had any chance to arrive.
            // Pause once per stall. The host reports the actual bounded time
            // it waited; Machine::expire_network_wait has already credited
            // exactly that interval to the clocks. Expiry therefore admits a
            // readiness pass, not a jump to an arbitrary later deadline.
            if broker.borrow().host_driven() {
                if env.network_expired {
                    env.network_expired = false;
                    let now = env.now_nanos(cpu);
                    if let Some(index) = env.sched.find_ready(now) {
                        return Some(index);
                    }
                    env.network_wait = true;
                    return None;
                } else {
                    env.network_wait = true;
                    return None;
                }
            } else {
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
    }

    // Nothing external woke us: advance deterministic time to the earliest
    // deadline so timeouts and timers fire.
    let deadline = deadline?;
    if deadline > now {
        let delta = deadline - now;
        env.warp_nanos = env.warp_nanos.saturating_add(delta);
        cpu.time_offset = cpu.time_offset.saturating_add(delta);
        tracing::debug!("time warp: +{delta} ns (idle until deadline)");
    }
    let now = env.now_nanos(cpu);
    env.sched.find_ready(now)
}

fn parse_sockaddr_in(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr: u64,
    len: u64,
) -> Result<std::net::SocketAddrV4, u64> {
    if len < 8 {
        return Err(abi::EINVAL);
    }
    let bytes = read_mem(env, cpu, addr, 8)?;
    let family = u16::from_le_bytes(bytes[..2].try_into().expect("slice length"));
    if family as u64 != AF_INET {
        return Err(abi::EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes(bytes[2..4].try_into().expect("slice length"));
    let ip = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
    Ok(std::net::SocketAddrV4::new(ip, port))
}

fn parse_sockaddr_in6(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr: u64,
    len: u64,
) -> Result<std::net::SocketAddrV6, u64> {
    if len < 28 {
        return Err(abi::EINVAL);
    }
    let bytes = read_mem(env, cpu, addr, 28)?;
    let family = u16::from_le_bytes(bytes[..2].try_into().expect("slice length"));
    if family as u64 != AF_INET6 {
        return Err(abi::EAFNOSUPPORT);
    }
    let port = u16::from_be_bytes(bytes[2..4].try_into().expect("slice length"));
    let flowinfo = u32::from_be_bytes(bytes[4..8].try_into().expect("slice length"));
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&bytes[8..24]);
    let scope_id = u32::from_ne_bytes(bytes[24..28].try_into().expect("slice length"));
    Ok(std::net::SocketAddrV6::new(
        std::net::Ipv6Addr::from(octets),
        port,
        flowinfo,
        scope_id,
    ))
}

fn write_sockaddr(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr_ptr: u64,
    len_ptr: u64,
    addr: std::net::SocketAddr,
) -> Result<(), u64> {
    if addr_ptr == 0 {
        return Ok(());
    }
    let out = match addr {
        std::net::SocketAddr::V4(addr) => {
            let mut out = vec![0_u8; 16];
            out[..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
            out[2..4].copy_from_slice(&addr.port().to_be_bytes());
            out[4..8].copy_from_slice(&addr.ip().octets());
            out
        }
        std::net::SocketAddr::V6(addr) => {
            let mut out = vec![0_u8; 28];
            out[..2].copy_from_slice(&(AF_INET6 as u16).to_le_bytes());
            out[2..4].copy_from_slice(&addr.port().to_be_bytes());
            out[4..8].copy_from_slice(&addr.flowinfo().to_be_bytes());
            out[8..24].copy_from_slice(&addr.ip().octets());
            out[24..28].copy_from_slice(&addr.scope_id().to_ne_bytes());
            out
        }
    };
    // The caller's socklen bounds the write (the address is truncated when
    // the buffer is short); the full length is reported back regardless.
    let cap = if len_ptr != 0 {
        let bytes = read_mem(env, cpu, len_ptr, 4)?;
        u32::from_le_bytes(bytes.try_into().expect("read_mem length")) as usize
    } else {
        out.len()
    };
    write_mem(env, cpu, addr_ptr, &out[..out.len().min(cap)])?;
    if len_ptr != 0 {
        write_mem(env, cpu, len_ptr, &(out.len() as u32).to_le_bytes())?;
    }
    Ok(())
}

fn write_sockaddr_nl(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    addr_ptr: u64,
    len_ptr: u64,
    pid: u32,
    groups: u32,
) -> Result<(), u64> {
    if addr_ptr == 0 {
        return Ok(());
    }
    // struct sockaddr_nl { sa_family_t; unsigned short pad; u32 pid; u32 groups; }
    let mut out = [0_u8; 12];
    out[..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
    out[4..8].copy_from_slice(&pid.to_ne_bytes());
    out[8..12].copy_from_slice(&groups.to_ne_bytes());
    let cap = if len_ptr != 0 {
        let bytes = read_mem(env, cpu, len_ptr, 4)?;
        u32::from_le_bytes(bytes.try_into().expect("read_mem length")) as usize
    } else {
        out.len()
    };
    write_mem(env, cpu, addr_ptr, &out[..out.len().min(cap)])?;
    if len_ptr != 0 {
        write_mem(env, cpu, len_ptr, &(out.len() as u32).to_le_bytes())?;
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
    if domain != AF_INET && domain != AF_INET6 && domain != AF_UNIX && domain != AF_NETLINK {
        tracing::warn!("socket: unsupported domain {domain}");
        return Err(abi::EAFNOSUPPORT);
    }
    let broker = match env.net.clone() {
        Some(broker) => broker,
        // AF_UNIX is a local kernel facility, not an opt-in route to the
        // host network. It still needs a descriptor object so connect can
        // faithfully return ENOENT for an absent guest service such as nscd.
        None if domain == AF_UNIX || domain == AF_NETLINK => {
            std::rc::Rc::new(std::cell::RefCell::new(crate::net::HostBroker::new()))
        }
        None => {
            tracing::warn!("socket: network is denied (no broker attached)");
            return Err(abi::EAFNOSUPPORT);
        }
    };
    let kind = match (domain, sock_type & SOCK_TYPE_MASK) {
        (AF_UNIX, SOCK_STREAM | SOCK_DGRAM) => SocketKind::Unix,
        (AF_NETLINK, SOCK_RAW) if _protocol == 0 => SocketKind::NetlinkRoute,
        (_, SOCK_STREAM) => SocketKind::Tcp,
        (AF_INET | AF_INET6, SOCK_DGRAM) => SocketKind::Udp,
        (_, SOCK_DGRAM) => return Err(abi::EAFNOSUPPORT),
        other => {
            tracing::warn!("socket: unsupported type {}", other.1);
            return Err(abi::EPROTONOSUPPORT);
        }
    };
    let socket = NetSocket {
        broker,
        kind,
        family: domain,
        // Local protocol sockets do not own a broker handle; a nonzero
        // sentinel lets the shared read path reach their in-kernel queue.
        handle: (kind == SocketKind::NetlinkRoute).then_some(0),
        peer: None,
        local_rx: Default::default(),
        local_protocol_id: (kind == SocketKind::NetlinkRoute)
            .then_some(env.proc.tgid as u32)
            .unwrap_or(0),
        activity: 0,
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
    let nonblocking = env.proc.fds.borrow().get(fd)?.desc.borrow().flags & abi::O_NONBLOCK != 0;
    let socket = net_of(env, fd)?;
    let mut inner = socket.borrow_mut();
    if inner.family == AF_UNIX {
        // Linux's libc probes local nscd/system-daemon paths before falling
        // back to DNS. Validate the supplied sockaddr_un shape, then report
        // the guest-visible absence of that service as ENOENT rather than
        // pretending local IPC is an unsupported network family.
        if len < 3 {
            return Err(abi::EINVAL);
        }
        let bytes = read_mem(env, cpu, addr, (len as usize).min(108))?;
        let family = u16::from_le_bytes(bytes[..2].try_into().expect("sockaddr family"));
        if family as u64 != AF_UNIX {
            return Err(abi::EAFNOSUPPORT);
        }
        return Err(abi::ENOENT);
    }
    // Linux uses connect(AF_UNSPEC) to detach a datagram peer so that the
    // same socket can be reused for another address-family probe. It is not
    // an IPv6 sockaddr with a bad family. NativeBroker uses send_to rather
    // than an OS-level connected UDP socket, so clearing the guest peer is
    // the complete observable operation here.
    if (inner.family == AF_INET || inner.family == AF_INET6) && len >= 2 {
        let family = u16::from_le_bytes(
            read_mem(env, cpu, addr, 2)?
                .try_into()
                .expect("sockaddr family"),
        ) as u64;
        if family == AF_UNSPEC {
            inner.peer = None;
            return Ok(0);
        }
    }
    let target = match inner.family {
        AF_INET => std::net::SocketAddr::V4(parse_sockaddr_in(env, cpu, addr, len)?),
        AF_INET6 => std::net::SocketAddr::V6(parse_sockaddr_in6(env, cpu, addr, len)?),
        _ => return Err(abi::EAFNOSUPPORT),
    };
    if std::env::var_os("SYSCALL_NET_TRACE").is_some() {
        eprintln!(
            "[syscall-net] pid={} connect fd={fd} kind={:?} target={target}",
            env.proc.pid, inner.kind
        );
    }
    match inner.kind {
        SocketKind::Tcp => {
            let handle = match target {
                std::net::SocketAddr::V4(target) => {
                    inner.broker.borrow_mut().tcp_connect(target)?
                }
                std::net::SocketAddr::V6(target) => {
                    inner.broker.borrow_mut().tcp_connect_v6(target)?
                }
            };
            inner.handle = Some(handle);
        }
        SocketKind::Udp => {
            if inner.handle.is_none() {
                let handle = match target {
                    std::net::SocketAddr::V4(_) => inner.broker.borrow_mut().udp_open()?,
                    std::net::SocketAddr::V6(_) => inner.broker.borrow_mut().udp_open_v6()?,
                };
                inner.handle = Some(handle);
            }
        }
        SocketKind::Unix => return Err(abi::ENOTCONN),
        SocketKind::NetlinkRoute => return Ok(0),
    }
    inner.peer = Some(target);
    if inner.kind == SocketKind::Tcp && nonblocking {
        let handle = inner.handle.expect("TCP connect installed a broker handle");
        if matches!(
            inner.broker.borrow_mut().tcp_connect_status(handle),
            crate::net::ConnectStatus::Pending
        ) {
            return Err(abi::EINPROGRESS);
        }
    }
    Ok(0)
}

/// Implements the deliberately small, guest-local subset of NETLINK_ROUTE
/// required by runtime address discovery: RTM_GETADDR + NLM_F_DUMP. It never
/// reflects host interfaces. The result is a deterministic loopback-only
/// address view and a matching NLMSG_DONE terminator.
fn netlink_route_request(socket: &crate::fd::NetRef, request: &[u8]) -> SysResult {
    const RTM_GETADDR: u16 = 22;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_MULTI: u16 = 2;
    const NLM_F_DUMP: u16 = 0x300;
    if request.len() < 20 {
        return Err(abi::EINVAL);
    }
    let declared = u32::from_ne_bytes(request[..4].try_into().expect("netlink length")) as usize;
    let kind = u16::from_ne_bytes(request[4..6].try_into().expect("netlink type"));
    let flags = u16::from_ne_bytes(request[6..8].try_into().expect("netlink flags"));
    let sequence = u32::from_ne_bytes(request[8..12].try_into().expect("netlink sequence"));
    if declared != request.len()
        || declared < 20
        || kind != RTM_GETADDR
        || flags & (NLM_F_REQUEST | NLM_F_DUMP) != (NLM_F_REQUEST | NLM_F_DUMP)
    {
        return Err(abi::EOPNOTSUPP);
    }
    fn align4(out: &mut Vec<u8>) {
        while out.len() & 3 != 0 {
            out.push(0);
        }
    }
    fn attr(out: &mut Vec<u8>, ty: u16, value: &[u8]) {
        out.extend_from_slice(&((4 + value.len()) as u16).to_ne_bytes());
        out.extend_from_slice(&ty.to_ne_bytes());
        out.extend_from_slice(value);
        align4(out);
    }
    fn address(
        sequence: u32,
        port_id: u32,
        family: u8,
        prefix: u8,
        scope: u8,
        index: u32,
        bytes: &[u8],
        label: Option<&[u8]>,
    ) -> Vec<u8> {
        const RTM_NEWADDR: u16 = 20;
        const NLM_F_MULTI: u16 = 2;
        const IFA_ADDRESS: u16 = 1;
        const IFA_LOCAL: u16 = 2;
        const IFA_LABEL: u16 = 3;
        const IFA_CACHEINFO: u16 = 6;
        const IFA_FLAGS: u16 = 8;
        const IFA_F_PERMANENT: u32 = 0x80;
        let mut out = vec![0; 16];
        out.extend_from_slice(&[family, prefix, 0x80, scope]);
        out.extend_from_slice(&index.to_ne_bytes());
        attr(&mut out, IFA_ADDRESS, bytes);
        if family == AF_INET as u8 {
            attr(&mut out, IFA_LOCAL, bytes);
        }
        if let Some(label) = label {
            attr(&mut out, IFA_LABEL, label);
        }
        // Match the complete kernel record shape returned by RTM_GETADDR.
        // Consumers such as language runtimes treat these as address-state
        // evidence, not optional decoration. The values are synthetic and
        // stable: the virtual egress is present indefinitely, while the
        // loopback retains Linux's permanent flag.
        let address_flags = (scope == 254).then_some(IFA_F_PERMANENT).unwrap_or(0);
        attr(&mut out, IFA_FLAGS, &address_flags.to_ne_bytes());
        let cache_info = [u32::MAX, u32::MAX, 0, 0]
            .into_iter()
            .flat_map(u32::to_ne_bytes)
            .collect::<Vec<_>>();
        attr(&mut out, IFA_CACHEINFO, &cache_info);
        let len = out.len() as u32;
        out[..4].copy_from_slice(&len.to_ne_bytes());
        out[4..6].copy_from_slice(&RTM_NEWADDR.to_ne_bytes());
        out[6..8].copy_from_slice(&NLM_F_MULTI.to_ne_bytes());
        out[8..12].copy_from_slice(&sequence.to_ne_bytes());
        out[12..16].copy_from_slice(&port_id.to_ne_bytes());
        out
    }
    // Never expose a host interface or address through this virtual kernel.
    // A deterministic globally-scoped egress identity nevertheless matters:
    // modern runtimes commonly refuse to open a client socket when netlink
    // reports only loopback, documentation blocks, or private/ULA space.
    // These are synthetic logical identities, never bind targets: every
    // actual outbound operation remains mediated by the broker.
    let port_id = socket.borrow().local_protocol_id;
    let mut response = address(
        sequence,
        port_id,
        AF_INET as u8,
        8,
        254,
        1,
        &[127, 0, 0, 1],
        Some(b"lo\0"),
    );
    response.extend(address(
        sequence,
        port_id,
        AF_INET6 as u8,
        128,
        254,
        1,
        &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        None,
    ));
    response.extend(address(
        sequence,
        port_id,
        AF_INET as u8,
        24,
        0,
        2,
        &[1, 1, 1, 1],
        Some(b"eth0\0"),
    ));
    response.extend(address(
        sequence,
        port_id,
        AF_INET6 as u8,
        64,
        0,
        2,
        &[
            0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11,
        ],
        None,
    ));
    response.extend_from_slice(&20_u32.to_ne_bytes());
    response.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
    response.extend_from_slice(&NLM_F_MULTI.to_ne_bytes());
    response.extend_from_slice(&sequence.to_ne_bytes());
    response.extend_from_slice(&port_id.to_ne_bytes());
    response.extend_from_slice(&0_i32.to_ne_bytes());
    socket.borrow_mut().local_rx.extend(response);
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
    if socket.borrow().kind == SocketKind::NetlinkRoute {
        let bytes = match read_mem(env, cpu, buf, (len as usize).min(0x1_0000)) {
            Ok(bytes) => bytes,
            Err(errno) => return Outcome::Ret(Err(errno)),
        };
        return Outcome::Ret(netlink_route_request(&socket, &bytes).map(|_| bytes.len() as u64));
    }
    let family = socket.borrow().family;
    let target = match match family {
        AF_INET => parse_sockaddr_in(env, cpu, addr, addrlen).map(std::net::SocketAddr::V4),
        AF_INET6 => parse_sockaddr_in6(env, cpu, addr, addrlen).map(std::net::SocketAddr::V6),
        _ => Err(abi::EAFNOSUPPORT),
    } {
        Ok(target) => target,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let bytes = match read_mem(env, cpu, buf, (len as usize).min(0x1_0000)) {
        Ok(bytes) => bytes,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    Outcome::Ret(net_send_bytes(&socket, Some(target), &bytes).map(|n| n as u64))
}

/// Sends an already-gathered packet through a guest network descriptor.
/// `sendmsg(2)` is allowed to carry many iovecs; for UDP they form one
/// datagram, so routing only the first iovec silently corrupts DNS and other
/// protocol packets. Keep this lower-level path independent of guest memory
/// so both sendto and sendmsg share the same atomic broker admission.
fn net_send_bytes(
    socket: &crate::fd::NetRef,
    target: Option<std::net::SocketAddr>,
    bytes: &[u8],
) -> Result<usize, u64> {
    let mut inner = socket.borrow_mut();
    match inner.kind {
        SocketKind::Tcp => {
            if target.is_some() {
                return Err(abi::EISCONN);
            }
            let handle = inner.handle.ok_or(abi::ENOTCONN)?;
            let result = inner.broker.borrow_mut().tcp_send(handle, bytes);
            if std::env::var_os("SYSCALL_NET_TRACE").is_some() {
                match &result {
                    Ok(sent) => eprintln!(
                        "[net] tcp send handle={} requested={} sent={}",
                        handle,
                        bytes.len(),
                        sent
                    ),
                    Err(errno) => eprintln!(
                        "[net] tcp send handle={} requested={} errno={}",
                        handle,
                        bytes.len(),
                        errno
                    ),
                }
            }
            if result.is_ok() {
                inner.activity += 1;
            }
            result
        }
        SocketKind::Udp => {
            let peer = target.or(inner.peer).ok_or(abi::EDESTADDRREQ)?;
            let expected_family = match peer {
                std::net::SocketAddr::V4(_) => AF_INET,
                std::net::SocketAddr::V6(_) => AF_INET6,
            };
            if inner.family != expected_family {
                return Err(abi::EAFNOSUPPORT);
            }
            let broker = inner.broker.clone();
            if inner.handle.is_none() {
                let opened = match peer {
                    std::net::SocketAddr::V4(_) => broker.borrow_mut().udp_open(),
                    std::net::SocketAddr::V6(_) => broker.borrow_mut().udp_open_v6(),
                };
                inner.handle = Some(opened?);
            }
            let handle = inner.handle.expect("UDP handle set above");
            let result = match peer {
                std::net::SocketAddr::V4(peer) => {
                    broker.borrow_mut().udp_send_to(handle, peer, bytes)
                }
                std::net::SocketAddr::V6(peer) => {
                    broker.borrow_mut().udp_send_to_v6(handle, peer, bytes)
                }
            };
            if result.is_ok() {
                inner.activity += 1;
            }
            result
        }
        SocketKind::Unix => Err(abi::ENOTCONN),
        SocketKind::NetlinkRoute => Err(abi::EOPNOTSUPP),
    }
}

fn sys_recvfrom(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> Outcome {
    let [fd, buf, len, flags, addr, addrlen] = a;
    const MSG_PEEK: u64 = 0x2;
    let socket = match net_of(env, fd) {
        Ok(socket) => socket,
        // Not a network socket: plain read (recv on a socketpair).
        Err(_) => return outcome_read(env, cpu, fd, buf, len),
    };
    let is_udp = socket.borrow().kind == SocketKind::Udp;
    if !is_udp {
        return outcome_read(env, cpu, fd, buf, len);
    }
    if std::env::var_os("SYSCALL_NET_TRACE").is_some() {
        eprintln!(
            "[syscall-net] pid={} recvfrom fd={fd} requested={len} flags={flags:#x}",
            env.proc.pid,
        );
    }
    let received = {
        let (broker, handle, family) = {
            let inner = socket.borrow();
            let Some(handle) = inner.handle else {
                return Outcome::Ret(Err(abi::ENOTCONN));
            };
            (inner.broker.clone(), handle, inner.family)
        };
        let mut broker = broker.borrow_mut();
        let peek = flags & MSG_PEEK != 0;
        match (family, peek) {
            (AF_INET, false) => broker
                .udp_recv_from(handle, len as usize)
                .map(|value| value.map(|(bytes, from)| (bytes, std::net::SocketAddr::V4(from)))),
            (AF_INET, true) => broker
                .udp_peek_from(handle, len as usize)
                .map(|value| value.map(|(bytes, from)| (bytes, std::net::SocketAddr::V4(from)))),
            (AF_INET6, false) => broker
                .udp_recv_from_v6(handle, len as usize)
                .map(|value| value.map(|(bytes, from)| (bytes, std::net::SocketAddr::V6(from)))),
            (AF_INET6, true) => broker
                .udp_peek_from_v6(handle, len as usize)
                .map(|value| value.map(|(bytes, from)| (bytes, std::net::SocketAddr::V6(from)))),
            _ => Err(abi::EAFNOSUPPORT),
        }
    };
    match received {
        Ok(Some((bytes, from))) => {
            if std::env::var_os("SYSCALL_NET_TRACE").is_some() {
                eprintln!(
                    "[syscall-net] pid={} recvfrom fd={fd} from={from} bytes={} prefix={:02x?}",
                    env.proc.pid,
                    bytes.len(),
                    &bytes[..bytes.len().min(96)]
                );
            }
            socket.borrow_mut().activity += 1;
            if let Err(errno) = write_mem(env, cpu, buf, &bytes) {
                return Outcome::Ret(Err(errno));
            }
            if let Err(errno) = write_sockaddr(env, cpu, addr, addrlen, from) {
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
    write_sockaddr(env, cpu, addr, len, peer)?;
    Ok(0)
}

fn sys_getsockopt(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    let [fd, level, optname, optval, optlen, _] = a;
    let socket = net_of(env, fd)?;
    const SOL_SOCKET: u64 = 1;
    const SO_ERROR: u64 = 4;
    let value = if level == SOL_SOCKET && optname == SO_ERROR {
        let inner = socket.borrow();
        match inner.handle {
            Some(handle) => inner
                .broker
                .borrow_mut()
                .tcp_take_error(handle)?
                .unwrap_or(0) as u32,
            None => 0,
        }
    } else {
        0
    };
    if optval != 0 {
        write_mem(env, cpu, optval, &value.to_ne_bytes())?;
        if optlen != 0 {
            write_mem(env, cpu, optlen, &4_u32.to_le_bytes())?;
        }
    }
    Ok(0)
}

fn sys_socketpair(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> SysResult {
    let [domain, sock_type, _proto, sv, _, _] = a;
    if domain != AF_UNIX {
        return Err(abi::EAFNOSUPPORT);
    }
    // Stream pairs are exact; datagram/seqpacket pairs are approximated as
    // byte streams (message boundaries are not preserved).
    const SOCK_SEQPACKET: u64 = 5;
    match sock_type & SOCK_TYPE_MASK {
        SOCK_STREAM => {}
        SOCK_DGRAM | SOCK_SEQPACKET => {
            tracing::debug!(
                "socketpair: type {} approximated as a byte stream",
                sock_type & SOCK_TYPE_MASK
            );
        }
        other => {
            tracing::warn!("socketpair: unsupported type {other}");
            return Err(abi::EPROTONOSUPPORT);
        }
    }
    use crate::fd::PipeInner;
    let make_pipe = || {
        std::rc::Rc::new(std::cell::RefCell::new(PipeInner {
            data: Default::default(),
            readers: 1,
            writers: 1,
            activity: 0,
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
    write_mem(env, cpu, sv, &buf)?;
    Ok(0)
}

fn sys_eventfd(env: &mut LinuxEnv, initval: u64, flags: u64) -> SysResult {
    const EFD_SEMAPHORE: u64 = 1;
    let event = EventFdInner {
        count: initval,
        semaphore: flags & EFD_SEMAPHORE != 0,
        activity: 0,
    };
    install_fd(
        env,
        Backing::EventFd(std::rc::Rc::new(std::cell::RefCell::new(event))),
        abi::O_RDWR | (flags & abi::O_NONBLOCK),
        flags & abi::O_CLOEXEC != 0,
    )
}

/// A `timespec` read as a duration, for the five callers that wait on one:
/// `futex`, `timerfd_settime`, `pselect6`, `ppoll`, and `nanosleep`.
///
/// The guest wrote these two numbers, so neither is trustworthy. A timespec
/// that cannot be interpreted is refused rather than rounded into one that
/// can — clamping a negative second count to zero turns "this is nonsense"
/// into "wait no time at all", which is a different answer than the one the
/// kernel gives and hides the guest's mistake from it. And the arithmetic
/// saturates: seconds near `i64::MAX` scaled to nanoseconds overflow, and a
/// wrapped result is a short wait where the guest asked for a long one.
fn read_timespec_at(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64) -> Result<u64, u64> {
    let bytes = read_mem(env, cpu, addr, 16)?;
    let sec = i64::from_le_bytes(bytes[..8].try_into().expect("slice length"));
    let nsec = i64::from_le_bytes(bytes[8..].try_into().expect("slice length"));
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Err(abi::EINVAL);
    }
    Ok((sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64))
}

/// `select`'s `timeval` read as a duration, on the same terms as
/// [`read_timespec_at`]: refused if it cannot be interpreted, saturating
/// rather than wrapping when it can.
fn read_timeval_at(env: &mut LinuxEnv, cpu: &mut Cpu, addr: u64) -> Result<u64, u64> {
    let bytes = read_mem(env, cpu, addr, 16)?;
    let sec = i64::from_le_bytes(bytes[..8].try_into().expect("slice length"));
    let usec = i64::from_le_bytes(bytes[8..].try_into().expect("slice length"));
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return Err(abi::EINVAL);
    }
    Ok((sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add((usec as u64).saturating_mul(1_000)))
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
        write_mem(env, cpu, old_value, &out)?;
    }

    let interval = read_timespec_at(env, cpu, new_value)?;
    let value = read_timespec_at(env, cpu, new_value + 16)?;
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
    write_mem(env, cpu, curr, &out)?;
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
            let bytes = read_mem(env, cpu, event_ptr, 12)?;
            let events = u32::from_le_bytes(bytes[..4].try_into().expect("slice length"));
            let data = u64::from_le_bytes(bytes[4..12].try_into().expect("slice length"));
            let mut inner = epoll.borrow_mut();
            if op == EPOLL_CTL_ADD && inner.interests.contains_key(&fd) {
                return Err(abi::EEXIST);
            }
            if op == EPOLL_CTL_MOD && !inner.interests.contains_key(&fd) {
                return Err(abi::ENOENT);
            }
            inner.interests.insert(fd, (events, data));
            // A fresh ADD or MOD arms ONESHOT and starts with no delivered
            // edge.  Linux uses MOD as the explicit ONESHOT rearm operation.
            inner.oneshot_disabled.remove(&fd);
            inner.edge_fired.remove(&fd);
            Ok(0)
        }
        EPOLL_CTL_DEL => {
            let mut inner = epoll.borrow_mut();
            inner.interests.remove(&fd).ok_or(abi::ENOENT)?;
            inner.oneshot_disabled.remove(&fd);
            inner.edge_fired.remove(&fd);
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
    let mut ready: Vec<(u64, u32, u64)> = Vec::new();
    let mut watches: Vec<Watch> = Vec::new();
    // Edge-triggered bookkeeping applied after the scan (the interest map is
    // borrowed immutably during it), tracked per direction so a delivered
    // writable edge never masks a fresh readable edge on the same fd. Each
    // entry is the new suppression mask for that fd.
    let mut new_fired: Vec<(u64, u32, u64)> = Vec::new();
    {
        let inner = epoll.borrow();
        let fds = env.proc.fds.borrow();
        for (&fd, &(events, data)) in inner.interests.iter() {
            if inner.oneshot_disabled.contains(&fd) {
                continue;
            }
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
            if events & EPOLLRDHUP != 0 && desc_net_read_closed(&desc) {
                fired |= EPOLLRDHUP;
            }
            // Hang-up is reported regardless of the requested events.
            if let Backing::Pipe {
                inner,
                write_end: false,
            } = &desc.backing
            {
                if inner.borrow().writers == 0 {
                    fired |= EPOLLHUP;
                }
            }
            if events & EPOLLOUT != 0 && desc.writable() {
                if desc_write_ready(&desc) {
                    fired |= EPOLLOUT;
                } else if let Some(watch) = write_watch_of(&desc) {
                    watches.push(watch);
                }
            }
            let is_et = events & EPOLLET != 0;
            if is_et {
                // Edge tracking, per condition. Each ready condition (readable,
                // writable, hang-up) is delivered once and then suppressed while
                // it stays ready with no new activity; it re-arms the moment it
                // is observed not-ready OR the backing's activity counter moves
                // (a new write to a still-readable pipe/eventfd is a new edge,
                // exactly as the kernel re-queues the epoll item on every
                // wakeup — async runtimes drain their waker only when it is
                // reported, so suppressing it until empty loses wakeups).
                // Tracking the conditions independently is essential: a
                // delivered writable edge (an empty send buffer on a fresh
                // connect) must not mask the readable edge that arrives later
                // (the peer's first bytes) on the same fd.
                let act = backing_activity(&desc);
                let (prev_mask, prev_act) = inner.edge_fired.get(&fd).copied().unwrap_or((0, act));
                let prev = if act == prev_act { prev_mask } else { 0 };
                let report = fired & !prev;
                if fired != prev_mask || act != prev_act {
                    new_fired.push((fd, fired, act));
                }
                if report != 0 && ready.len() < max_events {
                    ready.push((fd, report, data));
                } else if fired != 0 {
                    // Ready but suppressed: nothing to report now, yet fresh
                    // activity must wake a parked waiter so the new edge is
                    // seen. Watch the activity counter itself.
                    if let Some(watch) = activity_watch_of(&desc) {
                        watches.push(watch);
                    }
                }
                continue;
            }
            if fired != 0 && ready.len() < max_events {
                ready.push((fd, fired, data));
            }
        }
    }
    if !new_fired.is_empty() {
        let mut inner = epoll.borrow_mut();
        for (fd, mask, act) in new_fired {
            if mask == 0 {
                inner.edge_fired.remove(&fd);
            } else {
                inner.edge_fired.insert(fd, (mask, act));
            }
        }
    }

    if !ready.is_empty() {
        // Disarm only entries actually copied to this wait's result. A ready
        // ONESHOT entry beyond maxevents was not delivered and remains armed.
        {
            let mut inner = epoll.borrow_mut();
            for (fd, _, _) in &ready {
                if inner
                    .interests
                    .get(fd)
                    .is_some_and(|(events, _)| events & EPOLLONESHOT != 0)
                {
                    inner.oneshot_disabled.insert(*fd);
                }
            }
        }
        let mut out = Vec::with_capacity(ready.len() * 12);
        for (_, events, data) in &ready {
            out.extend_from_slice(&events.to_le_bytes());
            out.extend_from_slice(&data.to_le_bytes());
        }
        if let Err(errno) = write_mem(env, cpu, events_ptr, &out) {
            return Outcome::Ret(Err(errno));
        }
        return Outcome::Ret(Ok(ready.len() as u64));
    }

    let timeout_ms = timeout_ms as u32 as i32;
    if timeout_ms == 0 {
        return Outcome::Ret(Ok(0));
    }
    if timeout_ms > 0 {
        let deadline = now + timeout_ms as u64 * 1_000_000;
        return park_timeout_returning_zero(env, cpu, watches, deadline);
    }
    // Infinite wait: restart semantics re-evaluate readiness on wakeup.
    block_and_switch(
        env,
        cpu,
        ParkState::Waiting {
            watches,
            deadline: None,
        },
        true,
    )
}

/// `epoll_pwait2` differs from epoll_pwait only in its optional `timespec`
/// timeout. Signal-mask replacement is not modelled by the deterministic
/// guest, but timeout precision is: round a non-zero nanosecond interval up
/// to the millisecond scheduler tick so it never expires early.
fn sys_epoll_pwait2(env: &mut LinuxEnv, cpu: &mut Cpu, mut a: [u64; 6]) -> Outcome {
    let timeout_ptr = a[3];
    if timeout_ptr == 0 {
        a[3] = u64::MAX; // epoll_wait's conventional infinite timeout (-1).
        return sys_epoll_wait(env, cpu, a);
    }
    let bytes = match read_mem(env, cpu, timeout_ptr, 16) {
        Ok(bytes) => bytes,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let sec = i64::from_le_bytes(bytes[..8].try_into().expect("timespec seconds"));
    let nsec = i64::from_le_bytes(bytes[8..].try_into().expect("timespec nanoseconds"));
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return Outcome::Ret(Err(abi::EINVAL));
    }
    let nanos = (sec as u128)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u128);
    let millis = nanos.saturating_add(999_999) / 1_000_000;
    a[3] = millis.min(i32::MAX as u128) as u64;
    sys_epoll_wait(env, cpu, a)
}

/// `select`/`pselect6` over readable/writable fd sets. Evaluates
/// immediately; blocks with restart semantics when nothing is ready and
/// the timeout allows it.
fn sys_select(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6], timespec: bool) -> Outcome {
    let [nfds, readfds, writefds, exceptfds, timeout_ptr, _] = a;
    let nfds = nfds.min(1024) as usize;
    let words = nfds.div_ceil(64);
    let now = env.now_nanos(cpu);

    let read_set = |env: &mut LinuxEnv, cpu: &mut Cpu, ptr: u64| -> Result<Vec<u64>, u64> {
        if ptr == 0 || words == 0 {
            return Ok(vec![0; words]);
        }
        let bytes = read_mem(env, cpu, ptr, words * 8)?;
        Ok(bytes
            .as_chunks::<8>()
            .0
            .iter()
            .map(|word| u64::from_le_bytes(*word))
            .collect())
    };
    let (rset, wset) = match (read_set(env, cpu, readfds), read_set(env, cpu, writefds)) {
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
            if want_write && desc.writable() {
                if desc_write_ready(&desc) {
                    w_out[word] |= bit;
                    count += 1;
                } else if let Some(watch) = write_watch_of(&desc) {
                    watches.push(watch);
                }
            }
        }
    }

    let timeout = if timeout_ptr == 0 {
        None
    } else if timespec {
        match read_timespec_at(env, cpu, timeout_ptr) {
            Ok(nanos) => Some(nanos),
            Err(errno) => return Outcome::Ret(Err(errno)),
        }
    } else {
        match read_timeval_at(env, cpu, timeout_ptr) {
            Ok(nanos) => Some(nanos),
            Err(errno) => return Outcome::Ret(Err(errno)),
        }
    };

    if count == 0 && timeout != Some(0) {
        match timeout {
            Some(t) => {
                // Sets were already written back zeroed; a zero return on
                // wake is a valid (spurious-wakeup) select result.
                return park_timeout_returning_zero(env, cpu, watches, now + t);
            }
            None => {
                return block_and_switch(
                    env,
                    cpu,
                    ParkState::Waiting {
                        watches,
                        deadline: None,
                    },
                    true,
                );
            }
        }
    }

    let write_set = |env: &mut LinuxEnv, cpu: &mut Cpu, ptr: u64, set: &[u64]| -> Result<(), u64> {
        if ptr == 0 {
            return Ok(());
        }
        let bytes: Vec<u8> = set.iter().flat_map(|w| w.to_le_bytes()).collect();
        write_mem(env, cpu, ptr, &bytes)
    };
    if let Err(errno) = write_set(env, cpu, readfds, &r_out) {
        return Outcome::Ret(Err(errno));
    }
    if let Err(errno) = write_set(env, cpu, writefds, &w_out) {
        return Outcome::Ret(Err(errno));
    }
    if exceptfds != 0 {
        let zeros = vec![0_u8; words * 8];
        if let Err(errno) = write_mem(env, cpu, exceptfds, &zeros) {
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
        match read_mem(env, cpu, offset_ptr, 8) {
            Ok(bytes) => u64::from_le_bytes(bytes.try_into().expect("read_mem length")),
            Err(errno) => return Outcome::Ret(Err(errno)),
        }
    } else {
        base_offset
    };

    let chunk: Vec<u8> = if env.is_host_secret_node(node) {
        let Some(secret) = env.host_secret_for_node(node) else {
            return Outcome::Ret(Err(abi::EACCES));
        };
        let start = offset_into(offset, secret.len());
        let end = start
            .saturating_add(count.min(0x4_0000) as usize)
            .min(secret.len());
        secret[start..end].to_vec()
    } else {
        match env
            .vfs
            .read_node_range(node, offset, count.min(0x4_0000) as usize)
        {
            Ok(crate::chunk::ReadRange::Ready(bytes)) => bytes,
            Ok(crate::chunk::ReadRange::Missing(hash)) => {
                return wait_for_file_chunk(env, cpu, hash);
            }
            Ok(crate::chunk::ReadRange::Invalid(_)) => return Outcome::Ret(Err(abi::EIO)),
            Err(errno) => return Outcome::Ret(Err(errno)),
        }
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
        if let Err(errno) = write_mem(env, cpu, offset_ptr, &next.to_le_bytes()) {
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
            match read_timespec_at(env, cpu, timeout_arg) {
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
    let records = match read_mem(env, cpu, fds_ptr, nfds.min(1024) as usize * 8) {
        Ok(records) => records,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    {
        let fds = env.proc.fds.borrow();
        for record in records.as_chunks::<8>().0 {
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
                // Match the readiness scan above and epoll's blocking path:
                // a pending non-blocking network connect is not writable yet,
                // but it is still a host-owned wait that must keep the
                // scheduler from warping directly to the poll timeout.
                if let Some(watch) = write_watch_of(&desc) {
                    watches.push(watch);
                }
            }
        }
    }
    match timeout {
        Some(t) => park_timeout_returning_zero(env, cpu, watches, now + t),
        None => block_and_switch(
            env,
            cpu,
            ParkState::Waiting {
                watches,
                deadline: None,
            },
            true,
        ),
    }
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
        let path = path_arg(env, cpu, path_ptr)?;
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
        let bytes = read_mem(env, cpu, times_ptr + 16, 16)?;
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

/// Reads a `struct msghdr`: (name ptr, name len, iov ptr, iov count).
/// Control messages are not modeled and are reported as absent.
fn read_msghdr(env: &mut LinuxEnv, cpu: &mut Cpu, msg: u64) -> Result<(u64, u64, u64, u64), u64> {
    let bytes = read_mem(env, cpu, msg, 56)?;
    let field = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().expect("slice length"));
    Ok((field(0), field(8) & 0xffff_ffff, field(16), field(24)))
}

/// `sendmsg`: name + iovec gather (control data unsupported and refused).
fn sys_sendmsg(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> Outcome {
    let [fd, msg, _flags, _, _, _] = a;
    let (name, name_len, iov, iovcnt) = match read_msghdr(env, cpu, msg) {
        Ok(parts) => parts,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let entries = match iter_iov(env, cpu, iov, iovcnt) {
        Ok(entries) => entries,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    if let Ok(socket) = net_of(env, fd) {
        let mut bytes = Vec::new();
        for (base, len) in &entries {
            if *len == 0 {
                continue;
            }
            let remaining = 0x40_0000_usize.saturating_sub(bytes.len());
            if remaining == 0 {
                return Outcome::Ret(Err(abi::EMSGSIZE));
            }
            let part = match read_mem(env, cpu, *base, (*len as usize).min(remaining)) {
                Ok(part) => part,
                Err(errno) => return Outcome::Ret(Err(errno)),
            };
            bytes.extend_from_slice(&part);
            if part.len() < *len as usize {
                return Outcome::Ret(Err(abi::EMSGSIZE));
            }
        }
        let target = if name == 0 {
            Ok(None)
        } else {
            let family = socket.borrow().family;
            match family {
                AF_INET => {
                    parse_sockaddr_in(env, cpu, name, name_len).map(std::net::SocketAddr::V4)
                }
                AF_INET6 => {
                    parse_sockaddr_in6(env, cpu, name, name_len).map(std::net::SocketAddr::V6)
                }
                _ => Err(abi::EAFNOSUPPORT),
            }
            .map(Some)
        };
        return Outcome::Ret(
            target.and_then(|target| net_send_bytes(&socket, target, &bytes).map(|n| n as u64)),
        );
    }
    // Non-network descriptors retain the existing short-write behavior.
    for (base, len) in entries {
        if len == 0 {
            continue;
        }
        if name != 0 {
            return sys_sendto(env, cpu, [fd, base, len, 0, name, name_len]);
        }
        return outcome_write(env, cpu, fd, base, len);
    }
    Outcome::Ret(Ok(0))
}

/// `sendmmsg(2)`: submit a bounded batch of `struct mmsghdr` records. Modern
/// resolvers send A and AAAA queries this way; treating the syscall as absent
/// prevents name resolution before a client can open its TCP socket.
fn sys_sendmmsg(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> Outcome {
    let [fd, msgvec, vlen, flags, _, _] = a;
    // Linux rejects absurdly large counts. The compatibility layer also
    // keeps a hard bound so a hostile guest cannot force unbounded host work.
    if vlen > 1024 {
        return Outcome::Ret(Err(abi::EINVAL));
    }
    let mut completed = 0_u64;
    // On x86-64 `struct mmsghdr` is one 56-byte msghdr followed by a u32
    // msg_len and 4 bytes of padding, so its stride is 64 bytes.
    for index in 0..vlen {
        let message = match msgvec.checked_add(index.saturating_mul(64)) {
            Some(message) => message,
            None => return Outcome::Ret(Err(abi::EFAULT)),
        };
        match sys_sendmsg(env, cpu, [fd, message, flags, 0, 0, 0]) {
            Outcome::Ret(Ok(length)) => {
                if std::env::var_os("SYSCALL_NET_TRACE").is_some() {
                    if let Ok((_, _, iov, iovcnt)) = read_msghdr(env, cpu, message) {
                        if let Ok(entries) = iter_iov(env, cpu, iov, iovcnt) {
                            let mut prefix = Vec::new();
                            for (base, len) in entries {
                                let remaining = 32_usize.saturating_sub(prefix.len());
                                if remaining == 0 {
                                    break;
                                }
                                if let Ok(bytes) =
                                    read_mem(env, cpu, base, (len as usize).min(remaining))
                                {
                                    prefix.extend_from_slice(&bytes);
                                }
                            }
                            eprintln!(
                                "[syscall-net] pid={} sendmmsg fd={fd} index={index} bytes={length} prefix={prefix:02x?}",
                                env.proc.pid
                            );
                        }
                    }
                }
                if let Err(errno) =
                    write_mem(env, cpu, message + 56, &(length as u32).to_le_bytes())
                {
                    return Outcome::Ret(Err(errno));
                }
                completed += 1;
            }
            Outcome::Ret(Err(errno)) if completed == 0 => return Outcome::Ret(Err(errno)),
            Outcome::Ret(Err(_)) => return Outcome::Ret(Ok(completed)),
            other => return other,
        }
    }
    Outcome::Ret(Ok(completed))
}

/// `recvmsg`: name + iovec scatter (first segment; control data absent —
/// msg_controllen is zeroed so callers do not read stale lengths).
fn sys_recvmsg(env: &mut LinuxEnv, cpu: &mut Cpu, a: [u64; 6]) -> Outcome {
    let [fd, msg, _flags, _, _, _] = a;
    let (name, name_len, iov, iovcnt) = match read_msghdr(env, cpu, msg) {
        Ok(parts) => parts,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    if let Err(errno) = write_mem(env, cpu, msg + 40, &0_u64.to_le_bytes()) {
        return Outcome::Ret(Err(errno)); // msg_controllen = 0
    }
    let entries = match iter_iov(env, cpu, iov, iovcnt) {
        Ok(entries) => entries,
        Err(errno) => return Outcome::Ret(Err(errno)),
    };
    let is_netlink_route =
        net_of(env, fd).is_ok_and(|socket| socket.borrow().kind == SocketKind::NetlinkRoute);
    for (base, len) in entries {
        if len == 0 {
            continue;
        }
        // `recvfrom` takes a socklen_t *pointer*; the msghdr carries the
        // buffer length by value, so the address length is written back into
        // msg_namelen (offset 8) here instead. Passing the scalar through
        // would make recvfrom scribble 4 bytes at that guest address.
        let required_name_len = if is_netlink_route { 12 } else { 16 };
        let cap_name = if name != 0 && name_len >= required_name_len {
            name
        } else {
            0
        };
        let out = sys_recvfrom(env, cpu, [fd, base, len, 0, cap_name, 0]);
        if let Outcome::Ret(Ok(_)) = out {
            if cap_name != 0 {
                // A NETLINK_ROUTE response is kernel-originated and carries
                // sockaddr_nl (family, pad, pid, groups), not sockaddr_in.
                // Returning the latter's 16-byte length makes callers which
                // validate the ancillary address discard an otherwise valid
                // RTM_GETADDR dump.
                let address_len = if is_netlink_route {
                    let mut sender = [0_u8; 12];
                    sender[..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
                    if let Err(errno) = write_mem(env, cpu, cap_name, &sender) {
                        return Outcome::Ret(Err(errno));
                    }
                    12_u32
                } else {
                    16_u32
                };
                if let Err(errno) = write_mem(env, cpu, msg + 8, &address_len.to_le_bytes()) {
                    return Outcome::Ret(Err(errno));
                }
            }
        }
        return out;
    }
    Outcome::Ret(Ok(0))
}

/// `nanosleep`/`clock_nanosleep`: park until the deadline so other tasks
/// run during the sleep; when everything is idle, the scheduler warps the
/// deterministic clock to the deadline. Zero-length sleeps still yield.
fn outcome_nanosleep(env: &mut LinuxEnv, cpu: &mut Cpu, req: u64, absolute: bool) -> Outcome {
    let duration = if req == 0 {
        0
    } else {
        match read_timespec_at(env, cpu, req) {
            Ok(nanos) => nanos,
            Err(errno) => return Outcome::Ret(Err(errno)),
        }
    };
    let now = env.now_nanos(cpu);
    let deadline = if absolute {
        duration.max(now)
    } else {
        now + duration
    };
    cpu.write_var(env.regs.rax, 0_u64);
    prepare_resume(env, cpu, false);
    park_current(
        env,
        cpu,
        ParkState::Waiting {
            watches: Vec::new(),
            deadline: Some(deadline),
        },
    );
    if schedule_next(env, cpu) {
        Outcome::Switched
    } else {
        stall_outcome(
            env,
            "sleep with no runnable task and no deadline progress",
            false,
        )
    }
}

/// Parks on `watches` with a timeout, returning 0 to the guest on wake
/// (whether the deadline fired or a watch became ready — callers loop and
/// the next invocation reports real readiness). Restart semantics cannot
/// be used with relative timeouts: re-executing the syscall would re-arm
/// the full timeout forever.
fn park_timeout_returning_zero(
    env: &mut LinuxEnv,
    cpu: &mut Cpu,
    watches: Vec<Watch>,
    deadline: u64,
) -> Outcome {
    cpu.write_var(env.regs.rax, 0_u64);
    prepare_resume(env, cpu, false);
    park_current(
        env,
        cpu,
        ParkState::Waiting {
            watches,
            deadline: Some(deadline),
        },
    );
    if schedule_next(env, cpu) {
        Outcome::Switched
    } else {
        stall_outcome(env, "timed wait with no runnable task", false)
    }
}
