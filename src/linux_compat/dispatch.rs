//! Main Linux syscall dispatcher.
//!
//! Routes Linux x86_64 syscall numbers to the appropriate ATOS handlers.

use crate::serial_println;
use super::constants::*;
use super::state;
use super::memory;
use super::fs;
use super::process;
use super::signal;
use super::network;
use super::epoll;
use super::time;
use super::identity;

/// Dispatch a Linux x86_64 syscall to the appropriate handler.
///
/// Returns the Linux-convention result: >= 0 on success, negative errno on error.
pub fn dispatch(agent_id: u16, num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    // Ensure the agent has a Linux compat state initialised
    if state::get_state(agent_id).is_none() {
        state::init_state(agent_id);
    }

    match num {
        // ── File I/O ────────────────────────────────────────────────────
        SYS_READ => fs::sys_read(agent_id, a1 as i32, a2, a3),
        SYS_WRITE => fs::sys_write(agent_id, a1 as i32, a2, a3),
        SYS_OPEN => fs::sys_open(agent_id, a1, a2 as u32, a3 as u32),
        SYS_CLOSE => fs::sys_close(agent_id, a1 as i32),
        SYS_STAT => fs::sys_stat(agent_id, a1, a2),
        SYS_FSTAT => fs::sys_fstat(agent_id, a1 as i32, a2),
        SYS_LSTAT => fs::sys_lstat(agent_id, a1, a2),
        SYS_POLL => fs::sys_poll(agent_id, a1, a2, a3 as i32),
        SYS_LSEEK => fs::sys_lseek(agent_id, a1 as i32, a2 as i64, a3 as u32),
        SYS_PREAD64 => fs::sys_pread64(agent_id, a1 as i32, a2, a3, a4),
        SYS_PWRITE64 => fs::sys_pwrite64(agent_id, a1 as i32, a2, a3, a4),
        SYS_READV => fs::sys_readv(agent_id, a1 as i32, a2, a3),
        SYS_WRITEV => fs::sys_writev(agent_id, a1 as i32, a2, a3),
        SYS_ACCESS => fs::sys_access(agent_id, a1, a2 as u32),
        SYS_PIPE => fs::sys_pipe(agent_id, a1),
        SYS_PIPE2 => fs::sys_pipe2(agent_id, a1, a2 as i32),
        SYS_SELECT => fs::sys_select(agent_id, a1, a2, a3, a4, a5),
        SYS_DUP => fs::sys_dup(agent_id, a1 as i32),
        SYS_DUP2 => fs::sys_dup2(agent_id, a1 as i32, a2 as i32),
        SYS_FCNTL => fs::sys_fcntl(agent_id, a1 as i32, a2 as u32, a3),
        SYS_FLOCK => fs::sys_flock(agent_id, a1 as i32, a2 as u32),
        SYS_FSYNC => fs::sys_fsync(agent_id, a1 as i32),
        SYS_GETCWD => fs::sys_getcwd(agent_id, a1, a2),
        SYS_CHDIR => fs::sys_chdir(agent_id, a1),
        SYS_MKDIR => fs::sys_mkdir(agent_id, a1, a2 as u32),
        SYS_READLINK => fs::sys_readlink(agent_id, a1, a2, a3),
        SYS_GETDENTS64 => fs::sys_getdents64(agent_id, a1 as i32, a2, a3),
        SYS_IOCTL => fs::sys_ioctl(agent_id, a1 as i32, a2, a3),

        // ── Memory management ───────────────────────────────────────────
        SYS_MMAP => memory::sys_mmap(agent_id, a1, a2, a3 as u32, a4 as u32, a5 as i32, 0),
        SYS_MPROTECT => memory::sys_mprotect(agent_id, a1, a2, a3 as u32),
        SYS_MUNMAP => memory::sys_munmap(agent_id, a1, a2),
        SYS_BRK => memory::sys_brk(agent_id, a1),
        SYS_MREMAP => -ENOSYS,
        SYS_MSYNC => 0,  // no-op: no real pages to sync
        SYS_MADVISE => memory::sys_madvise(agent_id, a1, a2, a3 as u32),

        // ── Process control ─────────────────────────────────────────────
        SYS_CLONE => process::sys_clone(agent_id, a1, a2, a3, a4, a5),
        SYS_CLONE3 => process::sys_clone3(agent_id, a1, a2),
        SYS_FORK => process::sys_fork(agent_id),
        SYS_EXECVE => process::sys_execve(agent_id, a1, a2, a3),
        SYS_EXIT => process::sys_exit(agent_id, a1 as i32),
        SYS_EXIT_GROUP => process::sys_exit_group(agent_id, a1 as i32),
        SYS_WAIT4 => process::sys_wait4(agent_id, a1, a2, a3, a4),
        SYS_KILL => process::sys_kill(agent_id, a1 as i32, a2 as i32),
        SYS_GETPID => process::sys_getpid(agent_id),
        SYS_GETTID => process::sys_gettid(agent_id),
        SYS_GETPPID => {
            // Return parent agent id or 1
            match crate::agent::get_agent(agent_id) {
                Some(a) => match a.parent_id {
                    Some(pid) => pid as i64,
                    None => 1,
                },
                None => 1,
            }
        }
        SYS_SCHED_YIELD => process::sys_sched_yield(agent_id),
        SYS_SET_TID_ADDRESS => process::sys_set_tid_address(agent_id, a1),
        SYS_SET_ROBUST_LIST => process::sys_set_robust_list(agent_id, a1, a2),
        SYS_GET_ROBUST_LIST => process::sys_get_robust_list(agent_id, a1, a2, a3),
        SYS_PRCTL => process::sys_prctl(agent_id, a1 as u32, a2, a3, a4, a5),
        SYS_SCHED_GETAFFINITY => process::sys_sched_getaffinity(agent_id, a1 as u32, a2, a3),
        SYS_GETRUSAGE => process::sys_getrusage(agent_id, a1 as i32, a2),
        SYS_CAPGET => process::sys_capget(agent_id, a1, a2),
        SYS_FUTEX => 0,  // single-threaded agents don't truly block

        // ── Signals ─────────────────────────────────────────────────────
        SYS_RT_SIGACTION => signal::sys_rt_sigaction(agent_id, a1, a2, a3, a4),
        SYS_RT_SIGPROCMASK => signal::sys_rt_sigprocmask(agent_id, a1, a2, a3, a4),
        SYS_RT_SIGRETURN => signal::sys_rt_sigreturn(agent_id),

        // ── Networking ──────────────────────────────────────────────────
        SYS_SOCKET => network::sys_socket(agent_id, a1 as i32, a2 as i32, a3 as i32),
        SYS_CONNECT => network::sys_connect(agent_id, a1 as i32, a2, a3),
        SYS_ACCEPT => network::sys_accept(agent_id, a1 as i32, a2, a3),
        SYS_SENDTO => network::sys_sendto(agent_id, a1 as i32, a2, a3, a4, a5),
        SYS_RECVFROM => network::sys_recvfrom(agent_id, a1 as i32, a2, a3, a4, a5),
        SYS_SENDMSG => network::sys_sendmsg(agent_id, a1 as i32, a2, a3),
        SYS_RECVMSG => network::sys_recvmsg(agent_id, a1 as i32, a2, a3),
        SYS_SHUTDOWN => network::sys_shutdown(agent_id, a1 as i32, a2 as i32),
        SYS_BIND => network::sys_bind(agent_id, a1 as i32, a2, a3),
        SYS_LISTEN => network::sys_listen(agent_id, a1 as i32, a2 as i32),
        SYS_GETSOCKNAME => network::sys_getsockname(agent_id, a1 as i32, a2, a3),
        SYS_GETPEERNAME => network::sys_getpeername(agent_id, a1 as i32, a2, a3),
        SYS_SOCKETPAIR => network::sys_socketpair(agent_id, a1, a2, a3, a4),
        SYS_SETSOCKOPT => network::sys_setsockopt(agent_id, a1 as i32, a2, a3, a4, a5),
        SYS_GETSOCKOPT => network::sys_getsockopt(agent_id, a1 as i32, a2, a3, a4, a5),

        // ── Epoll ───────────────────────────────────────────────────────
        SYS_EPOLL_CREATE => epoll::sys_epoll_create(agent_id, a1 as i32),
        SYS_EPOLL_CREATE1 => epoll::sys_epoll_create1(agent_id, a1 as i32),
        SYS_EPOLL_CTL => epoll::sys_epoll_ctl(agent_id, a1 as i32, a2 as i32, a3 as i32, a4),
        SYS_EPOLL_WAIT => epoll::sys_epoll_wait(agent_id, a1 as i32, a2, a3 as i32, a4 as i32),
        SYS_EVENTFD2 => epoll::sys_eventfd2(agent_id, a1 as u32, a2 as i32),

        // ── Time ────────────────────────────────────────────────────────
        SYS_NANOSLEEP => time::sys_nanosleep(agent_id, a1, a2),
        SYS_GETITIMER => time::sys_getitimer(agent_id, a1, a2),
        SYS_ALARM => time::sys_alarm(agent_id, a1 as u32),
        SYS_SETITIMER => time::sys_setitimer(agent_id, a1, a2, a3),
        SYS_CLOCK_GETTIME => time::sys_clock_gettime(agent_id, a1, a2),
        SYS_CLOCK_GETRES => time::sys_clock_getres(agent_id, a1, a2),

        // ── Identity / system info ──────────────────────────────────────
        SYS_GETUID => identity::sys_getuid(agent_id),
        SYS_GETGID => identity::sys_getgid(agent_id),
        SYS_GETEUID => identity::sys_geteuid(agent_id),
        SYS_GETEGID => identity::sys_getegid(agent_id),
        SYS_SETPGID => identity::sys_setpgid(agent_id, a1, a2),
        SYS_GETPGID => identity::sys_getpgid(agent_id, a1),
        SYS_GETGROUPS => identity::sys_getgroups(agent_id, a1, a2),
        SYS_SETGROUPS => identity::sys_setgroups(agent_id, a1, a2),
        SYS_UNAME => identity::sys_uname(agent_id, a1),
        SYS_SYSINFO => identity::sys_sysinfo(agent_id, a1),
        SYS_ARCH_PRCTL => identity::sys_arch_prctl(agent_id, a1 as i32, a2),
        SYS_PRLIMIT64 => identity::sys_prlimit64(agent_id, a1, a2, a3, a4),

        // ── Random ──────────────────────────────────────────────────────
        SYS_GETRANDOM => identity::sys_getrandom(agent_id, a1, a2, a3),

        // ── Unknown ─────────────────────────────────────────────────────
        _ => {
            serial_println!(
                "[linux_compat] agent {}: unimplemented syscall {}",
                agent_id, num
            );
            -ENOSYS
        }
    }
}
