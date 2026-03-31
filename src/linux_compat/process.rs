//! Process-related Linux syscall implementations.
//!
//! Maps Linux process/thread primitives onto ATOS deterministic agents.
//! clone3 is the critical syscall: it creates a child agent that shares the
//! parent's keyspace and gets a deterministic, sequential agent_id.

extern crate alloc;

use crate::agent::{self, AgentContext, AgentId, AgentMode, AgentStatus, MAX_AGENTS, USER_STACK_SIZE};
use crate::arch::x86_64::timer;
use crate::linux_compat::constants::*;
use crate::linux_compat::state::{self, MAX_FDS, MAX_LINUX_AGENTS};
use crate::sched;
use crate::serial_println;

// ── ATOS utsname constants ─────────────────────────────────────────────────

const UTSNAME_LENGTH: usize = 65;

// ── RLIMIT constants ───────────────────────────────────────────────────────

const RLIMIT_NOFILE: u64 = 7;
const RLIMIT_STACK: u64 = 3;

// ── FUTEX operations ───────────────────────────────────────────────────────

const FUTEX_WAIT: u32 = 0;
const FUTEX_WAKE: u32 = 1;
const FUTEX_REQUEUE: u32 = 3;
const FUTEX_WAIT_BITSET: u32 = 9;
const FUTEX_WAKE_BITSET: u32 = 10;
const FUTEX_PRIVATE_FLAG: u32 = 128;
const FUTEX_CLOCK_REALTIME: u32 = 256;
const FUTEX_WAITERS_BIT: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3FFF_FFFF;

const ROBUST_LIST_LIMIT: usize = 2048;

/// Default bitmask: match everything (used by plain FUTEX_WAIT/FUTEX_WAKE).
const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

// ── FUTEX wait queue ──────────────────────────────────────────────────────

const MAX_FUTEX_WAITERS: usize = MAX_LINUX_AGENTS * 2;

// Kerla-aligned execve envelope. execve itself is still stubbed, but the
// interface limits are defined here so future argument parsing uses a
// Linux-like shape instead of ad hoc fixed buffers.
const EXECVE_ARG_MAX: usize = 512;
const EXECVE_ARG_LEN_MAX: usize = 4096;
const EXECVE_ENV_MAX: usize = 512;
const EXECVE_ENV_LEN_MAX: usize = 4096;

#[derive(Clone, Copy)]
struct FutexWaiter {
    agent_id: u16,
    futex_addr: u64,
    bitset: u32,
    deadline_tick: u64,
    active: bool,
}

const FUTEX_WAITER_EMPTY: FutexWaiter = FutexWaiter {
    agent_id: 0,
    futex_addr: 0,
    bitset: FUTEX_BITSET_MATCH_ANY,
    deadline_tick: 0,
    active: false,
};

static mut FUTEX_WAITERS: [FutexWaiter; MAX_FUTEX_WAITERS] =
    [FUTEX_WAITER_EMPTY; MAX_FUTEX_WAITERS];

const FUTEX_WAIT_NONE: i64 = i64::MIN;

static mut FUTEX_WAIT_RESULTS: [i64; MAX_AGENTS] = [FUTEX_WAIT_NONE; MAX_AGENTS];

#[repr(C)]
#[derive(Clone, Copy)]
struct RobustList {
    next: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RobustListHead {
    list: RobustList,
    futex_offset: i64,
    list_op_pending: u64,
}

#[inline]
fn set_futex_wait_result(agent_id: u16, result: i64) {
    let idx = agent_id as usize;
    if idx < MAX_AGENTS {
        unsafe {
            FUTEX_WAIT_RESULTS[idx] = result;
        }
    }
}

#[inline]
fn take_futex_wait_result(agent_id: u16) -> i64 {
    let idx = agent_id as usize;
    if idx >= MAX_AGENTS {
        return 0;
    }
    unsafe {
        let result = FUTEX_WAIT_RESULTS[idx];
        FUTEX_WAIT_RESULTS[idx] = FUTEX_WAIT_NONE;
        if result == FUTEX_WAIT_NONE { 0 } else { result }
    }
}

#[inline]
fn clear_futex_wait_state(agent_id: u16) {
    let idx = agent_id as usize;
    if idx < MAX_AGENTS {
        unsafe {
            FUTEX_WAIT_RESULTS[idx] = FUTEX_WAIT_NONE;
            for waiter in FUTEX_WAITERS.iter_mut() {
                if waiter.active && waiter.agent_id == agent_id {
                    waiter.active = false;
                }
            }
        }
    }
}

fn agent_cr3(agent_id: u16) -> Option<u64> {
    agent::get_agent(agent_id)
        .map(|agent| agent.context.cr3)
        .filter(|cr3| *cr3 != 0)
}

fn copy_from_user(agent_id: u16, user_addr: u64, dst: &mut [u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };

    let mut copied = 0usize;
    while copied < dst.len() {
        let vaddr = user_addr.saturating_add(copied as u64);
        let Some(phys) = crate::arch::x86_64::paging::translate_virt(cr3, vaddr) else {
            return false;
        };
        let page_off = (vaddr as usize) & (crate::arch::x86_64::paging::PAGE_SIZE - 1);
        let chunk_len = (dst.len() - copied).min(crate::arch::x86_64::paging::PAGE_SIZE - page_off);
        unsafe {
            core::ptr::copy_nonoverlapping(
                crate::arch::x86_64::paging::phys_to_virt(phys) as *const u8,
                dst.as_mut_ptr().add(copied),
                chunk_len,
            );
        }
        copied += chunk_len;
    }

    true
}

fn copy_to_user(agent_id: u16, user_addr: u64, src: &[u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };

    let mut copied = 0usize;
    while copied < src.len() {
        let vaddr = user_addr.saturating_add(copied as u64);
        let Some(phys) = crate::arch::x86_64::paging::translate_virt(cr3, vaddr) else {
            return false;
        };
        let page_off = (vaddr as usize) & (crate::arch::x86_64::paging::PAGE_SIZE - 1);
        let chunk_len = (src.len() - copied).min(crate::arch::x86_64::paging::PAGE_SIZE - page_off);
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr().add(copied),
                crate::arch::x86_64::paging::phys_to_virt(phys) as *mut u8,
                chunk_len,
            );
        }
        copied += chunk_len;
    }

    true
}

fn read_user_u32(agent_id: u16, user_addr: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    copy_from_user(agent_id, user_addr, &mut bytes).then(|| u32::from_ne_bytes(bytes))
}

fn read_user_u64(agent_id: u16, user_addr: u64) -> Option<u64> {
    let mut bytes = [0u8; 8];
    copy_from_user(agent_id, user_addr, &mut bytes).then(|| u64::from_ne_bytes(bytes))
}

fn read_user_i64(agent_id: u16, user_addr: u64) -> Option<i64> {
    let mut bytes = [0u8; 8];
    copy_from_user(agent_id, user_addr, &mut bytes).then(|| i64::from_ne_bytes(bytes))
}

fn write_user_u32(agent_id: u16, user_addr: u64, value: u32) -> bool {
    copy_to_user(agent_id, user_addr, &value.to_ne_bytes())
}

fn wake_clear_child_tid(agent_id: u16, clear_child_tid: u64) {
    if clear_child_tid == 0 {
        return;
    }

    let _ = write_user_u32(agent_id, clear_child_tid, 0);
    let _ = sys_futex(agent_id, clear_child_tid, FUTEX_WAKE as u64, 1, 0, 0, 0);
}

fn robust_futex_addr(entry_ptr: u64, futex_offset: i64) -> Option<u64> {
    futex_offset
        .checked_add(entry_ptr as i64)
        .map(|addr| addr as u64)
}

fn wake_robust_futex(agent_id: u16, futex_addr: u64) {
    if futex_addr == 0 || !futex_addr.is_multiple_of(core::mem::align_of::<u32>() as u64) {
        return;
    }

    let Some(old_val) = read_user_u32(agent_id, futex_addr) else {
        return;
    };

    if old_val & FUTEX_TID_MASK != agent_id as u32 {
        return;
    }

    let new_val = (old_val & FUTEX_WAITERS_BIT) | FUTEX_OWNER_DIED;
    if !write_user_u32(agent_id, futex_addr, new_val) {
        return;
    }

    if new_val & FUTEX_WAITERS_BIT != 0 {
        let _ = sys_futex(agent_id, futex_addr, FUTEX_WAKE as u64, 1, 0, 0, 0);
    }
}

fn wake_robust_list(agent_id: u16, head_ptr: u64) {
    if head_ptr == 0 {
        return;
    }

    let Some(list_next) = read_user_u64(agent_id, head_ptr) else {
        return;
    };
    let Some(futex_offset) = read_user_i64(agent_id, head_ptr + 8) else {
        return;
    };
    let pending = read_user_u64(agent_id, head_ptr + 16).unwrap_or(0);

    let mut entry_ptr = list_next;
    let end_ptr = list_next;
    let mut count = 0usize;

    while (entry_ptr != end_ptr || count == 0) && count < ROBUST_LIST_LIMIT {
        if entry_ptr == 0 {
            break;
        }

        if entry_ptr != pending {
            if let Some(futex_addr) = robust_futex_addr(entry_ptr, futex_offset) {
                wake_robust_futex(agent_id, futex_addr);
            }
        }

        let Some(next) = read_user_u64(agent_id, entry_ptr) else {
            break;
        };
        entry_ptr = next;
        count += 1;
    }

    if pending != 0 {
        if let Some(futex_addr) = robust_futex_addr(pending, futex_offset) {
            wake_robust_futex(agent_id, futex_addr);
        }
    }
}

/// Prepare Linux thread-local termination state.
///
/// Mirrors the split used by Asterinas/Moss: thread-local exit artifacts
/// (`clear_child_tid`, robust futex list, futex wait-queue membership) are
/// cleaned up independently from the shared address-space lifetime.
pub fn prepare_agent_termination(agent_id: u16) {
    clear_futex_wait_state(agent_id);

    let (clear_child_tid, robust_list_head) = match state::get_state_mut(agent_id) {
        Some(ls) => {
            let clear_child_tid = ls.clear_child_tid;
            let robust_list_head = ls.robust_list_head;
            ls.clear_child_tid = 0;
            ls.robust_list_head = 0;
            ls.active = false;
            (clear_child_tid, robust_list_head)
        }
        None => (0, 0),
    };

    wake_clear_child_tid(agent_id, clear_child_tid);
    wake_robust_list(agent_id, robust_list_head);
}

/// Wake timed futex waiters whose deadlines have expired.
pub fn futex_tick() {
    let now = timer::get_ticks();
    let mut expired: [u16; MAX_FUTEX_WAITERS] = [0; MAX_FUTEX_WAITERS];
    let mut expired_count = 0usize;

    unsafe {
        for i in 0..MAX_FUTEX_WAITERS {
            let waiter = &mut FUTEX_WAITERS[i];
            if waiter.active && agent::get_agent(waiter.agent_id).is_none() {
                waiter.active = false;
                continue;
            }
            if waiter.active && waiter.deadline_tick != 0 && now >= waiter.deadline_tick {
                waiter.active = false;
                set_futex_wait_result(waiter.agent_id, -ETIMEDOUT);
                expired[expired_count] = waiter.agent_id;
                expired_count += 1;
            }
        }
    }

    for wid in expired.into_iter().take(expired_count) {
        if let Some(agent) = agent::get_agent_mut(wid) {
            if agent.status == AgentStatus::BlockedRecv {
                agent.status = AgentStatus::Ready;
            }
        }
        sched::add_to_run_queue(wid);
    }
}

// ── wait4 options ─────────────────────────────────────────────────────────

const WNOHANG: u64 = 1;

// ── Clone3 args layout (subset of Linux struct clone_args) ─────────────────

/// Minimal clone_args parsed from user memory.
/// See linux/sched.h: struct clone_args.
#[repr(C)]
#[derive(Clone, Copy)]
struct CloneArgs {
    flags: u64,       // offset 0
    pidfd: u64,       // offset 8
    child_tid: u64,   // offset 16
    parent_tid: u64,  // offset 24
    exit_signal: u64, // offset 32
    stack: u64,       // offset 40
    stack_size: u64,  // offset 48
    tls: u64,         // offset 56
}

const CLONE_ARGS_MIN_SIZE: u64 = 64;

extern "C" {
    static mut CURRENT_SYSCALL_FRAME: u64;
    fn enter_user_clone_return();
}

/// Saved SYSCALL frame exposed by `asm/syscall_entry.asm`.
///
/// The layout starts at the FXSAVE area base and matches the stack slots
/// pushed on kernel entry:
///   fxsave[512], r15, r14, r13, r12, rbp, rbx, r10, r9, r8, rdx, rsi, rdi,
///   user_rflags, user_rip, user_rsp, kernel_stack_top
#[repr(C)]
#[derive(Clone, Copy)]
struct SyscallSavedFrame {
    fpu_state: [u8; 512],
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    user_rflags: u64,
    user_rip: u64,
    user_rsp: u64,
    kernel_stack_top: u64,
}

fn snapshot_current_syscall_frame() -> Option<SyscallSavedFrame> {
    unsafe {
        let ptr = CURRENT_SYSCALL_FRAME as *const SyscallSavedFrame;
        if ptr.is_null() {
            None
        } else {
            Some(core::ptr::read_volatile(ptr))
        }
    }
}

fn build_clone_child_context(
    frame: &SyscallSavedFrame,
    child_kernel_stack_top: u64,
    child_user_rsp: u64,
    child_cr3: u64,
) -> AgentContext {
    let mut ctx = AgentContext::zero();
    ctx.rsp = child_kernel_stack_top;
    ctx.rip = enter_user_clone_return as *const () as u64;
    ctx.rax = 0; // clone returns 0 in the child
    ctx.rbx = frame.rbx;
    ctx.rcx = frame.user_rip;
    ctx.rdx = frame.rdx;
    ctx.rsi = frame.rsi;
    ctx.rdi = frame.rdi;
    ctx.rbp = frame.rbp;
    ctx.r8 = frame.r8;
    ctx.r9 = child_user_rsp;
    ctx.r10 = frame.r10;
    ctx.r11 = frame.user_rflags | 0x2;
    ctx.r12 = frame.r12;
    ctx.r13 = frame.r13;
    ctx.r14 = frame.r14;
    ctx.r15 = frame.r15;
    ctx.rflags = 0x200;
    ctx.cr3 = child_cr3;
    ctx.fpu_state = frame.fpu_state;
    ctx
}

// Clone flag bits we care about
#[allow(dead_code)]
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_THREAD: u64 = 0x0001_0000;

fn inherit_linux_state_for_clone(
    parent_id: u16,
    child_id: u16,
    flags: u64,
    tls: u64,
    child_tid_ptr: u64,
) {
    let Some(parent_state) = state::get_state(parent_id) else {
        return;
    };

    let fd_table = parent_state.fd_table;
    let dir_handles = parent_state.dir_handles;
    let cwd = parent_state.cwd;
    let cwd_len = parent_state.cwd_len;
    let brk_current = parent_state.brk_current;
    let mmap_next = parent_state.mmap_next;
    let vm_space_owner = parent_state.vm_space_owner;
    let uid = parent_state.uid;
    let gid = parent_state.gid;
    let prng_state = parent_state.prng_state;
    let prng_counter = parent_state.prng_counter;
    let epoll_instances = parent_state.epoll_instances;
    let fs_base = parent_state.fs_base;
    let gs_base = parent_state.gs_base;
    let exe_path = parent_state.exe_path;
    let exe_path_len = parent_state.exe_path_len;
    let parent_pid = parent_state.pid;

    if let Some(child_state) = state::get_state_mut(child_id) {
        child_state.fd_table = fd_table;
        child_state.dir_handles = dir_handles;
        child_state.cwd = cwd;
        child_state.cwd_len = cwd_len;
        child_state.brk_current = brk_current;
        child_state.mmap_next = mmap_next;
        child_state.vm_space_owner = if flags & CLONE_VM != 0 {
            vm_space_owner
        } else {
            child_id
        };
        child_state.uid = uid;
        child_state.gid = gid;
        child_state.prng_state = prng_state;
        child_state.prng_counter = prng_counter;
        child_state.epoll_instances = epoll_instances;
        child_state.fs_base = if flags & CLONE_SETTLS != 0 {
            tls
        } else {
            fs_base
        };
        child_state.gs_base = gs_base;
        child_state.exe_path = exe_path;
        child_state.exe_path_len = exe_path_len;
        child_state.pid = if flags & CLONE_THREAD != 0 {
            parent_pid
        } else {
            child_id as u32
        };

        if flags & CLONE_CHILD_SETTID != 0 && child_tid_ptr != 0 {
            unsafe {
                core::ptr::write_volatile(child_tid_ptr as *mut u32, child_id as u32);
            }
        }
        if flags & CLONE_CHILD_CLEARTID != 0 {
            child_state.clear_child_tid = child_tid_ptr;
        }
    }
}

#[inline]
fn thread_group_pid(agent_id: u16) -> u32 {
    state::get_state(agent_id)
        .map(|st| st.pid)
        .unwrap_or(agent_id as u32)
}

#[inline]
fn thread_group_leader(agent_id: u16) -> u16 {
    let leader_id = thread_group_pid(agent_id) as u16;
    if agent::get_agent(leader_id).is_some() {
        leader_id
    } else {
        agent_id
    }
}

#[inline]
fn is_thread_group_worker(agent_id: u16) -> bool {
    thread_group_pid(agent_id) != agent_id as u32
}

fn has_other_active_group_members(agent_id: u16) -> bool {
    let group_pid = thread_group_pid(agent_id);
    for id in 0..MAX_AGENTS as u16 {
        if id == agent_id {
            continue;
        }
        if let Some(ls) = state::get_state(id) {
            if ls.active && ls.pid == group_pid {
                return true;
            }
        }
    }
    false
}

#[inline]
fn clone_child_parent(agent_id: u16, flags: u64) -> Option<AgentId> {
    if flags & CLONE_THREAD != 0 {
        // Linux threads inherit the process parent. They are not children of
        // the thread-group leader.
        agent::get_agent(agent_id).and_then(|agent| agent.parent_id)
    } else {
        Some(agent_id)
    }
}

#[inline]
fn trace_runtime_agent(agent_id: u16) -> bool {
    state::trace_runtime_agent(agent_id)
}

fn log_clone_vma(agent_id: u16, label: &str, addr: u64) {
    let vm_owner = state::get_state(agent_id)
        .map(|st| {
            if st.vm_space_owner != 0 {
                st.vm_space_owner
            } else {
                agent_id
            }
        })
        .unwrap_or(agent_id);

    let Some(vm_state) = state::get_state(vm_owner) else {
        serial_println!(
            "[RTDBG] clone3-vma agent={} owner={} {}={:#x} state=missing",
            agent_id,
            vm_owner,
            label,
            addr
        );
        return;
    };

    if let Some(idx) = vm_state.find_vma_index(addr) {
        let vma = vm_state.vmas[idx];
        serial_println!(
            "[RTDBG] clone3-vma agent={} owner={} {}={:#x} idx={} vma=[{:#x},{:#x}) prot={:#x} flags={:#x} kind={:?} file_off={:#x}",
            agent_id,
            vm_owner,
            label,
            addr,
            idx,
            vma.start,
            vma.end(),
            vma.prot,
            vma.flags,
            vma.kind,
            vma.file_offset
        );
    } else {
        serial_println!(
            "[RTDBG] clone3-vma agent={} owner={} {}={:#x} vma=missing",
            agent_id,
            vm_owner,
            label,
            addr
        );
    }
}

// ── prctl options ──────────────────────────────────────────────────────────

const PR_SET_NAME: u32 = 15;
const PR_GET_NAME: u32 = 16;

// ── Per-agent metadata (names, etc.) ───────────────────────────────────────

/// Agent names set via prctl(PR_SET_NAME).
static mut AGENT_NAMES: [[u8; 16]; MAX_LINUX_AGENTS] = [[0u8; 16]; MAX_LINUX_AGENTS];

// ── Syscall implementations ────────────────────────────────────────────────

/// clone3(2) -- Create a new thread/agent deterministically.
///
/// This is the most important Linux-compat syscall. It maps Linux threads
/// to ATOS child agents with deterministic, sequential agent IDs.
///
/// 1. Parse clone_args from user memory
/// 2. Create child agent via agent::create_agent()
/// 3. Child shares parent keyspace (same keyspace_id)
/// 4. Initialize LinuxAgentState for child (copy fd_table from parent)
/// 5. Add child to deterministic scheduler
/// 6. Return child agent_id as pid to parent, 0 to child
pub fn sys_clone3(agent_id: u16, cl_args_ptr: u64, size: u64) -> i64 {
    if cl_args_ptr == 0 {
        return -EFAULT;
    }
    if size < CLONE_ARGS_MIN_SIZE {
        return -EINVAL;
    }

    // Parse clone_args from user memory.
    // Safety: we trust the agent's address space is valid (single-core kernel).
    let args: CloneArgs = unsafe {
        let ptr = cl_args_ptr as *const CloneArgs;
        if ptr.is_null() {
            return -EFAULT;
        }
        core::ptr::read_volatile(ptr)
    };

    // Read parent agent to split energy and memory quota.
    let (parent_energy, parent_mem_quota) = match agent::get_agent(agent_id) {
        Some(parent) => (parent.energy_budget, parent.memory_quota),
        None => return -ESRCH,
    };

    // Child gets half of parent's remaining resources.
    let child_energy = parent_energy / 2;
    let child_mem_quota = parent_mem_quota / 2;

    // Deduct from parent.
    if let Some(parent) = agent::get_agent_mut(agent_id) {
        parent.energy_budget -= child_energy;
        parent.memory_quota -= child_mem_quota;
    }

    let frame = match snapshot_current_syscall_frame() {
        Some(frame) => frame,
        None => return -EINVAL,
    };
    let child_user_rsp = if args.stack != 0 {
        if args.stack_size != 0 {
            args.stack + args.stack_size
        } else {
            args.stack
        }
    } else {
        frame.user_rsp
    };
    if trace_runtime_agent(agent_id) {
        serial_println!(
            "[RTDBG] clone3-enter agent={} flags={:#x} stack={:#x} stack_size={:#x} child_rsp={:#x} tls={:#x} ptid={:#x} ctid={:#x} exit_signal={:#x}",
            agent_id,
            args.flags,
            args.stack,
            args.stack_size,
            child_user_rsp,
            args.tls,
            args.parent_tid,
            args.child_tid,
            args.exit_signal
        );
    }
    let child_kernel_stack_top = sched::allocate_agent_stack();
    if child_kernel_stack_top == 0 {
        return -ENOMEM;
    }

    // Create the child agent.
    let child_parent = clone_child_parent(agent_id, args.flags);
    let child_id = match agent::create_agent(
        child_parent,
        enter_user_clone_return as *const () as u64,
        child_kernel_stack_top,
        child_energy,
        child_mem_quota,
    ) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let clone_vm = args.flags & CLONE_VM != 0;
    let parent_cr3 = match agent::get_agent(agent_id) {
        Some(parent) => parent.context.cr3,
        None => return -ESRCH,
    };
    let child_cr3 = if clone_vm {
        let _ = crate::arch::x86_64::paging::retain_address_space(parent_cr3);
        parent_cr3
    } else if let Some(new_cr3) = crate::arch::x86_64::paging::create_linux_address_space() {
        new_cr3
    } else {
        agent::terminate_agent(child_id, AgentStatus::Faulted);
        return -ENOMEM;
    };

    if let Some(child) = agent::get_agent_mut(child_id) {
        child.mode = AgentMode::User;
        child.kernel_stack_top = child_kernel_stack_top;
        child.stack_bottom = sched::stack_bottom_from_top(child_kernel_stack_top);
        child.context =
            build_clone_child_context(&frame, child_kernel_stack_top, child_user_rsp, child_cr3);
        child.status = AgentStatus::Ready;
    } else {
        return -ESRCH;
    }

    state::init_state(child_id);
    inherit_linux_state_for_clone(agent_id, child_id, args.flags, args.tls, args.child_tid);

    if trace_runtime_agent(agent_id) {
        serial_println!(
            "[RTDBG] clone3-child parent={} child={} cr3={:#x} kernel_stack_top={:#x} kernel_stack_bottom={:#x}",
            agent_id,
            child_id,
            child_cr3,
            child_kernel_stack_top,
            sched::stack_bottom_from_top(child_kernel_stack_top)
        );
        if args.stack != 0 {
            log_clone_vma(child_id, "stack_base", args.stack);
        }
        if child_user_rsp != 0 {
            log_clone_vma(child_id, "stack_rsp_minus_8", child_user_rsp.saturating_sub(8));
        }
        if args.tls != 0 {
            log_clone_vma(child_id, "tls", args.tls);
        }
    }

    // Handle CLONE_PARENT_SETTID: write child tid to parent_tid address.
    if args.flags & CLONE_PARENT_SETTID != 0 && args.parent_tid != 0 {
        unsafe {
            let ptr = args.parent_tid as *mut u32;
            core::ptr::write_volatile(ptr, child_id as u32);
        }
    }

    // Add child to the deterministic scheduler run queue.
    sched::add_to_run_queue(child_id);

    serial_println!(
        "[linux_compat] clone3: parent={} child={} flags={:#x}",
        agent_id,
        child_id,
        args.flags
    );

    // Return child's agent_id as pid to parent.
    child_id as i64
}

/// execve(2) -- Replace current agent with a new program image.
///
/// In ATOS, this spawns a new Linux agent from the target ELF binary
/// (resolved via VFS) with the provided argv, then exits the calling agent.
/// The new agent inherits the caller's parent.
pub fn sys_execve(agent_id: u16, pathname_ptr: u64, argv_ptr: u64, envp_ptr: u64) -> i64 {
    // 1. Read pathname
    let mut path_buf = [0u8; state::MAX_PATH];
    let path_len = unsafe { read_user_cstr(pathname_ptr, &mut path_buf) };
    if path_len == 0 {
        return -ENOENT;
    }
    let path = &path_buf[..path_len];

    // 2. Resolve path → keyspace and load the binary
    let (ks, key) = crate::linux_compat::vfs::resolve_path(agent_id, path);

    // Embedded base-image files can be executed directly without copying the
    // whole ELF into the kernel heap. This is critical for large runtimes such
    // as host-installed Node.js whose executable can exceed 100 MiB.
    if ks == crate::state::BASE_IMAGE_KEYSPACE {
        if let Some(entry) = crate::base_image::find_by_key(key) {
            return do_execve(agent_id, path, entry.data, argv_ptr, envp_ptr);
        }
    }

    let image_size = crate::state::query_file_size(ks, key);
    if image_size == 0 {
        return -ENOENT;
    }
    if image_size > crate::agent_loader::max_linux_image_size() {
        serial_println!(
            "[execve] image too large: path={:?} size={} limit={}",
            core::str::from_utf8(path).unwrap_or("?"),
            image_size,
            crate::agent_loader::max_linux_image_size()
        );
        return -ENOMEM;
    }

    let mut image_buf = alloc::vec![0u8; image_size];
    let image_len = crate::state::load_multi_segment(ks, key, &mut image_buf);
    if image_len == 0 {
        // Try plain state_get for small files
        match crate::state::state_get(ks, key) {
            Some((val, len)) => {
                image_buf[..len].copy_from_slice(&val[..len]);
                if len == 0 {
                    return -ENOENT;
                }
                // Use len as image_len below
                let image_len = len;
                return do_execve(agent_id, path, &image_buf[..image_len], argv_ptr, envp_ptr);
            }
            None => return -ENOENT,
        }
    }

    do_execve(agent_id, path, &image_buf[..image_len], argv_ptr, envp_ptr)
}

fn do_execve(agent_id: u16, path: &[u8], image: &[u8], argv_ptr: u64, envp_ptr: u64) -> i64 {
    let elf_info = match crate::loader::parse_elf64(image) {
        Ok(info) => info,
        Err(_) => return -ENOEXEC,
    };

    // 3. Read argv from user memory
    let mut argv_bufs: [[u8; 256]; 32] = [[0u8; 256]; 32];
    let mut argv_lens: [usize; 32] = [0; 32];
    let mut argc: usize = 0;

    if argv_ptr != 0 {
        for i in 0..32 {
            let ptr = unsafe { core::ptr::read((argv_ptr + (i as u64) * 8) as *const u64) };
            if ptr == 0 {
                break;
            }
            let len = unsafe { read_user_cstr(ptr, &mut argv_bufs[i]) };
            argv_lens[i] = len;
            argc += 1;
        }
    }

    // Build argv slice references
    let mut argv_refs: [&[u8]; 32] = [b"" as &[u8]; 32];
    for i in 0..argc {
        argv_refs[i] = &argv_bufs[i][..argv_lens[i]];
    }

    // 4. Read envp from user memory
    let mut envp_bufs: [[u8; 256]; 32] = [[0u8; 256]; 32];
    let mut envp_lens: [usize; 32] = [0; 32];
    let mut envc: usize = 0;

    if envp_ptr != 0 {
        for i in 0..32 {
            let ptr = unsafe { core::ptr::read((envp_ptr + (i as u64) * 8) as *const u64) };
            if ptr == 0 {
                break;
            }
            let len = unsafe { read_user_cstr(ptr, &mut envp_bufs[i]) };
            envp_lens[i] = len;
            envc += 1;
        }
    }

    let mut envp_refs: [&[u8]; 32] = [b"" as &[u8]; 32];
    for i in 0..envc {
        envp_refs[i] = &envp_bufs[i][..envp_lens[i]];
    }

    // 5. Determine parent: use the current agent's parent
    let parent_id = agent::get_agent(agent_id)
        .and_then(|a| a.parent_id)
        .unwrap_or(1); // fallback to root

    let energy = agent::get_agent(agent_id)
        .map(|a| a.energy_budget)
        .unwrap_or(100_000);

    let mem_quota = agent::get_agent(agent_id)
        .map(|a| a.memory_quota)
        .unwrap_or(256);

    // 6. Spawn new Linux agent with the loaded image
    match crate::agent_loader::spawn_linux_agent_with_env(
        parent_id,
        image,
        energy,
        mem_quota,
        path,
        &argv_refs[..argc],
        &envp_refs[..envc],
    ) {
        Ok(new_id) => {
            serial_println!(
                "[execve] agent {} replaced by {} ({:?})",
                agent_id,
                new_id,
                core::str::from_utf8(path).unwrap_or("?")
            );
            // 7. Exit the calling agent — same sequence as sys_exit()
            if let Some(ls) = state::get_state_mut(agent_id) {
                ls.active = false;
            }
            sched::remove_from_run_queue(agent_id);
            agent::terminate_agent(agent_id, AgentStatus::Exited);
            // Never restore the old caller's kernel continuation after a
            // successful exec replacement.
            sched::switch_without_current()
        }
        Err(e) => {
            serial_println!("[execve] failed to spawn: error {}", e);
            e
        }
    }
}

/// Read a null-terminated string from user memory into buf.
/// Returns the number of bytes read (excluding NUL).
unsafe fn read_user_cstr(ptr: u64, buf: &mut [u8]) -> usize {
    if ptr == 0 {
        return 0;
    }
    let max = buf.len();
    let mut len = 0;
    while len < max {
        let b = core::ptr::read((ptr + len as u64) as *const u8);
        if b == 0 {
            break;
        }
        buf[len] = b;
        len += 1;
    }
    len
}

fn debug_python_exit_rela() {
    let probes: [(&str, u64); 6] = [
        ("main-last-rel", 0x4006_9120),
        ("main-first-nonrel", 0x4006_9138),
        ("interp-last-rel", 0x7f00_1a90),
        ("libm-last-rel", 0x10000_cf50),
        ("libexpat-last-rel", 0x1000e_c038),
        ("libc-last-rel", 0x10015_d290),
    ];

    for (label, addr) in probes {
        let a = unsafe { core::ptr::read_volatile(addr as *const u64) };
        let b = unsafe { core::ptr::read_volatile((addr + 8) as *const u64) };
        let c = unsafe { core::ptr::read_volatile((addr + 16) as *const u64) };
        serial_println!(
            "[PYDBG] exit-rela {} addr={:#x} val0={:#x} val1={:#x} val2={:#x}",
            label,
            addr,
            a,
            b,
            c
        );
    }

    let regions: [(&str, u64, u64); 6] = [
        ("main", 0x4001_b060, 0x3409),
        ("interp", 0x7f00_0d58, 142),
        ("libm", 0x10000_cf20, 3),
        ("libexpat", 0x1000e_a760, 266),
        ("libz", 0x10011_ba88, 28),
        ("libc", 0x10015_6270, 1197),
    ];

    for (label, rela, relacount) in regions {
        let mut first_bad = None;
        for idx in 0..relacount {
            let entry = rela + idx * 24;
            let info = unsafe { core::ptr::read_volatile((entry + 8) as *const u64) };
            if info != 0x8 {
                first_bad = Some((idx, entry, info));
                break;
            }
        }
        match first_bad {
            Some((idx, entry, info)) => serial_println!(
                "[PYDBG] exit-validate {} first_bad_idx={} entry={:#x} info={:#x}",
                label,
                idx,
                entry,
                info
            ),
            None => serial_println!(
                "[PYDBG] exit-validate {} ok relacount={}",
                label,
                relacount
            ),
        }
    }
}

/// exit(2) -- Terminate the calling agent.
pub fn sys_exit(agent_id: u16, status: i32) -> i64 {
    crate::syscall::set_linux_exit_debug_stage(0xE210);
    serial_println!("[linux_compat] exit: agent={} status={}", agent_id, status);
    if status == 127
        && (state::exe_path_eq(agent_id, b"/usr/bin/python3")
            || state::exe_path_eq(agent_id, b"/usr/bin/java")
            || state::exe_path_eq(agent_id, b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java"))
    {
        debug_python_exit_rela();
    }

    let notify_parent = !is_thread_group_worker(agent_id) && !has_other_active_group_members(agent_id);

    // Read parent_id before termination (terminate sets active=false).
    let parent_id = if notify_parent {
        agent::get_agent(agent_id).and_then(|agent| agent.parent_id)
    } else {
        None
    };

    // Remove from scheduler and terminate.
    sched::remove_from_run_queue(agent_id);
    if notify_parent {
        agent::terminate_agent(agent_id, AgentStatus::Exited);
    } else {
        agent::terminate_agent_no_reparent(agent_id, AgentStatus::Exited);
    }

    // Raise SIGCHLD on the parent agent.
    if let Some(pid) = parent_id {
        super::state::raise_signal(pid, 17); // SIGCHLD = 17
    }

    // Wake parent if it's blocked in wait4.
    if let Some(pid) = parent_id {
        if let Some(parent) = agent::get_agent_mut(pid) {
            if parent.status == AgentStatus::BlockedRecv {
                parent.status = AgentStatus::Ready;
                sched::add_to_run_queue(pid);
            }
        }
    }

    // This syscall never returns; the scheduler will pick the next agent.
    crate::syscall::set_linux_exit_debug_stage(0xE230);
    sched::switch_without_current()
}

/// exit_group(2) -- Terminate all threads in the thread group.
///
/// In Linux-compat mode, all agents with the same `pid` field belong to the
/// same thread group. `exit_group` must terminate every member, not just the
/// caller.
pub fn sys_exit_group(agent_id: u16, status: i32) -> i64 {
    crate::syscall::set_linux_exit_debug_stage(0xE200);
    serial_println!(
        "[linux_compat] exit_group: agent={} status={}",
        agent_id,
        status
    );

    let leader_id = thread_group_leader(agent_id);
    let group_pid = thread_group_pid(agent_id);
    let parent_id = agent::get_agent(leader_id).and_then(|agent| agent.parent_id);

    let mut members: [Option<AgentId>; MAX_AGENTS] = [None; MAX_AGENTS];
    let mut member_count = 0usize;
    for id in 0..MAX_AGENTS as AgentId {
        if let Some(ls) = state::get_state(id) {
            if ls.active && ls.pid == group_pid {
                members[member_count] = Some(id);
                member_count += 1;
            }
        }
    }

    for member in members[..member_count].iter().copied().flatten() {
        if member == agent_id {
            continue;
        }
        sched::remove_from_run_queue(member);
        agent::terminate_agent_no_reparent(member, AgentStatus::Exited);
    }

    if let Some(pid) = parent_id {
        super::state::raise_signal(pid, 17);
        if let Some(parent) = agent::get_agent_mut(pid) {
            if parent.status == AgentStatus::BlockedRecv {
                parent.status = AgentStatus::Ready;
                sched::add_to_run_queue(pid);
            }
        }
    }

    sched::remove_from_run_queue(agent_id);
    agent::terminate_agent_no_reparent(agent_id, AgentStatus::Exited);

    crate::syscall::set_linux_exit_debug_stage(0xE230);
    sched::switch_without_current()
}

/// getpid(2) -- Return the agent's pid (= agent_id).
pub fn sys_getpid(agent_id: u16) -> i64 {
    state::get_state(agent_id)
        .map(|st| st.pid as i64)
        .unwrap_or(agent_id as i64)
}

/// gettid(2) -- Return the thread id (= agent_id, always unique).
pub fn sys_gettid(agent_id: u16) -> i64 {
    agent_id as i64
}

/// set_tid_address(2) -- Set pointer for clear_child_tid on exit.
///
/// Returns the caller's tid.
pub fn sys_set_tid_address(agent_id: u16, tidptr: u64) -> i64 {
    if let Some(ls) = state::get_state_mut(agent_id) {
        ls.clear_child_tid = tidptr;
    }
    agent_id as i64
}

/// set_robust_list(2) -- Store robust futex list head pointer.
///
/// The kernel records this for cleanup when the thread exits.
pub fn sys_set_robust_list(agent_id: u16, head: u64, len: u64) -> i64 {
    // Linux requires len == sizeof(struct robust_list_head) == 24
    if len != 24 {
        return -EINVAL;
    }
    if let Some(ls) = state::get_state_mut(agent_id) {
        ls.robust_list_head = head;
    }
    0
}

/// prctl(2) -- Process control operations.
///
/// Handles PR_SET_NAME and PR_GET_NAME; others return 0.
pub fn sys_prctl(agent_id: u16, option: u32, arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> i64 {
    match option {
        PR_SET_NAME => {
            // arg2 points to a 16-byte name buffer.
            if arg2 == 0 {
                return -EFAULT;
            }
            let idx = agent_id as usize;
            if idx >= MAX_LINUX_AGENTS {
                return -EINVAL;
            }
            unsafe {
                let src = arg2 as *const [u8; 16];
                AGENT_NAMES[idx] = core::ptr::read_volatile(src);
            }
            0
        }
        PR_GET_NAME => {
            // arg2 points to a 16-byte buffer to write the name into.
            if arg2 == 0 {
                return -EFAULT;
            }
            let idx = agent_id as usize;
            if idx >= MAX_LINUX_AGENTS {
                return -EINVAL;
            }
            unsafe {
                let dst = arg2 as *mut [u8; 16];
                core::ptr::write_volatile(dst, AGENT_NAMES[idx]);
            }
            0
        }
        _ => {
            // Unhandled prctl options succeed silently.
            0
        }
    }
}

/// sched_yield(2) -- Yield the processor.
pub fn sys_sched_yield(_agent_id: u16) -> i64 {
    sched::yield_current();
    0
}

/// sched_getaffinity(2) -- Get CPU affinity mask.
///
/// Writes a bitmask with CPU 0 set. ATOS is deterministic so affinity
/// is advisory only; we report a single CPU.
pub fn sys_sched_getaffinity(_agent_id: u16, _pid: u32, cpusetsize: u64, mask_ptr: u64) -> i64 {
    if mask_ptr == 0 {
        return -EFAULT;
    }
    if cpusetsize == 0 {
        return -EINVAL;
    }

    // Write a mask with CPU 0 set (bit 0 = 1), rest zeroed.
    unsafe {
        let dst = mask_ptr as *mut u8;
        // Zero the entire buffer first.
        let len = cpusetsize.min(128) as usize;
        for i in 0..len {
            core::ptr::write_volatile(dst.add(i), 0u8);
        }
        // Set bit 0 (CPU 0).
        core::ptr::write_volatile(dst, 1u8);
    }

    // Return the number of bytes written (minimum of cpusetsize and 8).
    cpusetsize.min(8) as i64
}

/// getrusage(2) -- Get resource usage.
///
/// Fills a minimal rusage struct: ru_utime derived from energy consumed,
/// ru_stime = 0. All other fields zeroed.
pub fn sys_getrusage(agent_id: u16, _who: i32, usage_ptr: u64) -> i64 {
    if usage_ptr == 0 {
        return -EFAULT;
    }

    // who: RUSAGE_SELF=0, RUSAGE_CHILDREN=-1, RUSAGE_THREAD=1
    // We report the same values regardless of who.

    // Get energy consumed to approximate user time.
    let energy_consumed = match agent::get_agent(agent_id) {
        Some(agent) => {
            // Energy consumed = initial - remaining. We don't store initial,
            // so just report remaining budget as a proxy.
            agent.energy_budget
        }
        None => 0,
    };

    // struct rusage is 144 bytes on x86_64. Zero it, then set ru_utime.
    unsafe {
        let dst = usage_ptr as *mut u8;
        for i in 0..144 {
            core::ptr::write_volatile(dst.add(i), 0u8);
        }

        // ru_utime is the first field: struct timeval { tv_sec: i64, tv_usec: i64 }
        // Convert energy ticks to microseconds (1 tick ~= 10ms = 10000 us).
        let usec = energy_consumed * 10_000;
        let tv_sec = usec / 1_000_000;
        let tv_usec = usec % 1_000_000;

        let sec_ptr = usage_ptr as *mut i64;
        core::ptr::write_volatile(sec_ptr, tv_sec as i64);
        core::ptr::write_volatile(sec_ptr.add(1), tv_usec as i64);
    }

    0
}

/// capget(2) -- Get Linux capabilities.
///
/// ATOS does not implement Linux capabilities. Write empty data.
pub fn sys_capget(_agent_id: u16, hdrp: u64, datap: u64) -> i64 {
    if hdrp == 0 {
        return -EFAULT;
    }

    // Fill header: version = _LINUX_CAPABILITY_VERSION_3, pid = 0.
    unsafe {
        let hdr = hdrp as *mut u32;
        // version field (offset 0): 0x20080522 = capability v3
        core::ptr::write_volatile(hdr, 0x2008_0522u32);
        // pid field (offset 4): 0
        core::ptr::write_volatile(hdr.add(1), 0u32);
    }

    if datap != 0 {
        // struct __user_cap_data_struct[2] = 2 * 12 bytes = 24 bytes, all zero.
        unsafe {
            let dst = datap as *mut u8;
            for i in 0..24 {
                core::ptr::write_volatile(dst.add(i), 0u8);
            }
        }
    }

    0
}

// ── Additional syscalls required by dispatch.rs ────────────────────────────

/// clone(2) -- Legacy clone syscall (pre-clone3).
///
/// Maps to the same logic as clone3 but with positional arguments.
/// flags=a1, child_stack=a2, parent_tid=a3, child_tid=a4, tls=a5.
pub fn sys_clone(
    agent_id: u16,
    flags: u64,
    child_stack: u64,
    parent_tid_ptr: u64,
    child_tid_ptr: u64,
    tls: u64,
) -> i64 {
    // Read parent agent to split energy and memory quota.
    let (parent_energy, parent_mem_quota) = match agent::get_agent(agent_id) {
        Some(parent) => (parent.energy_budget, parent.memory_quota),
        None => return -ESRCH,
    };

    let child_energy = parent_energy / 2;
    let child_mem_quota = parent_mem_quota / 2;

    // Deduct from parent.
    if let Some(parent) = agent::get_agent_mut(agent_id) {
        parent.energy_budget -= child_energy;
        parent.memory_quota -= child_mem_quota;
    }

    let frame = match snapshot_current_syscall_frame() {
        Some(frame) => frame,
        None => return -EINVAL,
    };
    let child_user_rsp = if child_stack != 0 {
        child_stack
    } else {
        frame.user_rsp
    };
    let child_kernel_stack_top = {
        let st = sched::allocate_agent_stack();
        if st == 0 {
            return -ENOMEM;
        }
        st
    };

    let child_parent = clone_child_parent(agent_id, flags);
    let child_id = match agent::create_agent(
        child_parent,
        enter_user_clone_return as *const () as u64,
        child_kernel_stack_top,
        child_energy,
        child_mem_quota,
    ) {
        Ok(id) => id,
        Err(e) => return e,
    };

    let clone_vm = flags & CLONE_VM != 0;
    let parent_cr3 = match agent::get_agent(agent_id) {
        Some(parent) => parent.context.cr3,
        None => return -ESRCH,
    };
    let child_cr3 = if clone_vm {
        let _ = crate::arch::x86_64::paging::retain_address_space(parent_cr3);
        parent_cr3
    } else if let Some(new_cr3) = crate::arch::x86_64::paging::create_linux_address_space() {
        new_cr3
    } else {
        agent::terminate_agent(child_id, AgentStatus::Faulted);
        return -ENOMEM;
    };

    if let Some(child) = agent::get_agent_mut(child_id) {
        child.mode = AgentMode::User;
        child.kernel_stack_top = child_kernel_stack_top;
        child.stack_bottom = sched::stack_bottom_from_top(child_kernel_stack_top);
        child.context =
            build_clone_child_context(&frame, child_kernel_stack_top, child_user_rsp, child_cr3);
        child.status = AgentStatus::Ready;
    } else {
        return -ESRCH;
    }

    state::init_state(child_id);
    inherit_linux_state_for_clone(agent_id, child_id, flags, tls, child_tid_ptr);

    if flags & CLONE_PARENT_SETTID != 0 && parent_tid_ptr != 0 {
        unsafe {
            core::ptr::write_volatile(parent_tid_ptr as *mut u32, child_id as u32);
        }
    }

    sched::add_to_run_queue(child_id);

    serial_println!(
        "[linux_compat] clone: parent={} child={} flags={:#x}",
        agent_id,
        child_id,
        flags
    );

    child_id as i64
}

/// fork(2) -- Create child process (full copy).
///
/// In ATOS, fork maps to clone with default flags.
pub fn sys_fork(agent_id: u16) -> i64 {
    sys_clone(agent_id, 0, 0, 0, 0, 0)
}

/// wait4(2) -- Wait for a child agent to terminate.
///
/// Supports pid > 0 (specific child) and pid == -1 (any child).
/// Blocks the parent until a child terminates unless WNOHANG is set.
pub fn sys_wait4(agent_id: u16, pid: u64, wstatus_ptr: u64, options: u64, rusage_ptr: u64) -> i64 {
    let pid_i32 = pid as i64 as i32;

    // Determine which child to wait for.
    let specific_pid = if pid_i32 > 0 {
        // Wait for specific child -- verify it's actually our child.
        if !agent::is_child_of_any_state(pid_i32 as u16, agent_id) {
            return -ECHILD;
        }
        pid_i32
    } else if pid_i32 == -1 || pid_i32 == 0 {
        // Wait for any child.
        if !agent::has_any_child(agent_id) {
            return -ECHILD;
        }
        -1
    } else {
        // pid < -1: wait for any child in process group |pid|.
        // We don't implement process groups; treat as any child.
        -1
    };

    // Check for an already-terminated child.
    if let Some((child_id, child_status)) = agent::find_terminated_child(agent_id, specific_pid) {
        // Compute the wait status word.
        let wstatus: u32 = match child_status {
            AgentStatus::Exited => {
                // Normal exit: status << 8 (W_EXITCODE macro).
                // Exit code is 0 since we don't store per-agent exit codes yet.
                0u32 << 8
            }
            AgentStatus::Faulted => {
                // Killed by signal: encode as SIGSEGV (11).
                11u32 // terminated by signal, signal number in low 7 bits
            }
            _ => 0,
        };

        // Write wstatus to user memory if pointer is non-null.
        if wstatus_ptr != 0 {
            unsafe {
                core::ptr::write_volatile(wstatus_ptr as *mut u32, wstatus);
            }
        }

        // Fill rusage if requested.
        if rusage_ptr != 0 {
            // Zero out the rusage struct (144 bytes on x86_64).
            unsafe {
                let dst = rusage_ptr as *mut u8;
                for i in 0..144 {
                    core::ptr::write_volatile(dst.add(i), 0u8);
                }
            }
        }

        // Reap the terminated child (remove from agent table).
        agent::reap_agent(child_id);

        serial_println!(
            "[linux_compat] wait4: parent={} reaped child={} status={:#x}",
            agent_id,
            child_id,
            wstatus
        );

        return child_id as i64;
    }

    // No terminated child found yet.
    if options & WNOHANG != 0 {
        // Non-blocking: return 0 (no child ready).
        return 0;
    }

    // Blocking wait: block the parent until a child exits.
    // The sys_exit handler will wake parents via futex_wake_parent().
    if let Some(agent) = agent::get_agent_mut(agent_id) {
        agent.status = AgentStatus::BlockedRecv;
    }
    sched::remove_from_run_queue(agent_id);
    sched::yield_current();

    // Resumed after being woken -- retry the check.
    if let Some((child_id, child_status)) = agent::find_terminated_child(agent_id, specific_pid) {
        let wstatus: u32 = match child_status {
            AgentStatus::Exited => 0u32 << 8,
            AgentStatus::Faulted => 11u32,
            _ => 0,
        };

        if wstatus_ptr != 0 {
            unsafe {
                core::ptr::write_volatile(wstatus_ptr as *mut u32, wstatus);
            }
        }

        if rusage_ptr != 0 {
            unsafe {
                let dst = rusage_ptr as *mut u8;
                for i in 0..144 {
                    core::ptr::write_volatile(dst.add(i), 0u8);
                }
            }
        }

        agent::reap_agent(child_id);

        serial_println!(
            "[linux_compat] wait4: parent={} reaped child={} (after block)",
            agent_id,
            child_id
        );

        return child_id as i64;
    }

    // Spurious wakeup or child not yet terminated -- return -ECHILD.
    -ECHILD
}

fn send_signal_to_agent(tid: i32, sig: i32) -> i64 {
    if tid <= 0 {
        return -ESRCH;
    }
    if !(0..=64).contains(&sig) {
        return -EINVAL;
    }

    let target_id = tid as AgentId;
    if agent::get_agent(target_id).is_none() {
        return -ESRCH;
    }

    if sig != 0 {
        state::raise_signal(target_id, sig as u32);
    }

    0
}

/// kill(2) -- Send a signal to a process.
pub fn sys_kill(_agent_id: u16, pid: i32, sig: i32) -> i64 {
    send_signal_to_agent(pid, sig)
}

/// tgkill(2) -- Send a signal to a specific thread.
///
/// ATOS currently models one Linux thread per agent, so `pid` and `tid`
/// both resolve to the target agent's Linux pid. The signal is queued and
/// will be delivered at the next syscall-return boundary.
pub fn sys_tgkill(_agent_id: u16, pid: i32, tid: i32, sig: i32) -> i64 {
    if pid <= 0 || tid <= 0 {
        return -ESRCH;
    }

    let target_id = tid as AgentId;
    let target_pid = state::get_state(target_id)
        .map(|st| st.pid as i32)
        .unwrap_or(target_id as i32);
    if target_pid != pid {
        return -ESRCH;
    }

    send_signal_to_agent(tid, sig)
}

/// getppid(2) -- Return the parent's pid.
pub fn sys_getppid(agent_id: u16) -> i64 {
    match agent::get_agent(agent_id) {
        Some(agent) => match agent.parent_id {
            Some(parent_id) => state::get_state(parent_id)
                .map(|st| st.pid as i64)
                .unwrap_or(parent_id as i64),
            None => 1, // init (root agent)
        },
        None => 1,
    }
}

/// uname(2) -- Get system identification.
///
/// Writes a struct utsname to the user buffer. Each field is 65 bytes.
pub fn sys_uname(_agent_id: u16, buf_ptr: u64) -> i64 {
    if buf_ptr == 0 {
        return -EFAULT;
    }

    // struct utsname has 6 fields of 65 bytes each = 390 bytes total.
    // sysname, nodename, release, version, machine, domainname.
    unsafe {
        let dst = buf_ptr as *mut u8;
        // Zero the whole struct first.
        for i in 0..(UTSNAME_LENGTH * 6) {
            core::ptr::write_volatile(dst.add(i), 0u8);
        }

        // sysname = "Linux" (for compatibility)
        let sysname = b"Linux";
        for (i, &b) in sysname.iter().enumerate() {
            core::ptr::write_volatile(dst.add(i), b);
        }

        // nodename = "atos"
        let nodename = b"atos";
        let off1 = UTSNAME_LENGTH;
        for (i, &b) in nodename.iter().enumerate() {
            core::ptr::write_volatile(dst.add(off1 + i), b);
        }

        // release = "6.1.0-atos"
        let release = b"6.1.0-atos";
        let off2 = UTSNAME_LENGTH * 2;
        for (i, &b) in release.iter().enumerate() {
            core::ptr::write_volatile(dst.add(off2 + i), b);
        }

        // version = "#1 SMP ATOS"
        let version = b"#1 SMP ATOS";
        let off3 = UTSNAME_LENGTH * 3;
        for (i, &b) in version.iter().enumerate() {
            core::ptr::write_volatile(dst.add(off3 + i), b);
        }

        // machine = "x86_64"
        let machine = b"x86_64";
        let off4 = UTSNAME_LENGTH * 4;
        for (i, &b) in machine.iter().enumerate() {
            core::ptr::write_volatile(dst.add(off4 + i), b);
        }

        // domainname = "(none)"
        let domain = b"(none)";
        let off5 = UTSNAME_LENGTH * 5;
        for (i, &b) in domain.iter().enumerate() {
            core::ptr::write_volatile(dst.add(off5 + i), b);
        }
    }

    0
}

/// get_robust_list(2) -- Get robust futex list head.
pub fn sys_get_robust_list(agent_id: u16, _pid: u64, head_ptr: u64, len_ptr: u64) -> i64 {
    if head_ptr == 0 || len_ptr == 0 {
        return -EFAULT;
    }

    let robust_head = match state::get_state(agent_id) {
        Some(ls) => ls.robust_list_head,
        None => 0,
    };

    unsafe {
        core::ptr::write_volatile(head_ptr as *mut u64, robust_head);
        core::ptr::write_volatile(len_ptr as *mut u64, 24); // sizeof(robust_list_head)
    }

    0
}

/// arch_prctl(2) -- Set architecture-specific thread state.
///
/// Handles ARCH_SET_FS (TLS base), ARCH_GET_FS, ARCH_SET_GS, ARCH_GET_GS.
pub fn sys_arch_prctl(agent_id: u16, code: i32, addr: u64) -> i64 {
    use crate::linux_compat::constants::{ARCH_GET_FS, ARCH_GET_GS, ARCH_SET_FS, ARCH_SET_GS};

    match code as u64 {
        ARCH_SET_FS => {
            if let Some(ls) = state::get_state_mut(agent_id) {
                ls.fs_base = addr;
            }
            0
        }
        ARCH_GET_FS => {
            if addr == 0 {
                return -EFAULT;
            }
            let fs_base = match state::get_state(agent_id) {
                Some(ls) => ls.fs_base,
                None => 0,
            };
            unsafe {
                core::ptr::write_volatile(addr as *mut u64, fs_base);
            }
            0
        }
        ARCH_SET_GS | ARCH_GET_GS => {
            // GS is not commonly used by user programs. Stub.
            0
        }
        _ => -EINVAL,
    }
}

/// futex(2) -- Fast userspace mutex with deterministic wait queue.
///
/// Implements FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAIT_BITSET, FUTEX_WAKE_BITSET,
/// and FUTEX_REQUEUE with a static wait queue keyed by futex address.
/// Determinism: WAKE always wakes waiters in ascending agent_id order,
/// and WAIT always blocks (no spin-waiting races).
pub fn sys_futex(
    agent_id: u16,
    uaddr: u64,
    op: u64,
    val: u64,
    timeout_or_val2: u64,
    uaddr2: u64,
    val3: u64,
) -> i64 {
    let cmd = (op as u32) & !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            if uaddr == 0 {
                return -EFAULT;
            }

            // For FUTEX_WAIT_BITSET, the bitmask is passed as val3 (6th arg).
            // A zero bitset is invalid per the Linux man page.
            let bitset = if cmd == FUTEX_WAIT_BITSET {
                let bs = val3 as u32;
                if bs == 0 {
                    return -EINVAL;
                }
                bs
            } else {
                FUTEX_BITSET_MATCH_ANY
            };

            // Step 1: Read the current value at the futex address.
            let current_val = unsafe { core::ptr::read_volatile(uaddr as *const u32) };

            // Step 2: Spurious wakeup check -- if value changed, return -EAGAIN.
            if current_val != val as u32 {
                return -EAGAIN;
            }

            // Step 2b: Parse timeout from user memory if provided.
            // FUTEX_WAIT uses a relative timeout.
            // FUTEX_WAIT_BITSET uses an absolute timeout.
            let deadline = if timeout_or_val2 != 0 {
                let ts_ptr = timeout_or_val2 as *const i64;
                let tv_sec = unsafe { core::ptr::read_volatile(ts_ptr) };
                let tv_nsec = unsafe { core::ptr::read_volatile(ts_ptr.add(1)) };
                if tv_sec < 0 || !(0..1_000_000_000).contains(&tv_nsec) {
                    return -EINVAL;
                }
                let timeout_ticks = (tv_sec as u64)
                    .saturating_mul(100)
                    .saturating_add((tv_nsec as u64) / 10_000_000);
                if timeout_ticks == 0 {
                    return -ETIMEDOUT;
                }

                let now = timer::get_ticks();
                Some(if cmd == FUTEX_WAIT_BITSET {
                    timeout_ticks
                } else {
                    now.saturating_add(timeout_ticks)
                })
            } else {
                None
            };

            if let Some(deadline_tick) = deadline {
                if timer::get_ticks() >= deadline_tick {
                    return -ETIMEDOUT;
                }
            }

            // Step 3: Add this agent to the futex wait queue.
            let added = unsafe {
                let mut slot_found = false;
                for i in 0..MAX_FUTEX_WAITERS {
                    if !FUTEX_WAITERS[i].active {
                        FUTEX_WAITERS[i] = FutexWaiter {
                            agent_id,
                            futex_addr: uaddr,
                            bitset,
                            deadline_tick: deadline.unwrap_or(0),
                            active: true,
                        };
                        slot_found = true;
                        break;
                    }
                }
                slot_found
            };

            if !added {
                // Wait queue full -- cannot block, return -EAGAIN.
                serial_println!("[linux_compat] futex: wait queue full, agent={}", agent_id);
                return -EAGAIN;
            }

            set_futex_wait_result(agent_id, FUTEX_WAIT_NONE);

            // Step 4: Block the agent (set status to BlockedRecv).
            if let Some(agent) = agent::get_agent_mut(agent_id) {
                agent.status = AgentStatus::BlockedRecv;
            }

            // Step 5: Remove from scheduler run queue.
            sched::remove_from_run_queue(agent_id);

            // Step 6: Yield to let another agent run.
            sched::yield_current();

            // Step 7: When we resume, either a wake or timeout path has set
            // the per-agent futex result.
            take_futex_wait_result(agent_id)
        }
        FUTEX_WAKE | FUTEX_WAKE_BITSET => {
            // Wake up to `val` waiters on this futex address, deterministically.
            if uaddr == 0 {
                return 0;
            }
            let max_wake = val as usize;
            if max_wake == 0 {
                return 0;
            }

            // For FUTEX_WAKE_BITSET, only wake waiters whose bitset overlaps.
            let bitset = if cmd == FUTEX_WAKE_BITSET {
                let bs = val3 as u32;
                if bs == 0 {
                    return -EINVAL;
                }
                bs
            } else {
                FUTEX_BITSET_MATCH_ANY
            };

            // Step 1: Collect matching waiters (address match + bitmask overlap).
            let mut matching: [u16; MAX_FUTEX_WAITERS] = [0; MAX_FUTEX_WAITERS];
            let mut matching_indices: [usize; MAX_FUTEX_WAITERS] = [0; MAX_FUTEX_WAITERS];
            let mut match_count: usize = 0;

            unsafe {
                for i in 0..MAX_FUTEX_WAITERS {
                    if !FUTEX_WAITERS[i].active {
                        continue;
                    }
                    if agent::get_agent(FUTEX_WAITERS[i].agent_id).is_none() {
                        FUTEX_WAITERS[i].active = false;
                        continue;
                    }
                    if FUTEX_WAITERS[i].futex_addr == uaddr
                        && (FUTEX_WAITERS[i].bitset & bitset) != 0
                    {
                        matching[match_count] = FUTEX_WAITERS[i].agent_id;
                        matching_indices[match_count] = i;
                        match_count += 1;
                    }
                }
            }

            if match_count == 0 {
                return 0;
            }

            // Step 2: Sort matching entries by agent_id (deterministic ordering).
            // Simple insertion sort -- small array.
            for i in 1..match_count {
                let key_id = matching[i];
                let key_idx = matching_indices[i];
                let mut j = i;
                while j > 0 && matching[j - 1] > key_id {
                    matching[j] = matching[j - 1];
                    matching_indices[j] = matching_indices[j - 1];
                    j -= 1;
                }
                matching[j] = key_id;
                matching_indices[j] = key_idx;
            }

            // Step 3: Wake up to max_wake waiters (lowest agent_id first).
            let wake_count = match_count.min(max_wake);
            for w in 0..wake_count {
                let wid = matching[w];
                let widx = matching_indices[w];

                // Mark waiter as inactive.
                unsafe {
                    FUTEX_WAITERS[widx].active = false;
                }
                set_futex_wait_result(wid, 0);

                // Set agent status back to Ready and add to run queue.
                if let Some(agent) = agent::get_agent_mut(wid) {
                    agent.status = AgentStatus::Ready;
                }
                sched::add_to_run_queue(wid);
            }

            // Step 4: Return number of waiters woken.
            wake_count as i64
        }
        FUTEX_REQUEUE => {
            // FUTEX_REQUEUE: wake `val` waiters on uaddr, then move up to
            // `val2` remaining waiters from uaddr to uaddr2.
            // val2 is passed via timeout_or_val2, uaddr2 via the 5th syscall arg.
            if uaddr == 0 {
                return -EFAULT;
            }
            let max_wake = val as usize;
            let max_requeue = timeout_or_val2 as usize;

            // Collect all waiters on uaddr, sorted by agent_id for determinism.
            let mut matching: [u16; MAX_FUTEX_WAITERS] = [0; MAX_FUTEX_WAITERS];
            let mut matching_indices: [usize; MAX_FUTEX_WAITERS] = [0; MAX_FUTEX_WAITERS];
            let mut match_count: usize = 0;

            unsafe {
                for i in 0..MAX_FUTEX_WAITERS {
                    if !FUTEX_WAITERS[i].active {
                        continue;
                    }
                    if agent::get_agent(FUTEX_WAITERS[i].agent_id).is_none() {
                        FUTEX_WAITERS[i].active = false;
                        continue;
                    }
                    if FUTEX_WAITERS[i].futex_addr == uaddr {
                        matching[match_count] = FUTEX_WAITERS[i].agent_id;
                        matching_indices[match_count] = i;
                        match_count += 1;
                    }
                }
            }

            if match_count == 0 {
                return 0;
            }

            // Sort by agent_id (deterministic).
            for i in 1..match_count {
                let key_id = matching[i];
                let key_idx = matching_indices[i];
                let mut j = i;
                while j > 0 && matching[j - 1] > key_id {
                    matching[j] = matching[j - 1];
                    matching_indices[j] = matching_indices[j - 1];
                    j -= 1;
                }
                matching[j] = key_id;
                matching_indices[j] = key_idx;
            }

            // Phase 1: Wake the first `max_wake` waiters.
            let wake_count = match_count.min(max_wake);
            for w in 0..wake_count {
                let wid = matching[w];
                let widx = matching_indices[w];
                unsafe {
                    FUTEX_WAITERS[widx].active = false;
                }
                set_futex_wait_result(wid, 0);
                if let Some(agent) = agent::get_agent_mut(wid) {
                    agent.status = AgentStatus::Ready;
                }
                sched::add_to_run_queue(wid);
            }

            // Phase 2: Move the next `max_requeue` waiters to uaddr2.
            let requeue_start = wake_count;
            let requeue_end = match_count.min(requeue_start + max_requeue);
            for r in requeue_start..requeue_end {
                let ridx = matching_indices[r];
                unsafe {
                    FUTEX_WAITERS[ridx].futex_addr = uaddr2;
                }
            }

            wake_count as i64
        }
        _ => {
            // Other futex ops not implemented. Return 0 to avoid crashing.
            0
        }
    }
}

/// prlimit64(2) -- Get/set resource limits.
///
/// Returns sensible defaults for RLIMIT_NOFILE and RLIMIT_STACK.
pub fn sys_prlimit64(
    _agent_id: u16,
    _pid: u64,
    resource: u64,
    _new_limit_ptr: u64,
    old_limit_ptr: u64,
) -> i64 {
    // struct rlimit { rlim_cur: u64, rlim_max: u64 } = 16 bytes
    if old_limit_ptr != 0 {
        let (cur, max) = match resource {
            RLIMIT_NOFILE => (MAX_FDS as u64, MAX_FDS as u64),
            RLIMIT_STACK => (USER_STACK_SIZE as u64, USER_STACK_SIZE as u64),
            _ => (u64::MAX, u64::MAX), // RLIM_INFINITY
        };
        unsafe {
            let dst = old_limit_ptr as *mut u64;
            core::ptr::write_volatile(dst, cur);
            core::ptr::write_volatile(dst.add(1), max);
        }
    }

    // Ignore new_limit_ptr (we don't actually enforce resource limits).
    0
}
