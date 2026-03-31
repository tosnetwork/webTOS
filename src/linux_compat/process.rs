//! Process-related Linux syscall implementations.
//!
//! Maps Linux process/thread primitives onto ATOS deterministic agents.
//! clone3 is the critical syscall: it creates a child agent that shares the
//! parent's keyspace and gets a deterministic, sequential agent_id.

use crate::agent::{self, AgentId, AgentStatus, USER_STACK_SIZE};
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
    active: bool,
}

const FUTEX_WAITER_EMPTY: FutexWaiter = FutexWaiter {
    agent_id: 0,
    futex_addr: 0,
    bitset: FUTEX_BITSET_MATCH_ANY,
    active: false,
};

static mut FUTEX_WAITERS: [FutexWaiter; MAX_FUTEX_WAITERS] =
    [FUTEX_WAITER_EMPTY; MAX_FUTEX_WAITERS];

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

// Clone flag bits we care about
#[allow(dead_code)]
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;

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

    // Determine child entry point and stack.
    // For clone3 the child returns to the same instruction as the parent
    // but with return value 0. The stack is specified in clone_args.
    let child_stack_top = if args.stack != 0 {
        args.stack + args.stack_size
    } else {
        // Allocate from scheduler pool if no stack specified.
        let st = sched::allocate_agent_stack();
        if st == 0 {
            return -ENOMEM;
        }
        st
    };

    // Use parent's current instruction pointer as child entry point.
    let child_entry = match agent::get_agent(agent_id) {
        Some(parent) => parent.context.rip,
        None => return -ESRCH,
    };

    // Create the child agent.
    let child_id = match agent::create_agent(
        Some(agent_id),
        child_entry,
        child_stack_top,
        child_energy,
        child_mem_quota,
    ) {
        Ok(id) => id,
        Err(e) => return e,
    };

    // Set up child context: copy parent registers, override rax=0 (return value).
    let clone_vm = args.flags & CLONE_VM != 0;

    if let Some(parent) = agent::get_agent(agent_id) {
        let parent_ctx = parent.context;
        let parent_mode = parent.mode;
        if let Some(child) = agent::get_agent_mut(child_id) {
            child.context = parent_ctx;
            child.context.rax = 0; // clone returns 0 to child
            child.context.rsp = child_stack_top;

            if clone_vm {
                // CLONE_VM: child shares parent's address space (same cr3).
                // cr3 is already correct from the parent context copy.
                // The child gets its own kernel stack but shares user memory.
            } else {
                // No CLONE_VM: create an independent address space for the child.
                if let Some(new_cr3) = crate::arch::x86_64::paging::create_address_space() {
                    child.context.cr3 = new_cr3;
                } else {
                    // Failed to allocate address space -- terminate child and return error.
                    agent::terminate_agent(child_id, AgentStatus::Faulted);
                    return -ENOMEM;
                }
            }

            // Allocate a dedicated kernel stack for the child so it does not
            // share the parent's kernel stack during syscalls.
            let k_stack = sched::allocate_agent_stack();
            if k_stack != 0 {
                child.kernel_stack_top = k_stack;
            }

            // Inherit parent's execution mode (User or Kernel).
            child.mode = parent_mode;

            // If CLONE_SETTLS, set the child's FS base for TLS.
            if args.flags & CLONE_SETTLS != 0 {
                // This would be applied via wrmsr on context switch;
                // store in the context for now.
                child.context.r8 = args.tls; // stash TLS; arch layer applies it
            }

            child.status = AgentStatus::Ready;
        }
    }

    // Initialize Linux compat state for the child.
    state::init_state(child_id);

    // Copy parent's fd table to child.
    if let Some(parent_state) = state::get_state(agent_id) {
        // Snapshot fd_table before borrowing child state.
        let fd_snapshot = parent_state.fd_table;
        let fs_base = parent_state.fs_base;

        if let Some(child_state) = state::get_state_mut(child_id) {
            child_state.fd_table = fd_snapshot;

            // Copy TLS FS base from parent (or from clone_args.tls).
            if args.flags & CLONE_SETTLS != 0 {
                child_state.fs_base = args.tls;
            } else {
                child_state.fs_base = fs_base;
            }

            // Handle CLONE_CHILD_SETTID: write child tid to child_tid address.
            if args.flags & CLONE_CHILD_SETTID != 0 && args.child_tid != 0 {
                unsafe {
                    let ptr = args.child_tid as *mut u32;
                    core::ptr::write_volatile(ptr, child_id as u32);
                }
            }

            // Handle CLONE_CHILD_CLEARTID: store address for clear on exit.
            if args.flags & CLONE_CHILD_CLEARTID != 0 {
                child_state.clear_child_tid = args.child_tid;
            }
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

/// execve(2) -- Replace current agent image.
///
/// Not commonly needed after initial load. Returns -ENOSYS for now.
pub fn sys_execve(_agent_id: u16, _pathname_ptr: u64, _argv_ptr: u64, _envp_ptr: u64) -> i64 {
    // Most programs don't execve after initial load in ATOS.
    // A full implementation would call crate::agent_loader::spawn_from_image().
    let _execve_limits = (
        EXECVE_ARG_MAX,
        EXECVE_ARG_LEN_MAX,
        EXECVE_ENV_MAX,
        EXECVE_ENV_LEN_MAX,
    );
    -ENOSYS
}

/// exit(2) -- Terminate the calling agent.
pub fn sys_exit(agent_id: u16, status: i32) -> i64 {
    crate::syscall::set_linux_exit_debug_stage(0xE210);
    serial_println!("[linux_compat] exit: agent={} status={}", agent_id, status);

    // Clear child_tid if set (CLONE_CHILD_CLEARTID behavior).
    // The futex_wake on this address is done below after termination.
    if let Some(ls) = state::get_state(agent_id) {
        if ls.clear_child_tid != 0 {
            unsafe {
                let ptr = ls.clear_child_tid as *mut u32;
                core::ptr::write_volatile(ptr, 0);
            }
        }
    }

    // Deactivate the Linux compat state.
    if let Some(ls) = state::get_state_mut(agent_id) {
        ls.active = false;
    }

    // Read parent_id before termination (terminate sets active=false).
    let parent_id = match agent::get_agent(agent_id) {
        Some(agent) => agent.parent_id,
        None => None,
    };

    // Remove from scheduler and terminate.
    sched::remove_from_run_queue(agent_id);
    agent::terminate_agent(agent_id, AgentStatus::Exited);

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

    // Also do futex_wake on the clear_child_tid address (CLONE_CHILD_CLEARTID).
    if let Some(ls) = state::get_state(agent_id) {
        if ls.clear_child_tid != 0 {
            // Wake one waiter on this address (matching Linux behavior).
            sys_futex(agent_id, ls.clear_child_tid, FUTEX_WAKE as u64, 1, 0, 0, 0);
        }
    }

    // This syscall never returns; the scheduler will pick the next agent.
    crate::syscall::set_linux_exit_debug_stage(0xE230);
    sched::yield_current();
    0 // unreachable in practice
}

/// exit_group(2) -- Terminate all threads in the thread group.
///
/// In ATOS, a "thread group" is the parent agent and all its children.
/// For simplicity, we just exit the calling agent (same as exit).
pub fn sys_exit_group(agent_id: u16, status: i32) -> i64 {
    crate::syscall::set_linux_exit_debug_stage(0xE200);
    serial_println!(
        "[linux_compat] exit_group: agent={} status={}",
        agent_id,
        status
    );
    sys_exit(agent_id, status)
}

/// getpid(2) -- Return the agent's pid (= agent_id).
pub fn sys_getpid(agent_id: u16) -> i64 {
    // In ATOS, pid maps directly to agent_id.
    // For threads created via clone3, return the parent's id as the "pid"
    // (thread group leader), matching Linux semantics.
    match agent::get_agent(agent_id) {
        Some(agent) => match agent.parent_id {
            // If this agent was cloned, its "pid" is the parent (tgid).
            // However, if parent is None, this is the group leader itself.
            Some(parent_id) => parent_id as i64,
            None => agent_id as i64,
        },
        None => agent_id as i64,
    }
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

    let child_stack_top = if child_stack != 0 {
        child_stack
    } else {
        let st = sched::allocate_agent_stack();
        if st == 0 {
            return -ENOMEM;
        }
        st
    };

    let child_entry = match agent::get_agent(agent_id) {
        Some(parent) => parent.context.rip,
        None => return -ESRCH,
    };

    let child_id = match agent::create_agent(
        Some(agent_id),
        child_entry,
        child_stack_top,
        child_energy,
        child_mem_quota,
    ) {
        Ok(id) => id,
        Err(e) => return e,
    };

    // Copy parent context, child returns 0.
    let clone_vm = flags & CLONE_VM != 0;

    if let Some(parent) = agent::get_agent(agent_id) {
        let parent_ctx = parent.context;
        let parent_mode = parent.mode;
        if let Some(child) = agent::get_agent_mut(child_id) {
            child.context = parent_ctx;
            child.context.rax = 0;
            child.context.rsp = child_stack_top;

            if clone_vm {
                // CLONE_VM: shared address space -- cr3 already copied from parent.
            } else {
                // Separate address space for the child.
                if let Some(new_cr3) = crate::arch::x86_64::paging::create_address_space() {
                    child.context.cr3 = new_cr3;
                } else {
                    agent::terminate_agent(child_id, AgentStatus::Faulted);
                    return -ENOMEM;
                }
            }

            // Dedicated kernel stack for the child.
            let k_stack = sched::allocate_agent_stack();
            if k_stack != 0 {
                child.kernel_stack_top = k_stack;
            }

            child.mode = parent_mode;

            if flags & CLONE_SETTLS != 0 {
                child.context.r8 = tls;
            }
            child.status = AgentStatus::Ready;
        }
    }

    state::init_state(child_id);

    if let Some(parent_state) = state::get_state(agent_id) {
        let fd_snapshot = parent_state.fd_table;
        let fs_base = parent_state.fs_base;
        if let Some(child_state) = state::get_state_mut(child_id) {
            child_state.fd_table = fd_snapshot;
            child_state.fs_base = if flags & CLONE_SETTLS != 0 {
                tls
            } else {
                fs_base
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

/// kill(2) -- Send a signal to a process.
///
/// In ATOS, signals are not delivered between agents. This is a no-op
/// except for sig=0 (existence check).
pub fn sys_kill(_agent_id: u16, pid: i32, sig: i32) -> i64 {
    if sig == 0 {
        // sig=0: check if process exists.
        match agent::get_agent(pid as AgentId) {
            Some(_) => 0,
            None => -ESRCH,
        }
    } else {
        // Signal delivery is not implemented. Return success to avoid
        // crashing programs that send signals during normal operation.
        0
    }
}

/// getppid(2) -- Return the parent's pid.
pub fn sys_getppid(agent_id: u16) -> i64 {
    match agent::get_agent(agent_id) {
        Some(agent) => match agent.parent_id {
            Some(parent_id) => parent_id as i64,
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
    let cmd = (op as u32) & !(FUTEX_PRIVATE_FLAG);

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
            // timeout_or_val2 is a pointer to struct timespec { tv_sec: i64, tv_nsec: i64 }.
            // Convert to ATOS ticks at 100Hz: ticks = tv_sec * 100 + tv_nsec / 10_000_000.
            let timeout_ticks: u64 = if timeout_or_val2 != 0 {
                let ts_ptr = timeout_or_val2 as *const i64;
                let tv_sec = unsafe { core::ptr::read_volatile(ts_ptr) } as u64;
                let tv_nsec = unsafe { core::ptr::read_volatile(ts_ptr.add(1)) } as u64;
                let ticks = tv_sec * 100 + tv_nsec / 10_000_000;
                if ticks == 0 {
                    // Immediate timeout: value matches but caller wants non-blocking check.
                    return -ETIMEDOUT;
                }
                ticks
            } else {
                0 // No timeout -- block indefinitely.
            };

            // Step 3: Add this agent to the futex wait queue.
            let added = unsafe {
                let mut slot_found = false;
                for i in 0..MAX_FUTEX_WAITERS {
                    if !FUTEX_WAITERS[i].active {
                        FUTEX_WAITERS[i] = FutexWaiter {
                            agent_id,
                            futex_addr: uaddr,
                            bitset,
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

            if timeout_ticks > 0 {
                // Timed wait: yield up to timeout_ticks times, checking
                // whether we have been woken (removed from FUTEX_WAITERS)
                // each iteration. Keep the waiter runnable so the timeout loop
                // can make forward progress deterministically.
                for _ in 0..timeout_ticks {
                    sched::yield_current();

                    // Check if we were woken (our entry cleared by FUTEX_WAKE).
                    let still_waiting = unsafe {
                        let mut found = false;
                        for i in 0..MAX_FUTEX_WAITERS {
                            if FUTEX_WAITERS[i].active
                                && FUTEX_WAITERS[i].agent_id == agent_id
                                && FUTEX_WAITERS[i].futex_addr == uaddr
                            {
                                found = true;
                                break;
                            }
                        }
                        found
                    };

                    if !still_waiting {
                        // Woken normally by FUTEX_WAKE.
                        return 0;
                    }

                    // Check if the futex value changed (spurious/value-change wakeup).
                    let cur = unsafe { core::ptr::read_volatile(uaddr as *const u32) };
                    if cur != val as u32 {
                        // Value changed; remove ourselves from waiters and return.
                        unsafe {
                            for i in 0..MAX_FUTEX_WAITERS {
                                if FUTEX_WAITERS[i].active
                                    && FUTEX_WAITERS[i].agent_id == agent_id
                                    && FUTEX_WAITERS[i].futex_addr == uaddr
                                {
                                    FUTEX_WAITERS[i].active = false;
                                    break;
                                }
                            }
                        }
                        return 0;
                    }
                }

                // Timeout expired -- remove ourselves from the wait queue.
                unsafe {
                    for i in 0..MAX_FUTEX_WAITERS {
                        if FUTEX_WAITERS[i].active
                            && FUTEX_WAITERS[i].agent_id == agent_id
                            && FUTEX_WAITERS[i].futex_addr == uaddr
                        {
                            FUTEX_WAITERS[i].active = false;
                            break;
                        }
                    }
                }
                // Re-add to run queue so the agent continues.
                if let Some(agent) = agent::get_agent_mut(agent_id) {
                    agent.status = AgentStatus::Ready;
                }
                sched::add_to_run_queue(agent_id);
                return -ETIMEDOUT;
            }

            // Untimed wait: block indefinitely until woken by FUTEX_WAKE.

            // Step 4: Block the agent (set status to BlockedRecv).
            if let Some(agent) = agent::get_agent_mut(agent_id) {
                agent.status = AgentStatus::BlockedRecv;
            }

            // Step 5: Remove from scheduler run queue.
            sched::remove_from_run_queue(agent_id);

            // Step 6: Yield to let another agent run.
            sched::yield_current();

            // Step 7: When we resume, we've been woken -- return 0.
            0
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
                    if FUTEX_WAITERS[i].active
                        && FUTEX_WAITERS[i].futex_addr == uaddr
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
                    if FUTEX_WAITERS[i].active && FUTEX_WAITERS[i].futex_addr == uaddr {
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
