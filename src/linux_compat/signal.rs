//! Signal-related Linux syscall implementations.
//!
//! In ATOS, signals are rarely delivered (no real SIGCHLD, SIGPIPE, etc.),
//! so this is mostly bookkeeping to satisfy programs that call rt_sigaction
//! and rt_sigprocmask during initialization.

use crate::linux_compat::constants::*;
use crate::linux_compat::state::MAX_LINUX_AGENTS;
use crate::serial_println;

// ── Signal constants ───────────────────────────────────────────────────────

/// Maximum number of signals (Linux uses 64 for standard + real-time).
const MAX_SIGNALS: usize = 64;

/// sigset_t size in bytes (64 signals / 8 bits per byte = 8 bytes).
const SIGSET_BYTES: usize = 8;

// Signal mask manipulation modes (rt_sigprocmask `how` parameter).
const SIG_BLOCK: i32 = 0;
const SIG_UNBLOCK: i32 = 1;
const SIG_SETMASK: i32 = 2;

// ── Signal handler representation ──────────────────────────────────────────

/// Signal action entry, mirroring the relevant parts of struct sigaction.
#[derive(Clone, Copy)]
struct SigActionEntry {
    /// Handler address: 0 = SIG_DFL, 1 = SIG_IGN, other = handler fn ptr.
    handler: u64,
    /// Signal flags (SA_RESTART, SA_SIGINFO, etc.).
    flags: u64,
    /// Restorer function address (SA_RESTORER).
    restorer: u64,
    /// Blocked signal mask during handler execution.
    mask: u64,
}

impl SigActionEntry {
    const fn default() -> Self {
        SigActionEntry {
            handler: 0, // SIG_DFL
            flags: 0,
            restorer: 0,
            mask: 0,
        }
    }
}

// ── Per-agent signal state ─────────────────────────────────────────────────

/// Complete signal state for one agent.
struct SignalState {
    /// Registered signal actions (indexed by signal number - 1).
    actions: [SigActionEntry; MAX_SIGNALS],
    /// Current signal mask (blocked signals).
    blocked_mask: u64,
    /// Whether this state slot is in use.
    active: bool,
}

impl SignalState {
    const fn empty() -> Self {
        SignalState {
            actions: [SigActionEntry::default(); MAX_SIGNALS],
            blocked_mask: 0,
            active: false,
        }
    }
}

/// Global signal state table, indexed by agent_id.
/// Safety: single-core kernel, interrupts disabled during syscall handling.
static mut SIGNAL_STATES: [SignalState; MAX_LINUX_AGENTS] =
    [const { SignalState::empty() }; MAX_LINUX_AGENTS];

// ── Public helpers ─────────────────────────────────────────────────────────

/// Initialize signal state for a newly created agent.
/// Called from process::sys_clone3 or state::init_state.
pub fn init_signal_state(agent_id: u16) {
    let idx = agent_id as usize;
    if idx >= MAX_LINUX_AGENTS {
        return;
    }
    unsafe {
        SIGNAL_STATES[idx] = SignalState::empty();
        SIGNAL_STATES[idx].active = true;
    }
}

// ── Linux struct sigaction layout (x86_64) ─────────────────────────────────
//
// struct sigaction {
//     __sighandler_t sa_handler;     // offset  0, 8 bytes
//     unsigned long  sa_flags;       // offset  8, 8 bytes
//     __sigrestore_t sa_restorer;    // offset 16, 8 bytes
//     sigset_t       sa_mask;        // offset 24, 8 bytes (for 64 signals)
// };
// Total: 32 bytes (assuming 64-signal sigset_t).

#[allow(dead_code)]
const SIGACTION_SIZE: usize = 32;

// ── Syscall implementations ────────────────────────────────────────────────

/// rt_sigaction(2) -- Examine and change a signal action.
///
/// For ATOS: signals are rarely delivered, so this is mostly bookkeeping.
/// Programs call this during init to register handlers for SIGCHLD, SIGPIPE, etc.
pub fn sys_rt_sigaction(
    agent_id: u16,
    signum_raw: u64,
    act_ptr: u64,
    oldact_ptr: u64,
    sigsetsize: u64,
) -> i64 {
    let signum = signum_raw as i32;
    // Validate signal number (1..=64, SIGKILL=9 and SIGSTOP=19 cannot be caught).
    if signum < 1 || signum > MAX_SIGNALS as i32 {
        return -EINVAL;
    }
    if signum == 9 || signum == 19 {
        // Cannot change SIGKILL or SIGSTOP handlers.
        if act_ptr != 0 {
            return -EINVAL;
        }
    }
    if sigsetsize != SIGSET_BYTES as u64 {
        return -EINVAL;
    }

    let idx = agent_id as usize;
    if idx >= MAX_LINUX_AGENTS {
        return -EINVAL;
    }
    let sig_idx = (signum - 1) as usize;

    unsafe {
        let state = &mut SIGNAL_STATES[idx];
        if !state.active {
            // Auto-initialize if not yet active.
            *state = SignalState::empty();
            state.active = true;
        }

        // If oldact_ptr is set, write the current action there.
        if oldact_ptr != 0 {
            let old = &state.actions[sig_idx];
            let dst = oldact_ptr as *mut u8;
            let handler_bytes = old.handler.to_ne_bytes();
            let flags_bytes = old.flags.to_ne_bytes();
            let restorer_bytes = old.restorer.to_ne_bytes();
            let mask_bytes = old.mask.to_ne_bytes();

            core::ptr::copy_nonoverlapping(handler_bytes.as_ptr(), dst, 8);
            core::ptr::copy_nonoverlapping(flags_bytes.as_ptr(), dst.add(8), 8);
            core::ptr::copy_nonoverlapping(restorer_bytes.as_ptr(), dst.add(16), 8);
            core::ptr::copy_nonoverlapping(mask_bytes.as_ptr(), dst.add(24), 8);
        }

        // If act_ptr is set, install the new action.
        if act_ptr != 0 {
            let src = act_ptr as *const u8;

            let mut handler_bytes = [0u8; 8];
            let mut flags_bytes = [0u8; 8];
            let mut restorer_bytes = [0u8; 8];
            let mut mask_bytes = [0u8; 8];

            core::ptr::copy_nonoverlapping(src, handler_bytes.as_mut_ptr(), 8);
            core::ptr::copy_nonoverlapping(src.add(8), flags_bytes.as_mut_ptr(), 8);
            core::ptr::copy_nonoverlapping(src.add(16), restorer_bytes.as_mut_ptr(), 8);
            core::ptr::copy_nonoverlapping(src.add(24), mask_bytes.as_mut_ptr(), 8);

            state.actions[sig_idx] = SigActionEntry {
                handler: u64::from_ne_bytes(handler_bytes),
                flags: u64::from_ne_bytes(flags_bytes),
                restorer: u64::from_ne_bytes(restorer_bytes),
                mask: u64::from_ne_bytes(mask_bytes),
            };

            serial_println!(
                "[linux_compat] rt_sigaction: agent={} sig={} handler={:#x}",
                agent_id,
                signum,
                state.actions[sig_idx].handler
            );
        }
    }

    0
}

/// rt_sigprocmask(2) -- Examine and change blocked signals.
///
/// how: SIG_BLOCK(0), SIG_UNBLOCK(1), SIG_SETMASK(2).
pub fn sys_rt_sigprocmask(
    agent_id: u16,
    how_raw: u64,
    set_ptr: u64,
    oldset_ptr: u64,
    sigsetsize: u64,
) -> i64 {
    let how = how_raw as i32;
    if sigsetsize != SIGSET_BYTES as u64 {
        return -EINVAL;
    }

    let idx = agent_id as usize;
    if idx >= MAX_LINUX_AGENTS {
        return -EINVAL;
    }

    unsafe {
        let state = &mut SIGNAL_STATES[idx];
        if !state.active {
            *state = SignalState::empty();
            state.active = true;
        }

        // Write current mask to oldset if requested.
        if oldset_ptr != 0 {
            let dst = oldset_ptr as *mut u64;
            core::ptr::write_volatile(dst, state.blocked_mask);
        }

        // Apply new mask if set_ptr is provided.
        if set_ptr != 0 {
            let new_set = core::ptr::read_volatile(set_ptr as *const u64);

            match how {
                SIG_BLOCK => {
                    state.blocked_mask |= new_set;
                }
                SIG_UNBLOCK => {
                    state.blocked_mask &= !new_set;
                }
                SIG_SETMASK => {
                    state.blocked_mask = new_set;
                }
                _ => return -EINVAL,
            }

            // SIGKILL (bit 8) and SIGSTOP (bit 18) can never be blocked.
            state.blocked_mask &= !((1u64 << 8) | (1u64 << 18));
        }
    }

    0
}

/// rt_sigreturn(2) -- Return from signal handler.
///
/// Restores the register state from the signal frame on the stack.
/// In ATOS, signals are rarely delivered, so this is mostly a no-op.
/// A full implementation would pop the saved context from the user stack.
pub fn sys_rt_sigreturn(agent_id: u16) -> i64 {
    serial_println!(
        "[linux_compat] rt_sigreturn: agent={} (no-op in ATOS)",
        agent_id
    );

    // In a full implementation, we would:
    // 1. Read the signal frame from the agent's stack (pointed to by rsp)
    // 2. Restore all saved registers (rax, rbx, ..., rip, rflags)
    // 3. Restore the signal mask from the frame
    // 4. Resume execution at the saved rip
    //
    // Since ATOS does not deliver signals, this should not be called.
    // Return 0 to avoid crashing the calling program.
    0
}
