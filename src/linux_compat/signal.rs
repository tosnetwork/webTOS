//! Signal-related Linux syscall implementations.
//!
//! In TOS, signals are rarely delivered (no real SIGCHLD, SIGPIPE, etc.),
//! so this is mostly bookkeeping to satisfy programs that call rt_sigaction
//! and rt_sigprocmask during initialization.

use crate::linux_compat::constants::*;
use crate::linux_compat::identity;
use crate::linux_compat::state::{self, MAX_LINUX_AGENTS};
use crate::linux_compat::process;
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
const SA_SIGINFO: u64 = 0x0000_0004;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SA_RESETHAND: u64 = 0x8000_0000;

const SIGNAL_FRAME_MAGIC: u64 = 0x4154_4f53_5349_4746;
const SIGALTSTACK_SIZE: usize = 24;
const SIGINFO_SIZE: usize = 128;
const UCONTEXT_SIZE: usize = 968;
const SS_ONSTACK: u32 = 1;
const SS_DISABLE: u32 = 2;
const SS_AUTODISARM: u32 = 1 << 31;
const MINSIGSTKSZ: u64 = 2048;

const UCONTEXT_UC_SIGMASK_OFFSET: usize = 296;
const UCONTEXT_MCONTEXT_GREGS_OFFSET: usize = 40;
const GREG_SLOT_SIZE: usize = 8;
const GREG_R8: usize = 0;
const GREG_R9: usize = 1;
const GREG_R10: usize = 2;
const GREG_R11: usize = 3;
const GREG_R12: usize = 4;
const GREG_R13: usize = 5;
const GREG_R14: usize = 6;
const GREG_R15: usize = 7;
const GREG_RDI: usize = 8;
const GREG_RSI: usize = 9;
const GREG_RBP: usize = 10;
const GREG_RBX: usize = 11;
const GREG_RDX: usize = 12;
const GREG_RAX: usize = 13;
const GREG_RCX: usize = 14;
const GREG_RSP: usize = 15;
const GREG_RIP: usize = 16;
const GREG_EFL: usize = 17;

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

#[repr(C)]
#[derive(Clone, Copy)]
struct UserSignalFrame {
    magic: u64,
    saved_blocked_mask: u64,
    saved_rax: i64,
    _pad: i64,
    saved: process::SyscallSavedFrame,
    siginfo: [u8; SIGINFO_SIZE],
    ucontext: [u8; UCONTEXT_SIZE],
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
    /// Owning Linux agent ID for this slot.
    agent_id: u16,
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
            agent_id: 0,
            actions: [SigActionEntry::default(); MAX_SIGNALS],
            blocked_mask: 0,
            active: false,
        }
    }
}

/// Global signal state table, indexed by active Linux-agent slots rather than
/// raw agent IDs. Agent IDs are monotonically increasing and can exceed the
/// fixed slot count, so callers must never use `agent_id as usize` here.
/// Safety: single-core kernel, interrupts disabled during syscall handling.
static mut SIGNAL_STATES: [SignalState; MAX_LINUX_AGENTS] =
    [const { SignalState::empty() }; MAX_LINUX_AGENTS];

#[inline]
fn signal_state_idx(agent_id: u16) -> Option<usize> {
    unsafe {
        for (idx, state) in SIGNAL_STATES.iter().enumerate() {
            if state.active && state.agent_id == agent_id {
                return Some(idx);
            }
        }
    }
    None
}

#[inline]
fn find_free_signal_state_idx() -> Option<usize> {
    unsafe {
        for (idx, state) in SIGNAL_STATES.iter().enumerate() {
            if !state.active {
                return Some(idx);
            }
        }
    }
    None
}

#[inline]
fn ensure_signal_state_idx(agent_id: u16) -> Option<usize> {
    if let Some(idx) = signal_state_idx(agent_id) {
        return Some(idx);
    }
    let idx = find_free_signal_state_idx()?;
    unsafe {
        SIGNAL_STATES[idx] = SignalState::empty();
        SIGNAL_STATES[idx].agent_id = agent_id;
        SIGNAL_STATES[idx].active = true;
    }
    Some(idx)
}

#[inline]
fn sighand_owner(agent_id: u16) -> usize {
    state::sighand_owner(agent_id) as usize
}

#[inline]
fn thread_group_leader(agent_id: u16) -> u16 {
    state::get_state(agent_id)
        .map(|st| st.thread_group_leader)
        .unwrap_or(agent_id)
}

#[inline]
fn blocked_mask(agent_id: u16) -> u64 {
    let Some(idx) = signal_state_idx(agent_id) else {
        return 0;
    };
    unsafe {
        let state = &SIGNAL_STATES[idx];
        if state.active { state.blocked_mask } else { 0 }
    }
}

fn agent_cr3(agent_id: u16) -> Option<u64> {
    crate::agent::get_agent(agent_id)
        .map(|agent| agent.context.cr3)
        .filter(|cr3| *cr3 != 0)
}

fn ensure_user_range_mapped(agent_id: u16, user_addr: u64, len: usize, write: bool) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if len == 0 {
        return true;
    }

    let start = user_addr & !(crate::arch::x86_64::paging::PAGE_SIZE as u64 - 1);
    let end_addr = user_addr.saturating_add(len.saturating_sub(1) as u64);
    let end = end_addr & !(crate::arch::x86_64::paging::PAGE_SIZE as u64 - 1);
    let mut page = start;
    let fault_code = if write { 0x2 } else { 0x0 };

    loop {
        if crate::arch::x86_64::page_table::translate_user_vaddr(cr3, page).is_none()
            && !crate::linux_compat::memory::handle_user_page_fault(agent_id, page, fault_code)
        {
            return false;
        }
        if page == end {
            break;
        }
        page = page.saturating_add(crate::arch::x86_64::paging::PAGE_SIZE as u64);
    }

    true
}

fn copy_from_user(agent_id: u16, user_addr: u64, dst: &mut [u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if !ensure_user_range_mapped(agent_id, user_addr, dst.len(), false) {
        return false;
    }
    crate::arch::x86_64::page_table::copy_from_user(cr3, user_addr, dst)
}

fn copy_to_user(agent_id: u16, user_addr: u64, src: &[u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if !ensure_user_range_mapped(agent_id, user_addr, src.len(), true) {
        return false;
    }
    crate::arch::x86_64::page_table::copy_to_user(cr3, user_addr, src)
}

#[inline]
fn push_u64(dst: &mut [u8], off: &mut usize, value: u64) {
    dst[*off..*off + 8].copy_from_slice(&value.to_ne_bytes());
    *off += 8;
}

#[inline]
fn push_i64(dst: &mut [u8], off: &mut usize, value: i64) {
    dst[*off..*off + 8].copy_from_slice(&value.to_ne_bytes());
    *off += 8;
}

#[inline]
fn pop_u64(src: &[u8], off: &mut usize) -> u64 {
    let value = u64::from_ne_bytes(src[*off..*off + 8].try_into().unwrap());
    *off += 8;
    value
}

#[inline]
fn pop_i64(src: &[u8], off: &mut usize) -> i64 {
    let value = i64::from_ne_bytes(src[*off..*off + 8].try_into().unwrap());
    *off += 8;
    value
}

fn serialize_syscall_saved_frame(frame: &process::SyscallSavedFrame, dst: &mut [u8]) {
    let mut off = 0usize;
    dst[off..off + frame.fpu_state.len()].copy_from_slice(&frame.fpu_state);
    off += frame.fpu_state.len();
    push_u64(dst, &mut off, frame.r15);
    push_u64(dst, &mut off, frame.r14);
    push_u64(dst, &mut off, frame.r13);
    push_u64(dst, &mut off, frame.r12);
    push_u64(dst, &mut off, frame.rbp);
    push_u64(dst, &mut off, frame.rbx);
    push_u64(dst, &mut off, frame.r10);
    push_u64(dst, &mut off, frame.r9);
    push_u64(dst, &mut off, frame.r8);
    push_u64(dst, &mut off, frame.rdx);
    push_u64(dst, &mut off, frame.rsi);
    push_u64(dst, &mut off, frame.rdi);
    push_u64(dst, &mut off, frame.user_rflags);
    push_u64(dst, &mut off, frame.user_rip);
    push_u64(dst, &mut off, frame.user_rsp);
    push_u64(dst, &mut off, frame.kernel_stack_top);
}

fn deserialize_syscall_saved_frame(src: &[u8]) -> process::SyscallSavedFrame {
    let mut off = 0usize;
    let mut fpu_state = [0u8; 512];
    let fpu_len = fpu_state.len();
    fpu_state.copy_from_slice(&src[off..off + fpu_len]);
    off += fpu_len;
    process::SyscallSavedFrame {
        fpu_state,
        r15: pop_u64(src, &mut off),
        r14: pop_u64(src, &mut off),
        r13: pop_u64(src, &mut off),
        r12: pop_u64(src, &mut off),
        rbp: pop_u64(src, &mut off),
        rbx: pop_u64(src, &mut off),
        r10: pop_u64(src, &mut off),
        r9: pop_u64(src, &mut off),
        r8: pop_u64(src, &mut off),
        rdx: pop_u64(src, &mut off),
        rsi: pop_u64(src, &mut off),
        rdi: pop_u64(src, &mut off),
        user_rflags: pop_u64(src, &mut off),
        user_rip: pop_u64(src, &mut off),
        user_rsp: pop_u64(src, &mut off),
        kernel_stack_top: pop_u64(src, &mut off),
    }
}

fn serialize_user_signal_frame(frame: &UserSignalFrame, dst: &mut [u8]) {
    let mut off = 0usize;
    push_u64(dst, &mut off, frame.magic);
    push_u64(dst, &mut off, frame.saved_blocked_mask);
    push_i64(dst, &mut off, frame.saved_rax);
    push_i64(dst, &mut off, frame._pad);
    let saved_size = core::mem::size_of::<process::SyscallSavedFrame>();
    serialize_syscall_saved_frame(&frame.saved, &mut dst[off..off + saved_size]);
    off += saved_size;
    dst[off..off + SIGINFO_SIZE].copy_from_slice(&frame.siginfo);
    off += SIGINFO_SIZE;
    dst[off..off + UCONTEXT_SIZE].copy_from_slice(&frame.ucontext);
}

fn deserialize_user_signal_frame(src: &[u8]) -> UserSignalFrame {
    let mut off = 0usize;
    let magic = pop_u64(src, &mut off);
    let saved_blocked_mask = pop_u64(src, &mut off);
    let saved_rax = pop_i64(src, &mut off);
    let pad = pop_i64(src, &mut off);
    let saved_size = core::mem::size_of::<process::SyscallSavedFrame>();
    let saved = deserialize_syscall_saved_frame(&src[off..off + saved_size]);
    off += saved_size;
    let mut siginfo = [0u8; SIGINFO_SIZE];
    siginfo.copy_from_slice(&src[off..off + SIGINFO_SIZE]);
    off += SIGINFO_SIZE;
    let mut ucontext = [0u8; UCONTEXT_SIZE];
    ucontext.copy_from_slice(&src[off..off + UCONTEXT_SIZE]);
    UserSignalFrame {
        magic,
        saved_blocked_mask,
        saved_rax,
        _pad: pad,
        saved,
        siginfo,
        ucontext,
    }
}

#[inline]
fn set_greg(dst: &mut [u8; UCONTEXT_SIZE], greg: usize, value: u64) {
    let off = UCONTEXT_MCONTEXT_GREGS_OFFSET + greg * GREG_SLOT_SIZE;
    dst[off..off + GREG_SLOT_SIZE].copy_from_slice(&value.to_ne_bytes());
}

fn build_siginfo(signum: u32) -> [u8; SIGINFO_SIZE] {
    let mut siginfo = [0u8; SIGINFO_SIZE];
    siginfo[0..4].copy_from_slice(&(signum as i32).to_ne_bytes());
    siginfo
}

fn build_ucontext(
    saved: &process::SyscallSavedFrame,
    blocked_mask: u64,
    initial_rsp: u64,
    current_result: i64,
) -> [u8; UCONTEXT_SIZE] {
    let mut ucontext = [0u8; UCONTEXT_SIZE];
    ucontext[UCONTEXT_UC_SIGMASK_OFFSET..UCONTEXT_UC_SIGMASK_OFFSET + 8]
        .copy_from_slice(&blocked_mask.to_ne_bytes());

    set_greg(&mut ucontext, GREG_R8, saved.r8);
    set_greg(&mut ucontext, GREG_R9, saved.r9);
    set_greg(&mut ucontext, GREG_R10, saved.r10);
    set_greg(&mut ucontext, GREG_R11, 0);
    set_greg(&mut ucontext, GREG_R12, saved.r12);
    set_greg(&mut ucontext, GREG_R13, saved.r13);
    set_greg(&mut ucontext, GREG_R14, saved.r14);
    set_greg(&mut ucontext, GREG_R15, saved.r15);
    set_greg(&mut ucontext, GREG_RDI, saved.rdi);
    set_greg(&mut ucontext, GREG_RSI, saved.rsi);
    set_greg(&mut ucontext, GREG_RBP, saved.rbp);
    set_greg(&mut ucontext, GREG_RBX, saved.rbx);
    set_greg(&mut ucontext, GREG_RDX, saved.rdx);
    set_greg(&mut ucontext, GREG_RAX, current_result as u64);
    set_greg(&mut ucontext, GREG_RCX, 0);
    set_greg(&mut ucontext, GREG_RSP, initial_rsp);
    set_greg(&mut ucontext, GREG_RIP, saved.user_rip);
    set_greg(&mut ucontext, GREG_EFL, saved.user_rflags);

    ucontext
}

#[inline]
fn signal_frame_saved_offset() -> usize {
    core::mem::size_of::<u64>() * 2 + core::mem::size_of::<i64>() * 2
}

#[inline]
fn signal_frame_siginfo_offset() -> usize {
    signal_frame_saved_offset() + core::mem::size_of::<process::SyscallSavedFrame>()
}

#[inline]
fn signal_frame_ucontext_offset() -> usize {
    signal_frame_siginfo_offset() + SIGINFO_SIZE
}

#[inline]
fn lowest_pending_unblocked(pending: u64, blocked: u64) -> Option<u32> {
    let visible = pending & !blocked;
    if visible == 0 {
        return None;
    }
    let bit = visible.trailing_zeros();
    (bit < 64).then_some(bit + 1)
}

fn current_user_rsp(agent_id: u16) -> u64 {
    process::snapshot_current_syscall_frame()
        .map(|frame| frame.user_rsp)
        .or_else(|| {
            crate::agent::get_agent(agent_id).map(|agent| match agent.mode {
                crate::agent::AgentMode::User => agent.context.rsp,
                _ => 0,
            })
        })
        .unwrap_or(0)
}

fn sigaltstack_attr_flags(raw: u32) -> u32 {
    raw & SS_AUTODISARM
}

fn sigaltstack_contains(st: &state::LinuxAgentState, rsp: u64) -> bool {
    if st.sigaltstack_size == 0 {
        return false;
    }
    if st.sigaltstack_flags & SS_AUTODISARM != 0 {
        return false;
    }
    let base = st.sigaltstack_sp;
    let top = base.saturating_add(st.sigaltstack_size);
    base < rsp && rsp <= top
}

fn sigaltstack_status_flags(st: &state::LinuxAgentState, rsp: u64) -> u32 {
    if st.sigaltstack_size == 0 {
        SS_DISABLE
    } else if sigaltstack_contains(st, rsp) {
        SS_ONSTACK
    } else {
        0
    }
}

fn encode_sigaltstack(st: &state::LinuxAgentState, rsp: u64) -> [u8; SIGALTSTACK_SIZE] {
    let mut bytes = [0u8; SIGALTSTACK_SIZE];
    let flags = sigaltstack_attr_flags(st.sigaltstack_flags) | sigaltstack_status_flags(st, rsp);
    bytes[0..8].copy_from_slice(&st.sigaltstack_sp.to_ne_bytes());
    bytes[8..12].copy_from_slice(&(flags as i32).to_ne_bytes());
    bytes[16..24].copy_from_slice(&st.sigaltstack_size.to_ne_bytes());
    bytes
}

fn parse_sigaltstack(bytes: &[u8; SIGALTSTACK_SIZE]) -> (u64, u32, u64) {
    let ss_sp = u64::from_ne_bytes(bytes[0..8].try_into().unwrap());
    let ss_flags = i32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as u32;
    let ss_size = u64::from_ne_bytes(bytes[16..24].try_into().unwrap());
    (ss_sp, ss_flags, ss_size)
}

fn use_alternate_signal_stack(agent_id: u16, action_flags: u64, rsp: u64) -> Option<u64> {
    if action_flags & SA_ONSTACK == 0 {
        return None;
    }
    let st = state::get_state(agent_id)?;
    if st.sigaltstack_size == 0 || sigaltstack_status_flags(st, rsp) != 0 {
        return None;
    }
    st.sigaltstack_sp.checked_add(st.sigaltstack_size)
}

// ── Public helpers ─────────────────────────────────────────────────────────

/// Initialize signal state for a newly created agent.
/// Called from process::sys_clone3 or state::init_state.
pub fn init_signal_state(agent_id: u16) {
    let Some(idx) = ensure_signal_state_idx(agent_id) else {
        return;
    };
    unsafe {
        SIGNAL_STATES[idx] = SignalState::empty();
        SIGNAL_STATES[idx].agent_id = agent_id;
        SIGNAL_STATES[idx].active = true;
    }
}

pub fn remove_signal_state(agent_id: u16) {
    let Some(idx) = signal_state_idx(agent_id) else {
        return;
    };
    unsafe {
        SIGNAL_STATES[idx] = SignalState::empty();
    }
}

pub fn inherit_signal_state_for_clone(parent_id: u16, child_id: u16, share_handlers: bool) {
    let (parent_owner, parent_actions, parent_mask) = unsafe {
        let Some(parent_idx) = signal_state_idx(parent_id) else {
            return;
        };
        let parent_state = &SIGNAL_STATES[parent_idx];
        let Some(owner_idx) = signal_state_idx(state::sighand_owner(parent_id)) else {
            return;
        };
        let owner_actions = SIGNAL_STATES[owner_idx].actions;
        (owner_idx, owner_actions, parent_state.blocked_mask)
    };

    let Some(child_idx) = ensure_signal_state_idx(child_id) else {
        return;
    };

    unsafe {
        SIGNAL_STATES[child_idx] = SignalState::empty();
        SIGNAL_STATES[child_idx].agent_id = child_id;
        SIGNAL_STATES[child_idx].active = true;
        SIGNAL_STATES[child_idx].blocked_mask = parent_mask;
        if share_handlers {
            SIGNAL_STATES[child_idx].actions = SIGNAL_STATES[parent_owner].actions;
        } else {
            SIGNAL_STATES[child_idx].actions = parent_actions;
        }
    }
}

pub fn reset_signal_state_for_exec(agent_id: u16) {
    let Some(idx) = ensure_signal_state_idx(agent_id) else {
        return;
    };

    let ignored_actions = unsafe {
        signal_state_idx(state::sighand_owner(agent_id))
            .map(|owner_idx| {
                SIGNAL_STATES[owner_idx]
                    .actions
                    .map(|entry| if entry.handler == SIG_IGN { SIG_IGN } else { SIG_DFL })
            })
            .unwrap_or([SIG_DFL; MAX_SIGNALS])
    };

    unsafe {
        SIGNAL_STATES[idx] = SignalState::empty();
        SIGNAL_STATES[idx].agent_id = agent_id;
        SIGNAL_STATES[idx].active = true;
        for (slot, handler) in SIGNAL_STATES[idx]
            .actions
            .iter_mut()
            .zip(ignored_actions.into_iter())
        {
            slot.handler = handler;
        }
    }
}

pub fn raise_thread_signal(agent_id: u16, signum: u32) {
    if !(1..=64).contains(&signum) {
        return;
    }
    if let Some(st) = state::get_state_mut(agent_id) {
        st.thread_pending_signals |= 1u64 << (signum - 1);
        if signum == SIGCHLD && state::trace_runtime_agent(agent_id) {
            serial_println!(
                "[SIGDBG] raise-thread agent={} pending_thread={:#x}",
                agent_id,
                st.thread_pending_signals
            );
        }
    }
}

pub fn raise_group_signal(agent_id: u16, signum: u32) {
    if !(1..=64).contains(&signum) {
        return;
    }
    let leader = thread_group_leader(agent_id);
    if let Some(st) = state::get_state_mut(leader) {
        st.group_pending_signals |= 1u64 << (signum - 1);
    }
}

fn next_pending_signal(agent_id: u16) -> Option<(u32, bool)> {
    let st = state::get_state(agent_id)?;
    let blocked = blocked_mask(agent_id);
    let thread_sig = lowest_pending_unblocked(st.thread_pending_signals, blocked);

    let leader = thread_group_leader(agent_id);
    // Keep process-directed delivery deterministic by picking the lowest-id
    // active thread in the group whose mask allows the signal. This is closer
    // to Linux than forcing everything onto the leader, while still keeping
    // delivery stable across runs.
    let group_sig = next_group_pending_signal_for_agent(agent_id, leader);

    match (thread_sig, group_sig) {
        (Some(thread_signum), Some(group_signum)) => {
            if thread_signum <= group_signum {
                Some((thread_signum, false))
            } else {
                Some((group_signum, true))
            }
        }
        (Some(signum), None) => Some((signum, false)),
        (None, Some(signum)) => Some((signum, true)),
        (None, None) => None,
    }
}

fn next_group_pending_signal_for_agent(agent_id: u16, leader: u16) -> Option<u32> {
    let leader_state = state::get_state(leader)?;
    let pending = leader_state.group_pending_signals;
    if pending == 0 {
        return None;
    }

    let group_pid = leader_state.pid;
    for signum in 1..=64u32 {
        let bit = 1u64 << (signum - 1);
        if pending & bit == 0 {
            continue;
        }
        if group_signal_recipient(group_pid, signum) == Some(agent_id) {
            return Some(signum);
        }
    }
    None
}

fn group_signal_recipient(group_pid: u32, signum: u32) -> Option<u16> {
    let bit = 1u64 << (signum - 1);
    for id in 0..MAX_LINUX_AGENTS as u16 {
        let Some(st) = state::get_state(id) else {
            continue;
        };
        if !st.active || st.pid != group_pid {
            continue;
        }
        if blocked_mask(id) & bit == 0 {
            return Some(id);
        }
    }
    None
}

/// Return true if the agent currently has any unblocked pending signal that
/// would be observable at a syscall-return boundary.
pub fn has_unblocked_pending_signal(agent_id: u16) -> bool {
    next_pending_signal(agent_id).is_some()
}

fn clear_pending_signal(agent_id: u16, signum: u32, group_directed: bool) {
    if !(1..=64).contains(&signum) {
        return;
    }
    if group_directed {
        let leader = thread_group_leader(agent_id);
        if let Some(st) = state::get_state_mut(leader) {
            st.group_pending_signals &= !(1u64 << (signum - 1));
        }
    } else if let Some(st) = state::get_state_mut(agent_id) {
        st.thread_pending_signals &= !(1u64 << (signum - 1));
    }
}

fn reset_sigaction(agent_id: u16, signum: u32) {
    if !(1..=64).contains(&signum) {
        return;
    }
    let Some(owner_idx) = ensure_signal_state_idx(state::sighand_owner(agent_id)) else {
        return;
    };
    unsafe {
        let state = &mut SIGNAL_STATES[owner_idx];
        state.actions[(signum - 1) as usize] = SigActionEntry::default();
    }
}

fn install_user_signal_frame(
    agent_id: u16,
    action: SigActionEntry,
    signum: u32,
    current_result: i64,
) -> Result<(), i64> {
    if action.restorer == 0 {
        return Err(-EINVAL);
    }

    let Some(saved) = process::snapshot_current_syscall_frame() else {
        return Err(-EFAULT);
    };

    let initial_rsp = use_alternate_signal_stack(agent_id, action.flags, saved.user_rsp)
        .unwrap_or(saved.user_rsp);
    let frame_size = core::mem::size_of::<UserSignalFrame>() as u64;
    let frame_base = initial_rsp.saturating_sub(frame_size) & !0xf;
    if frame_base < 8 {
        return Err(-EFAULT);
    }
    let user_rsp = frame_base - 8;

    let frame = UserSignalFrame {
        magic: SIGNAL_FRAME_MAGIC,
        saved_blocked_mask: blocked_mask(agent_id),
        saved_rax: current_result,
        _pad: 0,
        saved,
        siginfo: build_siginfo(signum),
        ucontext: build_ucontext(&saved, blocked_mask(agent_id), saved.user_rsp, current_result),
    };

    let mut frame_bytes = [0u8; core::mem::size_of::<UserSignalFrame>()];
    serialize_user_signal_frame(&frame, &mut frame_bytes);

    if !copy_to_user(agent_id, frame_base, &frame_bytes) {
        return Err(-EFAULT);
    }
    if !copy_to_user(agent_id, user_rsp, &action.restorer.to_ne_bytes()) {
        return Err(-EFAULT);
    }

    let Some(idx) = ensure_signal_state_idx(agent_id) else {
        return Err(-EINVAL);
    };
    unsafe {
        let state = &mut SIGNAL_STATES[idx];
        state.blocked_mask = frame.saved_blocked_mask | action.mask;
        if action.flags & SA_NODEFER == 0 {
            state.blocked_mask |= 1u64 << (signum - 1);
        }
        state.blocked_mask &= !((1u64 << 8) | (1u64 << 18));
    }

    let Some(current) = process::current_syscall_frame_mut() else {
        return Err(-EFAULT);
    };
    let siginfo_ptr = frame_base + signal_frame_siginfo_offset() as u64;
    let ucontext_ptr = frame_base + signal_frame_ucontext_offset() as u64;
    current.user_rip = action.handler;
    current.user_rsp = user_rsp;
    current.rdi = signum as u64;
    if action.flags & SA_SIGINFO != 0 {
        current.rsi = siginfo_ptr;
        current.rdx = ucontext_ptr;
    } else {
        current.rsi = 0;
        current.rdx = 0;
    }

    Ok(())
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
/// For TOS: signals are rarely delivered, so this is mostly bookkeeping.
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

    let Some(idx) = ensure_signal_state_idx(agent_id) else {
        return -EINVAL;
    };
    let sig_idx = (signum - 1) as usize;

    unsafe {
        let mask_state = &mut SIGNAL_STATES[idx];
        let Some(action_owner) = ensure_signal_state_idx(state::sighand_owner(agent_id)) else {
            return -EINVAL;
        };
        let state = &mut SIGNAL_STATES[action_owner];

        // If oldact_ptr is set, write the current action there.
        if oldact_ptr != 0 {
            let old = &state.actions[sig_idx];
            let mut old_bytes = [0u8; SIGACTION_SIZE];
            old_bytes[0..8].copy_from_slice(&old.handler.to_ne_bytes());
            old_bytes[8..16].copy_from_slice(&old.flags.to_ne_bytes());
            old_bytes[16..24].copy_from_slice(&old.restorer.to_ne_bytes());
            old_bytes[24..32].copy_from_slice(&old.mask.to_ne_bytes());
            if !copy_to_user(agent_id, oldact_ptr, &old_bytes) {
                return -EFAULT;
            }
        }

        // If act_ptr is set, install the new action.
        if act_ptr != 0 {
            let mut act_bytes = [0u8; SIGACTION_SIZE];
            if !copy_from_user(agent_id, act_ptr, &mut act_bytes) {
                return -EFAULT;
            }

            state.actions[sig_idx] = SigActionEntry {
                handler: u64::from_ne_bytes(act_bytes[0..8].try_into().unwrap()),
                flags: u64::from_ne_bytes(act_bytes[8..16].try_into().unwrap()),
                restorer: u64::from_ne_bytes(act_bytes[16..24].try_into().unwrap()),
                mask: u64::from_ne_bytes(act_bytes[24..32].try_into().unwrap()),
            };

            if signum as u32 == SIGCHLD {
                serial_println!(
                    "[linux_compat] rt_sigaction: agent={} sig={} handler={:#x} flags={:#x} restorer={:#x} mask={:#x}",
                    agent_id,
                    signum,
                    state.actions[sig_idx].handler,
                    state.actions[sig_idx].flags,
                    state.actions[sig_idx].restorer,
                    state.actions[sig_idx].mask
                );
            } else {
                serial_println!(
                    "[linux_compat] rt_sigaction: agent={} sig={} handler={:#x}",
                    agent_id,
                    signum,
                    state.actions[sig_idx].handler
                );
            }
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

    let Some(idx) = ensure_signal_state_idx(agent_id) else {
        return -EINVAL;
    };

    unsafe {
        let state = &mut SIGNAL_STATES[idx];
        let old_mask = state.blocked_mask;

        // Write current mask to oldset if requested.
        if oldset_ptr != 0 {
            if !copy_to_user(agent_id, oldset_ptr, &state.blocked_mask.to_ne_bytes()) {
                return -EFAULT;
            }
        }

        // Apply new mask if set_ptr is provided.
        if set_ptr != 0 {
            let mut new_set_bytes = [0u8; 8];
            if !copy_from_user(agent_id, set_ptr, &mut new_set_bytes) {
                return -EFAULT;
            }
            let new_set = u64::from_ne_bytes(new_set_bytes);

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

        let sigchld_bit = 1u64 << (SIGCHLD - 1);
        if (old_mask ^ state.blocked_mask) & sigchld_bit != 0
            && state::trace_runtime_agent(agent_id)
        {
            serial_println!(
                "[SIGDBG] mask agent={} how={} blocked={:#x}",
                agent_id,
                how,
                state.blocked_mask
            );
        }
    }

    0
}

pub fn sys_rt_sigpending(agent_id: u16, set_ptr: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != SIGSET_BYTES as u64 {
        return -EINVAL;
    }
    if set_ptr == 0 {
        return -EFAULT;
    }

    let Some(st) = state::get_state(agent_id) else {
        return -EINVAL;
    };
    let leader = thread_group_leader(agent_id);
    let group_pending = state::get_state(leader)
        .map(|leader_st| leader_st.group_pending_signals)
        .unwrap_or(0);
    let pending = (st.thread_pending_signals | group_pending) & blocked_mask(agent_id);
    if !copy_to_user(agent_id, set_ptr, &pending.to_ne_bytes()) {
        return -EFAULT;
    }
    0
}

/// sigaltstack(2) -- Configure or query the thread's alternate signal stack.
pub fn sys_sigaltstack(agent_id: u16, ss_ptr: u64, old_ss_ptr: u64) -> i64 {
    let rsp = current_user_rsp(agent_id);

    if old_ss_ptr != 0 {
        let Some(st) = state::get_state(agent_id) else {
            return -EINVAL;
        };
        let old_bytes = encode_sigaltstack(st, rsp);
        if !copy_to_user(agent_id, old_ss_ptr, &old_bytes) {
            return -EFAULT;
        }
    }

    if ss_ptr == 0 {
        return 0;
    }

    let mut new_bytes = [0u8; SIGALTSTACK_SIZE];
    if !copy_from_user(agent_id, ss_ptr, &mut new_bytes) {
        return -EFAULT;
    }

    let (ss_sp, ss_flags, ss_size) = parse_sigaltstack(&new_bytes);
    let attr_flags = sigaltstack_attr_flags(ss_flags);
    let status_flags = ss_flags & (SS_ONSTACK | SS_DISABLE);
    if status_flags != 0 && status_flags != SS_ONSTACK && status_flags != SS_DISABLE {
        return -EINVAL;
    }

    let Some(st) = state::get_state_mut(agent_id) else {
        return -EINVAL;
    };
    if sigaltstack_status_flags(st, rsp) == SS_ONSTACK {
        return -EPERM;
    }

    if status_flags == SS_DISABLE {
        st.sigaltstack_sp = 0;
        st.sigaltstack_size = 0;
        st.sigaltstack_flags = attr_flags;
        st.sigaltstack_pad = 0;
        return 0;
    }

    if ss_size < MINSIGSTKSZ {
        return -ENOMEM;
    }
    if ss_sp.checked_add(ss_size).is_none() {
        return -EINVAL;
    }

    st.sigaltstack_sp = ss_sp;
    st.sigaltstack_size = ss_size;
    st.sigaltstack_flags = attr_flags;
    st.sigaltstack_pad = 0;
    0
}

// ── Signal delivery ───────────────────────────────────────────────────────

// Signals whose default action is to terminate the process.
const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

// Signal numbers for well-known signals.
const SIGKILL: u32 = 9;
const SIGSEGV: u32 = 11;
const SIGCHLD: u32 = 17;
const SIGSTOP: u32 = 19;
const SIGURG: u32 = 23;
const SIGWINCH: u32 = 28;

/// Returns true if the default action for `signum` is to ignore the signal.
fn default_action_is_ignore(signum: u32) -> bool {
    matches!(signum, SIGCHLD | SIGURG | SIGWINCH)
}

/// Look up the registered handler address for a given signal on an agent.
/// Returns SIG_DFL (0) if no handler has been registered.
fn get_sigaction(agent_id: u16, signum: u32) -> SigActionEntry {
    if signum < 1 || signum > 64 {
        return SigActionEntry::default();
    }
    let Some(idx) = signal_state_idx(state::sighand_owner(agent_id)) else {
        return SigActionEntry::default();
    };
    unsafe {
        let s = &SIGNAL_STATES[idx];
        s.actions[(signum - 1) as usize]
    }
}

/// Deliver all pending signals for an agent.
///
/// Called at syscall-return boundary to ensure deterministic delivery.
/// For now, user-space handler invocation (pushing a signal frame and
/// redirecting RIP) is deferred -- handlers are logged and the signal
/// is cleared.  SIG_DFL terminate actions do terminate the agent.
pub fn deliver_pending_signals(agent_id: u16, current_result: i64) -> i64 {
    // Process signals one at a time, lowest number first.
    loop {
        let (signum, group_directed) = match next_pending_signal(agent_id) {
            Some(s) => s,
            None => break current_result,
        };

        let action = get_sigaction(agent_id, signum);
        let handler = action.handler;
        identity::clear_rseq_critical_section(agent_id);
        if signum == SIGCHLD && state::trace_runtime_agent(agent_id) {
            serial_println!(
                "[SIGDBG] deliver agent={} group={} handler={:#x} flags={:#x} restorer={:#x} blocked={:#x}",
                agent_id,
                group_directed,
                handler,
                action.flags,
                action.restorer,
                blocked_mask(agent_id)
            );
        }

        if handler == SIG_IGN {
            // Explicitly ignored -- clear and continue.
            clear_pending_signal(agent_id, signum, group_directed);
            continue;
        }

        if handler == SIG_DFL {
            // Default action.
            if default_action_is_ignore(signum) {
                // Default-ignore signals (SIGCHLD, SIGURG, SIGWINCH).
                clear_pending_signal(agent_id, signum, group_directed);
                continue;
            }
            // Default action for most other signals is terminate.
            serial_println!(
                "[signal] agent {} terminated by SIG{} (default action, group={})",
                agent_id,
                signum,
                group_directed
            );
            clear_pending_signal(agent_id, signum, group_directed);
            // Default fatal signals terminate the Linux thread group.
            let _ = crate::linux_compat::process::sys_exit_group(agent_id, 128 + signum as i32);
            return current_result; // unreachable in practice
        }

        // User-registered handler: build a minimal x86_64 signal frame and
        // enter the handler at syscall-return. Unsupported variants fall back
        // to deterministic log+clear behavior.
        clear_pending_signal(agent_id, signum, group_directed);
        if action.flags & SA_RESETHAND != 0 {
            reset_sigaction(agent_id, signum);
        }
        if install_user_signal_frame(agent_id, action, signum, current_result).is_ok() {
            return current_result;
        }
        serial_println!(
            "[signal] agent {}: signal {} has unsupported handler shape {:#x} flags={:#x} restorer={:#x}",
            agent_id,
            signum,
            handler,
            action.flags,
            action.restorer
        );
    }
}

fn restore_from_user_signal_frame(agent_id: u16) -> Result<i64, i64> {
    let Some(current) = process::current_syscall_frame_mut() else {
        return Err(-EFAULT);
    };

    let frame_addr = current.user_rsp;
    let mut frame_bytes = [0u8; core::mem::size_of::<UserSignalFrame>()];
    if !copy_from_user(agent_id, frame_addr, &mut frame_bytes) {
        return Err(-EFAULT);
    }
    let frame = deserialize_user_signal_frame(&frame_bytes);
    if frame.magic != SIGNAL_FRAME_MAGIC {
        return Err(-EINVAL);
    }

    let Some(idx) = ensure_signal_state_idx(agent_id) else {
        return Err(-EINVAL);
    };
    unsafe {
        let state = &mut SIGNAL_STATES[idx];
        state.blocked_mask = frame.saved_blocked_mask;
        state.blocked_mask &= !((1u64 << 8) | (1u64 << 18));
    }

    let kernel_stack_top = current.kernel_stack_top;
    *current = frame.saved;
    current.kernel_stack_top = kernel_stack_top;

    Ok(frame.saved_rax)
}

/// rt_sigreturn(2) -- Return from signal handler.
///
/// Restores the saved user context from the synthetic TOS user-signal frame.
pub fn sys_rt_sigreturn(agent_id: u16) -> i64 {
    match restore_from_user_signal_frame(agent_id) {
        Ok(saved_rax) => saved_rax,
        Err(err) => {
            serial_println!(
                "[linux_compat] rt_sigreturn: agent={} restore failed err={}",
                agent_id,
                err
            );
            err
        }
    }
}
