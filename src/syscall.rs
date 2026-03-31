//! ATOS Syscall Dispatcher
//!
//! Provides the syscall entry point for agents. In Stage-1, agents call
//! `syscall::syscall()` directly as a Rust function call (no privilege
//! transition). Later stages will use the x86_64 SYSCALL/SYSRET mechanism.
//!
//! Every syscall is gated by capability checks and charged against the
//! calling agent's energy budget.
//!
//! Syscall numbers follow Yellow Paper §14.2.

use crate::agent::RuntimeKind;
use crate::agent::*;
use crate::arch::x86_64::paging;
use crate::arch::x86_64::security;
use crate::capability::{self, CapType, Capability};
use crate::energy;
use crate::mailbox;
use crate::sched;
use crate::serial_println;
use crate::state;

#[inline]
fn interrupts_were_enabled() -> bool {
    let flags: u64;
    unsafe {
        core::arch::asm!("pushfq; pop {}", out(reg) flags, options(nomem, preserves_flags));
    }
    (flags & (1 << 9)) != 0
}

// ─── Replay transcript capture ──────────────────────────────────────────────

/// Syscall transcript entry for replay verification.
#[derive(Clone, Copy)]
pub struct TranscriptEntry {
    pub tick: u64,
    pub agent_id: u16,
    pub syscall_num: u64,
    pub arg0: u64,
    pub result: i64,
}

const TRANSCRIPT_CAP: usize = 4096;

// Safety: single-core, no preemption during syscall handling.
static mut TRANSCRIPT: [TranscriptEntry; TRANSCRIPT_CAP] = [TranscriptEntry {
    tick: 0,
    agent_id: 0,
    syscall_num: 0,
    arg0: 0,
    result: 0,
}; TRANSCRIPT_CAP];
static mut TRANSCRIPT_LEN: usize = 0;
static mut TRANSCRIPT_WRAP: bool = false;
static mut LINUX_EXIT_DEBUG_STAGE: u64 = 0;

/// Record a syscall invocation into the replay transcript ring buffer.
fn record_transcript(tick: u64, agent_id: u16, syscall_num: u64, arg0: u64, result: i64) {
    unsafe {
        let idx = TRANSCRIPT_LEN % TRANSCRIPT_CAP;
        TRANSCRIPT[idx] = TranscriptEntry {
            tick,
            agent_id,
            syscall_num,
            arg0,
            result,
        };
        TRANSCRIPT_LEN += 1;
        if TRANSCRIPT_LEN >= TRANSCRIPT_CAP {
            TRANSCRIPT_WRAP = true;
        }
    }
}

/// Return the total number of transcript entries recorded (may exceed ring capacity).
pub fn transcript_count() -> usize {
    unsafe {
        if TRANSCRIPT_WRAP {
            TRANSCRIPT_CAP
        } else {
            TRANSCRIPT_LEN
        }
    }
}

pub fn linux_exit_debug_stage() -> u64 {
    unsafe { LINUX_EXIT_DEBUG_STAGE }
}

pub fn set_linux_exit_debug_stage(stage: u64) {
    unsafe {
        LINUX_EXIT_DEBUG_STAGE = stage;
    }
}

/// Compute a hash commitment over transcript entries for a given agent within a tick range.
pub fn compute_transcript_hash(agent_id: u16, tick_start: u64, tick_end: u64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    unsafe {
        let cap = TRANSCRIPT_CAP;
        let count = if TRANSCRIPT_WRAP { cap } else { TRANSCRIPT_LEN };
        let start = if TRANSCRIPT_WRAP {
            TRANSCRIPT_LEN.wrapping_sub(cap)
        } else {
            0
        };
        for i in 0..count {
            let idx = (start + i) % cap;
            let e = &TRANSCRIPT[idx];
            if e.agent_id == agent_id && e.tick >= tick_start && e.tick <= tick_end {
                hasher.update(&e.syscall_num.to_le_bytes());
                hasher.update(&e.arg0.to_le_bytes());
                hasher.update(&(e.result as u64).to_le_bytes());
                hasher.update(&e.tick.to_le_bytes());
            }
        }
    }
    let hash = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Dispatch a syscall from the current agent.
///
/// # Arguments
/// * `num` - syscall number (Yellow Paper §14.2)
/// * `a1`-`a5` - syscall arguments (meaning depends on syscall number)
///
/// # Returns
/// Syscall-specific return value. Negative values indicate errors (as i64 bit pattern).
///
/// In Stage-1, this is a direct function call. No privilege transition occurs.
pub fn syscall(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    syscall_with_a6(num, a1, a2, a3, a4, a5, 0)
}

fn syscall_with_a6(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
    let restore_if = interrupts_were_enabled();
    unsafe {
        core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
    }

    // Spectre v2: restrict indirect branch speculation on kernel entry
    security::spectre_kernel_enter();

    let result = syscall_inner(num, a1, a2, a3, a4, a5, a6);

    // Spectre v2: relax speculation restrictions before returning to user mode
    security::spectre_user_enter();

    if restore_if {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }

    result
}

#[inline(never)]
fn handle_linux_compat_syscall(
    caller_id: u16,
    num: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
) -> i64 {
    if num == crate::linux_compat::constants::SYS_EXIT
        || num == crate::linux_compat::constants::SYS_EXIT_GROUP
    {
        set_linux_exit_debug_stage(0xE100);
    }

    let result = if num == crate::linux_compat::constants::SYS_EXIT {
        set_linux_exit_debug_stage(0xE110);
        crate::linux_compat::process::sys_exit(caller_id, a1 as i32)
    } else if num == crate::linux_compat::constants::SYS_EXIT_GROUP {
        set_linux_exit_debug_stage(0xE120);
        crate::linux_compat::process::sys_exit_group(caller_id, a1 as i32)
    } else {
        crate::linux_compat::dispatch::dispatch(caller_id, num, a1, a2, a3, a4, a5, a6)
    };

    // Keep the LinuxCompat path out of syscall_inner(): qemu64 TCG remains
    // sensitive to large inlined dispatch tables in this hot function.
    if num != SYS_YIELD {
        let exit_ctx = crate::ebpf::attach::SyscallContext {
            agent_id: caller_id,
            syscall_num: num,
            arg0: result as u64,
            arg1: 0,
            arg2: 0,
        };
        crate::ebpf::attach::run_at(
            crate::ebpf::attach::AttachPoint::SyscallExit(num),
            &exit_ctx as *const crate::ebpf::attach::SyscallContext as u64,
        );
    }

    result
}

#[inline(never)]
fn finish_native_syscall(caller_id: u16, num: u64, a1: u64, result: i64) -> i64 {
    // ── eBPF SyscallExit hook (audit only) ──
    if num != SYS_YIELD {
        let exit_ctx = crate::ebpf::attach::SyscallContext {
            agent_id: caller_id,
            syscall_num: num,
            arg0: result as u64,
            arg1: 0,
            arg2: 0,
        };
        let exit_action = crate::ebpf::attach::run_at(
            crate::ebpf::attach::AttachPoint::SyscallExit(num),
            &exit_ctx as *const crate::ebpf::attach::SyscallContext as u64,
        );
        if exit_action == crate::ebpf::types::Action::Log {
            crate::event::emit(
                caller_id,
                crate::event::EventType::EbpfPolicy,
                num,
                result as u64,
                0,
            );
        }
    }

    // ── Record syscall to replay transcript ──
    // Skip SYS_YIELD to avoid flooding the ring buffer with idle ticks
    if num != SYS_YIELD {
        let tick = crate::arch::x86_64::timer::get_ticks();
        record_transcript(tick, caller_id, num, a1, result);
    }

    result
}

#[inline(never)]
fn handle_mailbox_syscall(
    caller_id: u16,
    num: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
) -> Option<i64> {
    let result = match num {
        // ── 3: sys_send ─────────────────────────────────────────────────
        // a1 = target mailbox, a2 = payload ptr, a3 = payload len
        SYS_SEND => {
            let target_mailbox = a1 as MailboxId;
            let payload_len = a3 as usize;

            if payload_len > MAX_MESSAGE_PAYLOAD {
                return Some(E_PAYLOAD_TOO_LARGE);
            }

            // ── eBPF policy check ──
            // Run any eBPF programs attached at MailboxSend for this target
            let ebpf_ctx = crate::ebpf::attach::MailboxContext {
                sender_id: caller_id,
                target_mailbox,
                payload_len: payload_len as u16,
            };
            let ebpf_action = crate::ebpf::attach::run_at(
                crate::ebpf::attach::AttachPoint::MailboxSend(target_mailbox),
                &ebpf_ctx as *const crate::ebpf::attach::MailboxContext as u64,
            );
            if ebpf_action == crate::ebpf::types::Action::Deny {
                crate::event::cap_denied(caller_id, 0xFF, target_mailbox as u64); // 0xFF = eBPF policy denial
                return Some(E_NO_CAP);
            }
            if ebpf_action == crate::ebpf::types::Action::Log {
                crate::event::emit(
                    caller_id,
                    crate::event::EventType::EbpfPolicy,
                    target_mailbox as u64,
                    0,
                    0,
                );
            }

            // Safety: the payload pointer comes from the calling agent's stack,
            // which is valid memory in Stage-1 (all agents share the kernel address space).
            // stac/clac bracket the user-memory read to satisfy SMAP when enabled.
            let payload = unsafe {
                security::stac();
                let s = core::slice::from_raw_parts(a2 as *const u8, payload_len);
                security::clac();
                s
            };

            match mailbox::send_message(caller_id, target_mailbox, payload) {
                Ok(()) => E_OK,
                Err(e) => e,
            }
        }

        // ── 4: sys_recv ─────────────────────────────────────────────────
        // a1 = mailbox id, a2 = buffer ptr, a3 = buffer len
        SYS_RECV => {
            let mailbox_id = a1 as MailboxId;
            let buf_len = a3 as usize;

            loop {
                match mailbox::recv_message(caller_id, mailbox_id) {
                    Ok(msg) => {
                        // ── eBPF MailboxRecv check ──
                        let recv_ctx = crate::ebpf::attach::MailboxContext {
                            sender_id: msg.sender_id,
                            target_mailbox: mailbox_id,
                            payload_len: msg.len,
                        };
                        let recv_action = crate::ebpf::attach::run_at(
                            crate::ebpf::attach::AttachPoint::MailboxRecv(mailbox_id),
                            &recv_ctx as *const crate::ebpf::attach::MailboxContext as u64,
                        );
                        if recv_action == crate::ebpf::types::Action::Deny {
                            // Message already dequeued; discard and continue blocking
                            continue;
                        }
                        if recv_action == crate::ebpf::types::Action::Log {
                            crate::event::emit(
                                caller_id,
                                crate::event::EventType::EbpfPolicy,
                                mailbox_id as u64,
                                msg.sender_id as u64,
                                0,
                            );
                        }

                        let copy_len = (msg.len as usize).min(buf_len);
                        if copy_len > 0 {
                            // Safety: the buffer pointer comes from the calling agent's stack.
                            // stac/clac bracket the write to satisfy SMAP when enabled.
                            unsafe {
                                security::stac();
                                core::ptr::copy(msg.payload.as_ptr(), a2 as *mut u8, copy_len);
                                security::clac();
                            }
                        }
                        break copy_len as i64;
                    }
                    Err(E_NOT_FOUND) => {
                        sched::block_current(AgentStatus::BlockedRecv);
                    }
                    Err(e) => break e,
                }
            }
        }

        // ── 12: sys_recv_nonblocking ─────────────────────────────────────
        // a1 = mailbox id, a2 = buffer ptr, a3 = buffer capacity
        SYS_RECV_NONBLOCKING => {
            let mailbox_id = a1 as MailboxId;
            let buf_len = a3 as usize;

            match mailbox::recv_message(caller_id, mailbox_id) {
                Ok(msg) => {
                    // ── eBPF MailboxRecv check ──
                    let recv_ctx = crate::ebpf::attach::MailboxContext {
                        sender_id: msg.sender_id,
                        target_mailbox: mailbox_id,
                        payload_len: msg.len,
                    };
                    let recv_action = crate::ebpf::attach::run_at(
                        crate::ebpf::attach::AttachPoint::MailboxRecv(mailbox_id),
                        &recv_ctx as *const crate::ebpf::attach::MailboxContext as u64,
                    );
                    if recv_action == crate::ebpf::types::Action::Deny {
                        return Some(0);
                    }
                    if recv_action == crate::ebpf::types::Action::Log {
                        crate::event::emit(
                            caller_id,
                            crate::event::EventType::EbpfPolicy,
                            mailbox_id as u64,
                            msg.sender_id as u64,
                            0,
                        );
                    }

                    let copy_len = (msg.len as usize).min(buf_len);
                    if copy_len > 0 {
                        unsafe {
                            security::stac();
                            core::ptr::copy(msg.payload.as_ptr(), a2 as *mut u8, copy_len);
                            security::clac();
                        }
                    }
                    copy_len as i64
                }
                Err(_) => 0, // empty or error: return 0 immediately, no blocking
            }
        }

        // ── 13: sys_send_blocking ────────────────────────────────────────
        // a1 = target mailbox, a2 = payload ptr, a3 = payload len
        SYS_SEND_BLOCKING => {
            let target_mailbox = a1 as MailboxId;
            let payload_len = a3 as usize;

            if payload_len > MAX_MESSAGE_PAYLOAD {
                return Some(E_PAYLOAD_TOO_LARGE);
            }

            // ── eBPF policy check (same as SYS_SEND) ──
            let ebpf_ctx = crate::ebpf::attach::MailboxContext {
                sender_id: caller_id,
                target_mailbox,
                payload_len: payload_len as u16,
            };
            let ebpf_action = crate::ebpf::attach::run_at(
                crate::ebpf::attach::AttachPoint::MailboxSend(target_mailbox),
                &ebpf_ctx as *const crate::ebpf::attach::MailboxContext as u64,
            );
            if ebpf_action == crate::ebpf::types::Action::Deny {
                crate::event::cap_denied(caller_id, 0xFF, target_mailbox as u64);
                return Some(E_NO_CAP);
            }
            if ebpf_action == crate::ebpf::types::Action::Log {
                crate::event::emit(
                    caller_id,
                    crate::event::EventType::EbpfPolicy,
                    target_mailbox as u64,
                    0,
                    0,
                );
            }

            let payload = unsafe {
                security::stac();
                let s = core::slice::from_raw_parts(a2 as *const u8, payload_len);
                security::clac();
                s
            };

            match mailbox::send_message(caller_id, target_mailbox, payload) {
                Ok(()) => E_OK,
                Err(E_MAILBOX_FULL) => {
                    // Mailbox is full: block the sender
                    serial_println!(
                        "[SYSCALL] Agent {} blocking on full mailbox {}",
                        caller_id,
                        target_mailbox
                    );
                    mailbox::add_blocked_sender(target_mailbox, caller_id);
                    sched::block_current(AgentStatus::BlockedSend);
                    // When we resume, the mailbox may have space. Try sending again.
                    // Re-read payload since we're resuming after context switch.
                    let payload_retry = unsafe {
                        security::stac();
                        let s = core::slice::from_raw_parts(a2 as *const u8, payload_len);
                        security::clac();
                        s
                    };
                    match mailbox::send_message(caller_id, target_mailbox, payload_retry) {
                        Ok(()) => E_OK,
                        Err(e) => e,
                    }
                }
                Err(e) => e,
            }
        }

        // ── 18: sys_mailbox_create ──────────────────────────────────────
        SYS_MAILBOX_CREATE => {
            // Create an additional mailbox for the calling agent
            let new_id = crate::mailbox::find_free_mailbox_id();
            match new_id {
                Some(id) => {
                    crate::mailbox::create_mailbox(id, caller_id).ok();
                    serial_println!("[SYSCALL] Agent {} created mailbox {}", caller_id, id);
                    id as i64
                }
                None => E_QUOTA_EXCEEDED,
            }
        }

        // ── 19: sys_mailbox_destroy ─────────────────────────────────────
        SYS_MAILBOX_DESTROY => {
            let mailbox_id = a1 as MailboxId;
            // Cannot destroy primary mailbox (== agent_id)
            if mailbox_id == caller_id {
                return Some(E_INVALID_ARG);
            }
            // Check ownership
            match crate::mailbox::get_mailbox_owner(mailbox_id) {
                Some(owner) if owner == caller_id => {
                    crate::mailbox::destroy_mailbox(mailbox_id);
                    serial_println!(
                        "[SYSCALL] Agent {} destroyed mailbox {}",
                        caller_id,
                        mailbox_id
                    );
                    E_OK
                }
                _ => E_INVALID_ARG,
            }
        }

        // ── 21: sys_recv_timeout ────────────────────────────────────────
        // a1 = mailbox id, a2 = buffer ptr, a3 = buffer len, a4 = timeout in ticks (0 = infinite)
        SYS_RECV_TIMEOUT => {
            let mailbox_id = a1 as MailboxId;
            let buf_len = a3 as usize;
            let timeout_ticks = a4; // 4th argument = timeout in ticks (0 = infinite)

            // Try non-blocking recv first
            match mailbox::recv_message(caller_id, mailbox_id) {
                Ok(msg) => {
                    // ── eBPF MailboxRecv check ──
                    let recv_ctx = crate::ebpf::attach::MailboxContext {
                        sender_id: msg.sender_id,
                        target_mailbox: mailbox_id,
                        payload_len: msg.len,
                    };
                    let recv_action = crate::ebpf::attach::run_at(
                        crate::ebpf::attach::AttachPoint::MailboxRecv(mailbox_id),
                        &recv_ctx as *const crate::ebpf::attach::MailboxContext as u64,
                    );
                    if recv_action == crate::ebpf::types::Action::Deny {
                        return Some(0);
                    }
                    if recv_action == crate::ebpf::types::Action::Log {
                        crate::event::emit(
                            caller_id,
                            crate::event::EventType::EbpfPolicy,
                            mailbox_id as u64,
                            msg.sender_id as u64,
                            0,
                        );
                    }

                    let copy_len = (msg.len as usize).min(buf_len);
                    if copy_len > 0 {
                        unsafe {
                            security::stac();
                            core::ptr::copy(msg.payload.as_ptr(), a2 as *mut u8, copy_len);
                            security::clac();
                        }
                    }
                    copy_len as i64
                }
                Err(_) => {
                    if timeout_ticks == 0 {
                        // No timeout: block like regular recv
                        sched::block_current(AgentStatus::BlockedRecv);
                        0 // will be retried when unblocked
                    } else {
                        // Timeout: check if deadline has passed
                        // For Stage-3, return E_TIMEOUT immediately if no message
                        // so the agent can retry with yield in a loop
                        E_TIMEOUT
                    }
                }
            }
        }

        _ => return None,
    };

    Some(result)
}

#[inline(never)]
fn handle_state_syscall(caller_id: u16, num: u64, a1: u64, a2: u64, a3: u64) -> Option<i64> {
    let result = match num {
        // ── 9: sys_state_get ────────────────────────────────────────────
        // a1 = key, a2 = buffer ptr, a3 = buffer len
        SYS_STATE_GET => {
            let keyspace = caller_id as KeyspaceId;

            if !capability::agent_has_cap(caller_id, CapType::StateRead, keyspace) {
                crate::event::cap_denied(caller_id, CapType::StateRead as u64, keyspace as u64);
                return Some(E_NO_CAP);
            }

            match state::state_get(keyspace, a1) {
                Some((data, len)) => {
                    let copy_len = len.min(a3 as usize);
                    if copy_len > 0 {
                        // stac/clac bracket the write to user buffer to satisfy SMAP.
                        unsafe {
                            security::stac();
                            let buf = core::slice::from_raw_parts_mut(a2 as *mut u8, copy_len);
                            buf.copy_from_slice(&data[..copy_len]);
                            security::clac();
                        }
                    }
                    copy_len as i64
                }
                None => E_NOT_FOUND,
            }
        }

        // ── 10: sys_state_put ───────────────────────────────────────────
        // a1 = key, a2 = value ptr, a3 = value len
        SYS_STATE_PUT => {
            let keyspace = caller_id as KeyspaceId;

            if !capability::agent_has_cap(caller_id, CapType::StateWrite, keyspace) {
                crate::event::cap_denied(caller_id, CapType::StateWrite as u64, keyspace as u64);
                return Some(E_NO_CAP);
            }

            // stac/clac bracket the read from user buffer to satisfy SMAP.
            let value = unsafe {
                security::stac();
                let s = core::slice::from_raw_parts(a2 as *const u8, a3 as usize);
                security::clac();
                s
            };

            match state::state_put(keyspace, a1, value) {
                Ok(()) => E_OK,
                Err(e) => e,
            }
        }

        // ── 26: sys_state_tx_begin ────────────────────────────────────
        // a1 = keyspace_id (0 = own keyspace)
        // Creates a new transaction for atomic multi-key updates.
        SYS_STATE_TX_BEGIN => {
            let keyspace = if a1 == 0 {
                caller_id as KeyspaceId
            } else {
                a1 as KeyspaceId
            };

            if !capability::agent_has_cap(caller_id, CapType::StateWrite, keyspace) {
                crate::event::cap_denied(caller_id, CapType::StateWrite as u64, keyspace as u64);
                return Some(E_NO_CAP);
            }

            match state::tx_begin(caller_id as u16, keyspace) {
                Ok(tx_id) => tx_id as i64,
                Err(e) => e,
            }
        }

        // ── 27: sys_state_tx_commit ──────────────────────────────────
        // Commits all buffered mutations atomically and advances the
        // keyspace version.
        SYS_STATE_TX_COMMIT => match state::tx_commit(caller_id as u16) {
            Ok(()) => E_OK,
            Err(e) => e,
        },

        // ── 28: sys_state_snapshot ───────────────────────────────────
        // a1 = keyspace_id (0 = own keyspace)
        // Returns the current version number.
        SYS_STATE_SNAPSHOT => {
            let keyspace = if a1 == 0 {
                caller_id as KeyspaceId
            } else {
                a1 as KeyspaceId
            };

            if !capability::agent_has_cap(caller_id, CapType::StateRead, keyspace) {
                crate::event::cap_denied(caller_id, CapType::StateRead as u64, keyspace as u64);
                return Some(E_NO_CAP);
            }

            match state::get_version(keyspace) {
                Some(v) => v as i64,
                None => E_NOT_FOUND,
            }
        }

        // ── 29: sys_state_proof_get ──────────────────────────────────
        // a1 = keyspace_id (0 = own), a2 = key, a3 = version
        // Generates a historical inclusion/exclusion proof.
        // Returns 1 for inclusion, 0 for exclusion, negative on error.
        SYS_STATE_PROOF_GET => {
            let keyspace = if a1 == 0 {
                caller_id as KeyspaceId
            } else {
                a1 as KeyspaceId
            };

            if !capability::agent_has_cap(caller_id, CapType::StateRead, keyspace) {
                crate::event::cap_denied(caller_id, CapType::StateRead as u64, keyspace as u64);
                return Some(E_NO_CAP);
            }

            match crate::proof::generate_historical_proof(keyspace, a3 as u32, a2 as u16) {
                Some(hp) => {
                    if hp.inclusion {
                        1
                    } else {
                        0
                    }
                }
                None => E_NOT_FOUND,
            }
        }

        _ => return None,
    };

    Some(result)
}

#[inline(never)]
fn handle_memory_syscall(caller_id: u16, num: u64, a1: u64, a2: u64) -> Option<i64> {
    let result = match num {
        // ── 16: sys_mmap ─────────────────────────────────────────────────
        // a1 = num_pages
        SYS_MMAP => {
            let num_pages = a1 as u32;

            if num_pages == 0 {
                return Some(E_INVALID_ARG);
            }

            // Check memory quota
            let (memory_used, memory_quota) = match get_agent(caller_id) {
                Some(agent) => (agent.memory_used, agent.memory_quota),
                None => return Some(E_INVALID_ARG),
            };

            if memory_used + num_pages > memory_quota {
                return Some(E_QUOTA_EXCEEDED);
            }

            // Allocate frames
            let mut first_addr: u64 = 0;
            let mut allocated: u32 = 0;

            for i in 0..num_pages {
                match paging::alloc_frame() {
                    Some(addr) => {
                        if i == 0 {
                            first_addr = addr;
                        }
                        allocated += 1;
                    }
                    None => {
                        // Roll back any frames we already allocated
                        for j in 0..allocated {
                            paging::dealloc_frame(first_addr + (j as u64) * 4096);
                        }
                        return Some(E_QUOTA_EXCEEDED);
                    }
                }
            }

            // Update agent's memory usage
            if let Some(agent) = get_agent_mut(caller_id) {
                agent.memory_used += num_pages;
            }

            serial_println!(
                "[SYSCALL] Agent {} mmap {} pages at {:#x}",
                caller_id,
                num_pages,
                first_addr
            );

            first_addr as i64
        }

        // ── 17: sys_munmap ───────────────────────────────────────────────
        // a1 = virtual_address, a2 = num_pages
        SYS_MUNMAP => {
            let vaddr = a1;
            let num_pages = a2 as u32;

            if num_pages == 0 {
                return Some(E_INVALID_ARG);
            }

            // Deallocate frames
            for i in 0..num_pages {
                paging::dealloc_frame(vaddr + (i as u64) * 4096);
            }

            // Decrement agent's memory usage
            if let Some(agent) = get_agent_mut(caller_id) {
                agent.memory_used = agent.memory_used.saturating_sub(num_pages);
            }

            serial_println!(
                "[SYSCALL] Agent {} munmap {} pages at {:#x}",
                caller_id,
                num_pages,
                vaddr
            );

            E_OK
        }

        _ => return None,
    };

    Some(result)
}

#[inline(never)]
fn syscall_inner(num: u64, a1: u64, a2: u64, a3: u64, _a4: u64, _a5: u64, _a6: u64) -> i64 {
    let caller_id = sched::current();

    crate::metrics::increment_syscall_count();

    // Charge energy for the syscall (except for idle agent)
    if caller_id != IDLE_AGENT_ID {
        let cost = crate::cost::COSTS.syscall;
        if !crate::cost::charge(caller_id, cost) {
            if let Some(agent) = crate::agent::get_agent_mut(caller_id) {
                agent.status = crate::agent::AgentStatus::Suspended;
            }
            crate::event::energy_exhausted(caller_id);
            crate::sched::remove_from_run_queue(caller_id);
            crate::sched::schedule();
            return E_NO_BUDGET;
        }
        crate::cost::record_consumption(caller_id, cost);
    }

    // ── eBPF SyscallEntry hook ──
    // Skip SYS_YIELD for performance (idle agent calls it constantly)
    if num != SYS_YIELD {
        let entry_ctx = crate::ebpf::attach::SyscallContext {
            agent_id: caller_id,
            syscall_num: num,
            arg0: a1,
            arg1: a2,
            arg2: a3,
        };
        let entry_action = crate::ebpf::attach::run_at(
            crate::ebpf::attach::AttachPoint::SyscallEntry(num),
            &entry_ctx as *const crate::ebpf::attach::SyscallContext as u64,
        );
        if entry_action == crate::ebpf::types::Action::Deny {
            crate::event::cap_denied(caller_id, 0xFE, num); // 0xFE = eBPF syscall entry denial
            return E_NO_CAP;
        }
        if entry_action == crate::ebpf::types::Action::Log {
            crate::event::emit(caller_id, crate::event::EventType::EbpfPolicy, num, 0, 0);
        }
    }

    // ── LinuxCompat ABI routing ──────────────────────────────────────────
    // If this agent has a LinuxAgentState initialized, route to the Linux
    // compat dispatcher instead of the ATOS native dispatcher.
    if crate::linux_compat::state::get_state(caller_id).is_some() {
        return handle_linux_compat_syscall(caller_id, num, a1, a2, a3, _a4, _a5, _a6);
    }

    if let Some(result) = handle_mailbox_syscall(caller_id, num, a1, a2, a3, _a4) {
        return finish_native_syscall(caller_id, num, a1, result);
    }

    if let Some(result) = handle_state_syscall(caller_id, num, a1, a2, a3) {
        return finish_native_syscall(caller_id, num, a1, result);
    }

    if let Some(result) = handle_memory_syscall(caller_id, num, a1, a2) {
        return finish_native_syscall(caller_id, num, a1, result);
    }

    let result = match num {
        // ── 0: sys_yield ────────────────────────────────────────────────
        SYS_YIELD => {
            sched::yield_current();
            E_OK
        }

        // ── 1: sys_spawn ────────────────────────────────────────────────
        // a1 = entry point, a2 = energy budget, a3 = memory quota (pages)
        SYS_SPAWN => {
            // Check spawn capability
            if !capability::agent_try_cap(caller_id, CapType::AgentSpawn, 0) {
                crate::event::cap_denied(caller_id, CapType::AgentSpawn as u64, 0);
                return E_NO_CAP;
            }

            // ── eBPF AgentSpawn check ──
            let spawn_ctx = crate::ebpf::attach::SpawnContext {
                parent_id: caller_id,
                energy_quota: a2,
                mem_quota: a3 as u32,
            };
            let spawn_action = crate::ebpf::attach::run_at(
                crate::ebpf::attach::AttachPoint::AgentSpawn,
                &spawn_ctx as *const crate::ebpf::attach::SpawnContext as u64,
            );
            if spawn_action == crate::ebpf::types::Action::Deny {
                crate::event::cap_denied(caller_id, 0xFD, 0); // 0xFD = eBPF spawn denial
                return E_NO_CAP;
            }
            if spawn_action == crate::ebpf::types::Action::Log {
                crate::event::emit(caller_id, crate::event::EventType::EbpfPolicy, 0xFD, 0, 0);
            }

            let entry = a1;
            let energy_budget = a2;
            let mem_quota = a3 as u32;

            // Allocate a stack for the new agent
            let stack_top = sched::allocate_agent_stack();
            if stack_top == 0 {
                return E_QUOTA_EXCEEDED;
            }

            match create_agent(Some(caller_id), entry, stack_top, energy_budget, mem_quota) {
                Ok(new_id) => {
                    // Set cr3 to current page table so the new agent can run
                    if let Some(agent) = get_agent_mut(new_id) {
                        agent.context.cr3 = read_cr3_safe();
                    }
                    // Create mailbox and keyspace for the new agent
                    mailbox::create_mailbox(new_id as MailboxId, new_id).ok();
                    state::create_keyspace(new_id as u16).ok();
                    // Snapshot initial state root and creation tick for receipts
                    if let Some(agent) = get_agent_mut(new_id) {
                        let root32 = state::get_root(new_id as u16).unwrap_or([0u8; 32]);
                        agent.initial_state_root = root32;
                        agent.tick_created = crate::arch::x86_64::timer::get_ticks();
                    }
                    // Add to run queue
                    sched::enqueue(new_id);
                    crate::metrics::increment_agent_spawned();
                    crate::event::agent_created(new_id, caller_id);
                    new_id as i64
                }
                Err(e) => e,
            }
        }

        // ── 2: sys_exit ─────────────────────────────────────────────────
        SYS_EXIT => {
            let exit_code = a1;

            // Emit an execution receipt before terminating the agent
            let tick_now = crate::arch::x86_64::timer::get_ticks();
            let (energy_remaining, initial_root, tick_start) = match get_agent(caller_id) {
                Some(a) => (a.energy_budget, a.initial_state_root, a.tick_created),
                None => (0, [0u8; 32], 0u64),
            };
            // Compute final state root from agent's keyspace
            let mut final_root = [0u8; 32];
            if let Some(root32) = state::get_root(caller_id as u16) {
                final_root.copy_from_slice(&root32);
            }
            // Compute trace commitment from transcript
            let trace_commitment = compute_transcript_hash(caller_id, tick_start, tick_now);
            // Use the initial state root as input commitment and combine
            // the final state root with the exit code for the output commitment.
            let input_hash = initial_root;
            let mut output_preimage = [0u8; 40]; // 32 (final_root) + 8 (exit_code)
            output_preimage[..32].copy_from_slice(&final_root);
            output_preimage[32..40].copy_from_slice(&exit_code.to_le_bytes());
            let output_hash = crate::receipts::compute_commitment(&output_preimage);
            let receipt_idx = crate::receipts::emit_receipt_on_exit(
                caller_id,
                crate::receipts::RuntimeClassTag::ProofGradeWasm,
                energy_remaining,
                initial_root,
                final_root,
                tick_start,
                tick_now,
                input_hash,
                output_hash,
            );
            // Patch trace_commitment into the receipt
            if let Some(idx) = receipt_idx {
                crate::receipts::patch_trace_commitment(idx, trace_commitment);
            }

            terminate_agent(caller_id, AgentStatus::Exited);
            crate::metrics::increment_agent_exited();
            crate::event::agent_exited(caller_id, exit_code);
            sched::remove_from_run_queue(caller_id);
            sched::yield_current();
            E_OK // unreachable for the caller
        }

        // ── 5: sys_cap_query ────────────────────────────────────────────
        // a1 = cap_type, a2 = target
        // Returns 1 if the agent has the capability, 0 otherwise.
        SYS_CAP_QUERY => {
            let cap_type_raw = a1 as u8;
            let target = a2 as u16;

            // Convert raw u8 to CapType
            let cap_type = match cap_type_raw {
                0 => CapType::SendMailbox,
                1 => CapType::RecvMailbox,
                2 => CapType::EventEmit,
                3 => CapType::AgentSpawn,
                4 => CapType::StateRead,
                5 => CapType::StateWrite,
                6 => CapType::Network,
                7 => CapType::PolicyLoad,
                _ => return E_INVALID_ARG,
            };

            if capability::agent_has_cap(caller_id, cap_type, target) {
                1
            } else {
                0
            }
        }

        // ── 6: sys_cap_grant ────────────────────────────────────────────
        // a1 = target agent id, a2 = cap_type, a3 = cap_target
        SYS_CAP_GRANT => {
            let target_agent = a1 as AgentId;
            let cap_type_raw = a2 as u8;
            let cap_target = a3 as u16;

            let cap_type = match cap_type_raw {
                0 => CapType::SendMailbox,
                1 => CapType::RecvMailbox,
                2 => CapType::EventEmit,
                3 => CapType::AgentSpawn,
                4 => CapType::StateRead,
                5 => CapType::StateWrite,
                6 => CapType::Network,
                7 => CapType::PolicyLoad,
                _ => return E_INVALID_ARG,
            };

            let cap = Capability::new(cap_type, cap_target);
            match capability::grant_cap(caller_id, target_agent, cap) {
                Ok(()) => {
                    crate::event::cap_grant(caller_id, target_agent as u64, cap_type as u64);
                    E_OK
                }
                Err(e) => e,
            }
        }

        // ── 7: sys_event_emit ───────────────────────────────────────────
        // a1 = event arg0, a2 = event a1
        SYS_EVENT_EMIT => {
            if !capability::agent_try_cap(caller_id, CapType::EventEmit, 0) {
                crate::event::cap_denied(caller_id, CapType::EventEmit as u64, 0);
                return E_NO_CAP;
            }

            crate::event::emit(caller_id, crate::event::EventType::Custom, a1, a2, E_OK);
            E_OK
        }

        // ── 8: sys_energy_get ───────────────────────────────────────────
        SYS_ENERGY_GET => energy::get_remaining(caller_id) as i64,

        // ── 11: sys_cap_revoke ──────────────────────────────────────────
        // a1 = target agent id, a2 = cap_type, a3 = cap_target
        SYS_CAP_REVOKE => {
            let target_agent = a1 as AgentId;
            let cap_type_raw = a2 as u8;
            let cap_target = a3 as u16;

            let cap_type = match cap_type_raw {
                0 => CapType::SendMailbox,
                1 => CapType::RecvMailbox,
                2 => CapType::EventEmit,
                3 => CapType::AgentSpawn,
                4 => CapType::StateRead,
                5 => CapType::StateWrite,
                6 => CapType::Network,
                7 => CapType::PolicyLoad,
                _ => return E_INVALID_ARG,
            };

            match capability::revoke_cap(caller_id, target_agent, cap_type, cap_target) {
                Ok(()) => {
                    crate::event::cap_revoked(caller_id, target_agent as u64, cap_type as u64);
                    E_OK
                }
                Err(e) => e,
            }
        }

        // ── 14: sys_energy_grant ─────────────────────────────────────────
        // a1 = target agent id, a2 = amount
        SYS_ENERGY_GRANT => {
            let target_agent = a1 as AgentId;
            let amount = a2;

            // Verify target is a direct child
            if !crate::agent::is_child_of(target_agent, caller_id) {
                return E_INVALID_ARG;
            }

            match energy::grant(caller_id, target_agent, amount) {
                Ok(()) => {
                    crate::event::energy_granted(caller_id, target_agent, amount);

                    // If the child was Suspended and now has energy, move to Ready
                    if let Some(agent) = get_agent_mut(target_agent) {
                        if agent.status == AgentStatus::Suspended && agent.energy_budget > 0 {
                            serial_println!(
                                "[SYSCALL] Resuming suspended agent {} with {} energy",
                                target_agent,
                                agent.energy_budget
                            );
                            sched::enqueue(target_agent);
                        }
                    }

                    E_OK
                }
                Err(e) => e,
            }
        }

        // ── 15: sys_checkpoint ───────────────────────────────────────────
        SYS_CHECKPOINT => {
            if caller_id != ROOT_AGENT_ID {
                return E_NO_CAP;
            }

            serial_println!("[SYSCALL] Checkpoint triggered by root agent");
            let saved = crate::checkpoint::save_to_disk();
            crate::event::checkpoint_triggered(caller_id);
            if saved {
                E_OK
            } else {
                E_NOT_FOUND
            } // E_NOT_FOUND = no disk
        }

        // ── 22: sys_spawn_image ─────────────────────────────────────────
        // a1 = image_ptr, a2 = image_len
        // a3 = runtime_kind[7:0] | runtime_class[15:8]
        //      runtime_kind: 0=Native, 1=WASM
        //      runtime_class: 0=ProofGrade, 1=ReplayGrade, 2=BestEffort
        // a4 = energy_budget, a5 = mem_quota (pages)
        SYS_SPAWN_IMAGE => {
            // Check spawn capability
            if !capability::agent_try_cap(caller_id, CapType::AgentSpawn, 0) {
                crate::event::cap_denied(caller_id, CapType::AgentSpawn as u64, 0);
                return E_NO_CAP;
            }

            // ── eBPF AgentSpawn check ──
            let spawn_ctx = crate::ebpf::attach::SpawnContext {
                parent_id: caller_id,
                energy_quota: _a4,
                mem_quota: _a5 as u32,
            };
            let spawn_action = crate::ebpf::attach::run_at(
                crate::ebpf::attach::AttachPoint::AgentSpawn,
                &spawn_ctx as *const crate::ebpf::attach::SpawnContext as u64,
            );
            if spawn_action == crate::ebpf::types::Action::Deny {
                crate::event::cap_denied(caller_id, 0xFD, 0);
                return E_NO_CAP;
            }
            if spawn_action == crate::ebpf::types::Action::Log {
                crate::event::emit(caller_id, crate::event::EventType::EbpfPolicy, 0xFD, 0, 0);
            }

            let image_ptr = a1;
            let image_len = a2 as usize;
            let runtime_kind_raw = a3 & 0xFF;
            let runtime_class_raw = (a3 >> 8) & 0xFF;
            let energy_budget = _a4;
            let mem_quota = _a5 as u32;

            // Validate image length
            if image_len == 0 || image_len > 4 * 1024 * 1024 {
                return E_INVALID_ARG;
            }

            // Parse runtime kind
            let kind = match runtime_kind_raw {
                0 => RuntimeKind::Native,
                1 => RuntimeKind::Wasm,
                _ => return E_INVALID_ARG,
            };

            // Parse runtime class
            // runtime_class: 0=BestEffort (default), 1=ReplayGrade, 2=ProofGrade
            let runtime_class = match runtime_class_raw {
                0 => crate::wasm::types::RuntimeClass::BestEffort,
                1 => crate::wasm::types::RuntimeClass::ReplayGrade,
                2 => crate::wasm::types::RuntimeClass::ProofGrade,
                _ => return E_INVALID_ARG,
            };

            // Read image bytes from caller's address space
            let image = unsafe {
                security::stac();
                let s = core::slice::from_raw_parts(image_ptr as *const u8, image_len);
                security::clac();
                s
            };

            match crate::agent_loader::spawn_from_image_with_class(
                caller_id,
                image,
                kind,
                energy_budget,
                mem_quota,
                runtime_class,
            ) {
                Ok(new_id) => new_id as i64,
                Err(e) => e,
            }
        }

        // ── 20: sys_replay ──────────────────────────────────────────────
        // Root-only: enter replay mode (load checkpoint + deterministic scheduler)
        SYS_REPLAY => {
            if caller_id != ROOT_AGENT_ID {
                return E_NO_CAP;
            }

            serial_println!("[SYSCALL] Replay mode requested by root agent");
            match crate::replay::enter_replay() {
                Ok(()) => E_OK,
                Err(e) => e,
            }
        }

        // ── 23: sys_principal_query ─────────────────────────────────────
        // Returns the principal_id associated with this agent (derived from agent_id).
        SYS_PRINCIPAL_QUERY => {
            // Derive a principal ID from the agent ID: zero-fill with agent_id in first 2 bytes
            let mut principal_id = [0u8; 32];
            let id_bytes = caller_id.to_le_bytes();
            principal_id[0] = id_bytes[0];
            principal_id[1] = id_bytes[1];

            // If a2 is a valid buffer pointer, write the principal_id there
            if a1 != 0 && a2 >= 32 {
                unsafe {
                    security::stac();
                    core::ptr::copy_nonoverlapping(principal_id.as_ptr(), a1 as *mut u8, 32);
                    security::clac();
                }
            }

            E_OK
        }

        // ── 24: sys_lease_verify (removed — distributed feature)
        SYS_LEASE_VERIFY => E_INVALID_ARG,

        // ── 25: sys_revocation_check (removed — authority feature)
        SYS_REVOCATION_CHECK => E_INVALID_ARG,

        // ── 30: sys_receipt_emit ────────────────────────────────────────
        // Manually emit an execution receipt for the calling agent.
        // Returns the receipt store index on success, or E_QUOTA_EXCEEDED if full.
        SYS_RECEIPT_EMIT => match crate::receipts::emit_receipt_for_agent(caller_id) {
            Some(idx) => idx as i64,
            None => E_QUOTA_EXCEEDED,
        },

        // ── 31: sys_package_verify ──────────────────────────────────────
        // Verify package manifest signature and code hash.
        // a1 = pointer to package data, a2 = length
        // Returns 0 on success (valid), negative on failure.
        SYS_PACKAGE_VERIFY => {
            if a2 == 0 {
                E_INVALID_ARG
            } else {
                match crate::package::parse_package(unsafe {
                    core::slice::from_raw_parts(a1 as *const u8, a2 as usize)
                }) {
                    Some(pkg) => {
                        if pkg.manifest.verify_code_hash(&pkg.code) {
                            serial_println!(
                                "[SYSCALL] Package '{}' verified OK",
                                pkg.manifest.name_str()
                            );
                            0
                        } else {
                            serial_println!(
                                "[SYSCALL] Package '{}' code hash mismatch",
                                pkg.manifest.name_str()
                            );
                            E_INVALID_ARG
                        }
                    }
                    None => {
                        serial_println!("[SYSCALL] Package parse failed");
                        E_INVALID_ARG
                    }
                }
            }
        }

        // ── 32: sys_package_install ─────────────────────────────────────
        // Install package from data in agent memory.
        // a1 = pointer to package data, a2 = length
        // Returns registry index on success, negative on failure.
        SYS_PACKAGE_INSTALL => {
            if a2 == 0 {
                E_INVALID_ARG
            } else {
                match crate::package::parse_package(unsafe {
                    core::slice::from_raw_parts(a1 as *const u8, a2 as usize)
                }) {
                    Some(pkg) => {
                        if !pkg.manifest.verify_code_hash(&pkg.code) {
                            serial_println!(
                                "[SYSCALL] Package install rejected: code hash mismatch"
                            );
                            E_INVALID_ARG
                        } else {
                            let name = pkg.manifest.name_str();
                            serial_println!("[SYSCALL] Installing package '{}'", name);
                            match crate::package::install_package(pkg.manifest) {
                                Some(idx) => idx as i64,
                                None => E_QUOTA_EXCEEDED,
                            }
                        }
                    }
                    None => {
                        serial_println!("[SYSCALL] Package install: parse failed");
                        E_INVALID_ARG
                    }
                }
            }
        }

        // ── 33: sys_node_attest (removed — distributed feature)
        SYS_NODE_ATTEST => E_INVALID_ARG,

        // ── 34: sys_agent_migrate (removed — distributed feature)
        SYS_AGENT_MIGRATE => E_INVALID_ARG,

        // ── 35: sys_placement_hint (removed — distributed feature)
        SYS_PLACEMENT_HINT => E_INVALID_ARG,

        // ── 36: sys_quote_request ──────────────────────────────────────
        // Return estimated energy cost for a workload.
        // a1 = workload type (0=wasm, 1=native, 2=migrate)
        // a2 = estimated size/duration
        // Returns: estimated energy units
        SYS_QUOTE_REQUEST => {
            let workload_type = a1;
            let size_hint = a2;
            let estimate = match workload_type {
                0 => size_hint * 10,   // WASM: 10 energy per estimated instruction
                1 => size_hint * 5,    // Native: 5 energy per unit
                2 => 1000 + size_hint, // Migration: 1000 base + size
                _ => 0,
            };
            estimate as i64
        }

        // ── 37: sys_proof_generate ──────────────────────────────────────
        // Generate a proof bundle for the most recent receipt.
        // Returns: proof bundle index or -1 on failure
        SYS_PROOF_GENERATE => {
            // Generate a proof bundle for the most recent receipt
            let count = crate::receipts::receipt_count();
            if count == 0 {
                -1
            } else {
                let idx = count - 1;
                if let Some(receipt) = crate::receipts::get_receipt(idx) {
                    let proof = crate::receipts::ProofBundle::from_receipt(receipt);
                    crate::receipts::store_proof_bundle(proof);
                    (crate::receipts::proof_count() - 1) as i64
                } else {
                    -1
                }
            }
        }

        // ── 38: sys_send_remote (removed — distributed feature)
        SYS_SEND_REMOTE => E_INVALID_ARG,

        // ── 39: sys_contract_call ──────────────────────────────────────
        // a1 = pointer to 32-byte contract_id, a2 = selector (u32),
        // a3 = pointer to input data, a4 = input length, a5 = energy_limit
        SYS_CONTRACT_CALL => {
            let input_len = _a4 as usize;
            let energy_limit = _a5;

            if input_len > 236 {
                return E_INVALID_ARG;
            }

            // Read the 32-byte contract_id from user memory.
            let contract_id: [u8; 32] = unsafe {
                security::stac();
                let ptr = a1 as *const [u8; 32];
                let id = core::ptr::read(ptr);
                security::clac();
                id
            };

            // Read the input data from user memory.
            let input_slice = unsafe {
                security::stac();
                let s = core::slice::from_raw_parts(a3 as *const u8, input_len);
                security::clac();
                s
            };

            match crate::contract_call::call_contract(
                caller_id as u16,
                &contract_id,
                a2 as u32,
                input_slice,
                energy_limit,
            ) {
                Ok(_) => E_OK,
                Err(e) => e,
            }
        }

        _ => {
            serial_println!("[SYSCALL] Unknown syscall {} from agent {}", num, caller_id);
            E_INVALID_ARG
        }
    };

    finish_native_syscall(caller_id, num, a1, result)
}

/// Entry point called from syscall_entry.asm when a ring 3 agent executes
/// the SYSCALL instruction. This is just a thin wrapper around the existing
/// syscall dispatcher.
#[no_mangle]
pub extern "C" fn syscall_handler(
    num: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
) -> i64 {
    syscall_with_a6(num, a1, a2, a3, a4, a5, a6)
}

/// Read CR3 safely. Returns 0 if inline assembly is not available.
/// In Stage-1 all agents share the kernel page table.
fn read_cr3_safe() -> u64 {
    let cr3: u64;
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
    }
    cr3
}
