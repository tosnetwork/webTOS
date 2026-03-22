//! AOS Syscall Dispatcher
//!
//! Provides the syscall entry point for agents. In Stage-1, agents call
//! `syscall::syscall()` directly as a Rust function call (no privilege
//! transition). Later stages will use the x86_64 SYSCALL/SYSRET mechanism.
//!
//! Every syscall is gated by capability checks and charged against the
//! calling agent's energy budget.
//!
//! Syscall numbers follow Yellow Paper §14.2.

use crate::serial_println;
use crate::agent::*;
use crate::capability::{self, CapType, Capability};
use crate::energy;
use crate::sched;
use crate::mailbox;
use crate::state;

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
pub fn syscall(num: u64, a1: u64, a2: u64, a3: u64, _a4: u64, _a5: u64) -> i64 {
    let caller_id = sched::current();

    // Charge energy for the syscall (except for idle agent)
    if caller_id != IDLE_AGENT_ID {
        if !energy::charge_syscall(caller_id) {
            // Energy exhausted
            crate::event::energy_exhausted(caller_id);
            return E_NO_BUDGET;
        }
    }

    match num {
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
                    // Add to run queue
                    sched::enqueue(new_id);
                    crate::event::agent_created(new_id, caller_id);
                    new_id as i64
                }
                Err(e) => e,
            }
        }

        // ── 2: sys_exit ─────────────────────────────────────────────────
        SYS_EXIT => {
            let exit_code = a1;
            terminate_agent(caller_id, AgentStatus::Exited);
            crate::event::agent_exited(caller_id, exit_code);
            sched::remove_from_run_queue(caller_id);
            sched::yield_current();
            E_OK // unreachable for the caller
        }

        // ── 3: sys_send ─────────────────────────────────────────────────
        // a1 = target mailbox, a2 = payload ptr, a3 = payload len
        SYS_SEND => {
            let target_mailbox = a1 as MailboxId;
            let payload_len = a3 as usize;

            if payload_len > MAX_MESSAGE_PAYLOAD {
                return E_PAYLOAD_TOO_LARGE;
            }

            // Safety: the payload pointer comes from the calling agent's stack,
            // which is valid memory in Stage-1 (all agents share the kernel address space).
            let payload = unsafe {
                core::slice::from_raw_parts(a2 as *const u8, payload_len)
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

            match mailbox::recv_message(caller_id, mailbox_id) {
                Ok(msg) => {
                    let copy_len = (msg.len as usize).min(buf_len);
                    if copy_len > 0 {
                        // Safety: the buffer pointer comes from the calling agent's stack.
                        // Use ptr::copy instead of copy_from_slice to avoid alignment requirements.
                        unsafe {
                            core::ptr::copy(
                                msg.payload.as_ptr(),
                                a2 as *mut u8,
                                copy_len,
                            );
                        }
                    }
                    copy_len as i64
                }
                Err(_) => 0, // no message available or error
            }
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
        // a1 = event arg0, a2 = event arg1
        SYS_EVENT_EMIT => {
            if !capability::agent_try_cap(caller_id, CapType::EventEmit, 0) {
                crate::event::cap_denied(caller_id, CapType::EventEmit as u64, 0);
                return E_NO_CAP;
            }

            crate::event::emit(
                caller_id,
                crate::event::EventType::Custom,
                a1,
                a2,
                E_OK,
            );
            E_OK
        }

        // ── 8: sys_energy_get ───────────────────────────────────────────
        SYS_ENERGY_GET => {
            energy::get_remaining(caller_id) as i64
        }

        // ── 9: sys_state_get ────────────────────────────────────────────
        // a1 = key, a2 = buffer ptr, a3 = buffer len
        SYS_STATE_GET => {
            let keyspace = caller_id as KeyspaceId;

            if !capability::agent_has_cap(caller_id, CapType::StateRead, keyspace) {
                crate::event::cap_denied(caller_id, CapType::StateRead as u64, keyspace as u64);
                return E_NO_CAP;
            }

            match state::state_get(keyspace, a1) {
                Some((data, len)) => {
                    let copy_len = len.min(a3 as usize);
                    if copy_len > 0 {
                        unsafe {
                            let buf = core::slice::from_raw_parts_mut(a2 as *mut u8, copy_len);
                            buf.copy_from_slice(&data[..copy_len]);
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
                return E_NO_CAP;
            }

            let value = unsafe {
                core::slice::from_raw_parts(a2 as *const u8, a3 as usize)
            };

            match state::state_put(keyspace, a1, value) {
                Ok(()) => E_OK,
                Err(e) => e,
            }
        }

        _ => {
            serial_println!(
                "[SYSCALL] Unknown syscall {} from agent {}",
                num, caller_id
            );
            E_INVALID_ARG
        }
    }
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
