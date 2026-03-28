//! ATOS authd — Authority Service Agent (Yellow Paper Stage 5)
//!
//! System agent that manages principal revocation and capability lease lifecycle.
//!
//! Protocol (mailbox message payload):
//!   REVOKE:      [op=0x01, principal_id: [u8; 32]]
//!   STATUS:      [op=0x02, principal_id: [u8; 32]]
//!   LEASE_RENEW: [op=0x03, cap_index: u16, new_expiry_ticks: u64]

use crate::serial_println;
use crate::agent::*;
use crate::principal::PrincipalId;

const OP_REVOKE: u8 = 0x01;
const OP_STATUS: u8 = 0x02;
const OP_LEASE_RENEW: u8 = 0x03;

// ─── Principal revocation list ──────────────────────────────────────────────

const MAX_REVOKED_PRINCIPALS: usize = 64;

static mut REVOKED_PRINCIPALS: [PrincipalId; MAX_REVOKED_PRINCIPALS] = [[0u8; 32]; MAX_REVOKED_PRINCIPALS];
static mut REVOKED_COUNT: usize = 0;

/// Check if a principal has been revoked.
///
/// This function is pub so that `syscall.rs` can call it for admission control.
pub fn is_principal_revoked(principal_id: &PrincipalId) -> bool {
    unsafe {
        for i in 0..REVOKED_COUNT {
            if REVOKED_PRINCIPALS[i] == *principal_id {
                return true;
            }
        }
        false
    }
}

/// Add a principal to the revocation list.
fn revoke_principal(principal_id: PrincipalId) {
    unsafe {
        if REVOKED_COUNT < MAX_REVOKED_PRINCIPALS {
            REVOKED_PRINCIPALS[REVOKED_COUNT] = principal_id;
            REVOKED_COUNT += 1;
        }
    }
}

/// Authd agent ID — assigned during init as agent slot 12.
const AUTHD_ID: AgentId = 12;
const AUTHD_MAILBOX: MailboxId = 12;

pub extern "C" fn authd_entry() -> ! {
    serial_println!("[AUTHD] Authority service started");

    loop {
        match crate::mailbox::recv_message(AUTHD_ID, AUTHD_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_REVOKE => handle_revoke(&msg.payload, msg_len, msg.sender_id),
                        OP_STATUS => handle_status(&msg.payload, msg_len, msg.sender_id),
                        OP_LEASE_RENEW => handle_lease_renew(&msg.payload, msg_len, msg.sender_id),
                        _ => {
                            serial_println!("[AUTHD] Unknown opcode: {}", op);
                        }
                    }
                }
            }
            Err(_) => {} // no message available
        }

        // Yield to other agents
        crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}

/// Handle REVOKE request: revoke a principal by ID.
/// Format: [op=0x01, principal_id: [u8; 32]]
fn handle_revoke(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 33 {
        serial_println!("[AUTHD] REVOKE: payload too short");
        return;
    }

    // Only root agent can revoke principals
    if sender_id != ROOT_AGENT_ID {
        serial_println!("[AUTHD] REVOKE denied: agent {} is not root", sender_id);
        crate::event::auth_deny(sender_id, OP_REVOKE as u64, 0);
        return;
    }

    // Extract principal_id (bytes 1..33)
    let mut principal_id = [0u8; 32];
    principal_id.copy_from_slice(&payload[1..33]);

    revoke_principal(principal_id);

    serial_println!("[AUTHD] Principal revoked: {:02x}{:02x}{:02x}{:02x}...",
        principal_id[0], principal_id[1], principal_id[2], principal_id[3]);
    crate::event::auth_revoke(sender_id, 0, OP_REVOKE as u64);
}

/// Handle STATUS query: check if a principal is active.
/// Format: [op=0x02, principal_id: [u8; 32]]
fn handle_status(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 33 {
        serial_println!("[AUTHD] STATUS: payload too short");
        return;
    }

    let mut principal_id = [0u8; 32];
    principal_id.copy_from_slice(&payload[1..33]);

    let revoked = is_principal_revoked(&principal_id);
    let status_str = if revoked { "REVOKED" } else { "ACTIVE" };

    serial_println!("[AUTHD] STATUS query from agent {} for principal {:02x}{:02x}...: {}",
        sender_id, principal_id[0], principal_id[1], status_str);

    // Send response back (1 byte: 0 = active, 1 = revoked)
    let response = [if revoked { 1u8 } else { 0u8 }; 1];
    let _ = crate::mailbox::send_message(AUTHD_ID, sender_id as MailboxId, &response);
}

/// Handle LEASE_RENEW request: extend capability lease expiry.
/// Format: [op=0x03, agent_id: u16, cap_index: u16, new_expiry_ticks: u64]
fn handle_lease_renew(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 13 {
        serial_println!("[AUTHD] LEASE_RENEW: payload too short");
        return;
    }

    let target_agent = u16::from_le_bytes([payload[1], payload[2]]) as AgentId;
    let cap_index = u16::from_le_bytes([payload[3], payload[4]]) as usize;
    let new_expiry = u64::from_le_bytes([
        payload[5], payload[6], payload[7], payload[8],
        payload[9], payload[10], payload[11], payload[12],
    ]);

    // Only root or the agent itself can renew leases
    if sender_id != ROOT_AGENT_ID && sender_id != target_agent {
        serial_println!("[AUTHD] LEASE_RENEW denied: agent {} cannot renew for agent {}",
            sender_id, target_agent);
        crate::event::auth_deny(sender_id, OP_LEASE_RENEW as u64, target_agent as u64);
        return;
    }

    // Update the capability's expiry
    if let Some(agent) = crate::agent::get_agent_mut(target_agent) {
        if cap_index < agent.cap_count {
            if let Some(ref mut cap) = agent.capabilities[cap_index] {
                cap.expiry_ticks = new_expiry;
                serial_println!("[AUTHD] Lease renewed: agent={} cap={} new_expiry={}",
                    target_agent, cap_index, new_expiry);
                crate::event::auth_renew(sender_id, target_agent as u64, new_expiry);
                return;
            }
        }
    }

    serial_println!("[AUTHD] LEASE_RENEW failed: agent={} cap_index={}", target_agent, cap_index);
}
