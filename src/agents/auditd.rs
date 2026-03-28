//! ATOS auditd — Authority Audit Log Collection Agent (Stage 5)
//!
//! Collects AuthGrant/AuthDelegate/AuthRevoke/AuthRenew/AuthDeny events
//! and maintains an in-memory audit log queryable via mailbox.
//!
//! Protocol (mailbox message payload):
//!   LOG_EVENT    (0x01): [op, tick:u64, agent_id:u16, event_type:u8, target_id:u16, cap_type:u8]
//!   QUERY_COUNT  (0x02): [op] -> returns [count: u32 LE]
//!   QUERY_ENTRY  (0x03): [op, index: u32 LE] -> returns entry fields
//!   DUMP_ALL     (0x04): [op] -> prints all entries to serial

use crate::serial_println;
use crate::agent::*;

const OP_LOG_EVENT: u8 = 0x01;
const OP_QUERY_COUNT: u8 = 0x02;
const OP_QUERY_ENTRY: u8 = 0x03;
const OP_DUMP_ALL: u8 = 0x04;

/// Auditd agent — assigned during init as agent slot 21.
const AUDITD_ID: AgentId = 21;
const AUDITD_MAILBOX: MailboxId = 21;

/// Fixed-size audit log entry.
#[derive(Clone, Copy)]
pub struct AuditEntry {
    pub tick: u64,
    pub agent_id: u16,
    pub event_type: u8, // 0=Grant, 1=Delegate, 2=Revoke, 3=Renew, 4=Deny, 5=LeaseExpired
    pub target_id: u16,
    pub capability_type: u8,
}

const AUDIT_LOG_CAPACITY: usize = 256;

static mut AUDIT_LOG: [AuditEntry; AUDIT_LOG_CAPACITY] = [AuditEntry {
    tick: 0,
    agent_id: 0,
    event_type: 0,
    target_id: 0,
    capability_type: 0,
}; AUDIT_LOG_CAPACITY];
static mut AUDIT_COUNT: usize = 0;

/// Record an audit event (callable directly from kernel code).
pub fn record_audit_event(tick: u64, agent_id: u16, event_type: u8, target_id: u16, cap_type: u8) {
    unsafe {
        if AUDIT_COUNT < AUDIT_LOG_CAPACITY {
            AUDIT_LOG[AUDIT_COUNT] = AuditEntry {
                tick,
                agent_id,
                event_type,
                target_id,
                capability_type: cap_type,
            };
            AUDIT_COUNT += 1;
        }
    }
}

/// Return the number of recorded audit events.
pub fn audit_count() -> usize {
    unsafe { AUDIT_COUNT }
}

/// Retrieve an audit entry by index.
pub fn get_audit_entry(idx: usize) -> Option<AuditEntry> {
    unsafe {
        if idx < AUDIT_COUNT {
            Some(AUDIT_LOG[idx])
        } else {
            None
        }
    }
}

/// Authority audit service entry point.
pub fn auditd_main() {
    serial_println!("[AUDITD] Authority audit service started (log capacity: {})", AUDIT_LOG_CAPACITY);

    loop {
        match crate::mailbox::recv_message(AUDITD_ID, AUDITD_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_LOG_EVENT => handle_log_event(&msg.payload, msg_len),
                        OP_QUERY_COUNT => handle_query_count(msg.sender_id),
                        OP_QUERY_ENTRY => handle_query_entry(&msg.payload, msg_len, msg.sender_id),
                        OP_DUMP_ALL => handle_dump_all(),
                        _ => {
                            serial_println!("[AUDITD] Unknown opcode: {:#x}", op);
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

/// Handle LOG_EVENT: record an audit entry.
/// Format: [op=0x01, tick:u64, agent_id:u16, event_type:u8, target_id:u16, cap_type:u8]
/// Total: 1 + 8 + 2 + 1 + 2 + 1 = 15 bytes
fn handle_log_event(payload: &[u8], msg_len: usize) {
    if msg_len < 15 {
        serial_println!("[AUDITD] LOG_EVENT: payload too short ({} < 15)", msg_len);
        return;
    }

    let tick = u64::from_le_bytes([
        payload[1], payload[2], payload[3], payload[4],
        payload[5], payload[6], payload[7], payload[8],
    ]);
    let agent_id = u16::from_le_bytes([payload[9], payload[10]]);
    let event_type = payload[11];
    let target_id = u16::from_le_bytes([payload[12], payload[13]]);
    let cap_type = payload[14];

    record_audit_event(tick, agent_id, event_type, target_id, cap_type);

    let count = unsafe { AUDIT_COUNT };
    serial_println!(
        "[AUDITD] Logged event: tick={} agent={} type={} target={} cap={} (total: {})",
        tick, agent_id, event_type, target_id, cap_type, count
    );
}

/// Handle QUERY_COUNT: return number of audit entries.
fn handle_query_count(sender_id: AgentId) {
    let count = unsafe { AUDIT_COUNT as u32 };
    let response = count.to_le_bytes();
    let _ = crate::mailbox::send_message(AUDITD_ID, sender_id as MailboxId, &response);
}

/// Handle QUERY_ENTRY: return a specific audit entry by index.
/// Format: [op=0x03, index: u32 LE]
fn handle_query_entry(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 5 {
        serial_println!("[AUDITD] QUERY_ENTRY: payload too short");
        return;
    }

    let idx = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;

    match get_audit_entry(idx) {
        Some(entry) => {
            // Response: [tick:u64, agent_id:u16, event_type:u8, target_id:u16, cap_type:u8] = 14 bytes
            let mut response = [0u8; 14];
            response[0..8].copy_from_slice(&entry.tick.to_le_bytes());
            response[8..10].copy_from_slice(&entry.agent_id.to_le_bytes());
            response[10] = entry.event_type;
            response[11..13].copy_from_slice(&entry.target_id.to_le_bytes());
            response[13] = entry.capability_type;
            let _ = crate::mailbox::send_message(AUDITD_ID, sender_id as MailboxId, &response);
        }
        None => {
            // Not found: respond with single 0xFF byte
            let response = [0xFFu8];
            let _ = crate::mailbox::send_message(AUDITD_ID, sender_id as MailboxId, &response);
        }
    }
}

/// Handle DUMP_ALL: print all audit entries to serial.
fn handle_dump_all() {
    let count = unsafe { AUDIT_COUNT };
    serial_println!("[AUDITD] === Audit Log Dump ({} entries) ===", count);

    for i in 0..count {
        if let Some(entry) = get_audit_entry(i) {
            let type_str = match entry.event_type {
                0 => "Grant",
                1 => "Delegate",
                2 => "Revoke",
                3 => "Renew",
                4 => "Deny",
                5 => "LeaseExpired",
                _ => "Unknown",
            };
            serial_println!(
                "[AUDITD]   [{}] tick={} agent={} {} target={} cap={}",
                i, entry.tick, entry.agent_id, type_str, entry.target_id, entry.capability_type
            );
        }
    }

    serial_println!("[AUDITD] === End Audit Log ===");
}
