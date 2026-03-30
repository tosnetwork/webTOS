//! ATOS compactd — State Compaction and Garbage Collection (Stage 6)
//!
//! Periodically checks keyspace version counts and trims old history.
//! Also responds to on-demand compaction requests via mailbox.
//!
//! Protocol (mailbox message payload):
//!   COMPACT_NOW   (0x01): trigger immediate compaction scan
//!   COMPACT_STATUS(0x02): return compaction statistics

use crate::serial_println;
use crate::agent::*;

const OP_COMPACT_NOW: u8 = 0x01;
const OP_COMPACT_STATUS: u8 = 0x02;

/// Compactd agent — assigned during init as agent slot 18.
const COMPACTD_ID: AgentId = 18;
const COMPACTD_MAILBOX: MailboxId = 18;

/// Compaction interval: check every 500 scheduling ticks.
const COMPACT_INTERVAL: u64 = 500;

/// History entries to keep after compaction.
const HISTORY_KEEP: u8 = 8;
/// Trigger compaction when history exceeds this threshold.
const HISTORY_THRESHOLD: u8 = 12;

/// Total keyspaces compacted since startup.
static mut TOTAL_COMPACTED: u64 = 0;
/// Total compaction passes since startup.
static mut TOTAL_PASSES: u64 = 0;

/// State compaction and garbage collection agent.
pub extern "C" fn compactd_main() -> ! {
    serial_println!("[COMPACTD] State compaction service started (interval: {} ticks, threshold: {} entries)",
        COMPACT_INTERVAL, HISTORY_THRESHOLD);

    let mut tick_counter: u64 = 0;

    loop {
        tick_counter += 1;

        // Periodic compaction scan
        if tick_counter % COMPACT_INTERVAL == 0 {
            let compacted = compact_keyspaces();
            unsafe { TOTAL_PASSES += 1; }
            if compacted > 0 {
                unsafe { TOTAL_COMPACTED += compacted as u64; }
                serial_println!("[COMPACTD] Compacted {} keyspace(s) (pass #{})",
                    compacted, unsafe { TOTAL_PASSES });
            }
        }

        // Check mailbox for on-demand requests
        match crate::mailbox::recv_message(COMPACTD_ID, COMPACTD_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_COMPACT_NOW => handle_compact_now(msg.sender_id),
                        OP_COMPACT_STATUS => handle_compact_status(msg.sender_id),
                        _ => {
                            serial_println!("[COMPACTD] Unknown opcode: {:#x}", op);
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

/// Handle COMPACT_NOW: trigger immediate compaction and respond with count.
fn handle_compact_now(sender_id: AgentId) {
    serial_println!("[COMPACTD] On-demand compaction requested by agent {}", sender_id);
    let compacted = compact_keyspaces();
    unsafe {
        TOTAL_PASSES += 1;
        TOTAL_COMPACTED += compacted as u64;
    }
    serial_println!("[COMPACTD] On-demand compaction done: {} keyspace(s)", compacted);

    // Respond with compacted count as u32 LE
    let response = (compacted as u32).to_le_bytes();
    let _ = crate::mailbox::send_message(COMPACTD_ID, sender_id as MailboxId, &response);
}

/// Handle COMPACT_STATUS: return compaction statistics.
fn handle_compact_status(sender_id: AgentId) {
    let (passes, total) = unsafe { (TOTAL_PASSES, TOTAL_COMPACTED) };
    serial_println!("[COMPACTD] Status: {} passes, {} total keyspaces compacted", passes, total);

    // Response: [passes: u64 LE, total_compacted: u64 LE] = 16 bytes
    let mut response = [0u8; 16];
    response[0..8].copy_from_slice(&passes.to_le_bytes());
    response[8..16].copy_from_slice(&total.to_le_bytes());
    let _ = crate::mailbox::send_message(COMPACTD_ID, sender_id as MailboxId, &response);
}

/// Scan all keyspaces and compact those with excessive root history.
///
/// For each keyspace with root_history_count > HISTORY_THRESHOLD,
/// trim the root_history ring buffer down to HISTORY_KEEP entries.
fn compact_keyspaces() -> u32 {
    let mut compacted: u32 = 0;

    for ks_id in 0..MAX_AGENTS {
        if crate::state::get_version(ks_id as u16).is_some() {
            if crate::state::compact_keyspace_history(ks_id as u16, HISTORY_KEEP) {
                serial_println!("[COMPACTD] Keyspace {} history trimmed to {} entries",
                    ks_id, HISTORY_KEEP);
                compacted += 1;
            }
        }
    }

    compacted
}
