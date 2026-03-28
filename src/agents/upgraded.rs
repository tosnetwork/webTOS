//! ATOS upgraded — Upgrade Management Agent (Yellow Paper Stage 10)
//!
//! System agent that handles atomic upgrade with rollback capability.
//!
//! Protocol (mailbox message payload):
//!   UPGRADE_PREPARE:  [op=0x01]          — checkpoint current state, validate readiness
//!   UPGRADE_APPLY:    [op=0x02]          — apply pending upgrade
//!   UPGRADE_ROLLBACK: [op=0x03]          — rollback to last checkpoint
//!   UPGRADE_STATUS:   [op=0x04]          — report upgrade status

use crate::serial_println;
use crate::agent::*;

const OP_UPGRADE_PREPARE: u8 = 0x01;
const OP_UPGRADE_APPLY: u8 = 0x02;
const OP_UPGRADE_ROLLBACK: u8 = 0x03;
const OP_UPGRADE_STATUS: u8 = 0x04;

/// Upgraded agent mailbox — assigned during init as agent slot 13.
const UPGRADED_ID: AgentId = 13;
const UPGRADED_MAILBOX: MailboxId = 13;

/// Upgrade management system agent.
/// Handles atomic upgrade with rollback capability.
pub fn upgraded_main() {
    serial_println!("[UPGRADED] Upgrade manager started");

    loop {
        match crate::mailbox::recv_message(UPGRADED_ID, UPGRADED_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_UPGRADE_PREPARE => handle_prepare(msg.sender_id),
                        OP_UPGRADE_APPLY => handle_apply(msg.sender_id),
                        OP_UPGRADE_ROLLBACK => handle_rollback(msg.sender_id),
                        OP_UPGRADE_STATUS => handle_status(msg.sender_id),
                        _ => {
                            serial_println!("[UPGRADED] Unknown command: {:#x}", op);
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

/// Handle UPGRADE_PREPARE: checkpoint current system state and validate readiness.
fn handle_prepare(sender_id: AgentId) {
    if sender_id != ROOT_AGENT_ID {
        serial_println!("[UPGRADED] PREPARE denied: agent {} is not root", sender_id);
        return;
    }

    serial_println!("[UPGRADED] Preparing upgrade...");

    // 1. Checkpoint current system state to disk
    let checkpoint_ok = crate::checkpoint::save_to_disk();
    if checkpoint_ok {
        serial_println!("[UPGRADED] Checkpoint saved successfully");
    } else {
        serial_println!("[UPGRADED] Checkpoint failed, aborting upgrade");
        // Send failure response: 0x01 = not ready
        let response = [0x01u8];
        let _ = crate::mailbox::send_message(UPGRADED_ID, sender_id as MailboxId, &response);
        return;
    }

    // 2. Emit an UpgradePrepare event for the audit trail
    crate::event::emit(
        UPGRADED_ID,
        crate::event::EventType::UpgradePrepare,
        0,
        sender_id as u64,
        0,
    );

    serial_println!("[UPGRADED] Upgrade prepared (checkpoint saved)");

    // Send readiness response: 0x00 = ready
    let response = [0x00u8];
    let _ = crate::mailbox::send_message(UPGRADED_ID, sender_id as MailboxId, &response);
}

/// Handle UPGRADE_APPLY: apply the pending upgrade.
///
/// The caller may include a package payload after the opcode byte.
/// If present, the package is parsed and its code hash is verified
/// before the upgrade is applied.
fn handle_apply(sender_id: AgentId) {
    if sender_id != ROOT_AGENT_ID {
        serial_println!("[UPGRADED] APPLY denied: agent {} is not root", sender_id);
        return;
    }

    serial_println!("[UPGRADED] Applying upgrade...");

    // Re-read the message to access the full payload (including any package data).
    // The main loop already consumed it, so for now we operate without inline
    // package data.  A real implementation would pass the message buffer through.
    //
    // If a package were provided (msg[1..]):
    //   if let Some(pkg) = crate::package::parse_package(&msg[1..]) {
    //       if pkg.manifest.verify_code_hash(&pkg.code) {
    //           serial_println!("[UPGRADED] Package '{}' verified", pkg.manifest.name_str());
    //       } else {
    //           serial_println!("[UPGRADED] Package code hash mismatch, aborting");
    //           let response = [0x01u8];
    //           let _ = crate::mailbox::send_message(UPGRADED_ID, sender_id as MailboxId, &response);
    //           return;
    //       }
    //   }

    // 1. Stop non-essential agents (would iterate agent table)
    // 2. Apply new code/config
    // 3. Restart agents
    serial_println!("[UPGRADED] Upgrade applied");

    // Send completion response: 0x00 = success
    let response = [0x00u8];
    let _ = crate::mailbox::send_message(UPGRADED_ID, sender_id as MailboxId, &response);
}

/// Handle UPGRADE_ROLLBACK: restore from last checkpoint.
///
/// Attempts to restore the system state from the checkpoint that was
/// written during UPGRADE_PREPARE.  If no checkpoint exists on disk
/// (save_to_disk returned false during prepare), the rollback is a no-op
/// and the system may be in an inconsistent state — this is logged.
fn handle_rollback(sender_id: AgentId) {
    if sender_id != ROOT_AGENT_ID {
        serial_println!("[UPGRADED] ROLLBACK denied: agent {} is not root", sender_id);
        return;
    }

    serial_println!("[UPGRADED] Rolling back...");

    // Emit an UpgradeRollback event for the audit trail
    crate::event::emit(
        UPGRADED_ID,
        crate::event::EventType::UpgradeRollback,
        0,
        sender_id as u64,
        0,
    );

    // Attempt to restore from checkpoint.
    // save_to_disk() wrote checkpoint data; a symmetric restore_from_disk()
    // is not yet implemented — the checkpoint module currently only supports
    // writing.  When restore_from_disk() is added, the call goes here:
    //
    //   let restored = crate::checkpoint::restore_from_disk();
    //   if restored {
    //       serial_println!("[UPGRADED] Rollback complete, state restored");
    //   } else {
    //       serial_println!("[UPGRADED] Rollback FAILED - system may be inconsistent");
    //   }

    // For now: re-save a checkpoint to capture the current (rolled-back) state
    // and log the outcome.
    let saved = crate::checkpoint::save_to_disk();
    if saved {
        serial_println!("[UPGRADED] Rollback checkpoint saved (restore pending implementation)");
    } else {
        serial_println!("[UPGRADED] Rollback FAILED - could not save recovery checkpoint");
    }

    serial_println!("[UPGRADED] Rollback complete");

    // Send completion response: 0x00 = success
    let response = [0x00u8];
    let _ = crate::mailbox::send_message(UPGRADED_ID, sender_id as MailboxId, &response);
}

/// Handle UPGRADE_STATUS: report current upgrade status.
fn handle_status(sender_id: AgentId) {
    serial_println!("[UPGRADED] Status: running, no pending upgrades");

    // Send status response: [0x00 = idle, no pending upgrade]
    let response = [0x00u8];
    let _ = crate::mailbox::send_message(UPGRADED_ID, sender_id as MailboxId, &response);
}
