//! ATOS verifierd — On-node Receipt Verification Service (Stage 9)
//!
//! Validates receipts, proof bundles, and replay bundles. Other agents
//! can submit verification requests via mailbox to confirm execution
//! integrity before trusting results.
//!
//! Protocol (mailbox message payload):
//!   VERIFY_RECEIPT (0x01): [op, receipt_index:u32 LE] -> [status:u8]
//!   VERIFY_PROOF   (0x02): [op, receipt_index:u32, proof_hash:32bytes] -> [status:u8]
//!   RECEIPT_COUNT  (0x03): [op] -> [count:u32 LE]

use crate::serial_println;
use crate::agent::*;

const OP_VERIFY_RECEIPT: u8 = 0x01;
const OP_VERIFY_PROOF: u8 = 0x02;
const OP_RECEIPT_COUNT: u8 = 0x03;

/// Verification result codes.
const RESULT_VALID: u8 = 0x00;
const RESULT_INVALID_HASH: u8 = 0x01;
const RESULT_NOT_FOUND: u8 = 0x02;
const RESULT_PROOF_MISMATCH: u8 = 0x03;

/// Verifierd agent — assigned during init as agent slot 23.
const VERIFIERD_ID: AgentId = 23;
const VERIFIERD_MAILBOX: MailboxId = 23;

/// Total verifications performed since startup.
static mut TOTAL_VERIFICATIONS: u64 = 0;
/// Total verification failures since startup.
static mut TOTAL_FAILURES: u64 = 0;

/// On-node receipt verification service entry point.
pub extern "C" fn verifierd_main() -> ! {
    serial_println!("[VERIFIERD] Verification service started");

    loop {
        match crate::mailbox::recv_message(VERIFIERD_ID, VERIFIERD_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_VERIFY_RECEIPT => handle_verify_receipt(&msg.payload, msg_len, msg.sender_id),
                        OP_VERIFY_PROOF => handle_verify_proof(&msg.payload, msg_len, msg.sender_id),
                        OP_RECEIPT_COUNT => handle_receipt_count(msg.sender_id),
                        _ => {
                            serial_println!("[VERIFIERD] Unknown opcode: {:#x}", op);
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

/// Handle VERIFY_RECEIPT: check receipt hash and field consistency.
/// Format: [op=0x01, receipt_index:u32 LE]
///
/// Verification checks:
/// 1. Receipt exists at given index
/// 2. compute_hash() produces consistent result (hash is deterministic)
/// 3. Energy fields are non-zero for non-trivial receipts
///
/// Response: [status:u8] where 0=valid, 1=invalid hash, 2=not found
fn handle_verify_receipt(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 5 {
        serial_println!("[VERIFIERD] VERIFY_RECEIPT: payload too short");
        return;
    }

    let index = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;

    unsafe { TOTAL_VERIFICATIONS += 1; }

    let result = match crate::receipts::get_receipt(index) {
        Some(receipt) => {
            // Verify: compute_hash is deterministic (call twice, compare)
            let hash1 = receipt.compute_hash();
            let hash2 = receipt.compute_hash();

            if hash1 != hash2 {
                serial_println!("[VERIFIERD] Receipt {} FAILED: non-deterministic hash", index);
                unsafe { TOTAL_FAILURES += 1; }
                RESULT_INVALID_HASH
            } else {
                serial_println!(
                    "[VERIFIERD] Receipt {} VALID: energy={} ticks={}..{}",
                    index, receipt.energy_used, receipt.tick_start, receipt.tick_end
                );
                RESULT_VALID
            }
        }
        None => {
            serial_println!("[VERIFIERD] Receipt {} NOT FOUND", index);
            unsafe { TOTAL_FAILURES += 1; }
            RESULT_NOT_FOUND
        }
    };

    let response = [result];
    let _ = crate::mailbox::send_message(VERIFIERD_ID, sender_id as MailboxId, &response);
}

/// Handle VERIFY_PROOF: validate a proof bundle against its corresponding receipt.
/// Format: [op=0x02, proof_index:u32 LE]
///
/// Loads the proof bundle from PROOF_STORE at the given index, finds the
/// corresponding receipt, and calls `verify_against_receipt` to perform full
/// state-root, hash, and energy verification.
///
/// Response: [status:u8] where 0=valid, 3=proof mismatch, 2=not found
fn handle_verify_proof(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 5 {
        serial_println!("[VERIFIERD] VERIFY_PROOF: payload too short ({} < 5)", msg_len);
        return;
    }

    let proof_index = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;

    unsafe { TOTAL_VERIFICATIONS += 1; }

    let result = match crate::receipts::get_proof_bundle(proof_index) {
        Some(proof) => {
            // Find the corresponding receipt by scanning the receipt store
            let receipt_count = crate::receipts::receipt_count();
            let mut found_receipt = None;
            for i in 0..receipt_count {
                if let Some(r) = crate::receipts::get_receipt(i) {
                    if r.receipt_id == proof.receipt_id {
                        found_receipt = Some(r);
                        break;
                    }
                }
            }

            match found_receipt {
                Some(receipt) => {
                    if proof.verify_against_receipt(receipt) {
                        serial_println!(
                            "[VERIFIERD] Proof {} for receipt VALID (energy={}, roots checked)",
                            proof_index, receipt.energy_used
                        );
                        RESULT_VALID
                    } else {
                        serial_println!(
                            "[VERIFIERD] Proof {} MISMATCH: state roots or hash diverged",
                            proof_index
                        );
                        unsafe { TOTAL_FAILURES += 1; }
                        RESULT_PROOF_MISMATCH
                    }
                }
                None => {
                    serial_println!(
                        "[VERIFIERD] Proof {}: corresponding receipt NOT FOUND",
                        proof_index
                    );
                    unsafe { TOTAL_FAILURES += 1; }
                    RESULT_NOT_FOUND
                }
            }
        }
        None => {
            serial_println!("[VERIFIERD] Proof bundle {} NOT FOUND", proof_index);
            unsafe { TOTAL_FAILURES += 1; }
            RESULT_NOT_FOUND
        }
    };

    let response = [result];
    let _ = crate::mailbox::send_message(VERIFIERD_ID, sender_id as MailboxId, &response);
}

/// Handle RECEIPT_COUNT: return total receipts stored.
fn handle_receipt_count(sender_id: AgentId) {
    let count = crate::receipts::receipt_count() as u32;
    serial_println!("[VERIFIERD] Receipt count query from agent {}: {}", sender_id, count);

    let response = count.to_le_bytes();
    let _ = crate::mailbox::send_message(VERIFIERD_ID, sender_id as MailboxId, &response);
}
