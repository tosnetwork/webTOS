//! ATOS billingd — Billing and Settlement Service (Stage 9)
//!
//! Consumes execution receipts and produces billing records. Tracks
//! energy balances per principal and can generate billing summaries.
//!
//! Protocol (mailbox message payload):
//!   SUBMIT_RECEIPT  (0x01): [op, receipt_index:u32 LE] — accept receipt for billing
//!   GET_BALANCE     (0x02): [op, principal_lo:u64 LE] — return energy consumed by principal
//!   BILLING_SUMMARY (0x03): [op] — print all billing records to serial

use crate::serial_println;
use crate::agent::*;

const OP_SUBMIT_RECEIPT: u8 = 0x01;
const OP_GET_BALANCE: u8 = 0x02;
const OP_BILLING_SUMMARY: u8 = 0x03;

/// Billingd agent — assigned during init as agent slot 24.
const BILLINGD_ID: AgentId = 24;
const BILLINGD_MAILBOX: MailboxId = 24;

/// Maximum number of billing records (per principal).
const MAX_BILLING_RECORDS: usize = 64;

/// Billing record: maps principal_hash_lo to total energy consumed.
#[derive(Clone, Copy)]
struct BillingRecord {
    principal_hash_lo: u64,  // lower 8 bytes of principal_id for lookup
    energy_consumed: u64,
    receipt_count: u32,      // number of receipts billed
    active: bool,
}

static mut BILLING_RECORDS: [BillingRecord; MAX_BILLING_RECORDS] = [BillingRecord {
    principal_hash_lo: 0,
    energy_consumed: 0,
    receipt_count: 0,
    active: false,
}; MAX_BILLING_RECORDS];
static mut BILLING_COUNT: usize = 0;

/// Total energy billed across all principals.
static mut TOTAL_ENERGY_BILLED: u64 = 0;
/// Total receipts processed.
static mut TOTAL_RECEIPTS_PROCESSED: u64 = 0;

/// Billing and settlement service entry point.
pub extern "C" fn billingd_main() -> ! {
    serial_println!("[BILLINGD] Billing service started (capacity: {} records)", MAX_BILLING_RECORDS);

    loop {
        match crate::mailbox::recv_message(BILLINGD_ID, BILLINGD_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_SUBMIT_RECEIPT => handle_submit_receipt(&msg.payload, msg_len, msg.sender_id),
                        OP_GET_BALANCE => handle_get_balance(&msg.payload, msg_len, msg.sender_id),
                        OP_BILLING_SUMMARY => handle_billing_summary(msg.sender_id),
                        _ => {
                            serial_println!("[BILLINGD] Unknown opcode: {:#x}", op);
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

/// Handle SUBMIT_RECEIPT: accept a receipt for billing.
/// Format: [op=0x01, receipt_index:u32 LE]
///
/// Loads the receipt, extracts principal_id and energy_used,
/// and aggregates into the billing table by principal.
fn handle_submit_receipt(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 5 {
        serial_println!("[BILLINGD] SUBMIT_RECEIPT: payload too short");
        return;
    }

    let index = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]) as usize;

    match crate::receipts::get_receipt(index) {
        Some(receipt) => {
            // Extract principal hash (lower 8 bytes for lookup key)
            let principal_lo = u64::from_le_bytes([
                receipt.principal_id[0], receipt.principal_id[1],
                receipt.principal_id[2], receipt.principal_id[3],
                receipt.principal_id[4], receipt.principal_id[5],
                receipt.principal_id[6], receipt.principal_id[7],
            ]);
            let energy = receipt.energy_used;

            // Aggregate into billing records
            add_billing(principal_lo, energy);

            unsafe {
                TOTAL_RECEIPTS_PROCESSED += 1;
                TOTAL_ENERGY_BILLED += energy;
            }

            serial_println!(
                "[BILLINGD] Receipt {} billed: principal={:#x} energy={} (from agent {})",
                index, principal_lo, energy, sender_id
            );

            // Respond with success (0x00)
            let response = [0x00u8];
            let _ = crate::mailbox::send_message(BILLINGD_ID, sender_id as MailboxId, &response);
        }
        None => {
            serial_println!("[BILLINGD] SUBMIT_RECEIPT: receipt {} not found", index);
            // Respond with error (0xFF)
            let response = [0xFFu8];
            let _ = crate::mailbox::send_message(BILLINGD_ID, sender_id as MailboxId, &response);
        }
    }
}

/// Handle GET_BALANCE: return total energy consumed by a principal.
/// Format: [op=0x02, principal_lo:u64 LE]
fn handle_get_balance(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 9 {
        serial_println!("[BILLINGD] GET_BALANCE: payload too short");
        return;
    }

    let principal_lo = u64::from_le_bytes([
        payload[1], payload[2], payload[3], payload[4],
        payload[5], payload[6], payload[7], payload[8],
    ]);

    let balance = lookup_balance(principal_lo);

    serial_println!(
        "[BILLINGD] Balance query: principal={:#x} energy={} (from agent {})",
        principal_lo, balance, sender_id
    );

    let response = balance.to_le_bytes();
    let _ = crate::mailbox::send_message(BILLINGD_ID, sender_id as MailboxId, &response);
}

/// Handle BILLING_SUMMARY: print all billing records to serial.
fn handle_billing_summary(sender_id: AgentId) {
    serial_println!("[BILLINGD] === Billing Summary (requested by agent {}) ===", sender_id);

    unsafe {
        for i in 0..BILLING_COUNT {
            if BILLING_RECORDS[i].active {
                serial_println!(
                    "[BILLINGD]   principal={:#018x} energy={} receipts={}",
                    BILLING_RECORDS[i].principal_hash_lo,
                    BILLING_RECORDS[i].energy_consumed,
                    BILLING_RECORDS[i].receipt_count,
                );
            }
        }

        serial_println!(
            "[BILLINGD] === End (total billed: {} energy, {} receipts) ===",
            TOTAL_ENERGY_BILLED, TOTAL_RECEIPTS_PROCESSED
        );
    }
}

/// Add energy to the billing record for a principal (aggregate by principal_hash_lo).
fn add_billing(principal_lo: u64, energy: u64) {
    unsafe {
        // Look for existing record
        for i in 0..BILLING_COUNT {
            if BILLING_RECORDS[i].active && BILLING_RECORDS[i].principal_hash_lo == principal_lo {
                BILLING_RECORDS[i].energy_consumed += energy;
                BILLING_RECORDS[i].receipt_count += 1;
                return;
            }
        }

        // Create new record
        if BILLING_COUNT < MAX_BILLING_RECORDS {
            BILLING_RECORDS[BILLING_COUNT] = BillingRecord {
                principal_hash_lo: principal_lo,
                energy_consumed: energy,
                receipt_count: 1,
                active: true,
            };
            BILLING_COUNT += 1;
        } else {
            serial_println!("[BILLINGD] Billing table full, cannot track new principal");
        }
    }
}

/// Look up the total energy balance for a principal.
fn lookup_balance(principal_lo: u64) -> u64 {
    unsafe {
        for i in 0..BILLING_COUNT {
            if BILLING_RECORDS[i].active && BILLING_RECORDS[i].principal_hash_lo == principal_lo {
                return BILLING_RECORDS[i].energy_consumed;
            }
        }
        0
    }
}
