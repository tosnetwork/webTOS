//! ATOS quotad — Cost Estimation Service (Stage 9)
//!
//! Before launching expensive workloads, agents can request a quote for
//! the estimated energy cost. quotad responds with energy estimates based
//! on workload parameters.
//!
//! Protocol (mailbox message payload):
//!   QUOTE_WASM    (0x01): [op, code_size:u32] -> [energy:u64 LE]
//!   QUOTE_NATIVE  (0x02): [op, estimated_instructions:u64] -> [energy:u64 LE]
//!   QUOTE_MIGRATE (0x03): [op, checkpoint_size:u32] -> [energy:u64 LE]

use crate::serial_println;
use crate::agent::*;

const OP_QUOTE_WASM: u8 = 0x01;
const OP_QUOTE_NATIVE: u8 = 0x02;
const OP_QUOTE_MIGRATE: u8 = 0x03;

/// Quotad agent — assigned during init as agent slot 22.
const QUOTAD_ID: AgentId = 22;
const QUOTAD_MAILBOX: MailboxId = 22;

/// Base cost for any WASM execution quote.
const WASM_BASE_COST: u64 = 500;
/// Cost per byte of WASM code (fuel per instruction estimate).
const WASM_PER_BYTE_COST: u64 = 10;

/// Base cost for native execution.
const NATIVE_BASE_COST: u64 = 200;
/// Cost per estimated instruction for native execution.
const NATIVE_PER_INSTRUCTION_COST: u64 = 5;

/// Base cost for migration.
const MIGRATE_BASE_COST: u64 = 1000;
/// Cost per byte of checkpoint data for migration.
const MIGRATE_PER_BYTE_COST: u64 = 2;

/// Total quotes issued since startup.
static mut TOTAL_QUOTES: u64 = 0;

/// Cost estimation service entry point.
pub extern "C" fn quotad_main() -> ! {
    serial_println!("[QUOTAD] Cost estimation service started");

    loop {
        match crate::mailbox::recv_message(QUOTAD_ID, QUOTAD_MAILBOX) {
            Ok(msg) => {
                let msg_len = msg.len as usize;
                if msg_len >= 1 {
                    let op = msg.payload[0];
                    match op {
                        OP_QUOTE_WASM => handle_quote_wasm(&msg.payload, msg_len, msg.sender_id),
                        OP_QUOTE_NATIVE => handle_quote_native(&msg.payload, msg_len, msg.sender_id),
                        OP_QUOTE_MIGRATE => handle_quote_migrate(&msg.payload, msg_len, msg.sender_id),
                        _ => {
                            serial_println!("[QUOTAD] Unknown opcode: {:#x}", op);
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

/// Handle QUOTE_WASM: estimate energy for WASM execution.
/// Format: [op=0x01, code_size:u32 LE]
fn handle_quote_wasm(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 5 {
        serial_println!("[QUOTAD] QUOTE_WASM: payload too short");
        return;
    }

    let code_size = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let energy = WASM_BASE_COST + (code_size as u64) * WASM_PER_BYTE_COST;

    unsafe { TOTAL_QUOTES += 1; }
    serial_println!("[QUOTAD] WASM quote: code_size={} -> energy={} (for agent {})",
        code_size, energy, sender_id);

    let response = energy.to_le_bytes();
    let _ = crate::mailbox::send_message(QUOTAD_ID, sender_id as MailboxId, &response);
}

/// Handle QUOTE_NATIVE: estimate energy for native execution.
/// Format: [op=0x02, estimated_instructions:u64 LE]
fn handle_quote_native(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 9 {
        serial_println!("[QUOTAD] QUOTE_NATIVE: payload too short");
        return;
    }

    let instructions = u64::from_le_bytes([
        payload[1], payload[2], payload[3], payload[4],
        payload[5], payload[6], payload[7], payload[8],
    ]);
    let energy = NATIVE_BASE_COST + instructions * NATIVE_PER_INSTRUCTION_COST;

    unsafe { TOTAL_QUOTES += 1; }
    serial_println!("[QUOTAD] Native quote: instructions={} -> energy={} (for agent {})",
        instructions, energy, sender_id);

    let response = energy.to_le_bytes();
    let _ = crate::mailbox::send_message(QUOTAD_ID, sender_id as MailboxId, &response);
}

/// Handle QUOTE_MIGRATE: estimate migration cost.
/// Format: [op=0x03, checkpoint_size:u32 LE]
fn handle_quote_migrate(payload: &[u8], msg_len: usize, sender_id: AgentId) {
    if msg_len < 5 {
        serial_println!("[QUOTAD] QUOTE_MIGRATE: payload too short");
        return;
    }

    let checkpoint_size = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let energy = MIGRATE_BASE_COST + (checkpoint_size as u64) * MIGRATE_PER_BYTE_COST;

    unsafe { TOTAL_QUOTES += 1; }
    serial_println!("[QUOTAD] Migration quote: checkpoint_size={} -> energy={} (for agent {})",
        checkpoint_size, energy, sender_id);

    let response = energy.to_le_bytes();
    let _ = crate::mailbox::send_message(QUOTAD_ID, sender_id as MailboxId, &response);
}
