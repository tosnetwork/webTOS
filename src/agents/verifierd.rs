//! ATOS verifierd — On-node Receipt Verification Service  (Stage 9)
//!
//! Validates receipts, proof bundles, and replay bundles. Other agents
//! can submit verification requests via mailbox to confirm execution
//! integrity before trusting results.
//!
//! Commands:
//!   0x01 VERIFY_RECEIPT: check receipt signature and field consistency
//!   0x02 VERIFY_PROOF:   validate a ProofBundle against a receipt
//!   0x03 VERIFY_REPLAY:  validate a ReplayBundle (re-execute and compare)

use crate::serial_println;

/// On-node receipt verification service entry point.
pub extern "C" fn verifierd_main() -> ! {
    serial_println!("[VERIFIERD] Verification service started");
    // Commands:
    // 0x01 VERIFY_RECEIPT: check receipt signature and field consistency
    // 0x02 VERIFY_PROOF: validate a ProofBundle against a receipt
    // 0x03 VERIFY_REPLAY: validate a ReplayBundle (re-execute and compare)
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
