//! ATOS quotad — Cost Estimation Service  (Stage 9)
//!
//! Before launching expensive workloads, agents can request a quote
//! for the estimated energy cost. quotad listens on its well-known
//! mailbox for quote requests and responds with energy estimates.
//!
//! Commands:
//!   0x01 QUOTE_WASM:    estimate energy for WASM execution (based on code size + fuel)
//!   0x02 QUOTE_NATIVE:  estimate energy for native execution
//!   0x03 QUOTE_MIGRATE: estimate cost of agent migration

use crate::serial_println;

/// Cost estimation service entry point.
pub extern "C" fn quotad_main() -> ! {
    serial_println!("[QUOTAD] Cost estimation service started");
    // Listen for quote requests on mailbox
    // Commands:
    // 0x01 QUOTE_WASM: estimate energy for WASM execution (based on code size + fuel)
    // 0x02 QUOTE_NATIVE: estimate energy for native execution
    // 0x03 QUOTE_MIGRATE: estimate cost of agent migration
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
