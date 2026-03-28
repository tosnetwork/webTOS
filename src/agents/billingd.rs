//! ATOS billingd — Billing and Settlement Service  (Stage 9)
//!
//! Consumes execution receipts and produces billing records. Tracks
//! energy balances per principal and can generate invoices for billing
//! periods.
//!
//! Commands:
//!   0x01 SUBMIT_RECEIPT: accept receipt for billing
//!   0x02 GET_BALANCE:    return energy balance for a principal
//!   0x03 GET_INVOICE:    generate invoice for a time period

use crate::serial_println;

/// Billing and settlement service entry point.
pub extern "C" fn billingd_main() -> ! {
    serial_println!("[BILLINGD] Billing service started");
    // Commands:
    // 0x01 SUBMIT_RECEIPT: accept receipt for billing
    // 0x02 GET_BALANCE: return energy balance for a principal
    // 0x03 GET_INVOICE: generate invoice for a time period
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
