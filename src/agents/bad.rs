//! AOS Bad Agent (Demo 2: Capability Denial)
//!
//! This agent deliberately attempts to send a message to a mailbox it
//! does NOT have CAP_SEND_MAILBOX for. The kernel must deny the request,
//! emit a CAP_DENIED audit event, and return an error code.

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

/// Bad agent entry point.
///
/// Attempts to send to mailbox 1 (root's mailbox) without holding
/// CAP_SEND_MAILBOX:1. The kernel should deny this with E_NO_CAP.
pub extern "C" fn bad_entry() -> ! {
    serial_println!("[BAD] Bad agent started - will attempt unauthorized send");

    let unauthorized_mailbox: u64 = 1; // root's mailbox, no cap for this
    let msg = b"hack";

    let result = syscall::syscall(
        SYS_SEND,
        unauthorized_mailbox,
        msg.as_ptr() as u64,
        msg.len() as u64,
        0,
        0,
    );

    serial_println!(
        "[BAD] Unauthorized send result: {} (expected {})",
        result, E_NO_CAP
    );

    if result == E_NO_CAP {
        serial_println!("[BAD] PASS: capability denial enforced correctly");
    } else {
        serial_println!("[BAD] FAIL: expected E_NO_CAP, got {}", result);
    }

    // Exit cleanly after the test
    syscall::syscall(SYS_EXIT, 0, 0, 0, 0, 0);

    // Unreachable
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
