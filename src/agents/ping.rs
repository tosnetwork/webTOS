//! AOS Ping Agent
//!
//! Test agent that sends "ping" messages to the pong agent's mailbox
//! and waits for "pong" replies. Demonstrates mailbox IPC, capability
//! enforcement (needs CAP_SEND_MAILBOX:3), and cooperative scheduling.

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

/// Ping agent entry point.
///
/// Sends an initial "ping" message to the pong agent (mailbox 3),
/// then loops: receive a reply from own mailbox (2), send another ping, yield.
pub extern "C" fn ping_entry() -> ! {
    serial_println!("[PING] Ping agent started (id=2)");

    let my_mailbox: u64 = 2;
    let pong_mailbox: u64 = 3;

    // Send initial ping message
    let msg = b"ping";
    let result = syscall::syscall(
        SYS_SEND,
        pong_mailbox,            // target mailbox
        msg.as_ptr() as u64,     // payload pointer
        msg.len() as u64,        // payload length
        0,
        0,
    );
    serial_println!("[PING] Sent ping to mailbox {}, result={}", pong_mailbox, result);

    // Main loop: wait for reply, send another ping
    let mut recv_buf = [0u8; MAX_MESSAGE_PAYLOAD];
    loop {
        let len = syscall::syscall(
            SYS_RECV,
            my_mailbox,
            recv_buf.as_mut_ptr() as u64,
            recv_buf.len() as u64,
            0,
            0,
        );

        if len > 0 {
            let received = &recv_buf[..len as usize];
            serial_println!(
                "[PING] Received reply: {:?}",
                core::str::from_utf8(received).unwrap_or("<invalid>")
            );

            // Send another ping
            let result = syscall::syscall(
                SYS_SEND,
                pong_mailbox,
                msg.as_ptr() as u64,
                msg.len() as u64,
                0,
                0,
            );
            serial_println!("[PING] Sent ping, result={}", result);
        }

        // Yield between messages to let pong (and others) run
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
