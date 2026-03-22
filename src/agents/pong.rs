//! AOS Pong Agent
//!
//! Test agent that receives "ping" messages from the ping agent and
//! replies with "pong". Demonstrates the responder side of mailbox IPC,
//! capability enforcement (needs CAP_SEND_MAILBOX:2), and cooperative scheduling.

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

/// Pong agent entry point.
///
/// Loops: receive a message from own mailbox (3), send "pong" reply
/// to ping agent's mailbox (2), yield.
pub extern "C" fn pong_entry() -> ! {
    serial_println!("[PONG] Pong agent started (id=3)");

    let my_mailbox: u64 = 3;
    let ping_mailbox: u64 = 2;

    let mut recv_buf = [0u8; MAX_MESSAGE_PAYLOAD];

    loop {
        // Wait for a message
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
                "[PONG] Received: {:?}",
                core::str::from_utf8(received).unwrap_or("<invalid>")
            );

            // Reply with pong
            let reply = b"pong";
            let result = syscall::syscall(
                SYS_SEND,
                ping_mailbox,
                reply.as_ptr() as u64,
                reply.len() as u64,
                0,
                0,
            );
            serial_println!("[PONG] Sent pong to mailbox {}, result={}", ping_mailbox, result);
        }

        // Yield to let other agents run
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
