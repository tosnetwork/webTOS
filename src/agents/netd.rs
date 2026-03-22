//! AOS netd — Network Broker Agent
//!
//! System agent that brokers all network access. Agents send HTTP-like
//! requests via mailbox; netd validates, logs, and (when a network driver
//! is available) performs the request.
//!
//! Protocol (mailbox payload):
//!   Request:  [op=0x01, method: u8, url_len: u16, url: [u8], body_len: u16, body: [u8]]
//!   Response: [status: u8, response_code: u16, body_len: u16, body: [u8]]
//!
//! Methods: 0x01=GET, 0x02=POST, 0x03=PUT, 0x04=DELETE
//!
//! Without a network driver, netd returns a stub 503 (Service Unavailable).

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

const OP_REQUEST: u8 = 0x01;
const METHOD_GET: u8 = 0x01;
const METHOD_POST: u8 = 0x02;

pub extern "C" fn netd_entry() -> ! {
    serial_println!("[NETD] Network broker started (stub mode — no network driver)");

    let my_mailbox: u64 = 9; // netd's mailbox (agent 9)
    let mut recv_buf = [0u8; MAX_MESSAGE_PAYLOAD];

    loop {
        let len = syscall::syscall(
            SYS_RECV, my_mailbox,
            recv_buf.as_mut_ptr() as u64,
            recv_buf.len() as u64,
            0, 0,
        );

        if len > 0 {
            let msg_len = len as usize;

            if msg_len >= 1 && recv_buf[0] == OP_REQUEST {
                if msg_len >= 4 {
                    let method = recv_buf[1];
                    let url_len = u16::from_le_bytes([recv_buf[2], recv_buf[3]]) as usize;

                    let method_str = match method {
                        METHOD_GET => "GET",
                        METHOD_POST => "POST",
                        0x03 => "PUT",
                        0x04 => "DELETE",
                        _ => "UNKNOWN",
                    };

                    if msg_len >= 4 + url_len {
                        let url = &recv_buf[4..4 + url_len];
                        let url_str = core::str::from_utf8(url).unwrap_or("<invalid>");

                        serial_println!("[NETD] Request: {} {} (stub — no network driver)",
                            method_str, url_str);

                        // Emit audit event for network request
                        crate::event::emit(
                            crate::sched::current(),
                            crate::event::EventType::Custom,
                            method as u64,
                            url_len as u64,
                            503, // Service Unavailable
                        );

                        // In a real implementation:
                        // 1. Check eBPF policy filter
                        // 2. Perform actual HTTP request via virtio-net
                        // 3. Return response to requesting agent
                        // For now, just log and continue
                    }
                }
            }
        }

        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
