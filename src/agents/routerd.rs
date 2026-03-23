//! AOS routerd — Remote Mailbox Routing Agent
//!
//! Routes mailbox messages between AOS nodes. When an agent sends to a
//! remote mailbox (identified by a node prefix), routerd serializes the
//! message and sends it via the kernel UDP transport.
//!
//! Protocol: [msg_type: u8, src_node: u32, src_mailbox: u16, dst_mailbox: u16, payload_len: u16, payload: [u8]]

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

const MSG_MAILBOX_FORWARD: u8 = 0x01;
const MSG_NODE_DISCOVER: u8 = 0x02;
#[allow(dead_code)]
const MSG_NODE_ACK: u8 = 0x03;

/// Node ID for this AOS instance
static mut LOCAL_NODE_ID: u32 = 0;

pub extern "C" fn routerd_entry() -> ! {
    // Generate a simple node ID from MAC address
    unsafe {
        let mac = crate::net::get_mac();
        LOCAL_NODE_ID = u32::from_le_bytes([mac[2], mac[3], mac[4], mac[5]]);
    }

    serial_println!("[ROUTERD] Remote mailbox router started (node_id={:#x})", unsafe { LOCAL_NODE_ID });

    let my_mailbox: u64 = 10; // routerd's mailbox
    let mut recv_buf = [0u8; MAX_MESSAGE_PAYLOAD];

    loop {
        // Check for local messages (forwarding requests from other agents)
        let len = syscall::syscall(
            SYS_RECV_TIMEOUT,
            my_mailbox,
            recv_buf.as_mut_ptr() as u64,
            recv_buf.len() as u64,
            1, // timeout: 1 tick (non-blocking-ish)
            0,
        );

        if len > 0 {
            let msg_len = len as usize;
            if msg_len >= 1 {
                match recv_buf[0] {
                    MSG_MAILBOX_FORWARD => {
                        // Forward a mailbox message to a remote node
                        if msg_len >= 7 {
                            let dst_node = u32::from_le_bytes([recv_buf[1], recv_buf[2], recv_buf[3], recv_buf[4]]);
                            let dst_mailbox = u16::from_le_bytes([recv_buf[5], recv_buf[6]]);

                            serial_println!("[ROUTERD] Forwarding {} bytes to node {:#x} mailbox {}",
                                msg_len - 7, dst_node, dst_mailbox);

                            // Send via UDP
                            let src = crate::net::UdpEndpoint { ip: [10, 0, 2, 15], port: 7777 };
                            let dst = crate::net::UdpEndpoint { ip: [10, 0, 2, 2], port: 7777 };
                            let _ = crate::net::send_udp(&src, &dst, &recv_buf[..msg_len]);
                        }
                    }
                    MSG_NODE_DISCOVER => {
                        serial_println!("[ROUTERD] Node discovery request received");
                    }
                    _ => {}
                }
            }
        }

        // Check for incoming UDP packets (messages from remote nodes)
        let mut udp_buf = [0u8; 1400];
        if let Some((src, udp_len)) = crate::net::recv_udp(&mut udp_buf) {
            serial_println!("[ROUTERD] Received {} bytes from {:?}:{}", udp_len, src.ip, src.port);
        }

        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
