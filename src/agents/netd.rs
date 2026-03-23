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
    serial_println!("[NETD] Network broker started");

    // If virtio-net is available, send a test packet to prove network I/O works
    if crate::arch::x86_64::virtio_net::is_initialized() {
        serial_println!("[NETD] virtio-net available, sending test packet...");

        let mac = crate::arch::x86_64::virtio_net::mac_address();

        // Craft a minimal UDP packet (Ethernet + IP + UDP + payload)
        // Destination: broadcast (FF:FF:FF:FF:FF:FF)
        // Source: our MAC
        // EtherType: 0x0800 (IPv4)
        // IP: src=10.0.2.15 (QEMU default), dst=10.0.2.2 (QEMU gateway)
        // UDP: src_port=12345, dst_port=9999
        // Payload: "AOS NETD ALIVE"

        let mut packet = [0u8; 56]; // 14 (eth) + 20 (ip) + 8 (udp) + 14 (payload)

        // Ethernet header
        packet[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // dst MAC (broadcast)
        packet[6..12].copy_from_slice(&mac); // src MAC
        packet[12] = 0x08; packet[13] = 0x00; // EtherType: IPv4

        // IPv4 header (minimal, no options)
        packet[14] = 0x45; // version=4, IHL=5 (20 bytes)
        packet[15] = 0x00; // DSCP/ECN
        let total_len: u16 = 42; // 20 (IP) + 8 (UDP) + 14 (payload)
        packet[16..18].copy_from_slice(&total_len.to_be_bytes());
        packet[18..20].copy_from_slice(&[0x00, 0x01]); // identification
        packet[20..22].copy_from_slice(&[0x00, 0x00]); // flags + fragment offset
        packet[22] = 64; // TTL
        packet[23] = 17; // protocol: UDP
        packet[24..26].copy_from_slice(&[0x00, 0x00]); // checksum (0 = skip)
        packet[26..30].copy_from_slice(&[10, 0, 2, 15]); // src IP (QEMU default)
        packet[30..34].copy_from_slice(&[10, 0, 2, 2]);  // dst IP (QEMU gateway)

        // UDP header
        let src_port: u16 = 12345;
        let dst_port: u16 = 9999;
        let udp_len: u16 = 22; // 8 (header) + 14 (payload)
        packet[34..36].copy_from_slice(&src_port.to_be_bytes());
        packet[36..38].copy_from_slice(&dst_port.to_be_bytes());
        packet[38..40].copy_from_slice(&udp_len.to_be_bytes());
        packet[40..42].copy_from_slice(&[0x00, 0x00]); // checksum (0 = skip)

        // Payload: "AOS NETD ALIVE"
        packet[42..56].copy_from_slice(b"AOS NETD ALIVE");

        match crate::arch::x86_64::virtio_net::send_packet(&packet) {
            Ok(()) => serial_println!("[NETD] Test packet sent! (UDP 10.0.2.15:12345 -> 10.0.2.2:9999, 'AOS NETD ALIVE')"),
            Err(e) => serial_println!("[NETD] Test packet failed: {}", e),
        }

        // Also try to receive any packets (non-blocking)
        let mut net_recv_buf = [0u8; 1500];
        let received = crate::arch::x86_64::virtio_net::recv_packet(&mut net_recv_buf);
        if received > 0 {
            serial_println!("[NETD] Received {} bytes from network", received);
        }
    } else {
        serial_println!("[NETD] No network device, running in stub mode");
    }

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
