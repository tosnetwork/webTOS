//! AOS Minimal Kernel UDP
//!
//! Simple UDP send/receive for inter-node mailbox routing.
//! Uses raw Ethernet frames with IPv4/UDP headers.
//! NOT a full TCP/IP stack — just enough for kernel-to-kernel communication.

use crate::serial_println;

/// UDP endpoint
#[derive(Debug, Clone, Copy)]
pub struct UdpEndpoint {
    pub ip: [u8; 4],
    pub port: u16,
}

/// Craft a UDP packet and send via the available network driver
pub fn send_udp(src: &UdpEndpoint, dst: &UdpEndpoint, payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() > 1400 { return Err("payload too large for single UDP packet"); }

    let mut packet = [0u8; 1514]; // max Ethernet frame
    let total_len = 14 + 20 + 8 + payload.len(); // eth + ip + udp + payload

    // Ethernet header: broadcast destination, source from NIC
    let mac = get_mac();
    packet[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // dst
    packet[6..12].copy_from_slice(&mac); // src
    packet[12] = 0x08; packet[13] = 0x00; // IPv4

    // IPv4 header
    packet[14] = 0x45; // version + IHL
    let ip_total: u16 = (20 + 8 + payload.len()) as u16;
    packet[16..18].copy_from_slice(&ip_total.to_be_bytes());
    packet[20..22].copy_from_slice(&[0x40, 0x00]); // Don't fragment
    packet[22] = 64; // TTL
    packet[23] = 17; // UDP
    packet[26..30].copy_from_slice(&src.ip);
    packet[30..34].copy_from_slice(&dst.ip);

    // UDP header
    packet[34..36].copy_from_slice(&src.port.to_be_bytes());
    packet[36..38].copy_from_slice(&dst.port.to_be_bytes());
    let udp_len: u16 = (8 + payload.len()) as u16;
    packet[38..40].copy_from_slice(&udp_len.to_be_bytes());

    // Payload
    packet[42..42 + payload.len()].copy_from_slice(payload);

    // Send via whichever network driver is available
    if crate::arch::x86_64::virtio_net::is_initialized() {
        crate::arch::x86_64::virtio_net::send_packet(&packet[..total_len])
    } else if crate::arch::x86_64::e1000::is_initialized() {
        crate::arch::x86_64::e1000::send_packet(&packet[..total_len])
    } else {
        Err("no network device available")
    }
}

/// Try to receive a UDP packet (non-blocking)
pub fn recv_udp(buf: &mut [u8]) -> Option<(UdpEndpoint, usize)> {
    let mut frame = [0u8; 1514];
    let frame_len = if crate::arch::x86_64::virtio_net::is_initialized() {
        crate::arch::x86_64::virtio_net::recv_packet(&mut frame)
    } else if crate::arch::x86_64::e1000::is_initialized() {
        crate::arch::x86_64::e1000::recv_packet(&mut frame)
    } else {
        0
    };

    if frame_len < 42 { return None; } // too small for eth+ip+udp

    // Check EtherType = IPv4
    if frame[12] != 0x08 || frame[13] != 0x00 { return None; }

    // Check protocol = UDP
    if frame[23] != 17 { return None; }

    let src = UdpEndpoint {
        ip: [frame[26], frame[27], frame[28], frame[29]],
        port: u16::from_be_bytes([frame[34], frame[35]]),
    };

    let udp_len = u16::from_be_bytes([frame[38], frame[39]]) as usize;
    let payload_len = udp_len.saturating_sub(8);
    let copy_len = payload_len.min(buf.len());

    buf[..copy_len].copy_from_slice(&frame[42..42 + copy_len]);

    Some((src, copy_len))
}

pub fn get_mac() -> [u8; 6] {
    if crate::arch::x86_64::virtio_net::is_initialized() {
        crate::arch::x86_64::virtio_net::mac_address()
    } else if crate::arch::x86_64::e1000::is_initialized() {
        crate::arch::x86_64::e1000::mac_address()
    } else {
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01] // default
    }
}

/// Returns true if any network device is available.
pub fn nic_available() -> bool {
    crate::arch::x86_64::virtio_net::is_initialized()
        || crate::arch::x86_64::e1000::is_initialized()
}
