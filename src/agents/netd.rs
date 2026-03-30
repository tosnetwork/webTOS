//! ATOS netd — Network Broker Agent
//!
//! System agent that brokers all network access. Agents send HTTP-like
//! requests via mailbox; netd validates, logs, and (when a network driver
//! is available) performs the request by sending the HTTP payload as a
//! UDP datagram to the destination host.
//!
//! Protocol (mailbox payload):
//!   Request:  [op=0x01, reply_mailbox: u8, method: u8, url_len: u16, url: [u8], body_len: u16, body: [u8]]
//!   Response: [status: u8, response_code: u16, body_len: u16, body: [u8]]
//!
//! Methods: 0x01=GET, 0x02=POST, 0x03=PUT, 0x04=DELETE
//!
//! The URL should be in the form: host:port/path (e.g. "10.0.2.2:80/index.html")
//! If no port is specified, 80 is assumed.
//!
//! Without a NIC, netd returns 503 (Service Unavailable) with an
//! explicit "no NIC available" message.  With a NIC, netd sends the
//! HTTP request as a UDP payload and polls for a response; if none
//! arrives within the timeout window it returns 504 (Gateway Timeout).

use crate::serial_println;
use crate::agent::*;
use crate::syscall;

const OP_REQUEST: u8 = 0x01;
const OP_EXTERNAL_REQUEST: u8 = 0x10;
const METHOD_GET: u8 = 0x01;
const METHOD_POST: u8 = 0x02;

/// Default destination port when none is specified in the URL.
const DEFAULT_HTTP_PORT: u16 = 80;

/// Default source IP (QEMU user-mode networking).
const SRC_IP: [u8; 4] = [10, 0, 2, 15];

/// Default source port for outgoing UDP datagrams.
const SRC_PORT: u16 = 12345;

/// Number of poll iterations to wait for a network response.
const RECV_POLL_ITERATIONS: usize = 500_000;

/// Detect which NIC is available and return a string label.
fn detect_nic() -> Option<&'static str> {
    if crate::arch::x86_64::virtio_net::is_initialized() {
        Some("virtio-net")
    } else if crate::arch::x86_64::e1000::is_initialized() {
        Some("e1000")
    } else {
        None
    }
}

/// Send a raw Ethernet frame via whichever NIC is available.
fn send_raw(packet: &[u8]) -> Result<(), &'static str> {
    if crate::arch::x86_64::virtio_net::is_initialized() {
        crate::arch::x86_64::virtio_net::send_packet(packet)
    } else if crate::arch::x86_64::e1000::is_initialized() {
        crate::arch::x86_64::e1000::send_packet(packet)
    } else {
        Err("no network device available")
    }
}

/// Receive a raw Ethernet frame via whichever NIC is available (non-blocking).
fn recv_raw(buf: &mut [u8]) -> usize {
    if crate::arch::x86_64::virtio_net::is_initialized() {
        crate::arch::x86_64::virtio_net::recv_packet(buf)
    } else if crate::arch::x86_64::e1000::is_initialized() {
        crate::arch::x86_64::e1000::recv_packet(buf)
    } else {
        0
    }
}

/// Get MAC address from whichever NIC is available.
fn get_mac() -> [u8; 6] {
    if crate::arch::x86_64::virtio_net::is_initialized() {
        crate::arch::x86_64::virtio_net::mac_address()
    } else if crate::arch::x86_64::e1000::is_initialized() {
        crate::arch::x86_64::e1000::mac_address()
    } else {
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]
    }
}

/// Build and send a test UDP packet:
///   Ethernet broadcast, IPv4, UDP
///   src=10.0.2.15:12345 -> dst=10.0.2.2:9999
///   payload: b"ATOS NETD ALIVE"
fn send_test_packet(mac: [u8; 6]) {
    let mut packet = [0u8; 57]; // 14 (eth) + 20 (ip) + 8 (udp) + 15 (payload)

    // Ethernet header
    packet[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // dst MAC (broadcast)
    packet[6..12].copy_from_slice(&mac);   // src MAC
    packet[12] = 0x08; packet[13] = 0x00;  // EtherType: IPv4

    // IPv4 header (minimal, no options)
    packet[14] = 0x45; // version=4, IHL=5 (20 bytes)
    packet[15] = 0x00; // DSCP/ECN
    let total_len: u16 = 43; // 20 (IP) + 8 (UDP) + 15 (payload)
    packet[16..18].copy_from_slice(&total_len.to_be_bytes());
    packet[18..20].copy_from_slice(&[0x00, 0x01]); // identification
    packet[20..22].copy_from_slice(&[0x40, 0x00]); // flags=DF + fragment offset=0
    packet[22] = 64;  // TTL
    packet[23] = 17;  // protocol: UDP
    packet[24..26].copy_from_slice(&[0x00, 0x00]); // checksum (0 = skip)
    packet[26..30].copy_from_slice(&SRC_IP); // src IP
    packet[30..34].copy_from_slice(&[10, 0, 2, 2]);  // dst IP (QEMU gateway)

    // UDP header
    let src_port: u16 = SRC_PORT;
    let dst_port: u16 = 9999;
    let udp_len: u16 = 23; // 8 (header) + 15 (payload)
    packet[34..36].copy_from_slice(&src_port.to_be_bytes());
    packet[36..38].copy_from_slice(&dst_port.to_be_bytes());
    packet[38..40].copy_from_slice(&udp_len.to_be_bytes());
    packet[40..42].copy_from_slice(&[0x00, 0x00]); // checksum (0 = skip)

    // Payload: "ATOS NETD ALIVE"
    packet[42..57].copy_from_slice(b"ATOS NETD ALIVE");

    match send_raw(&packet) {
        Ok(()) => serial_println!(
            "[NETD] Test packet sent! (UDP 10.0.2.15:12345 -> 10.0.2.2:9999, 'ATOS NETD ALIVE')"
        ),
        Err(e) => serial_println!("[NETD] Test packet failed: {}", e),
    }
}

/// Parse a URL string into (host_ip, port, path).
///
/// Expected formats:
///   "10.0.2.2:8080/some/path"
///   "10.0.2.2/some/path"          (port defaults to 80)
///   "10.0.2.2"                     (port 80, path "/")
///
/// Returns `None` if the IP cannot be parsed.
fn parse_url(url: &str) -> Option<([u8; 4], u16, &str)> {
    // Split off path
    let (host_port, path) = match url.find('/') {
        Some(idx) => (&url[..idx], &url[idx..]),
        None => (url, "/"),
    };

    // Split host and optional port
    let (host_str, port) = match host_port.rfind(':') {
        Some(idx) => {
            let port_str = &host_port[idx + 1..];
            let p = parse_u16(port_str).unwrap_or(DEFAULT_HTTP_PORT);
            (&host_port[..idx], p)
        }
        None => (host_port, DEFAULT_HTTP_PORT),
    };

    let ip = parse_ipv4(host_str)?;
    Some((ip, port, path))
}

/// Parse a dotted-decimal IPv4 address (e.g. "10.0.2.2").
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut idx = 0usize;
    for part in s.split('.') {
        if idx >= 4 { return None; }
        octets[idx] = parse_u8(part)?;
        idx += 1;
    }
    if idx == 4 { Some(octets) } else { None }
}

/// Parse a string as u8 without pulling in the full fmt/parse machinery.
fn parse_u8(s: &str) -> Option<u8> {
    let mut val: u16 = 0;
    if s.is_empty() { return None; }
    for &b in s.as_bytes() {
        if b < b'0' || b > b'9' { return None; }
        val = val * 10 + (b - b'0') as u16;
        if val > 255 { return None; }
    }
    Some(val as u8)
}

/// Parse a string as u16 without pulling in the full fmt/parse machinery.
fn parse_u16(s: &str) -> Option<u16> {
    let mut val: u32 = 0;
    if s.is_empty() { return None; }
    for &b in s.as_bytes() {
        if b < b'0' || b > b'9' { return None; }
        val = val * 10 + (b - b'0') as u32;
        if val > 65535 { return None; }
    }
    Some(val as u16)
}

/// Build an HTTP/1.1 request string into `buf`. Returns the number of
/// bytes written, or 0 if the buffer is too small.
fn build_http_request(
    buf: &mut [u8],
    method: &str,
    host: &str,
    path: &str,
    body: &[u8],
) -> usize {
    let mut pos = 0usize;

    // Request line: "GET /path HTTP/1.1\r\n"
    pos += copy_str(&mut buf[pos..], method);
    pos += copy_str(&mut buf[pos..], " ");
    pos += copy_str(&mut buf[pos..], path);
    pos += copy_str(&mut buf[pos..], " HTTP/1.1\r\n");

    // Host header
    pos += copy_str(&mut buf[pos..], "Host: ");
    pos += copy_str(&mut buf[pos..], host);
    pos += copy_str(&mut buf[pos..], "\r\n");

    // Connection: close
    pos += copy_str(&mut buf[pos..], "Connection: close\r\n");

    // User-Agent
    pos += copy_str(&mut buf[pos..], "User-Agent: ATOS-netd/1.0\r\n");

    if !body.is_empty() {
        // Content-Length header
        pos += copy_str(&mut buf[pos..], "Content-Length: ");
        let mut num_buf = [0u8; 8];
        let num_len = fmt_usize(body.len(), &mut num_buf);
        if pos + num_len > buf.len() { return 0; }
        buf[pos..pos + num_len].copy_from_slice(&num_buf[..num_len]);
        pos += num_len;
        pos += copy_str(&mut buf[pos..], "\r\n");
    }

    // End of headers
    pos += copy_str(&mut buf[pos..], "\r\n");

    // Body
    if !body.is_empty() {
        if pos + body.len() > buf.len() { return 0; }
        buf[pos..pos + body.len()].copy_from_slice(body);
        pos += body.len();
    }

    pos
}

/// Copy a &str into a byte buffer, returning the number of bytes written.
fn copy_str(dst: &mut [u8], s: &str) -> usize {
    let bytes = s.as_bytes();
    let len = bytes.len().min(dst.len());
    dst[..len].copy_from_slice(&bytes[..len]);
    len
}

/// Format a usize as decimal ASCII into a buffer. Returns the number of digits.
fn fmt_usize(mut val: usize, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() { buf[0] = b'0'; }
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 0;
    while val > 0 && i < tmp.len() {
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    // Reverse into buf
    let len = i.min(buf.len());
    for j in 0..len {
        buf[j] = tmp[i - 1 - j];
    }
    len
}

/// Build a mailbox response payload.
///
/// Response format: [status: u8, response_code: u16 LE, body_len: u16 LE, body: [u8]]
///
/// `status`: 0x00 = success, 0x01 = error
fn build_response(buf: &mut [u8], status: u8, code: u16, body: &[u8]) -> usize {
    if buf.len() < 5 { return 0; }
    let body_len = body.len().min(buf.len() - 5);
    buf[0] = status;
    buf[1..3].copy_from_slice(&code.to_le_bytes());
    buf[3..5].copy_from_slice(&(body_len as u16).to_le_bytes());
    if body_len > 0 {
        buf[5..5 + body_len].copy_from_slice(&body[..body_len]);
    }
    5 + body_len
}

/// Send a response back to the requesting agent via its mailbox.
fn send_reply(reply_mailbox: u64, response: &[u8], response_len: usize) {
    if response_len == 0 { return; }
    let _ret = syscall::syscall(
        SYS_SEND,
        reply_mailbox,
        response[..response_len].as_ptr() as u64,
        response_len as u64,
        0, 0,
    );
}

/// Handle an HTTP request from an agent.
///
/// Parses the request, builds an HTTP/1.1 request string, sends it as
/// a UDP datagram via the available NIC, polls for a response, and
/// sends the result back to the requesting agent's mailbox.
fn handle_http_request(msg: &[u8], msg_len: usize) {
    // Protocol: [op=0x01, reply_mailbox: u8, method: u8, url_len: u16 LE, url: [u8], body_len: u16 LE, body: [u8]]
    if msg_len < 5 {
        serial_println!("[NETD] Request too short ({} bytes)", msg_len);
        return;
    }

    let reply_mailbox = msg[1] as u64;
    let method = msg[2];
    let url_len = u16::from_le_bytes([msg[3], msg[4]]) as usize;

    let method_str = match method {
        METHOD_GET  => "GET",
        METHOD_POST => "POST",
        0x03        => "PUT",
        0x04        => "DELETE",
        _           => "UNKNOWN",
    };

    if msg_len < 5 + url_len {
        serial_println!("[NETD] Request truncated: need {} url bytes, have {}", url_len, msg_len - 5);
        return;
    }

    let url = &msg[5..5 + url_len];
    let url_str = core::str::from_utf8(url).unwrap_or("<invalid>");

    // Parse optional body
    let body_offset = 5 + url_len;
    let body = if msg_len >= body_offset + 2 {
        let body_len = u16::from_le_bytes([msg[body_offset], msg[body_offset + 1]]) as usize;
        let body_start = body_offset + 2;
        if msg_len >= body_start + body_len {
            &msg[body_start..body_start + body_len]
        } else {
            &[]
        }
    } else {
        &[]
    };

    let nic_info = detect_nic();
    let nic_name = nic_info.unwrap_or("none");
    serial_println!("[NETD] Request: {} {} (NIC: {}, reply_mb: {})",
        method_str, url_str, nic_name, reply_mailbox);

    // No NIC available — return 503
    if nic_info.is_none() {
        serial_println!("[NETD] No NIC available, returning 503");
        let err_body = b"503 Service Unavailable: no NIC available";
        let mut resp = [0u8; 256];
        let resp_len = build_response(&mut resp, 0x01, 503, err_body);

        crate::event::emit(
            crate::sched::current(),
            crate::event::EventType::Custom,
            method as u64, url_len as u64, 503,
        );

        send_reply(reply_mailbox, &resp, resp_len);
        return;
    }

    // Parse URL into IP, port, path
    let (dst_ip, dst_port, path) = match parse_url(url_str) {
        Some(parsed) => parsed,
        None => {
            serial_println!("[NETD] Failed to parse URL: {}", url_str);
            let err_body = b"400 Bad Request: invalid URL";
            let mut resp = [0u8; 256];
            let resp_len = build_response(&mut resp, 0x01, 400, err_body);
            send_reply(reply_mailbox, &resp, resp_len);
            return;
        }
    };

    // Reconstruct host string for Host header (IP only, no port for default 80)
    let mut host_buf = [0u8; 32];
    let host_len = fmt_ipv4(&dst_ip, &mut host_buf);
    let host_str = core::str::from_utf8(&host_buf[..host_len]).unwrap_or("0.0.0.0");

    serial_println!("[NETD] Resolved: {}:{}{} (method={})", host_str, dst_port, path, method_str);

    // Build HTTP/1.1 request
    let mut http_buf = [0u8; 1400];
    let http_len = build_http_request(&mut http_buf, method_str, host_str, path, body);
    if http_len == 0 {
        serial_println!("[NETD] HTTP request too large for UDP");
        let err_body = b"413 Request Too Large";
        let mut resp = [0u8; 256];
        let resp_len = build_response(&mut resp, 0x01, 413, err_body);
        send_reply(reply_mailbox, &resp, resp_len);
        return;
    }

    serial_println!("[NETD] Sending HTTP request via UDP ({} bytes)", http_len);

    // Send as UDP datagram using crate::net::send_udp
    let src = crate::net::UdpEndpoint { ip: SRC_IP, port: SRC_PORT };
    let dst = crate::net::UdpEndpoint { ip: dst_ip, port: dst_port };

    match crate::net::send_udp(&src, &dst, &http_buf[..http_len]) {
        Ok(()) => {
            serial_println!("[NETD] UDP packet sent to {}.{}.{}.{}:{}",
                dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3], dst_port);
        }
        Err(e) => {
            serial_println!("[NETD] Send failed: {}", e);
            let err_body = b"502 Bad Gateway: send failed";
            let mut resp = [0u8; 256];
            let resp_len = build_response(&mut resp, 0x01, 502, err_body);

            crate::event::emit(
                crate::sched::current(),
                crate::event::EventType::Custom,
                method as u64, url_len as u64, 502,
            );

            send_reply(reply_mailbox, &resp, resp_len);
            return;
        }
    }

    // Poll for a response
    let mut udp_recv_buf = [0u8; 1400];
    let mut received = false;

    for _ in 0..RECV_POLL_ITERATIONS {
        if let Some((_src_ep, payload_len)) = crate::net::recv_udp(&mut udp_recv_buf) {
            serial_println!("[NETD] Received UDP response ({} bytes)", payload_len);

            // Send the raw response payload back to the requesting agent
            let mut resp = [0u8; MAX_MESSAGE_PAYLOAD];
            let resp_len = build_response(&mut resp, 0x00, 200, &udp_recv_buf[..payload_len]);

            crate::event::emit(
                crate::sched::current(),
                crate::event::EventType::Custom,
                method as u64, url_len as u64, 200,
            );

            send_reply(reply_mailbox, &resp, resp_len);
            received = true;
            break;
        }
        core::hint::spin_loop();
    }

    if !received {
        serial_println!("[NETD] No response received (timeout), returning 504");
        let err_body = b"504 Gateway Timeout: no response from host";
        let mut resp = [0u8; 256];
        let resp_len = build_response(&mut resp, 0x01, 504, err_body);

        crate::event::emit(
            crate::sched::current(),
            crate::event::EventType::Custom,
            method as u64, url_len as u64, 504,
        );

        send_reply(reply_mailbox, &resp, resp_len);
    }
}

/// Format an IPv4 address as "x.x.x.x" into a buffer. Returns the number of bytes written.
fn fmt_ipv4(ip: &[u8; 4], buf: &mut [u8]) -> usize {
    let mut pos = 0;
    for (i, &octet) in ip.iter().enumerate() {
        if i > 0 {
            if pos < buf.len() { buf[pos] = b'.'; pos += 1; }
        }
        let mut num_buf = [0u8; 8];
        let n = fmt_usize(octet as usize, &mut num_buf);
        let copy = n.min(buf.len() - pos);
        buf[pos..pos + copy].copy_from_slice(&num_buf[..copy]);
        pos += copy;
    }
    pos
}

/// Process a raw message as an external TCP interface request.
///
/// Parses the payload as an `ExternalRequest`, dispatches it via
/// `tcp_interface::handle_request()`, serializes the response, and
/// sends it back over the network.
fn handle_external_message(msg: &[u8]) {
    use crate::tcp_interface::ExternalRequest;

    let req = match ExternalRequest::parse(msg) {
        Some(r) => r,
        None => {
            serial_println!("[NETD] External request: failed to parse ({} bytes)", msg.len());
            return;
        }
    };

    serial_println!(
        "[NETD] External request id={} type={:?}",
        req.request_id, req.request_type,
    );

    let resp = crate::tcp_interface::handle_request(&req);

    serial_println!(
        "[NETD] External response id={} status={:?} output_len={}",
        resp.request_id, resp.status, resp.output_len,
    );

    // Serialize the response and send it back via the network.
    let mut resp_buf = [0u8; 4200]; // 4 KiB payload + header overhead
    let resp_len = resp.serialize(&mut resp_buf);
    if resp_len == 0 {
        serial_println!("[NETD] External response: serialization failed (buffer too small)");
        return;
    }

    match send_raw(&resp_buf[..resp_len]) {
        Ok(()) => serial_println!(
            "[NETD] External response sent ({} bytes)", resp_len
        ),
        Err(e) => serial_println!(
            "[NETD] External response send failed: {}", e
        ),
    }
}

pub extern "C" fn netd_entry() -> ! {
    serial_println!("[NETD] Network broker started");

    // Detect and use whichever NIC is available
    match detect_nic() {
        Some(nic_name) => {
            let mac = get_mac();
            serial_println!(
                "[NETD] NIC available: {} (MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x})",
                nic_name,
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
            );

            // Send a test packet to prove network I/O works
            serial_println!("[NETD] Sending test packet via {}...", nic_name);
            send_test_packet(mac);

            // Also try to receive any packets (non-blocking)
            let mut net_recv_buf = [0u8; 1500];
            let received = recv_raw(&mut net_recv_buf);
            if received > 0 {
                serial_println!("[NETD] Received {} bytes from network on init", received);
            }
        }
        None => {
            serial_println!("[NETD] No NIC detected; HTTP requests will return 503 (no NIC available)");
        }
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
                handle_http_request(&recv_buf, msg_len);
            } else if msg_len >= 1 && recv_buf[0] == OP_EXTERNAL_REQUEST {
                // External TCP interface request: payload starts after the op byte.
                handle_external_message(&recv_buf[1..msg_len]);
            }
        }

        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0);
    }
}
