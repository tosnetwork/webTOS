//! Network syscalls for the Linux compatibility layer.
//!
//! Socket operations are proxied through the ATOS mailbox system to netd.
//! Pipes use a mailbox pair. Eventfd uses keyspace-backed counters.
//! io_uring returns -ENOSYS (runtimes fall back to epoll).

use super::constants::*;
use super::state::{self, FdEntry, FdKind};
use crate::agent::MAX_MESSAGE_PAYLOAD;

// ── Network I/O replay buffer ─────────────────────────────────────────────

const MAX_NET_IO_LOG: usize = 256;
const MAX_NET_IO_SIZE: usize = 256;

#[repr(C)]
struct NetIoEntry {
    agent_id: u16,
    data: [u8; MAX_NET_IO_SIZE],
    len: u16,
    tick: u64,
    is_send: bool,
    active: bool,
}

impl NetIoEntry {
    const fn empty() -> Self {
        NetIoEntry {
            agent_id: 0,
            data: [0u8; MAX_NET_IO_SIZE],
            len: 0,
            tick: 0,
            is_send: false,
            active: false,
        }
    }
}

static mut NET_IO_LOG: [NetIoEntry; MAX_NET_IO_LOG] =
    [const { NetIoEntry::empty() }; MAX_NET_IO_LOG];
static mut NET_IO_COUNT: usize = 0;

/// Record a network I/O payload for deterministic replay.
fn record_network_io(agent_id: u16, data: &[u8], is_send: bool) {
    unsafe {
        if NET_IO_COUNT >= MAX_NET_IO_LOG {
            return;
        }
        let entry = &mut NET_IO_LOG[NET_IO_COUNT];
        entry.agent_id = agent_id;
        let copy_len = data.len().min(MAX_NET_IO_SIZE);
        entry.data[..copy_len].copy_from_slice(&data[..copy_len]);
        entry.len = copy_len as u16;
        entry.tick = crate::arch::x86_64::timer::get_ticks();
        entry.is_send = is_send;
        entry.active = true;
        NET_IO_COUNT += 1;
    }
}

/// Get a recorded network I/O entry by index.
pub fn get_network_io(index: usize) -> Option<&'static NetIoEntry> {
    unsafe {
        if index < NET_IO_COUNT && NET_IO_LOG[index].active {
            Some(&NET_IO_LOG[index])
        } else {
            None
        }
    }
}

/// Get the number of recorded network I/O entries.
pub fn network_io_count() -> usize {
    unsafe { NET_IO_COUNT }
}

/// Replay a recorded recv for the given agent.
///
/// Scans the NET_IO_LOG for the next unconsumed recv entry matching `agent_id`,
/// copies the saved payload into the user buffer, and returns the byte count.
fn replay_network_recv(agent_id: u16, buf_ptr: u64, count: u64) -> i64 {
    unsafe {
        for i in 0..NET_IO_COUNT {
            let entry = &mut NET_IO_LOG[i];
            if entry.active && !entry.is_send && entry.agent_id == agent_id {
                let copy_len = (entry.len as usize).min(count as usize);
                core::ptr::copy_nonoverlapping(entry.data.as_ptr(), buf_ptr as *mut u8, copy_len);
                // Mark consumed so it won't be replayed again
                entry.active = false;
                return copy_len as i64;
            }
        }
    }
    // No more recorded data for this agent
    -EAGAIN
}

/// Address family constants.
const AF_UNIX: i32 = 1;
const AF_INET: i32 = 2;

/// Sentinel keyspace_key indicating an AF_UNIX socket.
const AF_UNIX_MARKER: u64 = 0xFFFF_FFFF;

/// Netd's mailbox ID (agent 9).
const NETD_MAILBOX: u16 = 9;

/// Socket fd flag: listening (set by listen()).
const FD_FLAG_LISTENING: u32 = 0x0100_0000;
/// Socket fd flag: shutdown read side.
const FD_FLAG_SHUT_RD: u32 = 0x0200_0000;
/// Socket fd flag: shutdown write side.
const FD_FLAG_SHUT_WR: u32 = 0x0400_0000;

// ── socket ─────────────────────────────────────────────────────────────────

/// socket(int domain, int type, int protocol)
///
/// Allocates an fd with FdKind::Socket. The mailbox_id is set to the agent's
/// own mailbox for now; actual netd proxy routing happens on connect().
pub fn sys_socket(agent_id: u16, domain: i32, _sock_type: i32, _protocol: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };

    // AF_UNIX sockets get a marker so connect() can reject them gracefully
    let key = if domain == AF_UNIX { AF_UNIX_MARKER } else { 0 };

    st.fd_table[fd] = Some(FdEntry {
        kind: FdKind::Socket,
        keyspace_key: key,
        keyspace_id: 0,
        mailbox_id: agent_id, // will be updated on connect
        offset: 0,
        flags: 0,
        active: true,
    });

    fd as i64
}

// ── connect ────────────────────────────────────────────────────────────────

/// connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
///
/// Stores the target address metadata in the fd entry.
/// In a full implementation this would send a connect request to netd via mailbox.
pub fn sys_connect(agent_id: u16, sockfd: i32, addr_ptr: u64, _addrlen: u64) -> i64 {
    const ECONNREFUSED: i64 = 111;

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {
            // AF_UNIX socket — nscd is never running on ATOS, refuse immediately
            if entry.keyspace_key == AF_UNIX_MARKER {
                return -ECONNREFUSED;
            }
        }
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    if addr_ptr == 0 {
        return -EFAULT;
    }

    // Read sockaddr_in from user memory: family(u16) + port(u16) + ip(u32)
    let (port, ip) = unsafe {
        let p = addr_ptr as *const u8;
        // sin_family at offset 0 (u16) — we don't validate, just skip
        // sin_port at offset 2 (u16, network byte order / big-endian)
        let port = u16::from_be_bytes([*p.add(2), *p.add(3)]);
        // sin_addr at offset 4 (u32, network byte order)
        let ip = u32::from_be_bytes([*p.add(4), *p.add(5), *p.add(6), *p.add(7)]);
        (port, ip)
    };

    // Pack ip:port into keyspace_key — ip in upper 32 bits, port in lower 16
    let packed = ((ip as u64) << 16) | (port as u64);

    let entry = st.get_fd_mut(sockfd).unwrap();
    entry.keyspace_key = packed;
    entry.mailbox_id = NETD_MAILBOX;

    0
}

// ── accept ─────────────────────────────────────────────────────────────────

/// accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
pub fn sys_accept(agent_id: u16, sockfd: i32, _addr_ptr: u64, _addrlen_ptr: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    // Allocate a new fd for the accepted connection
    let new_fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };

    st.fd_table[new_fd] = Some(FdEntry {
        kind: FdKind::Socket,
        keyspace_key: 0,
        keyspace_id: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: 0,
        active: true,
    });

    new_fd as i64
}

// ── sendto ─────────────────────────────────────────────────────────────────

/// sendto(int sockfd, const void *buf, size_t len, int flags,
///        const struct sockaddr *dest_addr, socklen_t addrlen)
pub fn sys_sendto(
    agent_id: u16,
    sockfd: i32,
    buf_ptr: u64,
    len: u64,
    _flags: u64,
    _dest_addr: u64,
) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let packed_addr = match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => entry.keyspace_key,
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    };

    if buf_ptr == 0 || len == 0 {
        return 0;
    }

    // Read user data
    let data_len = (len as usize).min(MAX_MESSAGE_PAYLOAD - 32);
    let data = unsafe { core::slice::from_raw_parts(buf_ptr as *const u8, data_len) };

    // Build URL from packed ip:port in keyspace_key
    let port = (packed_addr & 0xFFFF) as u16;
    let ip = ((packed_addr >> 16) & 0xFFFF_FFFF) as u32;
    let ip_bytes = ip.to_be_bytes();

    // Format URL as "ip0.ip1.ip2.ip3:port/"
    let mut url_buf = [0u8; 32];
    let mut url_pos = 0usize;
    for (i, &octet) in ip_bytes.iter().enumerate() {
        if i > 0 {
            url_buf[url_pos] = b'.';
            url_pos += 1;
        }
        url_pos += fmt_u8(octet, &mut url_buf[url_pos..]);
    }
    url_buf[url_pos] = b':';
    url_pos += 1;
    url_pos += fmt_u16_decimal(port, &mut url_buf[url_pos..]);
    url_buf[url_pos] = b'/';
    url_pos += 1;

    // Build netd request message:
    // [op=0x01, reply_mailbox: u8, method: u8, url_len: u16 LE, url: [u8], body_len: u16 LE, body: [u8]]
    let mut msg = [0u8; MAX_MESSAGE_PAYLOAD];
    let mut pos = 0usize;
    msg[pos] = 0x01;
    pos += 1; // op = OP_REQUEST
    msg[pos] = agent_id as u8;
    pos += 1; // reply_mailbox
    msg[pos] = 0x02;
    pos += 1; // method = POST
    let url_len_bytes = (url_pos as u16).to_le_bytes();
    msg[pos] = url_len_bytes[0];
    pos += 1;
    msg[pos] = url_len_bytes[1];
    pos += 1; // url_len
    let url_copy = url_pos.min(msg.len() - pos);
    msg[pos..pos + url_copy].copy_from_slice(&url_buf[..url_copy]);
    pos += url_copy; // url
    let body_len_bytes = (data_len as u16).to_le_bytes();
    if pos + 2 + data_len <= msg.len() {
        msg[pos] = body_len_bytes[0];
        pos += 1;
        msg[pos] = body_len_bytes[1];
        pos += 1; // body_len
        msg[pos..pos + data_len].copy_from_slice(data);
        pos += data_len; // body
    }

    // Send to netd's mailbox
    let _ = crate::mailbox::send_message(agent_id, NETD_MAILBOX, &msg[..pos]);

    // Record trace entry for deterministic replay
    crate::checkpoint::record_trace(
        crate::arch::x86_64::timer::get_ticks(),
        crate::checkpoint::TRACE_NET_SEND,
        agent_id,
    );
    record_network_io(agent_id, data, true);

    data_len as i64
}

// ── recvfrom ───────────────────────────────────────────────────────────────

/// recvfrom(int sockfd, void *buf, size_t len, int flags,
///          struct sockaddr *src_addr, socklen_t *addrlen)
pub fn sys_recvfrom(
    agent_id: u16,
    sockfd: i32,
    buf_ptr: u64,
    len: u64,
    _flags: u64,
    _src_addr: u64,
) -> i64 {
    let fd_flags = {
        let st = match state::get_state(agent_id) {
            Some(s) => s,
            None => return -EBADF,
        };

        match st.get_fd(sockfd) {
            Some(entry) if entry.kind == FdKind::Socket => entry.flags,
            Some(_) => return -ENOTSOCK,
            None => return -EBADF,
        }
    };

    if buf_ptr == 0 || len == 0 {
        return 0;
    }

    // In replay mode, read from the recorded I/O log instead of the network
    if crate::replay::is_replay_mode() {
        return replay_network_recv(agent_id, buf_ptr, len);
    }

    // Try non-blocking recv from the agent's own mailbox
    match crate::mailbox::recv_message(agent_id, agent_id) {
        Ok(msg) => {
            let payload_len = msg.len as usize;
            let copy_len = payload_len.min(len as usize);
            unsafe {
                core::ptr::copy_nonoverlapping(msg.payload.as_ptr(), buf_ptr as *mut u8, copy_len);
            }
            // Record the received data for replay determinism
            crate::checkpoint::record_trace(
                crate::arch::x86_64::timer::get_ticks(),
                crate::checkpoint::TRACE_NET_RECV,
                agent_id,
            );
            record_network_io(agent_id, &msg.payload[..copy_len], false);
            copy_len as i64
        }
        Err(_) => {
            // No message available
            if fd_flags & O_NONBLOCK != 0 {
                return -EAGAIN;
            }
            // Blocking mode: yield once and retry
            crate::sched::yield_current();
            match crate::mailbox::recv_message(agent_id, agent_id) {
                Ok(msg) => {
                    let payload_len = msg.len as usize;
                    let copy_len = payload_len.min(len as usize);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            msg.payload.as_ptr(),
                            buf_ptr as *mut u8,
                            copy_len,
                        );
                    }
                    // Record the received data for replay determinism
                    crate::checkpoint::record_trace(
                        crate::arch::x86_64::timer::get_ticks(),
                        crate::checkpoint::TRACE_NET_RECV,
                        agent_id,
                    );
                    record_network_io(agent_id, &msg.payload[..copy_len], false);
                    copy_len as i64
                }
                Err(_) => -EAGAIN,
            }
        }
    }
}

// ── sendmsg / recvmsg ──────────────────────────────────────────────────────

/// sendmsg(int sockfd, const struct msghdr *msg, int flags)
///
/// Extracts the first iov from msghdr and delegates to sys_sendto.
pub fn sys_sendmsg(agent_id: u16, sockfd: i32, msg_ptr: u64, flags: u64) -> i64 {
    if msg_ptr == 0 {
        return -EFAULT;
    }

    // struct msghdr layout (x86_64):
    //   msg_name:       *void       (offset 0,  8 bytes)
    //   msg_namelen:    socklen_t   (offset 8,  4 bytes)
    //   msg_iov:        *iovec      (offset 16, 8 bytes)
    //   msg_iovlen:     size_t      (offset 24, 8 bytes)
    // struct iovec: { iov_base: *void (8), iov_len: size_t (8) }
    unsafe {
        let p = msg_ptr as *const u8;
        let iov_ptr = core::ptr::read_unaligned(p.add(16) as *const u64);
        let iov_len = core::ptr::read_unaligned(p.add(24) as *const u64);

        if iov_len == 0 || iov_ptr == 0 {
            return 0;
        }

        // Read first iovec
        let iov = iov_ptr as *const u8;
        let iov_base = core::ptr::read_unaligned(iov as *const u64);
        let iov_buf_len = core::ptr::read_unaligned(iov.add(8) as *const u64);

        sys_sendto(agent_id, sockfd, iov_base, iov_buf_len, flags, 0)
    }
}

/// recvmsg(int sockfd, struct msghdr *msg, int flags)
///
/// Extracts the first iov from msghdr and delegates to sys_recvfrom.
pub fn sys_recvmsg(agent_id: u16, sockfd: i32, msg_ptr: u64, flags: u64) -> i64 {
    if msg_ptr == 0 {
        return -EFAULT;
    }

    // Extract first iovec from msghdr (same layout as sendmsg)
    unsafe {
        let p = msg_ptr as *const u8;
        let iov_ptr = core::ptr::read_unaligned(p.add(16) as *const u64);
        let iov_len = core::ptr::read_unaligned(p.add(24) as *const u64);

        if iov_len == 0 || iov_ptr == 0 {
            return 0;
        }

        let iov = iov_ptr as *const u8;
        let iov_base = core::ptr::read_unaligned(iov as *const u64);
        let iov_buf_len = core::ptr::read_unaligned(iov.add(8) as *const u64);

        sys_recvfrom(agent_id, sockfd, iov_base, iov_buf_len, flags, 0)
    }
}

// ── shutdown ───────────────────────────────────────────────────────────────

/// shutdown(int sockfd, int how)
///
/// how: 0 = SHUT_RD, 1 = SHUT_WR, 2 = SHUT_RDWR
pub fn sys_shutdown(agent_id: u16, sockfd: i32, how: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    let entry = st.get_fd_mut(sockfd).unwrap();
    match how {
        0 => entry.flags |= FD_FLAG_SHUT_RD,                   // SHUT_RD
        1 => entry.flags |= FD_FLAG_SHUT_WR,                   // SHUT_WR
        2 => entry.flags |= FD_FLAG_SHUT_RD | FD_FLAG_SHUT_WR, // SHUT_RDWR
        _ => return -EINVAL,
    }

    0
}

// ── bind ───────────────────────────────────────────────────────────────────

/// bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
///
/// Stores the bind port in the fd's keyspace_key field.
pub fn sys_bind(agent_id: u16, sockfd: i32, addr_ptr: u64, _addrlen: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    if addr_ptr == 0 {
        return -EFAULT;
    }

    // Read sin_port from sockaddr_in (offset 2, network byte order)
    let port = unsafe {
        let p = addr_ptr as *const u8;
        u16::from_be_bytes([*p.add(2), *p.add(3)])
    };

    let entry = st.get_fd_mut(sockfd).unwrap();
    entry.keyspace_key = port as u64;

    0
}

// ── listen ─────────────────────────────────────────────────────────────────

/// listen(int sockfd, int backlog)
///
/// Marks the socket fd as listening.
pub fn sys_listen(agent_id: u16, sockfd: i32, _backlog: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    let entry = st.get_fd_mut(sockfd).unwrap();
    entry.flags |= FD_FLAG_LISTENING;

    0
}

// ── getsockname ────────────────────────────────────────────────────────────

/// getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
///
/// Returns a zeroed sockaddr_in (AF_INET, port 0, addr 0.0.0.0).
pub fn sys_getsockname(agent_id: u16, sockfd: i32, addr_ptr: u64, addrlen_ptr: u64) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    if addr_ptr == 0 || addrlen_ptr == 0 {
        return -EFAULT;
    }

    // Write a minimal sockaddr_in: AF_INET (2), port 0, addr 0.0.0.0
    // struct sockaddr_in is 16 bytes
    unsafe {
        let p = addr_ptr as *mut u8;
        core::ptr::write_bytes(p, 0, 16);
        // sa_family = AF_INET = 2 (u16 at offset 0)
        let af_inet: u16 = 2;
        core::ptr::copy_nonoverlapping(&af_inet as *const u16 as *const u8, p, 2);
        // Write addrlen = 16
        let addrlen: u32 = 16;
        core::ptr::copy_nonoverlapping(
            &addrlen as *const u32 as *const u8,
            addrlen_ptr as *mut u8,
            4,
        );
    }

    0
}

// ── getpeername ─────────────────────────────────────────────────────────────

/// getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
pub fn sys_getpeername(agent_id: u16, sockfd: i32, addr_ptr: u64, addrlen_ptr: u64) -> i64 {
    // Same implementation as getsockname for now
    sys_getsockname(agent_id, sockfd, addr_ptr, addrlen_ptr)
}

// ── socketpair ─────────────────────────────────────────────────────────────

/// socketpair(int domain, int type, int protocol, int sv[2])
pub fn sys_socketpair(
    agent_id: u16,
    _domain: u64,
    _sock_type: u64,
    _protocol: u64,
    sv_ptr: u64,
) -> i64 {
    if sv_ptr == 0 {
        return -EFAULT;
    }

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let fd0 = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };
    st.fd_table[fd0] = Some(FdEntry {
        kind: FdKind::Socket,
        keyspace_key: 0,
        keyspace_id: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: 0,
        active: true,
    });

    let fd1 = match st.alloc_fd() {
        Some(f) => f,
        None => {
            st.fd_table[fd0] = None;
            return -EMFILE;
        }
    };
    st.fd_table[fd1] = Some(FdEntry {
        kind: FdKind::Socket,
        keyspace_key: 0,
        keyspace_id: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: 0,
        active: true,
    });

    unsafe {
        let p = sv_ptr as *mut i32;
        core::ptr::write(p, fd0 as i32);
        core::ptr::write(p.add(1), fd1 as i32);
    }

    0
}

// ── setsockopt / getsockopt ────────────────────────────────────────────────

/// setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
pub fn sys_setsockopt(
    agent_id: u16,
    sockfd: i32,
    _level: u64,
    _optname: u64,
    _optval_ptr: u64,
    _optlen: u64,
) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    // Accept all socket options silently
    0
}

/// getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
///
/// Returns zeroed/default values.
pub fn sys_getsockopt(
    agent_id: u16,
    sockfd: i32,
    _level: u64,
    _optname: u64,
    optval_ptr: u64,
    optlen_ptr: u64,
) -> i64 {
    let st = match state::get_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match st.get_fd(sockfd) {
        Some(entry) if entry.kind == FdKind::Socket => {}
        Some(_) => return -ENOTSOCK,
        None => return -EBADF,
    }

    if optval_ptr != 0 && optlen_ptr != 0 {
        // Read the optlen, write zeroed data
        unsafe {
            let len_ptr = optlen_ptr as *mut u32;
            let len = core::ptr::read(len_ptr) as usize;
            if len > 0 && len <= 128 {
                core::ptr::write_bytes(optval_ptr as *mut u8, 0, len);
            }
        }
    }

    0
}

// ── pipe2 ──────────────────────────────────────────────────────────────────

/// pipe2(int pipefd[2], int flags)
///
/// Creates two fds backed by a mailbox pair: writing to pipefd[1] sends to
/// the mailbox, reading from pipefd[0] receives from it.
pub fn sys_pipe2(agent_id: u16, pipefd_ptr: u64, flags: i32) -> i64 {
    if pipefd_ptr == 0 {
        return -EFAULT;
    }

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    // Allocate read end
    let read_fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };
    st.fd_table[read_fd] = Some(FdEntry {
        kind: FdKind::Pipe,
        keyspace_key: 0,
        keyspace_id: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: flags as u32,
        active: true,
    });

    // Allocate write end
    let write_fd = match st.alloc_fd() {
        Some(f) => f,
        None => {
            st.fd_table[read_fd] = None;
            return -EMFILE;
        }
    };
    st.fd_table[write_fd] = Some(FdEntry {
        kind: FdKind::Pipe,
        keyspace_key: 0,
        keyspace_id: 0,
        mailbox_id: agent_id,
        offset: 0,
        flags: flags as u32,
        active: true,
    });

    unsafe {
        let p = pipefd_ptr as *mut i32;
        core::ptr::write(p, read_fd as i32);
        core::ptr::write(p.add(1), write_fd as i32);
    }

    0
}

// ── eventfd2 ───────────────────────────────────────────────────────────────

/// eventfd2(unsigned int initval, int flags)
///
/// Creates an fd backed by a u64 counter. The initial value is stored
/// in the keyspace_key field of the fd entry.
pub fn sys_eventfd2(agent_id: u16, initval: u32, flags: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };

    st.fd_table[fd] = Some(FdEntry {
        kind: FdKind::EventFd,
        keyspace_key: initval as u64, // counter value stored here
        keyspace_id: 0,
        mailbox_id: 0,
        offset: 0,
        flags: flags as u32,
        active: true,
    });

    fd as i64
}

// ── Formatting helpers ─────────────────────────────────────────────────────

/// Format a u8 as decimal ASCII into a buffer. Returns the number of bytes written.
fn fmt_u8(val: u8, buf: &mut [u8]) -> usize {
    if val >= 100 {
        let d2 = val / 100;
        let d1 = (val / 10) % 10;
        let d0 = val % 10;
        if buf.len() >= 3 {
            buf[0] = b'0' + d2;
            buf[1] = b'0' + d1;
            buf[2] = b'0' + d0;
            return 3;
        }
    } else if val >= 10 {
        let d1 = val / 10;
        let d0 = val % 10;
        if buf.len() >= 2 {
            buf[0] = b'0' + d1;
            buf[1] = b'0' + d0;
            return 2;
        }
    } else if !buf.is_empty() {
        buf[0] = b'0' + val;
        return 1;
    }
    0
}

/// Format a u16 as decimal ASCII into a buffer. Returns the number of bytes written.
fn fmt_u16_decimal(mut val: u16, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
            return 1;
        }
        return 0;
    }
    let mut tmp = [0u8; 5];
    let mut i = 0usize;
    while val > 0 && i < 5 {
        tmp[i] = b'0' + (val % 10) as u8;
        val /= 10;
        i += 1;
    }
    let len = i.min(buf.len());
    for j in 0..len {
        buf[j] = tmp[i - 1 - j];
    }
    len
}

// ── io_uring stubs ─────────────────────────────────────────────────────────

/// io_uring_setup(u32 entries, struct io_uring_params *p)
///
/// Not supported — ATOS uses deterministic epoll instead.
/// Returns -ENOSYS; Node.js and other runtimes fall back to epoll
/// automatically when io_uring is unavailable (same as Linux < 5.1).
/// OpenJDK does not use io_uring.
#[allow(dead_code)]
pub fn sys_io_uring_setup(_agent_id: u16, _entries: u32, _params_ptr: u64) -> i64 {
    // -ENOSYS is the correct return here — identical to what the Linux
    // kernel returns on kernels that predate io_uring (< 5.1).
    // All runtimes handle this gracefully.
    -ENOSYS
}

/// io_uring_enter — see io_uring_setup rationale.
#[allow(dead_code)]
pub fn sys_io_uring_enter(
    _agent_id: u16,
    _fd: u32,
    _to_submit: u32,
    _min_complete: u32,
    _flags: u32,
    _sig: u64,
) -> i64 {
    -ENOSYS
}
