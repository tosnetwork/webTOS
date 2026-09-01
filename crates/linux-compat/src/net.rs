//! The network broker boundary.
//!
//! Guest sockets never touch host networking directly: every operation goes
//! through a [`NetworkBroker`] the host attaches explicitly. A machine with
//! no broker has no network — `socket(2)` fails with `EAFNOSUPPORT` — which
//! makes "denied by default" the structural baseline the roadmap requires.
//!
//! Two brokers live here. [`NativeBroker`] drives non-blocking `std::net`
//! sockets and is used by tests and native hosts. [`HostBroker`] owns no
//! transport at all: it records what the guest wants into a command queue
//! the host drains, and accepts results back. That is what a browser needs,
//! where the only transports are asynchronous and a worker must never block
//! — see [`NetworkBroker::host_driven`].

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::time::Duration;

use crate::abi;

pub type Handle = u64;

/// One byte-stream or datagram endpoint result.
pub enum RecvOutcome {
    /// Bytes received (possibly fewer than requested).
    Data(Vec<u8>),
    /// The peer closed the stream (TCP only).
    Closed,
    /// Nothing available right now.
    WouldBlock,
}

/// Host-side network mediation. All methods are non-blocking except
/// [`NetworkBroker::wait_ready`], which the scheduler calls only when every
/// task is blocked and at least one waits on the network.
pub trait NetworkBroker {
    /// True when this broker cannot make progress on its own: the host must
    /// run its event loop and feed results back. The scheduler then pauses
    /// the machine on a network stall instead of waiting inside `wait_ready`.
    fn host_driven(&self) -> bool {
        false
    }

    /// Opens a TCP connection. Blocking (bounded by the broker's own
    /// connect timeout); called at `connect(2)`.
    fn tcp_connect(&mut self, addr: SocketAddrV4) -> Result<Handle, u64>;
    /// Opens an IPv6 TCP endpoint. Brokers that only have an IPv4 transport
    /// reject this explicitly; callers can then apply normal Happy-Eyeballs
    /// fallback instead of receiving a fabricated IPv4 connection.
    fn tcp_connect_v6(&mut self, _addr: SocketAddrV6) -> Result<Handle, u64> {
        Err(abi::EAFNOSUPPORT)
    }
    fn tcp_send(&mut self, handle: Handle, bytes: &[u8]) -> Result<usize, u64>;
    fn tcp_recv(&mut self, handle: Handle, max: usize) -> Result<RecvOutcome, u64>;
    fn tcp_shutdown_write(&mut self, handle: Handle) -> Result<(), u64>;

    /// Returns the number of bytes that a non-consuming read can presently
    /// observe.  This is the kernel-visible value behind `FIONREAD`: for a
    /// stream it is the available prefix, and for a datagram it is the next
    /// datagram's size.  `None` means that no data is readable yet.
    ///
    /// This deliberately belongs to the broker rather than the syscall
    /// layer.  A host-driven broker owns the receive queue, while a native
    /// broker must query its host socket without consuming data.
    fn pending_read_bytes(&mut self, handle: Handle) -> Result<Option<usize>, u64>;

    /// Creates a UDP endpoint (bound to an ephemeral local port).
    fn udp_open(&mut self) -> Result<Handle, u64>;
    /// Creates an IPv6 UDP endpoint. A broker which cannot preserve the
    /// address family must reject it rather than silently changing a guest
    /// IPv6 probe into IPv4.
    fn udp_open_v6(&mut self) -> Result<Handle, u64> {
        Err(abi::EAFNOSUPPORT)
    }
    fn udp_send_to(
        &mut self,
        handle: Handle,
        addr: SocketAddrV4,
        bytes: &[u8],
    ) -> Result<usize, u64>;
    fn udp_recv_from(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64>;
    /// Reads a UDP datagram without consuming it, for `MSG_PEEK`.
    fn udp_peek_from(
        &mut self,
        _handle: Handle,
        _max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64> {
        Err(abi::EOPNOTSUPP)
    }
    fn udp_send_to_v6(
        &mut self,
        _handle: Handle,
        _addr: SocketAddrV6,
        _bytes: &[u8],
    ) -> Result<usize, u64> {
        Err(abi::EAFNOSUPPORT)
    }
    fn udp_recv_from_v6(
        &mut self,
        _handle: Handle,
        _max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV6)>, u64> {
        Err(abi::EAFNOSUPPORT)
    }
    /// IPv6 counterpart of [`NetworkBroker::udp_peek_from`].
    fn udp_peek_from_v6(
        &mut self,
        _handle: Handle,
        _max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV6)>, u64> {
        Err(abi::EAFNOSUPPORT)
    }

    /// True when a read on `handle` would make progress (data, EOF, or an
    /// error to report).
    fn readable(&mut self, handle: Handle) -> bool;

    /// The local address of an endpoint, when known.
    fn local_addr(&mut self, handle: Handle) -> Option<SocketAddrV4>;
    fn local_addr_v6(&mut self, _handle: Handle) -> Option<SocketAddrV6> {
        None
    }

    fn close(&mut self, handle: Handle);

    /// Blocks the host until any of `handles` is readable or `timeout`
    /// elapses. Returns false on timeout. Only called when the guest is
    /// otherwise idle.
    fn wait_ready(&mut self, handles: &[Handle], timeout: Duration) -> bool;
}

pub type BrokerRef = Rc<RefCell<dyn NetworkBroker>>;

/// Native broker over `std::net`, for tests and native hosts.
///
/// `redirects` rewrites guest destinations before connecting — the test
/// suite uses it to serve "port 53 DNS" from an unprivileged local port,
/// and it doubles as a coarse allowlist: with `restrict_to_redirects`, any
/// destination not in the table is refused (`ENETUNREACH`), so fixtures
/// can never reach the open internet by accident.
pub struct NativeBroker {
    redirects: HashMap<SocketAddrV4, SocketAddrV4>,
    restrict_to_redirects: bool,
    tcp: HashMap<Handle, std::net::TcpStream>,
    udp: HashMap<Handle, std::net::UdpSocket>,
    next_handle: Handle,
}

impl NativeBroker {
    pub fn new() -> Self {
        Self {
            redirects: HashMap::new(),
            restrict_to_redirects: false,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            next_handle: 1,
        }
    }

    /// Rewrites guest connections to `from` so they reach `to` instead.
    pub fn redirect(&mut self, from: SocketAddrV4, to: SocketAddrV4) {
        self.redirects.insert(from, to);
    }

    /// Refuse any destination that has no redirect entry.
    pub fn restrict_to_redirects(&mut self) {
        self.restrict_to_redirects = true;
    }

    fn resolve(&self, addr: SocketAddrV4) -> Result<SocketAddrV4, u64> {
        if let Some(target) = self.redirects.get(&addr) {
            return Ok(*target);
        }
        if self.restrict_to_redirects {
            tracing::warn!("network: destination {addr} refused (not in redirect table)");
            return Err(abi::ENETUNREACH);
        }
        Ok(addr)
    }

    fn handle(&mut self) -> Handle {
        let handle = self.next_handle;
        self.next_handle += 1;
        handle
    }

    fn tcp_connect_addr(&mut self, target: SocketAddr) -> Result<Handle, u64> {
        let stream = std::net::TcpStream::connect_timeout(&target, Duration::from_secs(10))
            .map_err(|e| {
                tracing::warn!("network: connect {target} failed: {e}");
                io_errno(&e)
            })?;
        stream.set_nonblocking(true).map_err(|e| io_errno(&e))?;
        stream.set_nodelay(true).ok();
        let handle = self.handle();
        self.tcp.insert(handle, stream);
        Ok(handle)
    }
}

impl Default for NativeBroker {
    fn default() -> Self {
        Self::new()
    }
}

fn io_errno(err: &std::io::Error) -> u64 {
    match err.kind() {
        ErrorKind::ConnectionRefused => abi::ECONNREFUSED,
        ErrorKind::ConnectionReset | ErrorKind::BrokenPipe => abi::ECONNRESET,
        ErrorKind::TimedOut => abi::ETIMEDOUT,
        _ => abi::EIO,
    }
}

impl NetworkBroker for NativeBroker {
    fn tcp_connect(&mut self, addr: SocketAddrV4) -> Result<Handle, u64> {
        let target = self.resolve(addr)?;
        self.tcp_connect_addr(SocketAddr::V4(target))
    }

    fn tcp_connect_v6(&mut self, addr: SocketAddrV6) -> Result<Handle, u64> {
        if self.restrict_to_redirects {
            tracing::warn!("network: IPv6 destination {addr} refused (no IPv6 redirect table)");
            return Err(abi::ENETUNREACH);
        }
        self.tcp_connect_addr(SocketAddr::V6(addr))
    }

    fn tcp_send(&mut self, handle: Handle, bytes: &[u8]) -> Result<usize, u64> {
        let stream = self.tcp.get_mut(&handle).ok_or(abi::EBADF)?;
        loop {
            match stream.write(bytes) {
                Ok(n) => {
                    tracing::debug!("broker: tcp[{handle}] sent {n} bytes");
                    return Ok(n);
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    // Sends are small; wait for the kernel buffer briefly.
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => return Err(io_errno(&e)),
            }
        }
    }

    fn tcp_recv(&mut self, handle: Handle, max: usize) -> Result<RecvOutcome, u64> {
        let stream = self.tcp.get_mut(&handle).ok_or(abi::EBADF)?;
        let mut buf = vec![0_u8; max.min(0x10_0000)];
        match stream.read(&mut buf) {
            Ok(0) => {
                tracing::debug!("broker: tcp[{handle}] peer closed");
                Ok(RecvOutcome::Closed)
            }
            Ok(n) => {
                tracing::debug!("broker: tcp[{handle}] recv {n} bytes (asked {max})");
                buf.truncate(n);
                Ok(RecvOutcome::Data(buf))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(RecvOutcome::WouldBlock),
            Err(e) => Err(io_errno(&e)),
        }
    }

    fn tcp_shutdown_write(&mut self, handle: Handle) -> Result<(), u64> {
        let stream = self.tcp.get_mut(&handle).ok_or(abi::EBADF)?;
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|e| io_errno(&e))
    }

    fn pending_read_bytes(&mut self, handle: Handle) -> Result<Option<usize>, u64> {
        if let Some(stream) = self.tcp.get_mut(&handle) {
            let mut bytes = vec![0_u8; 0x10_0000];
            return match stream.peek(&mut bytes) {
                Ok(count) => Ok(Some(count)), // includes EOF as zero
                Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(None),
                Err(error) => Err(io_errno(&error)),
            };
        }
        let socket = self.udp.get_mut(&handle).ok_or(abi::EBADF)?;
        let mut bytes = vec![0_u8; 0x1_0000];
        match socket.peek_from(&mut bytes) {
            Ok((count, _)) => Ok(Some(count)),
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(io_errno(&error)),
        }
    }

    fn udp_open(&mut self) -> Result<Handle, u64> {
        // Bind to the unspecified address, not loopback: a 127.0.0.1-bound
        // socket cannot reach a public resolver (real DNS), only a loopback
        // one. 0.0.0.0 lets the host pick the right source interface for both.
        let socket =
            std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| io_errno(&e))?;
        socket.set_nonblocking(true).map_err(|e| io_errno(&e))?;
        let handle = self.handle();
        self.udp.insert(handle, socket);
        Ok(handle)
    }

    fn udp_open_v6(&mut self) -> Result<Handle, u64> {
        let socket =
            std::net::UdpSocket::bind(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                .map_err(|e| io_errno(&e))?;
        socket.set_nonblocking(true).map_err(|e| io_errno(&e))?;
        let handle = self.handle();
        self.udp.insert(handle, socket);
        Ok(handle)
    }

    fn udp_send_to(
        &mut self,
        handle: Handle,
        addr: SocketAddrV4,
        bytes: &[u8],
    ) -> Result<usize, u64> {
        let target = self.resolve(addr)?;
        let socket = self.udp.get_mut(&handle).ok_or(abi::EBADF)?;
        socket
            .send_to(bytes, SocketAddr::V4(target))
            .map_err(|e| io_errno(&e))
    }

    fn udp_recv_from(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64> {
        let socket = self.udp.get_mut(&handle).ok_or(abi::EBADF)?;
        let mut buf = vec![0_u8; max.min(0x1_0000)];
        match socket.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(from))) => {
                buf.truncate(n);
                Ok(Some((buf, from)))
            }
            Ok((n, _)) => {
                buf.truncate(n);
                Ok(Some((buf, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))))
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(io_errno(&e)),
        }
    }

    fn udp_peek_from(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64> {
        let socket = self.udp.get_mut(&handle).ok_or(abi::EBADF)?;
        let mut buf = vec![0_u8; max.min(0x1_0000)];
        match socket.peek_from(&mut buf) {
            Ok((n, SocketAddr::V4(from))) => {
                buf.truncate(n);
                Ok(Some((buf, from)))
            }
            Ok((_, SocketAddr::V6(_))) => Err(abi::EAFNOSUPPORT),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(io_errno(&e)),
        }
    }

    fn udp_send_to_v6(
        &mut self,
        handle: Handle,
        addr: SocketAddrV6,
        bytes: &[u8],
    ) -> Result<usize, u64> {
        if self.restrict_to_redirects {
            tracing::warn!(
                "network: IPv6 datagram destination {addr} refused (no IPv6 redirect table)"
            );
            return Err(abi::ENETUNREACH);
        }
        let socket = self.udp.get_mut(&handle).ok_or(abi::EBADF)?;
        socket
            .send_to(bytes, SocketAddr::V6(addr))
            .map_err(|e| io_errno(&e))
    }

    fn udp_recv_from_v6(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV6)>, u64> {
        let socket = self.udp.get_mut(&handle).ok_or(abi::EBADF)?;
        let mut buf = vec![0_u8; max.min(0x1_0000)];
        match socket.recv_from(&mut buf) {
            Ok((n, SocketAddr::V6(from))) => {
                buf.truncate(n);
                Ok(Some((buf, from)))
            }
            Ok((_, SocketAddr::V4(_))) => Err(abi::EAFNOSUPPORT),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(io_errno(&e)),
        }
    }

    fn udp_peek_from_v6(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV6)>, u64> {
        let socket = self.udp.get_mut(&handle).ok_or(abi::EBADF)?;
        let mut buf = vec![0_u8; max.min(0x1_0000)];
        match socket.peek_from(&mut buf) {
            Ok((n, SocketAddr::V6(from))) => {
                buf.truncate(n);
                Ok(Some((buf, from)))
            }
            Ok((_, SocketAddr::V4(_))) => Err(abi::EAFNOSUPPORT),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(io_errno(&e)),
        }
    }

    fn readable(&mut self, handle: Handle) -> bool {
        if let Some(stream) = self.tcp.get_mut(&handle) {
            let mut probe = [0_u8; 1];
            return match stream.peek(&mut probe) {
                Ok(_) => true, // data or EOF
                Err(e) if e.kind() == ErrorKind::WouldBlock => false,
                Err(_) => true, // surface the error via read
            };
        }
        if let Some(socket) = self.udp.get_mut(&handle) {
            let mut probe = [0_u8; 1];
            return match socket.peek_from(&mut probe) {
                Ok(_) => true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => false,
                Err(_) => true,
            };
        }
        false
    }

    fn local_addr(&mut self, handle: Handle) -> Option<SocketAddrV4> {
        let addr = if let Some(stream) = self.tcp.get(&handle) {
            stream.local_addr().ok()
        } else {
            self.udp.get(&handle).and_then(|s| s.local_addr().ok())
        };
        match addr {
            Some(SocketAddr::V4(addr)) => Some(addr),
            _ => None,
        }
    }

    fn local_addr_v6(&mut self, handle: Handle) -> Option<SocketAddrV6> {
        let addr = if let Some(stream) = self.tcp.get(&handle) {
            stream.local_addr().ok()
        } else {
            self.udp
                .get(&handle)
                .and_then(|socket| socket.local_addr().ok())
        };
        match addr {
            Some(SocketAddr::V6(addr)) => Some(addr),
            _ => None,
        }
    }

    fn close(&mut self, handle: Handle) {
        self.tcp.remove(&handle);
        self.udp.remove(&handle);
    }

    fn wait_ready(&mut self, handles: &[Handle], timeout: Duration) -> bool {
        // Simple portable wait: poll readiness with a short sleep. The
        // browser broker replaces this with real readiness events.
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if handles.iter().any(|&h| self.readable(h)) {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

// --------------------------------------------------------------- host broker

/// One command the host must carry out on the guest's behalf. Encoded into a
/// byte stream by [`HostBroker::take_commands`], because the browser host
/// reads it out of wasm linear memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetCommand {
    TcpConnect {
        handle: Handle,
        addr: SocketAddrV4,
    },
    TcpSend {
        handle: Handle,
        bytes: Vec<u8>,
    },
    TcpShutdownWrite {
        handle: Handle,
    },
    UdpOpen {
        handle: Handle,
    },
    UdpSendTo {
        handle: Handle,
        addr: SocketAddrV4,
        bytes: Vec<u8>,
    },
    Close {
        handle: Handle,
    },
}

/// Command stream opcodes. The host decodes these; keep them stable.
const OP_TCP_CONNECT: u8 = 1;
const OP_TCP_SEND: u8 = 2;
const OP_TCP_SHUTDOWN_WRITE: u8 = 3;
const OP_UDP_OPEN: u8 = 4;
const OP_UDP_SEND_TO: u8 = 5;
const OP_CLOSE: u8 = 6;

#[derive(Default)]
struct Endpoint {
    /// Bytes received from the peer, not yet read by the guest.
    rx: std::collections::VecDeque<u8>,
    /// Datagrams received, with their sender.
    datagrams: std::collections::VecDeque<(Vec<u8>, SocketAddrV4)>,
    /// The peer closed its side (TCP).
    closed: bool,
    /// A transport error to report on the guest's next operation.
    error: Option<u64>,
    /// The local address the host assigned, when it reported one.
    local: Option<SocketAddrV4>,
}

impl Endpoint {
    /// Readable means "a guest read makes progress": data, EOF, or an error.
    fn readable(&self) -> bool {
        !self.rx.is_empty() || !self.datagrams.is_empty() || self.closed || self.error.is_some()
    }
}

/// A broker whose transport lives in the host. Every guest operation is
/// recorded as a [`NetCommand`] for the host to perform; every result the
/// host produces is pushed back in through the `deliver_*` methods.
///
/// Connections are optimistic: `tcp_connect` records the request and returns
/// a handle immediately, and a refusal arrives later as an error on the
/// endpoint — which is what a guest using a non-blocking socket, as every
/// real workload here does, already handles.
pub struct HostBroker {
    endpoints: HashMap<Handle, Endpoint>,
    commands: Vec<NetCommand>,
    next_handle: Handle,
}

impl HostBroker {
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
            commands: Vec::new(),
            next_handle: 1,
        }
    }

    fn endpoint(&mut self, handle: Handle) -> &mut Endpoint {
        self.endpoints.entry(handle).or_default()
    }

    fn handle(&mut self) -> Handle {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        handle
    }

    /// Takes the pending commands, encoded for a host that reads bytes.
    /// Layout per command: `op:u8, handle:u32le`, then op-specific fields
    /// (`addr:u32be, port:u16be` for a destination, `len:u32le` + bytes for
    /// a payload).
    pub fn take_commands(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        let push_addr = |out: &mut Vec<u8>, addr: &SocketAddrV4| {
            out.extend_from_slice(&addr.ip().octets());
            out.extend_from_slice(&addr.port().to_be_bytes());
        };
        for command in std::mem::take(&mut self.commands) {
            match command {
                NetCommand::TcpConnect { handle, addr } => {
                    out.push(OP_TCP_CONNECT);
                    out.extend_from_slice(&(handle as u32).to_le_bytes());
                    push_addr(&mut out, &addr);
                }
                NetCommand::TcpSend { handle, bytes } => {
                    out.push(OP_TCP_SEND);
                    out.extend_from_slice(&(handle as u32).to_le_bytes());
                    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                    out.extend_from_slice(&bytes);
                }
                NetCommand::TcpShutdownWrite { handle } => {
                    out.push(OP_TCP_SHUTDOWN_WRITE);
                    out.extend_from_slice(&(handle as u32).to_le_bytes());
                }
                NetCommand::UdpOpen { handle } => {
                    out.push(OP_UDP_OPEN);
                    out.extend_from_slice(&(handle as u32).to_le_bytes());
                }
                NetCommand::UdpSendTo {
                    handle,
                    addr,
                    bytes,
                } => {
                    out.push(OP_UDP_SEND_TO);
                    out.extend_from_slice(&(handle as u32).to_le_bytes());
                    push_addr(&mut out, &addr);
                    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                    out.extend_from_slice(&bytes);
                }
                NetCommand::Close { handle } => {
                    out.push(OP_CLOSE);
                    out.extend_from_slice(&(handle as u32).to_le_bytes());
                }
            }
        }
        out
    }

    /// True when the host has commands waiting to be carried out.
    pub fn has_commands(&self) -> bool {
        !self.commands.is_empty()
    }

    /// The host reports that a connection is open and, when it knows it, the
    /// local address it was given.
    pub fn deliver_connected(&mut self, handle: Handle, local: Option<SocketAddrV4>) {
        let endpoint = self.endpoint(handle);
        endpoint.local = local;
    }

    /// The host delivers stream bytes from the peer.
    pub fn deliver_data(&mut self, handle: Handle, bytes: &[u8]) {
        self.endpoint(handle).rx.extend(bytes.iter().copied());
    }

    /// The host delivers one datagram and its sender.
    pub fn deliver_datagram(&mut self, handle: Handle, from: SocketAddrV4, bytes: &[u8]) {
        self.endpoint(handle)
            .datagrams
            .push_back((bytes.to_vec(), from));
    }

    /// The host reports the peer closed the stream.
    pub fn deliver_closed(&mut self, handle: Handle) {
        self.endpoint(handle).closed = true;
    }

    /// The host reports a transport failure; the guest sees `errno` on its
    /// next operation. A refused connection arrives this way.
    pub fn deliver_error(&mut self, handle: Handle, errno: u64) {
        let endpoint = self.endpoint(handle);
        if endpoint.error.is_none() {
            endpoint.error = Some(errno);
        }
    }
}

impl Default for HostBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkBroker for HostBroker {
    fn host_driven(&self) -> bool {
        true
    }

    fn tcp_connect(&mut self, addr: SocketAddrV4) -> Result<Handle, u64> {
        let handle = self.handle();
        self.endpoints.insert(handle, Endpoint::default());
        self.commands.push(NetCommand::TcpConnect { handle, addr });
        Ok(handle)
    }

    fn tcp_send(&mut self, handle: Handle, bytes: &[u8]) -> Result<usize, u64> {
        let endpoint = self.endpoints.get(&handle).ok_or(abi::EBADF)?;
        if let Some(errno) = endpoint.error {
            return Err(errno);
        }
        self.commands.push(NetCommand::TcpSend {
            handle,
            bytes: bytes.to_vec(),
        });
        Ok(bytes.len())
    }

    fn tcp_recv(&mut self, handle: Handle, max: usize) -> Result<RecvOutcome, u64> {
        let endpoint = self.endpoints.get_mut(&handle).ok_or(abi::EBADF)?;
        if !endpoint.rx.is_empty() {
            let take = max.min(endpoint.rx.len()).min(0x10_0000);
            return Ok(RecvOutcome::Data(endpoint.rx.drain(..take).collect()));
        }
        // An error is reported only once the buffered bytes are drained, so a
        // response that arrived before a reset is not lost.
        if let Some(errno) = endpoint.error {
            return Err(errno);
        }
        if endpoint.closed {
            return Ok(RecvOutcome::Closed);
        }
        Ok(RecvOutcome::WouldBlock)
    }

    fn tcp_shutdown_write(&mut self, handle: Handle) -> Result<(), u64> {
        if !self.endpoints.contains_key(&handle) {
            return Err(abi::EBADF);
        }
        self.commands.push(NetCommand::TcpShutdownWrite { handle });
        Ok(())
    }

    fn pending_read_bytes(&mut self, handle: Handle) -> Result<Option<usize>, u64> {
        let endpoint = self.endpoints.get(&handle).ok_or(abi::EBADF)?;
        if !endpoint.rx.is_empty() {
            return Ok(Some(endpoint.rx.len()));
        }
        if let Some((bytes, _)) = endpoint.datagrams.front() {
            return Ok(Some(bytes.len()));
        }
        if endpoint.closed {
            return Ok(Some(0));
        }
        if let Some(errno) = endpoint.error {
            return Err(errno);
        }
        Ok(None)
    }

    fn udp_open(&mut self) -> Result<Handle, u64> {
        let handle = self.handle();
        self.endpoints.insert(handle, Endpoint::default());
        self.commands.push(NetCommand::UdpOpen { handle });
        Ok(handle)
    }

    fn udp_send_to(
        &mut self,
        handle: Handle,
        addr: SocketAddrV4,
        bytes: &[u8],
    ) -> Result<usize, u64> {
        let endpoint = self.endpoints.get(&handle).ok_or(abi::EBADF)?;
        if let Some(errno) = endpoint.error {
            return Err(errno);
        }
        self.commands.push(NetCommand::UdpSendTo {
            handle,
            addr,
            bytes: bytes.to_vec(),
        });
        Ok(bytes.len())
    }

    fn udp_recv_from(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64> {
        let endpoint = self.endpoints.get_mut(&handle).ok_or(abi::EBADF)?;
        match endpoint.datagrams.pop_front() {
            Some((mut bytes, from)) => {
                bytes.truncate(max.min(0x1_0000));
                Ok(Some((bytes, from)))
            }
            None => match endpoint.error {
                Some(errno) => Err(errno),
                None => Ok(None),
            },
        }
    }

    fn udp_peek_from(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64> {
        let endpoint = self.endpoints.get(&handle).ok_or(abi::EBADF)?;
        match endpoint.datagrams.front() {
            Some((bytes, from)) => Ok(Some((bytes[..bytes.len().min(max)].to_vec(), *from))),
            None => match endpoint.error {
                Some(errno) => Err(errno),
                None => Ok(None),
            },
        }
    }

    fn readable(&mut self, handle: Handle) -> bool {
        self.endpoints
            .get(&handle)
            .is_some_and(|endpoint| endpoint.readable())
    }

    fn local_addr(&mut self, handle: Handle) -> Option<SocketAddrV4> {
        self.endpoints.get(&handle).and_then(|e| e.local)
    }

    fn close(&mut self, handle: Handle) {
        if self.endpoints.remove(&handle).is_some() {
            self.commands.push(NetCommand::Close { handle });
        }
    }

    fn wait_ready(&mut self, handles: &[Handle], _timeout: Duration) -> bool {
        // Never blocks: the host owns the transport, so the scheduler pauses
        // the machine instead (see `host_driven`). Answers honestly for the
        // data already delivered.
        handles.iter().any(|&h| self.readable(h))
    }
}

// ── The network quota ───────────────────────────────────────────────────────

/// Bytes the guest has moved across the broker boundary, both ways.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetUsage {
    /// Payload the guest handed the broker to send.
    pub sent_bytes: usize,
    /// Payload the broker handed back to the guest.
    pub received_bytes: usize,
    pub total_bytes: usize,
}

/// The meter behind the network quota: what has crossed the broker boundary,
/// and the ceiling on it.
///
/// Only guest payload is counted — the bytes of `send`/`recv` in either
/// direction. Connection setup, DNS the host does on the guest's behalf, TCP
/// and TLS framing, and whatever the transport spends underneath are not
/// counted, because the broker interface never sees them. So the number here
/// is a floor on what a tab actually moves, not an exact wire total, and a
/// host should size the budget with that slack in mind.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetMeter {
    sent: usize,
    received: usize,
    budget: Option<usize>,
}

pub type MeterRef = Rc<RefCell<NetMeter>>;

impl NetMeter {
    pub fn new() -> Self {
        Self::default()
    }

    /// What has crossed so far.
    pub fn usage(&self) -> NetUsage {
        NetUsage {
            sent_bytes: self.sent,
            received_bytes: self.received,
            total_bytes: self.sent.saturating_add(self.received),
        }
    }

    /// Sets the ceiling on sent plus received bytes, or clears it with None.
    /// Takes effect on the next operation, so a host may set it before or
    /// after attaching its broker.
    pub fn set_budget(&mut self, bytes: Option<usize>) {
        self.budget = bytes;
    }

    /// Bytes still allowed through, or None when no budget is set.
    pub fn headroom(&self) -> Option<usize> {
        self.budget
            .map(|budget| budget.saturating_sub(self.usage().total_bytes))
    }

    /// How much of a `want`-byte request may go ahead.
    fn allowance(&self, want: usize) -> usize {
        match self.headroom() {
            Some(left) => want.min(left),
            None => want,
        }
    }

    fn charge(&mut self, sent: usize, received: usize) {
        self.sent = self.sent.saturating_add(sent);
        self.received = self.received.saturating_add(received);
    }
}

/// Wraps a broker so every byte the guest sends or receives is charged
/// against a [`NetMeter`], and refused once the budget is spent.
///
/// The wrapper sits at the broker boundary rather than in the socket
/// syscalls: every path the guest has to host networking already goes
/// through this trait, so there is no send or receive that can be added
/// later and quietly escape the meter.
///
/// Over budget, the guest sees `EPERM` — the errno Linux returns when local
/// policy rejects the packet, which is what this is. Where a partial
/// operation is honest the request is clipped instead: a stream send or
/// receive is short, which every correct TCP caller already handles. A
/// datagram is never clipped, because half a datagram is a corrupt message —
/// a `sendto` that does not fit the remaining budget is refused whole.
pub struct MeteredBroker {
    inner: BrokerRef,
    meter: MeterRef,
}

impl MeteredBroker {
    pub fn new(inner: BrokerRef, meter: MeterRef) -> Self {
        Self { inner, meter }
    }

    /// The allowance for a `want`-byte transfer, or `EPERM` when the budget
    /// leaves no room for any of it.
    fn allow(&self, want: usize) -> Result<usize, u64> {
        let allowance = self.meter.borrow().allowance(want);
        if allowance == 0 && want > 0 {
            tracing::warn!(want, "network: over the byte budget");
            return Err(abi::EPERM);
        }
        Ok(allowance)
    }
}

impl NetworkBroker for MeteredBroker {
    fn host_driven(&self) -> bool {
        self.inner.borrow().host_driven()
    }

    fn tcp_connect(&mut self, addr: SocketAddrV4) -> Result<Handle, u64> {
        self.inner.borrow_mut().tcp_connect(addr)
    }

    fn tcp_connect_v6(&mut self, addr: SocketAddrV6) -> Result<Handle, u64> {
        self.inner.borrow_mut().tcp_connect_v6(addr)
    }

    fn tcp_send(&mut self, handle: Handle, bytes: &[u8]) -> Result<usize, u64> {
        let allowance = self.allow(bytes.len())?;
        let sent = self
            .inner
            .borrow_mut()
            .tcp_send(handle, &bytes[..allowance])?;
        self.meter.borrow_mut().charge(sent, 0);
        Ok(sent)
    }

    fn tcp_recv(&mut self, handle: Handle, max: usize) -> Result<RecvOutcome, u64> {
        let allowance = self.allow(max)?;
        let outcome = self.inner.borrow_mut().tcp_recv(handle, allowance)?;
        if let RecvOutcome::Data(bytes) = &outcome {
            self.meter.borrow_mut().charge(0, bytes.len());
        }
        Ok(outcome)
    }

    fn tcp_shutdown_write(&mut self, handle: Handle) -> Result<(), u64> {
        self.inner.borrow_mut().tcp_shutdown_write(handle)
    }

    fn pending_read_bytes(&mut self, handle: Handle) -> Result<Option<usize>, u64> {
        // Inspection does not cross the broker boundary, so it must not
        // consume quota.  The following actual receive remains metered.
        self.inner.borrow_mut().pending_read_bytes(handle)
    }

    fn udp_open(&mut self) -> Result<Handle, u64> {
        self.inner.borrow_mut().udp_open()
    }

    fn udp_open_v6(&mut self) -> Result<Handle, u64> {
        self.inner.borrow_mut().udp_open_v6()
    }

    fn udp_send_to(
        &mut self,
        handle: Handle,
        addr: SocketAddrV4,
        bytes: &[u8],
    ) -> Result<usize, u64> {
        // Whole datagram or none of it.
        if self.allow(bytes.len())? < bytes.len() {
            tracing::warn!(
                len = bytes.len(),
                "network: datagram does not fit the byte budget"
            );
            return Err(abi::EPERM);
        }
        let sent = self.inner.borrow_mut().udp_send_to(handle, addr, bytes)?;
        self.meter.borrow_mut().charge(sent, 0);
        Ok(sent)
    }

    fn udp_recv_from(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64> {
        // Clipping `max` here is the truncation a small receive buffer
        // already produces, not a new failure mode.
        let allowance = self.allow(max)?;
        let received = self.inner.borrow_mut().udp_recv_from(handle, allowance)?;
        if let Some((bytes, _)) = &received {
            self.meter.borrow_mut().charge(0, bytes.len());
        }
        Ok(received)
    }

    fn udp_peek_from(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64> {
        let allowance = self.allow(max)?;
        self.inner.borrow_mut().udp_peek_from(handle, allowance)
    }

    fn udp_send_to_v6(
        &mut self,
        handle: Handle,
        addr: SocketAddrV6,
        bytes: &[u8],
    ) -> Result<usize, u64> {
        if self.allow(bytes.len())? < bytes.len() {
            return Err(abi::EPERM);
        }
        let sent = self
            .inner
            .borrow_mut()
            .udp_send_to_v6(handle, addr, bytes)?;
        self.meter.borrow_mut().charge(sent, 0);
        Ok(sent)
    }

    fn udp_recv_from_v6(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV6)>, u64> {
        let allowance = self.allow(max)?;
        let received = self
            .inner
            .borrow_mut()
            .udp_recv_from_v6(handle, allowance)?;
        if let Some((bytes, _)) = &received {
            self.meter.borrow_mut().charge(0, bytes.len());
        }
        Ok(received)
    }

    fn udp_peek_from_v6(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV6)>, u64> {
        let allowance = self.allow(max)?;
        self.inner.borrow_mut().udp_peek_from_v6(handle, allowance)
    }

    fn readable(&mut self, handle: Handle) -> bool {
        self.inner.borrow_mut().readable(handle)
    }

    fn local_addr(&mut self, handle: Handle) -> Option<SocketAddrV4> {
        self.inner.borrow_mut().local_addr(handle)
    }

    fn close(&mut self, handle: Handle) {
        self.inner.borrow_mut().close(handle)
    }

    fn wait_ready(&mut self, handles: &[Handle], timeout: Duration) -> bool {
        self.inner.borrow_mut().wait_ready(handles, timeout)
    }
}
