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
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
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
    fn tcp_send(&mut self, handle: Handle, bytes: &[u8]) -> Result<usize, u64>;
    fn tcp_recv(&mut self, handle: Handle, max: usize) -> Result<RecvOutcome, u64>;
    fn tcp_shutdown_write(&mut self, handle: Handle) -> Result<(), u64>;

    /// Creates a UDP endpoint (bound to an ephemeral local port).
    fn udp_open(&mut self) -> Result<Handle, u64>;
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

    /// True when a read on `handle` would make progress (data, EOF, or an
    /// error to report).
    fn readable(&mut self, handle: Handle) -> bool;

    /// The local address of an endpoint, when known.
    fn local_addr(&mut self, handle: Handle) -> Option<SocketAddrV4>;

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
        let stream =
            std::net::TcpStream::connect_timeout(&SocketAddr::V4(target), Duration::from_secs(10))
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
