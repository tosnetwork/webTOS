//! The network broker boundary.
//!
//! Guest sockets never touch host networking directly: every operation goes
//! through a [`NetworkBroker`] the host attaches explicitly. A machine with
//! no broker has no network — `socket(2)` fails with `EAFNOSUPPORT` — which
//! makes "denied by default" the structural baseline the roadmap requires.
//!
//! The native broker below drives non-blocking `std::net` sockets and is
//! used by tests and native hosts. The browser host will provide a broker
//! that translates to browser-available transports instead.

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
                Ok(n) => return Ok(n),
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
            Ok(0) => Ok(RecvOutcome::Closed),
            Ok(n) => {
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
        let socket =
            std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| io_errno(&e))?;
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
