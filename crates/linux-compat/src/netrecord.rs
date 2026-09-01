//! Recording network input, replaying it without a network, and classifying
//! what a session touched.
//!
//! Every byte the guest receives crosses one interface — [`NetworkBroker`] —
//! at `tcp_recv` and `udp_recv_from`, and every byte it sends crosses it at
//! `tcp_send` and `udp_send_to`. That is the one place a session's network
//! can be observed, so it is where recording belongs.
//!
//! Three things come out of it. A **recording** is the sequence of results
//! the guest consumed, enough to reproduce the session. A **replay** is a
//! broker that answers from a recording and needs no transport at all, so a
//! session captured against a live server runs again offline and the guest
//! cannot tell the difference. A **receipt** is the classification: who the
//! session contacted, how many bytes went each way, and how each connection
//! ended — an opaque session turned into a ledger.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::SocketAddrV4;
use std::rc::Rc;
use std::time::Duration;

use crate::net::{Handle, NetworkBroker, RecvOutcome};

/// One thing that happened at the network interface. Recorded in order, so a
/// replay hands the same results back in the same sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetEvent {
    /// A TCP connect and the handle it was given, or the errno it failed
    /// with. The address is the classification key: it is who was contacted.
    TcpConnect {
        addr: SocketAddrV4,
        result: Result<Handle, u64>,
    },
    /// A UDP endpoint opened.
    UdpOpen { result: Result<Handle, u64> },
    /// Bytes the guest sent. Recorded for the receipt, not for replay: replay
    /// reproduces what the guest *received*, and what it sends it will send
    /// again on its own.
    Sent { handle: Handle, len: usize },
    /// A datagram the guest sent, and where to.
    SentTo {
        handle: Handle,
        addr: SocketAddrV4,
        len: usize,
    },
    /// The result of a receive: the bytes, an EOF, or nothing yet. This is
    /// the input a replay must reproduce exactly.
    Received {
        handle: Handle,
        outcome: RecordedRecv,
    },
    /// A datagram received and its sender.
    ReceivedFrom {
        handle: Handle,
        result: Option<(Vec<u8>, SocketAddrV4)>,
    },
    /// The guest closed a handle.
    Closed { handle: Handle },
}

/// A `RecvOutcome` in a form that can be stored and compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedRecv {
    Data(Vec<u8>),
    Closed,
    WouldBlock,
    Error(u64),
}

/// An ordered log of what crossed the network interface.
#[derive(Debug, Clone, Default)]
pub struct Recording {
    pub events: Vec<NetEvent>,
}

impl Recording {
    /// Classifies the recording into one receipt per connection: who it
    /// reached, how much went each way, and how it ended. This is the
    /// session as a ledger rather than a byte stream.
    pub fn receipts(&self) -> Vec<Receipt> {
        let mut by_handle: BTreeMap<Handle, Receipt> = BTreeMap::new();
        // A handle is only meaningful once a connect gave it out, so a
        // receipt is created there and everything else is attributed to it.
        for event in &self.events {
            match event {
                NetEvent::TcpConnect {
                    addr,
                    result: Ok(handle),
                } => {
                    by_handle
                        .entry(*handle)
                        .or_insert_with(|| Receipt::tcp(*addr, *handle));
                }
                NetEvent::TcpConnect {
                    addr,
                    result: Err(errno),
                } => {
                    // A refused connection has no handle, so it is its own
                    // receipt keyed by a sentinel. It is the outcome most
                    // worth classifying — a session that could not reach
                    // where it meant to.
                    let mut receipt = Receipt::tcp(*addr, Handle::MAX);
                    receipt.outcome = Outcome::Refused(*errno);
                    by_handle.insert(sentinel(&by_handle), receipt);
                }
                NetEvent::UdpOpen { result: Ok(handle) } => {
                    by_handle
                        .entry(*handle)
                        .or_insert_with(|| Receipt::udp(*handle));
                }
                NetEvent::Sent { handle, len } | NetEvent::SentTo { handle, len, .. } => {
                    if let Some(r) = by_handle.get_mut(handle) {
                        r.bytes_sent += len;
                    }
                }
                NetEvent::Received { handle, outcome } => {
                    if let Some(r) = by_handle.get_mut(handle) {
                        match outcome {
                            RecordedRecv::Data(bytes) => r.bytes_received += bytes.len(),
                            RecordedRecv::Closed => r.outcome = Outcome::Closed,
                            RecordedRecv::Error(errno) => r.outcome = Outcome::Error(*errno),
                            RecordedRecv::WouldBlock => {}
                        }
                    }
                }
                NetEvent::ReceivedFrom {
                    handle,
                    result: Some((bytes, _)),
                } => {
                    if let Some(r) = by_handle.get_mut(handle) {
                        r.bytes_received += bytes.len();
                    }
                }
                _ => {}
            }
        }
        by_handle.into_values().collect()
    }
}

/// A sentinel key for a refused connection, which has no handle of its own.
/// Kept above any real handle so ordering stays stable.
fn sentinel(existing: &BTreeMap<Handle, Receipt>) -> Handle {
    let base = Handle::MAX - 1_000_000;
    base + existing.len() as Handle
}

/// What one connection did, for classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub protocol: Protocol,
    /// The peer, when there was one. A UDP endpoint has none until it sends.
    pub peer: Option<SocketAddrV4>,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub outcome: Outcome,
}

impl Receipt {
    fn tcp(addr: SocketAddrV4, _handle: Handle) -> Self {
        Self {
            protocol: Protocol::Tcp,
            peer: Some(addr),
            bytes_sent: 0,
            bytes_received: 0,
            outcome: Outcome::Open,
        }
    }

    fn udp(_handle: Handle) -> Self {
        Self {
            protocol: Protocol::Udp,
            peer: None,
            bytes_sent: 0,
            bytes_received: 0,
            outcome: Outcome::Open,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// How a connection ended, which is the part of a receipt worth acting on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Still open when the recording ended.
    Open,
    /// The peer closed the stream.
    Closed,
    /// The connection was refused before it opened.
    Refused(u64),
    /// A transport error was reported on it.
    Error(u64),
}

/// Wraps a broker and records what crosses it, forwarding every call
/// unchanged. The guest and the real broker behave exactly as they would
/// without it; the recording is a side effect.
pub struct RecordingBroker<B: NetworkBroker> {
    inner: B,
    log: Rc<RefCell<Recording>>,
}

impl<B: NetworkBroker> RecordingBroker<B> {
    pub fn new(inner: B) -> (Self, Rc<RefCell<Recording>>) {
        let log = Rc::new(RefCell::new(Recording::default()));
        (
            Self {
                inner,
                log: Rc::clone(&log),
            },
            log,
        )
    }

    fn record(&self, event: NetEvent) {
        self.log.borrow_mut().events.push(event);
    }
}

impl<B: NetworkBroker> NetworkBroker for RecordingBroker<B> {
    fn host_driven(&self) -> bool {
        self.inner.host_driven()
    }

    fn tcp_connect(&mut self, addr: SocketAddrV4) -> Result<Handle, u64> {
        let result = self.inner.tcp_connect(addr);
        self.record(NetEvent::TcpConnect { addr, result });
        result
    }

    fn tcp_send(&mut self, handle: Handle, bytes: &[u8]) -> Result<usize, u64> {
        let result = self.inner.tcp_send(handle, bytes);
        if let Ok(len) = result {
            self.record(NetEvent::Sent { handle, len });
        }
        result
    }

    fn tcp_recv(&mut self, handle: Handle, max: usize) -> Result<RecvOutcome, u64> {
        let result = self.inner.tcp_recv(handle, max);
        let outcome = match &result {
            Ok(RecvOutcome::Data(bytes)) => RecordedRecv::Data(bytes.clone()),
            Ok(RecvOutcome::Closed) => RecordedRecv::Closed,
            Ok(RecvOutcome::WouldBlock) => RecordedRecv::WouldBlock,
            Err(errno) => RecordedRecv::Error(*errno),
        };
        self.record(NetEvent::Received { handle, outcome });
        result
    }

    fn tcp_shutdown_write(&mut self, handle: Handle) -> Result<(), u64> {
        self.inner.tcp_shutdown_write(handle)
    }

    fn pending_read_bytes(&mut self, handle: Handle) -> Result<Option<usize>, u64> {
        self.inner.pending_read_bytes(handle)
    }

    fn udp_open(&mut self) -> Result<Handle, u64> {
        let result = self.inner.udp_open();
        self.record(NetEvent::UdpOpen { result });
        result
    }

    fn udp_send_to(
        &mut self,
        handle: Handle,
        addr: SocketAddrV4,
        bytes: &[u8],
    ) -> Result<usize, u64> {
        let result = self.inner.udp_send_to(handle, addr, bytes);
        if let Ok(len) = result {
            self.record(NetEvent::SentTo { handle, addr, len });
        }
        result
    }

    fn udp_recv_from(
        &mut self,
        handle: Handle,
        max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64> {
        let result = self.inner.udp_recv_from(handle, max);
        if let Ok(value) = &result {
            self.record(NetEvent::ReceivedFrom {
                handle,
                result: value.clone(),
            });
        }
        result
    }

    fn readable(&mut self, handle: Handle) -> bool {
        self.inner.readable(handle)
    }

    fn local_addr(&mut self, handle: Handle) -> Option<SocketAddrV4> {
        self.inner.local_addr(handle)
    }

    fn close(&mut self, handle: Handle) {
        self.record(NetEvent::Closed { handle });
        self.inner.close(handle);
    }

    fn wait_ready(&mut self, handles: &[Handle], timeout: Duration) -> bool {
        self.inner.wait_ready(handles, timeout)
    }
}

/// Answers from a recording, with no transport behind it. A session captured
/// against a live server replays here offline: the guest issues the same
/// calls and gets the same results back, in order, and cannot tell it is not
/// talking to the network.
pub struct ReplayBroker {
    recording: Recording,
    /// The next event of each kind to serve. Replay walks the log forward,
    /// matching each guest call against the next recorded result of that
    /// kind — the guest is deterministic, so it makes the same calls in the
    /// same order it did when recorded.
    cursor: usize,
}

impl ReplayBroker {
    pub fn new(recording: Recording) -> Self {
        Self {
            recording,
            cursor: 0,
        }
    }

    /// The next recorded event, advancing past it. None when the recording is
    /// spent, which a replayed guest reaches only if it diverges from what it
    /// did when recorded.
    fn next_event(&mut self) -> Option<NetEvent> {
        let event = self.recording.events.get(self.cursor).cloned();
        if event.is_some() {
            self.cursor += 1;
        }
        event
    }
}

impl NetworkBroker for ReplayBroker {
    fn tcp_connect(&mut self, _addr: SocketAddrV4) -> Result<Handle, u64> {
        match self.next_event() {
            Some(NetEvent::TcpConnect { result, .. }) => result,
            _ => Err(crate::abi::ECONNREFUSED),
        }
    }

    fn tcp_send(&mut self, _handle: Handle, bytes: &[u8]) -> Result<usize, u64> {
        // A send has nowhere to go in a replay, but the guest expects it to
        // succeed as it did. Consume the matching record if the next event is
        // a send; accept the bytes regardless, since replay reproduces
        // received input rather than re-checking output.
        if matches!(
            self.recording.events.get(self.cursor),
            Some(NetEvent::Sent { .. })
        ) {
            self.cursor += 1;
        }
        Ok(bytes.len())
    }

    fn tcp_recv(&mut self, _handle: Handle, _max: usize) -> Result<RecvOutcome, u64> {
        match self.next_event() {
            Some(NetEvent::Received { outcome, .. }) => match outcome {
                RecordedRecv::Data(bytes) => Ok(RecvOutcome::Data(bytes)),
                RecordedRecv::Closed => Ok(RecvOutcome::Closed),
                RecordedRecv::WouldBlock => Ok(RecvOutcome::WouldBlock),
                RecordedRecv::Error(errno) => Err(errno),
            },
            // The recording ran out before the guest stopped reading, which
            // means the run diverged from the one recorded. EOF is the safe
            // answer: it ends the read rather than inventing bytes.
            _ => Ok(RecvOutcome::Closed),
        }
    }

    fn tcp_shutdown_write(&mut self, _handle: Handle) -> Result<(), u64> {
        Ok(())
    }

    fn pending_read_bytes(&mut self, _handle: Handle) -> Result<Option<usize>, u64> {
        // Queue inspection must not consume an event: the next real receive
        // still has to replay the same bytes.  The recording preserves the
        // received result, which is enough to reconstruct Linux FIONREAD's
        // next-read size without inventing host input.
        match self.recording.events.get(self.cursor) {
            Some(NetEvent::Received {
                outcome: RecordedRecv::Data(bytes),
                ..
            }) => Ok(Some(bytes.len())),
            Some(NetEvent::Received {
                outcome: RecordedRecv::Closed,
                ..
            }) => Ok(Some(0)),
            Some(NetEvent::Received {
                outcome: RecordedRecv::WouldBlock,
                ..
            }) => Ok(None),
            Some(NetEvent::Received {
                outcome: RecordedRecv::Error(errno),
                ..
            }) => Err(*errno),
            Some(NetEvent::ReceivedFrom {
                result: Some((bytes, _)),
                ..
            }) => Ok(Some(bytes.len())),
            Some(NetEvent::ReceivedFrom { result: None, .. }) | None => Ok(None),
            Some(_) => Ok(None),
        }
    }

    fn udp_open(&mut self) -> Result<Handle, u64> {
        match self.next_event() {
            Some(NetEvent::UdpOpen { result }) => result,
            _ => Err(crate::abi::EAFNOSUPPORT),
        }
    }

    fn udp_send_to(
        &mut self,
        _handle: Handle,
        _addr: SocketAddrV4,
        bytes: &[u8],
    ) -> Result<usize, u64> {
        if matches!(
            self.recording.events.get(self.cursor),
            Some(NetEvent::SentTo { .. })
        ) {
            self.cursor += 1;
        }
        Ok(bytes.len())
    }

    fn udp_recv_from(
        &mut self,
        _handle: Handle,
        _max: usize,
    ) -> Result<Option<(Vec<u8>, SocketAddrV4)>, u64> {
        match self.next_event() {
            Some(NetEvent::ReceivedFrom { result, .. }) => Ok(result),
            _ => Ok(None),
        }
    }

    fn readable(&mut self, _handle: Handle) -> bool {
        // In a replay the next input is always already known, so a read never
        // has to wait.
        true
    }

    fn local_addr(&mut self, _handle: Handle) -> Option<SocketAddrV4> {
        None
    }

    fn close(&mut self, _handle: Handle) {
        if matches!(
            self.recording.events.get(self.cursor),
            Some(NetEvent::Closed { .. })
        ) {
            self.cursor += 1;
        }
    }

    fn wait_ready(&mut self, _handles: &[Handle], _timeout: Duration) -> bool {
        true
    }
}
