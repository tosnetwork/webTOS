//! File descriptors and open file descriptions.
//!
//! Linux semantics: `dup` clones the descriptor but shares the open file
//! description (offset and status flags), so descriptions live behind
//! `Rc<RefCell<..>>`.

use std::{cell::RefCell, rc::Rc};

use crate::net::{BrokerRef, Handle};
use crate::{abi, vfs::Dev};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdStream {
    In,
    Out,
    Err,
}

/// Shared buffer between the two ends of a pipe. Endpoint counts track live
/// open file descriptions, not descriptors: `dup` and `fork` share
/// descriptions, so the counts change only when a description is created or
/// dropped.
#[derive(Debug, Default)]
pub struct PipeInner {
    pub data: std::collections::VecDeque<u8>,
    pub readers: u32,
    pub writers: u32,
}

pub type PipeRef = Rc<RefCell<PipeInner>>;

/// eventfd counter state.
#[derive(Debug, Default)]
pub struct EventFdInner {
    pub count: u64,
    pub semaphore: bool,
}

pub type EventFdRef = Rc<RefCell<EventFdInner>>;

/// timerfd state; times are deterministic nanoseconds (see `LinuxEnv::now`).
#[derive(Debug, Default)]
pub struct TimerFdInner {
    /// Next expiry in absolute nanoseconds; None while disarmed.
    pub next_expiry: Option<u64>,
    /// Interval in nanoseconds (0 = one-shot).
    pub interval: u64,
}

pub type TimerFdRef = Rc<RefCell<TimerFdInner>>;

/// A guest network socket, mediated by the host broker.
pub struct NetSocket {
    pub broker: BrokerRef,
    pub kind: SocketKind,
    /// Broker endpoint; created lazily for UDP, at connect for TCP.
    pub handle: Option<Handle>,
    /// Destination set by `connect` (TCP peer, or default UDP target).
    pub peer: Option<std::net::SocketAddrV4>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Tcp,
    Udp,
}

impl std::fmt::Debug for NetSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetSocket")
            .field("kind", &self.kind)
            .field("handle", &self.handle)
            .field("peer", &self.peer)
            .finish()
    }
}

pub type NetRef = Rc<RefCell<NetSocket>>;

/// epoll interest list: guest fd -> (events mask, user data).
#[derive(Debug, Default)]
pub struct EpollInner {
    pub interests: std::collections::BTreeMap<u64, (u32, u64)>,
    /// Edge-triggered (`EPOLLET`) suppression, tracked per direction. Maps a
    /// guest fd to the mask of directions (`EPOLLIN`/`EPOLLOUT`) whose readiness
    /// edge has been delivered and not yet re-armed. A direction is suppressed
    /// while it stays ready; it re-arms when a wait observes that direction
    /// not-ready (then a fresh ready state is a new edge). Keeping the read and
    /// write edges separate is essential: a delivered writable (connect) edge
    /// must not suppress a later readable edge on the same fd. Cleared for a fd
    /// on `EPOLL_CTL_MOD`/`DEL`.
    pub edge_fired: std::collections::BTreeMap<u64, u32>,
}

pub type EpollRef = Rc<RefCell<EpollInner>>;

#[derive(Debug)]
pub enum Backing {
    /// Host-visible standard stream. Stdin reads EOF; out/err append to the
    /// machine's output buffer.
    Std(StdStream),
    /// Regular VFS file.
    File { node: usize },
    /// Directory opened for reading entries; `cookie` is the getdents64
    /// position.
    Dir { node: usize, cookie: u64 },
    /// Character device.
    Dev(Dev),
    /// One end of an in-memory pipe.
    Pipe { inner: PipeRef, write_end: bool },
    /// One end of a socketpair: read from `rx`, write to `tx`.
    SocketPair { rx: PipeRef, tx: PipeRef },
    /// eventfd counter.
    EventFd(EventFdRef),
    /// timerfd over the deterministic clock.
    TimerFd(TimerFdRef),
    /// Network socket mediated by the host broker.
    Net(NetRef),
    /// epoll instance.
    Epoll(EpollRef),
}

#[derive(Debug)]
pub struct Description {
    pub backing: Backing,
    pub offset: u64,
    /// Status flags from open(2): access mode, O_APPEND, O_NONBLOCK.
    pub flags: u64,
}

impl Description {
    pub fn readable(&self) -> bool {
        self.flags & abi::O_ACCMODE != abi::O_WRONLY
    }

    pub fn writable(&self) -> bool {
        self.flags & abi::O_ACCMODE != abi::O_RDONLY
    }
}

impl Drop for Description {
    fn drop(&mut self) {
        // The last descriptor of a pipe end closing changes the peer's
        // readiness (EOF for readers, EPIPE for writers); blocked tasks
        // re-check at the next scheduling point.
        match &self.backing {
            Backing::Pipe { inner, write_end } => {
                let mut inner = inner.borrow_mut();
                if *write_end {
                    inner.writers = inner.writers.saturating_sub(1);
                } else {
                    inner.readers = inner.readers.saturating_sub(1);
                }
            }
            Backing::SocketPair { rx, tx } => {
                {
                    let mut rx = rx.borrow_mut();
                    rx.readers = rx.readers.saturating_sub(1);
                }
                let mut tx = tx.borrow_mut();
                tx.writers = tx.writers.saturating_sub(1);
            }
            Backing::Net(socket) => {
                let socket = socket.borrow();
                if let Some(handle) = socket.handle {
                    socket.broker.borrow_mut().close(handle);
                }
            }
            _ => {}
        }
    }
}

pub type Ofd = Rc<RefCell<Description>>;

#[derive(Clone)]
pub struct FdEntry {
    pub desc: Ofd,
    pub cloexec: bool,
}

pub struct FdTable {
    entries: Vec<Option<FdEntry>>,
}

impl Clone for FdTable {
    /// `fork` semantics: the child gets its own descriptor table, but every
    /// entry shares the parent's open file descriptions (offsets included).
    fn clone(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }
}

const FD_LIMIT: usize = 1024;

impl FdTable {
    pub fn new() -> Self {
        let std = |stream| {
            Some(FdEntry {
                desc: Rc::new(RefCell::new(Description {
                    backing: Backing::Std(stream),
                    offset: 0,
                    flags: match stream {
                        StdStream::In => abi::O_RDONLY,
                        _ => abi::O_WRONLY,
                    },
                })),
                cloexec: false,
            })
        };
        Self {
            entries: vec![std(StdStream::In), std(StdStream::Out), std(StdStream::Err)],
        }
    }

    pub fn get(&self, fd: u64) -> Result<&FdEntry, u64> {
        self.entries
            .get(fd as usize)
            .and_then(|e| e.as_ref())
            .ok_or(abi::EBADF)
    }

    pub fn get_mut(&mut self, fd: u64) -> Result<&mut FdEntry, u64> {
        self.entries
            .get_mut(fd as usize)
            .and_then(|e| e.as_mut())
            .ok_or(abi::EBADF)
    }

    /// Installs `entry` at the lowest free slot at or above `min`.
    pub fn insert_from(&mut self, min: usize, entry: FdEntry) -> Result<u64, u64> {
        if min >= FD_LIMIT {
            return Err(abi::EINVAL);
        }
        while self.entries.len() < min {
            self.entries.push(None);
        }
        for (fd, slot) in self.entries.iter_mut().enumerate().skip(min) {
            if slot.is_none() {
                *slot = Some(entry);
                return Ok(fd as u64);
            }
        }
        if self.entries.len() >= FD_LIMIT {
            return Err(abi::EMFILE);
        }
        self.entries.push(Some(entry));
        Ok((self.entries.len() - 1) as u64)
    }

    pub fn insert(&mut self, entry: FdEntry) -> Result<u64, u64> {
        self.insert_from(0, entry)
    }

    /// Installs `entry` exactly at `fd`, closing anything already there.
    pub fn insert_at(&mut self, fd: u64, entry: FdEntry) -> Result<u64, u64> {
        let fd = fd as usize;
        if fd >= FD_LIMIT {
            return Err(abi::EBADF);
        }
        while self.entries.len() <= fd {
            self.entries.push(None);
        }
        self.entries[fd] = Some(entry);
        Ok(fd as u64)
    }

    /// Drops every descriptor marked close-on-exec (used by `execve`).
    pub fn close_cloexec(&mut self) {
        for slot in &mut self.entries {
            if slot.as_ref().is_some_and(|entry| entry.cloexec) {
                *slot = None;
            }
        }
    }

    pub fn close(&mut self, fd: u64) -> Result<(), u64> {
        let slot = self.entries.get_mut(fd as usize).ok_or(abi::EBADF)?;
        if slot.take().is_none() {
            return Err(abi::EBADF);
        }
        Ok(())
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}
