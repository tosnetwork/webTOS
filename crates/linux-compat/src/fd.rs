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
    /// Monotone change counter, bumped on every write, read, and end close.
    /// Edge-triggered epoll re-arms a delivered edge when this moves, so a
    /// new write is a new edge even while the pipe stays readable (matching
    /// the kernel, where each wakeup re-queues the epoll item).
    pub activity: u64,
}

pub type PipeRef = Rc<RefCell<PipeInner>>;

/// A pseudoterminal pair. `m2s` carries master writes to the slave (terminal
/// input); `s2m` carries slave writes to the master (terminal output, subject
/// to `OPOST`/`ONLCR`). One `Pty` is shared by both the master and slave
/// descriptors.
#[derive(Debug)]
pub struct Pty {
    pub id: u64,
    pub m2s: std::collections::VecDeque<u8>,
    pub s2m: std::collections::VecDeque<u8>,
    /// 36-byte `struct termios` (little-endian fields), settable via TCSETS.
    pub termios: [u8; 36],
    /// `struct winsize` as [rows, cols, xpixel, ypixel].
    pub winsize: [u16; 4],
    /// Live master descriptors; the slave sees EOF/hangup once this hits 0.
    pub masters: u32,
    /// Live slave descriptors; the master sees EOF once this hits 0 (after a
    /// slave has existed).
    pub slaves: u32,
    /// Set once a slave has been opened, so a master read before any slave
    /// exists blocks rather than reporting EOF.
    pub slave_ever_opened: bool,
    /// Monotone change counter; edge-triggered epoll re-arms on it.
    pub activity: u64,
    /// Foreground process group: set by the controlling process (TIOCSCTTY)
    /// or TIOCSPGRP, and the target for terminal-generated signals such as
    /// SIGWINCH on a window-size change.
    pub fg_pgrp: u64,
    /// Session which owns this terminal. Separate from `fg_pgrp`: shells
    /// move foreground jobs between process groups without changing session.
    pub session_id: u64,
}

impl Pty {
    pub fn new(id: u64) -> Self {
        // Cooked-mode defaults matching openpty(): ICRNL|IXON, OPOST|ONLCR,
        // CS8|CREAD, ISIG|ICANON|ECHO|ECHOE|ECHOK.
        let mut termios = [0_u8; 36];
        termios[0..4].copy_from_slice(&0x0500_u32.to_le_bytes());
        termios[4..8].copy_from_slice(&0x0005_u32.to_le_bytes());
        termios[8..12].copy_from_slice(&0x00bf_u32.to_le_bytes());
        termios[12..16].copy_from_slice(&0x8a3b_u32.to_le_bytes());
        // c_cc, which a program reads to learn which keys mean what. Leaving
        // it zeroed advertises NUL as the interrupt character and VMIN 0,
        // which is not what any terminal library expects.
        termios[C_CC..].copy_from_slice(&[
            3,   // VINTR   ^C
            28,  // VQUIT   ^\
            127, // VERASE  DEL
            21,  // VKILL   ^U
            4,   // VEOF    ^D
            0,   // VTIME
            1,   // VMIN
            0,   // VSWTC
            17,  // VSTART  ^Q
            19,  // VSTOP   ^S
            26,  // VSUSP   ^Z
            0,   // VEOL
            18,  // VREPRINT ^R
            15,  // VDISCARD ^O
            23,  // VWERASE  ^W
            22,  // VLNEXT   ^V
            0,   // VEOL2
            0, 0,
        ]);
        Self {
            id,
            m2s: std::collections::VecDeque::new(),
            s2m: std::collections::VecDeque::new(),
            termios,
            winsize: [24, 80, 0, 0],
            masters: 1,
            slaves: 0,
            slave_ever_opened: false,
            activity: 0,
            fg_pgrp: 0,
            session_id: 0,
        }
    }

    /// True when `OPOST` (c_oflag bit 0) and `ONLCR` (c_oflag bit 2) are set,
    /// so a slave-written `\n` is expanded to `\r\n` on the way to the master.
    pub fn onlcr(&self) -> bool {
        let oflag = u32::from_le_bytes(self.termios[4..8].try_into().expect("size"));
        oflag & 0x1 != 0 && oflag & 0x4 != 0
    }

    /// True when `TOSTOP` (c_lflag bit 8) is set, so a background process
    /// group writing to the terminal is signalled rather than allowed. Off in
    /// the default termios, which is why background output normally appears.
    pub fn tostop(&self) -> bool {
        u32::from_le_bytes(self.termios[12..16].try_into().expect("size")) & 0x100 != 0
    }

    /// True when `ISIG` (c_lflag bit 0) is set, so the interrupt and quit
    /// characters generate signals instead of arriving as data.
    fn isig(&self) -> bool {
        u32::from_le_bytes(self.termios[12..16].try_into().expect("size")) & 0x1 != 0
    }

    /// Queues terminal input, applying the input side of the line discipline.
    ///
    /// With `ISIG` set, the interrupt and quit characters are not data: the
    /// kernel consumes the character, discards whatever input was already
    /// queued, and raises a signal on the foreground process group. Returns
    /// the signal to raise, which the caller delivers — a `Pty` has no view of
    /// the process table. A program that puts the terminal in raw mode clears
    /// `ISIG` and then reads `\x03` as an ordinary byte, which is how a
    /// full-screen editor keeps its own key bindings.
    ///
    /// The suspend character raises SIGTSTP the same way: the scheduler has
    /// a stopped task state, and `wait4(WUNTRACED)` reports the stop to the
    /// job-control shell.
    pub fn feed_input(&mut self, bytes: &[u8]) -> Option<u64> {
        const SIGINT: u64 = 2;
        const SIGQUIT: u64 = 3;
        const SIGTSTP: u64 = 20;
        if !self.isig() {
            self.m2s.extend(bytes.iter().copied());
            self.activity += 1;
            return None;
        }
        let (intr, quit, susp) = (
            self.termios[C_CC],
            self.termios[C_CC + 1],
            self.termios[C_CC + 10],
        );
        let mut signal = None;
        for &byte in bytes {
            // A disabled character is encoded as NUL and must not match a
            // typed NUL.
            let raised = if intr != 0 && byte == intr {
                Some(SIGINT)
            } else if quit != 0 && byte == quit {
                Some(SIGQUIT)
            } else if susp != 0 && byte == susp {
                Some(SIGTSTP)
            } else {
                None
            };
            match raised {
                Some(sig) => {
                    self.m2s.clear();
                    signal = Some(sig);
                }
                None => self.m2s.push_back(byte),
            }
        }
        self.activity += 1;
        signal
    }
}

/// Offset of `c_cc` in the 36-byte `struct termios`: four 32-bit flag words
/// and the one-byte `c_line`.
const C_CC: usize = 17;

pub type PtyRef = Rc<RefCell<Pty>>;

/// eventfd counter state.
#[derive(Debug, Default)]
pub struct EventFdInner {
    pub count: u64,
    pub semaphore: bool,
    /// Monotone change counter; see [`PipeInner::activity`].
    pub activity: u64,
}

pub type EventFdRef = Rc<RefCell<EventFdInner>>;

/// One watch: the path a program asked about and the events it asked for.
#[derive(Debug, Clone)]
pub struct Watch {
    pub descriptor: i32,
    /// The node being watched. A watch follows the file, not the name: the
    /// kernel watches an inode, so renaming what is watched does not move the
    /// watch, and two names for one file are one watch.
    pub node: usize,
    /// The path it was asked for, kept so a program can be told what it
    /// asked about rather than a number it never chose.
    pub path: Vec<u8>,
    pub mask: u32,
}

/// An inotify instance: what a program is watching, and what has happened
/// that it has not read yet.
///
/// Events are queued rather than delivered, because a watcher reads on its
/// own schedule and the change that interests it happens on someone else's.
/// The queue has a ceiling: a program that stops reading must not be able to
/// grow this without end, and the kernel answers that case with `IN_Q_OVERFLOW`
/// — one event that says "you missed some" rather than a silent gap.
#[derive(Debug, Default)]
pub struct InotifyInner {
    pub watches: Vec<Watch>,
    /// Next watch descriptor. Kernel descriptors start at 1 and do not
    /// repeat while an instance lives, so a stale one is recognisably stale.
    pub next_descriptor: i32,
    pub queue: std::collections::VecDeque<InotifyEvent>,
    /// Set when the queue filled and events were dropped; the next read
    /// reports the overflow before anything else.
    pub overflowed: bool,
    /// Monotone change counter; edge-triggered epoll re-arms on it.
    pub activity: u64,
}

/// A queued event, in the shape `read` will serialise it.
#[derive(Debug, Clone)]
pub struct InotifyEvent {
    pub descriptor: i32,
    pub mask: u32,
    pub cookie: u32,
    /// The entry within a watched directory, empty when the watch is on the
    /// file itself.
    pub name: Vec<u8>,
}

/// The most events one instance will hold. Past this the queue drops and says
/// so, which is what the kernel does and what a watcher already handles.
pub const INOTIFY_QUEUE_LIMIT: usize = 16384;

pub type InotifyRef = Rc<RefCell<InotifyInner>>;

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
    /// Linux address family selected at `socket(2)`. The broker keeps the
    /// family so `connect`, getpeername and getsockname cannot silently
    /// reinterpret an IPv6 endpoint as IPv4.
    pub family: u64,
    /// Broker endpoint; created lazily for UDP, at connect for TCP.
    pub handle: Option<Handle>,
    /// Destination set by `connect` (TCP peer, or default UDP target).
    pub peer: Option<std::net::SocketAddr>,
    /// Kernel-local protocol bytes (currently the deterministic, read-only
    /// NETLINK_ROUTE address dump). They never cross the host network broker.
    pub local_rx: std::collections::VecDeque<u8>,
    /// Kernel-assigned local port ID for a local protocol socket. NETLINK
    /// uses the thread-group's `getpid()` value, not the calling thread ID.
    pub local_protocol_id: u32,
    /// Monotone counter bumped on every guest send/recv on this socket.
    /// Edge-triggered epoll re-arms a delivered edge when it moves: once the
    /// guest consumed some of the readable data, still-pending bytes are a
    /// new edge (runtimes that stop reading after a partial fill rely on it).
    pub activity: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Tcp,
    Udp,
    /// A local-domain client socket. The compatibility layer models its
    /// kernel-visible creation and absent-path error separately from the
    /// brokered IP transport.
    Unix,
    NetlinkRoute,
}

impl std::fmt::Debug for NetSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetSocket")
            .field("kind", &self.kind)
            .field("family", &self.family)
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
    /// `EPOLLONESHOT` entries that have delivered an event and therefore stay
    /// disabled until userspace rearms them with `EPOLL_CTL_MOD`.  Keep this
    /// separate from edge-trigger suppression: ONESHOT disarms even a
    /// level-triggered, permanently writable descriptor, while EPOLLET
    /// automatically observes later readiness transitions.
    pub oneshot_disabled: std::collections::BTreeSet<u64>,
    /// Edge-triggered (`EPOLLET`) suppression, tracked per direction. Maps a
    /// guest fd to the mask of directions (`EPOLLIN`/`EPOLLOUT`) whose readiness
    /// edge has been delivered and not yet re-armed. A direction is suppressed
    /// while it stays ready; it re-arms when a wait observes that direction
    /// not-ready (then a fresh ready state is a new edge). Keeping the read and
    /// write edges separate is essential: a delivered writable (connect) edge
    /// must not suppress a later readable edge on the same fd. Cleared for a fd
    /// on `EPOLL_CTL_MOD`/`DEL`.
    /// Value is `(delivered direction mask, backing activity at delivery)`.
    /// A direction's edge stays suppressed only while the backing's activity
    /// counter is unchanged; any new write/read/close re-arms it.
    pub edge_fired: std::collections::BTreeMap<u64, (u32, u64)>,
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
    /// Pseudoterminal master (`/dev/ptmx`): writes are terminal input, reads
    /// drain terminal output.
    PtyMaster(PtyRef),
    /// Pseudoterminal slave (`/dev/pts/N`): the process side of the terminal.
    PtySlave(PtyRef),
    /// inotify instance: watches, and the events they have collected.
    Inotify(InotifyRef),
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
                inner.activity += 1;
            }
            Backing::SocketPair { rx, tx } => {
                {
                    let mut rx = rx.borrow_mut();
                    rx.readers = rx.readers.saturating_sub(1);
                    rx.activity += 1;
                }
                let mut tx = tx.borrow_mut();
                tx.writers = tx.writers.saturating_sub(1);
                tx.activity += 1;
            }
            Backing::Net(socket) => {
                let socket = socket.borrow();
                if let Some(handle) = socket.handle {
                    socket.broker.borrow_mut().close(handle);
                }
            }
            Backing::PtyMaster(pty) => {
                let mut pty = pty.borrow_mut();
                pty.masters = pty.masters.saturating_sub(1);
                pty.activity += 1;
            }
            Backing::PtySlave(pty) => {
                let mut pty = pty.borrow_mut();
                pty.slaves = pty.slaves.saturating_sub(1);
                pty.activity += 1;
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

    /// Iterates over occupied descriptors as `(fd, entry)`, for diagnostics.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &FdEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(fd, e)| e.as_ref().map(|e| (fd as u64, e)))
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
