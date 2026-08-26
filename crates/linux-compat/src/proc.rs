//! Processes, threads, and the cooperative scheduler.
//!
//! One virtual CPU runs one task at a time; every other task is parked with
//! its CPU snapshot and virtual memory map. Switches happen only at
//! well-defined syscall boundaries (blocking calls, `sched_yield`, task
//! exit), so scheduling is deterministic: the first ready task in queue
//! order always runs next.
//!
//! Memory: `fork` marks the parent's pages copy-on-write and gives the
//! child a cloned map (both sides copy pages on write). Threads
//! (`CLONE_VM`) share the same map snapshot. Parking uses
//! `take_virtual_mapping`/`restore_virtual_mapping`, so page contents are
//! never copied on a switch.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    rc::Rc,
};

use icicle_cpu::CpuSnapshot;
use icicle_mem::VirtualMemoryMap;

use crate::fd::{EventFdRef, FdTable, NetRef, PipeRef, TimerFdRef};
use crate::SigAction;

pub const ROOT_PID: u64 = 1000;

/// Per-process (or per-thread) state. This is everything a task owns
/// besides its CPU registers and memory map.
pub struct Process {
    pub pid: u64,
    /// Thread-group id: `getpid` reports this; threads share it.
    pub tgid: u64,
    pub ppid: u64,
    /// Shared with sibling threads (`CLONE_FILES`); `fork` deep-clones the
    /// table (entries still share open file descriptions).
    pub fds: Rc<RefCell<FdTable>>,
    pub cwd: usize,
    pub umask: u32,
    pub brk_end: u64,
    pub mmap_next: u64,
    /// Signal dispositions are process-wide (shared by every thread in the
    /// group), matching Linux: registering a handler on one thread makes it
    /// visible to the whole process. `fork` gets its own copy; a new thread
    /// shares the table.
    pub sigactions: Rc<RefCell<HashMap<u64, SigAction>>>,
    pub sigmask: u64,
    /// Signals pending delivery to *this* thread (bit `sig - 1`). Only ever
    /// holds signals that have a user handler and are unblocked for the
    /// thread, so a set bit means "deliverable now". Not inherited.
    pub pending_signals: u64,
    /// Saved CPU state for each signal handler currently running on this
    /// thread (innermost last), restored by `rt_sigreturn`. Paired with the
    /// sigmask to reinstate when the handler returns.
    pub signal_saved: Vec<Box<CpuSnapshot>>,
    pub signal_saved_mask: Vec<u64>,
    pub exe_path: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
    pub envp: Vec<Vec<u8>>,
    /// `set_tid_address` / `CLONE_CHILD_CLEARTID`: zeroed and futex-woken
    /// when this task exits (pthread_join relies on it).
    pub clear_child_tid: u64,
    /// Set on a vfork child: fired (once) when the child replaces its image
    /// via `execve` or exits, releasing the parent parked in
    /// [`ParkState::VforkDone`]. Never inherited across fork/clone.
    pub vfork_done: Option<Rc<Cell<bool>>>,
}

impl Process {
    pub fn initial() -> Self {
        Self {
            pid: ROOT_PID,
            tgid: ROOT_PID,
            ppid: 1,
            fds: Rc::new(RefCell::new(FdTable::new())),
            cwd: crate::vfs::ROOT,
            umask: 0o022,
            brk_end: 0,
            mmap_next: crate::MMAP_BASE,
            sigactions: Rc::new(RefCell::new(HashMap::new())),
            sigmask: 0,
            pending_signals: 0,
            signal_saved: Vec::new(),
            signal_saved_mask: Vec::new(),
            exe_path: Vec::new(),
            argv: Vec::new(),
            envp: Vec::new(),
            clear_child_tid: 0,
            vfork_done: None,
        }
    }

    /// Child state for `fork` (own descriptor table, shared descriptions).
    pub fn fork_child(&self, pid: u64) -> Self {
        Self {
            pid,
            tgid: pid,
            ppid: self.tgid,
            fds: Rc::new(RefCell::new(self.fds.borrow().clone())),
            cwd: self.cwd,
            umask: self.umask,
            brk_end: self.brk_end,
            mmap_next: self.mmap_next,
            // A new process gets its own copy of the signal dispositions.
            sigactions: Rc::new(RefCell::new(self.sigactions.borrow().clone())),
            sigmask: self.sigmask,
            pending_signals: 0,
            signal_saved: Vec::new(),
            signal_saved_mask: Vec::new(),
            exe_path: self.exe_path.clone(),
            argv: self.argv.clone(),
            envp: self.envp.clone(),
            clear_child_tid: 0,
            vfork_done: None,
        }
    }

    /// Sibling state for a thread (`CLONE_VM | CLONE_THREAD`): shared
    /// descriptor table, shared thread-group id.
    pub fn thread_sibling(&self, tid: u64) -> Self {
        Self {
            pid: tid,
            tgid: self.tgid,
            ppid: self.ppid,
            fds: Rc::clone(&self.fds),
            cwd: self.cwd,
            umask: self.umask,
            brk_end: self.brk_end,
            mmap_next: self.mmap_next,
            // Threads share one signal-disposition table.
            sigactions: Rc::clone(&self.sigactions),
            sigmask: self.sigmask,
            pending_signals: 0,
            signal_saved: Vec::new(),
            signal_saved_mask: Vec::new(),
            exe_path: self.exe_path.clone(),
            argv: self.argv.clone(),
            envp: self.envp.clone(),
            clear_child_tid: 0,
            vfork_done: None,
        }
    }
}

/// Why a parked task is not runnable (or that it is).
pub enum ParkState {
    /// Runnable; waiting only for the CPU.
    Ready,
    /// `wait4`: waiting for a child to become a zombie. `pid` follows the
    /// wait4 convention (-1 = any child, >0 = that specific child).
    WaitChild { pid: i64 },
    /// `FUTEX_WAIT` on `addr`; `woken` is set by `FUTEX_WAKE`. With a
    /// deadline, expiry wakes the task and the scheduler patches the
    /// return value to `-ETIMEDOUT`.
    Futex {
        addr: u64,
        woken: bool,
        deadline: Option<u64>,
    },
    /// Blocked reading an empty pipe.
    PipeRead { pipe: PipeRef },
    /// Blocked writing a full pipe.
    PipeWrite { pipe: PipeRef },
    /// Blocked until any watch is ready or the deadline passes
    /// (blocking reads on eventfd/timerfd/sockets, epoll_wait, select).
    Waiting {
        watches: Vec<Watch>,
        deadline: Option<u64>,
    },
    /// vfork/posix_spawn parent: suspended until the child replaces its
    /// image via `execve` or exits (`done` fires). Like the kernel's vfork
    /// wait, this is not interruptible by signals.
    VforkDone { done: Rc<Cell<bool>> },
}

/// One readiness source a parked task may wait on.
pub enum Watch {
    PipeReadable(PipeRef),
    PipeWritable(PipeRef),
    Event(EventFdRef),
    Timer(TimerFdRef),
    /// Network socket readability, checked through the broker.
    NetReadable(NetRef),
    /// Immediately ready (regular files and similar).
    Always,
}

impl Watch {
    pub fn ready(&self, now: u64) -> bool {
        match self {
            Watch::PipeReadable(pipe) => {
                let pipe = pipe.borrow();
                !pipe.data.is_empty() || pipe.writers == 0
            }
            Watch::PipeWritable(pipe) => {
                let pipe = pipe.borrow();
                pipe.data.len() < crate::PIPE_CAPACITY || pipe.readers == 0
            }
            Watch::Event(event) => event.borrow().count > 0,
            Watch::Timer(timer) => timer.borrow().next_expiry.is_some_and(|t| now >= t),
            Watch::NetReadable(socket) => {
                let socket = socket.borrow();
                match socket.handle {
                    Some(handle) => socket.broker.borrow_mut().readable(handle),
                    None => false,
                }
            }
            Watch::Always => true,
        }
    }
}

pub struct ParkedTask {
    pub proc: Process,
    pub cpu: Box<CpuSnapshot>,
    pub state: ParkState,
}

/// A terminated process whose parent has not reaped it yet.
pub struct Zombie {
    pub pid: u64,
    pub ppid: u64,
    /// Encoded wait status (exit code or fatal signal).
    pub status: i32,
}

#[derive(Default)]
pub struct Scheduler {
    pub parked: Vec<ParkedTask>,
    pub zombies: Vec<Zombie>,
    /// Address spaces of thread groups that are entirely parked. The
    /// running group's map lives in the CPU's MMU; sibling threads share
    /// one map, so an mmap by any thread is visible to all of them.
    pub group_maps: HashMap<u64, VirtualMemoryMap>,
    next_pid: u64,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            parked: Vec::new(),
            zombies: Vec::new(),
            group_maps: HashMap::new(),
            next_pid: ROOT_PID + 1,
        }
    }

    /// True if any parked task belongs to thread group `tgid`.
    pub fn group_has_parked(&self, tgid: u64) -> bool {
        self.parked.iter().any(|t| t.proc.tgid == tgid)
    }

    pub fn next_pid(&mut self) -> u64 {
        let pid = self.next_pid;
        self.next_pid += 1;
        pid
    }

    /// True if the process `ppid` has any child (parked, running elsewhere,
    /// or zombie) matching the wait4 `pid` filter.
    pub fn has_child(&self, ppid: u64, pid_filter: i64) -> bool {
        let matches = |child_pid: u64, child_ppid: u64| {
            child_ppid == ppid && (pid_filter == -1 || child_pid == pid_filter as u64)
        };
        self.zombies.iter().any(|z| matches(z.pid, z.ppid))
            || self
                .parked
                .iter()
                .any(|t| matches(t.proc.tgid, t.proc.ppid))
    }

    /// Takes a zombie child of `ppid` matching the wait4 `pid` filter.
    pub fn take_zombie(&mut self, ppid: u64, pid_filter: i64) -> Option<Zombie> {
        let index = self
            .zombies
            .iter()
            .position(|z| z.ppid == ppid && (pid_filter == -1 || z.pid == pid_filter as u64))?;
        Some(self.zombies.remove(index))
    }

    /// Marks up to `count` tasks blocked on the futex at `addr` as woken.
    pub fn futex_wake(&mut self, addr: u64, count: u64) -> u64 {
        let mut woken = 0;
        for task in &mut self.parked {
            if woken >= count {
                break;
            }
            if let ParkState::Futex {
                addr: waiting,
                woken: flag,
                ..
            } = &mut task.state
            {
                if *waiting == addr && !*flag {
                    *flag = true;
                    woken += 1;
                }
            }
        }
        woken
    }

    /// Index of the first ready task, in stable queue order (deterministic).
    /// `now` is the deterministic clock in nanoseconds.
    pub fn find_ready(&self, now: u64) -> Option<usize> {
        self.parked.iter().position(|task| {
            // A deliverable pending signal interrupts any blocking wait
            // except the uninterruptible vfork suspension: a vfork parent
            // must not observe anything (including a handler running on its
            // borrowed stack semantics) until the child execs or exits.
            if task.proc.pending_signals != 0 && !matches!(task.state, ParkState::VforkDone { .. })
            {
                return true;
            }
            match &task.state {
                ParkState::Ready => true,
                ParkState::Futex {
                    woken, deadline, ..
                } => *woken || deadline.is_some_and(|d| now >= d),
                ParkState::WaitChild { pid } => self
                    .zombies
                    .iter()
                    .any(|z| z.ppid == task.proc.tgid && (*pid == -1 || z.pid == *pid as u64)),
                ParkState::PipeRead { pipe } => {
                    let pipe = pipe.borrow();
                    !pipe.data.is_empty() || pipe.writers == 0
                }
                ParkState::PipeWrite { pipe } => {
                    let pipe = pipe.borrow();
                    pipe.data.len() < crate::PIPE_CAPACITY || pipe.readers == 0
                }
                ParkState::Waiting { watches, deadline } => {
                    deadline.is_some_and(|d| now >= d) || watches.iter().any(|w| w.ready(now))
                }
                ParkState::VforkDone { done } => done.get(),
            }
        })
    }

    /// Earliest wake-up deadline among parked tasks (timerfd expiries and
    /// wait timeouts), used to warp the deterministic clock when the whole
    /// system is idle.
    pub fn earliest_deadline(&self) -> Option<u64> {
        self.parked
            .iter()
            .flat_map(|task| match &task.state {
                ParkState::Futex {
                    deadline: Some(deadline),
                    ..
                } => vec![*deadline],
                ParkState::Waiting { watches, deadline } => {
                    let timers = watches.iter().filter_map(|w| match w {
                        Watch::Timer(t) => t.borrow().next_expiry,
                        _ => None,
                    });
                    timers.chain(*deadline).collect::<Vec<_>>()
                }
                _ => Vec::new(),
            })
            .min()
    }

    /// Broker handles that parked tasks are waiting to read, for the idle
    /// host wait.
    pub fn net_watch_handles(&self) -> Vec<crate::net::Handle> {
        self.parked
            .iter()
            .flat_map(|task| match &task.state {
                ParkState::Waiting { watches, .. } => watches
                    .iter()
                    .filter_map(|w| match w {
                        Watch::NetReadable(s) => s.borrow().handle,
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect()
    }
}
