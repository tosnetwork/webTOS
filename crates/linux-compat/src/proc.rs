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

use crate::fd::{EventFdRef, FdTable, NetRef, PipeRef, PtyRef, TimerFdRef};
use crate::SigAction;

pub const ROOT_PID: u64 = 1000;

/// Host-side nesting metadata for one guest-visible `rt_sigframe`.
/// Architectural state and the saved mask live only in guest memory; these
/// addresses prevent an unrelated `rt_sigreturn` from consuming another
/// frame and let alternate-stack nesting unwind deterministically.
#[derive(Debug, Clone, Copy)]
pub struct SignalFrame {
    pub frame_base: u64,
    pub fpstate: u64,
    pub on_alt: bool,
}

/// Registration metadata for Linux's per-thread restartable-sequences ABI.
///
/// The ABI block itself remains guest-owned memory.  Keeping only its address
/// here lets the kernel publish a stable virtual CPU at registration and
/// invalidate that registration on teardown without treating hidden host
/// state as the authority for the sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RseqRegistration {
    pub addr: u64,
    pub signature: u32,
}

/// Per-thread registration made through `set_robust_list(2)`. Linux uses the
/// user-owned linked list when a thread exits to mark locks it held as owner
/// dead and wake a waiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RobustListRegistration {
    pub head: u64,
}

/// Per-process (or per-thread) state. This is everything a task owns
/// besides its CPU registers and memory map.
pub struct Process {
    pub pid: u64,
    /// Thread-group id: `getpid` reports this; threads share it.
    pub tgid: u64,
    pub ppid: u64,
    /// Process-group id (job control): inherited across fork, changed by
    /// `setpgid`/`setsid`. Signals sent to `-pgid` reach the whole group.
    pub pgid: u64,
    /// Session ID. A session survives fork and changes only through setsid;
    /// terminal ioctls expose it independently from the foreground group.
    pub sid: u64,
    /// Guest credentials. They are explicit machine configuration rather
    /// than an accidental reflection of the host runner's privilege. New
    /// processes and threads inherit them in the normal Linux manner.
    pub uid: u32,
    pub gid: u32,
    /// Shared with sibling threads (`CLONE_FILES`); `fork` deep-clones the
    /// table (entries still share open file descriptions).
    pub fds: Rc<RefCell<FdTable>>,
    pub cwd: usize,
    pub umask: u32,
    /// Program-break end and mmap search cursor. Address-space state, so
    /// threads (`CLONE_VM`) share them; `fork` gets an independent copy. A
    /// per-thread copy leaves siblings growing `brk` from a stale end, which
    /// violates the kernel contract.
    pub brk_end: Rc<Cell<u64>>,
    pub mmap_next: Rc<Cell<u64>>,
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
    /// Guest-visible signal frames currently active on this thread,
    /// innermost last. This stores nesting metadata, never hidden register or
    /// xstate authority: `rt_sigreturn` restores those bytes from the frame.
    pub signal_frames: Vec<SignalFrame>,
    /// The alternate signal stack, when one is registered: base and size.
    ///
    /// A runtime installs one so a handler has somewhere to run when the
    /// stack it interrupted is the problem — a fault on an exhausted thread
    /// or goroutine stack. Running that handler on the stack that just
    /// overflowed is how the process dies instead of reporting.
    pub altstack: Option<(u64, u64)>,
    /// How many handlers are currently running on it. Nested delivery
    /// continues on the same stack rather than starting over at its top,
    /// which would overwrite the frame of the handler that was interrupted.
    pub altstack_depth: u32,
    pub exe_path: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
    pub envp: Vec<Vec<u8>>,
    /// `set_tid_address` / `CLONE_CHILD_CLEARTID`: zeroed and futex-woken
    /// when this task exits (pthread_join relies on it).
    pub clear_child_tid: u64,
    /// Registered `struct rseq`, if this thread opted into the Linux rseq
    /// ABI. It is strictly per-thread: clone siblings and fork children must
    /// register their own area.
    pub rseq: Option<RseqRegistration>,
    /// Registered robust-futex list. It is per-thread; a new pthread starts
    /// with no registration, while a forked current thread inherits it.
    pub robust_list: Option<RobustListRegistration>,
    /// Address-space id (see [`crate::alloc_asid`]). Threads share it; fork
    /// and execve take a fresh one. Keys the block cache per address space.
    pub asid: u64,
    /// Set on a vfork child: fired (once) when the child replaces its image
    /// via `execve` or exits, releasing the parent parked in
    /// [`ParkState::VforkDone`]. Never inherited across fork/clone.
    pub vfork_done: Option<Rc<Cell<bool>>>,
    /// Job control: a stopped task is parked and stays unrunnable — whatever
    /// its park state says — until SIGCONT clears this.
    pub stopped: bool,
    /// A stop the parent has not yet collected through `wait4(WUNTRACED)`:
    /// the signal that caused it. Held by the thread-group leader.
    pub stop_report: Option<u64>,
    /// Retired work charged to this thread before its current CPU turn.
    /// `cpu_started_at` anchors the running portion in the machine-global
    /// instruction counter; parked tasks have no uncharged interval.
    pub thread_cpu_nanos: u64,
    pub cpu_started_at: u64,
    /// Aggregate retired work for the thread group. Threads share this cell;
    /// fork starts a new accounting domain. One retired instruction is one
    /// virtual nanosecond, matching the runtime's documented CPU-clock scale.
    pub group_cpu_nanos: Rc<Cell<u64>>,
}

impl Process {
    pub fn initial() -> Self {
        Self {
            pid: ROOT_PID,
            tgid: ROOT_PID,
            ppid: 1,
            pgid: ROOT_PID,
            sid: ROOT_PID,
            uid: 0,
            gid: 0,
            fds: Rc::new(RefCell::new(FdTable::new())),
            cwd: crate::vfs::ROOT,
            umask: 0o022,
            brk_end: Rc::new(Cell::new(0)),
            mmap_next: Rc::new(Cell::new(crate::MMAP_BASE)),
            sigactions: Rc::new(RefCell::new(HashMap::new())),
            sigmask: 0,
            pending_signals: 0,
            signal_frames: Vec::new(),
            altstack: None,
            altstack_depth: 0,
            exe_path: Vec::new(),
            argv: Vec::new(),
            envp: Vec::new(),
            clear_child_tid: 0,
            rseq: None,
            robust_list: None,
            asid: 0,
            vfork_done: None,
            stopped: false,
            stop_report: None,
            thread_cpu_nanos: 0,
            cpu_started_at: 0,
            group_cpu_nanos: Rc::new(Cell::new(0)),
        }
    }

    /// Child state for `fork` (own descriptor table, shared descriptions).
    pub fn fork_child(&self, pid: u64) -> Self {
        Self {
            pid,
            tgid: pid,
            ppid: self.tgid,
            pgid: self.pgid,
            sid: self.sid,
            uid: self.uid,
            gid: self.gid,
            fds: Rc::new(RefCell::new(self.fds.borrow().clone())),
            cwd: self.cwd,
            umask: self.umask,
            brk_end: Rc::new(Cell::new(self.brk_end.get())),
            mmap_next: Rc::new(Cell::new(self.mmap_next.get())),
            // A new process gets its own copy of the signal dispositions.
            sigactions: Rc::new(RefCell::new(self.sigactions.borrow().clone())),
            sigmask: self.sigmask,
            pending_signals: 0,
            signal_frames: Vec::new(),
            // A fork inherits the registration; a new thread does not, since
            // the memory it names is the registering thread's stack and two
            // threads must not run handlers on one.
            altstack: self.altstack,
            altstack_depth: 0,
            exe_path: self.exe_path.clone(),
            argv: self.argv.clone(),
            envp: self.envp.clone(),
            clear_child_tid: 0,
            rseq: None,
            robust_list: self.robust_list,
            asid: crate::alloc_asid(),
            vfork_done: None,
            stopped: false,
            stop_report: None,
            thread_cpu_nanos: 0,
            cpu_started_at: 0,
            group_cpu_nanos: Rc::new(Cell::new(0)),
        }
    }

    /// Sibling state for a thread (`CLONE_VM | CLONE_THREAD`): shared
    /// descriptor table, shared thread-group id.
    pub fn thread_sibling(&self, tid: u64) -> Self {
        Self {
            pid: tid,
            tgid: self.tgid,
            ppid: self.ppid,
            pgid: self.pgid,
            sid: self.sid,
            uid: self.uid,
            gid: self.gid,
            fds: Rc::clone(&self.fds),
            cwd: self.cwd,
            umask: self.umask,
            brk_end: Rc::clone(&self.brk_end),
            mmap_next: Rc::clone(&self.mmap_next),
            // Threads share one signal-disposition table.
            sigactions: Rc::clone(&self.sigactions),
            sigmask: self.sigmask,
            pending_signals: 0,
            signal_frames: Vec::new(),
            // A fork inherits the registration; a new thread does not, since
            // the memory it names is the registering thread's stack and two
            // threads must not run handlers on one.
            altstack: None,
            altstack_depth: 0,
            exe_path: self.exe_path.clone(),
            argv: self.argv.clone(),
            envp: self.envp.clone(),
            clear_child_tid: 0,
            rseq: None,
            robust_list: None,
            asid: self.asid,
            vfork_done: None,
            stopped: false,
            stop_report: None,
            thread_cpu_nanos: 0,
            cpu_started_at: 0,
            group_cpu_nanos: Rc::clone(&self.group_cpu_nanos),
        }
    }

    /// Charges the current CPU turn exactly once before this task is parked.
    pub fn finish_cpu_turn(&mut self, global_icount: u64) {
        let elapsed = global_icount.saturating_sub(self.cpu_started_at);
        self.thread_cpu_nanos = self.thread_cpu_nanos.saturating_add(elapsed);
        self.group_cpu_nanos
            .set(self.group_cpu_nanos.get().saturating_add(elapsed));
        self.cpu_started_at = global_icount;
    }

    /// Starts a new running interval after restoring this task.
    pub fn start_cpu_turn(&mut self, global_icount: u64) {
        self.cpu_started_at = global_icount;
    }

    pub fn current_thread_cpu_nanos(&self, global_icount: u64) -> u64 {
        self.thread_cpu_nanos
            .saturating_add(global_icount.saturating_sub(self.cpu_started_at))
    }

    pub fn current_group_cpu_nanos(&self, global_icount: u64) -> u64 {
        self.group_cpu_nanos
            .get()
            .saturating_add(global_icount.saturating_sub(self.cpu_started_at))
    }
}

/// Why a parked task is not runnable (or that it is).
pub enum ParkState {
    /// Runnable; waiting only for the CPU.
    Ready,
    /// `wait4`: waiting for a child to become a zombie — or, with
    /// `WUNTRACED` (`untraced`), to stop. `pid` follows the wait4
    /// convention (-1 = any child, >0 = that specific child).
    WaitChild { pid: i64, untraced: bool },
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
    /// Completion (success or failure) of a non-blocking TCP connect.
    NetWritable(NetRef),
    /// Fires when the pipe's activity counter moves past the recorded value
    /// (a new write, read, or end close). Used for edge-triggered epoll fds
    /// whose delivered edge is suppressed: only fresh activity re-arms them.
    PipeActivity(PipeRef, u64),
    /// Same as [`Watch::PipeActivity`] for an eventfd.
    EventActivity(EventFdRef, u64),
    /// Readability of a pty end (`master = true` watches slave-to-master
    /// output; `false` watches master-to-slave input).
    PtyReadable(PtyRef, bool),
    /// Fires when a pty's activity counter moves past the recorded value.
    PtyActivity(PtyRef, u64),
    /// An inotify instance with something to read.
    InotifyReadable(crate::fd::InotifyRef),
    /// Fires when an inotify instance's activity counter moves past the
    /// recorded value.
    InotifyActivity(crate::fd::InotifyRef, u64),
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
            Watch::NetWritable(socket) => {
                let socket = socket.borrow();
                match socket.handle {
                    Some(handle) => !matches!(
                        socket.broker.borrow_mut().tcp_connect_status(handle),
                        crate::net::ConnectStatus::Pending
                    ),
                    None => false,
                }
            }
            Watch::PipeActivity(pipe, seen) => pipe.borrow().activity != *seen,
            Watch::EventActivity(event, seen) => event.borrow().activity != *seen,
            Watch::PtyReadable(pty, master) => {
                let pty = pty.borrow();
                if *master {
                    !pty.s2m.is_empty() || (pty.slave_ever_opened && pty.slaves == 0)
                } else {
                    !pty.m2s.is_empty() || pty.masters == 0
                }
            }
            Watch::PtyActivity(pty, seen) => pty.borrow().activity != *seen,
            Watch::InotifyReadable(inner) => {
                let inner = inner.borrow();
                !inner.queue.is_empty() || inner.overflowed
            }
            Watch::InotifyActivity(inner, seen) => inner.borrow().activity != *seen,
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

    /// Invalidates execution positions derived from the VM's lifted-block
    /// table in every parked CPU snapshot. Architectural PCs live in the
    /// saved register files and remain authoritative; a resumed task will
    /// lift that PC again against current memory.
    pub fn invalidate_code_positions(&mut self) {
        for task in &mut self.parked {
            task.cpu.block_id = u64::MAX;
            task.cpu.block_offset = 0;
        }
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

    /// Takes an uncollected stop report from a child of `ppid` matching the
    /// wait4 `pid` filter: the child's pid and the signal that stopped it.
    /// Each stop is reported once, which is the `WUNTRACED` contract.
    pub fn take_stop_report(&mut self, ppid: u64, pid_filter: i64) -> Option<(u64, u64)> {
        self.parked
            .iter_mut()
            .filter(|t| {
                t.proc.ppid == ppid && (pid_filter == -1 || t.proc.tgid == pid_filter as u64)
            })
            .find_map(|t| t.proc.stop_report.take().map(|sig| (t.proc.tgid, sig)))
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
            // A stopped task is not runnable no matter what it waits on or
            // what is pending; only SIGCONT (which clears the flag) or a
            // kill that removes it outright ends the stop.
            if task.proc.stopped {
                return false;
            }
            // A deliverable pending signal interrupts any blocking wait
            // except the uninterruptible vfork suspension: a vfork parent
            // must not observe anything (including a handler running on its
            // borrowed stack semantics) until the child execs or exits.
            // Deliverable, not merely pending: a signal the task blocks must
            // not wake it, or it would spin being scheduled with nothing to
            // deliver.
            if task.proc.pending_signals & !task.proc.sigmask != 0
                && !matches!(task.state, ParkState::VforkDone { .. })
            {
                return true;
            }
            self.wait_is_satisfied(task, now)
        })
    }

    /// Whether the condition a parked task waits on is satisfied — the test
    /// `find_ready` applies, without the clause that makes a task runnable
    /// merely because a signal is deliverable. A task scheduled while this is
    /// false was woken by the signal alone, and that is what separates a
    /// syscall the kernel restarts from one that returns `EINTR`.
    pub fn wait_is_satisfied(&self, task: &ParkedTask, now: u64) -> bool {
        match &task.state {
            ParkState::Ready => true,
            ParkState::Futex {
                woken, deadline, ..
            } => *woken || deadline.is_some_and(|d| now >= d),
            ParkState::WaitChild { pid, untraced } => {
                let matches = |child_pid: u64, child_ppid: u64| {
                    child_ppid == task.proc.tgid && (*pid == -1 || child_pid == *pid as u64)
                };
                self.zombies.iter().any(|z| matches(z.pid, z.ppid))
                    || (*untraced
                        && self.parked.iter().any(|t| {
                            t.proc.stop_report.is_some() && matches(t.proc.tgid, t.proc.ppid)
                        }))
            }
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
    }

    /// Earliest wake-up deadline among parked tasks (timerfd expiries and
    /// wait timeouts), used to warp the deterministic clock when the whole
    /// system is idle.
    pub fn earliest_deadline(&self) -> Option<u64> {
        self.parked
            .iter()
            // A stopped task's deadline cannot wake it; warping to it would
            // advance the clock toward a task that stays unrunnable.
            .filter(|task| !task.proc.stopped)
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

    /// Broker handles that parked tasks are waiting on, for the idle host
    /// wait. Connection completion is a host network event just like input.
    pub fn net_watch_handles(&self) -> Vec<crate::net::Handle> {
        self.parked
            .iter()
            .flat_map(|task| match &task.state {
                ParkState::Waiting { watches, .. } => watches
                    .iter()
                    .filter_map(|w| match w {
                        Watch::NetReadable(s) | Watch::NetWritable(s) => s.borrow().handle,
                        _ => None,
                    })
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            })
            .collect()
    }
}
