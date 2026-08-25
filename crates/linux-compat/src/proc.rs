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

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use icicle_cpu::CpuSnapshot;
use icicle_mem::VirtualMemoryMap;

use crate::fd::{FdTable, PipeRef};
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
    pub sigactions: HashMap<u64, SigAction>,
    pub sigmask: u64,
    pub exe_path: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
    pub envp: Vec<Vec<u8>>,
    /// `set_tid_address` / `CLONE_CHILD_CLEARTID`: zeroed and futex-woken
    /// when this task exits (pthread_join relies on it).
    pub clear_child_tid: u64,
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
            sigactions: HashMap::new(),
            sigmask: 0,
            exe_path: Vec::new(),
            argv: Vec::new(),
            envp: Vec::new(),
            clear_child_tid: 0,
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
            sigactions: self.sigactions.clone(),
            sigmask: self.sigmask,
            exe_path: self.exe_path.clone(),
            argv: self.argv.clone(),
            envp: self.envp.clone(),
            clear_child_tid: 0,
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
            sigactions: self.sigactions.clone(),
            sigmask: self.sigmask,
            exe_path: self.exe_path.clone(),
            argv: self.argv.clone(),
            envp: self.envp.clone(),
            clear_child_tid: 0,
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
    /// `FUTEX_WAIT` on `addr`; `woken` is set by `FUTEX_WAKE`.
    Futex { addr: u64, woken: bool },
    /// Blocked reading an empty pipe.
    PipeRead { pipe: PipeRef },
    /// Blocked writing a full pipe.
    PipeWrite { pipe: PipeRef },
}

pub struct ParkedTask {
    pub proc: Process,
    pub cpu: Box<CpuSnapshot>,
    pub mem: VirtualMemoryMap,
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
    next_pid: u64,
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            parked: Vec::new(),
            zombies: Vec::new(),
            next_pid: ROOT_PID + 1,
        }
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
    pub fn find_ready(&self) -> Option<usize> {
        self.parked.iter().position(|task| match &task.state {
            ParkState::Ready => true,
            ParkState::Futex { woken, .. } => *woken,
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
        })
    }
}
