//! Portable Linux x86-64 userspace layer for webTOS (roadmap `linux-compat`).
//!
//! Implements the operating-system side of the Linux ABI over the
//! `x64-engine` virtual CPU: an in-memory VFS, file descriptors with Linux
//! open-file-description semantics, and processes, threads, pipes, and
//! futexes over a deterministic cooperative scheduler (roadmap milestones
//! 2–4). Dynamically linked binaries start through the system dynamic
//! loader (milestone 3).
//!
//! Unsupported syscalls return `-ENOSYS` with a log line — never fake
//! success.
//!
//! This crate supersedes the milestone-1 `linux_min` environment and is the
//! portable rebuild of the native kernel's `src/linux_compat` substrate.

pub mod abi;
pub mod fd;
pub mod net;
pub mod proc;
pub mod syscall;
pub mod vfs;

use std::collections::HashMap;
use std::path::Path;

use icicle_cpu::{
    elf::ElfLoader,
    mem::{perm, Mapping},
    Cpu, Environment, ExceptionCode, ValueSource, VmExit,
};
use x64_engine::{
    build::{build_x64_vm, build_x64_vm_from_files},
    classify_exit, CpuExit, EngineConfig, InterpVm,
};

use proc::{Process, Scheduler};
use vfs::{NodeKind, Vfs};

/// Diagnostic mirror of the currently scheduled task's pid, for memory-write
/// hooks that cannot reach the environment.
pub static CURRENT_PID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1000);

/// Allocates fresh address-space ids. Id 0 is the initial process; `fork` and
/// `execve` take a new id (a new/replaced address space), while threads share
/// their group's id. The block cache keys on it so a block lifted from one
/// image is never reused at the same VA in another.
pub(crate) static NEXT_ASID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

pub(crate) fn alloc_asid() -> u64 {
    NEXT_ASID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub(crate) const PAGE_SIZE: u64 = 0x1000;
const STACK_TOP: u64 = 0x7fff_ff00_0000;
// 16 MiB: the kernel's default RLIMIT_STACK is 8 MiB, but argv/envp/auxv
// consume the top of the region here, and a real workload's helper process
// faulted exactly 8 bytes below an 8 MiB stack. Pages are demand-allocated,
// so the extra headroom costs address space only.
const STACK_SIZE: u64 = 0x100_0000; // 16 MiB
                                    // 64 GiB: above any program image and brk region, but low enough for
                                    // allocators whose segment maps cover a bounded address range (mimalloc
                                    // rejects OS memory beyond its map and aborts on the resulting NULL).
pub(crate) const MMAP_BASE: u64 = 0x10_0000_0000;
/// A pipe write blocks once this much data is buffered.
pub(crate) const PIPE_CAPACITY: usize = 0x10_0000;

/// Default CLOCK_REALTIME base: a fixed instant so runs are reproducible
/// when the host does not supply the real wall clock. Hosts that talk to
/// real services (TLS certificate validity, token expiry) should override
/// it via [`Machine::set_wall_clock_base`].
pub(crate) const EPOCH_BASE_SEC: i64 = 1_790_000_000;

pub(crate) struct Regs {
    pub rax: pcode::VarNode,
    pub rdi: pcode::VarNode,
    pub rsi: pcode::VarNode,
    pub rdx: pcode::VarNode,
    pub r10: pcode::VarNode,
    pub r8: pcode::VarNode,
    pub r9: pcode::VarNode,
    pub rsp: pcode::VarNode,
    pub fs_offset: pcode::VarNode,
}

impl Regs {
    fn resolve(cpu: &Cpu) -> Result<Self, String> {
        let get = |name: &str| {
            cpu.arch
                .sleigh
                .get_varnode(name)
                .ok_or_else(|| format!("SLEIGH spec is missing varnode: {name}"))
        };
        Ok(Self {
            rax: get("RAX")?,
            rdi: get("RDI")?,
            rsi: get("RSI")?,
            rdx: get("RDX")?,
            r10: get("R10")?,
            r8: get("R8")?,
            r9: get("R9")?,
            rsp: get("RSP")?,
            fs_offset: get("FS_OFFSET")?,
        })
    }
}

/// Stored `rt_sigaction` registration (handler, flags, restorer, mask).
#[derive(Debug, Clone, Copy, Default)]
pub struct SigAction(pub [u8; 32]);

pub struct LinuxEnv {
    pub(crate) regs: Regs,
    pub vfs: Vfs,
    /// The task currently executing on the CPU.
    pub(crate) proc: Process,
    pub(crate) sched: Scheduler,
    /// Thread group whose address space currently occupies the MMU.
    pub(crate) last_group: u64,
    pub(crate) rng_state: u64,
    pub(crate) output: Vec<u8>,
    /// Host network broker; None = network denied (the default).
    pub(crate) net: Option<net::BrokerRef>,
    /// Secrets injected by the host: `name -> value`. `${name}` in guest
    /// files is expanded to the value in memory, and redacted back to
    /// `${name}` when the filesystem is serialized, so secrets never enter
    /// a snapshot.
    pub(crate) secrets: std::collections::BTreeMap<String, String>,
    /// Recent syscalls, as `(pid, nr, icount)` (bounded ring), for crash
    /// and deadlock diagnostics.
    pub(crate) syscall_trail: std::collections::VecDeque<(u64, u64, u64)>,
    /// Deterministic time-warp offset: advanced when the whole system is
    /// idle waiting on a timer, so timeouts fire without busy-waiting.
    pub(crate) warp_nanos: u64,
    /// CLOCK_REALTIME base (unix seconds at machine start). Defaults to a
    /// fixed instant for reproducibility; hosts override it with the real
    /// wall clock when the guest talks to real services.
    pub(crate) epoch_base_sec: i64,
    /// Live pseudoterminals, keyed by id (`/dev/pts/<id>`), for slave lookup.
    pub(crate) ptys: std::collections::BTreeMap<u64, fd::PtyRef>,
    pub(crate) next_pty_id: u64,
    /// When stdio is a pty (the "browser terminal" model), the shared pty and
    /// the pending terminal input to feed the guest when it blocks reading it.
    pub(crate) stdio_pty: Option<fd::PtyRef>,
    pub(crate) stdio_input: std::collections::VecDeque<u8>,
    /// Set when the machine went idle only because a task is blocked reading
    /// the stdio pty with no host keystrokes queued. That is an interactive
    /// pause, not a deadlock: the run stops so the host can collect input,
    /// and the next `run` puts the task back on the CPU.
    pub(crate) terminal_input_wait: bool,
    /// Set when the machine went idle waiting on a host-driven network broker
    /// (see `net::NetworkBroker::host_driven`). Like a terminal wait this is a
    /// pause, not a deadlock: the host runs its event loop, delivers what
    /// arrived, and calls `run` again.
    pub(crate) network_wait: bool,
    /// Set by the host to say its network wait expired with nothing to
    /// deliver, which lets the next stall advance the guest's clock so timers
    /// and socket timeouts fire.
    pub(crate) network_expired: bool,
    /// Exit code of the root process (the machine's exit code).
    exit_code: Option<i32>,
}

/// Terminal-generated signal for a window-size change.
const SIGWINCH: u64 = 28;

impl LinuxEnv {
    pub fn new(cpu: &Cpu) -> Result<Self, String> {
        Ok(Self {
            regs: Regs::resolve(cpu)?,
            vfs: Vfs::new(),
            proc: Process::initial(),
            sched: Scheduler::new(),
            last_group: proc::ROOT_PID,
            rng_state: 0x9e37_79b9_7f4a_7c15,
            output: Vec::new(),
            net: None,
            secrets: std::collections::BTreeMap::new(),
            syscall_trail: std::collections::VecDeque::with_capacity(128),
            warp_nanos: 0,
            epoch_base_sec: EPOCH_BASE_SEC,
            ptys: std::collections::BTreeMap::new(),
            next_pty_id: 0,
            stdio_pty: None,
            stdio_input: std::collections::VecDeque::new(),
            terminal_input_wait: false,
            network_wait: false,
            network_expired: false,
            exit_code: None,
        })
    }

    /// Attaches the host network broker. Without one, guest sockets fail
    /// with `EAFNOSUPPORT` (network is denied by default).
    pub fn set_network(&mut self, broker: net::BrokerRef) {
        self.net = Some(broker);
    }

    pub fn set_wall_clock_base(&mut self, unix_sec: i64) {
        self.epoch_base_sec = unix_sec;
    }

    /// Registers a secret. `${name}` in any guest file is expanded to
    /// `value` in memory (see `expand_secrets`), and redacted back to the
    /// placeholder in serialized snapshots, so the value never persists.
    pub fn set_secret(&mut self, name: &str, value: &str) {
        self.secrets.insert(name.to_string(), value.to_string());
    }

    /// Expands `${name}` placeholders in every regular file using the
    /// registered secrets. Call after seeding files and before `load`.
    pub fn expand_secrets(&mut self) {
        if self.secrets.is_empty() {
            return;
        }
        let subs: Vec<(String, String)> = self
            .secrets
            .iter()
            .map(|(name, value)| (format!("${{{name}}}"), value.clone()))
            .collect();
        self.vfs.rewrite_files(&subs);
    }

    /// The reverse map (`value -> ${name}`) used to redact snapshots.
    pub(crate) fn secret_redactions(&self) -> Vec<(String, String)> {
        self.secrets
            .iter()
            .map(|(name, value)| (value.clone(), format!("${{{name}}}")))
            .collect()
    }

    pub fn set_args(&mut self, argv: Vec<Vec<u8>>, envp: Vec<Vec<u8>>) {
        self.proc.argv = argv;
        self.proc.envp = envp;
    }

    /// Puts the process's stdin/stdout/stderr on a fresh pty slave, with the
    /// master held by the host (the "browser terminal"). `isatty` then reports
    /// true and the guest runs its interactive terminal path; the host feeds
    /// keystrokes with [`feed_terminal_input`] and reads rendered output with
    /// [`drain_terminal_output`].
    pub fn install_pty_stdio(&mut self, rows: u16, cols: u16) {
        use crate::fd::{Backing, Description, FdEntry, Pty};
        let id = self.next_pty_id;
        self.next_pty_id += 1;
        let mut pty = Pty::new(id);
        pty.winsize = [rows, cols, 0, 0];
        pty.slaves = 3; // fds 0, 1, 2
        pty.slave_ever_opened = true;
        pty.fg_pgrp = self.proc.pgid;
        let pty = std::rc::Rc::new(std::cell::RefCell::new(pty));
        self.ptys.insert(id, std::rc::Rc::clone(&pty));
        self.stdio_pty = Some(std::rc::Rc::clone(&pty));
        let mut fds = self.proc.fds.borrow_mut();
        for (fd, flags) in [(0, abi::O_RDONLY), (1, abi::O_WRONLY), (2, abi::O_WRONLY)] {
            let entry = FdEntry {
                desc: std::rc::Rc::new(std::cell::RefCell::new(Description {
                    backing: Backing::PtySlave(std::rc::Rc::clone(&pty)),
                    offset: 0,
                    flags,
                })),
                cloexec: false,
            };
            let _ = fds.insert_at(fd, entry);
        }
    }

    /// Queues host keystrokes for the stdio pty; delivered when the guest
    /// blocks reading it (see the stall resolver).
    pub fn feed_terminal_input(&mut self, bytes: &[u8]) {
        self.stdio_input.extend(bytes.iter().copied());
    }

    /// Drains everything the guest has written to the stdio pty (terminal
    /// output the host would render).
    pub fn drain_terminal_output(&mut self) -> Vec<u8> {
        match &self.stdio_pty {
            Some(pty) => pty.borrow_mut().s2m.drain(..).collect(),
            None => Vec::new(),
        }
    }

    /// Reports a new terminal size from the host (the user resized the
    /// window) and notifies the foreground group with SIGWINCH, exactly as
    /// the guest's own `TIOCSWINSZ` does, so a full-screen program redraws.
    /// Does nothing when stdio is not a pty.
    pub fn resize_terminal(&mut self, rows: u16, cols: u16) {
        let Some(pty) = self.stdio_pty.clone() else {
            return;
        };
        let pgrp = {
            let mut pty = pty.borrow_mut();
            if pty.winsize[0] == rows && pty.winsize[1] == cols {
                return;
            }
            pty.winsize[0] = rows;
            pty.winsize[1] = cols;
            pty.activity += 1;
            pty.fg_pgrp
        };
        syscall::deliver_signal_to_pgrp(self, pgrp, SIGWINCH);
    }

    /// True when the last run stopped because an interactive guest is waiting
    /// for the host to supply terminal input.
    pub fn awaiting_terminal_input(&self) -> bool {
        self.terminal_input_wait
    }

    /// True when the last run stopped waiting on the host's network transport.
    pub fn awaiting_network(&self) -> bool {
        self.network_wait
    }

    /// Tells the machine the host waited for network activity and none came,
    /// so the next stall may advance guest time instead of pausing again.
    pub fn expire_network_wait(&mut self) {
        self.network_expired = true;
    }

    /// How long the host may wait for network activity before the guest's own
    /// earliest timer deadline expires, in milliseconds. `None` means the
    /// guest armed no timer, so the host may wait as long as it likes.
    pub fn network_wait_budget_ms(&self, cpu: &Cpu) -> Option<u64> {
        let now = self.now_nanos(cpu);
        self.sched
            .earliest_deadline()
            .map(|deadline| deadline.saturating_sub(now) / 1_000_000)
    }

    pub fn add_file(&mut self, path: &[u8], bytes: Vec<u8>, mode: u32) -> Result<(), String> {
        self.vfs
            .add_node(path, NodeKind::File(bytes), mode)
            .map(|_| ())
            .map_err(|e| format!("cannot add {}: errno {e}", path.escape_ascii()))
    }

    /// Starts a file that will be delivered in pieces, reserving room for
    /// `capacity` bytes. An agent image is hundreds of megabytes; buffering
    /// one whole copy on the way in is the difference between fitting in a
    /// tab and not.
    pub fn create_file(&mut self, path: &[u8], capacity: usize, mode: u32) -> Result<(), String> {
        self.vfs
            .create_file_with_capacity(path, capacity, mode)
            .map(|_| ())
            .map_err(|e| format!("cannot create {}: errno {e}", path.escape_ascii()))
    }

    /// Appends one piece to a file started with [`create_file`].
    pub fn append_file(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), String> {
        self.vfs
            .append_file(path, bytes)
            .map_err(|e| format!("cannot append to {}: errno {e}", path.escape_ascii()))
    }

    /// Adds a symlink at `path` pointing at `target`. Multi-call binaries
    /// select their behaviour from `argv[0]`, so a link is how one image
    /// becomes many commands on `PATH`.
    pub fn add_symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), String> {
        self.vfs
            .add_node(path, NodeKind::Symlink(target.to_vec()), 0o777)
            .map(|_| ())
            .map_err(|e| format!("cannot link {}: errno {e}", path.escape_ascii()))
    }

    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub(crate) fn record_exit(&mut self, code: i32) {
        self.exit_code = Some(code);
    }

    /// Records a syscall in the bounded diagnostic trail.
    pub(crate) fn record_syscall(&mut self, nr: u64, icount: u64) {
        if self.syscall_trail.len() >= 128 {
            self.syscall_trail.pop_front();
        }
        self.syscall_trail.push_back((self.proc.pid, nr, icount));
    }

    pub(crate) fn now(&self, cpu: &Cpu) -> (i64, i64) {
        // u64 arithmetic before the split so the nanosecond field is always in
        // [0, 1e9) — a large monotonic value must never produce a negative
        // `tv_nsec` (which Rust's `Timespec::new` rejects as an invalid
        // timestamp).
        let nanos = self.now_nanos(cpu);
        (
            self.epoch_base_sec
                .saturating_add((nanos / 1_000_000_000) as i64),
            (nanos % 1_000_000_000) as i64,
        )
    }

    /// CLOCK_MONOTONIC as (sec, nsec): time since an arbitrary epoch (here,
    /// machine start), *without* the wall-clock offset. A program that mixes a
    /// monotonic deadline with the realtime clock must not see the ~55-year
    /// epoch base on the monotonic side.
    pub(crate) fn now_monotonic(&self, cpu: &Cpu) -> (i64, i64) {
        let nanos = self.now_nanos(cpu);
        (
            (nanos / 1_000_000_000) as i64,
            (nanos % 1_000_000_000) as i64,
        )
    }

    /// Deterministic monotonic clock: one retired instruction is one
    /// nanosecond, plus the idle time-warp offset.
    pub(crate) fn now_nanos(&self, cpu: &Cpu) -> u64 {
        cpu.icount().saturating_add(self.warp_nanos)
    }

    pub(crate) fn next_random(&mut self) -> u64 {
        // xorshift64* — deterministic entropy for the guest.
        let mut x = self.rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    #[allow(dead_code)]
    pub(crate) fn alloc_mmap(&mut self, len: u64) -> u64 {
        let target = self.proc.mmap_next.get();
        self.proc
            .mmap_next
            .set(target + align_up(len, PAGE_SIZE) + PAGE_SIZE);
        target
    }

    /// Loads `path` into a fresh address space for the current task and
    /// prepares registers and the initial stack. Shared by `load` (initial
    /// process) and `execve`.
    pub(crate) fn start_image(&mut self, cpu: &mut Cpu, path: &[u8]) -> Result<(), String> {
        // `reset_virtual` drops the mapping but leaks the physical pages
        // (the engine never frees them individually), so a long-lived
        // machine running many processes would exhaust memory. When no
        // other task is alive we can reclaim everything with `clear`
        // (keeping only the shared zero page); with siblings parked, their
        // maps still reference physical pages, so we must not clear — an
        // execve inside a multi-process guest keeps the (bounded) leak.
        let others_alive = !self.sched.parked.is_empty() || !self.sched.group_maps.is_empty();
        if others_alive {
            cpu.mem.reset_virtual();
        } else {
            cpu.mem.clear();
        }
        cpu.reset();

        // Null page: faults with a permission error instead of unmapped.
        cpu.mem.map_memory_len(
            0,
            PAGE_SIZE,
            Mapping {
                perm: perm::NONE,
                value: 0,
            },
        );

        let metadata = self.load_elf(cpu, path)?;

        self.proc.exe_path = if path.first() == Some(&b'/') {
            path.to_vec()
        } else {
            let mut abs = self.vfs.abs_path_of(self.proc.cwd);
            if abs != b"/" {
                abs.push(b'/');
            }
            abs.extend_from_slice(path);
            abs
        };
        if self.proc.argv.is_empty() {
            self.proc.argv = vec![path.to_vec()];
        }

        // Dynamically linked binaries start in the interpreter; auxv points
        // the loader at the main image.
        let entry = metadata
            .interpreter
            .as_ref()
            .map_or(metadata.binary.entry_ptr, |interp| interp.entry_ptr);
        (cpu.arch.on_boot)(cpu, entry);
        self.setup_stack(cpu, &metadata)?;

        let image_end = metadata.interpreter.as_ref().map_or(
            metadata.binary.base_ptr + metadata.binary.length,
            |interp| {
                (metadata.binary.base_ptr + metadata.binary.length)
                    .max(interp.base_ptr + interp.length)
            },
        );
        self.proc
            .brk_end
            .set(align_up(image_end, PAGE_SIZE) + 0x10_0000);
        self.proc.mmap_next.set(MMAP_BASE);
        Ok(())
    }

    /// Builds the initial process stack per the System V x86-64 ABI.
    fn setup_stack(
        &mut self,
        cpu: &mut Cpu,
        metadata: &icicle_cpu::elf::LoadedElf,
    ) -> Result<(), String> {
        let stack_base = STACK_TOP - STACK_SIZE;
        cpu.mem
            .map_memory_len(
                stack_base,
                STACK_SIZE,
                Mapping {
                    perm: perm::READ | perm::WRITE | perm::INIT,
                    value: 0,
                },
            )
            .then_some(())
            .ok_or("failed to map stack")?;

        let mut write_top = STACK_TOP;
        let mut push_bytes = |cpu: &mut Cpu, bytes: &[u8]| -> Result<u64, String> {
            write_top -= bytes.len() as u64;
            cpu.mem
                .write_bytes(write_top, bytes, perm::NONE)
                .map_err(|e| format!("stack write failed: {e:?}"))?;
            Ok(write_top)
        };

        let mut argv_ptrs = Vec::with_capacity(self.proc.argv.len());
        for arg in &self.proc.argv {
            let mut bytes = arg.clone();
            bytes.push(0);
            argv_ptrs.push(push_bytes(cpu, &bytes)?);
        }
        let mut envp_ptrs = Vec::with_capacity(self.proc.envp.len());
        for env in &self.proc.envp {
            let mut bytes = env.clone();
            bytes.push(0);
            envp_ptrs.push(push_bytes(cpu, &bytes)?);
        }
        // AT_RANDOM bytes: deterministic process-start entropy.
        let mut random = [0_u8; 16];
        random[..8].copy_from_slice(&self.next_random().to_le_bytes());
        random[8..].copy_from_slice(&self.next_random().to_le_bytes());
        let random_ptr = push_bytes(cpu, &random)?;
        let mut execfn = self.proc.exe_path.clone();
        execfn.push(0);
        let execfn_ptr = push_bytes(cpu, &execfn)?;
        let platform_ptr = push_bytes(cpu, b"x86_64\0")?;

        const AT_PHDR: u64 = 3;
        const AT_PHENT: u64 = 4;
        const AT_PHNUM: u64 = 5;
        const AT_PAGESZ: u64 = 6;
        const AT_BASE: u64 = 7;
        const AT_FLAGS: u64 = 8;
        const AT_ENTRY: u64 = 9;
        const AT_UID: u64 = 11;
        const AT_EUID: u64 = 12;
        const AT_GID: u64 = 13;
        const AT_EGID: u64 = 14;
        const AT_PLATFORM: u64 = 15;
        const AT_HWCAP: u64 = 16;
        const AT_CLKTCK: u64 = 17;
        const AT_SECURE: u64 = 23;
        const AT_RANDOM: u64 = 25;
        const AT_EXECFN: u64 = 31;
        const AT_NULL: u64 = 0;

        // For a dynamically linked binary, execution starts in the
        // interpreter and AT_BASE tells it where it was itself loaded; the
        // remaining entries describe the main binary.
        let interp_base = metadata
            .interpreter
            .as_ref()
            .map_or(0, |interp| interp.base_ptr);

        let auxv: &[(u64, u64)] = &[
            (AT_PHDR, metadata.binary.phdr_ptr),
            (AT_PHENT, 56),
            (AT_PHNUM, metadata.binary.phdr_num),
            (AT_PAGESZ, PAGE_SIZE),
            (AT_BASE, interp_base),
            (AT_FLAGS, 0),
            (AT_ENTRY, metadata.binary.entry_ptr),
            (AT_UID, 0),
            (AT_EUID, 0),
            (AT_GID, 0),
            (AT_EGID, 0),
            (AT_PLATFORM, platform_ptr),
            (AT_HWCAP, 0),
            (AT_SECURE, 0),
            (AT_CLKTCK, 100),
            (AT_RANDOM, random_ptr),
            (AT_EXECFN, execfn_ptr),
            (AT_NULL, 0),
        ];

        let mut vectors: Vec<u64> = Vec::new();
        vectors.push(self.proc.argv.len() as u64);
        vectors.extend(&argv_ptrs);
        vectors.push(0);
        vectors.extend(&envp_ptrs);
        vectors.push(0);
        for &(key, value) in auxv {
            vectors.push(key);
            vectors.push(value);
        }
        let vector_bytes: Vec<u8> = vectors.iter().flat_map(|v| v.to_le_bytes()).collect();

        let mut rsp = write_top - vector_bytes.len() as u64;
        rsp &= !0xf;
        cpu.mem
            .write_bytes(rsp, &vector_bytes, perm::NONE)
            .map_err(|e| format!("stack vector write failed: {e:?}"))?;
        cpu.write_var(self.regs.rsp, rsp);
        Ok(())
    }
}

impl ElfLoader for LinuxEnv {
    fn read_file(&mut self, path: &[u8]) -> Result<Vec<u8>, String> {
        let resolved = self
            .vfs
            .resolve(self.proc.cwd, path, true)
            .map_err(|e| format!("cannot resolve {}: errno {e}", path.escape_ascii()))?;
        let node = resolved
            .node
            .ok_or_else(|| format!("no such file: {}", path.escape_ascii()))?;
        match &self.vfs.node(node).kind {
            NodeKind::File(data) => Ok(data.clone()),
            _ => Err(format!("not a regular file: {}", path.escape_ascii())),
        }
    }
}

impl Environment for LinuxEnv {
    fn load(&mut self, cpu: &mut Cpu, path: &[u8]) -> Result<(), String> {
        // A fresh root process; the filesystem persists across loads, any
        // tasks from a previous run do not.
        let (argv, envp) = (
            std::mem::take(&mut self.proc.argv),
            std::mem::take(&mut self.proc.envp),
        );
        self.proc = Process::initial();
        self.proc.argv = argv;
        self.proc.envp = envp;
        self.sched = Scheduler::new();
        self.last_group = proc::ROOT_PID;
        self.exit_code = None;
        // A fresh root process gets fresh stdio: any terminal the previous
        // one ran on is gone, so the host must install one again to make this
        // process interactive.
        self.stdio_pty = None;
        self.stdio_input.clear();
        self.terminal_input_wait = false;
        self.start_image(cpu, path)
    }

    fn handle_exception(&mut self, cpu: &mut Cpu) -> Option<VmExit> {
        match ExceptionCode::from_u32(cpu.exception.code) {
            ExceptionCode::Syscall => syscall::handle(self, cpu),
            _ => None,
        }
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(())
    }

    fn restore(&mut self, _: &Box<dyn std::any::Any>) {}
}

pub(crate) fn align_up(value: u64, align: u64) -> u64 {
    let mask = !(align - 1);
    value.checked_add(align - 1).map_or(mask, |v| v & mask)
}

/// A complete Linux x86-64 user-mode machine: the interpreter VM plus this
/// crate's environment.
pub struct Machine {
    vm: InterpVm,
}

impl Machine {
    /// Builds a machine from a SLEIGH `.ldefs` path (native hosts).
    pub fn from_ldef(ldef_path: &Path, config: &EngineConfig) -> Result<Self, String> {
        let vm = build_x64_vm(ldef_path, config).map_err(|e| e.to_string())?;
        Self::finish(vm)
    }

    /// Builds a machine from in-memory SLEIGH sources (browser hosts).
    pub fn from_spec_files(
        files: HashMap<String, String>,
        config: &EngineConfig,
    ) -> Result<Self, String> {
        let vm = build_x64_vm_from_files(files, config).map_err(|e| e.to_string())?;
        Self::finish(vm)
    }

    fn finish(mut vm: InterpVm) -> Result<Self, String> {
        let env = LinuxEnv::new(&vm.cpu)?;
        vm.set_env(env);
        Ok(Self { vm })
    }

    pub fn env(&mut self) -> &mut LinuxEnv {
        self.vm
            .env_mut::<LinuxEnv>()
            .expect("machine environment is always LinuxEnv")
    }

    /// Adds a file to the guest filesystem (parent directories are created).
    pub fn add_file(&mut self, path: &[u8], bytes: Vec<u8>, mode: u32) -> Result<(), String> {
        self.env().add_file(path, bytes, mode)
    }

    /// Adds a symlink to the guest filesystem.
    pub fn add_symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), String> {
        self.env().add_symlink(path, target)
    }

    /// Starts a file delivered in pieces; see [`LinuxEnv::create_file`].
    pub fn create_file(&mut self, path: &[u8], capacity: usize, mode: u32) -> Result<(), String> {
        self.env().create_file(path, capacity, mode)
    }

    /// Appends one piece to a file started with [`create_file`](Self::create_file).
    pub fn append_file(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), String> {
        self.env().append_file(path, bytes)
    }

    /// Recursively copies a host directory tree into the guest filesystem,
    /// preserving symlinks and executable bits. Native hosts only (the
    /// browser host injects files individually).
    pub fn add_host_tree(&mut self, host_dir: &Path, guest_prefix: &str) -> Result<(), String> {
        fn walk(env: &mut LinuxEnv, host: &Path, guest: &str) -> Result<(), String> {
            let entries =
                std::fs::read_dir(host).map_err(|e| format!("{}: {e}", host.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let guest_path = format!("{}/{}", guest.trim_end_matches('/'), name);
                let file_type = entry.file_type().map_err(|e| e.to_string())?;
                if file_type.is_symlink() {
                    let target = std::fs::read_link(entry.path()).map_err(|e| e.to_string())?;
                    env.vfs
                        .add_node(
                            guest_path.as_bytes(),
                            vfs::NodeKind::Symlink(target.to_string_lossy().as_bytes().to_vec()),
                            0o777,
                        )
                        .map_err(|e| format!("{guest_path}: errno {e}"))?;
                } else if file_type.is_dir() {
                    env.vfs
                        .mkdir_p(guest_path.as_bytes())
                        .map_err(|e| format!("{guest_path}: errno {e}"))?;
                    walk(env, &entry.path(), &guest_path)?;
                } else if file_type.is_file() {
                    let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
                    #[cfg(unix)]
                    let mode = {
                        use std::os::unix::fs::PermissionsExt;
                        entry
                            .metadata()
                            .map_err(|e| e.to_string())?
                            .permissions()
                            .mode()
                            & 0o777
                    };
                    #[cfg(not(unix))]
                    let mode = 0o755;
                    env.add_file(guest_path.as_bytes(), bytes, mode)?;
                }
            }
            Ok(())
        }
        // Create the mountpoint itself so mounting an empty host directory
        // still yields an (empty) guest directory, not a missing path.
        let env = self.env();
        env.vfs
            .mkdir_p(guest_prefix.as_bytes())
            .map_err(|e| format!("{guest_prefix}: errno {e}"))?;
        walk(env, host_dir, guest_prefix)
    }

    pub fn set_args(&mut self, argv: Vec<Vec<u8>>, envp: Vec<Vec<u8>>) {
        self.env().set_args(argv, envp);
    }

    /// Runs the guest's stdin/stdout/stderr over a host-driven pty (so the
    /// guest sees an interactive terminal). Call after `load`, before `run`.
    pub fn install_pty_stdio(&mut self, rows: u16, cols: u16) {
        self.env().install_pty_stdio(rows, cols);
    }

    /// Queues terminal input (keystrokes) for the stdio pty.
    pub fn feed_terminal_input(&mut self, bytes: &[u8]) {
        self.env().feed_terminal_input(bytes);
    }

    /// Drains rendered terminal output written by the guest to the stdio pty.
    pub fn drain_terminal_output(&mut self) -> Vec<u8> {
        self.env().drain_terminal_output()
    }

    /// Reports a terminal resize from the host, delivering SIGWINCH to the
    /// foreground group.
    pub fn resize_terminal(&mut self, rows: u16, cols: u16) {
        self.env().resize_terminal(rows, cols);
    }

    /// True when [`run`](Self::run) stopped because the guest is blocked
    /// reading the terminal and the host has queued no keystrokes. Feed input
    /// with [`feed_terminal_input`](Self::feed_terminal_input) and call `run`
    /// again to continue.
    pub fn awaiting_terminal_input(&mut self) -> bool {
        self.env().awaiting_terminal_input()
    }

    /// True when [`run`](Self::run) stopped waiting on the host's network
    /// transport. The host should carry out any pending broker commands, wait
    /// up to [`network_wait_budget_ms`](Self::network_wait_budget_ms) for
    /// activity, deliver what arrived (or call
    /// [`expire_network_wait`](Self::expire_network_wait)), and run again.
    pub fn awaiting_network(&mut self) -> bool {
        self.env().awaiting_network()
    }

    /// See [`LinuxEnv::expire_network_wait`].
    pub fn expire_network_wait(&mut self) {
        self.env().expire_network_wait();
    }

    /// See [`LinuxEnv::network_wait_budget_ms`].
    pub fn network_wait_budget_ms(&mut self) -> Option<u64> {
        let InterpVm { cpu, env, .. } = &mut self.vm;
        let env = env
            .as_mut_any()
            .downcast_mut::<LinuxEnv>()
            .expect("machine environment is always LinuxEnv");
        env.network_wait_budget_ms(cpu)
    }

    /// Attaches a host network broker (network is denied without one).
    /// Sets the guest's CLOCK_REALTIME base (unix seconds at machine
    /// start). Call before `load` when the guest will validate real
    /// certificates or tokens; leaving the default keeps runs reproducible.
    pub fn set_wall_clock_base(&mut self, unix_sec: i64) {
        self.env().set_wall_clock_base(unix_sec);
    }

    pub fn set_network(&mut self, broker: net::BrokerRef) {
        self.env().set_network(broker);
    }

    /// Registers a secret injected into guest files at `expand_secrets`
    /// time and redacted from snapshots. See [`LinuxEnv::set_secret`].
    pub fn set_secret(&mut self, name: &str, value: &str) {
        self.env().set_secret(name, value);
    }

    /// Expands `${name}` secret placeholders in guest files. Call after
    /// seeding files and before `load`.
    pub fn expand_secrets(&mut self) {
        self.env().expand_secrets();
    }

    /// Serializes the guest filesystem (for reload persistence). Secret
    /// values are redacted back to their `${name}` placeholders first, so
    /// snapshots never carry injected credentials. Take snapshots between
    /// guest processes, not while one is running.
    pub fn export_fs(&mut self) -> Vec<u8> {
        let redactions = self.env().secret_redactions();
        if !redactions.is_empty() {
            self.env().vfs.rewrite_files(&redactions);
        }
        let image = self.env().vfs.serialize();
        // Restore the in-memory values so the running machine keeps working.
        self.env().expand_secrets();
        image
    }

    /// Replaces the guest filesystem with a serialized snapshot.
    pub fn import_fs(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.env().vfs = vfs::Vfs::deserialize(bytes)?;
        Ok(())
    }

    /// Loads a Linux ELF from the guest filesystem as a fresh root process.
    pub fn load(&mut self, path: &[u8]) -> Result<(), String> {
        let InterpVm { cpu, env, .. } = &mut self.vm;
        env.load(cpu, path)
    }

    /// Runs until the workload exits or faults.
    pub fn run(&mut self) -> CpuExit {
        // A previous run paused waiting on the host — for a keystroke or for
        // network activity. Put a task back on the CPU now that the host has
        // had its turn; with still nothing to deliver, stay paused rather
        // than spinning.
        if self.env().terminal_input_wait || self.env().network_wait {
            self.env().terminal_input_wait = false;
            self.env().network_wait = false;
            let InterpVm { cpu, env, .. } = &mut self.vm;
            let env = env
                .as_mut_any()
                .downcast_mut::<LinuxEnv>()
                .expect("machine environment is always LinuxEnv");
            if !syscall::resume_parked(env, cpu) {
                // Still nothing to run. Say which wait is outstanding so the
                // host knows to try again rather than reading the pause as a
                // stop; no outstanding wait is a real deadlock.
                match syscall::pending_host_wait(env) {
                    Some(syscall::HostWait::Terminal) => env.terminal_input_wait = true,
                    Some(syscall::HostWait::Network) => env.network_wait = true,
                    None => {}
                }
                return CpuExit::Interrupted;
            }
        }
        let exit = self.vm.run();
        let code = self.env().exit_code();
        classify_exit(&self.vm, exit, code)
    }

    /// The executable path and pid of the task currently on the CPU, for
    /// crash diagnostics.
    pub fn current_task(&mut self) -> (String, u64) {
        let env = self.env();
        (
            String::from_utf8_lossy(&env.proc.exe_path).into_owned(),
            env.proc.pid,
        )
    }

    /// The recent-syscall diagnostic trail as `pid:nr@icount` strings.
    pub fn syscall_trail(&mut self) -> Vec<String> {
        self.env()
            .syscall_trail
            .iter()
            .map(|(pid, nr, ic)| format!("{pid}:{nr}@{ic}"))
            .collect()
    }

    pub fn take_output(&mut self) -> Vec<u8> {
        self.env().take_output()
    }

    pub fn exit_code(&mut self) -> Option<i32> {
        self.env().exit_code()
    }

    pub fn icount(&self) -> u64 {
        self.vm.cpu.icount()
    }

    /// Produces a crash bundle for a non-clean exit: a compact, secret-free
    /// diagnostic (exit classification, faulting RIP, instruction count,
    /// executable path, and the tail of the syscall trail). Returns None
    /// when the machine exited cleanly.
    pub fn crash_bundle(&mut self, exit: &CpuExit) -> Option<String> {
        if matches!(exit, CpuExit::Halt { code: Some(0) }) {
            return None;
        }
        let rip = self.vm.cpu.read_pc();
        let icount = self.vm.cpu.icount();
        let exe = {
            let env = self.env();
            String::from_utf8_lossy(&env.proc.exe_path).into_owned()
        };
        let trail: Vec<String> = self
            .env()
            .syscall_trail
            .iter()
            .map(|(pid, nr, ic)| format!("{pid}:{nr}@{ic}"))
            .collect();
        let mut bundle = String::new();
        bundle.push_str(
            "webtos-crash-bundle v1
",
        );
        bundle.push_str(&format!(
            "engine: x64-engine {}
",
            env!("CARGO_PKG_VERSION")
        ));
        bundle.push_str(&format!(
            "exit: {exit:?}
"
        ));
        bundle.push_str(&format!(
            "rip: {rip:#x}
"
        ));
        bundle.push_str(&format!(
            "icount: {icount}
"
        ));
        bundle.push_str(&format!(
            "exe: {exe}
"
        ));
        bundle.push_str(&format!(
            "syscall_trail (most recent last): {}
",
            trail.join(" ")
        ));
        // Secrets are never in the trail or the fields above; nothing to
        // redact, but assert the invariant if a value happens to appear.
        for value in self.env().secrets.values() {
            debug_assert!(
                !bundle.contains(value.as_str()),
                "secret leaked into crash bundle"
            );
        }
        Some(bundle)
    }

    pub fn vm_mut(&mut self) -> &mut InterpVm {
        &mut self.vm
    }
}
