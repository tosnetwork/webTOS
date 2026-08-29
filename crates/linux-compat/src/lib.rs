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
pub mod chunk;
pub mod chunk_manifest;
pub mod digest;
pub mod fd;
mod lazy_elf;
pub mod liftcache;
pub mod manifest;
pub mod net;
pub mod netrecord;
pub mod pager;
pub mod proc;
pub mod syscall;
pub mod testing;
pub mod trace;
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

use pager::{AccessKind, FaultResolution, Pager};
use proc::{Process, Scheduler};
use vfs::{NodeKind, Vfs};

// Per-thread, like the engine's mirrors: a test binary runs several machines
// at once and a process-wide static lets them overwrite each other.
thread_local! {
    static PID: std::cell::Cell<u64> = const { std::cell::Cell::new(1000) };
}

/// Pid of the task currently on the CPU, for diagnostics that cannot reach
/// the environment.
pub fn current_pid() -> u64 {
    PID.with(std::cell::Cell::get)
}

pub fn set_current_pid(pid: u64) {
    PID.with(|c| c.set(pid));
}

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

/// A credential the host injects, and where it is allowed to appear. An
/// empty `paths` means every file, which is the older unscoped behaviour.
#[derive(Debug, Clone)]
pub(crate) struct Secret {
    pub(crate) value: String,
    pub(crate) paths: Vec<Vec<u8>>,
}

/// One content-addressed chunk the host must supply. Page requests carry VMA
/// coordinates; file-range requests use zero coordinates and still retry the
/// same syscall only after the verified chunk is resident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRequest {
    pub ticket: u64,
    pub hash: chunk::Hash,
    pub asid: u64,
    pub generation: u64,
    pub page: u64,
    pub access: Option<AccessKind>,
}

#[derive(Debug, Clone)]
struct FileChunkRequest {
    ticket: u64,
    hash: chunk::Hash,
}

pub struct LinuxEnv {
    pub(crate) regs: Regs,
    pub vfs: Vfs,
    /// Live `MAP_SHARED` file mappings: guest writes land in the mapped pages
    /// and are written back to the backing file at `msync`/`munmap`. One guest
    /// process is the honest scope — SQLite's WAL shared-memory file, mapped
    /// once per process, is the workload this exists for; a fork does not see
    /// the parent's later stores (documented divergence).
    pub(crate) shared_maps: Vec<SharedMap>,
    /// VFS node ids the guest has opened, when access tracking is on (`Some`).
    /// A delivered file never in this set was materialized for nothing — the
    /// measure of how much a lazy image could avoid. Off by default so the set
    /// insert per open is only paid when profiling.
    pub(crate) opened_files: Option<std::collections::HashSet<usize>>,
    /// The task currently executing on the CPU.
    pub(crate) proc: Process,
    pub(crate) sched: Scheduler,
    /// Thread group whose address space currently occupies the MMU.
    pub(crate) last_group: u64,
    pub(crate) rng_state: u64,
    pub(crate) output: Vec<u8>,
    /// Host network broker; None = network denied (the default). Whatever
    /// the host attaches is wrapped in a [`net::MeteredBroker`], so every
    /// byte the guest moves is counted whether a budget is set or not.
    pub(crate) net: Option<net::BrokerRef>,
    /// The counter that wrapper charges, and the network quota's ceiling.
    pub(crate) net_meter: net::MeterRef,
    /// Secrets injected by the host, by name. `${name}` in guest files is
    /// expanded to the value in memory, and redacted back to `${name}` when
    /// the filesystem is serialized, so secrets never enter a snapshot.
    pub(crate) secrets: std::collections::BTreeMap<String, Secret>,
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
    /// What the host has committed to delivering, when it has. None means no
    /// manifest was installed and delivery is unchecked, which is the old
    /// behaviour and stays the default: a host that has nothing to verify
    /// against should not be stopped from running.
    pub(crate) manifest: Option<crate::manifest::Manifest>,
    /// Canonical authority for immutable lazy-image paths and chunk layouts.
    pub(crate) chunk_manifest: Option<crate::chunk_manifest::ChunkManifest>,
    /// Running digests for images still arriving in pieces, by guest path.
    pub(crate) in_flight: std::collections::BTreeMap<Vec<u8>, (crate::digest::Sha256, usize)>,
    /// Live inotify instances. A change to the filesystem has to reach every
    /// watcher, and a watcher is reachable only through the descriptor that
    /// holds it — so they are registered here as well, and entries no
    /// descriptor holds any more are dropped when the list is next walked.
    pub(crate) inotify: Vec<crate::fd::InotifyRef>,
    /// A rename's two halves share a cookie so a watcher can pair them.
    pub(crate) inotify_cookie: u32,
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
    /// Set when a manifest-backed page fault has emitted a chunk request. The
    /// CPU remains at the faulting p-code until the host completes its ticket.
    pub(crate) page_in_wait: bool,
    /// An executable page became resident after a lift had already observed
    /// cold bytes. The partially lifted group must be discarded before the
    /// VM can retry; this is an internal turn, never a host-visible wait.
    page_in_recompile: bool,
    /// Immutable file mappings, keyed by the process address-space id.
    pub(crate) pager: Pager,
    file_chunk_wait: Option<FileChunkRequest>,
    next_file_ticket: u64,
    /// Set by the host to say its network wait expired with nothing to
    /// deliver, which lets the next stall advance the guest's clock so timers
    /// and socket timeouts fire.
    pub(crate) network_expired: bool,
    /// Architectural trace being recorded, when the host asked for one.
    pub(crate) trace: Option<trace::Trace>,
    /// Exit code of the root process (the machine's exit code).
    exit_code: Option<i32>,
}

fn resident_matches_chunk_layout(data: &[u8], layout: &crate::chunk::ChunkedFile) -> bool {
    let chunk_size = layout.chunk_size as usize;
    data.len() as u64 == layout.size
        && data.len().div_ceil(chunk_size) == layout.chunks.len()
        && data
            .chunks(chunk_size)
            .zip(&layout.chunks)
            .all(|(chunk, expected)| crate::digest::sha256(chunk) == *expected)
}

/// Terminal-generated signal for a window-size change.
const SIGWINCH: u64 = 28;

impl LinuxEnv {
    /// Whether any lazy file mappings exist (see [`crate::pager::Pager::is_empty`]).
    pub(crate) fn has_lazy_mappings(&self) -> bool {
        !self.pager.is_empty()
    }

    pub fn new(cpu: &Cpu) -> Result<Self, String> {
        Ok(Self {
            regs: Regs::resolve(cpu)?,
            vfs: Vfs::new(),
            shared_maps: Vec::new(),
            opened_files: None,
            proc: Process::initial(),
            sched: Scheduler::new(),
            last_group: proc::ROOT_PID,
            rng_state: 0x9e37_79b9_7f4a_7c15,
            output: Vec::new(),
            net: None,
            net_meter: std::rc::Rc::new(std::cell::RefCell::new(net::NetMeter::new())),
            secrets: std::collections::BTreeMap::new(),
            syscall_trail: std::collections::VecDeque::with_capacity(128),
            warp_nanos: 0,
            epoch_base_sec: EPOCH_BASE_SEC,
            manifest: None,
            chunk_manifest: None,
            in_flight: std::collections::BTreeMap::new(),
            inotify: Vec::new(),
            inotify_cookie: 0,
            ptys: std::collections::BTreeMap::new(),
            next_pty_id: 0,
            stdio_pty: None,
            stdio_input: std::collections::VecDeque::new(),
            terminal_input_wait: false,
            network_wait: false,
            page_in_wait: false,
            page_in_recompile: false,
            pager: Pager::default(),
            file_chunk_wait: None,
            next_file_ticket: 0,
            network_expired: false,
            trace: None,
            exit_code: None,
        })
    }

    /// Attaches the host network broker. Without one, guest sockets fail
    /// with `EAFNOSUPPORT` (network is denied by default).
    ///
    /// The broker is wrapped in a [`net::MeteredBroker`] before the guest
    /// can reach it, so the network quota applies to whatever the host
    /// attaches, including a host's own implementation of the trait.
    pub fn set_network(&mut self, broker: net::BrokerRef) {
        self.net = Some(std::rc::Rc::new(std::cell::RefCell::new(
            net::MeteredBroker::new(broker, std::rc::Rc::clone(&self.net_meter)),
        )));
    }

    /// The metered broker the guest's sockets use, or None when no broker is
    /// attached (network denied).
    pub fn network_broker(&self) -> Option<net::BrokerRef> {
        self.net.clone()
    }

    pub fn set_wall_clock_base(&mut self, unix_sec: i64) {
        self.epoch_base_sec = unix_sec;
    }

    /// Releases the contents of files that have been unlinked and are no
    /// longer open anywhere.
    ///
    /// The filesystem cannot decide this alone: a node stays alive while any
    /// descriptor still names it, and descriptors live in process tables —
    /// this task's and every parked one's, which `fork` makes share the same
    /// open file descriptions. Returns the bytes released.
    pub(crate) fn reclaim_unlinked(&mut self) -> usize {
        if !self.vfs.has_unlinked() {
            return 0;
        }
        let mut referenced = std::collections::HashSet::new();
        let mut collect = |fds: &crate::fd::FdTable| {
            for (_, entry) in fds.iter() {
                match entry.desc.borrow().backing {
                    crate::fd::Backing::File { node } => {
                        referenced.insert(node);
                    }
                    crate::fd::Backing::Dir { node, .. } => {
                        referenced.insert(node);
                    }
                    _ => {}
                }
            }
        };
        collect(&self.proc.fds.borrow());
        for task in &self.sched.parked {
            collect(&task.proc.fds.borrow());
        }
        self.vfs.release_unreferenced(&referenced)
    }

    /// Registers a secret readable by every guest file that names it.
    /// Prefer [`LinuxEnv::set_scoped_secret`]: an unscoped secret reaches any
    /// program that can read any file, which is not a boundary between two
    /// agents sharing a machine.
    pub fn set_secret(&mut self, name: &str, value: &str) {
        self.secrets.insert(
            name.to_string(),
            Secret {
                value: value.to_string(),
                paths: Vec::new(),
            },
        );
    }

    /// Registers a secret that is expanded only in the files named here.
    ///
    /// This is what keeps one agent's credential out of another's
    /// configuration on the same filesystem: the placeholder is substituted
    /// where the host says it belongs and nowhere else, so a program that
    /// reads a file it was not given still sees `${name}`.
    pub fn set_scoped_secret(&mut self, name: &str, value: &str, paths: &[&[u8]]) {
        self.secrets.insert(
            name.to_string(),
            Secret {
                value: value.to_string(),
                paths: paths.iter().map(|p| p.to_vec()).collect(),
            },
        );
    }

    /// Expands `${name}` placeholders using the registered secrets: in every
    /// regular file for an unscoped secret, and only in its own files for a
    /// scoped one. Call after seeding files and before `load`.
    pub fn expand_secrets(&mut self) -> Result<(), String> {
        if self.secrets.is_empty() {
            return Ok(());
        }
        let mut everywhere: Vec<(String, String)> = Vec::new();
        let mut scoped: Vec<(Vec<u8>, (String, String))> = Vec::new();
        for (name, secret) in &self.secrets {
            let sub = (format!("${{{name}}}"), secret.value.clone());
            if secret.paths.is_empty() {
                everywhere.push(sub);
            } else {
                for path in &secret.paths {
                    scoped.push((path.clone(), sub.clone()));
                }
            }
        }
        if !everywhere.is_empty() {
            self.vfs
                .rewrite_files(&everywhere)
                .map_err(|errno| format!("cannot expand unscoped secrets: errno {errno}"))?;
        }
        for (path, sub) in scoped {
            self.vfs
                .rewrite_file(&path, std::slice::from_ref(&sub))
                .map_err(|errno| {
                    format!(
                        "cannot expand secret in {}: errno {errno}",
                        path.escape_ascii()
                    )
                })?;
        }
        Ok(())
    }

    /// The reverse map (`value -> ${name}`) used to redact snapshots. Scope
    /// does not narrow this: wherever a value ended up, a snapshot must not
    /// carry it.
    pub(crate) fn secret_redactions(&self) -> Vec<(String, String)> {
        self.secrets
            .iter()
            .map(|(name, secret)| (secret.value.clone(), format!("${{{name}}}")))
            .collect()
    }

    /// Restores values after snapshot redaction without touching a new cold
    /// base file that may have been installed since secrets were expanded.
    /// Only resident overlays could have contained a value to redact.
    fn restore_resident_secrets(&mut self) {
        for (name, secret) in &self.secrets {
            let sub = (format!("${{{name}}}"), secret.value.clone());
            if secret.paths.is_empty() {
                self.vfs.rewrite_resident_files(std::slice::from_ref(&sub));
                continue;
            }
            for path in &secret.paths {
                if self.vfs.read_file(path).is_some() {
                    // `read_file` only returns resident regular files, so no
                    // materialization, quota, or missing-chunk error remains.
                    let _ = self.vfs.rewrite_file(path, std::slice::from_ref(&sub));
                }
            }
        }
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

    /// True when the CPU is stopped at a manifest-backed access fault and the
    /// host still owes the chunk named by [`Pager::pending`].
    pub fn awaiting_page_in(&self) -> bool {
        self.page_in_wait
    }

    pub(crate) fn request_file_chunk(&mut self, hash: chunk::Hash) -> Result<(), String> {
        if let Some(pending) = &self.file_chunk_wait {
            return (pending.hash == hash)
                .then_some(())
                .ok_or_else(|| "a second file chunk was requested while one is pending".into());
        }
        self.next_file_ticket = self.next_file_ticket.wrapping_add(1).max(1);
        self.file_chunk_wait = Some(FileChunkRequest {
            // Keep the namespace distinct from page tickets for diagnostics.
            ticket: self.next_file_ticket | (1_u64 << 63),
            hash,
        });
        self.page_in_wait = true;
        Ok(())
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
        // Only hash when a manifest is installed to check against; with no
        // manifest — the default — the digest is discarded, so computing it over
        // the whole file (a mounted tree, a hundred-megabyte agent image) is
        // pure waste. Streamed delivery (`create_file`) already gates its digest
        // this way.
        if self.manifest.is_some() {
            self.check_against_manifest(path, &crate::digest::sha256(&bytes), bytes.len())?;
        }
        let added = self
            .vfs
            .add_node(path, NodeKind::File(bytes), mode)
            .map(|_| ())
            .map_err(|e| format!("cannot add {}: errno {e}", path.escape_ascii()));
        // Writing over a name displaces whatever held it. Reclaim now rather
        // than at some later unlink: until this runs the old contents are
        // still in the arena, still counted, and still written into every
        // snapshot taken in between.
        self.reclaim_unlinked();
        added
    }

    /// Starts a file that will be delivered in pieces, reserving room for
    /// `capacity` bytes. An agent image is hundreds of megabytes; buffering
    /// one whole copy on the way in is the difference between fitting in a
    /// tab and not.
    pub fn create_file(&mut self, path: &[u8], capacity: usize, mode: u32) -> Result<(), String> {
        // A streamed image is judged when the last piece lands, not here:
        // nothing is known about its bytes yet. Start the digest.
        if self.manifest.is_some() {
            self.in_flight
                .insert(path.to_vec(), (crate::digest::Sha256::new(), 0));
        }
        let created = self
            .vfs
            .create_file_with_capacity(path, capacity, mode)
            .map(|_| ())
            .map_err(|e| format!("cannot create {}: errno {e}", path.escape_ascii()));
        // See `add_file`: a restarted delivery displaces the abandoned one.
        self.reclaim_unlinked();
        created
    }

    /// Refuses an image the manifest does not vouch for, at the moment
    /// before it runs.
    ///
    /// A streamed image was hashed as it arrived, so this costs nothing for
    /// the large ones; anything else is hashed here. With no manifest
    /// installed nothing is checked, which is the default.
    pub(crate) fn verify_image(&mut self, path: &[u8]) -> Result<(), String> {
        let resolved = self
            .vfs
            .resolve(self.proc.cwd, path, true)
            .map_err(|errno| format!("cannot load {}: errno {errno}", path.escape_ascii()))?;
        let node = resolved
            .node
            .ok_or_else(|| format!("cannot load {}: no such file", path.escape_ascii()))?;

        // Once a chunk manifest is installed it is the executable allowlist,
        // including after a snapshot restore. A mutable resident overlay is
        // guest state, not authenticated base-image authority: allow it to run
        // only when its complete bytes still reproduce the manifest layout.
        // This keeps configuration overlays writable without letting one
        // shadow a signed executable path and bypass verification.
        if let Some(manifest) = self.chunk_manifest.as_ref() {
            if self.vfs.manifest_root() != Some(manifest.root()) {
                return Err(
                    "refused: snapshot manifest root is not the installed authority".into(),
                );
            }
            let resolved_path = self.vfs.abs_path_of(node);
            let (expected, _) = manifest.file(&resolved_path).ok_or_else(|| {
                format!(
                    "refused: {} is not in the chunk manifest",
                    resolved_path.escape_ascii()
                )
            })?;
            match &self.vfs.node(node).kind {
                NodeKind::ChunkedFile(actual) if actual == expected => return Ok(()),
                NodeKind::ChunkedFile(_) => {
                    return Err(format!(
                        "refused: {} chunk layout differs from the manifest",
                        path.escape_ascii()
                    ));
                }
                NodeKind::File(data) if resident_matches_chunk_layout(data, expected) => {
                    return Ok(());
                }
                NodeKind::File(_) => {
                    return Err(format!(
                        "refused: {} resident bytes differ from the chunk manifest",
                        path.escape_ascii()
                    ));
                }
                _ => {
                    return Err(format!(
                        "refused: {} is not a regular manifest file",
                        path.escape_ascii()
                    ));
                }
            }
        }

        if matches!(self.vfs.node(node).kind, NodeKind::ChunkedFile(_)) {
            return Err(format!(
                "refused: {} is chunked but no authenticated chunk manifest is installed",
                path.escape_ascii()
            ));
        }
        if self.manifest.is_none() {
            return Ok(());
        }
        let (digest, size) = match self.in_flight.remove(path) {
            Some((hasher, size)) => (hasher.finish(), size),
            None => {
                let bytes = self
                    .vfs
                    .read_file(path)
                    .ok_or_else(|| format!("cannot load {}: no such file", path.escape_ascii()))?;
                (crate::digest::sha256(bytes), bytes.len())
            }
        };
        self.check_against_manifest(path, &digest, size)
    }

    /// Whether a delivered image is the one the manifest names.
    ///
    /// With no manifest, everything passes: a host with nothing to verify
    /// against is not stopped from running. With one, an image it does not
    /// name is refused too — a manifest is a list of what may be delivered,
    /// and waving through what it does not mention is how an image gets in.
    fn check_against_manifest(
        &self,
        path: &[u8],
        digest: &[u8; 32],
        size: usize,
    ) -> Result<(), String> {
        let Some(manifest) = self.manifest.as_ref() else {
            return Ok(());
        };
        manifest
            .check(path, digest, size)
            .map_err(|why| format!("refused: {why}"))
    }

    /// Appends one piece to a file started with [`create_file`].
    pub fn append_file(&mut self, path: &[u8], bytes: &[u8]) -> Result<(), String> {
        if let Some((hasher, size)) = self.in_flight.get_mut(path) {
            hasher.update(bytes);
            *size += bytes.len();
        }
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

    /// Records an event when a trace is being collected.
    pub(crate) fn trace_event(&mut self, event: trace::Event) {
        if let Some(trace) = self.trace.as_mut() {
            trace.push(event);
        }
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
        // `Cpu::reset` resets architectural registers and the active
        // exception, but a host-wait retry may also have queued the old
        // syscall/access exception separately. It belongs to the discarded
        // process and must never be presented to the new entry point.
        cpu.pending_exception = None;

        // Null page: faults with a permission error instead of unmapped.
        cpu.mem.map_memory_len(
            0,
            PAGE_SIZE,
            Mapping {
                perm: perm::NONE,
                value: 0,
            },
        );

        let chunked = self
            .vfs
            .resolve(self.proc.cwd, path, true)
            .ok()
            .and_then(|resolved| resolved.node)
            .is_some_and(|node| matches!(self.vfs.node(node).kind, NodeKind::ChunkedFile(_)));
        let metadata = if chunked {
            lazy_elf::load(self, cpu, path, 0)?
        } else {
            self.load_elf(cpu, path)?
        };

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
        // The generic loader calls this again for PT_INTERP. Manifest policy
        // applies to every executable image, not only the path the host named
        // in Machine::load.
        self.verify_image(path)?;
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
        // A host `load` replaces the current root process just as guest
        // `execve` replaces an address space. A previous turn may still be
        // stopped on a page or file-chunk ticket; neither authority may
        // survive into the replacement image. In particular, a late browser
        // response must fail as stale instead of filling a mapping owned by
        // the process that was just discarded.
        let old_asid = self.proc.asid;
        self.pager.drop_space(old_asid);
        self.file_chunk_wait = None;
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
        self.page_in_wait = false;
        self.page_in_recompile = false;
        // And a fresh address space, exactly as `execve` does. `Process::initial`
        // hands out id 0 every time, so without this a second image loaded into
        // the same machine keys its blocks identically to the first — and two
        // static binaries commonly share a load address, which meant the second
        // one ran the first one's code.
        self.proc.asid = crate::alloc_asid();
        x64_engine::vm::set_current_asid(self.proc.asid);
        self.start_image(cpu, path)
    }

    fn handle_exception(&mut self, cpu: &mut Cpu) -> Option<VmExit> {
        let code = ExceptionCode::from_u32(cpu.exception.code);
        let access = match code {
            ExceptionCode::ReadUnmapped
            | ExceptionCode::ReadPerm
            | ExceptionCode::ReadUninitialized => Some(AccessKind::Read),
            ExceptionCode::WriteUnmapped | ExceptionCode::WritePerm => Some(AccessKind::Write),
            ExceptionCode::ExecViolation => Some(AccessKind::Execute),
            _ => None,
        };
        if let Some(access) = access {
            match self
                .pager
                .resolve(&self.vfs, self.proc.asid, cpu.exception.value, access)
            {
                FaultResolution::Ready { page, bytes, perm } => {
                    let fault_address = cpu.exception.value;
                    if cpu.mem.write_bytes(page, &bytes, perm::NONE).is_ok()
                        && cpu.mem.update_perm(page, PAGE_SIZE, perm).is_ok()
                    {
                        cpu.exception.clear();
                        self.pager.mark_resident(self.proc.asid, page, access);
                        self.page_in_wait = false;
                        if access == AccessKind::Execute {
                            // A code-page miss usually happened while the
                            // lifter was reading source bytes, before a block
                            // existed. Leave `block_id = MAX`: the next VM
                            // pass raises CodeNotTranslated and lifts again
                            // from the now-resident bytes. Queuing a second
                            // ExternalAddr exception here is incorrect for a
                            // cross-page lift: it can replay the original
                            // ExecViolation after both pages are resident.
                            // Data faults keep their proven block-offset retry
                            // path unchanged.
                            let rip = fault_address;
                            cpu.write_pc(rip);
                            cpu.block_id = u64::MAX;
                            cpu.block_offset = 0;
                            self.page_in_recompile = true;
                            return Some(VmExit::Interrupted);
                        } else {
                            // The instruction marker already retired before
                            // this restartable data fault. Tell the engine not
                            // to apply its ordinary mid-block missing-marker
                            // compensation when the same p-code is retried.
                            x64_engine::vm::mark_page_in_retry();
                        }
                        return Some(VmExit::Running);
                    }
                }
                FaultResolution::Missing(_) => {
                    self.page_in_wait = true;
                    return Some(VmExit::Interrupted);
                }
                FaultResolution::Invalid(why) => {
                    tracing::error!("page-in refused: {why}");
                }
                FaultResolution::NotLazy => {}
            }
        }
        match code {
            ExceptionCode::Syscall => syscall::handle(self, cpu),
            _ => None,
        }
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(())
    }

    fn restore(&mut self, _: &Box<dyn std::any::Any>) {}
}

/// A digest over the SLEIGH source files a browser host provides, sorted by
/// name so the order the host happened to hand them in does not change the
/// answer. Two hosts with the same spec get the same fingerprint; a changed
/// grammar file changes it.
fn fingerprint_spec_files(files: &HashMap<String, String>) -> [u8; 32] {
    let mut names: Vec<&String> = files.keys().collect();
    names.sort();
    let mut hasher = crate::digest::Sha256::new();
    for name in names {
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
        let content = &files[name];
        hasher.update(&(content.len() as u64).to_le_bytes());
        hasher.update(content.as_bytes());
    }
    hasher.finish()
}

/// The same, over the files in a spec directory on disk. Unreadable entries
/// are skipped rather than failing the build: the fingerprint is an
/// identity, and a directory that cannot be fully read still has a stable
/// identity among the files that can. A directory that changes what it lifts
/// changes at least one readable file.
fn fingerprint_spec_dir(dir: &Path) -> [u8; 32] {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    let Ok(read) = std::fs::read_dir(dir) else {
        return [0; 32];
    };
    for entry in read.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Ok(bytes) = std::fs::read(entry.path()) {
            entries.push((name, bytes));
        }
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = crate::digest::Sha256::new();
    for (name, bytes) in &entries {
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finish()
}

pub(crate) fn align_up(value: u64, align: u64) -> u64 {
    let mask = !(align - 1);
    value.checked_add(align - 1).map_or(mask, |v| v & mask)
}

/// A complete Linux x86-64 user-mode machine: the interpreter VM plus this
/// crate's environment.
pub struct Machine {
    vm: InterpVm,
    /// Ceiling on the total footprint, or None for unbounded. See
    /// [`Machine::set_memory_budget`].
    memory_budget: Option<usize>,
    /// Ceiling on retired instructions, or None for unbounded. See
    /// [`Machine::set_cpu_budget`].
    cpu_budget: Option<u64>,
    /// Ceiling on recorded trace events, or None for unbounded. See
    /// [`Machine::set_event_log_budget`].
    event_log_budget: Option<usize>,
    /// A digest of the SLEIGH specification this machine lifts under.
    ///
    /// Lifting is a pure function of the guest bytes, the address, the
    /// context, and the specification. The in-process lift cache already
    /// keys on the first three; this is the fourth. Anything persisted from
    /// the cache would be p-code produced under exactly this spec, and
    /// executing p-code lifted under a different one against this register
    /// file is silent wrong execution — so a persisted artifact carries this,
    /// and a mismatch is refused rather than trusted.
    spec_fingerprint: [u8; 32],
}

/// What a machine occupies, split by what it is spent on. All three live in
/// one wasm linear memory and compete for its ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Footprint {
    /// Guest physical pages the MMU has handed out.
    pub guest_bytes: usize,
    /// Lifted p-code and the guest bytes kept to validate its reuse.
    pub code_bytes: usize,
    /// File contents and symlink targets in the guest filesystem.
    pub files_bytes: usize,
    pub total_bytes: usize,
}

/// Delivered versus opened files, for sizing a lazy-delivery win.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileAccessStats {
    pub delivered_files: usize,
    pub delivered_bytes: usize,
    pub opened_files: usize,
    pub opened_bytes: usize,
}

/// One live `MAP_SHARED` file mapping (see `LinuxEnv::shared_maps`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedMap {
    pub(crate) asid: u64,
    pub(crate) addr: u64,
    pub(crate) len: u64,
    pub(crate) node: usize,
    pub(crate) offset: u64,
}

impl Machine {
    /// Builds a machine from a SLEIGH `.ldefs` path (native hosts).
    pub fn from_ldef(ldef_path: &Path, config: &EngineConfig) -> Result<Self, String> {
        let vm = build_x64_vm(ldef_path, config).map_err(|e| e.to_string())?;
        // The ldef names a grammar spread across a directory of includes;
        // fingerprint the directory, since any of those files changing
        // changes what the bytes lift to.
        let fingerprint = ldef_path
            .parent()
            .map(fingerprint_spec_dir)
            .unwrap_or([0; 32]);
        Self::finish(vm, fingerprint)
    }

    /// Builds a machine from in-memory SLEIGH sources (browser hosts).
    pub fn from_spec_files(
        files: HashMap<String, String>,
        config: &EngineConfig,
    ) -> Result<Self, String> {
        let fingerprint = fingerprint_spec_files(&files);
        let vm = build_x64_vm_from_files(files, config).map_err(|e| e.to_string())?;
        Self::finish(vm, fingerprint)
    }

    fn finish(mut vm: InterpVm, spec_fingerprint: [u8; 32]) -> Result<Self, String> {
        let env = LinuxEnv::new(&vm.cpu)?;
        vm.set_env(env);
        Ok(Self {
            vm,
            memory_budget: None,
            cpu_budget: None,
            event_log_budget: None,
            spec_fingerprint,
        })
    }

    /// The digest of the SLEIGH specification this machine lifts under. Any
    /// artifact persisted from the lift cache must carry this and be refused
    /// on a mismatch, because p-code lifted under one spec is not valid under
    /// another.
    pub fn spec_fingerprint(&self) -> [u8; 32] {
        self.spec_fingerprint
    }

    pub fn env(&mut self) -> &mut LinuxEnv {
        self.vm
            .env_mut::<LinuxEnv>()
            .expect("machine environment is always LinuxEnv")
    }

    /// Adds a file to the guest filesystem (parent directories are created).
    /// Refused when it would not fit the memory budget.
    pub fn add_file(&mut self, path: &[u8], bytes: Vec<u8>, mode: u32) -> Result<(), String> {
        self.check_budget(bytes.len())?;
        self.env().add_file(path, bytes, mode)
    }

    /// Installs a manifest-pinned file without making its payload resident.
    pub fn add_chunked_file(
        &mut self,
        path: &[u8],
        file: chunk::ChunkedFile,
        mode: u32,
    ) -> Result<(), String> {
        if let Some(manifest) = &self.env().chunk_manifest {
            let Some((expected, _)) = manifest.file(path) else {
                return Err(format!(
                    "refused: {} is not in the chunk manifest",
                    path.escape_ascii()
                ));
            };
            if expected != &file {
                return Err(format!(
                    "refused: {} chunk layout differs from the manifest",
                    path.escape_ascii()
                ));
            }
        }
        self.env()
            .vfs
            .add_chunked_file(path, file, mode)
            .map(|_| ())
            .map_err(|errno| format!("cannot add {}: errno {errno}", path.escape_ascii()))
    }

    /// Adds a verified warm chunk before execution (for bounded ELF metadata
    /// or a host cache hit).
    pub fn put_chunk(&mut self, hash: chunk::Hash, bytes: Vec<u8>) -> Result<(), String> {
        if !self.env().vfs.has_chunk(&hash) {
            self.check_budget(bytes.capacity())?;
        }
        self.env().vfs.put_chunk(hash, bytes)
    }

    /// The cold page request currently stopping execution, if any.
    pub fn page_request(&mut self) -> Option<ChunkRequest> {
        let env = self.env();
        if let Some(request) = env.pager.pending() {
            return Some(ChunkRequest {
                ticket: request.ticket,
                hash: request.hash,
                asid: request.asid,
                generation: request.generation,
                page: request.page,
                access: Some(request.access),
            });
        }
        env.file_chunk_wait.as_ref().map(|request| ChunkRequest {
            ticket: request.ticket,
            hash: request.hash,
            asid: 0,
            generation: 0,
            page: 0,
            access: None,
        })
    }

    /// Completes exactly one page-in ticket. Hash, quota, address-space id,
    /// and mapping generation are checked before the bytes become usable.
    pub fn deliver_page(&mut self, ticket: u64, bytes: Vec<u8>) -> Result<(), String> {
        let expected_hash = self
            .page_request()
            .filter(|request| request.ticket == ticket)
            .map(|request| request.hash);
        if expected_hash.is_none_or(|hash| !self.env().vfs.has_chunk(&hash)) {
            self.check_budget(bytes.capacity())?;
        }
        let completed_page_fault = {
            let env = self.env();
            if env
                .pager
                .pending()
                .is_some_and(|request| request.ticket == ticket)
            {
                env.pager.complete(&mut env.vfs, ticket, bytes)?;
                true
            } else {
                let request = env
                    .file_chunk_wait
                    .as_ref()
                    .ok_or("no chunk request is pending")?;
                if request.ticket != ticket {
                    return Err("chunk ticket does not match the pending request".into());
                }
                env.vfs.put_chunk(request.hash, bytes)?;
                env.file_chunk_wait = None;
                false
            }
        };
        if completed_page_fault {
            // The CPU is still stopped on the original access exception. Make
            // the VM present it to the environment before it executes any
            // more p-code, so the newly available chunk is mapped first. If
            // we merely resume, the same p-code faults once more before the
            // normal post-block exception path and that failed retry consumes
            // fuel despite retiring no instruction.
            let exception = self.vm.cpu.exception;
            self.vm.cpu.pending_exception = Some(exception);
        }
        self.env().page_in_wait = false;
        Ok(())
    }

    pub fn page_in_count(&mut self) -> u64 {
        self.env().pager.page_ins()
    }

    /// Pages first made resident by read, write, and instruction-fetch
    /// accesses, in that order. This is diagnostic accounting only; it does
    /// not affect scheduling or architectural traces.
    pub fn page_in_access_counts(&mut self) -> [u64; 3] {
        self.env().pager.page_ins_by_access()
    }

    /// Adds a symlink to the guest filesystem.
    pub fn add_symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), String> {
        self.env().add_symlink(path, target)
    }

    /// Starts a file delivered in pieces; see [`LinuxEnv::create_file`].
    ///
    /// The whole reservation is charged here, before any of it arrives: an
    /// image that cannot fit should be refused at the request, not part-way
    /// through a download the host has already paid for.
    pub fn create_file(&mut self, path: &[u8], capacity: usize, mode: u32) -> Result<(), String> {
        self.check_budget(capacity)?;
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

    /// Starts recording an architectural trace, sampling registers and flags
    /// every `sample_every` retired instructions (0 records events only).
    /// Call after `load`, so the trace's header describes what is running.
    pub fn record_trace(&mut self, sample_every: u64) {
        let mut collected = trace::Trace::new(&self.vm.cpu, sample_every);
        collected.set_budget(self.event_log_budget);
        let env = self.env();
        collected.set_args(&env.proc.argv, &env.proc.envp);
        if let Some(manifest) = &env.chunk_manifest {
            if let Some((file, legacy_fnv)) = manifest.file(&env.proc.exe_path) {
                collected.set_manifest_image(
                    &env.proc.exe_path,
                    file.size,
                    manifest.root(),
                    legacy_fnv,
                );
            }
        }
        env.trace = Some(collected);
    }

    /// Names the image a trace is of, so the file identifies its own subject.
    pub fn describe_trace_image(&mut self, path: &[u8], bytes: &[u8]) {
        if let Some(trace) = self.env().trace.as_mut() {
            trace.set_image(path, bytes);
        }
    }

    /// Takes the recorded trace, if any.
    pub fn take_trace(&mut self) -> Option<trace::Trace> {
        self.env().trace.take()
    }

    /// Runs until the guest stops or `limit` instructions have retired,
    /// breaking at exact instruction counts to sample architectural state.
    /// Sample points are a function of the guest's own execution rather than
    /// of how the host sliced it, so two runs sample in the same places.
    pub fn run_traced(&mut self, limit: u64) -> CpuExit {
        let budget_end = self.icount().saturating_add(limit);
        loop {
            let sample_at = {
                let InterpVm { cpu, env, .. } = &mut self.vm;
                let env = env
                    .as_mut_any()
                    .downcast_mut::<LinuxEnv>()
                    .expect("machine environment is always LinuxEnv");
                match env.trace.as_mut() {
                    Some(trace) => {
                        // The first sample is the state before anything runs.
                        if trace.next_sample() == Some(0) && cpu.icount() == 0 {
                            trace.sample(cpu);
                        }
                        trace.next_sample()
                    }
                    None => None,
                }
            };
            let stop_at = sample_at.map_or(budget_end, |at| at.min(budget_end));
            self.vm.icount_limit = stop_at;
            let exit = self.run();
            if exit == CpuExit::InstructionLimit && self.icount() < budget_end {
                let InterpVm { cpu, env, .. } = &mut self.vm;
                let env = env
                    .as_mut_any()
                    .downcast_mut::<LinuxEnv>()
                    .expect("machine environment is always LinuxEnv");
                if let Some(trace) = env.trace.as_mut() {
                    trace.sample(cpu);
                    continue;
                }
            }
            // A page-in is a host transport pause, not an architectural stop.
            // Do not add a Stop event or a duplicate sample; after delivery,
            // the same run continues at the same p-code and sample schedule.
            if exit == CpuExit::Interrupted && self.env().awaiting_page_in() {
                return exit;
            }
            // A final sample makes the end state part of the record.
            let icount = self.icount();
            let InterpVm { cpu, env, .. } = &mut self.vm;
            let env = env
                .as_mut_any()
                .downcast_mut::<LinuxEnv>()
                .expect("machine environment is always LinuxEnv");
            if let Some(trace) = env.trace.as_mut() {
                match &exit {
                    CpuExit::Halt { code } => trace.push(trace::Event::Exit {
                        icount,
                        code: code.unwrap_or(-1),
                    }),
                    other => trace.push(trace::Event::Stop {
                        icount,
                        reason: format!("{other:?}"),
                    }),
                }
                trace.sample(cpu);
            }
            return exit;
        }
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

    /// Lifts blocks without the p-code optimizer until one has been entered
    /// `threshold` times. See [`InterpVm::set_lift_tiering`]; the default is
    /// to optimize every block as it is lifted.
    pub fn set_lift_tiering(&mut self, threshold: Option<u64>) {
        self.vm.set_lift_tiering(threshold);
    }

    /// Installs a JIT backend that compiles hot blocks to wasm and runs them in
    /// place of the interpreter. See [`InterpVm::set_jit`].
    pub fn set_jit(&mut self, backend: Box<dyn x64_engine::jit::JitBackend>) {
        self.vm.set_jit(backend);
    }

    /// Compiles a block after it has been entered `after` times; `None` turns
    /// the JIT off. See [`InterpVm::set_jit_tiering`].
    pub fn set_jit_tiering(&mut self, after: Option<u64>) {
        self.vm.set_jit_tiering(after);
    }

    /// How many times a compiled block ran in place of the interpreter.
    pub fn jit_dispatch_count(&self) -> u64 {
        self.vm.jit_dispatch_count()
    }

    pub fn jit_block_dispatch_count(&self) -> u64 {
        self.vm.jit_block_dispatch_count()
    }

    pub fn jit_region_dispatch_count(&self) -> u64 {
        self.vm.jit_region_dispatch_count()
    }

    /// Enables or disables exact unique executed-source-byte accounting.
    /// Intended for explicit image materialization measurements, not ordinary
    /// production runs where even a disabled branch is unnecessary overhead.
    pub fn track_executed_bytes(&mut self, enabled: bool) {
        self.vm.track_executed_bytes(enabled);
    }

    pub fn executed_byte_count(&self) -> u64 {
        self.vm.executed_byte_count()
    }

    /// Caps the wasm code the JIT may hold, in bytes (`0` = unlimited). See
    /// [`InterpVm::set_jit_code_budget`].
    pub fn set_jit_code_budget(&mut self, bytes: usize) {
        self.vm.set_jit_code_budget(bytes);
    }

    /// A snapshot of the compiled-code budget and its metrics.
    pub fn jit_code_stats(&self) -> x64_engine::vm::JitCodeStats {
        self.vm.jit_code_stats()
    }

    /// Turns wall-clock phase accounting (exec/lift/syscall) on or off.
    pub fn set_phase_timing(&mut self, on: bool) {
        self.vm.set_phase_timing(on);
    }

    /// The accumulated phase wall-clock, or `None` if timing is off.
    pub fn phase_times(&self) -> Option<x64_engine::vm::PhaseTimes> {
        self.vm.phase_times()
    }

    /// Turns file-access tracking on or off (which delivered files the guest
    /// opens). Off by default.
    pub fn set_access_tracking(&mut self, on: bool) {
        self.env().opened_files = on.then(std::collections::HashSet::new);
    }

    /// Delivered files/bytes versus the ones the guest actually opened — the
    /// untouched-image fraction a lazy delivery could avoid materializing.
    pub fn file_access_stats(&mut self) -> FileAccessStats {
        let env = self.env();
        let opened = env.opened_files.as_ref();
        let mut s = FileAccessStats::default();
        for (idx, node) in env.vfs.nodes.iter().enumerate() {
            let bytes = match &node.kind {
                crate::vfs::NodeKind::File(data) => data.len() as u64,
                crate::vfs::NodeKind::ChunkedFile(file) => file.size,
                _ => continue,
            };
            s.delivered_files += 1;
            s.delivered_bytes += bytes as usize;
            if opened.is_some_and(|o| o.contains(&idx)) {
                s.opened_files += 1;
                s.opened_bytes += bytes as usize;
            }
        }
        s
    }

    /// Records per-block entry counts, so [`jit_coverage`](Self::jit_coverage)
    /// can weigh JIT coverage by what actually executed.
    pub fn profile_blocks(&mut self, enabled: bool) {
        self.vm.profile_blocks(enabled);
    }

    /// How well the JIT covers the blocks a profiled run executed; `None` if
    /// profiling was not on. See [`InterpVm::jit_coverage`].
    pub fn jit_coverage(&self) -> Option<x64_engine::vm::JitCoverage> {
        self.vm.jit_coverage()
    }

    /// What the machine occupies, split by what it is spent on. One wasm
    /// linear memory holds all three, and a browser tab's ceiling is roughly
    /// 3.9 GiB (`docs/performance.md`), so they compete: an agent image, the
    /// guest's own pages, and the code the engine has lifted.
    /// Takes `&mut self` because the guest filesystem is reached through the
    /// environment's downcast, as everywhere else in this type.
    pub fn footprint(&mut self) -> Footprint {
        let guest_bytes = self.vm.cpu.mem.total_pages() * 4096;
        let code_bytes = self.vm.lifted_bytes();
        let files_bytes = self.env().vfs.bytes();
        Footprint {
            guest_bytes,
            code_bytes,
            files_bytes,
            total_bytes: guest_bytes + code_bytes + files_bytes,
        }
    }

    /// Sets a ceiling on the total footprint, or clears it with None.
    ///
    /// The point is to refuse work while refusing is still possible. Streaming
    /// a 258 MB image into a tab that cannot hold it fails somewhere in the
    /// middle, with the allocation that happens to be unlucky; checked here,
    /// it fails before the first byte with a number the host can report.
    pub fn set_memory_budget(&mut self, bytes: Option<usize>) {
        self.memory_budget = bytes;
    }

    /// The budget, and what is left of it. None when no budget is set.
    pub fn memory_headroom(&mut self) -> Option<usize> {
        self.memory_budget
            .map(|budget| budget.saturating_sub(self.footprint().total_bytes))
    }

    /// Installs the manifest the host has committed to, or clears it with
    /// None.
    ///
    /// The signature over it is the host's to check, with the platform's
    /// verifier, before this is called: what arrives here is already
    /// authenticated, and this layer is responsible only for the bytes
    /// matching what it says.
    pub fn set_manifest(&mut self, text: Option<&[u8]>) -> Result<(), String> {
        let parsed = match text {
            Some(text) => Some(crate::manifest::Manifest::parse(text)?),
            None => None,
        };
        self.env().manifest = parsed;
        Ok(())
    }

    /// Parses and installs one authenticated immutable image description.
    /// Payload chunks remain absent; only directory metadata, symlinks and
    /// file hash tables enter the VFS. The SHA-256 of the exact canonical
    /// bytes is retained as the image and snapshot identity.
    pub fn install_chunk_manifest(&mut self, text: &[u8]) -> Result<[u8; 32], String> {
        use crate::chunk_manifest::EntryKind;

        let manifest = crate::chunk_manifest::ChunkManifest::parse(text)?;
        let root = manifest.root();
        let env = self.env();

        // A v3 snapshot already contains the namespace, immutable
        // descriptors, and resident mutation overlays. Re-installing the
        // authenticated bytes is a rebind, not an image extraction: replacing
        // nodes here would lose guest mutations and append dead descriptors on
        // every reload. The root must match, and every descriptor carried by
        // the snapshot must occur in that authority; renamed/hard-linked base
        // files are allowed because those are guest namespace changes.
        if let Some(snapshot_root) = env.vfs.manifest_root() {
            if snapshot_root != root {
                return Err("snapshot manifest root differs from the installed authority".into());
            }
            let authorized = manifest
                .entries()
                .iter()
                .filter_map(|entry| match &entry.kind {
                    EntryKind::File { file, .. } => Some(file),
                    _ => None,
                })
                .collect::<Vec<_>>();
            for node in &env.vfs.nodes {
                if let crate::vfs::NodeKind::ChunkedFile(file) = &node.kind {
                    if !authorized.contains(&file) {
                        return Err(
                            "snapshot contains a chunk descriptor outside its manifest authority"
                                .into(),
                        );
                    }
                }
            }
            env.chunk_manifest = Some(manifest);
            return Ok(root);
        }

        fn apply(
            vfs: &mut crate::vfs::Vfs,
            manifest: &crate::chunk_manifest::ChunkManifest,
        ) -> Result<(), String> {
            for entry in manifest.entries() {
                let node = match &entry.kind {
                    EntryKind::Dir => vfs.mkdir_p(&entry.path).map_err(|errno| {
                        format!("cannot mkdir {}: errno {errno}", entry.path.escape_ascii())
                    })?,
                    EntryKind::Symlink(target) => vfs
                        .add_node(
                            &entry.path,
                            crate::vfs::NodeKind::Symlink(target.clone()),
                            entry.mode,
                        )
                        .map_err(|errno| {
                            format!("cannot link {}: errno {errno}", entry.path.escape_ascii())
                        })?,
                    EntryKind::File { file, .. } => vfs
                        .add_chunked_file(&entry.path, file.clone(), entry.mode)
                        .map_err(|errno| {
                            format!("cannot add {}: errno {errno}", entry.path.escape_ascii())
                        })?,
                };
                let node = vfs.node_mut(node);
                node.mode = entry.mode;
                node.mtime_sec = entry.mtime_sec;
            }
            Ok(())
        }

        // Validate the complete topology against a payload-free shadow before
        // mutating the live VFS. A malformed but correctly signed manifest
        // therefore cannot leave a half-installed namespace behind.
        let mut shadow = env.vfs.topology_only();
        apply(&mut shadow, &manifest)?;
        apply(&mut env.vfs, &manifest)?;
        env.vfs.set_manifest_root(Some(root));
        env.chunk_manifest = Some(manifest);
        Ok(root)
    }

    /// The paths the installed manifest names, for a host that wants to
    /// report what it is committed to. Empty when none is installed.
    pub fn manifest_paths(&mut self) -> Vec<Vec<u8>> {
        self.env()
            .manifest
            .as_ref()
            .map(|m| m.paths().cloned().collect())
            .unwrap_or_default()
    }

    /// Sets a ceiling on the instructions the workload may retire over its
    /// life, or clears it with None.
    ///
    /// The instruction limit on a run is not this. That one ends a turn so
    /// the host can do its own work and call again, and a host's loop calls
    /// again for as long as the guest keeps asking — which a guest computing
    /// in a loop, issuing no syscalls, does forever. Nothing else in the
    /// machine says stop to it: the terminal's interrupt character reaches a
    /// task at a kernel entry, and that task never makes one.
    ///
    /// Spent, `run` returns [`CpuExit::OutOfCpu`] without executing anything
    /// further. Raising the budget lets it continue where it stopped, so a
    /// host can ask a person before granting more.
    pub fn set_cpu_budget(&mut self, instructions: Option<u64>) {
        self.cpu_budget = instructions;
    }

    /// Instructions the workload may still retire, or None when unbounded.
    pub fn cpu_headroom(&self) -> Option<u64> {
        self.cpu_budget
            .map(|budget| budget.saturating_sub(self.icount()))
    }

    /// Sets a ceiling on the events the trace may record, or clears it with
    /// None. Takes effect on the trace now being recorded and on any started
    /// afterwards.
    ///
    /// See [`trace::Trace::set_budget`] for why this one stops recording
    /// rather than stopping the workload.
    pub fn set_event_log_budget(&mut self, events: Option<usize>) {
        self.event_log_budget = events;
        if let Some(trace) = self.env().trace.as_mut() {
            trace.set_budget(events);
        }
    }

    /// Events that happened after the ceiling was reached, and so were not
    /// recorded. Zero when the log kept up.
    pub fn event_log_dropped(&mut self) -> u64 {
        self.env().trace.as_ref().map_or(0, trace::Trace::dropped)
    }

    /// Events the log is holding. Zero when nothing is being recorded.
    pub fn event_log_len(&mut self) -> usize {
        self.env()
            .trace
            .as_ref()
            .map_or(0, |trace| trace.events().len())
    }

    /// Rejects an addition that would not fit, naming what it would cost and
    /// what is left.
    fn check_budget(&mut self, adding: usize) -> Result<(), String> {
        let Some(budget) = self.memory_budget else {
            return Ok(());
        };
        let footprint = self.footprint();
        if footprint.total_bytes + adding <= budget {
            return Ok(());
        }
        let mib = |bytes: usize| bytes as f64 / (1024.0 * 1024.0);
        Err(format!(
            "over the memory budget: {:.1} MiB more against {:.1} MiB free \
             (guest {:.1}, code {:.1}, files {:.1}, budget {:.1} MiB)",
            mib(adding),
            mib(budget.saturating_sub(footprint.total_bytes)),
            mib(footprint.guest_bytes),
            mib(footprint.code_bytes),
            mib(footprint.files_bytes),
            mib(budget),
        ))
    }

    /// Bytes the guest filesystem currently holds — the same number
    /// [`Footprint::files_bytes`] reports, and what the storage budget caps.
    pub fn storage_bytes(&mut self) -> usize {
        self.env().vfs.bytes()
    }

    /// Sets a ceiling on the guest filesystem, or clears it with None.
    ///
    /// Memory's budget refuses the host's requests; this one refuses the
    /// guest's. A runaway `while true; do echo >> /tmp/x; done` otherwise
    /// grows the tab's linear memory until the tab dies, with no error the
    /// guest could have handled. With a budget the write that would cross it
    /// returns `ENOSPC` — what a real kernel returns for a full filesystem,
    /// and what every program that writes files already knows how to report.
    ///
    /// The ceiling is on the whole filesystem, not on the guest's share of
    /// it: a preloaded image occupies the budget the way it occupies a real
    /// disk, so size this above the image. See
    /// [`vfs::Vfs::set_storage_budget`] for exactly which paths are refused,
    /// and for why deleting a file does not yet give its bytes back.
    pub fn set_storage_budget(&mut self, bytes: Option<usize>) {
        self.env().vfs.set_storage_budget(bytes);
    }

    /// Bytes the guest may still write, or None when no budget is set.
    pub fn storage_headroom(&mut self) -> Option<usize> {
        self.env().vfs.storage_headroom()
    }

    /// Bytes the guest has moved through the host broker, both ways. Counted
    /// whether or not a budget is set; see [`net::NetMeter`] for what is and
    /// is not included.
    pub fn network_usage(&mut self) -> net::NetUsage {
        self.env().net_meter.borrow().usage()
    }

    /// Sets a ceiling on the bytes the guest may relay through the host
    /// broker, or clears it with None.
    ///
    /// A tab is somebody else's bandwidth. Without this a guest can stream
    /// without end through the host's transport, and nothing in the machine
    /// says stop. Over the budget the guest's `send`/`recv` fails with
    /// `EPERM`, the errno a locally rejected packet gets.
    ///
    /// Independent of the memory budget: relayed bytes pass through, they do
    /// not accumulate in the footprint. May be set before or after
    /// [`Machine::set_network`].
    pub fn set_network_budget(&mut self, bytes: Option<usize>) {
        self.env().net_meter.borrow_mut().set_budget(bytes);
    }

    /// Bytes the guest may still relay, or None when no budget is set.
    pub fn network_headroom(&mut self) -> Option<usize> {
        self.env().net_meter.borrow().headroom()
    }

    /// Records that `nanos` of real time passed while nothing ran.
    ///
    /// A browser suspends a background tab: the worker stops being scheduled,
    /// and when it comes back, minutes have gone by outside. Nothing in a
    /// deterministic clock notices that on its own — this machine's time is
    /// retired instructions plus the idle warp, and neither moves while the
    /// host is not calling `run`. Without a way to say so, a resumed guest
    /// believes no time passed: its timers are still pending, its timeouts
    /// have not expired, and its idea of now disagrees with every peer it
    /// talks to.
    ///
    /// Both clocks move, because both move on a real machine whose process
    /// merely was not scheduled. Timers armed for a moment now past fire on
    /// the next run, and a periodic one reports how many periods it missed
    /// rather than firing once for each of them.
    pub fn skip_time(&mut self, nanos: u64) {
        let env = self.env();
        env.warp_nanos = env.warp_nanos.saturating_add(nanos);
    }

    /// Raises or lowers the guest's physical-memory cap, in mebibytes. The
    /// default is 1 GiB; a large runtime forking under load needs more, and a
    /// browser tab may have less to give. Returns false when the guest has
    /// already allocated past the requested cap.
    pub fn set_guest_memory_mb(&mut self, mb: usize) -> bool {
        // The MMU counts 4 KiB pages.
        self.vm.cpu.mem.set_capacity(mb.saturating_mul(256))
    }

    /// The guest's physical-memory cap and what it has actually allocated, in
    /// mebibytes — what a host needs to report pressure or refuse a workload.
    pub fn guest_memory_mb(&self) -> (usize, usize) {
        (
            self.vm.cpu.mem.total_pages() / 256,
            self.vm.cpu.mem.capacity() / 256,
        )
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

    /// Registers a secret that only the named files receive, so one agent's
    /// credential stays out of another's configuration.
    /// See [`LinuxEnv::set_scoped_secret`].
    pub fn set_scoped_secret(&mut self, name: &str, value: &str, paths: &[&[u8]]) {
        self.env().set_scoped_secret(name, value, paths);
    }

    /// Expands `${name}` secret placeholders in guest files. Call after
    /// seeding files and before `load`.
    pub fn expand_secrets(&mut self) -> Result<(), String> {
        self.env().expand_secrets()
    }

    /// Serializes the guest filesystem (for reload persistence). Secret
    /// values are redacted back to their `${name}` placeholders first, so
    /// snapshots never carry injected credentials. Take snapshots between
    /// guest processes, not while one is running.
    pub fn export_fs(&mut self) -> Vec<u8> {
        self.export_fs_excluding(&[])
    }

    /// Serializes the guest filesystem, writing the named files as empty.
    ///
    /// A host that supplies large images — a browser streaming an agent
    /// binary into the guest and caching it separately — would otherwise
    /// carry them in every snapshot as well, paying tens of megabytes twice.
    /// The caller names those paths here, and is responsible for putting them
    /// back after an import; a snapshot restored without that step has the
    /// files present but empty.
    ///
    /// Contents are moved out and moved back, so this costs no extra memory.
    pub fn export_fs_excluding(&mut self, paths: &[Vec<u8>]) -> Vec<u8> {
        let redactions = self.env().secret_redactions();
        if !redactions.is_empty() {
            self.env().vfs.rewrite_resident_files(&redactions);
        }
        let mut held: Vec<(&Vec<u8>, Vec<u8>)> = Vec::new();
        for path in paths {
            if let Some(data) = self.env().vfs.take_file_contents(path) {
                held.push((path, data));
            }
        }
        let image = self.env().vfs.serialize();
        for (path, data) in held {
            self.env().vfs.put_file_contents(path, data);
        }
        // Restore the in-memory values so the running machine keeps working.
        self.env().restore_resident_secrets();
        image
    }

    /// Replaces the guest filesystem with a serialized snapshot.
    ///
    /// The storage budget survives: it is a property of the machine the host
    /// configured, not of the tree that happens to be mounted in it.
    pub fn import_fs(&mut self, bytes: &[u8]) -> Result<(), String> {
        let mut restored = vfs::Vfs::deserialize(bytes)?;
        restored.set_storage_budget(self.env().vfs.storage_budget());
        self.env().vfs = restored;
        Ok(())
    }

    /// Loads a Linux ELF from the guest filesystem as a fresh root process.
    pub fn load(&mut self, path: &[u8]) -> Result<(), String> {
        // The check gates execution, not delivery. A host that forgets to
        // announce that a stream finished cannot skip it that way, and the
        // moment that matters is the one before the guest runs the bytes.
        self.env().verify_image(path)?;
        self.vm.cancel_page_in_resume();
        let InterpVm { cpu, env, .. } = &mut self.vm;
        env.load(cpu, path)
    }

    /// Runs until the workload exits or faults.
    pub fn run(&mut self) -> CpuExit {
        // Before anything executes. A ceiling noticed after the fact is not a
        // ceiling, and the host's own loop is what would otherwise keep
        // handing a spinning guest another turn.
        if self.cpu_headroom() == Some(0) {
            return CpuExit::OutOfCpu;
        }
        // The run may not exceed what is left, so a budget spent mid-run ends
        // the turn at the boundary rather than a whole fuel quantum past it.
        if let Some(headroom) = self.cpu_headroom() {
            let ceiling = self.icount().saturating_add(headroom);
            self.vm.icount_limit = self.vm.icount_limit.min(ceiling);
        }
        // A previous run paused waiting on the host — for a keystroke or for
        // network activity. Put a task back on the CPU now that the host has
        // had its turn; with still nothing to deliver, stay paused rather
        // than spinning.
        if self.env().page_in_wait {
            // No host completion yet: preserve the exact CPU fault and do not
            // spin or let wall-clock arrival reorder guest tasks.
            if self.env().pager.pending().is_some() || self.env().file_chunk_wait.is_some() {
                return CpuExit::Interrupted;
            }
            self.env().page_in_wait = false;
        }
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
        let exit = loop {
            let exit = self.vm.run();
            let recompile = {
                let env = self.env();
                std::mem::take(&mut env.page_in_recompile)
            };
            if exit == VmExit::Interrupted && recompile {
                // `lift_block` can retain a Target::Invalid after it decoded
                // into a cold executable page. Filling that page makes the
                // bytes valid but does not repair the already-built target;
                // drop all derived code and lift again from authority.
                self.vm.cpu.mem.clear_code_cache();
                self.vm.flush_code();
                self.vm.cpu.block_id = u64::MAX;
                self.vm.cpu.block_offset = 0;
                continue;
            }
            break exit;
        };
        if exit == VmExit::Interrupted && self.env().page_in_wait {
            self.vm.suspend_for_page_in();
        }
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
        // A bundle is a diagnostic that leaves the machine — a host may hand
        // it to someone, or upload it — so what it carries is a disclosure
        // decision, not a debugging convenience.
        //
        // Most of it is the machine's own account of itself. One field is
        // not: the executable path is whatever the guest asked to run, and a
        // guest can put anything in a path. This used to be a
        // `debug_assert!`, which is to say a check that does not run in the
        // builds that ship. Redact for real instead, in every build.
        let names: Vec<(String, String)> = self
            .env()
            .secrets
            .iter()
            .filter(|(_, secret)| !secret.value.is_empty())
            .map(|(name, secret)| (secret.value.clone(), format!("${{{name}}}")))
            .collect();
        for (value, placeholder) in names {
            bundle = bundle.replace(&value, &placeholder);
        }
        Some(bundle)
    }

    pub fn vm_mut(&mut self) -> &mut InterpVm {
        &mut self.vm
    }

    /// Issue one syscall with raw arguments, the way the guest's `SYSCALL`
    /// instruction does: the arguments go into the registers the ABI names
    /// and the same entry point reads them back out.
    ///
    /// This exists for the argument sweep in `tests/syscall_sweep.rs`. The
    /// guest is the untrusted party here, so every argument of every syscall
    /// is attacker-controlled, and the property worth proving — that no
    /// combination of them panics the host or reaches memory the guest does
    /// not own — needs to drive one call at a time and name the one that
    /// broke. Returns the value left in `rax`, which is a negated errno for
    /// a refusal, and whether the call ended the task.
    pub fn issue_syscall(&mut self, nr: u64, args: [u64; 6]) -> (i64, bool) {
        let InterpVm { cpu, env, .. } = &mut self.vm;
        let env = env
            .as_mut_any()
            .downcast_mut::<LinuxEnv>()
            .expect("machine environment is always LinuxEnv");
        let rax = env.regs.rax;
        // A real `SYSCALL` leaves the next-instruction register pointing just
        // past itself, and the restart path subtracts the instruction's length
        // from it. Presenting anything else manufactures failures no guest can
        // reach: at a next-pc of zero the subtraction underflows, which says
        // nothing about a kernel a guest can only enter by executing the
        // instruction.
        const SYSCALL_INSN_LEN: u64 = 2;
        let pc = cpu.read_pc();
        cpu.write_var(cpu.arch.reg_next_pc, pc.wrapping_add(SYSCALL_INSN_LEN));
        cpu.write_var(rax, nr);
        for (reg, value) in [
            (env.regs.rdi, args[0]),
            (env.regs.rsi, args[1]),
            (env.regs.rdx, args[2]),
            (env.regs.r10, args[3]),
            (env.regs.r8, args[4]),
            (env.regs.r9, args[5]),
        ] {
            cpu.write_var(reg, value);
        }
        let exit = syscall::handle(env, cpu);
        let ret: u64 = cpu.read_var(rax);
        (ret as i64, exit.is_some())
    }
}
