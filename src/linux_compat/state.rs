//! Per-agent Linux virtual OS state.
//!
//! Each agent running in Linux-compat mode gets its own virtual fd table,
//! cwd, brk pointer, mmap region, identity, etc.

use crate::{agent::MAX_AGENTS, serial_println};

pub const MAX_FDS: usize = 1024;
pub const MAX_EPOLL_INSTANCES: usize = 8;
pub const MAX_LINUX_AGENTS: usize = MAX_AGENTS;
pub const MAX_PATH: usize = 512;
pub const MAX_DIRECTORY_HANDLES: usize = 64;

// ── FD types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FdKind {
    File = 0,      // keyspace-backed file
    Socket = 1,    // netd proxy session
    Pipe = 2,      // mailbox pair
    Epoll = 3,     // epoll instance reference
    EventFd = 4,   // eventfd counter
    Directory = 5, // virtual directory handle
}

#[derive(Clone, Copy)]
pub struct FdEntry {
    pub kind: FdKind,
    pub keyspace_key: u64, // for File: keyspace key
    pub keyspace_id: u16,  // which keyspace to read/write from
    pub mailbox_id: u16,   // for Socket/Pipe: mailbox
    pub offset: u64,       // current read/write offset
    pub flags: u32,        // O_NONBLOCK, O_CLOEXEC, etc.
    pub active: bool,
}

impl FdEntry {
    pub const fn empty() -> Self {
        FdEntry {
            kind: FdKind::File,
            keyspace_key: 0,
            keyspace_id: 0,
            mailbox_id: 0,
            offset: 0,
            flags: 0,
            active: false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct DirectoryHandle {
    pub active: bool,
    pub path: [u8; MAX_PATH],
    pub path_len: u16,
}

impl DirectoryHandle {
    pub const fn empty() -> Self {
        DirectoryHandle {
            active: false,
            path: [0u8; MAX_PATH],
            path_len: 0,
        }
    }
}

// ── Epoll instance ──────────────────────────────────────────────────────────

pub struct EpollInstance {
    pub active: bool,
    pub watched_fds: [i32; 16],
    pub watch_count: u8,
}

impl EpollInstance {
    pub const fn empty() -> Self {
        EpollInstance {
            active: false,
            watched_fds: [0; 16],
            watch_count: 0,
        }
    }
}

// ── Per-agent state ─────────────────────────────────────────────────────────

pub struct LinuxAgentState {
    pub fd_table: [Option<FdEntry>; MAX_FDS],
    pub dir_handles: [DirectoryHandle; MAX_DIRECTORY_HANDLES],
    pub cwd: [u8; MAX_PATH],
    pub cwd_len: u16,
    pub brk_current: u64,
    pub mmap_next: u64,       // next deterministic mmap address
    pub pid: u32,             // = agent_id
    pub uid: u32,             // = 1000
    pub gid: u32,             // = 1000
    pub prng_state: [u8; 32], // SHA-256 PRNG seed
    pub prng_counter: u64,
    pub epoll_instances: [EpollInstance; MAX_EPOLL_INSTANCES],
    pub robust_list_head: u64,
    pub clear_child_tid: u64,
    pub fs_base: u64,          // TLS FS base (arch_prctl SET_FS)
    pub pending_signals: u64,  // bitmask of pending signals (bit N = signal N+1)
    pub exe_path: [u8; MAX_PATH], // executable path (for /proc/self/exe, AT_EXECFN)
    pub exe_path_len: u16,
    pub active: bool,
}

impl LinuxAgentState {
    /// Create a new Linux agent state for the given agent ID.
    pub fn new(agent_id: u16) -> Self {
        let mut cwd = [0u8; MAX_PATH];
        // Default cwd = "/"
        cwd[0] = b'/';

        // Seed PRNG deterministically from agent_id
        let mut prng_state = [0u8; 32];
        let id_bytes = agent_id.to_le_bytes();
        prng_state[0] = id_bytes[0];
        prng_state[1] = id_bytes[1];
        // Mix in a constant to differentiate from zero
        prng_state[2] = 0xA7;
        prng_state[3] = 0x05;

        let mut fd_table: [Option<FdEntry>; MAX_FDS] = [const { None }; MAX_FDS];

        // Pre-open fd 0 (stdin), 1 (stdout), 2 (stderr) — like Linux init.
        // stdout/stderr map to serial console via sys_write special-case.
        // stdin reads return 0 (EOF).
        for fd in 0..3u16 {
            fd_table[fd as usize] = Some(FdEntry {
                kind: FdKind::File,
                keyspace_key: 0,
                keyspace_id: agent_id,
                mailbox_id: 0,
                offset: 0,
                flags: if fd == 0 { 0 } else { 1 }, // O_WRONLY for stdout/stderr
                active: true,
            });
        }

        LinuxAgentState {
            fd_table,
            dir_handles: [const { DirectoryHandle::empty() }; MAX_DIRECTORY_HANDLES],
            cwd,
            cwd_len: 1,
            brk_current: 0x0060_0000, // conventional brk start
            mmap_next: 0x1_0000_0000, // deterministic base (4 GB)
            pid: agent_id as u32,
            uid: 1000,
            gid: 1000,
            prng_state,
            prng_counter: 0,
            epoll_instances: [const { EpollInstance::empty() }; MAX_EPOLL_INSTANCES],
            robust_list_head: 0,
            clear_child_tid: 0,
            fs_base: 0,
            pending_signals: 0,
            exe_path: [0u8; MAX_PATH],
            exe_path_len: 0,
            active: true,
        }
    }

    /// Allocate the lowest available file descriptor.
    pub fn alloc_fd(&mut self) -> Option<usize> {
        for i in 0..MAX_FDS {
            if self.fd_table[i].is_none() {
                return Some(i);
            }
        }
        None
    }

    /// Get an immutable reference to an fd entry.
    pub fn get_fd(&self, fd: i32) -> Option<&FdEntry> {
        if fd < 0 || fd as usize >= MAX_FDS {
            return None;
        }
        self.fd_table[fd as usize].as_ref()
    }

    /// Get a mutable reference to an fd entry.
    pub fn get_fd_mut(&mut self, fd: i32) -> Option<&mut FdEntry> {
        if fd < 0 || fd as usize >= MAX_FDS {
            return None;
        }
        self.fd_table[fd as usize].as_mut()
    }

    /// Close a file descriptor. Returns true if it was open.
    pub fn close_fd(&mut self, fd: i32) -> bool {
        if fd < 0 || fd as usize >= MAX_FDS {
            return false;
        }
        if let Some(entry) = self.fd_table[fd as usize] {
            if entry.kind == FdKind::Directory {
                self.free_directory_handle(entry.keyspace_key as u16);
            }
            self.fd_table[fd as usize] = None;
            true
        } else {
            false
        }
    }

    /// Allocate a lightweight directory handle that stores the opened path.
    pub fn alloc_directory_handle(&mut self, path: &[u8]) -> Option<u16> {
        let copy_len = path.len().min(MAX_PATH);
        for i in 0..MAX_DIRECTORY_HANDLES {
            if !self.dir_handles[i].active {
                self.dir_handles[i] = DirectoryHandle::empty();
                self.dir_handles[i].active = true;
                self.dir_handles[i].path[..copy_len].copy_from_slice(&path[..copy_len]);
                self.dir_handles[i].path_len = copy_len as u16;
                return Some(i as u16);
            }
        }
        None
    }

    /// Duplicate an existing directory handle by copying its stored path.
    pub fn clone_directory_handle(&mut self, handle_id: u16) -> Option<u16> {
        if handle_id as usize >= MAX_DIRECTORY_HANDLES {
            return None;
        }
        let handle = self.dir_handles[handle_id as usize];
        if !handle.active {
            return None;
        }
        self.alloc_directory_handle(&handle.path[..handle.path_len as usize])
    }

    /// Get an immutable directory handle reference.
    pub fn get_directory_handle(&self, handle_id: u16) -> Option<&DirectoryHandle> {
        if handle_id as usize >= MAX_DIRECTORY_HANDLES {
            return None;
        }
        let handle = &self.dir_handles[handle_id as usize];
        if handle.active {
            Some(handle)
        } else {
            None
        }
    }

    fn free_directory_handle(&mut self, handle_id: u16) {
        if handle_id as usize >= MAX_DIRECTORY_HANDLES {
            return;
        }
        self.dir_handles[handle_id as usize] = DirectoryHandle::empty();
    }
}

// ── Global state table ──────────────────────────────────────────────────────

// Safety: single-core, interrupts disabled during syscall handling.
static mut LINUX_STATES: [Option<LinuxAgentState>; MAX_LINUX_AGENTS] =
    [const { None }; MAX_LINUX_AGENTS];

/// Get an immutable reference to a Linux agent state.
pub fn get_state(agent_id: u16) -> Option<&'static LinuxAgentState> {
    if agent_id as usize >= MAX_LINUX_AGENTS {
        return None;
    }
    // Safety: single-core kernel, no concurrent access.
    unsafe { LINUX_STATES[agent_id as usize].as_ref() }
}

/// Get a mutable reference to a Linux agent state.
pub fn get_state_mut(agent_id: u16) -> Option<&'static mut LinuxAgentState> {
    if agent_id as usize >= MAX_LINUX_AGENTS {
        return None;
    }
    // Safety: single-core kernel, no concurrent access.
    unsafe { LINUX_STATES[agent_id as usize].as_mut() }
}

/// Initialize (or reinitialize) the Linux compat state for a given agent.
pub fn init_state(agent_id: u16) {
    if (agent_id as usize) < MAX_LINUX_AGENTS {
        // Safety: single-core kernel, no concurrent access.
        unsafe {
            LINUX_STATES[agent_id as usize] = Some(LinuxAgentState::new(agent_id));
        }
        serial_println!("[linux_compat] initialized state for agent {}", agent_id);
    }
}

/// Set the executable path for a Linux-compat agent.
pub fn set_exe_path(agent_id: u16, path: &[u8]) {
    if let Some(s) = get_state_mut(agent_id) {
        let len = path.len().min(MAX_PATH);
        s.exe_path[..len].copy_from_slice(&path[..len]);
        s.exe_path_len = len as u16;
    }
}

// ── Signal pending helpers ─────────────────────────────────────────────────

/// Raise a signal on an agent by setting the corresponding pending bit.
/// Signal numbers are 1-based (Linux convention); bit N corresponds to signal N+1.
pub fn raise_signal(agent_id: u16, signum: u32) {
    if signum < 1 || signum > 64 {
        return;
    }
    if let Some(s) = get_state_mut(agent_id) {
        s.pending_signals |= 1u64 << (signum - 1);
    }
}

/// Return the lowest pending (non-blocked) signal number, or None.
pub fn has_pending_signal(agent_id: u16) -> Option<u32> {
    if let Some(s) = get_state(agent_id) {
        if s.pending_signals == 0 {
            return None;
        }
        // Find lowest set bit
        let lowest_bit = s.pending_signals.trailing_zeros();
        if lowest_bit < 64 {
            return Some(lowest_bit + 1); // signal numbers are 1-based
        }
    }
    None
}

/// Clear a pending signal bit.
pub fn clear_signal(agent_id: u16, signum: u32) {
    if signum < 1 || signum > 64 {
        return;
    }
    if let Some(s) = get_state_mut(agent_id) {
        s.pending_signals &= !(1u64 << (signum - 1));
    }
}
