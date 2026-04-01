//! Per-agent Linux virtual OS state.
//!
//! Each agent running in Linux-compat mode gets its own virtual fd table,
//! cwd, brk pointer, mmap region, identity, etc.

use super::constants::{O_CLOEXEC, SOCKETPAIR_STREAM_MARKER};
use crate::{agent::MAX_AGENTS, serial_println};

pub const MAX_FDS: usize = 1024;
pub const MAX_EPOLL_INSTANCES: usize = 8;
pub const MAX_LINUX_AGENTS: usize = 128;
pub const MAX_PATH: usize = 512;
pub const MAX_DIRECTORY_HANDLES: usize = 64;
pub const MAX_VMAS: usize = 1024;
pub const MAX_EVENTFDS: usize = 256;
pub const MAX_PIPES: usize = 256;
pub const PIPE_BUFFER_SIZE: usize = 16 * 1024;
pub const DEFAULT_MMAP_BASE: u64 = 0x1_0000_0000;
const O_ACCMODE: u32 = 3;
const O_RDONLY: u32 = 0;
const O_WRONLY: u32 = 1;

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

// ── Eventfd objects ─────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct EventFdObject {
    pub active: bool,
    pub counter: u64,
    pub refs: u16,
    pub blocked_readers: [Option<u16>; MAX_AGENTS],
    pub blocked_writers: [Option<u16>; MAX_AGENTS],
}

impl EventFdObject {
    pub const fn empty() -> Self {
        EventFdObject {
            active: false,
            counter: 0,
            refs: 0,
            blocked_readers: [None; MAX_AGENTS],
            blocked_writers: [None; MAX_AGENTS],
        }
    }
}

// ── Pipe objects ────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct PipeObject {
    pub active: bool,
    pub buffer: [u8; PIPE_BUFFER_SIZE],
    pub read_pos: usize,
    pub count: usize,
    pub reader_refs: u16,
    pub writer_refs: u16,
    pub blocked_readers: [Option<u16>; MAX_AGENTS],
    pub blocked_writers: [Option<u16>; MAX_AGENTS],
}

impl PipeObject {
    pub const fn empty() -> Self {
        PipeObject {
            active: false,
            buffer: [0u8; PIPE_BUFFER_SIZE],
            read_pos: 0,
            count: 0,
            reader_refs: 0,
            writer_refs: 0,
            blocked_readers: [None; MAX_AGENTS],
            blocked_writers: [None; MAX_AGENTS],
        }
    }
}

// ── Linux user mappings ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum VmaKind {
    Empty = 0,
    Anonymous = 1,
    File = 2,
}

#[derive(Clone, Copy)]
pub struct VmaEntry {
    pub active: bool,
    pub start: u64,
    pub len: u64,
    pub prot: u32,
    pub flags: u32,
    pub kind: VmaKind,
    pub keyspace_id: u16,
    pub keyspace_key: u64,
    pub file_offset: u64,
}

impl VmaEntry {
    pub const fn empty() -> Self {
        VmaEntry {
            active: false,
            start: 0,
            len: 0,
            prot: 0,
            flags: 0,
            kind: VmaKind::Empty,
            keyspace_id: 0,
            keyspace_key: 0,
            file_offset: 0,
        }
    }

    #[inline]
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.len)
    }
}

// ── Epoll instance ──────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct EpollInstance {
    pub active: bool,
    pub watched_fds: [i32; 16],
    pub watched_events: [u32; 16],
    pub watched_data: [u64; 16],
    pub watch_count: u8,
}

impl EpollInstance {
    pub const fn empty() -> Self {
        EpollInstance {
            active: false,
            watched_fds: [0; 16],
            watched_events: [0; 16],
            watched_data: [0; 16],
            watch_count: 0,
        }
    }
}

// ── Per-agent state ─────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct LinuxAgentState {
    pub fd_table: [Option<FdEntry>; MAX_FDS],
    pub dir_handles: [DirectoryHandle; MAX_DIRECTORY_HANDLES],
    pub vmas: [VmaEntry; MAX_VMAS],
    pub cwd: [u8; MAX_PATH],
    pub cwd_len: u16,
    pub brk_current: u64,
    pub mmap_next: u64,      // next deterministic mmap address
    pub vm_space_owner: u16, // Linux agent that owns the shared VM metadata
    pub pid: u32,            // thread-group ID (tgid)
    pub thread_group_leader: u16,
    pub files_owner: u16,
    pub sighand_owner: u16,
    pub uid: u32,             // = 1000
    pub gid: u32,             // = 1000
    pub prng_state: [u8; 32], // SHA-256 PRNG seed
    pub prng_counter: u64,
    pub epoll_instances: [EpollInstance; MAX_EPOLL_INSTANCES],
    pub robust_list_head: u64,
    pub clear_child_tid: u64,
    pub fs_base: u64,           // TLS FS base (arch_prctl SET_FS)
    pub gs_base: u64,           // TLS GS base (arch_prctl SET_GS)
    pub sigaltstack_sp: u64,    // alternate signal stack base
    pub sigaltstack_size: u64,  // alternate signal stack size
    pub sigaltstack_flags: u32, // alternate signal stack attribute flags
    pub sigaltstack_pad: u32,
    pub thread_pending_signals: u64, // thread-directed pending signals
    pub group_pending_signals: u64,  // thread-group-directed pending signals
    pub exe_path: [u8; MAX_PATH],    // executable path (for /proc/self/exe, AT_EXECFN)
    pub exe_path_len: u16,
    pub vfork_parent: u16, // blocked parent waiting for vfork child exec/exit
    pub exit_status: i32,
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
            vmas: [const { VmaEntry::empty() }; MAX_VMAS],
            cwd,
            cwd_len: 1,
            brk_current: 0x0060_0000,     // conventional brk start
            mmap_next: DEFAULT_MMAP_BASE, // deterministic base (4 GB)
            vm_space_owner: agent_id,
            pid: agent_id as u32,
            thread_group_leader: agent_id,
            files_owner: agent_id,
            sighand_owner: agent_id,
            uid: 1000,
            gid: 1000,
            prng_state,
            prng_counter: 0,
            epoll_instances: [const { EpollInstance::empty() }; MAX_EPOLL_INSTANCES],
            robust_list_head: 0,
            clear_child_tid: 0,
            fs_base: 0,
            gs_base: 0,
            sigaltstack_sp: 0,
            sigaltstack_size: 0,
            sigaltstack_flags: 0,
            sigaltstack_pad: 0,
            thread_pending_signals: 0,
            group_pending_signals: 0,
            exe_path: [0u8; MAX_PATH],
            exe_path_len: 0,
            vfork_parent: 0,
            exit_status: 0,
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
            release_fd_resources(&entry);
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

    pub fn alloc_vma_slot(&mut self) -> Option<usize> {
        for i in 0..MAX_VMAS {
            if !self.vmas[i].active {
                return Some(i);
            }
        }
        None
    }

    pub fn find_vma_index(&self, addr: u64) -> Option<usize> {
        for i in 0..MAX_VMAS {
            let vma = &self.vmas[i];
            if vma.active && addr >= vma.start && addr < vma.end() {
                return Some(i);
            }
        }
        None
    }
}

fn retain_fd_mailboxes(entry: &FdEntry) {
    match entry.kind {
        FdKind::Pipe => {
            let handle = entry.keyspace_key as u16;
            let access = entry.flags & O_ACCMODE;
            if access != O_WRONLY {
                retain_pipe_reader(handle);
            }
            if access != O_RDONLY {
                retain_pipe_writer(handle);
            }
        }
        FdKind::Socket => {
            if entry.keyspace_key == SOCKETPAIR_STREAM_MARKER {
                retain_pipe_reader(entry.mailbox_id);
                retain_pipe_writer(entry.keyspace_id);
            } else {
                if entry.mailbox_id as usize >= crate::agent::MAX_AGENTS {
                    crate::mailbox::retain_reader_fd(entry.mailbox_id);
                }
                if entry.keyspace_id as usize >= crate::agent::MAX_AGENTS {
                    crate::mailbox::retain_writer_fd(entry.keyspace_id);
                }
            }
        }
        _ => {}
    }
}

fn release_fd_mailboxes(entry: &FdEntry) {
    match entry.kind {
        FdKind::Pipe => {
            let handle = entry.keyspace_key as u16;
            let access = entry.flags & O_ACCMODE;
            if access != O_WRONLY {
                release_pipe_reader(handle);
            }
            if access != O_RDONLY {
                release_pipe_writer(handle);
            }
        }
        FdKind::Socket => {
            if entry.keyspace_key == SOCKETPAIR_STREAM_MARKER {
                release_pipe_reader(entry.mailbox_id);
                release_pipe_writer(entry.keyspace_id);
            } else {
                if entry.mailbox_id as usize >= crate::agent::MAX_AGENTS {
                    crate::mailbox::release_reader_fd(entry.mailbox_id);
                }
                if entry.keyspace_id as usize >= crate::agent::MAX_AGENTS {
                    crate::mailbox::release_writer_fd(entry.keyspace_id);
                }
            }
        }
        _ => {}
    }
}

pub fn retain_fd_resources(entry: &FdEntry) {
    retain_fd_mailboxes(entry);
    if entry.kind == FdKind::EventFd {
        retain_eventfd(entry.keyspace_key as u16);
    }
}

pub fn release_fd_resources(entry: &FdEntry) {
    release_fd_mailboxes(entry);
    if entry.kind == FdKind::EventFd {
        release_eventfd(entry.keyspace_key as u16);
    }
}

pub fn retain_fd_table_resources(table: &[Option<FdEntry>; MAX_FDS]) {
    for entry in table.iter().flatten() {
        if entry.active {
            retain_fd_resources(entry);
        }
    }
}

pub fn has_other_active_files_users(files_owner: u16, excluding_agent: u16) -> bool {
    unsafe {
        for slot in LINUX_STATES.iter() {
            let Some(entry) = slot else {
                continue;
            };
            if entry.agent_id == excluding_agent {
                continue;
            }
            if entry.state.files_owner == files_owner && entry.state.active {
                return true;
            }
        }
    }
    false
}

// ── Global state table ──────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct LinuxStateSlot {
    agent_id: u16,
    state: LinuxAgentState,
}

// Safety: single-core, interrupts disabled during syscall handling.
static mut LINUX_STATES: [Option<LinuxStateSlot>; MAX_LINUX_AGENTS] =
    [const { None }; MAX_LINUX_AGENTS];
static mut EVENTFD_OBJECTS: [EventFdObject; MAX_EVENTFDS] =
    [const { EventFdObject::empty() }; MAX_EVENTFDS];
static mut PIPE_OBJECTS: [PipeObject; MAX_PIPES] = [const { PipeObject::empty() }; MAX_PIPES];

#[inline]
fn find_state_slot(agent_id: u16) -> Option<usize> {
    unsafe {
        for (idx, slot) in LINUX_STATES.iter().enumerate() {
            if let Some(entry) = slot {
                if entry.agent_id == agent_id {
                    return Some(idx);
                }
            }
        }
    }
    None
}

#[inline]
fn find_free_state_slot() -> Option<usize> {
    unsafe {
        for (idx, slot) in LINUX_STATES.iter().enumerate() {
            if slot.is_none() {
                return Some(idx);
            }
        }
    }
    None
}

/// Get an immutable reference to a Linux agent state.
pub fn get_state(agent_id: u16) -> Option<&'static LinuxAgentState> {
    let idx = find_state_slot(agent_id)?;
    unsafe { LINUX_STATES[idx].as_ref().map(|entry| &entry.state) }
}

/// Get a mutable reference to a Linux agent state.
pub fn get_state_mut(agent_id: u16) -> Option<&'static mut LinuxAgentState> {
    let idx = find_state_slot(agent_id)?;
    unsafe { LINUX_STATES[idx].as_mut().map(|entry| &mut entry.state) }
}

#[inline]
pub fn files_owner(agent_id: u16) -> u16 {
    get_state(agent_id)
        .map(|st| st.files_owner)
        .filter(|owner| get_state(*owner).is_some())
        .unwrap_or(agent_id)
}

pub fn get_files_state(agent_id: u16) -> Option<&'static LinuxAgentState> {
    let owner = files_owner(agent_id);
    get_state(owner)
}

pub fn get_files_state_mut(agent_id: u16) -> Option<&'static mut LinuxAgentState> {
    let owner = files_owner(agent_id);
    get_state_mut(owner)
}

#[inline]
pub fn sighand_owner(agent_id: u16) -> u16 {
    get_state(agent_id)
        .map(|st| st.sighand_owner)
        .filter(|owner| get_state(*owner).is_some())
        .unwrap_or(agent_id)
}

/// Initialize (or reinitialize) the Linux compat state for a given agent.
pub fn init_state(agent_id: u16) {
    if let Some(idx) = find_state_slot(agent_id).or_else(find_free_state_slot) {
        unsafe {
            LINUX_STATES[idx] = Some(LinuxStateSlot {
                agent_id,
                state: LinuxAgentState::new(agent_id),
            });
        }
        super::signal::init_signal_state(agent_id);
        serial_println!("[linux_compat] initialized state for agent {}", agent_id);
    } else {
        let mut used = 0usize;
        unsafe {
            for slot in LINUX_STATES.iter() {
                if slot.is_some() {
                    used += 1;
                }
            }
        }
        serial_println!(
            "[linux_compat] init_state failed: agent={} used_slots={}",
            agent_id,
            used
        );
    }
}

/// Remove the Linux compat state slot for a reaped agent.
pub fn remove_state(agent_id: u16) {
    if let Some(idx) = find_state_slot(agent_id) {
        unsafe {
            LINUX_STATES[idx] = None;
        }
    }
}

pub fn alloc_eventfd(initval: u64) -> Option<u16> {
    unsafe {
        for (idx, obj) in EVENTFD_OBJECTS.iter_mut().enumerate() {
            if !obj.active {
                *obj = EventFdObject::empty();
                obj.active = true;
                obj.counter = initval;
                return Some(idx as u16);
            }
        }
    }
    None
}

pub fn eventfd_counter(handle: u16) -> Option<u64> {
    unsafe {
        let obj = EVENTFD_OBJECTS.get(handle as usize)?;
        obj.active.then_some(obj.counter)
    }
}

pub fn eventfd_set_counter(handle: u16, value: u64) -> bool {
    unsafe {
        match EVENTFD_OBJECTS.get_mut(handle as usize) {
            Some(obj) if obj.active => {
                obj.counter = value;
                true
            }
            _ => false,
        }
    }
}

pub fn eventfd_read_ready(handle: u16) -> bool {
    eventfd_counter(handle)
        .map(|counter| counter > 0)
        .unwrap_or(false)
}

pub fn eventfd_write_ready(handle: u16) -> bool {
    eventfd_counter(handle)
        .map(|counter| counter < u64::MAX - 1)
        .unwrap_or(false)
}

fn retain_eventfd(handle: u16) {
    unsafe {
        let Some(obj) = EVENTFD_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if obj.active {
            obj.refs = obj.refs.saturating_add(1);
        }
    }
}

fn maybe_destroy_eventfd(handle: u16) {
    unsafe {
        let Some(obj) = EVENTFD_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if obj.active && obj.refs == 0 {
            *obj = EventFdObject::empty();
        }
    }
}

fn release_eventfd(handle: u16) {
    unsafe {
        let Some(obj) = EVENTFD_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !obj.active {
            return;
        }
        obj.refs = obj.refs.saturating_sub(1);
    }
    maybe_destroy_eventfd(handle);
}

pub fn alloc_pipe() -> Option<u16> {
    unsafe {
        for (idx, pipe) in PIPE_OBJECTS.iter_mut().enumerate() {
            if !pipe.active {
                *pipe = PipeObject::empty();
                pipe.active = true;
                return Some(idx as u16);
            }
        }
    }
    None
}

pub fn pipe_available(handle: u16) -> Option<usize> {
    unsafe {
        let pipe = PIPE_OBJECTS.get(handle as usize)?;
        pipe.active.then_some(pipe.count)
    }
}

pub fn pipe_has_writers(handle: u16) -> Option<bool> {
    unsafe {
        let pipe = PIPE_OBJECTS.get(handle as usize)?;
        pipe.active.then_some(pipe.writer_refs > 0)
    }
}

pub fn pipe_has_readers(handle: u16) -> Option<bool> {
    unsafe {
        let pipe = PIPE_OBJECTS.get(handle as usize)?;
        pipe.active.then_some(pipe.reader_refs > 0)
    }
}

pub fn pipe_ref_counts(handle: u16) -> Option<(u16, u16, usize)> {
    unsafe {
        let pipe = PIPE_OBJECTS.get(handle as usize)?;
        pipe.active
            .then_some((pipe.reader_refs, pipe.writer_refs, pipe.count))
    }
}

pub fn pipe_read_ready(handle: u16) -> bool {
    pipe_available(handle)
        .map(|count| count > 0)
        .unwrap_or(false)
        || !pipe_has_writers(handle).unwrap_or(false)
}

pub fn pipe_write_ready(handle: u16) -> bool {
    unsafe {
        match PIPE_OBJECTS.get(handle as usize) {
            Some(pipe) if pipe.active => pipe.reader_refs > 0 && pipe.count < PIPE_BUFFER_SIZE,
            _ => false,
        }
    }
}

pub fn pipe_read(handle: u16, dst: &mut [u8]) -> Option<usize> {
    let read = unsafe {
        let pipe = PIPE_OBJECTS.get_mut(handle as usize)?;
        if !pipe.active {
            return None;
        }
        let to_read = dst.len().min(pipe.count);
        for (idx, byte) in dst.iter_mut().take(to_read).enumerate() {
            let pos = (pipe.read_pos + idx) % PIPE_BUFFER_SIZE;
            *byte = pipe.buffer[pos];
        }
        pipe.read_pos = (pipe.read_pos + to_read) % PIPE_BUFFER_SIZE;
        pipe.count -= to_read;
        Some(to_read)
    };
    if read.unwrap_or(0) > 0 {
        wake_pipe_writer(handle);
    }
    read
}

pub fn pipe_write(handle: u16, src: &[u8]) -> Option<usize> {
    let written = unsafe {
        let pipe = PIPE_OBJECTS.get_mut(handle as usize)?;
        if !pipe.active {
            return None;
        }
        let free = PIPE_BUFFER_SIZE.saturating_sub(pipe.count);
        let to_write = src.len().min(free);
        let write_pos = (pipe.read_pos + pipe.count) % PIPE_BUFFER_SIZE;
        for (idx, byte) in src.iter().copied().take(to_write).enumerate() {
            let pos = (write_pos + idx) % PIPE_BUFFER_SIZE;
            pipe.buffer[pos] = byte;
        }
        pipe.count += to_write;
        Some(to_write)
    };
    if written.unwrap_or(0) > 0 {
        wake_pipe_reader(handle);
    }
    written
}

fn retain_pipe_reader(handle: u16) {
    unsafe {
        let Some(pipe) = PIPE_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if pipe.active {
            pipe.reader_refs = pipe.reader_refs.saturating_add(1);
        }
    }
}

fn retain_pipe_writer(handle: u16) {
    unsafe {
        let Some(pipe) = PIPE_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if pipe.active {
            pipe.writer_refs = pipe.writer_refs.saturating_add(1);
        }
    }
}

fn maybe_destroy_pipe(handle: u16) {
    unsafe {
        let Some(pipe) = PIPE_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if pipe.active && pipe.reader_refs == 0 && pipe.writer_refs == 0 {
            *pipe = PipeObject::empty();
        }
    }
}

pub fn add_blocked_pipe_reader(handle: u16, agent_id: u16) {
    unsafe {
        let Some(pipe) = PIPE_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !pipe.active {
            return;
        }
        for slot in pipe.blocked_readers.iter_mut() {
            if *slot == Some(agent_id) {
                return;
            }
            if slot.is_none() {
                *slot = Some(agent_id);
                return;
            }
        }
    }
}

pub fn add_blocked_eventfd_reader(handle: u16, agent_id: u16) {
    unsafe {
        let Some(obj) = EVENTFD_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !obj.active {
            return;
        }
        for slot in obj.blocked_readers.iter_mut() {
            if *slot == Some(agent_id) {
                return;
            }
            if slot.is_none() {
                *slot = Some(agent_id);
                return;
            }
        }
    }
}

pub fn remove_blocked_eventfd_reader(handle: u16, agent_id: u16) {
    unsafe {
        let Some(obj) = EVENTFD_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !obj.active {
            return;
        }
        for slot in obj.blocked_readers.iter_mut() {
            if *slot == Some(agent_id) {
                *slot = None;
                return;
            }
        }
    }
}

pub fn remove_blocked_pipe_reader(handle: u16, agent_id: u16) {
    unsafe {
        let Some(pipe) = PIPE_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !pipe.active {
            return;
        }
        for slot in pipe.blocked_readers.iter_mut() {
            if *slot == Some(agent_id) {
                *slot = None;
                return;
            }
        }
    }
}

pub fn add_blocked_pipe_writer(handle: u16, agent_id: u16) {
    unsafe {
        let Some(pipe) = PIPE_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !pipe.active {
            return;
        }
        for slot in pipe.blocked_writers.iter_mut() {
            if *slot == Some(agent_id) {
                return;
            }
            if slot.is_none() {
                *slot = Some(agent_id);
                return;
            }
        }
    }
}

pub fn add_blocked_eventfd_writer(handle: u16, agent_id: u16) {
    unsafe {
        let Some(obj) = EVENTFD_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !obj.active {
            return;
        }
        for slot in obj.blocked_writers.iter_mut() {
            if *slot == Some(agent_id) {
                return;
            }
            if slot.is_none() {
                *slot = Some(agent_id);
                return;
            }
        }
    }
}

pub fn remove_blocked_eventfd_writer(handle: u16, agent_id: u16) {
    unsafe {
        let Some(obj) = EVENTFD_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !obj.active {
            return;
        }
        for slot in obj.blocked_writers.iter_mut() {
            if *slot == Some(agent_id) {
                *slot = None;
                return;
            }
        }
    }
}

pub fn remove_blocked_pipe_writer(handle: u16, agent_id: u16) {
    unsafe {
        let Some(pipe) = PIPE_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !pipe.active {
            return;
        }
        for slot in pipe.blocked_writers.iter_mut() {
            if *slot == Some(agent_id) {
                *slot = None;
                return;
            }
        }
    }
}

fn try_unblock_pipe_reader(handle: u16) -> Option<u16> {
    unsafe {
        let pipe = PIPE_OBJECTS.get_mut(handle as usize)?;
        if !pipe.active {
            return None;
        }
        let mut best_idx = None;
        let mut best_id = 0u16;
        for (idx, slot) in pipe.blocked_readers.iter_mut().enumerate() {
            let Some(agent_id) = *slot else {
                continue;
            };
            let still_blocked = crate::agent::get_agent(agent_id)
                .map(|agent| agent.status == crate::agent::AgentStatus::BlockedRecv)
                .unwrap_or(false);
            if !still_blocked {
                *slot = None;
                continue;
            }
            if best_idx.is_none() || agent_id < best_id {
                best_idx = Some(idx);
                best_id = agent_id;
            }
        }
        if let Some(idx) = best_idx {
            pipe.blocked_readers[idx] = None;
            Some(best_id)
        } else {
            None
        }
    }
}

fn try_unblock_eventfd_reader(handle: u16) -> Option<u16> {
    unsafe {
        let obj = EVENTFD_OBJECTS.get_mut(handle as usize)?;
        if !obj.active {
            return None;
        }
        let mut best_idx = None;
        let mut best_id = 0u16;
        for (idx, slot) in obj.blocked_readers.iter_mut().enumerate() {
            let Some(agent_id) = *slot else {
                continue;
            };
            let still_blocked = crate::agent::get_agent(agent_id)
                .map(|agent| agent.status == crate::agent::AgentStatus::BlockedRecv)
                .unwrap_or(false);
            if !still_blocked {
                *slot = None;
                continue;
            }
            if best_idx.is_none() || agent_id < best_id {
                best_idx = Some(idx);
                best_id = agent_id;
            }
        }
        if let Some(idx) = best_idx {
            obj.blocked_readers[idx] = None;
            Some(best_id)
        } else {
            None
        }
    }
}

fn try_unblock_pipe_writer(handle: u16) -> Option<u16> {
    unsafe {
        let pipe = PIPE_OBJECTS.get_mut(handle as usize)?;
        if !pipe.active {
            return None;
        }
        let mut best_idx = None;
        let mut best_id = 0u16;
        for (idx, slot) in pipe.blocked_writers.iter_mut().enumerate() {
            let Some(agent_id) = *slot else {
                continue;
            };
            let still_blocked = crate::agent::get_agent(agent_id)
                .map(|agent| agent.status == crate::agent::AgentStatus::BlockedSend)
                .unwrap_or(false);
            if !still_blocked {
                *slot = None;
                continue;
            }
            if best_idx.is_none() || agent_id < best_id {
                best_idx = Some(idx);
                best_id = agent_id;
            }
        }
        if let Some(idx) = best_idx {
            pipe.blocked_writers[idx] = None;
            Some(best_id)
        } else {
            None
        }
    }
}

fn try_unblock_eventfd_writer(handle: u16) -> Option<u16> {
    unsafe {
        let obj = EVENTFD_OBJECTS.get_mut(handle as usize)?;
        if !obj.active {
            return None;
        }
        let mut best_idx = None;
        let mut best_id = 0u16;
        for (idx, slot) in obj.blocked_writers.iter_mut().enumerate() {
            let Some(agent_id) = *slot else {
                continue;
            };
            let still_blocked = crate::agent::get_agent(agent_id)
                .map(|agent| agent.status == crate::agent::AgentStatus::BlockedSend)
                .unwrap_or(false);
            if !still_blocked {
                *slot = None;
                continue;
            }
            if best_idx.is_none() || agent_id < best_id {
                best_idx = Some(idx);
                best_id = agent_id;
            }
        }
        if let Some(idx) = best_idx {
            obj.blocked_writers[idx] = None;
            Some(best_id)
        } else {
            None
        }
    }
}

fn wake_pipe_reader(handle: u16) {
    if let Some(agent_id) = try_unblock_pipe_reader(handle) {
        crate::sched::unblock(agent_id);
    }
}

fn wake_pipe_writer(handle: u16) {
    if let Some(agent_id) = try_unblock_pipe_writer(handle) {
        crate::sched::unblock(agent_id);
    }
}

pub fn wake_eventfd_readers(handle: u16) {
    while let Some(agent_id) = try_unblock_eventfd_reader(handle) {
        crate::sched::unblock(agent_id);
    }
}

pub fn wake_eventfd_writers(handle: u16) {
    while let Some(agent_id) = try_unblock_eventfd_writer(handle) {
        crate::sched::unblock(agent_id);
    }
}

fn unblock_all_pipe_readers(handle: u16) {
    while let Some(agent_id) = try_unblock_pipe_reader(handle) {
        crate::sched::unblock(agent_id);
    }
}

fn release_pipe_reader(handle: u16) {
    unsafe {
        let Some(pipe) = PIPE_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !pipe.active {
            return;
        }
        pipe.reader_refs = pipe.reader_refs.saturating_sub(1);
    }
    wake_pipe_writer(handle);
    maybe_destroy_pipe(handle);
}

fn release_pipe_writer(handle: u16) {
    let last_writer = unsafe {
        let Some(pipe) = PIPE_OBJECTS.get_mut(handle as usize) else {
            return;
        };
        if !pipe.active {
            return;
        }
        pipe.writer_refs = pipe.writer_refs.saturating_sub(1);
        pipe.writer_refs == 0
    };
    if last_writer {
        unblock_all_pipe_readers(handle);
    } else {
        wake_pipe_reader(handle);
    }
    maybe_destroy_pipe(handle);
}

/// Set the executable path for a Linux-compat agent.
pub fn set_exe_path(agent_id: u16, path: &[u8]) {
    if let Some(s) = get_state_mut(agent_id) {
        let len = path.len().min(MAX_PATH);
        s.exe_path[..len].copy_from_slice(&path[..len]);
        s.exe_path_len = len as u16;
    }
}

/// Reset Linux process-image state after a successful execve.
///
/// This preserves process identity and inherited file descriptors while
/// rebuilding the user VM image on the same agent slot.
pub fn reset_for_exec(agent_id: u16, path: &[u8], initial_brk: u64) {
    let files_owner = files_owner(agent_id);
    let shared_files = get_state(files_owner)
        .map(|owner| (owner.fd_table, owner.dir_handles, owner.epoll_instances));

    let Some(st) = get_state_mut(agent_id) else {
        return;
    };

    if let Some((fd_table, dir_handles, epoll_instances)) = shared_files {
        st.fd_table = fd_table;
        st.dir_handles = dir_handles;
        st.epoll_instances = epoll_instances;
    }

    for fd in 0..MAX_FDS {
        let should_close = matches!(st.fd_table[fd], Some(entry) if entry.active && (entry.flags & O_CLOEXEC) != 0);
        if should_close {
            let _ = st.close_fd(fd as i32);
        }
    }

    st.vmas = [const { VmaEntry::empty() }; MAX_VMAS];
    st.brk_current = initial_brk;
    st.mmap_next = DEFAULT_MMAP_BASE;
    st.vm_space_owner = agent_id;
    st.files_owner = agent_id;
    st.sighand_owner = agent_id;
    st.robust_list_head = 0;
    st.clear_child_tid = 0;
    st.fs_base = 0;
    st.gs_base = 0;
    st.sigaltstack_sp = 0;
    st.sigaltstack_size = 0;
    st.sigaltstack_flags = 0;
    st.sigaltstack_pad = 0;
    st.thread_pending_signals = 0;
    st.group_pending_signals = 0;
    st.vfork_parent = 0;
    st.active = true;

    let len = path.len().min(MAX_PATH);
    st.exe_path.fill(0);
    st.exe_path[..len].copy_from_slice(&path[..len]);
    st.exe_path_len = len as u16;
    st.exit_status = 0;
}

/// Return true if the agent executable path matches `path`.
pub fn exe_path_eq(agent_id: u16, path: &[u8]) -> bool {
    match get_state(agent_id) {
        Some(s) => {
            let len = s.exe_path_len as usize;
            len == path.len() && s.exe_path[..len] == path[..]
        }
        None => false,
    }
}

/// Return true if detailed Linux runtime tracing should be enabled for this agent.
pub fn trace_runtime_agent(agent_id: u16) -> bool {
    exe_path_eq(agent_id, b"/app/hello_dynamic")
        || exe_path_eq(agent_id, b"/usr/bin/hello_dynamic")
        || exe_path_eq(agent_id, b"/usr/bin/node")
        || get_state(agent_id)
            .map(|st| {
                st.vfork_parent != 0
                    && (exe_path_eq(agent_id, b"/usr/bin/java")
                        || exe_path_eq(agent_id, b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java")
                        || exe_path_eq(agent_id, b"/usr/bin/node"))
            })
            .unwrap_or(false)
}

pub fn trace_java_agent(agent_id: u16) -> bool {
    exe_path_eq(agent_id, b"/usr/bin/java")
        || exe_path_eq(agent_id, b"/usr/lib/jvm/java-11-openjdk-amd64/bin/java")
}
