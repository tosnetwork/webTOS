//! Deterministic epoll implementation.
//!
//! Epoll instances track a set of watched fds. On epoll_pwait, we iterate
//! watched fds in ascending order and check readiness deterministically.

use super::constants::*;
use super::state::{self, FdEntry, FdKind, MAX_EPOLL_INSTANCES};

const O_ACCMODE: u32 = 3;

fn agent_cr3(agent_id: u16) -> Option<u64> {
    crate::agent::get_agent(agent_id)
        .map(|agent| agent.context.cr3)
        .filter(|cr3| *cr3 != 0)
}

fn ensure_user_range_mapped(agent_id: u16, user_addr: u64, len: usize, write: bool) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if len == 0 {
        return true;
    }

    let start = user_addr & !(crate::arch::x86_64::paging::PAGE_SIZE as u64 - 1);
    let end_addr = user_addr.saturating_add(len.saturating_sub(1) as u64);
    let end = end_addr & !(crate::arch::x86_64::paging::PAGE_SIZE as u64 - 1);
    let mut page = start;
    let fault_code = if write { 0x2 } else { 0x0 };

    loop {
        if crate::arch::x86_64::page_table::translate_user_vaddr(cr3, page).is_none()
            && !crate::linux_compat::memory::handle_user_page_fault(agent_id, page, fault_code)
        {
            return false;
        }
        if page == end {
            break;
        }
        page = page.saturating_add(crate::arch::x86_64::paging::PAGE_SIZE as u64);
    }

    true
}

fn copy_to_user(agent_id: u16, user_addr: u64, src: &[u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if !ensure_user_range_mapped(agent_id, user_addr, src.len(), true) {
        return false;
    }
    crate::arch::x86_64::page_table::copy_to_user(cr3, user_addr, src)
}

fn copy_from_user(agent_id: u16, user_addr: u64, dst: &mut [u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if !ensure_user_range_mapped(agent_id, user_addr, dst.len(), false) {
        return false;
    }
    crate::arch::x86_64::page_table::copy_from_user(cr3, user_addr, dst)
}

fn fd_access_mode(flags: u32) -> u32 {
    flags & O_ACCMODE
}

fn fd_allows_read(kind: FdKind, flags: u32) -> bool {
    match kind {
        FdKind::Directory => true,
        FdKind::File | FdKind::Pipe => fd_access_mode(flags) != O_WRONLY,
        FdKind::Socket | FdKind::EventFd => true,
        FdKind::Epoll => false,
    }
}

fn fd_allows_write(kind: FdKind, flags: u32) -> bool {
    match kind {
        FdKind::Directory => false,
        FdKind::File | FdKind::Pipe => fd_access_mode(flags) != O_RDONLY,
        FdKind::Socket | FdKind::EventFd => true,
        FdKind::Epoll => false,
    }
}

// ── epoll_create ───────────────────────────────────────────────────────────

/// epoll_create(int size) -- size is ignored (legacy), must be > 0.
pub fn sys_epoll_create(agent_id: u16, size: i32) -> i64 {
    if size <= 0 {
        return -EINVAL;
    }
    sys_epoll_create1(agent_id, 0)
}

/// epoll_create1(int flags)
///
/// Allocates an epoll instance in LinuxAgentState and returns an fd
/// of kind FdKind::Epoll whose keyspace_key indexes the epoll instance.
pub fn sys_epoll_create1(agent_id: u16, flags: i32) -> i64 {
    let st = match state::get_files_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    // Find a free epoll instance slot
    let epoll_idx = {
        let mut found = None;
        for i in 0..MAX_EPOLL_INSTANCES {
            if !st.epoll_instances[i].active {
                found = Some(i);
                break;
            }
        }
        match found {
            Some(i) => i,
            None => return -EMFILE,
        }
    };

    // Initialize the epoll instance
    st.epoll_instances[epoll_idx].active = true;
    st.epoll_instances[epoll_idx].watch_count = 0;
    for j in 0..16 {
        st.epoll_instances[epoll_idx].watched_fds[j] = -1;
    }

    // Allocate an fd for this epoll instance
    let fd = match st.alloc_fd() {
        Some(f) => f,
        None => {
            st.epoll_instances[epoll_idx].active = false;
            return -EMFILE;
        }
    };

    st.fd_table[fd] = Some(FdEntry {
        kind: FdKind::Epoll,
        keyspace_key: epoll_idx as u64, // index into epoll_instances
        keyspace_id: 0,
        mailbox_id: 0,
        offset: 0,
        flags: flags as u32,
        active: true,
    });

    if state::trace_runtime_agent(agent_id) {
        crate::serial_println!(
            "[RTDBG] epoll_create1 agent={} fd={} epidx={} flags={:#x}",
            agent_id,
            fd,
            epoll_idx,
            flags
        );
    }

    fd as i64
}

// ── epoll_ctl ──────────────────────────────────────────────────────────────

/// epoll_ctl operation constants.
const EPOLL_CTL_ADD: i32 = 1;
const EPOLL_CTL_DEL: i32 = 2;
const EPOLL_CTL_MOD: i32 = 3;

/// epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
///
/// Add, modify, or remove a file descriptor from an epoll instance.
pub fn sys_epoll_ctl(agent_id: u16, epfd: i32, op: i32, fd: i32, _event_ptr: u64) -> i64 {
    let st = match state::get_files_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    // Validate the epoll fd
    let epoll_idx = match st.get_fd(epfd) {
        Some(entry) if entry.kind == FdKind::Epoll => entry.keyspace_key as usize,
        Some(_) => return -EINVAL,
        None => return -EBADF,
    };

    if epoll_idx >= MAX_EPOLL_INSTANCES {
        return -EINVAL;
    }

    let mut requested_events = 0u32;
    let mut requested_data = fd as u64;
    if op != EPOLL_CTL_DEL {
        if _event_ptr == 0 {
            return -EFAULT;
        }
        let mut raw = [0u8; EPOLL_EVENT_SIZE];
        if !copy_from_user(agent_id, _event_ptr, &mut raw) {
            return -EFAULT;
        }
        requested_events = u32::from_ne_bytes(raw[0..4].try_into().unwrap());
        requested_data = u64::from_ne_bytes(raw[4..12].try_into().unwrap());
    }

    // Validate the target fd exists (except on DEL, be lenient)
    if op != EPOLL_CTL_DEL {
        if st.get_fd(fd).is_none() {
            return -EBADF;
        }
    }

    let inst = &mut st.epoll_instances[epoll_idx];

    let ret = match op {
        EPOLL_CTL_ADD => {
            // Check if already watched
            for i in 0..inst.watch_count as usize {
                if inst.watched_fds[i] == fd {
                    return -EEXIST;
                }
            }
            // Add to watch list
            if inst.watch_count as usize >= 16 {
                return -ENOSPC;
            }
            let idx = inst.watch_count as usize;
            inst.watched_fds[idx] = fd;
            inst.watched_events[idx] = requested_events;
            inst.watched_data[idx] = requested_data;
            inst.watch_count += 1;
            0
        }
        EPOLL_CTL_DEL => {
            // Find and remove
            let mut found = false;
            for i in 0..inst.watch_count as usize {
                if inst.watched_fds[i] == fd {
                    // Shift remaining entries down
                    let count = inst.watch_count as usize;
                    for j in i..count - 1 {
                        inst.watched_fds[j] = inst.watched_fds[j + 1];
                        inst.watched_events[j] = inst.watched_events[j + 1];
                        inst.watched_data[j] = inst.watched_data[j + 1];
                    }
                    inst.watched_fds[count - 1] = -1;
                    inst.watched_events[count - 1] = 0;
                    inst.watched_data[count - 1] = 0;
                    inst.watch_count -= 1;
                    found = true;
                    break;
                }
            }
            if found { 0 } else { -ENOENT }
        }
        EPOLL_CTL_MOD => {
            // Check that fd is in the watch list
            let mut found = false;
            for i in 0..inst.watch_count as usize {
                if inst.watched_fds[i] == fd {
                    inst.watched_events[i] = requested_events;
                    inst.watched_data[i] = requested_data;
                    found = true;
                    break;
                }
            }
            if found { 0 } else { -ENOENT }
        }
        _ => -EINVAL,
    };

    if state::trace_runtime_agent(agent_id) {
        crate::serial_println!(
            "[RTDBG] epoll_ctl agent={} epfd={} op={} fd={} events={:#x} data={:#x} ret={}",
            agent_id,
            epfd,
            op,
            fd,
            requested_events,
            requested_data,
            ret
        );
    }

    ret
}

// ── epoll_wait / epoll_pwait ───────────────────────────────────────────────

/// Linux epoll_event struct layout (12 bytes, packed):
///   offset 0: u32 events  (EPOLLIN, EPOLLOUT, etc.)
///   offset 4: u64 data    (user data, typically the fd)
const EPOLL_EVENT_SIZE: usize = 12;

/// EPOLLIN / EPOLLOUT event flags
const EPOLLIN: u32 = 0x001;
const EPOLLHUP: u32 = 0x010;
const EPOLLOUT: u32 = 0x004;

#[inline]
fn eventfd_handle(entry: &FdEntry) -> Option<u16> {
    (entry.kind == FdKind::EventFd).then_some(entry.keyspace_key as u16)
}

fn collect_ready_events(
    agent_id: u16,
    epfd: i32,
    maxevents: usize,
    ready_events: &mut [(u32, u64); 16],
) -> Result<usize, i64> {
    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return Err(-EBADF),
    };

    let epoll_idx = match st.get_fd(epfd) {
        Some(entry) if entry.kind == FdKind::Epoll => entry.keyspace_key as usize,
        Some(_) => return Err(-EINVAL),
        None => return Err(-EBADF),
    };

    if epoll_idx >= MAX_EPOLL_INSTANCES || !st.epoll_instances[epoll_idx].active {
        return Err(-EINVAL);
    }

    let watch_count = st.epoll_instances[epoll_idx].watch_count as usize;
    let mut watched_fds = [0i32; 16];
    let mut watched_masks = [0u32; 16];
    let mut watched_data = [0u64; 16];
    for i in 0..watch_count {
        watched_fds[i] = st.epoll_instances[epoll_idx].watched_fds[i];
        watched_masks[i] = st.epoll_instances[epoll_idx].watched_events[i];
        watched_data[i] = st.epoll_instances[epoll_idx].watched_data[i];
    }

    for i in 1..watch_count {
        let key_fd = watched_fds[i];
        let key_mask = watched_masks[i];
        let key_data = watched_data[i];
        let mut j = i;
        while j > 0 && watched_fds[j - 1] > key_fd {
            watched_fds[j] = watched_fds[j - 1];
            watched_masks[j] = watched_masks[j - 1];
            watched_data[j] = watched_data[j - 1];
            j -= 1;
        }
        watched_fds[j] = key_fd;
        watched_masks[j] = key_mask;
        watched_data[j] = key_data;
    }

    let mut nevents = 0usize;
    let max = maxevents.min(ready_events.len());

    for i in 0..watch_count {
        if nevents >= max {
            break;
        }

        let fd = watched_fds[i];
        let requested_mask = watched_masks[i];
        let user_data = watched_data[i];
        let ready_mask = match st.get_fd(fd) {
            Some(entry) => match entry.kind {
                FdKind::Pipe => {
                    let handle = entry.keyspace_key as u16;
                    let mut events = 0;
                    let peer_closed = !state::pipe_has_writers(handle).unwrap_or(false);
                    if fd_allows_write(entry.kind, entry.flags) && state::pipe_write_ready(handle) {
                        events |= EPOLLOUT;
                    }
                    if fd_allows_read(entry.kind, entry.flags) && state::pipe_read_ready(handle) {
                        events |= EPOLLIN;
                    }
                    if peer_closed {
                        events |= EPOLLHUP;
                    }
                    events
                }
                FdKind::Socket => {
                    let mut events = 0;
                    if entry.keyspace_key == SOCKETPAIR_STREAM_MARKER {
                        let peer_closed = !state::pipe_has_writers(entry.mailbox_id).unwrap_or(false);
                        if fd_allows_write(entry.kind, entry.flags)
                            && state::pipe_write_ready(entry.keyspace_id)
                        {
                            events |= EPOLLOUT;
                        }
                        if fd_allows_read(entry.kind, entry.flags)
                            && state::pipe_read_ready(entry.mailbox_id)
                        {
                            events |= EPOLLIN;
                        }
                        if peer_closed {
                            events |= EPOLLHUP;
                        }
                    } else {
                        let peer_closed = !crate::mailbox::mailbox_has_writers(entry.mailbox_id);
                        if fd_allows_write(entry.kind, entry.flags) {
                            events |= EPOLLOUT;
                        }
                        if fd_allows_read(entry.kind, entry.flags)
                            && crate::mailbox::mailbox_fd_read_ready(entry.mailbox_id)
                        {
                            events |= EPOLLIN;
                        }
                        if peer_closed {
                            events |= EPOLLHUP;
                        }
                    }
                    events
                }
                FdKind::EventFd => {
                    let mut events = 0;
                    if fd_allows_write(entry.kind, entry.flags)
                        && eventfd_handle(entry)
                            .map(state::eventfd_write_ready)
                            .unwrap_or(false)
                    {
                        events |= EPOLLOUT;
                    }
                    if eventfd_handle(entry)
                        .map(state::eventfd_read_ready)
                        .unwrap_or(false)
                    {
                        events |= EPOLLIN;
                    }
                    events
                }
                FdKind::File | FdKind::Directory => {
                    let mut events = 0;
                    if fd_allows_read(entry.kind, entry.flags) {
                        events |= EPOLLIN;
                    }
                    if fd_allows_write(entry.kind, entry.flags) {
                        events |= EPOLLOUT;
                    }
                    events
                }
                FdKind::Epoll => continue,
            },
            None => continue,
        };

        let delivered_mask = if requested_mask == 0 {
            ready_mask
        } else {
            // Linux reports HUP/ERR regardless of the caller's interest mask.
            (ready_mask & requested_mask) | (ready_mask & EPOLLHUP)
        };

        if delivered_mask == 0 {
            continue;
        }

        ready_events[nevents] = (delivered_mask, user_data);
        nevents += 1;
    }

    Ok(nevents)
}

fn write_ready_events(
    agent_id: u16,
    events_ptr: u64,
    ready_events: &[(u32, u64); 16],
    count: usize,
) -> i64 {
    for (idx, (events, data)) in ready_events.iter().copied().take(count).enumerate() {
        let mut event = [0u8; EPOLL_EVENT_SIZE];
        event[0..4].copy_from_slice(&events.to_ne_bytes());
        event[4..12].copy_from_slice(&data.to_ne_bytes());
        let event_ptr = events_ptr + (idx as u64) * EPOLL_EVENT_SIZE as u64;
        if !copy_to_user(agent_id, event_ptr, &event) {
            return -EFAULT;
        }
    }

    count as i64
}

/// epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
///
/// Deterministic polling: iterate watched fds in ascending order, check each
/// for readiness. Sockets/pipes with data pending are EPOLLIN-ready.
/// For deterministic behavior, all fds are always reported as EPOLLOUT-ready.
pub fn sys_epoll_wait(
    agent_id: u16,
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    timeout: i32,
) -> i64 {
    if maxevents <= 0 {
        return -EINVAL;
    }
    if events_ptr == 0 {
        return -EFAULT;
    }

    let deadline_tick = if timeout >= 0 {
        let timeout_ms = timeout as u64;
        Some(
            crate::arch::x86_64::timer::get_ticks()
                .saturating_add(timeout_ms.saturating_add(9) / 10),
        )
    } else {
        None
    };
    let mut ready_events = [(0u32, 0u64); 16];

    loop {
        let ready_count =
            match collect_ready_events(agent_id, epfd, maxevents as usize, &mut ready_events) {
                Ok(count) => count,
                Err(err) => return err,
            };

        if ready_count > 0 {
            if state::trace_runtime_agent(agent_id) {
                crate::serial_println!(
                    "[RTDBG] epoll_wait-ready agent={} epfd={} maxevents={} timeout={} ready_count={} first_events={:#x} first_data={:#x}",
                    agent_id,
                    epfd,
                    maxevents,
                    timeout,
                    ready_count,
                    ready_events[0].0,
                    ready_events[0].1
                );
            }
            return write_ready_events(agent_id, events_ptr, &ready_events, ready_count);
        }

        // Linux blocking waits are interrupted by unblocked pending signals.
        // We surface that as -EINTR so the syscall-return path can install a
        // user signal frame or report interruption in the usual way.
        if crate::linux_compat::signal::has_unblocked_pending_signal(agent_id) {
            return -EINTR;
        }

        if timeout == 0 {
            return 0;
        }

        if let Some(deadline) = deadline_tick {
            if crate::arch::x86_64::timer::get_ticks() >= deadline {
                return 0;
            }
        }

        crate::sched::yield_current();
    }
}

// ── epoll_pwait (alias) ────────────────────────────────────────────────────

/// epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
///             int timeout, const sigset_t *sigmask)
///
/// We ignore the sigmask (no signal support) and delegate to epoll_wait.
#[allow(dead_code)]
pub fn sys_epoll_pwait(
    agent_id: u16,
    epfd: i32,
    events_ptr: u64,
    maxevents: i32,
    timeout: i32,
    _sigmask_ptr: u64,
) -> i64 {
    sys_epoll_wait(agent_id, epfd, events_ptr, maxevents, timeout)
}

// ── eventfd2 ───────────────────────────────────────────────────────────────

/// eventfd2(unsigned int initval, int flags)
///
/// Creates an eventfd backed by a shared counter object.
pub fn sys_eventfd2(agent_id: u16, initval: u32, flags: i32) -> i64 {
    let st = match state::get_files_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let handle = match state::alloc_eventfd(initval as u64) {
        Some(handle) => handle,
        None => return -EMFILE,
    };

    let fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };

    st.fd_table[fd] = Some(FdEntry {
        kind: FdKind::EventFd,
        keyspace_key: handle as u64,
        keyspace_id: 0,
        mailbox_id: 0,
        offset: 0,
        flags: flags as u32,
        active: true,
    });
    if let Some(entry) = st.fd_table[fd].as_ref() {
        state::retain_fd_resources(entry);
    }

    if state::trace_runtime_agent(agent_id) {
        crate::serial_println!(
            "[RTDBG] eventfd2 agent={} fd={} handle={} init={} flags={:#x}",
            agent_id,
            fd,
            handle,
            initval,
            flags
        );
    }

    fd as i64
}
