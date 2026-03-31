//! Deterministic epoll implementation.
//!
//! Epoll instances track a set of watched fds. On epoll_pwait, we iterate
//! watched fds in ascending order and check readiness deterministically.

use super::constants::*;
use super::state::{self, FdEntry, FdKind, MAX_EPOLL_INSTANCES};

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
    let st = match state::get_state_mut(agent_id) {
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
    let st = match state::get_state_mut(agent_id) {
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

    // Validate the target fd exists (except on DEL, be lenient)
    if op != EPOLL_CTL_DEL {
        if st.get_fd(fd).is_none() {
            return -EBADF;
        }
    }

    let inst = &mut st.epoll_instances[epoll_idx];

    match op {
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
            inst.watched_fds[inst.watch_count as usize] = fd;
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
                    }
                    inst.watched_fds[count - 1] = -1;
                    inst.watch_count -= 1;
                    found = true;
                    break;
                }
            }
            if found {
                0
            } else {
                -ENOENT
            }
        }
        EPOLL_CTL_MOD => {
            // Check that fd is in the watch list
            let mut found = false;
            for i in 0..inst.watch_count as usize {
                if inst.watched_fds[i] == fd {
                    found = true;
                    break;
                }
            }
            if found {
                0
            } else {
                -ENOENT
            }
        }
        _ => -EINVAL,
    }
}

// ── epoll_wait / epoll_pwait ───────────────────────────────────────────────

/// Linux epoll_event struct layout (12 bytes, packed):
///   offset 0: u32 events  (EPOLLIN, EPOLLOUT, etc.)
///   offset 4: u64 data    (user data, typically the fd)
const EPOLL_EVENT_SIZE: usize = 12;

/// EPOLLIN / EPOLLOUT event flags
const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;

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
    _timeout: i32,
) -> i64 {
    if events_ptr == 0 || maxevents <= 0 {
        return -EINVAL;
    }

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    // Get the epoll instance index from the fd
    let epoll_idx = match st.get_fd(epfd) {
        Some(entry) if entry.kind == FdKind::Epoll => entry.keyspace_key as usize,
        Some(_) => return -EINVAL,
        None => return -EBADF,
    };

    if epoll_idx >= MAX_EPOLL_INSTANCES || !st.epoll_instances[epoll_idx].active {
        return -EINVAL;
    }

    // Collect watched fds (sorted ascending — they're already in insertion order,
    // but we sort for determinism)
    let watch_count = st.epoll_instances[epoll_idx].watch_count as usize;
    let mut watched = [0i32; 16];
    for i in 0..watch_count {
        watched[i] = st.epoll_instances[epoll_idx].watched_fds[i];
    }

    // Simple insertion sort for deterministic ordering
    for i in 1..watch_count {
        let key = watched[i];
        let mut j = i;
        while j > 0 && watched[j - 1] > key {
            watched[j] = watched[j - 1];
            j -= 1;
        }
        watched[j] = key;
    }

    // Check each watched fd for readiness
    let mut nevents: i32 = 0;
    let max = maxevents as usize;

    for i in 0..watch_count {
        if nevents as usize >= max {
            break;
        }

        let fd = watched[i];
        let ready_events = match st.get_fd(fd) {
            Some(entry) => {
                match entry.kind {
                    // Pipes and sockets: check mailbox for readable data
                    FdKind::Socket | FdKind::Pipe => {
                        let mut events = EPOLLOUT;
                        if let Some(mb) = crate::mailbox::get_mailbox(entry.mailbox_id) {
                            if !mb.is_empty() {
                                events |= EPOLLIN;
                            }
                        }
                        events
                    }
                    // EventFd: readable if counter > 0
                    FdKind::EventFd => {
                        let mut events = EPOLLOUT;
                        if entry.keyspace_key > 0 {
                            events |= EPOLLIN;
                        }
                        events
                    }
                    // Regular files are always ready
                    FdKind::File | FdKind::Directory => EPOLLIN | EPOLLOUT,
                    // Epoll fds themselves — skip
                    FdKind::Epoll => continue,
                }
            }
            None => continue, // fd was closed, skip
        };

        // Write epoll_event { events: u32, data: u64 }
        unsafe {
            let p = (events_ptr as *mut u8).add(nevents as usize * EPOLL_EVENT_SIZE);
            core::ptr::copy_nonoverlapping(&ready_events as *const u32 as *const u8, p, 4);
            let data = fd as u64;
            core::ptr::copy_nonoverlapping(&data as *const u64 as *const u8, p.add(4), 8);
        }
        nevents += 1;
    }

    nevents as i64
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
/// Creates an eventfd backed by a u64 counter stored in keyspace_key.
pub fn sys_eventfd2(agent_id: u16, initval: u32, flags: i32) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let fd = match st.alloc_fd() {
        Some(f) => f,
        None => return -EMFILE,
    };

    st.fd_table[fd] = Some(FdEntry {
        kind: FdKind::EventFd,
        keyspace_key: initval as u64,
        keyspace_id: 0,
        mailbox_id: 0,
        offset: 0,
        flags: flags as u32,
        active: true,
    });

    fd as i64
}
