//! Deterministic time syscalls.
//!
//! All time values are derived from the TOS tick counter (100 Hz / 10ms per tick)
//! to ensure deterministic replay across all nodes.

use super::constants::*;
use super::state::{self, FdEntry, FdKind};
use crate::agent::{self, AgentStatus, MAX_AGENTS};
use crate::arch::x86_64::timer;

const NS_PER_TICK: u64 = 10_000_000;
const TIMER_ABSTIME: u32 = 1;
const CLOCK_REALTIME: i32 = 0;
const CLOCK_MONOTONIC: i32 = 1;
const ITIMER_REAL: u64 = 0;
const ITIMER_VIRTUAL: u64 = 1;
const ITIMER_PROF: u64 = 2;
const NUM_ITIMERS: usize = 3;
const SIGALRM: u32 = 14;

static mut SLEEP_DEADLINES: [u64; MAX_AGENTS] = [0; MAX_AGENTS];

#[inline]
fn sleep_slot(agent_id: u16) -> Option<usize> {
    if agent_id == 0 {
        return None;
    }
    let idx = agent_id as usize - 1;
    (idx < MAX_AGENTS).then_some(idx)
}

/// Helper: convert TOS ticks to (seconds, nanoseconds).
#[inline]
fn ticks_to_timespec() -> (u64, u64) {
    let ticks = timer::get_ticks();
    let seconds = ticks / 100;
    let nanoseconds = (ticks % 100) * NS_PER_TICK;
    (seconds, nanoseconds)
}

#[inline]
fn ticks_to_timeval(ticks: u64) -> (u64, u64) {
    let sec = ticks / 100;
    let rem_ticks = ticks % 100;
    (sec, rem_ticks * 10_000)
}

#[inline]
fn itimer_index(which: u64) -> Option<usize> {
    match which {
        ITIMER_REAL => Some(0),
        ITIMER_VIRTUAL => Some(1),
        ITIMER_PROF => Some(2),
        _ => None,
    }
}

#[inline]
fn process_timer_owner(agent_id: u16) -> u16 {
    state::get_state(agent_id)
        .map(|st| st.thread_group_leader)
        .unwrap_or(agent_id)
}

#[inline]
fn remaining_timer_ticks(it: &state::ItimerState, now: u64) -> u64 {
    if it.deadline_tick == 0 || now >= it.deadline_tick {
        0
    } else {
        it.deadline_tick - now
    }
}

fn timeval_to_ticks(sec: i64, usec: i64) -> Option<u64> {
    if sec < 0 || !(0..1_000_000).contains(&usec) {
        return None;
    }
    let base = (sec as u64).saturating_mul(100);
    let sub = if usec == 0 {
        0
    } else {
        (((usec as u64) * 1_000).saturating_add(NS_PER_TICK - 1)) / NS_PER_TICK
    };
    Some(base.saturating_add(sub))
}

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

/// Write a timespec { tv_sec: i64, tv_nsec: i64 } to the given user pointer.
///
/// Linux timespec layout (16 bytes):
///   offset 0: i64 tv_sec
///   offset 8: i64 tv_nsec
#[inline]
fn write_timespec(agent_id: u16, ptr: u64, sec: u64, nsec: u64) -> bool {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&(sec as i64).to_ne_bytes());
    buf[8..16].copy_from_slice(&(nsec as i64).to_ne_bytes());
    copy_to_user(agent_id, ptr, &buf)
}

/// Read a timespec { tv_sec: i64, tv_nsec: i64 } from the given user pointer.
#[inline]
fn read_timespec(agent_id: u16, ptr: u64) -> Option<(i64, i64)> {
    let mut buf = [0u8; 16];
    if !copy_from_user(agent_id, ptr, &mut buf) {
        return None;
    }
    Some((
        i64::from_ne_bytes(buf[0..8].try_into().ok()?),
        i64::from_ne_bytes(buf[8..16].try_into().ok()?),
    ))
}

#[inline]
fn write_timeval(agent_id: u16, ptr: u64, sec: u64, usec: u64) -> bool {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&(sec as i64).to_ne_bytes());
    buf[8..16].copy_from_slice(&(usec as i64).to_ne_bytes());
    copy_to_user(agent_id, ptr, &buf)
}

#[inline]
fn read_timeval(agent_id: u16, ptr: u64) -> Option<(i64, i64)> {
    let mut buf = [0u8; 16];
    if !copy_from_user(agent_id, ptr, &mut buf) {
        return None;
    }
    Some((
        i64::from_ne_bytes(buf[0..8].try_into().ok()?),
        i64::from_ne_bytes(buf[8..16].try_into().ok()?),
    ))
}

#[inline]
fn write_itimerval(agent_id: u16, ptr: u64, interval_ticks: u64, value_ticks: u64) -> bool {
    let (int_sec, int_usec) = ticks_to_timeval(interval_ticks);
    let (val_sec, val_usec) = ticks_to_timeval(value_ticks);
    write_timeval(agent_id, ptr, int_sec, int_usec)
        && write_timeval(agent_id, ptr + 16, val_sec, val_usec)
}

#[inline]
fn read_itimerval(agent_id: u16, ptr: u64) -> Option<(u64, u64)> {
    let (int_sec, int_usec) = read_timeval(agent_id, ptr)?;
    let (val_sec, val_usec) = read_timeval(agent_id, ptr + 16)?;
    Some((
        timeval_to_ticks(int_sec, int_usec)?,
        timeval_to_ticks(val_sec, val_usec)?,
    ))
}

#[inline]
fn write_itimerspec(agent_id: u16, ptr: u64, interval_ticks: u64, value_ticks: u64) -> bool {
    let (int_sec, int_nsec) = (
        interval_ticks / 100,
        (interval_ticks % 100) * NS_PER_TICK,
    );
    let (val_sec, val_nsec) = (value_ticks / 100, (value_ticks % 100) * NS_PER_TICK);
    write_timespec(agent_id, ptr, int_sec, int_nsec)
        && write_timespec(agent_id, ptr + 16, val_sec, val_nsec)
}

#[inline]
fn read_itimerspec(agent_id: u16, ptr: u64) -> Option<(u64, u64)> {
    let (int_sec, int_nsec) = read_timespec(agent_id, ptr)?;
    let (val_sec, val_nsec) = read_timespec(agent_id, ptr + 16)?;
    Some((
        timespec_to_ticks(int_sec, int_nsec)?,
        timespec_to_ticks(val_sec, val_nsec)?,
    ))
}

#[inline]
fn timespec_to_ticks(sec: i64, nsec: i64) -> Option<u64> {
    if sec < 0 || !(0..1_000_000_000).contains(&nsec) {
        return None;
    }
    let secs = (sec as u64).saturating_mul(100);
    let sub = if nsec == 0 {
        0
    } else {
        ((nsec as u64).saturating_add(NS_PER_TICK - 1)) / NS_PER_TICK
    };
    Some(secs.saturating_add(sub))
}

fn sleep_until_tick(agent_id: u16, deadline_tick: u64) {
    let Some(slot) = sleep_slot(agent_id) else {
        return;
    };
    unsafe {
        SLEEP_DEADLINES[slot] = deadline_tick;
    }
    crate::sched::block_current(AgentStatus::BlockedRecv);
    unsafe {
        SLEEP_DEADLINES[slot] = 0;
    }
}

pub fn sleep_tick() {
    let now = timer::get_ticks();
    unsafe {
        for (idx, deadline) in SLEEP_DEADLINES.iter_mut().enumerate() {
            if *deadline == 0 {
                continue;
            }
            let agent_id = idx as u16 + 1;
            if agent::get_agent(agent_id).is_none() {
                *deadline = 0;
                continue;
            }
            if now >= *deadline {
                *deadline = 0;
                crate::sched::unblock(agent_id);
            }
        }
    }

    let mut fired: [u16; state::MAX_LINUX_AGENTS] = [0; state::MAX_LINUX_AGENTS];
    let mut fired_count = 0usize;
    state::for_each_process_leader(|leader| {
        let Some(st) = state::get_state_mut(leader) else {
            return true;
        };
        let mut process_fired = false;
        for it in st.itimers.iter_mut() {
            if it.deadline_tick == 0 || now < it.deadline_tick {
                continue;
            }
            process_fired = true;
            if it.interval_ticks != 0 {
                it.deadline_tick = now.saturating_add(it.interval_ticks);
            } else {
                it.deadline_tick = 0;
            }
        }
        if process_fired && fired_count < fired.len() {
            fired[fired_count] = leader;
            fired_count += 1;
        }
        true
    });

    for leader in fired.into_iter().take(fired_count) {
        super::signal::raise_group_signal(leader, SIGALRM);
    }

    state::timerfd_tick(now);
}

// ── clock_getres ───────────────────────────────────────────────────────────

/// clock_getres(clockid_t clk_id, struct timespec *res)
///
/// Reports our 10ms (100 Hz) resolution for all clock types.
pub fn sys_clock_getres(agent_id: u16, _clk_id: u64, res_ptr: u64) -> i64 {
    if res_ptr != 0 && !write_timespec(agent_id, res_ptr, 0, 10_000_000) {
        return -EFAULT;
    }
    0
}

// ── clock_gettime ──────────────────────────────────────────────────────────

/// clock_gettime(clockid_t clk_id, struct timespec *tp)
///
/// Returns deterministic time derived from tick counter.
/// All clock IDs (REALTIME, MONOTONIC, etc.) return the same tick-based value.
pub fn sys_clock_gettime(agent_id: u16, _clk_id: u64, tp_ptr: u64) -> i64 {
    if tp_ptr == 0 {
        return -EFAULT;
    }
    let (sec, nsec) = ticks_to_timespec();
    if !write_timespec(agent_id, tp_ptr, sec, nsec) {
        return -EFAULT;
    }
    0
}

// ── time ───────────────────────────────────────────────────────────────────

/// time(time_t *tloc)
///
/// Returns deterministic seconds derived from the global tick counter.
pub fn sys_time(agent_id: u16, tloc_ptr: u64) -> i64 {
    let (sec, _) = ticks_to_timespec();
    if tloc_ptr != 0 && !copy_to_user(agent_id, tloc_ptr, &(sec as i64).to_ne_bytes()) {
        return -EFAULT;
    }
    sec as i64
}

// ── nanosleep ──────────────────────────────────────────────────────────────

/// nanosleep(const struct timespec *req, struct timespec *rem)
///
/// Deterministic: does not actually sleep. Returns immediately with remaining = 0.
pub fn sys_nanosleep(agent_id: u16, request_ptr: u64, remain_ptr: u64) -> i64 {
    let Some((sec, nsec)) = (if request_ptr != 0 {
        read_timespec(agent_id, request_ptr)
    } else {
        Some((0, 0))
    }) else {
        return -EFAULT;
    };
    let Some(delta_ticks) = timespec_to_ticks(sec, nsec) else {
        return -EINVAL;
    };
    if delta_ticks != 0 {
        let deadline = timer::get_ticks().saturating_add(delta_ticks);
        sleep_until_tick(agent_id, deadline);
    }
    if remain_ptr != 0 && !write_timespec(agent_id, remain_ptr, 0, 0) {
        return -EFAULT;
    }
    0
}

// ── clock_nanosleep (not in dispatch yet, but provided for future use) ─────

/// clock_nanosleep(clockid_t clk_id, int flags, const struct timespec *request,
///                 struct timespec *remain)
///
/// Deterministic: no actual sleep, return immediately.
#[allow(dead_code)]
pub fn sys_clock_nanosleep(
    agent_id: u16,
    _clk_id: u32,
    flags: u32,
    request_ptr: u64,
    remain_ptr: u64,
) -> i64 {
    let Some((sec, nsec)) = (if request_ptr != 0 {
        read_timespec(agent_id, request_ptr)
    } else {
        Some((0, 0))
    }) else {
        return -EFAULT;
    };
    let Some(req_ticks) = timespec_to_ticks(sec, nsec) else {
        return -EINVAL;
    };
    let deadline = if flags & TIMER_ABSTIME != 0 {
        req_ticks
    } else {
        timer::get_ticks().saturating_add(req_ticks)
    };
    if deadline > timer::get_ticks() {
        sleep_until_tick(agent_id, deadline);
    }
    if remain_ptr != 0 && !write_timespec(agent_id, remain_ptr, 0, 0) {
        return -EFAULT;
    }
    0
}

// ── gettimeofday ───────────────────────────────────────────────────────────

/// gettimeofday(struct timeval *tv, struct timezone *tz)
///
/// Linux timeval layout (16 bytes):
///   offset 0: i64 tv_sec
///   offset 8: i64 tv_usec
///
/// timezone layout (8 bytes):
///   offset 0: i32 tz_minuteswest
///   offset 4: i32 tz_dsttime
#[allow(dead_code)]
pub fn sys_gettimeofday(agent_id: u16, tv_ptr: u64, tz_ptr: u64) -> i64 {
    if tv_ptr != 0 {
        let (sec, nsec) = ticks_to_timespec();
        let usec = nsec / 1000;
        let mut tv = [0u8; 16];
        tv[0..8].copy_from_slice(&(sec as i64).to_ne_bytes());
        tv[8..16].copy_from_slice(&(usec as i64).to_ne_bytes());
        if !copy_to_user(agent_id, tv_ptr, &tv) {
            return -EFAULT;
        }
    }
    if tz_ptr != 0 {
        // UTC, no DST
        let zero = [0u8; 8];
        if !copy_to_user(agent_id, tz_ptr, &zero) {
            return -EFAULT;
        }
    }
    0
}

// ── getitimer / setitimer / alarm ──────────────────────────────────────────

/// getitimer(int which, struct itimerval *curr_value)
///
pub fn sys_getitimer(agent_id: u16, which: u64, curr_value_ptr: u64) -> i64 {
    if curr_value_ptr == 0 {
        return -EFAULT;
    }
    let Some(index) = itimer_index(which) else {
        return -EINVAL;
    };
    let owner = process_timer_owner(agent_id);
    let now = timer::get_ticks();
    let Some(st) = state::get_state(owner) else {
        return -EINVAL;
    };
    let it = st.itimers[index];
    if !write_itimerval(
        agent_id,
        curr_value_ptr,
        it.interval_ticks,
        remaining_timer_ticks(&it, now),
    ) {
        return -EFAULT;
    }
    0
}

/// setitimer(int which, const struct itimerval *new, struct itimerval *old)
///
pub fn sys_setitimer(agent_id: u16, which: u64, new_value_ptr: u64, old_value_ptr: u64) -> i64 {
    let Some(index) = itimer_index(which) else {
        return -EINVAL;
    };
    let owner = process_timer_owner(agent_id);
    let now = timer::get_ticks();
    let new_timer = if new_value_ptr != 0 {
        match read_itimerval(agent_id, new_value_ptr) {
            Some(v) => Some(v),
            None => return -EFAULT,
        }
    } else {
        None
    };

    let Some(st) = state::get_state_mut(owner) else {
        return -EINVAL;
    };
    let old = st.itimers[index];
    if old_value_ptr != 0
        && !write_itimerval(
            agent_id,
            old_value_ptr,
            old.interval_ticks,
            remaining_timer_ticks(&old, now),
        )
    {
        return -EFAULT;
    }

    if let Some((interval_ticks, value_ticks)) = new_timer {
        st.itimers[index].interval_ticks = interval_ticks;
        st.itimers[index].deadline_tick = if value_ticks == 0 {
            0
        } else {
            now.saturating_add(value_ticks)
        };
    }
    0
}

/// alarm(unsigned int seconds)
///
pub fn sys_alarm(agent_id: u16, seconds: u32) -> i64 {
    let owner = process_timer_owner(agent_id);
    let now = timer::get_ticks();
    let Some(st) = state::get_state_mut(owner) else {
        return -EINVAL;
    };
    let old = st.itimers[ITIMER_REAL as usize];
    let remaining = remaining_timer_ticks(&old, now);
    st.itimers[ITIMER_REAL as usize].interval_ticks = 0;
    st.itimers[ITIMER_REAL as usize].deadline_tick = if seconds == 0 {
        0
    } else {
        now.saturating_add((seconds as u64).saturating_mul(100))
    };
    remaining.div_ceil(100) as i64
}

// ── timerfd ────────────────────────────────────────────────────────────────

fn timerfd_handle(entry: &FdEntry) -> Option<u16> {
    (entry.kind == FdKind::TimerFd).then_some(entry.keyspace_key as u16)
}

pub fn sys_timerfd_create(agent_id: u16, clockid: i32, flags: i32) -> i64 {
    let flags = flags as u32;
    let supported_flags = O_CLOEXEC | O_NONBLOCK;
    if clockid != CLOCK_REALTIME && clockid != CLOCK_MONOTONIC {
        return -EINVAL;
    }
    if flags & !supported_flags != 0 {
        return -EINVAL;
    }

    let handle = match state::alloc_timerfd() {
        Some(handle) => handle,
        None => return -EMFILE,
    };

    let st = match state::get_files_state_mut(agent_id) {
        Some(s) => s,
        None => {
            state::release_fd_resources(&FdEntry {
                kind: FdKind::TimerFd,
                keyspace_key: handle as u64,
                keyspace_id: 0,
                mailbox_id: 0,
                offset: 0,
                flags,
                active: true,
            });
            return -EBADF;
        }
    };

    let fd = match st.alloc_fd() {
        Some(f) => f,
        None => {
            state::release_fd_resources(&FdEntry {
                kind: FdKind::TimerFd,
                keyspace_key: handle as u64,
                keyspace_id: 0,
                mailbox_id: 0,
                offset: 0,
                flags,
                active: true,
            });
            return -EMFILE;
        }
    };

    st.fd_table[fd] = Some(FdEntry {
        kind: FdKind::TimerFd,
        keyspace_key: handle as u64,
        keyspace_id: 0,
        mailbox_id: 0,
        offset: 0,
        flags,
        active: true,
    });
    if let Some(entry) = st.fd_table[fd].as_ref() {
        state::retain_fd_resources(entry);
    }
    fd as i64
}

pub fn sys_timerfd_settime(
    agent_id: u16,
    fd: i32,
    flags: i32,
    new_value_ptr: u64,
    old_value_ptr: u64,
) -> i64 {
    let flags = flags as u32;
    if flags & !TIMER_ABSTIME != 0 {
        return -EINVAL;
    }
    if new_value_ptr == 0 {
        return -EFAULT;
    }

    let Some((interval_ticks, value_ticks)) = read_itimerspec(agent_id, new_value_ptr) else {
        return -EFAULT;
    };

    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    let handle = match st.get_fd(fd).and_then(timerfd_handle) {
        Some(handle) => handle,
        None => return -EBADF,
    };

    let now = timer::get_ticks();
    let Some((old_interval, old_deadline, old_expirations)) = state::timerfd_state(handle) else {
        return -EBADF;
    };
    if old_value_ptr != 0 {
        let remaining = if old_expirations > 0 || old_deadline == 0 || old_deadline <= now {
            0
        } else {
            old_deadline - now
        };
        if !write_itimerspec(agent_id, old_value_ptr, old_interval, remaining) {
            return -EFAULT;
        }
    }

    let deadline_tick = if value_ticks == 0 {
        0
    } else if flags & TIMER_ABSTIME != 0 {
        value_ticks
    } else {
        now.saturating_add(value_ticks)
    };
    if !state::timerfd_arm(handle, interval_ticks, deadline_tick) {
        return -EBADF;
    }
    0
}

pub fn sys_timerfd_gettime(agent_id: u16, fd: i32, curr_value_ptr: u64) -> i64 {
    if curr_value_ptr == 0 {
        return -EFAULT;
    }

    let st = match state::get_files_state(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };
    let handle = match st.get_fd(fd).and_then(timerfd_handle) {
        Some(handle) => handle,
        None => return -EBADF,
    };
    let now = timer::get_ticks();
    let Some((interval_ticks, deadline_tick, expirations)) = state::timerfd_state(handle) else {
        return -EBADF;
    };
    let remaining = if expirations > 0 || deadline_tick == 0 || deadline_tick <= now {
        0
    } else {
        deadline_tick - now
    };
    if !write_itimerspec(agent_id, curr_value_ptr, interval_ticks, remaining) {
        return -EFAULT;
    }
    0
}
