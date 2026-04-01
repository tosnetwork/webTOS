//! Deterministic time syscalls.
//!
//! All time values are derived from the TOS tick counter (100 Hz / 10ms per tick)
//! to ensure deterministic replay across all nodes.

use super::constants::*;

/// Helper: convert TOS ticks to (seconds, nanoseconds).
#[inline]
fn ticks_to_timespec() -> (u64, u64) {
    let ticks = crate::arch::x86_64::timer::get_ticks();
    let seconds = ticks / 100;
    let nanoseconds = (ticks % 100) * 10_000_000;
    (seconds, nanoseconds)
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
    if request_ptr != 0 && read_timespec(agent_id, request_ptr).is_none() {
        return -EFAULT;
    }
    // No actual sleeping in deterministic mode — just return success.
    // If remain_ptr is set, write zero remaining time.
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
    _flags: u32,
    request_ptr: u64,
    remain_ptr: u64,
) -> i64 {
    if request_ptr != 0 && read_timespec(agent_id, request_ptr).is_none() {
        return -EFAULT;
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
/// Deterministic stub: returns zeroed timer (no active timers).
pub fn sys_getitimer(agent_id: u16, _which: u64, curr_value_ptr: u64) -> i64 {
    if curr_value_ptr == 0 {
        return -EFAULT;
    }
    // itimerval = two timevals (it_interval + it_value) = 32 bytes total
    if !copy_to_user(agent_id, curr_value_ptr, &[0u8; 32]) {
        return -EFAULT;
    }
    0
}

/// setitimer(int which, const struct itimerval *new, struct itimerval *old)
///
/// Deterministic stub: no-op, writes zeroed old value if requested.
pub fn sys_setitimer(agent_id: u16, _which: u64, new_value_ptr: u64, old_value_ptr: u64) -> i64 {
    if new_value_ptr != 0 && read_timespec(agent_id, new_value_ptr).is_none() {
        return -EFAULT;
    }
    if old_value_ptr != 0 && !copy_to_user(agent_id, old_value_ptr, &[0u8; 32]) {
        return -EFAULT;
    }
    0
}

/// alarm(unsigned int seconds)
///
/// Deterministic stub: returns 0 (no previous alarm).
pub fn sys_alarm(_agent_id: u16, _seconds: u32) -> i64 {
    0
}
