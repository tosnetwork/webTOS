//! Deterministic time syscalls.
//!
//! All time values are derived from the ATOS tick counter (100 Hz / 10ms per tick)
//! to ensure deterministic replay across all nodes.

use super::constants::*;

/// Helper: convert ATOS ticks to (seconds, nanoseconds).
#[inline]
fn ticks_to_timespec() -> (u64, u64) {
    let ticks = crate::arch::x86_64::timer::get_ticks();
    let seconds = ticks / 100;
    let nanoseconds = (ticks % 100) * 10_000_000;
    (seconds, nanoseconds)
}

/// Write a timespec { tv_sec: i64, tv_nsec: i64 } to the given user pointer.
///
/// Linux timespec layout (16 bytes):
///   offset 0: i64 tv_sec
///   offset 8: i64 tv_nsec
#[inline]
unsafe fn write_timespec(ptr: u64, sec: u64, nsec: u64) {
    let p = ptr as *mut u8;
    core::ptr::copy_nonoverlapping(&(sec as i64) as *const i64 as *const u8, p, 8);
    core::ptr::copy_nonoverlapping(&(nsec as i64) as *const i64 as *const u8, p.add(8), 8);
}

/// Read a timespec { tv_sec: i64, tv_nsec: i64 } from the given user pointer.
#[inline]
unsafe fn read_timespec(ptr: u64) -> (i64, i64) {
    let p = ptr as *const u8;
    let mut sec: i64 = 0;
    let mut nsec: i64 = 0;
    core::ptr::copy_nonoverlapping(p, &mut sec as *mut i64 as *mut u8, 8);
    core::ptr::copy_nonoverlapping(p.add(8), &mut nsec as *mut i64 as *mut u8, 8);
    (sec, nsec)
}

// ── clock_getres ───────────────────────────────────────────────────────────

/// clock_getres(clockid_t clk_id, struct timespec *res)
///
/// Reports our 10ms (100 Hz) resolution for all clock types.
pub fn sys_clock_getres(_agent_id: u16, _clk_id: u64, res_ptr: u64) -> i64 {
    if res_ptr != 0 {
        unsafe {
            write_timespec(res_ptr, 0, 10_000_000); // 10ms
        }
    }
    0
}

// ── clock_gettime ──────────────────────────────────────────────────────────

/// clock_gettime(clockid_t clk_id, struct timespec *tp)
///
/// Returns deterministic time derived from tick counter.
/// All clock IDs (REALTIME, MONOTONIC, etc.) return the same tick-based value.
pub fn sys_clock_gettime(_agent_id: u16, _clk_id: u64, tp_ptr: u64) -> i64 {
    if tp_ptr == 0 {
        return -EFAULT;
    }
    let (sec, nsec) = ticks_to_timespec();
    unsafe {
        write_timespec(tp_ptr, sec, nsec);
    }
    0
}

// ── nanosleep ──────────────────────────────────────────────────────────────

/// nanosleep(const struct timespec *req, struct timespec *rem)
///
/// Deterministic: does not actually sleep. Returns immediately with remaining = 0.
pub fn sys_nanosleep(_agent_id: u16, _request_ptr: u64, remain_ptr: u64) -> i64 {
    // No actual sleeping in deterministic mode — just return success.
    // If remain_ptr is set, write zero remaining time.
    if remain_ptr != 0 {
        unsafe {
            write_timespec(remain_ptr, 0, 0);
        }
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
    _agent_id: u16,
    _clk_id: u32,
    _flags: u32,
    _request_ptr: u64,
    remain_ptr: u64,
) -> i64 {
    if remain_ptr != 0 {
        unsafe {
            write_timespec(remain_ptr, 0, 0);
        }
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
pub fn sys_gettimeofday(_agent_id: u16, tv_ptr: u64, tz_ptr: u64) -> i64 {
    if tv_ptr != 0 {
        let (sec, nsec) = ticks_to_timespec();
        let usec = nsec / 1000;
        unsafe {
            let p = tv_ptr as *mut u8;
            core::ptr::copy_nonoverlapping(&(sec as i64) as *const i64 as *const u8, p, 8);
            core::ptr::copy_nonoverlapping(&(usec as i64) as *const i64 as *const u8, p.add(8), 8);
        }
    }
    if tz_ptr != 0 {
        // UTC, no DST
        unsafe {
            let p = tz_ptr as *mut u8;
            let zero: i32 = 0;
            core::ptr::copy_nonoverlapping(&zero as *const i32 as *const u8, p, 4);
            core::ptr::copy_nonoverlapping(&zero as *const i32 as *const u8, p.add(4), 4);
        }
    }
    0
}

// ── getitimer / setitimer / alarm ──────────────────────────────────────────

/// getitimer(int which, struct itimerval *curr_value)
///
/// Deterministic stub: returns zeroed timer (no active timers).
pub fn sys_getitimer(_agent_id: u16, _which: u64, curr_value_ptr: u64) -> i64 {
    if curr_value_ptr == 0 {
        return -EFAULT;
    }
    // itimerval = two timevals (it_interval + it_value) = 32 bytes total
    unsafe {
        let p = curr_value_ptr as *mut u8;
        core::ptr::write_bytes(p, 0, 32);
    }
    0
}

/// setitimer(int which, const struct itimerval *new, struct itimerval *old)
///
/// Deterministic stub: no-op, writes zeroed old value if requested.
pub fn sys_setitimer(_agent_id: u16, _which: u64, _new_value_ptr: u64, old_value_ptr: u64) -> i64 {
    if old_value_ptr != 0 {
        unsafe {
            let p = old_value_ptr as *mut u8;
            core::ptr::write_bytes(p, 0, 32);
        }
    }
    0
}

/// alarm(unsigned int seconds)
///
/// Deterministic stub: returns 0 (no previous alarm).
pub fn sys_alarm(_agent_id: u16, _seconds: u32) -> i64 {
    0
}
