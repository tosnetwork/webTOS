//! Deterministic identity and system information syscalls.
//!
//! All identity calls return fixed, deterministic values.
//! getrandom uses a SHA-256 PRNG seeded per-agent.

use super::constants::*;
use super::state;
use sha2::{Sha256, Digest};

// ── Simple identity getters ────────────────────────────────────────────────

/// getuid() -> 1000
pub fn sys_getuid(_agent_id: u16) -> i64 {
    1000
}

/// getgid() -> 1000
pub fn sys_getgid(_agent_id: u16) -> i64 {
    1000
}

/// geteuid() -> 1000
pub fn sys_geteuid(_agent_id: u16) -> i64 {
    1000
}

/// getegid() -> 1000
pub fn sys_getegid(_agent_id: u16) -> i64 {
    1000
}

/// setpgid(pid, pgid) -> 0 (no-op)
pub fn sys_setpgid(_agent_id: u16, _pid: u64, _pgid: u64) -> i64 {
    0
}

/// getpgid(pid) -> pid (or agent's own pid if 0)
pub fn sys_getpgid(agent_id: u16, pid: u64) -> i64 {
    if pid == 0 {
        agent_id as i64
    } else {
        pid as i64
    }
}

/// getgroups(size, list) -> 1 group (gid 1000), or count if size == 0
pub fn sys_getgroups(_agent_id: u16, size: u64, list_ptr: u64) -> i64 {
    if size == 0 {
        return 1; // one supplementary group
    }
    if list_ptr == 0 {
        return -EFAULT;
    }
    // Write single gid_t (u32) = 1000
    unsafe {
        let val: u32 = 1000;
        core::ptr::copy_nonoverlapping(
            &val as *const u32 as *const u8,
            list_ptr as *mut u8,
            4,
        );
    }
    1
}

/// setgroups(size, list) -> 0 (no-op, we always report gid 1000)
pub fn sys_setgroups(_agent_id: u16, _size: u64, _list_ptr: u64) -> i64 {
    0
}

// ── uname ──────────────────────────────────────────────────────────────────

/// Helper: write a null-terminated string into a fixed-size utsname field (65 bytes).
unsafe fn write_utsname_field(ptr: *mut u8, s: &[u8]) {
    let len = if s.len() > 64 { 64 } else { s.len() };
    core::ptr::write_bytes(ptr, 0, 65); // zero the field first
    core::ptr::copy_nonoverlapping(s.as_ptr(), ptr, len);
}

/// uname(struct utsname *buf)
///
/// Linux utsname: 6 fields of 65 bytes each = 390 bytes.
/// Fields: sysname, nodename, release, version, machine, domainname.
pub fn sys_uname(_agent_id: u16, buf_ptr: u64) -> i64 {
    if buf_ptr == 0 {
        return -EFAULT;
    }
    unsafe {
        let p = buf_ptr as *mut u8;
        write_utsname_field(p, b"Linux");                 // sysname
        write_utsname_field(p.add(65), b"atos");          // nodename
        write_utsname_field(p.add(130), b"5.15.0-atos");  // release
        write_utsname_field(p.add(195), b"#1 SMP ATOS");  // version
        write_utsname_field(p.add(260), b"x86_64");       // machine
        write_utsname_field(p.add(325), b"(none)");       // domainname
    }
    0
}

// ── sysinfo ────────────────────────────────────────────────────────────────

/// sysinfo(struct sysinfo *info)
///
/// Linux sysinfo struct layout (112 bytes on x86_64):
///   offset  0: i64  uptime
///   offset  8: [u64; 3] loads (1, 5, 15 min)
///   offset 32: u64  totalram
///   offset 40: u64  freeram
///   offset 48: u64  sharedram
///   offset 56: u64  bufferram
///   offset 64: u64  totalswap
///   offset 72: u64  freeswap
///   offset 80: u16  procs
///   offset 82: (padding)
///   offset 88: u64  totalhigh
///   offset 96: u64  freehigh
///   offset 104: u32 mem_unit
pub fn sys_sysinfo(_agent_id: u16, info_ptr: u64) -> i64 {
    if info_ptr == 0 {
        return -EFAULT;
    }

    let ticks = crate::arch::x86_64::timer::get_ticks();
    let uptime = (ticks / 100) as i64;

    // 128 MB total, report 64 MB free (conservative fixed value)
    let totalram: u64 = 128 * 1024 * 1024;
    let freeram: u64 = 64 * 1024 * 1024;
    let procs: u16 = 1; // at least the current agent

    unsafe {
        let p = info_ptr as *mut u8;
        // Zero the whole struct first
        core::ptr::write_bytes(p, 0, 112);

        // uptime
        core::ptr::copy_nonoverlapping(
            &uptime as *const i64 as *const u8, p, 8,
        );
        // totalram at offset 32
        core::ptr::copy_nonoverlapping(
            &totalram as *const u64 as *const u8, p.add(32), 8,
        );
        // freeram at offset 40
        core::ptr::copy_nonoverlapping(
            &freeram as *const u64 as *const u8, p.add(40), 8,
        );
        // procs at offset 80
        core::ptr::copy_nonoverlapping(
            &procs as *const u16 as *const u8, p.add(80), 2,
        );
        // mem_unit at offset 104
        let mem_unit: u32 = 1;
        core::ptr::copy_nonoverlapping(
            &mem_unit as *const u32 as *const u8, p.add(104), 4,
        );
    }
    0
}

// ── arch_prctl ─────────────────────────────────────────────────────────────

/// MSR numbers for FS/GS base.
const MSR_FS_BASE: u32 = 0xC000_0100;
const MSR_GS_BASE: u32 = 0xC000_0101;

/// Write a value to an MSR.
#[inline]
unsafe fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nostack, preserves_flags),
    );
}

/// Read a value from an MSR.
#[inline]
#[allow(dead_code)]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nostack, preserves_flags),
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// arch_prctl(int code, unsigned long addr)
///
/// ARCH_SET_FS (0x1002): set FS base for TLS
/// ARCH_GET_FS (0x1003): get FS base
/// ARCH_SET_GS (0x1001): set GS base
/// ARCH_GET_GS (0x1004): get GS base
pub fn sys_arch_prctl(agent_id: u16, code: i32, addr: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match code as u64 {
        ARCH_SET_FS => {
            st.fs_base = addr;
            unsafe { wrmsr(MSR_FS_BASE, addr); }
            0
        }
        ARCH_GET_FS => {
            if addr == 0 {
                return -EFAULT;
            }
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &st.fs_base as *const u64 as *const u8,
                    addr as *mut u8,
                    8,
                );
            }
            0
        }
        ARCH_SET_GS => {
            // Write the MSR; no persistent field for GS in state
            unsafe { wrmsr(MSR_GS_BASE, addr); }
            0
        }
        ARCH_GET_GS => {
            if addr == 0 {
                return -EFAULT;
            }
            let val = unsafe { rdmsr(MSR_GS_BASE) };
            unsafe {
                core::ptr::copy_nonoverlapping(
                    &val as *const u64 as *const u8,
                    addr as *mut u8,
                    8,
                );
            }
            0
        }
        _ => -EINVAL,
    }
}

// ── prlimit64 ──────────────────────────────────────────────────────────────

/// Resource limit constants.
const RLIMIT_NOFILE: u64 = 7;
const RLIMIT_STACK: u64 = 3;
const RLIM_INFINITY: u64 = !0; // 0xFFFFFFFFFFFFFFFF

/// prlimit64(pid_t pid, unsigned int resource,
///           const struct rlimit64 *new_limit, struct rlimit64 *old_limit)
///
/// rlimit64 struct: { rlim_cur: u64, rlim_max: u64 } = 16 bytes
pub fn sys_prlimit64(_agent_id: u16, _pid: u64, resource: u64, _new_limit_ptr: u64, old_limit_ptr: u64) -> i64 {
    // Determine the limit values for this resource
    let (cur, max) = match resource {
        RLIMIT_NOFILE => (256u64, 256u64),
        RLIMIT_STACK => (65536u64, 65536u64),
        _ => (RLIM_INFINITY, RLIM_INFINITY),
    };

    // Write old limit if requested
    if old_limit_ptr != 0 {
        unsafe {
            let p = old_limit_ptr as *mut u8;
            core::ptr::copy_nonoverlapping(
                &cur as *const u64 as *const u8, p, 8,
            );
            core::ptr::copy_nonoverlapping(
                &max as *const u64 as *const u8, p.add(8), 8,
            );
        }
    }

    0
}

// ── getrandom ──────────────────────────────────────────────────────────────

/// getrandom(void *buf, size_t buflen, unsigned int flags)
///
/// Deterministic PRNG using SHA-256 chaining.
/// Each call consumes from the agent's PRNG state, ensuring identical
/// output across all replicas for the same sequence of calls.
pub fn sys_getrandom(agent_id: u16, buf_ptr: u64, buflen: u64, _flags: u64) -> i64 {
    if buf_ptr == 0 {
        return -EFAULT;
    }
    if buflen == 0 {
        return 0;
    }

    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    let mut written: u64 = 0;
    let dst = buf_ptr as *mut u8;

    while written < buflen {
        // Generate 32 bytes of PRNG output via SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&st.prng_state);
        hasher.update(&st.prng_counter.to_le_bytes());
        let hash = hasher.finalize();

        // Update PRNG state
        st.prng_state.copy_from_slice(&hash);
        st.prng_counter += 1;

        // Copy to user buffer
        let remaining = (buflen - written) as usize;
        let chunk = if remaining > 32 { 32 } else { remaining };
        unsafe {
            core::ptr::copy_nonoverlapping(
                hash.as_ptr(),
                dst.add(written as usize),
                chunk,
            );
        }
        written += chunk as u64;
    }

    buflen as i64
}

// ── rseq ───────────────────────────────────────────────────────────────────

/// rseq(struct rseq *rseq, u32 rseq_len, int flags, u32 sig)
///
/// Restartable sequences registration. ATOS does not support rseq
/// acceleration, but returns 0 (success) because glibc and OpenJDK
/// call this for every thread and expect it to succeed. The registered
/// rseq struct is simply ignored — ATOS's deterministic scheduling
/// makes rseq optimizations unnecessary.
#[allow(dead_code)]
pub fn sys_rseq(_agent_id: u16, _rseq_ptr: u64, _rseq_len: u32, _flags: u32, _sig: u32) -> i64 {
    0
}
