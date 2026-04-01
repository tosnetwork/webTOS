//! Deterministic identity and system information syscalls.
//!
//! All identity calls return fixed, deterministic values.
//! getrandom uses a SHA-256 PRNG seeded per-agent.

use super::constants::*;
use super::state;
use crate::agent::USER_STACK_SIZE;
use crate::arch::x86_64::page_table;
use sha2::{Digest, Sha256};

#[inline]
fn current_uid(agent_id: u16) -> u32 {
    state::get_state(agent_id).map(|st| st.uid).unwrap_or(1000)
}

#[inline]
fn current_gid(agent_id: u16) -> u32 {
    state::get_state(agent_id).map(|st| st.gid).unwrap_or(1000)
}

#[inline]
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
        if page_table::translate_user_vaddr(cr3, page).is_none()
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

fn copy_from_user(agent_id: u16, user_addr: u64, dst: &mut [u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if !ensure_user_range_mapped(agent_id, user_addr, dst.len(), false) {
        return false;
    }
    page_table::copy_from_user(cr3, user_addr, dst)
}

fn copy_to_user(agent_id: u16, user_addr: u64, src: &[u8]) -> bool {
    let Some(cr3) = agent_cr3(agent_id) else {
        return false;
    };
    if !ensure_user_range_mapped(agent_id, user_addr, src.len(), true) {
        return false;
    }
    page_table::copy_to_user(cr3, user_addr, src)
}

// ── Simple identity getters ────────────────────────────────────────────────

/// getuid() -> deterministic Linux uid
pub fn sys_getuid(agent_id: u16) -> i64 {
    current_uid(agent_id) as i64
}

/// getgid() -> deterministic Linux gid
pub fn sys_getgid(agent_id: u16) -> i64 {
    current_gid(agent_id) as i64
}

/// geteuid() -> deterministic Linux uid
pub fn sys_geteuid(agent_id: u16) -> i64 {
    current_uid(agent_id) as i64
}

/// getegid() -> deterministic Linux gid
pub fn sys_getegid(agent_id: u16) -> i64 {
    current_gid(agent_id) as i64
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

/// getgroups(size, list) -> 1 deterministic supplementary group.
pub fn sys_getgroups(agent_id: u16, size: u64, list_ptr: u64) -> i64 {
    if size == 0 {
        return 1; // one supplementary group
    }
    if list_ptr == 0 {
        return -EFAULT;
    }
    let val = current_gid(agent_id).to_ne_bytes();
    if !copy_to_user(agent_id, list_ptr, &val) {
        return -EFAULT;
    }
    1
}

/// setgroups(size, list) -> 0 (no-op, we always report the deterministic gid)
pub fn sys_setgroups(_agent_id: u16, _size: u64, _list_ptr: u64) -> i64 {
    0
}

// ── uname ──────────────────────────────────────────────────────────────────

/// Helper: write a null-terminated string into a fixed-size utsname field (65 bytes).
fn write_utsname_field(buf: &mut [u8], offset: usize, s: &[u8]) {
    let len = if s.len() > 64 { 64 } else { s.len() };
    buf[offset..offset + 65].fill(0);
    buf[offset..offset + len].copy_from_slice(&s[..len]);
}

/// uname(struct utsname *buf)
///
/// Linux utsname: 6 fields of 65 bytes each = 390 bytes.
/// Fields: sysname, nodename, release, version, machine, domainname.
pub fn sys_uname(agent_id: u16, buf_ptr: u64) -> i64 {
    if buf_ptr == 0 {
        return -EFAULT;
    }
    let mut uts = [0u8; 390];
    write_utsname_field(&mut uts, 0, b"Linux");
    write_utsname_field(&mut uts, 65, b"tos");
    write_utsname_field(&mut uts, 130, b"5.15.0-tos");
    write_utsname_field(&mut uts, 195, b"#1 SMP TOS");
    write_utsname_field(&mut uts, 260, b"x86_64");
    write_utsname_field(&mut uts, 325, b"(none)");
    if !copy_to_user(agent_id, buf_ptr, &uts) {
        return -EFAULT;
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
pub fn sys_sysinfo(agent_id: u16, info_ptr: u64) -> i64 {
    if info_ptr == 0 {
        return -EFAULT;
    }

    let ticks = crate::arch::x86_64::timer::get_ticks();
    let uptime = (ticks / 100) as i64;

    // 512 MB total, report 256 MB free (conservative fixed value)
    let totalram: u64 = 512 * 1024 * 1024;
    let freeram: u64 = 64 * 1024 * 1024;
    let procs: u16 = 1; // at least the current agent

    let mut info = [0u8; 112];
    info[0..8].copy_from_slice(&uptime.to_ne_bytes());
    info[32..40].copy_from_slice(&totalram.to_ne_bytes());
    info[40..48].copy_from_slice(&freeram.to_ne_bytes());
    info[80..82].copy_from_slice(&procs.to_ne_bytes());
    info[104..108].copy_from_slice(&1u32.to_ne_bytes());
    if !copy_to_user(agent_id, info_ptr, &info) {
        return -EFAULT;
    }
    0
}

// ── getcpu ─────────────────────────────────────────────────────────────────

/// getcpu(unsigned *cpu, unsigned *node, void *tcache)
///
/// The result is inherently racy on Linux, so returning a deterministic
/// single-CPU / single-node view is sufficient for runtime probing.
/// `tcache` has been unused by Linux for years and is ignored here too.
pub fn sys_getcpu(agent_id: u16, cpu_ptr: u64, node_ptr: u64, _tcache: u64) -> i64 {
    let cpu: u32 = 0;
    let node: u32 = 0;

    if cpu_ptr != 0 && !copy_to_user(agent_id, cpu_ptr, &cpu.to_ne_bytes()) {
        return -EFAULT;
    }

    if node_ptr != 0 && !copy_to_user(agent_id, node_ptr, &node.to_ne_bytes()) {
        return -EFAULT;
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
pub fn restore_thread_pointer_bases(agent_id: u16) {
    let (fs_base, gs_base) = match state::get_state(agent_id) {
        Some(st) => (st.fs_base, st.gs_base),
        None => (0, 0),
    };

    unsafe {
        wrmsr(MSR_FS_BASE, fs_base);
        wrmsr(MSR_GS_BASE, gs_base);
    }
}

#[inline]
fn is_valid_user_thread_pointer_base(addr: u64) -> bool {
    // Linux x86_64 user-space TLS bases must stay in the lower canonical half.
    addr < 0x0000_8000_0000_0000
}

pub fn sys_arch_prctl(agent_id: u16, code: i32, addr: u64) -> i64 {
    let st = match state::get_state_mut(agent_id) {
        Some(s) => s,
        None => return -EBADF,
    };

    match code as u64 {
        ARCH_SET_FS => {
            if !is_valid_user_thread_pointer_base(addr) {
                return -EINVAL;
            }
            st.fs_base = addr;
            unsafe {
                wrmsr(MSR_FS_BASE, addr);
            }
            0
        }
        ARCH_GET_FS => {
            if addr == 0 {
                return -EFAULT;
            }
            if !copy_to_user(agent_id, addr, &st.fs_base.to_ne_bytes()) {
                return -EFAULT;
            }
            0
        }
        ARCH_SET_GS => {
            if !is_valid_user_thread_pointer_base(addr) {
                return -EINVAL;
            }
            st.gs_base = addr;
            unsafe {
                wrmsr(MSR_GS_BASE, addr);
            }
            0
        }
        ARCH_GET_GS => {
            if addr == 0 {
                return -EFAULT;
            }
            if !copy_to_user(agent_id, addr, &st.gs_base.to_ne_bytes()) {
                return -EFAULT;
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
pub fn sys_prlimit64(
    agent_id: u16,
    _pid: u64,
    resource: u64,
    new_limit_ptr: u64,
    old_limit_ptr: u64,
) -> i64 {
    // Determine the limit values for this resource
    let (cur, max) = match resource {
        RLIMIT_NOFILE => (state::MAX_FDS as u64, state::MAX_FDS as u64),
        RLIMIT_STACK => (USER_STACK_SIZE as u64, USER_STACK_SIZE as u64),
        _ => (RLIM_INFINITY, RLIM_INFINITY),
    };

    if new_limit_ptr != 0 {
        let mut new_limit = [0u8; 16];
        if !copy_from_user(agent_id, new_limit_ptr, &mut new_limit) {
            return -EFAULT;
        }
    }

    // Write old limit if requested
    if old_limit_ptr != 0 {
        let mut limit = [0u8; 16];
        limit[0..8].copy_from_slice(&cur.to_ne_bytes());
        limit[8..16].copy_from_slice(&max.to_ne_bytes());
        if !copy_to_user(agent_id, old_limit_ptr, &limit) {
            return -EFAULT;
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
        if !copy_to_user(agent_id, buf_ptr + written, &hash[..chunk]) {
            return -EFAULT;
        }
        written += chunk as u64;
    }

    buflen as i64
}

// ── rseq ───────────────────────────────────────────────────────────────────

/// rseq(struct rseq *rseq, u32 rseq_len, int flags, u32 sig)
///
/// Restartable sequences registration. TOS does not implement the kernel
/// bookkeeping needed to make user-space rseq critical sections safe, so we
/// must report it as unavailable and let libc fall back to non-rseq paths.
#[allow(dead_code)]
pub fn sys_rseq(_agent_id: u16, _rseq_ptr: u64, _rseq_len: u32, _flags: u32, _sig: u32) -> i64 {
    -ENOSYS
}
