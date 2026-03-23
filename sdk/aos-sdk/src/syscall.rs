//! Raw AOS syscall interface

pub const SYS_YIELD: u64 = 0;
pub const SYS_SPAWN: u64 = 1;
pub const SYS_EXIT: u64 = 2;
pub const SYS_SEND: u64 = 3;
pub const SYS_RECV: u64 = 4;
pub const SYS_CAP_QUERY: u64 = 5;
pub const SYS_CAP_GRANT: u64 = 6;
pub const SYS_EVENT_EMIT: u64 = 7;
pub const SYS_ENERGY_GET: u64 = 8;
pub const SYS_STATE_GET: u64 = 9;
pub const SYS_STATE_PUT: u64 = 10;
pub const SYS_CAP_REVOKE: u64 = 11;
pub const SYS_RECV_NONBLOCKING: u64 = 12;
pub const SYS_SEND_BLOCKING: u64 = 13;
pub const SYS_ENERGY_GRANT: u64 = 14;
pub const SYS_CHECKPOINT: u64 = 15;
pub const SYS_MMAP: u64 = 16;
pub const SYS_MUNMAP: u64 = 17;
pub const SYS_MAILBOX_CREATE: u64 = 18;
pub const SYS_MAILBOX_DESTROY: u64 = 19;
pub const SYS_REPLAY: u64 = 20;
pub const SYS_RECV_TIMEOUT: u64 = 21;

/// Raw syscall. Unsafe because it directly invokes the AOS syscall ABI.
#[inline(always)]
pub unsafe fn syscall(num: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") num as i64 => ret,
        in("rdi") a1,
        in("rsi") a2,
        in("rdx") a3,
        in("r10") a4,
        in("r8") a5,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}
