//! SYSCALL/SYSRET MSR Configuration
//!
//! Configures the Model-Specific Registers needed for the SYSCALL/SYSRET
//! instruction pair. This enables ring 3 agents to invoke kernel syscalls.

use crate::serial_println;

/// MSR addresses
const MSR_EFER: u32 = 0xC0000080;
const MSR_STAR: u32 = 0xC0000081;
const MSR_LSTAR: u32 = 0xC0000082;
const MSR_SFMASK: u32 = 0xC0000084;

/// EFER bits
const EFER_SCE: u64 = 1 << 0; // System Call Extensions enable

extern "C" {
    fn syscall_entry();
}

/// Read a Model-Specific Register
unsafe fn rdmsr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") low,
        out("edx") high,
        options(nomem, nostack)
    );
    (high as u64) << 32 | low as u64
}

/// Write a Model-Specific Register
unsafe fn wrmsr(msr: u32, val: u64) {
    let low = val as u32;
    let high = (val >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") low,
        in("edx") high,
        options(nomem, nostack)
    );
}

/// Initialize SYSCALL/SYSRET MSRs.
///
/// STAR encoding:
///   Bits [47:32] = kernel CS selector for SYSCALL (0x08)
///     -> SYSCALL sets CS = 0x08, SS = 0x08 + 8 = 0x10
///   Bits [63:48] = base selector for SYSRET (0x10)
///     -> SYSRET sets CS = 0x10 + 16 = 0x20 (user code, +RPL3 = 0x23)
///     -> SYSRET sets SS = 0x10 + 8  = 0x18 (user data, +RPL3 = 0x1B)
pub fn init() {
    unsafe {
        // Enable SYSCALL/SYSRET in EFER
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | EFER_SCE);

        // STAR: kernel CS in [47:32], SYSRET base in [63:48]
        let star: u64 = (0x0010u64 << 48) | (0x0008u64 << 32);
        wrmsr(MSR_STAR, star);

        // LSTAR: address of syscall entry point
        let lstar = syscall_entry as *const () as u64;
        wrmsr(MSR_LSTAR, lstar);

        // SFMASK: clear IF (bit 9) on SYSCALL entry to disable interrupts
        wrmsr(MSR_SFMASK, 0x200);
    }

    serial_println!("[syscall_msr] SYSCALL/SYSRET MSRs configured");
}
