//! CPU Security Features: SMEP, SMAP, NX, Spectre mitigations
//!
//! Implements Yellow Paper §16.8 requirements:
//! - SMEP (Supervisor Mode Execution Prevention): CR4 bit 20
//! - SMAP (Supervisor Mode Access Prevention): CR4 bit 21
//! - NX (No-Execute): IA32_EFER bit 11
//! - IBRS (Indirect Branch Restricted Speculation): IA32_SPEC_CTRL bit 0
//! - STIBP (Single Thread Indirect Branch Predictor): IA32_SPEC_CTRL bit 1

use crate::serial_println;
use super::kaslr;

/// CR4 bit 20: Supervisor Mode Execution Prevention
const CR4_SMEP: u64 = 1 << 20;

/// CR4 bit 21: Supervisor Mode Access Prevention
const CR4_SMAP: u64 = 1 << 21;

/// IA32_EFER MSR index
const MSR_EFER: u32 = 0xC000_0080;

/// IA32_EFER bit 11: No-Execute Enable
const EFER_NXE: u64 = 1 << 11;

/// CPUID leaf 7, subleaf 0 — EBX bit 7: SMEP support
const CPUID7_EBX_SMEP: u32 = 1 << 7;

/// CPUID leaf 7, subleaf 0 — EBX bit 20: SMAP support
const CPUID7_EBX_SMAP: u32 = 1 << 20;

/// CPUID extended leaf 0x80000001 — EDX bit 20: NX support
const CPUID_EXT1_EDX_NX: u32 = 1 << 20;

/// CPUID leaf 7, subleaf 0 — EDX bit 26: IBRS/IBPB support
const CPUID7_EDX_IBRS: u32 = 1 << 26;

/// CPUID leaf 7, subleaf 0 — EDX bit 27: STIBP support
const CPUID7_EDX_STIBP: u32 = 1 << 27;

/// IA32_SPEC_CTRL MSR (0x48) — controls Spectre mitigations
const MSR_SPEC_CTRL: u32 = 0x48;

/// IA32_SPEC_CTRL bit 0: IBRS — restrict indirect branch speculation
const SPEC_CTRL_IBRS: u64 = 1 << 0;

/// IA32_SPEC_CTRL bit 1: STIBP — single-thread indirect branch predictor
const SPEC_CTRL_STIBP: u64 = 1 << 1;

/// Global flag: true if IBRS is supported and should be used on context switch
static mut IBRS_SUPPORTED: bool = false;

/// Global flag: true if STIBP is supported
static mut STIBP_SUPPORTED: bool = false;

/// Check CPU feature support via CPUID.
///
/// Returns `(smep, smap, nx, ibrs, stibp)`.
pub fn cpuid_check() -> (bool, bool, bool, bool, bool) {
    let smep;
    let smap;
    let nx;
    let ibrs;
    let stibp;

    unsafe {
        // CPUID leaf 7, subleaf 0: structured extended feature flags
        let ebx7: u32;
        let edx7: u32;
        core::arch::asm!(
            "push rbx",
            "xor ecx, ecx",    // subleaf = 0
            "mov eax, 7",
            "cpuid",
            "mov {:e}, ebx",
            "mov {:e}, edx",
            "pop rbx",
            out(reg) ebx7,
            out(reg) edx7,
            out("eax") _,
            out("ecx") _,
            options(nomem, nostack, preserves_flags),
        );
        smep = (ebx7 & CPUID7_EBX_SMEP) != 0;
        smap = (ebx7 & CPUID7_EBX_SMAP) != 0;
        ibrs = (edx7 & CPUID7_EDX_IBRS) != 0;
        stibp = (edx7 & CPUID7_EDX_STIBP) != 0;

        // CPUID extended leaf 0x80000001: NX support in EDX
        let edx_ext: u32;
        core::arch::asm!(
            "push rbx",
            "mov eax, 0x80000001",
            "cpuid",
            "mov {:e}, edx",   // {:e} forces 32-bit (eXX) register name
            "pop rbx",
            out(reg) edx_ext,
            out("eax") _,
            out("ecx") _,
            options(nomem, nostack, preserves_flags),
        );
        nx = (edx_ext & CPUID_EXT1_EDX_NX) != 0;
    }

    (smep, smap, nx, ibrs, stibp)
}

/// Read the current value of CR4.
#[inline]
fn read_cr4() -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr4",
            out(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Write a new value to CR4.
///
/// # Safety
/// Caller must ensure the new CR4 value is valid for the current CPU state.
#[inline]
unsafe fn write_cr4(val: u64) {
    core::arch::asm!(
        "mov cr4, {}",
        in(reg) val,
        options(nomem, nostack, preserves_flags),
    );
}

/// Read an MSR.
///
/// # Safety
/// The MSR index must be valid on this CPU.
#[inline]
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    core::arch::asm!(
        "rdmsr",
        in("ecx") msr,
        out("eax") lo,
        out("edx") hi,
        options(nomem, nostack, preserves_flags),
    );
    ((hi as u64) << 32) | (lo as u64)
}

/// Write an MSR.
///
/// # Safety
/// The MSR index must be valid and the value must be legal for that MSR.
#[inline]
unsafe fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    core::arch::asm!(
        "wrmsr",
        in("ecx") msr,
        in("eax") lo,
        in("edx") hi,
        options(nomem, nostack, preserves_flags),
    );
}

/// Enable SMEP: sets CR4 bit 20.
///
/// After this, any attempt by CPL-0 code to fetch instructions from a
/// user-accessible page (U/S=1) will trigger a #PF.
pub fn enable_smep() {
    unsafe {
        let cr4 = read_cr4();
        write_cr4(cr4 | CR4_SMEP);
    }
}

/// Enable SMAP: sets CR4 bit 21.
///
/// After this, supervisor-mode data accesses to user pages are faulting
/// unless the AC flag in RFLAGS is set (via `stac`).
pub fn enable_smap() {
    unsafe {
        let cr4 = read_cr4();
        write_cr4(cr4 | CR4_SMAP);
    }
}

/// Enable NX: sets the NXE bit in IA32_EFER (MSR 0xC000_0080, bit 11).
///
/// This activates the No-Execute page attribute bit (PTE bit 63) globally.
/// Without NXE set, the CPU ignores PTE_NO_EXECUTE even if the bit is present.
pub fn enable_nx() {
    unsafe {
        let efer = rdmsr(MSR_EFER);
        wrmsr(MSR_EFER, efer | EFER_NXE);
    }
}

/// Enable IBRS: set IA32_SPEC_CTRL bit 0.
///
/// Restricts indirect branch speculation to prevent Spectre v2 attacks.
/// Should be set when transitioning from user mode to kernel mode.
pub fn enable_ibrs() {
    unsafe {
        let val = rdmsr(MSR_SPEC_CTRL);
        wrmsr(MSR_SPEC_CTRL, val | SPEC_CTRL_IBRS);
    }
}

/// Enable STIBP: set IA32_SPEC_CTRL bit 1.
///
/// Prevents indirect branch predictions from being shared across
/// hyperthreads. Set permanently when running untrusted agents.
pub fn enable_stibp() {
    unsafe {
        let val = rdmsr(MSR_SPEC_CTRL);
        wrmsr(MSR_SPEC_CTRL, val | SPEC_CTRL_STIBP);
    }
}

/// Set IA32_SPEC_CTRL for kernel entry (IBRS + STIBP if supported).
/// Called on context switch to kernel-mode or after returning from ring 3.
#[inline]
pub fn spectre_kernel_enter() {
    unsafe {
        if IBRS_SUPPORTED {
            let mut val: u64 = 0;
            if IBRS_SUPPORTED { val |= SPEC_CTRL_IBRS; }
            if STIBP_SUPPORTED { val |= SPEC_CTRL_STIBP; }
            wrmsr(MSR_SPEC_CTRL, val);
        }
    }
}

/// Clear IBRS for user-mode entry (speculation restrictions lifted).
/// STIBP stays set if supported (cross-thread protection always on).
#[inline]
pub fn spectre_user_enter() {
    unsafe {
        if IBRS_SUPPORTED {
            let val = if STIBP_SUPPORTED { SPEC_CTRL_STIBP } else { 0 };
            wrmsr(MSR_SPEC_CTRL, val);
        }
    }
}

/// Check if IBRS is available on this CPU.
pub fn ibrs_available() -> bool {
    unsafe { IBRS_SUPPORTED }
}

/// Temporarily allow supervisor access to user pages (SMAP bypass).
///
/// Sets the AC flag in RFLAGS. Must be paired with a `clac()` call as soon
/// as the user-memory access is complete.
///
/// # Safety
/// Caller must ensure `clac()` is called before returning to normal execution.
/// Leaving AC set defeats SMAP protection.
#[inline]
pub unsafe fn stac() {
    core::arch::asm!("stac", options(nomem, nostack, preserves_flags));
}

/// Re-enable SMAP protection after a `stac()` window.
///
/// Clears the AC flag in RFLAGS, preventing supervisor access to user pages.
///
/// # Safety
/// Must only be called after a matching `stac()`.
#[inline]
pub unsafe fn clac() {
    core::arch::asm!("clac", options(nomem, nostack, preserves_flags));
}

/// Initialize all CPU security features.
///
/// Checks CPUID for feature support, enables each available feature, and
/// logs results. Gracefully skips features not supported by the CPU (e.g.
/// older QEMU configurations).
pub fn init() {
    // Seed KASLR entropy first so that subsequent allocations (heap, stacks)
    // can use the randomised offsets before any subsystem is initialised.
    kaslr::init();

    let (smep_ok, smap_ok, nx_ok, ibrs_ok, stibp_ok) = cpuid_check();

    serial_println!(
        "[security] CPUID: SMEP={} SMAP={} NX={} IBRS={} STIBP={}",
        smep_ok, smap_ok, nx_ok, ibrs_ok, stibp_ok
    );

    if nx_ok {
        enable_nx();
        serial_println!("[security] NX (EFER.NXE) enabled");
    } else {
        serial_println!("[security] NX not supported by CPU, skipping");
    }

    if smep_ok {
        enable_smep();
        serial_println!("[security] SMEP (CR4.20) enabled");
    } else {
        serial_println!("[security] SMEP not supported by CPU, skipping");
    }

    if smap_ok {
        enable_smap();
        serial_println!("[security] SMAP (CR4.21) enabled");
    } else {
        serial_println!("[security] SMAP not supported by CPU, skipping");
    }

    // Spectre mitigations
    unsafe {
        IBRS_SUPPORTED = ibrs_ok;
        STIBP_SUPPORTED = stibp_ok;
    }

    if ibrs_ok {
        enable_ibrs();
        serial_println!("[security] IBRS (Spectre v2) enabled");
    } else {
        serial_println!("[security] IBRS not supported by CPU, skipping");
    }

    if stibp_ok {
        enable_stibp();
        serial_println!("[security] STIBP (cross-thread) enabled");
    } else {
        serial_println!("[security] STIBP not supported by CPU, skipping");
    }
}
