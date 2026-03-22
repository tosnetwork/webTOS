//! AOS x86_64 GDT (Global Descriptor Table)
//!
//! Sets up a 64-bit GDT with kernel code/data segments and a TSS.
//! The TSS provides RSP0 (kernel stack for privilege transitions) and
//! IST1 (separate stack for double-fault handling).

use crate::serial_println;

/// Kernel code segment selector (index 1 in GDT, RPL=0).
pub const KERNEL_CS: u16 = 0x08;

/// Kernel data segment selector (index 2 in GDT, RPL=0).
pub const KERNEL_DS: u16 = 0x10;

/// User data segment selector (index 3 in GDT, RPL=3).
/// Used by SYSRET to set user-mode SS and CS.
pub const USER_DS: u16 = 0x18 | 3;

/// User code segment selector (index 4 in GDT, RPL=3).
pub const USER_CS: u16 = 0x20 | 3;

/// TSS segment selector (index 5 in GDT).
const TSS_SELECTOR: u16 = 0x28;

// ---- GDT entry ----

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct GdtEntry {
    limit_low: u16,
    base_low: u16,
    base_mid: u8,
    access: u8,
    flags_limit_high: u8,
    base_high: u8,
}

impl GdtEntry {
    const fn null() -> Self {
        GdtEntry {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            flags_limit_high: 0,
            base_high: 0,
        }
    }

    /// Create a 64-bit code segment descriptor.
    /// access: Present(1) | DPL(2) | S=1 | Type(4)
    /// For kernel code (DPL=0): 0x9A = 1_00_1_1010
    /// For user code (DPL=3):   0xFA = 1_11_1_1010
    /// flags_limit_high: L=1 (long mode), D=0 for 64-bit: 0x20 | limit_high
    const fn code_segment(access: u8) -> Self {
        GdtEntry {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            flags_limit_high: 0xAF, // G=1, L=1, D=0, limit[19:16]=0xF
            base_high: 0,
        }
    }

    /// Create a 64-bit data segment descriptor.
    /// For kernel data (DPL=0): 0x92 = 1_00_1_0010
    /// For user data (DPL=3):   0xF2 = 1_11_1_0010
    const fn data_segment(access: u8) -> Self {
        GdtEntry {
            limit_low: 0xFFFF,
            base_low: 0,
            base_mid: 0,
            access,
            flags_limit_high: 0xCF, // G=1, D/B=1, limit[19:16]=0xF
            base_high: 0,
        }
    }
}

// ---- TSS ----

#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    ist1: u64,
    ist2: u64,
    ist3: u64,
    ist4: u64,
    ist5: u64,
    ist6: u64,
    ist7: u64,
    reserved2: u64,
    reserved3: u16,
    iomap_base: u16,
}

// ---- GDT pointer ----

#[repr(C, packed)]
struct GdtPtr {
    limit: u16,
    base: u64,
}

// ---- Static storage ----

// GDT: null + kernel_code + kernel_data + user_data + user_code + tss_low + tss_high = 7 entries
// TSS descriptor occupies two GDT entries (16 bytes) in 64-bit mode.
static mut GDT: [GdtEntry; 7] = [GdtEntry::null(); 7];
static mut TSS: Tss = Tss {
    reserved0: 0,
    rsp0: 0,
    rsp1: 0,
    rsp2: 0,
    reserved1: 0,
    ist1: 0,
    ist2: 0,
    ist3: 0,
    ist4: 0,
    ist5: 0,
    ist6: 0,
    ist7: 0,
    reserved2: 0,
    reserved3: 0,
    iomap_base: 104, // size of TSS
};

// Separate stacks for IST1 (double fault) and RSP0 (interrupt/ring transitions)
static mut IST1_STACK: [u8; 4096] = [0u8; 4096];
static mut RSP0_STACK: [u8; 8192] = [0u8; 8192];

/// Initialize the GDT, TSS, and load them into the CPU.
pub fn init() {
    unsafe {
        // Set up TSS stacks
        let ist1_top = IST1_STACK.as_ptr().add(IST1_STACK.len()) as u64;
        let rsp0_top = RSP0_STACK.as_ptr().add(RSP0_STACK.len()) as u64;

        TSS.ist1 = ist1_top;
        TSS.rsp0 = rsp0_top;

        // Build GDT entries
        GDT[0] = GdtEntry::null();                     // 0x00: null
        GDT[1] = GdtEntry::code_segment(0x9A);         // 0x08: kernel code
        GDT[2] = GdtEntry::data_segment(0x92);         // 0x10: kernel data
        GDT[3] = GdtEntry::data_segment(0xF2);         // 0x18: user data
        GDT[4] = GdtEntry::code_segment(0xFA);         // 0x20: user code

        // TSS descriptor (occupies entries 5 and 6)
        let tss_addr = &TSS as *const Tss as u64;
        let tss_limit = (core::mem::size_of::<Tss>() - 1) as u64;

        // Low 8 bytes of TSS descriptor (entry 5)
        GDT[5] = GdtEntry {
            limit_low: (tss_limit & 0xFFFF) as u16,
            base_low: (tss_addr & 0xFFFF) as u16,
            base_mid: ((tss_addr >> 16) & 0xFF) as u8,
            access: 0x89, // Present, 64-bit TSS (Available): 1_00_0_1001
            flags_limit_high: ((tss_limit >> 16) & 0x0F) as u8,
            base_high: ((tss_addr >> 24) & 0xFF) as u8,
        };

        // High 8 bytes of TSS descriptor (entry 6): upper 32 bits of base + reserved
        let tss_high_bytes = (tss_addr >> 32) as u32;
        GDT[6] = GdtEntry {
            limit_low: (tss_high_bytes & 0xFFFF) as u16,
            base_low: ((tss_high_bytes >> 16) & 0xFFFF) as u16,
            base_mid: 0,
            access: 0,
            flags_limit_high: 0,
            base_high: 0,
        };

        // Load the GDT
        let gdt_ptr = GdtPtr {
            limit: (core::mem::size_of_val(&GDT) - 1) as u16,
            base: GDT.as_ptr() as u64,
        };

        core::arch::asm!(
            "lgdt [{}]",
            in(reg) &gdt_ptr,
            options(nostack)
        );

        // Reload CS via far return
        core::arch::asm!(
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            cs = in(reg) KERNEL_CS as u64,
            tmp = lateout(reg) _,
            options(preserves_flags)
        );

        // Reload data segments
        core::arch::asm!(
            "mov ds, {0:x}",
            "mov es, {0:x}",
            "mov fs, {0:x}",
            "mov gs, {0:x}",
            "mov ss, {0:x}",
            in(reg) KERNEL_DS as u64,
            options(nostack, preserves_flags)
        );

        // Load TSS
        core::arch::asm!(
            "ltr {0:x}",
            in(reg) TSS_SELECTOR,
            options(nostack, preserves_flags)
        );
    }

    serial_println!("[gdt] GDT loaded: kernel CS=0x{:02x} DS=0x{:02x}, TSS at 0x{:02x}",
        KERNEL_CS, KERNEL_DS, TSS_SELECTOR);
}

/// Update TSS.rsp0 to the given stack top address.
/// Called on context switch to a ring 3 agent so the CPU knows
/// where to switch on interrupt/exception from user mode.
pub fn set_tss_rsp0(stack_top: u64) {
    // Safety: single-core, called during context switch with interrupts disabled.
    unsafe {
        TSS.rsp0 = stack_top;
    }
}
