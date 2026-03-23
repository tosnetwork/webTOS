//! AOS UEFI Boot Loader
//!
//! Minimal UEFI application that loads the AOS kernel, sets up
//! higher-half page tables, exits UEFI boot services, and jumps
//! to kernel_main. Follows Linux's EFI stub approach.
//!
//! Build: cd uefi && cargo build --release
//! Run:   make uefi-run

#![no_std]
#![no_main]

mod serial;
mod uefi_types;
mod elf;

use uefi_types::*;

/// Embed the AOS kernel ELF binary at compile time.
/// The kernel must be built first (`cargo build --release` in root).
static KERNEL_ELF: &[u8] = include_bytes!("../../target/x86_64-unknown-none/release/aos");

/// Magic number passed to kernel_main to indicate UEFI boot.
const UEFI_MAGIC: u32 = 0xAE51_0EF1;

/// Kernel higher-half virtual address offset.
const KERNEL_VMA: u64 = 0xFFFF_FFFF_8000_0000;

/// Page table entry flags.
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_HUGE: u64 = 1 << 7;

/// UEFI application entry point.
///
/// Called by UEFI firmware with the MS x64 ABI (efiapi):
///   RCX = ImageHandle, RDX = *SystemTable
#[no_mangle]
pub extern "efiapi" fn efi_main(
    image_handle: EfiHandle,
    system_table: *mut EfiSystemTable,
) -> EfiStatus {
    // 1. Initialize serial for debug output
    serial::init();
    serial::println("[UEFI] AOS UEFI boot loader starting");

    let bs = unsafe { &*(*system_table).boot_services };

    // 2. Load kernel ELF segments to physical memory
    serial::println("[UEFI] Loading kernel ELF...");
    let kernel_info = elf::load_kernel(KERNEL_ELF);

    // 3. Allocate page table frames (4 pages for PML4, PDPT, PD, PDPT_HIGH)
    let mut pt_base: u64 = 0;
    let status = (bs.allocate_pages)(ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, 4, &mut pt_base);
    if status != EFI_SUCCESS {
        serial::println("[UEFI] ERROR: Failed to allocate page table frames");
        loop { unsafe { core::arch::asm!("hlt"); } }
    }

    serial::print("[UEFI] Page tables allocated at: ");
    serial::print_hex(pt_base);
    serial::println("");

    // 4. Set up dual page table mapping (same as boot.asm)
    setup_page_tables(pt_base);
    serial::println("[UEFI] Dual page tables configured (identity + higher-half)");

    // 5. Get memory map (required for ExitBootServices map_key)
    let mut map_buf = [0u8; 16384];
    let mut map_size: usize = map_buf.len();
    let mut map_key: usize = 0;
    let mut desc_size: usize = 0;
    let mut desc_version: u32 = 0;

    let status = (bs.get_memory_map)(
        &mut map_size,
        map_buf.as_mut_ptr(),
        &mut map_key,
        &mut desc_size,
        &mut desc_version,
    );
    if status != EFI_SUCCESS {
        serial::println("[UEFI] ERROR: GetMemoryMap failed");
        loop { unsafe { core::arch::asm!("hlt"); } }
    }

    serial::print("[UEFI] Memory map: ");
    serial::print_hex(map_size as u64);
    serial::print(" bytes, desc_size=");
    serial::print_hex(desc_size as u64);
    serial::println("");

    // 6. Exit boot services — after this, NO UEFI calls allowed
    serial::println("[UEFI] Calling ExitBootServices...");
    let status = (bs.exit_boot_services)(image_handle, map_key);
    if status != EFI_SUCCESS {
        // Retry: GetMemoryMap again (map_key may be stale)
        map_size = map_buf.len();
        let _ = (bs.get_memory_map)(
            &mut map_size,
            map_buf.as_mut_ptr(),
            &mut map_key,
            &mut desc_size,
            &mut desc_version,
        );
        let status2 = (bs.exit_boot_services)(image_handle, map_key);
        if status2 != EFI_SUCCESS {
            serial::println("[UEFI] ERROR: ExitBootServices failed on retry");
            loop { unsafe { core::arch::asm!("hlt"); } }
        }
    }

    // ═══ POST EXIT BOOT SERVICES — firmware is gone ═══

    serial::println("[UEFI] Boot services exited. Loading CR3...");

    // 7. Load our page tables (replaces UEFI firmware's mapping)
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) pt_base,
            options(nostack, preserves_flags),
        );
    }

    serial::println("[UEFI] CR3 loaded. Jumping to kernel...");

    // 8. Jump to kernel_main at its higher-half virtual address
    //    Set RSP to kernel stack (higher-half VMA)
    //    Pass UEFI_MAGIC in RDI (first arg) and 0 in RSI (second arg)
    unsafe {
        core::arch::asm!(
            "mov rsp, {stack}",
            "xor rsi, rsi",          // boot_info = 0 (no memory map passed yet)
            "mov edi, {magic:e}",    // boot_magic = UEFI_MAGIC (32-bit in EDI)
            "jmp {entry}",
            stack = in(reg) kernel_info.stack_top,
            magic = in(reg) UEFI_MAGIC as u64,
            entry = in(reg) kernel_info.entry_point,
            options(noreturn),
        );
    }
}

/// Set up dual page tables: identity mapping + higher-half kernel mapping.
///
/// Replicates the boot.asm page table layout:
///   PML4[0]   → PDPT → PD (256 × 2MB huge pages = 512 MB identity)
///   PDPT[3]   → 1GB huge page at 3GB (LAPIC at 0xFEE00000)
///   PML4[511] → PDPT_HIGH → PD (shared, higher-half kernel)
///   PDPT_HIGH[511] → 1GB huge page at 3GB (LAPIC at 0xFFFFFFFFC0000000)
fn setup_page_tables(base: u64) {
    let pml4 = base as *mut u64;
    let pdpt = (base + 0x1000) as *mut u64;
    let pd = (base + 0x2000) as *mut u64;
    let pdpt_high = (base + 0x3000) as *mut u64;

    unsafe {
        // Zero all 4 tables (16 KB)
        core::ptr::write_bytes(base as *mut u8, 0, 4 * 4096);

        // ── Identity mapping (PML4[0]) ──────────────────────────────
        // PML4[0] → PDPT
        *pml4 = (base + 0x1000) | PTE_PRESENT | PTE_WRITABLE;

        // PDPT[0] → PD
        *pdpt = (base + 0x2000) | PTE_PRESENT | PTE_WRITABLE;

        // PD[0..255] → 256 × 2MB huge pages (512 MB identity map)
        for i in 0..256u64 {
            *pd.add(i as usize) = (i * 0x200000) | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE;
        }

        // PDPT[3] → 1GB huge page at 3GB (LAPIC MMIO at 0xFEE00000)
        *pdpt.add(3) = 0xC000_0000 | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE;

        // ── Higher-half mapping (PML4[511]) ─────────────────────────
        // PML4[511] → PDPT_HIGH
        *pml4.add(511) = (base + 0x3000) | PTE_PRESENT | PTE_WRITABLE;

        // PDPT_HIGH[510] → PD (SAME PD as identity — shared!)
        // Virtual 0xFFFFFFFF80000000 decodes as PML4[511], PDPT[510]
        *pdpt_high.add(510) = (base + 0x2000) | PTE_PRESENT | PTE_WRITABLE;

        // PDPT_HIGH[511] → 1GB huge page at 3GB (LAPIC high alias)
        *pdpt_high.add(511) = 0xC000_0000 | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE;
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    serial::print("[UEFI] PANIC: ");
    if let Some(location) = info.location() {
        serial::print(location.file());
        serial::print(":");
        // Can't easily format line number without alloc, just print marker
        serial::println(" (see source)");
    } else {
        serial::println("unknown location");
    }
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}
