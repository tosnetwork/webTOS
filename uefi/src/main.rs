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

/// Physical address where the BootInfo header is placed before jumping
/// to the kernel. Must be below the kernel load address and identity-mapped.
const BOOT_INFO_PHYS: u64 = 0x7000;

/// Byte offset within the 0x7000 page where the raw memory map is copied.
/// Provides space for the BootInfo header (56 bytes, padded to 64 for alignment).
const MMAP_DATA_OFFSET: u64 = 64;

/// Hand-off structure written at BOOT_INFO_PHYS before jumping to kernel_main.
///
/// Mirrors `paging::BootInfo` in the kernel — both must be kept in sync.
#[repr(C)]
struct BootInfo {
    /// Must equal UEFI_MAGIC so the kernel can validate the struct.
    magic: u32,
    /// Physical address of the raw EFI_MEMORY_DESCRIPTOR array.
    mmap_addr: u64,
    /// Total byte size of the memory map array.
    mmap_size: u32,
    /// Stride (in bytes) between consecutive descriptors.
    desc_size: u32,
    /// Number of descriptors in the map.
    desc_count: u32,
    // ── Framebuffer info (from UEFI GOP) ──
    /// Physical address of the GOP framebuffer (0 if unavailable).
    fb_addr: u64,
    /// Horizontal resolution in pixels.
    fb_width: u32,
    /// Vertical resolution in pixels.
    fb_height: u32,
    /// Pixels per scan line (stride).
    fb_stride: u32,
    /// Pixel format: 0=RGBX, 1=BGRX.
    fb_pixel_format: u32,
}

/// Kernel higher-half virtual address offset.
const KERNEL_VMA: u64 = 0xFFFF_FFFF_8000_0000;

/// Page table entry flags.
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_HUGE: u64 = 1 << 7;

/// Framebuffer info gathered from GOP before ExitBootServices.
struct FbInfo {
    addr: u64,
    width: u32,
    height: u32,
    stride: u32,
    pixel_format: u32,
}

/// Query UEFI GOP for framebuffer information.
///
/// Must be called BEFORE ExitBootServices. Returns None if GOP is
/// not available (e.g., headless/serial-only firmware).
fn query_gop(bs: &EfiBootServices) -> Option<FbInfo> {
    let mut gop_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = (bs.locate_protocol)(
        &EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID,
        core::ptr::null(),
        &mut gop_ptr,
    );
    if status != EFI_SUCCESS || gop_ptr.is_null() {
        return None;
    }

    let gop = unsafe { &*(gop_ptr as *const EfiGraphicsOutputProtocol) };
    if gop.mode.is_null() {
        return None;
    }

    let mode = unsafe { &*gop.mode };
    if mode.info.is_null() || mode.framebuffer_base == 0 {
        return None;
    }

    let info = unsafe { &*mode.info };

    // Only support RGB and BGR pixel formats (not BitMask or BltOnly)
    if info.pixel_format > 1 {
        serial::println("[UEFI] GOP: unsupported pixel format, skipping framebuffer");
        return None;
    }

    Some(FbInfo {
        addr: mode.framebuffer_base,
        width: info.horizontal_resolution,
        height: info.vertical_resolution,
        stride: info.pixels_per_scan_line,
        pixel_format: info.pixel_format,
    })
}

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

    // 4. Query GOP for framebuffer info (must be done before ExitBootServices)
    let fb_info = query_gop(bs);
    if let Some(ref fb) = fb_info {
        serial::print("[UEFI] GOP framebuffer: ");
        serial::print_hex(fb.addr);
        serial::print(" ");
        serial::print_hex(fb.width as u64);
        serial::print("x");
        serial::print_hex(fb.height as u64);
        serial::print(" stride=");
        serial::print_hex(fb.stride as u64);
        serial::print(" fmt=");
        serial::print_hex(fb.pixel_format as u64);
        serial::println("");
    } else {
        serial::println("[UEFI] GOP not available (serial-only mode)");
    }

    // 5. Set up dual page table mapping (same as boot.asm)
    let fb_addr = fb_info.as_ref().map(|f| f.addr).unwrap_or(0);
    setup_page_tables(pt_base, fb_addr);
    serial::println("[UEFI] Dual page tables configured (identity + higher-half)");

    // 6. Get memory map (required for ExitBootServices map_key)
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

    // 7. Exit boot services — after this, NO UEFI calls allowed
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

    serial::println("[UEFI] Boot services exited. Saving memory map...");

    // 8. Copy the UEFI memory map to a known physical address (0x7000 + 48)
    //    and write a BootInfo header at 0x7000 so the kernel can find it.
    let mmap_dest = (BOOT_INFO_PHYS + MMAP_DATA_OFFSET) as *mut u8;
    let max_mmap_bytes: usize = 0x1000 - MMAP_DATA_OFFSET as usize;
    let copy_size = if map_size <= max_mmap_bytes { map_size } else { max_mmap_bytes };
    let desc_count = copy_size / desc_size;

    unsafe {
        // Copy raw map bytes
        core::ptr::copy_nonoverlapping(map_buf.as_ptr(), mmap_dest, copy_size);

        // Write BootInfo header at 0x7000
        let boot_info_ptr = BOOT_INFO_PHYS as *mut BootInfo;
        let (fb_a, fb_w, fb_h, fb_s, fb_f) = match fb_info {
            Some(ref fb) => (fb.addr, fb.width, fb.height, fb.stride, fb.pixel_format),
            None => (0, 0, 0, 0, 0),
        };
        core::ptr::write_volatile(boot_info_ptr, BootInfo {
            magic:      UEFI_MAGIC,
            mmap_addr:  BOOT_INFO_PHYS + MMAP_DATA_OFFSET,
            mmap_size:  copy_size as u32,
            desc_size:  desc_size as u32,
            desc_count: desc_count as u32,
            fb_addr:    fb_a,
            fb_width:   fb_w,
            fb_height:  fb_h,
            fb_stride:  fb_s,
            fb_pixel_format: fb_f,
        });
    }

    serial::print("[UEFI] BootInfo written at 0x7000, mmap_size=");
    serial::print_hex(copy_size as u64);
    serial::print(", desc_count=");
    serial::print_hex(desc_count as u64);
    serial::println("");

    // 9. Load our page tables (replaces UEFI firmware's mapping)
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) pt_base,
            options(nostack, preserves_flags),
        );
    }

    serial::println("[UEFI] CR3 loaded. Jumping to kernel...");

    // 10. Jump to kernel_main at its higher-half virtual address.
    //    Calling convention (System V AMD64):
    //      RDI = first arg  = boot_magic  (UEFI_MAGIC, u32 in EDI)
    //      RSI = second arg = boot_info   (physical address of BootInfo = 0x7000)
    unsafe {
        core::arch::asm!(
            "mov rsp, {stack}",
            "mov rsi, {boot_info}",  // boot_info = physical address of BootInfo
            "mov edi, {magic:e}",    // boot_magic = UEFI_MAGIC (32-bit in EDI)
            "jmp {entry}",
            stack     = in(reg) kernel_info.stack_top,
            boot_info = in(reg) BOOT_INFO_PHYS,
            magic     = in(reg) UEFI_MAGIC as u64,
            entry     = in(reg) kernel_info.entry_point,
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
///   PDPT_HIGH[511] → 1GB huge page at 3GB (LAPIC high alias)
///
/// If a framebuffer address is provided, the corresponding 1GB PDPT entry
/// is added to identity-map the framebuffer region.
fn setup_page_tables(base: u64, fb_addr: u64) {
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

        // ── Framebuffer identity mapping ────────────────────────────
        // If the framebuffer is above the first 512MB, add a 1GB huge
        // page entry in the PDPT to cover it. Each PDPT entry covers 1GB.
        if fb_addr != 0 {
            let gb_index = (fb_addr >> 30) as usize; // which 1GB region
            if gb_index > 0 && gb_index < 512 && gb_index != 3 {
                // Don't overwrite PDPT[0] (identity) or PDPT[3] (LAPIC)
                let gb_base = (gb_index as u64) << 30;
                *pdpt.add(gb_index) = gb_base | PTE_PRESENT | PTE_WRITABLE | PTE_HUGE;
            }
        }

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
