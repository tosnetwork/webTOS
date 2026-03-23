/*
 * AOS Linker Script — Higher-Half Kernel
 *
 * Multiboot v1 compatible layout for QEMU -kernel loading.
 * Kernel loaded at physical address 0x100000 (1 MB) by Multiboot.
 * Kernel linked at virtual address 0xFFFFFFFF80000000+ (higher half).
 *
 * Boot code (.boot section) stays at the physical address so it can
 * run before paging sets up the higher-half mapping. All other kernel
 * sections (.text, .rodata, .data, .bss) have VMA in the higher half
 * but LMA at the corresponding physical address (contiguous after boot).
 */

ENTRY(_start)

KERNEL_VMA = 0xFFFFFFFF80000000;

SECTIONS
{
    /* ── Phase 1: Boot code at PHYSICAL address ─────────────────────
     * These sections are linked at low addresses so 32-bit boot code
     * can reference labels before paging enables the higher-half mapping.
     */
    . = 0x100000;

    __kernel_phys_start = .;

    /* Multiboot header must appear within the first 8KB of the binary */
    .multiboot ALIGN(4) :
    {
        KEEP(*(.multiboot))
    }

    /* Boot code: 32-bit entry + 64-bit trampoline, at physical address */
    .boot ALIGN(4096) :
    {
        *(.boot)
    }

    /* Page tables: at physical address (used before paging is enabled) */
    .page_tables ALIGN(4096) :
    {
        *(.page_tables)
    }

    __boot_end = .;

    /* ── Phase 2: Kernel proper at VIRTUAL address ──────────────────
     * The linker position is advanced by KERNEL_VMA so all subsequent
     * section symbols resolve to higher-half virtual addresses
     * (0xFFFFFFFF80xxxxxx). Each section uses AT(ADDR - KERNEL_VMA)
     * to set its LMA (load memory address) back to the corresponding
     * physical address, so the Multiboot loader places the data
     * contiguously after the boot sections in physical memory.
     *
     * Result: code runs at high VMA, but is loaded at low LMA.
     */
    . += KERNEL_VMA;

    .text ALIGN(4096) : AT(ADDR(.text) - KERNEL_VMA)
    {
        *(.text .text.*)
    }

    .got ALIGN(8) : AT(ADDR(.got) - KERNEL_VMA)
    {
        *(.got .got.*)
    }

    .rodata ALIGN(4096) : AT(ADDR(.rodata) - KERNEL_VMA)
    {
        *(.rodata .rodata.*)
    }

    .data ALIGN(4096) : AT(ADDR(.data) - KERNEL_VMA)
    {
        *(.data .data.*)
    }

    .bss ALIGN(4096) : AT(ADDR(.bss) - KERNEL_VMA)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    . = ALIGN(4096);

    /* Guard page (unmapped gap) between BSS and stack */
    . += 4096;

    /* Kernel stack: 64 KB, grows downward */
    __stack_bottom = .;
    . += 65536;
    __stack_top = .;

    __kernel_end = .;

    /* ── Physical equivalents for 32-bit boot code ──────────────────
     * 32-bit code cannot use 64-bit addresses. These symbols provide
     * the physical addresses of high-VMA sections.
     */
    __bss_phys_start  = __bss_start - KERNEL_VMA;
    __bss_phys_end    = __bss_end   - KERNEL_VMA;
    __stack_phys_top  = __stack_top - KERNEL_VMA;
    __kernel_phys_end = __kernel_end - KERNEL_VMA;

    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
