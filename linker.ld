/*
 * AOS Stage-1 Linker Script
 *
 * Multiboot v1 compatible layout for QEMU -kernel loading.
 * Kernel loaded at physical address 0x100000 (1 MB).
 * Identity-mapped in Stage-1 (no higher-half offset).
 */

ENTRY(_start)

SECTIONS
{
    . = 0x100000;

    __kernel_start = .;

    /* Multiboot header must appear within the first 8KB of the binary */
    .multiboot ALIGN(4) :
    {
        KEEP(*(.multiboot))
    }

    .text ALIGN(4096) :
    {
        *(.text .text.*)
    }

    .rodata ALIGN(4096) :
    {
        *(.rodata .rodata.*)
    }

    .data ALIGN(4096) :
    {
        *(.data .data.*)
    }

    .bss ALIGN(4096) :
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Page tables: placed before the stack so stack overflow
       can't corrupt them. */
    .page_tables ALIGN(4096) :
    {
        *(.page_tables)
    }

    . = ALIGN(4096);

    /* Guard page (unmapped gap) between page tables and stack */
    . += 4096;

    /* Kernel stack: 64 KB, grows downward */
    __stack_bottom = .;
    . += 65536;
    __stack_top = .;

    __kernel_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
