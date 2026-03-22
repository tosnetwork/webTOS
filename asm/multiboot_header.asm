; AOS Multiboot v1 Header
;
; Uses the AOUT_KLUDGE (flag bit 16) to provide explicit load addresses,
; bypassing ELF program header parsing. This is necessary because the kernel
; is compiled as ELF64 and converted to ELF32 via objcopy.
;
; The .multiboot section is placed first by the linker script at 0x100000.

section .multiboot
align 4

extern _start
extern __kernel_end

MULTIBOOT_MAGIC     equ 0x1BADB002
; Flags: ALIGN(0) | MEMINFO(1) | AOUT_KLUDGE(16)
MULTIBOOT_FLAGS     equ (1 << 0) | (1 << 1) | (1 << 16)
MULTIBOOT_CHECKSUM  equ -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)

multiboot_header:
    dd MULTIBOOT_MAGIC
    dd MULTIBOOT_FLAGS
    dd MULTIBOOT_CHECKSUM
    ; AOUT_KLUDGE fields (required when bit 16 set):
    dd multiboot_header    ; header_addr: where this header is in memory
    dd 0x100000            ; load_addr: start loading here
    dd 0                   ; load_end_addr: 0 = load entire file
    dd 0                   ; bss_end_addr: 0 = skip BSS zeroing (we do it in boot.asm)
    dd _start              ; entry_addr: jump here after loading
