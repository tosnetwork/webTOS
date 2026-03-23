; ATOS Multiboot v1 Header
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
; Flags: ALIGN(0) | MEMINFO(1)
; NOTE: AOUT_KLUDGE (bit 16) is NOT set. We rely on ELF program headers
; for loading. The ELF32 headers have correct PhysAddr (LMA) values
; set via AT() directives in the linker script, so the Multiboot loader
; places each segment at the right physical address.
MULTIBOOT_FLAGS     equ (1 << 0) | (1 << 1)
MULTIBOOT_CHECKSUM  equ -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)

multiboot_header:
    dd MULTIBOOT_MAGIC
    dd MULTIBOOT_FLAGS
    dd MULTIBOOT_CHECKSUM
