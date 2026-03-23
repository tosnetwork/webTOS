; ATOS AP Bootstrap Trampoline
;
; Entered by Application Processors (APs) in 16-bit real mode after
; receiving a Startup IPI (SIPI) from the BSP. Transitions through
; protected mode -> long mode -> calls Rust ap_entry().
;
; This code is position-dependent: it must be loaded at physical 0x8000.
; The BSP copies it there before sending SIPI.

; BSP writes these values before SIPI:
; [0x8FF0] = CR3 value (PML4 physical address)
; [0x8FF8] = AP stack top (unique per AP)

; ap_entry is called via indirect call from address stored at [0x8FE8]
; (written by BSP). No `extern ap_entry` needed since we don't reference
; the symbol directly in assembly.

; --- 16-bit Real Mode Entry ---
section .rodata
bits 16

global ap_trampoline_start
ap_trampoline_start:
    cli
    xor ax, ax
    mov ds, ax


    ; Load 32-bit GDT
    lgdt [0x8000 + (ap_gdt32_ptr - ap_trampoline_start)]

    ; Enable protected mode
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    ; Far jump to 32-bit protected mode
    jmp dword 0x08:(0x8000 + (ap_pm32 - ap_trampoline_start))

; --- 32-bit Protected Mode ---
bits 32
ap_pm32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax


    ; Enable PAE (CR4 bit 5)
    mov eax, cr4
    or eax, (1 << 5)
    mov cr4, eax

    ; Load page table (PML4) from data area
    mov eax, [0x8FF0]    ; CR3 value written by BSP
    mov cr3, eax

    ; Enable long mode via IA32_EFER MSR
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8)     ; LME bit
    wrmsr

    ; Enable paging
    mov eax, cr0
    or eax, (1 << 31)
    mov cr0, eax

    ; Load 64-bit GDT
    lgdt [0x8000 + (ap_gdt64_ptr - ap_trampoline_start)]

    ; Far jump to 64-bit long mode
    jmp 0x08:(0x8000 + (ap_long_mode - ap_trampoline_start))

; --- 64-bit Long Mode ---
bits 64
ap_long_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax


    ; Load per-AP stack from data area
    mov rsp, [0x8FF8]    ; Stack top written by BSP

    ; Call Rust AP entry function via INDIRECT call.
    ; We cannot use `call ap_entry` because that generates a RIP-relative
    ; offset computed from the original .rodata position, not from 0x8000
    ; where this code actually runs. The BSP writes the absolute address
    ; of ap_entry to [0x8FE8] before sending SIPI.
    mov rax, [0x8FE8]   ; ap_entry absolute address (written by BSP)
    call rax

    ; Should not return
.halt:
    cli
    hlt
    jmp .halt

; --- 32-bit GDT (for PM transition) ---
align 16
ap_gdt32:
    dq 0x0000000000000000    ; Null
    dq 0x00CF9A000000FFFF    ; 32-bit code
    dq 0x00CF92000000FFFF    ; 32-bit data
ap_gdt32_end:

ap_gdt32_ptr:
    dw ap_gdt32_end - ap_gdt32 - 1
    dd 0x8000 + (ap_gdt32 - ap_trampoline_start)

; --- 64-bit GDT (for long mode transition) ---
align 16
ap_gdt64:
    dq 0x0000000000000000    ; Null
    dq 0x00AF9A000000FFFF    ; 64-bit code
    dq 0x00CF92000000FFFF    ; 64-bit data
ap_gdt64_end:

ap_gdt64_ptr:
    dw ap_gdt64_end - ap_gdt64 - 1
    dd 0x8000 + (ap_gdt64 - ap_trampoline_start)

global ap_trampoline_end
ap_trampoline_end:
