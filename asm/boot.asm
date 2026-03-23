; AOS Stage-1 Boot Assembly
;
; Entry point: _start (called by Multiboot-compliant loader)
;
; On entry from Multiboot:
;   - CPU is in 32-bit protected mode
;   - Paging is disabled
;   - EAX = Multiboot magic (0x2BADB002)
;   - EBX = pointer to Multiboot info structure
;
; This code:
;   1. Sets up an initial stack
;   2. Saves Multiboot magic and info pointer
;   3. Zeroes BSS section (in 32-bit mode, before paging)
;   4. Checks for CPUID and long mode support
;   5. Sets up identity-mapped page tables (first 8 MB via 2 MB huge pages)
;   6. Enables PAE, long mode, and paging
;   7. Loads a 64-bit GDT and far-jumps to 64-bit code
;   8. In 64-bit mode: sets up segments, stack, calls kernel_main

; External symbols from linker script
extern __bss_start
extern __bss_end
extern __stack_top

; External Rust entry point
extern kernel_main

; ============================================================================
; 32-bit code
; ============================================================================
section .text
bits 32

global _start
_start:
    ; Disable interrupts
    cli

    ; Set up initial stack
    mov esp, __stack_top

    ; Save Multiboot magic and info pointer to callee-saved registers
    mov ebp, eax            ; Multiboot magic -> ebp
    mov ebx, ebx            ; Multiboot info already in ebx

    ; --- Zero BSS section (BEFORE paging, so page tables aren't affected) ---
    mov edi, __bss_start
    mov ecx, __bss_end
    sub ecx, edi
    shr ecx, 2              ; Divide by 4 (zero in dwords)
    xor eax, eax
    rep stosd

    ; --- Check CPUID availability ---
    call .check_cpuid

    ; --- Check long mode support ---
    call .check_long_mode

    ; --- Set up page tables ---
    call .setup_page_tables

    ; --- Enable PAE ---
    mov eax, cr4
    or eax, (1 << 5)       ; CR4.PAE (bit 5)
    mov cr4, eax

    ; --- Load PML4 into CR3 ---
    mov eax, pml4_table
    mov cr3, eax

    ; --- Enable long mode via IA32_EFER MSR ---
    mov ecx, 0xC0000080     ; IA32_EFER MSR
    rdmsr
    or eax, (1 << 8)        ; Set LME (Long Mode Enable) bit
    wrmsr

    ; --- Enable paging ---
    mov eax, cr0
    or eax, (1 << 31)       ; CR0.PG (bit 31)
    mov cr0, eax

    ; --- Load 64-bit GDT ---
    lgdt [gdt64.pointer]

    ; --- Far jump to 64-bit code segment ---
    jmp gdt64.code_segment:.long_mode_entry

; ---------------------------------------------------------------------------
; Check CPUID support by toggling the ID flag (bit 21) in EFLAGS
; ---------------------------------------------------------------------------
.check_cpuid:
    pushfd
    pop eax
    mov ecx, eax            ; Save original EFLAGS
    xor eax, (1 << 21)      ; Toggle ID bit
    push eax
    popfd
    pushfd
    pop eax
    push ecx                ; Restore original EFLAGS
    popfd
    cmp eax, ecx
    je .no_cpuid
    ret

.no_cpuid:
    mov al, 'C'
    jmp .error

; ---------------------------------------------------------------------------
; Check long mode support via CPUID extended functions
; ---------------------------------------------------------------------------
.check_long_mode:
    ; Check if extended CPUID functions are available
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode

    ; Check the long mode bit
    mov eax, 0x80000001
    cpuid
    test edx, (1 << 29)     ; LM bit in EDX
    jz .no_long_mode
    ret

.no_long_mode:
    mov al, 'L'
    jmp .error

; ---------------------------------------------------------------------------
; Set up identity-mapped page tables for the first 512 MB
;
; PML4[0] -> PDPT
; PDPT[0] -> PD
; PD[0..255] -> 0x000000..0x1FE00000 (256 x 2 MB huge pages = 512 MB)
;
; 512 MB covers kernel, ACPI tables (at ~128MB), and LAPIC MMIO.
; QEMU places ACPI tables near the top of RAM, so we need to map
; beyond the kernel's own memory footprint.
; ---------------------------------------------------------------------------
.setup_page_tables:
    ; Zero all page table memory first
    mov edi, pml4_table
    mov ecx, (4096 * 3) / 4  ; 3 tables, 4 bytes at a time
    xor eax, eax
    rep stosd

    ; PML4[0] -> PDPT (present | writable)
    mov eax, pdpt_table
    or eax, 0x3              ; Present | Writable
    mov [pml4_table], eax

    ; PDPT[0] -> PD (present | writable)
    mov eax, pd_table
    or eax, 0x3              ; Present | Writable
    mov [pdpt_table], eax

    ; Map 256 x 2MB pages (= 512 MB) for RAM + ACPI tables
    mov ecx, 0              ; counter
    mov eax, 0x83            ; Present | Writable | Huge, physical addr = 0
.map_page:
    mov [pd_table + ecx * 8], eax
    add eax, 0x200000        ; next 2MB
    inc ecx
    cmp ecx, 256
    jb .map_page

    ; Also map LAPIC MMIO at 0xFEE00000 (3GB + 0xEE00000)
    ; PDPT[3] -> pd_table2 for the 3-4GB region
    ; PD entry for 0xFEE00000: PD index = (0xFEE00000 >> 21) & 0x1FF = 0x1F7 = 503
    ; But we only have one PD (512 entries for PDPT[0]).
    ; For LAPIC, we need PDPT[3] which covers 3GB-4GB.
    ; Quick fix: map LAPIC as a single 2MB huge page at PDPT[3]->PD[0x77]
    ; Actually, simplest: create the mapping via the existing PD if we extend PDPT.
    ; For now, we'll map the LAPIC region by adding PDPT[3] inline.
    ; PDPT[3] needs its own PD. But we only allocated one PD.
    ; Simplest approach: use a 1GB huge page for PDPT[3] if supported.
    ; 1GB pages: PDPT entry with PS bit set → maps 1GB.
    ; PDPT[3] = 0xC0000000 | Present | Writable | Huge(PS)
    ; This maps 3GB-4GB as one huge page, covering LAPIC at 0xFEE00000.
    mov dword [pdpt_table + 3 * 8], 0xC0000083  ; 3GB, Present|Writable|Huge
    mov dword [pdpt_table + 3 * 8 + 4], 0       ; high 32 bits = 0

    ret

; ---------------------------------------------------------------------------
; Error handler: print character in AL to serial port 0x3F8, then halt
; ---------------------------------------------------------------------------
.error:
    ; Output error character to COM1 serial port
    mov dx, 0x3F8
    out dx, al
    mov al, 10              ; newline
    out dx, al
.halt:
    cli
    hlt
    jmp .halt

; ============================================================================
; 64-bit code
; ============================================================================
bits 64

.long_mode_entry:
    ; Set up segment registers for 64-bit mode
    mov ax, gdt64.data_segment
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Set up 64-bit stack pointer
    mov rsp, __stack_top

    ; Call kernel_main(multiboot_magic: u32, multiboot_info: u64)
    ; Restore saved Multiboot values from ebp and ebx
    xor rdi, rdi
    mov edi, ebp             ; multiboot_magic (zero-extended to 64-bit)
    xor rsi, rsi
    mov esi, ebx             ; multiboot_info (zero-extended to 64-bit)
    call kernel_main

    ; If kernel_main returns, halt
.halt64:
    cli
    hlt
    jmp .halt64

; ============================================================================
; 64-bit GDT
; ============================================================================
section .rodata
align 16

gdt64:
.null_segment: equ $ - gdt64
    dq 0x0000000000000000    ; Null descriptor

.code_segment: equ $ - gdt64
    dq 0x00AF9A000000FFFF    ; 64-bit code: Execute/Read, long mode

.data_segment: equ $ - gdt64
    dq 0x00CF92000000FFFF    ; 64-bit data: Read/Write

.pointer:
    dw $ - gdt64 - 1         ; GDT size (limit)
    dq gdt64                 ; GDT base address

; ============================================================================
; Page tables (in separate section, NOT in BSS, so BSS zeroing won't destroy them)
; ============================================================================
section .page_tables nobits alloc write
align 4096

pml4_table:
    resb 4096

pdpt_table:
    resb 4096

pd_table:
    resb 4096
