; ATOS Boot Assembly — Higher-Half Kernel
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
;   1. Sets up an initial stack (at physical address, pre-paging)
;   2. Saves Multiboot magic and info pointer
;   3. Zeroes BSS section (using physical addresses, before paging)
;   4. Checks for CPUID and long mode support
;   5. Sets up page tables with DUAL mapping:
;      - Identity map: PML4[0] → 0-512MB (for MMIO, ACPI, AP trampoline)
;      - Higher-half:  PML4[511] → same physical memory at 0xFFFFFFFF80000000+
;   6. Enables PAE, long mode, and paging
;   7. Loads a 64-bit GDT and far-jumps to 64-bit code
;   8. In 64-bit mode: switches to high virtual stack, calls kernel_main
;      at its higher-half virtual address
;
; The .boot section is linked at the PHYSICAL address (0x100000+) so
; labels resolve correctly before the higher-half mapping is active.
; The rest of the kernel (.text, .rodata, .data, .bss) is linked at
; KERNEL_VMA (0xFFFFFFFF80000000+).

; External symbols from linker script (physical addresses for 32-bit use)
extern __bss_phys_start
extern __bss_phys_end
extern __stack_phys_top

; External symbols (virtual addresses — valid after paging enabled)
extern __stack_top

; External Rust entry point (at higher-half virtual address)
extern kernel_main

; ============================================================================
; 32-bit boot code — linked at physical address
; ============================================================================
section .boot
bits 32

global _start
_start:
    ; Disable interrupts
    cli

    ; Set up initial stack at PHYSICAL address (paging not yet enabled)
    mov esp, __stack_phys_top

    ; Save Multiboot magic and info pointer to callee-saved registers
    mov ebp, eax            ; Multiboot magic -> ebp
    ; ebx already holds multiboot info pointer

    ; --- Zero BSS section (using PHYSICAL addresses, before paging) ---
    ; BSS is linked at high VMA but loaded at low LMA. We zero the
    ; physical copy before paging maps it to the high virtual address.
    mov edi, __bss_phys_start
    mov ecx, __bss_phys_end
    sub ecx, edi
    shr ecx, 2              ; Divide by 4 (zero in dwords)
    xor eax, eax
    rep stosd

    ; --- Check CPUID availability ---
    call .check_cpuid

    ; --- Check long mode support ---
    call .check_long_mode

    ; --- Set up page tables (identity + higher-half) ---
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

    ; --- Load 64-bit GDT (in .boot section, physical address) ---
    lgdt [gdt64_boot.pointer]

    ; --- Far jump to 64-bit code segment ---
    ; Still running at identity-mapped address; the jump target
    ; is in this same .boot section (physical address).
    jmp gdt64_boot.code_segment:.long_mode_entry

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
; Set up page tables with DUAL mapping (Linux-style higher-half kernel)
;
; Identity mapping (preserved for MMIO, ACPI, AP trampoline):
;   PML4[0]   → pdpt_table
;   PDPT[0]   → pd_table     (256 × 2MB huge pages = 512 MB)
;   PDPT[3]   → 1GB huge page at 3GB (LAPIC at 0xFEE00000)
;
; Higher-half mapping (kernel code/data/BSS runs here):
;   PML4[511] → pdpt_high_table
;   PDPT[510] → pd_table     (SAME PD — shared with identity!)
;   PDPT[511] → 1GB huge page at 3GB (LAPIC at 0xFFFFFFFFC0000000)
;
; The PD is shared: both PML4[0] and PML4[511] paths reach the same
; physical memory through the same PD entries. This means:
;   Physical 0x100000 == Virtual 0x100000 (identity)
;   Physical 0x100000 == Virtual 0xFFFFFFFF80100000 (higher-half)
; ---------------------------------------------------------------------------
.setup_page_tables:
    ; Zero all page table memory first (4 tables × 4096 bytes)
    mov edi, pml4_table
    mov ecx, (4096 * 4) / 4  ; 4 tables, 4 bytes at a time
    xor eax, eax
    rep stosd

    ; ── Identity mapping (PML4[0]) ──────────────────────────────────

    ; PML4[0] → PDPT (present | writable)
    mov eax, pdpt_table
    or eax, 0x3              ; Present | Writable
    mov [pml4_table], eax

    ; PDPT[0] → PD (present | writable)
    mov eax, pd_table
    or eax, 0x3              ; Present | Writable
    mov [pdpt_table], eax

    ; Map 256 × 2MB pages (= 512 MB) for RAM + ACPI tables
    mov ecx, 0              ; counter
    mov eax, 0x83            ; Present | Writable | Huge, physical addr = 0
.map_page:
    mov [pd_table + ecx * 8], eax
    add eax, 0x200000        ; next 2MB
    inc ecx
    cmp ecx, 256
    jb .map_page

    ; PDPT[3] → 1GB huge page at 3GB (LAPIC at 0xFEE00000)
    mov dword [pdpt_table + 3 * 8], 0xC0000083  ; 3GB, Present|Writable|Huge
    mov dword [pdpt_table + 3 * 8 + 4], 0       ; high 32 bits = 0

    ; ── Higher-half mapping (PML4[511]) ─────────────────────────────

    ; PML4[511] → pdpt_high_table
    mov eax, pdpt_high_table
    or eax, 0x3              ; Present | Writable
    mov [pml4_table + 511 * 8], eax

    ; pdpt_high_table[510] → pd_table (SAME PD as identity — shared!)
    ; Virtual 0xFFFFFFFF80000000 decodes as: PML4[511], PDPT[510], PD[0+]
    mov eax, pd_table
    or eax, 0x3              ; Present | Writable
    mov [pdpt_high_table + 510 * 8], eax

    ; pdpt_high_table[511] → 1GB huge page at 3GB
    ; Maps LAPIC at virtual 0xFFFFFFFFC0000000 (high alias)
    mov dword [pdpt_high_table + 511 * 8], 0xC0000083
    mov dword [pdpt_high_table + 511 * 8 + 4], 0

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
; 64-bit code — still in .boot section (physical address)
;
; After far jump from 32-bit mode, we arrive here with both identity
; and higher-half mappings active. We set up segments, switch to the
; higher-half stack, and jump to kernel_main at its high virtual address.
; ============================================================================
bits 64

.long_mode_entry:
    ; Set up segment registers for 64-bit mode
    mov ax, gdt64_boot.data_segment
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; Switch to higher-half virtual stack
    ; __stack_top is linked at 0xFFFFFFFF80xxxxxx (high VMA)
    mov rsp, __stack_top

    ; Call kernel_main(multiboot_magic: u32, multiboot_info: u64)
    ; Restore saved Multiboot values from ebp and ebx
    xor rdi, rdi
    mov edi, ebp             ; multiboot_magic (zero-extended to 64-bit)
    xor rsi, rsi
    mov esi, ebx             ; multiboot_info (zero-extended to 64-bit)

    ; Jump to kernel_main at its HIGHER-HALF virtual address.
    ; This is the moment we leave the identity-mapped world — from here
    ; on, all kernel code runs at 0xFFFFFFFF80000000+.
    mov rax, kernel_main
    call rax

    ; If kernel_main returns, halt
.halt64:
    cli
    hlt
    jmp .halt64

; ============================================================================
; Boot GDT — in .boot section (accessible at physical address)
;
; This GDT is used only during the boot transition. The Rust kernel
; replaces it with its own GDT in arch::x86_64::gdt::init().
; It must be in .boot (not .rodata) because .rodata is linked at the
; higher-half VMA which isn't accessible until after the far jump.
; ============================================================================
align 16

gdt64_boot:
.null_segment: equ $ - gdt64_boot
    dq 0x0000000000000000    ; Null descriptor

.code_segment: equ $ - gdt64_boot
    dq 0x00AF9A000000FFFF    ; 64-bit code: Execute/Read, long mode

.data_segment: equ $ - gdt64_boot
    dq 0x00CF92000000FFFF    ; 64-bit data: Read/Write

.pointer:
    dw $ - gdt64_boot - 1    ; GDT size (limit)
    dq gdt64_boot            ; GDT base address (physical, in .boot)

; ============================================================================
; Page tables (in separate section, NOT in BSS, so BSS zeroing won't
; destroy them). 4 tables: PML4, PDPT (identity), PD, PDPT (higher-half)
; ============================================================================
section .page_tables nobits alloc write
align 4096

pml4_table:
    resb 4096

pdpt_table:
    resb 4096

pd_table:
    resb 4096

pdpt_high_table:
    resb 4096
