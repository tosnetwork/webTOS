; AOS trap_entry.asm - interrupt/exception entry stubs
;
; Provides assembly entry points for CPU exceptions and hardware interrupts.
; Each stub pushes a uniform stack frame (vector number + error code) and
; jumps to `trap_common`, which saves all general-purpose registers and
; calls the Rust `trap_handler_common(frame: *const TrapFrame)`.
;
; The IDT can be configured to point to these stubs instead of (or in
; addition to) Rust x86-interrupt handlers. The advantage of the assembly
; stubs is full control over the register save/restore sequence and a
; uniform TrapFrame layout for all vectors.
;
; Stack frame layout (from top of stack when trap_handler_common is called):
;
;   [RSP+0]   r15           \
;   [RSP+8]   r14            |
;   [RSP+16]  r13            |
;   [RSP+24]  r12            |
;   [RSP+32]  r11            |  pushed by trap_common
;   [RSP+40]  r10            |
;   [RSP+48]  r9             |
;   [RSP+56]  r8             |
;   [RSP+64]  rbp            |
;   [RSP+72]  rdi            |
;   [RSP+80]  rsi            |
;   [RSP+88]  rdx            |
;   [RSP+96]  rcx            |
;   [RSP+104] rbx            |
;   [RSP+112] rax           /
;   [RSP+120] vector        -- pushed by stub
;   [RSP+128] error_code    -- pushed by stub (or CPU)
;   [RSP+136] rip           \
;   [RSP+144] cs             |  pushed by CPU
;   [RSP+152] rflags         |  (interrupt frame)
;   [RSP+160] rsp            |
;   [RSP+168] ss            /

bits 64
section .text

; ─── External Rust handler ───────────────────────────────────────────────────

extern trap_handler_common

; ─── Macros for stub generation ──────────────────────────────────────────────

; Macro for exceptions that do NOT push an error code.
; We push a dummy 0 to keep the stack frame uniform.
%macro TRAP_NO_ERR 1
global trap_stub_%1
trap_stub_%1:
    push qword 0        ; dummy error code (uniform frame layout)
    push qword %1       ; vector number
    jmp trap_common
%endmacro

; Macro for exceptions that DO push an error code.
; The CPU has already pushed the error code before we get control.
%macro TRAP_ERR 1
global trap_stub_%1
trap_stub_%1:
    ; error code is already on the stack (pushed by CPU)
    push qword %1       ; vector number
    jmp trap_common
%endmacro

; ─── Common handler: save registers and call Rust ────────────────────────────

trap_common:
    ; Save all general-purpose registers.
    ; Order must match the TrapFrame struct in trap.rs exactly.
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; Pass pointer to TrapFrame (current RSP) as first argument
    mov rdi, rsp
    call trap_handler_common

    ; Restore all general-purpose registers (reverse order)
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ; Remove vector number and error code from stack
    add rsp, 16

    ; Return from interrupt
    ; iretq pops: RIP, CS, RFLAGS, RSP, SS
    iretq

; ─── Exception stubs ────────────────────────────────────────────────────────

; Vector 0:  Division Error (#DE) -- no error code
TRAP_NO_ERR 0

; Vector 1:  Debug (#DB) -- no error code
TRAP_NO_ERR 1

; Vector 2:  Non-Maskable Interrupt (NMI) -- no error code
TRAP_NO_ERR 2

; Vector 3:  Breakpoint (#BP) -- no error code
TRAP_NO_ERR 3

; Vector 4:  Overflow (#OF) -- no error code
TRAP_NO_ERR 4

; Vector 5:  Bound Range Exceeded (#BR) -- no error code
TRAP_NO_ERR 5

; Vector 6:  Invalid Opcode (#UD) -- no error code
TRAP_NO_ERR 6

; Vector 7:  Device Not Available (#NM) -- no error code
TRAP_NO_ERR 7

; Vector 8:  Double Fault (#DF) -- error code (always 0)
TRAP_ERR 8

; Vector 10: Invalid TSS (#TS) -- error code
TRAP_ERR 10

; Vector 11: Segment Not Present (#NP) -- error code
TRAP_ERR 11

; Vector 12: Stack-Segment Fault (#SS) -- error code
TRAP_ERR 12

; Vector 13: General Protection Fault (#GP) -- error code
TRAP_ERR 13

; Vector 14: Page Fault (#PF) -- error code
TRAP_ERR 14

; Vector 16: x87 Floating-Point Exception (#MF) -- no error code
TRAP_NO_ERR 16

; Vector 17: Alignment Check (#AC) -- error code
TRAP_ERR 17

; Vector 18: Machine Check (#MC) -- no error code
TRAP_NO_ERR 18

; Vector 19: SIMD Floating-Point Exception (#XM/#XF) -- no error code
TRAP_NO_ERR 19

; ─── Hardware interrupt stubs (PIC IRQs remapped to vectors 32-47) ──────────

; Vector 32: Timer interrupt (IRQ0)
global trap_stub_32
trap_stub_32:
    push qword 0        ; dummy error code
    push qword 32       ; vector number
    jmp trap_common

; Vector 33: Keyboard interrupt (IRQ1)
global trap_stub_33
trap_stub_33:
    push qword 0
    push qword 33
    jmp trap_common

; Vector 34-39: IRQ2-IRQ7 (master PIC)
; Reserved for future use. Only timer (32) is active in Stage-1.

; ─── Stub address table ─────────────────────────────────────────────────────
; This table provides the addresses of all stubs so the IDT setup code
; in Rust can reference them without repeating extern declarations.

section .data
global trap_stub_table
trap_stub_table:
    dq trap_stub_0      ; vector 0:  #DE
    dq trap_stub_1      ; vector 1:  #DB
    dq trap_stub_2      ; vector 2:  NMI
    dq trap_stub_3      ; vector 3:  #BP
    dq trap_stub_4      ; vector 4:  #OF
    dq trap_stub_5      ; vector 5:  #BR
    dq trap_stub_6      ; vector 6:  #UD
    dq trap_stub_7      ; vector 7:  #NM
    dq trap_stub_8      ; vector 8:  #DF
    dq 0                ; vector 9:  (reserved, coprocessor segment overrun)
    dq trap_stub_10     ; vector 10: #TS
    dq trap_stub_11     ; vector 11: #NP
    dq trap_stub_12     ; vector 12: #SS
    dq trap_stub_13     ; vector 13: #GP
    dq trap_stub_14     ; vector 14: #PF
    dq 0                ; vector 15: (reserved)
    dq trap_stub_16     ; vector 16: #MF
    dq trap_stub_17     ; vector 17: #AC
    dq trap_stub_18     ; vector 18: #MC
    dq trap_stub_19     ; vector 19: #XM
    dq 0                ; vector 20
    dq 0                ; vector 21
    dq 0                ; vector 22
    dq 0                ; vector 23
    dq 0                ; vector 24
    dq 0                ; vector 25
    dq 0                ; vector 26
    dq 0                ; vector 27
    dq 0                ; vector 28
    dq 0                ; vector 29
    dq 0                ; vector 30
    dq 0                ; vector 31
    dq trap_stub_32     ; vector 32: timer (IRQ0)
    dq trap_stub_33     ; vector 33: keyboard (IRQ1)
