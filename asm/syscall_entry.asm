; AOS syscall_entry.asm — SYSCALL/SYSRET entry point for ring 3 agents
;
; On SYSCALL instruction (from ring 3):
;   RCX = saved user RIP (return address)
;   R11 = saved user RFLAGS
;   RAX = syscall number
;   RDI = arg0, RSI = arg1, RDX = arg2, R10 = arg3, R8 = arg4
;
; SFMASK clears IF, so interrupts are disabled on entry.
; We must switch to the kernel stack before re-enabling them.

bits 64
section .text

global syscall_entry
extern syscall_handler

; ─── Per-agent kernel stack pointer (set by scheduler on context switch) ───
section .data
global CURRENT_KERNEL_RSP
CURRENT_KERNEL_RSP: dq 0

global SAVED_USER_RSP
SAVED_USER_RSP: dq 0

section .text

syscall_entry:
    ; Switch to kernel stack (interrupts disabled by SFMASK)
    mov [rel SAVED_USER_RSP], rsp
    mov rsp, [rel CURRENT_KERNEL_RSP]

    ; Save user return context
    push rcx        ; user RIP
    push r11        ; user RFLAGS

    ; Save callee-saved registers
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Remap: syscall ABI -> System V ABI
    ; Syscall: RAX=num, RDI=arg0, RSI=arg1, RDX=arg2, R10=arg3, R8=arg4
    ; SysV:    RDI=num, RSI=arg0, RDX=arg1, RCX=arg2, R8=arg3, R9=arg4
    mov r9, r8      ; arg4 -> r9
    mov r8, r10     ; arg3 -> r8
    mov rcx, rdx    ; arg2 -> rcx
    mov rdx, rsi    ; arg1 -> rdx
    mov rsi, rdi    ; arg0 -> rsi
    mov rdi, rax    ; num  -> rdi

    ; Re-enable interrupts
    sti

    call syscall_handler

    ; Disable interrupts for return
    cli

    ; Restore callee-saved registers (reverse order)
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    ; Restore user return context
    pop r11         ; user RFLAGS
    pop rcx         ; user RIP

    ; Switch to user stack
    mov rsp, [rel SAVED_USER_RSP]

    ; Return to ring 3
    o64 sysret
