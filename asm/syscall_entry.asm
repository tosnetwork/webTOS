; ATOS syscall_entry.asm — SYSCALL/SYSRET entry point for ring 3 agents
;
; On SYSCALL instruction (from ring 3):
;   RCX = saved user RIP (return address)
;   R11 = saved user RFLAGS
;   RAX = syscall number
;   RDI = arg0, RSI = arg1, RDX = arg2, R10 = arg3, R8 = arg4
;
; SFMASK clears IF, so interrupts are disabled on entry.
;
; Stage-1 code assumes syscalls are non-preemptive on a single core, so we
; keep interrupts disabled for the entire syscall and restore the kernel stack
; top before returning to user mode.

bits 64
section .text

global syscall_entry
extern syscall_handler

; ─── Per-agent kernel stack pointer (set by scheduler on context switch) ───
section .data
global CURRENT_KERNEL_RSP
CURRENT_KERNEL_RSP: dq 0

section .text

syscall_entry:
    ; Swap to the per-agent kernel stack.
    ;   RSP = kernel stack top
    ;   CURRENT_KERNEL_RSP = user RSP
    xchg rsp, [rel CURRENT_KERNEL_RSP]

    ; Save the kernel stack top and user RSP on the kernel stack.
    ; Keeping the top on-stack lets us restore CURRENT_KERNEL_RSP before
    ; SYSRET, so repeated syscalls reuse the same stack top instead of
    ; walking down the stack forever.
    push rsp
    push qword [rel CURRENT_KERNEL_RSP]

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
    mov r9, r8      ; arg4 -> r9
    mov r8, r10     ; arg3 -> r8
    mov rcx, rdx    ; arg2 -> rcx
    mov rdx, rsi    ; arg1 -> rdx
    mov rsi, rdi    ; arg0 -> rsi
    mov rdi, rax    ; num  -> rdi

    call syscall_handler
    mov r10, rax    ; preserve syscall return value across stack restoration

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

    ; Restore user RSP and reset CURRENT_KERNEL_RSP back to the kernel
    ; stack top saved on entry.
    pop rax         ; user RSP
    pop qword [rel CURRENT_KERNEL_RSP]
    mov rsp, rax
    mov rax, r10

    ; Return to ring 3
    o64 sysret
