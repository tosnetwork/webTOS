; TOS syscall_entry.asm — SYSCALL/SYSRET entry point for ring 3 agents
;
; On SYSCALL instruction (from ring 3):
;   RCX = saved user RIP (return address)
;   R11 = saved user RFLAGS
;   RAX = syscall number
;   RDI = arg0, RSI = arg1, RDX = arg2, R10 = arg3, R8 = arg4, R9 = arg5
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
global CURRENT_SYSCALL_FRAME
CURRENT_SYSCALL_FRAME: dq 0

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

    ; Save user caller-saved registers that the syscall/sysret ABI expects
    ; to survive across the kernel entry/exit path. Only RAX is special:
    ; it carries the syscall return value back to user mode.
    push rdi
    push rsi
    push rdx
    push r8
    push r9
    push r10

    ; Save callee-saved registers
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Preserve the user's SIMD/FPU state across the kernel call path.
    ; Linux user space assumes SYSCALL does not clobber XMM/FPU registers.
    sub rsp, 512
    fxsave [rsp]
    mov [rel CURRENT_SYSCALL_FRAME], rsp

    ; Remap: syscall ABI -> System V ABI.
    ; Rust handler signature is:
    ;   syscall_handler(num, a1, a2, a3, a4, a5, a6)
    ; so the 7th integer argument is passed on the stack.
    mov r11, r9     ; preserve Linux arg5 for the stacked 7th parameter
    mov r9, r8      ; arg4 -> r9
    mov r8, r10     ; arg3 -> r8
    mov rcx, rdx    ; arg2 -> rcx
    mov rdx, rsi    ; arg1 -> rdx
    mov rsi, rdi    ; arg0 -> rsi
    mov rdi, rax    ; num  -> rdi

    sub rsp, 16
    mov [rsp], r11
    call syscall_handler
    add rsp, 16

    mov qword [rel CURRENT_SYSCALL_FRAME], 0
    fxrstor [rsp]
    add rsp, 512

    ; Restore callee-saved registers (reverse order)
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

    ; Restore the user caller-saved register set expected by SYSRET.
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rsi
    pop rdi

    ; Restore user return context
    pop r11         ; user RFLAGS
    pop rcx         ; user RIP

    ; Restore user RSP and reset CURRENT_KERNEL_RSP back to the kernel
    ; stack top saved on entry.
    pop rdx         ; user RSP
    pop qword [rel CURRENT_KERNEL_RSP]
    mov rsp, rdx

    ; Return to ring 3
    o64 sysret
