; AOS switch.asm - context switch between agents
;
; Saves the callee-saved register state of the old agent and restores
; the register state of the new agent. This is the core primitive that
; enables the scheduler to switch execution between agents.
;
; void context_switch(old: *mut AgentContext, new: *const AgentContext)
;
; The AgentContext struct layout (from agent.rs) is:
;
;   Offset  Field
;   ------  -----
;     0     rsp
;     8     rip
;    16     rax
;    24     rbx
;    32     rcx
;    40     rdx
;    48     rsi
;    56     rdi
;    64     rbp
;    72     r8
;    80     r9
;    88     r10
;    96     r11
;   104     r12
;   112     r13
;   120     r14
;   128     r15
;   136     rflags
;   144     cr3
;
; For a cooperative context switch (called from Rust code), we only need
; to save/restore callee-saved registers (rbx, rbp, r12-r15, rsp) plus
; rip and rflags. The caller-saved registers (rax, rcx, rdx, rsi, rdi,
; r8-r11) are already saved by the calling convention.
;
; For a preemptive switch (from a timer interrupt), the full register set
; is saved by the trap entry stub before the scheduler is called.

bits 64
section .text
global context_switch

; ─── AgentContext field offsets ───────────────────────────────────────────────
%define CTX_RSP     0
%define CTX_RIP     8
%define CTX_RAX     16
%define CTX_RBX     24
%define CTX_RCX     32
%define CTX_RDX     40
%define CTX_RSI     48
%define CTX_RDI     56
%define CTX_RBP     64
%define CTX_R8      72
%define CTX_R9      80
%define CTX_R10     88
%define CTX_R11     96
%define CTX_R12     104
%define CTX_R13     112
%define CTX_R14     120
%define CTX_R15     128
%define CTX_RFLAGS  136
%define CTX_CR3     144

context_switch:
    ; Arguments (System V AMD64):
    ;   RDI = pointer to old AgentContext (save current state here)
    ;   RSI = pointer to new AgentContext (restore state from here)

    ; ── Save old context ──

    ; Save callee-saved general-purpose registers
    mov [rdi + CTX_R15], r15
    mov [rdi + CTX_R14], r14
    mov [rdi + CTX_R13], r13
    mov [rdi + CTX_R12], r12
    mov [rdi + CTX_RBX], rbx
    mov [rdi + CTX_RBP], rbp
    mov [rdi + CTX_RSP], rsp

    ; Save the return address as rip. When this context is restored,
    ; execution will resume at .switch_return.
    lea rax, [rel .switch_return]
    mov [rdi + CTX_RIP], rax

    ; Save rflags
    pushfq
    pop rax
    mov [rdi + CTX_RFLAGS], rax

    ; Save cr3 (page table root)
    mov rax, cr3
    mov [rdi + CTX_CR3], rax

    ; ── Restore new context ──

    ; Restore callee-saved general-purpose registers
    mov r15, [rsi + CTX_R15]
    mov r14, [rsi + CTX_R14]
    mov r13, [rsi + CTX_R13]
    mov r12, [rsi + CTX_R12]
    mov rbx, [rsi + CTX_RBX]
    mov rbp, [rsi + CTX_RBP]

    ; Restore cr3 (only if different, to avoid unnecessary TLB flush)
    mov rax, [rsi + CTX_CR3]
    mov rcx, cr3
    cmp rax, rcx
    je .skip_cr3
    mov cr3, rax
.skip_cr3:

    ; Restore rflags
    mov rax, [rsi + CTX_RFLAGS]
    push rax
    popfq

    ; Restore stack pointer
    mov rsp, [rsi + CTX_RSP]

    ; Jump to the saved rip of the new context.
    ; For a context that was previously saved by context_switch, this
    ; will be .switch_return, and execution will resume as if the
    ; previous call to context_switch returned normally.
    ;
    ; For a brand-new agent that has never run, rip will be the agent's
    ; entry point function address.
    jmp [rsi + CTX_RIP]

.switch_return:
    ; We arrive here when another agent switches back to us.
    ; The original call to context_switch appears to return normally.
    ret
