; TOS switch.asm - context switch between agents
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
;   152     scratch / alignment
;   160     user_rip
;   168     user_rsp
;   176     user_rflags
;   184     fpu_pad
;   192     fxsave area (512 bytes, 16-byte aligned)
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
%define CTX_SCRATCH 152
%define CTX_USER_RIP 160
%define CTX_USER_RSP 168
%define CTX_USER_RFLAGS 176
%define CTX_FX      192

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

    ; Save x87/SSE state for the outgoing context.
    fxsave [rdi + CTX_FX]

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

    ; Restore x87/SSE state for the incoming context.
    fxrstor [rsi + CTX_FX]

    ; Restore rflags with IF (interrupt flag) CLEARED.
    ; Interrupts must stay disabled during the switch because RSP and RIP
    ; have not been restored yet. An interrupt here would use the wrong
    ; stack and corrupt state. The caller (schedule()) re-enables interrupts
    ; with STI after context_switch returns.
    mov rax, [rsi + CTX_RFLAGS]
    and rax, ~(1 << 9)       ; Clear IF bit (bit 9)
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

; ─── Ring 3 entry trampoline ────────────────────────────────────────────────
;
; Used for the FIRST context switch to a ring 3 agent. The agent's context
; has these callee-saved registers pre-loaded:
;   r12 = user entry point (RIP)
;   r13 = user stack top (RSP)
;   r14 = user code segment (USER_CS = 0x23)
;   r15 = user data segment (USER_DS = 0x1B)
;
; context_switch restores these registers and jumps here (rip = enter_user_mode).
; We build an iretq frame on the kernel stack and iretq to ring 3.

global enter_user_mode
global enter_user_clone_return
global resume_user_trap_return
global enter_kernel_mode

enter_user_mode:
    ; Build iretq frame:
    ;   [rsp+32] SS    = USER_DS
    ;   [rsp+24] RSP   = user stack
    ;   [rsp+16] RFLAGS = 0x202 (IF=1, reserved bit 1 always set)
    ;   [rsp+8]  CS    = USER_CS
    ;   [rsp+0]  RIP   = user entry point
    push r15            ; SS (USER_DS = 0x1B)
    push r13            ; RSP (user stack top)
    push qword 0x202    ; RFLAGS (IF=1)
    push r14            ; CS (USER_CS = 0x23)
    push r12            ; RIP (user entry point)
    iretq

; ─── Ring 3 clone-return trampoline ────────────────────────────────────────
;
; Used for clone/clone3 child threads created from a live syscall frame.
; Unlike enter_user_mode, this path restores the child's callee-saved
; registers from AgentContext and returns to the saved user RIP instead of
; restarting the ELF entry point.
;
; Conventions:
;   RSI = pointer to AgentContext (still live from context_switch)
;   CTX_RCX = saved user RIP
;   CTX_R11 = saved user RFLAGS
;   CTX_SCRATCH = child user RSP
;
; The remaining general-purpose fields carry the user's visible register
; state at the clone return point. Caller-saved registers are best-effort;
; callee-saved registers are restored exactly from the syscall snapshot.
enter_user_clone_return:
    mov rax, rsi

    ; Build iretq frame to return directly into the cloned thread's
    ; post-syscall user continuation.
    push qword 0x1B                 ; SS (USER_DS)
    push qword [rax + CTX_SCRATCH]  ; RSP (child user stack)
    push qword [rax + CTX_R11]      ; RFLAGS
    push qword 0x23                 ; CS (USER_CS)
    push qword [rax + CTX_RCX]      ; RIP (saved user return address)

    ; Restore user-visible registers from the syscall snapshot. The child must
    ; observe Linux syscall semantics: same register state as the parent at
    ; clone return, except RAX=0.
    mov rbx, [rax + CTX_RBX]
    mov rbp, [rax + CTX_RBP]
    mov rdi, [rax + CTX_RDI]
    mov rsi, [rax + CTX_RSI]
    mov r8,  [rax + CTX_R8]
    mov r9,  [rax + CTX_R9]
    mov r10, [rax + CTX_R10]
    mov r12, [rax + CTX_R12]
    mov r13, [rax + CTX_R13]
    mov r14, [rax + CTX_R14]
    mov r15, [rax + CTX_R15]
    mov rcx, [rax + CTX_RCX]
    mov rdx, [rax + CTX_RDX]
    mov r11, [rax + CTX_R11]
    mov rax, [rax + CTX_RAX]
    iretq

resume_user_trap_return:
    mov rax, rsi

    push qword 0x1B                      ; SS (USER_DS)
    push qword [rax + CTX_USER_RSP]      ; RSP
    push qword [rax + CTX_USER_RFLAGS]   ; RFLAGS
    push qword 0x23                      ; CS (USER_CS)
    push qword [rax + CTX_USER_RIP]      ; RIP

    mov rbx, [rax + CTX_RBX]
    mov rbp, [rax + CTX_RBP]
    mov rdi, [rax + CTX_RDI]
    mov rsi, [rax + CTX_RSI]
    mov r8,  [rax + CTX_R8]
    mov r9,  [rax + CTX_R9]
    mov r10, [rax + CTX_R10]
    mov r12, [rax + CTX_R12]
    mov r13, [rax + CTX_R13]
    mov r14, [rax + CTX_R14]
    mov r15, [rax + CTX_R15]
    mov rcx, [rax + CTX_RCX]
    mov rdx, [rax + CTX_RDX]
    mov r11, [rax + CTX_R11]
    mov rax, [rax + CTX_RAX]
    iretq

; ─── Kernel entry trampoline ───────────────────────────────────────────────
;
; Used for the FIRST context switch to a kernel-mode agent. `context_switch`
; jumps here with:
;   r12 = kernel entry point
;
; We synthesize a normal call-frame shape so Rust/C entry functions see the
; SysV-required stack alignment, then enable interrupts and jump to the
; agent entry point.

enter_kernel_mode:
    push qword 0        ; fake return address: gives normal SysV stack shape
    jmp r12
