; AOS syscall_entry.asm - syscall/sysret entry point
;
; This is the assembly entry point for the x86_64 `syscall` instruction.
; It is used when agents run in ring 3 (user mode). In Stage-1, agents
; run in kernel mode and call syscall_handler() directly via the Rust
; wrapper; this assembly is provided for future ring-3 support.
;
; The LSTAR MSR must be configured to point to `syscall_entry` during
; arch init (see syscall.rs::init_syscall_msrs).
;
; Register convention on `syscall` instruction entry:
;   RCX = saved RIP (return address, set by hardware)
;   R11 = saved RFLAGS (set by hardware)
;   RAX = syscall number
;   RDI = arg0
;   RSI = arg1
;   RDX = arg2
;   R10 = arg3 (not RCX, which is clobbered by hardware)
;   R8  = arg4
;
; We must:
;   1. Switch to kernel stack (when coming from ring 3)
;   2. Save caller-preserved registers
;   3. Remap args to System V calling convention
;   4. Call syscall_handler(num, arg0, arg1, arg2, arg3, arg4)
;   5. Restore registers
;   6. Return via sysret
;
; System V AMD64 calling convention parameter registers:
;   RDI, RSI, RDX, RCX, R8, R9

bits 64
section .text

global syscall_entry
extern syscall_handler

syscall_entry:
    ; ── Stage-2+ path: switch to kernel stack ──
    ; When agents run in ring 3, we must switch to the per-agent kernel
    ; stack. The kernel stack pointer is stored in the TSS RSP0 field,
    ; which the CPU does NOT automatically load on syscall (only on
    ; interrupts). We must do it manually.
    ;
    ; Save user RSP and load kernel RSP from a known location.
    ; For Stage-1 (ring 0 agents), we skip this -- agents already use
    ; kernel stacks.

    ; For now, assume we are on a valid kernel stack (Stage-1).
    ; TODO: when ring-3 agents are added:
    ;   swapgs                      ; swap GS base to kernel percpu
    ;   mov [gs:USER_RSP], rsp      ; save user RSP
    ;   mov rsp, [gs:KERNEL_RSP]    ; load kernel RSP

    ; ── Save callee-saved registers and syscall context ──
    ; RCX and R11 are clobbered by the syscall instruction itself.
    ; We save them so sysret can restore RIP and RFLAGS.
    push rcx            ; saved RIP (for sysret)
    push r11            ; saved RFLAGS (for sysret)

    ; Save callee-saved registers per System V ABI.
    ; The called function (syscall_handler) will preserve these, but
    ; we save them here so the full user context is recoverable.
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15

    ; ── Remap registers for System V calling convention ──
    ; Current state:
    ;   RAX = syscall number
    ;   RDI = arg0, RSI = arg1, RDX = arg2, R10 = arg3, R8 = arg4
    ;
    ; Target (System V):
    ;   RDI = num, RSI = arg0, RDX = arg1, RCX = arg2, R8 = arg3, R9 = arg4
    ;
    ; We must be careful about the order of moves to avoid clobbering.
    ; R10 -> R8 and R8 -> R9 must happen before we overwrite R8.

    mov r9, r8          ; arg4 -> r9  (6th param)
    mov r8, r10         ; arg3 -> r8  (5th param)
    mov rcx, rdx        ; arg2 -> rcx (4th param)
    mov rdx, rsi        ; arg1 -> rdx (3rd param)
    mov rsi, rdi        ; arg0 -> rsi (2nd param)
    mov rdi, rax        ; num  -> rdi (1st param)

    ; ── Call the Rust syscall dispatcher ──
    call syscall_handler

    ; Return value is in RAX -- this becomes the syscall return value.

    ; ── Restore callee-saved registers ──
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp

    ; Restore sysret context
    pop r11             ; RFLAGS for sysret
    pop rcx             ; RIP for sysret

    ; ── Return to user mode ──
    ; sysret loads:
    ;   RIP <- RCX
    ;   RFLAGS <- R11 (masked by SFMASK on entry)
    ;   CS <- STAR[63:48] + 16 (user code segment)
    ;   SS <- STAR[63:48] + 8  (user data segment)
    ;
    ; The `o64` prefix ensures 64-bit operand size for sysret,
    ; which is required in long mode to return to 64-bit user code.

    ; TODO: when ring-3 agents are added:
    ;   mov rsp, [gs:USER_RSP]  ; restore user RSP
    ;   swapgs                   ; swap back to user GS

    o64 sysret
