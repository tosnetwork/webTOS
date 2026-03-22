; AOS user_agents.asm — Ring 3 test agents
;
; These agents run in ring 3 and use the SYSCALL instruction for all
; kernel interactions. They are position-independent and self-contained.
;
; Syscall convention:
;   RAX = syscall number
;   RDI = arg0, RSI = arg1, RDX = arg2, R10 = arg3, R8 = arg4
;   Return: RAX
;   Clobbered: RCX, R11

bits 64
section .text

; Syscall numbers (from Yellow Paper)
%define SYS_YIELD   0
%define SYS_EXIT    2
%define SYS_SEND    3
%define SYS_RECV    4

; ─── User Ping Agent ────────────────────────────────────────────────────────
; Sends "ping" to mailbox 3, receives from mailbox 2, yields, loops.

global user_ping_entry
user_ping_entry:
    ; Send initial "ping" to mailbox 3
    mov rax, SYS_SEND
    mov rdi, 3                  ; mailbox_id = pong's mailbox
    lea rsi, [rel .ping_msg]    ; payload pointer
    mov rdx, 4                  ; payload length
    syscall

.ping_loop:
    ; Receive reply from own mailbox (2)
    sub rsp, 256                ; allocate receive buffer on stack
    mov rax, SYS_RECV
    mov rdi, 2                  ; own mailbox id
    mov rsi, rsp                ; buffer pointer
    mov rdx, 256                ; buffer capacity
    syscall

    ; Send another "ping"
    mov rax, SYS_SEND
    mov rdi, 3                  ; target mailbox (pong)
    lea rsi, [rel .ping_msg]    ; payload pointer
    mov rdx, 4                  ; payload length
    syscall

    add rsp, 256                ; deallocate buffer

    ; Yield
    mov rax, SYS_YIELD
    syscall

    jmp .ping_loop

.ping_msg: db "ping"

; Size marker for copying
global user_ping_end
user_ping_end:

; ─── User Pong Agent ────────────────────────────────────────────────────────
; Receives from mailbox 3, sends "pong" to mailbox 2, yields, loops.

global user_pong_entry
user_pong_entry:
.pong_loop:
    ; Receive from own mailbox (3)
    sub rsp, 256
    mov rax, SYS_RECV
    mov rdi, 3                  ; own mailbox id
    mov rsi, rsp                ; buffer
    mov rdx, 256                ; capacity
    syscall

    ; Send "pong" to mailbox 2
    mov rax, SYS_SEND
    mov rdi, 2                  ; target mailbox (ping)
    lea rsi, [rel .pong_msg]    ; payload pointer
    mov rdx, 4                  ; payload length
    syscall

    add rsp, 256

    ; Yield
    mov rax, SYS_YIELD
    syscall

    jmp .pong_loop

.pong_msg: db "pong"

global user_pong_end
user_pong_end:

; ─── User Bad Agent ─────────────────────────────────────────────────────────
; Attempts unauthorized send to mailbox 1 (root). Should be denied.

global user_bad_entry
user_bad_entry:
    ; Try to send to mailbox 1 (no capability)
    mov rax, SYS_SEND
    mov rdi, 1                  ; target = root's mailbox (unauthorized)
    lea rsi, [rel .bad_msg]     ; payload pointer
    mov rdx, 4                  ; payload length
    syscall
    ; RAX now contains error code (should be -1 = E_NO_CAP)

    ; Exit
    mov rax, SYS_EXIT
    xor rdi, rdi                ; exit code 0
    syscall

    ; Should not reach here
    hlt
    jmp $

.bad_msg: db "hack"

global user_bad_end
user_bad_end:
