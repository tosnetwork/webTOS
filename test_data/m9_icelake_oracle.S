// Portable M9 execution fingerprint.
//
// The native ptrace oracle remains the per-instruction authority. This small
// freestanding program is the replay artifact that can run unchanged inside
// the Linux compatibility layer and every browser engine. It exercises one
// dependency-closed path through every AVX-family extension published by
// webtos-x86_64-icelake-simdutf-v1, hashes the resulting bytes with FNV-1a,
// and writes an ASCII fingerprint using only Linux syscalls.

.intel_syntax noprefix

.section .text
.global _start
.type _start, @function
_start:
    lea rsi, [rip + input]
    lea rdi, [rip + output]

    // VEX/AVX2 baseline: byte shuffle, lane permutation, and integer multiply.
    vmovdqu ymm8, ymmword ptr [rsi]
    vpshufb ymm9, ymm8, ymmword ptr [rsi + 32]
    vpermq ymm10, ymm9, 0x1b
    vpmulld ymm11, ymm10, ymm8
    vmovdqu ymmword ptr [rdi], ymm11

    // AVX + AES-NI/PCLMULQDQ also publishes their VEX.128 forms. Store the
    // complete ZMM aliases so the fingerprint observes mandatory upper-lane
    // clearing, not only the low 128-bit result.
    vmovdqu xmm12, xmmword ptr [rsi]
    vmovdqu xmm13, xmmword ptr [rsi + 16]
    vaesenc xmm14, xmm12, xmm13
    vpclmulqdq xmm15, xmm12, xmm13, 0x11
    vmovdqu64 zmmword ptr [rdi + 32], zmm14
    vmovdqu64 zmmword ptr [rdi + 96], zmm15

    // AVX-512F/BW plus the two Claude/Bun canary operations.
    vmovdqu64 zmm0, zmmword ptr [rsi]
    vmovdqu64 zmm1, zmmword ptr [rsi + 64]
    vpbroadcastd zmm2, dword ptr [rsi + 128]
    vpternlogd zmm0, zmm1, zmm2, 0x96

    // VPOPCNTDQ, CD, and VBMI2. The variable double shift consumes the
    // conflict and population-count results, making every preceding value
    // observable in the final fingerprint.
    vpopcntd zmm3, zmm0
    vpconflictd zmm4, zmm3
    vpshldvd zmm5, zmm3, zmm4
    vpshufb zmm6, zmm5, zmm1

    // AVX-512VL mask merge/zero behavior and a compacting memory destination.
    mov eax, 0xa55a
    kmovw k1, eax
    vmovdqu32 zmm7{k1}{z}, zmm6
    vpcompressd zmmword ptr [rdi + 160]{k1}, zmm7
    vmovdqu64 zmmword ptr [rdi + 224], zmm0
    vmovdqu64 zmmword ptr [rdi + 288], zmm5

    // Scalar BMI1/BMI2 are part of the same simdutf selector closure.
    mov rax, 0x0123456789abcdef
    mov rbx, 0x55aa33cc0ff09669
    andn rcx, rax, rbx
    pdep rdx, rax, rbx
    pext r8, rax, rbx
    shlx r9, rax, rbx
    mov qword ptr [rdi + 352], rcx
    mov qword ptr [rdi + 360], rdx
    mov qword ptr [rdi + 368], r8
    mov qword ptr [rdi + 376], r9
    vzeroupper

    // FNV-1a over the complete observable output region.
    mov rax, 0xcbf29ce484222325
    mov r8, 0x100000001b3
    lea rsi, [rip + output]
    mov ecx, 384
.Lhash:
    movzx edx, byte ptr [rsi]
    xor rax, rdx
    imul rax, r8
    inc rsi
    dec ecx
    jne .Lhash

    // Render sixteen lowercase hexadecimal digits into the fixed message.
    lea rdi, [rip + message + 33]
    lea rsi, [rip + hex]
    mov ecx, 16
.Lhex:
    mov rdx, rax
    and edx, 0xf
    mov dl, byte ptr [rsi + rdx]
    mov byte ptr [rdi], dl
    dec rdi
    shr rax, 4
    dec ecx
    jne .Lhex

    mov eax, 1
    mov edi, 1
    lea rsi, [rip + message]
    mov edx, 35
    syscall

    mov eax, 60
    xor edi, edi
    syscall
.size _start, .-_start

.section .rodata
.balign 64
input:
    .byte 0x00,0x01,0x7e,0x7f,0x80,0x81,0xfe,0xff,0x11,0x22,0x55,0xaa,0x33,0xcc,0x69,0x96
    .byte 0x10,0x31,0x5e,0x7d,0x90,0xb1,0xde,0xfd,0x21,0x42,0x65,0x8a,0xb3,0xdc,0xe9,0x06
    .byte 0x7f,0x0e,0x1d,0x2c,0x3b,0x4a,0x59,0x68,0x77,0x86,0x95,0xa4,0xb3,0xc2,0xd1,0xe0
    .byte 0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0
    .byte 0x96,0x69,0xcc,0x33,0xaa,0x55,0x22,0x11,0xff,0xfe,0x81,0x80,0x7f,0x7e,0x01,0x00
    .byte 0x06,0xe9,0xdc,0xb3,0x8a,0x65,0x42,0x21,0xfd,0xde,0xb1,0x90,0x7d,0x5e,0x31,0x10
    .byte 0xe0,0xd1,0xc2,0xb3,0xa4,0x95,0x86,0x77,0x68,0x59,0x4a,0x3b,0x2c,0x1d,0x0e,0x7f
    .byte 0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f
    .long 0x6d395a17

hex:
    .ascii "0123456789abcdef"

.section .data
message:
    .ascii "M9_ORACLE_FNV1A64=0000000000000000\n"

.section .bss
.balign 64
output:
    .zero 384
