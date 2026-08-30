//! Native x86-64 bitwise execution authority.
//!
//! A ptrace-supervised child receives the same GPR, `NT_X86_XSTATE`, memory,
//! and raw instruction bytes as the interpreter. The parent single-steps one
//! instruction and compares every defined byte selected by the case mask.
//! Signal handlers and compiler prologues never touch the observed result.

#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::ffi::c_void;
use std::path::PathBuf;
use std::ptr;

use icicle_cpu::{mem::perm, mem::Mapping, ValueSource};
use x64_engine::{build::build_x64_vm, EngineConfig, InterpVm, VmExit};

const PAGE: usize = 4096;
const XSTATE_SIZE: usize = icicle_cpu::exec::helpers::x86::STANDARD_XSTATE_SIZE;
const XFEATURES: u64 = icicle_cpu::exec::helpers::x86::INITIAL_XCR0;
const NT_X86_XSTATE: usize = 0x202;

#[derive(Clone, Copy)]
struct Case {
    name: &'static str,
    bytes: &'static [u8],
}

#[derive(Clone)]
struct ResultState {
    gprs: [u64; 18],
    xstate: Vec<u8>,
    memory: Vec<u8>,
    fault_signal: Option<i32>,
    fault_offset: Option<u64>,
}

fn ldef() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn fill_xstate(image: &mut [u8]) {
    image[..XSTATE_SIZE].fill(0);
    image[0..2].copy_from_slice(&0x037f_u16.to_le_bytes());
    image[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes());
    image[28..32].copy_from_slice(&0xffff_u32.to_le_bytes());
    image[512..520].copy_from_slice(&XFEATURES.to_le_bytes());

    for index in 0..16 {
        image[160 + index * 16..160 + (index + 1) * 16].fill(0x10_u8.wrapping_add(index as u8));
        image[576 + index * 16..576 + (index + 1) * 16].fill(0x40_u8.wrapping_add(index as u8));
        image[1152 + index * 32..1152 + (index + 1) * 32].fill(0x70_u8.wrapping_add(index as u8));
    }
    for index in 0..8 {
        image[1088 + index * 8..1088 + (index + 1) * 8]
            .copy_from_slice(&(0x0102_0304_0506_0708_u64 ^ index as u64).to_le_bytes());
    }
    for index in 0..16 {
        image[1664 + index * 64..1664 + (index + 1) * 64].fill(0xa0_u8.wrapping_add(index as u8));
    }
}

fn initial_gprs(code: u64, data: u64) -> [u64; 18] {
    [
        0x0101,
        0x0202,
        0x0303,
        0x0404,
        data,
        data,
        0x0707,
        data + 0x800,
        0x0808,
        0x0909,
        0x1010,
        0x1111,
        0x1212,
        0x1313,
        0x1414,
        0x1515,
        code,
        0x202,
    ]
}

fn from_native_regs(regs: &libc::user_regs_struct) -> [u64; 18] {
    [
        regs.rax,
        regs.rbx,
        regs.rcx,
        regs.rdx,
        regs.rsi,
        regs.rdi,
        regs.rbp,
        regs.rsp,
        regs.r8,
        regs.r9,
        regs.r10,
        regs.r11,
        regs.r12,
        regs.r13,
        regs.r14,
        regs.r15,
        regs.rip,
        regs.eflags,
    ]
}

fn apply_native_regs(regs: &mut libc::user_regs_struct, values: [u64; 18]) {
    regs.rax = values[0];
    regs.rbx = values[1];
    regs.rcx = values[2];
    regs.rdx = values[3];
    regs.rsi = values[4];
    regs.rdi = values[5];
    regs.rbp = values[6];
    regs.rsp = values[7];
    regs.r8 = values[8];
    regs.r9 = values[9];
    regs.r10 = values[10];
    regs.r11 = values[11];
    regs.r12 = values[12];
    regs.r13 = values[13];
    regs.r14 = values[14];
    regs.r15 = values[15];
    regs.rip = values[16];
    regs.eflags = values[17];
    regs.orig_rax = u64::MAX;
}

unsafe fn checked_ptrace(
    request: libc::c_uint,
    pid: libc::pid_t,
    addr: *mut c_void,
    data: *mut c_void,
) {
    let result = unsafe { libc::ptrace(request, pid, addr, data) };
    assert_ne!(
        result,
        -1,
        "ptrace({request}) failed: {}",
        std::io::Error::last_os_error()
    );
}

fn wait_stopped(pid: libc::pid_t, expected: libc::c_int) {
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFSTOPPED(status), "child status {status:#x}");
    assert_eq!(libc::WSTOPSIG(status), expected, "child status {status:#x}");
}

fn native(case: Case) -> ResultState {
    native_with_layout(case, 0, false)
}

fn require_oracle_feature_set() {
    let required = [
        ("avx2", std::is_x86_feature_detected!("avx2")),
        ("bmi1", std::is_x86_feature_detected!("bmi1")),
        ("bmi2", std::is_x86_feature_detected!("bmi2")),
        ("avx512f", std::is_x86_feature_detected!("avx512f")),
        ("avx512bw", std::is_x86_feature_detected!("avx512bw")),
        ("avx512cd", std::is_x86_feature_detected!("avx512cd")),
        ("avx512vl", std::is_x86_feature_detected!("avx512vl")),
        ("avx512vbmi2", std::is_x86_feature_detected!("avx512vbmi2")),
        (
            "avx512vpopcntdq",
            std::is_x86_feature_detected!("avx512vpopcntdq"),
        ),
    ];
    let missing: Vec<_> = required
        .into_iter()
        .filter_map(|(name, present)| (!present).then_some(name))
        .collect();
    assert!(
        missing.is_empty(),
        "native oracle host lacks required Ice Lake execution features: {}",
        missing.join(", ")
    );
}

fn native_with_layout(case: Case, data_offset: usize, protect_tail: bool) -> ResultState {
    require_oracle_feature_set();
    let mapping = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE * 3,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    let code = mapping as u64;
    let data_base = code + PAGE as u64;
    let data = data_base + data_offset as u64;
    unsafe {
        ptr::copy_nonoverlapping(case.bytes.as_ptr(), mapping.cast::<u8>(), case.bytes.len());
        ptr::write_bytes((mapping as *mut u8).add(PAGE), 0x5a, PAGE);
        if protect_tail {
            assert_eq!(
                libc::mprotect(
                    (mapping as *mut u8).add(PAGE * 2).cast(),
                    PAGE,
                    libc::PROT_NONE,
                ),
                0,
                "mprotect failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed: {}", std::io::Error::last_os_error());
    if pid == 0 {
        unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                ptr::null_mut::<c_void>(),
                ptr::null_mut::<c_void>(),
            );
            libc::raise(libc::SIGSTOP);
            libc::_exit(127);
        }
    }

    wait_stopped(pid, libc::SIGSTOP);
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    unsafe {
        checked_ptrace(
            libc::PTRACE_GETREGS,
            pid,
            ptr::null_mut(),
            (&mut regs as *mut libc::user_regs_struct).cast(),
        );
    }
    apply_native_regs(&mut regs, initial_gprs(code, data));
    unsafe {
        checked_ptrace(
            libc::PTRACE_SETREGS,
            pid,
            ptr::null_mut(),
            (&mut regs as *mut libc::user_regs_struct).cast(),
        );
    }

    let mut xstate = vec![0_u8; 64 * 1024];
    let mut iov = libc::iovec {
        iov_base: xstate.as_mut_ptr().cast(),
        iov_len: xstate.len(),
    };
    unsafe {
        checked_ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            NT_X86_XSTATE as *mut c_void,
            (&mut iov as *mut libc::iovec).cast(),
        );
    }
    assert!(
        iov.iov_len >= XSTATE_SIZE,
        "native xstate is only {} bytes",
        iov.iov_len
    );
    xstate.truncate(iov.iov_len);
    fill_xstate(&mut xstate);
    let mut set_iov = libc::iovec {
        iov_base: xstate.as_mut_ptr().cast(),
        iov_len: xstate.len(),
    };
    unsafe {
        checked_ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            NT_X86_XSTATE as *mut c_void,
            (&mut set_iov as *mut libc::iovec).cast(),
        );
        checked_ptrace(
            libc::PTRACE_SINGLESTEP,
            pid,
            ptr::null_mut(),
            ptr::null_mut(),
        );
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFSTOPPED(status), "child status {status:#x}");
    let stop_signal = libc::WSTOPSIG(status);
    assert!(
        matches!(stop_signal, libc::SIGTRAP | libc::SIGSEGV),
        "{} stopped with unexpected signal {stop_signal}",
        case.name
    );
    let (fault_signal, fault_offset) = if stop_signal == libc::SIGSEGV {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        unsafe {
            checked_ptrace(
                libc::PTRACE_GETSIGINFO,
                pid,
                ptr::null_mut(),
                (&mut info as *mut libc::siginfo_t).cast(),
            );
        }
        let address = unsafe { info.si_addr() } as u64;
        (Some(stop_signal), Some(address.wrapping_sub(data_base)))
    } else {
        (None, None)
    };

    unsafe {
        checked_ptrace(
            libc::PTRACE_GETREGS,
            pid,
            ptr::null_mut(),
            (&mut regs as *mut libc::user_regs_struct).cast(),
        );
    }
    let mut result_xstate = vec![0_u8; xstate.len()];
    let mut result_iov = libc::iovec {
        iov_base: result_xstate.as_mut_ptr().cast(),
        iov_len: result_xstate.len(),
    };
    let memory = unsafe {
        checked_ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            NT_X86_XSTATE as *mut c_void,
            (&mut result_iov as *mut libc::iovec).cast(),
        );
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, ptr::null_mut(), 0);
        let memory = std::slice::from_raw_parts((mapping as *const u8).add(PAGE), PAGE).to_vec();
        libc::munmap(mapping, PAGE * 3);
        memory
    };
    result_xstate.truncate(result_iov.iov_len);
    ResultState {
        gprs: from_native_regs(&regs),
        xstate: result_xstate,
        memory,
        fault_signal,
        fault_offset,
    }
}

fn emulated(vm: &mut InterpVm, case: Case, code: u64, data: u64) -> ResultState {
    emulated_with_layout(vm, case, code, data, 0)
}

fn emulated_with_layout(
    vm: &mut InterpVm,
    case: Case,
    code: u64,
    data_base: u64,
    data_offset: usize,
) -> ResultState {
    let data = data_base + data_offset as u64;
    // Compiling the SLEIGH language is the expensive part of the oracle. The
    // architectural machine is reset between cases, while the immutable
    // decoded language and registered helper table are reused.
    vm.reset();
    vm.cpu.mem.map_memory_len(
        code,
        (PAGE * 2) as u64,
        Mapping {
            perm: perm::ALL,
            value: 0,
        },
    );
    vm.cpu
        .mem
        .write_bytes(code, case.bytes, perm::NONE)
        .unwrap();
    vm.cpu
        .mem
        .write_bytes(data_base, &vec![0x5a; PAGE], perm::NONE)
        .unwrap();
    (vm.cpu.arch.on_boot)(&mut vm.cpu, code);
    let decoded = x64_engine::decode::decode_one(&vm.cpu, case.bytes)
        .unwrap_or_else(|error| panic!("{} failed to decode: {error:?}", case.name));
    assert_eq!(
        decoded.len,
        case.bytes.len(),
        "{} decoded with the wrong length as {}",
        case.name,
        decoded.disasm
    );

    let names = [
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12",
        "R13", "R14", "R15", "RIP", "rflags",
    ];
    for (name, value) in names.into_iter().zip(initial_gprs(code, data)) {
        let register = vm.cpu.arch.sleigh.get_varnode(name).unwrap();
        vm.cpu.write_var(register, value);
    }
    let mut xstate = vec![0_u8; XSTATE_SIZE];
    fill_xstate(&mut xstate);
    icicle_cpu::exec::helpers::x86::restore_standard_xstate_image(&mut vm.cpu, &xstate, true)
        .expect("restore emulator xstate");

    vm.icount_limit = 1;
    let exit = vm.run();
    let (fault_signal, fault_offset) = match exit {
        VmExit::InstructionLimit => (None, None),
        VmExit::UnhandledException((
            x64_engine::ExceptionCode::ReadUnmapped
            | x64_engine::ExceptionCode::ReadPerm
            | x64_engine::ExceptionCode::WriteUnmapped
            | x64_engine::ExceptionCode::WritePerm,
            address,
        )) => (Some(libc::SIGSEGV), Some(address.wrapping_sub(data_base))),
        other => panic!("{}: {other:?}", case.name),
    };
    let gprs = std::array::from_fn(|index| {
        let register = vm.cpu.arch.sleigh.get_varnode(names[index]).unwrap();
        vm.cpu.read_var::<u64>(register)
    });
    let xstate = icicle_cpu::exec::helpers::x86::standard_xstate_image(&mut vm.cpu, true)
        .expect("save emulator xstate");
    let mut memory = vec![0_u8; PAGE];
    vm.cpu
        .mem
        .read_bytes(data_base, &mut memory, perm::NONE)
        .expect("read emulator data memory");
    ResultState {
        gprs,
        xstate,
        memory,
        fault_signal,
        fault_offset,
    }
}

fn defined_xstate_offsets() -> impl Iterator<Item = usize> {
    (0..416).chain(576..832).chain(1088..2688)
}

fn differences(expected: &ResultState, actual: &ResultState) -> Vec<String> {
    let names = [
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12",
        "R13", "R14", "R15", "RIP", "RFLAGS",
    ];
    let mut differences = Vec::new();
    if expected.fault_signal != actual.fault_signal {
        differences.push(format!(
            "fault signal: native={:?} emulator={:?}",
            expected.fault_signal, actual.fault_signal
        ));
    }
    if expected.fault_offset != actual.fault_offset {
        differences.push(format!(
            "fault offset: native={:?} emulator={:?}",
            expected.fault_offset, actual.fault_offset
        ));
    }
    for (index, name) in names.into_iter().enumerate() {
        let (expected, actual) = if name == "RFLAGS" {
            (
                expected.gprs[index] & 0x0004_0dd5,
                actual.gprs[index] & 0x0004_0dd5,
            )
        } else {
            (expected.gprs[index], actual.gprs[index])
        };
        if expected != actual {
            differences.push(format!("{name}: native={expected:#x} emulator={actual:#x}"));
        }
    }
    // XINUSE for initialized x87 state may architecturally be zero or one,
    // and the native host can expose state outside the virtual profile (for
    // example PKRU or AMX). Compare the enabled, non-x87 components seeded by
    // this case and mask every other bit explicitly.
    let expected_bv = u64::from_le_bytes(expected.xstate[512..520].try_into().unwrap()) & 0xe6;
    let actual_bv = u64::from_le_bytes(actual.xstate[512..520].try_into().unwrap()) & 0xe6;
    if expected_bv != actual_bv {
        differences.push(format!(
            "XSTATE_BV[0xe6]: native={expected_bv:#x} emulator={actual_bv:#x}"
        ));
    }
    for offset in defined_xstate_offsets() {
        let expected = expected.xstate[offset];
        let actual = actual.xstate[offset];
        if expected != actual {
            differences.push(format!(
                "xstate[{offset:#x}]: native={expected:#04x} emulator={actual:#04x}"
            ));
            if differences.len() >= 32 {
                break;
            }
        }
    }
    for (offset, (&expected, &actual)) in expected.memory.iter().zip(&actual.memory).enumerate() {
        if expected != actual {
            differences.push(format!(
                "memory[{offset:#x}]: native={expected:#04x} emulator={actual:#04x}"
            ));
            if differences.len() >= 32 {
                break;
            }
        }
    }
    differences
}

fn normalize_native(
    mut state: ResultState,
    case: Case,
    data_offset: usize,
    faulted: bool,
) -> ResultState {
    let data = 0x2000 + data_offset as u64;
    state.gprs[4] = data;
    state.gprs[5] = data;
    state.gprs[7] = data + 0x800;
    state.gprs[16] = 0x1000 + if faulted { 0 } else { case.bytes.len() as u64 };
    state
}

#[test]
fn vex_avx2_and_evex_families_match_native_gprs_and_xstate_bit_for_bit() {
    let cases = [
        Case {
            name: "vmovdqu ymm0,ymm1",
            bytes: &[0xc5, 0xfe, 0x6f, 0xc1],
        },
        Case {
            name: "vpaddd ymm0,ymm1,ymm2",
            bytes: &[0xc5, 0xf5, 0xfe, 0xc2],
        },
        Case {
            name: "vpsubq ymm3,ymm4,ymm5",
            bytes: &[0xc5, 0xdd, 0xfb, 0xdd],
        },
        Case {
            name: "vpxor ymm6,ymm7,ymm8",
            bytes: &[0xc4, 0xc1, 0x45, 0xef, 0xf0],
        },
        Case {
            name: "vpand ymm9,ymm10,ymm11",
            bytes: &[0xc4, 0x41, 0x2d, 0xdb, 0xcb],
        },
        Case {
            name: "vpshufb ymm12,ymm13,ymm14",
            bytes: &[0xc4, 0x42, 0x15, 0x00, 0xe6],
        },
        Case {
            name: "vperm2i128 ymm0,ymm1,ymm2,0x31",
            bytes: &[0xc4, 0xe3, 0x75, 0x46, 0xc2, 0x31],
        },
        Case {
            name: "vinserti128 ymm3,ymm4,xmm5,1",
            bytes: &[0xc4, 0xe3, 0x5d, 0x38, 0xdd, 0x01],
        },
        Case {
            name: "vextracti128 xmm6,ymm7,1",
            bytes: &[0xc4, 0xe3, 0x7d, 0x39, 0xfe, 0x01],
        },
        Case {
            name: "vpmovmskb eax,ymm8",
            bytes: &[0xc4, 0xc1, 0x7d, 0xd7, 0xc0],
        },
        Case {
            name: "vptest ymm9,ymm10",
            bytes: &[0xc4, 0x42, 0x7d, 0x17, 0xca],
        },
        Case {
            name: "vzeroupper",
            bytes: &[0xc5, 0xf8, 0x77],
        },
        Case {
            name: "vbroadcastss ymm11,[rdi]",
            bytes: &[0xc4, 0x62, 0x7d, 0x18, 0x1f],
        },
        Case {
            name: "vpbroadcastd ymm12,[rdi]",
            bytes: &[0xc4, 0x62, 0x7d, 0x58, 0x27],
        },
        Case {
            name: "vpermd ymm13,ymm14,ymm15",
            bytes: &[0xc4, 0x42, 0x0d, 0x36, 0xef],
        },
        Case {
            name: "vpermq ymm0,ymm1,0x1b",
            bytes: &[0xc4, 0xe3, 0xfd, 0x00, 0xc1, 0x1b],
        },
        Case {
            name: "vmovdqu64 zmm0,zmm1",
            bytes: &[0x62, 0xf1, 0xfe, 0x48, 0x6f, 0xc1],
        },
        Case {
            name: "vmovdqu8 xmm2{k1},xmm3",
            bytes: &[0x62, 0xf1, 0x7f, 0x09, 0x6f, 0xd3],
        },
        Case {
            name: "vmovdqu8 ymm4{k1}{z},ymm5",
            bytes: &[0x62, 0xf1, 0x7f, 0xa9, 0x6f, 0xe5],
        },
        Case {
            name: "vmovdqu8 zmm1{k1}{z},[rsi]",
            bytes: &[0x62, 0xf1, 0x7f, 0xc9, 0x6f, 0x0e],
        },
        Case {
            name: "vmovdqu8 [rdi]{k1},zmm1",
            bytes: &[0x62, 0xf1, 0x7f, 0x49, 0x7f, 0x0f],
        },
        Case {
            name: "vmovdqu16 xmm3{k2},xmm4",
            bytes: &[0x62, 0xf1, 0xff, 0x0a, 0x6f, 0xdc],
        },
        Case {
            name: "vmovdqu16 ymm5{k2}{z},ymm6",
            bytes: &[0x62, 0xf1, 0xff, 0xaa, 0x6f, 0xee],
        },
        Case {
            name: "vmovdqu16 zmm2{k2}{z},[rsi]",
            bytes: &[0x62, 0xf1, 0xff, 0xca, 0x6f, 0x16],
        },
        Case {
            name: "vmovdqu16 [rdi]{k2},zmm2",
            bytes: &[0x62, 0xf1, 0xff, 0x4a, 0x7f, 0x17],
        },
        Case {
            name: "vmovdqu32 xmm8{k3}{z},xmm9",
            bytes: &[0x62, 0x51, 0x7e, 0x8b, 0x6f, 0xc1],
        },
        Case {
            name: "vmovdqu32 ymm10{k3},ymm11",
            bytes: &[0x62, 0x51, 0x7e, 0x2b, 0x6f, 0xd3],
        },
        Case {
            name: "vmovdqu32 zmm7{k3},[rsi]",
            bytes: &[0x62, 0xf1, 0x7e, 0x4b, 0x6f, 0x3e],
        },
        Case {
            name: "vmovdqu32 [rdi]{k3},zmm7",
            bytes: &[0x62, 0xf1, 0x7e, 0x4b, 0x7f, 0x3f],
        },
        Case {
            name: "vmovdqu64 xmm13{k4},xmm14",
            bytes: &[0x62, 0x51, 0xfe, 0x0c, 0x6f, 0xee],
        },
        Case {
            name: "vmovdqu64 ymm15{k4}{z},ymm16",
            bytes: &[0x62, 0x31, 0xfe, 0xac, 0x6f, 0xf8],
        },
        Case {
            name: "vmovdqu64 zmm12{k4}{z},[rsi]",
            bytes: &[0x62, 0x71, 0xfe, 0xcc, 0x6f, 0x26],
        },
        Case {
            name: "vmovdqu64 [rdi]{k4},zmm12",
            bytes: &[0x62, 0x71, 0xfe, 0x4c, 0x7f, 0x27],
        },
        Case {
            name: "vpaddd zmm4,zmm5,zmm6",
            bytes: &[0x62, 0xf1, 0x55, 0x48, 0xfe, 0xe6],
        },
        Case {
            name: "vpsubq zmm7,zmm8,zmm9",
            bytes: &[0x62, 0xd1, 0xbd, 0x48, 0xfb, 0xf9],
        },
        Case {
            name: "vpternlogd zmm10,zmm11,zmm12,0x96",
            bytes: &[0x62, 0x53, 0x25, 0x48, 0x25, 0xd4, 0x96],
        },
        Case {
            name: "vpcmpltd k2,zmm13,zmm14",
            bytes: &[0x62, 0xd3, 0x15, 0x48, 0x1f, 0xd6, 0x01],
        },
        Case {
            name: "vptestmd k2{k3},xmm4,xmm5",
            bytes: &[0x62, 0xf2, 0x5d, 0x0b, 0x27, 0xd5],
        },
        Case {
            name: "vptestmd k4{k5},ymm6,ymm7",
            bytes: &[0x62, 0xf2, 0x4d, 0x2d, 0x27, 0xe7],
        },
        Case {
            name: "vptestmd k0,zmm0,zmm0",
            bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x27, 0xc0],
        },
        Case {
            name: "vptestmb k1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0x65, 0x0a, 0x26, 0xcc],
        },
        Case {
            name: "vptestmb k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf2, 0x55, 0x2c, 0x26, 0xde],
        },
        Case {
            name: "vptestmb k5{k6},zmm7,zmm8",
            bytes: &[0x62, 0xd2, 0x45, 0x4e, 0x26, 0xe8],
        },
        Case {
            name: "vptestmw k1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0xe5, 0x0a, 0x26, 0xcc],
        },
        Case {
            name: "vptestmw k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf2, 0xd5, 0x2c, 0x26, 0xde],
        },
        Case {
            name: "vptestmw k5{k6},zmm7,zmm8",
            bytes: &[0x62, 0xd2, 0xc5, 0x4e, 0x26, 0xe8],
        },
        Case {
            name: "vptestmq k1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0xe5, 0x0a, 0x27, 0xcc],
        },
        Case {
            name: "vptestmq k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf2, 0xd5, 0x2c, 0x27, 0xde],
        },
        Case {
            name: "vptestmq k5{k6},zmm7,zmm8",
            bytes: &[0x62, 0xd2, 0xc5, 0x4e, 0x27, 0xe8],
        },
        Case {
            name: "vptestnmb k1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0x66, 0x0a, 0x26, 0xcc],
        },
        Case {
            name: "vptestnmb k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf2, 0x56, 0x2c, 0x26, 0xde],
        },
        Case {
            name: "vptestnmb k5{k6},zmm7,zmm8",
            bytes: &[0x62, 0xd2, 0x46, 0x4e, 0x26, 0xe8],
        },
        Case {
            name: "vptestnmw k1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0xe6, 0x0a, 0x26, 0xcc],
        },
        Case {
            name: "vptestnmw k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf2, 0xd6, 0x2c, 0x26, 0xde],
        },
        Case {
            name: "vptestnmw k5{k6},zmm7,zmm8",
            bytes: &[0x62, 0xd2, 0xc6, 0x4e, 0x26, 0xe8],
        },
        Case {
            name: "vptestnmd k1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0x66, 0x0a, 0x27, 0xcc],
        },
        Case {
            name: "vptestnmd k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf2, 0x56, 0x2c, 0x27, 0xde],
        },
        Case {
            name: "vptestnmd k5{k6},zmm7,zmm8",
            bytes: &[0x62, 0xd2, 0x46, 0x4e, 0x27, 0xe8],
        },
        Case {
            name: "vptestnmq k1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0xe6, 0x0a, 0x27, 0xcc],
        },
        Case {
            name: "vptestnmq k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf2, 0xd6, 0x2c, 0x27, 0xde],
        },
        Case {
            name: "vptestnmq k5{k6},zmm7,zmm8",
            bytes: &[0x62, 0xd2, 0xc6, 0x4e, 0x27, 0xe8],
        },
        Case {
            name: "vptestmb k1{k2},xmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x65, 0x0a, 0x26, 0x0e],
        },
        Case {
            name: "vptestmb k1{k2},ymm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x65, 0x2a, 0x26, 0x0e],
        },
        Case {
            name: "vptestmb k1{k2},zmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x65, 0x4a, 0x26, 0x0e],
        },
        Case {
            name: "vptestmw k1{k2},xmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe5, 0x0a, 0x26, 0x0e],
        },
        Case {
            name: "vptestmw k1{k2},ymm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe5, 0x2a, 0x26, 0x0e],
        },
        Case {
            name: "vptestmw k1{k2},zmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe5, 0x4a, 0x26, 0x0e],
        },
        Case {
            name: "vptestmd k1{k2},xmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x65, 0x0a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmd k1{k2},ymm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x65, 0x2a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmd k1{k2},zmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x65, 0x4a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmq k1{k2},xmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe5, 0x0a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmq k1{k2},ymm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe5, 0x2a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmq k1{k2},zmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe5, 0x4a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmb k1{k2},xmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x66, 0x0a, 0x26, 0x0e],
        },
        Case {
            name: "vptestnmb k1{k2},ymm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x66, 0x2a, 0x26, 0x0e],
        },
        Case {
            name: "vptestnmb k1{k2},zmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x66, 0x4a, 0x26, 0x0e],
        },
        Case {
            name: "vptestnmw k1{k2},xmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe6, 0x0a, 0x26, 0x0e],
        },
        Case {
            name: "vptestnmw k1{k2},ymm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe6, 0x2a, 0x26, 0x0e],
        },
        Case {
            name: "vptestnmw k1{k2},zmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe6, 0x4a, 0x26, 0x0e],
        },
        Case {
            name: "vptestnmd k1{k2},xmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x66, 0x0a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmd k1{k2},ymm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x66, 0x2a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmd k1{k2},zmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0x66, 0x4a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmq k1{k2},xmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe6, 0x0a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmq k1{k2},ymm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe6, 0x2a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmq k1{k2},zmm3,[rsi]",
            bytes: &[0x62, 0xf2, 0xe6, 0x4a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmd k1{k2},xmm3,[rsi]{1to4}",
            bytes: &[0x62, 0xf2, 0x65, 0x1a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmd k1{k2},ymm3,[rsi]{1to8}",
            bytes: &[0x62, 0xf2, 0x65, 0x3a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmd k1{k2},zmm3,[rsi]{1to16}",
            bytes: &[0x62, 0xf2, 0x65, 0x5a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmq k1{k2},xmm3,[rsi]{1to2}",
            bytes: &[0x62, 0xf2, 0xe5, 0x1a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmq k1{k2},ymm3,[rsi]{1to4}",
            bytes: &[0x62, 0xf2, 0xe5, 0x3a, 0x27, 0x0e],
        },
        Case {
            name: "vptestmq k1{k2},zmm3,[rsi]{1to8}",
            bytes: &[0x62, 0xf2, 0xe5, 0x5a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmd k1{k2},xmm3,[rsi]{1to4}",
            bytes: &[0x62, 0xf2, 0x66, 0x1a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmd k1{k2},ymm3,[rsi]{1to8}",
            bytes: &[0x62, 0xf2, 0x66, 0x3a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmd k1{k2},zmm3,[rsi]{1to16}",
            bytes: &[0x62, 0xf2, 0x66, 0x5a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmq k1{k2},xmm3,[rsi]{1to2}",
            bytes: &[0x62, 0xf2, 0xe6, 0x1a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmq k1{k2},ymm3,[rsi]{1to4}",
            bytes: &[0x62, 0xf2, 0xe6, 0x3a, 0x27, 0x0e],
        },
        Case {
            name: "vptestnmq k1{k2},zmm3,[rsi]{1to8}",
            bytes: &[0x62, 0xf2, 0xe6, 0x5a, 0x27, 0x0e],
        },
        Case {
            name: "vpermd zmm15,zmm16,zmm17",
            bytes: &[0x62, 0x32, 0x7d, 0x40, 0x36, 0xf9],
        },
        Case {
            name: "vpermq zmm18,zmm19,0x1b",
            bytes: &[0x62, 0xa3, 0xfd, 0x48, 0x00, 0xd3, 0x1b],
        },
        Case {
            name: "vpshufb zmm20,zmm21,zmm22",
            bytes: &[0x62, 0xa2, 0x55, 0x40, 0x00, 0xe6],
        },
        Case {
            name: "vpcompressd zmm25{k5},zmm26",
            bytes: &[0x62, 0x02, 0x7d, 0x4d, 0x8b, 0xd1],
        },
        Case {
            name: "vpexpandd zmm27{k6}{z},zmm28",
            bytes: &[0x62, 0x02, 0x7d, 0xce, 0x89, 0xdc],
        },
        Case {
            name: "vpcompressd xmm1,xmm2",
            bytes: &[0x62, 0xf2, 0x7d, 0x08, 0x8b, 0xd1],
        },
        Case {
            name: "vpcompressd xmm3{k5},xmm4",
            bytes: &[0x62, 0xf2, 0x7d, 0x0d, 0x8b, 0xe3],
        },
        Case {
            name: "vpcompressd xmm5{k5}{z},xmm6",
            bytes: &[0x62, 0xf2, 0x7d, 0x8d, 0x8b, 0xf5],
        },
        Case {
            name: "vpcompressd ymm7,ymm8",
            bytes: &[0x62, 0x72, 0x7d, 0x28, 0x8b, 0xc7],
        },
        Case {
            name: "vpcompressd ymm9{k5},ymm10",
            bytes: &[0x62, 0x52, 0x7d, 0x2d, 0x8b, 0xd1],
        },
        Case {
            name: "vpcompressd ymm11{k5}{z},ymm12",
            bytes: &[0x62, 0x52, 0x7d, 0xad, 0x8b, 0xe3],
        },
        Case {
            name: "vpcompressd zmm13,zmm14",
            bytes: &[0x62, 0x52, 0x7d, 0x48, 0x8b, 0xf5],
        },
        Case {
            name: "vpcompressd zmm15{k5}{z},zmm16",
            bytes: &[0x62, 0xc2, 0x7d, 0xcd, 0x8b, 0xc7],
        },
        Case {
            name: "vpexpandd xmm1,xmm2",
            bytes: &[0x62, 0xf2, 0x7d, 0x08, 0x89, 0xca],
        },
        Case {
            name: "vpexpandd xmm3{k6},xmm4",
            bytes: &[0x62, 0xf2, 0x7d, 0x0e, 0x89, 0xdc],
        },
        Case {
            name: "vpexpandd xmm5{k6}{z},xmm6",
            bytes: &[0x62, 0xf2, 0x7d, 0x8e, 0x89, 0xee],
        },
        Case {
            name: "vpexpandd ymm7,ymm8",
            bytes: &[0x62, 0xd2, 0x7d, 0x28, 0x89, 0xf8],
        },
        Case {
            name: "vpexpandd ymm9{k6},ymm10",
            bytes: &[0x62, 0x52, 0x7d, 0x2e, 0x89, 0xca],
        },
        Case {
            name: "vpexpandd ymm11{k6}{z},ymm12",
            bytes: &[0x62, 0x52, 0x7d, 0xae, 0x89, 0xdc],
        },
        Case {
            name: "vpexpandd zmm13,zmm14",
            bytes: &[0x62, 0x52, 0x7d, 0x48, 0x89, 0xee],
        },
        Case {
            name: "vpexpandd zmm15{k6},zmm16",
            bytes: &[0x62, 0x32, 0x7d, 0x4e, 0x89, 0xf8],
        },
        Case {
            name: "vpcompressd [rdi]{k5},xmm26",
            bytes: &[0x62, 0x62, 0x7d, 0x0d, 0x8b, 0x17],
        },
        Case {
            name: "vpexpandd xmm27{k6}{z},[rsi]",
            bytes: &[0x62, 0x62, 0x7d, 0x8e, 0x89, 0x1e],
        },
        Case {
            name: "vpcompressd [rdi]{k5},ymm26",
            bytes: &[0x62, 0x62, 0x7d, 0x2d, 0x8b, 0x17],
        },
        Case {
            name: "vpexpandd ymm27{k6}{z},[rsi]",
            bytes: &[0x62, 0x62, 0x7d, 0xae, 0x89, 0x1e],
        },
        Case {
            name: "vpcompressd [rdi]{k5},zmm26",
            bytes: &[0x62, 0x62, 0x7d, 0x4d, 0x8b, 0x17],
        },
        Case {
            name: "vpexpandd zmm27{k6}{z},[rsi]",
            bytes: &[0x62, 0x62, 0x7d, 0xce, 0x89, 0x1e],
        },
        Case {
            name: "vpbroadcastd zmm1,[rdi]",
            bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x58, 0x0f],
        },
        Case {
            name: "vpternlogd zmm0,zmm1,[rsi],0xf8",
            bytes: &[0x62, 0xf3, 0x75, 0x48, 0x25, 0x06, 0xf8],
        },
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for case in cases {
        let native_authority = normalize_native(native(case), case, 0, false);
        let native_repeat = normalize_native(native(case), case, 0, false);
        let native_instability = differences(&native_authority, &native_repeat);
        assert!(
            native_instability.is_empty(),
            "{} native authority was not repeatable:\n{}",
            case.name,
            native_instability.join("\n")
        );
        // Native mmap addresses are intentionally not reused by the emulator;
        // normalize the two address-bearing inputs while preserving every
        // other seeded GPR. The instruction uses only the pointed-to bytes.
        let emulated = emulated(&mut vm, case, 0x1000, 0x2000);
        let mismatches = differences(&native_authority, &emulated);
        assert!(
            mismatches.is_empty(),
            "{}:\n{}",
            case.name,
            mismatches.join("\n")
        );

        let mut corrupted = emulated.clone();
        corrupted.xstate[160] ^= 1;
        assert!(
            !differences(&native_authority, &corrupted).is_empty(),
            "comparison mask failed to detect a defined-byte corruption"
        );
    }
}

#[test]
fn compress_expand_masked_page_boundaries_match_native_faults_and_partial_memory() {
    let cases = [
        Case {
            name: "vpcompressd [rdi]{k5},zmm26 boundary",
            bytes: &[0x62, 0x62, 0x7d, 0x4d, 0x8b, 0x17],
        },
        Case {
            name: "vpexpandd zmm27{k6}{z},[rsi] boundary",
            bytes: &[0x62, 0x62, 0x7d, 0xce, 0x89, 0x1e],
        },
    ];

    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for case in cases {
        // Each seeded mask selects six dwords. A pointer 24 bytes before the
        // guard page must succeed without touching the masked-off lanes; four
        // bytes later, the sixth selected element must fault at the guard.
        for (data_offset, should_fault) in [(PAGE - 24, false), (PAGE - 20, true)] {
            let native = normalize_native(
                native_with_layout(case, data_offset, true),
                case,
                data_offset,
                should_fault,
            );
            assert_eq!(native.fault_signal.is_some(), should_fault, "{}", case.name);
            let native_repeat = normalize_native(
                native_with_layout(case, data_offset, true),
                case,
                data_offset,
                should_fault,
            );
            let native_instability = differences(&native, &native_repeat);
            assert!(
                native_instability.is_empty(),
                "{} at offset {data_offset:#x} native authority was not repeatable:\n{}",
                case.name,
                native_instability.join("\n")
            );
            let emulated = emulated_with_layout(&mut vm, case, 0x1000, 0x2000, data_offset);
            let mismatches = differences(&native, &emulated);
            assert!(
                mismatches.is_empty(),
                "{} at offset {data_offset:#x}:\n{}",
                case.name,
                mismatches.join("\n")
            );
        }
    }
}

#[test]
fn masked_vmovdqu_suppresses_inactive_page_faults_and_matches_native_store_atomicity() {
    let cases = [
        (
            Case {
                name: "vmovdqu8 zmm1{k1}{z},[rsi] boundary",
                bytes: &[0x62, 0xf1, 0x7f, 0xc9, 0x6f, 0x0e],
            },
            57,
        ),
        (
            Case {
                name: "vmovdqu8 [rdi]{k1},zmm1 boundary",
                bytes: &[0x62, 0xf1, 0x7f, 0x49, 0x7f, 0x0f],
            },
            57,
        ),
        (
            Case {
                name: "vmovdqu16 zmm2{k2}{z},[rsi] boundary",
                bytes: &[0x62, 0xf1, 0xff, 0xca, 0x6f, 0x16],
            },
            54,
        ),
        (
            Case {
                name: "vmovdqu16 [rdi]{k2},zmm2 boundary",
                bytes: &[0x62, 0xf1, 0xff, 0x4a, 0x7f, 0x17],
            },
            54,
        ),
        (
            Case {
                name: "vmovdqu32 zmm7{k3},[rsi] boundary",
                bytes: &[0x62, 0xf1, 0x7e, 0x4b, 0x6f, 0x3e],
            },
            44,
        ),
        (
            Case {
                name: "vmovdqu32 [rdi]{k3},zmm7 boundary",
                bytes: &[0x62, 0xf1, 0x7e, 0x4b, 0x7f, 0x3f],
            },
            44,
        ),
        (
            Case {
                name: "vmovdqu64 zmm12{k4}{z},[rsi] boundary",
                bytes: &[0x62, 0x71, 0xfe, 0xcc, 0x6f, 0x26],
            },
            32,
        ),
        (
            Case {
                name: "vmovdqu64 [rdi]{k4},zmm12 boundary",
                bytes: &[0x62, 0x71, 0xfe, 0x4c, 0x7f, 0x27],
            },
            32,
        ),
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");

    for (case, mapped_span) in cases {
        // Each deterministic K-register seed leaves a masked-off tail after
        // its highest selected element. `mapped_span` places that complete
        // element at the end of the mapped page; advancing one byte makes the
        // selected element cross the guard while all later lanes stay masked.
        for (data_offset, should_fault) in
            [(PAGE - mapped_span, false), (PAGE - mapped_span + 1, true)]
        {
            let native = normalize_native(
                native_with_layout(case, data_offset, true),
                case,
                data_offset,
                should_fault,
            );
            assert_eq!(native.fault_signal.is_some(), should_fault, "{}", case.name);
            let emulated = emulated_with_layout(&mut vm, case, 0x1000, 0x2000, data_offset);
            let mismatches = differences(&native, &emulated);
            assert!(
                mismatches.is_empty(),
                "{} at offset {data_offset:#x}:\n{}",
                case.name,
                mismatches.join("\n")
            );
        }
    }
}

#[test]
fn vptest_memory_suppresses_inactive_element_faults() {
    let cases = [
        (
            Case {
                name: "vptestmb k1{k2},zmm3,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x65, 0x4a, 0x26, 0x0e],
            },
            57,
        ),
        (
            Case {
                name: "vptestmw k1{k2},zmm3,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0xe5, 0x4a, 0x26, 0x0e],
            },
            54,
        ),
        (
            Case {
                name: "vptestmd k1{k2},zmm3,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x65, 0x4a, 0x27, 0x0e],
            },
            44,
        ),
        (
            Case {
                name: "vptestmq k1{k2},zmm3,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0xe5, 0x4a, 0x27, 0x0e],
            },
            32,
        ),
        (
            Case {
                name: "vptestnmb k1{k2},zmm3,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x66, 0x4a, 0x26, 0x0e],
            },
            57,
        ),
        (
            Case {
                name: "vptestnmw k1{k2},zmm3,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0xe6, 0x4a, 0x26, 0x0e],
            },
            54,
        ),
        (
            Case {
                name: "vptestnmd k1{k2},zmm3,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x66, 0x4a, 0x27, 0x0e],
            },
            44,
        ),
        (
            Case {
                name: "vptestnmq k1{k2},zmm3,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0xe6, 0x4a, 0x27, 0x0e],
            },
            32,
        ),
        (
            Case {
                name: "vptestmd k1{k2},zmm3,[rsi]{1to16} boundary",
                bytes: &[0x62, 0xf2, 0x65, 0x5a, 0x27, 0x0e],
            },
            4,
        ),
        (
            Case {
                name: "vptestmq k1{k2},zmm3,[rsi]{1to8} boundary",
                bytes: &[0x62, 0xf2, 0xe5, 0x5a, 0x27, 0x0e],
            },
            8,
        ),
        (
            Case {
                name: "vptestnmd k1{k2},zmm3,[rsi]{1to16} boundary",
                bytes: &[0x62, 0xf2, 0x66, 0x5a, 0x27, 0x0e],
            },
            4,
        ),
        (
            Case {
                name: "vptestnmq k1{k2},zmm3,[rsi]{1to8} boundary",
                bytes: &[0x62, 0xf2, 0xe6, 0x5a, 0x27, 0x0e],
            },
            8,
        ),
    ];

    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for (case, selected_span) in cases {
        // K2 selects a sparse set of elements. Masked-off source elements do
        // suppress faults; the last selected element ends at selected_span.
        // Shifting the source one byte later makes precisely that element
        // cross into the guard page.
        for (data_offset, should_fault) in [
            (PAGE - selected_span, false),
            (PAGE - selected_span + 1, true),
        ] {
            let native = normalize_native(
                native_with_layout(case, data_offset, true),
                case,
                data_offset,
                should_fault,
            );
            assert_eq!(native.fault_signal.is_some(), should_fault, "{}", case.name);
            let native_repeat = normalize_native(
                native_with_layout(case, data_offset, true),
                case,
                data_offset,
                should_fault,
            );
            let native_instability = differences(&native, &native_repeat);
            assert!(
                native_instability.is_empty(),
                "{} at offset {data_offset:#x} native authority was not repeatable:\n{}",
                case.name,
                native_instability.join("\n")
            );
            let emulated = emulated_with_layout(&mut vm, case, 0x1000, 0x2000, data_offset);
            let mismatches = differences(&native, &emulated);
            assert!(
                mismatches.is_empty(),
                "{} at offset {data_offset:#x}:\n{}",
                case.name,
                mismatches.join("\n")
            );
        }
    }
}
