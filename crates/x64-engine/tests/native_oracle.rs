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
use x64_engine::{build::build_x64_vm, EngineConfig, VmExit};

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
    assert!(
        std::is_x86_feature_detected!("avx512f"),
        "native oracle requires AVX-512F"
    );
    let mapping = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE * 2,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    let code = mapping as u64;
    let data = code + PAGE as u64;
    unsafe {
        ptr::copy_nonoverlapping(case.bytes.as_ptr(), mapping.cast::<u8>(), case.bytes.len());
        ptr::write_bytes((mapping as *mut u8).add(PAGE), 0x5a, PAGE);
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
    wait_stopped(pid, libc::SIGTRAP);

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
    unsafe {
        checked_ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            NT_X86_XSTATE as *mut c_void,
            (&mut result_iov as *mut libc::iovec).cast(),
        );
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, ptr::null_mut(), 0);
        libc::munmap(mapping, PAGE * 2);
    }
    result_xstate.truncate(result_iov.iov_len);
    ResultState {
        gprs: from_native_regs(&regs),
        xstate: result_xstate,
    }
}

fn emulated(case: Case, code: u64, data: u64) -> ResultState {
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
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
        .write_bytes(data, &vec![0x5a; PAGE], perm::NONE)
        .unwrap();
    (vm.cpu.arch.on_boot)(&mut vm.cpu, code);

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
    assert!(
        matches!(exit, VmExit::InstructionLimit),
        "{}: {exit:?}",
        case.name
    );
    let gprs = std::array::from_fn(|index| {
        let register = vm.cpu.arch.sleigh.get_varnode(names[index]).unwrap();
        vm.cpu.read_var::<u64>(register)
    });
    let xstate = icicle_cpu::exec::helpers::x86::standard_xstate_image(&mut vm.cpu, true)
        .expect("save emulator xstate");
    ResultState { gprs, xstate }
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
    differences
}

#[test]
fn claude_evex_canaries_match_native_gprs_and_xstate_bit_for_bit() {
    let cases = [
        Case {
            name: "vpbroadcastd zmm1,[rdi]",
            bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x58, 0x0f],
        },
        Case {
            name: "vpternlogd zmm0,zmm1,[rsi],0xf8",
            bytes: &[0x62, 0xf3, 0x75, 0x48, 0x25, 0x06, 0xf8],
        },
    ];
    for case in cases {
        let native = native(case);
        // Native mmap addresses are intentionally not reused by the emulator;
        // normalize the two address-bearing inputs while preserving every
        // other seeded GPR. The instruction uses only the pointed-to bytes.
        let emulated = emulated(case, 0x1000, 0x2000);
        let mut normalized_native = native.clone();
        normalized_native.gprs[4] = 0x2000;
        normalized_native.gprs[5] = 0x2000;
        normalized_native.gprs[7] = 0x2800;
        normalized_native.gprs[16] = 0x1000 + case.bytes.len() as u64;
        let mismatches = differences(&normalized_native, &emulated);
        assert!(
            mismatches.is_empty(),
            "{}:\n{}",
            case.name,
            mismatches.join("\n")
        );

        let mut corrupted = emulated.clone();
        corrupted.xstate[160] ^= 1;
        assert!(
            !differences(&normalized_native, &corrupted).is_empty(),
            "comparison mask failed to detect a defined-byte corruption"
        );
    }
}
