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

    const EDGE_PATTERN: [u8; 16] = [
        0x00, 0x01, 0x7e, 0x7f, 0x80, 0x81, 0xfe, 0xff, 0x11, 0x22, 0x55, 0xaa, 0x33, 0xcc, 0x69,
        0x96,
    ];
    for index in 0..16 {
        for byte in 0..16 {
            image[160 + index * 16 + byte] =
                EDGE_PATTERN[byte].wrapping_add((index as u8).wrapping_mul(0x13));
            image[576 + index * 16 + byte] =
                EDGE_PATTERN[(byte + 5) % 16] ^ (index as u8).wrapping_mul(0x2d);
        }
        for byte in 0..32 {
            image[1152 + index * 32 + byte] = EDGE_PATTERN[(byte * 7 + index) % 16]
                .wrapping_add((index as u8).wrapping_mul(0x31));
        }
    }
    for index in 0..8 {
        image[1088 + index * 8..1088 + (index + 1) * 8]
            .copy_from_slice(&(0x0102_0304_0506_0708_u64 ^ index as u64).to_le_bytes());
    }
    // K7 intentionally selects only the first eight byte lanes. Boundary
    // cases use it to prove VPMULTISHIFTQB's E4NF full-source read behavior.
    image[1088 + 7 * 8..1088 + 8 * 8].copy_from_slice(&0xff_u64.to_le_bytes());
    for index in 0..16 {
        for byte in 0..64 {
            image[1664 + index * 64 + byte] = EDGE_PATTERN[(byte * 11 + index * 3) % 16]
                ^ (index as u8).wrapping_mul(0x47)
                ^ byte as u8;
        }
    }
}

fn zmm_byte_offset(register: usize, byte: usize) -> usize {
    if register < 16 {
        match byte {
            0..=15 => 160 + register * 16 + byte,
            16..=31 => 576 + register * 16 + byte - 16,
            32..=63 => 1152 + register * 32 + byte - 32,
            _ => panic!("invalid ZMM byte {byte}"),
        }
    } else {
        1664 + (register - 16) * 64 + byte
    }
}

fn prepare_vsib_case_xstate(case: Case, image: &mut [u8]) {
    let Some((register, lane_size, lane_count)) = (match case.name {
        "vsib vpgatherdd" => Some((3, 4, 16)),
        "vsib fault vpgatherdd" => Some((3, 4, 16)),
        "vsib vpgatherdq" => Some((4, 4, 8)),
        "vsib vpgatherqd" => Some((5, 8, 8)),
        "vsib vpgatherqq" => Some((7, 8, 8)),
        "vsib vgatherdps" => Some((9, 4, 16)),
        "vsib vgatherdpd" => Some((11, 4, 8)),
        "vsib vgatherqps" => Some((13, 8, 8)),
        "vsib vgatherqpd" => Some((15, 8, 8)),
        "vsib vpscatterdd" => Some((18, 4, 16)),
        "vsib fault vpscatterdd" => Some((18, 4, 16)),
        "vsib vpscatterdq" => Some((20, 4, 8)),
        "vsib vpscatterqd" => Some((22, 8, 8)),
        "vsib vpscatterqq" => Some((24, 8, 8)),
        "vsib vscatterdps" => Some((26, 4, 16)),
        "vsib vscatterdpd" => Some((28, 4, 8)),
        "vsib vscatterqps" => Some((30, 8, 8)),
        "vsib vscatterqpd" => Some((1, 8, 8)),
        "vex vsib vpgatherdd" => Some((3, 4, 8)),
        "vsib fault vex vpgatherdd" => Some((3, 4, 8)),
        "vex vsib vpgatherdq" => Some((4, 4, 4)),
        "vex vsib vpgatherqd" => Some((9, 8, 4)),
        "vex vsib vpgatherqq" => Some((10, 8, 4)),
        "vex vsib vgatherdps" => Some((14, 4, 8)),
        "vex vsib vgatherdpd" => Some((2, 4, 4)),
        "vex vsib vgatherqps" => Some((5, 8, 4)),
        "vex vsib vgatherqpd" => Some((8, 8, 4)),
        _ => None,
    }) else {
        return;
    };
    for lane in 0..lane_count {
        let value = (lane as u64 * 16).to_le_bytes();
        for byte in 0..lane_size {
            image[zmm_byte_offset(register, lane * lane_size + byte)] = value[byte];
        }
    }
    let mask = match case.name {
        "vex vsib vpgatherdd" => Some((5, 4, 8)),
        "vsib fault vex vpgatherdd" => Some((5, 4, 8)),
        "vex vsib vpgatherdq" => Some((6, 8, 4)),
        "vex vsib vpgatherqd" => Some((11, 4, 4)),
        "vex vsib vpgatherqq" => Some((12, 8, 4)),
        "vex vsib vgatherdps" => Some((15, 4, 8)),
        "vex vsib vgatherdpd" => Some((3, 8, 4)),
        "vex vsib vgatherqps" => Some((6, 4, 4)),
        "vex vsib vgatherqpd" => Some((9, 8, 4)),
        _ => None,
    };
    if let Some((mask_register, element_size, elements)) = mask {
        for lane in 0..elements {
            for byte in 0..element_size {
                image[zmm_byte_offset(mask_register, lane * element_size + byte)] =
                    if byte + 1 == element_size { 0x80 } else { 0 };
            }
        }
    }
}

fn prepare_special_float_case_xstate(case: Case, image: &mut [u8]) {
    let values = [
        0x3fe0_0000_u32,
        0xbfe0_0000,
        0x0000_0001,
        0x8000_0000,
        0x7f80_0000,
        0xff80_0000,
        0x7f80_0001,
        0x7fc1_2345,
        0x4060_0000,
        0xc060_0000,
        0x007f_ffff,
        0x3f40_0000,
        0x4000_0000,
        0xc000_0000,
        0x0080_0000,
        0x8080_0000,
    ];
    if case.name.starts_with("edge vgetmantps") || case.name.starts_with("edge vgetexpps") {
        for (lane, value) in values.into_iter().enumerate() {
            for (byte, value) in value.to_le_bytes().into_iter().enumerate() {
                image[zmm_byte_offset(2, lane * 4 + byte)] = value;
            }
        }
    } else if case.name.starts_with("edge vrndscaleps") {
        let round_values = [
            0x3fc0_0000_u32,
            0x4020_0000,
            0xbfc0_0000,
            0xc020_0000,
            0,
            0x8000_0000,
            0x7f80_0000,
            0xff80_0000,
            0x7fc1_2345,
            0x7f80_0001,
            1,
            0x007f_ffff,
            0x42f7_8000,
            0xc2f7_8000,
            0x4b00_0001,
            0xcb00_0001,
        ];
        for (lane, value) in round_values.into_iter().enumerate() {
            for (byte, value) in value.to_le_bytes().into_iter().enumerate() {
                image[zmm_byte_offset(2, lane * 4 + byte)] = value;
            }
        }
    } else if case.name.starts_with("edge vfixupimm") {
        let classes = [
            0x7fc1_2345_u32,
            0x7f80_0001,
            0,
            0x3f80_0000,
            0xff80_0000,
            0x7f80_0000,
            0xc000_0000,
            0x4000_0000,
        ];
        for lane in 0..16 {
            let source = classes[lane % classes.len()];
            let class = lane % classes.len();
            let control = ((lane as u32) & 0xf) << (class * 4);
            let old = (100.0_f32 + lane as f32).to_bits();
            for (register, value) in [(1, old), (2, source), (3, control)] {
                for (byte, value) in value.to_le_bytes().into_iter().enumerate() {
                    image[zmm_byte_offset(register, lane * 4 + byte)] = value;
                }
            }
        }
    } else if case.name.starts_with("edge vrcp14ps") || case.name.starts_with("edge vrsqrt14ps") {
        let approximate_values = [
            0x3f80_0000_u32,
            0x4000_0000,
            0x4040_0000,
            0x3f00_0000,
            0xbf80_0000,
            0xc000_0000,
            0,
            0x8000_0000,
            0x7f80_0000,
            0xff80_0000,
            0x7fc1_2345,
            0x7f80_0001,
            1,
            0x007f_ffff,
            0x7f7f_ffff,
            0x4080_0000,
        ];
        for (lane, value) in approximate_values.into_iter().enumerate() {
            for (byte, value) in value.to_le_bytes().into_iter().enumerate() {
                image[zmm_byte_offset(2, lane * 4 + byte)] = value;
            }
        }
    } else if case.name.starts_with("edge vscalefpd") {
        let scalars = [
            0x3ff0_0000_0000_0000_u64,
            0xbff0_0000_0000_0000,
            0,
            0x7ff0_0000_0000_0000,
            0x7fef_ffff_ffff_ffff,
            1,
            0x000f_ffff_ffff_ffff,
            0x7ff8_1234_5678_9abc,
        ];
        let scales = [
            0x4005_9999_9999_999a_u64,
            0xc000_cccc_cccc_cccd,
            0x7ff0_0000_0000_0000,
            0xfff0_0000_0000_0000,
            0xc090_cc00_0000_0000,
            0x3ff0_0000_0000_0000,
            0xc090_cc00_0000_0000,
            0x7ff0_0000_0000_0001,
        ];
        for lane in 0..8 {
            for (byte, value) in scalars[lane].to_le_bytes().into_iter().enumerate() {
                image[zmm_byte_offset(2, lane * 8 + byte)] = value;
            }
            for (byte, value) in scales[lane].to_le_bytes().into_iter().enumerate() {
                image[zmm_byte_offset(3, lane * 8 + byte)] = value;
            }
        }
    } else if case.name.starts_with("edge vscalefps") {
        let scalars = [
            0x3f80_0000_u32,
            0xbf80_0000,
            0,
            0x8000_0000,
            0x7f80_0000,
            0xff80_0000,
            0x7fc1_2345,
            0x7f80_0001,
            0x0080_0000,
            1,
            0x7f7f_ffff,
            0xff7f_ffff,
            0x3fc0_0000,
            0xbfc0_0000,
            0x4000_0000,
            0xc000_0000,
        ];
        let scales = [
            0x402c_cccd_u32,
            0xc006_6666,
            0x7f80_0000,
            0xff80_0000,
            0x7fc1_2345,
            0x7f80_0001,
            0x4316_0000,
            0xc316_0000,
            0xbf80_0000,
            0x3f80_0000,
            0x4300_0000,
            0xc316_0000,
            0x3fc0_0000,
            0xbfc0_0000,
            0,
            0x8000_0000,
        ];
        for lane in 0..16 {
            for (byte, value) in scalars[lane].to_le_bytes().into_iter().enumerate() {
                image[zmm_byte_offset(2, lane * 4 + byte)] = value;
            }
            for (byte, value) in scales[lane].to_le_bytes().into_iter().enumerate() {
                image[zmm_byte_offset(3, lane * 4 + byte)] = value;
            }
        }
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
        ("aes", std::is_x86_feature_detected!("aes")),
        ("pclmulqdq", std::is_x86_feature_detected!("pclmulqdq")),
        ("avx2", std::is_x86_feature_detected!("avx2")),
        ("bmi1", std::is_x86_feature_detected!("bmi1")),
        ("bmi2", std::is_x86_feature_detected!("bmi2")),
        ("avx512f", std::is_x86_feature_detected!("avx512f")),
        ("avx512bw", std::is_x86_feature_detected!("avx512bw")),
        ("avx512cd", std::is_x86_feature_detected!("avx512cd")),
        ("avx512vl", std::is_x86_feature_detected!("avx512vl")),
        ("avx512vbmi", std::is_x86_feature_detected!("avx512vbmi")),
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
    native_with_layout_and_lengths(case, data_offset, protect_tail, None)
}

fn native_with_layout_and_lengths(
    case: Case,
    data_offset: usize,
    protect_tail: bool,
    explicit_lengths: Option<(i32, i32)>,
) -> ResultState {
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
        // Fault-oriented VSIB cases run with PTRACE_CONT because the trap flag
        // is itself an architecturally visible gather interruption point. An
        // INT3 immediately after the case still gives the parent a bounded
        // success stop if every selected lane completes without faulting.
        *(mapping.cast::<u8>().add(case.bytes.len())) = 0xcc;
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
    let mut initial = initial_gprs(code, data);
    if let Some((left, right)) = explicit_lengths {
        initial[0] = left as i64 as u64;
        initial[3] = right as i64 as u64;
    }
    apply_native_regs(&mut regs, initial);
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
    prepare_vsib_case_xstate(case, &mut xstate);
    prepare_special_float_case_xstate(case, &mut xstate);
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
    }
    let mut seeded_xstate = vec![0_u8; xstate.len()];
    let mut seeded_iov = libc::iovec {
        iov_base: seeded_xstate.as_mut_ptr().cast(),
        iov_len: seeded_xstate.len(),
    };
    unsafe {
        checked_ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            NT_X86_XSTATE as *mut c_void,
            (&mut seeded_iov as *mut libc::iovec).cast(),
        );
    }
    seeded_xstate.truncate(seeded_iov.iov_len);
    for offset in defined_xstate_offsets() {
        assert_eq!(
            seeded_xstate[offset], xstate[offset],
            "{}: kernel changed seeded xstate byte {offset:#x}",
            case.name
        );
    }
    unsafe {
        checked_ptrace(
            if case.name.starts_with("vsib fault") {
                libc::PTRACE_CONT
            } else {
                libc::PTRACE_SINGLESTEP
            },
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
    emulated_with_layout_and_lengths(vm, case, code, data_base, data_offset, None)
}

fn emulated_with_layout_and_lengths(
    vm: &mut InterpVm,
    case: Case,
    code: u64,
    data_base: u64,
    data_offset: usize,
    explicit_lengths: Option<(i32, i32)>,
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
    let mut initial = initial_gprs(code, data);
    if let Some((left, right)) = explicit_lengths {
        initial[0] = left as i64 as u64;
        initial[3] = right as i64 as u64;
    }
    for (name, value) in names.into_iter().zip(initial) {
        let register = vm.cpu.arch.sleigh.get_varnode(name).unwrap();
        vm.cpu.write_var(register, value);
    }
    // Ghidra models the arithmetic/control flags as individual one-byte
    // registers. `rflags` is only a packed architectural shadow, so seed the
    // individual registers exactly as the native child was seeded.
    let initial_flags = initial[17];
    for (name, bit) in [
        ("CF", 0),
        ("PF", 2),
        ("AF", 4),
        ("ZF", 6),
        ("SF", 7),
        ("DF", 10),
        ("OF", 11),
        ("AC", 18),
    ] {
        let register = vm.cpu.arch.sleigh.get_varnode(name).unwrap();
        vm.cpu
            .write_var(register, ((initial_flags >> bit) & 1) as u8);
    }
    let mut xstate = vec![0_u8; XSTATE_SIZE];
    fill_xstate(&mut xstate);
    prepare_vsib_case_xstate(case, &mut xstate);
    prepare_special_float_case_xstate(case, &mut xstate);
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
        other => {
            let statement = vm
                .code
                .blocks
                .get(vm.cpu.block_id as usize)
                .and_then(|block| {
                    block
                        .pcode
                        .instructions
                        .get(vm.cpu.block_offset.saturating_sub(1) as usize)
                });
            let block = vm
                .code
                .blocks
                .get(vm.cpu.block_id as usize)
                .map(|block| &block.pcode.instructions);
            panic!(
                "{}: {other:?}; pcode={statement:?}; block={block:?}",
                case.name
            );
        }
    };
    let mut gprs = std::array::from_fn(|index| {
        let register = vm.cpu.arch.sleigh.get_varnode(names[index]).unwrap();
        vm.cpu.read_var::<u64>(register)
    });
    // Repack the independently modelled flag bits so the ptrace comparison
    // observes the values the instruction actually produced, not the stale
    // `rflags` shadow.
    for (name, bit) in [
        ("CF", 0),
        ("PF", 2),
        ("AF", 4),
        ("ZF", 6),
        ("SF", 7),
        ("DF", 10),
        ("OF", 11),
        ("AC", 18),
    ] {
        let register = vm.cpu.arch.sleigh.get_varnode(name).unwrap();
        let value = u64::from(vm.cpu.read_var::<u8>(register) & 1);
        gprs[17] = (gprs[17] & !(1_u64 << bit)) | (value << bit);
    }
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
    // RSP is never an output in these one-instruction cases, so it retains the
    // native mapping-derived input and gives us an unambiguous address anchor.
    // Normalize address-bearing registers only while they still contain that
    // input. Unconditionally replacing RSI/RDI would hide legitimate outputs
    // from instructions whose destination happens to be ESI/RSI or EDI/RDI.
    let native_data = state.gprs[7].wrapping_sub(0x800);
    let canonical_data = 0x2000 + data_offset as u64;
    for value in &mut state.gprs[..16] {
        if *value == native_data {
            *value = canonical_data;
        } else if *value == native_data.wrapping_add(0x800) {
            *value = canonical_data.wrapping_add(0x800);
        }
    }
    let native_code = if faulted {
        state.gprs[16]
    } else {
        state.gprs[16].wrapping_sub(case.bytes.len() as u64)
    };
    for value in &mut state.gprs[..16] {
        if *value == native_code {
            *value = 0x1000;
        }
    }
    state.gprs[16] = 0x1000 + if faulted { 0 } else { case.bytes.len() as u64 };
    state
}

#[test]
fn vex_avx2_and_evex_families_match_native_gprs_and_xstate_bit_for_bit() {
    let cases = [
        Case {
            name: "andn rax,rbx,rcx",
            bytes: &[0xc4, 0xe2, 0xe0, 0xf2, 0xc1],
        },
        Case {
            name: "bextr rdx,r8,r9",
            bytes: &[0xc4, 0xc2, 0xb0, 0xf7, 0xd0],
        },
        Case {
            name: "blsi r10,r11",
            bytes: &[0xc4, 0xc2, 0xa8, 0xf3, 0xdb],
        },
        Case {
            name: "blsmsk r12,r13",
            bytes: &[0xc4, 0xc2, 0x98, 0xf3, 0xd5],
        },
        Case {
            name: "blsr r14,r15",
            bytes: &[0xc4, 0xc2, 0x88, 0xf3, 0xcf],
        },
        Case {
            name: "tzcnt rax,rbx",
            bytes: &[0xf3, 0x48, 0x0f, 0xbc, 0xc3],
        },
        Case {
            name: "bzhi rcx,rdx,r8",
            bytes: &[0xc4, 0xe2, 0xb8, 0xf5, 0xca],
        },
        Case {
            name: "mulx r9,r10,r11",
            bytes: &[0xc4, 0x42, 0xab, 0xf6, 0xcb],
        },
        Case {
            name: "pdep r12,r13,r14",
            bytes: &[0xc4, 0x42, 0x93, 0xf5, 0xe6],
        },
        Case {
            name: "pext r15,rax,rbx",
            bytes: &[0xc4, 0x62, 0xfa, 0xf5, 0xfb],
        },
        Case {
            name: "rorx rcx,rdx,13",
            bytes: &[0xc4, 0xe3, 0xfb, 0xf0, 0xca, 0x0d],
        },
        Case {
            name: "sarx r8,r9,r10",
            bytes: &[0xc4, 0x42, 0xaa, 0xf7, 0xc1],
        },
        Case {
            name: "shlx r11,r12,r13",
            bytes: &[0xc4, 0x42, 0x91, 0xf7, 0xdc],
        },
        Case {
            name: "shrx r14,r15,rax",
            bytes: &[0xc4, 0x42, 0xfb, 0xf7, 0xf7],
        },
        Case {
            name: "vaesdec xmm1,xmm2,xmm3",
            bytes: &[0xc4, 0xe2, 0x69, 0xde, 0xcb],
        },
        Case {
            name: "vaesdeclast xmm4,xmm5,xmm6",
            bytes: &[0xc4, 0xe2, 0x51, 0xdf, 0xe6],
        },
        Case {
            name: "vaesenc xmm7,xmm8,xmm9",
            bytes: &[0xc4, 0xc2, 0x39, 0xdc, 0xf9],
        },
        Case {
            name: "vaesenclast xmm10,xmm11,xmm12",
            bytes: &[0xc4, 0x42, 0x21, 0xdd, 0xd4],
        },
        Case {
            name: "vaesimc xmm13,xmm14",
            bytes: &[0xc4, 0x42, 0x79, 0xdb, 0xee],
        },
        Case {
            name: "vaeskeygenassist xmm0,xmm1,0x5a",
            bytes: &[0xc4, 0xe3, 0x79, 0xdf, 0xc1, 0x5a],
        },
        Case {
            name: "vpclmullqlqdq xmm1,xmm2,xmm3",
            bytes: &[0xc4, 0xe3, 0x69, 0x44, 0xcb, 0x00],
        },
        Case {
            name: "vpclmulhqhqdq xmm4,xmm5,[rdi]",
            bytes: &[0xc4, 0xe3, 0x51, 0x44, 0x27, 0x11],
        },
        Case {
            name: "vcomisd xmm17,xmm18",
            bytes: &[0x62, 0xa1, 0xfd, 0x08, 0x2f, 0xca],
        },
        Case {
            name: "vcomiss xmm19,xmm20",
            bytes: &[0x62, 0xa1, 0x7c, 0x08, 0x2f, 0xdc],
        },
        Case {
            name: "vcmpeqpd k1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf1, 0xe5, 0x0a, 0xc2, 0xcc, 0x00],
        },
        Case {
            name: "vcmpnle_uqpd k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf1, 0xd5, 0x2c, 0xc2, 0xde, 0x16],
        },
        Case {
            name: "vcmptrue_uspd k5{k6},zmm7,zmm8",
            bytes: &[0x62, 0xd1, 0xc5, 0x4e, 0xc2, 0xe8, 0x1f],
        },
        Case {
            name: "vcmplt_oqps k1{k3},xmm9,xmm10",
            bytes: &[0x62, 0xd1, 0x34, 0x0b, 0xc2, 0xca, 0x11],
        },
        Case {
            name: "vcmpneq_usps k2{k4},ymm11,ymm12",
            bytes: &[0x62, 0xd1, 0x24, 0x2c, 0xc2, 0xd4, 0x14],
        },
        Case {
            name: "vcmpord_sps k5{k6},zmm13,zmm14",
            bytes: &[0x62, 0xd1, 0x14, 0x4e, 0xc2, 0xee, 0x17],
        },
        Case {
            name: "vcmpeqsd k7{k2},xmm15,xmm16",
            bytes: &[0x62, 0xb1, 0x87, 0x0a, 0xc2, 0xf8, 0x00],
        },
        Case {
            name: "vcmpfalse_osss k1{k3},xmm17,xmm18",
            bytes: &[0x62, 0xb1, 0x76, 0x03, 0xc2, 0xca, 0x1b],
        },
        Case {
            name: "vextractf64x4 ymm1{k2},zmm3,1",
            bytes: &[0x62, 0xf3, 0xfd, 0x4a, 0x1b, 0xd9, 0x01],
        },
        Case {
            name: "vextractf64x4 [rdi]{k3},zmm4,0",
            bytes: &[0x62, 0xf3, 0xfd, 0x4b, 0x1b, 0x27, 0x00],
        },
        Case {
            name: "vextracti64x4 [rdi]{k4},zmm5,1",
            bytes: &[0x62, 0xf3, 0xfd, 0x4c, 0x3b, 0x2f, 0x01],
        },
        Case {
            name: "vinsertf64x4 zmm6{k5}{z},zmm7,ymm8,1",
            bytes: &[0x62, 0xd3, 0xc5, 0xcd, 0x1a, 0xf0, 0x01],
        },
        Case {
            name: "vinsertf32x4 ymm1{k2},ymm3,xmm4,1",
            bytes: &[0x62, 0xf3, 0x65, 0x2a, 0x18, 0xcc, 0x01],
        },
        Case {
            name: "vinsertf32x4 zmm5{k3}{z},zmm6,xmm7,2",
            bytes: &[0x62, 0xf3, 0x4d, 0xcb, 0x18, 0xef, 0x02],
        },
        Case {
            name: "vinserti32x4 ymm8{k4}{z},ymm9,xmm10,1",
            bytes: &[0x62, 0x53, 0x35, 0xac, 0x38, 0xc2, 0x01],
        },
        Case {
            name: "vinserti32x4 zmm11{k5},zmm12,xmm13,3",
            bytes: &[0x62, 0x53, 0x1d, 0x4d, 0x38, 0xdd, 0x03],
        },
        Case {
            name: "vbroadcastf64x4 zmm1{k2},[rdi]",
            bytes: &[0x62, 0xf2, 0xfd, 0x4a, 0x1b, 0x0f],
        },
        Case {
            name: "vbroadcasti64x4 zmm3{k4}{z},[rdi]",
            bytes: &[0x62, 0xf2, 0xfd, 0xcc, 0x5b, 0x1f],
        },
        Case {
            name: "valignq xmm1{k2},xmm3,xmm4,1",
            bytes: &[0x62, 0xf3, 0xe5, 0x0a, 0x03, 0xcc, 0x01],
        },
        Case {
            name: "valignq ymm5{k3}{z},ymm6,ymm7,3",
            bytes: &[0x62, 0xf3, 0xcd, 0xab, 0x03, 0xef, 0x03],
        },
        Case {
            name: "valignq zmm8{k4},zmm9,zmm10,7",
            bytes: &[0x62, 0x53, 0xb5, 0x4c, 0x03, 0xc2, 0x07],
        },
        Case {
            name: "vblendmpd xmm1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0xe5, 0x0a, 0x65, 0xcc],
        },
        Case {
            name: "vblendmpd ymm5{k3}{z},ymm6,ymm7",
            bytes: &[0x62, 0xf2, 0xcd, 0xab, 0x65, 0xef],
        },
        Case {
            name: "vblendmpd zmm8{k4},zmm9,zmm10",
            bytes: &[0x62, 0x52, 0xb5, 0x4c, 0x65, 0xc2],
        },
        Case {
            name: "vblendmps xmm11{k5}{z},xmm12,xmm13",
            bytes: &[0x62, 0x52, 0x1d, 0x8d, 0x65, 0xdd],
        },
        Case {
            name: "vblendmps ymm14{k6},ymm15,ymm16",
            bytes: &[0x62, 0x32, 0x05, 0x2e, 0x65, 0xf0],
        },
        Case {
            name: "vblendmps zmm17{k7}{z},zmm18,zmm19",
            bytes: &[0x62, 0xa2, 0x6d, 0xc7, 0x65, 0xcb],
        },
        Case {
            name: "vpblendmb xmm1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0x65, 0x0a, 0x66, 0xcc],
        },
        Case {
            name: "vpblendmw ymm5{k3},ymm6,ymm7",
            bytes: &[0x62, 0xf2, 0xcd, 0x2b, 0x66, 0xef],
        },
        Case {
            name: "vpblendmd zmm8{k4},zmm9,zmm10",
            bytes: &[0x62, 0x52, 0x35, 0x4c, 0x64, 0xc2],
        },
        Case {
            name: "vpblendmq zmm11{k5},zmm12,zmm13",
            bytes: &[0x62, 0x52, 0x9d, 0x4d, 0x64, 0xdd],
        },
        Case {
            name: "vpbroadcastmb2q xmm1,k2",
            bytes: &[0x62, 0xf2, 0xfe, 0x08, 0x2a, 0xca],
        },
        Case {
            name: "vpbroadcastmb2q ymm3,k4",
            bytes: &[0x62, 0xf2, 0xfe, 0x28, 0x2a, 0xdc],
        },
        Case {
            name: "vpbroadcastmb2q zmm5,k6",
            bytes: &[0x62, 0xf2, 0xfe, 0x48, 0x2a, 0xee],
        },
        Case {
            name: "vpbroadcastmw2d xmm7,k1",
            bytes: &[0x62, 0xf2, 0x7e, 0x08, 0x3a, 0xf9],
        },
        Case {
            name: "vpbroadcastmw2d ymm8,k3",
            bytes: &[0x62, 0x72, 0x7e, 0x28, 0x3a, 0xc3],
        },
        Case {
            name: "vpbroadcastmw2d zmm9,k5",
            bytes: &[0x62, 0x72, 0x7e, 0x48, 0x3a, 0xcd],
        },
        Case {
            name: "vpconflictd xmm1{k2},xmm3",
            bytes: &[0x62, 0xf2, 0x7d, 0x0a, 0xc4, 0xcb],
        },
        Case {
            name: "vpconflictd ymm4{k3}{z},ymm5",
            bytes: &[0x62, 0xf2, 0x7d, 0xab, 0xc4, 0xe5],
        },
        Case {
            name: "vpconflictd zmm6{k4},zmm7",
            bytes: &[0x62, 0xf2, 0x7d, 0x4c, 0xc4, 0xf7],
        },
        Case {
            name: "vpconflictq xmm8{k5}{z},xmm9",
            bytes: &[0x62, 0x52, 0xfd, 0x8d, 0xc4, 0xc1],
        },
        Case {
            name: "vpconflictq ymm10{k6},ymm11",
            bytes: &[0x62, 0x52, 0xfd, 0x2e, 0xc4, 0xd3],
        },
        Case {
            name: "vpconflictq zmm12{k7}{z},zmm13",
            bytes: &[0x62, 0x52, 0xfd, 0xcf, 0xc4, 0xe5],
        },
        Case {
            name: "vpermw xmm1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0xe5, 0x0a, 0x8d, 0xcc],
        },
        Case {
            name: "vpermw ymm5{k3}{z},ymm6,ymm7",
            bytes: &[0x62, 0xf2, 0xcd, 0xab, 0x8d, 0xef],
        },
        Case {
            name: "vpermw zmm8{k4},zmm9,zmm10",
            bytes: &[0x62, 0x52, 0xb5, 0x4c, 0x8d, 0xc2],
        },
        Case {
            name: "vpermi2w xmm11{k5}{z},xmm12,xmm13",
            bytes: &[0x62, 0x52, 0x9d, 0x8d, 0x75, 0xdd],
        },
        Case {
            name: "vpermi2w ymm14{k6},ymm15,ymm16",
            bytes: &[0x62, 0x32, 0x85, 0x2e, 0x75, 0xf0],
        },
        Case {
            name: "vpermi2w zmm17{k7}{z},zmm18,zmm19",
            bytes: &[0x62, 0xa2, 0xed, 0xc7, 0x75, 0xcb],
        },
        Case {
            name: "vpermt2w xmm20{k2},xmm21,xmm22",
            bytes: &[0x62, 0xa2, 0xd5, 0x02, 0x7d, 0xe6],
        },
        Case {
            name: "vpermt2w ymm23{k3}{z},ymm24,ymm25",
            bytes: &[0x62, 0x82, 0xbd, 0xa3, 0x7d, 0xf9],
        },
        Case {
            name: "vpermt2w zmm26{k4},zmm27,zmm28",
            bytes: &[0x62, 0x02, 0xa5, 0x44, 0x7d, 0xd4],
        },
        Case {
            name: "vpshldvw xmm1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0xe5, 0x0a, 0x70, 0xcc],
        },
        Case {
            name: "vpshldvd ymm5{k3}{z},ymm6,ymm7",
            bytes: &[0x62, 0xf2, 0x4d, 0xab, 0x71, 0xef],
        },
        Case {
            name: "vpshldvq zmm8{k4},zmm9,zmm10",
            bytes: &[0x62, 0x52, 0xb5, 0x4c, 0x71, 0xc2],
        },
        Case {
            name: "vpshrdvw xmm11{k5}{z},xmm12,xmm13",
            bytes: &[0x62, 0x52, 0x9d, 0x8d, 0x72, 0xdd],
        },
        Case {
            name: "vpshrdvd ymm14{k6},ymm15,ymm16",
            bytes: &[0x62, 0x32, 0x05, 0x2e, 0x73, 0xf0],
        },
        Case {
            name: "vpshrdvq zmm17{k7}{z},zmm18,zmm19",
            bytes: &[0x62, 0xa2, 0xed, 0xc7, 0x73, 0xcb],
        },
        Case {
            name: "vdbpsadbw xmm1,xmm3,xmm4,0xe4",
            bytes: &[0x62, 0xf3, 0x65, 0x08, 0x42, 0xcc, 0xe4],
        },
        Case {
            name: "vdbpsadbw ymm5{k3}{z},ymm6,ymm7,0x1b",
            bytes: &[0x62, 0xf3, 0x4d, 0xab, 0x42, 0xef, 0x1b],
        },
        Case {
            name: "vdbpsadbw zmm8{k4},zmm9,zmm10,0x72",
            bytes: &[0x62, 0x53, 0x35, 0x4c, 0x42, 0xc2, 0x72],
        },
        Case {
            name: "vpmovm2w xmm1,k2",
            bytes: &[0x62, 0xf2, 0xfe, 0x08, 0x28, 0xca],
        },
        Case {
            name: "vpmovm2w ymm3,k4",
            bytes: &[0x62, 0xf2, 0xfe, 0x28, 0x28, 0xdc],
        },
        Case {
            name: "vpmovm2w zmm5,k6",
            bytes: &[0x62, 0xf2, 0xfe, 0x48, 0x28, 0xee],
        },
        Case {
            name: "vpmovw2m k1,xmm7",
            bytes: &[0x62, 0xf2, 0xfe, 0x08, 0x29, 0xcf],
        },
        Case {
            name: "vpmovw2m k3,ymm8",
            bytes: &[0x62, 0xd2, 0xfe, 0x28, 0x29, 0xd8],
        },
        Case {
            name: "vpmovw2m k5,zmm9",
            bytes: &[0x62, 0xd2, 0xfe, 0x48, 0x29, 0xe9],
        },
        Case {
            name: "vpmovdb xmm1{k2},zmm3",
            bytes: &[0x62, 0xf2, 0x7e, 0x4a, 0x31, 0xd9],
        },
        Case {
            name: "vpmovsdb xmm4{k3}{z},zmm5",
            bytes: &[0x62, 0xf2, 0x7e, 0xcb, 0x21, 0xec],
        },
        Case {
            name: "vpmovusdb xmm6{k4},zmm7",
            bytes: &[0x62, 0xf2, 0x7e, 0x4c, 0x11, 0xfe],
        },
        Case {
            name: "vpmovdw ymm8{k5},zmm9",
            bytes: &[0x62, 0x52, 0x7e, 0x4d, 0x33, 0xc8],
        },
        Case {
            name: "vpmovsdw ymm10{k6}{z},zmm11",
            bytes: &[0x62, 0x52, 0x7e, 0xce, 0x23, 0xda],
        },
        Case {
            name: "vpmovusdw ymm12{k7},zmm13",
            bytes: &[0x62, 0x52, 0x7e, 0x4f, 0x13, 0xec],
        },
        Case {
            name: "vpmovqb xmm14{k2},zmm15",
            bytes: &[0x62, 0x52, 0x7e, 0x4a, 0x32, 0xfe],
        },
        Case {
            name: "vpmovsqb xmm16{k3}{z},zmm17",
            bytes: &[0x62, 0xa2, 0x7e, 0xcb, 0x22, 0xc8],
        },
        Case {
            name: "vpmovusqb xmm18{k4},zmm19",
            bytes: &[0x62, 0xa2, 0x7e, 0x4c, 0x12, 0xda],
        },
        Case {
            name: "vpmovqw xmm20{k5},zmm21",
            bytes: &[0x62, 0xa2, 0x7e, 0x4d, 0x34, 0xec],
        },
        Case {
            name: "vpmovsqw xmm22{k6}{z},zmm23",
            bytes: &[0x62, 0xa2, 0x7e, 0xce, 0x24, 0xfe],
        },
        Case {
            name: "vpmovusqw xmm24{k7},zmm25",
            bytes: &[0x62, 0x02, 0x7e, 0x4f, 0x14, 0xc8],
        },
        Case {
            name: "vpmovqd ymm26{k2},zmm27",
            bytes: &[0x62, 0x02, 0x7e, 0x4a, 0x35, 0xda],
        },
        Case {
            name: "vpmovsqd ymm28{k3}{z},zmm29",
            bytes: &[0x62, 0x02, 0x7e, 0xcb, 0x25, 0xec],
        },
        Case {
            name: "vpmovusqd ymm30{k4},zmm31",
            bytes: &[0x62, 0x02, 0x7e, 0x4c, 0x15, 0xfe],
        },
        Case {
            name: "vpmovswb ymm1{k5},zmm2",
            bytes: &[0x62, 0xf2, 0x7e, 0x4d, 0x20, 0xd1],
        },
        Case {
            name: "vpmovuswb ymm3{k6}{z},zmm4",
            bytes: &[0x62, 0xf2, 0x7e, 0xce, 0x10, 0xe3],
        },
        Case {
            name: "vcvtdq2pd zmm1{k2},ymm3",
            bytes: &[0x62, 0xf1, 0x7e, 0x4a, 0xe6, 0xcb],
        },
        Case {
            name: "vcvtdq2ps zmm4{k3}{z},zmm5",
            bytes: &[0x62, 0xf1, 0x7c, 0xcb, 0x5b, 0xe5],
        },
        Case {
            name: "vcvtpd2dq ymm6{k4},zmm7",
            bytes: &[0x62, 0xf1, 0xff, 0x4c, 0xe6, 0xf7],
        },
        Case {
            name: "vcvtpd2ps ymm8{k5}{z},zmm9",
            bytes: &[0x62, 0x51, 0xfd, 0xcd, 0x5a, 0xc1],
        },
        Case {
            name: "vcvtpd2udq ymm10{k6},zmm11",
            bytes: &[0x62, 0x51, 0xfc, 0x4e, 0x79, 0xd3],
        },
        Case {
            name: "vcvtph2ps zmm12{k7}{z},ymm13",
            bytes: &[0x62, 0x52, 0x7d, 0xcf, 0x13, 0xe5],
        },
        Case {
            name: "vcvtps2dq zmm14{k2},zmm15",
            bytes: &[0x62, 0x51, 0x7d, 0x4a, 0x5b, 0xf7],
        },
        Case {
            name: "vcvtps2pd zmm16{k3}{z},ymm17",
            bytes: &[0x62, 0xa1, 0x7c, 0xcb, 0x5a, 0xc1],
        },
        Case {
            name: "vcvtps2ph ymm18{k4},zmm19,3",
            bytes: &[0x62, 0xa3, 0x7d, 0x4c, 0x1d, 0xda, 0x03],
        },
        Case {
            name: "vcvtps2udq zmm20{k5}{z},zmm21",
            bytes: &[0x62, 0xa1, 0x7c, 0xcd, 0x79, 0xe5],
        },
        Case {
            name: "vcvttpd2dq ymm22{k6},zmm23",
            bytes: &[0x62, 0xa1, 0xfd, 0x4e, 0xe6, 0xf7],
        },
        Case {
            name: "vcvttpd2udq ymm24{k7}{z},zmm25",
            bytes: &[0x62, 0x01, 0xfc, 0xcf, 0x78, 0xc1],
        },
        Case {
            name: "vcvttps2dq zmm26{k2},zmm27",
            bytes: &[0x62, 0x01, 0x7e, 0x4a, 0x5b, 0xd3],
        },
        Case {
            name: "vcvttps2udq zmm28{k3}{z},zmm29",
            bytes: &[0x62, 0x01, 0x7c, 0xcb, 0x78, 0xe5],
        },
        Case {
            name: "vcvtudq2pd zmm30{k4},ymm31",
            bytes: &[0x62, 0x01, 0x7e, 0x4c, 0x7a, 0xf7],
        },
        Case {
            name: "vcvtudq2ps zmm1{k5}{z},zmm2",
            bytes: &[0x62, 0xf1, 0x7f, 0xcd, 0x7a, 0xca],
        },
        Case {
            name: "vcvtsd2si rax,xmm3,{rn-sae}",
            bytes: &[0x62, 0xf1, 0xff, 0x18, 0x2d, 0xc3],
        },
        Case {
            name: "vcvtsd2ss xmm4{k2},xmm5,xmm6",
            bytes: &[0x62, 0xf1, 0xd7, 0x0a, 0x5a, 0xe6],
        },
        Case {
            name: "vcvtsd2usi rbx,xmm7",
            bytes: &[0x62, 0xf1, 0xff, 0x08, 0x79, 0xdf],
        },
        Case {
            name: "vcvtsi2sd xmm8,xmm9,r10,{rn-sae}",
            bytes: &[0x62, 0x51, 0xb7, 0x18, 0x2a, 0xc2],
        },
        Case {
            name: "vcvtsi2ss xmm11,xmm12,r13,{rd-sae}",
            bytes: &[0x62, 0x51, 0x9e, 0x38, 0x2a, 0xdd],
        },
        Case {
            name: "vcvtss2sd xmm14{k3}{z},xmm15,xmm16",
            bytes: &[0x62, 0x31, 0x06, 0x8b, 0x5a, 0xf0],
        },
        Case {
            name: "vcvtss2si r14d,xmm17",
            bytes: &[0x62, 0x31, 0x7e, 0x08, 0x2d, 0xf1],
        },
        Case {
            name: "vcvtss2usi r15,xmm18",
            bytes: &[0x62, 0x31, 0xfe, 0x08, 0x79, 0xfa],
        },
        Case {
            name: "vcvttsd2si rcx,xmm19",
            bytes: &[0x62, 0xb1, 0xff, 0x08, 0x2c, 0xcb],
        },
        Case {
            name: "vcvttsd2usi rdx,xmm20",
            bytes: &[0x62, 0xb1, 0xff, 0x08, 0x78, 0xd4],
        },
        Case {
            name: "vcvttss2si esi,xmm21",
            bytes: &[0x62, 0xb1, 0x7e, 0x08, 0x2c, 0xf5],
        },
        Case {
            name: "vcvttss2usi rdi,xmm22",
            bytes: &[0x62, 0xb1, 0xfe, 0x08, 0x78, 0xfe],
        },
        Case {
            name: "vcvtusi2sd xmm23,xmm24,r8",
            bytes: &[0x62, 0xc1, 0xbf, 0x00, 0x7b, 0xf8],
        },
        Case {
            name: "vcvtusi2ss xmm25,xmm26,r9",
            bytes: &[0x62, 0x41, 0xae, 0x00, 0x7b, 0xc9],
        },
        Case {
            name: "vfixupimmpd zmm1{k2},zmm2,zmm3,0xa5",
            bytes: &[0x62, 0xf3, 0xed, 0x4a, 0x54, 0xcb, 0xa5],
        },
        Case {
            name: "vfixupimmps zmm4{k3}{z},zmm5,zmm6,0x5a",
            bytes: &[0x62, 0xf3, 0x55, 0xcb, 0x54, 0xe6, 0x5a],
        },
        Case {
            name: "vfixupimmsd xmm7{k4},xmm8,xmm9,0x3c",
            bytes: &[0x62, 0xd3, 0xbd, 0x0c, 0x55, 0xf9, 0x3c],
        },
        Case {
            name: "vfixupimmss xmm10{k5}{z},xmm11,xmm12,0xc3",
            bytes: &[0x62, 0x53, 0x25, 0x8d, 0x55, 0xd4, 0xc3],
        },
        Case {
            name: "vgetexppd zmm13{k6},zmm14",
            bytes: &[0x62, 0x52, 0xfd, 0x4e, 0x42, 0xee],
        },
        Case {
            name: "vgetexpps zmm15{k7}{z},zmm16",
            bytes: &[0x62, 0x32, 0x7d, 0xcf, 0x42, 0xf8],
        },
        Case {
            name: "vgetexpsd xmm17{k2},xmm18,xmm19",
            bytes: &[0x62, 0xa2, 0xed, 0x02, 0x43, 0xcb],
        },
        Case {
            name: "vgetexpss xmm20{k3}{z},xmm21,xmm22",
            bytes: &[0x62, 0xa2, 0x55, 0x83, 0x43, 0xe6],
        },
        Case {
            name: "vgetmantpd zmm23{k4},zmm24,0x3",
            bytes: &[0x62, 0x83, 0xfd, 0x4c, 0x26, 0xf8, 0x03],
        },
        Case {
            name: "vgetmantps zmm25{k5}{z},zmm26,0x8",
            bytes: &[0x62, 0x03, 0x7d, 0xcd, 0x26, 0xca, 0x08],
        },
        Case {
            name: "vgetmantsd xmm27{k6},xmm28,xmm29,0x1",
            bytes: &[0x62, 0x03, 0x9d, 0x06, 0x27, 0xdd, 0x01],
        },
        Case {
            name: "vgetmantss xmm30{k7}{z},xmm31,xmm1,0x2",
            bytes: &[0x62, 0x63, 0x05, 0x87, 0x27, 0xf1, 0x02],
        },
        Case {
            name: "vrndscalepd zmm12{k6},zmm13,0x23",
            bytes: &[0x62, 0x53, 0xfd, 0x4e, 0x09, 0xe5, 0x23],
        },
        Case {
            name: "vrndscaleps zmm14{k7}{z},zmm15,0xd1",
            bytes: &[0x62, 0x53, 0x7d, 0xcf, 0x08, 0xf7, 0xd1],
        },
        Case {
            name: "vrndscalesd xmm16{k2},xmm17,xmm18,0x14",
            bytes: &[0x62, 0xa3, 0xf5, 0x02, 0x0b, 0xc2, 0x14],
        },
        Case {
            name: "vrndscaless xmm19{k3}{z},xmm20,xmm21,0xe2",
            bytes: &[0x62, 0xa3, 0x5d, 0x83, 0x0a, 0xdd, 0xe2],
        },
        Case {
            name: "vscalefpd zmm0{k2},zmm1,zmm2",
            bytes: &[0x62, 0xf2, 0xf5, 0x4a, 0x2c, 0xc2],
        },
        Case {
            name: "vscalefps zmm3{k3}{z},zmm4,zmm5",
            bytes: &[0x62, 0xf2, 0x5d, 0xcb, 0x2c, 0xdd],
        },
        Case {
            name: "vscalefsd xmm6{k4},xmm7,xmm8",
            bytes: &[0x62, 0xd2, 0xc5, 0x0c, 0x2d, 0xf0],
        },
        Case {
            name: "vscalefss xmm9{k5}{z},xmm10,xmm11",
            bytes: &[0x62, 0x52, 0x2d, 0x8d, 0x2d, 0xcb],
        },
        Case {
            name: "vfmadd132pd xmm1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf2, 0xe5, 0x0a, 0x98, 0xcc],
        },
        Case {
            name: "vfmadd213ps ymm5{k3}{z},ymm6,ymm7",
            bytes: &[0x62, 0xf2, 0x4d, 0xab, 0xa8, 0xef],
        },
        Case {
            name: "vfmadd231pd zmm8{k4},zmm9,zmm10",
            bytes: &[0x62, 0x52, 0xb5, 0x4c, 0xb8, 0xc2],
        },
        Case {
            name: "vfmadd132sd xmm11{k5}{z},xmm12,xmm13",
            bytes: &[0x62, 0x52, 0x9d, 0x8d, 0x99, 0xdd],
        },
        Case {
            name: "vfmadd213ss xmm14{k6},xmm15,xmm16",
            bytes: &[0x62, 0x32, 0x05, 0x0e, 0xa9, 0xf0],
        },
        Case {
            name: "vfmsub132ps xmm17{k7}{z},xmm18,xmm19",
            bytes: &[0x62, 0xa2, 0x6d, 0x87, 0x9a, 0xcb],
        },
        Case {
            name: "vfmsub213pd ymm20{k2},ymm21,ymm22",
            bytes: &[0x62, 0xa2, 0xd5, 0x22, 0xaa, 0xe6],
        },
        Case {
            name: "vfmsub231ps zmm23{k3}{z},zmm24,zmm25",
            bytes: &[0x62, 0x82, 0x3d, 0xc3, 0xba, 0xf9],
        },
        Case {
            name: "vfnmadd132pd xmm26{k4},xmm27,xmm28",
            bytes: &[0x62, 0x02, 0xa5, 0x04, 0x9c, 0xd4],
        },
        Case {
            name: "vfnmadd213ps ymm1{k5}{z},ymm2,ymm3",
            bytes: &[0x62, 0xf2, 0x6d, 0xad, 0xac, 0xcb],
        },
        Case {
            name: "vfnmadd231pd zmm4{k6},zmm5,zmm6",
            bytes: &[0x62, 0xf2, 0xd5, 0x4e, 0xbc, 0xe6],
        },
        Case {
            name: "vfnmsub132ps xmm7{k7}{z},xmm8,xmm9",
            bytes: &[0x62, 0xd2, 0x3d, 0x8f, 0x9e, 0xf9],
        },
        Case {
            name: "vfnmsub213pd ymm10{k2},ymm11,ymm12",
            bytes: &[0x62, 0x52, 0xa5, 0x2a, 0xae, 0xd4],
        },
        Case {
            name: "vfnmsub231ps zmm13{k3}{z},zmm14,zmm15",
            bytes: &[0x62, 0x52, 0x0d, 0xcb, 0xbe, 0xef],
        },
        Case {
            name: "vfmaddsub132pd xmm16{k4},xmm17,xmm18",
            bytes: &[0x62, 0xa2, 0xf5, 0x04, 0x96, 0xc2],
        },
        Case {
            name: "vfmaddsub213ps ymm19{k5}{z},ymm20,ymm21",
            bytes: &[0x62, 0xa2, 0x5d, 0xa5, 0xa6, 0xdd],
        },
        Case {
            name: "vfmaddsub231pd zmm22{k6},zmm23,zmm24",
            bytes: &[0x62, 0x82, 0xc5, 0x46, 0xb6, 0xf0],
        },
        Case {
            name: "vfmsubadd132ps xmm1{k7}{z},xmm2,xmm3",
            bytes: &[0x62, 0xf2, 0x6d, 0x8f, 0x97, 0xcb],
        },
        Case {
            name: "vfmsubadd213pd ymm28{k2},ymm29,ymm30",
            bytes: &[0x62, 0x02, 0x95, 0x22, 0xa7, 0xe6],
        },
        Case {
            name: "vfmsubadd231ps zmm1{k3}{z},zmm2,zmm3",
            bytes: &[0x62, 0xf2, 0x6d, 0xcb, 0xb7, 0xcb],
        },
        Case {
            name: "vcompresspd xmm1{k2},xmm3",
            bytes: &[0x62, 0xf2, 0xfd, 0x0a, 0x8a, 0xd9],
        },
        Case {
            name: "vcompresspd ymm4{k3}{z},ymm5",
            bytes: &[0x62, 0xf2, 0xfd, 0xab, 0x8a, 0xec],
        },
        Case {
            name: "vcompresspd zmm6{k4},zmm7",
            bytes: &[0x62, 0xf2, 0xfd, 0x4c, 0x8a, 0xfe],
        },
        Case {
            name: "vcompresspd [rdi]{k5},zmm8",
            bytes: &[0x62, 0x72, 0xfd, 0x4d, 0x8a, 0x07],
        },
        Case {
            name: "vcompressps xmm9{k2}{z},xmm10",
            bytes: &[0x62, 0x52, 0x7d, 0x8a, 0x8a, 0xd1],
        },
        Case {
            name: "vcompressps ymm11{k3},ymm12",
            bytes: &[0x62, 0x52, 0x7d, 0x2b, 0x8a, 0xe3],
        },
        Case {
            name: "vcompressps zmm13{k4}{z},zmm14",
            bytes: &[0x62, 0x52, 0x7d, 0xcc, 0x8a, 0xf5],
        },
        Case {
            name: "vcompressps [rdi]{k5},zmm15",
            bytes: &[0x62, 0x72, 0x7d, 0x4d, 0x8a, 0x3f],
        },
        Case {
            name: "vexpandpd xmm1{k2},xmm3",
            bytes: &[0x62, 0xf2, 0xfd, 0x0a, 0x88, 0xcb],
        },
        Case {
            name: "vexpandpd ymm4{k3}{z},ymm5",
            bytes: &[0x62, 0xf2, 0xfd, 0xab, 0x88, 0xe5],
        },
        Case {
            name: "vexpandpd zmm6{k4},zmm7",
            bytes: &[0x62, 0xf2, 0xfd, 0x4c, 0x88, 0xf7],
        },
        Case {
            name: "vexpandpd zmm8{k5}{z},[rsi]",
            bytes: &[0x62, 0x72, 0xfd, 0xcd, 0x88, 0x06],
        },
        Case {
            name: "vexpandps xmm9{k2}{z},xmm10",
            bytes: &[0x62, 0x52, 0x7d, 0x8a, 0x88, 0xca],
        },
        Case {
            name: "vexpandps ymm11{k3},ymm12",
            bytes: &[0x62, 0x52, 0x7d, 0x2b, 0x88, 0xdc],
        },
        Case {
            name: "vexpandps zmm13{k4}{z},zmm14",
            bytes: &[0x62, 0x52, 0x7d, 0xcc, 0x88, 0xee],
        },
        Case {
            name: "vexpandps zmm15{k5},[rsi]",
            bytes: &[0x62, 0x72, 0x7d, 0x4d, 0x88, 0x3e],
        },
        Case {
            name: "vpcompressq xmm1{k2},xmm3",
            bytes: &[0x62, 0xf2, 0xfd, 0x0a, 0x8b, 0xd9],
        },
        Case {
            name: "vpcompressq ymm4{k3}{z},ymm5",
            bytes: &[0x62, 0xf2, 0xfd, 0xab, 0x8b, 0xec],
        },
        Case {
            name: "vpcompressq zmm6{k4},zmm7",
            bytes: &[0x62, 0xf2, 0xfd, 0x4c, 0x8b, 0xfe],
        },
        Case {
            name: "vpcompressq [rdi]{k5},zmm8",
            bytes: &[0x62, 0x72, 0xfd, 0x4d, 0x8b, 0x07],
        },
        Case {
            name: "vpexpandq xmm9{k2}{z},xmm10",
            bytes: &[0x62, 0x52, 0xfd, 0x8a, 0x89, 0xca],
        },
        Case {
            name: "vpexpandq ymm11{k3},ymm12",
            bytes: &[0x62, 0x52, 0xfd, 0x2b, 0x89, 0xdc],
        },
        Case {
            name: "vpexpandq zmm13{k4}{z},zmm14",
            bytes: &[0x62, 0x52, 0xfd, 0xcc, 0x89, 0xee],
        },
        Case {
            name: "vpexpandq zmm15{k5},[rsi]",
            bytes: &[0x62, 0x72, 0xfd, 0x4d, 0x89, 0x3e],
        },
        Case {
            name: "vaddsd xmm1{k2}{z},xmm3,xmm4",
            bytes: &[0x62, 0xf1, 0xe7, 0x8a, 0x58, 0xcc],
        },
        Case {
            name: "vaddss xmm5{k3},xmm6,xmm7",
            bytes: &[0x62, 0xf1, 0x4e, 0x0b, 0x58, 0xef],
        },
        Case {
            name: "vdivsd xmm8{k4}{z},xmm9,xmm10",
            bytes: &[0x62, 0x51, 0xb7, 0x8c, 0x5e, 0xc2],
        },
        Case {
            name: "vdivss xmm11{k5},xmm12,xmm13",
            bytes: &[0x62, 0x51, 0x1e, 0x0d, 0x5e, 0xdd],
        },
        Case {
            name: "vmulsd xmm14{k6}{z},xmm15,xmm16",
            bytes: &[0x62, 0x31, 0x87, 0x8e, 0x59, 0xf0],
        },
        Case {
            name: "vmulss xmm17{k7},xmm18,xmm19",
            bytes: &[0x62, 0xa1, 0x6e, 0x07, 0x59, 0xcb],
        },
        Case {
            name: "vsubsd xmm20{k2}{z},xmm21,xmm22",
            bytes: &[0x62, 0xa1, 0xd7, 0x82, 0x5c, 0xe6],
        },
        Case {
            name: "vsubss xmm23{k3},xmm24,xmm25",
            bytes: &[0x62, 0x81, 0x3e, 0x03, 0x5c, 0xf9],
        },
        Case {
            name: "vmaxsd xmm26{k4}{z},xmm27,xmm28",
            bytes: &[0x62, 0x01, 0xa7, 0x84, 0x5f, 0xd4],
        },
        Case {
            name: "vmaxss xmm29{k5},xmm30,xmm31",
            bytes: &[0x62, 0x01, 0x0e, 0x05, 0x5f, 0xef],
        },
        Case {
            name: "vminsd xmm1{k6}{z},xmm2,xmm3",
            bytes: &[0x62, 0xf1, 0xef, 0x8e, 0x5d, 0xcb],
        },
        Case {
            name: "vminss xmm4{k7},xmm5,xmm6",
            bytes: &[0x62, 0xf1, 0x56, 0x0f, 0x5d, 0xe6],
        },
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
            name: "vperm2f128 ymm0,ymm1,ymm2,0xb8",
            bytes: &[0xc4, 0xe3, 0x75, 0x06, 0xc2, 0xb8],
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
            name: "vextractps eax,xmm6,2",
            bytes: &[0xc4, 0xe3, 0x79, 0x17, 0xf0, 0x02],
        },
        Case {
            name: "vinsertps xmm7,xmm8,xmm9,0xb4",
            bytes: &[0xc4, 0xc3, 0x39, 0x21, 0xf9, 0xb4],
        },
        Case {
            name: "vlddqu ymm1,[rdi]",
            bytes: &[0xc5, 0xff, 0xf0, 0x0f],
        },
        Case {
            name: "vmovntpd [rdi],ymm2",
            bytes: &[0xc5, 0xfd, 0x2b, 0x17],
        },
        Case {
            name: "vmovntps [rdi],ymm3",
            bytes: &[0xc5, 0xfc, 0x2b, 0x1f],
        },
        Case {
            name: "vmovmskpd eax,ymm4",
            bytes: &[0xc5, 0xfd, 0x50, 0xc4],
        },
        Case {
            name: "vmovmskps eax,ymm5",
            bytes: &[0xc5, 0xfc, 0x50, 0xc5],
        },
        Case {
            name: "vstmxcsr [rdi]",
            bytes: &[0xc5, 0xf8, 0xae, 0x1f],
        },
        Case {
            name: "vpmovsxbd xmm1,xmm2",
            bytes: &[0xc4, 0xe2, 0x79, 0x21, 0xca],
        },
        Case {
            name: "vpmovsxbq xmm3,xmm4",
            bytes: &[0xc4, 0xe2, 0x79, 0x22, 0xdc],
        },
        Case {
            name: "vpmovsxwq xmm5,xmm6",
            bytes: &[0xc4, 0xe2, 0x79, 0x24, 0xee],
        },
        Case {
            name: "vpmovzxbq xmm7,xmm8",
            bytes: &[0xc4, 0xc2, 0x79, 0x32, 0xf8],
        },
        Case {
            name: "vpmovzxwq xmm9,xmm10",
            bytes: &[0xc4, 0x42, 0x79, 0x34, 0xca],
        },
        Case {
            name: "vpmovsxbd ymm11,xmm12",
            bytes: &[0xc4, 0x42, 0x7d, 0x21, 0xdc],
        },
        Case {
            name: "vpmovsxbq ymm13,xmm14",
            bytes: &[0xc4, 0x42, 0x7d, 0x22, 0xee],
        },
        Case {
            name: "vpmovsxwq ymm1,xmm2",
            bytes: &[0xc4, 0xe2, 0x7d, 0x24, 0xca],
        },
        Case {
            name: "vpmovzxbq ymm3,xmm4",
            bytes: &[0xc4, 0xe2, 0x7d, 0x32, 0xdc],
        },
        Case {
            name: "vpmovzxwq ymm5,xmm6",
            bytes: &[0xc4, 0xe2, 0x7d, 0x34, 0xee],
        },
        Case {
            name: "vmovhlps xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe8, 0x12, 0xcb],
        },
        Case {
            name: "vmovlhps xmm4,xmm5,xmm6",
            bytes: &[0xc5, 0xd0, 0x16, 0xe6],
        },
        Case {
            name: "vmovhpd xmm7,xmm8,[rdi]",
            bytes: &[0xc5, 0xb9, 0x16, 0x3f],
        },
        Case {
            name: "vmovhpd [rdi],xmm9",
            bytes: &[0xc5, 0x79, 0x17, 0x0f],
        },
        Case {
            name: "vmovhps xmm10,xmm11,[rdi]",
            bytes: &[0xc5, 0x20, 0x16, 0x17],
        },
        Case {
            name: "vmovhps [rdi],xmm12",
            bytes: &[0xc5, 0x78, 0x17, 0x27],
        },
        Case {
            name: "vmovlpd xmm13,xmm14,[rdi]",
            bytes: &[0xc5, 0x09, 0x12, 0x2f],
        },
        Case {
            name: "vmovlpd [rdi],xmm15",
            bytes: &[0xc5, 0x79, 0x13, 0x3f],
        },
        Case {
            name: "vmovlps xmm1,xmm2,[rdi]",
            bytes: &[0xc5, 0xe8, 0x12, 0x0f],
        },
        Case {
            name: "vmovlps [rdi],xmm3",
            bytes: &[0xc5, 0xf8, 0x13, 0x1f],
        },
        Case {
            name: "vpermilpd xmm1,xmm2,xmm3",
            bytes: &[0xc4, 0xe2, 0x69, 0x0d, 0xcb],
        },
        Case {
            name: "vpermilpd ymm4,ymm5,ymm6",
            bytes: &[0xc4, 0xe2, 0x55, 0x0d, 0xe6],
        },
        Case {
            name: "vpermilpd xmm7,xmm8,0x2",
            bytes: &[0xc4, 0xc3, 0x79, 0x05, 0xf8, 0x02],
        },
        Case {
            name: "vpermilpd ymm9,ymm10,0x9",
            bytes: &[0xc4, 0x43, 0x7d, 0x05, 0xca, 0x09],
        },
        Case {
            name: "vpermilps xmm11,xmm12,xmm13",
            bytes: &[0xc4, 0x42, 0x19, 0x0c, 0xdd],
        },
        Case {
            name: "vpermilps ymm14,ymm15,ymm1",
            bytes: &[0xc4, 0x62, 0x05, 0x0c, 0xf1],
        },
        Case {
            name: "vpermilps xmm2,xmm3,0x39",
            bytes: &[0xc4, 0xe3, 0x79, 0x04, 0xd3, 0x39],
        },
        Case {
            name: "vpermilps ymm4,ymm5,0x93",
            bytes: &[0xc4, 0xe3, 0x7d, 0x04, 0xe5, 0x93],
        },
        Case {
            name: "vaddsubpd xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xd0, 0xcb],
        },
        Case {
            name: "vaddsubps ymm4,ymm5,ymm6",
            bytes: &[0xc5, 0xd7, 0xd0, 0xe6],
        },
        Case {
            name: "vhaddps xmm7,xmm8,xmm9",
            bytes: &[0xc4, 0xc1, 0x3b, 0x7c, 0xf9],
        },
        Case {
            name: "vhaddps ymm10,ymm11,ymm12",
            bytes: &[0xc4, 0x41, 0x27, 0x7c, 0xd4],
        },
        Case {
            name: "vhsubpd xmm13,xmm14,xmm15",
            bytes: &[0xc4, 0x41, 0x09, 0x7d, 0xef],
        },
        Case {
            name: "vhsubpd ymm1,ymm2,ymm3",
            bytes: &[0xc5, 0xed, 0x7d, 0xcb],
        },
        Case {
            name: "vhsubps xmm4,xmm5,xmm6",
            bytes: &[0xc5, 0xd3, 0x7d, 0xe6],
        },
        Case {
            name: "vhsubps ymm7,ymm8,ymm9",
            bytes: &[0xc4, 0xc1, 0x3f, 0x7d, 0xf9],
        },
        Case {
            name: "vmaxsd xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xeb, 0x5f, 0xcb],
        },
        Case {
            name: "vmaxss xmm4,xmm5,xmm6",
            bytes: &[0xc5, 0xd2, 0x5f, 0xe6],
        },
        Case {
            name: "vminsd xmm7,xmm8,xmm9",
            bytes: &[0xc4, 0xc1, 0x3b, 0x5d, 0xf9],
        },
        Case {
            name: "vminss xmm10,xmm11,xmm12",
            bytes: &[0xc4, 0x41, 0x22, 0x5d, 0xd4],
        },
        Case {
            name: "vroundpd xmm1,xmm2,0",
            bytes: &[0xc4, 0xe3, 0x79, 0x09, 0xca, 0x00],
        },
        Case {
            name: "vroundpd ymm3,ymm4,1",
            bytes: &[0xc4, 0xe3, 0x7d, 0x09, 0xdc, 0x01],
        },
        Case {
            name: "vroundps xmm5,xmm6,2",
            bytes: &[0xc4, 0xe3, 0x79, 0x08, 0xee, 0x02],
        },
        Case {
            name: "vroundps ymm7,ymm8,3",
            bytes: &[0xc4, 0xc3, 0x7d, 0x08, 0xf8, 0x03],
        },
        Case {
            name: "vroundsd xmm9,xmm10,xmm11,4",
            bytes: &[0xc4, 0x43, 0x29, 0x0b, 0xcb, 0x04],
        },
        Case {
            name: "vroundss xmm12,xmm13,xmm14,8",
            bytes: &[0xc4, 0x43, 0x11, 0x0a, 0xe6, 0x08],
        },
        Case {
            name: "vpermpd ymm1,ymm2,0x1b",
            bytes: &[0xc4, 0xe3, 0xfd, 0x01, 0xca, 0x1b],
        },
        Case {
            name: "vpermps ymm3,ymm4,ymm5",
            bytes: &[0xc4, 0xe2, 0x5d, 0x16, 0xdd],
        },
        Case {
            name: "vmpsadbw xmm1,xmm2,xmm3,5",
            bytes: &[0xc4, 0xe3, 0x69, 0x42, 0xcb, 0x05],
        },
        Case {
            name: "vmpsadbw ymm4,ymm5,ymm6,0x2d",
            bytes: &[0xc4, 0xe3, 0x55, 0x42, 0xe6, 0x2d],
        },
        Case {
            name: "vdppd xmm1,xmm2,xmm3,0x31",
            bytes: &[0xc4, 0xe3, 0x69, 0x41, 0xcb, 0x31],
        },
        Case {
            name: "vdpps xmm4,xmm5,xmm6,0xb5",
            bytes: &[0xc4, 0xe3, 0x51, 0x40, 0xe6, 0xb5],
        },
        Case {
            name: "vdpps ymm7,ymm8,ymm9,0x7a",
            bytes: &[0xc4, 0xc3, 0x3d, 0x40, 0xf9, 0x7a],
        },
        Case {
            name: "vcmpeqpd xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xc2, 0xcb, 0x00],
        },
        Case {
            name: "vcmpge_oqpd ymm4,ymm5,ymm6",
            bytes: &[0xc5, 0xd5, 0xc2, 0xe6, 0x1d],
        },
        Case {
            name: "vcmpneqps xmm7,xmm8,xmm9",
            bytes: &[0xc4, 0xc1, 0x38, 0xc2, 0xf9, 0x04],
        },
        Case {
            name: "vcmpgt_oqps ymm10,ymm11,ymm12",
            bytes: &[0xc4, 0x41, 0x24, 0xc2, 0xd4, 0x1e],
        },
        Case {
            name: "vcmplesd xmm13,xmm14,xmm15",
            bytes: &[0xc4, 0x41, 0x0b, 0xc2, 0xef, 0x02],
        },
        Case {
            name: "vcmptrue_usss xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xea, 0xc2, 0xcb, 0x1f],
        },
        Case {
            name: "vcvtdq2pd xmm1,xmm2",
            bytes: &[0xc5, 0xfa, 0xe6, 0xca],
        },
        Case {
            name: "vcvtdq2pd ymm3,xmm4",
            bytes: &[0xc5, 0xfe, 0xe6, 0xdc],
        },
        Case {
            name: "vcvtps2pd xmm5,xmm6",
            bytes: &[0xc5, 0xf8, 0x5a, 0xee],
        },
        Case {
            name: "vcvtps2pd ymm7,xmm8",
            bytes: &[0xc4, 0xc1, 0x7c, 0x5a, 0xf8],
        },
        Case {
            name: "vcvtdq2ps xmm1,xmm2",
            bytes: &[0xc5, 0xf8, 0x5b, 0xca],
        },
        Case {
            name: "vcvtdq2ps ymm3,ymm4",
            bytes: &[0xc5, 0xfc, 0x5b, 0xdc],
        },
        Case {
            name: "vcvtps2dq xmm5,xmm6",
            bytes: &[0xc5, 0xf9, 0x5b, 0xee],
        },
        Case {
            name: "vcvtps2dq ymm7,ymm8",
            bytes: &[0xc4, 0xc1, 0x7d, 0x5b, 0xf8],
        },
        Case {
            name: "vcvtpd2dq xmm1,xmm2",
            bytes: &[0xc5, 0xfb, 0xe6, 0xca],
        },
        Case {
            name: "vcvtpd2dq xmm3,ymm4",
            bytes: &[0xc5, 0xff, 0xe6, 0xdc],
        },
        Case {
            name: "vcvtpd2ps xmm1,xmm2",
            bytes: &[0xc5, 0xf9, 0x5a, 0xca],
        },
        Case {
            name: "vcvtpd2ps xmm3,ymm4",
            bytes: &[0xc5, 0xfd, 0x5a, 0xdc],
        },
        Case {
            name: "vmaskmovdqu xmm1,xmm2",
            bytes: &[0xc5, 0xf9, 0xf7, 0xca],
        },
        Case {
            name: "vmaskmovps xmm1,xmm2,[rdi]",
            bytes: &[0xc4, 0xe2, 0x69, 0x2c, 0x0f],
        },
        Case {
            name: "vmaskmovps ymm3,ymm4,[rdi]",
            bytes: &[0xc4, 0xe2, 0x5d, 0x2c, 0x1f],
        },
        Case {
            name: "vmaskmovpd xmm5,xmm6,[rdi]",
            bytes: &[0xc4, 0xe2, 0x49, 0x2d, 0x2f],
        },
        Case {
            name: "vmaskmovpd ymm7,ymm8,[rdi]",
            bytes: &[0xc4, 0xe2, 0x3d, 0x2d, 0x3f],
        },
        Case {
            name: "vmaskmovps [rdi],xmm2,xmm1",
            bytes: &[0xc4, 0xe2, 0x69, 0x2e, 0x0f],
        },
        Case {
            name: "vmaskmovps [rdi],ymm4,ymm3",
            bytes: &[0xc4, 0xe2, 0x5d, 0x2e, 0x1f],
        },
        Case {
            name: "vmaskmovpd [rdi],xmm6,xmm5",
            bytes: &[0xc4, 0xe2, 0x49, 0x2f, 0x2f],
        },
        Case {
            name: "vmaskmovpd [rdi],ymm8,ymm7",
            bytes: &[0xc4, 0xe2, 0x3d, 0x2f, 0x3f],
        },
        Case {
            name: "vpmaskmovd xmm1,xmm2,[rdi]",
            bytes: &[0xc4, 0xe2, 0x69, 0x8c, 0x0f],
        },
        Case {
            name: "vpmaskmovd ymm3,ymm4,[rdi]",
            bytes: &[0xc4, 0xe2, 0x5d, 0x8c, 0x1f],
        },
        Case {
            name: "vpmaskmovq xmm5,xmm6,[rdi]",
            bytes: &[0xc4, 0xe2, 0xc9, 0x8c, 0x2f],
        },
        Case {
            name: "vpmaskmovq ymm7,ymm8,[rdi]",
            bytes: &[0xc4, 0xe2, 0xbd, 0x8c, 0x3f],
        },
        Case {
            name: "vpmaskmovd [rdi],xmm2,xmm1",
            bytes: &[0xc4, 0xe2, 0x69, 0x8e, 0x0f],
        },
        Case {
            name: "vpmaskmovd [rdi],ymm4,ymm3",
            bytes: &[0xc4, 0xe2, 0x5d, 0x8e, 0x1f],
        },
        Case {
            name: "vpmaskmovq [rdi],xmm6,xmm5",
            bytes: &[0xc4, 0xe2, 0xc9, 0x8e, 0x2f],
        },
        Case {
            name: "vpmaskmovq [rdi],ymm8,ymm7",
            bytes: &[0xc4, 0xe2, 0xbd, 0x8e, 0x3f],
        },
        Case {
            name: "vmovntpd [rdi],zmm1",
            bytes: &[0x62, 0xf1, 0xfd, 0x48, 0x2b, 0x0f],
        },
        Case {
            name: "vmovntps [rdi],zmm2",
            bytes: &[0x62, 0xf1, 0x7c, 0x48, 0x2b, 0x17],
        },
        Case {
            name: "vextractps eax,xmm18,2",
            bytes: &[0x62, 0xe3, 0x7d, 0x08, 0x17, 0xd0, 0x02],
        },
        Case {
            name: "vinsertps xmm17,xmm18,xmm3,0xb4",
            bytes: &[0x62, 0xe3, 0x6d, 0x00, 0x21, 0xcb, 0xb4],
        },
        Case {
            name: "vpermilpd zmm1{k2}{z},zmm2,zmm3",
            bytes: &[0x62, 0xf2, 0xed, 0xca, 0x0d, 0xcb],
        },
        Case {
            name: "vpermilps ymm4{k3},ymm5,ymm6",
            bytes: &[0x62, 0xf2, 0x55, 0x2b, 0x0c, 0xe6],
        },
        Case {
            name: "vpmovsxbd zmm16,xmm17",
            bytes: &[0x62, 0xa2, 0x7d, 0x48, 0x21, 0xc1],
        },
        Case {
            name: "vpmovsxbq zmm18,xmm19",
            bytes: &[0x62, 0xa2, 0x7d, 0x48, 0x22, 0xd3],
        },
        Case {
            name: "vpmovsxwq zmm20,xmm21",
            bytes: &[0x62, 0xa2, 0x7d, 0x48, 0x24, 0xe5],
        },
        Case {
            name: "vpmovzxbq zmm22,xmm23",
            bytes: &[0x62, 0xa2, 0x7d, 0x48, 0x32, 0xf7],
        },
        Case {
            name: "vpmovzxwq zmm24,xmm25",
            bytes: &[0x62, 0x02, 0x7d, 0x48, 0x34, 0xc1],
        },
        Case {
            name: "vpcmpgtd k1{k2},zmm3,zmm4",
            bytes: &[0x62, 0xf1, 0x65, 0x4a, 0x66, 0xcc],
        },
        Case {
            name: "vpcmpgtw k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf1, 0x55, 0x2c, 0x65, 0xde],
        },
        Case {
            name: "vpcmpgtq k5{k6},xmm7,xmm8",
            bytes: &[0x62, 0xd2, 0xc5, 0x0e, 0x37, 0xe8],
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
            name: "vpbroadcastb xmm1{k1}{z},eax",
            bytes: &[0x62, 0xf2, 0x7d, 0x89, 0x7a, 0xc8],
        },
        Case {
            name: "vpbroadcastb ymm2{k2},eax",
            bytes: &[0x62, 0xf2, 0x7d, 0x2a, 0x7a, 0xd0],
        },
        Case {
            name: "vpbroadcastb zmm3{k3}{z},eax",
            bytes: &[0x62, 0xf2, 0x7d, 0xcb, 0x7a, 0xd8],
        },
        Case {
            name: "vpbroadcastw xmm4{k4},eax",
            bytes: &[0x62, 0xf2, 0x7d, 0x0c, 0x7b, 0xe0],
        },
        Case {
            name: "vpbroadcastw ymm5{k5}{z},eax",
            bytes: &[0x62, 0xf2, 0x7d, 0xad, 0x7b, 0xe8],
        },
        Case {
            name: "vpbroadcastw zmm6{k6},eax",
            bytes: &[0x62, 0xf2, 0x7d, 0x4e, 0x7b, 0xf0],
        },
        Case {
            name: "vpbroadcastq xmm7{k7}{z},rax",
            bytes: &[0x62, 0xf2, 0xfd, 0x8f, 0x7c, 0xf8],
        },
        Case {
            name: "vpbroadcastq ymm8{k1},rax",
            bytes: &[0x62, 0x72, 0xfd, 0x29, 0x7c, 0xc0],
        },
        Case {
            name: "vpbroadcastq zmm9{k2}{z},rax",
            bytes: &[0x62, 0x72, 0xfd, 0xca, 0x7c, 0xc8],
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
            name: "vmovdqu64 ymm17,[rsi+0x20]",
            bytes: &[0x62, 0xe1, 0xfe, 0x28, 0x6f, 0x4e, 0x01],
        },
        Case {
            name: "vmovntdq [rdi],xmm1",
            bytes: &[0xc5, 0xf9, 0xe7, 0x0f],
        },
        Case {
            name: "vmovntdq [rdi],ymm2",
            bytes: &[0xc5, 0xfd, 0xe7, 0x17],
        },
        Case {
            name: "vmovntdq [rdi],xmm16",
            bytes: &[0x62, 0xe1, 0x7d, 0x08, 0xe7, 0x07],
        },
        Case {
            name: "vmovntdq [rdi],ymm17",
            bytes: &[0x62, 0xe1, 0x7d, 0x28, 0xe7, 0x0f],
        },
        Case {
            name: "vmovntdq [rdi],zmm18",
            bytes: &[0x62, 0xe1, 0x7d, 0x48, 0xe7, 0x17],
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
            name: "vmovdqu8 zmm4{k3}{z},zmm3",
            bytes: &[0x62, 0xf1, 0x7f, 0xcb, 0x6f, 0xe3],
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
            name: "vmovdqu64 [rsi+0x40],zmm2 compressed disp8",
            bytes: &[0x62, 0xf1, 0xfe, 0x48, 0x7f, 0x56, 0x01],
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
            name: "vpmovzxbw zmm2,ymm0",
            bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x30, 0xd0],
        },
        Case {
            name: "vpmovwb [rsi]{k2},zmm2",
            bytes: &[0x62, 0xf2, 0x7e, 0x4a, 0x30, 0x16],
        },
        Case {
            name: "vextracti32x8 ymm2,zmm0,1",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x3b, 0xc2, 0x01],
        },
        Case {
            name: "vpcmpltub k3,zmm0,zmm1",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x3e, 0xd9, 0x01],
        },
        Case {
            name: "vpcmpnltuw k3{k2},zmm2,zmm3",
            bytes: &[0x62, 0xf3, 0xed, 0x4a, 0x3e, 0xdb, 0x05],
        },
        Case {
            name: "vpcmpeqw k1{k2},zmm0,zmm6",
            bytes: &[0x62, 0xf1, 0x7d, 0x4a, 0x75, 0xce],
        },
        Case {
            name: "vpslld zmm1{k3},zmm3,0x18",
            bytes: &[0x62, 0xf1, 0x75, 0x4b, 0x72, 0xf3, 0x18],
        },
        Case {
            name: "vpslldq xmm1,xmm2,0x0d",
            bytes: &[0xc5, 0xf1, 0x73, 0xfa, 0x0d],
        },
        Case {
            name: "vpslldq ymm3,ymm4,0x09",
            bytes: &[0xc5, 0xe5, 0x73, 0xfc, 0x09],
        },
        Case {
            name: "vpslldq zmm5,zmm6,0x05",
            bytes: &[0x62, 0xf1, 0x55, 0x48, 0x73, 0xfe, 0x05],
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
            name: "vpopcntd xmm1,xmm2",
            bytes: &[0x62, 0xf2, 0x7d, 0x08, 0x55, 0xca],
        },
        Case {
            name: "vpopcntd xmm3{k5},xmm4",
            bytes: &[0x62, 0xf2, 0x7d, 0x0d, 0x55, 0xdc],
        },
        Case {
            name: "vpopcntd xmm5{k5}{z},xmm6",
            bytes: &[0x62, 0xf2, 0x7d, 0x8d, 0x55, 0xee],
        },
        Case {
            name: "vpopcntd ymm7,ymm8",
            bytes: &[0x62, 0xd2, 0x7d, 0x28, 0x55, 0xf8],
        },
        Case {
            name: "vpopcntd ymm9{k5},ymm10",
            bytes: &[0x62, 0x52, 0x7d, 0x2d, 0x55, 0xca],
        },
        Case {
            name: "vpopcntd ymm11{k5}{z},ymm12",
            bytes: &[0x62, 0x52, 0x7d, 0xad, 0x55, 0xdc],
        },
        Case {
            name: "vpopcntd zmm13,zmm14",
            bytes: &[0x62, 0x52, 0x7d, 0x48, 0x55, 0xee],
        },
        Case {
            name: "vpopcntd zmm15{k5}{z},zmm16",
            bytes: &[0x62, 0x32, 0x7d, 0xcd, 0x55, 0xf8],
        },
        Case {
            name: "vpopcntd xmm17{k5}{z},[rsi]",
            bytes: &[0x62, 0xe2, 0x7d, 0x8d, 0x55, 0x0e],
        },
        Case {
            name: "vpopcntd ymm18{k5}{z},[rsi]",
            bytes: &[0x62, 0xe2, 0x7d, 0xad, 0x55, 0x16],
        },
        Case {
            name: "vpopcntd zmm19{k5}{z},[rsi]",
            bytes: &[0x62, 0xe2, 0x7d, 0xcd, 0x55, 0x1e],
        },
        Case {
            name: "vpopcntd xmm20{k5}{z},[rsi]{1to4}",
            bytes: &[0x62, 0xe2, 0x7d, 0x9d, 0x55, 0x26],
        },
        Case {
            name: "vpopcntd ymm21{k5}{z},[rsi]{1to8}",
            bytes: &[0x62, 0xe2, 0x7d, 0xbd, 0x55, 0x2e],
        },
        Case {
            name: "vpopcntd zmm22{k5}{z},[rsi]{1to16}",
            bytes: &[0x62, 0xe2, 0x7d, 0xdd, 0x55, 0x36],
        },
        Case {
            name: "vpopcntq xmm1,xmm2",
            bytes: &[0x62, 0xf2, 0xfd, 0x08, 0x55, 0xca],
        },
        Case {
            name: "vpopcntq xmm3{k6},xmm4",
            bytes: &[0x62, 0xf2, 0xfd, 0x0e, 0x55, 0xdc],
        },
        Case {
            name: "vpopcntq xmm5{k6}{z},xmm6",
            bytes: &[0x62, 0xf2, 0xfd, 0x8e, 0x55, 0xee],
        },
        Case {
            name: "vpopcntq ymm7,ymm8",
            bytes: &[0x62, 0xd2, 0xfd, 0x28, 0x55, 0xf8],
        },
        Case {
            name: "vpopcntq ymm9{k6},ymm10",
            bytes: &[0x62, 0x52, 0xfd, 0x2e, 0x55, 0xca],
        },
        Case {
            name: "vpopcntq ymm11{k6}{z},ymm12",
            bytes: &[0x62, 0x52, 0xfd, 0xae, 0x55, 0xdc],
        },
        Case {
            name: "vpopcntq zmm13,zmm14",
            bytes: &[0x62, 0x52, 0xfd, 0x48, 0x55, 0xee],
        },
        Case {
            name: "vpopcntq zmm15{k6}{z},zmm16",
            bytes: &[0x62, 0x32, 0xfd, 0xce, 0x55, 0xf8],
        },
        Case {
            name: "vpopcntq xmm17{k6}{z},[rsi]",
            bytes: &[0x62, 0xe2, 0xfd, 0x8e, 0x55, 0x0e],
        },
        Case {
            name: "vpopcntq ymm18{k6}{z},[rsi]",
            bytes: &[0x62, 0xe2, 0xfd, 0xae, 0x55, 0x16],
        },
        Case {
            name: "vpopcntq zmm19{k6}{z},[rsi]",
            bytes: &[0x62, 0xe2, 0xfd, 0xce, 0x55, 0x1e],
        },
        Case {
            name: "vpopcntq xmm20{k6}{z},[rsi]{1to2}",
            bytes: &[0x62, 0xe2, 0xfd, 0x9e, 0x55, 0x26],
        },
        Case {
            name: "vpopcntq ymm21{k6}{z},[rsi]{1to4}",
            bytes: &[0x62, 0xe2, 0xfd, 0xbe, 0x55, 0x2e],
        },
        Case {
            name: "vpopcntq zmm22{k6}{z},[rsi]{1to8}",
            bytes: &[0x62, 0xe2, 0xfd, 0xde, 0x55, 0x36],
        },
        Case {
            name: "vpsllw xmm1,xmm2,3",
            bytes: &[0xc5, 0xf1, 0x71, 0xf2, 0x03],
        },
        Case {
            name: "vpsllq xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xf3, 0xcb],
        },
        Case {
            name: "vpsllq ymm4,ymm5,xmm6",
            bytes: &[0xc5, 0xd5, 0xf3, 0xe6],
        },
        Case {
            name: "vpsllq xmm7,xmm8,63",
            bytes: &[0xc4, 0xc1, 0x41, 0x73, 0xf0, 0x3f],
        },
        Case {
            name: "vpsllq ymm9,ymm10,64",
            bytes: &[0xc4, 0xc1, 0x35, 0x73, 0xf2, 0x40],
        },
        Case {
            name: "vpsllq xmm11{k5},xmm12,xmm13",
            bytes: &[0x62, 0x51, 0x9d, 0x0d, 0xf3, 0xdd],
        },
        Case {
            name: "vpsllq ymm14{k5}{z},ymm15,xmm16",
            bytes: &[0x62, 0x31, 0x85, 0xad, 0xf3, 0xf0],
        },
        Case {
            name: "vpsllq zmm17{k5},zmm18,xmm19",
            bytes: &[0x62, 0xa1, 0xed, 0x45, 0xf3, 0xcb],
        },
        Case {
            name: "vpsllq xmm20{k5}{z},xmm21,7",
            bytes: &[0x62, 0xb1, 0xdd, 0x85, 0x73, 0xf5, 0x07],
        },
        Case {
            name: "vpsllq ymm22{k5},ymm23,56",
            bytes: &[0x62, 0xb1, 0xcd, 0x25, 0x73, 0xf7, 0x38],
        },
        Case {
            name: "vpsllq zmm24{k5}{z},zmm25,64",
            bytes: &[0x62, 0x91, 0xbd, 0xc5, 0x73, 0xf1, 0x40],
        },
        Case {
            name: "vpsllw ymm3,ymm4,15",
            bytes: &[0xc5, 0xe5, 0x71, 0xf4, 0x0f],
        },
        Case {
            name: "vpsllw zmm5{k5}{z},zmm6,16",
            bytes: &[0x62, 0xf1, 0x55, 0xcd, 0x71, 0xf6, 0x10],
        },
        Case {
            name: "vpsrlw xmm7,xmm8,4",
            bytes: &[0xc4, 0xc1, 0x41, 0x71, 0xd0, 0x04],
        },
        Case {
            name: "vpsrlw ymm9,ymm10,15",
            bytes: &[0xc4, 0xc1, 0x35, 0x71, 0xd2, 0x0f],
        },
        Case {
            name: "vpsrlw zmm11{k5}{z},zmm12,16",
            bytes: &[0x62, 0xd1, 0x25, 0xcd, 0x71, 0xd4, 0x10],
        },
        Case {
            name: "vpsrld xmm13,xmm14,7",
            bytes: &[0xc4, 0xc1, 0x11, 0x72, 0xd6, 0x07],
        },
        Case {
            name: "vpsrld ymm15,ymm16,31",
            bytes: &[0x62, 0xb1, 0x05, 0x28, 0x72, 0xd0, 0x1f],
        },
        Case {
            name: "vpsrld zmm17{k5}{z},zmm18,32",
            bytes: &[0x62, 0xb1, 0x75, 0xc5, 0x72, 0xd2, 0x20],
        },
        Case {
            name: "vpsrldq xmm19,xmm20,7",
            bytes: &[0x62, 0xb1, 0x65, 0x00, 0x73, 0xdc, 0x07],
        },
        Case {
            name: "vpsrldq ymm21,ymm22,15",
            bytes: &[0x62, 0xb1, 0x55, 0x20, 0x73, 0xde, 0x0f],
        },
        Case {
            name: "vpsrldq zmm23,zmm24,16",
            bytes: &[0x62, 0x91, 0x45, 0x40, 0x73, 0xd8, 0x10],
        },
        Case {
            name: "vpsllvd xmm1,xmm2,xmm3",
            bytes: &[0xc4, 0xe2, 0x69, 0x47, 0xcb],
        },
        Case {
            name: "vpsllvd ymm4,ymm5,ymm6",
            bytes: &[0xc4, 0xe2, 0x55, 0x47, 0xe6],
        },
        Case {
            name: "vpsllvd zmm7{k5}{z},zmm8,zmm9",
            bytes: &[0x62, 0xd2, 0x3d, 0xcd, 0x47, 0xf9],
        },
        Case {
            name: "vpsrlvd xmm10,xmm11,xmm12",
            bytes: &[0xc4, 0x42, 0x21, 0x45, 0xd4],
        },
        Case {
            name: "vpsrlvd ymm13,ymm14,ymm15",
            bytes: &[0xc4, 0x42, 0x0d, 0x45, 0xef],
        },
        Case {
            name: "vpsrlvd zmm16{k5}{z},zmm17,zmm18",
            bytes: &[0x62, 0xa2, 0x75, 0xc5, 0x45, 0xc2],
        },
        Case {
            name: "vpsllw zmm19{k5},zmm20,[rsi]",
            bytes: &[0x62, 0xe1, 0x5d, 0x45, 0xf1, 0x1e],
        },
        Case {
            name: "vpsrlw zmm21{k5},zmm22,[rsi]",
            bytes: &[0x62, 0xe1, 0x4d, 0x45, 0xd1, 0x2e],
        },
        Case {
            name: "vpsrld zmm23{k5},zmm24,[rsi]",
            bytes: &[0x62, 0xe1, 0x3d, 0x45, 0xd2, 0x3e],
        },
        Case {
            name: "vpsllvd zmm25{k5},zmm26,[rsi]",
            bytes: &[0x62, 0x62, 0x2d, 0x45, 0x47, 0x0e],
        },
        Case {
            name: "vpsrlvd zmm27{k5},zmm28,[rsi]",
            bytes: &[0x62, 0x62, 0x1d, 0x45, 0x45, 0x1e],
        },
        Case {
            name: "vpsllvd xmm1{k5}{z},xmm2,[rsi]",
            bytes: &[0x62, 0xf2, 0x6d, 0x8d, 0x47, 0x0e],
        },
        Case {
            name: "vpsllvd ymm3{k5},ymm4,[rsi]",
            bytes: &[0x62, 0xf2, 0x5d, 0x2d, 0x47, 0x1e],
        },
        Case {
            name: "vpsllvd zmm5{k5}{z},zmm6,[rsi]{1to16}",
            bytes: &[0x62, 0xf2, 0x4d, 0xdd, 0x47, 0x2e],
        },
        Case {
            name: "vpsrlvd xmm7{k5}{z},xmm8,[rsi]",
            bytes: &[0x62, 0xf2, 0x3d, 0x8d, 0x45, 0x3e],
        },
        Case {
            name: "vpsrlvd ymm9{k5},ymm10,[rsi]",
            bytes: &[0x62, 0x72, 0x2d, 0x2d, 0x45, 0x0e],
        },
        Case {
            name: "vpsrlvd zmm11{k5}{z},zmm12,[rsi]{1to16}",
            bytes: &[0x62, 0x72, 0x1d, 0xdd, 0x45, 0x1e],
        },
        Case {
            name: "vpabsb xmm1,xmm2",
            bytes: &[0xc4, 0xe2, 0x79, 0x1c, 0xca],
        },
        Case {
            name: "vpabsb ymm3,ymm4",
            bytes: &[0xc4, 0xe2, 0x7d, 0x1c, 0xdc],
        },
        Case {
            name: "vpabsb zmm5{k5}{z},zmm6",
            bytes: &[0x62, 0xf2, 0x7d, 0xcd, 0x1c, 0xee],
        },
        Case {
            name: "vpabsw xmm0,xmm1",
            bytes: &[0xc4, 0xe2, 0x79, 0x1d, 0xc1],
        },
        Case {
            name: "vpabsd ymm2,ymm3",
            bytes: &[0xc4, 0xe2, 0x7d, 0x1e, 0xd3],
        },
        Case {
            name: "vpabsw zmm4{k1}{z},zmm5",
            bytes: &[0x62, 0xf2, 0x7d, 0xc9, 0x1d, 0xe5],
        },
        Case {
            name: "vpabsq ymm6{k2},ymm7",
            bytes: &[0x62, 0xf2, 0xfd, 0x2a, 0x1f, 0xf7],
        },
        Case {
            name: "vpabsd zmm8{k3},[rdi]{1to16}",
            bytes: &[0x62, 0x72, 0x7d, 0x5b, 0x1e, 0x07],
        },
        Case {
            name: "vpaddw xmm7{k5},xmm8,xmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x0d, 0xfd, 0xf9],
        },
        Case {
            name: "vpaddw ymm10{k5}{z},ymm11,ymm12",
            bytes: &[0x62, 0x51, 0x25, 0xad, 0xfd, 0xd4],
        },
        Case {
            name: "vpaddw zmm13,zmm14,[rsi]",
            bytes: &[0x62, 0x71, 0x0d, 0x48, 0xfd, 0x2e],
        },
        Case {
            name: "vpaddusb xmm15,xmm1,xmm2",
            bytes: &[0xc5, 0x71, 0xdc, 0xfa],
        },
        Case {
            name: "vpaddusb ymm3,ymm4,ymm5",
            bytes: &[0xc5, 0xdd, 0xdc, 0xdd],
        },
        Case {
            name: "vpaddusb zmm6{k5}{z},zmm7,zmm8",
            bytes: &[0x62, 0xd1, 0x45, 0xcd, 0xdc, 0xf0],
        },
        Case {
            name: "vpaddsw xmm0,xmm1,xmm2",
            bytes: &[0xc5, 0xf1, 0xed, 0xc2],
        },
        Case {
            name: "vpaddsw zmm3{k1}{z},zmm4,zmm5",
            bytes: &[0x62, 0xf1, 0x5d, 0xc9, 0xed, 0xdd],
        },
        Case {
            name: "vpaddusw ymm6,ymm8,ymm7",
            bytes: &[0xc5, 0xbd, 0xdd, 0xf7],
        },
        Case {
            name: "vpaddusw zmm9{k2},zmm10,[rsi]",
            bytes: &[0x62, 0x71, 0x2d, 0x4a, 0xdd, 0x0e],
        },
        Case {
            name: "vpsubb xmm9,xmm10,xmm11",
            bytes: &[0xc4, 0x41, 0x29, 0xf8, 0xcb],
        },
        Case {
            name: "vpsubb ymm12,ymm13,ymm14",
            bytes: &[0xc4, 0x41, 0x15, 0xf8, 0xe6],
        },
        Case {
            name: "vpsubb zmm15{k5}{z},zmm16,zmm17",
            bytes: &[0x62, 0x31, 0x7d, 0xc5, 0xf8, 0xf9],
        },
        Case {
            name: "vpsubw xmm9,xmm10,xmm11",
            bytes: &[0xc4, 0x41, 0x29, 0xf9, 0xcb],
        },
        Case {
            name: "vpsubw ymm12,ymm13,ymm14",
            bytes: &[0xc4, 0x41, 0x15, 0xf9, 0xe6],
        },
        Case {
            name: "vpsubw ymm15{k4}{z},ymm16,ymm17",
            bytes: &[0x62, 0x31, 0x7d, 0xa4, 0xf9, 0xf9],
        },
        Case {
            name: "vpsubw zmm18{k6},zmm19,[rsi]",
            bytes: &[0x62, 0xe1, 0x65, 0x46, 0xf9, 0x16],
        },
        Case {
            name: "vpsubsb ymm11,ymm12,ymm13",
            bytes: &[0xc4, 0x41, 0x1d, 0xe8, 0xdd],
        },
        Case {
            name: "vpsubsb zmm14{k3}{z},zmm15,zmm16",
            bytes: &[0x62, 0x31, 0x05, 0xcb, 0xe8, 0xf0],
        },
        Case {
            name: "vpsubsw xmm17,xmm18,xmm19",
            bytes: &[0x62, 0xa1, 0x6d, 0x00, 0xe9, 0xcb],
        },
        Case {
            name: "vpsubsw zmm20{k4},zmm21,[rsi]",
            bytes: &[0x62, 0xe1, 0x55, 0x44, 0xe9, 0x26],
        },
        Case {
            name: "vpsubusb xmm18,xmm19,xmm20",
            bytes: &[0x62, 0xa1, 0x65, 0x00, 0xd8, 0xd4],
        },
        Case {
            name: "vpsubusb ymm5,ymm6,[rsi]",
            bytes: &[0xc5, 0xcd, 0xd8, 0x2e],
        },
        Case {
            name: "vpsubusb zmm7{k5},zmm8,zmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x4d, 0xd8, 0xf9],
        },
        Case {
            name: "vpmaddubsw xmm1,xmm2,xmm3",
            bytes: &[0xc4, 0xe2, 0x69, 0x04, 0xcb],
        },
        Case {
            name: "vpmaddubsw xmm4{k5},xmm6,xmm7",
            bytes: &[0x62, 0xf2, 0x4d, 0x0d, 0x04, 0xe7],
        },
        Case {
            name: "vpmaddubsw xmm8{k5}{z},xmm9,xmm10",
            bytes: &[0x62, 0x52, 0x35, 0x8d, 0x04, 0xc2],
        },
        Case {
            name: "vpmaddubsw ymm11,ymm12,ymm13",
            bytes: &[0xc4, 0x42, 0x1d, 0x04, 0xdd],
        },
        Case {
            name: "vpmaddubsw ymm14{k5},ymm15,ymm16",
            bytes: &[0x62, 0x32, 0x05, 0x2d, 0x04, 0xf0],
        },
        Case {
            name: "vpmaddubsw ymm17{k5}{z},ymm18,ymm19",
            bytes: &[0x62, 0xa2, 0x6d, 0xa5, 0x04, 0xcb],
        },
        Case {
            name: "vpmaddubsw zmm20,zmm21,zmm22",
            bytes: &[0x62, 0xa2, 0x55, 0x40, 0x04, 0xe6],
        },
        Case {
            name: "vpmaddubsw zmm23{k5},zmm24,zmm25",
            bytes: &[0x62, 0x82, 0x3d, 0x45, 0x04, 0xf9],
        },
        Case {
            name: "vpmaddubsw zmm26{k5}{z},zmm27,zmm28",
            bytes: &[0x62, 0x02, 0x25, 0xc5, 0x04, 0xd4],
        },
        Case {
            name: "vpmaddubsw xmm1{k5}{z},xmm2,[rsi]",
            bytes: &[0x62, 0xf2, 0x6d, 0x8d, 0x04, 0x0e],
        },
        Case {
            name: "vpmaddubsw ymm3{k5}{z},ymm4,[rsi]",
            bytes: &[0x62, 0xf2, 0x5d, 0xad, 0x04, 0x1e],
        },
        Case {
            name: "vpmaddubsw zmm5{k5}{z},zmm6,[rsi]",
            bytes: &[0x62, 0xf2, 0x4d, 0xcd, 0x04, 0x2e],
        },
        Case {
            name: "vpmaddwd xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xf5, 0xcb],
        },
        Case {
            name: "vpmaddwd xmm4{k5},xmm6,xmm7",
            bytes: &[0x62, 0xf1, 0x4d, 0x0d, 0xf5, 0xe7],
        },
        Case {
            name: "vpmaddwd xmm8{k5}{z},xmm9,xmm10",
            bytes: &[0x62, 0x51, 0x35, 0x8d, 0xf5, 0xc2],
        },
        Case {
            name: "vpmaddwd ymm11,ymm12,ymm13",
            bytes: &[0xc4, 0x41, 0x1d, 0xf5, 0xdd],
        },
        Case {
            name: "vpmaddwd ymm14{k5},ymm15,ymm16",
            bytes: &[0x62, 0x31, 0x05, 0x2d, 0xf5, 0xf0],
        },
        Case {
            name: "vpmaddwd ymm17{k5}{z},ymm18,ymm19",
            bytes: &[0x62, 0xa1, 0x6d, 0xa5, 0xf5, 0xcb],
        },
        Case {
            name: "vpmaddwd zmm20,zmm21,zmm22",
            bytes: &[0x62, 0xa1, 0x55, 0x40, 0xf5, 0xe6],
        },
        Case {
            name: "vpmaddwd zmm23{k5},zmm24,zmm25",
            bytes: &[0x62, 0x81, 0x3d, 0x45, 0xf5, 0xf9],
        },
        Case {
            name: "vpmaddwd zmm26{k5}{z},zmm27,zmm28",
            bytes: &[0x62, 0x01, 0x25, 0xc5, 0xf5, 0xd4],
        },
        Case {
            name: "vpmaddwd xmm1{k5}{z},xmm2,[rsi]",
            bytes: &[0x62, 0xf1, 0x6d, 0x8d, 0xf5, 0x0e],
        },
        Case {
            name: "vpmaddwd ymm3{k5}{z},ymm4,[rsi]",
            bytes: &[0x62, 0xf1, 0x5d, 0xad, 0xf5, 0x1e],
        },
        Case {
            name: "vpmaddwd zmm5{k5}{z},zmm6,[rsi]",
            bytes: &[0x62, 0xf1, 0x4d, 0xcd, 0xf5, 0x2e],
        },
        Case {
            name: "vpmovm2b xmm1,k2",
            bytes: &[0x62, 0xf2, 0x7e, 0x08, 0x28, 0xca],
        },
        Case {
            name: "vpmovm2b ymm3,k4",
            bytes: &[0x62, 0xf2, 0x7e, 0x28, 0x28, 0xdc],
        },
        Case {
            name: "vpmovm2b zmm5,k6",
            bytes: &[0x62, 0xf2, 0x7e, 0x48, 0x28, 0xee],
        },
        Case {
            name: "vpmovb2m k1,xmm2",
            bytes: &[0x62, 0xf2, 0x7e, 0x08, 0x29, 0xca],
        },
        Case {
            name: "vpmovb2m k3,ymm4",
            bytes: &[0x62, 0xf2, 0x7e, 0x28, 0x29, 0xdc],
        },
        Case {
            name: "vpmovb2m k5,zmm6",
            bytes: &[0x62, 0xf2, 0x7e, 0x48, 0x29, 0xee],
        },
        Case {
            name: "vpermb xmm1,xmm2,xmm3",
            bytes: &[0x62, 0xf2, 0x6d, 0x08, 0x8d, 0xcb],
        },
        Case {
            name: "vpermb xmm4{k5},xmm6,xmm7",
            bytes: &[0x62, 0xf2, 0x4d, 0x0d, 0x8d, 0xe7],
        },
        Case {
            name: "vpermb xmm8{k5}{z},xmm9,xmm10",
            bytes: &[0x62, 0x52, 0x35, 0x8d, 0x8d, 0xc2],
        },
        Case {
            name: "vpermb ymm11,ymm12,ymm13",
            bytes: &[0x62, 0x52, 0x1d, 0x28, 0x8d, 0xdd],
        },
        Case {
            name: "vpermb ymm14{k5},ymm15,ymm16",
            bytes: &[0x62, 0x32, 0x05, 0x2d, 0x8d, 0xf0],
        },
        Case {
            name: "vpermb ymm17{k5}{z},ymm18,ymm19",
            bytes: &[0x62, 0xa2, 0x6d, 0xa5, 0x8d, 0xcb],
        },
        Case {
            name: "vpermb zmm20,zmm21,zmm22",
            bytes: &[0x62, 0xa2, 0x55, 0x40, 0x8d, 0xe6],
        },
        Case {
            name: "vpermb zmm23{k5},zmm24,zmm25",
            bytes: &[0x62, 0x82, 0x3d, 0x45, 0x8d, 0xf9],
        },
        Case {
            name: "vpermb zmm26{k5}{z},zmm27,zmm28",
            bytes: &[0x62, 0x02, 0x25, 0xc5, 0x8d, 0xd4],
        },
        Case {
            name: "vpermt2d zmm0,zmm13,zmm3",
            bytes: &[0x62, 0xf2, 0x15, 0x48, 0x7e, 0xc3],
        },
        Case {
            name: "vpalignr zmm3,zmm1,zmm0,0xf",
            bytes: &[0x62, 0xf3, 0x75, 0x48, 0x0f, 0xd8, 0x0f],
        },
        Case {
            name: "vshufi32x4 zmm2,zmm2,zmm2,0x0",
            bytes: &[0x62, 0xf3, 0x6d, 0x48, 0x43, 0xd2, 0x00],
        },
        Case {
            name: "vshufi32x4 zmm3{k5}{z},zmm4,zmm6,0xe4",
            bytes: &[0x62, 0xf3, 0x5d, 0xcd, 0x43, 0xde, 0xe4],
        },
        Case {
            name: "vshufi32x4 ymm7{k5},ymm8,ymm9,0x3",
            bytes: &[0x62, 0xd3, 0x3d, 0x2d, 0x43, 0xf9, 0x03],
        },
        Case {
            name: "vshuff32x4 zmm10{k5}{z},zmm11,zmm12,0x1b",
            bytes: &[0x62, 0x53, 0x25, 0xcd, 0x23, 0xd4, 0x1b],
        },
        Case {
            name: "vshuff64x2 ymm13{k5},ymm14,ymm15,0x2",
            bytes: &[0x62, 0x53, 0x8d, 0x2d, 0x23, 0xef, 0x02],
        },
        Case {
            name: "vshufi64x2 zmm16{k5}{z},zmm17,zmm18,0x72",
            bytes: &[0x62, 0xa3, 0xf5, 0xc5, 0x43, 0xc2, 0x72],
        },
        Case {
            name: "vpaddb zmm0,zmm1,zmm0",
            bytes: &[0x62, 0xf1, 0x75, 0x48, 0xfc, 0xc0],
        },
        Case {
            name: "vpsadbw zmm0,zmm0,zmm1",
            bytes: &[0x62, 0xf1, 0x7d, 0x48, 0xf6, 0xc1],
        },
        Case {
            name: "vpaddq zmm4,zmm4,zmm0",
            bytes: &[0x62, 0xf1, 0xdd, 0x48, 0xd4, 0xe0],
        },
        Case {
            name: "vpaddq xmm1,xmm1,xmm2",
            bytes: &[0xc5, 0xf1, 0xd4, 0xca],
        },
        Case {
            name: "vmovd xmm3,eax",
            bytes: &[0xc5, 0xf9, 0x6e, 0xd8],
        },
        Case {
            name: "vmovq xmm1,[rsp+0x58]",
            bytes: &[0xc5, 0xfa, 0x7e, 0x4c, 0x24, 0x58],
        },
        Case {
            name: "vmovq xmm1,xmm2",
            bytes: &[0xc5, 0xfa, 0x7e, 0xca],
        },
        Case {
            name: "vpor ymm5,ymm3,ymm4",
            bytes: &[0xc5, 0xe5, 0xeb, 0xec],
        },
        Case {
            name: "vpor ymm0,ymm1,ymm5",
            bytes: &[0xc5, 0xf5, 0xeb, 0xc5],
        },
        Case {
            name: "vpalignr ymm7,ymm3,ymm2,0xf",
            bytes: &[0xc4, 0xe3, 0x65, 0x0f, 0xfa, 0x0f],
        },
        Case {
            name: "vpalignr ymm7,ymm3,ymm2,0xe",
            bytes: &[0xc4, 0xe3, 0x65, 0x0f, 0xfa, 0x0e],
        },
        Case {
            name: "vpalignr ymm2,ymm3,ymm2,0xd",
            bytes: &[0xc4, 0xe3, 0x65, 0x0f, 0xd2, 0x0d],
        },
        Case {
            name: "vinserti64x2 ymm1,ymm1,xmm0,0x1",
            bytes: &[0x62, 0xf3, 0xf5, 0x28, 0x38, 0xc8, 0x01],
        },
        Case {
            name: "vinserti64x4 zmm0,zmm0,ymm1,0x1",
            bytes: &[0x62, 0xf3, 0xfd, 0x48, 0x3a, 0xc1, 0x01],
        },
        Case {
            name: "vpshldw zmm1,zmm0,zmm6,0x8",
            bytes: &[0x62, 0xf3, 0xfd, 0x48, 0x70, 0xce, 0x08],
        },
        Case {
            name: "vpmaxud xmm1,xmm2,xmm3",
            bytes: &[0xc4, 0xe2, 0x69, 0x3f, 0xcb],
        },
        Case {
            name: "vpmaxud ymm4,ymm5,ymm6",
            bytes: &[0xc4, 0xe2, 0x55, 0x3f, 0xe6],
        },
        Case {
            name: "vpmaxud xmm7{k1},xmm8,xmm9",
            bytes: &[0x62, 0xd2, 0x3d, 0x09, 0x3f, 0xf9],
        },
        Case {
            name: "vpmaxud ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x52, 0x25, 0xaa, 0x3f, 0xd4],
        },
        Case {
            name: "vpmaxud zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x52, 0x0d, 0x4b, 0x3f, 0xef],
        },
        Case {
            name: "vpmaxud zmm0{k4}{z},zmm1,[rsi]{1to16}",
            bytes: &[0x62, 0xf2, 0x75, 0xdc, 0x3f, 0x06],
        },
        Case {
            name: "vpmaxsb xmm1,xmm2,xmm3",
            bytes: &[0xc4, 0xe2, 0x69, 0x3c, 0xcb],
        },
        Case {
            name: "vpmaxsw ymm4,ymm5,ymm6",
            bytes: &[0xc5, 0xd5, 0xee, 0xe6],
        },
        Case {
            name: "vpmaxsd zmm7{k1},zmm8,zmm9",
            bytes: &[0x62, 0xd2, 0x3d, 0x49, 0x3d, 0xf9],
        },
        Case {
            name: "vpmaxsq zmm10{k2}{z},zmm11,[rsi]",
            bytes: &[0x62, 0x72, 0xa5, 0xca, 0x3d, 0x16],
        },
        Case {
            name: "vpmaxub xmm12,xmm13,xmm14",
            bytes: &[0xc4, 0x41, 0x11, 0xde, 0xe6],
        },
        Case {
            name: "vpmaxuw ymm15,ymm16,ymm17",
            bytes: &[0x62, 0x32, 0x7d, 0x20, 0x3e, 0xf9],
        },
        Case {
            name: "vpmaxuq zmm18{k3},zmm19,zmm20",
            bytes: &[0x62, 0xa2, 0xe5, 0x43, 0x3f, 0xd4],
        },
        Case {
            name: "vpminsb xmm21{k4},xmm22,xmm23",
            bytes: &[0x62, 0xa2, 0x4d, 0x04, 0x38, 0xef],
        },
        Case {
            name: "vpminsw ymm24{k5}{z},ymm25,ymm26",
            bytes: &[0x62, 0x01, 0x35, 0xa5, 0xea, 0xc2],
        },
        Case {
            name: "vpminsd zmm27{k6},zmm28,zmm29",
            bytes: &[0x62, 0x02, 0x1d, 0x46, 0x39, 0xdd],
        },
        Case {
            name: "vpminsq zmm30{k7}{z},zmm31,[rsi]",
            bytes: &[0x62, 0x62, 0x85, 0xc7, 0x39, 0x36],
        },
        Case {
            name: "vpminud ymm1,ymm2,ymm3",
            bytes: &[0xc4, 0xe2, 0x6d, 0x3b, 0xcb],
        },
        Case {
            name: "vpminuq zmm4{k1},zmm5,zmm6",
            bytes: &[0x62, 0xf2, 0xd5, 0x49, 0x3b, 0xe6],
        },
        Case {
            name: "vpackssdw xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0x6b, 0xcb],
        },
        Case {
            name: "vpacksswb ymm4,ymm5,ymm6",
            bytes: &[0xc5, 0xd5, 0x63, 0xe6],
        },
        Case {
            name: "vpmulld zmm7{k1},zmm8,zmm9",
            bytes: &[0x62, 0xd2, 0x3d, 0x49, 0x40, 0xf9],
        },
        Case {
            name: "vpmulhw ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x51, 0x25, 0xaa, 0xe5, 0xd4],
        },
        Case {
            name: "vpmulhuw zmm13{k3},zmm14,[rsi]",
            bytes: &[0x62, 0x71, 0x0d, 0x4b, 0xe4, 0x2e],
        },
        Case {
            name: "vpmuldq zmm15{k4}{z},zmm16,zmm17",
            bytes: &[0x62, 0x32, 0xfd, 0xc4, 0x28, 0xf9],
        },
        Case {
            name: "vpmulhrsw zmm1{k1},zmm2,zmm3",
            bytes: &[0x62, 0xf2, 0x6d, 0x49, 0x0b, 0xcb],
        },
        Case {
            name: "vpsignb xmm4,xmm5,xmm6",
            bytes: &[0xc4, 0xe2, 0x51, 0x08, 0xe6],
        },
        Case {
            name: "vpsignw ymm7,ymm8,ymm9",
            bytes: &[0xc4, 0xc2, 0x3d, 0x09, 0xf9],
        },
        Case {
            name: "vpsignd ymm10,ymm11,ymm12",
            bytes: &[0xc4, 0x42, 0x25, 0x0a, 0xd4],
        },
        Case {
            name: "vpandn ymm13,ymm14,ymm15",
            bytes: &[0xc4, 0x41, 0x0d, 0xdf, 0xef],
        },
        Case {
            name: "vpcmpgtw ymm1,ymm2,ymm3",
            bytes: &[0xc5, 0xed, 0x65, 0xcb],
        },
        Case {
            name: "vpcmpgtq ymm4,ymm5,ymm6",
            bytes: &[0xc4, 0xe2, 0x55, 0x37, 0xe6],
        },
        Case {
            name: "vpshufhw ymm1,ymm2,0x1b",
            bytes: &[0xc5, 0xfe, 0x70, 0xca, 0x1b],
        },
        Case {
            name: "vpshuflw zmm3{k2}{z},zmm4,0xe4",
            bytes: &[0x62, 0xf1, 0x7f, 0xca, 0x70, 0xdc, 0xe4],
        },
        Case {
            name: "vpunpckhbw xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0x68, 0xcb],
        },
        Case {
            name: "vpunpcklbw ymm4,ymm5,ymm6",
            bytes: &[0xc5, 0xd5, 0x60, 0xe6],
        },
        Case {
            name: "vpunpckhdq zmm7{k1},zmm8,zmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x49, 0x6a, 0xf9],
        },
        Case {
            name: "vpunpckldq zmm10{k2}{z},zmm11,[rsi]",
            bytes: &[0x62, 0x71, 0x25, 0xca, 0x62, 0x16],
        },
        Case {
            name: "vphaddw xmm1,xmm2,xmm3",
            bytes: &[0xc4, 0xe2, 0x69, 0x01, 0xcb],
        },
        Case {
            name: "vphaddd ymm4,ymm5,ymm6",
            bytes: &[0xc4, 0xe2, 0x55, 0x02, 0xe6],
        },
        Case {
            name: "vphaddsw ymm7,ymm8,ymm9",
            bytes: &[0xc4, 0xc2, 0x3d, 0x03, 0xf9],
        },
        Case {
            name: "vphsubw xmm10,xmm11,xmm12",
            bytes: &[0xc4, 0x42, 0x21, 0x05, 0xd4],
        },
        Case {
            name: "vphsubd ymm13,ymm14,ymm15",
            bytes: &[0xc4, 0x42, 0x0d, 0x06, 0xef],
        },
        Case {
            name: "vphsubsw ymm1,ymm2,ymm3",
            bytes: &[0xc4, 0xe2, 0x6d, 0x07, 0xcb],
        },
        Case {
            name: "vprold xmm1,xmm2,7",
            bytes: &[0x62, 0xf1, 0x75, 0x08, 0x72, 0xca, 0x07],
        },
        Case {
            name: "vprolq ymm3,ymm4,13",
            bytes: &[0x62, 0xf1, 0xe5, 0x28, 0x72, 0xcc, 0x0d],
        },
        Case {
            name: "vprord zmm5{k1},zmm6,11",
            bytes: &[0x62, 0xf1, 0x55, 0x49, 0x72, 0xc6, 0x0b],
        },
        Case {
            name: "vprorq zmm7{k2}{z},zmm8,17",
            bytes: &[0x62, 0xd1, 0xc5, 0xca, 0x72, 0xc0, 0x11],
        },
        Case {
            name: "vprolvd xmm9,xmm10,xmm11",
            bytes: &[0x62, 0x52, 0x2d, 0x08, 0x15, 0xcb],
        },
        Case {
            name: "vprolvq ymm12,ymm13,ymm14",
            bytes: &[0x62, 0x52, 0x95, 0x28, 0x15, 0xe6],
        },
        Case {
            name: "vprorvd zmm15{k3},zmm16,zmm17",
            bytes: &[0x62, 0x32, 0x7d, 0x43, 0x14, 0xf9],
        },
        Case {
            name: "vprorvq zmm18{k4}{z},zmm19,zmm20",
            bytes: &[0x62, 0xa2, 0xe5, 0xc4, 0x14, 0xd4],
        },
        Case {
            name: "vpsllvq ymm1,ymm2,ymm3",
            bytes: &[0xc4, 0xe2, 0xed, 0x47, 0xcb],
        },
        Case {
            name: "vpsllvw zmm4{k1},zmm5,zmm6",
            bytes: &[0x62, 0xf2, 0xd5, 0x49, 0x12, 0xe6],
        },
        Case {
            name: "vpsrlvq zmm7{k2}{z},zmm8,zmm9",
            bytes: &[0x62, 0xd2, 0xbd, 0xca, 0x45, 0xf9],
        },
        Case {
            name: "vpsrlvw ymm10{k3},ymm11,ymm12",
            bytes: &[0x62, 0x52, 0xa5, 0x2b, 0x10, 0xd4],
        },
        Case {
            name: "vpsravd ymm13,ymm14,ymm15",
            bytes: &[0xc4, 0x42, 0x0d, 0x46, 0xef],
        },
        Case {
            name: "vpsravq zmm16{k4},zmm17,zmm18",
            bytes: &[0x62, 0xa2, 0xf5, 0x44, 0x46, 0xc2],
        },
        Case {
            name: "vpsravw zmm19{k5}{z},zmm20,zmm21",
            bytes: &[0x62, 0xa2, 0xdd, 0xc5, 0x11, 0xdd],
        },
        Case {
            name: "vpsrad ymm22,ymm23,xmm24",
            bytes: &[0x62, 0x81, 0x45, 0x20, 0xe2, 0xf0],
        },
        Case {
            name: "vpsraq zmm25{k6},zmm26,xmm27",
            bytes: &[0x62, 0x01, 0xad, 0x46, 0xe2, 0xcb],
        },
        Case {
            name: "vpsraw zmm28{k7}{z},zmm29,9",
            bytes: &[0x62, 0x91, 0x1d, 0xc7, 0x71, 0xe5, 0x09],
        },
        Case {
            name: "vbroadcastss zmm1{k1},xmm2",
            bytes: &[0x62, 0xf2, 0x7d, 0x49, 0x18, 0xca],
        },
        Case {
            name: "vbroadcastsd ymm3{k2}{z},xmm4",
            bytes: &[0x62, 0xf2, 0xfd, 0xaa, 0x19, 0xdc],
        },
        Case {
            name: "vbroadcastf32x4 zmm5{k3},[rsi]",
            bytes: &[0x62, 0xf2, 0x7d, 0x4b, 0x1a, 0x2e],
        },
        Case {
            name: "vbroadcasti32x4 ymm6{k4}{z},[rsi]",
            bytes: &[0x62, 0xf2, 0x7d, 0xac, 0x5a, 0x36],
        },
        Case {
            name: "vpmuludq zmm7{k5},zmm8,zmm9",
            bytes: &[0x62, 0xd1, 0xbd, 0x4d, 0xf4, 0xf9],
        },
        Case {
            name: "vplzcntd zmm1{k1},zmm2",
            bytes: &[0x62, 0xf2, 0x7d, 0x49, 0x44, 0xca],
        },
        Case {
            name: "vplzcntq ymm3{k2}{z},ymm4",
            bytes: &[0x62, 0xf2, 0xfd, 0xaa, 0x44, 0xdc],
        },
        Case {
            name: "vphminposuw xmm5,xmm6",
            bytes: &[0xc4, 0xe2, 0x79, 0x41, 0xee],
        },
        Case {
            name: "vpblendd ymm1,ymm2,ymm3,0xa5",
            bytes: &[0xc4, 0xe3, 0x6d, 0x02, 0xcb, 0xa5],
        },
        Case {
            name: "vpinsrb xmm4,xmm5,eax,11",
            bytes: &[0xc4, 0xe3, 0x51, 0x20, 0xe0, 0x0b],
        },
        Case {
            name: "vpinsrb xmm6,xmm7,byte ptr [rsi],3",
            bytes: &[0xc4, 0xe3, 0x41, 0x20, 0x36, 0x03],
        },
        Case {
            name: "vpinsrw xmm16,xmm17,eax,6",
            bytes: &[0x62, 0xe1, 0x75, 0x00, 0xc4, 0xc0, 0x06],
        },
        Case {
            name: "vpinsrb xmm18,xmm19,eax,4",
            bytes: &[0x62, 0xe3, 0x65, 0x00, 0x20, 0xd0, 0x04],
        },
        Case {
            name: "vpminub xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xda, 0xcb],
        },
        Case {
            name: "vpminub ymm2,ymm4,ymm1",
            bytes: &[0xc5, 0xdd, 0xda, 0xd1],
        },
        Case {
            name: "vpminub xmm7{k1},xmm8,xmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x09, 0xda, 0xf9],
        },
        Case {
            name: "vpminub ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x51, 0x25, 0xaa, 0xda, 0xd4],
        },
        Case {
            name: "vpminub zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0xda, 0xef],
        },
        Case {
            name: "vpavgb xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xe0, 0xcb],
        },
        Case {
            name: "vpavgb ymm3,ymm3,ymm13",
            bytes: &[0xc4, 0xc1, 0x65, 0xe0, 0xdd],
        },
        Case {
            name: "vpavgb xmm7{k1},xmm8,xmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x09, 0xe0, 0xf9],
        },
        Case {
            name: "vpavgb ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x51, 0x25, 0xaa, 0xe0, 0xd4],
        },
        Case {
            name: "vpavgb zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0xe0, 0xef],
        },
        Case {
            name: "vpavgw xmm0,xmm1,xmm2",
            bytes: &[0xc5, 0xf1, 0xe3, 0xc2],
        },
        Case {
            name: "vpavgw ymm3,ymm4,ymm5",
            bytes: &[0xc5, 0xdd, 0xe3, 0xdd],
        },
        Case {
            name: "vpavgw ymm6{k2}{z},ymm7,ymm8",
            bytes: &[0x62, 0xd1, 0x45, 0xaa, 0xe3, 0xf0],
        },
        Case {
            name: "vpavgw zmm9{k3},zmm10,[rsi]",
            bytes: &[0x62, 0x71, 0x2d, 0x4b, 0xe3, 0x0e],
        },
        Case {
            name: "vpaddsb xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xec, 0xcb],
        },
        Case {
            name: "vpaddsb ymm3,ymm3,ymm1",
            bytes: &[0xc5, 0xe5, 0xec, 0xd9],
        },
        Case {
            name: "vpaddsb xmm7{k1},xmm8,xmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x09, 0xec, 0xf9],
        },
        Case {
            name: "vpaddsb ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x51, 0x25, 0xaa, 0xec, 0xd4],
        },
        Case {
            name: "vpaddsb zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0xec, 0xef],
        },
        Case {
            name: "vpmulhuw xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xe4, 0xcb],
        },
        Case {
            name: "vpmulhuw ymm15,ymm15,ymm5",
            bytes: &[0xc5, 0x05, 0xe4, 0xfd],
        },
        Case {
            name: "vpmulhuw xmm7{k1},xmm8,xmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x09, 0xe4, 0xf9],
        },
        Case {
            name: "vpmulhuw ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x51, 0x25, 0xaa, 0xe4, 0xd4],
        },
        Case {
            name: "vpmulhuw zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0xe4, 0xef],
        },
        Case {
            name: "vpmullw xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xd5, 0xcb],
        },
        Case {
            name: "vpmullw ymm3,ymm4,ymm3",
            bytes: &[0xc5, 0xdd, 0xd5, 0xdb],
        },
        Case {
            name: "vpmullw xmm7{k1},xmm8,xmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x09, 0xd5, 0xf9],
        },
        Case {
            name: "vpmullw ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x51, 0x25, 0xaa, 0xd5, 0xd4],
        },
        Case {
            name: "vpmullw zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0xd5, 0xef],
        },
        Case {
            name: "vpsubd xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xfa, 0xcb],
        },
        Case {
            name: "vpsubd ymm3,ymm4,ymm2",
            bytes: &[0xc5, 0xdd, 0xfa, 0xda],
        },
        Case {
            name: "vpsubd xmm7{k1},xmm8,xmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x09, 0xfa, 0xf9],
        },
        Case {
            name: "vpsubd ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x51, 0x25, 0xaa, 0xfa, 0xd4],
        },
        Case {
            name: "vpsubd zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0xfa, 0xef],
        },
        Case {
            name: "vpcmpgtd xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0x66, 0xcb],
        },
        Case {
            name: "vpcmpgtd ymm1,ymm1,ymm3",
            bytes: &[0xc5, 0xf5, 0x66, 0xcb],
        },
        Case {
            name: "vpcmpgtb xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0x64, 0xcb],
        },
        Case {
            name: "vpcmpgtb ymm1,ymm1,ymm5",
            bytes: &[0xc5, 0xf5, 0x64, 0xcd],
        },
        Case {
            name: "vpcmpeqb xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0x74, 0xcb],
        },
        Case {
            name: "vpcmpeqb ymm2,ymm2,ymm4",
            bytes: &[0xc5, 0xed, 0x74, 0xd4],
        },
        Case {
            name: "vpcmpeqd xmm13,xmm13,xmm13",
            bytes: &[0xc4, 0x41, 0x11, 0x76, 0xed],
        },
        Case {
            name: "vpcmpeqd ymm1,ymm2,ymm3",
            bytes: &[0xc5, 0xed, 0x76, 0xcb],
        },
        Case {
            name: "vpand xmm5,xmm5,xmm0",
            bytes: &[0xc5, 0xd1, 0xdb, 0xe8],
        },
        Case {
            name: "vpand ymm1,ymm2,ymm3",
            bytes: &[0xc5, 0xed, 0xdb, 0xcb],
        },
        Case {
            name: "vpandn xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0xdf, 0xcb],
        },
        Case {
            name: "vpandn ymm8,ymm8,ymm9",
            bytes: &[0xc4, 0x41, 0x3d, 0xdf, 0xc1],
        },
        Case {
            name: "vpunpcklwd xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0x61, 0xcb],
        },
        Case {
            name: "vpunpcklwd ymm8,ymm1,ymm0",
            bytes: &[0xc5, 0x75, 0x61, 0xc0],
        },
        Case {
            name: "vpunpcklwd zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0x61, 0xef],
        },
        Case {
            name: "vpunpckhwd xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0x69, 0xcb],
        },
        Case {
            name: "vpunpckhwd ymm0,ymm1,ymm0",
            bytes: &[0xc5, 0xf5, 0x69, 0xc0],
        },
        Case {
            name: "vpunpckhwd zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0x69, 0xef],
        },
        Case {
            name: "vpunpcklqdq xmm5,xmm5,xmm5",
            bytes: &[0xc5, 0xd1, 0x6c, 0xed],
        },
        Case {
            name: "vpunpcklqdq ymm8,ymm1,ymm0",
            bytes: &[0xc5, 0x75, 0x6c, 0xc0],
        },
        Case {
            name: "vpunpcklqdq zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x8d, 0x4b, 0x6c, 0xef],
        },
        Case {
            name: "vpunpckhqdq xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0x6d, 0xcb],
        },
        Case {
            name: "vpunpckhqdq ymm0,ymm1,ymm0",
            bytes: &[0xc5, 0xf5, 0x6d, 0xc0],
        },
        Case {
            name: "vpunpckhqdq zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x8d, 0x4b, 0x6d, 0xef],
        },
        Case {
            name: "vpsubusw xmm0,xmm0,xmm2",
            bytes: &[0xc5, 0xf9, 0xd9, 0xc2],
        },
        Case {
            name: "vpsubusw ymm3,ymm4,ymm5",
            bytes: &[0xc5, 0xdd, 0xd9, 0xdd],
        },
        Case {
            name: "vpsubusw zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0xd9, 0xef],
        },
        Case {
            name: "vpshufd xmm1,xmm2,0x08",
            bytes: &[0xc5, 0xf9, 0x70, 0xca, 0x08],
        },
        Case {
            name: "vpshufd ymm3,ymm4,0x1b",
            bytes: &[0xc5, 0xfd, 0x70, 0xdc, 0x1b],
        },
        Case {
            name: "vpshufd zmm13{k3},zmm14,0xb1",
            bytes: &[0x62, 0x51, 0x7d, 0x4b, 0x70, 0xee, 0xb1],
        },
        Case {
            name: "valignd xmm1,xmm2,xmm3,1",
            bytes: &[0x62, 0xf3, 0x6d, 0x08, 0x03, 0xcb, 0x01],
        },
        Case {
            name: "valignd ymm4,ymm5,ymm6,7",
            bytes: &[0x62, 0xf3, 0x55, 0x28, 0x03, 0xe6, 0x07],
        },
        Case {
            name: "valignd zmm1,zmm2,zmm3,1",
            bytes: &[0x62, 0xf3, 0x6d, 0x48, 0x03, 0xcb, 0x01],
        },
        Case {
            name: "valignd zmm13{k3},zmm14,zmm15,15",
            bytes: &[0x62, 0x53, 0x0d, 0x4b, 0x03, 0xef, 0x0f],
        },
        Case {
            name: "vpackusdw xmm0,xmm0,xmm0",
            bytes: &[0xc4, 0xe2, 0x79, 0x2b, 0xc0],
        },
        Case {
            name: "vpackusdw ymm1,ymm2,ymm3",
            bytes: &[0xc4, 0xe2, 0x6d, 0x2b, 0xcb],
        },
        Case {
            name: "vpackusdw xmm7{k1},xmm8,xmm9",
            bytes: &[0x62, 0xd2, 0x3d, 0x09, 0x2b, 0xf9],
        },
        Case {
            name: "vpackusdw ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x52, 0x25, 0xaa, 0x2b, 0xd4],
        },
        Case {
            name: "vpackusdw zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x52, 0x0d, 0x4b, 0x2b, 0xef],
        },
        Case {
            name: "vpmovsxbw xmm1,xmm2",
            bytes: &[0xc4, 0xe2, 0x79, 0x20, 0xca],
        },
        Case {
            name: "vpmovsxbw ymm5,xmm0",
            bytes: &[0xc4, 0xe2, 0x7d, 0x20, 0xe8],
        },
        Case {
            name: "vpmovsxbw zmm13{k3},ymm14",
            bytes: &[0x62, 0x52, 0x7d, 0x4b, 0x20, 0xee],
        },
        Case {
            name: "vpmovsxwd xmm1,xmm2",
            bytes: &[0xc4, 0xe2, 0x79, 0x23, 0xca],
        },
        Case {
            name: "vpmovsxwd ymm7,xmm5",
            bytes: &[0xc4, 0xe2, 0x7d, 0x23, 0xfd],
        },
        Case {
            name: "vpmovsxwd zmm13{k3},ymm14",
            bytes: &[0x62, 0x52, 0x7d, 0x4b, 0x23, 0xee],
        },
        Case {
            name: "vpmovsxdq xmm1,xmm2",
            bytes: &[0xc4, 0xe2, 0x79, 0x25, 0xca],
        },
        Case {
            name: "vpmovsxdq ymm1,xmm7",
            bytes: &[0xc4, 0xe2, 0x7d, 0x25, 0xcf],
        },
        Case {
            name: "vpmovsxdq zmm13{k3},ymm14",
            bytes: &[0x62, 0x52, 0x7d, 0x4b, 0x25, 0xee],
        },
        Case {
            name: "vpackuswb xmm0,xmm0,xmm0",
            bytes: &[0xc5, 0xf9, 0x67, 0xc0],
        },
        Case {
            name: "vpackuswb ymm1,ymm2,ymm3",
            bytes: &[0xc5, 0xed, 0x67, 0xcb],
        },
        Case {
            name: "vpackuswb xmm7{k1},xmm8,xmm9",
            bytes: &[0x62, 0xd1, 0x3d, 0x09, 0x67, 0xf9],
        },
        Case {
            name: "vpackuswb ymm10{k2}{z},ymm11,ymm12",
            bytes: &[0x62, 0x51, 0x25, 0xaa, 0x67, 0xd4],
        },
        Case {
            name: "vpackuswb zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x51, 0x0d, 0x4b, 0x67, 0xef],
        },
        Case {
            name: "vpminuw xmm1,xmm2,xmm3",
            bytes: &[0xc4, 0xe2, 0x69, 0x3a, 0xcb],
        },
        Case {
            name: "vpminuw ymm9,ymm3,ymm2",
            bytes: &[0xc4, 0x62, 0x65, 0x3a, 0xca],
        },
        Case {
            name: "vpminuw zmm13{k3},zmm14,zmm15",
            bytes: &[0x62, 0x52, 0x0d, 0x4b, 0x3a, 0xef],
        },
        Case {
            name: "vpcmpeqw xmm1,xmm2,xmm3",
            bytes: &[0xc5, 0xe9, 0x75, 0xcb],
        },
        Case {
            name: "vpcmpeqw ymm2,ymm2,ymm4",
            bytes: &[0xc5, 0xed, 0x75, 0xd4],
        },
        Case {
            name: "vpsrlq xmm1,xmm2,0x20",
            bytes: &[0xc5, 0xf1, 0x73, 0xd2, 0x20],
        },
        Case {
            name: "vpsrlq ymm2,ymm0,0x20",
            bytes: &[0xc5, 0xed, 0x73, 0xd0, 0x20],
        },
        Case {
            name: "vpsrlq xmm3,xmm4,xmm5",
            bytes: &[0xc5, 0xd9, 0xd3, 0xdd],
        },
        Case {
            name: "vpsrlq ymm6,ymm7,xmm8",
            bytes: &[0xc4, 0xc1, 0x45, 0xd3, 0xf0],
        },
        Case {
            name: "vpsrlq zmm13{k3},zmm14,xmm15",
            bytes: &[0x62, 0x51, 0x8d, 0x4b, 0xd3, 0xef],
        },
        Case {
            name: "vpsrlq zmm13{k3}{z},zmm14,0x20",
            bytes: &[0x62, 0xd1, 0x95, 0xcb, 0x73, 0xd6, 0x20],
        },
        Case {
            name: "vpslld xmm5,xmm5,8",
            bytes: &[0xc5, 0xd1, 0x72, 0xf5, 0x08],
        },
        Case {
            name: "vpslld ymm5,ymm5,8",
            bytes: &[0xc5, 0xd5, 0x72, 0xf5, 0x08],
        },
        Case {
            name: "vpslld ymm1,ymm2,xmm3",
            bytes: &[0xc5, 0xed, 0xf2, 0xcb],
        },
        Case {
            name: "vpblendvb xmm0,xmm0,xmm1,xmm2",
            bytes: &[0xc4, 0xe3, 0x79, 0x4c, 0xc1, 0x20],
        },
        Case {
            name: "vpblendvb ymm0,ymm0,ymm1,ymm2",
            bytes: &[0xc4, 0xe3, 0x7d, 0x4c, 0xc1, 0x20],
        },
        Case {
            name: "vpblendw xmm1,xmm0,xmm1,0x55",
            bytes: &[0xc4, 0xe3, 0x79, 0x0e, 0xc9, 0x55],
        },
        Case {
            name: "vpblendw ymm3,ymm4,ymm5,0xa6",
            bytes: &[0xc4, 0xe3, 0x5d, 0x0e, 0xdd, 0xa6],
        },
        Case {
            name: "vpcmpgtb k1{k2},xmm3,xmm4",
            bytes: &[0x62, 0xf1, 0x65, 0x0a, 0x64, 0xcc],
        },
        Case {
            name: "vpcmpgtb k3{k4},ymm5,ymm6",
            bytes: &[0x62, 0xf1, 0x55, 0x2c, 0x64, 0xde],
        },
        Case {
            name: "vpcmpgtb k5{k6},zmm7,zmm8",
            bytes: &[0x62, 0xd1, 0x45, 0x4e, 0x64, 0xe8],
        },
        Case {
            name: "vpinsrw xmm2,xmm0,ecx,0",
            bytes: &[0xc5, 0xf9, 0xc4, 0xd1, 0x00],
        },
        Case {
            name: "vpinsrw xmm7,xmm8,[rsi],255",
            bytes: &[0xc5, 0xb9, 0xc4, 0x3e, 0xff],
        },
        Case {
            name: "vpmovzxbd zmm0,[rsi]",
            bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x31, 0x06],
        },
        Case {
            name: "vpmovzxbd zmm0,xmm0",
            bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x31, 0xc0],
        },
        Case {
            name: "vpmovzxbd xmm1,xmm2",
            bytes: &[0xc4, 0xe2, 0x79, 0x31, 0xca],
        },
        Case {
            name: "vpmovzxbd ymm0,[rsi]",
            bytes: &[0xc4, 0xe2, 0x7d, 0x31, 0x06],
        },
        Case {
            name: "vpmovzxdq xmm1,xmm2",
            bytes: &[0xc4, 0xe2, 0x79, 0x35, 0xca],
        },
        Case {
            name: "vpmovzxdq ymm3,xmm4",
            bytes: &[0xc4, 0xe2, 0x7d, 0x35, 0xdc],
        },
        Case {
            name: "vpmovzxdq zmm13{k3},ymm14",
            bytes: &[0x62, 0x52, 0x7d, 0x4b, 0x35, 0xee],
        },
        Case {
            name: "vextracti32x4 xmm2,zmm4,0x1",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x39, 0xe2, 0x01],
        },
        Case {
            name: "vextracti32x4 xmm0,zmm4,0x2",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x39, 0xe0, 0x02],
        },
        Case {
            name: "vextracti32x4 xmm4,zmm4,0x3",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x39, 0xe4, 0x03],
        },
        Case {
            name: "ktestb k0,k1",
            bytes: &[0xc5, 0xf9, 0x99, 0xc1],
        },
        Case {
            name: "ktestw k0,k1",
            bytes: &[0xc5, 0xf8, 0x99, 0xc1],
        },
        Case {
            name: "ktestd k0,k1",
            bytes: &[0xc4, 0xe1, 0xf9, 0x99, 0xc1],
        },
        Case {
            name: "ktestq k0,k1",
            bytes: &[0xc4, 0xe1, 0xf8, 0x99, 0xc1],
        },
        Case {
            name: "vpermb xmm1{k5}{z},xmm2,[rsi]",
            bytes: &[0x62, 0xf2, 0x6d, 0x8d, 0x8d, 0x0e],
        },
        Case {
            name: "vpermb ymm3{k5}{z},ymm4,[rsi]",
            bytes: &[0x62, 0xf2, 0x5d, 0xad, 0x8d, 0x1e],
        },
        Case {
            name: "vpermb zmm5{k5}{z},zmm6,[rsi]",
            bytes: &[0x62, 0xf2, 0x4d, 0xcd, 0x8d, 0x2e],
        },
        Case {
            name: "vpermi2b xmm1,xmm2,xmm3",
            bytes: &[0x62, 0xf2, 0x6d, 0x08, 0x75, 0xcb],
        },
        Case {
            name: "vpermi2b xmm4{k5},xmm6,xmm7",
            bytes: &[0x62, 0xf2, 0x4d, 0x0d, 0x75, 0xe7],
        },
        Case {
            name: "vpermi2b xmm8{k5}{z},xmm9,xmm10",
            bytes: &[0x62, 0x52, 0x35, 0x8d, 0x75, 0xc2],
        },
        Case {
            name: "vpermi2b ymm11,ymm12,ymm13",
            bytes: &[0x62, 0x52, 0x1d, 0x28, 0x75, 0xdd],
        },
        Case {
            name: "vpermi2b ymm14{k5},ymm15,ymm16",
            bytes: &[0x62, 0x32, 0x05, 0x2d, 0x75, 0xf0],
        },
        Case {
            name: "vpermi2b ymm17{k5}{z},ymm18,ymm19",
            bytes: &[0x62, 0xa2, 0x6d, 0xa5, 0x75, 0xcb],
        },
        Case {
            name: "vpermi2b zmm20,zmm21,zmm22",
            bytes: &[0x62, 0xa2, 0x55, 0x40, 0x75, 0xe6],
        },
        Case {
            name: "vpermi2b zmm23{k5},zmm24,zmm25",
            bytes: &[0x62, 0x82, 0x3d, 0x45, 0x75, 0xf9],
        },
        Case {
            name: "vpermi2b zmm26{k5}{z},zmm27,zmm28",
            bytes: &[0x62, 0x02, 0x25, 0xc5, 0x75, 0xd4],
        },
        Case {
            name: "vpermi2b xmm1{k5}{z},xmm2,[rsi]",
            bytes: &[0x62, 0xf2, 0x6d, 0x8d, 0x75, 0x0e],
        },
        Case {
            name: "vpermi2b ymm3{k5}{z},ymm4,[rsi]",
            bytes: &[0x62, 0xf2, 0x5d, 0xad, 0x75, 0x1e],
        },
        Case {
            name: "vpermi2b zmm5{k5}{z},zmm6,[rsi]",
            bytes: &[0x62, 0xf2, 0x4d, 0xcd, 0x75, 0x2e],
        },
        Case {
            name: "vpermt2b xmm1,xmm2,xmm3",
            bytes: &[0x62, 0xf2, 0x6d, 0x08, 0x7d, 0xcb],
        },
        Case {
            name: "vpermt2b xmm4{k5},xmm6,xmm7",
            bytes: &[0x62, 0xf2, 0x4d, 0x0d, 0x7d, 0xe7],
        },
        Case {
            name: "vpermt2b xmm8{k5}{z},xmm9,xmm10",
            bytes: &[0x62, 0x52, 0x35, 0x8d, 0x7d, 0xc2],
        },
        Case {
            name: "vpermt2b ymm11,ymm12,ymm13",
            bytes: &[0x62, 0x52, 0x1d, 0x28, 0x7d, 0xdd],
        },
        Case {
            name: "vpermt2b ymm14{k5},ymm15,ymm16",
            bytes: &[0x62, 0x32, 0x05, 0x2d, 0x7d, 0xf0],
        },
        Case {
            name: "vpermt2b ymm17{k5}{z},ymm18,ymm19",
            bytes: &[0x62, 0xa2, 0x6d, 0xa5, 0x7d, 0xcb],
        },
        Case {
            name: "vpermt2b zmm20,zmm21,zmm22",
            bytes: &[0x62, 0xa2, 0x55, 0x40, 0x7d, 0xe6],
        },
        Case {
            name: "vpermt2b zmm23{k5},zmm24,zmm25",
            bytes: &[0x62, 0x82, 0x3d, 0x45, 0x7d, 0xf9],
        },
        Case {
            name: "vpermt2b zmm26{k5}{z},zmm27,zmm28",
            bytes: &[0x62, 0x02, 0x25, 0xc5, 0x7d, 0xd4],
        },
        Case {
            name: "vpermt2b xmm1{k5}{z},xmm2,[rsi]",
            bytes: &[0x62, 0xf2, 0x6d, 0x8d, 0x7d, 0x0e],
        },
        Case {
            name: "vpermt2b ymm3{k5}{z},ymm4,[rsi]",
            bytes: &[0x62, 0xf2, 0x5d, 0xad, 0x7d, 0x1e],
        },
        Case {
            name: "vpermt2b zmm5{k5}{z},zmm6,[rsi]",
            bytes: &[0x62, 0xf2, 0x4d, 0xcd, 0x7d, 0x2e],
        },
        Case {
            name: "vpmultishiftqb xmm1,xmm2,xmm3",
            bytes: &[0x62, 0xf2, 0xed, 0x08, 0x83, 0xcb],
        },
        Case {
            name: "vpmultishiftqb xmm4{k5},xmm6,xmm7",
            bytes: &[0x62, 0xf2, 0xcd, 0x0d, 0x83, 0xe7],
        },
        Case {
            name: "vpmultishiftqb xmm8{k5}{z},xmm9,xmm10",
            bytes: &[0x62, 0x52, 0xb5, 0x8d, 0x83, 0xc2],
        },
        Case {
            name: "vpmultishiftqb ymm11,ymm12,ymm13",
            bytes: &[0x62, 0x52, 0x9d, 0x28, 0x83, 0xdd],
        },
        Case {
            name: "vpmultishiftqb ymm14{k5},ymm15,ymm16",
            bytes: &[0x62, 0x32, 0x85, 0x2d, 0x83, 0xf0],
        },
        Case {
            name: "vpmultishiftqb ymm17{k5}{z},ymm18,ymm19",
            bytes: &[0x62, 0xa2, 0xed, 0xa5, 0x83, 0xcb],
        },
        Case {
            name: "vpmultishiftqb zmm20,zmm21,zmm22",
            bytes: &[0x62, 0xa2, 0xd5, 0x40, 0x83, 0xe6],
        },
        Case {
            name: "vpmultishiftqb zmm23{k5}{z},zmm24,zmm25",
            bytes: &[0x62, 0x82, 0xbd, 0xc5, 0x83, 0xf9],
        },
        Case {
            name: "vpmultishiftqb xmm1{k5}{z},xmm2,[rsi]",
            bytes: &[0x62, 0xf2, 0xed, 0x8d, 0x83, 0x0e],
        },
        Case {
            name: "vpmultishiftqb ymm3{k5}{z},ymm4,[rsi]",
            bytes: &[0x62, 0xf2, 0xdd, 0xad, 0x83, 0x1e],
        },
        Case {
            name: "vpmultishiftqb zmm5{k5}{z},zmm6,[rsi]",
            bytes: &[0x62, 0xf2, 0xcd, 0xcd, 0x83, 0x2e],
        },
        Case {
            name: "vpmultishiftqb xmm7{k5}{z},xmm8,[rsi]{1to2}",
            bytes: &[0x62, 0xf2, 0xbd, 0x9d, 0x83, 0x3e],
        },
        Case {
            name: "vpmultishiftqb ymm9{k5}{z},ymm10,[rsi]{1to4}",
            bytes: &[0x62, 0x72, 0xad, 0xbd, 0x83, 0x0e],
        },
        Case {
            name: "vpmultishiftqb zmm11{k5}{z},zmm12,[rsi]{1to8}",
            bytes: &[0x62, 0x72, 0x9d, 0xdd, 0x83, 0x1e],
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
            name: "vpcompressb xmm1,xmm2",
            bytes: &[0x62, 0xf2, 0x7d, 0x08, 0x63, 0xd1],
        },
        Case {
            name: "vpcompressb xmm3{k5},xmm4",
            bytes: &[0x62, 0xf2, 0x7d, 0x0d, 0x63, 0xe3],
        },
        Case {
            name: "vpcompressb xmm5{k5}{z},xmm6",
            bytes: &[0x62, 0xf2, 0x7d, 0x8d, 0x63, 0xf5],
        },
        Case {
            name: "vpcompressb ymm7,ymm8",
            bytes: &[0x62, 0x72, 0x7d, 0x28, 0x63, 0xc7],
        },
        Case {
            name: "vpcompressb ymm9{k5},ymm10",
            bytes: &[0x62, 0x52, 0x7d, 0x2d, 0x63, 0xd1],
        },
        Case {
            name: "vpcompressb ymm11{k5}{z},ymm12",
            bytes: &[0x62, 0x52, 0x7d, 0xad, 0x63, 0xe3],
        },
        Case {
            name: "vpcompressb zmm13,zmm14",
            bytes: &[0x62, 0x52, 0x7d, 0x48, 0x63, 0xf5],
        },
        Case {
            name: "vpcompressb zmm15{k5}{z},zmm16",
            bytes: &[0x62, 0xc2, 0x7d, 0xcd, 0x63, 0xc7],
        },
        Case {
            name: "vpcompressb [rdi]{k5},xmm26",
            bytes: &[0x62, 0x62, 0x7d, 0x0d, 0x63, 0x17],
        },
        Case {
            name: "vpcompressb [rdi]{k5},ymm26",
            bytes: &[0x62, 0x62, 0x7d, 0x2d, 0x63, 0x17],
        },
        Case {
            name: "vpcompressb [rdi]{k5},zmm26",
            bytes: &[0x62, 0x62, 0x7d, 0x4d, 0x63, 0x17],
        },
        Case {
            name: "vpcompressw xmm1,xmm2",
            bytes: &[0x62, 0xf2, 0xfd, 0x08, 0x63, 0xd1],
        },
        Case {
            name: "vpcompressw xmm3{k5},xmm4",
            bytes: &[0x62, 0xf2, 0xfd, 0x0d, 0x63, 0xe3],
        },
        Case {
            name: "vpcompressw xmm5{k5}{z},xmm6",
            bytes: &[0x62, 0xf2, 0xfd, 0x8d, 0x63, 0xf5],
        },
        Case {
            name: "vpcompressw ymm7,ymm8",
            bytes: &[0x62, 0x72, 0xfd, 0x28, 0x63, 0xc7],
        },
        Case {
            name: "vpcompressw ymm9{k5},ymm10",
            bytes: &[0x62, 0x52, 0xfd, 0x2d, 0x63, 0xd1],
        },
        Case {
            name: "vpcompressw ymm11{k5}{z},ymm12",
            bytes: &[0x62, 0x52, 0xfd, 0xad, 0x63, 0xe3],
        },
        Case {
            name: "vpcompressw zmm13,zmm14",
            bytes: &[0x62, 0x52, 0xfd, 0x48, 0x63, 0xf5],
        },
        Case {
            name: "vpcompressw zmm15{k5}{z},zmm16",
            bytes: &[0x62, 0xc2, 0xfd, 0xcd, 0x63, 0xc7],
        },
        Case {
            name: "vpcompressw [rdi]{k5},xmm26",
            bytes: &[0x62, 0x62, 0xfd, 0x0d, 0x63, 0x17],
        },
        Case {
            name: "vpcompressw [rdi]{k5},ymm26",
            bytes: &[0x62, 0x62, 0xfd, 0x2d, 0x63, 0x17],
        },
        Case {
            name: "vpcompressw [rdi]{k5},zmm26",
            bytes: &[0x62, 0x62, 0xfd, 0x4d, 0x63, 0x17],
        },
        Case {
            name: "vpexpandb xmm1,xmm2",
            bytes: &[0x62, 0xf2, 0x7d, 0x08, 0x62, 0xca],
        },
        Case {
            name: "vpexpandb xmm3{k6},xmm4",
            bytes: &[0x62, 0xf2, 0x7d, 0x0e, 0x62, 0xdc],
        },
        Case {
            name: "vpexpandb xmm5{k6}{z},xmm6",
            bytes: &[0x62, 0xf2, 0x7d, 0x8e, 0x62, 0xee],
        },
        Case {
            name: "vpexpandb ymm7,ymm8",
            bytes: &[0x62, 0xd2, 0x7d, 0x28, 0x62, 0xf8],
        },
        Case {
            name: "vpexpandb ymm9{k6},ymm10",
            bytes: &[0x62, 0x52, 0x7d, 0x2e, 0x62, 0xca],
        },
        Case {
            name: "vpexpandb ymm11{k6}{z},ymm12",
            bytes: &[0x62, 0x52, 0x7d, 0xae, 0x62, 0xdc],
        },
        Case {
            name: "vpexpandb zmm13,zmm14",
            bytes: &[0x62, 0x52, 0x7d, 0x48, 0x62, 0xee],
        },
        Case {
            name: "vpexpandb zmm15{k6},zmm16",
            bytes: &[0x62, 0x32, 0x7d, 0x4e, 0x62, 0xf8],
        },
        Case {
            name: "vpexpandb xmm27{k6}{z},[rsi]",
            bytes: &[0x62, 0x62, 0x7d, 0x8e, 0x62, 0x1e],
        },
        Case {
            name: "vpexpandb ymm27{k6}{z},[rsi]",
            bytes: &[0x62, 0x62, 0x7d, 0xae, 0x62, 0x1e],
        },
        Case {
            name: "vpexpandb zmm27{k6}{z},[rsi]",
            bytes: &[0x62, 0x62, 0x7d, 0xce, 0x62, 0x1e],
        },
        Case {
            name: "vpexpandw xmm1,xmm2",
            bytes: &[0x62, 0xf2, 0xfd, 0x08, 0x62, 0xca],
        },
        Case {
            name: "vpexpandw xmm3{k6},xmm4",
            bytes: &[0x62, 0xf2, 0xfd, 0x0e, 0x62, 0xdc],
        },
        Case {
            name: "vpexpandw xmm5{k6}{z},xmm6",
            bytes: &[0x62, 0xf2, 0xfd, 0x8e, 0x62, 0xee],
        },
        Case {
            name: "vpexpandw ymm7,ymm8",
            bytes: &[0x62, 0xd2, 0xfd, 0x28, 0x62, 0xf8],
        },
        Case {
            name: "vpexpandw ymm9{k6},ymm10",
            bytes: &[0x62, 0x52, 0xfd, 0x2e, 0x62, 0xca],
        },
        Case {
            name: "vpexpandw ymm11{k6}{z},ymm12",
            bytes: &[0x62, 0x52, 0xfd, 0xae, 0x62, 0xdc],
        },
        Case {
            name: "vpexpandw zmm13,zmm14",
            bytes: &[0x62, 0x52, 0xfd, 0x48, 0x62, 0xee],
        },
        Case {
            name: "vpexpandw zmm15{k6},zmm16",
            bytes: &[0x62, 0x32, 0xfd, 0x4e, 0x62, 0xf8],
        },
        Case {
            name: "vpexpandw xmm27{k6}{z},[rsi]",
            bytes: &[0x62, 0x62, 0xfd, 0x8e, 0x62, 0x1e],
        },
        Case {
            name: "vpexpandw ymm27{k6}{z},[rsi]",
            bytes: &[0x62, 0x62, 0xfd, 0xae, 0x62, 0x1e],
        },
        Case {
            name: "vpexpandw zmm27{k6}{z},[rsi]",
            bytes: &[0x62, 0x62, 0xfd, 0xce, 0x62, 0x1e],
        },
        Case {
            name: "vpcmpistri xmm1,xmm2,equal-any unsigned bytes",
            bytes: &[0xc4, 0xe3, 0x79, 0x63, 0xca, 0x00],
        },
        Case {
            name: "vpcmpistri xmm3,xmm4,ranges unsigned bytes",
            bytes: &[0xc4, 0xe3, 0x79, 0x63, 0xdc, 0x04],
        },
        Case {
            name: "vpcmpistri xmm5,xmm6,equal-each unsigned bytes",
            bytes: &[0xc4, 0xe3, 0x79, 0x63, 0xee, 0x08],
        },
        Case {
            name: "vpcmpistri xmm7,xmm8,equal-ordered unsigned bytes",
            bytes: &[0xc4, 0xc3, 0x79, 0x63, 0xf8, 0x0c],
        },
        Case {
            name: "vpcmpistri xmm9,xmm10,negative equal-each signed bytes",
            bytes: &[0xc4, 0x43, 0x79, 0x63, 0xca, 0x1a],
        },
        Case {
            name: "vpcmpistri xmm11,xmm12,masked-negative equal-each signed bytes",
            bytes: &[0xc4, 0x43, 0x79, 0x63, 0xdc, 0x3a],
        },
        Case {
            name: "vpcmpistri xmm13,xmm14,most-significant equal-each signed bytes",
            bytes: &[0xc4, 0x43, 0x79, 0x63, 0xee, 0x4a],
        },
        Case {
            name: "vpcmpistri xmm15,xmm0,masked-negative ordered signed words",
            bytes: &[0xc4, 0x63, 0x79, 0x63, 0xf8, 0x7f],
        },
        Case {
            name: "vpcmpistrm xmm1,xmm2,equal-any unsigned bytes bit-mask",
            bytes: &[0xc4, 0xe3, 0x79, 0x62, 0xca, 0x00],
        },
        Case {
            name: "vpcmpistrm xmm3,xmm4,masked equal-any unsigned words bit-mask",
            bytes: &[0xc4, 0xe3, 0x79, 0x62, 0xdc, 0x21],
        },
        Case {
            name: "vpcmpistrm xmm5,xmm6,equal-any unsigned bytes byte-mask",
            bytes: &[0xc4, 0xe3, 0x79, 0x62, 0xee, 0x40],
        },
        Case {
            name: "vpcmpistrm xmm7,xmm8,masked-negative ordered signed words word-mask",
            bytes: &[0xc4, 0xc3, 0x79, 0x62, 0xf8, 0x7f],
        },
        Case {
            name: "vaddps zmm0,zmm1,zmm2",
            bytes: &[0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2],
        },
        Case {
            name: "vaddpd ymm3{k6},ymm4,ymm5",
            bytes: &[0x62, 0xf1, 0xdd, 0x2e, 0x58, 0xdd],
        },
        Case {
            name: "vdivps ymm6,ymm7,ymm8",
            bytes: &[0xc4, 0xc1, 0x44, 0x5e, 0xf0],
        },
        Case {
            name: "vdivpd zmm9{k6}{z},zmm10,zmm11",
            bytes: &[0x62, 0x51, 0xad, 0xce, 0x5e, 0xcb],
        },
        Case {
            name: "vmaxps ymm12,ymm13,ymm14",
            bytes: &[0xc4, 0x41, 0x14, 0x5f, 0xe6],
        },
        Case {
            name: "vminpd zmm15,zmm16,zmm17",
            bytes: &[0x62, 0x31, 0xfd, 0x40, 0x5d, 0xf9],
        },
        Case {
            name: "vmulps zmm18,zmm19,zmm20",
            bytes: &[0x62, 0xa1, 0x64, 0x40, 0x59, 0xd4],
        },
        Case {
            name: "vmulpd ymm21{k6},ymm22,ymm23",
            bytes: &[0x62, 0xa1, 0xcd, 0x26, 0x59, 0xef],
        },
        Case {
            name: "vsqrtps ymm24,ymm25",
            bytes: &[0x62, 0x01, 0x7c, 0x28, 0x51, 0xc1],
        },
        Case {
            name: "vsqrtpd zmm26{k6}{z},zmm27",
            bytes: &[0x62, 0x01, 0xfd, 0xce, 0x51, 0xd3],
        },
        Case {
            name: "vsubps ymm28,ymm29,ymm30",
            bytes: &[0x62, 0x01, 0x14, 0x20, 0x5c, 0xe6],
        },
        Case {
            name: "vsubpd zmm1,zmm2,zmm3",
            bytes: &[0x62, 0xf1, 0xed, 0x48, 0x5c, 0xcb],
        },
        Case {
            name: "vunpckhps ymm4,ymm5,ymm6",
            bytes: &[0xc5, 0xd4, 0x15, 0xe6],
        },
        Case {
            name: "vunpcklpd zmm7{k6},zmm8,zmm9",
            bytes: &[0x62, 0xd1, 0xbd, 0x4e, 0x14, 0xf9],
        },
        Case {
            name: "vblendpd ymm10,ymm11,ymm12,0x9",
            bytes: &[0xc4, 0x43, 0x25, 0x0d, 0xd4, 0x09],
        },
        Case {
            name: "vblendps ymm13,ymm14,ymm15,0xa5",
            bytes: &[0xc4, 0x43, 0x0d, 0x0c, 0xef, 0xa5],
        },
        Case {
            name: "vblendvpd ymm1,ymm2,ymm3,ymm4",
            bytes: &[0xc4, 0xe3, 0x6d, 0x4b, 0xcb, 0x40],
        },
        Case {
            name: "vblendvps ymm5,ymm6,ymm7,ymm8",
            bytes: &[0xc4, 0xe3, 0x4d, 0x4a, 0xef, 0x80],
        },
        Case {
            name: "vmovddup zmm9,zmm10",
            bytes: &[0x62, 0x51, 0xff, 0x48, 0x12, 0xca],
        },
        Case {
            name: "vmovshdup zmm11{k6},zmm12",
            bytes: &[0x62, 0x51, 0x7e, 0x4e, 0x16, 0xdc],
        },
        Case {
            name: "vmovsldup ymm13,ymm14",
            bytes: &[0xc4, 0x41, 0x7e, 0x12, 0xee],
        },
        Case {
            name: "vmovntdqa zmm15,[rdi]",
            bytes: &[0x62, 0x72, 0x7d, 0x48, 0x2a, 0x3f],
        },
        Case {
            name: "vshufpd zmm16,zmm17,zmm18,0x96",
            bytes: &[0x62, 0xa1, 0xf5, 0x40, 0xc6, 0xc2, 0x96],
        },
        Case {
            name: "vshufps ymm19,ymm20,ymm21,0x39",
            bytes: &[0x62, 0xa1, 0x5c, 0x20, 0xc6, 0xdd, 0x39],
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
    for name in ["vmovmskpd_avx", "vmovmskps_avx"] {
        let id = vm.cpu.arch.sleigh.get_userop(name).expect("oracle userop");
        let expected = icicle_cpu::exec::helpers::x86::HELPERS
            .iter()
            .find_map(|(candidate, helper)| (*candidate == name).then_some(*helper))
            .expect("oracle helper mapping");
        assert_eq!(
            vm.cpu.helpers[id as usize] as usize, expected as usize,
            "{name} was not installed in the execution helper table"
        );
    }
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
            "{}:\n{}\nnative xmm1={:02x?}\nemulated xmm1={:02x?}",
            case.name,
            mismatches.join("\n"),
            &native_authority.xstate[176..192],
            &emulated.xstate[176..192],
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
fn evex_vsib_gather_and_scatter_match_native_state_and_memory() {
    let cases = [
        Case {
            name: "vsib vpgatherdd",
            bytes: &[0x62, 0xf2, 0x7d, 0x4a, 0x90, 0x0c, 0x1f],
        },
        Case {
            name: "vsib vpgatherdq",
            bytes: &[0x62, 0xf2, 0xfd, 0x4b, 0x90, 0x54, 0x67, 0x02],
        },
        Case {
            name: "vsib vpgatherqd",
            bytes: &[0x62, 0xf2, 0x7d, 0x4c, 0x91, 0x74, 0xaf, 0x08],
        },
        Case {
            name: "vsib vpgatherqq",
            bytes: &[0x62, 0x72, 0xfd, 0x4d, 0x91, 0x44, 0xff, 0x08],
        },
        Case {
            name: "vsib vgatherdps",
            bytes: &[0x62, 0x32, 0x7d, 0x4e, 0x92, 0x54, 0x0f, 0x18],
        },
        Case {
            name: "vsib vgatherdpd",
            bytes: &[0x62, 0x32, 0xfd, 0x4f, 0x92, 0x64, 0x5f, 0x10],
        },
        Case {
            name: "vsib vgatherqps",
            bytes: &[0x62, 0x32, 0x7d, 0x4a, 0x93, 0x74, 0xaf, 0x28],
        },
        Case {
            name: "vsib vgatherqpd",
            bytes: &[0x62, 0xa2, 0xfd, 0x4b, 0x93, 0x44, 0xff, 0x18],
        },
        Case {
            name: "vsib vpscatterdd",
            bytes: &[0x62, 0xe2, 0x7d, 0x44, 0xa0, 0x4c, 0x17, 0x38],
        },
        Case {
            name: "vsib vpscatterdq",
            bytes: &[0x62, 0xe2, 0xfd, 0x45, 0xa0, 0x5c, 0x67, 0x20],
        },
        Case {
            name: "vsib vpscatterqd",
            bytes: &[0x62, 0xe2, 0x7d, 0x46, 0xa1, 0x6c, 0xb7, 0x48],
        },
        Case {
            name: "vsib vpscatterqq",
            bytes: &[0x62, 0xa2, 0xfd, 0x47, 0xa1, 0x7c, 0xc7, 0x28],
        },
        Case {
            name: "vsib vscatterdps",
            bytes: &[0x62, 0x22, 0x7d, 0x42, 0xa2, 0x4c, 0x17, 0x58],
        },
        Case {
            name: "vsib vscatterdpd",
            bytes: &[0x62, 0x22, 0xfd, 0x43, 0xa2, 0x5c, 0x67, 0x30],
        },
        Case {
            name: "vsib vscatterqps",
            bytes: &[0x62, 0x22, 0x7d, 0x44, 0xa3, 0x6c, 0xb7, 0x68],
        },
        Case {
            name: "vsib vscatterqpd",
            bytes: &[0x62, 0x62, 0xfd, 0x4d, 0xa3, 0x7c, 0xcf, 0x38],
        },
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for case in cases {
        let native_authority = normalize_native(native(case), case, 0, false);
        let native_repeat = normalize_native(native(case), case, 0, false);
        assert!(
            differences(&native_authority, &native_repeat).is_empty(),
            "{} native authority was not repeatable",
            case.name
        );
        let emulated = emulated(&mut vm, case, 0x1000, 0x2000);
        let mismatches = differences(&native_authority, &emulated);
        assert!(
            mismatches.is_empty(),
            "{}:\n{}",
            case.name,
            mismatches.join("\n")
        );
    }
}

#[test]
fn vex_avx2_vsib_gathers_match_native_state_and_mask_updates() {
    let cases = [
        Case {
            name: "vex vsib vpgatherdd",
            bytes: &[0xc4, 0xe2, 0x55, 0x90, 0x0c, 0x1f],
        },
        Case {
            name: "vex vsib vpgatherdq",
            bytes: &[0xc4, 0xe2, 0xcd, 0x90, 0x54, 0x66, 0x08],
        },
        Case {
            name: "vex vsib vpgatherqd",
            bytes: &[0xc4, 0xa2, 0x25, 0x91, 0x7c, 0x8f, 0x10],
        },
        Case {
            name: "vex vsib vpgatherqq",
            bytes: &[0xc4, 0x22, 0x9d, 0x91, 0x44, 0xd6, 0x18],
        },
        Case {
            name: "vex vsib vgatherdps",
            bytes: &[0xc4, 0x22, 0x05, 0x92, 0x2c, 0x37],
        },
        Case {
            name: "vex vsib vgatherdpd",
            bytes: &[0xc4, 0xe2, 0xe5, 0x92, 0x4c, 0x56, 0x08],
        },
        Case {
            name: "vex vsib vgatherqps",
            bytes: &[0xc4, 0xe2, 0x4d, 0x93, 0x64, 0xaf, 0x10],
        },
        Case {
            name: "vex vsib vgatherqpd",
            bytes: &[0xc4, 0xa2, 0xb5, 0x93, 0x7c, 0xc6, 0x18],
        },
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for case in cases {
        let native_authority = normalize_native(native(case), case, 0, false);
        let native_repeat = normalize_native(native(case), case, 0, false);
        assert!(
            differences(&native_authority, &native_repeat).is_empty(),
            "{} native authority was not repeatable",
            case.name
        );
        let emulated = emulated(&mut vm, case, 0x1000, 0x2000);
        let mismatches = differences(&native_authority, &emulated);
        assert!(
            mismatches.is_empty(),
            "{}:\n{}",
            case.name,
            mismatches.join("\n")
        );
    }
}

#[test]
fn vex_avx2_vsib_gather_fault_preserves_completed_lanes_and_restart_mask() {
    let case = Case {
        name: "vsib fault vex vpgatherdd",
        bytes: &[0xc4, 0xe2, 0x55, 0x90, 0x0c, 0x1f],
    };
    let data_offset = PAGE - 8;
    let native_authority = normalize_native(
        native_with_layout(case, data_offset, true),
        case,
        data_offset,
        true,
    );
    let native_repeat = normalize_native(
        native_with_layout(case, data_offset, true),
        case,
        data_offset,
        true,
    );
    assert!(
        differences(&native_authority, &native_repeat).is_empty(),
        "native AVX2 gather partial fault was not repeatable"
    );
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    let emulated = emulated_with_layout(&mut vm, case, 0x1000, 0x2000, data_offset);
    let mismatches = differences(&native_authority, &emulated);
    assert!(
        mismatches.is_empty(),
        "{}:\n{}",
        case.name,
        mismatches.join("\n")
    );
}

#[test]
fn evex_getmant_intervals_sign_controls_and_edge_classes_match_native() {
    let cases = [
        Case {
            name: "edge vgetmantps 1_2 source-sign",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x26, 0xca, 0x00],
        },
        Case {
            name: "edge vgetmantps p5_2 source-sign",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x26, 0xca, 0x01],
        },
        Case {
            name: "edge vgetmantps p5_1 source-sign",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x26, 0xca, 0x02],
        },
        Case {
            name: "edge vgetmantps p75_1p5 source-sign",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x26, 0xca, 0x03],
        },
        Case {
            name: "edge vgetmantps 1_2 positive-sign",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x26, 0xca, 0x04],
        },
        Case {
            name: "edge vgetmantps 1_2 nan-negative",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x26, 0xca, 0x08],
        },
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for case in cases {
        let native_authority = normalize_native(native(case), case, 0, false);
        let native_repeat = normalize_native(native(case), case, 0, false);
        assert!(
            differences(&native_authority, &native_repeat).is_empty(),
            "{} native authority was not repeatable",
            case.name
        );
        let emulated = emulated(&mut vm, case, 0x1000, 0x2000);
        let mismatches = differences(&native_authority, &emulated);
        assert!(
            mismatches.is_empty(),
            "{}:\n{}",
            case.name,
            mismatches.join("\n")
        );
    }
}

#[test]
fn evex_getexp_rndscale_and_scalef_edge_classes_match_native() {
    let cases = [
        Case {
            name: "edge vgetexpps",
            bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x42, 0xca],
        },
        Case {
            name: "edge vrndscaleps nearest",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x08, 0xca, 0x00],
        },
        Case {
            name: "edge vrndscaleps down",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x08, 0xca, 0x01],
        },
        Case {
            name: "edge vrndscaleps up",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x08, 0xca, 0x02],
        },
        Case {
            name: "edge vrndscaleps truncate",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x08, 0xca, 0x03],
        },
        Case {
            name: "edge vrndscaleps scale",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x08, 0xca, 0x72],
        },
        Case {
            name: "edge vrndscaleps sae",
            bytes: &[0x62, 0xf3, 0x7d, 0x48, 0x08, 0xca, 0x08],
        },
        Case {
            name: "edge vscalefps",
            bytes: &[0x62, 0xf2, 0x6d, 0x48, 0x2c, 0xcb],
        },
        Case {
            name: "edge vscalefps with ignored segment prefix",
            bytes: &[0x2e, 0x62, 0xf2, 0x6d, 0x48, 0x2c, 0xcb],
        },
        Case {
            name: "edge vscalefpd",
            bytes: &[0x62, 0xf2, 0xed, 0x48, 0x2c, 0xcb],
        },
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for case in cases {
        let native_authority = normalize_native(native(case), case, 0, false);
        let native_repeat = normalize_native(native(case), case, 0, false);
        assert!(
            differences(&native_authority, &native_repeat).is_empty(),
            "{} native authority was not repeatable",
            case.name
        );
        let emulated = emulated(&mut vm, case, 0x1000, 0x2000);
        let mismatches = differences(&native_authority, &emulated);
        assert!(
            mismatches.is_empty(),
            "{}:\n{}",
            case.name,
            mismatches.join("\n")
        );
    }
}

#[test]
fn evex_helper_fetch_stops_at_the_instruction_mapping_boundary() {
    let case = Case {
        name: "boundary vscalefps zmm1,zmm2,zmm3",
        bytes: &[0x62, 0xf2, 0x6d, 0x48, 0x2c, 0xcb],
    };
    let page_base = 0x10_000_u64;
    let code = page_base + PAGE as u64 - case.bytes.len() as u64;
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    vm.cpu.mem.map_memory_len(
        page_base,
        PAGE as u64,
        Mapping {
            perm: perm::ALL,
            value: 0,
        },
    );
    vm.cpu
        .mem
        .write_bytes(code, case.bytes, perm::NONE)
        .expect("write boundary instruction");
    (vm.cpu.arch.on_boot)(&mut vm.cpu, code);

    let mut xstate = vec![0_u8; XSTATE_SIZE];
    fill_xstate(&mut xstate);
    prepare_special_float_case_xstate(case, &mut xstate);
    icicle_cpu::exec::helpers::x86::restore_standard_xstate_image(&mut vm.cpu, &xstate, true)
        .expect("restore emulator xstate");

    vm.icount_limit = 1;
    assert_eq!(vm.run(), VmExit::InstructionLimit);
    assert_eq!(vm.cpu.read_pc(), page_base + PAGE as u64);
}

fn state_zmm_f32(state: &ResultState, register: usize, lane: usize) -> f32 {
    f32::from_bits(u32::from_le_bytes(std::array::from_fn(|byte| {
        state.xstate[zmm_byte_offset(register, lane * 4 + byte)]
    })))
}

#[test]
fn evex_rcp14_and_rsqrt14_obey_error_bounds_and_native_special_state() {
    let cases = [
        (
            Case {
                name: "edge vrcp14ps",
                bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x4c, 0xca],
            },
            false,
        ),
        (
            Case {
                name: "edge vrsqrt14ps",
                bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x4e, 0xca],
            },
            true,
        ),
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for (case, reciprocal_sqrt) in cases {
        let native_authority = normalize_native(native(case), case, 0, false);
        let native_repeat = normalize_native(native(case), case, 0, false);
        assert!(
            differences(&native_authority, &native_repeat).is_empty(),
            "{} native authority was not repeatable",
            case.name
        );
        let emulated = emulated(&mut vm, case, 0x1000, 0x2000);
        let mut native_without_approximation = native_authority.clone();
        for byte in 0..64 {
            let offset = zmm_byte_offset(1, byte);
            native_without_approximation.xstate[offset] = emulated.xstate[offset];
        }
        let state_mismatches = differences(&native_without_approximation, &emulated);
        assert!(
            state_mismatches.is_empty(),
            "{} non-approximate state:\n{}",
            case.name,
            state_mismatches.join("\n")
        );
        for lane in 0..16 {
            let input = state_zmm_f32(&native_authority, 2, lane);
            let native_result = state_zmm_f32(&native_authority, 1, lane);
            let emulated_result = state_zmm_f32(&emulated, 1, lane);
            let reference = if reciprocal_sqrt {
                1.0_f32 / input.sqrt()
            } else {
                1.0_f32 / input
            };
            if reference.is_finite() && reference != 0.0 {
                for (authority, result) in
                    [("native", native_result), ("emulated", emulated_result)]
                {
                    let relative_error = ((result - reference) / reference).abs();
                    assert!(
                        relative_error <= 2.0_f32.powi(-14),
                        "{} lane {lane} {authority} error {relative_error:e}: input={input:e} result={result:e} reference={reference:e}",
                        case.name
                    );
                }
            } else {
                assert_eq!(
                    native_result.classify(),
                    emulated_result.classify(),
                    "{} lane {lane} special classification",
                    case.name
                );
                if native_result == 0.0 || native_result.is_infinite() {
                    assert_eq!(
                        native_result.to_bits(),
                        emulated_result.to_bits(),
                        "{} lane {lane} signed special result",
                        case.name
                    );
                }
            }
        }
    }
}

#[test]
fn evex_fixupimm_classes_actions_and_exception_selectors_match_native() {
    let cases = [
        Case {
            name: "edge vfixupimmps all classes and actions",
            bytes: &[0x62, 0xf3, 0x6d, 0x48, 0x54, 0xcb, 0xff],
        },
        Case {
            name: "edge vfixupimmss qnan exception selector",
            bytes: &[0x62, 0xf3, 0x6d, 0x08, 0x55, 0xcb, 0xff],
        },
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for case in cases {
        let native_authority = normalize_native(native(case), case, 0, false);
        let native_repeat = normalize_native(native(case), case, 0, false);
        assert!(
            differences(&native_authority, &native_repeat).is_empty(),
            "{} native authority was not repeatable",
            case.name
        );
        let emulated = emulated(&mut vm, case, 0x1000, 0x2000);
        let mismatches = differences(&native_authority, &emulated);
        assert!(
            mismatches.is_empty(),
            "{}:\n{}",
            case.name,
            mismatches.join("\n")
        );
    }
}

#[test]
fn evex_vsib_faults_preserve_completed_lanes_and_restart_mask() {
    let cases = [
        Case {
            name: "vsib fault vpgatherdd",
            bytes: &[0x62, 0xf2, 0x7d, 0x4d, 0x90, 0x0c, 0x1f],
        },
        Case {
            name: "vsib fault vpscatterdd",
            bytes: &[0x62, 0xe2, 0x7d, 0x45, 0xa0, 0x0c, 0x17],
        },
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    // Lane zero lands on the last two dwords of the data page. Lane two then
    // reaches the protected page, so native and emulated execution must keep
    // lane zero's completed side effect and leave lane two selected in K5.
    let data_offset = PAGE - 8;
    for case in cases {
        let native_authority = normalize_native(
            native_with_layout(case, data_offset, true),
            case,
            data_offset,
            true,
        );
        let native_repeat = normalize_native(
            native_with_layout(case, data_offset, true),
            case,
            data_offset,
            true,
        );
        let instability = differences(&native_authority, &native_repeat);
        assert!(
            instability.is_empty(),
            "{} native partial fault was unstable:\n{}",
            case.name,
            instability.join("\n")
        );
        let emulated = emulated_with_layout(&mut vm, case, 0x1000, 0x2000, data_offset);
        let mismatches = differences(&native_authority, &emulated);
        assert!(
            mismatches.is_empty(),
            "{}:\n{}",
            case.name,
            mismatches.join("\n")
        );
    }
}

#[test]
fn vex_compare_all_32_predicates_match_native_bit_for_bit() {
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for (kind, prefix) in [("vcmpps", 0xe8_u8), ("vcmppd", 0xe9_u8)] {
        for predicate in 0..32_u8 {
            let name: &'static str =
                Box::leak(format!("{kind} xmm1,xmm2,xmm3,{predicate:#04x}").into_boxed_str());
            let bytes: &'static [u8] =
                Box::leak(vec![0xc5, prefix, 0xc2, 0xcb, predicate].into_boxed_slice());
            let case = Case { name, bytes };
            let native_authority = normalize_native(native(case), case, 0, false);
            let emulated = emulated(&mut vm, case, 0x1000, 0x2000);
            let mismatches = differences(&native_authority, &emulated);
            assert!(
                mismatches.is_empty(),
                "{}:\n{}",
                case.name,
                mismatches.join("\n")
            );
        }
    }
}

#[test]
fn vex_reciprocal_estimates_stay_within_the_architectural_error_bound() {
    let cases = [
        (
            Case {
                name: "vrcpps xmm1,xmm2",
                bytes: &[0xc5, 0xf8, 0x53, 0xca],
            },
            4_usize,
        ),
        (
            Case {
                name: "vrcpps ymm1,ymm2",
                bytes: &[0xc5, 0xfc, 0x53, 0xca],
            },
            8,
        ),
        (
            Case {
                name: "vrcpss xmm1,xmm2,xmm3",
                bytes: &[0xc5, 0xea, 0x53, 0xcb],
            },
            1,
        ),
        (
            Case {
                name: "vrsqrtps xmm1,xmm2",
                bytes: &[0xc5, 0xf8, 0x52, 0xca],
            },
            4,
        ),
        (
            Case {
                name: "vrsqrtps ymm1,ymm2",
                bytes: &[0xc5, 0xfc, 0x52, 0xca],
            },
            8,
        ),
        (
            Case {
                name: "vrsqrtss xmm1,xmm2,xmm3",
                bytes: &[0xc5, 0xea, 0x52, 0xcb],
            },
            1,
        ),
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for (case, lanes) in cases {
        let native_authority = normalize_native(native(case), case, 0, false);
        let mut emulated = emulated(&mut vm, case, 0x1000, 0x2000);
        for lane in 0..lanes {
            let offset = if lane < 4 {
                160 + 16 + lane * 4
            } else {
                576 + 16 + (lane - 4) * 4
            };
            let native_bits = u32::from_le_bytes(
                native_authority.xstate[offset..offset + 4]
                    .try_into()
                    .unwrap(),
            );
            let emulated_bits =
                u32::from_le_bytes(emulated.xstate[offset..offset + 4].try_into().unwrap());
            let native_value = f32::from_bits(native_bits);
            let emulated_value = f32::from_bits(emulated_bits);
            if native_value.is_nan() {
                assert!(emulated_value.is_nan(), "{} lane {lane}", case.name);
            } else if native_value.is_infinite() || native_value == 0.0 {
                assert_eq!(
                    emulated_bits, native_bits,
                    "{} lane {lane} special value",
                    case.name
                );
            } else {
                let relative = ((emulated_value - native_value) / native_value).abs();
                assert!(
                    relative <= 0.001,
                    "{} lane {lane}: native={native_value:?} emulator={emulated_value:?} relative={relative}",
                    case.name
                );
            }
            emulated.xstate[offset..offset + 4]
                .copy_from_slice(&native_authority.xstate[offset..offset + 4]);
        }
        let mismatches = differences(&native_authority, &emulated);
        assert!(
            mismatches.is_empty(),
            "{} changed state outside approximate result lanes:\n{}",
            case.name,
            mismatches.join("\n")
        );
    }
}

#[test]
fn pcmpistri_and_pcmpistrm_all_control_bytes_match_native() {
    // Exercise every imm8 interpretation for three distinct implicit-length
    // relationships: both strings fill the register, the left string is
    // empty, and the right string is empty. XMM0 begins with a null byte;
    // XMM1/XMM2 use nonzero edge-pattern data from `fill_xstate`.
    let forms = [
        ("vpcmpistri", 0x63_u8, false),
        ("vpcmpistrm", 0x62_u8, true),
    ];
    let pairs = [
        ("full-full", 0xe3_u8, 0xca_u8),       // xmm1, xmm2
        ("empty-full", 0xe3_u8, 0xc1_u8),      // xmm0, xmm1
        ("full-empty", 0xe3_u8, 0xc8_u8),      // xmm1, xmm0
        ("partial-full", 0x63_u8, 0xc9_u8),    // xmm9, xmm1
        ("full-partial", 0xc3_u8, 0xc9_u8),    // xmm1, xmm9
        ("partial-partial", 0x43_u8, 0xc9_u8), // xmm9, xmm9
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");

    for (mnemonic, opcode, writes_mask) in forms {
        for (lengths, vex_map, modrm) in pairs {
            for control in 0_u8..=u8::MAX {
                let name: &'static str =
                    Box::leak(format!("{mnemonic} {lengths} imm={control:#04x}").into_boxed_str());
                let bytes: &'static [u8] =
                    Box::leak(vec![0xc4, vex_map, 0x79, opcode, modrm, control].into_boxed_slice());
                let case = Case { name, bytes };
                let native_authority = normalize_native(native(case), case, 0, false);
                let emulated = emulated(&mut vm, case, 0x1000, 0x2000);
                let mismatches = differences(&native_authority, &emulated);
                assert!(
                    mismatches.is_empty(),
                    "{}{}:\n{}",
                    case.name,
                    if writes_mask {
                        " (mask result)"
                    } else {
                        " (index result)"
                    },
                    mismatches.join("\n")
                );
            }
        }
    }
}

#[test]
fn pcmpestri_and_pcmpestrm_explicit_lengths_match_native() {
    let forms = [("vpcmpestri", 0x61_u8), ("vpcmpestrm", 0x60_u8)];
    let lengths = [
        (0_i32, 0_i32),
        (3, 7),
        (-3, 7),
        (7, -3),
        (16, 16),
        (17, i32::MIN),
        (8, 2),
    ];
    // Cover all aggregation operations, both nontrivial polarity modes, and
    // both index/mask output selections. The implicit-length exhaustive test
    // above independently covers all 256 control bytes for the shared core.
    let controls = [0x00_u8, 0x04, 0x08, 0x0c, 0x10, 0x30, 0x40, 0x7f];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");

    for (mnemonic, opcode) in forms {
        for (left_length, right_length) in lengths {
            for control in controls {
                let name: &'static str = Box::leak(
                    format!(
                        "{mnemonic} left={left_length} right={right_length} imm={control:#04x}"
                    )
                    .into_boxed_str(),
                );
                let bytes: &'static [u8] =
                    Box::leak(vec![0xc4, 0xe3, 0x79, opcode, 0xca, control].into_boxed_slice());
                let case = Case { name, bytes };
                let native_authority = normalize_native(
                    native_with_layout_and_lengths(
                        case,
                        0,
                        false,
                        Some((left_length, right_length)),
                    ),
                    case,
                    0,
                    false,
                );
                let emulated = emulated_with_layout_and_lengths(
                    &mut vm,
                    case,
                    0x1000,
                    0x2000,
                    0,
                    Some((left_length, right_length)),
                );
                let mismatches = differences(&native_authority, &emulated);
                assert!(
                    mismatches.is_empty(),
                    "{}:\n{}",
                    case.name,
                    mismatches.join("\n")
                );
            }
        }
    }
}

#[test]
fn vpmovzxbd_reads_exactly_sixteen_source_bytes_at_a_page_boundary() {
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    let cases = [
        (
            Case {
                name: "vpmovzxbd zmm0,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x31, 0x06],
            },
            PAGE - 16,
            false,
        ),
        (
            Case {
                name: "vpmovzxbd zmm0,[rsi] crossing boundary",
                bytes: &[0x62, 0xf2, 0x7d, 0x48, 0x31, 0x06],
            },
            PAGE - 15,
            true,
        ),
        (
            Case {
                name: "vpmovzxbd zmm0{k7},[rsi] masked boundary",
                bytes: &[0x62, 0xf2, 0x7d, 0x4f, 0x31, 0x06],
            },
            PAGE - 8,
            false,
        ),
        (
            Case {
                name: "vpmovzxbd zmm0{k7}{z},[rsi] masked crossing boundary",
                bytes: &[0x62, 0xf2, 0x7d, 0xcf, 0x31, 0x06],
            },
            PAGE - 7,
            true,
        ),
    ];
    for (case, data_offset, should_fault) in cases {
        let native = normalize_native(
            native_with_layout(case, data_offset, true),
            case,
            data_offset,
            should_fault,
        );
        assert_eq!(
            native.fault_signal.is_some(),
            should_fault,
            "native {} at offset {data_offset:#x}",
            case.name
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

#[test]
fn compress_expand_masked_page_boundaries_match_native_faults_and_partial_memory() {
    let cases = [
        (
            Case {
                name: "vpcompressd [rdi]{k5},zmm26 boundary",
                bytes: &[0x62, 0x62, 0x7d, 0x4d, 0x8b, 0x17],
            },
            24,
        ),
        (
            Case {
                name: "vpexpandd zmm27{k6}{z},[rsi] boundary",
                bytes: &[0x62, 0x62, 0x7d, 0xce, 0x89, 0x1e],
            },
            24,
        ),
        (
            Case {
                name: "vpcompressb [rdi]{k5},zmm26 boundary",
                bytes: &[0x62, 0x62, 0x7d, 0x4d, 0x63, 0x17],
            },
            15,
        ),
        (
            Case {
                name: "vpexpandb zmm27{k6}{z},[rsi] boundary",
                bytes: &[0x62, 0x62, 0x7d, 0xce, 0x62, 0x1e],
            },
            15,
        ),
        (
            Case {
                name: "vpcompressw [rdi]{k5},zmm26 boundary",
                bytes: &[0x62, 0x62, 0xfd, 0x4d, 0x63, 0x17],
            },
            20,
        ),
        (
            Case {
                name: "vpexpandw zmm27{k6}{z},[rsi] boundary",
                bytes: &[0x62, 0x62, 0xfd, 0xce, 0x62, 0x1e],
            },
            20,
        ),
    ];

    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for (case, selected_span) in cases {
        // Only compacted/expanded selected elements are accessed. Place the
        // exact selected span before the guard to succeed, then advance one
        // byte so the final selected element crosses into the guard page.
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

#[test]
fn vex_masked_moves_suppress_inactive_page_faults_and_match_native_stores() {
    let cases = [
        (
            Case {
                name: "vmaskmovdqu xmm1,xmm6 boundary",
                bytes: &[0xc5, 0xf9, 0xf7, 0xce],
            },
            16,
        ),
        (
            Case {
                name: "vmaskmovps ymm3,ymm4,[rdi] boundary",
                bytes: &[0xc4, 0xe2, 0x5d, 0x2c, 0x1f],
            },
            28,
        ),
        (
            Case {
                name: "vmaskmovps [rdi],ymm4,ymm3 boundary",
                bytes: &[0xc4, 0xe2, 0x5d, 0x2e, 0x1f],
            },
            28,
        ),
        (
            Case {
                name: "vmaskmovpd ymm7,ymm9,[rdi] boundary",
                bytes: &[0xc4, 0xe2, 0x35, 0x2d, 0x3f],
            },
            24,
        ),
        (
            Case {
                name: "vmaskmovpd [rdi],ymm9,ymm7 boundary",
                bytes: &[0xc4, 0xe2, 0x35, 0x2f, 0x3f],
            },
            24,
        ),
        (
            Case {
                name: "vpmaskmovd ymm3,ymm4,[rdi] boundary",
                bytes: &[0xc4, 0xe2, 0x5d, 0x8c, 0x1f],
            },
            28,
        ),
        (
            Case {
                name: "vpmaskmovd [rdi],ymm4,ymm3 boundary",
                bytes: &[0xc4, 0xe2, 0x5d, 0x8e, 0x1f],
            },
            28,
        ),
        (
            Case {
                name: "vpmaskmovq ymm7,ymm9,[rdi] boundary",
                bytes: &[0xc4, 0xe2, 0xb5, 0x8c, 0x3f],
            },
            24,
        ),
        (
            Case {
                name: "vpmaskmovq [rdi],ymm9,ymm7 boundary",
                bytes: &[0xc4, 0xe2, 0xb5, 0x8e, 0x3f],
            },
            24,
        ),
    ];

    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for (case, selected_span) in cases {
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

#[test]
fn vpopcnt_memory_masks_and_broadcasts_have_precise_faults() {
    let cases = [
        (
            Case {
                name: "vpopcntd zmm19{k5}{z},[rsi] boundary",
                bytes: &[0x62, 0xe2, 0x7d, 0xcd, 0x55, 0x1e],
            },
            44,
        ),
        (
            Case {
                name: "vpopcntq zmm19{k6}{z},[rsi] boundary",
                bytes: &[0x62, 0xe2, 0xfd, 0xce, 0x55, 0x1e],
            },
            32,
        ),
        (
            Case {
                name: "vpopcntd zmm22{k5}{z},[rsi]{1to16} boundary",
                bytes: &[0x62, 0xe2, 0x7d, 0xdd, 0x55, 0x36],
            },
            4,
        ),
        (
            Case {
                name: "vpopcntq zmm22{k6}{z},[rsi]{1to8} boundary",
                bytes: &[0x62, 0xe2, 0xfd, 0xde, 0x55, 0x36],
            },
            8,
        ),
    ];

    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for (case, selected_span) in cases {
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

#[test]
fn variable_shift_memory_suppresses_inactive_dword_faults() {
    let cases = [
        (
            Case {
                name: "vpsllvd zmm25{k5},zmm26,[rsi] boundary",
                bytes: &[0x62, 0x62, 0x2d, 0x45, 0x47, 0x0e],
            },
            44,
        ),
        (
            Case {
                name: "vpsrlvd zmm27{k5},zmm28,[rsi] boundary",
                bytes: &[0x62, 0x62, 0x1d, 0x45, 0x45, 0x1e],
            },
            44,
        ),
        (
            Case {
                name: "vpsllvd zmm5{k5}{z},zmm6,[rsi]{1to16} boundary",
                bytes: &[0x62, 0xf2, 0x4d, 0xdd, 0x47, 0x2e],
            },
            4,
        ),
        (
            Case {
                name: "vpsrlvd zmm11{k5}{z},zmm12,[rsi]{1to16} boundary",
                bytes: &[0x62, 0x72, 0x1d, 0xdd, 0x45, 0x1e],
            },
            4,
        ),
    ];
    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");

    // K5's highest selected dword is lane 10. Masked-off lanes 11 through 15
    // must not fault, while shifting lane 10 one byte into the guard must.
    for (case, selected_span) in cases {
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
fn vpmultishift_memory_masks_and_broadcasts_have_precise_faults() {
    let cases = [
        (
            Case {
                name: "vpmultishiftqb zmm5{k7}{z},zmm6,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0xcd, 0xcf, 0x83, 0x2e],
            },
            64,
        ),
        (
            Case {
                name: "vpmultishiftqb zmm11{k7}{z},zmm12,[rsi]{1to8} boundary",
                bytes: &[0x62, 0x72, 0x9d, 0xdf, 0x83, 0x1e],
            },
            8,
        ),
    ];

    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for (case, source_span) in cases {
        // VPMULTISHIFTQB has E4NF memory exceptions: its output writemask does
        // not suppress ordinary source reads. The normal form consumes the
        // complete vector even though K7 selects only lanes 0..7, while the
        // broadcast form consumes exactly one qword.
        for (data_offset, should_fault) in
            [(PAGE - source_span, false), (PAGE - source_span + 1, true)]
        {
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
fn byte_permute_memory_forms_have_precise_full_source_faults() {
    let cases = [
        (
            Case {
                name: "vpermb xmm1{k7}{z},xmm2,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x6d, 0x8f, 0x8d, 0x0e],
            },
            16,
        ),
        (
            Case {
                name: "vpermb ymm3{k7}{z},ymm4,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x5d, 0xaf, 0x8d, 0x1e],
            },
            32,
        ),
        (
            Case {
                name: "vpermb zmm5{k7}{z},zmm6,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x4d, 0xcf, 0x8d, 0x2e],
            },
            64,
        ),
        (
            Case {
                name: "vpermi2b xmm1{k7}{z},xmm2,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x6d, 0x8f, 0x75, 0x0e],
            },
            16,
        ),
        (
            Case {
                name: "vpermi2b ymm3{k7}{z},ymm4,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x5d, 0xaf, 0x75, 0x1e],
            },
            32,
        ),
        (
            Case {
                name: "vpermi2b zmm5{k7}{z},zmm6,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x4d, 0xcf, 0x75, 0x2e],
            },
            64,
        ),
        (
            Case {
                name: "vpermt2b xmm1{k7}{z},xmm2,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x6d, 0x8f, 0x7d, 0x0e],
            },
            16,
        ),
        (
            Case {
                name: "vpermt2b ymm3{k7}{z},ymm4,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x5d, 0xaf, 0x7d, 0x1e],
            },
            32,
        ),
        (
            Case {
                name: "vpermt2b zmm5{k7}{z},zmm6,[rsi] boundary",
                bytes: &[0x62, 0xf2, 0x4d, 0xcf, 0x7d, 0x2e],
            },
            64,
        ),
    ];

    let mut vm = build_x64_vm(&ldef(), &EngineConfig::default()).expect("build engine");
    for (case, source_span) in cases {
        // These full-vector memory operands consume every source byte even
        // when K7 selects only result lanes 0..7.
        for (data_offset, should_fault) in
            [(PAGE - source_span, false), (PAGE - source_span + 1, true)]
        {
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
