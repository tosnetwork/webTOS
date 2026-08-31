//! Mandatory EVEX execution canaries from the pinned Claude/Bun workload.

use std::path::PathBuf;

use icicle_cpu::{
    mem::{perm, Mapping},
    ValueSource,
};
use pcode::VarNode;
use x64_engine::{build::build_x64_vm, EngineConfig, InterpVm, VmExit};

const CODE_ADDR: u64 = 0x1000;
const DATA_ADDR: u64 = 0x8000;
const CLAUDE_BROADCAST_RIP: u64 = 0x399_b8e2;
const CLAUDE_BROADCAST: [u8; 10] = [0x62, 0xf2, 0x7d, 0x48, 0x58, 0x0d, 0x54, 0x67, 0xc5, 0xfc];
const CLAUDE_TERNLOG: [u8; 7] = [0x62, 0xf3, 0x75, 0x48, 0x25, 0x06, 0xf8];
const CLAUDE_MASK_TO_QWORDS: [u8; 6] = [0x62, 0x72, 0xfe, 0x48, 0x38, 0xd0];
const CLAUDE_COMPARE_EQUAL_BYTES: [u8; 6] = [0x62, 0xf1, 0x5d, 0x40, 0x74, 0xd4];

fn vm() -> InterpVm {
    let ldef = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs");
    build_x64_vm(&ldef, &EngineConfig::default()).expect("build x86-64 engine")
}

fn reg(vm: &InterpVm, name: &str) -> VarNode {
    vm.cpu
        .arch
        .sleigh
        .get_varnode(name)
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn zmm_slice(vm: &InterpVm, name: &str, index: usize) -> VarNode {
    vm.cpu
        .arch
        .sleigh
        .get_reg(name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .slice_var((index * 16) as u8, 16)
        .unwrap_or_else(|| panic!("missing {name} slice {index}"))
}

fn map_page(vm: &mut InterpVm, address: u64) {
    vm.cpu.mem.map_memory_len(
        address & !0xfff,
        0x1000,
        Mapping {
            perm: perm::ALL,
            value: 0,
        },
    );
}

fn run_one(vm: &mut InterpVm) -> VmExit {
    let before = vm.cpu.icount;
    vm.icount_limit = before + 1;
    vm.run()
}

fn read_zmm(vm: &InterpVm, name: &str) -> [u128; 4] {
    std::array::from_fn(|index| vm.cpu.read_var(zmm_slice(vm, name, index)))
}

fn write_zmm(vm: &mut InterpVm, name: &str, value: [u128; 4]) {
    for (index, chunk) in value.into_iter().enumerate() {
        vm.cpu.write_var(zmm_slice(vm, name, index), chunk);
    }
}

fn read_zmm_dwords(vm: &InterpVm, name: &str) -> [u32; 16] {
    let chunks = read_zmm(vm, name);
    std::array::from_fn(|lane| (chunks[lane / 4] >> ((lane % 4) * 32)) as u32)
}

fn write_zmm_dwords(vm: &mut InterpVm, name: &str, value: [u32; 16]) {
    let chunks = std::array::from_fn(|chunk| {
        let mut value128 = 0_u128;
        for lane in 0..4 {
            value128 |= u128::from(value[chunk * 4 + lane]) << (lane * 32);
        }
        value128
    });
    write_zmm(vm, name, chunks);
}

fn execute_broadcast(
    vm: &mut InterpVm,
    p2: u8,
    opcode: u8,
    modrm: u8,
    source: u32,
    mask: u64,
) -> [u32; 16] {
    vm.cpu.reset();
    vm.flush_code();
    vm.cpu
        .mem
        .write_bytes(
            CODE_ADDR,
            &[0x62, 0xf2, 0x7d, p2, opcode, modrm],
            perm::NONE,
        )
        .unwrap();
    vm.cpu
        .mem
        .write_bytes(DATA_ADDR, &source.to_le_bytes(), perm::NONE)
        .unwrap();
    (vm.cpu.arch.on_boot)(&mut vm.cpu, CODE_ADDR);
    vm.cpu.write_var(reg(vm, "RDI"), DATA_ADDR);
    vm.cpu.write_var(reg(vm, "RAX"), u64::from(source));
    vm.cpu.write_var(reg(vm, "K1"), mask);
    write_zmm_dwords(vm, "ZMM1", std::array::from_fn(|lane| 0x1000 + lane as u32));
    let exit = run_one(vm);
    assert!(matches!(exit, VmExit::InstructionLimit), "{exit:?}");
    read_zmm_dwords(vm, "ZMM1")
}

fn ternary_chunk(destination: u128, source1: u128, source2: u128, table: u8) -> u128 {
    let mut result = 0_u128;
    for index in 0..8 {
        if table & (1 << index) == 0 {
            continue;
        }
        let d = if index & 4 != 0 {
            destination
        } else {
            !destination
        };
        let a = if index & 2 != 0 { source1 } else { !source1 };
        let b = if index & 1 != 0 { source2 } else { !source2 };
        result |= d & a & b;
    }
    result
}

#[test]
fn claude_vpbroadcastd_replicates_the_rip_relative_dword_to_all_zmm_lanes() {
    let mut vm = vm();
    map_page(&mut vm, CLAUDE_BROADCAST_RIP);
    vm.cpu
        .mem
        .write_bytes(CLAUDE_BROADCAST_RIP, &CLAUDE_BROADCAST, perm::NONE)
        .unwrap();

    let displacement = i64::from(i32::from_le_bytes(
        CLAUDE_BROADCAST[6..10].try_into().unwrap(),
    ));
    let source = (CLAUDE_BROADCAST_RIP + CLAUDE_BROADCAST.len() as u64)
        .checked_add_signed(displacement)
        .unwrap();
    map_page(&mut vm, source);
    let dword = 0x89ab_cdef_u32;
    vm.cpu
        .mem
        .write_bytes(source, &dword.to_le_bytes(), perm::NONE)
        .unwrap();
    (vm.cpu.arch.on_boot)(&mut vm.cpu, CLAUDE_BROADCAST_RIP);
    write_zmm(&mut vm, "ZMM1", [u128::MAX; 4]);

    let exit = run_one(&mut vm);
    assert!(matches!(exit, VmExit::InstructionLimit), "{exit:?}");
    let repeated = u128::from(dword)
        | (u128::from(dword) << 32)
        | (u128::from(dword) << 64)
        | (u128::from(dword) << 96);
    assert_eq!(read_zmm(&vm, "ZMM1"), [repeated; 4]);
}

#[test]
fn vpbroadcastd_covers_all_vector_lengths_and_gpr_source_decoding() {
    let mut vm = vm();
    map_page(&mut vm, CODE_ADDR);
    map_page(&mut vm, DATA_ADDR);
    let source = 0x89ab_cdef;

    for (p2, lanes) in [(0x08, 4), (0x28, 8), (0x48, 16)] {
        for (opcode, modrm) in [(0x58, 0x0f), (0x7c, 0xc8)] {
            let actual = execute_broadcast(&mut vm, p2, opcode, modrm, source, u64::MAX);
            let expected = std::array::from_fn(|lane| if lane < lanes { source } else { 0 });
            assert_eq!(actual, expected, "p2={p2:#04x}, opcode={opcode:#04x}");
        }
    }
}

#[test]
fn vpbroadcastd_honors_merge_and_zero_masks_while_k0_is_unmasked() {
    let mut vm = vm();
    map_page(&mut vm, CODE_ADDR);
    map_page(&mut vm, DATA_ADDR);
    let source = 0x89ab_cdef;
    let mask = 0xa55a_u64;

    let merged = execute_broadcast(&mut vm, 0x49, 0x58, 0x0f, source, mask);
    let expected_merge = std::array::from_fn(|lane| {
        if mask & (1 << lane) != 0 {
            source
        } else {
            0x1000 + lane as u32
        }
    });
    assert_eq!(merged, expected_merge);

    let zeroed = execute_broadcast(&mut vm, 0xc9, 0x58, 0x0f, source, mask);
    let expected_zero =
        std::array::from_fn(|lane| if mask & (1 << lane) != 0 { source } else { 0 });
    assert_eq!(zeroed, expected_zero);

    let k0 = execute_broadcast(&mut vm, 0x48, 0x58, 0x0f, source, 0);
    assert_eq!(k0, [source; 16]);
}

#[test]
fn claude_vpmovm2q_expands_each_k_mask_bit_to_a_full_qword() {
    let mut vm = vm();
    map_page(&mut vm, CODE_ADDR);
    vm.cpu
        .mem
        .write_bytes(CODE_ADDR, &CLAUDE_MASK_TO_QWORDS, perm::NONE)
        .unwrap();
    (vm.cpu.arch.on_boot)(&mut vm.cpu, CODE_ADDR);

    let mask = 0b1010_0101_u64;
    vm.cpu.write_var(reg(&vm, "K0"), mask);
    write_zmm(&mut vm, "ZMM10", [u128::MAX; 4]);

    let exit = run_one(&mut vm);
    assert!(matches!(exit, VmExit::InstructionLimit), "{exit:?}");

    let expected = std::array::from_fn(|chunk| {
        let mut value = 0_u128;
        for lane in 0..2 {
            if mask & (1 << (chunk * 2 + lane)) != 0 {
                value |= u128::from(u64::MAX) << (lane * 64);
            }
        }
        value
    });
    assert_eq!(read_zmm(&vm, "ZMM10"), expected);
}

#[test]
fn claude_vpcmpeqb_compares_all_64_zmm_byte_lanes() {
    let mut vm = vm();
    map_page(&mut vm, CODE_ADDR);
    vm.cpu
        .mem
        .write_bytes(CODE_ADDR, &CLAUDE_COMPARE_EQUAL_BYTES, perm::NONE)
        .unwrap();
    (vm.cpu.arch.on_boot)(&mut vm.cpu, CODE_ADDR);

    let left = std::array::from_fn(|index| index as u8 ^ 0xa5);
    let mut right = left;
    for index in [0, 17, 34, 63] {
        right[index] ^= 0xff;
    }
    let pack = |bytes: [u8; 64]| {
        std::array::from_fn(|chunk| {
            u128::from_le_bytes(bytes[chunk * 16..(chunk + 1) * 16].try_into().unwrap())
        })
    };
    write_zmm(&mut vm, "ZMM20", pack(left));
    write_zmm(&mut vm, "ZMM4", pack(right));
    vm.cpu.write_var(reg(&vm, "K2"), u64::MAX);

    let exit = run_one(&mut vm);
    assert!(matches!(exit, VmExit::InstructionLimit), "{exit:?}");

    let expected = left
        .iter()
        .zip(right)
        .enumerate()
        .fold(0_u64, |mask, (lane, (left, right))| {
            mask | (u64::from(left == &right) << lane)
        });
    assert_eq!(vm.cpu.read_var::<u64>(reg(&vm, "K2")), expected);
}

#[test]
fn claude_vpternlogd_matches_all_256_truth_tables_in_every_zmm_chunk() {
    let mut vm = vm();
    map_page(&mut vm, CODE_ADDR);
    map_page(&mut vm, DATA_ADDR);

    let destination: [u128; 4] = [
        0x0123_4567_89ab_cdef_fedc_ba98_7654_3210,
        0xffff_0000_aaaa_5555_0f0f_f0f0_3333_cccc,
        0x8000_0001_7fff_fffe_dead_beef_cafe_babe,
        0x1357_9bdf_2468_ace0_1122_3344_5566_7788,
    ];
    let source1: [u128; 4] = [
        0xfedc_ba98_7654_3210_0123_4567_89ab_cdef,
        0x5555_aaaa_ffff_0000_f0f0_0f0f_cccc_3333,
        0x7fff_fffe_8000_0001_cafe_babe_dead_beef,
        0x0246_8ace_1357_9bdf_8877_6655_4433_2211,
    ];
    let source2: [u128; 4] = [
        0xa5a5_5a5a_9696_6969_c3c3_3c3c_f00f_0ff0,
        0x3333_cccc_5555_aaaa_ffff_0000_00ff_ff00,
        0x0101_8080_7f7f_fefe_1234_5678_9abc_def0,
        0xffff_ffff_0000_0000_aaaa_aaaa_5555_5555,
    ];
    let mut source2_bytes = [0_u8; 64];
    for (bytes, chunk) in source2_bytes.chunks_exact_mut(16).zip(source2) {
        bytes.copy_from_slice(&chunk.to_le_bytes());
    }
    vm.cpu
        .mem
        .write_bytes(DATA_ADDR, &source2_bytes, perm::NONE)
        .unwrap();

    for table in 0_u16..=255 {
        vm.cpu.reset();
        vm.flush_code();
        let mut instruction = CLAUDE_TERNLOG;
        instruction[6] = table as u8;
        vm.cpu
            .mem
            .write_bytes(CODE_ADDR, &instruction, perm::NONE)
            .unwrap();
        (vm.cpu.arch.on_boot)(&mut vm.cpu, CODE_ADDR);
        write_zmm(&mut vm, "ZMM0", destination);
        write_zmm(&mut vm, "ZMM1", source1);
        vm.cpu.write_var(reg(&vm, "RSI"), DATA_ADDR);

        let exit = run_one(&mut vm);
        assert!(
            matches!(exit, VmExit::InstructionLimit),
            "imm={table:#04x}: {exit:?}"
        );
        let expected = std::array::from_fn(|index| {
            ternary_chunk(
                destination[index],
                source1[index],
                source2[index],
                table as u8,
            )
        });
        assert_eq!(read_zmm(&vm, "ZMM0"), expected, "imm={table:#04x}");
    }
}
