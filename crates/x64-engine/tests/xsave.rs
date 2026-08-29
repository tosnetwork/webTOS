//! Standard-format XSAVE/XRSTOR gates.

use std::path::PathBuf;

use icicle_cpu::{
    mem::{perm, Mapping},
    ValueSource,
};
use x64_engine::{build::build_x64_vm, EngineConfig, InterpVm, VmExit};

const CODE_ADDR: u64 = 0x1000;
const IMAGE_ADDR: u64 = 0x2000;
const XSAVE_SIZE: usize = 2688;

fn vm_for(instruction: &[u8]) -> InterpVm {
    let ldef = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs");
    let mut vm = build_x64_vm(&ldef, &EngineConfig::default()).expect("build x86-64 engine");
    vm.cpu.mem.map_memory_len(
        CODE_ADDR,
        0x3000,
        Mapping {
            perm: perm::ALL,
            value: 0,
        },
    );
    vm.cpu
        .mem
        .write_bytes(CODE_ADDR, instruction, perm::NONE)
        .expect("write instruction");
    (vm.cpu.arch.on_boot)(&mut vm.cpu, CODE_ADDR);
    for (name, value) in [("RDI", IMAGE_ADDR), ("RAX", 0xe7), ("RDX", 0)] {
        let var = vm.cpu.arch.sleigh.get_varnode(name).unwrap();
        vm.cpu.write_var(var, value);
    }
    vm
}

fn slice(vm: &InterpVm, name: &str, offset: u8, size: u8) -> pcode::VarNode {
    vm.cpu
        .arch
        .sleigh
        .get_reg(name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .slice_var(offset, size)
        .unwrap_or_else(|| panic!("missing {name}[{offset}..{}]", offset + size))
}

#[test]
fn xsave64_uses_the_same_component_layout_as_cpuid_0d() {
    // REX.W + 0f ae /4: XSAVE64 [rdi].
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x27]);
    let ymm0_high = [0x22; 16];
    let zmm0_high_256_a = [0x33; 16];
    let zmm0_high_256_b = [0x44; 16];
    let zmm16 = [[0x50; 16], [0x51; 16], [0x52; 16], [0x53; 16]];
    vm.cpu.write_var(slice(&vm, "ZMM0", 16, 16), ymm0_high);
    vm.cpu
        .write_var(slice(&vm, "ZMM0", 32, 16), zmm0_high_256_a);
    vm.cpu
        .write_var(slice(&vm, "ZMM0", 48, 16), zmm0_high_256_b);
    for (index, value) in zmm16.into_iter().enumerate() {
        vm.cpu
            .write_var(slice(&vm, "ZMM16", (index * 16) as u8, 16), value);
    }
    let k0 = vm.cpu.arch.sleigh.get_varnode("K0").unwrap();
    vm.cpu.write_var(k0, 0x0123_4567_89ab_cdef_u64);
    vm.icount_limit = 1;

    assert!(matches!(vm.run(), VmExit::InstructionLimit));
    let mut image = vec![0_u8; XSAVE_SIZE];
    vm.cpu
        .mem
        .read_bytes(IMAGE_ADDR, &mut image, perm::READ)
        .unwrap();
    assert_eq!(&image[512..520], &0xe7_u64.to_le_bytes());
    assert_eq!(&image[520..576], &[0; 56]);
    assert_eq!(&image[576..592], &ymm0_high);
    assert_eq!(&image[1088..1096], &0x0123_4567_89ab_cdef_u64.to_le_bytes());
    assert_eq!(&image[1152..1168], &zmm0_high_256_a);
    assert_eq!(&image[1168..1184], &zmm0_high_256_b);
    for (index, value) in zmm16.into_iter().enumerate() {
        let offset = 1664 + index * 16;
        assert_eq!(&image[offset..offset + 16], &value);
    }
}
