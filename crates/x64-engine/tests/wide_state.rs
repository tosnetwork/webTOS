//! Wide architectural register-state gates.

use std::path::PathBuf;

use icicle_cpu::{ExceptionCode, ValueSource};
use pcode::{Inputs, Op, VarNode};
use x64_engine::{build::build_x64_vm, EngineConfig, InterpVm};

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

fn wide_slices(vm: &InterpVm, name: &str, size: u8) -> Vec<VarNode> {
    let register = vm
        .cpu
        .arch
        .sleigh
        .get_reg(name)
        .unwrap_or_else(|| panic!("missing {name}"));
    (0..size)
        .step_by(16)
        .map(|offset| {
            register
                .slice_var(offset, 16)
                .unwrap_or_else(|| panic!("missing {name}[{offset}..{}]", offset + 16))
        })
        .collect()
}

fn pattern(register: usize) -> [u8; 64] {
    let mut bytes = [0_u8; 64];
    for (lane, byte) in bytes.iter_mut().enumerate() {
        *byte = (register as u8).wrapping_mul(67).wrapping_add(lane as u8);
    }
    bytes
}

#[test]
fn all_zmm_registers_alias_their_xmm_and_ymm_views() {
    let mut vm = vm();

    for index in 0..32 {
        let xmm = reg(&vm, &format!("XMM{index}"));
        let ymm = wide_slices(&vm, &format!("YMM{index}"), 32);
        let zmm = wide_slices(&vm, &format!("ZMM{index}"), 64);
        assert_eq!(ymm.len(), 2);
        assert_eq!(zmm.len(), 4);

        let seeded = pattern(index);
        for (slice, bytes) in zmm.iter().zip(seeded.chunks_exact(16)) {
            vm.cpu
                .write_var(*slice, <[u8; 16]>::try_from(bytes).unwrap());
        }
        assert_eq!(vm.cpu.read_var::<[u8; 16]>(xmm), seeded[..16]);
        assert_eq!(vm.cpu.read_var::<[u8; 16]>(ymm[0]), seeded[..16]);
        assert_eq!(vm.cpu.read_var::<[u8; 16]>(ymm[1]), seeded[16..32]);
        for (slice, expected) in zmm.iter().zip(seeded.chunks_exact(16)) {
            assert_eq!(vm.cpu.read_var::<[u8; 16]>(*slice), expected);
        }

        let low = [0xa5; 16];
        vm.cpu.write_var(xmm, low);
        assert_eq!(vm.cpu.read_var::<[u8; 16]>(zmm[0]), low);
        for (slice, expected) in zmm[1..].iter().zip(seeded[16..].chunks_exact(16)) {
            assert_eq!(vm.cpu.read_var::<[u8; 16]>(*slice), expected);
        }
    }
}

#[test]
fn all_opmask_registers_are_independent_64_bit_state() {
    let mut vm = vm();

    for index in 0..8 {
        let mask = reg(&vm, &format!("K{index}"));
        assert_eq!(mask.size, 8);
        vm.cpu
            .write_var(mask, 0x0102_0304_0506_0708_u64 ^ index as u64);
    }
    for index in 0..8 {
        let mask = reg(&vm, &format!("K{index}"));
        assert_eq!(
            vm.cpu.read_var::<u64>(mask),
            0x0102_0304_0506_0708_u64 ^ index as u64
        );
    }
}

#[test]
fn additional_helper_arguments_reject_wide_values_instead_of_truncating() {
    let mut vm = vm();
    let zmm0 = {
        #[allow(deprecated)]
        let raw = vm.cpu.arch.sleigh.get_reg("ZMM0").unwrap().var;
        raw
    };
    let arg = (VarNode::NONE, Op::Arg(2), Inputs::one(zmm0)).into();

    // This models a third p-codeop operand. The current helper ABI stores
    // additional operands in one u128 slot, so accepting ZMM here would
    // silently discard 384 bits.
    unsafe { vm.cpu.interpret_unchecked(arg) };
    assert_eq!(
        ExceptionCode::from_u32(vm.cpu.exception.code),
        ExceptionCode::InvalidOpSize
    );
    assert_eq!(vm.cpu.exception.value, 64);
}
