//! Architectural XCR0 policy gates.

use std::path::PathBuf;

use icicle_cpu::mem::{perm, Mapping};
use x64_engine::{build::build_x64_vm, EngineConfig, ExceptionCode, InterpVm, VmExit};

const CODE_ADDR: u64 = 0x1000;

fn vm_for(instruction: &[u8]) -> InterpVm {
    let ldef = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs");
    let mut vm = build_x64_vm(&ldef, &EngineConfig::default()).expect("build x86-64 engine");
    vm.cpu.mem.map_memory_len(
        CODE_ADDR,
        0x1000,
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
    vm
}

fn reg(vm: &InterpVm, name: &str) -> pcode::VarNode {
    vm.cpu
        .arch
        .sleigh
        .get_varnode(name)
        .unwrap_or_else(|| panic!("missing {name}"))
}

#[test]
fn xgetbv_exposes_the_immutable_user_xstate_policy() {
    let mut vm = vm_for(&[0x0f, 0x01, 0xd0]);
    let rax = reg(&vm, "RAX");
    let rcx = reg(&vm, "RCX");
    let rdx = reg(&vm, "RDX");
    vm.cpu.write_reg(rcx, 0_u64);
    vm.icount_limit = 1;

    let exit = vm.run();
    assert!(matches!(exit, VmExit::InstructionLimit));
    let xcr0 = vm.cpu.read_reg(rax) | (vm.cpu.read_reg(rdx) << 32);
    assert_eq!(xcr0, 0xe7, "x87, XMM, YMM, opmask and both ZMM components");
}

#[test]
fn xgetbv_rejects_nonzero_selectors() {
    let mut vm = vm_for(&[0x0f, 0x01, 0xd0]);
    let rcx = reg(&vm, "RCX");
    vm.cpu.write_reg(rcx, 1_u64);
    vm.icount_limit = 1;

    assert!(matches!(
        vm.run(),
        VmExit::UnhandledException((ExceptionCode::GeneralProtection, 0))
    ));
}

#[test]
fn user_mode_xsetbv_faults_without_mutating_xcr0() {
    let mut vm = vm_for(&[0x0f, 0x01, 0xd1]);
    let rax = reg(&vm, "RAX");
    let rcx = reg(&vm, "RCX");
    let rdx = reg(&vm, "RDX");
    let xcr0 = reg(&vm, "XCR0");
    vm.cpu.write_reg(rax, 0_u64);
    vm.cpu.write_reg(rcx, 0_u64);
    vm.cpu.write_reg(rdx, 0_u64);
    vm.icount_limit = 1;

    assert!(matches!(
        vm.run(),
        VmExit::UnhandledException((ExceptionCode::GeneralProtection, 0))
    ));
    assert_eq!(vm.cpu.read_reg(xcr0), 0xe7);
}
