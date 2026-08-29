//! Architectural FXSAVE/FXRSTOR image gates.

use std::path::PathBuf;

use icicle_cpu::{
    mem::{perm, Mapping},
    ValueSource,
};
use x64_engine::{build::build_x64_vm, EngineConfig, ExceptionCode, InterpVm, VmExit};

const CODE_ADDR: u64 = 0x1000;
const IMAGE_ADDR: u64 = 0x2000;

fn vm_for(instruction: &[u8]) -> InterpVm {
    let ldef = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs");
    let mut vm = build_x64_vm(&ldef, &EngineConfig::default()).expect("build x86-64 engine");
    vm.cpu.mem.map_memory_len(
        CODE_ADDR,
        0x2000,
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
    let rdi = vm.cpu.arch.sleigh.get_varnode("RDI").unwrap();
    vm.cpu.write_var(rdi, IMAGE_ADDR);
    vm
}

fn reg(vm: &InterpVm, name: &str) -> pcode::VarNode {
    vm.cpu
        .arch
        .sleigh
        .get_varnode(name)
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn read_image(vm: &mut InterpVm) -> [u8; 512] {
    let mut image = [0_u8; 512];
    vm.cpu
        .mem
        .read_bytes(IMAGE_ADDR, &mut image, perm::READ)
        .expect("read fx image");
    image
}

fn write_image(vm: &mut InterpVm, image: &[u8; 512]) {
    vm.cpu
        .mem
        .write_bytes(IMAGE_ADDR, image, perm::WRITE)
        .expect("write fx image");
}

#[test]
fn fxsave64_writes_the_architectural_legacy_image() {
    // REX.W + 0f ae /0: FXSAVE64 [rdi].
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x07]);
    vm.cpu.write_var(reg(&vm, "FPUControlWord"), 0x037f_u16);
    vm.cpu.write_var(reg(&vm, "FPUStatusWord"), 0x4123_u16);
    vm.cpu.write_var(reg(&vm, "FPUTagWord"), 0xfffc_u16);
    vm.cpu
        .write_var(reg(&vm, "FPULastInstructionOpcode"), 0x05ab_u16);
    vm.cpu
        .write_var(reg(&vm, "FPUInstructionPointer"), 0x0123_4567_89ab_cdef_u64);
    vm.cpu
        .write_var(reg(&vm, "FPUDataPointer"), 0xfedc_ba98_7654_3210_u64);
    vm.cpu.write_var(reg(&vm, "MXCSR"), 0x1f80_u32);
    let st0 = [1, 2, 3, 4, 5, 6, 7, 0x80, 0xff, 0x3f];
    let xmm0 = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    vm.cpu.write_var(reg(&vm, "ST0"), st0);
    vm.cpu.write_var(reg(&vm, "XMM0"), xmm0);
    vm.icount_limit = 1;

    assert!(matches!(vm.run(), VmExit::InstructionLimit));
    let image = read_image(&mut vm);
    assert_eq!(&image[0..2], &0x037f_u16.to_le_bytes());
    assert_eq!(&image[2..4], &0x4123_u16.to_le_bytes());
    assert_eq!(image[4], 0x01, "FXSAVE stores the abridged x87 tag word");
    assert_eq!(&image[6..8], &(0x05ab_u16 & 0x07ff).to_le_bytes());
    assert_eq!(&image[8..16], &0x0123_4567_89ab_cdef_u64.to_le_bytes());
    assert_eq!(&image[16..24], &0xfedc_ba98_7654_3210_u64.to_le_bytes());
    assert_eq!(&image[24..28], &0x1f80_u32.to_le_bytes());
    assert_eq!(&image[28..32], &0x0000_ffff_u32.to_le_bytes());
    assert_eq!(&image[32..42], &st0);
    assert_eq!(&image[160..176], &xmm0);
}

#[test]
fn fxrstor64_reconstructs_tags_and_restores_legacy_state() {
    let mut image = [0_u8; 512];
    image[0..2].copy_from_slice(&0x027f_u16.to_le_bytes());
    image[2..4].copy_from_slice(&0x3800_u16.to_le_bytes());
    image[4] = 0b0000_0011;
    image[6..8].copy_from_slice(&0x0312_u16.to_le_bytes());
    image[8..16].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
    image[16..24].copy_from_slice(&0xfedc_ba98_7654_3210_u64.to_le_bytes());
    image[24..28].copy_from_slice(&0x1f40_u32.to_le_bytes());
    // ST0 is a normal extended value; ST1 is zero. Other tags are empty.
    image[32..42].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 0x80, 0xff, 0x3f]);
    image[48..58].copy_from_slice(&[0; 10]);
    let xmm15 = [0x5a; 16];
    image[400..416].copy_from_slice(&xmm15);

    // REX.W + 0f ae /1: FXRSTOR64 [rdi].
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x0f]);
    write_image(&mut vm, &image);
    vm.icount_limit = 1;
    assert!(matches!(vm.run(), VmExit::InstructionLimit));

    assert_eq!(vm.cpu.read_var::<u16>(reg(&vm, "FPUControlWord")), 0x027f);
    assert_eq!(vm.cpu.read_var::<u16>(reg(&vm, "FPUStatusWord")), 0x3800);
    assert_eq!(
        vm.cpu.read_var::<u16>(reg(&vm, "FPUTagWord")),
        0xfff4,
        "normal, zero, then six empty x87 tags"
    );
    assert_eq!(
        vm.cpu.read_var::<u16>(reg(&vm, "FPULastInstructionOpcode")),
        0x0312
    );
    assert_eq!(
        vm.cpu.read_var::<u64>(reg(&vm, "FPUInstructionPointer")),
        0x0123_4567_89ab_cdef
    );
    assert_eq!(
        vm.cpu.read_var::<u64>(reg(&vm, "FPUDataPointer")),
        0xfedc_ba98_7654_3210
    );
    assert_eq!(vm.cpu.read_var::<u32>(reg(&vm, "MXCSR")), 0x1f40);
    assert_eq!(vm.cpu.read_var::<[u8; 16]>(reg(&vm, "XMM15")), xmm15);
}

#[test]
fn fxrstor_rejects_reserved_mxcsr_bits_before_changing_state() {
    let mut image = [0_u8; 512];
    image[0..2].copy_from_slice(&0x0123_u16.to_le_bytes());
    image[24..28].copy_from_slice(&0x8000_1f80_u32.to_le_bytes());
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x0f]);
    write_image(&mut vm, &image);
    vm.cpu.write_var(reg(&vm, "FPUControlWord"), 0x037f_u16);
    vm.icount_limit = 1;

    assert!(matches!(
        vm.run(),
        VmExit::UnhandledException((ExceptionCode::GeneralProtection, 0))
    ));
    assert_eq!(vm.cpu.read_var::<u16>(reg(&vm, "FPUControlWord")), 0x037f);
}

#[test]
fn fxsave_requires_sixteen_byte_alignment() {
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x07]);
    let rdi = reg(&vm, "RDI");
    vm.cpu.write_var(rdi, IMAGE_ADDR + 1);
    vm.icount_limit = 1;

    assert!(matches!(
        vm.run(),
        VmExit::UnhandledException((ExceptionCode::GeneralProtection, 0))
    ));
}
