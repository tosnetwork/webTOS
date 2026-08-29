//! Standard-format XSAVE/XRSTOR gates.

use std::path::PathBuf;

use icicle_cpu::{
    mem::{perm, Mapping},
    ValueSource,
};
use x64_engine::{build::build_x64_vm, EngineConfig, ExceptionCode, InterpVm, VmExit};

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

fn reg(vm: &InterpVm, name: &str) -> pcode::VarNode {
    vm.cpu
        .arch
        .sleigh
        .get_varnode(name)
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn set_mask(vm: &mut InterpVm, mask: u64) {
    vm.cpu.write_var(reg(vm, "RAX"), mask & 0xffff_ffff);
    vm.cpu.write_var(reg(vm, "RDX"), mask >> 32);
}

fn write_image(vm: &mut InterpVm, address: u64, image: &[u8]) {
    vm.cpu
        .mem
        .write_bytes(address, image, perm::WRITE)
        .expect("write xsave image");
}

fn read_image(vm: &mut InterpVm, address: u64) -> Vec<u8> {
    let mut image = vec![0_u8; XSAVE_SIZE];
    vm.cpu
        .mem
        .read_bytes(address, &mut image, perm::READ)
        .expect("read xsave image");
    image
}

fn run_one(vm: &mut InterpVm) -> VmExit {
    vm.icount_limit = 1;
    vm.run()
}

fn write_zmm(vm: &mut InterpVm, name: &str, value: [u8; 64]) {
    for lane in 0..4_u8 {
        vm.cpu.write_var(
            slice(vm, name, lane * 16, 16),
            <[u8; 16]>::try_from(&value[lane as usize * 16..lane as usize * 16 + 16]).unwrap(),
        );
    }
}

fn read_zmm(vm: &InterpVm, name: &str) -> [u8; 64] {
    let mut value = [0_u8; 64];
    for lane in 0..4_u8 {
        value[lane as usize * 16..lane as usize * 16 + 16]
            .copy_from_slice(&vm.cpu.read_var::<[u8; 16]>(slice(vm, name, lane * 16, 16)));
    }
    value
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
    assert_eq!(
        &image[512..520],
        &0xe4_u64.to_le_bytes(),
        "XSTATE_BV reports in-use state rather than echoing RFBM"
    );
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

#[test]
fn xsave64_honors_the_requested_mask_and_preserves_unselected_header_bits() {
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x27]);
    let mut before = vec![0xa5_u8; XSAVE_SIZE];
    let old_bv = (1_u64 << 1) | (1_u64 << 5);
    before[512..520].copy_from_slice(&old_bv.to_le_bytes());
    write_image(&mut vm, IMAGE_ADDR, &before);
    set_mask(&mut vm, 1 << 2);
    vm.cpu.write_var(reg(&vm, "FPUControlWord"), 0x0123_u16);
    vm.cpu.write_var(reg(&vm, "XMM0"), [0x11_u8; 16]);
    vm.cpu.write_var(slice(&vm, "ZMM0", 16, 16), [0x22_u8; 16]);

    assert!(matches!(run_one(&mut vm), VmExit::InstructionLimit));
    let after = read_image(&mut vm, IMAGE_ADDR);
    assert_eq!(&after[0..24], &before[0..24], "x87 was not requested");
    assert_eq!(&after[160..176], &before[160..176], "SSE was not requested");
    assert_eq!(
        &after[24..28],
        &0x1f80_u32.to_le_bytes(),
        "AVX also saves MXCSR"
    );
    assert_eq!(&after[28..32], &0x0000_ffff_u32.to_le_bytes());
    assert_eq!(&after[576..592], &[0x22; 16]);
    assert_eq!(
        &after[1088..1096],
        &before[1088..1096],
        "opmask was not requested"
    );
    assert_eq!(
        u64::from_le_bytes(after[512..520].try_into().unwrap()),
        old_bv | (1 << 2),
        "unselected XSTATE_BV bits survive"
    );
    assert_eq!(
        &after[520..576],
        &before[520..576],
        "reserved header bytes survive"
    );
}

#[test]
fn xsave64_clears_requested_xstate_bv_for_init_state_but_still_writes_component() {
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x27]);
    let mut before = vec![0x5a_u8; XSAVE_SIZE];
    before[512..520].copy_from_slice(&(1_u64 << 2).to_le_bytes());
    write_image(&mut vm, IMAGE_ADDR, &before);
    set_mask(&mut vm, 1 << 2);

    assert!(matches!(run_one(&mut vm), VmExit::InstructionLimit));
    let after = read_image(&mut vm, IMAGE_ADDR);
    assert_eq!(u64::from_le_bytes(after[512..520].try_into().unwrap()), 0);
    assert_eq!(
        &after[576..832],
        &[0; 256],
        "plain XSAVE does not omit init data"
    );
    assert_eq!(&after[520..576], &before[520..576]);
}

#[test]
fn fresh_machine_xsave64_serializes_the_architectural_initial_state() {
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x27]);
    assert!(matches!(run_one(&mut vm), VmExit::InstructionLimit));
    let image = read_image(&mut vm, IMAGE_ADDR);

    assert_eq!(u64::from_le_bytes(image[512..520].try_into().unwrap()), 0);
    assert_eq!(&image[0..2], &0x037f_u16.to_le_bytes());
    assert_eq!(&image[2..4], &0_u16.to_le_bytes());
    assert_eq!(
        image[4], 0,
        "the abridged tag word marks all x87 slots empty"
    );
    assert_eq!(&image[24..28], &0x1f80_u32.to_le_bytes());
    assert_eq!(&image[28..32], &0x0000_ffff_u32.to_le_bytes());
    assert_eq!(&image[32..160], &[0; 128]);
    assert_eq!(&image[160..416], &[0; 256]);
    assert_eq!(&image[576..], &[0; XSAVE_SIZE - 576]);
}

#[test]
fn xrstor64_applies_present_components_initializes_absent_ones_and_preserves_unrequested_state() {
    // REX.W + 0f ae /5: XRSTOR64 [rdi].
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x2f]);
    let mut image = vec![0_u8; XSAVE_SIZE];
    image[24..28].copy_from_slice(&0x1f40_u32.to_le_bytes());
    image[512..520].copy_from_slice(&((1_u64 << 2) | (1_u64 << 5)).to_le_bytes());
    image[576..592].copy_from_slice(&[0x22; 16]);
    image[1088..1096].copy_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());
    write_image(&mut vm, IMAGE_ADDR, &image);
    set_mask(&mut vm, 0x27);

    vm.cpu.write_var(reg(&vm, "FPUControlWord"), 0x0123_u16);
    vm.cpu.write_var(reg(&vm, "FPUTagWord"), 0_u16);
    vm.cpu.write_var(reg(&vm, "ST0"), [0x77_u8; 10]);
    vm.cpu.write_var(reg(&vm, "XMM0"), [0x11_u8; 16]);
    vm.cpu.write_var(slice(&vm, "ZMM0", 16, 16), [0x33_u8; 16]);
    vm.cpu.write_var(slice(&vm, "ZMM0", 32, 16), [0x44_u8; 16]);
    vm.cpu.write_var(reg(&vm, "K0"), u64::MAX);
    write_zmm(&mut vm, "ZMM16", [0x55_u8; 64]);

    assert!(matches!(run_one(&mut vm), VmExit::InstructionLimit));
    assert_eq!(vm.cpu.read_var::<u16>(reg(&vm, "FPUControlWord")), 0x037f);
    assert_eq!(vm.cpu.read_var::<u16>(reg(&vm, "FPUTagWord")), 0xffff);
    assert_eq!(vm.cpu.read_var::<[u8; 10]>(reg(&vm, "ST0")), [0; 10]);
    assert_eq!(vm.cpu.read_var::<u32>(reg(&vm, "MXCSR")), 0x1f40);
    assert_eq!(vm.cpu.read_var::<[u8; 16]>(reg(&vm, "XMM0")), [0; 16]);
    assert_eq!(
        vm.cpu.read_var::<[u8; 16]>(slice(&vm, "ZMM0", 16, 16)),
        [0x22; 16]
    );
    assert_eq!(
        vm.cpu.read_var::<[u8; 16]>(slice(&vm, "ZMM0", 32, 16)),
        [0x44; 16],
        "unrequested ZMM_Hi256 survives"
    );
    assert_eq!(
        vm.cpu.read_var::<u64>(reg(&vm, "K0")),
        0x0123_4567_89ab_cdef
    );
    assert_eq!(read_zmm(&vm, "ZMM16"), [0x55; 64]);
}

#[test]
fn xrstor64_rejects_all_reserved_header_bytes_before_mutating_state() {
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x2f]);
    let mut image = vec![0_u8; XSAVE_SIZE];
    image[528] = 1;
    write_image(&mut vm, IMAGE_ADDR, &image);
    set_mask(&mut vm, 1 << 5);
    vm.cpu.write_var(reg(&vm, "K0"), 0xfeed_face_cafe_beef_u64);

    assert!(matches!(
        run_one(&mut vm),
        VmExit::UnhandledException((ExceptionCode::GeneralProtection, 0))
    ));
    assert_eq!(
        vm.cpu.read_var::<u64>(reg(&vm, "K0")),
        0xfeed_face_cafe_beef
    );
}

#[test]
fn xrstor64_validates_mxcsr_whenever_sse_or_avx_is_requested() {
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x2f]);
    let mut image = vec![0_u8; XSAVE_SIZE];
    image[24..28].copy_from_slice(&0x8000_1f80_u32.to_le_bytes());
    write_image(&mut vm, IMAGE_ADDR, &image);
    set_mask(&mut vm, 1 << 2);
    vm.cpu.write_var(slice(&vm, "ZMM0", 16, 16), [0x77_u8; 16]);

    assert!(matches!(
        run_one(&mut vm),
        VmExit::UnhandledException((ExceptionCode::GeneralProtection, 0))
    ));
    assert_eq!(
        vm.cpu.read_var::<[u8; 16]>(slice(&vm, "ZMM0", 16, 16)),
        [0x77; 16]
    );
}

#[test]
fn xsave_and_xrstor64_round_trip_every_enabled_component() {
    let mut save = vm_for(&[0x48, 0x0f, 0xae, 0x27]);
    save.cpu.write_var(reg(&save, "FPUControlWord"), 0x027f_u16);
    save.cpu.write_var(reg(&save, "FPUStatusWord"), 0x3800_u16);
    save.cpu.write_var(reg(&save, "FPUTagWord"), 0xfffc_u16);
    save.cpu.write_var(reg(&save, "ST0"), [0x19_u8; 10]);
    save.cpu.write_var(reg(&save, "MXCSR"), 0x1f40_u32);
    save.cpu.write_var(reg(&save, "XMM0"), [0x21_u8; 16]);
    save.cpu
        .write_var(slice(&save, "ZMM0", 16, 16), [0x22_u8; 16]);
    save.cpu
        .write_var(reg(&save, "K7"), 0x2345_6789_abcd_ef01_u64);
    save.cpu
        .write_var(slice(&save, "ZMM15", 32, 16), [0x23_u8; 16]);
    write_zmm(&mut save, "ZMM31", [0x24_u8; 64]);
    assert!(matches!(run_one(&mut save), VmExit::InstructionLimit));
    let image = read_image(&mut save, IMAGE_ADDR);
    assert_eq!(
        u64::from_le_bytes(image[512..520].try_into().unwrap()),
        0xe7
    );

    let mut restore = vm_for(&[0x48, 0x0f, 0xae, 0x2f]);
    write_image(&mut restore, IMAGE_ADDR, &image);
    assert!(matches!(run_one(&mut restore), VmExit::InstructionLimit));
    assert_eq!(
        restore.cpu.read_var::<u16>(reg(&restore, "FPUControlWord")),
        0x027f
    );
    assert_eq!(
        restore.cpu.read_var::<u16>(reg(&restore, "FPUStatusWord")),
        0x3800
    );
    assert_eq!(
        restore.cpu.read_var::<[u8; 10]>(reg(&restore, "ST0")),
        [0x19; 10]
    );
    assert_eq!(restore.cpu.read_var::<u32>(reg(&restore, "MXCSR")), 0x1f40);
    assert_eq!(
        restore.cpu.read_var::<[u8; 16]>(reg(&restore, "XMM0")),
        [0x21; 16]
    );
    assert_eq!(
        restore
            .cpu
            .read_var::<[u8; 16]>(slice(&restore, "ZMM0", 16, 16)),
        [0x22; 16]
    );
    assert_eq!(
        restore.cpu.read_var::<u64>(reg(&restore, "K7")),
        0x2345_6789_abcd_ef01
    );
    assert_eq!(
        restore
            .cpu
            .read_var::<[u8; 16]>(slice(&restore, "ZMM15", 32, 16)),
        [0x23; 16]
    );
    assert_eq!(read_zmm(&restore, "ZMM31"), [0x24; 64]);
}

#[test]
fn xrstor64_page_crossing_fault_is_precise_and_does_not_commit_staged_state() {
    let address = 0x3900_u64;
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x2f]);
    vm.cpu.write_var(reg(&vm, "RDI"), address);
    set_mask(&mut vm, 1 << 7);
    let mut header = [0_u8; 64];
    header[..8].copy_from_slice(&(1_u64 << 7).to_le_bytes());
    write_image(&mut vm, address + 512, &header);
    write_image(&mut vm, address + 1664, &[0x42; 128]);
    write_zmm(&mut vm, "ZMM16", [0x77_u8; 64]);
    write_zmm(&mut vm, "ZMM17", [0x77_u8; 64]);

    assert!(matches!(
        run_one(&mut vm),
        VmExit::UnhandledException((ExceptionCode::ReadUnmapped, 0x4000))
    ));
    assert_eq!(read_zmm(&vm, "ZMM16"), [0x77; 64]);
    assert_eq!(read_zmm(&vm, "ZMM17"), [0x77; 64]);
    assert_eq!(vm.cpu.read_pc(), CODE_ADDR, "faults restart at XRSTOR64");
}

#[test]
fn xsave64_page_crossing_fault_reports_the_first_inaccessible_component_byte() {
    let address = 0x3900_u64;
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x27]);
    vm.cpu.write_var(reg(&vm, "RDI"), address);
    set_mask(&mut vm, 1 << 7);
    write_zmm(&mut vm, "ZMM16", [0x42_u8; 64]);
    write_zmm(&mut vm, "ZMM17", [0x43_u8; 64]);
    write_zmm(&mut vm, "ZMM18", [0x44_u8; 64]);

    assert!(matches!(
        run_one(&mut vm),
        VmExit::UnhandledException((ExceptionCode::WriteUnmapped, 0x4000))
    ));
    let mut saved_prefix = [0_u8; 128];
    vm.cpu
        .mem
        .read_bytes(address + 1664, &mut saved_prefix, perm::READ)
        .unwrap();
    assert_eq!(&saved_prefix[..64], &[0x42; 64]);
    assert_eq!(&saved_prefix[64..], &[0x43; 64]);
    assert_eq!(vm.cpu.read_pc(), CODE_ADDR, "faults restart at XSAVE64");
}

#[test]
fn xsave64_requires_sixty_four_byte_alignment() {
    let mut vm = vm_for(&[0x48, 0x0f, 0xae, 0x27]);
    vm.cpu.write_var(reg(&vm, "RDI"), IMAGE_ADDR + 1);
    assert!(matches!(
        run_one(&mut vm),
        VmExit::UnhandledException((ExceptionCode::GeneralProtection, 0))
    ));
}
