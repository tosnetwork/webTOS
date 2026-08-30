//! System V process-entry stack invariants used by dynamic loaders.

use std::path::PathBuf;

use icicle_cpu::mem::perm;
use icicle_cpu::ValueSource;
use linux_compat::Machine;
use x64_engine::EngineConfig;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn sample_elf() -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/hello_linux.elf"))
        .expect("in-repo fixture")
}

#[test]
fn argv_terminator_has_mapped_zero_filled_scan_slack() {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/probe", sample_elf(), 0o755)
        .expect("seed image");
    machine.set_args(vec![b"x".to_vec()], Vec::new());
    machine.load(b"/bin/probe").expect("load guest");

    let vm = machine.vm_mut();
    let rsp: u64 = vm.cpu.read_dynamic(vm.cpu.arch.reg_sp.into()).zxt();
    let mut pointer = [0_u8; 8];
    vm.cpu
        .mem
        .read_bytes(rsp + 8, &mut pointer, perm::READ)
        .expect("read argv[0] pointer");
    let argv0 = u64::from_le_bytes(pointer);

    let mut bytes = [0xff_u8; 64];
    vm.cpu
        .mem
        .read_bytes(argv0, &mut bytes, perm::READ)
        .expect("a bounded vector scan may read past argv[0]'s NUL");
    assert_eq!(bytes[0], b'x');
    assert_eq!(bytes[1], 0);
    assert!(
        bytes[2..].iter().all(|&byte| byte == 0),
        "initial-string scan slack must not disclose stale memory"
    );
}
