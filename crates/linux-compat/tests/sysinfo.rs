//! x86-64 `sysinfo(2)` layout regression tests.

use std::path::PathBuf;

use linux_compat::Machine;
use x64_engine::EngineConfig;

const SYS_SYSINFO: u64 = 99;
const PAGE_SIZE: u64 = 4096;

fn machine() -> Machine {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut machine = Machine::from_ldef(
        &root.join("third_party/ghidra-x86/languages/x86.ldefs"),
        &EngineConfig::default(),
    )
    .expect("machine build failed");
    machine
        .add_file(
            b"/bin/probe",
            std::fs::read(root.join("test_data/hello_linux.elf")).expect("in-repo fixture"),
            0o755,
        )
        .expect("seed image");
    machine.load(b"/bin/probe").expect("load guest");
    machine
}

#[test]
fn sysinfo_uses_the_linux_x86_64_field_offsets() {
    let mut machine = machine();
    let address = 0x6fff_0000;
    machine.vm_mut().cpu.mem.map_memory_len(
        address,
        PAGE_SIZE,
        icicle_cpu::mem::Mapping {
            perm: icicle_cpu::mem::perm::READ
                | icicle_cpu::mem::perm::WRITE
                | icicle_cpu::mem::perm::INIT,
            value: 0,
        },
    );
    let (result, exited) = machine.issue_syscall(SYS_SYSINFO, [address, 0, 0, 0, 0, 0]);
    assert!(!exited);
    assert_eq!(result, 0);

    let mut bytes = [0_u8; 112];
    machine
        .vm_mut()
        .cpu
        .mem
        .read_bytes(address, &mut bytes, icicle_cpu::mem::perm::READ)
        .expect("read sysinfo");
    let u64_at = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    assert_eq!(u64_at(32), machine.vm_mut().cpu.mem.capacity() as u64);
    assert!(u64_at(32) > 0, "totalram must never be reported as zero");
    assert!(u64_at(40) <= u64_at(32), "freeram cannot exceed totalram");
    assert_eq!(u16::from_le_bytes(bytes[80..82].try_into().unwrap()), 1);
    assert_eq!(
        u32::from_le_bytes(bytes[104..108].try_into().unwrap()),
        PAGE_SIZE as u32
    );
}
