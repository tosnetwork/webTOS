//! Observable `madvise` memory semantics used by production allocators.

use std::path::PathBuf;

use icicle_cpu::mem::perm;
use linux_compat::Machine;
use x64_engine::EngineConfig;

const SYS_MMAP: u64 = 9;
const SYS_MADVISE: u64 = 28;
const PROT_READ_WRITE: u64 = 3;
const PROT_READ_WRITE_EXEC: u64 = 7;
const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;
const MADV_DONTNEED: u64 = 4;

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
fn dontneed_discards_anonymous_bytes_and_preserves_the_mapping() {
    let mut machine = machine();
    let (address, exited) = machine.issue_syscall(
        SYS_MMAP,
        [0, 8192, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, u64::MAX, 0],
    );
    assert!(!exited);
    assert!(address > 0, "mmap failed: {address}");
    let address = address as u64;

    machine
        .vm_mut()
        .cpu
        .mem
        .write_bytes(address + 37, &[0xa5; 128], perm::WRITE)
        .expect("dirty anonymous memory");
    let (result, exited) =
        machine.issue_syscall(SYS_MADVISE, [address, 8192, MADV_DONTNEED, 0, 0, 0]);
    assert!(!exited);
    assert_eq!(result, 0);

    let mut bytes = [0xff; 128];
    machine
        .vm_mut()
        .cpu
        .mem
        .read_bytes(address + 37, &mut bytes, perm::READ)
        .expect("the advised mapping must remain readable");
    assert_eq!(bytes, [0; 128]);
    machine
        .vm_mut()
        .cpu
        .mem
        .write_bytes(address, &[0x5a], perm::WRITE)
        .expect("the advised mapping must remain writable");
}

#[test]
fn dontneed_on_executed_anonymous_code_discards_bytes_and_invalidates_code_cache() {
    let mut machine = machine();
    let (address, exited) = machine.issue_syscall(
        SYS_MMAP,
        [
            0,
            4096,
            PROT_READ_WRITE_EXEC,
            MAP_PRIVATE_ANONYMOUS,
            u64::MAX,
            0,
        ],
    );
    assert!(!exited);
    assert!(address > 0, "mmap failed: {address}");
    let address = address as u64;

    machine
        .vm_mut()
        .cpu
        .mem
        .write_bytes(address, &[0x90], perm::WRITE)
        .expect("seed executable byte");
    assert!(machine.vm_mut().cpu.mem.ensure_executable(address, 1));

    let (result, exited) =
        machine.issue_syscall(SYS_MADVISE, [address, 4096, MADV_DONTNEED, 0, 0, 0]);
    assert!(!exited);
    assert_eq!(
        result, 0,
        "DONTNEED must not turn code-cache tracking into ENOMEM"
    );
    assert!(
        machine.vm_mut().cpu.mem.invalidate_icache,
        "the VM must flush lifted blocks before dispatching after host-side discard"
    );

    let mut byte = [0xff];
    machine
        .vm_mut()
        .cpu
        .mem
        .read_bytes(address, &mut byte, perm::READ)
        .expect("advised mapping remains readable");
    assert_eq!(byte, [0]);
}

#[test]
fn dontneed_rejects_an_unaligned_start_instead_of_discarding_a_neighbor() {
    let mut machine = machine();
    let (address, _) = machine.issue_syscall(
        SYS_MMAP,
        [0, 4096, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, u64::MAX, 0],
    );
    assert!(address > 0);
    let (result, _) = machine.issue_syscall(
        SYS_MADVISE,
        [address as u64 + 1, 4095, MADV_DONTNEED, 0, 0, 0],
    );
    assert_eq!(result, -22); // EINVAL
}

#[test]
fn unknown_and_unimplemented_structural_advice_fail_closed() {
    let mut machine = machine();
    let (address, _) = machine.issue_syscall(
        SYS_MMAP,
        [0, 4096, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, u64::MAX, 0],
    );
    assert!(address > 0);
    for advice in [u64::MAX, 9, 18, 19, 24] {
        let (result, _) =
            machine.issue_syscall(SYS_MADVISE, [address as u64, 4096, advice, 0, 0, 0]);
        assert_eq!(
            result, -22,
            "advice {advice} must not claim an absent policy"
        );
    }
}

#[test]
fn dontneed_accepts_immutable_eager_file_pages_without_changing_bytes() {
    let mut machine = machine();
    let mut before = [0_u8; 16];
    machine
        .vm_mut()
        .cpu
        .mem
        .read_bytes(0x40_0000, &mut before, perm::READ)
        .expect("ELF header page");
    assert!(before.iter().any(|&byte| byte != 0));

    let (result, _) = machine.issue_syscall(SYS_MADVISE, [0x40_0000, 4096, MADV_DONTNEED, 0, 0, 0]);
    assert_eq!(result, 0, "clean read-only file bytes may stay resident");
    let mut after = [0_u8; 16];
    machine
        .vm_mut()
        .cpu
        .mem
        .read_bytes(0x40_0000, &mut after, perm::READ)
        .expect("ELF header page after advice");
    assert_eq!(after, before, "file-backed bytes must remain intact");
}
