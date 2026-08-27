//! What one part of the machine can see of another.
//!
//! The other suites ask whether a boundary refuses what it should. These ask
//! the quieter question: when something is released — a page unmapped, a file
//! deleted, a process gone — can what it held be read back by whoever gets
//! that space next?
//!
//! A refusal that leaks is not a refusal. These are the four boundaries the
//! roadmap names for audit, minus the host-message one, which has a sweep of
//! its own.

use std::path::PathBuf;

use linux_compat::Machine;
use x64_engine::EngineConfig;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// A distinctive run of bytes, long enough that finding it in a haystack is
/// not a coincidence.
const MARKER: &[u8] = b"WEBTOS-LEAK-CANARY-1f4c8a2e-DO-NOT-COPY";

fn machine() -> Machine {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data");
    let image = std::fs::read(dir.join("hello_linux.elf")).expect("in-repo fixture");
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine.add_file(b"/bin/probe", image, 0o755).expect("add");
    machine.set_args(vec![b"probe".to_vec()], vec![]);
    machine.load(b"/bin/probe").expect("load");
    machine
}

const SYS_MMAP: u64 = 9;
const SYS_MUNMAP: u64 = 11;
const PROT_READ_WRITE: u64 = 3;
const MAP_PRIVATE_ANONYMOUS: u64 = 0x22;

fn map(machine: &mut Machine, len: u64) -> u64 {
    let (addr, _) = machine.issue_syscall(
        SYS_MMAP,
        [0, len, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, u64::MAX, 0],
    );
    assert!(addr > 0, "mmap returned {addr}");
    addr as u64
}

fn poke(machine: &mut Machine, at: u64, bytes: &[u8]) {
    machine
        .vm_mut()
        .cpu
        .mem
        .write_bytes(at, bytes, icicle_mem::perm::NONE)
        .expect("the test owns this page");
}

fn peek(machine: &mut Machine, at: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0_u8; len];
    machine
        .vm_mut()
        .cpu
        .mem
        .read_bytes(at, &mut out, icicle_mem::perm::NONE)
        .expect("readable");
    out
}

#[test]
fn a_page_mapped_again_does_not_carry_what_the_last_one_held() {
    let mut machine = machine();
    let first = map(&mut machine, 4096);
    poke(&mut machine, first, MARKER);
    assert_eq!(
        &peek(&mut machine, first, MARKER.len())[..],
        MARKER,
        "the test could not write its own marker"
    );

    let (freed, _) = machine.issue_syscall(SYS_MUNMAP, [first, 4096, 0, 0, 0, 0]);
    assert_eq!(freed, 0, "munmap refused");

    // The allocator hands back the same region, which is exactly the case
    // worth testing: the guest must see a fresh page, not the last one.
    let second = map(&mut machine, 4096);
    let seen = peek(&mut machine, second, MARKER.len());
    assert!(
        seen.iter().all(|&b| b == 0),
        "a page mapped again at {second:#x} still held {:?} of the marker \
         written before it was unmapped",
        String::from_utf8_lossy(&seen)
    );
}

#[test]
fn a_new_process_cannot_read_the_last_ones_pages() {
    let mut machine = machine();
    let page = map(&mut machine, 4096);
    poke(&mut machine, page, MARKER);

    // `load` is what `execve` does to the address space: the image is
    // replaced and the old mappings go with it.
    machine.set_args(vec![b"probe".to_vec()], vec![]);
    machine.load(b"/bin/probe").expect("reload");

    let next = map(&mut machine, 4096);
    let seen = peek(&mut machine, next, MARKER.len());
    assert!(
        seen.iter().all(|&b| b == 0),
        "a page mapped after the image was replaced held {:?}",
        String::from_utf8_lossy(&seen)
    );
}

#[test]
fn a_snapshot_does_not_carry_a_deleted_file() {
    let mut machine = machine();
    machine
        .add_file(b"/tmp/secret-notes", MARKER.to_vec(), 0o600)
        .expect("seed");
    let with_it = machine.export_fs();
    assert!(
        find(&with_it, MARKER).is_some(),
        "the marker was not in the snapshot while the file existed, so this \
         test cannot tell a deletion from a mistake"
    );

    // Deleted the way a guest deletes: through `unlinkat`, with the path in
    // guest memory, so the reclamation the syscall does is part of the test.
    const SYS_UNLINKAT: u64 = 263;
    const AT_FDCWD: u64 = (-100_i64) as u64;
    let scratch = map(&mut machine, 4096);
    poke(&mut machine, scratch, b"/tmp/secret-notes\0");
    let (removed, _) = machine.issue_syscall(SYS_UNLINKAT, [AT_FDCWD, scratch, 0, 0, 0, 0]);
    assert_eq!(removed, 0, "unlinkat refused");

    let after = machine.export_fs();
    assert!(
        find(&after, MARKER).is_none(),
        "a snapshot taken after the file was deleted still carried its bytes"
    );
}

#[test]
fn a_snapshot_does_not_carry_a_file_that_was_overwritten_shorter() {
    let mut machine = machine();
    machine
        .add_file(b"/tmp/notes", MARKER.to_vec(), 0o600)
        .expect("seed");
    // Replacing the contents with something shorter must not leave the tail
    // of the old contents behind it.
    machine
        .add_file(b"/tmp/notes", b"short".to_vec(), 0o600)
        .expect("replace");
    let after = machine.export_fs();
    assert!(
        find(&after, MARKER).is_none(),
        "a file overwritten with shorter contents kept the tail of the old \
         ones in the snapshot"
    );
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn a_secret_removed_from_a_config_does_not_survive_in_the_snapshot() {
    let mut machine = machine();
    // The shape that makes this matter: a credential written to a config, and
    // the config later rewritten without it. Rewriting is a replacement, and
    // a replacement that keeps the old node keeps the credential.
    machine
        .add_file(
            b"/root/.agent/config.json",
            format!("{{\"key\": \"{}\"}}\n", String::from_utf8_lossy(MARKER)).into_bytes(),
            0o600,
        )
        .expect("seed");
    machine
        .add_file(b"/root/.agent/config.json", b"{}\n".to_vec(), 0o600)
        .expect("rewrite");

    let snapshot = machine.export_fs();
    assert!(
        find(&snapshot, MARKER).is_none(),
        "a credential removed from a config was still in the snapshot"
    );
}

#[test]
fn the_guest_replacing_a_name_does_not_leave_the_old_bytes_behind() {
    let mut machine = machine();
    machine
        .add_file(b"/tmp/a", MARKER.to_vec(), 0o600)
        .expect("seed a");
    machine
        .add_file(b"/tmp/b", b"replacement".to_vec(), 0o600)
        .expect("seed b");

    // `rename` over an existing name is the guest's way of replacing a file
    // atomically, and it is what every "write a temp file and move it into
    // place" idiom does — including the ones an agent uses to edit a file.
    const SYS_RENAMEAT: u64 = 264;
    const AT_FDCWD: u64 = (-100_i64) as u64;
    let scratch = map(&mut machine, 4096);
    poke(&mut machine, scratch, b"/tmp/b\0");
    poke(&mut machine, scratch + 64, b"/tmp/a\0");
    let (moved, _) = machine.issue_syscall(
        SYS_RENAMEAT,
        [AT_FDCWD, scratch, AT_FDCWD, scratch + 64, 0, 0],
    );
    assert_eq!(moved, 0, "renameat refused");

    let snapshot = machine.export_fs();
    assert!(
        find(&snapshot, MARKER).is_none(),
        "renaming over a file left the replaced file's bytes in the snapshot"
    );
}

#[test]
fn a_crash_bundle_redacts_a_secret_that_reached_a_path() {
    let mut machine = machine();
    machine
        .env()
        .set_secret("AGENT_KEY", &String::from_utf8_lossy(MARKER));

    // The executable path is the one field of a bundle the guest chooses, and
    // a guest can put anything in a path. Nothing else in a bundle is guest
    // data, which is why this is the field worth checking. Set the real way:
    // by running something from a path that carries it.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data");
    let image = std::fs::read(dir.join("hello_linux.elf")).expect("in-repo fixture");
    let path = format!("/tmp/{}", String::from_utf8_lossy(MARKER)).into_bytes();
    machine.add_file(&path, image, 0o755).expect("add");
    machine.set_args(vec![b"probe".to_vec()], vec![]);
    machine.load(&path).expect("load");

    let bundle = machine
        .crash_bundle(&x64_engine::CpuExit::IllegalInstruction { rip: 0x1000 })
        .expect("a non-zero exit produces a bundle");
    assert!(
        find(bundle.as_bytes(), MARKER).is_none(),
        "a crash bundle carried a secret out of the machine:\n{bundle}"
    );
    assert!(
        bundle.contains("${AGENT_KEY}"),
        "the secret was removed without saying what had been there:\n{bundle}"
    );
}

#[test]
fn a_clean_exit_produces_no_bundle() {
    let mut machine = machine();
    assert!(
        machine
            .crash_bundle(&x64_engine::CpuExit::Halt { code: Some(0) })
            .is_none(),
        "a workload that exited cleanly produced a crash bundle"
    );
}
