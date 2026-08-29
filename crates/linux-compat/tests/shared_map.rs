//! The syscalls SQLite's WAL mode leans on, found missing when the real Codex
//! TUI first ran in a browser profile: `MAP_SHARED` file mappings written back
//! at `msync`/`munmap`, `fchown` as a single-user no-op, and the `fcntl` lock
//! queries reporting an uncontended file. One probe exercises the lot: it maps
//! a file shared, stores a marker through the mapping, syncs, checks fchown and
//! F_GETLK, then reads the marker back *through the file* — which only works if
//! the shared mapping's store reached the backing file.

use std::path::PathBuf;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// A minimal static ELF: one RWX PT_LOAD at 0x400000, entry at the code, with
/// `tail` laid immediately after the code. Returns the image and `tail`'s
/// virtual address.
fn tiny_elf(code: &[u8], tail: &[u8]) -> (Vec<u8>, u64) {
    const CODE_OFF: usize = 120;
    const VADDR: u64 = 0x40_0000;
    let total = CODE_OFF + code.len() + tail.len();
    let mut b = vec![0u8; total];
    b[..8].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&(VADDR + CODE_OFF as u64).to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&7u32.to_le_bytes());
    b[80..88].copy_from_slice(&VADDR.to_le_bytes());
    b[88..96].copy_from_slice(&VADDR.to_le_bytes());
    b[96..104].copy_from_slice(&(total as u64).to_le_bytes());
    b[104..112].copy_from_slice(&(total as u64).to_le_bytes());
    b[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
    b[CODE_OFF..CODE_OFF + code.len()].copy_from_slice(code);
    b[CODE_OFF + code.len()..].copy_from_slice(tail);
    (b, VADDR + CODE_OFF as u64 + code.len() as u64)
}

/// open(path, O_RDWR); mmap(0, 4096, RW, MAP_SHARED, fd, 0); map[0] = 'X';
/// msync; fchown(fd, 0, 0); fcntl(fd, F_GETLK) expecting F_UNLCK; munmap;
/// reopen O_RDONLY; read 1 byte; write it to stdout; exit(any step failed).
/// Errors accumulate in rbx (each result OR'd in), so the exit code is 0 only
/// when every step succeeded — no branches to keep the bytes simple.
fn probe(path_vaddr: u64) -> Vec<u8> {
    let p = (path_vaddr as u32).to_le_bytes();
    vec![
        0x31, 0xdb, // xor ebx, ebx (error accumulator)
        0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2 (open)
        0xbf, p[0], p[1], p[2], p[3], // mov edi, path
        0xbe, 0x02, 0x00, 0x00, 0x00, // mov esi, 2 (O_RDWR)
        0x0f, 0x05, // syscall
        0x49, 0x89, 0xc4, // mov r12, rax (fd)
        0xb8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9 (mmap)
        0x31, 0xff, // xor edi, edi
        0xbe, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
        0xba, 0x03, 0x00, 0x00, 0x00, // mov edx, 3 (PROT_READ|WRITE)
        0x41, 0xba, 0x01, 0x00, 0x00, 0x00, // mov r10d, 1 (MAP_SHARED)
        0x4d, 0x89, 0xe0, // mov r8, r12
        0x45, 0x31, 0xc9, // xor r9d, r9d
        0x0f, 0x05, // syscall
        0x49, 0x89, 0xc5, // mov r13, rax (map)
        0xc6, 0x00, 0x58, // mov byte [rax], 'X'
        0xb8, 0x1a, 0x00, 0x00, 0x00, // mov eax, 26 (msync)
        0x4c, 0x89, 0xef, // mov rdi, r13
        0xbe, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
        0xba, 0x04, 0x00, 0x00, 0x00, // mov edx, 4 (MS_SYNC)
        0x0f, 0x05, // syscall
        0x48, 0x09, 0xc3, // or rbx, rax
        0xb8, 0x5d, 0x00, 0x00, 0x00, // mov eax, 93 (fchown)
        0x4c, 0x89, 0xe7, // mov rdi, r12
        0x31, 0xf6, // xor esi, esi
        0x31, 0xd2, // xor edx, edx
        0x0f, 0x05, // syscall
        0x48, 0x09, 0xc3, // or rbx, rax
        0x48, 0x83, 0xec, 0x20, // sub rsp, 32 (struct flock)
        0x31, 0xc0, // xor eax, eax
        0x48, 0x89, 0x04, 0x24, // mov [rsp], rax
        0x48, 0x89, 0x44, 0x24, 0x08, // mov [rsp+8], rax
        0x48, 0x89, 0x44, 0x24, 0x10, // mov [rsp+16], rax
        0x48, 0x89, 0x44, 0x24, 0x18, // mov [rsp+24], rax
        0x66, 0xc7, 0x04, 0x24, 0x01, 0x00, // mov word [rsp], 1 (F_WRLCK query)
        0xb8, 0x48, 0x00, 0x00, 0x00, // mov eax, 72 (fcntl)
        0x4c, 0x89, 0xe7, // mov rdi, r12
        0xbe, 0x05, 0x00, 0x00, 0x00, // mov esi, 5 (F_GETLK)
        0x48, 0x89, 0xe2, // mov rdx, rsp
        0x0f, 0x05, // syscall
        0x48, 0x09, 0xc3, // or rbx, rax
        0x0f, 0xb7, 0x04, 0x24, // movzx eax, word [rsp] (l_type)
        0x83, 0xe8, 0x02, // sub eax, 2 (F_UNLCK -> 0)
        0x48, 0x63, 0xc0, // movsxd rax, eax
        0x48, 0x09, 0xc3, // or rbx, rax
        0xb8, 0x0b, 0x00, 0x00, 0x00, // mov eax, 11 (munmap)
        0x4c, 0x89, 0xef, // mov rdi, r13
        0xbe, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
        0x0f, 0x05, // syscall
        0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2 (open O_RDONLY)
        0xbf, p[0], p[1], p[2], p[3], // mov edi, path
        0x31, 0xf6, // xor esi, esi
        0x0f, 0x05, // syscall
        0x48, 0x89, 0xc7, // mov rdi, rax (fd)
        0x31, 0xc0, // xor eax, eax (read)
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
        0x0f, 0x05, // syscall
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (write)
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
        0x0f, 0x05, // syscall
        0x48, 0x85, 0xdb, // test rbx, rbx
        0x0f, 0x95, 0xc0, // setne al
        0x0f, 0xb6, 0xf8, // movzx edi, al
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
        0x0f, 0x05, // syscall
    ]
}

#[test]
fn a_shared_file_mapping_writes_back_and_the_lock_queries_answer() {
    let (exe, path_vaddr) = tiny_elf(&probe(0), b"/data\0");
    let (exe, _) = tiny_elf(&probe(path_vaddr), b"/data\0");

    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    machine
        .add_file(b"/bin/probe", exe, 0o755)
        .expect("add probe");
    machine
        .add_file(b"/data", vec![0u8; 4096], 0o644)
        .expect("add data");
    machine.set_args(vec![b"probe".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/probe").expect("load");
    machine.vm_mut().icount_limit = 10_000_000;
    let exit = machine.run();
    let output = machine.take_output();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "a WAL-shaped step failed (msync/fchown/F_GETLK accumulate into the exit code); output={output:?}"
    );
    assert_eq!(
        output, b"X",
        "the store through the MAP_SHARED mapping never reached the backing file"
    );
}
