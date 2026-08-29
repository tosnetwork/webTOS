//! Host-side syscall access to an untouched lazy mapping must behave exactly
//! as it does against an eager one. The guest passes syscalls *pointers into*
//! a manifest-backed mmap without touching the bytes first; the kernel-side
//! copy is the first access. Linux's copy_from_user faults such pages in, so
//! the eager and lazy runs must be indistinguishable.

use std::collections::BTreeMap;
use std::path::PathBuf;

use linux_compat::{
    chunk::ChunkedFile,
    chunk_manifest::HEADER,
    digest::{hex, sha256},
    trace::fnv1a,
    Machine,
};
use x64_engine::{CpuExit, EngineConfig};

const CHUNK: usize = 64 * 1024;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn chunks(bytes: &[u8]) -> (ChunkedFile, BTreeMap<[u8; 32], Vec<u8>>) {
    let mut store = BTreeMap::new();
    let hashes = bytes
        .chunks(CHUNK)
        .map(|part| {
            let hash = sha256(part);
            store.insert(hash, part.to_vec());
            hash
        })
        .collect();
    (
        ChunkedFile::new(bytes.len() as u64, CHUNK as u32, hashes).expect("chunk layout"),
        store,
    )
}

fn manifest(files: &[(&[u8], &[u8], &ChunkedFile, u32)]) -> Vec<u8> {
    let mut records = BTreeMap::<Vec<u8>, String>::new();
    for (path, bytes, file, mode) in files {
        let mut slash = 1;
        while let Some(next) = path[slash..].iter().position(|byte| *byte == b'/') {
            slash += next;
            let directory = path[..slash].to_vec();
            let directory_hex: String =
                directory.iter().map(|byte| format!("{byte:02x}")).collect();
            records
                .entry(directory)
                .or_insert_with(|| format!("d 755 0 {directory_hex}"));
            slash += 1;
        }
        let path_hex: String = path.iter().map(|byte| format!("{byte:02x}")).collect();
        let hashes = file.chunks.iter().map(hex).collect::<Vec<_>>().join(",");
        records.insert(
            path.to_vec(),
            format!(
                "f {mode:o} 0 {path_hex} {} {} {:016x} {hashes}",
                file.size,
                file.chunk_size,
                fnv1a(bytes)
            ),
        );
    }
    let mut out = format!("{HEADER}\n");
    for record in records.values() {
        out.push_str(record);
        out.push('\n');
    }
    out.into_bytes()
}

/// A minimal static ELF: one RWX PT_LOAD at 0x400000, entry at the code, with
/// `tail` (e.g. a path string) laid immediately after the code. Returns the
/// image and the virtual address of `tail`.
fn tiny_elf(code: &[u8], tail: &[u8]) -> (Vec<u8>, u64) {
    const CODE_OFF: usize = 120; // 64 ehdr + 56 phdr
    const VADDR: u64 = 0x40_0000;
    let total = CODE_OFF + code.len() + tail.len();
    let mut b = vec![0u8; total];
    b[..8].copy_from_slice(&[0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
    b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    b[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // x86-64
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&(VADDR + CODE_OFF as u64).to_le_bytes()); // e_entry
    b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    b[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[68..72].copy_from_slice(&7u32.to_le_bytes()); // RWX
    b[80..88].copy_from_slice(&VADDR.to_le_bytes()); // p_vaddr
    b[88..96].copy_from_slice(&VADDR.to_le_bytes()); // p_paddr
    b[96..104].copy_from_slice(&(total as u64).to_le_bytes()); // p_filesz
    b[104..112].copy_from_slice(&(total as u64).to_le_bytes()); // p_memsz
    b[112..120].copy_from_slice(&0x1000u64.to_le_bytes()); // p_align
    b[CODE_OFF..CODE_OFF + code.len()].copy_from_slice(code);
    b[CODE_OFF + code.len()..].copy_from_slice(tail);
    (b, VADDR + CODE_OFF as u64 + code.len() as u64)
}

/// open(path) ; mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0) ;
/// writev(1, [{map, 32}], 1) ; exit(0). The mapping is never touched by guest
/// loads before the writev, so the kernel-side gather is the first access.
fn writev_probe(path_vaddr: u64) -> Vec<u8> {
    let p = (path_vaddr as u32).to_le_bytes();
    let mut c = vec![
        0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2 (open)
        0xbf, p[0], p[1], p[2], p[3], // mov edi, path
        0x31, 0xf6, // xor esi, esi
        0x0f, 0x05, // syscall
        0x49, 0x89, 0xc0, // mov r8, rax (fd)
        0xb8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9 (mmap)
        0x31, 0xff, // xor edi, edi
        0xbe, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1 (PROT_READ)
        0x41, 0xba, 0x02, 0x00, 0x00, 0x00, // mov r10d, 2 (MAP_PRIVATE)
        0x45, 0x31, 0xc9, // xor r9d, r9d
        0x0f, 0x05, // syscall -> rax = map
        0x6a, 0x20, // push 32 (iov_len)
        0x50, // push rax (iov_base)
        0xb8, 0x14, 0x00, 0x00, 0x00, // mov eax, 20 (writev)
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0x48, 0x89, 0xe6, // mov rsi, rsp
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
        0x0f, 0x05, // syscall
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
    ];
    c.shrink_to_fit();
    c
}

/// open("/data") ; mmap(...) ; open(map) — the path string lives inside the
/// untouched mapping ; exit(open_result < 0). Eagerly the second open finds
/// "/tmp/ok"; if the kernel-side path copy reads an unfilled page it sees an
/// empty string instead.
fn open_from_map_probe(path_vaddr: u64) -> Vec<u8> {
    let p = (path_vaddr as u32).to_le_bytes();
    vec![
        0xb8, 0x02, 0x00, 0x00, 0x00, // mov eax, 2 (open /data)
        0xbf, p[0], p[1], p[2], p[3], // mov edi, path
        0x31, 0xf6, // xor esi, esi
        0x0f, 0x05, // syscall
        0x49, 0x89, 0xc0, // mov r8, rax
        0xb8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9 (mmap)
        0x31, 0xff, // xor edi, edi
        0xbe, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000
        0xba, 0x01, 0x00, 0x00, 0x00, // mov edx, 1
        0x41, 0xba, 0x02, 0x00, 0x00, 0x00, // mov r10d, 2
        0x45, 0x31, 0xc9, // xor r9d, r9d
        0x0f, 0x05, // syscall -> rax = map
        0x48, 0x89, 0xc7, // mov rdi, rax (path = map)
        0xb8, 0x15, 0x00, 0x00, 0x00, // mov eax, 21 (access)
        0x31, 0xf6, // xor esi, esi (F_OK)
        0x0f, 0x05, // syscall
        0x48, 0xc1, 0xe8, 0x3f, // shr rax, 63 (1 if access failed)
        0x89, 0xc7, // mov edi, eax
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60
        0x0f, 0x05, // syscall
    ]
}

struct Outcome {
    exit: CpuExit,
    output: Vec<u8>,
    read_page_ins: u64,
}

fn run(exe: &[u8], data: &[u8], lazy: bool, extra_file: Option<(&[u8], &[u8])>) -> Outcome {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    if let Some((path, bytes)) = extra_file {
        machine
            .add_file(path, bytes.to_vec(), 0o644)
            .expect("extra");
    }
    let store = if lazy {
        let (file, mut store) = chunks(data);
        let (exe_file, exe_store) = chunks(exe);
        let authority = manifest(&[
            (b"/data", data, &file, 0o644),
            (b"/bin/probe", exe, &exe_file, 0o755),
        ]);
        machine
            .install_chunk_manifest(&authority)
            .expect("chunk manifest");
        // The probe image itself is not under test: make its chunks resident so
        // only /data is lazy.
        for (hash, bytes) in &exe_store {
            machine.put_chunk(*hash, bytes.clone()).expect("exe chunk");
        }
        store.extend(exe_store);
        store
    } else {
        machine
            .add_file(b"/bin/probe", exe.to_vec(), 0o755)
            .expect("probe");
        machine
            .add_file(b"/data", data.to_vec(), 0o644)
            .expect("eager data");
        BTreeMap::new()
    };
    machine.set_args(vec![b"probe".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/probe").expect("load probe");
    machine.vm_mut().icount_limit = 50_000_000;
    let exit = loop {
        let exit = machine.run();
        if exit != CpuExit::Interrupted {
            break exit;
        }
        let request = machine
            .page_request()
            .expect("interrupted without a chunk request");
        let bytes = store
            .get(&request.hash)
            .expect("manifest named unknown hash")
            .clone();
        machine
            .deliver_page(request.ticket, bytes)
            .expect("verified delivery");
    };
    Outcome {
        exit,
        output: machine.take_output(),
        read_page_ins: machine.page_in_access_counts()[0],
    }
}

#[test]
fn writev_from_an_untouched_lazy_mapping_matches_eager() {
    let mut data = Vec::new();
    while data.len() < 64 {
        data.extend_from_slice(b"LAZY-DATA-BYTES!");
    }
    let (exe, path_vaddr) = tiny_elf(&writev_probe(0), b"/data\0");
    // Rebuild with the real path address (code length is independent of it).
    let (exe, _) = tiny_elf(&writev_probe(path_vaddr), b"/data\0");

    let eager = run(&exe, &data, false, None);
    let lazy = run(&exe, &data, true, None);
    assert_eq!(eager.exit, CpuExit::Halt { code: Some(0) }, "eager exit");
    assert_eq!(lazy.exit, CpuExit::Halt { code: Some(0) }, "lazy exit");
    assert_eq!(
        eager.output,
        &data[..32],
        "eager writev must write the file's first 32 bytes"
    );
    assert_eq!(
        lazy.output, eager.output,
        "writev gathering from an untouched lazy mapping diverged from eager \
         (zeros mean the kernel-side copy bypassed the pager)"
    );
    assert!(
        lazy.read_page_ins > 0,
        "the kernel-side gather must have paged the data in"
    );
}

#[test]
fn open_with_a_path_inside_an_untouched_lazy_mapping_matches_eager() {
    // The mapped file's content *is* a path string.
    let mut data = b"/tmp/ok\0".to_vec();
    data.resize(64, 0);
    let (exe, path_vaddr) = tiny_elf(&open_from_map_probe(0), b"/data\0");
    let (exe, _) = tiny_elf(&open_from_map_probe(path_vaddr), b"/data\0");

    let target: (&[u8], &[u8]) = (b"/tmp/ok", b"x");
    let eager = run(&exe, &data, false, Some(target));
    let lazy = run(&exe, &data, true, Some(target));
    assert_eq!(
        eager.exit,
        CpuExit::Halt { code: Some(0) },
        "eager: open(path-inside-mapping) must succeed"
    );
    assert_eq!(
        lazy.exit, eager.exit,
        "access() with a path string inside an untouched lazy mapping diverged \
         from eager (an empty path means the kernel-side copy read an unfilled page)"
    );
    assert!(
        lazy.read_page_ins > 0,
        "the kernel-side path copy must have paged the string in \
         (zero page-ins means it read allocator zeros and the empty-path \
          fallback masked it)"
    );
}
