//! End-to-end gates for manifest-backed executable page-in. These run on the
//! x86-64 fixture host; macOS deliberately lacks the pinned Linux images.

use std::{collections::BTreeMap, path::PathBuf, process::Command, time::Instant};

use jit_wasmi::WasmiJit;
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

struct Run {
    exit: CpuExit,
    output: Vec<u8>,
    icount: u64,
    page_ins: u64,
    page_ins_by_access: [u64; 3],
    supplied: usize,
    resident: usize,
    executed_bytes: u64,
    trace: Vec<linux_compat::trace::Event>,
}

fn drive(mut machine: Machine, store: &BTreeMap<[u8; 32], Vec<u8>>) -> Run {
    machine.vm_mut().icount_limit = 1_000_000_000;
    let mut supplied = 0;
    let exit = loop {
        let exit = machine.run_traced(1_000_000_000_u64.saturating_sub(machine.icount()));
        if exit != CpuExit::Interrupted {
            if !matches!(exit, CpuExit::Halt { .. }) {
                if let CpuExit::PageFault { address, .. } = exit {
                    use icicle_cpu::mem::perm;
                    let rip = machine.vm_mut().cpu.read_pc();
                    let mut instruction = [0_u8; 16];
                    let cross_read =
                        machine
                            .vm_mut()
                            .cpu
                            .mem
                            .read_bytes(address, &mut instruction, perm::EXEC);
                    let permissions: Vec<u8> = (0..16)
                        .map(|offset| machine.vm_mut().cpu.mem.get_perm(address + offset))
                        .collect();
                    let ensured = machine.vm_mut().cpu.mem.ensure_executable(address, 5);
                    eprintln!(
                        "lazy fault address={address:#x} rip={rip:#x} cross_exec={cross_read:?} \
                         ensure5={ensured} bytes={instruction:02x?} perms={permissions:02x?}"
                    );
                    for page in [address & !0xfff, (address & !0xfff) + 4096] {
                        let mut byte = [0_u8; 1];
                        let vm = machine.vm_mut();
                        let mapped = vm.cpu.mem.mapping.get_range((page, page)).is_some();
                        let readable = vm.cpu.mem.read_bytes(page, &mut byte, perm::READ).is_ok();
                        let executable = vm.cpu.mem.read_bytes(page, &mut byte, perm::EXEC).is_ok();
                        eprintln!(
                            "lazy page {page:#x}: mapped={mapped} read={readable} exec={executable}"
                        );
                    }
                }
                eprintln!(
                    "lazy stop {exit:?} task={:?} trail={:?}",
                    machine.current_task(),
                    machine.syscall_trail()
                );
            }
            break exit;
        }
        let request = machine
            .page_request()
            .expect("interrupted without chunk request");
        let bytes = store
            .get(&request.hash)
            .expect("manifest named unknown hash");
        machine
            .deliver_page(request.ticket, bytes.clone())
            .expect("verified page delivery");
        supplied += bytes.len();
    };
    let trace = machine
        .take_trace()
        .map_or_else(Vec::new, |trace| trace.events().to_vec());
    let executed_bytes = machine.executed_byte_count();
    Run {
        exit,
        output: machine.take_output(),
        icount: machine.icount(),
        page_ins: machine.page_in_count(),
        page_ins_by_access: machine.page_in_access_counts(),
        supplied,
        resident: machine.storage_bytes(),
        executed_bytes,
        trace,
    }
}

fn busybox_run(image: &[u8], lazy: bool, jit: bool) -> Run {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    let (file, store) = chunks(image);
    if lazy {
        let authority = manifest(&[(b"/bin/busybox", image, &file, 0o755)]);
        machine
            .install_chunk_manifest(&authority)
            .expect("chunk manifest");
        let first = file.chunks[0];
        machine
            .put_chunk(first, store[&first].clone())
            .expect("bounded ELF metadata");
        assert!(
            machine.storage_bytes() < image.len(),
            "installing the logical image eagerly charged its full payload"
        );
    } else {
        machine
            .add_file(b"/bin/busybox", image.to_vec(), 0o755)
            .expect("eager busybox");
    }
    machine.set_args(
        vec![b"busybox".to_vec(), b"echo".to_vec(), b"lazy-ok".to_vec()],
        vec![b"PATH=/bin".to_vec()],
    );
    let load_path: &[u8] = if lazy {
        b"bin/busybox"
    } else {
        b"/bin/busybox"
    };
    machine.load(load_path).expect("load busybox");
    if jit {
        machine.set_jit(Box::new(WasmiJit::new()));
        machine.set_jit_tiering(Some(1));
    }
    machine.record_trace(1_000);
    drive(machine, &store)
}

#[test]
fn executable_page_in_matches_eager_interpreter_and_jit() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    let Some(image) = linux_compat::testing::require(
        &format!("{} (run tools/fetch_busybox.sh)", path.display()),
        std::fs::read(path).ok(),
    ) else {
        return;
    };

    for jit in [false, true] {
        let eager = busybox_run(&image, false, jit);
        let lazy = busybox_run(&image, true, jit);
        assert_eq!(lazy.exit, CpuExit::Halt { code: Some(0) });
        assert_eq!(lazy.output, eager.output);
        assert_eq!(lazy.output, b"lazy-ok\n");
        assert_eq!(lazy.icount, eager.icount, "page-in changed retired icount");
        assert_eq!(
            lazy.trace, eager.trace,
            "page-in changed architectural trace"
        );
        assert!(lazy.page_ins > 0, "the lazy image never faulted in a page");
        assert!(
            lazy.supplied < image.len(),
            "the run fetched the whole image"
        );
    }
}

#[test]
fn lazy_trace_header_uses_manifest_root_without_reading_the_whole_image() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    let Some(image) = linux_compat::testing::require(
        &format!("{} (run tools/fetch_busybox.sh)", path.display()),
        std::fs::read(path).ok(),
    ) else {
        return;
    };
    let (file, store) = chunks(&image);
    let authority = manifest(&[(b"/bin/busybox", image.as_slice(), &file, 0o755)]);
    let root = sha256(&authority);
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    machine
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    machine.set_args(vec![b"busybox".to_vec()], vec![b"PATH=/bin".to_vec()]);
    loop {
        match machine.load(b"/bin/busybox") {
            Ok(()) => break,
            Err(error) => {
                let request = machine
                    .page_request()
                    .unwrap_or_else(|| panic!("load failed without a chunk request: {error}"));
                machine
                    .deliver_page(request.ticket, store[&request.hash].clone())
                    .expect("metadata delivery");
            }
        }
    }
    machine.record_trace(0);
    let text = machine.take_trace().expect("trace").to_text();
    assert!(text.starts_with("# webtos-trace 2\n"));
    assert!(text.contains(&format!(
        "# image path=/bin/busybox len={} root={} legacy-fnv={:016x}\n",
        image.len(),
        hex(&root),
        linux_compat::trace::fnv1a(&image),
    )));
    assert!(
        machine.storage_bytes() < image.len(),
        "describing the trace materialized the image"
    );
}

#[test]
fn lazy_loader_requests_every_metadata_chunk_without_a_preload_hint() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    let Some(mut image) = linux_compat::testing::require(
        &format!("{} (run tools/fetch_busybox.sh)", path.display()),
        std::fs::read(path).ok(),
    ) else {
        return;
    };
    let old_phoff = u64::from_le_bytes(image[32..40].try_into().expect("e_phoff")) as usize;
    let phentsize = u16::from_le_bytes(image[54..56].try_into().expect("e_phentsize")) as usize;
    let phnum = u16::from_le_bytes(image[56..58].try_into().expect("e_phnum")) as usize;
    let ph_len = phentsize.checked_mul(phnum).expect("program headers");
    let table = image[old_phoff..old_phoff + ph_len].to_vec();
    let new_phoff = image.len().next_multiple_of(CHUNK) + CHUNK;
    image.resize(new_phoff, 0);
    image.extend_from_slice(&table);
    image[32..40].copy_from_slice(&(new_phoff as u64).to_le_bytes());

    let (file, store) = chunks(&image);
    let authority = manifest(&[(b"/bin/busybox", image.as_slice(), &file, 0o755)]);
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    machine
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    machine.set_args(
        vec![b"busybox".to_vec(), b"echo".to_vec(), b"metadata".to_vec()],
        vec![b"PATH=/bin".to_vec()],
    );
    let mut metadata_hashes = std::collections::BTreeSet::new();
    loop {
        match machine.load(b"/bin/busybox") {
            Ok(()) => break,
            Err(error) => {
                let request = machine
                    .page_request()
                    .unwrap_or_else(|| panic!("load failed without a chunk request: {error}"));
                assert!(request.access.is_none());
                metadata_hashes.insert(request.hash);
                machine
                    .deliver_page(request.ticket, store[&request.hash].clone())
                    .expect("metadata delivery");
            }
        }
    }
    assert!(
        metadata_hashes.len() >= 2,
        "header and relocated program-header table did not request independently"
    );
    assert_ne!(
        machine.vm_mut().cpu.read_pc(),
        0,
        "loader completed without installing an entry point"
    );
}

#[test]
fn a_restored_chunked_image_must_rebind_its_authenticated_manifest() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    let Some(image) = linux_compat::testing::require(
        &format!("{} (run tools/fetch_busybox.sh)", path.display()),
        std::fs::read(path).ok(),
    ) else {
        return;
    };
    let (file, store) = chunks(&image);
    let authority = manifest(&[(b"/bin/busybox", image.as_slice(), &file, 0o755)]);

    let mut original =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    original
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    let snapshot = original.export_fs();

    let mut restored =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    restored.import_fs(&snapshot).expect("restore descriptors");
    let first = file.chunks[0];
    restored
        .put_chunk(first, store[&first].clone())
        .expect("ELF metadata chunk");
    restored.set_args(
        vec![b"busybox".to_vec(), b"echo".to_vec(), b"rebound".to_vec()],
        vec![b"PATH=/bin".to_vec()],
    );
    assert!(
        restored
            .load(b"/bin/busybox")
            .unwrap_err()
            .contains("no authenticated"),
        "snapshot descriptor ran without re-authenticating its manifest"
    );

    restored
        .install_chunk_manifest(&authority)
        .expect("rebind manifest authority");
    restored.load(b"/bin/busybox").expect("load after rebind");
    let run = drive(restored, &store);
    assert_eq!(run.exit, CpuExit::Halt { code: Some(0) });
    assert_eq!(run.output, b"rebound\n");
}

#[test]
fn snapshot_rebind_preserves_resident_overlays_and_is_idempotent() {
    let base = b"base-value\n";
    let (file, store) = chunks(base);
    let authority = manifest(&[(b"/etc/value", base.as_slice(), &file, 0o644)]);

    let mut original =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    original
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    let hash = file.chunks[0];
    original
        .put_chunk(hash, store[&hash].clone())
        .expect("base chunk");
    let node = original
        .env()
        .vfs
        .resolve(linux_compat::vfs::ROOT, b"/etc/value", true)
        .expect("resolve overlay")
        .node
        .expect("overlay node");
    original
        .env()
        .vfs
        .materialize_file(node)
        .expect("materialize overlay")
        .copy_from_slice(b"user-value\n");
    let snapshot = original.export_fs();

    let mut restored =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    restored.import_fs(&snapshot).expect("restore overlay");
    restored
        .install_chunk_manifest(&authority)
        .expect("rebind authority");
    assert_eq!(
        restored.env().vfs.read_file(b"/etc/value"),
        Some(b"user-value\n".as_slice()),
        "rebind replaced the resident mutation with the immutable base"
    );
    let rebound_once = restored.export_fs();
    restored
        .install_chunk_manifest(&authority)
        .expect("idempotent rebind");
    assert_eq!(
        restored.export_fs(),
        rebound_once,
        "re-installing one authority grew or rewrote the snapshot"
    );
}

#[test]
fn resident_snapshot_overlay_cannot_bypass_chunk_manifest_execution_authority() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    let Some(image) = linux_compat::testing::require(
        &format!("{} (run tools/fetch_busybox.sh)", path.display()),
        std::fs::read(path).ok(),
    ) else {
        return;
    };
    let (file, store) = chunks(&image);
    let authority = manifest(&[(b"/bin/busybox", image.as_slice(), &file, 0o755)]);

    let mut original =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    original
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    for hash in &file.chunks {
        original
            .put_chunk(*hash, store[hash].clone())
            .expect("base chunk");
    }
    let node = original
        .env()
        .vfs
        .resolve(linux_compat::vfs::ROOT, b"/bin/busybox", true)
        .expect("resolve executable")
        .node
        .expect("executable node");
    let overlay = original
        .env()
        .vfs
        .materialize_file(node)
        .expect("materialize executable overlay");
    overlay[0] ^= 0xff;
    let snapshot = original.export_fs();

    let mut restored =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    restored.import_fs(&snapshot).expect("restore overlay");
    restored
        .install_chunk_manifest(&authority)
        .expect("rebind authority");
    let error = restored
        .load(b"/bin/busybox")
        .expect_err("mutated resident executable ran as authenticated base");
    assert!(error.contains("resident bytes differ from the chunk manifest"));

    restored
        .add_file(b"/tmp/unlisted", image, 0o755)
        .expect("unlisted executable");
    let error = restored
        .load(b"/tmp/unlisted")
        .expect_err("unlisted resident executable ran under chunk authority");
    assert!(error.contains("is not in the chunk manifest"));
}

#[test]
fn manifest_installation_is_atomic_and_snapshot_descriptors_stay_in_authority() {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    machine
        .add_file(b"/z", b"occupied".to_vec(), 0o644)
        .expect("blocking file");
    let (first, _) = chunks(b"first");
    let (second, _) = chunks(b"second");
    let malformed_topology = manifest(&[
        (b"/new", b"first".as_slice(), &first, 0o644),
        (b"/z/child", b"second".as_slice(), &second, 0o644),
    ]);
    assert!(machine.install_chunk_manifest(&malformed_topology).is_err());
    assert!(machine.env().vfs.read_file(b"/new").is_none());
    assert_eq!(
        machine.env().vfs.read_file(b"/z"),
        Some(b"occupied".as_slice())
    );

    let authority = manifest(&[(b"/base", b"first".as_slice(), &first, 0o644)]);
    machine
        .install_chunk_manifest(&authority)
        .expect("valid authority");
    let snapshot = machine.export_fs();
    let mut restored =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    restored.import_fs(&snapshot).expect("restore descriptors");
    restored
        .env()
        .vfs
        .add_chunked_file(b"/forged", second, 0o644)
        .expect("inject foreign descriptor into untrusted snapshot state");
    assert!(restored
        .install_chunk_manifest(&authority)
        .unwrap_err()
        .contains("outside its manifest authority"));
}

#[test]
fn dynamic_interpreter_is_manifest_backed_too() {
    let data = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data");
    let hello_path = data.join("hello_dynamic.elf");
    let loader_path = data.join("alpine-minirootfs/lib/ld-musl-x86_64.so.1");
    let Some((hello, loader)) = linux_compat::testing::require(
        "hello_dynamic.elf and Alpine musl loader",
        std::fs::read(hello_path)
            .ok()
            .zip(std::fs::read(loader_path).ok()),
    ) else {
        return;
    };

    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    let (hello_file, mut store) = chunks(&hello);
    let (loader_file, loader_store) = chunks(&loader);
    store.extend(loader_store);
    let authority = manifest(&[
        (
            b"/bin/hello_dynamic".as_slice(),
            hello.as_slice(),
            &hello_file,
            0o755,
        ),
        (
            b"/lib/ld-musl-x86_64.so.1".as_slice(),
            loader.as_slice(),
            &loader_file,
            0o755,
        ),
    ]);
    let mut tampered =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    tampered
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    tampered
        .env()
        .vfs
        .add_chunked_file(b"/lib/ld-musl-x86_64.so.1", hello_file.clone(), 0o755)
        .expect("forge interpreter descriptor");
    let main_metadata = hello_file.chunks[0];
    tampered
        .put_chunk(main_metadata, store[&main_metadata].clone())
        .expect("main metadata chunk");
    tampered.set_args(vec![b"hello_dynamic".to_vec()], vec![]);
    assert!(tampered
        .load(b"/bin/hello_dynamic")
        .unwrap_err()
        .contains("chunk layout differs from the manifest"));

    machine
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    for file in [hello_file, loader_file] {
        let first = file.chunks[0];
        machine
            .put_chunk(first, store[&first].clone())
            .expect("ELF metadata chunk");
    }
    machine.set_args(vec![b"hello_dynamic".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine
        .load(b"/bin/hello_dynamic")
        .expect("lazy dynamic load");
    let run = drive(machine, &store);
    assert_eq!(run.exit, CpuExit::Halt { code: Some(0) });
    assert!(String::from_utf8_lossy(&run.output)
        .to_lowercase()
        .contains("hello"));
    assert!(
        run.page_ins > 1,
        "main image and interpreter did not both page in"
    );
    assert!(run.supplied < hello.len() + loader.len());
}

#[test]
fn guest_execve_fetches_lazy_interpreter_metadata_before_commit() {
    let data = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data");
    let busybox_path = data.join("busybox-musl");
    let hello_path = data.join("hello_dynamic.elf");
    let loader_path = data.join("alpine-minirootfs/lib/ld-musl-x86_64.so.1");
    let Some((busybox, hello, loader)) = linux_compat::testing::require(
        "BusyBox, hello_dynamic.elf, and Alpine musl loader",
        std::fs::read(busybox_path).ok().and_then(|busybox| {
            std::fs::read(hello_path).ok().and_then(|hello| {
                std::fs::read(loader_path)
                    .ok()
                    .map(|loader| (busybox, hello, loader))
            })
        }),
    ) else {
        return;
    };

    let (busybox_file, mut store) = chunks(&busybox);
    let (hello_file, hello_store) = chunks(&hello);
    let (loader_file, loader_store) = chunks(&loader);
    store.extend(hello_store);
    store.extend(loader_store);
    let authority = manifest(&[
        (b"/bin/driver", busybox.as_slice(), &busybox_file, 0o755),
        (b"/bin/hello_dynamic", hello.as_slice(), &hello_file, 0o755),
        (
            b"/lib/ld-musl-x86_64.so.1",
            loader.as_slice(),
            &loader_file,
            0o755,
        ),
    ]);
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    machine
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    // Keep the shell driver resident so every page request after it starts
    // belongs to the guest execve target or its interpreter.
    machine
        .add_file(b"/bin/driver", busybox, 0o755)
        .expect("resident shell driver");
    machine.set_args(
        vec![
            b"busybox".to_vec(),
            b"sh".to_vec(),
            b"-c".to_vec(),
            b"/bin/hello_dynamic".to_vec(),
        ],
        vec![b"PATH=/bin".to_vec()],
    );
    machine.load(b"/bin/driver").expect("driver load");
    let run = drive(machine, &store);
    assert_eq!(run.exit, CpuExit::Halt { code: Some(0) });
    assert!(String::from_utf8_lossy(&run.output)
        .to_lowercase()
        .contains("hello"));
    assert!(
        run.supplied >= store[&hello_file.chunks[0]].len() + store[&loader_file.chunks[0]].len(),
        "execve committed before fetching both ELF metadata authorities"
    );
}

#[test]
fn private_mapping_keeps_the_version_from_mmap_time() {
    let temp = std::env::temp_dir().join(format!("webtos-lazy-private-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp);
    let source = temp.join("private.c");
    let binary = temp.join("private");
    std::fs::write(
        &source,
        br#"#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
int main(void) {
  int fd = open("/data", O_RDWR);
  char *p = mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
  char changed = 'Z';
  char live = 0;
  if (fd < 0 || p == MAP_FAILED || write(1, p, 1) != 1) return 2;
  if (pwrite(fd, &changed, 1, 0) != 1 || pread(fd, &live, 1, 0) != 1) return 3;
  if (write(1, &live, 1) != 1 || write(1, p, 1) != 1) return 4;
  return p[0] == 'A' && live == 'Z' ? 0 : 5;
}
"#,
    )
    .expect("fixture source");
    let built = Command::new("gcc")
        .args(["-Os", "-static", "-s", "-o"])
        .arg(&binary)
        .arg(&source)
        .status()
        .ok()
        .filter(|status| status.success())
        .and_then(|_| std::fs::read(&binary).ok());
    let Some(program) = linux_compat::testing::require("x86-64 gcc static mmap fixture", built)
    else {
        return;
    };

    let original = vec![b'A'; 4096];
    let (program_file, mut store) = chunks(&program);
    let (file, data_store) = chunks(&original);
    store.extend(data_store);
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    let authority = manifest(&[
        (b"/bin/private", program.as_slice(), &program_file, 0o755),
        (b"/data", original.as_slice(), &file, 0o644),
    ]);
    machine
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    machine
        .add_file(b"/bin/private", program, 0o755)
        .expect("program");
    machine.set_args(vec![b"private".to_vec()], vec![]);
    machine.load(b"/bin/private").expect("load");
    let run = drive(machine, &store);
    assert_eq!(run.exit, CpuExit::Halt { code: Some(0) });
    assert_eq!(
        run.output, b"AZA",
        "MAP_PRIVATE did not pin its file version"
    );
    assert_eq!(run.page_ins, 1);
}

#[test]
fn syscall_copies_sendfile_and_growing_mremap_keep_lazy_file_semantics() {
    let temp = std::env::temp_dir().join(format!("webtos-lazy-adapters-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp);
    let source = temp.join("adapters.c");
    let binary = temp.join("adapters");
    std::fs::write(
        &source,
        br#"#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <unistd.h>
int main(void) {
  int data = open("/data", O_RDONLY);
  int input = open("/input", O_RDONLY);
  char *to = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, data, 0);
  char *from = mmap(0, 4096, PROT_READ, MAP_PRIVATE, data, 0);
  if (data < 0 || input < 0 || to == MAP_FAILED || from == MAP_FAILED) return 2;
  if (read(input, to, 1) != 1 || write(1, to, 1) != 1) return 3;
  if (write(1, from, 1) != 1) return 4;

  int sent = open("/send", O_RDONLY);
  if (sent < 0 || sendfile(1, sent, 0, 5) != 5) return 5;

  int grow = open("/grow", O_RDONLY);
  char *p = mmap(0, 4096, PROT_READ, MAP_PRIVATE, grow, 0);
  if (grow < 0 || p == MAP_FAILED) return 6;
  p = mremap(p, 4096, 8192, MREMAP_MAYMOVE);
  if (p == MAP_FAILED || write(1, p + 4096, 1) != 1) return 7;
  return 0;
}
"#,
    )
    .expect("fixture source");
    let built = Command::new("gcc")
        .args(["-Os", "-static", "-s", "-o"])
        .arg(&binary)
        .arg(&source)
        .status()
        .ok()
        .filter(|status| status.success())
        .and_then(|_| std::fs::read(&binary).ok());
    let Some(program) = linux_compat::testing::require("x86-64 gcc lazy-adapter fixture", built)
    else {
        return;
    };

    let data = vec![b'A'; 4096];
    let mut grow = vec![b'C'; 8192];
    grow[4096] = b'B';
    let (program_file, mut store) = chunks(&program);
    let (data_file, data_store) = chunks(&data);
    let (send_file, send_store) = chunks(b"send\n");
    let (grow_file, grow_store) = chunks(&grow);
    store.extend(data_store);
    store.extend(send_store);
    store.extend(grow_store);
    let authority = manifest(&[
        (b"/bin/adapters", program.as_slice(), &program_file, 0o755),
        (b"/data", data.as_slice(), &data_file, 0o644),
        (b"/grow", grow.as_slice(), &grow_file, 0o644),
        (b"/send", b"send\n".as_slice(), &send_file, 0o644),
    ]);
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    machine
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    machine
        .add_file(b"/bin/adapters", program, 0o755)
        .expect("program");
    machine
        .add_file(b"/input", b"Z".to_vec(), 0o644)
        .expect("input");
    machine.set_args(vec![b"adapters".to_vec()], Vec::new());
    machine.load(b"/bin/adapters").expect("load");
    let run = drive(machine, &store);
    assert_eq!(run.exit, CpuExit::Halt { code: Some(0) });
    assert_eq!(run.output, b"ZAsend\nB");
    assert!(
        run.page_ins_by_access[0] >= 2,
        "copy_from_user or the grown mapping never read-faulted"
    );
    assert!(
        run.page_ins_by_access[1] >= 1,
        "copy_to_user never write-faulted"
    );
    assert!(
        run.supplied >= data.len() + b"send\n".len(),
        "sendfile did not cross the chunk request boundary"
    );
}

#[test]
fn a_fresh_host_load_cancels_the_replaced_process_chunk_ticket() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    let Some(image) = linux_compat::testing::require(
        &format!("{} (run tools/fetch_busybox.sh)", path.display()),
        std::fs::read(path).ok(),
    ) else {
        return;
    };
    let payload = b"old process must not receive this\n";
    let (busybox_file, mut store) = chunks(&image);
    let (file, wait_store) = chunks(payload);
    store.extend(wait_store);
    let authority = manifest(&[
        (b"/bin/busybox", image.as_slice(), &busybox_file, 0o755),
        (b"/wait", payload.as_slice(), &file, 0o644),
    ]);
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    machine
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("busybox");
    machine.set_args(
        vec![b"busybox".to_vec(), b"cat".to_vec(), b"/wait".to_vec()],
        vec![b"PATH=/bin".to_vec()],
    );
    machine.load(b"/bin/busybox").expect("old load");
    machine.vm_mut().icount_limit = 10_000_000;
    assert_eq!(machine.run(), CpuExit::Interrupted);
    let request = machine.page_request().expect("old file ticket");
    assert!(request.access.is_none());

    machine.set_args(
        vec![
            b"busybox".to_vec(),
            b"echo".to_vec(),
            b"replacement".to_vec(),
        ],
        vec![b"PATH=/bin".to_vec()],
    );
    machine.load(b"/bin/busybox").expect("replacement load");
    assert!(machine.page_request().is_none());
    assert!(machine
        .deliver_page(request.ticket, store[&request.hash].clone())
        .unwrap_err()
        .contains("no chunk request is pending"));
    let run = drive(machine, &store);
    assert_eq!(run.exit, CpuExit::Halt { code: Some(0) });
    assert_eq!(run.output, b"replacement\n");
}

#[test]
fn a_cross_page_instruction_discards_the_lift_built_from_cold_bytes() {
    let temp = std::env::temp_dir().join(format!("webtos-lazy-cross-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp);
    let source = temp.join("cross.S");
    let binary = temp.join("cross");
    std::fs::write(
        &source,
        br#".global _start
.text
_start:
  .fill 4095, 1, 0x90
  cmpl $0, %eax
  mov $60, %eax
  xor %edi, %edi
  syscall
"#,
    )
    .expect("fixture source");
    let built = Command::new("gcc")
        .args([
            "-nostdlib",
            "-static",
            "-Wl,-Ttext=0x401000",
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&binary)
        .arg(&source)
        .status()
        .ok()
        .filter(|status| status.success())
        .and_then(|_| std::fs::read(&binary).ok());
    let Some(image) = linux_compat::testing::require("x86-64 cross-page ELF fixture", built) else {
        return;
    };

    for jit in [false, true] {
        let run = |lazy: bool| {
            let mut machine =
                Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
            let (file, store) = chunks(&image);
            if lazy {
                let authority = manifest(&[(b"/bin/cross", image.as_slice(), &file, 0o755)]);
                machine
                    .install_chunk_manifest(&authority)
                    .expect("chunk manifest");
                let first = file.chunks[0];
                machine
                    .put_chunk(first, store[&first].clone())
                    .expect("ELF metadata chunk");
            } else {
                machine
                    .add_file(b"/bin/cross", image.clone(), 0o755)
                    .expect("eager fixture");
            }
            machine.set_args(vec![b"cross".to_vec()], Vec::new());
            machine
                .load(b"/bin/cross")
                .expect("load cross-page fixture");
            if jit {
                machine.set_jit(Box::new(WasmiJit::new()));
                machine.set_jit_tiering(Some(1));
            }
            machine.record_trace(128);
            drive(machine, &store)
        };
        let eager = run(false);
        let lazy = run(true);
        assert_eq!(lazy.exit, CpuExit::Halt { code: Some(0) });
        assert_eq!(lazy.output, eager.output);
        assert_eq!(lazy.icount, eager.icount);
        assert_eq!(lazy.trace, eager.trace);
        assert!(lazy.page_ins >= 2, "both executable pages were not filled");
    }
}

#[test]
fn a_five_byte_instruction_with_three_resident_prefix_bytes_pages_in_its_tail() {
    let temp = std::env::temp_dir().join(format!(
        "webtos-lazy-cross-three-byte-prefix-{}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&temp);
    let source = temp.join("cross-three-byte-prefix.S");
    let binary = temp.join("cross-three-byte-prefix");
    std::fs::write(
        &source,
        br#".global _start
.text
_start:
  .fill 4093, 1, 0x90
  psllq $0x39, %xmm0
  mov $60, %eax
  xor %edi, %edi
  syscall
"#,
    )
    .expect("fixture source");
    let built = Command::new("gcc")
        .args([
            "-nostdlib",
            "-static",
            "-Wl,-Ttext=0x401000",
            "-Wl,-e,_start",
            "-o",
        ])
        .arg(&binary)
        .arg(&source)
        .status()
        .ok()
        .filter(|status| status.success())
        .and_then(|_| std::fs::read(&binary).ok());
    let Some(image) = linux_compat::testing::require("x86-64 cross-page SSE fixture", built) else {
        return;
    };

    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    let (file, store) = chunks(&image);
    let authority = manifest(&[(
        b"/bin/cross-three-byte-prefix",
        image.as_slice(),
        &file,
        0o755,
    )]);
    machine
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    let first = file.chunks[0];
    machine
        .put_chunk(first, store[&first].clone())
        .expect("ELF metadata chunk");
    machine.set_args(vec![b"cross-three-byte-prefix".to_vec()], Vec::new());
    machine
        .load(b"/bin/cross-three-byte-prefix")
        .expect("load cross-page fixture");

    let run = drive(machine, &store);
    assert_eq!(run.exit, CpuExit::Halt { code: Some(0) });
    assert!(run.page_ins >= 2, "both executable pages were not filled");
}

#[test]
fn scoped_secret_promotes_only_an_authorized_resident_file() {
    let config = br#"{"token":"${TOKEN}"}\n"#;
    let (file, store) = chunks(config);
    let authority = manifest(&[(b"/root/config.json", config.as_slice(), &file, 0o600)]);

    let mut missing =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    missing
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    missing.set_scoped_secret("TOKEN", "secret", &[b"/root/config.json"]);
    assert!(
        missing.expand_secrets().is_err(),
        "a missing authority chunk was silently treated as an injected config"
    );

    let mut ready =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    ready
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    let hash = file.chunks[0];
    ready
        .put_chunk(hash, store[&hash].clone())
        .expect("verified config chunk");
    ready.set_scoped_secret("TOKEN", "secret", &[b"/root/config.json"]);
    ready.expand_secrets().expect("expand scoped secret");
    assert_eq!(
        ready
            .env()
            .vfs
            .read_file(b"/root/config.json")
            .expect("materialized config"),
        br#"{"token":"secret"}\n"#
    );
}

/// Explicit release measurement, not part of the ordinary fixture matrix.
/// Run on the x86-64 host with, for example:
///
/// WEBTOS_LAZY_AGENT_IMAGE="$HOME/.codex/packages/standalone/current/bin/codex" \
///   cargo test -p linux-compat --release --test lazy_paging \
///   large_agent_image_reports_lazy_materialization -- --ignored --nocapture
#[test]
#[ignore = "large-image demand-paging measurement; set WEBTOS_LAZY_AGENT_IMAGE"]
fn large_agent_image_reports_lazy_materialization() {
    let path = PathBuf::from(
        std::env::var_os("WEBTOS_LAZY_AGENT_IMAGE")
            .expect("WEBTOS_LAZY_AGENT_IMAGE must name a static x86-64 agent binary"),
    );
    let image = std::fs::read(&path).expect("read large agent image");
    assert!(
        image.len() >= 100 * 1024 * 1024,
        "measurement image is not agent-sized"
    );

    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    let (file, store) = chunks(&image);
    let authority = manifest(&[(b"/bin/agent", image.as_slice(), &file, 0o755)]);
    machine
        .install_chunk_manifest(&authority)
        .expect("chunk manifest");
    machine.set_args(
        vec![b"agent".to_vec(), b"--version".to_vec()],
        vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()],
    );
    let mut metadata_delivered = 0_usize;
    loop {
        match machine.load(b"/bin/agent") {
            Ok(()) => break,
            Err(error) => {
                let request = machine.page_request().unwrap_or_else(|| {
                    panic!("agent load failed without a chunk request: {error}")
                });
                let bytes = store[&request.hash].clone();
                metadata_delivered += bytes.len();
                machine
                    .deliver_page(request.ticket, bytes)
                    .expect("metadata delivery");
            }
        }
    }
    machine.track_executed_bytes(true);

    let started = Instant::now();
    let run = drive(machine, &store);
    let elapsed = started.elapsed();
    assert_eq!(run.exit, CpuExit::Halt { code: Some(0) });
    assert!(!run.output.is_empty(), "agent --version printed nothing");

    let delivered = metadata_delivered + run.supplied;
    let filled = run.page_ins as usize * 4096;
    let execute_first = run.page_ins_by_access[2] as usize * 4096;
    println!(
        "[lazy-large] image={} logical_bytes={} delivered_bytes={} resident_bytes={} \
         page_filled_bytes={} execute_first_fill_bytes={} executed_bytes={} retired_icount={} latency_ms={} output={:?}",
        path.display(),
        image.len(),
        delivered,
        run.resident,
        filled,
        execute_first,
        run.executed_bytes,
        run.icount,
        elapsed.as_millis(),
        String::from_utf8_lossy(&run.output).trim(),
    );
    assert!(
        delivered < image.len() / 4,
        "version run fetched at least a quarter of the image"
    );
    assert!(
        run.resident < image.len() / 4,
        "version run materialized at least a quarter of the image"
    );
    assert!(execute_first > 0, "no executable page was demand-filled");
    assert!(
        run.executed_bytes > 0,
        "no executed source bytes were recorded"
    );
    assert!(
        run.executed_bytes <= execute_first as u64,
        "executed bytes exceed pages first fetched for execution"
    );
}
