//! Probe: a dynamically linked agent under JIT + manifest-backed demand
//! paging. The wasm engine in the browser hangs or faults early on exactly
//! this combination; this reproduces it natively where debuggers work.
//!
//! Ignored by default: it needs the agent staging (`web/claude`,
//! `web/claude-libs/`) that the repository gitignores. Run with:
//!   cargo test -p linux-compat --test jit_lazy_agent -- --ignored --nocapture

use std::{collections::BTreeMap, path::PathBuf};

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

#[test]
#[ignore]
fn dynamic_agent_under_jit_and_lazy_paging() {
    let web = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../web");
    let read = |p: PathBuf| std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()));
    let staged: Result<Vec<(Vec<u8>, Vec<u8>)>, String> = (|| {
        let mut files = vec![(b"/bin/claude".to_vec(), read(web.join("claude"))?)];
        let libs = web.join("claude-libs");
        files.push((
            b"/lib64/ld-linux-x86-64.so.2".to_vec(),
            read(libs.join("ld-linux-x86-64.so.2"))?,
        ));
        for name in [
            "libc.so.6",
            "libm.so.6",
            "libdl.so.2",
            "libpthread.so.0",
            "librt.so.1",
        ] {
            files.push((
                format!("/lib/x86_64-linux-gnu/{name}").into_bytes(),
                read(libs.join(name))?,
            ));
        }
        Ok(files)
    })();
    let staged = match staged {
        Ok(files) => files,
        Err(why) => {
            eprintln!("SKIP: agent staging missing ({why})");
            return;
        }
    };

    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build");
    let mut store = BTreeMap::new();
    let mut chunked = Vec::new();
    for (path, bytes) in &staged {
        let (file, part) = chunks(bytes);
        store.extend(part);
        chunked.push((path.clone(), file));
    }
    let records: Vec<(&[u8], &[u8], &ChunkedFile, u32)> = staged
        .iter()
        .zip(&chunked)
        .map(|((path, bytes), (_, file))| (path.as_slice(), bytes.as_slice(), file, 0o755))
        .collect();
    machine
        .install_chunk_manifest(&manifest(&records))
        .expect("chunk manifest");

    machine.set_args(
        vec![b"claude".to_vec()],
        vec![
            b"PATH=/bin".to_vec(),
            b"HOME=/root".to_vec(),
            b"TERM=xterm-256color".to_vec(),
        ],
    );
    // The initial ELF metadata pages in during load.
    let mut supplied = 0usize;
    loop {
        match machine.load(b"/bin/claude") {
            Ok(()) => break,
            Err(e) => {
                let Some(request) = machine.page_request() else {
                    panic!("load failed without a chunk request: {e}");
                };
                let bytes = store
                    .get(&request.hash)
                    .expect("manifest named unknown hash");
                supplied += bytes.len();
                machine
                    .deliver_page(request.ticket, bytes.clone())
                    .expect("verified page delivery");
            }
        }
    }
    machine.set_jit(Box::new(WasmiJit::new()));
    machine.set_jit_tiering(Some(10));

    let limit: u64 = std::env::var("PROBE_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50_000_000);
    machine.vm_mut().icount_limit = limit;
    let started = std::time::Instant::now();
    let exit = loop {
        let exit = machine.run();
        if exit != CpuExit::Interrupted {
            break exit;
        }
        let Some(request) = machine.page_request() else {
            // Interrupted for another reason (terminal input, network).
            break exit;
        };
        let bytes = store
            .get(&request.hash)
            .expect("manifest named unknown hash");
        supplied += bytes.len();
        machine
            .deliver_page(request.ticket, bytes.clone())
            .expect("verified page delivery");
        if started.elapsed().as_secs() > 300 {
            break CpuExit::Interrupted;
        }
    };
    eprintln!(
        "exit={exit:?} icount={} supplied={} KiB elapsed={:?}",
        machine.icount(),
        supplied / 1024,
        started.elapsed()
    );
    eprintln!("trail={:?}", machine.syscall_trail());
    eprintln!(
        "jit dispatches: total={} block={} region={}",
        machine.vm_mut().jit_dispatch_count(),
        machine.vm_mut().jit_block_dispatch_count(),
        machine.vm_mut().jit_region_dispatch_count(),
    );
    let output = machine.take_output();
    eprintln!(
        "output ({} bytes): {:?}",
        output.len(),
        String::from_utf8_lossy(&output[..output.len().min(400)])
    );
    assert!(
        matches!(exit, CpuExit::InstructionLimit | CpuExit::Halt { .. }),
        "agent under jit+lazy stopped abnormally: {exit:?}"
    );
}
