//! Milestone-3 stress: dynamically linked binaries against the host glibc
//! (its loader exercises far more of the ABI than musl). The fixtures are
//! compiled on the host by the test itself and the runtime is borrowed from
//! the host, so these tests only run on an x86-64 Linux machine and skip
//! elsewhere (a macOS or ARM host compiles the fixture for its own platform
//! and has no glibc loader to donate).

use std::path::{Path, PathBuf};
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

const GLIBC_RUNTIME: [&str; 3] = [
    "/lib64/ld-linux-x86-64.so.2",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libgcc_s.so.1",
];

/// True when this host has an x86-64 glibc runtime to donate to the guest.
fn host_has_glibc() -> bool {
    GLIBC_RUNTIME.iter().all(|lib| Path::new(lib).is_file())
}

/// Copies the host glibc runtime (loader + shared libraries) into the guest.
fn add_glibc(machine: &mut Machine) -> Result<(), String> {
    for lib in GLIBC_RUNTIME {
        let bytes = std::fs::read(lib).map_err(|e| format!("{lib}: {e}"))?;
        machine.add_file(lib.as_bytes(), bytes, 0o755)?;
    }
    Ok(())
}

/// An ELF64 little-endian image for EM_X86_64. A compiler on a macOS or ARM
/// host happily produces something the guest cannot run, so the format is
/// checked rather than assumed.
fn is_x86_64_elf(image: &[u8]) -> bool {
    image.len() > 20 && &image[..4] == b"\x7fELF" && image[4] == 2 && image[18] == 0x3e
}

fn compile(cmd: &mut Command, out: &Path) -> Option<Vec<u8>> {
    match cmd.status() {
        Ok(status) if status.success() => {
            let image = std::fs::read(out).expect("compiler output");
            if !is_x86_64_elf(&image) {
                eprintln!("skipping: host compiler does not target x86-64 Linux ({cmd:?})");
                return None;
            }
            Some(image)
        }
        _ => {
            eprintln!("skipping: fixture compiler unavailable ({cmd:?})");
            None
        }
    }
}

fn run_guest(image: Vec<u8>, name: &str) -> Run {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    add_glibc(&mut machine).expect("host glibc import failed");
    let guest_path = format!("/bin/{name}");
    machine
        .add_file(guest_path.as_bytes(), image, 0o755)
        .expect("add fixture");

    machine.set_args(vec![name.as_bytes().to_vec()], vec![b"HOME=/root".to_vec()]);
    machine
        .load(guest_path.as_bytes())
        .expect("ELF load failed");
    machine.vm_mut().icount_limit = 2_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Run { exit, output }
}

struct Run {
    exit: CpuExit,
    output: String,
}

#[test]
fn glibc_dynamic_c_hello() {
    if !host_has_glibc() {
        eprintln!("skipping: host has no x86-64 glibc runtime to donate");
        return;
    }
    let dir = std::env::temp_dir().join("webtos-glibc-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join("hello.c");
    let out = dir.join("hello");
    std::fs::write(
        &src,
        "#include <stdio.h>\nint main(void){ printf(\"glibc dynamic hello\\n\"); return 0; }\n",
    )
    .expect("write source");
    let Some(image) = compile(Command::new("gcc").arg("-o").arg(&out).arg(&src), &out) else {
        return;
    };

    let run = run_guest(image, "hello");
    assert_eq!(
        run.exit,
        CpuExit::Halt { code: Some(0) },
        "guest did not exit cleanly; output: {:?}",
        run.output
    );
    assert_eq!(run.output, "glibc dynamic hello\n");
}

#[test]
fn glibc_dynamic_rust_hello() {
    if !host_has_glibc() {
        eprintln!("skipping: host has no x86-64 glibc runtime to donate");
        return;
    }
    let dir = std::env::temp_dir().join("webtos-glibc-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join("hello.rs");
    let out = dir.join("rhello");
    std::fs::write(&src, "fn main(){ println!(\"rust dynamic hello\"); }\n").expect("write source");
    let Some(image) = compile(
        Command::new("rustc")
            .arg("-O")
            .arg("-o")
            .arg(&out)
            .arg(&src),
        &out,
    ) else {
        return;
    };

    let run = run_guest(image, "rhello");
    assert_eq!(
        run.exit,
        CpuExit::Halt { code: Some(0) },
        "guest did not exit cleanly; output: {:?}",
        run.output
    );
    assert_eq!(run.output, "rust dynamic hello\n");
}
