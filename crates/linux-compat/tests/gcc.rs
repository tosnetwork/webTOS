//! A C toolchain compiling, linking, and running a program inside the guest.
//!
//! Every other workload gate runs one program. This one runs a process tree:
//! a shell forks the compiler driver, which execs the compiler proper, then
//! the assembler, then the linker driver and the linker, and the shell then
//! executes what came out. It is the densest use of fork, exec, temporary
//! files, pipes, and exit-status propagation the suite has, and unlike the
//! agents it fails loudly and specifically when one of them is wrong — a
//! toolchain says which stage broke.
//!
//! The toolchain is a host-path dependency rather than a vendored fixture, so
//! the tests skip when the host has no `gcc`, when it is not an x86-64 Linux
//! one, or when the pieces it points at are missing. `WEBTOS_REQUIRE_FIXTURES=1`
//! turns those skips into failures.

use std::path::{Path, PathBuf};
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

const GCC: &str = "/usr/bin/gcc";

/// Asks the driver where one of its subprograms lives. It answers with a bare
/// name when it means "resolve this on PATH", which is not a location, so only
/// an absolute path that exists counts as an answer.
fn prog(name: &str) -> Option<PathBuf> {
    ask(&["-print-prog-name", name])
}

/// Asks the driver where one of its input files lives — the C runtime objects
/// it hands the linker. Same rule about bare names.
fn file(name: &str) -> Option<PathBuf> {
    ask(&["-print-file-name", name])
}

fn ask(spec: &[&str; 2]) -> Option<PathBuf> {
    let out = Command::new(GCC)
        .arg(format!("{}={}", spec[0], spec[1]))
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let answer = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let path = PathBuf::from(answer);
    (path.is_absolute() && path.exists()).then_some(path)
}

/// The shared libraries a host binary loads, the loader among them, read from
/// `ldd` rather than assumed. A static binary yields an empty list, which is
/// an answer; a binary `ldd` cannot read yields None, which is a skip.
fn shared_libs(binary: &Path) -> Option<Vec<PathBuf>> {
    let out = Command::new("ldd").arg(binary).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut libs = Vec::new();
    for line in text.lines() {
        // `name => /path (0x…)` for a resolved library, `/path (0x…)` for the
        // loader itself, and `name (0x…)` for the vdso, which is not a file.
        let token = match line.split_once("=> ") {
            Some((_, rhs)) => rhs.split_whitespace().next(),
            None => line.split_whitespace().next(),
        };
        if let Some(token) = token {
            let path = PathBuf::from(token);
            if path.is_absolute() && path.is_file() {
                libs.push(path);
            }
        }
    }
    Some(libs)
}

/// Everything the guest needs before it can compile: the driver and the
/// programs it execs, the libraries all of them load, the C runtime objects
/// the linker consumes, the header tree, and a shell to drive it.
struct Toolchain {
    /// Host files placed at their own path in the guest.
    files: Vec<PathBuf>,
    /// Host directories mounted at their own path in the guest.
    trees: Vec<PathBuf>,
    /// The assembler and linker, each paired with the plain tool name. A host
    /// toolchain installs them as `x86_64-linux-gnu-as` and names them that
    /// way to the driver, but collect2 searches for `ld`, so both names have
    /// to resolve.
    on_path: Vec<(PathBuf, &'static str)>,
    shell: Vec<u8>,
}

fn toolchain() -> Option<Toolchain> {
    let shell = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    let shell = linux_compat::testing::require(
        &format!("{} (run tools/fetch_busybox.sh)", shell.display()),
        std::fs::read(&shell).ok(),
    )?;
    linux_compat::testing::require(
        &format!("a host C toolchain at {GCC} targeting Linux x86-64"),
        assemble(shell),
    )
}

/// Collects the toolchain, or None when any part of it is absent. Kept apart
/// from `toolchain` so that every missing piece produces one skip message
/// naming the toolchain, rather than one per piece.
fn assemble(shell: Vec<u8>) -> Option<Toolchain> {
    if !Path::new(GCC).exists() {
        return None;
    }
    // The compiler proper, the assembler, and the two halves of linking. A
    // driver that cannot name these is not one we can drive.
    let cc1 = prog("cc1")?;
    let assembler = prog("as")?;
    let linker = prog("ld")?;
    let collect2 = prog("collect2")?;

    let mut files = vec![PathBuf::from(GCC), cc1.clone(), collect2.clone()];
    files.push(assembler.clone());
    files.push(linker.clone());

    for binary in [Path::new(GCC), &cc1, &assembler, &linker, &collect2] {
        files.extend(shared_libs(binary)?);
    }

    // The driver passes the linker plugin whenever the host build has one, so
    // its absence in the guest is a fatal error rather than a missing feature.
    // It sits beside cc1, not among the files the driver can be asked about.
    if let Some(plugin) = cc1.parent().map(|dir| dir.join("liblto_plugin.so")) {
        if plugin.is_file() {
            files.push(plugin);
        }
    }

    // The objects and libraries the linker consumes, located by asking the
    // driver rather than by guessing a path. `libgcc_s.so.1` is here because
    // the link needs the file itself, not only the loader's copy.
    for object in [
        "crt1.o",
        "crti.o",
        "crtn.o",
        "Scrt1.o",
        "libc.so",
        "libc.so.6",
        "libc.a",
        "libc_nonshared.a",
        "libgcc_s.so",
        "libgcc_s.so.1",
    ] {
        if let Some(path) = file(object) {
            files.push(path);
        }
    }
    let gcc_lib = file("crtbegin.o")?.parent()?.to_path_buf();

    let headers = PathBuf::from("/usr/include");
    if !headers.is_dir() {
        return None;
    }

    files.sort();
    files.dedup();
    Some(Toolchain {
        files,
        trees: vec![gcc_lib, headers],
        on_path: vec![(assembler, "as"), (linker, "ld")],
        shell,
    })
}

/// Builds a machine carrying the toolchain, with `source` at /source.c.
fn machine_with(toolchain: &Toolchain, source: &str) -> Machine {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");

    // A compiler maps far more than an agent does: the default cap is a
    // gigabyte, and cc1 alone is tens of megabytes before it allocates.
    let pages = 4096usize * 256; // 4 GiB in 4 KiB pages
    assert!(
        machine.vm_mut().cpu.mem.set_capacity(pages),
        "cannot raise the guest memory cap"
    );

    for host in &toolchain.files {
        let bytes = std::fs::read(host).expect("read toolchain file");
        let guest = host.to_string_lossy().into_owned();
        machine
            .add_file(guest.as_bytes(), bytes, 0o755)
            .expect("stage toolchain file");
    }
    for host in &toolchain.trees {
        let guest = host.to_string_lossy().into_owned();
        machine
            .add_host_tree(host, &guest)
            .expect("mount toolchain tree");
    }
    // The driver searches its configured directories first and PATH after, and
    // which one finds the assembler depends on how the host gcc was built. Both
    // are populated so the test does not depend on that.
    for (host, generic) in &toolchain.on_path {
        let bytes = std::fs::read(host).expect("read toolchain program");
        let installed = host
            .file_name()
            .expect("program name")
            .to_string_lossy()
            .into_owned();
        let mut names = vec![installed.clone()];
        if installed != *generic {
            names.push((*generic).to_string());
        }
        for name in names {
            for dir in ["/bin", "/usr/bin"] {
                let guest = format!("{dir}/{name}");
                machine
                    .add_file(guest.as_bytes(), bytes.clone(), 0o755)
                    .expect("stage program on PATH");
            }
        }
    }
    machine
        .add_file(b"/bin/sh", toolchain.shell.clone(), 0o755)
        .expect("stage shell");
    machine
        .add_file(b"/source.c", source.as_bytes().to_vec(), 0o644)
        .expect("stage source");
    // The driver writes its intermediates here and unlinks them after.
    machine
        .add_file(b"/tmp/.keep", Vec::new(), 0o644)
        .expect("create /tmp");
    machine
}

struct Run {
    exit: CpuExit,
    output: String,
}

/// Runs `sh -c <script>` in the guest and returns its exit and output.
fn run_shell(machine: &mut Machine, script: &str) -> Run {
    machine.set_args(
        vec![b"sh".to_vec(), b"-c".to_vec(), script.as_bytes().to_vec()],
        vec![
            b"PATH=/usr/bin:/bin".to_vec(),
            b"HOME=/root".to_vec(),
            b"TMPDIR=/tmp".to_vec(),
        ],
    );
    machine.load(b"/bin/sh").expect("shell ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    Run {
        exit,
        output: String::from_utf8_lossy(&machine.take_output()).into_owned(),
    }
}

/// The whole toolchain, end to end: the driver compiles and links a program,
/// and the shell then runs what it produced. The greeting can only reach the
/// output if code the guest generated ran in the guest.
#[test]
fn compiles_links_and_runs_a_c_program() {
    let Some(toolchain) = toolchain() else {
        return;
    };
    let source = r#"
#include <stdio.h>
int main(void) {
    printf("hello from a compiler in the guest\n");
    return 0;
}
"#;
    let mut machine = machine_with(&toolchain, source);
    let run = run_shell(
        &mut machine,
        "gcc -O2 -o /tmp/program /source.c && /tmp/program",
    );
    assert_eq!(
        run.exit,
        CpuExit::Halt { code: Some(0) },
        "the toolchain did not finish cleanly; output: {:?}",
        run.output
    );
    assert!(
        run.output.contains("hello from a compiler in the guest"),
        "the compiled program did not run; output: {:?}",
        run.output
    );
}

/// The status of the compiled program, not of the compiler. A driver that
/// silently produced nothing would still exit 0 above if the shell were
/// lenient; an exit status the source alone decides cannot come from anywhere
/// but generated code that ran.
#[test]
fn the_compiled_program_decides_its_own_exit_status() {
    let Some(toolchain) = toolchain() else {
        return;
    };
    let mut machine = machine_with(&toolchain, "int main(void) { return 7; }\n");
    let run = run_shell(
        &mut machine,
        "gcc -o /tmp/program /source.c && /tmp/program; echo status=$?",
    );
    assert_eq!(
        run.exit,
        CpuExit::Halt { code: Some(0) },
        "the shell did not finish cleanly; output: {:?}",
        run.output
    );
    assert!(
        run.output.contains("status=7"),
        "the compiled program's exit status did not reach the shell; output: {:?}",
        run.output
    );
}
