//! Milestone-3 workload gates: dynamically linked PIE executables started
//! through the system dynamic loader (musl `ld-musl-x86_64.so.1`).
//!
//! Requires the pinned Alpine minirootfs fixture
//! (`tools/fetch_alpine_rootfs.sh`); every test skips with a message when it
//! is absent so `cargo test` works from a bare checkout.

use std::path::PathBuf;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn rootfs() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/alpine-minirootfs");
    if path.join("lib/ld-musl-x86_64.so.1").exists() {
        Some(path)
    } else {
        eprintln!(
            "skipping: {} missing (run tools/fetch_alpine_rootfs.sh)",
            path.display()
        );
        None
    }
}

fn alpine_machine() -> Option<Machine> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let rootfs = rootfs()?;
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_host_tree(&rootfs, "/")
        .expect("rootfs import failed");
    Some(machine)
}

struct Run {
    exit: CpuExit,
    output: String,
}

fn exec(machine: &mut Machine, path: &str, args: &[&str]) -> Run {
    let argv: Vec<Vec<u8>> = args.iter().map(|a| a.as_bytes().to_vec()).collect();
    machine.set_args(
        argv,
        vec![b"PATH=/bin:/usr/bin:/sbin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine.load(path.as_bytes()).expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 1_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Run { exit, output }
}

fn expect_clean(run: &Run) {
    assert_eq!(
        run.exit,
        CpuExit::Halt { code: Some(0) },
        "guest did not exit cleanly; output: {:?}",
        run.output
    );
}

#[test]
fn dynamic_hello_fixture_runs_through_the_loader() {
    // The repository's own musl-linked dynamic PIE fixture.
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let hello = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/hello_dynamic.elf"),
    )
    .expect("hello_dynamic.elf missing");
    machine
        .add_file(b"/bin/hello_dynamic", hello, 0o755)
        .expect("add fixture");

    let run = exec(&mut machine, "/bin/hello_dynamic", &["hello_dynamic"]);
    expect_clean(&run);
    assert!(
        run.output.to_lowercase().contains("hello"),
        "unexpected output: {:?}",
        run.output
    );
}

#[test]
fn alpine_dynamic_busybox_echo() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let run = exec(
        &mut machine,
        "/bin/busybox",
        &["echo", "dynamic-milestone-3"],
    );
    expect_clean(&run);
    assert_eq!(run.output, "dynamic-milestone-3\n");
}

#[test]
fn alpine_applet_symlinks_select_the_applet() {
    // /bin/ls is a symlink to /bin/busybox; argv[0] selects the applet.
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let run = exec(&mut machine, "/bin/ls", &["ls", "/etc"]);
    expect_clean(&run);
    assert!(
        run.output.contains("passwd"),
        "ls /etc missing passwd: {:?}",
        run.output
    );
}

#[test]
fn alpine_shell_and_filesystem_roundtrip() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };

    let run = exec(
        &mut machine,
        "/bin/sh",
        &["sh", "-c", "echo dyn > /tmp/dyn.txt && cd /tmp && pwd"],
    );
    expect_clean(&run);
    assert!(run.output.contains("/tmp"), "pwd failed: {:?}", run.output);

    let run = exec(&mut machine, "/bin/cat", &["cat", "/tmp/dyn.txt"]);
    expect_clean(&run);
    assert_eq!(run.output, "dyn\n", "redirect roundtrip failed");
}
