//! Milestone-2 workload gates: BusyBox applets over the full linux-compat
//! environment.
//!
//! Requires the pinned BusyBox fixture (`tools/fetch_busybox.sh`); every
//! test skips with a message when it is absent so `cargo test` works from a
//! bare checkout.

use std::path::PathBuf;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn busybox() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: {} missing (run tools/fetch_busybox.sh)",
                path.display()
            );
            None
        }
    }
}

struct Run {
    exit: CpuExit,
    output: String,
}

/// Boots a fresh machine with BusyBox at /bin/busybox plus `extra_files`,
/// runs `busybox <args>`, and returns the exit and combined output.
fn run_busybox(args: &[&str], extra_files: &[(&str, &str)]) -> Option<Run> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let image = busybox()?;
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("add busybox");
    for (path, content) in extra_files {
        machine
            .add_file(path.as_bytes(), content.as_bytes().to_vec(), 0o644)
            .expect("add extra file");
    }

    let mut argv: Vec<Vec<u8>> = vec![b"busybox".to_vec()];
    argv.extend(args.iter().map(|a| a.as_bytes().to_vec()));
    machine.set_args(
        argv,
        vec![b"PATH=/bin:/usr/bin".to_vec(), b"HOME=/home".to_vec()],
    );
    machine.load(b"/bin/busybox").expect("ELF load failed");

    machine.vm_mut().icount_limit = 500_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Some(Run { exit, output })
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
fn echo_prints_arguments() {
    let Some(run) = run_busybox(&["echo", "hello", "milestone-2"], &[]) else {
        return;
    };
    expect_clean(&run);
    assert_eq!(run.output, "hello milestone-2\n");
}

#[test]
fn cat_reads_a_file() {
    let content = "line one\nline two\n";
    let Some(run) = run_busybox(
        &["cat", "/etc/greeting.txt"],
        &[("/etc/greeting.txt", content)],
    ) else {
        return;
    };
    expect_clean(&run);
    assert_eq!(run.output, content);
}

#[test]
fn ls_lists_directories() {
    let Some(run) = run_busybox(&["ls", "/"], &[]) else {
        return;
    };
    expect_clean(&run);
    for name in ["bin", "dev", "etc", "tmp", "usr"] {
        assert!(
            run.output.contains(name),
            "ls output missing {name}: {:?}",
            run.output
        );
    }
}

/// Runs several BusyBox invocations as consecutive processes on one
/// machine: the VFS persists across process lifetimes, so this exercises
/// both the applets and filesystem persistence.
fn run_sequence(machine: &mut linux_compat::Machine, args: &[&str]) -> Run {
    let mut argv: Vec<Vec<u8>> = vec![b"busybox".to_vec()];
    argv.extend(args.iter().map(|a| a.as_bytes().to_vec()));
    machine.set_args(
        argv,
        vec![b"PATH=/bin:/usr/bin".to_vec(), b"HOME=/home".to_vec()],
    );
    machine.load(b"/bin/busybox").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 500_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Run { exit, output }
}

#[test]
fn mkdir_cp_mv_rm_roundtrip() {
    // The full milestone-2 applet set, one process per command (the shell
    // cannot spawn external applets until process support lands in
    // milestone 4). The filesystem persists across the processes.
    let Some(image) = busybox() else { return };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("add busybox");
    machine
        .add_file(b"/etc/f.txt", b"payload\n".to_vec(), 0o644)
        .expect("add file");

    for args in [
        &["mkdir", "/tmp/a"][..],
        &["cp", "/etc/f.txt", "/tmp/a/f.txt"],
        &["mv", "/tmp/a/f.txt", "/tmp/a/g.txt"],
    ] {
        let run = run_sequence(&mut machine, args);
        expect_clean(&run);
    }

    let run = run_sequence(&mut machine, &["cat", "/tmp/a/g.txt"]);
    expect_clean(&run);
    assert_eq!(run.output, "payload\n", "cp/mv lost content");

    for args in [&["rm", "/tmp/a/g.txt"][..], &["rmdir", "/tmp/a"]] {
        let run = run_sequence(&mut machine, args);
        expect_clean(&run);
    }

    // The directory really is gone.
    let run = run_sequence(&mut machine, &["ls", "/tmp"]);
    expect_clean(&run);
    assert!(
        !run.output.contains('a'),
        "rmdir left /tmp/a behind: {:?}",
        run.output
    );
}

#[test]
fn shell_runs_builtin_sequences() {
    let script = "echo first && cd /tmp && pwd && echo $HOME";
    let Some(run) = run_busybox(&["sh", "-c", script], &[]) else {
        return;
    };
    expect_clean(&run);
    assert!(
        run.output.contains("first"),
        "missing echo output: {:?}",
        run.output
    );
    assert!(
        run.output.contains("/tmp"),
        "missing pwd output: {:?}",
        run.output
    );
    assert!(
        run.output.contains("/home"),
        "missing $HOME output: {:?}",
        run.output
    );
}

#[test]
fn shell_redirection_persists_across_processes() {
    // The redirect itself is pure shell work (open + dup2 + builtin echo);
    // a second process then reads the file back.
    let Some(image) = busybox() else { return };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("add busybox");

    let run = run_sequence(&mut machine, &["sh", "-c", "echo persisted > /tmp/out.txt"]);
    expect_clean(&run);

    let run = run_sequence(&mut machine, &["cat", "/tmp/out.txt"]);
    expect_clean(&run);
    assert_eq!(run.output, "persisted\n", "redirect roundtrip failed");
}
