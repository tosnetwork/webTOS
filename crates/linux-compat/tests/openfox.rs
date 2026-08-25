//! Milestone-6 workload gates: OpenFox (a real Go agent binary) inside the
//! machine.
//!
//! Requires the fixture from `tools/build_openfox_fixture.sh` (a static
//! CGO-free build of the pinned OpenFox commit); every test skips with a
//! message when it is absent. These gates exercise the whole Go runtime:
//! threads over CLONE_VM with a shared group address space, timed futexes,
//! timed epoll waits, nanosleep parking, and signal dispositions.

use std::path::PathBuf;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn openfox() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/openfox");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: {} missing (run tools/build_openfox_fixture.sh)",
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

fn machine_with_openfox(image: Vec<u8>) -> Machine {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/openfox", image, 0o755)
        .expect("add openfox");
    machine
}

fn run_openfox(machine: &mut Machine, args: &[&str]) -> Run {
    let mut argv: Vec<Vec<u8>> = vec![b"openfox".to_vec()];
    argv.extend(args.iter().map(|a| a.as_bytes().to_vec()));
    machine.set_args(
        argv,
        vec![
            b"HOME=/root".to_vec(),
            b"PATH=/bin".to_vec(),
            b"TERM=xterm".to_vec(),
            // Belt and braces: preemption signals are dropped anyway.
            b"GODEBUG=asyncpreemptoff=1".to_vec(),
        ],
    );
    machine.load(b"/bin/openfox").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 20_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Run { exit, output }
}

fn expect_clean(run: &Run) {
    assert_eq!(
        run.exit,
        CpuExit::Halt { code: Some(0) },
        "guest did not exit cleanly; output tail: {:?}",
        &run.output[run.output.len().saturating_sub(600)..]
    );
}

#[test]
fn openfox_version_reports_cleanly() {
    let Some(image) = openfox() else { return };
    let mut machine = machine_with_openfox(image);
    let run = run_openfox(&mut machine, &["version"]);
    expect_clean(&run);
    assert!(
        run.output.contains("openfox") && run.output.contains("Go: go1."),
        "version output tail: {:?}",
        &run.output[run.output.len().saturating_sub(300)..]
    );
}

#[test]
fn openfox_help_lists_commands() {
    let Some(image) = openfox() else { return };
    let mut machine = machine_with_openfox(image);
    let run = run_openfox(&mut machine, &["--help"]);
    expect_clean(&run);
    for expected in ["Usage", "version", "status"] {
        assert!(
            run.output.contains(expected),
            "help output missing {expected:?}: {:?}",
            &run.output[run.output.len().saturating_sub(400)..]
        );
    }
}

#[test]
fn openfox_status_sees_configuration_across_a_snapshot() {
    let Some(image) = openfox() else { return };
    let mut machine = machine_with_openfox(image);

    // Fresh profile: status must run cleanly and report missing config.
    let run = run_openfox(&mut machine, &["status"]);
    expect_clean(&run);
    assert!(
        run.output.contains("config.json \u{2717}"),
        "expected missing-config marker: {:?}",
        &run.output[run.output.len().saturating_sub(400)..]
    );

    // Seed a configuration and workspace, snapshot the filesystem
    // (browser-reload semantics), restore into a new machine: status must
    // now see both.
    machine
        .add_file(b"/root/.openfox/config.json", b"{}\n".to_vec(), 0o644)
        .expect("seed config");
    machine
        .env()
        .vfs
        .mkdir_p(b"/root/.openfox/workspace")
        .expect("seed workspace");
    let snapshot = machine.export_fs();

    let mut reborn =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    reborn.import_fs(&snapshot).expect("snapshot import failed");
    let run = run_openfox(&mut reborn, &["status"]);
    expect_clean(&run);
    assert!(
        run.output.contains("config.json \u{2713}"),
        "config did not survive the snapshot: {:?}",
        &run.output[run.output.len().saturating_sub(400)..]
    );
    assert!(
        run.output.contains("workspace \u{2713}"),
        "workspace did not survive the snapshot: {:?}",
        &run.output[run.output.len().saturating_sub(400)..]
    );
}
