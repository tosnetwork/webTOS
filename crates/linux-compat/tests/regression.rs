//! Per-version regression data: the deterministic figures each target
//! workload retires, recorded and compared build over build.
//!
//! The architectural traces pin four workloads register for register. This is
//! the wider, coarser net: for many workloads, the numbers that are exactly
//! reproducible — instructions retired, syscalls issued, the distinct syscall
//! numbers used, the exit code — recorded in one ledger and checked on every
//! run. Wall time is not here, because it is not reproducible; these are.
//!
//! A change to any of them moves the ledger, and that is the gate working: the
//! diff names the workload and the figure, so a regression between versions is
//! visible and attributable rather than silent. When the change is intended,
//! regenerate deliberately, the way the traces are:
//!
//!   cargo test -p linux-compat --release --test regression -- --ignored rewrite
//!
//! The ledger carries the crate version it was written under, so its git
//! history is the per-version record the milestone asks for.

use std::collections::BTreeSet;
use std::path::PathBuf;

use linux_compat::trace::Event;
use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn ledger_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/regression/workloads.txt")
}

/// One workload's reproducible figures.
#[derive(Debug, PartialEq, Eq)]
struct Metrics {
    label: String,
    instructions: u64,
    syscalls: u64,
    distinct_syscalls: Vec<u64>,
    exit_code: i32,
}

impl Metrics {
    /// One line per workload: label, then `key=value` fields. Distinct
    /// syscall numbers are listed so a change in *which* kernel entries a
    /// workload uses is caught, not only how many.
    fn to_line(&self) -> String {
        let distinct = self
            .distinct_syscalls
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}\tinstructions={} syscalls={} exit={} distinct={}",
            self.label, self.instructions, self.syscalls, self.exit_code, distinct
        )
    }

    fn from_line(line: &str) -> Option<Self> {
        let (label, rest) = line.split_once('\t')?;
        let mut instructions = 0;
        let mut syscalls = 0;
        let mut exit_code = 0;
        let mut distinct = Vec::new();
        for field in rest.split_whitespace() {
            let (key, value) = field.split_once('=')?;
            match key {
                "instructions" => instructions = value.parse().ok()?,
                "syscalls" => syscalls = value.parse().ok()?,
                "exit" => exit_code = value.parse().ok()?,
                "distinct" => {
                    distinct = if value.is_empty() {
                        Vec::new()
                    } else {
                        value
                            .split(',')
                            .map(|n| n.parse().unwrap_or(u64::MAX))
                            .collect()
                    }
                }
                _ => {}
            }
        }
        Some(Self {
            label: label.to_string(),
            instructions,
            syscalls,
            distinct_syscalls: distinct,
            exit_code,
        })
    }
}

/// The workloads tracked. In-repo fixtures, so the ledger reproduces on every
/// host rather than skipping where a cross compiler is absent.
fn workloads() -> Vec<(&'static str, &'static str, Vec<Vec<u8>>)> {
    vec![
        ("static-hello", "hello_linux.elf", vec![b"hello".to_vec()]),
        ("procfs-read", "test_procfs.elf", vec![b"procfs".to_vec()]),
        ("guest-ps", "guest_ps.elf", vec![b"ps".to_vec()]),
        ("argv", "test_argv.elf", vec![b"argv".to_vec()]),
        ("syscalls", "test_syscalls.elf", vec![b"syscalls".to_vec()]),
    ]
}

fn measure(fixture: &str, argv: &[Vec<u8>]) -> Option<Metrics> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data");
    let bytes = std::fs::read(dir.join(fixture)).ok()?;
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine.add_file(b"/bin/x", bytes, 0o755).ok()?;
    machine.set_args(argv.to_vec(), vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/x").expect("load failed");
    // Events only, no register samples, and no cap — every syscall must be
    // seen for the count to be a count.
    machine.record_trace(0);
    machine.vm_mut().icount_limit = machine.icount() + 40_000_000_000;
    let before = machine.icount();
    let exit = machine.run_traced(40_000_000_000);
    let instructions = machine.icount() - before;
    let trace = machine.take_trace().expect("a trace was recorded");
    let mut syscalls = 0_u64;
    let mut distinct = BTreeSet::new();
    for event in trace.events() {
        if let Event::Syscall { nr, .. } = event {
            syscalls += 1;
            distinct.insert(*nr);
        }
    }
    let exit_code = match exit {
        CpuExit::Halt { code: Some(code) } => code,
        other => panic!("{fixture} did not exit cleanly: {other:?}"),
    };
    Some(Metrics {
        label: String::new(),
        instructions,
        syscalls,
        distinct_syscalls: distinct.into_iter().collect(),
        exit_code,
    })
}

fn current() -> Vec<Metrics> {
    let mut out = Vec::new();
    for (label, fixture, argv) in workloads() {
        let mut metrics =
            measure(fixture, &argv).unwrap_or_else(|| panic!("in-repo fixture {fixture} missing"));
        metrics.label = label.to_string();
        out.push(metrics);
    }
    out
}

fn render(metrics: &[Metrics]) -> String {
    let mut out = format!(
        "# webtos regression ledger, linux-compat {}\n\
         # instructions/syscalls/distinct-syscall-numbers/exit are reproducible;\n\
         # a change here is a change in what a workload does. Regenerate with\n\
         # --ignored rewrite when the change is intended.\n",
        env!("CARGO_PKG_VERSION")
    );
    for m in metrics {
        out.push_str(&m.to_line());
        out.push('\n');
    }
    out
}

#[test]
fn workload_metrics_match_the_ledger() {
    let path = ledger_path();
    let recorded = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("no regression ledger at {}: {e}", path.display()));
    let expected: Vec<Metrics> = recorded
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(Metrics::from_line)
        .collect();

    let actual = current();
    let mut failures = Vec::new();
    for got in &actual {
        match expected.iter().find(|e| e.label == got.label) {
            None => failures.push(format!("{}: not in the ledger", got.label)),
            Some(want) => {
                if want.instructions != got.instructions {
                    failures.push(format!(
                        "{}: instructions {} -> {}",
                        got.label, want.instructions, got.instructions
                    ));
                }
                if want.syscalls != got.syscalls {
                    failures.push(format!(
                        "{}: syscalls {} -> {}",
                        got.label, want.syscalls, got.syscalls
                    ));
                }
                if want.distinct_syscalls != got.distinct_syscalls {
                    failures.push(format!(
                        "{}: distinct syscalls {:?} -> {:?}",
                        got.label, want.distinct_syscalls, got.distinct_syscalls
                    ));
                }
                if want.exit_code != got.exit_code {
                    failures.push(format!(
                        "{}: exit {} -> {}",
                        got.label, want.exit_code, got.exit_code
                    ));
                }
            }
        }
    }
    // A ledger entry with no matching workload means a workload was removed;
    // that is a change too, and it should be recorded rather than silently
    // passing because nothing recomputed it.
    for want in &expected {
        if !actual.iter().any(|a| a.label == want.label) {
            failures.push(format!(
                "{}: in the ledger but no longer measured",
                want.label
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "the workload ledger has drifted; if this was intended, regenerate with \
         `--ignored rewrite`:\n  {}",
        failures.join("\n  ")
    );
}

#[test]
#[ignore = "regenerates test_data/regression/workloads.txt; run deliberately"]
fn rewrite() {
    let metrics = current();
    std::fs::write(ledger_path(), render(&metrics)).expect("write ledger");
    println!("[regression] wrote {} workloads", metrics.len());
}
