//! Milestone-0 evidence: architectural traces, recorded against versioned
//! baselines.
//!
//! Determinism was gated by comparing runs to each other — same output, same
//! instruction count, twice. That catches an engine that is inconsistent with
//! itself, and nothing else. These tests compare a run against a file in the
//! repository that a reviewer can read, so a change in what the CPU does shows
//! up as a diff rather than as an equal-but-different number.
//!
//! They are also the shape of milestone 8's gate. When a translation tier
//! exists it has to produce these same traces; the harness for that is this
//! one, pointed at a second engine.
//!
//! Regenerate after an intentional change:
//!
//! ```text
//! cargo test -p linux-compat --release --test trace -- --ignored rewrite
//! ```

use std::path::PathBuf;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn test_data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data")
}

/// One recorded workload: which image, which arguments, and how densely to
/// sample. Sampling is per retired instruction, so a bigger workload gets a
/// coarser rate and the file stays reviewable.
struct Case {
    name: &'static str,
    image: &'static str,
    guest_path: &'static str,
    argv: &'static [&'static str],
    sample_every: u64,
}

const CASES: &[Case] = &[
    Case {
        name: "hello-static",
        image: "hello_linux.elf",
        guest_path: "/bin/hello",
        argv: &["hello"],
        sample_every: 8,
    },
    Case {
        name: "guest-ps",
        image: "guest_ps.elf",
        guest_path: "/bin/ps",
        argv: &["ps"],
        sample_every: 64,
    },
    Case {
        name: "busybox-echo",
        image: "busybox-musl",
        guest_path: "/bin/busybox",
        argv: &["busybox", "echo", "trace"],
        sample_every: 512,
    },
    Case {
        name: "busybox-ls",
        image: "busybox-musl",
        guest_path: "/bin/busybox",
        argv: &["busybox", "ls", "/bin"],
        sample_every: 8192,
    },
];

/// Records a case, or None when its fixture is not present (BusyBox is
/// fetched, not vendored).
fn record(case: &Case) -> Option<String> {
    let image = std::fs::read(test_data().join(case.image)).ok()?;
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(case.guest_path.as_bytes(), image.clone(), 0o755)
        .expect("add image");
    machine.set_args(
        case.argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
        vec![b"PATH=/bin".to_vec()],
    );
    machine
        .load(case.guest_path.as_bytes())
        .expect("ELF load failed");
    machine.record_trace(case.sample_every);
    machine.describe_trace_image(case.guest_path.as_bytes(), &image);

    let exit = machine.run_traced(4_000_000_000);
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "{} did not exit cleanly",
        case.name
    );
    Some(machine.take_trace().expect("trace was recorded").to_text())
}

/// Records a case with the wasmi JIT installed, so hot blocks execute as
/// compiled wasm instead of being interpreted. Returns the trace text and the
/// number of JIT dispatches, or None when the fixture is absent. Every input —
/// image, args, sampling — is identical to [`record`], so the trace it produces
/// must be byte-identical to the interpreter's: same bytes seen by the CPU, same
/// retired-instruction count at every sample point.
fn record_jit(case: &Case) -> Option<(String, u64)> {
    let image = std::fs::read(test_data().join(case.image)).ok()?;
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(case.guest_path.as_bytes(), image.clone(), 0o755)
        .expect("add image");
    machine.set_args(
        case.argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
        vec![b"PATH=/bin".to_vec()],
    );
    machine
        .load(case.guest_path.as_bytes())
        .expect("ELF load failed");
    machine.record_trace(case.sample_every);
    machine.describe_trace_image(case.guest_path.as_bytes(), &image);

    // Compile a block the first time it is re-entered, so the trace exercises as
    // much of the emitter as the workload allows; blocks the translator bails on
    // fall back to the interpreter and are traced the same either way.
    machine.set_jit(Box::new(jit_wasmi::WasmiJit::new()));
    machine.set_jit_tiering(Some(1));

    let exit = machine.run_traced(4_000_000_000);
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "{} did not exit cleanly under the JIT",
        case.name
    );
    Some((
        machine.take_trace().expect("trace was recorded").to_text(),
        machine.jit_dispatch_count(),
    ))
}

fn reference_path(case: &Case) -> PathBuf {
    test_data()
        .join("traces")
        .join(format!("{}.trace", case.name))
}

/// The first line of difference, which is what a reviewer wants to see.
fn first_difference(expected: &str, actual: &str) -> String {
    for (line, (want, got)) in expected.lines().zip(actual.lines()).enumerate() {
        if want != got {
            return format!("line {}:\n  expected: {want}\n  actual:   {got}", line + 1);
        }
    }
    format!(
        "the traces agree for {} lines, then differ in length: expected {}, actual {}",
        expected.lines().count().min(actual.lines().count()),
        expected.lines().count(),
        actual.lines().count()
    )
}

#[test]
fn reference_traces_still_reproduce() {
    let mut checked = 0;
    for case in CASES {
        let Some(actual) = record(case) else {
            eprintln!("skipping {}: {} missing", case.name, case.image);
            continue;
        };
        let path = reference_path(case);
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("no reference trace at {}: {e}", path.display()));
        assert!(
            expected == actual,
            "{} diverged from its reference trace.\n{}\n\
             If the change was intended, regenerate with:\n  \
             cargo test -p linux-compat --release --test trace -- --ignored rewrite",
            case.name,
            first_difference(&expected, &actual)
        );
        checked += 1;
    }
    assert!(
        checked >= 2,
        "no reference trace was checked; the in-repository fixtures should always be present"
    );
}

/// The exit gate for the optimized mode: with hot blocks translated to
/// WebAssembly and executed by wasmi, every case must reproduce the
/// interpreter's reference trace register for register — the same file the
/// interpreter is held to above. The JIT must actually have fired, or a match
/// proves nothing. wasmi is a correctness backend, not a speedup one (see
/// `feasibility/jit_native_wasmi.md`); the browser matrix carries the same proof
/// against V8/SpiderMonkey/JavaScriptCore.
#[test]
fn reference_traces_reproduce_under_the_jit() {
    let mut checked = 0;
    for case in CASES {
        let Some((actual, dispatches)) = record_jit(case) else {
            eprintln!("skipping {}: {} missing", case.name, case.image);
            continue;
        };
        assert!(
            dispatches > 0,
            "{}: the JIT never dispatched under this workload — the trace match proves nothing",
            case.name
        );
        let path = reference_path(case);
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("no reference trace at {}: {e}", path.display()));
        assert!(
            expected == actual,
            "{} diverged from its interpreter reference trace under the JIT \
             ({dispatches} dispatches).\n{}\n\
             The optimized mode must reproduce the interpreter bit for bit; this \
             is a JIT correctness bug, not a trace to regenerate.",
            case.name,
            first_difference(&expected, &actual)
        );
        checked += 1;
    }
    assert!(
        checked >= 2,
        "no reference trace was checked under the JIT; the in-repository fixtures should always be present"
    );
}

/// A trace has to be a property of the guest, not of how far a single `run`
/// call happened to get. Recording the same case twice must produce the same
/// file even though the second run is served entirely from a warm lift cache.
#[test]
fn recording_is_reproducible_within_a_process() {
    let case = &CASES[0];
    let first = record(case).expect("in-repository fixture");
    let second = record(case).expect("in-repository fixture");
    assert!(
        first == second,
        "the same case traced differently on a second recording.\n{}",
        first_difference(&first, &second)
    );
}

#[test]
#[ignore = "writes reference traces; run deliberately after an intended change"]
fn rewrite_reference_traces() {
    let dir = test_data().join("traces");
    std::fs::create_dir_all(&dir).expect("create traces directory");
    for case in CASES {
        let Some(text) = record(case) else {
            eprintln!("skipping {}: {} missing", case.name, case.image);
            continue;
        };
        let path = reference_path(case);
        std::fs::write(&path, text).expect("write reference trace");
        println!("wrote {}", path.display());
    }
}
