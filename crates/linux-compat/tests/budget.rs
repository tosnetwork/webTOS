//! Published latency budgets, gated on instruction counts.
//!
//! Latency is what a person feels, and wall time is how you would measure it —
//! but wall time flaps, and it differs by an order of magnitude between
//! browser engines for reasons `docs/performance.md` shows are the engines'
//! wasm compilers rather than anything in webTOS. A gate on it would fire on a
//! loaded CI box and pass on a quiet laptop, which is a gate that reports the
//! machine rather than the code.
//!
//! Instruction count is the deterministic half of latency: the same workload
//! retires the same count on every host and every engine — the browser matrix
//! asserts exactly that, register for register against a recorded trace. So a
//! budget on instruction count is a latency contract that cannot flap. It does
//! not say how many nanoseconds a workload takes; it says how much work it
//! does, and a regression that doubles the work is a regression that doubles
//! the latency on every engine at once.
//!
//! These budgets are ceilings, not fingerprints. The architectural trace gate
//! already pins the exact count of the workloads it covers; a budget is the
//! looser, published promise — startup stays in its class — with room for an
//! intended change and no room for a blow-up. Each names the count measured
//! when it was set, so the headroom is visible.
//!
//! Wall time is printed alongside, explicitly not gated, because a number
//! worth seeing is not the same as a number worth failing on.

use std::path::PathBuf;
use std::time::Instant;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// One budgeted workload: what to run, the ceiling it must stay under, and
/// the count measured when the ceiling was chosen.
struct Budget {
    label: &'static str,
    ceiling: u64,
    measured: u64,
}

fn run_fixture(fixture: &str, argv: &[&str], expect_code: i32) -> Option<(u64, f64)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data");
    let bytes = std::fs::read(dir.join(fixture)).ok()?;
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine.add_file(b"/bin/x", bytes, 0o755).ok()?;
    let mut args = vec![b"x".to_vec()];
    args.extend(argv.iter().map(|a| a.as_bytes().to_vec()));
    machine.set_args(args, vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()]);
    machine.load(b"/bin/x").expect("load failed");
    machine.vm_mut().icount_limit = machine.icount() + 40_000_000_000;
    let before = machine.icount();
    let start = Instant::now();
    let exit = machine.run();
    let seconds = start.elapsed().as_secs_f64();
    assert_eq!(
        exit,
        CpuExit::Halt {
            code: Some(expect_code)
        },
        "{fixture} did not exit with {expect_code}"
    );
    Some((machine.icount() - before, seconds))
}

fn busybox() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    linux_compat::testing::require(
        &format!("{} (run tools/fetch_busybox.sh)", path.display()),
        path.exists()
            .then(|| std::fs::read(&path).expect("busybox")),
    )
}

fn run_busybox(image: &[u8], argv: &[&str]) -> (u64, f64) {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image.to_vec(), 0o755)
        .expect("add busybox");
    let mut args = vec![b"busybox".to_vec()];
    args.extend(argv.iter().map(|a| a.as_bytes().to_vec()));
    machine.set_args(args, vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()]);
    machine.load(b"/bin/busybox").expect("load failed");
    machine.vm_mut().icount_limit = machine.icount() + 40_000_000_000;
    let before = machine.icount();
    let start = Instant::now();
    let exit = machine.run();
    let seconds = start.elapsed().as_secs_f64();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "busybox {argv:?} failed"
    );
    (machine.icount() - before, seconds)
}

/// Checks one measurement against its budget, collecting the failure rather
/// than panicking, so a run reports every workload that is over rather than
/// stopping at the first.
fn check(budget: &Budget, icount: u64, seconds: f64, failures: &mut Vec<String>) {
    let verdict = if icount <= budget.ceiling {
        "ok"
    } else {
        "OVER"
    };
    println!(
        "[budget] {:<32} {:>10} / {:>10}  ({:>5.1}% of budget)  {:>7.3} s (ungated)  {verdict}",
        budget.label,
        icount,
        budget.ceiling,
        icount as f64 / budget.ceiling as f64 * 100.0,
        seconds,
    );
    if icount > budget.ceiling {
        failures.push(format!(
            "{}: {icount} instructions over a budget of {} (measured {} when set)",
            budget.label, budget.ceiling, budget.measured
        ));
    }
}

#[test]
fn startup_budgets_are_met() {
    // Every-host anchors, from in-repo fixtures.
    let anchors: &[(Budget, &str, &[&str], i32)] = &[
        (
            // A static binary that prints and exits. This is the floor: if it
            // is not tens of instructions, the loader has started doing work
            // that startup should not.
            Budget {
                label: "static hello: start to exit",
                ceiling: 100,
                measured: 23,
            },
            "hello_linux.elf",
            &[],
            0,
        ),
        (
            // Reading a couple of /proc files, which is what a runtime does
            // before it runs a line.
            Budget {
                label: "read /proc and exit",
                ceiling: 6_000,
                measured: 2_922,
            },
            "test_procfs.elf",
            &[],
            0,
        ),
    ];

    let mut failures = Vec::new();
    for (budget, fixture, argv, code) in anchors {
        let Some((icount, seconds)) = run_fixture(fixture, argv, *code) else {
            panic!("in-repo fixture {fixture} is missing; the budget gate cannot run");
        };
        check(budget, icount, seconds, &mut failures);
    }

    // Richer workloads, from busybox. Fixture-gated, so this half is real on
    // a host that has it and skips on one that does not — the anchors above
    // still gate on every host.
    if let Some(image) = busybox() {
        let bb: &[(Budget, &[&str])] = &[
            (
                Budget {
                    label: "busybox startup (true)",
                    ceiling: 6_000,
                    measured: 2_713,
                },
                &["true"],
            ),
            (
                Budget {
                    label: "busybox ls /",
                    ceiling: 120_000,
                    measured: 73_280,
                },
                &["ls", "/"],
            ),
            (
                Budget {
                    label: "busybox sh: 20x fork/exec",
                    ceiling: 640_000,
                    measured: 532_845,
                },
                &[
                    "sh",
                    "-c",
                    "i=0; while [ $i -lt 20 ]; do busybox true; i=$((i+1)); done",
                ],
            ),
        ];
        for (budget, argv) in bb {
            let (icount, seconds) = run_busybox(&image, argv);
            check(budget, icount, seconds, &mut failures);
        }
    } else {
        println!("[budget] busybox workloads skipped (fixture absent); anchors still gated");
    }

    assert!(
        failures.is_empty(),
        "{} workload(s) over budget:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}
