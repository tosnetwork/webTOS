//! Throughput and memory measurements, not gates.
//!
//! These print numbers rather than asserting on them: what the interpreter
//! costs varies with the host, and a test that fails because a laptop was
//! busy teaches nothing. They exist so the browser figures from
//! `web/bench.mjs` have a native reference — the same guest workloads, the
//! same instruction counts, measured the same way.
//!
//! Run with:  cargo test -p linux-compat --release --test bench -- --ignored --nocapture

use std::path::PathBuf;
use std::time::Instant;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn busybox() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    std::fs::read(&path).ok().or_else(|| {
        eprintln!(
            "skipping: {} missing (tools/fetch_busybox.sh)",
            path.display()
        );
        None
    })
}

/// Deterministic bytes: a compressible pattern would make the compute
/// measurement depend on the data rather than the instruction stream.
fn payload(len: usize) -> Vec<u8> {
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

struct Measured {
    icount: u64,
    seconds: f64,
    output: String,
}

impl Measured {
    fn report(&self, label: &str) {
        println!(
            "[bench] {label:<28} {:>13} instructions  {:>7.2} s  {:>8.1} M inst/s",
            self.icount,
            self.seconds,
            self.icount as f64 / self.seconds / 1e6,
        );
    }
}

fn measure(argv: &[&str], extra: &[(&[u8], Vec<u8>)]) -> Option<Measured> {
    let image = busybox()?;
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("add busybox");
    for (path, bytes) in extra {
        machine
            .add_file(path, bytes.clone(), 0o644)
            .expect("add fixture");
    }
    let mut args: Vec<Vec<u8>> = vec![b"busybox".to_vec()];
    args.extend(argv.iter().map(|a| a.as_bytes().to_vec()));
    machine.set_args(args, vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()]);
    machine.load(b"/bin/busybox").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 40_000_000_000;

    let before = machine.icount();
    let start = Instant::now();
    let exit = machine.run();
    let seconds = start.elapsed().as_secs_f64();
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "workload failed");
    Some(Measured {
        icount: machine.icount() - before,
        seconds,
        output: String::from_utf8_lossy(&machine.take_output()).into_owned(),
    })
}

#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture"]
fn bench_machine_build() {
    if busybox().is_none() {
        return;
    }
    let start = Instant::now();
    let machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    println!(
        "[bench] {:<28} {:>7.2} s (SLEIGH specification compiled)",
        "machine build",
        start.elapsed().as_secs_f64()
    );
    drop(machine);
}

/// Compute-bound: hashing runs a tight instruction loop with almost no
/// syscalls, so this is the interpreter's raw throughput.
#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture"]
fn bench_compute_md5sum() {
    let mut points = Vec::new();
    for mb in [1, 4] {
        let data = payload(mb * 1024 * 1024);
        let Some(run) = measure(&["md5sum", "/root/data.bin"], &[(b"/root/data.bin", data)]) else {
            return;
        };
        assert!(run.output.contains(' '), "md5sum printed nothing");
        run.report(&format!("md5sum {mb} MiB"));
        points.push(run);
    }
    // Each run pays once to lift the blocks it touches and once to start the
    // process. The difference between two sizes of the same workload cancels
    // both, leaving what the interpreter sustains once it is warm — the
    // number that says how an interactive session will feel.
    let (small, large) = (&points[0], &points[1]);
    let instructions = large.icount - small.icount;
    let seconds = large.seconds - small.seconds;
    println!(
        "[bench] {:<28} {:>13} instructions  {:>7.2} s  {:>8.1} M inst/s (fixed cost removed)",
        "md5sum marginal",
        instructions,
        seconds,
        instructions as f64 / seconds / 1e6,
    );
}

/// Syscall- and process-bound: a shell pipeline forks, execs, and moves bytes
/// through pipes. Its instruction count is tiny and its wall time is not, so
/// what it measures is the cost of lifting each new image's blocks — time
/// that never appears in an instruction count.
#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture"]
fn bench_process_pipeline() {
    let Some(run) = measure(
        &[
            "sh",
            "-c",
            "for i in 1 2 3 4 5; do echo $i | /bin/busybox cat; done",
        ],
        &[],
    ) else {
        return;
    };
    run.report("shell pipeline x5");
}

/// What a first process costs before it runs any of its own code.
#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture"]
fn bench_process_startup() {
    let Some(run) = measure(&["true"], &[]) else {
        return;
    };
    run.report("busybox true");
}

/// How much guest physical memory a workload actually touches, against the
/// cap. A browser tab has a smaller budget than a workstation, so the number
/// that matters is what a real workload needs, not what the engine allows.
#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture"]
fn bench_guest_memory_footprint() {
    let Some(image) = busybox() else {
        return;
    };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("add busybox");
    machine.set_args(
        vec![
            b"busybox".to_vec(),
            b"sh".to_vec(),
            b"-c".to_vec(),
            b"echo hi".to_vec(),
        ],
        vec![b"PATH=/bin".to_vec()],
    );
    machine.load(b"/bin/busybox").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    machine.run();
    let (used, cap) = machine.guest_memory_mb();
    println!(
        "[bench] {:<28} {used} MiB used of a {cap} MiB cap",
        "shell startup footprint"
    );
}
