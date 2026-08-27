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
/// What an `execve` costs when the image is already in memory and its blocks
/// have already been lifted by another process.
///
/// The shell here *is* BusyBox and so is every command it runs, so by the
/// time the first `/bin/true` starts, every block of its startup path has
/// been lifted once already. It is re-lifted anyway: `fork` and `execve` each
/// take a fresh address-space id, and the block cache keys on that, so the
/// work is repeated per process. The marginal figure below is the size of
/// that repetition — compare its instructions-per-second against the
/// sustained rate from `bench_compute_md5sum` on the same machine.
#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture"]
fn bench_execve_relift_cost() {
    let Some(image) = busybox() else {
        return;
    };
    let mut points = Vec::new();
    for execs in [1_usize, 16] {
        let mut machine = Machine::from_ldef(&ldef_path(), &EngineConfig::default())
            .expect("machine build failed");
        machine
            .add_file(b"/bin/busybox", image.clone(), 0o755)
            .expect("add busybox");
        for applet in ["sh", "true"] {
            machine
                .add_symlink(format!("/bin/{applet}").as_bytes(), b"/bin/busybox")
                .expect("applet link");
        }
        let script = format!("i=0; while [ $i -lt {execs} ]; do /bin/true; i=$((i+1)); done");
        machine.set_args(
            vec![b"sh".to_vec(), b"-c".to_vec(), script.into_bytes()],
            vec![b"PATH=/bin".to_vec()],
        );
        machine.load(b"/bin/sh").expect("ELF load failed");
        machine.vm_mut().icount_limit = machine.icount() + 40_000_000_000;

        let before = machine.icount();
        let start = Instant::now();
        let exit = machine.run();
        let seconds = start.elapsed().as_secs_f64();
        assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "shell loop failed");
        let run = Measured {
            icount: machine.icount() - before,
            seconds,
            output: String::new(),
        };
        run.report(&format!("shell + {execs} execs"));
        points.push(run);
    }

    let (one, many) = (&points[0], &points[1]);
    let instructions = many.icount - one.icount;
    let seconds = many.seconds - one.seconds;
    let each = 15.0;
    println!(
        "[bench] {:<28} {:>13} instructions  {:>7.2} s  {:>8.1} M inst/s (per extra execve: {:.0} instructions, {:.1} ms)",
        "execve marginal",
        instructions,
        seconds,
        instructions as f64 / seconds / 1e6,
        instructions as f64 / each,
        seconds * 1000.0 / each,
    );
}

/// The same image loaded again into a live machine. Each load takes a fresh
/// address space, so nothing is found under the previous one's key; the win
/// here comes from the content-addressed lift cache recognising the bytes.
#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture"]
fn bench_reload_same_image() {
    let Some(image) = busybox() else {
        return;
    };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("add busybox");
    for run in 0..4 {
        machine.set_args(
            vec![b"busybox".to_vec(), b"true".to_vec()],
            vec![b"PATH=/bin".to_vec()],
        );
        machine.load(b"/bin/busybox").expect("ELF load failed");
        machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
        let start = Instant::now();
        let exit = machine.run();
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(exit, CpuExit::Halt { code: Some(0) });
        println!(
            "[bench] {:<28} load {run}: {ms:>7.1} ms",
            "reload same image"
        );
    }
}

/// Where a workload's time actually goes, per basic block.
///
/// Milestone 8's first work item is to "profile executed blocks and translate
/// only proven hot paths". This is the profiling half. It reports how
/// concentrated execution is, because that number decides whether a
/// translator is worth building: if a handful of blocks account for most of
/// the retired instructions, translating them is cheap and the payoff is
/// large; if the distribution is flat, a translator has to cover most of the
/// program before it earns anything.
#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture"]
fn bench_block_hotness() {
    let Some(image) = busybox() else {
        return;
    };
    for (label, argv) in [
        ("busybox ls /bin", vec!["busybox", "ls", "/bin"]),
        (
            "sh loop (100 iterations)",
            vec![
                "busybox",
                "sh",
                "-c",
                "i=0; while [ $i -lt 100 ]; do i=$((i+1)); done",
            ],
        ),
        ("md5sum 1 MiB", vec!["busybox", "md5sum", "/root/data.bin"]),
    ] {
        let mut machine = Machine::from_ldef(&ldef_path(), &EngineConfig::default())
            .expect("machine build failed");
        machine
            .add_file(b"/bin/busybox", image.clone(), 0o755)
            .expect("add busybox");
        machine
            .add_file(b"/root/data.bin", payload(1024 * 1024), 0o644)
            .expect("add payload");
        machine.set_args(
            argv.iter().map(|a| a.as_bytes().to_vec()).collect(),
            vec![b"PATH=/bin".to_vec()],
        );
        machine.load(b"/bin/busybox").expect("ELF load failed");
        machine.vm_mut().profile_blocks(true);
        machine.vm_mut().icount_limit = machine.icount() + 40_000_000_000;
        let exit = machine.run();
        assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{label} failed");

        let profile = machine
            .vm_mut()
            .block_profile()
            .expect("profiling was enabled");
        // Weight by work done, not by how often a block was entered: a short
        // block entered often is not the same target as a long one.
        let mut blocks: Vec<(u64, u64)> = profile
            .iter()
            .map(|(&addr, p)| (addr, p.entries.saturating_mul(p.instructions)))
            .collect();
        blocks.sort_by_key(|(_, work)| std::cmp::Reverse(*work));
        let total: u64 = blocks.iter().map(|(_, work)| work).sum();
        if total == 0 {
            continue;
        }
        let coverage = |fraction: f64| {
            let target = (total as f64 * fraction) as u64;
            let mut sum = 0_u64;
            for (i, (_, work)) in blocks.iter().enumerate() {
                sum += work;
                if sum >= target {
                    return i + 1;
                }
            }
            blocks.len()
        };
        println!(
            "[bench] {:<28} {:>6} blocks executed; {:>4} cover 50%, {:>4} cover 90%, {:>5} cover 99%",
            label,
            blocks.len(),
            coverage(0.5),
            coverage(0.9),
            coverage(0.99),
        );
        let top: String = blocks
            .iter()
            .take(3)
            .map(|(addr, work)| format!("{addr:#x}={:.0}%", *work as f64 * 100.0 / total as f64))
            .collect::<Vec<_>>()
            .join(" ");
        println!("[bench] {:<28} hottest: {top}", "");
    }
}

/// The measurement that decides what milestone 8 should build.
///
/// A real agent binary starting up is the workload that matters, and it is
/// nothing like a hot loop. This runs the same invocation three times in one
/// machine: the first pays to lift every block it touches, the rest find them
/// already lifted. The gap between them is the share of a cold start that is
/// translation rather than execution — and the block distribution alongside
/// says whether a selective translator could ever capture it.
///
/// Needs `tools/build_openfox_fixture.sh`; skips without it.
#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture"]
fn bench_agent_startup_is_lifting() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/openfox");
    let Ok(image) = std::fs::read(&path) else {
        eprintln!(
            "skipping: {} missing (tools/build_openfox_fixture.sh)",
            path.display()
        );
        return;
    };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/openfox", image, 0o755)
        .expect("add openfox");
    machine.vm_mut().profile_blocks(true);

    let mut cold = 0.0_f64;
    let mut warm = 0.0_f64;
    for run in 0..3 {
        machine.set_args(
            vec![b"openfox".to_vec(), b"--help".to_vec()],
            vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()],
        );
        machine.load(b"/bin/openfox").expect("ELF load failed");
        machine.vm_mut().icount_limit = machine.icount() + 40_000_000_000;
        let before = machine.icount();
        let start = Instant::now();
        let exit = machine.run();
        let seconds = start.elapsed().as_secs_f64();
        let instructions = machine.icount() - before;
        machine.take_output();
        assert_eq!(
            exit,
            CpuExit::Halt { code: Some(0) },
            "openfox --help failed"
        );
        println!(
            "[bench] {:<28} run {run}: {instructions} instructions  {seconds:>6.2} s  {:>6.1} M inst/s",
            "agent --help",
            instructions as f64 / seconds / 1e6,
        );
        if run == 0 {
            cold = seconds;
        } else {
            warm = seconds;
        }
    }
    println!(
        "[bench] {:<28} {:.0}% of a cold start is lifting, not executing",
        "agent startup",
        (cold - warm) * 100.0 / cold,
    );

    let profile = machine
        .vm_mut()
        .block_profile()
        .expect("profiling was enabled");
    let mut blocks: Vec<u64> = profile
        .values()
        .map(|p| p.entries.saturating_mul(p.instructions))
        .collect();
    blocks.sort_unstable_by_key(|work| std::cmp::Reverse(*work));
    let total: u64 = blocks.iter().sum();
    let coverage = |fraction: f64| {
        let target = (total as f64 * fraction) as u64;
        let mut sum = 0_u64;
        for (i, work) in blocks.iter().enumerate() {
            sum += work;
            if sum >= target {
                return i + 1;
            }
        }
        blocks.len()
    };
    println!(
        "[bench] {:<28} {} blocks executed; {} cover 50%, {} cover 90%, {} cover 99%",
        "agent block spread",
        blocks.len(),
        coverage(0.5),
        coverage(0.9),
        coverage(0.99),
    );
}
