//! JIT coverage histogram: run a guest ELF, profile the blocks it executes, and
//! report what fraction of that executed work the translator handles whole and,
//! for what it does not, which op and width bailed.
//!
//! The answer is weighted by execution (`entries * instructions`), so it is
//! about the hot path, not the static op count — which is what says whether the
//! JIT is worth more coverage, and where to spend it.
//!
//! Usage: jit_coverage <elf> [args...]

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: jit_coverage <elf> [args...]");
        std::process::exit(2);
    }
    let ldef = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs");
    let mut machine = Machine::from_ldef(&ldef, &EngineConfig::default()).expect("build machine");

    let image = std::fs::read(&args[0]).expect("read elf");
    machine
        .add_file(b"/bin/guest", image, 0o755)
        .expect("add guest");
    // argv[0] the guest sees. Defaults to its path; GUEST_ARGV0 overrides it,
    // which a multicall binary like BusyBox needs (its applet is chosen by
    // argv[0]'s basename, so run it as `GUEST_ARGV0=busybox ... sha256sum f`).
    let argv0 = std::env::var("GUEST_ARGV0").unwrap_or_else(|_| "/bin/guest".to_string());
    let mut argv: Vec<Vec<u8>> = vec![argv0.into_bytes()];
    argv.extend(args[1..].iter().map(|a| a.as_bytes().to_vec()));
    machine.set_args(argv, vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()]);
    machine.load(b"/bin/guest").expect("load");

    machine.profile_blocks(true);
    machine.vm_mut().icount_limit = 50_000_000_000;
    loop {
        let exit = machine.run();
        // A normal guest returns a terminal exit; only a breakpoint asks to
        // resume, and none are set here.
        if !matches!(exit, CpuExit::Breakpoint { .. }) {
            eprintln!("[coverage] guest stopped: {exit:?}");
            break;
        }
    }

    let cov = machine.jit_coverage().expect("profiling was on");
    let pct = |n: u64| {
        if cov.hot_insns == 0 {
            0.0
        } else {
            100.0 * n as f64 / cov.hot_insns as f64
        }
    };

    println!("profiled hot blocks:          {}", cov.blocks);
    println!("weighted executed insns:      {}", cov.hot_insns);
    println!(
        "translate whole (JIT-able):   {:.1}%  ({} of {})",
        pct(cov.covered_insns),
        cov.covered_insns,
        cov.hot_insns
    );
    println!("bail causes (op@width, share of executed insns):");
    for (cause, weight) in cov.bails.iter().take(20) {
        println!("  {cause:<26} {:5.1}%", pct(*weight));
    }
}
