//! JIT coverage histogram: run a guest ELF, profile the blocks it executes, and
//! report what fraction of that executed work the translator handles whole and,
//! for what it does not, which op and width bailed.
//!
//! The answer is weighted by execution (`entries * instructions`), so it is
//! about the hot path, not the static op count — which is what says whether the
//! JIT is worth more coverage, and where to spend it.
//!
//! Usage: jit_coverage <elf> [args...]
//!
//! Static ELFs need nothing else. A dynamic glibc binary (or Node) needs its
//! loader and libraries delivered as files; mirror run_guest and import them:
//!
//!   GUEST_MOUNT="host_dir:guest_prefix,..."  import host trees (glibc, Node)
//!   GUEST_COPY="host_file:guest_path,..."    copy individual host files
//!   GUEST_EXE=/guest/path                    where to place and load the guest
//!   GUEST_ENV="K=V,K=V"                       extra environment for the guest
//!   GUEST_MEM_MB=N                            raise the physical-memory cap
//!   GUEST_ARGV0=name                          argv[0] the guest sees (multicall)

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

    // GUEST_MEM_MB=N raises the guest's physical-memory cap (default 1 GiB).
    // A dynamic runtime (loader + shared libraries, plus copy-on-write pages of
    // a fork-heavy program like Node) can exceed the default.
    if let Ok(mb) = std::env::var("GUEST_MEM_MB") {
        let mb: usize = mb.parse().expect("GUEST_MEM_MB must be a number");
        let pages = mb.saturating_mul(256); // 4 KiB pages
        assert!(
            machine.vm_mut().cpu.mem.set_capacity(pages),
            "cannot shrink below allocated pages"
        );
    }

    // A dynamic glibc program (and Node) reads the clock; give it the host's
    // real wall clock rather than the fixed reproducible default so libc's
    // start-up does not trip over an implausible time.
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("host clock before unix epoch")
        .as_secs() as i64;
    machine.set_wall_clock_base(epoch);

    // GUEST_MOUNT="host_dir:guest_prefix,host_dir:guest_prefix" imports host
    // trees (the glibc runtime, a Node install) into the guest. This is what a
    // dynamic binary needs — its loader and libraries delivered as files.
    if let Ok(mounts) = std::env::var("GUEST_MOUNT") {
        for entry in mounts.split(',').filter(|e| !e.is_empty()) {
            let (host, guest) = entry.split_once(':').expect("GUEST_MOUNT host:guest");
            machine
                .add_host_tree(std::path::Path::new(host), guest)
                .unwrap_or_else(|e| panic!("mount {host} -> {guest}: {e}"));
        }
    }
    // GUEST_COPY="host_file:guest_path,..." copies individual host files.
    if let Ok(copies) = std::env::var("GUEST_COPY") {
        for entry in copies.split(',').filter(|e| !e.is_empty()) {
            let (host, guest) = entry.split_once(':').expect("GUEST_COPY host:guest");
            let bytes = std::fs::read(host).unwrap_or_else(|e| panic!("read {host}: {e}"));
            machine
                .add_file(guest.as_bytes(), bytes, 0o755)
                .expect("copy");
        }
    }

    // GUEST_EXE controls where the binary is placed inside the guest and which
    // path is loaded. Defaults to /bin/guest, preserving the static behaviour.
    let guest_exe = std::env::var("GUEST_EXE").unwrap_or_else(|_| "/bin/guest".to_string());
    let image = std::fs::read(&args[0]).expect("read elf");
    machine
        .add_file(guest_exe.as_bytes(), image, 0o755)
        .expect("add guest");
    // argv[0] the guest sees. Defaults to the guest exe path; GUEST_ARGV0
    // overrides it, which a multicall binary like BusyBox needs (its applet is
    // chosen by argv[0]'s basename, so run it as `GUEST_ARGV0=busybox ...`).
    let argv0 = std::env::var("GUEST_ARGV0").unwrap_or_else(|_| guest_exe.clone());
    let mut argv: Vec<Vec<u8>> = vec![argv0.into_bytes()];
    argv.extend(args[1..].iter().map(|a| a.as_bytes().to_vec()));
    let mut envp: Vec<Vec<u8>> = vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()];
    if let Ok(extra) = std::env::var("GUEST_ENV") {
        envp.extend(extra.split(',').map(|kv| kv.as_bytes().to_vec()));
    }
    machine.set_args(argv, envp);
    machine.load(guest_exe.as_bytes()).expect("load");

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
    println!(
        "  of that, self-loop (region): {:.1}%   non-self-loop (trace target): {:.1}%",
        pct(cov.covered_self_loop_insns),
        pct(cov.covered_chain_insns),
    );
    println!(
        "  of the non-self-loop, in a looping trace (selector reach): {:.1}% of all",
        pct(cov.covered_trace_insns),
    );
    println!("  non-self-loop exit shapes (share of all executed insns):");
    for (kind, weight) in cov.chain_exits.iter().take(10) {
        println!("    {kind:<22} {:5.1}%", pct(*weight));
    }
    if cov.chain_dispatches > 0 {
        println!(
            "  non-self-loop dispatch granularity: {:.1} guest insns per jit_call (avg over {} dispatches)",
            cov.covered_chain_insns as f64 / cov.chain_dispatches as f64,
            cov.chain_dispatches,
        );
        let dtot: u64 = cov.chain_dispatch_sizes.iter().map(|(_, v)| v).sum();
        for (bucket, count) in &cov.chain_dispatch_sizes {
            let share = if dtot == 0 {
                0.0
            } else {
                100.0 * *count as f64 / dtot as f64
            };
            println!("    block size {bucket:<6} {share:5.1}% of dispatches");
        }
    }
    println!("bail causes (op@width, share of executed insns):");
    for (cause, weight) in cov.bails.iter().take(20) {
        println!("  {cause:<26} {:5.1}%", pct(*weight));
    }
}
