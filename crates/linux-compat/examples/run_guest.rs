//! Debug runner: execute an ELF from the host filesystem inside the machine.
//! Usage: run_guest <elf> [args...] (env: GUEST_ENV="K=V,K=V")

use std::cell::RefCell;
use std::rc::Rc;

use linux_compat::net::NativeBroker;
use linux_compat::Machine;
use x64_engine::EngineConfig;

/// Expands `\n`, `\r`, `\t`, `\xNN`, and `\\` in a terminal-input script.
fn unescape(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chars = s.bytes().peekable();
    while let Some(b) = chars.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match chars.next() {
            Some(b'n') => out.push(b'\n'),
            Some(b'r') => out.push(b'\r'),
            Some(b't') => out.push(b'\t'),
            Some(b'\\') => out.push(b'\\'),
            Some(b'x') => {
                let hi = chars.next().unwrap_or(b'0');
                let lo = chars.next().unwrap_or(b'0');
                let hex = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
                out.push(hex(hi) << 4 | hex(lo));
            }
            Some(other) => {
                out.push(b'\\');
                out.push(other);
            }
            None => out.push(b'\\'),
        }
    }
    out
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let ldef = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs");
    let mut machine = Machine::from_ldef(&ldef, &EngineConfig::default()).expect("build");

    // GUEST_MEM_MB=N raises the guest's physical-memory cap (default 1 GiB).
    // Large workloads (a package download landing in the in-memory fs, plus
    // copy-on-write pages of a fork-heavy runtime) can exceed the default.
    if let Ok(mb) = std::env::var("GUEST_MEM_MB") {
        let mb: usize = mb.parse().expect("GUEST_MEM_MB must be a number");
        let pages = mb.saturating_mul(256); // 4 KiB pages
        assert!(
            machine.vm_mut().cpu.mem.set_capacity(pages),
            "cannot shrink below allocated pages"
        );
    }

    // The debug runner talks to real services (TLS certificates, tokens), so
    // give the guest the host's actual wall clock instead of the fixed
    // reproducible default. GUEST_EPOCH=<unix_sec> overrides it explicitly.
    let epoch = match std::env::var("GUEST_EPOCH") {
        Ok(sec) => sec.parse().expect("GUEST_EPOCH must be unix seconds"),
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("host clock before unix epoch")
            .as_secs() as i64,
    };
    machine.set_wall_clock_base(epoch);

    // GUEST_NET=1 attaches an allow-all native broker (real host outbound) and
    // a resolv.conf pointing at a public resolver, so the guest can do real
    // DNS + TCP. Without it, sockets are denied by default.
    if std::env::var("GUEST_NET").is_ok() {
        machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
        let _ = machine.add_file(b"/etc/resolv.conf", b"nameserver 8.8.8.8\n".to_vec(), 0o644);
    }

    // GUEST_MOUNT="host_dir:guest_prefix,host_dir:guest_prefix" imports host
    // trees (e.g. the glibc runtime, a Node install) into the guest.
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

    let image = std::fs::read(&args[0]).expect("read elf");
    let guest_exe = std::env::var("GUEST_EXE").unwrap_or_else(|_| "/bin/guest".to_string());
    machine
        .add_file(guest_exe.as_bytes(), image, 0o755)
        .expect("add");
    let mut argv: Vec<Vec<u8>> = vec![guest_exe.as_bytes().to_vec()];
    argv.extend(args[1..].iter().map(|a| a.as_bytes().to_vec()));
    let mut envp: Vec<Vec<u8>> = vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()];
    if let Ok(extra) = std::env::var("GUEST_ENV") {
        envp.extend(extra.split(',').map(|kv| kv.as_bytes().to_vec()));
    }
    machine.set_args(argv, envp);
    machine.load(guest_exe.as_bytes()).expect("load");

    // GUEST_PTY=1 runs the guest on an interactive terminal (stdin/stdout a
    // host-driven pty). GUEST_PTY_INPUT provides the keystrokes to feed
    // (`\n`/`\t`/`\xNN` escapes recognized); rendered output is printed after
    // the run. GUEST_PTY_SIZE=ROWSxCOLS overrides the 40x120 default.
    let pty_stdio = std::env::var_os("GUEST_PTY").is_some();
    if pty_stdio {
        let (rows, cols) = std::env::var("GUEST_PTY_SIZE")
            .ok()
            .and_then(|s| {
                let (r, c) = s.split_once('x')?;
                Some((r.parse().ok()?, c.parse().ok()?))
            })
            .unwrap_or((40u16, 120u16));
        machine.install_pty_stdio(rows, cols);
        if let Ok(script) = std::env::var("GUEST_PTY_INPUT") {
            machine.feed_terminal_input(&unescape(&script));
        }
    }

    machine.vm_mut().icount_limit = std::env::var("GUEST_ICOUNT_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000_000_000);
    // WATCH_GUEST_WRITE=hexaddr: MMU-level write hook on the 8 bytes at
    // that guest address. Every write (guest instruction or host) reports
    // the value and the guest basic block executing at the time.
    if let Ok(spec) = std::env::var("WATCH_GUEST_WRITE") {
        let target = u64::from_str_radix(spec.trim_start_matches("0x"), 16).expect("watch addr");
        machine.vm_mut().cpu.mem.add_write_hook(
            target,
            target + 8,
            Box::new(move |_mem: &mut icicle_mem::Mmu, addr: u64, value: &[u8]| {
                let block =
                    x64_engine::vm::current_block_start();
                let icount =
                    x64_engine::vm::current_icount();
                let pid = linux_compat::current_pid();
                eprintln!(
                    "[guest-watch] pid={pid} ic={icount} write {addr:#x} len={} val={:02x?} in-block={block:#x}",
                    value.len(),
                    &value[..value.len().min(16)]
                );
            }),
        );
    }

    // WATCH_GUEST_READ=hexaddr: MMU read hook on 8 bytes at that guest VA.
    // Reports the value the load returns and the block executing, so a read
    // that returns something other than the byte in memory is visible.
    if let Ok(spec) = std::env::var("WATCH_GUEST_READ") {
        let target = u64::from_str_radix(spec.trim_start_matches("0x"), 16).expect("read addr");
        struct ReadWatch;
        impl icicle_mem::ReadAfterHook for ReadWatch {
            fn read(&mut self, _mem: &mut icicle_mem::Mmu, addr: u64, value: &[u8]) {
                let block = x64_engine::vm::current_block_start();
                let ic = x64_engine::vm::current_icount();
                eprintln!(
                    "[guest-read] ic={ic} read {addr:#x} len={} val={:02x?} in-block={block:#x}",
                    value.len(),
                    &value[..value.len().min(16)]
                );
            }
        }
        machine
            .vm_mut()
            .cpu
            .mem
            .add_read_after_hook(target, target + 8, Box::new(ReadWatch));
    }

    // GUEST_BREAK="hexaddr,hexaddr": single-shot breakpoints. Each hit dumps
    // the GPRs (and FAULT_PEEK targets) and execution continues.
    if let Ok(spec) = std::env::var("GUEST_BREAK") {
        for part in spec.split(',').filter(|p| !p.is_empty()) {
            let addr = u64::from_str_radix(part.trim_start_matches("0x"), 16).expect("GUEST_BREAK");
            machine.vm_mut().code.breakpoints.insert(addr);
        }
    }
    // GUEST_PROFILE=1: count block entries and dump the hottest blocks at
    // exit — the cheapest way to see where a silent guest actually spins.
    let profile = std::env::var_os("GUEST_PROFILE").is_some();
    if profile {
        machine.vm_mut().profile_blocks(true);
    }
    let exit = loop {
        let exit = machine.run();
        let x64_engine::CpuExit::Breakpoint { rip } = exit else {
            break exit;
        };
        {
            let vm = machine.vm_mut();
            // Sticky breakpoints (BREAK_STICKY=1) stay armed and fire on every
            // pass. A DEREF_FILTER=reg only prints a hit when that register
            // points at a would-be-corrupt Rust enum tag (top byte 0x80, low
            // 32 bits > 3), which pinpoints the last dispatch before the jump.
            let sticky = std::env::var_os("BREAK_STICKY").is_some();
            let show = match std::env::var("DEREF_FILTER") {
                Ok(reg) => {
                    let ptr = vm
                        .cpu
                        .arch
                        .sleigh
                        .get_varnode(&reg)
                        .map(|v| vm.cpu.read_reg(v))
                        .unwrap_or(0);
                    let mut buf = [0u8; 8];
                    let _ = vm.cpu.mem.read_bytes(ptr, &mut buf, icicle_mem::perm::NONE);
                    let low = u32::from_le_bytes(buf[..4].try_into().unwrap());
                    buf[7] == 0x80 && low > 3
                }
                Err(_) => true,
            };
            if !sticky {
                vm.code.breakpoints.remove(&rip);
            }
            if !show {
                continue;
            }
            let mut regs = String::new();
            for name in [
                "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11",
                "R12", "R13", "R14", "R15",
            ] {
                if let Some(var) = vm.cpu.arch.sleigh.get_varnode(name) {
                    regs.push_str(&format!("{name}={:#x} ", vm.cpu.read_reg(var)));
                }
            }
            eprintln!("[runner] breakpoint rip={rip:#x} {regs}");
            // Dump the 16 bytes each named register points at, to see what a
            // dereference like `mov (%rdi),...` actually reads.
            if let Ok(regspec) = std::env::var("BREAK_DEREF") {
                for name in regspec.split(',').filter(|p| !p.is_empty()) {
                    if let Some(var) = vm.cpu.arch.sleigh.get_varnode(name) {
                        let ptr: u64 = vm.cpu.read_reg(var);
                        let mut buf = [0u8; 16];
                        let _ = vm.cpu.mem.read_bytes(ptr, &mut buf, icicle_mem::perm::NONE);
                        let hex: String = buf.iter().map(|b| format!("{b:02x} ")).collect();
                        eprintln!("[runner]   [{name}={ptr:#x}]: {hex}");
                    }
                }
            }
            if let Ok(spec) = std::env::var("FAULT_PEEK") {
                for part in spec.split(',').filter(|p| !p.is_empty()) {
                    let addr = u64::from_str_radix(part.trim_start_matches("0x"), 16).unwrap_or(0);
                    let mut buf = [0u8; 16];
                    let _ = vm
                        .cpu
                        .mem
                        .read_bytes(addr, &mut buf, icicle_mem::perm::NONE);
                    let hex: String = buf.iter().map(|b| format!("{b:02x} ")).collect();
                    eprintln!("[runner] peek {addr:#x}: {hex}");
                }
            }
        }
    };
    let output = machine.take_output();
    print!("{}", String::from_utf8_lossy(&output));
    if pty_stdio {
        let rendered = machine.drain_terminal_output();
        print!("{}", String::from_utf8_lossy(&rendered));
    }
    if !matches!(exit, x64_engine::CpuExit::Halt { code: Some(0) }) {
        let (exe, pid) = machine.current_task();
        let vm = machine.vm_mut();
        let rip = vm.cpu.read_pc();
        let rsp: u64 = vm
            .cpu
            .arch
            .sleigh
            .get_varnode("RSP")
            .map(|v| vm.cpu.read_reg(v))
            .unwrap_or(0);
        let mut buf = [0u8; 16];
        let _ = vm.cpu.mem.read_bytes(rip, &mut buf, icicle_mem::perm::NONE);
        let hex: String = buf.iter().map(|b| format!("{b:02x} ")).collect();
        eprintln!("[runner] fault pid={pid} exe={exe} rip={rip:#x} rsp={rsp:#x} bytes: {hex}");
        // What the faulting page is actually mapped as. A jump into a page
        // the loader left non-executable and a jump into nothing at all look
        // identical from the exception alone.
        {
            use icicle_mem::perm;
            let page = rip & !0xfff;
            let mut one = [0u8; 1];
            let readable = vm.cpu.mem.read_bytes(rip, &mut one, perm::READ).is_ok();
            let executable = vm.cpu.mem.read_bytes(rip, &mut one, perm::EXEC).is_ok();
            let mapped = vm.cpu.mem.mapping.get_range((page, page)).is_some();
            eprintln!(
                "[runner]   page {page:#x}: mapped={mapped} readable={readable} executable={executable}"
            );
        }
        eprintln!(
            "[runner] syscall trail (pid:nr@icount): {}",
            machine.syscall_trail().join(" ")
        );
        // FAULT_STACK=N prints N qwords from the faulting RSP, flagging
        // values that look like return addresses into the program image.
        if let Ok(n) = std::env::var("FAULT_STACK") {
            let n: u64 = n.parse().unwrap_or(64);
            let vm = machine.vm_mut();
            for i in 0..n {
                let addr = rsp + i * 8;
                let mut buf = [0u8; 8];
                if vm
                    .cpu
                    .mem
                    .read_bytes(addr, &mut buf, icicle_mem::perm::NONE)
                    .is_err()
                {
                    break;
                }
                let v = u64::from_le_bytes(buf);
                if (0x1000..0x1000_0000).contains(&v) {
                    eprintln!("[runner] stack[{i:>3}] {addr:#x}: {v:#x} <- code?");
                }
            }
        }
        // FAULT_PEEK="addr,addr" prints 16 bytes at each hex address.
        if let Ok(spec) = std::env::var("FAULT_PEEK") {
            let vm = machine.vm_mut();
            for part in spec.split(',').filter(|p| !p.is_empty()) {
                let addr = u64::from_str_radix(part.trim_start_matches("0x"), 16).unwrap_or(0);
                let mut buf = [0u8; 16];
                let _ = vm
                    .cpu
                    .mem
                    .read_bytes(addr, &mut buf, icicle_mem::perm::NONE);
                let hex: String = buf.iter().map(|b| format!("{b:02x} ")).collect();
                eprintln!("[runner] peek {addr:#x}: {hex}");
            }
        }
    }
    eprintln!("[runner] exit={exit:?} icount={}", machine.icount());
    if profile {
        if let Some(blocks) = machine.vm_mut().block_profile() {
            let mut hot: Vec<_> = blocks
                .iter()
                .map(|(addr, p)| {
                    (
                        p.entries.saturating_mul(p.instructions.max(1)),
                        *addr,
                        p.entries,
                    )
                })
                .collect();
            hot.sort_unstable_by(|a, b| b.0.cmp(&a.0));
            eprintln!("[profile] hottest blocks (weight = entries x instructions):");
            for (weight, addr, entries) in hot.iter().take(30) {
                eprintln!("[profile]   {addr:#x} weight={weight} entries={entries}");
            }
        }
    }
}
