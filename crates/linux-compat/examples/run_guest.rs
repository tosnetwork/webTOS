//! Debug runner: execute an ELF from the host filesystem inside the machine.
//! Usage: run_guest <elf> [args...] (env: GUEST_ENV="K=V,K=V")

use std::{
    cell::RefCell,
    collections::VecDeque,
    io::{Read as _, Write as _},
    rc::Rc,
};

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
    // GUEST_NO_PCODE_OPT=1 is a diagnostic parity switch: it leaves the
    // decoder and guest ABI unchanged, but runs the exact workload without
    // instruction/block p-code rewrites.  It is useful when a generated
    // runtime fails only after it has emitted self-modifying native code.
    let config = if std::env::var_os("GUEST_NO_PCODE_OPT").is_some() {
        EngineConfig {
            optimize_instructions: false,
            optimize_block: false,
            ..EngineConfig::default()
        }
    } else {
        EngineConfig::default()
    };
    let mut machine = Machine::from_ldef(&ldef, &config).expect("build");

    // GUEST_MEM_MB=N sets the guest's physical-memory cap (default 2 GiB).
    // The cap is lazy: it reserves no host memory up front. A modern agent
    // CLI can fork several helpers while its language runtime holds a large
    // JIT heap, which exceeds the engine's conservative 1 GiB default before
    // the child has even built its exec stack. Hosts needing a tighter limit
    // can still select it explicitly through GUEST_MEM_MB.
    let mb: usize = std::env::var("GUEST_MEM_MB").map_or(2048, |value| {
        value.parse().expect("GUEST_MEM_MB must be a number")
    });
    let pages = mb.saturating_mul(256); // 4 KiB pages
    assert!(
        machine.vm_mut().cpu.mem.set_capacity(pages),
        "cannot shrink below allocated pages"
    );

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

    // GUEST_NET=1 attaches an allow-all native broker (real host outbound)
    // and imports the host resolver configuration, so the guest follows the
    // same local stub/DNS policy as a native CLI. GUEST_RESOLV_CONF can
    // select an explicit configuration; a public resolver is only the
    // fallback for hosts with no resolv.conf. Without GUEST_NET, sockets are
    // denied by default.
    if std::env::var("GUEST_NET").is_ok() {
        machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
        let resolv_conf = std::env::var_os("GUEST_RESOLV_CONF")
            .map(std::path::PathBuf::from)
            .map_or_else(
                || std::fs::read("/etc/resolv.conf"),
                |path| std::fs::read(path),
            )
            .unwrap_or_else(|_| b"nameserver 8.8.8.8\n".to_vec());
        let _ = machine.add_file(b"/etc/resolv.conf", resolv_conf, 0o644);
        // A native network run must provide a trust anchor as well as a
        // resolver. Copy only the public CA bundle (rather than a broad
        // /etc mount) so TLS clients can initialize without exposing host
        // credentials or unrelated configuration to the guest.
        if let Ok(ca_bundle) = std::fs::read("/etc/ssl/certs/ca-certificates.crt") {
            let _ = machine.add_file(b"/etc/ssl/certs/ca-certificates.crt", ca_bundle, 0o644);
        }
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

    // A packaged CLI can re-exec `/proc/self/exe` to start workers, or derive
    // its front-end mode from `argv[0]`. Mapping every host executable to
    // `/bin/guest` fabricates that identity; canonicalizing the supplied path
    // is also wrong for a launcher symlink such as `claude`, because native
    // exec preserves the invocation spelling in argv[0]. Canonicalize only
    // for reading the image and preserve the supplied guest entry path by
    // default. Callers can still select an explicit synthetic path with
    // GUEST_EXE when that is intentional.
    let host_exe = std::fs::canonicalize(&args[0]).expect("canonicalize elf path");
    let image = std::fs::read(&host_exe).expect("read elf");
    let guest_exe = std::env::var("GUEST_EXE").unwrap_or_else(|_| args[0].clone());
    machine
        .add_file(guest_exe.as_bytes(), image, 0o755)
        .expect("add");
    let mut argv: Vec<Vec<u8>> = vec![guest_exe.as_bytes().to_vec()];
    argv.extend(args[1..].iter().map(|a| a.as_bytes().to_vec()));
    // Match the process' initial VFS working directory. `PWD` is not a
    // kernel authority (getcwd(2) remains authoritative), but runtimes such
    // as Bun use it while resolving their startup directory and expect the
    // conventional shell environment to contain it.
    // GUEST_PTY=1 runs the guest on an interactive terminal (stdin/stdout a
    // host-driven pty). GUEST_PTY_INPUT provides an initial keystroke batch;
    // GUEST_PTY_INPUT_STEPS="first|second" supplies batches only after each
    // guest terminal wait. Both recognize `\n`/`\t`/`\xNN` escapes. Without
    // scripted steps, terminal waits are bridged to the runner's own stdin.
    // GUEST_PTY_SIZE=ROWSxCOLS overrides the 40x120 default.
    let pty_stdio = std::env::var_os("GUEST_PTY").is_some();

    let mut envp: Vec<Vec<u8>> = vec![
        b"PATH=/bin".to_vec(),
        b"HOME=/root".to_vec(),
        b"PWD=/".to_vec(),
    ];
    if pty_stdio {
        // A real interactive session always has TERM exported by the shell;
        // a CLI's TUI entry point (Ink, readline, etc.) treats a missing
        // TERM as "not a real terminal" and falls back to non-interactive
        // mode even though isatty() on the pty fds succeeds.
        envp.push(b"TERM=xterm-256color".to_vec());
    }
    if let Ok(extra) = std::env::var("GUEST_ENV") {
        // Environment lookup is defined by name, but some real runtimes
        // choose the first duplicate entry.  Appending `HOME=/home/guest`
        // after the runner default `HOME=/root` therefore left child
        // processes (including re-execed helpers) rooted at `/root`.  Make
        // GUEST_ENV a true override and reject malformed entries early.
        for kv in extra.split(',') {
            let (key, _) = kv
                .split_once('=')
                .filter(|(key, _)| !key.is_empty())
                .expect("GUEST_ENV entries must be NAME=VALUE");
            envp.retain(|entry| {
                entry
                    .splitn(2, |byte| *byte == b'=')
                    .next()
                    .is_none_or(|existing_key| existing_key != key.as_bytes())
            });
            envp.push(kv.as_bytes().to_vec());
        }
    }
    machine.set_args(argv, envp);
    // Keep the guest principal explicit. A tool such as Claude Code uses
    // getuid(2), not only $HOME, when locating its state and credential
    // directories. The default remains root for hermetic fixtures; a native
    // runner can opt into its intended unprivileged guest identity without
    // granting it any new host authority.
    let guest_uid = std::env::var("GUEST_UID")
        .ok()
        .map(|value| value.parse::<u32>().expect("GUEST_UID must be a u32"))
        .unwrap_or(0);
    let guest_gid = std::env::var("GUEST_GID")
        .ok()
        .map(|value| value.parse::<u32>().expect("GUEST_GID must be a u32"))
        .unwrap_or(0);
    // `getpwuid(3)` is used independently of $HOME by interactive CLIs and
    // their helper processes.  Provide only the declared guest principal,
    // not the host's whole account database.  This preserves the runner's
    // explicit-identity model while letting glibc resolve a non-root home.
    if guest_uid != 0 || guest_gid != 0 || std::env::var_os("GUEST_HOME").is_some() {
        let account = std::env::var("GUEST_ACCOUNT").unwrap_or_else(|_| "guest".to_owned());
        let home = std::env::var("GUEST_HOME").unwrap_or_else(|_| {
            if guest_uid == 0 {
                "/root".to_owned()
            } else {
                format!("/home/{account}")
            }
        });
        let passwd = format!("{account}:x:{guest_uid}:{guest_gid}:{account}:{home}:/bin/sh\n");
        let group = format!("{account}:x:{guest_gid}:\n");
        machine
            .add_file(b"/etc/passwd", passwd.into_bytes(), 0o644)
            .expect("add guest passwd entry");
        machine
            .add_file(b"/etc/group", group.into_bytes(), 0o644)
            .expect("add guest group entry");
    }
    machine.load(guest_exe.as_bytes()).expect("load");
    // `load` performs an exec-style initial-process setup, so credentials
    // must be installed after it rather than being overwritten by that reset.
    machine.set_credentials(guest_uid, guest_gid);

    let mut pty_input_steps: VecDeque<Vec<u8>> = std::env::var("GUEST_PTY_INPUT_STEPS")
        .ok()
        .map(|steps| steps.split('|').map(unescape).collect())
        .unwrap_or_default();
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
        if matches!(exit, x64_engine::CpuExit::Interrupted)
            && pty_stdio
            && machine.awaiting_terminal_input()
        {
            // A terminal read is a host turn, not a process exit. Flush the
            // first frame/prompt now, then resume exactly the same machine
            // after the user (or scripted harness) supplies more bytes.
            let rendered = machine.drain_terminal_output();
            print!("{}", String::from_utf8_lossy(&rendered));
            std::io::stdout().flush().expect("flush terminal output");
            if let Some(bytes) = pty_input_steps.pop_front() {
                machine.feed_terminal_input(&bytes);
                continue;
            }
            let mut bytes = [0_u8; 4096];
            match std::io::stdin().read(&mut bytes) {
                Ok(count) if count != 0 => {
                    machine.feed_terminal_input(&bytes[..count]);
                    continue;
                }
                Ok(_) => break exit, // host stdin reached EOF
                Err(error) => panic!("read terminal input: {error}"),
            }
        }
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
            let show = show
                && match std::env::var("BREAK_NONZERO") {
                    Ok(reg) => vm
                        .cpu
                        .arch
                        .sleigh
                        .get_varnode(&reg)
                        .is_some_and(|var| vm.cpu.read_reg(var) != 0),
                    Err(_) => true,
                };
            let show = show
                && match std::env::var("BREAK_EQ") {
                    Ok(spec) => {
                        let (reg, value) = spec
                            .split_once(':')
                            .expect("BREAK_EQ must be REGISTER:VALUE");
                        let expected = u64::from_str_radix(value.trim_start_matches("0x"), 16)
                            .expect("BREAK_EQ value must be hexadecimal");
                        vm.cpu
                            .arch
                            .sleigh
                            .get_varnode(reg)
                            .is_some_and(|var| vm.cpu.read_reg(var) == expected)
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
    if std::env::var_os("GUEST_TASK_STATES").is_some() {
        let (exe, pid) = machine.current_task();
        eprintln!("[runner] current pid={pid} exe={exe}");
        for state in machine.parked_task_snapshot() {
            eprintln!("[runner] parked {state}");
        }
    }
    if !matches!(exit, x64_engine::CpuExit::Halt { code: Some(0) }) {
        let (exe, pid) = machine.current_task();
        let syscall_trail = machine.syscall_trail().join(" ");
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
        let code_start = rip.saturating_sub(64);
        let mut code_window = [0_u8; 160];
        let _ = vm
            .cpu
            .mem
            .read_bytes(code_start, &mut code_window, icicle_mem::perm::NONE);
        let code_hex: String = code_window.iter().map(|b| format!("{b:02x} ")).collect();
        eprintln!("[runner] fault code window @{code_start:#x}: {code_hex}");
        let mut registers = String::new();
        for name in [
            "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11",
            "R12", "R13", "R14", "R15",
        ] {
            if let Some(var) = vm.cpu.arch.sleigh.get_varnode(name) {
                registers.push_str(&format!("{name}={:#x} ", vm.cpu.read_reg(var)));
            }
        }
        eprintln!("[runner] fault registers: {registers}");
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
        eprintln!("[runner] syscall trail (pid:nr@icount): {syscall_trail}");
        // FAULT_CODE_WINDOW=N dumps N bytes before and after RIP. This is
        // deliberately relative to the actual fault rather than a manually
        // supplied address: generated runtimes allocate code at a different
        // address every run, and the predecessor branch often explains an
        // invalid value at the first faulting load.
        if let Ok(radius) = std::env::var("FAULT_CODE_WINDOW") {
            let radius: u64 = radius.parse().unwrap_or(64);
            let start = rip.saturating_sub(radius);
            let len = radius.saturating_mul(2).min(4096) as usize;
            let mut bytes = vec![0_u8; len];
            if vm
                .cpu
                .mem
                .read_bytes(start, &mut bytes, icicle_mem::perm::NONE)
                .is_ok()
            {
                let hex: String = bytes.iter().map(|byte| format!("{byte:02x} ")).collect();
                eprintln!(
                    "[runner] code window start={start:#x} rip-offset={:#x}: {hex}",
                    rip.saturating_sub(start)
                );
            }
        }
        // FAULT_PCODE=1 prints the current lifted block around the failing
        // p-code operation. Generated runtimes often fault far from a symbol,
        // so the guest instruction alone is not enough to tell whether an
        // emulator register/value became invalid before the access.
        if std::env::var_os("FAULT_PCODE").is_some() {
            use pcode::PcodeDisplay;
            let block_id = vm.cpu.block_id;
            let offset = vm.cpu.block_offset as usize;
            match vm.code.blocks.get(block_id as usize) {
                Some(block) => {
                    eprintln!(
                        "[runner] pcode block={block_id} start={:#x} offset={offset}",
                        block.start
                    );
                    let first = offset.saturating_sub(8);
                    let last = (offset + 9).min(block.pcode.instructions.len());
                    for (index, statement) in
                        block.pcode.instructions[first..last].iter().enumerate()
                    {
                        let index = first + index;
                        let marker = if index == offset { "=>" } else { "  " };
                        eprintln!(
                            "[runner] {marker} pcode[{index}] {}",
                            statement.display(&vm.cpu.arch.sleigh)
                        );
                    }
                }
                None => eprintln!(
                    "[runner] pcode unavailable: block={block_id} offset={offset} blocks={}",
                    vm.code.blocks.len()
                ),
            }
        }
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
    // GUEST_GPRS=1: dump the register file at exit. Two runs stopped at
    // different icounts show whether a silent loop's pointers progress
    // (bounded work) or cycle (a real spin).
    if std::env::var_os("GUEST_GPRS").is_some() {
        let vm = machine.vm_mut();
        let mut regs = String::new();
        for name in [
            "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11",
            "R12", "R13", "R14", "R15",
        ] {
            if let Some(var) = vm.cpu.arch.sleigh.get_varnode(name) {
                regs.push_str(&format!("{name}={:#x} ", vm.cpu.read_reg(var)));
            }
        }
        eprintln!("[runner] gprs {regs}");
        // Walk the stack conservatively: every qword above RSP that lands in
        // a mapped page is a potential return address for symbolization.
        if let Some(var) = vm.cpu.arch.sleigh.get_varnode("RSP") {
            let rsp: u64 = vm.cpu.read_reg(var);
            let mut addrs = String::new();
            for slot in 0..1024u64 {
                let mut buf = [0u8; 8];
                if vm
                    .cpu
                    .mem
                    .read_bytes(rsp + slot * 8, &mut buf, icicle_mem::perm::NONE)
                    .is_err()
                {
                    break;
                }
                let val = u64::from_le_bytes(buf);
                if (0x40_0000..0x6000_0000).contains(&val) {
                    addrs.push_str(&format!("{val:#x} "));
                }
            }
            eprintln!("[runner] stack-code-ptrs {addrs}");
        }
        // The registers commonly hold a {capacity, data, len} buffer during
        // string building; dump what the data pointers point at, as text.
        for name in ["R15", "RDI", "RSI", "R12"] {
            let Some(var) = vm.cpu.arch.sleigh.get_varnode(name) else {
                continue;
            };
            let base: u64 = vm.cpu.read_reg(var);
            let mut hdr = [0u8; 24];
            if vm
                .cpu
                .mem
                .read_bytes(base, &mut hdr, icicle_mem::perm::NONE)
                .is_err()
            {
                continue;
            }
            let data = u64::from_le_bytes(hdr[8..16].try_into().expect("8 bytes"));
            let mut text = [0u8; 256];
            if data > 0x1000
                && vm
                    .cpu
                    .mem
                    .read_bytes(data, &mut text, icicle_mem::perm::NONE)
                    .is_ok()
            {
                eprintln!(
                    "[runner] [{name}]+8 -> {data:#x}: {:?}",
                    String::from_utf8_lossy(&text)
                );
            }
        }
    }
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
            if let Ok(spec) = std::env::var("GUEST_PROFILE_IMAGE_RANGE") {
                let (start, end) = spec
                    .split_once(':')
                    .map(|(start, end)| {
                        let parse = |value: &str| {
                            u64::from_str_radix(value.trim_start_matches("0x"), 16)
                                .expect("profile image address")
                        };
                        (parse(start), parse(end))
                    })
                    .expect("GUEST_PROFILE_IMAGE_RANGE=start:end");
                let (inside, outside) =
                    hot.iter()
                        .fold((0_u64, 0_u64), |(inside, outside), (weight, addr, _)| {
                            if (start..end).contains(addr) {
                                (inside.saturating_add(*weight), outside)
                            } else {
                                (inside, outside.saturating_add(*weight))
                            }
                        });
                eprintln!(
                    "[profile] image_range={start:#x}..{end:#x} inside={inside} outside={outside}"
                );
                eprintln!("[profile] hottest blocks outside image range:");
                for (weight, addr, entries) in hot
                    .iter()
                    .filter(|(_, addr, _)| !(start..end).contains(addr))
                    .take(30)
                {
                    eprintln!("[profile]   {addr:#x} weight={weight} entries={entries}");
                }
            }
        }
        if let Some(coverage) = machine.jit_coverage() {
            let percent = |weight: u64| {
                if coverage.hot_insns == 0 {
                    0.0
                } else {
                    100.0 * weight as f64 / coverage.hot_insns as f64
                }
            };
            eprintln!(
                "[profile] JIT-able {:.1}% ({} of {} weighted instructions)",
                percent(coverage.covered_insns),
                coverage.covered_insns,
                coverage.hot_insns
            );
            for (cause, weight) in coverage.bails.iter().take(20) {
                eprintln!("[profile]   bail {cause}: {:.1}%", percent(*weight));
            }
        }
    }
}
