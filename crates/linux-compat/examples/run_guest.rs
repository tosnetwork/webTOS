//! Debug runner: execute an ELF from the host filesystem inside the machine.
//! Usage: run_guest <elf> [args...] (env: GUEST_ENV="K=V,K=V")

use std::cell::RefCell;
use std::rc::Rc;

use linux_compat::net::NativeBroker;
use linux_compat::Machine;
use x64_engine::EngineConfig;

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
    machine.vm_mut().icount_limit = 20_000_000_000;
    // GUEST_BREAK="hexaddr,hexaddr": single-shot breakpoints. Each hit dumps
    // the GPRs (and FAULT_PEEK targets) and execution continues.
    if let Ok(spec) = std::env::var("GUEST_BREAK") {
        for part in spec.split(',').filter(|p| !p.is_empty()) {
            let addr = u64::from_str_radix(part.trim_start_matches("0x"), 16).expect("GUEST_BREAK");
            machine.vm_mut().code.breakpoints.insert(addr);
        }
    }
    let exit = loop {
        let exit = machine.run();
        let x64_engine::CpuExit::Breakpoint { rip } = exit else {
            break exit;
        };
        {
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
            eprintln!("[runner] breakpoint rip={rip:#x} {regs}");
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
            vm.code.breakpoints.remove(&rip);
        }
    };
    let output = machine.take_output();
    print!("{}", String::from_utf8_lossy(&output));
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
}
