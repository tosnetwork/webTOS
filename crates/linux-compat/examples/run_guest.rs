//! Debug runner: execute an ELF from the host filesystem inside the machine.
//! Usage: run_guest <elf> [args...] (env: GUEST_ENV="K=V,K=V")

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
    let exit = machine.run();
    let output = machine.take_output();
    print!("{}", String::from_utf8_lossy(&output));
    eprintln!("[runner] exit={exit:?} icount={}", machine.icount());
}
