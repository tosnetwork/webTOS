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
    let image = std::fs::read(&args[0]).expect("read elf");
    machine.add_file(b"/bin/guest", image, 0o755).expect("add");
    let mut argv: Vec<Vec<u8>> = vec![b"guest".to_vec()];
    argv.extend(args[1..].iter().map(|a| a.as_bytes().to_vec()));
    let mut envp: Vec<Vec<u8>> = vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()];
    if let Ok(extra) = std::env::var("GUEST_ENV") {
        envp.extend(extra.split(',').map(|kv| kv.as_bytes().to_vec()));
    }
    machine.set_args(argv, envp);
    machine.load(b"/bin/guest").expect("load");
    machine.vm_mut().icount_limit = 20_000_000_000;
    let exit = machine.run();
    let output = machine.take_output();
    print!("{}", String::from_utf8_lossy(&output));
    eprintln!("[runner] exit={exit:?} icount={}", machine.icount());
}
