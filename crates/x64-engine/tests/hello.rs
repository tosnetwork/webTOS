//! Milestone-1 workload gate: a static x86-64 ELF prints text and exits
//! through the engine, and invalid code traps with a useful exit.

use std::path::PathBuf;

use x64_engine::{CpuExit, Engine, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn test_elf(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test_data")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

#[test]
fn static_hello_prints_and_exits() {
    let mut engine = Engine::new_linux_minimal(&ldef_path(), &EngineConfig::default())
        .expect("engine build failed");

    engine.preload_file(b"hello_linux.elf", test_elf("hello_linux.elf"));
    engine.load(b"hello_linux.elf").expect("ELF load failed");

    let exit = engine.run();
    let output = engine.take_output();

    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "unexpected exit: {exit:?}"
    );
    let text = String::from_utf8_lossy(&output);
    assert!(text.contains("Hello"), "unexpected guest output: {text:?}");
    assert!(engine.icount() > 0, "no instructions were retired");
}

#[test]
fn invalid_instruction_traps() {
    use x64_engine::GuestMemory;

    let mut engine = Engine::new_linux_minimal(&ldef_path(), &EngineConfig::default())
        .expect("engine build failed");

    engine.preload_file(b"hello_linux.elf", test_elf("hello_linux.elf"));
    engine.load(b"hello_linux.elf").expect("ELF load failed");

    // Overwrite the entry point with bytes that do not decode in 64-bit mode
    // (0x06 is `push es`, invalid outside 16/32-bit modes).
    let rip = {
        let vm = engine.vm_mut();
        vm.cpu.read_pc()
    };
    engine
        .write(rip, &[0x06, 0x06, 0x06, 0x06])
        .expect("patching entry failed");

    let exit = engine.run();
    match exit {
        CpuExit::IllegalInstruction { rip: fault_rip } => {
            assert_eq!(fault_rip, rip, "fault should point at the invalid bytes");
        }
        other => panic!("expected IllegalInstruction, got {other:?}"),
    }
}

#[test]
fn instruction_limit_is_enforced() {
    let mut engine = Engine::new_linux_minimal(&ldef_path(), &EngineConfig::default())
        .expect("engine build failed");

    engine.preload_file(b"hello_linux.elf", test_elf("hello_linux.elf"));
    engine.load(b"hello_linux.elf").expect("ELF load failed");

    engine.vm_mut().icount_limit = 5;
    let exit = engine.run();
    assert_eq!(exit, CpuExit::InstructionLimit, "unexpected exit: {exit:?}");
    assert!(
        engine.icount() <= 6,
        "ran past the instruction limit: {}",
        engine.icount()
    );
}

#[test]
fn in_memory_spec_source_matches_ldef_path() {
    use x64_engine::build::build_x64_vm_from_files;
    use x64_engine::linux_min::MinimalLinux;

    // Feed the engine the same language files the browser host will embed.
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/ghidra-x86/languages");
    let mut files = std::collections::HashMap::new();
    for entry in std::fs::read_dir(&dir).expect("language dir missing") {
        let entry = entry.expect("dir entry");
        if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                files.insert(entry.file_name().to_string_lossy().into_owned(), content);
            }
        }
    }

    let mut vm =
        build_x64_vm_from_files(files, &EngineConfig::default()).expect("from-files build failed");
    let env = MinimalLinux::new(&vm.cpu).expect("env setup failed");
    vm.set_env(env);

    let elf = test_elf("hello_linux.elf");
    {
        let env = vm.env_mut::<MinimalLinux>().expect("env downcast");
        env.preload_file(b"hello_linux.elf", elf);
    }
    let x64_engine::vm::InterpVm { cpu, env, .. } = &mut vm;
    env.load(cpu, b"hello_linux.elf").expect("ELF load failed");

    let exit = vm.run();
    assert_eq!(exit, x64_engine::VmExit::Halt, "unexpected exit: {exit:?}");
    let env = vm.env_mut::<MinimalLinux>().expect("env downcast");
    assert_eq!(env.exit_code(), Some(0));
    let text = String::from_utf8_lossy(&env.take_output()).into_owned();
    assert!(text.contains("Hello"), "unexpected guest output: {text:?}");
}
