//! x86-64 user-mode execution engine for webTOS.
//!
//! This crate is the `x64-engine` layer from the webTOS roadmap: it executes
//! x86-64 long-mode instructions over sparse guest memory and reports
//! structured exits. Instruction semantics come from the vendored icicle CPU
//! core (`third_party/icicle`), driven by an interpreter-only VM loop so the
//! whole engine can compile to `wasm32-unknown-unknown`.
//!
//! The engine does not implement Linux policy. Operating-system semantics are
//! provided by an [`icicle_cpu::Environment`] implementation; syscalls surface
//! there as `ExceptionCode::Syscall`. [`linux_min::MinimalLinux`] is the
//! milestone-1 environment (static ELFs, `write`/`exit`-class syscalls); the
//! full webTOS `linux_compat` layer replaces it in later milestones.

pub mod build;
pub mod linux_min;
pub mod vm;

pub use build::{build_x64_vm, BuildError, EngineConfig};
pub use icicle_cpu::{Environment, ExceptionCode, VmExit};
pub use vm::InterpVm;

use std::path::Path;

/// Structured exit reasons reported by [`Engine::run`].
///
/// This is the stable boundary between the CPU engine and its callers; it
/// deliberately does not expose icicle types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuExit {
    /// The workload halted (e.g. `exit`/`exit_group`). `code` is the guest
    /// exit code when the environment recorded one.
    Halt { code: Option<i32> },
    /// The configured instruction limit was reached.
    InstructionLimit,
    /// A breakpoint was hit.
    Breakpoint { rip: u64 },
    /// Execution was interrupted via [`InterpVm::interrupt_flag`].
    Interrupted,
    /// A guest memory access faulted.
    PageFault { address: u64, access: AccessKind },
    /// The bytes at `rip` did not decode to a supported instruction.
    IllegalInstruction { rip: u64 },
    /// The engine could not allocate guest memory.
    OutOfMemory,
    /// Any other exception, reported without translation.
    Unhandled { code: ExceptionCode, value: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessKind {
    Read,
    Write,
    Execute,
}

/// Byte-level access to sparse guest memory (roadmap `GuestMemory` boundary).
pub trait GuestMemory {
    fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), MemoryError>;
    fn write(&mut self, address: u64, input: &[u8]) -> Result<(), MemoryError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryError {
    pub address: u64,
}

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "guest memory access failed at {:#x}", self.address)
    }
}

impl std::error::Error for MemoryError {}

/// A ready-to-run x86-64 user-mode machine: interpreter VM plus a Linux
/// environment.
pub struct Engine {
    vm: InterpVm,
}

impl Engine {
    /// Builds an engine using the minimal milestone-1 Linux environment.
    ///
    /// `ldef_path` points at a SLEIGH `x86.ldefs` file (the vendored copy
    /// lives at `third_party/ghidra-x86/languages/x86.ldefs`).
    pub fn new_linux_minimal(ldef_path: &Path, config: &EngineConfig) -> Result<Self, BuildError> {
        let vm = build_x64_vm(ldef_path, config)?;
        Self::with_minimal_env(vm)
    }

    /// Like [`Engine::new_linux_minimal`], but compiles the SLEIGH
    /// specification from in-memory sources (file name -> content) so no
    /// filesystem is required — the construction path for the browser host.
    pub fn new_linux_minimal_from_files(
        files: std::collections::HashMap<String, String>,
        config: &EngineConfig,
    ) -> Result<Self, BuildError> {
        let vm = build::build_x64_vm_from_files(files, config)?;
        Self::with_minimal_env(vm)
    }

    fn with_minimal_env(mut vm: InterpVm) -> Result<Self, BuildError> {
        let env = linux_min::MinimalLinux::new(&vm.cpu).map_err(BuildError::EnvironmentSetup)?;
        vm.set_env(env);
        Ok(Self { vm })
    }

    /// Loads a static x86-64 Linux ELF and prepares the initial process state.
    pub fn load(&mut self, path: &[u8]) -> Result<(), String> {
        let InterpVm { cpu, env, .. } = &mut self.vm;
        env.load(cpu, path)
    }

    /// Provides ELF bytes for `path` up front so `load` does not touch the
    /// host filesystem (required in the browser).
    pub fn preload_file(&mut self, path: &[u8], bytes: Vec<u8>) {
        if let Some(env) = self.vm.env_mut::<linux_min::MinimalLinux>() {
            env.preload_file(path, bytes);
        }
    }

    /// Passes the process argv/envp used by the next `load`.
    pub fn set_args(&mut self, argv: Vec<Vec<u8>>, envp: Vec<Vec<u8>>) {
        if let Some(env) = self.vm.env_mut::<linux_min::MinimalLinux>() {
            env.set_args(argv, envp);
        }
    }

    /// Runs until the workload exits or faults.
    pub fn run(&mut self) -> CpuExit {
        let exit = self.vm.run();
        self.translate_exit(exit)
    }

    /// Number of guest instructions retired so far.
    pub fn icount(&self) -> u64 {
        self.vm.cpu.icount()
    }

    /// Drains output written by the guest to stdout/stderr.
    pub fn take_output(&mut self) -> Vec<u8> {
        self.vm
            .env_mut::<linux_min::MinimalLinux>()
            .map(|env| env.take_output())
            .unwrap_or_default()
    }

    /// Exit code recorded by `exit`/`exit_group`, if the guest has exited.
    pub fn exit_code(&mut self) -> Option<i32> {
        self.vm
            .env_mut::<linux_min::MinimalLinux>()
            .and_then(|env| env.exit_code())
    }

    /// Escape hatch for hosts that need direct VM access (scheduling,
    /// snapshots, custom environments). The facade above is the stable API.
    pub fn vm_mut(&mut self) -> &mut InterpVm {
        &mut self.vm
    }

    fn translate_exit(&mut self, exit: VmExit) -> CpuExit {
        let code = self.exit_code();
        classify_exit(&self.vm, exit, code)
    }
}

/// Maps a raw [`VmExit`] to the stable [`CpuExit`] boundary. `exit_code` is
/// the guest exit code recorded by the environment, if any.
pub fn classify_exit(vm: &InterpVm, exit: VmExit, exit_code: Option<i32>) -> CpuExit {
    match exit {
        VmExit::Halt => CpuExit::Halt { code: exit_code },
        VmExit::InstructionLimit => CpuExit::InstructionLimit,
        VmExit::Breakpoint => CpuExit::Breakpoint {
            rip: vm.cpu.read_pc(),
        },
        VmExit::Interrupted => CpuExit::Interrupted,
        VmExit::OutOfMemory => CpuExit::OutOfMemory,
        VmExit::UnhandledException((code, value)) => match code {
            ExceptionCode::ReadUnmapped
            | ExceptionCode::ReadPerm
            | ExceptionCode::ReadUnaligned
            | ExceptionCode::ReadWatch
            | ExceptionCode::ReadUninitialized => CpuExit::PageFault {
                address: value,
                access: AccessKind::Read,
            },
            ExceptionCode::WriteUnmapped
            | ExceptionCode::WritePerm
            | ExceptionCode::WriteWatch
            | ExceptionCode::WriteUnaligned => CpuExit::PageFault {
                address: value,
                access: AccessKind::Write,
            },
            ExceptionCode::ExecViolation => CpuExit::PageFault {
                address: value,
                access: AccessKind::Execute,
            },
            ExceptionCode::InvalidInstruction
            | ExceptionCode::InvalidOpSize
            | ExceptionCode::InvalidFloatSize
            | ExceptionCode::UnimplementedOp => CpuExit::IllegalInstruction {
                rip: vm.cpu.read_pc(),
            },
            code => CpuExit::Unhandled { code, value },
        },
        // The remaining variants (Running, Killed, Deadlock, Unimplemented)
        // are internal conditions; report them without translation.
        other => CpuExit::Unhandled {
            code: ExceptionCode::from_u32(vm.cpu.exception.code),
            value: {
                let _ = other;
                vm.cpu.exception.value
            },
        },
    }
}

impl GuestMemory for Engine {
    fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), MemoryError> {
        self.vm
            .cpu
            .mem
            .read_bytes(address, output, icicle_mem::perm::NONE)
            .map_err(|_| MemoryError { address })
    }

    fn write(&mut self, address: u64, input: &[u8]) -> Result<(), MemoryError> {
        self.vm
            .cpu
            .mem
            .write_bytes(address, input, icicle_mem::perm::NONE)
            .map_err(|_| MemoryError { address })
    }
}
