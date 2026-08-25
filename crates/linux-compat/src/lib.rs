//! Portable Linux x86-64 userspace layer for webTOS (roadmap `linux-compat`).
//!
//! Implements the operating-system side of the Linux ABI over the
//! `x64-engine` virtual CPU: an in-memory VFS, file descriptors with Linux
//! open-file-description semantics, process state, and the syscall surface
//! required by static userlands such as BusyBox (roadmap milestone 2).
//!
//! Unsupported syscalls return `-ENOSYS` with a log line — never fake
//! success. Process management (`fork`, `execve`, `wait4`, pipes) is the
//! milestone-4 boundary and is intentionally absent.
//!
//! This crate supersedes the milestone-1 `linux_min` environment and is the
//! portable rebuild of the native kernel's `src/linux_compat` substrate.

pub mod abi;
pub mod fd;
pub mod syscall;
pub mod vfs;

use std::collections::HashMap;
use std::path::Path;

use icicle_cpu::{
    elf::ElfLoader,
    mem::{perm, Mapping},
    Cpu, Environment, ExceptionCode, ValueSource, VmExit,
};
use x64_engine::{
    build::{build_x64_vm, build_x64_vm_from_files},
    classify_exit, CpuExit, EngineConfig, InterpVm,
};

use fd::FdTable;
use vfs::{NodeKind, Vfs};

const PAGE_SIZE: u64 = 0x1000;
const STACK_TOP: u64 = 0x7fff_ff00_0000;
const STACK_SIZE: u64 = 0x80_0000; // 8 MiB
const MMAP_BASE: u64 = 0x6000_0000_0000;

/// Deterministic wall-clock base (fixed, not host time).
const EPOCH_BASE_SEC: i64 = 1_755_000_000;

pub(crate) struct Regs {
    pub rax: pcode::VarNode,
    pub rdi: pcode::VarNode,
    pub rsi: pcode::VarNode,
    pub rdx: pcode::VarNode,
    pub r10: pcode::VarNode,
    pub r8: pcode::VarNode,
    pub r9: pcode::VarNode,
    pub rsp: pcode::VarNode,
    pub fs_offset: pcode::VarNode,
}

impl Regs {
    fn resolve(cpu: &Cpu) -> Result<Self, String> {
        let get = |name: &str| {
            cpu.arch
                .sleigh
                .get_varnode(name)
                .ok_or_else(|| format!("SLEIGH spec is missing varnode: {name}"))
        };
        Ok(Self {
            rax: get("RAX")?,
            rdi: get("RDI")?,
            rsi: get("RSI")?,
            rdx: get("RDX")?,
            r10: get("R10")?,
            r8: get("R8")?,
            r9: get("R9")?,
            rsp: get("RSP")?,
            fs_offset: get("FS_OFFSET")?,
        })
    }
}

/// Stored `rt_sigaction` registration (handler, flags, restorer, mask).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SigAction(pub [u8; 32]);

pub struct LinuxEnv {
    pub(crate) regs: Regs,
    pub vfs: Vfs,
    pub(crate) fds: FdTable,
    pub(crate) cwd: usize,
    pub(crate) umask: u32,
    pub(crate) brk_end: u64,
    pub(crate) mmap_next: u64,
    pub(crate) rng_state: u64,
    pub(crate) sigactions: HashMap<u64, SigAction>,
    pub(crate) sigmask: u64,
    pub(crate) exe_path: Vec<u8>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    pub(crate) output: Vec<u8>,
    exit_code: Option<i32>,
}

impl LinuxEnv {
    pub fn new(cpu: &Cpu) -> Result<Self, String> {
        Ok(Self {
            regs: Regs::resolve(cpu)?,
            vfs: Vfs::new(),
            fds: FdTable::new(),
            cwd: vfs::ROOT,
            umask: 0o022,
            brk_end: 0,
            mmap_next: MMAP_BASE,
            rng_state: 0x9e37_79b9_7f4a_7c15,
            sigactions: HashMap::new(),
            sigmask: 0,
            exe_path: Vec::new(),
            argv: Vec::new(),
            envp: Vec::new(),
            output: Vec::new(),
            exit_code: None,
        })
    }

    pub fn set_args(&mut self, argv: Vec<Vec<u8>>, envp: Vec<Vec<u8>>) {
        self.argv = argv;
        self.envp = envp;
    }

    pub fn add_file(&mut self, path: &[u8], bytes: Vec<u8>, mode: u32) -> Result<(), String> {
        self.vfs
            .add_node(path, NodeKind::File(bytes), mode)
            .map(|_| ())
            .map_err(|e| format!("cannot add {}: errno {e}", path.escape_ascii()))
    }

    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub(crate) fn record_exit(&mut self, code: i32) {
        self.exit_code = Some(code);
    }

    pub(crate) fn now(&self, cpu: &Cpu) -> (i64, i64) {
        // Deterministic: one retired instruction ~ one nanosecond.
        let nanos = cpu.icount() as i64;
        (
            EPOCH_BASE_SEC + nanos / 1_000_000_000,
            nanos % 1_000_000_000,
        )
    }

    pub(crate) fn next_random(&mut self) -> u64 {
        // xorshift64* — deterministic entropy for the guest.
        let mut x = self.rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub(crate) fn alloc_mmap(&mut self, len: u64) -> u64 {
        let target = self.mmap_next;
        self.mmap_next += align_up(len, PAGE_SIZE) + PAGE_SIZE;
        target
    }

    /// Builds the initial process stack per the System V x86-64 ABI.
    fn setup_stack(
        &mut self,
        cpu: &mut Cpu,
        metadata: &icicle_cpu::elf::LoadedElf,
    ) -> Result<(), String> {
        let stack_base = STACK_TOP - STACK_SIZE;
        cpu.mem
            .map_memory_len(
                stack_base,
                STACK_SIZE,
                Mapping {
                    perm: perm::READ | perm::WRITE | perm::INIT,
                    value: 0,
                },
            )
            .then_some(())
            .ok_or("failed to map stack")?;

        let mut write_top = STACK_TOP;
        let mut push_bytes = |cpu: &mut Cpu, bytes: &[u8]| -> Result<u64, String> {
            write_top -= bytes.len() as u64;
            cpu.mem
                .write_bytes(write_top, bytes, perm::NONE)
                .map_err(|e| format!("stack write failed: {e:?}"))?;
            Ok(write_top)
        };

        let mut argv_ptrs = Vec::with_capacity(self.argv.len());
        for arg in &self.argv {
            let mut bytes = arg.clone();
            bytes.push(0);
            argv_ptrs.push(push_bytes(cpu, &bytes)?);
        }
        let mut envp_ptrs = Vec::with_capacity(self.envp.len());
        for env in &self.envp {
            let mut bytes = env.clone();
            bytes.push(0);
            envp_ptrs.push(push_bytes(cpu, &bytes)?);
        }
        // AT_RANDOM bytes: deterministic process-start entropy.
        let mut random = [0_u8; 16];
        random[..8].copy_from_slice(&self.next_random().to_le_bytes());
        random[8..].copy_from_slice(&self.next_random().to_le_bytes());
        let random_ptr = push_bytes(cpu, &random)?;
        let mut execfn = self.exe_path.clone();
        execfn.push(0);
        let execfn_ptr = push_bytes(cpu, &execfn)?;
        let platform_ptr = push_bytes(cpu, b"x86_64\0")?;

        const AT_PHDR: u64 = 3;
        const AT_PHENT: u64 = 4;
        const AT_PHNUM: u64 = 5;
        const AT_PAGESZ: u64 = 6;
        const AT_BASE: u64 = 7;
        const AT_FLAGS: u64 = 8;
        const AT_ENTRY: u64 = 9;
        const AT_UID: u64 = 11;
        const AT_EUID: u64 = 12;
        const AT_GID: u64 = 13;
        const AT_EGID: u64 = 14;
        const AT_PLATFORM: u64 = 15;
        const AT_HWCAP: u64 = 16;
        const AT_CLKTCK: u64 = 17;
        const AT_SECURE: u64 = 23;
        const AT_RANDOM: u64 = 25;
        const AT_EXECFN: u64 = 31;
        const AT_NULL: u64 = 0;

        // For a dynamically linked binary, execution starts in the
        // interpreter and AT_BASE tells it where it was itself loaded; the
        // remaining entries describe the main binary.
        let interp_base = metadata
            .interpreter
            .as_ref()
            .map_or(0, |interp| interp.base_ptr);

        let auxv: &[(u64, u64)] = &[
            (AT_PHDR, metadata.binary.phdr_ptr),
            (AT_PHENT, 56),
            (AT_PHNUM, metadata.binary.phdr_num),
            (AT_PAGESZ, PAGE_SIZE),
            (AT_BASE, interp_base),
            (AT_FLAGS, 0),
            (AT_ENTRY, metadata.binary.entry_ptr),
            (AT_UID, 0),
            (AT_EUID, 0),
            (AT_GID, 0),
            (AT_EGID, 0),
            (AT_PLATFORM, platform_ptr),
            (AT_HWCAP, 0),
            (AT_SECURE, 0),
            (AT_CLKTCK, 100),
            (AT_RANDOM, random_ptr),
            (AT_EXECFN, execfn_ptr),
            (AT_NULL, 0),
        ];

        let mut vectors: Vec<u64> = Vec::new();
        vectors.push(self.argv.len() as u64);
        vectors.extend(&argv_ptrs);
        vectors.push(0);
        vectors.extend(&envp_ptrs);
        vectors.push(0);
        for &(key, value) in auxv {
            vectors.push(key);
            vectors.push(value);
        }
        let vector_bytes: Vec<u8> = vectors.iter().flat_map(|v| v.to_le_bytes()).collect();

        let mut rsp = write_top - vector_bytes.len() as u64;
        rsp &= !0xf;
        cpu.mem
            .write_bytes(rsp, &vector_bytes, perm::NONE)
            .map_err(|e| format!("stack vector write failed: {e:?}"))?;
        cpu.write_var(self.regs.rsp, rsp);
        Ok(())
    }
}

impl ElfLoader for LinuxEnv {
    fn read_file(&mut self, path: &[u8]) -> Result<Vec<u8>, String> {
        let resolved = self
            .vfs
            .resolve(self.cwd, path, true)
            .map_err(|e| format!("cannot resolve {}: errno {e}", path.escape_ascii()))?;
        let node = resolved
            .node
            .ok_or_else(|| format!("no such file: {}", path.escape_ascii()))?;
        match &self.vfs.node(node).kind {
            NodeKind::File(data) => Ok(data.clone()),
            _ => Err(format!("not a regular file: {}", path.escape_ascii())),
        }
    }
}

impl Environment for LinuxEnv {
    fn load(&mut self, cpu: &mut Cpu, path: &[u8]) -> Result<(), String> {
        cpu.mem.reset_virtual();
        cpu.reset();

        // Null page: faults with a permission error instead of unmapped.
        cpu.mem.map_memory_len(
            0,
            PAGE_SIZE,
            Mapping {
                perm: perm::NONE,
                value: 0,
            },
        );

        let metadata = self.load_elf(cpu, path)?;

        self.exe_path = if path.first() == Some(&b'/') {
            path.to_vec()
        } else {
            let mut abs = self.vfs.abs_path_of(self.cwd);
            if abs != b"/" {
                abs.push(b'/');
            }
            abs.extend_from_slice(path);
            abs
        };
        if self.argv.is_empty() {
            self.argv = vec![path.to_vec()];
        }

        // Dynamically linked binaries start in the interpreter; auxv points
        // the loader at the main image.
        let entry = metadata
            .interpreter
            .as_ref()
            .map_or(metadata.binary.entry_ptr, |interp| interp.entry_ptr);
        (cpu.arch.on_boot)(cpu, entry);
        self.setup_stack(cpu, &metadata)?;

        let image_end = metadata.interpreter.as_ref().map_or(
            metadata.binary.base_ptr + metadata.binary.length,
            |interp| {
                (metadata.binary.base_ptr + metadata.binary.length)
                    .max(interp.base_ptr + interp.length)
            },
        );
        self.brk_end = align_up(image_end, PAGE_SIZE) + 0x10_0000;
        self.fds = FdTable::new();
        self.exit_code = None;
        Ok(())
    }

    fn handle_exception(&mut self, cpu: &mut Cpu) -> Option<VmExit> {
        match ExceptionCode::from_u32(cpu.exception.code) {
            ExceptionCode::Syscall => syscall::handle(self, cpu),
            _ => None,
        }
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(())
    }

    fn restore(&mut self, _: &Box<dyn std::any::Any>) {}
}

pub(crate) fn align_up(value: u64, align: u64) -> u64 {
    let mask = !(align - 1);
    value.checked_add(align - 1).map_or(mask, |v| v & mask)
}

/// A complete Linux x86-64 user-mode machine: the interpreter VM plus this
/// crate's environment.
pub struct Machine {
    vm: InterpVm,
}

impl Machine {
    /// Builds a machine from a SLEIGH `.ldefs` path (native hosts).
    pub fn from_ldef(ldef_path: &Path, config: &EngineConfig) -> Result<Self, String> {
        let vm = build_x64_vm(ldef_path, config).map_err(|e| e.to_string())?;
        Self::finish(vm)
    }

    /// Builds a machine from in-memory SLEIGH sources (browser hosts).
    pub fn from_spec_files(
        files: HashMap<String, String>,
        config: &EngineConfig,
    ) -> Result<Self, String> {
        let vm = build_x64_vm_from_files(files, config).map_err(|e| e.to_string())?;
        Self::finish(vm)
    }

    fn finish(mut vm: InterpVm) -> Result<Self, String> {
        let env = LinuxEnv::new(&vm.cpu)?;
        vm.set_env(env);
        Ok(Self { vm })
    }

    pub fn env(&mut self) -> &mut LinuxEnv {
        self.vm
            .env_mut::<LinuxEnv>()
            .expect("machine environment is always LinuxEnv")
    }

    /// Adds a file to the guest filesystem (parent directories are created).
    pub fn add_file(&mut self, path: &[u8], bytes: Vec<u8>, mode: u32) -> Result<(), String> {
        self.env().add_file(path, bytes, mode)
    }

    /// Recursively copies a host directory tree into the guest filesystem,
    /// preserving symlinks and executable bits. Native hosts only (the
    /// browser host injects files individually).
    pub fn add_host_tree(&mut self, host_dir: &Path, guest_prefix: &str) -> Result<(), String> {
        fn walk(env: &mut LinuxEnv, host: &Path, guest: &str) -> Result<(), String> {
            let entries =
                std::fs::read_dir(host).map_err(|e| format!("{}: {e}", host.display()))?;
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let name = entry.file_name();
                let name = name.to_string_lossy();
                let guest_path = format!("{}/{}", guest.trim_end_matches('/'), name);
                let file_type = entry.file_type().map_err(|e| e.to_string())?;
                if file_type.is_symlink() {
                    let target = std::fs::read_link(entry.path()).map_err(|e| e.to_string())?;
                    env.vfs
                        .add_node(
                            guest_path.as_bytes(),
                            vfs::NodeKind::Symlink(target.to_string_lossy().as_bytes().to_vec()),
                            0o777,
                        )
                        .map_err(|e| format!("{guest_path}: errno {e}"))?;
                } else if file_type.is_dir() {
                    env.vfs
                        .mkdir_p(guest_path.as_bytes())
                        .map_err(|e| format!("{guest_path}: errno {e}"))?;
                    walk(env, &entry.path(), &guest_path)?;
                } else if file_type.is_file() {
                    let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
                    #[cfg(unix)]
                    let mode = {
                        use std::os::unix::fs::PermissionsExt;
                        entry
                            .metadata()
                            .map_err(|e| e.to_string())?
                            .permissions()
                            .mode()
                            & 0o777
                    };
                    #[cfg(not(unix))]
                    let mode = 0o755;
                    env.add_file(guest_path.as_bytes(), bytes, mode)?;
                }
            }
            Ok(())
        }
        walk(self.env(), host_dir, guest_prefix)
    }

    pub fn set_args(&mut self, argv: Vec<Vec<u8>>, envp: Vec<Vec<u8>>) {
        self.env().set_args(argv, envp);
    }

    /// Loads a static ELF from the guest filesystem.
    pub fn load(&mut self, path: &[u8]) -> Result<(), String> {
        let InterpVm { cpu, env, .. } = &mut self.vm;
        env.load(cpu, path)
    }

    /// Runs until the workload exits or faults.
    pub fn run(&mut self) -> CpuExit {
        let exit = self.vm.run();
        let code = self.env().exit_code();
        classify_exit(&self.vm, exit, code)
    }

    pub fn take_output(&mut self) -> Vec<u8> {
        self.env().take_output()
    }

    pub fn exit_code(&mut self) -> Option<i32> {
        self.env().exit_code()
    }

    pub fn icount(&self) -> u64 {
        self.vm.cpu.icount()
    }

    pub fn vm_mut(&mut self) -> &mut InterpVm {
        &mut self.vm
    }
}
