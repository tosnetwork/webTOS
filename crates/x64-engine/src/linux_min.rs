//! Minimal Linux x86-64 userspace environment (roadmap milestone 1).
//!
//! Loads a *static* ELF, builds the initial process stack (argv, envp,
//! auxv), and services the small syscall set needed by `hello`-class
//! programs: `write`/`writev`, `exit`/`exit_group`, `brk`, anonymous `mmap`,
//! and `arch_prctl(ARCH_SET_FS)`. Everything else returns `-ENOSYS` with a
//! log line — never fake success.
//!
//! This environment is a bring-up stand-in: the full webTOS `linux_compat`
//! layer replaces it in later milestones.

use std::collections::HashMap;

use icicle_cpu::{
    elf::ElfLoader,
    mem::{perm, Mapping},
    Cpu, Environment, Exception, ExceptionCode, ValueSource, VmExit,
};

const PAGE_SIZE: u64 = 0x1000;

const STACK_TOP: u64 = 0x7fff_ff00_0000;
const STACK_SIZE: u64 = 0x10_0000; // 1 MiB
const MMAP_BASE: u64 = 0x6000_0000_0000;

// Linux x86-64 syscall numbers.
const SYS_WRITE: u64 = 1;
const SYS_MMAP: u64 = 9;
const SYS_MUNMAP: u64 = 11;
const SYS_BRK: u64 = 12;
const SYS_WRITEV: u64 = 20;
const SYS_EXIT: u64 = 60;
const SYS_ARCH_PRCTL: u64 = 158;
const SYS_SET_TID_ADDRESS: u64 = 218;
const SYS_EXIT_GROUP: u64 = 231;

const ARCH_SET_FS: u64 = 0x1002;

const ENOSYS: u64 = 38;
const EBADF: u64 = 9;
const EINVAL: u64 = 22;
const ENOMEM: u64 = 12;

const FAKE_TID: u64 = 1000;

// Auxiliary vector keys (System V x86-64 ABI).
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_ENTRY: u64 = 9;
const AT_UID: u64 = 11;
const AT_EUID: u64 = 12;
const AT_GID: u64 = 13;
const AT_EGID: u64 = 14;
const AT_CLKTCK: u64 = 17;
const AT_SECURE: u64 = 23;
const AT_RANDOM: u64 = 25;

struct Regs {
    rax: pcode::VarNode,
    rdi: pcode::VarNode,
    rsi: pcode::VarNode,
    rdx: pcode::VarNode,
    r8: pcode::VarNode,
    r9: pcode::VarNode,
    r10: pcode::VarNode,
    rsp: pcode::VarNode,
    fs_offset: pcode::VarNode,
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
            r8: get("R8")?,
            r9: get("R9")?,
            r10: get("R10")?,
            rsp: get("RSP")?,
            fs_offset: get("FS_OFFSET")?,
        })
    }
}

pub struct MinimalLinux {
    regs: Regs,
    /// ELF images provided up front, keyed by path (used instead of the host
    /// filesystem when present — required in the browser).
    preloaded: HashMap<Vec<u8>, Vec<u8>>,
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    /// Bytes the guest wrote to stdout/stderr, in write order.
    output: Vec<u8>,
    exit_code: Option<i32>,
    brk_start: u64,
    brk_end: u64,
    mmap_next: u64,
}

impl MinimalLinux {
    pub fn new(cpu: &Cpu) -> Result<Self, String> {
        Ok(Self {
            regs: Regs::resolve(cpu)?,
            preloaded: HashMap::new(),
            argv: Vec::new(),
            envp: Vec::new(),
            output: Vec::new(),
            exit_code: None,
            brk_start: 0,
            brk_end: 0,
            mmap_next: MMAP_BASE,
        })
    }

    pub fn preload_file(&mut self, path: &[u8], bytes: Vec<u8>) {
        self.preloaded.insert(path.to_vec(), bytes);
    }

    pub fn set_args(&mut self, argv: Vec<Vec<u8>>, envp: Vec<Vec<u8>>) {
        self.argv = argv;
        self.envp = envp;
    }

    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.output)
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    /// Builds the initial process stack per the System V x86-64 ABI and
    /// points RSP at `argc`.
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

        // String and byte data (grows down from the top of the stack).
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
        // 16 bytes for AT_RANDOM. A fixed value keeps execution
        // deterministic; this is process start entropy, not a secrecy
        // boundary inside the engine.
        let random_ptr = push_bytes(cpu, &[0x5a; 16])?;

        // Vector area: argc, argv, NULL, envp, NULL, auxv.
        let auxv: &[(u64, u64)] = &[
            (AT_PHDR, metadata.binary.phdr_ptr),
            (AT_PHENT, 56),
            (AT_PHNUM, metadata.binary.phdr_num),
            (AT_PAGESZ, PAGE_SIZE),
            (AT_ENTRY, metadata.binary.entry_ptr),
            (AT_UID, 0),
            (AT_EUID, 0),
            (AT_GID, 0),
            (AT_EGID, 0),
            (AT_SECURE, 0),
            (AT_CLKTCK, 100),
            (AT_RANDOM, random_ptr),
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

        // RSP must be 16-byte aligned at `argc`.
        let mut rsp = write_top - vector_bytes.len() as u64;
        rsp &= !0xf;
        cpu.mem
            .write_bytes(rsp, &vector_bytes, perm::NONE)
            .map_err(|e| format!("stack vector write failed: {e:?}"))?;

        cpu.write_var(self.regs.rsp, rsp);
        Ok(())
    }

    fn handle_syscall(&mut self, cpu: &mut Cpu) -> Option<VmExit> {
        let nr: u64 = cpu.read_var(self.regs.rax);
        let arg0: u64 = cpu.read_var(self.regs.rdi);
        let arg1: u64 = cpu.read_var(self.regs.rsi);
        let arg2: u64 = cpu.read_var(self.regs.rdx);

        let result: u64 = match nr {
            SYS_WRITE => self.sys_write(cpu, arg0, arg1, arg2),
            SYS_WRITEV => self.sys_writev(cpu, arg0, arg1, arg2),
            SYS_BRK => self.sys_brk(cpu, arg0),
            SYS_MMAP => {
                let flags: u64 = cpu.read_var(self.regs.r10);
                self.sys_mmap(cpu, arg0, arg1, arg2, flags)
            }
            SYS_MUNMAP => match cpu.mem.unmap_memory_len(arg0, arg1) {
                true => 0,
                false => EINVAL.wrapping_neg(),
            },
            SYS_ARCH_PRCTL => match arg0 {
                ARCH_SET_FS => {
                    cpu.write_var(self.regs.fs_offset, arg1);
                    0
                }
                _ => {
                    tracing::warn!("arch_prctl: unsupported op {arg0:#x}");
                    EINVAL.wrapping_neg()
                }
            },
            SYS_SET_TID_ADDRESS => FAKE_TID,
            SYS_EXIT | SYS_EXIT_GROUP => {
                self.exit_code = Some(arg0 as i32);
                tracing::debug!("guest exited with code {}", arg0 as i32);
                return Some(VmExit::Halt);
            }
            _ => {
                tracing::warn!("unimplemented syscall {nr} -> ENOSYS");
                ENOSYS.wrapping_neg()
            }
        };
        let _ = cpu.read_var::<u64>(self.regs.r8);
        let _ = cpu.read_var::<u64>(self.regs.r9);

        cpu.write_var(self.regs.rax, result);

        // Resume at the instruction after `syscall`.
        let next_pc: u64 = cpu.read_var(cpu.arch.reg_next_pc);
        cpu.exception = Exception::new(ExceptionCode::ExternalAddr, next_pc);
        None
    }

    fn sys_write(&mut self, cpu: &mut Cpu, fd: u64, buf: u64, len: u64) -> u64 {
        if fd != 1 && fd != 2 {
            return EBADF.wrapping_neg();
        }
        // Cap single writes at 1 MiB to bound host memory usage.
        let len = len.min(0x10_0000);
        let mut data = vec![0_u8; len as usize];
        if cpu.mem.read_bytes(buf, &mut data, perm::READ).is_err() {
            return EINVAL.wrapping_neg();
        }
        self.output.extend_from_slice(&data);
        len
    }

    fn sys_writev(&mut self, cpu: &mut Cpu, fd: u64, iov: u64, iovcnt: u64) -> u64 {
        if fd != 1 && fd != 2 {
            return EBADF.wrapping_neg();
        }
        let iovcnt = iovcnt.min(64);
        let mut total: u64 = 0;
        for i in 0..iovcnt {
            let mut entry = [0_u8; 16];
            if cpu
                .mem
                .read_bytes(iov + i * 16, &mut entry, perm::READ)
                .is_err()
            {
                return EINVAL.wrapping_neg();
            }
            let base = u64::from_le_bytes(entry[..8].try_into().unwrap_or([0; 8]));
            let len = u64::from_le_bytes(entry[8..].try_into().unwrap_or([0; 8]));
            if len == 0 {
                continue;
            }
            let written = self.sys_write(cpu, fd, base, len);
            if (written as i64) < 0 {
                return written;
            }
            total = total.saturating_add(written);
        }
        total
    }

    fn sys_brk(&mut self, cpu: &mut Cpu, addr: u64) -> u64 {
        if addr == 0 || addr <= self.brk_end {
            // Shrinking is accepted but memory is not reclaimed.
            return self.brk_end;
        }
        let new_end = align_up(addr, PAGE_SIZE);
        let cur_end = align_up(self.brk_end, PAGE_SIZE);
        if new_end > cur_end {
            let ok = cpu.mem.map_memory_len(
                cur_end,
                new_end - cur_end,
                Mapping {
                    perm: perm::READ | perm::WRITE | perm::INIT,
                    value: 0,
                },
            );
            if !ok {
                return self.brk_end;
            }
        }
        self.brk_end = addr;
        addr
    }

    fn sys_mmap(&mut self, cpu: &mut Cpu, addr: u64, len: u64, prot: u64, flags: u64) -> u64 {
        const MAP_ANONYMOUS: u64 = 0x20;
        const MAP_FIXED: u64 = 0x10;
        const PROT_EXEC: u64 = 0x4;

        if len == 0 {
            return EINVAL.wrapping_neg();
        }
        if flags & MAP_ANONYMOUS == 0 {
            tracing::warn!("mmap: file-backed mappings are not supported in the minimal env");
            return ENOSYS.wrapping_neg();
        }

        let len = align_up(len, PAGE_SIZE);
        let target = if flags & MAP_FIXED != 0 && addr != 0 {
            addr & !(PAGE_SIZE - 1)
        } else {
            let target = self.mmap_next;
            self.mmap_next += len + PAGE_SIZE;
            target
        };

        let mut perm_bits = perm::READ | perm::WRITE | perm::INIT;
        if prot & PROT_EXEC != 0 {
            perm_bits |= perm::EXEC;
        }
        match cpu.mem.map_memory_len(
            target,
            len,
            Mapping {
                perm: perm_bits,
                value: 0,
            },
        ) {
            true => target,
            false => ENOMEM.wrapping_neg(),
        }
    }
}

/// Rounds `value` up to the next multiple of `align` (a power of two),
/// saturating at the highest aligned address on overflow.
fn align_up(value: u64, align: u64) -> u64 {
    let mask = !(align - 1);
    value.checked_add(align - 1).map_or(mask, |v| v & mask)
}

impl ElfLoader for MinimalLinux {
    fn read_file(&mut self, path: &[u8]) -> Result<Vec<u8>, String> {
        if let Some(bytes) = self.preloaded.get(path) {
            return Ok(bytes.clone());
        }
        let path = std::str::from_utf8(path).map_err(|e| format!("non-UTF-8 path: {e}"))?;
        std::fs::read(path).map_err(|e| format!("failed to read {path}: {e}"))
    }
}

impl Environment for MinimalLinux {
    fn load(&mut self, cpu: &mut Cpu, path: &[u8]) -> Result<(), String> {
        cpu.mem.reset_virtual();
        cpu.reset();

        // Reserve the null page so null dereferences fault with a permission
        // error instead of an unmapped-memory error.
        cpu.mem.map_memory_len(
            0,
            PAGE_SIZE,
            Mapping {
                perm: perm::NONE,
                value: 0,
            },
        );

        let metadata = self.load_elf(cpu, path)?;
        if metadata.interpreter.is_some() {
            return Err(
                "dynamically linked binaries are not supported by the minimal environment".into(),
            );
        }

        if self.argv.is_empty() {
            self.argv = vec![path.to_vec()];
        }

        (cpu.arch.on_boot)(cpu, metadata.binary.entry_ptr);
        self.setup_stack(cpu, &metadata)?;

        // Place the program break above the loaded image.
        let image_end = metadata.binary.base_ptr + metadata.binary.length;
        self.brk_start = align_up(image_end, PAGE_SIZE) + 0x10_0000;
        self.brk_end = self.brk_start;

        self.exit_code = None;
        Ok(())
    }

    fn handle_exception(&mut self, cpu: &mut Cpu) -> Option<VmExit> {
        match ExceptionCode::from_u32(cpu.exception.code) {
            ExceptionCode::Syscall => self.handle_syscall(cpu),
            _ => None,
        }
    }

    fn snapshot(&mut self) -> Box<dyn std::any::Any> {
        Box::new(())
    }

    fn restore(&mut self, _: &Box<dyn std::any::Any>) {}
}
