//! Builds an x86-64 long-mode [`InterpVm`] from a SLEIGH specification.
//!
//! Ported from the upstream icicle `icicle-vm` builder, reduced to the single
//! architecture this engine supports (`x86:LE:64:default`).

use std::{collections::HashMap, path::Path};

use icicle_cpu::{cpu::CallCov, exec::helpers, lifter, Arch, Cpu};
use sleigh_runtime::SleighData;

use crate::vm::InterpVm;

#[derive(Debug)]
pub enum BuildError {
    SpecNotFound(std::path::PathBuf),
    SpecCompileError(String),
    MissingVarnode(&'static str),
    EnvironmentSetup(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpecNotFound(path) => write!(f, "SLEIGH spec not found: {}", path.display()),
            Self::SpecCompileError(err) => write!(f, "SLEIGH spec compile error: {err}"),
            Self::MissingVarnode(name) => write!(f, "SLEIGH spec is missing varnode: {name}"),
            Self::EnvironmentSetup(err) => write!(f, "failed to set up environment: {err}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// Engine construction options. Defaults follow the upstream icicle
/// interpreter configuration.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Run per-instruction p-code optimizations while lifting.
    pub optimize_instructions: bool,
    /// Run whole-block p-code optimizations while lifting.
    pub optimize_block: bool,
    /// Track and fault on reads of uninitialized memory.
    pub track_uninitialized: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            optimize_instructions: true,
            optimize_block: true,
            track_uninitialized: false,
        }
    }
}

const LANGUAGE_ID: &str = "x86:LE:64:default";

/// x86-64 registers treated as scratch space by the SLEIGH spec.
const TEMPORARY_VARNODES: &[&str] = &["xmmTmp1", "xmmTmp2"];

/// Root specification file for x86-64 long mode within the language set.
const ROOT_SLASPEC: &str = "x86-64.slaspec";

/// Preprocessor defines the upstream SLEIGH language builder always sets.
const SPEC_DEFINES: &[&str] = &["ICICLE"];

/// Initial context-register values for `x86:LE:64:default`, mirroring the
/// `<context_set>` block of the vendored `x86-64.pspec`.
const INITIAL_CONTEXT: &[(&str, u64)] = &[
    ("addrsize", 2),
    ("opsize", 1),
    ("rexprefix", 0),
    ("longMode", 1),
];

/// A compiled x86-64 SLEIGH specification plus the metadata the CPU needs.
struct SpecOutput {
    sleigh: SleighData,
    initial_ctx: u64,
    pc: pcode::VarNode,
    sp: pcode::VarNode,
    int_args: Vec<pcode::VarNode>,
}

/// Builds an interpreter-only VM for x86-64 long mode from a `.ldefs` file
/// on the host filesystem.
///
/// The vendored copy lives at `third_party/ghidra-x86/languages/x86.ldefs`.
pub fn build_x64_vm(ldef_path: &Path, config: &EngineConfig) -> Result<InterpVm, BuildError> {
    if !ldef_path.exists() {
        return Err(BuildError::SpecNotFound(ldef_path.to_path_buf()));
    }

    let lang = sleigh_compile::SleighLanguageBuilder::new(ldef_path, LANGUAGE_ID)
        .build()
        .map_err(|e| BuildError::SpecCompileError(e.to_string()))?;

    let spec = SpecOutput {
        sleigh: lang.sleigh,
        initial_ctx: lang.initial_ctx,
        pc: lang.pc,
        sp: lang.sp,
        int_args: lang.default_calling_cov.int_args,
    };
    finish_vm(spec, config)
}

/// Builds an interpreter-only VM for x86-64 long mode from in-memory SLEIGH
/// sources (file name -> content), for hosts without a filesystem such as
/// the browser. `files` must contain `x86-64.slaspec` and everything it
/// includes (the contents of `third_party/ghidra-x86/languages/`).
pub fn build_x64_vm_from_files(
    files: HashMap<String, String>,
    config: &EngineConfig,
) -> Result<InterpVm, BuildError> {
    let mut parser = sleigh_parse::Parser::new(files, SPEC_DEFINES);
    parser
        .include_file(ROOT_SLASPEC)
        .map_err(|e| BuildError::SpecCompileError(parser.error_formatter(e).to_string()))?;
    let sleigh =
        sleigh_compile::build_inner(parser, false).map_err(BuildError::SpecCompileError)?;

    // Mirrors the `<context_set>` handling of the upstream ldefs builder.
    let mut initial_ctx = 0_u64;
    for &(name, value) in INITIAL_CONTEXT {
        let field = sleigh
            .get_context_field(name)
            .ok_or(BuildError::SpecCompileError(format!(
                "missing context field: {name}"
            )))?;
        field.field.set(&mut initial_ctx, value as i64);
    }

    let get = |name: &'static str| {
        sleigh
            .get_varnode(name)
            .ok_or(BuildError::MissingVarnode(name))
    };
    let int_args = ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]
        .into_iter()
        .map(|name| {
            sleigh
                .get_varnode(name)
                .ok_or(BuildError::SpecCompileError(format!(
                    "missing calling-convention register: {name}"
                )))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let spec = SpecOutput {
        initial_ctx,
        pc: get("RIP")?,
        sp: get("RSP")?,
        int_args,
        sleigh,
    };
    finish_vm(spec, config)
}

fn finish_vm(mut spec: SpecOutput, config: &EngineConfig) -> Result<InterpVm, BuildError> {
    let reg_next_pc = spec
        .sleigh
        .add_custom_reg("NEXT_PC", 8)
        .ok_or(BuildError::MissingVarnode("NEXT_PC"))?;
    let reg_isa_mode = spec.sleigh.get_varnode("ISAModeSwitch");
    let reg_xcr0 = spec
        .sleigh
        .get_varnode("XCR0")
        .ok_or(BuildError::MissingVarnode("XCR0"))?;
    let reg_fcw = spec
        .sleigh
        .get_varnode("FPUControlWord")
        .ok_or(BuildError::MissingVarnode("FPUControlWord"))?;
    let reg_ftw = spec
        .sleigh
        .get_varnode("FPUTagWord")
        .ok_or(BuildError::MissingVarnode("FPUTagWord"))?;
    let reg_mxcsr = spec
        .sleigh
        .get_varnode("MXCSR")
        .ok_or(BuildError::MissingVarnode("MXCSR"))?;

    let temporaries = TEMPORARY_VARNODES
        .iter()
        .map(|name| {
            spec.sleigh
                .get_varnode(name)
                .map(|var| var.id)
                .ok_or(BuildError::MissingVarnode(name))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let arch = Arch {
        triple: "x86_64-unknown-linux-gnu"
            .parse()
            .unwrap_or_else(|_| target_lexicon::Triple::unknown()),
        reg_pc: spec.pc,
        reg_next_pc,
        reg_sp: spec.sp,
        reg_isa_mode,
        isa_mode_context: vec![spec.initial_ctx],
        reg_init: vec![
            (reg_xcr0, helpers::x86::INITIAL_XCR0.into()),
            (reg_fcw, 0x037f),
            (reg_ftw, 0xffff),
            (reg_mxcsr, 0x1f80),
        ],
        temporaries,
        calling_cov: CallCov {
            integers: spec.int_args,
            stack_align: 4,
            stack_offset: 0,
        },
        on_boot,
        sleigh: spec.sleigh,
    };

    let mut cpu = Cpu::new_boxed(arch);
    cpu.enable_shadow_stack = false;
    cpu.mem.track_uninitialized = config.track_uninitialized;

    let settings = lifter::Settings {
        optimize: config.optimize_instructions,
        optimize_block: config.optimize_block,
        ..Default::default()
    };
    let instruction_lifter = lifter::InstructionLifter::new();
    let mut block_lifter = lifter::BlockLifter::new(settings, instruction_lifter);
    for var in &cpu.arch.temporaries {
        block_lifter.mark_as_temporary(*var);
    }

    let mut vm = InterpVm::new(cpu, block_lifter);
    register_x86_helpers(&mut vm)?;
    Ok(vm)
}

fn on_boot(cpu: &mut Cpu, entry: u64) {
    use icicle_cpu::ValueSource;

    cpu.reset();
    cpu.regs.write_trunc(cpu.arch.reg_pc, entry);
}

fn register_x86_helpers(vm: &mut InterpVm) -> Result<(), BuildError> {
    lifter::get_injectors(&mut vm.cpu, &mut vm.lifter.op_injectors);

    for &(name, func) in helpers::HELPERS.iter().chain(helpers::x86::HELPERS) {
        if let Some(id) = vm.cpu.arch.sleigh.get_userop(name) {
            vm.cpu.set_helper(id, func);
        }
    }

    // Rewrites direct RIP reads so instructions observe the address of the
    // current instruction rather than a stale PC register.
    let pc = vm.cpu.arch.reg_pc;
    let tmp_pc = vm
        .cpu
        .arch
        .sleigh
        .add_custom_reg("tmp_pc", pc.size)
        .ok_or(BuildError::MissingVarnode("tmp_pc"))?;
    vm.lifter.mark_as_temporary(tmp_pc.id);
    vm.lifter
        .patchers
        .push(lifter::read_pc_patcher(pc, tmp_pc, false));

    Ok(())
}
