//! CPUID profile gates.
//!
//! The SLEIGH helper result is a 16-byte tuple whose physical slice order is
//! EAX, EBX, EDX, ECX. These tests read the architectural registers after the
//! instruction so a helper that accidentally assumes EAX, EBX, ECX, EDX is
//! caught at the CPU boundary.

use std::path::PathBuf;

use icicle_cpu::mem::{perm, Mapping};
use x64_engine::{build::build_x64_vm, EngineConfig, InterpVm};

const CODE_ADDR: u64 = 0x1000;

#[derive(Debug, PartialEq, Eq)]
struct CpuidRegisters {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

struct CpuidProbe {
    vm: InterpVm,
}

impl CpuidProbe {
    fn new() -> Self {
        let ldef = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../third_party/ghidra-x86/languages/x86.ldefs");
        let vm = build_x64_vm(&ldef, &EngineConfig::default()).expect("build x86-64 engine");
        Self { vm }
    }

    fn run(&mut self, leaf: u32, subleaf: u32) -> CpuidRegisters {
        self.vm.cpu.mem.reset_virtual();
        self.vm.cpu.reset();
        self.vm.flush_code();
        self.vm.cpu.block_id = u64::MAX;
        self.vm.cpu.mem.map_memory_len(
            CODE_ADDR,
            0x1000,
            Mapping {
                perm: perm::ALL,
                value: 0,
            },
        );
        self.vm
            .cpu
            .mem
            .write_bytes(CODE_ADDR, &[0x0f, 0xa2], perm::NONE)
            .expect("write CPUID instruction");
        (self.vm.cpu.arch.on_boot)(&mut self.vm.cpu, CODE_ADDR);

        let reg = |vm: &InterpVm, name| {
            vm.cpu
                .arch
                .sleigh
                .get_varnode(name)
                .unwrap_or_else(|| panic!("missing {name}"))
        };
        let rax = reg(&self.vm, "RAX");
        let rbx = reg(&self.vm, "RBX");
        let rcx = reg(&self.vm, "RCX");
        let rdx = reg(&self.vm, "RDX");
        self.vm.cpu.write_reg(rax, u64::from(leaf));
        self.vm.cpu.write_reg(rcx, u64::from(subleaf));

        let before = self.vm.cpu.icount;
        self.vm.icount_limit = before + 1;
        let exit = self.vm.run();
        assert!(
            self.vm.cpu.icount > before,
            "CPUID did not retire for leaf {leaf:#x}, subleaf {subleaf:#x}: {exit:?}"
        );

        CpuidRegisters {
            eax: self.vm.cpu.read_reg(rax) as u32,
            ebx: self.vm.cpu.read_reg(rbx) as u32,
            ecx: self.vm.cpu.read_reg(rcx) as u32,
            edx: self.vm.cpu.read_reg(rdx) as u32,
        }
    }
}

#[test]
fn cpuid_results_use_architectural_register_order_and_truthful_features() {
    let mut probe = CpuidProbe::new();

    assert_eq!(
        probe.run(0, 0),
        CpuidRegisters {
            eax: 0x0d,
            ebx: u32::from_le_bytes(*b"Genu"),
            ecx: u32::from_le_bytes(*b"ntel"),
            edx: u32::from_le_bytes(*b"ineI"),
        },
        "CPUID.0 vendor tuple must be EAX:EBX:ECX:EDX architecturally"
    );

    let expected_leaf_1_ecx = (1 << 0) // SSE3
        | (1 << 1) // PCLMULQDQ
        | (1 << 8) // TM2
        | (1 << 15) // PDCM
        | (1 << 23) // POPCNT
        | (1 << 24) // TSC deadline
        | (1 << 25) // AES-NI
        | (1 << 26) // XSAVE
        | (1 << 27) // OSXSAVE
        | (1 << 28); // AVX
    let expected_leaf_1_edx = (1 << 0) // FPU
        | (1 << 1) // VME
        | (1 << 2) // DE
        | (1 << 4) // TSC
        | (1 << 5) // MSR
        | (1 << 6) // PAE
        | (1 << 8) // CX8
        | (1 << 11) // SEP
        | (1 << 15) // CMOV
        | (1 << 19) // CLFSH
        | (1 << 23) // MMX
        | (1 << 24) // FXSR
        | (1 << 25) // SSE
        | (1 << 26); // SSE2
    assert_eq!(
        probe.run(1, 0),
        CpuidRegisters {
            eax: 0x0009_06e0,
            ebx: 0,
            ecx: expected_leaf_1_ecx,
            edx: expected_leaf_1_edx,
        },
        "CPUID.1 feature masks and AVX/xstate prerequisites must not be crossed"
    );

    assert_eq!(
        probe.run(0x8000_0001, 0),
        CpuidRegisters {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: (1 << 11) | (1 << 29), // SYSCALL and LONG_MODE
        },
        "extended feature bits belong in EDX"
    );
}

#[test]
fn icelake_profile_has_finite_leaf_boundaries() {
    let mut probe = CpuidProbe::new();

    assert_eq!(
        probe.run(7, 0),
        CpuidRegisters {
            eax: 0,
            ebx: (1 << 3) // BMI1
                | (1 << 5) // AVX2
                | (1 << 8) // BMI2
                | (1 << 16) // AVX-512F
                | (1 << 28) // AVX-512CD
                | (1 << 30) // AVX-512BW
                | (1 << 31), // AVX-512VL
            ecx: 1 << 6,  // AVX-512VBMI2
            edx: 1 << 14, // AVX-512VPOPCNTDQ
        },
        "CPUID.7.0 EAX is the maximum supported subleaf, never a sentinel"
    );

    for subleaf in [1, 2, 7, u32::MAX] {
        assert_eq!(
            probe.run(7, subleaf),
            CpuidRegisters {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            },
            "unsupported CPUID.7 subleaf {subleaf:#x} must be a total zero result"
        );
    }
}

#[test]
fn profile_satisfies_the_pinned_simdutf_icelake_selector_without_forcing() {
    // The simdutf implementation embedded by the pinned Bun/Claude workload
    // requires AVX2, BMI1/2, AVX-512BW/CD/VL/VBMI2/VPOPCNTDQ. AVX-512F and
    // the AVX/OSXSAVE prerequisites are architectural dependencies. Keep this
    // gate explicit so changing one CPUID bit cannot silently demote normal
    // runtime detection to haswell/westmere while the instruction tests stay
    // green. AVX-512DQ is intentionally not part of simdutf's selector.
    let mut probe = CpuidProbe::new();
    let leaf1 = probe.run(1, 0);
    let leaf7 = probe.run(7, 0);

    let required_leaf1_ecx = (1 << 26) | (1 << 27) | (1 << 28); // XSAVE, OSXSAVE, AVX
    assert_eq!(
        leaf1.ecx & required_leaf1_ecx,
        required_leaf1_ecx,
        "simdutf's AVX prerequisite is not guest-visible"
    );

    let required_leaf7_ebx = (1 << 3) // BMI1
        | (1 << 5) // AVX2
        | (1 << 8) // BMI2
        | (1 << 16) // AVX-512F
        | (1 << 28) // AVX-512CD
        | (1 << 30) // AVX-512BW
        | (1 << 31); // AVX-512VL
    assert_eq!(leaf7.ebx & required_leaf7_ebx, required_leaf7_ebx);
    assert_ne!(leaf7.ecx & (1 << 6), 0, "AVX-512VBMI2 is required");
    assert_ne!(leaf7.edx & (1 << 14), 0, "AVX-512VPOPCNTDQ is required");
}

#[test]
fn xstate_enumeration_comes_from_the_standard_layout() {
    let mut probe = CpuidProbe::new();

    assert_eq!(
        probe.run(0x0d, 0),
        CpuidRegisters {
            eax: 0x00e7,
            ebx: 2688,
            ecx: 2688,
            edx: 0,
        }
    );
    for (subleaf, size, offset) in [
        (2, 256, 576),
        (5, 64, 1088),
        (6, 512, 1152),
        (7, 1024, 1664),
    ] {
        assert_eq!(
            probe.run(0x0d, subleaf),
            CpuidRegisters {
                eax: size,
                ebx: offset,
                ecx: 0,
                edx: 0,
            },
            "xstate component {subleaf}"
        );
    }
    assert_eq!(
        probe.run(0x0d, 1),
        CpuidRegisters {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        },
        "compacted, optimized and supervisor save forms stay unadvertised"
    );
}
