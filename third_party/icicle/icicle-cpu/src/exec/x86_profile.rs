//! Versioned virtual x86-64 CPU profiles.
//!
//! CPUID feature publication is deliberately data, not control flow spread
//! through instruction helpers.  Extended-state serialization and XCR0 use
//! this same module as M9 grows, so they cannot silently disagree with CPUID.

/// The conservative profile shipped before AVX-family execution is enabled.
pub(crate) const PROFILE_NAME: &str = "webtos-x86_64-conservative-v1";

/// Immutable userspace xstate policy.  Bits 0, 1, 2, 5, 6 and 7 select x87,
/// XMM, YMM, opmask, ZMM_Hi256 and Hi16_ZMM respectively.
pub(crate) const INITIAL_XCR0: u64 = 0xe7;

pub(crate) const XSAVE_LEGACY_SIZE: u32 = 512;
pub(crate) const XSAVE_HEADER_SIZE: u32 = 64;
pub(crate) const XSAVE_AREA_SIZE: u32 = 2688;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct XstateComponent {
    pub(crate) bit: u8,
    pub(crate) size: u32,
    pub(crate) offset: u32,
}

/// Standard-format user xstate components beyond the 512-byte legacy region
/// and 64-byte header. CPUID.0d and XSAVE/XRSTOR consume this exact table.
pub(crate) const XSTATE_COMPONENTS: &[XstateComponent] = &[
    XstateComponent { bit: 2, size: 256, offset: 576 },
    XstateComponent { bit: 5, size: 64, offset: 1088 },
    XstateComponent { bit: 6, size: 512, offset: 1152 },
    XstateComponent { bit: 7, size: 1024, offset: 1664 },
];

const MAX_BASIC_LEAF: u32 = 1;
const MAX_EXTENDED_LEAF: u32 = 0x8000_0001;

/// Architectural CPUID output registers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CpuidResult {
    pub(crate) eax: u32,
    pub(crate) ebx: u32,
    pub(crate) ecx: u32,
    pub(crate) edx: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Feature {
    Xsave,
    Osxsave,
    Avx,
    Avx2,
    Avx512F,
    Avx512Dq,
    Avx512Cd,
    Avx512Bw,
    Avx512Vl,
}

impl Feature {
    const fn bit(self) -> u16 {
        1 << self as u8
    }
}

#[derive(Clone, Copy)]
struct FeatureRule {
    feature: Feature,
    requires: u16,
}

/// Architectural dependency closure for the AVX-family publication boundary.
///
/// The conservative profile enables none of these bits.  Keeping the graph in
/// executable data makes a later profile flip fail closed if it omits a
/// prerequisite.
const FEATURE_RULES: &[FeatureRule] = &[
    FeatureRule { feature: Feature::Osxsave, requires: Feature::Xsave.bit() },
    FeatureRule { feature: Feature::Avx, requires: Feature::Xsave.bit() | Feature::Osxsave.bit() },
    FeatureRule { feature: Feature::Avx2, requires: Feature::Avx.bit() },
    FeatureRule { feature: Feature::Avx512F, requires: Feature::Avx2.bit() },
    FeatureRule { feature: Feature::Avx512Dq, requires: Feature::Avx512F.bit() },
    FeatureRule { feature: Feature::Avx512Cd, requires: Feature::Avx512F.bit() },
    FeatureRule { feature: Feature::Avx512Bw, requires: Feature::Avx512F.bit() },
    FeatureRule { feature: Feature::Avx512Vl, requires: Feature::Avx512F.bit() },
];

const ENABLED_AVX_FAMILY: u16 = 0;

pub(crate) fn feature_dependencies_are_closed(enabled: u16) -> bool {
    FEATURE_RULES
        .iter()
        .all(|rule| enabled & rule.feature.bit() == 0 || enabled & rule.requires == rule.requires)
}

/// Returns the total CPUID result for the active profile.
///
/// Leaves outside the advertised maxima are still total and return zeros, as
/// real CPUID does for an unsupported query.  No query becomes an interpreter
/// `UnimplementedOp`.
pub(crate) fn cpuid(leaf: u32, subleaf: u32) -> CpuidResult {
    debug_assert!(feature_dependencies_are_closed(ENABLED_AVX_FAMILY));

    match (leaf, subleaf) {
        (0, _) => CpuidResult {
            eax: MAX_BASIC_LEAF,
            ebx: u32::from_le_bytes(*b"Genu"),
            ecx: u32::from_le_bytes(*b"ntel"),
            edx: u32::from_le_bytes(*b"ineI"),
        },
        (1, _) => CpuidResult {
            // Family 6, model 0x9e.  The profile is an execution contract, not
            // a claim about cache topology or physical model identity.
            eax: 0x0009_06e0,
            ebx: 0,
            // SSE3, PCLMULQDQ, TM2, PDCM, POPCNT, TSC deadline, AES-NI.
            // XSAVE/OSXSAVE/AVX/F16C stay clear until M9-L publishes the
            // completed extended-state profile.
            ecx: (1 << 0) | (1 << 1) | (1 << 8) | (1 << 15) | (1 << 23) | (1 << 24) | (1 << 25),
            // FPU, VME, DE, TSC, MSR, PAE, CX8, SEP, CMOV, CLFSH, MMX,
            // FXSR, SSE, SSE2.
            edx: (1 << 0)
                | (1 << 1)
                | (1 << 2)
                | (1 << 4)
                | (1 << 5)
                | (1 << 6)
                | (1 << 8)
                | (1 << 11)
                | (1 << 15)
                | (1 << 19)
                | (1 << 23)
                | (1 << 24)
                | (1 << 25)
                | (1 << 26),
        },
        // Structured extended features: subleaf zero is the only supported
        // subleaf, and EAX reports that finite maximum.
        (7, 0) => CpuidResult { eax: 0, ..CpuidResult::default() },
        (7, _) => CpuidResult::default(),
        (0x0d, 0) => CpuidResult {
            eax: INITIAL_XCR0 as u32,
            ebx: XSAVE_AREA_SIZE,
            ecx: XSAVE_AREA_SIZE,
            edx: (INITIAL_XCR0 >> 32) as u32,
        },
        // XSAVEOPT, XSAVEC, XGETBV(1) and XSAVES are intentionally absent.
        (0x0d, 1) => CpuidResult::default(),
        (0x0d, component) => XSTATE_COMPONENTS
            .iter()
            .find(|entry| u32::from(entry.bit) == component)
            .map(|entry| CpuidResult { eax: entry.size, ebx: entry.offset, ecx: 0, edx: 0 })
            .unwrap_or_default(),
        (0x8000_0000, _) => CpuidResult { eax: MAX_EXTENDED_LEAF, ..CpuidResult::default() },
        (0x8000_0001, _) => CpuidResult {
            // SYSCALL and long mode.
            edx: (1 << 11) | (1 << 29),
            ..CpuidResult::default()
        },
        _ => CpuidResult::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_feature_set_is_dependency_closed() {
        assert!(feature_dependencies_are_closed(ENABLED_AVX_FAMILY));
    }

    #[test]
    fn dependency_graph_rejects_missing_prerequisites() {
        assert!(!feature_dependencies_are_closed(Feature::Avx.bit()));
        assert!(!feature_dependencies_are_closed(Feature::Avx2.bit()));
        assert!(!feature_dependencies_are_closed(Feature::Avx512F.bit()));

        let avx = Feature::Xsave.bit() | Feature::Osxsave.bit() | Feature::Avx.bit();
        assert!(feature_dependencies_are_closed(avx));
        assert!(feature_dependencies_are_closed(avx | Feature::Avx2.bit()));
    }
}
