//! Contract Identity and Registry
//!
//! Provides content-addressed contract identities (SHA-256-like hash of code),
//! a static registry of deployed contracts, and lookup by ID, agent, or
//! entry-point selector.

use crate::agent::{E_INVALID_ARG, E_QUOTA_EXCEEDED};
use sha2::{Digest, Sha256};

/// Maximum number of contracts that can be registered simultaneously.
const MAX_CONTRACTS: usize = 64;

/// Maximum number of callable entry points per contract.
pub const MAX_ENTRY_POINTS: usize = 8;

/// Content-addressed contract identity (hash of the contract code).
pub type ContractId = [u8; 32];

/// Lifecycle status of a deployed contract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ContractStatus {
    /// Contract is live and accepting calls.
    Deployed,
    /// Contract is temporarily suspended (e.g. by governance).
    Suspended,
    /// Contract has been permanently terminated.
    Terminated,
}

/// A callable function exported by a contract.
#[derive(Clone, Copy)]
pub struct EntryPoint {
    /// Function name, null-terminated, up to 32 bytes.
    pub name: [u8; 32],
    /// Actual length of the name (excluding any null terminator).
    pub name_len: u8,
    /// 4-byte selector derived from SHA-256 hash of the name.
    pub selector: u32,
}

/// Metadata for a deployed contract in the registry.
#[derive(Clone, Copy)]
pub struct ContractEntry {
    /// Content hash of the contract code (the contract's identity).
    pub id: ContractId,
    /// The TOS agent ID running this contract.
    pub agent_id: u16,
    /// Mailbox ID for receiving invocation messages.
    pub mailbox_id: u16,
    /// Code content hash (identical to `id`).
    pub code_hash: [u8; 32],
    /// Agent ID of the deployer.
    pub deployer: u16,
    /// Tick at which the contract was deployed.
    pub deploy_tick: u64,
    /// Current lifecycle status.
    pub status: ContractStatus,
    /// Callable entry points exported by this contract.
    pub entry_points: [EntryPoint; MAX_ENTRY_POINTS],
    /// Number of valid entry points in `entry_points`.
    pub entry_point_count: u8,
}

// ---------------------------------------------------------------------------
// Global registry (static, no_std compatible)
// ---------------------------------------------------------------------------

static mut REGISTRY: [Option<ContractEntry>; MAX_CONTRACTS] = [const { None }; MAX_CONTRACTS];
static mut CONTRACT_COUNT: usize = 0;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute a 4-byte selector from a function name using SHA-256.
///
/// The selector is the first 4 bytes of the SHA-256 hash, interpreted as a
/// big-endian u32.  This mirrors Ethereum's approach (keccak truncated to 4
/// bytes) but uses SHA-256.
pub fn compute_selector(name: &[u8]) -> u32 {
    let hash = Sha256::digest(name);
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

/// Compute a 32-byte contract ID from the contract code.
///
/// Returns the SHA-256 digest of the code, providing a cryptographically
/// strong content-addressed identity.
pub fn compute_contract_id(code: &[u8]) -> ContractId {
    let hash = Sha256::digest(code);
    let mut id = [0u8; 32];
    id.copy_from_slice(&hash);
    id
}

/// Register a new contract in the global registry.
///
/// Returns the slot index on success, or `E_QUOTA_EXCEEDED` if the registry
/// is full, or `E_INVALID_ARG` if a contract with the same ID already exists.
pub fn register(entry: ContractEntry) -> Result<usize, i64> {
    unsafe {
        // Check for duplicate ID.
        for slot in REGISTRY.iter() {
            if let Some(existing) = slot {
                if existing.id == entry.id && existing.status != ContractStatus::Terminated {
                    return Err(E_INVALID_ARG);
                }
            }
        }

        // Find a free slot.
        for (i, slot) in REGISTRY.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                CONTRACT_COUNT += 1;
                return Ok(i);
            }
        }

        Err(E_QUOTA_EXCEEDED)
    }
}

/// Look up a contract by its content-addressed ID.
pub fn lookup_by_id(id: &ContractId) -> Option<&'static ContractEntry> {
    unsafe {
        for slot in REGISTRY.iter() {
            if let Some(entry) = slot {
                if &entry.id == id {
                    return Some(entry);
                }
            }
        }
        None
    }
}

/// Look up a contract by the agent ID that runs it.
pub fn lookup_by_agent(agent_id: u16) -> Option<&'static ContractEntry> {
    unsafe {
        for slot in REGISTRY.iter() {
            if let Some(entry) = slot {
                if entry.agent_id == agent_id {
                    return Some(entry);
                }
            }
        }
        None
    }
}

/// Look up a contract by an entry-point selector.
///
/// Returns the first contract that exports an entry point matching the given
/// 4-byte selector.
pub fn lookup_by_selector(selector: u32) -> Option<&'static ContractEntry> {
    unsafe {
        for slot in REGISTRY.iter() {
            if let Some(entry) = slot {
                for ep_idx in 0..entry.entry_point_count as usize {
                    if entry.entry_points[ep_idx].selector == selector {
                        return Some(entry);
                    }
                }
            }
        }
        None
    }
}

/// Mark a contract as `Terminated` by its ID.
///
/// Returns `true` if the contract was found and terminated, `false` otherwise.
pub fn unregister(id: &ContractId) -> bool {
    unsafe {
        for slot in REGISTRY.iter_mut() {
            if let Some(entry) = slot {
                if &entry.id == id {
                    entry.status = ContractStatus::Terminated;
                    return true;
                }
            }
        }
        false
    }
}

/// Return the number of currently registered (non-None) contracts.
pub fn contract_count() -> usize {
    unsafe { CONTRACT_COUNT }
}

/// Get a reference to the contract at a given registry index.
pub fn get_contract(index: usize) -> Option<&'static ContractEntry> {
    if index >= MAX_CONTRACTS {
        return None;
    }
    unsafe { REGISTRY[index].as_ref() }
}
