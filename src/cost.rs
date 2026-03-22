//! AOS Energy Cost Table
//!
//! Defines energy costs per operation type. Costs are configurable
//! at compile time and used by the syscall dispatcher and timer.

/// Energy cost per operation type
pub struct CostTable {
    pub syscall: u64,         // Cost per syscall invocation
    pub timer_tick: u64,      // Cost per timer tick (running agent)
    pub frame_alloc: u64,     // Cost per frame allocation (sys_mmap)
    pub disk_read: u64,       // Cost per disk sector read
    pub disk_write: u64,      // Cost per disk sector write
    pub network_request: u64, // Cost per network request
    pub mailbox_create: u64,  // Cost per mailbox creation
    pub wasm_fuel_unit: u64,  // AOS energy per WASM fuel unit
}

/// Default cost table (Yellow Paper §25.2.6)
pub static COSTS: CostTable = CostTable {
    syscall: 1,
    timer_tick: 1,
    frame_alloc: 10,
    disk_read: 100,
    disk_write: 200,
    network_request: 500,
    mailbox_create: 50,
    wasm_fuel_unit: 1,
};

/// Charge an operation cost to an agent's energy budget.
/// Returns true if the agent has sufficient budget, false if exhausted.
pub fn charge(agent_id: crate::agent::AgentId, cost: u64) -> bool {
    if let Some(agent) = crate::agent::get_agent_mut(agent_id) {
        if agent.energy_budget >= cost {
            agent.energy_budget -= cost;
            true
        } else {
            agent.energy_budget = 0;
            false
        }
    } else {
        false
    }
}

/// Get the cost for a specific operation
pub fn get_cost(op: OperationType) -> u64 {
    match op {
        OperationType::Syscall => COSTS.syscall,
        OperationType::TimerTick => COSTS.timer_tick,
        OperationType::FrameAlloc => COSTS.frame_alloc,
        OperationType::DiskRead => COSTS.disk_read,
        OperationType::DiskWrite => COSTS.disk_write,
        OperationType::NetworkRequest => COSTS.network_request,
        OperationType::MailboxCreate => COSTS.mailbox_create,
        OperationType::WasmFuel => COSTS.wasm_fuel_unit,
    }
}

#[derive(Debug, Clone, Copy)]
pub enum OperationType {
    Syscall,
    TimerTick,
    FrameAlloc,
    DiskRead,
    DiskWrite,
    NetworkRequest,
    MailboxCreate,
    WasmFuel,
}

/// Per-agent cumulative energy consumption tracking (for accountd)
static mut CUMULATIVE_ENERGY: [u64; crate::agent::MAX_AGENTS] = [0; crate::agent::MAX_AGENTS];

/// Record energy consumption for an agent
pub fn record_consumption(agent_id: crate::agent::AgentId, amount: u64) {
    let idx = agent_id as usize;
    if idx < crate::agent::MAX_AGENTS {
        unsafe { CUMULATIVE_ENERGY[idx] = CUMULATIVE_ENERGY[idx].wrapping_add(amount); }
    }
}

/// Get cumulative energy consumed by an agent
pub fn get_cumulative(agent_id: crate::agent::AgentId) -> u64 {
    let idx = agent_id as usize;
    if idx < crate::agent::MAX_AGENTS {
        unsafe { CUMULATIVE_ENERGY[idx] }
    } else {
        0
    }
}
