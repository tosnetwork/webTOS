//! AOS Energy Accounting
//!
//! Implements per-agent execution budgeting. Every agent runs under an
//! energy budget that is decremented on timer ticks and syscall invocations.
//! When the budget reaches zero, the agent is suspended.

use crate::agent::{AgentId, EnergyUnit, TICK_ENERGY_COST, SYSCALL_ENERGY_COST};

/// Decrement energy for a running agent on timer tick.
///
/// Returns `true` if the agent still has budget remaining,
/// `false` if the budget is now exhausted.
pub fn tick_running(agent_id: AgentId) -> bool {
    let agent = match crate::agent::get_agent_mut(agent_id) {
        Some(a) => a,
        None => return false,
    };

    if agent.energy_budget >= TICK_ENERGY_COST {
        agent.energy_budget -= TICK_ENERGY_COST;
        agent.energy_budget > 0
    } else {
        agent.energy_budget = 0;
        false
    }
}

/// Decrement energy for a blocked agent on timer tick.
///
/// Blocked agents (e.g., BlockedRecv) must also consume budget;
/// otherwise an agent could block on an empty mailbox indefinitely
/// at zero cost.
///
/// Returns `true` if the agent still has budget remaining,
/// `false` if the budget is now exhausted.
pub fn tick_blocked(agent_id: AgentId) -> bool {
    let agent = match crate::agent::get_agent_mut(agent_id) {
        Some(a) => a,
        None => return false,
    };

    if agent.energy_budget >= TICK_ENERGY_COST {
        agent.energy_budget -= TICK_ENERGY_COST;
        agent.energy_budget > 0
    } else {
        agent.energy_budget = 0;
        false
    }
}

/// Charge a syscall cost to an agent's energy budget.
///
/// Prevents agents from avoiding budget consumption by performing
/// many cheap syscalls between timer ticks.
///
/// Returns `true` if the agent still has budget remaining,
/// `false` if the budget is now exhausted.
pub fn charge_syscall(agent_id: AgentId) -> bool {
    let agent = match crate::agent::get_agent_mut(agent_id) {
        Some(a) => a,
        None => return false,
    };

    if agent.energy_budget >= SYSCALL_ENERGY_COST {
        agent.energy_budget -= SYSCALL_ENERGY_COST;
        agent.energy_budget > 0
    } else {
        agent.energy_budget = 0;
        false
    }
}

/// Get the remaining energy budget for an agent.
pub fn get_remaining(agent_id: AgentId) -> EnergyUnit {
    match crate::agent::get_agent(agent_id) {
        Some(a) => a.energy_budget,
        None => 0,
    }
}

/// Replenish an agent's energy budget by the given amount.
///
/// Used for `sys_energy_grant` (future) and root-level budget management.
pub fn replenish(agent_id: AgentId, amount: EnergyUnit) {
    if let Some(agent) = crate::agent::get_agent_mut(agent_id) {
        agent.energy_budget = agent.energy_budget.saturating_add(amount);
    }
}

/// Transfer energy from one agent (parent) to another (child).
///
/// Decreases the caller's budget by `amount` and increases the target's budget.
/// Returns an error if the caller lacks sufficient energy.
pub fn grant(from_id: AgentId, to_id: AgentId, amount: EnergyUnit) -> Result<(), i64> {
    // Check caller has enough energy
    let from_agent = match crate::agent::get_agent_mut(from_id) {
        Some(a) => a,
        None => return Err(crate::agent::E_INVALID_ARG),
    };

    if from_agent.energy_budget < amount {
        return Err(crate::agent::E_NO_BUDGET);
    }

    from_agent.energy_budget -= amount;

    // Add to the target agent
    let to_agent = match crate::agent::get_agent_mut(to_id) {
        Some(a) => a,
        None => return Err(crate::agent::E_INVALID_ARG),
    };

    to_agent.energy_budget = to_agent.energy_budget.saturating_add(amount);

    Ok(())
}
