//! TOS Inter-Contract Call Model
//!
//! Implements caller-pays energy semantics for contract-to-contract invocations
//! via mailbox message passing. The calling contract sends a `ContractCallRequest`
//! to the target contract's mailbox; the target processes it and (asynchronously)
//! returns a `ContractCallResponse` through the caller's mailbox.
//!
//! See docs/specs/yellowpaper.md for the full specification.

use crate::agent::{AgentId, E_INVALID_ARG, E_NOT_FOUND, E_NO_CAP};
use crate::capability::{agent_has_cap, CapType};
use crate::contract::{self, ContractId, ContractStatus};

// ─── Constants ──────────────────────────────────────────────────────────────

/// Maximum input payload size within a 256-byte request message.
///
/// Layout: caller_agent(2) + selector(4) + energy_budget(8) + input_len(2) = 16 bytes header.
/// Remaining: 256 - 16 = 240 bytes, but we use 236 to keep alignment and leave
/// 4 bytes of padding at the end.
const MAX_CALL_INPUT: usize = 236;

/// Maximum output payload size within a 256-byte response message.
///
/// Layout: status(1) + energy_used(8) + output_len(2) = 11 bytes header.
/// Remaining: 256 - 11 = 245, but we use 243 for alignment with 2 bytes padding.
const MAX_CALL_OUTPUT: usize = 243;

/// Response status codes.
pub const STATUS_SUCCESS: u8 = 0;
pub const STATUS_REVERT: u8 = 1;
pub const STATUS_OUT_OF_ENERGY: u8 = 2;
pub const STATUS_ERROR: u8 = 3;
/// The request was sent but the response has not yet arrived.
/// The caller should check its own mailbox (recv on `caller_id`) for a
/// `ContractCallResponse` from the callee.
pub const STATUS_PENDING: u8 = 4;

// ─── SHA-256 selector computation ───────────────────────────────────────────

use sha2::{Digest, Sha256};

/// Compute a 4-byte function selector from a function name using SHA-256.
///
/// Returns the first 4 bytes of the SHA-256 hash as a big-endian u32,
/// consistent with `crate::contract::compute_selector`.
pub fn compute_selector(name: &[u8]) -> u32 {
    let hash = Sha256::digest(name);
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}

// ─── ContractCallRequest ────────────────────────────────────────────────────

/// Inter-contract call request, sized to fit within a single 256-byte
/// mailbox message.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ContractCallRequest {
    /// Agent ID of the caller.
    pub caller_agent: u16,
    /// 4-byte function selector (SHA-256 hash of entry point name, first 4 bytes).
    pub selector: u32,
    /// Energy budget allocated by the caller for this invocation.
    pub energy_budget: u64,
    /// Actual length of meaningful data in `input`.
    pub input_len: u16,
    /// Input data (padded to fill the 256-byte message).
    pub input: [u8; MAX_CALL_INPUT],
}

/// Build a `ContractCallRequest` from components.
pub fn build_request(caller: u16, selector: u32, energy: u64, input: &[u8]) -> ContractCallRequest {
    let len = input.len().min(MAX_CALL_INPUT);
    let mut req = ContractCallRequest {
        caller_agent: caller,
        selector,
        energy_budget: energy,
        input_len: len as u16,
        input: [0u8; MAX_CALL_INPUT],
    };
    req.input[..len].copy_from_slice(&input[..len]);
    req
}

/// Parse a `ContractCallRequest` from raw mailbox message bytes.
///
/// Returns `None` if the buffer is too small or the embedded length field
/// exceeds the available payload.
pub fn parse_request(msg: &[u8]) -> Option<ContractCallRequest> {
    // Minimum header: caller_agent(2) + selector(4) + energy_budget(8) + input_len(2) = 16
    if msg.len() < 16 {
        return None;
    }

    let caller_agent = u16::from_le_bytes([msg[0], msg[1]]);
    let selector = u32::from_le_bytes([msg[2], msg[3], msg[4], msg[5]]);
    let energy_budget = u64::from_le_bytes([
        msg[6], msg[7], msg[8], msg[9], msg[10], msg[11], msg[12], msg[13],
    ]);
    let input_len = u16::from_le_bytes([msg[14], msg[15]]);

    if (input_len as usize) > MAX_CALL_INPUT {
        return None;
    }

    let available = msg.len().saturating_sub(16);
    if (input_len as usize) > available {
        return None;
    }

    let mut input = [0u8; MAX_CALL_INPUT];
    let copy_len = (input_len as usize).min(available);
    input[..copy_len].copy_from_slice(&msg[16..16 + copy_len]);

    Some(ContractCallRequest {
        caller_agent,
        selector,
        energy_budget,
        input_len,
        input,
    })
}

// ─── ContractCallResponse ───────────────────────────────────────────────────

/// Inter-contract call response, sized to fit within a single 256-byte
/// mailbox message.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ContractCallResponse {
    /// Outcome status: 0=success, 1=revert, 2=out_of_energy, 3=error.
    pub status: u8,
    /// Actual energy consumed by the callee during execution.
    pub energy_used: u64,
    /// Actual length of meaningful data in `output`.
    pub output_len: u16,
    /// Output data (padded to fill the 256-byte message).
    pub output: [u8; MAX_CALL_OUTPUT],
}

/// Build a `ContractCallResponse` from components.
pub fn build_response(status: u8, energy_used: u64, output: &[u8]) -> ContractCallResponse {
    let len = output.len().min(MAX_CALL_OUTPUT);
    let mut resp = ContractCallResponse {
        status,
        energy_used,
        output_len: len as u16,
        output: [0u8; MAX_CALL_OUTPUT],
    };
    resp.output[..len].copy_from_slice(&output[..len]);
    resp
}

/// Parse a `ContractCallResponse` from raw mailbox message bytes.
///
/// Returns `None` if the buffer is too small or the embedded length field
/// exceeds the available payload.
pub fn parse_response(msg: &[u8]) -> Option<ContractCallResponse> {
    // Minimum header: status(1) + energy_used(8) + output_len(2) = 11
    if msg.len() < 11 {
        return None;
    }

    let status = msg[0];
    let energy_used = u64::from_le_bytes([
        msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], msg[8],
    ]);
    let output_len = u16::from_le_bytes([msg[9], msg[10]]);

    if (output_len as usize) > MAX_CALL_OUTPUT {
        return None;
    }

    let available = msg.len().saturating_sub(11);
    if (output_len as usize) > available {
        return None;
    }

    let mut output = [0u8; MAX_CALL_OUTPUT];
    let copy_len = (output_len as usize).min(available);
    output[..copy_len].copy_from_slice(&msg[11..11 + copy_len]);

    Some(ContractCallResponse {
        status,
        energy_used,
        output_len,
        output,
    })
}

// ─── Serialisation helpers ──────────────────────────────────────────────────

/// Serialise a `ContractCallRequest` into a byte buffer suitable for
/// `mailbox::send_message`.  Returns the number of bytes written.
fn serialise_request(req: &ContractCallRequest, buf: &mut [u8]) -> usize {
    if buf.len() < 16 + req.input_len as usize {
        return 0;
    }

    buf[0..2].copy_from_slice(&req.caller_agent.to_le_bytes());
    buf[2..6].copy_from_slice(&req.selector.to_le_bytes());
    buf[6..14].copy_from_slice(&req.energy_budget.to_le_bytes());
    buf[14..16].copy_from_slice(&req.input_len.to_le_bytes());

    let ilen = req.input_len as usize;
    buf[16..16 + ilen].copy_from_slice(&req.input[..ilen]);

    16 + ilen
}

// ─── Core call_contract function ────────────────────────────────────────────

/// Initiate an inter-contract call via mailbox message passing.
///
/// This performs the caller-side of the invocation protocol:
///
/// 1. Resolve the target contract from the registry.
/// 2. Verify the caller holds `CAP_SEND_MAILBOX` for the target's mailbox.
/// 3. Transfer `energy_limit` energy from the caller to the callee agent.
/// 4. Serialise a `ContractCallRequest` and deliver it to the callee's mailbox.
/// 5. Emit an audit event recording the inter-contract call.
/// 6. Attempt a non-blocking receive on the caller's own mailbox for the
///    response. If the callee has already processed the request (e.g. it
///    was scheduled between steps 4 and 6), the real result is returned.
///    Otherwise returns `STATUS_PENDING` — the caller must poll its own
///    mailbox (agent_id == mailbox_id in Stage-1) for the
///    `ContractCallResponse`.
///
/// # Errors
///
/// Returns `Err(E_NOT_FOUND)` if the target contract is not in the registry
/// or is not in `Deployed` status.
/// Returns `Err(E_NO_CAP)` if the caller lacks send permission for the
/// target's mailbox.
/// Returns `Err(E_INVALID_ARG)` if the input exceeds the maximum size.
/// Forwards any error from `energy::grant` or `mailbox::send_message`.
pub fn call_contract(
    caller_id: u16,
    target_contract_id: &[u8; 32],
    selector: u32,
    input: &[u8],
    energy_limit: u64,
) -> Result<ContractCallResponse, i64> {
    // 1. Look up the target contract in the registry.
    let contract_entry = match contract::lookup_by_id(target_contract_id) {
        Some(c) => c,
        None => return Err(E_NOT_FOUND),
    };

    // Verify contract is in deployed status.
    if contract_entry.status != ContractStatus::Deployed {
        return Err(E_NOT_FOUND);
    }

    let callee_agent_id: AgentId = contract_entry.agent_id;
    let callee_mailbox: u16 = contract_entry.mailbox_id;

    // 2. Check caller has CAP_SEND_MAILBOX for the target's mailbox.
    if !agent_has_cap(caller_id, CapType::SendMailbox, callee_mailbox) {
        crate::event::cap_denied(
            caller_id,
            CapType::SendMailbox as u64,
            callee_mailbox as u64,
        );
        return Err(E_NO_CAP);
    }

    // Validate input length.
    if input.len() > MAX_CALL_INPUT {
        return Err(E_INVALID_ARG);
    }

    // 3. Transfer energy from caller to callee (caller-pays semantics).
    crate::energy::grant(caller_id, callee_agent_id, energy_limit)?;

    // 4. Build the request and send it to the callee's mailbox.
    let req = build_request(caller_id, selector, energy_limit, input);

    let mut msg_buf = [0u8; 256];
    let msg_len = serialise_request(&req, &mut msg_buf);

    // send_message handles its own capability check via agent_try_cap, but we
    // already verified with agent_has_cap above so it should pass.
    crate::mailbox::send_message(caller_id, callee_mailbox, &msg_buf[..msg_len])?;

    // 5. Emit an audit event for the inter-contract call.
    //    arg0 = callee agent ID, arg1 = selector
    crate::event::emit(
        caller_id,
        crate::event::EventType::MailboxSend,
        callee_agent_id as u64,
        selector as u64,
        0,
    );

    // 6. Try a non-blocking receive on the caller's own mailbox.
    //    In Stage-1, mailbox_id == agent_id (1:1 binding).
    //    If the callee happened to run synchronously (e.g. in a cooperative
    //    scheduling window), its response may already be waiting.
    let caller_mailbox: u16 = caller_id;
    if let Ok(msg) = crate::mailbox::recv_message(caller_id, caller_mailbox) {
        // Try to parse the received message as a ContractCallResponse.
        let payload = &msg.payload[..msg.len as usize];
        if let Some(resp) = parse_response(payload) {
            return Ok(resp);
        }
        // Received a message but it wasn't a valid ContractCallResponse.
        // Re-enqueue it so unrelated messages aren't lost.
        let _ = crate::mailbox::send_message(caller_id, caller_mailbox, payload);
        return Ok(build_response(STATUS_PENDING, 0, &[]));
    }

    // No response available yet. Return STATUS_PENDING so the caller knows
    // the request was sent and it should poll its own mailbox for the real
    // ContractCallResponse from the callee.
    Ok(build_response(STATUS_PENDING, 0, &[]))
}
