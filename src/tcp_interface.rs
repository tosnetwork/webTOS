//! ATOS TCP External Interface Protocol (Yellow Paper §28)
//!
//! Defines the binary wire protocol for external clients to submit requests
//! (deploy, call, query, submit) and receive responses over a TCP connection.
//! All structures are fixed-size and `no_std`-compatible.

use crate::agent::{KeyspaceId, CAP_TARGET_WILDCARD, ROOT_AGENT_ID};
use crate::capability::{Capability, CapType};

// ─── Magic & version ───────────────────────────────────────────────────────

/// Wire protocol magic bytes: "ATSR" (ATOS Request).
const MAGIC: [u8; 4] = [0x41, 0x54, 0x53, 0x52];

/// Current protocol version.
const PROTOCOL_VERSION: u8 = 1;

// ─── RequestType ───────────────────────────────────────────────────────────

/// The type of an external request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestType {
    /// Deploy a new contract (WASM bytecode in `input`).
    Deploy = 1,
    /// Call a deployed contract's entry point.
    Call = 2,
    /// Query contract state (read-only, no state mutation).
    Query = 3,
    /// Submit a raw transaction.
    Submit = 4,
    /// Retrieve a full execution receipt by index.
    GetReceipt = 5,
    /// Retrieve a proof bundle by index.
    GetProof = 6,
    /// Retrieve a replay bundle by index.
    GetReplay = 7,
}

impl RequestType {
    /// Convert from a raw `u8` discriminant.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(RequestType::Deploy),
            2 => Some(RequestType::Call),
            3 => Some(RequestType::Query),
            4 => Some(RequestType::Submit),
            5 => Some(RequestType::GetReceipt),
            6 => Some(RequestType::GetProof),
            7 => Some(RequestType::GetReplay),
            _ => None,
        }
    }
}

// ─── ExternalRequest ───────────────────────────────────────────────────────

/// A fixed-size external request received over the TCP interface.
///
/// Wire format (little-endian):
///   magic:          [u8; 4]   — 0x41545352 ("ATSR")
///   version:        u8
///   request_id:     u64
///   request_type:   u8
///   contract_id:    [u8; 32]  — zero for Deploy/Submit
///   entry_point:    [u8; 32]  — function name (padded with zeroes)
///   entry_point_len: u8
///   input_len:      u16
///   input:          [u8; input_len]  (max 4096)
///   energy_limit:   u64
///   signature:      [u8; 64]  — Ed25519
pub struct ExternalRequest {
    pub request_id: u64,
    pub request_type: RequestType,
    /// Target contract identifier (zeroed for Deploy and Submit).
    pub contract_id: [u8; 32],
    /// Entry-point / method selector (UTF-8 name, zero-padded).
    pub entry_point: [u8; 32],
    /// Actual length of the entry_point name (max 32).
    pub entry_point_len: u8,
    /// Calldata buffer (fixed 4 KiB).
    pub input: [u8; 4096],
    /// Actual length of calldata in `input`.
    pub input_len: u16,
    /// Maximum energy (gas) budget for this execution.
    pub energy_limit: u64,
    /// Ed25519 signature over the request fields.
    pub signature: [u8; 64],
}

/// Minimum wire size: magic(4) + version(1) + request_id(8) + type(1)
///   + contract_id(32) + entry_point(32) + entry_point_len(1) + input_len(2)
///   + energy_limit(8) + signature(64) = 153 bytes (without input payload).
const REQUEST_HEADER_SIZE: usize = 4 + 1 + 8 + 1 + 32 + 32 + 1 + 2 + 8 + 64;

impl ExternalRequest {
    /// Parse an `ExternalRequest` from a raw byte buffer.
    ///
    /// Expected wire format:
    ///   [0..4]    magic "ATSR"
    ///   [4]       version (must be 1)
    ///   [5..13]   request_id   (u64 LE)
    ///   [13]      request_type (u8)
    ///   [14..46]  contract_id  ([u8; 32])
    ///   [46..78]  entry_point  ([u8; 32])
    ///   [78]      entry_point_len (u8)
    ///   [79..81]  input_len    (u16 LE)
    ///   [81..81+input_len]  input payload
    ///   [81+input_len .. 81+input_len+8]   energy_limit (u64 LE)
    ///   [81+input_len+8 .. 81+input_len+72] signature ([u8; 64])
    pub fn parse(buf: &[u8]) -> Option<Self> {
        // Minimum length check (header without variable input, plus energy+sig).
        if buf.len() < REQUEST_HEADER_SIZE {
            return None;
        }

        // Magic check
        if buf[0] != MAGIC[0] || buf[1] != MAGIC[1] || buf[2] != MAGIC[2] || buf[3] != MAGIC[3] {
            return None;
        }

        // Version check
        if buf[4] != PROTOCOL_VERSION {
            return None;
        }

        let request_id = u64::from_le_bytes([
            buf[5], buf[6], buf[7], buf[8],
            buf[9], buf[10], buf[11], buf[12],
        ]);

        let request_type = RequestType::from_u8(buf[13])?;

        let mut contract_id = [0u8; 32];
        contract_id.copy_from_slice(&buf[14..46]);

        let mut entry_point = [0u8; 32];
        entry_point.copy_from_slice(&buf[46..78]);

        let entry_point_len = buf[78];
        if entry_point_len > 32 {
            return None;
        }

        let input_len = u16::from_le_bytes([buf[79], buf[80]]);
        if input_len as usize > 4096 {
            return None;
        }

        // Check that buffer is large enough for the variable-length input + trailer.
        let trailer_start = 81 + input_len as usize;
        let total_needed = trailer_start + 8 + 64; // energy_limit + signature
        if buf.len() < total_needed {
            return None;
        }

        let mut input = [0u8; 4096];
        input[..input_len as usize].copy_from_slice(&buf[81..trailer_start]);

        let energy_limit = u64::from_le_bytes([
            buf[trailer_start],
            buf[trailer_start + 1],
            buf[trailer_start + 2],
            buf[trailer_start + 3],
            buf[trailer_start + 4],
            buf[trailer_start + 5],
            buf[trailer_start + 6],
            buf[trailer_start + 7],
        ]);

        let sig_start = trailer_start + 8;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&buf[sig_start..sig_start + 64]);

        Some(ExternalRequest {
            request_id,
            request_type,
            contract_id,
            entry_point,
            entry_point_len,
            input,
            input_len,
            energy_limit,
            signature,
        })
    }
}

// ─── ResponseStatus ────────────────────────────────────────────────────────

/// Status code returned in an external response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    /// Execution completed successfully.
    Success = 0,
    /// Contract explicitly reverted.
    Revert = 1,
    /// Energy budget exhausted.
    OutOfEnergy = 2,
    /// Internal error during execution.
    Error = 3,
    /// Target contract not found.
    NotFound = 4,
}

// ─── ExternalResponse ──────────────────────────────────────────────────────

/// A fixed-size external response sent back over the TCP interface.
pub struct ExternalResponse {
    /// Echoed request identifier.
    pub request_id: u64,
    /// Outcome of the request.
    pub status: ResponseStatus,
    /// Return data buffer (fixed 4 KiB).
    pub output: [u8; 4096],
    /// Actual length of return data in `output`.
    pub output_len: u16,
    /// Energy consumed by the execution.
    pub energy_used: u64,
    /// Post-execution Merkle state root.
    pub state_root: [u8; 32],
    /// Hash of the full ExecutionReceipt (for off-band retrieval).
    pub receipt_hash: [u8; 32],
}

impl ExternalResponse {
    /// Create an empty response for the given request id.
    pub fn new(request_id: u64) -> Self {
        ExternalResponse {
            request_id,
            status: ResponseStatus::Error,
            output: [0u8; 4096],
            output_len: 0,
            energy_used: 0,
            state_root: [0u8; 32],
            receipt_hash: [0u8; 32],
        }
    }

    /// Create an error response with the given status.
    pub fn error(request_id: u64, status: ResponseStatus) -> Self {
        let mut resp = Self::new(request_id);
        resp.status = status;
        resp
    }

    /// Serialize this response into `buf` in little-endian wire format.
    ///
    /// Wire layout:
    ///   [0..4]    magic "ATSR"
    ///   [4]       version
    ///   [5..13]   request_id   (u64 LE)
    ///   [13]      status       (u8)
    ///   [14..16]  output_len   (u16 LE)
    ///   [16..16+output_len]    output payload
    ///   [T..T+8]  energy_used  (u64 LE)
    ///   [T+8..T+40]  state_root  ([u8; 32])
    ///   [T+40..T+72] receipt_hash ([u8; 32])
    ///
    /// Returns the number of bytes written, or 0 if the buffer is too small.
    pub fn serialize(&self, buf: &mut [u8]) -> usize {
        let payload_len = self.output_len as usize;
        let total = 4 + 1 + 8 + 1 + 2 + payload_len + 8 + 32 + 32;
        if buf.len() < total {
            return 0;
        }

        // Magic
        buf[0] = MAGIC[0];
        buf[1] = MAGIC[1];
        buf[2] = MAGIC[2];
        buf[3] = MAGIC[3];

        // Version
        buf[4] = PROTOCOL_VERSION;

        // request_id
        let id_bytes = self.request_id.to_le_bytes();
        buf[5..13].copy_from_slice(&id_bytes);

        // status
        buf[13] = self.status as u8;

        // output_len
        let len_bytes = self.output_len.to_le_bytes();
        buf[14..16].copy_from_slice(&len_bytes);

        // output payload
        let trailer_start = 16 + payload_len;
        buf[16..trailer_start].copy_from_slice(&self.output[..payload_len]);

        // energy_used
        let eu_bytes = self.energy_used.to_le_bytes();
        buf[trailer_start..trailer_start + 8].copy_from_slice(&eu_bytes);

        // state_root
        let sr_start = trailer_start + 8;
        buf[sr_start..sr_start + 32].copy_from_slice(&self.state_root);

        // receipt_hash
        let rh_start = sr_start + 32;
        buf[rh_start..rh_start + 32].copy_from_slice(&self.receipt_hash);

        total
    }
}

// ─── Request handler dispatch ──────────────────────────────────────────────

/// Dispatch an external request and produce a response.
///
/// This is the main entry point for the TCP interface handler. It routes
/// the request to the appropriate subsystem based on `request_type`.
pub fn handle_request(req: &ExternalRequest) -> ExternalResponse {
    match req.request_type {
        RequestType::Deploy => handle_deploy(req),
        RequestType::Call   => handle_call(req),
        RequestType::Query  => handle_query(req),
        RequestType::Submit => handle_submit(req),
        RequestType::GetReceipt => handle_get_receipt(req),
        RequestType::GetProof => handle_get_proof(req),
        RequestType::GetReplay => handle_get_replay(req),
    }
}

// ─── Deploy handler ────────────────────────────────────────────────────────

/// Handle a Deploy request: register a new contract from WASM bytecode.
///
/// The contract bytecode is in `req.input[..req.input_len]`. A new agent is
/// spawned, its keyspace is initialised, and the contract is registered in
/// the contract registry.
fn handle_deploy(req: &ExternalRequest) -> ExternalResponse {
    use crate::contract::{self, ContractEntry, ContractStatus, EntryPoint, MAX_ENTRY_POINTS};

    let mut resp = ExternalResponse::new(req.request_id);

    let bytecode = &req.input[..req.input_len as usize];
    if bytecode.is_empty() {
        resp.status = ResponseStatus::Error;
        return resp;
    }

    // Compute a content-addressed contract id from the bytecode.
    let contract_id = contract::compute_contract_id(bytecode);

    // Allocate a stack for the new contract agent.
    let stack_top = crate::sched::allocate_agent_stack();
    if stack_top == 0 {
        resp.status = ResponseStatus::Error;
        return resp;
    }

    // Spawn a new agent with the WASM agent entry point.
    let agent_id = match crate::agent::create_agent(
        Some(ROOT_AGENT_ID),
        crate::agents::wasm_agent::wasm_agent_entry as *const () as u64,
        stack_top,
        req.energy_limit,
        256, // default memory quota in pages
    ) {
        Ok(id) => id,
        Err(_) => {
            resp.status = ResponseStatus::Error;
            return resp;
        }
    };

    // Create a mailbox for the new agent.
    let mailbox_id = agent_id;
    if crate::mailbox::create_mailbox(mailbox_id, agent_id).is_err() {
        resp.status = ResponseStatus::Error;
        return resp;
    }

    // Create a keyspace for the new agent.
    let ks = agent_id as KeyspaceId;
    if crate::state::create_keyspace(ks).is_err() {
        resp.status = ResponseStatus::Error;
        return resp;
    }

    // Store the WASM bytecode in the agent's keyspace using chunked large
    // value storage.  This supports contracts up to 64 KB (256 x 256-byte
    // chunks), bypassing the 256-byte single-entry limit.
    if crate::state::store_large_value(ks, bytecode).is_err() {
        resp.status = ResponseStatus::Error;
        return resp;
    }

    // Grant basic capabilities to the deployed contract agent:
    //   - RecvMailbox on its own mailbox (to receive call requests)
    //   - SendMailbox wildcard (to send responses back to callers)
    //   - StateRead/StateWrite on its own keyspace
    //   - EventEmit for logging
    if let Some(agent) = crate::agent::get_agent_mut(agent_id) {
        agent.capabilities[0] = Some(Capability::new(CapType::RecvMailbox, mailbox_id));
        agent.capabilities[1] = Some(Capability::new(CapType::SendMailbox, CAP_TARGET_WILDCARD));
        agent.capabilities[2] = Some(Capability::new(CapType::StateRead, ks));
        agent.capabilities[3] = Some(Capability::new(CapType::StateWrite, ks));
        agent.capabilities[4] = Some(Capability::new(CapType::EventEmit, 0));
        agent.cap_count = 5;
        agent.status = crate::agent::AgentStatus::Ready;
    }

    // Add the agent to the scheduler run queue.
    crate::sched::enqueue(agent_id);

    // Build a ContractEntry for the registry with the real agent and mailbox IDs.
    let entry = ContractEntry {
        id: contract_id,
        agent_id,
        mailbox_id,
        code_hash: contract_id,
        deployer: ROOT_AGENT_ID,
        deploy_tick: crate::arch::x86_64::timer::get_ticks(),
        status: ContractStatus::Deployed,
        entry_points: [EntryPoint { name: [0u8; 32], name_len: 0, selector: 0 }; MAX_ENTRY_POINTS],
        entry_point_count: 0,
    };

    match contract::register(entry) {
        Ok(_slot) => {
            // Retrieve the state root for the new agent's keyspace.
            if let Some(root) = crate::state::get_root(ks) {
                resp.state_root = root;
            }
            // Return the contract_id as output so the caller knows the address.
            resp.output[..32].copy_from_slice(&contract_id);
            resp.output_len = 32;
            resp.energy_used = 0;
            resp.receipt_hash = [0u8; 32];
            resp.status = ResponseStatus::Success;
        }
        Err(_) => {
            resp.status = ResponseStatus::Error;
        }
    }

    resp
}

// ─── Call handler ──────────────────────────────────────────────────────────

/// Handle a Call request: invoke an entry point on a deployed contract.
///
/// Dispatches calldata to the target contract's agent via the mailbox
/// subsystem and waits for a response.
fn handle_call(req: &ExternalRequest) -> ExternalResponse {
    use crate::contract::{self, ContractStatus};
    use crate::contract_call;

    let mut resp = ExternalResponse::new(req.request_id);

    // Look up the contract by contract_id.
    let contract_entry = match contract::lookup_by_id(&req.contract_id) {
        Some(entry) => entry,
        None => {
            resp.status = ResponseStatus::NotFound;
            return resp;
        }
    };

    // Verify the contract is in Deployed status.
    if contract_entry.status != ContractStatus::Deployed {
        resp.status = ResponseStatus::NotFound;
        return resp;
    }

    let agent_id = contract_entry.agent_id;
    let mailbox_id = contract_entry.mailbox_id;

    // Extract the entry point name and compute the 4-byte selector.
    let ep_name = &req.entry_point[..req.entry_point_len as usize];
    let selector = contract_call::compute_selector(ep_name);

    // Build a ContractCallRequest with the calldata.
    let call_req = contract_call::build_request(
        ROOT_AGENT_ID,   // external calls enter through the root agent
        selector,
        req.energy_limit,
        &req.input[..req.input_len as usize],
    );

    // Serialize the request into a mailbox-sized buffer and send it to the
    // contract agent's mailbox.  The serialization layout matches
    // contract_call::parse_request (caller(2) + selector(4) + energy(8) +
    // input_len(2) + input).
    let mut msg_buf = [0u8; 256];
    let mut off = 0;

    msg_buf[off..off + 2].copy_from_slice(&call_req.caller_agent.to_le_bytes());
    off += 2;
    msg_buf[off..off + 4].copy_from_slice(&call_req.selector.to_le_bytes());
    off += 4;
    msg_buf[off..off + 8].copy_from_slice(&call_req.energy_budget.to_le_bytes());
    off += 8;
    msg_buf[off..off + 2].copy_from_slice(&call_req.input_len.to_le_bytes());
    off += 2;
    let ilen = call_req.input_len as usize;
    msg_buf[off..off + ilen].copy_from_slice(&call_req.input[..ilen]);
    off += ilen;

    // Send the serialized request to the contract's mailbox.
    // Use ROOT_AGENT_ID as the sender since this is an external invocation.
    if crate::mailbox::send_message(ROOT_AGENT_ID, mailbox_id, &msg_buf[..off]).is_err() {
        resp.status = ResponseStatus::Error;
        return resp;
    }

    // Attach the current state root from the contract's keyspace.
    let ks = agent_id as KeyspaceId;
    if let Some(root) = crate::state::get_root(ks) {
        resp.state_root = root;
    }

    // The contract agent will process the request asynchronously on its next
    // scheduled tick.  Return a success/pending status with the energy budget
    // and current state root so the caller can poll for the result.
    resp.energy_used = contract_entry.deploy_tick; // echo deploy_tick as a reference marker
    resp.status = ResponseStatus::Success;
    resp
}

// ─── Query handler ─────────────────────────────────────────────────────────

/// Handle a Query request: read contract state without mutation.
///
/// The `entry_point` field is interpreted as a state key (first 8 bytes,
/// little-endian u64). The value is returned in `output`.
fn handle_query(req: &ExternalRequest) -> ExternalResponse {
    let mut resp = ExternalResponse::new(req.request_id);

    // Look up the contract by contract_id.
    let agent_id = match crate::contract::lookup_by_id(&req.contract_id).map(|e| e.agent_id) {
        Some(id) => id,
        None => {
            resp.status = ResponseStatus::NotFound;
            return resp;
        }
    };

    let ks = agent_id as KeyspaceId;

    // Interpret entry_point as a state key (u64 LE from first 8 bytes).
    if req.entry_point_len < 8 {
        resp.status = ResponseStatus::Error;
        return resp;
    }
    let key = u64::from_le_bytes([
        req.entry_point[0], req.entry_point[1],
        req.entry_point[2], req.entry_point[3],
        req.entry_point[4], req.entry_point[5],
        req.entry_point[6], req.entry_point[7],
    ]);

    // Read from the keyspace.
    match crate::state::state_get(ks, key) {
        Some((value_buf, value_len)) => {
            let copy_len = if value_len > 4096 { 4096 } else { value_len };
            resp.output[..copy_len].copy_from_slice(&value_buf[..copy_len]);
            resp.output_len = copy_len as u16;
            resp.status = ResponseStatus::Success;
        }
        None => {
            // Key not found — return success with empty output.
            resp.output_len = 0;
            resp.status = ResponseStatus::Success;
        }
    }

    // Attach the current state root.
    if let Some(root) = crate::state::get_root(ks) {
        resp.state_root = root;
    }

    resp.energy_used = 0; // Queries are free (read-only)
    resp
}

// ─── Submit handler ────────────────────────────────────────────────────────

/// Handle a Submit request: execute a raw transaction.
///
/// Similar to Call but for pre-encoded transaction payloads. The contract_id
/// may be zero (for system-level transactions) or target a specific contract.
fn handle_submit(req: &ExternalRequest) -> ExternalResponse {
    // Submit is functionally equivalent to Call for the single-instance VM.
    // The contract_id in the request identifies the target contract; the
    // input payload is treated as calldata just like a Call request.
    handle_call(req)
}

// ─── GetReceipt handler ───────────────────────────────────────────────────

/// Handle a GetReceipt request: retrieve a full execution receipt by index.
///
/// If `contract_id` is all zeros, `input[0..2]` is interpreted as a u16
/// index into the receipt store. Otherwise, `contract_id` is used as the
/// receipt hash to look up (linear scan).
fn handle_get_receipt(req: &ExternalRequest) -> ExternalResponse {
    let mut resp = ExternalResponse::new(req.request_id);

    let is_zero = req.contract_id.iter().all(|&b| b == 0);

    let receipt = if is_zero {
        // Use input[0..2] as a u16 index.
        if req.input_len < 2 {
            resp.status = ResponseStatus::Error;
            return resp;
        }
        let index = u16::from_le_bytes([req.input[0], req.input[1]]) as usize;
        crate::receipts::get_receipt(index)
    } else {
        // Linear scan by receipt_id matching contract_id field.
        let count = crate::receipts::receipt_count();
        let mut found = None;
        for i in 0..count {
            if let Some(r) = crate::receipts::get_receipt(i) {
                if r.receipt_id == req.contract_id {
                    found = Some(r);
                    break;
                }
            }
        }
        found
    };

    let receipt = match receipt {
        Some(r) => r,
        None => {
            resp.status = ResponseStatus::NotFound;
            return resp;
        }
    };

    // Serialize receipt fields into output buffer:
    //   receipt_id(32) + contract_id(32) + execution_id(32) + caller_id(32)
    //   + code_hash(32) + input_commitment(32) + output_commitment(32)
    //   + initial_state_root(32) + final_state_root(32)
    //   + energy_used(8) + tick_start(8) + tick_end(8)
    //   + signature(64) = 360 bytes total
    let mut pos = 0usize;
    resp.output[pos..pos + 32].copy_from_slice(&receipt.receipt_id);
    pos += 32;
    resp.output[pos..pos + 32].copy_from_slice(&receipt.contract_id);
    pos += 32;
    resp.output[pos..pos + 32].copy_from_slice(&receipt.execution_id);
    pos += 32;
    resp.output[pos..pos + 32].copy_from_slice(&receipt.caller_id);
    pos += 32;
    resp.output[pos..pos + 32].copy_from_slice(&receipt.code_hash);
    pos += 32;
    resp.output[pos..pos + 32].copy_from_slice(&receipt.input_commitment);
    pos += 32;
    resp.output[pos..pos + 32].copy_from_slice(&receipt.output_commitment);
    pos += 32;
    resp.output[pos..pos + 32].copy_from_slice(&receipt.initial_state_root);
    pos += 32;
    resp.output[pos..pos + 32].copy_from_slice(&receipt.final_state_root);
    pos += 32;
    resp.output[pos..pos + 8].copy_from_slice(&receipt.energy_used.to_le_bytes());
    pos += 8;
    resp.output[pos..pos + 8].copy_from_slice(&receipt.tick_start.to_le_bytes());
    pos += 8;
    resp.output[pos..pos + 8].copy_from_slice(&receipt.tick_end.to_le_bytes());
    pos += 8;
    resp.output[pos..pos + 64].copy_from_slice(&receipt.signature);
    pos += 64;

    resp.output_len = pos as u16; // 360
    resp.receipt_hash = receipt.receipt_id;
    resp.state_root = receipt.final_state_root;
    resp.energy_used = 0;
    resp.status = ResponseStatus::Success;
    resp
}

// ─── GetProof handler ─────────────────────────────────────────────────────

/// Handle a GetProof request: retrieve a proof bundle by index.
///
/// `input[0..2]` is interpreted as a u16 index into the proof bundle store.
fn handle_get_proof(req: &ExternalRequest) -> ExternalResponse {
    let mut resp = ExternalResponse::new(req.request_id);

    if req.input_len < 2 {
        resp.status = ResponseStatus::Error;
        return resp;
    }

    let index = u16::from_le_bytes([req.input[0], req.input[1]]) as usize;

    let proof = match crate::receipts::get_proof_bundle(index) {
        Some(p) => p,
        None => {
            resp.status = ResponseStatus::NotFound;
            return resp;
        }
    };

    // Serialize proof bundle into output:
    //   receipt_id(32) + proof_type(1) + proof_len(2) + proof_data(proof_len)
    //   + verifier_key(32)
    let mut pos = 0usize;
    resp.output[pos..pos + 32].copy_from_slice(&proof.receipt_id);
    pos += 32;
    resp.output[pos] = proof.proof_type;
    pos += 1;
    let plen = proof.proof_len.min(1024);
    resp.output[pos..pos + 2].copy_from_slice(&(plen as u16).to_le_bytes());
    pos += 2;
    resp.output[pos..pos + plen].copy_from_slice(&proof.proof_data[..plen]);
    pos += plen;
    resp.output[pos..pos + 32].copy_from_slice(&proof.verifier_key);
    pos += 32;

    resp.output_len = pos as u16;
    resp.receipt_hash = proof.receipt_id;
    resp.energy_used = 0;
    resp.status = ResponseStatus::Success;
    resp
}

// ─── GetReplay handler ────────────────────────────────────────────────────

/// Handle a GetReplay request: retrieve a replay bundle by index.
///
/// `input[0..2]` is interpreted as a u16 index into the replay bundle store.
fn handle_get_replay(req: &ExternalRequest) -> ExternalResponse {
    let mut resp = ExternalResponse::new(req.request_id);

    if req.input_len < 2 {
        resp.status = ResponseStatus::Error;
        return resp;
    }

    let index = u16::from_le_bytes([req.input[0], req.input[1]]) as usize;

    let replay = match crate::receipts::get_replay_bundle(index) {
        Some(r) => r,
        None => {
            resp.status = ResponseStatus::NotFound;
            return resp;
        }
    };

    // Serialize replay bundle into output:
    //   receipt_id(32) + checkpoint_len(2) + checkpoint_data(checkpoint_len)
    //   + transcript_len(2) + transcript(transcript_len)
    //   + initial_state_len(2) + initial_state(initial_state_len)
    let mut pos = 0usize;
    resp.output[pos..pos + 32].copy_from_slice(&replay.receipt_id);
    pos += 32;

    let ck_len = replay.checkpoint_len as usize;
    resp.output[pos..pos + 2].copy_from_slice(&replay.checkpoint_len.to_le_bytes());
    pos += 2;
    let ck_copy = ck_len.min(4096 - pos);
    resp.output[pos..pos + ck_copy].copy_from_slice(&replay.checkpoint_data[..ck_copy]);
    pos += ck_copy;

    let tr_len = replay.transcript_len as usize;
    resp.output[pos..pos + 2].copy_from_slice(&replay.transcript_len.to_le_bytes());
    pos += 2;
    let tr_copy = tr_len.min(4096 - pos);
    resp.output[pos..pos + tr_copy].copy_from_slice(&replay.transcript[..tr_copy]);
    pos += tr_copy;

    let is_len = replay.initial_state_len as usize;
    resp.output[pos..pos + 2].copy_from_slice(&replay.initial_state_len.to_le_bytes());
    pos += 2;
    let is_copy = is_len.min(4096 - pos);
    resp.output[pos..pos + is_copy].copy_from_slice(&replay.initial_state[..is_copy]);
    pos += is_copy;

    resp.output_len = pos as u16;
    resp.receipt_hash = replay.receipt_id;
    resp.energy_used = 0;
    resp.status = ResponseStatus::Success;
    resp
}
