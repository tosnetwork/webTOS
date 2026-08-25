# webTOS Smart Contract Example

**Status: conceptual example.**

This document walks through one possible flow for writing, packaging,
deploying, and calling a smart contract on webTOS. It explains the existing
kernel interfaces, but the code below is not a copy-and-run SDK tutorial: the
host-call functions are placeholders until the SDK exposes stable wrappers.

The `.tos` package suffix and the `tos` Wasm import namespace are kernel ABI
names. They remain unchanged while the product and browser runtime use the
webTOS name.

## Example: A Token Contract

### 1. Write the Contract (Rust → WASM)

```rust
// src/lib.rs
// Compile: cargo build --target wasm32-unknown-unknown --release

/// Read a u64 from the webTOS keyspace.
fn state_get(key: u64) -> u64 {
    let mut buf = [0u8; 8];
    unsafe {
        // webTOS host call: sys_state_get(key, buf_ptr, buf_len)
        core::arch::wasm32::unreachable(); // placeholder — real SDK provides this
    }
    u64::from_le_bytes(buf)
}

/// Write a u64 to the webTOS keyspace.
fn state_put(key: u64, value: u64) {
    let bytes = value.to_le_bytes();
    unsafe {
        // webTOS host call: sys_state_put(key, buf_ptr, buf_len)
        core::arch::wasm32::unreachable(); // placeholder
    }
}

/// Transfer tokens from caller to recipient.
///
/// Input layout (40 bytes):
///   [0..8]   caller key (u64 LE)
///   [8..16]  recipient key (u64 LE)
///   [16..24] amount (u64 LE)
///
/// Output: 1 byte — 0x01 = success, 0x00 = insufficient balance.
///
/// The WASM export name "transfer" maps to selector SHA-256("transfer")[:4].
#[no_mangle]
pub extern "C" fn transfer(input_len: i32) -> i32 {
    // Input is pre-written to linear memory at offset 0 by the webTOS runtime.
    let mem = unsafe { core::slice::from_raw_parts(0 as *const u8, input_len as usize) };

    let caller_key = u64::from_le_bytes(mem[0..8].try_into().unwrap());
    let recipient_key = u64::from_le_bytes(mem[8..16].try_into().unwrap());
    let amount = u64::from_le_bytes(mem[16..24].try_into().unwrap());

    let caller_balance = state_get(caller_key);
    if caller_balance < amount {
        // Write failure to output (offset 0, length prefix at bytes 0..4)
        unsafe {
            let out = 0 as *mut u8;
            core::ptr::write(out as *mut u32, 1); // output length = 1
            core::ptr::write(out.add(4), 0x00);   // failure
        }
        return 0;
    }

    state_put(caller_key, caller_balance - amount);
    state_put(recipient_key, state_get(recipient_key) + amount);

    unsafe {
        let out = 0 as *mut u8;
        core::ptr::write(out as *mut u32, 1); // output length = 1
        core::ptr::write(out.add(4), 0x01);   // success
    }
    0
}

/// Query the balance of an account.
///
/// Input layout (8 bytes):
///   [0..8] account key (u64 LE)
///
/// Output: 8 bytes — balance as u64 LE.
#[no_mangle]
pub extern "C" fn balance_of(input_len: i32) -> i32 {
    let mem = unsafe { core::slice::from_raw_parts(0 as *const u8, input_len as usize) };
    let account_key = u64::from_le_bytes(mem[0..8].try_into().unwrap());
    let balance = state_get(account_key);

    unsafe {
        let out = 0 as *mut u8;
        core::ptr::write(out as *mut u32, 8); // output length = 8
        core::ptr::copy_nonoverlapping(balance.to_le_bytes().as_ptr(), out.add(4), 8);
    }
    0
}
```

### 2. Build

```bash
# Compile to WASM
cargo build --target wasm32-unknown-unknown --release

# Package as a .tos file using the current CLI
atp build target/wasm32-unknown-unknown/release/token.wasm -o token.tos

# Sign with Ed25519
atp sign token.tos
```

### 3. Deploy

Submit a deployment request through the webTOS host interface. The native
reference build currently transports this request over TCP; the browser host
will expose the same logical request without making TCP part of the contract
ABI.

```
Request {
    request_type: Deploy (1),
    contract_id: [0; 32],          // zero = new deployment
    entry_point: "",
    input: <token.wasm bytes>,
    energy_limit: 500000,
    signature: <Ed25519 over request>,
}
```

webTOS returns:

```
Response {
    status: Success (0),
    output: <contract_id: 32 bytes>,   // SHA-256 of the WASM code
    energy_used: 12000,
    state_root: <Merkle root>,
    receipt_hash: <receipt ID>,
}
```

The `contract_id` (SHA-256 of the code) is used for all subsequent calls.

### 4. Call

**Transfer 100 tokens from account A to account B:**

```
Request {
    request_type: Call (2),
    contract_id: <from deploy response>,
    entry_point: "transfer",           // webTOS computes SHA-256("transfer")[:4]
    input: [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // caller key = 1
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // recipient key = 2
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // amount = 100
    ],
    energy_limit: 100000,
    signature: <Ed25519>,
}
```

webTOS returns:

```
Response {
    status: Success (0),
    output: [0x01],                    // success
    energy_used: 3500,
    state_root: <new Merkle root>,     // state changed
    receipt_hash: <receipt ID>,
}
```

**Query balance:**

```
Request {
    request_type: Call (2),
    contract_id: <same>,
    entry_point: "balance_of",
    input: [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  // account key = 2
    energy_limit: 50000,
    signature: <Ed25519>,
}
```

Returns:

```
Response {
    output: [0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],  // 100
}
```

### 5. Verify

A verifier can retrieve the signed execution receipt and the associated state
proof without trusting the executor:

```
Request { request_type: GetReceipt (5), input: [receipt_index...] }
→ ExecutionReceipt (360 bytes) with Ed25519 signature

Request { request_type: GetProof (6), input: [proof_index...] }
→ ProofBundle with Merkle sibling hashes
```

Verification steps:

1. Check Ed25519 signature over receipt hash.
2. Recompute receipt hash from fields, compare with `receipt_id`.
3. Optionally verify the Merkle path for a specific state key. This step is
   proportional to the tree depth, rather than constant time.

### 6. Inter-Contract Call

Contract A can call Contract B via mailbox:

```rust
// Inside Contract A's WASM code:
// 1. Build a ContractCallRequest
// 2. sys_send(B.mailbox, request_bytes)
// 3. sys_recv(A.mailbox) → ContractCallResponse
```

The energy for Contract B's execution is deducted from Contract A's budget (caller-pays model).

### 7. Optional: Manifest File

A `manifest.toml` can document the contract interface for client tooling. It
is not currently required by the webTOS kernel; it is a developer convenience.

```toml
[contract]
name = "token"
version = "1.0.0"
runtime = "wasm"
description = "Simple token with transfer and balance query"

[[functions]]
name = "transfer"
description = "Transfer tokens between accounts"

[[functions.inputs]]
name = "caller"
type = "u64"

[[functions.inputs]]
name = "recipient"
type = "u64"

[[functions.inputs]]
name = "amount"
type = "u64"

[[functions.outputs]]
name = "success"
type = "bool"

[[functions]]
name = "balance_of"
description = "Query account balance"

[[functions.inputs]]
name = "account"
type = "u64"

[[functions.outputs]]
name = "balance"
type = "u64"
```

### 8. Alternative: Linux ELF Contract

The same logic can be written as a Linux C program instead of WASM:

```c
// token.c — compile with: gcc -nostdlib -static -o token token.c
void _start() {
    // Read input from keyspace key 0xFFFF (pre-loaded by webTOS)
    // Parse function selector from first 4 bytes
    // Dispatch to transfer() or balance_of()
    // Write output to keyspace
    // sys_exit(0)
}
```

In the native reference environment this runs under the Linux compatibility
layer (`RuntimeKind::LinuxCompat`). Bringing this path to the browser also
requires the x86-64 Web execution engine. Energy metering is at the tick level,
not per instruction as it is for Wasm, so the receipt uses
`ReplayGradeNative` instead of `ProofGradeWasm`.

| Approach | Determinism | Energy Precision | Language Support |
|----------|-------------|-----------------|-----------------|
| WASM | Proof-grade (exact) | Per-instruction fuel | Rust, C, Go, AssemblyScript, any → WASM |
| Linux ELF | Replay-grade | Per-tick | Any language with Linux x86_64 compiler |
