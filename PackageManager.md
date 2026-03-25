# ATOS Package Manager — Design Document

**Status:** Design Document
**Companion to:** Yellow Paper §27.4 (Stage-7)
**Depends on:** skilld agent, WASM engine integration, Ristretto integration

> This document defines `atp` — the ATOS package manager. It plays the same role as `apt` on Debian or `cargo install` in Rust, but built on ATOS primitives: agents, capabilities, keyspaces, and cryptographic verification.

---

## 1. Why Not Just apt

apt solves packaging for a shared-everything OS. ATOS is a shared-nothing OS. The problems are fundamentally different:

| apt problem | ATOS non-problem |
|-------------|-----------------|
| Dependency resolution (libssl 1.1 vs 3.0) | Agents are self-contained, no shared libraries |
| File conflicts (/usr/bin/python) | No filesystem, no path collisions |
| Post-install scripts running as root | No root, no scripts — just spawn an agent with declared capabilities |
| Partial upgrade leaving broken state | Atomic: new agent succeeds or old agent stays |
| Rollback requires snapshot of entire system | Checkpoint single agent + its keyspace |

ATOS needs a package manager not for dependency management, but for **lifecycle management**: install, upgrade, rollback, verify, and uninstall agents with signed provenance and capability control.

## 2. Package Format: `.tos`

An ATOS package is a simple archive containing a manifest and one or more binaries:

```
my-agent-1.2.0.tos
├── manifest.toml          # Package metadata
├── agent.wasm             # or agent.jar, agent.elf
└── signature.ed25519      # Ed25519 signature over manifest + binary hash
```

### 2.1 Manifest

```toml
[package]
name = "web-search"
version = "1.2.0"
description = "Web search skill for AI agents"
runtime = "wasm"                    # wasm | java | native
entry = "agent.wasm"               # binary filename within package
hash = "sha256:a1b2c3d4..."        # content hash of the binary

[author]
name = "Alice"
pubkey = "ed25519:AAAA..."         # public key for signature verification

[requirements]
capabilities = ["Network", "StateWrite"]   # capabilities the agent needs
energy = 100000                            # minimum energy budget to run
memory_pages = 64                          # memory quota (pages)
atos_version = ">=2.0"                     # minimum ATOS kernel version

[upgrade]
from_versions = ["1.0.0", "1.1.0"]        # versions this can upgrade from
state_migration = "auto"                    # auto | manual | none
rollback_safe = true                        # can safely rollback to previous version
```

### 2.2 Signature

The `signature.ed25519` file contains a signature over `sha256(manifest.toml || binary_hash)`. The signer's public key is embedded in the manifest. Verification requires no external PKI — the installing agent decides which public keys it trusts.

### 2.3 Content Addressing

Packages are identified by their content hash, not by name+version. This enables:
- Deduplication (same binary = same hash, stored once)
- Integrity verification (download from anywhere, verify hash)
- Reproducible builds (same source → same hash → same package)

```
atp:sha256:a1b2c3d4...   ← globally unique, content-addressed
```

## 3. Architecture

```
┌─────────────────────────────────────────────────────┐
│  atp install web-search-1.2.0.tos             │
│  (CLI tool, runs on developer machine)              │
└─────────────────┬───────────────────────────────────┘
                  │ writes .tos to Agent Storage Region
                  │ or sends via serial/network
                  ▼
┌─────────────────────────────────────────────────────┐
│  pkgd (Package Manager Agent)                       │
│  - Reads .tos from storage or mailbox              │
│  - Verifies signature + manifest                    │
│  - Checks capability subset rule                    │
│  - Calls skilld to spawn the agent                  │
│  - Records version metadata in its keyspace         │
│  - Manages upgrade / rollback lifecycle             │
└─────────────────┬───────────────────────────────────┘
                  │
          ┌───────┴───────┐
          ▼               ▼
┌──────────────┐  ┌──────────────┐
│   skilld     │  │  Keyspace    │
│ (spawn agent)│  │ (pkg metadata│
│              │  │  + versions) │
└──────────────┘  └──────────────┘
```

### 3.1 pkgd — Package Manager Agent

A new system agent (like policyd, stated, netd) that manages the package lifecycle:

| Operation | Protocol |
|-----------|----------|
| `install` | Receive .tos bytes → verify → skilld spawn → record metadata |
| `upgrade` | Receive new .tos → checkpoint old agent → spawn new → migrate keyspace → terminate old |
| `rollback` | Restore checkpoint of previous version (code + state) |
| `uninstall` | Terminate agent → clean keyspace → remove metadata |
| `list` | Return all installed packages with versions |
| `info` | Return metadata for a specific package |
| `verify` | Re-verify signature and hash of an installed package |

### 3.2 Mailbox Protocol

```
Install:
  Agent → pkgd: { op: "install", pkg_bytes: [...] }
  Agent ← pkgd: { status: "ok", agent_id: 42, version: "1.2.0" }

Upgrade:
  Agent → pkgd: { op: "upgrade", name: "web-search", pkg_bytes: [...] }
  Agent ← pkgd: { status: "ok", old_version: "1.1.0", new_version: "1.2.0" }

Rollback:
  Agent → pkgd: { op: "rollback", name: "web-search" }
  Agent ← pkgd: { status: "ok", restored_version: "1.1.0" }

List:
  Agent → pkgd: { op: "list" }
  Agent ← pkgd: { packages: [{ name, version, agent_id, runtime, status }, ...] }

Uninstall:
  Agent → pkgd: { op: "uninstall", name: "web-search" }
  Agent ← pkgd: { status: "ok" }
```

## 4. CLI Tool: `atp`

Runs on the developer's machine (Linux/macOS), communicates with ATOS via serial or network.

```bash
# Build a package from source
atp build ./my-agent/
# → my-agent-1.2.0.tos

# Sign a package
atp sign my-agent-1.2.0.tos --key ~/.tos/signing-key.ed25519
# → signature.ed25519 embedded in package

# Install to a running ATOS instance
atp install my-agent-1.2.0.tos --target serial:/dev/ttyUSB0
atp install my-agent-1.2.0.tos --target udp:192.168.1.100:9000

# Manage packages on a running instance
atp list --target serial:/dev/ttyUSB0
atp upgrade web-search --target udp:192.168.1.100:9000
atp rollback web-search --target serial:/dev/ttyUSB0
atp uninstall web-search --target serial:/dev/ttyUSB0

# Verify a package offline (no ATOS instance needed)
atp verify my-agent-1.2.0.tos --pubkey alice.pub
```

## 5. Upgrade Lifecycle

```
v1.0.0 running                    v1.1.0 arrives
┌──────────┐                      ┌──────────┐
│ Agent A  │                      │ .tos    │
│ keyspace │                      │ (new bin)│
│ caps     │                      └────┬─────┘
└────┬─────┘                           │
     │                                 ▼
     │                        ┌──────────────────┐
     │  1. checkpoint ───────>│ pkgd             │
     │                        │ 2. verify sig    │
     │                        │ 3. check caps ⊆  │
     │                        │ 4. spawn new     │
     │                        │ 5. migrate state │
     │  6. terminate old <────│ 7. record version│
     │                        └──────────────────┘
     ▼
v1.1.0 running
┌──────────┐
│ Agent A' │  (same agent_id slot, new binary, migrated state)
│ keyspace │
│ caps     │
└──────────┘

Rollback: restore checkpoint from step 1 → v1.0.0 with original state
```

### 5.1 Atomic Upgrade Guarantee

```
Success path:
  checkpoint old → spawn new → migrate state → verify new runs → terminate old
  ✓ At no point are both old and new serving simultaneously

Failure path:
  checkpoint old → spawn new → new crashes during startup
  → restore old from checkpoint → old resumes exactly where it was
  ✓ No downtime, no data loss, no partial state
```

### 5.2 State Migration

Three modes declared in manifest:

| Mode | Behavior |
|------|----------|
| `auto` | Copy all keyspace entries from old to new agent |
| `manual` | New agent's `on_upgrade(old_keyspace)` entry point handles migration |
| `none` | New agent starts with empty keyspace (stateless service) |

## 6. Registry (Future)

Phase 1 uses local `.tos` files (CLI → serial/network → pkgd).

Phase 2 adds registry support:

```bash
# Publish to a registry
atp publish my-agent-1.2.0.tos --registry https://pkg.tos.network

# Install from registry
atp install web-search@1.2.0 --registry https://pkg.tos.network --target ...

# Search
atp search "web search" --registry https://pkg.tos.network
```

Registry is a simple content-addressed store:
- Upload: `PUT /pkg/{sha256-hash}` with `.tos` body
- Download: `GET /pkg/{sha256-hash}` → `.tos` body
- Search: `GET /search?q=...` → manifest list
- No server-side trust needed — packages are self-verifying (signature + hash)

## 7. Comparison with Linux Package Managers

| Feature | apt (Debian) | atp (ATOS) |
|---------|-------------|-------------|
| Dependency resolution | Complex (SAT solver) | **None needed** (self-contained agents) |
| Shared libraries | Yes (DLL hell) | **No** (agents are isolated) |
| Post-install scripts | Yes (arbitrary root scripts) | **No** (just spawn an agent) |
| Rollback | Difficult (snapshot entire FS) | **Trivial** (checkpoint single agent) |
| Signature verification | At download time | **At install + at runtime** (ProofGrade) |
| Upgrade atomicity | No (can leave partial state) | **Yes** (checkpoint → spawn → verify → switch) |
| Permission escalation | Possible (setuid, sudoers) | **Impossible** (capability subset rule) |
| Multi-version coexistence | Difficult (alternatives) | **Trivial** (each version is a separate agent) |
| Reproducible builds | Optional | **Required** (content-addressed by hash) |
| Offline verification | GPG key check | **Full execution proof** (third party can verify) |

## 8. Implementation Phases

### Phase 1: pkgd Agent + CLI (Stage-4 closure)

- Define `.tos` format (TOML manifest + binary + signature)
- Implement `pkgd` system agent (~300 lines): install, list, uninstall
- Implement `atp build/sign/install/list` CLI commands
- Transport: serial protocol (write to Agent Storage Region)

### Phase 2: Upgrade & Rollback (Stage-7)

- Checkpoint-based upgrade lifecycle
- State migration (auto/manual/none)
- Rollback to previous checkpoint
- Version metadata in pkgd's keyspace

### Phase 3: Registry & Distribution (Stage-7+)

- Content-addressed remote registry
- `atp publish/search` commands
- Cross-node package distribution via routerd
- Canary rollout (partial traffic to new version)

## 9. Relationship to Other System Agents

```
pkgd (package lifecycle)
  ├── skilld (spawn/terminate agents)
  ├── stated (persist version metadata)
  ├── policyd (eBPF policy for install/upgrade events)
  └── netd (registry access for remote packages)
```

pkgd does not spawn agents directly — it delegates to skilld. pkgd's role is the **lifecycle layer** on top: versioning, signing, upgrade orchestration, rollback. skilld's role is the **execution layer**: validate WASM/JAR, check capabilities, spawn.
