# A Study of AI-Fi Development Methods Based on webTOS

**Version:** Draft v1.0 · 2026-08-29  
**Status:** Research and architecture proposal  
**webTOS baseline:** `e6eef9d981ac6331539d5454e98abfd29f556741`  
**Scope:** webTOS browser applications, TOS Agent applications, and AI-Fi application development

> **Status boundary.** This document combines capabilities that already exist
> in webTOS, authority and commerce concepts defined by the TOS Service
> Protocol repositories, and proposed browser integration APIs. Proposed names,
> manifests, host calls, SDKs, and evidence formats in this paper are not claims
> of shipped functionality. The live status of webTOS remains controlled by the
> [README](../README.md), [Roadmap](../ROADMAP.md), and
> [Use Cases](USE-CASES.md).

---

## Abstract

AI agents are evolving from conversational interfaces into software processes
that inspect data, modify repositories, invoke tools, discover services,
negotiate terms, purchase resources, deliver results, and receive payment. A
conventional web application can present these actions, but it normally cannot
host the underlying Linux agent locally. A conventional blockchain application
can authorize and settle value, but it does not provide the operating
environment in which an unmodified agent executes. An AI-Fi application needs
both layers and must connect them without giving an untrusted or model-driven
process unrestricted access to credentials, networks, or funds.

This paper studies a development method for AI-Fi applications built on
webTOS. webTOS supplies a browser-local Linux x86-64 execution environment with
processes, threads, a virtual filesystem, pseudoterminals, sockets, persistent
state, explicit network authority, resource budgets, content-addressed image
delivery, and deterministic execution gates. TOS supplies the complementary
trust and economic plane: portable Agent identity, Capability resolution,
signed operations, optional commercial agreements, payment authorization,
receipts, and settlement based on finalized TOS state.

The central design result is a strict separation of concerns:

```text
AI proposes and executes.
Deterministic policy authorizes.
The custody boundary signs.
TOS finality establishes canonical economic facts.
```

The paper defines a layered architecture, trust boundaries, a proposed
application manifest, browser and guest SDK surfaces, buyer and provider
workflows, persistence and recovery rules, an execution-evidence model, a
security threat model, and a staged implementation methodology. It also
proposes conformance gates for proving that an AI-Fi application is not merely
a web interface connected to a privileged wallet, but a bounded autonomous
application whose code, authority, spending, execution, and settlement can be
independently inspected.

**Keywords:** webTOS, AI-Fi, autonomous agents, agentic Internet, browser
runtime, local-first software, capability security, TOS Network, agent
commerce, deterministic execution, verifiable images, settlement

---

## 1. Introduction

### 1.1 The development problem

Most current Agent applications use the following architecture:

```text
Browser UI
    |
    v
Application server
    |
    +-- cloud container or VM
    +-- Agent runtime
    +-- user data and credentials
    +-- wallet or billing integration
```

This architecture is convenient, but the application operator becomes the
custodian of execution, data, credentials, and failure risk. The operator also
pays for idle environments and must secure a multi-tenant execution fleet.
Installing the Agent directly on the user's machine removes some cloud custody,
but introduces installation friction and gives the process ambient access to
the host unless a separate sandbox is deployed and maintained.

webTOS creates a third execution location: an unmodified Linux x86-64 Agent can
run inside the user's browser tab. The browser supplies the outer sandbox and
webTOS supplies the inner process, filesystem, scheduling, networking, and
resource model. This changes the Web application from:

```text
frontend + remote backend
```

into:

```text
frontend + local Linux backend + optional remote services
```

TOS adds the missing economic layer. It allows an Agent application to resolve
identity and Capability state, discover counterparties through replaceable
Carriers or Gateways, promote selected terms into an explicit Agreement, and
use finalized TOS state for payments or settlement when shared public trust is
required.

The unresolved engineering question is how to join these systems safely.
Simply placing a wallet seed inside the guest would destroy the security value
of the runtime. Simply calling a privileged JavaScript wallet from model output
would turn prompt injection into transaction authority. Simply putting every
Agent message on-chain would make ordinary interaction expensive and slow.
Therefore, AI-Fi development requires an explicit method rather than a loose
collection of APIs.

### 1.2 Research questions

This paper addresses five questions:

1. How can a Web developer package an unmodified Linux Agent as a browser
   application without understanding x86 emulation or Linux syscall internals?
2. How should reasoning, execution, policy, custody, and settlement be separated
   so that autonomy does not imply unrestricted authority?
3. How can webTOS state and TOS economic state be connected without making a
   Gateway, browser origin, or model output the source of canonical truth?
4. What evidence can a browser-local runtime produce, and how should that
   evidence be distinguished from hardware attestation?
5. What staged development and test process can move from a local Agent demo to
   a bounded autonomous buyer or provider application?

### 1.3 Contributions

The paper contributes:

- a precise definition of an AI-Fi Web application;
- a layered webTOS–TOS architecture and trust model;
- ten non-negotiable security and economic invariants;
- a proposed developer abstraction built around image, execution, mount,
  capability, policy, custody, and evidence;
- buyer, provider, and coordinator application methods;
- a crash-safe state and recovery model;
- a proposed evidence bundle that does not overclaim attestation;
- a reference application pattern for autonomous compute procurement; and
- an implementation roadmap with falsifiable exit gates.

### 1.4 Method

This is a design-science study. It derives an application method from the
current constraints and capabilities of webTOS and from the authority model of
TOS Service Protocol. The method is evaluated against compatibility,
confinement, custody safety, economic correctness, reproducibility,
deployability, and user comprehensibility. It is not an adoption study and
makes no market-size, revenue, or token-price prediction.

---

## 2. Foundations and Status Boundary

### 2.1 What webTOS contributes today

webTOS is not a JavaScript UI framework. Vue, React, or Svelte may still be
used for the interface. webTOS is the execution substrate beneath that
interface. Its current repository provides the major primitives needed by an
Agent application:

- execution of unmodified Linux x86-64 ELF programs;
- dynamic linking, processes, threads, signals, futexes, polling, and epoll;
- pseudoterminals suitable for shells and full-screen Agent TUIs;
- a virtual filesystem with browser persistence and snapshot restore;
- guest-side DNS and TLS over a deny-by-default byte relay;
- runtime budgets for memory, CPU, storage, network bytes, and event logs;
- scoped secret injection kept out of filesystem snapshots;
- deterministic time, randomness, scheduling, and event ordering;
- architectural trace gates across Chromium, Firefox, and WebKit;
- content-addressed manifests and lazy image chunks; and
- an interpreter-first execution model with verified p-code-to-Wasm
  translation for supported hot paths.

These properties are unusually well aligned with Agent workloads. An Agent is
not only a model call. It is a long-running Unix process that needs a workspace,
subprocesses, package tools, network access, credentials, interruption,
recovery, and a terminal. The current webTOS roadmap uses real OpenFox, Codex,
and Claude Code workloads as gates rather than treating syscall counts as a
product definition.

### 2.2 What webTOS does not contribute today

Several boundaries must remain explicit:

- webTOS does not currently expose the JavaScript SDK proposed in this paper;
- it does not currently include a browser TOS wallet or TOS Agent bridge;
- deterministic replay is not hardware attestation;
- the current browser runtime does not produce a third-party-verifiable signed
  execution certificate binding code, input, state, and output;
- browser-host recording and export remain less complete than the native
  recording path;
- a browser tab is not an always-on server and cannot guarantee provider
  availability after suspension or closure; and
- the browser runtime is not a high-performance replacement for remote GPU,
  large-memory, or continuously available infrastructure.

The proposed AI-Fi layer must build on real webTOS properties without silently
reintroducing removed or unimplemented features.

### 2.3 What TOS contributes

TOS is the trust and coordination plane for the Agentic Internet. The relevant
TOS Service Protocol architecture separates:

```text
finalized TOS state
    identity, delegation, custody, value, optional agreement and settlement

signed Agent operations
    authorization, replay identity, ordering, audience, payload commitments

replaceable propagation
    direct links, Messenger, Mailbox, relays, Gateways, DHT and local indexes

Agent runtimes
    AI interpretation, deterministic policy, skills, resources and memory

applications
    communication, discovery, Gifts, paid work, compute, data and other uses
```

The TOS repositories define Agent and Capability objects, signed operation
patterns, Quote and Agreement concepts, software-work execution and Receipt
structures, buyer and provider SDK boundaries, transaction relay profiles, and
settlement rules. Their own specifications and roadmaps remain authoritative
for implementation and deployment status. This paper treats those interfaces
as an external trust substrate and does not replace their canonical schemas.

### 2.4 The missing integration layer

webTOS answers:

> Where and under what local resource authority does the Agent execute?

TOS answers:

> Who is authorized, what terms are canonical, and what economic outcome is
> finalized?

The missing layer must answer:

> How does an untrusted local Agent request identity, network, signing,
> spending, discovery, and settlement operations without possessing the
> underlying authority?

That layer is the proposed **webTOS Agent Application Layer**.

---

## 3. Defining an AI-Fi Application

### 3.1 Definition

In this paper, **AI-Fi** means the application layer for autonomous economic
activity performed by AI Agents. It is broader than decentralized finance and
narrower than all AI software.

An AI-Fi application enables an Agent to perform some or all of the following
under explicit owner policy:

```text
identity
  -> discovery
  -> interpretation
  -> negotiation
  -> explicit agreement
  -> payment authorization
  -> execution
  -> receipt and evidence
  -> settlement or dispute
  -> reputation and local memory
```

The Agent may buy compute, data, storage, analysis, code work, or another
Agent's service. It may also advertise and sell a bounded Capability. Most
messages and bulk artifacts remain off-chain; TOS consensus is used only for
facts that require shared canonical authority.

### 3.2 The application equation

A useful development model is:

```text
AI-Fi Web App
    = Web UI
    + local Agent runtime
    + explicit capability broker
    + custody and policy boundary
    + TOS identity and settlement
    + execution and economic evidence
```

Vue.js or another UI framework controls presentation and interaction. webTOS
controls local Linux execution. The capability broker controls side effects.
The signer controls keys. TOS controls canonical economic facts.

### 3.3 Formal state model

An AI-Fi session can be modeled as:

```text
S = (I, W, P, R, C, E)
```

where:

- `I` is immutable image identity, including manifest root and runtime version;
- `W` is mutable guest workspace state;
- `P` is owner policy and granted capabilities;
- `R` is runtime state, resource budgets, process state, and event order;
- `C` is canonical TOS state relevant to identity, Agreement, payment, Receipt,
  and settlement; and
- `E` is the evidence set produced or collected by the application.

An external operation `o` is permitted only when:

```text
Allow(o) =
    VerifiedImage(I)
    AND AuthenticatedActor(o)
    AND CurrentCapability(o, C)
    AND PolicyAllows(o, P)
    AND BudgetAllows(o, P, R)
    AND FreshTerms(o, C)
    AND CorrectNetworkDomain(o)
```

For a canonical economic result, an additional condition is required:

```text
Canonical(o) = ExpectedFinalizedState(o, C)
```

A successful HTTP response, Gateway acknowledgement, relay submission, or
wallet broadcast is not sufficient.

### 3.4 Autonomy is not custody

A common design error is to equate an autonomous Agent with an Agent holding a
private key. That is unnecessary and dangerous. An Agent can autonomously
select a provider and request a transaction while a separate deterministic
policy and custody component decides whether the exact request is permitted.

The intended relationship is:

```text
model output
    -> proposed operation
    -> deterministic validation
    -> owner policy
    -> optional user confirmation
    -> custody signs exact bytes
    -> finality resolver verifies effect
```

The Agent is autonomous in planning and execution, but not sovereign over
authority that the owner did not grant.

---

## 4. Non-Negotiable Invariants

A webTOS AI-Fi application should preserve the following invariants.

### Invariant 1: No private key enters the guest

Mnemonic phrases, raw private keys, hardware-wallet secrets, and unrestricted
session signing keys must not be mounted into the webTOS filesystem, provided
as environment variables, or included in snapshots. The guest receives only a
narrow request interface.

### Invariant 2: AI interpretation cannot authorize a side effect

A model may recommend a provider, price, action, or transaction. A deterministic
policy engine must authorize network access, file access, signing, payment,
publication, and execution separately.

### Invariant 3: No ambient network

The guest starts without network access. Every reachable host and port is
explicitly granted, time bounded where practical, and accounted against a
network budget. The economic protocol does not justify general Internet
access.

### Invariant 4: Finalized TOS state is canonical

Gateways, indexes, relays, and application databases may improve discovery and
transport. They cannot establish Agent ownership, Capability version,
Agreement acceptance, payment, Receipt validity, or settlement.

### Invariant 5: Gateways remain replaceable

The application must retain enough signed objects, digests, identifiers, and
network-domain data to re-resolve state through another Gateway or directly
through independent TOS endpoints.

### Invariant 6: Bulk bytes stay off-chain

Prompts, source trees, model output, datasets, logs, and artifacts remain in
local or content-addressed storage. Signed operations and finalized state bind
them by digest when shared trust is necessary.

### Invariant 7: Ambiguous writes are resolved, not blindly repeated

After a transaction or payment may have been broadcast, the application must
resolve finalized state before constructing, signing, or paying again. A new
request identifier must never convert uncertainty into a duplicate economic
effect.

### Invariant 8: Snapshots exclude live authority

Guest workspace and process state may survive reload. Credentials, approval
tokens, wallet handles, and one-time signing capabilities must either be
excluded or invalidated and reissued after restore.

### Invariant 9: Reproducibility is not attestation

A manifest root and deterministic trace can help another party reproduce an
execution. They do not prove that an unmodified browser performed the execution
on trusted hardware. UI and protocol language must preserve that distinction.

### Invariant 10: The user can inspect and revoke authority

The interface must show the active image identity, network allowlist, mounted
paths, resource budgets, spending limits, counterparties, pending
confirmations, and revocation controls. Invisible capabilities are ambient
capabilities wearing a nicer name.

---

## 5. Layered Architecture

### 5.1 Overview

```text
+--------------------------------------------------------------+
| AI-Fi Web Application                                        |
| Vue / React / Svelte / HTML                                  |
| task UI, market UI, approvals, receipts, session dashboard   |
+-------------------------------+------------------------------+
                                |
                                v
+--------------------------------------------------------------+
| Proposed AI-Fi Application SDK                               |
| session, discovery, agreement, purchase, receipt, recovery   |
+-------------------------------+------------------------------+
                                |
                                v
+--------------------------------------------------------------+
| Browser Host and Authority Broker                            |
| policy, capability grants, signer adapter, finality resolver |
| origin binding, audit log, network gateway, secret injection |
+-------------------------------+------------------------------+
                                |
                    narrow typed host-service channel
                                |
                                v
+--------------------------------------------------------------+
| webTOS Guest                                                 |
| Linux x86-64 Agent, shell, tools, workspace, local memory    |
| no private key, no DOM, no ambient host filesystem/network   |
+-------------------------------+------------------------------+
                                |
             signed operations / content digests / exact bytes
                                |
                                v
+--------------------------------------------------------------+
| TOS Network and Replaceable Carriers                         |
| identity, Capability, Agreement, value, Receipt, settlement  |
| Gateway, Messenger, relay, DHT, content store, providers     |
+--------------------------------------------------------------+
```

### 5.2 UI layer

The UI remains an ordinary Web application. It should provide:

- task creation and progress views;
- workspace and terminal access where appropriate;
- capability and resource-budget panels;
- exact transaction and Agreement review;
- user confirmation for policy-selected actions;
- Receipt, artifact, and settlement views; and
- recovery status after reload or ambiguous network outcomes.

A UI framework does not need Agent-specific privileges. It calls the proposed
AI-Fi SDK, which exposes only policy-controlled operations.

### 5.3 webTOS runtime layer

The guest hosts the real Agent and its Unix tools. It may run Python, Node,
Bun, Rust tooling, shell commands, Git, Codex, Claude Code, OpenFox, or another
pinned Linux x86-64 workload supported by the compatibility gates.

The runtime owns:

- process and thread execution;
- the guest filesystem and workspace;
- terminal behavior;
- guest memory and scheduling;
- guest-side DNS and TLS;
- instruction and event accounting;
- snapshot and restore; and
- deterministic execution inputs that are under runtime control.

It does not own wallet custody or canonical TOS authority.

### 5.4 Browser authority broker

The browser host is the most important new component. It mediates every
external authority crossing and should be smaller and more auditable than the
Agent application itself.

It owns:

- image-manifest verification before guest execution;
- policy loading and validation;
- capability issuance and revocation;
- network relay configuration;
- scoped secret injection;
- TOS identity and finalized-state resolution;
- exact transaction construction or validation;
- access to an external signer or wallet;
- economic journals and idempotency fences; and
- append-only local audit events.

The browser origin is part of the trusted computing base for this broker. A
production application therefore also needs conventional Web security: strict
Content Security Policy, dependency pinning, subresource integrity where
applicable, isolated workers, no untrusted script injection, and a signer that
shows the exact action independently of the page.

### 5.5 TOS integration adapter

The TOS adapter maps application requests to existing TOS Service Protocol
objects and SDKs. It should not create a second Agent, Capability, Quote,
Receipt, or settlement schema merely for webTOS.

The adapter has five logical interfaces:

```text
Resolver       -> finalized Agent, Capability, Agreement and settlement state
Discovery      -> non-canonical candidate search and signed-object retrieval
Operation      -> canonical signed Agent operations and replay identity
Custody        -> exact signing or payment authorization outside the guest
Verifier       -> Receipt, artifact digest and finalized outcome verification
```

### 5.6 Provider execution layer

A provider may itself run in webTOS, in a native OpenFox process, in a cloud
worker, or on specialized hardware. The buyer should bind the provider's
Capability, version, execution signer, endpoint, price, deadline, and evidence
requirements before disclosing sensitive work or authorizing payment.

webTOS is especially suitable for the buyer-side personal Agent and for
interactive provider sessions owned by the user. Always-on, high-performance,
or hardware-attested providers will normally execute outside the tab while
participating in the same TOS commercial lifecycle.

### 5.7 Trust-boundary matrix

| Component | May propose | May execute | May sign or spend | May establish canonical TOS facts |
|---|---:|---:|---:|---:|
| AI model | Yes | Through approved tools | No | No |
| Guest Agent process | Yes | Yes, inside webTOS | No direct key access | No |
| Browser policy broker | No semantic planning required | Host operations only | May request exact custody action | No |
| Wallet or custody signer | No | Signing only | Yes, for exact reviewed bytes | No |
| Gateway or relay | May return candidates | Transport only | May pay bounded relay fees | No |
| TOS finalized state | No | Contract state transitions | Enforces authorized effects | Yes |
| Provider executor | May quote within policy | Yes | Provider-side authority only | No |

---

## 6. Proposed Developer Model

Everything in this section is an application-layer proposal. Names are
illustrative and should be frozen only after prototype and conformance work.

### 6.1 Project structure

A developer should be able to build an AI-Fi application with a familiar Web
project plus an Agent image and an authority policy:

```text
my-ai-fi-app/
|-- webtos.app.toml
|-- package.json
|-- ui/
|   |-- src/
|   `-- public/
|-- agent/
|   |-- Dockerfile
|   |-- entrypoint.sh
|   `-- app/
|-- policy/
|   `-- owner-policy.json
|-- manifests/
|   `-- agent-image.manifest
`-- tests/
    |-- policy/
    |-- browser/
    `-- economic/
```

The developer should not need to understand the x86 decoder, p-code, softmmu,
ELF relocation, futex semantics, or JIT internals. The public abstraction should
remain small:

```text
image -> spawn -> mount -> grant -> exec -> authorize -> verify -> snapshot
```

### 6.2 Proposed application manifest

The following manifest is illustrative, not a shipped schema:

```toml
schema = "webtos.agent-app.v1"
name = "autonomous-compute-buyer"
version = "0.1.0"

[image]
manifest_root = "sha256:<agent-image-root>"
entrypoint = ["/opt/agent/bin/buyer-agent"]
working_directory = "/workspace"

[runtime]
memory_bytes = 2147483648
cpu_instruction_budget = 5000000000
storage_bytes = 1073741824
network_bytes = 536870912
event_log_bytes = 67108864

[workspace]
mount = "/workspace"
persistence = "snapshot"

[network]
default = "deny"
allow = [
  "gateway.example:443",
  "content.example:443",
  "provider.example:443"
]

[tos]
network_id = "<exact-network-id>"
genesis_root_hash = "<exact-root-hash>"
genesis_file_hash = "<exact-file-hash>"
agent_id = "<owner-agent-id>"

[spending]
default = "deny"
assets = ["<exact-tos-asset-contract>"]
max_per_purchase_atomic = "50000000"
max_total_per_day_atomic = "250000000"
max_purchases_per_day = 20
confirmation = "policy-dependent"

[evidence]
record_runtime_events = true
bind_image_manifest = true
bind_input_digests = true
bind_output_digests = true
```

Important properties are exact network identity, exact asset identity, bounded
resources, deny-by-default network and spending, and an immutable image root.
A ticker symbol, human-readable host name, or mutable image tag is not enough
for an autonomous payment decision.

### 6.3 Proposed package boundaries

A clean implementation could expose four packages or modules:

| Package | Responsibility |
|---|---|
| `@webtos/runtime` | Spawn, execute, mount, terminal, budgets, snapshot and runtime events |
| `@tos/agent-web` | Identity resolution, signed Agent operations, discovery and messaging adapters |
| `@tos/ai-fi` | Agreement, policy-gated purchase, Receipt, settlement and recovery workflow |
| `tos-agentctl` | Narrow guest-side client for typed host capability requests |

These names are deliberately separate. The webTOS runtime must remain useful
without TOS, and TOS protocol libraries must remain useful outside a browser.
AI-Fi is a composition layer, not a reason to merge the execution engine with
the economic protocol.

### 6.4 Proposed browser API

The following TypeScript is pseudocode:

```ts
import { WebTOS } from "@webtos/runtime";
import { createAiFiSession } from "@tos/ai-fi";

const runtime = await WebTOS.create({
  image: {
    manifestRoot: "sha256:<agent-image-root>",
    source: new URL("/images/agent/", location.origin),
  },
  budgets: {
    memoryBytes: 2 * 1024 ** 3,
    cpuInstructions: 5_000_000_000n,
    storageBytes: 1024 ** 3,
    networkBytes: 512 * 1024 ** 2,
  },
});

await runtime.mountWorkspace("project", "/workspace");

const session = await createAiFiSession({
  runtime,
  policy: await loadOwnerPolicy(),
  resolver: finalizedTosResolver,
  discovery: federatedDiscoveryClient,
  custody: externalWalletAdapter,
  journal: ownerPrivateJournal,
});

await session.grantNetwork({
  destinations: ["gateway.example:443", "provider.example:443"],
  expiresAt: Date.now() + 60 * 60 * 1000,
});

const process = await runtime.exec([
  "/opt/agent/bin/buyer-agent",
  "--task",
  "/workspace/task.json",
]);

for await (const event of session.events()) {
  renderEvent(event);
}
```

The guest process may request discovery, agreement, or payment operations, but
the browser session decides whether to service them.

### 6.5 Proposed guest-to-host service channel

The guest needs a narrow, typed path to the browser broker. It should not gain
generic access to JavaScript, the DOM, browser storage, or wallet APIs.

A practical design is a synthetic local endpoint such as:

```text
/run/webtos/host-agent.sock
```

The Linux compatibility layer can present it as a local Unix-domain service,
while the browser host implements the other endpoint. An alternative is an
explicit WebAssembly host-call queue. Either mechanism must preserve the same
semantics:

- request and response messages use a canonical, bounded encoding;
- every request has a domain, type, version, request ID, expiry, and payload
  digest;
- request IDs are not economic idempotency by themselves;
- unsupported operations fail explicitly;
- the guest cannot choose which browser object implements custody;
- responses distinguish proposal, prepared, submitted, finalized, rejected,
  expired, and ambiguous states; and
- secrets returned to the guest are scoped, revocable, and excluded from
  snapshots.

Suggested operation families are:

```text
resolve.*       finalized identity, Capability and economic state
publish.*       signed operation proposals under delegated authority
discover.*      candidate search and content-addressed detail retrieval
network.*       temporary destination grants
secret.*        scoped runtime credential requests
agreement.*     proposal review and exact Agreement construction
payment.*       prepare, review, authorize, submit and resolve
receipt.*       verify result signer, digests and settlement intent
evidence.*      append runtime evidence and export a bundle
```

The channel should never expose `sign(arbitraryBytes)` to the guest. Signing
must be profile-aware or exact-transaction-aware so policy can understand the
requested effect.

### 6.6 Vue integration pattern

A Vue application remains conventional. It starts a session in a composable or
service and binds UI state to typed events:

```ts
// Illustrative API, not current webTOS code.
import { ref, onMounted, onBeforeUnmount } from "vue";
import { createAiFiApp } from "@tos/ai-fi";

export function useAgentSession() {
  const status = ref("starting");
  const approvals = ref([]);
  const events = ref([]);
  let app: Awaited<ReturnType<typeof createAiFiApp>> | undefined;

  onMounted(async () => {
    app = await createAiFiApp({ manifestUrl: "/webtos.app.toml" });
    app.on("status", value => (status.value = value));
    app.on("approval-required", value => approvals.value.push(value));
    app.on("event", value => events.value.push(value));
    await app.start();
  });

  onBeforeUnmount(() => app?.suspend());

  return { status, approvals, events };
}
```

Vue controls display. It does not become the security boundary. The broker and
custody adapter must enforce policy even if the UI is buggy or the model emits
malicious instructions.

---

## 7. End-to-End AI-Fi Lifecycle

### 7.1 Bootstrap

1. The page loads from an authenticated origin under a restrictive Content
   Security Policy.
2. The browser verifies the application and Agent image manifests.
3. webTOS installs immutable manifest descriptors and lazily retrieves verified
   chunks as execution touches them.
4. The broker loads owner policy and resource budgets.
5. A fresh guest starts with no network and no wallet authority.
6. The workspace is restored or mounted separately from secrets and economic
   journals.

### 7.2 Identity and discovery

The Agent asks the broker to resolve its own Agent identity and the current
state of candidate provider Capabilities. Discovery results are treated as
candidates, not authority. For each selected provider, the broker re-resolves:

- exact network domain;
- Agent controller state;
- Capability owner and version;
- revocation state;
- manifest digest;
- endpoint or transport binding; and
- execution signer where the profile requires one.

### 7.3 Interpretation and negotiation

Most negotiation remains off-chain. The Agent can interpret signed discovery
cards, retrieve content-addressed details, compare offers, and converse through
A2A, Messenger, MCP, or another approved transport.

The model may produce:

```text
preferred provider
requested task
maximum acceptable price
required deadline
required evidence
proposed settlement profile
```

These values remain proposals until deterministic validation confirms they are
inside owner policy.

### 7.4 Agreement

When the interaction needs binding commercial terms, the application creates
an exact Agreement or Accepted Quote using the controlling TOS profile. The
bound terms should include at least:

- buyer and provider identities;
- exact Capability version and manifest digest;
- exact input or task commitment;
- price and exact asset contract;
- deadline and expiry;
- execution signer;
- transport and artifact bindings;
- acceptance criteria;
- Receipt requirements; and
- release, refund, timeout, or dispute policy.

The UI must display the exact effect before custody approval when policy
requires human confirmation.

### 7.5 Payment authorization

The guest sends a typed request such as:

```text
AuthorizePurchase {
  agreement_digest
  provider_agent_id
  capability_id
  asset_contract
  amount_atomic
  deadline
  purpose_digest
}
```

The broker then:

1. resolves current finalized state;
2. reconstructs or validates the exact transaction semantics;
3. checks per-purchase and time-window budgets;
4. checks asset, counterparty, Capability, expiry, and confirmation policy;
5. records a durable prepared journal entry;
6. asks custody to sign exact reviewed bytes;
7. records the broadcast lease before submission;
8. submits the unchanged signed transaction; and
9. resolves finalized state before reporting success.

At no point does the guest receive the signing key.

### 7.6 Execution

After the required Agreement and funding state is finalized, the Agent sends
the task through the selected off-chain transport. Local work may execute in
the buyer's webTOS guest. Purchased heavy work normally executes at the
provider.

During execution, the application records:

- image manifest root;
- runtime and application version;
- input digests;
- granted capabilities;
- resource-budget changes;
- process exit status;
- output artifact digests;
- externally supplied responses selected for replay; and
- relevant TOS object or transaction identifiers.

### 7.7 Receipt and verification

A provider Receipt is checked against the Agreement and execution authority.
The application verifies:

- Receipt profile and signature domain;
- selected execution signer;
- task and input commitment;
- output and artifact commitments;
- usage and charged amount;
- release or refund intent; and
- finalized settlement state.

A successful Agent message is not a successful Receipt. A valid Receipt is not
settlement until the controlling TOS state reaches the expected finalized
outcome.

### 7.8 Persistence and resume

When the browser reloads, the application restores guest workspace state and
then re-resolves all live authority. It must not assume that a previously valid
Capability, quote, approval, network grant, or wallet session remains valid.

The recommended resume sequence is:

```text
restore workspace
  -> invalidate ephemeral capabilities
  -> reopen owner-private journal
  -> resolve finalized TOS state
  -> reconcile ambiguous operations
  -> reissue narrowly scoped grants
  -> resume Agent process or restart from task checkpoint
```

---

## 8. Buyer Application Method

A buyer Agent is the strongest initial webTOS AI-Fi application because it
benefits directly from local custody of data and interactive user oversight.

### 8.1 Buyer components

```text
Buyer UI
Buyer Agent running in webTOS
Owner policy
Federated discovery client
Finalized TOS resolver
External custody signer
Crash-safe purchase journal
Task transport
Receipt and settlement verifier
```

### 8.2 Buyer development sequence

1. **Start with a non-economic local Agent.** Prove that the pinned binary can
   complete the task in webTOS with all unnecessary network destinations
   denied.
2. **Add read-only TOS resolution.** Resolve the user's Agent and provider
   Capability state without signing anything.
3. **Add proposal-only discovery.** Let the Agent rank candidate providers, but
   require the user to select and copy the result manually.
4. **Add Agreement construction.** Build and display exact terms without
   broadcasting.
5. **Add external custody with mandatory confirmation.** The wallet displays
   exact network, asset, amount, destination, Agreement, and transaction hash.
6. **Add finalized-state resolution and crash recovery.** Simulate dropped
   responses and prove that no duplicate purchase occurs.
7. **Add bounded autonomous approval.** Only after the negative tests pass,
   permit automatic purchases inside an owner-defined policy envelope.

### 8.3 Appropriate buyer policies

A useful policy is multidimensional:

```text
asset allowlist
AND amount per purchase
AND cumulative time-window amount
AND purchase count
AND provider or Capability class
AND task category
AND deadline
AND evidence requirement
AND network destination
AND confirmation mode
```

A policy such as `spend up to 100 units` is incomplete. It does not constrain
what is purchased, from whom, on which network, for which task, or under which
Receipt and refund rules.

### 8.4 One Agreement, many messages

Streaming output, progress events, tool calls, and model tokens should normally
remain off-chain. A practical economic session is:

```text
one finalized Agreement and budget
    -> many bounded off-chain task messages
    -> one or a few signed Receipts
    -> one settlement outcome
```

This preserves accountability without turning the Agent's inner loop into a
sequence of chain transactions.

---

## 9. Provider Application Method

A provider Agent advertises a Capability, accepts only properly authorized
work, executes it, produces artifacts and a Receipt, and reconciles settlement.

### 9.1 Provider components

```text
Capability and immutable version manifest
Quote policy
Admission controller
Finalized Agreement and funding resolver
Bounded executor
Content-addressed artifact store
Execution signer outside untrusted work
Receipt builder
Settlement reconciler
```

### 9.2 Provider admission

The provider should not execute paid work merely because it received a task.
Admission requires:

```text
recognized network domain
AND current provider Capability
AND exact Agreement binding
AND finalized required funding state
AND unused execution identity
AND task digest match
AND resource availability
AND local provider policy
```

One funded purchase must not admit multiple executions through different
transports. A2A, MCP, Messenger, or Agent Packet adapters must converge on one
shared admission fence.

### 9.3 Provider execution in webTOS

A browser-local provider is useful for:

- user-controlled interactive services;
- local document or data processing;
- demonstrations and temporary markets;
- spare-device participation while the page is active; and
- reproducible software work that fits browser limits.

It is not a reliable always-on provider. The browser may suspend the tab, the
user may close it, storage quotas may change, and no availability claim should
outlive an active lease. Persistent provider services should usually use a
native OpenFox or server runtime while preserving the same Capability,
Agreement, Receipt, and policy model.

### 9.4 Receipt authority

The untrusted task process should not control the provider's Receipt signer.
The executor returns bounded results to a provider policy component, which
constructs a Receipt only after checking the exit status, artifact digests,
usage, and accepted terms. A failed execution must not produce a success
Receipt.

---

## 10. Coordinator and Composable Agent Businesses

A coordinator Agent purchases several lower-level services to satisfy one
higher-level task:

```text
user
  -> coordinator in webTOS
       |-> data provider
       |-> compute provider
       |-> analysis provider
       `-> visualization provider
```

Each subordinate purchase has its own:

- provider identity and Capability;
- Agreement and budget;
- execution signer;
- Receipt;
- settlement state; and
- artifact commitments.

The coordinator's final evidence may include the subordinate Receipt digests,
but those receipts do not remove the coordinator's responsibility to the user.
A top-level provider must not silently outsource work when the accepted terms
forbid it or require disclosure.

The webTOS advantage is that coordination policy, private intermediate data,
and the user's workspace can remain local while expensive or specialized work
is purchased externally.

---

## 11. Reference Application: Autonomous Compute Procurement

### 11.1 User experience

A user opens a Web application and enters:

```text
Task: Fine-tune a small model
Maximum budget: 120 stablecoin units
Deadline: 2 hours
Required evidence: image digest, logs, output digest, usage Receipt
```

The local webTOS Agent:

1. discovers compute-provider Capabilities;
2. filters stale, revoked, incompatible, or over-budget offers;
3. retrieves details only for promising candidates;
4. estimates cost and completion probability;
5. proposes one provider and exact Agreement;
6. obtains policy or user approval;
7. funds the accepted purchase through external custody;
8. uploads encrypted or content-addressed task inputs;
9. monitors off-chain progress;
10. verifies output and Receipt commitments; and
11. resolves settlement from finalized TOS state.

The heavy compute remains remote. The planning Agent, private task definition,
policy, and economic journal remain in the user's browser.

### 11.2 Illustrative guest request

```json
{
  "type": "payment.authorize-purchase.v1",
  "request_id": "01J...",
  "expires_at": 1787971200,
  "agreement_digest": "sha256:...",
  "provider_agent_id": "...",
  "capability_id": "...",
  "asset_contract": "...",
  "amount_atomic": "72000000",
  "purpose_digest": "sha256:..."
}
```

The broker must ignore any human-readable explanation that conflicts with the
canonical fields. The UI may show a friendly summary, but the policy and signer
operate on exact semantics.

### 11.3 Why this is AI-Fi

This application is not merely a token payment interface. The Agent performs
an economic workflow: discovery, selection, negotiation, authorization,
purchase, execution monitoring, verification, settlement, and memory update.
It is also not merely a cloud Agent. The user's local runtime remains the
coordinator and authority requester, while providers are replaceable.

---

## 12. State, Persistence, and Recovery

### 12.1 Four stores, four authorities

An AI-Fi application should separate four classes of state:

| Store | Example contents | Authority |
|---|---|---|
| Immutable image store | manifest, file metadata, verified chunks | image digest and signer policy |
| Guest workspace | repository, Agent memory, generated files | local application state |
| Owner-private control store | policy, budget journal, pending exact actions, capability grants | browser broker and owner |
| TOS state | Agent, Capability, Agreement, value, Receipt, settlement | finalized TOS consensus |

The guest snapshot must not become the control store. Otherwise a compromised
Agent could edit its own limits or restore a spent approval.

### 12.2 Recommended lifecycle journal

A purchase journal may use states such as:

```text
created
  -> candidate-selected
  -> agreement-prepared
  -> approval-pending
  -> signed
  -> broadcasting
  -> resolving
  -> funded
  -> executing
  -> receipt-received
  -> settlement-resolving
  -> settled | refunded | disputed | expired
```

State transitions should be atomic. Entering `broadcasting` grants a one-way
lease to one exact signed message. After that point, an uncertain response
must move to `resolving`, never back to `agreement-prepared`.

### 12.3 Snapshot rules

Safe to snapshot:

- guest files and installed tools;
- task checkpoints;
- content-addressed object references;
- non-secret Agent memory;
- deterministic runtime state supported by webTOS; and
- identifiers needed to re-resolve TOS state.

Unsafe to snapshot as live authority:

- wallet seeds or private keys;
- unrestricted bearer tokens;
- one-time approvals;
- stale network grants;
- custody handles that remain valid after reload; and
- journal state whose integrity the guest can modify.

---

## 13. Execution Evidence and Reproducibility

### 13.1 Current foundation

webTOS already treats deterministic instruction retirement, syscall behavior,
signals, scheduling, time, randomness, and event order as testable runtime
properties. It also has content-addressed image manifests and runtime event
records. These are strong foundations for reproducible Agent execution.

However, the current runtime does not claim a signed third-party-verifiable
attestation artifact. This paper therefore proposes an evidence bundle rather
than claiming attestation.

### 13.2 Proposed `WebTOSExecutionEvidenceV1`

An exported evidence bundle could include:

```text
schema and version
runtime build digest
browser engine and platform metadata
Agent image manifest root
mutable workspace input root or selected input digests
owner policy digest
capability-grant log digest
network recording digest or external-input commitments
initial and final snapshot descriptors
retired instruction count
architectural trace root or selected trace commitments
process exit status
stdout/stderr or log digests
output artifact digests
Agreement or Accepted Quote identifier
provider Receipt digest
relevant finalized TOS transaction and state references
bundle signer and assurance level
```

### 13.3 Evidence levels

The application should distinguish at least four levels:

1. **Local record:** useful to the owner but not independently authenticated.
2. **Signed application record:** signed by the browser application or owner
   key, proving who asserted the record but not trusted execution.
3. **Reproducible evidence:** sufficient inputs and deterministic records for a
   verifier to rerun the workload and compare outputs or traces.
4. **External attestation:** optional proof from hardware or another trusted
   execution system, outside webTOS's current claim.

Calling levels 1–3 “hardware attestation” would be incorrect. Their value is
transparency, integrity, replay, and reproducibility.

### 13.4 Relationship to TOS Receipts

A TOS Receipt and a webTOS execution evidence bundle serve different purposes:

- the Receipt binds the provider's claimed commercial result to the accepted
  terms and selected execution authority;
- the evidence bundle describes what the local or provider runtime observed;
- finalized TOS state establishes the canonical settlement outcome.

They may reference one another by digest, but one must not silently replace the
other.

---

## 14. Security Threat Model

| Threat | Failure mode | Required control |
|---|---|---|
| Prompt injection | Model requests data exfiltration or payment | Typed capability requests, deny-by-default policy, no generic signing |
| Malicious Agent image | Binary steals secrets or burns resources | Signed/verified manifest, scoped secrets, runtime budgets, isolated workspace |
| Dependency compromise | UI or guest package changes behavior | Version pinning, content hashes, reproducible builds, release review |
| Credential exfiltration | Agent reads wallet or API credentials | Keys outside guest, per-process secret scope, snapshot exclusion, network allowlist |
| Transaction substitution | UI summary differs from signed bytes | Profile-aware construction, exact semantic display, independent signer verification |
| Stale or revoked Capability | Agent buys from obsolete provider | Re-resolve finalized state immediately before authorization and execution |
| Replay or duplicate payment | Retry creates second economic effect | Canonical action identity, durable journal, broadcast lease, finality resolution |
| Gateway equivocation | Gateway returns false identity or settlement | Quorum-finalized verification, replaceable Gateways, exact network and code hashes |
| Resource exhaustion | Agent freezes tab or fills storage/network | CPU, memory, storage, network, and event budgets returning explicit errors |
| Snapshot privilege resurrection | Restored guest reuses old approval | Ephemeral grants invalid after restore; re-resolve and reissue |
| Browser-origin compromise | Injected script controls broker UI or requests | CSP, dependency isolation, worker boundaries, external signer with exact-action display |
| Provider fraud | Wrong or incomplete output claims success | Bound acceptance rules, artifact digests, execution signer, Receipt verification, dispute/refund policy |
| Privacy leakage through metadata | Chain reveals sensitive task details | Keep bulk data off-chain, use minimal commitments, avoid descriptive plaintext in transactions |
| False attestation claim | User assumes browser record proves trusted hardware | Explicit evidence levels and accurate UI language |

### 14.1 Highest-value boundary

The browser authority broker is the highest-value application component. It
must be designed like a wallet and sandbox controller, not like ordinary UI
state. Its code should be small, typed, tested against negative vectors, and
isolated from model-generated text and untrusted page content.

### 14.2 User confirmation is not enough by itself

A confirmation dialog does not repair an ambiguous or misleading action. The
application must first construct exact semantics and apply deterministic policy.
Human review is an additional gate, not the only gate.

### 14.3 Regulatory and operator policy

An AI-Fi runtime does not remove legal obligations. Asset support, consumer
protection, data handling, sanctions screening, tax, licensing, and identity
requirements depend on the application and jurisdiction. These belong in
operator and owner policy and must not be hidden inside model judgment.

---

## 15. Packaging and Deployment Method

### 15.1 Build the Agent image

A practical toolchain should accept a Docker or OCI-style build context, then
produce a canonical webTOS image:

```text
Dockerfile or rootfs
    -> normalize paths and metadata
    -> freeze executable and library versions
    -> split files into verified chunks
    -> construct canonical manifest
    -> compute manifest root
    -> sign or approve manifest
    -> publish manifest and chunks
```

The output is not a block-device image. It is a content-addressed Agent image
whose identity can be bound to application policy, Capability metadata, and
execution evidence.

### 15.2 Deploy the Web application

The application deployment contains:

- static UI assets;
- the webTOS WebAssembly module and worker host;
- the signed application and Agent-image manifests;
- content-addressed chunks on a CDN or compatible content store;
- a deny-by-default byte relay for the destinations the guest must reach;
- replaceable TOS Gateway or direct resolver configuration; and
- an external wallet or custody adapter.

The local Agent does not require a remote execution VM. Network relay,
discovery, TOS resolution, content hosting, and purchased provider services may
still be remote. Their role must remain transport or service execution, not
unbounded custody of the user's local Agent.

### 15.3 Release discipline

Every release should pin:

- webTOS runtime build;
- Agent binary and rootfs manifest;
- UI build and dependency lock;
- owner-policy schema;
- TOS protocol/profile versions;
- network domain and contract code hashes where required;
- browser compatibility evidence; and
- migration behavior for snapshots and economic journals.

A mutable `latest` tag is convenient for development and unsuitable as the
sole identity for autonomous spending.

---

## 16. Testing and Evaluation Method

An AI-Fi application is complete only when failure paths are tested as
aggressively as the happy path.

### 16.1 Runtime compatibility gates

Use pinned real workloads, not synthetic API presence:

- Agent starts from a clean browser profile;
- dynamic libraries and required files lazy-load correctly;
- terminal and subprocess behavior is correct;
- authenticated HTTPS works through the allowlisted relay;
- task execution survives a browser reload or resumes from a documented
  checkpoint; and
- unsupported behavior fails explicitly.

### 16.2 Authority and policy gates

Tests must prove that:

- no network exists before a grant;
- disallowed destinations remain unreachable;
- a guest process cannot read another process's scoped secret;
- private key material never appears in guest memory, environment, files, or
  snapshots;
- amount, asset, provider, Capability, deadline, and cumulative budgets are
  independently enforced;
- arbitrary bytes cannot be signed through the Agent bridge; and
- restoring a snapshot does not restore expired authority.

### 16.3 Economic lifecycle gates

A fresh testnet or controlled-network session should cover:

```text
resolve identity
  -> verify Capability
  -> receive proposal
  -> prepare exact Agreement
  -> authorize and submit
  -> lose the client response intentionally
  -> recover from finalized state
  -> fund exactly once
  -> admit one execution
  -> verify one Receipt
  -> settle or refund
```

The test must fail if a duplicate payment or duplicate execution can be caused
by changing a request ID, restarting the page, switching transport, or losing a
response.

### 16.4 Cross-browser reproducibility gates

For a fixed image and input:

- compare retired instruction counts;
- compare selected architectural trace points;
- compare syscall, signal, and process outcomes;
- compare output artifact digests; and
- document external inputs that prevent complete offline replay.

### 16.5 User-experience gates

A non-expert user should be able to answer:

1. What Agent image is running?
2. Which files can it access?
3. Which network destinations can it reach?
4. What is the maximum amount it can spend?
5. What exact action currently needs approval?
6. Has the transaction merely been submitted or actually finalized?
7. How can all authority be revoked?

If the interface cannot answer these questions, the capability model is not
usable even if the backend is correct.

### 16.6 Suggested evaluation matrix

| Property | Metric or gate |
|---|---|
| Compatibility | Pinned Agent completes a real task in supported browsers |
| Startup | Time and bytes fetched before first useful action |
| Memory | Resident guest memory under task-specific ceiling |
| Confinement | Zero unauthorized network, file, secret, signing, or spending effects |
| Determinism | Matching instruction and trace commitments for fixed inputs |
| Recovery | Reload and ambiguous broadcast resolve without duplicate effect |
| Economic correctness | Agreement, Receipt, and settlement reconstruct from finalized TOS state |
| Usability | User correctly understands active authority and transaction state |
| Portability | Loss of one Gateway does not destroy canonical resolution |

---

## 17. Staged Implementation Roadmap

### Stage 0: Local Agent application

**Goal:** package one pinned Agent and run a useful non-economic task entirely
inside webTOS.

**Exit gate:** clean-profile browser task, bounded resources, no network beyond
the explicit allowlist, persistent workspace, and no TOS integration.

### Stage 1: Read-only TOS identity and discovery

**Goal:** resolve Agent and Capability state and retrieve signed discovery
objects without signing or spending.

**Exit gate:** application rejects wrong network, wrong genesis, stale,
revoked, mismatched-owner, and mismatched-manifest candidates.

### Stage 2: Browser authority broker

**Goal:** introduce the typed guest-to-host service channel, scoped network and
secret grants, owner policy, audit events, and an external custody adapter in
read-only or prepare-only mode.

**Exit gate:** no arbitrary signing surface, negative policy vectors pass, and
snapshot restore cannot resurrect grants.

### Stage 3: Human-confirmed test purchase

**Goal:** construct one exact Agreement and complete one controlled purchase
with mandatory independent wallet confirmation.

**Exit gate:** dropped submission responses and page reloads produce no
duplicate transaction, funding, or execution.

### Stage 4: Bounded autonomous buyer

**Goal:** allow the Agent to purchase automatically inside a narrowly defined
policy envelope.

**Exit gate:** adversarial model output cannot escape asset, provider,
Capability, amount, count, deadline, evidence, or network limits.

### Stage 5: Provider and Receipt mode

**Goal:** publish a Capability, admit one funded task, execute in a bounded
worker, produce a canonical Receipt, and reconcile settlement.

**Exit gate:** one purchase admits at most one execution across all transports;
failed work cannot produce a success Receipt.

### Stage 6: Multi-Agent composition

**Goal:** let one local coordinator buy from several providers and return a
composed result.

**Exit gate:** every subordinate purchase and artifact is independently
reconstructible, while the coordinator's responsibility remains explicit.

### Stage 7: Evidence export and conformance

**Goal:** freeze an application manifest, host-capability protocol, policy
schema, journal model, and execution-evidence bundle with test vectors.

**Exit gate:** two independent implementations agree on canonical encodings and
reject adversarial vectors; browser and native verifiers reproduce a selected
workload result.

---

## 18. Recommended Standardization Work

The integration should introduce only application-local schemas and must not
fork existing TOS canonical objects.

### 18.1 `WEBTOS_AGENT_APP_MANIFEST_V1`

Defines image identity, entrypoint, mounts, runtime budgets, network policy,
TOS network domain, spending-policy references, and evidence options.

### 18.2 `WEBTOS_HOST_CAPABILITY_RPC_V1`

Defines bounded guest-to-host requests, canonical encoding, replay identity,
expiry, typed outcomes, error semantics, and negative vectors. It must not
include a generic arbitrary-sign operation.

### 18.3 `WEBTOS_AI_FI_POLICY_V1`

Defines owner-controlled limits over assets, amounts, counterparties,
Capability classes, task categories, deadlines, evidence requirements,
network destinations, confirmation modes, and cumulative windows.

### 18.4 `WEBTOS_AI_FI_JOURNAL_V1`

Defines atomic lifecycle states, economic slot identity, prepared and broadcast
leases, finality checkpoints, and recovery after reload or ambiguous writes.
The journal remains owner-private and outside guest authority.

### 18.5 `WEBTOS_EXECUTION_EVIDENCE_V1`

Defines image, input, runtime, trace, output, Agreement, Receipt, and finalized
state commitments, plus explicit assurance levels. It must not label ordinary
browser evidence as hardware attestation.

### 18.6 `WEBTOS_AI_FI_TEST_VECTORS_V1`

Contains valid and adversarial examples for manifest parsing, host calls,
policy decisions, transaction substitution, stale Capability resolution,
replay, duplicate funding, snapshot restore, Receipt mismatch, and evidence
bundle verification.

---

## 19. Limitations and Non-Goals

1. **webTOS is not a UI framework.** Developers still use Vue, React, Svelte,
   or another interface technology.
2. **AI-Fi is not “put every Agent action on-chain.”** Ordinary conversation,
   progress, tool calls, and bulk data should normally remain off-chain.
3. **The guest is not the wallet.** Keeping keys outside the guest is a core
   design property, not an optional enterprise feature.
4. **The browser is not an always-on datacenter.** Closed and suspended tabs
   cannot provide continuous provider availability.
5. **webTOS is not currently a hardware-attested TEE.** Determinism and replay
   improve reproducibility, not hardware trust.
6. **Heavy compute remains external.** GPU training, large-memory workloads,
   and persistent infrastructure are natural AI-Fi purchases rather than work
   the local runtime must absorb.
7. **The browser origin remains in the trusted computing base.** A compromised
   page can misrepresent or misuse host APIs unless policy and independent
   custody verification remain effective.
8. **Protocol status remains external.** This paper does not promote draft or
   incubation TOS profiles to production facts; each controlling repository
   and roadmap defines its own acceptance status.
9. **Financial and legal compliance is application-specific.** A secure
   runtime does not by itself make a financial service lawful or suitable.
10. **The proposed SDKs do not yet exist as stable public APIs.** They are the
    recommended shape for implementation and experimentation.

---

## 20. Conclusion

webTOS and TOS solve different halves of the Agent application problem.
webTOS gives a Web page a local Linux x86-64 backend with an explicit execution
boundary. TOS gives Agents portable identity, replaceable discovery and
transport, explicit commercial commitments, and canonical settlement. An
AI-Fi application emerges when these systems are joined through a narrow
capability and custody layer rather than by placing a wallet inside the Agent.

The most important architectural rule is simple:

> **The Agent may decide what it wants to do, but it may perform an external
> side effect only through deterministic owner policy and exact authority.**

This rule turns the browser Agent from an unbounded script into a controlled
economic process. The image it runs can be content-addressed. Its workspace can
remain local. Its network can be deny-by-default. Its resources can be metered.
Its purchases can be bounded. Its transactions can be resolved from finalized
state. Its execution can be recorded and, within the limits of available
external inputs, reproduced.

The resulting application model is neither a traditional frontend nor a
traditional decentralized application:

```text
Agentic Web Application
    = local executable software
    + explicit capabilities
    + owner-controlled custody
    + decentralized identity and settlement
    + inspectable evidence
```

The recommended product wedge is a local buyer Agent: a browser application
that keeps user data and policy local while safely purchasing bounded software,
compute, data, or Agent services from external providers. Once that lifecycle
survives adversarial policy tests, ambiguous writes, browser reloads, and
replaceable Gateways, the same method can expand to provider Agents,
coordinators, autonomous service businesses, and broader AI-Fi markets.

---

## Appendix A. Minimal Illustrative Application

```ts
// Proposed API: illustrative only.
const app = await AiFiApp.open({
  manifest: "/webtos.app.toml",
  custody: walletAdapter,
  resolver: finalizedResolver,
});

await app.start();

const result = await app.agent.run({
  task: {
    kind: "software-analysis",
    inputDigest: "sha256:<input>",
    maximumPriceAtomic: "10000000",
  },
  authority: {
    network: ["gateway.example:443", "provider.example:443"],
    files: ["/workspace"],
    paymentPolicy: "owner-policy-v1",
  },
});

console.log(result.outputDigest);
console.log(result.receiptDigest);
console.log(result.finalizedSettlement);
```

The apparent simplicity is intentional. Complexity belongs in the runtime,
policy broker, custody adapter, resolver, journals, and conformance tests, not
in every application developer's code.

---

## Appendix B. Capability Status Matrix

| Capability | Source | Status in this paper |
|---|---|---|
| Linux x86-64 execution in a browser | webTOS | Current, governed by repository gates |
| Processes, PTY, VFS, sockets, persistence | webTOS | Current, governed by repository gates |
| Deny-by-default networking and resource budgets | webTOS | Current, governed by repository gates |
| Content-addressed image manifests and lazy chunks | webTOS | Current integration foundation |
| Deterministic cross-browser execution gates | webTOS | Current foundation |
| Signed third-party execution attestation | webTOS | Not current; not claimed |
| Agent and Capability authority model | TOS Service Protocol | External TOS specification and implementation boundary |
| Quote, Agreement, Receipt and settlement profiles | TOS Service Protocol | External TOS boundary; status controlled by its roadmaps |
| Browser TOS Agent bridge | This paper | Proposed |
| `@webtos/runtime` stable SDK | This paper | Proposed public abstraction |
| `@tos/agent-web` and `@tos/ai-fi` | This paper | Proposed |
| Guest host-capability socket/RPC | This paper | Proposed |
| AI-Fi policy and journal schemas | This paper | Proposed |
| webTOS execution evidence bundle | This paper | Proposed |

---

## Related Documents

### webTOS

- [Project README](../README.md)
- [webTOS White Paper](WHITEPAPER.md)
- [webTOS Roadmap](../ROADMAP.md)
- [webTOS Use Cases](USE-CASES.md)
- [Performance and Memory](performance.md)
- [Lazy Image Demand Paging](../feasibility/lazy_chunk_fs.md)

### TOS Agentic Internet and commerce

- [TOS Agentic Internet Operation Architecture V1](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/TOS_AGENTIC_INTERNET_OPERATION_ARCHITECTURE_V1.md)
- [Decentralized Agent-to-Agent Use Cases](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/A2A_USE_CASES.md)
- [Agent Intent Exchange V1](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/AGENT_INTENT_EXCHANGE_V1.md)
- [OpenFox Economic Bridge V1](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/OPENFOX_ECONOMIC_BRIDGE_V1.md)
- [Settlement](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/SETTLEMENT.md)
- [Software Work Execution V1](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/SOFTWARE_WORK_EXECUTION_V1.md)
- [Agent Gas Sponsorship and Transaction Relay V1](https://github.com/tosnetwork/tos-service-spec/blob/main/docs/AGENT_GAS_SPONSORSHIP_AND_TRANSACTION_RELAY_V1.md)
- [TOS Service Protocol Buyer SDK](https://github.com/tosnetwork/tos-service-protocol/blob/main/docs/buyer-sdk.md)
- [TOS Service Protocol Provider SDK](https://github.com/tosnetwork/tos-service-protocol/blob/main/docs/provider-sdk.md)
