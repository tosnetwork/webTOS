# webTOS — Investor Brief

**The local execution layer for AI agents**<br>
**Draft · August 2026 · Not for external circulation until the team, round, and customer sections are completed**

> **One-line pitch:** The link is the install, and the tab is the computer.
> webTOS runs unmodified Linux x86-64 agent software locally inside a browser,
> with explicit permissions, persistent state, and runtime-enforced resource
> limits.

This brief applies investment criteria found in a16z's public writing on AI
infrastructure, developer tools, open source, and agent execution. It has not
been reviewed or endorsed by a16z.

---

## 1. Investment Thesis

AI agents are moving from generating text to taking actions: reading
repositories, running code, using tools, changing files, and operating over
long-lived workflows. The model is only the decision layer. Every useful agent
also needs a computer.

a16z describes code sandboxes as critical components of the AI development
stack and places execution environments at the base of the computer-use stack.
It also identifies reliability, latency, cost, security, credentials,
permissioning, auditability, and data retention as unresolved production
constraints.[^a16z-sandboxes][^a16z-computer-use]

Today, that computer normally has one of two shapes:

1. a cloud VM or container, where the vendor pays for compute and takes
   custody of customer data; or
2. a local installation, where onboarding is slow and the agent inherits broad
   machine authority.

webTOS creates a third shape: **unmodified Linux software running on the
user's hardware, inside the browser sandbox, under authority the host grants
deliberately.**

The venture thesis is straightforward: if agents become a primary way people
use software, their execution layer becomes load-bearing infrastructure. A
browser-native execution layer can win where local data, zero-install
distribution, controlled authority, and cloud unit economics matter at the
same time.

---

## 2. Product and Core Innovation

webTOS is a WebAssembly x86-64 engine plus the operating-system side of the
Linux userspace ABI: processes, threads, signals, virtual memory, files,
sockets, pseudoterminals, scheduling, snapshots, and budgets. It is not a
remote container, a JavaScript rewrite, or a full PC emulator.

🔸 **The program, not a port.** Existing Linux x86-64 ELF binaries run without
being rebuilt for WebAssembly. Agent vendors can ship the binary they already
test and support.

🔸 **Local by architecture.** Repository work, compilation, tests, and
workspace state execute on the user's device. The application operator does
not need a per-user Linux compute fleet for those operations.

🔸 **Useful agency without ambient authority.** The guest begins with no
network or host access. Network destinations, credentials, files, and external
effects cross explicit host-controlled boundaries.

🔸 **Budgets that fail like an operating system.** CPU, memory, storage,
network, and event-log limits are enforced by the runtime. Where possible, a
limit becomes an error the Linux program can handle rather than a crashed tab.

🔸 **Persistent, verifiable delivery.** Large binaries and libraries are
demand-paged from content-addressed manifests, cached in browser storage, and
bound to approved bytes. Filesystem state can survive a reload.

🔸 **Determinism as architecture, not a dashboard claim.** The reference
interpreter, JIT, scheduler, time, randomness, and external-input boundaries
are designed around reproducible execution and cross-browser trace gates.

The innovation is the combination. Emulation alone is another virtual
machine. A sandbox without Linux compatibility cannot run the software agents
already use. A generated interface without a real execution boundary is only
generated markup.

---

## 3. Initial Wedge: Agent Runtime SDK

The first product should not be sold as a general operating system or as the
full intent-native application vision. The narrow entry point is:

> **Embed an unmodified Linux coding agent in a web product without operating
> a cloud container for every user.**

### Initial customers

- coding-agent companies that want a zero-install browser experience;
- browser IDEs and developer platforms;
- AI SaaS products that need Git, compilers, shell tools, or repository access;
- security- and privacy-sensitive products that want customer code to remain
  on the endpoint by default.

### Target developer experience

```ts
const runtime = await WebTOS.create({
  image: "claude-code",
  workspace: userDirectory,
  network: ["api.anthropic.com"],
  credentials: { claude: credentialHandle },
  budgets: { memory: "2GB", cpu: "30m" },
});

await runtime.start();
```

The SDK should turn today's engine, manifest, terminal, networking, credential,
and persistence primitives into one supported integration surface. The
long-term Application Graph can then compose agents, tools, UI, approvals, and
budgets dynamically; it is expansion, not the initial wedge.

---

## 4. Technical Validation — Strong; Commercial Traction — Not Yet Proven

The repository contains unusually deep technical evidence for a project at
this product stage:

- unmodified BusyBox, dynamic musl and glibc programs, Git history operations,
  a multi-process C toolchain, Vim, curl, Node, OpenFox, Codex, and Claude Code
  have crossed progressively harder workload gates;
- a real Codex session authenticates, calls a model, edits a file, runs a child
  command on a PTY, reports the result, and exits cleanly on the native runner;
- pinned Codex and Claude Code images load in Chromium, Firefox, and WebKit;
  the Claude Code version workload retires the same approximately 186 million
  guest instructions in every engine;
- a 52 MB real agent image streams into a browser, reaches a prompt in roughly
  three seconds, and runs in all three engines;
- 7,128,576 adversarial syscall cases and 365,568 decoder sequences have been
  swept, alongside strict Linux fixture tests and architectural traces;
- hot loops can translate to WebAssembly and reach roughly 30× the interpreter
  on the measured V8 canaries;
- the M0–M8 roadmap is approximately 97.7% complete by the project's declared
  engineering weights; the M9 Ice Lake execution profile is approximately 99%.

The current boundary must stay explicit: the final sustained Claude Code task
in the browser is still an acceptance item, and the repository does not yet
show customer adoption, revenue, retention, or paid pilots. This is technical
de-risking, not product-market fit. See the [Roadmap](ROADMAP.md),
[Compatibility Dashboard](docs/compatibility/README.md), and
[Performance Methodology](docs/performance.md).

---

## 5. Why This Can Be Venture-Scale

The market is not “people who want Linux in a tab.” The market is the
execution layer beneath software-using agents.

The initial coding wedge can expand across three axes:

1. **More agent vendors:** proprietary and open agents using the same runtime
   contract.
2. **More workloads:** development, data analysis, research, media processing,
   security tooling, education, and enterprise automation.
3. **More control-plane value:** policy, signed workloads, compatibility,
   audit records, credential brokerage, collaboration, and fleet management.

The browser provides a distribution advantage: a URL can reach users without
an installer or a provisioned VM. Local execution provides a structural unit
economics advantage for CPU-heavy tool use because the customer's device
supplies the compute. The cloud remains a complement for model inference,
relays, synchronization, and workloads that exceed endpoint limits.

No top-down TAM number is asserted here. Before external fundraising, the
company should size the market bottom-up from target design partners: active
agent workspaces × annual platform value, plus avoided sandbox infrastructure
and data-custody costs. A credible bottom-up model is more useful than claiming
the entire cloud or developer-tools market.

---

## 6. Business Model and Go-to-Market

### Open-source funnel

The MIT runtime can create developer trust and distribution. a16z's open-source
framework separates project-community fit, product-market fit, and
value-market fit; all three must eventually be measured.[^a16z-oss]

The recommended sequence is:

1. a one-click public demo that completes a real repository task;
2. a TypeScript SDK and reproducible workload registry;
3. 5–10 design partners in coding agents, browser IDEs, and AI SaaS;
4. paid production pilots with measurable cost, privacy, or onboarding wins;
5. bottom-up developer adoption followed by enterprise security and platform
   sales — the “growth + sales” motion a16z has documented for developer-led
   enterprise companies.[^a16z-growth]

### Paid product

- **Enterprise Runtime SDK:** supported releases, browser certification,
  integration support, and compatibility SLAs.
- **Policy and Control Plane:** organization policy, workload identity,
  approvals, audit records, version management, and administration.
- **Managed Connectivity:** credential brokerage and deny-by-default network
  relay for products that do not want to operate those services.
- **Workload Supply Chain:** signed images, provenance, compatibility reports,
  and private registries.

Pricing should reflect a recognizable unit of customer value — a protected
active workspace, supported integration, or completed agent job — rather than
raw emulated instructions. This preserves the local-compute advantage instead
of recreating cloud VM billing inside the browser.

---

## 7. Defensibility

🔸 **Compatibility compounds.** Real Linux software exposes a long tail of ISA,
loader, syscall, process, PTY, networking, and filesystem semantics. Each fixed
workload becomes a permanent regression gate.

🔸 **Determinism is difficult to retrofit.** Reproducible scheduling, time,
randomness, faults, and external inputs constrain the architecture from the
start; they are not an observability feature added later.

🔸 **The workload corpus is an asset.** Pinned real agents, native authorities,
cross-browser traces, fuzz surfaces, and compatibility evidence shorten future
integration cycles and raise the cost of superficial imitation.

🔸 **The browser changes the cost and trust boundary.** A cloud sandbox vendor
can add a web terminal, but moving execution, persistence, and policy into the
tab requires a different architecture and business model.

🔸 **A future ecosystem can deepen the moat.** SDK adoption, signed workload
registries, policy standards, and shared compatibility data can create
switching costs and ecosystem effects.

Open source is not itself a moat. The moat becomes investable only if technical
leadership converts into developer adoption, a stable integration contract,
and a paid control plane.

---

## 8. Kill Risks and the Financing Plan

### Risks an investor should underwrite

- **Product risk:** the engine is ahead of the SDK and onboarding experience.
- **Market risk:** customers may prefer managed cloud sandboxes despite their
  cost and data-custody tradeoffs.
- **Performance risk:** browsers, devices, and long-running workloads vary;
  some jobs will always require cloud fallback.
- **Security risk:** webTOS adds an inner policy boundary but still relies on
  the browser trusted computing base and does not claim hardware attestation.
- **Platform risk:** browser storage, memory ceilings, and WebAssembly behavior
  remain outside the company's control.
- **Execution risk:** the final Claude browser task, supported release,
  production signing, and multi-hour agent soak are not all closed.
- **Commercial risk:** no customer, revenue, retention, or community metrics
  have been supplied for this brief.

### Milestones for the next financing period

1. close the full Claude Code browser task and long-session gates;
2. ship a supported TypeScript SDK and a one-link flagship coding demo;
3. secure 5–10 design partners and convert at least three into paid pilots;
4. publish measured cloud-cost avoidance, endpoint resource use, and data-flow
   evidence for real customer workloads;
5. deliver signed releases, compatibility SLAs, and the first enterprise
   policy/control-plane surface;
6. prove repeat usage: active workspaces, completed jobs, retention, and
   expansion inside design partners.

### The investment decision

**Invest if:** you believe agents become a major software interface; execution
infrastructure becomes a durable control point; and the browser can support a
meaningful local share of agent work. webTOS then has a credible chance to own
the local execution standard rather than compete as another cloud sandbox.

**Wait if:** the product remains a technically impressive runtime without a
simple SDK, repeated customer usage, or a buyer willing to pay for policy,
compatibility, and reduced cloud/data-custody burden.

The technology is sufficiently de-risked for a serious seed conversation. The
next value inflection is commercial proof, not another instruction family.

> **Before external circulation:** add founder and team biographies, company
> ownership, financing amount and use of funds, customer pipeline, community
> metrics, and a bottom-up market model. None should be invented from repository
> evidence.

---

## Public a16z Lens Used in This Brief

[^a16z-sandboxes]: a16z, [The Trillion Dollar AI Software Development Stack](https://a16z.com/the-trillion-dollar-ai-software-development-stack/) — identifies code sandboxes as critical tools for agents.
[^a16z-computer-use]: a16z, [The Rise of Computer Use and Agentic Coworkers](https://a16z.com/the-rise-of-computer-use-and-agentic-coworkers/) and [Can Agents Use a Computer Yet? We've Got the Data](https://a16z.com/can-agents-use-a-computer-yet-weve-got-the-data/) — frame execution environments, orchestration, accuracy, latency, cost, security, and governance as core layers and constraints.
[^a16z-oss]: a16z, [Open Source: From Community to Commercialization](https://a16z.com/open-source-from-community-to-commercialization/) — distinguishes project-community fit, product-market fit, and value-market fit.
[^a16z-growth]: a16z, [Growth+Sales: The New Era of Enterprise Go-to-Market](https://a16z.com/growthsales-the-new-era-of-enterprise-go-to-market/) — describes bottom-up product adoption followed by top-down enterprise sales.

Additional framing: a16z's [The New Business of AI](https://a16z.com/the-new-business-of-ai-and-how-its-different-from-traditional-software/) highlights cloud infrastructure as a material AI gross-margin cost, while [Investing in Temporal](https://a16z.com/announcement/investing-in-temporal/) argues that reliable execution becomes indispensable as agents take consequential, long-running actions.
