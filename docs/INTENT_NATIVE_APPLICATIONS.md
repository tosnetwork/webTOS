# webTOS and Intent-Native Applications

**Version:** Draft v1.0 · 2026-08-29  
**Status:** Product and architecture direction  
**Scope:** Dynamic, agent-composed Web applications built on webTOS

> **Status boundary.** webTOS today is a browser-hosted Linux x86-64 runtime.
> This document describes a product and developer direction that can be built
> on that runtime. The dynamic application graph, UI composition APIs, public
> SDK names, and component protocols described below are proposals, not claims
> of shipped functionality. Current implementation status remains controlled
> by the [README](../README.md), [Roadmap](../ROADMAP.md), and
> [Use Cases](USE-CASES.md).

---

## Abstract

The Web application model assumes that developers know the interface before a
user arrives. Routes, forms, dashboards, API bindings, and workflows are
assembled at development time and shipped as a mostly fixed application. AI
changes this assumption. An agent can infer a user's goal, inspect local state,
discover tools and services, plan a workflow, execute software, and revise the
plan as results arrive. In that environment the optimal interface cannot
always be known in advance. The interface itself becomes part of the plan.

This paper proposes **intent-native applications**: applications assembled at
runtime for a user's current objective from interface components, local data,
Linux programs, agents, tools, services, permissions, and approval points. The
result may exist for minutes, hours, or months; it may evolve during the task;
and two users expressing different goals to the same origin may receive
materially different application structures.

webTOS is a natural execution substrate for this model because dynamic
interfaces require dynamic execution. A generated comparison table is useful
only if something can obtain and normalize the compared data. A generated
terminal is useful only if a process can run behind it. A generated code-review
surface needs a repository, `git`, compilers, analyzers, and an agent. A media
workflow may need `ffmpeg`; a research workflow may need Python; a development
workflow may need an unmodified coding-agent binary. webTOS already supplies
the local Linux x86-64 execution boundary, filesystem, processes, terminals,
network brokerage, persistence, resource budgets, content-addressed image
foundations, and deterministic execution gates needed to make such generated
applications more than generated markup.

The central thesis is:

> **In an agentic Web, the application is no longer only a package written
> before the user arrives. It can be a runtime graph assembled from intent.**

This document develops that thesis without requiring a blockchain, token,
proprietary agent network, model vendor, or specific application framework.
webTOS remains a neutral MIT-licensed runtime. React, Vue, Svelte, Web
Components, remote APIs, local models, hosted models, open agents, commercial
agents, and ordinary Linux software can all participate above the same
execution boundary.

---

## 1. From Application-First to Intent-First

### 1.1 The conventional Web

A conventional Web application is designed approximately in this order:

```text
product requirements
        |
        v
developer chooses workflows
        |
        v
developer builds routes and components
        |
        v
developer binds APIs
        |
        v
application is deployed
        |
        v
user chooses among predefined actions
```

Modern frontend frameworks make this model efficient, reactive, and
maintainable. They do not fundamentally change who decides the application's
shape: the developer decides before runtime.

AI assistants are commonly inserted into the same structure as another
component:

```text
fixed application
  + chat panel
  + model API
```

The model may generate sophisticated answers while the application around it
remains static. This is an important product category, but it does not use the
full implication of an agent that can plan and act.

### 1.2 The agentic inversion

An agentic application can begin with the user's objective rather than a
preselected workflow:

```text
user intent
    |
    v
interpret context and constraints
    |
    v
discover available capabilities
    |
    v
construct a plan
    |
    +-- choose tools
    +-- choose data
    +-- choose local programs
    +-- choose remote services
    +-- choose interaction surfaces
    +-- request required authority
    |
    v
compose the application
    |
    v
execute, observe, and revise
```

The application becomes a projection of the current plan.

A user asking for a trip plan may receive maps, date controls, comparison
cards, a budget table, and explicit booking approvals. A developer asking to
repair a repository may receive a file tree, terminal, test results, code diff,
and approval surface for external effects. A researcher may receive a source
browser, Python-backed analysis table, charts, citations, and a persistent
workspace.

These are not merely different pages. They may require different executable
software, network destinations, files, state, and permissions.

---

## 2. Definition: Intent-Native Application

An **intent-native application** is a runtime application whose structure is
materially derived from a user's current goal and context rather than being
fully fixed at build time.

We model it as:

```text
Intent-Native Application
    = Intent
    + Application Graph
    + Execution Environment
    + Capabilities
    + State
    + Generated/Selected Interface
```

The word *generated* does not require that an LLM emit arbitrary source code.
A safer implementation can select and parameterize reviewed components from a
registry. Generation may occur at several levels:

1. selecting existing components;
2. connecting components into a graph;
3. choosing data bindings and commands;
4. generating declarative UI descriptions;
5. generating sandboxed application code where policy permits it.

The architecture should support the first four without requiring the fifth.

### 2.1 Ephemeral does not mean stateless

Many intent-native applications are **ephemeral in structure** but persistent
in state. The interface for a task can disappear while its workspace,
preferences, artifacts, and execution checkpoint survive. Reopening the task
may reconstruct a new interface over the same durable state.

This distinction is important:

```text
application structure   dynamic / replaceable
workspace state         persistent when granted
external authority      explicit and revocable
execution image         content-addressable
```

---

## 3. Why Dynamic UI Alone Is Insufficient

A model can already produce HTML, JSON UI schemas, or framework source code.
That does not by itself create an agentic application runtime.

Consider a generated button labelled `Run tests`. Something must actually:

- possess the repository;
- have the required compiler and package manager;
- start subprocesses;
- stream output;
- enforce CPU and memory limits;
- persist resulting files; and
- prevent the process from reaching unrelated user data or networks.

A generated travel comparison may need Python for normalization. A media tool
may need an existing native binary. A coding workflow may need `git`, a shell,
and a coding agent. If every dynamic interface requires a new cloud backend,
then the interface is dynamic but the execution architecture remains
application-server-first.

The missing abstraction is therefore not only **dynamic UI**. It is:

> **dynamic UI backed by a dynamically composed, bounded execution graph.**

webTOS supplies the local execution half of that problem.

---

## 4. webTOS as the Execution Substrate

webTOS currently runs unmodified Linux x86-64 binaries in a browser tab. The
runtime owns guest memory, process state, scheduling, filesystem semantics,
and Linux compatibility rather than mapping a guest directly onto ambient
browser authority.

The properties most relevant to intent-native applications are:

- unmodified Linux x86-64 ELF execution;
- processes, threads, signals, futexes, polling, and epoll;
- a virtual filesystem and persistent browser storage;
- pseudoterminals and interactive TUI support;
- guest-side DNS and TLS over a browser-controlled byte relay;
- deny-by-default network access;
- scoped runtime credential injection;
- memory, CPU, storage, network, and event-log budgets;
- filesystem snapshots and recovery after reload;
- canonical manifest and content-addressed lazy-image foundations; and
- deterministic execution gates across Chromium, Firefox, and WebKit.

These capabilities turn the browser from a renderer plus JavaScript runtime
into a host for local application backends.

The intended layering is:

```text
Dynamic Interface
  React / Vue / Svelte / Web Components / declarative UI
                         |
                         v
              Application Graph Runtime
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
      UI nodes       Agent nodes     Tool nodes
                                        |
                                        v
                                    webTOS
                         Linux x86-64 processes
                         VFS / PTY / sockets / state
                         capabilities / budgets
                                        |
                                        v
                                     Browser
```

webTOS does not replace frontend frameworks. It gives dynamically selected
components something substantial to execute against.

---

## 5. The Application Graph

The central proposed abstraction is the **Application Graph**.

A traditional application source tree encodes a mostly static graph at build
time. An intent-native runtime needs an explicit graph that can be created and
modified while the application runs.

Example:

```text
ApplicationGraph
|
+-- intent: "Review this repository and prepare a safe patch"
|
+-- state
|   +-- workspace: /workspace
|   `-- report: /artifacts/review.md
|
+-- execution
|   +-- process: git
|   +-- process: test runner
|   `-- agent: coding-agent
|
+-- interface
|   +-- FileTree(workspace)
|   +-- Terminal(agent.pty)
|   +-- DiffView(workspace.diff)
|   +-- TestResults(test.events)
|   `-- ApprovalCard(patch.apply)
|
+-- capabilities
|   +-- fs.read: /workspace
|   +-- fs.write: /workspace
|   `-- network: selected destinations
|
`-- budgets
    +-- memory
    +-- cpu
    +-- storage
    `-- network
```

The graph is not a DOM tree. It contains execution, state, authority, and UI
nodes. A UI renderer projects the relevant portion into the visible interface.

### 5.1 Node classes

A first graph model should remain small:

| Node | Purpose |
|---|---|
| `Intent` | User objective and explicit constraints |
| `State` | Files, structured data, task memory, artifacts |
| `Process` | A Linux process running inside webTOS |
| `Agent` | A process or service that can plan and invoke capabilities |
| `Service` | A remote capability reached through an approved adapter |
| `UI` | A reviewed interactive component or declarative surface |
| `Capability` | Explicit authority available to one or more nodes |
| `Approval` | A user-controlled decision point for a consequential action |
| `Budget` | Resource ceiling for a node or graph subtree |
| `Event` | Typed observation connecting execution to UI and policy |

### 5.2 Graph mutation

The graph must be mutable because plans change:

```text
observe result
     |
     v
agent proposes graph patch
     |
     v
schema validation
     |
     v
capability/policy validation
     |
     +-- no new authority --> apply
     |
     `-- authority increase --> approval or reject
     |
     v
render and execute new graph
```

An agent may propose a new chart or start a tool within an existing budget.
It must not silently enlarge its network access, filesystem scope, credentials,
or resource ceiling merely by generating a new graph node.

This leads to a foundational invariant:

> **Graph mutation can rearrange granted authority; it cannot manufacture new
> authority.**

---

## 6. UI Composition Model

The UI layer should be dynamic without making arbitrary generated JavaScript
the default trust model.

A practical progression is:

### Level 1 — component selection

The agent chooses reviewed components:

```json
{
  "component": "ComparisonTable",
  "props": {
    "source": "state://offers",
    "columns": ["name", "price", "latency"]
  }
}
```

### Level 2 — declarative composition

The agent composes layouts and dataflow:

```text
Stack
  Header(task.title)
  Split
    Map(state.locations)
    ComparisonTable(state.options)
  BudgetSummary(state.budget)
  ApprovalBar(action.commit)
```

### Level 3 — runtime-bound interaction

Components subscribe to typed process and state events:

```text
Terminal       <- pty://agent/main
DiffView       <- workspace://current/diff
Progress       <- event://job/progress
Chart          <- state://analysis/series
ApprovalCard   <- capability://request/42
```

### Level 4 — sandboxed generated extensions

Where a deployment explicitly permits it, generated code can run as an
additional sandboxed component. It receives a narrow message interface, not
ambient access to the host page or webTOS internals.

This hierarchy allows useful dynamic applications before solving the much
harder problem of safely executing arbitrary model-generated frontend code.

---

## 7. Execution Composition

Dynamic application composition must include executable dependencies.

A graph planner should be able to request an environment such as:

```text
base image
  + python3
  + git
  + ffmpeg
  + application-specific binary
```

but the browser should not eagerly download a multi-gigabyte disk image. The
content-addressed manifest and lazy paging direction in webTOS provides the
right foundation: identify an immutable environment, fetch metadata first, and
materialize only the chunks execution touches.

A future package/image layer can make this developer-facing:

```toml
[application]
name = "media-analysis"

[image]
base = "linux-x86_64:minimal"
packages = ["python3", "ffmpeg"]

[entrypoints]
analyze = ["python3", "/app/analyze.py"]

[capabilities]
filesystem = ["/workspace"]
network = []

[budgets]
memory_mb = 1024
storage_mb = 512
```

The exact syntax is proposed. The important property is that the application
graph refers to reproducible executable environments rather than silently
installing arbitrary software with ambient authority.

---

## 8. Proposed Developer Surface

Developers should not need to understand x86 decoding, p-code, softmmu, ELF
loading, futexes, or browser worker internals.

A future public API could expose a compact execution vocabulary:

```ts
// Illustrative API; not shipped.
const runtime = await WebTOS.create({
  image: "sha256:<manifest-root>",
  budgets: {
    memoryMB: 1024,
    storageMB: 512,
  },
});

const workspace = await runtime.mount(userWorkspace, {
  guestPath: "/workspace",
  access: "read-write",
});

const process = await runtime.exec([
  "/usr/bin/python3",
  "/app/analyze.py",
  "/workspace/input.csv",
]);

const terminal = await runtime.attachPTY(process);
```

Above it, an application-composition API could operate on graph primitives:

```ts
// Illustrative API; not shipped.
const app = await IntentApp.create({ runtime });

await app.apply({
  add: [
    UI.table({ source: "state://analysis" }),
    UI.chart({ source: "state://analysis" }),
    UI.terminal({ source: terminal }),
  ],
});
```

The runtime API and composition API should remain separate. A developer may
use webTOS without dynamic UI, and a composition framework may use remote
services without webTOS. Neutrality and composability are features.

---

## 9. Authority Is Part of the Application Graph

Dynamic applications are dangerous if generated structure implicitly creates
permissions.

The runtime must distinguish:

```text
what the agent wants
        !=
what the graph describes
        !=
what the runtime permits
```

An agent can propose:

```text
"I need github.com:443"
```

but the host policy decides whether that capability is already granted,
requires user approval, or is forbidden.

A capability node should therefore carry explicit scope:

```text
Capability
  type: network.connect
  subject: agent:reviewer
  target: github.com:443
  expires: task-end
  budget: 50 MiB
```

Likewise for filesystem, secrets, clipboard, camera, microphone, local files,
remote APIs, and future browser capabilities.

### 9.1 Approval is UI generated from policy, not from the agent

A consequential approval surface must not be arbitrary agent-authored text