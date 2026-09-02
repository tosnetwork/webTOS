// Probe: does the Claude Code TUI paint under the engine when the JIT is on?
// Drives the wasm module directly (Node's V8 compiles the engine ~30x faster
// than the native interpreter), delivers claude + loader + glibc by manifest,
// installs a pty, and pumps until the TUI paints or a budget runs out. Claude
// renders with Ink on the MAIN screen (no alternate-screen switch), so the
// paint detector is its first interactive text, not \x1b[?1049h.
// Usage: node web/probe_claude_tui.mjs [minutes]
import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createConnection } from "node:net";
import { createSocket } from "node:dgram";
import { resolve4, resolve6 } from "node:dns/promises";
import { makeJitHost } from "./jit_host.mjs";

const wasmPath = new URL("./webtos_web.wasm", import.meta.url).pathname;
const realTask = process.env.PROBE_REAL_TASK === "1";
const fetchFixture = process.env.PROBE_FETCH_FIXTURE === "1";
const networkMode = realTask || fetchFixture;
// This exercises the exact browser/PTY/controller path without depending on
// a remote model service.  It deliberately renders the same accessibility
// cursor-position controls used by the real client, waits for the explicit
// trust selection, accepts a task, mutates the scoped work file, and waits for
// `/exit`.  It is a state-machine fixture, never evidence about Claude itself.
const mockTask = process.env.PROBE_MOCK_CLAUDE === "1";
const taskMode = realTask || mockTask;
// This diagnostic is deliberately opt-in.  It begins only after the controller
// has submitted the task, so the multi-billion-instruction Bun cold-start does
// not drown the evidence needed to explain a post-prompt stall.
const taskTrace = process.env.PROBE_TASK_TRACE === "1";
// Capture the narrow synchronous failure window after Claude has constructed
// an API request but before a broker command appears.  Starting at terminal
// submission is too early: Bun can exhaust a bounded trace while preparing the
// request.  Starting after the debug marker lets the following retry expose
// the exact guest syscall result that Claude turns into "Connection error".
const apiFailureTrace = realTask && process.env.PROBE_API_FAILURE_TRACE === "1";
const apiFailureTraceInstructions = Number(
  process.env.PROBE_API_FAILURE_TRACE_INSTRUCTIONS ?? 800_000_000,
);
if (!Number.isSafeInteger(apiFailureTraceInstructions) || apiFailureTraceInstructions < 1) {
  throw new Error(
    `PROBE_API_FAILURE_TRACE_INSTRUCTIONS must be a positive integer, got ${process.env.PROBE_API_FAILURE_TRACE_INSTRUCTIONS}`,
  );
}
// Claude's own debug stream is opt-in and routed to the controlling terminal
// only for diagnosis. Real-session output remains redacted; below we expose
// boolean lifecycle markers rather than log lines, request IDs, or content.
const claudeDebug = realTask && process.env.PROBE_CLAUDE_DEBUG === "1";
const claudeDebugPath = "/work/claude-debug.log";
// Metadata-only transport chronology for diagnosing a guest runtime. It never
// prints command payloads (which are encrypted TLS records but can still carry
// sensitive traffic), credentials, terminal text, or response bytes.
const networkTrace = networkMode && process.env.PROBE_NET_TRACE === "1";
const networkTraceEpoch = performance.now();
let networkTraceSequence = 0;
const traceNetwork = (event, fields = {}) => {
  if (!networkTrace) return;
  networkTraceSequence += 1;
  console.error(
    `[network-trace] seq=${networkTraceSequence} ms=${Math.round(performance.now() - networkTraceEpoch)} ` +
      `event=${event} ${Object.entries(fields)
        .map(([key, value]) => `${key}=${String(value).replaceAll(/\s/g, "_")}`)
        .join(" ")}`.trimEnd(),
  );
};
const taskTraceInstructions = Number(process.env.PROBE_TASK_TRACE_INSTRUCTIONS ?? 750_000_000);
if (!Number.isSafeInteger(taskTraceInstructions) || taskTraceInstructions < 1) {
  throw new Error(`PROBE_TASK_TRACE_INSTRUCTIONS must be a positive integer, got ${process.env.PROBE_TASK_TRACE_INSTRUCTIONS}`);
}
// A real Claude/Bun startup executes billions of guest instructions before its
// first interactive frame on the interpreter, and the browser-side JIT replay
// deliberately favors architectural checking over throughput.  A measured
// healthy run can still be in startup after 343 million instructions and 25
// minutes. Keep an explicit CLI override for short diagnostic probes, but give
// the final real-task path a conservative eight-hour budget. The ordinary
// paint-only probe retains its short default. The guest task itself remains
// bounded by its virtual file, tool, credential, and network authorities; this
// is a wall-time allowance, not an authority expansion.
const minutes = Number(process.argv[2] ?? (realTask ? 480 : 10));

const claude = fetchFixture
  ? await readFile(
      process.env.PROBE_FETCH_RUNTIME ??
        "/tmp/webtos-bun-1.3.1/bun-linux-x64-baseline/bun",
    )
  : await readFile(new URL("./claude", import.meta.url));
const libDir = new URL("./claude-libs/", import.meta.url);
const mockClaude = mockTask
  ? await readFile(new URL("./mock_claude", import.meta.url))
  : null;
const lib = async (name) => ({
  path: name === "ld-linux-x86-64.so.2" ? "/lib64/ld-linux-x86-64.so.2" : `/lib/x86_64-linux-gnu/${name}`,
  bytes: await readFile(new URL(name, libDir)),
});
const files = [
  { path: fetchFixture ? "/bin/bun" : "/bin/claude", bytes: mockTask ? mockClaude : claude },
  await lib("ld-linux-x86-64.so.2"),
  await lib("libc.so.6"),
  await lib("libm.so.6"),
  await lib("libdl.so.2"),
  await lib("libpthread.so.0"),
  await lib("librt.so.1"),
];
if (fetchFixture) {
  files.push(
    { path: "/etc/resolv.conf", bytes: Buffer.from("nameserver 1.1.1.1\n") },
    {
      path: "/work/fetch-fixture.js",
      bytes: Buffer.from(`
const endpoint = "https://api.anthropic.com/api/hello";
const report = (label, error) =>
  console.log(\`FETCH \${label} code=\${error?.code ?? "none"} name=\${error?.name ?? "none"}\`);
await Promise.all([1, 2].map(async (attempt) => {
  try {
    const response = await fetch(endpoint);
    await response.body?.cancel();
    console.log(\`FETCH parallel=\${attempt} status=\${response.status}\`);
  } catch (error) {
    report(\`parallel=\${attempt}\`, error);
  }
}));
try {
  const response = await fetch(endpoint);
  const body = await response.arrayBuffer();
  console.log(\`FETCH final status=\${response.status} bytes=\${body.byteLength}\`);
} catch (error) {
  report("final", error);
}
`),
    },
  );
}
if (taskMode) {
  files.push(
    { path: "/bin/busybox", bytes: await readFile(new URL("./busybox-musl", import.meta.url)) },
    {
      path: "/root/.claude.json",
      bytes: Buffer.from(JSON.stringify({
        hasCompletedOnboarding: true,
        theme: "dark",
        projects: { "/work": { allowedTools: [], hasTrustDialogAccepted: true } },
      })),
    },
    { path: "/etc/resolv.conf", bytes: Buffer.from("nameserver 1.1.1.1\n") },
    { path: "/work/input.txt", bytes: Buffer.from("M9_PENDING\n") },
  );
}

const chunkSize = 64 * 1024;
const chunks = new Map();
const dirs = new Set();
const records = [];
for (const { path, bytes } of files) {
  let at = 1;
  for (;;) {
    const next = path.indexOf("/", at);
    if (next < 0) break;
    dirs.add(path.slice(0, next));
    at = next + 1;
  }
  const hashes = [];
  for (let off = 0; off < bytes.length; off += chunkSize) {
    const chunk = bytes.subarray(off, Math.min(off + chunkSize, bytes.length));
    const hash = createHash("sha256").update(chunk).digest("hex");
    hashes.push(hash);
    chunks.set(hash, chunk);
  }
  records.push({
    path,
    line: `f 755 0 ${Buffer.from(path).toString("hex")} ${bytes.length} ${chunkSize} ${"0".repeat(16)} ${hashes.join(",")}`,
  });
}
for (const d of dirs) records.push({ path: d, line: `d 755 0 ${Buffer.from(d).toString("hex")}` });
records.sort((a, b) => (a.path < b.path ? -1 : 1));
const manifest = `webtos-chunk-manifest 1\n${records.map((r) => r.line).join("\n")}\n`;

const jit = makeJitHost();
const { instance } = await WebAssembly.instantiate(await readFile(wasmPath), { env: jit.imports });
const e = instance.exports;
jit.bind(e);
const mem = () => new Uint8Array(e.memory.buffer);
const put = (v) => {
  const d = typeof v === "string" ? new TextEncoder().encode(v) : v;
  const p = e.wtw_alloc(d.length);
  mem().set(d, p);
  return [p, d.length];
};
const err = () => new TextDecoder().decode(mem().slice(e.wtw_error_ptr(), e.wtw_error_ptr() + e.wtw_error_len()));

// The block JIT is useful for ordinary guest workloads, but the current
// browser bridge is counterproductive for Bun's startup: it produces millions
// of tiny, dynamically generated blocks whose compile/call crossings dominate
// execution. A measured real-Claude start advanced ~18x faster in the
// interpreter. Keep JIT opt-in for this acceptance workload so this probe
// validates the architectural path rather than timing out in an unrelated
// optimizer limitation; `PROBE_JIT=1` remains available for profiling it.
const useJit =
  process.env.PROBE_JIT === "1" || (!networkMode && process.env.PROBE_JIT !== "0");
const usePty = process.env.PROBE_PTY !== "0";
const traceEvery = Number(process.env.PROBE_TRACE_EVERY ?? 0);
if (!Number.isSafeInteger(traceEvery) || traceEvery < 0 || traceEvery > 0xffff_ffff) {
  throw new Error(`PROBE_TRACE_EVERY must be a non-negative u32, got ${process.env.PROBE_TRACE_EVERY}`);
}
// A cold Claude start has far more events than are useful for diagnosing a
// post-paint stall.  Let a reproduction defer the bounded trace until a known
// guest instruction boundary, rather than retaining the entire bootstrap.
const traceAfterIcount = process.env.PROBE_TRACE_AFTER_ICOUNT === undefined
  ? null
  : Number(process.env.PROBE_TRACE_AFTER_ICOUNT);
if (
  traceAfterIcount !== null &&
  (!Number.isSafeInteger(traceAfterIcount) || traceAfterIcount < 0)
) {
  throw new Error(
    `PROBE_TRACE_AFTER_ICOUNT must be a non-negative safe integer, got ${process.env.PROBE_TRACE_AFTER_ICOUNT}`,
  );
}
const traceAfterRenderedBytes = process.env.PROBE_TRACE_AFTER_RENDERED_BYTES === undefined
  ? null
  : Number(process.env.PROBE_TRACE_AFTER_RENDERED_BYTES);
if (
  traceAfterRenderedBytes !== null &&
  (!Number.isSafeInteger(traceAfterRenderedBytes) || traceAfterRenderedBytes < 1)
) {
  throw new Error(
    `PROBE_TRACE_AFTER_RENDERED_BYTES must be a positive safe integer, got ${process.env.PROBE_TRACE_AFTER_RENDERED_BYTES}`,
  );
}
const traceEventBudget = Number(process.env.PROBE_TRACE_EVENT_BUDGET ?? 0);
if (!Number.isSafeInteger(traceEventBudget) || traceEventBudget < 0 || traceEventBudget > 0xffff_ffff) {
  throw new Error(
    `PROBE_TRACE_EVENT_BUDGET must be a non-negative u32, got ${process.env.PROBE_TRACE_EVENT_BUDGET}`,
  );
}
const traceStopAfterIcount = process.env.PROBE_TRACE_STOP_AFTER_ICOUNT === undefined
  ? null
  : Number(process.env.PROBE_TRACE_STOP_AFTER_ICOUNT);
if (
  traceStopAfterIcount !== null &&
  (!Number.isSafeInteger(traceStopAfterIcount) || traceStopAfterIcount < 0)
) {
  throw new Error(
    `PROBE_TRACE_STOP_AFTER_ICOUNT must be a non-negative safe integer, got ${process.env.PROBE_TRACE_STOP_AFTER_ICOUNT}`,
  );
}
if (
  traceAfterIcount !== null &&
  traceStopAfterIcount !== null &&
  traceStopAfterIcount < traceAfterIcount
) {
  throw new Error("PROBE_TRACE_STOP_AFTER_ICOUNT must not precede PROBE_TRACE_AFTER_ICOUNT");
}
const logEvery = Number(process.env.PROBE_LOG_EVERY ?? 50);
if (!Number.isSafeInteger(logEvery) || logEvery < 1) {
  throw new Error(`PROBE_LOG_EVERY must be a positive integer, got ${process.env.PROBE_LOG_EVERY}`);
}
const guestMemoryMb = Number(process.env.PROBE_GUEST_MEMORY_MB ?? 2048);
if (!Number.isSafeInteger(guestMemoryMb) || guestMemoryMb < 1) {
  throw new Error(`PROBE_GUEST_MEMORY_MB must be a positive integer, got ${process.env.PROBE_GUEST_MEMORY_MB}`);
}
const jitAfter = Number(process.env.PROBE_JIT_AFTER ?? 10);
if (!Number.isSafeInteger(jitAfter) || jitAfter < 1) {
  throw new Error(`PROBE_JIT_AFTER must be a positive integer, got ${process.env.PROBE_JIT_AFTER}`);
}
if (e.wtw_init() !== 0) throw new Error(`init: ${err()}`);
if (e.wtw_set_guest_memory_mb(guestMemoryMb) !== 0) throw new Error(`guestmem: ${err()}`);
if (useJit && e.wtw_jit_enable(jitAfter) !== 0) throw new Error(`jit: ${err()}`);
if (e.wtw_install_chunk_manifest(...put(manifest)) !== 0) throw new Error(`manifest: ${err()}`);
const executable = taskMode ? "/bin/busybox" : fetchFixture ? "/bin/bun" : "/bin/claude";
if (taskMode) {
  e.wtw_arg(...put("sh"));
  e.wtw_arg(...put("-i"));
}
if (fetchFixture) {
  e.wtw_arg(...put("bun"));
  e.wtw_arg(...put("/work/fetch-fixture.js"));
}
if (realTask) {
  const principal = "claude-m9-acceptance";
  const credentials = await readFile(
    process.env.PROBE_CLAUDE_CREDENTIALS ?? "/home/tomi/.claude/.credentials.json",
  );
  if (e.wtw_agent_principal(...put(principal)) !== 0) {
    throw new Error(`agent principal: ${err()}`);
  }
  if (e.wtw_secret_handle(
    ...put("CLAUDE_OAUTH_PROFILE"),
    ...put(credentials),
    ...put("/root/.claude/.credentials.json"),
    ...put(principal),
  ) !== 0) {
    throw new Error(`credential handle: ${err()}`);
  }
  if (e.wtw_net_enable() !== 0) throw new Error(`network: ${err()}`);
} else if (fetchFixture) {
  if (e.wtw_net_enable() !== 0) throw new Error(`network: ${err()}`);
} else if (!taskMode) {
  e.wtw_arg(...put("claude"));
  // Minimal-startup mode is useful for an unauthenticated paint-only probe.
  e.wtw_arg(...put("--bare"));
  e.wtw_arg(...put("--ax-screen-reader"));
}
e.wtw_env(...put("PATH=/bin"));
e.wtw_env(...put("HOME=/root"));
e.wtw_env(...put("TERM=xterm-256color"));
e.wtw_env(...put("PS1=webtos:\\w$ "));
e.wtw_env(...put("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1"));
// Diagnostic only: isolate JSC's concurrent collectors and compilation pools
// from the main-thread startup path.  The acceptance gate never sets this;
// a result obtained with it cannot count as workload compatibility.
if (process.env.PROBE_JSC_SINGLE_THREADED === "1") {
  for (const setting of [
    "BUN_JSC_useConcurrentGC=false",
    "BUN_JSC_numberOfGCMarkers=1",
    "BUN_JSC_minNumberOfWorklistThreads=1",
    "BUN_JSC_maxNumberOfWorklistThreads=1",
    "BUN_JSC_numberOfBaselineCompilerThreads=1",
    "BUN_JSC_numberOfDFGCompilerThreads=1",
    "BUN_JSC_numberOfFTLCompilerThreads=1",
    "BUN_JSC_numberOfWasmCompilerThreads=1",
  ]) {
    e.wtw_env(...put(setting));
  }
}
if (process.env.PROBE_GLIBC_TUNABLES) {
  e.wtw_env(...put(`GLIBC_TUNABLES=${process.env.PROBE_GLIBC_TUNABLES}`));
}

const deliver = (ctx) => {
  const len = e.wtw_page_request_take();
  if (len !== 65) throw new Error(`${ctx}: request len ${len}: ${err()}`);
  const req = mem().slice(e.wtw_page_request_ptr(), e.wtw_page_request_ptr() + len);
  const hash = Buffer.from(req.slice(32, 64)).toString("hex");
  const view = new DataView(req.buffer, req.byteOffset, req.byteLength);
  const bytes = chunks.get(hash);
  if (!bytes) throw new Error(`${ctx}: unknown chunk ${hash}`);
  if (e.wtw_page_deliver(view.getUint32(0, true), view.getUint32(4, true), ...put(bytes)) !== 0) {
    throw new Error(`${ctx}: deliver: ${err()}`);
  }
};

const STATUS_AWAITING_INPUT = 7;
const STATUS_AWAITING_NETWORK = 8;
const NET_BUDGET_UNBOUNDED = 0xffff_ffff;
const ENETUNREACH = 101;
const ECONNRESET = 104;
const ETIMEDOUT = 110;
const ECONNREFUSED = 111;
const apiAddressFamilies = networkMode
  ? await Promise.all([
      resolve4("api.anthropic.com").catch(() => []),
      resolve6("api.anthropic.com").catch(() => []),
    ])
  : [[], []];
const canonicalAddress = (ip) => {
  if (!ip.includes(":")) return ip;
  // URL's host parser gives one RFC 5952-style representation, so a DNS
  // resolver's compressed spelling and the command stream's expanded
  // spelling cannot bypass or accidentally fail the exact allowlist.
  const host = new URL(`http://[${ip}]/`).hostname;
  return host.slice(1, -1);
};
const apiAddresses = new Set(apiAddressFamilies.flat().map(canonicalAddress));
const sockets = new Map();
let netEvents = 0;
let netWake = null;
let networkCommandBatches = 0;
let networkCommandBytes = 0;
const noteNetEvent = () => {
  netEvents += 1;
  if (netWake) {
    const wake = netWake;
    netWake = null;
    wake();
  }
};
const deliverNetError = (handle, errno) => {
  traceNetwork("guest-error", { handle, errno });
  e.wtw_net_error(handle, errno);
  noteNetEvent();
};
const nodeErrno = (error) => {
  if (error?.code === "ECONNREFUSED") return ECONNREFUSED;
  if (error?.code === "ETIMEDOUT") return ETIMEDOUT;
  if (error?.code === "ECONNRESET") return ECONNRESET;
  return ENETUNREACH;
};
const permitted = (ip, port) =>
  (ip === "1.1.1.1" && port === 53) ||
  (apiAddresses.has(canonicalAddress(ip)) && port === 443);
const deliverNetData = (handle, bytes) => {
  traceNetwork("guest-data", { handle, bytes: bytes.length });
  e.wtw_net_data(handle, ...put(bytes));
  noteNetEvent();
};
const openTcp = (handle, ip, port) => {
  if (!permitted(ip, port)) {
    console.error(`[network] refused tcp ${ip}:${port}`);
    deliverNetError(handle, ENETUNREACH);
    return;
  }
  traceNetwork("host-connect-start", {
    handle,
    family: ip.includes(":") ? 6 : 4,
    destination: `${ip}:${port}`,
  });
  const socket = createConnection({ host: ip, port, family: ip.includes(":") ? 6 : 4 });
  sockets.set(handle, { kind: "tcp", socket });
  socket.on("connect", () => {
    traceNetwork("host-connect", { handle });
    e.wtw_net_connected(handle, 0, 0);
    noteNetEvent();
  });
  socket.on("data", (bytes) => deliverNetData(handle, bytes));
  socket.on("end", () => {
    traceNetwork("host-end", { handle });
    e.wtw_net_closed(handle);
    noteNetEvent();
  });
  socket.on("error", (error) => {
    traceNetwork("host-error", { handle, code: error?.code ?? "unknown" });
    deliverNetError(handle, nodeErrno(error));
  });
  socket.on("close", (hadError) => traceNetwork("host-close", { handle, hadError }));
  socket.on("drain", () => traceNetwork("host-drain", { handle }));
};
const openUdp = (handle) => {
  const socket = createSocket("udp4");
  sockets.set(handle, { kind: "udp", socket });
  socket.on("message", (bytes, remote) => {
    traceNetwork("host-udp-data", {
      handle,
      family: remote.family,
      source: `${remote.address}:${remote.port}`,
      bytes: bytes.length,
    });
    const octets = remote.address.split(".").map(Number);
    const ip = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
    e.wtw_net_datagram(handle, ip, remote.port, ...put(bytes));
    noteNetEvent();
  });
  socket.on("error", (error) => deliverNetError(handle, nodeErrno(error)));
};
const takeNetworkCommands = () => {
  const len = e.wtw_net_take();
  if (len < 0) throw new Error(`network drain: ${err()}`);
  return mem().slice(e.wtw_net_cmd_ptr(), e.wtw_net_cmd_ptr() + len);
};
const performNetwork = (stream) => {
  const view = new DataView(stream.buffer, stream.byteOffset, stream.byteLength);
  let offset = 0;
  const u32 = () => {
    const value = view.getUint32(offset, true);
    offset += 4;
    return value;
  };
  const destination = () => {
    const ip = `${stream[offset]}.${stream[offset + 1]}.${stream[offset + 2]}.${stream[offset + 3]}`;
    const port = view.getUint16(offset + 4, false);
    offset += 6;
    return { ip, port };
  };
  const destination6 = () => {
    const groups = [];
    for (let at = 0; at < 16; at += 2) {
      groups.push(((stream[offset + at] << 8) | stream[offset + at + 1]).toString(16));
    }
    let ip = groups.join(":");
    const port = view.getUint16(offset + 16, false);
    // Flow information is transport metadata which Node does not expose on
    // connect. Scope is part of a routable link-local IPv6 address.
    const scope = view.getUint32(offset + 22, true);
    if (scope !== 0) ip += `%${scope}`;
    offset += 26;
    return { ip, port };
  };
  const payload = () => {
    const length = u32();
    const bytes = stream.slice(offset, offset + length);
    offset += length;
    return bytes;
  };
  while (offset < stream.length) {
    const op = stream[offset++];
    const handle = u32();
    if (op === 1) {
      const { ip, port } = destination();
      traceNetwork("command-connect", { handle, family: 4, destination: `${ip}:${port}` });
      openTcp(handle, ip, port);
    } else if (op === 2) {
      const bytes = payload();
      const accepted = sockets.get(handle)?.socket.write(bytes);
      traceNetwork("command-send", { handle, bytes: bytes.length, accepted: accepted ?? false });
    } else if (op === 3) {
      traceNetwork("command-shutdown-write", { handle });
      sockets.get(handle)?.socket.end();
    } else if (op === 4) {
      traceNetwork("command-udp-open", { handle });
      openUdp(handle);
    } else if (op === 5) {
      const { ip, port } = destination();
      const bytes = payload();
      traceNetwork("command-udp-send", {
        handle,
        destination: `${ip}:${port}`,
        bytes: bytes.length,
      });
      if (!permitted(ip, port)) {
        console.error(`[network] refused udp ${ip}:${port}`);
        deliverNetError(handle, ENETUNREACH);
      } else {
        sockets.get(handle)?.socket.send(bytes, port, ip);
      }
    } else if (op === 6) {
      const entry = sockets.get(handle);
      traceNetwork("command-close", { handle, kind: entry?.kind ?? "missing" });
      if (entry?.kind === "udp") entry.socket.close();
      else entry?.socket.destroy();
      sockets.delete(handle);
    } else if (op === 7) {
      const { ip, port } = destination6();
      traceNetwork("command-connect", { handle, family: 6, destination: `[${ip}]:${port}` });
      openTcp(handle, ip, port);
    } else {
      throw new Error(`unknown network opcode ${op}`);
    }
  }
};
// Broker commands are per-socket side effects, not a whole-machine wait
// state. A Bun worker may stay runnable after another thread queued connect
// or send, so every VM slice must dispatch these commands without blocking.
// Waiting for a reply remains exclusive to STATUS_AWAITING_NETWORK below.
const drainNetworkCommands = () => {
  const commands = takeNetworkCommands();
  if (commands.length === 0) return false;
  performNetwork(commands);
  networkCommandBatches += 1;
  networkCommandBytes += commands.length;
  console.error(
    `[network] dispatched_batch=${networkCommandBatches} bytes=${commands.length} total_bytes=${networkCommandBytes}`,
  );
  return true;
};
const pumpNetwork = async () => {
  const before = netEvents;
  drainNetworkCommands();
  if (netEvents !== before) return;
  const budget = e.wtw_net_budget_ms() >>> 0;
  const waitMs = Math.min(budget === NET_BUDGET_UNBOUNDED ? 1000 : budget, 1000);
  await new Promise((resolve) => {
    netWake = resolve;
    setTimeout(() => {
      if (netWake === resolve) {
        netWake = null;
        resolve();
      }
    }, waitMs);
  });
  if (netEvents === before) e.wtw_net_expire();
};

for (;;) {
  const s = e.wtw_load(...put(executable));
  if (s === 0) break;
  if (s !== 10) throw new Error(`load: status ${s}: ${err()}`);
  deliver("metadata");
}
if (usePty && e.wtw_pty_install(40, 120) !== 0) throw new Error(`pty: ${err()}`);
if (
  traceEvery > 0 &&
  traceAfterIcount === null &&
  traceAfterRenderedBytes === null &&
  e.wtw_trace_start(traceEvery) !== 0
) {
  throw new Error(`trace start: ${err()}`);
}
if (
  traceEvery > 0 &&
  traceAfterIcount === null &&
  traceAfterRenderedBytes === null &&
  traceEventBudget > 0 &&
  e.wtw_set_event_log_budget(traceEventBudget) !== 0
) {
  throw new Error(`trace budget: ${err()}`);
}
const maxFuel = process.env.PROBE_MAX_FUEL ? Number(process.env.PROBE_MAX_FUEL) : 50_000_000;
if (!Number.isSafeInteger(maxFuel) || maxFuel < 1) {
  throw new Error(`PROBE_MAX_FUEL must be a positive integer, got ${process.env.PROBE_MAX_FUEL}`);
}

const deadline = Date.now() + minutes * 60_000;
let rendered = "";
let status = 0;
let slices = 0;
let pageIns = 0;
let taskPhase = taskMode ? "shell" : "paint";
let taskSucceeded = false;
let networkWaits = 0;
let taskNetworkBaseline = 0;
let taskNetworkBatchBaseline = 0;
let taskSuccessBaseline = 0;
let exitMarkerBaseline = 0;
let taskTraceStartIcount = null;
let taskTraceExpired = false;
let apiFailureTraceStartIcount = null;
let apiFailureTraceExpired = false;
let tracing = traceEvery > 0 && traceAfterIcount === null && traceAfterRenderedBytes === null;
let deferredTraceStarted = false;
let trustSelectionSent = false;
let loggedRenderedBytes = 0;
let taskInputEchoed = false;
let loggedClaudeDebugState = "";
const guestFile = (path) => {
  const len = e.wtw_file_read(...put(path));
  if (len < 0) return null;
  return new TextDecoder().decode(mem().slice(e.wtw_file_read_ptr(), e.wtw_file_read_ptr() + len));
};
const taskInstruction =
  "Read /work/input.txt, replace M9_PENDING with M9_CLAUDE_COMPLETED using the Edit tool, " +
  "then reply with exactly WEBTOS_TASK_DONE.";
const currentIcount = () =>
  (e.wtw_icount_hi() >>> 0) * 2 ** 32 + (e.wtw_icount_lo() >>> 0);
// The cost of emulating runnable guest instructions is not guest-visible wall
// time. Feeding that host overhead back into the VM makes a slow emulator look
// like a suspended machine and can fire minutes of maintenance timers during
// process startup. Real blocking network waits advance through `net_expire`;
// suspension is tested separately. Keep this diagnostic warp opt-in only.
const realtimeClock = realTask && process.env.PROBE_REALTIME_CLOCK === "1";
const realtimeHostStart = performance.now();
const realtimeIcountStart = currentIcount();
let realtimeWarpAppliedMs = 0;
const syncRealtimeClock = () => {
  if (!realtimeClock) return;
  const hostElapsedMs = performance.now() - realtimeHostStart;
  const instructionElapsedMs = (currentIcount() - realtimeIcountStart) / 1_000_000;
  const deficitMs = Math.floor(hostElapsedMs - instructionElapsedMs - realtimeWarpAppliedMs);
  if (deficitMs > 0) {
    if (e.wtw_skip_time_ms(deficitMs) !== 0) throw new Error(`clock sync: ${err()}`);
    realtimeWarpAppliedMs += deficitMs;
  }
};
// Ink's accessibility renderer may position every word with a cursor-control
// sequence (for example `Quick ESC[8G safety`).  State detection must operate
// on that terminal projection, never on the raw byte stream.
const terminalText = () =>
  rendered
    .replace(/\x1b\][^\x07]*(?:\x07|\x1b\\)/g, "")
    // Ink's accessibility surface uses CHA (CSI n G) between words. It moves
    // the cursor to a column, so preserving a separator is the safe textual
    // projection; deleting it would turn `Quick safety` into `Quicksafety`.
    .replace(/\x1b\[[0-9;]*G/g, " ")
    .replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "")
    .replace(/\x1b[=>]/g, "");
const interactivePromptVisible = () =>
  /trust\s+this\s+folder|Welcome\s+to\s+Claude|Choose\s+the\s+text\s+style|What\s+can\s+I\s+help|How\s+can\s+I\s+help|Claude\s+Code\s+v\d/.test(terminalText());
// A verified Claude composer can read from a non-blocking terminal and wait
// in epoll rather than parking a blocking read.  The pty is a byte queue, so
// queuing a task at this explicit, non-trust prompt is safe; it will be read
// by that event loop on its next turn.  Do not use a generic paint byte count
// here: startup/progress frames are not input authority.
const composerPromptVisible = () =>
  !trustPromptVisible() && interactivePromptVisible();
const painted = () =>
  interactivePromptVisible() ||
  // A short paint-only probe is permitted to use a generic visual hint. A
  // task-bearing session is not: startup/progress screens can have the same
  // colour escape codes, and submitting a task into one would lose input.
  (!taskMode && rendered.length > 500 && rendered.includes("\x1b[38;5;"));
const drain = () => {
  const n = e.wtw_output_len();
  if (n > 0) rendered += new TextDecoder().decode(mem().slice(e.wtw_output_ptr(), e.wtw_output_ptr() + n));
};
const input = (text) => {
  if (e.wtw_pty_input(...put(text)) !== 0) throw new Error(`pty input: ${err()}`);
};
// A multithreaded guest can have its foreground TUI parked in read(pty) while
// another runtime thread remains runnable.  In that state wtw_run correctly
// returns STATUS_RUNNING, so status alone is not an input-admission signal.
const terminalInputPending = () => e.wtw_pty_input_pending() !== 0;
const occurrences = (needle) => rendered.split(needle).length - 1;
const safeErrorDetail = (value) =>
  value
    .replace(/https?:\/\/\S+/gi, "<url>")
    .replace(/\b(?:Bearer|Basic)\s+\S+/gi, "<authorization>")
    .replace(/\b(?:sk-ant|sk-|oauth)[A-Za-z0-9._-]+/gi, "<credential>")
    .replace(/\b[A-Za-z0-9_-]{32,}\b/g, "<opaque-id>")
    .slice(0, 240);
const claudeExited = () => /(?:^|\r?\n)WEBTOS_CLAUDE_EXIT=\d+/.test(rendered);
const trustPromptVisible = () => /Quick\s+safety\s+check|trust\s+this\s+folder/.test(terminalText());
while (Date.now() < deadline) {
  if (
    traceEvery > 0 &&
    !tracing &&
    ((traceAfterIcount !== null && currentIcount() >= traceAfterIcount) ||
      (traceAfterRenderedBytes !== null && rendered.length >= traceAfterRenderedBytes))
  ) {
    if (e.wtw_trace_start(traceEvery) !== 0) throw new Error(`deferred trace start: ${err()}`);
    if (traceEventBudget > 0 && e.wtw_set_event_log_budget(traceEventBudget) !== 0) {
      throw new Error(`deferred trace budget: ${err()}`);
    }
    tracing = true;
    deferredTraceStarted = true;
    console.error(
      `[trace] deferred trace started at icount=${currentIcount().toLocaleString()} rendered_bytes=${rendered.length} sample_every=${traceEvery} budget=${traceEventBudget}`,
    );
  }
  if (traceStopAfterIcount !== null && currentIcount() >= traceStopAfterIcount) {
    console.error(`[trace] requested stop at icount=${currentIcount().toLocaleString()}`);
    break;
  }
  const t0 = Date.now();
  status = tracing ? e.wtw_run_traced(maxFuel) : e.wtw_run(maxFuel);
  syncRealtimeClock();
  slices += 1;
  if (slices <= 20 || slices % logEvery === 0) {
    const ic = (e.wtw_icount_hi() >>> 0) * 2 ** 32 + (e.wtw_icount_lo() >>> 0);
    console.error(
      `[slice ${slices}] status=${status} icount=${ic.toLocaleString()} ms=${Date.now() - t0} ` +
        `rendered=${rendered.length} jit_blocks=${Number(e.wtw_jit_block_dispatch_count()).toLocaleString()} ` +
        `jit_regions=${Number(e.wtw_jit_region_dispatch_count()).toLocaleString()} ` +
        `jit_code_bytes=${Number(e.wtw_jit_code_bytes()).toLocaleString()} ` +
        `jit_evictions=${Number(e.wtw_jit_evictions()).toLocaleString()} ` +
        `guest_mem_mb=${e.wtw_guest_memory_used_mb()}/${e.wtw_guest_memory_cap_mb()}`,
    );
  }
  drain();
  // Do not hide per-thread network work behind a whole-machine status. The
  // broker's empty take is a side-effect-free zero-length result.
  if (realTask && drainNetworkCommands()) {
    // A queued non-blocking connect is not complete until Node's socket
    // callback runs. Bun may keep unrelated guest threads runnable, so the
    // machine need not report a whole-process network wait yet. Yield exactly
    // after a new host command batch; otherwise a synchronous probe loop can
    // starve the callback that makes EPOLLOUT true.
    await new Promise((resolve) => setImmediate(resolve));
  }
  // This is only a boolean confirmation that the fixed, locally generated
  // acceptance instruction crossed the terminal boundary.  Never print the
  // terminal transcript for a real session: it can contain model output or
  // private task data.
  if (
    (taskPhase === "task-text" || taskPhase === "task") &&
    !taskInputEchoed &&
    terminalText().includes("Read /work/input.txt")
  ) {
    taskInputEchoed = true;
    console.error("[terminal-input] task_instruction_echoed=true");
  }
  // Keep enough provenance to distinguish a genuinely quiet Bun bootstrap
  // from a state transition that simply has not reached an input boundary.
  // This records byte counts only; it deliberately does not print potentially
  // sensitive terminal content.
  if (rendered.length !== loggedRenderedBytes) {
    console.error(
      `[terminal-output] phase=${taskPhase} rendered_bytes=${rendered.length} ` +
        `delta=${rendered.length - loggedRenderedBytes} status=${status} ` +
        `interactive_prompt=${interactivePromptVisible()} trust_prompt=${trustPromptVisible()} ` +
        `terminal_input_pending=${terminalInputPending()}`,
    );
    loggedRenderedBytes = rendered.length;
  }
  // Read Claude's private debug file only after the task has been submitted.
  // Before that point a missing file is expected, and probing it must not
  // replace a genuine VM diagnostic in the shared error buffer.
  if (claudeDebug && taskPhase === "task" && slices % 250 === 0) {
    const debugText = guestFile(claudeDebugPath);
    if (debugText !== null) {
      const connectionDetails = [
        ...debugText.matchAll(/Connection error details: code=([^,\r\n]*), message=([^\r\n]*)/g),
      ]
        .map((match) => ({
          code: safeErrorDetail(match[1].trim()),
          message: safeErrorDetail(match[2].trim()),
        }))
        .filter(
          (item, index, all) =>
            all.findIndex(
              (candidate) =>
                candidate.code === item.code && candidate.message === item.message,
            ) === index,
        )
        .slice(-4);
      const debugLifecycle = {
        // Counts and fixed source labels distinguish Claude's background
        // session-title request from the actual engine turn without exposing
        // prompts, model output, request IDs, or account data.
        apiDispatchCount: (debugText.match(/\[API:timing\] dispatching/g) ?? []).length,
        apiRequestCount: (debugText.match(/\[API REQUEST\]/g) ?? []).length,
        titleRequest: debugText.includes("source=generate_session_title"),
        replMainRequest: debugText.includes("source=repl_main_thread"),
        sdkRequest: debugText.includes("source=sdk"),
        engineTurnStart: /\[engine\] turn \d+ start/.test(debugText),
        firstByte: debugText.includes("[API:timing] first byte"),
        engineTurnEnd: /\[engine\] turn \d+ end/.test(debugText),
        toolUse: debugText.includes("tool_use") || debugText.includes("ToolUse"),
        bootstrapFetchOk: debugText.includes("[Bootstrap] Fetch ok"),
        authError: /auth(?:entication|orization)?[^\r\n]{0,80}(?:error|failed|invalid)/i.test(debugText),
        apiError: /\[API[^\]]*\][^\r\n]{0,120}(?:error|failed)/i.test(debugText),
        connectionError: debugText.includes("undefined Connection error"),
        connectionDetails,
        fetchError: /(?:fetch|network)[^\r\n]{0,100}(?:error|failed|timeout)/i.test(debugText),
      };
      const debugState = JSON.stringify(debugLifecycle);
      if (debugState !== loggedClaudeDebugState) {
        console.error(`[claude-debug-state] ${debugState}`);
        loggedClaudeDebugState = debugState;
      }
      if (
        apiFailureTrace &&
        apiFailureTraceStartIcount === null &&
        debugLifecycle.engineTurnStart
      ) {
        // Events only: register samples spend the finite event budget without
        // explaining a synchronous I/O failure.  Starting at engine-turn
        // admission captures the *first* request's initialization; later
        // retries can merely rethrow an error cached by Bun's dispatcher.
        if (e.wtw_trace_start(0) !== 0) {
          throw new Error(`API failure trace: ${err()}`);
        }
        if (e.wtw_set_event_log_budget(32768) !== 0) {
          throw new Error(`API failure trace budget: ${err()}`);
        }
        tracing = true;
        apiFailureTraceStartIcount = currentIcount();
        console.error(
          `[trace] API failure trace started at icount=${apiFailureTraceStartIcount.toLocaleString()} ` +
            `before_or_at_requests=${debugLifecycle.apiRequestCount}`,
        );
      }
    }
  }
  if (
    apiFailureTraceStartIcount !== null &&
    currentIcount() - apiFailureTraceStartIcount >= apiFailureTraceInstructions
  ) {
    apiFailureTraceExpired = true;
    console.error(
      `[trace] API failure trace budget reached at icount=${currentIcount().toLocaleString()}`,
    );
    break;
  }
  if (status === STATUS_AWAITING_NETWORK) {
    networkWaits += 1;
    await pumpNetwork();
    continue;
  }
  if (status === 10) {
    deliver("run");
    pageIns += 1;
    continue;
  }
  if (taskMode) {
    if (taskPhase === "shell" && status === 7) {
      input(
        // `--mcp-config` takes a configuration-file input, not an inline JSON
        // document. Passing JSON makes Claude reject the startup profile before
        // it can draw. Safe mode is stronger and sufficient here: Claude
        // disables MCP, skills, hooks, plugins, agents, and project
        // customizations, while the virtual filesystem/network broker remains
        // the independent execution boundary.
        "cd /work && /bin/claude --safe-mode --ax-screen-reader --no-chrome " +
          (claudeDebug ? `--debug-file ${claudeDebugPath} ` : "") +
          "--permission-mode acceptEdits " +
          "--allowedTools Read,Edit --model haiku; echo WEBTOS_CLAUDE_EXIT=$?\r",
      );
      taskPhase = "claude-start";
      continue;
    }
    if (taskPhase === "claude-start" && trustPromptVisible()) {
      // The workspace safety chooser starts on "No, exit". It is a distinct
      // TUI state: a natural-language task here would merely become input to
      // the chooser. Select the explicit trust option first, then wait for the
      // next terminal-read boundary before addressing Claude.
      input("\x1b[B\r");
      trustSelectionSent = true;
      taskPhase = "trust";
      continue;
    }
    // Prefer a concrete pending pty read, but do not confuse it with the
    // only admissible TUI shape. Bun may use O_NONBLOCK + epoll for stdin, in
    // which case the foreground has no blocked read even though it is at the
    // verified composer. The pty preserves the bytes until that poll reads.
    if (
      taskPhase === "claude-start" &&
      (terminalInputPending() || composerPromptVisible())
    ) {
      // Bun/Ink distinguishes human key events from pasted input partly by
      // delivery shape. If the text and CR share one pty write, they can be
      // returned by one read and the trailing CR can remain part of the paste
      // instead of becoming the Return key. Send the text first; the
      // task-text state waits for proof that the guest consumed it before a
      // separate Return event is admitted.
      input(taskInstruction);
      taskNetworkBaseline = networkWaits;
      taskNetworkBatchBaseline = networkCommandBatches;
      taskSuccessBaseline = occurrences("WEBTOS_TASK_DONE");
      taskPhase = "task-text";
      continue;
    }
    if (taskPhase === "trust" && terminalInputPending() && trustSelectionSent) {
      input(taskInstruction);
      taskNetworkBaseline = networkWaits;
      taskNetworkBatchBaseline = networkCommandBatches;
      taskSuccessBaseline = occurrences("WEBTOS_TASK_DONE");
      taskPhase = "task-text";
      continue;
    }
    if (
      taskPhase === "task-text" &&
      // The real TUI's application-level repaint proves that Ink consumed
      // the text. The deterministic mock does not echo in raw mode, so its
      // next blocked terminal read is the equivalent consumption proof.
      (taskInputEchoed || (mockTask && terminalInputPending()))
    ) {
      input("\r");
      taskPhase = "task";
      if (taskTrace) {
        // Trace from the semantic submit event rather than from the preceding
        // text insertion, so the bounded event budget covers task dispatch.
        if (e.wtw_trace_start(50_000_000) !== 0) throw new Error(`task trace: ${err()}`);
        if (e.wtw_set_event_log_budget(4096) !== 0) throw new Error(`task trace budget: ${err()}`);
        tracing = true;
        taskTraceStartIcount = currentIcount();
      }
      continue;
    }
    if (taskPhase === "claude-start" && claudeExited()) {
      const visible = rendered
        .replace(/\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[=>]/g, "")
        .trim();
      throw new Error(`Claude exited before painting: ${JSON.stringify(visible.slice(-800))}`);
    }
    if (
      taskPhase === "task" &&
      terminalInputPending() &&
      (mockTask ||
        networkWaits > taskNetworkBaseline ||
        networkCommandBatches > taskNetworkBatchBaseline) &&
      occurrences("WEBTOS_TASK_DONE") > taskSuccessBaseline
    ) {
      exitMarkerBaseline = occurrences("WEBTOS_CLAUDE_EXIT=");
      input("/exit\r");
      taskPhase = "exit";
      continue;
    }
    if (
      taskPhase === "exit" &&
      terminalInputPending() &&
      occurrences("WEBTOS_CLAUDE_EXIT=") > exitMarkerBaseline
    ) {
      input("printf 'WEBTOS_FILE='; /bin/busybox cat /work/input.txt; echo WEBTOS_FILE_CHECK\r");
      taskPhase = "verify";
      continue;
    }
    if (
      taskPhase === "verify" &&
      rendered.includes("WEBTOS_FILE=M9_CLAUDE_COMPLETED") &&
      rendered.includes("WEBTOS_FILE_CHECK")
    ) {
      taskSucceeded = true;
      break;
    }
    if (
      taskTraceStartIcount !== null &&
      currentIcount() - taskTraceStartIcount >= taskTraceInstructions
    ) {
      taskTraceExpired = true;
      console.error(
        `[task-trace] instruction window exhausted after ${(currentIcount() - taskTraceStartIcount).toLocaleString()} guest instructions`,
      );
      break;
    }
  }
  if (!taskMode && painted()) break;
  if (status === 7) {
    // An idle pty is not runnable guest work. Avoid burning a host core while
    // retaining prompt responsiveness for terminal input and network events.
    await new Promise((resolve) => setTimeout(resolve, 1));
    continue;
  }
  if (status !== 0) break;
  // wtw_run is synchronous. Once a host socket exists, yield so Node can run
  // connect/data/error callbacks even while another guest thread keeps the
  // VM continuously runnable.
  if (networkMode && sockets.size > 0) {
    await new Promise((resolve) => setImmediate(resolve));
  }
}
drain();

const icount = (e.wtw_icount_hi() >>> 0) * 2 ** 32 + (e.wtw_icount_lo() >>> 0);
const alt = painted();
console.log(
  `jit=${useJit} jit_after=${jitAfter} pty=${usePty} realtime_clock=${realtimeClock} ` +
    `guest_memory_mb=${guestMemoryMb} ` +
    `clock_warp_ms=${realtimeWarpAppliedMs} status=${status} slices=${slices} ` +
    `network_command_batches=${networkCommandBatches} network_command_bytes=${networkCommandBytes} ` +
    `page_ins=${pageIns} icount=${icount.toLocaleString()} ` +
    `jit_blocks=${Number(e.wtw_jit_block_dispatch_count()).toLocaleString()} ` +
    `jit_regions=${Number(e.wtw_jit_region_dispatch_count()).toLocaleString()} ` +
    `jit_code_bytes=${Number(e.wtw_jit_code_bytes()).toLocaleString()} ` +
    `jit_evictions=${Number(e.wtw_jit_evictions()).toLocaleString()}`,
);
if (status !== 0 && status !== 1 && status !== 7) console.log(`engine error: ${err()}`);
console.log(
  `painted=${alt} real_task=${realTask} mock_task=${mockTask} task_phase=${taskPhase} task_succeeded=${taskSucceeded} task_trace_expired=${taskTraceExpired} api_failure_trace_expired=${apiFailureTraceExpired} ` +
    `task_instruction_echoed=${taskInputEchoed} deferred_trace_started=${deferredTraceStarted} rendered_bytes=${rendered.length}`,
);
const printable = rendered.replace(/\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[=>]/g, "").trim();
// A real session can legitimately render private task data or model output.
// The acceptance signal above is deliberately marker-based, so do not leak a
// terminal transcript into CI or a developer console. The deterministic mock
// keeps its small projection for controller debugging.
if (realTask) console.log("visible text: redacted for real-task acceptance");
else console.log(`visible text (first 400): ${JSON.stringify(printable.slice(0, 400))}`);
if (tracing) {
  const traceLen = e.wtw_trace_take();
  if (traceLen < 0) throw new Error(`trace take: ${err()}`);
  const traceText = new TextDecoder().decode(
    mem().slice(e.wtw_trace_ptr(), e.wtw_trace_ptr() + traceLen),
  );
  if (process.env.PROBE_TRACE_OUTPUT) {
    await writeFile(process.env.PROBE_TRACE_OUTPUT, traceText, { mode: 0o600 });
    console.error(`[trace] raw trace written to ${process.env.PROBE_TRACE_OUTPUT}`);
  }
  const ripCounts = new Map();
  const syscallCounts = new Map();
  const syscallShapeCounts = new Map();
  const syscallErrorCounts = new Map();
  let stateSamples = 0;
  for (const line of traceText.split("\n")) {
    const fields = line.trim().split(/\s+/);
    if (fields[1] === "state" && fields.length >= 19) {
      stateSamples += 1;
      const rip = fields[18]; // RAX..R15 are fields 2..17; RIP is field 18.
      ripCounts.set(rip, (ripCounts.get(rip) ?? 0) + 1);
      continue;
    }
    const syscall = line.match(
      / syscall pid=(\d+) nr=(\d+) args=([^ ]+) ret=([^ ]+)/,
    );
    if (syscall) {
      const key = `pid=${syscall[1]} nr=${syscall[2]}`;
      syscallCounts.set(key, (syscallCounts.get(key) ?? 0) + 1);
      const nr = Number(syscall[2]);
      const args = syscall[3].split(",").map((value) => BigInt(value));
      if (syscall[4].startsWith("0x")) {
        const raw = BigInt(syscall[4]);
        if (raw >= 0xffff_ffff_ffff_f001n) {
          const errno = 0x1_0000_0000_0000_0000n - raw;
          const error = `pid=${syscall[1]} nr=${nr} errno=${errno}`;
          syscallErrorCounts.set(error, (syscallErrorCounts.get(error) ?? 0) + 1);
        }
      }
      let shape;
      if (nr === 0) {
        shape = `read pid=${syscall[1]} fd=${args[0]} count=${args[2]} ret=${syscall[4]}`;
      } else if (nr === 202) {
        const timeout = args[3] === 0n ? "none" : "some";
        shape = `futex pid=${syscall[1]} cmd=${Number(args[1] & 0x7fn)} op=${args[1].toString(16)} timeout=${timeout} ret=${syscall[4]}`;
      } else if (nr === 228 || nr === 229) {
        shape = `clock pid=${syscall[1]} nr=${nr} id=${args[0]} ret=${syscall[4]}`;
      } else if (nr === 441) {
        // Keep the raw ABI-level timeout pointer out of the real transcript,
        // but retain enough non-secret call shape to distinguish a genuine
        // zero-timeout poll from an incorrectly woken timed epoll wait.
        shape =
          `epoll_pwait2 pid=${syscall[1]} epfd=${args[0]} maxevents=${args[2]} ` +
          `timeout_ptr=${args[3] === 0n ? "none" : "some"} ret=${syscall[4]}`;
      } else if (nr === 24 || nr === 56 || nr === 435) {
        shape = `thread pid=${syscall[1]} nr=${nr} arg0=${args[0].toString(16)} ret=${syscall[4]}`;
      }
      if (shape) syscallShapeCounts.set(shape, (syscallShapeCounts.get(shape) ?? 0) + 1);
    }
  }
  const top = (counts, limit) =>
    [...counts.entries()]
      .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
      .slice(0, limit)
      .map(([key, count]) => `${key}:${count}`)
      .join(" ");
  console.log(
    `trace_summary bytes=${traceLen} states=${stateSamples} unique_rips=${ripCounts.size} ` +
      `top_rips=${top(ripCounts, 24)}`,
  );
  console.log(`trace_syscalls=${top(syscallCounts, 100)}`);
  console.log(`trace_syscall_shapes=${top(syscallShapeCounts, 40)}`);
  console.log(`trace_syscall_errors=${top(syscallErrorCounts, 100)}`);
  if (process.env.PROBE_TRACE_RAW === "1") {
    console.log(`architectural trace (last 32768 bytes):\n${traceText.slice(-32768)}`);
  }
}
for (const entry of sockets.values()) {
  if (entry.kind === "udp") entry.socket.close();
  else entry.socket.destroy();
}
process.exit(taskMode ? (taskSucceeded ? 0 : 2) : alt ? 0 : 2);
