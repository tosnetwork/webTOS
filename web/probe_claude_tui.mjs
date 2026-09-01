// Probe: does the Claude Code TUI paint under the engine when the JIT is on?
// Drives the wasm module directly (Node's V8 compiles the engine ~30x faster
// than the native interpreter), delivers claude + loader + glibc by manifest,
// installs a pty, and pumps until the TUI paints or a budget runs out. Claude
// renders with Ink on the MAIN screen (no alternate-screen switch), so the
// paint detector is its first interactive text, not \x1b[?1049h.
// Usage: node web/probe_claude_tui.mjs [minutes]
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createConnection } from "node:net";
import { createSocket } from "node:dgram";
import { resolve4 } from "node:dns/promises";
import { makeJitHost } from "./jit_host.mjs";

const wasmPath = new URL("./webtos_web.wasm", import.meta.url).pathname;
const realTask = process.env.PROBE_REAL_TASK === "1";
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

const claude = await readFile(new URL("./claude", import.meta.url));
const libDir = new URL("./claude-libs/", import.meta.url);
const mockClaude = mockTask
  ? await readFile(new URL("./mock_claude", import.meta.url))
  : null;
const lib = async (name) => ({
  path: name === "ld-linux-x86-64.so.2" ? "/lib64/ld-linux-x86-64.so.2" : `/lib/x86_64-linux-gnu/${name}`,
  bytes: await readFile(new URL(name, libDir)),
});
const files = [
  { path: "/bin/claude", bytes: mockTask ? mockClaude : claude },
  await lib("ld-linux-x86-64.so.2"),
  await lib("libc.so.6"),
  await lib("libm.so.6"),
  await lib("libdl.so.2"),
  await lib("libpthread.so.0"),
  await lib("librt.so.1"),
];
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
const useJit = process.env.PROBE_JIT === "1" || (!realTask && process.env.PROBE_JIT !== "0");
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
const executable = taskMode ? "/bin/busybox" : "/bin/claude";
if (taskMode) {
  e.wtw_arg(...put("sh"));
  e.wtw_arg(...put("-i"));
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
const apiAddresses = new Set(realTask ? await resolve4("api.anthropic.com") : []);
const sockets = new Map();
let netEvents = 0;
let netWake = null;
const noteNetEvent = () => {
  netEvents += 1;
  if (netWake) {
    const wake = netWake;
    netWake = null;
    wake();
  }
};
const deliverNetError = (handle, errno) => {
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
  (ip === "1.1.1.1" && port === 53) || (apiAddresses.has(ip) && port === 443);
const deliverNetData = (handle, bytes) => {
  e.wtw_net_data(handle, ...put(bytes));
  noteNetEvent();
};
const openTcp = (handle, ip, port) => {
  if (!permitted(ip, port)) {
    console.error(`[network] refused tcp ${ip}:${port}`);
    deliverNetError(handle, ENETUNREACH);
    return;
  }
  const socket = createConnection({ host: ip, port });
  sockets.set(handle, { kind: "tcp", socket });
  socket.on("connect", () => {
    e.wtw_net_connected(handle, 0, 0);
    noteNetEvent();
  });
  socket.on("data", (bytes) => deliverNetData(handle, bytes));
  socket.on("end", () => {
    e.wtw_net_closed(handle);
    noteNetEvent();
  });
  socket.on("error", (error) => deliverNetError(handle, nodeErrno(error)));
};
const openUdp = (handle) => {
  const socket = createSocket("udp4");
  sockets.set(handle, { kind: "udp", socket });
  socket.on("message", (bytes, remote) => {
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
      openTcp(handle, ip, port);
    } else if (op === 2) {
      sockets.get(handle)?.socket.write(payload());
    } else if (op === 3) {
      sockets.get(handle)?.socket.end();
    } else if (op === 4) {
      openUdp(handle);
    } else if (op === 5) {
      const { ip, port } = destination();
      const bytes = payload();
      if (!permitted(ip, port)) {
        console.error(`[network] refused udp ${ip}:${port}`);
        deliverNetError(handle, ENETUNREACH);
      } else {
        sockets.get(handle)?.socket.send(bytes, port, ip);
      }
    } else if (op === 6) {
      const entry = sockets.get(handle);
      if (entry?.kind === "udp") entry.socket.close();
      else entry?.socket.destroy();
      sockets.delete(handle);
    } else {
      throw new Error(`unknown network opcode ${op}`);
    }
  }
};
const pumpNetwork = async () => {
  const before = netEvents;
  performNetwork(takeNetworkCommands());
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
if (traceEvery > 0 && traceAfterIcount === null && e.wtw_trace_start(traceEvery) !== 0) {
  throw new Error(`trace start: ${err()}`);
}
if (traceEvery > 0 && traceAfterIcount === null && traceEventBudget > 0 && e.wtw_set_event_log_budget(traceEventBudget) !== 0) {
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
let taskSuccessBaseline = 0;
let exitMarkerBaseline = 0;
let taskTraceStartIcount = null;
let taskTraceExpired = false;
let tracing = traceEvery > 0 && traceAfterIcount === null;
let deferredTraceStarted = false;
let trustSelectionSent = false;
let loggedRenderedBytes = 0;
let taskInputEchoed = false;
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
const claudeExited = () => /(?:^|\r?\n)WEBTOS_CLAUDE_EXIT=\d+/.test(rendered);
const trustPromptVisible = () => /Quick\s+safety\s+check|trust\s+this\s+folder/.test(terminalText());
while (Date.now() < deadline) {
  if (
    traceEvery > 0 &&
    !tracing &&
    traceAfterIcount !== null &&
    currentIcount() >= traceAfterIcount
  ) {
    if (e.wtw_trace_start(traceEvery) !== 0) throw new Error(`deferred trace start: ${err()}`);
    if (traceEventBudget > 0 && e.wtw_set_event_log_budget(traceEventBudget) !== 0) {
      throw new Error(`deferred trace budget: ${err()}`);
    }
    tracing = true;
    deferredTraceStarted = true;
    console.error(
      `[trace] deferred trace started at icount=${currentIcount().toLocaleString()} sample_every=${traceEvery} budget=${traceEventBudget}`,
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
  // This is only a boolean confirmation that the fixed, locally generated
  // acceptance instruction crossed the terminal boundary.  Never print the
  // terminal transcript for a real session: it can contain model output or
  // private task data.
  if (taskPhase === "task" && !taskInputEchoed && terminalText().includes("Read /work/input.txt")) {
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
    // A rendered frame is not an input boundary.  The real client continues
    // bootstrapping for a short period after drawing its accessibility prompt;
    // submitting then can be consumed by an internal terminal mode change
    // rather than by Claude's composer.  Only inject a task once the guest
    // has actually blocked on the pty read that asks the host for input.
    if (taskPhase === "claude-start" && terminalInputPending() && painted()) {
      input(
        "Read /work/input.txt, replace M9_PENDING with M9_CLAUDE_COMPLETED using the Edit tool, " +
          "then reply with exactly WEBTOS_TASK_DONE.\r",
      );
      taskNetworkBaseline = networkWaits;
      taskSuccessBaseline = occurrences("WEBTOS_TASK_DONE");
      taskPhase = "task";
      if (taskTrace) {
        // A coarse architectural sample plus a bounded syscall stream makes
        // the busy path diagnosable without retaining a multi-gigabyte trace.
        if (e.wtw_trace_start(50_000_000) !== 0) throw new Error(`task trace: ${err()}`);
        if (e.wtw_set_event_log_budget(4096) !== 0) throw new Error(`task trace budget: ${err()}`);
        tracing = true;
        taskTraceStartIcount = currentIcount();
      }
      continue;
    }
    if (taskPhase === "trust" && terminalInputPending() && trustSelectionSent) {
      input(
        "Read /work/input.txt, replace M9_PENDING with M9_CLAUDE_COMPLETED using the Edit tool, " +
          "then reply with exactly WEBTOS_TASK_DONE.\r",
      );
      taskNetworkBaseline = networkWaits;
      taskSuccessBaseline = occurrences("WEBTOS_TASK_DONE");
      taskPhase = "task";
      if (taskTrace) {
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
      (mockTask || networkWaits > taskNetworkBaseline) &&
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
}
drain();

const icount = (e.wtw_icount_hi() >>> 0) * 2 ** 32 + (e.wtw_icount_lo() >>> 0);
const alt = painted();
console.log(
  `jit=${useJit} jit_after=${jitAfter} pty=${usePty} realtime_clock=${realtimeClock} ` +
    `guest_memory_mb=${guestMemoryMb} ` +
    `clock_warp_ms=${realtimeWarpAppliedMs} status=${status} slices=${slices} ` +
    `page_ins=${pageIns} icount=${icount.toLocaleString()} ` +
    `jit_blocks=${Number(e.wtw_jit_block_dispatch_count()).toLocaleString()} ` +
    `jit_regions=${Number(e.wtw_jit_region_dispatch_count()).toLocaleString()} ` +
    `jit_code_bytes=${Number(e.wtw_jit_code_bytes()).toLocaleString()} ` +
    `jit_evictions=${Number(e.wtw_jit_evictions()).toLocaleString()}`,
);
if (status !== 0 && status !== 1 && status !== 7) console.log(`engine error: ${err()}`);
console.log(
  `painted=${alt} real_task=${realTask} mock_task=${mockTask} task_phase=${taskPhase} task_succeeded=${taskSucceeded} task_trace_expired=${taskTraceExpired} ` +
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
