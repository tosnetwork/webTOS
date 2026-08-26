// Three-engine browser matrix for the webTOS browser host: proves the Linux
// runtime, its terminal output, and its reload persistence work in Chromium,
// Firefox, and WebKit — the exit gate the Node/V8 harness cannot cover.
//
// Phase A drives the real demo page (web/index.html) exactly as a user would:
// BusyBox applets, "Save FS", a browser reload, and a read-back of the
// restored filesystem. Phase B drives web/worker.js directly on a blank page
// to cover the static and dynamically linked hello binaries. Phase C drives
// the interactive terminal — a real shell on a pty, a full-screen editor, a
// window resize, and a real HTTP fetch through the network gateway. Phase D
// reruns the one-shot demo in a storage-less profile to prove the host
// degrades cleanly.
//
// The run starts its own gateway, allowing exactly one destination: its own
// static server. That is what makes both network checks meaningful — one
// destination reachable, everything else refused.
// Finally the run compares per-command instruction counts across engines:
// the same input must retire the same instruction stream on every engine.
//
// Phases A and B need an on-disk profile: WebKit denies the origin-private
// filesystem outright to a browsing context that has no persistent storage.
//
// Setup:  npm install && npx playwright install
// Usage:  node web/test_browsers.mjs [--engines=chromium,firefox,webkit] [--headed]
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, normalize, extname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const ALL_ENGINES = ["chromium", "firefox", "webkit"];

const args = process.argv.slice(2);
const headed = args.includes("--headed");
const engineArg = args.find((a) => a.startsWith("--engines="));
const engines = engineArg ? engineArg.slice("--engines=".length).split(",") : ALL_ENGINES;
for (const name of engines) {
  if (!ALL_ENGINES.includes(name)) {
    console.error(`unknown engine ${name}; expected one of ${ALL_ENGINES.join(", ")}`);
    process.exit(2);
  }
}

let playwright;
try {
  playwright = await import("playwright");
} catch {
  console.error("playwright is not installed. Run:  npm install && npx playwright install");
  process.exit(2);
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".wasm": "application/wasm",
  ".json": "application/json",
};

// A blank same-origin document: phase B needs a page whose only worker is the
// one the test creates, so the demo page's own worker cannot race it on OPFS.
const BLANK = "<!doctype html><meta charset=utf-8><title>webTOS test</title>";
/// Served at /__net_probe: the body a guest must fetch over a real socket.
const NET_PROBE = "net-probe-ok";

async function startServer() {
  const server = createServer(async (req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
    if (path === "/__blank.html") {
      res.writeHead(200, { "content-type": MIME[".html"] });
      res.end(BLANK);
      return;
    }
    if (path === "/__net_probe") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(NET_PROBE);
      return;
    }
    // normalize() collapses ".." before the join, so the served tree is the
    // repository and nothing above it.
    const file = join(REPO, normalize(path).replace(/^(\.\.[/\\])+/, ""));
    try {
      if (!(await stat(file)).isFile()) throw new Error("not a file");
      res.writeHead(200, {
        "content-type": MIME[extname(file)] ?? "application/octet-stream",
        "cache-control": "no-store",
      });
      res.end(await readFile(file));
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, origin: `http://127.0.0.1:${server.address().port}` };
}

/// Starts the relay with a single rule: the harness's own static server. It
/// prints the port it bound, which is how `--port 0` becomes usable here.
async function startGateway(allow) {
  const child = spawn(
    process.execPath,
    [fileURLToPath(new URL("../tools/webtos_gateway.mjs", import.meta.url)), "--port", "0", "--allow", allow],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  const refusals = [];
  let buffered = "";
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("gateway did not start")), 20_000);
    child.stdout.on("data", (chunk) => {
      buffered += chunk;
      for (const line of buffered.split("\n")) {
        if (line.includes("REFUSED")) refusals.push(line.trim());
        const match = /gateway on ws:\/\/127\.0\.0\.1:(\d+)/.exec(line);
        if (match) {
          clearTimeout(timer);
          resolve(Number(match[1]));
        }
      }
    });
    child.stderr.on("data", (chunk) => reject(new Error(`gateway: ${chunk}`)));
    child.on("exit", (code) => reject(new Error(`gateway exited with ${code}`)));
  });
  return { child, port, url: `ws://127.0.0.1:${port}`, refusals };
}

// ---------------------------------------------------------------- page side

// Drives web/worker.js over postMessage. Playwright serializes this into the
// page, so it must close over nothing outside its own argument.
const workerDriver = async (input) => {
  const worker = new Worker(input.workerUrl);
  const pending = { output: "", status: null };
  let resolveReady, resolveDone;
  const ready = new Promise((r) => { resolveReady = r; });
  worker.onmessage = (event) => {
    const msg = event.data;
    if (msg.type === "ready") resolveReady(msg);
    if (msg.type === "output") pending.output += msg.text;
    if (msg.type === "done") { pending.status = msg; resolveDone?.(msg); }
    if (msg.type === "error") {
      const failure = { type: "done", status: -1, error: msg.text, exitCode: -1, icount: 0 };
      pending.status = failure;
      resolveReady(failure);
      resolveDone?.(failure);
    }
  };

  const files = [];
  for (const spec of input.files) {
    const response = await fetch(spec.url);
    if (!response.ok) throw new Error(`${spec.url}: HTTP ${response.status}`);
    files.push({ path: spec.path, bytes: await response.arrayBuffer() });
  }
  const t0 = performance.now();
  worker.postMessage({ type: "boot", files }, files.map((f) => f.bytes));
  const readyMsg = await ready;
  if (readyMsg.status === -1) throw new Error(`boot failed: ${readyMsg.error}`);
  const bootMs = performance.now() - t0;

  const runs = [];
  for (const step of input.steps) {
    pending.output = "";
    pending.status = null;
    const done = new Promise((r) => { resolveDone = r; });
    worker.postMessage({ type: "exec", path: step.path, argv: step.argv, envp: step.envp ?? ["PATH=/bin:/usr/bin", "HOME=/home"] });
    const result = await done;
    runs.push({
      label: step.label,
      output: pending.output,
      status: result.status,
      exitCode: result.exitCode,
      icount: result.icount,
      error: result.error ?? "",
    });
  }
  worker.terminate();
  return { bootMs, restored: readyMsg.restored === true, runs };
};

// --------------------------------------------------------------- terminal

/// The rendered terminal screen, as the user sees it.
const readScreen = (page) =>
  page.evaluate(() => {
    const buffer = window.webtos.term.buffer.active;
    const lines = [];
    for (let i = 0; i < buffer.length; i += 1) {
      lines.push(buffer.getLine(i)?.translateToString(true) ?? "");
    }
    return lines.join("\n");
  });

const terminalSize = (page) =>
  page.evaluate(() => [window.webtos.term.cols, window.webtos.term.rows]);

/// Types a command line and waits for `expect` — a regular expression source
/// — to match a rendered line. The guest parks between individual keystrokes,
/// so screen content, not the run state, is what says a command finished.
/// The pattern must not match the echoed command itself: the line discipline
/// prints what was typed before the guest has run any of it.
async function typeLine(page, line, expect) {
  await page.keyboard.type(line);
  await page.keyboard.press("Enter");
  return waitForScreen(page, expect);
}

/// Waits until a rendered line matches `expect`, then returns the screen.
async function waitForScreen(page, expect) {
  await page.waitForFunction(
    (pattern) => {
      const regex = new RegExp(pattern);
      const buffer = window.webtos.term.buffer.active;
      for (let i = 0; i < buffer.length; i += 1) {
        if (regex.test(buffer.getLine(i)?.translateToString(true) ?? "")) return true;
      }
      return false;
    },
    expect,
    { timeout: EXEC_TIMEOUT },
  );
  return readScreen(page);
}

/// Where the editor's status line sits, and how tall the terminal is. A
/// full-screen program paints its status line on the last row, so the pair
/// says whether the guest is painting at the size the window actually has.
/// Counting `~` filler instead would depend on the engine's cell size: a
/// short enough window has no filler rows at all.
const statusRow = (page) =>
  page.evaluate(() => {
    const buffer = window.webtos.term.buffer.active;
    let row = -1;
    for (let i = 0; i < buffer.length; i += 1) {
      if ((buffer.getLine(i)?.translateToString(true) ?? "").includes("/root/notes.txt")) row = i;
    }
    return { row, rows: window.webtos.term.rows };
  });

async function runTerminalPhase(page, origin, name, record, gateway) {
  await page.goto(`${origin}/web/terminal.html?gateway=${encodeURIComponent(gateway.url)}`);
  const vendored = await page.evaluate(() => typeof window.Terminal === "function");
  if (!vendored) {
    record("terminal: emulator vendored", false, "run tools/fetch_xterm.sh");
    return;
  }
  await page.waitForFunction(() => window.webtos?.state === "waiting", undefined, {
    timeout: EXEC_TIMEOUT,
  });
  const [cols, rows] = await terminalSize(page);
  record("terminal: interactive shell reaches a prompt", true, `${cols}x${rows}`);

  const echoed = await typeLine(page, `echo hello-from-${name}`, `hello-from-${name}`);
  record(
    "terminal: the shell echoes and runs a command",
    echoed.includes(`echo hello-from-${name}`) && echoed.includes(`hello-from-${name}`),
    "typed line echoed by the line discipline, output printed by the guest",
  );

  const piped = await typeLine(page, "ls /bin | head -3", "^busybox");
  record(
    "terminal: pipeline across processes",
    piped.includes("busybox") && piped.includes("cat"),
    "fork + execve + pipe, from a shell on a pty",
  );

  // A full-screen program is launched in a deliberately short window and the
  // window is then grown. Growing is the honest test: xterm adds blank rows
  // at the bottom, and only a guest that was told the window changed fills
  // them in. Shrinking proves nothing — rows just disappear either way.
  const viewport = page.viewportSize();
  const cellHeight = await page.evaluate(
    () => document.getElementById("screen").clientHeight / window.webtos.term.rows,
  );
  const shortHeight = Math.round(viewport.height - Math.max(6, rows * 0.4) * cellHeight);
  await page.setViewportSize({ width: viewport.width, height: shortHeight });
  await page
    .waitForFunction((before) => window.webtos.term.rows < before, rows, { timeout: 60_000 })
    .catch(() => {});

  await typeLine(page, "vi /root/notes.txt", "This file lives in the guest");
  const bottomIsStatus = () =>
    page
      .waitForFunction(
        () => {
          const buffer = window.webtos.term.buffer.active;
          const last = buffer.getLine(window.webtos.term.rows - 1);
          return (last?.translateToString(true) ?? "").includes("/root/notes.txt");
        },
        undefined,
        { timeout: 60_000 },
      )
      .catch(() => {});

  await bottomIsStatus();
  const painted = await statusRow(page);
  record(
    "terminal: full-screen editor paints",
    painted.row === painted.rows - 1 && painted.rows > 2,
    `status line on row ${painted.row + 1} of ${painted.rows}`,
  );

  // Nothing is typed. The window grows; the guest must notice and repaint.
  await page.setViewportSize(viewport);
  await page
    .waitForFunction((before) => window.webtos.term.rows > before, painted.rows, {
      timeout: 60_000,
    })
    .catch(() => {});
  await bottomIsStatus();
  const repainted = await statusRow(page);
  record(
    "terminal: SIGWINCH repaints without a keystroke",
    repainted.rows > painted.rows && repainted.row === repainted.rows - 1,
    `status line followed the window: row ${painted.row + 1}/${painted.rows} -> ${repainted.row + 1}/${repainted.rows}`,
  );

  await page.keyboard.type(":q!");
  await page.keyboard.press("Enter");
  // Leaving the alternate screen is how the editor says it is gone; typing at
  // the shell before that races the editor for the same keystrokes.
  const left = await page
    .waitForFunction(() => window.webtos.term.buffer.active.type === "normal", undefined, {
      timeout: 60_000,
    })
    .then(() => true)
    .catch(() => false);
  const back = left ? await typeLine(page, "echo back-in-the-shell", "^back-in-the-shell") : "";
  record(
    "terminal: the editor quits back to the shell",
    back.includes("back-in-the-shell"),
    left ? "prompt restored and commands run again" : "editor never left the alternate screen",
  );

  // The guest opens a real TCP connection: BusyBox wget, its own HTTP, over
  // a socket the relay holds. Only the harness's own server is allowed.
  // The status goes on a line of its own, because wget's body has no
  // trailing newline. Each command gets its own marker so the wait cannot
  // match a status still on screen from an earlier one, and the pattern is
  // anchored so it cannot match the echoed command, which carries `$s`.
  const port = new URL(origin).port;
  const fetched = await typeLine(
    page,
    `wget -q -O - ${origin}/__net_probe; s=$?; echo; echo fetched$s`,
    "^fetched[0-9]+$",
  );
  record(
    "network: the guest fetches over a relayed socket",
    fetched.includes("net-probe-ok") && /^fetched0$/m.test(fetched),
    `wget reached 127.0.0.1:${port} through the gateway`,
  );

  // Everything else is refused. The gateway's own port is a live listener
  // the policy does not name, so this fails on policy, not on reachability.
  const refused = await typeLine(
    page,
    `wget -T 3 -q -O - http://127.0.0.1:${gateway.port}/__net_probe; s=$?; echo; echo refused$s`,
    "^refused[0-9]+$",
  );
  // Only what this command produced: the successful fetch above is still on
  // screen, and its body would otherwise look like a leak.
  const tail = refused.slice(refused.lastIndexOf("wget -T 3"));
  record(
    "network: a destination outside the allowlist is refused",
    /^refused[1-9][0-9]*$/m.test(tail) && !tail.includes("net-probe-ok"),
    `gateway refused 127.0.0.1:${gateway.port}`,
  );
}

// ------------------------------------------------------------- browser side

const EXEC_TIMEOUT = 180_000;

// "exit 0 · 73,280 instructions total" -> 73280
const icountOf = (status) => {
  const match = /·\s*([\d,]+)\s*instructions/.exec(status);
  return match ? Number(match[1].replace(/,/g, "")) : null;
};

async function runEngine(name, origin, gateway) {
  const checks = [];
  const fingerprint = {};
  const record = (label, ok, detail = "") => {
    checks.push({ label, ok, detail });
    console.log(`[${name}] ${ok ? "ok" : "FAILED"}: ${label}${detail ? ` -> ${detail}` : ""}`);
  };

  const pageErrors = [];
  const watch = (page) => {
    page.on("pageerror", (e) => pageErrors.push(String(e)));
    page.on("console", (m) => {
      if (m.type() === "error") pageErrors.push(`console: ${m.text()}`);
    });
    return page;
  };

  const profile = await mkdtemp(join(tmpdir(), `webtos-${name}-`));
  const context = await playwright[name].launchPersistentContext(profile, { headless: !headed });
  // Every navigation here boots a machine: fetching the module, compiling the
  // SLEIGH specification, and restoring a filesystem. Firefox takes ten
  // seconds over that, so the default 30 s navigation timeout is too tight.
  context.setDefaultTimeout(EXEC_TIMEOUT);
  context.setDefaultNavigationTimeout(EXEC_TIMEOUT);
  const page = watch(context.pages()[0] ?? (await context.newPage()));

  try {
    // ---- Phase A: the demo page, driven the way a user drives it.
    await page.goto(`${origin}/web/index.html`);
    await page.waitForSelector("#run:not([disabled])", { timeout: EXEC_TIMEOUT });
    const bootStatus = await page.textContent("#status");
    record("demo page boots", true, bootStatus.trim());

    const runCommand = async (line) => {
      const before = (await page.textContent("#terminal")).length;
      await page.fill("#cmd", line);
      await page.click("#run");
      await page.waitForSelector("#run:not([disabled])", { timeout: EXEC_TIMEOUT });
      const status = (await page.textContent("#status")).trim();
      const terminal = await page.textContent("#terminal");
      return { status, output: terminal.slice(before) };
    };

    const echo = await runCommand(`echo hello-from-${name}`);
    record(
      "busybox echo",
      echo.output.includes(`hello-from-${name}`) && echo.status.startsWith("exit 0"),
      echo.status,
    );

    const ls = await runCommand("ls /");
    record("busybox ls /", ls.output.includes("etc") && ls.status.startsWith("exit 0"), ls.status);
    fingerprint["busybox ls /"] = icountOf(ls.status);

    // /bin/busybox is the only image the demo seeds, so the pipeline's right
    // half is spawned through it explicitly rather than through PATH.
    const pipeline = await runCommand("sh -c 'echo from-pipe | /bin/busybox cat'");
    record(
      "sh pipeline (fork/pipe/execve)",
      pipeline.output.includes("from-pipe") && pipeline.status.startsWith("exit 0"),
      pipeline.status,
    );
    fingerprint["sh pipeline"] = icountOf(pipeline.status);

    const write = await runCommand("sh -c 'echo survived-the-reload > /home/state.txt'");
    record("write state before reload", write.status.startsWith("exit 0"), write.status);

    // This page never asks for a network, so the guest must not have one —
    // even though the server it names is listening and the gateway allows it.
    const offline = await runCommand(`wget -T 2 -q -O - ${origin}/__net_probe`);
    record(
      "no network unless the host grants one",
      !offline.output.includes("net-probe-ok") && !offline.status.startsWith("exit 0"),
      offline.status,
    );

    // ---- Phase A2: persist to OPFS, reload the tab, read the state back.
    await page.click("#save");
    await page.waitForFunction(
      () => {
        const text = document.getElementById("status").textContent;
        return text.includes("filesystem saved") || text.startsWith("error:");
      },
      undefined,
      { timeout: EXEC_TIMEOUT },
    );
    const savedStatus = (await page.textContent("#status")).trim();
    record("persist filesystem to OPFS", savedStatus.includes("filesystem saved"), savedStatus);

    await page.reload();
    await page.waitForSelector("#run:not([disabled])", { timeout: EXEC_TIMEOUT });
    const restoredStatus = (await page.textContent("#status")).trim();
    record(
      "reload restores the snapshot",
      restoredStatus.includes("previous session restored"),
      restoredStatus,
    );

    const readBack = await runCommand("cat /home/state.txt");
    record(
      "state survives the browser reload",
      readBack.output.includes("survived-the-reload"),
      readBack.status,
    );

    await page.click("#forget");
    await page.waitForFunction(
      () => document.getElementById("status").textContent.includes("deleted"),
      undefined,
      { timeout: EXEC_TIMEOUT },
    ).catch(() => {});

    // ---- Phase B: the worker protocol directly, on a page of its own.
    await page.goto(`${origin}/__blank.html`);
    const direct = await page.evaluate(workerDriver, {
      workerUrl: `${origin}/web/worker.js`,
      files: [
        { path: "/bin/hello", url: `${origin}/web/hello_linux.elf` },
        { path: "/bin/hello_dynamic", url: `${origin}/test_data/hello_dynamic.elf` },
        { path: "/lib/ld-musl-x86_64.so.1", url: `${origin}/test_data/alpine-minirootfs/lib/ld-musl-x86_64.so.1` },
      ],
      steps: [
        { label: "static hello", path: "/bin/hello", argv: ["hello"] },
        { label: "dynamic hello (musl loader)", path: "/bin/hello_dynamic", argv: ["hello_dynamic"] },
      ],
    });
    record("worker boots the machine", true, `${direct.bootMs.toFixed(0)} ms`);
    for (const run of direct.runs) {
      const ok = run.status === 1 && run.exitCode === 0 && /ello/.test(run.output);
      fingerprint[run.label] = run.icount;
      record(run.label, ok, ok ? `${run.icount.toLocaleString()} instructions` : `status=${run.status} exit=${run.exitCode} ${run.error} ${JSON.stringify(run.output.slice(0, 80))}`);
    }

    // ---- Phase C: the interactive terminal, including its network.
    await runTerminalPhase(page, origin, name, record, gateway);

  } catch (e) {
    record("engine run completed", false, String(e));
  } finally {
    await context.close();
    await rm(profile, { recursive: true, force: true });
  }

  // ---- Phase D: a profile with no persistent storage (a private window).
  // The runtime must still boot and run; only the snapshot buttons stand down.
  const browser = await playwright[name].launch({ headless: !headed });
  try {
    const ephemeralContext = await browser.newContext();
    ephemeralContext.setDefaultTimeout(EXEC_TIMEOUT);
    ephemeralContext.setDefaultNavigationTimeout(EXEC_TIMEOUT);
    const ephemeral = watch(await ephemeralContext.newPage());
    await ephemeral.goto(`${origin}/web/index.html`);
    await ephemeral.waitForSelector("#run:not([disabled])", { timeout: EXEC_TIMEOUT });
    const status = (await ephemeral.textContent("#status")).trim();
    const saveDisabled = await ephemeral.isDisabled("#save");
    const declared = status.includes("browser storage unavailable");
    await ephemeral.fill("#cmd", "echo storage-less");
    await ephemeral.click("#run");
    await ephemeral.waitForSelector("#run:not([disabled])", { timeout: EXEC_TIMEOUT });
    const ran = (await ephemeral.textContent("#terminal")).includes("storage-less");
    record(
      "storage-less profile: runtime still runs",
      ran,
      `${status}${saveDisabled ? " [save disabled]" : ""}`,
    );
    record(
      "storage-less profile: snapshot capability reported honestly",
      saveDisabled === declared,
      declared ? "storage unavailable and Save FS disabled" : "storage available and Save FS enabled",
    );
  } catch (e) {
    record("storage-less profile run completed", false, String(e));
  } finally {
    await browser.close();
  }

  record("no uncaught page errors", pageErrors.length === 0, pageErrors.join(" | "));
  return { checks, fingerprint };
}

// -------------------------------------------------------------------- main

const { server, origin } = await startServer();
const gateway = await startGateway(`127.0.0.1:${new URL(origin).port}`);
const summary = [];
const fingerprints = {};
try {
  for (const name of engines) {
    console.log(`\n=== ${name} ===`);
    const { checks, fingerprint } = await runEngine(name, origin, gateway);
    const failed = checks.filter((c) => !c.ok);
    summary.push({ name, total: checks.length, failed: failed.length });
    fingerprints[name] = fingerprint;
  }
} finally {
  gateway.child.kill();
  server.close();
}

if (gateway.refusals.length > 0) {
  console.log(`\n=== gateway refusals (${gateway.refusals.length}) ===`);
  for (const line of gateway.refusals.slice(0, 6)) console.log(line);
}

// Determinism: identical input must retire an identical instruction stream on
// every engine. A divergence here is an engine bug, not a rendering quirk.
let divergent = 0;
const ran = summary.map((r) => r.name);
if (ran.length > 1) {
  console.log("\n=== instruction counts ===");
  const commands = [...new Set(ran.flatMap((name) => Object.keys(fingerprints[name])))];
  for (const command of commands) {
    const counts = ran.map((name) => fingerprints[name][command]);
    const agree = counts.every((c) => c !== null && c !== undefined && c === counts[0]);
    if (!agree) divergent += 1;
    const detail = agree
      ? `${counts[0].toLocaleString()} on every engine`
      : ran.map((name, i) => `${name}=${counts[i]}`).join(" ");
    console.log(`${agree ? "ok" : "DIVERGED"}: ${command.padEnd(28)} ${detail}`);
  }
}

console.log("\n=== matrix ===");
for (const row of summary) {
  console.log(`${row.name.padEnd(9)} ${row.failed === 0 ? "PASS" : "FAIL"}  ${row.total - row.failed}/${row.total} checks`);
}
const broken = summary.filter((r) => r.failed > 0);
if (broken.length > 0 || divergent > 0) {
  const reasons = [
    ...broken.map((r) => r.name),
    ...(divergent > 0 ? [`${divergent} divergent instruction count(s)`] : []),
  ];
  console.error(`\n[browsers] FAIL (${reasons.join(", ")})`);
  process.exit(1);
}
console.log("\n[browsers] PASS");
