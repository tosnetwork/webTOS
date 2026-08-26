// Throughput and memory measurements for the browser host, per engine.
//
// These are numbers, not gates: they print what the interpreter costs and
// what a tab will give it, so decisions about the runtime rest on measurement
// rather than impression. The workloads match
// `crates/linux-compat/tests/bench.rs` exactly — same guest, same inputs, same
// instruction counts — so the browser figures can be read against a native
// reference measured the same way.
//
// Setup:  npm install && npx playwright install && bash web/build.sh
// Usage:  node web/bench.mjs [--engines=chromium,firefox,webkit] [--headed]
import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, normalize, extname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = fileURLToPath(new URL("..", import.meta.url));
const ALL_ENGINES = ["chromium", "firefox", "webkit"];

const args = process.argv.slice(2);
const headed = args.includes("--headed");
const engineArg = args.find((a) => a.startsWith("--engines="));
const engines = engineArg ? engineArg.slice("--engines=".length).split(",") : ALL_ENGINES;

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
  ".wasm": "application/wasm",
};

async function startServer() {
  const server = createServer(async (req, res) => {
    const path = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
    if (path === "/__blank.html") {
      res.writeHead(200, { "content-type": MIME[".html"] });
      res.end("<!doctype html><meta charset=utf-8><title>webTOS bench</title>");
      return;
    }
    const file = join(REPO, normalize(path).replace(/^(\.\.[/\\])+/, ""));
    try {
      const info = await stat(file);
      if (!info.isFile()) throw new Error("not a file");
      res.writeHead(200, {
        "content-type": MIME[extname(file)] ?? "application/octet-stream",
        "content-length": info.size,
      });
      createReadStream(file).pipe(res);
    } catch {
      res.writeHead(404).end("not found");
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, origin: `http://127.0.0.1:${server.address().port}` };
}

// ---------------------------------------------------------------- page side

// Runs entirely inside the page: Playwright serializes it, so it closes over
// nothing but its argument.
const benchmark = async (input) => {
  const { wasmUrl, busyboxUrl, controlUrl, sizesMiB } = input;
  const FUEL = 50_000_000;

  const busybox = new Uint8Array(await (await fetch(busyboxUrl)).arrayBuffer());

  // Deterministic bytes; a compressible pattern would make the measurement
  // depend on the data rather than the instruction stream.
  const payload = (length) => {
    const out = new Uint8Array(length);
    let lo = 0x4f6cdd1d >>> 0;
    let hi = 0x2545f491 >>> 0;
    for (let i = 0; i < length; i += 1) {
      // xorshift64 over a 32-bit pair, matching the native fixture's shape.
      let t = lo ^ ((lo << 13) | (hi >>> 19));
      hi = hi ^ ((hi << 13) | (lo >>> 19));
      lo = t >>> 0;
      t = lo ^ (lo >>> 7);
      hi = hi ^ ((hi >>> 7) | (lo << 25));
      lo = t >>> 0;
      out[i] = (hi >>> 16) & 0xff;
    }
    return out;
  };

  const instantiateStart = performance.now();
  const { instance } = await WebAssembly.instantiateStreaming(fetch(wasmUrl), {});
  const e = instance.exports;
  const instantiateMs = performance.now() - instantiateStart;

  const mem = () => new Uint8Array(e.memory.buffer);
  const put = (value) => {
    const data = typeof value === "string" ? new TextEncoder().encode(value) : value;
    const ptr = e.wtw_alloc(data.length);
    mem().set(data, ptr);
    return [ptr, data.length];
  };
  const icount = () => e.wtw_icount_hi() * 2 ** 32 + e.wtw_icount_lo();
  const heapMiB = () => e.memory.buffer.byteLength / (1 << 20);

  const runs = [];
  let buildMs = 0;
  for (const mib of sizesMiB) {
    // A fresh machine per size, so each run pays the same fixed costs and the
    // difference between them cancels those out.
    const buildStart = performance.now();
    if (e.wtw_init() !== 0) throw new Error("machine build failed");
    buildMs = performance.now() - buildStart;

    e.wtw_add_file(...put("/bin/busybox"), ...put(busybox));
    const data = payload(mib * 1024 * 1024);
    e.wtw_file_create(...put("/root/data.bin"), data.length, 0o644);
    for (let at = 0; at < data.length; at += 4 << 20) {
      e.wtw_file_append(...put("/root/data.bin"), ...put(data.subarray(at, at + (4 << 20))));
    }

    for (const arg of ["busybox", "md5sum", "/root/data.bin"]) e.wtw_arg(...put(arg));
    // Matches the native fixture's environment exactly: envp lands on the
    // guest stack, so a different one is a different instruction count.
    e.wtw_env(...put("PATH=/bin"));
    e.wtw_env(...put("HOME=/root"));
    if (e.wtw_load(...put("/bin/busybox")) !== 0) throw new Error("ELF load failed");

    const start = performance.now();
    let status;
    let output = "";
    do {
      status = e.wtw_run(FUEL);
      const text = new TextDecoder().decode(
        mem().slice(e.wtw_output_ptr(), e.wtw_output_ptr() + e.wtw_output_len()),
      );
      output += text;
    } while (status === 0);
    const seconds = (performance.now() - start) / 1000;
    if (status !== 1 || e.wtw_exit_code() !== 0) throw new Error(`md5sum failed: ${output}`);
    runs.push({
      label: `md5sum ${mib} MiB`,
      mib,
      instructions: icount(),
      seconds,
      heapMiB: heapMiB(),
      guestUsedMiB: e.wtw_guest_memory_used_mb(),
      guestCapMiB: e.wtw_guest_memory_cap_mb(),
    });
  }

  // What this tab is willing to give the module. wasm32 caps a linear memory
  // at 4 GiB by construction; engines stop earlier, and that ceiling is what
  // decides which workloads fit.
  // The control: a few hundred bytes with one hot loop, measured before the
  // memory probe disturbs anything. It separates "this engine's wasm compiler
  // is slow" from "this engine declined our 60 KB interpreter function" — the
  // two look identical in the numbers above.
  let control = null;
  if (controlUrl) {
    try {
      const { instance: tiny } = await WebAssembly.instantiateStreaming(fetch(controlUrl), {});
      tiny.exports.mix(1_000_000); // let the engine tier up before timing
      const rounds = 200_000_000;
      const controlStart = performance.now();
      const checksum = tiny.exports.mix(rounds);
      const controlSeconds = (performance.now() - controlStart) / 1000;
      control = { rounds, seconds: controlSeconds, checksum };
    } catch {
      control = null; // Not staged; the rest of the run still stands.
    }
  }

  const beforeGrowMiB = heapMiB();
  const STEP_PAGES = 4096; // 256 MiB
  for (;;) {
    try {
      if (e.memory.grow(STEP_PAGES) < 0) break;
    } catch {
      break;
    }
    if (e.memory.buffer.byteLength >= 4 * 1024 * 1024 * 1024) break;
  }
  const ceilingMiB = heapMiB();

  return { instantiateMs, buildMs, runs, control, beforeGrowMiB, ceilingMiB };
};

// -------------------------------------------------------------------- main

const { server, origin } = await startServer();
const wasmUrl = `${origin}/web/webtos_web.wasm`;
const busyboxUrl = `${origin}/web/busybox-musl`;
const controlUrl = `${origin}/web/bench_control.wasm`;
const rows = [];

try {
  for (const name of engines) {
    const profile = await mkdtemp(join(tmpdir(), `webtos-bench-${name}-`));
    const context = await playwright[name].launchPersistentContext(profile, {
      headless: !headed,
    });
    context.setDefaultTimeout(900_000);
    context.setDefaultNavigationTimeout(900_000);
    const page = context.pages()[0] ?? (await context.newPage());
    try {
      await page.goto(`${origin}/__blank.html`);
      const result = await page.evaluate(benchmark, {
        wasmUrl,
        busyboxUrl,
        controlUrl,
        sizesMiB: [1, 4],
      });
      rows.push({ name, ...result });
      console.log(`\n=== ${name} ===`);
      console.log(
        `[bench] ${"module instantiate".padEnd(28)} ${result.instantiateMs.toFixed(0).padStart(7)} ms`,
      );
      console.log(
        `[bench] ${"machine build".padEnd(28)} ${result.buildMs.toFixed(0).padStart(7)} ms (SLEIGH specification compiled)`,
      );
      for (const run of result.runs) {
        console.log(
          `[bench] ${run.label.padEnd(28)} ${String(run.instructions).padStart(13)} instructions  ` +
            `${run.seconds.toFixed(2).padStart(7)} s  ` +
            `${(run.instructions / run.seconds / 1e6).toFixed(1).padStart(8)} M inst/s  ` +
            `heap ${run.heapMiB.toFixed(0)} MiB, guest ${run.guestUsedMiB}/${run.guestCapMiB} MiB`,
        );
      }
      const [small, large] = result.runs;
      const instructions = large.instructions - small.instructions;
      const seconds = large.seconds - small.seconds;
      console.log(
        `[bench] ${"md5sum marginal".padEnd(28)} ${String(instructions).padStart(13)} instructions  ` +
          `${seconds.toFixed(2).padStart(7)} s  ` +
          `${(instructions / seconds / 1e6).toFixed(1).padStart(8)} M inst/s (fixed cost removed)`,
      );
      if (result.control) {
        const { rounds, seconds, checksum } = result.control;
        console.log(
          `[bench] ${"control module".padEnd(28)} ${String(rounds).padStart(13)} iterations  ` +
            `${seconds.toFixed(2).padStart(7)} s  ` +
            `${(rounds / seconds / 1e6).toFixed(1).padStart(8)} M iter/s  (checksum ${checksum})`,
        );
      } else {
        console.log(`[bench] ${"control module".padEnd(28)} not staged (run web/build.sh)`);
      }
      console.log(
        `[bench] ${"linear memory ceiling".padEnd(28)} ${result.ceilingMiB.toFixed(0).padStart(7)} MiB ` +
          `(grown from ${result.beforeGrowMiB.toFixed(0)} MiB)`,
      );
    } finally {
      await context.close();
      await rm(profile, { recursive: true, force: true });
    }
  }
} finally {
  server.close();
}

if (rows.length > 1) {
  console.log("\n=== summary ===");
  console.log("engine     build      md5sum 4 MiB   marginal        control          heap ceiling");
  for (const row of rows) {
    const [small, large] = row.runs;
    const marginal =
      (large.instructions - small.instructions) / (large.seconds - small.seconds) / 1e6;
    const control = row.control
      ? `${(row.control.rounds / row.control.seconds / 1e6).toFixed(0)} M iter/s`
      : "n/a";
    console.log(
      `${row.name.padEnd(10)} ${`${row.buildMs.toFixed(0)} ms`.padEnd(10)} ` +
        `${`${large.seconds.toFixed(2)} s`.padEnd(14)} ` +
        `${`${marginal.toFixed(1)} M inst/s`.padEnd(15)} ` +
        `${control.padEnd(16)} ` +
        `${row.ceilingMiB.toFixed(0)} MiB`,
    );
  }
  console.log(
    "\nA slow engine in both columns is a slow wasm compiler; slow only in the\n" +
      "middle would point at the interpreter's own shape.",
  );
}
