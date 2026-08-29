// Node harness for the webtos-web wasm module: proves the Linux runtime
// works end-to-end outside a browser renderer. Runs a static hello ELF and,
// when the BusyBox fixture is present (tools/fetch_busybox.sh), a sequence
// of BusyBox applets over the persistent in-memory filesystem.
// Usage: node web/test_node.mjs [path/to/module.wasm]
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { makeJitHost } from "./jit_host.mjs";

// Instantiate the engine, providing the JIT host imports and binding the
// exports back so a compiled block can call into wtw_jit_*.
async function instantiateEngine(source) {
  const jit = makeJitHost();
  const r = await WebAssembly.instantiate(source, { env: jit.imports });
  jit.bind(r.instance.exports);
  return r;
}

const wasmPath = process.argv[2] ?? new URL("./webtos_web.wasm", import.meta.url).pathname;

const { instance } = await instantiateEngine(await readFile(wasmPath));
const e = instance.exports;
const mem = () => new Uint8Array(e.memory.buffer);
const text = (ptr, len) => new TextDecoder().decode(mem().slice(ptr, ptr + len));
const err = () => text(e.wtw_error_ptr(), e.wtw_error_len());

const put = (bytes) => {
  const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
  const ptr = e.wtw_alloc(data.length);
  mem().set(data, ptr);
  return [ptr, data.length];
};
const addFile = (path, bytes) => {
  if (e.wtw_add_file(...put(path), ...put(bytes)) !== 0) throw new Error(`add_file: ${err()}`);
};
const runProcess = (path, argv, envp = ["PATH=/bin:/usr/bin", "HOME=/home"]) => {
  for (const a of argv) e.wtw_arg(...put(a));
  for (const v of envp) e.wtw_env(...put(v));
  if (e.wtw_load(...put(path)) !== 0) throw new Error(`load: ${err()}`);
  let status;
  let output = "";
  do {
    status = e.wtw_run(5_000_000);
    output += text(e.wtw_output_ptr(), e.wtw_output_len());
  } while (status === 0);
  return {
    status,
    output,
    exitCode: e.wtw_exit_code(),
    icount: e.wtw_icount_hi() * 2 ** 32 + e.wtw_icount_lo(),
  };
};
const expect = (label, run, expected) => {
  if (run.status !== 1 || run.exitCode !== 0 || (expected && !run.output.includes(expected))) {
    console.error(`[node] FAILED ${label}: status=${run.status} exit=${run.exitCode}`);
    console.error(`[node]   output: ${JSON.stringify(run.output)}  error: ${err()}`);
    process.exit(1);
  }
  console.log(`[node] ok: ${label} -> ${JSON.stringify(run.output.slice(0, 60))}`);
};

const t0 = performance.now();
if (e.wtw_init() !== 0) throw new Error(`init: ${err()}`);
console.log(`[node] machine ready in ${(performance.now() - t0).toFixed(0)} ms`);

// Milestone 1: static hello.
const hello = await readFile(new URL("../test_data/hello_linux.elf", import.meta.url));
addFile("/bin/hello", hello);
expect("hello", runProcess("/bin/hello", ["hello"]), "Hello");

// A guest image arrives over the network, so it can be damaged in transit or
// at rest. Refusing it has to leave the machine standing: on wasm a Rust panic
// is an abort, so an image that panics the loader does not fail to load, it
// takes the module with it and the tab has no machine left. Every case here
// is one the host tests cover too (crates/linux-compat/tests/elf.rs); what
// only this side can show is that the module is still alive afterwards.
{
  const view = (bytes) => new DataView(bytes.buffer, bytes.byteOffset);
  const PHDR_SIZE = 56;
  const phoff = (bytes) => Number(view(bytes).getBigUint64(0x20, true));
  const phnum = (bytes) => view(bytes).getUint16(0x38, true);
  const typeOf = (bytes, i) => view(bytes).getUint32(phoff(bytes) + i * PHDR_SIZE, true);
  const setType = (bytes, i, value) =>
    view(bytes).setUint32(phoff(bytes) + i * PHDR_SIZE, value, true);
  const setField = (bytes, i, field, value) =>
    view(bytes).setBigUint64(phoff(bytes) + i * PHDR_SIZE + field, value, true);
  const P_FILESZ = 32;
  const P_MEMSZ = 40;
  const P_ALIGN = 48;
  const PT_LOAD = 1;
  const loadable = [...Array(phnum(hello)).keys()].find((i) => typeOf(hello, i) === PT_LOAD);
  // A length of 2^32 plus the real one is the probe for a 32-bit `usize`:
  // narrowed, it reads as the real length and the image loads as though
  // nothing were wrong. The host refuses this same image, and so must this.
  const realFilesz = Number(
    view(hello).getBigUint64(phoff(hello) + loadable * PHDR_SIZE + 32, true),
  );

  const refuse = (transform, what) => {
    const damaged = transform(Uint8Array.from(hello));
    addFile("/bin/damaged", damaged);
    let code;
    try {
      code = e.wtw_load(...put("/bin/damaged"));
    } catch (error) {
      console.error(`[node] FAILED ${what} took the module down: ${error}`);
      process.exit(1);
    }
    if (code === 0) {
      console.error(`[node] FAILED ${what} was loaded`);
      process.exit(1);
    }
    console.log(`[node] ok: ${what} refused -> ${err()}`);
  };

  refuse((bytes) => bytes.slice(0, 16), "an image cut off after 16 bytes");
  refuse((bytes) => {
    setField(bytes, loadable, P_ALIGN, 0x1001n);
    return bytes;
  }, "a segment alignment that is not a power of two");
  refuse((bytes) => {
    setField(bytes, loadable, P_MEMSZ, (1n << 64n) - 1n);
    return bytes;
  }, "a segment of 2^64 bytes");
  refuse((bytes) => {
    setField(bytes, loadable, P_FILESZ, (1n << 32n) + BigInt(realFilesz));
    return bytes;
  }, "a segment length of 2^32 plus its real one");
  refuse((bytes) => {
    for (let i = 0; i < phnum(bytes); i += 1) {
      if (typeOf(bytes, i) === PT_LOAD) setType(bytes, i, 0);
    }
    return bytes;
  }, "an image with no loadable segment");

  // An alignment of zero means "no alignment" in ELF, so this image is meant
  // to load. It is here because dividing by it is a Rust panic in a release
  // build as much as a debug one, and on wasm that abort would end the module
  // rather than the load.
  const unaligned = Uint8Array.from(hello);
  setField(unaligned, loadable, P_ALIGN, 0n);
  addFile("/bin/unaligned", unaligned);
  try {
    if (e.wtw_load(...put("/bin/unaligned")) !== 0) {
      console.error(`[node] FAILED an unaligned segment was refused: ${err()}`);
      process.exit(1);
    }
  } catch (error) {
    console.error(`[node] FAILED an alignment of zero took the module down: ${error}`);
    process.exit(1);
  }
  console.log("[node] ok: an alignment of zero loaded as unaligned");

  if (e.wtw_load(...put("/bin/hello")) !== 0) {
    console.error(`[node] FAILED the machine did not survive a damaged image: ${err()}`);
    process.exit(1);
  }
  console.log("[node] ok: the machine still loads a good image afterwards");
}

// Milestone 2: BusyBox applets over the persistent filesystem.
let busybox;
try {
  busybox = await readFile(new URL("../test_data/busybox-musl", import.meta.url));
} catch {
  console.log("[node] busybox fixture missing (tools/fetch_busybox.sh) — skipping applet checks");
  console.log("[node] PASS (hello only)");
  process.exit(0);
}
addFile("/bin/busybox", busybox);
addFile("/etc/motd.txt", "from-the-vfs\n");

const bb = (...argv) => runProcess("/bin/busybox", ["busybox", ...argv]);

// The same BusyBox through the canonical chunk-manifest boundary. Only
// requested hashes are delivered, and the architectural result must match
// the eager run above it byte-for-byte and instruction-for-instruction.
{
  const eagerEngine = await instantiateEngine(await readFile(wasmPath));
  const g = eagerEngine.instance.exports;
  const gmem = () => new Uint8Array(g.memory.buffer);
  const gput = (value) => {
    const data = typeof value === "string" ? new TextEncoder().encode(value) : value;
    const ptr = g.wtw_alloc(data.length);
    gmem().set(data, ptr);
    return [ptr, data.length];
  };
  if (g.wtw_init() !== 0 || g.wtw_add_file(...gput("/bin/busybox"), ...gput(busybox)) !== 0) {
    throw new Error("eager comparison: setup");
  }
  for (const arg of ["busybox", "echo", "lazy-node"]) g.wtw_arg(...gput(arg));
  g.wtw_env(...gput("PATH=/bin"));
  if (g.wtw_load(...gput("/bin/busybox")) !== 0) throw new Error("eager comparison: load");
  let eagerStatus = 0;
  let eagerOutput = "";
  while (eagerStatus === 0) {
    eagerStatus = g.wtw_run(5_000_000);
    eagerOutput += new TextDecoder().decode(
      gmem().slice(g.wtw_output_ptr(), g.wtw_output_ptr() + g.wtw_output_len()),
    );
  }
  const eager = {
    status: eagerStatus,
    output: eagerOutput,
    exitCode: g.wtw_exit_code(),
    icount: g.wtw_icount_hi() * 2 ** 32 + g.wtw_icount_lo(),
  };
  const chunkSize = 64 * 1024;
  const hashes = [];
  const chunks = new Map();
  let legacy = 0xcbf29ce484222325n;
  for (let at = 0; at < busybox.length; at += chunkSize) {
    const chunk = busybox.subarray(at, Math.min(at + chunkSize, busybox.length));
    for (const byte of chunk) {
      legacy ^= BigInt(byte);
      legacy = BigInt.asUintN(64, legacy * 0x100000001b3n);
    }
    const hash = createHash("sha256").update(chunk).digest("hex");
    hashes.push(hash);
    chunks.set(hash, chunk);
  }
  const manifest =
    `webtos-chunk-manifest 1\n` +
    `d 755 0 ${Buffer.from("/bin").toString("hex")}\n` +
    `f 755 0 ${Buffer.from("/bin/busybox").toString("hex")} ${busybox.length} ${chunkSize} ${legacy.toString(16).padStart(16, "0")} ${hashes.join(",")}\n`;

  const fresh = await instantiateEngine(await readFile(wasmPath));
  const f = fresh.instance.exports;
  const fmem = () => new Uint8Array(f.memory.buffer);
  const fput = (value) => {
    const data = typeof value === "string" ? new TextEncoder().encode(value) : value;
    const ptr = f.wtw_alloc(data.length);
    fmem().set(data, ptr);
    return [ptr, data.length];
  };
  if (f.wtw_init() !== 0) throw new Error("lazy node: init");
  if (f.wtw_install_chunk_manifest(...fput(manifest)) !== 0) throw new Error("lazy node: manifest");
  for (const arg of ["busybox", "echo", "lazy-node"]) f.wtw_arg(...fput(arg));
  f.wtw_env(...fput("PATH=/bin"));
  const deliverRequest = (context) => {
    const len = f.wtw_page_request_take();
    if (len !== 65) throw new Error(`lazy node: ${context} request length ${len}`);
    const request = fmem().slice(f.wtw_page_request_ptr(), f.wtw_page_request_ptr() + len);
    const hash = Buffer.from(request.slice(32, 64)).toString("hex");
    const view = new DataView(request.buffer, request.byteOffset, request.byteLength);
    if (f.wtw_page_deliver(view.getUint32(0, true), view.getUint32(4, true), ...fput(chunks.get(hash))) !== 0) {
      throw new Error(`lazy node: ${context} deliver ${hash}`);
    }
  };
  for (;;) {
    const loadStatus = f.wtw_load(...fput("/bin/busybox"));
    if (loadStatus === 0) break;
    if (loadStatus !== 10) throw new Error("lazy node: load");
    deliverRequest("metadata");
  }
  let status = 0;
  let output = "";
  while (status === 0 || status === 10) {
    status = f.wtw_run(5_000_000);
    output += new TextDecoder().decode(
      fmem().slice(f.wtw_output_ptr(), f.wtw_output_ptr() + f.wtw_output_len()),
    );
    if (status !== 10) continue;
    deliverRequest("run");
  }
  const icount = f.wtw_icount_hi() * 2 ** 32 + f.wtw_icount_lo();
  if (
    status !== 1 ||
    f.wtw_exit_code() !== 0 ||
    output !== eager.output ||
    icount !== eager.icount ||
    f.wtw_page_in_count() === 0 ||
    f.wtw_footprint_kib(2) * 1024 >= busybox.length
  ) {
    console.error(`[node] FAILED lazy image: status=${status} exit=${f.wtw_exit_code()} icount=${icount}/${eager.icount} pages=${f.wtw_page_in_count()}`);
    process.exit(1);
  }
  console.log(`[node] ok: lazy image -> ${f.wtw_page_in_count()} pages, ${f.wtw_footprint_kib(2)} KiB resident of ${Math.ceil(busybox.length / 1024)} KiB`);
}

// Builds a chunk manifest over several files (with their parent directories)
// and the content-addressed chunk store to serve it. The legacy-FNV field
// feeds trace headers only; these gates record no trace.
function buildManifest(files) {
  const chunkSize = 64 * 1024;
  const chunks = new Map();
  const dirs = new Set();
  const lines = [];
  for (const { path, bytes, mode = "755" } of files) {
    let at = 1;
    while (true) {
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
    lines.push({
      path,
      line: `f ${mode} 0 ${Buffer.from(path).toString("hex")} ${bytes.length} ${chunkSize} ${"0".repeat(16)} ${hashes.join(",")}`,
    });
  }
  // The parser requires every record (directories and files together) in
  // strictly sorted path order.
  const records = [
    ...[...dirs].map((d) => ({ path: d, line: `d 755 0 ${Buffer.from(d).toString("hex")}` })),
    ...lines,
  ].sort((a, b) => (a.path < b.path ? -1 : 1));
  return {
    manifest: `webtos-chunk-manifest 1\n${records.map((r) => r.line).join("\n")}\n`,
    chunks,
  };
}

// Runs one lazy-agent command against a fresh engine: install the manifest,
// deliver requested chunks, and assert clean exit, expected output, and
// partial materialization. Returns totals for the log line.
async function lazyAgentRun({ label, manifest, chunks, loadPath, argv, envp, expectPattern, quarterOf, memMb }) {
  const fresh = await instantiateEngine(await readFile(wasmPath));
  const f = fresh.instance.exports;
  const fmem = () => new Uint8Array(f.memory.buffer);
  const fput = (value) => {
    const data = typeof value === "string" ? new TextEncoder().encode(value) : value;
    const ptr = f.wtw_alloc(data.length);
    fmem().set(data, ptr);
    return [ptr, data.length];
  };
  if (f.wtw_init() !== 0) throw new Error(`${label}: init`);
  if (memMb && f.wtw_set_guest_memory_mb(memMb) !== 0) throw new Error(`${label}: guestmem`);
  if (f.wtw_install_chunk_manifest(...fput(manifest)) !== 0) throw new Error(`${label}: manifest`);
  for (const arg of argv) f.wtw_arg(...fput(arg));
  for (const env of envp) f.wtw_env(...fput(env));
  let delivered = 0;
  const deliverRequest = (context) => {
    const len = f.wtw_page_request_take();
    if (len !== 65) throw new Error(`${label}: ${context} request length ${len}`);
    const request = fmem().slice(f.wtw_page_request_ptr(), f.wtw_page_request_ptr() + len);
    const hash = Buffer.from(request.slice(32, 64)).toString("hex");
    const view = new DataView(request.buffer, request.byteOffset, request.byteLength);
    const bytes = chunks.get(hash);
    if (!bytes) throw new Error(`${label}: unknown chunk ${hash}`);
    delivered += bytes.length;
    if (f.wtw_page_deliver(view.getUint32(0, true), view.getUint32(4, true), ...fput(bytes)) !== 0) {
      throw new Error(`${label}: ${context} deliver ${hash}`);
    }
  };
  for (;;) {
    const loadStatus = f.wtw_load(...fput(loadPath));
    if (loadStatus === 0) break;
    if (loadStatus !== 10) throw new Error(`${label}: load status ${loadStatus}`);
    deliverRequest("metadata");
  }
  let status = 0;
  let output = "";
  while (status === 0 || status === 10) {
    status = f.wtw_run(50_000_000);
    output += new TextDecoder().decode(
      fmem().slice(f.wtw_output_ptr(), f.wtw_output_ptr() + f.wtw_output_len()),
    );
    if (status === 10) deliverRequest("run");
  }
  const residentKiB = f.wtw_footprint_kib(2);
  const ok =
    status === 1 &&
    f.wtw_exit_code() === 0 &&
    expectPattern.test(output) &&
    f.wtw_page_in_count() > 0 &&
    delivered < quarterOf / 4 &&
    residentKiB * 1024 < quarterOf / 4;
  if (!ok) {
    console.error(
      `[node] FAILED ${label}: status=${status} exit=${f.wtw_exit_code()} ` +
        `pages=${f.wtw_page_in_count()} delivered=${delivered} resident=${residentKiB} KiB ` +
        `output=${JSON.stringify(output.slice(0, 160))}`,
    );
    process.exit(1);
  }
  console.log(
    `[node] ok: ${label} -> ${JSON.stringify(output.trim().slice(0, 40))}, ` +
      `${f.wtw_page_in_count()} pages, ${Math.round(delivered / 1024)} KiB fetched of ${Math.round(quarterOf / 1024)} KiB`,
  );
}

// The real Codex agent through the same manifest boundary: a 256 MB
// static-pie image installs by manifest and answers --version and --help while
// materializing only the pages execution touches. Self-skipping: the binary is
// not in the repository (scp the x86-64 standalone from a host that has it to
// web/codex).
{
  const codex = await readFile(new URL("./codex", import.meta.url)).catch(() => null);
  if (codex === null) {
    console.log("note: web/codex missing — real-agent lazy checks skipped");
  } else {
    const chunkSize = 64 * 1024;
    const hashes = [];
    const chunks = new Map();
    for (let at = 0; at < codex.length; at += chunkSize) {
      const chunk = codex.subarray(at, Math.min(at + chunkSize, codex.length));
      const hash = createHash("sha256").update(chunk).digest("hex");
      hashes.push(hash);
      chunks.set(hash, chunk);
    }
    // The legacy-FNV field feeds trace headers only; no trace is recorded here.
    const manifest =
      `webtos-chunk-manifest 1\n` +
      `d 755 0 ${Buffer.from("/bin").toString("hex")}\n` +
      `f 755 0 ${Buffer.from("/bin/codex").toString("hex")} ${codex.length} ${chunkSize} ${"0".repeat(16)} ${hashes.join(",")}\n`;

    const agentRun = async (label, argv, expectPattern) => {
      const fresh = await instantiateEngine(await readFile(wasmPath));
      const f = fresh.instance.exports;
      const fmem = () => new Uint8Array(f.memory.buffer);
      const fput = (value) => {
        const data = typeof value === "string" ? new TextEncoder().encode(value) : value;
        const ptr = f.wtw_alloc(data.length);
        fmem().set(data, ptr);
        return [ptr, data.length];
      };
      if (f.wtw_init() !== 0) throw new Error(`${label}: init`);
      if (f.wtw_install_chunk_manifest(...fput(manifest)) !== 0) throw new Error(`${label}: manifest`);
      for (const arg of argv) f.wtw_arg(...fput(arg));
      f.wtw_env(...fput("PATH=/bin"));
      f.wtw_env(...fput("HOME=/root"));
      let delivered = 0;
      const deliverRequest = (context) => {
        const len = f.wtw_page_request_take();
        if (len !== 65) throw new Error(`${label}: ${context} request length ${len}`);
        const request = fmem().slice(f.wtw_page_request_ptr(), f.wtw_page_request_ptr() + len);
        const hash = Buffer.from(request.slice(32, 64)).toString("hex");
        const view = new DataView(request.buffer, request.byteOffset, request.byteLength);
        const bytes = chunks.get(hash);
        if (!bytes) throw new Error(`${label}: unknown chunk ${hash}`);
        delivered += bytes.length;
        if (f.wtw_page_deliver(view.getUint32(0, true), view.getUint32(4, true), ...fput(bytes)) !== 0) {
          throw new Error(`${label}: ${context} deliver ${hash}`);
        }
      };
      for (;;) {
        const loadStatus = f.wtw_load(...fput("/bin/codex"));
        if (loadStatus === 0) break;
        if (loadStatus !== 10) throw new Error(`${label}: load status ${loadStatus}`);
        deliverRequest("metadata");
      }
      let status = 0;
      let output = "";
      while (status === 0 || status === 10) {
        status = f.wtw_run(50_000_000);
        output += new TextDecoder().decode(
          fmem().slice(f.wtw_output_ptr(), f.wtw_output_ptr() + f.wtw_output_len()),
        );
        if (status === 10) deliverRequest("run");
      }
      const residentKiB = f.wtw_footprint_kib(2);
      const ok =
        status === 1 &&
        f.wtw_exit_code() === 0 &&
        expectPattern.test(output) &&
        f.wtw_page_in_count() > 0 &&
        delivered < codex.length / 4 &&
        residentKiB * 1024 < codex.length / 4;
      if (!ok) {
        console.error(
          `[node] FAILED ${label}: status=${status} exit=${f.wtw_exit_code()} ` +
            `pages=${f.wtw_page_in_count()} delivered=${delivered} resident=${residentKiB} KiB ` +
            `output=${JSON.stringify(output.slice(0, 120))}`,
        );
        process.exit(1);
      }
      console.log(
        `[node] ok: ${label} -> ${JSON.stringify(output.trim().slice(0, 40))}, ` +
          `${f.wtw_page_in_count()} pages, ${Math.round(delivered / 1024)} KiB fetched of ${Math.round(codex.length / 1024)} KiB`,
      );
    };
    await agentRun("codex --version (lazy 256MB agent)", ["codex", "--version"], /codex-cli \d+\.\d+\.\d+/);
    await agentRun("codex --help (lazy 256MB agent)", ["codex", "--help"], /[Uu]sage/);
  }
}

// The real Claude Code agent: a dynamically linked Bun runtime whose loader
// and glibc libraries are delivered by the same manifest, every file lazy.
// Self-skipping: stage the x86-64 binary at web/claude and its libraries at
// web/claude-libs/ (ld-linux-x86-64.so.2, libc.so.6, libm.so.6, libdl.so.2,
// libpthread.so.0, librt.so.1).
{
  const claude = await readFile(new URL("./claude", import.meta.url)).catch(() => null);
  if (claude === null) {
    console.log("note: web/claude missing — Claude Code lazy checks skipped");
  } else {
    const lib = async (name) => ({
      path: name === "ld-linux-x86-64.so.2" ? "/lib64/ld-linux-x86-64.so.2" : `/lib/x86_64-linux-gnu/${name}`,
      bytes: await readFile(new URL(`./claude-libs/${name}`, import.meta.url)),
    });
    const files = [
      { path: "/bin/claude", bytes: claude },
      await lib("ld-linux-x86-64.so.2"),
      await lib("libc.so.6"),
      await lib("libm.so.6"),
      await lib("libdl.so.2"),
      await lib("libpthread.so.0"),
      await lib("librt.so.1"),
    ];
    const { manifest, chunks } = buildManifest(files);
    const logical = files.reduce((sum, f) => sum + f.bytes.length, 0);
    await lazyAgentRun({
      label: "claude --version (lazy dynamic agent)",
      manifest,
      chunks,
      loadPath: "/bin/claude",
      argv: ["claude", "--version"],
      envp: ["PATH=/bin", "HOME=/root"],
      expectPattern: /\(Claude Code\)/,
      quarterOf: logical,
      memMb: 2048,
    });
  }
}

expect("echo", bb("echo", "hi-from-wasm"), "hi-from-wasm");
expect("cat", bb("cat", "/etc/motd.txt"), "from-the-vfs");
expect("ls /", bb("ls", "/"), "etc");
expect("mkdir", bb("mkdir", "/tmp/w"));
expect("cp", bb("cp", "/etc/motd.txt", "/tmp/w/copy.txt"));
expect("mv", bb("mv", "/tmp/w/copy.txt", "/tmp/w/moved.txt"));
expect("cat moved", bb("cat", "/tmp/w/moved.txt"), "from-the-vfs");
expect("sh redirect", bb("sh", "-c", "echo persisted > /tmp/out.txt"));
expect("cat redirected", bb("cat", "/tmp/out.txt"), "persisted");
expect("rm", bb("rm", "/tmp/w/moved.txt", "/tmp/out.txt"));
expect("rmdir", bb("rmdir", "/tmp/w"));

// Milestone 4: fork + copy-on-write + pipes + execve, all inside wasm.
addFile("/bin/cat", busybox);
expect(
  "sh pipeline (fork/pipe/execve)",
  bb("sh", "-c", "echo from-pipe | /bin/cat"),
  "from-pipe",
);

// Milestone 3: a dynamically linked PIE through the musl loader.
try {
  const ldso = await readFile(new URL("../test_data/alpine-minirootfs/lib/ld-musl-x86_64.so.1", import.meta.url));
  const dynHello = await readFile(new URL("../test_data/hello_dynamic.elf", import.meta.url));
  addFile("/lib/ld-musl-x86_64.so.1", ldso);
  addFile("/bin/hello_dynamic", dynHello);
  const run = runProcess("/bin/hello_dynamic", ["hello_dynamic"]);
  expect("dynamic hello (musl loader)", run, "ello");
} catch {
  console.log("[node] alpine fixture missing (tools/fetch_alpine_rootfs.sh) — skipping dynamic check");
}

// Reload persistence: snapshot the filesystem, boot a brand-new module
// instance (what a browser refresh does), restore, and read back.
{
  const run = bb("sh", "-c", "echo survived-the-reload > /home/state.txt");
  expect("write state before reload", run);
  if (e.wtw_fs_export() !== 0) throw new Error(`fs export: ${err()}`);
  const snapshot = mem().slice(e.wtw_fs_ptr(), e.wtw_fs_ptr() + e.wtw_fs_len());
  console.log(`[node] snapshot: ${snapshot.length.toLocaleString()} bytes`);

  const fresh = await instantiateEngine(await readFile(wasmPath));
  const f = fresh.instance.exports;
  const fmem = () => new Uint8Array(f.memory.buffer);
  const ftext = (ptr, len) => new TextDecoder().decode(fmem().slice(ptr, ptr + len));
  const ferr = () => ftext(f.wtw_error_ptr(), f.wtw_error_len());
  const fput = (bytes) => {
    const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    const ptr = f.wtw_alloc(data.length);
    fmem().set(data, ptr);
    return [ptr, data.length];
  };
  if (f.wtw_init() !== 0) throw new Error(`reborn init: ${ferr()}`);
  if (f.wtw_fs_import(...fput(snapshot)) !== 0) throw new Error(`fs import: ${ferr()}`);
  for (const a of ["busybox", "cat", "/home/state.txt"]) f.wtw_arg(...fput(a));
  f.wtw_env(...fput("PATH=/bin"));
  if (f.wtw_load(...fput("/bin/busybox")) !== 0) throw new Error(`reborn load: ${ferr()}`);
  let status;
  let output = "";
  do {
    status = f.wtw_run(5_000_000);
    output += ftext(f.wtw_output_ptr(), f.wtw_output_len());
  } while (status === 0);
  if (status !== 1 || f.wtw_exit_code() !== 0 || !output.includes("survived-the-reload")) {
    console.error(`[node] FAILED reload persistence: ${JSON.stringify(output)} ${ferr()}`);
    process.exit(1);
  }
  console.log(`[node] ok: reload persistence -> ${JSON.stringify(output)}`);

  // A snapshot comes out of browser storage, so it can be anything. The
  // interesting corruption is one that only misbehaves here: wasm is 32-bit,
  // and a 64-bit length cast to `usize` narrows — 2^32 + 1 would read as 1
  // and the parse would carry on with a plausible-looking filesystem. A
  // 64-bit host cannot show that, because there the same value is simply too
  // large and fails anyway.
  const corrupt = (transform, what) => {
    const damaged = transform(snapshot.slice());
    const again = f.wtw_fs_import(...fput(damaged));
    if (again === 0) {
      console.error(`[node] FAILED ${what} was accepted`);
      process.exit(1);
    }
    console.log(`[node] ok: ${what} refused -> ${ferr()}`);
  };

  // The first file length in the snapshot, set to 2^32 + 1: narrowed to 32
  // bits it is 1, which the parse would accept.
  const marker = new TextEncoder().encode("survived-the-reload");
  const at = snapshot.findIndex((_, i) =>
    marker.every((byte, j) => snapshot[i + j] === byte),
  );
  if (at < 8) throw new Error("could not find the seeded file in the snapshot");
  corrupt((bytes) => {
    const view = new DataView(bytes.buffer, bytes.byteOffset);
    view.setBigUint64(at - 8, (1n << 32n) + 1n, true);
    return bytes;
  }, "a file length that narrows to 1 on a 32-bit host");

  corrupt((bytes) => bytes.slice(0, bytes.length >> 1), "a half-written snapshot");
  corrupt((bytes) => {
    const view = new DataView(bytes.buffer, bytes.byteOffset);
    view.setUint32(8, 3_999_999, true);
    return bytes.slice(0, 12);
  }, "a header claiming four million nodes");
}

// Guest sizes that do not fit a 32-bit `usize`. This can only be checked
// here: on a 64-bit host the same values are simply large and behave, while
// in a browser `as usize` keeps the low half — a 4 GiB `ftruncate` became a
// truncate to zero, and a write at offset 2^32 landed on the first bytes of
// the file. Real Linux honours both and leaves the head intact; a tab cannot
// hold 4 GiB, so refusing is right and quietly doing something smaller is not.
{
  const fixture = new URL("../test_data/test_size_narrowing.elf", import.meta.url);
  const fresh = await instantiateEngine(await readFile(wasmPath));
  const f = fresh.instance.exports;
  const fmem = () => new Uint8Array(f.memory.buffer);
  const fput = (bytes) => {
    const data = typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes;
    const ptr = f.wtw_alloc(data.length);
    fmem().set(data, ptr);
    return [ptr, data.length];
  };
  if (f.wtw_init() !== 0) throw new Error("narrowing: init");
  f.wtw_add_file(...fput("/bin/narrow"), ...fput(await readFile(fixture)));
  f.wtw_arg(...fput("narrow"));
  f.wtw_env(...fput("PATH=/bin"));
  if (f.wtw_load(...fput("/bin/narrow")) !== 0) throw new Error("narrowing: load");
  let st;
  let out = "";
  do {
    st = f.wtw_run(20_000_000);
    out += new TextDecoder().decode(
      fmem().slice(f.wtw_output_ptr(), f.wtw_output_ptr() + f.wtw_output_len()),
    );
  } while (st === 0);

  const head = /head=(\S*)/.exec(out)?.[1] ?? "";
  const size = Number(/size=(-?\d+)/.exec(out)?.[1] ?? -1);
  if (head !== "keep-me") {
    console.error(`[node] FAILED a 2^32 offset wrote over the start of the file: ${out.trim()}`);
    process.exit(1);
  }
  const far = Number(/far_read=(-?\d+)/.exec(out)?.[1] ?? -1);
  if (far !== 0) {
    console.error(
      `[node] FAILED a read at offset 2^32 returned ${far} bytes instead of end-of-file: ${out.trim()}`,
    );
    process.exit(1);
  }
  if (size !== 7) {
    console.error(`[node] FAILED a 4 GiB ftruncate changed the file to ${size} bytes: ${out.trim()}`);
    process.exit(1);
  }
  console.log(`[node] ok: guest sizes past 32 bits are refused, not narrowed -> ${out.trim()}`);
}

// A workload that computes in a loop and issues no syscalls is outside every
// other mechanism the runtime has for stopping a task: there is no kernel
// entry to interrupt it at, and the instruction limit only ends a turn, which
// this loop begins another of. Its allowance is the only thing that stops it,
// and until now there was none.
{
  // BusyBox `ls /` is 73,280 instructions, which is more than the allowance
  // below. The workload that this ceiling exists for — a loop with no
  // syscalls in it — needs a fixture compiled for Linux, so that half is
  // gated natively in `crates/linux-compat/tests/quota.rs`; what is gated
  // here is the boundary: setting the allowance, being told it is spent, and
  // continuing after it is raised.
  for (const a of ["busybox", "ls", "/"]) e.wtw_arg(...put(a));
  if (e.wtw_load(...put("/bin/busybox")) !== 0) throw new Error(`load: ${err()}`);

  // Ten thousand instructions, in turns of a thousand.
  if (e.wtw_set_cpu_budget_kinsn(10) !== 0) throw new Error(`cpu budget: ${err()}`);
  let status;
  let turns = 0;
  do {
    status = e.wtw_run(1_000);
    turns += 1;
  } while (status === 0 && turns < 1000);

  const STATUS_OUT_OF_CPU = 9;
  if (status !== STATUS_OUT_OF_CPU) {
    console.error(`[node] FAILED cpu budget: status=${status} after ${turns} turns`);
    process.exit(1);
  }
  if (e.wtw_cpu_headroom_kinsn() !== 0) {
    console.error(`[node] FAILED cpu budget: ${e.wtw_cpu_headroom_kinsn()}k left after stopping`);
    process.exit(1);
  }
  console.log(
    `[node] ok: a workload runs out of its instruction allowance -> stopped after ${turns} turns`,
  );

  // Raising it lets the workload continue, so a host can ask a person for
  // more rather than killing the tab.
  e.wtw_set_cpu_budget_kinsn(20);
  if (e.wtw_run(1_000) !== 0) {
    console.error(`[node] FAILED cpu budget: a raised allowance did not resume`);
    process.exit(1);
  }
  console.log("[node] ok: a raised allowance resumes where it stopped");
  e.wtw_reset();
  if (e.wtw_init() !== 0) throw new Error(`init: ${err()}`);
}

console.log("[node] PASS");
