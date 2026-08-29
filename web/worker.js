// webTOS execution worker: hosts the wasm Linux runtime off the UI thread.
// Messages in:  { type: "boot", files: [{path, bytes: ArrayBuffer}],
//                                links: [{path, target}] }
//               { type: "exec", path, argv: [..], envp: [..] }
//               { type: "spawn", path, argv, envp, rows, cols }
//                                     -- like exec, but stdin/stdout/stderr
//                                        are a terminal and the run yields
//                                        to this worker's message queue
//               { type: "input", data: string }  -- keystrokes for the terminal
//               { type: "resize", rows, cols }   -- terminal size (SIGWINCH)
//               { type: "network", gateway: "ws://127.0.0.1:8081" }
//                                     -- allow the guest to reach the network
//                                        through that relay; without it the
//                                        guest has no network at all
//               { type: "image", path, url, mode }
//                                     -- stream a large guest image in from
//                                        `url`, cached in OPFS so a reload
//                                        does not download it again
//               { type: "trace", path, url, argv, envp, sampleEvery }
//                                     -- run one image start to finish while
//                                        recording an architectural trace
//               { type: "persist" }   -- snapshot the guest FS into OPFS
//                                        (images this worker cached are left
//                                        out; boot re-injects them)
//               { type: "guestmem", mib } -- raise the guest's physical cap
//               { type: "budget", mib }  -- cap the total footprint; 0 clears
//               { type: "storageBudget", mib }  -- cap the guest filesystem;
//                                        past it a guest write gets ENOSPC
//               { type: "networkBudget", mib } -- cap the bytes the guest may
//                                        relay through the broker; past it a
//                                        guest send or receive gets EPERM
//               { type: "footprint" }   -- ask for a fresh reading
//               { type: "secrets", secrets: [{ name, value, paths? }] }
//                                     -- inject credentials by placeholder;
//                                        values never reach storage or a log
//               { type: "forget" }    -- delete the OPFS snapshot
// Messages out: { type: "status", text }, { type: "ready", restored, storage },
//               { type: "output", text },
//               { type: "progress", path, loaded, total, cached }
//               { type: "image", path, bytes, cached }  -- one image is in
//               { type: "footprint", guest, code, files, total, headroom,
//                                       storageHeadroom, network }
//                                     -- bytes, and what each budget has left
//               { type: "waiting" }   -- the guest is blocked on the terminal
//               { type: "done", status, error, exitCode, icount },
//               { type: "trace", status, trace }  -- the recorded trace text
//               { type: "persisted", bytes }, { type: "error", text }

const SNAPSHOT_FILE = "webtos-fs.bin";
/// Directory inside OPFS holding downloaded guest images.
const IMAGE_CACHE = "webtos-images";
/// Content-addressed chunks are independent of guest paths and image runs.
const CHUNK_CACHE = "webtos-chunks";
/// Bytes moved per step while streaming an image. Small enough that the
/// module's staging buffer stays modest, large enough that a 100 MB image
/// does not cost a hundred thousand calls.
const IMAGE_CHUNK = 4 << 20;
/// Guest instructions per slice. Bounds how long the worker goes without
/// draining output or reading its own message queue.
const FUEL = 5_000_000;
/// `wtw_run` status classes shared with crates/webtos-web.
const STATUS_RUNNING = 0;
const STATUS_HALT = 1;
const STATUS_AWAITING_INPUT = 7;
const STATUS_AWAITING_NETWORK = 8;
// The workload has spent its instruction allowance. The run loops below stop
// on it like any non-running status; it is named here so a reader of a
// stopped session can tell "out of allowance" from "crashed".
const STATUS_OUT_OF_CPU = 9;
const STATUS_AWAITING_PAGEIN = 10;
/// wtw_net_budget_ms when the guest armed no timer.
const NET_BUDGET_UNBOUNDED = 0xffff_ffff;
/// Longest the worker waits on the network in one go, so a silent peer
/// cannot stall the machine indefinitely.
const NET_WAIT_CAP_MS = 5_000;

// Whether this browsing context may use the origin-private filesystem at all.
// WebKit refuses it outright when the profile has no on-disk storage (a
// private window), so the host reports the capability up front instead of
// failing at the first "Save".
let storageReady = false;

async function opfsProbe() {
  try {
    if (typeof navigator === "undefined" || !navigator.storage) return false;
    await navigator.storage.getDirectory();
    return true;
  } catch {
    return false;
  }
}

async function opfsRead(name) {
  try {
    const root = await navigator.storage.getDirectory();
    const handle = await root.getFileHandle(name);
    const file = await handle.getFile();
    return new Uint8Array(await file.arrayBuffer());
  } catch {
    return null;
  }
}

/// Writes `bytes` to `name` so that a cancellation cannot leave the committed
/// file partial.
///
/// `createWritable()` truncates the file it opens at once, so writing straight
/// to `name` and being killed before `close()` destroys whatever was there —
/// for a snapshot, that is the session. So the bytes go to a `.partial` first,
/// which is fully written and closed before the committed name is touched at
/// all, and the commit is a single `move()`, which replaces atomically. If the
/// worker dies before the move, the old committed file is exactly as it was;
/// if it dies during the partial write, only the partial is damaged, and a
/// stale partial is overwritten by the next write or ignored on read.
async function opfsWriteAtomic(name, bytes) {
  const root = await navigator.storage.getDirectory();
  const partial = `${name}.partial`;
  const scratch = await root.getFileHandle(partial, { create: true });
  const writable = await scratch.createWritable();
  try {
    await writable.write(bytes);
    await writable.close();
  } catch (e) {
    // A failed write must not leave a partial masquerading as committable.
    try { await root.removeEntry(partial); } catch {}
    throw e;
  }
  if (typeof scratch.move === "function") {
    try {
      // The atomic path: one rename over the target.
      await scratch.move(name);
      return;
    } catch {
      // Some engines expose move() with a different signature or refuse a
      // rename over an existing file. Fall through to the copy commit.
    }
  }
  // Fallback where move() is absent or refused: the target is written from the
  // completed partial's bytes, which are already known to be whole. This
  // reopens the window the partial was meant to close, so it is the lesser
  // path, taken only when the atomic one is unavailable.
  const whole = await (await scratch.getFile()).arrayBuffer();
  const handle = await root.getFileHandle(name, { create: true });
  const commit = await handle.createWritable();
  await commit.write(whole);
  await commit.close();
  try { await root.removeEntry(partial); } catch {}
}

async function opfsDelete(name) {
  try {
    const root = await navigator.storage.getDirectory();
    await root.removeEntry(name);
  } catch {
    // Nothing to delete.
  }
}

// ------------------------------------------------------------------ images

// An agent image is two orders of magnitude larger than BusyBox, and the
// obvious way to load one — fetch it whole, postMessage it, hand it to
// wtw_alloc — holds three copies at once, which on wasm32 is fatal. So the
// worker fetches it itself, writes it to an OPFS cache and into the guest as
// the bytes arrive, and never holds more than one chunk.

async function imageCacheDir(create) {
  const root = await navigator.storage.getDirectory();
  return root.getDirectoryHandle(IMAGE_CACHE, { create });
}

async function chunkCacheDir(create) {
  const root = await navigator.storage.getDirectory();
  return root.getDirectoryHandle(CHUNK_CACHE, { create });
}

/// The cache name for an image: its guest path, flattened. Two images at the
/// same guest path are the same image as far as a session is concerned.
const cacheName = (path) => path.replace(/[^A-Za-z0-9._-]/g, "_");

/// Feeds an image into the guest filesystem in chunks.
function guestWriter(path, size, mode) {
  // The path is copied into the module once and reused by every chunk.
  const [pathPtr, pathLen] = put(path);
  if (exports.wtw_file_create(pathPtr, pathLen, size, mode) !== 0) {
    throw new Error(`create ${path}: ${lastError()}`);
  }
  return (chunk) => {
    if (exports.wtw_file_append(pathPtr, pathLen, ...stage(chunk)) !== 0) {
      throw new Error(`append ${path}: ${lastError()}`);
    }
  };
}

/// Reads a cached image out of OPFS and into the guest, without ever holding
/// the whole file: the slices come straight off the File handle.
async function loadFromCache(handle, path, mode) {
  const file = await handle.getFile();
  const write = guestWriter(path, file.size, mode);
  let loaded = 0;
  while (loaded < file.size) {
    const end = Math.min(loaded + IMAGE_CHUNK, file.size);
    write(new Uint8Array(await file.slice(loaded, end).arrayBuffer()));
    loaded = end;
    postMessage({ type: "progress", path, loaded, total: file.size, cached: true });
  }
  return file.size;
}

/// Downloads an image, writing it into the guest and the cache as it arrives.
async function loadFromNetwork(url, path, mode) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
  const total = Number(response.headers.get("content-length")) || 0;
  const write = guestWriter(path, total, mode);

  // The cache is written under a temporary name and renamed at the end, so an
  // interrupted download cannot be mistaken for a complete image later.
  let sink = null;
  let temporary = null;
  if (storageReady) {
    try {
      const dir = await imageCacheDir(true);
      temporary = `${cacheName(path)}.partial`;
      sink = await (await dir.getFileHandle(temporary, { create: true })).createWritable();
    } catch {
      sink = null; // Caching is an optimisation; the run continues without it.
    }
  }

  const reader = response.body.getReader();
  let loaded = 0;
  // Accumulate small network reads into one guest write.
  let pending = [];
  let pendingBytes = 0;
  const flush = async () => {
    if (pendingBytes === 0) return;
    const chunk = pending.length === 1 ? pending[0] : concat(pending, pendingBytes);
    write(chunk);
    if (sink) await sink.write(chunk);
    pending = [];
    pendingBytes = 0;
  };
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    pending.push(value);
    pendingBytes += value.length;
    loaded += value.length;
    if (pendingBytes >= IMAGE_CHUNK) {
      await flush();
      postMessage({ type: "progress", path, loaded, total, cached: false });
    }
  }
  await flush();
  postMessage({ type: "progress", path, loaded, total: total || loaded, cached: false });

  if (sink) {
    await sink.close();
    try {
      const dir = await imageCacheDir(true);
      // Rename is not available on every engine, so the completed image is
      // copied into place and the partial removed.
      const source = await (await dir.getFileHandle(temporary)).getFile();
      const target = await (await dir.getFileHandle(cacheName(path), { create: true })).createWritable();
      await target.write(source);
      await target.close();
      await dir.removeEntry(temporary);
    } catch {
      // A cache that could not be completed is simply absent next time.
    }
  }
  return loaded;
}

function concat(parts, total) {
  const out = new Uint8Array(total);
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

const hexBytes = (hex) => {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error(`invalid chunk hash ${hex}`);
  return Uint8Array.from(hex.match(/../g), (pair) => Number.parseInt(pair, 16));
};

async function readCachedChunk(hash) {
  if (!storageReady) return null;
  try {
    const handle = await (await chunkCacheDir(false)).getFileHandle(hash);
    // Dedicated workers may expose synchronous OPFS reads. Where they do not,
    // the File fallback is the same verified async completion path.
    if (typeof handle.createSyncAccessHandle === "function") {
      const access = await handle.createSyncAccessHandle();
      try {
        const bytes = new Uint8Array(access.getSize());
        access.read(bytes, { at: 0 });
        return bytes;
      } finally {
        access.close();
      }
    }
    return new Uint8Array(await (await handle.getFile()).arrayBuffer());
  } catch {
    return null;
  }
}

async function cacheChunk(hash, bytes) {
  if (!storageReady) return;
  try {
    const handle = await (await chunkCacheDir(true)).getFileHandle(hash, { create: true });
    const sink = await handle.createWritable();
    await sink.write(bytes);
    await sink.close();
  } catch {
    // Caching is optional; the module still verifies and consumes this chunk.
  }
}

async function fetchChunk(hash) {
  const cached = await readCachedChunk(hash);
  if (cached) return cached;
  if (!chunkBaseUrl) throw new Error(`no chunk source configured for ${hash}`);
  const response = await fetch(`${chunkBaseUrl}/${hash}`);
  if (!response.ok) throw new Error(`chunk ${hash}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

/// Completes the one deterministic chunk request currently exported by the
/// module. ELF metadata loading, file reads, and mapped-page faults all use
/// this ticket/hash authority. Bytes enter OPFS only after the module accepts
/// their digest and storage charge.
async function satisfyChunkRequest(context) {
  const len = exports.wtw_page_request_take();
  if (len !== 65) {
    throw new Error(`${context}: invalid page request length ${len}: ${lastError()}`);
  }
  const request = mem().slice(
    exports.wtw_page_request_ptr(),
    exports.wtw_page_request_ptr() + len,
  );
  const view = new DataView(request.buffer, request.byteOffset, request.byteLength);
  const ticketLo = view.getUint32(0, true);
  const ticketHi = view.getUint32(4, true);
  const hash = [...request.slice(32, 64)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  const bytes = await fetchChunk(hash);
  if (exports.wtw_page_deliver(ticketLo, ticketHi, ...stage(bytes)) !== 0) {
    throw new Error(`${context}: ${hash}: ${lastError()}`);
  }
  await cacheChunk(hash, bytes);
}

/// Installs the exact canonical manifest bytes only after the page has
/// authenticated them. `preload` names the bounded ELF-metadata chunks needed
/// by the synchronous load call and any scoped-secret target that must be
/// promoted before execution; those hints cannot redefine manifest paths.
async function installLazyImage({ manifest, chunkBase, preload = [] }) {
  chunkBaseUrl = chunkBase.replace(/\/$/, "");
  const bytes = typeof manifest === "string" ? new TextEncoder().encode(manifest) : manifest;
  if (exports.wtw_install_chunk_manifest(...stage(bytes)) !== 0) {
    throw new Error(`chunk manifest: ${lastError()}`);
  }
  for (const hash of preload) {
    const bytes = await fetchChunk(hash);
    const [hashPtr] = put(hexBytes(hash));
    if (exports.wtw_put_chunk(hashPtr, ...stage(bytes)) !== 0) {
      throw new Error(`preload chunk ${hash}: ${lastError()}`);
    }
    // The module has now verified SHA-256 and quota. Persist only bytes that
    // crossed that authority boundary successfully; a corrupt response must
    // not poison the warm cache under the hash it failed to match.
    await cacheChunk(hash, bytes);
  }
  postMessage({ type: "lazyImage", preloaded: preload.length });
}

/// The cached copy of an image, or null when there is none to trust. A
/// rebuilt image keeps its name, so the cache is only used when the server
/// still reports the size that was stored.
async function cachedImage(path, url) {
  try {
    const dir = await imageCacheDir(false);
    const handle = await dir.getFileHandle(cacheName(path));
    const file = await handle.getFile();
    const head = await fetch(url, { method: "HEAD" }).catch(() => null);
    const size = head?.ok ? Number(head.headers.get("content-length")) : 0;
    if (size && size !== file.size) return null;
    return handle;
  } catch {
    return null; // Not cached yet, or the cache is unusable.
  }
}

/// Guest paths this worker put there from its own image cache. A snapshot
/// leaves them out — the cache already holds the bytes and they are injected
/// again on the next boot, so carrying them would pay for the image twice.
const hostImages = new Set();

async function loadImage({ path, url, mode = 0o755 }) {
  postMessage({ type: "status", text: `loading ${path}…` });
  hostImages.add(path);
  if (storageReady) {
    const handle = await cachedImage(path, url);
    if (handle) {
      const bytes = await loadFromCache(handle, path, mode);
      postMessage({ type: "image", path, bytes, cached: true });
      reportFootprint();
      return;
    }
  }
  const bytes = await loadFromNetwork(url, path, mode);
  postMessage({ type: "image", path, bytes, cached: false });
  reportFootprint();
}

/// Deletes every cached image.
async function forgetImages() {
  if (!storageReady) return;
  const root = await navigator.storage.getDirectory();
  for (const name of [IMAGE_CACHE, CHUNK_CACHE]) {
    try {
      await root.removeEntry(name, { recursive: true });
    } catch {
      // That cache has not been created.
    }
  }
}

let exports = null;
let chunkBaseUrl = "";

const mem = () => new Uint8Array(exports.memory.buffer);
const text = (ptr, len) => new TextDecoder().decode(mem().slice(ptr, ptr + len));
const lastError = () => text(exports.wtw_error_ptr(), exports.wtw_error_len());
/// Copies bytes into a module-owned buffer that lives until wtw_reset. For
/// one-shot input: images, argv, a restored snapshot.
const put = (value) => {
  const data = typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value);
  const ptr = exports.wtw_alloc(data.length);
  mem().set(data, ptr);
  return [ptr, data.length];
};

/// Copies bytes into the module's reusable staging buffer. For input that
/// repeats without bound — keystrokes, received packets — where a fresh
/// allocation per call would grow the module's memory all session.
const stage = (value) => {
  const data = typeof value === "string" ? new TextEncoder().encode(value) : new Uint8Array(value);
  const ptr = exports.wtw_scratch(data.length);
  mem().set(data, ptr);
  return [ptr, data.length];
};

// The JIT host imports (inlined; this classic worker cannot import a module).
// A compiled block imports the engine's own memory as env.regs and routes its
// guest-memory callbacks back into the engine's wtw_jit_* shims.
const jitBlockInstances = [];
const jitImports = {
  jit_compile(ptr, len) {
    let instance;
    try {
      const bytes = new Uint8Array(exports.memory.buffer).slice(ptr, ptr + len);
      const module = new WebAssembly.Module(bytes);
      const lo = (x) => Number(x & 0xffffffffn);
      const hi = (x) => Number((x >> 32n) & 0xffffffffn);
      instance = new WebAssembly.Instance(module, {
        env: {
          regs: exports.memory,
          load: (a, d, s) => exports.wtw_jit_load(lo(a), hi(a), d, s),
          store: (a, v, s) => exports.wtw_jit_store(lo(a), hi(a), lo(v), hi(v), s),
          fault: (i) => exports.wtw_jit_fault(i),
          raise: (c, v, i) => exports.wtw_jit_raise(c, lo(v), hi(v), i),
        },
      });
    } catch {
      return 0;
    }
    jitBlockInstances.push(instance);
    return jitBlockInstances.length;
  },
  jit_call(handle, regsBase, tlbBase) {
    jitBlockInstances[handle - 1].exports.run(regsBase, tlbBase);
  },
  jit_call_region(handle, regsBase, tlbBase, maxItersLo, maxItersHi) {
    const maxIters = BigInt(maxItersLo >>> 0) | (BigInt(maxItersHi >>> 0) << 32n);
    const iters = jitBlockInstances[handle - 1].exports.run(regsBase, tlbBase, maxIters);
    return Number(BigInt(iters) & 0xffffffffn);
  },
  // Drop the evicted module and instance so the engine's native code memory is
  // reclaimed; the slot is nulled, not spliced, so later handles keep indices.
  jit_evict(handle) {
    if (handle >= 1 && handle <= jitBlockInstances.length) {
      jitBlockInstances[handle - 1] = null;
    }
  },
};

async function boot(files, links = [], jitAfter = null) {
  postMessage({ type: "status", text: "loading wasm module…" });
  const url = new URL("./webtos_web.wasm", self.location.href);
  jitBlockInstances.length = 0;
  const { instance } = await WebAssembly.instantiateStreaming(fetch(url), { env: jitImports });
  exports = instance.exports;

  postMessage({ type: "status", text: "compiling SLEIGH specification…" });
  const t0 = performance.now();
  if (exports.wtw_init() !== 0) throw new Error(`machine init failed: ${lastError()}`);
  if (jitAfter !== null && exports.wtw_jit_enable(Math.max(1, Math.round(jitAfter))) !== 0) {
    throw new Error(`JIT enable failed: ${lastError()}`);
  }

  // Restore the filesystem persisted before the last reload, if any.
  storageReady = await opfsProbe();
  let restored = false;
  const snapshot = storageReady ? await opfsRead(SNAPSHOT_FILE) : null;
  if (snapshot && snapshot.length > 0) {
    if (exports.wtw_fs_import(...put(snapshot)) === 0) {
      restored = true;
    } else {
      postMessage({ type: "status", text: `snapshot ignored: ${lastError()}` });
    }
  }

  // Seed images are (re-)injected on top of whatever was restored.
  for (const file of files) {
    if (exports.wtw_add_file(...put(file.path), ...put(file.bytes)) !== 0) {
      throw new Error(`add_file ${file.path}: ${lastError()}`);
    }
  }
  for (const link of links) {
    if (exports.wtw_add_symlink(...put(link.path), ...put(link.target)) !== 0) {
      throw new Error(`add_symlink ${link.path}: ${lastError()}`);
    }
  }
  postMessage({
    type: "status",
    text: `machine ready in ${(performance.now() - t0).toFixed(0)} ms` +
      (restored ? " — filesystem restored from the previous session" : ""),
  });
  postMessage({ type: "ready", restored, storage: storageReady });
}

/// Reports where the machine's memory has gone. One wasm linear memory holds
/// the guest's pages, the images streamed into it, and the code the engine has
/// lifted; a tab's ceiling is about 3.9 GiB, so a host that wants to refuse a
/// workload rather than die needs to see all three.
function reportFootprint() {
  const kib = (part) => exports.wtw_footprint_kib(part) * 1024;
  const headroom = exports.wtw_memory_headroom_kib();
  const storageHeadroom = exports.wtw_storage_headroom_kib();
  const networkHeadroom = exports.wtw_network_headroom_kib();
  postMessage({
    type: "footprint",
    guest: kib(0),
    code: kib(1),
    files: kib(2),
    // The sum of the parts, not a separately rounded whole: each part is
    // reported in KiB, and round(a)+round(b)+round(c) is not round(a+b+c), so
    // a separately rounded total would disagree with its own parts by a few
    // KiB. The total is what the footprint is spent on, which is the parts.
    total: kib(0) + kib(1) + kib(2),
    headroom: headroom < 0 ? null : headroom * 1024,
    // The filesystem's own ceiling. `files` is what it holds; this is what
    // the guest may still add before a write gets ENOSPC.
    storageHeadroom: storageHeadroom < 0 ? null : storageHeadroom * 1024,
    // Relayed bytes pass through rather than accumulating, so the network
    // quota is counted, not measured off the footprint.
    network: {
      sent: exports.wtw_network_usage_kib(0) * 1024,
      received: exports.wtw_network_usage_kib(1) * 1024,
      total: exports.wtw_network_usage_kib(2) * 1024,
      headroom: networkHeadroom < 0 ? null : networkHeadroom * 1024,
    },
  });
}

/// Registers credentials with the guest and expands their placeholders.
///
/// The values are handed to the module and dropped here: nothing keeps a copy
/// in the worker, and no message, status line, or error carries one. A
/// snapshot redacts them back to `${name}`, so they never reach OPFS either.
function applySecrets(secrets) {
  for (const { name, value, paths = [] } of secrets ?? []) {
    if (exports.wtw_secret(...put(name), ...put(value)) !== 0) {
      throw new Error(`secret ${name}: ${lastError()}`);
    }
    for (const path of paths) {
      if (exports.wtw_secret_scope(...put(path)) !== 0) {
        throw new Error(`secret ${name} scope: ${lastError()}`);
      }
    }
  }
  if (exports.wtw_secrets_apply() !== 0) throw new Error(`secrets: ${lastError()}`);
  postMessage({ type: "status", text: `${(secrets ?? []).length} credential(s) injected` });
}

async function persist() {
  if (!storageReady) {
    throw new Error("browser storage is unavailable here (private window or blocked storage)");
  }
  for (const path of hostImages) exports.wtw_fs_exclude(...put(path));
  if (exports.wtw_fs_export() !== 0) throw new Error(`export failed: ${lastError()}`);
  const bytes = mem().slice(
    exports.wtw_fs_ptr(),
    exports.wtw_fs_ptr() + exports.wtw_fs_len(),
  );
  await opfsWriteAtomic(SNAPSHOT_FILE, bytes);
  postMessage({ type: "persisted", bytes: bytes.length });
}

async function load(path, argv, envp) {
  for (const arg of argv) exports.wtw_arg(...put(arg));
  for (const env of envp) exports.wtw_env(...put(env));
  for (;;) {
    const status = exports.wtw_load(...put(path));
    if (status === 0) return;
    if (status === STATUS_AWAITING_PAGEIN) {
      await satisfyChunkRequest("ELF metadata page-in");
      continue;
    }
    throw new Error(`load failed: ${lastError()}`);
  }
}

function drain() {
  const out = text(exports.wtw_output_ptr(), exports.wtw_output_len());
  if (out.length > 0) postMessage({ type: "output", text: out });
}

function finish(status) {
  postMessage({
    type: "done",
    status,
    error: status === STATUS_HALT ? "" : lastError(),
    exitCode: exports.wtw_exit_code(),
    icount: exports.wtw_icount_hi() * 2 ** 32 + exports.wtw_icount_lo(),
    pageIns: exports.wtw_page_in_count(),
    filesKiB: exports.wtw_footprint_kib(2),
    jitBlocks: Number(exports.wtw_jit_block_dispatch_count()),
    jitRegions: Number(exports.wtw_jit_region_dispatch_count()),
  });
}

/// A non-interactive process, run through the same pump so a workload that
/// uses the network still gets its host turns.
async function exec(path, argv, envp) {
  await load(path, argv, envp);
  waiting = false;
  return pump();
}

// A macrotask yield that the browser does not clamp to 4 ms the way nested
// setTimeout is. Letting the worker reach its message queue between slices is
// what makes typing and resizing land mid-run.
const channel = new MessageChannel();
const yieldToQueue = () =>
  new Promise((resolve) => {
    channel.port1.onmessage = () => resolve();
    channel.port2.postMessage(0);
  });

// ----------------------------------------------------------------- network

// The guest's sockets live in the gateway; this side is only a courier. Each
// guest endpoint gets its own WebSocket, so the relay's own open/close and
// back-pressure carry the stream's semantics instead of a framing layer.
//
// Linux errno values the guest expects to see for a transport failure.
const ENETUNREACH = 101;
const ECONNREFUSED = 111;
const ECONNRESET = 104;
/// WebSocket close codes the gateway uses to say why it hung up.
const CLOSE_BAD_REQUEST = 4400;
const CLOSE_REFUSED = 4403;
const CLOSE_UNREACHABLE = 4502;

let gateway = null;
const sockets = new Map();
/// Bumped whenever anything is delivered into the machine, so a paused pump
/// can tell "something arrived" from "the wait expired".
let netEvents = 0;
/// Resolver for a pump parked on the network, so a delivery wakes it at once
/// instead of after its timeout.
let netWake = null;

function noteNetEvent() {
  netEvents += 1;
  if (netWake) {
    const wake = netWake;
    netWake = null;
    wake();
  }
}

const netCommands = () => {
  const len = exports.wtw_net_take();
  if (len < 0) throw new Error(`network drain failed: ${lastError()}`);
  return mem().slice(exports.wtw_net_cmd_ptr(), exports.wtw_net_cmd_ptr() + len);
};

const deliverData = (handle, bytes) => {
  const [ptr, len] = stage(bytes);
  exports.wtw_net_data(handle, ptr, len);
  noteNetEvent();
};

const deliverDatagram = (handle, frame) => {
  const ip = (frame[0] << 24) | (frame[1] << 16) | (frame[2] << 8) | frame[3];
  const port = (frame[4] << 8) | frame[5];
  const [ptr, len] = stage(frame.subarray(6));
  exports.wtw_net_datagram(handle, ip >>> 0, port, ptr, len);
  noteNetEvent();
};

const deliverError = (handle, errno) => {
  exports.wtw_net_error(handle, errno);
  noteNetEvent();
};

function openTcp(handle, ip, port) {
  const socket = new WebSocket(`${gateway}/tcp?host=${ip}&port=${port}`);
  socket.binaryType = "arraybuffer";
  const entry = { socket, queue: [], open: false };
  sockets.set(handle, entry);
  socket.onopen = () => {
    entry.open = true;
    for (const pending of entry.queue) socket.send(pending);
    entry.queue.length = 0;
  };
  socket.onmessage = (event) => {
    if (typeof event.data === "string") {
      // "open" once the relay's own TCP connect succeeded; "eof" on a peer
      // half-close, which the guest reads as end of stream.
      if (event.data === "open") {
        entry.connected = true;
        exports.wtw_net_connected(handle, 0, 0);
        noteNetEvent();
      } else if (event.data === "eof") {
        entry.eof = true;
        exports.wtw_net_closed(handle);
        noteNetEvent();
      }
      return;
    }
    deliverData(handle, new Uint8Array(event.data));
  };
  // The close event always follows an error and carries why, so the guest's
  // errno is decided there rather than twice.
  socket.onerror = () => {};
  socket.onclose = (event) => {
    if (sockets.get(handle) !== entry) return; // the guest already closed it
    sockets.delete(handle);
    if (event.code === CLOSE_REFUSED || event.code === CLOSE_BAD_REQUEST) {
      // The relay refused the destination by policy, so nothing was dialled:
      // unreachable, not refused by a peer.
      deliverError(handle, ENETUNREACH);
    } else if (event.code === CLOSE_UNREACHABLE) {
      deliverError(handle, ECONNREFUSED);
    } else if (!entry.connected) {
      // Never opened: no gateway listening, or the upgrade was rejected.
      deliverError(handle, ENETUNREACH);
    } else if (!entry.eof) {
      exports.wtw_net_closed(handle);
      noteNetEvent();
    }
  };
}

function openUdp(handle) {
  const socket = new WebSocket(`${gateway}/udp`);
  socket.binaryType = "arraybuffer";
  const entry = { socket, queue: [], open: false };
  sockets.set(handle, entry);
  socket.onopen = () => {
    entry.open = true;
    for (const pending of entry.queue) socket.send(pending);
    entry.queue.length = 0;
  };
  socket.onmessage = (event) => {
    if (typeof event.data !== "string") deliverDatagram(handle, new Uint8Array(event.data));
  };
  socket.onerror = () => {};
  socket.onclose = () => {
    if (sockets.get(handle) !== entry) return; // the guest already closed it
    sockets.delete(handle);
    deliverError(handle, entry.open ? ECONNRESET : ENETUNREACH);
  };
}

const sendOn = (handle, payload) => {
  const entry = sockets.get(handle);
  if (!entry) return;
  if (entry.open) entry.socket.send(payload);
  else entry.queue.push(payload);
};

/// Decodes and carries out one batch of broker commands. The encoding is
/// defined by linux_compat::net::HostBroker::take_commands.
function performNetwork(stream) {
  const view = new DataView(stream.buffer, stream.byteOffset, stream.byteLength);
  let i = 0;
  const u32 = () => {
    const value = view.getUint32(i, true);
    i += 4;
    return value;
  };
  const dest = () => {
    const ip = `${stream[i]}.${stream[i + 1]}.${stream[i + 2]}.${stream[i + 3]}`;
    const port = view.getUint16(i + 4, false);
    i += 6;
    return { ip, port };
  };
  const payload = () => {
    const len = u32();
    const bytes = stream.slice(i, i + len);
    i += len;
    return bytes;
  };
  while (i < stream.length) {
    const op = stream[i];
    i += 1;
    const handle = u32();
    switch (op) {
      case 1: {
        const { ip, port } = dest();
        if (gateway) openTcp(handle, ip, port);
        else deliverError(handle, ENETUNREACH);
        break;
      }
      case 2:
        sendOn(handle, payload());
        break;
      case 3:
        sockets.get(handle)?.socket.send("shutdown");
        break;
      case 4:
        if (gateway) openUdp(handle);
        else deliverError(handle, ENETUNREACH);
        break;
      case 5: {
        const { ip, port } = dest();
        const bytes = payload();
        const frame = new Uint8Array(6 + bytes.length);
        for (const [slot, part] of ip.split(".").entries()) frame[slot] = Number(part);
        frame[4] = (port >> 8) & 0xff;
        frame[5] = port & 0xff;
        frame.set(bytes, 6);
        sendOn(handle, frame);
        break;
      }
      case 6: {
        sockets.get(handle)?.socket.close();
        sockets.delete(handle);
        break;
      }
      default:
        throw new Error(`unknown broker opcode ${op}`);
    }
  }
}

/// Runs one turn of the host's side of the network: carry out what the guest
/// asked for, then wait for a reply. Returns once something was delivered or
/// the guest's own timer is due, and tells the machine which happened.
async function pumpNetwork() {
  performNetwork(netCommands());
  // The export is a u32; JS reads a wasm i32, so 0xffffffff arrives as -1.
  const budget = exports.wtw_net_budget_ms() >>> 0;
  const waitMs = Math.min(
    budget === NET_BUDGET_UNBOUNDED ? NET_WAIT_CAP_MS : budget,
    NET_WAIT_CAP_MS,
  );
  const before = netEvents;
  if (waitMs > 0) {
    // Sleep until a socket delivers something or the guest's own timer is
    // due. Spinning here would burn the worker for nothing.
    await new Promise((resolve) => {
      netWake = resolve;
      setTimeout(() => {
        if (netWake === resolve) {
          netWake = null;
          resolve();
        }
      }, waitMs);
    });
  }
  // Nothing arrived: let the guest's clock advance so its timeouts can fire.
  if (netEvents === before) exports.wtw_net_expire();
}

// ---------------------------------------------------------------- terminal

// An interactive process is not a single call: it runs, blocks for a
// keystroke, and continues. `running` says a pump is in flight, `waiting`
// says the guest is parked on the terminal until input or a resize arrives.
let running = false;
let waiting = false;

async function pump() {
  if (running) return;
  running = true;
  try {
    for (;;) {
      const status = exports.wtw_run(FUEL);
      drain();
      if (status === STATUS_AWAITING_INPUT) {
        waiting = true;
        postMessage({ type: "waiting" });
        return;
      }
      if (status === STATUS_AWAITING_NETWORK) {
        await pumpNetwork();
        continue;
      }
      if (status === STATUS_AWAITING_PAGEIN) {
        await satisfyChunkRequest("page-in");
        continue;
      }
      if (status === STATUS_OUT_OF_CPU) {
        postMessage({
          type: "status",
          text: "the workload has spent its instruction allowance",
        });
      }
      if (status !== STATUS_RUNNING) {
        finish(status);
        return;
      }
      await yieldToQueue();
    }
  } finally {
    running = false;
  }
}

/// Grants the guest a network, routed through the host's relay. Called before
/// the process starts; without it `socket(2)` fails and nothing can connect.
function enableNetwork(url) {
  if (exports.wtw_net_enable() !== 0) {
    throw new Error(`network enable failed: ${lastError()}`);
  }
  gateway = url.replace(/\/$/, "");
  postMessage({ type: "status", text: `network enabled via ${gateway}` });
}

/// Records an architectural trace of one image, run to completion. The text
/// is the same format the native recorder writes, so a browser recording can
/// be diffed against the reference in the repository.
async function recordTrace({ path, url, argv, envp, sampleEvery }) {
  let image = null;
  if (url) {
    image = new Uint8Array(await (await fetch(url)).arrayBuffer());
    if (exports.wtw_add_file(...put(path), ...put(image)) !== 0) {
      throw new Error(`add_file ${path}: ${lastError()}`);
    }
  }
  await load(path, argv, envp);
  if (exports.wtw_trace_start(sampleEvery) !== 0) {
    throw new Error(`trace start: ${lastError()}`);
  }
  // Manifest-backed traces identify themselves from the manifest root and
  // precomputed legacy FNV. Only eager traces need their bytes named here.
  if (image && exports.wtw_trace_image(...put(path), ...put(image)) !== 0) {
    throw new Error(`trace image: ${lastError()}`);
  }
  let status;
  for (;;) {
    status = exports.wtw_run_traced(FUEL);
    drain();
    if (status === STATUS_RUNNING) continue;
    if (status === STATUS_AWAITING_PAGEIN) {
      await satisfyChunkRequest("traced page-in");
      continue;
    }
    break;
  }
  const len = exports.wtw_trace_take();
  if (len < 0) throw new Error(`trace take: ${lastError()}`);
  const trace = text(exports.wtw_trace_ptr(), len);
  postMessage({
    type: "trace",
    status,
    trace,
    exitCode: exports.wtw_exit_code(),
    icount: exports.wtw_icount_hi() * 2 ** 32 + exports.wtw_icount_lo(),
    pageIns: exports.wtw_page_in_count(),
    filesKiB: exports.wtw_footprint_kib(2),
    jitBlocks: Number(exports.wtw_jit_block_dispatch_count()),
    jitRegions: Number(exports.wtw_jit_region_dispatch_count()),
  });
}

async function spawn(path, argv, envp, rows, cols) {
  await load(path, argv, envp);
  if (exports.wtw_pty_install(rows, cols) !== 0) {
    throw new Error(`terminal setup failed: ${lastError()}`);
  }
  waiting = false;
  pump();
}

/// Delivers host keystrokes and restarts the pump if the guest was parked.
function input(data) {
  if (exports.wtw_pty_input(...stage(data)) !== 0) {
    throw new Error(`terminal input failed: ${lastError()}`);
  }
  if (waiting) {
    waiting = false;
    pump();
  }
}

/// Reports a new window size. SIGWINCH can wake a parked guest, so a resize
/// resumes the pump too — that is how a full-screen program repaints without
/// the user typing.
function resize(rows, cols) {
  if (exports.wtw_pty_resize(rows, cols) !== 0) {
    throw new Error(`terminal resize failed: ${lastError()}`);
  }
  if (waiting) {
    waiting = false;
    pump();
  }
}

self.onmessage = async (event) => {
  const msg = event.data;
  try {
    if (msg.type === "boot") await boot(msg.files, msg.links, msg.jitAfter ?? null);
    if (msg.type === "image") await loadImage(msg);
    if (msg.type === "lazyImage") await installLazyImage(msg);
    if (msg.type === "trace") await recordTrace(msg);
    if (msg.type === "network") enableNetwork(msg.gateway);
    if (msg.type === "exec") await exec(msg.path, msg.argv, msg.envp);
    if (msg.type === "spawn") {
      await spawn(msg.path, msg.argv, msg.envp, msg.rows, msg.cols);
    }
    if (msg.type === "input") input(msg.data);
    if (msg.type === "resize") resize(msg.rows, msg.cols);
    // A large agent wants more physical memory than the default: Codex
    // reserves about 246 MiB of segments before it runs a line.
    if (msg.type === "guestmem") {
      if (exports.wtw_set_guest_memory_mb(msg.mib) !== 0) {
        throw new Error(`guest memory cap: ${lastError()}`);
      }
      postMessage({ type: "status", text: `guest memory cap ${msg.mib} MiB` });
    }
    if (msg.type === "footprint") reportFootprint();
    if (msg.type === "persistFaultProbe") {
      // Does an interrupted persist leave the committed snapshot partial?
      // Persist a good snapshot, then persist again with the very next
      // createWritable write made to reject — the shape of a worker killed
      // mid-write — and read the committed file back. `intact` says whether
      // the committed snapshot is still the good one.
      await persist();
      const root = await navigator.storage.getDirectory();
      const read = async () =>
        new Uint8Array(
          await (await (await root.getFileHandle(SNAPSHOT_FILE)).getFile()).arrayBuffer(),
        );
      const before = await read();
      const proto = self.FileSystemWritableFileStream.prototype;
      const realWrite = proto.write;
      let armed = true;
      proto.write = function (...args) {
        if (armed) {
          armed = false;
          return Promise.reject(new Error("injected write fault"));
        }
        return realWrite.apply(this, args);
      };
      let threw = false;
      try {
        exports.wtw_file_create(...put("/home/probe.txt"), 4, 0o644);
        exports.wtw_file_append(...put("/home/probe.txt"), ...put("data"));
        await persist();
      } catch {
        threw = true;
      } finally {
        proto.write = realWrite;
      }
      let after;
      try {
        after = await read();
      } catch {
        after = new Uint8Array(0); // the committed file is gone entirely
      }
      const intact =
        before.length > 0 &&
        before.length === after.length &&
        before.every((b, i) => b === after[i]);
      postMessage({ type: "persistProbe", intact, threw, len: before.length });
    }
    if (msg.type === "budget") {
      if (exports.wtw_set_memory_budget_kib(Math.round((msg.mib ?? 0) * 1024)) !== 0) {
        throw new Error(`budget: ${lastError()}`);
      }
      reportFootprint();
    }
    if (msg.type === "storageBudget") {
      if (exports.wtw_set_storage_budget_kib(Math.round((msg.mib ?? 0) * 1024)) !== 0) {
        throw new Error(`storage budget: ${lastError()}`);
      }
      reportFootprint();
    }
    if (msg.type === "networkBudget") {
      if (exports.wtw_set_network_budget_kib(Math.round((msg.mib ?? 0) * 1024)) !== 0) {
        throw new Error(`network budget: ${lastError()}`);
      }
      reportFootprint();
    }
    // A workload that computes in a loop and issues no syscalls is outside
    // every other mechanism here: nothing to interrupt, nothing to refuse.
    // Its allowance is the only thing that stops it.
    if (msg.type === "cpuBudget") {
      if (exports.wtw_set_cpu_budget_kinsn(Math.round(msg.kinsn ?? 0)) !== 0) {
        throw new Error(`cpu budget: ${lastError()}`);
      }
      postMessage({
        type: "status",
        text: msg.kinsn
          ? `cpu budget ${(msg.kinsn / 1000).toFixed(0)}M instructions`
          : "cpu budget cleared",
      });
    }
    // The page noticed it was away — `document.visibilitychange` and a wall
    // clock are how a host knows. Without telling the guest, it comes back
    // believing no time passed.
    if (msg.type === "skipTime") {
      if (exports.wtw_skip_time_ms(Math.max(0, Math.round(msg.ms ?? 0))) !== 0) {
        throw new Error(`skip time: ${lastError()}`);
      }
      postMessage({ type: "status", text: `${Math.round((msg.ms ?? 0) / 1000)}s of real time skipped` });
    }
    if (msg.type === "eventLogBudget") {
      if (exports.wtw_set_event_log_budget(Math.round(msg.events ?? 0)) !== 0) {
        throw new Error(`event log budget: ${lastError()}`);
      }
    }
    if (msg.type === "secrets") applySecrets(msg.secrets);
    if (msg.type === "persist") await persist();
    if (msg.type === "forget") {
      if (!storageReady) throw new Error("browser storage is unavailable here");
      await opfsDelete(SNAPSHOT_FILE);
      await forgetImages();
      postMessage({ type: "status", text: "saved filesystem deleted" });
    }
  } catch (e) {
    postMessage({ type: "error", text: String(e) });
  }
};
