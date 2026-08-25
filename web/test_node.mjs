// Node harness for the webtos-web wasm module: proves the Linux runtime
// works end-to-end outside a browser renderer. Runs a static hello ELF and,
// when the BusyBox fixture is present (tools/fetch_busybox.sh), a sequence
// of BusyBox applets over the persistent in-memory filesystem.
// Usage: node web/test_node.mjs [path/to/module.wasm]
import { readFile } from "node:fs/promises";

const wasmPath = process.argv[2] ?? new URL("./webtos_web.wasm", import.meta.url).pathname;

const { instance } = await WebAssembly.instantiate(await readFile(wasmPath), {});
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
  return { status, output, exitCode: e.wtw_exit_code() };
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

console.log("[node] PASS");
