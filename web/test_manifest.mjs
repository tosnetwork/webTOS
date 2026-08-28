// The host's half of a signed manifest.
//
// The module checks that delivered bytes match what the manifest names. It
// does not check the signature over the manifest, deliberately: a wrong
// signature verifier fails open — it accepts what it should not and nothing
// says so — and a hand-rolled unaudited one in a security boundary is worse
// than none. The platform ships an audited verifier. This is where it is
// used, and where the two halves are shown to compose: a manifest that does
// not verify is never installed, and one that does is enforced.
//
// Usage: node web/test_manifest.mjs [path/to/module.wasm]
import { readFile } from "node:fs/promises";
import { webcrypto, createHash } from "node:crypto";
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
const bytes = await readFile(wasmPath);

const { instance } = await instantiateEngine(bytes);
const e = instance.exports;
if (e.wtw_init() !== 0) throw new Error("init failed");

const mem = () => new Uint8Array(e.memory.buffer);
const text = (ptr, len) => new TextDecoder().decode(mem().slice(ptr, ptr + len));
const err = () => text(e.wtw_error_ptr(), e.wtw_error_len());
const put = (data) => {
  const b = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const ptr = e.wtw_alloc(b.length);
  mem().set(b, ptr);
  return [ptr, b.length];
};

let failures = 0;
const check = (label, ok, detail = "") => {
  if (ok) console.log(`[manifest] ok: ${label}${detail ? ` -> ${detail}` : ""}`);
  else {
    console.error(`[manifest] FAILED: ${label}${detail ? ` -> ${detail}` : ""}`);
    failures += 1;
  }
};

// ---------------------------------------------------------------- signing
// Ed25519 is what the platform verifies; the key is generated here because
// this test is about the mechanism, not about any particular publisher.
const keys = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
const sign = (data) =>
  webcrypto.subtle.sign({ name: "Ed25519" }, keys.privateKey, new TextEncoder().encode(data));
const verify = (data, signature) =>
  webcrypto.subtle.verify(
    { name: "Ed25519" },
    keys.publicKey,
    signature,
    new TextEncoder().encode(data),
  );

/// What a host does before installing: verify, then install. A manifest that
/// does not verify never reaches the module.
const install = async (manifest, signature) => {
  if (!(await verify(manifest, signature))) return "signature";
  return e.wtw_set_manifest(...put(manifest)) === 0 ? null : err();
};

// ---------------------------------------------------------------- images
const hello = await readFile(new URL("../test_data/hello_linux.elf", import.meta.url));
const sha = (b) => createHash("sha256").update(b).digest("hex");
const manifest = `${sha(hello)} ${hello.length} /bin/hello\n`;
const signature = await sign(manifest);

// A manifest whose signature does not check out is not installed, and the
// module is left with whatever it had — which is nothing.
const tampered = manifest.replace(/^./, (c) => (c === "a" ? "b" : "a"));
check(
  "a manifest that does not verify is not installed",
  (await install(tampered, signature)) === "signature" && e.wtw_manifest_len() === 0,
  `${e.wtw_manifest_len()} entries installed`,
);

// The real one verifies and installs.
check("a signed manifest installs", (await install(manifest, signature)) === null);
check("the module reports what it is committed to", e.wtw_manifest_len() === 1);

// And is then enforced: bytes that do not match are refused at delivery.
const altered = Uint8Array.from(hello);
altered[Math.floor(altered.length / 2)] ^= 1;
const refusedDelivery = e.wtw_add_file(...put("/bin/hello"), ...put(altered)) !== 0;
check("an image whose bytes changed is refused", refusedDelivery, refusedDelivery ? err() : "");

// An image nobody committed to is refused too: a manifest is a list of what
// may be delivered, and waving through what it omits is how one gets in.
const refusedExtra = e.wtw_add_file(...put("/bin/extra"), ...put(hello)) !== 0;
check("an image the manifest does not name is refused", refusedExtra, refusedExtra ? err() : "");

// The real image is delivered and runs.
check("the committed image is delivered", e.wtw_add_file(...put("/bin/hello"), ...put(hello)) === 0, err());
e.wtw_arg(...put("hello"));
check("the committed image loads", e.wtw_load(...put("/bin/hello")) === 0, err());
let status;
let output = "";
do {
  status = e.wtw_run(5_000_000);
  output += text(e.wtw_output_ptr(), e.wtw_output_len());
} while (status === 0);
check("the committed image runs", status === 1 && e.wtw_exit_code() === 0, JSON.stringify(output.slice(0, 40)));

// Clearing it restores the unchecked default, which is what a host with
// nothing to verify against gets.
check("clearing the manifest is possible", e.wtw_set_manifest(0, 0) === 0 && e.wtw_manifest_len() === 0);

if (failures > 0) {
  console.error(`[manifest] ${failures} failed`);
  process.exit(1);
}
console.log("[manifest] PASS");
