// Host side of the JIT.
//
// The engine emits a hot block as wasm and asks the host to compile it
// (`jit_compile`) and run it (`jit_call`). Compiled blocks import the engine's
// own memory as `env.regs` — no copy — and route their guest-memory callbacks
// back into the engine's `wtw_jit_*` shims. Providing these two imports is
// harmless where the JIT is never enabled: they are simply never called.
//
//   const jit = makeJitHost();
//   const { instance } = await WebAssembly.instantiate(bytes, { env: jit.imports });
//   jit.bind(instance.exports);
export function makeJitHost() {
  let e = null; // engine exports, set by bind() after instantiation
  const instances = []; // handle-1 -> compiled block instance
  const mem = () => new Uint8Array(e.memory.buffer);
  // The wtw_* boundary is u32-only, so a 64-bit guest address or value (a
  // BigInt at the block's i64 import) is split into low and high halves.
  const lo = (x) => Number(x & 0xffffffffn);
  const hi = (x) => Number((x >> 32n) & 0xffffffffn);

  const imports = {
    // Compile the block bytes at [ptr, ptr+len) and return a handle (>=1), or 0
    // if the browser declines — which the engine caches as a permanent bail.
    jit_compile(ptr, len) {
      let instance;
      try {
        const module = new WebAssembly.Module(mem().slice(ptr, ptr + len));
        instance = new WebAssembly.Instance(module, {
          env: {
            regs: e.memory,
            load: (addr, dstOff, size) => e.wtw_jit_load(lo(addr), hi(addr), dstOff, size),
            store: (addr, value, size) =>
              e.wtw_jit_store(lo(addr), hi(addr), lo(value), hi(value), size),
            fault: (index) => e.wtw_jit_fault(index),
            raise: (code, value, index) => e.wtw_jit_raise(code, lo(value), hi(value), index),
          },
        });
      } catch {
        return 0;
      }
      instances.push(instance);
      return instances.length;
    },

    // Run the compiled block against the register file at regsBase.
    jit_call(handle, regsBase) {
      instances[handle - 1].exports.run(regsBase);
    },
  };

  return {
    imports,
    bind(exports) {
      e = exports;
    },
  };
}
