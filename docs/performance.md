# Performance and memory: what is measured

Milestone 8 is where the interpreter becomes a supportable runtime. Deciding
what to optimize needs numbers rather than impressions, so this records what
the current build actually costs and what a browser tab actually grants.

Two harnesses produce these figures, running the same guest workloads with the
same inputs so the results are comparable:

```bash
# native reference
cargo test -p linux-compat --release --test bench -- --ignored --nocapture

# per browser engine
node web/bench.mjs
```

Both hash a file with BusyBox `md5sum` at two sizes and report the difference
between them. That subtraction is the point: each run pays once to start a
process and once to lift the blocks it touches, and those fixed costs cancel,
leaving what the interpreter sustains once warm — the number that decides how
an interactive session feels.

## Measured, 2026-08-27

Apple M-series laptop, otherwise idle; `crates` built `--release` (wasm32
pinned to `opt-level = 2`). Single runs, so treat the times as good to about
20% — a second run on a busy machine moved the native figure from 21.3 to
19.6 M inst/s. The ratios between rows are what matters, and those are stable.
Instruction counts are identical everywhere, which is the determinism gate
doing its job: only the time differs.

| Where | Machine build | md5sum 4 MiB | Sustained | Linear-memory ceiling |
|-------|---------------|--------------|-----------|-----------------------|
| Native | 150 ms | 3.10 s | 21.3 M inst/s | n/a |
| Chromium | 124 ms | 5.19 s | 10.9 M inst/s | 3892 MiB |
| WebKit | 129 ms | 4.70 s | 11.9 M inst/s | 3892 MiB |
| Firefox | 1048 ms | 39.30 s | 1.4 M inst/s | 3892 MiB |

"Machine build" is compiling the embedded SLEIGH specification, which every
session pays once before the first instruction runs.

### The browser costs about half of native — except in one engine

Chromium and WebKit run the interpreter at roughly half native throughput.
That is a far smaller gap than the architecture suggests, and it means the
browser is not the reason a workload feels slow: the interpreter is.

Firefox is the exception, at about an eighth of the other two engines and a
fifteenth of native. The ratio is the same for compiling the SLEIGH
specification (1048 ms against ~125 ms) as for executing guest instructions,
so this is not a guest-code path — it is how that engine compiles this
module. It is worth an investigation of its own before any interpreter work,
because a change that wins 20% everywhere is worth less than understanding an
8× difference between engines.

### The 4 GiB ceiling is real but not the near-term limit

All three engines grew the module's linear memory to 3892 MiB, which is
effectively the whole wasm32 address space. So the ceiling is not "browsers
give you a few hundred megabytes" — it is the architectural 4 GiB, and the
constraint that matters is what has to fit inside it *together*: the guest's
physical pages, the guest filesystem holding the image, the translated-block
cache, and the module's own heap.

For scale, a BusyBox shell touches 1 MiB of guest physical memory against the
1 GiB default cap, and hashing 4 MiB leaves the module at a 52 MiB heap. The
agent images are what press on this: a 52 MB image is 52 MB in the filesystem
plus its mapped segments once it runs. A workload that natively wants a 4 GiB
guest does not fit beside everything else, and `wtw_set_guest_memory_mb` exists
so a host can say what its budget is and have the guest fail an allocation
cleanly rather than have the module die when the browser refuses to grow.

### Instruction counts do not measure everything

`busybox true` retires 2,713 instructions and takes 20 ms; a five-stage shell
pipeline retires 124k instructions and takes a second. Almost none of that
time is spent executing guest code — it is spent lifting each new image's
basic blocks, which no instruction count shows. Process startup is therefore a
translation problem, not an execution one, and caching lifted blocks across
`execve` of the same image would pay for itself long before a faster
interpreter loop would.

## What this says about milestone 8

In priority order, on the evidence above:

1. **Understand the Firefox gap.** An 8× spread between engines on identical
   bytecode is a defect somewhere, and fixing it is worth more than a uniform
   speedup.
2. **Attack translation cost, not just execution.** Startup and short-lived
   processes are dominated by lifting. Keeping lifted blocks across processes
   that share an image is the obvious first move.
3. **Then hot-block translation.** The interpreter is the floor for
   long-running compute: an agent's 20-second command is 200-odd million
   instructions, and no amount of host tuning turns that into 2 seconds.
4. **Budget memory as a whole.** Guest RAM, image bytes, and block cache share
   one 4 GiB address space; quotas need to account for all three together.

## Keeping the numbers honest

Both harnesses print rather than assert. A benchmark that fails because a
laptop was busy teaches nothing, and a threshold picked from one machine
becomes a lie on another. Re-run them when the interpreter changes and update
the table above with the date and the machine.
