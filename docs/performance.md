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

The browser harness also runs a control: `crates/bench-control`, a few hundred
bytes containing one hot loop. The reason is in the next section.

## Measured, 2026-08-27

Apple M-series laptop; `crates` built `--release` (wasm32 pinned to
`opt-level = 2`). Instruction counts are identical everywhere, which is the
determinism gate doing its job — only the time differs.

**Read the ratios, not the absolutes.** The machine was not quiet (other
applications, load average 6–9), and that moves the absolute times by about
3x between runs. Two runs, hours apart:

| | Machine build | md5sum 4 MiB | Sustained | Control | Ceiling |
|---|---|---|---|---|---|
| Native, quieter | 150 ms | 3.10 s | 21.3 M inst/s | — | n/a |
| Chromium, quieter | 124 ms | 5.19 s | 10.9 M inst/s | — | 3892 MiB |
| WebKit, quieter | 129 ms | 4.70 s | 11.9 M inst/s | — | 3892 MiB |
| Firefox, quieter | 1048 ms | 39.30 s | 1.4 M inst/s | — | 3892 MiB |
| Native, loaded | 120 ms | 4.31 s | 15.4 M inst/s | — | n/a |
| Chromium, loaded | 303 ms | 14.26 s | 3.5 M inst/s | 219 M iter/s | 3892 MiB |
| WebKit, loaded | 193 ms | 6.96 s | 8.3 M inst/s | 338 M iter/s | 3892 MiB |
| Firefox, loaded | 1573 ms | 55.76 s | 1.2 M inst/s | 46 M iter/s | 3892 MiB |

"Machine build" is compiling the embedded SLEIGH specification, which every
session pays once before the first instruction runs. "Control" is
`crates/bench-control`, and only the second run had it.

What survives both runs: the ordering (WebKit ≥ Chromium ≫ Firefox), the
browser landing within a small factor of native on the fast engines, and an
identical 3892 MiB ceiling. Run the harnesses on the machine you care about
rather than trusting the numbers here.

### Half of native — and one engine's column is not about webTOS at all

Chromium and WebKit run the interpreter at roughly half native throughput.
That is a far smaller gap than the architecture suggests, and it means the
browser is not the reason a workload feels slow: the interpreter is.

Firefox measures at about an eighth of the other two. The tempting explanation
is the interpreter's shape — `icicle_cpu::exec::interpreter::interpret` is a
single 61.8 KiB function, 4.7% of the whole code section and three times the
next largest, which is exactly what an optimizing compiler might decline to
handle. That explanation is wrong, and three measurements say so:

- Forcing Chromium to its baseline tier (`--js-flags=--liftoff-only`) costs
  2.7x: 10.1 to 3.8 M inst/s, measured back to back. So tier matters, and a
  declined function would look roughly like that.
- Turning Firefox's optimizing tier *off* changes nothing (1.3 to 1.6 M inst/s,
  within noise), and turning its baseline tier off leaves "no WebAssembly
  compiler available". Its optimizing tier is contributing nothing here.
- The control module settles it. At a few hundred bytes, no size heuristic can
  reach it, and the spread is there anyway: 219, 338 and 46 M iterations per
  second for Chromium, WebKit and Firefox, on identical work with identical
  results.

The control also points the other way from the hypothesis. If the 61.8 KiB
function were being declined, webTOS would look *worse* than the control in
Firefox. It looks better: Firefox runs the control at 0.21x Chromium and the
interpreter at 0.34x. Whatever is slow, it is slower on a tiny loop than on
ours.

So the Firefox column measures the browser build the test harness downloads,
which compiles wasm with its baseline compiler only. It is not a statement
about Firefox as shipped, and it is not a webTOS problem to fix. The control
stays in the harness so this does not have to be rediscovered.

What survives from the scare is a real risk, just not a demonstrated one: a
60 KB function is a large thing to hand an optimizing compiler, and Chromium's
own baseline-versus-optimized gap shows what it would cost if an engine ever
did decline it. Splitting the cold half of the interpreter — the float and
80-bit paths, about a third of the match arms — would remove the risk cheaply.

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
pipeline retires 124k instructions and takes well over a second. Almost none of that
time is spent executing guest code — it is spent lifting each new image's
basic blocks, which no instruction count shows. Process startup is therefore a
translation problem, not an execution one, and caching lifted blocks across
`execve` of the same image would pay for itself long before a faster
interpreter loop would.

## What this says about milestone 8

In priority order, on the evidence above:

1. **Attack translation cost, not just execution.** Startup and short-lived
   processes are dominated by lifting. Keeping lifted blocks across processes
   that share an image is the obvious first move.
2. **Then hot-block translation.** The interpreter is the floor for
   long-running compute: an agent's 20-second command is 200-odd million
   instructions, and no amount of host tuning turns that into 2 seconds.
3. **Split the interpreter's cold half.** Not urgent — no engine has been shown
   to decline the 61.8 KiB function — but the cost if one did is known, and the
   fix is mechanical.
4. **Budget memory as a whole.** Guest RAM, image bytes, and block cache share
   one 4 GiB address space; quotas need to account for all three together.

Not on the list: chasing the Firefox column. It measures a baseline-only
browser build, and the control in the harness is what proves it.

## Keeping the numbers honest

Both harnesses print rather than assert. A benchmark that fails because a
laptop was busy teaches nothing — and this laptop was busy, which is exactly
why the table above carries two runs instead of one tidy set of figures. A
threshold picked from one machine becomes a lie on another. Re-run them when
the interpreter changes, record the conditions, and keep the control column:
it is what turns "one engine is slow" into a statement about which engine.
