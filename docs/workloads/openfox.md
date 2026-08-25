# Workload profile: OpenFox

**Status: all milestone-6 workload gates pass natively — version, help,
configuration persistence, the scripted network agent task, secret
injection, crash bundles, and a compressed soak.**

OpenFox is the first real agent workload (roadmap milestone 6): a static Go
binary (~97 MB with embedded assets) exercising the whole Go runtime on the
webTOS Linux layer.

## Fixture

Built by [`tools/build_openfox_fixture.sh`](../../tools/build_openfox_fixture.sh)
from a local OpenFox checkout (`OPENFOX_SRC`, default `~/openfox`):

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags goolm,stdjson ./cmd/openfox
```

The source commit is recorded next to the binary (`test_data/openfox.commit`).
Static + pure-Go olm means the guest needs no shared libraries.

## What the Go runtime demanded (all implemented)

- **Timed futex waits** returning `-ETIMEDOUT` (the scheduler patches the
  return value when the deadline fires without a wake; restart semantics
  cannot express timeouts — re-execution would re-arm them forever).
- The same fix for **timed `epoll_wait`/`poll`/`select`**: timed waits park
  once and return 0 on wake; only infinite waits use restart semantics.
- **`nanosleep` as a scheduling point**: the sleeper parks until its
  deadline (Go's sysmon micro-sleeps in a loop; returning immediately
  starved every other thread).
- **Per-thread-group address spaces**: an `mmap` by any thread is visible
  to its siblings (maps swap only on cross-group switches). This replaces
  the per-task map clone inherited from upstream, which lost post-clone
  mappings.
- **Signal dispositions**: default-ignore signals and signals with a
  registered handler are dropped, not fatal (Go's SIGURG preemption).
- `sched_getaffinity` (one-CPU mask), `prctl(PR_SET_NAME)`, and
  best-effort debug info (Go's compressed DWARF no longer fails the load).

## Gates (crates/linux-compat/tests/openfox.rs)

- `openfox version` exits 0 and reports the Go toolchain.
- `openfox --help` exits 0 and lists subcommands.
- `openfox status` runs on a clean profile (reports missing config), and
  after seeding `~/.openfox/config.json` + workspace, a filesystem
  snapshot restored into a brand-new machine still shows both present —
  the reload-persistence semantics of the milestone gate.
- **Scripted agent task**: a test-owned OpenAI-compatible mock behind the
  broker scripts a two-turn exchange — the model requests the `read_file`
  tool, OpenFox actually reads `NOTES.md` from the mounted workspace, the
  file content travels back over the network as the tool result, and the
  final answer reaches the terminal. Asserted on both sides (guest output
  and the mock's recorded request bodies). The mock answers plain JSON or
  SSE depending on the request's `stream` flag.

Each invocation retires ~60 M instructions (a few seconds native).

## Secrets, crash bundles, and the soak

- **Secret injection**: `Machine::set_secret` registers a value; `${name}`
  placeholders in guest files expand to it in memory (`expand_secrets`),
  and `export_fs` redacts the value back to `${name}` before serializing,
  so a filesystem snapshot never carries the key. The scripted-task gate
  asserts the snapshot holds the placeholder (not the key) while the key
  still reaches the model endpoint's Authorization header.
- **Crash bundles**: `Machine::crash_bundle` produces a compact,
  secret-free diagnostic for any non-clean exit — exit classification,
  faulting RIP, instruction count, executable path, and the tail of a
  bounded syscall trail. A clean exit produces none.
- **Soak**: `openfox_soak_is_bounded` (run with `--ignored`) executes 25
  OpenFox commands on one machine and asserts the filesystem does not grow
  without bound between rounds. This caught a real cross-process physical
  memory leak: `reset_virtual` dropped the mapping but never reclaimed
  physical pages, so a long-lived machine exhausted memory; `start_image`
  now fully clears physical memory when no other task is alive.

## Not yet covered

- Browser delivery of the 97 MB image (interpreter throughput makes this a
  post-M8 concern) and the full 60-minute interactive soak (the bounded
  25-round soak is the CI-friendly proxy).
