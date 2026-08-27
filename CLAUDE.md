# Working on webTOS

Read this before hunting for a binary or a machine. Everything here cost
someone an hour to find once.

`AGENTS.md` is a symlink to this file, so Codex and Claude Code read the same
thing.

## The two machines

Development happens on macOS (arm64). **Most of the test suite does not run
there** — every fixture built by the host `gcc` needs an x86-64 Linux
toolchain, and on macOS those cases skip and still report `ok`. 23 of them.

The x86-64 Linux host is where the suite is real:

```bash
ssh tomi@100.91.25.120        # repo at ~/webTOS
export PATH="$HOME/.cargo/bin:$PATH"   # non-interactive ssh has almost no PATH
```

A skip prints `SKIP:` naming the fixture, but `cargo test` swallows that for a
passing test — add `-- --nocapture` to see what a run actually covered. To
forbid skipping entirely:

```bash
cd crates && WEBTOS_REQUIRE_FIXTURES=1 cargo test --tests -p linux-compat -p x64-engine --release
```

The Linux host passes that way with no skips. macOS fails 26 cases under it.

## Where the real workloads live

All on the Linux host. None are in the repository — they are large, and
`test_data/` gitignores them.

| what | path | shape |
|---|---|---|
| Claude Code | `~/.local/share/claude/versions/2.1.247` | 239 MB, **Bun** 1.4.1, dynamic |
| Codex | `~/.codex/packages/standalone/current/bin/codex` | 256 MB, static-pie |
| Node | `~/.nvm/versions/node/v24.13.0/bin/node` | 121 MB, glibc, dynamic |
| OpenFox | built by `tools/build_openfox_fixture.sh` | 52 MB, static |

`~/.local/bin/claude` and `~/.local/bin/codex` are symlinks to the first two.
**They are not npm packages** — looking in `lib/node_modules` finds empty
directories and suggests they are not installed. They are.

A dynamically linked guest needs its loader and libraries delivered as *files*;
a browser has no host filesystem to mount. Node and Claude Code both want:

```
/lib64/ld-linux-x86-64.so.2
/lib/x86_64-linux-gnu/{libc,libm,libdl,libpthread,librt,libstdc++,libgcc_s}.so.*
```

## Running a guest binary

Natively, with the host's libraries mounted (fast to iterate, native only):

```bash
cd crates
GUEST_MOUNT="/lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu,/lib64:/lib64" \
GUEST_EXE=/bin/claude \
cargo run --release -p linux-compat --example run_guest -- <path-to-binary> --version
```

`SYSCALL_ERR_TRACE=1` prints every syscall that returned an error, with the
path for `openat`. `RUST_LOG=linux_compat=trace` prints all of them. On a
fault the runner prints the faulting page's permissions, which is what
separates "jumped into nothing" from "jumped into a page the loader left
non-executable".

In the browser's engine: build with `bash web/build.sh`, then drive
`web/webtos_web.wasm` from Node. `web/test_node.mjs` is the worked example.

## Conventions

- cargo runs from `crates/`, never the repository root.
- On macOS add `--target aarch64-apple-darwin`.
- Format only the files you edited (`rustfmt --edition 2021 --check <file>`).
  `cargo fmt --all` reformats vendored code and untouched crates.
- `cargo clippy -p linux-compat --lib -- -D warnings` must be clean.
- Browser gates: `node web/test_node.mjs`, then `node web/test_browsers.mjs`
  (Chromium, Firefox, WebKit; several minutes). `node web/test_messages.mjs`
  sweeps the exported `wtw_*` boundary with arguments a page made up; it
  needs a freshly built `web/webtos_web.wasm`, so run `bash web/build.sh`
  after changing anything under `crates/`.
- A change to what the CPU does moves `test_data/traces/*.trace`. That is the
  gate working. Regenerate deliberately:
  `cargo test -p linux-compat --release --test trace -- --ignored rewrite`,
  and check the diff is only what you meant to change.

## Instruments lie by staying silent

Four separate times in one session, a measurement returned nothing and the
nothing was read as an answer. Before trusting silence, prove the instrument
speaks:

- `std::env::var_os` **always returns None on wasm32**. Env-var-gated
  experiments never run there. Compile the code out instead.
- `clippy` invoked from `crates/` compiles a path dependency and emits **no
  lints for it**. Run it from `third_party/icicle` for those crates. Add a
  deliberately offending line to tell "clean" from "not looking".
- `scp a/x.rs host:/tmp/ && scp b/x.rs host:/tmp/` leaves one file. Two
  `elf.rs`, two `lib.rs` — name them apart and verify they landed.
- "No FAILED in the output" is not a pass. A build that never ran prints no
  failures either. Check the `test result:` lines.

- **`--release` cannot see wrapped arithmetic.** The syscall sweep found five
  defects, four of them wraps, and its first run under `--release` reported
  none of them. The workspace has a `relcheck` profile that turns overflow
  checks on, and nothing had ever used it:

  ```bash
  cd crates && cargo test --profile relcheck -p linux-compat --test syscall_sweep -- --nocapture
  ```

  It prints whether overflow checks are on, so a pass in the wrong profile
  says so out loud rather than reading as a clean sweep.

And a test that cannot fail is not evidence. Before believing a new one,
remove the thing it tests and watch it go red.
