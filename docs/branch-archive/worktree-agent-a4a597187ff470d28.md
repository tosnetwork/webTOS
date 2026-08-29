# `worktree-agent-a4a597187ff470d28`

- Tip: `c11e89afc6c3126307fdd4aec847cd6a97222997`
- Merge base with archival `main`: `eae771c590da1ec2fd04cbe6f6fc7a9e4d3ace7f`
- Relationship at archival: 47 commits behind `main`, one commit ahead
- Worktree-only file: `feasibility/jit_coverage_dynamic.md`

The worktree-only measurement note is preserved as
[JIT_COVERAGE_DYNAMIC_RUNTIMES.md](../JIT_COVERAGE_DYNAMIC_RUNTIMES.md).
The unique commit extended `jit_coverage` with `GUEST_MOUNT`,
`GUEST_COPY`, `GUEST_EXE`, `GUEST_ENV`, and `GUEST_MEM_MB`, plus a host
wall-clock base, so dynamically linked glibc and Node workloads could be
profiled. It was not merged into `main`; the complete commit and patch are
retained below so deleting the branch does not discard its implementation.

```diff
commit c11e89afc6c3126307fdd4aec847cd6a97222997
Author:     gtosnetwork-dotcom <gtosnetwork@gmail.com>
AuthorDate: Fri Aug 28 21:34:01 2026 +0900
Commit:     gtosnetwork-dotcom <gtosnetwork@gmail.com>
CommitDate: Fri Aug 28 21:34:01 2026 +0900

    jit_coverage: mount dynamic runtimes to profile glibc/Node

    Add GUEST_MOUNT / GUEST_COPY / GUEST_EXE / GUEST_ENV / GUEST_MEM_MB
    support (mirrored from run_guest) so the coverage histogram can run a
    dynamic glibc binary or Node, whose loader and libraries must be
    delivered as files. Static ELF and GUEST_ARGV0 behaviour are unchanged.

    Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
    Claude-Session: https://claude.ai/code/session_01Es8A2ZZXpVVomTHKCkbxU9

diff --git a/crates/linux-compat/examples/jit_coverage.rs b/crates/linux-compat/examples/jit_coverage.rs
index fa9a6a4..30f9338 100644
--- a/crates/linux-compat/examples/jit_coverage.rs
+++ b/crates/linux-compat/examples/jit_coverage.rs
@@ -7,6 +7,16 @@
 //! JIT is worth more coverage, and where to spend it.
 //!
 //! Usage: jit_coverage <elf> [args...]
+//!
+//! Static ELFs need nothing else. A dynamic glibc binary (or Node) needs its
+//! loader and libraries delivered as files; mirror run_guest and import them:
+//!
+//!   GUEST_MOUNT="host_dir:guest_prefix,..."  import host trees (glibc, Node)
+//!   GUEST_COPY="host_file:guest_path,..."    copy individual host files
+//!   GUEST_EXE=/guest/path                    where to place and load the guest
+//!   GUEST_ENV="K=V,K=V"                       extra environment for the guest
+//!   GUEST_MEM_MB=N                            raise the physical-memory cap
+//!   GUEST_ARGV0=name                          argv[0] the guest sees (multicall)

 use linux_compat::Machine;
 use x64_engine::{CpuExit, EngineConfig};
@@ -21,18 +31,68 @@ fn main() {
         .join("../../third_party/ghidra-x86/languages/x86.ldefs");
     let mut machine = Machine::from_ldef(&ldef, &EngineConfig::default()).expect("build machine");

+    // GUEST_MEM_MB=N raises the guest's physical-memory cap (default 1 GiB).
+    // A dynamic runtime (loader + shared libraries, plus copy-on-write pages of
+    // a fork-heavy program like Node) can exceed the default.
+    if let Ok(mb) = std::env::var("GUEST_MEM_MB") {
+        let mb: usize = mb.parse().expect("GUEST_MEM_MB must be a number");
+        let pages = mb.saturating_mul(256); // 4 KiB pages
+        assert!(
+            machine.vm_mut().cpu.mem.set_capacity(pages),
+            "cannot shrink below allocated pages"
+        );
+    }
+
+    // A dynamic glibc program (and Node) reads the clock; give it the host's
+    // real wall clock rather than the fixed reproducible default so libc's
+    // start-up does not trip over an implausible time.
+    let epoch = std::time::SystemTime::now()
+        .duration_since(std::time::UNIX_EPOCH)
+        .expect("host clock before unix epoch")
+        .as_secs() as i64;
+    machine.set_wall_clock_base(epoch);
+
+    // GUEST_MOUNT="host_dir:guest_prefix,host_dir:guest_prefix" imports host
+    // trees (the glibc runtime, a Node install) into the guest. This is what a
+    // dynamic binary needs — its loader and libraries delivered as files.
+    if let Ok(mounts) = std::env::var("GUEST_MOUNT") {
+        for entry in mounts.split(',').filter(|e| !e.is_empty()) {
+            let (host, guest) = entry.split_once(':').expect("GUEST_MOUNT host:guest");
+            machine
+                .add_host_tree(std::path::Path::new(host), guest)
+                .unwrap_or_else(|e| panic!("mount {host} -> {guest}: {e}"));
+        }
+    }
+    // GUEST_COPY="host_file:guest_path,..." copies individual host files.
+    if let Ok(copies) = std::env::var("GUEST_COPY") {
+        for entry in copies.split(',').filter(|e| !e.is_empty()) {
+            let (host, guest) = entry.split_once(':').expect("GUEST_COPY host:guest");
+            let bytes = std::fs::read(host).unwrap_or_else(|e| panic!("read {host}: {e}"));
+            machine
+                .add_file(guest.as_bytes(), bytes, 0o755)
+                .expect("copy");
+        }
+    }
+
+    // GUEST_EXE controls where the binary is placed inside the guest and which
+    // path is loaded. Defaults to /bin/guest, preserving the static behaviour.
+    let guest_exe = std::env::var("GUEST_EXE").unwrap_or_else(|_| "/bin/guest".to_string());
     let image = std::fs::read(&args[0]).expect("read elf");
     machine
-        .add_file(b"/bin/guest", image, 0o755)
+        .add_file(guest_exe.as_bytes(), image, 0o755)
         .expect("add guest");
-    // argv[0] the guest sees. Defaults to its path; GUEST_ARGV0 overrides it,
-    // which a multicall binary like BusyBox needs (its applet is chosen by
-    // argv[0]'s basename, so run it as `GUEST_ARGV0=busybox ... sha256sum f`).
-    let argv0 = std::env::var("GUEST_ARGV0").unwrap_or_else(|_| "/bin/guest".to_string());
+    // argv[0] the guest sees. Defaults to the guest exe path; GUEST_ARGV0
+    // overrides it, which a multicall binary like BusyBox needs (its applet is
+    // chosen by argv[0]'s basename, so run it as `GUEST_ARGV0=busybox ...`).
+    let argv0 = std::env::var("GUEST_ARGV0").unwrap_or_else(|_| guest_exe.clone());
     let mut argv: Vec<Vec<u8>> = vec![argv0.into_bytes()];
     argv.extend(args[1..].iter().map(|a| a.as_bytes().to_vec()));
-    machine.set_args(argv, vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()]);
-    machine.load(b"/bin/guest").expect("load");
+    let mut envp: Vec<Vec<u8>> = vec![b"PATH=/bin".to_vec(), b"HOME=/root".to_vec()];
+    if let Ok(extra) = std::env::var("GUEST_ENV") {
+        envp.extend(extra.split(',').map(|kv| kv.as_bytes().to_vec()));
+    }
+    machine.set_args(argv, envp);
+    machine.load(guest_exe.as_bytes()).expect("load");

     machine.profile_blocks(true);
     machine.vm_mut().icount_limit = 50_000_000_000;
```
