//! Milestone-4 workload gates: processes, threads, pipes, and futexes over
//! the deterministic cooperative scheduler.
//!
//! C fixtures are compiled by the tests with the host `gcc` (static
//! binaries, so no guest libraries are needed); shell-level gates use the
//! pinned Alpine minirootfs (`tools/fetch_alpine_rootfs.sh`). Every test
//! skips with a message when its prerequisite is missing.

use std::path::{Path, PathBuf};
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
}

struct Run {
    exit: CpuExit,
    output: String,
    icount: u64,
}

fn compile_c(name: &str, source: &str, extra: &[&str]) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-m4-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join(format!("{name}.c"));
    let out = dir.join(name);
    std::fs::write(&src, source).expect("write source");
    let mut cmd = Command::new("gcc");
    cmd.arg("-O1")
        .arg("-static")
        .arg("-o")
        .arg(&out)
        .arg(&src)
        .args(extra);
    let built = matches!(cmd.status(), Ok(status) if status.success());
    linux_compat::testing::require(
        &format!("a compiler that targets Linux x86-64 for {name} ({cmd:?})"),
        built.then(|| std::fs::read(&out).expect("compiler output")),
    )
}

fn run_image(image: Vec<u8>, name: &str) -> Run {
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    let guest_path = format!("/bin/{name}");
    machine
        .add_file(guest_path.as_bytes(), image, 0o755)
        .expect("add fixture");
    machine.set_args(vec![name.as_bytes().to_vec()], vec![b"HOME=/root".to_vec()]);
    machine
        .load(guest_path.as_bytes())
        .expect("ELF load failed");
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Run {
        exit,
        output,
        icount: machine.icount(),
    }
}

fn expect_clean(run: &Run) {
    assert_eq!(
        run.exit,
        CpuExit::Halt { code: Some(0) },
        "guest did not exit cleanly; output: {:?}",
        run.output
    );
}

#[test]
fn fork_pipe_wait_roundtrip() {
    let source = r#"
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int p[2];
    if (pipe(p)) return 1;
    pid_t pid = fork();
    if (pid < 0) return 4;
    if (pid == 0) {
        close(p[1]);
        char buf[64];
        int n = read(p[0], buf, sizeof(buf) - 1);
        if (n <= 0) _exit(2);
        buf[n] = 0;
        printf("child got: %s\n", buf);
        fflush(stdout);
        _exit(42);
    }
    close(p[0]);
    const char *msg = "ping-from-parent";
    if (write(p[1], msg, strlen(msg)) != (long)strlen(msg)) return 5;
    close(p[1]);
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return 6;
    printf("parent: child exited %d\n", WEXITSTATUS(status));
    return WEXITSTATUS(status) == 42 ? 0 : 3;
}
"#;
    let Some(image) = compile_c("fork_pipe", source, &[]) else {
        return;
    };
    let run = run_image(image, "fork_pipe");
    expect_clean(&run);
    assert!(
        run.output.contains("child got: ping-from-parent"),
        "output: {:?}",
        run.output
    );
    assert!(
        run.output.contains("parent: child exited 42"),
        "output: {:?}",
        run.output
    );
}

/// A parent reading a child's stdout pipe to EOF must wake when the child
/// exits, even when the child is the last other runnable task. The exiting
/// process's descriptor table has to be released before the scheduler looks
/// for a runnable task, so the pipe's writer count drops to zero and the
/// parent's blocked read becomes ready in the same scheduling decision.
/// Otherwise the exiting child still holds its write end when readiness is
/// evaluated and the whole machine deadlocks (observed bringing up a real
/// Codex binary, which spawns short-lived probe subprocesses and reads their
/// output). The child here fails its `execve` and exits, producing no output.
#[test]
fn parent_reading_child_pipe_wakes_on_child_exit() {
    let source = r#"
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
int main(void) {
    int p[2];
    if (pipe(p)) return 1;
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) {
        dup2(p[1], 1);
        close(p[0]); close(p[1]);
        char *av[] = {"/bin/does-not-exist", 0};
        execve(av[0], av, 0);   /* fails: no such file */
        _exit(127);
    }
    close(p[1]);                /* parent keeps only the read end */
    char buf[128]; ssize_t n; int total = 0;
    while ((n = read(p[0], buf, sizeof buf)) > 0) total += n;
    int st = 0; waitpid(pid, &st, 0);
    printf("eof total=%d n=%zd child=%d\n", total, n, WEXITSTATUS(st));
    return n == 0 ? 0 : 3;
}
"#;
    let Some(image) = compile_c("pipe_eof_on_exit", source, &[]) else {
        return;
    };
    let run = run_image(image, "pipe_eof_on_exit");
    expect_clean(&run);
    assert!(
        run.output.contains("eof total=0 n=0 child=127"),
        "parent did not reach EOF after the child exited; output: {:?}",
        run.output
    );
}

#[test]
fn threads_futex_mutex_and_join() {
    let source = r#"
#include <pthread.h>
#include <stdio.h>
static long counter = 0;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static void *worker(void *arg) {
    (void)arg;
    for (int i = 0; i < 2000; i++) {
        pthread_mutex_lock(&lock);
        counter++;
        pthread_mutex_unlock(&lock);
        if (i % 500 == 0)
            sched_yield();
    }
    return (void *)123;
}
int main(void) {
    pthread_t a, b;
    if (pthread_create(&a, 0, worker, 0)) return 1;
    if (pthread_create(&b, 0, worker, 0)) return 2;
    void *ra = 0, *rb = 0;
    pthread_join(a, &ra);
    pthread_join(b, &rb);
    printf("counter=%ld ra=%ld rb=%ld\n", counter, (long)ra, (long)rb);
    return (counter == 4000 && (long)ra == 123 && (long)rb == 123) ? 0 : 3;
}
"#;
    let Some(image) = compile_c("threads", source, &["-pthread"]) else {
        return;
    };
    let run = run_image(image, "threads");
    expect_clean(&run);
    assert!(
        run.output.contains("counter=4000"),
        "output: {:?}",
        run.output
    );
}

// ── Shell-level gates over the Alpine rootfs ────────────────────────────────

fn alpine_machine() -> Option<Machine> {
    init_logging();
    let rootfs =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/alpine-minirootfs");
    linux_compat::testing::require(
        &format!("{} (run tools/fetch_alpine_rootfs.sh)", rootfs.display()),
        rootfs
            .join("lib/ld-musl-x86_64.so.1")
            .exists()
            .then_some(()),
    )?;
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_host_tree(Path::new(&rootfs), "/")
        .expect("rootfs import failed");
    Some(machine)
}

fn run_sh(machine: &mut Machine, script: &str) -> Run {
    machine.set_args(
        vec![b"sh".to_vec(), b"-c".to_vec(), script.as_bytes().to_vec()],
        vec![b"PATH=/bin:/usr/bin:/sbin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine.load(b"/bin/sh").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Run {
        exit,
        output,
        icount: machine.icount(),
    }
}

#[test]
fn shell_spawns_external_commands() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let run = run_sh(&mut machine, "/bin/echo external-command-works");
    expect_clean(&run);
    assert_eq!(run.output, "external-command-works\n");
}

/// `posix_spawn` uses `clone(CLONE_VM | CLONE_VFORK | SIGCHLD)`. That child
/// shares the parent's address space and must run to `execve` (or exit)
/// before the parent proceeds. Misclassifying it as a thread ran both
/// concurrently on the shared stack and corrupted the child (observed with a
/// real Codex binary: a `PageFault` on a garbage pointer right after such a
/// clone). Treating a vfork clone as a copy-on-write fork isolates them.
#[test]
fn posix_spawn_runs_a_child_to_completion() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let source = r#"
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
extern char **environ;
int main(void) {
    pid_t pid;
    char *argv[] = { "/bin/echo", "spawned-child-ran", 0 };
    int rc = posix_spawn(&pid, "/bin/echo", 0, 0, argv, environ);
    if (rc != 0) { printf("spawn failed rc=%d\n", rc); return 1; }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) { printf("wait failed\n"); return 2; }
    printf("parent-status=%d\n", WEXITSTATUS(status));
    return 0;
}
"#;
    let Some(image) = compile_c("spawner", source, &[]) else {
        return;
    };
    machine
        .add_file(b"/bin/spawner", image, 0o755)
        .expect("add spawner");
    machine.set_args(
        vec![b"spawner".to_vec()],
        vec![b"PATH=/bin:/usr/bin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine.load(b"/bin/spawner").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "spawner did not exit cleanly; output: {output:?}"
    );
    assert!(
        output.contains("spawned-child-ran") && output.contains("parent-status=0"),
        "posix_spawn child did not run to completion; output: {output:?}"
    );
}

#[test]
fn shell_pipelines_flow_between_processes() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let run = run_sh(&mut machine, "echo pipe-payload | cat");
    expect_clean(&run);
    assert_eq!(run.output, "pipe-payload\n");
}

#[test]
fn shell_multi_stage_pipeline_and_exit_codes() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let run = run_sh(
        &mut machine,
        "printf 'b\\na\\nc\\n' | sort | head -2 && echo rc=$?",
    );
    expect_clean(&run);
    assert!(
        run.output.contains("a\nb\n"),
        "sort|head failed: {:?}",
        run.output
    );
    assert!(
        run.output.contains("rc=0"),
        "exit code lost: {:?}",
        run.output
    );
}

#[test]
fn scheduling_is_deterministic_across_runs() {
    // Two fresh machines running the same multi-process workload must
    // produce identical output AND identical instruction counts.
    let mut runs = Vec::new();
    for _ in 0..2 {
        let Some(mut machine) = alpine_machine() else {
            return;
        };
        let run = run_sh(&mut machine, "echo det | cat && /bin/echo second");
        expect_clean(&run);
        runs.push(run);
    }
    assert_eq!(runs[0].output, runs[1].output);
    assert_eq!(
        runs[0].icount, runs[1].icount,
        "instruction counts diverged: {} vs {}",
        runs[0].icount, runs[1].icount
    );
}

#[test]
fn fork_memory_is_copy_on_write_isolated() {
    // The most dangerous silent failure: if COW is broken, parent and child
    // share writable pages and corrupt each other without any error.
    let source = r#"
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
static volatile long shared_global = 1;
int main(void) {
    char stack_local = 'A';
    pid_t pid = fork();
    if (pid < 0) return 9;
    if (pid == 0) {
        shared_global = 2;      // must NOT be visible to the parent
        stack_local = 'B';
        _exit(shared_global == 2 && stack_local == 'B' ? 7 : 8);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return 3;
    if (WEXITSTATUS(status) != 7) return 4;
    printf("parent sees global=%ld local=%c\n", shared_global, stack_local);
    return (shared_global == 1 && stack_local == 'A') ? 0 : 5;
}
"#;
    let Some(image) = compile_c("cow", source, &[]) else {
        return;
    };
    let run = run_image(image, "cow");
    expect_clean(&run);
    assert!(
        run.output.contains("parent sees global=1 local=A"),
        "COW isolation broken: {:?}",
        run.output
    );
}

#[test]
fn fork_shares_open_file_descriptions() {
    // Linux semantics: after fork, parent and child share file offsets.
    let source = r#"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int fd = open("/etc/data.txt", O_RDONLY);
    if (fd < 0) return 1;
    char buf[6] = {0};
    if (read(fd, buf, 5) != 5) return 2; // consume "AAAAA"
    pid_t pid = fork();
    if (pid < 0) return 3;
    if (pid == 0) {
        char child_buf[6] = {0};
        if (read(fd, child_buf, 5) != 5) _exit(4); // must be "BBBBB"
        _exit(strcmp(child_buf, "BBBBB") == 0 ? 7 : 5);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WEXITSTATUS(status) != 7) return 6;
    char tail[6] = {0};
    if (read(fd, tail, 5) != 5) return 7; // shared offset: now "CCCCC"
    printf("parent tail=%s\n", tail);
    return strcmp(tail, "CCCCC") == 0 ? 0 : 8;
}
"#;
    let Some(image) = compile_c("fdshare", source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/fdshare", image, 0o755)
        .expect("add fixture");
    machine
        .add_file(b"/etc/data.txt", b"AAAAABBBBBCCCCC".to_vec(), 0o644)
        .expect("add data");
    machine.set_args(vec![b"fdshare".to_vec()], vec![]);
    machine.load(b"/bin/fdshare").expect("ELF load failed");
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    let run = Run {
        exit,
        output,
        icount: machine.icount(),
    };
    expect_clean(&run);
    assert!(
        run.output.contains("parent tail=CCCCC"),
        "shared offset broken: {:?}",
        run.output
    );
}

#[test]
fn pipe_backpressure_blocks_and_drains() {
    // `yes` floods the pipe far past its capacity; `head -c` drains a fixed
    // amount. Exercises blocking writes, partial writes, EPIPE shutdown.
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let run = run_sh(&mut machine, "yes | head -c 2097152 | wc -c");
    expect_clean(&run);
    assert!(
        run.output.contains("2097152"),
        "backpressure roundtrip lost data: {:?}",
        run.output
    );
}

#[test]
fn large_anonymous_reservation_then_allocations_do_not_collide() {
    // A big PROT_NONE reservation (as V8's sandbox does) followed by smaller
    // mappings must not overlap: the mmap allocator has to find real holes,
    // not bump linearly into the reservation.
    let source = r#"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
int main(void) {
    size_t big = 256UL << 20; // 256 MiB
    void *reserve = mmap(NULL, big, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserve == MAP_FAILED) { printf("reserve failed\n"); return 1; }
    // Several writable mappings afterwards must each be usable and distinct.
    char *a = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *b = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (a == MAP_FAILED || b == MAP_FAILED) { printf("alloc failed\n"); return 2; }
    memset(a, 0xAA, 4096);
    memset(b, 0xBB, 65536);
    if ((unsigned char)a[0] != 0xAA || (unsigned char)b[65535] != 0xBB) { printf("corrupt\n"); return 3; }
    // The small mappings must not fall inside the reservation.
    if (a >= (char *)reserve && a < (char *)reserve + big) { printf("a inside reserve\n"); return 4; }
    printf("mmap-holes-ok reserve=%p a=%p b=%p\n", reserve, (void *)a, (void *)b);
    return 0;
}
"#;
    let Some(image) = compile_c("mmaptest", source, &[]) else {
        return;
    };
    let run = run_image(image, "mmaptest");
    expect_clean(&run);
    assert!(
        run.output.contains("mmap-holes-ok"),
        "output: {:?}",
        run.output
    );
}

/// Async runtimes (tokio) do not sit in `wait4`: they install a SIGCHLD
/// handler that writes a self-pipe and block on that pipe. Without real
/// signal delivery the parent never learns its child exited and hangs
/// forever (observed with a real Codex binary deadlocking on process
/// spawns).
#[test]
fn sigchld_self_pipe_wakes_a_parent_not_in_wait() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let source = r#"
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;
static int wake[2];
static void on_sigchld(int sig) {
    (void)sig;
    char byte = 'c';
    write(wake[1], &byte, 1);
}
int main(void) {
    if (pipe(wake) != 0) { printf("pipe failed\n"); return 1; }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigchld;
    if (sigaction(SIGCHLD, &sa, 0) != 0) { printf("sigaction failed\n"); return 2; }
    pid_t pid;
    char *argv[] = { "/bin/echo", "child-ran", 0 };
    int rc = posix_spawn(&pid, "/bin/echo", 0, 0, argv, environ);
    if (rc != 0) { printf("spawn failed rc=%d\n", rc); return 3; }
    /* Block on the self-pipe, not wait4: only SIGCHLD delivery can wake us. */
    char buf;
    if (read(wake[0], &buf, 1) != 1) { printf("wakeup read failed\n"); return 4; }
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) { printf("reap failed\n"); return 5; }
    printf("reaped-status=%d\n", WEXITSTATUS(status));
    return 0;
}
"#;
    let Some(image) = compile_c("sigchld_pipe", source, &[]) else {
        return;
    };
    machine
        .add_file(b"/bin/sigchld_pipe", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"sigchld_pipe".to_vec()],
        vec![b"PATH=/bin:/usr/bin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine.load(b"/bin/sigchld_pipe").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "parent was not woken by SIGCHLD; output: {output:?}"
    );
    assert!(
        output.contains("child-ran") && output.contains("reaped-status=0"),
        "SIGCHLD self-pipe wakeup did not reap the child; output: {output:?}"
    );
}

/// A `posix_spawn` whose `execve` fails: the vfork child exits without ever
/// replacing its image. The suspended parent must still be released (by the
/// child's exit) and must still receive SIGCHLD so it can reap the failure
/// without sitting in `wait4` (the exact shape of the Codex spawn deadlock).
#[test]
fn failed_exec_releases_vfork_parent_and_raises_sigchld() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let source = r#"
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
extern char **environ;
static int wake[2];
static void on_sigchld(int sig) {
    (void)sig;
    char byte = 'c';
    write(wake[1], &byte, 1);
}
int main(void) {
    if (pipe(wake) != 0) { printf("pipe failed\n"); return 1; }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigchld;
    if (sigaction(SIGCHLD, &sa, 0) != 0) { printf("sigaction failed\n"); return 2; }
    pid_t pid;
    char *argv[] = { "/bin/does-not-exist", 0 };
    int rc = posix_spawn(&pid, "/bin/does-not-exist", 0, 0, argv, environ);
    if (rc != 0) {
        /* Error detected synchronously: equally valid. */
        printf("spawn-error=%d\n", rc);
        return 0;
    }
    char buf;
    if (read(wake[0], &buf, 1) != 1) { printf("wakeup read failed\n"); return 4; }
    int status = 0;
    if (waitpid(pid, &status, WNOHANG) != pid) { printf("reap failed\n"); return 5; }
    printf("exec-failed-status=%d\n", WEXITSTATUS(status));
    return 0;
}
"#;
    let Some(image) = compile_c("spawn_fail", source, &[]) else {
        return;
    };
    machine
        .add_file(b"/bin/spawn_fail", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"spawn_fail".to_vec()],
        vec![b"PATH=/bin:/usr/bin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine.load(b"/bin/spawn_fail").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "failed exec left the parent stuck; output: {output:?}"
    );
    assert!(
        output.contains("spawn-error=") || output.contains("exec-failed-status="),
        "failed exec was not reported to the parent; output: {output:?}"
    );
}

/// Smoke test for repeated spawn+exec with parent continuity: the parent
/// recomputes a recognizable value after each child execs and exits, so a
/// child's image must not disturb the parent's execution. Related to the
/// per-address-space block-cache keying (blocks are keyed by address-space
/// id, not virtual address alone, so an exec'd child's blocks never run in
/// the parent at the same VA); the decisive end-to-end check for that fix is
/// a real coding agent completing an exec-heavy session cleanly.
#[test]
fn exec_child_does_not_pollute_parent_block_cache() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let source = r#"
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
extern char **environ;

__attribute__((noinline)) static unsigned mix(unsigned x) {
    for (int i = 0; i < 64; i++) x = x * 1664525u + 1013904223u;
    return x;
}

int main(void) {
    unsigned want = mix(12345u);
    for (int i = 0; i < 8; i++) {
        pid_t pid;
        char *argv[] = { "/bin/busybox", "true", 0 };
        if (posix_spawn(&pid, "/bin/busybox", 0, 0, argv, environ) != 0) {
            printf("spawn failed\n");
            return 1;
        }
        int status = 0;
        if (waitpid(pid, &status, 0) != pid) {
            printf("wait failed\n");
            return 2;
        }
        unsigned got = mix(12345u);
        if (got != want) {
            printf("cache polluted at iter %d: %u != %u\n", i, got, want);
            return 3;
        }
    }
    printf("parent-cache-stable\n");
    return 0;
}
"#;
    let Some(image) = compile_c("cachepollute", source, &[]) else {
        return;
    };
    machine
        .add_file(b"/bin/cachepollute", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"cachepollute".to_vec()],
        vec![b"PATH=/bin:/usr/bin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine.load(b"/bin/cachepollute").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 8_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "parent did not finish cleanly; output: {output:?}"
    );
    assert!(
        output.contains("parent-cache-stable"),
        "exec'd child polluted the parent's block cache; output: {output:?}"
    );
}

/// Two different static binaries commonly share a load address — every
/// fixture built by this repository's linker script starts at 0x40000000 —
/// so a block cache that keys on the address alone hands the second program
/// the first one's code. It did: `guest_ps` printed `hello`'s output.
///
/// Each loaded image now takes its own address space, and the engine's
/// content-addressed lift cache reuses a block only when the bytes at that
/// address still match the ones it was lifted from. This runs the two
/// fixtures alternately, so a stale block in either direction shows up as one
/// program printing the other's output.
#[test]
fn two_images_at_one_address_do_not_share_lifted_code() {
    init_logging();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data");
    let hello = std::fs::read(dir.join("hello_linux.elf")).expect("hello fixture");
    let ps = std::fs::read(dir.join("guest_ps.elf")).expect("ps fixture");
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/hello", hello, 0o755)
        .expect("add hello");
    machine.add_file(b"/bin/ps", ps, 0o755).expect("add ps");

    for (path, expected, forbidden) in [
        (&b"/bin/hello"[..], "Hello", "PID"),
        (&b"/bin/ps"[..], "PID", "Hello"),
        (&b"/bin/hello"[..], "Hello", "PID"),
        (&b"/bin/ps"[..], "PID", "Hello"),
    ] {
        let name = String::from_utf8_lossy(path).into_owned();
        machine.set_args(vec![b"prog".to_vec()], vec![b"PATH=/bin".to_vec()]);
        machine.load(path).expect("ELF load failed");
        machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
        let exit = machine.run();
        let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
        assert_eq!(
            exit,
            CpuExit::Halt { code: Some(0) },
            "{name} did not exit cleanly: {output:?}"
        );
        assert!(
            output.contains(expected),
            "{name} printed {output:?}, which is not its own output"
        );
        assert!(
            !output.contains(forbidden),
            "{name} printed the other image's output: {output:?}"
        );
    }
}

/// A signal raised while it is blocked must be delivered once it is
/// unblocked, not discarded.
///
/// This was broken, and the way it was broken is why it went unnoticed:
/// SIGCHLD was only recorded against a thread that did not currently block
/// it, so a child exiting inside `posix_spawn` — which blocks every signal
/// for the duration — lost its notification entirely and the parent waited
/// forever for a child that had already gone. Whether the child got there
/// first depended on how much work the host libc's `posix_spawn` did, so the
/// same code passed on one machine and hung on another.
///
/// Here the window is opened deliberately rather than raced for: the parent
/// blocks SIGCHLD, waits for the child to have exited, and only then unblocks.
#[test]
fn a_signal_raised_while_blocked_is_delivered_when_unblocked() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let source = r#"
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
extern char **environ;
static volatile sig_atomic_t caught = 0;
static void on_sigchld(int sig) { (void)sig; caught = 1; }

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sigchld;
    if (sigaction(SIGCHLD, &sa, 0) != 0) { printf("sigaction failed\n"); return 1; }

    sigset_t chld, saved;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &chld, &saved) != 0) { printf("block failed\n"); return 2; }

    pid_t pid;
    char *argv[] = { "/bin/echo", "child-done", 0 };
    if (posix_spawn(&pid, "/bin/echo", 0, 0, argv, environ) != 0) { printf("spawn failed\n"); return 3; }

    /* Reap it while SIGCHLD is blocked: the child is gone before the signal
       can be delivered, so only a signal held pending can still arrive. */
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) { printf("reap failed\n"); return 4; }
    if (caught) { printf("handler ran while blocked\n"); return 5; }

    if (sigprocmask(SIG_SETMASK, &saved, 0) != 0) { printf("unblock failed\n"); return 6; }
    /* Delivery happens at the next scheduling point rather than on the way
       out of the mask change, so the guest reaches one deliberately. What
       matters is that the signal survived the blocked window at all. */
    struct timespec pause = { 0, 1000000 };
    nanosleep(&pause, 0);
    printf("caught=%d\n", caught ? 1 : 0);
    return 0;
}
"#;
    let Some(image) = compile_c("sigchld_blocked", source, &[]) else {
        return;
    };
    machine
        .add_file(b"/bin/sigchld_blocked", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"sigchld_blocked".to_vec()],
        vec![b"PATH=/bin:/usr/bin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/sigchld_blocked")
        .expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "guest did not finish; output: {output:?}"
    );
    assert!(
        output.contains("caught=1"),
        "SIGCHLD raised while blocked was discarded rather than held pending; output: {output:?}"
    );
}

/// A signal one process sends another has to be resolved against the
/// *target's* disposition. The rule used to read the sender's: a process that
/// handled a signal itself could not `kill` anything with it, because its own
/// handler made the signal look already dealt with — and where the sender had
/// no handler, the target was zombied outright rather than running the one it
/// did have. Dispositions are inherited across `fork`, so a parent that
/// installs a handler and then signals its child exercises both halves.
#[test]
fn a_signal_sent_to_another_process_runs_that_process_handler() {
    let source = r#"
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t got = 0;
static void on_usr1(int s) { (void)s; got = 1; }

int main(void) {
    // Installed before the fork, so the sender has a handler too — which is
    // exactly what used to make the signal disappear.
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_usr1;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGUSR1, &sa, NULL);

    int ready[2], done[2];
    if (pipe(ready) || pipe(done)) return 1;

    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) {
        close(ready[0]);
        close(done[1]);
        // Tell the parent the handler is in place, then block until it fires.
        write(ready[1], "r", 1);
        char c;
        read(done[0], &c, 1);
        _exit(got ? 42 : 43);
    }

    close(ready[1]);
    close(done[0]);
    char c;
    if (read(ready[0], &c, 1) != 1) return 3;

    if (kill(pid, SIGUSR1) != 0) return 4;
    // Release the child only after the signal has been sent, so a child that
    // exits without ever seeing it reports 43 rather than racing to 42.
    write(done[1], "d", 1);

    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return 5;
    printf("child saw the signal: %d\n", WEXITSTATUS(status) == 42);
    fflush(stdout);
    return WEXITSTATUS(status) == 42 ? 0 : 6;
}
"#;
    let Some(image) = compile_c("kill_handler", source, &[]) else {
        return;
    };
    let run = run_image(image, "kill_handler");
    expect_clean(&run);
    assert!(
        run.output.contains("child saw the signal: 1"),
        "the child's own handler did not run: {:?}",
        run.output
    );
}

/// A regression guard, not evidence of the fix above: a target with no
/// handler used to be removed by the sender and now takes its own default
/// action at its next kernel entry, and this pins that the observable
/// outcome did not change — the child dies and the parent sees a signal
/// death. It passes with the old path too, which is why it is labelled this
/// way; the old status word was `128 + signal`, and its low seven bits are
/// the signal either way, so `WIFSIGNALED` and `WTERMSIG` never told them
/// apart.
#[test]
fn a_signal_with_no_handler_terminates_the_target_as_a_signal_death() {
    let source = r#"
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int ready[2], hold[2];
    if (pipe(ready) || pipe(hold)) return 1;
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) {
        close(ready[0]);
        close(hold[1]);
        write(ready[1], "r", 1);
        /* Blocks until signalled. No SIGTERM handler, so the default action
           applies and this read never returns. */
        char c;
        read(hold[0], &c, 1);
        _exit(7);
    }
    close(ready[1]);
    close(hold[0]);
    char c;
    if (read(ready[0], &c, 1) != 1) return 3;

    if (kill(pid, SIGTERM) != 0) return 4;
    int status = 0;
    if (waitpid(pid, &status, 0) != pid) return 5;
    printf("signalled=%d sig=%d exited=%d\n",
           WIFSIGNALED(status) ? 1 : 0,
           WIFSIGNALED(status) ? WTERMSIG(status) : -1,
           WIFEXITED(status) ? 1 : 0);
    fflush(stdout);
    return 0;
}
"#;
    let Some(image) = compile_c("kill_default", source, &[]) else {
        return;
    };
    let run = run_image(image, "kill_default");
    expect_clean(&run);
    assert!(
        run.output.contains("signalled=1 sig=15 exited=0"),
        "a signal death was not reported as one: {:?}",
        run.output
    );
}

/// Loads an image without running it, so a test can look at the filesystem
/// before and after.
fn image_machine(image: Vec<u8>, name: &str) -> Machine {
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/fixture", image, 0o755)
        .expect("add fixture");
    machine.set_args(vec![name.as_bytes().to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/fixture").expect("ELF load failed");
    machine
}

fn run_loaded(machine: &mut Machine) -> Run {
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    let icount = machine.icount();
    Run {
        exit,
        output,
        icount,
    }
}

/// Deleting a file has to give its bytes back. They used to stay: `unlink`
/// detached the name and left the contents in the node, so a guest churning
/// temporary files walked into the storage ceiling while nothing it could see
/// was growing — and the bytes went into every snapshot, which for a browser
/// means deleted data reaching disk.
#[test]
fn deleting_a_file_releases_its_bytes_and_keeps_them_out_of_a_snapshot() {
    let source = r#"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char buf[4096];
    memset(buf, 'Z', sizeof buf);

    int fd = open("/tmp/scratch", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return 1;
    for (int i = 0; i < 16; i++) {
        if (write(fd, buf, sizeof buf) != (ssize_t)sizeof buf) return 2;
    }
    close(fd);

    if (unlink("/tmp/scratch") != 0) return 3;
    printf("deleted\n");
    fflush(stdout);
    return 0;
}
"#;
    let Some(image) = compile_c("unlink_release", source, &[]) else {
        return;
    };
    let mut machine = image_machine(image, "unlink_release");
    let before = machine.env().vfs.bytes();
    let run = run_loaded(&mut machine);
    assert!(
        run.output.contains("deleted"),
        "probe did not run: {:?}",
        run.output
    );

    let after = machine.env().vfs.bytes();
    assert!(
        after <= before + 8192,
        "the 64 KiB the guest deleted is still held: {before} then {after}"
    );

    let snapshot = machine.export_fs();
    let run_of_z = [b'Z'; 512];
    assert!(
        !snapshot
            .windows(run_of_z.len())
            .any(|w| w == run_of_z.as_slice()),
        "deleted contents reached the snapshot"
    );
}

/// The reclamation must not break the idiom it exists alongside: a file
/// unlinked while still open stays readable through the descriptor that was
/// already there. Freeing on `unlink` alone would be the easy fix and the
/// wrong one.
#[test]
fn a_file_unlinked_while_open_is_still_readable() {
    let source = r#"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    int fd = open("/tmp/held", O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (fd < 0) return 1;
    const char *msg = "still-here-after-unlink";
    if (write(fd, msg, strlen(msg)) != (ssize_t)strlen(msg)) return 2;

    if (unlink("/tmp/held") != 0) return 3;
    if (open("/tmp/held", O_RDONLY) >= 0) return 4;   /* gone by name */

    char buf[64] = {0};
    if (lseek(fd, 0, SEEK_SET) != 0) return 5;
    ssize_t n = read(fd, buf, sizeof buf - 1);
    if (n <= 0) return 6;
    printf("read back: %s\n", buf);
    fflush(stdout);
    close(fd);
    return 0;
}
"#;
    let Some(image) = compile_c("unlink_open", source, &[]) else {
        return;
    };
    let mut machine = image_machine(image, "unlink_open");
    let run = run_loaded(&mut machine);
    assert!(
        run.output.contains("read back: still-here-after-unlink"),
        "an unlinked file was not readable through its open descriptor: {:?}",
        run.output
    );
    // And once the descriptor is gone, so are the bytes. Measured rather than
    // searched for: the string is a literal in the fixture, and the fixture
    // is itself a file in this filesystem, so looking for it in a snapshot
    // finds the program image and proves nothing.
    assert!(
        !machine.env().vfs.has_unlinked(),
        "the file is still held after its last descriptor closed"
    );
}
