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
    match cmd.status() {
        Ok(status) if status.success() => Some(std::fs::read(&out).expect("compiler output")),
        _ => {
            eprintln!("skipping: fixture compiler unavailable ({cmd:?})");
            None
        }
    }
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
    if !rootfs.join("lib/ld-musl-x86_64.so.1").exists() {
        eprintln!(
            "skipping: {} missing (run tools/fetch_alpine_rootfs.sh)",
            rootfs.display()
        );
        return None;
    }
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
