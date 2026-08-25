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
