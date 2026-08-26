//! Milestone-7 workload: pseudoterminals. openpty()/forkpty() are how a
//! coding agent gives a child process a real controlling terminal for its
//! interactive TUI. Fixtures are compiled by the test with the host gcc, so
//! these are native-only and skip when no static compiler is available.

use std::path::{Path, PathBuf};
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn compile_c(name: &str, source: &str, extra: &[&str]) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-pty-fixture");
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

fn run(image: Vec<u8>) -> (CpuExit, String) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/fixture", image, 0o755)
        .expect("add fixture");
    machine.set_args(vec![b"fixture".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/fixture").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    (exit, output)
}

/// openpty()-style flow: allocate a master via /dev/ptmx, open the slave by
/// its /dev/pts/<n> name, and move bytes slave→master. ONLCR maps the
/// slave's `\n` to `\r\n` on the master side (14 bytes out for 13 in).
#[test]
fn openpty_moves_data_slave_to_master() {
    let source = r#"
#define _XOPEN_SOURCE 600
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0) { perror("posix_openpt"); return 1; }
    if (grantpt(m) != 0) { perror("grantpt"); return 2; }
    if (unlockpt(m) != 0) { perror("unlockpt"); return 3; }
    char *name = ptsname(m);
    if (!name) { perror("ptsname"); return 4; }
    int s = open(name, O_RDWR | O_NOCTTY);
    if (s < 0) { perror("open slave"); return 5; }
    if (write(s, "hi-from-slave\n", 14) != 14) { perror("write"); return 6; }
    char buf[64];
    int n = read(m, buf, sizeof buf);
    if (n <= 0) { printf("read returned %d\n", n); return 7; }
    buf[n] = 0;
    printf("master got %d: %s", n, buf);
    return 0;
}
"#;
    let Some(image) = compile_c("openpty", source, &[]) else {
        return;
    };
    let (exit, out) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "openpty: {out:?}");
    // 14 input bytes; the trailing '\n' is expanded to "\r\n" -> 15 out.
    assert!(
        out.contains("master got 15: hi-from-slave\r\n"),
        "openpty output: {out:?}"
    );
}

/// forkpty(): the child runs on the slave as its controlling terminal (via
/// login_tty — setsid, TIOCSCTTY, dup2), writes to its stdout, and the parent
/// reads it back through the master.
#[test]
fn forkpty_runs_a_child_on_a_controlling_terminal() {
    let source = r#"
#define _GNU_SOURCE
#include <pty.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

int main(void) {
    int m;
    pid_t p = forkpty(&m, NULL, NULL, NULL);
    if (p < 0) { perror("forkpty"); return 1; }
    if (p == 0) {
        write(1, "child-on-tty\n", 13);
        _exit(0);
    }
    char buf[128];
    int total = 0, n;
    while (total < (int)sizeof(buf) - 1 &&
           (n = read(m, buf + total, sizeof(buf) - 1 - total)) > 0) {
        total += n;
        if (memchr(buf, '\n', total)) break;
    }
    buf[total] = 0;
    int st = 0;
    waitpid(p, &st, 0);
    printf("parent read %d: %s", total, buf);
    return 0;
}
"#;
    let Some(image) = compile_c("forkpty", source, &["-lutil"]) else {
        return;
    };
    let (exit, out) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "forkpty: {out:?}");
    assert!(out.contains("child-on-tty"), "forkpty output: {out:?}");
}
