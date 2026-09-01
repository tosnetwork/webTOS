//! File watching.
//!
//! An agent watches the files it is working on: all three of the binaries
//! this runtime targets carry inotify. Without it the syscalls answer
//! `ENOSYS`, and what a watcher does with that is its own business —
//! sometimes a fallback, sometimes a crash, never the thing the program was
//! written to do.
//!
//! These fixtures use libc's inotify rather than raw syscalls, because the
//! shape of `struct inotify_event` on the wire is half of what is being
//! tested: a reader that cannot walk the buffer sees nothing regardless of
//! what was queued.

use std::path::PathBuf;
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn compile_c(name: &str, source: &str) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-watch-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join(format!("{name}.c"));
    let out = dir.join(name);
    std::fs::write(&src, source).expect("write source");
    let mut cmd = Command::new("gcc");
    cmd.arg("-O1")
        .arg("-static")
        .arg("-std=gnu17")
        .arg("-D_GNU_SOURCE")
        .arg("-o")
        .arg(&out)
        .arg(&src);
    let built = matches!(cmd.status(), Ok(status) if status.success());
    linux_compat::testing::require(
        &format!("a compiler that targets Linux x86-64 for {name} ({cmd:?})"),
        built.then(|| std::fs::read(&out).expect("compiler output")),
    )
}

fn run(image: Vec<u8>) -> (CpuExit, String) {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/fixture", image, 0o755)
        .expect("add fixture");
    machine
        .add_file(b"/work/existing", b"before\n".to_vec(), 0o644)
        .expect("seed");
    machine.set_args(vec![b"fixture".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/fixture").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    (exit, output)
}

/// The shared preamble: open an instance, watch `/work`, and a helper that
/// drains whatever is queued and prints it in a form a test can assert on.
const PREAMBLE: &str = r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/inotify.h>

static int fd;

static void drain(void) {
    char buf[4096];
    ssize_t got = read(fd, buf, sizeof buf);
    if (got <= 0) { printf("drain: nothing (%s)\n", got < 0 ? strerror(errno) : "eof"); return; }
    for (char *p = buf; p < buf + got; ) {
        struct inotify_event *e = (struct inotify_event *) p;
        printf("event wd=%d mask=%#x cookie=%u name=[%s]\n",
               e->wd, e->mask, e->cookie, e->len ? e->name : "");
        p += sizeof(struct inotify_event) + e->len;
    }
}
"#;

#[test]
fn a_watcher_hears_a_file_being_written() {
    let Some(image) = compile_c(
        "watch_modify",
        &format!(
            r#"{PREAMBLE}
int main(void) {{
    fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) {{ printf("inotify_init1: %s\n", strerror(errno)); return 1; }}
    int wd = inotify_add_watch(fd, "/work/existing", IN_MODIFY);
    if (wd < 0) {{ printf("add_watch: %s\n", strerror(errno)); return 1; }}
    printf("watching wd=%d\n", wd);

    int f = open("/work/existing", O_WRONLY | O_APPEND);
    write(f, "more", 4);
    close(f);
    drain();
    return 0;
}}
"#
        ),
    ) else {
        return;
    };
    let (exit, output) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(output.contains("watching wd=1"), "no watch: {output}");
    assert!(
        output.contains(&format!("mask={:#x}", 0x2)),
        "a write to a watched file raised no IN_MODIFY: {output}"
    );
}

#[test]
fn a_watcher_on_a_directory_hears_which_entry_changed() {
    let Some(image) = compile_c(
        "watch_dir",
        &format!(
            r#"{PREAMBLE}
int main(void) {{
    fd = inotify_init1(IN_NONBLOCK);
    int wd = inotify_add_watch(fd, "/work", IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO);
    if (wd < 0) {{ printf("add_watch: %s\n", strerror(errno)); return 1; }}

    int f = creat("/work/fresh", 0644);
    close(f);
    rename("/work/fresh", "/work/renamed");
    unlink("/work/renamed");
    drain();
    return 0;
}}
"#
        ),
    ) else {
        return;
    };
    let (exit, output) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("name=[fresh]") && output.contains("mask=0x100"),
        "a created entry was not named: {output}"
    );
    // The two halves of a rename must carry the same non-zero cookie, which
    // is the only thing that tells a watcher it was a rename rather than an
    // unrelated delete and create.
    let cookies: Vec<&str> = output
        .lines()
        .filter(|l| l.contains("mask=0x40") || l.contains("mask=0x80"))
        .map(|l| {
            l.split("cookie=")
                .nth(1)
                .unwrap_or("")
                .split(' ')
                .next()
                .unwrap_or("")
        })
        .collect();
    assert_eq!(
        cookies.len(),
        2,
        "a rename did not produce two halves: {output}"
    );
    assert_eq!(
        cookies[0], cookies[1],
        "the halves of a rename did not pair: {output}"
    );
    assert_ne!(cookies[0], "0", "a rename's cookie was zero: {output}");
    assert!(
        output.contains("name=[renamed]") && output.contains("mask=0x200"),
        "a deleted entry was not named: {output}"
    );
}

#[test]
fn a_removed_watch_goes_quiet() {
    let Some(image) = compile_c(
        "watch_rm",
        &format!(
            r#"{PREAMBLE}
int main(void) {{
    fd = inotify_init1(IN_NONBLOCK);
    int wd = inotify_add_watch(fd, "/work/existing", IN_MODIFY);
    if (inotify_rm_watch(fd, wd) != 0) {{ printf("rm_watch: %s\n", strerror(errno)); return 1; }}
    if (inotify_rm_watch(fd, wd) == 0) {{ printf("rm_watch twice succeeded\n"); return 1; }}

    int f = open("/work/existing", O_WRONLY | O_APPEND);
    write(f, "more", 4);
    close(f);
    drain();
    printf("done\n");
    return 0;
}}
"#
        ),
    ) else {
        return;
    };
    let (exit, output) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("drain: nothing") && output.contains("done"),
        "a removed watch still reported: {output}"
    );
}

#[test]
fn a_blocked_watcher_wakes_when_something_happens() {
    let Some(image) = compile_c(
        "watch_poll",
        &format!(
            r#"{PREAMBLE}
#include <poll.h>
#include <sys/wait.h>
int main(void) {{
    fd = inotify_init1(0);
    if (inotify_add_watch(fd, "/work", IN_CREATE) < 0) {{ printf("add_watch failed\n"); return 1; }}

    pid_t pid = fork();
    if (pid == 0) {{
        /* The change happens in another process, which is where a watcher's
           changes come from. */
        close(creat("/work/from-child", 0644));
        _exit(0);
    }}
    int st = 0;
    waitpid(pid, &st, 0);

    struct pollfd p = {{ .fd = fd, .events = POLLIN }};
    int n = poll(&p, 1, 0);
    printf("poll=%d revents=%#x\n", n, p.revents);
    drain();
    return 0;
}}
"#
        ),
    ) else {
        return;
    };
    let (exit, output) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("poll=1"),
        "poll did not see the queued event, so a watcher would block forever: {output}"
    );
    assert!(
        output.contains("name=[from-child]"),
        "a change from another process did not reach the watcher: {output}"
    );
}

/// An empty *blocking* inotify descriptor is not a file at end-of-file.  A
/// file watcher such as a terminal client commonly submits a 64 KiB read and
/// expects the kernel to park it until another task changes a watched path.
/// Returning zero here makes the watcher treat the descriptor as permanently
/// closed and spin, consuming its entire event-loop turn before it can make
/// the network request that follows.
#[test]
fn a_blocking_inotify_read_waits_for_and_consumes_an_event() {
    let Some(image) = compile_c(
        "watch_blocking_read",
        &format!(
            r#"{PREAMBLE}
#include <sys/wait.h>
int main(void) {{
    fd = inotify_init1(0);
    if (fd < 0) {{ printf("init: %s\n", strerror(errno)); return 1; }}
    if (inotify_add_watch(fd, "/work", IN_CREATE) < 0) {{
        printf("watch: %s\n", strerror(errno)); return 2;
    }}
    pid_t pid = fork();
    if (pid < 0) return 3;
    if (pid == 0) {{
        int child = creat("/work/unblocks-parent", 0644);
        if (child < 0) _exit(4);
        close(child);
        _exit(0);
    }}

    char buf[65536];
    ssize_t got = read(fd, buf, sizeof buf);
    if (got <= 0) {{
        printf("read=%zd errno=%d\n", got, errno);
        return 5;
    }}
    struct inotify_event *event = (struct inotify_event *)buf;
    int status = 0;
    waitpid(pid, &status, 0);
    printf("read=%zd mask=%#x name=[%s] child=%d\n", got, event->mask,
           event->len ? event->name : "", status);
    return event->mask == IN_CREATE && event->len &&
                   strcmp(event->name, "unblocks-parent") == 0 && status == 0
               ? 0
               : 6;
}}
"#
        ),
    ) else {
        return;
    };
    let (exit, output) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("name=[unblocks-parent]"),
        "the blocked read did not consume its wake event: {output}"
    );
}
