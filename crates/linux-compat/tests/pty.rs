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

/// A TUI on a pty must be told about window-size changes: the parent resizes
/// the master with TIOCSWINSZ, the kernel raises SIGWINCH on the slave's
/// foreground group, and the child re-reads the new size — then keeps taking
/// input. This is the terminal-resize behavior an interactive agent needs.
#[test]
fn pty_resize_delivers_sigwinch_to_the_foreground_group() {
    let source = r#"
#define _GNU_SOURCE
#include <pty.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

static volatile sig_atomic_t got_winch = 0;
static void on_winch(int s) { (void)s; got_winch = 1; }

static int child_main(void) {
    struct termios t;
    tcgetattr(0, &t);
    cfmakeraw(&t);
    tcsetattr(0, TCSANOW, &t);
    signal(SIGWINCH, on_winch);
    struct winsize ws;
    ioctl(0, TIOCGWINSZ, &ws);
    dprintf(1, "START %d %d\n", ws.ws_row, ws.ws_col);
    while (!got_winch) {
        char b;
        int n = read(0, &b, 1);
        if (n == 1) dprintf(1, "KEY %d\n", (int)(unsigned char)b);
        if (got_winch) break;
    }
    ioctl(0, TIOCGWINSZ, &ws);
    dprintf(1, "WINCH %d %d\n", ws.ws_row, ws.ws_col);
    char b;
    if (read(0, &b, 1) == 1) dprintf(1, "KEY %d\n", (int)(unsigned char)b);
    return 0;
}

static int read_line(int fd, char *buf, int max) {
    int n = 0;
    while (n < max - 1) {
        char c; int r = read(fd, &c, 1);
        if (r <= 0) break;
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = 0;
    return n;
}

int main(void) {
    int m;
    struct winsize init = { 24, 80, 0, 0 };
    pid_t p = forkpty(&m, NULL, NULL, &init);
    if (p < 0) { perror("forkpty"); return 1; }
    if (p == 0) { _exit(child_main()); }
    char line[128];
    read_line(m, line, sizeof line);
    printf("%s", line);
    struct winsize ws = { 40, 120, 0, 0 };
    ioctl(m, TIOCSWINSZ, &ws);
    char key = 'A';
    if (write(m, &key, 1) != 1) perror("write");
    for (int i = 0; i < 8; i++) {
        if (read_line(m, line, sizeof line) <= 0) break;
        printf("%s", line);
        if (strncmp(line, "WINCH", 5) == 0) {
            key = 'Z';
            if (write(m, &key, 1) != 1) perror("write");
        }
    }
    int st = 0;
    waitpid(p, &st, 0);
    return 0;
}
"#;
    let Some(image) = compile_c("ptyresize", source, &["-lutil"]) else {
        return;
    };
    let (exit, out) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "resize: {out:?}");
    assert!(
        out.contains("START 24 80") && out.contains("WINCH 40 120") && out.contains("KEY 90"),
        "resize sequence: {out:?}"
    );
}

/// The "browser terminal" model: stdin/stdout are a host-driven pty, so
/// isatty() is true and the program runs its interactive path. The host feeds
/// keystrokes and reads rendered output. Exercises Machine::install_pty_stdio,
/// feed_terminal_input, drain_terminal_output, and the stall-time input
/// injection that keeps a blocked terminal read from deadlocking.
#[test]
fn stdio_pty_drives_an_interactive_program() {
    let source = r#"
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    dprintf(1, "tty=%d\n", isatty(0));
    char buf[128];
    int n = 0;
    while (n < (int)sizeof(buf) - 1) {
        char c;
        int r = read(0, &c, 1);
        if (r <= 0) break;
        buf[n++] = c;
        if (c == '\n') break;
    }
    buf[n] = 0;
    dprintf(1, "echo:%s", buf);
    return 0;
}
"#;
    let Some(image) = compile_c("stdiopty", source, &[]) else {
        return;
    };
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
    machine.install_pty_stdio(40, 120);
    machine.feed_terminal_input(b"hello-terminal\n");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let rendered = String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "stdio pty: {rendered:?}"
    );
    assert!(
        rendered.contains("tty=1") && rendered.contains("echo:hello-terminal"),
        "terminal output: {rendered:?}"
    );
}

/// The pinned BusyBox image, or None when it has not been fetched.
fn busybox() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: {} missing (run tools/fetch_busybox.sh)",
                path.display()
            );
            None
        }
    }
}

/// The browser terminal's core loop: a guest blocked on a terminal read is
/// waiting for the user, not deadlocked. `run` returns with
/// `awaiting_terminal_input`, the host types, and the next `run` continues
/// from exactly where the guest stopped. Without this a tab hosting an
/// interactive program would halt the moment it asked for a keystroke.
#[test]
fn stdio_pty_pauses_for_input_and_resumes() {
    let Some(image) = busybox() else {
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("add busybox");
    machine.set_args(
        vec![b"busybox".to_vec(), b"cat".to_vec()],
        vec![b"PATH=/bin".to_vec()],
    );
    machine.load(b"/bin/busybox").expect("ELF load failed");
    machine.install_pty_stdio(40, 120);
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;

    // No keystrokes queued: `cat` blocks on its first read and the machine
    // pauses instead of reporting a deadlock.
    let exit = machine.run();
    assert_eq!(exit, CpuExit::Interrupted, "expected an interactive pause");
    assert!(
        machine.awaiting_terminal_input(),
        "pause should be attributed to terminal input"
    );
    assert_eq!(machine.exit_code(), None, "a pause is not an exit");

    // The user types. The same process resumes and echoes the line back.
    machine.feed_terminal_input(b"typed-in-the-browser\n");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let rendered = String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned();
    assert!(
        rendered.contains("typed-in-the-browser"),
        "terminal output after typing: {rendered:?}"
    );

    // `cat` has no more input, so it parks again rather than exiting.
    assert_eq!(exit, CpuExit::Interrupted, "output: {rendered:?}");
    assert!(machine.awaiting_terminal_input());
}

/// A real full-screen program in the terminal. `busybox vi` takes the
/// alternate screen, paints the file with `~` filler to the window height,
/// and parks waiting for a keystroke. A host-side resize (the user resizing
/// the browser window) reaches it as SIGWINCH, and it repaints at the new
/// size without the user typing anything — the redraw is the evidence that
/// the guest both received the signal and read back the new TIOCGWINSZ.
#[test]
fn host_resize_repaints_a_full_screen_program() {
    let Some(image) = busybox() else {
        return;
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("add busybox");
    machine
        .add_file(b"/tmp/note.txt", b"alpha\nbeta\n".to_vec(), 0o644)
        .expect("add file");
    machine.set_args(
        vec![
            b"busybox".to_vec(),
            b"vi".to_vec(),
            b"/tmp/note.txt".to_vec(),
        ],
        vec![
            b"PATH=/bin".to_vec(),
            b"TERM=xterm".to_vec(),
            b"HOME=/root".to_vec(),
        ],
    );
    machine.load(b"/bin/busybox").expect("ELF load failed");
    machine.install_pty_stdio(10, 40);
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;

    assert_eq!(machine.run(), CpuExit::Interrupted, "vi should await input");
    assert!(machine.awaiting_terminal_input());
    let first = String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned();
    assert!(
        first.contains("\u{1b}[?1049h") && first.contains("alpha"),
        "vi did not paint the alternate screen: {first:?}"
    );
    // A 10-row window: rows 3..9 are filler and row 10 is the status line.
    assert!(
        first.contains("\u{1b}[9;1H~") && first.contains("\u{1b}[10;1H"),
        "vi painted the wrong height: {first:?}"
    );

    // The user resizes the window. Nothing is typed.
    machine.resize_terminal(6, 20);
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    assert_eq!(machine.run(), CpuExit::Interrupted);
    let repaint = String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned();
    assert!(
        repaint.contains("\u{1b}[5;1H~") && repaint.contains("\u{1b}[6;1H"),
        "vi did not repaint at 6 rows: {repaint:?}"
    );
    assert!(
        !repaint.contains("\u{1b}[9;1H"),
        "vi still painted the old height: {repaint:?}"
    );

    // It is still interactive afterwards: quitting exits cleanly.
    machine.feed_terminal_input(b":q!\r");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let tail = String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned();
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "quit: {tail:?}");
}
