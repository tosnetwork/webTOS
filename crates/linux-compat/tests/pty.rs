//! Milestone-7 workload: pseudoterminals. openpty()/forkpty() are how a
//! coding agent gives a child process a real controlling terminal for its
//! interactive TUI. Fixtures are compiled by the test with the host gcc, so
//! these are native-only and skip when no static compiler is available.

use std::path::PathBuf;
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
    let built = matches!(cmd.status(), Ok(status) if status.success());
    linux_compat::testing::require(
        &format!("a compiler that targets Linux x86-64 for {name} ({cmd:?})"),
        built.then(|| std::fs::read(&out).expect("compiler output")),
    )
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
#include <sys/ioctl.h>

int main(void) {
    pid_t sid = -1;
    if (ioctl(0, TIOCGSID, &sid) != 0) return 2;
    dprintf(1, "tty=%d sid=%d\n", isatty(0), (int)sid);
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
        rendered.contains("tty=1 sid=1000") && rendered.contains("echo:hello-terminal"),
        "terminal output: {rendered:?}"
    );
}

/// Runtimes that classify stdio via statx(2) — Bun is one — read
/// stx_rdev_major/minor to recognize a Linux pty (major 136). A prior
/// version left those fields zero, making a real pty look like an unrelated
/// character device even though ioctl-based isatty() succeeded.
#[test]
fn statx_reports_pty_rdev() {
    let source = r#"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

struct statx_timestamp { int64_t tv_sec; uint32_t tv_nsec; int32_t pad; };
struct statx {
    uint32_t stx_mask, stx_blksize; uint64_t stx_attributes;
    uint32_t stx_nlink, stx_uid, stx_gid; uint16_t stx_mode; uint16_t pad0;
    uint64_t stx_ino; uint64_t stx_size; uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    struct statx_timestamp stx_atime, stx_btime, stx_ctime, stx_mtime;
    uint32_t stx_rdev_major, stx_rdev_minor, stx_dev_major, stx_dev_minor;
    /* The kernel always writes its full 256-byte statx ABI object. */
    unsigned char reserved[128];
};

int main(void) {
    struct statx sx;
    memset(&sx, 0, sizeof(sx));
    long r = syscall(SYS_statx, 0, "", AT_EMPTY_PATH, 0x7ff /* STATX_BASIC_STATS */, &sx);
    if (r != 0) return 2;
    dprintf(1, "statx=%u:%u\n", sx.stx_rdev_major, sx.stx_rdev_minor);
    if (sx.stx_rdev_major != 136 || sx.stx_rdev_minor != 0) return 3;
    return 0;
}
"#;
    let Some(image) = compile_c("statxpty", source, &[]) else {
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
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "stdio pty did not expose its Linux rdev through statx: {output}"
    );
}

/// The pinned BusyBox image, or None when it has not been fetched.
fn busybox() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/busybox-musl");
    linux_compat::testing::require(
        &format!("{} (run tools/fetch_busybox.sh)", path.display()),
        std::fs::read(&path).ok(),
    )
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

/// The shape the browser terminal actually runs: an interactive shell that
/// starts a full-screen program, and a window resize while that program owns
/// the screen. The shell puts the job in its own process group and claims the
/// terminal for it through `/dev/tty`, so the resize must reach the group the
/// shell made the foreground one — not the shell's own.
#[test]
fn a_shell_launched_program_repaints_on_resize() {
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
    for applet in ["sh", "vi"] {
        machine
            .add_symlink(format!("/bin/{applet}").as_bytes(), b"/bin/busybox")
            .expect("applet link");
    }
    machine
        .add_file(b"/root/notes.txt", b"alpha\nbeta\ngamma\n".to_vec(), 0o644)
        .expect("add file");
    machine.set_args(
        vec![b"sh".to_vec(), b"-i".to_vec()],
        vec![
            b"PATH=/bin".to_vec(),
            b"TERM=xterm".to_vec(),
            b"HOME=/root".to_vec(),
            b"PS1=$ ".to_vec(),
        ],
    );
    machine.load(b"/bin/sh").expect("ELF load failed");
    machine.install_pty_stdio(12, 40);

    let run = |machine: &mut Machine| {
        machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
        let exit = machine.run();
        (
            exit,
            String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned(),
        )
    };

    let (_, prompt) = run(&mut machine);
    assert!(prompt.contains('$'), "no shell prompt: {prompt:?}");

    machine.feed_terminal_input(b"vi /root/notes.txt\n");
    let (_, painted) = run(&mut machine);
    assert!(
        painted.contains("\u{1b}[?1049h") && painted.contains("\u{1b}[12;1H"),
        "editor did not paint a 12-row screen: {painted:?}"
    );

    // The window grows. Nothing is typed.
    machine.resize_terminal(20, 40);
    let (_, repainted) = run(&mut machine);
    assert!(
        repainted.contains("\u{1b}[20;1H") && repainted.contains("alpha"),
        "editor did not repaint at 20 rows: {repainted:?}"
    );
}

/// `^C` has to be a signal, not a byte. Without the input line discipline the
/// interrupt character arrives as data and a foreground program blocked in a
/// read simply never ends, which is what a person notices first when a
/// terminal is not really a terminal. The `^C` at the prompt exercises the
/// other half: BusyBox `sh` converts it to a self-directed SIGINT (blocked
/// around the `raise` by musl), and the shell survives only if the handler
/// runs on the way out of the `rt_sigprocmask` that unblocked it — otherwise
/// the shell reads the interrupt as end-of-file and exits 130.
#[test]
fn the_interrupt_character_kills_the_foreground_program() {
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
    for applet in ["sh", "cat", "echo"] {
        machine
            .add_symlink(format!("/bin/{applet}").as_bytes(), b"/bin/busybox")
            .expect("applet link");
    }
    machine.set_args(
        vec![b"sh".to_vec(), b"-i".to_vec()],
        vec![
            b"PATH=/bin".to_vec(),
            b"TERM=xterm".to_vec(),
            b"HOME=/root".to_vec(),
            b"PS1=$ ".to_vec(),
        ],
    );
    machine.load(b"/bin/sh").expect("ELF load failed");
    machine.install_pty_stdio(24, 80);

    let run = |machine: &mut Machine| {
        machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
        machine.run();
        String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned()
    };

    let prompt = run(&mut machine);
    assert!(prompt.contains('$'), "no shell prompt: {prompt:?}");

    // A foreground program blocked reading the terminal. Unlike `sleep`, a
    // blocked `cat` has no deadline, so the deterministic clock cannot warp
    // past it: only the interrupt can end it.
    machine.feed_terminal_input(b"cat\n");
    let _ = run(&mut machine);
    assert!(
        machine.awaiting_terminal_input(),
        "the shell should be waiting on a child blocked in a terminal read"
    );

    machine.feed_terminal_input(b"\x03");
    let after = run(&mut machine);
    assert!(
        machine.awaiting_terminal_input(),
        "the shell did not come back after the interrupt: {after:?}"
    );

    // The shell survived the signal aimed at its child and still works.
    machine.feed_terminal_input(b"echo interrupted-and-alive\n");
    let echoed = run(&mut machine);
    assert!(
        echoed.contains("interrupted-and-alive"),
        "the shell did not run a command after the interrupt: {echoed:?}"
    );

    // `^C` at the prompt itself: the shell prints its own `^C`, redraws the
    // prompt, and keeps working instead of treating it as end-of-file.
    machine.feed_terminal_input(b"\x03");
    let at_prompt = run(&mut machine);
    assert!(
        machine.awaiting_terminal_input(),
        "the shell exited on ^C at the prompt: {at_prompt:?}"
    );
    machine.feed_terminal_input(b"echo still-here\n");
    let echoed = run(&mut machine);
    assert!(
        echoed.contains("still-here"),
        "the shell did not run a command after ^C at the prompt: {echoed:?}"
    );
}

/// `^Z` is the other half of job control: the foreground program stops (it
/// does not die), the shell reports it and takes the terminal back, and `fg`
/// puts it back in the foreground exactly where it left off — a blocked read
/// resumes blocking, and the next line typed reaches the same process.
#[test]
fn the_suspend_character_stops_and_fg_resumes() {
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
    for applet in ["sh", "cat", "echo"] {
        machine
            .add_symlink(format!("/bin/{applet}").as_bytes(), b"/bin/busybox")
            .expect("applet link");
    }
    machine.set_args(
        vec![b"sh".to_vec(), b"-i".to_vec()],
        vec![
            b"PATH=/bin".to_vec(),
            b"TERM=xterm".to_vec(),
            b"HOME=/root".to_vec(),
            b"PS1=$ ".to_vec(),
        ],
    );
    machine.load(b"/bin/sh").expect("ELF load failed");
    machine.install_pty_stdio(24, 80);

    let run = |machine: &mut Machine| {
        machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
        machine.run();
        String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned()
    };

    let prompt = run(&mut machine);
    assert!(prompt.contains('$'), "no shell prompt: {prompt:?}");

    machine.feed_terminal_input(b"cat\n");
    let _ = run(&mut machine);
    machine.feed_terminal_input(b"first-line\n");
    let echoed = run(&mut machine);
    assert!(
        echoed.contains("first-line"),
        "cat did not echo before the suspend: {echoed:?}"
    );

    // ^Z: cat stops, the shell reports the stopped job and prompts again.
    machine.feed_terminal_input(b"\x1a");
    let stopped = run(&mut machine);
    assert!(
        machine.awaiting_terminal_input(),
        "the shell did not come back after ^Z: {stopped:?}"
    );
    assert!(
        stopped.contains("Stopped"),
        "the shell did not report a stopped job: {stopped:?}"
    );

    // The stopped cat is not dead: fg resumes it and it reads the next line.
    machine.feed_terminal_input(b"fg\n");
    let _ = run(&mut machine);
    machine.feed_terminal_input(b"second-line\n");
    let echoed = run(&mut machine);
    assert!(
        echoed.contains("second-line") && !echoed.contains("not found"),
        "cat did not resume reading after fg (a dead cat leaves the line \
         to the shell, which rejects it as a command): {echoed:?}"
    );

    // And the interrupt still ends it: back to a working shell.
    machine.feed_terminal_input(b"\x03");
    let _ = run(&mut machine);
    machine.feed_terminal_input(b"echo after-jobctl\n");
    let echoed = run(&mut machine);
    assert!(
        echoed.contains("after-jobctl"),
        "the shell did not run a command after the job-control cycle: {echoed:?}"
    );
}

/// A blocking syscall interrupted by a handler ends with `EINTR` unless the
/// handler asked for a restart. Nothing in the runtime returned `EINTR`
/// before this: every wait restarted, which is `SA_RESTART` semantics applied
/// to handlers that never asked for them. A program that breaks out of a
/// blocking read by catching a signal would wait forever.
const EINTR_FIXTURE: &str = r#"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t hits = 0;
static void on_int(int s) { (void)s; hits++; }

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_int;
    if (argc > 1 && strcmp(argv[1], "restart") == 0) sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);
    printf("ready\n");
    fflush(stdout);

    char buf[64];
    ssize_t n = read(0, buf, sizeof buf);
    if (n < 0) {
        printf("read failed errno=%d hits=%d\n", errno, hits);
        fflush(stdout);
        return errno == EINTR ? 0 : 1;
    }
    buf[n] = 0;
    printf("read %zd bytes hits=%d: %s", n, hits, buf);
    fflush(stdout);
    return 0;
}
"#;

fn eintr_machine(image: Vec<u8>, arg: Option<&str>) -> Machine {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/fixture", image, 0o755)
        .expect("add fixture");
    let mut argv = vec![b"fixture".to_vec()];
    if let Some(arg) = arg {
        argv.push(arg.as_bytes().to_vec());
    }
    machine.set_args(argv, vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/fixture").expect("ELF load failed");
    machine.install_pty_stdio(24, 80);
    machine
}

#[test]
fn an_interrupted_read_returns_eintr_unless_the_handler_asked_for_a_restart() {
    let Some(image) = compile_c("eintr", EINTR_FIXTURE, &[]) else {
        return;
    };
    let step = |machine: &mut Machine| {
        machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
        machine.run();
        String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned()
    };

    // Without SA_RESTART the read ends, and the handler ran first.
    let mut plain = eintr_machine(image.clone(), None);
    let ready = step(&mut plain);
    assert!(ready.contains("ready"), "fixture did not start: {ready:?}");
    assert!(
        plain.awaiting_terminal_input(),
        "fixture should be blocked in read"
    );
    plain.feed_terminal_input(b"\x03");
    let interrupted = step(&mut plain);
    assert!(
        interrupted.contains("read failed errno=4") && interrupted.contains("hits=1"),
        "expected EINTR after one handler run: {interrupted:?}"
    );

    // With SA_RESTART the same signal runs the same handler and the read
    // carries on, returning the line typed afterwards.
    let mut restarting = eintr_machine(image, Some("restart"));
    let ready = step(&mut restarting);
    assert!(ready.contains("ready"), "fixture did not start: {ready:?}");
    restarting.feed_terminal_input(b"\x03");
    let after_signal = step(&mut restarting);
    assert!(
        !after_signal.contains("read failed"),
        "SA_RESTART should not surface EINTR: {after_signal:?}"
    );
    restarting.feed_terminal_input(b"typed-after-the-signal\n");
    let delivered = step(&mut restarting);
    assert!(
        delivered.contains("typed-after-the-signal") && delivered.contains("hits=1"),
        "the restarted read should return the typed line: {delivered:?}"
    );
}

/// A background process group may not read the terminal. Without the rule it
/// simply does, and the keystrokes meant for the shell disappear into it —
/// the user types a command and nothing happens.
#[test]
fn a_background_reader_is_stopped_instead_of_stealing_keystrokes() {
    let Some(image) = busybox() else {
        return;
    };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/busybox", image, 0o755)
        .expect("add busybox");
    for applet in ["sh", "cat", "echo"] {
        machine
            .add_symlink(format!("/bin/{applet}").as_bytes(), b"/bin/busybox")
            .expect("applet link");
    }
    machine.set_args(
        vec![b"sh".to_vec(), b"-i".to_vec()],
        vec![
            b"PATH=/bin".to_vec(),
            b"TERM=xterm".to_vec(),
            b"HOME=/root".to_vec(),
            b"PS1=$ ".to_vec(),
        ],
    );
    machine.load(b"/bin/sh").expect("ELF load failed");
    machine.install_pty_stdio(24, 80);

    let run = |machine: &mut Machine| {
        machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
        machine.run();
        String::from_utf8_lossy(&machine.drain_terminal_output()).into_owned()
    };

    let prompt = run(&mut machine);
    assert!(prompt.contains('$'), "no shell prompt: {prompt:?}");

    // `cat` in the background wants the terminal it is not the foreground of.
    machine.feed_terminal_input(b"cat &\n");
    let _ = run(&mut machine);

    // The shell's own account of what the terminal did. BusyBox names the
    // reason: without the rule this reads "Running", and the background `cat`
    // sits in the read competing for every keystroke.
    machine.feed_terminal_input(b"jobs\n");
    let jobs = run(&mut machine);
    assert!(
        jobs.contains("Stopped (tty input)"),
        "the background reader was not stopped by the terminal: {jobs:?}"
    );

    // And the shell is still the one being talked to.
    machine.feed_terminal_input(b"echo keystrokes-reached-the-shell\n");
    let echoed = run(&mut machine);
    assert!(
        echoed.contains("keystrokes-reached-the-shell"),
        "the shell stopped responding after the background reader: {echoed:?}"
    );
}

#[test]
fn background_terminal_state_changes_stop_with_sigttou_even_without_tostop() {
    let Some(image) = compile_c(
        "background_tty_ioctl",
        r#"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

static int stopped_by_sigttou(int slave, int operation) {
    pid_t child = fork();
    if (child < 0) return 0;
    if (child == 0) {
        setpgid(0, 0);
        if (operation == 0) {
            struct termios term;
            if (tcgetattr(slave, &term) < 0) _exit(10);
            term.c_lflag ^= ECHO;
            tcsetattr(slave, TCSANOW, &term);
        } else {
            tcsetpgrp(slave, getpgrp());
        }
        _exit(11);
    }
    int status = 0;
    if (waitpid(child, &status, WUNTRACED) != child) return 0;
    int ok = WIFSTOPPED(status) && WSTOPSIG(status) == SIGTTOU;
    kill(child, SIGKILL);
    waitpid(child, &status, 0);
    return ok;
}

int main(void) {
    int master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    int unlock = 0, number = 0;
    if (master < 0 || ioctl(master, TIOCSPTLCK, &unlock) < 0 ||
        ioctl(master, TIOCGPTN, &number) < 0) return 1;
    char path[64];
    snprintf(path, sizeof path, "/dev/pts/%d", number);
    int slave = open(path, O_RDWR | O_NOCTTY);
    if (slave < 0) return 2;
    if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) < 0) return 3;
    if (tcsetpgrp(slave, getpgrp()) < 0) return 4;

    int attr = stopped_by_sigttou(slave, 0);
    int pgrp = stopped_by_sigttou(slave, 1);
    printf("tcsetattr=%d tcsetpgrp=%d\n", attr, pgrp);
    return attr && pgrp ? 0 : 5;
}
"#,
        &["-std=gnu17", "-D_GNU_SOURCE"],
    ) else {
        return;
    };

    let (exit, output) = run(image);
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "background tty ioctl fixture failed: {output}"
    );
    assert!(
        output.contains("tcsetattr=1 tcsetpgrp=1"),
        "one background ioctl escaped SIGTTOU: {output}"
    );
}

/// `tcsetattr(TCSAFLUSH)` is how a program changes terminal mode without
/// letting keystrokes typed under the old mode be read back under the new
/// one. Returning ENOTTY for it stops any program that switches modes —
/// which is every program that runs a command on a terminal of its own.
#[test]
fn changing_terminal_mode_discards_what_was_typed_under_the_old_one() {
    let Some(image) = compile_c(
        "tcsaflush",
        r#"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/ioctl.h>

int main(void) {
    int master = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    int unlock = 0, n = 0;
    ioctl(master, TIOCSPTLCK, &unlock);
    ioctl(master, TIOCGPTN, &n);
    char path[64];
    snprintf(path, sizeof path, "/dev/pts/%d", n);
    int slave = open(path, O_RDWR | O_NOCTTY);

    struct termios t;
    tcgetattr(slave, &t);
    t.c_lflag &= ~(ICANON | ECHO);

    /* Type ahead, then switch modes. The typed bytes must not survive. */
    write(master, "stale", 5);
    errno = 0;
    if (tcsetattr(slave, TCSAFLUSH, &t) < 0) {
        printf("TCSAFLUSH refused: %s\n", strerror(errno));
        return 1;
    }

    /* Fresh input under the new settings is what the program should see. */
    write(master, "fresh", 5);
    char buf[32];
    ssize_t got = read(slave, buf, sizeof buf);
    if (got < 0) { printf("read failed: %s\n", strerror(errno)); return 1; }
    buf[got] = 0;
    printf("read [%s]\n", buf);

    /* TCIOFLUSH must drop both directions. */
    write(master, "dropme", 6);
    errno = 0;
    if (tcflush(slave, TCIOFLUSH) < 0) {
        printf("tcflush refused: %s\n", strerror(errno));
        return 1;
    }
    write(master, "kept", 4);
    got = read(slave, buf, sizeof buf);
    if (got < 0) { printf("second read failed: %s\n", strerror(errno)); return 1; }
    buf[got] = 0;
    printf("after flush [%s]\n", buf);
    return 0;
}
"#,
        &["-std=gnu17", "-D_GNU_SOURCE"],
    ) else {
        return;
    };

    let (exit, output) = run(image);
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "fixture did not exit cleanly: {output}"
    );
    assert!(
        output.contains("read [fresh]"),
        "type-ahead survived a mode change: {output}"
    );
    assert!(
        output.contains("after flush [kept]"),
        "tcflush did not discard queued input: {output}"
    );
}
