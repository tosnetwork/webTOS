//! Milestone-5 workload gates: event-loop primitives (eventfd, timerfd,
//! epoll) and networking through the explicit host broker (HTTP fetch, UDP
//! DNS, denied-by-default).
//!
//! C fixtures are compiled with the host `gcc`; network gates use the
//! pinned Alpine minirootfs plus loopback servers owned by the test. Every
//! test skips with a message when a prerequisite is missing.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use linux_compat::net::{ConnectStatus, HostBroker, NativeBroker, NetworkBroker, RecvOutcome};
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
}

fn compile_c(name: &str, source: &str, extra: &[&str]) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-m5-fixture");
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
    Run { exit, output }
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
fn eventfd_wakes_a_blocked_reader() {
    let source = r#"
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <unistd.h>
static int efd;
static void *worker(void *arg) {
    (void)arg;
    uint64_t v = 5;
    write(efd, &v, sizeof(v));
    return 0;
}
int main(void) {
    efd = eventfd(0, 0);
    if (efd < 0) return 1;
    pthread_t t;
    if (pthread_create(&t, 0, worker, 0)) return 2;
    uint64_t got = 0;
    if (read(efd, &got, sizeof(got)) != sizeof(got)) return 3;
    pthread_join(t, 0);
    printf("eventfd got %llu\n", (unsigned long long)got);
    return got == 5 ? 0 : 4;
}
"#;
    let Some(image) = compile_c("efd", source, &["-pthread"]) else {
        return;
    };
    let run = run_image(image, "efd");
    expect_clean(&run);
    assert!(
        run.output.contains("eventfd got 5"),
        "output: {:?}",
        run.output
    );
}

/// Edge-triggered epoll (`EPOLLET`): a fd that stays readable must fire only
/// once per not-ready→ready transition, not on every wait. This is what
/// mio/tokio relies on — without it, an async runtime's wakeup eventfd is
/// reported ready on every `epoll_wait`, spinning the reactor forever
/// (observed running a real Codex binary: millions of `epoll_pwait` calls,
/// each returning the same fd, no progress). Level-triggered interest, by
/// contrast, must keep reporting while the fd stays ready.
#[test]
fn epoll_edge_triggered_fires_once_per_edge() {
    let source = r#"
#include <stdio.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
int main(void) {
    struct epoll_event out[8];
    uint64_t one = 1, got = 0;

    /* Edge-triggered: fires once, then silent until re-armed. */
    int efd = eventfd(0, EFD_NONBLOCK);
    int ep = epoll_create1(0);
    struct epoll_event ev; ev.events = EPOLLIN | EPOLLET; ev.data.u64 = 42;
    epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev);
    write(efd, &one, sizeof(one));            /* not-ready -> ready edge */
    int n1 = epoll_wait(ep, out, 8, 0);       /* edge delivered */
    int n2 = epoll_wait(ep, out, 8, 0);       /* still ready, no new edge */
    /* Re-arm the way a reactor does: drain to not-ready, observe it, then a
       fresh edge fires again. */
    if (read(efd, &got, sizeof(got)) != sizeof(got)) return 10;
    int arm = epoll_wait(ep, out, 8, 0);      /* observes not-ready, re-arms */
    write(efd, &one, sizeof(one));            /* fresh not-ready -> ready */
    int n3 = epoll_wait(ep, out, 8, 0);

    /* Level-triggered: keeps reporting while ready. */
    int lfd = eventfd(0, EFD_NONBLOCK);
    int lp = epoll_create1(0);
    struct epoll_event lv; lv.events = EPOLLIN; lv.data.u64 = 7;
    epoll_ctl(lp, EPOLL_CTL_ADD, lfd, &lv);
    write(lfd, &one, sizeof(one));
    int m1 = epoll_wait(lp, out, 8, 0);
    int m2 = epoll_wait(lp, out, 8, 0);

    printf("ET n1=%d n2=%d arm=%d rearm=%d LT m1=%d m2=%d\n",
           n1, n2, arm, n3, m1, m2);
    return 0;
}

"#;
    let Some(image) = compile_c("epollet", source, &[]) else {
        return;
    };
    let run = run_image(image, "epollet");
    expect_clean(&run);
    assert!(
        run.output
            .contains("ET n1=1 n2=0 arm=0 rearm=1 LT m1=1 m2=1"),
        "edge/level epoll semantics wrong; output: {:?}",
        run.output
    );
}

/// `EPOLLONESHOT` is how Bun and other modern reactors keep a writable fd
/// from being returned forever. Delivery disables the interest regardless of
/// level/edge mode; only `EPOLL_CTL_MOD` rearms it.
#[test]
fn epoll_oneshot_disarms_until_mod_rearms_it() {
    let source = r#"
#include <stdio.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

int main(void) {
    int efd = eventfd(1, EFD_NONBLOCK);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (efd < 0 || ep < 0) return 1;
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLOUT | EPOLLONESHOT,
        .data.u64 = 99,
    };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, efd, &ev)) return 2;
    struct epoll_event out;
    int first = epoll_wait(ep, &out, 1, 0);
    int disabled = epoll_wait(ep, &out, 1, 0);
    if (epoll_ctl(ep, EPOLL_CTL_MOD, efd, &ev)) return 3;
    int rearmed = epoll_wait(ep, &out, 1, 0);
    int disabled_again = epoll_wait(ep, &out, 1, 0);
    printf("oneshot first=%d disabled=%d rearmed=%d disabled_again=%d\n",
           first, disabled, rearmed, disabled_again);
    return first == 1 && disabled == 0 && rearmed == 1 && disabled_again == 0
        ? 0 : 4;
}
"#;
    let Some(image) = compile_c("epoll-oneshot", source, &[]) else {
        return;
    };
    let run = run_image(image, "epoll-oneshot");
    expect_clean(&run);
    assert!(
        run.output
            .contains("oneshot first=1 disabled=0 rearmed=1 disabled_again=0"),
        "EPOLLONESHOT semantics wrong; output: {:?}",
        run.output
    );
}

#[test]
fn closing_an_epoll_target_drops_oneshot_state_before_fd_reuse() {
    let source = r#"
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

int main(void) {
    int old = eventfd(1, EFD_NONBLOCK);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (old < 0 || ep < 0) return 1;
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLONESHOT,
        .data.u64 = 41,
    };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, old, &ev)) return 2;
    struct epoll_event out;
    if (epoll_wait(ep, &out, 1, 0) != 1) return 3;
    if (close(old)) return 4;

    int replacement = eventfd(1, EFD_NONBLOCK);
    if (replacement != old) return 5;
    ev.data.u64 = 42;
    if (epoll_ctl(ep, EPOLL_CTL_ADD, replacement, &ev)) return 6;
    int delivered = epoll_wait(ep, &out, 1, 0);

    errno = 0;
    int absent = eventfd(0, EFD_NONBLOCK);
    int mod = epoll_ctl(ep, EPOLL_CTL_MOD, absent, &ev);
    printf("reuse delivered=%d data=%llu mod=%d errno=%d\n",
           delivered, (unsigned long long)out.data.u64, mod, errno);
    return delivered == 1 && out.data.u64 == 42 && mod == -1 && errno == ENOENT
        ? 0 : 7;
}
"#;
    let Some(image) = compile_c("epoll-close-reuse", source, &[]) else {
        return;
    };
    let run = run_image(image, "epoll-close-reuse");
    expect_clean(&run);
    assert!(
        run.output
            .contains("reuse delivered=1 data=42 mod=-1 errno=2"),
        "epoll close/reuse semantics wrong; output: {:?}",
        run.output
    );
}

#[test]
fn dup2_replacement_drops_the_destination_epoll_registration() {
    let source = r#"
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

int main(void) {
    int destination = eventfd(1, EFD_NONBLOCK);
    int source = eventfd(1, EFD_NONBLOCK);
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (destination < 0 || source < 0 || ep < 0) return 1;
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLONESHOT,
        .data.u64 = 51,
    };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, destination, &ev)) return 2;
    struct epoll_event out;
    if (epoll_wait(ep, &out, 1, 0) != 1) return 3;
    if (dup2(source, destination) != destination) return 4;

    ev.data.u64 = 52;
    errno = 0;
    int added = epoll_ctl(ep, EPOLL_CTL_ADD, destination, &ev);
    int delivered = epoll_wait(ep, &out, 1, 0);
    printf("dup2 added=%d errno=%d delivered=%d data=%llu\n",
           added, errno, delivered, (unsigned long long)out.data.u64);
    return added == 0 && delivered == 1 && out.data.u64 == 52 ? 0 : 5;
}
"#;
    let Some(image) = compile_c("epoll-dup2-replace", source, &[]) else {
        return;
    };
    let run = run_image(image, "epoll-dup2-replace");
    expect_clean(&run);
    assert!(
        run.output
            .contains("dup2 added=0 errno=0 delivered=1 data=52"),
        "epoll dup2 replacement semantics wrong; output: {:?}",
        run.output
    );
}

#[test]
fn exec_drops_cloexec_target_from_surviving_epoll_instance() {
    let source = r#"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 3) {
        int target = atoi(argv[1]);
        int ep = atoi(argv[2]);
        int replacement = eventfd(1, EFD_NONBLOCK);
        if (replacement != target) return 10;
        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLONESHOT,
            .data.u64 = 62,
        };
        errno = 0;
        int added = epoll_ctl(ep, EPOLL_CTL_ADD, replacement, &ev);
        struct epoll_event out;
        int delivered = epoll_wait(ep, &out, 1, 0);
        printf("exec added=%d errno=%d delivered=%d data=%llu\n",
               added, errno, delivered, (unsigned long long)out.data.u64);
        return added == 0 && delivered == 1 && out.data.u64 == 62 ? 0 : 11;
    }

    int target = eventfd(1, EFD_NONBLOCK | EFD_CLOEXEC);
    int ep = epoll_create1(0);
    if (target < 0 || ep < 0) return 1;
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLONESHOT,
        .data.u64 = 61,
    };
    if (epoll_ctl(ep, EPOLL_CTL_ADD, target, &ev)) return 2;
    struct epoll_event out;
    if (epoll_wait(ep, &out, 1, 0) != 1) return 3;
    char target_text[32], ep_text[32];
    snprintf(target_text, sizeof(target_text), "%d", target);
    snprintf(ep_text, sizeof(ep_text), "%d", ep);
    execl("/bin/epoll-exec-cloexec", "epoll-exec-cloexec",
          target_text, ep_text, (char *)0);
    return 4;
}
"#;
    let Some(image) = compile_c("epoll-exec-cloexec", source, &[]) else {
        return;
    };
    let run = run_image(image, "epoll-exec-cloexec");
    expect_clean(&run);
    assert!(
        run.output
            .contains("exec added=0 errno=0 delivered=1 data=62"),
        "epoll close-on-exec semantics wrong; output: {:?}",
        run.output
    );
}

#[test]
fn epoll_create_variants_take_flags_from_the_linux_abi_position() {
    let source = r#"
#include <fcntl.h>
#include <stdio.h>
#include <sys/epoll.h>

int main(void) {
    int legacy = epoll_create(7);
    int modern = epoll_create1(EPOLL_CLOEXEC);
    if (legacy < 0 || modern < 0) return 1;
    int legacy_flags = fcntl(legacy, F_GETFD);
    int modern_flags = fcntl(modern, F_GETFD);
    printf("epoll flags legacy=%d modern=%d\n", legacy_flags, modern_flags);
    return legacy_flags == 0 && modern_flags == FD_CLOEXEC ? 0 : 2;
}
"#;
    let Some(image) = compile_c("epoll-create-flags", source, &[]) else {
        return;
    };
    let run = run_image(image, "epoll-create-flags");
    expect_clean(&run);
    assert!(
        run.output.contains("epoll flags legacy=0 modern=1"),
        "epoll create argument mapping wrong; output: {:?}",
        run.output
    );
}

/// Edge-triggered epoll must track the read and write edges *separately*. A
/// socket registered `EPOLLIN|EPOLLOUT|EPOLLET` fires its writable edge first
/// (an empty send buffer is writable). If that delivered OUT edge suppressed
/// the whole fd, the readable edge that arrives later — the TLS ServerHello on
/// a freshly connected socket — would never be reported, and the reactor would
/// park watching nothing and time the handshake out. Conflating the directions
/// is exactly the failure seen bringing up a real HTTPS client: connect →
/// ClientHello → (ServerHello arrives, never delivered) → timeout → close.
#[test]
fn epoll_edge_read_and_write_are_independent() {
    let source = r#"
#include <stdio.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return 1;
    struct epoll_event out[8];
    int ep = epoll_create1(0);
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET; ev.data.u64 = 9;
    epoll_ctl(ep, EPOLL_CTL_ADD, sv[0], &ev);

    /* Empty send buffer -> writable edge fires; not readable yet. */
    int n1 = epoll_wait(ep, out, 8, 0);
    int w1 = (n1 == 1) && (out[0].events & EPOLLOUT) && !(out[0].events & EPOLLIN);
    /* Still writable, no new edge. */
    int n2 = epoll_wait(ep, out, 8, 0);
    /* Peer writes: a fresh readable edge must fire even though the writable
       edge already fired on this same fd. */
    char b = 'x';
    if (write(sv[1], &b, 1) != 1) return 2;
    int n3 = epoll_wait(ep, out, 8, 0);
    int r3 = (n3 == 1) && (out[0].events & EPOLLIN);

    printf("w1=%d n2=%d r3=%d\n", w1, n2, r3);
    return 0;
}
"#;
    let Some(image) = compile_c("epoll_rw_edge", source, &[]) else {
        return;
    };
    let run = run_image(image, "epoll_rw_edge");
    expect_clean(&run);
    assert!(
        run.output.contains("w1=1 n2=0 r3=1"),
        "read/write edges not independent; output: {:?}",
        run.output
    );
}

/// `FIONBIO` is a general fd ioctl (set non-blocking), not tty-specific: it
/// must succeed on a pipe/socket and actually flip `O_NONBLOCK`, not return
/// `ENOTTY`. A real Codex binary sets it on an internal pipe and unwraps the
/// result; returning ENOTTY there panicked it.
#[test]
fn fionbio_sets_nonblocking_on_a_pipe() {
    let source = r#"
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
int main(void) {
    int fds[2];
    if (pipe(fds)) return 1;
    int on = 1;
    if (ioctl(fds[0], FIONBIO, &on) != 0) return 2;   /* must not ENOTTY */
    if (!(fcntl(fds[0], F_GETFL) & O_NONBLOCK)) return 3;
    int off = 0;
    if (ioctl(fds[0], FIONBIO, &off) != 0) return 4;
    if (fcntl(fds[0], F_GETFL) & O_NONBLOCK) return 5;
    printf("fionbio ok\n");
    return 0;
}
"#;
    let Some(image) = compile_c("fionbio", source, &[]) else {
        return;
    };
    let run = run_image(image, "fionbio");
    expect_clean(&run);
    assert!(
        run.output.contains("fionbio ok"),
        "output: {:?}",
        run.output
    );
}

#[test]
fn timerfd_fires_through_the_time_warp() {
    let source = r#"
#include <stdio.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>
int main(void) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (tfd < 0) return 1;
    struct itimerspec spec = {0};
    spec.it_value.tv_nsec = 30 * 1000 * 1000; // 30 ms
    if (timerfd_settime(tfd, 0, &spec, 0)) return 2;
    uint64_t expirations = 0;
    if (read(tfd, &expirations, sizeof(expirations)) != sizeof(expirations)) return 3;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long long elapsed_ms = (t1.tv_sec - t0.tv_sec) * 1000LL + (t1.tv_nsec - t0.tv_nsec) / 1000000LL;
    printf("timerfd fired %llu time(s) after %lld ms\n",
           (unsigned long long)expirations, elapsed_ms);
    return (expirations == 1 && elapsed_ms >= 30) ? 0 : 4;
}
"#;
    let Some(image) = compile_c("tfd", source, &[]) else {
        return;
    };
    let run = run_image(image, "tfd");
    expect_clean(&run);
    assert!(
        run.output.contains("timerfd fired 1"),
        "output: {:?}",
        run.output
    );
}

#[test]
fn epoll_reports_pipe_readiness_across_processes() {
    let source = r#"
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <unistd.h>
int main(void) {
    int p[2];
    if (pipe(p)) return 1;
    pid_t pid = fork();
    if (pid < 0) return 2;
    if (pid == 0) {
        close(p[0]);
        write(p[1], "ping", 4);
        close(p[1]);
        _exit(0);
    }
    close(p[1]);
    int ep = epoll_create1(0);
    if (ep < 0) return 3;
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.fd = p[0];
    if (epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev)) return 4;
    struct epoll_event out[4];
    int n = epoll_wait(ep, out, 4, -1);
    if (n != 1 || out[0].data.fd != p[0]) return 5;
    char buf[8] = {0};
    if (read(p[0], buf, sizeof(buf)) != 4 || strcmp(buf, "ping")) return 6;
    int status = 0;
    waitpid(pid, &status, 0);
    printf("epoll saw %d event(s), payload %s\n", n, buf);
    return 0;
}
"#;
    let Some(image) = compile_c("ep", source, &[]) else {
        return;
    };
    let run = run_image(image, "ep");
    expect_clean(&run);
    assert!(
        run.output.contains("epoll saw 1"),
        "output: {:?}",
        run.output
    );
}

// ── Networking through the broker ───────────────────────────────────────────

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

fn run_argv(machine: &mut Machine, path: &str, args: &[&str]) -> Run {
    let argv: Vec<Vec<u8>> = args.iter().map(|a| a.as_bytes().to_vec()).collect();
    machine.set_args(
        argv,
        vec![b"PATH=/bin:/usr/bin:/sbin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine.load(path.as_bytes()).expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    if let CpuExit::IllegalInstruction { rip } = exit {
        let mut instruction = [0_u8; 15];
        let readable = machine
            .vm_mut()
            .cpu
            .mem
            .read_bytes(rip, &mut instruction, icicle_cpu::mem::perm::NONE)
            .is_ok();
        if readable {
            eprintln!("illegal instruction at {rip:#x}: {instruction:02x?}");
        } else {
            eprintln!("illegal instruction at {rip:#x}: <unmapped>");
        }
    }
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Run { exit, output }
}

/// Serves one minimal HTTP response per connection, forever.
fn spawn_http_server() -> SocketAddrV4 {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = match listener.local_addr().expect("local addr") {
        std::net::SocketAddr::V4(addr) => addr,
        _ => unreachable!("bound to IPv4"),
    };
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0_u8; 2048];
            let mut seen = Vec::new();
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
                if seen.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let body = "hello-from-webtos-m5";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    addr
}

/// Answers every DNS query with an A record for 10.0.0.1, forever.
fn spawn_dns_server() -> SocketAddrV4 {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = match socket.local_addr().expect("local addr") {
        std::net::SocketAddr::V4(addr) => addr,
        _ => unreachable!("bound to IPv4"),
    };
    std::thread::spawn(move || {
        let mut buf = [0_u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            if n < 12 {
                continue;
            }
            let query = &buf[..n];
            let mut response = Vec::with_capacity(n + 16);
            response.extend_from_slice(&query[..2]); // transaction id
            response.extend_from_slice(&[0x81, 0x80]); // standard response, no error
            response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]); // 1 question, 1 answer
            response.extend_from_slice(&query[12..]); // echo the question
            response.extend_from_slice(&[0xc0, 0x0c]); // name: pointer to question
            response.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
            response.extend_from_slice(&[0, 0, 0, 60]); // TTL
            response.extend_from_slice(&[0, 4, 10, 0, 0, 1]); // 10.0.0.1
            let _ = socket.send_to(&response, from);
        }
    });
    addr
}

#[test]
fn wget_fetches_http_through_the_broker() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let server = spawn_http_server();

    // The guest talks to a stable guest-visible address; the broker rewrites
    // it to the test server and refuses everything else.
    let mut broker = NativeBroker::new();
    broker.redirect(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80), server);
    broker.restrict_to_redirects();
    machine.set_network(Rc::new(RefCell::new(broker)));

    let run = run_argv(
        &mut machine,
        "/usr/bin/wget",
        &["wget", "-q", "-O", "-", "http://10.0.0.1/hello"],
    );
    expect_clean(&run);
    assert_eq!(
        run.output, "hello-from-webtos-m5",
        "wget output: {:?}",
        run.output
    );
}

#[test]
fn nslookup_resolves_through_udp_dns() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let dns = spawn_dns_server();

    let mut broker = NativeBroker::new();
    broker.redirect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53), dns);
    broker.restrict_to_redirects();
    machine.set_network(Rc::new(RefCell::new(broker)));
    machine
        .add_file(
            b"/etc/resolv.conf",
            b"nameserver 127.0.0.1\n".to_vec(),
            0o644,
        )
        .expect("resolv.conf");

    let run = run_argv(
        &mut machine,
        "/usr/bin/nslookup",
        &["nslookup", "webtos.test", "127.0.0.1"],
    );
    expect_clean(&run);
    assert!(
        run.output.contains("10.0.0.1"),
        "nslookup output: {:?}",
        run.output
    );
}

/// IPv6 TCP must be a first-class client socket family even when the test does
/// not make an external connection. Modern agent CLIs create an IPv6 endpoint
/// before their IPv4 Happy-Eyeballs fallback; rejecting socket(2) itself makes
/// that normal probe look like a total network failure.
#[test]
fn ipv6_tcp_socket_reports_a_real_sockaddr_in6_identity() {
    let source = r#"
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_in6 addr = {0};
    socklen_t len = sizeof(addr);
    if (getsockname(fd, (struct sockaddr *)&addr, &len) != 0) return 2;
    if (addr.sin6_family != AF_INET6 || len != sizeof(addr)) return 3;
    puts("ipv6-tcp-socket-ok");
    return 0;
}

"#;
    let Some(image) = compile_c("ipv6-tcp-socket", source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/ipv6-tcp-socket", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"ipv6-tcp-socket".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/ipv6-tcp-socket")
        .expect("ELF load failed");
    machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "IPv6 guest output: {output:?}"
    );
    assert!(
        output.contains("ipv6-tcp-socket-ok"),
        "IPv6 guest output: {output:?}"
    );
}

/// Native mode must carry an IPv6 TCP connection through the same explicit
/// broker boundary as IPv4. This is loopback-only: it proves address handling
/// without depending on public DNS or an external service.
#[test]
fn native_broker_connects_ipv6_tcp_without_reinterpreting_the_peer() {
    let listener = match TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("skipping IPv6 loopback broker test: {error}");
            return;
        }
    };
    let peer = match listener.local_addr().expect("listener address") {
        std::net::SocketAddr::V6(peer) => peer,
        std::net::SocketAddr::V4(_) => panic!("IPv6 listener returned IPv4 address"),
    };
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("IPv6 accept");
        let mut received = [0_u8; 4];
        stream.read_exact(&mut received).expect("IPv6 read");
        received
    });

    let mut broker = NativeBroker::new();
    let handle = broker.tcp_connect_v6(peer).expect("IPv6 broker connect");
    assert_eq!(broker.tcp_send(handle, b"ping").expect("IPv6 send"), 4);
    assert_eq!(server.join().expect("IPv6 server"), *b"ping");
}

/// `Machine::set_network` always inserts `MeteredBroker`; IPv6 cannot be
/// accidentally lost at that wrapper boundary. Agent runtimes commonly try
/// an IPv6 address before their IPv4 fallback, so returning EAFNOSUPPORT here
/// turns a valid native transport into a misleading generic connection error.
#[test]
fn metered_broker_forwards_ipv6_tcp_connections() {
    let listener = match TcpListener::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("skipping IPv6 loopback metered-broker test: {error}");
            return;
        }
    };
    let peer = match listener.local_addr().expect("listener address") {
        std::net::SocketAddr::V6(peer) => peer,
        std::net::SocketAddr::V4(_) => panic!("IPv6 listener returned IPv4 address"),
    };
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("IPv6 accept");
        let mut received = [0_u8; 4];
        stream.read_exact(&mut received).expect("IPv6 read");
        received
    });

    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
    let broker = machine
        .env()
        .network_broker()
        .expect("the metered broker installed by set_network");
    let handle = broker
        .borrow_mut()
        .tcp_connect_v6(peer)
        .expect("metered IPv6 broker connect");
    assert_eq!(broker.borrow_mut().tcp_send(handle, b"ping"), Ok(4));
    assert_eq!(server.join().expect("IPv6 server"), *b"ping");
}

/// Runtime network discovery uses an IPv6 UDP socket before its TLS client
/// opens TCP. Keep that native, metered path available: rejecting it makes a
/// valid network stack surface as an opaque `FailedToOpenSocket` error.
#[test]
fn guest_sends_ipv6_udp_through_the_metered_broker() {
    let listener = match UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0)) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("skipping IPv6 UDP loopback test: {error}");
            return;
        }
    };
    listener
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("read timeout");
    let port = listener.local_addr().expect("listener address").port();
    let source = format!(
        r#"
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {{
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_in6 local = {{0}};
    local.sin6_family = AF_INET6;
    local.sin6_addr = in6addr_any;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) return 2;
    struct sockaddr_in6 peer = {{0}};
    peer.sin6_family = AF_INET6;
    peer.sin6_port = htons({port});
    peer.sin6_addr = in6addr_loopback;
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != 0) return 3;
    struct sockaddr disconnected = {{ .sa_family = AF_UNSPEC }};
    if (connect(fd, &disconnected, sizeof(disconnected)) != 0) return 4;
    if (sendto(fd, "ping", 4, 0, (struct sockaddr *)&peer, sizeof(peer)) != 4) return 5;
    puts("ipv6-udp-ok");
    return 0;
}}
"#
    );
    let Some(image) = compile_c("ipv6-udp", &source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/ipv6-udp", image, 0o755)
        .expect("add fixture");
    machine.set_args(vec![b"ipv6-udp".to_vec()], vec![b"HOME=/root".to_vec()]);
    machine.load(b"/bin/ipv6-udp").expect("ELF load failed");
    machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "IPv6 UDP output: {output:?}"
    );
    let mut received = [0_u8; 4];
    let (count, _) = listener.recv_from(&mut received).expect("IPv6 UDP receive");
    assert_eq!(&received[..count], b"ping");
    assert!(
        output.contains("ipv6-udp-ok"),
        "IPv6 UDP output: {output:?}"
    );
}

/// DNS and modern runtime probes commonly use `sendmsg` with a header and a
/// payload in separate iovecs. UDP must emit those iovecs as one complete
/// datagram; forwarding just the first produces a syntactically malformed
/// query and makes higher layers report a misleading socket-open failure.
#[test]
fn guest_sendmsg_gathers_all_udp_iovecs_into_one_datagram() {
    let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP listener");
    listener
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("read timeout");
    let port = listener.local_addr().expect("listener address").port();
    let source = format!(
        r#"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

int main(void) {{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_in peer = {{0}};
    peer.sin_family = AF_INET;
    peer.sin_port = htons({port});
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    char first[] = "dns-";
    char second[] = "packet";
    struct iovec iov[] = {{
        {{ .iov_base = first, .iov_len = sizeof(first) - 1 }},
        {{ .iov_base = second, .iov_len = sizeof(second) - 1 }},
    }};
    struct msghdr msg = {{
        .msg_name = &peer,
        .msg_namelen = sizeof(peer),
        .msg_iov = iov,
        .msg_iovlen = 2,
    }};
    if (sendmsg(fd, &msg, 0) != 10) return 2;
    puts("udp-sendmsg-gather-ok");
    return 0;
}}
"#
    );
    let Some(image) = compile_c("udp-sendmsg-gather", &source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/udp-sendmsg-gather", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"udp-sendmsg-gather".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/udp-sendmsg-gather")
        .expect("ELF load failed");
    machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "UDP sendmsg output: {output:?}"
    );
    let mut received = [0_u8; 32];
    let (count, _) = listener.recv_from(&mut received).expect("UDP receive");
    assert_eq!(&received[..count], b"dns-packet");
    assert!(
        output.contains("udp-sendmsg-gather-ok"),
        "UDP sendmsg output: {output:?}"
    );
}

/// TLS libraries build a ClientHello with `writev(2)`.  A short write is
/// permitted, but silently forwarding only the first iovec while returning
/// success corrupts the record and is not a short write at all.
#[test]
fn guest_writev_gathers_all_tcp_iovecs_into_one_stream_write() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("TCP listener");
    listener
        .set_nonblocking(false)
        .expect("listener blocking mode");
    let port = listener.local_addr().expect("listener address").port();
    let received = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("TCP accept");
        let mut out = [0_u8; 32];
        let count = stream.read(&mut out).expect("TCP read");
        out[..count].to_vec()
    });
    let source = format!(
        r#"
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
int main(void) {{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_in peer = {{0}};
    peer.sin_family = AF_INET;
    peer.sin_port = htons({port});
    peer.sin_addr.s_addr = htonl(0x0a000002);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) return 2;
    char first[] = "TLS-";
    char second[] = "record";
    struct iovec iov[] = {{
        {{ .iov_base = first, .iov_len = 4 }},
        {{ .iov_base = second, .iov_len = 6 }},
    }};
    if (writev(fd, iov, 2) != 10) return 3;
    puts("tcp-writev-gather-ok");
    return 0;
}}
"#
    );
    let Some(image) = compile_c("tcp-writev-gather", &source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/tcp-writev-gather", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"tcp-writev-gather".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/tcp-writev-gather")
        .expect("ELF load failed");
    let mut broker = NativeBroker::new();
    broker.redirect(
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), port),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port),
    );
    broker.restrict_to_redirects();
    machine.set_network(Rc::new(RefCell::new(broker)));
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "TCP writev output: {output:?}"
    );
    assert_eq!(received.join().expect("TCP server"), b"TLS-record");
    assert!(
        output.contains("tcp-writev-gather-ok"),
        "TCP writev output: {output:?}"
    );
}

/// Glibc's resolver uses `sendmmsg` to submit A and AAAA queries together.
/// The batch must report a completed count and write each `msg_len`, rather
/// than degrading into ENOSYS before DNS ever leaves the guest.
#[test]
fn guest_sendmmsg_submits_each_udp_datagram_and_writes_lengths() {
    let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP listener");
    listener
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("read timeout");
    let port = listener.local_addr().expect("listener address").port();
    let source = format!(
        r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

int main(void) {{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_in peer = {{0}};
    peer.sin_family = AF_INET;
    peer.sin_port = htons({port});
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) return 2;
    char one[] = "A?";
    char two[] = "AAAA?";
    struct iovec iov[] = {{
        {{ .iov_base = one, .iov_len = sizeof(one) - 1 }},
        {{ .iov_base = two, .iov_len = sizeof(two) - 1 }},
    }};
    struct mmsghdr messages[2] = {{
        {{ .msg_hdr = {{ .msg_iov = &iov[0], .msg_iovlen = 1 }} }},
        {{ .msg_hdr = {{ .msg_iov = &iov[1], .msg_iovlen = 1 }} }},
    }};
    if (sendmmsg(fd, messages, 2, 0) != 2) return 3;
    if (messages[0].msg_len != 2 || messages[1].msg_len != 5) return 4;
    puts("udp-sendmmsg-batch-ok");
    return 0;
}}
"#
    );
    let Some(image) = compile_c("udp-sendmmsg-batch", &source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/udp-sendmmsg-batch", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"udp-sendmmsg-batch".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/udp-sendmmsg-batch")
        .expect("ELF load failed");
    machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "UDP sendmmsg output: {output:?}"
    );
    let mut first = [0_u8; 16];
    let mut second = [0_u8; 16];
    let (first_count, _) = listener.recv_from(&mut first).expect("first UDP receive");
    let (second_count, _) = listener.recv_from(&mut second).expect("second UDP receive");
    assert_eq!(&first[..first_count], b"A?");
    assert_eq!(&second[..second_count], b"AAAA?");
    assert!(
        output.contains("udp-sendmmsg-batch-ok"),
        "UDP sendmmsg output: {output:?}"
    );
}

/// `recvfrom` must preserve the caller's independent buffer/length state
/// across datagrams while writing back a sockaddr and its reduced length.
/// Resolver code performs this exact sequence for A and AAAA replies.
#[test]
fn guest_recvfrom_reads_two_udp_replies_without_corrupting_next_length() {
    let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP listener");
    listener
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("read timeout");
    let port = listener.local_addr().expect("listener address").port();
    let server = std::thread::spawn(move || {
        let mut request = [0_u8; 16];
        let (_, peer) = listener.recv_from(&mut request).expect("UDP request");
        listener.send_to(b"answer-a", peer).expect("first reply");
        listener
            .send_to(b"answer-aaaa", peer)
            .expect("second reply");
    });
    let source = format!(
        r#"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_in peer = {{0}};
    peer.sin_family = AF_INET;
    peer.sin_port = htons({port});
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) return 2;
    if (send(fd, "query", 5, 0) != 5) return 3;
    char first[32] = {{0}}, second[32] = {{0}};
    struct sockaddr_in from = {{0}};
    socklen_t from_len = sizeof(from);
    int a = recvfrom(fd, first, sizeof(first), 0, (struct sockaddr *)&from, &from_len);
    if (a != 8 || from_len != sizeof(from) || from.sin_family != AF_INET) return 4;
    from_len = sizeof(from);
    int b = recvfrom(fd, second, sizeof(second), 0, (struct sockaddr *)&from, &from_len);
    if (b != 11 || from_len != sizeof(from) || from.sin_family != AF_INET) return 5;
    if (memcmp(first, "answer-a", 8) || memcmp(second, "answer-aaaa", 11)) return 6;
    puts("udp-recvfrom-two-replies-ok");
    return 0;
}}
"#
    );
    let Some(image) = compile_c("udp-recvfrom-two-replies", &source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/udp-recvfrom-two-replies", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"udp-recvfrom-two-replies".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/udp-recvfrom-two-replies")
        .expect("ELF load failed");
    machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "UDP recvfrom output: {output:?}"
    );
    server.join().expect("UDP server");
    assert!(
        output.contains("udp-recvfrom-two-replies-ok"),
        "UDP recvfrom output: {output:?}"
    );
}

/// Event-loop DNS clients commonly use `FIONREAD` to size a receive buffer
/// after epoll marks a UDP socket readable.  Returning zero here makes the
/// client issue a legal but destructive zero-length `recvfrom`, silently
/// discarding the queued DNS reply before any TCP connection can be opened.
#[test]
fn guest_fionread_reports_the_next_udp_datagram_size_without_consuming_it() {
    let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP listener");
    listener
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("read timeout");
    let port = listener.local_addr().expect("listener address").port();
    let server = std::thread::spawn(move || {
        let mut request = [0_u8; 16];
        let (_, peer) = listener.recv_from(&mut request).expect("UDP request");
        listener.send_to(b"sized-reply", peer).expect("reply");
    });
    let source = format!(
        r#"
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_in peer = {{0}};
    peer.sin_family = AF_INET;
    peer.sin_port = htons({port});
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) return 2;
    if (send(fd, "q", 1, 0) != 1) return 3;
    int available = 0;
    for (int attempts = 0; attempts != 1000 && available == 0; ++attempts) {{
        if (ioctl(fd, FIONREAD, &available)) return 4;
        usleep(1000);
    }}
    if (available != 11) return 5;
    char reply[16] = {{0}};
    if (recvfrom(fd, reply, available, 0, 0, 0) != available) return 6;
    if (reply[0] != 's' || reply[10] != 'y') return 7;
    puts("udp-fionread-size-ok");
    return 0;
}}
"#
    );
    let Some(image) = compile_c("udp-fionread-size", &source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/udp-fionread-size", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"udp-fionread-size".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/udp-fionread-size")
        .expect("ELF load failed");
    machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "UDP FIONREAD output: {output:?}"
    );
    server.join().expect("UDP server");
    assert!(
        output.contains("udp-fionread-size-ok"),
        "UDP FIONREAD output: {output:?}"
    );
}

/// A zero-length `MSG_PEEK` is a readiness probe, not permission to discard
/// the pending datagram. Resolver runtimes use it between A/AAAA receives.
#[test]
fn guest_zero_length_udp_peek_does_not_consume_the_datagram() {
    let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("UDP listener");
    listener
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("read timeout");
    let port = listener.local_addr().expect("listener address").port();
    let server = std::thread::spawn(move || {
        let mut request = [0_u8; 16];
        let (_, peer) = listener.recv_from(&mut request).expect("UDP request");
        listener.send_to(b"reply", peer).expect("reply");
    });
    let source = format!(
        r#"
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_in peer = {{0}};
    peer.sin_family = AF_INET;
    peer.sin_port = htons({port});
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer))) return 2;
    if (send(fd, "q", 1, 0) != 1) return 3;
    char ignored;
    if (recvfrom(fd, &ignored, 0, MSG_PEEK, 0, 0) != 0) return 4;
    char reply[8] = {{0}};
    if (recvfrom(fd, reply, sizeof(reply), 0, 0, 0) != 5) return 5;
    if (reply[0] != 'r' || reply[4] != 'y') return 6;
    puts("udp-zero-peek-ok");
    return 0;
}}
"#
    );
    let Some(image) = compile_c("udp-zero-peek", &source, &[]) else {
        return;
    };
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/udp-zero-peek", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"udp-zero-peek".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/udp-zero-peek")
        .expect("ELF load failed");
    machine.set_network(Rc::new(RefCell::new(NativeBroker::new())));
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "UDP zero peek output: {output:?}"
    );
    server.join().expect("UDP server");
    assert!(
        output.contains("udp-zero-peek-ok"),
        "UDP zero peek output: {output:?}"
    );
}

/// A missing local name-service socket is an ordinary ENOENT probe, not a
/// global network denial. This must work even with no IP broker attached.
#[test]
fn unix_socket_absent_service_returns_enoent_without_a_network_broker() {
    let source = r#"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/var/run/nscd/socket");
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != -1) return 2;
    if (errno != ENOENT) return 3;
    puts("unix-enoent-fallback-ok");
    return 0;
}

"#;
    let Some(image) = compile_c("unix-enoent-fallback", source, &[]) else {
        return;
    };
    let run = run_image(image, "unix-enoent-fallback");
    expect_clean(&run);
    assert!(
        run.output.contains("unix-enoent-fallback-ok"),
        "UNIX probe output: {:?}",
        run.output
    );
}

/// A runtime may reserve a guest-local Unix control endpoint before any
/// helper connects to it. This must not be misclassified as an unsupported
/// network listener merely because host networking is denied.
#[test]
fn unix_control_listener_binds_and_listens_without_a_network_broker() {
    let source = r#"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/run/user/1000/control.sock");
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 2;
    if (listen(fd, 16) != 0) return 3;
    puts("unix-control-listener-ok");
    return 0;
}
"#;
    let Some(image) = compile_c("unix-control-listener", source, &[]) else {
        return;
    };
    let run = run_image(image, "unix-control-listener");
    expect_clean(&run);
    assert!(
        run.output.contains("unix-control-listener-ok"),
        "UNIX control listener output: {:?}",
        run.output
    );
}

/// Linux 5.11's epoll_pwait2 accepts a timespec timeout rather than the
/// millisecond integer used by epoll_wait. A zero timeout is a compact guest
/// regression for the syscall decoding and argument layout.
#[test]
fn epoll_pwait2_accepts_a_zero_timespec_timeout() {
    let source = r#"
#include <asm/unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    int ep = epoll_create1(EPOLL_CLOEXEC);
    if (ep < 0) return 1;
    struct epoll_event event;
    struct timespec timeout = {0, 0};
    long result = syscall(__NR_epoll_pwait2, ep, &event, 1, &timeout, 0, 0);
    if (result != 0) return 2;
    puts("epoll-pwait2-zero-timeout-ok");
    return 0;
}
"#;
    let Some(image) = compile_c("epoll-pwait2", source, &[]) else {
        return;
    };
    let run = run_image(image, "epoll-pwait2");
    expect_clean(&run);
    assert!(
        run.output.contains("epoll-pwait2-zero-timeout-ok"),
        "epoll_pwait2 output: {:?}",
        run.output
    );
}

/// The guest-local route view is deliberately limited to a deterministic
/// loopback address dump. It must nevertheless use the real netlink framing
/// expected by runtime address-discovery code.
#[test]
fn netlink_route_getaddr_returns_a_loopback_dump_and_done() {
    let source = r#"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return 1;
    struct sockaddr_nl local = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&local, sizeof(local))) return 2;
    struct sockaddr_nl reported = {0};
    socklen_t reported_len = sizeof(reported);
    if (getsockname(fd, (struct sockaddr *)&reported, &reported_len)) return 10;
    if (reported_len != sizeof(reported) || reported.nl_family != AF_NETLINK ||
        reported.nl_pid == 0 || reported.nl_groups != 0) return 11;
    struct { struct nlmsghdr hdr; struct ifaddrmsg addr; } req = {0};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETADDR;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 7;
    req.addr.ifa_family = AF_UNSPEC;
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&kernel, sizeof(kernel)) != sizeof(req)) return 3;
    char buf[512];
    /* The route response is a byte stream from the guest-local protocol
       queue. A partial recv must consume its byte, rather than replay it on
       the next call. */
    int first = recv(fd, buf, 1, 0);
    if (first != 1) return 4;
    unsigned char first_byte = (unsigned char)buf[0];
    struct sockaddr_nl sender = {0};
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    struct msghdr msg = { .msg_name = &sender, .msg_namelen = sizeof(sender), .msg_iov = &iov, .msg_iovlen = 1 };
    int n = recvmsg(fd, &msg, 0);
    if (n < 19) return 5;
    if (msg.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK || sender.nl_pid != 0) return 9;
    /* The first byte is the little-endian low byte of nlmsg_len (normally
       0x20 or larger), so a replay would put it at buf[0] here. The next byte
       must instead be the second length byte, usually zero. */
    if ((unsigned char)buf[0] == first_byte) return 6;
    unsigned char header[sizeof(struct nlmsghdr)];
    header[0] = first_byte;
    memcpy(header + 1, buf, sizeof(header) - 1);
    struct nlmsghdr *h = (struct nlmsghdr *)header;
    if (h->nlmsg_type != RTM_NEWADDR || h->nlmsg_seq != 7 || h->nlmsg_pid != reported.nl_pid) return 7;
    if (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) != -1 || errno != EAGAIN) return 8;
    puts("netlink-loopback-dump-ok");
    return 0;
}
"#;
    let Some(image) = compile_c("netlink-loopback-dump", source, &[]) else {
        return;
    };
    let run = run_image(image, "netlink-loopback-dump");
    expect_clean(&run);
    assert!(
        run.output.contains("netlink-loopback-dump-ok"),
        "netlink output: {:?}",
        run.output
    );
}

#[test]
fn network_is_denied_without_a_broker() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    // No broker attached: wget must fail, not silently succeed.
    let run = run_argv(
        &mut machine,
        "/usr/bin/wget",
        &["wget", "-q", "-O", "-", "http://10.0.0.1/hello"],
    );
    match run.exit {
        CpuExit::Halt { code: Some(code) } => {
            assert_ne!(
                code, 0,
                "wget must fail with no network; output: {:?}",
                run.output
            );
        }
        other => panic!("expected a clean failure, got {other:?}"),
    }
    assert!(
        !run.output.contains("hello-from-webtos-m5"),
        "no data must flow without a broker"
    );
}

/// Spawns `openssl s_server -WWW` with a fresh self-signed certificate,
/// serving files from a temp directory. Returns (address, child guard).
fn spawn_tls_server() -> Option<(SocketAddrV4, KillOnDrop)> {
    let dir = std::env::temp_dir().join("webtos-m5-tls");
    std::fs::create_dir_all(&dir).ok()?;
    std::fs::write(dir.join("hello.txt"), "hello-from-webtos-tls\n").ok()?;

    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    if !cert.exists() || !key.exists() {
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "3650",
                "-addext",
                "subjectAltName=IP:10.0.0.2",
            ])
            .arg("-keyout")
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .args(["-subj", "/CN=10.0.0.2"])
            .status();
        match status {
            Ok(status) if status.success() => {}
            _ => {
                eprintln!("skipping: openssl unavailable for certificate generation");
                return None;
            }
        }
    }

    // Grab a free port; a small race with s_server binding it is acceptable
    // in a test.
    let port = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .ok()?
        .local_addr()
        .ok()?
        .port();
    let child = Command::new("openssl")
        .args(["s_server", "-quiet", "-naccept", "8", "-WWW"])
        .args(["-accept", &format!("127.0.0.1:{port}")])
        .arg("-cert")
        .arg(&cert)
        .arg("-key")
        .arg(&key)
        .current_dir(&dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(_) => {
            eprintln!("skipping: openssl s_server unavailable");
            return None;
        }
    };
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);

    // Wait until the server accepts connections.
    for _ in 0..100 {
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::V4(addr),
            std::time::Duration::from_millis(100),
        )
        .is_ok()
        {
            return Some((addr, KillOnDrop(child)));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    eprintln!("skipping: openssl s_server did not come up");
    None
}

struct KillOnDrop(std::process::Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn wget_fetches_https_through_guest_tls() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let Some((server, _guard)) = spawn_tls_server() else {
        return;
    };

    // wget spawns the ssl_client applet (dynamic musl + OpenSSL 3 from the
    // rootfs), which performs the TLS handshake inside the guest over the
    // broker's TCP stream — the host never sees plaintext HTTP. The test
    // certificate is installed as the guest's trust anchor so the chain is
    // actually verified (no --no-check-certificate).
    let cert = std::fs::read(std::env::temp_dir().join("webtos-m5-tls/cert.pem"))
        .expect("test certificate");
    // Install the anchor both as the default CA file and in the hashed
    // certificate directory (the two default OpenSSL lookup paths).
    let hash = Command::new("openssl")
        .args(["x509", "-noout", "-subject_hash", "-in"])
        .arg(std::env::temp_dir().join("webtos-m5-tls/cert.pem"))
        .output()
        .expect("openssl x509");
    let hash = String::from_utf8_lossy(&hash.stdout).trim().to_string();
    machine
        .add_file(b"/etc/ssl/cert.pem", cert.clone(), 0o644)
        .expect("install trust anchor");
    machine
        .add_file(format!("/etc/ssl/certs/{hash}.0").as_bytes(), cert, 0o644)
        .expect("install hashed trust anchor");

    let mut broker = NativeBroker::new();
    broker.redirect(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 443), server);
    broker.restrict_to_redirects();
    machine.set_network(Rc::new(RefCell::new(broker)));

    let run = run_argv(
        &mut machine,
        "/usr/bin/wget",
        &["wget", "-q", "-O", "-", "https://10.0.0.2/hello.txt"],
    );
    expect_clean(&run);
    assert_eq!(
        run.output, "hello-from-webtos-tls\n",
        "wget https output: {:?}",
        run.output
    );
}

// ------------------------------------------------- host-driven broker gates

/// A test stand-in for the browser host: it decodes the broker's command
/// stream, performs each operation on real sockets, and feeds results back.
/// Destinations outside `allow` are refused without a connection attempt,
/// which is the deny-by-default policy the browser gateway enforces.
struct BrokerHost {
    allow: Vec<SocketAddrV4>,
    /// Guest-visible destination -> where the host actually sends it. The
    /// browser gateway resolves names and picks the real endpoint the same
    /// way; the guest never learns of the rewrite.
    redirects: std::collections::HashMap<SocketAddrV4, SocketAddrV4>,
    tcp: std::collections::HashMap<u64, std::net::TcpStream>,
    udp: std::collections::HashMap<u64, std::net::UdpSocket>,
    refused: Vec<SocketAddrV4>,
}

impl BrokerHost {
    fn new(allow: Vec<SocketAddrV4>) -> Self {
        Self {
            allow,
            redirects: std::collections::HashMap::new(),
            tcp: std::collections::HashMap::new(),
            udp: std::collections::HashMap::new(),
            refused: Vec::new(),
        }
    }

    fn redirect(&mut self, from: SocketAddrV4, to: SocketAddrV4) {
        self.redirects.insert(from, to);
        self.allow.push(from);
    }

    /// Applies policy: an allowed destination resolves to where the host
    /// will really send it; anything else is recorded and refused.
    fn permitted(&mut self, addr: SocketAddrV4) -> Option<SocketAddrV4> {
        if !self.allow.contains(&addr) {
            self.refused.push(addr);
            return None;
        }
        Some(self.redirects.get(&addr).copied().unwrap_or(addr))
    }

    /// Decodes and performs one batch of commands. Mirrors the encoding in
    /// `HostBroker::take_commands`, so a change there fails here first.
    fn perform(&mut self, stream: &[u8], broker: &Rc<RefCell<HostBroker>>) {
        let mut i = 0;
        let u32_at = |s: &[u8], i: usize| u32::from_le_bytes(s[i..i + 4].try_into().expect("u32"));
        let addr_at = |s: &[u8], i: usize| {
            SocketAddrV4::new(
                Ipv4Addr::new(s[i], s[i + 1], s[i + 2], s[i + 3]),
                u16::from_be_bytes(s[i + 4..i + 6].try_into().expect("port")),
            )
        };
        while i < stream.len() {
            let op = stream[i];
            let handle = u32_at(stream, i + 1) as u64;
            i += 5;
            match op {
                1 => {
                    let addr = addr_at(stream, i);
                    i += 6;
                    let Some(target) = self.permitted(addr) else {
                        broker.borrow_mut().deliver_error(handle, 101); // ENETUNREACH
                        continue;
                    };
                    match std::net::TcpStream::connect(std::net::SocketAddr::V4(target)) {
                        Ok(stream) => {
                            stream.set_nonblocking(true).expect("nonblocking");
                            self.tcp.insert(handle, stream);
                            broker.borrow_mut().deliver_connected(handle, None);
                        }
                        Err(_) => broker.borrow_mut().deliver_error(handle, 111), // ECONNREFUSED
                    }
                }
                2 => {
                    let len = u32_at(stream, i) as usize;
                    i += 4;
                    let bytes = &stream[i..i + len];
                    i += len;
                    if let Some(socket) = self.tcp.get_mut(&handle) {
                        socket.set_nonblocking(false).expect("blocking");
                        let _ = socket.write_all(bytes);
                        socket.set_nonblocking(true).expect("nonblocking");
                    }
                }
                3 => {
                    if let Some(socket) = self.tcp.get(&handle) {
                        let _ = socket.shutdown(std::net::Shutdown::Write);
                    }
                }
                4 => {
                    let socket =
                        std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("udp bind");
                    socket.set_nonblocking(true).expect("nonblocking");
                    self.udp.insert(handle, socket);
                }
                5 => {
                    let addr = addr_at(stream, i);
                    i += 6;
                    let len = u32_at(stream, i) as usize;
                    i += 4;
                    let bytes = &stream[i..i + len];
                    i += len;
                    let Some(target) = self.permitted(addr) else {
                        broker.borrow_mut().deliver_error(handle, 101);
                        continue;
                    };
                    if let Some(socket) = self.udp.get(&handle) {
                        let _ = socket.send_to(bytes, std::net::SocketAddr::V4(target));
                    }
                }
                6 => {
                    self.tcp.remove(&handle);
                    self.udp.remove(&handle);
                }
                other => panic!("unknown broker opcode {other}"),
            }
        }
    }

    /// Polls every open socket once and delivers whatever arrived. Returns
    /// true when anything was delivered.
    fn poll(&mut self, broker: &Rc<RefCell<HostBroker>>) -> bool {
        let mut delivered = false;
        let mut buf = [0_u8; 8192];
        let mut dead = Vec::new();
        for (&handle, socket) in self.tcp.iter_mut() {
            match socket.read(&mut buf) {
                Ok(0) => {
                    broker.borrow_mut().deliver_closed(handle);
                    dead.push(handle);
                    delivered = true;
                }
                Ok(n) => {
                    broker.borrow_mut().deliver_data(handle, &buf[..n]);
                    delivered = true;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    broker.borrow_mut().deliver_error(handle, 104); // ECONNRESET
                    dead.push(handle);
                    delivered = true;
                }
            }
        }
        for handle in dead {
            self.tcp.remove(&handle);
        }
        for (&handle, socket) in self.udp.iter() {
            if let Ok((n, std::net::SocketAddr::V4(from))) = socket.recv_from(&mut buf) {
                // A resolver checks the reply's source, so report the address
                // the guest sent to rather than where the host redirected it.
                let seen = self
                    .redirects
                    .iter()
                    .find(|(_, to)| **to == from)
                    .map_or(from, |(guest, _)| *guest);
                broker
                    .borrow_mut()
                    .deliver_datagram(handle, seen, &buf[..n]);
                delivered = true;
            }
        }
        delivered
    }
}

/// Runs a guest whose network is host-driven, pumping the transport between
/// slices exactly as the browser worker does: run until the machine says it
/// is waiting on the network, carry out its commands, deliver what arrived,
/// and either continue or tell it the wait expired so its timers can fire.
fn run_argv_pumped(machine: &mut Machine, host: &mut BrokerHost, path: &str, args: &[&str]) -> Run {
    let broker = Rc::new(RefCell::new(HostBroker::new()));
    machine.set_network(broker.clone());
    let argv: Vec<Vec<u8>> = args.iter().map(|a| a.as_bytes().to_vec()).collect();
    machine.set_args(
        argv,
        vec![b"PATH=/bin:/usr/bin:/sbin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine.load(path.as_bytes()).expect("ELF load failed");

    let mut output = Vec::new();
    // Bounded so a bug cannot hang the suite; a fetch needs a few dozen.
    for _ in 0..4000 {
        machine.vm_mut().icount_limit = machine.icount() + 200_000_000;
        let exit = machine.run();
        output.extend(machine.take_output());
        if !machine.awaiting_network() {
            if exit == CpuExit::Interrupted {
                // Out of fuel for this slice, or another host wait; keep going.
                continue;
            }
            return Run {
                exit,
                output: String::from_utf8_lossy(&output).into_owned(),
            };
        }
        let commands = broker.borrow_mut().take_commands();
        host.perform(&commands, &broker);
        // A real host waits on its event loop here; polling briefly is the
        // portable stand-in. Nothing delivered means the wait expired.
        let mut delivered = false;
        for _ in 0..50 {
            if host.poll(&broker) {
                delivered = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        if !delivered {
            machine.expire_network_wait(100);
        }
    }
    panic!(
        "guest never finished; output so far: {:?}",
        String::from_utf8_lossy(&output)
    );
}

/// A host-side network command is independent of the scheduler's aggregate
/// wait state. Bun keeps housekeeping threads runnable while its request
/// thread is parked, so a browser driver that drains commands only after
/// `awaiting_network()` can starve a connect forever.
#[test]
fn host_commands_are_drained_while_sibling_is_runnable() {
    let source = r#"
#include <arpa/inet.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile int done;
static void *housekeeping(void *unused) {
    (void)unused;
    while (!done) sched_yield();
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 2) return 10;
    pthread_t worker;
    if (pthread_create(&worker, NULL, housekeeping, NULL) != 0) return 11;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 12;
    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons((unsigned short)atoi(argv[1]));
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != 0) return 13;
    static const char request[] = "GET /hello HTTP/1.0\r\n\r\n";
    if (write(fd, request, sizeof(request) - 1) != (ssize_t)(sizeof(request) - 1)) return 14;
    char response[512] = {0};
    ssize_t n = read(fd, response, sizeof(response) - 1);
    if (n <= 0) return 15;
    done = 1;
    pthread_join(worker, NULL);
    close(fd);
    puts(strstr(response, "hello-from-webtos-m5") ? "sibling-network-ok" : "bad-response");
    return strstr(response, "hello-from-webtos-m5") ? 0 : 16;
}
"#;
    let Some(image) = compile_c("network-runnable-sibling", source, &["-pthread"]) else {
        return;
    };
    let server = spawn_http_server();
    let mut host = BrokerHost::new(vec![server]);
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/network-runnable-sibling", image, 0o755)
        .expect("add fixture");
    let broker = Rc::new(RefCell::new(HostBroker::new()));
    machine.set_network(broker.clone());
    machine.set_args(
        vec![
            b"network-runnable-sibling".to_vec(),
            server.port().to_string().into_bytes(),
        ],
        vec![b"PATH=/bin".to_vec()],
    );
    machine
        .load(b"/bin/network-runnable-sibling")
        .expect("ELF load failed");

    let mut output = Vec::new();
    let mut drained_while_running = false;
    let mut exit = None;
    for _ in 0..2_000 {
        machine.vm_mut().icount_limit = machine.icount() + 5_000_000;
        let outcome = machine.run();
        output.extend(machine.take_output());

        // This mirrors the browser's fixed per-slice, nonblocking drain. The
        // assertion records the exact state that made status-gated pumping
        // incorrect: commands exist although the whole machine is runnable.
        if broker.borrow().has_commands() {
            if !machine.awaiting_network() {
                drained_while_running = true;
            }
            let commands = broker.borrow_mut().take_commands();
            host.perform(&commands, &broker);
        }
        let _ = host.poll(&broker);

        if outcome != CpuExit::InstructionLimit && outcome != CpuExit::Interrupted {
            exit = Some(outcome);
            break;
        }
    }
    let output = String::from_utf8_lossy(&output);
    assert!(
        drained_while_running,
        "fixture never exposed commands behind a runnable sibling"
    );
    assert_eq!(
        exit,
        Some(CpuExit::Halt { code: Some(0) }),
        "guest did not complete after per-slice network drains: {output:?}"
    );
    assert!(output.contains("sibling-network-ok"), "output: {output:?}");
}

#[test]
fn epoll_reports_host_connect_completion_and_so_error() {
    let source = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons((unsigned short)atoi(argv[1]));
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != -1 || errno != EINPROGRESS) return 2;
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event wanted = { .events = EPOLLOUT | EPOLLET, .data.fd = fd };
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, fd, &wanted)) return 3;
    struct epoll_event got = {0};
    if (epoll_wait(ep, &got, 1, -1) != 1 || !(got.events & EPOLLOUT)) return 4;
    int error = -1;
    socklen_t length = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) || error != 0 || length != sizeof(error)) return 5;
    puts("host-connect-complete-ok");
    return 0;
}
"#;
    let Some(image) = compile_c("host-connect-complete", source, &[]) else {
        return;
    };
    let server = spawn_http_server();
    let mut host = BrokerHost::new(vec![server]);
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/host-connect-complete", image, 0o755)
        .expect("add fixture");
    let port = server.port().to_string();
    let run = run_argv_pumped(
        &mut machine,
        &mut host,
        "/bin/host-connect-complete",
        &["host-connect-complete", &port],
    );
    expect_clean(&run);
    assert!(
        run.output.contains("host-connect-complete-ok"),
        "output: {:?}",
        run.output
    );
}

#[test]
fn epoll_reports_host_tcp_read_half_close() {
    let source = r#"
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons((unsigned short)atoi(argv[1]));
    peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0) return 2;
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != 0 && errno != EINPROGRESS) return 3;
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event wanted = {
        .events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET,
        .data.fd = fd,
    };
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, fd, &wanted)) return 4;
    for (int attempt = 0; attempt < 8; ++attempt) {
        struct epoll_event got = {0};
        if (epoll_wait(ep, &got, 1, -1) != 1) return 5;
        if (got.events & EPOLLRDHUP) {
            char byte;
            if (read(fd, &byte, 1) != 0) return 6;
            puts("host-rdhup-ok");
            return 0;
        }
    }
    return 7;
}
"#;
    let Some(image) = compile_c("host-rdhup", source, &[]) else {
        return;
    };
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind close server");
    let destination = match listener.local_addr().expect("close server address") {
        std::net::SocketAddr::V4(address) => address,
        _ => unreachable!("bound IPv4 close server"),
    };
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept close fixture");
        drop(stream);
    });
    let mut host = BrokerHost::new(vec![destination]);
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/host-rdhup", image, 0o755)
        .expect("add fixture");
    let port = destination.port().to_string();
    let run = run_argv_pumped(
        &mut machine,
        &mut host,
        "/bin/host-rdhup",
        &["host-rdhup", &port],
    );
    server.join().expect("close server");
    expect_clean(&run);
    assert!(
        run.output.contains("host-rdhup-ok"),
        "output: {:?}",
        run.output
    );
}

#[test]
fn host_driven_broker_fetches_http() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let server = spawn_http_server();
    let mut host = BrokerHost::new(vec![server]);
    let url = format!("http://{}/hello", server);

    let run = run_argv_pumped(
        &mut machine,
        &mut host,
        "/usr/bin/wget",
        &["wget", "-q", "-O", "-", &url],
    );
    expect_clean(&run);
    assert_eq!(
        run.output, "hello-from-webtos-m5",
        "wget output: {:?}",
        run.output
    );
}

#[test]
fn host_driven_broker_resolves_dns_over_udp() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let dns = spawn_dns_server();
    // The guest asks its configured resolver on the standard port; the host
    // sends that to the test server, and allows nothing else.
    let mut host = BrokerHost::new(Vec::new());
    host.redirect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 53), dns);
    machine
        .add_file(
            b"/etc/resolv.conf",
            b"nameserver 127.0.0.1\n".to_vec(),
            0o644,
        )
        .expect("resolv.conf");

    let run = run_argv_pumped(
        &mut machine,
        &mut host,
        "/usr/bin/nslookup",
        &["nslookup", "webtos.test", "127.0.0.1"],
    );
    expect_clean(&run);
    assert!(
        run.output.contains("10.0.0.1"),
        "nslookup output: {:?}",
        run.output
    );
}

/// The host, not the guest, decides what may be reached. A destination the
/// host refuses must surface as a failure the guest can see, and no
/// connection may be attempted.
#[test]
fn host_driven_broker_refuses_a_destination_outside_the_allowlist() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let server = spawn_http_server();
    // The server exists, but the host allows nothing.
    let mut host = BrokerHost::new(Vec::new());
    let url = format!("http://{}/hello", server);

    let run = run_argv_pumped(
        &mut machine,
        &mut host,
        "/usr/bin/wget",
        &["wget", "-q", "-O", "-", &url],
    );
    match run.exit {
        CpuExit::Halt { code: Some(code) } => assert_ne!(
            code, 0,
            "wget must fail against a refused destination; output: {:?}",
            run.output
        ),
        other => panic!("unexpected exit {other:?}; output: {:?}", run.output),
    }
    assert!(
        !run.output.contains("hello-from-webtos-m5"),
        "refused destination leaked a response: {:?}",
        run.output
    );
    assert_eq!(host.refused, vec![server], "the host saw the attempt");
}

// ------------------------------------------- a signal during a socket wait

/// The guest side of the interrupted-network-call gate: connect to the test
/// server, send a request, then block in `recv` on a peer that has not
/// answered yet. The handler writes a line of its own, so the test can tell
/// that the signal was taken *while* the call was outstanding rather than
/// before it or after it finished.
const SOCKET_EINTR_FIXTURE: &str = r#"
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t hits = 0;
static void on_int(int s) {
    (void)s;
    hits++;
    if (write(1, "handler ran\n", 12) < 0) _exit(9);
}

int main(int argc, char **argv) {
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_int;
    if (argc > 2 && strcmp(argv[2], "restart") == 0) sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, NULL);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { printf("socket errno=%d\n", errno); fflush(stdout); return 1; }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(argv[1]));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        printf("connect errno=%d\n", errno); fflush(stdout); return 2;
    }
    const char *req = "GET /gated HTTP/1.0\r\n\r\n";
    if (write(fd, req, strlen(req)) != (ssize_t)strlen(req)) {
        printf("send errno=%d\n", errno); fflush(stdout); return 3;
    }
    printf("waiting for the peer\n"); fflush(stdout);

    char buf[256];
    ssize_t n = recv(fd, buf, sizeof buf - 1, 0);
    if (n < 0) {
        printf("recv failed errno=%d hits=%d\n", errno, (int)hits);
        fflush(stdout);
        return errno == EINTR ? 0 : 4;
    }
    buf[n] = 0;
    printf("recv got %zd bytes hits=%d: %s\n", n, (int)hits, buf);
    fflush(stdout);
    return 0;
}
"#;

/// A TCP server that accepts, reads the request, and then says nothing until
/// the test releases it. That is what puts the guest in a wait whose end the
/// test owns: no reply can race the signal.
fn spawn_gated_server(body: &'static str) -> (SocketAddrV4, std::sync::mpsc::Sender<()>) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = match listener.local_addr().expect("local addr") {
        std::net::SocketAddr::V4(addr) => addr,
        _ => unreachable!("bound to IPv4"),
    };
    let (release, gate) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf);
            // Dropping the sender ends the wait with an error: the test
            // finished without ever asking for the reply.
            if gate.recv().is_err() {
                return;
            }
            let _ = stream.write_all(body.as_bytes());
        }
    });
    (addr, release)
}

fn socket_eintr_machine(
    image: Vec<u8>,
    port: u16,
    restart: bool,
) -> (Machine, Rc<RefCell<HostBroker>>) {
    init_logging();
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/netintr", image, 0o755)
        .expect("add fixture");
    let broker = Rc::new(RefCell::new(HostBroker::new()));
    machine.set_network(broker.clone());
    let mut argv = vec![b"netintr".to_vec(), port.to_string().into_bytes()];
    if restart {
        argv.push(b"restart".to_vec());
    }
    machine.set_args(argv, vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/netintr").expect("ELF load failed");
    // Stdio on a pty: `^C` is how the host raises a signal in a guest that is
    // busy elsewhere — here, inside a socket read.
    machine.install_pty_stdio(24, 80);
    (machine, broker)
}

/// Runs the guest until it exits or parks on the socket with nothing for the
/// host to deliver, carrying out broker commands and delivering whatever the
/// real server produced. Returns the terminal output of *this* stretch only
/// (drained, so nothing an earlier stretch printed can match) and the exit,
/// if the guest exited.
fn pump_socket_wait(
    machine: &mut Machine,
    host: &mut BrokerHost,
    broker: &Rc<RefCell<HostBroker>>,
) -> (String, Option<CpuExit>) {
    let mut output = String::new();
    for _ in 0..200 {
        machine.vm_mut().icount_limit = machine.icount() + 200_000_000;
        let exit = machine.run();
        output.push_str(&String::from_utf8_lossy(&machine.drain_terminal_output()));
        if machine.awaiting_network() {
            let commands = broker.borrow_mut().take_commands();
            host.perform(&commands, broker);
            let mut delivered = false;
            for _ in 0..200 {
                if host.poll(broker) {
                    delivered = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            if delivered {
                continue;
            }
            // The peer is silent and the guest is parked on the socket. The
            // wait is deliberately left outstanding rather than expired: a
            // host does not let guest time move on while a connection it
            // still owns is open.
            return (output, None);
        }
        if exit == CpuExit::Interrupted {
            continue; // out of fuel for this slice
        }
        return (output, Some(exit));
    }
    panic!("guest never settled; output so far: {output:?}");
}

/// A network call interrupted mid-flight. A socket read parks on the same
/// machinery as every other blocking wait, but nothing exercised that
/// machinery through a socket: a guest waiting on a peer that has not
/// answered must fail with `EINTR` when the handler was installed without
/// `SA_RESTART`, and must resume the very same `recv` — completing when the
/// bytes finally arrive — when it was installed with it. Getting this wrong
/// either strands a program that breaks out of a network wait by catching a
/// signal, or surfaces a spurious `EINTR` to one that asked never to see it.
#[test]
fn a_signal_interrupts_a_socket_read_unless_the_handler_asked_for_a_restart() {
    let Some(image) = compile_c("net_eintr", SOCKET_EINTR_FIXTURE, &[]) else {
        return;
    };

    // Without SA_RESTART: the read ends, and the handler ran first.
    {
        let (server, release) = spawn_gated_server("never-sent");
        let mut host = BrokerHost::new(vec![server]);
        let (mut machine, broker) = socket_eintr_machine(image.clone(), server.port(), false);

        let (blocked, exit) = pump_socket_wait(&mut machine, &mut host, &broker);
        assert!(exit.is_none(), "guest exited before blocking: {blocked:?}");
        assert!(
            blocked.contains("waiting for the peer"),
            "fixture did not reach the read: {blocked:?}"
        );
        assert!(
            !blocked.contains("handler ran"),
            "the signal must arrive while the read is outstanding: {blocked:?}"
        );

        machine.feed_terminal_input(b"\x03");
        let (interrupted, exit) = pump_socket_wait(&mut machine, &mut host, &broker);
        assert!(
            interrupted.contains("handler ran"),
            "the handler did not run: {interrupted:?}"
        );
        assert!(
            interrupted.contains("recv failed errno=4 hits=1"),
            "an interrupted socket read must return EINTR: {interrupted:?}"
        );
        assert_eq!(
            exit,
            Some(CpuExit::Halt { code: Some(0) }),
            "guest did not exit cleanly: {interrupted:?}"
        );
        // The peer never answered, so nothing but the signal can have ended
        // the read.
        drop(release);
    }

    // With SA_RESTART: the same signal runs the same handler, the read
    // carries on, and it returns the bytes that only arrive afterwards.
    {
        let (server, release) = spawn_gated_server("answered-after-the-signal");
        let mut host = BrokerHost::new(vec![server]);
        let (mut machine, broker) = socket_eintr_machine(image, server.port(), true);

        let (blocked, exit) = pump_socket_wait(&mut machine, &mut host, &broker);
        assert!(exit.is_none(), "guest exited before blocking: {blocked:?}");
        assert!(
            blocked.contains("waiting for the peer"),
            "fixture did not reach the read: {blocked:?}"
        );

        machine.feed_terminal_input(b"\x03");
        let (signalled, exit) = pump_socket_wait(&mut machine, &mut host, &broker);
        assert!(
            signalled.contains("handler ran"),
            "the handler did not run: {signalled:?}"
        );
        assert!(
            !signalled.contains("recv failed"),
            "SA_RESTART must not surface EINTR on a socket: {signalled:?}"
        );
        assert!(
            exit.is_none(),
            "the restarted read should still be waiting on the peer: {signalled:?}"
        );

        // Only now does the peer answer: whatever the guest reads was sent
        // strictly after the signal was handled.
        release.send(()).expect("release the server");
        let (answered, exit) = pump_socket_wait(&mut machine, &mut host, &broker);
        assert!(
            answered.contains("hits=1: answered-after-the-signal"),
            "the restarted read did not complete: {answered:?}"
        );
        assert_eq!(
            exit,
            Some(CpuExit::Halt { code: Some(0) }),
            "guest did not exit cleanly: {answered:?}"
        );
    }
}

// ── Transient failure and reconnect ──────────────────────────────────────────

#[test]
fn nonblocking_host_connect_is_in_progress_until_the_host_completes_it() {
    let source = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return 1;
    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(443);
    peer.sin_addr.s_addr = htonl(0x0a000001);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != -1 || errno != EINPROGRESS) return 2;
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event wanted = { .events = EPOLLOUT | EPOLLET, .data.fd = fd };
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, fd, &wanted)) return 3;
    struct epoll_event got;
    if (epoll_wait(ep, &got, 1, 0) != 0) return 4;
    puts("host-connect-pending-ok");
    return 0;
}
"#;
    let Some(image) = compile_c("host-connect-pending", source, &[]) else {
        return;
    };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/host-connect-pending", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"host-connect-pending".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/host-connect-pending")
        .expect("ELF load failed");
    machine.set_network(Rc::new(RefCell::new(HostBroker::new())));
    machine.vm_mut().icount_limit = 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output:?}");
    assert!(output.contains("host-connect-pending-ok"), "{output:?}");
}

#[test]
fn host_broker_serializes_ipv6_tcp_without_losing_scope_or_flowinfo() {
    let mut broker = HostBroker::new();
    let destination = SocketAddrV6::new(
        "2001:db8:1:2:3:4:5:6".parse().expect("IPv6 fixture"),
        443,
        0x1122_3344,
        7,
    );
    let handle = broker
        .tcp_connect_v6(destination)
        .expect("IPv6 connect command");
    assert_eq!(handle, 1);
    assert_eq!(
        broker.tcp_connect_status(handle),
        ConnectStatus::Pending,
        "queuing a host connect is not synchronous connection success"
    );
    let encoded = broker.take_commands();
    let mut expected = vec![7, 1, 0, 0, 0];
    expected.extend_from_slice(&destination.ip().octets());
    expected.extend_from_slice(&destination.port().to_be_bytes());
    expected.extend_from_slice(&destination.flowinfo().to_le_bytes());
    expected.extend_from_slice(&destination.scope_id().to_le_bytes());
    assert_eq!(encoded, expected);
    broker.deliver_connected(handle, None);
    assert_eq!(broker.tcp_connect_status(handle), ConnectStatus::Connected);
}

#[test]
fn host_broker_socket_error_is_observable_then_cleared_like_so_error() {
    let mut broker = HostBroker::new();
    let handle = broker
        .tcp_connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443))
        .expect("connect handle");
    broker.deliver_error(handle, linux_compat::abi::ECONNREFUSED);
    assert_eq!(
        broker.tcp_connect_status(handle),
        ConnectStatus::Failed(linux_compat::abi::ECONNREFUSED)
    );
    assert_eq!(
        broker.tcp_take_error(handle),
        Ok(Some(linux_compat::abi::ECONNREFUSED))
    );
    assert_eq!(broker.tcp_take_error(handle), Ok(None));
}

/// A host-driven transport wait must advance by the amount the host actually
/// waited, not jump straight to the guest's (possibly distant) timeout.  A
/// browser deliberately caps each host wait so it can service cancellation
/// and other sockets; treating that cap as proof that the whole guest timeout
/// elapsed makes a 30-second request fail after one second of real time.
#[test]
fn capped_host_wait_does_not_expire_a_distant_socket_timeout() {
    let source = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return 10;
    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(443);
    peer.sin_addr.s_addr = htonl(0x0a000001);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != -1 || errno != EINPROGRESS)
        return 11;
    puts("waiting");
    fflush(stdout);
    struct pollfd wanted = { .fd = fd, .events = POLLOUT };
    int result = poll(&wanted, 1, 30000);
    printf("poll=%d\n", result);
    return result == 0 ? 12 : 0;
}

"#;
    let Some(image) = compile_c("capped-host-wait", source, &[]) else {
        return;
    };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/capped-host-wait", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"capped-host-wait".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/capped-host-wait")
        .expect("ELF load failed");
    let broker = Rc::new(RefCell::new(HostBroker::new()));
    machine.set_network(broker.clone());

    machine.vm_mut().icount_limit = 4_000_000_000;
    let first = machine.run();
    let first_output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(first, CpuExit::Interrupted, "{first_output:?}");
    assert!(machine.awaiting_network());
    assert!(first_output.contains("waiting"));
    assert!(!broker.borrow_mut().take_commands().is_empty());

    // Report that no socket event arrived during one bounded real second.
    machine.expire_network_wait(1_000);
    machine.vm_mut().icount_limit = machine.icount() + 1_000_000_000;
    let second = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(second, CpuExit::Interrupted, "{output:?}");
    assert!(
        machine.awaiting_network(),
        "a one-second host wait incorrectly consumed the full 30-second timeout: {output:?}"
    );
}

/// A host callback is itself edge-producing activity.  This matters when an
/// EPOLLET consumer intentionally leaves a socket readable: after the current
/// edge has been delivered, another host data callback must wake the parked
/// epoll waiter even though readability never transitioned through false.
#[test]
fn host_delivery_rearms_a_suppressed_network_edge() {
    let source = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return 10;
    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(443);
    peer.sin_addr.s_addr = htonl(0x0a000001);
    if (connect(fd, (struct sockaddr *)&peer, sizeof(peer)) != -1 || errno != EINPROGRESS)
        return 11;
    int ep = epoll_create1(0);
    struct epoll_event wanted = { .events = EPOLLIN | EPOLLOUT | EPOLLET, .data.fd = fd };
    if (ep < 0 || epoll_ctl(ep, EPOLL_CTL_ADD, fd, &wanted)) return 12;
    struct epoll_event got;
    if (epoll_wait(ep, &got, 1, -1) != 1 || !(got.events & EPOLLIN)) return 13;
    char byte;
    if (recv(fd, &byte, 1, 0) != 1) return 14; /* leave one byte readable */
    if (epoll_wait(ep, &got, 1, 0) != 1 || !(got.events & EPOLLIN)) return 15;
    puts("suppressed-wait-ready");
    fflush(stdout);
    if (epoll_wait(ep, &got, 1, -1) != 1 || !(got.events & EPOLLIN)) return 16;
    puts("fresh-host-edge");
    return 0;
}
"#;
    let Some(image) = compile_c("host-delivery-edge", source, &[]) else {
        return;
    };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/host-delivery-edge", image, 0o755)
        .expect("add fixture");
    machine.set_args(
        vec![b"host-delivery-edge".to_vec()],
        vec![b"HOME=/root".to_vec()],
    );
    machine
        .load(b"/bin/host-delivery-edge")
        .expect("ELF load failed");
    let broker = Rc::new(RefCell::new(HostBroker::new()));
    machine.set_network(broker.clone());

    machine.vm_mut().icount_limit = 4_000_000_000;
    assert_eq!(machine.run(), CpuExit::Interrupted);
    assert!(machine.awaiting_network());
    assert!(!broker.borrow_mut().take_commands().is_empty());

    // The first callback establishes both readiness directions and leaves two
    // bytes so the guest can consume only part of the readable state.
    broker.borrow_mut().deliver_connected(1, None);
    broker.borrow_mut().deliver_data(1, b"ab");
    machine.vm_mut().icount_limit = machine.icount() + 200_000_000;
    let middle_exit = machine.run();
    let middle = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(middle_exit, CpuExit::Interrupted, "{middle:?}");
    assert!(machine.awaiting_network(), "{middle:?}");
    assert!(middle.contains("suppressed-wait-ready"), "{middle:?}");

    // Readability never became false.  Only the broker's activity generation
    // distinguishes this delivery from the edge already consumed above.
    broker.borrow_mut().deliver_data(1, b"c");
    machine.vm_mut().icount_limit = machine.icount() + 200_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    let parked = machine.parked_task_snapshot();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "output={output:?} awaiting={} parked={parked:?}",
        machine.awaiting_network()
    );
    assert!(output.contains("fresh-host-edge"), "{output:?}");
}

#[test]
fn nofile_limit_matches_the_descriptor_table_ceiling() {
    let source = r#"
#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>

int main(void) {
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit)) return 10;
    if (limit.rlim_cur != 65536 || limit.rlim_max != 65536) return 11;
    if (setrlimit(RLIMIT_NOFILE, &limit)) return 12;
    limit.rlim_cur--;
    errno = 0;
    if (setrlimit(RLIMIT_NOFILE, &limit) != -1 || errno != EPERM) return 13;
    puts("nofile-limit-ok");
    return 0;
}
"#;
    let Some(image) = compile_c("nofile-limit", source, &[]) else {
        return;
    };
    let run = run_image(image, "nofile-limit");
    expect_clean(&run);
    assert!(run.output.contains("nofile-limit-ok"), "{:?}", run.output);
}

#[test]
fn host_proxy_error_is_delivered_once_as_econnreset() {
    let mut broker = HostBroker::new();
    let destination = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 443);
    let handle = broker.tcp_connect(destination).expect("connect handle");
    broker.deliver_connected(handle, None);
    broker.deliver_data(handle, b"buffered");
    broker.deliver_error(handle, linux_compat::abi::ECONNRESET);

    match broker.tcp_recv(handle, 64) {
        Ok(RecvOutcome::Data(bytes)) => assert_eq!(bytes, b"buffered"),
        _ => panic!("bytes received before the proxy failure were discarded"),
    }
    assert!(
        matches!(
            broker.tcp_recv(handle, 64),
            Err(linux_compat::abi::ECONNRESET)
        ),
        "a failed relay must terminate the wait with ECONNRESET, not EOF"
    );
}

/// Accepts and drops the first `fail_first` connections without answering,
/// then serves normally. A peer that goes away mid-exchange is the ordinary
/// case on a network, and the question is what the guest is left holding.
fn spawn_flaky_server(fail_first: usize) -> (SocketAddrV4, std::sync::Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = match listener.local_addr().expect("local addr") {
        std::net::SocketAddr::V4(addr) => addr,
        _ => unreachable!("bound to IPv4"),
    };
    // How many connections actually arrived. Without it the test passes
    // whether or not the guest ever reached the server, which would make
    // "the guest got an error" say nothing about the path it came from.
    let arrived = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = std::sync::Arc::clone(&arrived);
    std::thread::spawn(move || {
        let mut seen = 0_usize;
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            seen += 1;
            counter.fetch_add(1, Ordering::SeqCst);
            if seen <= fail_first {
                // Read the request so the guest gets as far as waiting for an
                // answer, then vanish. Waiting forever is the failure that
                // ends a long-running loop; an error is one it can act on.
                let mut buf = [0_u8; 2048];
                let _ = stream.read(&mut buf);
                drop(stream);
                continue;
            }
            let mut buf = [0_u8; 2048];
            let mut request = Vec::new();
            while let Ok(n) = stream.read(&mut buf) {
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let body = "back-after-the-drop";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (addr, arrived)
}

#[test]
fn a_peer_that_vanishes_leaves_an_error_rather_than_a_wait() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    let (server, arrived) = spawn_flaky_server(1);
    let mut broker = NativeBroker::new();
    broker.redirect(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80), server);
    broker.restrict_to_redirects();
    machine.set_network(Rc::new(RefCell::new(broker)));

    let url = "http://10.0.0.1/".to_string();

    // The first attempt meets a peer that reads the request and disappears.
    let first = run_argv(&mut machine, "/usr/bin/wget", &["wget", "-q", "-O-", &url]);
    assert!(
        matches!(first.exit, CpuExit::Halt { .. }),
        "a peer that vanished left the guest waiting: {:?} {}",
        first.exit,
        first.output
    );
    assert!(
        !first.output.contains("back-after-the-drop"),
        "the dropped attempt somehow got a body: {}",
        first.output
    );
    assert_eq!(
        arrived.load(Ordering::SeqCst),
        1,
        "the guest never reached the server, so its failure says nothing \
         about a peer that vanished: {}",
        first.output
    );

    // The second reaches a server that is answering again. Nothing about the
    // first attempt may have poisoned the machine's ability to try.
    let second = run_argv(&mut machine, "/usr/bin/wget", &["wget", "-q", "-O-", &url]);
    assert_eq!(
        second.exit,
        CpuExit::Halt { code: Some(0) },
        "a retry after a dropped connection failed: {}",
        second.output
    );
    assert!(
        second.output.contains("back-after-the-drop"),
        "the retry did not get the body: {}",
        second.output
    );
    assert_eq!(
        arrived.load(Ordering::SeqCst),
        2,
        "the retry did not open a second connection"
    );
}

#[test]
fn a_connection_refused_is_reported_and_does_not_stop_the_next_one() {
    let Some(mut machine) = alpine_machine() else {
        return;
    };
    // A port nothing is listening on. Bound and dropped, so it is a port that
    // was real a moment ago — which is what a peer that went away looks like.
    let dead = {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        match listener.local_addr().expect("local addr") {
            std::net::SocketAddr::V4(addr) => addr,
            _ => unreachable!("bound to IPv4"),
        }
    };
    let alive = spawn_http_server();
    let mut broker = NativeBroker::new();
    broker.redirect(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80), dead);
    broker.redirect(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 80), alive);
    broker.restrict_to_redirects();
    machine.set_network(Rc::new(RefCell::new(broker)));

    let refused = run_argv(
        &mut machine,
        "/usr/bin/wget",
        &["wget", "-q", "-O-", "http://10.0.0.1/"],
    );
    assert!(
        matches!(refused.exit, CpuExit::Halt { code: Some(code) } if code != 0),
        "connecting to nothing did not fail cleanly: {:?} {}",
        refused.exit,
        refused.output
    );

    let ok = run_argv(
        &mut machine,
        "/usr/bin/wget",
        &["wget", "-q", "-O-", "http://10.0.0.2/"],
    );
    assert_eq!(
        ok.exit,
        CpuExit::Halt { code: Some(0) },
        "a refused connection stopped the next one from working: {}",
        ok.output
    );
    assert!(
        ok.output.contains("hello-from-webtos-m5"),
        "the working connection returned nothing: {}",
        ok.output
    );
}
