//! Milestone-5 workload gates: event-loop primitives (eventfd, timerfd,
//! epoll) and networking through the explicit host broker (HTTP fetch, UDP
//! DNS, denied-by-default).
//!
//! C fixtures are compiled with the host `gcc`; network gates use the
//! pinned Alpine minirootfs plus loopback servers owned by the test. Every
//! test skips with a message when a prerequisite is missing.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

use linux_compat::net::{HostBroker, NativeBroker};
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
            machine.expire_network_wait();
        }
    }
    panic!(
        "guest never finished; output so far: {:?}",
        String::from_utf8_lossy(&output)
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
