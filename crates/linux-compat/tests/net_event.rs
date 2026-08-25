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

use linux_compat::net::NativeBroker;
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
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                "-addext", "subjectAltName=IP:10.0.0.2",
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
