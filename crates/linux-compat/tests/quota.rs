//! Storage, network, and CPU quotas.
//!
//! Memory's budget refuses what the host asks for. The rest refuse what the
//! guest does: a filesystem that may not grow past a ceiling, a byte count
//! the guest may not relay past, and instructions it may not retire past.
//! The first two fail the way a real system fails — an errno the guest can
//! read and report — rather than by exhausting the tab.
//!
//! The CPU ceiling is not symmetric with those, because the guest it exists
//! for cannot be told anything: a workload that computes in a loop and issues
//! no syscalls is outside every mechanism the machine has for stopping a
//! task. The terminal's interrupt character reaches a task at a kernel entry,
//! and this one never makes one; the instruction limit ends a turn, and the
//! host's loop begins another.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, UdpSocket};
use std::path::PathBuf;
use std::process::Command;
use std::rc::Rc;
use std::time::Duration;

use linux_compat::abi;
use linux_compat::net::{BrokerRef, HostBroker, NativeBroker, RecvOutcome};
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

fn fresh_machine() -> Machine {
    init_logging();
    Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed")
}

// ── Storage ────────────────────────────────────────────────────────────────

/// The lifecycle fixture writes 4 KiB at a time until it has put 320 KiB in
/// `/tmp`, then truncates, rewrites and unlinks it — twenty-four times over.
/// It reports every syscall's return value, which is what makes it useful
/// here: the number it prints when a write is refused is the number the guest
/// actually saw.
fn large_file_fixture() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test_data/test_large_file_lifecycle.elf");
    linux_compat::testing::require(&path.display().to_string(), std::fs::read(&path).ok())
}

struct Run {
    exit: CpuExit,
    output: String,
}

fn run_fixture(machine: &mut Machine) -> Run {
    machine.set_args(vec![b"lifecycle".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/lifecycle").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    Run { exit, output }
}

/// A guest that writes without end must hit a wall it can see. Before this
/// there was none: `/tmp` grew into the tab's linear memory until the
/// allocator gave up, and the guest never learned anything was wrong.
///
/// The wall is `ENOSPC`, which is what a real kernel returns for a full
/// filesystem, so every program that already handles a full disk handles this
/// one. The same fixture is run twice — once with room, once without — so the
/// failure is attributable to the budget and nothing else.
#[test]
fn a_guest_write_past_the_storage_budget_gets_enospc() {
    let Some(image) = large_file_fixture() else {
        return;
    };

    // With no budget the fixture writes its 320 KiB and reports no failures.
    let mut machine = fresh_machine();
    machine
        .add_file(b"/bin/lifecycle", image.clone(), 0o755)
        .expect("add fixture");
    assert!(machine.storage_headroom().is_none());
    let unbudgeted = run_fixture(&mut machine);
    assert_eq!(
        unbudgeted.exit,
        CpuExit::Halt { code: Some(0) },
        "the fixture does not pass unconstrained, so nothing below means \
         anything; output: {:?}",
        unbudgeted.output
    );
    assert!(
        unbudgeted.output.contains("0 failed"),
        "output: {:?}",
        unbudgeted.output
    );

    // Same fixture, same machine, but /tmp may only grow by 64 KiB — a
    // quarter of what one pass writes.
    const ROOM: usize = 64 * 1024;
    let mut machine = fresh_machine();
    machine
        .add_file(b"/bin/lifecycle", image, 0o755)
        .expect("add fixture");
    let image_bytes = machine.storage_bytes();
    let budget = image_bytes + ROOM;
    machine.set_storage_budget(Some(budget));
    assert_eq!(machine.storage_headroom(), Some(ROOM));

    let budgeted = run_fixture(&mut machine);

    // -28 is ENOSPC. Asserting on the number rather than on "it failed" is
    // the point: the fixture reports a failed write whatever went wrong, and
    // only this errno says the filesystem was full.
    assert!(
        budgeted.output.contains(&format!("got=-{}", abi::ENOSPC)),
        "the guest did not see ENOSPC; output: {:?}",
        budgeted.output
    );
    assert!(
        !budgeted.output.contains("0 failed"),
        "the writes were not refused at all; output: {:?}",
        budgeted.output
    );

    // Refused, not merely reported: the filesystem stayed inside the ceiling,
    // and the guest survived to print its own summary rather than taking the
    // host down with it.
    assert!(
        machine.storage_bytes() <= budget,
        "the filesystem grew past its budget: {} > {budget}",
        machine.storage_bytes()
    );
    assert_eq!(
        machine.exit_code(),
        Some(1),
        "the guest did not exit under its own control; output: {:?}",
        budgeted.output
    );
}

/// The budget is on the filesystem, so every path the guest can grow it by
/// answers to it — not only `write`. A symlink is the one that would be
/// easiest to forget: its target is data the guest chooses the length of, and
/// it never goes through a write path.
#[test]
fn every_guest_path_that_grows_the_filesystem_is_charged() {
    let mut machine = fresh_machine();
    machine
        .add_file(b"/tmp/seed", vec![0; 4096], 0o644)
        .expect("add seed");
    let start = machine.storage_bytes();
    assert!(start >= 4096);

    // Room for eight bytes and not a ninth.
    machine.set_storage_budget(Some(start + 8));
    let vfs = &mut machine.env().vfs;
    let root = vfs
        .resolve(0, b"/tmp", true)
        .expect("/tmp")
        .node
        .expect("/tmp");

    assert_eq!(
        vfs.create(
            root,
            b"short",
            linux_compat::vfs::NodeKind::Symlink(b"12345678".to_vec()),
            0o777
        )
        .map(|_| ()),
        Ok(()),
        "eight bytes should fit in eight bytes of headroom"
    );
    assert_eq!(
        vfs.create(
            root,
            b"long",
            linux_compat::vfs::NodeKind::Symlink(b"123456789".to_vec()),
            0o777
        )
        .map(|_| ()),
        Err(abi::ENOSPC),
        "a symlink target past the ceiling should be refused with ENOSPC"
    );
    assert!(
        vfs.resolve(0, b"/tmp/long", false)
            .expect("resolve")
            .node
            .is_none(),
        "the refused symlink was created anyway"
    );

    // A directory is free — it holds no data — and must not be refused just
    // because the filesystem is full.
    assert!(
        vfs.create(
            root,
            b"dir",
            linux_compat::vfs::NodeKind::Dir(Default::default()),
            0o755
        )
        .is_ok(),
        "an empty directory costs no bytes and should not be refused"
    );

    // A host may set a budget below what is already there — by lowering it
    // under load, or by preloading past it, neither of which is refused. That
    // must not wedge the guest into a filesystem it cannot even make a
    // directory on: what costs nothing still fits.
    vfs.set_storage_budget(Some(1));
    assert_eq!(vfs.storage_headroom(), Some(0));
    assert!(
        vfs.create(
            root,
            b"empty",
            linux_compat::vfs::NodeKind::File(Vec::new()),
            0o644
        )
        .is_ok(),
        "an empty file was refused on an over-budget filesystem"
    );
    assert!(
        vfs.create(
            root,
            b"deep",
            linux_compat::vfs::NodeKind::Dir(Default::default()),
            0o755
        )
        .is_ok(),
        "a directory was refused on an over-budget filesystem"
    );
    assert_eq!(
        vfs.create(
            root,
            b"more",
            linux_compat::vfs::NodeKind::Symlink(b"z".to_vec()),
            0o777
        )
        .map(|_| ()),
        Err(abi::ENOSPC),
        "one more byte was allowed on an over-budget filesystem"
    );
}

/// Builds a freestanding x86-64 Linux fixture with whatever cross toolchain
/// the host has. Skips (loudly) when it has none.
fn compile_guest(name: &str, source: &str) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-quota-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join(format!("{name}.c"));
    let out = dir.join(name);
    std::fs::write(&src, source).expect("write source");
    let common = ["-Os", "-static", "-nostdlib", "-fno-stack-protector"];
    let candidates: [&[&str]; 2] = [
        &[],
        // Apple's clang emits ELF for a Linux triple; lld links it.
        &["-target", "x86_64-unknown-linux-gnu", "-fuse-ld=lld"],
    ];
    for compiler in ["gcc", "clang"] {
        for extra in candidates {
            let mut cmd = std::process::Command::new(compiler);
            cmd.args(common)
                .args(extra)
                .arg("-o")
                .arg(&out)
                .arg(&src)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if matches!(cmd.status(), Ok(status) if status.success()) {
                return Some(std::fs::read(&out).expect("compiler output"));
            }
        }
    }
    linux_compat::testing::require::<Vec<u8>>(
        &format!("a compiler that targets Linux x86-64 for {name}"),
        None,
    )
}

/// Reports what the kernel told it, for each way a guest can ask the
/// filesystem for more room.
const QUOTA_PROBE: &str = r#"
#define SYS_WRITE 1
#define SYS_LSEEK 8
#define SYS_FTRUNCATE 77
#define SYS_OPENAT 257
#define SYS_SYMLINKAT 266
#define SYS_EXIT 60
#define AT_FDCWD (-100)
#define O_RDWR 2
#define O_CREAT 0x40

typedef unsigned long u64;
typedef long i64;

/* Freestanding, but a compiler is still allowed to turn a byte loop into a
   call to the libc that is not here. The volatile pointers stop it folding
   these two into calls to themselves. */
void *memset(void *dst, int c, u64 n) {
    volatile unsigned char *p = (volatile unsigned char *)dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

u64 strlen(const char *s) {
    const volatile char *p = s;
    u64 n = 0;
    while (p[n]) n++;
    return n;
}

static i64 sys4(u64 nr, u64 a, u64 b, u64 c, u64 d) {
    i64 ret;
    register u64 r10 __asm__("r10") = d;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10)
                     : "rcx", "r11", "memory");
    return ret;
}

static void out(const char *s) {
    sys4(SYS_WRITE, 1, (u64)s, strlen(s), 0);
}

static void num(i64 v) {
    char buf[24];
    int i = 0;
    unsigned long m;
    if (v == 0) { out("0"); return; }
    if (v < 0) { out("-"); m = (unsigned long)(-v); } else { m = (unsigned long)v; }
    while (m) { buf[i++] = (char)('0' + (m % 10)); m /= 10; }
    while (i) { char c = buf[--i]; sys4(SYS_WRITE, 1, (u64)&c, 1, 0); }
}

static void report(const char *label, i64 v) { out(label); num(v); out("\n"); }

static char chunk[4096];
static char target[512];

void _start(void) {
    long grown = 0;
    i64 refused = 0;
    int i;
    for (i = 0; i < (int)sizeof(chunk); i++) chunk[i] = 'x';
    for (i = 0; i < (int)sizeof(target) - 1; i++) target[i] = 'y';

    i64 fd = sys4(SYS_OPENAT, (u64)(long)AT_FDCWD, (u64)"/tmp/fill",
                  O_CREAT | O_RDWR, 0644);
    report("open=", fd);
    if (fd < 0) sys4(SYS_EXIT, 1, 0, 0, 0);

    /* Grow until the filesystem says no. Bounded so a machine with no
       budget still finishes. */
    for (i = 0; i < 4096; i++) {
        i64 n = sys4(SYS_WRITE, (u64)fd, (u64)chunk, sizeof(chunk), 0);
        if (n < 0) { refused = n; break; }
        grown += n;
    }
    report("grown=", grown);
    report("write_refused=", refused);

    /* Rewriting bytes that are already there costs the filesystem nothing
       and must still be allowed on a full one. */
    report("seek=", sys4(SYS_LSEEK, (u64)fd, 0, 0, 0));
    report("overwrite=", sys4(SYS_WRITE, (u64)fd, (u64)chunk, 64, 0));

    /* Growing by ftruncate is the other way to ask for room. */
    report("ftruncate_grow=", sys4(SYS_FTRUNCATE, (u64)fd, (u64)(grown + (1 << 20)), 0, 0));
    report("symlink=", sys4(SYS_SYMLINKAT, (u64)target, (u64)(long)AT_FDCWD,
                            (u64)"/tmp/link", 0));
    report("ftruncate_shrink=", sys4(SYS_FTRUNCATE, (u64)fd, 128, 0, 0));

    out("done\n");
    sys4(SYS_EXIT, 0, 0, 0, 0);
    __builtin_unreachable();
}
"#;

fn probe_report(output: &str, label: &str) -> i64 {
    let line = output
        .lines()
        .find(|line| line.starts_with(label))
        .unwrap_or_else(|| panic!("no {label:?} line in guest output: {output:?}"));
    line[label.len()..]
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("{label:?} is not a number ({e}): {line:?}"))
}

/// Every way a guest can ask the filesystem for more room answers to the
/// budget, and none of them answers with anything but `ENOSPC`.
///
/// `write` is the obvious one. `ftruncate` is the one that would hurt most if
/// it were missed — a single call names its own size, so a guest could ask
/// for a gigabyte in one syscall and the host would go looking for it.
/// Overwriting is here for the opposite reason: it costs the filesystem
/// nothing, so refusing it would break programs that rewrite a full disk's
/// existing files, which is a thing programs do.
#[test]
fn a_full_filesystem_refuses_growth_and_nothing_else() {
    let Some(image) = compile_guest("quota_probe", QUOTA_PROBE) else {
        return;
    };

    const ROOM: usize = 64 * 1024;
    let mut machine = fresh_machine();
    machine
        .add_file(b"/bin/probe", image, 0o755)
        .expect("add fixture");
    let budget = machine.storage_bytes() + ROOM;
    machine.set_storage_budget(Some(budget));

    machine.set_args(vec![b"probe".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/probe").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "the probe did not run to the end: {output:?}"
    );
    assert!(output.contains("done"), "output: {output:?}");

    let enospc = -(abi::ENOSPC as i64);
    let grown = probe_report(&output, "grown=");
    assert!(
        grown > 0 && (grown as usize) <= ROOM,
        "the guest wrote {grown} bytes against {ROOM} of headroom"
    );
    assert_eq!(
        probe_report(&output, "write_refused="),
        enospc,
        "a write past the budget did not return ENOSPC: {output:?}"
    );
    assert_eq!(
        probe_report(&output, "ftruncate_grow="),
        enospc,
        "ftruncate grew the file past the budget: {output:?}"
    );
    assert_eq!(
        probe_report(&output, "symlink="),
        enospc,
        "a symlink target was stored on a full filesystem: {output:?}"
    );

    // The refusals are for growth only.
    assert_eq!(
        probe_report(&output, "overwrite="),
        64,
        "rewriting existing bytes was refused on a full filesystem: {output:?}"
    );
    assert_eq!(
        probe_report(&output, "ftruncate_shrink="),
        0,
        "shrinking a file was refused on a full filesystem: {output:?}"
    );

    assert!(
        machine.storage_bytes() <= budget,
        "the filesystem grew past its budget: {} > {budget}",
        machine.storage_bytes()
    );
}

// ── Network ────────────────────────────────────────────────────────────────

/// The broker the guest's sockets actually use — the metered wrapper
/// `set_network` installs around what the host attached, not the host's own
/// object. Driving this is driving the same code path a guest `send(2)`
/// reaches.
fn guest_broker(machine: &mut Machine) -> BrokerRef {
    machine
        .env()
        .network_broker()
        .expect("a broker was attached")
}

fn recv_all(broker: &BrokerRef, handle: u64, want: usize) -> Result<Vec<u8>, u64> {
    let mut got = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while got.len() < want && std::time::Instant::now() < deadline {
        broker
            .borrow_mut()
            .wait_ready(&[handle], Duration::from_millis(50));
        match broker.borrow_mut().tcp_recv(handle, want - got.len())? {
            RecvOutcome::Data(bytes) => got.extend_from_slice(&bytes),
            RecvOutcome::Closed => break,
            RecvOutcome::WouldBlock => {}
        }
    }
    Ok(got)
}

/// A tab is somebody else's bandwidth. Without a cap a guest can stream
/// through the host broker until the host notices, which on a phone is after
/// the damage.
///
/// The cap is checked at the broker boundary, so it holds for every socket
/// path at once, and the refusal is `EPERM` — an errno, delivered to the
/// guest, not a host-side abort. The assertions are on the specific errno and
/// on the server having received nothing, because "the send failed" would be
/// true of a closed connection too.
#[test]
fn a_guest_send_past_the_network_budget_is_refused_and_relays_nothing() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let addr = match listener.local_addr().expect("addr") {
        std::net::SocketAddr::V4(addr) => addr,
        other => panic!("unexpected loopback address {other}"),
    };

    let mut machine = fresh_machine();
    machine.set_network(Rc::new(std::cell::RefCell::new(NativeBroker::new())));

    // Sixteen bytes of allowance, total, in both directions.
    const BUDGET: usize = 16;
    machine.set_network_budget(Some(BUDGET));
    assert_eq!(machine.network_headroom(), Some(BUDGET));

    let broker = guest_broker(&mut machine);
    let handle = broker
        .borrow_mut()
        .tcp_connect(addr)
        .expect("connect to the test listener");
    let (mut server, _) = listener.accept().expect("accept");
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");

    // Connection setup is not payload and is not charged.
    assert_eq!(machine.network_usage().total_bytes, 0);

    // Ten bytes out, six back: the budget is now exactly spent.
    assert_eq!(broker.borrow_mut().tcp_send(handle, b"0123456789"), Ok(10));
    let mut echoed = [0_u8; 10];
    server.read_exact(&mut echoed).expect("server read");
    assert_eq!(&echoed, b"0123456789");
    server.write_all(b"abcdef").expect("server write");
    assert_eq!(recv_all(&broker, handle, 6), Ok(b"abcdef".to_vec()));

    let spent = machine.network_usage();
    assert_eq!(spent.sent_bytes, 10);
    assert_eq!(spent.received_bytes, 6);
    assert_eq!(spent.total_bytes, BUDGET);
    assert_eq!(machine.network_headroom(), Some(0));

    // The next byte is refused with EPERM, and none of it reaches the wire.
    assert_eq!(
        broker.borrow_mut().tcp_send(handle, b"more"),
        Err(abi::EPERM),
        "a send past the budget should be refused with EPERM"
    );
    server
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("read timeout");
    let mut leaked = [0_u8; 4];
    assert!(
        server.read(&mut leaked).is_err(),
        "bytes reached the server after the budget was spent: {leaked:?}"
    );
    assert_eq!(
        machine.network_usage(),
        spent,
        "a refused send was charged anyway"
    );

    // A receive is refused the same way, and the data stays in the socket
    // rather than being relayed and dropped.
    server.write_all(b"xyz").expect("server write");
    assert_eq!(
        broker.borrow_mut().tcp_recv(handle, 3).err(),
        Some(abi::EPERM),
        "a receive past the budget should be refused with EPERM"
    );
    assert_eq!(machine.network_usage(), spent);

    // Lifting the cap lets the very same calls through, so the refusals above
    // were the cap and not a broken connection.
    machine.set_network_budget(None);
    assert!(machine.network_headroom().is_none());
    assert_eq!(recv_all(&broker, handle, 3), Ok(b"xyz".to_vec()));
    assert_eq!(broker.borrow_mut().tcp_send(handle, b"more"), Ok(4));
    let mut tail = [0_u8; 4];
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    server.read_exact(&mut tail).expect("server read");
    assert_eq!(&tail, b"more");
    assert_eq!(machine.network_usage().total_bytes, BUDGET + 3 + 4);
}

/// Half a datagram is a corrupt message, so a `sendto` that does not fit the
/// remaining budget is refused whole rather than clipped to the headroom the
/// way a stream send is.
#[test]
fn a_datagram_that_does_not_fit_the_budget_is_refused_whole() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    peer.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("read timeout");
    let addr = match peer.local_addr().expect("addr") {
        std::net::SocketAddr::V4(addr) => addr,
        other => panic!("unexpected loopback address {other}"),
    };

    let mut machine = fresh_machine();
    machine.set_network(Rc::new(std::cell::RefCell::new(NativeBroker::new())));
    machine.set_network_budget(Some(8));

    let broker = guest_broker(&mut machine);
    let handle = broker.borrow_mut().udp_open().expect("udp open");

    assert_eq!(
        broker
            .borrow_mut()
            .udp_send_to(handle, addr, b"0123456789012345"),
        Err(abi::EPERM),
        "a 16-byte datagram should not fit an 8-byte budget"
    );
    let mut buf = [0_u8; 64];
    assert!(
        peer.recv_from(&mut buf).is_err(),
        "a refused datagram was sent anyway: {buf:?}"
    );
    assert_eq!(machine.network_usage().total_bytes, 0);

    // What fits goes, whole.
    assert_eq!(
        broker.borrow_mut().udp_send_to(handle, addr, b"01234567"),
        Ok(8)
    );
    let (n, _) = peer.recv_from(&mut buf).expect("datagram");
    assert_eq!(&buf[..n], b"01234567");
    assert_eq!(machine.network_usage().total_bytes, 8);
}

/// The browser's broker owns no transport: it writes what the guest wants
/// into a queue the host drains, and the scheduler pauses the machine instead
/// of waiting inside it. Metering must not disturb either half — a wrapper
/// that answered `host_driven` for itself would make the worker block, and
/// one that swallowed the queue would make the network silently stop. Neither
/// shows up on a machine without the browser fixtures, so it is asserted
/// directly.
#[test]
fn a_host_driven_broker_is_metered_without_losing_its_command_queue() {
    let host = Rc::new(RefCell::new(HostBroker::new()));
    let mut machine = fresh_machine();
    machine.set_network(host.clone());
    machine.set_network_budget(Some(8));

    let broker = guest_broker(&mut machine);
    assert!(
        broker.borrow().host_driven(),
        "metering hid that the host owns the transport; the worker would block"
    );

    let handle = broker
        .borrow_mut()
        .tcp_connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80))
        .expect("connect is queued, not performed");
    // Drain the connect, so what turns up next is the send and nothing else.
    assert!(
        !host.borrow_mut().take_commands().is_empty(),
        "the connect never reached the host's queue"
    );
    assert_eq!(broker.borrow_mut().tcp_send(handle, b"01234"), Ok(5));
    let queued = host.borrow_mut().take_commands();
    assert!(
        queued.windows(5).any(|window| window == b"01234"),
        "the guest's bytes never reached the host's queue: {queued:?}"
    );
    assert_eq!(machine.network_usage().sent_bytes, 5);

    // Three bytes of budget left. The host delivers five; the guest is handed
    // three, and the rest stays queued rather than being relayed and dropped.
    host.borrow_mut().deliver_data(handle, b"abcde");
    match broker.borrow_mut().tcp_recv(handle, 5) {
        Ok(RecvOutcome::Data(bytes)) => assert_eq!(bytes, b"abc"),
        Ok(_) => panic!("the delivered data did not come back"),
        Err(errno) => panic!("receive failed with errno {errno}"),
    }
    assert_eq!(machine.network_headroom(), Some(0));
    assert_eq!(
        broker.borrow_mut().tcp_send(handle, b"x").err(),
        Some(abi::EPERM),
        "a send past the budget should be refused on a host-driven broker too"
    );
}

// ── CPU ──────────────────────────────────────────────────────────────────────

fn compile_c(name: &str, source: &str) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-quota-fixture");
    std::fs::create_dir_all(&dir).expect("temp dir");
    let src = dir.join(format!("{name}.c"));
    let out = dir.join(name);
    std::fs::write(&src, source).expect("write source");
    let mut cmd = Command::new("gcc");
    cmd.arg("-O0").arg("-static").arg("-o").arg(&out).arg(&src);
    let built = matches!(cmd.status(), Ok(status) if status.success());
    linux_compat::testing::require(
        &format!("a compiler that targets Linux x86-64 for {name} ({cmd:?})"),
        built.then(|| std::fs::read(&out).expect("compiler output")),
    )
}

/// A guest that never returns and never enters the kernel after it starts.
fn spinner() -> Option<Machine> {
    let image = compile_c(
        "spin",
        r#"
#include <unistd.h>
int main(void) {
    write(1, "spinning\n", 9);
    /* No syscalls past this point, and no way out. */
    volatile unsigned long x = 0;
    for (;;) x += 1;
}
"#,
    )?;
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine.add_file(b"/bin/spin", image, 0o755).expect("add");
    machine.set_args(vec![b"spin".to_vec()], vec![]);
    machine.load(b"/bin/spin").expect("load");
    Some(machine)
}

/// The host's loop: hand the guest a turn, take the answer, repeat. This is
/// what `web/worker.js` does, and what a spinning guest exploits.
fn host_loop(machine: &mut Machine, turns: u32, fuel: u64) -> (CpuExit, u32) {
    for turn in 1..=turns {
        machine.vm_mut().icount_limit = machine.icount() + fuel;
        let exit = machine.run();
        if exit != CpuExit::InstructionLimit {
            return (exit, turn);
        }
    }
    (CpuExit::InstructionLimit, turns)
}

#[test]
fn a_guest_that_only_computes_still_runs_out_of_cpu() {
    let Some(mut machine) = spinner() else {
        return;
    };
    machine.set_cpu_budget(Some(20_000_000));

    let (exit, turns) = host_loop(&mut machine, 10_000, 1_000_000);
    assert_eq!(
        exit,
        CpuExit::OutOfCpu,
        "a guest that issues no syscalls ran for {turns} turns without the \
         budget stopping it"
    );
    assert_eq!(machine.cpu_headroom(), Some(0), "stopped with budget left");
    assert!(
        machine.icount() <= 20_000_000,
        "ran {} instructions against a budget of 20,000,000",
        machine.icount()
    );
    assert!(
        String::from_utf8_lossy(&machine.take_output()).contains("spinning"),
        "the guest never got started, so the budget proved nothing"
    );
}

#[test]
fn a_spent_budget_stays_spent_until_it_is_raised() {
    let Some(mut machine) = spinner() else {
        return;
    };
    machine.set_cpu_budget(Some(5_000_000));
    assert_eq!(host_loop(&mut machine, 100, 1_000_000).0, CpuExit::OutOfCpu);

    // Asking again changes nothing: a ceiling a host can walk through by
    // calling twice is not a ceiling.
    machine.vm_mut().icount_limit = machine.icount() + 1_000_000;
    assert_eq!(machine.run(), CpuExit::OutOfCpu, "a second ask got through");
    let stopped_at = machine.icount();

    // Raising it lets the workload continue from where it stopped, so a host
    // can put the question to a person instead of killing the tab.
    machine.set_cpu_budget(Some(10_000_000));
    let (exit, _) = host_loop(&mut machine, 100, 1_000_000);
    assert_eq!(exit, CpuExit::OutOfCpu, "the raised budget was not spent");
    assert!(
        machine.icount() > stopped_at,
        "the workload did not continue: {} then {}",
        stopped_at,
        machine.icount()
    );
}

#[test]
fn no_budget_leaves_the_workload_alone() {
    let Some(mut machine) = spinner() else {
        return;
    };
    let (exit, turns) = host_loop(&mut machine, 20, 1_000_000);
    assert_eq!(
        exit,
        CpuExit::InstructionLimit,
        "an unbudgeted workload stopped on its own after {turns} turns"
    );
}

// ── The event log ────────────────────────────────────────────────────────────

/// A machine running an in-repo image, so this gate is real on every host
/// rather than skipping where no cross compiler lives.
fn traced(events: Option<usize>) -> Machine {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data");
    let image = std::fs::read(dir.join("hello_linux.elf")).expect("in-repo fixture");
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine.add_file(b"/bin/hello", image, 0o755).expect("add");
    machine.set_args(vec![b"hello".to_vec()], vec![]);
    machine.load(b"/bin/hello").expect("load");
    machine.set_event_log_budget(events);
    // Sample often enough that a short program produces many events.
    machine.record_trace(1);
    machine
}

#[test]
fn the_event_log_stops_at_its_ceiling_and_says_how_much_it_missed() {
    let mut machine = traced(Some(4));
    machine.vm_mut().icount_limit = machine.icount() + 1_000_000;
    let exit = machine.run_traced(1_000_000);
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "the guest did not run"
    );

    let dropped = machine.event_log_dropped();
    assert!(
        dropped > 0,
        "a ceiling of four events dropped none; either the workload produced \
         fewer than four events or the ceiling is not enforced"
    );

    let text = machine
        .take_trace()
        .expect("a trace was recorded")
        .to_text();
    let recorded = text.lines().filter(|l| !l.starts_with('#')).count();
    assert_eq!(
        recorded, 4,
        "recorded {recorded} events against a ceiling of 4"
    );
    assert!(
        text.contains(&format!("# truncated {dropped} events not recorded")),
        "the trace does not say it was truncated, so its end reads as the \
         workload's end:\n{}",
        text.lines().take(8).collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn an_unbounded_event_log_records_everything() {
    let mut machine = traced(None);
    machine.vm_mut().icount_limit = machine.icount() + 1_000_000;
    assert_eq!(
        machine.run_traced(1_000_000),
        CpuExit::Halt { code: Some(0) }
    );
    assert_eq!(
        machine.event_log_dropped(),
        0,
        "dropped events with no ceiling"
    );

    let text = machine
        .take_trace()
        .expect("a trace was recorded")
        .to_text();
    assert!(
        !text.contains("# truncated"),
        "an untruncated trace claimed truncation"
    );
    assert!(
        text.lines().filter(|l| !l.starts_with('#')).count() > 4,
        "the workload produced too few events for the ceiling test above to \
         mean anything"
    );
}

// ── Storage measures live data, not lifetime allocation ──────────────────────

/// A guest that writes a file, deletes it, and writes another must not be
/// refused for the second on account of the first. A storage ceiling that
/// counted every byte ever written — rather than what is live now — would
/// turn a long session that churns temporary files into one that eventually
/// cannot write at all.
///
/// Driven through the guest's own syscalls, because the reclamation a delete
/// triggers is part of what is under test.
#[test]
fn deleting_a_file_frees_its_storage() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data");
    let Ok(image) = std::fs::read(dir.join("hello_linux.elf")) else {
        return;
    };
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine.add_file(b"/bin/x", image, 0o755).expect("add");
    machine.set_args(vec![b"x".to_vec()], vec![]);
    machine.load(b"/bin/x").expect("load");

    // A page the guest owns, to hold syscall arguments.
    const SYS_MMAP: u64 = 9;
    const SYS_OPENAT: u64 = 257;
    const SYS_WRITE: u64 = 1;
    const SYS_CLOSE: u64 = 3;
    const SYS_UNLINKAT: u64 = 263;
    const AT_FDCWD: u64 = (-100_i64) as u64;
    const O_CREAT_WRONLY: u64 = 0o1 | 0o100;
    let (scratch, _) = machine.issue_syscall(SYS_MMAP, [0, 4096, 3, 0x22, u64::MAX, 0]);
    let scratch = scratch as u64;
    let (data_page, _) = machine.issue_syscall(SYS_MMAP, [0, 262_144, 3, 0x22, u64::MAX, 0]);
    let data_page = data_page as u64;

    // A ceiling that fits one big write but not two live at once.
    machine.set_storage_budget(Some(400_000));

    let path = b"/tmp/churn\0";
    machine
        .vm_mut()
        .cpu
        .mem
        .write_bytes(scratch, path, icicle_mem::perm::NONE)
        .expect("write path");

    for round in 0..3 {
        let (fd, _) =
            machine.issue_syscall(SYS_OPENAT, [AT_FDCWD, scratch, O_CREAT_WRONLY, 0o644, 0, 0]);
        assert!(fd >= 0, "round {round}: open failed ({fd})");
        let (written, _) =
            machine.issue_syscall(SYS_WRITE, [fd as u64, data_page, 200_000, 0, 0, 0]);
        assert_eq!(
            written, 200_000,
            "round {round}: a 200 KB write returned {written}; freed storage was not reclaimed"
        );
        machine.issue_syscall(SYS_CLOSE, [fd as u64, 0, 0, 0, 0, 0]);
        let (removed, _) = machine.issue_syscall(SYS_UNLINKAT, [AT_FDCWD, scratch, 0, 0, 0, 0]);
        assert_eq!(removed, 0, "round {round}: unlink failed");
    }

    let live = machine.env().vfs.bytes();
    assert!(
        live < 100_000,
        "live storage is {live} bytes after writing and deleting three 200 KB files; \
         deleted bytes were not freed"
    );
}
