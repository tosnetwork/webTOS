//! Recording network input, replaying it offline, and classifying it.
//!
//! The interface a session's network crosses is one trait, so recording is a
//! wrapper around it and replay is another implementation of it. The property
//! that makes a recording a recording: a session captured against a live
//! server runs again from the recording alone, with no server, and the guest
//! produces the identical output. If the recording were lossy, or replay
//! served the wrong bytes, the second run would diverge.

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use linux_compat::net::{BrokerRef, NativeBroker};
use linux_compat::netrecord::{Outcome, Protocol, Recording, RecordingBroker, ReplayBroker};
use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

mod netcommon;
use netcommon::{ldef_path, spawn_http_server};

fn alpine() -> Option<Machine> {
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

fn wget(machine: &mut Machine) -> (CpuExit, String) {
    machine.set_args(
        vec![
            b"wget".to_vec(),
            b"-q".to_vec(),
            b"-O-".to_vec(),
            b"http://10.0.0.1/".to_vec(),
        ],
        vec![b"PATH=/bin:/usr/bin".to_vec(), b"HOME=/root".to_vec()],
    );
    machine.load(b"/usr/bin/wget").expect("load wget");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    (
        exit,
        String::from_utf8_lossy(&machine.take_output()).into_owned(),
    )
}

#[test]
fn a_session_recorded_against_a_server_replays_with_no_server() {
    let Some(mut machine) = alpine() else {
        return;
    };
    let server = spawn_http_server();

    // Record: a real fetch through a real broker, wrapped so every byte the
    // guest receives is logged.
    let mut inner = NativeBroker::new();
    inner.redirect(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80), server);
    inner.restrict_to_redirects();
    let (recorder, log) = RecordingBroker::new(inner);
    machine.set_network(Rc::new(RefCell::new(recorder)) as BrokerRef);

    let (exit, live_output) = wget(&mut machine);
    assert_eq!(
        exit,
        CpuExit::Halt { code: Some(0) },
        "live fetch failed: {live_output}"
    );
    assert!(
        live_output.contains("hello-from-webtos-m5"),
        "the live fetch got no body: {live_output}"
    );

    let recording = log.borrow().clone();
    assert!(
        !recording.events.is_empty(),
        "the recording captured nothing"
    );

    // Replay: a fresh guest, the recording, and no server at all — the port
    // the recording names is not even listened on now.
    let Some(mut replayed) = alpine() else {
        return;
    };
    replayed.set_network(Rc::new(RefCell::new(ReplayBroker::new(recording))) as BrokerRef);
    let (replay_exit, replay_output) = wget(&mut replayed);

    assert_eq!(
        replay_exit,
        CpuExit::Halt { code: Some(0) },
        "the replay did not complete: {replay_output}"
    );
    assert_eq!(
        replay_output, live_output,
        "the replay produced different output than the recording it came from"
    );
}

#[test]
fn a_recording_classifies_into_receipts() {
    let Some(mut machine) = alpine() else {
        return;
    };
    let server = spawn_http_server();
    let mut inner = NativeBroker::new();
    inner.redirect(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80), server);
    inner.restrict_to_redirects();
    let (recorder, log) = RecordingBroker::new(inner);
    machine.set_network(Rc::new(RefCell::new(recorder)) as BrokerRef);

    let (exit, _) = wget(&mut machine);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) });

    let receipts = log.borrow().receipts();
    let tcp: Vec<_> = receipts
        .iter()
        .filter(|r| r.protocol == Protocol::Tcp)
        .collect();
    assert_eq!(
        tcp.len(),
        1,
        "expected one TCP connection, got {}",
        tcp.len()
    );
    let receipt = tcp[0];
    // The receipt says who was reached — the guest-visible redirect address,
    // which is what the session was told it was talking to.
    assert_eq!(
        receipt.peer,
        Some(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 80)),
        "the receipt named the wrong peer"
    );
    assert!(receipt.bytes_sent > 0, "the request was not counted");
    assert!(
        receipt.bytes_received > 0,
        "the response was not counted: {receipt:?}"
    );
    // The server sends `Connection: close`, so the stream ends in a close.
    assert!(
        matches!(receipt.outcome, Outcome::Closed | Outcome::Open),
        "unexpected outcome: {:?}",
        receipt.outcome
    );
}

#[test]
fn a_refused_connection_is_its_own_receipt() {
    // Classification without a machine: a recording built by hand, to check
    // that a refusal — the outcome most worth seeing in a receipt — is
    // classified even though it never got a handle.
    use linux_compat::netrecord::NetEvent;
    let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 80);
    let recording = Recording {
        events: vec![NetEvent::TcpConnect {
            addr,
            result: Err(linux_compat::abi::ECONNREFUSED),
        }],
    };
    let receipts = recording.receipts();
    assert_eq!(receipts.len(), 1, "a refusal produced no receipt");
    assert_eq!(receipts[0].peer, Some(addr));
    assert_eq!(
        receipts[0].outcome,
        Outcome::Refused(linux_compat::abi::ECONNREFUSED),
        "a refused connection was not classified as refused"
    );
}
