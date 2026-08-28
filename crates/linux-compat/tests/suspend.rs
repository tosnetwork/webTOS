//! What a long-running workload sees when the tab it lives in is suspended.
//!
//! A browser stops scheduling a background tab. The worker is not called, so
//! no instructions retire and the idle warp does not move — this machine's
//! clock is made of exactly those two things. Minutes pass outside and none
//! inside, and a resumed guest believes it is still where it was: timers
//! pending that should have fired, timeouts unexpired, an idea of now that
//! every peer disagrees with.
//!
//! `Machine::skip_time` is how a host says it happened. These are the things
//! that have to hold when it does.

use std::path::PathBuf;
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn compile_c(name: &str, source: &str) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-suspend-fixture");
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

/// Runs `image`, suspending for `gap` nanoseconds the first time the guest
/// prints the line it uses to say it is ready for one.
fn run_with_suspension(image: Vec<u8>, gap: u64, marker: &str) -> (CpuExit, String) {
    let mut machine =
        Machine::from_ldef(&ldef_path(), &EngineConfig::default()).expect("machine build failed");
    machine
        .add_file(b"/bin/fixture", image, 0o755)
        .expect("add fixture");
    machine.set_args(vec![b"fixture".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/fixture").expect("ELF load failed");

    let mut output = String::new();
    let mut suspended = false;
    let mut exit;
    loop {
        // Short turns, so the host sees the marker while the guest still has
        // work left. A turn long enough to run the whole fixture would apply
        // the suspension after everything it was supposed to affect.
        machine.vm_mut().icount_limit = machine.icount() + 20_000_000;
        exit = machine.run();
        output.push_str(&String::from_utf8_lossy(&machine.take_output()));
        if !suspended && output.contains(marker) {
            // The tab goes away here, and comes back with the world moved on.
            machine.skip_time(gap);
            suspended = true;
        }
        if exit != CpuExit::InstructionLimit {
            break;
        }
    }
    assert!(suspended, "the guest never asked to be suspended: {output}");
    (exit, output)
}

#[test]
fn a_periodic_timer_reports_the_periods_it_missed_rather_than_firing_for_each() {
    let Some(image) = compile_c(
        "periodic",
        r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/timerfd.h>
#include <time.h>

int main(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec it;
    memset(&it, 0, sizeof it);
    it.it_value.tv_nsec = 1000000;      /* first in a millisecond */
    it.it_interval.tv_nsec = 1000000;   /* then every millisecond */
    if (timerfd_settime(fd, 0, &it, NULL) != 0) { printf("settime: %s\n", strerror(errno)); return 1; }

    struct timespec before, after;
    clock_gettime(CLOCK_MONOTONIC, &before);
    printf("READY\n");
    fflush(stdout);
    /* Work, not a wait: the suspension has to land while the guest still has
       something to do, because a machine whose clock is instructions plus an
       idle warp jumps straight to a deadline it is only waiting for. A tab is
       suspended mid-work, and that is the case worth modelling. */
    for (volatile long i = 0; i < 30000000L; i++) { }

    /* The read then reports what went by. Across a gap of three seconds that
       is three thousand periods — as a count, not as three thousand
       wakeups. */
    uint64_t count = 0;
    if (read(fd, &count, sizeof count) != sizeof count) { printf("read: %s\n", strerror(errno)); return 1; }
    clock_gettime(CLOCK_MONOTONIC, &after);

    long long moved = (long long) (after.tv_sec - before.tv_sec) * 1000000000LL
                    + (after.tv_nsec - before.tv_nsec);
    printf("expirations=%llu moved_ns=%lld\n", (unsigned long long) count, moved);

    /* And it keeps working afterwards: the next period still arrives. */
    if (read(fd, &count, sizeof count) != sizeof count) { printf("second read failed\n"); return 1; }
    printf("again=%llu\n", (unsigned long long) count);
    return 0;
}
"#,
    ) else {
        return;
    };

    // Three seconds of suspension against a one-millisecond period.
    let (exit, output) = run_with_suspension(image, 3_000_000_000, "READY");
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");

    let expirations: u64 = output
        .split("expirations=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("the fixture reported no expiration count");
    assert!(
        expirations > 1000,
        "a three-second gap against a one-millisecond period reported \
         {expirations} expirations; the clock did not move across the \
         suspension: {output}"
    );
    let moved: i64 = output
        .split("moved_ns=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("the fixture reported no elapsed time");
    assert!(
        moved >= 3_000_000_000,
        "the monotonic clock moved {moved} ns across a three-second gap: {output}"
    );
    assert!(
        output.contains("again="),
        "the timer stopped working after the gap: {output}"
    );
}

#[test]
fn an_interval_too_large_to_add_does_not_wrap_the_next_expiry() {
    let Some(image) = compile_c(
        "huge_interval",
        r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/timerfd.h>

int main(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec it;
    memset(&it, 0, sizeof it);
    it.it_value.tv_nsec = 1000;            /* fires almost at once */
    /* Large enough that converting it to nanoseconds saturates: the interval
       becomes the biggest number there is, and adding it to anything at all
       is where the wrap lives. */
    it.it_interval.tv_sec = 9223372036854775807LL;
    if (timerfd_settime(fd, 0, &it, NULL) != 0) { printf("settime: %s\n", strerror(errno)); return 1; }
    printf("READY\n");
    fflush(stdout);

    uint64_t count = 0;
    if (read(fd, &count, sizeof count) != sizeof count) { printf("read: %s\n", strerror(errno)); return 1; }
    printf("first=%llu\n", (unsigned long long) count);

    /* A next expiry that wrapped would land in the past, and this read would
       return immediately instead of the timer being far in the future. */
    struct itimerspec left;
    timerfd_gettime(fd, &left);
    printf("remaining_sec=%lld\n", (long long) left.it_value.tv_sec);
    return 0;
}
"#,
    ) else {
        return;
    };
    let (exit, output) = run_with_suspension(image, 1_000_000_000, "READY");
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("first=1"),
        "the timer did not fire once: {output}"
    );
    let remaining: i64 = output
        .split("remaining_sec=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("no remaining time reported");
    assert!(
        remaining > 0,
        "the next expiry wrapped into the past ({remaining}s remaining), so \
         the timer would fire forever: {output}"
    );
}

#[test]
fn a_sleep_that_the_gap_swallowed_returns_rather_than_waiting_again() {
    let Some(image) = compile_c(
        "sleeper",
        r#"
#include <stdio.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    struct timespec before, after;
    clock_gettime(CLOCK_MONOTONIC, &before);
    printf("READY\n");
    fflush(stdout);

    /* Two seconds, against a gap of ten. */
    struct timespec want = { .tv_sec = 2, .tv_nsec = 0 };
    nanosleep(&want, NULL);

    clock_gettime(CLOCK_MONOTONIC, &after);
    long long moved = (long long) (after.tv_sec - before.tv_sec) * 1000000000LL
                    + (after.tv_nsec - before.tv_nsec);
    printf("slept moved_ns=%lld\n", moved);
    return 0;
}
"#,
    ) else {
        return;
    };
    let (exit, output) = run_with_suspension(image, 10_000_000_000, "READY");
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("slept moved_ns="),
        "the sleep never returned across the gap: {output}"
    );
    let moved: i64 = output
        .split("moved_ns=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .expect("no elapsed time reported");
    assert!(
        moved >= 2_000_000_000,
        "a two-second sleep across a ten-second gap measured {moved} ns: {output}"
    );
}
