//! Alternate signal stacks.
//!
//! A runtime installs one so a handler has somewhere to run when the stack it
//! interrupted is the problem — a fault on an exhausted thread or goroutine
//! stack. Recording the request and ignoring it is the failure that matters
//! least until it matters most: the handler runs on the stack that just
//! overflowed, and the process dies where it meant to report.
//!
//! The test is where the handler's own locals live. Nothing else distinguishes
//! a handler that got the stack it asked for from one that was told it did.

use std::path::PathBuf;
use std::process::Command;

use linux_compat::Machine;
use x64_engine::{CpuExit, EngineConfig};

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

fn compile_c(name: &str, source: &str) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join("webtos-altstack-fixture");
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
    machine.set_args(vec![b"fixture".to_vec()], vec![b"PATH=/bin".to_vec()]);
    machine.load(b"/bin/fixture").expect("ELF load failed");
    machine.vm_mut().icount_limit = machine.icount() + 4_000_000_000;
    let exit = machine.run();
    let output = String::from_utf8_lossy(&machine.take_output()).into_owned();
    (exit, output)
}

#[test]
fn a_handler_that_asked_for_the_alternate_stack_runs_on_it() {
    let Some(image) = compile_c(
        "onstack",
        r#"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#define ALT_SIZE 65536
static char alt[ALT_SIZE];
static volatile int ran;

static void handler(int sig) {
    volatile char local;
    /* The one question worth asking: where does the handler's own frame
       live? On the alternate stack, or on the one it interrupted? */
    unsigned long here = (unsigned long) &local;
    unsigned long base = (unsigned long) alt;
    printf("handler local=%lu inside=%d\n", here, here >= base && here < base + ALT_SIZE);
    stack_t cur;
    sigaltstack(NULL, &cur);
    printf("during: flags=%d\n", cur.ss_flags);
    /* Changing the stack a handler is standing on must be refused. */
    stack_t other = { .ss_sp = alt, .ss_size = ALT_SIZE, .ss_flags = 0 };
    errno = 0;
    /* Sequenced deliberately: argument evaluation order is unspecified, so
       reading errno inside the same call can read it before the call ran. */
    int rc = sigaltstack(&other, NULL);
    int saved = errno;
    printf("swap during: rc=%d errno=%d\n", rc, saved);
    ran = 1;
}

int main(void) {
    stack_t ss = { .ss_sp = alt, .ss_size = ALT_SIZE, .ss_flags = 0 };
    if (sigaltstack(&ss, NULL) != 0) { printf("sigaltstack: %s\n", strerror(errno)); return 1; }

    stack_t back;
    sigaltstack(NULL, &back);
    printf("registered base=%lu size=%lu flags=%d\n",
           (unsigned long) back.ss_sp, (unsigned long) back.ss_size, back.ss_flags);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sa.sa_flags = SA_ONSTACK;
    sigaction(SIGUSR1, &sa, NULL);

    volatile char main_local;
    printf("main local=%lu\n", (unsigned long) &main_local);
    raise(SIGUSR1);
    printf("ran=%d\n", ran);

    /* After the handler returns, the process is off the alternate stack. */
    stack_t after;
    sigaltstack(NULL, &after);
    printf("after: flags=%d\n", after.ss_flags);
    return 0;
}
"#,
    ) else {
        return;
    };
    let (exit, output) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("registered base=") && output.contains("flags=0\n"),
        "the registration was not read back: {output}"
    );
    assert!(
        output.contains("inside=1"),
        "the handler's frame was not on the stack it asked for: {output}"
    );
    assert!(
        output.contains("during: flags=1"),
        "sigaltstack did not report SS_ONSTACK while the handler ran: {output}"
    );
    assert!(
        output.contains(&format!("swap during: rc=-1 errno={}", 1)),
        "changing the stack under a running handler was allowed: {output}"
    );
    assert!(
        output.contains("after: flags=0"),
        "the process stayed on the alternate stack after the handler returned: {output}"
    );
    assert!(
        output.contains("ran=1"),
        "the handler did not run: {output}"
    );
}

#[test]
fn a_handler_without_the_flag_stays_where_it_was() {
    let Some(image) = compile_c(
        "offstack",
        r#"
#include <stdio.h>
#include <string.h>
#include <signal.h>

#define ALT_SIZE 65536
static char alt[ALT_SIZE];

static void handler(int sig) {
    volatile char local;
    unsigned long here = (unsigned long) &local;
    unsigned long base = (unsigned long) alt;
    printf("handler inside=%d\n", here >= base && here < base + ALT_SIZE);
}

int main(void) {
    stack_t ss = { .ss_sp = alt, .ss_size = ALT_SIZE, .ss_flags = 0 };
    sigaltstack(&ss, NULL);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    sa.sa_flags = 0;   /* registered, but not asked for */
    sigaction(SIGUSR1, &sa, NULL);
    raise(SIGUSR1);
    return 0;
}
"#,
    ) else {
        return;
    };
    let (exit, output) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("inside=0"),
        "a handler that did not ask for the alternate stack was put on it anyway: {output}"
    );
}

#[test]
fn a_stack_too_small_to_hold_a_frame_is_refused() {
    let Some(image) = compile_c(
        "toosmall",
        r#"
#include <stdio.h>
#include <errno.h>
#include <signal.h>

static char tiny[64];
static char ok_stack[65536];

int main(void) {
    stack_t small = { .ss_sp = tiny, .ss_size = sizeof tiny, .ss_flags = 0 };
    errno = 0;
    int rc = sigaltstack(&small, NULL);
    int saved = errno;
    printf("small: rc=%d errno=%d\n", rc, saved);

    stack_t good = { .ss_sp = ok_stack, .ss_size = sizeof ok_stack, .ss_flags = 0 };
    printf("good: rc=%d\n", sigaltstack(&good, NULL));

    stack_t off = { .ss_flags = SS_DISABLE };
    printf("disable: rc=%d\n", sigaltstack(&off, NULL));
    stack_t back;
    sigaltstack(NULL, &back);
    printf("after disable: flags=%d\n", back.ss_flags);
    return 0;
}
"#,
    ) else {
        return;
    };
    let (exit, output) = run(image);
    assert_eq!(exit, CpuExit::Halt { code: Some(0) }, "{output}");
    assert!(
        output.contains("small: rc=-1 errno=12"),
        "a stack too small to hold a frame was accepted: {output}"
    );
    assert!(
        output.contains("good: rc=0"),
        "a usable stack was refused: {output}"
    );
    assert!(
        output.contains("disable: rc=0") && output.contains("after disable: flags=2"),
        "the stack could not be taken away again: {output}"
    );
}
