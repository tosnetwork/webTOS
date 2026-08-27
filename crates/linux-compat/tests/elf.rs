//! A guest image comes from outside this program: streamed in over the network
//! or read back out of browser storage, where a partial write, an eviction, or
//! a flipped bit is ordinary. Loading one must fail closed — an error, never a
//! panic, never a hang, and never a reservation made on the strength of a
//! number in the header rather than on the bytes that are actually there.
//!
//! The sweeps below build one machine and reuse it: `Machine::from_ldef` parses
//! the whole processor spec and costs about two seconds, while a load costs
//! well under a millisecond, and `load` resets the address space anyway.

use std::cell::Cell;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::{Mutex, Once};
use std::time::{Duration, Instant};

use linux_compat::Machine;
use x64_engine::EngineConfig;

fn ldef_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/ghidra-x86/languages/x86.ldefs")
}

/// A real, statically linked x86-64 image that lives in the repository, so a
/// sweep over it can never silently skip.
fn sample_elf() -> Vec<u8> {
    std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test_data/hello_linux.elf"))
        .expect("in-repo fixture")
}

/// What happened to a load. Refusing corrupt bytes is the point; panicking on
/// them is the defect, so the two are kept apart rather than both counting as
/// "did not load".
enum Outcome {
    Loaded,
    Refused(String),
    Panicked(String),
}

impl Outcome {
    /// The message from a load that was refused, failing the test on anything
    /// else. Callers then assert on *which* refusal: a corrupt image fails to
    /// load for many reasons, so "it returned an error" on its own says
    /// nothing about the reason the test is here for.
    fn refusal(self, what: &str) -> String {
        match self {
            Outcome::Refused(message) => message,
            Outcome::Loaded => panic!("{what} was loaded"),
            Outcome::Panicked(message) => panic!("{what} panicked: {message}"),
        }
    }
}

static PANICS: Mutex<Option<HashMap<std::thread::ThreadId, String>>> = Mutex::new(None);
static HOOK: Once = Once::new();
thread_local! {
    /// Set while a load is running, so the panic hook can tell a panic that
    /// this file is here to catch from one that means the test itself failed.
    static IN_LOAD: Cell<bool> = const { Cell::new(false) };
}

/// A machine to feed images to. A `Machine` is not `Sync`, so each test owns
/// one and reuses it for every image it tries.
struct Probe {
    machine: Machine,
}

impl Probe {
    fn new() -> Self {
        HOOK.call_once(|| {
            // The default hook prints every panic, and a sweep that trips
            // thousands would bury its own output — so a panic from inside a
            // load is kept rather than printed. Every other panic, including
            // this file's own failed assertions, still goes to the default
            // hook, or a failing test would report nothing at all.
            let default = std::panic::take_hook();
            std::panic::set_hook(Box::new(move |info| {
                if !IN_LOAD.with(|loading| loading.get()) {
                    return default(info);
                }
                PANICS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_or_insert_with(HashMap::new)
                    .insert(
                        std::thread::current().id(),
                        format!("{info}").replace('\n', " "),
                    );
            }));
        });
        Probe {
            machine: Machine::from_ldef(&ldef_path(), &EngineConfig::default())
                .expect("machine build failed"),
        }
    }

    /// Loads `image` as the guest's `/bin/probe`, catching a panic instead of
    /// taking the test binary down with it — a sweep that aborts on its first
    /// panic reports neither which case caused it nor what else is behind it.
    fn load(&mut self, image: &[u8]) -> Outcome {
        let machine = &mut self.machine;
        machine
            .add_file(b"/bin/probe", image.to_vec(), 0o755)
            .expect("seed image");
        IN_LOAD.with(|loading| loading.set(true));
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| machine.load(b"/bin/probe")));
        IN_LOAD.with(|loading| loading.set(false));
        match outcome {
            Ok(Ok(())) => Outcome::Loaded,
            Ok(Err(message)) => Outcome::Refused(message),
            Err(_) => Outcome::Panicked(
                PANICS
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .as_mut()
                    .and_then(|panics| panics.remove(&std::thread::current().id()))
                    .unwrap_or_else(|| "panicked".into()),
            ),
        }
    }

    /// Guest pages the machine is holding after the last load.
    fn guest_bytes(&mut self) -> usize {
        self.machine.footprint().guest_bytes
    }
}

// Field offsets in a 64-bit ELF: the file header, then the program header
// table it points at, each entry `PHDR_SIZE` bytes.
const E_PHOFF: usize = 0x20;
const E_PHNUM: usize = 0x38;
const PHDR_SIZE: usize = 56;
const P_TYPE: usize = 0;
const P_OFFSET: usize = 8;
const P_VADDR: usize = 16;
const P_FILESZ: usize = 32;
const P_MEMSZ: usize = 40;
const P_ALIGN: usize = 48;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;

fn u64_at(image: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(image[at..at + 8].try_into().expect("eight bytes"))
}

fn phdr_at(image: &[u8], index: usize) -> usize {
    u64_at(image, E_PHOFF) as usize + index * PHDR_SIZE
}

fn phnum(image: &[u8]) -> usize {
    u16::from_le_bytes(image[E_PHNUM..E_PHNUM + 2].try_into().expect("two bytes")) as usize
}

fn segment_type(image: &[u8], index: usize) -> u32 {
    let at = phdr_at(image, index) + P_TYPE;
    u32::from_le_bytes(image[at..at + 4].try_into().expect("four bytes"))
}

fn set_type(image: &mut [u8], index: usize, value: u32) {
    let at = phdr_at(image, index) + P_TYPE;
    image[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn set_field(image: &mut [u8], index: usize, field: usize, value: u64) {
    let at = phdr_at(image, index) + field;
    image[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// The index of a segment the loader maps, so a test can rewrite one field of
/// a header that is actually used.
fn a_loadable_segment(image: &[u8]) -> usize {
    (0..phnum(image))
        .find(|&index| segment_type(image, index) == PT_LOAD)
        .expect("the fixture has a loadable segment")
}

/// One past the last file byte any loadable segment refers to. Bytes after it
/// are section headers and debug information, which the loader does not need,
/// so a file cut there is still a complete program — unlike the snapshot
/// format, an ELF has a legitimate loadable prefix.
fn last_loaded_byte(image: &[u8]) -> usize {
    (0..phnum(image))
        .filter(|&index| segment_type(image, index) == PT_LOAD)
        .map(|index| {
            let at = phdr_at(image, index);
            (u64_at(image, at + P_OFFSET) + u64_at(image, at + P_FILESZ)) as usize
        })
        .max()
        .expect("the fixture has a loadable segment")
}

/// The header table itself, where a flipped bit changes what the loader is
/// told to do rather than what the program will compute.
fn header_bytes(image: &[u8]) -> usize {
    u64_at(image, E_PHOFF) as usize + phnum(image) * PHDR_SIZE
}

#[test]
fn the_fixture_loads() {
    let elf = sample_elf();
    match Probe::new().load(&elf) {
        Outcome::Loaded => {}
        Outcome::Refused(message) => panic!("the fixture did not load: {message}"),
        Outcome::Panicked(message) => panic!("the fixture panicked: {message}"),
    }
}

/// Every truncation. A stream that stops early is the likeliest corruption
/// there is, and every prefix short of the last byte a segment refers to has
/// to be an error rather than a shorter program.
#[test]
fn every_truncation_short_of_the_last_segment_is_refused() {
    let elf = sample_elf();
    let mut probe = Probe::new();
    let complete = last_loaded_byte(&elf);
    for cut in 0..complete {
        match probe.load(&elf[..cut]) {
            Outcome::Refused(_) => {}
            Outcome::Loaded => panic!("an image truncated to {cut} of {} bytes loaded", elf.len()),
            Outcome::Panicked(message) => {
                panic!("an image truncated to {cut} bytes panicked: {message}")
            }
        }
    }
    // The bytes past that point are section headers the loader does not need,
    // so cutting them off leaves a program that still runs. Checked here so
    // the bound above is a real edge and not a blanket refusal.
    match probe.load(&elf[..complete]) {
        Outcome::Loaded => {}
        Outcome::Refused(message) => panic!("an image with every mapped byte present: {message}"),
        Outcome::Panicked(message) => panic!("panicked: {message}"),
    }
}

/// Single-bit corruption. Accepting one is allowed — most of an image is code
/// and data, where a flipped bit makes a different but perfectly loadable
/// program — but panicking is not, and neither is taking a long time or
/// holding a lot of memory over a few kilobytes of input.
///
/// Every bit of the ELF header and the program header table is swept, because
/// that is where a bit decides what the loader does. The rest is sampled every
/// 13th byte: a full sweep is 70,528 loads and about 50 seconds, and the stride
/// is fixed rather than random so that a failure here is reproducible.
#[test]
fn no_single_bit_flip_panics() {
    let elf = sample_elf();
    let mut probe = Probe::new();
    let headers = header_bytes(&elf);
    let mut loaded = 0_usize;
    let mut slowest = (Duration::ZERO, String::new());
    let mut peak = 0_usize;
    for index in (0..elf.len()).filter(|&index| index < headers || index % 13 == 0) {
        for bit in 0..8 {
            let mut damaged = elf.clone();
            damaged[index] ^= 1 << bit;
            let started = Instant::now();
            let outcome = probe.load(&damaged);
            let elapsed = started.elapsed();
            if elapsed > slowest.0 {
                slowest = (elapsed, format!("byte {index} bit {bit}"));
            }
            peak = peak.max(probe.guest_bytes());
            match outcome {
                Outcome::Loaded => loaded += 1,
                Outcome::Refused(_) => {}
                Outcome::Panicked(message) => {
                    panic!("byte {index} bit {bit} panicked: {message}")
                }
            }
        }
    }
    // The sweep is only evidence if some of it got past the headers and into
    // the mapping, the writing, and the stack it all lands on.
    assert!(
        loaded > 0,
        "no damaged image loaded, so nothing past the header was tested"
    );
    // A load is under a millisecond; a second means something went looking for
    // a place to put an implausible claim.
    assert!(
        slowest.0 < Duration::from_secs(1),
        "a damaged image took {:?} to refuse ({})",
        slowest.0,
        slowest.1
    );
    assert!(
        peak < 64 * 1024 * 1024,
        "a damaged 8 KiB image left {peak} bytes of guest memory allocated"
    );
}

/// A segment can claim an alignment that is not a power of two — one flipped
/// bit in 0x1000 does it — and the loader divides the address by it and hands
/// it to an `align_up` that asserts on it. Refusing the claim is the only
/// thing that can be done with it.
#[test]
fn an_alignment_that_is_not_a_power_of_two_is_refused() {
    let mut elf = sample_elf();
    let segment = a_loadable_segment(&elf);
    set_field(&mut elf, segment, P_ALIGN, 0x1001);
    let message = Probe::new().load(&elf).refusal("an alignment of 0x1001");
    assert!(
        message.contains("alignment") && message.contains("power of two"),
        "the alignment was not refused as such; it failed later for another reason: {message}"
    );
}

/// Zero is the other end of the same flipped bit, and ELF gives it a meaning:
/// no alignment requirement. Dividing by it is what must not happen, so this
/// image is expected to load rather than to be refused.
#[test]
fn an_alignment_of_zero_means_unaligned_rather_than_a_division() {
    let mut elf = sample_elf();
    let segment = a_loadable_segment(&elf);
    set_field(&mut elf, segment, P_ALIGN, 0);
    match Probe::new().load(&elf) {
        Outcome::Loaded => {}
        Outcome::Refused(message) => panic!("an unaligned segment was refused: {message}"),
        Outcome::Panicked(message) => panic!("an alignment of zero panicked: {message}"),
    }
}

/// With no loadable segment there is no image, and the layout that describes
/// one is a region of zero length starting at the top of the address space.
/// Allocating that underflows on the length, so it has to be refused here.
#[test]
fn an_image_with_nothing_to_load_is_refused() {
    let mut elf = sample_elf();
    for index in 0..phnum(&elf) {
        if segment_type(&elf, index) == PT_LOAD {
            set_type(&mut elf, index, 0); // PT_NULL
        }
    }
    let message = Probe::new()
        .load(&elf)
        .refusal("an image with no loadable segment");
    assert!(
        message.contains("no loadable segments"),
        "an image with nothing to load failed for an unrelated reason: {message}"
    );
}

/// A segment can say it starts one page below the top of the address space,
/// or that it is as long as the address space itself. Either is a claim about
/// where it ends that does not fit in an address, and computing with it wraps
/// the end of the image around to a low one.
#[test]
fn a_segment_that_runs_past_the_address_space_is_refused() {
    let mut probe = Probe::new();

    let mut elf = sample_elf();
    let segment = a_loadable_segment(&elf);
    set_field(&mut elf, segment, P_VADDR, u64::MAX - 0xfff);
    let message = probe
        .load(&elf)
        .refusal("a segment at the top of the address space");
    assert!(
        message.contains("past the address space"),
        "the span was not refused as impossible; it failed later: {message}"
    );

    let mut elf = sample_elf();
    set_field(&mut elf, segment, P_MEMSZ, u64::MAX);
    let message = probe.load(&elf).refusal("a segment of 2^64 bytes");
    assert!(
        message.contains("past the address space"),
        "the length was not refused as impossible; it failed later: {message}"
    );
}

/// A length of 2^32 plus the real one reads as the real one to anything that
/// narrows it to a 32-bit `usize`, and the browser's `usize` is 32-bit: the
/// image would load as though nothing were wrong, with a segment of a
/// different size than the file says. Nothing in this path narrows — it works
/// in `u64` throughout, and the conversions into an index are checked — so
/// this is a guard rather than a fix, and it has a twin in the wasm harness
/// (`web/test_node.mjs`), which is the only place a narrowing could show.
#[test]
fn a_length_that_would_narrow_on_a_32_bit_host_is_refused() {
    let mut elf = sample_elf();
    let segment = a_loadable_segment(&elf);
    let real = u64_at(&elf, phdr_at(&elf, segment) + P_FILESZ);
    set_field(&mut elf, segment, P_FILESZ, (1 << 32) + real);
    let message = Probe::new()
        .load(&elf)
        .refusal("a file length of 2^32 plus the real one");
    assert!(
        message.contains("data invalid"),
        "the length was not refused against the file; it failed later: {message}"
    );
}

/// The same claim made through the alignment instead of the length: a segment
/// aligned to 2^63 is rounded up to a length of 2^63, and the image is then
/// mapped somewhere that leaves it ending past the top of the address space.
/// Whoever loaded it goes on to place the heap after the end, so an end that
/// wrapped is worse than a refusal.
#[test]
fn an_image_that_ends_past_the_address_space_is_refused() {
    let mut elf = sample_elf();
    let segment = a_loadable_segment(&elf);
    set_field(&mut elf, segment, P_ALIGN, 1 << 63);
    let message = Probe::new()
        .load(&elf)
        .refusal("an image spanning half the address space");
    assert!(
        message.contains("does not fit"),
        "the image was not refused for where it ends; it failed later: {message}"
    );
}

/// An image is free to name itself as its own interpreter. Following that
/// recurses until the stack is gone, which aborts the process — the sweep
/// above cannot even catch it, because a stack overflow is not a panic.
#[test]
fn an_image_that_names_itself_as_its_interpreter_is_refused() {
    let mut elf = sample_elf();
    // Point a segment the loader otherwise ignores at a null-terminated path
    // stored in the image, and call it the interpreter.
    let path = b"/bin/probe\0";
    let at = 0x300;
    elf[at..at + path.len()].copy_from_slice(path);
    let spare = (0..phnum(&elf))
        .find(|&index| segment_type(&elf, index) != PT_LOAD)
        .expect("the fixture has a segment to spare");
    set_type(&mut elf, spare, PT_INTERP);
    set_field(&mut elf, spare, P_OFFSET, at as u64);
    set_field(&mut elf, spare, P_FILESZ, path.len() as u64);
    set_field(&mut elf, spare, P_MEMSZ, path.len() as u64);
    let message = Probe::new()
        .load(&elf)
        .refusal("an image that is its own interpreter");
    assert!(
        message.contains("interpreter"),
        "the self-reference was not what stopped it: {message}"
    );
}

/// A header can claim far more memory than the file could ever hold — 64 TiB
/// out of 8 KiB. Reserving for that on the strength of the claim is the whole
/// attack, so what is asserted is the consequence rather than the return
/// value: whatever the loader decides about this image, it must not have put
/// anything aside for the claim.
///
/// This passes as the loader stands: it maps a range and hands out pages when
/// the guest touches them, so a claim costs a map entry. Nothing was fixed
/// here; the assertion exists so that a loader which starts reserving eagerly
/// fails this test rather than a browser tab.
#[test]
fn a_segment_claiming_more_memory_than_the_file_holds_reserves_nothing() {
    let mut elf = sample_elf();
    let segment = a_loadable_segment(&elf);
    set_field(&mut elf, segment, P_MEMSZ, 0x0000_4000_0000_0000);
    let mut probe = Probe::new();
    let started = Instant::now();
    let outcome = probe.load(&elf);
    let elapsed = started.elapsed();
    if let Outcome::Panicked(message) = outcome {
        panic!("a 64 TiB claim panicked: {message}");
    }
    assert!(
        probe.guest_bytes() < 4 * 1024 * 1024,
        "a 64 TiB claim from an 8 KiB file left {} bytes of guest memory allocated",
        probe.guest_bytes()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "a 64 TiB claim from an 8 KiB file took {elapsed:?}"
    );
}
