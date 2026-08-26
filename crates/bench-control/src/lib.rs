//! A control for browser measurements: one small hot loop, and nothing else.
//!
//! The engine benchmark in `web/bench.mjs` runs a 1.3 MB module whose
//! interpreter is a single 60 KB function, which is exactly the shape an
//! optimizing compiler might decline to handle. When one engine turns out to
//! be several times slower than another, that is the first explanation to
//! reach for — and it was wrong: the same spread appears here, in a module of
//! a few hundred bytes that no size heuristic can touch.
//!
//! So this exists to keep that mistake from being made again. A slow engine
//! here is a slow engine, not a declined function.

/// Retires a fixed amount of arithmetic per round, with a dependency chain
/// that stops the loop from being vectorised or hoisted away. The return
/// value is checked by the caller so the whole thing cannot be optimized out.
#[no_mangle]
pub extern "C" fn mix(rounds: u32) -> u32 {
    let mut state: u32 = 0x9e37_79b9;
    for i in 0..rounds {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        state ^= state >> 15;
        state = state.wrapping_add(i);
        state = state.rotate_left(7);
    }
    state
}
