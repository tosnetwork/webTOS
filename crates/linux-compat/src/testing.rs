//! Support for the integration tests.
//!
//! A test whose fixture is missing skips. That is right on a developer's
//! machine — nobody should need a cross compiler and a 96 MB agent image to
//! run the unit tests — and it is how two failing gates went unnoticed once
//! already: the suite reported "ok" in hundredths of a second while running
//! none of the cases that mattered.
//!
//! So a skip has to be visible, and somewhere it has to be forbidden. With
//! `WEBTOS_REQUIRE_FIXTURES=1` every skip becomes a failure, which is how the
//! host that can build and run everything is stopped from quietly covering
//! less than it claims.

/// Passes a fixture through, or records that it is missing.
///
/// `what` should name the fixture and how to obtain it, because the message
/// is the only thing a reader gets when a test does nothing.
pub fn require<T>(what: &str, found: Option<T>) -> Option<T> {
    if found.is_some() {
        return found;
    }
    assert!(
        std::env::var_os("WEBTOS_REQUIRE_FIXTURES").is_none(),
        "fixture unavailable: {what} — and WEBTOS_REQUIRE_FIXTURES is set, \
         so skipping is a failure here"
    );
    eprintln!("SKIP: fixture unavailable: {what}");
    None
}
