#![no_main]
//! Fuzz target: dom_wallet_keys::ExtendedPrivKey::derive_path — DEPTH-OVERFLOW leg.
//!
//! WHY THIS EXISTS (anti-theater): the sibling target `fuzz_derive_path` already
//! feeds an arbitrary UTF-8-lossy `&str` to `derive_path`, so it covers the whole
//! string-parsing surface (separators, "m/" strip, trailing "'" hardened markers,
//! u32::parse leading-zeros / huge indices, checked_add(HARDENED_OFFSET) overflow).
//! That coverage is NOT duplicated here.
//!
//! The one branch the byte-mutator string fuzzer realistically CANNOT reach is the
//! depth counter at `child(): depth = self.depth.saturating_add(1)` (hd_wallet.rs).
//! Saturating past u8::MAX (255) requires a path with >255 *valid* components, each
//! surviving a real secp256k1 tweak-add. A random &str almost never synthesizes a
//! 256-deep all-valid path, so the saturation edge is under-exercised by that target.
//!
//! This target STRUCTURES the input so the fuzzer can deterministically build very
//! deep, valid component chains and drive the saturating_add depth edge:
//!   layout: [0..32] = seed; [32] = per-component hardened bitmask seed (unused as
//!   mask, kept for entropy); [33..] = stream of LE u16 indices, one component each.
//! We synthesize the path string ("m/<i0>/<i1>'/...") and feed it to derive_path,
//! so we exercise the SAME public API the production code uses — no private reach.
//!
//! Invariant: deriving a (possibly very deep) path must NEVER panic. Ok | Err only.
//! In particular `depth` must saturate at 255, never wrap/overflow-panic.

use dom_wallet_keys::ExtendedPrivKey;
use libfuzzer_sys::fuzz_target;
use std::fmt::Write as _;

// Bound the synthesized path so a single case stays cheap-ish while still able to
// exceed the u8 depth ceiling (256 components > 255 -> saturation). secp256k1
// tweak-adds dominate cost; ~300 keeps the door to the edge open without runaway.
const MAX_COMPONENTS: usize = 300;

fuzz_target!(|data: &[u8]| {
    if data.len() < 33 {
        return;
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&data[..32]);
    let master = match ExtendedPrivKey::from_seed(&seed) {
        Ok(m) => m,
        Err(_) => return,
    };

    // Remaining bytes drive component indices, 2 bytes (LE u16) per component.
    // Using small (u16) indices maximizes the chance child() succeeds, so the
    // chain actually gets deep enough to saturate `depth`.
    let body = &data[33..];
    let mut path = String::from("m");
    let mut count = 0usize;
    for chunk in body.chunks_exact(2) {
        if count >= MAX_COMPONENTS {
            break;
        }
        let idx = u16::from_le_bytes([chunk[0], chunk[1]]) as u32;
        // Alternate hardened/non-hardened so both child() arms are exercised at depth.
        if count % 2 == 0 {
            let _ = write!(path, "/{}'", idx);
        } else {
            let _ = write!(path, "/{}", idx);
        }
        count += 1;
    }

    let _ = master.derive_path(&path);
});
