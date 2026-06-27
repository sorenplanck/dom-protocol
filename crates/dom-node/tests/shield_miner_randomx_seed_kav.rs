//! dom-shield — miner/validator RandomX seed agreement KAV (miner sub-area).
//!
//! RFC-0011 fixes the seed schedule:
//!   epoch       = floor(height / RANDOMX_SEED_INTERVAL)
//!   seed_height = epoch == 0 ? 0 : epoch*RANDOMX_SEED_INTERVAL - RANDOMX_SEED_OFFSET
//! and "seed = block hash at seed_height". A miner that hashes against a
//! different seed than validators recompute mines blocks that the network
//! rejects (self-inflicted orphan) — or, worse on a divergent fork, a block
//! validators accept under a seed the miner did NOT intend.
//!
//! Both miner (`miner.rs`: `let seed_h = randomx_seed_height(new_height)`) and
//! validator (`dom-chain::chain_state::compute_randomx_seed`:
//! `let seed_height = randomx_seed_height(height)`) route through the SAME pub
//! `dom_pow::randomx_seed_height`. This KAV pins that function against a
//! hand-computed table of the RFC-0011 schedule across every epoch boundary, so
//! a unilateral change to either side's seed height is caught.
//!
//! KNOWN DIVERGENCE (static-review, recorded — see fallback test below):
//! the miner resolves the seed hash with
//!   `store.get_hash_at_height(seed_h).ok().flatten().unwrap_or([0u8; 32])`
//! i.e. it SILENTLY falls back to a zero seed when the seed block is missing at
//! ANY height. The validator (`compute_randomx_seed`) returns `[0u8;32]` ONLY
//! when `seed_height == 0`, and returns an ERROR for a missing non-zero seed
//! block — explicitly to avoid "silently hashing against a zero seed, which
//! would reject an otherwise valid block". So under a corrupt/pruned store the
//! miner would mine with seed=0 at an epoch>0 height while the validator path
//! refuses to even compute a seed there. Reachable only with a damaged store;
//! recorded as a divergence, not exercised here because both seed-resolution
//! methods are private to their crates.

use dom_pow::{randomx_seed_height, RANDOMX_SEED_INTERVAL, RANDOMX_SEED_OFFSET};

/// Schedule KAV: the seed height both miner and validator derive is exactly the
/// RFC-0011 formula at and around every epoch boundary.
#[test]
fn seed_height_matches_rfc0011_schedule() {
    // Epoch 0: all heights in [0, INTERVAL) seed against height 0.
    for h in [0u64, 1, 100, RANDOMX_SEED_INTERVAL - 1] {
        assert_eq!(
            randomx_seed_height(h),
            0,
            "epoch 0 must seed against height 0"
        );
    }
    // Epoch boundary 1: height INTERVAL -> anchor INTERVAL, minus OFFSET.
    assert_eq!(
        randomx_seed_height(RANDOMX_SEED_INTERVAL),
        RANDOMX_SEED_INTERVAL - RANDOMX_SEED_OFFSET
    );
    // Concrete values for the locked constants (2048 / 64).
    assert_eq!(RANDOMX_SEED_INTERVAL, 2048);
    assert_eq!(RANDOMX_SEED_OFFSET, 64);
    assert_eq!(randomx_seed_height(2048), 1984);
    assert_eq!(randomx_seed_height(2049), 1984);
    assert_eq!(randomx_seed_height(4095), 1984);
    assert_eq!(randomx_seed_height(4096), 2048 * 2 - 64); // 4032

    // Exhaustive cross-check of the formula over many epochs — this is the
    // single source of truth both the miner and the validator consume.
    for epoch in 0u64..50 {
        for delta in [
            0u64,
            1,
            RANDOMX_SEED_INTERVAL / 2,
            RANDOMX_SEED_INTERVAL - 1,
        ] {
            let h = epoch * RANDOMX_SEED_INTERVAL + delta;
            let expected = if epoch == 0 {
                0
            } else {
                epoch * RANDOMX_SEED_INTERVAL - RANDOMX_SEED_OFFSET
            };
            assert_eq!(
                randomx_seed_height(h),
                expected,
                "seed-height divergence at height {h} (epoch {epoch})"
            );
        }
    }
}

/// Documents the miner vs validator zero-seed-fallback divergence as an
/// executable note. The values here mirror the production decision points:
///   * miner  (miner.rs): missing seed at ANY height -> seed = [0u8;32]
///   * chain  (chain_state): missing seed -> [0u8;32] ONLY if seed_height==0,
///     else Err.
///
/// The only height where the two agree on a zero seed is seed_height == 0,
/// i.e. epoch 0. For epoch>0 the miner's fallback and the validator's error
/// path disagree.
#[test]
fn zero_seed_fallback_only_safe_in_epoch_zero() {
    // Epoch 0 height: seed_height == 0 -> both sides legitimately use [0;32].
    assert_eq!(randomx_seed_height(10), 0, "epoch-0 height seeds against 0");

    // Epoch>0 height: seed_height != 0. Here the miner's unwrap_or([0;32])
    // fallback (on a missing seed block) is NOT what the validator would do
    // (validator returns Err). Assert the precondition that makes the
    // divergence reachable: seed_height is non-zero, so a zero seed is NOT the
    // convention — it would be a silent fabrication.
    let sh = randomx_seed_height(2048);
    assert_ne!(
        sh, 0,
        "epoch>0 seed_height is non-zero; a [0;32] fallback here is a miner/validator divergence"
    );
}
