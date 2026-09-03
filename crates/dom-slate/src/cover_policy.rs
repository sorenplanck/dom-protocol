//! Cover-traffic lock-height policy for ordinary sends (T1 / spec §16.2).
//!
//! Master specification `DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0`
//! §16.2 "Precondicionamento normativo do anonymity set de refund", NORMATIVE
//! V1: the `HEIGHT_LOCKED` feature must not appear for the first time when the
//! first refund is published. A stable wallet release creates it by default on
//! every eligible ordinary L1 send, using the same `dom-slate` builder, codec
//! and verifier a common transfer uses. This module is that policy; the wiring
//! point is the send flow, before the slate is frozen
//! (`build_send_with_lock_height`).
//!
//! Normative rules implemented here, with their sources:
//!
//! - **The cover lock must be satisfied at construction time** (§16.2):
//!   `cover_lock_height <= H_mature_max`, where `H_mature_max` is the highest
//!   lock height accepted immediately under the validated snapshot. The
//!   consensus rule is `dom_consensus::validate_lock_heights` (RFC-0010 §7): a
//!   `HEIGHT_LOCKED` kernel is `TemporarilyInvalid` iff `lock_height >
//!   current`, so `H_mature_max` is the current validated height. The policy
//!   never chooses a future height; it therefore never delays inclusion and
//!   never withholds funds.
//! - **The lookback is drawn, not fixed** (Cronograma T1): a fixed distance
//!   creates its own signature — an ordinary cover send would confirm at
//!   `lock_height + N` while a refund confirms at `lock_height + ~0-2`, and
//!   the distance becomes the classifier. The lookback is drawn uniformly
//!   from a public, frozen window so the two distributions overlap.
//! - **CSPRNG is used only for the lookback inside the public window and for
//!   the per-transaction participation draw** (§16.2, §15.8). Selection never
//!   uses wallet ID, seed, key, installation or persistent cohort. The
//!   caller must pass a cover RNG that is not one of the Schnorr/Bulletproof
//!   nonce RNG streams (§15.8); OS-entropy generators satisfy this.
//! - **Fallback to PLAIN happens only before any byte or signature is
//!   exported** (§16.2). This policy runs before `build_send_with_lock_height`
//!   performs any slate crypto, so a caller that maps a policy error to
//!   `lock_height == 0` satisfies the rule; the aggregate fallback count is
//!   part of G-COVER and is the caller's to report.
//! - **Eligibility exclusions are documented, not silently inferred**
//!   (§16.2): coinbase kernels (miner-built, never pass through this send
//!   path), transactions already subject to another lock (an explicit caller
//!   lock wins; the policy must not be applied on top), and paths whose
//!   consensus does not accept the feature.
//!
//! Staging (§15.8): participation is a per-transaction draw — R1 = 10% of
//! eligible sends (`participation_permille = 100`), R2 = 50% (`500`),
//! R3 = 100% (`1000`). The G-COVER calendar starts at the first public
//! default-on release and requires 90 consecutive days and 1,000 confirmed
//! ordinary `HEIGHT_LOCKED` kernels before any production Scriptless funding.

use crate::SlateError;
use rand::{CryptoRng, RngCore};

/// The validated-chain input to the cover policy (§16.2).
///
/// §16.2: "O chain adapter consulta o validador real e obtém `H_mature_max`,
/// a maior altura aceita imediatamente no snapshot validado; tip observado é
/// apenas uma entrada, não substituto da semântica de mempool/consenso." The
/// constructor takes the **validated** height — the same `current` that
/// `dom_consensus::validate_lock_heights` compares against — not an
/// unvalidated peer claim. Passing an unvalidated tip violates the policy's
/// premise and is the caller's responsibility to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedChainSnapshotV1 {
    validated_height: u64,
}

impl ValidatedChainSnapshotV1 {
    /// Build the snapshot from the validated chain height.
    pub const fn from_validated_height(validated_height: u64) -> Self {
        Self { validated_height }
    }

    /// `H_mature_max`: the highest lock height accepted immediately.
    ///
    /// Consensus (`validate_lock_heights`, RFC-0010 §7) rejects a kernel as
    /// `TemporarilyInvalid` iff `lock_height > current`, so every height up to
    /// and including the validated height is immediately valid.
    pub const fn max_immediately_valid_lock_height(&self) -> u64 {
        self.validated_height
    }
}

/// The policy's per-send decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverLockOutcomeV1 {
    /// This send carries a cover `HEIGHT_LOCKED` kernel at the given
    /// satisfied height.
    Cover(u64),
    /// The per-transaction participation draw did not select this send; it
    /// stays PLAIN. This is staged rollout, not a fallback, and is not
    /// counted in the G-COVER fallback rate.
    NotSelected,
}

/// Cover-traffic lock policy: a public frozen lookback window plus the
/// staged-rollout participation rate (§16.2, §15.8).
///
/// Both parameters are release decisions frozen per public version — the
/// policy validates their shape but deliberately fixes no values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoverLockPolicyV1 {
    max_lookback: u32,
    participation_permille: u16,
}

impl CoverLockPolicyV1 {
    /// Construct a policy from the frozen public window and rollout stage.
    ///
    /// `max_lookback` must be nonzero: a zero window collapses every cover
    /// lock to exactly `H_mature_max`, recreating the unique numeric
    /// fingerprint §16.2 and T1 exist to avoid ("Pode amostrar uma pequena
    /// janela de lookback pública e congelada para evitar fingerprint
    /// numérico único"). `participation_permille` must be in `1..=1000`
    /// (R1 = 100, R2 = 500, R3 = 1000); zero would mean the campaign is off,
    /// which is expressed by not applying the policy at all, never by a
    /// policy that silently does nothing.
    pub fn new(max_lookback: u32, participation_permille: u16) -> Result<Self, SlateError> {
        if max_lookback == 0 {
            return Err(SlateError::Crypto(
                "cover lookback window must be nonzero: a fixed distance is a fingerprint".into(),
            ));
        }
        if participation_permille == 0 || participation_permille > 1000 {
            return Err(SlateError::Crypto(
                "cover participation must be 1..=1000 permille".into(),
            ));
        }
        Ok(Self {
            max_lookback,
            participation_permille,
        })
    }

    /// The frozen public lookback window in blocks.
    pub const fn max_lookback(&self) -> u32 {
        self.max_lookback
    }

    /// The staged-rollout participation rate in permille (§15.8 R-stages).
    pub const fn participation_permille(&self) -> u16 {
        self.participation_permille
    }

    /// Draw a satisfied cover lock height (§16.2's `sample_satisfied_height`).
    ///
    /// Deterministic in its bounds, CSPRNG only for the lookback inside the
    /// public window, exactly as the spec's skeleton:
    ///
    /// ```text
    /// mature_max = snapshot.max_immediately_valid_lock_height()
    /// bounded    = min(max_lookback, mature_max - 1)
    /// lookback   = uniform_inclusive(rng, 0, bounded)
    /// height     = max(mature_max - lookback, 1)
    /// ```
    ///
    /// Fails closed when `mature_max == 0`: `HEIGHT_LOCKED` requires a
    /// nonzero lock height, and on a genesis-only snapshot every nonzero
    /// height is in the future — and §16.2 forbids choosing a future height
    /// without an explicit user request. The caller maps this to a PLAIN
    /// fallback (before any byte is exported) and counts it.
    pub fn sample_satisfied_height(
        &self,
        snapshot: &ValidatedChainSnapshotV1,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<u64, SlateError> {
        let mature_max = snapshot.max_immediately_valid_lock_height();
        if mature_max == 0 {
            return Err(SlateError::Crypto(
                "no satisfiable cover lock exists at height zero; never choose a future height"
                    .into(),
            ));
        }
        let bounded = u64::from(self.max_lookback).min(mature_max - 1);
        let lookback = uniform_u64_inclusive(rng, 0, bounded);
        Ok(mature_max.saturating_sub(lookback).max(1))
    }

    /// The full per-send decision: participation draw, then height draw.
    ///
    /// The participation draw is per transaction with CSPRNG (§15.8) — never
    /// wallet ID, seed, key, installation or persistent cohort — so rollout
    /// staging cannot become a wallet-linkable cohort.
    pub fn cover_lock_for_send(
        &self,
        snapshot: &ValidatedChainSnapshotV1,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<CoverLockOutcomeV1, SlateError> {
        let draw = uniform_u64_inclusive(rng, 1, 1000);
        if draw > u64::from(self.participation_permille) {
            return Ok(CoverLockOutcomeV1::NotSelected);
        }
        Ok(CoverLockOutcomeV1::Cover(
            self.sample_satisfied_height(snapshot, rng)?,
        ))
    }
}

/// Uniform draw in `lo..=hi` by rejection sampling — no modulo bias, so the
/// public lookback window's distribution is exactly uniform.
fn uniform_u64_inclusive(rng: &mut (impl RngCore + CryptoRng), lo: u64, hi: u64) -> u64 {
    debug_assert!(lo <= hi);
    let span = hi - lo;
    if span == 0 {
        return lo;
    }
    if span == u64::MAX {
        return rng.next_u64();
    }
    let buckets = span + 1;
    // Largest multiple of `buckets` that fits in u64: values at or above it
    // would wrap the modulo and bias the low residues, so they are rejected.
    let zone = u64::MAX - (u64::MAX % buckets);
    loop {
        let raw = rng.next_u64();
        if raw < zone {
            return lo + (raw % buckets);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x5343_4f56_4552_0001)
    }

    #[test]
    fn constructor_rejects_degenerate_parameters() {
        // A zero window is the unique numeric fingerprint T1 forbids.
        assert!(CoverLockPolicyV1::new(0, 100).is_err());
        // Zero participation is "campaign off", which is not a policy value.
        assert!(CoverLockPolicyV1::new(6, 0).is_err());
        assert!(CoverLockPolicyV1::new(6, 1001).is_err());
        assert!(CoverLockPolicyV1::new(6, 100).is_ok());
        assert!(CoverLockPolicyV1::new(6, 1000).is_ok());
    }

    #[test]
    fn sampled_height_is_always_satisfied_and_never_zero() {
        let mut rng = rng();
        let policy = CoverLockPolicyV1::new(6, 1000).expect("policy");
        for mature_max in [1u64, 2, 3, 7, 100, 1_000_000] {
            let snapshot = ValidatedChainSnapshotV1::from_validated_height(mature_max);
            for _ in 0..500 {
                let height = policy
                    .sample_satisfied_height(&snapshot, &mut rng)
                    .expect("satisfied height");
                // §16.2: cover_lock_height <= H_mature_max, never future,
                // and HEIGHT_LOCKED requires a nonzero height.
                assert!(height <= mature_max, "future height at {mature_max}");
                assert!(height >= 1);
                // The lookback never exceeds the frozen public window.
                assert!(mature_max - height <= 6);
            }
        }
    }

    #[test]
    fn genesis_only_snapshot_fails_closed_instead_of_choosing_a_future_height() {
        let mut rng = rng();
        let policy = CoverLockPolicyV1::new(6, 1000).expect("policy");
        let snapshot = ValidatedChainSnapshotV1::from_validated_height(0);
        assert!(policy.sample_satisfied_height(&snapshot, &mut rng).is_err());
    }

    #[test]
    fn every_height_in_the_public_window_is_reachable() {
        // T1: the distance must be drawn from a range, not fixed — so every
        // value of the window must actually occur.
        let mut rng = rng();
        let policy = CoverLockPolicyV1::new(3, 1000).expect("policy");
        let snapshot = ValidatedChainSnapshotV1::from_validated_height(100);
        let mut seen = [false; 4]; // heights 97, 98, 99, 100
        for _ in 0..2000 {
            let height = policy
                .sample_satisfied_height(&snapshot, &mut rng)
                .expect("height");
            assert!((97..=100).contains(&height));
            seen[(height - 97) as usize] = true;
        }
        assert!(
            seen.iter().all(|s| *s),
            "a drawn range must reach every value, else the window is narrower than frozen"
        );
    }

    #[test]
    fn window_is_clamped_to_the_available_history() {
        // mature_max = 2 with window 6: bounded = min(6, 1) = 1, so heights
        // are 1 or 2 — clamped, satisfied, never zero.
        let mut rng = rng();
        let policy = CoverLockPolicyV1::new(6, 1000).expect("policy");
        let snapshot = ValidatedChainSnapshotV1::from_validated_height(2);
        for _ in 0..200 {
            let height = policy
                .sample_satisfied_height(&snapshot, &mut rng)
                .expect("height");
            assert!((1..=2).contains(&height));
        }
    }

    #[test]
    fn full_participation_always_covers_and_staged_participation_is_a_real_draw() {
        let mut rng = rng();
        let snapshot = ValidatedChainSnapshotV1::from_validated_height(1000);

        // R3 (1000 permille): every eligible send is a cover send.
        let full = CoverLockPolicyV1::new(6, 1000).expect("policy");
        for _ in 0..200 {
            match full.cover_lock_for_send(&snapshot, &mut rng).expect("draw") {
                CoverLockOutcomeV1::Cover(height) => assert!((1..=1000).contains(&height)),
                CoverLockOutcomeV1::NotSelected => panic!("R3 must always select"),
            }
        }

        // R1 (100 permille): per-transaction draw lands near 10% — the seeded
        // RNG makes this deterministic, and the wide band guards the property
        // (a draw happens) rather than a brittle exact rate.
        let staged = CoverLockPolicyV1::new(6, 100).expect("policy");
        let mut covered = 0u32;
        for _ in 0..5000 {
            if let CoverLockOutcomeV1::Cover(_) = staged
                .cover_lock_for_send(&snapshot, &mut rng)
                .expect("draw")
            {
                covered += 1;
            }
        }
        assert!(
            (300..=700).contains(&covered),
            "R1 coverage {covered}/5000 is outside any plausible 10% band"
        );
    }

    #[test]
    fn uniform_inclusive_reaches_both_endpoints_and_stays_in_range() {
        let mut rng = rng();
        let (mut lo_seen, mut hi_seen) = (false, false);
        for _ in 0..2000 {
            let value = uniform_u64_inclusive(&mut rng, 5, 8);
            assert!((5..=8).contains(&value));
            lo_seen |= value == 5;
            hi_seen |= value == 8;
        }
        assert!(lo_seen && hi_seen);
        assert_eq!(uniform_u64_inclusive(&mut rng, 7, 7), 7);
    }
}
