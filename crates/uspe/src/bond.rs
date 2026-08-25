//! `BondAdapter` — the custody seam of the F4 specification §7 (D-017).
//!
//! The trait is chain-neutral on purpose: the machine and its objects
//! never see chain bytes (I9), and this crate never gains a chain
//! dependency. The v1 implementation lives in the dev-only `f4-harness`
//! crate, over the audited `ConditionLockV2` paths — lock is `open`,
//! release is the PERMISSIONLESS `refund` after the deadline, slash is
//! the beneficiary's `claim(lockId, t)` with the revealed scalar. There
//! is no third role and no privileged path anywhere (I12).

use counterparty_api::{ChainCursor, RevealedSecretBytes};
use kaystra_core::types::Digest32;

use crate::objects::AssurancePolicyV1;

/// What happened to an artifact handed to the broadcast seam.
///
/// Same discipline as the settlement legs: byte-identical resend is
/// acknowledged, never re-executed (I7).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BroadcastOutcome {
    /// The bytes were accepted for inclusion.
    Accepted,
    /// The chain already had them (byte-identical dedupe, I7).
    Duplicate,
    /// Not now, but the same bytes may be offered again later.
    RetryLater,
}

/// A FINALIZED bond-chain fact, already filtered to the one bond lock the
/// adapter is configured for. The scalar inside [`BondEvent::BondClaimed`]
/// is public by construction — it was published on chain by the claim
/// itself — but it is still never logged by this workspace (I6).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BondEvent {
    /// The collateral lock exists on chain. Feeds `BondLockObserved`;
    /// certificate issuance additionally requires the step-4 verifier.
    CollateralLocked {
        /// The bond's `ConditionLockV2` lock id.
        bond_lock_id: Digest32,
        /// Finalized height of the observation.
        height: u64,
    },
    /// The slash spend executed, revealing the scalar. Feeds the
    /// `CompensationConfirmed` path once verified.
    BondClaimed {
        /// The bond's lock id.
        bond_lock_id: Digest32,
        /// The scalar the claim published.
        revealed: RevealedSecretBytes,
        /// Finalized height of the observation.
        height: u64,
    },
    /// The release spend executed (refund to the funder). Feeds
    /// `ReleaseConfirmed`.
    BondRefunded {
        /// The bond's lock id.
        bond_lock_id: Digest32,
        /// Finalized height of the observation.
        height: u64,
    },
    /// Reorg: observations from this height on are invalidated (I11).
    Reorged {
        /// First invalidated height.
        from_height: u64,
    },
}

/// One `observe` round: the finalized events plus the cursor to resume
/// from. The cursor is opaque and belongs to the chain adapter.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BondObservation {
    /// Finalized bond events, oldest first.
    pub events: Vec<BondEvent>,
    /// Cursor for the next round.
    pub cursor: ChainCursor,
}

/// Custody of ONE bond under ONE policy (F4 spec §7.1).
///
/// Implementations are configured for a single policy at construction and
/// must refuse anything else: `submit_bond` cross-checks the policy
/// byte-for-byte, and the spend submissions accept only the configured
/// lock id. Amounts above the compensation cap must be refused before any
/// transaction is built (§7.3).
pub trait BondAdapter {
    /// Implementation-specific error. Every refusal is a named error —
    /// nothing is stubbed to succeed (I13).
    type Error;

    /// Submit the collateral lock. Idempotent: repeated calls offer
    /// byte-identical bytes (I7).
    fn submit_bond(&mut self, policy: &AssurancePolicyV1) -> Result<BroadcastOutcome, Self::Error>;

    /// Execute the release spend — the permissionless refund after the
    /// bond release deadline. Must refuse while the deadline has not
    /// passed on the bond chain's own clock.
    fn submit_release(&mut self, bond_lock_id: &Digest32) -> Result<BroadcastOutcome, Self::Error>;

    /// Execute the slash spend with the REVEALED scalar. Must refuse a
    /// non-canonical scalar, a scalar that does not open the lock's
    /// adaptor commitment, and a deadline already passed (the contract
    /// would revert; failing closed here keeps the refusal named).
    fn submit_slash(
        &mut self,
        bond_lock_id: &Digest32,
        revealed: &RevealedSecretBytes,
    ) -> Result<BroadcastOutcome, Self::Error>;

    /// Observe finalized bond-chain events from `cursor`. Only the
    /// configured bond lock's events are surfaced.
    fn observe(&mut self, cursor: &ChainCursor) -> Result<BondObservation, Self::Error>;
}
