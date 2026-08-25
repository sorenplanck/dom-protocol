//! Reversible chain projection and reorg monitoring rules (spec §11).
//!
//! §10.1 separates storage into three categories: irreversible cryptographic
//! state (nonces used, shares sent, adaptor secret exposed), monotonic
//! protocol state, and the reversible chain projection (height, block,
//! confirmations, canonicality). "Um reorg só altera a terceira categoria."
//! This module encodes that boundary in types:
//!
//! - [`IrreversibleStateV1`] (§10.1) only ever advances: its flags set once
//!   and expose no clearing API, and its nonce epoch only increases. The
//!   `Exposed` mark of §7.5 — set after the monitor extracts the adaptor
//!   secret from a confirmed canonical signature and checks `t*G == T` — is
//!   irreversible by construction, which is invariant I-F5: "reorg não apaga
//!   segredo adaptor já observado."
//! - [`ChainProjectionV1`] (§11.1) is the only thing a reorg may rewrite, and
//!   [`ChainProjectionV1::apply_reorg`] takes the irreversible state by
//!   shared reference — the signature itself is the proof that applying a
//!   reorg cannot mutate category one.
//!
//! The §11.2 rules are returned as prescribed monitor actions, never
//! performed here (broadcasting is node-side):
//!
//! - funding removed → back to awaiting/rebroadcast, refund/adaptor/nonces
//!   stay consumed;
//! - claim removed → rebroadcast if still valid, `adaptor_secret_exposed`
//!   stays true;
//! - refund removed → rebroadcast after its unlock height, nonces stay
//!   consumed;
//! - concurrent claim/refund → follow the canonical spend of the output;
//!   there is deliberately no action variant that signs a new alternative
//!   ("nunca assinar alternativa nova automaticamente");
//! - reorg deeper than the local window → fail closed with a full rescan by
//!   commitment/txid, leaving the projection untouched.
//!
//! §11.3: with no session id on chain, monitoring indexes locally by the
//! shared-output commitment, the funding/claim/refund txids and kernel
//! excesses, and the refund height ([`LocalContractIndexV1`]); encrypting
//! those indexes at rest is the store's job. No on-chain metadata is ever
//! added to "help" monitoring. `first_seen_unix` is wallet/UI information
//! only — nothing in this module derives consensus or cryptographic decisions
//! from it.

use crate::{AdaptorError, Result};

/// §11.1 `TxObservation`: where one contract transaction currently stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxObservation {
    /// Never seen.
    Unknown,
    /// Broadcast by us; `first_seen_unix` is wallet/UI display data only and
    /// never enters consensus or cryptographic decisions.
    Broadcast {
        /// Wall-clock first-seen time, UI-only (§11.1).
        first_seen_unix: u64,
    },
    /// Seen in the mempool.
    Mempool,
    /// Confirmed in a block on the current canonical chain.
    Confirmed {
        /// The confirming block.
        block_id: [u8; 32],
        /// The confirming height.
        height: u64,
    },
    /// Previously confirmed; its block left the canonical chain.
    Orphaned {
        /// The block that formerly confirmed it.
        former_block_id: [u8; 32],
        /// The height that formerly confirmed it.
        former_height: u64,
    },
    /// The monitored output was spent by a different transaction.
    Conflicted {
        /// The canonical spending transaction.
        spending_tx_id: [u8; 32],
    },
}

/// §10.1 irreversible cryptographic state: it only ever advances.
///
/// No method clears a flag and the nonce epoch only increases — the type has
/// no reverse direction, so no reorg, crash, restore, or rollback can undo
/// it (A-06, I-F5, I-F6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IrreversibleStateV1 {
    any_signing_share_sent: bool,
    funding_authorized: bool,
    adaptor_secret_exposed: bool,
    nonce_epoch: u64,
}

impl IrreversibleStateV1 {
    /// Fresh state with nothing irreversible yet.
    pub const fn new() -> Self {
        Self {
            any_signing_share_sent: false,
            funding_authorized: false,
            adaptor_secret_exposed: false,
            nonce_epoch: 0,
        }
    }

    /// Record that some signing share left the process. Never unset.
    pub fn mark_signing_share_sent(&mut self) {
        self.any_signing_share_sent = true;
    }

    /// Record that funding was authorized. Never unset.
    pub fn mark_funding_authorized(&mut self) {
        self.funding_authorized = true;
    }

    /// §7.5: the monitor extracted the adaptor secret from a confirmed
    /// canonical signature and verified `t*G == T`; mark `Exposed`
    /// irreversibly. Never unset — I-F5.
    pub fn mark_adaptor_secret_exposed(&mut self) {
        self.adaptor_secret_exposed = true;
    }

    /// Advance the nonce epoch. Strictly forward; overflow fails closed.
    pub fn advance_nonce_epoch(&mut self) -> Result<u64> {
        self.nonce_epoch = self
            .nonce_epoch
            .checked_add(1)
            .ok_or(AdaptorError::InvalidContext("nonce epoch overflows"))?;
        Ok(self.nonce_epoch)
    }

    /// Whether any signing share was ever sent.
    pub const fn any_signing_share_sent(&self) -> bool {
        self.any_signing_share_sent
    }

    /// Whether funding was ever authorized.
    pub const fn funding_authorized(&self) -> bool {
        self.funding_authorized
    }

    /// Whether the adaptor secret was ever observed (§7.5 `Exposed`).
    pub const fn adaptor_secret_exposed(&self) -> bool {
        self.adaptor_secret_exposed
    }

    /// The current nonce epoch.
    pub const fn nonce_epoch(&self) -> u64 {
        self.nonce_epoch
    }
}

/// §11.1 `ChainProjectionV1`: the reversible category, and only it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainProjectionV1 {
    /// Current canonical tip block.
    pub tip_id: [u8; 32],
    /// Current canonical tip height.
    pub tip_height: u64,
    /// Funding observation.
    pub funding: TxObservation,
    /// Claim observation.
    pub claim: TxObservation,
    /// Refund observation.
    pub refund: TxObservation,
}

/// The local reorg tolerance window, in blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReorgWindowV1 {
    depth_blocks: u64,
}

impl ReorgWindowV1 {
    /// A nonzero local reorg window.
    pub fn new(depth_blocks: u64) -> Result<Self> {
        if depth_blocks == 0 {
            return Err(AdaptorError::InvalidContext("reorg window must be nonzero"));
        }
        Ok(Self { depth_blocks })
    }
}

/// One observed reorg: blocks at and above `first_orphaned_height` left the
/// canonical chain and the tip moved to (`new_tip_id`, `new_tip_height`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReorgEventV1 {
    /// The new canonical tip block.
    pub new_tip_id: [u8; 32],
    /// The new canonical tip height.
    pub new_tip_height: u64,
    /// The lowest height whose former block was disconnected.
    pub first_orphaned_height: u64,
}

/// What §11.2 prescribes for the monitor after a projection change. Actions
/// are returned, never performed — broadcasting is node-side. There is
/// deliberately no variant that signs a new alternative transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonitorActionV1 {
    /// Funding left the chain: return to awaiting/rebroadcast. Refund,
    /// adaptor, and nonces stay consumed (§11.2).
    AwaitFundingRebroadcast,
    /// Claim left the chain: rebroadcast the identical bytes if still valid.
    /// `adaptor_secret_exposed` remains true (§11.2, I-F5).
    RebroadcastClaimIfStillValid,
    /// Refund left the chain: rebroadcast the identical bytes once the unlock
    /// height allows. Nonces stay consumed (§11.2).
    RebroadcastRefundAfterUnlockHeight,
    /// The output was spent by a competing canonical transaction: follow the
    /// canonical spend; never sign a new alternative automatically (§11.2).
    FollowCanonicalSpend {
        /// The canonical spending transaction.
        spending_tx_id: [u8; 32],
    },
    /// The reorg exceeded the local window: fail closed and run a full rescan
    /// by commitment/txid (§11.2). The projection was left untouched.
    FailClosedFullRescan,
}

impl ChainProjectionV1 {
    /// A fresh projection at the given tip with nothing observed.
    pub const fn at_tip(tip_id: [u8; 32], tip_height: u64) -> Self {
        Self {
            tip_id,
            tip_height,
            funding: TxObservation::Unknown,
            claim: TxObservation::Unknown,
            refund: TxObservation::Unknown,
        }
    }

    /// Apply one reorg under the §11.2 rules, returning the prescribed
    /// monitor actions.
    ///
    /// Takes the irreversible state by shared reference: the signature itself
    /// guarantees a reorg cannot mutate category one (§10.1) — the parameter
    /// exists so the rule is visible at the call site, and so tests can pin
    /// that the state is byte-identical afterwards.
    ///
    /// A reorg deeper than the local window changes nothing and prescribes
    /// the fail-closed full rescan. Otherwise every `Confirmed` observation
    /// at or above the fork becomes `Orphaned`, the tip advances, and one
    /// action per demoted transaction is returned.
    pub fn apply_reorg(
        &mut self,
        reorg: &ReorgEventV1,
        window: ReorgWindowV1,
        _irreversible: &IrreversibleStateV1,
    ) -> Result<Vec<MonitorActionV1>> {
        if reorg.first_orphaned_height == 0 || reorg.first_orphaned_height > self.tip_height {
            return Err(AdaptorError::InvalidContext(
                "reorg fork height is outside the projected chain",
            ));
        }
        if reorg.new_tip_height < reorg.first_orphaned_height.saturating_sub(1) {
            return Err(AdaptorError::InvalidContext(
                "reorg new tip is below the surviving prefix",
            ));
        }
        // §11.2: deeper than the local window → fail closed, full rescan by
        // commitment/txid, and no partial mutation of the projection.
        let depth = self
            .tip_height
            .checked_sub(reorg.first_orphaned_height)
            .and_then(|d| d.checked_add(1))
            .ok_or(AdaptorError::InvalidContext("reorg depth overflows"))?;
        if depth > window.depth_blocks {
            return Ok(vec![MonitorActionV1::FailClosedFullRescan]);
        }

        let mut actions = Vec::new();
        let fork = reorg.first_orphaned_height;
        let demote = |observation: &mut TxObservation| -> bool {
            if let TxObservation::Confirmed { block_id, height } = *observation {
                if height >= fork {
                    *observation = TxObservation::Orphaned {
                        former_block_id: block_id,
                        former_height: height,
                    };
                    return true;
                }
            }
            false
        };
        if demote(&mut self.funding) {
            actions.push(MonitorActionV1::AwaitFundingRebroadcast);
        }
        if demote(&mut self.claim) {
            actions.push(MonitorActionV1::RebroadcastClaimIfStillValid);
        }
        if demote(&mut self.refund) {
            actions.push(MonitorActionV1::RebroadcastRefundAfterUnlockHeight);
        }
        self.tip_id = reorg.new_tip_id;
        self.tip_height = reorg.new_tip_height;
        Ok(actions)
    }

    /// Record that the shared output was spent by a competing canonical
    /// transaction (§11.2): the observation flips to `Conflicted` and the
    /// only prescription is to follow the canonical spend — never to sign a
    /// new alternative.
    pub fn observe_conflict(
        &mut self,
        ours: ContractTxRoleV1,
        spending_tx_id: [u8; 32],
    ) -> MonitorActionV1 {
        let slot = match ours {
            ContractTxRoleV1::Funding => &mut self.funding,
            ContractTxRoleV1::Claim => &mut self.claim,
            ContractTxRoleV1::Refund => &mut self.refund,
        };
        *slot = TxObservation::Conflicted { spending_tx_id };
        MonitorActionV1::FollowCanonicalSpend { spending_tx_id }
    }
}

/// The three monitored contract transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractTxRoleV1 {
    /// The funding transaction.
    Funding,
    /// The adaptor claim transaction.
    Claim,
    /// The timeout refund transaction.
    Refund,
}

/// §11.3 local monitor index: everything needed to recognize the contract on
/// chain, with no on-chain marker.
///
/// Encrypting this at rest is the store's job; nothing here is secret-bearing
/// beyond linkability, and nothing here is ever serialized into a
/// transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalContractIndexV1 {
    /// The shared-output commitment.
    pub shared_output_commitment: [u8; 33],
    /// Funding txid and kernel excess.
    pub funding: TxIndexEntryV1,
    /// Claim txid and kernel excess.
    pub claim: TxIndexEntryV1,
    /// Refund txid and kernel excess.
    pub refund: TxIndexEntryV1,
    /// The refund unlock height.
    pub refund_unlock_height: u64,
}

/// One transaction's local index entry (§11.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxIndexEntryV1 {
    /// The transaction id.
    pub tx_id: [u8; 32],
    /// The kernel excess.
    pub kernel_excess: [u8; 33],
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confirmed(byte: u8, height: u64) -> TxObservation {
        TxObservation::Confirmed {
            block_id: [byte; 32],
            height,
        }
    }

    fn projection() -> ChainProjectionV1 {
        ChainProjectionV1 {
            tip_id: [0xAA; 32],
            tip_height: 120,
            funding: confirmed(0x01, 100),
            claim: confirmed(0x02, 110),
            refund: TxObservation::Unknown,
        }
    }

    fn exposed_state() -> IrreversibleStateV1 {
        let mut state = IrreversibleStateV1::new();
        state.mark_signing_share_sent();
        state.mark_funding_authorized();
        state.mark_adaptor_secret_exposed();
        state
    }

    #[test]
    fn irreversible_state_only_advances() {
        let mut state = IrreversibleStateV1::new();
        assert!(!state.adaptor_secret_exposed());
        state.mark_adaptor_secret_exposed();
        assert!(state.adaptor_secret_exposed());
        // There is no clearing API — the compiler enforces it; the epoch is
        // strictly forward.
        assert_eq!(state.advance_nonce_epoch().expect("epoch"), 1);
        assert_eq!(state.advance_nonce_epoch().expect("epoch"), 2);
        assert_eq!(state.nonce_epoch(), 2);
    }

    #[test]
    fn a_reorg_rewrites_only_the_projection_and_never_the_irreversible_state() {
        // §10.1: "Um reorg só altera a terceira categoria." Funding and claim
        // both fall; the irreversible state is byte-identical afterwards —
        // exposed stays true (I-F5), nonces stay consumed.
        let mut projection = projection();
        let irreversible = exposed_state();
        let before = irreversible;
        let actions = projection
            .apply_reorg(
                &ReorgEventV1 {
                    new_tip_id: [0xBB; 32],
                    new_tip_height: 121,
                    first_orphaned_height: 100,
                },
                ReorgWindowV1::new(30).expect("window"),
                &irreversible,
            )
            .expect("reorg");
        assert_eq!(
            actions,
            vec![
                MonitorActionV1::AwaitFundingRebroadcast,
                MonitorActionV1::RebroadcastClaimIfStillValid,
            ]
        );
        assert_eq!(
            projection.funding,
            TxObservation::Orphaned {
                former_block_id: [0x01; 32],
                former_height: 100,
            }
        );
        assert_eq!(projection.tip_height, 121);
        assert_eq!(irreversible, before);
        assert!(irreversible.adaptor_secret_exposed(), "I-F5");
    }

    #[test]
    fn a_partial_reorg_leaves_deeper_confirmations_alone() {
        // Fork at 110: the claim falls, the funding at 100 stays confirmed.
        let mut projection = projection();
        let actions = projection
            .apply_reorg(
                &ReorgEventV1 {
                    new_tip_id: [0xBB; 32],
                    new_tip_height: 119,
                    first_orphaned_height: 110,
                },
                ReorgWindowV1::new(30).expect("window"),
                &IrreversibleStateV1::new(),
            )
            .expect("reorg");
        assert_eq!(actions, vec![MonitorActionV1::RebroadcastClaimIfStillValid]);
        assert_eq!(projection.funding, confirmed(0x01, 100));
    }

    #[test]
    fn a_refund_falling_out_prescribes_rebroadcast_after_its_height() {
        let mut projection = ChainProjectionV1 {
            refund: confirmed(0x03, 115),
            ..projection()
        };
        let actions = projection
            .apply_reorg(
                &ReorgEventV1 {
                    new_tip_id: [0xBB; 32],
                    new_tip_height: 120,
                    first_orphaned_height: 115,
                },
                ReorgWindowV1::new(30).expect("window"),
                &IrreversibleStateV1::new(),
            )
            .expect("reorg");
        assert!(actions.contains(&MonitorActionV1::RebroadcastRefundAfterUnlockHeight));
    }

    #[test]
    fn deeper_than_the_window_fails_closed_with_a_full_rescan_and_no_mutation() {
        let mut projection = projection();
        let before = projection;
        let actions = projection
            .apply_reorg(
                &ReorgEventV1 {
                    new_tip_id: [0xBB; 32],
                    new_tip_height: 121,
                    first_orphaned_height: 100,
                },
                // Depth is 120-100+1 = 21; a window of 20 refuses it.
                ReorgWindowV1::new(20).expect("window"),
                &IrreversibleStateV1::new(),
            )
            .expect("reorg");
        assert_eq!(actions, vec![MonitorActionV1::FailClosedFullRescan]);
        assert_eq!(projection, before, "fail closed must not partially mutate");
    }

    #[test]
    fn a_conflicting_canonical_spend_is_followed_never_replaced() {
        let mut projection = projection();
        let action = projection.observe_conflict(ContractTxRoleV1::Claim, [0xCC; 32]);
        assert_eq!(
            action,
            MonitorActionV1::FollowCanonicalSpend {
                spending_tx_id: [0xCC; 32]
            }
        );
        assert_eq!(
            projection.claim,
            TxObservation::Conflicted {
                spending_tx_id: [0xCC; 32]
            }
        );
    }

    #[test]
    fn degenerate_reorg_events_fail_closed() {
        let mut projection = projection();
        let window = ReorgWindowV1::new(30).expect("window");
        let state = IrreversibleStateV1::new();
        // Fork at height zero and fork beyond the tip are both nonsense.
        for first_orphaned_height in [0u64, 121] {
            assert!(projection
                .apply_reorg(
                    &ReorgEventV1 {
                        new_tip_id: [0xBB; 32],
                        new_tip_height: 121,
                        first_orphaned_height,
                    },
                    window,
                    &state,
                )
                .is_err());
        }
        assert!(ReorgWindowV1::new(0).is_err());
    }
}
