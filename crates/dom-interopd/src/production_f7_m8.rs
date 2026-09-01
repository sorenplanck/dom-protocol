//! Productive F7/M.8 authority bridge over the retained Stage-12 graph.
//!
//! This module has one minting path: the read-only F7 handle sharing the DOM
//! child's exact runtime drives the real V2 validator, then its linear
//! aggregate is split exactly once. The Contracts share is durably issued or
//! recovered through the selected Stage-12 owner. Of the two public M.8
//! authorizations, only the one selected by the already-provisioned local
//! Stage-8 participant authority remains consumable. The peer half is reduced
//! to a process-local comparison snapshot; this bridge can never own two Bitcoin keys
//! or two nonce vaults. There is deliberately no path/key constructor or
//! evidence-only substitute here.

use adapter_btc::timelock::{AnchoredCrossChainWindowV1, CrossChainWindowV1};
use btc_actuator::BitcoinParticipantRoleV1;
use dom_final_claim_binding::ComposedSettlementLegV1;
use f7_anchor_authority::{F7AnchorAuthorityError, F7AnchorValidationRequestV2};
use route_executor::LegIdV1;

use crate::production_chain_signers::ProductionBitcoinParticipantAuthorityV1;
use crate::production_child_dom::ProductionDomF7ScannerAuthorityV1;
use crate::production_contracts::{
    ProductionContractsPostAnchorErrorV2, ProductionContractsPostAnchorV2,
};
use crate::production_relay_stage12::ProductionRelayStage12OwnerV1;

/// Redacted refusal from the productive F7/M.8 composition boundary.
#[derive(Debug, thiserror::Error)]
#[expect(
    clippy::enum_variant_names,
    reason = "fail-closed refusal naming is the daemon-wide convention"
)]
pub(crate) enum ProductionF7M8ErrorV2 {
    /// Real canonical DOM or Bitcoin anchor validation failed closed.
    #[error("productive F7 anchor validation refused")]
    AnchorRefused(#[source] F7AnchorAuthorityError),
    /// The selected retained Contracts Store rejected its linear share.
    #[error("productive Contracts post-anchor transition refused")]
    ContractsRefused(#[source] ProductionContractsPostAnchorErrorV2),
    /// The Stage-8 Bitcoin participant authority does not own this exact leg or
    /// does not match the role-bound F7 authorization.
    #[error("productive Bitcoin participant authority refused")]
    BitcoinParticipantRefused,
}

impl From<F7AnchorAuthorityError> for ProductionF7M8ErrorV2 {
    fn from(error: F7AnchorAuthorityError) -> Self {
        Self::AnchorRefused(error)
    }
}

impl From<ProductionContractsPostAnchorErrorV2> for ProductionF7M8ErrorV2 {
    fn from(error: ProductionContractsPostAnchorErrorV2) -> Self {
        Self::ContractsRefused(error)
    }
}

/// Move-only local M.8 capability selected by the exact Stage-8 participant.
///
/// The raw authorization has no getter. It can leave this wrapper only when the
/// same participant authority (leg, role, participant and authority digest) is
/// presented again, preventing a route-local handoff from being transplanted
/// to the peer signer.
#[must_use = "the local Bitcoin M.8 authority must reach its participant signer"]
pub(crate) struct ProductionLocalBitcoinM8AuthorizationV2 {
    authorization: AnchoredCrossChainWindowV1,
    leg: LegIdV1,
    participant_id: [u8; 32],
    role: BitcoinParticipantRoleV1,
    authority_digest: [u8; 32],
}

impl ProductionLocalBitcoinM8AuthorizationV2 {
    /// Releases the one local M.8 capability only to the same Stage-8 owner
    /// that selected it. The peer authorization is never reconstructible here.
    #[expect(
        dead_code,
        reason = "frozen F7-to-M8 settlement round surface; fails the build when first wired"
    )]
    pub(crate) fn consume_for(
        self,
        participant: &ProductionBitcoinParticipantAuthorityV1<'_>,
    ) -> Result<AnchoredCrossChainWindowV1, ProductionF7M8ErrorV2> {
        let authority = participant.authority();
        if participant.leg() != self.leg
            || authority.participant_id() != self.participant_id
            || authority.role() != self.role
            || authority.authority_digest() != self.authority_digest
        {
            return Err(ProductionF7M8ErrorV2::BitcoinParticipantRefused);
        }
        Ok(self.authorization)
    }
}

/// Secret-free peer M.8 result for process-local equality checks only.
///
/// This snapshot contains no nonce permit, participant key authority, vault
/// handle or consumable `AnchoredCrossChainWindowV1`. It deliberately omits the
/// complete remote participant/session/transport scope and therefore must never
/// be serialized or used as a network payload. The peer daemon must run its own
/// F7 validation and select its own local capability; a future BTC DSC1 edge
/// needs a separate fully bound canonical type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionPeerBitcoinM8ComparisonV2 {
    settlement_terms_hash: [u8; 32],
    window: CrossChainWindowV1,
    anchor_evidence_digest: [u8; 32],
    peer_role: BitcoinParticipantRoleV1,
}

impl ProductionPeerBitcoinM8ComparisonV2 {
    #[expect(
        dead_code,
        reason = "frozen F7-to-M8 settlement round surface; fails the build when first wired"
    )]
    pub(crate) const fn settlement_terms_hash(&self) -> [u8; 32] {
        self.settlement_terms_hash
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "frozen F7-to-M8 settlement round surface; fails the build when first wired"
        )
    )]
    pub(crate) const fn window(&self) -> &CrossChainWindowV1 {
        &self.window
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "frozen F7-to-M8 settlement round surface; fails the build when first wired"
        )
    )]
    pub(crate) const fn anchor_evidence_digest(&self) -> [u8; 32] {
        self.anchor_evidence_digest
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "frozen F7-to-M8 settlement round surface; fails the build when first wired"
        )
    )]
    pub(crate) const fn peer_role(&self) -> BitcoinParticipantRoleV1 {
        self.peer_role
    }
}

/// Participant-separated Bitcoin output of the unique F7 aggregate.
#[must_use = "the local capability and peer public result must be routed"]
pub(crate) struct ProductionBitcoinM8ParticipantHandoffV2 {
    local: ProductionLocalBitcoinM8AuthorizationV2,
    peer_comparison: ProductionPeerBitcoinM8ComparisonV2,
}

impl ProductionBitcoinM8ParticipantHandoffV2 {
    #[expect(
        dead_code,
        reason = "frozen F7-to-M8 settlement round surface; fails the build when first wired"
    )]
    pub(crate) fn into_parts(
        self,
    ) -> (
        ProductionLocalBitcoinM8AuthorizationV2,
        ProductionPeerBitcoinM8ComparisonV2,
    ) {
        (self.local, self.peer_comparison)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalBitcoinAuthorizationSideV2 {
    Maker,
    Taker,
}

const fn participant_authorization_selection(
    role: BitcoinParticipantRoleV1,
) -> (LocalBitcoinAuthorizationSideV2, BitcoinParticipantRoleV1) {
    match role {
        BitcoinParticipantRoleV1::Maker => (
            LocalBitcoinAuthorizationSideV2::Maker,
            BitcoinParticipantRoleV1::Taker,
        ),
        BitcoinParticipantRoleV1::Taker => (
            LocalBitcoinAuthorizationSideV2::Taker,
            BitcoinParticipantRoleV1::Maker,
        ),
    }
}

/// Result of the single real-verifier split after Contracts issuance.
///
/// The Contracts capability and participant-separated Bitcoin handoff remain
/// move-only. No peer network authorization is emitted by this type.
#[must_use = "the unique F7 aggregate must reach both settlement owners"]
pub(crate) struct ProductionF7M8ContractsIssuedV2 {
    contracts: ProductionContractsPostAnchorV2,
    bitcoin: ProductionBitcoinM8ParticipantHandoffV2,
}

impl ProductionF7M8ContractsIssuedV2 {
    /// Splits the already verified/issued aggregate into its two typed owners.
    #[expect(
        dead_code,
        reason = "frozen F7-to-M8 settlement round surface; fails the build when first wired"
    )]
    pub(crate) fn into_parts(
        self,
    ) -> (
        ProductionContractsPostAnchorV2,
        ProductionBitcoinM8ParticipantHandoffV2,
    ) {
        (self.contracts, self.bitcoin)
    }
}

/// Drives real F7 V2 validation and consumes its Contracts share through the
/// selected owner of the same retained Stage-12 graph.
///
/// `request` is only a lookup/proof request to the authoritative verifier. It
/// cannot mint either output, and no field is copied from it after validation.
#[expect(
    dead_code,
    reason = "frozen F7-to-M8 settlement round surface; fails the build when first wired"
)]
pub(crate) fn verify_and_issue_production_f7_m8_v2(
    owner: &mut ProductionRelayStage12OwnerV1,
    scanner: &ProductionDomF7ScannerAuthorityV1,
    local_bitcoin: &ProductionBitcoinParticipantAuthorityV1<'_>,
    leg: LegIdV1,
    request: F7AnchorValidationRequestV2<'_>,
) -> Result<ProductionF7M8ContractsIssuedV2, ProductionF7M8ErrorV2> {
    let verified = scanner.verify_f7_route_anchor_authority_v2(request)?;
    let (contracts_authorization, bitcoin_authorizations) = verified.into_parts();
    let expected_leg = match contracts_authorization.route_leg() {
        ComposedSettlementLegV1::Upstream => LegIdV1::Upstream,
        ComposedSettlementLegV1::Downstream => LegIdV1::Downstream,
    };
    if expected_leg != leg || local_bitcoin.leg() != leg {
        return Err(ProductionF7M8ErrorV2::BitcoinParticipantRefused);
    }
    let authority = local_bitcoin.authority();
    let role = authority.role();
    // F7 deliberately emits two role-unbound, byte-identical M.8 windows. The
    // array position is not itself signer authority: only the retained Stage-8
    // participant role below selects which single move-only wrapper survives.
    let [maker, taker] = bitcoin_authorizations;
    let (local_side, peer_role) = participant_authorization_selection(role);
    let (local_authorization, remote_authorization) = match local_side {
        LocalBitcoinAuthorizationSideV2::Maker => (maker, taker),
        LocalBitcoinAuthorizationSideV2::Taker => (taker, maker),
    };
    if local_authorization.settlement_terms_hash() != *contracts_authorization.terms_hash()
        || local_authorization.anchor_evidence_digest()
            != *contracts_authorization.anchor_evidence_digest()
        || remote_authorization.settlement_terms_hash()
            != local_authorization.settlement_terms_hash()
        || remote_authorization.anchor_evidence_digest()
            != local_authorization.anchor_evidence_digest()
        || remote_authorization.window() != local_authorization.window()
    {
        return Err(ProductionF7M8ErrorV2::BitcoinParticipantRefused);
    }
    let bitcoin = ProductionBitcoinM8ParticipantHandoffV2 {
        local: ProductionLocalBitcoinM8AuthorizationV2 {
            authorization: local_authorization,
            leg,
            participant_id: authority.participant_id(),
            role,
            authority_digest: authority.authority_digest(),
        },
        peer_comparison: ProductionPeerBitcoinM8ComparisonV2 {
            settlement_terms_hash: remote_authorization.settlement_terms_hash(),
            window: *remote_authorization.window(),
            anchor_evidence_digest: remote_authorization.anchor_evidence_digest(),
            peer_role,
        },
    };
    let contracts = owner.leg_mut(leg).contracts_mut();
    let contracts = contracts.issue_post_anchor_v2(contracts_authorization)?;
    Ok(ProductionF7M8ContractsIssuedV2 { contracts, bitcoin })
}

#[cfg(test)]
mod tests {
    use static_assertions::assert_not_impl_any;

    use super::*;

    assert_not_impl_any!(ProductionLocalBitcoinM8AuthorizationV2: Clone, Copy, core::fmt::Debug, Default);
    assert_not_impl_any!(ProductionBitcoinM8ParticipantHandoffV2: Clone, Copy, core::fmt::Debug, Default);
    assert_not_impl_any!(ProductionF7M8ContractsIssuedV2: Clone, Copy, core::fmt::Debug, Default);

    #[test]
    fn participant_role_selects_exactly_one_local_and_opposite_peer() {
        assert_eq!(
            participant_authorization_selection(BitcoinParticipantRoleV1::Maker),
            (
                LocalBitcoinAuthorizationSideV2::Maker,
                BitcoinParticipantRoleV1::Taker
            )
        );
        assert_eq!(
            participant_authorization_selection(BitcoinParticipantRoleV1::Taker),
            (
                LocalBitcoinAuthorizationSideV2::Taker,
                BitcoinParticipantRoleV1::Maker
            )
        );
    }
}
