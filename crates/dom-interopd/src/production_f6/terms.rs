//! Adapter-owned F6 refund-face commitments.
//!
//! A refund face is not a digest supplied by the route caller.  It is a
//! canonical record reconstructed from the frozen settlement and an
//! authenticated deployment/adapter authority.  The record below is private,
//! move-only and has no decoder: only adapter-specific constructors can mint
//! it.  The BTC constructor consumes the fresh Bitcoin owner's exact payout
//! capability. The DOM constructor consumes the wallet/store joint payout
//! capability and the exact registry-resolved DOM deployment.

use adapter_btc_live::AuthenticatedBitcoinPayoutFaceV1;
use adapter_evm::{adaptor_address, derive_binding, derive_lock_id, Direction, LockTerms};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chain_profile::ChainKindV1;
use deployment_registry::{
    AssetRepresentationV1, ResolvedBitcoinDeploymentV1, ResolvedDomDeploymentV1,
    ResolvedEvmDeploymentV1,
};
use dom_actuator::AuthenticatedDomPayoutFaceV1;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{Digest32, IntentHash, LockMechanism, SolverId, TimelockSpec};
use rfq::v2::{NativeClockKindV2, RefundFaceV2, ScopedTimelockV2, SettlementPositionV2};
use rfq::LegDirectionV1;
use route_composer::ComposedBindingV2;
use route_executor::LegIdV1;

use super::{ProductionF6ErrorV2, ProductionSolverF6BindingV2};
use crate::production_refund_arming::production_bitcoin_refund_route_binding_v1;

const ZERO_DIGEST: Digest32 = [0; 32];
const DOM_RECORD_DOMAIN: &[u8] = b"DOM-INTEROP/F6/ADAPTER-REFUND-FACE/DOM/V2\0";
const EVM_RECORD_DOMAIN: &[u8] = b"DOM-INTEROP/F6/ADAPTER-REFUND-FACE/EVM/V2\0";
const BTC_RECORD_DOMAIN: &[u8] = b"DOM-INTEROP/F6/ADAPTER-REFUND-FACE/BTC/V2\0";
const PAYOUT_COMMITMENT_DOMAIN: &[u8] = b"DOM-INTEROP/F6/PAYOUT-COMMITMENT/V2\0";
const EVIDENCE_DOMAIN: &[u8] = b"DOM-INTEROP/F6/ADAPTER-FACE-EVIDENCE/V2\0";
const TERMS_EVIDENCE_DOMAIN: &[u8] = b"DOM-INTEROP/F6/TERMS-AUTHORITY-EVIDENCE/V2\0";

#[derive(Clone, Copy, PartialEq, Eq)]
enum AdapterFaceLegV2 {
    Dom,
    Counterparty,
}

/// Adapter-authenticated face retained between adapter construction and the
/// F6 terms cross-object validator.
///
/// There is intentionally no public constructor, codec, `Clone`, `Copy`,
/// equality or `Debug` implementation.  The contained `RefundFaceV2` can be
/// consumed only together with the evidence that authenticated it.
pub(crate) struct AdapterAuthenticatedRefundFaceV2 {
    leg: AdapterFaceLegV2,
    position: SettlementPositionV2,
    settlement_id: Digest32,
    session_id: Digest32,
    terms_hash: Digest32,
    face: RefundFaceV2,
    evidence_digest: Digest32,
    evidence_revision: u64,
}

impl AdapterAuthenticatedRefundFaceV2 {
    /// Builds the DOM face exclusively from the wallet/store joint payout
    /// authority and the exact registry-resolved DOM deployment.
    pub(crate) fn from_dom(
        payout: AuthenticatedDomPayoutFaceV1,
        binding: &ProductionSolverF6BindingV2,
        settlement: &SettlementTermsV1,
        composition: &ComposedBindingV2,
        deployment: ResolvedDomDeploymentV1,
    ) -> Result<Self, ProductionF6ErrorV2> {
        settlement
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        binding.validate()?;
        let terms_hash = settlement
            .terms_hash()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let selected = match binding.position {
            SettlementPositionV2::Upstream => composition.upstream(),
            SettlementPositionV2::Downstream => composition.downstream(),
        };
        let direction = match binding.position {
            SettlementPositionV2::Upstream => LegDirectionV1::UserReceives,
            SettlementPositionV2::Downstream => LegDirectionV1::UserGives,
        };
        let deadline = match settlement.dom_leg.deadline {
            TimelockSpec::BlockHeight { value } if value != 0 => ScopedTimelockV2 {
                chain_id: settlement.dom_leg.chain_id,
                kind: NativeClockKindV2::BlockHeight,
                value,
            },
            TimelockSpec::BlockHeight { .. }
            | TimelockSpec::TimestampSeconds { .. }
            | TimelockSpec::BtcTime512s { .. } => return Err(ProductionF6ErrorV2::InvalidTerms),
        };
        deadline
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;

        let owner = payout.binding();
        let dom = deployment.deployment();
        let asset = deployment.native_asset_binding();
        let owner_participant = owner.participant();
        let roster_index = settlement
            .roster
            .iter()
            .position(|participant| participant.0 == owner_participant.participant_id())
            .and_then(|index| u8::try_from(index).ok());
        let payout_value = u128::from(payout.payout_value());
        if selected != settlement
            || composition.binding_digest() != binding.composition_id
            || composition.binding_digest() == ZERO_DIGEST
            || composition.route_scope_digest() == ZERO_DIGEST
            || binding.wire.session_id != settlement.session_id.0
            || binding.dom_chain_id != settlement.dom_leg.chain_id
            || binding.pins.registry_digest != deployment.registry_digest()
            || binding.pins.registry_epoch != deployment.registry_epoch()
            || deployment.registry_epoch() == 0
            || dom.chain_id != settlement.dom_leg.chain_id
            || dom.native_asset != settlement.dom_leg.asset_id
            || dom.consensus_rules_digest != settlement.dom_leg.adapter_profile_hash
            || dom.finality != settlement.dom_leg.finality
            || asset.chain_id != settlement.dom_leg.chain_id
            || asset.asset_id != settlement.dom_leg.asset_id
            || !matches!(asset.representation, AssetRepresentationV1::Native)
            || settlement.dom_leg.mechanism != LockMechanism::DomAdaptor2of2
            || owner.route_id() != binding.wire.route_id
            || owner.session_id() != settlement.session_id.0
            || owner.chain_id() != settlement.dom_leg.chain_id.0
            || owner.genesis_hash() != dom.genesis_hash
            || owner.runtime_identity() != dom.runtime_identity
            || owner.terms_digest() != terms_hash
            || owner.profile_digest() != dom.consensus_rules_digest
            || owner.deployment_digest() != deployment.registry_digest()
            || owner.asset_binding_digest() != deployment.native_asset_binding_digest()
            || owner.registry_epoch() != deployment.registry_epoch()
            || owner.min_confirmations() != dom.finality.min_confirmations
            || owner.max_reorg_depth() != dom.finality.max_reorg_depth
            || roster_index != Some(owner_participant.protocol_index())
            || owner_participant.participant_id() != settlement.dom_leg.beneficiary.0
            || payout.payout_commitment() == [0; 33]
            || payout_value != settlement.dom_leg.amount
            || payout.evidence_digest() == ZERO_DIGEST
            || payout.evidence_revision() == 0
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }

        let record = DomFaceRecordV2 {
            position: binding.position,
            direction,
            route_id: binding.wire.route_id,
            composition_id: binding.composition_id,
            composition_binding_digest: composition.binding_digest(),
            route_scope_digest: composition.route_scope_digest(),
            time_policy_digest: composition.time_policy_digest(),
            time_evidence_digest: composition.time_evidence_digest(),
            time_proof_digest: composition.time_proof_digest(),
            time_evidence_sequence: composition.evidence_sequence(),
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_hash,
            chain_id: settlement.dom_leg.chain_id.0,
            profile_digest: dom.consensus_rules_digest,
            deadline,
            registry_digest: deployment.registry_digest(),
            registry_epoch: deployment.registry_epoch(),
            asset_binding_digest: deployment.native_asset_binding_digest(),
            asset_id: asset.asset_id.0,
            asset_decimals: asset.decimals,
            genesis_hash: dom.genesis_hash,
            network: dom.runtime_identity.network as u8,
            network_magic: dom.runtime_identity.network_magic,
            protocol_version: dom.runtime_identity.protocol_version,
            range_proof_serialization_version: dom
                .runtime_identity
                .range_proof_serialization_version,
            consensus_rules_digest: dom.consensus_rules_digest,
            scriptless_api_version: dom.scriptless_api_version,
            min_block_seconds: dom.timing.min_block_seconds,
            max_block_seconds: dom.timing.max_block_seconds,
            max_reorg_seconds: dom.timing.max_reorg_seconds,
            observation_seconds: dom.timing.observation_seconds,
            broadcast_seconds: dom.timing.broadcast_seconds,
            min_confirmations: dom.finality.min_confirmations,
            max_reorg_depth: dom.finality.max_reorg_depth,
            participant_id: owner_participant.participant_id(),
            participant_index: owner_participant.protocol_index(),
            beneficiary: settlement.dom_leg.beneficiary.0,
            refund_to: settlement.dom_leg.refund_to.0,
            payout_commitment: payout.payout_commitment(),
            payout_value: payout.payout_value(),
            owner_evidence_digest: payout.evidence_digest(),
            owner_revision: payout.evidence_revision(),
        };
        let record = encode_dom_face_record(&record)?;
        let payout_commitment = digest(PAYOUT_COMMITMENT_DOMAIN, &[&record])?;
        let evidence_digest = digest(
            EVIDENCE_DOMAIN,
            &[
                &record,
                &payout_commitment,
                &payout.evidence_digest(),
                &payout.evidence_revision().to_be_bytes(),
            ],
        )?;
        Ok(Self {
            leg: AdapterFaceLegV2::Dom,
            position: binding.position,
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_hash,
            face: RefundFaceV2 {
                direction,
                chain_id: settlement.dom_leg.chain_id,
                refund_deadline: deadline,
                payout_commitment,
            },
            evidence_digest,
            evidence_revision: payout.evidence_revision(),
        })
    }

    /// Builds the Bitcoin face from the fresh wallet owner's move-only payout
    /// capability and the exact authenticated composition/deployment.
    pub(crate) fn from_btc(
        payout: AuthenticatedBitcoinPayoutFaceV1,
        binding: &ProductionSolverF6BindingV2,
        settlement: &SettlementTermsV1,
        composition: &ComposedBindingV2,
        deployment: ResolvedBitcoinDeploymentV1,
    ) -> Result<Self, ProductionF6ErrorV2> {
        settlement
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        binding.validate()?;
        deployment
            .profile()
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let terms_hash = settlement
            .terms_hash()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let (leg, direction, selected) = match binding.position {
            SettlementPositionV2::Upstream => (
                LegIdV1::Upstream,
                LegDirectionV1::UserGives,
                composition.upstream(),
            ),
            SettlementPositionV2::Downstream => (
                LegIdV1::Downstream,
                LegDirectionV1::UserReceives,
                composition.downstream(),
            ),
        };
        let deadline = match settlement.counterparty_leg.deadline {
            TimelockSpec::BtcTime512s { value } if value != 0 => ScopedTimelockV2 {
                chain_id: settlement.counterparty_leg.chain_id,
                kind: NativeClockKindV2::BitcoinTime512,
                value,
            },
            TimelockSpec::BlockHeight { .. }
            | TimelockSpec::TimestampSeconds { .. }
            | TimelockSpec::BtcTime512s { .. } => return Err(ProductionF6ErrorV2::InvalidTerms),
        };
        deadline
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;

        let expected_route_binding = production_bitcoin_refund_route_binding_v1(
            binding.wire.route_id,
            composition,
            leg,
            &deployment,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let contract_amount = u64::try_from(settlement.counterparty_leg.amount)
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let claim_amount = payout.claim_output_amount_sat();
        let claim_fee = contract_amount
            .checked_sub(claim_amount)
            .ok_or(ProductionF6ErrorV2::InvalidTerms)?;
        let asset = deployment.asset_binding();
        if selected != settlement
            || composition.binding_digest() != binding.composition_id
            || composition.binding_digest() == ZERO_DIGEST
            || composition.route_scope_digest() == ZERO_DIGEST
            || binding.wire.session_id != settlement.session_id.0
            || binding.dom_chain_id != settlement.dom_leg.chain_id
            || binding.pins.registry_digest != deployment.registry_digest()
            || binding.pins.registry_epoch != deployment.registry_epoch()
            || deployment.registry_epoch() == 0
            || deployment.profile_digest() != settlement.counterparty_leg.adapter_profile_hash
            || deployment.profile().chain_id != settlement.counterparty_leg.chain_id
            || asset.chain_id != settlement.counterparty_leg.chain_id
            || asset.asset_id != settlement.counterparty_leg.asset_id
            || !matches!(asset.representation, AssetRepresentationV1::Native)
            || !matches!(deployment.profile().kind, ChainKindV1::Bitcoin { .. })
            || settlement.counterparty_leg.mechanism != LockMechanism::SchnorrAdaptor
            || payout.route_binding() != expected_route_binding
            || payout.receipt_digest() == ZERO_DIGEST
            || payout.contract_amount_sat() != contract_amount
            || claim_amount == 0
            || claim_amount >= contract_amount
            || u128::from(claim_fee) > settlement.fee_limit.counterparty_max
            || payout.claim_destination_script_pubkey().is_empty()
            || payout.claim_template_hash() == ZERO_DIGEST
            || payout.evidence_digest() == ZERO_DIGEST
            || payout.revision() == 0
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }

        let record = BitcoinFaceRecordV2 {
            position: binding.position,
            direction,
            route_id: binding.wire.route_id,
            composition_id: binding.composition_id,
            composition_binding_digest: composition.binding_digest(),
            route_scope_digest: composition.route_scope_digest(),
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_hash,
            chain_id: settlement.counterparty_leg.chain_id.0,
            profile_digest: deployment.profile_digest(),
            deadline,
            registry_digest: deployment.registry_digest(),
            registry_epoch: deployment.registry_epoch(),
            asset_binding_digest: deployment.asset_binding_digest(),
            asset_id: asset.asset_id.0,
            asset_decimals: asset.decimals,
            genesis_hash: deployment.deployment().genesis_hash,
            signet_challenge: deployment.deployment().signet_challenge.clone(),
            max_fee_rate_sat_vbyte: deployment.deployment().max_fee_rate_sat_vbyte,
            min_relay_fee_sat_kvb: deployment.deployment().min_relay_fee_sat_kvb,
            owner_route_binding: payout.route_binding(),
            owner_receipt_digest: payout.receipt_digest(),
            contract_amount_sat: payout.contract_amount_sat(),
            claim_amount_sat: claim_amount,
            claim_destination_script: payout.claim_destination_script_pubkey().to_vec(),
            claim_template_hash: payout.claim_template_hash(),
            owner_evidence_digest: payout.evidence_digest(),
            owner_revision: payout.revision(),
        };
        let record = encode_bitcoin_face_record(&record)?;
        let payout_commitment = digest(PAYOUT_COMMITMENT_DOMAIN, &[&record])?;
        let evidence_digest = digest(
            EVIDENCE_DOMAIN,
            &[
                &record,
                &payout_commitment,
                &payout.evidence_digest(),
                &payout.revision().to_be_bytes(),
            ],
        )?;
        Ok(Self {
            leg: AdapterFaceLegV2::Counterparty,
            position: binding.position,
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_hash,
            face: RefundFaceV2 {
                direction,
                chain_id: settlement.counterparty_leg.chain_id,
                refund_deadline: deadline,
                payout_commitment,
            },
            evidence_digest,
            evidence_revision: payout.revision(),
        })
    }

    /// Builds the EVM face exclusively from a verified registry deployment,
    /// its session-bound adapter config and the exact composed settlement.
    pub(crate) fn from_evm(
        binding: &ProductionSolverF6BindingV2,
        settlement: &SettlementTermsV1,
        deployment: ResolvedEvmDeploymentV1,
    ) -> Result<Self, ProductionF6ErrorV2> {
        settlement
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        binding.validate()?;
        let terms_hash = settlement
            .terms_hash()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let config = deployment.adapter_config();
        config
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;

        let (direction, expected_adapter_direction) = match binding.position {
            SettlementPositionV2::Upstream => (LegDirectionV1::UserGives, Direction::EvmToDom),
            SettlementPositionV2::Downstream => (LegDirectionV1::UserReceives, Direction::DomToEvm),
        };
        let deadline = match settlement.counterparty_leg.deadline {
            TimelockSpec::TimestampSeconds { value } if value != 0 => ScopedTimelockV2 {
                chain_id: settlement.counterparty_leg.chain_id,
                kind: NativeClockKindV2::TimestampSeconds,
                value,
            },
            TimelockSpec::BlockHeight { .. }
            | TimelockSpec::BtcTime512s { .. }
            | TimelockSpec::TimestampSeconds { .. } => {
                return Err(ProductionF6ErrorV2::InvalidTerms)
            }
        };
        deadline
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;

        if deployment.registry_digest() != binding.pins.registry_digest
            || deployment.registry_epoch() != binding.pins.registry_epoch
            || deployment.registry_epoch() == 0
            || deployment.profile_digest() != settlement.counterparty_leg.adapter_profile_hash
            || deployment.asset_binding().chain_id != settlement.counterparty_leg.chain_id
            || deployment.asset_binding().asset_id != settlement.counterparty_leg.asset_id
            || binding.dom_chain_id.0 != settlement.dom_leg.chain_id.0
            || config.dom_chain_id != settlement.dom_leg.chain_id.0
            || config.session_id != settlement.session_id.0
            || config.terms_hash != terms_hash
            || config.direction != expected_adapter_direction
            || settlement.counterparty_leg.mechanism != LockMechanism::ConditionLock
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }

        match deployment.asset_binding().representation {
            AssetRepresentationV1::Native if config.asset == [0; 20] => {}
            AssetRepresentationV1::EvmErc20 { token, .. } if token == config.asset => {}
            AssetRepresentationV1::Native | AssetRepresentationV1::EvmErc20 { .. } => {
                return Err(ProductionF6ErrorV2::InvalidTerms)
            }
        }

        let mut amount = [0_u8; 32];
        amount[16..].copy_from_slice(&settlement.counterparty_leg.amount.to_be_bytes());
        let lock_terms = LockTerms {
            dom_chain_id: config.dom_chain_id,
            direction: config.direction.as_u8(),
            session_id: config.session_id,
            terms_hash: config.terms_hash,
            participants_hash: config.participants_hash,
            asset: config.asset,
            amount,
            beneficiary: config.beneficiary,
            adaptor_address: adaptor_address(&settlement.adaptor_point_sec1)
                .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?,
            deadline: deadline.value,
        };
        if !config.binds_terms(&lock_terms) {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        let evm_binding = derive_binding(config.chain_id, &config.contract, &lock_terms)
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let lock_id = derive_lock_id(&evm_binding, &config.funder)
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;

        let record = canonical_evm_record(
            binding.position,
            direction,
            settlement,
            terms_hash,
            deadline,
            deployment,
            evm_binding,
            lock_id,
        )?;
        let payout_commitment = digest(PAYOUT_COMMITMENT_DOMAIN, &[&record])?;
        let evidence_digest = digest(
            EVIDENCE_DOMAIN,
            &[
                &record,
                &payout_commitment,
                &deployment.registry_epoch().to_be_bytes(),
            ],
        )?;
        let face = RefundFaceV2 {
            direction,
            chain_id: settlement.counterparty_leg.chain_id,
            refund_deadline: deadline,
            payout_commitment,
        };
        Ok(Self {
            leg: AdapterFaceLegV2::Counterparty,
            position: binding.position,
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_hash,
            face,
            evidence_digest,
            evidence_revision: deployment.registry_epoch(),
        })
    }

    fn validates_for(
        &self,
        binding: &ProductionSolverF6BindingV2,
        settlement: &SettlementTermsV1,
        expected_leg: AdapterFaceLegV2,
    ) -> Result<(), ProductionF6ErrorV2> {
        let terms_hash = settlement
            .terms_hash()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let expected_chain = match expected_leg {
            AdapterFaceLegV2::Dom => settlement.dom_leg.chain_id,
            AdapterFaceLegV2::Counterparty => settlement.counterparty_leg.chain_id,
        };
        let expected_direction = match (binding.position, expected_leg) {
            (SettlementPositionV2::Upstream, AdapterFaceLegV2::Dom)
            | (SettlementPositionV2::Downstream, AdapterFaceLegV2::Counterparty) => {
                LegDirectionV1::UserReceives
            }
            (SettlementPositionV2::Downstream, AdapterFaceLegV2::Dom)
            | (SettlementPositionV2::Upstream, AdapterFaceLegV2::Counterparty) => {
                LegDirectionV1::UserGives
            }
        };
        let deadline_spec = match expected_leg {
            AdapterFaceLegV2::Dom => settlement.dom_leg.deadline,
            AdapterFaceLegV2::Counterparty => settlement.counterparty_leg.deadline,
        };
        let expected_deadline = scoped_deadline(expected_chain, deadline_spec)?;
        if self.leg != expected_leg
            || self.position != binding.position
            || self.settlement_id != settlement.settlement_id.0
            || self.session_id != settlement.session_id.0
            || self.terms_hash != terms_hash
            || self.face.direction != expected_direction
            || self.face.chain_id != expected_chain
            || self.face.refund_deadline != expected_deadline
            || self.face.payout_commitment == ZERO_DIGEST
            || self.evidence_digest == ZERO_DIGEST
            || self.evidence_revision == 0
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        Ok(())
    }
}

fn scoped_deadline(
    chain_id: kaystra_core::types::ChainId,
    spec: TimelockSpec,
) -> Result<ScopedTimelockV2, ProductionF6ErrorV2> {
    let (kind, value) = match spec {
        TimelockSpec::BlockHeight { value } => (NativeClockKindV2::BlockHeight, value),
        TimelockSpec::TimestampSeconds { value } => (NativeClockKindV2::TimestampSeconds, value),
        TimelockSpec::BtcTime512s { value } => (NativeClockKindV2::BitcoinTime512, value),
    };
    if value == 0 {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    let deadline = ScopedTimelockV2 {
        chain_id,
        kind,
        value,
    };
    deadline
        .validate()
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    Ok(deadline)
}

/// One-shot concrete F6 terms authority backed by exactly one DOM face and one
/// external adapter face. Construction accepts no raw digest, deadline,
/// payout, direction or revision fields.
pub(crate) struct ProductionAdapterF6TermsAuthorityV2 {
    binding: ProductionSolverF6BindingV2,
    settlement: SettlementTermsV1,
    composition_binding_digest: Digest32,
    route_scope_digest: Digest32,
    time_policy_digest: Digest32,
    time_evidence_digest: Digest32,
    time_proof_digest: Digest32,
    time_evidence_sequence: u64,
    dom: Option<AdapterAuthenticatedRefundFaceV2>,
    counterparty: Option<AdapterAuthenticatedRefundFaceV2>,
}

impl ProductionAdapterF6TermsAuthorityV2 {
    /// Retains the two move-only faces only after proving that the selected
    /// settlement is the exact member of the authenticated composition named
    /// by the F6 binding.
    pub(crate) fn new(
        binding: ProductionSolverF6BindingV2,
        composition: &ComposedBindingV2,
        dom: AdapterAuthenticatedRefundFaceV2,
        counterparty: AdapterAuthenticatedRefundFaceV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        binding.validate()?;
        let settlement = match binding.position {
            SettlementPositionV2::Upstream => composition.upstream(),
            SettlementPositionV2::Downstream => composition.downstream(),
        };
        settlement
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        if composition.binding_digest() != binding.composition_id
            || composition.binding_digest() == ZERO_DIGEST
            || composition.route_scope_digest() == ZERO_DIGEST
            || composition.time_policy_digest() == ZERO_DIGEST
            || composition.time_evidence_digest() == ZERO_DIGEST
            || composition.time_proof_digest() == ZERO_DIGEST
            || composition.evidence_sequence() == 0
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        dom.validates_for(&binding, settlement, AdapterFaceLegV2::Dom)?;
        counterparty.validates_for(&binding, settlement, AdapterFaceLegV2::Counterparty)?;
        Ok(Self {
            binding,
            settlement: settlement.clone(),
            composition_binding_digest: composition.binding_digest(),
            route_scope_digest: composition.route_scope_digest(),
            time_policy_digest: composition.time_policy_digest(),
            time_evidence_digest: composition.time_evidence_digest(),
            time_proof_digest: composition.time_proof_digest(),
            time_evidence_sequence: composition.evidence_sequence(),
            dom: Some(dom),
            counterparty: Some(counterparty),
        })
    }

    fn validate_cross_objects(
        &self,
        binding: &ProductionSolverF6BindingV2,
        rfq: &rfq::v2::RfqV2,
        quote: &rfq::v2::QuoteV2,
    ) -> Result<(), ProductionF6ErrorV2> {
        binding.validate()?;
        rfq.validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        quote
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        self.settlement
            .validate()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let terms_hash = self
            .settlement
            .terms_hash()
            .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        let mut expected_roster = [binding.initiator, binding.solver];
        expected_roster.sort_by_key(|participant| participant.0);
        let expected_dom_direction = match binding.position {
            SettlementPositionV2::Upstream => LegDirectionV1::UserReceives,
            SettlementPositionV2::Downstream => LegDirectionV1::UserGives,
        };
        let expected_counterparty_direction = match binding.position {
            SettlementPositionV2::Upstream => LegDirectionV1::UserGives,
            SettlementPositionV2::Downstream => LegDirectionV1::UserReceives,
        };
        let expected_dom_amount = match expected_dom_direction {
            LegDirectionV1::UserGives => quote.total_input,
            LegDirectionV1::UserReceives => quote.net_output,
        };
        let expected_counterparty_amount = match expected_counterparty_direction {
            LegDirectionV1::UserGives => quote.total_input,
            LegDirectionV1::UserReceives => quote.net_output,
        };
        let dom_route_leg = rfq
            .route
            .legs
            .iter()
            .find(|leg| leg.chain_id == binding.dom_chain_id);
        let counterparty_route_leg = rfq
            .route
            .legs
            .iter()
            .find(|leg| leg.chain_id != binding.dom_chain_id);
        let quote_satisfies_mode = match rfq.mode {
            rfq::RfqModeV1::ExactIn {
                input_amount,
                minimum_output,
            } => quote.total_input == input_amount && quote.net_output >= minimum_output,
            rfq::RfqModeV1::ExactOut {
                exact_output,
                maximum_input,
            } => quote.net_output == exact_output && quote.total_input <= maximum_input,
        };
        let total_fee_limit = rfq
            .fee_limit
            .dom_max
            .checked_add(rfq.fee_limit.counterparty_max);

        if self.binding != *binding
            || binding.rfq_id != rfq.rfq_id
            || binding.composition_id != rfq.route.composition_id
            || binding.position != rfq.route.position
            || binding.initiator != rfq.initiator
            || binding.solver != quote.solver
            || binding.wire.session_id != rfq.session_id
            || quote.rfq_id != rfq.rfq_id
            || quote.route != rfq.route
            || quote.execution_deadline.clock != rfq.negotiation_clock
            || quote.expiry.clock != rfq.negotiation_clock
            || !quote_satisfies_mode
            || total_fee_limit.map_or(true, |limit| quote.total_fee > limit)
            || self.composition_binding_digest != binding.composition_id
            || self.route_scope_digest == ZERO_DIGEST
            || self.time_policy_digest == ZERO_DIGEST
            || self.time_evidence_digest == ZERO_DIGEST
            || self.time_proof_digest == ZERO_DIGEST
            || self.time_evidence_sequence == 0
            || self.settlement.session_id.0 != rfq.session_id
            || self.settlement.intent_hash != IntentHash(rfq.rfq_id)
            || self.settlement.solver_id != SolverId(quote.solver.0)
            || self.settlement.roster != expected_roster
            || self.settlement.fee_limit != rfq.fee_limit
            || self.settlement.assurance_policy_hash != Some(rfq.assurance_policy_ref.0)
            || self.settlement.policy_version != rfq.policy_version
            || binding.wire.policy_version != rfq.policy_version
            || self.settlement.dom_leg.amount != expected_dom_amount
            || self.settlement.counterparty_leg.amount != expected_counterparty_amount
            || dom_route_leg.map_or(true, |leg| {
                leg.asset != self.settlement.dom_leg.asset_id
                    || leg.direction != expected_dom_direction
            })
            || counterparty_route_leg.map_or(true, |leg| {
                leg.chain_id != self.settlement.counterparty_leg.chain_id
                    || leg.asset != self.settlement.counterparty_leg.asset_id
                    || leg.direction != expected_counterparty_direction
            })
            || terms_hash == ZERO_DIGEST
        {
            return Err(ProductionF6ErrorV2::InvalidTerms);
        }
        self.dom
            .as_ref()
            .ok_or(ProductionF6ErrorV2::TermsUnavailable)?
            .validates_for(binding, &self.settlement, AdapterFaceLegV2::Dom)?;
        self.counterparty
            .as_ref()
            .ok_or(ProductionF6ErrorV2::TermsUnavailable)?
            .validates_for(binding, &self.settlement, AdapterFaceLegV2::Counterparty)?;
        self.dom
            .as_ref()
            .and_then(|dom| {
                self.counterparty.as_ref().and_then(|counterparty| {
                    dom.evidence_revision
                        .checked_add(counterparty.evidence_revision)
                        .and_then(|revision| revision.checked_add(self.time_evidence_sequence))
                })
            })
            .ok_or(ProductionF6ErrorV2::InvalidTerms)?;
        Ok(())
    }
}

impl super::source_seal::Sealed for ProductionAdapterF6TermsAuthorityV2 {}

impl super::ProductionF6TermsAuthorityV2 for ProductionAdapterF6TermsAuthorityV2 {
    fn authenticate_terms(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
        rfq: &rfq::v2::RfqV2,
        quote: &rfq::v2::QuoteV2,
    ) -> Result<super::AuthenticatedF6TermsV2, ProductionF6ErrorV2> {
        self.validate_cross_objects(binding, rfq, quote)?;
        let dom = self
            .dom
            .as_ref()
            .ok_or(ProductionF6ErrorV2::TermsUnavailable)?;
        let counterparty = self
            .counterparty
            .as_ref()
            .ok_or(ProductionF6ErrorV2::TermsUnavailable)?;
        let (dom_face, dom_evidence, dom_revision) =
            (dom.face, dom.evidence_digest, dom.evidence_revision);
        let (counterparty_face, counterparty_evidence, counterparty_revision) = (
            counterparty.face,
            counterparty.evidence_digest,
            counterparty.evidence_revision,
        );
        let (faces, ordered_evidence, ordered_revisions) =
            if rfq.route.legs[0].chain_id == binding.dom_chain_id {
                (
                    [dom_face, counterparty_face],
                    [dom_evidence, counterparty_evidence],
                    [dom_revision, counterparty_revision],
                )
            } else {
                (
                    [counterparty_face, dom_face],
                    [counterparty_evidence, dom_evidence],
                    [counterparty_revision, dom_revision],
                )
            };
        let evidence_revision = ordered_revisions[0]
            .checked_add(ordered_revisions[1])
            .and_then(|revision| revision.checked_add(self.time_evidence_sequence))
            .ok_or(ProductionF6ErrorV2::InvalidTerms)?;
        let binding_evidence = binding.authority_digest(TERMS_EVIDENCE_DOMAIN)?;
        let evidence_digest = digest(
            TERMS_EVIDENCE_DOMAIN,
            &[
                &binding_evidence,
                &self.composition_binding_digest,
                &self.route_scope_digest,
                &self.time_policy_digest,
                &self.time_evidence_digest,
                &self.time_proof_digest,
                &self.time_evidence_sequence.to_be_bytes(),
                &rfq.rfq_id,
                &quote.quote_id,
                &ordered_evidence[0],
                &ordered_revisions[0].to_be_bytes(),
                &ordered_evidence[1],
                &ordered_revisions[1].to_be_bytes(),
            ],
        )?;
        let authenticated = super::AuthenticatedF6TermsV2::from_adapter_faces(
            rfq,
            quote,
            faces,
            evidence_digest,
            evidence_revision,
        )?;
        let consumed_dom = self.dom.take();
        let consumed_counterparty = self.counterparty.take();
        debug_assert!(consumed_dom.is_some() && consumed_counterparty.is_some());
        Ok(authenticated)
    }
}

struct DomFaceRecordV2 {
    position: SettlementPositionV2,
    direction: LegDirectionV1,
    route_id: Digest32,
    composition_id: Digest32,
    composition_binding_digest: Digest32,
    route_scope_digest: Digest32,
    time_policy_digest: Digest32,
    time_evidence_digest: Digest32,
    time_proof_digest: Digest32,
    time_evidence_sequence: u64,
    settlement_id: Digest32,
    session_id: Digest32,
    terms_hash: Digest32,
    chain_id: Digest32,
    profile_digest: Digest32,
    deadline: ScopedTimelockV2,
    registry_digest: Digest32,
    registry_epoch: u64,
    asset_binding_digest: Digest32,
    asset_id: Digest32,
    asset_decimals: u8,
    genesis_hash: Digest32,
    network: u8,
    network_magic: u32,
    protocol_version: u32,
    range_proof_serialization_version: u8,
    consensus_rules_digest: Digest32,
    scriptless_api_version: u32,
    min_block_seconds: u32,
    max_block_seconds: u32,
    max_reorg_seconds: u32,
    observation_seconds: u32,
    broadcast_seconds: u32,
    min_confirmations: u32,
    max_reorg_depth: u32,
    participant_id: Digest32,
    participant_index: u8,
    beneficiary: Digest32,
    refund_to: Digest32,
    payout_commitment: [u8; 33],
    payout_value: u64,
    owner_evidence_digest: Digest32,
    owner_revision: u64,
}

fn encode_dom_face_record(record: &DomFaceRecordV2) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    if [
        record.route_id,
        record.composition_id,
        record.composition_binding_digest,
        record.route_scope_digest,
        record.time_policy_digest,
        record.time_evidence_digest,
        record.time_proof_digest,
        record.settlement_id,
        record.session_id,
        record.terms_hash,
        record.chain_id,
        record.profile_digest,
        record.registry_digest,
        record.asset_binding_digest,
        record.asset_id,
        record.genesis_hash,
        record.consensus_rules_digest,
        record.participant_id,
        record.beneficiary,
        record.refund_to,
        record.owner_evidence_digest,
    ]
    .contains(&ZERO_DIGEST)
        || record.time_evidence_sequence == 0
        || record.registry_epoch == 0
        || record.network == 0
        || record.network_magic == 0
        || record.protocol_version == 0
        || record.range_proof_serialization_version == 0
        || record.scriptless_api_version == 0
        || record.min_block_seconds == 0
        || record.max_block_seconds < record.min_block_seconds
        || record.max_reorg_seconds == 0
        || record.observation_seconds == 0
        || record.broadcast_seconds == 0
        || record.min_confirmations == 0
        || record.max_reorg_depth < record.min_confirmations
        || record.participant_index > 1
        || record.payout_commitment == [0; 33]
        || record.payout_value == 0
        || record.owner_revision == 0
    {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    record
        .deadline
        .validate()
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    if record.deadline.chain_id.0 != record.chain_id
        || record.deadline.kind != NativeClockKindV2::BlockHeight
        || record.profile_digest != record.consensus_rules_digest
        || record.participant_id != record.beneficiary
    {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }

    let mut output = Vec::with_capacity(896);
    output.extend_from_slice(DOM_RECORD_DOMAIN);
    output.push(record.position as u8);
    output.push(direction_tag(record.direction));
    output.extend_from_slice(&record.route_id);
    output.extend_from_slice(&record.composition_id);
    output.extend_from_slice(&record.composition_binding_digest);
    output.extend_from_slice(&record.route_scope_digest);
    output.extend_from_slice(&record.time_policy_digest);
    output.extend_from_slice(&record.time_evidence_digest);
    output.extend_from_slice(&record.time_proof_digest);
    output.extend_from_slice(&record.time_evidence_sequence.to_be_bytes());
    output.extend_from_slice(&record.settlement_id);
    output.extend_from_slice(&record.session_id);
    output.extend_from_slice(&record.terms_hash);
    output.extend_from_slice(&record.chain_id);
    output.extend_from_slice(&record.profile_digest);
    output.push(record.deadline.kind as u8);
    output.extend_from_slice(&record.deadline.value.to_be_bytes());
    output.extend_from_slice(&record.registry_digest);
    output.extend_from_slice(&record.registry_epoch.to_be_bytes());
    output.extend_from_slice(&record.asset_binding_digest);
    output.extend_from_slice(&record.asset_id);
    output.push(record.asset_decimals);
    output.extend_from_slice(&record.genesis_hash);
    output.push(record.network);
    output.extend_from_slice(&record.network_magic.to_be_bytes());
    output.extend_from_slice(&record.protocol_version.to_be_bytes());
    output.push(record.range_proof_serialization_version);
    output.extend_from_slice(&record.consensus_rules_digest);
    output.extend_from_slice(&record.scriptless_api_version.to_be_bytes());
    output.extend_from_slice(&record.min_block_seconds.to_be_bytes());
    output.extend_from_slice(&record.max_block_seconds.to_be_bytes());
    output.extend_from_slice(&record.max_reorg_seconds.to_be_bytes());
    output.extend_from_slice(&record.observation_seconds.to_be_bytes());
    output.extend_from_slice(&record.broadcast_seconds.to_be_bytes());
    output.extend_from_slice(&record.min_confirmations.to_be_bytes());
    output.extend_from_slice(&record.max_reorg_depth.to_be_bytes());
    output.extend_from_slice(&record.participant_id);
    output.push(record.participant_index);
    output.extend_from_slice(&record.beneficiary);
    output.extend_from_slice(&record.refund_to);
    output.extend_from_slice(&record.payout_commitment);
    output.extend_from_slice(&record.payout_value.to_be_bytes());
    output.extend_from_slice(&record.owner_evidence_digest);
    output.extend_from_slice(&record.owner_revision.to_be_bytes());
    Ok(output)
}

struct BitcoinFaceRecordV2 {
    position: SettlementPositionV2,
    direction: LegDirectionV1,
    route_id: Digest32,
    composition_id: Digest32,
    composition_binding_digest: Digest32,
    route_scope_digest: Digest32,
    settlement_id: Digest32,
    session_id: Digest32,
    terms_hash: Digest32,
    chain_id: Digest32,
    profile_digest: Digest32,
    deadline: ScopedTimelockV2,
    registry_digest: Digest32,
    registry_epoch: u64,
    asset_binding_digest: Digest32,
    asset_id: Digest32,
    asset_decimals: u8,
    genesis_hash: Digest32,
    signet_challenge: Vec<u8>,
    max_fee_rate_sat_vbyte: u64,
    min_relay_fee_sat_kvb: u64,
    owner_route_binding: Digest32,
    owner_receipt_digest: Digest32,
    contract_amount_sat: u64,
    claim_amount_sat: u64,
    claim_destination_script: Vec<u8>,
    claim_template_hash: Digest32,
    owner_evidence_digest: Digest32,
    owner_revision: u64,
}

fn encode_bitcoin_face_record(
    record: &BitcoinFaceRecordV2,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    let signet_length = u64::try_from(record.signet_challenge.len())
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    let script_length = u64::try_from(record.claim_destination_script.len())
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    if record.route_id == ZERO_DIGEST
        || record.composition_id == ZERO_DIGEST
        || record.composition_binding_digest == ZERO_DIGEST
        || record.route_scope_digest == ZERO_DIGEST
        || record.settlement_id == ZERO_DIGEST
        || record.session_id == ZERO_DIGEST
        || record.terms_hash == ZERO_DIGEST
        || record.chain_id == ZERO_DIGEST
        || record.profile_digest == ZERO_DIGEST
        || record.registry_digest == ZERO_DIGEST
        || record.registry_epoch == 0
        || record.asset_binding_digest == ZERO_DIGEST
        || record.asset_id == ZERO_DIGEST
        || record.genesis_hash == ZERO_DIGEST
        || record.owner_route_binding == ZERO_DIGEST
        || record.owner_receipt_digest == ZERO_DIGEST
        || record.contract_amount_sat == 0
        || record.claim_amount_sat == 0
        || record.claim_amount_sat >= record.contract_amount_sat
        || record.claim_destination_script.is_empty()
        || record.claim_template_hash == ZERO_DIGEST
        || record.owner_evidence_digest == ZERO_DIGEST
        || record.owner_revision == 0
    {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    record
        .deadline
        .validate()
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    if record.deadline.chain_id.0 != record.chain_id
        || record.deadline.kind != NativeClockKindV2::BitcoinTime512
    {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }

    let mut output = Vec::with_capacity(768);
    output.extend_from_slice(BTC_RECORD_DOMAIN);
    output.push(record.position as u8);
    output.push(direction_tag(record.direction));
    output.extend_from_slice(&record.route_id);
    output.extend_from_slice(&record.composition_id);
    output.extend_from_slice(&record.composition_binding_digest);
    output.extend_from_slice(&record.route_scope_digest);
    output.extend_from_slice(&record.settlement_id);
    output.extend_from_slice(&record.session_id);
    output.extend_from_slice(&record.terms_hash);
    output.extend_from_slice(&record.chain_id);
    output.extend_from_slice(&record.profile_digest);
    output.push(record.deadline.kind as u8);
    output.extend_from_slice(&record.deadline.value.to_be_bytes());
    output.extend_from_slice(&record.registry_digest);
    output.extend_from_slice(&record.registry_epoch.to_be_bytes());
    output.extend_from_slice(&record.asset_binding_digest);
    output.extend_from_slice(&record.asset_id);
    output.push(record.asset_decimals);
    output.extend_from_slice(&record.genesis_hash);
    output.extend_from_slice(&signet_length.to_be_bytes());
    output.extend_from_slice(&record.signet_challenge);
    output.extend_from_slice(&record.max_fee_rate_sat_vbyte.to_be_bytes());
    output.extend_from_slice(&record.min_relay_fee_sat_kvb.to_be_bytes());
    output.extend_from_slice(&record.owner_route_binding);
    output.extend_from_slice(&record.owner_receipt_digest);
    output.extend_from_slice(&record.contract_amount_sat.to_be_bytes());
    output.extend_from_slice(&record.claim_amount_sat.to_be_bytes());
    output.extend_from_slice(&script_length.to_be_bytes());
    output.extend_from_slice(&record.claim_destination_script);
    output.extend_from_slice(&record.claim_template_hash);
    output.extend_from_slice(&record.owner_evidence_digest);
    output.extend_from_slice(&record.owner_revision.to_be_bytes());
    Ok(output)
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
)]
fn canonical_evm_record(
    position: SettlementPositionV2,
    direction: LegDirectionV1,
    settlement: &SettlementTermsV1,
    terms_hash: Digest32,
    deadline: ScopedTimelockV2,
    deployment: ResolvedEvmDeploymentV1,
    evm_binding: Digest32,
    lock_id: Digest32,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    let config = deployment.adapter_config();
    let evm = deployment.deployment();
    let asset = deployment.asset_binding();
    let mut record = Vec::with_capacity(768);
    record.extend_from_slice(EVM_RECORD_DOMAIN);
    record.push(position as u8);
    record.push(direction_tag(direction));
    record.extend_from_slice(&settlement.settlement_id.0);
    record.extend_from_slice(&settlement.session_id.0);
    record.extend_from_slice(&terms_hash);
    record.extend_from_slice(&settlement.counterparty_leg.chain_id.0);
    record.extend_from_slice(&deployment.profile_digest());
    record.push(deadline.kind as u8);
    record.extend_from_slice(&deadline.value.to_be_bytes());
    record.extend_from_slice(&deployment.registry_digest());
    record.extend_from_slice(&deployment.registry_epoch().to_be_bytes());
    record.extend_from_slice(&deployment.asset_binding_digest());
    record.extend_from_slice(&asset.asset_id.0);
    record.push(asset.decimals);
    match asset.representation {
        AssetRepresentationV1::Native => record.push(0),
        AssetRepresentationV1::EvmErc20 {
            token,
            token_code_hash,
        } => {
            record.push(1);
            record.extend_from_slice(&token);
            record.extend_from_slice(&token_code_hash);
        }
    }
    record.extend_from_slice(&config.chain_id.to_be_bytes());
    record.extend_from_slice(&config.contract);
    record.extend_from_slice(&config.expected_code_hash);
    record.extend_from_slice(&config.asset);
    record.extend_from_slice(&config.funder);
    record.extend_from_slice(&config.beneficiary);
    record.extend_from_slice(&config.participants_hash);
    record.extend_from_slice(&evm_binding);
    record.extend_from_slice(&lock_id);
    record.extend_from_slice(&evm.genesis_hash);
    record.extend_from_slice(&evm.abi_digest);
    record.extend_from_slice(&evm.compiler_digest);
    record.extend_from_slice(&evm.source_digest);
    record.extend_from_slice(&evm.deployment_digest);
    record.push(u8::from(evm.finalized_tag_required));
    record.extend_from_slice(&evm.native_start_block.to_be_bytes());
    match evm.erc20_start_block {
        Some(block) => {
            record.push(1);
            record.extend_from_slice(&block.to_be_bytes());
        }
        None => record.push(0),
    }
    record.extend_from_slice(&evm.page_size.to_be_bytes());
    record.extend_from_slice(&evm.gas_limit_hint.to_be_bytes());
    record.extend_from_slice(&evm.max_fee_per_gas.to_be_bytes());
    record.extend_from_slice(&evm.max_priority_fee_per_gas.to_be_bytes());
    if record.iter().all(|byte| *byte == 0) {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    Ok(record)
}

const fn direction_tag(direction: LegDirectionV1) -> u8 {
    match direction {
        LegDirectionV1::UserGives => 1,
        LegDirectionV1::UserReceives => 2,
    }
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ProductionF6ErrorV2> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    hasher.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| ProductionF6ErrorV2::InvalidTerms)?;
    if output == ZERO_DIGEST {
        return Err(ProductionF6ErrorV2::InvalidTerms);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_f6::{ProductionF6PinsV2, ProductionF6TermsAuthorityV2 as _};
    use kaystra_core::types::{
        AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, LegRole, LegTermsV1, ParticipantId,
        RecoveryPolicyV1, SessionId, SettlementId,
    };
    use rfq::v2::{
        NegotiationClockV2, NegotiationInstantV2, QuoteProposalV2, QuoteV2, RfqRequestV2, RfqV2,
        RouteV2,
    };
    use rfq::{PolicyId, RfqModeV1, RouteLegV1};
    use route_transport::RouteWireContextV1;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(AdapterAuthenticatedRefundFaceV2: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(AuthenticatedBitcoinPayoutFaceV1: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(AuthenticatedDomPayoutFaceV1: Clone, Copy, core::fmt::Debug);
    assert_not_impl_any!(ProductionAdapterF6TermsAuthorityV2: Clone, Copy, core::fmt::Debug);

    #[test]
    fn dom_record_has_a_pinned_canonical_shape() {
        let record =
            encode_dom_face_record(&synthetic_dom_record()).expect("fixed DOM face record");
        assert_eq!(record.len(), 834);
        assert_eq!(&record[..DOM_RECORD_DOMAIN.len()], DOM_RECORD_DOMAIN);
        assert_eq!(
            digest(PAYOUT_COMMITMENT_DOMAIN, &[&record]).expect("fixed KAT hash"),
            [
                0x2c, 0x92, 0xc8, 0x3f, 0xfd, 0x85, 0x8d, 0x46, 0x2c, 0xc2, 0x66, 0xca, 0xc1, 0x84,
                0x2f, 0xb8, 0xb5, 0x6e, 0x83, 0xd9, 0x4d, 0xd2, 0x12, 0xdf, 0x2e, 0xcd, 0x07, 0xb1,
                0x2a, 0xe1, 0x42, 0x68,
            ]
        );
    }

    #[test]
    fn dom_record_refuses_or_rebinds_every_transplant_class() {
        let base = encode_dom_face_record(&synthetic_dom_record()).expect("fixed DOM face record");
        let base_digest = digest(PAYOUT_COMMITMENT_DOMAIN, &[&base]).expect("fixed KAT hash");
        let mut mutations = Vec::new();

        let mut changed = synthetic_dom_record();
        changed.position = SettlementPositionV2::Downstream;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.direction = LegDirectionV1::UserGives;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.route_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.composition_binding_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.route_scope_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.time_policy_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.time_evidence_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.time_proof_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.time_evidence_sequence += 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.settlement_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.chain_id[0] ^= 1;
        changed.deadline.chain_id.0[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.profile_digest[0] ^= 1;
        changed.consensus_rules_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.deadline.value += 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.registry_epoch += 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.asset_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.genesis_hash[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.participant_id[0] ^= 1;
        changed.beneficiary[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.payout_commitment[1] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.payout_value += 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.owner_evidence_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_dom_record();
        changed.owner_revision += 1;
        mutations.push(changed);

        for changed in mutations {
            let changed = encode_dom_face_record(&changed).expect("valid changed DOM record");
            assert_ne!(
                digest(PAYOUT_COMMITMENT_DOMAIN, &[&changed]).expect("fixed changed hash"),
                base_digest
            );
        }

        let mut wrong_clock = synthetic_dom_record();
        wrong_clock.deadline.kind = NativeClockKindV2::TimestampSeconds;
        assert!(matches!(
            encode_dom_face_record(&wrong_clock),
            Err(ProductionF6ErrorV2::InvalidTerms)
        ));
        let mut wrong_owner = synthetic_dom_record();
        wrong_owner.participant_id[0] ^= 1;
        assert!(matches!(
            encode_dom_face_record(&wrong_owner),
            Err(ProductionF6ErrorV2::InvalidTerms)
        ));
        let mut wrong_value = synthetic_dom_record();
        wrong_value.payout_value = 0;
        assert!(matches!(
            encode_dom_face_record(&wrong_value),
            Err(ProductionF6ErrorV2::InvalidTerms)
        ));
        let mut unauthenticated = synthetic_dom_record();
        unauthenticated.owner_evidence_digest = ZERO_DIGEST;
        assert!(matches!(
            encode_dom_face_record(&unauthenticated),
            Err(ProductionF6ErrorV2::InvalidTerms)
        ));
    }

    #[test]
    fn concrete_terms_authority_orders_faces_by_the_authenticated_route_and_is_one_shot() {
        for (position, dom_first) in [
            (SettlementPositionV2::Upstream, false),
            (SettlementPositionV2::Downstream, true),
        ] {
            let (binding, rfq, quote, mut authority) = authority_fixture(position, dom_first);
            let authenticated = authority
                .authenticate_terms(&binding, &rfq, &quote)
                .expect("coherent authenticated faces advance exactly once");
            for (face, leg) in authenticated.terms.faces.iter().zip(rfq.route.legs) {
                assert_eq!(face.chain_id, leg.chain_id);
                assert_eq!(face.direction, leg.direction);
            }
            assert_eq!(authenticated.evidence_revision, 3 + 5 + 7);
            assert_ne!(authenticated.evidence_digest, ZERO_DIGEST);
            assert!(matches!(
                authority.authenticate_terms(&binding, &rfq, &quote),
                Err(ProductionF6ErrorV2::TermsUnavailable)
            ));
        }
    }

    #[test]
    fn concrete_terms_authority_refuses_face_and_scope_transplants_before_consumption() {
        for mutation in 0..9 {
            let (binding, rfq, quote, mut authority) =
                authority_fixture(SettlementPositionV2::Upstream, false);
            match mutation {
                0 => {
                    authority
                        .dom
                        .as_mut()
                        .expect("fixture DOM face")
                        .face
                        .direction = LegDirectionV1::UserGives
                }
                1 => {
                    authority
                        .dom
                        .as_mut()
                        .expect("fixture DOM face")
                        .face
                        .chain_id
                        .0[0] ^= 1
                }
                2 => {
                    authority
                        .counterparty
                        .as_mut()
                        .expect("fixture counterparty face")
                        .face
                        .refund_deadline
                        .value += 1
                }
                3 => {
                    authority
                        .counterparty
                        .as_mut()
                        .expect("fixture counterparty face")
                        .face
                        .payout_commitment = ZERO_DIGEST
                }
                4 => {
                    authority
                        .dom
                        .as_mut()
                        .expect("fixture DOM face")
                        .evidence_digest = ZERO_DIGEST
                }
                5 => {
                    authority
                        .counterparty
                        .as_mut()
                        .expect("fixture counterparty face")
                        .evidence_revision = 0
                }
                6 => authority.composition_binding_digest[0] ^= 1,
                7 => authority.time_evidence_sequence = 0,
                8 => {
                    authority
                        .counterparty
                        .as_mut()
                        .expect("fixture counterparty face")
                        .evidence_revision = u64::MAX
                }
                _ => unreachable!(),
            }
            assert!(matches!(
                authority.authenticate_terms(&binding, &rfq, &quote),
                Err(ProductionF6ErrorV2::InvalidTerms)
            ));
            assert!(authority.dom.is_some());
            assert!(authority.counterparty.is_some());
        }
    }

    #[test]
    fn concrete_terms_authority_refuses_binding_quote_and_position_transplants() {
        let (_binding, rfq, quote, mut authority) =
            authority_fixture(SettlementPositionV2::Upstream, false);
        let (foreign_binding, _, _, _) = authority_fixture(SettlementPositionV2::Downstream, false);
        assert!(matches!(
            authority.authenticate_terms(&foreign_binding, &rfq, &quote),
            Err(ProductionF6ErrorV2::InvalidTerms | ProductionF6ErrorV2::InvalidBinding)
        ));
        assert!(authority.dom.is_some());

        let (binding, rfq, quote, mut authority) =
            authority_fixture(SettlementPositionV2::Upstream, false);
        let foreign_quote = QuoteV2::create(QuoteProposalV2 {
            rfq_id: rfq.rfq_id,
            solver: quote.solver,
            route: quote.route,
            net_output: quote.net_output - 1,
            total_input: quote.total_input,
            total_fee: quote.total_fee + 1,
            execution_deadline: quote.execution_deadline,
            bond_reservation_id: quote.bond_reservation_id,
            bond_policy_version: quote.bond_policy_version,
            expiry: quote.expiry,
            solver_signature: quote.solver_signature,
        })
        .expect("foreign quote remains structurally valid");
        assert!(matches!(
            authority.authenticate_terms(&binding, &rfq, &foreign_quote),
            Err(ProductionF6ErrorV2::InvalidTerms)
        ));
        assert!(authority.dom.is_some());
    }

    #[test]
    fn evm_record_commitment_is_sensitive_to_every_face_scope_class() {
        let base = synthetic_record(
            SettlementPositionV2::Upstream,
            LegDirectionV1::UserGives,
            [0x11; 32],
            NativeClockKindV2::TimestampSeconds,
            1_000,
            [0x21; 20],
        );
        let base_digest = digest(PAYOUT_COMMITMENT_DOMAIN, &[&base]).expect("fixed KAT hashes");
        for changed in [
            synthetic_record(
                SettlementPositionV2::Downstream,
                LegDirectionV1::UserGives,
                [0x11; 32],
                NativeClockKindV2::TimestampSeconds,
                1_000,
                [0x21; 20],
            ),
            synthetic_record(
                SettlementPositionV2::Upstream,
                LegDirectionV1::UserReceives,
                [0x11; 32],
                NativeClockKindV2::TimestampSeconds,
                1_000,
                [0x21; 20],
            ),
            synthetic_record(
                SettlementPositionV2::Upstream,
                LegDirectionV1::UserGives,
                [0x12; 32],
                NativeClockKindV2::TimestampSeconds,
                1_000,
                [0x21; 20],
            ),
            synthetic_record(
                SettlementPositionV2::Upstream,
                LegDirectionV1::UserGives,
                [0x11; 32],
                NativeClockKindV2::BlockHeight,
                1_000,
                [0x21; 20],
            ),
            synthetic_record(
                SettlementPositionV2::Upstream,
                LegDirectionV1::UserGives,
                [0x11; 32],
                NativeClockKindV2::TimestampSeconds,
                1_001,
                [0x21; 20],
            ),
            synthetic_record(
                SettlementPositionV2::Upstream,
                LegDirectionV1::UserGives,
                [0x11; 32],
                NativeClockKindV2::TimestampSeconds,
                1_000,
                [0x22; 20],
            ),
        ] {
            assert_ne!(
                digest(PAYOUT_COMMITMENT_DOMAIN, &[&changed]).expect("fixed KAT hashes"),
                base_digest
            );
        }
    }

    #[test]
    fn bitcoin_record_has_a_pinned_canonical_commitment() {
        let record = encode_bitcoin_face_record(&synthetic_bitcoin_record())
            .expect("fixed Bitcoin face record");
        assert_eq!(record.len(), 670);
        assert_eq!(&record[..BTC_RECORD_DOMAIN.len()], BTC_RECORD_DOMAIN);
        assert_eq!(
            digest(PAYOUT_COMMITMENT_DOMAIN, &[&record]).expect("fixed KAT hash"),
            [
                0xc0, 0x88, 0x42, 0x30, 0x56, 0x27, 0x9b, 0x29, 0x0d, 0xc0, 0xc8, 0xaa, 0x8a, 0x05,
                0x36, 0x66, 0x1e, 0x53, 0xb7, 0x2b, 0xc3, 0x00, 0x1b, 0xc7, 0xdb, 0x68, 0x49, 0xfc,
                0x69, 0x7c, 0x95, 0x8c,
            ]
        );
    }

    #[test]
    fn bitcoin_record_refuses_or_rebinds_every_transplant_class() {
        let base = encode_bitcoin_face_record(&synthetic_bitcoin_record())
            .expect("fixed Bitcoin face record");
        let base_digest = digest(PAYOUT_COMMITMENT_DOMAIN, &[&base]).expect("fixed KAT hash");
        let mut mutations = Vec::new();

        let mut changed = synthetic_bitcoin_record();
        changed.position = SettlementPositionV2::Downstream;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.direction = LegDirectionV1::UserReceives;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.route_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.composition_binding_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.settlement_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.chain_id[0] ^= 1;
        changed.deadline.chain_id.0[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.profile_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.deadline.value += 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.registry_epoch += 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.asset_id[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.owner_route_binding[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.contract_amount_sat += 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.claim_amount_sat -= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.claim_destination_script.push(0x51);
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.claim_template_hash[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.owner_evidence_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = synthetic_bitcoin_record();
        changed.owner_revision += 1;
        mutations.push(changed);

        for changed in mutations {
            let changed = encode_bitcoin_face_record(&changed).expect("valid changed record");
            assert_ne!(
                digest(PAYOUT_COMMITMENT_DOMAIN, &[&changed]).expect("fixed changed hash"),
                base_digest
            );
        }

        let mut wrong_clock = synthetic_bitcoin_record();
        wrong_clock.deadline.kind = NativeClockKindV2::BlockHeight;
        assert!(matches!(
            encode_bitcoin_face_record(&wrong_clock),
            Err(ProductionF6ErrorV2::InvalidTerms)
        ));
        let mut mismatched_chain = synthetic_bitcoin_record();
        mismatched_chain.deadline.chain_id.0[0] ^= 1;
        assert!(matches!(
            encode_bitcoin_face_record(&mismatched_chain),
            Err(ProductionF6ErrorV2::InvalidTerms)
        ));
        let mut non_payout = synthetic_bitcoin_record();
        non_payout.claim_amount_sat = non_payout.contract_amount_sat;
        assert!(matches!(
            encode_bitcoin_face_record(&non_payout),
            Err(ProductionF6ErrorV2::InvalidTerms)
        ));
        let mut unauthenticated = synthetic_bitcoin_record();
        unauthenticated.owner_evidence_digest = ZERO_DIGEST;
        assert!(matches!(
            encode_bitcoin_face_record(&unauthenticated),
            Err(ProductionF6ErrorV2::InvalidTerms)
        ));
    }

    fn synthetic_record(
        position: SettlementPositionV2,
        direction: LegDirectionV1,
        chain: Digest32,
        deadline_kind: NativeClockKindV2,
        deadline: u64,
        payout: [u8; 20],
    ) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(EVM_RECORD_DOMAIN);
        record.push(position as u8);
        record.push(direction_tag(direction));
        record.extend_from_slice(&[0x31; 32]);
        record.extend_from_slice(&[0x32; 32]);
        record.extend_from_slice(&[0x33; 32]);
        record.extend_from_slice(&chain);
        record.extend_from_slice(&[0x34; 32]);
        record.push(deadline_kind as u8);
        record.extend_from_slice(&deadline.to_be_bytes());
        record.extend_from_slice(&payout);
        record
    }

    fn authority_fixture(
        position: SettlementPositionV2,
        dom_first: bool,
    ) -> (
        ProductionSolverF6BindingV2,
        RfqV2,
        QuoteV2,
        ProductionAdapterF6TermsAuthorityV2,
    ) {
        let dom_chain = ChainId([0x51; 32]);
        let counterparty_chain = ChainId([0x52; 32]);
        let dom_asset = AssetId([0x53; 32]);
        let counterparty_asset = AssetId([0x54; 32]);
        let initiator = ParticipantId([0x10; 32]);
        let solver = ParticipantId([0x20; 32]);
        let dom_direction = match position {
            SettlementPositionV2::Upstream => LegDirectionV1::UserReceives,
            SettlementPositionV2::Downstream => LegDirectionV1::UserGives,
        };
        let counterparty_direction = match position {
            SettlementPositionV2::Upstream => LegDirectionV1::UserGives,
            SettlementPositionV2::Downstream => LegDirectionV1::UserReceives,
        };
        let dom_route_leg = RouteLegV1 {
            chain_id: dom_chain,
            asset: dom_asset,
            direction: dom_direction,
        };
        let counterparty_route_leg = RouteLegV1 {
            chain_id: counterparty_chain,
            asset: counterparty_asset,
            direction: counterparty_direction,
        };
        let route = RouteV2 {
            composition_id: [0x55; 32],
            position,
            legs: if dom_first {
                [dom_route_leg, counterparty_route_leg]
            } else {
                [counterparty_route_leg, dom_route_leg]
            },
        };
        let clock = NegotiationClockV2 {
            chain_id: dom_chain,
            profile_digest: [0x56; 32],
            authority_scope: [0x57; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        let fee_limit = FeeLimitV1 {
            dom_max: 2,
            counterparty_max: 3,
        };
        let rfq = RfqV2::create(RfqRequestV2 {
            initiator,
            route,
            mode: RfqModeV1::ExactIn {
                input_amount: 100,
                minimum_output: 90,
            },
            fee_limit,
            negotiation_clock: clock,
            quote_deadline: NegotiationInstantV2 {
                clock,
                value: 1_200,
            },
            assurance_policy_ref: PolicyId([0x58; 32]),
            policy_version: 3,
            session_id: [0x59; 32],
        })
        .expect("fixed RFQ");
        let quote = QuoteV2::create(QuoteProposalV2 {
            rfq_id: rfq.rfq_id,
            solver,
            route,
            net_output: 95,
            total_input: 100,
            total_fee: 5,
            execution_deadline: NegotiationInstantV2 {
                clock,
                value: 1_150,
            },
            bond_reservation_id: [0x5a; 32],
            bond_policy_version: 3,
            expiry: NegotiationInstantV2 {
                clock,
                value: 1_100,
            },
            solver_signature: [0x5b; 64],
        })
        .expect("fixed quote");
        let binding = ProductionSolverF6BindingV2::new(
            RouteWireContextV1 {
                network_id: [0x5c; 32],
                session_id: rfq.session_id,
                route_id: [0x5d; 32],
                roster_snapshot: [0x5e; 32],
                policy_version: rfq.policy_version,
            },
            &rfq,
            solver,
            dom_chain,
            ProductionF6PinsV2 {
                inventory_binding_digest: [0x5f; 32],
                registry_digest: [0x60; 32],
                registry_epoch: 4,
                profile_bundle_digest: [0x61; 32],
                bond_policy_hash: [0x62; 32],
                bond_asset_binding_digest: [0x63; 32],
                required_collateral: 10,
                bond_attestation_authority_set_digest: [0x64; 32],
                remote_status_authority_set_digest: [0x65; 32],
                solver_status_scope_digest: [0x66; 32],
                pre_f6_time_scope_digest: [0x67; 32],
            },
        )
        .expect("fixed binding");
        let (dom_amount, counterparty_amount) = match position {
            SettlementPositionV2::Upstream => (quote.net_output, quote.total_input),
            SettlementPositionV2::Downstream => (quote.total_input, quote.net_output),
        };
        let (dom_beneficiary, dom_refund) = if dom_direction == LegDirectionV1::UserReceives {
            (initiator, solver)
        } else {
            (solver, initiator)
        };
        let (counterparty_beneficiary, counterparty_refund) =
            if counterparty_direction == LegDirectionV1::UserReceives {
                (initiator, solver)
            } else {
                (solver, initiator)
            };
        let settlement = SettlementTermsV1 {
            settlement_id: SettlementId(match position {
                SettlementPositionV2::Upstream => [0x68; 32],
                SettlementPositionV2::Downstream => [0x69; 32],
            }),
            session_id: SessionId(rfq.session_id),
            intent_hash: IntentHash(rfq.rfq_id),
            solver_id: SolverId(solver.0),
            roster: [initiator, solver],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: dom_chain,
                asset_id: dom_asset,
                amount: dom_amount,
                beneficiary: dom_beneficiary,
                refund_to: dom_refund,
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 900 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 3,
                    max_reorg_depth: 12,
                },
                adapter_profile_hash: [0x6a; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: counterparty_chain,
                asset_id: counterparty_asset,
                amount: counterparty_amount,
                beneficiary: counterparty_beneficiary,
                refund_to: counterparty_refund,
                mechanism: LockMechanism::ConditionLock,
                deadline: TimelockSpec::TimestampSeconds { value: 1_000 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 4,
                    max_reorg_depth: 16,
                },
                adapter_profile_hash: [0x6b; 32],
            },
            adaptor_point_sec1: [0x02; 33],
            fee_limit,
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 100,
            },
            assurance_policy_hash: Some(rfq.assurance_policy_ref.0),
            policy_version: rfq.policy_version,
            metadata: Vec::new(),
        };
        settlement.validate().expect("fixed settlement");
        let terms_hash = settlement.terms_hash().expect("fixed terms hash");
        let dom = AdapterAuthenticatedRefundFaceV2 {
            leg: AdapterFaceLegV2::Dom,
            position,
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_hash,
            face: RefundFaceV2 {
                direction: dom_direction,
                chain_id: dom_chain,
                refund_deadline: scoped_deadline(dom_chain, settlement.dom_leg.deadline)
                    .expect("fixed DOM deadline"),
                payout_commitment: [0x6c; 32],
            },
            evidence_digest: [0x6d; 32],
            evidence_revision: 3,
        };
        let counterparty = AdapterAuthenticatedRefundFaceV2 {
            leg: AdapterFaceLegV2::Counterparty,
            position,
            settlement_id: settlement.settlement_id.0,
            session_id: settlement.session_id.0,
            terms_hash,
            face: RefundFaceV2 {
                direction: counterparty_direction,
                chain_id: counterparty_chain,
                refund_deadline: scoped_deadline(
                    counterparty_chain,
                    settlement.counterparty_leg.deadline,
                )
                .expect("fixed counterparty deadline"),
                payout_commitment: [0x6e; 32],
            },
            evidence_digest: [0x6f; 32],
            evidence_revision: 5,
        };
        let authority = ProductionAdapterF6TermsAuthorityV2 {
            binding,
            settlement,
            composition_binding_digest: binding.composition_id,
            route_scope_digest: [0x70; 32],
            time_policy_digest: [0x71; 32],
            time_evidence_digest: [0x72; 32],
            time_proof_digest: [0x73; 32],
            time_evidence_sequence: 7,
            dom: Some(dom),
            counterparty: Some(counterparty),
        };
        (binding, rfq, quote, authority)
    }

    fn synthetic_bitcoin_record() -> BitcoinFaceRecordV2 {
        BitcoinFaceRecordV2 {
            position: SettlementPositionV2::Upstream,
            direction: LegDirectionV1::UserGives,
            route_id: [0x11; 32],
            composition_id: [0x12; 32],
            composition_binding_digest: [0x13; 32],
            route_scope_digest: [0x14; 32],
            settlement_id: [0x15; 32],
            session_id: [0x16; 32],
            terms_hash: [0x17; 32],
            chain_id: [0x18; 32],
            profile_digest: [0x19; 32],
            deadline: ScopedTimelockV2 {
                chain_id: kaystra_core::types::ChainId([0x18; 32]),
                kind: NativeClockKindV2::BitcoinTime512,
                value: 144,
            },
            registry_digest: [0x1a; 32],
            registry_epoch: 7,
            asset_binding_digest: [0x1b; 32],
            asset_id: [0x1c; 32],
            asset_decimals: 8,
            genesis_hash: [0x1d; 32],
            signet_challenge: vec![0x51, 0x21, 0x02, 0xae],
            max_fee_rate_sat_vbyte: 250,
            min_relay_fee_sat_kvb: 1_000,
            owner_route_binding: [0x1e; 32],
            owner_receipt_digest: [0x1f; 32],
            contract_amount_sat: 100_000,
            claim_amount_sat: 99_000,
            claim_destination_script: vec![0x51, 0x20, 0x22, 0x23],
            claim_template_hash: [0x24; 32],
            owner_evidence_digest: [0x25; 32],
            owner_revision: 1,
        }
    }

    fn synthetic_dom_record() -> DomFaceRecordV2 {
        DomFaceRecordV2 {
            position: SettlementPositionV2::Upstream,
            direction: LegDirectionV1::UserReceives,
            route_id: [0x31; 32],
            composition_id: [0x32; 32],
            composition_binding_digest: [0x32; 32],
            route_scope_digest: [0x33; 32],
            time_policy_digest: [0x34; 32],
            time_evidence_digest: [0x35; 32],
            time_proof_digest: [0x36; 32],
            time_evidence_sequence: 9,
            settlement_id: [0x37; 32],
            session_id: [0x38; 32],
            terms_hash: [0x39; 32],
            chain_id: [0x3a; 32],
            profile_digest: [0x3b; 32],
            deadline: ScopedTimelockV2 {
                chain_id: kaystra_core::types::ChainId([0x3a; 32]),
                kind: NativeClockKindV2::BlockHeight,
                value: 900,
            },
            registry_digest: [0x3c; 32],
            registry_epoch: 7,
            asset_binding_digest: [0x3d; 32],
            asset_id: [0x3e; 32],
            asset_decimals: 9,
            genesis_hash: [0x3f; 32],
            network: 1,
            network_magic: 0x4455_6677,
            protocol_version: 3,
            range_proof_serialization_version: 2,
            consensus_rules_digest: [0x3b; 32],
            scriptless_api_version: 1,
            min_block_seconds: 50,
            max_block_seconds: 70,
            max_reorg_seconds: 600,
            observation_seconds: 30,
            broadcast_seconds: 20,
            min_confirmations: 3,
            max_reorg_depth: 12,
            participant_id: [0x40; 32],
            participant_index: 0,
            beneficiary: [0x40; 32],
            refund_to: [0x41; 32],
            payout_commitment: [0x02; 33],
            payout_value: 95_000,
            owner_evidence_digest: [0x42; 32],
            owner_revision: 4,
        }
    }
}
