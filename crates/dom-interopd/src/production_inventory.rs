//! Production inventory observation, reconciliation and expiry sweep.
//!
//! This module closes the loop between the durable solver inventory and the
//! chains it promises liquidity on. Each leg owns one evidence-bound
//! observer over an already-authenticated custody surface — the DOM
//! participant wallet, the finalized EVM balance reads, the tip-pinned
//! Bitcoin Core wallet scan — and every observation carries the exact
//! registry/profile/asset digests the account was admitted under. No caller
//! supplies a balance, a height or an anchor.
//!
//! Consumption acknowledgement is proof-driven per leg: an EVM pending
//! consumption is acknowledged only by a finalized successful receipt of its
//! exact execution id, a Bitcoin one only by a genesis-rooted confirmation
//! proof, and a DOM one never advances here (the wallet's reconciled state
//! already excludes spent outputs; sequence release stays with the F6
//! terminal flow). Unproven consumptions keep their capacity encumbered —
//! the failure mode is withheld capacity, never invented solvency.
//!
//! The Monero and Solana legs plug into the same closed observer enum once
//! their observation authorities land; the reconciler and sweep are already
//! leg-agnostic.

use adapter_btc_live::{
    observe_confirmed_spendable, BitcoinCoreEvidenceCollectorV1, BitcoinCoreRpcClientV1,
};
use blake2::digest::{consts::U32, Digest as _};
use blake2::Blake2b;
use dom_actuator::DomParticipantWalletV1;
use evm_actuator::{EvmAddressV1, EvmInventoryRpcV1, EvmRpcV1};
use solver_inventory::{
    Digest32, DurableInventoryStoreV1, InventoryKeyV1, InventoryLeaseV1,
    InventoryObservationKindV1, InventoryObservationV1, InventoryObserverRequestV1,
    InventoryObserverV1, InventoryStoreErrorV1, MutationOutcomeV1, PendingConsumptionV1,
};

const OBSERVATION_OPERATION_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/INVENTORY-RECONCILE-OP/V1\0";
const EXPIRY_OPERATION_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/INVENTORY-EXPIRE-OP/V1\0";
const REORG_EVIDENCE_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/INVENTORY-REORG-EVIDENCE/V1\0";

/// Shortest observation validity a binding may declare.
const MIN_OBSERVATION_VALIDITY_MS_V1: u64 = 1_000;
/// Longest observation validity; equals the store's own hard ceiling.
const MAX_OBSERVATION_VALIDITY_MS_V1: u64 = 86_400_000;

/// Fail-closed refusal of the production inventory boundary.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ProductionInventoryErrorV1 {
    /// A binding, amount or height was outside its authenticated bounds.
    #[error("production inventory binding refused")]
    InvalidBinding,
    /// The chain observation source refused or returned unusable material.
    #[error("production inventory observation unavailable")]
    ObservationUnavailable,
    /// The durable inventory store refused the mutation.
    #[error("production inventory store refused")]
    Store(#[from] InventoryStoreErrorV1),
}

/// One account's authenticated observation context.
///
/// Every digest is produced by the admission/registry path, never by the
/// observer, so a snapshot can only ever attest the configuration the route
/// was admitted under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProductionInventoryAccountBindingV1 {
    /// Account key: frozen chain, asset and owning authority.
    pub key: InventoryKeyV1,
    /// Authenticated deployment-registry manifest digest.
    pub registry_manifest_digest: Digest32,
    /// Authenticated chain-profile bundle digest.
    pub profile_bundle_digest: Digest32,
    /// Authenticated chain/asset binding digest.
    pub asset_binding_digest: Digest32,
    /// How long one observation may authorize new quote authority.
    pub observation_validity_ms: u64,
}

impl ProductionInventoryAccountBindingV1 {
    fn validate(&self) -> Result<(), ProductionInventoryErrorV1> {
        if self.registry_manifest_digest == [0; 32]
            || self.profile_bundle_digest == [0; 32]
            || self.asset_binding_digest == [0; 32]
            || self.observation_validity_ms < MIN_OBSERVATION_VALIDITY_MS_V1
            || self.observation_validity_ms > MAX_OBSERVATION_VALIDITY_MS_V1
        {
            return Err(ProductionInventoryErrorV1::InvalidBinding);
        }
        Ok(())
    }
}

/// Raw leg-agnostic observation material before binding and successor rules.
struct ObservedBalanceV1 {
    spendable_amount: u128,
    canonical_height: u64,
    canonical_anchor_digest: Digest32,
    evidence_digest: Digest32,
    acknowledged_consumption_sequence: u64,
}

fn bind_observation(
    binding: &ProductionInventoryAccountBindingV1,
    request: &InventoryObserverRequestV1,
    observed: ObservedBalanceV1,
    now_unix_ms: u64,
) -> Result<InventoryObservationV1, ProductionInventoryErrorV1> {
    binding.validate()?;
    if binding.key != request.key || now_unix_ms == 0 {
        return Err(ProductionInventoryErrorV1::InvalidBinding);
    }
    let valid_until_unix_ms = now_unix_ms
        .checked_add(binding.observation_validity_ms)
        .ok_or(ProductionInventoryErrorV1::InvalidBinding)?;
    let kind = match &request.current {
        Some(previous)
            if observed.canonical_height < previous.canonical_height
                || (observed.canonical_height == previous.canonical_height
                    && observed.canonical_anchor_digest != previous.canonical_anchor_digest) =>
        {
            let invalidated_from_height = if observed.canonical_height < previous.canonical_height {
                observed
                    .canonical_height
                    .checked_add(1)
                    .ok_or(ProductionInventoryErrorV1::InvalidBinding)?
            } else {
                observed.canonical_height
            };
            if invalidated_from_height == 0 {
                return Err(ProductionInventoryErrorV1::ObservationUnavailable);
            }
            let mut hasher = Blake2b::<U32>::new();
            hasher.update(REORG_EVIDENCE_DOMAIN_V1);
            hasher.update(previous.canonical_height.to_be_bytes());
            hasher.update(previous.canonical_anchor_digest);
            hasher.update(observed.canonical_height.to_be_bytes());
            hasher.update(observed.canonical_anchor_digest);
            hasher.update(observed.evidence_digest);
            InventoryObservationKindV1::Reorg {
                invalidated_from_height,
                reorg_evidence_digest: hasher.finalize().into(),
            }
        }
        _ => InventoryObservationKindV1::Forward,
    };
    Ok(InventoryObservationV1 {
        key: binding.key,
        spendable_amount: observed.spendable_amount,
        canonical_height: observed.canonical_height,
        canonical_anchor_digest: observed.canonical_anchor_digest,
        evidence_digest: observed.evidence_digest,
        registry_manifest_digest: binding.registry_manifest_digest,
        profile_bundle_digest: binding.profile_bundle_digest,
        asset_binding_digest: binding.asset_binding_digest,
        observed_at_unix_ms: now_unix_ms,
        valid_until_unix_ms,
        acknowledged_consumption_sequence: observed.acknowledged_consumption_sequence,
        kind,
    })
}

/// Largest contiguously proven consumption sequence starting from `acked`.
///
/// `prove` returns whether one exact pending consumption finalized on chain.
/// A gap or an unproven entry stops the advance: sequences are only ever
/// acknowledged as a prefix, so capacity is released in commit order.
fn acknowledged_prefix<E>(
    acked: u64,
    pending: &[PendingConsumptionV1],
    mut prove: impl FnMut(&PendingConsumptionV1) -> Result<bool, E>,
) -> Result<u64, E> {
    let mut ordered: Vec<&PendingConsumptionV1> = pending.iter().collect();
    ordered.sort_by_key(|entry| entry.consumption_sequence);
    let mut acknowledged = acked;
    for entry in ordered {
        if entry.consumption_sequence <= acknowledged {
            continue;
        }
        if entry.consumption_sequence != acknowledged + 1 || !prove(entry)? {
            break;
        }
        acknowledged = entry.consumption_sequence;
    }
    Ok(acknowledged)
}

/// DOM leg: the wallet's reconciled, unreserved confirmed balance.
pub(crate) struct ProductionDomInventoryObserverV1<'wallet> {
    wallet: &'wallet DomParticipantWalletV1,
    binding: ProductionInventoryAccountBindingV1,
    now_unix_ms: u64,
}

impl<'wallet> ProductionDomInventoryObserverV1<'wallet> {
    pub(crate) fn new(
        wallet: &'wallet DomParticipantWalletV1,
        binding: ProductionInventoryAccountBindingV1,
        now_unix_ms: u64,
    ) -> Result<Self, ProductionInventoryErrorV1> {
        binding.validate()?;
        Ok(Self {
            wallet,
            binding,
            now_unix_ms,
        })
    }
}

impl InventoryObserverV1 for ProductionDomInventoryObserverV1<'_> {
    type Error = ProductionInventoryErrorV1;

    fn observe(
        &mut self,
        request: &InventoryObserverRequestV1,
    ) -> Result<InventoryObservationV1, Self::Error> {
        let observed = self
            .wallet
            .observe_confirmed_spendable()
            .map_err(|_| ProductionInventoryErrorV1::ObservationUnavailable)?;
        // DOM spends leave the confirmed balance through the wallet's own
        // reconciliation; sequences advance only with the current snapshot's
        // acknowledgement (never regress, never leap without proof).
        let acknowledged = request
            .current
            .map_or(0, |snapshot| snapshot.acknowledged_consumption_sequence);
        bind_observation(
            &self.binding,
            request,
            ObservedBalanceV1 {
                spendable_amount: u128::from(observed.spendable_value),
                canonical_height: observed.canonical_height,
                canonical_anchor_digest: observed.canonical_anchor,
                evidence_digest: observed.evidence_digest,
                acknowledged_consumption_sequence: acknowledged,
            },
            self.now_unix_ms,
        )
    }
}

/// EVM leg: finalized native or ERC-20 balance of the solver account.
pub(crate) struct ProductionEvmInventoryObserverV1<'rpc, R> {
    rpc: &'rpc mut R,
    owner: EvmAddressV1,
    token: Option<EvmAddressV1>,
    binding: ProductionInventoryAccountBindingV1,
    now_unix_ms: u64,
}

impl<'rpc, R: EvmRpcV1 + EvmInventoryRpcV1> ProductionEvmInventoryObserverV1<'rpc, R> {
    pub(crate) fn new(
        rpc: &'rpc mut R,
        owner: EvmAddressV1,
        token: Option<EvmAddressV1>,
        binding: ProductionInventoryAccountBindingV1,
        now_unix_ms: u64,
    ) -> Result<Self, ProductionInventoryErrorV1> {
        binding.validate()?;
        if owner == [0; 20] || token == Some([0; 20]) {
            return Err(ProductionInventoryErrorV1::InvalidBinding);
        }
        Ok(Self {
            rpc,
            owner,
            token,
            binding,
            now_unix_ms,
        })
    }
}

impl<R: EvmRpcV1 + EvmInventoryRpcV1> InventoryObserverV1
    for ProductionEvmInventoryObserverV1<'_, R>
{
    type Error = ProductionInventoryErrorV1;

    fn observe(
        &mut self,
        request: &InventoryObserverRequestV1,
    ) -> Result<InventoryObservationV1, Self::Error> {
        let balance = match self.token {
            Some(token) => self.rpc.finalized_token_balance(token, self.owner),
            None => self.rpc.finalized_native_balance(self.owner),
        }
        .map_err(|_| ProductionInventoryErrorV1::ObservationUnavailable)?;
        // A balance above u128 cannot be represented by the inventory and is
        // refused rather than truncated.
        if balance.amount[..16] != [0; 16] {
            return Err(ProductionInventoryErrorV1::ObservationUnavailable);
        }
        let mut spendable = [0_u8; 16];
        spendable.copy_from_slice(&balance.amount[16..]);
        let acked = request
            .current
            .map_or(0, |snapshot| snapshot.acknowledged_consumption_sequence);
        let acknowledged = acknowledged_prefix(acked, &request.pending_consumptions, |pending| {
            let lookup = self
                .rpc
                .receipt(pending.execution_id)
                .map_err(|_| ProductionInventoryErrorV1::ObservationUnavailable)?;
            Ok::<bool, ProductionInventoryErrorV1>(
                lookup
                    .receipt
                    .is_some_and(|receipt| receipt.finalized && receipt.success),
            )
        })?;
        bind_observation(
            &self.binding,
            request,
            ObservedBalanceV1 {
                spendable_amount: u128::from_be_bytes(spendable),
                canonical_height: balance.block_number,
                canonical_anchor_digest: balance.block_hash,
                evidence_digest: balance.evidence_digest,
                acknowledged_consumption_sequence: acknowledged,
            },
            self.now_unix_ms,
        )
    }
}

/// Bitcoin leg: tip-pinned confirmed spendable balance of the Core wallet.
pub(crate) struct ProductionBitcoinInventoryObserverV1<'rpc> {
    rpc: &'rpc BitcoinCoreRpcClientV1,
    minimum_confirmations: u64,
    binding: ProductionInventoryAccountBindingV1,
    now_unix_ms: u64,
}

impl<'rpc> ProductionBitcoinInventoryObserverV1<'rpc> {
    pub(crate) fn new(
        rpc: &'rpc BitcoinCoreRpcClientV1,
        minimum_confirmations: u64,
        binding: ProductionInventoryAccountBindingV1,
        now_unix_ms: u64,
    ) -> Result<Self, ProductionInventoryErrorV1> {
        binding.validate()?;
        if minimum_confirmations == 0 {
            return Err(ProductionInventoryErrorV1::InvalidBinding);
        }
        Ok(Self {
            rpc,
            minimum_confirmations,
            binding,
            now_unix_ms,
        })
    }
}

impl InventoryObserverV1 for ProductionBitcoinInventoryObserverV1<'_> {
    type Error = ProductionInventoryErrorV1;

    fn observe(
        &mut self,
        request: &InventoryObserverRequestV1,
    ) -> Result<InventoryObservationV1, Self::Error> {
        let observed = observe_confirmed_spendable(self.rpc, self.minimum_confirmations)
            .map_err(|_| ProductionInventoryErrorV1::ObservationUnavailable)?;
        let acked = request
            .current
            .map_or(0, |snapshot| snapshot.acknowledged_consumption_sequence);
        let depth = u32::try_from(self.minimum_confirmations)
            .map_err(|_| ProductionInventoryErrorV1::InvalidBinding)?;
        let collector = BitcoinCoreEvidenceCollectorV1::new(self.rpc);
        let acknowledged = acknowledged_prefix(acked, &request.pending_consumptions, |pending| {
            // A confirmation proof is a positive attestation; any failure
            // (absence, shallow depth, RPC outage) simply withholds the
            // acknowledgement.
            Ok::<bool, ProductionInventoryErrorV1>(
                collector
                    .collect_confirmed(pending.execution_id, depth)
                    .is_ok(),
            )
        })?;
        bind_observation(
            &self.binding,
            request,
            ObservedBalanceV1 {
                spendable_amount: u128::from(observed.spendable_sat),
                canonical_height: observed.canonical_height,
                canonical_anchor_digest: observed.canonical_anchor,
                evidence_digest: observed.evidence_digest,
                acknowledged_consumption_sequence: acknowledged,
            },
            self.now_unix_ms,
        )
    }
}

/// Reconciles one account: current snapshot + pending consumptions in, one
/// evidence-bound observation out, installed under snapshot CAS.
pub(crate) fn reconcile_account_v1<O>(
    store: &mut DurableInventoryStoreV1,
    lease: InventoryLeaseV1,
    observer: &mut O,
    key: InventoryKeyV1,
    now_unix_ms: u64,
) -> Result<MutationOutcomeV1, ProductionInventoryErrorV1>
where
    O: InventoryObserverV1<Error = ProductionInventoryErrorV1>,
{
    let current = match store.load_snapshot(key) {
        Ok(snapshot) => Some(snapshot),
        Err(InventoryStoreErrorV1::SnapshotNotFound) => None,
        Err(error) => return Err(error.into()),
    };
    let pending_consumptions = if current.is_some() {
        store.pending_consumptions(lease, key, now_unix_ms)?
    } else {
        Vec::new()
    };
    let request = InventoryObserverRequestV1 {
        key,
        current,
        pending_consumptions,
    };
    let observation = observer.observe(&request)?;
    let expected_revision = current.map_or(0, |snapshot| snapshot.revision);
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(OBSERVATION_OPERATION_DOMAIN_V1);
    hasher.update(key.authority_id.0);
    hasher.update(key.chain_id.0);
    hasher.update(key.asset_id.0);
    hasher.update(expected_revision.to_be_bytes());
    hasher.update(observation.evidence_digest);
    let operation_id: Digest32 = hasher.finalize().into();
    Ok(store.reconcile_snapshot(
        lease,
        expected_revision,
        operation_id,
        &observation,
        now_unix_ms,
    )?)
}

/// Releases every `Reserved` row whose expiry already passed. A concurrent
/// transition surfaces as a CAS refusal on that one row and the sweep moves
/// on; storage failures abort the sweep.
pub(crate) fn sweep_expired_reservations_v1(
    store: &mut DurableInventoryStoreV1,
    lease: InventoryLeaseV1,
    now_unix_ms: u64,
) -> Result<u64, ProductionInventoryErrorV1> {
    let expired = store.expired_reservations(lease, now_unix_ms)?;
    let mut released = 0_u64;
    for (reservation_id, revision) in expired {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(EXPIRY_OPERATION_DOMAIN_V1);
        hasher.update(reservation_id);
        hasher.update(revision.to_be_bytes());
        let operation_id: Digest32 = hasher.finalize().into();
        match store.expire_reservation(lease, revision, operation_id, reservation_id, now_unix_ms) {
            Ok(_) => {
                released = released
                    .checked_add(1)
                    .ok_or(ProductionInventoryErrorV1::InvalidBinding)?;
            }
            Err(
                InventoryStoreErrorV1::RevisionConflict
                | InventoryStoreErrorV1::InvalidReservationState
                | InventoryStoreErrorV1::ReservationNotExpired,
            ) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(released)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(sequence: u64, tag: u8) -> PendingConsumptionV1 {
        PendingConsumptionV1 {
            key: InventoryKeyV1 {
                chain_id: kaystra_core::types::ChainId([1; 32]),
                asset_id: rfq::AssetId([2; 32]),
                authority_id: kaystra_core::types::ParticipantId([3; 32]),
            },
            reservation_id: [tag; 32],
            execution_id: [tag; 32],
            execution_evidence_digest: [tag; 32],
            amount: 10,
            consumption_sequence: sequence,
        }
    }

    #[test]
    fn acknowledgement_advances_only_over_a_proven_contiguous_prefix() {
        let entries = [pending(1, 0x11), pending(2, 0x22), pending(4, 0x44)];
        // All proven: stops at the sequence gap after 2.
        let acked = acknowledged_prefix::<()>(0, &entries, |_| Ok(true)).expect("prefix");
        assert_eq!(acked, 2);
        // Second entry unproven: stops after 1.
        let acked =
            acknowledged_prefix::<()>(0, &entries, |entry| Ok(entry.consumption_sequence == 1))
                .expect("prefix");
        assert_eq!(acked, 1);
        // Already acknowledged entries are skipped, unproven successor holds.
        let acked = acknowledged_prefix::<()>(1, &entries, |_| Ok(false)).expect("prefix");
        assert_eq!(acked, 1);
        // Proof failures propagate instead of acknowledging.
        assert!(acknowledged_prefix(0, &entries, |_| Err(())).is_err());
    }

    #[test]
    fn binding_bounds_and_zero_digests_are_refused() {
        let key = InventoryKeyV1 {
            chain_id: kaystra_core::types::ChainId([1; 32]),
            asset_id: rfq::AssetId([2; 32]),
            authority_id: kaystra_core::types::ParticipantId([3; 32]),
        };
        let good = ProductionInventoryAccountBindingV1 {
            key,
            registry_manifest_digest: [4; 32],
            profile_bundle_digest: [5; 32],
            asset_binding_digest: [6; 32],
            observation_validity_ms: 60_000,
        };
        assert!(good.validate().is_ok());
        for broken in [
            ProductionInventoryAccountBindingV1 {
                registry_manifest_digest: [0; 32],
                ..good
            },
            ProductionInventoryAccountBindingV1 {
                profile_bundle_digest: [0; 32],
                ..good
            },
            ProductionInventoryAccountBindingV1 {
                asset_binding_digest: [0; 32],
                ..good
            },
            ProductionInventoryAccountBindingV1 {
                observation_validity_ms: MIN_OBSERVATION_VALIDITY_MS_V1 - 1,
                ..good
            },
            ProductionInventoryAccountBindingV1 {
                observation_validity_ms: MAX_OBSERVATION_VALIDITY_MS_V1 + 1,
                ..good
            },
        ] {
            assert!(broken.validate().is_err());
        }
    }

    #[test]
    fn regressing_height_or_switched_anchor_becomes_an_evidence_bound_reorg() {
        let key = InventoryKeyV1 {
            chain_id: kaystra_core::types::ChainId([1; 32]),
            asset_id: rfq::AssetId([2; 32]),
            authority_id: kaystra_core::types::ParticipantId([3; 32]),
        };
        let binding = ProductionInventoryAccountBindingV1 {
            key,
            registry_manifest_digest: [4; 32],
            profile_bundle_digest: [5; 32],
            asset_binding_digest: [6; 32],
            observation_validity_ms: 60_000,
        };
        let previous = solver_inventory::InventorySnapshotV1 {
            key,
            revision: 3,
            spendable_amount: 100,
            encumbered_amount: 0,
            deficit_amount: 0,
            canonical_height: 50,
            canonical_anchor_digest: [7; 32],
            evidence_digest: [8; 32],
            registry_manifest_digest: [4; 32],
            profile_bundle_digest: [5; 32],
            asset_binding_digest: [6; 32],
            observed_at_unix_ms: 1_000,
            valid_until_unix_ms: 2_000,
            issued_consumption_sequence: 0,
            acknowledged_consumption_sequence: 0,
        };
        let request = InventoryObserverRequestV1 {
            key,
            current: Some(previous),
            pending_consumptions: Vec::new(),
        };
        let material = |height, anchor| ObservedBalanceV1 {
            spendable_amount: 90,
            canonical_height: height,
            canonical_anchor_digest: anchor,
            evidence_digest: [9; 32],
            acknowledged_consumption_sequence: 0,
        };
        // Height regression: everything above the new height is invalidated.
        let observation =
            bind_observation(&binding, &request, material(40, [10; 32]), 3_000).expect("reorg");
        assert!(matches!(
            observation.kind,
            InventoryObservationKindV1::Reorg {
                invalidated_from_height: 41,
                ..
            }
        ));
        // Same height, different anchor: that exact height is invalidated.
        let observation =
            bind_observation(&binding, &request, material(50, [10; 32]), 3_000).expect("reorg");
        assert!(matches!(
            observation.kind,
            InventoryObservationKindV1::Reorg {
                invalidated_from_height: 50,
                ..
            }
        ));
        // Forward progress stays forward and inherits the binding digests.
        let observation =
            bind_observation(&binding, &request, material(51, [7; 32]), 3_000).expect("forward");
        assert!(matches!(
            observation.kind,
            InventoryObservationKindV1::Forward
        ));
        assert_eq!(observation.registry_manifest_digest, [4; 32]);
        assert_eq!(observation.valid_until_unix_ms, 63_000);
    }
}
