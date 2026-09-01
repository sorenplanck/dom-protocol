//! Durable, purpose-limited producer for local F6 bond attestations.
//!
//! The producer commits every exact signing intent before contacting any
//! signer and chains completed revisions by the preceding signed-statement
//! digest. A changed current head supersedes an unsigned pending intent in the
//! append-only journal without advancing its economic sequence. Crash recovery
//! therefore retries the exact durable digest and never silently skips a
//! revision. Signer ports authorize only the F6 bond domain; they are not
//! generic secret-key or arbitrary-digest interfaces.

use std::collections::BTreeSet;
use std::path::Path;

use btc_crypto::SecpContext;
use deployment_registry::AuthoritySetV1;
use f6_engine::candidate_book::{
    bond_reservation_authority_set_digest_v2, candidate_status_authority_set_digest_v2,
    verify_candidate_quote_delivery_v2, BondReservationAttestationRequestV2,
    BondReservationAttestationV2, BondReservationSignatureV2, CandidateQuoteDeliveryV2,
    SignedBondReservationAttestationV2,
};
use kaystra_core::types::Digest32;
use rfq::v2::QuoteV2;
use solver_inventory::QuoteInventoryCapabilityV2;
use solver_status::{
    CurrentActiveSignedSolverStatusV1, SignedSolverStatusV1, SolverOperationalStateV1,
};
use store::{ProductionAuditLimitsV1, ProductionStoreBindingV1, Store};

use super::{
    bond_collateral_total, candidate_scope, validate_status,
    ProductionF6CandidateAttestationAuthorityV2, ProductionF6ErrorV2, ProductionSolverF6BindingV2,
    ZERO_DIGEST,
};

const STORE_BINDING_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-ATTESTATION-STORE/V2\0";
const SOURCE_EVIDENCE_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-ATTESTATION-SOURCE/V2\0";
const INTENT_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-ATTESTATION-INTENT/V2\0";
const RESULT_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-ATTESTATION-RESULT/V2\0";
const SUPERSEDE_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-ATTESTATION-SUPERSEDE/V2\0";
const RESERVED_KEYS_DOMAIN: &[u8] = b"DOM-INTEROP/INTEROPD/F6-RESERVED-SIGNER-ROLES/V2\0";
const INTENT_MAGIC: &[u8; 8] = b"DOMF6AI2";
const RESULT_MAGIC: &[u8; 8] = b"DOMF6AR2";
const SUPERSEDE_MAGIC: &[u8; 8] = b"DOMF6AS2";
const FORMAT_VERSION: u16 = 2;
const INTENT_JOURNAL_KIND: u16 = 0xF611;
const RESULT_JOURNAL_KIND: u16 = 0xF612;
const SUPERSEDE_JOURNAL_KIND: u16 = 0xF613;
const MAX_ATTESTATION_LIFETIME_SECONDS: u64 = 300;
/// Maximum number of successfully signed economic revisions in one stream.
const MAX_ATTESTATION_REVISIONS: usize = 256;
/// Physical budget for intent, result and bounded supersede records. Every
/// transition that creates a pending intent reserves one remaining Result
/// row, so signer I/O cannot strand an unpersistable success at the bound. A
/// never-completed first revision can therefore contain at most 766 durable
/// Supersede records before its reserved Result row.
const MAX_ATTESTATION_JOURNAL_ROWS: usize = MAX_ATTESTATION_REVISIONS * 3;
const MAX_QUOTE_BYTES: usize = 4_096;
const MAX_ATTESTATION_BYTES: usize = 2_048;
const MAX_STATUS_BYTES: usize = 2_048;
const MAX_DELIVERY_BYTES: usize = 12_288;

/// Public-key roles which are forbidden from signing bond attestations.
///
/// The three sets must come from the authenticated Relay roster, participant
/// authority and chain-signing configuration. Keeping the categories explicit
/// prevents a caller from proving only one convenient subset.
pub(crate) struct ProductionF6ReservedSignerKeysV2 {
    relay: Vec<[u8; 32]>,
    participant: Vec<[u8; 32]>,
    chain: Vec<[u8; 32]>,
}

impl core::fmt::Debug for ProductionF6ReservedSignerKeysV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionF6ReservedSignerKeysV2([keys redacted])")
    }
}

impl ProductionF6ReservedSignerKeysV2 {
    /// Freezes the complete three-role exclusion set.
    pub(crate) fn new(
        relay: Vec<[u8; 32]>,
        participant: Vec<[u8; 32]>,
        chain: Vec<[u8; 32]>,
    ) -> Result<Self, ProductionF6ErrorV2> {
        let value = Self {
            relay,
            participant,
            chain,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ProductionF6ErrorV2> {
        if self.relay.is_empty() || self.participant.is_empty() || self.chain.is_empty() {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let mut unique = BTreeSet::new();
        for keys in [&self.relay, &self.participant, &self.chain] {
            for key in keys {
                if *key == ZERO_DIGEST || !unique.insert(*key) {
                    return Err(ProductionF6ErrorV2::InvalidBinding);
                }
            }
        }
        Ok(())
    }

    fn all(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.relay
            .iter()
            .chain(self.participant.iter())
            .chain(self.chain.iter())
    }

    fn digest(&self) -> Result<Digest32, ProductionF6ErrorV2> {
        self.validate()?;
        let mut bytes = Vec::new();
        for keys in [&self.relay, &self.participant, &self.chain] {
            bytes.extend_from_slice(
                &u16::try_from(keys.len())
                    .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?
                    .to_be_bytes(),
            );
            for key in keys {
                bytes.extend_from_slice(key);
            }
        }
        digest_parts(RESERVED_KEYS_DOMAIN, &[&bytes])
    }
}

/// Purpose-limited request sent to one independent bond-attestation signer.
///
/// It deliberately exposes no generic signing method and carries both the
/// canonical public statement and its locally recomputed digest.
pub(crate) struct PreparedF6BondAttestationSigningRequestV2 {
    signer_index: u16,
    signer_public_key: [u8; 32],
    intent_digest: Digest32,
    attestation_digest: Digest32,
    attestation_bytes: Vec<u8>,
}

impl core::fmt::Debug for PreparedF6BondAttestationSigningRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PreparedF6BondAttestationSigningRequestV2")
            .field("signer_index", &self.signer_index)
            .field("signer_public_key", &self.signer_public_key)
            .field("intent_digest", &self.intent_digest)
            .field("attestation_digest", &self.attestation_digest)
            .finish_non_exhaustive()
    }
}

impl PreparedF6BondAttestationSigningRequestV2 {
    /// Exact index in the pinned authority set.
    pub(crate) const fn signer_index(&self) -> u16 {
        self.signer_index
    }

    /// Pinned BIP340 public key for this signer.
    pub(crate) const fn signer_public_key(&self) -> [u8; 32] {
        self.signer_public_key
    }

    /// Durable intent digest committed before signer I/O.
    pub(crate) const fn intent_digest(&self) -> Digest32 {
        self.intent_digest
    }

    /// Domain-separated digest the signer is authorized to sign.
    pub(crate) const fn attestation_digest(&self) -> Digest32 {
        self.attestation_digest
    }

    /// Canonical public F6 bond statement for policy inspection by the signer.
    pub(crate) fn attestation_bytes(&self) -> &[u8] {
        &self.attestation_bytes
    }
}

/// Purpose-limited response from one independent signer.
pub(crate) struct ProductionF6BondAttestationSignatureV2 {
    signer_index: u16,
    intent_digest: Digest32,
    attestation_digest: Digest32,
    signature: [u8; 64],
}

impl ProductionF6BondAttestationSignatureV2 {
    /// Constructs the exact response envelope returned by an HSM/remote signer.
    pub(crate) const fn new(
        signer_index: u16,
        intent_digest: Digest32,
        attestation_digest: Digest32,
        signature: [u8; 64],
    ) -> Self {
        Self {
            signer_index,
            intent_digest,
            attestation_digest,
            signature,
        }
    }
}

/// Narrow error surface for an independent signer transport/HSM boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProductionF6BondSignerErrorV2 {
    /// The independent signer was not reachable for this attempt.
    Unavailable,
    /// The signer explicitly refused this F6 bond statement.
    Refused,
}

/// Independent, purpose-limited signer port. It cannot sign arbitrary bytes.
pub(crate) trait ProductionF6BondAttestationSignerV2: super::source_seal::Sealed {
    /// Stable independent HSM/service identity, distinct from the signing key.
    fn independent_authority_id(&self) -> Digest32;

    /// Exact authority-set index owned by this independent signer.
    fn signer_index(&self) -> u16;

    /// Exact pinned BIP340 public key owned by this independent signer.
    fn signer_public_key(&self) -> [u8; 32];

    /// Signs only a prepared F6 bond-attestation request.
    fn sign_bond_attestation(
        &mut self,
        request: &PreparedF6BondAttestationSigningRequestV2,
    ) -> Result<ProductionF6BondAttestationSignatureV2, ProductionF6BondSignerErrorV2>;
}

struct PersistedAttestationIntentV2 {
    quote: QuoteV2,
    attestation: BondReservationAttestationV2,
    signed_status: SignedSolverStatusV1,
    digest: Digest32,
}

impl core::fmt::Debug for PersistedAttestationIntentV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PersistedAttestationIntentV2")
            .field("quote_id", &self.quote.quote_id)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

struct CompletedAttestationV2 {
    intent: PersistedAttestationIntentV2,
    delivery: CandidateQuoteDeliveryV2,
    attestation_digest: Digest32,
}

enum ReplayedAttestationStateV2 {
    Empty,
    Pending {
        previous: Option<Box<CompletedAttestationV2>>,
        intent: Box<PersistedAttestationIntentV2>,
        seen_intent_digests: BTreeSet<Digest32>,
        signed_history: Vec<CandidateQuoteDeliveryV2>,
    },
    Complete {
        head: Box<CompletedAttestationV2>,
        signed_history: Vec<CandidateQuoteDeliveryV2>,
    },
}

/// Strict durable producer for one local F6 candidate attestation stream.
pub(crate) struct ProductionF6CandidateAttestationAuthorityStoreV2 {
    binding: ProductionSolverF6BindingV2,
    store: Store,
    bond_authorities: AuthoritySetV1,
    status_authorities: AuthoritySetV1,
    secp: SecpContext,
    signers: Vec<Box<dyn ProductionF6BondAttestationSignerV2>>,
}

impl core::fmt::Debug for ProductionF6CandidateAttestationAuthorityStoreV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .write_str("ProductionF6CandidateAttestationAuthorityStoreV2([authorities redacted])")
    }
}

#[derive(Clone, Copy)]
enum StoreOpenModeV2 {
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    Create,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    Open,
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    Resume,
    Prepared(Digest32),
}

/// Move-only signer and verifier bundle for one attestation Store opening.
pub(crate) struct ProductionF6CandidateAuthorityInputsV2 {
    bond_authorities: AuthoritySetV1,
    status_authorities: AuthoritySetV1,
    reserved_keys: ProductionF6ReservedSignerKeysV2,
    secp: SecpContext,
    signers: Vec<Box<dyn ProductionF6BondAttestationSignerV2>>,
}

impl ProductionF6CandidateAuthorityInputsV2 {
    /// Bundles the independently pinned authorities without opening storage.
    pub(crate) fn new(
        bond_authorities: AuthoritySetV1,
        status_authorities: AuthoritySetV1,
        reserved_keys: ProductionF6ReservedSignerKeysV2,
        secp: SecpContext,
        signers: Vec<Box<dyn ProductionF6BondAttestationSignerV2>>,
    ) -> Self {
        Self {
            bond_authorities,
            status_authorities,
            reserved_keys,
            secp,
            signers,
        }
    }
}

impl ProductionF6CandidateAttestationAuthorityStoreV2 {
    /// Creates a pristine durable attestation producer.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn create_production(
        path: &Path,
        binding: ProductionSolverF6BindingV2,
        inputs: ProductionF6CandidateAuthorityInputsV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(path, binding, inputs, StoreOpenModeV2::Create)
    }

    /// Opens an existing complete producer and verifies its entire journal.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "retained surface not yet wired by the stage-7 composition root"
        )
    )]
    pub(crate) fn open_production(
        path: &Path,
        binding: ProductionSolverF6BindingV2,
        inputs: ProductionF6CandidateAuthorityInputsV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(path, binding, inputs, StoreOpenModeV2::Open)
    }

    /// Resumes only a globally authorized pristine Store creation prefix.
    #[expect(
        dead_code,
        reason = "retained surface not yet wired by the stage-7 composition root"
    )]
    pub(crate) fn resume_create_production(
        path: &Path,
        binding: ProductionSolverF6BindingV2,
        inputs: ProductionF6CandidateAuthorityInputsV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(path, binding, inputs, StoreOpenModeV2::Resume)
    }

    /// Opens retained producer state or completes the exact externally
    /// journalled lazy-binding prefix after both authenticated RFQs fix this
    /// position's final F6 binding.
    pub(crate) fn open_or_resume_prepared_production(
        path: &Path,
        preparation_digest: Digest32,
        binding: ProductionSolverF6BindingV2,
        inputs: ProductionF6CandidateAuthorityInputsV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        Self::open_with_mode(
            path,
            binding,
            inputs,
            StoreOpenModeV2::Prepared(preparation_digest),
        )
    }

    fn open_with_mode(
        path: &Path,
        binding: ProductionSolverF6BindingV2,
        mut inputs: ProductionF6CandidateAuthorityInputsV2,
        mode: StoreOpenModeV2,
    ) -> Result<Self, ProductionF6ErrorV2> {
        validate_authority_inputs(binding, &inputs)?;
        inputs.signers.sort_by_key(|signer| signer.signer_index());
        validate_signer_ports(&inputs.bond_authorities, &inputs.signers)?;
        let store_binding = attestation_store_binding(
            binding,
            &inputs.bond_authorities,
            &inputs.status_authorities,
            &inputs.reserved_keys,
            &inputs.signers,
        )?;
        let store = match mode {
            StoreOpenModeV2::Create => Store::create_production(path, store_binding),
            StoreOpenModeV2::Open => Store::open_production(path, store_binding),
            StoreOpenModeV2::Resume => Store::resume_create_production(path, store_binding),
            StoreOpenModeV2::Prepared(preparation_digest) => {
                let preparation = ProductionStoreBindingV1::new(preparation_digest)
                    .map_err(|_| ProductionF6ErrorV2::CandidateAttestationUnavailable)?;
                Store::open_or_resume_prepared_production(path, preparation, store_binding)
            }
        }
        .map_err(|_| ProductionF6ErrorV2::CandidateAttestationUnavailable)?;
        let mut value = Self {
            binding,
            store,
            bond_authorities: inputs.bond_authorities,
            status_authorities: inputs.status_authorities,
            secp: inputs.secp,
            signers: inputs.signers,
        };
        value.replay()?;
        Ok(value)
    }

    fn replay(&mut self) -> Result<ReplayedAttestationStateV2, ProductionF6ErrorV2> {
        let limits = ProductionAuditLimitsV1::new(
            u64::try_from(MAX_ATTESTATION_JOURNAL_ROWS)
                .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?,
            12_582_912,
            16_384,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        let snapshot = self
            .store
            .production_audit_snapshot(limits)
            .map_err(|_| ProductionF6ErrorV2::CandidateAttestationUnavailable)?;
        if !snapshot.opaque_records().is_empty() || !snapshot.revisions().is_empty() {
            return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
        }
        if snapshot.journal().is_empty() {
            return Ok(ReplayedAttestationStateV2::Empty);
        }
        let mut completed: Option<CompletedAttestationV2> = None;
        let mut pending: Option<PersistedAttestationIntentV2> = None;
        let mut intent_digests = BTreeSet::new();
        let mut signed_history = Vec::new();
        for (index, record) in snapshot.journal().iter().enumerate() {
            let expected_store_sequence = u64::try_from(index)
                .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?
                .checked_add(1)
                .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
            if record.sequence() != expected_store_sequence {
                return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
            }
            match pending.take() {
                None if record.kind() == INTENT_JOURNAL_KIND => {
                    let intent = decode_intent(record.payload())?;
                    if !intent_digests.insert(intent.digest) {
                        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
                    }
                    validate_intent_link(completed.as_ref(), &intent)?;
                    validate_persistable_intent(
                        self.binding,
                        &intent,
                        &self.status_authorities,
                        &self.secp,
                    )?;
                    pending = Some(intent);
                }
                Some(intent) if record.kind() == RESULT_JOURNAL_KIND => {
                    let delivery = decode_result(record.payload(), intent.digest)?;
                    validate_delivery_matches_intent(&intent, &delivery)?;
                    verify_candidate_quote_delivery_v2(
                        &delivery,
                        candidate_scope(self.binding),
                        &self.bond_authorities,
                        &self.status_authorities,
                        &self.secp,
                        intent.attestation.request().observed_at_seconds,
                    )
                    .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
                    let attestation_digest = delivery
                        .attestation()
                        .attestation()
                        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?
                        .attestation_digest()
                        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
                    signed_history.push(delivery.clone());
                    completed = Some(CompletedAttestationV2 {
                        intent,
                        delivery,
                        attestation_digest,
                    });
                }
                Some(intent) if record.kind() == SUPERSEDE_JOURNAL_KIND => {
                    let replacement = decode_supersede(record.payload(), intent.digest)?;
                    if !intent_digests.insert(replacement.digest) {
                        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
                    }
                    validate_intent_link(completed.as_ref(), &replacement)?;
                    validate_compatible_refresh(&intent, &replacement)?;
                    if require_same_intent(&intent, &replacement).is_ok() {
                        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
                    }
                    validate_persistable_intent(
                        self.binding,
                        &replacement,
                        &self.status_authorities,
                        &self.secp,
                    )?;
                    pending = Some(replacement);
                }
                _ => return Err(ProductionF6ErrorV2::InvalidCandidateAttestation),
            }
        }
        match (completed, pending) {
            (None, Some(intent)) => Ok(ReplayedAttestationStateV2::Pending {
                previous: None,
                intent: Box::new(intent),
                seen_intent_digests: intent_digests,
                signed_history,
            }),
            (Some(previous), Some(intent)) => Ok(ReplayedAttestationStateV2::Pending {
                previous: Some(Box::new(previous)),
                intent: Box::new(intent),
                seen_intent_digests: intent_digests,
                signed_history,
            }),
            (Some(head), None) => Ok(ReplayedAttestationStateV2::Complete {
                head: Box::new(head),
                signed_history,
            }),
            (None, None) => Err(ProductionF6ErrorV2::InvalidCandidateAttestation),
        }
    }

    fn persist_new_intent(
        &mut self,
        intent: &PersistedAttestationIntentV2,
    ) -> Result<(), ProductionF6ErrorV2> {
        self.ensure_journal_capacity(2)?;
        self.store
            .append_journal(INTENT_JOURNAL_KIND, &encode_intent(intent)?)
            .map_err(|_| ProductionF6ErrorV2::CandidateAttestationUnavailable)?;
        Ok(())
    }

    fn persist_result(
        &mut self,
        intent_digest: Digest32,
        delivery: &CandidateQuoteDeliveryV2,
    ) -> Result<(), ProductionF6ErrorV2> {
        self.ensure_journal_capacity(1)?;
        self.store
            .append_journal(
                RESULT_JOURNAL_KIND,
                &encode_result(intent_digest, delivery)?,
            )
            .map_err(|_| ProductionF6ErrorV2::CandidateAttestationUnavailable)?;
        Ok(())
    }

    fn persist_supersede(
        &mut self,
        pending: &PersistedAttestationIntentV2,
        replacement: &PersistedAttestationIntentV2,
    ) -> Result<(), ProductionF6ErrorV2> {
        self.ensure_journal_capacity(2)?;
        self.store
            .append_journal(
                SUPERSEDE_JOURNAL_KIND,
                &encode_supersede(pending.digest, replacement)?,
            )
            .map_err(|_| ProductionF6ErrorV2::CandidateAttestationUnavailable)?;
        Ok(())
    }

    fn ensure_journal_capacity(&self, required_rows: usize) -> Result<(), ProductionF6ErrorV2> {
        let rows = self
            .store
            .read_journal()
            .map_err(|_| ProductionF6ErrorV2::CandidateAttestationUnavailable)?;
        if !journal_capacity_allows(rows.len(), required_rows) {
            return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
        }
        Ok(())
    }

    fn sign_pending_intent(
        &mut self,
        intent: &PersistedAttestationIntentV2,
        trusted_now_seconds: u64,
    ) -> Result<CandidateQuoteDeliveryV2, ProductionF6ErrorV2> {
        let statement = intent.attestation.request();
        if trusted_now_seconds == 0
            || statement.observed_at_seconds > trusted_now_seconds
            || trusted_now_seconds >= statement.valid_until_seconds
        {
            return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
        }
        let attestation_digest = intent
            .attestation
            .attestation_digest()
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        let attestation_bytes = intent
            .attestation
            .canonical_bytes()
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        let mut signatures = Vec::new();
        for signer in &mut self.signers {
            let signer_index = signer.signer_index();
            let key = *self
                .bond_authorities
                .xonly_keys()
                .get(usize::from(signer_index))
                .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
            let request = PreparedF6BondAttestationSigningRequestV2 {
                signer_index,
                signer_public_key: key,
                intent_digest: intent.digest,
                attestation_digest,
                attestation_bytes: attestation_bytes.clone(),
            };
            let response = match signer.sign_bond_attestation(&request) {
                Ok(response) => response,
                Err(ProductionF6BondSignerErrorV2::Unavailable) => continue,
                Err(ProductionF6BondSignerErrorV2::Refused) => {
                    return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
                }
            };
            if response.signer_index != signer_index
                || response.intent_digest != intent.digest
                || response.attestation_digest != attestation_digest
                || self
                    .secp
                    .verify_bip340(&key, &attestation_digest, &response.signature)
                    .is_err()
            {
                return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
            }
            signatures.push(BondReservationSignatureV2 {
                signer_index,
                signature: response.signature,
            });
        }
        if signatures.len() < usize::from(self.bond_authorities.threshold()) {
            return Err(ProductionF6ErrorV2::CandidateAttestationUnavailable);
        }
        let signed = SignedBondReservationAttestationV2::new(intent.attestation, signatures)
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        let delivery =
            CandidateQuoteDeliveryV2::new(intent.quote, signed, intent.signed_status.clone())
                .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        verify_candidate_quote_delivery_v2(
            &delivery,
            candidate_scope(self.binding),
            &self.bond_authorities,
            &self.status_authorities,
            &self.secp,
            trusted_now_seconds,
        )
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        validate_delivery_matches_intent(intent, &delivery)?;
        self.persist_result(intent.digest, &delivery)?;
        Ok(delivery)
    }

    fn attest_prepared(
        &mut self,
        proposed: PersistedAttestationIntentV2,
        trusted_now_seconds: u64,
    ) -> Result<CandidateQuoteDeliveryV2, ProductionF6ErrorV2> {
        match self.replay()? {
            ReplayedAttestationStateV2::Empty => {
                validate_intent_link(None, &proposed)?;
                validate_persistable_intent(
                    self.binding,
                    &proposed,
                    &self.status_authorities,
                    &self.secp,
                )?;
                self.persist_new_intent(&proposed)?;
                self.sign_pending_intent(&proposed, trusted_now_seconds)
            }
            ReplayedAttestationStateV2::Pending {
                previous,
                intent,
                seen_intent_digests,
                ..
            } => {
                if require_same_intent(&intent, &proposed).is_ok() {
                    return self.sign_pending_intent(&intent, trusted_now_seconds);
                }
                if seen_intent_digests.contains(&proposed.digest) {
                    return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
                }
                validate_intent_link(previous.as_deref(), &proposed)?;
                validate_compatible_refresh(&intent, &proposed)?;
                validate_persistable_intent(
                    self.binding,
                    &proposed,
                    &self.status_authorities,
                    &self.secp,
                )?;
                self.persist_supersede(&intent, &proposed)?;
                self.sign_pending_intent(&proposed, trusted_now_seconds)
            }
            ReplayedAttestationStateV2::Complete { head, .. } => {
                if require_same_intent(&head.intent, &proposed).is_ok() {
                    if trusted_now_seconds == 0
                        || trusted_now_seconds
                            >= head.intent.attestation.request().valid_until_seconds
                    {
                        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
                    }
                    return Ok(head.delivery.clone());
                }
                validate_intent_link(Some(&head), &proposed)?;
                validate_compatible_refresh(&head.intent, &proposed)?;
                validate_persistable_intent(
                    self.binding,
                    &proposed,
                    &self.status_authorities,
                    &self.secp,
                )?;
                self.persist_new_intent(&proposed)?;
                self.sign_pending_intent(&proposed, trusted_now_seconds)
            }
        }
    }
}

fn journal_capacity_allows(existing_rows: usize, required_rows: usize) -> bool {
    required_rows != 0
        && existing_rows
            .checked_add(required_rows)
            .is_some_and(|rows| rows <= MAX_ATTESTATION_JOURNAL_ROWS)
}

fn validate_economic_sequence(
    sequence: u64,
    previous_attestation_digest: Digest32,
) -> Result<(), ProductionF6ErrorV2> {
    if sequence == 0
        || (sequence == 1 && previous_attestation_digest != ZERO_DIGEST)
        || (sequence > 1 && previous_attestation_digest == ZERO_DIGEST)
        || usize::try_from(sequence)
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?
            > MAX_ATTESTATION_REVISIONS
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(())
}

impl super::source_seal::Sealed for ProductionF6CandidateAttestationAuthorityStoreV2 {}

impl ProductionF6CandidateAttestationAuthorityV2
    for ProductionF6CandidateAttestationAuthorityStoreV2
{
    fn signed_candidate_history(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
    ) -> Result<Vec<CandidateQuoteDeliveryV2>, ProductionF6ErrorV2> {
        if *binding != self.binding {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        match self.replay()? {
            ReplayedAttestationStateV2::Empty => Ok(Vec::new()),
            ReplayedAttestationStateV2::Pending { signed_history, .. }
            | ReplayedAttestationStateV2::Complete { signed_history, .. } => Ok(signed_history),
        }
    }

    fn attest_local_candidate(
        &mut self,
        binding: &ProductionSolverF6BindingV2,
        quote: &QuoteV2,
        inventory: &QuoteInventoryCapabilityV2,
        status: &CurrentActiveSignedSolverStatusV1,
        trusted_now_seconds: u64,
    ) -> Result<CandidateQuoteDeliveryV2, ProductionF6ErrorV2> {
        if *binding != self.binding {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        let proposed = match self.replay()? {
            ReplayedAttestationStateV2::Empty => derive_intent(
                self.binding,
                quote,
                inventory,
                status,
                trusted_now_seconds,
                1,
                ZERO_DIGEST,
            )?,
            ReplayedAttestationStateV2::Pending { intent, .. } => {
                let request = intent.attestation.request();
                let exact_current = derive_intent(
                    self.binding,
                    quote,
                    inventory,
                    status,
                    request.observed_at_seconds,
                    request.sequence,
                    request.previous_attestation_digest,
                )?;
                if require_same_intent(&intent, &exact_current).is_ok()
                    && trusted_now_seconds < request.valid_until_seconds
                {
                    exact_current
                } else {
                    derive_intent(
                        self.binding,
                        quote,
                        inventory,
                        status,
                        trusted_now_seconds,
                        request.sequence,
                        request.previous_attestation_digest,
                    )?
                }
            }
            ReplayedAttestationStateV2::Complete { head, .. } => {
                let request = head.intent.attestation.request();
                let exact_current = derive_intent(
                    self.binding,
                    quote,
                    inventory,
                    status,
                    request.observed_at_seconds,
                    request.sequence,
                    request.previous_attestation_digest,
                )?;
                if require_same_intent(&head.intent, &exact_current).is_ok()
                    && trusted_now_seconds < request.valid_until_seconds
                {
                    exact_current
                } else {
                    derive_intent(
                        self.binding,
                        quote,
                        inventory,
                        status,
                        trusted_now_seconds,
                        request
                            .sequence
                            .checked_add(1)
                            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?,
                        head.attestation_digest,
                    )?
                }
            }
        };
        self.attest_prepared(proposed, trusted_now_seconds)
    }
}

fn validate_authority_inputs(
    binding: ProductionSolverF6BindingV2,
    inputs: &ProductionF6CandidateAuthorityInputsV2,
) -> Result<(), ProductionF6ErrorV2> {
    binding.validate()?;
    inputs.reserved_keys.validate()?;
    if inputs.bond_authorities.xonly_keys().len() < 2
        || inputs.bond_authorities.threshold() < 2
        || usize::from(inputs.bond_authorities.threshold())
            > inputs.bond_authorities.xonly_keys().len()
        || bond_reservation_authority_set_digest_v2(&inputs.bond_authorities, &inputs.secp)
            .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?
            != binding.pins.bond_attestation_authority_set_digest
        || candidate_status_authority_set_digest_v2(&inputs.status_authorities, &inputs.secp)
            .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?
            != binding.pins.remote_status_authority_set_digest
        || inputs.status_authorities.xonly_keys().len() < 2
        || inputs.status_authorities.threshold() < 2
        || usize::from(inputs.status_authorities.threshold())
            > inputs.status_authorities.xonly_keys().len()
    {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    let status_keys: BTreeSet<_> = inputs
        .status_authorities
        .xonly_keys()
        .iter()
        .copied()
        .collect();
    let reserved_keys: BTreeSet<_> = inputs.reserved_keys.all().copied().collect();
    if inputs.bond_authorities.xonly_keys().iter().any(|key| {
        status_keys.contains(key)
            || reserved_keys.contains(key)
            || *key == binding.initiator.0
            || *key == binding.solver.0
    }) {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    if inputs.status_authorities.xonly_keys().iter().any(|key| {
        reserved_keys.contains(key) || *key == binding.initiator.0 || *key == binding.solver.0
    }) {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    Ok(())
}

fn validate_signer_ports(
    authorities: &AuthoritySetV1,
    signers: &[Box<dyn ProductionF6BondAttestationSignerV2>],
) -> Result<(), ProductionF6ErrorV2> {
    if signers.len() != authorities.xonly_keys().len() {
        return Err(ProductionF6ErrorV2::InvalidBinding);
    }
    let mut previous = None;
    let mut independent_ids = BTreeSet::new();
    for signer in signers {
        let index = signer.signer_index();
        let independent_id = signer.independent_authority_id();
        if previous.is_some_and(|value| value >= index)
            || independent_id == ZERO_DIGEST
            || !independent_ids.insert(independent_id)
            || authorities.xonly_keys().get(usize::from(index)).copied()
                != Some(signer.signer_public_key())
        {
            return Err(ProductionF6ErrorV2::InvalidBinding);
        }
        previous = Some(index);
    }
    Ok(())
}

fn attestation_store_binding(
    binding: ProductionSolverF6BindingV2,
    bond: &AuthoritySetV1,
    status: &AuthoritySetV1,
    reserved: &ProductionF6ReservedSignerKeysV2,
    signers: &[Box<dyn ProductionF6BondAttestationSignerV2>],
) -> Result<ProductionStoreBindingV1, ProductionF6ErrorV2> {
    let bond_bytes = bond
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?;
    let status_bytes = status
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?;
    let reserved_digest = reserved.digest()?;
    let mut signer_instances = Vec::new();
    for signer in signers {
        signer_instances.extend_from_slice(&signer.signer_index().to_be_bytes());
        signer_instances.extend_from_slice(&signer.independent_authority_id());
    }
    let digest = digest_parts(
        STORE_BINDING_DOMAIN,
        &[
            &binding.authority_digest(STORE_BINDING_DOMAIN)?,
            &bond_bytes,
            &status_bytes,
            &reserved_digest,
            &signer_instances,
        ],
    )?;
    ProductionStoreBindingV1::new(digest).map_err(|_| ProductionF6ErrorV2::InvalidBinding)
}

fn derive_intent(
    binding: ProductionSolverF6BindingV2,
    quote: &QuoteV2,
    inventory: &QuoteInventoryCapabilityV2,
    status: &CurrentActiveSignedSolverStatusV1,
    trusted_now_seconds: u64,
    sequence: u64,
    previous_attestation_digest: Digest32,
) -> Result<PersistedAttestationIntentV2, ProductionF6ErrorV2> {
    if trusted_now_seconds == 0 {
        return Err(ProductionF6ErrorV2::ClockUnavailable);
    }
    validate_economic_sequence(sequence, previous_attestation_digest)?;
    quote
        .validate()
        .map_err(|_| ProductionF6ErrorV2::InvalidPayload)?;
    if quote.rfq_id != binding.rfq_id
        || quote.solver != binding.solver
        || quote.route.composition_id != binding.composition_id
        || quote.route.position != binding.position
        || quote.bond_reservation_id != inventory.reservation_id()
        || inventory.composition_id() != binding.composition_id
        || inventory.position() != binding.position
        || inventory.route_id() != binding.wire.route_id
        || inventory.rfq_id() != binding.rfq_id
        || inventory.quote_id() != quote.quote_id
        || inventory.solver_id() != binding.solver
        || inventory.reservation_id() != quote.bond_reservation_id
        || inventory.registry_manifest_digest() != binding.pins.registry_digest
        || inventory.profile_bundle_digest() != binding.pins.profile_bundle_digest
        || inventory.bond_policy_hash() != binding.pins.bond_policy_hash
        || inventory.bond_policy_version() != quote.bond_policy_version
        || inventory.bond_asset_binding_digest() != binding.pins.bond_asset_binding_digest
        || inventory.required_bond_amount() != binding.pins.required_collateral
        || inventory.reservation_revision() == 0
        || inventory.reservation_digest() == ZERO_DIGEST
    {
        return Err(ProductionF6ErrorV2::Inventory);
    }
    validate_status(binding, status.capability())?;
    let signed_status = status.signed_head().clone();
    let status_statement = signed_status
        .statement()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let status_digest = status_statement
        .statement_digest()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    if status_digest != status.capability().statement_digest()
        || status_statement.status_epoch() != status.capability().status_epoch()
        || status_statement.observed_at_seconds() != status.capability().observed_at_seconds()
        || status_statement.valid_until_seconds() != status.capability().valid_until_seconds()
        || status_statement.source_evidence_digest() != status.capability().source_evidence_digest()
        || status_statement.state() != SolverOperationalStateV1::Active
        || status_statement.solver_id() != binding.solver
        || status_statement.network_id() != binding.wire.network_id
        || status_statement.registry_digest() != binding.pins.registry_digest
        || status_statement.registry_epoch() != binding.pins.registry_epoch
        || status_statement.roster_snapshot() != binding.wire.roster_snapshot
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let valid_until_seconds = trusted_now_seconds
        .checked_add(MAX_ATTESTATION_LIFETIME_SECONDS)
        .ok_or(ProductionF6ErrorV2::ClockUnavailable)?
        .min(status.capability().valid_until_seconds());
    if trusted_now_seconds >= valid_until_seconds {
        return Err(ProductionF6ErrorV2::StatusUnavailable);
    }
    let reserved_collateral = bond_collateral_total(inventory)?;
    let source_evidence_digest = digest_parts(
        SOURCE_EVIDENCE_DOMAIN,
        &[
            &binding.composition_id,
            &[binding.position as u8],
            &inventory.reservation_id(),
            &inventory.reservation_revision().to_be_bytes(),
            &inventory.reservation_digest(),
            &status.capability().source_evidence_digest(),
        ],
    )?;
    let attestation = BondReservationAttestationV2::new(BondReservationAttestationRequestV2 {
        network_id: binding.wire.network_id,
        composition_id: binding.composition_id,
        position: binding.position,
        rfq_id: binding.rfq_id,
        quote_id: quote.quote_id,
        solver: binding.solver,
        reservation_id: inventory.reservation_id(),
        bond_policy_hash: binding.pins.bond_policy_hash,
        registry_digest: binding.pins.registry_digest,
        registry_epoch: binding.pins.registry_epoch,
        bond_asset_binding_digest: binding.pins.bond_asset_binding_digest,
        required_collateral: binding.pins.required_collateral,
        reserved_collateral,
        reservation_state_digest: inventory.reservation_digest(),
        source_evidence_digest,
        solver_status_statement_digest: status_digest,
        solver_status_epoch: status.capability().status_epoch(),
        solver_status_valid_until_seconds: status.capability().valid_until_seconds(),
        observed_at_seconds: trusted_now_seconds,
        valid_until_seconds,
        sequence,
        previous_attestation_digest,
    })
    .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    make_intent(*quote, attestation, signed_status)
}

fn make_intent(
    quote: QuoteV2,
    attestation: BondReservationAttestationV2,
    signed_status: SignedSolverStatusV1,
) -> Result<PersistedAttestationIntentV2, ProductionF6ErrorV2> {
    let mut intent = PersistedAttestationIntentV2 {
        quote,
        attestation,
        signed_status,
        digest: ZERO_DIGEST,
    };
    let body = encode_intent_body(&intent)?;
    intent.digest = digest_parts(INTENT_DIGEST_DOMAIN, &[&body])?;
    Ok(intent)
}

fn require_same_intent(
    durable: &PersistedAttestationIntentV2,
    proposed: &PersistedAttestationIntentV2,
) -> Result<(), ProductionF6ErrorV2> {
    if durable.digest != proposed.digest || encode_intent(durable)? != encode_intent(proposed)? {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(())
}

fn validate_intent_link(
    previous: Option<&CompletedAttestationV2>,
    intent: &PersistedAttestationIntentV2,
) -> Result<(), ProductionF6ErrorV2> {
    let request = intent.attestation.request();
    let (expected_sequence, expected_previous) = match previous {
        Some(previous) => (
            previous
                .intent
                .attestation
                .request()
                .sequence
                .checked_add(1)
                .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?,
            previous.attestation_digest,
        ),
        None => (1, ZERO_DIGEST),
    };
    if request.sequence != expected_sequence
        || request.previous_attestation_digest != expected_previous
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    validate_economic_sequence(request.sequence, request.previous_attestation_digest)?;
    if let Some(previous) = previous {
        validate_compatible_refresh(&previous.intent, intent)?;
    }
    Ok(())
}

fn validate_compatible_refresh(
    previous: &PersistedAttestationIntentV2,
    next: &PersistedAttestationIntentV2,
) -> Result<(), ProductionF6ErrorV2> {
    let old = previous.attestation.request();
    let new = next.attestation.request();
    let old_status = previous
        .signed_status
        .statement()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let new_status = next
        .signed_status
        .statement()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let old_status_bytes = previous
        .signed_status
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let new_status_bytes = next
        .signed_status
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    if next.quote != previous.quote
        || new.network_id != old.network_id
        || new.composition_id != old.composition_id
        || new.position != old.position
        || new.rfq_id != old.rfq_id
        || new.quote_id != old.quote_id
        || new.solver != old.solver
        || new.reservation_id != old.reservation_id
        || new.bond_policy_hash != old.bond_policy_hash
        || new.registry_digest != old.registry_digest
        || new.registry_epoch != old.registry_epoch
        || new.bond_asset_binding_digest != old.bond_asset_binding_digest
        || new.required_collateral != old.required_collateral
        || new.reserved_collateral < old.reserved_collateral
        || new.observed_at_seconds < old.observed_at_seconds
        || new.solver_status_epoch < old.solver_status_epoch
        || (new.solver_status_epoch == old.solver_status_epoch
            && (new.solver_status_statement_digest != old.solver_status_statement_digest
                || new_status_bytes != old_status_bytes))
        || new_status.observed_at_seconds() < old_status.observed_at_seconds()
        || new.valid_until_seconds <= new.observed_at_seconds
        || new.solver_status_valid_until_seconds < new.valid_until_seconds
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(())
}

fn validate_persistable_intent(
    binding: ProductionSolverF6BindingV2,
    intent: &PersistedAttestationIntentV2,
    status_authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<(), ProductionF6ErrorV2> {
    intent
        .quote
        .validate()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    verify_signed_status_head(&intent.signed_status, status_authorities, secp)?;
    let request = intent.attestation.request();
    let status = intent
        .signed_status
        .statement()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let status_digest = status
        .statement_digest()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    encode_intent(intent)?;
    if intent.quote.rfq_id != binding.rfq_id
        || intent.quote.solver != binding.solver
        || intent.quote.route.composition_id != binding.composition_id
        || intent.quote.route.position != binding.position
        || intent.quote.bond_reservation_id != request.reservation_id
        || request.network_id != binding.wire.network_id
        || request.composition_id != binding.composition_id
        || request.position != binding.position
        || request.rfq_id != binding.rfq_id
        || request.quote_id != intent.quote.quote_id
        || request.solver != binding.solver
        || request.bond_policy_hash != binding.pins.bond_policy_hash
        || request.registry_digest != binding.pins.registry_digest
        || request.registry_epoch != binding.pins.registry_epoch
        || request.bond_asset_binding_digest != binding.pins.bond_asset_binding_digest
        || request.required_collateral != binding.pins.required_collateral
        || request.reserved_collateral < request.required_collateral
        || request.observed_at_seconds == 0
        || request.valid_until_seconds <= request.observed_at_seconds
        || request.solver_status_statement_digest != status_digest
        || request.solver_status_epoch != status.status_epoch()
        || request.solver_status_valid_until_seconds != status.valid_until_seconds()
        || request.valid_until_seconds > status.valid_until_seconds()
        || status.observed_at_seconds() > request.observed_at_seconds
        || status.state() != SolverOperationalStateV1::Active
        || status.solver_id() != binding.solver
        || status.network_id() != binding.wire.network_id
        || status.registry_digest() != binding.pins.registry_digest
        || status.registry_epoch() != binding.pins.registry_epoch
        || status.roster_snapshot() != binding.wire.roster_snapshot
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(())
}

fn verify_signed_status_head(
    signed: &SignedSolverStatusV1,
    authorities: &AuthoritySetV1,
    secp: &SecpContext,
) -> Result<(), ProductionF6ErrorV2> {
    if authorities.xonly_keys().len() < 2
        || authorities.threshold() < 2
        || usize::from(authorities.threshold()) > authorities.xonly_keys().len()
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let reparsed = SignedSolverStatusV1::decode(
        &signed
            .canonical_bytes()
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?,
    )
    .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let statement = reparsed
        .statement()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    if statement.state() != SolverOperationalStateV1::Active {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let digest = statement
        .statement_digest()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    for signature in reparsed.signatures() {
        let key = authorities
            .xonly_keys()
            .get(usize::from(signature.signer_index))
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        secp.verify_bip340(key, &digest, &signature.signature)
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    }
    if reparsed.signatures().len() < usize::from(authorities.threshold()) {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(())
}

fn validate_delivery_matches_intent(
    intent: &PersistedAttestationIntentV2,
    delivery: &CandidateQuoteDeliveryV2,
) -> Result<(), ProductionF6ErrorV2> {
    let signed_status = intent
        .signed_status
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let delivered_status = delivery
        .status()
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    if delivery.quote() != intent.quote
        || delivery
            .attestation()
            .attestation()
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?
            != intent.attestation
        || delivered_status != signed_status
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(())
}

fn encode_intent(intent: &PersistedAttestationIntentV2) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    let mut bytes = encode_intent_body(intent)?;
    let digest = digest_parts(INTENT_DIGEST_DOMAIN, &[&bytes])?;
    if intent.digest != digest {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn encode_intent_body(
    intent: &PersistedAttestationIntentV2,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    let quote = intent
        .quote
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let attestation = intent
        .attestation
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let status = intent
        .signed_status
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    if quote.len() > MAX_QUOTE_BYTES
        || attestation.len() > MAX_ATTESTATION_BYTES
        || status.len() > MAX_STATUS_BYTES
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(INTENT_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    put_bounded(&mut bytes, &quote)?;
    put_bounded(&mut bytes, &attestation)?;
    put_bounded(&mut bytes, &status)?;
    Ok(bytes)
}

fn decode_intent(bytes: &[u8]) -> Result<PersistedAttestationIntentV2, ProductionF6ErrorV2> {
    if bytes.len() < 8 + 2 + 4 * 3 + 32 || bytes.get(..8) != Some(INTENT_MAGIC.as_slice()) {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let (body, stored_digest) = bytes.split_at(
        bytes
            .len()
            .checked_sub(32)
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?,
    );
    let expected = digest_parts(INTENT_DIGEST_DOMAIN, &[body])?;
    if stored_digest != expected.as_slice() {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let mut cursor = CursorV2::new(body);
    cursor.require_bytes(INTENT_MAGIC)?;
    if cursor.u16()? != FORMAT_VERSION {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let quote = QuoteV2::decode(cursor.bounded(MAX_QUOTE_BYTES)?)
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let attestation = BondReservationAttestationV2::decode(cursor.bounded(MAX_ATTESTATION_BYTES)?)
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    let signed_status = SignedSolverStatusV1::decode(cursor.bounded(MAX_STATUS_BYTES)?)
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    cursor.finish()?;
    let intent = PersistedAttestationIntentV2 {
        quote,
        attestation,
        signed_status,
        digest: expected,
    };
    if encode_intent(&intent)?.as_slice() != bytes {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(intent)
}

fn encode_result(
    intent_digest: Digest32,
    delivery: &CandidateQuoteDeliveryV2,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    let delivery = delivery
        .canonical_bytes()
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    if delivery.len() > MAX_DELIVERY_BYTES {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(RESULT_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&intent_digest);
    put_bounded(&mut bytes, &delivery)?;
    let digest = digest_parts(RESULT_DIGEST_DOMAIN, &[&bytes])?;
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn decode_result(
    bytes: &[u8],
    expected_intent_digest: Digest32,
) -> Result<CandidateQuoteDeliveryV2, ProductionF6ErrorV2> {
    if bytes.len() < 8 + 2 + 32 + 4 + 32 || bytes.get(..8) != Some(RESULT_MAGIC.as_slice()) {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let (body, stored_digest) = bytes.split_at(
        bytes
            .len()
            .checked_sub(32)
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?,
    );
    if stored_digest != digest_parts(RESULT_DIGEST_DOMAIN, &[body])?.as_slice() {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let mut cursor = CursorV2::new(body);
    cursor.require_bytes(RESULT_MAGIC)?;
    if cursor.u16()? != FORMAT_VERSION || cursor.array32()? != expected_intent_digest {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let delivery = CandidateQuoteDeliveryV2::decode(cursor.bounded(MAX_DELIVERY_BYTES)?)
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    cursor.finish()?;
    if encode_result(expected_intent_digest, &delivery)?.as_slice() != bytes {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(delivery)
}

fn encode_supersede(
    pending_intent_digest: Digest32,
    replacement: &PersistedAttestationIntentV2,
) -> Result<Vec<u8>, ProductionF6ErrorV2> {
    if pending_intent_digest == ZERO_DIGEST || pending_intent_digest == replacement.digest {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let replacement = encode_intent(replacement)?;
    if replacement.len() > 16_384 {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(SUPERSEDE_MAGIC);
    bytes.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    bytes.extend_from_slice(&pending_intent_digest);
    put_bounded(&mut bytes, &replacement)?;
    let digest = digest_parts(SUPERSEDE_DIGEST_DOMAIN, &[&bytes])?;
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn decode_supersede(
    bytes: &[u8],
    expected_pending_intent_digest: Digest32,
) -> Result<PersistedAttestationIntentV2, ProductionF6ErrorV2> {
    if bytes.len() < 8 + 2 + 32 + 4 + 32 || bytes.get(..8) != Some(SUPERSEDE_MAGIC.as_slice()) {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let (body, stored_digest) = bytes.split_at(
        bytes
            .len()
            .checked_sub(32)
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?,
    );
    if stored_digest != digest_parts(SUPERSEDE_DIGEST_DOMAIN, &[body])?.as_slice() {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let mut cursor = CursorV2::new(body);
    cursor.require_bytes(SUPERSEDE_MAGIC)?;
    if cursor.u16()? != FORMAT_VERSION || cursor.array32()? != expected_pending_intent_digest {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    let replacement = decode_intent(cursor.bounded(16_384)?)?;
    cursor.finish()?;
    if replacement.digest == expected_pending_intent_digest
        || encode_supersede(expected_pending_intent_digest, &replacement)?.as_slice() != bytes
    {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(replacement)
}

fn put_bounded(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ProductionF6ErrorV2> {
    output.extend_from_slice(
        &u32::try_from(bytes.len())
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}

struct CursorV2<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CursorV2<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ProductionF6ErrorV2> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        self.offset = end;
        Ok(value)
    }

    fn require_bytes(&mut self, expected: &[u8]) -> Result<(), ProductionF6ErrorV2> {
        if self.take(expected.len())? != expected {
            return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
        }
        Ok(())
    }

    fn u16(&mut self) -> Result<u16, ProductionF6ErrorV2> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| ProductionF6ErrorV2::InvalidCandidateAttestation,
        )?))
    }

    fn u32(&mut self) -> Result<u32, ProductionF6ErrorV2> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| ProductionF6ErrorV2::InvalidCandidateAttestation,
        )?))
    }

    fn array32(&mut self) -> Result<[u8; 32], ProductionF6ErrorV2> {
        self.take(32)?
            .try_into()
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)
    }

    fn bounded(&mut self, maximum: usize) -> Result<&'a [u8], ProductionF6ErrorV2> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
        if length == 0 || length > maximum {
            return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), ProductionF6ErrorV2> {
        if self.offset != self.bytes.len() {
            return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
        }
        Ok(())
    }
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, ProductionF6ErrorV2> {
    use blake2::digest::{Update, VariableOutput};
    use blake2::Blake2bVar;

    let mut hasher =
        Blake2bVar::new(32).map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    hasher.update(domain);
    for part in parts {
        hasher.update(
            &u64::try_from(part.len())
                .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?
                .to_be_bytes(),
        );
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .map_err(|_| ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    if output == ZERO_DIGEST {
        return Err(ProductionF6ErrorV2::InvalidCandidateAttestation);
    }
    Ok(output)
}

#[cfg(test)]
mod tests;
