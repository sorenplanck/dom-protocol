//! Genuine pre-bootstrap Bitcoin plan and retained refund authority.

#[cfg(test)]
use std::path::Path;
use std::rc::Rc;

use adapter_btc::roster::{
    BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1, ROSTER_VERSION,
};
use adapter_btc::sighash::key_path_sighash_default;
use adapter_btc::taproot::build_taproot_contract;
#[cfg(any(test, feature = "harness"))]
use adapter_btc::taproot::TaprootContractV1;
use adapter_btc::templates::{
    frozen_template_digest_v1, BitcoinPrevoutV1, BitcoinTxInV1, BitcoinTxOutV1,
    FrozenBitcoinTemplateV1,
};
use adapter_btc::timelock::BitcoinCsvDelayV1;
use adapter_btc::types::BitcoinNetworkV1 as TemplateNetworkV1;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
#[cfg(any(test, feature = "harness"))]
use bitcoin::secp256k1::Keypair;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_crypto::{NonceParity, SecpContext};
use btc_vault::PersistedArtifactDescriptorV1;
use zeroize::{Zeroize, Zeroizing};

use crate::authority::{
    BitcoinRefundDelayV1, BitcoinRefundSignatureV1, BitcoinRefundSigningRequestV1,
    RetainedBitcoinRefundSignerV1,
};
use crate::funding::{
    ArmedBitcoinFundingV1, BitcoinPrebroadcastPlanV1,
    BitcoinPrebroadcastStoreV1, BitcoinRefundContractV1, BitcoinRefundOutputV1,
    PreparedBitcoinFundingV1, ReopenedBitcoinFundingV1,
};
#[cfg(any(test, feature = "harness"))]
use crate::funding::prepared_template_digests;
use crate::rpc::{BitcoinCoreNetworkV1, BitcoinCoreRpcClientV1, MAX_SIGNET_CHALLENGE_BYTES};
use crate::store::StageKind;
use crate::LiveBitcoinError;

const AUTHORITY_MAGIC: &[u8; 8] = b"DBTCFAV1";
const TEMPLATES_MAGIC: &[u8; 8] = b"DBTCFTV1";
const FACE_EVIDENCE_MAGIC: &[u8; 8] = b"DBTCFPV1";
const CLAIM_PREPARED_MAGIC: &[u8; 8] = b"DBTCFCV1";
const CLAIM_INTENT_MAGIC: &[u8; 8] = b"DBTCFIV1";
const CLAIM_EXTRACTION_INTENT_MAGIC: &[u8; 8] = b"DBTCXIV1";
const CLAIM_EXTRACTION_COMPLETE_MAGIC: &[u8; 8] = b"DBTCXCV1";
const CLAIM_FINALIZATION_INTENT_MAGIC: &[u8; 8] = b"DBTCZIV1";
const CLAIM_FINALIZED_MAGIC: &[u8; 8] = b"DBTCZFV1";
const CODEC_VERSION: u16 = 1;
const FACE_EVIDENCE_REVISION: u64 = 1;
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/FRESH-RECEIPT/V1\0";
const FACE_EVIDENCE_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/FRESH-PAYOUT-FACE/V1\0";
const CLAIM_PREPARED_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/FRESH-CLAIM-PREPARED/V1\0";
const CLAIM_PREPARED_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"DOM-INTEROP/F7/BTC-LIVE/FRESH-CLAIM-PREPARED-PAYLOAD/V1\0";
const CLAIM_INTENT_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/FRESH-CLAIM-INTENT/V1\0";
const CLAIM_EXTRACTION_INTENT_DIGEST_DOMAIN: &[u8] =
    b"DOM-INTEROP/F7/BTC-LIVE/FRESH-CLAIM-EXTRACTION-INTENT/V1\0";
const CLAIM_EXTRACTION_CONTEXT_DIGEST_DOMAIN: &[u8] =
    b"DOM-INTEROP/F7/BTC-LIVE/FRESH-CLAIM-EXTRACTION-CONTEXT/V1\0";
const CLAIM_EXTRACTION_COMPLETE_DIGEST_DOMAIN: &[u8] =
    b"DOM-INTEROP/F7/BTC-LIVE/FRESH-CLAIM-EXTRACTION-COMPLETE/V1\0";
const CLAIM_FINALIZATION_INTENT_DIGEST_DOMAIN: &[u8] =
    b"DOM-INTEROP/F7/BTC-LIVE/FRESH-CLAIM-FINALIZATION-INTENT/V1\0";
const CLAIM_FINALIZED_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/FRESH-CLAIM-FINALIZED/V1\0";
const EXACT_CLAIM_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/BTC/F7/EXACT-CLAIM/V1\0";
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;
const MAX_FEE_RATE_SAT_VB: u64 = 1_000_000;
#[cfg(any(test, feature = "harness"))]
const MAX_KEY_ATTEMPTS: usize = 128;
const MAX_CLAIM_TRANSACTION_BYTES: usize = 4_000_000;

/// Public economics and identities known before Bitcoin wallet input selection.
///
/// `route_binding` must be derived by the route layer from its canonical
/// scenario, terms, M.8 policy, chain identities, economics, adaptor point,
/// and already prepared DOM receipt.  It deliberately cannot contain any of
/// the three Bitcoin template hashes, which do not exist until preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BitcoinFreshRouteRequestV1 {
    /// Nonzero stable pre-bootstrap route binding.
    pub route_binding: [u8; 32],
    /// Canonical participant identifiers in Maker, Taker order.
    pub participant_ids: [[u8; 32]; 2],
    /// Exact value funded into the Taproot contract.
    pub amount_sat: u64,
    /// Wallet funding fee rate in satoshis per virtual byte.
    pub funding_fee_rate_sat_vb: u64,
    /// Exact fee reserved by the single-output key-path claim.
    pub claim_fee_sat: u64,
    /// Exact fee reserved by the single-output CSV refund.
    pub refund_fee_sat: u64,
    /// Unit-tagged relative delay selected by the authenticated M.8 policy.
    pub refund_delay: BitcoinRefundDelayV1,
}

/// Public receipt created only after real wallet input selection.
///
/// It contains the exact three signature-independent Bitcoin template
/// commitments required to finish the cross-chain manifest.  It contains no
/// private key, raw transaction, witness, RPC credential, or signing share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitcoinFreshRouteReceiptV1 {
    route_binding: [u8; 32],
    plan_digest: [u8; 32],
    prepared_record_digest: [u8; 32],
    summary_record_digest: [u8; 32],
    funding_txid: [u8; 32],
    funding_wtxid: [u8; 32],
    contract_vout: u32,
    contract_amount_sat: u64,
    actual_funding_fee_sat: u64,
    funding_virtual_size_vb: u64,
    claim_roster: ParticipantKeyRosterV1,
    refund_key_xonly: [u8; 32],
    contract_script_pubkey: Vec<u8>,
    claim_output: BitcoinRefundOutputV1,
    refund_output: BitcoinRefundOutputV1,
    funding_template_hash: [u8; 32],
    claim_template_hash: [u8; 32],
    refund_template_hash: [u8; 32],
    receipt_digest: [u8; 32],
}

impl BitcoinFreshRouteReceiptV1 {
    /// Stable route binding accepted by the prebroadcast store.
    #[must_use]
    pub const fn route_binding(&self) -> [u8; 32] {
        self.route_binding
    }

    /// Digest of the complete public prebroadcast plan.
    #[must_use]
    pub const fn plan_digest(&self) -> [u8; 32] {
        self.plan_digest
    }

    /// Digest of the exact authenticated Prepared record.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> [u8; 32] {
        self.prepared_record_digest
    }

    /// Digest of the exact wallet cost summary.
    #[must_use]
    pub const fn summary_record_digest(&self) -> [u8; 32] {
        self.summary_record_digest
    }

    /// Exact funding transaction id in internal byte order.
    #[must_use]
    pub const fn funding_txid(&self) -> [u8; 32] {
        self.funding_txid
    }

    /// Exact funding witness transaction id in internal byte order.
    #[must_use]
    pub const fn funding_wtxid(&self) -> [u8; 32] {
        self.funding_wtxid
    }

    /// Unique contract output index selected by the wallet transaction.
    #[must_use]
    pub const fn contract_vout(&self) -> u32 {
        self.contract_vout
    }

    /// Exact contract amount in satoshis.
    #[must_use]
    pub const fn contract_amount_sat(&self) -> u64 {
        self.contract_amount_sat
    }

    /// Exact wallet-selected funding fee in satoshis.
    #[must_use]
    pub const fn actual_funding_fee_sat(&self) -> u64 {
        self.actual_funding_fee_sat
    }

    /// Exact virtual size of the signed funding transaction.
    #[must_use]
    pub const fn funding_virtual_size_vb(&self) -> u64 {
        self.funding_virtual_size_vb
    }

    /// Canonical Maker, Taker claim-key roster committed by Taproot.
    #[must_use]
    pub const fn claim_roster(&self) -> ParticipantKeyRosterV1 {
        self.claim_roster
    }

    /// Retained BIP340 key committed by the CSV refund leaf.
    #[must_use]
    pub const fn refund_key_xonly(&self) -> [u8; 32] {
        self.refund_key_xonly
    }

    /// Exact P2TR contract scriptPubKey.
    #[must_use]
    pub fn contract_script_pubkey(&self) -> &[u8] {
        &self.contract_script_pubkey
    }

    /// Exact wallet-owned claim destination scriptPubKey.
    #[must_use]
    pub fn claim_destination_script_pubkey(&self) -> &[u8] {
        &self.claim_output.script_pubkey
    }

    /// Exact output amount of the key-path claim.
    #[must_use]
    pub const fn claim_output_amount_sat(&self) -> u64 {
        self.claim_output.amount_sat
    }

    /// Exact wallet-owned refund destination scriptPubKey.
    #[must_use]
    pub fn refund_destination_script_pubkey(&self) -> &[u8] {
        &self.refund_output.script_pubkey
    }

    /// Exact output amount of the CSV refund.
    #[must_use]
    pub const fn refund_output_amount_sat(&self) -> u64 {
        self.refund_output.amount_sat
    }

    /// Signature-independent funding-template commitment.
    #[must_use]
    pub const fn funding_template_hash(&self) -> [u8; 32] {
        self.funding_template_hash
    }

    /// Signature-independent key-path claim-template commitment.
    #[must_use]
    pub const fn claim_template_hash(&self) -> [u8; 32] {
        self.claim_template_hash
    }

    /// Signature-independent CSV refund-template commitment.
    #[must_use]
    pub const fn refund_template_hash(&self) -> [u8; 32] {
        self.refund_template_hash
    }

    /// Domain-separated commitment to every field of this public receipt.
    #[must_use]
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }
}

struct FreshPayoutFaceEvidenceRecordV1 {
    revision: u64,
    route_binding: [u8; 32],
    receipt_digest: [u8; 32],
    contract_amount_sat: u64,
    claim_destination_script_pubkey: Vec<u8>,
    claim_output_amount_sat: u64,
    claim_template_hash: [u8; 32],
    record_digest: [u8; 32],
}

/// Move-only owner proof of the exact Bitcoin payout representation.
///
/// The only constructor rereads the MAC-authenticated `FreshFaceEvidence`
/// stage and cross-checks it against the exact fresh-route receipt. No caller
/// can supply a revision, script, amount, template hash or evidence digest.
#[must_use = "the authenticated payout face must be consumed by the route terms authority"]
pub struct AuthenticatedBitcoinPayoutFaceV1 {
    revision: u64,
    route_binding: [u8; 32],
    receipt_digest: [u8; 32],
    contract_amount_sat: u64,
    claim_destination_script_pubkey: Vec<u8>,
    claim_output_amount_sat: u64,
    claim_template_hash: [u8; 32],
    evidence_digest: [u8; 32],
}

impl AuthenticatedBitcoinPayoutFaceV1 {
    /// First and only immutable payout-face revision for this one-shot route.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Exact pre-bootstrap route binding authenticated by the owner store.
    #[must_use]
    pub const fn route_binding(&self) -> [u8; 32] {
        self.route_binding
    }

    /// Digest of the complete fresh-route receipt.
    #[must_use]
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    /// Exact amount locked by the fresh funding contract output.
    #[must_use]
    pub const fn contract_amount_sat(&self) -> u64 {
        self.contract_amount_sat
    }

    /// Wallet-owned claim destination script committed by the claim template.
    #[must_use]
    pub fn claim_destination_script_pubkey(&self) -> &[u8] {
        &self.claim_destination_script_pubkey
    }

    /// Exact amount paid by the signature-independent claim template.
    #[must_use]
    pub const fn claim_output_amount_sat(&self) -> u64 {
        self.claim_output_amount_sat
    }

    /// Signature-independent key-path claim-template commitment.
    #[must_use]
    pub const fn claim_template_hash(&self) -> [u8; 32] {
        self.claim_template_hash
    }

    /// Domain-separated digest of the complete owner-authenticated face row.
    #[must_use]
    pub const fn evidence_digest(&self) -> [u8; 32] {
        self.evidence_digest
    }
}

/// Public route facts that an authenticated fresh claim authority must bind.
///
/// This value contains no signing secret. The retained authority accepts it
/// only when every field recreates the exact claim template already committed
/// by the durable fresh-route receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BitcoinFreshClaimBindingV1 {
    /// Route settlement whose nonce permits will be issued.
    pub settlement_id: [u8; 32],
    /// Exact signing session retained by the combined runner.
    pub session_id: [u8; 32],
    /// Canonical settlement-terms digest.
    pub terms_hash: [u8; 32],
    /// Funding transaction identifier in internal byte order.
    pub funding_txid: [u8; 32],
    /// Exact Taproot contract output index.
    pub funding_vout: u32,
    /// Exact Taproot contract output amount.
    pub funding_amount_sat: u64,
    /// Exact wallet-owned claim destination scriptPubKey.
    pub destination_script_pubkey: Vec<u8>,
    /// Exact fee subtracted by the one-output cooperative claim.
    pub fee_sat: u64,
    /// Manifest-committed frozen claim-template digest.
    pub expected_template_hash: [u8; 32],
    /// Public compressed adaptor point shared with the DOM claim.
    pub adaptor_point: [u8; 33],
}

/// Opaque restart-authenticated owner of the two fresh claim signing keys.
///
/// The keys remain in zeroizing storage and this type deliberately implements
/// no codec, `Clone`, `Copy`, or `Debug`. There are no raw-key getters. Its
/// sole operation first binds the complete public claim and transfers the
/// keys into another opaque, single-use preparation authority.
#[cfg(test)]
pub(crate) struct RetainedFreshBitcoinClaimAuthorityV1 {
    network: BitcoinCoreNetworkV1,
    route_binding: [u8; 32],
    plan_digest: [u8; 32],
    receipt_digest: [u8; 32],
    funding_txid: [u8; 32],
    funding_vout: u32,
    funding_amount_sat: u64,
    claim_roster: ParticipantKeyRosterV1,
    refund_key_xonly: [u8; 32],
    refund_delay: BitcoinRefundDelayV1,
    contract_script_pubkey: Vec<u8>,
    claim_destination_script_pubkey: Vec<u8>,
    claim_output_amount_sat: u64,
    claim_template_hash: [u8; 32],
    maker_secret: Zeroizing<[u8; 32]>,
    taker_secret: Zeroizing<[u8; 32]>,
}

/// Test-only witness that exact public claim binding completed before custody.
///
/// The legacy dual-signer transition was removed: production may only use the
/// participant-separated BTC actuator. This witness retains no signing key,
/// nonce authority or vault path.
#[cfg(test)]
pub(crate) struct BoundFreshBitcoinClaimAuthorityV1 {
    contract: TaprootContractV1,
    template_digest: [u8; 32],
}

/// Public output of fresh-key claim preparation before adaptor revelation.
///
/// This type contains only the unsigned transaction, adaptor pre-signature
/// and public restart metadata. The two private keys and both secret nonces
/// are absent.
pub struct PreparedFreshBitcoinClaimV1 {
    record: FreshBitcoinPreparedClaimRecordV1,
    record_digest: [u8; 32],
    authority_instance: Rc<()>,
}

/// Public route and Taproot facts retained beside one durable post-M.8 claim.
///
/// This value contains no key, nonce, partial signature, aggregate
/// pre-signature, transaction bytes, or adaptor scalar. It is exposed only so
/// a composition root can bind the durable claim to its authenticated route.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreshBitcoinPreparedClaimPublicV1 {
    /// Stable pre-bootstrap route binding of the existing prebroadcast store.
    pub route_binding: [u8; 32],
    /// Exact public prebroadcast plan digest.
    pub plan_digest: [u8; 32],
    /// Exact fresh-route receipt digest.
    pub receipt_digest: [u8; 32],
    /// Authenticated Bitcoin Core network.
    pub network: BitcoinCoreNetworkV1,
    /// Route settlement whose nonce permits were consumed.
    pub settlement_id: [u8; 32],
    /// Exact one-shot signing session.
    pub session_id: [u8; 32],
    /// Canonical settlement terms digest.
    pub terms_hash: [u8; 32],
    /// Exact funding transaction identifier in internal byte order.
    pub funding_txid: [u8; 32],
    /// Exact Taproot contract output index.
    pub funding_vout: u32,
    /// Exact Taproot contract output amount.
    pub funding_amount_sat: u64,
    /// Canonical Maker, Taker claim roster.
    pub roster: ParticipantKeyRosterV1,
    /// Exact P2TR contract scriptPubKey.
    pub contract_script_pubkey: Vec<u8>,
    /// Refund leaf x-only key committed into the P2TR output.
    pub refund_key_xonly: [u8; 32],
    /// Unit-tagged CSV delay committed into the refund leaf.
    pub refund_delay: BitcoinRefundDelayV1,
    /// Exact wallet-owned cooperative-claim destination scriptPubKey.
    pub destination_script_pubkey: Vec<u8>,
    /// Exact cooperative-claim fee.
    pub fee_sat: u64,
    /// Frozen signature-independent claim template digest.
    pub template_digest: [u8; 32],
    /// Shared public adaptor point.
    pub adaptor_point: [u8; 33],
}

struct FreshBitcoinPreparedClaimRecordV1 {
    public: FreshBitcoinPreparedClaimPublicV1,
    transaction: Transaction,
    tap_sighash: [u8; 32],
    nonce_parity: NonceParity,
    output_xonly: [u8; 32],
    pre_signature: [u8; 64],
    signer_one_partial: Option<PersistedArtifactDescriptorV1>,
    signer_two_partial: Option<PersistedArtifactDescriptorV1>,
}

/// Exact signed claim plus its secret-free, confirmation-gated extraction
/// authority.
///
/// The transaction bytes can be consumed once by the durable actuator. The
/// extraction authority never accepts caller-supplied evidence; it re-reads
/// the exact transaction from an authenticated Bitcoin Core client.
pub struct FinalizedFreshBitcoinClaimV1 {
    public: FreshBitcoinPreparedClaimPublicV1,
    canonical_transaction: Vec<u8>,
    extraction: FreshBitcoinClaimExtractionAuthorityV1,
}

/// Exact durable restart stage of the fresh claim.
pub enum ReopenedFreshBitcoinClaimV1 {
    /// M.8 preparation is durable but no adaptation was begun.
    Prepared(PreparedFreshBitcoinClaimV1),
    /// Adaptation intent is durable and an exact claim may already be retained
    /// by the actuator, but the redundant finalized transaction row is absent.
    /// This stage can recover only the secret-free extraction capability; it
    /// cannot sign, adapt, or reconstruct transaction bytes.
    ExtractionReady(PreparedFreshBitcoinClaimV1),
    /// Adaptation and the exact witness-bearing claim are durable.
    Finalized(FinalizedFreshBitcoinClaimV1),
}

/// Secret-free authority for extracting from one exact canonical Bitcoin
/// claim after the required confirmation depth.
///
/// It has no codec, `Clone`, `Copy`, raw pre-signature getter, or extraction
/// method that accepts arbitrary transaction bytes. Restart reconstructs it
/// only by reopening the MAC-authenticated post-M.8 record in the same
/// [`BitcoinPrebroadcastStoreV1`].
pub struct FreshBitcoinClaimExtractionAuthorityV1 {
    expected_txid: [u8; 32],
    pre_signature: [u8; 64],
    nonce_parity: NonceParity,
    adaptor_point: [u8; 33],
    output_xonly: [u8; 32],
    tap_sighash: [u8; 32],
    prepared_record_digest: [u8; 32],
    authority_instance: Rc<()>,
}

/// Redacting, zeroizing scalar extracted only from a confirmed canonical
/// Bitcoin claim.
pub struct FreshBitcoinRevealedSecretV1 {
    scalar: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FreshClaimExtractionIntentV1 {
    prepared_record_digest: [u8; 32],
    expected_txid: [u8; 32],
    context_digest: [u8; 32],
    minimum_confirmations: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FreshClaimExtractionCompleteV1 {
    intent_digest: [u8; 32],
    expected_txid: [u8; 32],
    canonical_transaction_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FreshClaimFinalizationIntentV1 {
    prepared_record_digest: [u8; 32],
    expected_txid: [u8; 32],
    extraction_context_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FreshClaimFinalizedRecordV1 {
    prepared_record_digest: [u8; 32],
    expected_txid: [u8; 32],
    extraction_context_digest: [u8; 32],
    canonical_transaction_digest: [u8; 32],
    canonical_transaction: Vec<u8>,
}

impl PreparedFreshBitcoinClaimV1 {
    /// Public route and Taproot facts revalidated from the authenticated store.
    #[must_use]
    pub const fn public(&self) -> &FreshBitcoinPreparedClaimPublicV1 {
        &self.record.public
    }

    /// Digest of the exact MAC-authenticated post-M.8 record.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    /// Proves that this authority was issued by the exact currently locked
    /// prebroadcast store object, rather than a copied directory or another
    /// route owner with coincidentally equal public fields.
    #[must_use]
    pub fn authenticates_store(&self, store: &BitcoinPrebroadcastStoreV1) -> bool {
        Rc::ptr_eq(&self.authority_instance, &store.authority_instance)
    }

    /// Adapts the single durable aggregate pre-signature and returns the exact
    /// signed transaction plus a confirmation-gated public extraction owner.
    ///
    /// The source scalar buffer is wiped on every return path. This transition
    /// never touches either nonce vault and therefore cannot create a second
    /// signing attempt.
    pub fn finalize_claim(
        mut self,
        store: &BitcoinPrebroadcastStoreV1,
        scalar: &mut [u8; 32],
    ) -> Result<FinalizedFreshBitcoinClaimV1, LiveBitcoinError> {
        if !self.authenticates_store(store) {
            scalar.zeroize();
            return Err(LiveBitcoinError::StateConflict);
        }
        let retained_scalar = Zeroizing::new(*scalar);
        scalar.zeroize();
        let extraction = self.extraction_authority()?;
        let finalization_intent = FreshClaimFinalizationIntentV1 {
            prepared_record_digest: self.record_digest,
            expected_txid: extraction.expected_txid,
            extraction_context_digest: extraction.context_digest()?,
        };
        let encoded_intent = encode_finalization_intent(&finalization_intent)?;
        store
            .store
            .publish(StageKind::FreshClaimFinalizationIntent, &encoded_intent)?;
        let exact_intent = store
            .store
            .read(StageKind::FreshClaimFinalizationIntent)?
            .ok_or(LiveBitcoinError::StateConflict)?;
        if exact_intent != encoded_intent
            || decode_finalization_intent(&exact_intent)? != finalization_intent
        {
            return Err(LiveBitcoinError::StateConflict);
        }
        let key = SecretKey::from_slice(retained_scalar.as_ref())
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let mut secp = Secp256k1::new();
        secp.seeded_randomize(&*fresh_entropy()?);
        if PublicKey::from_secret_key(&secp, &key).serialize() != self.record.public.adaptor_point {
            return Err(LiveBitcoinError::ClaimMismatch);
        }
        let crypto = SecpContext::new(&*fresh_entropy()?);
        let final_signature = crypto
            .adapt(
                &self.record.pre_signature,
                &retained_scalar,
                self.record.nonce_parity,
                &self.record.output_xonly,
                &self.record.tap_sighash,
            )
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        crypto
            .verify_bip340(
                &self.record.output_xonly,
                &self.record.tap_sighash,
                &final_signature,
            )
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        self.record.transaction.input[0].witness =
            Witness::from_slice(&[final_signature.as_slice()]);
        let canonical_transaction = serialize(&self.record.transaction);
        let decoded: Transaction =
            deserialize(&canonical_transaction).map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        if decoded != self.record.transaction || decoded.input[0].witness.len() != 1 {
            return Err(LiveBitcoinError::ClaimMismatch);
        }
        if decoded.compute_txid().to_raw_hash().to_byte_array() != extraction.expected_txid {
            return Err(LiveBitcoinError::ClaimMismatch);
        }
        let finalized_record = FreshClaimFinalizedRecordV1 {
            prepared_record_digest: self.record_digest,
            expected_txid: extraction.expected_txid,
            extraction_context_digest: extraction.context_digest()?,
            canonical_transaction_digest: digest(
                EXACT_CLAIM_DIGEST_DOMAIN,
                &canonical_transaction,
            )?,
            canonical_transaction,
        };
        let encoded_finalized = encode_finalized_claim(&finalized_record)?;
        store
            .store
            .publish(StageKind::FreshClaimFinalized, &encoded_finalized)?;
        let exact_finalized = store
            .store
            .read(StageKind::FreshClaimFinalized)?
            .ok_or(LiveBitcoinError::StateConflict)?;
        if exact_finalized != encoded_finalized {
            return Err(LiveBitcoinError::StateConflict);
        }
        let finalized_record = decode_finalized_claim(&exact_finalized)?;
        validate_finalized_claim_record(&finalized_record, &extraction)?;
        Ok(FinalizedFreshBitcoinClaimV1 {
            public: self.record.public.clone(),
            canonical_transaction: finalized_record.canonical_transaction,
            extraction,
        })
    }

    /// Consumes the authenticated post-M.8 preparation into the same
    /// confirmation-gated extraction authority without requiring `t`.
    ///
    /// This recovery transition is used only after the durable actuator proves
    /// that the exact claim row already exists. The expected txid is derived
    /// from the stored unsigned claim; no transaction identity is supplied by
    /// the caller and no final witness or scalar is persisted.
    fn into_public_extraction_authority(
        self,
    ) -> Result<FreshBitcoinClaimExtractionAuthorityV1, LiveBitcoinError> {
        self.extraction_authority()
    }

    /// Consumes a restart-authenticated finalization-intent stage into public
    /// route facts and its secret-free canonical extraction capability.
    ///
    /// The caller must still prove that the exact expected transaction is
    /// durably retained by its actuator before releasing this capability.
    pub fn into_recovery_extraction_parts(
        self,
    ) -> Result<
        (
            FreshBitcoinPreparedClaimPublicV1,
            FreshBitcoinClaimExtractionAuthorityV1,
        ),
        LiveBitcoinError,
    > {
        let public = self.record.public.clone();
        let extraction = self.into_public_extraction_authority()?;
        Ok((public, extraction))
    }

    fn extraction_authority(
        &self,
    ) -> Result<FreshBitcoinClaimExtractionAuthorityV1, LiveBitcoinError> {
        validate_prepared_claim_record(&self.record)?;
        let expected_txid = self
            .record
            .transaction
            .compute_txid()
            .to_raw_hash()
            .to_byte_array();
        if expected_txid == [0; 32] {
            return Err(LiveBitcoinError::ClaimMismatch);
        }
        Ok(FreshBitcoinClaimExtractionAuthorityV1 {
            expected_txid,
            pre_signature: self.record.pre_signature,
            nonce_parity: self.record.nonce_parity,
            adaptor_point: self.record.public.adaptor_point,
            output_xonly: self.record.output_xonly,
            tap_sighash: self.record.tap_sighash,
            prepared_record_digest: self.record_digest,
            authority_instance: Rc::clone(&self.authority_instance),
        })
    }
}

impl FinalizedFreshBitcoinClaimV1 {
    /// Public route/session facts authenticated by the same post-M.8 record.
    #[must_use]
    pub const fn public(&self) -> &FreshBitcoinPreparedClaimPublicV1 {
        &self.public
    }

    /// Proves the finalized authority belongs to this exact open Store owner.
    #[must_use]
    pub fn authenticates_store(&self, store: &BitcoinPrebroadcastStoreV1) -> bool {
        Rc::ptr_eq(
            &self.extraction.authority_instance,
            &store.authority_instance,
        )
    }

    /// Digest of the exact post-M.8 preparation behind this finalized claim.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> [u8; 32] {
        self.extraction.prepared_record_digest
    }

    /// Consumes the result into the actuator payload and the sole public
    /// extraction authority.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        FreshBitcoinPreparedClaimPublicV1,
        Vec<u8>,
        FreshBitcoinClaimExtractionAuthorityV1,
    ) {
        (self.public, self.canonical_transaction, self.extraction)
    }
}

impl FreshBitcoinClaimExtractionAuthorityV1 {
    /// Exact claim transaction id in internal byte order.
    #[must_use]
    pub const fn expected_txid(&self) -> [u8; 32] {
        self.expected_txid
    }

    /// Digest of the MAC-authenticated post-M.8 record that created this
    /// authority.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> [u8; 32] {
        self.prepared_record_digest
    }

    /// Proves this move-only authority belongs to the exact open Store owner.
    #[must_use]
    pub fn authenticates_store(&self, store: &BitcoinPrebroadcastStoreV1) -> bool {
        Rc::ptr_eq(&self.authority_instance, &store.authority_instance)
    }

    /// Re-reads the exact transaction from authenticated Bitcoin Core, proves
    /// its canonical inclusion and depth, then verifies BIP340 and `t*G == T`
    /// before returning the redacting scalar.
    pub fn extract_confirmed(
        &mut self,
        store: &BitcoinPrebroadcastStoreV1,
        rpc: &BitcoinCoreRpcClientV1,
        minimum_confirmations: u32,
    ) -> Result<FreshBitcoinRevealedSecretV1, LiveBitcoinError> {
        if minimum_confirmations == 0
            || !Rc::ptr_eq(&self.authority_instance, &store.authority_instance)
        {
            return Err(LiveBitcoinError::StateConflict);
        }
        let context_digest = self.context_digest()?;
        let intent = FreshClaimExtractionIntentV1 {
            prepared_record_digest: self.prepared_record_digest,
            expected_txid: self.expected_txid,
            context_digest,
            minimum_confirmations,
        };
        let encoded_intent = encode_extraction_intent(&intent)?;
        store
            .store
            .publish(StageKind::FreshClaimExtractionIntent, &encoded_intent)?;
        let exact_intent = store
            .store
            .read(StageKind::FreshClaimExtractionIntent)?
            .ok_or(LiveBitcoinError::StateConflict)?;
        if exact_intent != encoded_intent || decode_extraction_intent(&exact_intent)? != intent {
            return Err(LiveBitcoinError::StateConflict);
        }
        let intent_digest = digest(CLAIM_EXTRACTION_INTENT_DIGEST_DOMAIN, &exact_intent)?;
        if let Some(complete) = store.store.read(StageKind::FreshClaimExtractionComplete)? {
            let complete = decode_extraction_complete(&complete)?;
            if complete.intent_digest != intent_digest
                || complete.expected_txid != self.expected_txid
            {
                return Err(LiveBitcoinError::StateConflict);
            }
        }
        let evidence = crate::BitcoinCoreEvidenceCollectorV1::new(rpc)
            .collect_confirmed(self.expected_txid, minimum_confirmations)?;
        let canonical_transaction = evidence.raw_transaction();
        let canonical_transaction_digest =
            digest(EXACT_CLAIM_DIGEST_DOMAIN, canonical_transaction)?;
        if let Some(complete) = store.store.read(StageKind::FreshClaimExtractionComplete)? {
            let complete = decode_extraction_complete(&complete)?;
            if complete.intent_digest != intent_digest
                || complete.expected_txid != self.expected_txid
                || complete.canonical_transaction_digest != canonical_transaction_digest
            {
                return Err(LiveBitcoinError::StateConflict);
            }
        }
        let transaction: Transaction =
            deserialize(canonical_transaction).map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        if serialize(&transaction).as_slice() != canonical_transaction
            || transaction.compute_txid().to_raw_hash().to_byte_array() != self.expected_txid
            || transaction.input.len() != 1
            || transaction.input[0].witness.len() != 1
        {
            return Err(LiveBitcoinError::ClaimMismatch);
        }
        let final_signature: [u8; 64] = transaction.input[0]
            .witness
            .iter()
            .next()
            .and_then(|item| item.try_into().ok())
            .ok_or(LiveBitcoinError::ClaimMismatch)?;
        let crypto = SecpContext::new(&*fresh_entropy()?);
        crypto
            .verify_bip340(&self.output_xonly, &self.tap_sighash, &final_signature)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let mut scalar = crypto
            .extract(
                &final_signature,
                &self.pre_signature,
                self.nonce_parity,
                &self.adaptor_point,
            )
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let revealed = FreshBitcoinRevealedSecretV1 {
            scalar: Zeroizing::new(scalar),
        };
        scalar.zeroize();
        let complete = FreshClaimExtractionCompleteV1 {
            intent_digest,
            expected_txid: self.expected_txid,
            canonical_transaction_digest,
        };
        let encoded_complete = encode_extraction_complete(&complete)?;
        store
            .store
            .publish(StageKind::FreshClaimExtractionComplete, &encoded_complete)?;
        let exact_complete = store
            .store
            .read(StageKind::FreshClaimExtractionComplete)?
            .ok_or(LiveBitcoinError::StateConflict)?;
        if exact_complete != encoded_complete
            || decode_extraction_complete(&exact_complete)? != complete
        {
            return Err(LiveBitcoinError::StateConflict);
        }
        Ok(revealed)
    }

    fn context_digest(&self) -> Result<[u8; 32], LiveBitcoinError> {
        let mut bytes = Vec::with_capacity(32 * 6 + 66);
        bytes.extend_from_slice(&self.expected_txid);
        bytes.extend_from_slice(&self.pre_signature);
        bytes.push(nonce_parity_tag(self.nonce_parity));
        bytes.extend_from_slice(&self.adaptor_point);
        bytes.extend_from_slice(&self.output_xonly);
        bytes.extend_from_slice(&self.tap_sighash);
        bytes.extend_from_slice(&self.prepared_record_digest);
        digest(CLAIM_EXTRACTION_CONTEXT_DIGEST_DOMAIN, &bytes)
    }
}

impl FreshBitcoinRevealedSecretV1 {
    /// Moves the verified scalar into a caller-owned zeroizable buffer and
    /// wipes the retained copy before returning.
    pub fn move_into(mut self, output: &mut [u8; 32]) {
        output.copy_from_slice(self.scalar.as_ref());
        self.scalar.zeroize();
    }
}

#[cfg(test)]
impl RetainedFreshBitcoinClaimAuthorityV1 {
    /// Recreates and authenticates the exact cooperative claim without
    /// touching a nonce key store or vault.
    pub(crate) fn bind_exact_claim(
        self,
        binding: BitcoinFreshClaimBindingV1,
    ) -> Result<BoundFreshBitcoinClaimAuthorityV1, LiveBitcoinError> {
        if self.route_binding == [0; 32]
            || self.plan_digest == [0; 32]
            || self.receipt_digest == [0; 32]
            || binding.settlement_id == [0; 32]
            || binding.session_id == [0; 32]
            || binding.terms_hash == [0; 32]
            || binding.funding_txid != self.funding_txid
            || binding.funding_vout != self.funding_vout
            || binding.funding_amount_sat != self.funding_amount_sat
            || binding.funding_amount_sat == 0
            || binding.destination_script_pubkey != self.claim_destination_script_pubkey
            || binding.destination_script_pubkey.is_empty()
            || binding.destination_script_pubkey.len() > MAX_SCRIPT_BYTES
            || binding.fee_sat == 0
            || binding.funding_amount_sat.checked_sub(binding.fee_sat)
                != Some(self.claim_output_amount_sat)
            || binding.expected_template_hash == [0; 32]
            || binding.expected_template_hash != self.claim_template_hash
            || PublicKey::from_slice(&binding.adaptor_point).is_err()
        {
            return Err(LiveBitcoinError::ClaimMismatch);
        }

        // Audit finding F1: this context derives public keys from the two
        // route secrets, so it is randomized before it touches them.
        // `Secp256k1::new()` performs no randomization of its own, and
        // `seeded_randomize` is the ungated form (`randomize` needs the
        // `rand` feature, which this crate does not enable).
        let mut secp = Secp256k1::new();
        secp.seeded_randomize(&*fresh_entropy()?);
        let maker_secret = SecretKey::from_slice(self.maker_secret.as_ref())
            .map_err(|_| LiveBitcoinError::CorruptRecord)?;
        let taker_secret = SecretKey::from_slice(self.taker_secret.as_ref())
            .map_err(|_| LiveBitcoinError::CorruptRecord)?;
        let maker_key = PublicKey::from_secret_key(&secp, &maker_secret).serialize();
        let taker_key = PublicKey::from_secret_key(&secp, &taker_secret).serialize();
        if self.claim_roster.participants()[0].role != BitcoinSignerRoleV1::Maker
            || self.claim_roster.participants()[1].role != BitcoinSignerRoleV1::Taker
            || self.claim_roster.participants()[0].compressed_key != maker_key
            || self.claim_roster.participants()[1].compressed_key != taker_key
        {
            return Err(LiveBitcoinError::CorruptRecord);
        }

        // F1-PUBLIC-ONLY: deliberately a constant seed. This context only
        // aggregates public keys and builds the taproot contract; no secret
        // passes through it, so there is nothing for randomization to blind.
        // Kept constant so the contract derivation stays reproducible.
        let context = SecpContext::new(&[0x5a; 32]);
        let contract = build_taproot_contract(
            &context,
            &self.claim_roster,
            &self.refund_key_xonly,
            csv_delay(self.refund_delay),
        )
        .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        if contract.script_pubkey != self.contract_script_pubkey
            || contract.refund_leaf.refund_key_xonly != self.refund_key_xonly
            || contract.refund_leaf.delay != csv_delay(self.refund_delay)
            || contract.script_pubkey.len() != 34
            || contract.script_pubkey[0..2] != [0x51, 0x20]
            || contract.script_pubkey[2..] != contract.output_key_xonly
        {
            return Err(LiveBitcoinError::ClaimMismatch);
        }

        let transaction = exact_claim_transaction(&binding)?;
        let template = exact_claim_template(
            &transaction,
            &binding,
            &contract.script_pubkey,
            template_network(self.network),
        );
        let template_digest =
            frozen_template_digest_v1(&template).map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        if template_digest != self.claim_template_hash
            || template_digest != binding.expected_template_hash
        {
            return Err(LiveBitcoinError::ClaimMismatch);
        }
        Ok(BoundFreshBitcoinClaimAuthorityV1 {
            contract,
            template_digest,
        })
    }
}

/// Opaque real-wallet preparation plus its retained one-shot refund signer.
///
/// This value has no constructor, codec, `Clone`, or `Debug` implementation.
/// The exact public plan can be inspected for higher-layer authentication;
/// consuming the value transfers the prepared funding and signer together.
pub struct PreparedFreshBitcoinRouteV1 {
    plan: BitcoinPrebroadcastPlanV1,
    prepared: PreparedBitcoinFundingV1,
    receipt: BitcoinFreshRouteReceiptV1,
    payout_face: Option<AuthenticatedBitcoinPayoutFaceV1>,
    signer: RetainedFreshBitcoinRefundSignerV1,
}

/// Production-safe restart authority for an already refund-armed fresh route.
///
/// This value is reconstructed solely from the secret-free receipt and generic
/// funding records. Opening it never reads or decodes the legacy record
/// containing both cooperative claim keys. It can therefore move only funding
/// custody and public payout evidence into the production composition root.
pub struct ReopenedFreshBitcoinFundingRouteV1 {
    plan: BitcoinPrebroadcastPlanV1,
    receipt: BitcoinFreshRouteReceiptV1,
    payout_face: Option<AuthenticatedBitcoinPayoutFaceV1>,
    armed: ArmedBitcoinFundingV1,
}

impl ReopenedFreshBitcoinFundingRouteV1 {
    /// Exact public plan authenticated without opening bilateral claim keys.
    #[must_use]
    pub const fn plan(&self) -> &BitcoinPrebroadcastPlanV1 {
        &self.plan
    }

    /// Persisted secret-free template receipt authenticated at restart.
    #[must_use]
    pub const fn receipt(&self) -> &BitcoinFreshRouteReceiptV1 {
        &self.receipt
    }

    /// Takes the exact owner-authenticated payout face once.
    pub fn take_payout_face_evidence(
        &mut self,
    ) -> Result<AuthenticatedBitcoinPayoutFaceV1, LiveBitcoinError> {
        take_payout_face_evidence(&mut self.payout_face)
    }

    /// Consumes the production-safe restart state into public plan metadata and
    /// the sole armed funding capability.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BitcoinPrebroadcastPlanV1,
        BitcoinFreshRouteReceiptV1,
        ArmedBitcoinFundingV1,
    ) {
        (self.plan, self.receipt, self.armed)
    }
}

impl PreparedFreshBitcoinRouteV1 {
    /// Exact public plan whose wallet funding has been prepared.
    #[must_use]
    pub const fn plan(&self) -> &BitcoinPrebroadcastPlanV1 {
        &self.plan
    }

    /// Public template receipt needed to construct the final manifest.
    #[must_use]
    pub const fn receipt(&self) -> &BitcoinFreshRouteReceiptV1 {
        &self.receipt
    }

    /// Takes the exact owner-authenticated payout face once.
    pub fn take_payout_face_evidence(
        &mut self,
    ) -> Result<AuthenticatedBitcoinPayoutFaceV1, LiveBitcoinError> {
        take_payout_face_evidence(&mut self.payout_face)
    }

    /// Consumes the pre-bootstrap authority after the route layer has
    /// authenticated its plan and receipt against the final bootstrap.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        BitcoinPrebroadcastPlanV1,
        PreparedBitcoinFundingV1,
        RetainedFreshBitcoinRefundSignerV1,
    ) {
        (self.plan, self.prepared, self.signer)
    }
}

fn take_payout_face_evidence(
    retained: &mut Option<AuthenticatedBitcoinPayoutFaceV1>,
) -> Result<AuthenticatedBitcoinPayoutFaceV1, LiveBitcoinError> {
    retained.take().ok_or(LiveBitcoinError::StateConflict)
}

/// Retained one-shot signer for the fresh route's exact CSV refund.
///
/// The secret is generated from operating-system entropy and reopened only
/// from the owner-only authenticated store.  No raw-key getter exists.
pub struct RetainedFreshBitcoinRefundSignerV1 {
    route_binding: [u8; 32],
    plan_digest: [u8; 32],
    prepared_record_digest: [u8; 32],
    summary_record_digest: [u8; 32],
    funding_txid: [u8; 32],
    contract_vout: u32,
    contract_amount_sat: u64,
    refund_key_xonly: [u8; 32],
    refund_delay: BitcoinRefundDelayV1,
    secret: Zeroizing<[u8; 32]>,
}

impl RetainedBitcoinRefundSignerV1 for RetainedFreshBitcoinRefundSignerV1 {
    fn refund_key_xonly(&self) -> [u8; 32] {
        self.refund_key_xonly
    }

    fn sign_refund(
        self,
        request: BitcoinRefundSigningRequestV1,
    ) -> Result<BitcoinRefundSignatureV1, LiveBitcoinError> {
        if request.route_binding() != self.route_binding
            || request.plan_digest() != self.plan_digest
            || request.prepared_record_digest() != self.prepared_record_digest
            || request.summary_record_digest() != self.summary_record_digest
            || request.funding_txid() != self.funding_txid
            || request.contract_vout() != self.contract_vout
            || request.contract_amount_sat() != self.contract_amount_sat
            || request.refund_key_xonly() != self.refund_key_xonly
            || request.refund_delay() != self.refund_delay
        {
            return Err(LiveBitcoinError::RefundMismatch);
        }
        let context_seed = fresh_entropy()?;
        let auxiliary_randomness = fresh_entropy()?;
        let context = SecpContext::new(&context_seed);
        let (signature, public_key) = context
            .sign_bip340(&self.secret, &request.sighash(), &auxiliary_randomness)
            .map_err(|_| LiveBitcoinError::RefundMismatch)?;
        if public_key != self.refund_key_xonly {
            return Err(LiveBitcoinError::RefundMismatch);
        }
        BitcoinRefundSignatureV1::from_bytes(signature)
    }
}

struct FreshAuthorityRecord {
    network: BitcoinCoreNetworkV1,
    genesis_hash: [u8; 32],
    signet_challenge: Option<Vec<u8>>,
    request: BitcoinFreshRouteRequestV1,
    claim_script_pubkey: Vec<u8>,
    refund_script_pubkey: Vec<u8>,
    maker_secret: Zeroizing<[u8; 32]>,
    taker_secret: Zeroizing<[u8; 32]>,
    refund_secret: Zeroizing<[u8; 32]>,
}

impl BitcoinPrebroadcastStoreV1 {
    /// Reopens the exact MAC-authenticated post-M.8 claim without touching a
    /// nonce vault or creating another signing attempt.
    ///
    /// The caller must repeat the complete route-visible binding. A record
    /// copied from another route, settlement, session, terms set, funding
    /// output, destination, template, or adaptor point is refused.
    pub fn reopen_fresh_claim(
        &self,
        expected: &BitcoinFreshClaimBindingV1,
    ) -> Result<Option<ReopenedFreshBitcoinClaimV1>, LiveBitcoinError> {
        let intent = self.store.read(StageKind::FreshClaimIntent)?;
        let prepared = self.store.read(StageKind::FreshClaimPrepared)?;
        let finalization_intent = self.store.read(StageKind::FreshClaimFinalizationIntent)?;
        let finalized = self.store.read(StageKind::FreshClaimFinalized)?;
        let (intent, encoded) = match (intent, prepared, &finalization_intent, &finalized) {
            (None, None, None, None) => return Ok(None),
            (Some(intent), Some(prepared), None, None)
            | (Some(intent), Some(prepared), Some(_), None)
            | (Some(intent), Some(prepared), Some(_), Some(_)) => (intent, prepared),
            _ => return Err(LiveBitcoinError::StateConflict),
        };
        let intended_public = decode_claim_intent(&intent)?;
        let record = decode_prepared_claim_record(&encoded)?;
        validate_prepared_claim_store(self, &record)?;
        if record.public != intended_public || !prepared_claim_matches_binding(&record, expected) {
            return Err(LiveBitcoinError::StateConflict);
        }
        let record_digest = digest(CLAIM_PREPARED_DIGEST_DOMAIN, &encoded)?;
        let prepared = PreparedFreshBitcoinClaimV1 {
            record,
            record_digest,
            authority_instance: Rc::clone(&self.authority_instance),
        };
        let reopened = match (finalization_intent, finalized) {
            (None, None) => ReopenedFreshBitcoinClaimV1::Prepared(prepared),
            (Some(intent), None) => {
                let intent = decode_finalization_intent(&intent)?;
                let extraction = prepared.extraction_authority()?;
                if intent.prepared_record_digest != extraction.prepared_record_digest
                    || intent.expected_txid != extraction.expected_txid
                    || intent.extraction_context_digest != extraction.context_digest()?
                {
                    return Err(LiveBitcoinError::StateConflict);
                }
                ReopenedFreshBitcoinClaimV1::ExtractionReady(prepared)
            }
            (Some(intent), Some(finalized)) => {
                let intent = decode_finalization_intent(&intent)?;
                let public = prepared.public().clone();
                let extraction = prepared.into_public_extraction_authority()?;
                if intent.prepared_record_digest != extraction.prepared_record_digest
                    || intent.expected_txid != extraction.expected_txid
                    || intent.extraction_context_digest != extraction.context_digest()?
                {
                    return Err(LiveBitcoinError::StateConflict);
                }
                let finalized = decode_finalized_claim(&finalized)?;
                validate_finalized_claim_record(&finalized, &extraction)?;
                ReopenedFreshBitcoinClaimV1::Finalized(FinalizedFreshBitcoinClaimV1 {
                    public,
                    canonical_transaction: finalized.canonical_transaction,
                    extraction,
                })
            }
            _ => return Err(LiveBitcoinError::StateConflict),
        };
        self.issue_fresh_claim_authority()?;
        Ok(Some(reopened))
    }

    fn issue_fresh_claim_authority(&self) -> Result<(), LiveBitcoinError> {
        if self.fresh_claim_issued.replace(true) {
            return Err(LiveBitcoinError::StateConflict);
        }
        Ok(())
    }

    /// Creates or reopens a genuine fresh Bitcoin route before the complete
    /// cross-chain manifest exists.
    ///
    /// Bitcoin Core generates and proves ownership of distinct claim/refund
    /// destinations.  Three canonical secp256k1 keys are generated from OS
    /// entropy and persisted in the same authenticated owner-only store.  The
    /// wallet then selects and locks real inputs.  Only after that selection
    /// are the exact funding, claim, and refund template hashes published.
    /// Harness-only: prepares maker and taker material in one store. The
    /// production composition never calls this (its dual-key shape is the
    /// stage-6 finding this gate closes); e2e harnesses opt in explicitly.
    #[cfg(any(test, feature = "harness"))]
    pub fn prepare_fresh_route(
        &self,
        rpc: &BitcoinCoreRpcClientV1,
        request: BitcoinFreshRouteRequestV1,
    ) -> Result<PreparedFreshBitcoinRouteV1, LiveBitcoinError> {
        validate_request(request)?;
        let authority = self.load_or_create_fresh_authority(rpc, request)?;
        let (plan, roster, refund_key_xonly) = plan_for(&authority)?;
        let prepared = self.prepare(rpc, &plan)?;
        let claim_output = BitcoinRefundOutputV1 {
            amount_sat: request
                .amount_sat
                .checked_sub(request.claim_fee_sat)
                .ok_or(LiveBitcoinError::InvalidRequest)?,
            script_pubkey: authority.claim_script_pubkey.clone(),
        };
        let [funding_template_hash, claim_template_hash, refund_template_hash] =
            prepared_template_digests(rpc, &prepared, &claim_output)?;
        let summary = prepared.funding_summary();
        let refund_output = plan
            .refund_outputs
            .first()
            .cloned()
            .ok_or(LiveBitcoinError::InvalidRequest)?;
        if plan.refund_outputs.len() != 1 {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        let mut receipt = BitcoinFreshRouteReceiptV1 {
            route_binding: request.route_binding,
            plan_digest: plan.canonical_digest()?,
            prepared_record_digest: prepared.prepared_record_digest(),
            summary_record_digest: summary.summary_record_digest(),
            funding_txid: prepared.funding_txid(),
            funding_wtxid: prepared.funding_wtxid(),
            contract_vout: prepared.contract_vout(),
            contract_amount_sat: prepared.contract_amount_sat(),
            actual_funding_fee_sat: summary.actual_fee_sat(),
            funding_virtual_size_vb: summary.virtual_size_vb(),
            claim_roster: roster,
            refund_key_xonly,
            contract_script_pubkey: plan.contract_script_pubkey.clone(),
            claim_output,
            refund_output,
            funding_template_hash,
            claim_template_hash,
            refund_template_hash,
            receipt_digest: [0; 32],
        };
        receipt.receipt_digest = receipt_digest(&receipt)?;
        validate_receipt(&receipt, &plan, &prepared)?;
        let encoded = encode_receipt(&receipt)?;
        self.store.publish(StageKind::FreshTemplates, &encoded)?;
        let exact = self
            .store
            .read(StageKind::FreshTemplates)?
            .ok_or(LiveBitcoinError::StoreUnavailable)?;
        let persisted = decode_receipt(&exact)?;
        if persisted != receipt {
            return Err(LiveBitcoinError::StateConflict);
        }
        let payout_face = self.load_fresh_payout_face(&persisted, true)?;
        let signer = RetainedFreshBitcoinRefundSignerV1 {
            route_binding: receipt.route_binding,
            plan_digest: receipt.plan_digest,
            prepared_record_digest: receipt.prepared_record_digest,
            summary_record_digest: receipt.summary_record_digest,
            funding_txid: receipt.funding_txid,
            contract_vout: receipt.contract_vout,
            contract_amount_sat: receipt.contract_amount_sat,
            refund_key_xonly: receipt.refund_key_xonly,
            refund_delay: request.refund_delay,
            secret: authority.refund_secret,
        };
        Ok(PreparedFreshBitcoinRouteV1 {
            plan,
            prepared,
            receipt: persisted,
            payout_face: Some(payout_face),
            signer,
        })
    }

    /// Reopens only the secret-free, refund-armed funding side of a fresh route.
    ///
    /// This is the production composition entrypoint. It deliberately does not
    /// read `FreshAuthority`, whose legacy V1 encoding contains both cooperative
    /// claim private keys. The exact plan is instead reconstructed from the
    /// MAC-authenticated public receipt and authenticated generic funding
    /// summary, then compared against the durable Armed capability.
    pub fn reopen_fresh_funding_route(
        &self,
        rpc: &BitcoinCoreRpcClientV1,
        expected_route_binding: [u8; 32],
    ) -> Result<ReopenedFreshBitcoinFundingRouteV1, LiveBitcoinError> {
        if expected_route_binding == [0; 32] {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        let receipt_bytes = self
            .store
            .read(StageKind::FreshTemplates)?
            .ok_or(LiveBitcoinError::CorruptRecord)?;
        let receipt = decode_receipt(&receipt_bytes)?;
        if receipt.route_binding != expected_route_binding {
            return Err(LiveBitcoinError::StateConflict);
        }
        let armed = match self.reopen(rpc, expected_route_binding)? {
            Some(ReopenedBitcoinFundingV1::Armed(armed)) => armed,
            Some(ReopenedBitcoinFundingV1::Prepared(_)) | None => {
                return Err(LiveBitcoinError::FundingNotArmed);
            }
        };
        let (plan, request) = funding_only_plan_and_request(&receipt, &armed)?;
        validate_reopened_receipt(ReopenedReceiptValidationV1 {
            receipt: &receipt,
            plan: &plan,
            request,
            roster: receipt.claim_roster,
            refund_key_xonly: receipt.refund_key_xonly,
            claim_script_pubkey: &receipt.claim_output.script_pubkey,
            refund_script_pubkey: &receipt.refund_output.script_pubkey,
            armed: &armed,
        })?;
        let payout_face = self.load_fresh_payout_face(&receipt, false)?;
        Ok(ReopenedFreshBitcoinFundingRouteV1 {
            plan,
            receipt,
            payout_face: Some(payout_face),
            armed,
        })
    }

    fn load_fresh_payout_face(
        &self,
        receipt: &BitcoinFreshRouteReceiptV1,
        create_if_missing: bool,
    ) -> Result<AuthenticatedBitcoinPayoutFaceV1, LiveBitcoinError> {
        let bytes = match self.store.read(StageKind::FreshFaceEvidence)? {
            Some(bytes) => bytes,
            None if create_if_missing => {
                let record = fresh_payout_face_record(receipt)?;
                let bytes = encode_fresh_payout_face_record(&record)?;
                self.store.publish(StageKind::FreshFaceEvidence, &bytes)?;
                self.store
                    .read(StageKind::FreshFaceEvidence)?
                    .ok_or(LiveBitcoinError::StoreUnavailable)?
            }
            None => return Err(LiveBitcoinError::CorruptRecord),
        };
        let record = decode_fresh_payout_face_record(&bytes)?;
        validate_fresh_payout_face_record(&record, receipt)?;
        authenticated_payout_face(record)
    }

    #[cfg(any(test, feature = "harness"))]
    fn load_or_create_fresh_authority(
        &self,
        rpc: &BitcoinCoreRpcClientV1,
        request: BitcoinFreshRouteRequestV1,
    ) -> Result<FreshAuthorityRecord, LiveBitcoinError> {
        if let Some(bytes) = self.store.read(StageKind::FreshAuthority)? {
            let bytes = Zeroizing::new(bytes);
            let record = decode_authority(bytes.as_ref())?;
            require_authority_binding(rpc, request, &record)?;
            return Ok(record);
        }
        rpc.require_chain_identity()?;
        let claim_script_pubkey = rpc.fresh_wallet_destination_script("f7-claim")?;
        let refund_script_pubkey = rpc.fresh_wallet_destination_script("f7-refund")?;
        if claim_script_pubkey == refund_script_pubkey {
            return Err(LiveBitcoinError::IdentityMismatch);
        }
        let record = FreshAuthorityRecord {
            network: rpc.network(),
            genesis_hash: rpc.genesis_hash(),
            signet_challenge: rpc.signet_challenge().map(ToOwned::to_owned),
            request,
            claim_script_pubkey,
            refund_script_pubkey,
            maker_secret: fresh_secret()?,
            taker_secret: fresh_secret()?,
            refund_secret: fresh_secret()?,
        };
        plan_for(&record)?;
        rpc.require_chain_identity()?;
        let encoded = Zeroizing::new(encode_authority(&record)?);
        self.store
            .publish(StageKind::FreshAuthority, encoded.as_ref())?;
        let exact = Zeroizing::new(
            self.store
                .read(StageKind::FreshAuthority)?
                .ok_or(LiveBitcoinError::StoreUnavailable)?,
        );
        let persisted = decode_authority(exact.as_ref())?;
        require_authority_binding(rpc, request, &persisted)?;
        Ok(persisted)
    }
}

fn funding_only_plan_and_request(
    receipt: &BitcoinFreshRouteReceiptV1,
    armed: &ArmedBitcoinFundingV1,
) -> Result<(BitcoinPrebroadcastPlanV1, BitcoinFreshRouteRequestV1), LiveBitcoinError> {
    let summary = armed.funding_summary();
    funding_only_plan_and_request_from_public(
        receipt,
        summary.requested_fee_rate_sat_vb(),
        summary.refund_delay(),
    )
}

fn funding_only_plan_and_request_from_public(
    receipt: &BitcoinFreshRouteReceiptV1,
    funding_fee_rate_sat_vb: u64,
    refund_delay: BitcoinRefundDelayV1,
) -> Result<(BitcoinPrebroadcastPlanV1, BitcoinFreshRouteRequestV1), LiveBitcoinError> {
    let claim_fee_sat = receipt
        .contract_amount_sat
        .checked_sub(receipt.claim_output.amount_sat)
        .filter(|fee| *fee != 0)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let refund_fee_sat = receipt
        .contract_amount_sat
        .checked_sub(receipt.refund_output.amount_sat)
        .filter(|fee| *fee != 0)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let participants = receipt.claim_roster.participants();
    let request = BitcoinFreshRouteRequestV1 {
        route_binding: receipt.route_binding,
        participant_ids: [
            participants[0].participant_id,
            participants[1].participant_id,
        ],
        amount_sat: receipt.contract_amount_sat,
        funding_fee_rate_sat_vb,
        claim_fee_sat,
        refund_fee_sat,
        refund_delay,
    };
    validate_request(request)?;
    let context = SecpContext::new(&*fresh_entropy()?);
    let contract = build_taproot_contract(
        &context,
        &receipt.claim_roster,
        &receipt.refund_key_xonly,
        csv_delay(request.refund_delay),
    )
    .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if contract.script_pubkey != receipt.contract_script_pubkey {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let plan = BitcoinPrebroadcastPlanV1 {
        route_binding: request.route_binding,
        amount_sat: request.amount_sat,
        contract_script_pubkey: contract.script_pubkey,
        refund_contract: BitcoinRefundContractV1 {
            script: contract.refund_leaf.script,
            control_block: contract.control_block,
            refund_key_xonly: receipt.refund_key_xonly,
            sequence: request.refund_delay.sequence(),
        },
        refund_outputs: vec![BitcoinRefundOutputV1 {
            amount_sat: receipt.refund_output.amount_sat,
            script_pubkey: receipt.refund_output.script_pubkey.clone(),
        }],
        fee_rate_sat_vb: request.funding_fee_rate_sat_vb,
    };
    Ok((plan, request))
}

fn validate_request(request: BitcoinFreshRouteRequestV1) -> Result<(), LiveBitcoinError> {
    let delay = BitcoinRefundDelayV1::from_sequence(request.refund_delay.sequence())?;
    if request.route_binding == [0; 32]
        || request.participant_ids[0] == [0; 32]
        || request.participant_ids[1] == [0; 32]
        || request.participant_ids[0] == request.participant_ids[1]
        || request.amount_sat == 0
        || request.amount_sat > MAX_MONEY_SAT
        || request.funding_fee_rate_sat_vb == 0
        || request.funding_fee_rate_sat_vb > MAX_FEE_RATE_SAT_VB
        || request.claim_fee_sat == 0
        || request.claim_fee_sat >= request.amount_sat
        || request.refund_fee_sat == 0
        || request.refund_fee_sat >= request.amount_sat
        || delay != request.refund_delay
    {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    Ok(())
}

#[cfg(any(test, feature = "harness"))]
fn require_authority_binding(
    rpc: &BitcoinCoreRpcClientV1,
    request: BitcoinFreshRouteRequestV1,
    record: &FreshAuthorityRecord,
) -> Result<(), LiveBitcoinError> {
    validate_request(request)?;
    if record.network != rpc.network()
        || record.genesis_hash != rpc.genesis_hash()
        || record.signet_challenge.as_deref() != rpc.signet_challenge()
        || record.request != request
        || record.claim_script_pubkey.is_empty()
        || record.claim_script_pubkey.len() > MAX_SCRIPT_BYTES
        || record.refund_script_pubkey.is_empty()
        || record.refund_script_pubkey.len() > MAX_SCRIPT_BYTES
        || record.claim_script_pubkey == record.refund_script_pubkey
    {
        return Err(LiveBitcoinError::StateConflict);
    }
    plan_for(record)?;
    rpc.require_chain_identity()
}

#[cfg(any(test, feature = "harness"))]
fn plan_for(
    record: &FreshAuthorityRecord,
) -> Result<(BitcoinPrebroadcastPlanV1, ParticipantKeyRosterV1, [u8; 32]), LiveBitcoinError> {
    // Audit finding F1: this context derives public keys and a keypair from
    // all three route secrets, so it is randomized before it touches them.
    let mut secp = Secp256k1::new();
    secp.seeded_randomize(&*fresh_entropy()?);
    let maker_secret = SecretKey::from_slice(record.maker_secret.as_ref())
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    let taker_secret = SecretKey::from_slice(record.taker_secret.as_ref())
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    let refund_secret = SecretKey::from_slice(record.refund_secret.as_ref())
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    let maker_key = PublicKey::from_secret_key(&secp, &maker_secret).serialize();
    let taker_key = PublicKey::from_secret_key(&secp, &taker_secret).serialize();
    let refund_keypair = Keypair::from_secret_key(&secp, &refund_secret);
    let (refund_key, _) = XOnlyPublicKey::from_keypair(&refund_keypair);
    let refund_key_xonly = refund_key.serialize();
    let roster = ParticipantKeyRosterV1::new([
        ParticipantKeyV1 {
            participant_id: record.request.participant_ids[0],
            role: BitcoinSignerRoleV1::Maker,
            compressed_key: maker_key,
        },
        ParticipantKeyV1 {
            participant_id: record.request.participant_ids[1],
            role: BitcoinSignerRoleV1::Taker,
            compressed_key: taker_key,
        },
    ])
    .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    let context_seed = fresh_entropy()?;
    let context = SecpContext::new(&context_seed);
    let contract = build_taproot_contract(
        &context,
        &roster,
        &refund_key_xonly,
        csv_delay(record.request.refund_delay),
    )
    .map_err(|_| LiveBitcoinError::InvalidRequest)?;
    let plan = plan_from_contract(record, contract, refund_key_xonly)?;
    Ok((plan, roster, refund_key_xonly))
}

#[cfg(any(test, feature = "harness"))]
fn plan_from_contract(
    record: &FreshAuthorityRecord,
    contract: TaprootContractV1,
    refund_key_xonly: [u8; 32],
) -> Result<BitcoinPrebroadcastPlanV1, LiveBitcoinError> {
    let refund_amount = record
        .request
        .amount_sat
        .checked_sub(record.request.refund_fee_sat)
        .filter(|amount| *amount > 0)
        .ok_or(LiveBitcoinError::InvalidRequest)?;
    Ok(BitcoinPrebroadcastPlanV1 {
        route_binding: record.request.route_binding,
        amount_sat: record.request.amount_sat,
        contract_script_pubkey: contract.script_pubkey,
        refund_contract: BitcoinRefundContractV1 {
            script: contract.refund_leaf.script,
            control_block: contract.control_block,
            refund_key_xonly,
            sequence: record.request.refund_delay.sequence(),
        },
        refund_outputs: vec![BitcoinRefundOutputV1 {
            amount_sat: refund_amount,
            script_pubkey: record.refund_script_pubkey.clone(),
        }],
        fee_rate_sat_vb: record.request.funding_fee_rate_sat_vb,
    })
}

const fn csv_delay(delay: BitcoinRefundDelayV1) -> BitcoinCsvDelayV1 {
    match delay {
        BitcoinRefundDelayV1::Blocks(units) => BitcoinCsvDelayV1::Blocks(units),
        BitcoinRefundDelayV1::Time512Seconds(units) => BitcoinCsvDelayV1::Time512s(units),
    }
}

fn exact_claim_transaction(
    binding: &BitcoinFreshClaimBindingV1,
) -> Result<Transaction, LiveBitcoinError> {
    let output_amount = binding
        .funding_amount_sat
        .checked_sub(binding.fee_sat)
        .filter(|amount| *amount > 0)
        .ok_or(LiveBitcoinError::ClaimMismatch)?;
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
        binding.funding_txid,
    ));
    Ok(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid,
                vout: binding.funding_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_amount),
            script_pubkey: ScriptBuf::from_bytes(binding.destination_script_pubkey.clone()),
        }],
    })
}

fn exact_claim_template(
    transaction: &Transaction,
    binding: &BitcoinFreshClaimBindingV1,
    contract_script_pubkey: &[u8],
    network: TemplateNetworkV1,
) -> FrozenBitcoinTemplateV1 {
    FrozenBitcoinTemplateV1 {
        codec_version: 1,
        network,
        version: transaction.version.0,
        lock_time: transaction.lock_time.to_consensus_u32(),
        inputs: vec![BitcoinTxInV1 {
            txid: binding.funding_txid,
            vout: binding.funding_vout,
            sequence: transaction.input[0].sequence.0,
        }],
        outputs: vec![BitcoinTxOutV1 {
            amount_sat: transaction.output[0].value.to_sat(),
            script_pubkey: transaction.output[0].script_pubkey.as_bytes().to_vec(),
        }],
        prevouts: vec![BitcoinPrevoutV1 {
            txid: binding.funding_txid,
            vout: binding.funding_vout,
            amount_sat: binding.funding_amount_sat,
            script_pubkey: contract_script_pubkey.to_vec(),
        }],
    }
}

const fn template_network(network: BitcoinCoreNetworkV1) -> TemplateNetworkV1 {
    match network {
        BitcoinCoreNetworkV1::Regtest => TemplateNetworkV1::Regtest,
        BitcoinCoreNetworkV1::PublicSignet => TemplateNetworkV1::PublicSignet,
        BitcoinCoreNetworkV1::CustomSignet => TemplateNetworkV1::CustomSignet,
    }
}

#[cfg(any(test, feature = "harness"))]
fn fresh_secret() -> Result<Zeroizing<[u8; 32]>, LiveBitcoinError> {
    for _ in 0..MAX_KEY_ATTEMPTS {
        let secret = fresh_entropy()?;
        if SecretKey::from_slice(secret.as_ref()).is_ok() {
            return Ok(secret);
        }
    }
    Err(LiveBitcoinError::StoreUnavailable)
}

fn fresh_entropy() -> Result<Zeroizing<[u8; 32]>, LiveBitcoinError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(bytes.as_mut()).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(LiveBitcoinError::StoreUnavailable);
    }
    Ok(bytes)
}

fn fresh_payout_face_record(
    receipt: &BitcoinFreshRouteReceiptV1,
) -> Result<FreshPayoutFaceEvidenceRecordV1, LiveBitcoinError> {
    let mut record = FreshPayoutFaceEvidenceRecordV1 {
        revision: FACE_EVIDENCE_REVISION,
        route_binding: receipt.route_binding,
        receipt_digest: receipt.receipt_digest,
        contract_amount_sat: receipt.contract_amount_sat,
        claim_destination_script_pubkey: receipt.claim_output.script_pubkey.clone(),
        claim_output_amount_sat: receipt.claim_output.amount_sat,
        claim_template_hash: receipt.claim_template_hash,
        record_digest: [0; 32],
    };
    record.record_digest = fresh_payout_face_record_digest(&record)?;
    validate_fresh_payout_face_record(&record, receipt)?;
    Ok(record)
}

fn validate_fresh_payout_face_record(
    record: &FreshPayoutFaceEvidenceRecordV1,
    receipt: &BitcoinFreshRouteReceiptV1,
) -> Result<(), LiveBitcoinError> {
    if record.revision != FACE_EVIDENCE_REVISION
        || record.route_binding == [0; 32]
        || record.route_binding != receipt.route_binding
        || record.receipt_digest == [0; 32]
        || record.receipt_digest != receipt.receipt_digest
        || record.contract_amount_sat == 0
        || record.contract_amount_sat != receipt.contract_amount_sat
        || record.claim_destination_script_pubkey.is_empty()
        || record.claim_destination_script_pubkey.len() > MAX_SCRIPT_BYTES
        || record.claim_destination_script_pubkey != receipt.claim_output.script_pubkey
        || record.claim_output_amount_sat == 0
        || record.claim_output_amount_sat != receipt.claim_output.amount_sat
        || record.claim_template_hash == [0; 32]
        || record.claim_template_hash != receipt.claim_template_hash
        || record.record_digest == [0; 32]
        || record.record_digest != fresh_payout_face_record_digest(record)?
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(())
}

fn authenticated_payout_face(
    record: FreshPayoutFaceEvidenceRecordV1,
) -> Result<AuthenticatedBitcoinPayoutFaceV1, LiveBitcoinError> {
    if record.revision == 0
        || record.route_binding == [0; 32]
        || record.receipt_digest == [0; 32]
        || record.contract_amount_sat == 0
        || record.claim_destination_script_pubkey.is_empty()
        || record.claim_output_amount_sat == 0
        || record.claim_template_hash == [0; 32]
        || record.record_digest == [0; 32]
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(AuthenticatedBitcoinPayoutFaceV1 {
        revision: record.revision,
        route_binding: record.route_binding,
        receipt_digest: record.receipt_digest,
        contract_amount_sat: record.contract_amount_sat,
        claim_destination_script_pubkey: record.claim_destination_script_pubkey,
        claim_output_amount_sat: record.claim_output_amount_sat,
        claim_template_hash: record.claim_template_hash,
        evidence_digest: record.record_digest,
    })
}

fn encode_fresh_payout_face_record_without_digest(
    record: &FreshPayoutFaceEvidenceRecordV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    let mut output = Vec::new();
    output.extend_from_slice(FACE_EVIDENCE_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&record.revision.to_be_bytes());
    output.extend_from_slice(&record.route_binding);
    output.extend_from_slice(&record.receipt_digest);
    output.extend_from_slice(&record.contract_amount_sat.to_be_bytes());
    put_bytes(&mut output, &record.claim_destination_script_pubkey)?;
    output.extend_from_slice(&record.claim_output_amount_sat.to_be_bytes());
    output.extend_from_slice(&record.claim_template_hash);
    Ok(output)
}

fn fresh_payout_face_record_digest(
    record: &FreshPayoutFaceEvidenceRecordV1,
) -> Result<[u8; 32], LiveBitcoinError> {
    digest(
        FACE_EVIDENCE_DIGEST_DOMAIN,
        &encode_fresh_payout_face_record_without_digest(record)?,
    )
}

fn encode_fresh_payout_face_record(
    record: &FreshPayoutFaceEvidenceRecordV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    if record.record_digest != fresh_payout_face_record_digest(record)? {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let mut output = encode_fresh_payout_face_record_without_digest(record)?;
    output.extend_from_slice(&record.record_digest);
    Ok(output)
}

fn decode_fresh_payout_face_record(
    bytes: &[u8],
) -> Result<FreshPayoutFaceEvidenceRecordV1, LiveBitcoinError> {
    let mut cursor = FreshCursor::new(bytes);
    cursor.require_header(FACE_EVIDENCE_MAGIC)?;
    let record = FreshPayoutFaceEvidenceRecordV1 {
        revision: cursor.take_u64()?,
        route_binding: cursor.take_array()?,
        receipt_digest: cursor.take_array()?,
        contract_amount_sat: cursor.take_u64()?,
        claim_destination_script_pubkey: cursor.take_bytes(MAX_SCRIPT_BYTES)?,
        claim_output_amount_sat: cursor.take_u64()?,
        claim_template_hash: cursor.take_array()?,
        record_digest: cursor.take_array()?,
    };
    cursor.finish()?;
    if record.revision != FACE_EVIDENCE_REVISION
        || record.record_digest != fresh_payout_face_record_digest(&record)?
        || encode_fresh_payout_face_record(&record)?.as_slice() != bytes
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(record)
}

fn receipt_digest(receipt: &BitcoinFreshRouteReceiptV1) -> Result<[u8; 32], LiveBitcoinError> {
    digest(
        RECEIPT_DIGEST_DOMAIN,
        &encode_receipt_without_digest(receipt)?,
    )
}

#[cfg(any(test, feature = "harness"))]
fn validate_receipt(
    receipt: &BitcoinFreshRouteReceiptV1,
    plan: &BitcoinPrebroadcastPlanV1,
    prepared: &PreparedBitcoinFundingV1,
) -> Result<(), LiveBitcoinError> {
    let summary = prepared.funding_summary();
    let templates = [
        receipt.funding_template_hash,
        receipt.claim_template_hash,
        receipt.refund_template_hash,
    ];
    receipt
        .claim_roster
        .validate()
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if receipt.route_binding == [0; 32]
        || receipt.route_binding != plan.route_binding
        || receipt.plan_digest == [0; 32]
        || receipt.plan_digest != plan.canonical_digest()?
        || receipt.prepared_record_digest != prepared.prepared_record_digest()
        || receipt.summary_record_digest != summary.summary_record_digest()
        || receipt.funding_txid != prepared.funding_txid()
        || receipt.funding_wtxid != prepared.funding_wtxid()
        || receipt.contract_vout != prepared.contract_vout()
        || receipt.contract_amount_sat != prepared.contract_amount_sat()
        || receipt.actual_funding_fee_sat == 0
        || receipt.actual_funding_fee_sat != summary.actual_fee_sat()
        || receipt.funding_virtual_size_vb == 0
        || receipt.funding_virtual_size_vb != summary.virtual_size_vb()
        || receipt.refund_key_xonly != plan.refund_contract.refund_key_xonly
        || receipt.contract_script_pubkey != plan.contract_script_pubkey
        || receipt.claim_output.amount_sat == 0
        || receipt.claim_output.amount_sat >= receipt.contract_amount_sat
        || receipt.claim_output.script_pubkey.is_empty()
        || plan.refund_outputs.len() != 1
        || receipt.refund_output != plan.refund_outputs[0]
        || templates.contains(&[0; 32])
        || templates[0] == templates[1]
        || templates[0] == templates[2]
        || templates[1] == templates[2]
        || receipt.receipt_digest == [0; 32]
        || receipt.receipt_digest != receipt_digest(receipt)?
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(())
}

struct ReopenedReceiptValidationV1<'a> {
    receipt: &'a BitcoinFreshRouteReceiptV1,
    plan: &'a BitcoinPrebroadcastPlanV1,
    request: BitcoinFreshRouteRequestV1,
    roster: ParticipantKeyRosterV1,
    refund_key_xonly: [u8; 32],
    claim_script_pubkey: &'a [u8],
    refund_script_pubkey: &'a [u8],
    armed: &'a ArmedBitcoinFundingV1,
}

fn validate_reopened_receipt(
    validation: ReopenedReceiptValidationV1<'_>,
) -> Result<(), LiveBitcoinError> {
    let ReopenedReceiptValidationV1 {
        receipt,
        plan,
        request,
        roster,
        refund_key_xonly,
        claim_script_pubkey,
        refund_script_pubkey,
        armed,
    } = validation;
    validate_request(request)?;
    let plan_digest = plan.canonical_digest()?;
    let summary = armed.funding_summary();
    let custody = armed.external_funding_custody()?;
    let expected_claim_amount = request
        .amount_sat
        .checked_sub(request.claim_fee_sat)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let expected_refund_amount = request
        .amount_sat
        .checked_sub(request.refund_fee_sat)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let templates = [
        receipt.funding_template_hash,
        receipt.claim_template_hash,
        receipt.refund_template_hash,
    ];
    receipt
        .claim_roster
        .validate()
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if request.route_binding != receipt.route_binding
        || plan.route_binding != receipt.route_binding
        || plan.amount_sat != request.amount_sat
        || plan.fee_rate_sat_vb != request.funding_fee_rate_sat_vb
        || plan.refund_delay()? != request.refund_delay
        || receipt.plan_digest == [0; 32]
        || receipt.plan_digest != plan_digest
        || receipt.prepared_record_digest != armed.prepared_record_digest()
        || receipt.prepared_record_digest != summary.prepared_record_digest()
        || receipt.summary_record_digest != summary.summary_record_digest()
        || receipt.funding_txid != armed.funding_txid()
        || receipt.funding_txid != summary.funding_txid()
        || receipt.funding_wtxid != summary.funding_wtxid()
        || receipt.contract_vout != summary.contract_vout()
        || receipt.contract_amount_sat != summary.contract_amount_sat()
        || receipt.contract_amount_sat != request.amount_sat
        || receipt.actual_funding_fee_sat == 0
        || receipt.actual_funding_fee_sat != summary.actual_fee_sat()
        || receipt.funding_virtual_size_vb == 0
        || receipt.funding_virtual_size_vb != summary.virtual_size_vb()
        || receipt.claim_roster != roster
        || receipt.refund_key_xonly != refund_key_xonly
        || receipt.refund_key_xonly != plan.refund_contract.refund_key_xonly
        || receipt.contract_script_pubkey != plan.contract_script_pubkey
        || receipt.claim_output.amount_sat != expected_claim_amount
        || receipt.claim_output.script_pubkey.as_slice() != claim_script_pubkey
        || receipt.claim_output.script_pubkey.is_empty()
        || receipt.claim_output.script_pubkey.len() > MAX_SCRIPT_BYTES
        || plan.refund_outputs.len() != 1
        || receipt.refund_output != plan.refund_outputs[0]
        || receipt.refund_output.amount_sat != expected_refund_amount
        || receipt.refund_output.script_pubkey.as_slice() != refund_script_pubkey
        || summary.route_binding() != receipt.route_binding
        || summary.plan_digest() != plan_digest
        || summary.requested_fee_rate_sat_vb() != request.funding_fee_rate_sat_vb
        || summary.refund_delay() != request.refund_delay
        || custody.route_binding() != receipt.route_binding
        || custody.plan_digest() != plan_digest
        || custody.prepared_record_digest() != receipt.prepared_record_digest
        || custody.summary_record_digest() != receipt.summary_record_digest
        || custody.funding_txid() != receipt.funding_txid
        || custody.contract_vout() != receipt.contract_vout
        || custody.contract_amount_sat() != receipt.contract_amount_sat
        || custody.actual_fee_sat() != receipt.actual_funding_fee_sat
        || templates.contains(&[0; 32])
        || templates[0] == templates[1]
        || templates[0] == templates[2]
        || templates[1] == templates[2]
        || receipt.receipt_digest == [0; 32]
        || receipt.receipt_digest != receipt_digest(receipt)?
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(())
}

fn prepared_claim_matches_binding(
    record: &FreshBitcoinPreparedClaimRecordV1,
    binding: &BitcoinFreshClaimBindingV1,
) -> bool {
    record.public.settlement_id == binding.settlement_id
        && record.public.session_id == binding.session_id
        && record.public.terms_hash == binding.terms_hash
        && record.public.funding_txid == binding.funding_txid
        && record.public.funding_vout == binding.funding_vout
        && record.public.funding_amount_sat == binding.funding_amount_sat
        && record.public.destination_script_pubkey == binding.destination_script_pubkey
        && record.public.fee_sat == binding.fee_sat
        && record.public.template_digest == binding.expected_template_hash
        && record.public.adaptor_point == binding.adaptor_point
}

fn validate_prepared_claim_store(
    store: &BitcoinPrebroadcastStoreV1,
    record: &FreshBitcoinPreparedClaimRecordV1,
) -> Result<(), LiveBitcoinError> {
    validate_prepared_claim_store_public(store, &record.public)
}

fn validate_prepared_claim_store_public(
    store: &BitcoinPrebroadcastStoreV1,
    public: &FreshBitcoinPreparedClaimPublicV1,
) -> Result<(), LiveBitcoinError> {
    let receipt_bytes = store
        .store
        .read(StageKind::FreshTemplates)?
        .ok_or(LiveBitcoinError::StateConflict)?;
    let receipt = decode_receipt(&receipt_bytes)?;
    let authority_bytes = store
        .store
        .read(StageKind::FreshAuthority)?
        .ok_or(LiveBitcoinError::StateConflict)?;
    let authority = decode_authority(&authority_bytes)?;
    if public.route_binding != receipt.route_binding
        || public.route_binding != authority.request.route_binding
        || public.plan_digest != receipt.plan_digest
        || public.receipt_digest != receipt.receipt_digest
        || public.network != authority.network
        || public.funding_txid != receipt.funding_txid
        || public.funding_vout != receipt.contract_vout
        || public.funding_amount_sat != receipt.contract_amount_sat
        || public.roster != receipt.claim_roster
        || public.contract_script_pubkey != receipt.contract_script_pubkey
        || public.refund_key_xonly != receipt.refund_key_xonly
        || public.refund_delay != authority.request.refund_delay
        || public.destination_script_pubkey != receipt.claim_output.script_pubkey
        || public.fee_sat != authority.request.claim_fee_sat
        || public.template_digest != receipt.claim_template_hash
    {
        return Err(LiveBitcoinError::StateConflict);
    }
    Ok(())
}

fn validate_prepared_claim_record(
    record: &FreshBitcoinPreparedClaimRecordV1,
) -> Result<(), LiveBitcoinError> {
    let public = &record.public;
    validate_prepared_claim_public(public)?;
    if XOnlyPublicKey::from_slice(&record.output_xonly).is_err()
        || record.tap_sighash == [0; 32]
        || record.pre_signature == [0; 64]
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let contract_context = SecpContext::new(&*fresh_entropy()?);
    let contract = build_taproot_contract(
        &contract_context,
        &public.roster,
        &public.refund_key_xonly,
        csv_delay(public.refund_delay),
    )
    .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if contract.script_pubkey != public.contract_script_pubkey
        || contract.output_key_xonly != record.output_xonly
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let binding = BitcoinFreshClaimBindingV1 {
        settlement_id: public.settlement_id,
        session_id: public.session_id,
        terms_hash: public.terms_hash,
        funding_txid: public.funding_txid,
        funding_vout: public.funding_vout,
        funding_amount_sat: public.funding_amount_sat,
        destination_script_pubkey: public.destination_script_pubkey.clone(),
        fee_sat: public.fee_sat,
        expected_template_hash: public.template_digest,
        adaptor_point: public.adaptor_point,
    };
    let expected_transaction = exact_claim_transaction(&binding)?;
    if record.transaction != expected_transaction || !record.transaction.input[0].witness.is_empty()
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let template = exact_claim_template(
        &record.transaction,
        &binding,
        &public.contract_script_pubkey,
        template_network(public.network),
    );
    if frozen_template_digest_v1(&template).map_err(|_| LiveBitcoinError::CorruptRecord)?
        != public.template_digest
        || key_path_sighash_default(&template, 0).map_err(|_| LiveBitcoinError::CorruptRecord)?
            != record.tap_sighash
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    validate_partial_descriptor(record.signer_one_partial)?;
    validate_partial_descriptor(record.signer_two_partial)?;
    let one = record
        .signer_one_partial
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let two = record
        .signer_two_partial
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    if one.reservation_id == two.reservation_id || one.outbound_digest == two.outbound_digest {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(())
}

fn validate_prepared_claim_public(
    public: &FreshBitcoinPreparedClaimPublicV1,
) -> Result<(), LiveBitcoinError> {
    public
        .roster
        .validate()
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if public.route_binding == [0; 32]
        || public.plan_digest == [0; 32]
        || public.receipt_digest == [0; 32]
        || public.settlement_id == [0; 32]
        || public.session_id == [0; 32]
        || public.terms_hash == [0; 32]
        || public.funding_txid == [0; 32]
        || public.funding_amount_sat == 0
        || public.funding_amount_sat > MAX_MONEY_SAT
        || public.contract_script_pubkey.is_empty()
        || public.contract_script_pubkey.len() > MAX_SCRIPT_BYTES
        || public.destination_script_pubkey.is_empty()
        || public.destination_script_pubkey.len() > MAX_SCRIPT_BYTES
        || public.fee_sat == 0
        || public.funding_amount_sat.checked_sub(public.fee_sat) == Some(0)
        || public
            .funding_amount_sat
            .checked_sub(public.fee_sat)
            .is_none()
        || public.template_digest == [0; 32]
        || PublicKey::from_slice(&public.adaptor_point).is_err()
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(())
}

fn validate_partial_descriptor(
    descriptor: Option<PersistedArtifactDescriptorV1>,
) -> Result<(), LiveBitcoinError> {
    let descriptor = descriptor.ok_or(LiveBitcoinError::CorruptRecord)?;
    if descriptor.reservation_id == [0; 32]
        || descriptor.artifact_kind != 2
        || descriptor.outbound_digest == [0; 32]
        || descriptor.byte_length != 32
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(())
}

fn encode_extraction_intent(
    intent: &FreshClaimExtractionIntentV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    if intent.prepared_record_digest == [0; 32]
        || intent.expected_txid == [0; 32]
        || intent.context_digest == [0; 32]
        || intent.minimum_confirmations == 0
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let mut output = Vec::with_capacity(142);
    output.extend_from_slice(CLAIM_EXTRACTION_INTENT_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&intent.prepared_record_digest);
    output.extend_from_slice(&intent.expected_txid);
    output.extend_from_slice(&intent.context_digest);
    output.extend_from_slice(&intent.minimum_confirmations.to_be_bytes());
    let record_digest = digest(CLAIM_EXTRACTION_INTENT_DIGEST_DOMAIN, &output)?;
    output.extend_from_slice(&record_digest);
    Ok(output)
}

fn decode_extraction_intent(
    bytes: &[u8],
) -> Result<FreshClaimExtractionIntentV1, LiveBitcoinError> {
    let mut cursor = FreshCursor::new(bytes);
    cursor.require_header(CLAIM_EXTRACTION_INTENT_MAGIC)?;
    let intent = FreshClaimExtractionIntentV1 {
        prepared_record_digest: cursor.take_array()?,
        expected_txid: cursor.take_array()?,
        context_digest: cursor.take_array()?,
        minimum_confirmations: cursor.take_u32()?,
    };
    let stored_digest: [u8; 32] = cursor.take_array()?;
    cursor.finish()?;
    let payload_length = bytes
        .len()
        .checked_sub(32)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    if stored_digest
        != digest(
            CLAIM_EXTRACTION_INTENT_DIGEST_DOMAIN,
            &bytes[..payload_length],
        )?
        || encode_extraction_intent(&intent)?.as_slice() != bytes
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(intent)
}

fn encode_extraction_complete(
    complete: &FreshClaimExtractionCompleteV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    if complete.intent_digest == [0; 32]
        || complete.expected_txid == [0; 32]
        || complete.canonical_transaction_digest == [0; 32]
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let mut output = Vec::with_capacity(138);
    output.extend_from_slice(CLAIM_EXTRACTION_COMPLETE_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&complete.intent_digest);
    output.extend_from_slice(&complete.expected_txid);
    output.extend_from_slice(&complete.canonical_transaction_digest);
    let record_digest = digest(CLAIM_EXTRACTION_COMPLETE_DIGEST_DOMAIN, &output)?;
    output.extend_from_slice(&record_digest);
    Ok(output)
}

fn decode_extraction_complete(
    bytes: &[u8],
) -> Result<FreshClaimExtractionCompleteV1, LiveBitcoinError> {
    let mut cursor = FreshCursor::new(bytes);
    cursor.require_header(CLAIM_EXTRACTION_COMPLETE_MAGIC)?;
    let complete = FreshClaimExtractionCompleteV1 {
        intent_digest: cursor.take_array()?,
        expected_txid: cursor.take_array()?,
        canonical_transaction_digest: cursor.take_array()?,
    };
    let stored_digest: [u8; 32] = cursor.take_array()?;
    cursor.finish()?;
    let payload_length = bytes
        .len()
        .checked_sub(32)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    if stored_digest
        != digest(
            CLAIM_EXTRACTION_COMPLETE_DIGEST_DOMAIN,
            &bytes[..payload_length],
        )?
        || encode_extraction_complete(&complete)?.as_slice() != bytes
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(complete)
}

fn encode_finalization_intent(
    intent: &FreshClaimFinalizationIntentV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    if intent.prepared_record_digest == [0; 32]
        || intent.expected_txid == [0; 32]
        || intent.extraction_context_digest == [0; 32]
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let mut output = Vec::with_capacity(138);
    output.extend_from_slice(CLAIM_FINALIZATION_INTENT_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&intent.prepared_record_digest);
    output.extend_from_slice(&intent.expected_txid);
    output.extend_from_slice(&intent.extraction_context_digest);
    let record_digest = digest(CLAIM_FINALIZATION_INTENT_DIGEST_DOMAIN, &output)?;
    output.extend_from_slice(&record_digest);
    Ok(output)
}

fn decode_finalization_intent(
    bytes: &[u8],
) -> Result<FreshClaimFinalizationIntentV1, LiveBitcoinError> {
    let mut cursor = FreshCursor::new(bytes);
    cursor.require_header(CLAIM_FINALIZATION_INTENT_MAGIC)?;
    let intent = FreshClaimFinalizationIntentV1 {
        prepared_record_digest: cursor.take_array()?,
        expected_txid: cursor.take_array()?,
        extraction_context_digest: cursor.take_array()?,
    };
    let stored_digest: [u8; 32] = cursor.take_array()?;
    cursor.finish()?;
    let payload_length = bytes
        .len()
        .checked_sub(32)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    if stored_digest
        != digest(
            CLAIM_FINALIZATION_INTENT_DIGEST_DOMAIN,
            &bytes[..payload_length],
        )?
        || encode_finalization_intent(&intent)?.as_slice() != bytes
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(intent)
}

fn encode_finalized_claim(
    record: &FreshClaimFinalizedRecordV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    if record.prepared_record_digest == [0; 32]
        || record.expected_txid == [0; 32]
        || record.extraction_context_digest == [0; 32]
        || record.canonical_transaction_digest == [0; 32]
        || record.canonical_transaction.is_empty()
        || record.canonical_transaction.len() > MAX_CLAIM_TRANSACTION_BYTES
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let transaction_length = u32::try_from(record.canonical_transaction.len())
        .map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    let mut output = Vec::with_capacity(174 + record.canonical_transaction.len());
    output.extend_from_slice(CLAIM_FINALIZED_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&record.prepared_record_digest);
    output.extend_from_slice(&record.expected_txid);
    output.extend_from_slice(&record.extraction_context_digest);
    output.extend_from_slice(&record.canonical_transaction_digest);
    output.extend_from_slice(&transaction_length.to_be_bytes());
    output.extend_from_slice(&record.canonical_transaction);
    let record_digest = digest(CLAIM_FINALIZED_DIGEST_DOMAIN, &output)?;
    output.extend_from_slice(&record_digest);
    Ok(output)
}

fn decode_finalized_claim(bytes: &[u8]) -> Result<FreshClaimFinalizedRecordV1, LiveBitcoinError> {
    let mut cursor = FreshCursor::new(bytes);
    cursor.require_header(CLAIM_FINALIZED_MAGIC)?;
    let prepared_record_digest = cursor.take_array()?;
    let expected_txid = cursor.take_array()?;
    let extraction_context_digest = cursor.take_array()?;
    let canonical_transaction_digest = cursor.take_array()?;
    let transaction_length =
        usize::try_from(cursor.take_u32()?).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    if transaction_length == 0 || transaction_length > MAX_CLAIM_TRANSACTION_BYTES {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let canonical_transaction = cursor.take(transaction_length)?.to_vec();
    let stored_digest: [u8; 32] = cursor.take_array()?;
    cursor.finish()?;
    let payload_length = bytes
        .len()
        .checked_sub(32)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let record = FreshClaimFinalizedRecordV1 {
        prepared_record_digest,
        expected_txid,
        extraction_context_digest,
        canonical_transaction_digest,
        canonical_transaction,
    };
    if stored_digest != digest(CLAIM_FINALIZED_DIGEST_DOMAIN, &bytes[..payload_length])?
        || encode_finalized_claim(&record)?.as_slice() != bytes
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(record)
}

fn validate_finalized_claim_record(
    record: &FreshClaimFinalizedRecordV1,
    extraction: &FreshBitcoinClaimExtractionAuthorityV1,
) -> Result<(), LiveBitcoinError> {
    if record.prepared_record_digest != extraction.prepared_record_digest
        || record.expected_txid != extraction.expected_txid
        || record.extraction_context_digest != extraction.context_digest()?
        || record.canonical_transaction_digest
            != digest(EXACT_CLAIM_DIGEST_DOMAIN, &record.canonical_transaction)?
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let transaction: Transaction =
        deserialize(&record.canonical_transaction).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if serialize(&transaction) != record.canonical_transaction
        || transaction.compute_txid().to_raw_hash().to_byte_array() != record.expected_txid
        || transaction.input.len() != 1
        || transaction.input[0].witness.len() != 1
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let final_signature: [u8; 64] = transaction.input[0]
        .witness
        .iter()
        .next()
        .and_then(|item| item.try_into().ok())
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let crypto = SecpContext::new(&*fresh_entropy()?);
    crypto
        .verify_bip340(
            &extraction.output_xonly,
            &extraction.tap_sighash,
            &final_signature,
        )
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    let mut scalar = crypto
        .extract(
            &final_signature,
            &extraction.pre_signature,
            extraction.nonce_parity,
            &extraction.adaptor_point,
        )
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    scalar.zeroize();
    Ok(())
}

fn encode_claim_intent(
    public: &FreshBitcoinPreparedClaimPublicV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    validate_prepared_claim_public(public)?;
    let mut output = Vec::new();
    output.extend_from_slice(CLAIM_INTENT_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    encode_claim_public_fields(&mut output, public)?;
    let intent_digest = digest(CLAIM_INTENT_DIGEST_DOMAIN, &output)?;
    output.extend_from_slice(&intent_digest);
    Ok(output)
}

fn decode_claim_intent(
    bytes: &[u8],
) -> Result<FreshBitcoinPreparedClaimPublicV1, LiveBitcoinError> {
    let payload_length = bytes
        .len()
        .checked_sub(32)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let (payload, stored_digest) = bytes.split_at(payload_length);
    if digest(CLAIM_INTENT_DIGEST_DOMAIN, payload)?.as_slice() != stored_digest {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let mut cursor = FreshCursor::new(payload);
    cursor.require_header(CLAIM_INTENT_MAGIC)?;
    let public = decode_claim_public_fields(&mut cursor)?;
    cursor.finish()?;
    validate_prepared_claim_public(&public)?;
    if encode_claim_intent(&public)?.as_slice() != bytes {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(public)
}

fn encode_claim_public_fields(
    output: &mut Vec<u8>,
    public: &FreshBitcoinPreparedClaimPublicV1,
) -> Result<(), LiveBitcoinError> {
    output.extend_from_slice(&public.route_binding);
    output.extend_from_slice(&public.plan_digest);
    output.extend_from_slice(&public.receipt_digest);
    output.push(network_tag(public.network));
    output.extend_from_slice(&public.settlement_id);
    output.extend_from_slice(&public.session_id);
    output.extend_from_slice(&public.terms_hash);
    output.extend_from_slice(&public.funding_txid);
    output.extend_from_slice(&public.funding_vout.to_be_bytes());
    output.extend_from_slice(&public.funding_amount_sat.to_be_bytes());
    output.extend_from_slice(&public.roster.version().to_be_bytes());
    for participant in public.roster.participants() {
        output.extend_from_slice(&participant.participant_id);
        output.push(role_tag(participant.role));
        output.extend_from_slice(&participant.compressed_key);
    }
    put_bytes(output, &public.contract_script_pubkey)?;
    output.extend_from_slice(&public.refund_key_xonly);
    output.extend_from_slice(&public.refund_delay.sequence().to_be_bytes());
    put_bytes(output, &public.destination_script_pubkey)?;
    output.extend_from_slice(&public.fee_sat.to_be_bytes());
    output.extend_from_slice(&public.template_digest);
    output.extend_from_slice(&public.adaptor_point);
    Ok(())
}

fn decode_claim_public_fields(
    cursor: &mut FreshCursor<'_>,
) -> Result<FreshBitcoinPreparedClaimPublicV1, LiveBitcoinError> {
    let route_binding = cursor.take_array()?;
    let plan_digest = cursor.take_array()?;
    let receipt_digest = cursor.take_array()?;
    let network = network_from_tag(cursor.take_u8()?)?;
    let settlement_id = cursor.take_array()?;
    let session_id = cursor.take_array()?;
    let terms_hash = cursor.take_array()?;
    let funding_txid = cursor.take_array()?;
    let funding_vout = cursor.take_u32()?;
    let funding_amount_sat = cursor.take_u64()?;
    let roster_version = cursor.take_u16()?;
    let mut participants = [
        ParticipantKeyV1 {
            participant_id: [0; 32],
            role: BitcoinSignerRoleV1::Maker,
            compressed_key: [0; 33],
        },
        ParticipantKeyV1 {
            participant_id: [0; 32],
            role: BitcoinSignerRoleV1::Taker,
            compressed_key: [0; 33],
        },
    ];
    for participant in &mut participants {
        participant.participant_id = cursor.take_array()?;
        participant.role = role_from_tag(cursor.take_u8()?)?;
        participant.compressed_key = cursor.take_array()?;
    }
    if roster_version != ROSTER_VERSION {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let roster =
        ParticipantKeyRosterV1::new(participants).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    Ok(FreshBitcoinPreparedClaimPublicV1 {
        route_binding,
        plan_digest,
        receipt_digest,
        network,
        settlement_id,
        session_id,
        terms_hash,
        funding_txid,
        funding_vout,
        funding_amount_sat,
        roster,
        contract_script_pubkey: cursor.take_bytes(MAX_SCRIPT_BYTES)?,
        refund_key_xonly: cursor.take_array()?,
        refund_delay: BitcoinRefundDelayV1::from_sequence(cursor.take_u32()?)?,
        destination_script_pubkey: cursor.take_bytes(MAX_SCRIPT_BYTES)?,
        fee_sat: cursor.take_u64()?,
        template_digest: cursor.take_array()?,
        adaptor_point: cursor.take_array()?,
    })
}

fn encode_prepared_claim_record(
    record: &FreshBitcoinPreparedClaimRecordV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    validate_prepared_claim_record(record)?;
    let mut output = Vec::new();
    output.extend_from_slice(CLAIM_PREPARED_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    encode_claim_public_fields(&mut output, &record.public)?;
    put_bytes(&mut output, &serialize(&record.transaction))?;
    output.extend_from_slice(&record.tap_sighash);
    output.push(nonce_parity_tag(record.nonce_parity));
    output.extend_from_slice(&record.output_xonly);
    output.extend_from_slice(&record.pre_signature);
    encode_partial_descriptor(&mut output, record.signer_one_partial)?;
    encode_partial_descriptor(&mut output, record.signer_two_partial)?;
    let payload_digest = digest(CLAIM_PREPARED_PAYLOAD_DIGEST_DOMAIN, &output)?;
    output.extend_from_slice(&payload_digest);
    Ok(output)
}

fn decode_prepared_claim_record(
    bytes: &[u8],
) -> Result<FreshBitcoinPreparedClaimRecordV1, LiveBitcoinError> {
    let payload_length = bytes
        .len()
        .checked_sub(32)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let (payload, stored_digest) = bytes.split_at(payload_length);
    if digest(CLAIM_PREPARED_PAYLOAD_DIGEST_DOMAIN, payload)?.as_slice() != stored_digest {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let mut cursor = FreshCursor::new(payload);
    cursor.require_header(CLAIM_PREPARED_MAGIC)?;
    let public = decode_claim_public_fields(&mut cursor)?;
    let transaction_bytes = cursor.take_bytes(MAX_CLAIM_TRANSACTION_BYTES)?;
    let transaction: Transaction =
        deserialize(&transaction_bytes).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if serialize(&transaction) != transaction_bytes {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let record = FreshBitcoinPreparedClaimRecordV1 {
        public,
        transaction,
        tap_sighash: cursor.take_array()?,
        nonce_parity: nonce_parity_from_tag(cursor.take_u8()?)?,
        output_xonly: cursor.take_array()?,
        pre_signature: cursor.take_array()?,
        signer_one_partial: decode_partial_descriptor(&mut cursor)?,
        signer_two_partial: decode_partial_descriptor(&mut cursor)?,
    };
    cursor.finish()?;
    validate_prepared_claim_record(&record)?;
    if encode_prepared_claim_record(&record)?.as_slice() != bytes {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(record)
}

fn encode_partial_descriptor(
    output: &mut Vec<u8>,
    descriptor: Option<PersistedArtifactDescriptorV1>,
) -> Result<(), LiveBitcoinError> {
    let descriptor = descriptor.ok_or(LiveBitcoinError::CorruptRecord)?;
    validate_partial_descriptor(Some(descriptor))?;
    output.extend_from_slice(&descriptor.reservation_id);
    output.push(descriptor.artifact_kind);
    output.extend_from_slice(&descriptor.outbound_digest);
    output.extend_from_slice(&descriptor.byte_length.to_be_bytes());
    Ok(())
}

fn decode_partial_descriptor(
    cursor: &mut FreshCursor<'_>,
) -> Result<Option<PersistedArtifactDescriptorV1>, LiveBitcoinError> {
    let descriptor = PersistedArtifactDescriptorV1 {
        reservation_id: cursor.take_array()?,
        artifact_kind: cursor.take_u8()?,
        outbound_digest: cursor.take_array()?,
        byte_length: cursor.take_u32()?,
    };
    validate_partial_descriptor(Some(descriptor))?;
    Ok(Some(descriptor))
}

const fn nonce_parity_tag(parity: NonceParity) -> u8 {
    match parity {
        NonceParity::Even => 0,
        NonceParity::Odd => 1,
    }
}

fn nonce_parity_from_tag(tag: u8) -> Result<NonceParity, LiveBitcoinError> {
    match tag {
        0 => Ok(NonceParity::Even),
        1 => Ok(NonceParity::Odd),
        _ => Err(LiveBitcoinError::CorruptRecord),
    }
}

fn encode_authority(record: &FreshAuthorityRecord) -> Result<Vec<u8>, LiveBitcoinError> {
    let mut output = Vec::new();
    output.extend_from_slice(AUTHORITY_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.push(network_tag(record.network));
    output.extend_from_slice(&record.genesis_hash);
    put_bytes(
        &mut output,
        record.signet_challenge.as_deref().unwrap_or_default(),
    )?;
    encode_request(&mut output, record.request);
    put_bytes(&mut output, &record.claim_script_pubkey)?;
    put_bytes(&mut output, &record.refund_script_pubkey)?;
    output.extend_from_slice(record.maker_secret.as_ref());
    output.extend_from_slice(record.taker_secret.as_ref());
    output.extend_from_slice(record.refund_secret.as_ref());
    Ok(output)
}

fn decode_authority(bytes: &[u8]) -> Result<FreshAuthorityRecord, LiveBitcoinError> {
    let mut cursor = FreshCursor::new(bytes);
    cursor.require_header(AUTHORITY_MAGIC)?;
    let network = network_from_tag(cursor.take_u8()?)?;
    let genesis_hash = cursor.take_array()?;
    let signet_challenge = match cursor.take_bytes(MAX_SIGNET_CHALLENGE_BYTES)? {
        value if value.is_empty() => None,
        value => Some(value),
    };
    let request = decode_request(&mut cursor)?;
    let claim_script_pubkey = cursor.take_bytes(MAX_SCRIPT_BYTES)?;
    let refund_script_pubkey = cursor.take_bytes(MAX_SCRIPT_BYTES)?;
    let maker_secret = Zeroizing::new(cursor.take_array()?);
    let taker_secret = Zeroizing::new(cursor.take_array()?);
    let refund_secret = Zeroizing::new(cursor.take_array()?);
    cursor.finish()?;
    let record = FreshAuthorityRecord {
        network,
        genesis_hash,
        signet_challenge,
        request,
        claim_script_pubkey,
        refund_script_pubkey,
        maker_secret,
        taker_secret,
        refund_secret,
    };
    validate_request(record.request)?;
    if encode_authority(&record)?.as_slice() != bytes {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(record)
}

fn encode_receipt(receipt: &BitcoinFreshRouteReceiptV1) -> Result<Vec<u8>, LiveBitcoinError> {
    let mut output = encode_receipt_without_digest(receipt)?;
    output.extend_from_slice(&receipt.receipt_digest);
    Ok(output)
}

fn encode_receipt_without_digest(
    receipt: &BitcoinFreshRouteReceiptV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    let mut output = Vec::new();
    output.extend_from_slice(TEMPLATES_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&receipt.route_binding);
    output.extend_from_slice(&receipt.plan_digest);
    output.extend_from_slice(&receipt.prepared_record_digest);
    output.extend_from_slice(&receipt.summary_record_digest);
    output.extend_from_slice(&receipt.funding_txid);
    output.extend_from_slice(&receipt.funding_wtxid);
    output.extend_from_slice(&receipt.contract_vout.to_be_bytes());
    output.extend_from_slice(&receipt.contract_amount_sat.to_be_bytes());
    output.extend_from_slice(&receipt.actual_funding_fee_sat.to_be_bytes());
    output.extend_from_slice(&receipt.funding_virtual_size_vb.to_be_bytes());
    output.extend_from_slice(&receipt.claim_roster.version().to_be_bytes());
    for participant in receipt.claim_roster.participants() {
        output.extend_from_slice(&participant.participant_id);
        output.push(role_tag(participant.role));
        output.extend_from_slice(&participant.compressed_key);
    }
    output.extend_from_slice(&receipt.refund_key_xonly);
    put_bytes(&mut output, &receipt.contract_script_pubkey)?;
    output.extend_from_slice(&receipt.claim_output.amount_sat.to_be_bytes());
    put_bytes(&mut output, &receipt.claim_output.script_pubkey)?;
    output.extend_from_slice(&receipt.refund_output.amount_sat.to_be_bytes());
    put_bytes(&mut output, &receipt.refund_output.script_pubkey)?;
    output.extend_from_slice(&receipt.funding_template_hash);
    output.extend_from_slice(&receipt.claim_template_hash);
    output.extend_from_slice(&receipt.refund_template_hash);
    Ok(output)
}

fn decode_receipt(bytes: &[u8]) -> Result<BitcoinFreshRouteReceiptV1, LiveBitcoinError> {
    let mut cursor = FreshCursor::new(bytes);
    cursor.require_header(TEMPLATES_MAGIC)?;
    let route_binding = cursor.take_array()?;
    let plan_digest = cursor.take_array()?;
    let prepared_record_digest = cursor.take_array()?;
    let summary_record_digest = cursor.take_array()?;
    let funding_txid = cursor.take_array()?;
    let funding_wtxid = cursor.take_array()?;
    let contract_vout = cursor.take_u32()?;
    let contract_amount_sat = cursor.take_u64()?;
    let actual_funding_fee_sat = cursor.take_u64()?;
    let funding_virtual_size_vb = cursor.take_u64()?;
    let roster_version = cursor.take_u16()?;
    let mut participants = [
        ParticipantKeyV1 {
            participant_id: [0; 32],
            role: BitcoinSignerRoleV1::Maker,
            compressed_key: [0; 33],
        },
        ParticipantKeyV1 {
            participant_id: [0; 32],
            role: BitcoinSignerRoleV1::Taker,
            compressed_key: [0; 33],
        },
    ];
    for participant in &mut participants {
        participant.participant_id = cursor.take_array()?;
        participant.role = role_from_tag(cursor.take_u8()?)?;
        participant.compressed_key = cursor.take_array()?;
    }
    // Audit finding F2(b): this was the one production literal construction,
    // and it validated nothing but the version — a roster with a duplicated
    // participant_id decoded fine and collided in the pre-F2(a) digest. The
    // fields are private now; the validating constructor is the only path.
    if roster_version != ROSTER_VERSION {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let claim_roster =
        ParticipantKeyRosterV1::new(participants).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    let refund_key_xonly = cursor.take_array()?;
    let contract_script_pubkey = cursor.take_bytes(MAX_SCRIPT_BYTES)?;
    let claim_output = BitcoinRefundOutputV1 {
        amount_sat: cursor.take_u64()?,
        script_pubkey: cursor.take_bytes(MAX_SCRIPT_BYTES)?,
    };
    let refund_output = BitcoinRefundOutputV1 {
        amount_sat: cursor.take_u64()?,
        script_pubkey: cursor.take_bytes(MAX_SCRIPT_BYTES)?,
    };
    let funding_template_hash = cursor.take_array()?;
    let claim_template_hash = cursor.take_array()?;
    let refund_template_hash = cursor.take_array()?;
    let stored_receipt_digest = cursor.take_array()?;
    cursor.finish()?;
    let receipt = BitcoinFreshRouteReceiptV1 {
        route_binding,
        plan_digest,
        prepared_record_digest,
        summary_record_digest,
        funding_txid,
        funding_wtxid,
        contract_vout,
        contract_amount_sat,
        actual_funding_fee_sat,
        funding_virtual_size_vb,
        claim_roster,
        refund_key_xonly,
        contract_script_pubkey,
        claim_output,
        refund_output,
        funding_template_hash,
        claim_template_hash,
        refund_template_hash,
        receipt_digest: stored_receipt_digest,
    };
    if receipt.receipt_digest != receipt_digest(&receipt)?
        || encode_receipt(&receipt)?.as_slice() != bytes
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(receipt)
}

fn encode_request(output: &mut Vec<u8>, request: BitcoinFreshRouteRequestV1) {
    output.extend_from_slice(&request.route_binding);
    output.extend_from_slice(&request.participant_ids[0]);
    output.extend_from_slice(&request.participant_ids[1]);
    output.extend_from_slice(&request.amount_sat.to_be_bytes());
    output.extend_from_slice(&request.funding_fee_rate_sat_vb.to_be_bytes());
    output.extend_from_slice(&request.claim_fee_sat.to_be_bytes());
    output.extend_from_slice(&request.refund_fee_sat.to_be_bytes());
    output.extend_from_slice(&request.refund_delay.sequence().to_be_bytes());
}

fn decode_request(
    cursor: &mut FreshCursor<'_>,
) -> Result<BitcoinFreshRouteRequestV1, LiveBitcoinError> {
    let request = BitcoinFreshRouteRequestV1 {
        route_binding: cursor.take_array()?,
        participant_ids: [cursor.take_array()?, cursor.take_array()?],
        amount_sat: cursor.take_u64()?,
        funding_fee_rate_sat_vb: cursor.take_u64()?,
        claim_fee_sat: cursor.take_u64()?,
        refund_fee_sat: cursor.take_u64()?,
        refund_delay: BitcoinRefundDelayV1::from_sequence(cursor.take_u32()?)?,
    };
    validate_request(request)?;
    Ok(request)
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), LiveBitcoinError> {
    let length = u32::try_from(value.len()).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

const fn network_tag(network: BitcoinCoreNetworkV1) -> u8 {
    match network {
        BitcoinCoreNetworkV1::Regtest => 1,
        BitcoinCoreNetworkV1::PublicSignet => 2,
        BitcoinCoreNetworkV1::CustomSignet => 3,
    }
}

fn network_from_tag(tag: u8) -> Result<BitcoinCoreNetworkV1, LiveBitcoinError> {
    match tag {
        1 => Ok(BitcoinCoreNetworkV1::Regtest),
        2 => Ok(BitcoinCoreNetworkV1::PublicSignet),
        3 => Ok(BitcoinCoreNetworkV1::CustomSignet),
        _ => Err(LiveBitcoinError::CorruptRecord),
    }
}

const fn role_tag(role: BitcoinSignerRoleV1) -> u8 {
    match role {
        BitcoinSignerRoleV1::Maker => 1,
        BitcoinSignerRoleV1::Taker => 2,
    }
}

fn role_from_tag(tag: u8) -> Result<BitcoinSignerRoleV1, LiveBitcoinError> {
    match tag {
        1 => Ok(BitcoinSignerRoleV1::Maker),
        2 => Ok(BitcoinSignerRoleV1::Taker),
        _ => Err(LiveBitcoinError::CorruptRecord),
    }
}

fn digest(domain: &[u8], payload: &[u8]) -> Result<[u8; 32], LiveBitcoinError> {
    let mut hasher = Blake2bVar::new(32).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    hasher.update(domain);
    hasher.update(payload);
    let mut digest = [0_u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    Ok(digest)
}

struct FreshCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> FreshCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn require_header(&mut self, magic: &[u8; 8]) -> Result<(), LiveBitcoinError> {
        if self.take(8)? != magic || self.take_u16()? != CODEC_VERSION {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], LiveBitcoinError> {
        if length > self.remaining.len() {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        let (head, tail) = self.remaining.split_at(length);
        self.remaining = tail;
        Ok(head)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], LiveBitcoinError> {
        self.take(N)?
            .try_into()
            .map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn take_u8(&mut self) -> Result<u8, LiveBitcoinError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(LiveBitcoinError::CorruptRecord)
    }

    fn take_u16(&mut self) -> Result<u16, LiveBitcoinError> {
        self.take_array().map(u16::from_be_bytes)
    }

    fn take_u32(&mut self) -> Result<u32, LiveBitcoinError> {
        self.take_array().map(u32::from_be_bytes)
    }

    fn take_u64(&mut self) -> Result<u64, LiveBitcoinError> {
        self.take_array().map(u64::from_be_bytes)
    }

    fn take_bytes(&mut self, maximum: usize) -> Result<Vec<u8>, LiveBitcoinError> {
        let length =
            usize::try_from(self.take_u32()?).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
        if length > maximum {
            return Err(LiveBitcoinError::BoundsExceeded);
        }
        self.take(length).map(ToOwned::to_owned)
    }

    fn finish(self) -> Result<(), LiveBitcoinError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(LiveBitcoinError::CorruptRecord)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn request() -> BitcoinFreshRouteRequestV1 {
        BitcoinFreshRouteRequestV1 {
            route_binding: [1; 32],
            participant_ids: [[2; 32], [3; 32]],
            amount_sat: 100_000,
            funding_fee_rate_sat_vb: 2,
            claim_fee_sat: 1_000,
            refund_fee_sat: 2_000,
            refund_delay: BitcoinRefundDelayV1::Blocks(10),
        }
    }

    fn authority() -> FreshAuthorityRecord {
        FreshAuthorityRecord {
            network: BitcoinCoreNetworkV1::Regtest,
            genesis_hash: [4; 32],
            signet_challenge: None,
            request: request(),
            claim_script_pubkey: vec![0x51, 0x20, 5],
            refund_script_pubkey: vec![0x51, 0x20, 6],
            maker_secret: Zeroizing::new([0x11; 32]),
            taker_secret: Zeroizing::new([0x22; 32]),
            refund_secret: Zeroizing::new([0x33; 32]),
        }
    }

    fn receipt() -> Result<BitcoinFreshRouteReceiptV1, LiveBitcoinError> {
        let record = authority();
        let (plan, claim_roster, refund_key_xonly) = plan_for(&record)?;
        let mut receipt = BitcoinFreshRouteReceiptV1 {
            route_binding: record.request.route_binding,
            plan_digest: plan.canonical_digest()?,
            prepared_record_digest: [0x41; 32],
            summary_record_digest: [0x42; 32],
            funding_txid: [0x43; 32],
            funding_wtxid: [0x44; 32],
            contract_vout: 1,
            contract_amount_sat: record.request.amount_sat,
            actual_funding_fee_sat: 500,
            funding_virtual_size_vb: 250,
            claim_roster,
            refund_key_xonly,
            contract_script_pubkey: plan.contract_script_pubkey,
            claim_output: BitcoinRefundOutputV1 {
                amount_sat: record.request.amount_sat - record.request.claim_fee_sat,
                script_pubkey: record.claim_script_pubkey,
            },
            refund_output: plan.refund_outputs[0].clone(),
            funding_template_hash: [0x45; 32],
            claim_template_hash: [0; 32],
            refund_template_hash: [0x47; 32],
            receipt_digest: [0; 32],
        };
        // The reopen path cross-checks the prepared record's frozen template
        // digest against this receipt, so the fixture must carry the real
        // digest computed by the same template chain as the record fixture.
        receipt.claim_template_hash = fixture_claim_template_digest(&receipt)?;
        receipt.receipt_digest = receipt_digest(&receipt)?;
        Ok(receipt)
    }

    fn fixture_claim_template_digest(
        receipt: &BitcoinFreshRouteReceiptV1,
    ) -> Result<[u8; 32], LiveBitcoinError> {
        let binding = BitcoinFreshClaimBindingV1 {
            settlement_id: [0x51; 32],
            session_id: [0x52; 32],
            terms_hash: [0x53; 32],
            funding_txid: receipt.funding_txid,
            funding_vout: receipt.contract_vout,
            funding_amount_sat: receipt.contract_amount_sat,
            destination_script_pubkey: receipt.claim_output.script_pubkey.clone(),
            fee_sat: request().claim_fee_sat,
            expected_template_hash: [0; 32],
            adaptor_point: receipt.claim_roster.participants()[0].compressed_key,
        };
        let transaction = exact_claim_transaction(&binding)?;
        let template = exact_claim_template(
            &transaction,
            &binding,
            &receipt.contract_script_pubkey,
            TemplateNetworkV1::Regtest,
        );
        frozen_template_digest_v1(&template).map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn store_root(label: &str) -> Result<PathBuf, LiveBitcoinError> {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let parent = std::env::temp_dir().join(format!(
            "btc-live-fresh-face-{label}-{}-{sequence}",
            std::process::id()
        ));
        if parent.exists() {
            std::fs::remove_dir_all(&parent).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        }
        std::fs::create_dir(&parent).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        let canonical =
            std::fs::canonicalize(&parent).map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        Ok(canonical.join("route"))
    }

    fn cleanup_store(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    fn prepared_claim_record() -> Result<FreshBitcoinPreparedClaimRecordV1, LiveBitcoinError> {
        let receipt = receipt()?;
        let binding = BitcoinFreshClaimBindingV1 {
            settlement_id: [0x51; 32],
            session_id: [0x52; 32],
            terms_hash: [0x53; 32],
            funding_txid: receipt.funding_txid,
            funding_vout: receipt.contract_vout,
            funding_amount_sat: receipt.contract_amount_sat,
            destination_script_pubkey: receipt.claim_output.script_pubkey.clone(),
            fee_sat: request().claim_fee_sat,
            expected_template_hash: [0; 32],
            adaptor_point: receipt.claim_roster.participants()[0].compressed_key,
        };
        let transaction = exact_claim_transaction(&binding)?;
        let template = exact_claim_template(
            &transaction,
            &binding,
            &receipt.contract_script_pubkey,
            TemplateNetworkV1::Regtest,
        );
        let template_digest =
            frozen_template_digest_v1(&template).map_err(|_| LiveBitcoinError::CorruptRecord)?;
        let tap_sighash =
            key_path_sighash_default(&template, 0).map_err(|_| LiveBitcoinError::CorruptRecord)?;
        let context = SecpContext::new(&[0x61; 32]);
        let contract = build_taproot_contract(
            &context,
            &receipt.claim_roster,
            &receipt.refund_key_xonly,
            csv_delay(request().refund_delay),
        )
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
        Ok(FreshBitcoinPreparedClaimRecordV1 {
            public: FreshBitcoinPreparedClaimPublicV1 {
                route_binding: receipt.route_binding,
                plan_digest: receipt.plan_digest,
                receipt_digest: receipt.receipt_digest,
                network: BitcoinCoreNetworkV1::Regtest,
                settlement_id: binding.settlement_id,
                session_id: binding.session_id,
                terms_hash: binding.terms_hash,
                funding_txid: binding.funding_txid,
                funding_vout: binding.funding_vout,
                funding_amount_sat: binding.funding_amount_sat,
                roster: receipt.claim_roster,
                contract_script_pubkey: receipt.contract_script_pubkey,
                refund_key_xonly: receipt.refund_key_xonly,
                refund_delay: request().refund_delay,
                destination_script_pubkey: binding.destination_script_pubkey,
                fee_sat: binding.fee_sat,
                template_digest,
                adaptor_point: binding.adaptor_point,
            },
            transaction,
            tap_sighash,
            nonce_parity: NonceParity::Even,
            output_xonly: contract.output_key_xonly,
            pre_signature: [0x62; 64],
            signer_one_partial: Some(PersistedArtifactDescriptorV1 {
                reservation_id: [0x63; 32],
                artifact_kind: 2,
                outbound_digest: [0x64; 32],
                byte_length: 32,
            }),
            signer_two_partial: Some(PersistedArtifactDescriptorV1 {
                reservation_id: [0x65; 32],
                artifact_kind: 2,
                outbound_digest: [0x66; 32],
                byte_length: 32,
            }),
        })
    }

    fn claim_binding_from_record(
        record: &FreshBitcoinPreparedClaimRecordV1,
    ) -> BitcoinFreshClaimBindingV1 {
        BitcoinFreshClaimBindingV1 {
            settlement_id: record.public.settlement_id,
            session_id: record.public.session_id,
            terms_hash: record.public.terms_hash,
            funding_txid: record.public.funding_txid,
            funding_vout: record.public.funding_vout,
            funding_amount_sat: record.public.funding_amount_sat,
            destination_script_pubkey: record.public.destination_script_pubkey.clone(),
            fee_sat: record.public.fee_sat,
            expected_template_hash: record.public.template_digest,
            adaptor_point: record.public.adaptor_point,
        }
    }

    fn cryptographic_prepared_claim_record(
    ) -> Result<(FreshBitcoinPreparedClaimRecordV1, [u8; 32]), LiveBitcoinError> {
        let mut record = prepared_claim_record()?;
        let maker_secret = [0x11; 32];
        let taker_secret = [0x22; 32];
        let adaptor_scalar = maker_secret;
        let context = SecpContext::new(&[0x91; 32]);
        let ordered_keys = [
            record.public.roster.participants()[0].compressed_key,
            record.public.roster.participants()[1].compressed_key,
        ];
        let mut keyagg = context
            .key_agg(&ordered_keys)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let contract = build_taproot_contract(
            &context,
            &record.public.roster,
            &record.public.refund_key_xonly,
            csv_delay(record.public.refund_delay),
        )
        .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let tweaked = context
            .apply_tap_tweak(&mut keyagg, &contract.tweak)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let (secret_nonce_one, public_nonce_one) = context
            .nonce_gen(
                &[0xa1; 32],
                &maker_secret,
                &ordered_keys[0],
                &record.tap_sighash,
                &keyagg,
            )
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let (secret_nonce_two, public_nonce_two) = context
            .nonce_gen(
                &[0xa2; 32],
                &taker_secret,
                &ordered_keys[1],
                &record.tap_sighash,
                &keyagg,
            )
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let aggregate_nonce = context
            .nonce_agg(&[public_nonce_one.0, public_nonce_two.0])
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let session = context
            .nonce_process(
                &aggregate_nonce,
                &record.tap_sighash,
                &keyagg,
                &record.public.adaptor_point,
            )
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let partial_one = context
            .partial_sign(
                secret_nonce_one,
                &maker_secret,
                &ordered_keys[0],
                &public_nonce_one.0,
                &keyagg,
                &session,
            )
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let partial_two = context
            .partial_sign(
                secret_nonce_two,
                &taker_secret,
                &ordered_keys[1],
                &public_nonce_two.0,
                &keyagg,
                &session,
            )
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        record.pre_signature = context
            .aggregate_pre_signature(
                &[partial_one, partial_two],
                &tweaked.output_xonly,
                &record.tap_sighash,
                &session,
            )
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        record.nonce_parity = session.nonce_parity;
        record.output_xonly = tweaked.output_xonly;
        validate_prepared_claim_record(&record)?;
        Ok((record, adaptor_scalar))
    }

    #[test]
    fn prepared_claim_codec_rejects_tamper_trailing_and_partial_reuse(
    ) -> Result<(), LiveBitcoinError> {
        let record = prepared_claim_record()?;
        let encoded = encode_prepared_claim_record(&record)?;
        let decoded = decode_prepared_claim_record(&encoded)?;
        assert_eq!(encode_prepared_claim_record(&decoded)?, encoded);

        for offset in 0..encoded.len() {
            let mut tampered = encoded.clone();
            tampered[offset] ^= 0x80;
            assert!(
                decode_prepared_claim_record(&tampered).is_err(),
                "tampered prepared-claim byte {offset} was accepted"
            );
        }

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_prepared_claim_record(&trailing).is_err());

        let claim_intent = encode_claim_intent(&record.public)?;
        assert_eq!(decode_claim_intent(&claim_intent)?, record.public);
        for offset in 0..claim_intent.len() {
            let mut tampered = claim_intent.clone();
            tampered[offset] ^= 0x80;
            assert!(
                decode_claim_intent(&tampered).is_err(),
                "tampered claim-intent byte {offset} was accepted"
            );
        }
        let mut trailing_intent = claim_intent;
        trailing_intent.push(0);
        assert!(decode_claim_intent(&trailing_intent).is_err());

        let mut reused = prepared_claim_record()?;
        reused.signer_two_partial = reused.signer_one_partial;
        assert!(validate_prepared_claim_record(&reused).is_err());
        Ok(())
    }

    #[test]
    fn extraction_journal_codecs_reject_every_byte_tamper_and_never_encode_scalar(
    ) -> Result<(), LiveBitcoinError> {
        let intent = FreshClaimExtractionIntentV1 {
            prepared_record_digest: [0x71; 32],
            expected_txid: [0x72; 32],
            context_digest: [0x73; 32],
            minimum_confirmations: 6,
        };
        let intent_bytes = encode_extraction_intent(&intent)?;
        assert_eq!(decode_extraction_intent(&intent_bytes)?, intent);
        for offset in 0..intent_bytes.len() {
            let mut tampered = intent_bytes.clone();
            tampered[offset] ^= 0x80;
            assert!(
                decode_extraction_intent(&tampered).is_err(),
                "tampered extraction-intent byte {offset} was accepted"
            );
        }
        let mut trailing_intent = intent_bytes.clone();
        trailing_intent.push(0);
        assert!(decode_extraction_intent(&trailing_intent).is_err());

        let intent_digest = digest(CLAIM_EXTRACTION_INTENT_DIGEST_DOMAIN, &intent_bytes)?;
        let complete = FreshClaimExtractionCompleteV1 {
            intent_digest,
            expected_txid: intent.expected_txid,
            canonical_transaction_digest: [0x74; 32],
        };
        let complete_bytes = encode_extraction_complete(&complete)?;
        assert_eq!(decode_extraction_complete(&complete_bytes)?, complete);
        for offset in 0..complete_bytes.len() {
            let mut tampered = complete_bytes.clone();
            tampered[offset] ^= 0x80;
            assert!(
                decode_extraction_complete(&tampered).is_err(),
                "tampered extraction-complete byte {offset} was accepted"
            );
        }
        let mut trailing_complete = complete_bytes.clone();
        trailing_complete.push(0);
        assert!(decode_extraction_complete(&trailing_complete).is_err());

        let scalar_marker = [0xa7; 32];
        assert!(!intent_bytes
            .windows(scalar_marker.len())
            .any(|window| window == scalar_marker));
        assert!(!complete_bytes
            .windows(scalar_marker.len())
            .any(|window| window == scalar_marker));

        let finalization_intent = FreshClaimFinalizationIntentV1 {
            prepared_record_digest: [0x75; 32],
            expected_txid: [0x76; 32],
            extraction_context_digest: [0x77; 32],
        };
        let finalization_intent_bytes = encode_finalization_intent(&finalization_intent)?;
        assert_eq!(
            decode_finalization_intent(&finalization_intent_bytes)?,
            finalization_intent
        );
        for offset in 0..finalization_intent_bytes.len() {
            let mut tampered = finalization_intent_bytes.clone();
            tampered[offset] ^= 0x80;
            assert!(decode_finalization_intent(&tampered).is_err());
        }
        let canonical_transaction = serialize(&prepared_claim_record()?.transaction);
        let finalized = FreshClaimFinalizedRecordV1 {
            prepared_record_digest: finalization_intent.prepared_record_digest,
            expected_txid: finalization_intent.expected_txid,
            extraction_context_digest: finalization_intent.extraction_context_digest,
            canonical_transaction_digest: digest(
                EXACT_CLAIM_DIGEST_DOMAIN,
                &canonical_transaction,
            )?,
            canonical_transaction,
        };
        let finalized_bytes = encode_finalized_claim(&finalized)?;
        assert_eq!(decode_finalized_claim(&finalized_bytes)?, finalized);
        for offset in 0..finalized_bytes.len() {
            let mut tampered = finalized_bytes.clone();
            tampered[offset] ^= 0x80;
            assert!(decode_finalized_claim(&tampered).is_err());
        }
        assert!(!finalization_intent_bytes
            .windows(scalar_marker.len())
            .any(|window| window == scalar_marker));

        let root = store_root("claim-extraction-journal")?;
        let store = BitcoinPrebroadcastStoreV1::open_or_create(&root)?;
        store
            .store
            .publish(StageKind::FreshClaimExtractionIntent, &intent_bytes)?;
        store
            .store
            .publish(StageKind::FreshClaimExtractionIntent, &intent_bytes)?;
        let mut conflicting_intent = intent;
        conflicting_intent.minimum_confirmations += 1;
        assert!(matches!(
            store.store.publish(
                StageKind::FreshClaimExtractionIntent,
                &encode_extraction_intent(&conflicting_intent)?
            ),
            Err(LiveBitcoinError::StateConflict)
        ));
        store
            .store
            .publish(StageKind::FreshClaimExtractionComplete, &complete_bytes)?;
        store
            .store
            .publish(StageKind::FreshClaimExtractionComplete, &complete_bytes)?;
        let mut conflicting_complete = complete;
        conflicting_complete.expected_txid[0] ^= 1;
        assert!(matches!(
            store.store.publish(
                StageKind::FreshClaimExtractionComplete,
                &encode_extraction_complete(&conflicting_complete)?
            ),
            Err(LiveBitcoinError::StateConflict)
        ));
        drop(store);
        cleanup_store(&root);
        Ok(())
    }

    #[test]
    fn post_m8_reopen_fails_closed_on_missing_half_and_issues_once() -> Result<(), LiveBitcoinError>
    {
        let empty_root = store_root("claim-empty")?;
        let empty = BitcoinPrebroadcastStoreV1::open_or_create(&empty_root)?;
        let record = prepared_claim_record()?;
        let binding = claim_binding_from_record(&record);
        assert!(empty.reopen_fresh_claim(&binding)?.is_none());
        drop(empty);
        cleanup_store(&empty_root);

        let intent_only_root = store_root("claim-intent-only")?;
        let intent_only = BitcoinPrebroadcastStoreV1::open_or_create(&intent_only_root)?;
        intent_only.store.publish(
            StageKind::FreshClaimIntent,
            &encode_claim_intent(&record.public)?,
        )?;
        assert!(matches!(
            intent_only.reopen_fresh_claim(&binding),
            Err(LiveBitcoinError::StateConflict)
        ));
        drop(intent_only);
        cleanup_store(&intent_only_root);

        let corrupt_staging_root = store_root("claim-corrupt-staging")?;
        let corrupt_staging = BitcoinPrebroadcastStoreV1::open_or_create(&corrupt_staging_root)?;
        corrupt_staging.store.publish(
            StageKind::FreshClaimIntent,
            &encode_claim_intent(&record.public)?,
        )?;
        let corrupt_path = corrupt_staging_root.join(".fresh-claim-prepared.v1.staging");
        std::fs::write(&corrupt_path, [0x81; 96])
            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        std::fs::set_permissions(&corrupt_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        assert!(matches!(
            corrupt_staging.reopen_fresh_claim(&binding),
            Err(LiveBitcoinError::StateConflict)
        ));
        assert!(!corrupt_path.exists());
        drop(corrupt_staging);
        cleanup_store(&corrupt_staging_root);

        let prepared_only_root = store_root("claim-prepared-only")?;
        let prepared_only = BitcoinPrebroadcastStoreV1::open_or_create(&prepared_only_root)?;
        prepared_only.store.publish(
            StageKind::FreshClaimPrepared,
            &encode_prepared_claim_record(&record)?,
        )?;
        assert!(matches!(
            prepared_only.reopen_fresh_claim(&binding),
            Err(LiveBitcoinError::StateConflict)
        ));
        drop(prepared_only);
        cleanup_store(&prepared_only_root);

        let finalization_torn_root = store_root("claim-finalization-torn")?;
        let finalization_torn =
            BitcoinPrebroadcastStoreV1::open_or_create(&finalization_torn_root)?;
        finalization_torn.store.publish(
            StageKind::FreshClaimIntent,
            &encode_claim_intent(&record.public)?,
        )?;
        finalization_torn.store.publish(
            StageKind::FreshClaimPrepared,
            &encode_prepared_claim_record(&record)?,
        )?;
        finalization_torn.store.publish(
            StageKind::FreshClaimFinalizationIntent,
            &encode_finalization_intent(&FreshClaimFinalizationIntentV1 {
                prepared_record_digest: [0x78; 32],
                expected_txid: [0x79; 32],
                extraction_context_digest: [0x7a; 32],
            })?,
        )?;
        assert!(matches!(
            finalization_torn.reopen_fresh_claim(&binding),
            Err(LiveBitcoinError::StateConflict)
        ));
        drop(finalization_torn);
        cleanup_store(&finalization_torn_root);

        let resumable_root = store_root("claim-finalization-intent-resume")?;
        let resumable = BitcoinPrebroadcastStoreV1::open_or_create(&resumable_root)?;
        resumable
            .store
            .publish(StageKind::FreshAuthority, &encode_authority(&authority())?)?;
        resumable
            .store
            .publish(StageKind::FreshTemplates, &encode_receipt(&receipt()?)?)?;
        let encoded_record = encode_prepared_claim_record(&record)?;
        resumable.store.publish(
            StageKind::FreshClaimIntent,
            &encode_claim_intent(&record.public)?,
        )?;
        resumable
            .store
            .publish(StageKind::FreshClaimPrepared, &encoded_record)?;
        let prepared_record_digest = digest(CLAIM_PREPARED_DIGEST_DOMAIN, &encoded_record)?;
        let extraction = PreparedFreshBitcoinClaimV1 {
            record: decode_prepared_claim_record(&encoded_record)?,
            record_digest: prepared_record_digest,
            authority_instance: Rc::clone(&resumable.authority_instance),
        }
        .extraction_authority()?;
        resumable.store.publish(
            StageKind::FreshClaimFinalizationIntent,
            &encode_finalization_intent(&FreshClaimFinalizationIntentV1 {
                prepared_record_digest,
                expected_txid: extraction.expected_txid(),
                extraction_context_digest: extraction.context_digest()?,
            })?,
        )?;
        let Some(ReopenedFreshBitcoinClaimV1::ExtractionReady(recovered)) =
            resumable.reopen_fresh_claim(&binding)?
        else {
            return Err(LiveBitcoinError::StateConflict);
        };
        assert!(recovered.authenticates_store(&resumable));
        let (recovered_public, recovered_extraction) =
            recovered.into_recovery_extraction_parts()?;
        assert_eq!(recovered_public, record.public);
        assert_eq!(
            recovered_extraction.expected_txid(),
            extraction.expected_txid()
        );
        drop(recovered_extraction);
        drop(extraction);
        drop(resumable);
        cleanup_store(&resumable_root);

        let valid_root = store_root("claim-valid-reopen")?;
        let valid = BitcoinPrebroadcastStoreV1::open_or_create(&valid_root)?;
        valid
            .store
            .publish(StageKind::FreshAuthority, &encode_authority(&authority())?)?;
        valid
            .store
            .publish(StageKind::FreshTemplates, &encode_receipt(&receipt()?)?)?;
        valid.store.publish(
            StageKind::FreshClaimIntent,
            &encode_claim_intent(&record.public)?,
        )?;
        valid.store.publish(
            StageKind::FreshClaimPrepared,
            &encode_prepared_claim_record(&record)?,
        )?;
        let ReopenedFreshBitcoinClaimV1::Prepared(reopened) =
            valid
                .reopen_fresh_claim(&binding)?
                .ok_or(LiveBitcoinError::StateConflict)?
        else {
            return Err(LiveBitcoinError::StateConflict);
        };
        assert!(reopened.authenticates_store(&valid));
        assert_eq!(
            reopened.prepared_record_digest(),
            digest(
                CLAIM_PREPARED_DIGEST_DOMAIN,
                &encode_prepared_claim_record(&record)?
            )?
        );
        assert!(matches!(
            valid.reopen_fresh_claim(&binding),
            Err(LiveBitcoinError::StateConflict)
        ));
        drop(reopened);
        drop(valid);
        cleanup_store(&valid_root);

        let owner_root = store_root("claim-owner")?;
        let foreign_root = store_root("claim-foreign-owner")?;
        let owner = BitcoinPrebroadcastStoreV1::open_or_create(&owner_root)?;
        let foreign = BitcoinPrebroadcastStoreV1::open_or_create(&foreign_root)?;
        owner.issue_fresh_claim_authority()?;
        assert!(matches!(
            owner.issue_fresh_claim_authority(),
            Err(LiveBitcoinError::StateConflict)
        ));
        let prepared = PreparedFreshBitcoinClaimV1 {
            record,
            record_digest: [0x75; 32],
            authority_instance: Rc::clone(&owner.authority_instance),
        };
        assert!(prepared.authenticates_store(&owner));
        assert!(!prepared.authenticates_store(&foreign));
        drop(prepared);
        drop(owner);
        drop(foreign);
        cleanup_store(&owner_root);
        cleanup_store(&foreign_root);
        Ok(())
    }

    #[test]
    fn finalized_claim_reopens_without_scalar_before_or_after_actuator_retention(
    ) -> Result<(), LiveBitcoinError> {
        let root = store_root("claim-finalized-recovery")?;
        let store = BitcoinPrebroadcastStoreV1::open_or_create(&root)?;
        let (record, mut scalar) = cryptographic_prepared_claim_record()?;
        let binding = claim_binding_from_record(&record);
        store
            .store
            .publish(StageKind::FreshAuthority, &encode_authority(&authority())?)?;
        store
            .store
            .publish(StageKind::FreshTemplates, &encode_receipt(&receipt()?)?)?;
        store.store.publish(
            StageKind::FreshClaimIntent,
            &encode_claim_intent(&record.public)?,
        )?;
        let encoded_prepared = encode_prepared_claim_record(&record)?;
        store
            .store
            .publish(StageKind::FreshClaimPrepared, &encoded_prepared)?;
        let prepared = PreparedFreshBitcoinClaimV1 {
            record,
            record_digest: digest(CLAIM_PREPARED_DIGEST_DOMAIN, &encoded_prepared)?,
            authority_instance: Rc::clone(&store.authority_instance),
        };
        let finalized = prepared.finalize_claim(&store, &mut scalar)?;
        assert_eq!(scalar, [0; 32]);
        let expected_txid = finalized.extraction.expected_txid();
        let expected_exact = finalized.canonical_transaction.clone();
        drop(finalized);
        drop(store);

        let reopened_store = BitcoinPrebroadcastStoreV1::open_existing(&root)?;
        let ReopenedFreshBitcoinClaimV1::Finalized(reopened) = reopened_store
            .reopen_fresh_claim(&binding)?
            .ok_or(LiveBitcoinError::StateConflict)?
        else {
            return Err(LiveBitcoinError::StateConflict);
        };
        assert!(reopened.authenticates_store(&reopened_store));
        let (_public, exact, extraction) = reopened.into_parts();
        assert_eq!(exact, expected_exact);
        assert_eq!(extraction.expected_txid(), expected_txid);
        drop(extraction);
        drop(reopened_store);

        let retried_store = BitcoinPrebroadcastStoreV1::open_existing(&root)?;
        let ReopenedFreshBitcoinClaimV1::Finalized(retried) = retried_store
            .reopen_fresh_claim(&binding)?
            .ok_or(LiveBitcoinError::StateConflict)?
        else {
            return Err(LiveBitcoinError::StateConflict);
        };
        let (_public, retried_exact, retried_extraction) = retried.into_parts();
        assert_eq!(retried_exact, expected_exact);
        assert_eq!(retried_extraction.expected_txid(), expected_txid);
        drop(retried_extraction);
        drop(retried_store);
        cleanup_store(&root);
        Ok(())
    }

    #[test]
    fn payout_face_record_is_canonical_and_one_shot() -> Result<(), LiveBitcoinError> {
        let receipt = receipt()?;
        let record = fresh_payout_face_record(&receipt)?;
        let bytes = encode_fresh_payout_face_record(&record)?;
        let decoded = decode_fresh_payout_face_record(&bytes)?;
        validate_fresh_payout_face_record(&decoded, &receipt)?;
        let mut retained = Some(authenticated_payout_face(decoded)?);
        let authority = take_payout_face_evidence(&mut retained)?;
        assert_eq!(authority.revision(), 1);
        assert_eq!(authority.route_binding(), receipt.route_binding());
        assert_eq!(authority.receipt_digest(), receipt.receipt_digest());
        assert_eq!(
            authority.contract_amount_sat(),
            receipt.contract_amount_sat()
        );
        assert_eq!(
            authority.claim_destination_script_pubkey(),
            receipt.claim_destination_script_pubkey()
        );
        assert_eq!(
            authority.claim_output_amount_sat(),
            receipt.claim_output_amount_sat()
        );
        assert_eq!(
            authority.claim_template_hash(),
            receipt.claim_template_hash()
        );
        assert_ne!(authority.evidence_digest(), [0; 32]);
        assert!(matches!(
            take_payout_face_evidence(&mut retained),
            Err(LiveBitcoinError::StateConflict)
        ));
        Ok(())
    }

    #[test]
    fn funding_only_projection_reconstructs_exact_plan_without_legacy_authority(
    ) -> Result<(), LiveBitcoinError> {
        let record = authority();
        let (expected, _, _) = plan_for(&record)?;
        let receipt = receipt()?;
        let (projected, request) = funding_only_plan_and_request_from_public(
            &receipt,
            record.request.funding_fee_rate_sat_vb,
            record.request.refund_delay,
        )?;

        assert_eq!(projected, expected);
        assert_eq!(projected.canonical_digest()?, receipt.plan_digest());
        assert_eq!(request, record.request);
        Ok(())
    }

    #[test]
    fn payout_face_refuses_route_receipt_script_amount_and_template_transplants(
    ) -> Result<(), LiveBitcoinError> {
        let receipt = receipt()?;
        let base = fresh_payout_face_record(&receipt)?;
        let mut mutations = Vec::new();
        let mut changed = fresh_payout_face_record(&receipt)?;
        changed.route_binding[0] ^= 1;
        mutations.push(changed);
        let mut changed = fresh_payout_face_record(&receipt)?;
        changed.receipt_digest[0] ^= 1;
        mutations.push(changed);
        let mut changed = fresh_payout_face_record(&receipt)?;
        changed.contract_amount_sat += 1;
        mutations.push(changed);
        let mut changed = fresh_payout_face_record(&receipt)?;
        changed.claim_destination_script_pubkey.push(0x51);
        mutations.push(changed);
        let mut changed = fresh_payout_face_record(&receipt)?;
        changed.claim_output_amount_sat += 1;
        mutations.push(changed);
        let mut changed = fresh_payout_face_record(&receipt)?;
        changed.claim_template_hash[0] ^= 1;
        mutations.push(changed);
        let mut changed = fresh_payout_face_record(&receipt)?;
        changed.revision = 2;
        mutations.push(changed);

        for changed in mutations {
            assert!(matches!(
                validate_fresh_payout_face_record(&changed, &receipt),
                Err(LiveBitcoinError::CorruptRecord)
            ));
            assert_ne!(
                fresh_payout_face_record_digest(&changed)?,
                base.record_digest
            );
        }
        Ok(())
    }

    #[test]
    fn payout_face_stage_converges_and_reopen_never_repairs_absence() -> Result<(), LiveBitcoinError>
    {
        let root = store_root("resume")?;
        let receipt = receipt()?;
        let store = BitcoinPrebroadcastStoreV1::open_or_create(&root)?;
        let first = store.load_fresh_payout_face(&receipt, true)?;
        let replay = store.load_fresh_payout_face(&receipt, true)?;
        assert_eq!(first.revision(), replay.revision());
        assert_eq!(first.evidence_digest(), replay.evidence_digest());
        drop(store);

        let reopened = BitcoinPrebroadcastStoreV1::open_or_create(&root)?;
        let recovered = reopened.load_fresh_payout_face(&receipt, false)?;
        assert_eq!(recovered.revision(), 1);
        assert_eq!(recovered.evidence_digest(), first.evidence_digest());
        drop(reopened);

        std::fs::remove_file(root.join("fresh-face-evidence.v1"))
            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        let reopened = BitcoinPrebroadcastStoreV1::open_or_create(&root)?;
        assert!(matches!(
            reopened.load_fresh_payout_face(&receipt, false),
            Err(LiveBitcoinError::CorruptRecord)
        ));
        assert!(!root.join("fresh-face-evidence.v1").exists());
        drop(reopened);
        cleanup_store(&root);
        Ok(())
    }

    #[test]
    fn payout_face_stage_refuses_same_revision_substitution_and_cross_root_transplant(
    ) -> Result<(), LiveBitcoinError> {
        let first_root = store_root("first")?;
        let second_root = store_root("second")?;
        let receipt = receipt()?;
        let first = BitcoinPrebroadcastStoreV1::open_or_create(&first_root)?;
        drop(first.load_fresh_payout_face(&receipt, true)?);
        let exact_before = std::fs::read(first_root.join("fresh-face-evidence.v1"))
            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        let mut foreign_receipt = receipt.clone();
        foreign_receipt.claim_output.script_pubkey.push(0x51);
        foreign_receipt.receipt_digest = receipt_digest(&foreign_receipt)?;
        assert!(matches!(
            first.load_fresh_payout_face(&foreign_receipt, true),
            Err(LiveBitcoinError::CorruptRecord)
        ));
        let exact_after = std::fs::read(first_root.join("fresh-face-evidence.v1"))
            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        assert_eq!(exact_after, exact_before);
        drop(first);

        {
            let second = BitcoinPrebroadcastStoreV1::open_or_create(&second_root)?;
            drop(second);
        }
        std::fs::copy(
            first_root.join("fresh-face-evidence.v1"),
            second_root.join("fresh-face-evidence.v1"),
        )
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        std::fs::set_permissions(
            second_root.join("fresh-face-evidence.v1"),
            std::fs::Permissions::from_mode(0o600),
        )
        .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        let second = BitcoinPrebroadcastStoreV1::open_or_create(&second_root)?;
        assert!(matches!(
            second.load_fresh_payout_face(&receipt, false),
            Err(LiveBitcoinError::CorruptRecord) | Err(LiveBitcoinError::StoreUnavailable)
        ));
        drop(second);
        cleanup_store(&first_root);
        cleanup_store(&second_root);
        Ok(())
    }

    fn retained_claim_fixture() -> Result<
        (
            RetainedFreshBitcoinClaimAuthorityV1,
            BitcoinFreshClaimBindingV1,
        ),
        LiveBitcoinError,
    > {
        let record = authority();
        let (plan, claim_roster, refund_key_xonly) = plan_for(&record)?;
        let plan_digest = plan.canonical_digest()?;
        let mut binding = BitcoinFreshClaimBindingV1 {
            settlement_id: [10; 32],
            session_id: [11; 32],
            terms_hash: [12; 32],
            funding_txid: [13; 32],
            funding_vout: 1,
            funding_amount_sat: record.request.amount_sat,
            destination_script_pubkey: record.claim_script_pubkey.clone(),
            fee_sat: record.request.claim_fee_sat,
            expected_template_hash: [0; 32],
            adaptor_point: PublicKey::from_secret_key(
                &Secp256k1::new(),
                &SecretKey::from_slice(&[0x44; 32])
                    .map_err(|_| LiveBitcoinError::InvalidRequest)?,
            )
            .serialize(),
        };
        let transaction = exact_claim_transaction(&binding)?;
        let template = exact_claim_template(
            &transaction,
            &binding,
            &plan.contract_script_pubkey,
            TemplateNetworkV1::Regtest,
        );
        binding.expected_template_hash =
            frozen_template_digest_v1(&template).map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let retained = RetainedFreshBitcoinClaimAuthorityV1 {
            network: record.network,
            route_binding: record.request.route_binding,
            plan_digest,
            receipt_digest: [14; 32],
            funding_txid: binding.funding_txid,
            funding_vout: binding.funding_vout,
            funding_amount_sat: binding.funding_amount_sat,
            claim_roster,
            refund_key_xonly,
            refund_delay: record.request.refund_delay,
            contract_script_pubkey: plan.contract_script_pubkey,
            claim_destination_script_pubkey: record.claim_script_pubkey,
            claim_output_amount_sat: binding
                .funding_amount_sat
                .checked_sub(binding.fee_sat)
                .ok_or(LiveBitcoinError::InvalidRequest)?,
            claim_template_hash: binding.expected_template_hash,
            maker_secret: record.maker_secret,
            taker_secret: record.taker_secret,
        };
        Ok((retained, binding))
    }

    #[test]
    fn authority_codec_retains_real_plan_material_exactly() -> Result<(), LiveBitcoinError> {
        let record = authority();
        let encoded = Zeroizing::new(encode_authority(&record)?);
        let decoded = decode_authority(encoded.as_ref())?;
        assert_eq!(decoded.request, record.request);
        assert_eq!(decoded.claim_script_pubkey, record.claim_script_pubkey);
        assert_eq!(decoded.refund_script_pubkey, record.refund_script_pubkey);
        assert_eq!(&*decoded.maker_secret, &*record.maker_secret);
        assert_eq!(&*decoded.taker_secret, &*record.taker_secret);
        assert_eq!(&*decoded.refund_secret, &*record.refund_secret);
        let (plan, roster, refund_key) = plan_for(&decoded)?;
        assert_eq!(plan.amount_sat, 100_000);
        assert_eq!(plan.refund_outputs[0].amount_sat, 98_000);
        assert_eq!(roster.participants()[0].participant_id, [2; 32]);
        assert_eq!(plan.refund_contract.refund_key_xonly, refund_key);
        Ok(())
    }

    #[test]
    fn fresh_request_rejects_zero_or_untagged_economics() {
        let mut invalid = request();
        invalid.route_binding = [0; 32];
        assert_eq!(
            validate_request(invalid),
            Err(LiveBitcoinError::InvalidRequest)
        );
        invalid = request();
        invalid.refund_delay = BitcoinRefundDelayV1::Time512Seconds(0);
        assert_eq!(
            validate_request(invalid),
            Err(LiveBitcoinError::InvalidRequest)
        );
        invalid = request();
        invalid.claim_fee_sat = invalid.amount_sat;
        assert_eq!(
            validate_request(invalid),
            Err(LiveBitcoinError::InvalidRequest)
        );
    }

    #[test]
    fn exact_fresh_claim_binds_receipt_template_before_nonce_custody(
    ) -> Result<(), LiveBitcoinError> {
        let (authority, binding) = retained_claim_fixture()?;
        let expected = binding.expected_template_hash;
        let bound = authority.bind_exact_claim(binding)?;
        assert_eq!(bound.template_digest, expected);
        assert_eq!(bound.contract.script_pubkey.len(), 34);
        Ok(())
    }

    #[test]
    fn template_mismatch_cannot_create_a_nonce_vault() -> Result<(), LiveBitcoinError> {
        let (authority, mut binding) = retained_claim_fixture()?;
        binding.expected_template_hash[0] ^= 1;
        let absent_root =
            std::env::temp_dir().join(format!("btc-live-bind-before-nonce-{}", std::process::id()));
        let signer_one_vault = absent_root.join("signer-one.sqlite3");
        let signer_two_vault = absent_root.join("signer-two.sqlite3");
        assert!(!signer_one_vault.exists());
        assert!(!signer_two_vault.exists());
        assert!(matches!(
            authority.bind_exact_claim(binding),
            Err(LiveBitcoinError::ClaimMismatch)
        ));
        assert!(!signer_one_vault.exists());
        assert!(!signer_two_vault.exists());
        Ok(())
    }
}
