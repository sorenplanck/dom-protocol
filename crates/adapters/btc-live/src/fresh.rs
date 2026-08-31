//! Genuine pre-bootstrap Bitcoin plan and retained refund authority.

use std::path::Path;

use adapter_btc::roster::{
    BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1, ROSTER_VERSION,
};
use adapter_btc::rounds::{ClaimRound, ClaimRoundInputs, LocalSigner};
use adapter_btc::sighash::key_path_sighash_default;
use adapter_btc::taproot::{build_taproot_contract, TaprootContractV1};
use adapter_btc::templates::{
    frozen_template_digest_v1, BitcoinPrevoutV1, BitcoinTxInV1, BitcoinTxOutV1,
    FrozenBitcoinTemplateV1,
};
use adapter_btc::timelock::{AnchoredCrossChainWindowV1, BitcoinCsvDelayV1};
use adapter_btc::types::BitcoinNetworkV1 as TemplateNetworkV1;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_crypto::{NonceParity, SecpContext};
use btc_vault::{
    BitcoinNoncePermitV1, BitcoinNoncePurposeV1, BitcoinNonceSealKeyV1, BitcoinNonceVault,
    BitcoinSigningPhaseV1, PersistedArtifactDescriptorV1,
};
use zeroize::Zeroizing;

use crate::authority::{
    BitcoinRefundDelayV1, BitcoinRefundSignatureV1, BitcoinRefundSigningRequestV1,
    RetainedBitcoinRefundSignerV1,
};
use crate::funding::{
    prepared_template_digests, ArmedBitcoinFundingV1, BitcoinPrebroadcastPlanV1,
    BitcoinPrebroadcastStoreV1, BitcoinRefundContractV1, BitcoinRefundOutputV1,
    PreparedBitcoinFundingV1, ReopenedBitcoinFundingV1,
};
use crate::rpc::{BitcoinCoreNetworkV1, BitcoinCoreRpcClientV1, MAX_SIGNET_CHALLENGE_BYTES};
use crate::store::StageKind;
use crate::LiveBitcoinError;

const AUTHORITY_MAGIC: &[u8; 8] = b"DBTCFAV1";
const TEMPLATES_MAGIC: &[u8; 8] = b"DBTCFTV1";
const CODEC_VERSION: u16 = 1;
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/FRESH-RECEIPT/V1\0";
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;
const MAX_FEE_RATE_SAT_VB: u64 = 1_000_000;
const MAX_KEY_ATTEMPTS: usize = 128;

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
pub struct RetainedFreshBitcoinClaimAuthorityV1 {
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

/// Opaque exact-template authority ready to consume the two M.8 grants.
///
/// Construction proves the complete funding prevout, roster, refund leaf,
/// Taproot tweak, destination, fee and frozen template before any nonce seal
/// key or vault path is accepted. It is linear and has no codec or debug view.
pub struct BoundFreshBitcoinClaimAuthorityV1 {
    binding: BitcoinFreshClaimBindingV1,
    roster: ParticipantKeyRosterV1,
    contract: TaprootContractV1,
    transaction: Transaction,
    template_digest: [u8; 32],
    tap_sighash: [u8; 32],
    maker_secret: Zeroizing<[u8; 32]>,
    taker_secret: Zeroizing<[u8; 32]>,
}

/// Public output of fresh-key claim preparation before adaptor revelation.
///
/// This type contains only the unsigned transaction, adaptor pre-signature
/// and public restart metadata. The two private keys and both secret nonces
/// are absent.
pub struct PreparedFreshBitcoinClaimV1 {
    parts: FreshBitcoinPreparedClaimPartsV1,
}

/// Public non-secret fields imported by the legacy F5 continuation codec.
pub struct FreshBitcoinPreparedClaimPartsV1 {
    /// Route settlement bound to both nonce permits.
    pub settlement_id: [u8; 32],
    /// Exact signing session.
    pub session_id: [u8; 32],
    /// Canonical settlement-terms digest.
    pub terms_hash: [u8; 32],
    /// Funding transaction identifier in internal byte order.
    pub funding_txid: [u8; 32],
    /// Exact funding output index.
    pub funding_vout: u32,
    /// Exact funding output amount.
    pub funding_amount_sat: u64,
    /// Frozen unsigned cooperative-claim transaction.
    pub transaction: Transaction,
    /// Manifest-matching frozen template digest.
    pub template_digest: [u8; 32],
    /// BIP341 key-path `SIGHASH_DEFAULT` message.
    pub tap_sighash: [u8; 32],
    /// Aggregate nonce parity selected by MuSig2.
    pub nonce_parity: NonceParity,
    /// Exact public adaptor point.
    pub adaptor_point: [u8; 33],
    /// Tweaked Taproot output key.
    pub output_xonly: [u8; 32],
    /// Aggregate adaptor pre-signature.
    pub pre_signature: [u8; 64],
    /// Durable public descriptor for participant one's partial signature.
    pub signer_one_partial: Option<PersistedArtifactDescriptorV1>,
    /// Durable public descriptor for participant two's partial signature.
    pub signer_two_partial: Option<PersistedArtifactDescriptorV1>,
}

impl PreparedFreshBitcoinClaimV1 {
    /// Consumes the preparation into its public continuation fields.
    #[must_use]
    pub fn into_parts(self) -> FreshBitcoinPreparedClaimPartsV1 {
        self.parts
    }
}

impl RetainedFreshBitcoinClaimAuthorityV1 {
    /// Recreates and authenticates the exact cooperative claim without
    /// touching a nonce key store or vault.
    pub fn bind_exact_claim(
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
        let tap_sighash =
            key_path_sighash_default(&template, 0).map_err(|_| LiveBitcoinError::ClaimMismatch)?;

        Ok(BoundFreshBitcoinClaimAuthorityV1 {
            binding,
            roster: self.claim_roster,
            contract,
            transaction,
            template_digest,
            tap_sighash,
            maker_secret: self.maker_secret,
            taker_secret: self.taker_secret,
        })
    }
}

impl BoundFreshBitcoinClaimAuthorityV1 {
    /// Consumes both M.8 authorizations into the two exact durable nonce vaults.
    ///
    /// All template and key bindings were completed by
    /// [`RetainedFreshBitcoinClaimAuthorityV1::bind_exact_claim`] before this
    /// method can receive any custody path. Both fixed arrays are ordered as
    /// the canonical claim roster: signer one (Maker), then signer two (Taker).
    pub fn prepare_after_m8(
        self,
        m8_authorizations: [AnchoredCrossChainWindowV1; 2],
        signer_seal_keys: [&BitcoinNonceSealKeyV1; 2],
        signer_vaults: [&Path; 2],
    ) -> Result<PreparedFreshBitcoinClaimV1, LiveBitcoinError> {
        let [authorization_one, authorization_two] = m8_authorizations;
        let [signer_one_seal_key, signer_two_seal_key] = signer_seal_keys;
        let [signer_one_vault, signer_two_vault] = signer_vaults;
        if authorization_one.settlement_terms_hash() != self.binding.terms_hash
            || authorization_two.settlement_terms_hash() != self.binding.terms_hash
            || authorization_one.anchor_evidence_digest() == [0; 32]
            || authorization_one != authorization_two
        {
            return Err(LiveBitcoinError::ClaimMismatch);
        }
        // Audit finding F1: this context is handed to `ClaimRoundInputs` as
        // `crypto`, beside `local_secret`, and on into nonce generation and
        // partial signing. A constant seed makes the blinding predictable, so
        // it takes fresh entropy like the other two signing contexts.
        let context = SecpContext::new(&*fresh_entropy()?);
        let ordered_keys = [
            self.roster.participants()[0].compressed_key,
            self.roster.participants()[1].compressed_key,
        ];
        let mut keyagg = context
            .key_agg(&ordered_keys)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let tweaked = context
            .apply_tap_tweak(&mut keyagg, &self.contract.tweak)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        if tweaked.output_xonly != self.contract.output_key_xonly {
            return Err(LiveBitcoinError::ClaimMismatch);
        }

        let permit_one = BitcoinNoncePermitV1 {
            settlement_id: self.binding.settlement_id,
            session_id: self.binding.session_id,
            participant_id: self.roster.participants()[0].participant_id,
            purpose: BitcoinNoncePurposeV1::ClaimAdaptor,
            phase: BitcoinSigningPhaseV1::NonceGeneration,
            roster_hash: self
                .roster
                .roster_hash()
                .map_err(|_| LiveBitcoinError::CorruptRecord)?,
            terms_hash: self.binding.terms_hash,
            claim_template_hash: self.template_digest,
            tap_sighash: self.tap_sighash,
            adaptor_point: self.binding.adaptor_point,
            attempt: 0,
        };
        let permit_two = BitcoinNoncePermitV1 {
            participant_id: self.roster.participants()[1].participant_id,
            ..permit_one
        };
        let mut vault_one = BitcoinNonceVault::open(signer_one_vault)
            .map_err(|_| LiveBitcoinError::ClaimNonceCustody)?;
        let mut vault_two = BitcoinNonceVault::open(signer_two_vault)
            .map_err(|_| LiveBitcoinError::ClaimNonceCustody)?;
        let inputs_one = ClaimRoundInputs {
            crypto: &context,
            keyagg: &keyagg,
            roster: &self.roster,
            local: LocalSigner::First,
            local_secret: &self.maker_secret,
            tap_sighash: &self.tap_sighash,
            adaptor_point: &self.binding.adaptor_point,
            output_xonly: &self.contract.output_key_xonly,
            permit: &permit_one,
        };
        let mut round_one = ClaimRound::prepare_after_m8(
            inputs_one,
            authorization_one,
            signer_one_seal_key,
            &mut vault_one,
        )
        .map_err(|_| LiveBitcoinError::ClaimNonceCustody)?;
        let inputs_two = ClaimRoundInputs {
            crypto: &context,
            keyagg: &keyagg,
            roster: &self.roster,
            local: LocalSigner::Second,
            local_secret: &self.taker_secret,
            tap_sighash: &self.tap_sighash,
            adaptor_point: &self.binding.adaptor_point,
            output_xonly: &self.contract.output_key_xonly,
            permit: &permit_two,
        };
        let mut round_two = ClaimRound::prepare_after_m8(
            inputs_two,
            authorization_two,
            signer_two_seal_key,
            &mut vault_two,
        )
        .map_err(|_| LiveBitcoinError::ClaimNonceCustody)?;
        let public_one = round_one
            .expose_local_pubnonce(&mut vault_one)
            .map_err(|_| LiveBitcoinError::ClaimNonceCustody)?;
        let public_two = round_two
            .expose_local_pubnonce(&mut vault_two)
            .map_err(|_| LiveBitcoinError::ClaimNonceCustody)?;
        round_one
            .ingest_counterparty_pubnonce(public_two)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        round_two
            .ingest_counterparty_pubnonce(public_one)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let parity_one = round_one
            .process_session()
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let parity_two = round_two
            .process_session()
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        if parity_one != parity_two {
            return Err(LiveBitcoinError::ClaimMismatch);
        }
        let partial_one = round_one
            .produce_local_partial(&mut vault_one)
            .map_err(|_| LiveBitcoinError::ClaimNonceCustody)?;
        let partial_two = round_two
            .produce_local_partial(&mut vault_two)
            .map_err(|_| LiveBitcoinError::ClaimNonceCustody)?;
        round_one
            .verify_counterparty_partial(&partial_two)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        round_two
            .verify_counterparty_partial(&partial_one)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let pre_one = round_one
            .aggregate_pre_signature(&partial_two)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        let pre_two = round_two
            .aggregate_pre_signature(&partial_one)
            .map_err(|_| LiveBitcoinError::ClaimMismatch)?;
        if pre_one != pre_two {
            return Err(LiveBitcoinError::ClaimMismatch);
        }

        Ok(PreparedFreshBitcoinClaimV1 {
            parts: FreshBitcoinPreparedClaimPartsV1 {
                settlement_id: self.binding.settlement_id,
                session_id: self.binding.session_id,
                terms_hash: self.binding.terms_hash,
                funding_txid: self.binding.funding_txid,
                funding_vout: self.binding.funding_vout,
                funding_amount_sat: self.binding.funding_amount_sat,
                transaction: self.transaction,
                template_digest: self.template_digest,
                tap_sighash: self.tap_sighash,
                nonce_parity: parity_one,
                adaptor_point: self.binding.adaptor_point,
                output_xonly: self.contract.output_key_xonly,
                pre_signature: pre_one,
                signer_one_partial: round_one.local_partial_descriptor(),
                signer_two_partial: round_two.local_partial_descriptor(),
            },
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
    signer: RetainedFreshBitcoinRefundSignerV1,
}

/// Restart-authenticated fresh route whose exact refund is already durable.
///
/// The public plan and receipt are retained only so a higher route layer can
/// authenticate the opaque armed capability against its final manifest.  No
/// funding bytes, refund bytes, private key, or RPC credential are exposed.
pub struct ReopenedFreshBitcoinRouteV1 {
    plan: BitcoinPrebroadcastPlanV1,
    receipt: BitcoinFreshRouteReceiptV1,
    armed: ArmedBitcoinFundingV1,
    claim_authority: RetainedFreshBitcoinClaimAuthorityV1,
}

impl ReopenedFreshBitcoinRouteV1 {
    /// Exact public plan reconstructed from the authenticated fresh authority.
    #[must_use]
    pub const fn plan(&self) -> &BitcoinPrebroadcastPlanV1 {
        &self.plan
    }

    /// Persisted secret-free template receipt for final-manifest authentication.
    #[must_use]
    pub const fn receipt(&self) -> &BitcoinFreshRouteReceiptV1 {
        &self.receipt
    }

    /// Consumes the restart authority after higher-layer authentication.
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

    /// Consumes the restart state while retaining the opaque cooperative-claim owner.
    ///
    /// Unlike [`Self::into_parts`], this handoff preserves the two zeroizing
    /// fresh claim keys for the post-M.8 signing transition. No raw secret is
    /// returned.
    #[must_use]
    pub fn into_parts_with_claim_authority(
        self,
    ) -> (
        BitcoinPrebroadcastPlanV1,
        BitcoinFreshRouteReceiptV1,
        ArmedBitcoinFundingV1,
        RetainedFreshBitcoinClaimAuthorityV1,
    ) {
        (self.plan, self.receipt, self.armed, self.claim_authority)
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
    /// Creates or reopens a genuine fresh Bitcoin route before the complete
    /// cross-chain manifest exists.
    ///
    /// Bitcoin Core generates and proves ownership of distinct claim/refund
    /// destinations.  Three canonical secp256k1 keys are generated from OS
    /// entropy and persisted in the same authenticated owner-only store.  The
    /// wallet then selects and locks real inputs.  Only after that selection
    /// are the exact funding, claim, and refund template hashes published.
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
            signer,
        })
    }

    /// Reopens an already refund-armed fresh route without preparing or signing again.
    ///
    /// The owner-only fresh authority is authenticated against the live Core
    /// identity and used only to reconstruct the exact public plan.  The
    /// persisted receipt and generic Armed stage must agree field-for-field;
    /// an empty or merely Prepared stage is rejected rather than implicitly
    /// consuming the retained refund key a second time.
    pub fn reopen_fresh_route(
        &self,
        rpc: &BitcoinCoreRpcClientV1,
        expected_route_binding: [u8; 32],
    ) -> Result<ReopenedFreshBitcoinRouteV1, LiveBitcoinError> {
        if expected_route_binding == [0; 32] {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        let authority_bytes = Zeroizing::new(
            self.store
                .read(StageKind::FreshAuthority)?
                .ok_or(LiveBitcoinError::CorruptRecord)?,
        );
        let authority = decode_authority(authority_bytes.as_ref())?;
        if authority.request.route_binding != expected_route_binding {
            return Err(LiveBitcoinError::StateConflict);
        }
        require_authority_binding(rpc, authority.request, &authority)?;
        let (plan, roster, refund_key_xonly) = plan_for(&authority)?;

        let receipt_bytes = self
            .store
            .read(StageKind::FreshTemplates)?
            .ok_or(LiveBitcoinError::CorruptRecord)?;
        let receipt = decode_receipt(&receipt_bytes)?;
        let armed = match self.reopen(rpc, expected_route_binding)? {
            Some(ReopenedBitcoinFundingV1::Armed(armed)) => armed,
            Some(ReopenedBitcoinFundingV1::Prepared(_)) | None => {
                return Err(LiveBitcoinError::FundingNotArmed);
            }
        };
        validate_reopened_receipt(ReopenedReceiptValidationV1 {
            receipt: &receipt,
            plan: &plan,
            request: authority.request,
            roster,
            refund_key_xonly,
            claim_script_pubkey: &authority.claim_script_pubkey,
            refund_script_pubkey: &authority.refund_script_pubkey,
            armed: &armed,
        })?;
        let claim_authority = RetainedFreshBitcoinClaimAuthorityV1 {
            network: authority.network,
            route_binding: receipt.route_binding,
            plan_digest: receipt.plan_digest,
            receipt_digest: receipt.receipt_digest,
            funding_txid: receipt.funding_txid,
            funding_vout: receipt.contract_vout,
            funding_amount_sat: receipt.contract_amount_sat,
            claim_roster: receipt.claim_roster,
            refund_key_xonly: receipt.refund_key_xonly,
            refund_delay: authority.request.refund_delay,
            contract_script_pubkey: receipt.contract_script_pubkey.clone(),
            claim_destination_script_pubkey: receipt.claim_output.script_pubkey.clone(),
            claim_output_amount_sat: receipt.claim_output.amount_sat,
            claim_template_hash: receipt.claim_template_hash,
            maker_secret: authority.maker_secret,
            taker_secret: authority.taker_secret,
        };
        Ok(ReopenedFreshBitcoinRouteV1 {
            plan,
            receipt,
            armed,
            claim_authority,
        })
    }

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

fn receipt_digest(receipt: &BitcoinFreshRouteReceiptV1) -> Result<[u8; 32], LiveBitcoinError> {
    digest(
        RECEIPT_DIGEST_DOMAIN,
        &encode_receipt_without_digest(receipt)?,
    )
}

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
