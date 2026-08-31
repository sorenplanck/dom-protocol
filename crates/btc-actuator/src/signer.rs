//! One-participant MuSig2 adaptor claim authority.

use adapter_btc::roster::{BitcoinSignerRoleV1, ParticipantKeyRosterV1};
use adapter_btc::rounds::{ClaimRound, ClaimRoundInputs, LocalSigner};
use adapter_btc::sighash::key_path_sighash_default;
use adapter_btc::taproot::{build_taproot_contract, TaprootContractV1};
use adapter_btc::templates::{
    frozen_template_digest_v1, BitcoinPrevoutV1, BitcoinTxInV1, BitcoinTxOutV1,
    FrozenBitcoinTemplateV1,
};
use adapter_btc::timelock::{AnchoredCrossChainWindowV1, BitcoinCsvDelayV1};
use adapter_btc::types::{BitcoinNetworkV1, PublicNonceBytesV1};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use btc_crypto::{NonceParity, SecpContext};
use btc_vault::{
    BitcoinNoncePermitV1, BitcoinNoncePurposeV1, BitcoinNonceSealKeyV1, BitcoinSigningPhaseV1,
};
use deployment_registry::ResolvedBitcoinDeploymentV1;
use zeroize::{Zeroize, Zeroizing};

use crate::model::{digest, resolved_deployment_digest, ExactBitcoinTransactionV1};
use crate::store::BitcoinParticipantNonceVaultV1;
use crate::{BitcoinActuatorErrorV1, Result};

const PARTICIPANT_AUTHORITY_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/PARTICIPANT-AUTHORITY/V1\0";
const CLAIM_SESSION_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/CLAIM-SESSION/V1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/CLAIM-TRANSCRIPT/V1\0";
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;

/// Participant role in the canonical two-party roster.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinParticipantRoleV1 {
    /// Maker, roster index zero.
    Maker,
    /// Taker, roster index one.
    Taker,
}

impl BitcoinParticipantRoleV1 {
    const fn roster_role(self) -> BitcoinSignerRoleV1 {
        match self {
            Self::Maker => BitcoinSignerRoleV1::Maker,
            Self::Taker => BitcoinSignerRoleV1::Taker,
        }
    }

    const fn local_signer(self) -> LocalSigner {
        match self {
            Self::Maker => LocalSigner::First,
            Self::Taker => LocalSigner::Second,
        }
    }

    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Maker => 1,
            Self::Taker => 2,
        }
    }
}

/// One route-scoped participant key authority.
///
/// The object owns exactly one secret key and cannot represent the remote
/// participant's key. It has no generic signing method, codec, clone or debug
/// view; its only operations are the fixed MuSig2 adaptor-claim transitions.
pub struct BitcoinParticipantClaimAuthorityV1 {
    route_id: [u8; 32],
    terms_digest: [u8; 32],
    registry_digest: [u8; 32],
    profile_digest: [u8; 32],
    deployment_digest: [u8; 32],
    participant_id: [u8; 32],
    role: BitcoinParticipantRoleV1,
    public_key: [u8; 33],
    authority_digest: [u8; 32],
    secret: Zeroizing<[u8; 32]>,
}

/// Authenticated public context for importing one Bitcoin participant key.
pub struct BitcoinParticipantClaimAuthorityRequestV1<'a> {
    /// Threshold-resolved Bitcoin deployment selected for the route.
    pub deployment: &'a ResolvedBitcoinDeploymentV1,
    /// Stable route identity.
    pub route_id: [u8; 32],
    /// Frozen settlement-terms digest.
    pub terms_digest: [u8; 32],
    /// Participant identity selected from the authenticated roster.
    pub participant_id: [u8; 32],
    /// Participant role selected from the authenticated roster.
    pub role: BitcoinParticipantRoleV1,
    /// Exact compressed public key committed by that roster entry.
    pub expected_public_key: [u8; 33],
}

impl BitcoinParticipantClaimAuthorityV1 {
    /// Imports one local participant key into an exact route/deployment scope.
    ///
    /// Production composition should source `secret` from an isolated wallet
    /// or OS credential boundary. The supplied buffer is zeroized immediately
    /// after import; the retained copy lives only in zeroizing storage.
    pub fn authorize_local_key(
        request: BitcoinParticipantClaimAuthorityRequestV1<'_>,
        secret: &mut [u8; 32],
    ) -> Result<Self> {
        let BitcoinParticipantClaimAuthorityRequestV1 {
            deployment,
            route_id,
            terms_digest,
            participant_id,
            role,
            expected_public_key,
        } = request;
        if route_id == [0; 32]
            || terms_digest == [0; 32]
            || participant_id == [0; 32]
            || deployment.registry_digest() == [0; 32]
            || deployment.profile_digest() == [0; 32]
        {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        deployment
            .profile()
            .validate()
            .map_err(|_| BitcoinActuatorErrorV1::InvalidScope)?;
        if !matches!(
            deployment.profile().kind,
            chain_profile::ChainKindV1::Bitcoin { .. }
        ) {
            return Err(BitcoinActuatorErrorV1::InvalidScope);
        }
        let retained_secret = Zeroizing::new(*secret);
        secret.zeroize();
        let secret_key = SecretKey::from_slice(retained_secret.as_ref())
            .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
        let mut secp = Secp256k1::new();
        let mut randomization = [0_u8; 32];
        getrandom::getrandom(&mut randomization)
            .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
        secp.seeded_randomize(&randomization);
        randomization.zeroize();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key).serialize();
        if public_key != expected_public_key {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        let deployment_digest = resolved_deployment_digest(deployment)?;
        let mut bytes = Vec::with_capacity(225);
        bytes.extend_from_slice(&route_id);
        bytes.extend_from_slice(&terms_digest);
        bytes.extend_from_slice(&deployment.registry_digest());
        bytes.extend_from_slice(&deployment.profile_digest());
        bytes.extend_from_slice(&deployment_digest);
        bytes.extend_from_slice(&participant_id);
        bytes.push(role.tag());
        bytes.extend_from_slice(&public_key);
        let authority_digest = digest(PARTICIPANT_AUTHORITY_DOMAIN, &bytes)?;
        Ok(Self {
            route_id,
            terms_digest,
            registry_digest: deployment.registry_digest(),
            profile_digest: deployment.profile_digest(),
            deployment_digest,
            participant_id,
            role,
            public_key,
            authority_digest,
            secret: retained_secret,
        })
    }

    /// Local public participant id.
    pub const fn participant_id(&self) -> [u8; 32] {
        self.participant_id
    }

    /// Local role; an instance can never answer for the other role.
    pub const fn role(&self) -> BitcoinParticipantRoleV1 {
        self.role
    }

    /// Local compressed public key.
    pub const fn public_key(&self) -> [u8; 33] {
        self.public_key
    }

    /// Public commitment to route/deployment/participant authority.
    pub const fn authority_digest(&self) -> [u8; 32] {
        self.authority_digest
    }
}

/// Complete public claim transcript shared by the two participant daemons.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinClaimSessionV1 {
    /// Route identity.
    pub route_id: [u8; 32],
    /// Route-executor effect identity.
    pub effect_id: [u8; 32],
    /// Current fencing epoch.
    pub fence_epoch: u64,
    /// Settlement id bound into nonce permits.
    pub settlement_id: [u8; 32],
    /// One-shot signing-session id.
    pub session_id: [u8; 32],
    /// Frozen terms digest.
    pub terms_digest: [u8; 32],
    /// Authenticated registry manifest digest.
    pub registry_digest: [u8; 32],
    /// Authenticated profile digest.
    pub profile_digest: [u8; 32],
    /// Authenticated Bitcoin deployment digest.
    pub deployment_digest: [u8; 32],
    /// Network committed by the registry profile.
    pub network: BitcoinNetworkV1,
    /// Ordered maker/taker public-key roster.
    pub roster: ParticipantKeyRosterV1,
    /// Exact funded contract outpoint.
    pub funding_txid: [u8; 32],
    /// Exact funded contract output index.
    pub funding_vout: u32,
    /// Exact funded contract amount.
    pub funding_amount_sat: u64,
    /// Exact P2TR contract scriptPubKey.
    pub contract_script_pubkey: Vec<u8>,
    /// Refund leaf key, needed to rederive the P2TR commitment.
    pub refund_key_xonly: [u8; 32],
    /// Refund CSV delay, needed to rederive the P2TR commitment.
    pub refund_delay: BitcoinCsvDelayV1,
    /// Exact cooperative-claim destination scriptPubKey.
    pub destination_script_pubkey: Vec<u8>,
    /// Exact claim fee.
    pub fee_sat: u64,
    /// Frozen signature-independent claim template commitment.
    pub expected_template_hash: [u8; 32],
    /// Shared public adaptor point `T`.
    pub adaptor_point: [u8; 33],
    /// Attempt counter; a different attempt has a distinct nonce permit.
    pub attempt: u32,
}

impl BitcoinClaimSessionV1 {
    /// Canonical commitment to every public claim/signing field.
    pub fn session_digest(&self) -> Result<[u8; 32]> {
        let context = build_context(self)?;
        let mut bytes = Vec::with_capacity(1024);
        bytes.extend_from_slice(&self.route_id);
        bytes.extend_from_slice(&self.effect_id);
        // Fencing is process authority, not cryptographic session identity.
        // A takeover must continue the exact same nonce reservation rather
        // than minting another nonce for the same signing message.
        bytes.extend_from_slice(&self.settlement_id);
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&self.terms_digest);
        bytes.extend_from_slice(&self.registry_digest);
        bytes.extend_from_slice(&self.profile_digest);
        bytes.extend_from_slice(&self.deployment_digest);
        bytes.push(self.network as u8);
        bytes.extend_from_slice(
            &self
                .roster
                .roster_hash()
                .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?,
        );
        bytes.extend_from_slice(&self.funding_txid);
        bytes.extend_from_slice(&self.funding_vout.to_be_bytes());
        bytes.extend_from_slice(&self.funding_amount_sat.to_be_bytes());
        put_bytes(&mut bytes, &self.contract_script_pubkey)?;
        bytes.extend_from_slice(&self.refund_key_xonly);
        bytes.extend_from_slice(&csv_sequence(self.refund_delay).to_be_bytes());
        put_bytes(&mut bytes, &self.destination_script_pubkey)?;
        bytes.extend_from_slice(&self.fee_sat.to_be_bytes());
        bytes.extend_from_slice(&self.expected_template_hash);
        bytes.extend_from_slice(&self.adaptor_point);
        bytes.extend_from_slice(&self.attempt.to_be_bytes());
        bytes.extend_from_slice(&context.tap_sighash);
        digest(CLAIM_SESSION_DOMAIN, &bytes)
    }
}

/// Persisted-before-exposure local MuSig2 public nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BitcoinLocalPubNonceV1 {
    pub(crate) session_digest: [u8; 32],
    pub(crate) participant_id: [u8; 32],
    pub(crate) bytes: [u8; 66],
}

impl BitcoinLocalPubNonceV1 {
    /// Session commitment.
    pub const fn session_digest(&self) -> [u8; 32] {
        self.session_digest
    }

    /// Participant that owns the nonce.
    pub const fn participant_id(&self) -> [u8; 32] {
        self.participant_id
    }

    /// Exact public nonce bytes for authenticated peer transport.
    pub const fn bytes(&self) -> [u8; 66] {
        self.bytes
    }
}

/// Local MuSig2 partial signature bound to the persisted remote nonce.
///
/// It intentionally has no `Debug` implementation.
pub struct BitcoinLocalPartialV1 {
    pub(crate) session_digest: [u8; 32],
    pub(crate) transcript_digest: [u8; 32],
    pub(crate) participant_id: [u8; 32],
    pub(crate) nonce_parity: NonceParity,
    pub(crate) bytes: [u8; 32],
}

impl BitcoinLocalPartialV1 {
    /// Session commitment.
    pub const fn session_digest(&self) -> [u8; 32] {
        self.session_digest
    }

    /// Commitment to local and remote public nonces in canonical order.
    pub const fn transcript_digest(&self) -> [u8; 32] {
        self.transcript_digest
    }

    /// Participant that produced this partial.
    pub const fn participant_id(&self) -> [u8; 32] {
        self.participant_id
    }

    /// Consumes the partial into bytes for authenticated peer transport.
    pub fn into_bytes(self) -> [u8; 32] {
        self.bytes
    }
}

/// Aggregate adaptor pre-signature and exact unsigned claim.
///
/// No `Debug` or `Clone` implementation exists. The only secret-bearing
/// transition consumes an [`BitcoinAdaptorSecretV1`] and emits an exact final
/// transaction ready for owner-only durable custody.
pub struct BitcoinPreSignatureV1 {
    pub(crate) session_digest: [u8; 32],
    pub(crate) transcript_digest: [u8; 32],
    pub(crate) transaction: Transaction,
    pub(crate) pre_signature: [u8; 64],
    pub(crate) nonce_parity: NonceParity,
    pub(crate) adaptor_point: [u8; 33],
    pub(crate) output_xonly: [u8; 32],
    pub(crate) tap_sighash: [u8; 32],
}

impl BitcoinPreSignatureV1 {
    /// Session commitment.
    pub const fn session_digest(&self) -> [u8; 32] {
        self.session_digest
    }

    /// Finalizes and verifies the BIP340 claim, consuming the adaptor secret.
    pub fn finalize_claim(
        mut self,
        secret: BitcoinAdaptorSecretV1,
    ) -> Result<ExactBitcoinTransactionV1> {
        if secret.adaptor_point != self.adaptor_point {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        let context = SecpContext::new(&fresh_entropy()?);
        let signature = context
            .adapt(
                &self.pre_signature,
                &secret.scalar,
                self.nonce_parity,
                &self.output_xonly,
                &self.tap_sighash,
            )
            .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
        self.transaction.input[0].witness = Witness::from_slice(&[signature]);
        ExactBitcoinTransactionV1::from_consensus_bytes(bitcoin::consensus::serialize(
            &self.transaction,
        ))
    }
}

/// Validated, zeroizing adaptor scalar received from the counterpart leg.
pub struct BitcoinAdaptorSecretV1 {
    scalar: Zeroizing<[u8; 32]>,
    adaptor_point: [u8; 33],
}

impl BitcoinAdaptorSecretV1 {
    /// Imports a scalar only when `t*G` equals the frozen adaptor point and
    /// zeroizes the caller's source buffer immediately after import.
    pub fn verify(scalar: &mut [u8; 32], adaptor_point: [u8; 33]) -> Result<Self> {
        let retained_scalar = Zeroizing::new(*scalar);
        scalar.zeroize();
        let key = SecretKey::from_slice(retained_scalar.as_ref())
            .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
        let mut context = Secp256k1::new();
        context.seeded_randomize(&fresh_entropy()?);
        if PublicKey::from_secret_key(&context, &key).serialize() != adaptor_point {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        Ok(Self {
            scalar: retained_scalar,
            adaptor_point,
        })
    }
}

pub(crate) fn expose_local_pubnonce(
    authority: &BitcoinParticipantClaimAuthorityV1,
    session: &BitcoinClaimSessionV1,
    authorization: AnchoredCrossChainWindowV1,
    seal_key: &BitcoinNonceSealKeyV1,
    participant_state: &mut BitcoinParticipantNonceVaultV1,
) -> Result<BitcoinLocalPubNonceV1> {
    require_authority(authority, session)?;
    let context = build_context(session)?;
    let crypto = SecpContext::new(&fresh_entropy()?);
    let mut keyagg = crypto
        .key_agg(&roster_keys(&session.roster))
        .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    let tweaked = crypto
        .apply_tap_tweak(&mut keyagg, &context.contract.tweak)
        .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    if tweaked.output_xonly != context.contract.output_key_xonly {
        return Err(BitcoinActuatorErrorV1::ClaimCryptography);
    }
    let permit = permit(authority, session, &context)?;
    let inputs = round_inputs(authority, session, &context, &crypto, &keyagg, &permit);
    let bytes = participant_state.with_vault(authority, |vault| {
        let mut round = ClaimRound::prepare_after_m8(inputs, authorization, seal_key, vault)
            .map_err(|_| BitcoinActuatorErrorV1::ClaimNonceCustody)?;
        round
            .expose_local_pubnonce(vault)
            .map_err(|_| BitcoinActuatorErrorV1::ClaimNonceCustody)
    })?;
    Ok(BitcoinLocalPubNonceV1 {
        session_digest: session.session_digest()?,
        participant_id: authority.participant_id,
        bytes,
    })
}

pub(crate) fn produce_local_partial(
    authority: &BitcoinParticipantClaimAuthorityV1,
    session: &BitcoinClaimSessionV1,
    authorization: AnchoredCrossChainWindowV1,
    seal_key: &BitcoinNonceSealKeyV1,
    participant_state: &mut BitcoinParticipantNonceVaultV1,
    remote_pubnonce: [u8; 66],
) -> Result<BitcoinLocalPartialV1> {
    PublicNonceBytesV1::from_bytes(remote_pubnonce)
        .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
    require_authority(authority, session)?;
    let context = build_context(session)?;
    let crypto = SecpContext::new(&fresh_entropy()?);
    let mut keyagg = crypto
        .key_agg(&roster_keys(&session.roster))
        .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    crypto
        .apply_tap_tweak(&mut keyagg, &context.contract.tweak)
        .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    let permit = permit(authority, session, &context)?;
    let inputs = round_inputs(authority, session, &context, &crypto, &keyagg, &permit);
    let (local_pubnonce, nonce_parity, bytes) =
        participant_state.with_vault(authority, |vault| {
            let mut round = ClaimRound::prepare_after_m8(inputs, authorization, seal_key, vault)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimNonceCustody)?;
            let local_pubnonce = round
                .expose_local_pubnonce(vault)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimNonceCustody)?;
            round
                .ingest_counterparty_pubnonce(remote_pubnonce)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
            let nonce_parity = round
                .process_session()
                .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
            let bytes = round
                .produce_local_partial(vault)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimNonceCustody)?;
            Ok((local_pubnonce, nonce_parity, bytes))
        })?;
    let transcript_digest = transcript_digest(session, local_pubnonce, remote_pubnonce)?;
    Ok(BitcoinLocalPartialV1 {
        session_digest: session.session_digest()?,
        transcript_digest,
        participant_id: authority.participant_id,
        nonce_parity,
        bytes,
    })
}

pub(crate) struct AggregatePreSignatureRequestV1<'a> {
    pub(crate) authority: &'a BitcoinParticipantClaimAuthorityV1,
    pub(crate) session: &'a BitcoinClaimSessionV1,
    pub(crate) authorization: AnchoredCrossChainWindowV1,
    pub(crate) seal_key: &'a BitcoinNonceSealKeyV1,
    pub(crate) participant_state: &'a mut BitcoinParticipantNonceVaultV1,
    pub(crate) remote_pubnonce: [u8; 66],
    pub(crate) remote_partial: [u8; 32],
}

pub(crate) fn aggregate_pre_signature(
    request: AggregatePreSignatureRequestV1<'_>,
) -> Result<BitcoinPreSignatureV1> {
    let AggregatePreSignatureRequestV1 {
        authority,
        session,
        authorization,
        seal_key,
        participant_state,
        remote_pubnonce,
        remote_partial,
    } = request;
    PublicNonceBytesV1::from_bytes(remote_pubnonce)
        .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
    require_authority(authority, session)?;
    let context = build_context(session)?;
    let crypto = SecpContext::new(&fresh_entropy()?);
    let mut keyagg = crypto
        .key_agg(&roster_keys(&session.roster))
        .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    crypto
        .apply_tap_tweak(&mut keyagg, &context.contract.tweak)
        .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    let permit = permit(authority, session, &context)?;
    let inputs = round_inputs(authority, session, &context, &crypto, &keyagg, &permit);
    let (local_pubnonce, nonce_parity, pre_signature) =
        participant_state.with_vault(authority, |vault| {
            let mut round = ClaimRound::prepare_after_m8(inputs, authorization, seal_key, vault)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimNonceCustody)?;
            let local_pubnonce = round
                .expose_local_pubnonce(vault)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimNonceCustody)?;
            round
                .ingest_counterparty_pubnonce(remote_pubnonce)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
            let nonce_parity = round
                .process_session()
                .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
            round
                .produce_local_partial(vault)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimNonceCustody)?;
            round
                .verify_counterparty_partial(&remote_partial)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
            let pre_signature = round
                .aggregate_pre_signature(&remote_partial)
                .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
            Ok((local_pubnonce, nonce_parity, pre_signature))
        })?;
    Ok(BitcoinPreSignatureV1 {
        session_digest: session.session_digest()?,
        transcript_digest: transcript_digest(session, local_pubnonce, remote_pubnonce)?,
        transaction: context.transaction,
        pre_signature,
        nonce_parity,
        adaptor_point: session.adaptor_point,
        output_xonly: context.contract.output_key_xonly,
        tap_sighash: context.tap_sighash,
    })
}

pub(crate) fn validate_claim_authority(
    authority: &BitcoinParticipantClaimAuthorityV1,
    session: &BitcoinClaimSessionV1,
) -> Result<[u8; 32]> {
    require_authority(authority, session)?;
    let context = build_context(session)?;
    Ok(context
        .transaction
        .compute_txid()
        .to_raw_hash()
        .to_byte_array())
}

struct ClaimContext {
    contract: TaprootContractV1,
    transaction: Transaction,
    template_hash: [u8; 32],
    tap_sighash: [u8; 32],
}

fn build_context(session: &BitcoinClaimSessionV1) -> Result<ClaimContext> {
    session
        .roster
        .validate()
        .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
    if session.route_id == [0; 32]
        || session.effect_id == [0; 32]
        || session.fence_epoch == 0
        || session.settlement_id == [0; 32]
        || session.session_id == [0; 32]
        || session.terms_digest == [0; 32]
        || session.registry_digest == [0; 32]
        || session.profile_digest == [0; 32]
        || session.deployment_digest == [0; 32]
        || session.funding_txid == [0; 32]
        || session.funding_amount_sat == 0
        || session.funding_amount_sat > MAX_MONEY_SAT
        || session.contract_script_pubkey.is_empty()
        || session.contract_script_pubkey.len() > MAX_SCRIPT_BYTES
        || session.destination_script_pubkey.is_empty()
        || session.destination_script_pubkey.len() > MAX_SCRIPT_BYTES
        || session.fee_sat == 0
        || session.fee_sat >= session.funding_amount_sat
        || session.expected_template_hash == [0; 32]
        || PublicKey::from_slice(&session.adaptor_point).is_err()
    {
        return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
    }
    let crypto = SecpContext::new(&[0x5a; 32]);
    let contract = build_taproot_contract(
        &crypto,
        &session.roster,
        &session.refund_key_xonly,
        session.refund_delay,
    )
    .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    if contract.script_pubkey != session.contract_script_pubkey {
        return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
    }
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                    session.funding_txid,
                )),
                vout: session.funding_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(session.funding_amount_sat - session.fee_sat),
            script_pubkey: ScriptBuf::from_bytes(session.destination_script_pubkey.clone()),
        }],
    };
    let template = FrozenBitcoinTemplateV1 {
        codec_version: 1,
        network: session.network,
        version: transaction.version.0,
        lock_time: transaction.lock_time.to_consensus_u32(),
        inputs: vec![BitcoinTxInV1 {
            txid: session.funding_txid,
            vout: session.funding_vout,
            sequence: Sequence::MAX.to_consensus_u32(),
        }],
        outputs: vec![BitcoinTxOutV1 {
            amount_sat: session.funding_amount_sat - session.fee_sat,
            script_pubkey: session.destination_script_pubkey.clone(),
        }],
        prevouts: vec![BitcoinPrevoutV1 {
            txid: session.funding_txid,
            vout: session.funding_vout,
            amount_sat: session.funding_amount_sat,
            script_pubkey: session.contract_script_pubkey.clone(),
        }],
    };
    let template_hash = frozen_template_digest_v1(&template)
        .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?;
    if template_hash != session.expected_template_hash {
        return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
    }
    let tap_sighash = key_path_sighash_default(&template, 0)
        .map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    Ok(ClaimContext {
        contract,
        transaction,
        template_hash,
        tap_sighash,
    })
}

fn require_authority(
    authority: &BitcoinParticipantClaimAuthorityV1,
    session: &BitcoinClaimSessionV1,
) -> Result<()> {
    let index = match authority.role {
        BitcoinParticipantRoleV1::Maker => 0,
        BitcoinParticipantRoleV1::Taker => 1,
    };
    let participant = session.roster.participants()[index];
    if authority.route_id != session.route_id
        || authority.terms_digest != session.terms_digest
        || authority.registry_digest != session.registry_digest
        || authority.profile_digest != session.profile_digest
        || authority.deployment_digest != session.deployment_digest
        || participant.participant_id != authority.participant_id
        || participant.role != authority.role.roster_role()
        || participant.compressed_key != authority.public_key
    {
        return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
    }
    Ok(())
}

fn permit(
    authority: &BitcoinParticipantClaimAuthorityV1,
    session: &BitcoinClaimSessionV1,
    context: &ClaimContext,
) -> Result<BitcoinNoncePermitV1> {
    Ok(BitcoinNoncePermitV1 {
        settlement_id: session.settlement_id,
        session_id: session.session_id,
        participant_id: authority.participant_id,
        purpose: BitcoinNoncePurposeV1::ClaimAdaptor,
        phase: BitcoinSigningPhaseV1::NonceGeneration,
        roster_hash: session
            .roster
            .roster_hash()
            .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?,
        terms_hash: session.terms_digest,
        claim_template_hash: context.template_hash,
        tap_sighash: context.tap_sighash,
        adaptor_point: session.adaptor_point,
        attempt: session.attempt,
    })
}

fn round_inputs<'a>(
    authority: &'a BitcoinParticipantClaimAuthorityV1,
    session: &'a BitcoinClaimSessionV1,
    context: &'a ClaimContext,
    crypto: &'a SecpContext,
    keyagg: &'a btc_crypto::KeyAggContext,
    permit: &'a BitcoinNoncePermitV1,
) -> ClaimRoundInputs<'a> {
    ClaimRoundInputs {
        crypto,
        keyagg,
        roster: &session.roster,
        local: authority.role.local_signer(),
        local_secret: &authority.secret,
        tap_sighash: &context.tap_sighash,
        adaptor_point: &session.adaptor_point,
        output_xonly: &context.contract.output_key_xonly,
        permit,
    }
}

fn roster_keys(roster: &ParticipantKeyRosterV1) -> [[u8; 33]; 2] {
    [
        roster.participants()[0].compressed_key,
        roster.participants()[1].compressed_key,
    ]
}

fn transcript_digest(
    session: &BitcoinClaimSessionV1,
    local: [u8; 66],
    remote: [u8; 66],
) -> Result<[u8; 32]> {
    let ordered = match session.roster.participants()[0].participant_id {
        _ if local == remote => return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch),
        _ => {
            // Caller local role is not available here, so make the commitment
            // order-independent while preserving both exact nonce positions.
            if local < remote {
                [local, remote]
            } else {
                [remote, local]
            }
        }
    };
    let mut bytes = Vec::with_capacity(164);
    bytes.extend_from_slice(&session.session_digest()?);
    bytes.extend_from_slice(&ordered[0]);
    bytes.extend_from_slice(&ordered[1]);
    digest(TRANSCRIPT_DOMAIN, &bytes)
}

fn csv_sequence(delay: BitcoinCsvDelayV1) -> u32 {
    match delay {
        BitcoinCsvDelayV1::Blocks(value) => u32::from(value),
        BitcoinCsvDelayV1::Time512s(value) => (1 << 22) | u32::from(value),
    }
}

fn fresh_entropy() -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    if bytes == [0; 32] {
        return Err(BitcoinActuatorErrorV1::ClaimCryptography);
    }
    Ok(bytes)
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    output.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| BitcoinActuatorErrorV1::ClaimAuthorityMismatch)?
            .to_be_bytes(),
    );
    output.extend_from_slice(value);
    Ok(())
}
