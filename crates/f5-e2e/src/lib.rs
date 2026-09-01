//! F5 end-to-end harness library (Annex M M.17 steps 14–16).
//!
//! Turnkey construction of the two spending transactions the operator
//! broadcasts on a live Bitcoin Core node:
//!
//! - the **key-path claim**, signed end-to-end through the real MuSig2
//!   2-of-2 adaptor pipeline (`btc-crypto`) over the frozen SIGHASH_DEFAULT
//!   message, adapted with the secret `t`, yielding the 64-byte witness;
//! - the **script-path CSV refund**, signed BIP340 under the refund key
//!   with the CSV `nSequence`, yielding the `[sig, leaf_script,
//!   control_block]` witness.
//!
//! Everything here except the node round-trip is deterministic and unit
//! tested: `verify_claim_witness` / `verify_refund_witness` prove the
//! emitted transactions carry consensus-valid signatures BEFORE any node
//! is involved. The keys are fixed TEST-ONLY-NON-PRODUCTION constants; a
//! production deployment supplies real per-settlement keys and a
//! vault-born `t`.

#![forbid(unsafe_code)]

mod historical_signet;
mod public;
mod regtest_authority;

pub use historical_signet::{
    verify_custom_evidence_file, verify_public_evidence_file, HistoricalSignetEvidenceResultV1,
    SignetEvidenceProfile,
};
pub use public::{
    verify_regtest_evidence_file, PublicEvidenceResult, RegtestEvidenceExpectationV2,
    RegtestExpectedOutcomeV2, RegtestRouteExpectationV2,
};
pub use regtest_authority::{
    create_regtest_authority_from_file, PinnedRegtestHeaderAuthorityV2, RegtestAuthorityFactsV2,
    RegtestAuthorityPinV2,
};

use adapter_btc::roster::{BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1};
use adapter_btc::rounds::{ClaimRound, ClaimRoundInputs, LocalSigner};
use adapter_btc::sighash::key_path_sighash_default;
use adapter_btc::taproot::{build_taproot_contract, TaprootContractV1};
use adapter_btc::templates::{
    BitcoinPrevoutV1, BitcoinTxInV1, BitcoinTxOutV1, FrozenBitcoinTemplateV1,
};
use adapter_btc::timelock::{encode_csv, AnchoredCrossChainWindowV1, BitcoinCsvDelayV1};
use adapter_btc::types::BitcoinNetworkV1 as TemplateNetwork;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Keypair, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use btc_crypto::SecpContext;
use btc_vault::{
    BitcoinNoncePermitV1, BitcoinNoncePurposeV1, BitcoinNonceReservationIdV1,
    BitcoinNonceSealKeyV1, BitcoinNonceStateV1, BitcoinNonceVault, BitcoinSigningPhaseV1,
    PersistedArtifactDescriptorV1,
};
use counterparty_api::{AdaptorPointBytes, RevealedSecretBytes};
use zeroize::{Zeroize, Zeroizing};

/// Fixed TEST-ONLY-NON-PRODUCTION signer secrets.
pub const SK1: [u8; 32] = [0x11; 32];
/// Second signer secret.
pub const SK2: [u8; 32] = [0x22; 32];
/// Adaptor secret `t` (revealed by the claim; a real deployment receives it
/// locally from the external secret owner and never persists it in Interop).
pub const ADAPTOR_T: [u8; 32] = [0x2b; 32];
/// Refund key secret (the Bitcoin funder, M.7.1).
pub const REFUND_SK: [u8; 32] = [0x33; 32];
/// Default CSV delay for deterministic regtest and custom-signet runs.
pub const CSV_BLOCKS: u16 = 144;

/// Returns the CSV delay explicitly selected for an E2E invocation.
///
/// A Signet harness may select an explicitly committed conformance value; it
/// is incorporated into the refund leaf before the funding address is derived.
/// The default preserves the 144-block production-compatible local profile.
pub fn selected_csv_blocks() -> u16 {
    match std::env::var("F5_E2E_CSV_BLOCKS") {
        Ok(value) => value
            .parse::<u16>()
            .ok()
            .filter(|blocks| *blocks > 0)
            .expect("F5_E2E_CSV_BLOCKS must be an integer in 1..=65535"),
        Err(_) => CSV_BLOCKS,
    }
}

fn selected_signet_template_network() -> TemplateNetwork {
    match std::env::var("F5_E2E_SIGNET_PROFILE").as_deref() {
        Ok("custom") => TemplateNetwork::CustomSignet,
        Ok("public") | Err(_) => TemplateNetwork::PublicSignet,
        Ok(_) => panic!("F5_E2E_SIGNET_PROFILE must be 'custom' or 'public'"),
    }
}

/// A funding output to spend.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FundingRef {
    /// Funding txid, internal byte order.
    pub txid: [u8; 32],
    /// Funding output index.
    pub vout: u32,
    /// Funded amount, in satoshis.
    pub amount_sat: u64,
}

/// Public, non-secret facts produced while constructing a claim.
#[derive(Clone, Debug)]
pub struct PublicClaimArtifacts {
    /// Fully signed transaction bytes.
    pub raw_transaction: Vec<u8>,
    /// Digest of the frozen Public-Signet transaction template.
    pub template_digest: [u8; 32],
    /// Frozen SIGHASH_DEFAULT message.
    pub tap_sighash: [u8; 32],
    /// Aggregate nonce parity selected by the real MuSig2 backend.
    pub nonce_parity_odd: bool,
    /// Independent BIP340 verification result.
    pub bip340_verified: bool,
    /// Exact extraction succeeded and the extracted scalar opened `T`.
    /// The scalar itself is deliberately never returned.
    pub extracted_t_opens_adaptor_point: bool,
    /// Public adaptor point committed before signing.
    pub adaptor_point: [u8; 33],
    /// Public point recomputed from the extracted scalar before zeroization.
    pub extracted_t_point: [u8; 33],
    /// `true` when the F7 path deliberately retained extraction authority
    /// until byte-exact confirmed chain evidence is supplied.
    pub extraction_deferred_until_confirmation: bool,
    /// Descriptor for signer one's durable partial (public metadata).
    pub signer_one_partial: Option<PersistedArtifactDescriptorV1>,
    /// Descriptor for signer two's durable partial (public metadata).
    pub signer_two_partial: Option<PersistedArtifactDescriptorV1>,
}

/// Public data needed to extract `t` only after the exact Bitcoin claim has
/// been observed in canonical chain evidence.
///
/// This object contains no secret.  It binds the adaptor pre-signature to the
/// exact signed transaction bytes, SIGHASH message, output key and adaptor
/// point.  A caller must pass the scanner-returned canonical transaction to
/// [`extract_revealed_secret_from_confirmed_claim`]; a different witness or
/// transaction fails closed even when it shares the same non-witness txid.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinClaimExtractionContextV1 {
    expected_transaction_digest: [u8; 32],
    pre_signature: [u8; 64],
    nonce_parity: btc_crypto::NonceParity,
    adaptor_point: [u8; 33],
    output_xonly: [u8; 32],
    tap_sighash: [u8; 32],
}

/// A signed Bitcoin route claim plus its non-secret delayed-extraction
/// context.
#[derive(Clone, Debug)]
pub struct RouteClaimArtifactsV1 {
    /// Public claim artifacts and exact transaction bytes.
    pub claim: PublicClaimArtifacts,
    /// Context retained until the exact transaction is confirmed.
    pub extraction: BitcoinClaimExtractionContextV1,
}

/// A fully persisted two-party adaptor pre-signature whose witness has not
/// yet been adapted with `t`.
///
/// This linear value is the F7 hand-off between preparation and either
/// chain's reveal. It intentionally implements neither `Clone` nor `Debug`.
/// Its public continuation can be encoded for restart through
/// [`Self::durable_continuation_bytes`] and can only be re-imported through
/// [`Self::from_durable_continuation_bytes`], which re-derives the complete
/// frozen transaction binding. The encoding contains no nonce or secret
/// scalar; the two nonce vaults remain the authority for the spent attempt.
pub struct PreparedBitcoinRouteClaimV1 {
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    funding: FundingRef,
    transaction: Transaction,
    template_digest: [u8; 32],
    tap_sighash: [u8; 32],
    nonce_parity: btc_crypto::NonceParity,
    adaptor_point: [u8; 33],
    output_xonly: [u8; 32],
    pre_signature: [u8; 64],
    signer_one_partial: Option<PersistedArtifactDescriptorV1>,
    signer_two_partial: Option<PersistedArtifactDescriptorV1>,
}

impl PreparedBitcoinRouteClaimV1 {
    /// The public adaptor point frozen before either nonce was reserved.
    #[must_use]
    pub fn adaptor_point(&self) -> AdaptorPointBytes {
        AdaptorPointBytes(self.adaptor_point)
    }

    /// Digest of the exact frozen Bitcoin transaction template.
    #[must_use]
    pub fn template_digest(&self) -> [u8; 32] {
        self.template_digest
    }

    /// Exact Bitcoin funding output frozen into this continuation.
    #[must_use]
    pub const fn funding_ref(&self) -> FundingRef {
        self.funding
    }

    /// Encodes the non-secret prepared-claim continuation for durable storage.
    ///
    /// The exact unsigned transaction, aggregate adaptor pre-signature and
    /// public bindings are covered by a domain-separated digest. A restarted
    /// route must still supply its expected settlement/session/terms and
    /// adaptor point to [`Self::from_durable_continuation_bytes`]; a record
    /// copied from another route therefore fails before adaptation.
    pub fn durable_continuation_bytes(&self) -> Result<Vec<u8>, String> {
        encode_prepared_route_claim(self)
    }

    /// Reconstructs a prepared claim after restart and revalidates every
    /// derivable transaction, Taproot and route binding.
    ///
    /// This does not mint a new signing attempt and never opens either nonce
    /// vault. It imports only the exact public continuation emitted by
    /// [`Self::durable_continuation_bytes`].
    pub fn from_durable_continuation_bytes(
        bytes: &[u8],
        expected_settlement_id: [u8; 32],
        expected_session_id: [u8; 32],
        expected_terms_hash: [u8; 32],
        expected_adaptor_point: &AdaptorPointBytes,
    ) -> Result<Self, String> {
        decode_prepared_route_claim(
            bytes,
            expected_settlement_id,
            expected_session_id,
            expected_terms_hash,
            expected_adaptor_point,
        )
    }
}

const PREPARED_ROUTE_MAGIC: &[u8; 8] = b"DBTCPR1\0";
const PREPARED_ROUTE_VERSION: u16 = 1;
const MAX_PREPARED_ROUTE_TRANSACTION_BYTES: usize = 1_000_000;

/// The derived material shared by every step.
struct Material {
    roster: ParticipantKeyRosterV1,
    pk1: [u8; 33],
    pk2: [u8; 33],
    big_t: [u8; 33],
    refund_xonly: [u8; 32],
}

/// Public-Signet matrix row whose deterministic TEST-ONLY key material is
/// being used. Every on-chain row gets a distinct P2TR output, preventing a
/// duplicate-address funding output from being selected ambiguously.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicRow {
    /// DOM→BTC, Bitcoin-first claim.
    E01,
    /// DOM→BTC, DOM-first claim.
    E02,
    /// BTC→DOM, Bitcoin-first claim.
    E03,
    /// BTC→DOM, DOM-first claim (also the E12 recovery row).
    E04,
    /// DOM→BTC CSV refund.
    E05,
    /// BTC→DOM CSV refund.
    E06,
}

impl PublicRow {
    /// Parses the literal Annex M matrix row identifier.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "E01" => Self::E01,
            "E02" => Self::E02,
            "E03" => Self::E03,
            "E04" => Self::E04,
            "E05" => Self::E05,
            "E06" => Self::E06,
            _ => return None,
        })
    }

    fn index(self) -> u8 {
        match self {
            Self::E01 => 1,
            Self::E02 => 2,
            Self::E03 => 3,
            Self::E04 => 4,
            Self::E05 => 5,
            Self::E06 => 6,
        }
    }
}

fn compressed(secp: &Secp256k1<bitcoin::secp256k1::All>, secret: &[u8; 32]) -> [u8; 33] {
    let sk = SecretKey::from_slice(secret).expect("valid test secret");
    PublicKey::from_secret_key(secp, &sk).serialize()
}

fn row_secret(mut base: [u8; 32], row: Option<PublicRow>) -> [u8; 32] {
    if let Some(row) = row {
        base[31] = base[31].wrapping_add(row.index());
    }
    base
}

fn material_for(secp: &Secp256k1<bitcoin::secp256k1::All>, row: Option<PublicRow>) -> Material {
    let sk1 = row_secret(SK1, row);
    let sk2 = row_secret(SK2, row);
    let adaptor_t = row_secret(ADAPTOR_T, row);
    let refund_sk = row_secret(REFUND_SK, row);
    let pk1 = compressed(secp, &sk1);
    let pk2 = compressed(secp, &sk2);
    let big_t = compressed(secp, &adaptor_t);
    let refund_full = compressed(secp, &refund_sk);
    let mut refund_xonly = [0u8; 32];
    refund_xonly.copy_from_slice(&refund_full[1..]);
    let roster = ParticipantKeyRosterV1::new([
        ParticipantKeyV1 {
            participant_id: [1; 32],
            role: BitcoinSignerRoleV1::Maker,
            compressed_key: pk1,
        },
        ParticipantKeyV1 {
            participant_id: [2; 32],
            role: BitcoinSignerRoleV1::Taker,
            compressed_key: pk2,
        },
    ])
    .expect("valid roster");
    Material {
        roster,
        pk1,
        pk2,
        big_t,
        refund_xonly,
    }
}

fn material(secp: &Secp256k1<bitcoin::secp256k1::All>) -> Material {
    material_for(secp, None)
}

/// Builds the P2TR contract for the fixed test keys.
fn contract(ctx: &SecpContext, m: &Material) -> TaprootContractV1 {
    build_taproot_contract(
        ctx,
        &m.roster,
        &m.refund_xonly,
        BitcoinCsvDelayV1::Blocks(selected_csv_blocks()),
    )
    .expect("taproot contract")
}

fn report_for(row: Option<PublicRow>, network: Network) -> String {
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material_for(&secp, row);
    let c = contract(&ctx, &m);
    let spk = ScriptBuf::from_bytes(c.script_pubkey.clone());
    let address = Address::from_script(&spk, network).expect("P2TR address");
    let mut out = String::new();
    out.push_str(&format!("network={}\n", network));
    if let Some(row) = row {
        out.push_str(&format!("row={row:?}\n"));
    }
    out.push_str(&format!(
        "internal_key_xonly={}\n",
        hex(&c.internal_key_xonly)
    ));
    out.push_str(&format!("output_key_xonly={}\n", hex(&c.output_key_xonly)));
    out.push_str(&format!("script_pubkey={}\n", hex(&c.script_pubkey)));
    out.push_str(&format!(
        "refund_leaf_script={}\n",
        hex(&c.refund_leaf.script)
    ));
    out.push_str(&format!("control_block={}\n", hex(&c.control_block)));
    out.push_str(&format!("adaptor_point={}\n", hex(&m.big_t)));
    out.push_str(&format!(
        "roster_hash={}\n",
        hex(&m.roster.roster_hash().expect("derived roster is valid"))
    ));
    out.push_str(&format!("csv_blocks={}\n", selected_csv_blocks()));
    out.push_str(&format!("address={address}\n"));
    out
}

/// The regtest P2TR address funds are sent to.
pub fn regtest_address() -> String {
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material(&secp);
    let c = contract(&ctx, &m);
    let spk = ScriptBuf::from_bytes(c.script_pubkey.clone());
    Address::from_script(&spk, Network::Regtest)
        .expect("P2TR address")
        .to_string()
}

/// A multi-line report of the derived contract (used by `derive`).
pub fn contract_report() -> String {
    let address_network = match std::env::var("F5_E2E_ADDRESS_NETWORK").as_deref() {
        Ok("signet") => Network::Signet,
        Ok("regtest") | Err(_) => Network::Regtest,
        Ok(_) => panic!("F5_E2E_ADDRESS_NETWORK must be 'regtest' or 'signet'"),
    };
    report_for(None, address_network)
}

/// Full Public-Signet contract report for one matrix row. The template
/// network is Public Signet and the test profile fixes CSV to one block.
pub fn public_contract_report(row: PublicRow) -> String {
    report_for(Some(row), Network::Signet)
}

/// Assembles the unsigned spending transaction skeleton shared by claim
/// and refund: one input spending `funding`, one output paying `dest_spk`
/// `funding.amount_sat - fee_sat`.
fn skeleton(funding: &FundingRef, dest_spk: &[u8], fee_sat: u64, sequence: u32) -> Transaction {
    let value = funding
        .amount_sat
        .checked_sub(fee_sat)
        .expect("fee below funding amount");
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(Hash::from_byte_array(funding.txid)),
                vout: funding.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(sequence),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(dest_spk.to_vec()),
        }],
    }
}

fn template_digest(template: &FrozenBitcoinTemplateV1) -> [u8; 32] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"DOM-INTEROP/BTC/F5/V1/FROZEN-TEMPLATE\0");
    bytes.extend_from_slice(&template.codec_version.to_be_bytes());
    bytes.push(template.network as u8);
    bytes.extend_from_slice(&template.version.to_be_bytes());
    bytes.extend_from_slice(&template.lock_time.to_be_bytes());
    bytes.extend_from_slice(&(template.inputs.len() as u32).to_be_bytes());
    for input in &template.inputs {
        bytes.extend_from_slice(&input.txid);
        bytes.extend_from_slice(&input.vout.to_be_bytes());
        bytes.extend_from_slice(&input.sequence.to_be_bytes());
    }
    bytes.extend_from_slice(&(template.outputs.len() as u32).to_be_bytes());
    for output in &template.outputs {
        bytes.extend_from_slice(&output.amount_sat.to_be_bytes());
        bytes.extend_from_slice(&(output.script_pubkey.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&output.script_pubkey);
    }
    bytes.extend_from_slice(&(template.prevouts.len() as u32).to_be_bytes());
    for prevout in &template.prevouts {
        bytes.extend_from_slice(&prevout.txid);
        bytes.extend_from_slice(&prevout.vout.to_be_bytes());
        bytes.extend_from_slice(&prevout.amount_sat.to_be_bytes());
        bytes.extend_from_slice(&(prevout.script_pubkey.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&prevout.script_pubkey);
    }
    let mut digest = [0u8; 32];
    let mut hasher = Blake2bVar::new(32).expect("valid fixed digest length");
    hasher.update(&bytes);
    hasher
        .finalize_variable(&mut digest)
        .expect("valid fixed digest length");
    digest
}

fn prepared_route_digest(bytes: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let mut hasher = Blake2bVar::new(32).expect("valid fixed digest length");
    hasher.update(b"DOM-INTEROP/BTC/F7/PREPARED-CLAIM-CONTINUATION/V1\0");
    hasher.update(bytes);
    hasher
        .finalize_variable(&mut digest)
        .expect("valid fixed digest length");
    digest
}

fn p2tr_script_pubkey(output_xonly: &[u8; 32]) -> Result<Vec<u8>, String> {
    XOnlyPublicKey::from_slice(output_xonly)
        .map_err(|_| "prepared route Taproot output key is not canonical".to_string())?;
    let mut script_pubkey = Vec::with_capacity(34);
    script_pubkey.extend_from_slice(&[0x51, 0x20]);
    script_pubkey.extend_from_slice(output_xonly);
    Ok(script_pubkey)
}

fn put_prepared_descriptor(
    output: &mut Vec<u8>,
    descriptor: Option<PersistedArtifactDescriptorV1>,
) -> Result<(), String> {
    match descriptor {
        None => output.push(0),
        Some(descriptor) => {
            if descriptor.reservation_id == [0; 32]
                || descriptor.artifact_kind != 2
                || descriptor.outbound_digest == [0; 32]
                || descriptor.byte_length != 32
            {
                return Err("invalid persisted partial descriptor".to_string());
            }
            output.push(1);
            output.extend_from_slice(&descriptor.reservation_id);
            output.push(descriptor.artifact_kind);
            output.extend_from_slice(&descriptor.outbound_digest);
            output.extend_from_slice(&descriptor.byte_length.to_be_bytes());
        }
    }
    Ok(())
}

fn encode_prepared_route_claim(prepared: &PreparedBitcoinRouteClaimV1) -> Result<Vec<u8>, String> {
    if prepared.settlement_id == [0; 32]
        || prepared.session_id == [0; 32]
        || prepared.terms_hash == [0; 32]
        || prepared.funding.txid == [0; 32]
        || prepared.funding.amount_sat == 0
    {
        return Err("invalid prepared route binding".to_string());
    }
    let transaction = serialize(&prepared.transaction);
    if transaction.is_empty() || transaction.len() > MAX_PREPARED_ROUTE_TRANSACTION_BYTES {
        return Err("prepared route transaction exceeds bound".to_string());
    }
    let transaction_len = u32::try_from(transaction.len())
        .map_err(|_| "prepared route transaction exceeds bound".to_string())?;
    let mut output = Vec::with_capacity(512 + transaction.len());
    output.extend_from_slice(PREPARED_ROUTE_MAGIC);
    output.extend_from_slice(&PREPARED_ROUTE_VERSION.to_be_bytes());
    output.extend_from_slice(&prepared.settlement_id);
    output.extend_from_slice(&prepared.session_id);
    output.extend_from_slice(&prepared.terms_hash);
    output.extend_from_slice(&prepared.funding.txid);
    output.extend_from_slice(&prepared.funding.vout.to_be_bytes());
    output.extend_from_slice(&prepared.funding.amount_sat.to_be_bytes());
    output.extend_from_slice(&transaction_len.to_be_bytes());
    output.extend_from_slice(&transaction);
    output.extend_from_slice(&prepared.template_digest);
    output.extend_from_slice(&prepared.tap_sighash);
    output.push(match prepared.nonce_parity {
        btc_crypto::NonceParity::Even => 0,
        btc_crypto::NonceParity::Odd => 1,
    });
    output.extend_from_slice(&prepared.adaptor_point);
    output.extend_from_slice(&prepared.output_xonly);
    output.extend_from_slice(&prepared.pre_signature);
    put_prepared_descriptor(&mut output, prepared.signer_one_partial)?;
    put_prepared_descriptor(&mut output, prepared.signer_two_partial)?;
    let digest = prepared_route_digest(&output);
    output.extend_from_slice(&digest);
    Ok(output)
}

struct PreparedRouteReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PreparedRouteReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| "prepared route continuation length overflow".to_string())?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| "truncated prepared route continuation".to_string())?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        self.take(N)?
            .try_into()
            .map_err(|_| "invalid prepared route continuation field".to_string())
    }

    fn descriptor(&mut self) -> Result<Option<PersistedArtifactDescriptorV1>, String> {
        match self.array::<1>()?[0] {
            0 => Ok(None),
            1 => {
                let descriptor = PersistedArtifactDescriptorV1 {
                    reservation_id: self.array()?,
                    artifact_kind: self.array::<1>()?[0],
                    outbound_digest: self.array()?,
                    byte_length: u32::from_be_bytes(self.array()?),
                };
                if descriptor.reservation_id == [0; 32]
                    || descriptor.artifact_kind != 2
                    || descriptor.outbound_digest == [0; 32]
                    || descriptor.byte_length != 32
                {
                    return Err("invalid persisted partial descriptor".to_string());
                }
                Ok(Some(descriptor))
            }
            _ => Err("invalid prepared route descriptor flag".to_string()),
        }
    }
}

fn decode_prepared_route_claim(
    bytes: &[u8],
    expected_settlement_id: [u8; 32],
    expected_session_id: [u8; 32],
    expected_terms_hash: [u8; 32],
    expected_adaptor_point: &AdaptorPointBytes,
) -> Result<PreparedBitcoinRouteClaimV1, String> {
    const MINIMUM_LENGTH: usize =
        8 + 2 + 32 * 4 + 4 + 8 + 4 + 32 + 32 + 1 + 33 + 32 + 64 + 1 + 1 + 32;
    if bytes.len() < MINIMUM_LENGTH {
        return Err("truncated prepared route continuation".to_string());
    }
    let body_len = bytes
        .len()
        .checked_sub(32)
        .ok_or_else(|| "truncated prepared route continuation".to_string())?;
    if prepared_route_digest(&bytes[..body_len]) != bytes[body_len..] {
        return Err("prepared route continuation digest mismatch".to_string());
    }
    let mut reader = PreparedRouteReader::new(&bytes[..body_len]);
    if reader.take(8)? != PREPARED_ROUTE_MAGIC
        || u16::from_be_bytes(reader.array()?) != PREPARED_ROUTE_VERSION
    {
        return Err("unsupported prepared route continuation".to_string());
    }
    let settlement_id = reader.array()?;
    let session_id = reader.array()?;
    let terms_hash = reader.array()?;
    if settlement_id != expected_settlement_id
        || session_id != expected_session_id
        || terms_hash != expected_terms_hash
        || settlement_id == [0; 32]
        || session_id == [0; 32]
        || terms_hash == [0; 32]
    {
        return Err("prepared route continuation binding mismatch".to_string());
    }
    let funding = FundingRef {
        txid: reader.array()?,
        vout: u32::from_be_bytes(reader.array()?),
        amount_sat: u64::from_be_bytes(reader.array()?),
    };
    let transaction_len = usize::try_from(u32::from_be_bytes(reader.array()?))
        .map_err(|_| "prepared route transaction exceeds bound".to_string())?;
    if transaction_len == 0 || transaction_len > MAX_PREPARED_ROUTE_TRANSACTION_BYTES {
        return Err("prepared route transaction exceeds bound".to_string());
    }
    let transaction_bytes = reader.take(transaction_len)?;
    let transaction: Transaction = deserialize(transaction_bytes)
        .map_err(|error| format!("prepared route transaction decode: {error}"))?;
    if serialize(&transaction) != transaction_bytes {
        return Err("prepared route transaction is not canonical".to_string());
    }
    let stored_template_digest = reader.array()?;
    let stored_sighash = reader.array()?;
    let nonce_parity = match reader.array::<1>()?[0] {
        0 => btc_crypto::NonceParity::Even,
        1 => btc_crypto::NonceParity::Odd,
        _ => return Err("invalid prepared route nonce parity".to_string()),
    };
    let adaptor_point = reader.array()?;
    let output_xonly = reader.array()?;
    let pre_signature = reader.array()?;
    let signer_one_partial = reader.descriptor()?;
    let signer_two_partial = reader.descriptor()?;
    if reader.offset != body_len
        || signer_one_partial.is_none()
        || signer_two_partial.is_none()
        || funding.txid == [0; 32]
        || funding.amount_sat == 0
        || stored_template_digest == [0; 32]
        || stored_sighash == [0; 32]
        || pre_signature == [0; 64]
        || adaptor_point != expected_adaptor_point.0
    {
        return Err("prepared route continuation binding mismatch".to_string());
    }
    PublicKey::from_slice(&adaptor_point)
        .map_err(|_| "route adaptor point is not canonical".to_string())?;
    if transaction.version != Version(2)
        || transaction.lock_time != LockTime::ZERO
        || transaction.input.len() != 1
        || transaction.output.len() != 1
        || transaction.input[0]
            .previous_output
            .txid
            .to_raw_hash()
            .to_byte_array()
            != funding.txid
        || transaction.input[0].previous_output.vout != funding.vout
        || !transaction.input[0].script_sig.is_empty()
        || transaction.input[0].sequence != Sequence(0xffff_fffd)
        || !transaction.input[0].witness.is_empty()
        || transaction.output[0].value.to_sat() == 0
        || transaction.output[0].value.to_sat() >= funding.amount_sat
    {
        return Err("prepared route transaction binding mismatch".to_string());
    }
    let ctx = SecpContext::new(&[0x5a; 32]);
    let contract_script_pubkey = p2tr_script_pubkey(&output_xonly)?;
    let template = template_for(
        &transaction,
        &funding,
        &contract_script_pubkey,
        TemplateNetwork::Regtest,
    );
    let recomputed_template_digest = template_digest(&template);
    let recomputed_sighash =
        key_path_sighash_default(&template, 0).map_err(|error| error.to_string())?;
    if stored_template_digest != recomputed_template_digest || stored_sighash != recomputed_sighash
    {
        return Err("prepared route template mismatch".to_string());
    }
    if ctx
        .verify_bip340(&output_xonly, &stored_sighash, &pre_signature)
        .is_ok()
    {
        return Err("prepared adaptor signature is already final".to_string());
    }
    Ok(PreparedBitcoinRouteClaimV1 {
        settlement_id,
        session_id,
        terms_hash,
        funding,
        transaction,
        template_digest: stored_template_digest,
        tap_sighash: stored_sighash,
        nonce_parity,
        adaptor_point,
        output_xonly,
        pre_signature,
        signer_one_partial,
        signer_two_partial,
    })
}

fn exact_transaction_digest(canonical_transaction: &[u8]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    let mut hasher = Blake2bVar::new(32).expect("valid fixed digest length");
    hasher.update(b"DOM-INTEROP/BTC/F7/EXACT-CLAIM/V1\0");
    hasher.update(canonical_transaction);
    hasher
        .finalize_variable(&mut digest)
        .expect("valid fixed digest length");
    digest
}

/// Extracts the route secret from an exact, canonically encoded Bitcoin
/// claim after the caller has obtained that transaction from confirmed chain
/// evidence.
///
/// The function does not accept a txid as proof: Bitcoin txids do not commit
/// to witness bytes.  It requires the complete canonical transaction, checks
/// its byte-exact digest, verifies the final BIP340 signature, then delegates
/// adaptor extraction and `t*G == T` validation to the pinned crypto backend.
pub fn extract_revealed_secret_from_confirmed_claim(
    context: &BitcoinClaimExtractionContextV1,
    canonical_transaction: &[u8],
) -> Result<RevealedSecretBytes, String> {
    if exact_transaction_digest(canonical_transaction) != context.expected_transaction_digest {
        return Err("confirmed Bitcoin claim bytes do not match the frozen claim".to_string());
    }
    let transaction: Transaction =
        deserialize(canonical_transaction).map_err(|error| format!("claim decode: {error}"))?;
    if serialize(&transaction) != canonical_transaction {
        return Err("Bitcoin claim is not canonically encoded".to_string());
    }
    if transaction.input.len() != 1 || transaction.input[0].witness.len() != 1 {
        return Err("Bitcoin claim must carry exactly one key-path witness".to_string());
    }
    let signature: [u8; 64] = transaction.input[0]
        .witness
        .iter()
        .next()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "Bitcoin claim witness must be a 64-byte BIP340 signature".to_string())?;
    let crypto = SecpContext::new(&[0x5a; 32]);
    crypto
        .verify_bip340(&context.output_xonly, &context.tap_sighash, &signature)
        .map_err(|error| format!("confirmed Bitcoin claim signature: {error}"))?;
    let mut extracted = crypto
        .extract(
            &signature,
            &context.pre_signature,
            context.nonce_parity,
            &context.adaptor_point,
        )
        .map_err(|error| format!("confirmed Bitcoin claim extraction: {error}"))?;
    let revealed = RevealedSecretBytes::new(extracted);
    extracted.zeroize();
    Ok(revealed)
}

/// Builds the frozen template mirroring `tx`, with the single P2TR prevout.
fn template_for(
    tx: &Transaction,
    funding: &FundingRef,
    contract_spk: &[u8],
    network: TemplateNetwork,
) -> FrozenBitcoinTemplateV1 {
    FrozenBitcoinTemplateV1 {
        codec_version: 1,
        network,
        version: tx.version.0,
        lock_time: 0,
        inputs: vec![BitcoinTxInV1 {
            txid: funding.txid,
            vout: funding.vout,
            sequence: tx.input[0].sequence.0,
        }],
        outputs: vec![BitcoinTxOutV1 {
            amount_sat: tx.output[0].value.to_sat(),
            script_pubkey: tx.output[0].script_pubkey.as_bytes().to_vec(),
        }],
        prevouts: vec![BitcoinPrevoutV1 {
            txid: funding.txid,
            vout: funding.vout,
            amount_sat: funding.amount_sat,
            script_pubkey: contract_spk.to_vec(),
        }],
    }
}

/// Builds and fully signs the key-path claim transaction, returning the
/// raw bytes for `sendrawtransaction`. The 2-of-2 MuSig2 adaptor signature
/// is produced by the real backend and adapted with `t`.
pub fn build_signed_claim(funding: &FundingRef, dest_spk: &[u8], fee_sat: u64) -> Vec<u8> {
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material(&secp);
    let c = contract(&ctx, &m);

    // Standard nSequence for a non-timelocked claim input.
    let mut tx = skeleton(funding, dest_spk, fee_sat, 0xffff_fffd);
    let template = template_for(&tx, funding, &c.script_pubkey, TemplateNetwork::Regtest);
    let sighash = key_path_sighash_default(&template, 0).expect("claim sighash");

    // Real 2-of-2 MuSig2 adaptor signing over the frozen sighash.
    let mut keyagg = ctx.key_agg(&[m.pk1, m.pk2]).expect("key agg");
    ctx.apply_tap_tweak(&mut keyagg, &c.tweak).expect("tweak");
    let (sec1, pub1) = ctx
        .nonce_gen(&[0xa1; 32], &SK1, &m.pk1, &sighash, &keyagg)
        .expect("nonce1");
    let (sec2, pub2) = ctx
        .nonce_gen(&[0xa2; 32], &SK2, &m.pk2, &sighash, &keyagg)
        .expect("nonce2");
    let aggnonce = ctx.nonce_agg(&[pub1.0, pub2.0]).expect("nonce agg");
    let session = ctx
        .nonce_process(&aggnonce, &sighash, &keyagg, &m.big_t)
        .expect("session");
    let p1 = ctx
        .partial_sign(sec1, &SK1, &m.pk1, &pub1.0, &keyagg, &session)
        .expect("partial1");
    let p2 = ctx
        .partial_sign(sec2, &SK2, &m.pk2, &pub2.0, &keyagg, &session)
        .expect("partial2");
    let pre = ctx
        .aggregate_pre_signature(&[p1, p2], &c.output_key_xonly, &sighash, &session)
        .expect("pre-signature");
    let final_sig = ctx
        .adapt(
            &pre,
            &ADAPTOR_T,
            session.nonce_parity,
            &c.output_key_xonly,
            &sighash,
        )
        .expect("adapt");
    // Self-check before emitting: the witness signature must verify.
    ctx.verify_bip340(&c.output_key_xonly, &sighash, &final_sig)
        .expect("claim signature verifies");

    tx.input[0].witness = Witness::from_slice(&[final_sig.as_slice()]);
    serialize(&tx)
}

/// Builds one row-specific Public-Signet key-path claim and returns only
/// public verification facts. This path commits
/// [`TemplateNetwork::PublicSignet`]; it never reuses the local Regtest
/// template profile.
pub fn build_public_claim(
    row: PublicRow,
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
) -> PublicClaimArtifacts {
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material_for(&secp, Some(row));
    let c = contract(&ctx, &m);
    let sk1 = row_secret(SK1, Some(row));
    let sk2 = row_secret(SK2, Some(row));
    let mut adaptor_t = row_secret(ADAPTOR_T, Some(row));

    let mut tx = skeleton(funding, dest_spk, fee_sat, 0xffff_fffd);
    let template = template_for(
        &tx,
        funding,
        &c.script_pubkey,
        selected_signet_template_network(),
    );
    let digest = template_digest(&template);
    let sighash = key_path_sighash_default(&template, 0).expect("claim sighash");

    let mut keyagg = ctx.key_agg(&[m.pk1, m.pk2]).expect("key agg");
    ctx.apply_tap_tweak(&mut keyagg, &c.tweak).expect("tweak");
    let nonce_seed_1 = row_secret([0xa1; 32], Some(row));
    let nonce_seed_2 = row_secret([0xa2; 32], Some(row));
    let (sec1, pub1) = ctx
        .nonce_gen(&nonce_seed_1, &sk1, &m.pk1, &sighash, &keyagg)
        .expect("nonce1");
    let (sec2, pub2) = ctx
        .nonce_gen(&nonce_seed_2, &sk2, &m.pk2, &sighash, &keyagg)
        .expect("nonce2");
    let aggnonce = ctx.nonce_agg(&[pub1.0, pub2.0]).expect("nonce agg");
    let session = ctx
        .nonce_process(&aggnonce, &sighash, &keyagg, &m.big_t)
        .expect("session");
    let p1 = ctx
        .partial_sign(sec1, &sk1, &m.pk1, &pub1.0, &keyagg, &session)
        .expect("partial1");
    let p2 = ctx
        .partial_sign(sec2, &sk2, &m.pk2, &pub2.0, &keyagg, &session)
        .expect("partial2");
    ctx.partial_verify(&p1, &pub1.0, &m.pk1, &keyagg, &session)
        .expect("partial1 verifies");
    ctx.partial_verify(&p2, &pub2.0, &m.pk2, &keyagg, &session)
        .expect("partial2 verifies");
    let pre = ctx
        .aggregate_pre_signature(&[p1, p2], &c.output_key_xonly, &sighash, &session)
        .expect("pre-signature");
    let final_sig = ctx
        .adapt(
            &pre,
            &adaptor_t,
            session.nonce_parity,
            &c.output_key_xonly,
            &sighash,
        )
        .expect("adapt");
    let bip340_verified = ctx
        .verify_bip340(&c.output_key_xonly, &sighash, &final_sig)
        .is_ok();
    let mut extracted = ctx
        .extract(&final_sig, &pre, session.nonce_parity, &m.big_t)
        .expect("extract and t*G=T");
    let extracted_t_point = compressed(&secp, &extracted);
    let extracted_t_opens_adaptor_point = extracted == adaptor_t && extracted_t_point == m.big_t;
    extracted.zeroize();
    adaptor_t.zeroize();
    tx.input[0].witness = Witness::from_slice(&[final_sig.as_slice()]);

    PublicClaimArtifacts {
        raw_transaction: serialize(&tx),
        template_digest: digest,
        tap_sighash: sighash,
        nonce_parity_odd: matches!(session.nonce_parity, btc_crypto::NonceParity::Odd),
        bip340_verified,
        extracted_t_opens_adaptor_point,
        adaptor_point: m.big_t,
        extracted_t_point,
        extraction_deferred_until_confirmation: false,
        signer_one_partial: None,
        signer_two_partial: None,
    }
}

/// Builds a Public-Signet claim through two real durable one-shot nonce
/// vaults. Every nonce and partial follows persist-before-exposure. The
/// caller must persist the returned raw transaction before broadcasting it.
#[allow(clippy::too_many_arguments)]
pub fn build_public_claim_durable(
    row: PublicRow,
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    signer_one_vault: &std::path::Path,
    signer_two_vault: &std::path::Path,
) -> Result<PublicClaimArtifacts, String> {
    let secret = RevealedSecretBytes::new(row_secret(ADAPTOR_T, Some(row)));
    let secp = Secp256k1::new();
    let point = AdaptorPointBytes(compressed(&secp, &secret.expose_scalar_bytes()));
    let prepared = prepare_claim_durable_internal(
        Some(row),
        selected_signet_template_network(),
        funding,
        dest_spk,
        fee_sat,
        settlement_id,
        session_id,
        terms_hash,
        &point,
        None,
        None,
        signer_one_vault,
        signer_two_vault,
    )?;
    adapt_prepared_claim(prepared, &secret, false).map(|artifacts| artifacts.claim)
}

/// Builds a real-regtest Bitcoin claim for an F7 route, using the same
/// adaptor secret/point as the DOM leg and requiring a validated M.8
/// authorization before either signer reserves a nonce.
///
/// The returned extraction context is non-secret and must be retained until
/// the exact claim transaction is returned by confirmed Bitcoin evidence.
/// This convenience entry point is useful when the route owner already holds
/// `t`. Cross-chain execution prepares without `t` through
/// [`prepare_regtest_route_claim_durable_after_m8`] and adapts only after a
/// canonical chain observation through [`adapt_prepared_route_claim`]. The
/// older Public-Signet helper remains an F5 compatibility surface.
#[allow(clippy::too_many_arguments)]
pub fn build_regtest_route_claim_durable_after_m8(
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    adaptor_secret: &RevealedSecretBytes,
    expected_adaptor_point: &AdaptorPointBytes,
    m8_authorizations: [AnchoredCrossChainWindowV1; 2],
    signer_one_seal_key: &BitcoinNonceSealKeyV1,
    signer_two_seal_key: &BitcoinNonceSealKeyV1,
    signer_one_vault: &std::path::Path,
    signer_two_vault: &std::path::Path,
) -> Result<RouteClaimArtifactsV1, String> {
    validate_adaptor_secret(adaptor_secret, expected_adaptor_point)?;
    let prepared = prepare_claim_durable_internal(
        None,
        TemplateNetwork::Regtest,
        funding,
        dest_spk,
        fee_sat,
        settlement_id,
        session_id,
        terms_hash,
        expected_adaptor_point,
        Some(m8_authorizations),
        Some([signer_one_seal_key, signer_two_seal_key]),
        signer_one_vault,
        signer_two_vault,
    )?;
    adapt_prepared_claim(prepared, adaptor_secret, true)
}

/// Prepares the real-regtest Bitcoin claim through both durable nonce vaults
/// without possessing or consuming the adaptor secret.
///
/// F7 uses this entry point only after both funding transactions confirmed
/// and their real anchors passed M.8, immediately before economic claim
/// signing. Whichever chain reveals `t` later hands the canonical scalar to
/// [`adapt_prepared_route_claim`]. Consequently neither a builder-side secret
/// nor a simulated observation can masquerade as the cross-chain reveal.
#[allow(clippy::too_many_arguments)]
pub fn prepare_regtest_route_claim_durable_after_m8(
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    expected_adaptor_point: &AdaptorPointBytes,
    m8_authorizations: [AnchoredCrossChainWindowV1; 2],
    signer_one_seal_key: &BitcoinNonceSealKeyV1,
    signer_two_seal_key: &BitcoinNonceSealKeyV1,
    signer_one_vault: &std::path::Path,
    signer_two_vault: &std::path::Path,
) -> Result<PreparedBitcoinRouteClaimV1, String> {
    prepare_claim_durable_internal(
        None,
        TemplateNetwork::Regtest,
        funding,
        dest_spk,
        fee_sat,
        settlement_id,
        session_id,
        terms_hash,
        expected_adaptor_point,
        Some(m8_authorizations),
        Some([signer_one_seal_key, signer_two_seal_key]),
        signer_one_vault,
        signer_two_vault,
    )
}

/// Adapts a prepared Bitcoin claim after a canonical chain observation has
/// revealed `t`.  A non-canonical scalar or a scalar from another route is
/// rejected before any transaction bytes are returned.
pub fn adapt_prepared_route_claim(
    prepared: PreparedBitcoinRouteClaimV1,
    revealed_secret: &RevealedSecretBytes,
) -> Result<RouteClaimArtifactsV1, String> {
    adapt_prepared_claim(prepared, revealed_secret, true)
}

/// Reconstructs the non-secret delayed-extraction context after a process
/// restart from the persisted prepared continuation and exact signed claim.
///
/// The signed transaction must differ from the prepared transaction only by
/// its single 64-byte key-path witness. The final signature is verified, but
/// adaptor extraction remains deliberately deferred. Actual cross-chain
/// disclosure and adaptor-relation validation require
/// [`extract_revealed_secret_from_confirmed_claim`] over canonical chain
/// evidence.
#[allow(clippy::too_many_arguments)]
pub fn restore_route_claim_artifacts_from_durable_continuation(
    continuation_bytes: &[u8],
    canonical_signed_claim: &[u8],
    expected_settlement_id: [u8; 32],
    expected_session_id: [u8; 32],
    expected_terms_hash: [u8; 32],
    expected_adaptor_point: &AdaptorPointBytes,
) -> Result<RouteClaimArtifactsV1, String> {
    let prepared = PreparedBitcoinRouteClaimV1::from_durable_continuation_bytes(
        continuation_bytes,
        expected_settlement_id,
        expected_session_id,
        expected_terms_hash,
        expected_adaptor_point,
    )?;
    let mut signed: Transaction = deserialize(canonical_signed_claim)
        .map_err(|error| format!("signed Bitcoin claim decode: {error}"))?;
    if serialize(&signed) != canonical_signed_claim
        || signed.input.len() != 1
        || signed.input[0].witness.len() != 1
    {
        return Err("signed Bitcoin claim is not canonical key-path spend".to_string());
    }
    let signature: [u8; 64] = signed.input[0]
        .witness
        .iter()
        .next()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "signed Bitcoin claim witness is not 64 bytes".to_string())?;
    signed.input[0].witness = Witness::new();
    if signed != prepared.transaction {
        return Err("signed Bitcoin claim changed the frozen transaction".to_string());
    }
    let ctx = SecpContext::new(&[0x5a; 32]);
    ctx.verify_bip340(&prepared.output_xonly, &prepared.tap_sighash, &signature)
        .map_err(|error| format!("signed Bitcoin claim verification: {error}"))?;
    let extraction = BitcoinClaimExtractionContextV1 {
        expected_transaction_digest: exact_transaction_digest(canonical_signed_claim),
        pre_signature: prepared.pre_signature,
        nonce_parity: prepared.nonce_parity,
        adaptor_point: prepared.adaptor_point,
        output_xonly: prepared.output_xonly,
        tap_sighash: prepared.tap_sighash,
    };
    Ok(RouteClaimArtifactsV1 {
        claim: PublicClaimArtifacts {
            raw_transaction: canonical_signed_claim.to_vec(),
            template_digest: prepared.template_digest,
            tap_sighash: prepared.tap_sighash,
            nonce_parity_odd: matches!(prepared.nonce_parity, btc_crypto::NonceParity::Odd),
            bip340_verified: true,
            extracted_t_opens_adaptor_point: false,
            adaptor_point: prepared.adaptor_point,
            extracted_t_point: [0; 33],
            extraction_deferred_until_confirmation: true,
            signer_one_partial: prepared.signer_one_partial,
            signer_two_partial: prepared.signer_two_partial,
        },
        extraction,
    })
}

#[allow(clippy::too_many_arguments)]
fn prepare_claim_durable_internal(
    row: Option<PublicRow>,
    network: TemplateNetwork,
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    expected_adaptor_point: &AdaptorPointBytes,
    m8_authorizations: Option<[AnchoredCrossChainWindowV1; 2]>,
    m8_seal_keys: Option<[&BitcoinNonceSealKeyV1; 2]>,
    signer_one_vault: &std::path::Path,
    signer_two_vault: &std::path::Path,
) -> Result<PreparedBitcoinRouteClaimV1, String> {
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    PublicKey::from_slice(&expected_adaptor_point.0)
        .map_err(|_| "route adaptor point is not a canonical compressed secp256k1 point")?;
    let mut m = material_for(&secp, row);
    m.big_t = expected_adaptor_point.0;
    let c = contract(&ctx, &m);
    let sk1 = row_secret(SK1, row);
    let sk2 = row_secret(SK2, row);
    let tx = skeleton(funding, dest_spk, fee_sat, 0xffff_fffd);
    let template = template_for(&tx, funding, &c.script_pubkey, network);
    let digest = template_digest(&template);
    let sighash = key_path_sighash_default(&template, 0).map_err(|error| error.to_string())?;
    let mut keyagg = ctx
        .key_agg(&[m.pk1, m.pk2])
        .map_err(|error| error.to_string())?;
    ctx.apply_tap_tweak(&mut keyagg, &c.tweak)
        .map_err(|error| error.to_string())?;

    let permit_one = BitcoinNoncePermitV1 {
        settlement_id,
        session_id,
        participant_id: m.roster.participants()[0].participant_id,
        purpose: BitcoinNoncePurposeV1::ClaimAdaptor,
        phase: BitcoinSigningPhaseV1::NonceGeneration,
        roster_hash: m
            .roster
            .roster_hash()
            .map_err(|error| format!("roster hash: {error}"))?,
        terms_hash,
        claim_template_hash: digest,
        tap_sighash: sighash,
        adaptor_point: m.big_t,
        attempt: 0,
    };
    let permit_two = BitcoinNoncePermitV1 {
        participant_id: m.roster.participants()[1].participant_id,
        ..permit_one
    };
    let mut vault_one = BitcoinNonceVault::open(signer_one_vault)
        .map_err(|error| format!("signer-one vault: {error}"))?;
    let mut vault_two = BitcoinNonceVault::open(signer_two_vault)
        .map_err(|error| format!("signer-two vault: {error}"))?;
    let (m8_authorization_one, m8_authorization_two) = match m8_authorizations {
        Some([one, two]) => (Some(one), Some(two)),
        None => (None, None),
    };
    let (m8_seal_key_one, m8_seal_key_two) = match m8_seal_keys {
        Some([one, two]) => (Some(one), Some(two)),
        None => (None, None),
    };
    if m8_authorization_one.is_some() != m8_seal_key_one.is_some()
        || m8_authorization_two.is_some() != m8_seal_key_two.is_some()
    {
        return Err("F7 restartable nonce-owner authority mismatch".to_string());
    }
    let inputs_one = ClaimRoundInputs {
        crypto: &ctx,
        keyagg: &keyagg,
        roster: &m.roster,
        local: LocalSigner::First,
        local_secret: &sk1,
        tap_sighash: &sighash,
        adaptor_point: &m.big_t,
        output_xonly: &c.output_key_xonly,
        permit: &permit_one,
    };
    let mut round_one = match m8_authorization_one {
        Some(authorization) => ClaimRound::prepare_after_m8(
            inputs_one,
            authorization,
            m8_seal_key_one.ok_or_else(|| "signer-one seal key unavailable".to_string())?,
            &mut vault_one,
        ),
        None => ClaimRound::prepare(inputs_one, &mut vault_one),
    }
    .map_err(|error| format!("signer-one prepare: {error}"))?;
    let inputs_two = ClaimRoundInputs {
        crypto: &ctx,
        keyagg: &keyagg,
        roster: &m.roster,
        local: LocalSigner::Second,
        local_secret: &sk2,
        tap_sighash: &sighash,
        adaptor_point: &m.big_t,
        output_xonly: &c.output_key_xonly,
        permit: &permit_two,
    };
    let mut round_two = match m8_authorization_two {
        Some(authorization) => ClaimRound::prepare_after_m8(
            inputs_two,
            authorization,
            m8_seal_key_two.ok_or_else(|| "signer-two seal key unavailable".to_string())?,
            &mut vault_two,
        ),
        None => ClaimRound::prepare(inputs_two, &mut vault_two),
    }
    .map_err(|error| format!("signer-two prepare: {error}"))?;
    let public_one = round_one
        .expose_local_pubnonce(&mut vault_one)
        .map_err(|error| format!("signer-one exposure: {error}"))?;
    let public_two = round_two
        .expose_local_pubnonce(&mut vault_two)
        .map_err(|error| format!("signer-two exposure: {error}"))?;
    round_one
        .ingest_counterparty_pubnonce(public_two)
        .map_err(|error| error.to_string())?;
    round_two
        .ingest_counterparty_pubnonce(public_one)
        .map_err(|error| error.to_string())?;
    let parity_one = round_one
        .process_session()
        .map_err(|error| error.to_string())?;
    let parity_two = round_two
        .process_session()
        .map_err(|error| error.to_string())?;
    if parity_one != parity_two {
        return Err("signer nonce parity divergence".to_string());
    }
    let partial_one = round_one
        .produce_local_partial(&mut vault_one)
        .map_err(|error| format!("signer-one partial: {error}"))?;
    let partial_two = round_two
        .produce_local_partial(&mut vault_two)
        .map_err(|error| format!("signer-two partial: {error}"))?;
    round_one
        .verify_counterparty_partial(&partial_two)
        .map_err(|error| format!("signer-one verification: {error}"))?;
    round_two
        .verify_counterparty_partial(&partial_one)
        .map_err(|error| format!("signer-two verification: {error}"))?;
    let pre_one = round_one
        .aggregate_pre_signature(&partial_two)
        .map_err(|error| error.to_string())?;
    let pre_two = round_two
        .aggregate_pre_signature(&partial_one)
        .map_err(|error| error.to_string())?;
    if pre_one != pre_two {
        return Err("signer pre-signature divergence".to_string());
    }
    Ok(PreparedBitcoinRouteClaimV1 {
        settlement_id,
        session_id,
        terms_hash,
        funding: *funding,
        transaction: tx,
        template_digest: digest,
        tap_sighash: sighash,
        nonce_parity: parity_one,
        adaptor_point: m.big_t,
        output_xonly: c.output_key_xonly,
        pre_signature: pre_one,
        signer_one_partial: round_one.local_partial_descriptor(),
        signer_two_partial: round_two.local_partial_descriptor(),
    })
}

fn validate_adaptor_secret(
    adaptor_secret: &RevealedSecretBytes,
    expected_adaptor_point: &AdaptorPointBytes,
) -> Result<(), String> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&adaptor_secret.expose_scalar_bytes())
        .map_err(|_| "route adaptor secret is not a canonical secp256k1 scalar".to_string())?;
    let derived_adaptor_point = PublicKey::from_secret_key(&secp, &secret_key).serialize();
    if derived_adaptor_point != expected_adaptor_point.0 {
        return Err("route adaptor secret does not open the frozen adaptor point".to_string());
    }
    Ok(())
}

fn adapt_prepared_claim(
    mut prepared: PreparedBitcoinRouteClaimV1,
    adaptor_secret: &RevealedSecretBytes,
    extraction_deferred_until_confirmation: bool,
) -> Result<RouteClaimArtifactsV1, String> {
    let expected_point = AdaptorPointBytes(prepared.adaptor_point);
    validate_adaptor_secret(adaptor_secret, &expected_point)?;

    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    // The copy this makes is the one `Zeroizing` scrubs; the wrapper the
    // scalar came out of is the caller's and is untouched.
    let adaptor_t = Zeroizing::new(adaptor_secret.expose_scalar_bytes());
    let final_sig = ctx
        .adapt(
            &prepared.pre_signature,
            &adaptor_t,
            prepared.nonce_parity,
            &prepared.output_xonly,
            &prepared.tap_sighash,
        )
        .map_err(|error| error.to_string())?;
    ctx.verify_bip340(&prepared.output_xonly, &prepared.tap_sighash, &final_sig)
        .map_err(|error| {
            format!("adapted claim failed independent BIP340 verification: {error}")
        })?;

    let (extracted_t_opens_adaptor_point, extracted_t_point) =
        if extraction_deferred_until_confirmation {
            // F7 extraction is exclusively a canonical-chain evidence
            // consumer.  Adapting locally must not be reported as observing
            // the counterparty reveal.
            (false, [0u8; 33])
        } else {
            let mut extracted = ctx
                .extract(
                    &final_sig,
                    &prepared.pre_signature,
                    prepared.nonce_parity,
                    &prepared.adaptor_point,
                )
                .map_err(|error| error.to_string())?;
            let extracted_t_point = compressed(&secp, &extracted);
            let opened = extracted == *adaptor_t && extracted_t_point == prepared.adaptor_point;
            extracted.zeroize();
            (opened, extracted_t_point)
        };
    prepared.transaction.input[0].witness = Witness::from_slice(&[final_sig.as_slice()]);
    let raw_transaction = serialize(&prepared.transaction);
    let extraction = BitcoinClaimExtractionContextV1 {
        expected_transaction_digest: exact_transaction_digest(&raw_transaction),
        pre_signature: prepared.pre_signature,
        nonce_parity: prepared.nonce_parity,
        adaptor_point: prepared.adaptor_point,
        output_xonly: prepared.output_xonly,
        tap_sighash: prepared.tap_sighash,
    };
    Ok(RouteClaimArtifactsV1 {
        claim: PublicClaimArtifacts {
            raw_transaction,
            template_digest: prepared.template_digest,
            tap_sighash: prepared.tap_sighash,
            nonce_parity_odd: matches!(prepared.nonce_parity, btc_crypto::NonceParity::Odd),
            bip340_verified: true,
            extracted_t_opens_adaptor_point,
            adaptor_point: prepared.adaptor_point,
            extracted_t_point,
            extraction_deferred_until_confirmation,
            signer_one_partial: prepared.signer_one_partial,
            signer_two_partial: prepared.signer_two_partial,
        },
        extraction,
    })
}

/// Crash point exercised by the E10/E11 process probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashProbePhase {
    /// Exit after the real nonce and PubNonce are durably created, before exposure.
    BeforeExposure,
    /// Exit after the real, persisted PubNonce has been exposed.
    AfterPubNonce,
}

/// Starts a real-backend claim round and exits at the requested crash point.
///
/// The caller invokes this in one process and [`restore_crash_probe`] in a
/// second process. The OS-entropy nonce and backend `SecNonce` never leave
/// this function; only the public reservation id is returned.
#[allow(clippy::too_many_arguments)]
pub fn prepare_crash_probe(
    row: PublicRow,
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
    settlement_id: [u8; 32],
    session_id: [u8; 32],
    terms_hash: [u8; 32],
    vault_path: &std::path::Path,
    phase: CrashProbePhase,
) -> Result<BitcoinNonceReservationIdV1, String> {
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material_for(&secp, Some(row));
    let c = contract(&ctx, &m);
    let sk1 = row_secret(SK1, Some(row));
    let tx = skeleton(funding, dest_spk, fee_sat, 0xffff_fffd);
    let template = template_for(
        &tx,
        funding,
        &c.script_pubkey,
        selected_signet_template_network(),
    );
    let digest = template_digest(&template);
    let sighash = key_path_sighash_default(&template, 0).map_err(|error| error.to_string())?;
    let mut keyagg = ctx
        .key_agg(&[m.pk1, m.pk2])
        .map_err(|error| error.to_string())?;
    ctx.apply_tap_tweak(&mut keyagg, &c.tweak)
        .map_err(|error| error.to_string())?;
    let permit = BitcoinNoncePermitV1 {
        settlement_id,
        session_id,
        participant_id: m.roster.participants()[0].participant_id,
        purpose: BitcoinNoncePurposeV1::ClaimAdaptor,
        phase: BitcoinSigningPhaseV1::NonceGeneration,
        roster_hash: m
            .roster
            .roster_hash()
            .map_err(|error| format!("roster hash: {error}"))?,
        terms_hash,
        claim_template_hash: digest,
        tap_sighash: sighash,
        adaptor_point: m.big_t,
        attempt: 0,
    };
    let mut vault = BitcoinNonceVault::open(vault_path).map_err(|error| error.to_string())?;
    let mut round = ClaimRound::prepare(
        ClaimRoundInputs {
            crypto: &ctx,
            keyagg: &keyagg,
            roster: &m.roster,
            local: LocalSigner::First,
            local_secret: &sk1,
            tap_sighash: &sighash,
            adaptor_point: &m.big_t,
            output_xonly: &c.output_key_xonly,
            permit: &permit,
        },
        &mut vault,
    )
    .map_err(|error| format!("crash probe prepare: {error}"))?;
    if phase == CrashProbePhase::AfterPubNonce {
        round
            .expose_local_pubnonce(&mut vault)
            .map_err(|error| format!("crash probe exposure: {error}"))?;
    }
    Ok(round.reservation_id())
}

/// Reopens a crash-probe vault and proves reconciliation selected the safe
/// refund path instead of rederiving or reusing the lost nonce.
pub fn restore_crash_probe(
    vault_path: &std::path::Path,
    reservation_id: BitcoinNonceReservationIdV1,
) -> Result<(), String> {
    let vault = BitcoinNonceVault::open(vault_path).map_err(|error| error.to_string())?;
    let state = vault
        .state_of(&reservation_id)
        .map_err(|error| error.to_string())?;
    if state != BitcoinNonceStateV1::Aborted {
        return Err(format!("crash restore state is {state:?}, not Aborted"));
    }
    Ok(())
}

/// Reopens a vault and returns the exact persisted artifact bytes. Used by
/// E12 in a separate process after the signing process has exited.
pub fn resend_persisted_artifact(
    vault_path: &std::path::Path,
    descriptor: PersistedArtifactDescriptorV1,
) -> Result<Vec<u8>, String> {
    let mut vault = BitcoinNonceVault::open(vault_path).map_err(|error| error.to_string())?;
    vault.resend(&descriptor).map_err(|error| error.to_string())
}

/// Builds and fully signs the script-path CSV refund transaction. The
/// refund is plain BIP340 under the refund key (not MuSig2), with the CSV
/// `nSequence` and the `[sig, leaf_script, control_block]` witness.
pub fn build_signed_refund(funding: &FundingRef, dest_spk: &[u8], fee_sat: u64) -> Vec<u8> {
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material(&secp);
    let c = contract(&ctx, &m);

    let csv_sequence =
        encode_csv(BitcoinCsvDelayV1::Blocks(selected_csv_blocks())).expect("csv sequence");
    let mut tx = skeleton(funding, dest_spk, fee_sat, csv_sequence);

    // Tapscript (leaf) sighash with SIGHASH_DEFAULT over the refund leaf.
    let prevout = TxOut {
        value: Amount::from_sat(funding.amount_sat),
        script_pubkey: ScriptBuf::from_bytes(c.script_pubkey.clone()),
    };
    let leaf_script = ScriptBuf::from_bytes(c.refund_leaf.script.clone());
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("refund sighash");

    // BIP340 sign under the refund key.
    let keypair = Keypair::from_seckey_slice(&secp, &REFUND_SK).expect("refund key");
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    // Self-check: verify the refund signature.
    let refund_xk = XOnlyPublicKey::from_slice(&m.refund_xonly).expect("refund xonly");
    secp.verify_schnorr(&sig, &msg, &refund_xk)
        .expect("refund signature verifies");

    tx.input[0].witness = Witness::from_slice(&[
        sig.as_ref(),
        c.refund_leaf.script.as_slice(),
        c.control_block.as_slice(),
    ]);
    serialize(&tx)
}

/// Builds a row-specific Signet refund using the CSV selected by the harness.
/// Returns the raw transaction and its frozen Signet template digest.
pub fn build_public_refund(
    row: PublicRow,
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
) -> (Vec<u8>, [u8; 32]) {
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material_for(&secp, Some(row));
    let c = contract(&ctx, &m);
    let refund_sk = row_secret(REFUND_SK, Some(row));
    let csv_sequence =
        encode_csv(BitcoinCsvDelayV1::Blocks(selected_csv_blocks())).expect("csv sequence");
    let mut tx = skeleton(funding, dest_spk, fee_sat, csv_sequence);
    let template = template_for(
        &tx,
        funding,
        &c.script_pubkey,
        selected_signet_template_network(),
    );
    let digest = template_digest(&template);
    let prevout = TxOut {
        value: Amount::from_sat(funding.amount_sat),
        script_pubkey: ScriptBuf::from_bytes(c.script_pubkey.clone()),
    };
    let leaf_script = ScriptBuf::from_bytes(c.refund_leaf.script.clone());
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    let mut cache = SighashCache::new(&tx);
    let sighash = cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[prevout]),
            leaf_hash,
            TapSighashType::Default,
        )
        .expect("refund sighash");
    let keypair = Keypair::from_seckey_slice(&secp, &refund_sk).expect("refund key");
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    let refund_xk = XOnlyPublicKey::from_slice(&m.refund_xonly).expect("refund xonly");
    secp.verify_schnorr(&sig, &msg, &refund_xk)
        .expect("refund signature verifies");
    tx.input[0].witness = Witness::from_slice(&[
        sig.as_ref(),
        c.refund_leaf.script.as_slice(),
        c.control_block.as_slice(),
    ]);
    (serialize(&tx), digest)
}

/// Independently verifies a row-specific Public-Signet claim witness
/// against its frozen SIGHASH_DEFAULT template.
pub fn verify_public_claim_witness(
    row: PublicRow,
    raw: &[u8],
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
) -> bool {
    let tx: Transaction = match bitcoin::consensus::deserialize(raw) {
        Ok(tx) => tx,
        Err(_) => return false,
    };
    let input = match tx.input.first() {
        Some(input) => input,
        None => return false,
    };
    let witness: Vec<&[u8]> = input.witness.iter().collect();
    if witness.len() != 1 || witness[0].len() != 64 {
        return false;
    }
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material_for(&secp, Some(row));
    let c = contract(&ctx, &m);
    let unsigned = skeleton(funding, dest_spk, fee_sat, 0xffff_fffd);
    let template = template_for(
        &unsigned,
        funding,
        &c.script_pubkey,
        selected_signet_template_network(),
    );
    let sighash = match key_path_sighash_default(&template, 0) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let mut signature = [0u8; 64];
    signature.copy_from_slice(witness[0]);
    ctx.verify_bip340(&c.output_key_xonly, &sighash, &signature)
        .is_ok()
}

/// Independently verifies a row-specific Public-Signet refund witness,
/// leaf, control block, sequence and SIGHASH_DEFAULT signature.
pub fn verify_public_refund_witness(
    row: PublicRow,
    raw: &[u8],
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
) -> bool {
    let tx: Transaction = match bitcoin::consensus::deserialize(raw) {
        Ok(tx) => tx,
        Err(_) => return false,
    };
    let input = match tx.input.first() {
        Some(input) => input,
        None => return false,
    };
    let selected_sequence =
        encode_csv(BitcoinCsvDelayV1::Blocks(selected_csv_blocks())).expect("csv sequence");
    if input.sequence.0 != selected_sequence {
        return false;
    }
    let witness = input.witness.to_vec();
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material_for(&secp, Some(row));
    let c = contract(&ctx, &m);
    if witness.len() != 3
        || witness[0].len() != 64
        || witness[1] != c.refund_leaf.script
        || witness[2] != c.control_block
    {
        return false;
    }
    let unsigned = skeleton(funding, dest_spk, fee_sat, selected_sequence);
    let prevout = TxOut {
        value: Amount::from_sat(funding.amount_sat),
        script_pubkey: ScriptBuf::from_bytes(c.script_pubkey),
    };
    let leaf_script = ScriptBuf::from_bytes(c.refund_leaf.script);
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    let mut cache = SighashCache::new(&unsigned);
    let sighash = match cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[prevout]),
        leaf_hash,
        TapSighashType::Default,
    ) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let signature = match bitcoin::secp256k1::schnorr::Signature::from_slice(&witness[0]) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let key = match XOnlyPublicKey::from_slice(&m.refund_xonly) {
        Ok(value) => value,
        Err(_) => return false,
    };
    secp.verify_schnorr(
        &signature,
        &Message::from_digest(sighash.to_byte_array()),
        &key,
    )
    .is_ok()
}

/// Re-parses a signed claim tx and verifies its key-path witness against
/// the frozen sighash (used by tests to prove consensus-valid output).
pub fn verify_claim_witness(
    raw: &[u8],
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
) -> bool {
    let tx: Transaction = match bitcoin::consensus::deserialize(raw) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let input = match tx.input.first() {
        Some(input) => input,
        None => return false,
    };
    let items: Vec<&[u8]> = input.witness.iter().collect();
    if items.len() != 1 || items[0].len() != 64 {
        return false;
    }
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material(&secp);
    let c = contract(&ctx, &m);
    let skeleton = skeleton(funding, dest_spk, fee_sat, 0xffff_fffd);
    let template = template_for(
        &skeleton,
        funding,
        &c.script_pubkey,
        TemplateNetwork::Regtest,
    );
    let sighash = match key_path_sighash_default(&template, 0) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut sig = [0u8; 64];
    sig.copy_from_slice(items[0]);
    ctx.verify_bip340(&c.output_key_xonly, &sighash, &sig)
        .is_ok()
}

/// Re-parses a signed refund tx and verifies its script-path witness.
pub fn verify_refund_witness(
    raw: &[u8],
    funding: &FundingRef,
    dest_spk: &[u8],
    fee_sat: u64,
) -> bool {
    let tx: Transaction = match bitcoin::consensus::deserialize(raw) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let input = match tx.input.first() {
        Some(input) => input,
        None => return false,
    };
    let items: Vec<Vec<u8>> = input.witness.to_vec();
    if items.len() != 3 || items[0].len() != 64 {
        return false;
    }
    let ctx = SecpContext::new(&[0x5a; 32]);
    let secp = Secp256k1::new();
    let m = material(&secp);
    let c = contract(&ctx, &m);
    // The leaf script and control block must match the contract.
    if items[1] != c.refund_leaf.script || items[2] != c.control_block {
        return false;
    }
    let csv_sequence =
        encode_csv(BitcoinCsvDelayV1::Blocks(selected_csv_blocks())).expect("csv sequence");
    let skeleton = skeleton(funding, dest_spk, fee_sat, csv_sequence);
    let prevout = TxOut {
        value: Amount::from_sat(funding.amount_sat),
        script_pubkey: ScriptBuf::from_bytes(c.script_pubkey.clone()),
    };
    let leaf_script = ScriptBuf::from_bytes(c.refund_leaf.script.clone());
    let leaf_hash = TapLeafHash::from_script(&leaf_script, LeafVersion::TapScript);
    let mut cache = SighashCache::new(&skeleton);
    let sighash = match cache.taproot_script_spend_signature_hash(
        0,
        &Prevouts::All(&[prevout]),
        leaf_hash,
        TapSighashType::Default,
    ) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let msg = Message::from_digest(sighash.to_byte_array());
    let refund_xk = match XOnlyPublicKey::from_slice(&m.refund_xonly) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match bitcoin::secp256k1::schnorr::Signature::from_slice(&items[0]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = ctx; // the contract derivation above exercises the pinned backend
    secp.verify_schnorr(&sig, &msg, &refund_xk).is_ok()
}

pub(crate) fn hex_internal(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub(crate) fn decode_hex_internal(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        output.push(((high << 4) | low) as u8);
    }
    Some(output)
}

fn hex(bytes: &[u8]) -> String {
    hex_internal(bytes)
}

#[cfg(test)]
mod public_profile_tests {
    use super::*;

    fn funding() -> FundingRef {
        FundingRef {
            txid: [0x71; 32],
            vout: 2,
            amount_sat: 10_000,
        }
    }

    fn destination() -> Vec<u8> {
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[0x42; 20]);
        script
    }

    #[test]
    fn public_rows_have_six_distinct_signet_contracts() {
        let mut scripts = std::collections::BTreeSet::new();
        for row in [
            PublicRow::E01,
            PublicRow::E02,
            PublicRow::E03,
            PublicRow::E04,
            PublicRow::E05,
            PublicRow::E06,
        ] {
            let report = public_contract_report(row);
            assert!(report.contains("network=signet"));
            assert!(report.contains("csv_blocks=1"));
            let script = report
                .lines()
                .find_map(|line| line.strip_prefix("script_pubkey="))
                .expect("script pubkey");
            assert!(scripts.insert(script.to_string()));
        }
        assert_eq!(scripts.len(), 6);
    }

    #[test]
    fn public_claim_and_refund_verify_under_public_templates() {
        let funding = funding();
        let destination = destination();
        let claim = build_public_claim(PublicRow::E01, &funding, &destination, 2_000);
        assert!(claim.bip340_verified);
        assert!(claim.extracted_t_opens_adaptor_point);
        assert!(verify_public_claim_witness(
            PublicRow::E01,
            &claim.raw_transaction,
            &funding,
            &destination,
            2_000
        ));
        let (refund, _) = build_public_refund(PublicRow::E05, &funding, &destination, 2_000);
        assert!(verify_public_refund_witness(
            PublicRow::E05,
            &refund,
            &funding,
            &destination,
            2_000
        ));
    }

    #[test]
    fn durable_partial_resends_after_process_style_reopen() {
        let unique = format!("f5-public-{}", std::process::id());
        let root = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&root).expect("test directory");
        let one = root.join("one.sqlite");
        let two = root.join("two.sqlite");
        let artifact = build_public_claim_durable(
            PublicRow::E04,
            &funding(),
            &destination(),
            2_000,
            [0x51; 32],
            [0x52; 32],
            [0x53; 32],
            &one,
            &two,
        )
        .expect("durable public claim");
        let descriptor = artifact.signer_one_partial.expect("partial descriptor");
        let resent = resend_persisted_artifact(&one, descriptor).expect("reopen and resend");
        assert_eq!(resent.len(), descriptor.byte_length as usize);
        std::fs::remove_dir_all(root).expect("remove test directory");
    }
}
