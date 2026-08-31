//! Confirmation-gated extraction of a Bitcoin adaptor secret.
//!
//! The authority in this module contains only public transcript material. It
//! nevertheless remains linear: it is created by consuming the aggregate
//! pre-signature authority and can reveal the scalar only from the exact,
//! canonical witness-bearing transaction to which it was bound.

use core::fmt;

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bitcoin::{Transaction, Witness};
use btc_crypto::{NonceParity, SecpContext};
use counterparty_api::RevealedSecretBytes;
use zeroize::{Zeroize, Zeroizing};

use crate::model::digest;
use crate::signer::BitcoinPreSignatureV1;
use crate::{BitcoinActuatorErrorV1, BitcoinRpcLookupV1, Result};

const EXACT_CLAIM_DOMAIN: &[u8] = b"DOM-INTEROP/BTC/F7/EXACT-CLAIM/V1\0";
const EXTRACTION_CONTEXT_DOMAIN: &[u8] = b"DOM-INTEROP/BTC-ACTUATOR/CLAIM-EXTRACTION-CONTEXT/V1\0";
const EXTRACTION_CONTEXT_MAGIC: [u8; 8] = *b"DOMBCEX1";
const EXTRACTION_CONTEXT_VERSION: u16 = 1;
const MAX_CONFIRMED_CLAIM_BYTES: usize = 4_000_000;

/// Exact byte length of a durable [`BitcoinClaimExtractionContextV1`].
pub const BITCOIN_CLAIM_EXTRACTION_CONTEXT_V1_BYTES: usize = 236;

const EXPECTED_TRANSACTION_DIGEST_RANGE: core::ops::Range<usize> = 10..42;
const PRE_SIGNATURE_RANGE: core::ops::Range<usize> = 42..106;
const NONCE_PARITY_OFFSET: usize = 106;
const ADAPTOR_POINT_RANGE: core::ops::Range<usize> = 107..140;
const OUTPUT_XONLY_RANGE: core::ops::Range<usize> = 140..172;
const TAP_SIGHASH_RANGE: core::ops::Range<usize> = 172..204;
const CONTEXT_DIGEST_RANGE: core::ops::Range<usize> = 204..236;

/// Public, restart-safe authority for confirmation-gated claim extraction.
///
/// The context contains no secret scalar. It binds the exact witness-bearing
/// transaction digest to the aggregate adaptor pre-signature, nonce parity,
/// adaptor point, Taproot output key and key-path sighash. It intentionally
/// implements neither `Clone` nor `Copy`: durable encoding is the explicit,
/// reviewable way to persist and restore this authority.
#[derive(PartialEq, Eq)]
pub struct BitcoinClaimExtractionContextV1 {
    expected_transaction_digest: [u8; 32],
    pre_signature: [u8; 64],
    nonce_parity: NonceParity,
    adaptor_point: [u8; 33],
    output_xonly: [u8; 32],
    tap_sighash: [u8; 32],
    context_digest: [u8; 32],
}

impl BitcoinClaimExtractionContextV1 {
    /// Digest of the exact, witness-bearing transaction frozen at creation.
    #[must_use]
    pub const fn expected_transaction_digest(&self) -> [u8; 32] {
        self.expected_transaction_digest
    }

    /// Canonical commitment to every public field in this context.
    #[must_use]
    pub const fn context_digest(&self) -> [u8; 32] {
        self.context_digest
    }

    /// Encodes this public authority in one fixed-size canonical record.
    #[must_use]
    pub fn to_durable_bytes(&self) -> [u8; BITCOIN_CLAIM_EXTRACTION_CONTEXT_V1_BYTES] {
        let mut bytes = [0_u8; BITCOIN_CLAIM_EXTRACTION_CONTEXT_V1_BYTES];
        bytes[..8].copy_from_slice(&EXTRACTION_CONTEXT_MAGIC);
        bytes[8..10].copy_from_slice(&EXTRACTION_CONTEXT_VERSION.to_be_bytes());
        bytes[EXPECTED_TRANSACTION_DIGEST_RANGE].copy_from_slice(&self.expected_transaction_digest);
        bytes[PRE_SIGNATURE_RANGE].copy_from_slice(&self.pre_signature);
        bytes[NONCE_PARITY_OFFSET] = nonce_parity_tag(self.nonce_parity);
        bytes[ADAPTOR_POINT_RANGE].copy_from_slice(&self.adaptor_point);
        bytes[OUTPUT_XONLY_RANGE].copy_from_slice(&self.output_xonly);
        bytes[TAP_SIGHASH_RANGE].copy_from_slice(&self.tap_sighash);
        bytes[CONTEXT_DIGEST_RANGE].copy_from_slice(&self.context_digest);
        bytes
    }

    /// Restores one exact canonical durable record.
    ///
    /// Short, trailing, unknown-version, non-canonical parity/key and
    /// self-inconsistent records fail closed before extraction authority is
    /// returned.
    pub fn from_durable_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != BITCOIN_CLAIM_EXTRACTION_CONTEXT_V1_BYTES
            || bytes[..8] != EXTRACTION_CONTEXT_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != EXTRACTION_CONTEXT_VERSION
        {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }

        let mut expected_transaction_digest = [0_u8; 32];
        expected_transaction_digest.copy_from_slice(&bytes[EXPECTED_TRANSACTION_DIGEST_RANGE]);
        let mut pre_signature = [0_u8; 64];
        pre_signature.copy_from_slice(&bytes[PRE_SIGNATURE_RANGE]);
        let nonce_parity = nonce_parity_from_tag(bytes[NONCE_PARITY_OFFSET])?;
        let mut adaptor_point = [0_u8; 33];
        adaptor_point.copy_from_slice(&bytes[ADAPTOR_POINT_RANGE]);
        let mut output_xonly = [0_u8; 32];
        output_xonly.copy_from_slice(&bytes[OUTPUT_XONLY_RANGE]);
        let mut tap_sighash = [0_u8; 32];
        tap_sighash.copy_from_slice(&bytes[TAP_SIGHASH_RANGE]);
        let mut stored_context_digest = [0_u8; 32];
        stored_context_digest.copy_from_slice(&bytes[CONTEXT_DIGEST_RANGE]);

        if !public_parts_are_valid(
            &expected_transaction_digest,
            &pre_signature,
            &adaptor_point,
            &output_xonly,
            &tap_sighash,
        ) {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }
        let context_digest = extraction_context_digest(
            &expected_transaction_digest,
            &pre_signature,
            nonce_parity,
            &adaptor_point,
            &output_xonly,
            &tap_sighash,
        )?;
        if context_digest != stored_context_digest {
            return Err(BitcoinActuatorErrorV1::CorruptState);
        }

        Ok(Self {
            expected_transaction_digest,
            pre_signature,
            nonce_parity,
            adaptor_point,
            output_xonly,
            tap_sighash,
            context_digest,
        })
    }

    fn from_validated_parts(
        expected_transaction_digest: [u8; 32],
        pre_signature: [u8; 64],
        nonce_parity: NonceParity,
        adaptor_point: [u8; 33],
        output_xonly: [u8; 32],
        tap_sighash: [u8; 32],
    ) -> Result<Self> {
        if !public_parts_are_valid(
            &expected_transaction_digest,
            &pre_signature,
            &adaptor_point,
            &output_xonly,
            &tap_sighash,
        ) {
            return Err(BitcoinActuatorErrorV1::ClaimAuthorityMismatch);
        }
        let context_digest = extraction_context_digest(
            &expected_transaction_digest,
            &pre_signature,
            nonce_parity,
            &adaptor_point,
            &output_xonly,
            &tap_sighash,
        )?;
        Ok(Self {
            expected_transaction_digest,
            pre_signature,
            nonce_parity,
            adaptor_point,
            output_xonly,
            tap_sighash,
            context_digest,
        })
    }
}

impl fmt::Debug for BitcoinClaimExtractionContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BitcoinClaimExtractionContextV1")
            .field("context_digest", &self.context_digest)
            .field("nonce_parity", &self.nonce_parity)
            .field("bound_public_material", &"<redacted>")
            .finish()
    }
}

impl BitcoinPreSignatureV1 {
    /// Consumes this pre-signature into an exact claim-extraction authority.
    ///
    /// `canonical_signed_claim` must be the complete consensus transaction,
    /// not a txid. The method requires one 64-byte key-path witness, removes
    /// that witness and compares the remainder with the frozen transaction,
    /// then independently verifies BIP340 before freezing the exact bytes.
    /// Extraction itself remains deferred until confirmed evidence is passed
    /// to [`extract_revealed_secret_from_confirmed_claim`].
    pub fn into_extraction_context(
        self,
        canonical_signed_claim: &[u8],
    ) -> Result<BitcoinClaimExtractionContextV1> {
        let (mut transaction, signature) = decode_canonical_claim(canonical_signed_claim)?;
        let signature = Zeroizing::new(signature);
        transaction.input[0].witness = Witness::new();
        if transaction != self.transaction {
            return Err(BitcoinActuatorErrorV1::TransactionMismatch);
        }

        let crypto = fresh_crypto_context()?;
        let verification = crypto.verify_bip340(&self.output_xonly, &self.tap_sighash, &signature);
        verification.map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;

        BitcoinClaimExtractionContextV1::from_validated_parts(
            exact_transaction_digest(canonical_signed_claim)?,
            self.pre_signature,
            self.nonce_parity,
            self.adaptor_point,
            self.output_xonly,
            self.tap_sighash,
        )
    }
}

/// Extracts the adaptor scalar from one exact confirmed Bitcoin claim.
///
/// The caller must supply the complete canonical transaction obtained from
/// confirmed chain evidence. A txid is insufficient because it does not
/// commit to witness bytes. The function rechecks the exact byte digest,
/// canonical single-item key-path witness, final BIP340 signature and the
/// backend-enforced `t*G == T` relation before returning a redacting,
/// zeroizing [`RevealedSecretBytes`].
pub fn extract_revealed_secret_from_confirmed_claim(
    context: &BitcoinClaimExtractionContextV1,
    canonical_transaction: &[u8],
) -> Result<RevealedSecretBytes> {
    if canonical_transaction.is_empty() || canonical_transaction.len() > MAX_CONFIRMED_CLAIM_BYTES {
        return Err(BitcoinActuatorErrorV1::InvalidTransaction);
    }
    if exact_transaction_digest(canonical_transaction)? != context.expected_transaction_digest {
        return Err(BitcoinActuatorErrorV1::TransactionMismatch);
    }

    let (_, signature) = decode_canonical_claim(canonical_transaction)?;
    let signature = Zeroizing::new(signature);
    let crypto = fresh_crypto_context()?;
    if crypto
        .verify_bip340(&context.output_xonly, &context.tap_sighash, &signature)
        .is_err()
    {
        return Err(BitcoinActuatorErrorV1::ClaimCryptography);
    }
    let extraction = crypto.extract(
        &signature,
        &context.pre_signature,
        context.nonce_parity,
        &context.adaptor_point,
    );
    let mut extracted = extraction.map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    let revealed = RevealedSecretBytes::new(extracted);
    extracted.zeroize();
    Ok(revealed)
}

/// Consumes one exact RPC lookup and extracts only from a sufficiently buried
/// canonical claim.
///
/// The witness-bearing bytes remain private to `btc-actuator`: callers cannot
/// obtain them from [`crate::BitcoinRpcTransactionV1`] and therefore cannot
/// accidentally persist or format a secret-revealing signature.  A mempool or
/// absent result is never treated as confirmed, and the transaction id is
/// recomputed from the returned consensus bytes rather than trusted from the
/// lookup key.
pub fn extract_revealed_secret_from_confirmed_lookup(
    context: &BitcoinClaimExtractionContextV1,
    expected_txid: [u8; 32],
    minimum_confirmations: u32,
    lookup: BitcoinRpcLookupV1,
) -> Result<RevealedSecretBytes> {
    if expected_txid == [0; 32] || minimum_confirmations == 0 {
        return Err(BitcoinActuatorErrorV1::InvalidScope);
    }
    let BitcoinRpcLookupV1::Confirmed {
        transaction,
        block_hash,
        block_height,
        confirmations,
    } = lookup
    else {
        return Err(BitcoinActuatorErrorV1::InvalidState);
    };
    if block_hash == [0; 32]
        || block_height == 0
        || confirmations < minimum_confirmations
        || transaction.evidence_digest == [0; 32]
    {
        return Err(BitcoinActuatorErrorV1::InvalidState);
    }
    let decoded: Transaction = deserialize(&transaction.raw_transaction)
        .map_err(|_| BitcoinActuatorErrorV1::InvalidTransaction)?;
    if decoded.compute_txid().to_raw_hash().to_byte_array() != expected_txid {
        return Err(BitcoinActuatorErrorV1::TransactionMismatch);
    }
    extract_revealed_secret_from_confirmed_claim(context, &transaction.raw_transaction)
}

fn decode_canonical_claim(bytes: &[u8]) -> Result<(Transaction, [u8; 64])> {
    if bytes.is_empty() || bytes.len() > MAX_CONFIRMED_CLAIM_BYTES {
        return Err(BitcoinActuatorErrorV1::InvalidTransaction);
    }
    let transaction: Transaction =
        deserialize(bytes).map_err(|_| BitcoinActuatorErrorV1::InvalidTransaction)?;
    if serialize(&transaction).as_slice() != bytes
        || transaction.input.len() != 1
        || transaction.input[0].witness.len() != 1
    {
        return Err(BitcoinActuatorErrorV1::InvalidTransaction);
    }
    let signature = transaction.input[0]
        .witness
        .iter()
        .next()
        .and_then(|item| <[u8; 64]>::try_from(item).ok())
        .ok_or(BitcoinActuatorErrorV1::InvalidTransaction)?;
    Ok((transaction, signature))
}

fn exact_transaction_digest(canonical_transaction: &[u8]) -> Result<[u8; 32]> {
    digest(EXACT_CLAIM_DOMAIN, canonical_transaction)
}

fn extraction_context_digest(
    expected_transaction_digest: &[u8; 32],
    pre_signature: &[u8; 64],
    nonce_parity: NonceParity,
    adaptor_point: &[u8; 33],
    output_xonly: &[u8; 32],
    tap_sighash: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut bytes = Vec::with_capacity(194);
    bytes.extend_from_slice(expected_transaction_digest);
    bytes.extend_from_slice(pre_signature);
    bytes.push(nonce_parity_tag(nonce_parity));
    bytes.extend_from_slice(adaptor_point);
    bytes.extend_from_slice(output_xonly);
    bytes.extend_from_slice(tap_sighash);
    digest(EXTRACTION_CONTEXT_DOMAIN, &bytes)
}

fn public_parts_are_valid(
    expected_transaction_digest: &[u8; 32],
    pre_signature: &[u8; 64],
    adaptor_point: &[u8; 33],
    output_xonly: &[u8; 32],
    tap_sighash: &[u8; 32],
) -> bool {
    expected_transaction_digest != &[0; 32]
        && pre_signature != &[0; 64]
        && tap_sighash != &[0; 32]
        && PublicKey::from_slice(adaptor_point).is_ok()
        && XOnlyPublicKey::from_slice(output_xonly).is_ok()
}

const fn nonce_parity_tag(nonce_parity: NonceParity) -> u8 {
    match nonce_parity {
        NonceParity::Even => 0,
        NonceParity::Odd => 1,
    }
}

fn nonce_parity_from_tag(tag: u8) -> Result<NonceParity> {
    match tag {
        0 => Ok(NonceParity::Even),
        1 => Ok(NonceParity::Odd),
        _ => Err(BitcoinActuatorErrorV1::CorruptState),
    }
}

fn fresh_crypto_context() -> Result<SecpContext> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::getrandom(seed.as_mut()).map_err(|_| BitcoinActuatorErrorV1::ClaimCryptography)?;
    if *seed == [0; 32] {
        return Err(BitcoinActuatorErrorV1::ClaimCryptography);
    }
    Ok(SecpContext::new(&seed))
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use btc_crypto::SecpContext;
    use zeroize::Zeroize;

    use super::{
        exact_transaction_digest, extract_revealed_secret_from_confirmed_claim,
        extract_revealed_secret_from_confirmed_lookup, BitcoinClaimExtractionContextV1,
        BITCOIN_CLAIM_EXTRACTION_CONTEXT_V1_BYTES, NONCE_PARITY_OFFSET,
    };
    use crate::signer::BitcoinPreSignatureV1;
    use crate::{BitcoinActuatorErrorV1, BitcoinRpcLookupV1, BitcoinRpcTransactionV1};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    struct ExtractionFixture {
        prepared: BitcoinPreSignatureV1,
        raw: Vec<u8>,
        final_signature: [u8; 64],
        expected_secret: [u8; 32],
    }

    fn extraction_fixture() -> TestResult<ExtractionFixture> {
        let sk1 = [0x11; 32];
        let sk2 = [0x22; 32];
        let expected_secret = [0x2b; 32];
        let secp = Secp256k1::new();
        let pk1 = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk1)?).serialize();
        let pk2 = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&sk2)?).serialize();
        let adaptor_point =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&expected_secret)?)
                .serialize();

        let crypto = SecpContext::new(&[0x5a; 32]);
        let tap_sighash = [0x6d; 32];
        let mut keyagg = crypto.key_agg(&[pk1, pk2])?;
        let tweak = crypto.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
        let output_xonly = crypto.apply_tap_tweak(&mut keyagg, &tweak)?.output_xonly;
        let (secret_nonce_one, public_nonce_one) =
            crypto.nonce_gen(&[0xa1; 32], &sk1, &pk1, &tap_sighash, &keyagg)?;
        let (secret_nonce_two, public_nonce_two) =
            crypto.nonce_gen(&[0xa2; 32], &sk2, &pk2, &tap_sighash, &keyagg)?;
        let aggregate_nonce = crypto.nonce_agg(&[public_nonce_one.0, public_nonce_two.0])?;
        let session =
            crypto.nonce_process(&aggregate_nonce, &tap_sighash, &keyagg, &adaptor_point)?;
        let partial_one = crypto.partial_sign(
            secret_nonce_one,
            &sk1,
            &pk1,
            &public_nonce_one.0,
            &keyagg,
            &session,
        )?;
        let partial_two = crypto.partial_sign(
            secret_nonce_two,
            &sk2,
            &pk2,
            &public_nonce_two.0,
            &keyagg,
            &session,
        )?;
        let pre_signature = crypto.aggregate_pre_signature(
            &[partial_one, partial_two],
            &output_xonly,
            &tap_sighash,
            &session,
        )?;
        let final_signature = crypto.adapt(
            &pre_signature,
            &expected_secret,
            session.nonce_parity,
            &output_xonly,
            &tap_sighash,
        )?;

        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let prepared = BitcoinPreSignatureV1 {
            session_digest: [0x31; 32],
            transcript_digest: [0x32; 32],
            transaction: transaction.clone(),
            pre_signature,
            nonce_parity: session.nonce_parity,
            adaptor_point,
            output_xonly,
            tap_sighash,
        };
        let mut signed = transaction;
        signed.input[0].witness = Witness::from_slice(&[final_signature]);
        Ok(ExtractionFixture {
            prepared,
            raw: serialize(&signed),
            final_signature,
            expected_secret,
        })
    }

    fn context_for_exact_bytes(
        prepared: &BitcoinPreSignatureV1,
        exact_bytes: &[u8],
    ) -> TestResult<BitcoinClaimExtractionContextV1> {
        Ok(BitcoinClaimExtractionContextV1::from_validated_parts(
            exact_transaction_digest(exact_bytes)?,
            prepared.pre_signature,
            prepared.nonce_parity,
            prepared.adaptor_point,
            prepared.output_xonly,
            prepared.tap_sighash,
        )?)
    }

    #[test]
    fn exact_claim_extracts_and_context_round_trips() -> TestResult {
        let ExtractionFixture {
            prepared,
            raw,
            mut expected_secret,
            ..
        } = extraction_fixture()?;
        let context = prepared.into_extraction_context(&raw)?;
        let durable = context.to_durable_bytes();
        assert_eq!(durable.len(), BITCOIN_CLAIM_EXTRACTION_CONTEXT_V1_BYTES);
        let restored = BitcoinClaimExtractionContextV1::from_durable_bytes(&durable)?;
        assert_eq!(restored, context);

        let revealed = extract_revealed_secret_from_confirmed_claim(&restored, &raw)?;
        let mut exposed = revealed.expose_scalar_bytes();
        assert_eq!(exposed, expected_secret);
        exposed.zeroize();
        expected_secret.zeroize();
        Ok(())
    }

    #[test]
    fn confirmed_lookup_keeps_witness_bytes_inside_the_actuator_boundary() -> TestResult {
        let ExtractionFixture {
            prepared,
            raw,
            mut expected_secret,
            ..
        } = extraction_fixture()?;
        let transaction: Transaction = deserialize(&raw)?;
        let txid = transaction.compute_txid().to_raw_hash().to_byte_array();
        let context = prepared.into_extraction_context(&raw)?;
        let lookup = BitcoinRpcLookupV1::Confirmed {
            transaction: BitcoinRpcTransactionV1::from_consensus_bytes(raw, [0x71; 32])?,
            block_hash: [0x72; 32],
            block_height: 42,
            confirmations: 6,
        };

        let revealed = extract_revealed_secret_from_confirmed_lookup(&context, txid, 6, lookup)?;
        let mut scalar = revealed.expose_scalar_bytes();
        assert_eq!(scalar, expected_secret);
        scalar.zeroize();
        expected_secret.zeroize();
        Ok(())
    }

    #[test]
    fn mempool_shallow_and_wrong_txid_lookups_never_extract() -> TestResult {
        let fixture = extraction_fixture()?;
        let context = fixture.prepared.into_extraction_context(&fixture.raw)?;
        let transaction: Transaction = deserialize(&fixture.raw)?;
        let txid = transaction.compute_txid().to_raw_hash().to_byte_array();
        assert!(matches!(
            extract_revealed_secret_from_confirmed_lookup(
                &context,
                txid,
                1,
                BitcoinRpcLookupV1::Mempool(BitcoinRpcTransactionV1::from_consensus_bytes(
                    fixture.raw,
                    [0x73; 32]
                )?),
            ),
            Err(BitcoinActuatorErrorV1::InvalidState)
        ));

        let fixture = extraction_fixture()?;
        let context = fixture.prepared.into_extraction_context(&fixture.raw)?;
        assert!(matches!(
            extract_revealed_secret_from_confirmed_lookup(
                &context,
                txid,
                2,
                BitcoinRpcLookupV1::Confirmed {
                    transaction: BitcoinRpcTransactionV1::from_consensus_bytes(
                        fixture.raw,
                        [0x74; 32]
                    )?,
                    block_hash: [0x75; 32],
                    block_height: 42,
                    confirmations: 1,
                },
            ),
            Err(BitcoinActuatorErrorV1::InvalidState)
        ));

        let fixture = extraction_fixture()?;
        let context = fixture.prepared.into_extraction_context(&fixture.raw)?;
        assert!(matches!(
            extract_revealed_secret_from_confirmed_lookup(
                &context,
                [0x76; 32],
                1,
                BitcoinRpcLookupV1::Confirmed {
                    transaction: BitcoinRpcTransactionV1::from_consensus_bytes(
                        fixture.raw,
                        [0x77; 32]
                    )?,
                    block_hash: [0x78; 32],
                    block_height: 42,
                    confirmations: 1,
                },
            ),
            Err(BitcoinActuatorErrorV1::TransactionMismatch)
        ));
        Ok(())
    }

    #[test]
    fn same_txid_with_different_witness_is_rejected() -> TestResult {
        let fixture = extraction_fixture()?;
        let context = fixture.prepared.into_extraction_context(&fixture.raw)?;
        let original: Transaction = deserialize(&fixture.raw)?;
        let mut changed = original.clone();
        let mut changed_signature = fixture.final_signature;
        changed_signature[63] ^= 1;
        changed.input[0].witness = Witness::from_slice(&[changed_signature]);
        assert_eq!(original.compute_txid(), changed.compute_txid());

        let changed_raw = serialize(&changed);
        assert!(matches!(
            extract_revealed_secret_from_confirmed_claim(&context, &changed_raw),
            Err(BitcoinActuatorErrorV1::TransactionMismatch)
        ));
        Ok(())
    }

    #[test]
    fn wrong_bip340_signature_is_rejected_after_exact_binding() -> TestResult {
        let fixture = extraction_fixture()?;
        let mut transaction: Transaction = deserialize(&fixture.raw)?;
        let mut wrong_signature = fixture.final_signature;
        wrong_signature[63] ^= 1;
        transaction.input[0].witness = Witness::from_slice(&[wrong_signature]);
        let wrong_raw = serialize(&transaction);
        let context = context_for_exact_bytes(&fixture.prepared, &wrong_raw)?;

        assert!(matches!(
            extract_revealed_secret_from_confirmed_claim(&context, &wrong_raw),
            Err(BitcoinActuatorErrorV1::ClaimCryptography)
        ));
        Ok(())
    }

    #[test]
    fn wrong_adaptor_point_is_rejected_by_group_check() -> TestResult {
        let mut fixture = extraction_fixture()?;
        let secp = Secp256k1::new();
        fixture.prepared.adaptor_point =
            PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x2c; 32])?).serialize();
        let context = fixture.prepared.into_extraction_context(&fixture.raw)?;

        assert!(matches!(
            extract_revealed_secret_from_confirmed_claim(&context, &fixture.raw),
            Err(BitcoinActuatorErrorV1::ClaimCryptography)
        ));
        Ok(())
    }

    #[test]
    fn trailing_noncanonical_and_multi_item_witnesses_are_rejected() -> TestResult {
        let fixture = extraction_fixture()?;
        let mut trailing_transaction = fixture.raw.clone();
        trailing_transaction.push(0);
        assert!(matches!(
            fixture
                .prepared
                .into_extraction_context(&trailing_transaction),
            Err(BitcoinActuatorErrorV1::InvalidTransaction)
        ));

        let fixture = extraction_fixture()?;
        assert_eq!(&fixture.raw[4..7], &[0, 1, 1]);
        let mut non_minimal_input_count = Vec::with_capacity(fixture.raw.len() + 2);
        non_minimal_input_count.extend_from_slice(&fixture.raw[..6]);
        non_minimal_input_count.extend_from_slice(&[0xfd, 1, 0]);
        non_minimal_input_count.extend_from_slice(&fixture.raw[7..]);
        assert!(matches!(
            fixture
                .prepared
                .into_extraction_context(&non_minimal_input_count),
            Err(BitcoinActuatorErrorV1::InvalidTransaction)
        ));

        let fixture = extraction_fixture()?;
        let mut two_items: Transaction = deserialize(&fixture.raw)?;
        two_items.input[0].witness = Witness::from_slice(&[fixture.final_signature, [1_u8; 64]]);
        assert!(matches!(
            fixture
                .prepared
                .into_extraction_context(&serialize(&two_items)),
            Err(BitcoinActuatorErrorV1::InvalidTransaction)
        ));
        Ok(())
    }

    #[test]
    fn durable_codec_rejects_trailing_unknown_parity_and_zero_records() -> TestResult {
        let fixture = extraction_fixture()?;
        let context = fixture.prepared.into_extraction_context(&fixture.raw)?;
        let durable = context.to_durable_bytes();
        let mut trailing = durable.to_vec();
        trailing.push(0);
        assert!(matches!(
            BitcoinClaimExtractionContextV1::from_durable_bytes(&trailing),
            Err(BitcoinActuatorErrorV1::CorruptState)
        ));

        let mut unknown_parity = durable;
        unknown_parity[NONCE_PARITY_OFFSET] = 2;
        assert!(matches!(
            BitcoinClaimExtractionContextV1::from_durable_bytes(&unknown_parity),
            Err(BitcoinActuatorErrorV1::CorruptState)
        ));
        assert!(matches!(
            BitcoinClaimExtractionContextV1::from_durable_bytes(
                &[0; BITCOIN_CLAIM_EXTRACTION_CONTEXT_V1_BYTES]
            ),
            Err(BitcoinActuatorErrorV1::CorruptState)
        ));
        Ok(())
    }

    #[test]
    fn zero_extracted_scalar_is_rejected_and_debug_is_redacted() -> TestResult {
        let fixture = extraction_fixture()?;
        let context = BitcoinClaimExtractionContextV1::from_validated_parts(
            exact_transaction_digest(&fixture.raw)?,
            fixture.final_signature,
            fixture.prepared.nonce_parity,
            fixture.prepared.adaptor_point,
            fixture.prepared.output_xonly,
            fixture.prepared.tap_sighash,
        )?;
        assert!(matches!(
            extract_revealed_secret_from_confirmed_claim(&context, &fixture.raw),
            Err(BitcoinActuatorErrorV1::ClaimCryptography)
        ));

        let debug = format!("{context:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("pre_signature"));
        Ok(())
    }
}
