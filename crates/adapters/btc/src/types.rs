//! Canonical domain types of the Bitcoin leg (M.1, M.3.1, M.4.1, M.5).
//!
//! Everything here is *public protocol data*: nonces, partial signatures,
//! pre-signatures, bindings. The one secret type of this layer,
//! [`crate::scalar::AdaptorSecretV1`], lives in its own module with its
//! own rules. Sizes follow the canonical communication format of M.5.2,
//! not the in-memory layout of any FFI type.

use crate::codec::{self, CanonicalBitcoinCodec};
use crate::error::CodecError;
use crate::scalar;

/// Frozen protocol version of every F5 binding (M.5.1).
pub const BTC_PROTOCOL_VERSION: u16 = 1;

/// Parity of a point's y coordinate after x-only normalization (M.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParityV1 {
    /// Even y.
    Even = 0,
    /// Odd y.
    Odd = 1,
}

impl ParityV1 {
    /// Decodes the frozen discriminant.
    pub fn from_u8(value: u8, field: &'static str) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Even),
            1 => Ok(Self::Odd),
            _ => Err(CodecError::UnknownDiscriminant { field }),
        }
    }
}

/// Parity of the aggregate nonce produced by `nonce_process` (M.4.2).
///
/// Distinct from [`ParityV1`] on purpose: one describes keys, the other
/// describes the session nonce; the two are never interchangeable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NonceParityV1 {
    /// Even aggregate nonce.
    Even = 0,
    /// Odd aggregate nonce.
    Odd = 1,
}

impl NonceParityV1 {
    /// Decodes the frozen discriminant.
    pub fn from_u8(value: u8, field: &'static str) -> Result<Self, CodecError> {
        match value {
            0 => Ok(Self::Even),
            1 => Ok(Self::Odd),
            _ => Err(CodecError::UnknownDiscriminant { field }),
        }
    }
}

/// The F5 network registry (M.3.1). Mainnet does not exist in this enum;
/// its introduction is a later decision with its own gate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinNetworkV1 {
    /// Deterministic local network.
    Regtest = 0x01,
    /// Persistent controlled signet with a known challenge.
    CustomSignet = 0x02,
    /// The public signet.
    PublicSignet = 0x03,
}

impl BitcoinNetworkV1 {
    /// Decodes the frozen discriminant.
    pub fn from_u8(value: u8, field: &'static str) -> Result<Self, CodecError> {
        match value {
            0x01 => Ok(Self::Regtest),
            0x02 => Ok(Self::CustomSignet),
            0x03 => Ok(Self::PublicSignet),
            _ => Err(CodecError::UnknownDiscriminant { field }),
        }
    }
}

/// Economic direction of the settlement (M.5.1). Never inferred from the
/// reveal order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettlementDirectionV1 {
    /// Originator delivers DOM, receives BTC.
    DomToBitcoin = 0x01,
    /// Originator delivers BTC, receives DOM.
    BitcoinToDom = 0x02,
}

impl SettlementDirectionV1 {
    /// Decodes the frozen discriminant.
    pub fn from_u8(value: u8, field: &'static str) -> Result<Self, CodecError> {
        match value {
            0x01 => Ok(Self::DomToBitcoin),
            0x02 => Ok(Self::BitcoinToDom),
            _ => Err(CodecError::UnknownDiscriminant { field }),
        }
    }
}

/// Which leg reveals `t` first (M.5.1). Never inferred from the economic
/// direction.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RevealLegV1 {
    /// The DOM claim reveals `t`.
    DomFirst = 0x01,
    /// The Bitcoin claim reveals `t`.
    BitcoinFirst = 0x02,
}

impl RevealLegV1 {
    /// Decodes the frozen discriminant.
    pub fn from_u8(value: u8, field: &'static str) -> Result<Self, CodecError> {
        match value {
            0x01 => Ok(Self::DomFirst),
            0x02 => Ok(Self::BitcoinFirst),
            _ => Err(CodecError::UnknownDiscriminant { field }),
        }
    }
}

/// A previous output being spent (M.3.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinOutPointV1 {
    /// Transaction id, internal byte order.
    pub txid: [u8; 32],
    /// Output index.
    pub vout: u32,
}

/// The adaptor point `T = t·G`, compressed SEC1 (M.4.1).
///
/// The type-level check covers the *encoding form* (33 bytes, 0x02/0x03
/// prefix); the curve check belongs to the cryptographic backend, which
/// re-validates every external point before use (M.1.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AdaptorPointV1(pub(crate) [u8; 33]);

impl AdaptorPointV1 {
    /// Validates the SEC1 compressed form.
    pub fn from_bytes(bytes: [u8; 33]) -> Result<Self, CodecError> {
        if bytes[0] != 0x02 && bytes[0] != 0x03 {
            return Err(CodecError::InvalidField {
                field: "adaptor_point",
            });
        }
        Ok(Self(bytes))
    }

    /// The canonical 33 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

/// The BIP341 sighash message being signed (M.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TapSighashV1(pub [u8; 32]);

/// A final 64-byte BIP340 signature (M.4.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Bip340SignatureV1(pub [u8; 64]);

/// A 64-byte MuSig2 adaptor pre-signature `x(R) || ŝ` (M.4.1).
///
/// Not a valid BIP340 signature until adapted — C2 vector rule 7 proves
/// this for every fixture.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BtcAdaptorPreSignatureV1(pub [u8; 64]);

/// A MuSig2 public nonce: two compressed points, 66 bytes (M.5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicNonceBytesV1(pub(crate) [u8; 66]);

impl PublicNonceBytesV1 {
    /// Validates the encoding form of both halves (0x02/0x03 prefixes).
    ///
    /// An *individual* participant nonce never contains the point at
    /// infinity; the all-zero half only exists in BIP327's aggregate
    /// nonce, which has its own type in the signing layer.
    pub fn from_bytes(bytes: [u8; 66]) -> Result<Self, CodecError> {
        for half_start in [0usize, 33] {
            let prefix = bytes[half_start];
            if prefix != 0x02 && prefix != 0x03 {
                return Err(CodecError::InvalidField {
                    field: "public_nonce",
                });
            }
        }
        Ok(Self(bytes))
    }

    /// The canonical 66 bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 66] {
        &self.0
    }
}

/// The complete identity of one Bitcoin signing session (M.5.1).
///
/// Every artifact of the leg carries this binding's digest; an artifact
/// whose binding digest diverges is rejected before any cryptographic
/// work (P4).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinSessionBindingV1 {
    /// Frozen protocol version ([`BTC_PROTOCOL_VERSION`]).
    pub protocol_version: u16,
    /// One-shot public settlement identifier.
    pub settlement_id: [u8; 32],
    /// One-shot public signing-session identifier.
    pub session_id: [u8; 32],
    /// A3 authority hash of the frozen terms.
    pub terms_hash: [u8; 32],
    /// Genesis hash of the Bitcoin network in use (M.13.2).
    pub bitcoin_genesis_hash: [u8; 32],
    /// Identifier of the DOM chain on the other leg.
    pub dom_chain_id: [u8; 32],
    /// Economic direction (never inferred from `reveal_leg`).
    pub direction: SettlementDirectionV1,
    /// Which leg reveals `t` first (never inferred from `direction`).
    pub reveal_leg: RevealLegV1,
    /// Digest of the canonical participant roster.
    pub roster_hash: [u8; 32],
    /// The adaptor point `T` committed by the terms.
    pub adaptor_point: AdaptorPointV1,
    /// Digest of the frozen funding template.
    pub funding_template_hash: [u8; 32],
    /// Digest of the frozen claim template.
    pub claim_template_hash: [u8; 32],
    /// Digest of the frozen refund template.
    pub refund_template_hash: [u8; 32],
}

impl BitcoinSessionBindingV1 {
    /// The binding digest: `BLAKE2b-256` over the domain-prefixed
    /// canonical encoding (M.5.3). Infallible for a value that already
    /// passed construction/decoding.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut out = Vec::with_capacity(Self::MAX_ENCODED_LEN);
        // A constructed value always encodes: the only encode failure is
        // an invalid protocol_version, checked below against the frozen
        // constant at both construction and decode.
        debug_assert_eq!(self.protocol_version, BTC_PROTOCOL_VERSION);
        let _ = self.encode_canonical(&mut out);
        codec::f5_digest(Self::KIND, &out)
    }
}

/// Wire envelope of one participant's public nonce (M.5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicNonceEnvelopeV1 {
    /// Digest of the session binding this nonce belongs to.
    pub binding_digest: [u8; 32],
    /// The participant that produced the nonce.
    pub participant_id: [u8; 32],
    /// The 66-byte MuSig2 public nonce.
    pub public_nonce: PublicNonceBytesV1,
    /// Integrity digest over the canonical prelude of this envelope.
    pub outbound_digest: [u8; 32],
}

impl PublicNonceEnvelopeV1 {
    /// Builds the envelope, computing its outbound digest.
    #[must_use]
    pub fn new(
        binding_digest: [u8; 32],
        participant_id: [u8; 32],
        public_nonce: PublicNonceBytesV1,
    ) -> Self {
        let mut env = Self {
            binding_digest,
            participant_id,
            public_nonce,
            outbound_digest: [0u8; 32],
        };
        env.outbound_digest = codec::envelope_digest(&env);
        env
    }
}

/// Wire envelope of one participant's partial signature (M.5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PartialSignatureEnvelopeV1 {
    /// Digest of the session binding this partial belongs to.
    pub binding_digest: [u8; 32],
    /// The participant that produced the partial.
    pub participant_id: [u8; 32],
    /// Digest of the public-nonce envelope this partial answers.
    pub public_nonce_digest: [u8; 32],
    /// The 32-byte partial signature scalar (canonical, `< n`).
    pub partial_signature: [u8; 32],
    /// Integrity digest over the canonical prelude of this envelope.
    pub outbound_digest: [u8; 32],
}

impl PartialSignatureEnvelopeV1 {
    /// Builds the envelope, computing its outbound digest.
    ///
    /// Fails when the scalar is not canonical (`≥ n`); zero is accepted
    /// at the wire layer and adjudicated by `partial_verify`.
    pub fn new(
        binding_digest: [u8; 32],
        participant_id: [u8; 32],
        public_nonce_digest: [u8; 32],
        partial_signature: [u8; 32],
    ) -> Result<Self, CodecError> {
        if !scalar::is_below_order(&partial_signature) {
            return Err(CodecError::InvalidField {
                field: "partial_signature",
            });
        }
        let mut env = Self {
            binding_digest,
            participant_id,
            public_nonce_digest,
            partial_signature,
            outbound_digest: [0u8; 32],
        };
        env.outbound_digest = codec::envelope_digest(&env);
        Ok(env)
    }
}

/// Wire envelope of the aggregated adaptor pre-signature (M.5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PreSignatureEnvelopeV1 {
    /// Digest of the session binding this pre-signature belongs to.
    pub binding_digest: [u8; 32],
    /// The 64-byte aggregate pre-signature `x(R) || ŝ`.
    pub pre_signature: BtcAdaptorPreSignatureV1,
    /// The session's nonce parity, required for adapt/extract (M.4.2).
    pub nonce_parity: NonceParityV1,
    /// The adaptor point `T` the pre-signature is bound to.
    pub adaptor_point: AdaptorPointV1,
    /// The frozen sighash the pre-signature commits to.
    pub tap_sighash: TapSighashV1,
    /// Integrity digest over the canonical prelude of this envelope.
    pub outbound_digest: [u8; 32],
}

impl PreSignatureEnvelopeV1 {
    /// Builds the envelope, computing its outbound digest.
    ///
    /// Fails when the `ŝ` half of the pre-signature is not a canonical
    /// scalar (M.1.1: external scalars are never silently reduced).
    pub fn new(
        binding_digest: [u8; 32],
        pre_signature: BtcAdaptorPreSignatureV1,
        nonce_parity: NonceParityV1,
        adaptor_point: AdaptorPointV1,
        tap_sighash: TapSighashV1,
    ) -> Result<Self, CodecError> {
        let mut s_half = [0u8; 32];
        s_half.copy_from_slice(&pre_signature.0[32..64]);
        if !scalar::is_below_order(&s_half) {
            return Err(CodecError::InvalidField {
                field: "pre_signature",
            });
        }
        let mut env = Self {
            binding_digest,
            pre_signature,
            nonce_parity,
            adaptor_point,
            tap_sighash,
            outbound_digest: [0u8; 32],
        };
        env.outbound_digest = codec::envelope_digest(&env);
        Ok(env)
    }
}
