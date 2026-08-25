//! The canonical DOMBTC wire codec (M.5.3).
//!
//! Every F5 wire format starts with the ASCII magic `DOMBTC`, a
//! big-endian `u16` wire version and a `u16` kind; uses fixed-width
//! big-endian integers; has a per-type maximum length enforced *before*
//! parsing; rejects unknown values, trailing bytes and tampered digests;
//! and computes digests under the domain
//! `DOM-INTEROP/BTC/F5/V1/<KIND>`. serde/bincode never define this wire.
//!
//! Canonical property set proved by the tests: P1 `decode(encode(x)) = x`,
//! P2 `encode(decode(b)) = b`, P3 trailing bytes always fail, P4 altering
//! any byte prevents acceptance.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::error::CodecError;
use crate::roster::{
    BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1, ROSTER_VERSION,
};
use crate::types::{
    AdaptorPointV1, BitcoinSessionBindingV1, BtcAdaptorPreSignatureV1, NonceParityV1,
    PartialSignatureEnvelopeV1, PreSignatureEnvelopeV1, PublicNonceBytesV1, PublicNonceEnvelopeV1,
    RevealLegV1, SettlementDirectionV1, TapSighashV1, BTC_PROTOCOL_VERSION,
};

/// Leading ASCII magic of every canonical F5 encoding.
pub const DOMBTC_MAGIC: &[u8; 6] = b"DOMBTC";
/// Frozen wire version. Any other version fails closed.
pub const WIRE_VERSION: u16 = 1;
/// Size of the common header: magic + version + kind.
pub const HEADER_LEN: usize = 6 + 2 + 2;

/// Kind registry. Kinds are frozen; a new artifact takes a new number,
/// never reuses one.
pub const KIND_SESSION_BINDING: u16 = 0x0001;
/// Kind of [`ParticipantKeyRosterV1`].
pub const KIND_ROSTER: u16 = 0x0002;
/// Kind of [`PublicNonceEnvelopeV1`].
pub const KIND_PUBLIC_NONCE: u16 = 0x0003;
/// Kind of [`PartialSignatureEnvelopeV1`].
pub const KIND_PARTIAL_SIGNATURE: u16 = 0x0004;
/// Kind of [`PreSignatureEnvelopeV1`].
pub const KIND_PRE_SIGNATURE: u16 = 0x0005;

/// Canonical codec of one F5 artifact (M.5.3).
pub trait CanonicalBitcoinCodec: Sized {
    /// Frozen kind discriminant of this artifact.
    const KIND: u16;
    /// Hard input cap, enforced before any parse or allocation.
    const MAX_ENCODED_LEN: usize;

    /// Appends the canonical encoding to `out`.
    fn encode_canonical(&self, out: &mut Vec<u8>) -> Result<(), CodecError>;
    /// Decodes and fully validates one artifact from exactly `input`.
    fn decode_canonical(input: &[u8]) -> Result<Self, CodecError>;
}

/// Digest under the F5 domain of `kind` (M.5.3):
/// `BLAKE2b-256("DOM-INTEROP/BTC/F5/V1/<KIND>\0" || payload)`.
#[must_use]
pub fn f5_digest(kind: u16, payload: &[u8]) -> [u8; 32] {
    let domain: &[u8] = match kind {
        KIND_SESSION_BINDING => b"DOM-INTEROP/BTC/F5/V1/SESSION-BINDING\0",
        KIND_ROSTER => b"DOM-INTEROP/BTC/F5/V1/ROSTER\0",
        KIND_PUBLIC_NONCE => b"DOM-INTEROP/BTC/F5/V1/PUBLIC-NONCE\0",
        KIND_PARTIAL_SIGNATURE => b"DOM-INTEROP/BTC/F5/V1/PARTIAL-SIGNATURE\0",
        KIND_PRE_SIGNATURE => b"DOM-INTEROP/BTC/F5/V1/PRE-SIGNATURE\0",
        // The registry is closed; an unknown kind cannot be reached from
        // any public API because KIND is an associated constant.
        _ => b"DOM-INTEROP/BTC/F5/V1/UNKNOWN\0",
    };
    let mut h = Blake2bVar::new(32).expect("BLAKE2b-256 output size is valid"); // I14-ALLOW: fixed 32-byte output is always valid
    h.update(domain);
    h.update(payload);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out)
        .expect("BLAKE2b-256 output size is valid"); // I14-ALLOW: fixed 32-byte output
    out
}

/// Fixed-offset reader over one canonical input.
struct ByteReader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(CodecError::Truncated(self.pos))?;
        if end > self.input.len() {
            return Err(CodecError::Truncated(self.pos));
        }
        let slice = &self.input[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    fn take_u16(&mut self) -> Result<u16, CodecError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    fn finish(&self) -> Result<(), CodecError> {
        if self.pos != self.input.len() {
            return Err(CodecError::TrailingBytes(self.pos));
        }
        Ok(())
    }
}

fn encode_header(out: &mut Vec<u8>, kind: u16) {
    out.extend_from_slice(DOMBTC_MAGIC);
    out.extend_from_slice(&WIRE_VERSION.to_be_bytes());
    out.extend_from_slice(&kind.to_be_bytes());
}

fn decode_header(reader: &mut ByteReader<'_>, kind: u16) -> Result<(), CodecError> {
    let magic = reader.take(6)?;
    if magic != DOMBTC_MAGIC {
        return Err(CodecError::BadMagic);
    }
    if reader.take_u16()? != WIRE_VERSION {
        return Err(CodecError::UnsupportedVersion);
    }
    if reader.take_u16()? != kind {
        return Err(CodecError::KindMismatch);
    }
    Ok(())
}

fn check_cap(input: &[u8], max: usize) -> Result<(), CodecError> {
    if input.len() > max {
        return Err(CodecError::OverCap);
    }
    Ok(())
}

/// The prelude of an envelope: everything except its outbound digest.
/// Crate-private — used by the constructors in `types.rs` and by the
/// codec impls below, so the digest is always computed over the same
/// bytes that go on the wire.
pub(crate) trait EnvelopePrelude {
    const KIND: u16;
    fn encode_prelude(&self, out: &mut Vec<u8>);
}

/// Digest of an envelope's canonical prelude (header included, so the
/// digest also binds magic, version and kind).
pub(crate) fn envelope_digest<T: EnvelopePrelude>(envelope: &T) -> [u8; 32] {
    let mut buf = Vec::new();
    encode_header(&mut buf, T::KIND);
    envelope.encode_prelude(&mut buf);
    f5_digest(T::KIND, &buf)
}

// ─── BitcoinSessionBindingV1 ────────────────────────────────────────────

impl CanonicalBitcoinCodec for BitcoinSessionBindingV1 {
    const KIND: u16 = KIND_SESSION_BINDING;
    // header + version + 5×32 ids/hashes + 2 enums + roster_hash +
    // adaptor_point + 3 template hashes.
    const MAX_ENCODED_LEN: usize = HEADER_LEN + 2 + 32 * 5 + 1 + 1 + 32 + 33 + 32 * 3;

    fn encode_canonical(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        if self.protocol_version != BTC_PROTOCOL_VERSION {
            return Err(CodecError::InvalidField {
                field: "protocol_version",
            });
        }
        encode_header(out, Self::KIND);
        out.extend_from_slice(&self.protocol_version.to_be_bytes());
        out.extend_from_slice(&self.settlement_id);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.terms_hash);
        out.extend_from_slice(&self.bitcoin_genesis_hash);
        out.extend_from_slice(&self.dom_chain_id);
        out.push(self.direction as u8);
        out.push(self.reveal_leg as u8);
        out.extend_from_slice(&self.roster_hash);
        out.extend_from_slice(self.adaptor_point.as_bytes());
        out.extend_from_slice(&self.funding_template_hash);
        out.extend_from_slice(&self.claim_template_hash);
        out.extend_from_slice(&self.refund_template_hash);
        Ok(())
    }

    fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        check_cap(input, Self::MAX_ENCODED_LEN)?;
        let mut r = ByteReader::new(input);
        decode_header(&mut r, Self::KIND)?;
        let protocol_version = r.take_u16()?;
        if protocol_version != BTC_PROTOCOL_VERSION {
            return Err(CodecError::InvalidField {
                field: "protocol_version",
            });
        }
        let settlement_id = r.take_array::<32>()?;
        let session_id = r.take_array::<32>()?;
        let terms_hash = r.take_array::<32>()?;
        let bitcoin_genesis_hash = r.take_array::<32>()?;
        let dom_chain_id = r.take_array::<32>()?;
        let direction = SettlementDirectionV1::from_u8(r.take_u8()?, "direction")?;
        let reveal_leg = RevealLegV1::from_u8(r.take_u8()?, "reveal_leg")?;
        let roster_hash = r.take_array::<32>()?;
        let adaptor_point = AdaptorPointV1::from_bytes(r.take_array::<33>()?)?;
        let funding_template_hash = r.take_array::<32>()?;
        let claim_template_hash = r.take_array::<32>()?;
        let refund_template_hash = r.take_array::<32>()?;
        r.finish()?;
        Ok(Self {
            protocol_version,
            settlement_id,
            session_id,
            terms_hash,
            bitcoin_genesis_hash,
            dom_chain_id,
            direction,
            reveal_leg,
            roster_hash,
            adaptor_point,
            funding_template_hash,
            claim_template_hash,
            refund_template_hash,
        })
    }
}

// ─── ParticipantKeyRosterV1 ─────────────────────────────────────────────

impl CanonicalBitcoinCodec for ParticipantKeyRosterV1 {
    const KIND: u16 = KIND_ROSTER;
    const MAX_ENCODED_LEN: usize = HEADER_LEN + 2 + 2 * (32 + 1 + 33);

    fn encode_canonical(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        self.validate()?;
        encode_header(out, Self::KIND);
        out.extend_from_slice(&self.version().to_be_bytes());
        for p in self.participants() {
            out.extend_from_slice(&p.participant_id);
            out.push(p.role as u8);
            out.extend_from_slice(&p.compressed_key);
        }
        Ok(())
    }

    fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        check_cap(input, Self::MAX_ENCODED_LEN)?;
        let mut r = ByteReader::new(input);
        decode_header(&mut r, Self::KIND)?;
        let version = r.take_u16()?;
        if version != ROSTER_VERSION {
            return Err(CodecError::Roster(
                crate::error::RosterError::UnsupportedVersion,
            ));
        }
        let mut participants = [ParticipantKeyV1 {
            participant_id: [0; 32],
            role: BitcoinSignerRoleV1::Maker,
            compressed_key: [0; 33],
        }; 2];
        for slot in &mut participants {
            let participant_id = r.take_array::<32>()?;
            let role_raw = r.take_u8()?;
            let role = match role_raw {
                0x01 => BitcoinSignerRoleV1::Maker,
                0x02 => BitcoinSignerRoleV1::Taker,
                _ => {
                    return Err(CodecError::UnknownDiscriminant { field: "role" });
                }
            };
            let compressed_key = r.take_array::<33>()?;
            *slot = ParticipantKeyV1 {
                participant_id,
                role,
                compressed_key,
            };
        }
        r.finish()?;
        let roster = Self::from_wire(version, participants)?;
        Ok(roster)
    }
}

// ─── PublicNonceEnvelopeV1 ──────────────────────────────────────────────

impl EnvelopePrelude for PublicNonceEnvelopeV1 {
    const KIND: u16 = KIND_PUBLIC_NONCE;

    fn encode_prelude(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.binding_digest);
        out.extend_from_slice(&self.participant_id);
        out.extend_from_slice(self.public_nonce.as_bytes());
    }
}

impl CanonicalBitcoinCodec for PublicNonceEnvelopeV1 {
    const KIND: u16 = KIND_PUBLIC_NONCE;
    const MAX_ENCODED_LEN: usize = HEADER_LEN + 32 + 32 + 66 + 32;

    fn encode_canonical(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        if envelope_digest(self) != self.outbound_digest {
            return Err(CodecError::DigestMismatch);
        }
        encode_header(out, <Self as CanonicalBitcoinCodec>::KIND);
        self.encode_prelude(out);
        out.extend_from_slice(&self.outbound_digest);
        Ok(())
    }

    fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        check_cap(input, Self::MAX_ENCODED_LEN)?;
        let mut r = ByteReader::new(input);
        decode_header(&mut r, <Self as CanonicalBitcoinCodec>::KIND)?;
        let binding_digest = r.take_array::<32>()?;
        let participant_id = r.take_array::<32>()?;
        let public_nonce = PublicNonceBytesV1::from_bytes(r.take_array::<66>()?)?;
        let outbound_digest = r.take_array::<32>()?;
        r.finish()?;
        let prelude_len = input.len() - 32;
        let expected = f5_digest(<Self as CanonicalBitcoinCodec>::KIND, &input[..prelude_len]);
        if expected != outbound_digest {
            return Err(CodecError::DigestMismatch);
        }
        Ok(Self {
            binding_digest,
            participant_id,
            public_nonce,
            outbound_digest,
        })
    }
}

// ─── PartialSignatureEnvelopeV1 ─────────────────────────────────────────

impl EnvelopePrelude for PartialSignatureEnvelopeV1 {
    const KIND: u16 = KIND_PARTIAL_SIGNATURE;

    fn encode_prelude(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.binding_digest);
        out.extend_from_slice(&self.participant_id);
        out.extend_from_slice(&self.public_nonce_digest);
        out.extend_from_slice(&self.partial_signature);
    }
}

impl CanonicalBitcoinCodec for PartialSignatureEnvelopeV1 {
    const KIND: u16 = KIND_PARTIAL_SIGNATURE;
    const MAX_ENCODED_LEN: usize = HEADER_LEN + 32 * 5;

    fn encode_canonical(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        if !crate::scalar::is_below_order(&self.partial_signature) {
            return Err(CodecError::InvalidField {
                field: "partial_signature",
            });
        }
        if envelope_digest(self) != self.outbound_digest {
            return Err(CodecError::DigestMismatch);
        }
        encode_header(out, <Self as CanonicalBitcoinCodec>::KIND);
        self.encode_prelude(out);
        out.extend_from_slice(&self.outbound_digest);
        Ok(())
    }

    fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        check_cap(input, Self::MAX_ENCODED_LEN)?;
        let mut r = ByteReader::new(input);
        decode_header(&mut r, <Self as CanonicalBitcoinCodec>::KIND)?;
        let binding_digest = r.take_array::<32>()?;
        let participant_id = r.take_array::<32>()?;
        let public_nonce_digest = r.take_array::<32>()?;
        let partial_signature = r.take_array::<32>()?;
        if !crate::scalar::is_below_order(&partial_signature) {
            return Err(CodecError::InvalidField {
                field: "partial_signature",
            });
        }
        let outbound_digest = r.take_array::<32>()?;
        r.finish()?;
        let prelude_len = input.len() - 32;
        let expected = f5_digest(<Self as CanonicalBitcoinCodec>::KIND, &input[..prelude_len]);
        if expected != outbound_digest {
            return Err(CodecError::DigestMismatch);
        }
        Ok(Self {
            binding_digest,
            participant_id,
            public_nonce_digest,
            partial_signature,
            outbound_digest,
        })
    }
}

// ─── PreSignatureEnvelopeV1 ─────────────────────────────────────────────

impl EnvelopePrelude for PreSignatureEnvelopeV1 {
    const KIND: u16 = KIND_PRE_SIGNATURE;

    fn encode_prelude(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.binding_digest);
        out.extend_from_slice(&self.pre_signature.0);
        out.push(self.nonce_parity as u8);
        out.extend_from_slice(self.adaptor_point.as_bytes());
        out.extend_from_slice(&self.tap_sighash.0);
    }
}

impl CanonicalBitcoinCodec for PreSignatureEnvelopeV1 {
    const KIND: u16 = KIND_PRE_SIGNATURE;
    const MAX_ENCODED_LEN: usize = HEADER_LEN + 32 + 64 + 1 + 33 + 32 + 32;

    fn encode_canonical(&self, out: &mut Vec<u8>) -> Result<(), CodecError> {
        let mut s_half = [0u8; 32];
        s_half.copy_from_slice(&self.pre_signature.0[32..64]);
        if !crate::scalar::is_below_order(&s_half) {
            return Err(CodecError::InvalidField {
                field: "pre_signature",
            });
        }
        if envelope_digest(self) != self.outbound_digest {
            return Err(CodecError::DigestMismatch);
        }
        encode_header(out, <Self as CanonicalBitcoinCodec>::KIND);
        self.encode_prelude(out);
        out.extend_from_slice(&self.outbound_digest);
        Ok(())
    }

    fn decode_canonical(input: &[u8]) -> Result<Self, CodecError> {
        check_cap(input, Self::MAX_ENCODED_LEN)?;
        let mut r = ByteReader::new(input);
        decode_header(&mut r, <Self as CanonicalBitcoinCodec>::KIND)?;
        let binding_digest = r.take_array::<32>()?;
        let pre_signature = BtcAdaptorPreSignatureV1(r.take_array::<64>()?);
        let mut s_half = [0u8; 32];
        s_half.copy_from_slice(&pre_signature.0[32..64]);
        if !crate::scalar::is_below_order(&s_half) {
            return Err(CodecError::InvalidField {
                field: "pre_signature",
            });
        }
        let nonce_parity = NonceParityV1::from_u8(r.take_u8()?, "nonce_parity")?;
        let adaptor_point = AdaptorPointV1::from_bytes(r.take_array::<33>()?)?;
        let tap_sighash = TapSighashV1(r.take_array::<32>()?);
        let outbound_digest = r.take_array::<32>()?;
        r.finish()?;
        let prelude_len = input.len() - 32;
        let expected = f5_digest(<Self as CanonicalBitcoinCodec>::KIND, &input[..prelude_len]);
        if expected != outbound_digest {
            return Err(CodecError::DigestMismatch);
        }
        Ok(Self {
            binding_digest,
            pre_signature,
            nonce_parity,
            adaptor_point,
            tap_sighash,
            outbound_digest,
        })
    }
}
