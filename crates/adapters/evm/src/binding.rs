//! Canonical §1 binding / `lockId` derivation, plus EVM address derivation.
//!
//! # I15 — this module is NOT a DOM primitive
//!
//! This module uses secp256k1 (via `k256`) for exactly one purpose: to compute
//! the *Ethereum account address* of a point, i.e. `address(P) = keccak256(
//! uncompressed(P)[1..65])[12..32]`. That is an **EVM-side** notion. The
//! `ConditionLockV2` contract stores `adaptorAddress = address(T)` and its
//! `claim(t)` recovers `address(t·G)` with `ecrecover`; this adapter has to be
//! able to reproduce the same value locally in order to validate what it sees
//! on chain and to fill in the lock terms it prepares.
//!
//! It is **not** a reimplementation of a DOM primitive, challenge or verifier.
//! Nothing here hashes a DOM transcript, builds a DOM challenge, verifies a DOM
//! signature or produces/consumes an adaptor pre-signature. All of that lives
//! exclusively behind `dom-leg`, which is the only crate allowed to touch the
//! pinned DOM authority. Concretely, the only cryptographic statements this
//! module makes are:
//!
//! 1. "the compressed point `T33` decodes to a valid, non-identity curve point,
//!    and its EVM address is `A`", and
//! 2. "the scalar `t` is canonical in `[1, n-1]` and `address(t·G)` is `A`".
//!
//! Both are statements *about the EVM contract's acceptance rule*, which is the
//! adapter's job to mirror. If either statement were used to accept or produce
//! DOM-side material, that would be an I15 violation; this crate never does so
//! and has no dependency that would let it.
//!
//! # Byte-exactness requirement
//!
//! Every derivation here must be byte-identical to the Solidity library. The
//! encoding is plain `abi.encode` over static types, so it is a concatenation
//! of 32-byte words with no offsets — see [`crate::abi`]. The cross-language
//! vector file (`contracts/test/vectors/f3_vectors.json`) is the proof.

use counterparty_api::AdapterError;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
// `PrimeField` brings `Field` (and therefore `is_zero`) into scope.
use k256::elliptic_curve::PrimeField;
use k256::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar};

use crate::abi::{
    concat_words, keccak256, word_address, word_bytes32, word_u16, word_u256, word_u64, word_u8,
    Word,
};
use crate::error::Result;

/// Domain-separation preimage for the binding hash.
pub const BINDING_DOMAIN_PREIMAGE: &str = "DOM-Interop/ConditionLockV2/binding";
/// Domain-separation preimage for the `lockId` hash.
pub const LOCKID_DOMAIN_PREIMAGE: &str = "DOM-Interop/ConditionLockV2/lockId";
/// Frozen binding version. Bumping it changes every `binding` and every
/// `lockId`, and is therefore a protocol break, not a refactor.
pub const BINDING_VERSION: u16 = 2;

/// Order of the secp256k1 group, big-endian. Reproduced here only to document
/// the canonicity window `1 <= t <= n-1` that the contract enforces; the actual
/// range check is done by `k256` (`Scalar::from_repr` rejects `t >= n`).
pub const SECP256K1_ORDER_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// `keccak256(BINDING_DOMAIN_PREIMAGE)`.
pub fn binding_domain() -> [u8; 32] {
    keccak256(BINDING_DOMAIN_PREIMAGE.as_bytes())
}

/// `keccak256(LOCKID_DOMAIN_PREIMAGE)`.
pub fn lockid_domain() -> [u8; 32] {
    keccak256(LOCKID_DOMAIN_PREIMAGE.as_bytes())
}

/// Direction of the settlement, as bound into the lock terms.
///
/// Bound into `binding`, so the two directions can never share a `lockId` even
/// with otherwise identical terms.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    /// DOM leg funds first; the EVM leg is claimed with `t`.
    DomToEvm,
    /// EVM leg funds first; the DOM leg is claimed with `t`.
    EvmToDom,
}

impl Direction {
    /// Wire value used by the contract (`uint8`).
    pub fn as_u8(self) -> u8 {
        match self {
            Self::DomToEvm => 0,
            Self::EvmToDom => 1,
        }
    }

    /// Strict decode; any other value fails closed (I10).
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Self::DomToEvm),
            1 => Ok(Self::EvmToDom),
            _ => Err(AdapterError::EvidenceInvalid),
        }
    }
}

/// The `LockTerms` ABI struct, in the exact field order the contract declares.
///
/// `amount` is kept as 32 big-endian bytes rather than a `u128` so that a
/// `uint256` coming back from the chain is never silently truncated; conversion
/// to the neutral `u128` happens explicitly and fails closed on overflow.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LockTerms {
    /// DOM `TrustedChainIdV1` (32 bytes).
    pub dom_chain_id: [u8; 32],
    /// `0` = DOM→EVM, `1` = EVM→DOM.
    pub direction: u8,
    /// DOM `session_id`.
    pub session_id: [u8; 32],
    /// DOM `terms_hash`.
    pub terms_hash: [u8; 32],
    /// keccak256 over the ordered roster encoding.
    pub participants_hash: [u8; 32],
    /// `address(0)` for the native contract, token address for the ERC-20 one.
    pub asset: [u8; 20],
    /// Exact locked amount in the asset's smallest unit, big-endian `uint256`.
    pub amount: [u8; 32],
    /// The only address allowed to `claim`.
    pub beneficiary: [u8; 20],
    /// `address(T)` where `T = t·G`.
    pub adaptor_address: [u8; 20],
    /// UNIX timestamp (`TimelockDomain::Timestamp`).
    pub deadline: u64,
}

/// Fixed canonical length of [`LockTerms::encode_fixed`].
pub const LOCK_TERMS_FIXED_LEN: usize = 32 + 1 + 32 + 32 + 32 + 20 + 32 + 20 + 20 + 8;

impl LockTerms {
    /// The ten ABI words of the struct, in declaration order.
    ///
    /// `LockTerms` contains only static types, so as a function argument it is
    /// encoded *inline* — there is no head offset. This is what makes
    /// `open(LockTerms)` calldata exactly `selector ++ 10 words`.
    pub fn abi_words(&self) -> [Word; 10] {
        [
            word_bytes32(self.dom_chain_id),
            word_u8(self.direction),
            word_bytes32(self.session_id),
            word_bytes32(self.terms_hash),
            word_bytes32(self.participants_hash),
            word_address(self.asset),
            word_u256(self.amount),
            word_address(self.beneficiary),
            word_address(self.adaptor_address),
            word_u64(self.deadline),
        ]
    }

    /// Compact fixed-width canonical encoding, used inside evidence frames.
    ///
    /// This is deliberately *not* the ABI encoding: evidence is a local frame
    /// and pays no reason to carry 22 zero bytes per address. It is fixed-width
    /// and therefore unambiguous, which is what canonicity requires.
    pub fn encode_fixed(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(LOCK_TERMS_FIXED_LEN);
        out.extend_from_slice(&self.dom_chain_id);
        out.push(self.direction);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.terms_hash);
        out.extend_from_slice(&self.participants_hash);
        out.extend_from_slice(&self.asset);
        out.extend_from_slice(&self.amount);
        out.extend_from_slice(&self.beneficiary);
        out.extend_from_slice(&self.adaptor_address);
        out.extend_from_slice(&self.deadline.to_be_bytes());
        out
    }

    /// Strict inverse of [`LockTerms::encode_fixed`]; the slice must be exactly
    /// [`LOCK_TERMS_FIXED_LEN`] bytes long.
    pub fn decode_fixed(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != LOCK_TERMS_FIXED_LEN {
            return Err(AdapterError::EvidenceInvalid);
        }
        let mut c = Cut { b: bytes, at: 0 };
        let terms = Self {
            dom_chain_id: c.take32()?,
            direction: c.take1()?,
            session_id: c.take32()?,
            terms_hash: c.take32()?,
            participants_hash: c.take32()?,
            asset: c.take20()?,
            amount: c.take32()?,
            beneficiary: c.take20()?,
            adaptor_address: c.take20()?,
            deadline: c.take_u64()?,
        };
        // Trailing bytes are never ignored (I14).
        if c.at != bytes.len() {
            return Err(AdapterError::EvidenceInvalid);
        }
        // The direction byte is the only non-opaque field; reject unknown values
        // here so that no downstream code has to guess (I10).
        Direction::from_u8(terms.direction)?;
        Ok(terms)
    }
}

/// Tiny cursor over a fixed-width frame. Bounds-checked, never panics.
pub(crate) struct Cut<'a> {
    pub(crate) b: &'a [u8],
    pub(crate) at: usize,
}

impl Cut<'_> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self.at.checked_add(n).ok_or(AdapterError::BoundsExceeded)?;
        let s = self
            .b
            .get(self.at..end)
            .ok_or(AdapterError::EvidenceInvalid)?;
        self.at = end;
        Ok(s)
    }
    pub(crate) fn take1(&mut self) -> Result<u8> {
        let s = self.take(1)?;
        s.first().copied().ok_or(AdapterError::EvidenceInvalid)
    }
    pub(crate) fn take20(&mut self) -> Result<[u8; 20]> {
        let s = self.take(20)?;
        let mut a = [0u8; 20];
        a.copy_from_slice(s);
        Ok(a)
    }
    pub(crate) fn take32(&mut self) -> Result<[u8; 32]> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    pub(crate) fn take_u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        let mut a = [0u8; 2];
        a.copy_from_slice(s);
        Ok(u16::from_be_bytes(a))
    }
    pub(crate) fn take_u32(&mut self) -> Result<u32> {
        let s = self.take(4)?;
        let mut a = [0u8; 4];
        a.copy_from_slice(s);
        Ok(u32::from_be_bytes(a))
    }
    pub(crate) fn take_u64(&mut self) -> Result<u64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }
}

/// `binding = keccak256(abi.encode(BINDING_DOMAIN, BINDING_VERSION,
/// block.chainid, address(this), ...terms))`.
///
/// Byte-identical to `LockBinding.deriveBinding` in Solidity.
pub fn derive_binding(chain_id: u64, contract: &[u8; 20], terms: &LockTerms) -> Result<[u8; 32]> {
    let t = terms.abi_words();
    let words: [Word; 14] = [
        word_bytes32(binding_domain()),
        word_u16(BINDING_VERSION),
        // `block.chainid` is a `uint256`; every real chain id fits in 64 bits,
        // and the word layout is identical either way.
        word_u64(chain_id),
        word_address(*contract),
        t[0],
        t[1],
        t[2],
        t[3],
        t[4],
        t[5],
        t[6],
        t[7],
        t[8],
        t[9],
    ];
    Ok(keccak256(&concat_words(&words)?))
}

/// `lockId = keccak256(abi.encode(LOCKID_DOMAIN, BINDING_VERSION, binding, funder))`.
///
/// `funder` is `msg.sender` at `open`, which is what makes `lockId`
/// un-squattable: a third party cannot pre-open somebody else's identifier
/// because their own address is hashed in.
pub fn derive_lock_id(binding: &[u8; 32], funder: &[u8; 20]) -> Result<[u8; 32]> {
    let words: [Word; 4] = [
        word_bytes32(lockid_domain()),
        word_u16(BINDING_VERSION),
        word_bytes32(*binding),
        word_address(*funder),
    ];
    Ok(keccak256(&concat_words(&words)?))
}

/// Convenience: both derivations at once.
pub fn derive_binding_and_lock_id(
    chain_id: u64,
    contract: &[u8; 20],
    terms: &LockTerms,
    funder: &[u8; 20],
) -> Result<([u8; 32], [u8; 32])> {
    let b = derive_binding(chain_id, contract, terms)?;
    let l = derive_lock_id(&b, funder)?;
    Ok((b, l))
}

// ---------------------------------------------------------------------------
// EVM address derivation (see the I15 note in the module header)
// ---------------------------------------------------------------------------

fn address_of_affine(p: &AffinePoint) -> Result<[u8; 20]> {
    let unc = p.to_encoded_point(false);
    let bytes = unc.as_bytes();
    // The identity encodes as a single zero byte; a valid affine point encodes
    // as `0x04 || X(32) || Y(32)`. Anything else is rejected.
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(AdapterError::PreconditionUnsatisfied);
    }
    let h = keccak256(&bytes[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    Ok(a)
}

/// Only tags SEC1 defines for a *compressed* point. Deliberately narrower than
/// what a general SEC1 decoder accepts.
const SEC1_COMPRESSED_TAGS: [u8; 2] = [0x02, 0x03];

/// EVM address of a compressed SEC1 point `T = t·G` (33 bytes).
///
/// Fails closed on a malformed prefix, an off-curve point, or the identity.
///
/// # Only `0x02` / `0x03` are accepted
///
/// SEC1 also defines a 33-byte *compact* encoding with tag `0x05`, and general
/// decoders (including `k256`'s) accept it. This function rejects it. The
/// adaptor point is produced by the DOM leg as a compressed point, so accepting
/// a second 33-byte spelling would buy nothing and cost encoding malleability:
/// two distinct byte strings that a peer could substitute for one another while
/// both "being the adaptor point". One encoding, one meaning.
pub fn adaptor_address(t_compressed: &[u8; 33]) -> Result<[u8; 20]> {
    if !SEC1_COMPRESSED_TAGS.contains(&t_compressed[0]) {
        return Err(AdapterError::PreconditionUnsatisfied);
    }
    let ep = EncodedPoint::from_bytes(t_compressed.as_slice())
        .map_err(|_| AdapterError::PreconditionUnsatisfied)?;
    let maybe: Option<AffinePoint> = AffinePoint::from_encoded_point(&ep).into();
    let p = maybe.ok_or(AdapterError::PreconditionUnsatisfied)?;
    address_of_affine(&p)
}

/// EVM address of `t·G` for a canonical scalar `t`.
///
/// Fails closed when `t == 0` or `t >= n`, which is exactly the window the
/// contract rejects (`require(t != 0 && t < N)`).
///
/// I6: `t` is never echoed. The error is a unit variant, and this function has
/// no logging and no `Debug` on the scalar.
pub fn adaptor_address_of_scalar(t: &[u8; 32]) -> Result<[u8; 20]> {
    let p = point_of_scalar(t)?;
    address_of_affine(&p)
}

fn point_of_scalar(t: &[u8; 32]) -> Result<AffinePoint> {
    let repr = FieldBytes::from(*t);
    let maybe: Option<Scalar> = Scalar::from_repr(repr).into();
    let s = maybe.ok_or(AdapterError::PreconditionUnsatisfied)?;
    if bool::from(s.is_zero()) {
        return Err(AdapterError::PreconditionUnsatisfied);
    }
    Ok((ProjectivePoint::GENERATOR * s).to_affine())
}

/// Compressed SEC1 encoding of `T = t·G`.
///
/// Provided so that a caller holding `t` (the claiming side, in its own
/// process) can check the point it published — and so that tests can build
/// consistent fixtures. This crate never *stores* a `t`.
pub fn adaptor_point_of_scalar(t: &[u8; 32]) -> Result<[u8; 33]> {
    let p = point_of_scalar(t)?;
    let ep = p.to_encoded_point(true);
    let bytes = ep.as_bytes();
    if bytes.len() != 33 {
        return Err(AdapterError::PreconditionUnsatisfied);
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}

/// True when `t` is canonical for the contract: `0 < t < n`.
pub fn is_canonical_scalar(t: &[u8; 32]) -> bool {
    point_of_scalar(t).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> LockTerms {
        LockTerms {
            dom_chain_id: [0x11; 32],
            direction: 0,
            session_id: [0x22; 32],
            terms_hash: [0x33; 32],
            participants_hash: [0x44; 32],
            asset: [0u8; 20],
            amount: word_u128(1_000_000_000_000_000_000u128),
            beneficiary: [0x55; 20],
            adaptor_address: [0x66; 20],
            deadline: 1_800_000_000,
        }
    }

    fn word_u128(v: u128) -> [u8; 32] {
        crate::abi::word_u128(v)
    }

    #[test]
    fn domains_are_frozen() {
        // Golden values. If these ever move, every deployed lock id moves with
        // them, so this test is a tripwire, not a convenience.
        assert_eq!(
            binding_domain(),
            keccak256(b"DOM-Interop/ConditionLockV2/binding")
        );
        assert_eq!(
            lockid_domain(),
            keccak256(b"DOM-Interop/ConditionLockV2/lockId")
        );
        assert_ne!(binding_domain(), lockid_domain());
        assert_eq!(BINDING_VERSION, 2);
    }

    #[test]
    fn binding_preimage_is_fourteen_words() {
        // The whole point of `abi.encode` over static types: fixed 32-byte
        // words, no field-boundary ambiguity (anti-collision).
        let t = terms();
        let words = t.abi_words();
        assert_eq!(words.len(), 10);
        let all = concat_words(&words).expect("10 words");
        assert_eq!(all.len(), 320);
    }

    #[test]
    fn derivation_is_deterministic() {
        let t = terms();
        let a = derive_binding_and_lock_id(31337, &[0xAA; 20], &t, &[0xBB; 20]);
        let b = derive_binding_and_lock_id(31337, &[0xAA; 20], &t, &[0xBB; 20]);
        assert_eq!(a, b);
    }

    #[test]
    fn lock_id_is_bound_to_the_funder_anti_squatting() {
        let t = terms();
        let (_, l1) =
            derive_binding_and_lock_id(31337, &[0xAA; 20], &t, &[0x01; 20]).expect("derivation");
        let (_, l2) =
            derive_binding_and_lock_id(31337, &[0xAA; 20], &t, &[0x02; 20]).expect("derivation");
        assert_ne!(l1, l2, "same terms, different funder must not collide");
    }

    #[test]
    fn binding_is_bound_to_chain_and_contract_anti_replay() {
        let t = terms();
        let base = derive_binding(31337, &[0xAA; 20], &t).expect("derivation");
        assert_ne!(base, derive_binding(1337, &[0xAA; 20], &t).expect("d"));
        assert_ne!(base, derive_binding(31337, &[0xAB; 20], &t).expect("d"));
    }

    #[test]
    fn every_terms_field_changes_the_binding() {
        let base_terms = terms();
        let base = derive_binding(31337, &[0xAA; 20], &base_terms).expect("d");
        let mut variants = Vec::new();

        let mut v = base_terms;
        v.dom_chain_id[0] ^= 1;
        variants.push(("domChainId", v));
        let mut v = base_terms;
        v.direction = 1;
        variants.push(("direction", v));
        let mut v = base_terms;
        v.session_id[31] ^= 1;
        variants.push(("sessionId", v));
        let mut v = base_terms;
        v.terms_hash[7] ^= 1;
        variants.push(("termsHash", v));
        let mut v = base_terms;
        v.participants_hash[3] ^= 1;
        variants.push(("participantsHash", v));
        let mut v = base_terms;
        v.asset[19] = 1;
        variants.push(("asset", v));
        let mut v = base_terms;
        v.amount[31] ^= 1;
        variants.push(("amount", v));
        let mut v = base_terms;
        v.beneficiary[0] ^= 1;
        variants.push(("beneficiary", v));
        let mut v = base_terms;
        v.adaptor_address[0] ^= 1;
        variants.push(("adaptorAddress", v));
        let mut v = base_terms;
        v.deadline += 1;
        variants.push(("deadline", v));

        for (name, v) in variants {
            let d = derive_binding(31337, &[0xAA; 20], &v).expect("d");
            assert_ne!(base, d, "flipping {name} did not change the binding");
        }
    }

    #[test]
    fn lock_terms_fixed_codec_round_trips_and_rejects_slop() {
        let t = terms();
        let enc = t.encode_fixed();
        assert_eq!(enc.len(), LOCK_TERMS_FIXED_LEN);
        assert_eq!(LockTerms::decode_fixed(&enc), Ok(t));

        let mut short = enc.clone();
        short.pop();
        assert_eq!(
            LockTerms::decode_fixed(&short),
            Err(AdapterError::EvidenceInvalid)
        );
        let mut long = enc.clone();
        long.push(0);
        assert_eq!(
            LockTerms::decode_fixed(&long),
            Err(AdapterError::EvidenceInvalid),
            "I14: trailing bytes must never be ignored"
        );

        let mut bad_dir = enc;
        bad_dir[32] = 9;
        assert_eq!(
            LockTerms::decode_fixed(&bad_dir),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn address_of_scalar_one_is_the_generator_address() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let a = adaptor_address_of_scalar(&one).expect("scalar 1 is canonical");
        // address(G) is a well-known constant.
        let expected: [u8; 20] = [
            0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2,
            0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf,
        ];
        assert_eq!(a, expected);
    }

    #[test]
    fn address_of_point_and_of_scalar_agree() {
        for seed in 1u8..16 {
            let mut t = [0u8; 32];
            t[31] = seed;
            t[0] = seed;
            let p = adaptor_point_of_scalar(&t).expect("canonical");
            assert_eq!(
                adaptor_address(&p),
                adaptor_address_of_scalar(&t),
                "point path and scalar path disagree"
            );
        }
    }

    #[test]
    fn non_canonical_scalars_fail_closed() {
        assert_eq!(
            adaptor_address_of_scalar(&[0u8; 32]),
            Err(AdapterError::PreconditionUnsatisfied),
            "t == 0 must be rejected"
        );
        assert_eq!(
            adaptor_address_of_scalar(&SECP256K1_ORDER_BE),
            Err(AdapterError::PreconditionUnsatisfied),
            "t == n must be rejected"
        );
        assert_eq!(
            adaptor_address_of_scalar(&[0xFF; 32]),
            Err(AdapterError::PreconditionUnsatisfied),
            "t > n must be rejected"
        );
        let mut n_minus_1 = SECP256K1_ORDER_BE;
        n_minus_1[31] -= 1;
        assert!(
            adaptor_address_of_scalar(&n_minus_1).is_ok(),
            "t == n-1 must be accepted"
        );
        assert!(is_canonical_scalar(&n_minus_1));
        assert!(!is_canonical_scalar(&SECP256K1_ORDER_BE));
    }

    #[test]
    fn malformed_points_fail_closed() {
        // All-zero: tag 0x00 is the identity encoding, never a valid `T`.
        assert_eq!(
            adaptor_address(&[0u8; 33]),
            Err(AdapterError::PreconditionUnsatisfied),
            "identity/zero prefix must be rejected"
        );
        // x above the field modulus: not a coordinate at all.
        let mut overflow = [0xFFu8; 33];
        overflow[0] = 0x02;
        assert_eq!(
            adaptor_address(&overflow),
            Err(AdapterError::PreconditionUnsatisfied),
            "x >= p must be rejected"
        );
        // A valid field element that is not an x-coordinate of any curve point
        // (x = 5: 5^3 + 7 = 132 is a non-residue mod p).
        let mut off_curve = [0u8; 33];
        off_curve[0] = 0x03;
        off_curve[32] = 5;
        assert_eq!(
            adaptor_address(&off_curve),
            Err(AdapterError::PreconditionUnsatisfied),
            "off-curve x must be rejected"
        );
        // Unknown SEC1 tag.
        let mut wrong_prefix = [0x11u8; 33];
        wrong_prefix[0] = 0x09;
        assert_eq!(
            adaptor_address(&wrong_prefix),
            Err(AdapterError::PreconditionUnsatisfied),
            "unknown SEC1 tag must be rejected"
        );
    }

    #[test]
    fn the_sec1_compact_encoding_is_rejected() {
        // Tag 0x05 is the SEC1 *compact* form. `k256` decodes it happily, which
        // would give the adaptor point two valid 33-byte spellings. We take the
        // narrow reading: compressed means 0x02 or 0x03, nothing else.
        let mut one = [0u8; 32];
        one[31] = 1;
        let compressed = adaptor_point_of_scalar(&one).expect("canonical");
        let mut compact = compressed;
        compact[0] = 0x05;
        assert!(
            adaptor_address(&compressed).is_ok(),
            "the compressed spelling must still work"
        );
        assert_eq!(
            adaptor_address(&compact),
            Err(AdapterError::PreconditionUnsatisfied),
            "the compact spelling must be refused: one encoding, one meaning"
        );
    }

    #[test]
    fn direction_round_trips_and_rejects_unknown() {
        assert_eq!(Direction::from_u8(0), Ok(Direction::DomToEvm));
        assert_eq!(Direction::from_u8(1), Ok(Direction::EvmToDom));
        assert_eq!(Direction::DomToEvm.as_u8(), 0);
        assert_eq!(Direction::EvmToDom.as_u8(), 1);
        for v in 2u8..=255 {
            assert_eq!(Direction::from_u8(v), Err(AdapterError::EvidenceInvalid));
        }
    }
}

/// Frozen witness of the `point_of_scalar` path.
///
/// Built BEFORE the `generic-array` deprecation migration and committed on
/// its own, so the migration is measured against the behaviour of the code
/// as it stood. Fixed scalars only; nothing reads the clock or an RNG.
#[cfg(test)]
mod frozen_scalar_vectors {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `t = 1` — the generator itself, the sharpest fixture available.
    #[test]
    fn generator_point_and_address_are_frozen() {
        let mut t = [0_u8; 32];
        t[31] = 1;
        assert_eq!(
            hex(&adaptor_point_of_scalar(&t).expect("t = 1 is canonical")),
            GENERATOR_SEC1
        );
        assert_eq!(
            hex(&adaptor_address_of_scalar(&t).expect("t = 1 is canonical")),
            GENERATOR_ADDRESS
        );
    }

    /// An arbitrary fixed scalar, to catch a change that happens to leave the
    /// generator alone.
    #[test]
    fn fixed_scalar_point_and_address_are_frozen() {
        let mut t = [0_u8; 32];
        for (i, byte) in t.iter_mut().enumerate() {
            *byte = 0x10_u8.wrapping_add(i as u8);
        }
        assert_eq!(
            hex(&adaptor_point_of_scalar(&t).expect("the fixture is canonical")),
            FIXED_SEC1
        );
        assert_eq!(
            hex(&adaptor_address_of_scalar(&t).expect("the fixture is canonical")),
            FIXED_ADDRESS
        );
    }

    /// The refusal window the contract enforces is unchanged: `t = 0` is not
    /// canonical, and neither is `t = n`.
    #[test]
    fn the_refusal_window_is_unchanged() {
        assert!(!is_canonical_scalar(&[0_u8; 32]));
        let n = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        assert!(!is_canonical_scalar(&n));
    }

    const GENERATOR_SEC1: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const GENERATOR_ADDRESS: &str = "7e5f4552091a69125d5dfcb7b8c2659029395bdf";
    const FIXED_SEC1: &str = "023799f7f28db16bfffbbfd700814fe94eef8f33479b773b9a1f515e81b4116d2b";
    const FIXED_ADDRESS: &str = "8526a302de2b8cda37e78da6d305554f23d3f40e";
}
