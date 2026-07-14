//! dom-shield — property tests for Slate serialization invariants.
//!
//! Properties:
//!   * roundtrip: for any structurally-valid slate, decode(encode(x)) == x;
//!   * no-panic-on-garbage: arbitrary bytes prefixed with a valid version
//!     never panic the parser (Ok/Err only);
//!   * commitment-list length bound: a u32 count above MAX_INPUTS_PER_TX is
//!     rejected by read_commitment_list (cap-before-alloc, see comment below).

use dom_core::MAX_INPUTS_PER_TX;
use dom_serialization::{DomDeserialize, DomSerialize};
use dom_tx::slate::{OutputCommitmentAndProof, Slate, CURRENT_SLATE_VERSION};

use dom_crypto::pedersen::Commitment;
use dom_crypto::{bp2_prove, BlindingFactor, PartialSig, PublicKey, RangeProof, SecretKey};
use proptest::prelude::*;

// Map any byte into a band [1, 64] so `[b; 32]` is always a small, in-range,
// non-zero secp256k1 scalar (`[64; 32]` << curve order). Keeps generated keys
// distinct enough for roundtrip while guaranteeing valid scalar construction.
fn safe_byte(b: u8) -> u8 {
    (b % 64) + 1
}

fn commitment(value: u64, blinding_byte: u8) -> Commitment {
    let blinding = BlindingFactor::from_bytes([safe_byte(blinding_byte); 32]).unwrap();
    Commitment::commit(value, &blinding)
}

fn output(value: u64, blinding_byte: u8) -> OutputCommitmentAndProof {
    let blinding = BlindingFactor::from_bytes([safe_byte(blinding_byte); 32]).unwrap();
    let (proof_bytes, commitment_bytes) = bp2_prove(value.max(1), &blinding).unwrap();
    OutputCommitmentAndProof {
        commitment: Commitment::from_compressed_bytes(&commitment_bytes).unwrap(),
        proof: RangeProof::from_bytes(proof_bytes).unwrap(),
    }
}

fn public_key(secret_byte: u8) -> PublicKey {
    SecretKey::from_bytes(&[safe_byte(secret_byte); 32])
        .unwrap()
        .public_key()
}

fn partial_sig(scalar_byte: u8) -> PartialSig {
    PartialSig::from_bytes(&[safe_byte(scalar_byte); 32]).unwrap()
}

prop_compose! {
    fn arb_slate()(
        chain_id in any::<[u8; 32]>(),
        amount in any::<u64>(),
        fee in any::<u64>(),
        lock_height in any::<u64>(),
        n_inputs in 0usize..4,
        in_byte in 1u8..=254,
        has_change in any::<bool>(),
        change_byte in 1u8..=254,
        excess_byte in 1u8..=254,
        nonce_byte in 1u8..=254,
        offset in any::<[u8; 32]>(),
        has_recip_out in any::<bool>(),
        recip_byte in 1u8..=254,
        has_recip_excess in any::<bool>(),
        has_recip_nonce in any::<bool>(),
        has_sender_sig in any::<bool>(),
        sender_sig_byte in 1u8..=254,
        has_recip_sig in any::<bool>(),
        recip_sig_byte in 1u8..=254,
    ) -> Slate {
        let sender_inputs = (0..n_inputs)
            .map(|i| commitment(1_000 + i as u64, in_byte.wrapping_add(i as u8).max(1)))
            .collect();
        Slate {
            version: CURRENT_SLATE_VERSION,
            chain_id,
            amount,
            fee,
            lock_height,
            sender_inputs,
            sender_change_output: has_change.then(|| output(1_000, change_byte)),
            sender_public_excess: public_key(excess_byte),
            sender_public_nonce: public_key(nonce_byte),
            sender_offset_contribution: offset,
            recipient_output: has_recip_out.then(|| output(2_000, recip_byte)),
            recipient_public_excess: has_recip_excess.then(|| public_key(recip_byte)),
            recipient_public_nonce: has_recip_nonce.then(|| public_key(nonce_byte)),
            sender_partial_sig: has_sender_sig.then(|| partial_sig(sender_sig_byte)),
            recipient_partial_sig: has_recip_sig.then(|| partial_sig(recip_sig_byte)),
            sender_change_recovery_capsule: Vec::new(),
            recipient_recovery_capsule: Vec::new(),
        }
    }
}

proptest! {
    /// Roundtrip invariant over the full structural space of valid slates.
    #[test]
    fn prop_slate_roundtrip(slate in arb_slate()) {
        let bytes = slate.to_bytes().unwrap();
        let decoded = Slate::from_bytes(&bytes).unwrap();
        prop_assert_eq!(decoded.clone(), slate);
        // canonical re-encode
        prop_assert_eq!(decoded.to_bytes().unwrap(), bytes);
    }

    /// Arbitrary bytes never panic the parser.
    #[test]
    fn prop_arbitrary_bytes_no_panic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = Slate::from_bytes(&data);
    }

    /// DoS / cap-before-alloc: a sender_inputs u32 count above
    /// MAX_INPUTS_PER_TX (255) must be REJECTED before any large allocation.
    ///
    /// `read_commitment_list` reads the u32 count, checks `count >
    /// MAX_INPUTS_PER_TX` and returns Err BEFORE `Vec::with_capacity(count)`.
    /// So an attacker cannot drive a multi-GB allocation from a 4-byte count.
    /// We craft a header declaring a huge count with no payload and assert a
    /// clean Err with no OOM. This is the behavioral half of the
    /// "bounded-by-construction" claim recorded in the report.
    #[test]
    fn prop_oversized_input_count_rejected(count in (MAX_INPUTS_PER_TX as u32 + 1)..=u32::MAX) {
        // Minimal valid header up to the sender_inputs count.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u16.to_le_bytes());      // version
        bytes.extend_from_slice(&[0u8; 32]);               // chain_id
        bytes.extend_from_slice(&0u64.to_le_bytes());      // amount
        bytes.extend_from_slice(&0u64.to_le_bytes());      // fee
        bytes.extend_from_slice(&0u64.to_le_bytes());      // lock_height
        bytes.extend_from_slice(&count.to_le_bytes());     // sender_inputs count (oversized)
        // No commitment payload follows.
        let res = Slate::from_bytes(&bytes);
        prop_assert!(res.is_err(), "oversized input count {} must be rejected", count);
    }
}
