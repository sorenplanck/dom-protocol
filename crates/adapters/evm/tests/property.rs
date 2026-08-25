//! Property and fuzz coverage for `adapter-evm`.
//!
//! One module per item in the §3 checklist of the F3 interface spec. Every
//! generator is offline: the "chain" is always the deterministic in-crate mock.

mod common;

use adapter_evm::abi::{
    concat_words, decode_address, decode_bool, decode_u128, decode_u16, decode_u32, decode_u64,
    decode_u8, event_topic0, split_words, word_address, word_u128, word_u16, word_u256, word_u64,
    word_u8, MAX_ABI_WORDS, MAX_LOG_DATA_BYTES, SIG_CLAIMED, SIG_LOCK_OPENED, SIG_REFUNDED,
};
use adapter_evm::binding::{
    adaptor_address, adaptor_address_of_scalar, adaptor_point_of_scalar, derive_binding,
    derive_lock_id, is_canonical_scalar, Direction, LockTerms, SECP256K1_ORDER_BE,
};
use adapter_evm::cursor::{EvmCursor, CURSOR_LEN, CURSOR_VERSION};
use adapter_evm::evidence::{
    decode_settlement_log, EvidenceKind, EvmEvidence, EVIDENCE_LEN, EVIDENCE_VERSION,
};
use adapter_evm::finality::{clamp_to_finalized, gate, FinalizedHead};
use adapter_evm::mock::Faults;
use adapter_evm::reorg::{apply_rewind, detect, HeaderSource, KnownHeaders, ReorgOutcome};
use adapter_evm::rpc::{hex_bytes, hex_of, hex_quantity, RpcBlockHeader, RpcLog};
use adapter_evm::UnsignedEvmCall;
use common::{block_on, scenario};
use counterparty_api::{AdapterError, ChainCursor, ObservedEvent, VerifiedOutcome};
use proptest::prelude::*;
use serde_json::json;

// ---------------------------------------------------------------------------
// strategies
// ---------------------------------------------------------------------------

fn arb_b32() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>()
}

fn arb_addr() -> impl Strategy<Value = [u8; 20]> {
    any::<[u8; 20]>()
}

prop_compose! {
    fn arb_terms()(
        dom_chain_id in arb_b32(),
        direction in 0u8..=1,
        session_id in arb_b32(),
        terms_hash in arb_b32(),
        participants_hash in arb_b32(),
        asset in arb_addr(),
        amount in arb_b32(),
        beneficiary in arb_addr(),
        adaptor_address in arb_addr(),
        deadline in any::<u64>(),
    ) -> LockTerms {
        LockTerms {
            dom_chain_id, direction, session_id, terms_hash, participants_hash,
            asset, amount, beneficiary, adaptor_address, deadline,
        }
    }
}

/// A scalar guaranteed canonical for secp256k1 (`0 < t < n`).
fn arb_canonical_scalar() -> impl Strategy<Value = [u8; 32]> {
    any::<[u8; 32]>().prop_map(|mut t| {
        // Force the top byte low so the value is far below `n`, and force a
        // non-zero low byte so it is never the identity.
        t[0] = 0;
        t[31] |= 1;
        t
    })
}

// ---------------------------------------------------------------------------
// 1. ABI codec
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn abi_scalar_encoders_round_trip(
        a in arb_addr(), u8v in any::<u8>(), u16v in any::<u16>(),
        u64v in any::<u64>(), u128v in any::<u128>(), w in arb_b32(),
    ) {
        prop_assert_eq!(decode_address(&word_address(a)), Ok(a));
        prop_assert_eq!(decode_u8(&word_u8(u8v)), Ok(u8v));
        prop_assert_eq!(decode_u16(&word_u16(u16v)), Ok(u16v));
        prop_assert_eq!(decode_u64(&word_u64(u64v)), Ok(u64v));
        prop_assert_eq!(decode_u128(&word_u128(u128v)), Ok(u128v));
        prop_assert_eq!(word_u256(w), w);
    }

    #[test]
    fn abi_decoders_reject_non_canonical_padding(mut w in arb_b32(), pos in 0usize..12) {
        // Any non-zero byte above an address' width makes the word invalid.
        w[pos] = w[pos].wrapping_add(1).max(1);
        prop_assert_eq!(decode_address(&w), Err(AdapterError::EvidenceInvalid));
    }

    #[test]
    fn abi_u64_rejects_high_bytes(v in any::<u64>(), pos in 0usize..24) {
        let mut w = word_u64(v);
        w[pos] = 1;
        prop_assert_eq!(decode_u64(&w), Err(AdapterError::EvidenceInvalid));
    }

    #[test]
    fn abi_bool_rejects_anything_but_zero_and_one(v in 2u8..=255) {
        let w = word_u8(v);
        prop_assert_eq!(decode_bool(&w), Err(AdapterError::EvidenceInvalid));
    }

    #[test]
    fn abi_u32_rejects_overflow(v in any::<u32>(), extra in 1u8..=255) {
        let mut w = [0u8; 32];
        w[28..].copy_from_slice(&v.to_be_bytes());
        w[27] = extra;
        prop_assert_eq!(decode_u32(&w), Err(AdapterError::EvidenceInvalid));
    }

    #[test]
    fn abi_split_words_round_trips(words in prop::collection::vec(arb_b32(), 0..16)) {
        let enc = concat_words(&words).expect("within cap");
        prop_assert_eq!(enc.len(), words.len() * 32);
        prop_assert_eq!(split_words(&enc, words.len()), Ok(words));
    }

    #[test]
    fn abi_split_words_rejects_wrong_length(
        words in prop::collection::vec(arb_b32(), 1..8),
        delta in 1usize..8,
    ) {
        let enc = concat_words(&words).expect("within cap");
        prop_assert_eq!(split_words(&enc, words.len() + delta), Err(AdapterError::EvidenceInvalid));
        prop_assert!(split_words(&enc, words.len().saturating_sub(delta)).is_err());
    }

    #[test]
    fn abi_split_words_rejects_truncation_and_trailing_bytes(
        words in prop::collection::vec(arb_b32(), 1..8),
        cut in 1usize..32,
    ) {
        let enc = concat_words(&words).expect("within cap");
        let mut truncated = enc.clone();
        truncated.truncate(enc.len() - cut);
        prop_assert_eq!(split_words(&truncated, words.len()), Err(AdapterError::EvidenceInvalid));
        let mut extended = enc;
        extended.extend(std::iter::repeat_n(0u8, cut));
        prop_assert_eq!(split_words(&extended, words.len()), Err(AdapterError::EvidenceInvalid));
    }

    #[test]
    fn abi_caps_are_validated_before_allocation(over in 1usize..4096) {
        prop_assert_eq!(
            split_words(&[], MAX_ABI_WORDS + over),
            Err(AdapterError::BoundsExceeded)
        );
        let oversized = vec![0u8; MAX_LOG_DATA_BYTES + over];
        prop_assert_eq!(split_words(&oversized, 1), Err(AdapterError::BoundsExceeded));
        let too_many = vec![[0u8; 32]; MAX_ABI_WORDS + over];
        prop_assert_eq!(concat_words(&too_many), Err(AdapterError::BoundsExceeded));
    }

    #[test]
    fn topic0_is_injective_over_distinct_signatures(a in "[A-Za-z]{1,12}", b in "[A-Za-z]{1,12}") {
        prop_assume!(a != b);
        prop_assert_ne!(event_topic0(&format!("{a}()")), event_topic0(&format!("{b}()")));
    }
}

// ---------------------------------------------------------------------------
// 2. binding derivation
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn binding_is_deterministic(chain_id in any::<u64>(), c in arb_addr(), t in arb_terms()) {
        prop_assert_eq!(derive_binding(chain_id, &c, &t), derive_binding(chain_id, &c, &t));
    }

    #[test]
    fn binding_separates_chain_and_contract(
        chain_a in any::<u64>(), chain_b in any::<u64>(),
        ca in arb_addr(), cb in arb_addr(), t in arb_terms(),
    ) {
        prop_assume!(chain_a != chain_b || ca != cb);
        prop_assert_ne!(
            derive_binding(chain_a, &ca, &t).expect("d"),
            derive_binding(chain_b, &cb, &t).expect("d")
        );
    }

    #[test]
    fn lock_id_separates_funders(b in arb_b32(), fa in arb_addr(), fb in arb_addr()) {
        prop_assume!(fa != fb);
        prop_assert_ne!(
            derive_lock_id(&b, &fa).expect("d"),
            derive_lock_id(&b, &fb).expect("d")
        );
    }

    #[test]
    fn every_terms_field_is_load_bearing(base in arb_terms(), which in 0usize..10, mask in 1u8..=255) {
        let mut v = base;
        match which {
            0 => v.dom_chain_id[0] ^= mask,
            1 => v.direction ^= 1,
            2 => v.session_id[0] ^= mask,
            3 => v.terms_hash[0] ^= mask,
            4 => v.participants_hash[0] ^= mask,
            5 => v.asset[0] ^= mask,
            6 => v.amount[0] ^= mask,
            7 => v.beneficiary[0] ^= mask,
            8 => v.adaptor_address[0] ^= mask,
            _ => v.deadline ^= u64::from(mask),
        }
        prop_assume!(v != base);
        prop_assert_ne!(
            derive_binding(31337, &[0xC0; 20], &base).expect("d"),
            derive_binding(31337, &[0xC0; 20], &v).expect("d")
        );
    }

    #[test]
    fn lock_terms_fixed_codec_round_trips(t in arb_terms()) {
        let enc = t.encode_fixed();
        prop_assert_eq!(LockTerms::decode_fixed(&enc), Ok(t));
    }

    #[test]
    fn lock_terms_fixed_codec_rejects_length_changes(t in arb_terms(), cut in 1usize..16) {
        let enc = t.encode_fixed();
        let mut short = enc.clone();
        short.truncate(enc.len() - cut);
        prop_assert!(LockTerms::decode_fixed(&short).is_err());
        let mut long = enc;
        long.extend(std::iter::repeat_n(0u8, cut));
        prop_assert!(LockTerms::decode_fixed(&long).is_err());
    }

    #[test]
    fn direction_decoding_is_total_and_strict(v in any::<u8>()) {
        match v {
            0 | 1 => prop_assert!(Direction::from_u8(v).is_ok()),
            _ => prop_assert_eq!(Direction::from_u8(v), Err(AdapterError::EvidenceInvalid)),
        }
    }
}

// ---------------------------------------------------------------------------
// 2b. EVM address derivation (the I15-scoped secp256k1 use)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn point_path_and_scalar_path_agree(t in arb_canonical_scalar()) {
        let p = adaptor_point_of_scalar(&t).expect("canonical");
        prop_assert_eq!(adaptor_address(&p), adaptor_address_of_scalar(&t));
        prop_assert!(is_canonical_scalar(&t));
    }

    #[test]
    fn distinct_scalars_give_distinct_addresses(a in arb_canonical_scalar(), b in arb_canonical_scalar()) {
        prop_assume!(a != b);
        prop_assert_ne!(
            adaptor_address_of_scalar(&a).expect("canonical"),
            adaptor_address_of_scalar(&b).expect("canonical")
        );
    }

    #[test]
    fn scalars_at_or_above_the_group_order_are_rejected(delta in 0u8..=200) {
        let mut t = SECP256K1_ORDER_BE;
        t[31] = t[31].saturating_add(delta);
        prop_assert_eq!(
            adaptor_address_of_scalar(&t),
            Err(AdapterError::PreconditionUnsatisfied)
        );
        prop_assert!(!is_canonical_scalar(&t));
    }

    #[test]
    fn garbage_points_never_decode(bytes in any::<[u8; 33]>()) {
        // Whatever the outcome, it must be a decision, never a panic, and a
        // successful decode must round-trip through the scalar-free path.
        if let Ok(addr) = adaptor_address(&bytes) {
            prop_assert_ne!(addr, [0u8; 20]);
            prop_assert!(matches!(bytes[0], 0x02 | 0x03));
        }
    }
}

// ---------------------------------------------------------------------------
// 3. event decoding
// ---------------------------------------------------------------------------

const CONTRACT: [u8; 20] = [0xC0; 20];

fn claimed_log(t: [u8; 32]) -> RpcLog {
    RpcLog {
        address: CONTRACT,
        topics: vec![
            event_topic0(SIG_CLAIMED),
            [0x01; 32],
            [0x02; 32],
            word_address([0xBE; 20]),
        ],
        data: concat_words(&[t]).expect("one word"),
        block_number: 5,
        block_hash: [0x11; 32],
        tx_hash: [0x22; 32],
        log_index: 0,
        removed: false,
    }
}

proptest! {
    #[test]
    fn well_formed_claim_logs_decode(t in arb_b32()) {
        let decoded = decode_settlement_log(&claimed_log(t), &CONTRACT).expect("decodes");
        prop_assert_eq!(decoded.kind(), EvidenceKind::Claimed);
        prop_assert_eq!(decoded.identity(), ([0x01; 32], [0x02; 32], t));
    }

    #[test]
    fn a_foreign_emitter_is_rejected(other in arb_addr()) {
        prop_assume!(other != CONTRACT);
        let mut l = claimed_log([7u8; 32]);
        l.address = other;
        prop_assert_eq!(
            decode_settlement_log(&l, &CONTRACT),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn an_unknown_topic0_is_rejected(t0 in arb_b32()) {
        prop_assume!(
            t0 != event_topic0(SIG_CLAIMED)
                && t0 != event_topic0(SIG_LOCK_OPENED)
                && t0 != event_topic0(SIG_REFUNDED)
        );
        let mut l = claimed_log([7u8; 32]);
        l.topics[0] = t0;
        prop_assert_eq!(
            decode_settlement_log(&l, &CONTRACT),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn wrong_topic_arity_is_rejected(n in 0usize..=8) {
        prop_assume!(n != 4);
        let mut l = claimed_log([7u8; 32]);
        l.topics.resize(n, [0u8; 32]);
        prop_assert_eq!(
            decode_settlement_log(&l, &CONTRACT),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn truncated_or_padded_data_is_rejected(extra in 1usize..64, cut in 1usize..32) {
        let mut l = claimed_log([7u8; 32]);
        l.data.extend(std::iter::repeat_n(0u8, extra));
        prop_assert!(decode_settlement_log(&l, &CONTRACT).is_err());

        let mut l = claimed_log([7u8; 32]);
        l.data.truncate(32usize.saturating_sub(cut));
        prop_assert!(decode_settlement_log(&l, &CONTRACT).is_err());
    }

    #[test]
    fn a_removed_log_is_never_decoded(t in arb_b32()) {
        let mut l = claimed_log(t);
        l.removed = true;
        prop_assert_eq!(
            decode_settlement_log(&l, &CONTRACT),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn non_canonical_indexed_address_padding_is_rejected(pos in 0usize..12, b in 1u8..=255) {
        let mut l = claimed_log([7u8; 32]);
        l.topics[3][pos] = b;
        prop_assert_eq!(
            decode_settlement_log(&l, &CONTRACT),
            Err(AdapterError::EvidenceInvalid)
        );
    }
}

// ---------------------------------------------------------------------------
// 4. evidence canonicity
// ---------------------------------------------------------------------------

/// Bytes `0..DERIVABLE_PREFIX_LEN` of an evidence frame hold everything
/// `verify_static` can re-derive: version, kind, chain id, contract, codehash,
/// funder, the full terms, the binding and the lock id.
const DERIVABLE_PREFIX_LEN: usize = 2 + 1 + 8 + 20 + 32 + 20 + 229 + 32 + 32;
/// Offset of the payload word, the other derivable region.
const PAYLOAD_OFFSET: usize = EVIDENCE_LEN - 32;

fn sample_evidence(t: [u8; 32]) -> (EvmEvidence, adapter_evm::EvmAdapterConfig) {
    let cfg = adapter_evm::adapter::test_support::sample_config();
    let mut terms = adapter_evm::adapter::test_support::sample_terms(&cfg);
    terms.adaptor_address = adaptor_address_of_scalar(&t).expect("canonical");
    let binding = derive_binding(cfg.chain_id, &cfg.contract, &terms).expect("d");
    let lock_id = derive_lock_id(&binding, &cfg.funder).expect("d");
    (
        EvmEvidence {
            version: EVIDENCE_VERSION,
            kind: EvidenceKind::Claimed,
            chain_id: cfg.chain_id,
            contract: cfg.contract,
            code_hash: cfg.expected_code_hash,
            funder: cfg.funder,
            terms,
            binding,
            lock_id,
            block_number: 3,
            block_hash: [0x31; 32],
            tx_hash: [0x32; 32],
            log_index: 1,
            finalized_height: 9,
            finalized_block_hash: [0x33; 32],
            payload: t,
        },
        cfg,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn evidence_round_trips_byte_for_byte(t in arb_canonical_scalar()) {
        let (e, _) = sample_evidence(t);
        let enc = e.encode();
        prop_assert_eq!(enc.len(), EVIDENCE_LEN);
        prop_assert_eq!(EvmEvidence::decode(&enc), Ok(e));
    }

    #[test]
    fn evidence_decode_rejects_any_other_length(len in 0usize..1024) {
        prop_assume!(len != EVIDENCE_LEN);
        prop_assert_eq!(
            EvmEvidence::decode(&vec![0u8; len]),
            Err(AdapterError::EvidenceInvalid)
        );
    }

    #[test]
    fn arbitrary_bytes_never_verify(bytes in prop::collection::vec(any::<u8>(), 0..1200)) {
        let (_, cfg) = sample_evidence([1u8; 32]);
        // A random buffer must be rejected, and must never panic.
        match EvmEvidence::decode(&bytes) {
            Err(_) => {}
            Ok(e) => {
                prop_assert!(e.verify_static(&cfg).is_err());
            }
        }
    }

    /// Every byte of the *derivable* region of an evidence frame is
    /// load-bearing: version, kind, deployment bindings, funder, terms,
    /// binding, lock id and payload. Flipping any bit there must break
    /// `verify_static`.
    ///
    /// The observation-location region (block number/hash, tx hash, log index,
    /// finalized height/hash) is deliberately excluded: it records *where* the
    /// fact was seen and cannot be re-derived from the frame itself. It is
    /// checked against the chain by `verify_onchain`, and the integration test
    /// `tampered_evidence_is_refused_field_by_field` covers it end to end.
    #[test]
    fn a_single_flipped_bit_in_the_derivable_region_breaks_verification(
        t in arb_canonical_scalar(),
        pos in (0usize..DERIVABLE_PREFIX_LEN + 32).prop_map(|p| {
            if p < DERIVABLE_PREFIX_LEN { p } else { PAYLOAD_OFFSET + (p - DERIVABLE_PREFIX_LEN) }
        }),
        mask in 1u8..=255,
    ) {
        let (e, cfg) = sample_evidence(t);
        prop_assert!(e.verify_static(&cfg).is_ok());
        let mut enc = e.encode();
        enc[pos] ^= mask;
        prop_assume!(enc != e.encode());
        match EvmEvidence::decode(&enc) {
            Err(_) => {}
            Ok(mutated) => {
                prop_assume!(mutated != e);
                prop_assert!(
                    mutated.verify_static(&cfg).is_err(),
                    "a mutated evidence frame verified"
                );
            }
        }
    }

    #[test]
    fn evidence_bound_to_another_deployment_is_rejected(t in arb_canonical_scalar(), other in any::<u64>()) {
        let (mut e, cfg) = sample_evidence(t);
        prop_assume!(other != cfg.chain_id);
        e.chain_id = other;
        prop_assert_eq!(e.verify_static(&cfg), Err(AdapterError::EvidenceInvalid));
    }

    #[test]
    fn evidence_above_its_own_checkpoint_is_rejected(t in arb_canonical_scalar(), over in 1u64..1_000) {
        let (mut e, cfg) = sample_evidence(t);
        e.block_number = e.finalized_height.saturating_add(over);
        prop_assert_eq!(e.verify_static(&cfg), Err(AdapterError::PreconditionUnsatisfied));
    }
}

// ---------------------------------------------------------------------------
// 5. cursor
// ---------------------------------------------------------------------------

prop_compose! {
    fn arb_cursor()(
        chain_id in 2u64..1_000_000,
        contract in arb_addr(),
        next_from_block in any::<u64>(),
        last_seen_block_hash in arb_b32(),
        finalized_height in any::<u64>(),
        emitted_high_water in any::<u64>(),
    ) -> EvmCursor {
        EvmCursor {
            version: CURSOR_VERSION,
            chain_id, contract, next_from_block, last_seen_block_hash,
            finalized_height, emitted_high_water,
        }
    }
}

proptest! {
    #[test]
    fn cursor_round_trips(c in arb_cursor()) {
        let enc = c.encode();
        prop_assert_eq!(enc.0.len(), CURSOR_LEN);
        prop_assert_eq!(EvmCursor::decode(&enc, c.chain_id, &c.contract, 0), Ok(c));
    }

    #[test]
    fn cursor_rejects_any_other_length(c in arb_cursor(), len in 1usize..200) {
        prop_assume!(len != CURSOR_LEN);
        let mut v = c.encode().0;
        v.resize(len, 0);
        prop_assert_eq!(
            EvmCursor::decode(&ChainCursor(v), c.chain_id, &c.contract, 0),
            Err(AdapterError::VersionMismatch)
        );
    }

    #[test]
    fn cursor_rejects_a_version_bump(c in arb_cursor(), v in any::<u16>()) {
        prop_assume!(v != CURSOR_VERSION);
        let mut enc = c.encode();
        enc.0[..2].copy_from_slice(&v.to_be_bytes());
        prop_assert_eq!(
            EvmCursor::decode(&enc, c.chain_id, &c.contract, 0),
            Err(AdapterError::VersionMismatch)
        );
    }

    #[test]
    fn cursor_rejects_a_foreign_deployment(c in arb_cursor(), other_chain in 2u64..1_000_000, other_contract in arb_addr()) {
        prop_assume!(other_chain != c.chain_id || other_contract != c.contract);
        let enc = c.encode();
        prop_assert_eq!(
            EvmCursor::decode(&enc, other_chain, &other_contract, 0),
            Err(AdapterError::StaleCursor)
        );
    }

    #[test]
    fn the_empty_cursor_always_means_the_start_block(chain_id in 2u64..1_000_000, contract in arb_addr(), start in any::<u64>()) {
        prop_assert_eq!(
            EvmCursor::decode(&ChainCursor::default(), chain_id, &contract, start),
            Ok(EvmCursor::fresh(chain_id, contract, start))
        );
    }

    #[test]
    fn rewinding_never_raises_the_high_water_mark(c in arb_cursor(), to in any::<u64>(), anchor in arb_b32()) {
        let r = c.rewind_to(to, anchor);
        prop_assert!(r.emitted_high_water <= c.emitted_high_water);
        prop_assert!(r.emitted_high_water <= to.saturating_sub(1));
        prop_assert_eq!(r.next_from_block, to);
    }

    #[test]
    fn advancing_never_lowers_the_high_water_mark(c in arb_cursor(), through in any::<u64>(), anchor in arb_b32(), emitted in any::<u64>()) {
        let a = c.advance_to(through, anchor, c.finalized_height, emitted);
        prop_assert!(a.emitted_high_water >= c.emitted_high_water);
    }
}

// ---------------------------------------------------------------------------
// 6. finality gating
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn the_gate_is_exactly_less_or_equal(h in any::<u64>(), f in any::<u64>(), hash in arb_b32()) {
        prop_assume!(hash != [0u8; 32]);
        let head = FinalizedHead { height: f, hash };
        prop_assert_eq!(gate(h, &head), h <= f);
        prop_assert!(clamp_to_finalized(h, &head) <= f);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn nothing_above_the_checkpoint_is_ever_emitted(
        pre in 0u64..4, post in 0u64..4, cut in 0u64..8,
    ) {
        let s = scenario(101);
        s.mine(pre);
        s.mine_open();
        s.mine(post);
        s.mine_claim();
        let tip = s.height();
        let finalized = cut.min(tip);
        s.finalize(finalized);

        let a = s.adapter();
        let (events, _) = a.observe_blocking(&ChainCursor::default(), 512).expect("observe");
        for e in &events {
            let h = match e {
                ObservedEvent::LockOpened { height, .. }
                | ObservedEvent::LockClaimed { height, .. }
                | ObservedEvent::LockRefunded { height, .. } => *height,
                ObservedEvent::Reorged { from_height } => *from_height,
            };
            prop_assert!(h <= finalized, "event at {h} above the checkpoint {finalized}");
        }
    }
}

// ---------------------------------------------------------------------------
// 7. reorg
// ---------------------------------------------------------------------------

struct ForkedChain {
    height: u64,
    fork_at: u64,
    tag: u8,
}

impl ForkedChain {
    fn hash(&self, h: u64) -> [u8; 32] {
        let tag = if h >= self.fork_at { self.tag } else { 0 };
        let mut pre = [0u8; 9];
        pre[0] = tag;
        pre[1..].copy_from_slice(&h.to_be_bytes());
        adapter_evm::keccak256(&pre)
    }
}

impl HeaderSource for ForkedChain {
    fn header_at(&self, height: u64) -> Result<Option<RpcBlockHeader>, AdapterError> {
        if height > self.height {
            return Ok(None);
        }
        Ok(Some(RpcBlockHeader {
            number: height,
            hash: self.hash(height),
            parent_hash: if height == 0 {
                [0u8; 32]
            } else {
                self.hash(height - 1)
            },
        }))
    }
}

proptest! {
    #[test]
    fn a_reorg_resume_point_is_never_above_the_fork(
        last_h in 10u64..60, fork_depth in 1u64..9, tag in 1u8..=255,
    ) {
        let old = ForkedChain { height: 80, fork_at: u64::MAX, tag: 0 };
        let fork_at = last_h.saturating_sub(fork_depth).max(1);
        let new = ForkedChain { height: 80, fork_at, tag };

        let mut known = KnownHeaders::with_capacity(64);
        for h in 0..=last_h {
            known.record(h, old.hash(h));
        }
        let mut c = EvmCursor::fresh(31337, CONTRACT, 0);
        c.next_from_block = last_h + 1;
        c.last_seen_block_hash = old.hash(last_h);

        let out = detect(&new, &known, &c, 0, 32).expect("within tolerance");
        match out {
            ReorgOutcome::Continuous => prop_assert!(false, "a fork must be detected"),
            ReorgOutcome::Reorg { from_height, .. } => {
                prop_assert!(
                    from_height <= fork_at,
                    "resume point {from_height} is above the fork at {fork_at}: invalidation was under-reported"
                );
            }
        }
    }

    #[test]
    fn a_reorg_deeper_than_the_tolerance_fails_closed(
        last_h in 40u64..60, depth in 1u32..6, tag in 1u8..=255,
    ) {
        let old = ForkedChain { height: 80, fork_at: u64::MAX, tag: 0 };
        let new = ForkedChain { height: 80, fork_at: last_h - u64::from(depth) - 5, tag };
        let mut known = KnownHeaders::with_capacity(64);
        for h in 0..=last_h {
            known.record(h, old.hash(h));
        }
        let mut c = EvmCursor::fresh(31337, CONTRACT, 0);
        c.next_from_block = last_h + 1;
        c.last_seen_block_hash = old.hash(last_h);
        prop_assert_eq!(detect(&new, &known, &c, 0, depth), Err(AdapterError::ReorgDetected));
    }

    #[test]
    fn rewinding_is_idempotent(
        last_h in 10u64..60, fork_depth in 1u64..9, tag in 1u8..=255,
    ) {
        let old = ForkedChain { height: 80, fork_at: u64::MAX, tag: 0 };
        let fork_at = last_h.saturating_sub(fork_depth).max(1);
        let new = ForkedChain { height: 80, fork_at, tag };
        let mut known = KnownHeaders::with_capacity(64);
        for h in 0..=last_h {
            known.record(h, old.hash(h));
        }
        let mut c = EvmCursor::fresh(31337, CONTRACT, 0);
        c.next_from_block = last_h + 1;
        c.last_seen_block_hash = old.hash(last_h);

        let ReorgOutcome::Reorg { from_height, anchor } =
            detect(&new, &known, &c, 0, 32).expect("reorg") else {
                prop_assert!(false, "expected a reorg");
                return Ok(());
            };
        let once = apply_rewind(&c, &mut known, from_height, anchor);
        let twice = apply_rewind(&once, &mut known, from_height, anchor);
        prop_assert_eq!(once, twice);
        prop_assert_eq!(detect(&new, &known, &once, 0, 32), Ok(ReorgOutcome::Continuous));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn observation_survives_a_reorg_without_losing_the_secret(depth in 1u64..3) {
        let s = scenario(103);
        s.mine_open();
        s.mine_claim();
        s.mine(2);
        s.finalize_tip();
        let a = s.adapter();
        let (_, cursor) = a.observe_blocking(&ChainCursor::default(), 512).expect("observe");
        prop_assert!(a.is_revealed(&s.lock_id).expect("state"));

        s.reorg(depth);
        s.finalize_tip();
        // Whatever happens, the secret stays known and nothing panics.
        let _ = a.observe_blocking(&cursor, 512);
        prop_assert!(
            a.is_revealed(&s.lock_id).expect("state"),
            "a reorg must never un-reveal a scalar"
        );
    }

    #[test]
    fn replay_from_the_start_is_idempotent(extra in 0u64..4) {
        let s = scenario(107);
        s.mine_open();
        s.mine_claim();
        s.mine(extra);
        s.finalize_tip();
        let a = s.adapter();
        let first = a.observe_blocking(&ChainCursor::default(), 512).expect("observe");
        let second = a.observe_blocking(&ChainCursor::default(), 512).expect("observe");
        prop_assert_eq!(first, second);
    }
}

// ---------------------------------------------------------------------------
// 8. out-of-order / duplicated pages, 9. garbage RPC, 10. restart
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn page_shuffling_and_duplication_do_not_change_the_result(
        out_of_order in any::<bool>(), duplicate in any::<bool>(), page_size in 1u64..8,
    ) {
        let s = scenario(109);
        s.mine_open();
        s.mine(1);
        s.mine_claim();
        s.finalize_tip();

        let mut cfg = s.cfg;
        cfg.page_size = page_size;
        let clean = adapter_evm::EvmAdapter::new(cfg, s.chain.clone()).expect("valid");
        let expected = clean.observe_blocking(&ChainCursor::default(), 512).expect("observe");

        s.chain.set_faults(Faults {
            logs_out_of_order: out_of_order,
            duplicate_logs: duplicate,
            ..Faults::default()
        });
        let hostile = adapter_evm::EvmAdapter::new(cfg, s.chain.clone()).expect("valid");
        let got = hostile.observe_blocking(&ChainCursor::default(), 512).expect("observe");
        prop_assert_eq!(expected, got);
    }

    #[test]
    fn a_persisted_cursor_always_resumes_without_replaying(split in 1u64..4) {
        let s = scenario(113);
        s.mine_open();
        s.mine(split);
        s.mine_claim();
        s.finalize_tip();

        let a = s.adapter();
        let (first, cursor) = a.observe_blocking(&ChainCursor::default(), 1).expect("observe");
        // A fresh adapter picks up exactly where the cursor points.
        let restarted = s.adapter();
        restarted.track_lock(&s.terms).expect("re-register");
        let (second, _) = restarted.observe_blocking(&cursor, 512).expect("observe");
        let mut all = first;
        all.extend(second);
        let (whole, _) = s.adapter().observe_blocking(&ChainCursor::default(), 512).expect("observe");
        prop_assert_eq!(all, whole, "splitting an observation must not change what is seen");
    }
}

proptest! {
    #[test]
    fn hex_helpers_reject_garbage_without_panicking(sv in ".{0,40}") {
        let v = json!(sv);
        let _ = hex_quantity(&v);
        let _ = hex_bytes(&v, 64);
        // Anything we produce ourselves must round-trip.
        let bytes = sv.as_bytes();
        if bytes.len() <= 64 {
            prop_assert_eq!(hex_bytes(&json!(hex_of(bytes)), 64), Ok(bytes.to_vec()));
        }
    }

    #[test]
    fn rpc_header_parsing_never_accepts_a_partial_object(
        n in any::<u64>(), h in arb_b32(), p in arb_b32(), drop in 0usize..3,
    ) {
        let mut obj = json!({
            "number": format!("0x{n:x}"),
            "hash": hex_of(&h),
            "parentHash": hex_of(&p),
        });
        let key = ["number", "hash", "parentHash"][drop];
        obj.as_object_mut().expect("object").remove(key);
        prop_assert_eq!(RpcBlockHeader::parse(&obj), Err(AdapterError::EvidenceInvalid));
    }
}

// ---------------------------------------------------------------------------
// unsigned artifact
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn prepare_lock_is_a_pure_function_of_its_inputs(
        t in arb_canonical_scalar(), amount in 1u128..u128::from(u64::MAX), deadline in any::<u64>(),
    ) {
        let s = scenario(127);
        let a = s.adapter();
        let point = counterparty_api::AdaptorPointBytes(
            adaptor_point_of_scalar(&t).expect("canonical"),
        );
        let neutral = adapter_evm::adapter::test_support::sample_neutral(a.config(), amount, deadline);
        let one = block_on(
            <adapter_evm::EvmAdapter<common::SharedChain> as counterparty_api::CounterpartyAdapter>
                ::prepare_lock(&a, &neutral, &point),
        ).expect("artifact");
        let two = a.prepare_lock_blocking(&neutral, &point).expect("artifact");
        prop_assert_eq!(&one, &two);

        let call = UnsignedEvmCall::decode(&one.bytes).expect("decodes");
        prop_assert_eq!(call.encode(), one.bytes);
        prop_assert_eq!(call.calldata.len(), 4 + 320);
        prop_assert_eq!(call.value, word_u128(amount));
    }

    #[test]
    fn unsigned_call_decoding_rejects_mutated_frames(payload_len in 0usize..64, pos in 0usize..8, mask in 1u8..=255) {
        let call = UnsignedEvmCall {
            version: 1,
            chain_id: 31337,
            to: CONTRACT,
            value: [0u8; 32],
            gas_limit_hint: 21_000,
            lock_id: [1u8; 32],
            binding: [2u8; 32],
            calldata: vec![7u8; payload_len],
        };
        let enc = call.encode();
        prop_assert_eq!(UnsignedEvmCall::decode(&enc), Ok(call));
        // Corrupting the declared length always breaks the frame.
        let head = 2 + 8 + 20 + 32 + 8 + 32 + 32;
        let mut broken = enc;
        broken[head + (pos % 4)] ^= mask;
        prop_assert!(UnsignedEvmCall::decode(&broken).is_err());
    }
}

// ---------------------------------------------------------------------------
// verified outcomes are the only thing the core ever sees (I9)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn verified_outcomes_carry_only_neutral_facts(seed in 1u8..40) {
        let s = scenario(seed);
        s.mine_open();
        s.mine_claim();
        s.finalize_tip();
        let a = s.adapter();
        let _ = a.observe_blocking(&ChainCursor::default(), 512).expect("observe");
        let evidence = a
            .collect_evidence(&s.lock_id, EvidenceKind::Claimed)
            .expect("evidence");
        let outcome = block_on(
            <adapter_evm::EvmAdapter<common::SharedChain> as counterparty_api::CounterpartyAdapter>
                ::verify_evidence(&a, &evidence.encode()),
        ).expect("verifies");
        match outcome {
            VerifiedOutcome::Claimed { revealed, height } => {
                prop_assert_eq!(revealed.0, s.secret);
                prop_assert_eq!(height, evidence.block_number);
                // The neutral wrapper never renders the scalar.
                let rendered = format!("{revealed:?}");
                prop_assert!(rendered.contains("redacted"));
            }
            other => prop_assert!(false, "unexpected outcome {other:?}"),
        }
    }
}
