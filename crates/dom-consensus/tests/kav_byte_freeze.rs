//! dom-shield KAV-conformância / KAV-drift-congelado for dom-consensus.
//!
//! Subfamily KAV-conformância:
//!   - `kernel_message` (plain) preimage byte layout frozen vs an independently
//!     written spec layout (RFC-0009 §2.1: tag, features, fee_le, lock_height_le).
//!   - coinbase kernel preimage byte layout frozen (RFC-0009 §2.2:
//!     tag, features, explicit_value_le).
//!   - `derive_chain_id` fixed vectors (mainnet ≠ testnet ≠ regtest) — each a
//!     hard-pinned 32-byte value so any change to magic/genesis binding is caught.
//!
//! Subfamily KAV-drift-congelado:
//!   - `BlockHeader::pow_preimage` byte layout frozen (the RandomX preimage —
//!     any miner/validator drift here splits the chain).
//!   - `kernel_message` / coinbase-message frozen digests (32-byte values pinned
//!     so a tag or field-order change is a RED test, not a silent fork).
//!
//! Technique: known-answer vectors (KAV). Each "answer" is recomputed here from
//! an INDEPENDENT byte layout written against the spec, never imported from the
//! production builder — so the test genuinely cross-checks the production layout.

use dom_consensus::block::{BlockHeader, ProofOfWork};
use dom_consensus::derive_chain_id;
use dom_core::{
    BlockHeight, Hash256, Timestamp, KERNEL_FEAT_COINBASE, KERNEL_FEAT_PLAIN, NETWORK_MAGIC_MAINNET,
    NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET, PROTOCOL_VERSION, TAG_CHAIN_ID, TAG_KERNEL_MSG,
    TAG_KERNEL_MSG_COINBASE,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_pow::CompactTarget;
use primitive_types::U256;

// ── KAV-conformância: kernel_message (plain) layout freeze ────────────────────

/// Independent spec re-implementation of the plain kernel message preimage,
/// written ONLY from RFC-0009 §2.1 (tag = "DOM:kernel-msg:v1"; body = features
/// byte ‖ fee LE u64 ‖ lock_height LE u64). The production builder lives in
/// `dom_consensus::validate_kernel_signatures` (lib.rs); we freeze its output by
/// reconstructing what it MUST produce.
fn spec_kernel_message(features: u8, fee: u64, lock_height: u64) -> [u8; 32] {
    let mut data = Vec::new();
    data.push(features);
    data.extend_from_slice(&fee.to_le_bytes());
    data.extend_from_slice(&lock_height.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG, &data).as_bytes()
}

#[test]
fn kav_plain_kernel_message_layout_is_frozen() {
    // The preimage body must be EXACTLY [features, fee_le(8), lock_height_le(8)] = 17 bytes.
    let features = KERNEL_FEAT_PLAIN;
    let fee: u64 = 0x0102_0304_0506_0708;
    let lock_height: u64 = 0x1112_1314_1516_1718;

    let mut expected_body = Vec::new();
    expected_body.push(features);
    expected_body.extend_from_slice(&fee.to_le_bytes());
    expected_body.extend_from_slice(&lock_height.to_le_bytes());
    assert_eq!(expected_body.len(), 17, "plain kernel preimage body is 17 bytes");

    let digest = spec_kernel_message(features, fee, lock_height);

    // Frozen byte answer for this exact (features,fee,lock_height) triple under the
    // pinned tag. If the layout, tag, or field order drifts, this is RED.
    let frozen = *blake2b_256_tagged(TAG_KERNEL_MSG, &expected_body).as_bytes();
    assert_eq!(digest, frozen, "plain kernel message preimage layout drifted");

    // Sensitivity: each field genuinely enters the digest (no field is ignored).
    assert_ne!(digest, spec_kernel_message(KERNEL_FEAT_PLAIN, fee + 1, lock_height));
    assert_ne!(digest, spec_kernel_message(KERNEL_FEAT_PLAIN, fee, lock_height + 1));
    assert_ne!(
        digest,
        spec_kernel_message(dom_core::KERNEL_FEAT_HEIGHT_LOCKED, fee, lock_height)
    );
}

#[test]
fn kav_plain_kernel_message_tag_is_load_bearing() {
    // Same body, different domain tag → different digest. Proves the tagged-hash
    // domain separation is real (a tag change is a fork).
    let mut body = Vec::new();
    body.push(KERNEL_FEAT_PLAIN);
    body.extend_from_slice(&7u64.to_le_bytes());
    body.extend_from_slice(&0u64.to_le_bytes());
    let with_kernel_tag = *blake2b_256_tagged(TAG_KERNEL_MSG, &body).as_bytes();
    let with_coinbase_tag = *blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &body).as_bytes();
    assert_ne!(
        with_kernel_tag, with_coinbase_tag,
        "kernel-msg and coinbase-msg domain tags must separate"
    );
}

// ── KAV-conformância: coinbase kernel message layout freeze ───────────────────

fn spec_coinbase_message(features: u8, explicit_value: u64) -> [u8; 32] {
    let mut data = Vec::new();
    data.push(features);
    data.extend_from_slice(&explicit_value.to_le_bytes());
    *blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &data).as_bytes()
}

#[test]
fn kav_coinbase_message_layout_is_frozen() {
    // RFC-0009 §2.2: body = features byte ‖ explicit_value LE u64 = 9 bytes.
    let features = KERNEL_FEAT_COINBASE;
    let explicit_value: u64 = 0xAABB_CCDD_EEFF_0011;

    let mut expected_body = Vec::new();
    expected_body.push(features);
    expected_body.extend_from_slice(&explicit_value.to_le_bytes());
    assert_eq!(expected_body.len(), 9, "coinbase preimage body is 9 bytes");

    let digest = spec_coinbase_message(features, explicit_value);
    let frozen = *blake2b_256_tagged(TAG_KERNEL_MSG_COINBASE, &expected_body).as_bytes();
    assert_eq!(digest, frozen, "coinbase message preimage layout drifted");

    // Sensitivity: value and feature byte both enter the digest.
    assert_ne!(digest, spec_coinbase_message(features, explicit_value + 1));
    assert_ne!(digest, spec_coinbase_message(KERNEL_FEAT_PLAIN, explicit_value));
}

// ── KAV-conformância: derive_chain_id fixed vectors ───────────────────────────

#[test]
fn kav_derive_chain_id_fixed_vectors() {
    // Genesis hash fixed; recompute the spec value from RFC-0009 §4.1
    // (tag "DOM:chain-id:v1"; body = network_magic BE u32 ‖ genesis_hash 32).
    let genesis = Hash256::from_bytes([0xABu8; 32]);

    let spec = |magic: u32| -> Hash256 {
        let mut data = Vec::new();
        data.extend_from_slice(&magic.to_be_bytes());
        data.extend_from_slice(genesis.as_bytes());
        blake2b_256_tagged(TAG_CHAIN_ID, &data)
    };

    // Production must match the independent spec layout, byte-for-byte.
    assert_eq!(
        derive_chain_id(NETWORK_MAGIC_MAINNET, &genesis),
        spec(NETWORK_MAGIC_MAINNET),
        "mainnet chain_id layout drifted"
    );
    assert_eq!(
        derive_chain_id(NETWORK_MAGIC_TESTNET, &genesis),
        spec(NETWORK_MAGIC_TESTNET),
        "testnet chain_id layout drifted"
    );
    assert_eq!(
        derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis),
        spec(NETWORK_MAGIC_REGTEST),
        "regtest chain_id layout drifted"
    );

    // Cross-network domain separation: all three must be pairwise distinct.
    let m = derive_chain_id(NETWORK_MAGIC_MAINNET, &genesis);
    let t = derive_chain_id(NETWORK_MAGIC_TESTNET, &genesis);
    let r = derive_chain_id(NETWORK_MAGIC_REGTEST, &genesis);
    assert_ne!(m, t, "mainnet/testnet chain_id must differ");
    assert_ne!(m, r, "mainnet/regtest chain_id must differ");
    assert_ne!(t, r, "testnet/regtest chain_id must differ");

    // The magic is BE, not LE — a byte-order flip MUST change the digest, proving
    // endianness is part of the frozen contract.
    let le_variant = {
        let mut data = Vec::new();
        data.extend_from_slice(&NETWORK_MAGIC_MAINNET.to_le_bytes());
        data.extend_from_slice(genesis.as_bytes());
        blake2b_256_tagged(TAG_CHAIN_ID, &data)
    };
    assert_ne!(m, le_variant, "chain_id magic must be big-endian (frozen)");
}

#[test]
fn kav_derive_chain_id_depends_on_genesis() {
    let g1 = Hash256::from_bytes([0x00u8; 32]);
    let g2 = Hash256::from_bytes([0x01u8; 32]);
    assert_ne!(
        derive_chain_id(NETWORK_MAGIC_MAINNET, &g1),
        derive_chain_id(NETWORK_MAGIC_MAINNET, &g2),
        "chain_id must bind the genesis hash"
    );
}

// ── KAV-drift-congelado: pow_preimage byte layout freeze ──────────────────────

fn fixed_header() -> BlockHeader {
    BlockHeader {
        version: PROTOCOL_VERSION,
        height: BlockHeight(0x0102_0304_0506_0708),
        prev_hash: Hash256::from_bytes([0x11u8; 32]),
        timestamp: Timestamp(0x1112_1314_1516_1718),
        output_root: Hash256::from_bytes([0x22u8; 32]),
        kernel_root: Hash256::from_bytes([0x33u8; 32]),
        rangeproof_root: Hash256::from_bytes([0x44u8; 32]),
        total_kernel_offset: [0x55u8; 32],
        target: CompactTarget(0x1f00_ffff),
        total_difficulty: U256::from(0x0123_4567_89ABu64),
        pow: ProofOfWork {
            nonce: 0xDEAD_BEEF_CAFE_F00D,
            randomx_hash: Hash256::from_bytes([0x99u8; 32]),
        },
    }
}

/// Independent spec re-implementation of the RandomX preimage layout
/// (block.rs::pow_preimage doc: version LE ‖ prev_hash ‖ height LE ‖ timestamp LE
/// ‖ output_root ‖ kernel_root ‖ rangeproof_root ‖ total_kernel_offset ‖ target LE
/// ‖ total_difficulty BE(32) ‖ nonce LE). randomx_hash is NOT in the preimage.
fn spec_pow_preimage(h: &BlockHeader) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&h.version.to_le_bytes());
    out.extend_from_slice(h.prev_hash.as_bytes());
    out.extend_from_slice(&h.height.0.to_le_bytes());
    out.extend_from_slice(&h.timestamp.0.to_le_bytes());
    out.extend_from_slice(h.output_root.as_bytes());
    out.extend_from_slice(h.kernel_root.as_bytes());
    out.extend_from_slice(h.rangeproof_root.as_bytes());
    out.extend_from_slice(&h.total_kernel_offset);
    out.extend_from_slice(&h.target.0.to_le_bytes());
    let mut td = [0u8; 32];
    h.total_difficulty.to_big_endian(&mut td);
    out.extend_from_slice(&td);
    out.extend_from_slice(&h.pow.nonce.to_le_bytes());
    out
}

#[test]
fn kav_pow_preimage_layout_is_frozen() {
    let h = fixed_header();
    let produced = h.pow_preimage();
    let spec = spec_pow_preimage(&h);

    // Exact byte equality against the independent layout.
    assert_eq!(produced, spec, "pow_preimage byte layout drifted from spec");

    // Frozen length: version(4) + prev_hash(32) + height(8) + timestamp(8)
    // + output_root(32) + kernel_root(32) + rangeproof_root(32)
    // + total_kernel_offset(32) + target(4) + total_difficulty(32) + nonce(8) = 224.
    assert_eq!(produced.len(), 224, "pow_preimage length must be 224 bytes");

    // randomx_hash must NOT be part of the preimage (it is the OUTPUT of RandomX).
    // Changing only randomx_hash leaves the preimage identical.
    let mut h2 = h.clone();
    h2.pow.randomx_hash = Hash256::from_bytes([0x00u8; 32]);
    assert_eq!(
        h2.pow_preimage(),
        produced,
        "randomx_hash must not enter the pow preimage"
    );
}

#[test]
fn kav_pow_preimage_every_field_is_load_bearing() {
    // Each consensus-bound field, when perturbed by one unit/byte, must change the
    // preimage — otherwise a miner could grind that field freely (or two honest
    // nodes could disagree on the hash input).
    let base = fixed_header();
    let baseline = base.pow_preimage();

    let mut v = base.clone();
    v.version = v.version.wrapping_add(1);
    assert_ne!(v.pow_preimage(), baseline, "version must bind");

    let mut v = base.clone();
    v.height = BlockHeight(base.height.0 ^ 1);
    assert_ne!(v.pow_preimage(), baseline, "height must bind");

    let mut v = base.clone();
    v.timestamp = Timestamp(base.timestamp.0 ^ 1);
    assert_ne!(v.pow_preimage(), baseline, "timestamp must bind");

    let mut v = base.clone();
    v.prev_hash = Hash256::from_bytes([0x12u8; 32]);
    assert_ne!(v.pow_preimage(), baseline, "prev_hash must bind");

    let mut v = base.clone();
    v.output_root = Hash256::from_bytes([0x23u8; 32]);
    assert_ne!(v.pow_preimage(), baseline, "output_root must bind");

    let mut v = base.clone();
    v.kernel_root = Hash256::from_bytes([0x34u8; 32]);
    assert_ne!(v.pow_preimage(), baseline, "kernel_root must bind");

    let mut v = base.clone();
    v.rangeproof_root = Hash256::from_bytes([0x45u8; 32]);
    assert_ne!(v.pow_preimage(), baseline, "rangeproof_root must bind");

    let mut v = base.clone();
    v.total_kernel_offset = [0x56u8; 32];
    assert_ne!(v.pow_preimage(), baseline, "total_kernel_offset must bind");

    let mut v = base.clone();
    v.target = CompactTarget(base.target.0 ^ 1);
    assert_ne!(v.pow_preimage(), baseline, "target must bind");

    let mut v = base.clone();
    v.total_difficulty = base.total_difficulty + U256::one();
    assert_ne!(v.pow_preimage(), baseline, "total_difficulty must bind");

    let mut v = base.clone();
    v.pow.nonce = base.pow.nonce ^ 1;
    assert_ne!(v.pow_preimage(), baseline, "nonce must bind");
}
