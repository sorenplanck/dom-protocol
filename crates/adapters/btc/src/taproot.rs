//! Taproot contract construction (Annex M M.2).
//!
//! Deterministic, rederivable byte-for-byte: given the roster, the refund
//! key and the CSV delay, the P2TR output (key-path claim, single
//! script-path CSV refund leaf) is fully determined. The aggregate
//! internal key `P` and the tweak `Q = P + h·G` come from the pinned
//! crypto backend (`btc-crypto`); the tagged hashes come from the same
//! backend, never reimplemented (M.0.4).
//!
//! `internal_flip`/`output_flip` are explicit results of the x-only
//! normalization and the TapTweak, not ad-hoc corrections (M.2.2).

use btc_crypto::{Parity, SecpContext};

use crate::error::TaprootError;
use crate::roster::ParticipantKeyRosterV1;
use crate::timelock::{encode_csv, script_number_minimal, BitcoinCsvDelayV1};

/// Taproot leaf version of a BIP342 tapscript leaf (M.2.1).
pub const TAPROOT_LEAF_VERSION: u8 = 0xc0;

const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
const OP_DROP: u8 = 0x75;
const OP_CHECKSIG: u8 = 0xac;
const OP_0: u8 = 0x00;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_PUSH32: u8 = 0x20;

/// The single refund leaf of the tree (M.2.2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RefundLeafV1 {
    /// Exactly [`TAPROOT_LEAF_VERSION`].
    pub leaf_version: u8,
    /// The CSV delay in its native unit.
    pub delay: BitcoinCsvDelayV1,
    /// The 32-byte x-only refund key (the Bitcoin funder, M.7.1).
    pub refund_key_xonly: [u8; 32],
    /// The canonical, rederivable leaf script bytes.
    pub script: Vec<u8>,
    /// TapLeaf hash of `(leaf_version, script)`.
    pub tapleaf_hash: [u8; 32],
}

/// The fully derived P2TR contract (M.2.2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TaprootContractV1 {
    /// x-only aggregate internal key `x(P)`.
    pub internal_key_xonly: [u8; 32],
    /// Parity of the full aggregate key `P` (`internal_flip`).
    pub internal_parity: ParityV1,
    /// The single refund leaf.
    pub refund_leaf: RefundLeafV1,
    /// Merkle root of the single-leaf tree (equals the leaf hash).
    pub merkle_root: [u8; 32],
    /// TapTweak `h = tagged_hash("TapTweak", x(P) || merkle_root)`.
    pub tweak: [u8; 32],
    /// x-only Taproot output key `x(Q)`.
    pub output_key_xonly: [u8; 32],
    /// Parity of `Q` (`output_flip`).
    pub output_parity: ParityV1,
    /// `OP_1 PUSH32 x(Q)` — the P2TR scriptPubKey.
    pub script_pubkey: Vec<u8>,
    /// `(0xc0 | parity(Q)) || x(P)` with an empty Merkle path.
    pub control_block: Vec<u8>,
}

/// Parity re-exported at the crate boundary so callers need not depend on
/// `btc-crypto` directly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ParityV1 {
    /// Even y.
    Even,
    /// Odd y.
    Odd,
}

impl From<Parity> for ParityV1 {
    fn from(p: Parity) -> Self {
        match p {
            Parity::Even => Self::Even,
            Parity::Odd => Self::Odd,
        }
    }
}

/// Encodes the refund leaf script `<csv> OP_CSV OP_DROP <pk> OP_CHECKSIG`
/// (M.2.1). Deterministic and rederivable byte for byte.
pub fn encode_refund_script(
    delay: BitcoinCsvDelayV1,
    refund_key_xonly: &[u8; 32],
) -> Result<Vec<u8>, TaprootError> {
    let csv_value = encode_csv(delay).map_err(|_| TaprootError::InvalidTimelock)?;
    let csv_push = script_number_minimal(csv_value);
    let mut script = Vec::with_capacity(1 + csv_push.len() + 2 + 1 + 32 + 1);
    // <csv_delay> as a minimal push.
    push_minimal(&mut script, &csv_push);
    script.push(OP_CHECKSEQUENCEVERIFY);
    script.push(OP_DROP);
    // <refund_xonly_pk>
    script.push(OP_PUSH32);
    script.extend_from_slice(refund_key_xonly);
    script.push(OP_CHECKSIG);
    Ok(script)
}

/// Pushes `data` with the minimal push opcode, as `CheckMinimalPush`
/// defines minimality: empty data is `OP_0`; a single byte in `1..=16` is
/// `OP_1..OP_16`; the single byte `0x81` is `OP_1NEGATE`; anything else up
/// to 75 bytes is a direct push with a one-byte length prefix.
///
/// The `1..=16` and `0x81` arms were missing before 2026-08-19, so a CSV
/// operand in that range produced a length-prefixed push that a verifier
/// enforcing minimality rejects (audit finding F3). The `0x81` arm cannot
/// be reached through `encode_refund_script`: `script_number_minimal` pads
/// any value whose top byte has the sign bit set, so it never returns a
/// lone `0x81`. It is written out because this function's contract is the
/// push rule, not the subset of it that one caller happens to exercise.
///
/// Data longer than 75 bytes would need `OP_PUSHDATA1`, which this function
/// does not emit; the bound is asserted rather than encoded because the sole
/// caller pushes at most three bytes.
fn push_minimal(out: &mut Vec<u8>, data: &[u8]) {
    match data {
        [] => out.push(OP_0),
        &[byte] if (1..=16).contains(&byte) => out.push(OP_1 + byte - 1),
        &[0x81] => out.push(OP_1NEGATE),
        _ => {
            debug_assert!(data.len() <= 75, "CSV push is always small");
            out.push(data.len() as u8);
            out.extend_from_slice(data);
        }
    }
}

/// BIP341 CompactSize (only the single-byte range is reachable for our
/// bounded scripts, but the full small-int encoding is implemented).
fn compact_size(out: &mut Vec<u8>, n: usize) {
    if n < 0xfd {
        out.push(n as u8);
    } else if n <= 0xffff {
        out.push(0xfd);
        out.extend_from_slice(&(n as u16).to_le_bytes());
    } else {
        out.push(0xfe);
        out.extend_from_slice(&(n as u32).to_le_bytes());
    }
}

/// Builds the P2TR contract from the ordered roster, the refund key and
/// the CSV delay (M.2.2). Deterministic and rederivable; fails closed on
/// `h ≥ n` or `Q = ∞`. The `ctx` carries the pinned crypto backend.
pub fn build_taproot_contract(
    ctx: &SecpContext,
    roster: &ParticipantKeyRosterV1,
    refund_key_xonly: &[u8; 32],
    delay: BitcoinCsvDelayV1,
) -> Result<TaprootContractV1, TaprootError> {
    {
        roster.validate().map_err(TaprootError::Roster)?;

        // 1-2. Refund script and its TapLeaf hash.
        let script = encode_refund_script(delay, refund_key_xonly)?;
        let mut leaf_preimage = Vec::with_capacity(1 + 3 + script.len());
        leaf_preimage.push(TAPROOT_LEAF_VERSION);
        compact_size(&mut leaf_preimage, script.len());
        leaf_preimage.extend_from_slice(&script);
        let tapleaf_hash = ctx.tagged_sha256(b"TapLeaf", &leaf_preimage);

        // 3. Single-leaf tree: merkle root == leaf hash.
        let merkle_root = tapleaf_hash;

        // Aggregate internal key P (roster order is law).
        let ordered: Vec<[u8; 33]> = roster
            .participants()
            .iter()
            .map(|p| p.compressed_key)
            .collect();
        let mut keyagg = ctx
            .key_agg(&ordered)
            .map_err(|_| TaprootError::KeyAggregationFailed)?;
        let internal_key_xonly = keyagg.internal_xonly;

        // 4-5. h = tagged_hash("TapTweak", x(P) || merkle_root).
        let mut tweak_preimage = Vec::with_capacity(64);
        tweak_preimage.extend_from_slice(&internal_key_xonly);
        tweak_preimage.extend_from_slice(&merkle_root);
        let tweak = ctx.tagged_sha256(b"TapTweak", &tweak_preimage);

        // 6-9. Q = P + h·G; the backend fails closed on h ≥ n or Q = ∞.
        let tw = ctx
            .apply_tap_tweak(&mut keyagg, &tweak)
            .map_err(|_| TaprootError::TapTweakRejected)?;

        // 10. scriptPubKey = OP_1 PUSH32 x(Q).
        let mut script_pubkey = Vec::with_capacity(2 + 32);
        script_pubkey.push(OP_1);
        script_pubkey.push(OP_PUSH32);
        script_pubkey.extend_from_slice(&tw.output_xonly);

        // 11. control block = (0xc0 | parity(Q)) || x(P) (empty path).
        let parity_bit = match tw.output_parity {
            Parity::Even => 0u8,
            Parity::Odd => 1u8,
        };
        let mut control_block = Vec::with_capacity(1 + 32);
        control_block.push(TAPROOT_LEAF_VERSION | parity_bit);
        control_block.extend_from_slice(&internal_key_xonly);

        Ok(TaprootContractV1 {
            internal_key_xonly,
            internal_parity: keyagg.internal_parity.into(),
            refund_leaf: RefundLeafV1 {
                leaf_version: TAPROOT_LEAF_VERSION,
                delay,
                refund_key_xonly: *refund_key_xonly,
                script,
                tapleaf_hash,
            },
            merkle_root,
            tweak,
            output_key_xonly: tw.output_xonly,
            output_parity: tw.output_parity.into(),
            script_pubkey,
            control_block,
        })
    }
}
