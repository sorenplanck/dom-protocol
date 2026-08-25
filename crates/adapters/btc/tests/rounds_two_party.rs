//! End-to-end 2-of-2 adaptor claim through the round machine (Annex M
//! M.6.7): two independent signers, each with its own vault, driven
//! through nonce → session → partial → pre-signature, then adapt/extract.
//! Proves the M.6.7 rule that a tampered counterparty partial blocks the
//! pre-signature.
//!
//! TEST-ONLY-NON-PRODUCTION: synthetic keys and a deterministic entropy
//! source; production uses the OS CSPRNG and vault-born secrets.

#![cfg(feature = "real-bitcoin-crypto")]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};

use adapter_btc::roster::{BitcoinSignerRoleV1, ParticipantKeyRosterV1, ParticipantKeyV1};
use adapter_btc::rounds::{ClaimRound, ClaimRoundInputs, ClaimRoundV1, LocalSigner, RoundError};
use adapter_btc::taproot::build_taproot_contract;
use adapter_btc::timelock::{
    bind_and_validate_funding_anchors, BitcoinCsvDelayV1, BitcoinFinalityPolicyV1,
    BitcoinFundingAnchorV1, ChainTimingBoundsV1, DomFundingAnchorV1, M8FundingAnchorsV1,
    M8TimingPolicyV1, TimelockOffsetV1,
};
use adapter_btc::types::BitcoinNetworkV1;
use btc_crypto::SecpContext;
use btc_vault::{
    BitcoinNoncePermitV1, BitcoinNoncePurposeV1, BitcoinNonceSealKeyV1, BitcoinNonceVault,
    BitcoinSigningPhaseV1, EntropyError, EntropySource,
};

struct CountingEntropy {
    base: u8,
    counter: AtomicU8,
}
impl CountingEntropy {
    fn new(base: u8) -> Self {
        Self {
            base,
            counter: AtomicU8::new(1),
        }
    }
}
impl EntropySource for CountingEntropy {
    fn fill(&self, out: &mut [u8; 32]) -> Result<(), EntropyError> {
        let c = self.counter.fetch_add(1, Ordering::SeqCst);
        out.fill(self.base ^ c);
        Ok(())
    }
}

fn tmp_db(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("btc_rounds_{name}_{}.sqlite", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

fn compressed(_secp: &SecpContext, secret: &[u8; 32]) -> [u8; 33] {
    // Derive the compressed pubkey with rust-bitcoin's secp (already a
    // dev/prod dependency); the same value parses in our backend below.
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret).expect("valid secret");
    PublicKey::from_secret_key(&secp, &sk).serialize()
}

struct Setup {
    sk1: [u8; 32],
    sk2: [u8; 32],
    t: [u8; 32],
    big_t: [u8; 33],
    roster: ParticipantKeyRosterV1,
    output_xonly: [u8; 32],
    /// The contract TapTweak (includes the merkle root) — the round's
    /// key-agg must apply exactly this so signing matches `output_xonly`.
    tweak: [u8; 32],
    tap_sighash: [u8; 32],
}

fn setup(secp: &SecpContext) -> Setup {
    let sk1 = [0x11u8; 32];
    let sk2 = [0x22u8; 32];
    let t = [0x2bu8; 32];
    let pk1 = compressed(secp, &sk1);
    let pk2 = compressed(secp, &sk2);
    let big_t = compressed(secp, &t);
    let refund_full = compressed(secp, &[0x33u8; 32]);
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
    .unwrap();

    let contract =
        build_taproot_contract(secp, &roster, &refund_xonly, BitcoinCsvDelayV1::Blocks(144))
            .unwrap();

    // A frozen 32-byte sighash stand-in (the real one comes from M.3;
    // here the round machine only needs a fixed message).
    let tap_sighash = [0x6du8; 32];

    Setup {
        sk1,
        sk2,
        t,
        big_t,
        roster,
        output_xonly: contract.output_key_xonly,
        tweak: contract.tweak,
        tap_sighash,
    }
}

fn permit(base: u8) -> BitcoinNoncePermitV1 {
    BitcoinNoncePermitV1 {
        settlement_id: [0x10; 32],
        session_id: [0x11; 32],
        participant_id: [base; 32],
        purpose: BitcoinNoncePurposeV1::ClaimAdaptor,
        phase: BitcoinSigningPhaseV1::NonceGeneration,
        roster_hash: [0x12; 32],
        terms_hash: [0x13; 32],
        claim_template_hash: [0x14; 32],
        tap_sighash: [0x6d; 32],
        adaptor_point: {
            let mut p = [0u8; 33];
            p[0] = 0x02;
            p
        },
        attempt: 0,
    }
}

fn m8_authorization() -> adapter_btc::timelock::AnchoredCrossChainWindowV1 {
    let bounds = ChainTimingBoundsV1 {
        min_block_seconds: 60,
        max_block_seconds: 60,
        max_reorg_seconds: 0,
        observation_seconds: 0,
        broadcast_seconds: 0,
    };
    let policy = M8TimingPolicyV1 {
        settlement_terms_hash: [0x13; 32],
        first_refund: TimelockOffsetV1::BtcBlocks { delta_blocks: 10 },
        second_refund: TimelockOffsetV1::DomBlocks { delta_blocks: 30 },
        safety_margin_seconds: 10,
        dom_bounds: bounds,
        btc_bounds: bounds,
        bitcoin_finality: BitcoinFinalityPolicyV1 {
            network: BitcoinNetworkV1::Regtest,
            minimum_confirmations: 1,
            maximum_reorg_depth: 1,
            require_header_chain: true,
            require_witness_commitment: true,
            policy_id: [0x15; 32],
            version: 1,
        },
    };
    let anchors = M8FundingAnchorsV1 {
        settlement_terms_hash: policy.settlement_terms_hash,
        policy_digest: policy.policy_digest().unwrap(),
        dom: DomFundingAnchorV1 {
            funding_txid: [0x16; 32],
            block_hash: [0x17; 32],
            height: 500,
            block_time_seconds: 1_700_000_000,
        },
        bitcoin: BitcoinFundingAnchorV1 {
            funding_txid: [0x18; 32],
            block_hash: [0x19; 32],
            height: 1_000,
            median_time_past: 1_700_000_000,
        },
    };
    bind_and_validate_funding_anchors(&policy, &anchors).unwrap()
}

#[test]
fn two_party_claim_produces_valid_pre_signature() {
    let crypto = SecpContext::new(&[0x5a; 32]);
    let s = setup(&crypto);
    // Both parties recompute the same key-agg + tweak.
    let keyagg = |c: &SecpContext| {
        let mut k = c
            .key_agg(&[
                s.roster.participants()[0].compressed_key,
                s.roster.participants()[1].compressed_key,
            ])
            .unwrap();
        // Apply the SAME tweak the contract used (includes the merkle
        // root), so signing verifies under `output_xonly`.
        c.apply_tap_tweak(&mut k, &s.tweak).unwrap();
        k
    };
    let keyagg1 = keyagg(&crypto);
    let keyagg2 = keyagg(&crypto);

    let path1 = tmp_db("p1");
    let path2 = tmp_db("p2");
    let mut vault1 =
        BitcoinNonceVault::open_with_entropy(&path1, CountingEntropy::new(0xA0)).unwrap();
    let mut vault2 =
        BitcoinNonceVault::open_with_entropy(&path2, CountingEntropy::new(0xB0)).unwrap();

    let permit1 = permit(1);
    let permit2 = permit(2);
    let m8_one = m8_authorization();
    let m8_two = m8_authorization();
    let seal_one = BitcoinNonceSealKeyV1::new([0x71; 32]).unwrap();
    let seal_two = BitcoinNonceSealKeyV1::new([0x72; 32]).unwrap();

    let mut r1 = ClaimRound::prepare_after_m8(
        ClaimRoundInputs {
            crypto: &crypto,
            keyagg: &keyagg1,
            roster: &s.roster,
            local: LocalSigner::First,
            local_secret: &s.sk1,
            tap_sighash: &s.tap_sighash,
            adaptor_point: &s.big_t,
            output_xonly: &s.output_xonly,
            permit: &permit1,
        },
        m8_one,
        &seal_one,
        &mut vault1,
    )
    .unwrap();
    let mut r2 = ClaimRound::prepare_after_m8(
        ClaimRoundInputs {
            crypto: &crypto,
            keyagg: &keyagg2,
            roster: &s.roster,
            local: LocalSigner::Second,
            local_secret: &s.sk2,
            tap_sighash: &s.tap_sighash,
            adaptor_point: &s.big_t,
            output_xonly: &s.output_xonly,
            permit: &permit2,
        },
        m8_two,
        &seal_two,
        &mut vault2,
    )
    .unwrap();

    // Exchange public nonces (each exposed only after being persisted).
    let n1 = r1.expose_local_pubnonce(&mut vault1).unwrap();
    let n2 = r2.expose_local_pubnonce(&mut vault2).unwrap();
    r1.ingest_counterparty_pubnonce(n2).unwrap();
    r2.ingest_counterparty_pubnonce(n1).unwrap();

    // Both process the session; parities must agree (same aggregate).
    let par1 = r1.process_session().unwrap();
    let par2 = r2.process_session().unwrap();
    assert_eq!(par1, par2);

    // Each produces and persists its partial (self-verified inside).
    let p1 = r1.produce_local_partial(&mut vault1).unwrap();
    let p2 = r2.produce_local_partial(&mut vault2).unwrap();

    // Each verifies the counterparty partial (M.6.7).
    r1.verify_counterparty_partial(&p2).unwrap();
    r2.verify_counterparty_partial(&p1).unwrap();

    // Aggregate the pre-signature (backend also proves it is NOT final).
    let pre1 = r1.aggregate_pre_signature(&p2).unwrap();
    let pre2 = r2.aggregate_pre_signature(&p1).unwrap();
    assert_eq!(pre1, pre2, "both parties derive the same pre-signature");
    assert_eq!(r1.round(), ClaimRoundV1::PreSignatureReady);

    // The adaptor holder completes: adapt with t, verify, extract t back.
    let final_sig = crypto
        .adapt(&pre1, &s.t, par1, &s.output_xonly, &s.tap_sighash)
        .unwrap();
    crypto
        .verify_bip340(&s.output_xonly, &s.tap_sighash, &final_sig)
        .unwrap();
    let extracted = crypto.extract(&final_sig, &pre1, par1, &s.big_t).unwrap();
    assert_eq!(extracted, s.t, "extracted t equals the original");

    let _ = std::fs::remove_file(&path1);
    let _ = std::fs::remove_file(&path2);
}

#[test]
fn m8_terms_mismatch_fails_before_vault_reservation() {
    let crypto = SecpContext::new(&[0x5a; 32]);
    let s = setup(&crypto);
    let mut keyagg = crypto
        .key_agg(&[
            s.roster.participants()[0].compressed_key,
            s.roster.participants()[1].compressed_key,
        ])
        .unwrap();
    crypto.apply_tap_tweak(&mut keyagg, &s.tweak).unwrap();

    let path = tmp_db("m8_mismatch");
    let mut vault =
        BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new(0xC0)).unwrap();
    let mut wrong_permit = permit(1);
    wrong_permit.terms_hash = [0x99; 32];
    let reservation_id = wrong_permit.reservation_id();
    let m8 = m8_authorization();
    let seal = BitcoinNonceSealKeyV1::new([0x73; 32]).unwrap();

    let result = ClaimRound::prepare_after_m8(
        ClaimRoundInputs {
            crypto: &crypto,
            keyagg: &keyagg,
            roster: &s.roster,
            local: LocalSigner::First,
            local_secret: &s.sk1,
            tap_sighash: &s.tap_sighash,
            adaptor_point: &s.big_t,
            output_xonly: &s.output_xonly,
            permit: &wrong_permit,
        },
        m8,
        &seal,
        &mut vault,
    );
    assert_eq!(result.err(), Some(RoundError::M8AuthorizationMismatch));
    assert!(vault.state_of(&reservation_id).is_err());

    let _ = std::fs::remove_file(&path);
}

#[test]
fn tampered_counterparty_partial_blocks_pre_signature() {
    let crypto = SecpContext::new(&[0x5a; 32]);
    let s = setup(&crypto);
    let mut keyagg1 = crypto
        .key_agg(&[
            s.roster.participants()[0].compressed_key,
            s.roster.participants()[1].compressed_key,
        ])
        .unwrap();
    crypto.apply_tap_tweak(&mut keyagg1, &s.tweak).unwrap();
    let mut keyagg2 = crypto
        .key_agg(&[
            s.roster.participants()[0].compressed_key,
            s.roster.participants()[1].compressed_key,
        ])
        .unwrap();
    crypto.apply_tap_tweak(&mut keyagg2, &s.tweak).unwrap();

    let path1 = tmp_db("tp1");
    let path2 = tmp_db("tp2");
    let mut vault1 =
        BitcoinNonceVault::open_with_entropy(&path1, CountingEntropy::new(0xA0)).unwrap();
    let mut vault2 =
        BitcoinNonceVault::open_with_entropy(&path2, CountingEntropy::new(0xB0)).unwrap();
    let permit1 = permit(1);
    let permit2 = permit(2);

    let mut r1 = ClaimRound::prepare(
        ClaimRoundInputs {
            crypto: &crypto,
            keyagg: &keyagg1,
            roster: &s.roster,
            local: LocalSigner::First,
            local_secret: &s.sk1,
            tap_sighash: &s.tap_sighash,
            adaptor_point: &s.big_t,
            output_xonly: &s.output_xonly,
            permit: &permit1,
        },
        &mut vault1,
    )
    .unwrap();
    let mut r2 = ClaimRound::prepare(
        ClaimRoundInputs {
            crypto: &crypto,
            keyagg: &keyagg2,
            roster: &s.roster,
            local: LocalSigner::Second,
            local_secret: &s.sk2,
            tap_sighash: &s.tap_sighash,
            adaptor_point: &s.big_t,
            output_xonly: &s.output_xonly,
            permit: &permit2,
        },
        &mut vault2,
    )
    .unwrap();
    let n1 = r1.expose_local_pubnonce(&mut vault1).unwrap();
    let n2 = r2.expose_local_pubnonce(&mut vault2).unwrap();
    r1.ingest_counterparty_pubnonce(n2).unwrap();
    r2.ingest_counterparty_pubnonce(n1).unwrap();
    r1.process_session().unwrap();
    r2.process_session().unwrap();
    let _p1 = r1.produce_local_partial(&mut vault1).unwrap();
    let p2 = r2.produce_local_partial(&mut vault2).unwrap();

    // Tamper with the counterparty partial: verification must reject it,
    // and the round never reaches PartialsVerified, so no pre-signature.
    let mut tampered = p2;
    tampered[0] ^= 0x01;
    assert!(r1.verify_counterparty_partial(&tampered).is_err());
    assert_ne!(r1.round(), ClaimRoundV1::PartialsVerified);
    // Even calling aggregate with the (real) partial now fails the round
    // guard, because verification never advanced the round.
    assert!(r1.aggregate_pre_signature(&p2).is_err());

    let _ = std::fs::remove_file(&path1);
    let _ = std::fs::remove_file(&path2);
}
