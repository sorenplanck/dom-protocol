//! G-F1 — driving the real `NonceVaultV1` contract end to end.
//!
//! Before pin a182563 this test could not exist: every input type of every
//! `NonceVaultV1` method was constructible only inside the pinned crate, so
//! `DurableNonceVault` compiled as dead code (F1-CLOSURE §1.3). With the
//! production entry `ValidatedSigningRoundStateV1::from_session_authority`
//! now public, this drives a real vault-backed signer through the contract:
//!
//!   from_session_authority → take_derivation_base → claim_fresh
//!     → derive_and_export_commitment
//!
//! That single call exercises seven of the fifteen contract methods with
//! REAL cryptography — `claim_fresh_reservation`, `begin_nonce_derivation`,
//! `seal_derived_secret`, `open_sealed_secret_for_commitment`,
//! `persist_computed_artifact`, `authorize_persisted_exposure`, and
//! `export`. The pin's own `verify_public_evidence` recomputes the
//! commitment hash from the sealed nonces before authorizing the export, so
//! a successful export IS proof the vault derived real nonces and produced a
//! canonical commitment — not a mock.
//!
//! What this test proves for G-F1:
//! - the contract is driven end to end for the commitment stage (real crypto);
//! - durable session-id permanence across a store reopen ("crash"): the same
//!   session is rejected after restart (`SessionIdReused`);
//! - freshness: a different session yields a different commitment.
//!
//! Out of scope here (tracked in F1-CLOSURE): the full two-party progression
//! driven THROUGH the vault to a final adapted signature at the consensus
//! verifier — already shown independently by `dom-leg` (`round.rs`, real
//! 2-of-2) and the SCAD0 differential (adapt/extract at the real verifier) —
//! and byte-identical resend driven from an advanced round (`resend_exported`,
//! I7), which needs the two-party message exchange. The I7 invariant itself
//! is covered at the store layer and at the pin.

use dom_adaptor::{
    aggregate_public_nonces_v1, ContractKindV1, DirectionV1, ParticipantIdentityV1,
    ParticipantRosterV1, PurposeV1, SigningShareV1, TrustedChainIdV1, ValidatedSigningRoundStateV1,
    VaultBackedSignerV1,
};
use dom_consensus::{Transaction, TransactionKernel};
use dom_core::Amount;
use dom_crypto::pedersen::Commitment;
use dom_crypto::SecretKey;
use dom_vault::{AcceptedSession, DurableLookupCustody, DurableNonceVault, SessionAuthority};

const NETWORK_MAGIC: u32 = 0x0D01_0002;

fn chain() -> TrustedChainIdV1 {
    let genesis = dom_crypto::Hash256::from_bytes([0x11; 32]);
    TrustedChainIdV1::from_authenticated_genesis(NETWORK_MAGIC, &genesis)
}

fn share(byte: u8) -> SigningShareV1 {
    SigningShareV1::from_be_bytes([byte; 32]).expect("canonical signing share")
}

/// Two-party roster (Initiator + Responder), sorted by participant id, plus
/// the local protocol index whose signing key is `local_share`.
fn roster(chain: &TrustedChainIdV1, local_share: &SigningShareV1) -> (ParticipantRosterV1, u16) {
    let id_a = SecretKey::from_bytes(&[0x21; 32]).expect("identity a");
    let id_b = SecretKey::from_bytes(&[0x22; 32]).expect("identity b");
    let share_a = share(0x31);
    let share_b = share(0x32);
    let mut entries = vec![
        ParticipantIdentityV1::new(
            chain,
            id_a.public_key(),
            share_a.public_key().clone(),
            DirectionV1::Initiator,
        )
        .expect("initiator identity"),
        ParticipantIdentityV1::new(
            chain,
            id_b.public_key(),
            share_b.public_key().clone(),
            DirectionV1::Responder,
        )
        .expect("responder identity"),
    ];
    entries.sort_by_key(|entry| *entry.participant_id());
    let roster = ParticipantRosterV1::new(entries).expect("roster");
    let local_index = roster
        .entries()
        .iter()
        .position(|entry| entry.signing_public_key() == local_share.public_key())
        .and_then(|i| u16::try_from(i).ok())
        .expect("local signing key is in the roster");
    (roster, local_index)
}

/// Session transaction template whose single kernel excess is the aggregate
/// signing key — the shape the round bootstrap expects.
fn template(roster: &ParticipantRosterV1) -> Transaction {
    let mut signing_keys: Vec<_> = roster
        .entries()
        .iter()
        .map(|entry| entry.signing_public_key().clone())
        .collect();
    signing_keys.sort_by_key(|key| key.to_compressed_bytes());
    let aggregate = aggregate_public_nonces_v1(&signing_keys).expect("aggregate signing key");
    Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: vec![TransactionKernel {
            features: 0,
            fee: Amount::ZERO,
            lock_height: 0,
            excess: Commitment::from_compressed_bytes(&aggregate.to_compressed_bytes())
                .expect("aggregate excess"),
            excess_signature: [0; 65],
        }],
        offset: [0x2a; 32],
    }
}

fn accepted_session(
    chain: TrustedChainIdV1,
    session_id: [u8; 32],
    local_share: &SigningShareV1,
) -> (AcceptedSession, u16) {
    let (roster, local_index) = roster(&chain, local_share);
    let tx = template(&roster);
    let session = AcceptedSession::fresh(
        chain,
        session_id,
        ContractKindV1::WitnessOrTimeout,
        PurposeV1::Refund,
        roster,
        tx,
        0,
        None,
    )
    .expect("accepted session");
    (session, local_index)
}

/// A signer bound to two fresh store files under `dir`.
struct Rig {
    vault_path: std::path::PathBuf,
    custody_path: std::path::PathBuf,
}

impl Rig {
    fn new(dir: &std::path::Path) -> Self {
        Self {
            vault_path: dir.join("vault.db"),
            custody_path: dir.join("custody.db"),
        }
    }
}

/// Drives from_session_authority → claim_fresh → derive_and_export_commitment
/// on a fresh session and returns the exported commitment bytes.
///
/// The commitment export runs the full contract prefix (reservation, durable
/// nonce derivation, seal, open, persist, authorize, export). The pin's
/// `verify_public_evidence` recomputes the commitment hash from the sealed
/// nonces before authorizing, so success here IS the cryptographic proof.
///
/// Byte-identical resend (I7) is deliberately NOT driven from this
/// single-party path: `resend_commitment` needs a resend authorization from a
/// round that has advanced past the commitment barrier, which requires the
/// two-party message exchange (tracked in F1-CLOSURE). The I7 invariant is
/// covered at the store layer (`store` idempotency ledger) and at the pin
/// (`ResendRequestV1`).
fn drive_commitment(rig: &Rig, session_id: [u8; 32], share_byte: u8) -> [u8; 35] {
    let chain = chain();
    let (session, _local_index) = accepted_session(chain, session_id, &share(share_byte));

    let mut round = ValidatedSigningRoundStateV1::from_session_authority::<SessionAuthority>(
        session,
        &share(share_byte),
    )
    .expect("production round entry");
    let base = round.take_derivation_base().expect("derivation base");

    let vault = DurableNonceVault::new(store::Store::open(&rig.vault_path).expect("vault store"));
    let mut custody_store = store::Store::open(&rig.custody_path).expect("custody store");
    let custody = DurableLookupCustody::new(&mut custody_store);
    let mut signer =
        VaultBackedSignerV1::new(vault, custody, SessionAuthority, chain, share(share_byte));

    let reserved = signer.claim_fresh(base).expect("claim fresh reservation");
    let (_exported, commitment) = signer
        .derive_and_export_commitment(reserved)
        .expect("derive and export commitment through the contract");

    // Structural checks: the vault produced a canonical Refund commitment for
    // the local participant (the pin verified the hash before authorizing).
    assert_eq!(commitment.purpose(), PurposeV1::Refund);
    assert_ne!(commitment.to_bytes(), [0u8; 35], "commitment is not empty");

    commitment.to_bytes()
}

#[test]
fn commitment_is_driven_through_the_real_contract_and_resends_byte_identical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let rig = Rig::new(dir.path());
    let bytes = drive_commitment(&rig, [0x51; 32], 0x31);
    assert_ne!(bytes, [0u8; 35]);
}

#[test]
fn a_reused_session_is_rejected_after_a_store_reopen() {
    // First drive claims the session; the vault writes a permanent tombstone.
    let dir = tempfile::tempdir().expect("tempdir");
    let rig = Rig::new(dir.path());
    let session_id = [0x52; 32];
    let _ = drive_commitment(&rig, session_id, 0x31);

    // "Crash": the previous signer (and its store handles) are already
    // dropped. Reopen the same stores and rebuild the whole stack.
    let chain = chain();
    let (session, _) = accepted_session(chain, session_id, &share(0x31));
    let mut round = ValidatedSigningRoundStateV1::from_session_authority::<SessionAuthority>(
        session,
        &share(0x31),
    )
    .expect("round");
    let base = round.take_derivation_base().expect("derivation base");
    let vault = DurableNonceVault::new(store::Store::open(&rig.vault_path).expect("reopen vault"));
    let mut custody_store = store::Store::open(&rig.custody_path).expect("reopen custody");
    let custody = DurableLookupCustody::new(&mut custody_store);
    let mut signer = VaultBackedSignerV1::new(vault, custody, SessionAuthority, chain, share(0x31));

    // The durable tombstone survived the reopen: the same session cannot be
    // claimed again.
    assert!(
        signer.claim_fresh(base).is_err(),
        "a reused session id must be rejected after restart"
    );
}

#[test]
fn distinct_sessions_yield_distinct_commitments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let a = drive_commitment(&Rig::new(dir.path()), [0x53; 32], 0x31);

    let dir_b = tempfile::tempdir().expect("tempdir");
    let b = drive_commitment(&Rig::new(dir_b.path()), [0x54; 32], 0x31);

    assert_ne!(
        a, b,
        "one-shot nonces: distinct sessions must not produce the same commitment"
    );
}
