//! ROUND-3 ADVERSARIAL AUDIT — the DOM settlement session is not bound.
//!
//! `crates/adapters/evm/src/evidence.rs` states, in the module header, that an
//! `EvmEvidence` "is only meaningful if it cannot be replayed anywhere else"
//! and that [`EvmEvidence::verify_static`] "re-derives **or re-checks**" a
//! table of bindings whose third row is:
//!
//! > | full `LockTerms` (incl. `session_id`, `terms_hash`) | ties the fact to
//! > one DOM settlement |
//!
//! It does not. `verify_static` compares seven of the configuration's fields
//! against the evidence — `chain_id`, `contract`, `code_hash`, `dom_chain_id`,
//! `direction`, `participants_hash`, `asset`, `beneficiary`, `funder` — and
//! omits exactly the two that name the settlement: `session_id` and
//! `terms_hash`. The same crate's own `EvmAdapter::check_terms_against_config`
//! *does* include both, so the two lists disagree by exactly the two fields
//! that make a fact "this settlement's" rather than "that contract's".
//!
//! The re-derivation is not a substitute. `derive_binding` is computed from the
//! evidence's **own** `terms`, so a blob whose `session_id`, `terms_hash`,
//! `binding` and `lock_id` are mutually consistent passes it — it proves the
//! blob is internally coherent, never that it is coherent with *this adapter*.
//!
//! Consequence: a genuine, fully corroborated on-chain settlement belonging to
//! a **different DOM session** — same chain, same contract, same funder,
//! beneficiary, asset, roster and direction — verifies, and
//! `EvmAdapter::verify_evidence_blocking` hands the caller
//! `VerifiedOutcome::Claimed { revealed }` carrying *that* session's scalar.
//! Nothing in `verify_onchain` closes it either: every chain-side check is
//! satisfied, because the settlement really happened.
//!
//! Nothing here touches a network; the whole finding is in the pure half.
//!
//! Run: `cargo test -p adapter-evm --test audit_r3_session_binding`

mod common;

use adapter_evm::adapter::test_support::{sample_config, sample_terms};
use adapter_evm::rpc::EthClient;
use adapter_evm::{
    adaptor_address_of_scalar, derive_binding, derive_lock_id, EvidenceKind, EvidencePayload,
    EvmAdapterConfig, EvmEvidence,
};
use counterparty_api::AdapterError;

/// A canonical, non-zero scalar with a derivable `address(t*G)`.
fn scalar(n: u8) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[31] = n;
    t[5] = n;
    t
}

/// Builds a **self-consistent** claim record: `binding` and `lock_id` are
/// derived from the terms it carries, so every re-derivation in
/// `verify_static` succeeds. Only the two settlement-naming fields are the
/// attacker's choice.
fn coherent_claim(
    cfg: &EvmAdapterConfig,
    session_id: [u8; 32],
    terms_hash: [u8; 32],
) -> EvmEvidence {
    let t = scalar(9);
    let mut terms = sample_terms(cfg);
    terms.adaptor_address = adaptor_address_of_scalar(&t).expect("canonical scalar");
    terms.session_id = session_id;
    terms.terms_hash = terms_hash;
    let binding = derive_binding(cfg.chain_id, &cfg.contract, &terms).expect("binding");
    let lock_id = derive_lock_id(&binding, &cfg.funder).expect("lock id");
    EvmEvidence {
        version: 1,
        kind: EvidenceKind::Claimed,
        chain_id: cfg.chain_id,
        contract: cfg.contract,
        code_hash: cfg.expected_code_hash,
        funder: cfg.funder,
        terms,
        binding,
        lock_id,
        block_number: 5,
        block_hash: [0x51; 32],
        tx_hash: [0x52; 32],
        log_index: 0,
        finalized_height: 7,
        finalized_block_hash: [0x53; 32],
        payload: EvidencePayload::ClaimedScalar(t),
    }
}

#[test]
fn the_fixture_is_honest_about_the_matching_case() {
    // The premise: with this adapter's own session the record verifies. Without
    // this, the assertion below could be passing for the wrong reason.
    let cfg = sample_config();
    let mine = coherent_claim(&cfg, cfg.session_id, cfg.terms_hash);
    assert!(
        mine.verify_static(&cfg).is_ok(),
        "the matching-session control must verify, or the negative case proves \
         nothing",
    );
}

#[test]
fn a_claim_from_a_foreign_dom_session_must_not_verify_statically() {
    let cfg = sample_config();
    let foreign = coherent_claim(&cfg, [0x77; 32], [0x88; 32]);
    assert_ne!(foreign.terms.session_id, cfg.session_id);
    assert_ne!(foreign.terms.terms_hash, cfg.terms_hash);
    assert_eq!(
        foreign.verify_static(&cfg).map(|_| ()),
        Err(AdapterError::EvidenceInvalid),
        "a settlement of ANOTHER DOM session, on the same contract and with the \
         same parties, is not a fact about this settlement — but verify_static \
         never compares session_id or terms_hash against the configuration, so \
         it returns Claimed and hands the caller the other session's scalar",
    );
}

/// The whole path, not just the pure half: a **real** settlement of another
/// DOM session, mined on the very chain this adapter watches, put through
/// `EvmAdapter::verify_evidence_blocking`.
///
/// Every chain-side check passes because the settlement genuinely happened —
/// receipt, transaction, canonical block and finalized ancestry all corroborate
/// it. The only thing that could refuse it is the static session binding, and
/// there is none, so the adapter answers `Claimed` and returns the *other*
/// session's revealed scalar to its caller.
#[test]
fn the_adapter_must_not_verify_another_sessions_settlement_end_to_end() {
    let s = common::scenario(7);
    let cfg = s.cfg;

    // The other session: same deployment, same parties, same asset, same
    // adaptor point — only the two settlement-naming fields differ.
    let mut foreign_terms = s.terms;
    foreign_terms.session_id = [0x99; 32];
    foreign_terms.terms_hash = [0xAA; 32];
    let foreign_binding =
        derive_binding(cfg.chain_id, &cfg.contract, &foreign_terms).expect("binding");
    let foreign_lock = derive_lock_id(&foreign_binding, &cfg.funder).expect("lock id");
    assert_ne!(foreign_lock, s.lock_id, "fixture: a different lock");

    // Mine and finalize the other session's claim.
    let claim_height = s.chain.with_mut(|c| {
        let h = c.push_block();
        c.push_claimed(foreign_lock, foreign_binding, cfg.beneficiary, s.secret)
            .expect("log appended");
        h
    });
    s.mine(3);
    s.finalize_tip();

    // Read the log back exactly as an observer would, so every positional field
    // in the evidence is the chain's own answer rather than a guess.
    let log = EthClient::new(&s.chain)
        .logs(
            claim_height,
            claim_height,
            &cfg.contract,
            &[EvidenceKind::Claimed.topic0()],
        )
        .expect("logs")
        .into_iter()
        .next()
        .expect("the claim is on chain");
    let head = adapter_evm::finality::fetch_finalized(&s.chain).expect("finalized");

    let evidence = EvmEvidence {
        version: 1,
        kind: EvidenceKind::Claimed,
        chain_id: cfg.chain_id,
        contract: cfg.contract,
        code_hash: cfg.expected_code_hash,
        funder: cfg.funder,
        terms: foreign_terms,
        binding: foreign_binding,
        lock_id: foreign_lock,
        block_number: log.block_number,
        block_hash: log.block_hash,
        tx_hash: log.tx_hash,
        log_index: log.log_index,
        finalized_height: head.height,
        finalized_block_hash: head.hash,
        payload: EvidencePayload::ClaimedScalar(s.secret),
    };

    let outcome = s.adapter().verify_evidence_blocking(&evidence.encode());
    assert_eq!(
        outcome.map(|_| ()),
        Err(AdapterError::EvidenceInvalid),
        "the adapter is configured for session {:?} and this settlement belongs \
         to session {:?}; accepting it hands the caller a VerifiedOutcome that \
         names a scalar revealed for a different DOM settlement",
        cfg.session_id[0],
        foreign_terms.session_id[0],
    );
}

#[test]
fn each_settlement_naming_field_is_checked_on_its_own() {
    // Separated so a fix that binds only one of the two cannot pass.
    let cfg = sample_config();

    let other_session = coherent_claim(&cfg, [0x77; 32], cfg.terms_hash);
    assert_eq!(
        other_session.verify_static(&cfg).map(|_| ()),
        Err(AdapterError::EvidenceInvalid),
        "session_id alone must be enough to refuse",
    );

    let other_terms = coherent_claim(&cfg, cfg.session_id, [0x88; 32]);
    assert_eq!(
        other_terms.verify_static(&cfg).map(|_| ()),
        Err(AdapterError::EvidenceInvalid),
        "terms_hash alone must be enough to refuse",
    );
}
