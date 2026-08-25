//! The two lists that bind a settlement must stay one list.
//!
//! Round 3 of the audit found `EvmEvidence::verify_static` and
//! `EvmAdapter::check_terms_against_config` maintaining, by hand, two copies of
//! "the fields this configuration names", and the copies had drifted apart by
//! `session_id` and `terms_hash` — the two fields that make a fact *this
//! settlement's* rather than *that contract's*. The fix collapsed the shared
//! part into [`EvmAdapterConfig::binds_terms`], which both call sites consume.
//!
//! # Why the existing tests could not see it
//!
//! The audit's mutation sweep left **seven survivors** in `verify_static`'s
//! configuration chain: every field named there is *also* inside the `binding`
//! / `lock_id` preimage, and the pre-existing tests mutate one field and watch
//! the record be refused — which the re-derivation does first, every time. The
//! configuration comparison was never the reason a test went red, so the two
//! fields with no re-derivation backstop were invisible.
//!
//! Every case in this file therefore keeps the record **internally coherent**:
//! `binding` and `lock_id` are recomputed from the mutated content, so every
//! re-derivation succeeds and the *comparison against the configuration* is the
//! only thing that can refuse. Each case also proves the record verifies once
//! the configuration is moved by the same step — so the refusal is attributable
//! to the disagreement and to nothing else.
//!
//! The walk is two-way, which is what pins the list at exactly its right
//! length:
//!
//! - every field the configuration names must be refused by both call sites
//!   when it differs (a list that loses a field fails here), and
//! - every field the configuration does not name must be accepted by both (a
//!   list that gains one fails here too).
//!
//! Run: `cargo test -p adapter-evm --test session_binding_is_one_list`

mod common;

use adapter_evm::adapter::test_support::{
    sample_config, sample_terms, FIXTURE_BENEFICIARY, FIXTURE_CHAIN_ID, FIXTURE_CONTRACT,
    FIXTURE_FUNDER,
};
use adapter_evm::evidence::amount_word;
use adapter_evm::mock::MockChain;
use adapter_evm::rpc::EthClient;
use adapter_evm::{
    adaptor_address_of_scalar, derive_binding, derive_lock_id, Direction, EvidenceKind, EvmAdapter,
    EvmAdapterConfig, EvmEvidence, LockTerms,
};
use counterparty_api::{AdapterError, VerifiedOutcome};

/// A canonical, non-zero scalar with a derivable `address(t*G)`.
fn scalar(n: u8) -> [u8; 32] {
    let mut t = [0u8; 32];
    t[31] = n;
    t[5] = n;
    t
}

/// Terms for [`sample_config`] whose adaptor address really opens under `t`.
fn base_terms(cfg: &EvmAdapterConfig, t: &[u8; 32]) -> LockTerms {
    let mut terms = sample_terms(cfg);
    terms.adaptor_address = adaptor_address_of_scalar(t).expect("canonical scalar");
    terms
}

/// An **internally coherent** claim record over `terms`.
fn coherent_claim(cfg: &EvmAdapterConfig, terms: LockTerms, t: [u8; 32]) -> EvmEvidence {
    let mut e = EvmEvidence {
        version: 1,
        kind: EvidenceKind::Claimed,
        chain_id: cfg.chain_id,
        contract: cfg.contract,
        code_hash: cfg.expected_code_hash,
        funder: cfg.funder,
        terms,
        binding: [0u8; 32],
        lock_id: [0u8; 32],
        block_number: 5,
        block_hash: [0x51; 32],
        tx_hash: [0x52; 32],
        log_index: 0,
        finalized_height: 7,
        finalized_block_hash: [0x53; 32],
        payload: t,
    };
    recohere(&mut e);
    e
}

/// Recomputes `binding` and `lock_id` from whatever the record now says, so
/// that no re-derivation in `verify_static` can be the reason it is refused.
fn recohere(e: &mut EvmEvidence) {
    e.binding = derive_binding(e.chain_id, &e.contract, &e.terms).expect("binding");
    e.lock_id = derive_lock_id(&e.binding, &e.funder).expect("lock id");
}

/// An adapter over a default mock chain, for the `track_lock` side.
fn adapter_for(cfg: EvmAdapterConfig) -> EvmAdapter<MockChain> {
    EvmAdapter::new(cfg, MockChain::new(FIXTURE_CHAIN_ID, FIXTURE_CONTRACT))
        .expect("valid configuration")
}

/// One named field, with the two edits that move the record and the
/// configuration by the same step.
type FieldCase = (&'static str, fn(&mut LockTerms), fn(&mut EvmAdapterConfig));

/// One named `LockTerms` field the configuration does not name.
type PerLockCase = (&'static str, fn(&mut LockTerms));

/// One named configuration field that is not a term, with the two edits that
/// move the record and the configuration by the same step.
type DeploymentCase = (
    &'static str,
    fn(&mut EvmEvidence),
    fn(&mut EvmAdapterConfig),
);

/// The `LockTerms` fields the configuration names. Both call sites must refuse
/// each one, and accept it again once the configuration agrees.
///
/// Written out by hand *on purpose*: a hand-written expectation is the only
/// thing that can catch the production list shrinking.
const CONFIGURED: &[FieldCase] = &[
    (
        "dom_chain_id",
        |t| t.dom_chain_id[0] ^= 1,
        |c| c.dom_chain_id[0] ^= 1,
    ),
    (
        "direction",
        |t| t.direction ^= 1,
        |c| {
            c.direction = match c.direction {
                Direction::DomToEvm => Direction::EvmToDom,
                Direction::EvmToDom => Direction::DomToEvm,
            }
        },
    ),
    (
        "session_id",
        |t| t.session_id[0] ^= 1,
        |c| c.session_id[0] ^= 1,
    ),
    (
        "terms_hash",
        |t| t.terms_hash[0] ^= 1,
        |c| c.terms_hash[0] ^= 1,
    ),
    (
        "participants_hash",
        |t| t.participants_hash[0] ^= 1,
        |c| c.participants_hash[0] ^= 1,
    ),
    ("asset", |t| t.asset[0] ^= 1, |c| c.asset[0] ^= 1),
    (
        "beneficiary",
        |t| t.beneficiary[0] ^= 1,
        |c| c.beneficiary[0] ^= 1,
    ),
];

/// The `LockTerms` fields the configuration does **not** name: they belong to
/// one lock, not to the settlement, and a configuration has nothing to compare
/// them against. Both call sites must accept them.
///
/// `adaptor_address` is the third such field and is deliberately absent: it is
/// per-lock too, but a claim's `address(t·G)` re-derivation pins it, so
/// changing it is refused for a reason that has nothing to do with this list.
const PER_LOCK: &[PerLockCase] = &[
    ("amount", |t| t.amount[31] ^= 1),
    ("deadline", |t| t.deadline += 1),
];

#[test]
fn both_call_sites_bind_exactly_the_same_terms_fields() {
    let cfg = sample_config();
    let adapter = adapter_for(cfg);
    let t = scalar(9);
    let terms = base_terms(&cfg, &t);

    // The control, so a refusal below is never passing for the wrong reason.
    assert_eq!(adapter.track_lock(&terms).map(|_| ()), Ok(()));
    assert!(coherent_claim(&cfg, terms, t).verify_static(&cfg).is_ok());

    for (name, mutate_terms, mutate_cfg) in CONFIGURED {
        let mut mutated = terms;
        mutate_terms(&mut mutated);
        let record = coherent_claim(&cfg, mutated, t);

        assert_eq!(
            adapter.track_lock(&mutated).map(|_| ()),
            Err(AdapterError::PreconditionUnsatisfied),
            "check_terms_against_config does not bind `{name}`",
        );
        assert_eq!(
            record.verify_static(&cfg).map(|_| ()),
            Err(AdapterError::EvidenceInvalid),
            "verify_static does not bind `{name}` — the two lists have drifted \
             apart again, which is exactly how a settlement of another DOM \
             session became verifiable",
        );

        // ... and the record is otherwise impeccable: move the configuration
        // by the same step and it verifies. The disagreement was the reason.
        let mut agreeing = cfg;
        mutate_cfg(&mut agreeing);
        assert!(
            record.verify_static(&agreeing).is_ok(),
            "the `{name}` case is refused for some reason other than the \
             comparison it is meant to exercise",
        );
        assert_eq!(
            adapter_for(agreeing).track_lock(&mutated).map(|_| ()),
            Ok(()),
        );
    }

    for (name, mutate_terms) in PER_LOCK {
        let mut mutated = terms;
        mutate_terms(&mut mutated);
        assert_eq!(
            adapter.track_lock(&mutated).map(|_| ()),
            Ok(()),
            "check_terms_against_config binds `{name}`, which no configuration \
             names",
        );
        assert!(
            coherent_claim(&cfg, mutated, t).verify_static(&cfg).is_ok(),
            "verify_static binds `{name}`, which no configuration names",
        );
    }
}

/// The four configuration fields that are not terms: `chain_id`, `contract`,
/// `expected_code_hash` and `funder`.
///
/// `check_terms_against_config` cannot compare them — a `LockTerms` does not
/// carry them — and does not need to: `track_lock` sources every derivation
/// input from the configuration itself, so the terms cannot disagree with them
/// by construction. `verify_static` is handed a whole record and must compare
/// all four, which is what this pins, again with every re-derivation left
/// satisfied.
#[test]
fn verify_static_binds_the_configuration_fields_that_are_not_terms() {
    let cfg = sample_config();
    let t = scalar(9);
    let base = coherent_claim(&cfg, base_terms(&cfg, &t), t);

    let cases: &[DeploymentCase] = &[
        ("chain_id", |e| e.chain_id ^= 1, |c| c.chain_id ^= 1),
        ("contract", |e| e.contract[0] ^= 1, |c| c.contract[0] ^= 1),
        (
            "code_hash",
            |e| e.code_hash[0] ^= 1,
            |c| c.expected_code_hash[0] ^= 1,
        ),
        ("funder", |e| e.funder[0] ^= 1, |c| c.funder[0] ^= 1),
    ];

    for (name, mutate_evidence, mutate_cfg) in cases {
        let mut record = base;
        mutate_evidence(&mut record);
        // Re-derive over the mutated record: `chain_id`, `contract` and
        // `funder` are all inside the `binding` / `lockId` preimages, and a
        // record that fails *those* proves nothing about the comparison.
        recohere(&mut record);

        assert_eq!(
            record.verify_static(&cfg).map(|_| ()),
            Err(AdapterError::EvidenceInvalid),
            "verify_static does not compare `{name}` against the configuration",
        );
        let mut agreeing = cfg;
        mutate_cfg(&mut agreeing);
        assert!(
            record.verify_static(&agreeing).is_ok(),
            "the `{name}` case is refused for some reason other than the \
             comparison it is meant to exercise",
        );
    }
}

/// The P2 the round-3 auditor found behind the P1, and its remedy.
///
/// A verified record names a **settlement**, not a **lock**: `amount`,
/// `deadline` and the adaptor point are per-lock and no `EvmAdapterConfig`
/// carries them, so a second lock of *this* session — different amount,
/// different `lockId` — verifies through the entry point that names no lock.
/// The gap is documented in the `adapter_evm::evidence` module header, together
/// with why the tracked-lock gate cannot close it: verification must serve a
/// cold verifier, and the same record must not verify in one process and fail
/// in another.
///
/// **If a later change closes the gap, the first assertion below becomes
/// `Err` — update it, and the module header with it. Do not delete it.**
#[test]
fn a_second_lock_of_this_session_verifies_until_the_lock_is_named() {
    let s = common::scenario(7);
    let cfg = s.cfg;

    // Same session, same parties, same adaptor point — one wei.
    let mut dust_terms = s.terms;
    dust_terms.amount = amount_word(1);
    let dust_binding = derive_binding(cfg.chain_id, &cfg.contract, &dust_terms).expect("binding");
    let dust_lock = derive_lock_id(&dust_binding, &cfg.funder).expect("lock id");
    assert_ne!(dust_lock, s.lock_id, "fixture: a different lock");

    let height = s.chain.with_mut(|c| {
        let h = c.push_block();
        c.push_lock_opened(
            dust_lock,
            dust_binding,
            FIXTURE_FUNDER,
            FIXTURE_BENEFICIARY,
            cfg.asset,
            dust_terms.amount,
            dust_terms.adaptor_address,
            dust_terms.deadline,
        )
        .expect("log appended");
        h
    });
    s.mine(2);
    s.finalize_tip();

    let log = EthClient::new(&s.chain)
        .logs(
            height,
            height,
            &cfg.contract,
            &[EvidenceKind::Funded.topic0()],
        )
        .expect("logs")
        .into_iter()
        .next()
        .expect("the funding is on chain");
    let head = adapter_evm::finality::fetch_finalized(&s.chain).expect("finalized");
    let bytes = EvmEvidence {
        version: 1,
        kind: EvidenceKind::Funded,
        chain_id: cfg.chain_id,
        contract: cfg.contract,
        code_hash: cfg.expected_code_hash,
        funder: cfg.funder,
        terms: dust_terms,
        binding: dust_binding,
        lock_id: dust_lock,
        block_number: log.block_number,
        block_hash: log.block_hash,
        tx_hash: log.tx_hash,
        log_index: log.log_index,
        finalized_height: head.height,
        finalized_block_hash: head.hash,
        payload: dust_terms.amount,
    }
    .encode();

    let a = s.adapter();
    assert_eq!(
        a.verify_evidence_blocking(&bytes),
        Ok(VerifiedOutcome::Funded { height }),
        "documented P2: an entry point that names no lock can only answer for \
         the settlement, and this funding really is this settlement's",
    );

    // The remedy: name the lock. No observer state is consulted, so a cold
    // verifier gets the same answer.
    assert_eq!(
        a.verify_evidence_for_lock(&bytes, &s.lock_id).map(|_| ()),
        Err(AdapterError::EvidenceInvalid),
        "a caller that named the lock it is waiting for must not be handed \
         another lock's funding",
    );
    assert_eq!(
        a.verify_evidence_for_lock(&bytes, &dust_lock),
        Ok(VerifiedOutcome::Funded { height }),
        "control: naming the lock the record really is must still verify",
    );
}
