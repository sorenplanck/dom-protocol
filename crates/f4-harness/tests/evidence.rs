//! Step-4 suite (F4 spec §13): the `RevealedScalarVerifier` against the
//! deterministic mock chain, over evidence the ratified F3 path itself
//! collected. Every §8 refusal is exercised, and the load-bearing
//! distinction — unavailability is an error, never a verdict — has its
//! own test.

use std::sync::{Arc, Mutex};

use adapter_evm::adapter::test_support::{sample_config, FIXTURE_BENEFICIARY, FIXTURE_FUNDER};
use adapter_evm::binding::{
    adaptor_address_of_scalar, adaptor_point_of_scalar, derive_binding, derive_lock_id,
};
use adapter_evm::evidence::amount_word;
use adapter_evm::mock::{Faults, MockChain};
use adapter_evm::rpc::JsonRpc;
use adapter_evm::{EvidenceKind, EvmAdapter, EvmAdapterConfig, LockTerms};
use counterparty_api::{AdaptorPointBytes, RevealedSecretBytes};
use f4_harness::{BondError, RevealedScalarVerifier};
use serde_json::Value;
use uspe::evidence::{EvidenceVerdict, EvidenceVerifier, InvalidEvidence};
use uspe::objects::{
    AssetId, AssurancePolicyV1, ChainId, EvidenceRuleV1, PolicyId, SettlementId, TerminalPolicyV1,
    TimelockSpec, POLICY_STRUCT_VERSION,
};

/// A [`MockChain`] that can be mutated while the adapter holds it.
#[derive(Clone)]
struct SharedChain(Arc<Mutex<MockChain>>);

impl SharedChain {
    fn new(chain: MockChain) -> Self {
        Self(Arc::new(Mutex::new(chain)))
    }
    fn with_mut<T>(&self, f: impl FnOnce(&mut MockChain) -> T) -> T {
        f(&mut self.0.lock().expect("mock chain lock"))
    }
}

impl JsonRpc for SharedChain {
    fn call(&self, method: &str, params: Value) -> Result<Value, counterparty_api::AdapterError> {
        self.0
            .lock()
            .map_err(|_| counterparty_api::AdapterError::AdapterUnavailable)?
            .call(method, params)
    }
}

const AMOUNT: u128 = 1_000_000;
const LOCK_DEADLINE: u64 = 9_000;
const EVIDENCE_DEADLINE: u64 = 3_000;

fn secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = 0x2a;
    s[3] = 0x77;
    s
}

/// The settlement-leg scenario the evidence talks about: the F3 lock
/// whose `Claimed` reveals the scalar.
struct Scenario {
    cfg: EvmAdapterConfig,
    chain: SharedChain,
    lock_id: [u8; 32],
    binding: [u8; 32],
    terms: LockTerms,
}

fn scenario() -> Scenario {
    let chain = MockChain::new(sample_config().chain_id, sample_config().contract);
    let mut cfg = sample_config();
    cfg.expected_code_hash = chain.code_hash();
    let mut terms = adapter_evm::adapter::test_support::sample_terms(&cfg);
    terms.adaptor_address = adaptor_address_of_scalar(&secret()).expect("canonical scalar");
    terms.amount = amount_word(AMOUNT);
    terms.deadline = LOCK_DEADLINE;
    let binding = derive_binding(cfg.chain_id, &cfg.contract, &terms).expect("binding");
    let lock_id = derive_lock_id(&binding, &cfg.funder).expect("lock id");
    Scenario {
        cfg,
        chain: SharedChain::new(chain),
        lock_id,
        binding,
        terms,
    }
}

impl Scenario {
    fn adapter(&self) -> EvmAdapter<SharedChain> {
        let adapter = EvmAdapter::new(self.cfg, self.chain.clone()).expect("valid configuration");
        // Collection only serves TRACKED locks — the same discipline the
        // F3 leg runs under.
        adapter.track_lock(&self.terms).expect("track");
        adapter
    }

    /// Mines open + claim and finalizes the tip.
    fn mine_claimed(&self) {
        self.chain.with_mut(|c| {
            c.push_block();
            c.push_lock_opened(
                self.lock_id,
                self.binding,
                FIXTURE_FUNDER,
                FIXTURE_BENEFICIARY,
                self.cfg.asset,
                self.terms.amount,
                self.terms.adaptor_address,
                self.terms.deadline,
            )
            .expect("open log");
            c.push_block();
            c.push_claimed(self.lock_id, self.binding, FIXTURE_BENEFICIARY, secret())
                .expect("claim log");
            let tip = c.height();
            c.set_finalized(tip);
        });
    }

    /// Collects the adapter-attested evidence bytes for `kind`.
    fn evidence(&self, kind: EvidenceKind) -> Vec<u8> {
        self.adapter()
            .collect_evidence(&self.lock_id, kind)
            .expect("evidence collected")
            .encode()
    }
}

fn policy_for(s: &Scenario) -> AssurancePolicyV1 {
    AssurancePolicyV1 {
        policy_id: PolicyId([0x10; 32]),
        version: POLICY_STRUCT_VERSION,
        protected_settlement: SettlementId(s.cfg.session_id),
        terms_hash: s.cfg.terms_hash,
        bond_chain_id: ChainId([0x40; 32]),
        bond_asset: AssetId([0x00; 32]),
        required_collateral: 700,
        compensation_cap: 1_000,
        collateral_deadline: TimelockSpec::TimestampSeconds { value: 1_000 },
        claim_deadline: TimelockSpec::TimestampSeconds { value: 2_000 },
        evidence_deadline: TimelockSpec::TimestampSeconds {
            value: EVIDENCE_DEADLINE,
        },
        bond_release_deadline: TimelockSpec::TimestampSeconds { value: 4_000 },
        evidence_rule: EvidenceRuleV1::RevealedScalarClaim {
            adaptor_point: AdaptorPointBytes(
                adaptor_point_of_scalar(&secret()).expect("canonical scalar"),
            ),
        },
        terminal_policy: TerminalPolicyV1::ConservativeRelease,
    }
}

fn now(t: u64) -> TimelockSpec {
    TimelockSpec::TimestampSeconds { value: t }
}

#[test]
fn a_finalized_bound_claim_inside_the_window_is_valid() {
    let s = scenario();
    s.mine_claimed();
    let policy = policy_for(&s);
    let verifier = RevealedScalarVerifier::new(&policy, s.cfg, s.chain.clone()).expect("verifier");

    let verdict = verifier
        .verify(&policy, &s.evidence(EvidenceKind::Claimed), now(2_500))
        .expect("decidable");
    match verdict {
        EvidenceVerdict::Valid {
            revealed,
            claim_height,
        } => {
            assert_eq!(revealed, RevealedSecretBytes::new(secret()));
            assert!(claim_height > 0);
        }
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[test]
fn funding_evidence_of_the_bound_leg_does_not_prove_failure() {
    let s = scenario();
    s.mine_claimed();
    let policy = policy_for(&s);
    let verifier = RevealedScalarVerifier::new(&policy, s.cfg, s.chain.clone()).expect("verifier");
    let verdict = verifier
        .verify(&policy, &s.evidence(EvidenceKind::Funded), now(2_500))
        .expect("decidable");
    assert_eq!(
        verdict,
        EvidenceVerdict::Invalid(InvalidEvidence::NotABoundClaim)
    );
}

#[test]
fn no_single_byte_tamper_ever_verifies() {
    // The full property, byte by byte: corrupting ANY position of the
    // evidence never yields Valid. Corruption of the DETERMINISTIC half
    // (header, terms, binding) is a verdict — a fact about the bytes —
    // while corruption of a chain-corroborated field (tx hash, block
    // hash) is indistinguishable from a reorg and stays an ERROR, so a
    // forged pointer can never be laundered into a `valid: false` that
    // burns the claim, nor into a `valid: true`.
    let s = scenario();
    s.mine_claimed();
    let policy = policy_for(&s);
    let verifier = RevealedScalarVerifier::new(&policy, s.cfg, s.chain.clone()).expect("verifier");
    let bytes = s.evidence(EvidenceKind::Claimed);
    let (mut verdicts, mut undecidable) = (0usize, 0usize);
    for i in 0..bytes.len() {
        let mut flipped = bytes.clone();
        flipped[i] ^= 0x01;
        match verifier.verify(&policy, &flipped, now(2_500)) {
            Ok(EvidenceVerdict::Valid { .. }) => {
                panic!("byte {i} flipped and the evidence still verified")
            }
            Ok(EvidenceVerdict::Invalid(_)) => verdicts += 1,
            Err(_) => undecidable += 1,
        }
    }
    // Both arms genuinely occur — the split is real, not vacuous.
    assert!(
        verdicts > 0,
        "no flip ever produced a deterministic verdict"
    );
    assert!(
        undecidable > 0,
        "no flip ever landed in the undecidable arm"
    );

    // Pinned: a header flip is Malformed, deterministically.
    let mut magic = bytes.clone();
    magic[0] ^= 0x01;
    assert_eq!(
        verifier
            .verify(&policy, &magic, now(2_500))
            .expect("decidable"),
        EvidenceVerdict::Invalid(InvalidEvidence::Malformed)
    );
}

#[test]
fn a_scalar_that_opens_a_different_commitment_is_refused() {
    // The chain really did see a claim reveal a scalar — but the POLICY
    // protects an obligation bound to a different point. The evidence is
    // real; it just proves nothing about this obligation.
    let s = scenario();
    s.mine_claimed();
    let mut policy = policy_for(&s);
    let mut other = secret();
    other[31] ^= 0x01;
    policy.evidence_rule = EvidenceRuleV1::RevealedScalarClaim {
        adaptor_point: AdaptorPointBytes(
            adaptor_point_of_scalar(&other).expect("canonical scalar"),
        ),
    };
    let verifier = RevealedScalarVerifier::new(&policy, s.cfg, s.chain.clone()).expect("verifier");
    let verdict = verifier
        .verify(&policy, &s.evidence(EvidenceKind::Claimed), now(2_500))
        .expect("decidable");
    assert_eq!(
        verdict,
        EvidenceVerdict::Invalid(InvalidEvidence::WrongScalarPoint)
    );
}

#[test]
fn verification_after_the_evidence_window_refuses_toward_release() {
    let s = scenario();
    s.mine_claimed();
    let policy = policy_for(&s);
    let verifier = RevealedScalarVerifier::new(&policy, s.cfg, s.chain.clone()).expect("verifier");
    let verdict = verifier
        .verify(
            &policy,
            &s.evidence(EvidenceKind::Claimed),
            now(EVIDENCE_DEADLINE + 1),
        )
        .expect("decidable");
    assert_eq!(
        verdict,
        EvidenceVerdict::Invalid(InvalidEvidence::OutsideEvidenceWindow)
    );
}

#[test]
fn a_clock_in_the_wrong_domain_is_an_error_never_a_conversion() {
    let s = scenario();
    s.mine_claimed();
    let policy = policy_for(&s);
    let verifier = RevealedScalarVerifier::new(&policy, s.cfg, s.chain.clone()).expect("verifier");
    let err = verifier
        .verify(
            &policy,
            &s.evidence(EvidenceKind::Claimed),
            TimelockSpec::BlockHeight { value: 2_500 },
        )
        .expect_err("height clock on a timestamp policy");
    assert!(matches!(err, BondError::WrongTimelockDomain));
}

#[test]
fn a_verifier_for_a_different_obligation_refuses_at_construction() {
    let s = scenario();
    let mut policy = policy_for(&s);
    policy.terms_hash = [0xEE; 32];
    let err = match RevealedScalarVerifier::new(&policy, s.cfg, s.chain.clone()) {
        Err(e) => e,
        Ok(_) => panic!("divergent terms hash must refuse"),
    };
    assert!(matches!(err, BondError::PolicyMismatch));
}

#[test]
fn an_unavailable_endpoint_is_an_error_never_a_verdict() {
    // THE load-bearing distinction: a broken RPC endpoint must not be
    // able to push a legitimate claim into ClaimRejected. Evidence is
    // collected while the chain answers, then the transport breaks.
    let s = scenario();
    s.mine_claimed();
    let policy = policy_for(&s);
    let bytes = s.evidence(EvidenceKind::Claimed);
    let verifier = RevealedScalarVerifier::new(&policy, s.cfg, s.chain.clone()).expect("verifier");

    s.chain.with_mut(|c| {
        let broken = c.clone().with_faults(Faults {
            break_transport: true,
            ..Faults::default()
        });
        *c = broken;
    });

    let err = verifier
        .verify(&policy, &bytes, now(2_500))
        .expect_err("unavailability must be an error");
    assert!(
        matches!(err, BondError::Adapter(_)),
        "an endpoint failure surfaced as {err:?} — it must never be a verdict"
    );
}
