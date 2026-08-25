//! Step-3 suite (F4 spec §13): the `EvmBondAdapter` against the
//! deterministic `adapter-evm` mock chain. Geometry, refusals, the three
//! spend artifacts and the observation filter — no network anywhere.

use std::cell::RefCell;
use std::sync::{Arc, Mutex};

use adapter_evm::abi::{selector, word_bytes32, word_u256, SIG_CLAIM, SIG_OPEN, SIG_REFUND};
use adapter_evm::adapter::test_support::{sample_config, FIXTURE_BENEFICIARY, FIXTURE_FUNDER};
use adapter_evm::binding::adaptor_point_of_scalar;
use adapter_evm::evidence::amount_word;
use adapter_evm::mock::MockChain;
use adapter_evm::rpc::JsonRpc;
use adapter_evm::UnsignedEvmCall;
use counterparty_api::{AdapterError, AdaptorPointBytes, ChainCursor, RevealedSecretBytes};
use f4_harness::{BondBroadcaster, BondDeployment, BondError, EvmBondAdapter, FixedClock};
use serde_json::Value;
use uspe::bond::{BondAdapter, BondEvent, BroadcastOutcome};
use uspe::objects::{
    AssetId, AssurancePolicyV1, ChainId, EvidenceRuleV1, PolicyId, SettlementId, TerminalPolicyV1,
    TimelockSpec, POLICY_STRUCT_VERSION,
};

/// secp256k1 group order, big-endian — the smallest non-canonical scalar.
const SECP256K1_N_BYTES: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

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
    fn call(&self, method: &str, params: Value) -> Result<Value, AdapterError> {
        self.0
            .lock()
            .map_err(|_| AdapterError::AdapterUnavailable)?
            .call(method, params)
    }
}

/// Records every offered artifact and dedupes byte-identically (I7),
/// exactly as a well-behaved chain endpoint would.
#[derive(Default)]
struct RecordingBroadcaster {
    offers: RefCell<Vec<UnsignedEvmCall>>,
}

impl RecordingBroadcaster {
    fn offers(&self) -> Vec<UnsignedEvmCall> {
        self.offers.borrow().clone()
    }
    fn count(&self) -> usize {
        self.offers.borrow().len()
    }
}

impl BondBroadcaster for &RecordingBroadcaster {
    fn broadcast(&self, call: &UnsignedEvmCall) -> f4_harness::Result<BroadcastOutcome> {
        let mut offers = self.offers.borrow_mut();
        let duplicate = offers.iter().any(|seen| seen.encode() == call.encode());
        offers.push(call.clone());
        Ok(if duplicate {
            BroadcastOutcome::Duplicate
        } else {
            BroadcastOutcome::Accepted
        })
    }
}

const TERMS: [u8; 32] = [0x30; 32];
const SETTLEMENT: [u8; 32] = [0x20; 32];
const COLLATERAL: u128 = 700;
const CAP: u128 = 1_000;
const RELEASE_DEADLINE: u64 = 4_000;

fn secret() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = 0x2a;
    s[7] = 0x11;
    s
}

fn policy() -> AssurancePolicyV1 {
    AssurancePolicyV1 {
        policy_id: PolicyId([0x10; 32]),
        version: POLICY_STRUCT_VERSION,
        protected_settlement: SettlementId(SETTLEMENT),
        terms_hash: TERMS,
        bond_chain_id: ChainId([0x40; 32]),
        bond_asset: AssetId([0x00; 32]),
        required_collateral: COLLATERAL,
        compensation_cap: CAP,
        collateral_deadline: TimelockSpec::TimestampSeconds { value: 1_000 },
        claim_deadline: TimelockSpec::TimestampSeconds { value: 2_000 },
        evidence_deadline: TimelockSpec::TimestampSeconds { value: 3_000 },
        bond_release_deadline: TimelockSpec::TimestampSeconds {
            value: RELEASE_DEADLINE,
        },
        evidence_rule: EvidenceRuleV1::RevealedScalarClaim {
            adaptor_point: AdaptorPointBytes(
                adaptor_point_of_scalar(&secret()).expect("canonical fixture scalar"),
            ),
        },
        terminal_policy: TerminalPolicyV1::ConservativeRelease,
    }
}

struct Fixture {
    chain: SharedChain,
    deployment: BondDeployment,
    broadcaster: RecordingBroadcaster,
}

fn fixture() -> Fixture {
    let cfg = sample_config();
    let chain = MockChain::new(cfg.chain_id, cfg.contract);
    let deployment = BondDeployment {
        chain_id: cfg.chain_id,
        contract: cfg.contract,
        expected_code_hash: chain.code_hash(),
        dom_chain_id: cfg.dom_chain_id,
        direction: cfg.direction,
        participants_hash: cfg.participants_hash,
        asset: [0u8; 20],
        funder: FIXTURE_FUNDER,
        beneficiary: FIXTURE_BENEFICIARY,
        start_block: cfg.start_block,
        page_size: cfg.page_size,
        max_reorg_depth: cfg.max_reorg_depth,
        gas_limit_hint: cfg.gas_limit_hint,
    };
    Fixture {
        chain: SharedChain::new(chain),
        deployment,
        broadcaster: RecordingBroadcaster::default(),
    }
}

impl Fixture {
    fn adapter(
        &self,
        clock_now: u64,
    ) -> EvmBondAdapter<SharedChain, &RecordingBroadcaster, FixedClock> {
        EvmBondAdapter::new(
            &policy(),
            self.deployment,
            self.chain.clone(),
            &self.broadcaster,
            FixedClock::new(clock_now),
        )
        .expect("valid policy and deployment")
    }
}

#[test]
fn construction_refuses_bad_policies_before_any_transaction_exists() {
    let f = fixture();

    let mut over_cap = policy();
    over_cap.required_collateral = CAP + 1;
    let err = match EvmBondAdapter::new(
        &over_cap,
        f.deployment,
        f.chain.clone(),
        &f.broadcaster,
        FixedClock::new(0),
    ) {
        Err(e) => e,
        Ok(_) => panic!("collateral above the cap must refuse"),
    };
    assert!(matches!(err, BondError::Policy(_)));

    let mut wrong_domain = policy();
    wrong_domain.collateral_deadline = TimelockSpec::BlockHeight { value: 1_000 };
    wrong_domain.claim_deadline = TimelockSpec::BlockHeight { value: 2_000 };
    wrong_domain.evidence_deadline = TimelockSpec::BlockHeight { value: 3_000 };
    wrong_domain.bond_release_deadline = TimelockSpec::BlockHeight {
        value: RELEASE_DEADLINE,
    };
    let err = match EvmBondAdapter::new(
        &wrong_domain,
        f.deployment,
        f.chain.clone(),
        &f.broadcaster,
        FixedClock::new(0),
    ) {
        Err(e) => e,
        Ok(_) => panic!("height deadlines must refuse on the EVM venue"),
    };
    assert!(matches!(err, BondError::WrongTimelockDomain));

    // §7.3 witness: no refusal built a transaction.
    assert_eq!(f.broadcaster.count(), 0);
}

#[test]
fn submit_bond_is_the_open_call_and_resends_byte_identically() {
    let f = fixture();
    let mut bond = f.adapter(0);

    assert_eq!(
        bond.submit_bond(&policy()).expect("first offer"),
        BroadcastOutcome::Accepted
    );
    assert_eq!(
        bond.submit_bond(&policy()).expect("second offer"),
        BroadcastOutcome::Duplicate,
        "byte-identical resend is acknowledged, never re-executed (I7)"
    );

    let offers = f.broadcaster.offers();
    assert_eq!(offers.len(), 2);
    assert_eq!(offers[0].encode(), offers[1].encode());
    let call = &offers[0];
    assert_eq!(&call.calldata[..4], &selector(SIG_OPEN));
    assert_eq!(
        call.calldata.len(),
        4 + 10 * 32,
        "selector + 10 static words"
    );
    assert_eq!(
        call.value,
        amount_word(COLLATERAL),
        "native collateral rides msg.value"
    );
    assert_eq!(call.to, f.deployment.contract);
    assert_eq!(call.lock_id, bond.bond_lock_id());

    // A near-miss policy must not open a differently-parameterised lock.
    let mut other = policy();
    other.compensation_cap = CAP + 1;
    assert!(matches!(
        bond.submit_bond(&other).expect_err("divergent policy"),
        BondError::PolicyMismatch
    ));
    assert_eq!(f.broadcaster.count(), 2, "the refusal built nothing");
}

#[test]
fn release_is_permissionless_but_only_after_the_deadline() {
    let f = fixture();
    let clock = FixedClock::new(RELEASE_DEADLINE - 1);
    let mut bond = EvmBondAdapter::new(
        &policy(),
        f.deployment,
        f.chain.clone(),
        &f.broadcaster,
        clock,
    )
    .expect("valid");
    let lock_id = bond.bond_lock_id();

    assert!(matches!(
        bond.submit_release(&lock_id).expect_err("one second early"),
        BondError::DeadlineNotReached
    ));
    assert!(matches!(
        bond.submit_release(&[0xEE; 32]).expect_err("foreign lock"),
        BondError::UnknownLock
    ));
    assert_eq!(f.broadcaster.count(), 0);

    // At the deadline the contract accepts refund; so do we.
    let clock = FixedClock::new(RELEASE_DEADLINE);
    let mut bond = EvmBondAdapter::new(
        &policy(),
        f.deployment,
        f.chain.clone(),
        &f.broadcaster,
        clock,
    )
    .expect("valid");
    assert_eq!(
        bond.submit_release(&lock_id).expect("release"),
        BroadcastOutcome::Accepted
    );
    let call = f.broadcaster.offers().pop().expect("one offer");
    let mut expected = selector(SIG_REFUND).to_vec();
    expected.extend_from_slice(&word_bytes32(lock_id));
    assert_eq!(call.calldata, expected);
    assert_eq!(call.value, [0u8; 32]);
}

#[test]
fn slash_prechecks_mirror_the_contract_and_never_relax_it() {
    let f = fixture();
    let mut bond = f.adapter(3_500); // inside the slash-execution margin
    let lock_id = bond.bond_lock_id();

    // Non-canonical scalars: zero and the group order.
    assert!(matches!(
        bond.submit_slash(&lock_id, &RevealedSecretBytes([0u8; 32]))
            .expect_err("zero scalar"),
        BondError::NonCanonicalScalar
    ));
    assert!(matches!(
        bond.submit_slash(&lock_id, &RevealedSecretBytes(SECP256K1_N_BYTES))
            .expect_err("t = n"),
        BondError::NonCanonicalScalar
    ));

    // Canonical but wrong: does not open this bond's commitment.
    let mut wrong = secret();
    wrong[31] ^= 0x01;
    assert!(matches!(
        bond.submit_slash(&lock_id, &RevealedSecretBytes(wrong))
            .expect_err("wrong scalar"),
        BondError::ScalarPointMismatch
    ));

    assert!(matches!(
        bond.submit_slash(&[0xEE; 32], &RevealedSecretBytes(secret()))
            .expect_err("foreign lock"),
        BondError::UnknownLock
    ));
    assert_eq!(f.broadcaster.count(), 0, "every refusal built nothing");

    // The right scalar, inside the window: the claim artifact.
    assert_eq!(
        bond.submit_slash(&lock_id, &RevealedSecretBytes(secret()))
            .expect("slash"),
        BroadcastOutcome::Accepted
    );
    assert_eq!(
        bond.submit_slash(&lock_id, &RevealedSecretBytes(secret()))
            .expect("byte-identical resend"),
        BroadcastOutcome::Duplicate
    );
    let call = f.broadcaster.offers().pop().expect("offer");
    let mut expected = selector(SIG_CLAIM).to_vec();
    expected.extend_from_slice(&word_bytes32(lock_id));
    expected.extend_from_slice(&word_u256(secret()));
    assert_eq!(call.calldata, expected);
}

#[test]
fn slash_after_the_deadline_is_refused_because_the_contract_would_revert() {
    let f = fixture();
    let mut bond = f.adapter(RELEASE_DEADLINE);
    let lock_id = bond.bond_lock_id();
    assert!(matches!(
        bond.submit_slash(&lock_id, &RevealedSecretBytes(secret()))
            .expect_err("expired"),
        BondError::DeadlineExpired
    ));
    assert_eq!(f.broadcaster.count(), 0);
}

#[test]
fn observe_surfaces_only_this_bond_and_passes_reorgs_through() {
    let f = fixture();
    let mut bond = f.adapter(0);
    let lock_id = bond.bond_lock_id();
    let binding = bond.bond_binding();
    let terms = *bond.lock_terms();

    f.chain.with_mut(|c| {
        c.push_block();
        c.push_lock_opened(
            lock_id,
            binding,
            FIXTURE_FUNDER,
            FIXTURE_BENEFICIARY,
            [0u8; 20],
            terms.amount,
            terms.adaptor_address,
            terms.deadline,
        )
        .expect("open log");
        // A foreign lock's whole life on the same deployment.
        c.push_block();
        c.push_lock_opened(
            [0xEE; 32],
            [0xEF; 32],
            FIXTURE_FUNDER,
            FIXTURE_BENEFICIARY,
            [0u8; 20],
            terms.amount,
            terms.adaptor_address,
            terms.deadline,
        )
        .expect("foreign open");
        c.push_block();
        c.push_claimed(lock_id, binding, FIXTURE_BENEFICIARY, secret())
            .expect("claim log");
        c.push_block();
        c.push_refunded(lock_id, binding, FIXTURE_FUNDER, terms.amount)
            .expect("refund log");
        let tip = c.height();
        c.set_finalized(tip);
    });

    let observation = bond.observe(&ChainCursor::default()).expect("observe");
    let kinds: Vec<&BondEvent> = observation.events.iter().collect();
    assert_eq!(
        kinds.len(),
        3,
        "the foreign lock is not this bond's business"
    );
    assert!(matches!(
        kinds[0],
        BondEvent::CollateralLocked { bond_lock_id, .. } if *bond_lock_id == lock_id
    ));
    match kinds[1] {
        BondEvent::BondClaimed {
            bond_lock_id,
            revealed,
            ..
        } => {
            assert_eq!(*bond_lock_id, lock_id);
            assert_eq!(
                revealed.0,
                secret(),
                "the revealed scalar survives translation"
            );
        }
        other => panic!("expected BondClaimed, got {other:?}"),
    }
    assert!(matches!(
        kinds[2],
        BondEvent::BondRefunded { bond_lock_id, .. } if *bond_lock_id == lock_id
    ));

    // A reorg below the cursor is surfaced, not swallowed (I11).
    f.chain.with_mut(|c| {
        c.reorg(2);
        let tip = c.height();
        c.set_finalized(tip);
    });
    let after = bond
        .observe(&observation.cursor)
        .expect("observe after reorg");
    assert!(
        after
            .events
            .iter()
            .any(|e| matches!(e, BondEvent::Reorged { .. })),
        "reorg must reach the machine as an event"
    );
}
