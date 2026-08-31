//! Gate G-F1 suite — CHAIN conditions of the DOM settlement.
//!
//! DOM Interop Foundation Document v0.2.1 §7 (F1) and §4.5.
//!
//! G-F1 requires abstract `funding→claim` and `funding→refund` **with
//! real cryptography**. This suite proves the half where the CHAIN is the
//! authority — submission, inclusion, confirmation, claim/refund
//! exclusivity, reorg regression, persisted cursor, duplication and
//! reordering — with REAL submissions to the `dom-sim`, never with doubles.
//!
//! ## What this suite does NOT prove (declared limit, §9.1 anti-theater)
//!
//! The other half of G-F1 — verified adaptor pre-signature, real
//! `adapt`/`extract`, "unilateral spend cryptographically impossible" —
//! belongs to the `dom-leg` over the pin
//! `eb6aa1ca59226bc316e3aace5ee0e279e5a154c2` and **is not exercised here**.
//! The `f2-harness` does not depend on the `dom-leg`, and declaring the
//! `real-dom-adaptor` feature in this manifest would fail
//! `scripts/guards.sh` until `ci.yml` gains the corresponding job.
//! In the meantime:
//!
//! - every artifact submitted by this suite carries the [`CHAIN_ONLY_TAG`]
//!   label, which makes it impossible to mistake for a signature; no
//!   assertion here depends on its content;
//! - the `dom-sim` TRANSPORTS these bytes as [`OpaqueWitness`] and never
//!   interprets them — swapping the artifact for a real `dom-leg`
//!   signature does not change a single chain-rule line;
//! - the gap is listed in [`G_F1_BLOCKED_ON_DOM_LEG`], which is the text
//!   the closing report must cite. No test in this suite claims to cover
//!   the cryptographic part.
//!
//! `dom-sim` is NOT the DOM: it confers no network compatibility; the
//! swap for the real node happens in F7 under the eligibility gate.

use adapter_dom_sim::{
    cursor_height, LockState, OpaqueWitness, RejectReason, SimChain, SimSubmission, SimTx,
    SubmitResult,
};
use counterparty_api::{ChainCursor, ObservedEvent, RevealedSecretBytes};

/// G-F1 conditions this suite does NOT cover, for literal citation in the
/// closing report. Keeping it as a constant prevents the gap from turning
/// into folklore: it lives in the test binary.
pub const G_F1_BLOCKED_ON_DOM_LEG: &str = "\
G-F1 (crypto): adaptor pre-signature verified against the session, \
adapt() reaching the pin's real verifier, extract() returning t, and \
'unilateral spend cryptographically impossible'. Requires dom-leg with \
--features real-dom-adaptor wired to the f2-harness.";

/// Mandatory label of every artifact in this suite.
///
/// It exists so that no future reading mistakes these bytes for
/// cryptographic material: a `dom-leg` artifact would never start like
/// this, and no assertion in this suite inspects the content.
const CHAIN_ONLY_TAG: &[u8] = b"G-F1/CHAIN-ONLY/NAO-E-ASSINATURA/v1";

/// Purpose bytes of the canonical registry (`dom_leg::Purpose`, authority
/// `dom-adaptor a182563`). Reproduced here because the `f2-harness` does
/// not depend on the `dom-leg`; they only compose the opaque artifact's
/// identity.
const PURPOSE_REFUND: u8 = 0x01;
const PURPOSE_CLAIM_ADAPTOR: u8 = 0x02;
const PURPOSE_FUNDING: u8 = 0x03;

const LOCK: [u8; 32] = [0xF1; 32];
const LOCK_B: [u8; 32] = [0xB2; 32];
const SECRET: [u8; 32] = [0x5E; 32];
/// Confirmations required by this suite's policy.
const MIN_CONF: u64 = 2;

fn artifact(purpose: u8, lock_id: [u8; 32], tail: &[u8]) -> OpaqueWitness {
    let mut bytes = Vec::with_capacity(CHAIN_ONLY_TAG.len() + 33 + tail.len());
    bytes.extend_from_slice(CHAIN_ONLY_TAG);
    bytes.push(purpose);
    bytes.extend_from_slice(&lock_id);
    bytes.extend_from_slice(tail);
    OpaqueWitness::new(bytes)
}

fn funding_artifact(lock_id: [u8; 32]) -> OpaqueWitness {
    artifact(PURPOSE_FUNDING, lock_id, &[])
}

fn claim_artifact(lock_id: [u8; 32], revealed: &[u8; 32]) -> OpaqueWitness {
    artifact(PURPOSE_CLAIM_ADAPTOR, lock_id, revealed)
}

fn refund_artifact(lock_id: [u8; 32], not_before_height: u64) -> OpaqueWitness {
    artifact(PURPOSE_REFUND, lock_id, &not_before_height.to_be_bytes())
}

fn funding_submission(lock_id: [u8; 32]) -> SimSubmission {
    SimSubmission::new(SimTx::Lock { lock_id }, funding_artifact(lock_id))
}

fn claim_submission(lock_id: [u8; 32], revealed: [u8; 32]) -> SimSubmission {
    SimSubmission::new(
        SimTx::Claim { lock_id, revealed },
        claim_artifact(lock_id, &revealed),
    )
}

fn refund_submission(lock_id: [u8; 32], not_before_height: u64) -> SimSubmission {
    SimSubmission::new(
        SimTx::Refund {
            lock_id,
            not_before_height,
        },
        refund_artifact(lock_id, not_before_height),
    )
}

fn accepted(result: SubmitResult, what: &str) -> [u8; 32] {
    match result {
        SubmitResult::Accepted { tx_id } => tx_id,
        SubmitResult::Rejected(reason) => panic!("{what} rejected by the chain: {reason:?}"),
    }
}

fn event_height(event: &ObservedEvent) -> u64 {
    match event {
        ObservedEvent::LockOpened { height, .. }
        | ObservedEvent::LockClaimed { height, .. }
        | ObservedEvent::LockRefunded { height, .. } => *height,
        ObservedEvent::Reorged { from_height } => *from_height,
    }
}

fn is_claim(event: &ObservedEvent) -> bool {
    matches!(event, ObservedEvent::LockClaimed { .. })
}

fn is_refund(event: &ObservedEvent) -> bool {
    matches!(event, ObservedEvent::LockRefunded { .. })
}

fn is_funding(event: &ObservedEvent) -> bool {
    matches!(event, ObservedEvent::LockOpened { .. })
}

/// Full scan from genesis: the chain's canonical truth against which
/// every derived state is compared.
fn full_scan(chain: &SimChain) -> Vec<ObservedEvent> {
    chain.scan(&ChainCursor::default()).0
}

fn count(events: &[ObservedEvent], pred: fn(&ObservedEvent) -> bool) -> usize {
    events.iter().filter(|e| pred(e)).count()
}

/// Observer with a PERSISTED cursor.
///
/// The only state surviving a restart is `disk_cursor` — the bytes a real
/// scanner would write. The `ledger` is DERIVED observation and, by I11,
/// must be able to regress: nothing above the valid cursor survives a
/// reorg.
#[derive(Default)]
struct Observer {
    disk_cursor: Vec<u8>,
    ledger: Vec<ObservedEvent>,
    reorgs: usize,
}

impl Observer {
    /// Applies a batch of events to the derived state.
    ///
    /// At-least-once delivery (I7): redelivery of the same event is
    /// harmless, and the batch order does not change the result.
    /// `valid_through` is the height of the cursor returned by the scan —
    /// after a reorg it rewinds, and every observation above it ceases to
    /// exist (I11).
    fn apply(&mut self, events: &[ObservedEvent], valid_through: u64) {
        for event in events {
            match event {
                ObservedEvent::Reorged { .. } => self.reorgs += 1,
                other => {
                    if !self.ledger.contains(other) {
                        self.ledger.push(other.clone());
                    }
                }
            }
        }
        self.ledger.retain(|e| event_height(e) <= valid_through);
    }

    /// One scan from the persisted cursor; persists the new cursor and
    /// returns the events delivered in this batch.
    fn poll(&mut self, chain: &SimChain) -> Vec<ObservedEvent> {
        let (events, next) = chain.scan(&ChainCursor(self.disk_cursor.clone()));
        self.disk_cursor.clone_from(&next.0);
        self.apply(&events, cursor_height(&next));
        events
    }

    /// Scans until a scan delivers nothing more (the dom-sim scanner
    /// rewinds one block per call after a reorg).
    fn poll_until_stable(&mut self, chain: &SimChain) -> usize {
        for round in 1..=32 {
            if self.poll(chain).is_empty() {
                return round;
            }
        }
        panic!("scanner did not converge within 32 scans");
    }

    /// Simulated restart: only the persisted cursor bytes survive.
    fn restart(&self) -> Self {
        Self {
            disk_cursor: self.disk_cursor.clone(),
            ledger: Vec::new(),
            reorgs: 0,
        }
    }
}

/// Chain with the funding of `lock_id` confirmed under [`MIN_CONF`].
fn funded(lock_id: [u8; 32]) -> (SimChain, [u8; 32]) {
    let mut chain = SimChain::new();
    let tx = accepted(
        chain.submit_submission(funding_submission(lock_id)),
        "funding",
    );
    chain.advance(MIN_CONF);
    assert_eq!(chain.confirmations(&tx), Some(MIN_CONF));
    assert_eq!(chain.lock_state(lock_id), LockState::Open);
    (chain, tx)
}

// ---------------------------------------------------------------------
// (1) funding → claim
// ---------------------------------------------------------------------

#[test]
fn item1_funding_then_claim_confirms_and_is_observed_from_a_cursor() {
    let mut chain = SimChain::new();
    let mut obs = Observer::default();

    // Funding submitted: in the mempool it is NOT yet a chain fact.
    let funding = funding_submission(LOCK);
    let funding_tx = accepted(chain.submit_submission(funding.clone()), "funding");
    assert_eq!(
        chain.lock_state(LOCK),
        LockState::Unknown,
        "mempool must not count as an open lock"
    );
    assert_eq!(chain.confirmations(&funding_tx), None);
    assert!(
        obs.poll(&chain).is_empty(),
        "scan delivered an event for a non-included transaction"
    );

    // Funding confirmed under the policy.
    chain.advance(MIN_CONF);
    assert_eq!(chain.confirmations(&funding_tx), Some(MIN_CONF));
    assert_eq!(chain.lock_state(LOCK), LockState::Open);
    // The artifact crossed the chain byte for byte, without interpretation.
    assert_eq!(
        chain.witness_of(&funding_tx).map(OpaqueWitness::as_bytes),
        Some(funding.witness().as_bytes()),
        "funding artifact did not survive transport"
    );
    assert_eq!(
        obs.poll(&chain),
        vec![ObservedEvent::LockOpened {
            lock_id: LOCK,
            height: 1
        }]
    );

    // Claim submitted and confirmed; the chain reveals the secret.
    let claim = claim_submission(LOCK, SECRET);
    let claim_tx = accepted(chain.submit_submission(claim.clone()), "claim");
    chain.advance(MIN_CONF);
    assert_eq!(chain.confirmations(&claim_tx), Some(MIN_CONF));
    assert_eq!(chain.lock_state(LOCK), LockState::Spent);
    assert_eq!(
        chain.witness_of(&claim_tx).map(OpaqueWitness::as_bytes),
        Some(claim.witness().as_bytes()),
        "claim artifact did not survive transport"
    );
    assert_eq!(
        obs.poll(&chain),
        vec![ObservedEvent::LockClaimed {
            lock_id: LOCK,
            revealed: RevealedSecretBytes::new(SECRET),
            height: 3
        }]
    );

    // The state derived from the cursor is exactly the chain's truth.
    assert_eq!(obs.ledger, full_scan(&chain));
    assert_eq!(count(&obs.ledger, is_refund), 0);
    assert!(
        obs.poll(&chain).is_empty(),
        "cursor at the tip redelivered events"
    );
}

// ---------------------------------------------------------------------
// (2) funding → refund
// ---------------------------------------------------------------------

#[test]
fn item2_funding_then_refund_after_the_height_timelock() {
    const NOT_BEFORE: u64 = 6;
    let (mut chain, _) = funded(LOCK);
    let mut obs = Observer::default();
    obs.poll(&chain);

    // Before the timelock the chain refuses — the refund is not
    // negotiable by local policy, it is block height.
    let refund = refund_submission(LOCK, NOT_BEFORE);
    assert_eq!(
        chain.submit_submission(refund.clone()),
        SubmitResult::Rejected(RejectReason::TimelockNotExpired)
    );
    assert_eq!(chain.lock_state(LOCK), LockState::Open);

    // Advances until the next block can include it.
    while chain.height() + 1 < NOT_BEFORE {
        chain.advance(1);
    }
    let refund_tx = accepted(chain.submit_submission(refund), "refund");
    chain.advance(MIN_CONF);

    assert_eq!(chain.confirmations(&refund_tx), Some(MIN_CONF));
    assert_eq!(chain.lock_state(LOCK), LockState::Spent);
    obs.poll_until_stable(&chain);
    assert!(obs.ledger.contains(&ObservedEvent::LockRefunded {
        lock_id: LOCK,
        height: NOT_BEFORE
    }));
    assert_eq!(count(&obs.ledger, is_claim), 0, "refund cannot coexist");
    assert_eq!(obs.ledger, full_scan(&chain));
}

// ---------------------------------------------------------------------
// (3) I4 — claim and refund are mutually exclusive per leg
// ---------------------------------------------------------------------

#[test]
fn item3_claim_then_refund_is_impossible_on_chain() {
    let (mut chain, _) = funded(LOCK);
    accepted(
        chain.submit_submission(claim_submission(LOCK, SECRET)),
        "claim",
    );
    chain.advance(MIN_CONF);
    assert_eq!(chain.lock_state(LOCK), LockState::Spent);

    // Even with the timelock expired and the refund artifact in hand.
    chain.advance(10);
    assert_eq!(
        chain.submit_submission(refund_submission(LOCK, 1)),
        SubmitResult::Rejected(RejectReason::AlreadySpent)
    );
    chain.advance(MIN_CONF);

    let events = full_scan(&chain);
    assert_eq!(
        (count(&events, is_claim), count(&events, is_refund)),
        (1, 0),
        "I4 violated: two economic outcomes on the same lock"
    );
}

#[test]
fn item3_refund_then_claim_is_impossible_on_chain() {
    let (mut chain, _) = funded(LOCK);
    chain.advance(4);
    accepted(
        chain.submit_submission(refund_submission(LOCK, 1)),
        "refund",
    );
    chain.advance(MIN_CONF);
    assert_eq!(chain.lock_state(LOCK), LockState::Spent);

    assert_eq!(
        chain.submit_submission(claim_submission(LOCK, SECRET)),
        SubmitResult::Rejected(RejectReason::AlreadySpent)
    );
    chain.advance(MIN_CONF);

    let events = full_scan(&chain);
    assert_eq!(
        (count(&events, is_claim), count(&events, is_refund)),
        (0, 1),
        "I4 violated: two economic outcomes on the same lock"
    );
}

// ---------------------------------------------------------------------
// (4) I11 — reorg invalidates derived observation, without duplicating the effect
// ---------------------------------------------------------------------

#[test]
fn item4_reorg_regresses_the_observation_and_never_duplicates_the_effect() {
    let (mut chain, _) = funded(LOCK);
    let mut obs = Observer::default();
    obs.poll(&chain);

    let claim_tx = accepted(
        chain.submit_submission(claim_submission(LOCK, SECRET)),
        "claim",
    );
    chain.advance(MIN_CONF); // claim in block 3, confirmed in 4
    obs.poll(&chain);
    assert_eq!(chain.lock_state(LOCK), LockState::Spent);
    assert_eq!(chain.confirmations(&claim_tx), Some(MIN_CONF));
    assert_eq!(count(&obs.ledger, is_claim), 1);

    // Reorg drops blocks 3 and 4: the claim returns to the mempool.
    chain.inject_reorg(MIN_CONF);
    assert_eq!(chain.height(), 2);
    assert_eq!(
        chain.lock_state(LOCK),
        LockState::Open,
        "unconfirmed spend kept counting as spent"
    );
    assert_eq!(chain.confirmations(&claim_tx), None);

    // The DERIVED observation regresses: the scanner signals the reorg
    // and the ledger loses everything above the valid cursor.
    obs.poll_until_stable(&chain);
    assert!(obs.reorgs >= 1, "reorg was not observable");
    assert_eq!(
        count(&obs.ledger, is_claim),
        0,
        "I11: derived observation survived the reorg"
    );
    assert_eq!(
        count(&obs.ledger, is_funding),
        1,
        "the funding was not affected"
    );
    assert_eq!(obs.ledger, full_scan(&chain));

    // Re-observation is idempotent: with no chain change, nothing new.
    let before = obs.ledger.clone();
    assert!(obs.poll(&chain).is_empty());
    assert!(obs.poll(&chain).is_empty());
    assert_eq!(obs.ledger, before);

    // The chain re-mines the claim: the economic effect remains UNIQUE.
    chain.advance(MIN_CONF);
    obs.poll_until_stable(&chain);
    assert_eq!(chain.lock_state(LOCK), LockState::Spent);
    assert_eq!(
        count(&obs.ledger, is_claim),
        1,
        "duplicated economic effect"
    );
    assert_eq!(count(&full_scan(&chain), is_claim), 1);
    assert_eq!(count(&full_scan(&chain), is_refund), 0);
    assert_eq!(obs.ledger, full_scan(&chain));
}

// ---------------------------------------------------------------------
// (5) cursor persisted across restarts
// ---------------------------------------------------------------------

#[test]
fn item5_persisted_cursor_across_restarts_has_no_gap_and_no_duplicate() {
    let mut chain = SimChain::new();
    let mut obs = Observer::default();
    let mut collected: Vec<ObservedEvent> = Vec::new();

    // Script with events at distinct heights and empty blocks in between.
    let steps: &[fn(&mut SimChain)] = &[
        |c| {
            accepted(c.submit_submission(funding_submission(LOCK)), "funding A");
            c.advance(1);
        },
        |c| {
            accepted(c.submit_submission(funding_submission(LOCK_B)), "funding B");
            c.advance(1);
        },
        |c| c.advance(1), // empty block
        |c| {
            accepted(
                c.submit_submission(claim_submission(LOCK, SECRET)),
                "claim A",
            );
            c.advance(1);
        },
        |c| {
            accepted(
                c.submit_submission(refund_submission(LOCK_B, 5)),
                "refund B",
            );
            c.advance(1);
        },
        |c| c.advance(2), // empty blocks
    ];

    for step in steps {
        step(&mut chain);
        collected.extend(obs.poll(&chain));
        // Restart: everything beyond the cursor bytes is lost.
        obs = obs.restart();
    }

    // Neither gap nor duplicate: the concatenation of the batches is
    // EXACTLY the full scan from genesis, in the same order.
    assert_eq!(collected, full_scan(&chain));
    assert_eq!(count(&collected, is_funding), 2);
    assert_eq!(count(&collected, is_claim), 1);
    assert_eq!(count(&collected, is_refund), 1);
    assert!(
        obs.poll(&chain).is_empty(),
        "persisted cursor redelivered events after the restart"
    );

    // An observer restarting from zero reaches the SAME derived state.
    let mut fresh = Observer::default();
    fresh.poll_until_stable(&chain);
    assert_eq!(fresh.ledger, full_scan(&chain));
}

// ---------------------------------------------------------------------
// (6) late, duplicated and out-of-order evidence
// ---------------------------------------------------------------------

#[test]
fn item6_byte_identical_resubmission_does_not_duplicate_anything() {
    let mut chain = SimChain::new();
    let funding = funding_submission(LOCK);
    let first = chain.submit_submission(funding.clone());
    let second = chain.submit_submission(funding.clone());
    assert_eq!(first, second, "I7: byte-identical resend changed identity");

    chain.advance(MIN_CONF);
    // Resend AFTER confirmation: refused, no second lock.
    assert_eq!(
        chain.submit_submission(funding),
        SubmitResult::Rejected(RejectReason::DuplicateLock)
    );

    let claim = claim_submission(LOCK, SECRET);
    let a = chain.submit_submission(claim.clone());
    let b = chain.submit_submission(claim);
    assert_eq!(a, b);
    chain.advance(MIN_CONF);

    let events = full_scan(&chain);
    assert_eq!(
        (
            count(&events, is_funding),
            count(&events, is_claim),
            count(&events, is_refund)
        ),
        (1, 1, 0)
    );
}

#[test]
fn item6_duplicated_and_reordered_delivery_is_idempotent() {
    let (mut chain, _) = funded(LOCK);
    accepted(
        chain.submit_submission(claim_submission(LOCK, SECRET)),
        "claim",
    );
    chain.advance(MIN_CONF);

    let mut obs = Observer::default();
    let batch = obs.poll(&chain);
    assert_eq!(batch.len(), 2);
    let reference = obs.ledger.clone();
    let valid_through = cursor_height(&ChainCursor(obs.disk_cursor.clone()));

    // The same batch again.
    obs.apply(&batch, valid_through);
    assert_eq!(obs.ledger, reference, "redelivery duplicated observation");

    // The same batch inverted (reorder).
    let mut reversed = batch.clone();
    reversed.reverse();
    obs.apply(&reversed, valid_through);
    assert_eq!(obs.ledger, reference, "reorder corrupted the observation");

    // LATE evidence: an already-consumed event, delivered again much
    // later, alongside new blocks.
    chain.advance(5);
    obs.poll_until_stable(&chain);
    obs.apply(&batch, cursor_height(&ChainCursor(obs.disk_cursor.clone())));
    assert_eq!(obs.ledger, reference);
    assert_eq!(obs.ledger, full_scan(&chain));
}

// ---------------------------------------------------------------------
// Declared limit
// ---------------------------------------------------------------------

#[test]
fn g_f1_crypto_conditions_are_declared_missing_not_simulated() {
    // This suite produces, verifies and fakes no signature whatsoever.
    // The proof is structural: every artifact it puts on the chain
    // carries the "not a signature" label, and no chain rule depends on
    // the content.
    for witness in [
        funding_artifact(LOCK),
        claim_artifact(LOCK, &SECRET),
        refund_artifact(LOCK, 6),
    ] {
        assert!(
            witness.as_bytes().starts_with(CHAIN_ONLY_TAG),
            "an unlabeled artifact could be mistaken for real material"
        );
    }
    assert!(G_F1_BLOCKED_ON_DOM_LEG.contains("real-dom-adaptor"));
}
