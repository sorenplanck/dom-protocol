//! Gate G-F3, offline half, under the **B-DOM** composition: the ratified
//! F2 §24 `SettlementEngine` drives the **DOM leg** (dom-sim, reused verbatim
//! from the G-F2 harness), and the **EVM leg is the counterparty** — observed
//! by `adapter_evm` through the [`f3_harness::EvmChainPort`] driver — with
//! zero network I/O.
//!
//! MANDATORY DECLARATION (Foundation §4.5): *dom-sim is not the DOM; it confers
//! no network compatibility; the swap for the real node happens in F7 under its
//! eligibility gate.* It simulates chain semantics only and never cryptography.
//!
//! # How this differs from the v0.5 suite, and why
//!
//! The v0.5 gate composed `EvmChainPort` as the engine's `ChainPort`: the
//! engine drove the EVM leg. `main`'s ratified engine binds its
//! `ChainSourceV1` to `terms.dom_leg` and requires a `BlockHeight` deadline,
//! so it models the DOM leg and only the DOM leg — the B-DOM finding in
//! `docs/normative/F3-F5-RECONCILIATION-PLAN.md`. Three consequences:
//!
//! - the "settles end to end through the frozen engine" claim is now made of
//!   the **DOM** leg, in the composition test, with the scalar the **EVM**
//!   leg revealed — the actual DOM Interop topology;
//! - the EVM leg's finalized-only discipline is proved at the driver level:
//!   the same adapter, the same fail-closed refusals, no engine in between;
//! - the v0.5 height→timestamp refund bridge is gone, because under B-DOM no
//!   block-height instruction ever crosses onto the timestamp chain. The
//!   refund tests assert the timestamp-domain margins directly; the domain
//!   machinery itself is exercised in `src/timelock.rs`.
//!
//! No validation was dropped anywhere else: finality before fact, scalar
//! canonicity, `address(t·G)`, `binding`/`lockId` re-derivation, `t` opens
//! `T`, the margins, and the adapt-vs-extract asymmetry all survive below.
//!
//! # Where the real cryptography lives
//!
//! **Not here.** In the default build `dom-leg` compiles without the pinned
//! backend and every cryptographic operation refuses with the **named**
//! refusal `CryptoBackendDisabled`; the seam tests below are gated to that
//! build and assert the exact refusal, never a wildcard. The wire boundary
//! (`adapt_claim_from_wire`/`extract_revealed_secret`) is identical in both
//! builds, so nothing here is shaped around a feature-only surface. The
//! positive halves — a real adaptation and a real byte-equal extraction —
//! run against the frozen SCAD0 corpus in `dom-leg`'s own conformance suite
//! at the pin, and on chain in the Anvil/Sepolia E2E.

use adapter_evm::abi::word_u128;
use adapter_evm::adapter::test_support::{sample_config, sample_neutral};
use adapter_evm::binding::{
    adaptor_address_of_scalar, adaptor_point_of_scalar, Direction, LockTerms,
};
use adapter_evm::mock::MockChain;
use adapter_evm::{EvidenceKind, EvmAdapterConfig, UnsignedEvmCall};
use counterparty_api::{
    AdaptorPointBytes, ChainCursor, NeutralTerms, ObservedEvent, RevealedSecretBytes,
    TimelockDomain,
};
use dom_leg::{pre_signature_layout as layout, PreSignatureBytes};
use f3_harness::{
    build_claim_call, idempotency_key, rederive, verify_scalar_opens_both_commitments,
    BroadcastOutcome, ChainClock, EvmChainPort, EvmDeployment, EvmPortConfig, FixedClock,
    HarnessError, MemoryLog, MockBroadcaster, Outbox, OutboxError, OutboxLog, SharedRpc,
    SimEffectSink, SimSettlementChain, SubmissionIntent, TimelockError, TimelockPoint,
    TimelockPolicy,
};
use kaystra_core::store_port::{SettlementStore, SqliteSettlementStore};
use kaystra_core::types::{
    AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1, LockMechanism,
    ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId, TimelockSpec,
};
use kaystra_core::{SettlementEngine, SettlementState, SettlementTermsV1};

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

const AMOUNT: u128 = 1_000_000;
const DEADLINE: u64 = 1_900_000_000;
const TEMPLATE_HASH: [u8; 32] = [0xA1; 32];
const TRANSCRIPT_HASH: [u8; 32] = [0xB2; 32];

/// A canonical scalar the test genuinely holds. Nothing is faked: `T = t·G` is
/// computed from it, and `address(T)` is what the lock commits to.
fn scalar() -> [u8; 32] {
    let mut t = [0u8; 32];
    t[31] = 0x2F;
    t[9] = 0x71;
    t
}

fn other_scalar() -> [u8; 32] {
    let mut t = [0u8; 32];
    t[31] = 0x13;
    t[3] = 0x44;
    t
}

fn adaptor_point() -> AdaptorPointBytes {
    AdaptorPointBytes(adaptor_point_of_scalar(&scalar()).expect("canonical scalar"))
}

fn adapter_cfg(chain: &MockChain) -> EvmAdapterConfig {
    let mut cfg = sample_config();
    cfg.expected_code_hash = chain.code_hash();
    cfg.direction = Direction::EvmToDom;
    cfg.start_block = 0;
    // A deliberately small `eth_getLogs` window. The adapter remembers the
    // hash of every page tip it validated, and that memory is what lets it
    // name a common ancestor after a reorg; a window wide enough to swallow
    // the whole history in one page would leave it with a single belief and
    // force the documented fail-closed path instead. Two blocks per page is
    // also what a rate-limited public endpoint tends to impose in practice.
    cfg.page_size = 2;
    cfg
}

fn deployment(cfg: &EvmAdapterConfig) -> EvmDeployment {
    EvmDeployment {
        chain_id: cfg.chain_id,
        contract: cfg.contract,
        funder: cfg.funder,
        gas_limit_hint: cfg.gas_limit_hint,
    }
}

fn neutral(cfg: &EvmAdapterConfig) -> NeutralTerms {
    sample_neutral(cfg, AMOUNT, DEADLINE)
}

/// Exactly the terms `prepare_lock` will build from the configuration above.
fn terms(cfg: &EvmAdapterConfig) -> LockTerms {
    LockTerms {
        dom_chain_id: cfg.dom_chain_id,
        direction: cfg.direction.as_u8(),
        session_id: cfg.session_id,
        terms_hash: cfg.terms_hash,
        participants_hash: cfg.participants_hash,
        asset: cfg.asset,
        amount: word_u128(AMOUNT),
        beneficiary: cfg.beneficiary,
        adaptor_address: adaptor_address_of_scalar(&scalar()).expect("canonical"),
        deadline: DEADLINE,
    }
}

/// A pre-signature frame committing to `T = t·G` and to this session.
///
/// Only the *frame* is built here; nothing cryptographic is simulated. The
/// nonce and scalar fields are opaque filler, and every operation that would
/// have to interpret them is delegated to `dom-leg`, which refuses.
fn pre_signature_for(t: &[u8; 32]) -> PreSignatureBytes {
    let mut buf = [0u8; layout::ENCODED_LEN];
    buf[layout::CLAIM_TEMPLATE_HASH].copy_from_slice(&TEMPLATE_HASH);
    buf[layout::ADAPTOR_POINT]
        .copy_from_slice(&adaptor_point_of_scalar(t).expect("canonical scalar"));
    buf[layout::AGGREGATE_NONCE_HAT].fill(0x04);
    buf[layout::SCALAR_HAT].fill(0x05);
    buf[layout::TRANSCRIPT_HASH].copy_from_slice(&TRANSCRIPT_HASH);
    PreSignatureBytes::from_slice(&buf).expect("fixed length frame")
}

type Port = EvmChainPort<MockChain, MockBroadcaster, FixedClock, MemoryLog>;

struct Parts {
    outbox: Outbox<MemoryLog>,
    broadcaster: MockBroadcaster,
    clock: FixedClock,
}

fn fresh_parts(chain: &SharedRpc<MockChain>, cfg: &EvmAdapterConfig, now: u64) -> Parts {
    Parts {
        outbox: Outbox::recover(MemoryLog::new()).expect("empty log"),
        broadcaster: MockBroadcaster::new(chain.clone(), cfg.funder, terms(cfg)),
        clock: FixedClock::new(now),
    }
}

fn build_port(chain: &SharedRpc<MockChain>, cfg: &EvmAdapterConfig, parts: Parts) -> Port {
    let port_cfg = EvmPortConfig {
        deployment: deployment(cfg),
        neutral: neutral(cfg),
        adaptor_point: adaptor_point(),
        terms: terms(cfg),
        timelock: TimelockPolicy::evm(),
    };
    EvmChainPort::new(
        port_cfg,
        *cfg,
        chain.clone(),
        parts.outbox,
        parts.broadcaster,
        parts.clock,
    )
    .expect("well-formed port configuration")
}

fn new_chain() -> (SharedRpc<MockChain>, EvmAdapterConfig) {
    let raw = MockChain::new(31337, [0xC0; 20]);
    let cfg = adapter_cfg(&raw);
    (SharedRpc::new(raw), cfg)
}

fn finalize(chain: &SharedRpc<MockChain>, h: u64) {
    chain
        .with_mut(|c| c.set_finalized(h))
        .expect("shared chain");
}

fn tip(chain: &SharedRpc<MockChain>) -> u64 {
    chain.with(|c| c.height()).expect("shared chain")
}

/// The counterparty spends the EVM lock, publishing `t` on chain. This is the
/// EVM→DOM direction's trigger, and it is somebody else's transaction — hence
/// applied straight to the world rather than through our driver.
fn counterparty_claims_on_evm(
    chain: &SharedRpc<MockChain>,
    cfg: &EvmAdapterConfig,
    lock_id: [u8; 32],
    binding: [u8; 32],
    t: [u8; 32],
) {
    chain
        .with_mut(|c| {
            c.push_block();
            c.push_claimed(lock_id, binding, cfg.beneficiary, t)
        })
        .expect("shared chain")
        .expect("log appended");
}

// ---------------------------------------------------------------------------
// 1. the EVM (counterparty) leg: finalized observations only, at the driver
// ---------------------------------------------------------------------------

#[test]
fn the_evm_leg_is_driven_on_finalized_observations_only() {
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (binding, lock_id) = port.identity().expect("derivation");

    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    assert_eq!(tip(&chain), 1, "the broadcast seam mined the funding");

    // Nothing is finalized yet, so nothing may surface (A4-EVM).
    let (events, cursor) = port.observe(&ChainCursor::default());
    assert!(events.is_empty(), "nothing above `finalized` may surface");
    assert_eq!(cursor, ChainCursor::default(), "the cursor must not move");

    finalize(&chain, 1);
    let (events, cursor) = port.observe(&cursor);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ObservedEvent::LockOpened { .. })),
        "once final, the funding is a fact: {events:?}"
    );

    counterparty_claims_on_evm(&chain, &cfg, lock_id, binding, scalar());
    let claim_height = tip(&chain);
    let (events, cursor) = port.observe(&cursor);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ObservedEvent::LockClaimed { .. })),
        "the claim is not final yet, so it is not a fact yet: {events:?}"
    );

    finalize(&chain, claim_height);
    assert_eq!(port.finalized_height(), claim_height);
    let (events, _) = port.observe(&cursor);
    let revealed = events
        .iter()
        .find_map(|e| match e {
            ObservedEvent::LockClaimed { revealed, .. } => Some(*revealed),
            _ => None,
        })
        .expect("the finalized claim must surface");
    assert_eq!(revealed.0, scalar(), "the published scalar must round-trip");
    assert_eq!(
        port.revealed_secret(&lock_id).expect("registry"),
        Some(RevealedSecretBytes(scalar()))
    );
}

// ---------------------------------------------------------------------------
// 1b. the B-DOM composition: the ratified engine settles the DOM leg with the
//     scalar the EVM leg revealed
// ---------------------------------------------------------------------------

/// Terms whose DOM leg lives on the simulated chain, in the same shape the
/// ratified G-F2 suite uses. The settlement id is also the DOM lock id.
fn b_dom_terms(deadline_height: u64, min_confirmations: u32) -> SettlementTermsV1 {
    let b32 = |x: u8| [x; 32];
    SettlementTermsV1 {
        settlement_id: SettlementId(b32(0xA1)),
        session_id: SessionId(b32(0xA2)),
        intent_hash: IntentHash(b32(0xA3)),
        solver_id: SolverId(b32(0xA4)),
        roster: [ParticipantId(b32(0xB1)), ParticipantId(b32(0xB2))],
        dom_leg: LegTermsV1 {
            role: LegRole::Dom,
            chain_id: ChainId(b32(0xC1)),
            asset_id: AssetId(b32(0xC2)),
            amount: 5,
            beneficiary: ParticipantId(b32(0xB2)),
            refund_to: ParticipantId(b32(0xB1)),
            mechanism: LockMechanism::DomAdaptor2of2,
            deadline: TimelockSpec::BlockHeight {
                value: deadline_height,
            },
            finality: FinalityPolicyV1 {
                min_confirmations,
                max_reorg_depth: min_confirmations + 8,
            },
            adapter_profile_hash: b32(0xC3),
        },
        counterparty_leg: LegTermsV1 {
            role: LegRole::Counterparty,
            chain_id: ChainId(b32(0xD1)),
            asset_id: AssetId(b32(0xD2)),
            amount: 7,
            beneficiary: ParticipantId(b32(0xB1)),
            refund_to: ParticipantId(b32(0xB2)),
            mechanism: LockMechanism::ConditionLock,
            deadline: TimelockSpec::BlockHeight { value: 500 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 9,
            },
            adapter_profile_hash: b32(0xD3),
        },
        adaptor_point_sec1: adaptor_point().0,
        fee_limit: FeeLimitV1 {
            dom_max: 0,
            counterparty_max: 0,
        },
        recovery: RecoveryPolicyV1 {
            refund_before_funding: true,
            evidence_retention_blocks: 10,
        },
        assurance_policy_hash: None,
        policy_version: 1,
        metadata: Vec::new(),
    }
}

fn b_dom_db(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("f3-g-f3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite{suffix}")));
    }
    dir.join(format!("{name}.sqlite"))
}

#[test]
fn the_engine_settles_the_dom_leg_with_the_scalar_the_evm_leg_revealed() {
    // ── EVM half: the counterparty leg publishes `t` and the driver observes
    //    it under finality, exactly as in the test above. ──────────────────
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (binding, lock_id) = port.identity().expect("derivation");
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    finalize(&chain, tip(&chain));
    let (_, cursor) = port.observe(&ChainCursor::default());
    counterparty_claims_on_evm(&chain, &cfg, lock_id, binding, scalar());
    finalize(&chain, tip(&chain));
    let (_, _) = port.observe(&cursor);
    let revealed = port
        .revealed_secret(&lock_id)
        .expect("registry")
        .expect("the finalized claim revealed the scalar");

    // ── DOM half: the ratified §24 engine over the reused G-F2 pieces. ────
    let path = b_dom_db("composition");
    let terms = b_dom_terms(1_000, 1);
    let dom = SimSettlementChain::new(terms.dom_leg.chain_id, terms.settlement_id.0);
    let store = SqliteSettlementStore::open(&path).expect("store");
    store.create(&terms, 1).expect("settlement created");
    let sink = SimEffectSink::new(dom.clone(), 1_000);
    let mut engine =
        SettlementEngine::open(store, dom.clone(), sink, terms.settlement_id).expect("open");

    // Arm, fund, confirm; then the DOM counterparty claims the DOM lock with
    // THE scalar the EVM leg just published — the value that crossed legs.
    engine.arm_refund(10).expect("armed");
    engine.tick(11).expect("tick");
    let mut settled = false;
    for round in 0..14usize {
        if round == 2 {
            assert!(
                matches!(
                    dom.submit_claim(revealed.0),
                    adapter_dom_sim::SubmitResult::Accepted { .. }
                ),
                "the DOM claim carrying the crossed scalar must be accepted"
            );
        }
        dom.advance(1);
        engine.tick(20 + round as i64).expect("tick");
        if engine
            .snapshot()
            .expect("snapshot")
            .context
            .state
            .is_terminal()
        {
            settled = true;
            break;
        }
    }
    assert!(settled, "the claim path did not converge");
    assert_eq!(
        engine.snapshot().expect("snapshot").context.state,
        SettlementState::Settled
    );
    assert_eq!(
        engine.sink().claim_consumptions().len(),
        1,
        "exactly one claim consumption reached the F1 boundary stand-in"
    );

    // Provenance: the value that settled the DOM leg is the one the EVM leg
    // revealed — not a look-alike.
    assert_eq!(revealed.0, scalar());

    // I6, strengthened by B-DOM: the settlement store NEVER holds the scalar.
    // The DOM chain source drops the revealed value at the adapter boundary
    // (the engine only ever sees an evidence reference), so the durable store
    // must be clean of it — checked over the raw database bytes, WAL included.
    drop(engine);
    let mut persisted = std::fs::read(&path).expect("db bytes");
    let wal = path.with_extension("sqlite-wal");
    if let Ok(mut extra) = std::fs::read(&wal) {
        persisted.append(&mut extra);
    }
    assert_eq!(
        occurrences(&persisted, &scalar()),
        0,
        "the ratified store must never hold the revealed scalar"
    );
}

// ---------------------------------------------------------------------------
// sweep helpers: a name, and the exact bytes that survive a restart
// ---------------------------------------------------------------------------

type Surface = (&'static str, Vec<u8>);

/// Every frame of an outbox log, concatenated with a discriminating prefix so
/// that adjacent frames cannot cancel a match across their boundary.
fn outbox_bytes(log: &MemoryLog) -> Vec<u8> {
    let mut out = Vec::new();
    for frame in log.frames().expect("frames") {
        out.push(0x02);
        out.extend_from_slice(&frame);
    }
    out
}

/// How many times the 32-byte value occurs in `haystack`, at any alignment.
fn occurrences(haystack: &[u8], needle: &[u8; 32]) -> usize {
    haystack.windows(32).filter(|w| *w == &needle[..]).count()
}

/// The names of every surface in which the value occurs.
fn sweep(surfaces: &[Surface], needle: &[u8; 32]) -> Vec<&'static str> {
    surfaces
        .iter()
        .filter(|(_, bytes)| occurrences(bytes, needle) > 0)
        .map(|(name, _)| *name)
        .collect()
}

#[test]
fn the_persistence_sweep_can_actually_detect_a_planted_scalar() {
    // CONTROL. A sweep that cannot fail proves nothing, so this test plants the
    // scalar in each shape a persisted surface can take and requires the sweep
    // to name every one of them — and to name nothing when it is looking for a
    // value that was never planted.
    let mut planted_log = MemoryLog::new();
    let mut frame = vec![0xAAu8; 8];
    frame.extend_from_slice(&scalar());
    frame.extend_from_slice(&[0xBBu8; 8]);
    planted_log.append_frame(&frame).expect("append");

    let mut planted_cursor = vec![0x01u8; 16];
    planted_cursor.extend_from_slice(&scalar());

    let surfaces: Vec<Surface> = vec![
        ("clean", vec![0u8; 512]),
        ("planted in an outbox frame", outbox_bytes(&planted_log)),
        ("planted in a cursor", planted_cursor),
    ];

    assert_eq!(
        sweep(&surfaces, &scalar()),
        vec!["planted in an outbox frame", "planted in a cursor"],
        "the sweep must find the scalar in every shape a surface can hold it"
    );
    assert!(
        sweep(&surfaces, &other_scalar()).is_empty(),
        "and must not report a value nobody planted"
    );
}

#[test]
fn the_scalar_is_never_persisted_raw_outside_the_permitted_artifacts() {
    // The permitted artifacts are exactly two, and both exist *in order to*
    // publish the scalar:
    //
    //   * the `claim(lockId, t)` calldata in the outbox — publishing `t` on the
    //     EVM leg IS the claim, and I7 requires the exact bytes to be resendable;
    //   * the `Claimed` evidence payload — a record of a fact the chain has
    //     already made public.
    //
    // Everything else — the scan cursor, every other outbox record — must be
    // clean, at every phase. (The settlement store's cleanliness is asserted
    // in the composition test above: under B-DOM it never sees `t` at all.)
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (binding, lock_id) = port.identity().expect("derivation");
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    finalize(&chain, tip(&chain));
    let (_, cursor) = port.observe(&ChainCursor::default());

    // --- phase 1: the lock is open and nobody has revealed anything ---------
    let surfaces: Vec<Surface> = vec![
        ("outbox log", outbox_bytes(port.outbox().log())),
        ("scan cursor", cursor.0.clone()),
    ];
    assert!(
        sweep(&surfaces, &scalar()).is_empty(),
        "nothing may hold the scalar before it is even used: {:?}",
        sweep(&surfaces, &scalar())
    );

    // --- phase 2: we authorise the claim; the scalar enters the outbox ------
    let call = build_claim_call(&deployment(&cfg), lock_id, binding, &scalar()).expect("call");
    assert_eq!(
        port.submit_claim(&call).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let outbox_after_claim = outbox_bytes(port.outbox().log());
    assert_eq!(
        occurrences(&outbox_after_claim, &scalar()),
        1,
        "exactly one persisted copy: the artifact that publishes it"
    );
    let claim_key = idempotency_key(
        cfg.chain_id,
        &cfg.contract,
        &lock_id,
        SubmissionIntent::Claim,
    );
    let record = port.outbox().get(&claim_key).expect("claim record");
    assert_eq!(
        &record.call.calldata[36..68],
        &scalar()[..],
        "the permitted copy is the `t` argument of `claim(lockId, t)`"
    );
    let open_key = idempotency_key(
        cfg.chain_id,
        &cfg.contract,
        &lock_id,
        SubmissionIntent::OpenLock,
    );
    let open = port.outbox().get(&open_key).expect("open record");
    assert_eq!(
        occurrences(&open.call.encode(), &scalar()),
        0,
        "the funding artifact commits to address(T), never to the scalar"
    );
    assert_eq!(
        occurrences(&cursor.0, &scalar()),
        0,
        "the cursor stays clean"
    );

    // --- phase 3: the chain publishes it; evidence may record that fact -----
    finalize(&chain, tip(&chain));
    let (events, cursor) = port.observe(&cursor);
    assert!(events
        .iter()
        .any(|e| matches!(e, ObservedEvent::LockClaimed { .. })));
    let evidence = port
        .adapter()
        .collect_evidence(&lock_id, EvidenceKind::Claimed)
        .expect("evidence")
        .encode();
    let surfaces: Vec<Surface> = vec![
        ("outbox log", outbox_bytes(port.outbox().log())),
        ("scan cursor", cursor.0.clone()),
        ("claim evidence", evidence),
    ];
    assert_eq!(
        sweep(&surfaces, &scalar()),
        vec!["outbox log", "claim evidence"],
        "after publication the evidence payload legitimately records it; the \
         cursor still must not"
    );
}

// ---------------------------------------------------------------------------
// 2. the routes and the DOM seam (offline build: the named refusal)
// ---------------------------------------------------------------------------

/// The EVM→DOM route's own source region must not even mention the extraction
/// operation, so the adapt-vs-extract asymmetry cannot be broken by a path a
/// test happens not to exercise. Feature-independent: the region is source.
#[test]
fn the_evm_to_dom_route_region_never_mentions_extraction() {
    const ROUTES: &str = include_str!("../src/routes.rs");
    let begin = ROUTES
        .find("// --- BEGIN ROUTE EVM->DOM")
        .expect("begin marker");
    let end = ROUTES
        .find("// --- END ROUTE EVM->DOM")
        .expect("end marker");
    assert!(begin < end, "markers out of order");
    let region = &ROUTES[begin..end];
    assert!(
        !region.contains("extract"),
        "the EVM->DOM route region must not reference the extraction operation"
    );
    // And the marker pair must actually enclose BOTH entry points of the
    // direction — otherwise the assertion above could be true of an empty or
    // misplaced region.
    assert!(region.contains("pub fn evm_to_dom"));
    assert!(region.contains("pub fn evm_to_dom_from_evidence"));
    assert!(
        region.contains("adapt_claim_from_wire"),
        "the region must call adapt"
    );
}

#[cfg(not(feature = "real-dom-adaptor"))]
mod offline_seam {
    //! The seam tests, in the build where `dom-leg` has no cryptographic
    //! backend and refuses with the **named** `CryptoBackendDisabled`.
    //!
    //! They are gated rather than dual-built because `main`'s real `dom-leg`
    //! cannot construct a session without a full 2-of-2 round — there is no
    //! "session with no signing key" to drive the negative against. The wire
    //! boundary the routes call is byte-identical in both builds, so what is
    //! proved here about the routes holds in both; the real-backend positive
    //! halves live at the pin (SCAD0) and on chain (Anvil/Sepolia).

    use super::*;
    use adapter_dom_sim::LockState;
    // Named through `disabled` rather than the crate root: this module is about
    // the refusal a build without the crypto backend produces, and a workspace
    // build unifies features so the root may resolve to the real leg instead.
    use dom_leg::disabled::{DomLegSession, SessionBindings};
    use dom_leg::LegError;
    use f3_harness::{
        dom_to_evm, evm_to_dom, evm_to_dom_from_evidence, DomLegOps, DomToEvmInput,
        EvmEvidenceToDomInput, EvmToDomInput,
    };
    use kaystra_core::store_port::ClaimedEffectV1;
    use kaystra_core::types::EffectId;
    use kaystra_core::{Effect, EffectOutcome, EffectSinkV1};
    use std::cell::Cell;
    use zeroize::Zeroizing;

    /// A session with the right bindings and no backend behind it. `0x02` is
    /// the canonical `ClaimAdaptor` purpose byte; without the pin it enables
    /// nothing.
    fn session() -> DomLegSession {
        DomLegSession::new(SessionBindings {
            chain_id: [0x11; 32],
            claim_template_hash: TEMPLATE_HASH,
            transcript_hash: TRANSCRIPT_HASH,
            purpose_byte: 0x02,
        })
    }

    /// The **exact** refusal this build's `dom-leg` produces: the backend is
    /// not compiled in, and the leg says so. Named rather than matched with a
    /// wildcard, so a change of reason is a test failure, not a silent pass.
    fn refusal_of_the_backendless_leg() -> HarnessError {
        HarnessError::DomLeg(LegError::CryptoBackendDisabled)
    }

    /// Wraps the real `DomLegSession` and counts which operations a route asks
    /// for. It delegates every call; it never invents a signature, a scalar or
    /// a success.
    struct CountingLeg<'a> {
        inner: &'a DomLegSession,
        adapt_calls: Cell<usize>,
        extract_calls: Cell<usize>,
    }

    impl<'a> CountingLeg<'a> {
        fn new(inner: &'a DomLegSession) -> Self {
            Self {
                inner,
                adapt_calls: Cell::new(0),
                extract_calls: Cell::new(0),
            }
        }
    }

    impl DomLegOps for CountingLeg<'_> {
        fn adapt_claim_from_wire(
            &self,
            pre: &PreSignatureBytes,
            secret: &Zeroizing<[u8; 32]>,
        ) -> Result<Vec<u8>, LegError> {
            self.adapt_calls.set(self.adapt_calls.get() + 1);
            self.inner.adapt_claim_from_wire(pre, secret)
        }
        fn extract_revealed_secret(
            &self,
            pre: &PreSignatureBytes,
            final_signature: &[u8],
        ) -> Result<RevealedSecretBytes, LegError> {
            self.extract_calls.set(self.extract_calls.get() + 1);
            self.inner.extract_revealed_secret(pre, final_signature)
        }
    }

    /// Delegates adaptation and makes the extraction operation fatal: any path
    /// through the EVM→DOM route that reaches extraction aborts the process
    /// instead of returning something that looks like an answer.
    struct PanicOnExtractLeg<'a> {
        inner: &'a DomLegSession,
    }

    impl DomLegOps for PanicOnExtractLeg<'_> {
        fn adapt_claim_from_wire(
            &self,
            pre: &PreSignatureBytes,
            secret: &Zeroizing<[u8; 32]>,
        ) -> Result<Vec<u8>, LegError> {
            self.inner.adapt_claim_from_wire(pre, secret)
        }
        fn extract_revealed_secret(
            &self,
            _pre: &PreSignatureBytes,
            _final_signature: &[u8],
        ) -> Result<RevealedSecretBytes, LegError> {
            panic!("the EVM->DOM route must never recover the scalar from a DOM signature");
        }
    }

    fn evm_to_dom_input<'a>(
        cfg: &EvmAdapterConfig,
        pre: &'a PreSignatureBytes,
        lock_id: [u8; 32],
        binding: [u8; 32],
    ) -> EvmToDomInput<'a> {
        EvmToDomInput {
            deployment: deployment(cfg),
            terms: terms(cfg),
            observed_lock_id: lock_id,
            observed_binding: binding,
            observed_height: 3,
            finalized_height: 3,
            revealed: RevealedSecretBytes(scalar()),
            pre_signature: pre,
            dom_now: TimelockPoint::height(10),
            dom_deadline: TimelockPoint::height(10 + TimelockPolicy::dom_sim().total_margin()),
        }
    }

    /// Opens the DOM lock on a real dom-sim chain by driving the reused G-F2
    /// sink with the engine's own funding effect — the only door to a lock.
    fn open_dom_lock(lock_id: [u8; 32]) -> SimSettlementChain {
        let dom = SimSettlementChain::new(ChainId([0xAD; 32]), lock_id);
        let mut sink = SimEffectSink::new(dom.clone(), u64::MAX);
        let outcome = sink.execute(&ClaimedEffectV1 {
            settlement_id: SettlementId(lock_id),
            effect_id: EffectId([0x0E; 32]),
            kind: Effect::AuthorizeFunding,
            payload: Vec::new(),
            payload_hash: [0u8; 32],
            attempts: 0,
        });
        assert_eq!(outcome, EffectOutcome::Completed, "funding submitted");
        dom.advance(1);
        assert_eq!(dom.lock_state(), LockState::Open);
        dom
    }

    #[test]
    fn evm_to_dom_reaches_the_dom_leg_and_stops_at_the_named_refusal() {
        let (_, cfg) = new_chain();
        let leg = session();
        let counting = CountingLeg::new(&leg);
        let pre = pre_signature_for(&scalar());
        let (binding, lock_id) = rederive(&deployment(&cfg), &terms(&cfg)).expect("derivation");

        // The DOM leg is a real dom-sim chain with the lock funded and unspent.
        let dom = open_dom_lock(lock_id);

        let out = evm_to_dom(
            &counting,
            &TimelockPolicy::dom_sim(),
            &evm_to_dom_input(&cfg, &pre, lock_id, binding),
        );

        // Every pre-validation passed: the route got all the way to the seam.
        assert_eq!(
            counting.adapt_calls.get(),
            1,
            "the route must actually reach the DOM leg, not stop short of it"
        );
        // NOT a wildcard. `Err(DomLeg(_))` would also be satisfied by a
        // template mismatch or a length error, which are different facts from
        // "this build has no cryptographic backend".
        assert_eq!(
            out.err(),
            Some(refusal_of_the_backendless_leg()),
            "the refusal must be the exact one the backendless leg produces"
        );

        // Nothing was settled on the DOM leg: no authorisation exists, so no
        // claim can even be submitted through `submit_dom_claim`.
        dom.advance(2);
        assert_eq!(
            dom.lock_state(),
            LockState::Open,
            "the DOM lock must still be unspent"
        );
    }

    #[test]
    fn dom_to_evm_reaches_the_dom_leg_and_produces_no_evm_call_at_the_named_refusal() {
        let (_, cfg) = new_chain();
        let leg = session();
        let counting = CountingLeg::new(&leg);
        let pre = pre_signature_for(&scalar());

        let out = dom_to_evm(
            &counting,
            &TimelockPolicy::evm(),
            &DomToEvmInput {
                deployment: deployment(&cfg),
                terms: terms(&cfg),
                pre_signature: &pre,
                final_signature: &[0u8; 65],
                evm_now: TimelockPoint::timestamp(
                    DEADLINE - 10 * TimelockPolicy::evm().total_margin(),
                ),
            },
        );
        assert_eq!(
            counting.extract_calls.get(),
            1,
            "the route must reach the seam"
        );
        assert_eq!(counting.adapt_calls.get(), 0, "this direction never adapts");
        assert_eq!(
            out.err(),
            Some(refusal_of_the_backendless_leg()),
            "the refusal must be the exact one the backendless leg produces"
        );
    }

    #[test]
    fn a_pre_signature_from_another_session_is_refused_with_the_named_mismatch() {
        let (_, cfg) = new_chain();
        let leg = session();
        let counting = CountingLeg::new(&leg);
        // Same committed point, wrong session frame.
        let mut buf = [0u8; layout::ENCODED_LEN];
        buf[layout::CLAIM_TEMPLATE_HASH].fill(0xEE);
        buf[layout::ADAPTOR_POINT].copy_from_slice(&adaptor_point().0);
        buf[layout::TRANSCRIPT_HASH].copy_from_slice(&TRANSCRIPT_HASH);
        let foreign = PreSignatureBytes::from_slice(&buf).expect("frame");
        let (binding, lock_id) = rederive(&deployment(&cfg), &terms(&cfg)).expect("derivation");

        let out = evm_to_dom(
            &counting,
            &TimelockPolicy::dom_sim(),
            &evm_to_dom_input(&cfg, &foreign, lock_id, binding),
        );
        // The session check lives INSIDE dom-leg now — one definition of
        // "belongs to this session", not a route-local copy that could drift.
        // The seam is therefore reached (one adapt call), and the leg names
        // the mismatch before anything cryptographic would have run.
        assert_eq!(
            out.err(),
            Some(HarnessError::DomLeg(LegError::TemplateMismatch))
        );
        assert_eq!(
            counting.adapt_calls.get(),
            1,
            "the check is the leg's own, behind the seam"
        );
        assert_eq!(
            counting.extract_calls.get(),
            0,
            "a foreign session must never provoke extraction"
        );
    }

    #[test]
    fn a_scalar_that_does_not_open_the_commitment_never_reaches_the_dom_leg() {
        let (_, cfg) = new_chain();
        let leg = session();
        let counting = CountingLeg::new(&leg);
        let pre = pre_signature_for(&scalar());
        let (binding, lock_id) = rederive(&deployment(&cfg), &terms(&cfg)).expect("derivation");

        let mut input = evm_to_dom_input(&cfg, &pre, lock_id, binding);
        input.revealed = RevealedSecretBytes(other_scalar());
        assert_eq!(
            evm_to_dom(&counting, &TimelockPolicy::dom_sim(), &input).err(),
            Some(HarnessError::AdaptorPointMismatch)
        );
        input.revealed = RevealedSecretBytes([0u8; 32]);
        assert_eq!(
            evm_to_dom(&counting, &TimelockPolicy::dom_sim(), &input).err(),
            Some(HarnessError::NonCanonicalScalar)
        );
        assert_eq!(counting.adapt_calls.get(), 0);
        assert_eq!(counting.extract_calls.get(), 0);
    }

    #[test]
    fn an_observation_above_the_finalized_height_never_reaches_the_dom_leg() {
        let (_, cfg) = new_chain();
        let leg = session();
        let counting = CountingLeg::new(&leg);
        let pre = pre_signature_for(&scalar());
        let (binding, lock_id) = rederive(&deployment(&cfg), &terms(&cfg)).expect("derivation");
        let mut input = evm_to_dom_input(&cfg, &pre, lock_id, binding);
        input.observed_height = 9;
        input.finalized_height = 8;
        assert_eq!(
            evm_to_dom(&counting, &TimelockPolicy::dom_sim(), &input).err(),
            Some(HarnessError::NotFinal {
                observed: 9,
                finalized: 8
            })
        );
        assert_eq!(counting.adapt_calls.get(), 0);
    }

    #[test]
    fn a_look_alike_lock_is_refused_by_re_derivation() {
        let (_, cfg) = new_chain();
        let leg = session();
        let counting = CountingLeg::new(&leg);
        let pre = pre_signature_for(&scalar());
        let (binding, lock_id) = rederive(&deployment(&cfg), &terms(&cfg)).expect("derivation");

        let mut input = evm_to_dom_input(&cfg, &pre, lock_id, binding);
        input.observed_binding[0] ^= 1;
        assert_eq!(
            evm_to_dom(&counting, &TimelockPolicy::dom_sim(), &input).err(),
            Some(HarnessError::BindingMismatch)
        );
        let mut input = evm_to_dom_input(&cfg, &pre, lock_id, binding);
        input.observed_lock_id[0] ^= 1;
        assert_eq!(
            evm_to_dom(&counting, &TimelockPolicy::dom_sim(), &input).err(),
            Some(HarnessError::BindingMismatch)
        );
        assert_eq!(counting.adapt_calls.get(), 0);
    }

    #[test]
    fn extract_is_never_called_on_the_evm_to_dom_route() {
        let (_, cfg) = new_chain();
        let leg = session();
        let counting = CountingLeg::new(&leg);
        let pre = pre_signature_for(&scalar());
        let (binding, lock_id) = rederive(&deployment(&cfg), &terms(&cfg)).expect("derivation");

        // Behavioural half: run the route and count.
        let _ = evm_to_dom(
            &counting,
            &TimelockPolicy::dom_sim(),
            &evm_to_dom_input(&cfg, &pre, lock_id, binding),
        );
        assert_eq!(counting.adapt_calls.get(), 1);
        assert_eq!(
            counting.extract_calls.get(),
            0,
            "`t` came from a public on-chain log; re-deriving it from a DOM \
             signature would be a second authority over the same value"
        );

        // Behavioural half, part two: a leg whose extraction operation panics.
        // The route must survive it — extraction is unreachable from this
        // direction by construction.
        let tripwire = PanicOnExtractLeg { inner: &leg };
        let out = evm_to_dom(
            &tripwire,
            &TimelockPolicy::dom_sim(),
            &evm_to_dom_input(&cfg, &pre, lock_id, binding),
        );
        assert_eq!(
            out.err(),
            Some(refusal_of_the_backendless_leg()),
            "the route must reach the DOM leg without ever touching extraction"
        );

        // CONTROL: an armed tripwire. Without this the assertion above would
        // be vacuous — "it did not panic" could just mean the panic is
        // unreachable from anywhere.
        let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            dom_to_evm(
                &tripwire,
                &TimelockPolicy::evm(),
                &DomToEvmInput {
                    deployment: deployment(&cfg),
                    terms: terms(&cfg),
                    pre_signature: &pre,
                    final_signature: &[0u8; 65],
                    evm_now: TimelockPoint::timestamp(DEADLINE - 100_000),
                },
            )
        }));
        assert!(
            fired.is_err(),
            "the tripwire must be able to fire, or the assertion above proves nothing"
        );
    }

    #[test]
    fn the_complete_evm_to_dom_path_validates_the_deployment_before_it_reaches_the_seam() {
        // The ordered validation list — chainId, contract, codehash, ABI,
        // emitter, topics, receipt status, tx hash, log index, block hash,
        // lockId, binding, session_id, terms_hash, T/address(T), 0 < t < n —
        // is decided by the adapter and then re-checked by the route. Here the
        // deployment half is driven both ways: a good record reaches the DOM
        // leg, a record with any one field flipped never does.
        let (chain, cfg) = new_chain();
        let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
        let (binding, lock_id) = port.identity().expect("derivation");
        assert_eq!(
            port.submit_funding(lock_id).expect("broadcast"),
            BroadcastOutcome::Accepted
        );
        counterparty_claims_on_evm(&chain, &cfg, lock_id, binding, scalar());
        finalize(&chain, tip(&chain));
        let evidence = port
            .adapter()
            .collect_evidence(&lock_id, EvidenceKind::Claimed)
            .expect("evidence");

        let leg = session();
        let pre = pre_signature_for(&scalar());
        let dom_policy = TimelockPolicy::dom_sim();
        let run = |counting: &CountingLeg<'_>, bytes: &[u8]| {
            evm_to_dom_from_evidence(
                port.adapter(),
                counting,
                &dom_policy,
                &EvmEvidenceToDomInput {
                    evidence: bytes,
                    pre_signature: &pre,
                    dom_now: TimelockPoint::height(10),
                    dom_deadline: TimelockPoint::height(10 + dom_policy.total_margin()),
                },
            )
        };

        // A well-formed record clears every deployment check, reaches the
        // seam, and stops at the named backendless refusal.
        let counting = CountingLeg::new(&leg);
        assert_eq!(
            run(&counting, &evidence.encode()).err(),
            Some(refusal_of_the_backendless_leg()),
            "the path must be stopped by the DOM leg and by nothing before it"
        );
        assert_eq!(counting.adapt_calls.get(), 1);
        assert_eq!(counting.extract_calls.get(), 0);

        // Flip one deployment- or settlement-binding field at a time. None of
        // them may reach the DOM leg.
        type Mutation = (
            &'static str,
            Box<dyn Fn(&mut adapter_evm::evidence::EvmEvidence)>,
        );
        let mutations: Vec<Mutation> = vec![
            ("chain id", Box::new(|e| e.chain_id ^= 1)),
            ("contract", Box::new(|e| e.contract[0] ^= 1)),
            ("codehash", Box::new(|e| e.code_hash[0] ^= 1)),
            ("session id", Box::new(|e| e.terms.session_id[0] ^= 1)),
            ("terms hash", Box::new(|e| e.terms.terms_hash[0] ^= 1)),
            (
                "adaptor address",
                Box::new(|e| e.terms.adaptor_address[0] ^= 1),
            ),
            ("lock id", Box::new(|e| e.lock_id[0] ^= 1)),
            ("binding", Box::new(|e| e.binding[0] ^= 1)),
            ("block hash", Box::new(|e| e.block_hash[0] ^= 1)),
            ("tx hash", Box::new(|e| e.tx_hash[0] ^= 1)),
            ("log index", Box::new(|e| e.log_index ^= 1)),
            ("payload", Box::new(|e| e.payload[31] ^= 1)),
        ];
        for (name, mutate) in mutations {
            let mut broken = evidence;
            mutate(&mut broken);
            let counting = CountingLeg::new(&leg);
            assert!(
                run(&counting, &broken.encode()).is_err(),
                "a record with a corrupted {name} must be refused"
            );
            assert_eq!(
                counting.adapt_calls.get(),
                0,
                "a corrupted {name} must never reach the DOM leg"
            );
            assert_eq!(counting.extract_calls.get(), 0);
        }

        // A funding record is not a claim and must never be read as one.
        let funded = port
            .adapter()
            .collect_evidence(&lock_id, EvidenceKind::Funded)
            .expect("funding evidence");
        let counting = CountingLeg::new(&leg);
        assert_eq!(
            run(&counting, &funded.encode()).err(),
            Some(HarnessError::Adapter(
                counterparty_api::AdapterError::EvidenceInvalid
            ))
        );
        assert_eq!(counting.adapt_calls.get(), 0);
    }
}

// ---------------------------------------------------------------------------
// 4. the post-conditions of extraction, tested without faking an extraction
// ---------------------------------------------------------------------------

#[test]
fn the_post_extraction_checks_accept_a_real_scalar_and_reject_everything_else() {
    // Deliberately NOT a fake successful extraction. `dom-leg` is the only
    // thing allowed to produce a scalar from a signature. What is exercised
    // here is the half of the DOM->EVM route that runs *after* a scalar
    // exists, using a scalar the test genuinely holds.
    let (_, cfg) = new_chain();
    let t = scalar();
    let pre = pre_signature_for(&t);
    let terms = terms(&cfg);
    assert_eq!(
        verify_scalar_opens_both_commitments(&t, &pre, &terms.adaptor_address),
        Ok(())
    );
    assert_eq!(
        verify_scalar_opens_both_commitments(&other_scalar(), &pre, &terms.adaptor_address),
        Err(HarnessError::AdaptorPointMismatch)
    );

    let d = deployment(&cfg);
    let (binding, lock_id) = rederive(&d, &terms).expect("derivation");
    let call = build_claim_call(&d, lock_id, binding, &t).expect("claim call");
    assert_eq!(
        call,
        build_claim_call(&d, lock_id, binding, &t).expect("claim call"),
        "I7: the artifact must be byte-identical across runs"
    );
    assert_eq!(call.value, [0u8; 32], "a claim never carries value");
    assert_eq!(
        UnsignedEvmCall::decode(&call.encode()),
        Ok(call),
        "the artifact must survive a durable round trip"
    );
}

#[test]
fn the_claim_artifact_is_a_real_transaction_the_adapter_then_observes() {
    // The artifact the DOM->EVM route would emit is handed to the broadcast
    // seam and comes back out of the adapter as a finalized `Claimed`, with the
    // same scalar. On Anvil this same step runs against the real contract.
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (binding, lock_id) = port.identity().expect("derivation");

    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    finalize(&chain, tip(&chain));
    let (events, cursor) = port.observe(&ChainCursor::default());
    assert!(events
        .iter()
        .any(|e| matches!(e, ObservedEvent::LockOpened { .. })));

    let call = build_claim_call(&deployment(&cfg), lock_id, binding, &scalar()).expect("call");
    assert_eq!(
        port.submit_claim(&call).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    finalize(&chain, tip(&chain));
    let (events, _) = port.observe(&cursor);
    let claimed = events
        .iter()
        .find_map(|e| match e {
            ObservedEvent::LockClaimed { revealed, .. } => Some(*revealed),
            _ => None,
        })
        .expect("the claim must be observable");
    assert_eq!(
        claimed.0,
        scalar(),
        "the scalar must survive the round trip"
    );
    assert_eq!(
        port.revealed_secret(&lock_id).expect("registry"),
        Some(RevealedSecretBytes(scalar()))
    );
}

// ---------------------------------------------------------------------------
// 5. outbox: durable, idempotent, byte-identical, equivocation-hostile
// ---------------------------------------------------------------------------

#[test]
fn the_outbox_replays_after_a_restart_and_resends_byte_identical_bytes() {
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (_, lock_id) = port.identity().expect("derivation");

    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let height_after_first = tip(&chain);
    let key = idempotency_key(
        cfg.chain_id,
        &cfg.contract,
        &lock_id,
        SubmissionIntent::OpenLock,
    );
    let bytes_before = port.outbox().get(&key).expect("record").call.encode();

    // CRASH: the process dies, the chain does not. Everything durable comes
    // back; everything in memory (the adapter's tracked locks, the cursor)
    // does not, and has to be rebuilt.
    let (outbox, broadcaster, clock) = port.into_parts();
    let recovered = Outbox::recover(outbox.into_log()).expect("replay");
    assert_eq!(recovered.len(), 1, "the record must survive the restart");
    assert_eq!(
        recovered.get(&key).expect("record").call.encode(),
        bytes_before,
        "I7: a replayed record must be byte-identical"
    );

    let mut port = build_port(
        &chain,
        &cfg,
        Parts {
            outbox: recovered,
            broadcaster,
            clock,
        },
    );
    assert!(
        matches!(
            port.submit_funding(lock_id).expect("resend"),
            BroadcastOutcome::Accepted | BroadcastOutcome::Duplicate
        ),
        "a resend must be safe"
    );
    assert_eq!(
        tip(&chain),
        height_after_first,
        "I7: the resend must be deduplicated, not mined a second time"
    );
    assert_eq!(port.outbox().len(), 1, "no second record");
    assert_eq!(
        port.outbox().get(&key).expect("record").call.encode(),
        bytes_before
    );
    assert_eq!(port.stats().duplicate_broadcasts, 1);
}

#[test]
fn the_outbox_refuses_to_hold_two_different_artifacts_under_one_key() {
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (binding, lock_id) = port.identity().expect("derivation");
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );

    let (outbox, _, _) = port.into_parts();
    let mut outbox = Outbox::recover(outbox.into_log()).expect("replay");
    let key = idempotency_key(
        cfg.chain_id,
        &cfg.contract,
        &lock_id,
        SubmissionIntent::OpenLock,
    );
    // Same key, different bytes: the equivocation the whole mechanism exists
    // to catch.
    let impostor = build_claim_call(&deployment(&cfg), lock_id, binding, &scalar()).expect("call");
    assert_eq!(
        outbox.submit(key, SubmissionIntent::OpenLock, &impostor),
        Err(OutboxError::Equivocation)
    );
    assert_eq!(outbox.len(), 1, "the log must be unchanged");
}

// ---------------------------------------------------------------------------
// 6. the refund is timestamp-domain only, and the margins are enforced
// ---------------------------------------------------------------------------

#[test]
fn the_driver_refuses_a_refund_until_the_deadline_is_safely_past() {
    // Under B-DOM there is no engine block-height instruction to bridge: the
    // EVM refund answers to the contract's own timestamp deadline, and to
    // nothing else. The driver still refuses to act on a deadline that has
    // not *safely* passed — a stale view must not trigger an early refund.
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, DEADLINE - 1));
    let (_, lock_id) = port.identity().expect("derivation");

    assert!(
        matches!(
            port.submit_refund(lock_id).unwrap_err(),
            HarnessError::Timelock(TimelockError::WindowTooNarrow { .. })
        ),
        "before the deadline the refusal is the margin, not a broadcast"
    );
    assert_eq!(port.stats().refunds_refused_for_timelock, 1);

    // Just past the deadline is still not enough: our view of the chain could
    // be stale by up to the finality + RPC-lag margins.
    port.clock().set(DEADLINE + 1);
    assert!(matches!(
        port.submit_refund(lock_id).unwrap_err(),
        HarnessError::Timelock(TimelockError::WindowTooNarrow { .. })
    ));
    assert_eq!(tip(&chain), 0, "nothing may have been broadcast yet");

    let p = TimelockPolicy::evm();
    port.clock()
        .set(DEADLINE + p.finality_margin + p.rpc_lag_margin);
    assert_eq!(
        port.submit_refund(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    assert_eq!(tip(&chain), 1, "the refund must now be on chain");
    assert_eq!(port.stats().refunds_refused_for_timelock, 2);
}

#[test]
fn the_clock_seam_reports_the_timestamp_domain_and_the_policy_enforces_it() {
    let (chain, cfg) = new_chain();
    let port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 42));
    assert_eq!(
        port.clock().now().expect("clock"),
        TimelockPoint::timestamp(42)
    );
    assert!(matches!(
        TimelockPolicy::evm().require_domain(TimelockPoint::height(42)),
        Err(TimelockError::DomainMismatch {
            expected: TimelockDomain::Timestamp,
            got: TimelockDomain::BlockHeight
        })
    ));
    assert!(matches!(
        TimelockPolicy::dom_sim().require_domain(TimelockPoint::timestamp(42)),
        Err(TimelockError::DomainMismatch {
            expected: TimelockDomain::BlockHeight,
            got: TimelockDomain::Timestamp
        })
    ));
}

// ---------------------------------------------------------------------------
// 7. reorg: the effect is invalidated, the scalar is not (I11)
// ---------------------------------------------------------------------------

#[test]
fn the_adapter_registry_keeps_the_scalar_across_a_reorg() {
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (binding, lock_id) = port.identity().expect("derivation");
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    finalize(&chain, tip(&chain));
    let (_, cursor) = port.observe(&ChainCursor::default());

    counterparty_claims_on_evm(&chain, &cfg, lock_id, binding, scalar());
    finalize(&chain, tip(&chain));
    let (events, cursor) = port.observe(&cursor);
    assert!(events
        .iter()
        .any(|e| matches!(e, ObservedEvent::LockClaimed { .. })));
    assert_eq!(
        port.revealed_secret(&lock_id).expect("registry"),
        Some(RevealedSecretBytes(scalar()))
    );

    // Orphan the claim's block. The funding block below it is one the observer
    // validated, so it is a common ancestor the adapter can name honestly.
    chain.with_mut(|c| c.reorg(1)).expect("chain");
    let (events, rewound) = port.observe(&cursor);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, ObservedEvent::Reorged { .. })),
        "the driver must surface the reorg, not swallow it: {events:?}"
    );
    assert_ne!(rewound, cursor, "the cursor must be rewound");
    assert_eq!(
        port.revealed_secret(&lock_id).expect("registry"),
        Some(RevealedSecretBytes(scalar())),
        "I11: the revealed-secret registry is append-only by construction"
    );

    // Re-scanning the rewound range finds no claim: the settlement effect is
    // genuinely gone, even though the scalar is not.
    let (events, _) = port.observe(&rewound);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, ObservedEvent::LockClaimed { .. })),
        "the orphaned claim must not reappear: {events:?}"
    );
    assert_eq!(
        port.revealed_secret(&lock_id).expect("registry"),
        Some(RevealedSecretBytes(scalar()))
    );
}

#[test]
fn a_reorg_deeper_than_the_validated_history_fails_closed() {
    // The documented case 4 of `adapter_evm::reorg`: the anchor is orphaned and
    // no retained height is still confirmed. The adapter cannot name an
    // ancestor honestly, so it refuses — and the driver surfaces nothing rather
    // than guessing.
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (_, lock_id) = port.identity().expect("derivation");
    port.submit_funding(lock_id).expect("broadcast");
    finalize(&chain, tip(&chain));
    let (_, cursor) = port.observe(&ChainCursor::default());

    chain.with_mut(|c| c.reorg(1)).expect("chain");
    let (events, _) = port.observe(&cursor);
    assert!(events.is_empty(), "nothing may be surfaced: {events:?}");
    assert_eq!(port.stats().scan_failures, 1);
    assert_eq!(
        port.last_error(),
        Some(HarnessError::Adapter(
            counterparty_api::AdapterError::ReorgDetected
        ))
    );
}

// ---------------------------------------------------------------------------
// 8. crash at every step (the f2-harness discipline, at the driver)
// ---------------------------------------------------------------------------

/// One deterministic scenario: each step is a change to the world, followed by
/// an observation. `crash_before_step` kills the driver before that step,
/// exactly as a process restart would, and rebuilds it from what was durable.
/// The cursor is in-memory and legitimately dies with the process; the rebuilt
/// driver rescans from genesis, and the outcome must not change.
fn run_claim_scenario(crash_before_step: Option<usize>) -> (Option<[u8; 32]>, bool) {
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (binding, lock_id) = port.identity().expect("derivation");
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let mut cursor = ChainCursor::default();
    let mut secret_seen = None;

    type Step = fn(&SharedRpc<MockChain>, &EvmAdapterConfig, [u8; 32], [u8; 32]);
    let world: &[Step] = &[
        |chain, _, _, _| finalize(chain, tip(chain)),
        |chain, cfg, lock_id, binding| {
            counterparty_claims_on_evm(chain, cfg, lock_id, binding, scalar());
        },
        |chain, _, _, _| finalize(chain, tip(chain)),
        |chain, _, _, _| {
            chain.with_mut(|c| c.push_block()).expect("chain");
            finalize(chain, tip(chain));
        },
        |_, _, _, _| {},
    ];

    for (i, act) in world.iter().enumerate() {
        if crash_before_step == Some(i) {
            let (outbox, broadcaster, clock) = port.into_parts();
            let outbox = Outbox::recover(outbox.into_log()).expect("durable replay");
            port = build_port(
                &chain,
                &cfg,
                Parts {
                    outbox,
                    broadcaster,
                    clock,
                },
            );
            cursor = ChainCursor::default();
        }
        act(&chain, &cfg, lock_id, binding);
        let (_, next) = port.observe(&cursor);
        cursor = next;
        if let Some(s) = port.revealed_secret(&lock_id).expect("registry") {
            secret_seen = Some(s.0);
        }
    }
    for _ in 0..3 {
        let (_, next) = port.observe(&cursor);
        cursor = next;
    }
    if let Some(s) = port.revealed_secret(&lock_id).expect("registry") {
        secret_seen = Some(s.0);
    }
    let evidence_ok = port
        .adapter()
        .collect_evidence(&lock_id, EvidenceKind::Claimed)
        .is_ok();
    (secret_seen, evidence_ok)
}

#[test]
fn the_claim_scenario_completes_without_a_crash() {
    let (secret, evidence_ok) = run_claim_scenario(None);
    assert_eq!(secret, Some(scalar()));
    assert!(evidence_ok, "the claim evidence must be collectible");
}

#[test]
fn crash_at_every_step_yields_the_same_outcome() {
    let baseline = run_claim_scenario(None);
    for step in 0..5 {
        assert_eq!(
            run_claim_scenario(Some(step)),
            baseline,
            "a crash before step {step} diverged from the no-crash baseline"
        );
    }
}

#[test]
fn a_restart_never_funds_the_lock_twice() {
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (_, lock_id) = port.identity().expect("derivation");
    assert_eq!(
        port.submit_funding(lock_id).expect("broadcast"),
        BroadcastOutcome::Accepted
    );
    let after_first = tip(&chain);

    let (outbox, broadcaster, clock) = port.into_parts();
    let outbox = Outbox::recover(outbox.into_log()).expect("replay");
    let mut port = build_port(
        &chain,
        &cfg,
        Parts {
            outbox,
            broadcaster,
            clock,
        },
    );
    assert!(matches!(
        port.submit_funding(lock_id).expect("resend"),
        BroadcastOutcome::Accepted | BroadcastOutcome::Duplicate
    ));
    assert_eq!(
        tip(&chain),
        after_first,
        "recovery must not mine a second funding"
    );
}

// ---------------------------------------------------------------------------
// 9. the broadcast seam is a seam: a refusal is reported, never assumed away
// ---------------------------------------------------------------------------

#[test]
fn a_refused_broadcast_is_reported_rather_than_treated_as_sent() {
    let (chain, cfg) = new_chain();
    let port_cfg = EvmPortConfig {
        deployment: deployment(&cfg),
        neutral: neutral(&cfg),
        adaptor_point: adaptor_point(),
        terms: terms(&cfg),
        timelock: TimelockPolicy::evm(),
    };
    let mut port: EvmChainPort<MockChain, f3_harness::RefusingBroadcaster, FixedClock, MemoryLog> =
        EvmChainPort::new(
            port_cfg,
            cfg,
            chain.clone(),
            Outbox::recover(MemoryLog::new()).expect("empty"),
            f3_harness::RefusingBroadcaster,
            FixedClock::new(1_000),
        )
        .expect("configuration");
    let (_, lock_id) = port.identity().expect("derivation");
    assert_eq!(
        port.submit_funding(lock_id).unwrap_err(),
        HarnessError::BroadcastRefused
    );
    assert_eq!(port.last_error(), Some(HarnessError::BroadcastRefused));
    assert_eq!(tip(&chain), 0);
    // The record is durable even though the wire refused: a resend later must
    // send the same bytes, not recompute them.
    assert_eq!(port.outbox().len(), 1);
}

// ---------------------------------------------------------------------------
// 10. the scan seam fails closed
// ---------------------------------------------------------------------------

#[test]
fn an_endpoint_that_cannot_serve_finality_surfaces_nothing() {
    let (chain, cfg) = new_chain();
    let mut port = build_port(&chain, &cfg, fresh_parts(&chain, &cfg, 1_000));
    let (_, lock_id) = port.identity().expect("derivation");
    port.submit_funding(lock_id).expect("broadcast");
    // No `finalized` checkpoint has been set: A4-EVM says observe nothing.
    let (events, cursor) = port.observe(&ChainCursor::default());
    assert!(events.is_empty(), "nothing may be surfaced: {events:?}");
    assert_eq!(cursor, ChainCursor::default(), "the cursor must not move");
    assert_eq!(port.stats().scan_failures, 1);
    assert_eq!(
        port.finalized_height(),
        0,
        "with no finalized checkpoint nothing is confirmable"
    );
}

#[test]
fn a_hostile_endpoint_cannot_make_the_driver_surface_events() {
    let raw = MockChain::new(31337, [0xC0; 20]).with_faults(adapter_evm::mock::Faults {
        break_transport: true,
        ..adapter_evm::mock::Faults::default()
    });
    let cfg = adapter_cfg(&MockChain::new(31337, [0xC0; 20]));
    let chain = SharedRpc::new(raw);
    let parts = Parts {
        outbox: Outbox::recover(MemoryLog::new()).expect("empty"),
        broadcaster: MockBroadcaster::new(chain.clone(), cfg.funder, terms(&cfg)),
        clock: FixedClock::new(1_000),
    };
    let port = build_port(&chain, &cfg, parts);
    let (events, _) = port.observe(&ChainCursor::default());
    assert!(events.is_empty());
    assert_eq!(port.stats().scan_failures, 1);
}
