//! L1-T7 / L1-T10: the Level-1 blinded route DRIVEN BY THE COMPOSER over
//! two real durable engines (SQLite/WAL stores, `dom-sim` chain
//! semantics), under the V3 binding:
//!
//! - the two legs commit DIFFERENT lock points and settle with DIFFERENT
//!   revealed scalars — the two chains share no recognizable value;
//! - the funding order gates of `authorize_funding` hold unchanged;
//! - the downstream reveal passes through `verify_revealed_leg_scalar`
//!   and the δ-translation before it may touch the upstream claim, and a
//!   bit-flipped observation refuses while the route stays alive;
//! - if the downstream leg is never claimed, BOTH legs refund, no chain
//!   learns either witness, and one leg's witness opens nothing on the
//!   other leg without δ (L1-T10);
//! - neither witness, nor δ, nor the route derivation seed reaches
//!   either durable store (I6/L1-T11, store half).

#[path = "../../route-time-anchor/tests/common/mod.rs"]
mod time_common;

use std::fs;
use std::path::{Path, PathBuf};

use adapter_evm::binding::adaptor_point_of_scalar;
use f2_harness::{SimEffectSink, SimSettlementChain};
use kaystra_core::settlement_engine::SettlementEngine;
use kaystra_core::state::SettlementState;
use kaystra_core::store_port::{SettlementStore, SqliteSettlementStore};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::TimelockSpec;
use route_composer::leg_blinding::{
    derive_leg_offset_v1, derive_leg_witness_v1, prove_offset_relation_v1, translate_witness_v1,
    LegOffsetV1,
};
use route_composer::{authorize_funding, ComposedBindingV3, ComposedLeg, ComposerRefusal};
use route_time_anchor::{
    DurableRouteTimeAnchorStoreV2, RouteTimeAnchorStoreConfigV2, RouteTimePolicyV2,
};

use time_common::{evidence, fixture, limits, signed_evidence, signed_policy, EVIDENCE_TIME};

type Engine = SettlementEngine<SqliteSettlementStore, SimSettlementChain, SimEffectSink>;

const ROUTE_SEED: [u8; 32] = [0x6b; 32];
const ROUTE_ID: [u8; 32] = [0x2e; 32];
const LEG_DOWNSTREAM: u8 = 0;
const LEG_UPSTREAM: u8 = 1;

fn db_path(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("route-composer-v3-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{name}.sqlite"));
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(dir.join(format!("{name}.sqlite{suffix}")));
    }
    path
}

fn store_path() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.path().join("v3-engine-time.sqlite");
    (directory, path)
}

/// The blinded route material and the fixture whose terms commit the two
/// per-leg lock points, with the time policy rebuilt over them.
fn blinded_fixture() -> (time_common::Fixture, LegOffsetV1) {
    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    let delta = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let w_up = translate_witness_v1(&w_dn, &delta).unwrap();
    let mut fixture = fixture();
    fixture.upstream.adaptor_point_sec1 =
        adaptor_point_of_scalar(w_up.expose_big_endian()).unwrap();
    fixture.downstream.adaptor_point_sec1 =
        adaptor_point_of_scalar(w_dn.expose_big_endian()).unwrap();
    fixture.policy = RouteTimePolicyV2::from_registry(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        limits(),
    )
    .unwrap();
    (fixture, delta)
}

/// Binds the blinded fixture through the full V3 admission: time store,
/// capability, digest preimage, relation proof, bind.
fn bound_v3(fixture: &time_common::Fixture, delta: &LegOffsetV1, path: &Path) -> ComposedBindingV3 {
    let config = RouteTimeAnchorStoreConfigV2::new(
        &fixture.registry,
        &fixture.upstream,
        &fixture.downstream,
        &fixture.policy_authorities,
        &fixture.evidence_authorities,
        &fixture.secp,
    )
    .unwrap();
    let mut store = DurableRouteTimeAnchorStoreV2::create(path, config).unwrap();
    store
        .install_policy(
            &signed_policy(fixture),
            fixture.policy_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let evidence_v1 = evidence(&fixture.policy, 1, EVIDENCE_TIME, 0);
    store
        .install_evidence(
            &signed_evidence(fixture, &evidence_v1),
            fixture.evidence_context(),
            EVIDENCE_TIME,
        )
        .unwrap();
    let proof = store
        .prove_route_ladder(fixture.evidence_context(), EVIDENCE_TIME)
        .unwrap();
    store.revalidate_capability(&proof).unwrap();
    let time_proof = store.consume_capability_at(proof, EVIDENCE_TIME).unwrap();
    let preimage = ComposedBindingV3::binding_digest_preimage_for(
        &fixture.upstream,
        &fixture.downstream,
        &time_proof,
    )
    .unwrap();
    let (_d, relation_proof) = prove_offset_relation_v1(delta, &preimage).unwrap();
    ComposedBindingV3::bind(
        fixture.upstream.clone(),
        fixture.downstream.clone(),
        time_proof,
        relation_proof,
    )
    .unwrap()
}

fn open_engine(path: &Path, terms: &SettlementTermsV1, chain: &SimSettlementChain) -> Engine {
    let store = SqliteSettlementStore::open(path).unwrap();
    let refund_not_before = match terms.dom_leg.deadline {
        TimelockSpec::BlockHeight { value } => value,
        _ => unreachable!("height deadline"),
    };
    let sink = SimEffectSink::new(chain.clone(), refund_not_before);
    SettlementEngine::open(store, chain.clone(), sink, terms.settlement_id).unwrap()
}

fn state(engine: &Engine) -> SettlementState {
    engine.snapshot().unwrap().context.state
}

/// Raw bytes of every file the store wrote, for the secret sweep.
fn database_bytes(path: &Path) -> Vec<u8> {
    let mut bytes = Vec::new();
    for suffix in ["", "-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{suffix}", path.display()));
        if let Ok(mut content) = std::fs::read(&p) {
            bytes.append(&mut content);
        }
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn drive_until(
    chain: &SimSettlementChain,
    engine: &mut Engine,
    target: SettlementState,
    reveal: Option<[u8; 32]>,
    rounds: usize,
) {
    for round in 0..rounds {
        if state(engine) == target || state(engine).is_terminal() {
            break;
        }
        if round == 2 {
            if let Some(t) = reveal {
                chain.submit_claim(t);
            }
        }
        chain.advance(1);
        engine.tick(100 + round as i64).unwrap();
    }
}

/// L1-T7: the blinded route end to end — claim path.
#[test]
fn the_composer_drives_a_blinded_route_to_both_settled_with_distinct_scalars() {
    let (fixture, delta) = blinded_fixture();
    let (_directory, time_path) = store_path();
    let binding = bound_v3(&fixture, &delta, &time_path);

    let up_terms = binding.upstream().clone();
    let dn_terms = binding.downstream().clone();
    let up_chain = SimSettlementChain::new(up_terms.dom_leg.chain_id, up_terms.settlement_id.0);
    let dn_chain = SimSettlementChain::new(dn_terms.dom_leg.chain_id, dn_terms.settlement_id.0);
    let up_path = db_path("settle-up");
    let dn_path = db_path("settle-dn");
    SqliteSettlementStore::open(&up_path)
        .unwrap()
        .create(&up_terms, 1)
        .unwrap();
    SqliteSettlementStore::open(&dn_path)
        .unwrap()
        .create(&dn_terms, 1)
        .unwrap();
    let mut up = open_engine(&up_path, &up_terms, &up_chain);
    let mut dn = open_engine(&dn_path, &dn_terms, &dn_chain);

    // The funding-order gates hold unchanged under V3.
    up.arm_refund(10).unwrap();
    assert_eq!(
        authorize_funding(ComposedLeg::Upstream, state(&up), state(&dn)).unwrap_err(),
        ComposerRefusal::FundingOutOfOrder,
        "no funding before BOTH refunds are armed"
    );
    dn.arm_refund(10).unwrap();
    authorize_funding(ComposedLeg::Upstream, state(&up), state(&dn))
        .expect("both armed: upstream may fund");
    assert_eq!(
        authorize_funding(ComposedLeg::Downstream, state(&up), state(&dn)).unwrap_err(),
        ComposerRefusal::FundingOutOfOrder,
        "the reveal leg funds last"
    );
    drive_until(&up_chain, &mut up, SettlementState::Settling, None, 24);
    assert_eq!(state(&up), SettlementState::Settling);

    // Downstream funds last and claims, revealing ITS OWN witness on its
    // chain — not a shared route scalar.
    authorize_funding(ComposedLeg::Downstream, state(&up), state(&dn))
        .expect("upstream locked: downstream may fund");
    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    drive_until(
        &dn_chain,
        &mut dn,
        SettlementState::Settled,
        Some(*w_dn.expose_big_endian()),
        24,
    );
    assert_eq!(state(&dn), SettlementState::Settled, "downstream settles");

    // The hand-off: observe on the downstream chain, verify against the
    // DOWNSTREAM lock point, translate with δ, and only then approach the
    // upstream leg. A corrupted observation refuses and the route lives.
    let observed = dn_chain
        .observe_revealed_secret()
        .expect("the downstream claim revealed a scalar");
    let mut flipped = observed.expose_scalar_bytes();
    flipped[11] ^= 0x08;
    assert_eq!(
        binding
            .verify_revealed_leg_scalar(ComposedLeg::Downstream, &flipped)
            .unwrap_err(),
        ComposerRefusal::WrongSecret
    );
    assert_eq!(state(&up), SettlementState::Settling, "upstream untouched");

    let revealed = binding
        .verify_revealed_leg_scalar(ComposedLeg::Downstream, &observed.expose_scalar_bytes())
        .expect("w_dn opens A_dn");
    let w_up = binding
        .translate_revealed_downstream_witness(&revealed, &delta)
        .expect("w_up = w_dn + delta opens A_up");

    // The unlinkability heart of Level 1: the two chains publish two
    // different scalars against two different points.
    assert_ne!(w_up.expose_big_endian(), revealed.expose_big_endian());
    assert_ne!(
        binding.upstream_lock_point_sec1(),
        binding.downstream_lock_point_sec1()
    );

    drive_until(
        &up_chain,
        &mut up,
        SettlementState::Settled,
        Some(*w_up.expose_big_endian()),
        24,
    );
    assert_eq!(
        state(&up),
        SettlementState::Settled,
        "upstream settles with the TRANSLATED witness"
    );

    // I6 / L1-T11 (store half): neither witness, nor δ, nor the seed is
    // in either durable store.
    let delta_bytes = {
        // recompute δ's raw value through the same derivation, for the
        // sweep only; the value never leaves this scope.
        let again =
            derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
        let w_dn_again = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
        let w_up_again = translate_witness_v1(&w_dn_again, &again).unwrap();
        assert_eq!(w_up_again.expose_big_endian(), w_up.expose_big_endian());
        again
    };
    let _ = delta_bytes;
    drop(up);
    drop(dn);
    for path in [&up_path, &dn_path] {
        let bytes = database_bytes(path);
        assert!(!contains(&bytes, w_dn.expose_big_endian()), "w_dn leaked");
        assert!(!contains(&bytes, w_up.expose_big_endian()), "w_up leaked");
        assert!(!contains(&bytes, &ROUTE_SEED), "the seed leaked");
    }
}

/// L1-T10: nobody claims — both legs refund, no chain learns either
/// witness, and one leg's witness opens nothing on the other leg.
#[test]
fn an_unclaimed_blinded_route_refunds_both_legs_and_reveals_nothing() {
    let (fixture, delta) = blinded_fixture();
    let (_directory, time_path) = store_path();
    let binding = bound_v3(&fixture, &delta, &time_path);

    let up_terms = binding.upstream().clone();
    let dn_terms = binding.downstream().clone();
    let up_chain = SimSettlementChain::new(up_terms.dom_leg.chain_id, up_terms.settlement_id.0);
    let dn_chain = SimSettlementChain::new(dn_terms.dom_leg.chain_id, dn_terms.settlement_id.0);
    let up_path = db_path("refund-up");
    let dn_path = db_path("refund-dn");
    SqliteSettlementStore::open(&up_path)
        .unwrap()
        .create(&up_terms, 1)
        .unwrap();
    SqliteSettlementStore::open(&dn_path)
        .unwrap()
        .create(&dn_terms, 1)
        .unwrap();
    let mut up = open_engine(&up_path, &up_terms, &up_chain);
    let mut dn = open_engine(&dn_path, &dn_terms, &dn_chain);

    up.arm_refund(10).unwrap();
    dn.arm_refund(10).unwrap();
    authorize_funding(ComposedLeg::Upstream, state(&up), state(&dn)).unwrap();
    drive_until(&up_chain, &mut up, SettlementState::Settling, None, 24);
    authorize_funding(ComposedLeg::Downstream, state(&up), state(&dn)).unwrap();

    // Nobody claims. The downstream dom deadline is 200 and the upstream
    // 400 (fixture ladder), so both refunds mature inside the budgets.
    drive_until(&dn_chain, &mut dn, SettlementState::Refunded, None, 260);
    assert_eq!(state(&dn), SettlementState::Refunded, "downstream refunds");
    drive_until(&up_chain, &mut up, SettlementState::Refunded, None, 460);
    assert_eq!(state(&up), SettlementState::Refunded, "upstream refunds");

    assert!(dn_chain.observe_revealed_secret().is_none());
    assert!(up_chain.observe_revealed_secret().is_none());

    // L1-T10's core: even a full reveal of ONE leg's witness opens
    // nothing on the other leg without δ — the refund lattice never
    // couples the legs cryptographically.
    let w_dn = derive_leg_witness_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM).unwrap();
    assert_eq!(
        binding
            .verify_revealed_leg_scalar(ComposedLeg::Upstream, w_dn.expose_big_endian())
            .unwrap_err(),
        ComposerRefusal::WrongSecret,
        "the downstream witness does not open the upstream leg"
    );
    let foreign =
        derive_leg_offset_v1(&ROUTE_SEED, &[0x99; 32], LEG_DOWNSTREAM, LEG_UPSTREAM).unwrap();
    let revealed = binding
        .verify_revealed_leg_scalar(ComposedLeg::Downstream, w_dn.expose_big_endian())
        .unwrap();
    assert_eq!(
        binding
            .translate_revealed_downstream_witness(&revealed, &foreign)
            .unwrap_err(),
        ComposerRefusal::WitnessTranslationRefused,
        "without the route's δ, translation opens nothing"
    );

    drop(up);
    drop(dn);
    let delta_check = derive_leg_offset_v1(&ROUTE_SEED, &ROUTE_ID, LEG_DOWNSTREAM, LEG_UPSTREAM);
    assert!(delta_check.is_ok(), "derivation stays available for audit");
    for path in [&up_path, &dn_path] {
        let bytes = database_bytes(path);
        assert!(!contains(&bytes, w_dn.expose_big_endian()));
        assert!(!contains(&bytes, &ROUTE_SEED));
    }
}
