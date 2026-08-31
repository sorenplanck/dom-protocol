//! Adversarial tests for the pre-F6 negotiation-time authority and its durable clock.

mod common;

use common::{fixture, sign_digest, EVIDENCE_SECRETS, EVIDENCE_TIME, REGISTRY_NETWORK};
use rfq::v2::{NativeClockKindV2, NegotiationClockV2};
use route_time_anchor::{
    resolved_dom_profile_digest_v1, DurablePreF6TimeStoreV2, PreF6CanonicalCheckpointV2,
    PreF6TimeEvidenceV2, PreF6TimeInstallOutcomeV2, PreF6TimePolicyLimitsV2, PreF6TimePolicyV2,
    PreF6TimeScopeRequestV2, PreF6TimeScopeV2, PreF6TimeSignatureV2, RouteTimeAnchorErrorV2,
    SignedPreF6TimeEvidenceV2,
};
use std::error::Error;
use std::os::unix::fs::PermissionsExt as _;

type TestResult = core::result::Result<(), Box<dyn Error>>;

fn build_policy(
    fixture: &common::Fixture,
    rfq_id: [u8; 32],
) -> Result<PreF6TimePolicyV2, Box<dyn Error>> {
    let manifest = fixture.registry.manifest();
    let scope = PreF6TimeScopeV2::new(PreF6TimeScopeRequestV2 {
        network_id: REGISTRY_NETWORK,
        session_id: fixture.upstream.session_id.0,
        route_id: [0x81; 32],
        composition_id: [0x82; 32],
        rfq_id,
        negotiation_clock: NegotiationClockV2 {
            chain_id: manifest.dom.chain_id,
            profile_digest: resolved_dom_profile_digest_v1(&fixture.registry)?,
            authority_scope: [0x83; 32],
            kind: NativeClockKindV2::BlockHeight,
        },
        registry_digest: fixture.registry.manifest_digest(),
        registry_epoch: manifest.epoch,
        profile_bundle_digest: [0x84; 32],
    })?;
    Ok(PreF6TimePolicyV2::from_registry(
        scope,
        &fixture.registry,
        PreF6TimePolicyLimitsV2 {
            valid_from_seconds: 900_000,
            expires_at_seconds: 4_000_000,
            max_evidence_age_seconds: 300,
        },
    )?)
}

fn checkpoint(
    fixture: &common::Fixture,
    finalized_height: u64,
    finalized_hash: [u8; 32],
) -> Result<PreF6CanonicalCheckpointV2, Box<dyn Error>> {
    let manifest = fixture.registry.manifest();
    Ok(PreF6CanonicalCheckpointV2 {
        chain_id: manifest.dom.chain_id,
        profile_digest: resolved_dom_profile_digest_v1(&fixture.registry)?,
        genesis_hash: manifest.dom.genesis_hash,
        clock_kind: NativeClockKindV2::BlockHeight,
        finalized_height,
        finalized_hash,
        finalized_parent_hash: [0x91; 32],
        finalized_timestamp_seconds: EVIDENCE_TIME - 10,
        canonical_tip_height: finalized_height + 100,
        canonical_tip_hash: [0x92; 32],
        canonicality_evidence_digest: [0x93; 32],
    })
}

fn signed(
    fixture: &common::Fixture,
    evidence: PreF6TimeEvidenceV2,
) -> Result<SignedPreF6TimeEvidenceV2, Box<dyn Error>> {
    let digest = evidence.evidence_digest()?;
    let signatures = sign_digest(&fixture.secp, &EVIDENCE_SECRETS, &digest, 0x70)
        .into_iter()
        .map(|signature| PreF6TimeSignatureV2 {
            signer_index: signature.signer_index,
            signature: signature.signature,
        })
        .collect();
    Ok(SignedPreF6TimeEvidenceV2::new(evidence, signatures)?)
}

#[test]
fn exact_current_dom_height_is_durable_and_restart_safe() -> TestResult {
    let fixture = fixture();
    let policy = build_policy(&fixture, [0xa1; 32])?;
    let evidence = PreF6TimeEvidenceV2::new(
        policy,
        1,
        [0; 32],
        EVIDENCE_TIME,
        EVIDENCE_TIME + 120,
        checkpoint(&fixture, 100, [0xa2; 32])?,
    )?;
    let signed = signed(&fixture, evidence)?;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("pre-f6-time.sqlite");
    let mut store = DurablePreF6TimeStoreV2::create_production(
        &path,
        policy,
        fixture.evidence_authorities.clone(),
        &fixture.secp,
    )?;
    assert_eq!(store.scope_digest(), policy.scope().scope_digest());
    assert_eq!(
        store.negotiation_clock(),
        policy.scope().negotiation_clock()
    );
    let (outcome, capability) =
        store.install_and_prove_current_pre_f6_time(&signed, &fixture.secp, EVIDENCE_TIME + 1)?;
    assert_eq!(outcome, PreF6TimeInstallOutcomeV2::Installed);
    assert_eq!(capability.observed_value(), 100);
    assert_eq!(
        capability.observation().clock,
        policy.scope().negotiation_clock()
    );
    assert_eq!(capability.store_revision(), 1);
    let revalidated = store.prove_current_pre_f6_time(&fixture.secp, EVIDENCE_TIME + 2)?;
    assert_eq!(revalidated.evidence_digest(), capability.evidence_digest());
    assert_eq!(
        store
            .prove_current_pre_f6_time(&fixture.secp, EVIDENCE_TIME + 1)
            .err(),
        Some(RouteTimeAnchorErrorV2::ClockRollback)
    );
    let (replay, replayed) =
        store.install_and_prove_current_pre_f6_time(&signed, &fixture.secp, EVIDENCE_TIME + 3)?;
    assert_eq!(replay, PreF6TimeInstallOutcomeV2::AlreadyCurrent);
    assert_eq!(replayed.evidence_digest(), capability.evidence_digest());
    drop(store);

    let mut reopened = DurablePreF6TimeStoreV2::open_production(
        &path,
        policy,
        fixture.evidence_authorities.clone(),
        &fixture.secp,
    )?;
    assert_eq!(reopened.scope_digest(), policy.scope().scope_digest());
    assert_eq!(
        reopened.negotiation_clock(),
        policy.scope().negotiation_clock()
    );
    assert_eq!(
        reopened
            .prove_current_pre_f6_time(&fixture.secp, EVIDENCE_TIME + 2)
            .err(),
        Some(RouteTimeAnchorErrorV2::ClockRollback)
    );
    let (_, recovered) = reopened.install_and_prove_current_pre_f6_time(
        &signed,
        &fixture.secp,
        EVIDENCE_TIME + 4,
    )?;
    assert_eq!(recovered.evidence_digest(), capability.evidence_digest());
    assert_eq!(recovered.store_revision(), 1);
    Ok(())
}

#[test]
fn evidence_chain_is_exact_and_reorg_or_rollback_fails_closed() -> TestResult {
    let fixture = fixture();
    let policy = build_policy(&fixture, [0xb1; 32])?;
    let first = PreF6TimeEvidenceV2::new(
        policy,
        1,
        [0; 32],
        EVIDENCE_TIME,
        EVIDENCE_TIME + 120,
        checkpoint(&fixture, 200, [0xb2; 32])?,
    )?;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("pre-f6-time.sqlite");
    let mut store = DurablePreF6TimeStoreV2::create_production(
        &path,
        policy,
        fixture.evidence_authorities.clone(),
        &fixture.secp,
    )?;
    store.install_and_prove_current_pre_f6_time(
        &signed(&fixture, first)?,
        &fixture.secp,
        EVIDENCE_TIME + 1,
    )?;

    let second = PreF6TimeEvidenceV2::new(
        policy,
        2,
        first.evidence_digest()?,
        EVIDENCE_TIME + 10,
        EVIDENCE_TIME + 130,
        checkpoint(&fixture, 201, [0xb3; 32])?,
    )?;
    let (_, current) = store.install_and_prove_current_pre_f6_time(
        &signed(&fixture, second)?,
        &fixture.secp,
        EVIDENCE_TIME + 11,
    )?;
    assert_eq!(current.observed_value(), 201);

    let rollback = PreF6TimeEvidenceV2::new(
        policy,
        3,
        second.evidence_digest()?,
        EVIDENCE_TIME + 20,
        EVIDENCE_TIME + 140,
        checkpoint(&fixture, 199, [0xb4; 32])?,
    )?;
    assert_eq!(
        store
            .install_and_prove_current_pre_f6_time(
                &signed(&fixture, rollback)?,
                &fixture.secp,
                EVIDENCE_TIME + 21,
            )
            .err(),
        Some(RouteTimeAnchorErrorV2::EvidenceRollback)
    );

    let same_height_reorg = PreF6TimeEvidenceV2::new(
        policy,
        3,
        second.evidence_digest()?,
        EVIDENCE_TIME + 20,
        EVIDENCE_TIME + 140,
        checkpoint(&fixture, 201, [0xb5; 32])?,
    )?;
    assert_eq!(
        store
            .install_and_prove_current_pre_f6_time(
                &signed(&fixture, same_height_reorg)?,
                &fixture.secp,
                EVIDENCE_TIME + 21,
            )
            .err(),
        Some(RouteTimeAnchorErrorV2::AnchorReorged)
    );
    Ok(())
}

#[test]
fn threshold_scope_freshness_and_encoding_are_not_bypassable() -> TestResult {
    let fixture = fixture();
    let policy = build_policy(&fixture, [0xc1; 32])?;
    let evidence = PreF6TimeEvidenceV2::new(
        policy,
        1,
        [0; 32],
        EVIDENCE_TIME,
        EVIDENCE_TIME + 30,
        checkpoint(&fixture, 300, [0xc2; 32])?,
    )?;
    let signed = signed(&fixture, evidence)?;
    let mut bytes = signed.canonical_bytes()?;
    bytes.push(0);
    assert_eq!(
        SignedPreF6TimeEvidenceV2::decode(&bytes, policy).err(),
        Some(RouteTimeAnchorErrorV2::NonCanonicalEncoding)
    );

    let mut tampered = signed.canonical_bytes()?;
    let last = tampered
        .last_mut()
        .ok_or_else(|| std::io::Error::other("signed evidence unexpectedly empty"))?;
    *last ^= 1;
    let tampered = SignedPreF6TimeEvidenceV2::decode(&tampered, policy)?;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("pre-f6-time.sqlite");
    let mut store = DurablePreF6TimeStoreV2::create_production(
        &path,
        policy,
        fixture.evidence_authorities.clone(),
        &fixture.secp,
    )?;
    assert_eq!(
        store
            .install_and_prove_current_pre_f6_time(&tampered, &fixture.secp, EVIDENCE_TIME + 1,)
            .err(),
        Some(RouteTimeAnchorErrorV2::InvalidSignature)
    );
    assert_eq!(
        store
            .install_and_prove_current_pre_f6_time(&signed, &fixture.secp, EVIDENCE_TIME + 30,)
            .err(),
        Some(RouteTimeAnchorErrorV2::EvidenceStale)
    );

    let foreign_policy = build_policy(&fixture, [0xc3; 32])?;
    assert_eq!(
        SignedPreF6TimeEvidenceV2::decode(&signed.canonical_bytes()?, foreign_policy).err(),
        Some(RouteTimeAnchorErrorV2::InvalidEvidence)
    );
    Ok(())
}
