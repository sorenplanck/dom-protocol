//! Adversarial contract tests for the threshold-authenticated solver-status authority.

#![cfg(target_os = "linux")]

use btc_crypto::SecpContext;
use deployment_registry::AuthoritySetV1;
use kaystra_core::types::ParticipantId;
use solver_status::{
    DurableSolverStatusStoreV1, SignedSolverStatusV1, SolverOperationalStateV1,
    SolverStatusErrorV1, SolverStatusFreshnessPolicyV1, SolverStatusInstallOutcomeV1,
    SolverStatusObservationV1, SolverStatusScopeV1, SolverStatusSignatureV1,
    SolverStatusStatementV1, SolverStatusStoreConfigV1, MAX_STATUS_LIFETIME_SECONDS_V1,
};
use std::error::Error;
use std::os::unix::fs::PermissionsExt as _;

const NETWORK: [u8; 32] = [0x11; 32];
const REGISTRY: [u8; 32] = [0x22; 32];
const ROSTER: [u8; 32] = [0x33; 32];
const SOLVER: ParticipantId = ParticipantId([0x44; 32]);
const SECRETS: [[u8; 32]; 3] = [[0x51; 32], [0x52; 32], [0x53; 32]];

type TestResult = core::result::Result<(), Box<dyn Error>>;

fn scope() -> SolverStatusScopeV1 {
    SolverStatusScopeV1 {
        network_id: NETWORK,
        registry_digest: REGISTRY,
        registry_epoch: 7,
        roster_snapshot: ROSTER,
        solver_id: SOLVER,
    }
}

fn authorities(secp: &SecpContext) -> Result<AuthoritySetV1, Box<dyn Error>> {
    let keys = SECRETS
        .iter()
        .map(|secret| secp.xonly_public_key(secret))
        .collect::<core::result::Result<Vec<_>, _>>()?;
    Ok(AuthoritySetV1::new(2, keys)?)
}

fn config(
    secp: &SecpContext,
    authorities: &AuthoritySetV1,
) -> Result<SolverStatusStoreConfigV1, Box<dyn Error>> {
    Ok(SolverStatusStoreConfigV1::new(
        scope(),
        authorities,
        secp,
        SolverStatusFreshnessPolicyV1 {
            max_status_lifetime_seconds: 60,
        },
    )?)
}

fn statement(
    epoch: u64,
    state: SolverOperationalStateV1,
    observed_at_seconds: u64,
) -> Result<SolverStatusStatementV1, Box<dyn Error>> {
    Ok(SolverStatusStatementV1::new(
        scope(),
        SolverStatusObservationV1 {
            status_epoch: epoch,
            source_evidence_digest: [u8::try_from(epoch)?; 32],
            state,
            observed_at_seconds,
            valid_until_seconds: observed_at_seconds + 30,
        },
    )?)
}

fn signed(
    secp: &SecpContext,
    statement: SolverStatusStatementV1,
) -> Result<SignedSolverStatusV1, Box<dyn Error>> {
    let digest = statement.statement_digest()?;
    let mut signatures = Vec::new();
    for (index, secret) in SECRETS.iter().take(2).enumerate() {
        let (signature, _) = secp.sign_bip340(secret, &digest, &[u8::try_from(index + 1)?; 32])?;
        signatures.push(SolverStatusSignatureV1 {
            signer_index: u16::try_from(index)?,
            signature,
        });
    }
    Ok(SignedSolverStatusV1::new(statement, signatures)?)
}

#[test]
fn active_status_is_durable_idempotent_and_restart_safe() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("solver-status.sqlite");
    let secp = SecpContext::new(&[0x61; 32]);
    let authority_set = authorities(&secp)?;
    let config = config(&secp, &authority_set)?;
    let signed = signed(
        &secp,
        statement(1, SolverOperationalStateV1::Active, 1_000)?,
    )?;
    let mut store =
        DurableSolverStatusStoreV1::create_production(&path, config, authority_set.clone(), &secp)?;
    assert_eq!(
        store.install(&signed, &secp, 1_001)?,
        SolverStatusInstallOutcomeV1::Installed
    );
    assert_eq!(
        store.install(&signed, &secp, 1_001)?,
        SolverStatusInstallOutcomeV1::AlreadyCurrent
    );
    let capability = store.prove_current_active(&secp, 1_002)?;
    assert_eq!(capability.solver_id(), SOLVER);
    assert_eq!(capability.status_epoch(), 1);
    assert_eq!(capability.store_revision(), 1);
    assert_eq!(capability.source_evidence_digest(), [1; 32]);
    assert_eq!(
        store.prove_current_active(&secp, 1_001).err(),
        Some(SolverStatusErrorV1::ClockRollback)
    );
    drop(store);

    let mut reopened =
        DurableSolverStatusStoreV1::open_production(&path, config, authority_set, &secp)?;
    assert_eq!(
        reopened.prove_current_active(&secp, 1_001).err(),
        Some(SolverStatusErrorV1::ClockRollback)
    );
    let recovered = reopened.prove_current_active(&secp, 1_003)?;
    assert_eq!(recovered.statement_digest(), capability.statement_digest());
    assert_eq!(recovered.store_revision(), 1);
    Ok(())
}

#[test]
fn active_proof_carries_the_exact_signed_durable_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("solver-status-signed-head.sqlite");
    let secp = SecpContext::new(&[0x69; 32]);
    let authority_set = authorities(&secp)?;
    let config = config(&secp, &authority_set)?;
    let signed_head = signed(
        &secp,
        statement(7, SolverOperationalStateV1::Active, 7_000)?,
    )?;
    let expected_bytes = signed_head.canonical_bytes()?;
    let mut store =
        DurableSolverStatusStoreV1::create_production(&path, config, authority_set, &secp)?;
    store.install(&signed_head, &secp, 7_001)?;

    let proof = store.prove_current_active_signed(&secp, 7_002)?;
    assert_eq!(proof.capability().status_epoch(), 7);
    assert_eq!(proof.capability().store_revision(), 1);
    assert_eq!(proof.signed_head().canonical_bytes()?, expected_bytes);
    assert_eq!(
        proof.signed_head().statement()?.statement_digest()?,
        proof.capability().statement_digest()
    );

    let (capability, transported) = proof.into_parts();
    assert_eq!(capability.source_evidence_digest(), [7; 32]);
    assert_eq!(transported.canonical_bytes()?, expected_bytes);
    Ok(())
}

#[test]
fn suspended_and_slashing_heads_never_mint_active_capability() -> TestResult {
    for (index, state) in [
        SolverOperationalStateV1::Suspended,
        SolverOperationalStateV1::Slashing,
    ]
    .into_iter()
    .enumerate()
    {
        let directory = tempfile::tempdir()?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = directory
            .path()
            .join(format!("solver-status-{index}.sqlite"));
        let secp = SecpContext::new(&[0x62; 32]);
        let authority_set = authorities(&secp)?;
        let config = config(&secp, &authority_set)?;
        let mut store =
            DurableSolverStatusStoreV1::create_production(&path, config, authority_set, &secp)?;
        store.install(&signed(&secp, statement(1, state, 2_000)?)?, &secp, 2_001)?;
        assert_eq!(
            store.prove_current_active(&secp, 2_001).err(),
            Some(SolverStatusErrorV1::NotActive)
        );
    }
    Ok(())
}

#[test]
fn rollback_equivocation_and_cross_scope_are_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("solver-status.sqlite");
    let secp = SecpContext::new(&[0x63; 32]);
    let authority_set = authorities(&secp)?;
    let config = config(&secp, &authority_set)?;
    let mut store =
        DurableSolverStatusStoreV1::create_production(&path, config, authority_set, &secp)?;
    store.install(
        &signed(
            &secp,
            statement(2, SolverOperationalStateV1::Active, 3_000)?,
        )?,
        &secp,
        3_001,
    )?;

    let rollback = signed(
        &secp,
        statement(1, SolverOperationalStateV1::Active, 3_001)?,
    )?;
    assert_eq!(
        store.install(&rollback, &secp, 3_002).err(),
        Some(SolverStatusErrorV1::Rollback)
    );

    let equivocation = signed(
        &secp,
        statement(2, SolverOperationalStateV1::Suspended, 3_000)?,
    )?;
    assert_eq!(
        store.install(&equivocation, &secp, 3_002).err(),
        Some(SolverStatusErrorV1::Equivocation)
    );

    let foreign = SolverStatusStatementV1::new(
        SolverStatusScopeV1 {
            network_id: [0x99; 32],
            ..scope()
        },
        SolverStatusObservationV1 {
            status_epoch: 3,
            source_evidence_digest: [3; 32],
            state: SolverOperationalStateV1::Active,
            observed_at_seconds: 3_002,
            valid_until_seconds: 3_030,
        },
    )?;
    assert_eq!(
        store.install(&signed(&secp, foreign)?, &secp, 3_003).err(),
        Some(SolverStatusErrorV1::ScopeMismatch)
    );
    Ok(())
}

#[test]
fn signatures_freshness_and_canonical_encoding_fail_closed() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("solver-status.sqlite");
    let secp = SecpContext::new(&[0x64; 32]);
    let authority_set = authorities(&secp)?;
    assert_eq!(
        SolverStatusStoreConfigV1::new(
            scope(),
            &authority_set,
            &secp,
            SolverStatusFreshnessPolicyV1 {
                max_status_lifetime_seconds: MAX_STATUS_LIFETIME_SECONDS_V1 + 1,
            },
        )
        .err(),
        Some(SolverStatusErrorV1::InvalidConfiguration)
    );
    let config = config(&secp, &authority_set)?;
    let mut store =
        DurableSolverStatusStoreV1::create_production(&path, config, authority_set, &secp)?;

    let current = statement(1, SolverOperationalStateV1::Active, 4_000)?;
    let mut signed_bytes = signed(&secp, current)?.canonical_bytes()?;
    signed_bytes.push(0);
    assert_eq!(
        SignedSolverStatusV1::decode(&signed_bytes).err(),
        Some(SolverStatusErrorV1::InvalidEncoding)
    );

    let mut tampered_signature_bytes = signed(&secp, current)?.canonical_bytes()?;
    let last = tampered_signature_bytes
        .last_mut()
        .ok_or_else(|| std::io::Error::other("signed status unexpectedly empty"))?;
    *last ^= 1;
    let tampered_signature = SignedSolverStatusV1::decode(&tampered_signature_bytes)?;
    assert_eq!(
        store.install(&tampered_signature, &secp, 4_001).err(),
        Some(SolverStatusErrorV1::InvalidSignature)
    );

    let digest = current.statement_digest()?;
    let (only_signature, _) = secp.sign_bip340(&SECRETS[0], &digest, &[1; 32])?;
    let below_threshold = SignedSolverStatusV1::new(
        current,
        vec![SolverStatusSignatureV1 {
            signer_index: 0,
            signature: only_signature,
        }],
    )?;
    assert_eq!(
        store.install(&below_threshold, &secp, 4_001).err(),
        Some(SolverStatusErrorV1::ThresholdNotMet)
    );

    assert_eq!(
        store.install(&signed(&secp, current)?, &secp, 4_031).err(),
        Some(SolverStatusErrorV1::StaleStatus)
    );
    let future = statement(2, SolverOperationalStateV1::Active, 4_100)?;
    assert_eq!(
        store.install(&signed(&secp, future)?, &secp, 4_090).err(),
        Some(SolverStatusErrorV1::StaleStatus)
    );
    Ok(())
}
