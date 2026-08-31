use std::cell::{Cell, RefCell};
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::rc::Rc;

use f6_engine::candidate_book::{
    BondReservationAttestationRequestV2, BondReservationAttestationV2,
};
use kaystra_core::types::ParticipantId;
use rfq::v2::{
    NativeClockKindV2, NegotiationClockV2, NegotiationInstantV2, QuoteProposalV2, RouteV2,
    SettlementPositionV2,
};
use rfq::{AssetId, LegDirectionV1, RouteLegV1};
use route_transport::RouteWireContextV1;
use solver_status::{
    SignedSolverStatusV1, SolverOperationalStateV1, SolverStatusObservationV1, SolverStatusScopeV1,
    SolverStatusSignatureV1, SolverStatusStatementV1,
};
use static_assertions::assert_not_impl_any;

use super::*;
use crate::production_f6::{ProductionF6PinsV2, ProductionSolverF6BindingV2};

assert_not_impl_any!(PreparedF6BondAttestationSigningRequestV2: Clone, Copy);
assert_not_impl_any!(ProductionF6ReservedSignerKeysV2: Clone, Copy);
assert_not_impl_any!(ProductionF6CandidateAuthorityInputsV2: Clone, Copy);
assert_not_impl_any!(ProductionF6CandidateAttestationAuthorityStoreV2: Clone, Copy);

type RequestLogV2 = Rc<RefCell<Vec<(Digest32, Digest32)>>>;

#[derive(Clone, Copy)]
enum BehaviorV2 {
    Good,
    Unavailable,
    Refused,
    WrongIntent,
    WrongDigest,
    InvalidSignature,
}

struct TestSignerV2 {
    index: u16,
    independent_authority_id: Digest32,
    public_key: [u8; 32],
    secret: [u8; 32],
    behavior: BehaviorV2,
    unavailable_once: Rc<Cell<bool>>,
    requests: RequestLogV2,
}

impl super::super::source_seal::Sealed for TestSignerV2 {}

impl ProductionF6BondAttestationSignerV2 for TestSignerV2 {
    fn independent_authority_id(&self) -> Digest32 {
        self.independent_authority_id
    }

    fn signer_index(&self) -> u16 {
        self.index
    }

    fn signer_public_key(&self) -> [u8; 32] {
        self.public_key
    }

    fn sign_bond_attestation(
        &mut self,
        request: &PreparedF6BondAttestationSigningRequestV2,
    ) -> Result<ProductionF6BondAttestationSignatureV2, ProductionF6BondSignerErrorV2> {
        self.requests
            .borrow_mut()
            .push((request.intent_digest(), request.attestation_digest()));
        if self.unavailable_once.replace(false) || matches!(self.behavior, BehaviorV2::Unavailable)
        {
            return Err(ProductionF6BondSignerErrorV2::Unavailable);
        }
        if matches!(self.behavior, BehaviorV2::Refused) {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        let decoded = BondReservationAttestationV2::decode(request.attestation_bytes())
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?;
        if request.signer_index() != self.index
            || request.signer_public_key() != self.public_key
            || decoded
                .attestation_digest()
                .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?
                != request.attestation_digest()
        {
            return Err(ProductionF6BondSignerErrorV2::Refused);
        }
        let context = SecpContext::new(&[0x91; 32]);
        let mut signature = context
            .sign_bip340(&self.secret, &request.attestation_digest(), &[0x92; 32])
            .map_err(|_| ProductionF6BondSignerErrorV2::Refused)?
            .0;
        if matches!(self.behavior, BehaviorV2::InvalidSignature) {
            signature[0] ^= 1;
        }
        Ok(ProductionF6BondAttestationSignatureV2::new(
            self.index,
            if matches!(self.behavior, BehaviorV2::WrongIntent) {
                [0xa1; 32]
            } else {
                request.intent_digest()
            },
            if matches!(self.behavior, BehaviorV2::WrongDigest) {
                [0xa2; 32]
            } else {
                request.attestation_digest()
            },
            signature,
        ))
    }
}

struct FixtureV2 {
    binding: ProductionSolverF6BindingV2,
    bond: AuthoritySetV1,
    status: AuthoritySetV1,
    bond_secrets: [[u8; 32]; 3],
    status_secrets: [[u8; 32]; 2],
    quote: QuoteV2,
    intent: PersistedAttestationIntentV2,
}

impl FixtureV2 {
    fn new(threshold: u16) -> Result<Self, Box<dyn Error>> {
        let secp = Self::secp();
        let bond_secrets = [[0x11; 32], [0x12; 32], [0x13; 32]];
        let status_secrets = [[0x21; 32], [0x22; 32]];
        let bond = authority_set(&secp, threshold, &bond_secrets)?;
        let status = authority_set(&secp, 2, &status_secrets)?;
        let solver = ParticipantId([0x31; 32]);
        let clock = NegotiationClockV2 {
            chain_id: rfq::ChainId([0x32; 32]),
            profile_digest: [0x33; 32],
            authority_scope: [0x34; 32],
            kind: NativeClockKindV2::BlockHeight,
        };
        let route = RouteV2 {
            composition_id: [0x35; 32],
            position: SettlementPositionV2::Upstream,
            legs: [
                RouteLegV1 {
                    chain_id: rfq::ChainId([0x36; 32]),
                    asset: AssetId([0x37; 32]),
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: clock.chain_id,
                    asset: AssetId([0x38; 32]),
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        };
        let quote = QuoteV2::create(QuoteProposalV2 {
            rfq_id: [0x39; 32],
            solver,
            route,
            net_output: 95,
            total_input: 100,
            total_fee: 5,
            execution_deadline: NegotiationInstantV2 {
                clock,
                value: 1_080,
            },
            bond_reservation_id: [0x3a; 32],
            bond_policy_version: 3,
            expiry: NegotiationInstantV2 {
                clock,
                value: 1_050,
            },
            solver_signature: [0x3b; 64],
        })?;
        let statement = SolverStatusStatementV1::new(
            SolverStatusScopeV1 {
                network_id: [0x41; 32],
                registry_digest: [0x42; 32],
                registry_epoch: 4,
                roster_snapshot: [0x43; 32],
                solver_id: solver,
            },
            SolverStatusObservationV1 {
                status_epoch: 7,
                source_evidence_digest: [0x44; 32],
                state: SolverOperationalStateV1::Active,
                observed_at_seconds: 90,
                valid_until_seconds: 180,
            },
        )?;
        let signed_status = sign_status(&secp, statement, &status_secrets)?;
        let binding = ProductionSolverF6BindingV2 {
            wire: RouteWireContextV1 {
                network_id: statement.network_id(),
                session_id: [0x45; 32],
                route_id: [0x46; 32],
                roster_snapshot: statement.roster_snapshot(),
                policy_version: 3,
            },
            rfq_id: quote.rfq_id,
            composition_id: quote.route.composition_id,
            position: quote.route.position,
            initiator: ParticipantId([0x47; 32]),
            solver,
            dom_chain_id: clock.chain_id,
            negotiation_clock: clock,
            pins: ProductionF6PinsV2 {
                inventory_binding_digest: [0x48; 32],
                registry_digest: statement.registry_digest(),
                registry_epoch: statement.registry_epoch(),
                profile_bundle_digest: [0x49; 32],
                bond_policy_hash: [0x4a; 32],
                bond_asset_binding_digest: [0x4b; 32],
                required_collateral: 10,
                bond_attestation_authority_set_digest: bond_reservation_authority_set_digest_v2(
                    &bond, &secp,
                )?,
                remote_status_authority_set_digest: candidate_status_authority_set_digest_v2(
                    &status, &secp,
                )?,
                solver_status_scope_digest: [0x4c; 32],
                pre_f6_time_scope_digest: [0x4d; 32],
            },
        };
        let attestation = BondReservationAttestationV2::new(BondReservationAttestationRequestV2 {
            network_id: binding.wire.network_id,
            composition_id: binding.composition_id,
            position: binding.position,
            rfq_id: binding.rfq_id,
            quote_id: quote.quote_id,
            solver,
            reservation_id: quote.bond_reservation_id,
            bond_policy_hash: binding.pins.bond_policy_hash,
            registry_digest: binding.pins.registry_digest,
            registry_epoch: binding.pins.registry_epoch,
            bond_asset_binding_digest: binding.pins.bond_asset_binding_digest,
            required_collateral: binding.pins.required_collateral,
            reserved_collateral: 12,
            reservation_state_digest: [0x4e; 32],
            source_evidence_digest: [0x4f; 32],
            solver_status_statement_digest: statement.statement_digest()?,
            solver_status_epoch: statement.status_epoch(),
            solver_status_valid_until_seconds: statement.valid_until_seconds(),
            observed_at_seconds: 100,
            valid_until_seconds: 150,
            sequence: 1,
            previous_attestation_digest: ZERO_DIGEST,
        })?;
        let intent = make_intent(quote, attestation, signed_status)?;
        Ok(Self {
            binding,
            bond,
            status,
            bond_secrets,
            status_secrets,
            quote,
            intent,
        })
    }

    fn secp() -> SecpContext {
        SecpContext::new(&[0x81; 32])
    }

    fn reserved(&self) -> Result<ProductionF6ReservedSignerKeysV2, Box<dyn Error>> {
        let secp = Self::secp();
        Ok(ProductionF6ReservedSignerKeysV2::new(
            vec![secp.xonly_public_key(&[0x71; 32])?],
            vec![secp.xonly_public_key(&[0x72; 32])?],
            vec![secp.xonly_public_key(&[0x73; 32])?],
        )?)
    }

    fn signers(
        &self,
        behaviors: [BehaviorV2; 3],
        unavailable_once: [bool; 3],
        requests: &RequestLogV2,
    ) -> Vec<Box<dyn ProductionF6BondAttestationSignerV2>> {
        self.signers_with_independent_ids(
            behaviors,
            unavailable_once,
            [[0xc0; 32], [0xc1; 32], [0xc2; 32]],
            requests,
        )
    }

    fn signers_with_independent_ids(
        &self,
        behaviors: [BehaviorV2; 3],
        unavailable_once: [bool; 3],
        independent_authority_ids: [Digest32; 3],
        requests: &RequestLogV2,
    ) -> Vec<Box<dyn ProductionF6BondAttestationSignerV2>> {
        [0u16, 1, 2]
            .into_iter()
            .zip(self.bond_secrets)
            .zip(behaviors)
            .zip(unavailable_once)
            .zip(independent_authority_ids)
            .map(
                |((((index, secret), behavior), unavailable_once), independent_authority_id)| {
                    Box::new(TestSignerV2 {
                        index,
                        independent_authority_id,
                        public_key: self.bond.xonly_keys()[usize::from(index)],
                        secret,
                        behavior,
                        unavailable_once: Rc::new(Cell::new(unavailable_once)),
                        requests: Rc::clone(requests),
                    }) as Box<dyn ProductionF6BondAttestationSignerV2>
                },
            )
            .collect()
    }

    fn copy_intent(&self) -> Result<PersistedAttestationIntentV2, ProductionF6ErrorV2> {
        decode_intent(&encode_intent(&self.intent)?)
    }

    fn replacement_intent(
        &self,
        sequence: u64,
        previous_attestation_digest: Digest32,
        observed_at_seconds: u64,
        source_evidence_digest: Digest32,
    ) -> Result<PersistedAttestationIntentV2, Box<dyn Error>> {
        let valid_until_seconds = observed_at_seconds
            .checked_add(40)
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?
            .min(180);
        let attestation = BondReservationAttestationV2::new(BondReservationAttestationRequestV2 {
            source_evidence_digest,
            observed_at_seconds,
            valid_until_seconds,
            sequence,
            previous_attestation_digest,
            ..self.intent.attestation.request()
        })?;
        Ok(make_intent(
            self.quote,
            attestation,
            self.intent.signed_status.clone(),
        )?)
    }

    fn replacement_intent_with_status_epoch(
        &self,
        sequence: u64,
        previous_attestation_digest: Digest32,
        observed_at_seconds: u64,
        status_epoch: u64,
    ) -> Result<PersistedAttestationIntentV2, Box<dyn Error>> {
        let old = self.intent.signed_status.statement()?;
        let statement = SolverStatusStatementV1::new(
            SolverStatusScopeV1 {
                network_id: old.network_id(),
                registry_digest: old.registry_digest(),
                registry_epoch: old.registry_epoch(),
                roster_snapshot: old.roster_snapshot(),
                solver_id: old.solver_id(),
            },
            SolverStatusObservationV1 {
                status_epoch,
                source_evidence_digest: [0xe8; 32],
                state: SolverOperationalStateV1::Active,
                observed_at_seconds,
                valid_until_seconds: 180,
            },
        )?;
        let signed_status = sign_status(&Self::secp(), statement, &self.status_secrets)?;
        let attestation = BondReservationAttestationV2::new(BondReservationAttestationRequestV2 {
            solver_status_statement_digest: statement.statement_digest()?,
            solver_status_epoch: statement.status_epoch(),
            solver_status_valid_until_seconds: statement.valid_until_seconds(),
            source_evidence_digest: [0xe9; 32],
            observed_at_seconds,
            valid_until_seconds: 170,
            sequence,
            previous_attestation_digest,
            ..self.intent.attestation.request()
        })?;
        Ok(make_intent(self.quote, attestation, signed_status)?)
    }

    fn create(
        &self,
        path: &std::path::Path,
        signers: Vec<Box<dyn ProductionF6BondAttestationSignerV2>>,
    ) -> Result<ProductionF6CandidateAttestationAuthorityStoreV2, ProductionF6ErrorV2> {
        ProductionF6CandidateAttestationAuthorityStoreV2::create_production(
            path,
            self.binding,
            ProductionF6CandidateAuthorityInputsV2::new(
                self.bond.clone(),
                self.status.clone(),
                self.reserved()
                    .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?,
                Self::secp(),
                signers,
            ),
        )
    }

    fn open(
        &self,
        path: &std::path::Path,
        signers: Vec<Box<dyn ProductionF6BondAttestationSignerV2>>,
    ) -> Result<ProductionF6CandidateAttestationAuthorityStoreV2, ProductionF6ErrorV2> {
        ProductionF6CandidateAttestationAuthorityStoreV2::open_production(
            path,
            self.binding,
            ProductionF6CandidateAuthorityInputsV2::new(
                self.bond.clone(),
                self.status.clone(),
                self.reserved()
                    .map_err(|_| ProductionF6ErrorV2::InvalidBinding)?,
                Self::secp(),
                signers,
            ),
        )
    }
}

fn authority_set(
    secp: &SecpContext,
    threshold: u16,
    secrets: &[[u8; 32]],
) -> Result<AuthoritySetV1, Box<dyn Error>> {
    let keys = secrets
        .iter()
        .map(|secret| secp.xonly_public_key(secret))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(AuthoritySetV1::new(threshold, keys)?)
}

fn sign_status(
    secp: &SecpContext,
    statement: SolverStatusStatementV1,
    secrets: &[[u8; 32]],
) -> Result<SignedSolverStatusV1, Box<dyn Error>> {
    let digest = statement.statement_digest()?;
    let indexes = [0u16, 1];
    let signatures = indexes
        .into_iter()
        .zip(secrets.iter())
        .map(|(index, secret)| {
            Ok(SolverStatusSignatureV1 {
                signer_index: index,
                signature: secp
                    .sign_bip340(secret, &digest, &[0x82 + index as u8; 32])?
                    .0,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok(SignedSolverStatusV1::new(statement, signatures)?)
}

fn path(directory: &tempfile::TempDir) -> Result<PathBuf, Box<dyn Error>> {
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    Ok(directory.path().join("candidate-attestation.sqlite3"))
}

const GOOD: [BehaviorV2; 3] = [BehaviorV2::Good; 3];
const DOWN: [BehaviorV2; 3] = [BehaviorV2::Unavailable; 3];

#[test]
fn journal_capacity_reserves_result_slot_at_exact_bound() {
    assert_eq!(MAX_ATTESTATION_JOURNAL_ROWS, MAX_ATTESTATION_REVISIONS * 3);
    let maximum_supersedes_before_first_result = MAX_ATTESTATION_JOURNAL_ROWS - 2;
    assert_eq!(maximum_supersedes_before_first_result, 766);
    assert!(journal_capacity_allows(
        1 + maximum_supersedes_before_first_result,
        1
    ));
    assert!(journal_capacity_allows(MAX_ATTESTATION_JOURNAL_ROWS - 2, 2));
    assert!(!journal_capacity_allows(
        MAX_ATTESTATION_JOURNAL_ROWS - 1,
        2
    ));
    assert!(journal_capacity_allows(MAX_ATTESTATION_JOURNAL_ROWS - 1, 1));
    assert!(!journal_capacity_allows(MAX_ATTESTATION_JOURNAL_ROWS, 1));
    assert!(!journal_capacity_allows(0, 0));
    let maximum_sequence = 256_u64;
    assert_eq!(
        usize::try_from(maximum_sequence),
        Ok(MAX_ATTESTATION_REVISIONS)
    );
    assert!(validate_economic_sequence(maximum_sequence, [0xa0; 32]).is_ok());
    assert!(matches!(
        validate_economic_sequence(maximum_sequence + 1, [0xa0; 32]),
        Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
    ));
    assert!(validate_economic_sequence(1, ZERO_DIGEST).is_ok());
    assert!(validate_economic_sequence(1, [0xa0; 32]).is_err());
    assert!(validate_economic_sequence(2, ZERO_DIGEST).is_err());
}

#[test]
fn intent_is_durable_before_io_and_retry_never_resequences() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(3)?;
    let directory = tempfile::tempdir()?;
    let path = path(&directory)?;
    let requests = Rc::new(RefCell::new(Vec::new()));
    let mut authority = fixture.create(
        &path,
        fixture.signers(GOOD, [false, false, true], &requests),
    )?;
    assert!(matches!(
        authority.attest_prepared(fixture.copy_intent()?, 100),
        Err(ProductionF6ErrorV2::CandidateAttestationUnavailable)
    ));
    let journal = authority.store.read_journal()?;
    assert_eq!(journal.len(), 1);
    assert_eq!(journal[0].kind, INTENT_JOURNAL_KIND);
    let durable_intent = decode_intent(&journal[0].payload)?;
    assert_eq!(durable_intent.attestation.request().sequence, 1);
    assert_eq!(
        durable_intent
            .attestation
            .request()
            .previous_attestation_digest,
        ZERO_DIGEST
    );
    assert_eq!(requests.borrow().len(), 3);
    assert!(requests
        .borrow()
        .iter()
        .all(|(intent, _)| *intent == fixture.intent.digest));

    let delivery = authority.attest_prepared(fixture.copy_intent()?, 101)?;
    let journal = authority.store.read_journal()?;
    assert_eq!(journal.len(), 2);
    assert_eq!(journal[1].sequence, 2);
    assert_eq!(requests.borrow().len(), 6);
    assert!(requests
        .borrow()
        .iter()
        .all(|(intent, _)| *intent == fixture.intent.digest));
    assert_eq!(
        delivery.status().canonical_bytes()?,
        fixture.intent.signed_status.canonical_bytes()?
    );
    Ok(())
}

#[test]
fn restart_reuses_pending_and_complete_without_signer_io() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(2)?;
    let directory = tempfile::tempdir()?;
    let path = path(&directory)?;
    let first_requests = Rc::new(RefCell::new(Vec::new()));
    let mut first = fixture.create(&path, fixture.signers(DOWN, [false; 3], &first_requests))?;
    assert!(first.attest_prepared(fixture.copy_intent()?, 100).is_err());
    drop(first);

    let second_requests = Rc::new(RefCell::new(Vec::new()));
    let mut second = fixture.open(
        &path,
        fixture.signers(
            [BehaviorV2::Good, BehaviorV2::Good, BehaviorV2::Unavailable],
            [false; 3],
            &second_requests,
        ),
    )?;
    let expected = second
        .attest_prepared(fixture.copy_intent()?, 101)?
        .canonical_bytes()?;
    drop(second);

    let replay_requests = Rc::new(RefCell::new(Vec::new()));
    let mut replay = fixture.open(&path, fixture.signers(DOWN, [false; 3], &replay_requests))?;
    assert_eq!(
        replay
            .attest_prepared(fixture.copy_intent()?, 102)?
            .canonical_bytes()?,
        expected
    );
    assert!(replay_requests.borrow().is_empty());
    assert_eq!(replay.store.read_journal()?.len(), 2);
    Ok(())
}

#[test]
fn pending_head_change_is_superseded_durably_then_retried_after_restart(
) -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(2)?;
    let directory = tempfile::tempdir()?;
    let path = path(&directory)?;
    let requests = Rc::new(RefCell::new(Vec::new()));
    let mut authority = fixture.create(&path, fixture.signers(DOWN, [false; 3], &requests))?;
    assert!(authority
        .attest_prepared(fixture.copy_intent()?, 100)
        .is_err());
    let alternate = fixture.replacement_intent_with_status_epoch(1, ZERO_DIGEST, 101, 8)?;
    assert!(matches!(
        authority.attest_prepared(alternate, 101),
        Err(ProductionF6ErrorV2::CandidateAttestationUnavailable)
    ));
    let journal = authority.store.read_journal()?;
    assert_eq!(journal.len(), 2);
    assert_eq!(journal[1].kind, SUPERSEDE_JOURNAL_KIND);
    drop(authority);

    let restart_requests = Rc::new(RefCell::new(Vec::new()));
    let mut restarted =
        fixture.open(&path, fixture.signers(GOOD, [false; 3], &restart_requests))?;
    let replacement = fixture.replacement_intent_with_status_epoch(1, ZERO_DIGEST, 101, 8)?;
    let delivery = restarted.attest_prepared(replacement, 102)?;
    assert_eq!(delivery.attestation().attestation()?.request().sequence, 1);
    assert_eq!(restarted.store.read_journal()?.len(), 3);
    assert_eq!(restart_requests.borrow().len(), 3);
    assert_eq!(delivery.status().statement()?.status_epoch(), 8);
    Ok(())
}

#[test]
fn multiple_pending_supersedes_preserve_economic_sequence_until_result(
) -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(2)?;
    let directory = tempfile::tempdir()?;
    let path = path(&directory)?;
    let requests = Rc::new(RefCell::new(Vec::new()));
    let mut authority = fixture.create(&path, fixture.signers(DOWN, [false; 3], &requests))?;
    assert!(authority
        .attest_prepared(fixture.copy_intent()?, 100)
        .is_err());
    for evidence in [[0xc1; 32], [0xc2; 32], [0xc3; 32], [0xc4; 32]] {
        let replacement = fixture.replacement_intent(1, ZERO_DIGEST, 101, evidence)?;
        assert!(matches!(
            authority.attest_prepared(replacement, 101),
            Err(ProductionF6ErrorV2::CandidateAttestationUnavailable)
        ));
    }
    assert_eq!(authority.store.read_journal()?.len(), 5);
    drop(authority);

    let retry_requests = Rc::new(RefCell::new(Vec::new()));
    let mut retry = fixture.open(&path, fixture.signers(GOOD, [false; 3], &retry_requests))?;
    let latest = fixture.replacement_intent(1, ZERO_DIGEST, 101, [0xc4; 32])?;
    let delivery = retry.attest_prepared(latest, 102)?;
    let request = delivery.attestation().attestation()?.request();
    assert_eq!(request.sequence, 1);
    assert_eq!(request.previous_attestation_digest, ZERO_DIGEST);
    assert_eq!(retry.store.read_journal()?.len(), 6);
    Ok(())
}

#[test]
fn completed_refresh_chains_sequence_and_previous_digest() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(2)?;
    let directory = tempfile::tempdir()?;
    let path = path(&directory)?;
    let requests = Rc::new(RefCell::new(Vec::new()));
    let mut authority = fixture.create(&path, fixture.signers(GOOD, [false; 3], &requests))?;
    let first = authority.attest_prepared(fixture.copy_intent()?, 100)?;
    let previous = first.attestation().attestation()?.attestation_digest()?;
    let refresh = fixture.replacement_intent(2, previous, 120, [0xb2; 32])?;
    let second = authority.attest_prepared(refresh, 120)?;
    let request = second.attestation().attestation()?.request();
    assert_eq!(request.sequence, 2);
    assert_eq!(request.previous_attestation_digest, previous);
    let journal = authority.store.read_journal()?;
    assert_eq!(journal.len(), 4);
    assert_eq!(journal[2].kind, INTENT_JOURNAL_KIND);
    assert_eq!(journal[3].kind, RESULT_JOURNAL_KIND);
    let signed_history = authority.signed_candidate_history(&fixture.binding)?;
    assert_eq!(signed_history.len(), 2);
    assert_eq!(
        signed_history[0].canonical_bytes()?,
        first.canonical_bytes()?
    );
    assert_eq!(
        signed_history[1].canonical_bytes()?,
        second.canonical_bytes()?
    );

    drop(authority);
    let no_io = Rc::new(RefCell::new(Vec::new()));
    let mut replay = fixture.open(&path, fixture.signers(DOWN, [false; 3], &no_io))?;
    let exact = fixture.replacement_intent(2, previous, 120, [0xb2; 32])?;
    assert_eq!(
        replay.attest_prepared(exact, 121)?.canonical_bytes()?,
        second.canonical_bytes()?
    );
    assert!(no_io.borrow().is_empty());
    Ok(())
}

#[test]
fn expired_completed_head_is_replaced_by_next_signed_revision() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(2)?;
    let directory = tempfile::tempdir()?;
    let path = path(&directory)?;
    let requests = Rc::new(RefCell::new(Vec::new()));
    let mut authority = fixture.create(&path, fixture.signers(GOOD, [false; 3], &requests))?;
    let first = authority.attest_prepared(fixture.copy_intent()?, 100)?;
    let previous = first.attestation().attestation()?.attestation_digest()?;
    assert!(matches!(
        authority.attest_prepared(fixture.copy_intent()?, 150),
        Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
    ));
    let refresh = fixture.replacement_intent(2, previous, 151, [0xcb; 32])?;
    let current = authority.attest_prepared(refresh, 151)?;
    assert_eq!(current.attestation().attestation()?.request().sequence, 2);
    assert_eq!(authority.store.read_journal()?.len(), 4);
    Ok(())
}

#[test]
fn crash_after_refresh_intent_retries_same_sequence_and_previous_digest(
) -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(2)?;
    let directory = tempfile::tempdir()?;
    let path = path(&directory)?;
    let first_requests = Rc::new(RefCell::new(Vec::new()));
    let mut first = fixture.create(&path, fixture.signers(GOOD, [false; 3], &first_requests))?;
    let initial = first.attest_prepared(fixture.copy_intent()?, 100)?;
    let previous = initial.attestation().attestation()?.attestation_digest()?;
    drop(first);

    let cut_requests = Rc::new(RefCell::new(Vec::new()));
    let mut cut = fixture.open(&path, fixture.signers(DOWN, [false; 3], &cut_requests))?;
    let refresh = fixture.replacement_intent(2, previous, 120, [0xba; 32])?;
    assert!(matches!(
        cut.attest_prepared(refresh, 120),
        Err(ProductionF6ErrorV2::CandidateAttestationUnavailable)
    ));
    assert_eq!(cut.store.read_journal()?.len(), 3);
    drop(cut);

    let retry_requests = Rc::new(RefCell::new(Vec::new()));
    let mut retry = fixture.open(&path, fixture.signers(GOOD, [false; 3], &retry_requests))?;
    let exact = fixture.replacement_intent(2, previous, 120, [0xba; 32])?;
    let delivery = retry.attest_prepared(exact, 121)?;
    let request = delivery.attestation().attestation()?.request();
    assert_eq!(request.sequence, 2);
    assert_eq!(request.previous_attestation_digest, previous);
    let journal = retry.store.read_journal()?;
    assert_eq!(journal.len(), 4);
    let durable_intent_digest = decode_intent(&journal[2].payload)?.digest;
    assert!(retry_requests
        .borrow()
        .iter()
        .all(|(intent, _)| *intent == durable_intent_digest));

    let signed_history = retry.signed_candidate_history(&fixture.binding)?;
    assert_eq!(signed_history.len(), 2);
    let receipt_path = directory.path().join("post-result-receipts.sqlite3");
    let receipt_binding = ProductionStoreBindingV1::new(
        fixture
            .binding
            .authority_digest(super::super::RECEIPT_BINDING_DOMAIN)?,
    )?;
    let mut receipts = Store::create_production(&receipt_path, receipt_binding)?;
    for historical in &signed_history {
        super::super::persist_outbound_quote_receipt(&mut receipts, fixture.binding, historical)?;
    }
    let recovered_head =
        super::super::read_outbound_quote_receipt_head(&receipts, fixture.binding)?
            .ok_or(ProductionF6ErrorV2::InvalidCandidateAttestation)?;
    assert_eq!(
        recovered_head.canonical_bytes()?,
        delivery.canonical_bytes()?
    );
    assert_eq!(receipts.read_journal()?.len(), 2);
    Ok(())
}

#[test]
fn sequence_gap_and_wrong_previous_digest_never_append() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(2)?;
    let directory = tempfile::tempdir()?;
    let path = path(&directory)?;
    let requests = Rc::new(RefCell::new(Vec::new()));
    let mut authority = fixture.create(&path, fixture.signers(GOOD, [false; 3], &requests))?;
    let first = authority.attest_prepared(fixture.copy_intent()?, 100)?;
    let previous = first.attestation().attestation()?.attestation_digest()?;
    let wrong_previous = fixture.replacement_intent(2, [0xb3; 32], 120, [0xb4; 32])?;
    assert!(matches!(
        authority.attest_prepared(wrong_previous, 120),
        Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
    ));
    let gap = fixture.replacement_intent(3, previous, 120, [0xb5; 32])?;
    assert!(matches!(
        authority.attest_prepared(gap, 120),
        Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
    ));
    assert_eq!(authority.store.read_journal()?.len(), 2);
    Ok(())
}

#[test]
fn every_mismatched_response_is_fail_closed() -> Result<(), Box<dyn Error>> {
    for bad in [
        BehaviorV2::Refused,
        BehaviorV2::WrongIntent,
        BehaviorV2::WrongDigest,
        BehaviorV2::InvalidSignature,
    ] {
        let fixture = FixtureV2::new(2)?;
        let directory = tempfile::tempdir()?;
        let path = path(&directory)?;
        let requests = Rc::new(RefCell::new(Vec::new()));
        let mut authority = fixture.create(
            &path,
            fixture.signers(
                [bad, BehaviorV2::Good, BehaviorV2::Good],
                [false; 3],
                &requests,
            ),
        )?;
        assert!(matches!(
            authority.attest_prepared(fixture.copy_intent()?, 100),
            Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
        ));
        assert_eq!(authority.store.read_journal()?.len(), 1);
    }
    Ok(())
}

#[test]
fn duplicate_threshold_and_cross_role_keys_fail_before_create() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(2)?;
    let reused_reserved = FixtureV2::secp().xonly_public_key(&[0x70; 32])?;
    assert!(matches!(
        ProductionF6ReservedSignerKeysV2::new(
            vec![reused_reserved],
            vec![reused_reserved],
            vec![FixtureV2::secp().xonly_public_key(&[0x73; 32])?],
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    let directory = tempfile::tempdir()?;
    let candidate_path = path(&directory)?;
    let requests = Rc::new(RefCell::new(Vec::new()));
    let mut duplicate = fixture.signers(GOOD, [false; 3], &requests);
    duplicate[1] = Box::new(TestSignerV2 {
        index: 0,
        independent_authority_id: [0xc1; 32],
        public_key: fixture.bond.xonly_keys()[0],
        secret: fixture.bond_secrets[0],
        behavior: BehaviorV2::Good,
        unavailable_once: Rc::new(Cell::new(false)),
        requests: Rc::new(RefCell::new(Vec::new())),
    });
    assert!(matches!(
        fixture.create(&candidate_path, duplicate),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    assert!(!candidate_path.exists());

    let duplicate_id_directory = tempfile::tempdir()?;
    let duplicate_id_path = path(&duplicate_id_directory)?;
    let duplicate_id_requests = Rc::new(RefCell::new(Vec::new()));
    let duplicate_ids = [[0xd1; 32], [0xd1; 32], [0xd2; 32]];
    assert!(matches!(
        fixture.create(
            &duplicate_id_path,
            fixture.signers_with_independent_ids(
                GOOD,
                [false; 3],
                duplicate_ids,
                &duplicate_id_requests,
            ),
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    assert!(!duplicate_id_path.exists());

    let weak = FixtureV2::new(1)?;
    let weak_directory = tempfile::tempdir()?;
    let weak_path = path(&weak_directory)?;
    let weak_requests = Rc::new(RefCell::new(Vec::new()));
    assert!(matches!(
        weak.create(&weak_path, weak.signers(GOOD, [false; 3], &weak_requests)),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    assert!(!weak_path.exists());

    let overlap_directory = tempfile::tempdir()?;
    let overlap_path = path(&overlap_directory)?;
    let overlap = ProductionF6ReservedSignerKeysV2::new(
        vec![fixture.bond.xonly_keys()[0]],
        vec![FixtureV2::secp().xonly_public_key(&[0x72; 32])?],
        vec![FixtureV2::secp().xonly_public_key(&[0x73; 32])?],
    )?;
    let overlap_requests = Rc::new(RefCell::new(Vec::new()));
    assert!(matches!(
        ProductionF6CandidateAttestationAuthorityStoreV2::create_production(
            &overlap_path,
            fixture.binding,
            ProductionF6CandidateAuthorityInputsV2::new(
                fixture.bond.clone(),
                fixture.status.clone(),
                overlap,
                FixtureV2::secp(),
                fixture.signers(GOOD, [false; 3], &overlap_requests),
            ),
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    assert!(!overlap_path.exists());

    let status_overlap_directory = tempfile::tempdir()?;
    let status_overlap_path = path(&status_overlap_directory)?;
    let mut status_overlap_binding = fixture.binding;
    status_overlap_binding
        .pins
        .remote_status_authority_set_digest =
        candidate_status_authority_set_digest_v2(&fixture.bond, &FixtureV2::secp())?;
    let status_overlap_requests = Rc::new(RefCell::new(Vec::new()));
    assert!(matches!(
        ProductionF6CandidateAttestationAuthorityStoreV2::create_production(
            &status_overlap_path,
            status_overlap_binding,
            ProductionF6CandidateAuthorityInputsV2::new(
                fixture.bond.clone(),
                fixture.bond.clone(),
                fixture.reserved()?,
                FixtureV2::secp(),
                fixture.signers(GOOD, [false; 3], &status_overlap_requests),
            ),
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    assert!(!status_overlap_path.exists());

    let weak_status_directory = tempfile::tempdir()?;
    let weak_status_path = path(&weak_status_directory)?;
    let weak_status = AuthoritySetV1::new(1, fixture.status.xonly_keys().to_vec())?;
    let mut weak_status_binding = fixture.binding;
    weak_status_binding.pins.remote_status_authority_set_digest =
        candidate_status_authority_set_digest_v2(&weak_status, &FixtureV2::secp())?;
    let weak_status_requests = Rc::new(RefCell::new(Vec::new()));
    assert!(matches!(
        ProductionF6CandidateAttestationAuthorityStoreV2::create_production(
            &weak_status_path,
            weak_status_binding,
            ProductionF6CandidateAuthorityInputsV2::new(
                fixture.bond.clone(),
                weak_status,
                fixture.reserved()?,
                FixtureV2::secp(),
                fixture.signers(GOOD, [false; 3], &weak_status_requests),
            ),
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    assert!(!weak_status_path.exists());

    let reserved_status_directory = tempfile::tempdir()?;
    let reserved_status_path = path(&reserved_status_directory)?;
    let status_reserved = ProductionF6ReservedSignerKeysV2::new(
        vec![fixture.status.xonly_keys()[0]],
        vec![FixtureV2::secp().xonly_public_key(&[0x72; 32])?],
        vec![FixtureV2::secp().xonly_public_key(&[0x73; 32])?],
    )?;
    let reserved_status_requests = Rc::new(RefCell::new(Vec::new()));
    assert!(matches!(
        ProductionF6CandidateAttestationAuthorityStoreV2::create_production(
            &reserved_status_path,
            fixture.binding,
            ProductionF6CandidateAuthorityInputsV2::new(
                fixture.bond.clone(),
                fixture.status.clone(),
                status_reserved,
                FixtureV2::secp(),
                fixture.signers(GOOD, [false; 3], &reserved_status_requests),
            ),
        ),
        Err(ProductionF6ErrorV2::InvalidBinding)
    ));
    assert!(!reserved_status_path.exists());
    Ok(())
}

#[test]
fn foreign_neutral_rows_are_not_accepted_as_attestation_state() -> Result<(), Box<dyn Error>> {
    let fixture = FixtureV2::new(2)?;
    let directory = tempfile::tempdir()?;
    let path = path(&directory)?;
    let requests = Rc::new(RefCell::new(Vec::new()));
    let mut authority = fixture.create(&path, fixture.signers(DOWN, [false; 3], &requests))?;
    authority
        .store
        .put_opaque(b"foreign-candidate-authority", b"foreign", b"foreign")?;
    drop(authority);

    let reopen_requests = Rc::new(RefCell::new(Vec::new()));
    assert!(matches!(
        fixture.open(&path, fixture.signers(GOOD, [false; 3], &reopen_requests)),
        Err(ProductionF6ErrorV2::InvalidCandidateAttestation)
    ));
    assert!(reopen_requests.borrow().is_empty());
    Ok(())
}
