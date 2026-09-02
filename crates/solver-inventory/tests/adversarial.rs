use counterparty_api::AdaptorPointBytes;
use f6_engine::v2::{BindingEventV2, DurableBindingV2};
use f6_engine::{BindingEventV1, DurableBinding, MemoryLog};
use rfq::v2::{
    NativeClockKindV2, NegotiationClockV2, NegotiationInstantV2, QuoteProposalV2, QuoteV2,
    RfqRequestV2, RfqV2, RouteV2, SettlementPositionV2,
};
use rfq::{
    AssetId, ChainId, FeeLimitV1, LegDirectionV1, ParticipantId, QuoteV1, RfqModeV1, RouteLegV1,
    RouteV1, TimelockSpec,
};
use rusqlite::Connection;
use solver_inventory::{
    DurableInventoryStoreV1, InventoryAllocationRequestV1, InventoryExecutionV1, InventoryKeyV1,
    InventoryMutationContextV1, InventoryObservationKindV1, InventoryObservationV1,
    InventoryPurposeV1, InventoryStoreErrorV1, LeaseAcquireOutcomeV1, MutationStatusV1,
    ReservationStateV1, ReserveQuoteRequestV1, ReserveQuoteRequestV2,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use tempfile::TempDir;
use uspe::objects::{
    AssurancePolicyV1, EvidenceRuleV1, PolicyId, SettlementId, TerminalPolicyV1,
    POLICY_STRUCT_VERSION,
};

const INITIAL_NOW: u64 = 1_000;
const DEFAULT_VALID_UNTIL: u64 = 50_000;
const DEFAULT_LEASE_DURATION: u64 = 40_000;

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn mutation(
    expected_revision: u64,
    operation_byte: u8,
    now_unix_ms: u64,
) -> InventoryMutationContextV1 {
    InventoryMutationContextV1 {
        expected_revision,
        operation_id: digest(operation_byte),
        now_unix_ms,
    }
}

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    store: DurableInventoryStoreV1,
    lease: solver_inventory::InventoryLeaseV1,
    authority: ParticipantId,
    owner: [u8; 32],
    output_key: InventoryKeyV1,
    bond_key: InventoryKeyV1,
    registry_digest: [u8; 32],
    profile_digest: [u8; 32],
    binding_digest: [u8; 32],
    route: RouteV1,
}

impl Fixture {
    fn new() -> Self {
        Self::with_windows(DEFAULT_LEASE_DURATION, DEFAULT_VALID_UNTIL)
    }

    fn with_windows(lease_duration: u64, valid_until: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("inventory.sqlite");
        let binding_digest = digest(250);
        let mut store = DurableInventoryStoreV1::create(&path, binding_digest).unwrap();
        let authority = ParticipantId(digest(1));
        let owner = digest(2);
        let lease = store
            .acquire_lease(authority, owner, INITIAL_NOW, lease_duration)
            .unwrap()
            .lease();
        let output_key = InventoryKeyV1 {
            chain_id: ChainId(digest(10)),
            asset_id: AssetId(digest(11)),
            authority_id: authority,
        };
        let bond_key = InventoryKeyV1 {
            chain_id: ChainId(digest(12)),
            asset_id: AssetId(digest(13)),
            authority_id: authority,
        };
        let registry_digest = digest(20);
        let profile_digest = digest(21);
        let route = RouteV1 {
            legs: [
                RouteLegV1 {
                    chain_id: ChainId(digest(14)),
                    asset: AssetId(digest(15)),
                    direction: LegDirectionV1::UserGives,
                },
                RouteLegV1 {
                    chain_id: output_key.chain_id,
                    asset: output_key.asset_id,
                    direction: LegDirectionV1::UserReceives,
                },
            ],
        };
        let output_observation = observation(
            output_key,
            1_000,
            10,
            ObservationMaterialV1 {
                canonical_anchor_digest: digest(30),
                evidence_digest: digest(31),
                registry_manifest_digest: registry_digest,
                profile_bundle_digest: profile_digest,
                asset_binding_digest: digest(32),
                observed_at_unix_ms: INITIAL_NOW,
                valid_until_unix_ms: valid_until,
                acknowledged_consumption_sequence: 0,
                kind: InventoryObservationKindV1::Forward,
            },
        );
        store
            .reconcile_snapshot(lease, 0, digest(33), &output_observation, INITIAL_NOW)
            .unwrap();
        let bond_observation = observation(
            bond_key,
            500,
            20,
            ObservationMaterialV1 {
                canonical_anchor_digest: digest(34),
                evidence_digest: digest(35),
                registry_manifest_digest: registry_digest,
                profile_bundle_digest: profile_digest,
                asset_binding_digest: digest(36),
                observed_at_unix_ms: INITIAL_NOW,
                valid_until_unix_ms: valid_until,
                acknowledged_consumption_sequence: 0,
                kind: InventoryObservationKindV1::Forward,
            },
        );
        store
            .reconcile_snapshot(lease, 0, digest(37), &bond_observation, INITIAL_NOW)
            .unwrap();
        Self {
            _directory: directory,
            path,
            store,
            lease,
            authority,
            owner,
            output_key,
            bond_key,
            registry_digest,
            profile_digest,
            binding_digest,
            route,
        }
    }

    fn quote(&self, reservation_byte: u8, rfq_byte: u8, net_output: u128) -> QuoteV1 {
        QuoteV1::create(
            digest(rfq_byte),
            self.authority,
            self.route,
            net_output,
            net_output + 20,
            20,
            TimelockSpec::TimestampSeconds { value: 20_000 },
            digest(reservation_byte),
            POLICY_STRUCT_VERSION,
            TimelockSpec::TimestampSeconds { value: 10_000 },
            [0xA5; 64],
        )
        .unwrap()
    }

    fn request(
        &mut self,
        reservation_byte: u8,
        route_byte: u8,
        settlement_amount: u128,
        bond_amount: u128,
        expires_at_unix_ms: u64,
    ) -> ReserveQuoteRequestV1 {
        let output = self.store.load_snapshot(self.output_key).unwrap();
        let bond = self.store.load_snapshot(self.bond_key).unwrap();
        let mut allocations = vec![
            InventoryAllocationRequestV1 {
                snapshot: output.reference(),
                purpose: InventoryPurposeV1::SettlementOutput,
                amount: settlement_amount,
            },
            InventoryAllocationRequestV1 {
                snapshot: bond.reference(),
                purpose: InventoryPurposeV1::BondCollateral,
                amount: bond_amount,
            },
        ];
        allocations.sort_by_key(|allocation| (allocation.snapshot.key, allocation.purpose));
        let bond_policy = bond_policy(
            self.authority,
            self.bond_key,
            bond.asset_binding_digest,
            bond_amount,
            41,
        );
        ReserveQuoteRequestV1 {
            reservation_id: digest(reservation_byte),
            route_id: digest(route_byte),
            terms_context_digest: digest(40),
            registry_manifest_digest: self.registry_digest,
            profile_bundle_digest: self.profile_digest,
            bond_policy,
            expires_at_unix_ms,
            allocations,
        }
    }
}

fn bond_policy(
    authority: ParticipantId,
    key: InventoryKeyV1,
    asset_binding_digest: [u8; 32],
    required_collateral: u128,
    policy_byte: u8,
) -> solver_inventory::BondInventoryPolicyCapabilityV1 {
    let assurance_policy = assurance_policy(key, required_collateral, policy_byte);
    let policy_hash = assurance_policy.policy_hash().unwrap();
    solver_inventory::BondInventoryPolicyCapabilityV1::authenticate(
        &assurance_policy,
        policy_hash,
        authority,
        asset_binding_digest,
    )
    .unwrap()
}

fn assurance_policy(
    key: InventoryKeyV1,
    required_collateral: u128,
    policy_byte: u8,
) -> AssurancePolicyV1 {
    AssurancePolicyV1 {
        policy_id: PolicyId(digest(policy_byte)),
        version: POLICY_STRUCT_VERSION,
        protected_settlement: SettlementId(digest(42)),
        terms_hash: digest(43),
        bond_chain_id: key.chain_id,
        bond_asset: key.asset_id,
        required_collateral,
        compensation_cap: required_collateral,
        collateral_deadline: TimelockSpec::TimestampSeconds { value: 2_000 },
        claim_deadline: TimelockSpec::TimestampSeconds { value: 3_000 },
        evidence_deadline: TimelockSpec::TimestampSeconds { value: 4_000 },
        bond_release_deadline: TimelockSpec::TimestampSeconds { value: 5_000 },
        evidence_rule: EvidenceRuleV1::RevealedScalarClaim {
            adaptor_point: AdaptorPointBytes([
                0x02, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1,
            ]),
        },
        terminal_policy: TerminalPolicyV1::ConservativeRelease,
    }
}

struct ObservationMaterialV1 {
    canonical_anchor_digest: [u8; 32],
    evidence_digest: [u8; 32],
    registry_manifest_digest: [u8; 32],
    profile_bundle_digest: [u8; 32],
    asset_binding_digest: [u8; 32],
    observed_at_unix_ms: u64,
    valid_until_unix_ms: u64,
    acknowledged_consumption_sequence: u64,
    kind: InventoryObservationKindV1,
}

fn observation(
    key: InventoryKeyV1,
    spendable_amount: u128,
    canonical_height: u64,
    material: ObservationMaterialV1,
) -> InventoryObservationV1 {
    InventoryObservationV1 {
        key,
        spendable_amount,
        canonical_height,
        canonical_anchor_digest: material.canonical_anchor_digest,
        evidence_digest: material.evidence_digest,
        registry_manifest_digest: material.registry_manifest_digest,
        profile_bundle_digest: material.profile_bundle_digest,
        asset_binding_digest: material.asset_binding_digest,
        observed_at_unix_ms: material.observed_at_unix_ms,
        valid_until_unix_ms: material.valid_until_unix_ms,
        acknowledged_consumption_sequence: material.acknowledged_consumption_sequence,
        kind: material.kind,
    }
}

fn bound_f6(quote: &QuoteV1, terms_hash: [u8; 32]) -> DurableBinding<MemoryLog> {
    let mut engine = DurableBinding::open(MemoryLog::new()).unwrap();
    engine
        .apply(&BindingEventV1::Reserved {
            reservation_id: quote.bond_reservation_id,
            rfq_id: quote.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
        })
        .unwrap();
    engine
        .apply(&BindingEventV1::Selected {
            rfq_id: quote.rfq_id,
            winning_quote: quote.quote_id,
            inputs_digest: digest(90),
        })
        .unwrap();
    engine
        .apply(&BindingEventV1::Bound {
            rfq_id: quote.rfq_id,
            quote_id: quote.quote_id,
            solver: quote.solver,
            accepted_by: ParticipantId(digest(91)),
            reservation_id: quote.bond_reservation_id,
            terms_hash,
        })
        .unwrap();
    engine
}

#[test]
fn reserve_is_idempotent_bound_and_recoverable_after_reopen() {
    let mut fixture = Fixture::new();
    let quote = fixture.quote(50, 51, 300);
    let request = fixture.request(50, 52, 300, 100, 9_000);
    let applied = fixture
        .store
        .reserve_quote(fixture.lease, digest(53), &quote, &request, 1_100)
        .unwrap();
    assert_eq!(applied.status, MutationStatusV1::Applied);
    assert_eq!(applied.revision, 1);
    let duplicate = fixture
        .store
        .reserve_quote(fixture.lease, digest(53), &quote, &request, 1_100)
        .unwrap();
    assert_eq!(duplicate.status, MutationStatusV1::DuplicateSameBytes);

    let mut conflicting_request = request.clone();
    conflicting_request.route_id = digest(54);
    assert_eq!(
        fixture.store.reserve_quote(
            fixture.lease,
            digest(53),
            &quote,
            &conflicting_request,
            1_100,
        ),
        Err(InventoryStoreErrorV1::IdempotencyConflict)
    );

    let capability = fixture
        .store
        .quote_capability(fixture.lease, request.reservation_id, 1_100)
        .unwrap();
    assert_eq!(capability.reservation_id(), request.reservation_id);
    assert_eq!(capability.route_id(), request.route_id);
    assert_eq!(capability.rfq_id(), quote.rfq_id);
    assert_eq!(capability.quote_id(), quote.quote_id);
    assert_eq!(capability.solver_id(), fixture.authority);
    assert_eq!(
        capability.terms_context_digest(),
        request.terms_context_digest
    );
    assert_eq!(
        capability.registry_manifest_digest(),
        fixture.registry_digest
    );
    assert_eq!(capability.profile_bundle_digest(), fixture.profile_digest);
    assert_eq!(capability.required_bond_amount(), 100);
    assert_eq!(capability.allocations().len(), 2);
    assert!(capability.allocations().iter().all(|allocation| {
        allocation.reserved_snapshot.asset_binding_digest != [0; 32]
            && allocation.key.authority_id == fixture.authority
    }));
    assert_eq!(
        capability.bond_facts().reservation_id,
        request.reservation_id
    );
    assert_eq!(
        capability.f6_reservation_event(),
        BindingEventV1::Reserved {
            reservation_id: request.reservation_id,
            rfq_id: quote.rfq_id,
            quote_id: quote.quote_id,
            solver: fixture.authority,
        }
    );

    drop(fixture.store);
    let mut reopened =
        DurableInventoryStoreV1::open_existing(&fixture.path, fixture.binding_digest).unwrap();
    reopened.verify_integrity().unwrap();
    let reopened_lease = reopened
        .acquire_lease(fixture.authority, fixture.owner, 1_200, 2_000)
        .unwrap();
    assert_eq!(
        reopened_lease,
        LeaseAcquireOutcomeV1::AlreadyOwned(fixture.lease)
    );
    assert_eq!(
        reopened
            .quote_capability(fixture.lease, request.reservation_id, 1_200)
            .unwrap(),
        capability
    );
}

#[test]
fn registry_profile_asset_bindings_are_mandatory_and_explicit_release_is_one_shot() {
    let mut fixture = Fixture::new();
    let quote = fixture.quote(180, 181, 300);
    let request = fixture.request(180, 182, 300, 100, 9_000);

    let mut wrong_registry = request.clone();
    wrong_registry.registry_manifest_digest = digest(183);
    assert_eq!(
        fixture
            .store
            .reserve_quote(fixture.lease, digest(184), &quote, &wrong_registry, 1_100,),
        Err(InventoryStoreErrorV1::SnapshotMismatch)
    );
    let mut wrong_profile = request.clone();
    wrong_profile.profile_bundle_digest = digest(185);
    assert_eq!(
        fixture
            .store
            .reserve_quote(fixture.lease, digest(186), &quote, &wrong_profile, 1_100,),
        Err(InventoryStoreErrorV1::SnapshotMismatch)
    );
    let mut wrong_asset = request.clone();
    wrong_asset.allocations[0].snapshot.asset_binding_digest = digest(187);
    assert_eq!(
        fixture
            .store
            .reserve_quote(fixture.lease, digest(188), &quote, &wrong_asset, 1_100,),
        Err(InventoryStoreErrorV1::SnapshotMismatch)
    );

    fixture
        .store
        .reserve_quote(fixture.lease, digest(189), &quote, &request, 1_100)
        .unwrap();
    let release = fixture
        .store
        .release_reservation(
            fixture.lease,
            1,
            digest(190),
            request.reservation_id,
            digest(191),
            1_200,
        )
        .unwrap();
    assert_eq!(release.status, MutationStatusV1::Applied);
    assert_eq!(
        fixture
            .store
            .release_reservation(
                fixture.lease,
                1,
                digest(190),
                request.reservation_id,
                digest(191),
                1_200,
            )
            .unwrap()
            .status,
        MutationStatusV1::DuplicateSameBytes
    );
    assert_eq!(
        fixture
            .store
            .load_reservation(request.reservation_id)
            .unwrap()
            .state,
        ReservationStateV1::Released
    );
    assert_eq!(
        fixture
            .store
            .load_snapshot(fixture.output_key)
            .unwrap()
            .encumbered_amount,
        0
    );
}

#[test]
fn bond_policy_rejects_cross_chain_asset_unit_and_multi_asset_summing() {
    let mut fixture = Fixture::new();
    let quote = fixture.quote(210, 211, 300);
    let request = fixture.request(210, 212, 300, 100, 9_000);

    let mut wrong_unit = request.clone();
    wrong_unit.bond_policy = bond_policy(fixture.authority, fixture.bond_key, digest(213), 100, 44);
    assert_eq!(
        fixture
            .store
            .reserve_quote(fixture.lease, digest(214), &quote, &wrong_unit, 1_100,),
        Err(InventoryStoreErrorV1::F6BindingMismatch)
    );

    let wrong_chain_key = InventoryKeyV1 {
        chain_id: ChainId(digest(215)),
        asset_id: fixture.bond_key.asset_id,
        authority_id: fixture.authority,
    };
    let wrong_asset_key = InventoryKeyV1 {
        chain_id: fixture.bond_key.chain_id,
        asset_id: AssetId(digest(216)),
        authority_id: fixture.authority,
    };
    for (key, operation, evidence, binding) in [
        (wrong_chain_key, 217, 218, 219),
        (wrong_asset_key, 220, 221, 222),
    ] {
        let observed = observation(
            key,
            100,
            21,
            ObservationMaterialV1 {
                canonical_anchor_digest: digest(evidence),
                evidence_digest: digest(evidence.wrapping_add(1)),
                registry_manifest_digest: fixture.registry_digest,
                profile_bundle_digest: fixture.profile_digest,
                asset_binding_digest: digest(binding),
                observed_at_unix_ms: INITIAL_NOW,
                valid_until_unix_ms: DEFAULT_VALID_UNTIL,
                acknowledged_consumption_sequence: 0,
                kind: InventoryObservationKindV1::Forward,
            },
        );
        fixture
            .store
            .reconcile_snapshot(fixture.lease, 0, digest(operation), &observed, INITIAL_NOW)
            .unwrap();
    }
    let output = fixture.store.load_snapshot(fixture.output_key).unwrap();
    let wrong_chain = fixture.store.load_snapshot(wrong_chain_key).unwrap();
    let wrong_asset = fixture.store.load_snapshot(wrong_asset_key).unwrap();
    let mut cross_asset_sum = request.clone();
    cross_asset_sum.allocations = vec![
        InventoryAllocationRequestV1 {
            snapshot: output.reference(),
            purpose: InventoryPurposeV1::SettlementOutput,
            amount: 300,
        },
        InventoryAllocationRequestV1 {
            snapshot: wrong_chain.reference(),
            purpose: InventoryPurposeV1::BondCollateral,
            amount: 60,
        },
        InventoryAllocationRequestV1 {
            snapshot: wrong_asset.reference(),
            purpose: InventoryPurposeV1::BondCollateral,
            amount: 60,
        },
    ];
    cross_asset_sum
        .allocations
        .sort_by_key(|allocation| (allocation.snapshot.key, allocation.purpose));
    assert_eq!(
        fixture
            .store
            .reserve_quote(fixture.lease, digest(223), &quote, &cross_asset_sum, 1_100,),
        Err(InventoryStoreErrorV1::F6BindingMismatch)
    );

    let mut wrong_chain_policy = request.clone();
    wrong_chain_policy.bond_policy = bond_policy(
        fixture.authority,
        wrong_chain_key,
        wrong_chain.asset_binding_digest,
        100,
        45,
    );
    assert_eq!(
        fixture.store.reserve_quote(
            fixture.lease,
            digest(224),
            &quote,
            &wrong_chain_policy,
            1_100,
        ),
        Err(InventoryStoreErrorV1::F6BindingMismatch)
    );
}

#[test]
fn bond_policy_capability_refuses_zero_ids_and_wrong_policy_hash() {
    let authority = ParticipantId(digest(225));
    let key = InventoryKeyV1 {
        chain_id: ChainId(digest(226)),
        asset_id: AssetId(digest(227)),
        authority_id: authority,
    };
    let policy = assurance_policy(key, 100, 46);
    assert!(
        solver_inventory::BondInventoryPolicyCapabilityV1::authenticate(
            &policy,
            digest(228),
            authority,
            digest(229),
        )
        .is_err()
    );

    let mut zero_chain = policy;
    zero_chain.bond_chain_id = ChainId([0; 32]);
    let zero_chain_hash = zero_chain.policy_hash().unwrap();
    assert!(
        solver_inventory::BondInventoryPolicyCapabilityV1::authenticate(
            &zero_chain,
            zero_chain_hash,
            authority,
            digest(230),
        )
        .is_err()
    );

    let mut zero_asset = policy;
    zero_asset.bond_asset = AssetId([0; 32]);
    let zero_asset_hash = zero_asset.policy_hash().unwrap();
    assert!(
        solver_inventory::BondInventoryPolicyCapabilityV1::authenticate(
            &zero_asset,
            zero_asset_hash,
            authority,
            digest(231),
        )
        .is_err()
    );
}

#[test]
fn physical_owner_and_capacity_checks_prevent_concurrent_overbooking() {
    let mut fixture = Fixture::new();
    let quote_a = fixture.quote(60, 61, 700);
    let request_a = fixture.request(60, 62, 700, 100, 9_000);
    let quote_b = fixture.quote(63, 64, 700);
    let request_b = fixture.request(63, 65, 700, 100, 9_000);
    assert!(matches!(
        DurableInventoryStoreV1::open_existing(&fixture.path, fixture.binding_digest),
        Err(InventoryStoreErrorV1::StorageAuthorityHeld)
    ));
    fixture
        .store
        .reserve_quote(fixture.lease, digest(66), &quote_a, &request_a, 1_100)
        .unwrap();
    assert_eq!(
        fixture
            .store
            .reserve_quote(fixture.lease, digest(67), &quote_b, &request_b, 1_100),
        Err(InventoryStoreErrorV1::CapacityAlreadyReserved)
    );

    drop(fixture.store);
    let mut reopened =
        DurableInventoryStoreV1::open_existing(&fixture.path, fixture.binding_digest).unwrap();
    assert_eq!(
        reopened
            .load_snapshot(fixture.output_key)
            .unwrap()
            .encumbered_amount,
        700
    );
    assert_eq!(
        reopened
            .load_snapshot(fixture.bond_key)
            .unwrap()
            .encumbered_amount,
        100
    );
}

#[test]
fn expiry_releases_capacity_but_reservation_id_remains_spent() {
    let mut fixture = Fixture::new();
    let quote = fixture.quote(70, 71, 300);
    let request = fixture.request(70, 72, 300, 100, 1_200);
    fixture
        .store
        .reserve_quote(fixture.lease, digest(73), &quote, &request, 1_100)
        .unwrap();
    assert_eq!(
        fixture.store.expire_reservation(
            fixture.lease,
            1,
            digest(74),
            request.reservation_id,
            1_200,
        ),
        Err(InventoryStoreErrorV1::ReservationNotExpired)
    );
    // The sweep listing agrees with the transition rule: nothing before the
    // deadline, exactly this (reservation, revision) pair right after it.
    assert_eq!(
        fixture
            .store
            .expired_reservations(fixture.lease, 1_200)
            .unwrap(),
        Vec::new()
    );
    assert_eq!(
        fixture
            .store
            .expired_reservations(fixture.lease, 1_201)
            .unwrap(),
        vec![(request.reservation_id, 1)]
    );
    fixture
        .store
        .expire_reservation(fixture.lease, 1, digest(74), request.reservation_id, 1_201)
        .unwrap();
    // Released rows leave the sweep immediately.
    assert_eq!(
        fixture
            .store
            .expired_reservations(fixture.lease, 1_202)
            .unwrap(),
        Vec::new()
    );
    assert_eq!(
        fixture
            .store
            .load_reservation(request.reservation_id)
            .unwrap()
            .state,
        ReservationStateV1::Released
    );
    assert_eq!(
        fixture
            .store
            .load_snapshot(fixture.output_key)
            .unwrap()
            .encumbered_amount,
        0
    );

    let same_id_quote = fixture.quote(70, 75, 300);
    let same_id_request = fixture.request(70, 76, 300, 100, 9_000);
    assert_eq!(
        fixture.store.reserve_quote(
            fixture.lease,
            digest(77),
            &same_id_quote,
            &same_id_request,
            1_300,
        ),
        Err(InventoryStoreErrorV1::ReservationAlreadyExists)
    );
    let next_quote = fixture.quote(78, 79, 1_000);
    let next_request = fixture.request(78, 80, 1_000, 500, 9_000);
    fixture
        .store
        .reserve_quote(fixture.lease, digest(81), &next_quote, &next_request, 1_300)
        .unwrap();
}

#[test]
fn stale_snapshot_and_stale_cas_are_refused() {
    let mut fixture = Fixture::new();
    let current = fixture.store.load_snapshot(fixture.output_key).unwrap();
    let short_lived = observation(
        fixture.output_key,
        current.spendable_amount,
        current.canonical_height + 1,
        ObservationMaterialV1 {
            canonical_anchor_digest: digest(82),
            evidence_digest: digest(83),
            registry_manifest_digest: fixture.registry_digest,
            profile_bundle_digest: fixture.profile_digest,
            asset_binding_digest: current.asset_binding_digest,
            observed_at_unix_ms: 1_100,
            valid_until_unix_ms: 1_200,
            acknowledged_consumption_sequence: 0,
            kind: InventoryObservationKindV1::Forward,
        },
    );
    fixture
        .store
        .reconcile_snapshot(fixture.lease, 1, digest(84), &short_lived, 1_100)
        .unwrap();
    assert_eq!(
        fixture
            .store
            .reconcile_snapshot(fixture.lease, 1, digest(85), &short_lived, 1_100,),
        Err(InventoryStoreErrorV1::RevisionConflict)
    );
    let quote = fixture.quote(86, 87, 300);
    let request = fixture.request(86, 88, 300, 100, 9_000);
    assert_eq!(
        fixture
            .store
            .reserve_quote(fixture.lease, digest(89), &quote, &request, 1_201),
        Err(InventoryStoreErrorV1::SnapshotStale)
    );
}

#[test]
fn balance_reducing_reorg_preserves_holds_and_blocks_new_authority() {
    let mut fixture = Fixture::new();
    let quote = fixture.quote(100, 101, 300);
    let request = fixture.request(100, 102, 300, 100, 9_000);
    fixture
        .store
        .reserve_quote(fixture.lease, digest(103), &quote, &request, 1_100)
        .unwrap();
    let before = fixture.store.load_snapshot(fixture.output_key).unwrap();
    let reorg = observation(
        fixture.output_key,
        200,
        8,
        ObservationMaterialV1 {
            canonical_anchor_digest: digest(104),
            evidence_digest: digest(105),
            registry_manifest_digest: fixture.registry_digest,
            profile_bundle_digest: fixture.profile_digest,
            asset_binding_digest: before.asset_binding_digest,
            observed_at_unix_ms: 1_200,
            valid_until_unix_ms: 9_000,
            acknowledged_consumption_sequence: 0,
            kind: InventoryObservationKindV1::Reorg {
                invalidated_from_height: 9,
                reorg_evidence_digest: digest(106),
            },
        },
    );
    fixture
        .store
        .reconcile_snapshot(fixture.lease, 1, digest(107), &reorg, 1_200)
        .unwrap();
    let after = fixture.store.load_snapshot(fixture.output_key).unwrap();
    assert_eq!(after.spendable_amount, 200);
    assert_eq!(after.encumbered_amount, 300);
    assert_eq!(after.deficit_amount, 100);
    assert_eq!(
        fixture
            .store
            .quote_capability(fixture.lease, request.reservation_id, 1_200),
        Err(InventoryStoreErrorV1::UnderCollateralized)
    );

    let second_quote = fixture.quote(108, 109, 1);
    let second_request = fixture.request(108, 110, 1, 1, 9_000);
    assert_eq!(
        fixture.store.reserve_quote(
            fixture.lease,
            digest(111),
            &second_quote,
            &second_request,
            1_200,
        ),
        Err(InventoryStoreErrorV1::UnderCollateralized)
    );

    let unexplained = observation(
        fixture.output_key,
        200,
        7,
        ObservationMaterialV1 {
            canonical_anchor_digest: digest(112),
            evidence_digest: digest(113),
            registry_manifest_digest: fixture.registry_digest,
            profile_bundle_digest: fixture.profile_digest,
            asset_binding_digest: after.asset_binding_digest,
            observed_at_unix_ms: 1_300,
            valid_until_unix_ms: 9_000,
            acknowledged_consumption_sequence: 0,
            kind: InventoryObservationKindV1::Forward,
        },
    );
    assert_eq!(
        fixture
            .store
            .reconcile_snapshot(fixture.lease, 2, digest(114), &unexplained, 1_300,),
        Err(InventoryStoreErrorV1::ObservationRegression)
    );
}

#[test]
fn exact_f6_binding_is_required_and_finalized_consumption_waits_for_observer_ack() {
    let mut fixture = Fixture::new();
    let quote = fixture.quote(120, 121, 300);
    let request = fixture.request(120, 122, 300, 100, 9_000);
    fixture
        .store
        .reserve_quote(fixture.lease, digest(123), &quote, &request, 1_100)
        .unwrap();

    let different_quote = QuoteV1::create(
        quote.rfq_id,
        quote.solver,
        quote.route,
        301,
        quote.total_input,
        quote.total_fee,
        quote.execution_deadline,
        quote.bond_reservation_id,
        quote.bond_policy_version,
        quote.expiry,
        quote.solver_signature,
    )
    .unwrap();
    let wrong_f6 = bound_f6(&different_quote, digest(124));
    assert_eq!(
        fixture.store.commit_from_f6(
            fixture.lease,
            mutation(1, 125, 1_200),
            request.reservation_id,
            &wrong_f6,
            digest(126),
        ),
        Err(InventoryStoreErrorV1::F6BindingMismatch)
    );
    assert_eq!(
        fixture
            .store
            .load_reservation(request.reservation_id)
            .unwrap()
            .state,
        ReservationStateV1::Reserved
    );

    let f6 = bound_f6(&quote, digest(127));
    let committed = fixture
        .store
        .commit_from_f6(
            fixture.lease,
            mutation(1, 128, 1_200),
            request.reservation_id,
            &f6,
            digest(129),
        )
        .unwrap();
    assert_eq!(committed.revision, 2);
    assert_eq!(
        fixture
            .store
            .commit_from_f6(
                fixture.lease,
                mutation(1, 128, 1_200),
                request.reservation_id,
                &f6,
                digest(129),
            )
            .unwrap()
            .status,
        MutationStatusV1::DuplicateSameBytes
    );
    assert_eq!(
        fixture.store.commit_from_f6(
            fixture.lease,
            mutation(1, 128, 1_200),
            request.reservation_id,
            &f6,
            digest(130),
        ),
        Err(InventoryStoreErrorV1::IdempotencyConflict)
    );
    let capability = fixture
        .store
        .committed_capability(fixture.lease, request.reservation_id, 1_200)
        .unwrap();
    assert_eq!(capability.accepted_terms_digest(), digest(127));
    assert_eq!(
        capability.execution_fencing_epoch(),
        fixture.lease.fencing_epoch
    );

    let execution = InventoryExecutionV1 {
        reservation_id: request.reservation_id,
        execution_fencing_epoch: fixture.lease.fencing_epoch,
        execution_id: digest(131),
        evidence_digest: digest(132),
        finalized_height: 55,
    };
    fixture
        .store
        .consume_reservation(fixture.lease, 2, digest(133), &execution, 1_300)
        .unwrap();
    assert_eq!(
        fixture
            .store
            .consume_reservation(fixture.lease, 2, digest(133), &execution, 1_300)
            .unwrap()
            .status,
        MutationStatusV1::DuplicateSameBytes
    );
    let output_pending = fixture
        .store
        .pending_consumptions(fixture.lease, fixture.output_key, 1_300)
        .unwrap();
    assert_eq!(output_pending.len(), 1);
    assert_eq!(output_pending[0].amount, 300);
    assert_eq!(output_pending[0].consumption_sequence, 1);
    assert_eq!(
        fixture
            .store
            .load_snapshot(fixture.output_key)
            .unwrap()
            .encumbered_amount,
        300
    );

    drop(fixture.store);
    let mut reopened =
        DurableInventoryStoreV1::open_existing(&fixture.path, fixture.binding_digest).unwrap();
    assert_eq!(
        reopened
            .pending_consumptions(fixture.lease, fixture.output_key, 1_400)
            .unwrap(),
        output_pending
    );
    let output_snapshot = reopened.load_snapshot(fixture.output_key).unwrap();
    let acknowledged = observation(
        fixture.output_key,
        700,
        output_snapshot.canonical_height + 1,
        ObservationMaterialV1 {
            canonical_anchor_digest: digest(134),
            evidence_digest: digest(135),
            registry_manifest_digest: fixture.registry_digest,
            profile_bundle_digest: fixture.profile_digest,
            asset_binding_digest: output_snapshot.asset_binding_digest,
            observed_at_unix_ms: 1_400,
            valid_until_unix_ms: 9_000,
            acknowledged_consumption_sequence: 1,
            kind: InventoryObservationKindV1::Forward,
        },
    );
    reopened
        .reconcile_snapshot(fixture.lease, 1, digest(136), &acknowledged, 1_400)
        .unwrap();
    assert!(reopened
        .pending_consumptions(fixture.lease, fixture.output_key, 1_400)
        .unwrap()
        .is_empty());
    assert_eq!(
        reopened
            .load_snapshot(fixture.output_key)
            .unwrap()
            .encumbered_amount,
        0
    );
}

#[test]
fn takeover_requires_reconciliation_and_stale_process_cannot_release_or_consume() {
    let mut fixture = Fixture::with_windows(1_000, 10_000);
    let quote = fixture.quote(140, 141, 300);
    let request = fixture.request(140, 142, 300, 100, 9_000);
    fixture
        .store
        .reserve_quote(fixture.lease, digest(143), &quote, &request, 1_100)
        .unwrap();
    let f6 = bound_f6(&quote, digest(144));
    fixture
        .store
        .commit_from_f6(
            fixture.lease,
            mutation(1, 145, 1_200),
            request.reservation_id,
            &f6,
            digest(146),
        )
        .unwrap();
    let old_lease = fixture.lease;
    let new_owner = digest(147);
    let new_lease = fixture
        .store
        .acquire_lease(fixture.authority, new_owner, 2_001, 2_000)
        .unwrap()
        .lease();
    assert_eq!(new_lease.fencing_epoch, old_lease.fencing_epoch + 1);
    assert_eq!(
        fixture
            .store
            .committed_capability(new_lease, request.reservation_id, 2_001,),
        Err(InventoryStoreErrorV1::ReauthorizationRequired)
    );
    assert_eq!(
        fixture.store.release_reservation(
            new_lease,
            2,
            digest(148),
            request.reservation_id,
            digest(149),
            2_001,
        ),
        Err(InventoryStoreErrorV1::ReauthorizationRequired)
    );
    fixture
        .store
        .reauthorize_committed(
            new_lease,
            2,
            digest(150),
            request.reservation_id,
            digest(151),
            2_001,
        )
        .unwrap();
    let capability = fixture
        .store
        .committed_capability(new_lease, request.reservation_id, 2_001)
        .unwrap();
    assert_eq!(
        capability.execution_fencing_epoch(),
        new_lease.fencing_epoch
    );

    let stale_execution = InventoryExecutionV1 {
        reservation_id: request.reservation_id,
        execution_fencing_epoch: old_lease.fencing_epoch,
        execution_id: digest(152),
        evidence_digest: digest(153),
        finalized_height: 60,
    };
    assert_eq!(
        fixture
            .store
            .consume_reservation(old_lease, 3, digest(154), &stale_execution, 2_001,),
        Err(InventoryStoreErrorV1::StaleFencing)
    );
    assert_eq!(
        fixture
            .store
            .consume_reservation(new_lease, 3, digest(155), &stale_execution, 2_001,),
        Err(InventoryStoreErrorV1::StaleFencing)
    );
    let current_execution = InventoryExecutionV1 {
        execution_fencing_epoch: new_lease.fencing_epoch,
        ..stale_execution
    };
    fixture
        .store
        .consume_reservation(new_lease, 3, digest(156), &current_execution, 2_001)
        .unwrap();
}

#[test]
fn live_second_owner_is_refused_and_takeover_epoch_is_monotonic() {
    let fixture = Fixture::with_windows(1_000, 10_000);
    assert!(matches!(
        DurableInventoryStoreV1::open_existing(&fixture.path, fixture.binding_digest),
        Err(InventoryStoreErrorV1::StorageAuthorityHeld)
    ));
    let old_lease = fixture.lease;
    drop(fixture.store);
    let mut second =
        DurableInventoryStoreV1::open_existing(&fixture.path, fixture.binding_digest).unwrap();
    assert_eq!(
        second.acquire_lease(fixture.authority, digest(160), 1_500, 1_000),
        Err(InventoryStoreErrorV1::LeaseHeld)
    );
    let takeover = second
        .acquire_lease(fixture.authority, digest(160), 2_001, 1_000)
        .unwrap()
        .lease();
    assert_eq!(takeover.fencing_epoch, old_lease.fencing_epoch + 1);
    assert_eq!(
        second.renew_lease(old_lease, 2_001, 1_000),
        Err(InventoryStoreErrorV1::StaleFencing)
    );
}

#[test]
fn foreign_trigger_is_rejected_before_any_reservation_effect() {
    let mut fixture = Fixture::new();
    let quote = fixture.quote(170, 171, 300);
    let request = fixture.request(170, 172, 300, 100, 9_000);
    let injector = Connection::open(&fixture.path).unwrap();
    injector
        .execute_batch(
            "CREATE TRIGGER inventory_test_abort_second_allocation
             BEFORE INSERT ON inventory_allocations
             WHEN NEW.position = 1
             BEGIN
               SELECT RAISE(ABORT, 'simulated crash cut');
             END;",
        )
        .unwrap();
    assert_eq!(
        fixture
            .store
            .reserve_quote(fixture.lease, digest(173), &quote, &request, 1_100),
        Err(InventoryStoreErrorV1::CorruptState)
    );

    injector
        .execute_batch("DROP TRIGGER inventory_test_abort_second_allocation;")
        .unwrap();
    assert_eq!(
        fixture.store.load_reservation(request.reservation_id),
        Err(InventoryStoreErrorV1::ReservationNotFound)
    );
    assert_eq!(
        fixture
            .store
            .load_snapshot(fixture.output_key)
            .unwrap()
            .encumbered_amount,
        0
    );
    assert_eq!(
        fixture
            .store
            .load_snapshot(fixture.bond_key)
            .unwrap()
            .encumbered_amount,
        0
    );
    let outcome = fixture
        .store
        .reserve_quote(fixture.lease, digest(173), &quote, &request, 1_100)
        .unwrap();
    assert_eq!(outcome.status, MutationStatusV1::Applied);
    assert_eq!(
        fixture
            .store
            .load_snapshot(fixture.output_key)
            .unwrap()
            .encumbered_amount,
        300
    );
    fixture.store.verify_integrity().unwrap();
}

#[test]
fn tampered_snapshot_evidence_is_rejected_on_reopen() {
    let fixture = Fixture::new();
    let path = fixture.path.clone();
    let key = fixture.output_key;
    drop(fixture.store);
    let attacker = Connection::open(&path).unwrap();
    attacker
        .execute(
            "UPDATE inventory_accounts SET evidence_digest = ?4
             WHERE authority_id = ?1 AND chain_id = ?2 AND asset_id = ?3",
            rusqlite::params![
                key.authority_id.0.as_slice(),
                key.chain_id.0.as_slice(),
                key.asset_id.0.as_slice(),
                digest(200).as_slice(),
            ],
        )
        .unwrap();
    drop(attacker);
    assert!(matches!(
        DurableInventoryStoreV1::open_existing(&path, digest(250)),
        Err(InventoryStoreErrorV1::CorruptState)
    ));
}

#[test]
fn v2_inventory_scope_is_durable_move_only_and_cross_composition_closed(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new();
    let composition_id = digest(201);
    let negotiation_clock = NegotiationClockV2 {
        chain_id: ChainId(digest(202)),
        profile_digest: digest(203),
        authority_scope: digest(204),
        kind: NativeClockKindV2::BlockHeight,
    };
    let route = RouteV2 {
        composition_id,
        position: SettlementPositionV2::Upstream,
        legs: [
            RouteLegV1 {
                chain_id: ChainId(digest(14)),
                asset: AssetId(digest(15)),
                direction: LegDirectionV1::UserGives,
            },
            RouteLegV1 {
                chain_id: fixture.output_key.chain_id,
                asset: fixture.output_key.asset_id,
                direction: LegDirectionV1::UserReceives,
            },
        ],
    };
    let rfq = RfqV2::create(RfqRequestV2 {
        initiator: ParticipantId(digest(205)),
        route,
        mode: RfqModeV1::ExactIn {
            input_amount: 320,
            minimum_output: 300,
        },
        fee_limit: FeeLimitV1 {
            dom_max: 10,
            counterparty_max: 10,
        },
        negotiation_clock,
        quote_deadline: NegotiationInstantV2 {
            clock: negotiation_clock,
            value: 2_000,
        },
        assurance_policy_ref: PolicyId(digest(206)),
        policy_version: POLICY_STRUCT_VERSION,
        session_id: digest(207),
    })?;
    let quote = QuoteV2::create(QuoteProposalV2 {
        rfq_id: rfq.rfq_id,
        solver: fixture.authority,
        route,
        net_output: 300,
        total_input: 320,
        total_fee: 20,
        execution_deadline: NegotiationInstantV2 {
            clock: negotiation_clock,
            value: 1_900,
        },
        bond_reservation_id: digest(208),
        bond_policy_version: POLICY_STRUCT_VERSION,
        expiry: NegotiationInstantV2 {
            clock: negotiation_clock,
            value: 1_800,
        },
        solver_signature: [0xA6; 64],
    })?;
    let base = fixture.request(208, 209, 300, 100, 9_000);
    let request = ReserveQuoteRequestV2::authenticate(base, &rfq, &quote)?;
    fixture
        .store
        .reserve_quote_v2(fixture.lease, digest(210), &quote, &request, 1_100)?;
    assert_eq!(
        fixture
            .store
            .quote_capability(fixture.lease, quote.bond_reservation_id, 1_100),
        Err(InventoryStoreErrorV1::F6BindingMismatch)
    );
    let capability =
        fixture
            .store
            .quote_capability_v2(fixture.lease, quote.bond_reservation_id, 1_100)?;
    assert_eq!(capability.composition_id(), composition_id);
    assert_eq!(capability.position(), SettlementPositionV2::Upstream);

    let wrong_composition = digest(211);
    let mut transplanted = DurableBindingV2::open(MemoryLog::new())?;
    transplanted.apply(&BindingEventV2::Reserved {
        composition_id: wrong_composition,
        position: route.position,
        reservation_id: quote.bond_reservation_id,
        rfq_id: quote.rfq_id,
        quote_id: quote.quote_id,
        solver: quote.solver,
    })?;
    transplanted.apply(&BindingEventV2::Selected {
        composition_id: wrong_composition,
        position: route.position,
        rfq_id: quote.rfq_id,
        winning_quote: quote.quote_id,
        inputs_digest: digest(212),
    })?;
    transplanted.apply(&BindingEventV2::Bound {
        composition_id: wrong_composition,
        position: route.position,
        rfq_id: quote.rfq_id,
        quote_id: quote.quote_id,
        solver: quote.solver,
        accepted_by: rfq.initiator,
        reservation_id: quote.bond_reservation_id,
        terms_hash: digest(213),
    })?;
    assert_eq!(
        fixture.store.commit_from_f6_v2(
            fixture.lease,
            mutation(1, 214, 1_200),
            quote.bond_reservation_id,
            &transplanted,
        ),
        Err(InventoryStoreErrorV1::F6BindingMismatch)
    );

    let mut exact = DurableBindingV2::open(MemoryLog::new())?;
    exact.apply(&capability.f6_reservation_event())?;
    exact.apply(&BindingEventV2::Selected {
        composition_id,
        position: route.position,
        rfq_id: quote.rfq_id,
        winning_quote: quote.quote_id,
        inputs_digest: digest(216),
    })?;
    exact.apply(&BindingEventV2::Bound {
        composition_id,
        position: route.position,
        rfq_id: quote.rfq_id,
        quote_id: quote.quote_id,
        solver: quote.solver,
        accepted_by: rfq.initiator,
        reservation_id: quote.bond_reservation_id,
        terms_hash: digest(217),
    })?;
    fixture.store.commit_from_f6_v2(
        fixture.lease,
        mutation(1, 218, 1_200),
        quote.bond_reservation_id,
        &exact,
    )?;
    let committed =
        fixture
            .store
            .committed_capability_v2(fixture.lease, quote.bond_reservation_id, 1_200)?;
    assert_eq!(committed.accepted_terms_digest(), digest(217));
    assert_eq!(
        committed.quote_capability().composition_id(),
        composition_id
    );
    Ok(())
}

#[test]
fn v2_scope_row_tamper_is_detected_on_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new();
    let composition_id = digest(220);
    let negotiation_clock = NegotiationClockV2 {
        chain_id: ChainId(digest(221)),
        profile_digest: digest(222),
        authority_scope: digest(223),
        kind: NativeClockKindV2::BlockHeight,
    };
    let route = RouteV2 {
        composition_id,
        position: SettlementPositionV2::Upstream,
        legs: [
            RouteLegV1 {
                chain_id: ChainId(digest(14)),
                asset: AssetId(digest(15)),
                direction: LegDirectionV1::UserGives,
            },
            RouteLegV1 {
                chain_id: fixture.output_key.chain_id,
                asset: fixture.output_key.asset_id,
                direction: LegDirectionV1::UserReceives,
            },
        ],
    };
    let rfq = RfqV2::create(RfqRequestV2 {
        initiator: ParticipantId(digest(224)),
        route,
        mode: RfqModeV1::ExactIn {
            input_amount: 320,
            minimum_output: 300,
        },
        fee_limit: FeeLimitV1 {
            dom_max: 10,
            counterparty_max: 10,
        },
        negotiation_clock,
        quote_deadline: NegotiationInstantV2 {
            clock: negotiation_clock,
            value: 2_000,
        },
        assurance_policy_ref: PolicyId(digest(225)),
        policy_version: POLICY_STRUCT_VERSION,
        session_id: digest(226),
    })?;
    let quote = QuoteV2::create(QuoteProposalV2 {
        rfq_id: rfq.rfq_id,
        solver: fixture.authority,
        route,
        net_output: 300,
        total_input: 320,
        total_fee: 20,
        execution_deadline: NegotiationInstantV2 {
            clock: negotiation_clock,
            value: 1_900,
        },
        bond_reservation_id: digest(227),
        bond_policy_version: POLICY_STRUCT_VERSION,
        expiry: NegotiationInstantV2 {
            clock: negotiation_clock,
            value: 1_800,
        },
        solver_signature: [0xA7; 64],
    })?;
    let request = ReserveQuoteRequestV2::authenticate(
        fixture.request(227, 228, 300, 100, 9_000),
        &rfq,
        &quote,
    )?;
    fixture
        .store
        .reserve_quote_v2(fixture.lease, digest(229), &quote, &request, 1_100)?;
    let path = fixture.path.clone();
    let binding_digest = fixture.binding_digest;
    drop(fixture.store);
    let attacker = Connection::open(&path)?;
    attacker.execute(
        "UPDATE inventory_reservation_scopes_v2
         SET composition_id = ?2 WHERE reservation_id = ?1",
        rusqlite::params![quote.bond_reservation_id.as_slice(), digest(230).as_slice()],
    )?;
    drop(attacker);
    assert!(matches!(
        DurableInventoryStoreV1::open_existing(&path, binding_digest),
        Err(InventoryStoreErrorV1::CorruptState)
    ));
    Ok(())
}
