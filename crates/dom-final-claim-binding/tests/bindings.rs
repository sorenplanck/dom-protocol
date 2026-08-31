//! Adversarial tests for the canonical FinalClaim role and M.8 readiness
//! bindings.

#![allow(clippy::unwrap_used)]

use dom_adaptor::{DirectionV1, ParticipantIdentityV1, ParticipantRosterV1, TrustedChainIdV1};
use dom_crypto::PublicKey;
use dom_final_claim_binding::{
    ComposedFinalClaimRolePlanInputV1, ComposedFinalClaimRolePlanV1, ComposedSettlementLegV1,
    FinalClaimBindingError, FinalClaimRevealModeV1, FinalClaimRoleBindingInputV1,
    FinalClaimRoleBindingV1, FinalClaimRoleSelectionV1, FinalClaimSecretSourceScopeInputV1,
    FinalClaimSecretSourceScopeV1, FinalClaimSecretSourceV1, OperationalM8ReadyBindingInputV2,
    OperationalM8ReadyBindingV2, RetainedFinalClaimRoleBindingAuditV1,
    RetainedOperationalM8ReadyBindingAuditV2, COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN,
    FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN, FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN,
    OPERATIONAL_M8_READY_BINDING_ENCODED_LEN,
};
use kaystra_core::{
    terms::SettlementTermsV1,
    types::{
        AssetId, ChainId, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1,
        LockMechanism, ParticipantId, RecoveryPolicyV1, SessionId, SettlementId, SolverId,
        TimelockSpec,
    },
};

const GENERATOR: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const TWO_G: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const THREE_G: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const FOUR_G: &str = "02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13";

fn public_key(encoded: &str) -> PublicKey {
    PublicKey::from_compressed_bytes(&hex::decode(encoded).unwrap()).unwrap()
}

fn point(encoded: &str) -> [u8; 33] {
    hex::decode(encoded).unwrap().try_into().unwrap()
}

#[derive(Clone)]
struct Fixture {
    trusted_chain: TrustedChainIdV1,
    roster: ParticipantRosterV1,
    upstream: SettlementTermsV1,
    downstream: SettlementTermsV1,
    route_id: [u8; 32],
    route_scope_digest: [u8; 32],
    composition_binding_digest: [u8; 32],
    sender: ParticipantId,
    receiver: ParticipantId,
    upstream_scope: FinalClaimSecretSourceScopeV1,
    downstream_scope: FinalClaimSecretSourceScopeV1,
    plan: ComposedFinalClaimRolePlanV1,
    role: FinalClaimRoleBindingV1,
    ready: OperationalM8ReadyBindingV2,
}

impl Fixture {
    fn new() -> Self {
        let genesis = dom_core::Hash256::from_bytes([0x42; 32]);
        let trusted_chain = TrustedChainIdV1::from_authenticated_genesis(0xd04d_0001, &genesis);
        let identity_a = public_key(GENERATOR);
        let identity_b = public_key(TWO_G);
        let signing_a = public_key(THREE_G);
        let signing_b = public_key(FOUR_G);
        let probe_a = ParticipantIdentityV1::new(
            &trusted_chain,
            identity_a.clone(),
            signing_a.clone(),
            DirectionV1::Initiator,
        )
        .unwrap();
        let probe_b = ParticipantIdentityV1::new(
            &trusted_chain,
            identity_b.clone(),
            signing_b.clone(),
            DirectionV1::Initiator,
        )
        .unwrap();
        let ((lower_identity, lower_signing), (upper_identity, upper_signing)) =
            if probe_a.participant_id() < probe_b.participant_id() {
                ((identity_a, signing_a), (identity_b, signing_b))
            } else {
                ((identity_b, signing_b), (identity_a, signing_a))
            };
        // Deliberately responder-first in participant-ID order.  Any code
        // deriving a role or direction from roster index will fail this KAT.
        let responder = ParticipantIdentityV1::new(
            &trusted_chain,
            lower_identity,
            lower_signing,
            DirectionV1::Responder,
        )
        .unwrap();
        let initiator = ParticipantIdentityV1::new(
            &trusted_chain,
            upper_identity,
            upper_signing,
            DirectionV1::Initiator,
        )
        .unwrap();
        let roster = ParticipantRosterV1::new(vec![responder, initiator]).unwrap();
        let sender = ParticipantId(*roster.entries()[0].participant_id());
        let receiver = ParticipantId(*roster.entries()[1].participant_id());
        let dom_chain = ChainId(*trusted_chain.as_bytes());
        let adaptor_point = point(GENERATOR);

        let terms = |settlement: u8, session: u8, counterparty_chain: u8| SettlementTermsV1 {
            settlement_id: SettlementId([settlement; 32]),
            session_id: SessionId([session; 32]),
            intent_hash: IntentHash([0x51; 32]),
            solver_id: SolverId([0x52; 32]),
            roster: [sender, receiver],
            dom_leg: LegTermsV1 {
                role: LegRole::Dom,
                chain_id: dom_chain,
                asset_id: AssetId([0x61; 32]),
                amount: 50,
                beneficiary: sender,
                refund_to: receiver,
                mechanism: LockMechanism::DomAdaptor2of2,
                deadline: TimelockSpec::BlockHeight { value: 400 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 2,
                    max_reorg_depth: 8,
                },
                adapter_profile_hash: [0x62; 32],
            },
            counterparty_leg: LegTermsV1 {
                role: LegRole::Counterparty,
                chain_id: ChainId([counterparty_chain; 32]),
                asset_id: AssetId([counterparty_chain.wrapping_add(1); 32]),
                amount: 60,
                beneficiary: receiver,
                refund_to: sender,
                mechanism: LockMechanism::ConditionLock,
                deadline: TimelockSpec::TimestampSeconds { value: 900_000 },
                finality: FinalityPolicyV1 {
                    min_confirmations: 3,
                    max_reorg_depth: 12,
                },
                adapter_profile_hash: [counterparty_chain.wrapping_add(2); 32],
            },
            adaptor_point_sec1: adaptor_point,
            fee_limit: FeeLimitV1 {
                dom_max: 7,
                counterparty_max: 11,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 144,
            },
            assurance_policy_hash: Some([0x63; 32]),
            policy_version: 2,
            metadata: b"final-claim-role-kat".to_vec(),
        };
        let upstream = terms(0x71, 0x72, 0x81);
        let downstream = terms(0x73, 0x74, 0x91);
        let route_id = [0xa1; 32];
        let route_scope_digest = [0xa2; 32];
        let composition_binding_digest = [0xa3; 32];
        let upstream_scope = scope(ScopeInput {
            terms: &upstream,
            route_id,
            composition_binding_digest,
            origin: sender,
            sender,
            reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
            secret_source: FinalClaimSecretSourceV1::LocalOrigin,
            source_claim_template_hash: [0xb1; 32],
        });
        let downstream_scope = scope(ScopeInput {
            terms: &downstream,
            route_id,
            composition_binding_digest,
            origin: sender,
            sender,
            reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
            secret_source: FinalClaimSecretSourceV1::LocalOrigin,
            source_claim_template_hash: [0xb2; 32],
        });
        let upstream_selection = FinalClaimRoleSelectionV1::new(
            sender,
            sender,
            receiver,
            FinalClaimRevealModeV1::DomRevealsFirst,
            FinalClaimSecretSourceV1::LocalOrigin,
            upstream_scope.clone(),
        )
        .unwrap();
        let downstream_selection = FinalClaimRoleSelectionV1::new(
            sender,
            sender,
            receiver,
            FinalClaimRevealModeV1::DomRevealsFirst,
            FinalClaimSecretSourceV1::LocalOrigin,
            downstream_scope.clone(),
        )
        .unwrap();
        let plan = ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
            route_id,
            route_scope_digest,
            composition_binding_digest,
            upstream_terms: &upstream,
            downstream_terms: &downstream,
            upstream_selection,
            downstream_selection,
        })
        .unwrap();
        let role = FinalClaimRoleBindingV1::bind(
            &trusted_chain,
            FinalClaimRoleBindingInputV1 {
                terms: &upstream,
                roster: &roster,
                role_plan: &plan,
                source_scope: &upstream_scope,
                route_leg: ComposedSettlementLegV1::Upstream,
                funding_template_hash: [0xc1; 32],
                claim_template_hash: [0xb1; 32],
                refund_template_hash: [0xc2; 32],
                shared_output_commitment: point(TWO_G),
                claim_kernel_index: 0,
            },
        )
        .unwrap();
        let ready = OperationalM8ReadyBindingV2::new(OperationalM8ReadyBindingInputV2 {
            role_binding: &role,
            m8_policy_digest: [0xd1; 32],
            refund_tx_hash: [0xd2; 32],
            bp_statement_hash: [0xd3; 32],
            recovery_binding_hash: [0xd4; 32],
            backup_receipt_hash: [0xd5; 32],
            refund_unlock_height: 777,
        })
        .unwrap();
        Self {
            trusted_chain,
            roster,
            upstream,
            downstream,
            route_id,
            route_scope_digest,
            composition_binding_digest,
            sender,
            receiver,
            upstream_scope,
            downstream_scope,
            plan,
            role,
            ready,
        }
    }
}

struct ScopeInput<'a> {
    terms: &'a SettlementTermsV1,
    route_id: [u8; 32],
    composition_binding_digest: [u8; 32],
    origin: ParticipantId,
    sender: ParticipantId,
    reveal_mode: FinalClaimRevealModeV1,
    secret_source: FinalClaimSecretSourceV1,
    source_claim_template_hash: [u8; 32],
}

fn scope(input: ScopeInput<'_>) -> FinalClaimSecretSourceScopeV1 {
    let source_chain = match input.secret_source {
        FinalClaimSecretSourceV1::LocalOrigin => input.terms.dom_leg.chain_id,
        FinalClaimSecretSourceV1::VerifiedCounterpartyClaim => {
            input.terms.counterparty_leg.chain_id
        }
    };
    FinalClaimSecretSourceScopeV1::new(FinalClaimSecretSourceScopeInputV1 {
        secret_source: input.secret_source,
        reveal_mode: input.reveal_mode,
        route_id: input.route_id,
        composition_binding_digest: input.composition_binding_digest,
        source_chain_id: source_chain,
        source_settlement_id: input.terms.settlement_id,
        source_session_id: input.terms.session_id,
        source_claim_template_hash: input.source_claim_template_hash,
        adaptor_point_sec1: input.terms.adaptor_point_sec1,
        adaptor_secret_origin_id: input.origin,
        dom_claim_sender_id: input.sender,
    })
    .unwrap()
}

#[test]
fn canonical_layouts_and_digest_kats_are_frozen() {
    let fixture = Fixture::new();
    let source_bytes = fixture.upstream_scope.canonical_bytes();
    assert_eq!(
        source_bytes.len(),
        FINAL_CLAIM_SECRET_SOURCE_SCOPE_ENCODED_LEN
    );
    assert_eq!(&source_bytes[..8], b"DOMFCSS1");
    assert_eq!(&source_bytes[8..10], &1_u16.to_le_bytes());
    assert_eq!(
        source_bytes[10],
        FinalClaimSecretSourceV1::LocalOrigin as u8
    );
    assert_eq!(
        source_bytes[11],
        FinalClaimRevealModeV1::DomRevealsFirst as u8
    );
    assert_eq!(&source_bytes[12..16], &[0; 4]);
    assert_eq!(
        &source_bytes[208..241],
        &fixture.upstream.adaptor_point_sec1
    );

    let plan_bytes = fixture.plan.canonical_bytes();
    assert_eq!(plan_bytes.len(), COMPOSED_FINAL_CLAIM_ROLE_PLAN_ENCODED_LEN);
    assert_eq!(&plan_bytes[..8], b"DOMFCRP1");
    assert_eq!(plan_bytes[10], 2);
    assert_eq!(plan_bytes[112], ComposedSettlementLegV1::Upstream as u8);
    assert_eq!(plan_bytes[308], ComposedSettlementLegV1::Downstream as u8);

    let terms_len = fixture.upstream.canonical_bytes().unwrap().len();
    let role_bytes = fixture.role.canonical_bytes().unwrap();
    assert_eq!(
        role_bytes.len(),
        FINAL_CLAIM_ROLE_BINDING_BASE_ENCODED_LEN + terms_len
    );
    assert_eq!(&role_bytes[..8], b"DOMFCRB1");
    assert_eq!(role_bytes[13], DirectionV1::Responder.to_byte());
    assert_eq!(role_bytes[14], DirectionV1::Initiator.to_byte());
    assert_eq!(&role_bytes[600..602], &(504_u16).to_le_bytes());
    assert_eq!(&role_bytes[602..604], &(305_u16).to_le_bytes());
    assert_eq!(&role_bytes[604..608], &(terms_len as u32).to_le_bytes());

    let ready_bytes = fixture.ready.canonical_bytes();
    assert_eq!(ready_bytes.len(), OPERATIONAL_M8_READY_BINDING_ENCODED_LEN);
    assert_eq!(&ready_bytes[..8], b"DOMM8RB2");
    assert_eq!(&ready_bytes[8..10], &2_u16.to_le_bytes());
    assert_eq!(&ready_bytes[10..14], b"M8R2");
    assert_eq!(&ready_bytes[594..602], &777_u64.to_le_bytes());

    // Cross-platform KATs.  These values freeze little-endian framing, the
    // embedded big-endian terms codec, responder-first roster ordering, and
    // the DOM tagged-hash construction.
    assert_eq!(
        hex::encode(fixture.upstream_scope.digest()),
        "2f5f860b71c2bd10cd4938496fa1378eedfbd94ef375adefbcb2b7ec77d6b460"
    );
    assert_eq!(
        hex::encode(fixture.plan.digest()),
        "83ed70d93bbc4fcd6718440ee97042085469a2167f0fa3572786b0c88da363c1"
    );
    assert_eq!(
        hex::encode(fixture.role.digest().unwrap()),
        "de5a397aa530078ee8b71416c135eb3b49aaa86bddc795fdda37ea3d69fb1d59"
    );
    assert_eq!(
        hex::encode(fixture.ready.digest()),
        "2c1f5841c308362bbc90e8cad184a3ca9608982d83b1acb6a4cd39e263c76832"
    );
}

#[test]
fn responder_first_roster_drives_directions_by_id_not_index_role() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture.roster.entries()[0].direction(),
        DirectionV1::Responder
    );
    assert_eq!(fixture.role.dom_claim_sender_id(), fixture.sender);
    assert_eq!(fixture.role.sender_direction(), DirectionV1::Responder);
    assert_eq!(fixture.role.receiver_direction(), DirectionV1::Initiator);
    assert_eq!(fixture.role.origin_direction(), DirectionV1::Responder);
    let decoded = FinalClaimRoleBindingV1::decode_canonical(
        &fixture.trusted_chain,
        &fixture.role.canonical_bytes().unwrap(),
    )
    .unwrap();
    assert_eq!(decoded.digest().unwrap(), fixture.role.digest().unwrap());
}

#[test]
fn retained_audit_matches_trusted_facts_and_requires_trusted_promotion() {
    let fixture = Fixture::new();
    let bytes = fixture.role.canonical_bytes().unwrap();
    let trusted =
        FinalClaimRoleBindingV1::decode_canonical(&fixture.trusted_chain, &bytes).unwrap();
    let retained = RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
        fixture.trusted_chain.as_bytes(),
        &bytes,
    )
    .unwrap();
    assert_eq!(retained.canonical_bytes(), bytes.as_slice());
    assert_eq!(retained.digest(), trusted.digest().unwrap());
    assert_eq!(retained.dom_chain_id(), trusted.dom_chain_id());
    assert_eq!(retained.settlement_id(), trusted.settlement_id());
    assert_eq!(retained.session_id(), trusted.session_id());
    assert_eq!(
        retained.terms_hash().unwrap(),
        trusted.terms_hash().unwrap()
    );
    assert_eq!(retained.route_id(), trusted.route_id());
    assert_eq!(retained.route_leg(), trusted.route_leg());
    assert_eq!(retained.roster_digest(), trusted.roster_digest());
    assert_eq!(retained.roster_entries().len(), 2);
    assert!(
        retained.roster_entries()[0].participant_id()
            < retained.roster_entries()[1].participant_id()
    );
    for (audit_entry, trusted_entry) in retained
        .roster_entries()
        .iter()
        .zip(fixture.roster.entries())
    {
        assert_eq!(
            audit_entry.participant_id(),
            *trusted_entry.participant_id()
        );
        assert_eq!(
            audit_entry.identity_public_key_sec1(),
            trusted_entry.identity_public_key().to_compressed_bytes()
        );
        assert_eq!(
            audit_entry.signing_public_key_sec1(),
            trusted_entry.signing_public_key().to_compressed_bytes()
        );
        assert_eq!(audit_entry.direction(), trusted_entry.direction());
    }

    let promoted = FinalClaimRoleBindingV1::decode_canonical(
        &fixture.trusted_chain,
        retained.canonical_bytes(),
    )
    .unwrap();
    assert_eq!(promoted, trusted);

    let other_genesis = dom_core::Hash256::from_bytes([0x43; 32]);
    let other_trusted_chain =
        TrustedChainIdV1::from_authenticated_genesis(0xd04d_0001, &other_genesis);
    assert_eq!(
        FinalClaimRoleBindingV1::decode_canonical(
            &other_trusted_chain,
            retained.canonical_bytes(),
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidRoster
    );

    let mut wrong_chain = *fixture.trusted_chain.as_bytes();
    wrong_chain[0] ^= 1;
    assert_eq!(
        RetainedFinalClaimRoleBindingAuditV1::decode_canonical(&wrong_chain, &bytes).unwrap_err(),
        FinalClaimBindingError::InvalidRoster
    );
    assert_eq!(
        RetainedFinalClaimRoleBindingAuditV1::decode_canonical(&[0; 32], &bytes).unwrap_err(),
        FinalClaimBindingError::InvalidRoster
    );

    let mut participant_id_tamper = bytes.clone();
    participant_id_tamper[608] ^= 1;
    assert_eq!(
        RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
            fixture.trusted_chain.as_bytes(),
            &participant_id_tamper,
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidRoster
    );

    let mut identity_key_tamper = bytes.clone();
    identity_key_tamper.copy_within(739..772, 640);
    assert_eq!(
        RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
            fixture.trusted_chain.as_bytes(),
            &identity_key_tamper,
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidRoster
    );

    let mut signing_key_tamper = bytes.clone();
    signing_key_tamper[673..706].copy_from_slice(&point(GENERATOR));
    assert_eq!(
        RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
            fixture.trusted_chain.as_bytes(),
            &signing_key_tamper,
        )
        .unwrap_err(),
        FinalClaimBindingError::CanonicalMismatch
    );

    let mut duplicate_signing_key = bytes.clone();
    duplicate_signing_key.copy_within(772..805, 673);
    assert_eq!(
        RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
            fixture.trusted_chain.as_bytes(),
            &duplicate_signing_key,
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidRoster
    );

    let mut reversed_roster = bytes.clone();
    let first = reversed_roster[608..707].to_vec();
    let second = reversed_roster[707..806].to_vec();
    reversed_roster[608..707].copy_from_slice(&second);
    reversed_roster[707..806].copy_from_slice(&first);
    assert_eq!(
        RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
            fixture.trusted_chain.as_bytes(),
            &reversed_roster,
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidRoster
    );

    let mut route_tamper = bytes.clone();
    route_tamper[12] = ComposedSettlementLegV1::Downstream.to_byte();
    assert!(RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
        fixture.trusted_chain.as_bytes(),
        &route_tamper,
    )
    .is_err());

    let mut kernel_index_tamper = bytes.clone();
    kernel_index_tamper[594] = 1;
    assert_eq!(
        RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
            fixture.trusted_chain.as_bytes(),
            &kernel_index_tamper,
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidLength
    );

    let mut direction_tamper = bytes;
    direction_tamper[706] = DirectionV1::Initiator.to_byte();
    assert_eq!(
        RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
            fixture.trusted_chain.as_bytes(),
            &direction_tamper,
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidRoster
    );
}

#[test]
fn retained_ready_audit_reuses_exact_canonical_core_without_minting_authority() {
    let fixture = Fixture::new();
    let retained_role = RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
        fixture.trusted_chain.as_bytes(),
        &fixture.role.canonical_bytes().unwrap(),
    )
    .unwrap();
    let ready_bytes = fixture.ready.canonical_bytes();
    let operational =
        OperationalM8ReadyBindingV2::decode_canonical(&fixture.role, &ready_bytes).unwrap();
    let retained =
        RetainedOperationalM8ReadyBindingAuditV2::decode_canonical(&retained_role, &ready_bytes)
            .unwrap();

    assert_eq!(retained.canonical_bytes(), &ready_bytes);
    assert_eq!(retained.digest(), operational.digest());
    assert_eq!(retained.route_id(), operational.route_id());
    assert_eq!(
        retained.composition_binding_digest(),
        operational.composition_binding_digest()
    );
    assert_eq!(retained.dom_chain_id(), operational.dom_chain_id());
    assert_eq!(retained.settlement_id(), operational.settlement_id());
    assert_eq!(retained.session_id(), operational.session_id());
    assert_eq!(retained.terms_hash(), operational.terms_hash());
    assert_eq!(
        retained.final_claim_role_binding_digest(),
        operational.final_claim_role_binding_digest()
    );
    assert_eq!(retained.roster_digest(), operational.roster_digest());
    assert_eq!(
        retained.funding_template_hash(),
        operational.funding_template_hash()
    );
    assert_eq!(
        retained.claim_template_hash(),
        operational.claim_template_hash()
    );
    assert_eq!(
        retained.refund_template_hash(),
        operational.refund_template_hash()
    );
    assert_eq!(
        retained.shared_output_commitment(),
        operational.shared_output_commitment()
    );
    assert_eq!(
        retained.adaptor_point_sec1(),
        operational.adaptor_point_sec1()
    );
    assert_eq!(retained.m8_policy_digest(), operational.m8_policy_digest());
    assert_eq!(retained.refund_tx_hash(), operational.refund_tx_hash());
    assert_eq!(
        retained.bp_statement_hash(),
        operational.bp_statement_hash()
    );
    assert_eq!(
        retained.recovery_binding_hash(),
        operational.recovery_binding_hash()
    );
    assert_eq!(
        retained.backup_receipt_hash(),
        operational.backup_receipt_hash()
    );
    assert_eq!(
        retained.refund_unlock_height(),
        operational.refund_unlock_height()
    );
    assert_eq!(
        retained.claim_kernel_index(),
        operational.claim_kernel_index()
    );

    let downstream_role = FinalClaimRoleBindingV1::bind(
        &fixture.trusted_chain,
        FinalClaimRoleBindingInputV1 {
            terms: &fixture.downstream,
            roster: &fixture.roster,
            role_plan: &fixture.plan,
            source_scope: &fixture.downstream_scope,
            route_leg: ComposedSettlementLegV1::Downstream,
            funding_template_hash: [0xc1; 32],
            claim_template_hash: [0xb2; 32],
            refund_template_hash: [0xc2; 32],
            shared_output_commitment: point(TWO_G),
            claim_kernel_index: 0,
        },
    )
    .unwrap();
    let downstream_retained = RetainedFinalClaimRoleBindingAuditV1::decode_canonical(
        fixture.trusted_chain.as_bytes(),
        &downstream_role.canonical_bytes().unwrap(),
    )
    .unwrap();
    assert_eq!(
        RetainedOperationalM8ReadyBindingAuditV2::decode_canonical(
            &downstream_retained,
            &ready_bytes,
        )
        .unwrap_err(),
        FinalClaimBindingError::CanonicalMismatch
    );

    let mut wrong_magic = ready_bytes;
    wrong_magic[0] ^= 1;
    assert_eq!(
        RetainedOperationalM8ReadyBindingAuditV2::decode_canonical(&retained_role, &wrong_magic)
            .unwrap_err(),
        FinalClaimBindingError::InvalidMagic
    );
    let mut wrong_version = ready_bytes;
    wrong_version[8..10].copy_from_slice(&1_u16.to_le_bytes());
    assert_eq!(
        RetainedOperationalM8ReadyBindingAuditV2::decode_canonical(&retained_role, &wrong_version)
            .unwrap_err(),
        FinalClaimBindingError::InvalidVersion
    );
    let mut nonzero_reserved = ready_bytes;
    nonzero_reserved[14] = 1;
    assert_eq!(
        RetainedOperationalM8ReadyBindingAuditV2::decode_canonical(
            &retained_role,
            &nonzero_reserved,
        )
        .unwrap_err(),
        FinalClaimBindingError::NonZeroReserved
    );
    let mut wrong_role_digest = ready_bytes;
    wrong_role_digest[240] ^= 1;
    assert_eq!(
        RetainedOperationalM8ReadyBindingAuditV2::decode_canonical(
            &retained_role,
            &wrong_role_digest,
        )
        .unwrap_err(),
        FinalClaimBindingError::CanonicalMismatch
    );
    let mut zero_policy = ready_bytes;
    zero_policy[208..240].fill(0);
    assert_eq!(
        RetainedOperationalM8ReadyBindingAuditV2::decode_canonical(&retained_role, &zero_policy)
            .unwrap_err(),
        FinalClaimBindingError::ZeroField("m8_policy_digest")
    );
    let mut different_public_policy = ready_bytes;
    different_public_policy[208] ^= 1;
    let changed = RetainedOperationalM8ReadyBindingAuditV2::decode_canonical(
        &retained_role,
        &different_public_policy,
    )
    .unwrap();
    assert_ne!(changed.digest(), retained.digest());
    assert_ne!(changed.m8_policy_digest(), retained.m8_policy_digest());

    let mut trailing = ready_bytes.to_vec();
    trailing.push(0);
    assert_eq!(
        RetainedOperationalM8ReadyBindingAuditV2::decode_canonical(&retained_role, &trailing)
            .unwrap_err(),
        FinalClaimBindingError::InvalidLength
    );
}

#[test]
fn reactive_mode_is_explicit_and_requires_receiver_as_origin() {
    let fixture = Fixture::new();
    let upstream_scope = scope(ScopeInput {
        terms: &fixture.upstream,
        route_id: fixture.route_id,
        composition_binding_digest: fixture.composition_binding_digest,
        origin: fixture.receiver,
        sender: fixture.sender,
        reveal_mode: FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
        secret_source: FinalClaimSecretSourceV1::VerifiedCounterpartyClaim,
        source_claim_template_hash: [0xe1; 32],
    });
    let downstream_scope = scope(ScopeInput {
        terms: &fixture.downstream,
        route_id: fixture.route_id,
        composition_binding_digest: fixture.composition_binding_digest,
        origin: fixture.receiver,
        sender: fixture.sender,
        reveal_mode: FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
        secret_source: FinalClaimSecretSourceV1::VerifiedCounterpartyClaim,
        source_claim_template_hash: [0xe2; 32],
    });
    let selection = |scope| {
        FinalClaimRoleSelectionV1::new(
            fixture.receiver,
            fixture.sender,
            fixture.receiver,
            FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
            FinalClaimSecretSourceV1::VerifiedCounterpartyClaim,
            scope,
        )
        .unwrap()
    };
    let plan = ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
        route_id: fixture.route_id,
        route_scope_digest: fixture.route_scope_digest,
        composition_binding_digest: fixture.composition_binding_digest,
        upstream_terms: &fixture.upstream,
        downstream_terms: &fixture.downstream,
        upstream_selection: selection(upstream_scope),
        downstream_selection: selection(downstream_scope),
    })
    .unwrap();
    assert_eq!(
        plan.entry(ComposedSettlementLegV1::Upstream)
            .adaptor_secret_origin_id(),
        fixture.receiver
    );

    assert_eq!(
        FinalClaimSecretSourceScopeV1::new(FinalClaimSecretSourceScopeInputV1 {
            secret_source: FinalClaimSecretSourceV1::VerifiedCounterpartyClaim,
            reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
            route_id: fixture.route_id,
            composition_binding_digest: fixture.composition_binding_digest,
            source_chain_id: fixture.upstream.counterparty_leg.chain_id,
            source_settlement_id: fixture.upstream.settlement_id,
            source_session_id: fixture.upstream.session_id,
            source_claim_template_hash: [0xe3; 32],
            adaptor_point_sec1: fixture.upstream.adaptor_point_sec1,
            adaptor_secret_origin_id: fixture.sender,
            dom_claim_sender_id: fixture.sender,
        })
        .unwrap_err(),
        FinalClaimBindingError::InvalidModeSource
    );
    let reactive_scope = scope(ScopeInput {
        terms: &fixture.upstream,
        route_id: fixture.route_id,
        composition_binding_digest: fixture.composition_binding_digest,
        origin: fixture.receiver,
        sender: fixture.sender,
        reveal_mode: FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
        secret_source: FinalClaimSecretSourceV1::VerifiedCounterpartyClaim,
        source_claim_template_hash: [0xe4; 32],
    });
    assert_eq!(
        FinalClaimRoleSelectionV1::new(
            fixture.receiver,
            fixture.sender,
            ParticipantId([0xfe; 32]),
            FinalClaimRevealModeV1::DomReactsToCounterpartyReveal,
            FinalClaimSecretSourceV1::VerifiedCounterpartyClaim,
            reactive_scope,
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidRoleRelation
    );
}

#[test]
fn plan_refuses_topology_scope_and_origin_mismatches() {
    let fixture = Fixture::new();
    let upstream_selection = FinalClaimRoleSelectionV1::new(
        fixture.sender,
        fixture.sender,
        fixture.receiver,
        FinalClaimRevealModeV1::DomRevealsFirst,
        FinalClaimSecretSourceV1::LocalOrigin,
        fixture.upstream_scope.clone(),
    )
    .unwrap();
    let downstream_selection = FinalClaimRoleSelectionV1::new(
        fixture.sender,
        fixture.sender,
        fixture.receiver,
        FinalClaimRevealModeV1::DomRevealsFirst,
        FinalClaimSecretSourceV1::LocalOrigin,
        fixture.downstream_scope.clone(),
    )
    .unwrap();
    let mut invalid_topology = fixture.downstream.clone();
    invalid_topology.counterparty_leg.beneficiary = fixture.sender;
    assert_eq!(
        ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
            route_id: fixture.route_id,
            route_scope_digest: fixture.route_scope_digest,
            composition_binding_digest: fixture.composition_binding_digest,
            upstream_terms: &fixture.upstream,
            downstream_terms: &invalid_topology,
            upstream_selection: upstream_selection.clone(),
            downstream_selection: downstream_selection.clone(),
        })
        .unwrap_err(),
        FinalClaimBindingError::InvalidTopology
    );

    let wrong_route_scope = scope(ScopeInput {
        terms: &fixture.upstream,
        route_id: [0xff; 32],
        composition_binding_digest: fixture.composition_binding_digest,
        origin: fixture.sender,
        sender: fixture.sender,
        reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
        secret_source: FinalClaimSecretSourceV1::LocalOrigin,
        source_claim_template_hash: [0xb1; 32],
    });
    let wrong_selection = FinalClaimRoleSelectionV1::new(
        fixture.sender,
        fixture.sender,
        fixture.receiver,
        FinalClaimRevealModeV1::DomRevealsFirst,
        FinalClaimSecretSourceV1::LocalOrigin,
        wrong_route_scope,
    )
    .unwrap();
    assert_eq!(
        ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
            route_id: fixture.route_id,
            route_scope_digest: fixture.route_scope_digest,
            composition_binding_digest: fixture.composition_binding_digest,
            upstream_terms: &fixture.upstream,
            downstream_terms: &fixture.downstream,
            upstream_selection: wrong_selection,
            downstream_selection,
        })
        .unwrap_err(),
        FinalClaimBindingError::SourceScopeMismatch
    );
}

#[test]
fn strict_decoders_reject_unknown_reserved_and_trailing_bytes() {
    let fixture = Fixture::new();
    let source = fixture.upstream_scope.canonical_bytes();
    for (offset, value, expected) in [
        (0, b'X', FinalClaimBindingError::InvalidMagic),
        (8, 2, FinalClaimBindingError::InvalidVersion),
        (10, 0xff, FinalClaimBindingError::UnknownTag),
        (11, 0xff, FinalClaimBindingError::UnknownTag),
        (12, 1, FinalClaimBindingError::NonZeroReserved),
    ] {
        let mut tampered = source;
        tampered[offset] = value;
        assert_eq!(
            FinalClaimSecretSourceScopeV1::decode_canonical(&tampered).unwrap_err(),
            expected
        );
    }
    let mut trailing = source.to_vec();
    trailing.push(0);
    assert_eq!(
        FinalClaimSecretSourceScopeV1::decode_canonical(&trailing).unwrap_err(),
        FinalClaimBindingError::InvalidLength
    );

    let plan = fixture.plan.canonical_bytes();
    for (offset, value, expected) in [
        (0, b'X', FinalClaimBindingError::InvalidMagic),
        (8, 2, FinalClaimBindingError::InvalidVersion),
        (112, 0xff, FinalClaimBindingError::UnknownTag),
        (113, 0xff, FinalClaimBindingError::UnknownTag),
        (114, 0xff, FinalClaimBindingError::UnknownTag),
        (115, 1, FinalClaimBindingError::NonZeroReserved),
    ] {
        let mut tampered = plan;
        tampered[offset] = value;
        assert_eq!(
            ComposedFinalClaimRolePlanV1::decode_canonical(&tampered).unwrap_err(),
            expected
        );
    }
    let mut trailing = plan.to_vec();
    trailing.push(0);
    assert_eq!(
        ComposedFinalClaimRolePlanV1::decode_canonical(&trailing).unwrap_err(),
        FinalClaimBindingError::InvalidLength
    );

    let role = fixture.role.canonical_bytes().unwrap();
    for offset in [10, 11, 12, 13] {
        let mut unknown_tag = role.clone();
        unknown_tag[offset] = 0xff;
        assert_eq!(
            FinalClaimRoleBindingV1::decode_canonical(&fixture.trusted_chain, &unknown_tag)
                .unwrap_err(),
            FinalClaimBindingError::UnknownTag
        );
    }
    let mut wrong_direction = role.clone();
    wrong_direction[13] = DirectionV1::Initiator.to_byte();
    assert_eq!(
        FinalClaimRoleBindingV1::decode_canonical(&fixture.trusted_chain, &wrong_direction)
            .unwrap_err(),
        FinalClaimBindingError::CanonicalMismatch
    );
    let mut wrong_plan_scope = role.clone();
    wrong_plan_scope[970] ^= 1;
    assert!(
        FinalClaimRoleBindingV1::decode_canonical(&fixture.trusted_chain, &wrong_plan_scope)
            .is_err()
    );
    let mut trailing = role;
    trailing.push(0);
    assert_eq!(
        FinalClaimRoleBindingV1::decode_canonical(&fixture.trusted_chain, &trailing).unwrap_err(),
        FinalClaimBindingError::InvalidLength
    );

    let ready = fixture.ready.canonical_bytes();
    for (offset, value, expected) in [
        (0, b'X', FinalClaimBindingError::InvalidMagic),
        (8, 3, FinalClaimBindingError::InvalidVersion),
        (10, b'X', FinalClaimBindingError::InvalidMagic),
        (14, 1, FinalClaimBindingError::NonZeroReserved),
        (606, 1, FinalClaimBindingError::NonZeroReserved),
    ] {
        let mut tampered = ready;
        tampered[offset] = value;
        assert_eq!(
            OperationalM8ReadyBindingV2::decode_canonical(&fixture.role, &tampered).unwrap_err(),
            expected
        );
    }
    let mut trailing = ready.to_vec();
    trailing.push(0);
    assert_eq!(
        OperationalM8ReadyBindingV2::decode_canonical(&fixture.role, &trailing).unwrap_err(),
        FinalClaimBindingError::InvalidLength
    );
}

#[test]
fn binding_rejects_wrong_roster_templates_source_and_commitment() {
    let fixture = Fixture::new();
    let mut different_t = fixture.downstream.clone();
    different_t.adaptor_point_sec1 = point(TWO_G);
    let upstream_selection = FinalClaimRoleSelectionV1::new(
        fixture.sender,
        fixture.sender,
        fixture.receiver,
        FinalClaimRevealModeV1::DomRevealsFirst,
        FinalClaimSecretSourceV1::LocalOrigin,
        fixture.upstream_scope.clone(),
    )
    .unwrap();
    let downstream_selection = FinalClaimRoleSelectionV1::new(
        fixture.sender,
        fixture.sender,
        fixture.receiver,
        FinalClaimRevealModeV1::DomRevealsFirst,
        FinalClaimSecretSourceV1::LocalOrigin,
        fixture.downstream_scope.clone(),
    )
    .unwrap();
    assert_eq!(
        ComposedFinalClaimRolePlanV1::bind(ComposedFinalClaimRolePlanInputV1 {
            route_id: fixture.route_id,
            route_scope_digest: fixture.route_scope_digest,
            composition_binding_digest: fixture.composition_binding_digest,
            upstream_terms: &fixture.upstream,
            downstream_terms: &different_t,
            upstream_selection,
            downstream_selection,
        })
        .unwrap_err(),
        FinalClaimBindingError::RolePlanMismatch
    );
    assert_eq!(
        FinalClaimRoleBindingV1::bind(
            &fixture.trusted_chain,
            FinalClaimRoleBindingInputV1 {
                terms: &fixture.upstream,
                roster: &fixture.roster,
                role_plan: &fixture.plan,
                source_scope: &fixture.upstream_scope,
                route_leg: ComposedSettlementLegV1::Upstream,
                funding_template_hash: [0xc1; 32],
                claim_template_hash: [0xc1; 32],
                refund_template_hash: [0xc2; 32],
                shared_output_commitment: point(TWO_G),
                claim_kernel_index: 0,
            },
        )
        .unwrap_err(),
        FinalClaimBindingError::CanonicalMismatch
    );
    assert_eq!(
        FinalClaimRoleBindingV1::bind(
            &fixture.trusted_chain,
            FinalClaimRoleBindingInputV1 {
                terms: &fixture.upstream,
                roster: &fixture.roster,
                role_plan: &fixture.plan,
                source_scope: &fixture.upstream_scope,
                route_leg: ComposedSettlementLegV1::Upstream,
                funding_template_hash: [0xc1; 32],
                claim_template_hash: [0xee; 32],
                refund_template_hash: [0xc2; 32],
                shared_output_commitment: point(TWO_G),
                claim_kernel_index: 0,
            },
        )
        .unwrap_err(),
        FinalClaimBindingError::SourceScopeMismatch
    );
    assert_eq!(
        FinalClaimRoleBindingV1::bind(
            &fixture.trusted_chain,
            FinalClaimRoleBindingInputV1 {
                terms: &fixture.upstream,
                roster: &fixture.roster,
                role_plan: &fixture.plan,
                source_scope: &fixture.upstream_scope,
                route_leg: ComposedSettlementLegV1::Upstream,
                funding_template_hash: [0xc1; 32],
                claim_template_hash: [0xb1; 32],
                refund_template_hash: [0xc2; 32],
                shared_output_commitment: [0; 33],
                claim_kernel_index: 0,
            },
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidPoint("shared_output_commitment")
    );

    let entries = fixture.roster.entries();
    let first = ParticipantIdentityV1::new(
        &fixture.trusted_chain,
        entries[0].identity_public_key().clone(),
        entries[0].signing_public_key().clone(),
        DirectionV1::Responder,
    )
    .unwrap();
    let second = ParticipantIdentityV1::new(
        &fixture.trusted_chain,
        entries[1].identity_public_key().clone(),
        entries[1].signing_public_key().clone(),
        DirectionV1::Responder,
    )
    .unwrap();
    let both_responder = ParticipantRosterV1::new(vec![first, second]).unwrap();
    assert_eq!(
        FinalClaimRoleBindingV1::bind(
            &fixture.trusted_chain,
            FinalClaimRoleBindingInputV1 {
                terms: &fixture.upstream,
                roster: &both_responder,
                role_plan: &fixture.plan,
                source_scope: &fixture.upstream_scope,
                route_leg: ComposedSettlementLegV1::Upstream,
                funding_template_hash: [0xc1; 32],
                claim_template_hash: [0xb1; 32],
                refund_template_hash: [0xc2; 32],
                shared_output_commitment: point(TWO_G),
                claim_kernel_index: 0,
            },
        )
        .unwrap_err(),
        FinalClaimBindingError::InvalidRoster
    );
}

#[test]
fn decoded_plan_requires_exact_terms_and_source_authentication() {
    let fixture = Fixture::new();
    let decoded =
        ComposedFinalClaimRolePlanV1::decode_canonical(&fixture.plan.canonical_bytes()).unwrap();
    decoded
        .authenticate(
            &fixture.upstream,
            &fixture.downstream,
            fixture.upstream_scope.clone(),
            fixture.downstream_scope.clone(),
        )
        .unwrap();
    let wrong_scope = scope(ScopeInput {
        terms: &fixture.upstream,
        route_id: fixture.route_id,
        composition_binding_digest: fixture.composition_binding_digest,
        origin: fixture.sender,
        sender: fixture.sender,
        reveal_mode: FinalClaimRevealModeV1::DomRevealsFirst,
        secret_source: FinalClaimSecretSourceV1::LocalOrigin,
        source_claim_template_hash: [0xfe; 32],
    });
    assert_eq!(
        decoded
            .authenticate(
                &fixture.upstream,
                &fixture.downstream,
                wrong_scope,
                fixture.downstream_scope,
            )
            .unwrap_err(),
        FinalClaimBindingError::RolePlanMismatch
    );
}

#[test]
fn semantically_valid_tamper_changes_digest_and_context_rejects_redundancy() {
    let fixture = Fixture::new();
    let original_ready_digest = fixture.ready.digest();
    let mut changed_external_fact = fixture.ready.canonical_bytes();
    changed_external_fact[466] ^= 1;
    let decoded =
        OperationalM8ReadyBindingV2::decode_canonical(&fixture.role, &changed_external_fact)
            .unwrap();
    assert_ne!(decoded.digest(), original_ready_digest);

    let mut changed_role_fact = fixture.ready.canonical_bytes();
    changed_role_fact[16] ^= 1;
    assert_eq!(
        OperationalM8ReadyBindingV2::decode_canonical(&fixture.role, &changed_role_fact)
            .unwrap_err(),
        FinalClaimBindingError::CanonicalMismatch
    );

    let mut changed_redundant_t = fixture.role.canonical_bytes().unwrap();
    changed_redundant_t[400] = if changed_redundant_t[400] == 2 { 3 } else { 2 };
    assert_eq!(
        FinalClaimRoleBindingV1::decode_canonical(&fixture.trusted_chain, &changed_redundant_t)
            .unwrap_err(),
        FinalClaimBindingError::CanonicalMismatch
    );
}

#[test]
fn different_owner_local_facts_produce_identical_bilateral_ready_payload() {
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct OwnerLocalFacts {
        validation_height: u64,
        now_unix_seconds: u64,
        revision: u64,
        tip_hash: [u8; 32],
        projection_digest: [u8; 32],
        authority_record_digest: [u8; 32],
    }

    fn build_for_store(
        role: &FinalClaimRoleBindingV1,
        _owner_local_facts: &OwnerLocalFacts,
    ) -> OperationalM8ReadyBindingV2 {
        // The constructor has no place for owner-local facts.  Both stores
        // pass only identical bilateral inputs into the vote binding.
        OperationalM8ReadyBindingV2::new(OperationalM8ReadyBindingInputV2 {
            role_binding: role,
            m8_policy_digest: [0xd1; 32],
            refund_tx_hash: [0xd2; 32],
            bp_statement_hash: [0xd3; 32],
            recovery_binding_hash: [0xd4; 32],
            backup_receipt_hash: [0xd5; 32],
            refund_unlock_height: 777,
        })
        .unwrap()
    }

    let fixture = Fixture::new();
    let store_a = OwnerLocalFacts {
        validation_height: 100,
        now_unix_seconds: 1_700_000_000,
        revision: 7,
        tip_hash: [0x11; 32],
        projection_digest: [0x12; 32],
        authority_record_digest: [0x13; 32],
    };
    let store_b = OwnerLocalFacts {
        validation_height: 103,
        now_unix_seconds: 1_700_000_009,
        revision: 9,
        tip_hash: [0x21; 32],
        projection_digest: [0x22; 32],
        authority_record_digest: [0x23; 32],
    };
    assert_ne!(store_a, store_b);
    let ready_a = build_for_store(&fixture.role, &store_a);
    let ready_b = build_for_store(&fixture.role, &store_b);
    assert_eq!(ready_a.canonical_bytes(), ready_b.canonical_bytes());
    assert_eq!(ready_a.digest(), ready_b.digest());
    assert_eq!(ready_a.digest(), fixture.ready.digest());
}

#[test]
fn exact_round_trips_and_zero_bilateral_facts_fail_closed() {
    let fixture = Fixture::new();
    assert_eq!(
        FinalClaimSecretSourceScopeV1::decode_canonical(&fixture.upstream_scope.canonical_bytes())
            .unwrap(),
        fixture.upstream_scope
    );
    assert_eq!(
        OperationalM8ReadyBindingV2::decode_canonical(
            &fixture.role,
            &fixture.ready.canonical_bytes()
        )
        .unwrap(),
        fixture.ready
    );
    assert_eq!(
        OperationalM8ReadyBindingV2::new(OperationalM8ReadyBindingInputV2 {
            role_binding: &fixture.role,
            m8_policy_digest: [0; 32],
            refund_tx_hash: [0xd2; 32],
            bp_statement_hash: [0xd3; 32],
            recovery_binding_hash: [0xd4; 32],
            backup_receipt_hash: [0xd5; 32],
            refund_unlock_height: 777,
        })
        .unwrap_err(),
        FinalClaimBindingError::ZeroField("m8_policy_digest")
    );
}
