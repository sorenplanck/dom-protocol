//! Stage-10 production bootstrap for the two DOM Contracts sessions.
//!
//! The V5 provisioning journal is the only pair marker.  Its binding commits
//! to the complete V5 create/recovery manifests, including the authenticated
//! Contracts commit/reveal artifact.  Consequently a crash after the first
//! leg leaves Stage 10 `Started`: replay converges the first leg by exact
//! authenticated bytes, creates the absent second leg, and only the caller may
//! then mark the stage complete.  A manifest or artifact swap changes the
//! journal binding and is refused before this module receives either Store.
//! Adding a second marker here would create an unratified split brain.

use std::path::{Component, Path};
use std::rc::Rc;
use std::sync::Arc;

use cap_std::fs::Dir;
use dom_adaptor::{
    combine_decoy_capsule_v1, initial_transcript_hash_v1, DecoyCommitmentV1, DecoyRevealV1,
    DirectionV1, ParticipantIdentityV1, ParticipantRosterV1, PendingSharedBlindingBindingV1,
    SharedBlindingBindingV1, TrustedChainIdV1,
};
use dom_core::Hash256;
use dom_crypto::PublicKey;
use dom_scriptless_chain_adapter::{
    DomHttpChainAdapterV1, ExpectedDomIdentityV1, ScriptlessScanCursorV1, ScriptlessScanPageV1,
};
use dom_scriptless_identity_store::{
    ContractsIdentityPassphraseV1, ContractsTransportIdentityStoreV1,
};
use dom_scriptless_store::{
    ContractsSessionStoreV1, PreparedEarlyTransportAuthorityV1, SessionChainProjectionV1,
    SessionIrreversibleV1, SessionPhaseV1, SessionRecordFieldsV1, SessionRecordV1,
    SessionStoreError, SessionTransportIdentityReferenceV1, SessionTransportParticipantV1,
    SessionTxObservationV1,
};
use route_executor::LegIdV1;
use zeroize::Zeroizing;

use crate::production_chain_signers::ProductionChainSignerAuthoritiesV1;
use crate::production_contracts_bootstrap::{
    AuthenticatedContractsBootstrapV1, AuthenticatedContractsLegV1,
    AuthenticatedContractsParticipantV1,
};
use crate::production_inputs::ProductionRoutePositionV1;

/// Redacted Stage-10 refusal.  No variant carries paths, public keys, session
/// bytes, or keystore references into the operator-facing error surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[expect(
    clippy::enum_variant_names,
    reason = "fail-closed refusal naming is the daemon-wide convention"
)]
pub(crate) enum ProductionContractsSessionBootstrapErrorV1 {
    #[error("live DOM genesis authentication failed")]
    DomGenesisRefused,
    #[error("authenticated Contracts bootstrap is inconsistent")]
    BootstrapRefused,
    #[error("local Contracts identity authority is unavailable")]
    IdentityRefused,
    #[error("Contracts session store refused Stage-10 convergence")]
    StoreRefused,
}

/// Inputs whose ownership is transferred into Stage 10.
pub(crate) struct ProductionContractsSessionBootstrapRequestV1<'authority> {
    pub(crate) state_capability: Arc<Dir>,
    pub(crate) state_dir: &'authority Path,
    pub(crate) identity_store_path: &'authority Path,
    pub(crate) identity_passphrase: Zeroizing<Vec<u8>>,
    pub(crate) dom_chain_adapter: DomHttpChainAdapterV1,
    pub(crate) authenticated_bootstrap: &'authority AuthenticatedContractsBootstrapV1,
    pub(crate) chain_signers: &'authority ProductionChainSignerAuthoritiesV1,
    pub(crate) upstream_store: ContractsSessionStoreV1,
    pub(crate) downstream_store: ContractsSessionStoreV1,
}

/// Move-only result for one completely reauthenticated Contracts leg.
///
/// The early authority must survive until Stage 12, where it is moved into
/// `PreparedContractsIngressV1::early`.  The Store stays in the same physical
/// opening that issued the authority; this owner exposes no reopen path.
pub(crate) struct ProductionContractsSessionLegBootstrapV1 {
    pub(crate) store: ContractsSessionStoreV1,
    pub(crate) trusted_chain_id: TrustedChainIdV1,
    pub(crate) shared_blinding_bindings: [SharedBlindingBindingV1; 2],
    pub(crate) early_transport_authority: PreparedEarlyTransportAuthorityV1,
}

/// Sole Stage-10 owner of the live DOM adapter, the one external Contracts
/// identity opening, and both raw Store openings.
///
/// This type intentionally implements neither `Clone` nor `Debug`.  Both legs
/// share the same `Rc` identity authority while retaining independent Stores
/// and linear early-transport authorities.
pub(crate) struct ProductionContractsSessionBootstrapV1 {
    pub(crate) dom_chain_adapter: DomHttpChainAdapterV1,
    pub(crate) identity: Rc<ContractsTransportIdentityStoreV1>,
    pub(crate) upstream: ProductionContractsSessionLegBootstrapV1,
    pub(crate) downstream: ProductionContractsSessionLegBootstrapV1,
}

#[derive(Clone)]
struct PreparedLegBootstrapV1 {
    initial: SessionRecordV1,
    transport_roster: [SessionTransportParticipantV1; 2],
    identity_references: [SessionTransportIdentityReferenceV1; 2],
    local_key_reference: [u8; 32],
    shared_blinding_bindings: [SharedBlindingBindingV1; 2],
}

/// Authenticate the live genesis once and converge both Stage-10 sessions.
///
/// Exactly one `scan_page(genesis, 1)` call occurs here.  The returned page is
/// checked again against the adapter's frozen identity and must contain the
/// exact height-zero block pinned by V5.  No later Stage-10 operation performs
/// another chain read or advances a DSC1 state machine.
pub(crate) fn bootstrap_production_contracts_sessions_v1(
    request: ProductionContractsSessionBootstrapRequestV1<'_>,
) -> Result<ProductionContractsSessionBootstrapV1, ProductionContractsSessionBootstrapErrorV1> {
    let ProductionContractsSessionBootstrapRequestV1 {
        state_capability,
        state_dir,
        identity_store_path,
        identity_passphrase,
        dom_chain_adapter,
        authenticated_bootstrap,
        chain_signers,
        upstream_store,
        downstream_store,
    } = request;

    let expected_identity = dom_chain_adapter.expected_identity().clone();
    require_bootstrap_dom_scope(authenticated_bootstrap, &expected_identity)?;
    let genesis_page = dom_chain_adapter
        .scan_page(ScriptlessScanCursorV1::genesis(), 1)
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::DomGenesisRefused)?;
    require_exact_genesis_page(&expected_identity, &genesis_page)?;
    let trusted_chain_id = TrustedChainIdV1::from_authenticated_genesis(
        expected_identity.network_magic,
        &Hash256::from_bytes(expected_identity.genesis_hash),
    );
    if trusted_chain_id.as_bytes() != authenticated_bootstrap.dom_chain_id() {
        return Err(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused);
    }

    let identity_parent =
        open_identity_parent_capability(state_capability.as_ref(), state_dir, identity_store_path)?;
    let identity_root = identity_store_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or(ProductionContractsSessionBootstrapErrorV1::IdentityRefused)?;
    let passphrase = ContractsIdentityPassphraseV1::new(identity_passphrase.to_vec())
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::IdentityRefused)?;
    let identity = Rc::new(
        ContractsTransportIdentityStoreV1::open_production(
            identity_parent,
            identity_root,
            &passphrase,
        )
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::IdentityRefused)?,
    );

    let local_participant = chain_signers.participant_id().0;
    let upstream_material = prepare_leg_bootstrap(
        authenticated_bootstrap,
        &authenticated_bootstrap.legs()[0],
        LegIdV1::Upstream,
        trusted_chain_id,
        expected_identity.genesis_hash,
        local_participant,
        identity.as_ref(),
        chain_signers,
    )?;
    let downstream_material = prepare_leg_bootstrap(
        authenticated_bootstrap,
        &authenticated_bootstrap.legs()[1],
        LegIdV1::Downstream,
        trusted_chain_id,
        expected_identity.genesis_hash,
        local_participant,
        identity.as_ref(),
        chain_signers,
    )?;

    // Converge both durable prefixes before minting either linear authority.
    // A crash after the first call leaves Stage 10 Started; replay compares the
    // exact revision-zero bytes and continues with the second leg.
    converge_leg_prefix(&upstream_store, &upstream_material)?;
    converge_leg_prefix(&downstream_store, &downstream_material)?;

    // Reauthenticate both complete prefixes only after both have converged.
    // These are the exact move-only authorities retained for Stage 12.
    let upstream_early =
        reauthenticate_and_prepare_early(&upstream_store, trusted_chain_id, &upstream_material)?;
    let downstream_early = reauthenticate_and_prepare_early(
        &downstream_store,
        trusted_chain_id,
        &downstream_material,
    )?;

    // Reauthenticate the external identity last as well.  A path replacement
    // or envelope mutation after session publication cannot be hidden by the
    // public references already frozen into either Store.
    require_local_identity_reference(
        identity.as_ref(),
        local_participant,
        authenticated_bootstrap.legs()[0].participants(),
    )?;
    require_local_identity_reference(
        identity.as_ref(),
        local_participant,
        authenticated_bootstrap.legs()[1].participants(),
    )?;

    Ok(ProductionContractsSessionBootstrapV1 {
        dom_chain_adapter,
        identity,
        upstream: ProductionContractsSessionLegBootstrapV1 {
            store: upstream_store,
            trusted_chain_id,
            shared_blinding_bindings: upstream_material.shared_blinding_bindings,
            early_transport_authority: upstream_early,
        },
        downstream: ProductionContractsSessionLegBootstrapV1 {
            store: downstream_store,
            trusted_chain_id,
            shared_blinding_bindings: downstream_material.shared_blinding_bindings,
            early_transport_authority: downstream_early,
        },
    })
}

fn require_bootstrap_dom_scope(
    bootstrap: &AuthenticatedContractsBootstrapV1,
    expected: &ExpectedDomIdentityV1,
) -> Result<(), ProductionContractsSessionBootstrapErrorV1> {
    if bootstrap.dom_chain_id() != &expected.chain_id
        || bootstrap.dom_genesis_hash() != &expected.genesis_hash
        || bootstrap.legs()[0].position() != ProductionRoutePositionV1::Upstream
        || bootstrap.legs()[1].position() != ProductionRoutePositionV1::Downstream
    {
        return Err(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused);
    }
    Ok(())
}

fn require_exact_genesis_page(
    expected: &ExpectedDomIdentityV1,
    page: &ScriptlessScanPageV1,
) -> Result<(), ProductionContractsSessionBootstrapErrorV1> {
    let observed = &page.identity;
    if observed.network != expected.network
        || observed.network_magic != expected.network_magic
        || observed.chain_id != expected.chain_id
        || observed.genesis_hash != expected.genesis_hash
        || observed.protocol_version != expected.protocol_version
        || observed.range_proof_serialization_version != expected.range_proof_serialization_version
        || observed.tip_hash == [0; 32]
        || page.blocks.len() != 1
        || page.next_cursor.next_height != 1
        || page.next_cursor.anchor_hash != Some(expected.genesis_hash)
    {
        return Err(ProductionContractsSessionBootstrapErrorV1::DomGenesisRefused);
    }
    let genesis = &page.blocks[0];
    if genesis.height != 0
        || genesis.block_hash != expected.genesis_hash
        || genesis.previous_block_hash != [0; 32]
        || genesis.canonical_header_bytes.is_empty()
        || observed.tip_height < genesis.height
    {
        return Err(ProductionContractsSessionBootstrapErrorV1::DomGenesisRefused);
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct authenticated authority; bundling would blur ownership"
)]
fn prepare_leg_bootstrap(
    bootstrap: &AuthenticatedContractsBootstrapV1,
    leg: &AuthenticatedContractsLegV1,
    expected_leg: LegIdV1,
    trusted_chain_id: TrustedChainIdV1,
    genesis_hash: [u8; 32],
    local_participant: [u8; 32],
    identity: &ContractsTransportIdentityStoreV1,
    chain_signers: &ProductionChainSignerAuthoritiesV1,
) -> Result<PreparedLegBootstrapV1, ProductionContractsSessionBootstrapErrorV1> {
    if leg.position() != route_position(expected_leg) {
        return Err(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused);
    }
    let mut participant_identities = Vec::with_capacity(2);
    for participant in leg.participants() {
        let identity_public_key =
            PublicKey::from_compressed_bytes(participant.schnorr_public_key())
                .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;
        let signing_public_key = PublicKey::from_compressed_bytes(participant.share_point())
            .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;
        let derived = ParticipantIdentityV1::new(
            &trusted_chain_id,
            identity_public_key,
            signing_public_key,
            participant.direction(),
        )
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;
        if derived.participant_id() != &participant.participant_id().0 {
            return Err(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused);
        }
        participant_identities.push(derived);
    }
    participant_identities.sort_by_key(|participant| *participant.participant_id());
    let roster = ParticipantRosterV1::new(participant_identities)
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;
    let roster_ids: Vec<[u8; 32]> = roster
        .entries()
        .iter()
        .map(|participant| *participant.participant_id())
        .collect();
    if roster_ids.as_slice()
        != [
            leg.participants()[0].participant_id().0,
            leg.participants()[1].participant_id().0,
        ]
    {
        return Err(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused);
    }

    let transcript_hash = initial_transcript_hash_v1(
        &trusted_chain_id,
        leg.session_id(),
        bootstrap.contract_kind(),
        &roster,
    );
    let initial = SessionRecordV1::new(
        SessionRecordFieldsV1 {
            session_id: *leg.session_id(),
            revision: 0,
            phase: SessionPhaseV1::Created,
            terms_hash: *leg.terms_hash(),
            transcript_hash,
            irreversible: SessionIrreversibleV1 {
                any_signing_share_sent: false,
                funding_authorized: false,
                adaptor_secret_exposed: false,
                nonce_epoch: 0,
            },
            chain: SessionChainProjectionV1 {
                tip_id: genesis_hash,
                tip_height: 0,
                funding: SessionTxObservationV1::Unknown,
                claim: SessionTxObservationV1::Unknown,
                refund: SessionTxObservationV1::Unknown,
            },
        },
        &[],
    )
    .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;

    require_chain_signer_binding(
        bootstrap,
        leg,
        expected_leg,
        trusted_chain_id,
        local_participant,
        chain_signers,
    )?;
    require_local_identity_reference(identity, local_participant, leg.participants())?;

    let capsule = reconstructed_capsule(leg)?;
    let mut shared = Vec::with_capacity(2);
    for (index, participant) in leg.participants().iter().enumerate() {
        let pending = PendingSharedBlindingBindingV1::new(
            &trusted_chain_id,
            *leg.session_id(),
            &roster_ids,
            participant.direction(),
            u16::try_from(index)
                .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?,
            *leg.terms_hash(),
            PublicKey::from_compressed_bytes(participant.share_point())
                .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?,
        )
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;
        shared.push(SharedBlindingBindingV1::bind_recovery_capsule(
            &pending, &capsule,
        ));
    }
    let shared_blinding_bindings: [SharedBlindingBindingV1; 2] = shared
        .try_into()
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;

    let initiator = participant_for_direction(leg, DirectionV1::Initiator)?;
    let responder = participant_for_direction(leg, DirectionV1::Responder)?;
    let transport_roster = [
        transport_participant(initiator)?,
        transport_participant(responder)?,
    ];
    let identity_references = [
        transport_identity_reference(initiator)?,
        transport_identity_reference(responder)?,
    ];
    let local_key_reference = *leg
        .participants()
        .iter()
        .find(|participant| participant.participant_id().0 == local_participant)
        .ok_or(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?
        .key_reference();

    Ok(PreparedLegBootstrapV1 {
        initial,
        transport_roster,
        identity_references,
        local_key_reference,
        shared_blinding_bindings,
    })
}

fn reconstructed_capsule(
    leg: &AuthenticatedContractsLegV1,
) -> Result<dom_crypto::recovery::RecoveryCapsule, ProductionContractsSessionBootstrapErrorV1> {
    let first = DecoyRevealV1::from_bytes(*leg.participants()[0].contribution_reveal());
    let second = DecoyRevealV1::from_bytes(*leg.participants()[1].contribution_reveal());
    let second_commit =
        DecoyCommitmentV1::from_bytes(*leg.participants()[1].contribution_commitment());
    let capsule = combine_decoy_capsule_v1(&first, &second, &second_commit)
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;
    if capsule.as_bytes() != leg.recovery_capsule() {
        return Err(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused);
    }
    Ok(capsule)
}

fn require_chain_signer_binding(
    bootstrap: &AuthenticatedContractsBootstrapV1,
    leg: &AuthenticatedContractsLegV1,
    leg_id: LegIdV1,
    trusted_chain_id: TrustedChainIdV1,
    local_participant: [u8; 32],
    chain_signers: &ProductionChainSignerAuthoritiesV1,
) -> Result<(), ProductionContractsSessionBootstrapErrorV1> {
    let local_index = leg
        .participants()
        .iter()
        .position(|participant| participant.participant_id().0 == local_participant)
        .ok_or(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;
    let binding = chain_signers.dom_binding(leg_id);
    if chain_signers.participant_id().0 != local_participant
        || binding.route_id() != *bootstrap.route_id()
        || binding.session_id() != *leg.session_id()
        || binding.participant().participant_id() != local_participant
        || usize::from(binding.participant().protocol_index()) != local_index
        || binding.chain_id() != *trusted_chain_id.as_bytes()
        || binding.genesis_hash() != *bootstrap.dom_genesis_hash()
        || binding.terms_digest() != *leg.terms_hash()
        || binding.deployment_digest() != *bootstrap.registry_digest()
        || binding.registry_epoch() != bootstrap.registry_epoch()
    {
        return Err(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused);
    }
    Ok(())
}

fn require_local_identity_reference(
    identity: &ContractsTransportIdentityStoreV1,
    local_participant: [u8; 32],
    participants: &[AuthenticatedContractsParticipantV1; 2],
) -> Result<(), ProductionContractsSessionBootstrapErrorV1> {
    let participant = participants
        .iter()
        .find(|participant| participant.participant_id().0 == local_participant)
        .ok_or(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;
    let reference = identity.reference();
    if reference.key_reference() != participant.key_reference()
        || reference.noise_public_key() != participant.noise_public_key()
        || reference.schnorr_public_key() != participant.schnorr_public_key()
    {
        return Err(ProductionContractsSessionBootstrapErrorV1::IdentityRefused);
    }
    Ok(())
}

fn converge_leg_prefix(
    store: &ContractsSessionStoreV1,
    material: &PreparedLegBootstrapV1,
) -> Result<(), ProductionContractsSessionBootstrapErrorV1> {
    match store.load_session(material.initial.session_id()) {
        Ok(retained) if retained.as_bytes() == material.initial.as_bytes() => {}
        Ok(_) => return Err(ProductionContractsSessionBootstrapErrorV1::StoreRefused),
        Err(SessionStoreError::SessionNotFound) => {
            let durable = store
                .create_session(&material.initial)
                .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)?;
            if durable.as_bytes() != material.initial.as_bytes() {
                return Err(ProductionContractsSessionBootstrapErrorV1::StoreRefused);
            }
        }
        Err(_) => return Err(ProductionContractsSessionBootstrapErrorV1::StoreRefused),
    }
    store
        .bind_transport_roster(
            material.initial.session_id(),
            material.shared_blinding_bindings[0].chain_id().to_owned(),
            material.transport_roster.clone(),
        )
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)?;
    store
        .bind_transport_identity_references(
            material.initial.session_id(),
            material.identity_references.clone(),
        )
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)?;
    store
        .bind_local_transport_signer(material.initial.session_id(), material.local_key_reference)
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)
}

fn reauthenticate_and_prepare_early(
    store: &ContractsSessionStoreV1,
    trusted_chain_id: TrustedChainIdV1,
    material: &PreparedLegBootstrapV1,
) -> Result<PreparedEarlyTransportAuthorityV1, ProductionContractsSessionBootstrapErrorV1> {
    let retained = store
        .load_session(material.initial.session_id())
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)?;
    if retained.as_bytes() != material.initial.as_bytes()
        || store
            .transport_identity_references(material.initial.session_id())
            .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)?
            != material.identity_references
    {
        return Err(ProductionContractsSessionBootstrapErrorV1::StoreRefused);
    }
    // Rebinding exact immutable records forces their full authenticated reload
    // and is idempotent; alternate bytes are a conflict, never an overwrite.
    store
        .bind_transport_roster(
            material.initial.session_id(),
            *trusted_chain_id.as_bytes(),
            material.transport_roster.clone(),
        )
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)?;
    store
        .bind_transport_identity_references(
            material.initial.session_id(),
            material.identity_references.clone(),
        )
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)?;
    store
        .bind_local_transport_signer(material.initial.session_id(), material.local_key_reference)
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)?;
    store
        .prepare_early_transport_authority(
            trusted_chain_id,
            [
                &material.shared_blinding_bindings[0],
                &material.shared_blinding_bindings[1],
            ],
        )
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::StoreRefused)
}

fn transport_participant(
    participant: &AuthenticatedContractsParticipantV1,
) -> Result<SessionTransportParticipantV1, ProductionContractsSessionBootstrapErrorV1> {
    SessionTransportParticipantV1::new(
        participant.participant_id().0,
        PublicKey::from_compressed_bytes(participant.schnorr_public_key())
            .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?,
        participant.direction(),
    )
    .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)
}

fn transport_identity_reference(
    participant: &AuthenticatedContractsParticipantV1,
) -> Result<SessionTransportIdentityReferenceV1, ProductionContractsSessionBootstrapErrorV1> {
    SessionTransportIdentityReferenceV1::new(
        participant.participant_id().0,
        *participant.key_reference(),
        *participant.noise_public_key(),
        PublicKey::from_compressed_bytes(participant.schnorr_public_key())
            .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?,
    )
    .map_err(|_| ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)
}

fn participant_for_direction(
    leg: &AuthenticatedContractsLegV1,
    direction: DirectionV1,
) -> Result<&AuthenticatedContractsParticipantV1, ProductionContractsSessionBootstrapErrorV1> {
    let mut matches = leg
        .participants()
        .iter()
        .filter(|participant| participant.direction() == direction);
    let participant = matches
        .next()
        .ok_or(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused)?;
    if matches.next().is_some() {
        return Err(ProductionContractsSessionBootstrapErrorV1::BootstrapRefused);
    }
    Ok(participant)
}

const fn route_position(leg: LegIdV1) -> ProductionRoutePositionV1 {
    match leg {
        LegIdV1::Upstream => ProductionRoutePositionV1::Upstream,
        LegIdV1::Downstream => ProductionRoutePositionV1::Downstream,
    }
}

fn open_identity_parent_capability(
    state_capability: &Dir,
    state_dir: &Path,
    identity_store_path: &Path,
) -> Result<Arc<Dir>, ProductionContractsSessionBootstrapErrorV1> {
    let relative = identity_store_path
        .strip_prefix(state_dir)
        .map_err(|_| ProductionContractsSessionBootstrapErrorV1::IdentityRefused)?;
    if relative.as_os_str().is_empty()
        || !relative
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(ProductionContractsSessionBootstrapErrorV1::IdentityRefused);
    }
    let parent = relative
        .parent()
        .ok_or(ProductionContractsSessionBootstrapErrorV1::IdentityRefused)?;
    let capability = if parent.as_os_str().is_empty() {
        state_capability
            .try_clone()
            .map_err(|_| ProductionContractsSessionBootstrapErrorV1::IdentityRefused)?
    } else {
        state_capability
            .open_dir(parent)
            .map_err(|_| ProductionContractsSessionBootstrapErrorV1::IdentityRefused)?
    };
    Ok(Arc::new(capability))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::production_provisioning::{
        DurableProductionProvisioningJournalV1, ProductionProvisioningErrorV1,
        ProductionProvisioningStageStateV1, ProductionProvisioningStageV1,
    };
    use dom_adaptor::{ContractKindV1, DecoyContributionV1, SessionId, SigningShareV1};
    use dom_scriptless_chain_adapter::{CanonicalBlockEvidenceV1, ObservedDomIdentityV1};
    use dom_scriptless_store::{BudgetPolicyProfileV1, BudgetPolicyV1, BUDGET_POLICY_LEN};
    use static_assertions::assert_not_impl_any;
    use std::fs::File;
    use std::os::unix::fs::PermissionsExt as _;

    fn expected_identity() -> ExpectedDomIdentityV1 {
        let network_magic = dom_core::NETWORK_MAGIC_REGTEST;
        let genesis_hash = *dom_core::startup_genesis_hash_for_network_magic(network_magic)
            .expect("regtest genesis")
            .as_bytes();
        let chain_id =
            *dom_consensus::derive_chain_id(network_magic, &Hash256::from_bytes(genesis_hash))
                .as_bytes();
        ExpectedDomIdentityV1 {
            network: "regtest".to_owned(),
            network_magic,
            chain_id,
            genesis_hash,
            protocol_version: dom_core::PROTOCOL_VERSION,
            range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        }
    }

    fn page(expected: &ExpectedDomIdentityV1) -> ScriptlessScanPageV1 {
        ScriptlessScanPageV1 {
            identity: ObservedDomIdentityV1 {
                network: expected.network.clone(),
                network_magic: expected.network_magic,
                chain_id: expected.chain_id,
                genesis_hash: expected.genesis_hash,
                protocol_version: expected.protocol_version,
                range_proof_serialization_version: expected.range_proof_serialization_version,
                coinbase_maturity: 60,
                tip_height: 0,
                tip_hash: expected.genesis_hash,
            },
            blocks: vec![CanonicalBlockEvidenceV1 {
                height: 0,
                block_hash: expected.genesis_hash,
                previous_block_hash: [0; 32],
                canonical_header_bytes: vec![1],
                timestamp: 1,
                transactions: Vec::new(),
            }],
            next_cursor: ScriptlessScanCursorV1 {
                next_height: 1,
                anchor_hash: Some(expected.genesis_hash),
            },
            reached_snapshot_tip: true,
        }
    }

    fn production_policy(marker: u8) -> Result<BudgetPolicyV1, Box<dyn std::error::Error>> {
        let mut bytes = [0; BUDGET_POLICY_LEN];
        bytes[..8].copy_from_slice(b"DOMNVBP1");
        bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
        bytes[10] = BudgetPolicyProfileV1::ProductionRatified as u8;
        bytes[11] = 1;
        bytes[16..48].fill(marker);
        bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
        bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
        bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
        let digest = dom_scriptless_crypto::authoritative_storage_hash_v1(
            dom_scriptless_crypto::StorageHashDomainV1::BudgetPolicy,
            &bytes[..112],
        );
        bytes[112..].copy_from_slice(&digest);
        Ok(BudgetPolicyV1::from_bytes(&bytes)?)
    }

    fn signer(marker: u8) -> Result<SigningShareV1, Box<dyn std::error::Error>> {
        let mut bytes = [0; 32];
        bytes[31] = marker;
        Ok(SigningShareV1::from_be_bytes(bytes)?)
    }

    fn prepared_leg(
        trusted_chain_id: TrustedChainIdV1,
        session_marker: u8,
    ) -> Result<PreparedLegBootstrapV1, Box<dyn std::error::Error>> {
        let session_id = [session_marker; 32];
        let terms_hash = [session_marker.wrapping_add(0x40); 32];
        let identity_shares = [signer(11)?, signer(12)?];
        let signing_shares = [signer(21)?, signer(22)?];
        let mut roster_entries = vec![
            ParticipantIdentityV1::new(
                &trusted_chain_id,
                identity_shares[0].public_key().clone(),
                signing_shares[0].public_key().clone(),
                DirectionV1::Initiator,
            )?,
            ParticipantIdentityV1::new(
                &trusted_chain_id,
                identity_shares[1].public_key().clone(),
                signing_shares[1].public_key().clone(),
                DirectionV1::Responder,
            )?,
        ];
        roster_entries.sort_by_key(|participant| *participant.participant_id());
        let roster = ParticipantRosterV1::new(roster_entries)?;
        let roster_ids: Vec<[u8; 32]> = roster
            .entries()
            .iter()
            .map(|participant| *participant.participant_id())
            .collect();

        let decoy_session = SessionId::from_bytes(session_id)?;
        let first_contribution = DecoyContributionV1::derive(&signing_shares[0], &decoy_session);
        let second_contribution = DecoyContributionV1::derive(&signing_shares[1], &decoy_session);
        let second_commitment = second_contribution.commitment();
        let first_reveal = first_contribution.into_reveal();
        let second_reveal = second_contribution.into_reveal();
        let capsule = combine_decoy_capsule_v1(&first_reveal, &second_reveal, &second_commitment)?;

        let mut shared = Vec::with_capacity(2);
        let mut transport = Vec::with_capacity(2);
        let mut references = Vec::with_capacity(2);
        for (index, participant) in roster.entries().iter().enumerate() {
            let pending = PendingSharedBlindingBindingV1::new(
                &trusted_chain_id,
                session_id,
                &roster_ids,
                participant.direction(),
                u16::try_from(index)?,
                terms_hash,
                participant.signing_public_key().clone(),
            )?;
            shared.push(SharedBlindingBindingV1::bind_recovery_capsule(
                &pending, &capsule,
            ));
            transport.push(SessionTransportParticipantV1::new(
                *participant.participant_id(),
                participant.identity_public_key().clone(),
                participant.direction(),
            )?);
            let direction_marker: u8 = match participant.direction() {
                DirectionV1::Initiator => 0x31,
                DirectionV1::Responder => 0x32,
            };
            references.push(SessionTransportIdentityReferenceV1::new(
                *participant.participant_id(),
                [direction_marker; 32],
                [direction_marker.wrapping_add(0x20); 32],
                participant.identity_public_key().clone(),
            )?);
        }
        let mut order = [0_usize, 1_usize];
        order.sort_by_key(|index| {
            u8::from(roster.entries()[*index].direction() != DirectionV1::Initiator)
        });
        let transport_roster = [transport[order[0]].clone(), transport[order[1]].clone()];
        let identity_references = [references[order[0]].clone(), references[order[1]].clone()];
        let local_key_reference = *identity_references[0].key_reference();
        let shared_blinding_bindings = shared
            .try_into()
            .map_err(|_| std::io::Error::other("shared binding count must remain two"))?;
        let expected = expected_identity();
        let initial = SessionRecordV1::new(
            SessionRecordFieldsV1 {
                session_id,
                revision: 0,
                phase: SessionPhaseV1::Created,
                terms_hash,
                transcript_hash: initial_transcript_hash_v1(
                    &trusted_chain_id,
                    &session_id,
                    ContractKindV1::WitnessOrTimeout,
                    &roster,
                ),
                irreversible: SessionIrreversibleV1 {
                    any_signing_share_sent: false,
                    funding_authorized: false,
                    adaptor_secret_exposed: false,
                    nonce_epoch: 0,
                },
                chain: SessionChainProjectionV1 {
                    tip_id: expected.genesis_hash,
                    tip_height: 0,
                    funding: SessionTxObservationV1::Unknown,
                    claim: SessionTxObservationV1::Unknown,
                    refund: SessionTxObservationV1::Unknown,
                },
            },
            &[],
        )?;
        Ok(PreparedLegBootstrapV1 {
            initial,
            transport_roster,
            identity_references,
            local_key_reference,
            shared_blinding_bindings,
        })
    }

    fn state_capability(path: &Path) -> Result<Arc<Dir>, Box<dyn std::error::Error>> {
        Ok(Arc::new(Dir::from_std_file(File::open(path)?)))
    }

    fn begin_contracts_stage(
        journal: &mut DurableProductionProvisioningJournalV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for stage in [
            ProductionProvisioningStageV1::TimeAnchorStore,
            ProductionProvisioningStageV1::RouteStore,
            ProductionProvisioningStageV1::RouteSecretVault,
            ProductionProvisioningStageV1::CoordinatorStore,
            ProductionProvisioningStageV1::DomActuatorStore,
            ProductionProvisioningStageV1::EvmActuatorStore,
            ProductionProvisioningStageV1::BitcoinActuatorStore,
            ProductionProvisioningStageV1::ChainSignerAuthorities,
            ProductionProvisioningStageV1::SolverInventoryStore,
        ] {
            journal.begin(stage)?;
            journal.complete(stage)?;
        }
        assert_eq!(
            journal.begin(ProductionProvisioningStageV1::ContractsStores)?,
            ProductionProvisioningStageStateV1::Started
        );
        Ok(())
    }

    #[test]
    fn exact_genesis_gate_rejects_identity_height_hash_and_shape_substitution() {
        let expected = expected_identity();
        assert_eq!(
            require_exact_genesis_page(&expected, &page(&expected)),
            Ok(())
        );

        let mut wrong = page(&expected);
        wrong.identity.chain_id[0] ^= 1;
        assert_eq!(
            require_exact_genesis_page(&expected, &wrong),
            Err(ProductionContractsSessionBootstrapErrorV1::DomGenesisRefused)
        );
        let mut wrong = page(&expected);
        wrong.blocks[0].height = 1;
        assert_eq!(
            require_exact_genesis_page(&expected, &wrong),
            Err(ProductionContractsSessionBootstrapErrorV1::DomGenesisRefused)
        );
        let mut wrong = page(&expected);
        wrong.blocks[0].block_hash[0] ^= 1;
        assert_eq!(
            require_exact_genesis_page(&expected, &wrong),
            Err(ProductionContractsSessionBootstrapErrorV1::DomGenesisRefused)
        );
        let mut wrong = page(&expected);
        wrong.blocks.push(wrong.blocks[0].clone());
        assert_eq!(
            require_exact_genesis_page(&expected, &wrong),
            Err(ProductionContractsSessionBootstrapErrorV1::DomGenesisRefused)
        );
    }

    #[test]
    fn nested_identity_parent_is_opened_as_capability_and_root_is_not_folded_into_it(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempfile::tempdir()?;
        std::fs::create_dir(temporary.path().join("inputs"))?;
        let state = Dir::open_ambient_dir(temporary.path(), cap_std::ambient_authority())?;
        let parent = open_identity_parent_capability(
            &state,
            temporary.path(),
            &temporary.path().join("inputs/contracts-identity"),
        )?;
        assert!(parent.metadata(".")?.is_dir());
        assert!(matches!(
            open_identity_parent_capability(
                &state,
                temporary.path(),
                &temporary.path().join("../escape/contracts-identity"),
            ),
            Err(ProductionContractsSessionBootstrapErrorV1::IdentityRefused)
        ));
        Ok(())
    }

    #[test]
    fn stage10_owners_and_linear_authorities_are_not_cloneable_or_debuggable() {
        assert_not_impl_any!(ProductionContractsSessionBootstrapV1: Clone, Copy, core::fmt::Debug);
        assert_not_impl_any!(ProductionContractsSessionLegBootstrapV1: Clone, Copy, core::fmt::Debug);
    }

    #[test]
    fn crash_after_first_session_replays_exact_bytes_and_converges_second_session(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const UPSTREAM_ROOT: &str = "upstream-contracts";
        const DOWNSTREAM_ROOT: &str = "downstream-contracts";
        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let binding = [0x71; 32];
        let policy = production_policy(0x41)?;
        let expected = expected_identity();
        let trusted_chain_id = TrustedChainIdV1::from_authenticated_genesis(
            expected.network_magic,
            &Hash256::from_bytes(expected.genesis_hash),
        );
        let upstream_material = prepared_leg(trusted_chain_id, 0x51)?;
        let downstream_material = prepared_leg(trusted_chain_id, 0x52)?;
        let mut journal =
            DurableProductionProvisioningJournalV1::create(temporary.path(), binding)?;
        begin_contracts_stage(&mut journal)?;
        let upstream = ContractsSessionStoreV1::resume_create_production(
            state_capability(temporary.path())?,
            UPSTREAM_ROOT,
            policy.clone(),
            binding,
        )?;
        let downstream = ContractsSessionStoreV1::resume_create_production(
            state_capability(temporary.path())?,
            DOWNSTREAM_ROOT,
            policy.clone(),
            binding,
        )?;
        converge_leg_prefix(&upstream, &upstream_material)?;
        assert!(matches!(
            downstream.load_session(downstream_material.initial.session_id()),
            Err(SessionStoreError::SessionNotFound)
        ));
        drop(upstream);
        drop(downstream);
        drop(journal);

        let mut journal = DurableProductionProvisioningJournalV1::open(temporary.path(), binding)?;
        assert_eq!(
            journal.stage_state(ProductionProvisioningStageV1::ContractsStores)?,
            ProductionProvisioningStageStateV1::Started
        );
        let upstream = ContractsSessionStoreV1::prepare_open_resumed_production(
            state_capability(temporary.path())?,
            UPSTREAM_ROOT,
            policy.clone(),
            binding,
        )?
        .finish()?;
        let downstream = ContractsSessionStoreV1::prepare_open_resumed_production(
            state_capability(temporary.path())?,
            DOWNSTREAM_ROOT,
            policy,
            binding,
        )?
        .finish()?;
        converge_leg_prefix(&upstream, &upstream_material)?;
        converge_leg_prefix(&downstream, &downstream_material)?;
        let upstream_early =
            reauthenticate_and_prepare_early(&upstream, trusted_chain_id, &upstream_material)?;
        let downstream_early =
            reauthenticate_and_prepare_early(&downstream, trusted_chain_id, &downstream_material)?;
        assert_eq!(
            upstream_early.session_id(),
            &upstream_material.initial.session_id()
        );
        assert_eq!(
            downstream_early.session_id(),
            &downstream_material.initial.session_id()
        );
        journal.complete(ProductionProvisioningStageV1::ContractsStores)?;
        assert_eq!(
            journal.stage_state(ProductionProvisioningStageV1::ContractsStores)?,
            ProductionProvisioningStageStateV1::Complete
        );
        Ok(())
    }

    #[test]
    fn v5_binding_or_artifact_family_swap_is_refused_before_second_session_convergence(
    ) -> Result<(), Box<dyn std::error::Error>> {
        const UPSTREAM_ROOT: &str = "upstream-contracts";
        const DOWNSTREAM_ROOT: &str = "downstream-contracts";
        let temporary = tempfile::tempdir()?;
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))?;
        let binding = [0x81; 32];
        let substituted_v5_binding = [0x82; 32];
        let policy = production_policy(0x42)?;
        let expected = expected_identity();
        let trusted_chain_id = TrustedChainIdV1::from_authenticated_genesis(
            expected.network_magic,
            &Hash256::from_bytes(expected.genesis_hash),
        );
        let upstream_material = prepared_leg(trusted_chain_id, 0x61)?;
        let downstream_material = prepared_leg(trusted_chain_id, 0x62)?;
        let mut journal =
            DurableProductionProvisioningJournalV1::create(temporary.path(), binding)?;
        begin_contracts_stage(&mut journal)?;
        let upstream = ContractsSessionStoreV1::resume_create_production(
            state_capability(temporary.path())?,
            UPSTREAM_ROOT,
            policy.clone(),
            binding,
        )?;
        let downstream = ContractsSessionStoreV1::resume_create_production(
            state_capability(temporary.path())?,
            DOWNSTREAM_ROOT,
            policy.clone(),
            binding,
        )?;
        converge_leg_prefix(&upstream, &upstream_material)?;
        drop(upstream);
        drop(downstream);
        drop(journal);

        assert!(matches!(
            DurableProductionProvisioningJournalV1::open(temporary.path(), substituted_v5_binding,),
            Err(ProductionProvisioningErrorV1::Inconsistent)
        ));
        assert!(ContractsSessionStoreV1::preflight_resume_create_production(
            state_capability(temporary.path())?,
            UPSTREAM_ROOT,
            &policy,
            substituted_v5_binding,
        )
        .is_err());

        let journal = DurableProductionProvisioningJournalV1::open(temporary.path(), binding)?;
        assert_eq!(
            journal.stage_state(ProductionProvisioningStageV1::ContractsStores)?,
            ProductionProvisioningStageStateV1::Started
        );
        let downstream = ContractsSessionStoreV1::resume_create_production(
            state_capability(temporary.path())?,
            DOWNSTREAM_ROOT,
            policy,
            binding,
        )?;
        assert!(matches!(
            downstream.load_session(downstream_material.initial.session_id()),
            Err(SessionStoreError::SessionNotFound)
        ));
        Ok(())
    }
}
