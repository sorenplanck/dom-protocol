//! Post-anchor Claim pre-signature (`0x0f`) V2 Relay ingress tests.
//!
//! DECLARED EDGE (evidence-only ancestry, 1/1): the productive V2 ancestry for
//! this edge terminates in `verify_f7_route_anchor_authority_v2`, which demands
//! a live DOM HTTP chain adapter, so a hermetic test cannot reach the authority
//! through the shipped path. This target therefore opens the Contracts Store in
//! the `EvidenceOnly` profile and seeds only the external F7 V2 verifier result
//! through the Store's laboratory seam. Everything the worker is asked to prove
//! stays production-exact: the Store still authenticates the real gate,
//! issuance, commit, chain projection and every role and readiness binding, and
//! the `0x0f` V2 transport entrypoints carry no profile gate, so the ingress
//! assertions below are byte-for-byte the ones the production suite makes.
//!
//! This target is compiled only with the isolated
//! `evidence-only-ancestry-tests` feature, which no shipped feature enables;
//! `tests/relay_worker.rs` pins that isolation statically, and the Store's own
//! release guard refuses the surface outside debug builds.
//!
//! # Why the scaffolding below is written here and not imported
//!
//! Every file under `tests/` is its own crate, and this workspace has no
//! `tests/common/` module, so nothing in `tests/relay_worker.rs` is reachable
//! from here. That is not the only reason: the fixtures there are built around
//! that file's own `EarlyFixture` session, while these tests must stand a
//! worker in front of **the staged session** the Store seam produces. The
//! relay-layer configuration is therefore rebuilt here from the daemon's public
//! API. No product logic and no economic staging is duplicated — the staging
//! comes from the seam, and the two doubles below (`AncestryVault`,
//! `AncestryF6Authority`) are test doubles for ports, which is exactly where a
//! double belongs.

#![cfg(all(
    feature = "production",
    feature = "evidence-only-ancestry-tests",
    target_os = "linux"
))]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use btc_crypto::SecpContext;
use cap_std::fs::Dir;
use dom_adaptor::{
    open_vault_backed_blinding_share_v1, AdaptorPreSignatureV1, BoundShareBackupAckV2,
    DurableShareBackupAckCapabilityV1, ParticipantRosterV1, PendingSharedBlindingBindingV1,
    ShareBackupAckV1, SharedBlindingBindingUpgradeCapabilityV1, SharedBlindingBindingV1,
    SharedBlindingImportCapabilityV1, SharedBlindingMaterialV1,
    SharedBlindingRetirementCapabilityV1, SharedBlindingSealCapabilityV1, SharedBlindingVaultV1,
    TrustedChainIdV1,
};
use dom_crypto::PublicKey;
use dom_interopd::{
    ContractsRelayIngressErrorV1, DurableRelayWorkerV1, PreparedContractsIngressV1,
    RelayWorkerConfigV1, RelayWorkerInboundErrorV1, RelayWorkerPathsV1,
};
use dom_scriptless_crypto::{authoritative_storage_hash_v1, StorageHashDomainV1};
use dom_scriptless_store::{
    evidence_only_stage_post_anchor_v2_graph, BudgetPolicyProfileV1, BudgetPolicyV1,
    ContractsSessionStoreV1, EvidenceOnlyStagedPostAnchorV2, PreparedEarlyTransportAuthorityV1,
    PreparedPostAnchorClaimPreSignatureTransportAuthorityV2, SessionPhaseV1, SessionStoreError,
    BUDGET_POLICY_LEN,
};
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::{
    AssetId, ChainId, Digest32, FeeLimitV1, FinalityPolicyV1, IntentHash, LegRole, LegTermsV1,
    LockMechanism, RecoveryPolicyV1, SessionId as KaystraSessionId, SettlementId, SolverId,
};
use relay::auth::{message_type, RosterMemberV1, RosterRegistryV1, RosterSnapshotV1};
use relay::production::{ProductionRelayV1, RelayDatabaseConfigV1, RelayDatabaseIdV1};
use relay::server::AckV1;
use relay::{ParticipantId, SenderRoleV1, TimelockSpec};
use route_transport::{
    BridgeRefusal, DurableFrameReassemblerConfigV2, DurableInboxConfigV1, DurablePayloadCommitV1,
    DurablePayloadDispositionV1, DurableRelaySenderConfigV1, DurableRelaySenderV1,
    F6PayloadDeliveryV1, F6TransportPortV1, FramedContractsTransportErrorV2, RelayQueueV1,
    RouteDispatchErrorV1, RouteWireContextV1, MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES,
};
use static_assertions::assert_not_impl_any;
use zeroize::Zeroizing;

const NETWORK: Digest32 = [0x21; 32];
const ROUTE: Digest32 = [0x41; 32];
const SNAPSHOT: Digest32 = [0x51; 32];
/// The Contracts session the seam stages, and the relay wire session. The two
/// must be the same value: the worker's Contracts port is constructed with
/// `config.wire_context().session_id` and refuses any other session.
const STAGED_SESSION: [u8; 32] = [0x31; 32];
/// Relay-layer transport secrets. These are **not** the Contracts identity
/// keys: `DurableRelayWorkerV1::create` takes an independent signing secret and
/// never the Contracts identity, which is why the staging seam hands over
/// participant identifiers and no key material at all.
const INITIATOR_RELAY_SECRET: [u8; 32] = [0x71; 32];
const RESPONDER_RELAY_SECRET: [u8; 32] = [0x72; 32];

type AncestryWorker = DurableRelayWorkerV1<AncestryF6Authority>;

// The sealed handles this target moves through the worker. Their missing
// `Debug` is the reason `into_early` below is matched with `let ... else`
// instead of `expect_err`, and these three lines are what stop that absence
// from being traded away for a convenience: a future hand that adds `Debug` to
// silence a test fails here first, and has to argue for it.
assert_not_impl_any!(PreparedContractsIngressV1: Clone, Copy, std::fmt::Debug, Eq, PartialEq);
assert_not_impl_any!(PreparedEarlyTransportAuthorityV1: Clone, Copy, std::fmt::Debug, Eq, PartialEq);
assert_not_impl_any!(
    PreparedPostAnchorClaimPreSignatureTransportAuthorityV2: Clone,
    Copy,
    std::fmt::Debug,
    Eq,
    PartialEq
);
assert_not_impl_any!(EvidenceOnlyStagedPostAnchorV2: Clone, Copy, std::fmt::Debug);

// ---------------------------------------------------------------------------
// The two doubles the staging seam requires as parameters.
//
// The seam takes both a settlement-terms producer and a backup-acknowledgement
// producer instead of building them itself, precisely so the shared-blinding
// double lives here — in an integration-test target that is never shipped —
// and not inside the Store's library surface.
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
#[error("ancestry test vault refused")]
struct AncestryVaultError;

/// A shared-blinding vault that seals nothing and keeps the share in the
/// clear.
///
/// It exists only to satisfy the seam's parameter. It must never be anywhere
/// but a test target, and the Store's own
/// `check_store_custody_traits_stay_out_of_the_laboratory` guard fails the
/// build if an implementation of this trait ever appears in code the
/// `evidence-only` feature can reach.
#[derive(Default)]
struct AncestryVault {
    plaintext: Option<[u8; 32]>,
    pending: Option<PendingSharedBlindingBindingV1>,
    bound: Option<SharedBlindingBindingV1>,
}

impl SharedBlindingVaultV1 for AncestryVault {
    type Error = AncestryVaultError;

    fn seal_fresh_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        material: SharedBlindingMaterialV1,
        capability: SharedBlindingSealCapabilityV1,
    ) -> Result<(), Self::Error> {
        if self.plaintext.is_some() {
            return Err(AncestryVaultError);
        }
        self.plaintext = Some(*capability.into_plaintext(material));
        self.pending = Some(binding.clone());
        Ok(())
    }

    fn open_persisted_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        if self.pending.as_ref() != Some(binding) {
            return Err(AncestryVaultError);
        }
        capability
            .import(Zeroizing::new(self.plaintext.ok_or(AncestryVaultError)?))
            .map_err(|_| AncestryVaultError)
    }

    fn confirm_pending_backup_roundtrip(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        capability
            .acknowledge_pending(binding, binding.share_point().clone())
            .map_err(|_| AncestryVaultError)
    }

    fn bind_recovery_capsule(
        &mut self,
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
        capability: SharedBlindingBindingUpgradeCapabilityV1,
    ) -> Result<(), Self::Error> {
        capability
            .authorize_upgrade(pending, bound)
            .map_err(|_| AncestryVaultError)?;
        if self.pending.as_ref() != Some(pending) || self.bound.is_some() {
            return Err(AncestryVaultError);
        }
        self.bound = Some(bound.clone());
        self.pending = None;
        Ok(())
    }

    fn open_persisted_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        if self.bound.as_ref() != Some(binding) {
            return Err(AncestryVaultError);
        }
        capability
            .import(Zeroizing::new(self.plaintext.ok_or(AncestryVaultError)?))
            .map_err(|_| AncestryVaultError)
    }

    fn confirm_backup_roundtrip(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        capability
            .acknowledge(binding, binding.share_point().clone())
            .map_err(|_| AncestryVaultError)
    }

    fn retire_pending_share(
        &mut self,
        _binding: &PendingSharedBlindingBindingV1,
        _capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        Err(AncestryVaultError)
    }

    fn retire_bound_share(
        &mut self,
        _binding: &SharedBlindingBindingV1,
        _capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        Err(AncestryVaultError)
    }
}

/// Builds the two bound backup acknowledgements the staged graph needs.
///
/// The two share plaintexts arrive as parameters. They are fixture constants of
/// the Store's staging module, not secrets, and the seam's documentation states
/// the condition under which that would stop being true.
fn ancestry_backup_acknowledgements(
    bindings: &[SharedBlindingBindingV1; 2],
    share_bytes: &[[u8; 32]; 2],
) -> Result<[BoundShareBackupAckV2; 2], Box<dyn Error>> {
    let mut vault_a = AncestryVault {
        plaintext: Some(share_bytes[0]),
        pending: None,
        bound: Some(bindings[0].clone()),
    };
    let mut vault_b = AncestryVault {
        plaintext: Some(share_bytes[1]),
        pending: None,
        bound: Some(bindings[1].clone()),
    };
    let mut capability_a = open_vault_backed_blinding_share_v1(bindings[0].clone(), &mut vault_a)?;
    let mut capability_b = open_vault_backed_blinding_share_v1(bindings[1].clone(), &mut vault_b)?;
    Ok([
        capability_a.take_bound_durable_backup_ack_v2()?,
        capability_b.take_bound_durable_backup_ack_v2()?,
    ])
}

/// Builds the upstream and downstream settlement terms the staged graph binds.
fn ancestry_settlement_terms(
    trusted_chain: &TrustedChainIdV1,
    roster: &ParticipantRosterV1,
    adaptor_point: &PublicKey,
    session_id: [u8; 32],
) -> Result<(SettlementTermsV1, SettlementTermsV1), Box<dyn Error>> {
    if roster.entries().len() != 2 {
        return Err(Box::new(SessionStoreError::Canonical));
    }
    let sender = ParticipantId(*roster.entries()[0].participant_id());
    let receiver = ParticipantId(*roster.entries()[1].participant_id());
    let dom_chain = ChainId(*trusted_chain.as_bytes());
    let terms = |settlement: u8, session: [u8; 32], counterparty_chain: u8| SettlementTermsV1 {
        settlement_id: SettlementId([settlement; 32]),
        session_id: KaystraSessionId(session),
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
            deadline: TimelockSpec::BlockHeight { value: 500 },
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
        adaptor_point_sec1: adaptor_point.to_compressed_bytes(),
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
        metadata: b"ancestry-target-fixture".to_vec(),
    };
    Ok((terms(0x71, session_id, 0x81), terms(0x73, [0x74; 32], 0x91)))
}

// ---------------------------------------------------------------------------
// Relay-layer scaffolding, rebuilt from the daemon's public API for the staged
// session.
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
#[error("ancestry F6 authority refused")]
struct AncestryF6Error;

#[derive(Default)]
struct AncestryF6Authority {
    receipts: BTreeSet<Digest32>,
}

impl F6TransportPortV1 for AncestryF6Authority {
    type Error = AncestryF6Error;

    fn accept_f6(
        &mut self,
        delivery: F6PayloadDeliveryV1<'_>,
    ) -> Result<DurablePayloadCommitV1, Self::Error> {
        let receipt = *delivery.envelope_digest();
        let duplicate = !self.receipts.insert(receipt);
        DurablePayloadCommitV1::new(DurablePayloadDispositionV1::Applied, receipt, duplicate)
            .map_err(|_| AncestryF6Error)
    }
}

struct AncestryQueue {
    relay: ProductionRelayV1,
}

impl RelayQueueV1 for AncestryQueue {
    fn queue_submit(&mut self, raw: &[u8]) -> Result<AckV1, BridgeRefusal> {
        self.relay.submit(raw).map_err(BridgeRefusal::DurableRelay)
    }

    fn queue_deliver(&self, recipient: &ParticipantId) -> Result<Vec<Vec<u8>>, BridgeRefusal> {
        self.relay
            .deliver(recipient)
            .map_err(BridgeRefusal::DurableRelay)
    }
}

#[derive(Clone, Copy)]
struct AncestryPeers {
    initiator: ParticipantId,
    responder: ParticipantId,
}

fn wire() -> RouteWireContextV1 {
    RouteWireContextV1 {
        network_id: NETWORK,
        session_id: STAGED_SESSION,
        route_id: ROUTE,
        roster_snapshot: SNAPSHOT,
        policy_version: 1,
    }
}

fn expiry() -> TimelockSpec {
    TimelockSpec::BlockHeight { value: 10_000 }
}

fn now() -> TimelockSpec {
    TimelockSpec::BlockHeight { value: 100 }
}

fn xonly(secret: &[u8; 32]) -> [u8; 32] {
    SecpContext::new(&[0x19; 32])
        .sign_bip340(secret, &[0; 32], &[0; 32])
        .expect("public test relay secret")
        .1
}

fn rosters_for(peers: AncestryPeers) -> RosterRegistryV1 {
    RosterRegistryV1::new().with_snapshot(
        SNAPSHOT,
        RosterSnapshotV1::new()
            .with_member(
                peers.initiator,
                RosterMemberV1 {
                    xonly_key: xonly(&INITIATOR_RELAY_SECRET),
                    role: SenderRoleV1::Initiator,
                },
            )
            .with_member(
                peers.responder,
                RosterMemberV1 {
                    xonly_key: xonly(&RESPONDER_RELAY_SECRET),
                    role: SenderRoleV1::Solver,
                },
            ),
    )
}

fn sender_config_for(local_initiator: bool, peers: AncestryPeers) -> DurableRelaySenderConfigV1 {
    let (local, remote, role, secret, discriminator) = if local_initiator {
        (
            peers.initiator,
            peers.responder,
            SenderRoleV1::Initiator,
            INITIATOR_RELAY_SECRET,
            0xa0,
        )
    } else {
        (
            peers.responder,
            peers.initiator,
            SenderRoleV1::Solver,
            RESPONDER_RELAY_SECRET,
            0xb0,
        )
    };
    DurableRelaySenderConfigV1::new(
        [discriminator + 1; 32],
        wire(),
        local,
        remote,
        role,
        xonly(&secret),
        128,
    )
    .expect("valid sender config")
}

fn worker_config_for(local_initiator: bool, peers: AncestryPeers) -> RelayWorkerConfigV1 {
    let discriminator = if local_initiator { 0xa0 } else { 0xb0 };
    let local = if local_initiator {
        peers.initiator
    } else {
        peers.responder
    };
    let sender = sender_config_for(local_initiator, peers);
    let inbox = DurableInboxConfigV1::new([discriminator + 2; 32], wire(), local, 128)
        .expect("valid inbox config");
    let frames = DurableFrameReassemblerConfigV2::new(
        [discriminator + 3; 32],
        wire(),
        local,
        16,
        2 * 1024 * 1024,
        128,
    )
    .expect("valid frame config");
    RelayWorkerConfigV1::new(sender, inbox, frames).expect("cross-bound worker config")
}

fn worker_paths(root: &Path, local_initiator: bool) -> RelayWorkerPathsV1 {
    let prefix = if local_initiator { "alice" } else { "bob" };
    RelayWorkerPathsV1::new(
        root.join(format!("{prefix}-sender")),
        root.join(format!("{prefix}-inbox")),
        root.join(format!("{prefix}-frames")),
    )
}

fn relay_config() -> Result<RelayDatabaseConfigV1, Box<dyn Error>> {
    Ok(RelayDatabaseConfigV1::new(
        RelayDatabaseIdV1::new([0xd1; 32])?,
        256,
    )?)
}

fn create_relay(root: &Path) -> Result<AncestryQueue, Box<dyn Error>> {
    Ok(AncestryQueue {
        relay: ProductionRelayV1::create(root, relay_config()?)?,
    })
}

fn secure_tempdir() -> Result<tempfile::TempDir, Box<dyn Error>> {
    let directory = tempfile::Builder::new()
        .prefix("dom-post-anchor-v2-ancestry-")
        .tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn parent_capability(path: &Path) -> Result<Arc<Dir>, Box<dyn Error>> {
    Ok(Arc::new(Dir::from_std_file(File::open(path)?)))
}

fn evidence_only_policy() -> Result<BudgetPolicyV1, Box<dyn Error>> {
    let mut bytes = [0; BUDGET_POLICY_LEN];
    bytes[..8].copy_from_slice(b"DOMNVBP1");
    bytes[8..10].copy_from_slice(&1_u16.to_le_bytes());
    bytes[10] = BudgetPolicyProfileV1::EvidenceOnly as u8;
    bytes[11] = 1;
    bytes[16..48].fill(0x41);
    bytes[48..56].copy_from_slice(&100_u64.to_le_bytes());
    bytes[56..64].copy_from_slice(&50_u64.to_le_bytes());
    bytes[64..68].copy_from_slice(&10_u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&25_u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&3_600_u64.to_le_bytes());
    bytes[88..96].copy_from_slice(&60_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&86_400_u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&1_u64.to_le_bytes());
    let digest = authoritative_storage_hash_v1(StorageHashDomainV1::BudgetPolicy, &bytes[..112]);
    bytes[112..].copy_from_slice(&digest);
    Ok(BudgetPolicyV1::from_bytes(&bytes)?)
}

/// Byte-exact snapshot of the durable Contracts tree.
///
/// Written here because the Store's own `snapshot_store_tree` is private to its
/// test module. Every negative below asserts this is unchanged, which is what
/// separates "the Store refused" from "the Store refused after writing
/// something".
fn snapshot_store_tree(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>, Box<dyn Error>> {
    let mut snapshot = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                let relative = path.strip_prefix(root)?.to_path_buf();
                snapshot.insert(relative, fs::read(&path)?);
            } else {
                return Err(Box::new(SessionStoreError::Filesystem));
            }
        }
    }
    Ok(snapshot)
}

/// The staged graph plus everything the relay layer needs to address it.
struct StagedAncestry {
    staged: EvidenceOnlyStagedPostAnchorV2,
    peers: AncestryPeers,
    /// Whether the canonical `0x0f` sender is the initiator. The peer that
    /// submits must be that participant, because the worker refuses with
    /// `SenderMismatch` when the outer Relay sender is not the inner DSC1
    /// signer; the worker under test is therefore the other side.
    sender_is_initiator: bool,
}

fn stage(root: &Path) -> Result<StagedAncestry, Box<dyn Error>> {
    let staged = evidence_only_stage_post_anchor_v2_graph(
        parent_capability(root)?,
        evidence_only_policy()?,
        STAGED_SESSION,
        ancestry_settlement_terms,
        ancestry_backup_acknowledgements,
    )?;
    assert_eq!(staged.session_id(), &STAGED_SESSION);
    let [initiator, responder] = *staged.participant_ids_by_direction();
    assert_ne!(initiator, responder);
    let canonical = *staged
        .prepared_pre_signature_authority()
        .canonical_sender_id();
    let sender_is_initiator = canonical == initiator;
    assert!(
        sender_is_initiator || canonical == responder,
        "the canonical 0x0f sender must be one of the two staged participants"
    );
    Ok(StagedAncestry {
        staged,
        peers: AncestryPeers {
            initiator: ParticipantId(initiator),
            responder: ParticipantId(responder),
        },
        sender_is_initiator,
    })
}

fn open_worker(
    root: &Path,
    local_initiator: bool,
    peers: AncestryPeers,
    store: ContractsSessionStoreV1,
    fresh: bool,
) -> Result<AncestryWorker, Box<dyn Error>> {
    let secret = if local_initiator {
        INITIATOR_RELAY_SECRET
    } else {
        RESPONDER_RELAY_SECRET
    };
    let paths = worker_paths(root, local_initiator);
    let config = worker_config_for(local_initiator, peers);
    let rosters = rosters_for(peers);
    let f6 = AncestryF6Authority::default();
    Ok(if fresh {
        DurableRelayWorkerV1::create(&paths, config, Rc::new(store), rosters, f6, secret)?
    } else {
        DurableRelayWorkerV1::open_existing(&paths, config, Rc::new(store), rosters, f6, secret)?
    })
}

fn open_peer_sender(
    root: &Path,
    local_initiator: bool,
    peers: AncestryPeers,
    fresh: bool,
) -> Result<DurableRelaySenderV1, Box<dyn Error>> {
    let secret = if local_initiator {
        INITIATOR_RELAY_SECRET
    } else {
        RESPONDER_RELAY_SECRET
    };
    // Bound before use: `sender_root()` borrows the paths value, so calling it
    // on a temporary would not outlive the statement.
    let paths = worker_paths(root, local_initiator);
    let sender_root = paths.sender_root();
    let config = sender_config_for(local_initiator, peers);
    Ok(if fresh {
        DurableRelaySenderV1::create(sender_root, config, secret, [0xc1; 32])?
    } else {
        DurableRelaySenderV1::open_existing(sender_root, config, secret, [0xc2; 32])?
    })
}

/// Submits one already-signed DSC1 envelope through the Relay.
fn submit_signed_dsc1(
    sender: &mut DurableRelaySenderV1,
    queue: &mut AncestryQueue,
    signed_dsc1: &[u8],
) -> Result<(), Box<dyn Error>> {
    if signed_dsc1.len() <= MAX_ROUTE_TRANSPORT_PAYLOAD_BYTES {
        sender.prepare_message(
            message_type::ROUTE_TRANSPORT,
            signed_dsc1,
            expiry(),
            [0xc4; 32],
        )?;
    } else {
        sender.begin_framed_route(signed_dsc1, expiry(), [0xc4; 32])?;
    }
    loop {
        if sender.pending_envelope()?.is_none() {
            if sender.frame_transfer_status()?.is_none() {
                return Ok(());
            }
            sender.prepare_next_frame([0xc5; 32])?;
        }
        sender.submit_pending(queue)?;
    }
}

/// Matches only the exact Contracts ingress refusal, through the full nested
/// error shape. `is_err()` would pass even with the variant removed from the
/// enum, which is why it is never used here.
macro_rules! assert_contracts_refusal {
    ($error:expr, $variant:pat) => {
        assert!(matches!(
            $error,
            RelayWorkerInboundErrorV1::Contracts(RouteDispatchErrorV1::Contracts(
                FramedContractsTransportErrorV2::Contracts($variant)
            ))
        ))
    };
}

/// Proves this target really carries the laboratory ancestry surface.
///
/// The two constructors exist only under the Store's `evidence-only` feature,
/// so naming them here fails to compile if the isolated feature ever stops
/// reaching the Store — the exact wiring the A2–A5 fixtures depend on.
#[test]
fn evidence_only_ancestry_target_links_the_store_laboratory_constructors() {
    let _create: fn(
        Arc<Dir>,
        &str,
        BudgetPolicyV1,
    ) -> Result<ContractsSessionStoreV1, SessionStoreError> =
        ContractsSessionStoreV1::create_evidence_only;
    let _open: fn(
        Arc<Dir>,
        &str,
        BudgetPolicyV1,
    ) -> Result<ContractsSessionStoreV1, SessionStoreError> =
        ContractsSessionStoreV1::open_evidence_only;
}

/// A2 — the linear ingress surface: install, accept, take, reinstall, and a
/// wrong extractor that returns the capability instead of consuming it.
#[test]
fn post_anchor_v2_evidence_only_ancestry_installs_accepts_take_and_reinstall(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path();
    let contracts_root = root.join("sessions");
    let StagedAncestry {
        staged,
        peers,
        sender_is_initiator,
    } = stage(root)?;
    let honest = staged.honest_signed_message().to_vec();
    let (store, prepared, _) = staged.into_parts();

    let mut worker = open_worker(root, !sender_is_initiator, peers, store, true)?;
    let mut peer = open_peer_sender(root, sender_is_initiator, peers, true)?;
    let mut relay = create_relay(&root.join("relay"))?;

    // Negative: the edge arrives with no capability installed. The generic
    // derived path must not promote an unseen `0x0f`.
    submit_signed_dsc1(&mut peer, &mut relay, &honest)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    let before = snapshot_store_tree(&contracts_root)?;
    let unprepared = worker
        .dispatch_inbound()
        .expect_err("an unseen 0x0f must not enter without its authority");
    assert_contracts_refusal!(unprepared, ContractsRelayIngressErrorV1::UnpreparedMessage);
    let staged_revision = worker.contracts_session_status()?.revision;
    assert_eq!(snapshot_store_tree(&contracts_root)?, before);
    // The refused message stays pending. Without this pair of counts the
    // acceptance below would only prove that *a* message was accepted, not
    // that it was **this** one — a test with the right name measuring
    // something next to what it claims.
    assert_eq!(worker.inbox_stats()?.pending_route, 1);

    // The wrong extractor gives the capability back rather than losing it.
    //
    // **There is no `expect_err` here, and there must not be one.** `expect_err`
    // requires `Debug` on the success type, and the success type of
    // `into_early` is a sealed capability handle: private fields, no `Clone`,
    // no `Copy`, no `Debug`, no codec. Adding a formatter to satisfy a test
    // would put a `{:?}` one line away from a log statement on an object that
    // exists precisely so it can never be printed, copied or serialized. The
    // absence of `Debug` is a property, not an oversight, and the
    // `assert_not_impl_any!` block at the top of this file is what keeps it
    // from being traded away for a convenience three months from now.
    let ingress = PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2(prepared);
    let Err(returned) = ingress.into_early() else {
        panic!("a post-anchor V2 authority is not an early authority")
    };
    let Ok(recovered) = returned.into_post_anchor_claim_pre_signature_v2() else {
        panic!("the wrong extractor must not consume the capability")
    };
    assert_eq!(recovered.session_id(), &STAGED_SESSION);

    // Positive: with the exact capability installed the same message is
    // accepted and the durable head moves exactly once.
    worker.install_contracts_ingress(
        PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2(recovered),
    )?;
    worker.dispatch_inbound()?;
    let accepted_revision = worker.contracts_session_status()?.revision;
    assert_eq!(accepted_revision, staged_revision + 1);
    assert_ne!(snapshot_store_tree(&contracts_root)?, before);
    // The pending row is gone, so the edge that moved the head is the one the
    // refusal above left behind.
    assert_eq!(worker.inbox_stats()?.pending_route, 0);

    // The capability is linear: it is taken back whole, and reinstalling the
    // same one is accepted while a second install without a take is refused.
    let taken = worker
        .take_contracts_ingress()
        .ok_or("the installed capability must be takeable")?;
    let taken = taken
        .into_post_anchor_claim_pre_signature_v2()
        .map_err(|_| "the taken capability must still be the post-anchor V2 one")?;
    assert_eq!(taken.session_id(), &STAGED_SESSION);
    worker.install_contracts_ingress(
        PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2(taken),
    )?;
    Ok(())
}

/// A3 — a real restart of both the worker and the Contracts Store, with the
/// authority reissued and authenticated against the same durable record.
#[test]
fn post_anchor_v2_evidence_only_ancestry_reissues_across_worker_and_store_restart(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path();
    let contracts_root = root.join("sessions");
    let StagedAncestry {
        staged,
        peers,
        sender_is_initiator,
    } = stage(root)?;
    let honest = staged.honest_signed_message().to_vec();
    let trusted_chain_id = *staged.trusted_chain_id();
    let (store, prepared, _) = staged.into_parts();
    let original_record_digest = *prepared.pre_signature_record_digest();
    let original_sender = *prepared.canonical_sender_id();
    let original_sequence = prepared.canonical_sender_sequence();

    let mut worker = open_worker(root, !sender_is_initiator, peers, store, true)?;
    let mut peer = open_peer_sender(root, sender_is_initiator, peers, true)?;
    let mut relay = create_relay(&root.join("relay"))?;

    worker.install_contracts_ingress(
        PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2(prepared),
    )?;
    submit_signed_dsc1(&mut peer, &mut relay, &honest)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    worker.dispatch_inbound()?;
    let accepted = worker.contracts_session_status()?;
    let after_accept = snapshot_store_tree(&contracts_root)?;

    // Real restart: the worker, its Store opening and the peer sender all go
    // away, and the durable tree is what survives.
    drop(worker);
    drop(peer);
    let reopened_store = ContractsSessionStoreV1::open_evidence_only(
        parent_capability(root)?,
        "sessions",
        evidence_only_policy()?,
    )?;
    assert_eq!(snapshot_store_tree(&contracts_root)?, after_accept);

    // The authority is reissued from the durable record, not rebuilt from
    // caller-shaped parts, and it names the same record the first one did.
    let consumed =
        reopened_store.resume_consumed_post_anchor_dom_claim_signing_v2(STAGED_SESSION)?;
    let reissued = reopened_store
        .prepare_post_anchor_dom_claim_pre_signature_transport_authority_v2(
            &consumed,
            trusted_chain_id,
        )?;
    assert_eq!(
        reissued.pre_signature_record_digest(),
        &original_record_digest
    );
    assert_eq!(reissued.canonical_sender_id(), &original_sender);
    assert_eq!(reissued.canonical_sender_sequence(), original_sequence);

    let mut worker = open_worker(root, !sender_is_initiator, peers, reopened_store, false)?;
    assert_eq!(
        worker.contracts_session_status()?.revision,
        accepted.revision
    );
    assert_eq!(worker.contracts_session_status()?.phase, accepted.phase);
    worker.install_contracts_ingress(
        PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2(reissued),
    )?;
    Ok(())
}

/// A4 — the exact same envelope delivered twice is a duplicate, and a
/// duplicate adds no revision and writes nothing.
#[test]
fn post_anchor_v2_evidence_only_ancestry_exact_duplicate_adds_no_revision(
) -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path();
    let contracts_root = root.join("sessions");
    let StagedAncestry {
        staged,
        peers,
        sender_is_initiator,
    } = stage(root)?;
    let honest = staged.honest_signed_message().to_vec();
    let (store, prepared, _) = staged.into_parts();

    let mut worker = open_worker(root, !sender_is_initiator, peers, store, true)?;
    let mut peer = open_peer_sender(root, sender_is_initiator, peers, true)?;
    let mut relay = create_relay(&root.join("relay"))?;
    worker.install_contracts_ingress(
        PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2(prepared),
    )?;

    // Positive: the first delivery is the real edge and moves the head once.
    let before = worker.contracts_session_status()?.revision;
    submit_signed_dsc1(&mut peer, &mut relay, &honest)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    worker.dispatch_inbound()?;
    let accepted = worker.contracts_session_status()?.revision;
    assert_eq!(accepted, before + 1);
    let after_accept = snapshot_store_tree(&contracts_root)?;

    // The identical envelope again. It travels as a fresh Relay message — the
    // sender assigns it its own outer sequence — so the duplicate is decided
    // by the Contracts layer on the exact inner bytes and not by the relay
    // dropping it.
    submit_signed_dsc1(&mut peer, &mut relay, &honest)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    worker.dispatch_inbound()?;
    assert_eq!(worker.contracts_session_status()?.revision, accepted);
    assert_eq!(snapshot_store_tree(&contracts_root)?, after_accept);
    Ok(())
}

/// A5 — a different validly signed message reusing the same logical key is an
/// equivocation, and it terminates the session durably.
#[test]
fn post_anchor_v2_evidence_only_ancestry_equivocation_fails_closed() -> Result<(), Box<dyn Error>> {
    let temporary = secure_tempdir()?;
    let root = temporary.path();
    let contracts_root = root.join("sessions");
    let StagedAncestry {
        staged,
        peers,
        sender_is_initiator,
    } = stage(root)?;
    let honest = staged.honest_signed_message().to_vec();

    // The conflicting message differs from the honest one in exactly one
    // payload byte and is signed by the same canonical sender, over the same
    // session, sequence and predecessor transcript. That is what makes it an
    // equivocation rather than a malformed message.
    let mut conflicting_payload = *staged
        .prepared_pre_signature_authority()
        .pre_signature_payload();
    let last = conflicting_payload.len() - 1;
    conflicting_payload[last] ^= 1;
    let conflicting = staged.sign_pre_signature_payload(&conflicting_payload)?;

    // The proof that this case cannot go vacuous, as an assertion and not as a
    // step someone once ran: the two envelopes must be different, must be the
    // same length, and must share the whole DSC1 prefix that carries chain,
    // session, sender, sequence and previous transcript. If a future change
    // made `sign_pre_signature_payload` produce a differently shaped or
    // differently keyed message, the refusal below would start coming from the
    // signature check instead of from the equivocation rule, and these three
    // lines fail instead of passing quietly.
    assert_ne!(conflicting, honest);
    assert_eq!(conflicting.len(), honest.len());
    assert_eq!(conflicting[..144], honest[..144]);
    assert_eq!(
        conflicting_payload.len(),
        AdaptorPreSignatureV1::ENCODED_LEN
    );

    let (store, prepared, _) = staged.into_parts();
    let mut worker = open_worker(root, !sender_is_initiator, peers, store, true)?;
    let mut peer = open_peer_sender(root, sender_is_initiator, peers, true)?;
    let mut relay = create_relay(&root.join("relay"))?;
    worker.install_contracts_ingress(
        PreparedContractsIngressV1::post_anchor_claim_pre_signature_v2(prepared),
    )?;

    // Positive first: the honest edge is accepted, so the refusal below is
    // attributable to the second message and not to a graph that was already
    // unusable.
    submit_signed_dsc1(&mut peer, &mut relay, &honest)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    worker.dispatch_inbound()?;
    let accepted = worker.contracts_session_status()?;
    assert_ne!(accepted.phase, SessionPhaseV1::FailedClosed);

    // The equivocation is persisted and the session is terminal afterwards.
    submit_signed_dsc1(&mut peer, &mut relay, &conflicting)?;
    assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
    worker.dispatch_inbound()?;
    let failed = worker.contracts_session_status()?;
    assert_eq!(failed.phase, SessionPhaseV1::FailedClosed);
    assert_eq!(failed.revision, accepted.revision + 1);
    let terminal = snapshot_store_tree(&contracts_root)?;

    // Nothing reopens after termination: redelivering either message leaves
    // the terminal state byte-identical.
    for message in [&honest, &conflicting] {
        submit_signed_dsc1(&mut peer, &mut relay, message)?;
        assert_eq!(worker.ingest_mailbox(&relay, now())?.accepted, 1);
        let _ = worker.dispatch_inbound();
        assert_eq!(
            worker.contracts_session_status()?.phase,
            SessionPhaseV1::FailedClosed
        );
        assert_eq!(snapshot_store_tree(&contracts_root)?, terminal);
    }
    Ok(())
}
