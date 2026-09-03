//! Official Wallet V3 bootstrap and real-node Slate funding for F7.
//!
//! This module deliberately stays inside `dom-leg`: the cross-chain runner
//! never names DOM transaction or Slate authority types. It receives only
//! high-level official-wallet operations and verified public receipts.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dom_adaptor::{SessionBlindingShareCapabilityV1, VerifiedSharedOutputV1};
use dom_wallet_core::{
    CoreError, ScriptlessFundingReservationRequestV1, ScriptlessFundingReservationSummaryV1,
    ScriptlessPayoutReservationRequestV1, ScriptlessPayoutReservationSummaryV1, WalletService,
};
use dom_wallet_core_protocol::{CanonicalSlate, ProtocolAdapterError};
use dom_wallet_core_sync::CoreChainIdentity;
use dom_wallet_domain::{Network, NetworkIdentity, ScriptlessPayoutRoleV1};
use dom_wallet_remote_source::RemoteNodeSource;
use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::f7_wallet::{
    compose_wallet_pair_claim_template_v1, compose_wallet_pair_funding_template_v1,
    compose_wallet_pair_refund_template_v1, F7WalletBoundDomClaimV1, F7WalletBoundDomFundingV1,
    F7WalletBoundDomRefundV1, F7WalletCompositorError,
};
use crate::F7DomRoutePreparationRequestV1;

const MAX_RPC_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SECRET_BYTES: u64 = 4 * 1024;
const MAX_WALLET_TREE_ENTRIES: usize = 4_096;
const MAX_WALLET_TREE_DEPTH: usize = 8;
/// How long a wallet may take to bring its cursor all the way to the tip.
///
/// This is a wait budget, not a criterion. The criterion is unchanged and is
/// not relaxed here: `synchronize_wallet` still returns only when
/// `cursor_height == tip_height`, and a wallet that never reaches the tip still
/// fails — later.
///
/// 120 s was sized when every route ran on a chain of a few hundred blocks. It
/// is structurally incompatible with the refund family, whose DOM height lock
/// is `tip + 11_023`: the wallet's per-page work scales with the chain, and
/// measured behaviour matches — every route prepared successfully at heights
/// ~700 to ~1300, and every preparation at ~3400 to ~4050 failed here, at this
/// deadline, surfacing as `F7OfficialWalletError::Rpc`.
///
/// The figure below is therefore taken from what the route requires rather than
/// from a measurement of the sync itself, which is not observable from outside
/// the wallet. Thirty minutes is proportionate to a route that then mines for
/// tens of hours, and it is bounded, so a genuinely stuck wallet is still a
/// failure and not a hang.
const SYNCHRONIZE_TIMEOUT: Duration = Duration::from_secs(1_800);
const SYNCHRONIZE_POLL: Duration = Duration::from_millis(100);

/// Fail-closed error from official Wallet V3 runtime composition.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum F7OfficialWalletError {
    /// An endpoint, identity, path, mode, amount or restart binding is invalid.
    #[error("invalid official Wallet V3 runtime binding")]
    Binding,
    /// Owner-only Wallet V3 or recovery storage failed closed.
    #[error("official Wallet V3 storage failed")]
    Filesystem,
    /// Official Wallet V3 rejected lifecycle, Slate, scan or reservation state.
    ///
    /// Carries the swallowed source with Display and Debug: the bare variant
    /// name was not enough to diagnose the 2026-08-18 preparation failures,
    /// which is the exact lesson `F7_HANDOVER_20260817.md` §4.5 records.
    #[error("official Wallet V3 rejected the operation: {0}")]
    Wallet(String),
    /// The authenticated node WalletDir Slate RPC rejected the operation.
    #[error("real DOM WalletDir Slate RPC rejected the operation")]
    Rpc,
    /// The frozen Wallet-owned Slate codec rejected canonical public bytes.
    #[error("official Wallet V3 rejected the canonical Slate: {0}")]
    Protocol(#[from] ProtocolAdapterError),
    /// Wallet Core rejected the operation. Core errors are public lifecycle or
    /// storage categories and never contain wallet secrets.
    #[error("official Wallet V3 core rejected the operation: {0}")]
    Core(#[from] CoreError),
}

impl From<F7WalletCompositorError> for F7OfficialWalletError {
    fn from(error: F7WalletCompositorError) -> Self {
        Self::Wallet(format!("compositor: {error} [{error:?}]"))
    }
}

/// Secret-bearing startup configuration for one official Wallet V3 peer.
///
/// Formatting always redacts both the bearer token and wallet password. The
/// values are zeroized on drop and are never put in argv, environment output
/// or an RPC body.
pub struct F7OfficialWalletParticipantConfigV1 {
    endpoint: String,
    bearer_token: Zeroizing<String>,
    wallet_path: PathBuf,
    recovery_phrase_file: PathBuf,
    password: Zeroizing<String>,
    expected_network_magic: u32,
    expected_chain_id: [u8; 32],
    expected_genesis_hash: [u8; 32],
}

impl core::fmt::Debug for F7OfficialWalletParticipantConfigV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7OfficialWalletParticipantConfigV1")
            .field("endpoint", &self.endpoint)
            .field("bearer_token", &"[redacted]")
            .field("wallet_path", &self.wallet_path)
            .field("recovery_phrase_file", &self.recovery_phrase_file)
            .field("password", &"[redacted]")
            .field("expected_network_magic", &self.expected_network_magic)
            .field("expected_chain_id", &self.expected_chain_id)
            .field("expected_genesis_hash", &self.expected_genesis_hash)
            .finish()
    }
}

impl F7OfficialWalletParticipantConfigV1 {
    /// Validates one loopback real-node/official-wallet binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: String,
        bearer_token: Zeroizing<String>,
        wallet_path: PathBuf,
        recovery_phrase_file: PathBuf,
        password: Zeroizing<String>,
        expected_network_magic: u32,
        expected_chain_id: [u8; 32],
        expected_genesis_hash: [u8; 32],
    ) -> Result<Self, F7OfficialWalletError> {
        validate_loopback_endpoint(&endpoint)?;
        validate_secret(&bearer_token)?;
        validate_secret(&password)?;
        if !wallet_path.is_absolute()
            || !recovery_phrase_file.is_absolute()
            || wallet_path == recovery_phrase_file
            || expected_network_magic == 0
            || expected_chain_id == [0; 32]
            || expected_genesis_hash == [0; 32]
        {
            return Err(F7OfficialWalletError::Binding);
        }
        Ok(Self {
            endpoint: endpoint.trim_end_matches('/').to_owned(),
            bearer_token,
            wallet_path,
            recovery_phrase_file,
            password,
            expected_network_magic,
            expected_chain_id,
            expected_genesis_hash,
        })
    }
}

/// Public, exact result of funding one official Wallet V3 through the node's
/// restart-safe three-message Slate boundary.
pub struct F7OfficialWalletFundingReceiptV1 {
    participant_index: u16,
    slate_id: [u8; 32],
    replay_id: [u8; 32],
    pending_key: [u8; 32],
    transaction_hash: [u8; 32],
    canonical_transaction: Vec<u8>,
}

impl core::fmt::Debug for F7OfficialWalletFundingReceiptV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7OfficialWalletFundingReceiptV1")
            .field("participant_index", &self.participant_index)
            .field("slate_id", &self.slate_id)
            .field("replay_id", &self.replay_id)
            .field("pending_key", &self.pending_key)
            .field("transaction_hash", &self.transaction_hash)
            .field(
                "canonical_transaction",
                &"[redacted public transaction bytes]",
            )
            .finish()
    }
}

impl F7OfficialWalletFundingReceiptV1 {
    /// Canonical participant slot funded by this receipt.
    #[must_use]
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }

    /// Public Slate identifier verified by the official wallet.
    #[must_use]
    pub const fn slate_id(&self) -> [u8; 32] {
        self.slate_id
    }

    /// Public replay identifier bound by the canonical offer.
    #[must_use]
    pub const fn replay_id(&self) -> [u8; 32] {
        self.replay_id
    }

    /// Opaque durable node WalletDir record key used for exact retry.
    #[must_use]
    pub const fn pending_key(&self) -> [u8; 32] {
        self.pending_key
    }

    /// Canonical transaction hash returned and independently recomputed.
    #[must_use]
    pub const fn transaction_hash(&self) -> [u8; 32] {
        self.transaction_hash
    }

    /// Exact finalized transaction bytes imported by the official wallet.
    #[must_use]
    pub fn canonical_transaction(&self) -> &[u8] {
        &self.canonical_transaction
    }
}

struct F7OfficialWalletParticipantV1 {
    config: F7OfficialWalletParticipantConfigV1,
    client: Client,
    wallet: WalletService,
}

/// Two official Wallet V3 services attached to independent real DOM peers.
///
/// Wallet database creation/recovery is restart-safe and owner-only. Funding
/// crosses the real node WalletDir create/finalize/submit boundary; no local
/// transaction fixture or simulated chain can satisfy this type.
pub struct F7OfficialWalletPairV1 {
    participants: [F7OfficialWalletParticipantV1; 2],
    chain_id: [u8; 32],
}

/// Six durable official-Wallet reservations retained in canonical participant
/// order for one F7 route.
///
/// The canonical-to-wallet permutation stays crate-private so the runner can
/// neither swap a reservation owner nor obtain either `WalletService`.
pub(crate) struct F7OfficialWalletRouteReservationsV1 {
    canonical_to_wallet: [usize; 2],
    funding: [ScriptlessFundingReservationSummaryV1; 2],
    claim: [ScriptlessPayoutReservationSummaryV1; 2],
    refund: [ScriptlessPayoutReservationSummaryV1; 2],
}

/// Three exact Wallet-bound DOM templates prepared from the six reservations.
/// Raw Wallet summaries and services remain private to `dom-leg`.
pub(crate) struct F7OfficialWalletRouteTemplatesV1 {
    pub(crate) funding: F7WalletBoundDomFundingV1,
    pub(crate) claim: F7WalletBoundDomClaimV1,
    pub(crate) refund: F7WalletBoundDomRefundV1,
}

impl core::fmt::Debug for F7OfficialWalletPairV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("F7OfficialWalletPairV1")
            .field("participants", &"[two official Wallet V3 services]")
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

impl F7OfficialWalletPairV1 {
    /// Creates or reopens two secure official wallets and authenticates both
    /// remote full-fidelity scanner identities before returning.
    pub fn connect(
        configs: [F7OfficialWalletParticipantConfigV1; 2],
    ) -> Result<Self, F7OfficialWalletError> {
        if configs[0].wallet_path == configs[1].wallet_path
            || configs[0].recovery_phrase_file == configs[1].recovery_phrase_file
            || configs[0].expected_chain_id != configs[1].expected_chain_id
            || configs[0].expected_genesis_hash != configs[1].expected_genesis_hash
            || configs[0].expected_network_magic != configs[1].expected_network_magic
        {
            return Err(F7OfficialWalletError::Binding);
        }
        let [first, second] = configs;
        let first = connect_participant_within_deadline(first)?;
        let second = connect_participant_within_deadline(second)?;
        let pair = Self {
            chain_id: first.config.expected_chain_id,
            participants: [first, second],
        };
        pair.require_live_identity(0)?;
        pair.require_live_identity(1)?;
        Ok(pair)
    }

    /// Exact authenticated DOM chain shared by both official wallets.
    #[must_use]
    pub const fn chain_id(&self) -> [u8; 32] {
        self.chain_id
    }

    /// Runs the bounded official scanner to convergence for both peers.
    pub fn synchronize(&mut self) -> Result<(), F7OfficialWalletError> {
        synchronize_wallet(&mut self.participants[0].wallet)?;
        synchronize_wallet(&mut self.participants[1].wallet)
    }

    /// Closes and reopens one official wallet database over the same real peer.
    /// This never regenerates recovery material or changes its scanner binding.
    pub fn restart_participant(
        &mut self,
        participant_index: u16,
    ) -> Result<(), F7OfficialWalletError> {
        let participant = self
            .participants
            .get_mut(usize::from(participant_index))
            .ok_or(F7OfficialWalletError::Binding)?;
        participant.wallet.close()?;
        participant.wallet = open_existing_wallet(&participant.config)?;
        require_live_identity_for_participant(participant).map(|_| ())
    }

    /// Transfers real mature node-WalletDir funds to one official Wallet V3
    /// service through create, recipient response, durable finalize, recipient
    /// verify/import and exact pending-key submit.
    pub fn fund_participant_from_node_wallet(
        &mut self,
        participant_index: u16,
        amount_noms: u64,
        fee_noms: u64,
        expires_at_height: u64,
    ) -> Result<F7OfficialWalletFundingReceiptV1, F7OfficialWalletError> {
        if amount_noms == 0 || fee_noms == 0 || amount_noms <= fee_noms {
            return Err(F7OfficialWalletError::Binding);
        }
        let participant = self
            .participants
            .get_mut(usize::from(participant_index))
            .ok_or(F7OfficialWalletError::Binding)?;
        let identity = require_live_identity_for_participant(participant)?;
        if expires_at_height <= identity.current_tip.height {
            return Err(F7OfficialWalletError::Binding);
        }
        let offer: SlateOfferResponseV1 = post_json(
            participant,
            "/wallet/slate/v1/create",
            json!({
                "amount_noms": amount_noms,
                "fee_noms": fee_noms,
                "expires_at_height": expires_at_height,
            }),
        )?;
        require_schema(offer.schema_version)?;
        let offer_bytes = decode_hex_bounded(&offer.canonical_slate_hex)?;
        let slate_id = decode_hex_array(&offer.slate_id)?;
        let replay_id = decode_hex_array(&offer.replay_id)?;
        let canonical_offer = CanonicalSlate::from_recovery_bytes(
            &offer_bytes,
            &identity,
            identity.current_tip.height,
        )?;
        let canonical_replay = canonical_offer.replay_key();
        if canonical_replay.slate_id != slate_id || canonical_replay.replay_id != replay_id {
            return Err(F7OfficialWalletError::Binding);
        }
        let offer_text = canonical_offer.to_text();
        let imported =
            retry_transient_wallet_core(|| participant.wallet.slate_request_import(&offer_text))?;
        let wallet_slate_id = imported.slate_id.ok_or(F7OfficialWalletError::Binding)?;
        if wallet_slate_id.as_bytes() != &slate_id[..16] {
            return Err(F7OfficialWalletError::Binding);
        }
        retry_transient_wallet_core(|| participant.wallet.slate_response_create(wallet_slate_id))?;
        let response_text = retry_transient_wallet_core(|| {
            participant.wallet.slate_response_export(wallet_slate_id)
        })?
        .text;
        let response =
            CanonicalSlate::from_text(&response_text, &identity, identity.current_tip.height)?;
        let finalized: SlateFinalizeResponseV1 = post_json(
            participant,
            "/wallet/slate/v1/finalize",
            json!({"canonical_response_hex": hex::encode(response.canonical_bytes())}),
        )?;
        require_schema(finalized.schema_version)?;
        let canonical_transaction = decode_hex_bounded(&finalized.canonical_tx_hex)?;
        let transaction_hash = decode_hex_array(&finalized.tx_hash)?;
        let pending_key = decode_hex_array(&finalized.pending_key)?;
        if dom_crypto::blake2b_256(&canonical_transaction).as_bytes() != &transaction_hash {
            return Err(F7OfficialWalletError::Binding);
        }
        let imported = retry_transient_wallet_core(|| {
            participant
                .wallet
                .transaction_finalized_verify_and_import(wallet_slate_id, &canonical_transaction)
        })?;
        if imported.transaction_hash != transaction_hash {
            return Err(F7OfficialWalletError::Binding);
        }
        let receipt = F7OfficialWalletFundingReceiptV1 {
            participant_index,
            slate_id,
            replay_id,
            pending_key,
            transaction_hash,
            canonical_transaction,
        };
        submit_exact_pending(participant, &receipt)?;
        Ok(receipt)
    }

    /// Retries only the exact node-WalletDir pending record already verified
    /// and imported by the official wallet; caller-provided transaction bytes
    /// are never accepted by the RPC.
    pub fn retry_node_wallet_funding(
        &mut self,
        receipt: &F7OfficialWalletFundingReceiptV1,
    ) -> Result<(), F7OfficialWalletError> {
        let participant = self
            .participants
            .get_mut(usize::from(receipt.participant_index))
            .ok_or(F7OfficialWalletError::Binding)?;
        submit_exact_pending(participant, receipt)
    }

    /// Creates or reopens the two Funding, two Claim and two Refund
    /// reservations without exposing either wallet or reservation identifier
    /// outside `dom-leg`.
    ///
    /// `canonical_to_wallet[i]` binds canonical DOM participant `i` to one
    /// stable official-wallet slot. The same permutation is retained for all
    /// three purposes, preventing a purpose-specific ownership swap when G1a
    /// signing-key order differs between Funding, Claim and Refund.
    pub(crate) fn prepare_or_resume_route_reservations(
        &mut self,
        request: &F7DomRoutePreparationRequestV1,
        shared_output_commitment: [u8; 33],
        canonical_to_wallet: [usize; 2],
    ) -> Result<F7OfficialWalletRouteReservationsV1, F7OfficialWalletError> {
        require_two_party_permutation(canonical_to_wallet)?;
        if shared_output_commitment == [0; 33] {
            return Err(F7OfficialWalletError::Binding);
        }
        let funding_shape = request.funding();
        let claim_shape = request.claim();
        let refund_shape = request.refund();
        let mut funding = Vec::with_capacity(2);
        let mut claim = Vec::with_capacity(2);
        let mut refund = Vec::with_capacity(2);
        // `canonical_index` indexes four parallel shape arrays, not one collection.
        #[allow(clippy::needless_range_loop)]
        for canonical_index in 0..2 {
            let wallet_index = canonical_to_wallet[canonical_index];
            let wallet = &mut self
                .participants
                .get_mut(wallet_index)
                .ok_or(F7OfficialWalletError::Binding)?
                .wallet;
            funding.push(wallet.scriptless_funding_prepare(
                ScriptlessFundingReservationRequestV1 {
                    session_id: request.session_id(),
                    shared_output_commitment,
                    local_debit_noms: funding_shape.local_debit_noms()[canonical_index],
                    funding_fee_noms: funding_shape.fee_noms(),
                    expected_input_count: funding_shape.expected_input_count(),
                    expected_output_count: funding_shape.expected_output_count(),
                },
            )?);
            claim.push(
                wallet.scriptless_payout_prepare(ScriptlessPayoutReservationRequestV1 {
                    session_id: request.session_id(),
                    role: ScriptlessPayoutRoleV1::Claim,
                    shared_output_commitment,
                    payout_value_noms: claim_shape.payout_noms()[canonical_index],
                    kernel_fee_noms: claim_shape.fee_noms(),
                    expected_output_count: claim_shape.expected_output_count(),
                    refund_lock_height: 0,
                })?,
            );
            refund.push(wallet.scriptless_payout_prepare(
                ScriptlessPayoutReservationRequestV1 {
                    session_id: request.session_id(),
                    role: ScriptlessPayoutRoleV1::Refund,
                    shared_output_commitment,
                    payout_value_noms: refund_shape.payout_noms()[canonical_index],
                    kernel_fee_noms: refund_shape.fee_noms(),
                    expected_output_count: refund_shape.expected_output_count(),
                    refund_lock_height: request.refund_lock_height(),
                },
            )?);
        }
        Ok(F7OfficialWalletRouteReservationsV1 {
            canonical_to_wallet,
            funding: funding
                .try_into()
                .map_err(|_| F7OfficialWalletError::Binding)?,
            claim: claim
                .try_into()
                .map_err(|_| F7OfficialWalletError::Binding)?,
            refund: refund
                .try_into()
                .map_err(|_| F7OfficialWalletError::Binding)?,
        })
    }

    /// Builds all three exact templates through the same private participant
    /// ownership permutation used when the six reservations were created.
    pub(crate) fn compose_route_templates(
        &mut self,
        request: &F7DomRoutePreparationRequestV1,
        reservations: F7OfficialWalletRouteReservationsV1,
        session_shares: [&SessionBlindingShareCapabilityV1; 2],
        shared_output: &VerifiedSharedOutputV1,
    ) -> Result<F7OfficialWalletRouteTemplatesV1, F7OfficialWalletError> {
        let F7OfficialWalletRouteReservationsV1 {
            canonical_to_wallet,
            funding,
            claim,
            refund,
        } = reservations;
        let [first_wallet, second_wallet] = self.wallets_in_canonical_order(canonical_to_wallet)?;
        let funding = compose_wallet_pair_funding_template_v1(
            first_wallet,
            second_wallet,
            funding,
            session_shares,
            shared_output,
            request.funding().shared_output_position(),
        )?;
        let claim = compose_wallet_pair_claim_template_v1(
            first_wallet,
            second_wallet,
            claim,
            session_shares,
            shared_output,
        )?;
        let refund = compose_wallet_pair_refund_template_v1(
            first_wallet,
            second_wallet,
            refund,
            session_shares,
            shared_output,
            request.funding_tip_height(),
        )?;
        Ok(F7OfficialWalletRouteTemplatesV1 {
            funding,
            claim,
            refund,
        })
    }

    /// Builds and binds the exact funding template without exposing either
    /// official `WalletService` to the cross-chain runner.
    pub fn compose_funding_template(
        &mut self,
        reservations: [ScriptlessFundingReservationSummaryV1; 2],
        session_shares: [&SessionBlindingShareCapabilityV1; 2],
        shared_output: &VerifiedSharedOutputV1,
        shared_output_position: usize,
    ) -> Result<F7WalletBoundDomFundingV1, F7OfficialWalletError> {
        let [first, second] = &mut self.participants;
        compose_wallet_pair_funding_template_v1(
            &mut first.wallet,
            &mut second.wallet,
            reservations,
            session_shares,
            shared_output,
            shared_output_position,
        )
        .map_err(Into::into)
    }

    /// Builds and binds the exact post-anchor DOM claim template without
    /// exposing either official wallet service.
    pub fn compose_claim_template(
        &mut self,
        reservations: [ScriptlessPayoutReservationSummaryV1; 2],
        session_shares: [&SessionBlindingShareCapabilityV1; 2],
        shared_output: &VerifiedSharedOutputV1,
    ) -> Result<F7WalletBoundDomClaimV1, F7OfficialWalletError> {
        let [first, second] = &mut self.participants;
        compose_wallet_pair_claim_template_v1(
            &mut first.wallet,
            &mut second.wallet,
            reservations,
            session_shares,
            shared_output,
        )
        .map_err(Into::into)
    }

    /// Builds and binds the exact pre-funded DOM recovery transaction without
    /// exposing either official wallet service.
    pub fn compose_refund_template(
        &mut self,
        reservations: [ScriptlessPayoutReservationSummaryV1; 2],
        session_shares: [&SessionBlindingShareCapabilityV1; 2],
        shared_output: &VerifiedSharedOutputV1,
        funding_tip_height: u64,
    ) -> Result<F7WalletBoundDomRefundV1, F7OfficialWalletError> {
        let [first, second] = &mut self.participants;
        compose_wallet_pair_refund_template_v1(
            &mut first.wallet,
            &mut second.wallet,
            reservations,
            session_shares,
            shared_output,
            funding_tip_height,
        )
        .map_err(Into::into)
    }

    fn require_live_identity(&self, participant_index: u16) -> Result<(), F7OfficialWalletError> {
        let participant = self
            .participants
            .get(usize::from(participant_index))
            .ok_or(F7OfficialWalletError::Binding)?;
        require_live_identity_for_participant(participant).map(|_| ())
    }

    fn wallets_in_canonical_order(
        &mut self,
        canonical_to_wallet: [usize; 2],
    ) -> Result<[&mut WalletService; 2], F7OfficialWalletError> {
        require_two_party_permutation(canonical_to_wallet)?;
        let [first, second] = &mut self.participants;
        Ok(match canonical_to_wallet {
            [0, 1] => [&mut first.wallet, &mut second.wallet],
            [1, 0] => [&mut second.wallet, &mut first.wallet],
            _ => return Err(F7OfficialWalletError::Binding),
        })
    }
}

fn require_two_party_permutation(
    canonical_to_wallet: [usize; 2],
) -> Result<(), F7OfficialWalletError> {
    if matches!(canonical_to_wallet, [0, 1] | [1, 0]) {
        Ok(())
    } else {
        Err(F7OfficialWalletError::Binding)
    }
}

/// How long `connect` waits for a node that is not yet answering.
///
/// A DOM node answers 503 "chain busy" for a while after a restart, and the
/// window is longer after a route that performed heavy wallet synchronization.
/// Connecting once, with no readiness wait, turns an ordinary startup transient
/// into a route result: four F7 runs died in preparation with "official Wallet
/// V3 runtime validation failed" on 2026-08-17, one of them AFTER the caller's
/// fixed settling sleep had been raised from 60 s to 180 s. That is what proved
/// the sleep duration was never the variable.
///
/// This is a deadline, not a criterion. Nothing is relaxed: every identity,
/// genesis and magic check `connect_participant` performs still runs, unchanged
/// and exactly once, and a node that never becomes ready still fails.
const CONNECT_READY_DEADLINE: Duration = Duration::from_secs(180);
/// Interval between readiness probes. Deliberately coarse: the node is
/// recovering, and a tight poll against a busy node is the livelock this
/// laboratory already met once in `synchronize_wallet`.
const CONNECT_READY_INTERVAL: Duration = Duration::from_secs(3);

/// Waits until the participant's node answers, then connects exactly once.
///
/// Only readiness is polled — the configuration is borrowed, never cloned, so
/// no secret-bearing value is duplicated to serve a retry.
fn connect_participant_within_deadline(
    config: F7OfficialWalletParticipantConfigV1,
) -> Result<F7OfficialWalletParticipantV1, F7OfficialWalletError> {
    let deadline = Instant::now() + CONNECT_READY_DEADLINE;
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| F7OfficialWalletError::Rpc)?;
    // The readiness signal must be the authenticated scan itself. `/status`
    // answers 200 while the chain lock is still busy after a restart, so
    // probing it proved insufficient: scenario 33 failed its preparation in
    // under two minutes WITH a /status probe in place (2026-08-17T23:28Z),
    // because the subsequent identity scan met the same 503 the probe never
    // saw. Readiness here means the node serves an authenticated zero-width
    // scan with the exact expected identity.
    let probe = format!(
        "{}/chain/scan/scriptless/v1?from=0&to=0&expected_network_magic={}&expected_chain_id={}",
        config.endpoint,
        config.expected_network_magic,
        hex::encode(config.expected_chain_id),
    );
    loop {
        let ready = client
            .get(&probe)
            .bearer_auth(config.bearer_token.as_str())
            .send()
            .map(|response| response.status().is_success())
            .unwrap_or(false);
        if ready || Instant::now() >= deadline {
            break;
        }
        thread::sleep(CONNECT_READY_INTERVAL);
    }
    connect_participant(config)
}

fn connect_participant(
    config: F7OfficialWalletParticipantConfigV1,
) -> Result<F7OfficialWalletParticipantV1, F7OfficialWalletError> {
    validate_private_parent(&config.wallet_path)?;
    validate_private_parent(&config.recovery_phrase_file)?;
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| F7OfficialWalletError::Rpc)?;
    let mut wallet = attach_remote_source(&config)?;
    let identity = require_identity(&config, &wallet)?;
    if config.wallet_path.exists() && !config.recovery_phrase_file.exists() {
        // A crash between WalletDirectory creation and phrase fsync leaves the
        // tree inside an owner-only parent but may precede our inner-mode
        // normalization. This is the sole repair case: the absent phrase proves
        // the creation ceremony never crossed this compositor's durable gate.
        require_repairable_interrupted_wallet_directory(&config.wallet_path)?;
        harden_new_wallet_tree(&config.wallet_path)?;
        let recovery = wallet
            .resume_recoverable_creation(&config.wallet_path, &config.password)
            .map_err(|error| {
                F7OfficialWalletError::Wallet(format!(
                    "resume_recoverable_creation: {error} [{error:?}]"
                ))
            })?;
        let resumed = Zeroizing::new(recovery.mnemonic);
        persist_owner_only_secret(&config.recovery_phrase_file, &resumed)?;
        wallet.recovery_phrase_confirmed(&config.password)?;
    } else if config.wallet_path.exists() {
        validate_owner_only_tree(&config.wallet_path)?;
        wallet.open(&config.wallet_path)?;
        match wallet.recovery_phrase_resume(&config.password) {
            Ok(recovery) => {
                let resumed = Zeroizing::new(recovery.mnemonic);
                let retained = read_owner_only_secret(&config.recovery_phrase_file)?;
                if retained.as_bytes() != resumed.as_bytes() {
                    return Err(F7OfficialWalletError::Binding);
                }
                wallet.recovery_phrase_confirmed(&config.password)?;
            }
            Err(CoreError::RecoveryPhraseAlreadyConfirmed) => {
                let _ = read_owner_only_secret(&config.recovery_phrase_file)?;
            }
            Err(error) => {
                return Err(F7OfficialWalletError::Wallet(format!(
                    "recovery_phrase_resume: {error} [{error:?}]"
                )))
            }
        }
    } else {
        if config.recovery_phrase_file.exists() {
            return Err(F7OfficialWalletError::Binding);
        }
        let recovery = wallet.create_recoverable(
            &config.wallet_path,
            &config.password,
            NetworkIdentity {
                network: Network::PrivateTestnet,
                chain_id: identity.chain_id,
                genesis_id: identity.genesis_hash,
            },
        )?;
        harden_new_wallet_tree(&config.wallet_path)?;
        let mnemonic = Zeroizing::new(recovery.mnemonic);
        persist_owner_only_secret(&config.recovery_phrase_file, &mnemonic)?;
        wallet.recovery_phrase_confirmed(&config.password)?;
    }
    wallet.unlock(&config.password)?;
    synchronize_wallet(&mut wallet)?;
    Ok(F7OfficialWalletParticipantV1 {
        config,
        client,
        wallet,
    })
}

fn open_existing_wallet(
    config: &F7OfficialWalletParticipantConfigV1,
) -> Result<WalletService, F7OfficialWalletError> {
    validate_owner_only_tree(&config.wallet_path)?;
    let _ = read_owner_only_secret(&config.recovery_phrase_file)?;
    let mut wallet = attach_remote_source(config)?;
    require_identity(config, &wallet)?;
    wallet.open(&config.wallet_path)?;
    wallet.unlock(&config.password)?;
    synchronize_wallet(&mut wallet)?;
    Ok(wallet)
}

fn attach_remote_source(
    config: &F7OfficialWalletParticipantConfigV1,
) -> Result<WalletService, F7OfficialWalletError> {
    let source = RemoteNodeSource::new(&config.endpoint, Some(&config.bearer_token))
        .map_err(|_| F7OfficialWalletError::Rpc)?;
    let mut wallet = WalletService::default();
    wallet.start_remote_source(Arc::new(source))?;
    Ok(wallet)
}

fn require_identity(
    config: &F7OfficialWalletParticipantConfigV1,
    wallet: &WalletService,
) -> Result<CoreChainIdentity, F7OfficialWalletError> {
    let identity = retry_transient_wallet_core(|| wallet.embedded_core_identity())?;
    if identity.network_magic != config.expected_network_magic
        || identity.chain_id != config.expected_chain_id
        || identity.genesis_hash != config.expected_genesis_hash
    {
        return Err(F7OfficialWalletError::Binding);
    }
    Ok(identity)
}

fn require_live_identity_for_participant(
    participant: &F7OfficialWalletParticipantV1,
) -> Result<CoreChainIdentity, F7OfficialWalletError> {
    require_identity(&participant.config, &participant.wallet)
}

fn synchronize_wallet(wallet: &mut WalletService) -> Result<(), F7OfficialWalletError> {
    let deadline = Instant::now() + SYNCHRONIZE_TIMEOUT;
    // Counted rather than printed: a library on stderr breaks the I6 guard,
    // and the count reaches the caller only if it travels in the error.
    // Known loss, stated rather than hidden: on a synchronize that eventually
    // succeeds, the tolerated count is discarded, because reporting it would
    // change this function's signature and that of its four callers.
    let mut tolerated_invalid_scans = 0usize;
    let mut last_invalid_scan = String::new();
    loop {
        match wallet.synchronize() {
            Ok(summary)
                if summary.cursor_height.is_some()
                    && summary.cursor_height == summary.tip_height =>
            {
                return Ok(())
            }
            Ok(_) | Err(CoreError::NodeNotReady) => {}
            Err(CoreError::Backend(error)) if error.is_transient_sync_unavailability() => {}
            // RATIFIED (explicit operator decision, 2026-09-02 —
            // ratifications/e13-executadas v2 §2.11): a scan validation failure is retried inside
            // the same deadline instead of aborting the attach. Every page the
            // wallet commits is durable, so a retried synchronize resumes from
            // the durable cursor and RE-RUNS the failed validation, which must
            // then pass — nothing is weakened, an idempotent read is repeated.
            // Motivation: scenario 82's resume died twice mid-sync on
            // InvalidScan { TIP_HASH_DISAGREEMENT } while both nodes served a
            // byte-identical canonical view before and after (a 308-page
            // replication of this client's own checks found zero
            // disagreements), so the failure is transient on the client path,
            // and the sync loop treated it as fatal. Each tolerated occurrence
            // is counted so the frequency reaches the caller on the failure
            // path, where the opaque `Rpc` used to hide the cause entirely.
            Err(CoreError::Backend(error)) if format!("{error:?}").contains("InvalidScan") => {
                tolerated_invalid_scans += 1;
                last_invalid_scan = format!("{error} [{error:?}]");
            }
            Err(error) => {
                return Err(F7OfficialWalletError::Wallet(format!(
                    "wallet synchronize failed: {error} [{error:?}]"
                )))
            }
        }
        if Instant::now() >= deadline {
            // §4.5: a bare `Rpc` here would say the synchronize timed out and
            // nothing about why. When the deadline was consumed tolerating
            // InvalidScan, that is the cause and it travels with the error.
            return Err(if tolerated_invalid_scans == 0 {
                F7OfficialWalletError::Rpc
            } else {
                F7OfficialWalletError::Wallet(format!(
                    "wallet synchronize timed out after tolerating \
                     {tolerated_invalid_scans} InvalidScan retries; last: {last_invalid_scan}"
                ))
            });
        }
        thread::sleep(SYNCHRONIZE_POLL);
    }
}

fn retry_transient_wallet_core<T>(
    mut operation: impl FnMut() -> Result<T, CoreError>,
) -> Result<T, CoreError> {
    let deadline = Instant::now() + SYNCHRONIZE_TIMEOUT;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(CoreError::Backend(error)) if error.is_transient_sync_unavailability() => {
                if Instant::now() >= deadline {
                    return Err(CoreError::Backend(error));
                }
            }
            Err(error) => return Err(error),
        }
        thread::sleep(SYNCHRONIZE_POLL);
    }
}

fn submit_exact_pending(
    participant: &F7OfficialWalletParticipantV1,
    receipt: &F7OfficialWalletFundingReceiptV1,
) -> Result<(), F7OfficialWalletError> {
    let submitted: SlateSubmitResponseV1 = post_json(
        participant,
        "/wallet/slate/v1/submit",
        json!({
            "pending_key_hex": hex::encode(receipt.pending_key),
            "expected_transaction_hash_hex": hex::encode(receipt.transaction_hash),
        }),
    )?;
    require_schema(submitted.schema_version)?;
    let canonical_transaction = decode_hex_bounded(&submitted.canonical_tx_hex)?;
    let transaction_hash: [u8; 32] = decode_hex_array(&submitted.tx_hash)?;
    let coherent_state = match submitted.state.as_str() {
        "new" => !submitted.already_known && !submitted.confirmed,
        "mempool" => submitted.already_known && !submitted.confirmed,
        "confirmed" => submitted.already_known && submitted.confirmed && !submitted.relayed,
        _ => false,
    };
    if !coherent_state
        || transaction_hash != receipt.transaction_hash
        || canonical_transaction != receipt.canonical_transaction
    {
        return Err(F7OfficialWalletError::Binding);
    }
    Ok(())
}

fn post_json<T: for<'de> Deserialize<'de>>(
    participant: &F7OfficialWalletParticipantV1,
    path: &str,
    body: serde_json::Value,
) -> Result<T, F7OfficialWalletError> {
    let response = participant
        .client
        .post(format!("{}{path}", participant.config.endpoint))
        .bearer_auth(participant.config.bearer_token.as_str())
        .json(&body)
        .send()
        .map_err(|_| F7OfficialWalletError::Rpc)?;
    decode_response(response)
}

fn decode_response<T: for<'de> Deserialize<'de>>(
    response: Response,
) -> Result<T, F7OfficialWalletError> {
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES)
    {
        return Err(F7OfficialWalletError::Rpc);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RPC_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| F7OfficialWalletError::Rpc)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_RPC_RESPONSE_BYTES {
        return Err(F7OfficialWalletError::Rpc);
    }
    serde_json::from_slice(&bytes).map_err(|_| F7OfficialWalletError::Rpc)
}

fn validate_loopback_endpoint(endpoint: &str) -> Result<(), F7OfficialWalletError> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| F7OfficialWalletError::Binding)?;
    let host = url.host_str().ok_or(F7OfficialWalletError::Binding)?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "http"
        || !loopback
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(F7OfficialWalletError::Binding);
    }
    Ok(())
}

fn validate_secret(secret: &str) -> Result<(), F7OfficialWalletError> {
    if secret.is_empty()
        || secret.len() > MAX_SECRET_BYTES as usize
        || secret.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(F7OfficialWalletError::Binding);
    }
    Ok(())
}

fn validate_private_parent(path: &Path) -> Result<(), F7OfficialWalletError> {
    let parent = path.parent().ok_or(F7OfficialWalletError::Binding)?;
    let metadata = fs::symlink_metadata(parent).map_err(|_| F7OfficialWalletError::Filesystem)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(F7OfficialWalletError::Binding);
    }
    Ok(())
}

fn require_repairable_interrupted_wallet_directory(
    path: &Path,
) -> Result<(), F7OfficialWalletError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| F7OfficialWalletError::Filesystem)?;
    let parent = path.parent().ok_or(F7OfficialWalletError::Binding)?;
    let parent_metadata = fs::metadata(parent).map_err(|_| F7OfficialWalletError::Filesystem)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != parent_metadata.uid()
        || parent_metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(F7OfficialWalletError::Binding);
    }
    Ok(())
}

fn harden_new_wallet_tree(root: &Path) -> Result<(), F7OfficialWalletError> {
    walk_wallet_tree(root, true)
}

fn validate_owner_only_tree(root: &Path) -> Result<(), F7OfficialWalletError> {
    walk_wallet_tree(root, false)
}

fn walk_wallet_tree(root: &Path, harden_new: bool) -> Result<(), F7OfficialWalletError> {
    let root_metadata =
        fs::symlink_metadata(root).map_err(|_| F7OfficialWalletError::Filesystem)?;
    if !root_metadata.file_type().is_dir() || root_metadata.file_type().is_symlink() {
        return Err(F7OfficialWalletError::Binding);
    }
    let owner = root_metadata.uid();
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut count = 0_usize;
    while let Some((path, depth)) = pending.pop() {
        if depth > MAX_WALLET_TREE_DEPTH || count >= MAX_WALLET_TREE_ENTRIES {
            return Err(F7OfficialWalletError::Binding);
        }
        count += 1;
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| F7OfficialWalletError::Filesystem)?;
        if metadata.file_type().is_symlink() || metadata.uid() != owner {
            return Err(F7OfficialWalletError::Binding);
        }
        if metadata.file_type().is_dir() {
            if harden_new {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .map_err(|_| F7OfficialWalletError::Filesystem)?;
            } else if metadata.permissions().mode() & 0o777 != 0o700 {
                return Err(F7OfficialWalletError::Binding);
            }
            for entry in fs::read_dir(&path).map_err(|_| F7OfficialWalletError::Filesystem)? {
                pending.push((
                    entry.map_err(|_| F7OfficialWalletError::Filesystem)?.path(),
                    depth + 1,
                ));
            }
        } else if metadata.file_type().is_file() {
            if harden_new {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .map_err(|_| F7OfficialWalletError::Filesystem)?;
            } else if metadata.permissions().mode() & 0o777 != 0o600 {
                return Err(F7OfficialWalletError::Binding);
            }
        } else {
            return Err(F7OfficialWalletError::Binding);
        }
    }
    if harden_new {
        File::open(root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| F7OfficialWalletError::Filesystem)?;
    }
    Ok(())
}

fn persist_owner_only_secret(path: &Path, secret: &str) -> Result<(), F7OfficialWalletError> {
    validate_private_parent(path)?;
    validate_secret(secret)?;
    if path.exists() {
        return Err(F7OfficialWalletError::Binding);
    }
    let parent = path.parent().ok_or(F7OfficialWalletError::Binding)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(F7OfficialWalletError::Binding)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| F7OfficialWalletError::Filesystem)?
        .as_nanos();
    let temporary = parent.join(format!(".{name}.tmp-{}-{timestamp}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|_| F7OfficialWalletError::Filesystem)?;
    let result = (|| {
        file.write_all(secret.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(F7OfficialWalletError::Filesystem);
    }
    Ok(())
}

fn read_owner_only_secret(path: &Path) -> Result<Zeroizing<String>, F7OfficialWalletError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| F7OfficialWalletError::Filesystem)?;
    let parent = path.parent().ok_or(F7OfficialWalletError::Binding)?;
    let parent_metadata = fs::metadata(parent).map_err(|_| F7OfficialWalletError::Filesystem)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != parent_metadata.uid()
        || metadata.len() == 0
        || metadata.len() > MAX_SECRET_BYTES
    {
        return Err(F7OfficialWalletError::Binding);
    }
    let mut value = fs::read_to_string(path).map_err(|_| F7OfficialWalletError::Filesystem)?;
    while matches!(value.as_bytes().last(), Some(b'\r' | b'\n')) {
        value.pop();
    }
    validate_secret(&value)?;
    Ok(Zeroizing::new(value))
}

fn require_schema(schema_version: u16) -> Result<(), F7OfficialWalletError> {
    if schema_version == 1 {
        Ok(())
    } else {
        Err(F7OfficialWalletError::Binding)
    }
}

fn decode_hex_bounded(value: &str) -> Result<Vec<u8>, F7OfficialWalletError> {
    if value.is_empty()
        || value.len() % 2 != 0
        || value.len() as u64 > MAX_RPC_RESPONSE_BYTES.saturating_mul(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(F7OfficialWalletError::Binding);
    }
    hex::decode(value).map_err(|_| F7OfficialWalletError::Binding)
}

fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N], F7OfficialWalletError> {
    decode_hex_bounded(value)?
        .try_into()
        .map_err(|_| F7OfficialWalletError::Binding)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlateOfferResponseV1 {
    schema_version: u16,
    canonical_slate_hex: String,
    slate_id: String,
    replay_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlateFinalizeResponseV1 {
    schema_version: u16,
    canonical_tx_hex: String,
    tx_hash: String,
    pending_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlateSubmitResponseV1 {
    schema_version: u16,
    canonical_tx_hex: String,
    tx_hash: String,
    relayed: bool,
    state: String,
    already_known: bool,
    confirmed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_and_hex_are_strict() {
        assert!(validate_loopback_endpoint("http://127.0.0.1:43672").is_ok());
        assert!(validate_loopback_endpoint("http://example.com:43672").is_err());
        assert!(validate_loopback_endpoint("http://127.0.0.1:43672?token=x").is_err());
        assert_eq!(decode_hex_array::<2>("00ff").ok(), Some([0, 255]));
        assert!(decode_hex_array::<2>("00FF").is_err());
    }
}
