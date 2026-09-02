//! Authoritative G0 common-wallet path over two real embedded DOM regtest nodes.
//!
//! This test deliberately uses only the public wallet, Slate, scanner, node,
//! mempool, verifier, and miner boundaries. The wallet-owned miner is used only
//! to create Alice's recovery-capable funding coinbases. Every ordinary
//! transaction is built by the production wallet and confirmed by the
//! canonical node miner from the real mempool.

use dom_adaptor::{
    contribute_vault_backed_blinding_share_v1, open_pending_vault_backed_blinding_share_v1,
    open_vault_backed_blinding_share_v1, DirectionV1, DurableShareBackupAckCapabilityV1,
    PendingSharedBlindingBindingV1, SessionBlindingShareCapabilityV1, ShareBackupAckV1,
    SharedBlindingBindingUpgradeCapabilityV1, SharedBlindingBindingV1,
    SharedBlindingImportCapabilityV1, SharedBlindingMaterialV1,
    SharedBlindingRetirementCapabilityV1, SharedBlindingSealCapabilityV1, SharedBlindingVaultV1,
    SigningShareV1, TrustedChainIdV1,
};
use dom_consensus::Transaction;
use dom_core::{Hash256, KERNEL_FEAT_HEIGHT_LOCKED, KERNEL_FEAT_PLAIN};
use dom_crypto::{
    pedersen::{BlindingFactor, Commitment},
    recovery::{
        RecoveryCapsule, RECOVERY_CAPSULE_SIZE, RECOVERY_CIPHERTEXT_SIZE, RECOVERY_VERSION,
    },
};
use dom_serialization::DomDeserialize;
use dom_slate::CoverLockPolicyV1;
use dom_wallet_core::{
    CoreError, CoverSendDecision, FinalizedTransactionExport,
    ScriptlessFundingReservationRequestV1, ScriptlessPayoutReservationRequestV1,
    TransactionSummary, WalletService, WalletSummary, MAX_TRANSACTION_LIFETIME_BLOCKS,
};
use dom_wallet_domain::{
    ScriptlessFundingReservationState, ScriptlessPayoutReservationState, ScriptlessPayoutRoleV1,
};
use dom_wallet_embedded_core::{
    mine_wallet_block, EmbeddedCoreConfiguration, EmbeddedCoreNetwork, WalletMiningOutcome,
    MINIMUM_LMDB_MAP_SIZE_BYTES,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

const TEST_PASSWORD: &str = "g0-regtest-only-password";
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const FIRST_SEND: u64 = 1_000_000;
const RECIPIENT_SPEND: u64 = 250_000;
const COVER_SEND: u64 = 500_000;

#[derive(Debug, thiserror::Error)]
#[error("test shared-blinding vault rejected operation")]
struct TestSharedVaultError;

/// Memory-only test implementation of DOM's selected vault trait. It exists
/// solely to obtain the real opaque session capability; no share is printed,
/// serialized, or handed to Wallet V3.
#[derive(Default)]
struct TestSharedVault {
    pending: Option<PendingSharedBlindingBindingV1>,
    bound: Option<SharedBlindingBindingV1>,
    primary: Option<[u8; 32]>,
    backup: Option<[u8; 32]>,
    pending_tombstone: bool,
    bound_tombstone: bool,
}

impl SharedBlindingVaultV1 for TestSharedVault {
    type Error = TestSharedVaultError;

    fn seal_fresh_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        material: SharedBlindingMaterialV1,
        capability: SharedBlindingSealCapabilityV1,
    ) -> Result<(), Self::Error> {
        if self.pending.is_some()
            || self.bound.is_some()
            || self.primary.is_some()
            || self.backup.is_some()
            || self.pending_tombstone
        {
            return Err(TestSharedVaultError);
        }
        let plaintext = capability.into_plaintext(material);
        self.pending = Some(binding.clone());
        self.primary = Some(*plaintext);
        self.backup = Some(*plaintext);
        Ok(())
    }

    fn open_persisted_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        if self.pending.as_ref() != Some(binding) || self.pending_tombstone {
            return Err(TestSharedVaultError);
        }
        capability
            .import(Zeroizing::new(self.primary.ok_or(TestSharedVaultError)?))
            .map_err(|_| TestSharedVaultError)
    }

    fn confirm_pending_backup_roundtrip(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        if self.pending.as_ref() != Some(binding) || self.pending_tombstone {
            return Err(TestSharedVaultError);
        }
        let recovered = SigningShareV1::from_be_bytes(self.backup.ok_or(TestSharedVaultError)?)
            .map_err(|_| TestSharedVaultError)?;
        capability
            .acknowledge_pending(binding, recovered.public_key().clone())
            .map_err(|_| TestSharedVaultError)
    }

    fn bind_recovery_capsule(
        &mut self,
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
        capability: SharedBlindingBindingUpgradeCapabilityV1,
    ) -> Result<(), Self::Error> {
        capability
            .authorize_upgrade(pending, bound)
            .map_err(|_| TestSharedVaultError)?;
        if self.pending.as_ref() != Some(pending)
            || self.pending_tombstone
            || self.bound.is_some()
            || self.primary.is_none()
            || self.backup.is_none()
        {
            return Err(TestSharedVaultError);
        }
        self.bound = Some(bound.clone());
        self.pending = None;
        self.pending_tombstone = true;
        Ok(())
    }

    fn open_persisted_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        if self.bound.as_ref() != Some(binding) || self.bound_tombstone {
            return Err(TestSharedVaultError);
        }
        capability
            .import(Zeroizing::new(self.primary.ok_or(TestSharedVaultError)?))
            .map_err(|_| TestSharedVaultError)
    }

    fn confirm_backup_roundtrip(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        if self.bound.as_ref() != Some(binding) || self.bound_tombstone {
            return Err(TestSharedVaultError);
        }
        let recovered = SigningShareV1::from_be_bytes(self.backup.ok_or(TestSharedVaultError)?)
            .map_err(|_| TestSharedVaultError)?;
        capability
            .acknowledge(binding, recovered.public_key().clone())
            .map_err(|_| TestSharedVaultError)
    }

    fn retire_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        capability
            .authorize_pending(binding)
            .map_err(|_| TestSharedVaultError)?;
        Err(TestSharedVaultError)
    }

    fn retire_bound_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        capability
            .authorize_bound(binding)
            .map_err(|_| TestSharedVaultError)?;
        Err(TestSharedVaultError)
    }
}

fn public_recovery_capsule_fixture(marker: [u8; 32]) -> RecoveryCapsule {
    let mut bytes = [0u8; RECOVERY_CAPSULE_SIZE];
    bytes[..2].copy_from_slice(&RECOVERY_VERSION.to_le_bytes());
    bytes[2..14].copy_from_slice(&marker[..12]);
    bytes[14..16].copy_from_slice(&(RECOVERY_CIPHERTEXT_SIZE as u16).to_le_bytes());
    for (index, byte) in bytes[16..].iter_mut().enumerate() {
        *byte = marker[index % marker.len()];
    }
    RecoveryCapsule::from_bytes(&bytes)
        .expect("construct canonical public recovery capsule fixture")
}

fn create_session_share(
    wallet: &WalletService,
    session_id: [u8; 32],
    roster: &[[u8; 32]; 2],
    role: DirectionV1,
    participant_position: u16,
    terms_hash: [u8; 32],
    capsule_marker: [u8; 32],
    vault: &mut TestSharedVault,
) -> SessionBlindingShareCapabilityV1 {
    let identity = wallet
        .embedded_core_identity()
        .expect("read authenticated test chain identity");
    let trusted = TrustedChainIdV1::from_authenticated_genesis(
        identity.network_magic,
        &Hash256::from_bytes(identity.genesis_hash),
    );
    assert_eq!(trusted.as_bytes(), &identity.chain_id);
    let pending = contribute_vault_backed_blinding_share_v1(
        &trusted,
        session_id,
        roster,
        role,
        participant_position,
        terms_hash,
        vault,
    )
    .expect("create durable provisional DOM session share");
    pending
        .bind_recovery_capsule_v1(&public_recovery_capsule_fixture(capsule_marker), vault)
        .expect("bind durable DOM session share to the exact public recovery capsule")
}

fn ephemeral_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve a loopback test port");
    let address = listener.local_addr().expect("read loopback test port");
    drop(listener);
    address
}

fn node_configuration(
    directory: &Path,
    listen_address: SocketAddr,
    seed: Option<SocketAddr>,
) -> EmbeddedCoreConfiguration {
    let configuration =
        EmbeddedCoreConfiguration::new(EmbeddedCoreNetwork::Regtest, directory, listen_address)
            .with_maximum_inbound_peers(4)
            .with_lmdb_map_size(MINIMUM_LMDB_MAP_SIZE_BYTES);
    match seed {
        Some(seed) => configuration.with_seed_peers(vec![seed]),
        None => configuration,
    }
}

fn create_wallet(
    node_directory: &Path,
    wallet_directory: &Path,
    address: SocketAddr,
    seed: Option<SocketAddr>,
) -> WalletService {
    let mut wallet = WalletService::default();
    wallet
        .start_embedded_core(node_configuration(node_directory, address, seed))
        .expect("start real embedded DOM regtest node");
    let created = wallet
        .create_recoverable_for_embedded(wallet_directory, TEST_PASSWORD)
        .expect("create recovery-capable wallet over the embedded identity");
    drop(created.mnemonic);
    wallet
        .recovery_phrase_confirmed(TEST_PASSWORD)
        .expect("complete the mandatory recovery ceremony");
    wallet
        .unlock(TEST_PASSWORD)
        .expect("unlock newly created wallet");
    wallet
}

fn reopen_wallet(
    node_directory: &Path,
    wallet_directory: &Path,
    address: SocketAddr,
    seed: Option<SocketAddr>,
) -> WalletService {
    let mut wallet = WalletService::default();
    wallet
        .start_embedded_core(node_configuration(node_directory, address, seed))
        .expect("restart real embedded DOM regtest node");
    wallet.open(wallet_directory).expect("reopen wallet");
    wallet
        .unlock(TEST_PASSWORD)
        .expect("unlock reopened wallet");
    wallet
}

fn wait_for_height(wallet: &WalletService, expected: u64) {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        match wallet.embedded_core_identity() {
            Ok(identity) if identity.current_tip.height >= expected => return,
            Ok(_) => {}
            Err(CoreError::Backend(error)) if error.is_transient_sync_unavailability() => {}
            Err(error) => panic!("query canonical embedded identity: {error:?}"),
        }
        assert!(
            Instant::now() < deadline,
            "embedded node did not reach canonical height {expected}"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

fn wait_for_peer(wallet: &WalletService) {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        let peers = wallet
            .embedded_peer_status()
            .expect("query real peer manager");
        if peers.connected_total > 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the two embedded DOM nodes did not establish a peer session"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

fn synchronize_to_tip(label: &str, wallet: &mut WalletService) -> WalletSummary {
    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        match wallet.synchronize() {
            Ok(summary) if summary.cursor_height == summary.tip_height => return summary,
            Ok(_) => {}
            Err(CoreError::NodeNotReady) => {}
            Err(CoreError::Backend(error)) if error.is_transient_sync_unavailability() => {}
            Err(error) => panic!("{label} canonical wallet scan failed: {error:?}"),
        }
        assert!(
            Instant::now() < deadline,
            "{label} wallet scanner did not converge to the canonical tip"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

fn mine_wallet_funding_block(runtime: &Runtime, wallet: &mut WalletService) -> u64 {
    let expected_height = wallet
        .embedded_core_identity()
        .expect("query funding node tip")
        .current_tip
        .height
        + 1;
    let coinbase = wallet
        .mining_coinbase_candidate(expected_height)
        .expect("build recovery-capable funding coinbase");
    let outcome = runtime
        .block_on(mine_wallet_block(
            wallet
                .embedded_node_handle()
                .expect("obtain real embedded node"),
            &coinbase,
            1,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
        ))
        .expect("mine real regtest funding block");
    assert_eq!(
        outcome,
        WalletMiningOutcome::Accepted {
            height: expected_height
        }
    );
    expected_height
}

fn expires_after_current_tip(wallet: &WalletService) -> u64 {
    wallet
        .embedded_core_identity()
        .expect("query transaction construction tip")
        .current_tip
        .height
        + MAX_TRANSACTION_LIFETIME_BLOCKS
}

fn complete_public_slate_exchange(
    sender: &mut WalletService,
    recipient: &mut WalletService,
    created: TransactionSummary,
) -> (TransactionSummary, FinalizedTransactionExport) {
    let slate_id = created.slate_id.expect("sender transaction has a Slate id");

    let request = sender
        .slate_request_export(slate_id)
        .expect("export canonical public sender request");
    let imported = recipient
        .slate_request_import(&request.text)
        .expect("recipient validates and imports sender request");
    assert_eq!(imported.slate_id, Some(slate_id));
    recipient
        .slate_response_create(slate_id)
        .expect("recipient builds canonical output and response");
    let response = recipient
        .slate_response_export(slate_id)
        .expect("export canonical public recipient response");
    sender
        .slate_response_import(&response.text)
        .expect("sender validates and imports recipient response");

    let finalized = sender
        .transaction_finalize(slate_id)
        .expect("finalize with the production Slate verifier");
    let public_transaction = sender
        .transaction_finalized_export(slate_id)
        .expect("sender independently validates exact final bytes");
    let recipient_evidence = recipient
        .transaction_finalized_verify_and_import(slate_id, &public_transaction.canonical_bytes)
        .expect("recipient independently validates and persists exact final bytes");
    assert_eq!(
        recipient_evidence.transaction_hash,
        public_transaction.transaction_hash
    );
    assert_eq!(
        finalized.transaction_hash.as_deref(),
        Some(hex::encode(public_transaction.transaction_hash).as_str())
    );
    (finalized, public_transaction)
}

fn wait_for_mempool(
    runtime: &Runtime,
    sender: &WalletService,
    recipient: &WalletService,
    hash: [u8; 32],
) {
    let sender_node = sender
        .embedded_node_handle()
        .expect("query sender real mempool");
    let recipient_node = recipient
        .embedded_node_handle()
        .expect("query recipient real mempool");
    let deadline = Instant::now() + SYNC_TIMEOUT;
    loop {
        let sender_has =
            runtime.block_on(async { sender_node.mempool.lock().await.contains(&hash) });
        let recipient_has =
            runtime.block_on(async { recipient_node.mempool.lock().await.contains(&hash) });
        if sender_has && recipient_has {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "transaction was not observed in both real mempools before mining"
        );
        thread::sleep(POLL_INTERVAL);
    }
}

fn submit_and_mine(
    runtime: &Runtime,
    sender: &mut WalletService,
    recipient: &WalletService,
    finalized: &FinalizedTransactionExport,
) -> u64 {
    sender
        .transaction_submit(finalized.slate_id)
        .expect("submit exact bytes to the canonical DOM mempool");
    wait_for_mempool(runtime, sender, recipient, finalized.transaction_hash);
    let node = sender
        .embedded_node_handle()
        .expect("obtain canonical miner node");
    let height = runtime
        .block_on(dom_node::miner::mine_one_block(node))
        .expect("canonical node miner confirms the mempool transaction");
    wait_for_height(sender, height);
    let confirmation = sender
        .transaction_reconcile_submission(finalized.slate_id)
        .expect("query exact transaction confirmation from canonical chain evidence");
    assert_eq!(confirmation.state, "CONFIRMED");
    assert_eq!(
        confirmation.transaction_hash.as_deref(),
        Some(hex::encode(finalized.transaction_hash).as_str())
    );
    height
}

#[test]
fn g0_two_wallet_regtest_restart_recipient_spend_and_height_locked_cover() {
    let laboratory = tempfile::tempdir().expect("create isolated G0 laboratory");
    let alice_node_directory = laboratory.path().join("alice-node");
    let bob_node_directory = laboratory.path().join("bob-node");
    let alice_wallet_directory = laboratory.path().join("alice-wallet");
    let bob_wallet_directory = laboratory.path().join("bob-wallet");
    let alice_address = ephemeral_address();
    let bob_address = ephemeral_address();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test control runtime");

    let mut alice = create_wallet(
        &alice_node_directory,
        &alice_wallet_directory,
        alice_address,
        None,
    );
    let mut bob = create_wallet(
        &bob_node_directory,
        &bob_wallet_directory,
        bob_address,
        Some(alice_address),
    );
    wait_for_peer(&alice);
    wait_for_peer(&bob);

    // Two wallet-owned blocks fund Alice and mature the first real coinbase.
    let first_height = mine_wallet_funding_block(&runtime, &mut alice);
    wait_for_height(&bob, first_height);
    let second_height = mine_wallet_funding_block(&runtime, &mut alice);
    wait_for_height(&bob, second_height);
    let alice_funded = synchronize_to_tip("Alice after funding", &mut alice);
    let bob_empty = synchronize_to_tip("Bob after funding", &mut bob);
    assert!(alice_funded.balance.spendable >= FIRST_SEND);
    assert_eq!(bob_empty.balance.total, 0);

    // Ordinary 1-to-1 send through the public wallet and Slate APIs.
    let plain_created = alice
        .transaction_send_create(FIRST_SEND, None, expires_after_current_tip(&alice))
        .expect("Alice selects real coins and creates the ordinary send");
    let plain_fee = plain_created.fee;
    let (_, plain_final) = complete_public_slate_exchange(&mut alice, &mut bob, plain_created);
    let plain_tx = Transaction::from_bytes(&plain_final.canonical_bytes)
        .expect("decode canonical finalized transaction");
    assert_eq!(plain_tx.kernels.len(), 1);
    assert_eq!(plain_tx.kernels[0].features, KERNEL_FEAT_PLAIN);
    assert_eq!(plain_tx.kernels[0].lock_height, 0);
    let plain_height = submit_and_mine(&runtime, &mut alice, &bob, &plain_final);
    wait_for_height(&bob, plain_height);
    let alice_after_plain = synchronize_to_tip("Alice after plain send", &mut alice);
    let bob_after_plain = synchronize_to_tip("Bob after plain send", &mut bob);
    assert_eq!(bob_after_plain.balance.spendable, FIRST_SEND);
    assert_eq!(
        alice_after_plain.balance.total,
        alice_funded.balance.total - FIRST_SEND - plain_fee
    );
    let alice_restart_transactions = alice
        .transaction_list()
        .expect("snapshot Alice public transaction state");
    let bob_restart_transactions = bob
        .transaction_list()
        .expect("snapshot Bob public transaction state");

    // Full node and wallet restart, followed by a genesis rescan, must recover
    // the same ownership and balances from canonical chain evidence.
    let alice_restart_balance = alice_after_plain.balance.clone();
    let bob_restart_balance = bob_after_plain.balance.clone();
    bob.close().expect("close Bob wallet and node cleanly");
    alice.close().expect("close Alice wallet and node cleanly");

    let mut alice = reopen_wallet(
        &alice_node_directory,
        &alice_wallet_directory,
        alice_address,
        None,
    );
    let mut bob = reopen_wallet(
        &bob_node_directory,
        &bob_wallet_directory,
        bob_address,
        Some(alice_address),
    );
    wait_for_peer(&alice);
    wait_for_peer(&bob);
    wait_for_height(&alice, plain_height);
    wait_for_height(&bob, plain_height);
    let alice_rescanned = alice
        .rescan_from_genesis()
        .expect("Alice reconstructs from canonical chain evidence");
    let bob_rescanned = bob
        .rescan_from_genesis()
        .expect("Bob reconstructs from canonical chain evidence");
    assert_eq!(alice_rescanned.balance, alice_restart_balance);
    assert_eq!(bob_rescanned.balance, bob_restart_balance);
    assert_eq!(
        alice
            .transaction_list()
            .expect("read restarted Alice transaction state"),
        alice_restart_transactions
    );
    assert_eq!(
        bob.transaction_list()
            .expect("read restarted Bob transaction state"),
        bob_restart_transactions
    );

    // Bob spending part of the recovered recipient output is the ownership
    // proof; no test-only spend key or miner transaction builder is used.
    let bob_spend = bob
        .transaction_send_create(RECIPIENT_SPEND, None, expires_after_current_tip(&bob))
        .expect("Bob spends the scanned recipient output");
    let bob_spend_fee = bob_spend.fee;
    let (_, bob_spend_final) = complete_public_slate_exchange(&mut bob, &mut alice, bob_spend);
    let bob_spend_height = submit_and_mine(&runtime, &mut bob, &alice, &bob_spend_final);
    wait_for_height(&alice, bob_spend_height);
    let bob_after_spend = synchronize_to_tip("Bob after recipient spend", &mut bob);
    let alice_after_bob_spend = synchronize_to_tip("Alice after recipient spend", &mut alice);
    assert_eq!(
        bob_after_spend.balance.spendable,
        FIRST_SEND - RECIPIENT_SPEND - bob_spend_fee
    );
    assert!(alice_after_bob_spend.balance.spendable >= RECIPIENT_SPEND);

    // R0/G-COVER: 100% test participation ensures this transaction exercises
    // the production HEIGHT_LOCKED builder at a CSPRNG-selected already-valid
    // public lookback height. It is still an ordinary wallet transaction.
    let cover_policy = CoverLockPolicyV1::new(8, 1_000).expect("valid R0 test policy");
    let cover_result = alice
        .transaction_send_create_with_cover(
            COVER_SEND,
            None,
            expires_after_current_tip(&alice),
            cover_policy,
        )
        .expect("construct ordinary HEIGHT_LOCKED cover send");
    let lock_height = match cover_result.decision {
        CoverSendDecision::HeightLocked { lock_height } => lock_height,
        decision => panic!("full-participation R0 produced unexpected decision: {decision:?}"),
    };
    let construction_tip = alice
        .embedded_core_identity()
        .expect("query cover construction tip")
        .current_tip
        .height;
    assert!((1..=construction_tip).contains(&lock_height));
    let (_, cover_final) =
        complete_public_slate_exchange(&mut alice, &mut bob, cover_result.transaction);
    let cover_tx = Transaction::from_bytes(&cover_final.canonical_bytes)
        .expect("decode canonical HEIGHT_LOCKED transaction");
    assert_eq!(cover_tx.kernels.len(), 1);
    assert_eq!(cover_tx.kernels[0].features, KERNEL_FEAT_HEIGHT_LOCKED);
    assert_eq!(cover_tx.kernels[0].lock_height, lock_height);
    let cover_height = submit_and_mine(&runtime, &mut alice, &bob, &cover_final);
    wait_for_height(&bob, cover_height);
    let alice_final = synchronize_to_tip("Alice after cover send", &mut alice);
    let bob_final = synchronize_to_tip("Bob after cover send", &mut bob);
    assert_eq!(alice_final.cursor_height, Some(cover_height));
    assert_eq!(bob_final.cursor_height, Some(cover_height));
    assert!(bob_final.balance.spendable >= COVER_SEND);

    // Emit only reproducible public evidence. The test never prints mnemonic,
    // wallet password, output blinding, nonce, or node Noise key material.
    let executable = std::env::current_exe().expect("resolve G0 test executable");
    let binary_sha256 = Sha256::digest(fs::read(executable).expect("hash G0 test executable"));
    let chain_id = alice
        .embedded_core_identity()
        .expect("read public G0 chain identity")
        .chain_id;
    println!("G0_PUBLIC_EVIDENCE_BEGIN");
    println!("wallet_base_commit=1868e61bc39eca223d794348d70e48668ad06708");
    println!("dom_protocol_commit=6a295fddf4e6a3afd6cf0f3fdb1e3a636a2f3d71");
    println!("network=regtest");
    println!("chain_id={}", hex::encode(chain_id));
    println!("test_binary_sha256={}", hex::encode(binary_sha256));
    println!("plain_txid={}", hex::encode(plain_final.transaction_hash));
    println!(
        "plain_tx_bytes={}",
        hex::encode(&plain_final.canonical_bytes)
    );
    println!("plain_inclusion_height={plain_height}");
    println!("plain_sender_fee={plain_fee}");
    println!("plain_receiver_value={}", bob_after_plain.balance.spendable);
    println!("restart_rescan_match=true");
    println!(
        "recipient_spend_txid={}",
        hex::encode(bob_spend_final.transaction_hash)
    );
    println!(
        "recipient_spend_tx_bytes={}",
        hex::encode(&bob_spend_final.canonical_bytes)
    );
    println!("recipient_spend_inclusion_height={bob_spend_height}");
    println!("cover_txid={}", hex::encode(cover_final.transaction_hash));
    println!(
        "cover_tx_bytes={}",
        hex::encode(&cover_final.canonical_bytes)
    );
    println!("cover_lock_height={lock_height}");
    println!("cover_inclusion_height={cover_height}");
    println!("scriptless_or_dl2p_fields=0");
    println!("G0_PUBLIC_EVIDENCE_END");

    bob.close().expect("close Bob G0 laboratory cleanly");
    alice.close().expect("close Alice G0 laboratory cleanly");
}

#[test]
fn f7_common_wallet_reservation_is_restart_safe_idempotent_and_fail_closed() {
    let laboratory = tempfile::tempdir().expect("create isolated F7 wallet laboratory");
    let node_directory = laboratory.path().join("node");
    let wallet_directory = laboratory.path().join("wallet");
    let zero_node_directory = laboratory.path().join("zero-node");
    let zero_wallet_directory = laboratory.path().join("zero-wallet");
    let address = ephemeral_address();
    let zero_address = ephemeral_address();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test control runtime");
    let mut wallet = create_wallet(&node_directory, &wallet_directory, address, None);
    let mut zero_signer = create_wallet(
        &zero_node_directory,
        &zero_wallet_directory,
        zero_address,
        Some(address),
    );
    wait_for_peer(&wallet);
    wait_for_peer(&zero_signer);

    // Fund and mature one real recovery-capable output. The reservation API
    // then uses the production spendable-output projection and Core fee policy.
    let first_height = mine_wallet_funding_block(&runtime, &mut wallet);
    wait_for_height(&zero_signer, first_height);
    let second_height = mine_wallet_funding_block(&runtime, &mut wallet);
    wait_for_height(&zero_signer, second_height);
    let funded = synchronize_to_tip("F7 wallet after funding", &mut wallet);
    let zero_balance = synchronize_to_tip("F7 zero-debit signer", &mut zero_signer).balance;
    let change_margin = 1_000_000u64;
    let shared_value = funded
        .balance
        .spendable
        .checked_sub(change_margin)
        .expect("real funding output exceeds the change margin");
    let preflight = wallet
        .preflight_funding(shared_value)
        .expect("calculate real wallet selection and node fee");
    assert!(preflight.fundable);
    assert!(preflight.estimated_fee < change_margin);
    let local_debit_noms = shared_value
        .checked_add(preflight.estimated_fee)
        .expect("bounded test debit");
    let shared_output_blinding = BlindingFactor::from_bytes([0x30; 32]).unwrap();
    let shared_output_commitment =
        *Commitment::commit(shared_value, &shared_output_blinding).as_bytes();
    let first_request = ScriptlessFundingReservationRequestV1 {
        session_id: [0x41; 32],
        shared_output_commitment,
        local_debit_noms,
        funding_fee_noms: preflight.estimated_fee,
        expected_input_count: preflight.selected_input_count,
        expected_output_count: 2,
    };

    // Same-session retry resolves to the same durable reservation, never a
    // second coin selection. Before exposure it can still be cancelled safely.
    let first = wallet
        .scriptless_funding_prepare(first_request)
        .expect("prepare exact common-wallet funding components");
    assert_eq!(first.state, ScriptlessFundingReservationState::Prepared);
    let mut competing_writer = WalletService::default();
    let writer_error = competing_writer
        .open(&wallet_directory)
        .expect_err("a second process must not bypass the active wallet writer lock");
    assert_eq!(writer_error.redacted_code(), "WALLET_WRITER_ACTIVE");
    let conflicting_request = ScriptlessFundingReservationRequestV1 {
        local_debit_noms: first_request.local_debit_noms - 1,
        ..first_request
    };
    assert!(matches!(
        wallet.scriptless_funding_prepare(conflicting_request),
        Err(CoreError::ScriptlessFundingSessionConflict)
    ));
    let different_shared_blinding = BlindingFactor::from_bytes([0x32; 32]).unwrap();
    let different_shared_commitment =
        *Commitment::commit(shared_value, &different_shared_blinding).as_bytes();
    assert!(matches!(
        wallet.scriptless_funding_prepare(ScriptlessFundingReservationRequestV1 {
            shared_output_commitment: different_shared_commitment,
            ..first_request
        }),
        Err(CoreError::ScriptlessFundingSessionConflict)
    ));
    let retried = wallet
        .scriptless_funding_prepare(first_request)
        .expect("idempotently resume the same session");
    assert_eq!(retried, first);
    let cancelled = wallet
        .scriptless_funding_cancel_unexposed(first.reservation_id)
        .expect("release an unexposed reservation");
    assert_eq!(
        cancelled.state,
        ScriptlessFundingReservationState::Cancelled
    );
    assert_eq!(
        wallet.summary().expect("read released balance").balance,
        funded.balance
    );

    // Re-reserve under a distinct session and expose exact public components.
    // Export is byte/object-identical, while another session cannot select the
    // same only-mature output.
    let exposed_request = ScriptlessFundingReservationRequestV1 {
        session_id: [0x42; 32],
        ..first_request
    };
    let exposed = wallet
        .scriptless_funding_prepare(exposed_request)
        .expect("prepare exposed F7 reservation");
    let zero_request = ScriptlessFundingReservationRequestV1 {
        local_debit_noms: 0,
        ..exposed_request
    };
    let explicit_local_zero = zero_signer
        .scriptless_funding_prepare(ScriptlessFundingReservationRequestV1 {
            session_id: [0x44; 32],
            expected_input_count: 0,
            ..zero_request
        })
        .expect("prepare an explicit local no-input description");
    assert_eq!(explicit_local_zero.selected_input_count, 0);
    assert_eq!(
        zero_signer
            .scriptless_funding_cancel_unexposed(explicit_local_zero.reservation_id)
            .expect("cancel the unexposed local no-input description")
            .state,
        ScriptlessFundingReservationState::Cancelled
    );
    let zero = zero_signer
        .scriptless_funding_prepare(zero_request)
        .expect("prepare no-input signer contribution for the same funding session");
    let roster = [[0x11; 32], [0x22; 32]];
    let terms_hash = [0x71; 32];
    let capsule_hash = [0x72; 32];
    let mut funding_vault = TestSharedVault::default();
    let mut zero_funding_vault = TestSharedVault::default();
    let funding_share = create_session_share(
        &wallet,
        exposed_request.session_id,
        &roster,
        DirectionV1::Initiator,
        0,
        terms_hash,
        capsule_hash,
        &mut funding_vault,
    );
    let zero_funding_share = create_session_share(
        &zero_signer,
        exposed_request.session_id,
        &roster,
        DirectionV1::Responder,
        1,
        terms_hash,
        capsule_hash,
        &mut zero_funding_vault,
    );
    let funding_kernel_point = wallet
        .scriptless_funding_prepare_kernel_excess_point(exposed.reservation_id, &funding_share)
        .expect("persist session binding before returning funding kernel point");
    let zero_funding_kernel_point = zero_signer
        .scriptless_funding_prepare_kernel_excess_point(zero.reservation_id, &zero_funding_share)
        .expect("persist no-input signer binding before returning its kernel point");
    assert_ne!(funding_kernel_point, zero_funding_kernel_point);
    assert_eq!(
        wallet
            .scriptless_funding_status(exposed.reservation_id)
            .unwrap()
            .state,
        ScriptlessFundingReservationState::SessionBound
    );
    assert!(matches!(
        wallet.scriptless_funding_signing_capability(exposed.reservation_id),
        Err(CoreError::ScriptlessFundingSigningNotAuthorized)
    ));

    // Rebind the same test-only share point under a binding that differs only
    // in terms_hash. Wallet V3 must compare DOM's complete binding digest and
    // reject it before returning another point.
    let funding_binding = funding_share.binding().clone();
    let zero_funding_binding = zero_funding_share.binding().clone();
    let identity = wallet.embedded_core_identity().unwrap();
    let trusted = TrustedChainIdV1::from_authenticated_genesis(
        identity.network_magic,
        &Hash256::from_bytes(identity.genesis_hash),
    );
    let altered_pending_binding = PendingSharedBlindingBindingV1::new(
        &trusted,
        exposed_request.session_id,
        &roster,
        DirectionV1::Initiator,
        0,
        [0x73; 32],
        funding_share.public_key().clone(),
    )
    .expect("construct public negative-test binding");
    let mut altered_vault = TestSharedVault {
        pending: Some(altered_pending_binding.clone()),
        bound: None,
        primary: funding_vault.primary,
        backup: funding_vault.backup,
        pending_tombstone: false,
        bound_tombstone: false,
    };
    let altered_pending =
        open_pending_vault_backed_blinding_share_v1(altered_pending_binding, &mut altered_vault)
            .expect("rehydrate the same provisional test share under altered public terms");
    let altered_share = altered_pending
        .bind_recovery_capsule_v1(
            &public_recovery_capsule_fixture(capsule_hash),
            &mut altered_vault,
        )
        .expect("bind the altered-terms share to the same public capsule");
    assert!(matches!(
        wallet.scriptless_funding_prepare_kernel_excess_point(
            exposed.reservation_id,
            &altered_share,
        ),
        Err(CoreError::ScriptlessSessionBindingMismatch)
    ));
    let composition = wallet
        .scriptless_funding_export(exposed.reservation_id)
        .expect("persist exposure before returning public components");
    let zero_composition = zero_signer
        .scriptless_funding_export(zero.reservation_id)
        .expect("export exact zero-debit signer contribution");
    assert_eq!(
        composition.inputs.len(),
        exposed.selected_input_count as usize
    );
    assert_eq!(composition.other_outputs.len(), 1);
    assert!(zero_composition.inputs.is_empty());
    assert!(zero_composition.other_outputs.is_empty());
    assert_eq!(zero.selected_input_count, 0);
    assert!(!zero.has_change);
    assert_eq!(
        composition.inputs.len() + zero_composition.inputs.len(),
        exposed_request.expected_input_count as usize
    );
    assert_eq!(
        composition.other_outputs.len() + zero_composition.other_outputs.len() + 1,
        exposed_request.expected_output_count as usize
    );
    assert_eq!(
        exposed_request.local_debit_noms + zero_request.local_debit_noms,
        shared_value + exposed_request.funding_fee_noms
    );
    assert_eq!(
        zero_signer.summary().expect("zero signer balance").balance,
        zero_balance
    );
    assert_eq!(
        composition.chain_id,
        wallet.embedded_core_identity().unwrap().chain_id
    );
    assert_eq!(
        composition.shared_output_commitment,
        shared_output_commitment
    );
    assert_eq!(
        zero_composition.shared_output_commitment,
        shared_output_commitment
    );
    assert_eq!(
        wallet
            .scriptless_funding_export(exposed.reservation_id)
            .expect("retransmit identical public components"),
        composition
    );
    assert!(matches!(
        wallet.scriptless_funding_cancel_unexposed(exposed.reservation_id),
        Err(CoreError::ScriptlessFundingCannotRelease)
    ));
    let competing_request = ScriptlessFundingReservationRequestV1 {
        session_id: [0x43; 32],
        ..exposed_request
    };
    assert!(matches!(
        wallet.scriptless_funding_prepare(competing_request),
        Err(CoreError::InsufficientFunds)
    ));

    // Restart reconstructs the same canonical objects and the same opaque
    // public key from encrypted context. A whole-history real scanner replay
    // then removes and rediscovers the source output under its scanner-local
    // UUID; the reservation follows the canonical commitment before the batch
    // is committed and remains unavailable to ordinary coin selection.
    drop(altered_share);
    drop(funding_share);
    drop(zero_funding_share);
    zero_signer
        .close()
        .expect("close zero-debit signer and node");
    wallet.close().expect("close F7 wallet and node");
    let mut wallet = reopen_wallet(&node_directory, &wallet_directory, address, None);
    let mut zero_signer = reopen_wallet(
        &zero_node_directory,
        &zero_wallet_directory,
        zero_address,
        Some(address),
    );
    wait_for_peer(&wallet);
    wait_for_peer(&zero_signer);
    wait_for_height(
        &wallet,
        funded.tip_height.expect("funding tip must be known"),
    );
    let funding_share = open_vault_backed_blinding_share_v1(funding_binding, &mut funding_vault)
        .expect("rehydrate exact funding share after wallet restart");
    let zero_funding_share =
        open_vault_backed_blinding_share_v1(zero_funding_binding, &mut zero_funding_vault)
            .expect("rehydrate exact no-input funding share after wallet restart");
    assert_eq!(
        wallet
            .scriptless_funding_prepare_kernel_excess_point(exposed.reservation_id, &funding_share,)
            .expect("restart returns identical funding kernel point"),
        funding_kernel_point
    );
    assert_eq!(
        zero_signer
            .scriptless_funding_prepare_kernel_excess_point(
                zero.reservation_id,
                &zero_funding_share,
            )
            .expect("restart returns identical no-input signer kernel point"),
        zero_funding_kernel_point
    );
    assert_eq!(
        wallet
            .scriptless_funding_export(exposed.reservation_id)
            .expect("restart retransmission is byte-identical"),
        composition
    );
    assert!(matches!(
        wallet.scriptless_funding_signing_capability(exposed.reservation_id),
        Err(CoreError::ScriptlessFundingSigningNotAuthorized)
    ));
    assert_eq!(
        zero_signer
            .scriptless_funding_export(zero.reservation_id)
            .expect("restart zero-debit contribution is byte-identical"),
        zero_composition
    );
    wallet
        .rescan_from_genesis()
        .expect("real scanner replay preserves the exposed funding reservation");
    zero_signer
        .rescan_from_genesis()
        .expect("real scanner replay preserves no-input signer contribution");
    assert_eq!(
        wallet
            .scriptless_funding_export(exposed.reservation_id)
            .expect("post-rescan retransmission is byte-identical"),
        composition
    );
    assert_eq!(
        wallet
            .scriptless_funding_prepare_kernel_excess_point(exposed.reservation_id, &funding_share,)
            .expect("post-rescan funding kernel point is identical"),
        funding_kernel_point
    );
    assert_eq!(
        zero_signer
            .scriptless_funding_prepare_kernel_excess_point(
                zero.reservation_id,
                &zero_funding_share,
            )
            .expect("post-rescan no-input signer kernel point is identical"),
        zero_funding_kernel_point
    );
    assert!(matches!(
        wallet.scriptless_funding_prepare(competing_request),
        Err(CoreError::InsufficientFunds)
    ));
    assert_eq!(
        zero_signer
            .summary()
            .expect("rescanned zero signer")
            .balance,
        zero_balance
    );

    // Operator abandonment is intentionally not a release authority.
    let abandoned = wallet
        .scriptless_funding_abandon_exposed(exposed.reservation_id)
        .expect("mark exposure abandoned without releasing inputs");
    assert_eq!(
        abandoned.state,
        ScriptlessFundingReservationState::AbandonedRetained
    );
    assert!(matches!(
        wallet.scriptless_funding_prepare(competing_request),
        Err(CoreError::InsufficientFunds)
    ));
    assert_eq!(
        zero_signer
            .scriptless_funding_abandon_exposed(zero.reservation_id)
            .expect("retain exposed no-input signer contribution")
            .state,
        ScriptlessFundingReservationState::AbandonedRetained
    );
    zero_signer
        .close()
        .expect("close zero-debit signer laboratory cleanly");
    wallet.close().expect("close F7 wallet laboratory cleanly");
}

#[test]
fn f7_scriptless_payouts_are_distinct_restart_safe_and_fail_closed() {
    let laboratory = tempfile::tempdir().expect("create isolated F7 payout laboratory");
    let node_directory = laboratory.path().join("node");
    let wallet_directory = laboratory.path().join("wallet");
    let zero_node_directory = laboratory.path().join("zero-node");
    let zero_wallet_directory = laboratory.path().join("zero-wallet");
    let address = ephemeral_address();
    let zero_address = ephemeral_address();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build payout test control runtime");
    let mut wallet = create_wallet(&node_directory, &wallet_directory, address, None);
    let mut zero_signer = create_wallet(
        &zero_node_directory,
        &zero_wallet_directory,
        zero_address,
        Some(address),
    );
    wait_for_peer(&wallet);
    wait_for_peer(&zero_signer);
    let height = mine_wallet_funding_block(&runtime, &mut wallet);
    wait_for_height(&zero_signer, height);
    synchronize_to_tip("F7 payout wallet", &mut wallet);
    let zero_balance = synchronize_to_tip("F7 payout no-output signer", &mut zero_signer).balance;

    // This is a public test-fixture commitment, not a wallet secret. The
    // common-wallet payout API validates it as a real DOM commitment but never
    // receives or reconstructs the collaborative shared-output blinding.
    let fixture_blinding = BlindingFactor::from_bytes([0x31; 32]).unwrap();
    let shared_value = 11_000_000;
    let shared_output_commitment = *Commitment::commit(shared_value, &fixture_blinding).as_bytes();
    let claim_request = ScriptlessPayoutReservationRequestV1 {
        session_id: [0x51; 32],
        role: ScriptlessPayoutRoleV1::Claim,
        shared_output_commitment,
        payout_value_noms: 1_000_000,
        kernel_fee_noms: 10_000_000,
        expected_output_count: 1,
        refund_lock_height: 0,
    };
    let refund_request = ScriptlessPayoutReservationRequestV1 {
        role: ScriptlessPayoutRoleV1::Refund,
        refund_lock_height: height + 10,
        ..claim_request
    };

    let claim = wallet
        .scriptless_payout_prepare(claim_request)
        .expect("prepare recoverable Claim payout");
    let refund = wallet
        .scriptless_payout_prepare(refund_request)
        .expect("prepare distinct recoverable Refund payout");
    let zero_claim_request = ScriptlessPayoutReservationRequestV1 {
        payout_value_noms: 0,
        ..claim_request
    };
    let zero_refund_request = ScriptlessPayoutReservationRequestV1 {
        payout_value_noms: 0,
        ..refund_request
    };
    let zero_claim = zero_signer
        .scriptless_payout_prepare(zero_claim_request)
        .expect("prepare Claim no-output signer contribution");
    let zero_refund = zero_signer
        .scriptless_payout_prepare(zero_refund_request)
        .expect("prepare Refund no-output signer contribution");
    assert_eq!(claim.state, ScriptlessPayoutReservationState::Prepared);
    assert_eq!(refund.state, ScriptlessPayoutReservationState::Prepared);
    assert_ne!(claim.reservation_id, refund.reservation_id);
    assert_eq!(
        wallet
            .scriptless_payout_prepare(claim_request)
            .expect("same Claim request resumes idempotently"),
        claim
    );
    assert!(matches!(
        wallet.scriptless_payout_prepare(ScriptlessPayoutReservationRequestV1 {
            payout_value_noms: claim_request.payout_value_noms - 1,
            ..claim_request
        }),
        Err(CoreError::ScriptlessPayoutSessionConflict)
    ));

    // A separate unexposed attempt can be cancelled, while its coordinate
    // stays burned in the durable tombstone.
    let cancellable = wallet
        .scriptless_payout_prepare(ScriptlessPayoutReservationRequestV1 {
            session_id: [0x52; 32],
            ..claim_request
        })
        .expect("prepare cancellable payout");
    assert_eq!(
        wallet
            .scriptless_payout_cancel_unexposed(cancellable.reservation_id)
            .expect("cancel only before component exposure")
            .state,
        ScriptlessPayoutReservationState::Cancelled
    );
    assert_eq!(
        wallet
            .scriptless_payout_prepare(ScriptlessPayoutReservationRequestV1 {
                session_id: [0x52; 32],
                ..claim_request
            })
            .expect("cancelled payout retry returns its retained tombstone")
            .state,
        ScriptlessPayoutReservationState::Cancelled
    );

    let roster = [[0x31; 32], [0x32; 32]];
    let terms_hash = [0x81; 32];
    let capsule_hash = [0x82; 32];
    let mut payout_vault = TestSharedVault::default();
    let mut zero_payout_vault = TestSharedVault::default();
    let payout_share = create_session_share(
        &wallet,
        claim_request.session_id,
        &roster,
        DirectionV1::Initiator,
        0,
        terms_hash,
        capsule_hash,
        &mut payout_vault,
    );
    let zero_payout_share = create_session_share(
        &zero_signer,
        claim_request.session_id,
        &roster,
        DirectionV1::Responder,
        1,
        terms_hash,
        capsule_hash,
        &mut zero_payout_vault,
    );
    let claim_kernel_point = wallet
        .scriptless_payout_prepare_kernel_excess_point(claim.reservation_id, &payout_share)
        .expect("persist Claim session binding before returning its kernel point");
    let refund_kernel_point = wallet
        .scriptless_payout_prepare_kernel_excess_point(refund.reservation_id, &payout_share)
        .expect("persist Refund session binding before returning its kernel point");
    let zero_claim_kernel_point = zero_signer
        .scriptless_payout_prepare_kernel_excess_point(
            zero_claim.reservation_id,
            &zero_payout_share,
        )
        .expect("persist no-output Claim signer binding before returning its kernel point");
    let zero_refund_kernel_point = zero_signer
        .scriptless_payout_prepare_kernel_excess_point(
            zero_refund.reservation_id,
            &zero_payout_share,
        )
        .expect("persist no-output Refund signer binding before returning its kernel point");
    assert_ne!(claim_kernel_point, refund_kernel_point);
    assert_ne!(zero_claim_kernel_point, zero_refund_kernel_point);
    assert_eq!(
        wallet
            .scriptless_payout_status(claim.reservation_id)
            .unwrap()
            .state,
        ScriptlessPayoutReservationState::SessionBound
    );
    assert!(matches!(
        wallet.scriptless_payout_signing_capability(claim.reservation_id),
        Err(CoreError::ScriptlessPayoutSigningNotAuthorized)
    ));
    let payout_binding = payout_share.binding().clone();
    let zero_payout_binding = zero_payout_share.binding().clone();

    let claim_components = wallet
        .scriptless_payout_export(claim.reservation_id)
        .expect("persist and export exact Claim components");
    let refund_components = wallet
        .scriptless_payout_export(refund.reservation_id)
        .expect("persist and export exact Refund components");
    let zero_claim_components = zero_signer
        .scriptless_payout_export(zero_claim.reservation_id)
        .expect("export Claim no-output signer contribution");
    let zero_refund_components = zero_signer
        .scriptless_payout_export(zero_refund.reservation_id)
        .expect("export Refund no-output signer contribution");
    assert_eq!(claim_components.role, ScriptlessPayoutRoleV1::Claim);
    assert_eq!(refund_components.role, ScriptlessPayoutRoleV1::Refund);
    assert_eq!(claim_components.refund_lock_height, 0);
    assert_eq!(refund_components.refund_lock_height, height + 10);
    assert_eq!(claim_components.outputs.len(), 1);
    assert_eq!(refund_components.outputs.len(), 1);
    assert!(zero_claim_components.outputs.is_empty());
    assert!(zero_refund_components.outputs.is_empty());
    assert_eq!(
        claim_components.outputs.len() + zero_claim_components.outputs.len(),
        claim_request.expected_output_count as usize
    );
    assert_eq!(
        refund_components.outputs.len() + zero_refund_components.outputs.len(),
        refund_request.expected_output_count as usize
    );
    assert_eq!(
        claim_request.payout_value_noms
            + zero_claim_request.payout_value_noms
            + claim_request.kernel_fee_noms,
        shared_value
    );
    assert_eq!(
        refund_request.payout_value_noms
            + zero_refund_request.payout_value_noms
            + refund_request.kernel_fee_noms,
        shared_value
    );
    assert_ne!(
        claim_components.outputs[0].commitment,
        refund_components.outputs[0].commitment
    );
    assert_ne!(
        claim_components.offset_contribution,
        refund_components.offset_contribution
    );
    assert_ne!(
        zero_claim_components.offset_contribution,
        zero_refund_components.offset_contribution
    );
    assert_ne!(
        zero_claim_components.payout_excess_public_key,
        zero_refund_components.payout_excess_public_key
    );
    assert!(claim_components.outputs[0]
        .recovery_capsule()
        .unwrap()
        .is_some());
    assert!(refund_components.outputs[0]
        .recovery_capsule()
        .unwrap()
        .is_some());
    assert_eq!(
        wallet
            .scriptless_payout_export(claim.reservation_id)
            .expect("Claim retransmission is exact"),
        claim_components
    );
    assert_eq!(
        wallet
            .scriptless_payout_export(refund.reservation_id)
            .expect("Refund retransmission is exact"),
        refund_components
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_export(zero_claim.reservation_id)
            .expect("Claim no-output retransmission is exact"),
        zero_claim_components
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_export(zero_refund.reservation_id)
            .expect("Refund no-output retransmission is exact"),
        zero_refund_components
    );
    assert_eq!(
        zero_signer
            .summary()
            .expect("no-output signer balance")
            .balance,
        zero_balance
    );
    assert!(matches!(
        wallet.scriptless_payout_cancel_unexposed(claim.reservation_id),
        Err(CoreError::ScriptlessPayoutCannotRelease)
    ));

    drop(payout_share);
    drop(zero_payout_share);
    zero_signer
        .close()
        .expect("close no-output signer before restart");
    wallet.close().expect("close payout wallet before restart");
    let mut wallet = reopen_wallet(&node_directory, &wallet_directory, address, None);
    let mut zero_signer = reopen_wallet(
        &zero_node_directory,
        &zero_wallet_directory,
        zero_address,
        Some(address),
    );
    wait_for_peer(&wallet);
    wait_for_peer(&zero_signer);
    wait_for_height(&wallet, height);
    let payout_share = open_vault_backed_blinding_share_v1(payout_binding, &mut payout_vault)
        .expect("rehydrate exact payout share after wallet restart");
    let zero_payout_share =
        open_vault_backed_blinding_share_v1(zero_payout_binding, &mut zero_payout_vault)
            .expect("rehydrate exact no-output payout share after wallet restart");
    assert_eq!(
        wallet
            .scriptless_payout_prepare_kernel_excess_point(claim.reservation_id, &payout_share)
            .expect("restart returns identical Claim kernel point"),
        claim_kernel_point
    );
    assert_eq!(
        wallet
            .scriptless_payout_prepare_kernel_excess_point(refund.reservation_id, &payout_share)
            .expect("restart returns identical Refund kernel point"),
        refund_kernel_point
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_prepare_kernel_excess_point(
                zero_claim.reservation_id,
                &zero_payout_share,
            )
            .expect("restart returns identical no-output Claim kernel point"),
        zero_claim_kernel_point
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_prepare_kernel_excess_point(
                zero_refund.reservation_id,
                &zero_payout_share,
            )
            .expect("restart returns identical no-output Refund kernel point"),
        zero_refund_kernel_point
    );
    assert_eq!(
        wallet
            .scriptless_payout_export(claim.reservation_id)
            .expect("restart returns identical Claim components"),
        claim_components
    );
    assert_eq!(
        wallet
            .scriptless_payout_export(refund.reservation_id)
            .expect("restart returns identical Refund components"),
        refund_components
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_export(zero_claim.reservation_id)
            .expect("restart returns identical Claim no-output contribution"),
        zero_claim_components
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_export(zero_refund.reservation_id)
            .expect("restart returns identical Refund no-output contribution"),
        zero_refund_components
    );
    wallet
        .rescan_from_genesis()
        .expect("real whole-history scan preserves payout reservations");
    zero_signer
        .rescan_from_genesis()
        .expect("real whole-history scan preserves no-output contributions");
    assert_eq!(
        wallet
            .scriptless_payout_export(claim.reservation_id)
            .expect("post-rescan Claim retransmission is exact"),
        claim_components
    );
    assert_eq!(
        wallet
            .scriptless_payout_export(refund.reservation_id)
            .expect("post-rescan Refund retransmission is exact"),
        refund_components
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_export(zero_claim.reservation_id)
            .expect("post-rescan Claim no-output retransmission is exact"),
        zero_claim_components
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_export(zero_refund.reservation_id)
            .expect("post-rescan Refund no-output retransmission is exact"),
        zero_refund_components
    );
    assert_eq!(
        wallet
            .scriptless_payout_prepare_kernel_excess_point(claim.reservation_id, &payout_share)
            .expect("post-rescan Claim kernel point is identical"),
        claim_kernel_point
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_prepare_kernel_excess_point(
                zero_claim.reservation_id,
                &zero_payout_share,
            )
            .expect("post-rescan no-output Claim kernel point is identical"),
        zero_claim_kernel_point
    );
    assert_eq!(
        zero_signer
            .summary()
            .expect("rescanned no-output signer")
            .balance,
        zero_balance
    );

    assert_eq!(
        wallet
            .scriptless_payout_abandon_exposed(claim.reservation_id)
            .expect("retain abandoned Claim material")
            .state,
        ScriptlessPayoutReservationState::AbandonedRetained
    );
    assert_eq!(
        wallet
            .scriptless_payout_abandon_exposed(refund.reservation_id)
            .expect("retain abandoned Refund material")
            .state,
        ScriptlessPayoutReservationState::AbandonedRetained
    );
    assert!(matches!(
        wallet.scriptless_payout_cancel_unexposed(refund.reservation_id),
        Err(CoreError::ScriptlessPayoutCannotRelease)
    ));
    assert_eq!(
        zero_signer
            .scriptless_payout_abandon_exposed(zero_claim.reservation_id)
            .expect("retain Claim no-output contribution")
            .state,
        ScriptlessPayoutReservationState::AbandonedRetained
    );
    assert_eq!(
        zero_signer
            .scriptless_payout_abandon_exposed(zero_refund.reservation_id)
            .expect("retain Refund no-output contribution")
            .state,
        ScriptlessPayoutReservationState::AbandonedRetained
    );
    zero_signer
        .close()
        .expect("close no-output signer laboratory cleanly");
    wallet.close().expect("close F7 payout laboratory cleanly");
}
