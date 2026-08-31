#![cfg(target_os = "linux")]

//! Adversarial storage, crash, fencing, idempotency and fee-bump tests.

use std::collections::VecDeque;
use std::error::Error;
use std::os::unix::fs::{symlink, PermissionsExt};

use adapter_btc::timelock::ChainTimingBoundsV1;
use adapter_btc::types::BitcoinNetworkV1;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use btc_actuator::{
    BitcoinActionV1, BitcoinActuationScopeAuthorizationV1, BitcoinActuationScopeV1,
    BitcoinActuatorErrorV1, BitcoinFeeBumpPolicyV1, BitcoinLegV1, BitcoinOperationKindV1,
    BitcoinOperationStageV1, BitcoinOutpointV1, BitcoinParticipantClaimAuthorityRequestV1,
    BitcoinParticipantClaimAuthorityV1, BitcoinParticipantNonceVaultV1, BitcoinParticipantRoleV1,
    BitcoinPortCallJournalStatusV1, BitcoinPortCallKeyV1, BitcoinPortCallKindV1,
    BitcoinPortCallOutcomeV1, BitcoinReconciliationV1, BitcoinRpcBroadcastV1, BitcoinRpcErrorV1,
    BitcoinRpcLookupV1, BitcoinRpcTransactionV1, BitcoinRpcV1, DurableBitcoinActuatorV1,
    ExactBitcoinTransactionV1,
};
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, BitcoinDeploymentV1, ChainDeploymentV1,
    DomDeploymentV1, DomNetworkV1, DomRuntimeIdentityV1, RegistryChainProfileV1,
    RegistryManifestV1, RegistrySignatureV1, RegistryValidationPolicyV1,
    ResolvedBitcoinDeploymentV1, SignedRegistryV1,
};
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
use tempfile::TempDir;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ROUTE: [u8; 32] = [0x41; 32];
const TERMS: [u8; 32] = [0x42; 32];
const CONTRACT_AMOUNT: u64 = 100_000;
const DOM_CHAIN: ChainId = ChainId([
    0x22, 0x38, 0x4b, 0x4c, 0xbf, 0xaa, 0xe3, 0x06, 0xa7, 0xbd, 0xb2, 0x3a, 0x82, 0x24, 0x42, 0xf7,
    0xe6, 0x8f, 0xb5, 0x1f, 0x65, 0x32, 0x86, 0x97, 0xa7, 0x54, 0xa9, 0xf3, 0xab, 0xd6, 0x98, 0xe1,
]);
const DOM_GENESIS: [u8; 32] = [
    0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9, 0x76, 0xbf, 0x3e,
    0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc, 0xa9, 0x9d, 0xde, 0xe3, 0xfe, 0x1f,
];

fn timing() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 1,
        max_block_seconds: 2,
        max_reorg_seconds: 10,
        observation_seconds: 2,
        broadcast_seconds: 2,
    }
}

fn finality() -> FinalityPolicyV1 {
    FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 3,
    }
}

fn deployment() -> TestResult<ResolvedBitcoinDeploymentV1> {
    let btc_chain = ChainId([0x02; 32]);
    let dom_asset = AssetId([0x11; 32]);
    let btc_asset = AssetId([0x12; 32]);
    let manifest = RegistryManifestV1 {
        network_id: [0x21; 32],
        epoch: 7,
        valid_from: 1_000,
        expires_at: 9_000,
        dom: DomDeploymentV1 {
            chain_id: DOM_CHAIN,
            genesis_hash: DOM_GENESIS,
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            consensus_rules_digest: [0x23; 32],
            scriptless_api_version: 1,
            timing: timing(),
            finality: finality(),
            native_asset: dom_asset,
        },
        chains: vec![RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id: btc_chain,
                kind: ChainKindV1::Bitcoin {
                    network: BitcoinNetworkV1::Regtest,
                },
                timing: timing(),
                finality: finality(),
                native_asset: btc_asset,
                allowed_assets: vec![],
            },
            deployment: ChainDeploymentV1::Bitcoin(BitcoinDeploymentV1 {
                genesis_hash: genesis_block(Network::Regtest)
                    .block_hash()
                    .to_raw_hash()
                    .to_byte_array(),
                signet_challenge: vec![],
                max_fee_rate_sat_vbyte: 100,
                min_relay_fee_sat_kvb: 1_000,
            }),
        }],
        assets: vec![
            AssetBindingV1 {
                chain_id: btc_chain,
                asset_id: btc_asset,
                decimals: 8,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: DOM_CHAIN,
                asset_id: dom_asset,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
        ],
    };
    let crypto = SecpContext::new(&[0x31; 32]);
    let digest = manifest.manifest_digest()?;
    let (signature, public_key) = crypto.sign_bip340(&[0x32; 32], &digest, &[0x33; 32])?;
    let authorities = AuthoritySetV1::new(1, vec![public_key])?;
    let signed = SignedRegistryV1::new(
        &manifest,
        vec![RegistrySignatureV1 {
            signer_index: 0,
            signature,
        }],
    )?;
    let resolved = signed.verify(
        &authorities,
        &crypto,
        RegistryValidationPolicyV1 {
            now_seconds: 2_000,
            expected_network_id: [0x21; 32],
            minimum_epoch: 7,
        },
    )?;
    Ok(resolved
        .resolve_chain(btc_chain)
        .ok_or("missing Bitcoin profile")?
        .bitcoin_deployment_capability()?)
}

fn owner_dir() -> TestResult<TempDir> {
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

fn outpoint() -> BitcoinOutpointV1 {
    BitcoinOutpointV1 {
        txid: [0x51; 32],
        vout: 3,
    }
}

fn terminal_transaction(outputs: Vec<u64>, witness_byte: u8) -> TestResult<Vec<u8>> {
    let point = outpoint();
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                    point.txid,
                )),
                vout: point.vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness: Witness::from_slice(&[vec![witness_byte; 64]]),
        }],
        output: outputs
            .into_iter()
            .enumerate()
            .map(|(index, value)| TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, index as u8]),
            })
            .collect(),
    };
    Ok(bitcoin::consensus::serialize(&transaction))
}

fn exact(raw: &[u8]) -> TestResult<ExactBitcoinTransactionV1> {
    Ok(ExactBitcoinTransactionV1::from_consensus_bytes(
        raw.to_vec(),
    )?)
}

fn scope(
    deployment: &ResolvedBitcoinDeploymentV1,
    raw: &[u8],
    effect: [u8; 32],
    action: BitcoinActionV1,
    fence: u64,
    valid_until_ms: u64,
    fee_policy: BitcoinFeeBumpPolicyV1,
) -> TestResult<BitcoinActuationScopeV1> {
    let exact = exact(raw)?;
    Ok(BitcoinActuationScopeV1::authorize(
        BitcoinActuationScopeAuthorizationV1 {
            deployment,
            route_id: ROUTE,
            effect_id: effect,
            leg: BitcoinLegV1::Downstream,
            action,
            fence_epoch: fence,
            terms_digest: TERMS,
            expected_txid: exact.txid(),
            intent_digest: exact.intent_digest(),
            contract_outpoint: Some(outpoint()),
            contract_amount_sat: CONTRACT_AMOUNT,
            refund_record_digest: None,
            fee_policy,
            valid_until_ms,
        },
    )?)
}

fn fixed_fee_policy() -> BitcoinFeeBumpPolicyV1 {
    BitcoinFeeBumpPolicyV1 {
        initial_fee_sat: 1_000,
        maximum_fee_sat: 5_000,
        maximum_fee_rate_sat_vbyte: 100,
        change_vout: None,
    }
}

struct MockRpc {
    broadcasts: VecDeque<Result<BitcoinRpcBroadcastV1, BitcoinRpcErrorV1>>,
    lookups: VecDeque<Result<BitcoinRpcLookupV1, BitcoinRpcErrorV1>>,
    sent: Vec<Vec<u8>>,
}

impl MockRpc {
    fn new() -> Self {
        Self {
            broadcasts: VecDeque::new(),
            lookups: VecDeque::new(),
            sent: Vec::new(),
        }
    }
}

impl BitcoinRpcV1 for MockRpc {
    fn verify_scope(&mut self, _scope: &BitcoinActuationScopeV1) -> Result<(), BitcoinRpcErrorV1> {
        Ok(())
    }

    fn broadcast_exact(
        &mut self,
        raw_transaction: &[u8],
        expected_txid: [u8; 32],
    ) -> Result<BitcoinRpcBroadcastV1, BitcoinRpcErrorV1> {
        self.sent.push(raw_transaction.to_vec());
        self.broadcasts
            .pop_front()
            .unwrap_or(Ok(BitcoinRpcBroadcastV1::Accepted {
                txid: expected_txid,
            }))
    }

    fn lookup_exact(
        &mut self,
        _expected_txid: [u8; 32],
    ) -> Result<BitcoinRpcLookupV1, BitcoinRpcErrorV1> {
        self.lookups
            .pop_front()
            .unwrap_or(Ok(BitcoinRpcLookupV1::Absent {
                evidence_digest: [0xe1; 32],
            }))
    }
}

fn observed(raw: &[u8], evidence: u8) -> TestResult<BitcoinRpcTransactionV1> {
    Ok(BitcoinRpcTransactionV1::from_consensus_bytes(
        raw.to_vec(),
        [evidence; 32],
    )?)
}

fn retained_clock(path: &std::path::Path) -> TestResult<u64> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let bytes: Vec<u8> = connection.query_row(
        "SELECT high_water_ms FROM monotonic_clock WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| "invalid clock")?,
    ))
}

#[test]
fn owner_only_create_open_lock_and_schema_are_fail_closed() -> TestResult {
    let directory = owner_dir()?;
    let path = directory.path().join("actuator.sqlite");
    let store = DurableBitcoinActuatorV1::create(&path, [0x61; 32])?;
    assert!(matches!(
        DurableBitcoinActuatorV1::create(&path, [0x61; 32]),
        Err(BitcoinActuatorErrorV1::DatabasePresent)
    ));
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&path, [0x62; 32]),
        Err(BitcoinActuatorErrorV1::LeaseHeld)
    ));
    drop(store);
    let reopened = DurableBitcoinActuatorV1::open_existing(&path, [0x62; 32])?;
    drop(reopened);
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&path, [0; 32]),
        Err(BitcoinActuatorErrorV1::InvalidScope)
    ));

    let missing = directory.path().join("missing.sqlite");
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&missing, [0x61; 32]),
        Err(BitcoinActuatorErrorV1::DatabaseMissing)
    ));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&path, [0x61; 32]),
        Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
    ));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    let connection = rusqlite::Connection::open(&path)?;
    let mode: String = connection.query_row("PRAGMA journal_mode=DELETE", [], |row| row.get(0))?;
    assert_eq!(mode.to_ascii_lowercase(), "delete");
    drop(connection);
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&path, [0x61; 32]),
        Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
    ));
    let connection = rusqlite::Connection::open(&path)?;
    let mode: String = connection.query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))?;
    assert_eq!(mode.to_ascii_lowercase(), "wal");
    drop(connection);

    let connection = rusqlite::Connection::open(&path)?;
    connection.pragma_update(None, "foreign_keys", "OFF")?;
    connection.execute(
        "INSERT INTO terminal_choice(route_id,leg,action,effect_id,txid) VALUES(?1,1,2,?2,?3)",
        rusqlite::params![
            [0xa1_u8; 32].as_slice(),
            [0xa2_u8; 32].as_slice(),
            [0xa3_u8; 32].as_slice()
        ],
    )?;
    drop(connection);
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&path, [0x61; 32]),
        Err(BitcoinActuatorErrorV1::CorruptState)
    ));
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("DELETE FROM terminal_choice", [])?;
    drop(connection);

    let connection = rusqlite::Connection::open(&path)?;
    connection.execute("CREATE TABLE injected(value INTEGER) STRICT", [])?;
    drop(connection);
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&path, [0x61; 32]),
        Err(BitcoinActuatorErrorV1::CorruptState)
    ));
    Ok(())
}

#[test]
fn obsolete_schema_version_is_refused_without_implicit_migration() -> TestResult {
    let directory = owner_dir()?;
    let path = directory.path().join("obsolete.sqlite");
    let store = DurableBitcoinActuatorV1::create(&path, [0xb1; 32])?;
    drop(store);

    // The port-call journal is schema V3. A complete V2 authority is refused;
    // open never invents journal history for previously returned calls.
    let connection = rusqlite::Connection::open(&path)?;
    connection.pragma_update(None, "user_version", 2)?;
    drop(connection);
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&path, [0xb1; 32]),
        Err(BitcoinActuatorErrorV1::CorruptState)
    ));
    Ok(())
}

#[test]
fn atomic_binding_and_port_journal_survive_restart_and_chain_change() -> TestResult {
    let deployment = deployment()?;
    let directory = owner_dir()?;
    let path = directory.path().join("port-journal.sqlite");
    let raw = terminal_transaction(vec![99_000], 0xb2)?;
    let effect = [0xb3; 32];
    let scope = scope(
        &deployment,
        &raw,
        effect,
        BitcoinActionV1::Claim,
        1,
        5_000,
        fixed_fee_policy(),
    )?;
    let mut store = DurableBitcoinActuatorV1::create(&path, [0xb4; 32])?;
    let lease = store.acquire_lease(100, 1_000)?;
    store.prepare_terminal(&scope, exact(&raw)?, 101)?;

    let binding = store.operation_binding(lease, BitcoinOperationKindV1::Terminal, effect, 102)?;
    assert_eq!(binding.scope().effect_id(), effect);
    assert_eq!(binding.scope_digest(), scope.scope_digest());
    assert_eq!(binding.terms_digest(), TERMS);
    assert_eq!(binding.chain_id(), [0x02; 32]);
    assert_ne!(binding.chain_identity_digest(), [0; 32]);
    assert_ne!(binding.chain_id(), binding.chain_identity_digest());
    assert_ne!(binding.custody_locator(), [0; 32]);
    assert_eq!(
        format!("{binding:?}"),
        "BitcoinOperationBindingViewV1([redacted])"
    );
    let locator = binding.locator();
    let key = BitcoinPortCallKeyV1::new(
        BitcoinPortCallKindV1::Observation,
        [0xb5; 32],
        [0xb6; 32],
        &binding,
    )?;
    assert_eq!(
        store.begin_port_call(lease, key, 103)?,
        BitcoinPortCallJournalStatusV1::Pending
    );
    let stable = BitcoinPortCallOutcomeV1::Pending {
        evidence_digest: [0xb7; 32],
    };
    assert_eq!(
        store.commit_port_call_outcome(lease, key, stable, 104)?,
        stable
    );

    let transplanted = BitcoinPortCallKeyV1::new(
        BitcoinPortCallKindV1::Observation,
        [0xb5; 32],
        [0xb8; 32],
        &binding,
    )?;
    assert!(matches!(
        store.begin_port_call(lease, transplanted, 105),
        Err(BitcoinActuatorErrorV1::IdempotencyConflict)
    ));

    let mut rpc = MockRpc::new();
    rpc.lookups.push_back(Ok(BitcoinRpcLookupV1::Confirmed {
        transaction: observed(&raw, 0xb9)?,
        block_hash: [0xba; 32],
        block_height: 77,
        confirmations: 2,
    }));
    assert_eq!(
        store.reconcile_terminal(&scope, &mut rpc, 106, || Ok(106))?,
        BitcoinReconciliationV1::ExactFinal {
            confirmations: 2,
            block_height: 77,
        }
    );
    assert_eq!(
        store.begin_port_call(lease, key, 107)?,
        BitcoinPortCallJournalStatusV1::Committed(stable)
    );

    drop(store);
    let mut store = DurableBitcoinActuatorV1::open_existing(&path, [0xb4; 32])?;
    let restarted_lease = store.acquire_lease(108, 1_000)?;
    let restarted = store.operation_binding(
        restarted_lease,
        BitcoinOperationKindV1::Terminal,
        effect,
        109,
    )?;
    assert_eq!(restarted.locator(), locator);
    let restarted_key = BitcoinPortCallKeyV1::new(
        BitcoinPortCallKindV1::Observation,
        [0xb5; 32],
        [0xb6; 32],
        &restarted,
    )?;
    let replay = store.begin_port_call(restarted_lease, restarted_key, 110)?;
    assert_eq!(replay, BitcoinPortCallJournalStatusV1::Committed(stable));
    if let BitcoinPortCallJournalStatusV1::Committed(value) = replay {
        assert_eq!(value.canonical_bytes(), stable.canonical_bytes());
    }

    drop(store);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "UPDATE port_call_journal SET outcome_digest=?1",
        rusqlite::params![[0xbb_u8; 32].as_slice()],
    )?;
    drop(connection);
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&path, [0xb4; 32]),
        Err(BitcoinActuatorErrorV1::CorruptState)
    ));
    Ok(())
}

#[test]
fn operation_binding_rejects_tampered_canonical_scope_bytes() -> TestResult {
    let deployment = deployment()?;
    let directory = owner_dir()?;
    let path = directory.path().join("scope-tamper.sqlite");
    let raw = terminal_transaction(vec![99_000], 0xbc)?;
    let effect = [0xbd; 32];
    let scope = scope(
        &deployment,
        &raw,
        effect,
        BitcoinActionV1::Claim,
        1,
        5_000,
        fixed_fee_policy(),
    )?;
    let mut store = DurableBitcoinActuatorV1::create(&path, [0xbe; 32])?;
    let lease = store.acquire_lease(100, 1_000)?;
    store.prepare_terminal(&scope, exact(&raw)?, 101)?;

    let connection = rusqlite::Connection::open(&path)?;
    let mut scope_bytes: Vec<u8> = connection.query_row(
        "SELECT scope_bytes FROM operations WHERE effect_id=?1",
        rusqlite::params![effect.as_slice()],
        |row| row.get(0),
    )?;
    scope_bytes[0] ^= 1;
    connection.execute(
        "UPDATE operations SET scope_bytes=?1 WHERE effect_id=?2",
        rusqlite::params![scope_bytes, effect.as_slice()],
    )?;
    drop(connection);

    assert!(matches!(
        store.operation_binding(lease, BitcoinOperationKindV1::Terminal, effect, 102),
        Err(BitcoinActuatorErrorV1::CorruptState)
    ));
    Ok(())
}

#[test]
fn symlink_hardlink_and_nonce_vault_replacement_are_refused() -> TestResult {
    let deployment = deployment()?;
    let directory = owner_dir()?;
    let target = directory.path().join("target.sqlite");
    let store = DurableBitcoinActuatorV1::create(&target, [0x63; 32])?;
    drop(store);
    let link = directory.path().join("link.sqlite");
    symlink(&target, &link)?;
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&link, [0x63; 32]),
        Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
    ));
    let hard = directory.path().join("hard.sqlite");
    std::fs::hard_link(&target, &hard)?;
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&target, [0x63; 32]),
        Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
    ));

    let sidecar_database = directory.path().join("sidecar.sqlite");
    let sidecar_store = DurableBitcoinActuatorV1::create(&sidecar_database, [0x64; 32])?;
    drop(sidecar_store);
    let sidecar_target = directory.path().join("sidecar-target");
    std::fs::write(&sidecar_target, b"not a WAL")?;
    std::fs::set_permissions(&sidecar_target, std::fs::Permissions::from_mode(0o600))?;
    symlink(
        &sidecar_target,
        format!("{}-wal", sidecar_database.display()),
    )?;
    assert!(matches!(
        DurableBitcoinActuatorV1::open_existing(&sidecar_database, [0x64; 32]),
        Err(BitcoinActuatorErrorV1::InvalidStorageAuthority)
    ));

    let vault = directory.path().join("participant-nonce.sqlite");
    let mut secret = [0x65; 32];
    let public_key =
        PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret)?).serialize();
    let authority = BitcoinParticipantClaimAuthorityV1::authorize_local_key(
        BitcoinParticipantClaimAuthorityRequestV1 {
            deployment: &deployment,
            route_id: ROUTE,
            terms_digest: TERMS,
            participant_id: [0x66; 32],
            role: BitcoinParticipantRoleV1::Maker,
            expected_public_key: public_key,
        },
        &mut secret,
    )?;
    let participant_state = BitcoinParticipantNonceVaultV1::create(&vault, &authority)?;
    assert_eq!(
        std::fs::metadata(&vault)?.permissions().mode() & 0o7777,
        0o600
    );
    assert!(matches!(
        BitcoinParticipantNonceVaultV1::create(&vault, &authority),
        Err(BitcoinActuatorErrorV1::DatabasePresent)
    ));
    drop(participant_state);
    Ok(())
}

#[test]
fn crash_restart_retries_only_identical_bytes_and_finishes_idempotently() -> TestResult {
    let deployment = deployment()?;
    let directory = owner_dir()?;
    let path = directory.path().join("actuator.sqlite");
    let raw = terminal_transaction(vec![99_000], 0x71)?;
    let claim_scope = scope(
        &deployment,
        &raw,
        [0x72; 32],
        BitcoinActionV1::Claim,
        1,
        10_000,
        fixed_fee_policy(),
    )?;
    let mut store = DurableBitcoinActuatorV1::create(&path, [0x73; 32])?;
    assert_eq!(store.acquire_lease(100, 1_000)?.fence_epoch(), 1);
    let prepared = store.prepare_terminal(&claim_scope, exact(&raw)?, 101)?;
    assert_eq!(prepared.stage, BitcoinOperationStageV1::Prepared);
    assert_eq!(prepared.confirmations, 0);
    assert_eq!(prepared.block_hash, None);
    assert_eq!(prepared.evidence_digest, None);
    let mut first_rpc = MockRpc::new();
    first_rpc
        .broadcasts
        .push_back(Err(BitcoinRpcErrorV1::TransportUnavailable));
    first_rpc.lookups.push_back(Ok(BitcoinRpcLookupV1::Absent {
        evidence_digest: [0x74; 32],
    }));
    assert!(matches!(
        store.broadcast_terminal(&claim_scope, &mut first_rpc, 102),
        Err(BitcoinActuatorErrorV1::ExternalizationAmbiguous)
    ));
    assert_eq!(first_rpc.sent, vec![raw.clone()]);
    drop(store);

    let mut store = DurableBitcoinActuatorV1::open_existing(&path, [0x73; 32])?;
    assert_eq!(store.acquire_lease(103, 1_000)?.fence_epoch(), 1);
    let mut retry_rpc = MockRpc::new();
    retry_rpc
        .broadcasts
        .push_back(Ok(BitcoinRpcBroadcastV1::AlreadyKnown {
            txid: exact(&raw)?.txid(),
        }));
    let receipt = store.broadcast_terminal(&claim_scope, &mut retry_rpc, 104)?;
    assert_eq!(receipt.attempt, 2);
    assert!(receipt.already_known);
    assert_eq!(retry_rpc.sent, vec![raw.clone()]);

    let mut confirmed_rpc = MockRpc::new();
    confirmed_rpc
        .lookups
        .push_back(Ok(BitcoinRpcLookupV1::Confirmed {
            transaction: observed(&raw, 0x75)?,
            block_hash: [0x76; 32],
            block_height: 41,
            confirmations: 2,
        }));
    assert_eq!(
        store.reconcile_terminal(&claim_scope, &mut confirmed_rpc, 105, || Ok(105))?,
        BitcoinReconciliationV1::ExactFinal {
            confirmations: 2,
            block_height: 41,
        }
    );
    let retained = store.terminal_operation(claim_scope.effect_id())?;
    assert_eq!(retained.stage, BitcoinOperationStageV1::Final);
    assert_eq!(retained.confirmations, 2);
    assert_eq!(retained.block_hash, Some([0x76; 32]));
    assert_eq!(retained.block_height, Some(41));
    assert_eq!(retained.evidence_digest, Some([0x75; 32]));
    let mut final_rpc = MockRpc::new();
    let final_receipt = store.broadcast_terminal(&claim_scope, &mut final_rpc, 106)?;
    assert_eq!(final_receipt.attempt, 2);
    assert!(final_rpc.sent.is_empty());

    // Canonical height and its evidence survive a second process restart;
    // a later canonical absence then fails closed and clears both block facts.
    drop(store);
    let mut store = DurableBitcoinActuatorV1::open_existing(&path, [0x73; 32])?;
    let restarted = store.terminal_operation(claim_scope.effect_id())?;
    assert_eq!(restarted.block_hash, Some([0x76; 32]));
    assert_eq!(restarted.block_height, Some(41));
    assert_eq!(restarted.evidence_digest, Some([0x75; 32]));
    let mut reorg_rpc = MockRpc::new();
    reorg_rpc.lookups.push_back(Ok(BitcoinRpcLookupV1::Absent {
        evidence_digest: [0x77; 32],
    }));
    assert_eq!(
        store.reconcile_terminal(&claim_scope, &mut reorg_rpc, 107, || Ok(107))?,
        BitcoinReconciliationV1::Ambiguous
    );
    let invalidated = store.terminal_operation(claim_scope.effect_id())?;
    assert_eq!(invalidated.stage, BitcoinOperationStageV1::Ambiguous);
    assert_eq!(invalidated.confirmations, 0);
    assert_eq!(invalidated.block_hash, None);
    assert_eq!(invalidated.block_height, None);
    assert_eq!(invalidated.evidence_digest, Some([0x77; 32]));
    Ok(())
}

#[test]
fn terminal_choice_and_takeover_fence_block_conflicts_and_stale_owner() -> TestResult {
    let deployment = deployment()?;
    let directory = owner_dir()?;
    let path = directory.path().join("actuator.sqlite");
    let raw = terminal_transaction(vec![99_000], 0x81)?;
    let claim = scope(
        &deployment,
        &raw,
        [0x82; 32],
        BitcoinActionV1::Claim,
        1,
        1_000,
        fixed_fee_policy(),
    )?;
    let refund = scope(
        &deployment,
        &raw,
        [0x83; 32],
        BitcoinActionV1::Refund,
        1,
        1_000,
        fixed_fee_policy(),
    )?;
    let mut store = DurableBitcoinActuatorV1::create(&path, [0x84; 32])?;
    store.acquire_lease(100, 50)?;
    store.prepare_terminal(&claim, exact(&raw)?, 101)?;
    store.prepare_terminal(&refund, exact(&raw)?, 102)?;
    let mut rpc = MockRpc::new();
    store.broadcast_terminal(&claim, &mut rpc, 103)?;
    assert!(matches!(
        store.broadcast_terminal(&refund, &mut rpc, 104),
        Err(BitcoinActuatorErrorV1::TerminalConflict)
    ));
    assert_eq!(rpc.sent.len(), 1);
    drop(store);

    let mut store = DurableBitcoinActuatorV1::open_existing(&path, [0x85; 32])?;
    assert_eq!(store.acquire_lease(151, 100)?.fence_epoch(), 2);
    let claim_takeover = scope(
        &deployment,
        &raw,
        [0x82; 32],
        BitcoinActionV1::Claim,
        2,
        2_000,
        fixed_fee_policy(),
    )?;
    let mut reconcile = MockRpc::new();
    reconcile
        .lookups
        .push_back(Ok(BitcoinRpcLookupV1::Mempool(observed(&raw, 0x86)?)));
    assert_eq!(
        store.reconcile_takeover(&claim_takeover, &mut reconcile, 152, || Ok(152))?,
        BitcoinReconciliationV1::ExactMempool
    );
    let mut stale_rpc = MockRpc::new();
    assert!(matches!(
        store.broadcast_terminal(&claim, &mut stale_rpc, 153),
        Err(BitcoinActuatorErrorV1::StaleFencing)
    ));
    let mut new_rpc = MockRpc::new();
    store.broadcast_terminal(&claim_takeover, &mut new_rpc, 154)?;
    assert_eq!(new_rpc.sent, vec![raw]);
    Ok(())
}

#[test]
fn rpc_lookup_cannot_commit_terminal_or_takeover_after_lease_expires() -> TestResult {
    let deployment = deployment()?;
    let directory = owner_dir()?;
    let path = directory.path().join("fresh-time.sqlite");
    let raw = terminal_transaction(vec![99_000], 0x8a)?;
    let effect = [0x8b; 32];
    let scope_v1 = scope(
        &deployment,
        &raw,
        effect,
        BitcoinActionV1::Claim,
        1,
        5_000,
        fixed_fee_policy(),
    )?;
    let mut store = DurableBitcoinActuatorV1::create(&path, [0x8c; 32])?;
    store.acquire_lease(100, 50)?;
    store.prepare_terminal(&scope_v1, exact(&raw)?, 101)?;
    let before = store.terminal_operation(effect)?;
    let clock_before = retained_clock(&path)?;

    let callback_called = std::cell::Cell::new(false);
    let mut unavailable_rpc = MockRpc::new();
    unavailable_rpc
        .lookups
        .push_back(Err(BitcoinRpcErrorV1::TransportUnavailable));
    assert!(store
        .reconcile_terminal(&scope_v1, &mut unavailable_rpc, 149, || {
            callback_called.set(true);
            Ok(149)
        })
        .is_err());
    assert!(!callback_called.get());
    assert_eq!(store.terminal_operation(effect)?, before);
    assert_eq!(retained_clock(&path)?, clock_before);

    let mut regressed_rpc = MockRpc::new();
    regressed_rpc
        .lookups
        .push_back(Ok(BitcoinRpcLookupV1::Mempool(observed(&raw, 0x8d)?)));
    assert!(matches!(
        store.reconcile_terminal(&scope_v1, &mut regressed_rpc, 149, || Ok(148)),
        Err(BitcoinActuatorErrorV1::InvalidTime)
    ));
    assert_eq!(store.terminal_operation(effect)?, before);
    assert_eq!(retained_clock(&path)?, clock_before);

    let mut rpc = MockRpc::new();
    rpc.lookups
        .push_back(Ok(BitcoinRpcLookupV1::Mempool(observed(&raw, 0x8e)?)));
    assert!(matches!(
        store.reconcile_terminal(&scope_v1, &mut rpc, 149, || Ok(151)),
        Err(BitcoinActuatorErrorV1::StaleFencing)
    ));
    assert_eq!(store.terminal_operation(effect)?, before);
    assert_eq!(retained_clock(&path)?, clock_before);

    drop(store);
    let mut store = DurableBitcoinActuatorV1::open_existing(&path, [0x8f; 32])?;
    assert_eq!(store.acquire_lease(151, 50)?.fence_epoch(), 2);
    let scope_v2 = scope(
        &deployment,
        &raw,
        effect,
        BitcoinActionV1::Claim,
        2,
        5_000,
        fixed_fee_policy(),
    )?;
    let before = store.terminal_operation(effect)?;
    let clock_before = retained_clock(&path)?;
    let mut takeover_rpc = MockRpc::new();
    takeover_rpc
        .lookups
        .push_back(Ok(BitcoinRpcLookupV1::Mempool(observed(&raw, 0x90)?)));
    assert!(matches!(
        store.reconcile_takeover(&scope_v2, &mut takeover_rpc, 200, || Ok(202)),
        Err(BitcoinActuatorErrorV1::StaleFencing)
    ));
    assert_eq!(store.terminal_operation(effect)?, before);
    assert_eq!(retained_clock(&path)?, clock_before);
    Ok(())
}

#[test]
fn fee_bump_preserves_every_semantic_field_except_authorized_change() -> TestResult {
    let deployment = deployment()?;
    let directory = owner_dir()?;
    let path = directory.path().join("actuator.sqlite");
    let original_raw = terminal_transaction(vec![50_000, 49_000], 0x91)?;
    let policy = BitcoinFeeBumpPolicyV1 {
        initial_fee_sat: 1_000,
        maximum_fee_sat: 5_000,
        maximum_fee_rate_sat_vbyte: 100,
        change_vout: Some(1),
    };
    let original_scope = scope(
        &deployment,
        &original_raw,
        [0x92; 32],
        BitcoinActionV1::Refund,
        1,
        5_000,
        policy,
    )?;
    let mut store = DurableBitcoinActuatorV1::create(&path, [0x93; 32])?;
    store.acquire_lease(100, 1_000)?;
    store.prepare_terminal(&original_scope, exact(&original_raw)?, 101)?;
    let mut rpc = MockRpc::new();
    store.broadcast_terminal(&original_scope, &mut rpc, 102)?;
    rpc.lookups
        .push_back(Ok(BitcoinRpcLookupV1::Mempool(observed(
            &original_raw,
            0x94,
        )?)));
    store.reconcile_terminal(&original_scope, &mut rpc, 103, || Ok(103))?;

    let unsafe_raw = terminal_transaction(vec![49_000, 49_000], 0x95)?;
    let unsafe_scope = scope(
        &deployment,
        &unsafe_raw,
        [0x92; 32],
        BitcoinActionV1::Refund,
        1,
        5_000,
        policy,
    )?;
    assert!(matches!(
        store.prepare_replacement(&original_scope, &unsafe_scope, exact(&unsafe_raw)?, 104),
        Err(BitcoinActuatorErrorV1::UnsafeReplacement)
    ));

    let replacement_raw = terminal_transaction(vec![50_000, 48_000], 0x96)?;
    let replacement_scope = scope(
        &deployment,
        &replacement_raw,
        [0x92; 32],
        BitcoinActionV1::Refund,
        1,
        5_000,
        policy,
    )?;
    let view = store.prepare_replacement(
        &original_scope,
        &replacement_scope,
        exact(&replacement_raw)?,
        105,
    )?;
    assert_eq!(view.generation, 1);
    assert_eq!(view.stage, BitcoinOperationStageV1::Prepared);
    assert_eq!(view.txid, exact(&replacement_raw)?.txid());

    // The active replacement has not been sent yet, but generation zero was
    // already externalized. Absence of the replacement can therefore never
    // prove that the terminal family as a whole was not externalized.
    let mut absent_replacement = MockRpc::new();
    absent_replacement
        .lookups
        .push_back(Ok(BitcoinRpcLookupV1::Absent {
            evidence_digest: [0x97; 32],
        }));
    assert_eq!(
        store.reconcile_terminal(&replacement_scope, &mut absent_replacement, 106, || Ok(106))?,
        BitcoinReconciliationV1::Ambiguous
    );
    Ok(())
}
