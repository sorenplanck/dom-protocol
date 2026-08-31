use std::fs;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use adapter_btc::timelock::ChainTimingBoundsV1;
use adapter_evm::{
    abi::{
        event_topic0, selector, word_address, word_u128, SIG_CLAIM, SIG_CLAIMED, SIG_REFUND,
        SIG_REFUNDED,
    },
    adapter::encode_open_calldata,
    adaptor_address_of_scalar, derive_binding, derive_lock_id, keccak256, Direction, LockTerms,
    UnsignedEvmCall,
};
use btc_crypto::SecpContext;
use chain_profile::{ChainKindV1, ChainProfileV1};
use deployment_registry::{
    AssetBindingV1, AssetRepresentationV1, AuthoritySetV1, ChainDeploymentV1, DomDeploymentV1,
    DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, EvmSessionBindingsV1,
    RegistryChainProfileV1, RegistryManifestV1, RegistrySignatureV1, RegistryValidationPolicyV1,
    ResolvedEvmDeploymentV1, SignedRegistryV1,
};
use evm_actuator::{
    BroadcastDispositionV1, Digest32, DurableEvmActuatorV1, Eip1559SignatureV1,
    Eip1559SigningRequestV1, EvmActuatorErrorV1, EvmActuatorLeaseV1, EvmAddressV1,
    EvmClaimSecretV1, EvmFeesV1, EvmObservationMutationRequestV1, EvmOperationKindV1,
    EvmOperationMutationRequestV1, EvmOperationPreparationRequestV1, EvmRetainedMutationKindV1,
    EvmRpcErrorV1, EvmRpcV1, EvmSignerRoleV1, EvmTxStageV1, MutationStatusV1, ReconciliationKindV1,
    RpcAllowanceV1, RpcFinalizedTimeV1, RpcLogV1, RpcPendingNonceV1, RpcReceiptLookupV1,
    RpcReceiptV1, RpcTransactionLookupV1, RpcTransactionV1, ScopedEip1559SignerV1,
    ScopedEvmClaimV1, ScopedEvmOpenV1, ScopedEvmRefundV1, SignerRefusalV1,
};
use k256::ecdsa::SigningKey;
use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
use rusqlite::OptionalExtension;
use static_assertions::assert_not_impl_any;
use tempfile::TempDir;

assert_not_impl_any!(EvmClaimSecretV1: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(ScopedEvmClaimV1: Clone, Copy, core::fmt::Debug);
assert_not_impl_any!(Eip1559SigningRequestV1: Clone, Copy);

const NETWORK: Digest32 = [0x90; 32];
const DOM_CHAIN: ChainId = ChainId([
    0x22, 0x38, 0x4b, 0x4c, 0xbf, 0xaa, 0xe3, 0x06, 0xa7, 0xbd, 0xb2, 0x3a, 0x82, 0x24, 0x42, 0xf7,
    0xe6, 0x8f, 0xb5, 0x1f, 0x65, 0x32, 0x86, 0x97, 0xa7, 0x54, 0xa9, 0xf3, 0xab, 0xd6, 0x98, 0xe1,
]);
const DOM_GENESIS: Digest32 = [
    0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9, 0x76, 0xbf, 0x3e,
    0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc, 0xa9, 0x9d, 0xde, 0xe3, 0xfe, 0x1f,
];
const EVM_CHAIN: ChainId = ChainId([0x02; 32]);
const DOM_ASSET: AssetId = AssetId([0x11; 32]);
const EVM_NATIVE: AssetId = AssetId([0x12; 32]);
const EVM_TOKEN: AssetId = AssetId([0x13; 32]);
const CHAIN_ID: u64 = 31_337;
const GENESIS: Digest32 = [0x35; 32];
const NATIVE_LOCK: EvmAddressV1 = [0x31; 20];
const TOKEN_LOCK: EvmAddressV1 = [0x33; 20];
const TOKEN: EvmAddressV1 = [0x42; 20];
const TOKEN_CODE_HASH: Digest32 = [0x43; 32];
const NOW: u64 = 2_000_000;
const LEASE_MS: u64 = 100_000;
const OBSERVATION_MS: u64 = 10_000;

fn id(value: u8) -> Digest32 {
    [value; 32]
}

fn timing() -> ChainTimingBoundsV1 {
    ChainTimingBoundsV1 {
        min_block_seconds: 5,
        max_block_seconds: 20,
        max_reorg_seconds: 200,
        observation_seconds: 30,
        broadcast_seconds: 20,
    }
}

fn finality() -> FinalityPolicyV1 {
    FinalityPolicyV1 {
        min_confirmations: 2,
        max_reorg_depth: 3,
    }
}

fn signer_address(key: &SigningKey) -> EvmAddressV1 {
    let encoded = key.verifying_key().to_encoded_point(false);
    let digest = keccak256(&encoded.as_bytes()[1..]);
    let mut address = [0; 20];
    address.copy_from_slice(&digest[12..]);
    address
}

fn signing_key(value: u8) -> SigningKey {
    SigningKey::from_bytes((&[value; 32]).into()).unwrap()
}

fn manifest() -> RegistryManifestV1 {
    RegistryManifestV1 {
        network_id: NETWORK,
        epoch: 7,
        valid_from: 1_000,
        expires_at: 10_000,
        dom: DomDeploymentV1 {
            chain_id: DOM_CHAIN,
            genesis_hash: DOM_GENESIS,
            runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
            consensus_rules_digest: [0x22; 32],
            scriptless_api_version: 1,
            timing: timing(),
            finality: finality(),
            native_asset: DOM_ASSET,
        },
        chains: vec![RegistryChainProfileV1 {
            profile: ChainProfileV1 {
                chain_id: EVM_CHAIN,
                kind: ChainKindV1::Evm {
                    evm_chain_id: CHAIN_ID,
                    native_lock_contract: NATIVE_LOCK,
                    native_code_hash: [0x32; 32],
                    erc20_lock_contract: Some((TOKEN_LOCK, [0x34; 32])),
                },
                timing: timing(),
                finality: finality(),
                native_asset: EVM_NATIVE,
                allowed_assets: vec![EVM_TOKEN],
            },
            deployment: ChainDeploymentV1::Evm(EvmDeploymentV1 {
                genesis_hash: GENESIS,
                native_start_block: 10,
                erc20_start_block: Some(11),
                abi_digest: [0x36; 32],
                compiler_digest: [0x37; 32],
                source_digest: [0x38; 32],
                deployment_digest: [0x39; 32],
                finalized_tag_required: true,
                page_size: 256,
                gas_limit_hint: 300_000,
                max_fee_per_gas: 100_000_000_000,
                max_priority_fee_per_gas: 2_000_000_000,
            }),
        }],
        assets: vec![
            AssetBindingV1 {
                chain_id: EVM_CHAIN,
                asset_id: EVM_NATIVE,
                decimals: 18,
                representation: AssetRepresentationV1::Native,
            },
            AssetBindingV1 {
                chain_id: EVM_CHAIN,
                asset_id: EVM_TOKEN,
                decimals: 6,
                representation: AssetRepresentationV1::EvmErc20 {
                    token: TOKEN,
                    token_code_hash: TOKEN_CODE_HASH,
                },
            },
            AssetBindingV1 {
                chain_id: DOM_CHAIN,
                asset_id: DOM_ASSET,
                decimals: 9,
                representation: AssetRepresentationV1::Native,
            },
        ],
    }
}

fn deployment(asset: AssetId, account: EvmAddressV1) -> ResolvedEvmDeploymentV1 {
    deployment_with_accounts(asset, account, [0x54; 20])
}

fn deployment_with_accounts(
    asset: AssetId,
    funder: EvmAddressV1,
    beneficiary: EvmAddressV1,
) -> ResolvedEvmDeploymentV1 {
    let manifest = manifest();
    let digest = manifest.manifest_digest().unwrap();
    let secp = SecpContext::new(&id(0x60));
    let (signature, public_key) = secp.sign_bip340(&id(3), &digest, &id(0x70)).unwrap();
    let authorities = AuthoritySetV1::new(1, vec![public_key]).unwrap();
    let signed = SignedRegistryV1::new(
        &manifest,
        vec![RegistrySignatureV1 {
            signer_index: 0,
            signature,
        }],
    )
    .unwrap();
    let registry = signed
        .verify(
            &authorities,
            &secp,
            RegistryValidationPolicyV1 {
                now_seconds: 2_000,
                expected_network_id: NETWORK,
                minimum_epoch: 7,
            },
        )
        .unwrap();
    registry
        .resolve_chain(EVM_CHAIN)
        .unwrap()
        .evm_deployment_capability(
            asset,
            EvmSessionBindingsV1 {
                direction: Direction::DomToEvm,
                session_id: id(0x51),
                terms_hash: id(0x52),
                participants_hash: id(0x53),
                beneficiary,
                funder,
            },
        )
        .unwrap()
}

fn open_call(deployment: ResolvedEvmDeploymentV1, amount: u128) -> UnsignedEvmCall {
    open_call_with_adaptor(deployment, amount, [0x77; 20])
}

fn open_call_with_adaptor(
    deployment: ResolvedEvmDeploymentV1,
    amount: u128,
    adaptor_address: EvmAddressV1,
) -> UnsignedEvmCall {
    let config = deployment.adapter_config();
    let amount_word = word_u128(amount);
    let terms = LockTerms {
        dom_chain_id: config.dom_chain_id,
        direction: config.direction.as_u8(),
        session_id: config.session_id,
        terms_hash: config.terms_hash,
        participants_hash: config.participants_hash,
        asset: config.asset,
        amount: amount_word,
        beneficiary: config.beneficiary,
        adaptor_address,
        deadline: 9_000_000,
    };
    let binding = derive_binding(config.chain_id, &config.contract, &terms).unwrap();
    let lock_id = derive_lock_id(&binding, &config.funder).unwrap();
    UnsignedEvmCall {
        version: 1,
        chain_id: config.chain_id,
        to: config.contract,
        value: if config.asset == [0; 20] {
            amount_word
        } else {
            [0; 32]
        },
        gas_limit_hint: config.gas_limit_hint,
        lock_id,
        binding,
        calldata: encode_open_calldata(&terms).unwrap(),
    }
}

fn secure_temp() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = directory.path().join("evm.sqlite3");
    (directory, path)
}

#[derive(Clone)]
struct TestSigner {
    key: SigningKey,
    seen: Vec<Digest32>,
    calldata_digests: Vec<Digest32>,
    operation_kinds: Vec<EvmOperationKindV1>,
    signer_roles: Vec<EvmSignerRoleV1>,
}

impl TestSigner {
    fn new(key: SigningKey) -> Self {
        Self {
            key,
            seen: vec![],
            calldata_digests: vec![],
            operation_kinds: vec![],
            signer_roles: vec![],
        }
    }
}

impl ScopedEip1559SignerV1 for TestSigner {
    fn sign_eip1559(
        &mut self,
        request: Eip1559SigningRequestV1,
    ) -> Result<Eip1559SignatureV1, SignerRefusalV1> {
        self.seen.push(request.one_shot_attempt_id());
        self.calldata_digests.push(request.calldata_digest());
        self.operation_kinds.push(request.operation_kind());
        self.signer_roles.push(request.signer_role());
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(&request.signing_hash())
            .map_err(|_| SignerRefusalV1::Refused)?;
        let bytes = signature.to_bytes();
        let mut r = [0; 32];
        let mut s = [0; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        Ok(Eip1559SignatureV1 {
            y_parity: recovery.to_byte(),
            r,
            s,
        })
    }
}

struct HighSSigner {
    inner: TestSigner,
}

impl ScopedEip1559SignerV1 for HighSSigner {
    fn sign_eip1559(
        &mut self,
        request: Eip1559SigningRequestV1,
    ) -> Result<Eip1559SignatureV1, SignerRefusalV1> {
        const ORDER: Digest32 = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut signature = self.inner.sign_eip1559(request)?;
        let mut borrow = 0u16;
        let mut high = [0; 32];
        for index in (0..32).rev() {
            let minuend = u16::from(ORDER[index]);
            let subtrahend = u16::from(signature.s[index]) + borrow;
            if minuend >= subtrahend {
                high[index] = (minuend - subtrahend) as u8;
                borrow = 0;
            } else {
                high[index] = (minuend + 256 - subtrahend) as u8;
                borrow = 1;
            }
        }
        assert_eq!(borrow, 0);
        signature.s = high;
        Ok(signature)
    }
}

#[derive(Clone)]
struct TestRpc {
    chain_id: u64,
    genesis: Digest32,
    pending_nonce: u64,
    lock_address: EvmAddressV1,
    lock_code_hash: Digest32,
    token_code_hash: Digest32,
    allowance: [u8; 32],
    allowance_block: u64,
    finalized_chain_id: u64,
    finalized_genesis: Digest32,
    finalized_timestamp: u64,
    send_error: bool,
    sent: Vec<Vec<u8>>,
    transaction: Option<RpcTransactionV1>,
    receipt: Option<RpcReceiptV1>,
}

impl TestRpc {
    fn new() -> Self {
        Self {
            chain_id: CHAIN_ID,
            genesis: GENESIS,
            pending_nonce: 4,
            lock_address: [0; 20],
            lock_code_hash: [0; 32],
            token_code_hash: TOKEN_CODE_HASH,
            allowance: word_u128(0),
            allowance_block: 100,
            finalized_chain_id: CHAIN_ID,
            finalized_genesis: GENESIS,
            finalized_timestamp: 10_000_000,
            send_error: false,
            sent: vec![],
            transaction: None,
            receipt: None,
        }
    }
}

impl EvmRpcV1 for TestRpc {
    fn chain_id(&mut self) -> Result<u64, EvmRpcErrorV1> {
        Ok(self.chain_id)
    }

    fn genesis_hash(&mut self) -> Result<Digest32, EvmRpcErrorV1> {
        Ok(self.genesis)
    }

    fn pending_nonce(
        &mut self,
        _account: EvmAddressV1,
    ) -> Result<RpcPendingNonceV1, EvmRpcErrorV1> {
        Ok(RpcPendingNonceV1 {
            nonce: self.pending_nonce,
            evidence_digest: id(0xa1),
        })
    }

    fn finalized_code_hash(
        &mut self,
        address: EvmAddressV1,
    ) -> Result<(Digest32, Digest32), EvmRpcErrorV1> {
        let code_hash = if address == self.lock_address {
            self.lock_code_hash
        } else if address == TOKEN {
            self.token_code_hash
        } else {
            return Err(EvmRpcErrorV1::InvalidResponse);
        };
        Ok((code_hash, id(0xa2)))
    }

    fn finalized_allowance(
        &mut self,
        _token: EvmAddressV1,
        _owner: EvmAddressV1,
        _spender: EvmAddressV1,
    ) -> Result<RpcAllowanceV1, EvmRpcErrorV1> {
        Ok(RpcAllowanceV1 {
            amount: self.allowance,
            block_number: self.allowance_block,
            block_hash: id(0xa3),
            evidence_digest: id(0xa4),
        })
    }

    fn finalized_block_time(&mut self) -> Result<RpcFinalizedTimeV1, EvmRpcErrorV1> {
        Ok(RpcFinalizedTimeV1 {
            chain_id: self.finalized_chain_id,
            genesis_hash: self.finalized_genesis,
            block_number: self.allowance_block,
            block_hash: id(0xa3),
            timestamp: self.finalized_timestamp,
            evidence_digest: id(0xa7),
        })
    }

    fn send_raw_transaction(&mut self, raw_transaction: &[u8]) -> Result<Digest32, EvmRpcErrorV1> {
        self.sent.push(raw_transaction.to_vec());
        if self.send_error {
            Err(EvmRpcErrorV1::Unavailable)
        } else {
            Ok(keccak256(raw_transaction))
        }
    }

    fn transaction_by_hash(
        &mut self,
        _transaction_hash: Digest32,
    ) -> Result<RpcTransactionLookupV1, EvmRpcErrorV1> {
        Ok(RpcTransactionLookupV1 {
            transaction: self.transaction.clone(),
            evidence_digest: id(0xa5),
        })
    }

    fn receipt(
        &mut self,
        _transaction_hash: Digest32,
    ) -> Result<RpcReceiptLookupV1, EvmRpcErrorV1> {
        Ok(RpcReceiptLookupV1 {
            receipt: self.receipt.clone(),
            evidence_digest: id(0xa6),
        })
    }
}

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    store: DurableEvmActuatorV1,
    lease: EvmActuatorLeaseV1,
    key: SigningKey,
    deployment: ResolvedEvmDeploymentV1,
    rpc: TestRpc,
}

impl Fixture {
    fn new(asset: AssetId) -> Self {
        let key = signing_key(7);
        let account = signer_address(&key);
        let deployment = deployment(asset, account);
        let (directory, path) = secure_temp();
        let mut store = DurableEvmActuatorV1::create(&path).unwrap();
        let lease = store
            .acquire_lease(&deployment, id(0xf1), NOW, LEASE_MS)
            .unwrap()
            .lease();
        Self {
            _directory: directory,
            path,
            store,
            lease,
            key,
            deployment,
            rpc: {
                let mut rpc = TestRpc::new();
                let config = deployment.adapter_config();
                rpc.lock_address = config.contract;
                rpc.lock_code_hash = config.expected_code_hash;
                rpc
            },
        }
    }

    fn nonce(&mut self) -> evm_actuator::NonceSnapshotV1 {
        self.store
            .refresh_pending_nonce(
                EvmObservationMutationRequestV1::new(
                    self.lease,
                    id(0x81),
                    0,
                    NOW + 1,
                    OBSERVATION_MS,
                ),
                &self.deployment,
                &mut self.rpc,
                || Ok(NOW + 1),
            )
            .unwrap()
            .value
    }

    fn scope(&self, route: u8, effect: u8, amount: u128) -> (ScopedEvmOpenV1, UnsignedEvmCall) {
        let call = open_call(self.deployment, amount);
        (
            ScopedEvmOpenV1::new(
                id(route),
                id(effect),
                id(effect.wrapping_add(1)),
                self.deployment,
                call.clone(),
            )
            .unwrap(),
            call,
        )
    }
}

fn prepare_native(
    fixture: &mut Fixture,
    operation: u8,
) -> (UnsignedEvmCall, evm_actuator::EvmOperationViewV1) {
    let nonce = fixture.nonce();
    let (scope, call) = fixture.scope(operation, operation.wrapping_add(1), 50);
    let view = fixture
        .store
        .prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(operation.wrapping_add(2)),
                id(operation),
                nonce,
                EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap(),
                NOW + 2,
            ),
            &scope,
        )
        .unwrap()
        .value;
    (call, view)
}

fn observed_transaction(
    call: &UnsignedEvmCall,
    lease: EvmActuatorLeaseV1,
    view: &evm_actuator::EvmOperationViewV1,
) -> RpcTransactionV1 {
    RpcTransactionV1 {
        transaction_hash: view.transaction_hash.unwrap(),
        chain_id: CHAIN_ID,
        from: lease.account(),
        to: call.to,
        nonce: view.nonce,
        value: call.value,
        gas_limit: call.gas_limit_hint,
        fees: view.fees,
        input: call.calldata.clone(),
    }
}

fn sign_current(
    fixture: &mut Fixture,
    operation: u8,
    prepared_revision: u64,
) -> evm_actuator::EvmOperationViewV1 {
    let mut signer = TestSigner::new(fixture.key.clone());
    fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(operation.wrapping_add(3)),
                id(operation),
                prepared_revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value
}

#[derive(Debug, Eq, PartialEq)]
struct FreshTimeDurableSnapshotV1 {
    clock_hex: String,
    nonce_hex: Option<String>,
    allowance_hex: Vec<String>,
}

fn fresh_time_durable_snapshot(path: &Path, authority_id: Digest32) -> FreshTimeDurableSnapshotV1 {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .unwrap();
    connection.pragma_update(None, "query_only", "ON").unwrap();
    let clock_hex = connection
        .query_row(
            "SELECT hex(clock_high_water_be) FROM evm_leases WHERE authority_id=?1",
            rusqlite::params![authority_id.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let nonce_hex = connection
        .query_row(
            "SELECT hex(observation_revision_be)||':'||hex(allocation_revision_be)||':'||
                    hex(pending_nonce_be)||':'||hex(evidence_digest)||':'||
                    hex(observed_at_be)||':'||hex(valid_until_be)
             FROM evm_nonce_snapshots WHERE authority_id=?1",
            rusqlite::params![authority_id.as_slice()],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    let allowance_hex = {
        let mut statement = connection
            .prepare(
                "SELECT hex(token)||':'||hex(spender)||':'||hex(revision_be)||':'||
                        hex(amount)||':'||hex(block_number_be)||':'||hex(block_hash)||':'||
                        hex(evidence_digest)||':'||hex(registry_digest)||':'||
                        hex(profile_digest)||':'||hex(asset_digest)||':'||
                        hex(observed_at_be)||':'||hex(valid_until_be)
                 FROM evm_allowances WHERE authority_id=?1 ORDER BY token,spender",
            )
            .unwrap();
        statement
            .query_map(rusqlite::params![authority_id.as_slice()], |row| row.get(0))
            .unwrap()
            .collect::<core::result::Result<Vec<String>, _>>()
            .unwrap()
    };
    FreshTimeDurableSnapshotV1 {
        clock_hex,
        nonce_hex,
        allowance_hex,
    }
}

struct TerminalFixture {
    _directory: TempDir,
    path: PathBuf,
    store: DurableEvmActuatorV1,
    funder_lease: EvmActuatorLeaseV1,
    beneficiary_lease: EvmActuatorLeaseV1,
    funder_key: SigningKey,
    beneficiary_key: SigningKey,
    deployment: ResolvedEvmDeploymentV1,
    opening_call: UnsignedEvmCall,
    scalar: Digest32,
    rpc: TestRpc,
}

impl TerminalFixture {
    fn new() -> Self {
        let funder_key = signing_key(7);
        let beneficiary_key = signing_key(9);
        let funder = signer_address(&funder_key);
        let beneficiary = signer_address(&beneficiary_key);
        let deployment = deployment_with_accounts(EVM_NATIVE, funder, beneficiary);
        let mut scalar = [0; 32];
        scalar[31] = 7;
        let adaptor_address = adaptor_address_of_scalar(&scalar).unwrap();
        let opening_call = open_call_with_adaptor(deployment, 50, adaptor_address);
        let (directory, path) = secure_temp();
        let mut store = DurableEvmActuatorV1::create(&path).unwrap();
        let funder_lease = store
            .acquire_lease_for_role(
                &deployment,
                EvmSignerRoleV1::Funder,
                id(0xe1),
                NOW,
                LEASE_MS,
            )
            .unwrap()
            .lease();
        let beneficiary_lease = store
            .acquire_lease_for_role(
                &deployment,
                EvmSignerRoleV1::Beneficiary,
                id(0xe2),
                NOW,
                LEASE_MS,
            )
            .unwrap()
            .lease();
        let config = deployment.adapter_config();
        let mut rpc = TestRpc::new();
        rpc.lock_address = config.contract;
        rpc.lock_code_hash = config.expected_code_hash;
        Self {
            _directory: directory,
            path,
            store,
            funder_lease,
            beneficiary_lease,
            funder_key,
            beneficiary_key,
            deployment,
            opening_call,
            scalar,
            rpc,
        }
    }

    fn nonce(&mut self, lease: EvmActuatorLeaseV1, mutation: u8) -> evm_actuator::NonceSnapshotV1 {
        self.store
            .refresh_pending_nonce(
                EvmObservationMutationRequestV1::new(
                    lease,
                    id(mutation),
                    0,
                    NOW + 1,
                    OBSERVATION_MS,
                ),
                &self.deployment,
                &mut self.rpc,
                || Ok(NOW + 1),
            )
            .unwrap()
            .value
    }

    fn claim_scope(&self, route: u8, effect: u8) -> ScopedEvmClaimV1 {
        let mut imported = self.scalar;
        let secret = EvmClaimSecretV1::import_and_zeroize(&mut imported).unwrap();
        assert_eq!(imported, [0; 32]);
        ScopedEvmClaimV1::new(
            id(route),
            id(effect),
            id(effect.wrapping_add(1)),
            self.deployment,
            self.opening_call.clone(),
            secret,
        )
        .unwrap()
    }

    fn refund_scope(&self, route: u8, effect: u8) -> ScopedEvmRefundV1 {
        ScopedEvmRefundV1::new(
            id(route),
            id(effect),
            id(effect.wrapping_add(1)),
            self.deployment,
            self.opening_call.clone(),
        )
        .unwrap()
    }
}

fn claim_calldata(lock_id: Digest32, scalar: Digest32) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&selector(SIG_CLAIM));
    calldata.extend_from_slice(&lock_id);
    calldata.extend_from_slice(&scalar);
    calldata
}

fn refund_calldata(lock_id: Digest32) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(36);
    calldata.extend_from_slice(&selector(SIG_REFUND));
    calldata.extend_from_slice(&lock_id);
    calldata
}

fn terminal_transaction(
    fixture: &TerminalFixture,
    lease: EvmActuatorLeaseV1,
    view: &evm_actuator::EvmOperationViewV1,
    input: Vec<u8>,
) -> RpcTransactionV1 {
    let config = fixture.deployment.adapter_config();
    RpcTransactionV1 {
        transaction_hash: view.transaction_hash.unwrap(),
        chain_id: CHAIN_ID,
        from: lease.account(),
        to: config.contract,
        nonce: view.nonce,
        value: [0; 32],
        gas_limit: config.gas_limit_hint,
        fees: view.fees,
        input,
    }
}

fn terminal_log(
    fixture: &TerminalFixture,
    view: &evm_actuator::EvmOperationViewV1,
    claimed: bool,
) -> RpcLogV1 {
    let config = fixture.deployment.adapter_config();
    RpcLogV1 {
        address: config.contract,
        topics: vec![
            event_topic0(if claimed { SIG_CLAIMED } else { SIG_REFUNDED }),
            fixture.opening_call.lock_id,
            fixture.opening_call.binding,
            word_address(if claimed {
                config.beneficiary
            } else {
                config.funder
            }),
        ],
        data: if claimed {
            fixture.scalar.to_vec()
        } else {
            word_u128(50).to_vec()
        },
        block_number: 101,
        block_hash: id(0xa7),
        transaction_hash: view.transaction_hash.unwrap(),
        log_index: 0,
        removed: false,
    }
}

fn final_receipt(
    view: &evm_actuator::EvmOperationViewV1,
    success: bool,
    logs: Vec<RpcLogV1>,
) -> RpcReceiptV1 {
    RpcReceiptV1 {
        transaction_hash: view.transaction_hash.unwrap(),
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS,
        success,
        block_number: 101,
        block_hash: id(0xa7),
        finalized: true,
        evidence_digest: id(0xa8),
        logs,
    }
}

#[test]
fn type2_kat_recovery_and_persist_before_send_survive_reopen() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (call, prepared) = prepare_native(&mut fixture, 0x10);
    assert_eq!(prepared.stage, EvmTxStageV1::Prepared);
    let mut signer = TestSigner::new(fixture.key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x13),
                id(0x10),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    assert_eq!(signed.stage, EvmTxStageV1::Signed);
    assert_eq!(signer.seen.len(), 1);
    let attempts = fixture.store.attempts(id(0x10)).unwrap();
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        hex::encode(attempts[0].signing_hash),
        "b8144aff65f2659379da6a63953a71855216a1bea8f1d4a17a2d8c7ecb9d41a1"
    );
    assert_ne!(attempts[0].signing_hash, [0; 32]);
    assert_eq!(Some(attempts[0].transaction_hash), signed.transaction_hash);

    drop(fixture.store);
    let mut reopened = DurableEvmActuatorV1::open_existing(&fixture.path).unwrap();
    let before_send = reopened.operation(id(0x10)).unwrap();
    assert_eq!(before_send.stage, EvmTxStageV1::Signed);
    let outcome = reopened
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x14),
                id(0x10),
                before_send.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    assert_eq!(outcome.disposition, BroadcastDispositionV1::Accepted);
    assert_eq!(fixture.rpc.sent.len(), 1);
    assert_eq!(&fixture.rpc.sent[0][..4], &[0x02, 0xf9, 0x01, 0xb4]);
    assert_eq!(fixture.rpc.sent[0].len(), 440);
    assert_eq!(
        hex::encode(outcome.transaction_hash),
        "adfe349d929dbc8953168c2811a37741955f87087c932e22843a821b17e83924"
    );
    assert_eq!(fixture.rpc.sent[0][0], 0x02);
    assert_eq!(keccak256(&fixture.rpc.sent[0]), outcome.transaction_hash);
    let sent = reopened.operation(id(0x10)).unwrap();
    assert_eq!(sent.stage, EvmTxStageV1::SendAttempted);
    assert!(sent.ambiguous_after_send);
    fixture.rpc.transaction = Some(observed_transaction(&call, fixture.lease, &sent));
}

#[test]
fn signer_io_cannot_persist_after_the_lease_expires() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0x1a);
    let mut signer = TestSigner::new(fixture.key.clone());
    let result = fixture.store.sign_prepared(
        EvmOperationMutationRequestV1::new(
            fixture.lease,
            id(0x1d),
            id(0x1a),
            prepared.revision,
            NOW + 3,
        ),
        &mut signer,
        || Ok(NOW + LEASE_MS + 1),
    );
    assert!(matches!(result, Err(EvmActuatorErrorV1::StaleFencing)));
    assert_eq!(
        fixture.store.operation(id(0x1a)).unwrap().stage,
        EvmTxStageV1::Prepared
    );
    assert!(fixture.store.attempts(id(0x1a)).unwrap().is_empty());
}

#[test]
fn scope_rejects_wrong_chain_destination_and_calldata_and_signer() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let call = open_call(fixture.deployment, 50);
    for changed in [
        {
            let mut value = call.clone();
            value.chain_id += 1;
            value
        },
        {
            let mut value = call.clone();
            value.to[0] ^= 1;
            value
        },
        {
            let mut value = call.clone();
            value.calldata[20] ^= 1;
            value
        },
    ] {
        assert!(matches!(
            ScopedEvmOpenV1::new(id(1), id(2), id(3), fixture.deployment, changed),
            Err(EvmActuatorErrorV1::CallScopeMismatch)
        ));
    }
    let (_, prepared) = prepare_native(&mut fixture, 0x20);
    let mut wrong = TestSigner::new(signing_key(8));
    assert!(matches!(
        fixture.store.sign_prepared(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x23),
                id(0x20),
                prepared.revision,
                NOW + 3
            ),
            &mut wrong,
            || Ok(NOW + 3)
        ),
        Err(EvmActuatorErrorV1::WrongSigner)
    ));
    assert_eq!(
        fixture.store.operation(id(0x20)).unwrap().stage,
        EvmTxStageV1::Prepared
    );
}

#[test]
fn ambiguous_send_retries_identical_bytes_and_never_releases_nonce() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0x30);
    let mut signer = TestSigner::new(fixture.key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x33),
                id(0x30),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    fixture.rpc.send_error = true;
    let first = fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x34),
                id(0x30),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    assert_eq!(first.disposition, BroadcastDispositionV1::Ambiguous);
    let after = fixture.store.operation(id(0x30)).unwrap();
    assert_eq!(after.stage, EvmTxStageV1::SendAttempted);
    assert!(after.ambiguous_after_send);
    fixture.rpc.send_error = false;
    let retry = fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x35),
                id(0x30),
                after.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap();
    assert_eq!(retry.disposition, BroadcastDispositionV1::Accepted);
    assert_eq!(fixture.rpc.sent.len(), 2);
    assert_eq!(fixture.rpc.sent[0], fixture.rpc.sent[1]);
    assert_eq!(first.transaction_hash, retry.transaction_hash);
}

#[test]
fn erc20_open_is_refused_until_finalized_allowance_and_cannot_overbook() {
    let mut fixture = Fixture::new(EVM_TOKEN);
    let nonce = fixture.nonce();
    let (scope, _) = fixture.scope(0x40, 0x41, 60);
    let fees = EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap();
    assert!(matches!(
        fixture.store.prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x42),
                id(0x40),
                nonce,
                fees,
                NOW + 2
            ),
            &scope
        ),
        Err(EvmActuatorErrorV1::AllowanceRequired)
    ));
    fixture.rpc.allowance = word_u128(100);
    assert_eq!(
        fixture
            .store
            .refresh_finalized_allowance(
                EvmObservationMutationRequestV1::new(
                    fixture.lease,
                    id(0x43),
                    0,
                    NOW + 2,
                    OBSERVATION_MS
                ),
                &fixture.deployment,
                &mut fixture.rpc,
                || Ok(NOW + 2)
            )
            .unwrap(),
        MutationStatusV1::Committed
    );
    let prepared = fixture
        .store
        .prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x44),
                id(0x40),
                nonce,
                fees,
                NOW + 3,
            ),
            &scope,
        )
        .unwrap()
        .value;
    assert_eq!(prepared.stage, EvmTxStageV1::Prepared);
    let fresh_nonce = fixture
        .store
        .nonce_snapshot(fixture.lease, NOW + 3)
        .unwrap();
    let (second, _) = fixture.scope(0x45, 0x46, 60);
    assert!(matches!(
        fixture.store.prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x47),
                id(0x45),
                fresh_nonce,
                fees,
                NOW + 4
            ),
            &second
        ),
        Err(EvmActuatorErrorV1::AllowanceRequired)
    ));
}

#[test]
fn replacement_preserves_nonce_and_only_increases_fees_under_caps() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0x50);
    let mut signer = TestSigner::new(fixture.key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x53),
                id(0x50),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    fixture.rpc.send_error = true;
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x54),
                id(0x50),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0x50)).unwrap();
    assert!(matches!(
        fixture.store.replace_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x59),
                id(0x50),
                attempted.revision,
                NOW + 5
            ),
            EvmFeesV1::new(19_000_000_000, 1_000_000_000).unwrap(),
            &mut signer,
            || Ok(NOW + 5)
        ),
        Err(EvmActuatorErrorV1::InvalidReplacement)
    ));
    assert!(matches!(
        fixture.store.replace_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x5a),
                id(0x50),
                attempted.revision,
                NOW + 5
            ),
            EvmFeesV1::new(101_000_000_000, 1_500_000_000).unwrap(),
            &mut signer,
            || Ok(NOW + 5)
        ),
        Err(EvmActuatorErrorV1::InvalidReplacement)
    ));
    let replacement_fees = EvmFeesV1::new(30_000_000_000, 1_500_000_000).unwrap();
    assert!(matches!(
        fixture.store.replace_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x5b),
                id(0x50),
                attempted.revision,
                NOW + 5,
            ),
            replacement_fees,
            &mut signer,
            || Ok(NOW + LEASE_MS + 1),
        ),
        Err(EvmActuatorErrorV1::StaleFencing)
    ));
    assert_eq!(fixture.store.operation(id(0x50)).unwrap(), attempted);
    let replacement = fixture
        .store
        .replace_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x55),
                id(0x50),
                attempted.revision,
                NOW + 5,
            ),
            replacement_fees,
            &mut signer,
            || Ok(NOW + 5),
        )
        .unwrap()
        .value;
    assert_eq!(replacement.stage, EvmTxStageV1::Signed);
    assert_eq!(replacement.nonce, attempted.nonce);
    assert_ne!(replacement.transaction_hash, attempted.transaction_hash);
    let attempts = fixture.store.attempts(id(0x50)).unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].stage, EvmTxStageV1::Replaced);
    assert_eq!(attempts[1].fees, replacement_fees);
}

#[test]
fn duplicate_broadcast_reuses_exact_persisted_bytes_and_conflict_is_refused() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0x60);
    let signed = sign_current(&mut fixture, 0x60, prepared.revision);
    let first = fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x64),
                id(0x60),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let duplicate = fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x64),
                id(0x60),
                signed.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap();
    assert_eq!(duplicate.status, MutationStatusV1::DuplicateSameBytes);
    assert_eq!(first.transaction_hash, duplicate.transaction_hash);
    assert_eq!(fixture.rpc.sent.len(), 2);
    assert_eq!(fixture.rpc.sent[0], fixture.rpc.sent[1]);
    assert!(matches!(
        fixture.store.broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x64),
                id(0x60),
                signed.revision + 1,
                NOW + 6
            ),
            &mut fixture.rpc,
            || Ok(NOW + 6),
        ),
        Err(EvmActuatorErrorV1::IdempotencyConflict)
    ));
}

#[test]
fn retained_mutation_input_revision_is_absent_then_replays_across_restart() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0x66);
    let signed = sign_current(&mut fixture, 0x66, prepared.revision);
    let mutation_id = id(0x6a);
    assert_eq!(
        fixture
            .store
            .retained_mutation_input_revision(
                fixture.lease,
                EvmRetainedMutationKindV1::BroadcastCurrent,
                mutation_id,
                id(0x66),
                NOW + 4,
            )
            .expect("fresh lookup"),
        None
    );
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                mutation_id,
                id(0x66),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .expect("persist send attempt");
    for now in [NOW + 4, NOW + 5] {
        assert_eq!(
            fixture
                .store
                .retained_mutation_input_revision(
                    fixture.lease,
                    EvmRetainedMutationKindV1::BroadcastCurrent,
                    mutation_id,
                    id(0x66),
                    now,
                )
                .expect("same live retained lookup"),
            Some(signed.revision)
        );
    }

    drop(fixture.store);
    let mut reopened = DurableEvmActuatorV1::open_existing(&fixture.path).expect("restart");
    let recovered = reopened
        .retained_mutation_input_revision(
            fixture.lease,
            EvmRetainedMutationKindV1::BroadcastCurrent,
            mutation_id,
            id(0x66),
            NOW + 6,
        )
        .expect("retained lookup after restart")
        .expect("retained revision");
    assert_eq!(recovered, signed.revision);
    assert_eq!(
        reopened
            .broadcast_current(
                EvmOperationMutationRequestV1::new(
                    fixture.lease,
                    mutation_id,
                    id(0x66),
                    recovered,
                    NOW + 6
                ),
                &mut fixture.rpc,
                || Ok(NOW + 6),
            )
            .expect("exact replay with recovered revision")
            .status,
        MutationStatusV1::DuplicateSameBytes
    );
}

#[test]
fn operation_binding_is_atomic_redacted_and_stable_across_restart() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0x40);
    let first = fixture
        .store
        .operation_binding(fixture.lease, id(0x40), NOW + 3)
        .expect("atomic operation binding");
    assert_eq!(first.operation(), &prepared);
    assert_ne!(first.intent_digest(), [0; 32]);
    let retained_intent = first.intent_digest();

    drop(fixture.store);
    let mut reopened = DurableEvmActuatorV1::open_existing(&fixture.path).expect("restart");
    let second = reopened
        .operation_binding(fixture.lease, id(0x40), NOW + 4)
        .expect("binding after restart");
    assert_eq!(second.operation(), &prepared);
    assert_eq!(second.intent_digest(), retained_intent);
    let debug = format!("{second:?}");
    assert!(!debug.contains("calldata"));
    assert!(!debug.contains("raw_transaction"));
    assert!(!debug.contains("scalar"));
    assert!(!debug.contains("private_key"));
}

#[test]
fn operation_binding_crosses_account_operation_owner_and_expiry() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0x41);
    assert!(matches!(
        fixture
            .store
            .operation_binding(fixture.lease, id(0x42), NOW + 3),
        Err(EvmActuatorErrorV1::OperationNotFound)
    ));

    let beneficiary_lease = fixture
        .store
        .acquire_lease_for_role(
            &fixture.deployment,
            EvmSignerRoleV1::Beneficiary,
            id(0x43),
            NOW + 3,
            LEASE_MS,
        )
        .expect("beneficiary lease")
        .lease();
    assert!(matches!(
        fixture
            .store
            .operation_binding(beneficiary_lease, id(0x41), NOW + 3),
        Err(EvmActuatorErrorV1::InvalidScope)
    ));
    assert!(matches!(
        fixture
            .store
            .operation_binding(fixture.lease, id(0x41), NOW + LEASE_MS + 1),
        Err(EvmActuatorErrorV1::StaleFencing)
    ));
    let takeover = fixture
        .store
        .acquire_lease(&fixture.deployment, id(0x44), NOW + LEASE_MS + 1, LEASE_MS)
        .expect("new owner after expiry")
        .lease();
    assert!(matches!(
        fixture
            .store
            .operation_binding(fixture.lease, id(0x41), NOW + LEASE_MS + 2),
        Err(EvmActuatorErrorV1::StaleFencing)
    ));
    assert_eq!(
        fixture
            .store
            .operation_binding(takeover, id(0x41), NOW + LEASE_MS + 2)
            .expect("new owner read for reconciliation")
            .operation(),
        &prepared
    );
}

#[test]
fn operation_binding_rejects_tampered_facts_and_request_commitment() {
    let mut fact_fixture = Fixture::new(EVM_NATIVE);
    prepare_native(&mut fact_fixture, 0x45);
    let connection = rusqlite::Connection::open(&fact_fixture.path).expect("raw fact database");
    connection
        .execute(
            "UPDATE evm_operations SET semantic_digest=?1 WHERE operation_id=?2",
            rusqlite::params![id(0x46).as_slice(), id(0x45).as_slice()],
        )
        .expect("tamper operation fact");
    drop(connection);
    assert!(matches!(
        fact_fixture
            .store
            .operation_binding(fact_fixture.lease, id(0x45), NOW + 3),
        Err(EvmActuatorErrorV1::CorruptState)
    ));

    let mut digest_fixture = Fixture::new(EVM_NATIVE);
    prepare_native(&mut digest_fixture, 0x47);
    let connection = rusqlite::Connection::open(&digest_fixture.path).expect("raw digest database");
    connection
        .execute(
            "UPDATE evm_operations SET request_digest=?1 WHERE operation_id=?2",
            rusqlite::params![id(0x48).as_slice(), id(0x47).as_slice()],
        )
        .expect("tamper request commitment");
    drop(connection);
    assert!(matches!(
        digest_fixture
            .store
            .operation_binding(digest_fixture.lease, id(0x47), NOW + 3),
        Err(EvmActuatorErrorV1::CorruptState)
    ));
}

#[test]
fn retained_mutation_revision_crosses_kind_operation_lease_and_expiry() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0x6b);
    let signed = sign_current(&mut fixture, 0x6b, prepared.revision);
    let mutation_id = id(0x6f);
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                mutation_id,
                id(0x6b),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .expect("persist send attempt");
    assert!(matches!(
        fixture.store.retained_mutation_input_revision(
            fixture.lease,
            EvmRetainedMutationKindV1::ObserveCurrent,
            mutation_id,
            id(0x6b),
            NOW + 5,
        ),
        Err(EvmActuatorErrorV1::IdempotencyConflict)
    ));

    let nonce = fixture
        .store
        .nonce_snapshot(fixture.lease, NOW + 5)
        .expect("current nonce allocation");
    let (second_scope, _) = fixture.scope(0x70, 0x71, 51);
    fixture
        .store
        .prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x72),
                id(0x70),
                nonce,
                EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap(),
                NOW + 5,
            ),
            &second_scope,
        )
        .expect("second operation locator");
    assert!(matches!(
        fixture.store.retained_mutation_input_revision(
            fixture.lease,
            EvmRetainedMutationKindV1::BroadcastCurrent,
            mutation_id,
            id(0x70),
            NOW + 5,
        ),
        Err(EvmActuatorErrorV1::IdempotencyConflict)
    ));

    let beneficiary_lease = fixture
        .store
        .acquire_lease_for_role(
            &fixture.deployment,
            EvmSignerRoleV1::Beneficiary,
            id(0x73),
            NOW + 5,
            LEASE_MS,
        )
        .expect("other account lease")
        .lease();
    assert!(matches!(
        fixture.store.retained_mutation_input_revision(
            beneficiary_lease,
            EvmRetainedMutationKindV1::BroadcastCurrent,
            mutation_id,
            id(0x6b),
            NOW + 5,
        ),
        Err(EvmActuatorErrorV1::InvalidScope)
    ));
    assert!(matches!(
        fixture.store.retained_mutation_input_revision(
            fixture.lease,
            EvmRetainedMutationKindV1::BroadcastCurrent,
            mutation_id,
            id(0x6b),
            NOW + LEASE_MS + 1,
        ),
        Err(EvmActuatorErrorV1::StaleFencing)
    ));
}

#[test]
fn retained_mutation_revision_rejects_zero_revision_and_digest_corruption() {
    let mut zero_fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut zero_fixture, 0x74);
    let signed = sign_current(&mut zero_fixture, 0x74, prepared.revision);
    let zero_mutation = id(0x78);
    zero_fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                zero_fixture.lease,
                zero_mutation,
                id(0x74),
                signed.revision,
                NOW + 4,
            ),
            &mut zero_fixture.rpc,
            || Ok(NOW + 4),
        )
        .expect("persist zero fixture mutation");
    drop(zero_fixture.store);
    let connection = rusqlite::Connection::open(&zero_fixture.path).expect("raw zero fixture");
    connection
        .execute(
            "UPDATE evm_mutations SET resulting_revision_be=?1 WHERE mutation_id=?2",
            rusqlite::params![0u64.to_be_bytes().as_slice(), zero_mutation.as_slice()],
        )
        .expect("corrupt resulting revision");
    drop(connection);
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&zero_fixture.path),
        Err(EvmActuatorErrorV1::CorruptState)
    ));

    let mut digest_fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut digest_fixture, 0x79);
    let signed = sign_current(&mut digest_fixture, 0x79, prepared.revision);
    let digest_mutation = id(0x7d);
    digest_fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                digest_fixture.lease,
                digest_mutation,
                id(0x79),
                signed.revision,
                NOW + 4,
            ),
            &mut digest_fixture.rpc,
            || Ok(NOW + 4),
        )
        .expect("persist digest fixture mutation");
    drop(digest_fixture.store);
    let connection = rusqlite::Connection::open(&digest_fixture.path).expect("raw digest fixture");
    connection
        .execute(
            "UPDATE evm_mutations SET mutation_digest=?1 WHERE mutation_id=?2",
            rusqlite::params![id(0x7e).as_slice(), digest_mutation.as_slice()],
        )
        .expect("corrupt mutation commitment");
    drop(connection);
    let mut reopened =
        DurableEvmActuatorV1::open_existing(&digest_fixture.path).expect("open digest fixture");
    assert!(matches!(
        reopened.retained_mutation_input_revision(
            digest_fixture.lease,
            EvmRetainedMutationKindV1::BroadcastCurrent,
            digest_mutation,
            id(0x79),
            NOW + 5,
        ),
        Err(EvmActuatorErrorV1::IdempotencyConflict)
    ));
}

#[test]
fn observed_transaction_becoming_absent_returns_to_ambiguous_without_nonce_release() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (call, prepared) = prepare_native(&mut fixture, 0x61);
    let signed = sign_current(&mut fixture, 0x61, prepared.revision);
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x65),
                id(0x61),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0x61)).unwrap();
    fixture.rpc.transaction = Some(observed_transaction(&call, fixture.lease, &attempted));
    fixture.rpc.receipt = None;
    let observed = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x66),
                id(0x61),
                attempted.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap()
        .value;
    assert_eq!(observed.stage, EvmTxStageV1::Observed);
    assert!(!observed.ambiguous_after_send);

    fixture.rpc.transaction = None;
    let absent = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x67),
                id(0x61),
                observed.revision,
                NOW + 6,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 6),
        )
        .unwrap()
        .value;
    assert_eq!(absent.stage, EvmTxStageV1::SendAttempted);
    assert!(absent.ambiguous_after_send);
    assert_eq!(absent.nonce, observed.nonce);
    assert_eq!(absent.transaction_hash, observed.transaction_hash);

    drop(fixture.store);
    let reopened = DurableEvmActuatorV1::open_existing(&fixture.path).unwrap();
    assert_eq!(reopened.operation(id(0x61)).unwrap(), absent);
}

#[test]
fn high_s_and_wrong_rpc_scope_are_rejected_without_externalization() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    fixture.rpc.chain_id += 1;
    assert!(matches!(
        fixture.store.refresh_pending_nonce(
            EvmObservationMutationRequestV1::new(
                fixture.lease,
                id(0x71),
                0,
                NOW + 1,
                OBSERVATION_MS
            ),
            &fixture.deployment,
            &mut fixture.rpc,
            || Ok(NOW + 1)
        ),
        Err(EvmActuatorErrorV1::RpcScopeMismatch)
    ));
    fixture.rpc.chain_id = CHAIN_ID;
    fixture.rpc.genesis[0] ^= 1;
    assert!(matches!(
        fixture.store.refresh_pending_nonce(
            EvmObservationMutationRequestV1::new(
                fixture.lease,
                id(0x71),
                0,
                NOW + 1,
                OBSERVATION_MS
            ),
            &fixture.deployment,
            &mut fixture.rpc,
            || Ok(NOW + 1)
        ),
        Err(EvmActuatorErrorV1::RpcScopeMismatch)
    ));
    fixture.rpc.genesis = GENESIS;
    fixture.rpc.lock_code_hash[0] ^= 1;
    assert!(matches!(
        fixture.store.refresh_pending_nonce(
            EvmObservationMutationRequestV1::new(
                fixture.lease,
                id(0x71),
                0,
                NOW + 1,
                OBSERVATION_MS
            ),
            &fixture.deployment,
            &mut fixture.rpc,
            || Ok(NOW + 1)
        ),
        Err(EvmActuatorErrorV1::RpcScopeMismatch)
    ));
    fixture.rpc.lock_code_hash = fixture.deployment.adapter_config().expected_code_hash;
    let (_, prepared) = prepare_native(&mut fixture, 0x70);
    let mut high = HighSSigner {
        inner: TestSigner::new(fixture.key.clone()),
    };
    assert!(matches!(
        fixture.store.sign_prepared(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x73),
                id(0x70),
                prepared.revision,
                NOW + 3
            ),
            &mut high,
            || Ok(NOW + 3)
        ),
        Err(EvmActuatorErrorV1::HighSignatureS)
    ));
    assert_eq!(
        fixture.store.operation(id(0x70)).unwrap().stage,
        EvmTxStageV1::Prepared
    );
    assert!(fixture.store.attempts(id(0x70)).unwrap().is_empty());
    let signed = sign_current(&mut fixture, 0x70, prepared.revision);
    let before_rpc_refusal =
        fresh_time_durable_snapshot(&fixture.path, fixture.lease.authority_id());
    fixture.rpc.lock_code_hash[0] ^= 1;
    assert!(matches!(
        fixture.store.broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x74),
                id(0x70),
                signed.revision,
                NOW + 4
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        ),
        Err(EvmActuatorErrorV1::RpcScopeMismatch)
    ));
    assert!(fixture.rpc.sent.is_empty());
    assert_eq!(
        fresh_time_durable_snapshot(&fixture.path, fixture.lease.authority_id()),
        before_rpc_refusal
    );
    let refused_preflight = fixture.store.operation(id(0x70)).unwrap();
    assert_eq!(refused_preflight, signed);
    fixture.rpc.lock_code_hash = fixture.deployment.adapter_config().expected_code_hash;
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x75),
                id(0x70),
                refused_preflight.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap();
    assert_eq!(fixture.rpc.sent.len(), 1);
}

#[test]
fn process_lock_is_exclusive_and_nonce_reservation_cas_survives_restart() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let nonce = fixture.nonce();
    assert!(matches!(
        fixture.store.nonce_snapshot(fixture.lease, NOW),
        Err(EvmActuatorErrorV1::InvalidTime)
    ));
    let (first_scope, _) = fixture.scope(0x80, 0x81, 50);
    let (second_scope, _) = fixture.scope(0x82, 0x83, 50);
    let (third_scope, _) = fixture.scope(0x87, 0x88, 50);
    let fees = EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap();
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&fixture.path),
        Err(EvmActuatorErrorV1::ProcessLocked)
    ));
    fixture
        .store
        .prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x84),
                id(0x80),
                nonce,
                fees,
                NOW + 2,
            ),
            &first_scope,
        )
        .unwrap();
    assert!(matches!(
        fixture.store.prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x85),
                id(0x82),
                nonce,
                fees,
                NOW + 2,
            ),
            &second_scope,
        ),
        Err(EvmActuatorErrorV1::RevisionConflict)
    ));
    drop(fixture.store);
    let mut reopened = DurableEvmActuatorV1::open_existing(&fixture.path).unwrap();
    let fresh = reopened.nonce_snapshot(fixture.lease, NOW + 3).unwrap();
    assert_eq!(fresh.allocation_revision(), nonce.allocation_revision() + 1);
    let second = reopened
        .prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x86),
                id(0x87),
                fresh,
                fees,
                NOW + 3,
            ),
            &third_scope,
        )
        .unwrap()
        .value;
    assert_eq!(second.nonce, nonce.pending_nonce() + 1);
}

#[test]
fn live_nonce_tamper_is_reaudited_in_the_next_transaction() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    fixture.nonce();
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    connection
        .execute(
            "UPDATE evm_nonce_snapshots SET observation_revision_be=?1",
            rusqlite::params![0u64.to_be_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        fixture.store.nonce_snapshot(fixture.lease, NOW + 2),
        Err(EvmActuatorErrorV1::CorruptState)
    ));
}

#[test]
fn stale_allowance_snapshot_never_authorizes_erc20_open() {
    let mut fixture = Fixture::new(EVM_TOKEN);
    let nonce = fixture.nonce();
    fixture.rpc.allowance = word_u128(100);
    fixture
        .store
        .refresh_finalized_allowance(
            EvmObservationMutationRequestV1::new(fixture.lease, id(0x91), 0, NOW + 2, 1),
            &fixture.deployment,
            &mut fixture.rpc,
            || Ok(NOW + 2),
        )
        .unwrap();
    let (scope, _) = fixture.scope(0x90, 0x92, 50);
    assert!(matches!(
        fixture.store.prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x93),
                id(0x90),
                nonce,
                EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap(),
                NOW + 4
            ),
            &scope
        ),
        Err(EvmActuatorErrorV1::StaleObservation)
    ));
}

#[test]
fn prepare_and_sign_are_idempotent_but_equivocation_is_rejected() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let nonce = fixture.nonce();
    let (scope, _) = fixture.scope(0x98, 0x99, 50);
    let fees = EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap();
    let prepared = fixture
        .store
        .prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x9a),
                id(0x98),
                nonce,
                fees,
                NOW + 2,
            ),
            &scope,
        )
        .unwrap();
    assert_eq!(prepared.status, MutationStatusV1::Committed);
    let duplicate = fixture
        .store
        .prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x9a),
                id(0x98),
                nonce,
                fees,
                NOW + 2,
            ),
            &scope,
        )
        .unwrap();
    assert_eq!(duplicate.status, MutationStatusV1::DuplicateSameBytes);
    let (different, _) = fixture.scope(0x9b, 0x9c, 51);
    assert!(matches!(
        fixture.store.prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0x9a),
                id(0x9b),
                nonce,
                fees,
                NOW + 2
            ),
            &different
        ),
        Err(EvmActuatorErrorV1::IdempotencyConflict)
    ));

    let mut signer = TestSigner::new(fixture.key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x9d),
                id(0x98),
                prepared.value.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap();
    let duplicate_sign = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0x9d),
                id(0x98),
                prepared.value.revision,
                NOW + 4,
            ),
            &mut signer,
            || Ok(NOW + 4),
        )
        .unwrap();
    assert_eq!(duplicate_sign.status, MutationStatusV1::DuplicateSameBytes);
    assert_eq!(
        duplicate_sign.value.transaction_hash,
        signed.value.transaction_hash
    );
    assert_eq!(signer.seen.len(), 1);
}

#[test]
fn finalized_revert_is_terminal_and_nonce_is_never_replaced() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (call, prepared) = prepare_native(&mut fixture, 0xa0);
    let signed = sign_current(&mut fixture, 0xa0, prepared.revision);
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xa4),
                id(0xa0),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0xa0)).unwrap();
    fixture.rpc.transaction = Some(observed_transaction(&call, fixture.lease, &attempted));
    fixture.rpc.receipt = Some(RpcReceiptV1 {
        transaction_hash: attempted.transaction_hash.unwrap(),
        chain_id: CHAIN_ID,
        genesis_hash: GENESIS,
        success: false,
        block_number: 101,
        block_hash: id(0xa7),
        finalized: true,
        evidence_digest: id(0xa8),
        logs: vec![],
    });
    let final_view = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xa5),
                id(0xa0),
                attempted.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap()
        .value;
    assert_eq!(final_view.stage, EvmTxStageV1::Final);
    assert_eq!(final_view.execution_success, Some(false));
    assert!(matches!(
        fixture.store.replace_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xa6),
                id(0xa0),
                final_view.revision,
                NOW + 6
            ),
            EvmFeesV1::new(30_000_000_000, 1_500_000_000).unwrap(),
            &mut TestSigner::new(fixture.key.clone()),
            || Ok(NOW + 6)
        ),
        Err(EvmActuatorErrorV1::InvalidState)
    ));
}

#[test]
fn observation_must_match_every_persisted_transaction_field() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (call, prepared) = prepare_native(&mut fixture, 0xaa);
    let signed = sign_current(&mut fixture, 0xaa, prepared.revision);
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xae),
                id(0xaa),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0xaa)).unwrap();
    let mut wrong = observed_transaction(&call, fixture.lease, &attempted);
    wrong.input[0] ^= 1;
    fixture.rpc.transaction = Some(wrong);
    assert!(matches!(
        fixture.store.observe_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xaf),
                id(0xaa),
                attempted.revision,
                NOW + 5
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        ),
        Err(EvmActuatorErrorV1::ObservationMismatch)
    ));
    assert_eq!(fixture.store.operation(id(0xaa)).unwrap(), attempted);
}

#[test]
fn expired_owner_is_fenced_and_unknown_takeover_can_be_reobserved_safely() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (call, prepared) = prepare_native(&mut fixture, 0xb0);
    let signed = sign_current(&mut fixture, 0xb0, prepared.revision);
    fixture.rpc.send_error = true;
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xb4),
                id(0xb0),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let old_attempted = fixture.store.operation(id(0xb0)).unwrap();
    assert!(matches!(
        fixture
            .store
            .acquire_lease(&fixture.deployment, id(0xf2), NOW + 5, LEASE_MS),
        Err(EvmActuatorErrorV1::LeaseHeld)
    ));
    let takeover_now = NOW + LEASE_MS + 1;
    let new_lease = fixture
        .store
        .acquire_lease(&fixture.deployment, id(0xf2), takeover_now, LEASE_MS)
        .unwrap()
        .lease();
    assert!(new_lease.fencing_epoch() > fixture.lease.fencing_epoch());
    assert!(matches!(
        fixture.store.broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xb5),
                id(0xb0),
                old_attempted.revision,
                NOW + 5
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        ),
        Err(EvmActuatorErrorV1::StaleFencing)
    ));
    let unknown = fixture
        .store
        .reconcile_takeover(
            EvmOperationMutationRequestV1::new(
                new_lease,
                id(0xb6),
                id(0xb0),
                old_attempted.revision,
                takeover_now + 1,
            ),
            &mut fixture.rpc,
            || Ok(takeover_now + 1),
        )
        .unwrap()
        .value;
    assert_eq!(unknown.stage, EvmTxStageV1::Reconciled);
    assert_eq!(
        unknown.reconciliation_kind,
        Some(ReconciliationKindV1::Unknown)
    );
    assert!(matches!(
        fixture.store.adopt_reconciled(
            new_lease,
            id(0xb7),
            id(0xb0),
            unknown.revision,
            takeover_now + 2,
        ),
        Err(EvmActuatorErrorV1::ReconciliationUnknown)
    ));
    fixture.rpc.transaction = Some(observed_transaction(&call, fixture.lease, &old_attempted));
    let observed = fixture
        .store
        .reconcile_takeover(
            EvmOperationMutationRequestV1::new(
                new_lease,
                id(0xb8),
                id(0xb0),
                unknown.revision,
                takeover_now + 3,
            ),
            &mut fixture.rpc,
            || Ok(takeover_now + 3),
        )
        .unwrap()
        .value;
    assert_eq!(
        observed.reconciliation_kind,
        Some(ReconciliationKindV1::Observed)
    );
    let adopted = fixture
        .store
        .adopt_reconciled(
            new_lease,
            id(0xb9),
            id(0xb0),
            observed.revision,
            takeover_now + 4,
        )
        .unwrap()
        .value;
    assert_eq!(adopted.stage, EvmTxStageV1::Observed);
    assert_eq!(adopted.fencing_epoch, new_lease.fencing_epoch());
}

#[test]
fn storage_open_is_owner_only_non_migrating_and_schema_exact() {
    let (directory, path) = secure_temp();
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&path),
        Err(EvmActuatorErrorV1::DatabaseMissing)
    ));
    let empty = directory.path().join("empty.sqlite3");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&empty)
        .unwrap();
    owner_only(&empty, 0o600);
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&empty),
        Err(EvmActuatorErrorV1::InvalidStorageAuthority)
    ));
    let empty_lock = PathBuf::from(format!("{}.lock", empty.display()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&empty_lock)
        .unwrap();
    owner_only(&empty_lock, 0o600);
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&empty),
        Err(EvmActuatorErrorV1::CreationIncomplete)
    ));
    drop(DurableEvmActuatorV1::resume_create_production(&empty).unwrap());
    drop(DurableEvmActuatorV1::open_existing(&empty).unwrap());

    let store = DurableEvmActuatorV1::create(&path).unwrap();
    drop(store);
    owner_only(&path, 0o640);
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&path),
        Err(EvmActuatorErrorV1::InvalidStorageAuthority)
    ));
    owner_only(&path, 0o600);
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("CREATE TABLE injected(value INTEGER) STRICT", [])
        .unwrap();
    drop(connection);
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&path),
        Err(EvmActuatorErrorV1::CorruptState)
    ));

    let residual = directory.path().join("residual.sqlite3");
    let wal = PathBuf::from(format!("{}-wal", residual.display()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&wal)
        .unwrap();
    owner_only(&wal, 0o600);
    assert!(matches!(
        DurableEvmActuatorV1::create(&residual),
        Err(EvmActuatorErrorV1::InvalidStorageAuthority)
    ));
}

#[test]
fn retained_call_or_raw_tamper_fails_closed_after_reopen() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0xc0);
    let signed = sign_current(&mut fixture, 0xc0, prepared.revision);
    assert_eq!(signed.stage, EvmTxStageV1::Signed);
    drop(fixture.store);
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    connection
        .execute(
            "UPDATE evm_operations SET calldata=zeroblob(length(calldata)) WHERE operation_id=?1",
            rusqlite::params![id(0xc0).as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&fixture.path),
        Err(EvmActuatorErrorV1::CorruptState)
    ));

    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0xc1);
    let signed = sign_current(&mut fixture, 0xc1, prepared.revision);
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xc5),
                id(0xc1),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0xc1)).unwrap();
    fixture
        .store
        .replace_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xc6),
                id(0xc1),
                attempted.revision,
                NOW + 5,
            ),
            EvmFeesV1::new(30_000_000_000, 1_500_000_000).unwrap(),
            &mut TestSigner::new(fixture.key.clone()),
            || Ok(NOW + 5),
        )
        .unwrap();
    drop(fixture.store);

    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    let mut historical_raw: Vec<u8> = connection
        .query_row(
            "SELECT raw_transaction FROM evm_attempts
             WHERE operation_id=?1 AND attempt=1",
            rusqlite::params![id(0xc1).as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let last = historical_raw.last_mut().unwrap();
    *last ^= 1;
    connection
        .execute(
            "UPDATE evm_attempts SET raw_transaction=?2
             WHERE operation_id=?1 AND attempt=1",
            rusqlite::params![id(0xc1).as_slice(), historical_raw],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&fixture.path),
        Err(EvmActuatorErrorV1::CorruptState)
    ));
}

fn owner_only(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

#[test]
fn claim_is_beneficiary_scoped_zeroizing_and_requires_exact_terminal_log() {
    let mut fixture = TerminalFixture::new();
    let beneficiary_lease = fixture.beneficiary_lease;
    let funder_lease = fixture.funder_lease;
    let nonce = fixture.nonce(beneficiary_lease, 0xd0);
    let fees = EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap();

    let wrong_scope = fixture.claim_scope(0xc1, 0xc2);
    assert!(matches!(
        fixture.store.prepare_claim(
            EvmOperationPreparationRequestV1::new(
                funder_lease,
                id(0xd1),
                id(0xc0),
                nonce,
                fees,
                NOW + 2
            ),
            wrong_scope
        ),
        Err(EvmActuatorErrorV1::InvalidScope)
    ));

    let scope = fixture.claim_scope(0xc1, 0xc2);
    let expected_calldata = claim_calldata(fixture.opening_call.lock_id, fixture.scalar);
    assert_eq!(scope.calldata_digest(), keccak256(&expected_calldata));
    let prepared = fixture
        .store
        .prepare_claim(
            EvmOperationPreparationRequestV1::new(
                beneficiary_lease,
                id(0xd2),
                id(0xc0),
                nonce,
                fees,
                NOW + 2,
            ),
            scope,
        )
        .unwrap()
        .value;
    assert_eq!(prepared.kind, EvmOperationKindV1::Claim);
    assert_eq!(prepared.signer_role, EvmSignerRoleV1::Beneficiary);
    assert_eq!(prepared.lock_id, fixture.opening_call.lock_id);
    assert_eq!(prepared.binding, fixture.opening_call.binding);
    assert!(!prepared.secret_exposed);
    assert_eq!(prepared.stage, EvmTxStageV1::Prepared);
    let public_debug = format!("{prepared:?}");
    assert!(!public_debug.contains("calldata"));
    assert!(!public_debug.contains("scalar"));

    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    let stored_calldata: Vec<u8> = connection
        .query_row(
            "SELECT calldata FROM evm_operations WHERE operation_id=?1",
            rusqlite::params![id(0xc0).as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_calldata, expected_calldata);
    drop(connection);

    let mut wrong_signer = TestSigner::new(fixture.funder_key.clone());
    assert!(matches!(
        fixture.store.sign_prepared(
            EvmOperationMutationRequestV1::new(
                beneficiary_lease,
                id(0xd3),
                id(0xc0),
                prepared.revision,
                NOW + 3
            ),
            &mut wrong_signer,
            || Ok(NOW + 3)
        ),
        Err(EvmActuatorErrorV1::WrongSigner)
    ));
    let mut signer = TestSigner::new(fixture.beneficiary_key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                beneficiary_lease,
                id(0xd4),
                id(0xc0),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    assert_eq!(signer.calldata_digests, vec![keccak256(&expected_calldata)]);
    assert_eq!(signer.operation_kinds, vec![EvmOperationKindV1::Claim]);
    assert_eq!(signer.signer_roles, vec![EvmSignerRoleV1::Beneficiary]);

    let broadcast = fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                beneficiary_lease,
                id(0xd5),
                id(0xc0),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    assert_eq!(broadcast.disposition, BroadcastDispositionV1::Accepted);
    let attempted = fixture.store.operation(id(0xc0)).unwrap();
    assert_eq!(attempted.stage, EvmTxStageV1::SendAttempted);
    assert!(attempted.secret_exposed);
    assert_eq!(fixture.rpc.sent.len(), 1);

    let transaction =
        terminal_transaction(&fixture, beneficiary_lease, &attempted, expected_calldata);
    let log = terminal_log(&fixture, &attempted, true);
    let transaction_debug = format!("{transaction:?}");
    let log_debug = format!("{log:?}");
    assert!(transaction_debug.contains("<redacted>"));
    assert!(!transaction_debug.contains(&hex::encode(fixture.scalar)));
    assert!(log_debug.contains("<redacted>"));
    assert!(!log_debug.contains(&hex::encode(fixture.scalar)));
    fixture.rpc.transaction = Some(transaction);
    fixture.rpc.receipt = Some(final_receipt(&attempted, true, vec![log]));
    let final_view = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                beneficiary_lease,
                id(0xd6),
                id(0xc0),
                attempted.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap()
        .value;
    assert_eq!(final_view.stage, EvmTxStageV1::Final);
    assert_eq!(final_view.execution_success, Some(true));
    assert!(final_view.secret_exposed);
    assert!(final_view.terminal_event_digest.is_some());

    drop(fixture.store);
    let reopened = DurableEvmActuatorV1::open_existing(&fixture.path).unwrap();
    assert_eq!(reopened.operation(id(0xc0)).unwrap(), final_view);
}

#[test]
fn refund_requires_funder_and_fresh_canonical_deadline_then_exact_event() {
    let mut fixture = TerminalFixture::new();
    let funder_lease = fixture.funder_lease;
    let beneficiary_lease = fixture.beneficiary_lease;
    let nonce = fixture.nonce(funder_lease, 0xe0);
    let fees = EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap();
    let scope = fixture.refund_scope(0xd1, 0xd2);

    fixture.rpc.finalized_timestamp = scope.deadline() - 1;
    assert!(matches!(
        fixture.store.prepare_refund(
            EvmOperationPreparationRequestV1::new(
                funder_lease,
                id(0xe1),
                id(0xd0),
                nonce,
                fees,
                NOW + 2
            ),
            &scope,
            &mut fixture.rpc,
            || Ok(NOW + 2)
        ),
        Err(EvmActuatorErrorV1::RefundDeadlineNotReached)
    ));
    fixture.rpc.finalized_timestamp = scope.deadline();
    fixture.rpc.finalized_chain_id += 1;
    assert!(matches!(
        fixture.store.prepare_refund(
            EvmOperationPreparationRequestV1::new(
                funder_lease,
                id(0xea),
                id(0xd0),
                nonce,
                fees,
                NOW + 2
            ),
            &scope,
            &mut fixture.rpc,
            || Ok(NOW + 2)
        ),
        Err(EvmActuatorErrorV1::RpcScopeMismatch)
    ));
    fixture.rpc.finalized_chain_id = CHAIN_ID;
    assert!(matches!(
        fixture.store.prepare_refund(
            EvmOperationPreparationRequestV1::new(
                beneficiary_lease,
                id(0xe2),
                id(0xd0),
                nonce,
                fees,
                NOW + 2
            ),
            &scope,
            &mut fixture.rpc,
            || Ok(NOW + 2)
        ),
        Err(EvmActuatorErrorV1::InvalidScope)
    ));

    let expected_calldata = refund_calldata(fixture.opening_call.lock_id);
    assert_eq!(scope.calldata_digest(), keccak256(&expected_calldata));
    let prepared = fixture
        .store
        .prepare_refund(
            EvmOperationPreparationRequestV1::new(
                funder_lease,
                id(0xe3),
                id(0xd0),
                nonce,
                fees,
                NOW + 2,
            ),
            &scope,
            &mut fixture.rpc,
            || Ok(NOW + 2),
        )
        .unwrap()
        .value;
    assert_eq!(prepared.kind, EvmOperationKindV1::Refund);
    assert_eq!(prepared.signer_role, EvmSignerRoleV1::Funder);
    assert_eq!(prepared.refund_authorized_block, Some(100));
    let authorization = prepared.refund_authorization.unwrap();
    assert_eq!(authorization.block_number(), 100);
    assert_eq!(authorization.block_hash(), id(0xa3));
    assert_eq!(authorization.timestamp(), scope.deadline());
    assert_eq!(authorization.evidence_digest(), id(0xa7));

    // A retry may observe a newer finalized head. That changes the canonical
    // deadline evidence, but not the operation intent or the exact evidence
    // already retained for crash recovery.
    fixture.rpc.allowance_block = 101;
    fixture.rpc.finalized_timestamp = scope.deadline() + 1;
    let same_mutation = fixture
        .store
        .prepare_refund(
            EvmOperationPreparationRequestV1::new(
                funder_lease,
                id(0xe3),
                id(0xd0),
                nonce,
                fees,
                NOW + 2,
            ),
            &scope,
            &mut fixture.rpc,
            || Ok(NOW + 2),
        )
        .unwrap();
    assert_eq!(same_mutation.status, MutationStatusV1::DuplicateSameBytes);
    assert_eq!(same_mutation.value, prepared);
    let new_mutation = fixture
        .store
        .prepare_refund(
            EvmOperationPreparationRequestV1::new(
                funder_lease,
                id(0xec),
                id(0xd0),
                nonce,
                fees,
                NOW + 2,
            ),
            &scope,
            &mut fixture.rpc,
            || Ok(NOW + 2),
        )
        .unwrap();
    assert_eq!(new_mutation.status, MutationStatusV1::DuplicateSameBytes);
    assert_eq!(new_mutation.value, prepared);
    assert_eq!(
        new_mutation
            .value
            .refund_authorization
            .unwrap()
            .block_number(),
        100
    );
    fixture.rpc.finalized_timestamp = scope.deadline() - 1;
    assert!(matches!(
        fixture.store.prepare_refund(
            EvmOperationPreparationRequestV1::new(
                funder_lease,
                id(0xe3),
                id(0xd0),
                nonce,
                fees,
                NOW + 2
            ),
            &scope,
            &mut fixture.rpc,
            || Ok(NOW + 2)
        ),
        Err(EvmActuatorErrorV1::RefundDeadlineNotReached)
    ));
    fixture.rpc.finalized_timestamp = scope.deadline() + 1;

    let mut signer = TestSigner::new(fixture.funder_key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xe4),
                id(0xd0),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    assert_eq!(signer.calldata_digests, vec![keccak256(&expected_calldata)]);
    assert_eq!(signer.operation_kinds, vec![EvmOperationKindV1::Refund]);
    assert_eq!(signer.signer_roles, vec![EvmSignerRoleV1::Funder]);

    fixture.rpc.finalized_timestamp = scope.deadline() - 1;
    assert!(matches!(
        fixture.store.broadcast_current(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xe5),
                id(0xd0),
                signed.revision,
                NOW + 4
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        ),
        Err(EvmActuatorErrorV1::RefundDeadlineNotReached)
    ));
    assert!(fixture.rpc.sent.is_empty());
    assert_eq!(
        fixture.store.operation(id(0xd0)).unwrap().stage,
        EvmTxStageV1::Signed
    );

    fixture.rpc.finalized_timestamp = scope.deadline();
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xe6),
                id(0xd0),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0xd0)).unwrap();
    fixture.rpc.finalized_timestamp = scope.deadline() - 1;
    assert!(matches!(
        fixture.store.broadcast_current(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xe6),
                id(0xd0),
                signed.revision,
                NOW + 5
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        ),
        Err(EvmActuatorErrorV1::RefundDeadlineNotReached)
    ));
    assert_eq!(fixture.rpc.sent.len(), 1);
    fixture.rpc.finalized_timestamp = scope.deadline();
    let transaction = terminal_transaction(&fixture, funder_lease, &attempted, expected_calldata);
    fixture.rpc.transaction = Some(transaction.clone());
    let mut wrong_chain_receipt = final_receipt(
        &attempted,
        true,
        vec![terminal_log(&fixture, &attempted, false)],
    );
    wrong_chain_receipt.chain_id += 1;
    fixture.rpc.receipt = Some(wrong_chain_receipt);
    assert!(matches!(
        fixture.store.observe_current(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xeb),
                id(0xd0),
                attempted.revision,
                NOW + 5
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        ),
        Err(EvmActuatorErrorV1::ObservationMismatch)
    ));
    assert_eq!(fixture.store.operation(id(0xd0)).unwrap(), attempted);

    fixture.rpc.receipt = Some(final_receipt(&attempted, true, vec![]));
    assert!(matches!(
        fixture.store.observe_current(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xe7),
                id(0xd0),
                attempted.revision,
                NOW + 5
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        ),
        Err(EvmActuatorErrorV1::TerminalEventMismatch)
    ));
    assert_eq!(fixture.store.operation(id(0xd0)).unwrap(), attempted);

    let mut wrong_log = terminal_log(&fixture, &attempted, false);
    wrong_log.topics[2] = id(0x45);
    fixture.rpc.receipt = Some(final_receipt(&attempted, true, vec![wrong_log]));
    assert!(matches!(
        fixture.store.observe_current(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xe8),
                id(0xd0),
                attempted.revision,
                NOW + 5
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        ),
        Err(EvmActuatorErrorV1::TerminalEventMismatch)
    ));

    let log = terminal_log(&fixture, &attempted, false);
    fixture.rpc.receipt = Some(final_receipt(&attempted, true, vec![log]));
    let final_view = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xe9),
                id(0xd0),
                attempted.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap()
        .value;
    assert_eq!(final_view.stage, EvmTxStageV1::Final);
    assert_eq!(final_view.execution_success, Some(true));
    assert!(!final_view.secret_exposed);
    assert!(final_view.terminal_event_digest.is_some());

    fixture.rpc.transaction = None;
    fixture.rpc.receipt = None;
    let invalidated = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xed),
                id(0xd0),
                final_view.revision,
                NOW + 6,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 6),
        )
        .unwrap()
        .value;
    assert_eq!(invalidated.stage, EvmTxStageV1::FinalityInvalidated);
    assert!(!invalidated.secret_exposed);
    assert_eq!(
        invalidated.refund_authorization,
        final_view.refund_authorization
    );
    assert_eq!(invalidated.final_block_hash, final_view.final_block_hash);
    assert!(invalidated.finality_invalidation_evidence_digest.is_some());

    fixture.rpc.transaction = Some(transaction);
    fixture.rpc.receipt = Some(final_receipt(
        &attempted,
        true,
        vec![terminal_log(&fixture, &attempted, false)],
    ));
    let refinalized = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                funder_lease,
                id(0xee),
                id(0xd0),
                invalidated.revision,
                NOW + 7,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 7),
        )
        .unwrap()
        .value;
    assert_eq!(refinalized.stage, EvmTxStageV1::Final);
    assert!(refinalized.finality_invalidation_evidence_digest.is_none());
    assert_eq!(
        refinalized.refund_authorization,
        final_view.refund_authorization
    );
    let connection = rusqlite::Connection::open(&fixture.path).unwrap();
    connection
        .execute(
            "UPDATE evm_operations SET finality_invalidation_evidence=?1
             WHERE operation_id=?2",
            rusqlite::params![id(0xf7).as_slice(), id(0xd0).as_slice()],
        )
        .unwrap();
    drop(connection);
    assert!(matches!(
        fixture.store.operation(id(0xd0)),
        Err(EvmActuatorErrorV1::CorruptState)
    ));
}

#[test]
fn claim_finality_invalidation_never_makes_secret_private_again() {
    let mut fixture = TerminalFixture::new();
    let lease = fixture.beneficiary_lease;
    let nonce = fixture.nonce(lease, 0xf0);
    let scope = fixture.claim_scope(0xe1, 0xe2);
    let prepared = fixture
        .store
        .prepare_claim(
            EvmOperationPreparationRequestV1::new(
                lease,
                id(0xf1),
                id(0xe0),
                nonce,
                EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap(),
                NOW + 2,
            ),
            scope,
        )
        .unwrap()
        .value;
    let mut signer = TestSigner::new(fixture.beneficiary_key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0xf2),
                id(0xe0),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(lease, id(0xf3), id(0xe0), signed.revision, NOW + 4),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0xe0)).unwrap();
    let transaction = terminal_transaction(
        &fixture,
        lease,
        &attempted,
        claim_calldata(fixture.opening_call.lock_id, fixture.scalar),
    );
    let receipt = final_receipt(
        &attempted,
        true,
        vec![terminal_log(&fixture, &attempted, true)],
    );
    fixture.rpc.transaction = Some(transaction.clone());
    fixture.rpc.receipt = Some(receipt.clone());
    let final_view = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0xf4),
                id(0xe0),
                attempted.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap()
        .value;
    let event_digest = final_view.terminal_event_digest.unwrap();

    fixture.rpc.transaction = None;
    fixture.rpc.receipt = None;
    let invalidated = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0xf5),
                id(0xe0),
                final_view.revision,
                NOW + 6,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 6),
        )
        .unwrap()
        .value;
    assert_eq!(invalidated.stage, EvmTxStageV1::FinalityInvalidated);
    assert!(invalidated.secret_exposed);
    assert_eq!(invalidated.terminal_event_digest, Some(event_digest));
    assert_eq!(invalidated.execution_success, Some(true));
    assert!(invalidated.final_block_number.is_some());
    assert!(invalidated.final_block_hash.is_some());
    assert!(invalidated.final_evidence_digest.is_some());
    assert!(invalidated.finality_invalidation_evidence_digest.is_some());

    fixture.rpc.transaction = Some(transaction);
    fixture.rpc.receipt = Some(receipt);
    let refinalized = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0xf6),
                id(0xe0),
                invalidated.revision,
                NOW + 7,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 7),
        )
        .unwrap()
        .value;
    assert_eq!(refinalized.stage, EvmTxStageV1::Final);
    assert!(refinalized.secret_exposed);
    assert_eq!(refinalized.terminal_event_digest, Some(event_digest));
    assert!(refinalized.finality_invalidation_evidence_digest.is_none());

    let takeover_time = NOW + LEASE_MS + 1;
    let takeover = fixture
        .store
        .acquire_lease_for_role(
            &fixture.deployment,
            EvmSignerRoleV1::Beneficiary,
            id(0xf7),
            takeover_time,
            LEASE_MS,
        )
        .unwrap()
        .lease();
    fixture.rpc.transaction = None;
    fixture.rpc.receipt = None;
    let reconciled = fixture
        .store
        .reconcile_takeover(
            EvmOperationMutationRequestV1::new(
                takeover,
                id(0xf8),
                id(0xe0),
                refinalized.revision,
                takeover_time + 1,
            ),
            &mut fixture.rpc,
            || Ok(takeover_time + 1),
        )
        .unwrap()
        .value;
    assert_eq!(reconciled.stage, EvmTxStageV1::Reconciled);
    assert_eq!(
        reconciled.reconciliation_kind,
        Some(ReconciliationKindV1::FinalityInvalidated)
    );
    assert!(reconciled.secret_exposed);
    let adopted = fixture
        .store
        .adopt_reconciled(
            takeover,
            id(0xf9),
            id(0xe0),
            reconciled.revision,
            takeover_time + 2,
        )
        .unwrap()
        .value;
    assert_eq!(adopted.stage, EvmTxStageV1::FinalityInvalidated);
    assert!(adopted.secret_exposed);
    assert_eq!(adopted.terminal_event_digest, Some(event_digest));
}

#[test]
fn invalid_claim_scalars_and_scope_tamper_fail_before_persistence() {
    const SECP256K1_ORDER: Digest32 = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    let fixture = TerminalFixture::new();

    let mut zero = [0; 32];
    assert!(matches!(
        EvmClaimSecretV1::import_and_zeroize(&mut zero),
        Err(EvmActuatorErrorV1::InvalidClaimSecret)
    ));
    assert_eq!(zero, [0; 32]);

    let mut order = SECP256K1_ORDER;
    assert!(matches!(
        EvmClaimSecretV1::import_and_zeroize(&mut order),
        Err(EvmActuatorErrorV1::InvalidClaimSecret)
    ));
    assert_eq!(order, [0; 32]);

    let mut wrong_scalar = [0; 32];
    wrong_scalar[31] = 8;
    let secret = EvmClaimSecretV1::import_and_zeroize(&mut wrong_scalar).unwrap();
    assert_eq!(wrong_scalar, [0; 32]);
    assert!(matches!(
        ScopedEvmClaimV1::new(
            id(0xf1),
            id(0xf2),
            id(0xf3),
            fixture.deployment,
            fixture.opening_call.clone(),
            secret,
        ),
        Err(EvmActuatorErrorV1::InvalidClaimSecret)
    ));

    let mut tampered = fixture.opening_call.clone();
    tampered.lock_id[0] ^= 1;
    assert!(matches!(
        ScopedEvmRefundV1::new(id(0xf4), id(0xf5), id(0xf6), fixture.deployment, tampered,),
        Err(EvmActuatorErrorV1::CallScopeMismatch)
    ));

    let mut wrong_chain = fixture.opening_call.clone();
    wrong_chain.chain_id += 1;
    assert!(matches!(
        ScopedEvmRefundV1::new(
            id(0xf4),
            id(0xf5),
            id(0xf6),
            fixture.deployment,
            wrong_chain,
        ),
        Err(EvmActuatorErrorV1::CallScopeMismatch)
    ));

    let other_funder = signer_address(&signing_key(11));
    let other_beneficiary = signer_address(&signing_key(12));
    let other_deployment = deployment_with_accounts(EVM_NATIVE, other_funder, other_beneficiary);
    assert!(matches!(
        ScopedEvmRefundV1::new(
            id(0xf4),
            id(0xf5),
            id(0xf6),
            other_deployment,
            fixture.opening_call.clone(),
        ),
        Err(EvmActuatorErrorV1::CallScopeMismatch)
    ));

    let mut valid = fixture.scalar;
    let secret = EvmClaimSecretV1::import_and_zeroize(&mut valid).unwrap();
    assert!(matches!(
        ScopedEvmClaimV1::new(
            [0; 32],
            id(0xf5),
            id(0xf6),
            fixture.deployment,
            fixture.opening_call.clone(),
            secret,
        ),
        Err(EvmActuatorErrorV1::InvalidScope)
    ));
}

#[test]
fn claim_duplicate_restart_and_ambiguous_retry_are_byte_identical() {
    let mut fixture = TerminalFixture::new();
    let lease = fixture.beneficiary_lease;
    let nonce = fixture.nonce(lease, 0x20);
    let fees = EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap();
    let prepared = fixture
        .store
        .prepare_claim(
            EvmOperationPreparationRequestV1::new(lease, id(0x21), id(0x22), nonce, fees, NOW + 2),
            fixture.claim_scope(0x23, 0x24),
        )
        .unwrap();
    assert_eq!(prepared.status, MutationStatusV1::Committed);
    let duplicate = fixture
        .store
        .prepare_claim(
            EvmOperationPreparationRequestV1::new(lease, id(0x21), id(0x22), nonce, fees, NOW + 2),
            fixture.claim_scope(0x23, 0x24),
        )
        .unwrap();
    assert_eq!(duplicate.status, MutationStatusV1::DuplicateSameBytes);
    assert_eq!(duplicate.value, prepared.value);
    assert!(matches!(
        fixture.store.prepare_claim(
            EvmOperationPreparationRequestV1::new(lease, id(0x21), id(0x22), nonce, fees, NOW + 2),
            fixture.claim_scope(0x23, 0x25)
        ),
        Err(EvmActuatorErrorV1::IdempotencyConflict)
    ));

    drop(fixture.store);
    let mut store = DurableEvmActuatorV1::open_existing(&fixture.path).unwrap();
    assert_eq!(store.operation(id(0x22)).unwrap(), prepared.value);
    let mut signer = TestSigner::new(fixture.beneficiary_key.clone());
    let signed = store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0x26),
                id(0x22),
                prepared.value.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    drop(store);

    let mut store = DurableEvmActuatorV1::open_existing(&fixture.path).unwrap();
    assert_eq!(store.operation(id(0x22)).unwrap(), signed);
    fixture.rpc.send_error = true;
    let first = store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(lease, id(0x27), id(0x22), signed.revision, NOW + 4),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    assert_eq!(first.status, MutationStatusV1::Committed);
    assert_eq!(first.disposition, BroadcastDispositionV1::Ambiguous);
    let attempted = store.operation(id(0x22)).unwrap();
    assert!(attempted.secret_exposed);
    drop(store);

    let mut store = DurableEvmActuatorV1::open_existing(&fixture.path).unwrap();
    let retry = store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(lease, id(0x27), id(0x22), signed.revision, NOW + 5),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap();
    assert_eq!(retry.status, MutationStatusV1::DuplicateSameBytes);
    assert_eq!(retry.transaction_hash, first.transaction_hash);
    assert_eq!(fixture.rpc.sent.len(), 2);
    assert_eq!(fixture.rpc.sent[0], fixture.rpc.sent[1]);
    assert_eq!(store.operation(id(0x22)).unwrap(), attempted);
}

#[test]
fn exposed_claim_replacement_survives_restart_and_signed_takeover() {
    let mut fixture = TerminalFixture::new();
    let old_lease = fixture.beneficiary_lease;
    let nonce = fixture.nonce(old_lease, 0x30);
    let prepared = fixture
        .store
        .prepare_claim(
            EvmOperationPreparationRequestV1::new(
                old_lease,
                id(0x31),
                id(0x32),
                nonce,
                EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap(),
                NOW + 2,
            ),
            fixture.claim_scope(0x33, 0x34),
        )
        .unwrap()
        .value;
    let mut signer = TestSigner::new(fixture.beneficiary_key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                old_lease,
                id(0x35),
                id(0x32),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                old_lease,
                id(0x36),
                id(0x32),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0x32)).unwrap();
    let replacement = fixture
        .store
        .replace_current(
            EvmOperationMutationRequestV1::new(
                old_lease,
                id(0x37),
                id(0x32),
                attempted.revision,
                NOW + 5,
            ),
            EvmFeesV1::new(30_000_000_000, 1_500_000_000).unwrap(),
            &mut signer,
            || Ok(NOW + 5),
        )
        .unwrap()
        .value;
    assert_eq!(replacement.stage, EvmTxStageV1::Signed);
    assert_eq!(replacement.nonce, attempted.nonce);
    assert!(replacement.secret_exposed);
    assert_ne!(replacement.transaction_hash, attempted.transaction_hash);

    drop(fixture.store);
    let mut store = DurableEvmActuatorV1::open_existing(&fixture.path).unwrap();
    assert_eq!(store.operation(id(0x32)).unwrap(), replacement);
    let takeover_now = NOW + LEASE_MS + 1;
    let new_lease = store
        .acquire_lease_for_role(
            &fixture.deployment,
            EvmSignerRoleV1::Beneficiary,
            id(0x38),
            takeover_now,
            LEASE_MS,
        )
        .unwrap()
        .lease();
    let reconciled = store
        .reconcile_takeover(
            EvmOperationMutationRequestV1::new(
                new_lease,
                id(0x39),
                id(0x32),
                replacement.revision,
                takeover_now + 1,
            ),
            &mut fixture.rpc,
            || Ok(takeover_now + 1),
        )
        .unwrap()
        .value;
    assert_eq!(reconciled.stage, EvmTxStageV1::Reconciled);
    assert_eq!(
        reconciled.reconciliation_kind,
        Some(ReconciliationKindV1::InternallyNeverSent)
    );
    assert!(reconciled.secret_exposed);
    let adopted = store
        .adopt_reconciled(
            new_lease,
            id(0x3a),
            id(0x32),
            reconciled.revision,
            takeover_now + 2,
        )
        .unwrap()
        .value;
    assert_eq!(adopted.stage, EvmTxStageV1::Signed);
    assert!(adopted.secret_exposed);
    store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                new_lease,
                id(0x3b),
                id(0x32),
                adopted.revision,
                takeover_now + 3,
            ),
            &mut fixture.rpc,
            || Ok(takeover_now + 3),
        )
        .unwrap();
    assert_eq!(fixture.rpc.sent.len(), 2);
    assert_ne!(fixture.rpc.sent[0], fixture.rpc.sent[1]);
    assert!(store.operation(id(0x32)).unwrap().secret_exposed);
}

#[test]
fn exposed_claim_unknown_takeover_stays_blocked_and_public() {
    let mut fixture = TerminalFixture::new();
    let old_lease = fixture.beneficiary_lease;
    let nonce = fixture.nonce(old_lease, 0x40);
    let prepared = fixture
        .store
        .prepare_claim(
            EvmOperationPreparationRequestV1::new(
                old_lease,
                id(0x41),
                id(0x42),
                nonce,
                EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap(),
                NOW + 2,
            ),
            fixture.claim_scope(0x43, 0x44),
        )
        .unwrap()
        .value;
    let mut signer = TestSigner::new(fixture.beneficiary_key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                old_lease,
                id(0x45),
                id(0x42),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    fixture.rpc.send_error = true;
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                old_lease,
                id(0x46),
                id(0x42),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0x42)).unwrap();
    assert!(attempted.secret_exposed);

    let takeover_now = NOW + LEASE_MS + 1;
    let new_lease = fixture
        .store
        .acquire_lease_for_role(
            &fixture.deployment,
            EvmSignerRoleV1::Beneficiary,
            id(0x47),
            takeover_now,
            LEASE_MS,
        )
        .unwrap()
        .lease();
    let unknown = fixture
        .store
        .reconcile_takeover(
            EvmOperationMutationRequestV1::new(
                new_lease,
                id(0x48),
                id(0x42),
                attempted.revision,
                takeover_now + 1,
            ),
            &mut fixture.rpc,
            || Ok(takeover_now + 1),
        )
        .unwrap()
        .value;
    assert_eq!(unknown.stage, EvmTxStageV1::Reconciled);
    assert_eq!(
        unknown.reconciliation_kind,
        Some(ReconciliationKindV1::Unknown)
    );
    assert!(unknown.secret_exposed);
    assert!(matches!(
        fixture.store.adopt_reconciled(
            new_lease,
            id(0x49),
            id(0x42),
            unknown.revision,
            takeover_now + 2,
        ),
        Err(EvmActuatorErrorV1::ReconciliationUnknown)
    ));
    assert_eq!(fixture.rpc.sent.len(), 1);
}

#[test]
fn finalized_claim_revert_is_terminal_but_forged_logs_are_refused() {
    let mut fixture = TerminalFixture::new();
    let lease = fixture.beneficiary_lease;
    let nonce = fixture.nonce(lease, 0x50);
    let prepared = fixture
        .store
        .prepare_claim(
            EvmOperationPreparationRequestV1::new(
                lease,
                id(0x51),
                id(0x52),
                nonce,
                EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap(),
                NOW + 2,
            ),
            fixture.claim_scope(0x53, 0x54),
        )
        .unwrap()
        .value;
    let mut signer = TestSigner::new(fixture.beneficiary_key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0x55),
                id(0x52),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(lease, id(0x56), id(0x52), signed.revision, NOW + 4),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0x52)).unwrap();
    fixture.rpc.transaction = Some(terminal_transaction(
        &fixture,
        lease,
        &attempted,
        claim_calldata(fixture.opening_call.lock_id, fixture.scalar),
    ));
    fixture.rpc.receipt = Some(final_receipt(
        &attempted,
        false,
        vec![terminal_log(&fixture, &attempted, true)],
    ));
    assert!(matches!(
        fixture.store.observe_current(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0x57),
                id(0x52),
                attempted.revision,
                NOW + 5
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        ),
        Err(EvmActuatorErrorV1::TerminalEventMismatch)
    ));
    assert_eq!(fixture.store.operation(id(0x52)).unwrap(), attempted);

    fixture.rpc.receipt = Some(final_receipt(&attempted, false, vec![]));
    let final_view = fixture
        .store
        .observe_current(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0x58),
                id(0x52),
                attempted.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 5),
        )
        .unwrap()
        .value;
    assert_eq!(final_view.stage, EvmTxStageV1::Final);
    assert_eq!(final_view.execution_success, Some(false));
    assert!(final_view.secret_exposed);
    assert!(final_view.terminal_event_digest.is_none());
    assert!(matches!(
        fixture.store.replace_current(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0x59),
                id(0x52),
                final_view.revision,
                NOW + 6
            ),
            EvmFeesV1::new(30_000_000_000, 1_500_000_000).unwrap(),
            &mut signer,
            || Ok(NOW + 6)
        ),
        Err(EvmActuatorErrorV1::InvalidState)
    ));
}

#[test]
fn schema_v2_is_explicitly_incompatible_and_never_migrated_on_open() {
    let (directory, path) = secure_temp();
    let store = DurableEvmActuatorV1::create(&path).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("UPDATE evm_schema SET version=2 WHERE singleton=1", [])
        .unwrap();
    connection.pragma_update(None, "user_version", 2).unwrap();
    drop(connection);
    assert!(matches!(
        DurableEvmActuatorV1::open_existing(&path),
        Err(EvmActuatorErrorV1::CorruptState)
    ));
    let connection = rusqlite::Connection::open(&path).unwrap();
    let version: i64 = connection
        .query_row(
            "SELECT version FROM evm_schema WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let user_version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!((version, user_version), (2, 2));
    drop(connection);
    drop(directory);
}

#[test]
fn erc20_broadcast_expiry_after_rpc_preserves_nonce_allowance_clock_and_revision() {
    let mut fixture = Fixture::new(EVM_TOKEN);
    let nonce = fixture.nonce();
    fixture.rpc.allowance = word_u128(100);
    fixture
        .store
        .refresh_finalized_allowance(
            EvmObservationMutationRequestV1::new(
                fixture.lease,
                id(0xc1),
                0,
                NOW + 2,
                OBSERVATION_MS,
            ),
            &fixture.deployment,
            &mut fixture.rpc,
            || Ok(NOW + 2),
        )
        .unwrap();
    let (scope, _) = fixture.scope(0xc6, 0xc7, 60);
    let prepared = fixture
        .store
        .prepare_open(
            EvmOperationPreparationRequestV1::new(
                fixture.lease,
                id(0xc3),
                id(0xc2),
                nonce,
                EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap(),
                NOW + 3,
            ),
            &scope,
        )
        .unwrap()
        .value;
    let signed = sign_current(&mut fixture, 0xc2, prepared.revision);
    let before = fresh_time_durable_snapshot(&fixture.path, fixture.lease.authority_id());
    let expired = fixture.lease.lease_until_unix_ms() + 1;

    assert!(matches!(
        fixture.store.broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xc8),
                id(0xc2),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(expired),
        ),
        Err(EvmActuatorErrorV1::StaleFencing)
    ));
    assert!(fixture.rpc.sent.is_empty());
    assert_eq!(fixture.store.operation(id(0xc2)).unwrap(), signed);
    assert_eq!(
        fresh_time_durable_snapshot(&fixture.path, fixture.lease.authority_id()),
        before
    );
}

#[test]
fn refund_broadcast_expiry_after_deadline_lookup_is_zero_write() {
    let mut fixture = TerminalFixture::new();
    let lease = fixture.funder_lease;
    let nonce = fixture.nonce(lease, 0xd1);
    let scope = fixture.refund_scope(0xd2, 0xd3);
    fixture.rpc.finalized_timestamp = scope.deadline();
    let prepared = fixture
        .store
        .prepare_refund(
            EvmOperationPreparationRequestV1::new(
                lease,
                id(0xd5),
                id(0xd4),
                nonce,
                EvmFeesV1::new(20_000_000_000, 1_000_000_000).unwrap(),
                NOW + 2,
            ),
            &scope,
            &mut fixture.rpc,
            || Ok(NOW + 2),
        )
        .unwrap()
        .value;
    let mut signer = TestSigner::new(fixture.funder_key.clone());
    let signed = fixture
        .store
        .sign_prepared(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0xd6),
                id(0xd4),
                prepared.revision,
                NOW + 3,
            ),
            &mut signer,
            || Ok(NOW + 3),
        )
        .unwrap()
        .value;
    let before = fresh_time_durable_snapshot(&fixture.path, lease.authority_id());

    assert!(matches!(
        fixture.store.broadcast_current(
            EvmOperationMutationRequestV1::new(
                lease,
                id(0xd7),
                id(0xd4),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(lease.lease_until_unix_ms() + 1),
        ),
        Err(EvmActuatorErrorV1::StaleFencing)
    ));
    assert!(fixture.rpc.sent.is_empty());
    assert_eq!(fixture.store.operation(id(0xd4)).unwrap(), signed);
    assert_eq!(
        fresh_time_durable_snapshot(&fixture.path, lease.authority_id()),
        before
    );
}

#[test]
fn observation_expiry_after_lookup_preserves_clock_and_operation_revision() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0xe0);
    let signed = sign_current(&mut fixture, 0xe0, prepared.revision);
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xe4),
                id(0xe0),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0xe0)).unwrap();
    let before = fresh_time_durable_snapshot(&fixture.path, fixture.lease.authority_id());
    let expired = fixture.lease.lease_until_unix_ms() + 1;

    assert!(matches!(
        fixture.store.observe_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xe5),
                id(0xe0),
                attempted.revision,
                NOW + 5,
            ),
            &mut fixture.rpc,
            || Ok(expired),
        ),
        Err(EvmActuatorErrorV1::StaleFencing)
    ));
    assert_eq!(fixture.store.operation(id(0xe0)).unwrap(), attempted);
    assert_eq!(
        fresh_time_durable_snapshot(&fixture.path, fixture.lease.authority_id()),
        before
    );
}

#[test]
fn takeover_expiry_after_lookup_does_not_refence_or_advance_clock() {
    let mut fixture = Fixture::new(EVM_NATIVE);
    let (_, prepared) = prepare_native(&mut fixture, 0xf0);
    let signed = sign_current(&mut fixture, 0xf0, prepared.revision);
    fixture
        .store
        .broadcast_current(
            EvmOperationMutationRequestV1::new(
                fixture.lease,
                id(0xf4),
                id(0xf0),
                signed.revision,
                NOW + 4,
            ),
            &mut fixture.rpc,
            || Ok(NOW + 4),
        )
        .unwrap();
    let attempted = fixture.store.operation(id(0xf0)).unwrap();
    let takeover_now = fixture.lease.lease_until_unix_ms() + 1;
    let takeover = fixture
        .store
        .acquire_lease(&fixture.deployment, id(0xf5), takeover_now, LEASE_MS)
        .unwrap()
        .lease();
    let before = fresh_time_durable_snapshot(&fixture.path, takeover.authority_id());

    assert!(matches!(
        fixture.store.reconcile_takeover(
            EvmOperationMutationRequestV1::new(
                takeover,
                id(0xf6),
                id(0xf0),
                attempted.revision,
                takeover_now + 1,
            ),
            &mut fixture.rpc,
            || Ok(takeover.lease_until_unix_ms() + 1),
        ),
        Err(EvmActuatorErrorV1::StaleFencing)
    ));
    assert_eq!(fixture.store.operation(id(0xf0)).unwrap(), attempted);
    assert_eq!(
        fresh_time_durable_snapshot(&fixture.path, takeover.authority_id()),
        before
    );
}
