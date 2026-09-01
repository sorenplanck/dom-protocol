//! Durable production authority proving both composed-route refund exits.
//!
//! A route snapshot is deliberately insufficient evidence here. Each arm
//! operation reauthenticates the exact DOM final-refund artifact and either an
//! armed Bitcoin prebroadcast store or the exact EVM timeout path against its
//! live deployment. Only then is one MAC-authenticated receipt committed.

#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use adapter_btc::types::BitcoinNetworkV1;
use adapter_btc_live::{
    bitcoin_signet_challenge_digest_v1, ArmedBitcoinFundingV1, BitcoinCoreNetworkV1,
    BitcoinCoreRpcClientV1, BitcoinPrebroadcastStoreV1, LiveBitcoinError, ReopenedBitcoinFundingV1,
};
use adapter_evm::rpc::HttpJsonRpc;
use adapter_evm::{
    adaptor_address, derive_binding, derive_lock_id, keccak256, EvmAdapter, JsonRpc, LockTerms,
    UnsignedEvmCall,
};
use blake2::digest::{consts::U32, KeyInit, Mac, Update, VariableOutput};
use blake2::{Blake2bMac, Blake2bVar};
use chain_profile::ChainKindV1;
use deployment_registry::{
    AssetRepresentationV1, ResolvedBitcoinDeploymentV1, ResolvedEvmDeploymentV1,
};
use dom_actuator::{DomContractsActuatorV1, DomSessionBindingV1};
use dom_adaptor::TrustedChainIdV1;
use dom_scriptless_store::{ContractsSessionStoreV1, SessionStoreError};
use evm_actuator::ScopedEvmRefundV1;
use fs2::FileExt;
use kaystra_core::terms::SettlementTermsV1;
use kaystra_core::types::TimelockSpec;
use route_composer::ComposedBindingV2;
use route_executor::{
    ActionProgressV1, CoordinationPhaseV1, Digest32, FrozenBindingsV1, HealthStateV1, LegIdV1,
    RefundBindingsV1, RouteIdV1, SecretVisibilityV1,
};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use zeroize::{Zeroize, Zeroizing};

use crate::admission::AuthenticatedRouteAdmissionV1;
#[cfg(not(any(feature = "development", feature = "simulation", test)))]
use crate::supervisor::authority_seal;
use crate::supervisor::{AuthorityRefusalV1, RefundArmingAuthority, RefundArmingRequestV1};

const ZERO_DIGEST: Digest32 = [0; 32];
const SCHEMA_VERSION: u32 = 1;
const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
const META_DOMAIN: &[u8] = b"DOM-INTEROP/REFUND-ARMING/META/V1\0";
const RECEIPT_DOMAIN: &[u8] = b"DOM-INTEROP/REFUND-ARMING/RECEIPT/V1\0";
const LEG_DOMAIN: &[u8] = b"DOM-INTEROP/REFUND-ARMING/LEG/V1\0";
const DOM_FACE_DOMAIN: &[u8] = b"DOM-INTEROP/REFUND-ARMING/DOM-FACE/V1\0";
const BTC_FACE_DOMAIN: &[u8] = b"DOM-INTEROP/REFUND-ARMING/BTC-FACE/V1\0";
const BTC_ROUTE_DOMAIN: &[u8] = b"DOM-INTEROP/REFUND-ARMING/BTC-ROUTE/V1\0";
const EVM_FACE_DOMAIN: &[u8] = b"DOM-INTEROP/REFUND-ARMING/EVM-FACE/V1\0";
const EVM_EFFECT_DOMAIN: &[u8] = b"DOM-INTEROP/REFUND-ARMING/EVM-EFFECT/V1\0";
const CONFIG_DOMAIN: &[u8] = b"DOM-INTEROP/REFUND-ARMING/CONFIG/V1\0";
const MAX_RECORD_BYTES: usize = 16 * 1024;
const APPLICATION_ID: u32 = 0x444f_4d52;
const META_TABLE_SQL: &str = "CREATE TABLE refund_arming_meta(id INTEGER PRIMARY KEY CHECK(id = 1),bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 16384),tag BLOB NOT NULL CHECK(length(tag) = 32)) STRICT";
const RECEIPT_TABLE_SQL: &str = "CREATE TABLE refund_arming_receipt(id INTEGER PRIMARY KEY CHECK(id = 1),bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 16384),tag BLOB NOT NULL CHECK(length(tag) = 32)) STRICT";

type Blake2bMac256 = Blake2bMac<U32>;

/// Secret authentication credential for the refund-arming journal.
///
/// It has no codec, `Clone`, `Copy`, equality, or `Debug` implementation.
pub struct ProductionRefundArmingCredentialV1(Zeroizing<[u8; 32]>);

impl ProductionRefundArmingCredentialV1 {
    /// Imports one independently provisioned, nonzero owner credential.
    #[cfg(test)]
    pub fn new(bytes: [u8; 32]) -> Result<Self, ProductionRefundArmingOpenErrorV1> {
        Self::import_zeroizing(Zeroizing::new(bytes))
    }

    /// Imports the production credential by move without a plaintext stack copy.
    pub fn import_zeroizing(
        bytes: Zeroizing<[u8; 32]>,
    ) -> Result<Self, ProductionRefundArmingOpenErrorV1> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
        }
        Ok(Self(bytes))
    }
}

/// Fail-closed construction/opening errors. No path or secret is retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionRefundArmingOpenErrorV1 {
    /// Route, topology, authority owner, epoch, or source facts are invalid.
    #[error("invalid refund-arming configuration")]
    InvalidConfiguration,
    /// The owner-only journal cannot be opened or exclusively locked.
    #[error("refund-arming journal unavailable")]
    Unavailable,
    /// Durable bytes, authentication, or immutable configuration disagree.
    #[error("refund-arming journal is inconsistent")]
    Inconsistent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaceEvidenceV1 {
    kind: u8,
    route_id: RouteIdV1,
    settlement_id: Digest32,
    session_id: Digest32,
    terms_digest: Digest32,
    chain_digest: Digest32,
    deployment_digest: Digest32,
    primary_artifact_digest: Digest32,
    secondary_artifact_digest: Digest32,
    evidence_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaceBindingIdentityV1 {
    kind: u8,
    route_id: RouteIdV1,
    settlement_id: Digest32,
    session_id: Digest32,
    terms_digest: Digest32,
    chain_digest: Digest32,
    deployment_digest: Digest32,
}

impl FaceEvidenceV1 {
    const fn binding_identity(self) -> FaceBindingIdentityV1 {
        FaceBindingIdentityV1 {
            kind: self.kind,
            route_id: self.route_id,
            settlement_id: self.settlement_id,
            session_id: self.session_id,
            terms_digest: self.terms_digest,
            chain_digest: self.chain_digest,
            deployment_digest: self.deployment_digest,
        }
    }
}

trait ProductionRefundFaceVerifierV1 {
    fn static_digest(&self) -> Digest32;
    fn binding_identity(&self) -> Result<FaceBindingIdentityV1, AuthorityRefusalV1>;
    fn verify(&self) -> Result<FaceEvidenceV1, AuthorityRefusalV1>;
}

/// DOM face backed by one retained Contracts session store.
pub struct ProductionDomRefundFaceV1 {
    store: Rc<ContractsSessionStoreV1>,
    binding: DomSessionBindingV1,
    trusted_chain_id: TrustedChainIdV1,
}

impl ProductionDomRefundFaceV1 {
    /// Binds the route/session/terms authority to an already-open store.
    pub fn new(
        store: Rc<ContractsSessionStoreV1>,
        binding: DomSessionBindingV1,
        trusted_chain_id: TrustedChainIdV1,
    ) -> Result<Self, ProductionRefundArmingOpenErrorV1> {
        if trusted_chain_id.as_bytes() != &binding.chain_id()
            || DomContractsActuatorV1::bind(store.as_ref(), binding).is_err()
        {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            store,
            binding,
            trusted_chain_id,
        })
    }
}

/// Bitcoin face backed by the only store state that can release funding.
pub struct ProductionBitcoinRefundFaceV1 {
    store: Rc<BitcoinPrebroadcastStoreV1>,
    rpc: Rc<BitcoinCoreRpcClientV1>,
    deployment: ResolvedBitcoinDeploymentV1,
    expected: BitcoinExpectedRefundV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BitcoinExpectedRefundV1 {
    route_binding: Digest32,
    plan_digest: Digest32,
    prepared_record_digest: Digest32,
    summary_record_digest: Digest32,
    refund_record_digest: Digest32,
    funding_txid: Digest32,
    refund_txid: Digest32,
    contract_vout: u32,
    contract_amount_sat: u64,
    refund_delay_sequence: u32,
    canonical_refund_digest: Digest32,
}

impl ProductionBitcoinRefundFaceV1 {
    /// Captures only public commitments from a genuine move-only Armed handle.
    pub fn new(
        store: Rc<BitcoinPrebroadcastStoreV1>,
        rpc: Rc<BitcoinCoreRpcClientV1>,
        deployment: ResolvedBitcoinDeploymentV1,
        armed: &ArmedBitcoinFundingV1,
    ) -> Result<Self, ProductionRefundArmingOpenErrorV1> {
        validate_bitcoin_deployment(&rpc, &deployment)?;
        let summary = armed.funding_summary();
        let expected = BitcoinExpectedRefundV1 {
            route_binding: summary.route_binding(),
            plan_digest: summary.plan_digest(),
            prepared_record_digest: armed.prepared_record_digest(),
            summary_record_digest: summary.summary_record_digest(),
            refund_record_digest: armed.refund_record_digest(),
            funding_txid: armed.funding_txid(),
            refund_txid: armed.refund_txid(),
            contract_vout: summary.contract_vout(),
            contract_amount_sat: summary.contract_amount_sat(),
            refund_delay_sequence: summary.refund_delay().sequence(),
            canonical_refund_digest: digest_parts(
                BTC_FACE_DOMAIN,
                &[armed.canonical_refund_transaction()],
            )
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?,
        };
        if expected.route_binding == ZERO_DIGEST
            || expected.refund_record_digest == ZERO_DIGEST
            || expected.canonical_refund_digest == ZERO_DIGEST
        {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            store,
            rpc,
            deployment,
            expected,
        })
    }
}

/// EVM face bound to an authenticated deployment and live finalized RPC.
pub struct ProductionEvmRefundFaceV1 {
    adapter: Rc<EvmAdapter<HttpJsonRpc>>,
    identity_rpc: HttpJsonRpc,
    deployment: ResolvedEvmDeploymentV1,
}

impl ProductionEvmRefundFaceV1 {
    /// Builds two redacted clients for one endpoint: the adapter proves chain
    /// id/codehash and the independent identity query proves exact genesis.
    pub fn connect(
        endpoint: impl Into<String>,
        timeout_seconds: u64,
        deployment: ResolvedEvmDeploymentV1,
    ) -> Result<Self, ProductionRefundArmingOpenErrorV1> {
        if timeout_seconds == 0 {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
        }
        let endpoint = endpoint.into();
        if endpoint.is_empty() {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
        }
        let adapter = EvmAdapter::new(
            deployment.adapter_config(),
            HttpJsonRpc::new(endpoint.clone(), timeout_seconds),
        )
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
        Ok(Self {
            adapter: Rc::new(adapter),
            identity_rpc: HttpJsonRpc::new(endpoint, timeout_seconds),
            deployment,
        })
    }
}

/// Closed production set of supported counterparty refund mechanisms.
pub enum ProductionCounterpartyRefundFaceV1 {
    /// Armed Bitcoin Core prebroadcast state.
    Bitcoin(ProductionBitcoinRefundFaceV1),
    /// Exact EVM escrow timeout path.
    Evm(ProductionEvmRefundFaceV1),
}

/// Derives the only btc-live route binding accepted by this authority.
///
/// Funding preparation must use this value before an `ArmedBitcoinFundingV1`
/// can exist. The derivation consumes the authenticated V2 composition order,
/// exact settlement bytes and registry deployment facts; a caller cannot
/// substitute a free-form digest later at the arming boundary.
pub fn production_bitcoin_refund_route_binding_v1(
    route_id: RouteIdV1,
    composition: &ComposedBindingV2,
    leg: LegIdV1,
    deployment: &ResolvedBitcoinDeploymentV1,
) -> Result<Digest32, ProductionRefundArmingOpenErrorV1> {
    if route_id == ZERO_DIGEST {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    let settlement = match leg {
        LegIdV1::Upstream => composition.upstream(),
        LegIdV1::Downstream => composition.downstream(),
    };
    if deployment.profile().chain_id.0 != settlement.counterparty_leg.chain_id.0
        || deployment.profile_digest() != settlement.counterparty_leg.adapter_profile_hash
        || deployment.asset_binding().asset_id != settlement.counterparty_leg.asset_id
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    bitcoin_route_binding(
        route_id,
        composition.binding_digest(),
        leg,
        settlement,
        deployment,
    )
}

/// Both chain faces of one settlement, kept in their canonical leg position.
pub struct ProductionRefundLegV1 {
    dom: ProductionDomRefundFaceV1,
    counterparty: ProductionCounterpartyRefundFaceV1,
}

/// One-shot construction bundle that keeps route authorities and exact leg order together.
pub struct ProductionRefundArmingSourcesV1<'a> {
    admission: &'a AuthenticatedRouteAdmissionV1,
    composition: &'a ComposedBindingV2,
    owner_id: Digest32,
    authority_epoch: u64,
    upstream: ProductionRefundLegV1,
    downstream: ProductionRefundLegV1,
}

impl<'a> ProductionRefundArmingSourcesV1<'a> {
    /// Freezes the two canonical legs under one nonzero owner and authority epoch.
    pub fn new(
        admission: &'a AuthenticatedRouteAdmissionV1,
        composition: &'a ComposedBindingV2,
        owner_id: Digest32,
        authority_epoch: u64,
        upstream: ProductionRefundLegV1,
        downstream: ProductionRefundLegV1,
    ) -> Result<Self, ProductionRefundArmingOpenErrorV1> {
        if owner_id == ZERO_DIGEST || authority_epoch == 0 {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            admission,
            composition,
            owner_id,
            authority_epoch,
            upstream,
            downstream,
        })
    }
}

impl ProductionRefundLegV1 {
    /// Joins one DOM face to exactly one counterparty face.
    pub fn new(
        dom: ProductionDomRefundFaceV1,
        counterparty: ProductionCounterpartyRefundFaceV1,
    ) -> Self {
        Self { dom, counterparty }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RefundArmingConfigV1 {
    route_id: RouteIdV1,
    composition_v2_digest: Digest32,
    frozen: FrozenBindingsV1,
    upstream_terms_digest: Digest32,
    downstream_terms_digest: Digest32,
    owner_id: Digest32,
    authority_epoch: u64,
    topology_digest: Digest32,
    config_digest: Digest32,
}

struct BoundRefundLegV1 {
    dom: Box<dyn ProductionRefundFaceVerifierV1>,
    counterparty: Box<dyn ProductionRefundFaceVerifierV1>,
    descriptor_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdmissionFacePinsV1 {
    registry_digest: Digest32,
    registry_epoch: u64,
    dom_profile_digest: Digest32,
    dom_asset_binding_digest: Digest32,
    counterparty_profile_digest: Digest32,
    counterparty_asset_binding_digest: Digest32,
    frozen_terms_digest: Digest32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetainedFileIdentityV1 {
    device: u64,
    inode: u64,
}

struct OpenedRefundDatabaseV1 {
    connection: Connection,
    lock: File,
    database: File,
    database_identity: RetainedFileIdentityV1,
    lock_identity: RetainedFileIdentityV1,
    lock_path: PathBuf,
}

/// Durable, exclusively locked production implementation of `RefundArmingAuthority`.
pub struct ProductionRefundArmingAuthorityV1 {
    connection: Connection,
    database: File,
    lock: File,
    database_path: PathBuf,
    lock_path: PathBuf,
    database_identity: RetainedFileIdentityV1,
    lock_identity: RetainedFileIdentityV1,
    credential: ProductionRefundArmingCredentialV1,
    config: RefundArmingConfigV1,
    upstream: BoundRefundLegV1,
    downstream: BoundRefundLegV1,
    #[cfg(test)]
    fault: RefundArmingFaultV1,
}

impl core::fmt::Debug for ProductionRefundArmingAuthorityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionRefundArmingAuthorityV1([authorities redacted])")
    }
}

struct BoundDomRefundFaceV1 {
    inner: ProductionDomRefundFaceV1,
    settlement_id: Digest32,
    static_digest: Digest32,
}

impl ProductionRefundFaceVerifierV1 for BoundDomRefundFaceV1 {
    fn static_digest(&self) -> Digest32 {
        self.static_digest
    }

    fn binding_identity(&self) -> Result<FaceBindingIdentityV1, AuthorityRefusalV1> {
        Ok(FaceBindingIdentityV1 {
            kind: 1,
            route_id: self.inner.binding.route_id(),
            settlement_id: self.settlement_id,
            session_id: self.inner.binding.session_id(),
            terms_digest: self.inner.binding.terms_digest(),
            chain_digest: self.inner.binding.chain_id(),
            deployment_digest: self.inner.binding.deployment_digest(),
        })
    }

    fn verify(&self) -> Result<FaceEvidenceV1, AuthorityRefusalV1> {
        DomContractsActuatorV1::bind(self.inner.store.as_ref(), self.inner.binding)
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        let artifact = self
            .inner
            .store
            .prepare_operational_final_refund_transport_authority(
                self.inner.trusted_chain_id,
                self.inner.binding.session_id(),
            )
            .map_err(map_dom_error)?;
        if artifact.session_id() != &self.inner.binding.session_id()
            || artifact.refund_tx_hash() == &ZERO_DIGEST
            || artifact.final_refund_payload().is_empty()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let payload_digest = digest_parts(DOM_FACE_DOMAIN, &[artifact.final_refund_payload()])?;
        let evidence_digest = digest_parts(
            DOM_FACE_DOMAIN,
            &[
                &self.static_digest,
                artifact.refund_tx_hash(),
                &payload_digest,
            ],
        )?;
        Ok(FaceEvidenceV1 {
            kind: 1,
            route_id: self.inner.binding.route_id(),
            settlement_id: self.settlement_id,
            session_id: self.inner.binding.session_id(),
            terms_digest: self.inner.binding.terms_digest(),
            chain_digest: self.inner.binding.chain_id(),
            deployment_digest: self.inner.binding.deployment_digest(),
            primary_artifact_digest: *artifact.refund_tx_hash(),
            secondary_artifact_digest: payload_digest,
            evidence_digest,
        })
    }
}

struct BoundBitcoinRefundFaceV1 {
    inner: ProductionBitcoinRefundFaceV1,
    route_id: RouteIdV1,
    settlement_id: Digest32,
    session_id: Digest32,
    terms_digest: Digest32,
    chain_digest: Digest32,
    static_digest: Digest32,
}

impl ProductionRefundFaceVerifierV1 for BoundBitcoinRefundFaceV1 {
    fn static_digest(&self) -> Digest32 {
        self.static_digest
    }

    fn binding_identity(&self) -> Result<FaceBindingIdentityV1, AuthorityRefusalV1> {
        Ok(FaceBindingIdentityV1 {
            kind: 2,
            route_id: self.route_id,
            settlement_id: self.settlement_id,
            session_id: self.session_id,
            terms_digest: self.terms_digest,
            chain_digest: self.chain_digest,
            deployment_digest: self.inner.deployment.registry_digest(),
        })
    }

    fn verify(&self) -> Result<FaceEvidenceV1, AuthorityRefusalV1> {
        validate_bitcoin_deployment(&self.inner.rpc, &self.inner.deployment)
            .map_err(map_open_error)?;
        let reopened = self
            .inner
            .store
            .reopen(&self.inner.rpc, self.inner.expected.route_binding)
            .map_err(map_bitcoin_error)?
            .ok_or(AuthorityRefusalV1::Inconsistent)?;
        let ReopenedBitcoinFundingV1::Armed(armed) = reopened else {
            return Err(AuthorityRefusalV1::Refused);
        };
        let summary = armed.funding_summary();
        let refund_digest = digest_parts(BTC_FACE_DOMAIN, &[armed.canonical_refund_transaction()])?;
        let actual = BitcoinExpectedRefundV1 {
            route_binding: summary.route_binding(),
            plan_digest: summary.plan_digest(),
            prepared_record_digest: armed.prepared_record_digest(),
            summary_record_digest: summary.summary_record_digest(),
            refund_record_digest: armed.refund_record_digest(),
            funding_txid: armed.funding_txid(),
            refund_txid: armed.refund_txid(),
            contract_vout: summary.contract_vout(),
            contract_amount_sat: summary.contract_amount_sat(),
            refund_delay_sequence: summary.refund_delay().sequence(),
            canonical_refund_digest: refund_digest,
        };
        if actual != self.inner.expected {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let evidence_digest = bitcoin_evidence_digest(&actual, self.static_digest)?;
        Ok(FaceEvidenceV1 {
            kind: 2,
            route_id: self.route_id,
            settlement_id: self.settlement_id,
            session_id: self.session_id,
            terms_digest: self.terms_digest,
            chain_digest: self.chain_digest,
            deployment_digest: self.inner.deployment.registry_digest(),
            primary_artifact_digest: actual.refund_record_digest,
            secondary_artifact_digest: actual.canonical_refund_digest,
            evidence_digest,
        })
    }
}

struct BoundEvmRefundFaceV1 {
    inner: ProductionEvmRefundFaceV1,
    route_id: RouteIdV1,
    settlement_id: Digest32,
    terms_digest: Digest32,
    semantic_scope: Digest32,
    opening_call: UnsignedEvmCall,
    refund_scope: ScopedEvmRefundV1,
    static_digest: Digest32,
}

impl ProductionRefundFaceVerifierV1 for BoundEvmRefundFaceV1 {
    fn static_digest(&self) -> Digest32 {
        self.static_digest
    }

    fn binding_identity(&self) -> Result<FaceBindingIdentityV1, AuthorityRefusalV1> {
        let config = self.inner.deployment.adapter_config();
        Ok(FaceBindingIdentityV1 {
            kind: 3,
            route_id: self.route_id,
            settlement_id: self.settlement_id,
            session_id: config.session_id,
            terms_digest: self.terms_digest,
            chain_digest: digest_parts(EVM_FACE_DOMAIN, &[&config.chain_id.to_be_bytes()])?,
            deployment_digest: self.inner.deployment.registry_digest(),
        })
    }

    fn verify(&self) -> Result<FaceEvidenceV1, AuthorityRefusalV1> {
        if self.inner.adapter.config() != &self.inner.deployment.adapter_config() {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        self.inner.adapter.preflight().map_err(map_evm_error)?;
        validate_evm_genesis(&self.inner.identity_rpc, &self.inner.deployment)?;
        let recomputed = scoped_evm_refund(
            self.route_id,
            self.settlement_id,
            self.semantic_scope,
            self.inner.deployment,
            self.opening_call.clone(),
        )?;
        if recomputed.lock_id() != self.refund_scope.lock_id()
            || recomputed.funder() != self.refund_scope.funder()
            || recomputed.deadline() != self.refund_scope.deadline()
            || recomputed.calldata_digest() != self.refund_scope.calldata_digest()
        {
            return Err(AuthorityRefusalV1::Inconsistent);
        }
        let config = self.inner.deployment.adapter_config();
        let opening_digest = keccak256(&self.opening_call.encode());
        let refund_digest = recomputed.calldata_digest();
        let evidence_digest = digest_parts(
            EVM_FACE_DOMAIN,
            &[
                &self.static_digest,
                &opening_digest,
                &recomputed.lock_id(),
                &refund_digest,
                &recomputed.deadline().to_be_bytes(),
            ],
        )?;
        Ok(FaceEvidenceV1 {
            kind: 3,
            route_id: self.route_id,
            settlement_id: self.settlement_id,
            session_id: config.session_id,
            terms_digest: self.terms_digest,
            chain_digest: digest_parts(EVM_FACE_DOMAIN, &[&config.chain_id.to_be_bytes()])?,
            deployment_digest: self.inner.deployment.registry_digest(),
            primary_artifact_digest: recomputed.lock_id(),
            secondary_artifact_digest: refund_digest,
            evidence_digest,
        })
    }
}

fn bind_dom_face(
    face: ProductionDomRefundFaceV1,
    route_id: RouteIdV1,
    settlement: &SettlementTermsV1,
    pins: AdmissionFacePinsV1,
) -> Result<Box<dyn ProductionRefundFaceVerifierV1>, ProductionRefundArmingOpenErrorV1> {
    let terms_digest = settlement
        .terms_hash()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    if face.binding.route_id() != route_id
        || face.binding.session_id() != settlement.session_id.0
        || face.binding.terms_digest() != terms_digest
        || face.binding.chain_id() != settlement.dom_leg.chain_id.0
        || face.binding.profile_digest() != settlement.dom_leg.adapter_profile_hash
        || validate_dom_admission_pins(face.binding, pins).is_err()
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    let static_digest = digest_parts(
        DOM_FACE_DOMAIN,
        &[
            &route_id,
            &settlement.settlement_id.0,
            &face.binding.session_id(),
            &terms_digest,
            &face.binding.chain_id(),
            &face.binding.genesis_hash(),
            &face.binding.profile_digest(),
            &face.binding.deployment_digest(),
            &face.binding.asset_binding_digest(),
            &face.binding.registry_epoch().to_be_bytes(),
        ],
    )
    .map_err(map_authority_open)?;
    Ok(Box::new(BoundDomRefundFaceV1 {
        inner: face,
        settlement_id: settlement.settlement_id.0,
        static_digest,
    }))
}

fn bind_counterparty_face(
    face: ProductionCounterpartyRefundFaceV1,
    route_id: RouteIdV1,
    composition_digest: Digest32,
    leg: LegIdV1,
    settlement: &SettlementTermsV1,
    pins: AdmissionFacePinsV1,
) -> Result<Box<dyn ProductionRefundFaceVerifierV1>, ProductionRefundArmingOpenErrorV1> {
    match face {
        ProductionCounterpartyRefundFaceV1::Bitcoin(inner) => {
            bind_bitcoin_face(inner, route_id, composition_digest, leg, settlement, pins)
        }
        ProductionCounterpartyRefundFaceV1::Evm(inner) => {
            bind_evm_face(inner, route_id, composition_digest, leg, settlement, pins)
        }
    }
}

fn bind_bitcoin_face(
    inner: ProductionBitcoinRefundFaceV1,
    route_id: RouteIdV1,
    composition_digest: Digest32,
    leg: LegIdV1,
    settlement: &SettlementTermsV1,
    pins: AdmissionFacePinsV1,
) -> Result<Box<dyn ProductionRefundFaceVerifierV1>, ProductionRefundArmingOpenErrorV1> {
    let terms_digest = settlement
        .terms_hash()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    let expected_route_binding = bitcoin_route_binding(
        route_id,
        composition_digest,
        leg,
        settlement,
        &inner.deployment,
    )?;
    if inner.expected.route_binding != expected_route_binding
        || inner.expected.contract_amount_sat
            != u64::try_from(settlement.counterparty_leg.amount)
                .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?
        || !bitcoin_delay_matches(
            settlement.counterparty_leg.deadline,
            inner.expected.refund_delay_sequence,
        )
        || inner.deployment.profile_digest() != settlement.counterparty_leg.adapter_profile_hash
        || inner.deployment.asset_binding().asset_id != settlement.counterparty_leg.asset_id
        || validate_bitcoin_admission_pins(&inner.deployment, pins).is_err()
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    let chain_digest = inner.deployment.profile().chain_id.0;
    if chain_digest != settlement.counterparty_leg.chain_id.0 {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    let static_digest = bitcoin_static_digest(&inner, route_id, settlement, terms_digest)?;
    Ok(Box::new(BoundBitcoinRefundFaceV1 {
        inner,
        route_id,
        settlement_id: settlement.settlement_id.0,
        session_id: settlement.session_id.0,
        terms_digest,
        chain_digest,
        static_digest,
    }))
}

fn bind_evm_face(
    inner: ProductionEvmRefundFaceV1,
    route_id: RouteIdV1,
    composition_digest: Digest32,
    leg: LegIdV1,
    settlement: &SettlementTermsV1,
    pins: AdmissionFacePinsV1,
) -> Result<Box<dyn ProductionRefundFaceVerifierV1>, ProductionRefundArmingOpenErrorV1> {
    let terms_digest = settlement
        .terms_hash()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    let config = inner.deployment.adapter_config();
    if config.session_id != settlement.session_id.0
        || config.dom_chain_id != settlement.dom_leg.chain_id.0
        || inner.deployment.profile_digest() != settlement.counterparty_leg.adapter_profile_hash
        || inner.deployment.asset_binding().asset_id != settlement.counterparty_leg.asset_id
        || validate_evm_admission_pins(&inner.deployment, pins).is_err()
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    let deadline = match settlement.counterparty_leg.deadline {
        TimelockSpec::TimestampSeconds { value } if value != 0 => value,
        TimelockSpec::BlockHeight { .. }
        | TimelockSpec::BtcTime512s { .. }
        | TimelockSpec::TimestampSeconds { .. } => {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        }
    };
    let mut amount = [0u8; 32];
    amount[16..].copy_from_slice(&settlement.counterparty_leg.amount.to_be_bytes());
    let lock_terms = LockTerms {
        dom_chain_id: config.dom_chain_id,
        direction: config.direction.as_u8(),
        session_id: config.session_id,
        terms_hash: config.terms_hash,
        participants_hash: config.participants_hash,
        asset: config.asset,
        amount,
        beneficiary: config.beneficiary,
        adaptor_address: adaptor_address(&settlement.adaptor_point_sec1)
            .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?,
        deadline,
    };
    if !config.binds_terms(&lock_terms) {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    let binding = derive_binding(config.chain_id, &config.contract, &lock_terms)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    let lock_id = derive_lock_id(&binding, &config.funder)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    let value = match inner.deployment.asset_binding().representation {
        AssetRepresentationV1::Native => amount,
        AssetRepresentationV1::EvmErc20 { token, .. } if token == config.asset => ZERO_DIGEST,
        AssetRepresentationV1::EvmErc20 { .. } => {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        }
    };
    let opening_call = UnsignedEvmCall {
        version: 1,
        chain_id: config.chain_id,
        to: config.contract,
        value,
        gas_limit_hint: config.gas_limit_hint,
        lock_id,
        binding,
        calldata: {
            let mut calldata = Vec::with_capacity(4 + 10 * 32);
            calldata.extend_from_slice(&adapter_evm::abi::selector(adapter_evm::abi::SIG_OPEN));
            calldata.extend_from_slice(
                &adapter_evm::abi::concat_words(&lock_terms.abi_words())
                    .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?,
            );
            calldata
        },
    };
    let refund_scope = scoped_evm_refund(
        route_id,
        settlement.settlement_id.0,
        composition_digest,
        inner.deployment,
        opening_call.clone(),
    )
    .map_err(map_authority_open)?;
    let static_digest = evm_static_digest(
        &inner,
        route_id,
        leg,
        settlement,
        terms_digest,
        &opening_call,
        &refund_scope,
    )?;
    Ok(Box::new(BoundEvmRefundFaceV1 {
        inner,
        route_id,
        settlement_id: settlement.settlement_id.0,
        terms_digest,
        semantic_scope: composition_digest,
        opening_call,
        refund_scope,
        static_digest,
    }))
}

fn validate_dom_admission_pins(
    binding: DomSessionBindingV1,
    pins: AdmissionFacePinsV1,
) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    if binding.deployment_digest() != pins.registry_digest
        || binding.registry_epoch() != pins.registry_epoch
        || binding.profile_digest() != pins.dom_profile_digest
        || binding.asset_binding_digest() != pins.dom_asset_binding_digest
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn validate_bitcoin_admission_pins(
    deployment: &ResolvedBitcoinDeploymentV1,
    pins: AdmissionFacePinsV1,
) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    if deployment.registry_digest() != pins.registry_digest
        || deployment.registry_epoch() != pins.registry_epoch
        || deployment.profile_digest() != pins.counterparty_profile_digest
        || deployment.asset_binding_digest() != pins.counterparty_asset_binding_digest
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn validate_evm_admission_pins(
    deployment: &ResolvedEvmDeploymentV1,
    pins: AdmissionFacePinsV1,
) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    let config = deployment.adapter_config();
    if deployment.registry_digest() != pins.registry_digest
        || deployment.registry_epoch() != pins.registry_epoch
        || deployment.profile_digest() != pins.counterparty_profile_digest
        || deployment.asset_binding_digest() != pins.counterparty_asset_binding_digest
        || config.terms_hash != pins.frozen_terms_digest
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn scoped_evm_refund(
    route_id: RouteIdV1,
    settlement_id: Digest32,
    semantic_scope: Digest32,
    deployment: ResolvedEvmDeploymentV1,
    opening_call: UnsignedEvmCall,
) -> Result<ScopedEvmRefundV1, AuthorityRefusalV1> {
    let effect_id = digest_parts(
        EVM_EFFECT_DOMAIN,
        &[&route_id, &settlement_id, &semantic_scope],
    )?;
    ScopedEvmRefundV1::new(
        route_id,
        effect_id,
        semantic_scope,
        deployment,
        opening_call,
    )
    .map_err(|_| AuthorityRefusalV1::Inconsistent)
}

fn bitcoin_route_binding(
    route_id: RouteIdV1,
    composition_digest: Digest32,
    leg: LegIdV1,
    settlement: &SettlementTermsV1,
    deployment: &ResolvedBitcoinDeploymentV1,
) -> Result<Digest32, ProductionRefundArmingOpenErrorV1> {
    let terms = settlement
        .canonical_bytes()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    digest_parts(
        BTC_ROUTE_DOMAIN,
        &[
            &route_id,
            &composition_digest,
            &[leg_tag(leg)],
            &terms,
            &deployment.registry_digest(),
            &deployment.registry_epoch().to_be_bytes(),
            &deployment.profile_digest(),
            &deployment.asset_binding_digest(),
        ],
    )
    .map_err(map_authority_open)
}

fn bitcoin_delay_matches(deadline: TimelockSpec, sequence: u32) -> bool {
    const TIME_FLAG: u32 = 1 << 22;
    match deadline {
        TimelockSpec::BtcTime512s { value } => {
            u32::try_from(value)
                .ok()
                .and_then(|value| value.checked_add(TIME_FLAG))
                == Some(sequence)
        }
        // Absolute height/timestamp is not the relative BIP68 clock.
        TimelockSpec::BlockHeight { .. } | TimelockSpec::TimestampSeconds { .. } => false,
    }
}

fn bitcoin_static_digest(
    inner: &ProductionBitcoinRefundFaceV1,
    route_id: RouteIdV1,
    settlement: &SettlementTermsV1,
    terms_digest: Digest32,
) -> Result<Digest32, ProductionRefundArmingOpenErrorV1> {
    let deployment = inner.deployment.deployment();
    digest_parts(
        BTC_FACE_DOMAIN,
        &[
            &route_id,
            &settlement.settlement_id.0,
            &settlement.session_id.0,
            &terms_digest,
            &inner.deployment.registry_digest(),
            &inner.deployment.registry_epoch().to_be_bytes(),
            &inner.deployment.profile_digest(),
            &inner.deployment.asset_binding_digest(),
            &deployment.genesis_hash,
            &deployment.signet_challenge,
            &deployment.max_fee_rate_sat_vbyte.to_be_bytes(),
            &deployment.min_relay_fee_sat_kvb.to_be_bytes(),
            &inner.expected.route_binding,
            &inner.expected.plan_digest,
            &inner.expected.prepared_record_digest,
            &inner.expected.summary_record_digest,
            &inner.expected.refund_record_digest,
            &inner.expected.funding_txid,
            &inner.expected.refund_txid,
            &inner.expected.contract_vout.to_be_bytes(),
            &inner.expected.contract_amount_sat.to_be_bytes(),
            &inner.expected.refund_delay_sequence.to_be_bytes(),
            &inner.expected.canonical_refund_digest,
        ],
    )
    .map_err(map_authority_open)
}

fn bitcoin_evidence_digest(
    expected: &BitcoinExpectedRefundV1,
    static_digest: Digest32,
) -> Result<Digest32, AuthorityRefusalV1> {
    digest_parts(
        BTC_FACE_DOMAIN,
        &[
            &static_digest,
            &expected.route_binding,
            &expected.plan_digest,
            &expected.prepared_record_digest,
            &expected.summary_record_digest,
            &expected.refund_record_digest,
            &expected.funding_txid,
            &expected.refund_txid,
            &expected.contract_vout.to_be_bytes(),
            &expected.contract_amount_sat.to_be_bytes(),
            &expected.refund_delay_sequence.to_be_bytes(),
            &expected.canonical_refund_digest,
        ],
    )
}

fn evm_static_digest(
    inner: &ProductionEvmRefundFaceV1,
    route_id: RouteIdV1,
    leg: LegIdV1,
    settlement: &SettlementTermsV1,
    terms_digest: Digest32,
    opening_call: &UnsignedEvmCall,
    refund: &ScopedEvmRefundV1,
) -> Result<Digest32, ProductionRefundArmingOpenErrorV1> {
    let config = inner.deployment.adapter_config();
    digest_parts(
        EVM_FACE_DOMAIN,
        &[
            &route_id,
            &[leg_tag(leg)],
            &settlement.settlement_id.0,
            &settlement.session_id.0,
            &terms_digest,
            &inner.deployment.registry_digest(),
            &inner.deployment.registry_epoch().to_be_bytes(),
            &inner.deployment.profile_digest(),
            &inner.deployment.asset_binding_digest(),
            &config.chain_id.to_be_bytes(),
            &config.contract,
            &config.expected_code_hash,
            &config.asset,
            &config.beneficiary,
            &config.funder,
            &config.session_id,
            &config.terms_hash,
            &config.participants_hash,
            &keccak256(&opening_call.encode()),
            &refund.lock_id(),
            &refund.calldata_digest(),
            &refund.deadline().to_be_bytes(),
        ],
    )
    .map_err(map_authority_open)
}

impl ProductionRefundArmingAuthorityV1 {
    /// Creates the one owner-only journal for this admitted V2 route.
    pub fn create(
        path: &Path,
        credential: ProductionRefundArmingCredentialV1,
        sources: ProductionRefundArmingSourcesV1<'_>,
    ) -> Result<Self, ProductionRefundArmingOpenErrorV1> {
        let (config, upstream, downstream) = bind_configuration(
            sources.admission,
            sources.composition,
            sources.owner_id,
            sources.authority_epoch,
            sources.upstream,
            sources.downstream,
        )?;
        let OpenedRefundDatabaseV1 {
            mut connection,
            lock,
            database,
            database_identity,
            lock_identity,
            lock_path,
        } = open_database(path, true, false)?;
        let meta = encode_config(&config)?;
        let tag = authenticate(&credential, META_DOMAIN, &meta)?;
        initialize_schema(&mut connection, &meta, &tag)?;
        sync_parent(path)?;
        let authority = Self {
            connection,
            database,
            lock,
            database_path: path.to_path_buf(),
            lock_path,
            database_identity,
            lock_identity,
            credential,
            config,
            upstream,
            downstream,
            #[cfg(test)]
            fault: RefundArmingFaultV1::None,
        };
        authority.audit_authority()?;
        Ok(authority)
    }

    /// Reopens and authenticates the journal against freshly supplied authorities.
    pub fn open_existing(
        path: &Path,
        credential: ProductionRefundArmingCredentialV1,
        sources: ProductionRefundArmingSourcesV1<'_>,
    ) -> Result<Self, ProductionRefundArmingOpenErrorV1> {
        let (config, upstream, downstream) = bind_configuration(
            sources.admission,
            sources.composition,
            sources.owner_id,
            sources.authority_epoch,
            sources.upstream,
            sources.downstream,
        )?;
        let OpenedRefundDatabaseV1 {
            connection,
            lock,
            database,
            database_identity,
            lock_identity,
            lock_path,
        } = open_database(path, false, false)?;
        validate_schema(&connection)?;
        let retained: Option<(Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT bytes, tag FROM refund_arming_meta WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
        let (meta, tag) = retained.ok_or(ProductionRefundArmingOpenErrorV1::Inconsistent)?;
        verify_authenticated(&credential, META_DOMAIN, &meta, &tag)?;
        if meta != encode_config(&config)? {
            return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
        }
        let authority = Self {
            connection,
            database,
            lock,
            database_path: path.to_path_buf(),
            lock_path,
            database_identity,
            lock_identity,
            credential,
            config,
            upstream,
            downstream,
            #[cfg(test)]
            fault: RefundArmingFaultV1::None,
        };
        authority.audit_authority()?;
        Ok(authority)
    }

    /// Resumes only the two strict pre-commit creation boundaries.
    ///
    /// The persistent lock must already exist exactly. The database may be
    /// absent (crash after lock publication), empty, pristine SQLite, or the
    /// exact fully initialized journal for these same authorities.
    pub fn resume_create_production(
        path: &Path,
        credential: ProductionRefundArmingCredentialV1,
        sources: ProductionRefundArmingSourcesV1<'_>,
    ) -> Result<Self, ProductionRefundArmingOpenErrorV1> {
        let (config, upstream, downstream) = bind_configuration(
            sources.admission,
            sources.composition,
            sources.owner_id,
            sources.authority_epoch,
            sources.upstream,
            sources.downstream,
        )?;
        let OpenedRefundDatabaseV1 {
            mut connection,
            lock,
            database,
            database_identity,
            lock_identity,
            lock_path,
        } = open_database(path, false, true)?;
        let meta = encode_config(&config)?;
        let tag = authenticate(&credential, META_DOMAIN, &meta)?;
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
        let objects: u32 = connection
            .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
        if version == 0 && objects == 0 {
            initialize_schema(&mut connection, &meta, &tag)?;
            sync_parent(path)?;
        } else {
            validate_schema(&connection)?;
            let retained: (Vec<u8>, Vec<u8>) = connection
                .query_row(
                    "SELECT bytes, tag FROM refund_arming_meta WHERE id = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
            verify_authenticated(&credential, META_DOMAIN, &retained.0, &retained.1)?;
            if retained.0 != meta {
                return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
            }
        }
        let authority = Self {
            connection,
            database,
            lock,
            database_path: path.to_path_buf(),
            lock_path,
            database_identity,
            lock_identity,
            credential,
            config,
            upstream,
            downstream,
            #[cfg(test)]
            fault: RefundArmingFaultV1::None,
        };
        authority.audit_authority()?;
        Ok(authority)
    }

    fn arm_refunds_inner(
        &mut self,
        request: RefundArmingRequestV1<'_>,
    ) -> Result<RefundBindingsV1, AuthorityRefusalV1> {
        let context = validate_request(&self.config, &request)?;
        self.arm_verified(context)
    }

    fn arm_verified(
        &mut self,
        context: ValidatedArmingRequestV1,
    ) -> Result<RefundBindingsV1, AuthorityRefusalV1> {
        self.audit_authority().map_err(map_open_error)?;
        let upstream_dom = self.upstream.dom.verify()?;
        let upstream_counterparty = self.upstream.counterparty.verify()?;
        let downstream_dom = self.downstream.dom.verify()?;
        let downstream_counterparty = self.downstream.counterparty.verify()?;

        let upstream_digest = validated_leg_evidence_digest(
            LegIdV1::Upstream,
            &self.upstream,
            upstream_dom,
            upstream_counterparty,
        )?;
        let downstream_digest = validated_leg_evidence_digest(
            LegIdV1::Downstream,
            &self.downstream,
            downstream_dom,
            downstream_counterparty,
        )?;
        let bindings = RefundBindingsV1 {
            upstream_refund_digest: upstream_digest,
            downstream_refund_digest: downstream_digest,
        };
        let receipt = encode_receipt(
            &self.config,
            context,
            ArmingEvidenceBundleV1 {
                upstream_dom,
                upstream_counterparty,
                downstream_dom,
                downstream_counterparty,
            },
            &bindings,
        )?;
        let existing: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT bytes, tag FROM refund_arming_receipt WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        if let Some((old, tag)) = existing {
            verify_authenticated(&self.credential, RECEIPT_DOMAIN, &old, &tag)
                .map_err(map_open_error)?;
            let old_header = decode_receipt_header(&old)?;
            if old_header.event_id != context.event_id
                || old_header.snapshot_revision != context.snapshot_revision
                || old_header.last_event_sequence != context.last_event_sequence
                || old_header.last_event_digest != context.last_event_digest
                || old_header.upstream_refund_digest != upstream_digest
                || old_header.downstream_refund_digest != downstream_digest
                || old_header.config_digest != self.config.config_digest
                || context.fencing_epoch < old_header.fencing_epoch
            {
                return Err(AuthorityRefusalV1::Inconsistent);
            }
            if context.fencing_epoch == old_header.fencing_epoch {
                if old != receipt {
                    return Err(AuthorityRefusalV1::Inconsistent);
                }
                return Ok(bindings);
            }
        }

        #[cfg(test)]
        if self.fault == RefundArmingFaultV1::BeforeReceiptCommit {
            return Err(AuthorityRefusalV1::Unavailable);
        }
        let tag =
            authenticate(&self.credential, RECEIPT_DOMAIN, &receipt).map_err(map_open_error)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        transaction
            .execute(
                "INSERT INTO refund_arming_receipt(id, bytes, tag) VALUES(1, ?1, ?2) \
                 ON CONFLICT(id) DO UPDATE SET bytes=excluded.bytes, tag=excluded.tag",
                params![receipt, tag.to_vec()],
            )
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        transaction
            .commit()
            .map_err(|_| AuthorityRefusalV1::Unavailable)?;
        self.audit_authority().map_err(map_open_error)?;
        #[cfg(test)]
        if self.fault == RefundArmingFaultV1::AfterReceiptCommit {
            return Err(AuthorityRefusalV1::Unavailable);
        }
        Ok(bindings)
    }

    fn audit_physical_storage(&self) -> Result<(), ProductionRefundArmingOpenErrorV1> {
        validate_parent(&self.database_path)?;
        if retained_identity(&self.database)? != self.database_identity
            || named_file_identity(&self.database_path)? != self.database_identity
            || retained_identity(&self.lock)? != self.lock_identity
            || named_file_identity(&self.lock_path)? != self.lock_identity
        {
            return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
        }
        validate_lock_file(&self.lock, &self.lock_path)?;
        validate_sqlite_sidecars(&self.database_path, false)
    }

    fn audit_authority(&self) -> Result<(), ProductionRefundArmingOpenErrorV1> {
        self.audit_physical_storage()?;
        validate_schema(&self.connection)?;
        self.audit_receipt_if_present()?;
        self.audit_physical_storage()
    }

    fn audit_receipt_if_present(&self) -> Result<(), ProductionRefundArmingOpenErrorV1> {
        let retained: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT bytes, tag FROM refund_arming_receipt WHERE id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
        if let Some((bytes, tag)) = retained {
            verify_authenticated(&self.credential, RECEIPT_DOMAIN, &bytes, &tag)?;
            let decoded = decode_receipt_full(&bytes).map_err(map_authority_open)?;
            if decoded.header.config_digest != self.config.config_digest
                || validated_leg_evidence_digest(
                    LegIdV1::Upstream,
                    &self.upstream,
                    decoded.evidence.upstream_dom,
                    decoded.evidence.upstream_counterparty,
                )
                .map_err(map_authority_open)?
                    != decoded.header.upstream_refund_digest
                || validated_leg_evidence_digest(
                    LegIdV1::Downstream,
                    &self.downstream,
                    decoded.evidence.downstream_dom,
                    decoded.evidence.downstream_counterparty,
                )
                .map_err(map_authority_open)?
                    != decoded.header.downstream_refund_digest
            {
                return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
            }
        }
        Ok(())
    }
}

#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl authority_seal::Sealed for ProductionRefundArmingAuthorityV1 {}

impl RefundArmingAuthority for ProductionRefundArmingAuthorityV1 {
    fn arm_refunds(
        &mut self,
        request: RefundArmingRequestV1<'_>,
    ) -> Result<RefundBindingsV1, AuthorityRefusalV1> {
        self.arm_refunds_inner(request)
    }
}

fn bind_configuration(
    admission: &AuthenticatedRouteAdmissionV1,
    composition: &ComposedBindingV2,
    owner_id: Digest32,
    authority_epoch: u64,
    upstream: ProductionRefundLegV1,
    downstream: ProductionRefundLegV1,
) -> Result<
    (RefundArmingConfigV1, BoundRefundLegV1, BoundRefundLegV1),
    ProductionRefundArmingOpenErrorV1,
> {
    let route_id = admission.route_id();
    let composition_v2_digest = composition.binding_digest();
    let time = admission
        .route_time_binding_v2()
        .ok_or(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    if route_id == ZERO_DIGEST
        || composition_v2_digest == ZERO_DIGEST
        || owner_id == ZERO_DIGEST
        || authority_epoch == 0
        || time.route_scope_digest() != composition.route_scope_digest()
        || time.policy_digest() != composition.time_policy_digest()
        || time.evidence_digest() != composition.time_evidence_digest()
        || time.proof_digest() != composition.time_proof_digest()
        || time.evidence_sequence() != composition.evidence_sequence()
        || time.issued_at_seconds() != composition.time_proof_issued_at_seconds()
        || time.valid_until_seconds() != composition.time_proof_valid_until_seconds()
        || time.validated_at_seconds() != composition.time_proof_validated_at_seconds()
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    let upstream_terms_digest = composition
        .upstream()
        .terms_hash()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    let downstream_terms_digest = composition
        .downstream()
        .terms_hash()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    let dom_deployment = admission
        .dom_deployment_capability()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    let common_pins =
        |counterparty_profile_digest, counterparty_asset_binding_digest| AdmissionFacePinsV1 {
            registry_digest: admission.registry_digest(),
            registry_epoch: admission.registry_epoch(),
            dom_profile_digest: dom_deployment.deployment().consensus_rules_digest,
            dom_asset_binding_digest: dom_deployment.native_asset_binding_digest(),
            counterparty_profile_digest,
            counterparty_asset_binding_digest,
            frozen_terms_digest: admission.frozen_bindings().terms_digest,
        };
    let upstream = bind_leg(
        upstream,
        route_id,
        composition_v2_digest,
        LegIdV1::Upstream,
        composition.upstream(),
        common_pins(
            admission.upstream_profile_digest(),
            admission.upstream_asset_binding_digest(),
        ),
    )?;
    let downstream = bind_leg(
        downstream,
        route_id,
        composition_v2_digest,
        LegIdV1::Downstream,
        composition.downstream(),
        common_pins(
            admission.downstream_profile_digest(),
            admission.downstream_asset_binding_digest(),
        ),
    )?;
    let topology_digest = digest_parts(
        CONFIG_DOMAIN,
        &[
            &upstream.descriptor_digest,
            &downstream.descriptor_digest,
            &upstream_terms_digest,
            &downstream_terms_digest,
        ],
    )
    .map_err(map_authority_open)?;
    let frozen = admission.frozen_bindings().clone();
    let config_digest = digest_parts(
        CONFIG_DOMAIN,
        &[
            &route_id,
            &composition_v2_digest,
            &frozen.terms_digest,
            &frozen.profile_bundle_digest,
            &frozen.deployment_bundle_digest,
            &upstream_terms_digest,
            &downstream_terms_digest,
            &owner_id,
            &authority_epoch.to_be_bytes(),
            &topology_digest,
        ],
    )
    .map_err(map_authority_open)?;
    Ok((
        RefundArmingConfigV1 {
            route_id,
            composition_v2_digest,
            frozen,
            upstream_terms_digest,
            downstream_terms_digest,
            owner_id,
            authority_epoch,
            topology_digest,
            config_digest,
        },
        upstream,
        downstream,
    ))
}

fn bind_leg(
    leg: ProductionRefundLegV1,
    route_id: RouteIdV1,
    composition_digest: Digest32,
    position: LegIdV1,
    settlement: &SettlementTermsV1,
    pins: AdmissionFacePinsV1,
) -> Result<BoundRefundLegV1, ProductionRefundArmingOpenErrorV1> {
    let dom = bind_dom_face(leg.dom, route_id, settlement, pins)?;
    let counterparty = bind_counterparty_face(
        leg.counterparty,
        route_id,
        composition_digest,
        position,
        settlement,
        pins,
    )?;
    let descriptor_digest = digest_parts(
        LEG_DOMAIN,
        &[
            &[leg_tag(position)],
            &dom.static_digest(),
            &counterparty.static_digest(),
        ],
    )
    .map_err(map_authority_open)?;
    Ok(BoundRefundLegV1 {
        dom,
        counterparty,
        descriptor_digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValidatedArmingRequestV1 {
    event_id: Digest32,
    fencing_epoch: u64,
    snapshot_revision: u64,
    last_event_sequence: u64,
    last_event_digest: Digest32,
}

fn validate_request(
    config: &RefundArmingConfigV1,
    request: &RefundArmingRequestV1<'_>,
) -> Result<ValidatedArmingRequestV1, AuthorityRefusalV1> {
    let snapshot = request.snapshot();
    let untouched = |leg: &route_executor::LegSnapshotV1| {
        leg.funding.progress() == ActionProgressV1::NotPrepared
            && leg.claim.progress() == ActionProgressV1::NotPrepared
            && leg.refund.progress() == ActionProgressV1::NotPrepared
    };
    if request.route_id() != config.route_id
        || request.event_id() == ZERO_DIGEST
        || request.fencing_epoch() == 0
        || request.bindings() != &config.frozen
        || snapshot.route_id != config.route_id
        || snapshot.coordination != CoordinationPhaseV1::TermsFrozen
        || snapshot.health != HealthStateV1::Running
        || snapshot.bindings.as_ref() != Some(&config.frozen)
        || snapshot.refunds.is_some()
        || snapshot.aborted_unfunded
        || snapshot.revision == 0
        || snapshot.last_event_sequence == 0
        || snapshot.last_event_digest == ZERO_DIGEST
        || !untouched(&snapshot.upstream)
        || !untouched(&snapshot.downstream)
        || !matches!(snapshot.secret_visibility, SecretVisibilityV1::Private)
    {
        return Err(AuthorityRefusalV1::Refused);
    }
    Ok(ValidatedArmingRequestV1 {
        event_id: request.event_id(),
        fencing_epoch: request.fencing_epoch(),
        snapshot_revision: snapshot.revision,
        last_event_sequence: snapshot.last_event_sequence,
        last_event_digest: snapshot.last_event_digest,
    })
}

fn leg_evidence_digest(
    position: LegIdV1,
    descriptor_digest: Digest32,
    dom: FaceEvidenceV1,
    counterparty: FaceEvidenceV1,
) -> Result<Digest32, AuthorityRefusalV1> {
    if dom.kind != 1
        || counterparty.kind == 1
        || dom.route_id != counterparty.route_id
        || dom.settlement_id != counterparty.settlement_id
        || dom.session_id != counterparty.session_id
        || dom.terms_digest != counterparty.terms_digest
        || dom.primary_artifact_digest == ZERO_DIGEST
        || dom.secondary_artifact_digest == ZERO_DIGEST
        || counterparty.primary_artifact_digest == ZERO_DIGEST
        || counterparty.secondary_artifact_digest == ZERO_DIGEST
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    digest_parts(
        LEG_DOMAIN,
        &[
            &[leg_tag(position)],
            &descriptor_digest,
            &encode_face(dom),
            &encode_face(counterparty),
        ],
    )
}

fn validated_leg_evidence_digest(
    position: LegIdV1,
    leg: &BoundRefundLegV1,
    dom: FaceEvidenceV1,
    counterparty: FaceEvidenceV1,
) -> Result<Digest32, AuthorityRefusalV1> {
    if dom.binding_identity() != leg.dom.binding_identity()?
        || counterparty.binding_identity() != leg.counterparty.binding_identity()?
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    leg_evidence_digest(position, leg.descriptor_digest, dom, counterparty)
}

fn encode_config(
    config: &RefundArmingConfigV1,
) -> Result<Vec<u8>, ProductionRefundArmingOpenErrorV1> {
    let mut bytes = Vec::with_capacity(4 + 10 * 32 + 8);
    put_u32(&mut bytes, SCHEMA_VERSION);
    put_digest(&mut bytes, config.route_id);
    put_digest(&mut bytes, config.composition_v2_digest);
    put_digest(&mut bytes, config.frozen.terms_digest);
    put_digest(&mut bytes, config.frozen.profile_bundle_digest);
    put_digest(&mut bytes, config.frozen.deployment_bundle_digest);
    put_digest(&mut bytes, config.upstream_terms_digest);
    put_digest(&mut bytes, config.downstream_terms_digest);
    put_digest(&mut bytes, config.owner_id);
    put_u64(&mut bytes, config.authority_epoch);
    put_digest(&mut bytes, config.topology_digest);
    put_digest(&mut bytes, config.config_digest);
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ArmingEvidenceBundleV1 {
    upstream_dom: FaceEvidenceV1,
    upstream_counterparty: FaceEvidenceV1,
    downstream_dom: FaceEvidenceV1,
    downstream_counterparty: FaceEvidenceV1,
}

fn encode_receipt(
    config: &RefundArmingConfigV1,
    context: ValidatedArmingRequestV1,
    evidence: ArmingEvidenceBundleV1,
    bindings: &RefundBindingsV1,
) -> Result<Vec<u8>, AuthorityRefusalV1> {
    let mut bytes = Vec::with_capacity(4 + 12 * 32 + 32 * 4);
    put_u32(&mut bytes, SCHEMA_VERSION);
    put_digest(&mut bytes, config.config_digest);
    put_digest(&mut bytes, context.event_id);
    put_u64(&mut bytes, context.fencing_epoch);
    put_u64(&mut bytes, context.snapshot_revision);
    put_u64(&mut bytes, context.last_event_sequence);
    put_digest(&mut bytes, context.last_event_digest);
    put_digest(&mut bytes, bindings.upstream_refund_digest);
    put_digest(&mut bytes, bindings.downstream_refund_digest);
    bytes.extend_from_slice(&encode_face(evidence.upstream_dom));
    bytes.extend_from_slice(&encode_face(evidence.upstream_counterparty));
    bytes.extend_from_slice(&encode_face(evidence.downstream_dom));
    bytes.extend_from_slice(&encode_face(evidence.downstream_counterparty));
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReceiptHeaderV1 {
    config_digest: Digest32,
    event_id: Digest32,
    fencing_epoch: u64,
    snapshot_revision: u64,
    last_event_sequence: u64,
    last_event_digest: Digest32,
    upstream_refund_digest: Digest32,
    downstream_refund_digest: Digest32,
}

fn decode_receipt_header(bytes: &[u8]) -> Result<ReceiptHeaderV1, AuthorityRefusalV1> {
    const HEADER_LEN: usize = 4 + 32 + 32 + 8 + 8 + 8 + 32 + 32 + 32;
    const FACE_LEN: usize = 1 + 9 * 32;
    if bytes.len() != HEADER_LEN + 4 * FACE_LEN
        || u32::from_be_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| AuthorityRefusalV1::Inconsistent)?,
        ) != SCHEMA_VERSION
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    let mut cursor = 4;
    let config_digest = take_digest(bytes, &mut cursor)?;
    let event_id = take_digest(bytes, &mut cursor)?;
    let fencing_epoch = take_u64(bytes, &mut cursor)?;
    let snapshot_revision = take_u64(bytes, &mut cursor)?;
    let last_event_sequence = take_u64(bytes, &mut cursor)?;
    let last_event_digest = take_digest(bytes, &mut cursor)?;
    let upstream_refund_digest = take_digest(bytes, &mut cursor)?;
    let downstream_refund_digest = take_digest(bytes, &mut cursor)?;
    Ok(ReceiptHeaderV1 {
        config_digest,
        event_id,
        fencing_epoch,
        snapshot_revision,
        last_event_sequence,
        last_event_digest,
        upstream_refund_digest,
        downstream_refund_digest,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DecodedReceiptV1 {
    header: ReceiptHeaderV1,
    evidence: ArmingEvidenceBundleV1,
}

fn decode_receipt_full(bytes: &[u8]) -> Result<DecodedReceiptV1, AuthorityRefusalV1> {
    const HEADER_LEN: usize = 4 + 32 + 32 + 8 + 8 + 8 + 32 + 32 + 32;
    let header = decode_receipt_header(bytes)?;
    let mut cursor = HEADER_LEN;
    let upstream_dom = decode_face(bytes, &mut cursor)?;
    let upstream_counterparty = decode_face(bytes, &mut cursor)?;
    let downstream_dom = decode_face(bytes, &mut cursor)?;
    let downstream_counterparty = decode_face(bytes, &mut cursor)?;
    if cursor != bytes.len()
        || upstream_dom.kind != 1
        || downstream_dom.kind != 1
        || !matches!(upstream_counterparty.kind, 2 | 3)
        || !matches!(downstream_counterparty.kind, 2 | 3)
        || header.event_id == ZERO_DIGEST
        || header.fencing_epoch == 0
        || header.snapshot_revision == 0
        || header.last_event_sequence == 0
        || header.last_event_digest == ZERO_DIGEST
        || header.upstream_refund_digest == ZERO_DIGEST
        || header.downstream_refund_digest == ZERO_DIGEST
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(DecodedReceiptV1 {
        header,
        evidence: ArmingEvidenceBundleV1 {
            upstream_dom,
            upstream_counterparty,
            downstream_dom,
            downstream_counterparty,
        },
    })
}

fn decode_face(bytes: &[u8], cursor: &mut usize) -> Result<FaceEvidenceV1, AuthorityRefusalV1> {
    let kind = *bytes.get(*cursor).ok_or(AuthorityRefusalV1::Inconsistent)?;
    *cursor = cursor
        .checked_add(1)
        .ok_or(AuthorityRefusalV1::Inconsistent)?;
    let face = FaceEvidenceV1 {
        kind,
        route_id: take_digest(bytes, cursor)?,
        settlement_id: take_digest(bytes, cursor)?,
        session_id: take_digest(bytes, cursor)?,
        terms_digest: take_digest(bytes, cursor)?,
        chain_digest: take_digest(bytes, cursor)?,
        deployment_digest: take_digest(bytes, cursor)?,
        primary_artifact_digest: take_digest(bytes, cursor)?,
        secondary_artifact_digest: take_digest(bytes, cursor)?,
        evidence_digest: take_digest(bytes, cursor)?,
    };
    if face.route_id == ZERO_DIGEST
        || face.settlement_id == ZERO_DIGEST
        || face.session_id == ZERO_DIGEST
        || face.terms_digest == ZERO_DIGEST
        || face.chain_digest == ZERO_DIGEST
        || face.deployment_digest == ZERO_DIGEST
        || face.primary_artifact_digest == ZERO_DIGEST
        || face.secondary_artifact_digest == ZERO_DIGEST
        || face.evidence_digest == ZERO_DIGEST
    {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(face)
}

fn encode_face(face: FaceEvidenceV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + 9 * 32);
    bytes.push(face.kind);
    put_digest(&mut bytes, face.route_id);
    put_digest(&mut bytes, face.settlement_id);
    put_digest(&mut bytes, face.session_id);
    put_digest(&mut bytes, face.terms_digest);
    put_digest(&mut bytes, face.chain_digest);
    put_digest(&mut bytes, face.deployment_digest);
    put_digest(&mut bytes, face.primary_artifact_digest);
    put_digest(&mut bytes, face.secondary_artifact_digest);
    put_digest(&mut bytes, face.evidence_digest);
    bytes
}

fn open_database(
    path: &Path,
    create: bool,
    permit_pristine: bool,
) -> Result<OpenedRefundDatabaseV1, ProductionRefundArmingOpenErrorV1> {
    validate_parent(path)?;
    let mut lock_name = path.as_os_str().to_os_string();
    lock_name.push(".lock");
    let lock_path = PathBuf::from(lock_name);
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .create_new(create)
        .mode(0o600)
        .open(&lock_path)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    validate_owner_file(&lock, path.parent())?;
    validate_lock_file(&lock, &lock_path)?;
    let lock_identity = retained_identity(&lock)?;
    if named_file_identity(&lock_path)? != lock_identity {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    lock.try_lock_exclusive()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    if create {
        lock.sync_all()
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
        sync_parent(&lock_path)?;
        test_creation_crash_hook("after-lock-fsync");
    }

    let database = if create {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
        validate_owner_file(&file, path.parent())?;
        file.sync_all()
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
        sync_parent(path)?;
        test_creation_crash_hook("after-database-fsync");
        file
    } else {
        let missing = match std::fs::symlink_metadata(path) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && permit_pristine => true,
            Err(_) => return Err(ProductionRefundArmingOpenErrorV1::Unavailable),
        };
        let mut options = OpenOptions::new();
        options.read(true).write(true).mode(0o600);
        if missing {
            options.create_new(true);
        }
        let mut file = options
            .open(path)
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
        if missing {
            file.sync_all()
                .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
            sync_parent(path)?;
        }
        validate_owner_file(&file, path.parent())?;
        let metadata = file
            .metadata()
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
        if metadata.len() != 0 && metadata.len() < SQLITE_HEADER.len() as u64 {
            return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
        }
        if metadata.len() != 0 {
            let mut header = [0u8; 16];
            use std::io::Read;
            file.read_exact(&mut header)
                .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
            if &header != SQLITE_HEADER {
                return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
            }
        } else if !permit_pristine {
            return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
        }
        file
    };
    let database_identity = retained_identity(&database)?;
    if named_file_identity(path)? != database_identity {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    if create {
        require_sqlite_sidecars_absent(path)?;
    } else {
        validate_sqlite_sidecars(path, permit_pristine)?;
    }
    let connection =
        Connection::open(path).map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    connection
        .busy_timeout(std::time::Duration::ZERO)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    connection
        .pragma_update(None, "foreign_keys", "ON")
        .and_then(|()| connection.pragma_update(None, "synchronous", "FULL"))
        .and_then(|()| connection.pragma_update(None, "trusted_schema", "OFF"))
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    if named_file_identity(path)? != database_identity
        || retained_identity(&database)? != database_identity
        || named_file_identity(&lock_path)? != lock_identity
        || retained_identity(&lock)? != lock_identity
    {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    Ok(OpenedRefundDatabaseV1 {
        connection,
        lock,
        database,
        database_identity,
        lock_identity,
        lock_path,
    })
}

fn initialize_schema(
    connection: &mut Connection,
    meta: &[u8],
    tag: &Digest32,
) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    test_creation_crash_hook("before-schema-transaction");
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Exclusive)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    transaction
        .execute(META_TABLE_SQL, [])
        .and_then(|_| transaction.execute(RECEIPT_TABLE_SQL, []))
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO refund_arming_meta(id, bytes, tag) VALUES(1, ?1, ?2)",
                params![meta, tag.to_vec()],
            )
        })
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    transaction
        .pragma_update(None, "user_version", SCHEMA_VERSION)
        .and_then(|()| transaction.pragma_update(None, "application_id", APPLICATION_ID))
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    test_creation_crash_hook("before-schema-commit");
    transaction
        .commit()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    test_creation_crash_hook("after-schema-commit");
    Ok(())
}

#[cfg(test)]
fn test_creation_crash_hook(boundary: &str) {
    if std::env::var("DOM_REFUND_ARMING_TEST_CRASH_BOUNDARY").as_deref() == Ok(boundary) {
        std::process::exit(86);
    }
}

#[cfg(not(test))]
fn test_creation_crash_hook(_boundary: &str) {}

fn validate_schema(connection: &Connection) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    let version: u32 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
    let application_id: u32 = connection
        .pragma_query_value(None, "application_id", |row| row.get(0))
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
    let mut statement = connection
        .prepare(
            "SELECT type, name, sql FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
    let integrity: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
    let foreign_keys: u32 = connection
        .pragma_query_value(None, "foreign_keys", |row| row.get(0))
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
    if version != SCHEMA_VERSION
        || application_id != APPLICATION_ID
        || foreign_keys != 1
        || integrity != "ok"
        || rows
            != vec![
                (
                    "table".to_owned(),
                    "refund_arming_meta".to_owned(),
                    META_TABLE_SQL.to_owned(),
                ),
                (
                    "table".to_owned(),
                    "refund_arming_receipt".to_owned(),
                    RECEIPT_TABLE_SQL.to_owned(),
                ),
            ]
    {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    Ok(())
}

fn validate_parent(path: &Path) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    let parent = path
        .parent()
        .ok_or(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    let metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    if std::fs::canonicalize(parent).map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?
        != parent
        || !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || metadata.uid() != effective_uid()?
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    Ok(())
}

fn validate_owner_file(
    file: &File,
    parent: Option<&Path>,
) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    let _parent = parent.ok_or(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid()?
        || metadata.permissions().mode() & 0o7777 != 0o600
    {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    Ok(())
}

fn retained_identity(
    file: &File,
) -> Result<RetainedFileIdentityV1, ProductionRefundArmingOpenErrorV1> {
    validate_owner_file(file, Some(Path::new(".")))?;
    let metadata = file
        .metadata()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    Ok(RetainedFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn validate_lock_file(file: &File, path: &Path) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    if retained_identity(file)? != named_file_identity(path)?
        || file
            .metadata()
            .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?
            .len()
            != 0
    {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    Ok(())
}

fn named_file_identity(
    path: &Path,
) -> Result<RetainedFileIdentityV1, ProductionRefundArmingOpenErrorV1> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid()?
    {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    Ok(RetainedFileIdentityV1 {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn effective_uid() -> Result<u32, ProductionRefundArmingOpenErrorV1> {
    use std::io::Read;
    let mut status = File::open("/proc/self/status")
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    let mut bytes = Vec::with_capacity(4096);
    Read::by_ref(&mut status)
        .take(64 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    let text =
        std::str::from_utf8(&bytes).map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    let effective = text
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|fields| fields.split_ascii_whitespace().nth(1))
        .ok_or(ProductionRefundArmingOpenErrorV1::Unavailable)?;
    effective
        .parse()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)
}

fn validate_sqlite_sidecars(
    path: &Path,
    permit_pristine_rollback_journal: bool,
) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    for (suffix, kind) in [
        ("-wal", SqliteSidecarKindV1::Wal),
        ("-shm", SqliteSidecarKindV1::SharedMemory),
        ("-journal", SqliteSidecarKindV1::RollbackJournal),
    ] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        let sidecar = PathBuf::from(name);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(_) => {
                validate_sqlite_sidecar(&sidecar, kind, permit_pristine_rollback_journal)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ProductionRefundArmingOpenErrorV1::Unavailable),
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SqliteSidecarKindV1 {
    Wal,
    SharedMemory,
    RollbackJournal,
}

fn validate_sqlite_sidecar(
    path: &Path,
    kind: SqliteSidecarKindV1,
    permit_pristine_rollback_journal: bool,
) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    use std::io::Read;
    let named = named_file_identity(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    if retained_identity(&file)? != named {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    let length = file
        .metadata()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?
        .len();
    if length == 0 {
        return Ok(());
    }
    let mut header = [0u8; 28];
    file.read_exact(&mut header)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
    let valid = match kind {
        SqliteSidecarKindV1::Wal => {
            length >= 32
                && matches!(
                    u32::from_be_bytes(
                        header[..4]
                            .try_into()
                            .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?
                    ),
                    0x377f_0682 | 0x377f_0683
                )
        }
        SqliteSidecarKindV1::SharedMemory => {
            length >= 32_768
                && length % 32_768 == 0
                && u32::from_ne_bytes(
                    header[..4]
                        .try_into()
                        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?,
                ) == 3_007_000
        }
        SqliteSidecarKindV1::RollbackJournal => {
            let hot_magic = header[..8] == [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
            hot_magic
                || (permit_pristine_rollback_journal
                    && pristine_rollback_journal(&mut file, length, &header)?)
        }
    };
    if !valid {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    Ok(())
}

fn pristine_rollback_journal(
    file: &mut File,
    length: u64,
    header: &[u8; 28],
) -> Result<bool, ProductionRefundArmingOpenErrorV1> {
    use std::io::Read;
    if length != 512
        || header[..12] != [0; 12]
        || header[12..16] == [0; 4]
        || header[16..20] != [0; 4]
        || header[20..24] != 512u32.to_be_bytes()
        || header[24..28] != 4096u32.to_be_bytes()
    {
        return Ok(false);
    }
    let mut tail = [0u8; 512 - 28];
    file.read_exact(&mut tail)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
    Ok(tail == [0; 512 - 28])
}

fn require_sqlite_sidecars_absent(path: &Path) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        match std::fs::symlink_metadata(PathBuf::from(name)) {
            Ok(_) => return Err(ProductionRefundArmingOpenErrorV1::Inconsistent),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(ProductionRefundArmingOpenErrorV1::Unavailable),
        }
    }
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    let parent = File::open(
        path.parent()
            .ok_or(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?,
    )
    .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    parent
        .sync_all()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)
}

fn authenticate(
    credential: &ProductionRefundArmingCredentialV1,
    domain: &[u8],
    bytes: &[u8],
) -> Result<Digest32, ProductionRefundArmingOpenErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    let mut mac = <Blake2bMac256 as KeyInit>::new_from_slice(credential.0.as_ref())
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Inconsistent)?;
    Mac::update(&mut mac, domain);
    Mac::update(&mut mac, &(bytes.len() as u64).to_be_bytes());
    Mac::update(&mut mac, bytes);
    let tag = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&tag);
    Ok(output)
}

fn verify_authenticated(
    credential: &ProductionRefundArmingCredentialV1,
    domain: &[u8],
    bytes: &[u8],
    tag: &[u8],
) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    if tag.len() != 32 {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    let expected = authenticate(credential, domain, bytes)?;
    let mut candidate = [0u8; 32];
    candidate.copy_from_slice(tag);
    let result = subtle_constant_time_eq(&expected, &candidate);
    candidate.zeroize();
    if !result {
        return Err(ProductionRefundArmingOpenErrorV1::Inconsistent);
    }
    Ok(())
}

fn subtle_constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32, AuthorityRefusalV1> {
    let mut hash = Blake2bVar::new(32).map_err(|_| AuthorityRefusalV1::Inconsistent)?;
    hash.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| AuthorityRefusalV1::Inconsistent)?;
        hash.update(&length.to_be_bytes());
        hash.update(part);
    }
    let mut digest = [0u8; 32];
    hash.finalize_variable(&mut digest)
        .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
    if digest == ZERO_DIGEST {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(digest)
}

fn validate_bitcoin_deployment(
    rpc: &BitcoinCoreRpcClientV1,
    deployment: &ResolvedBitcoinDeploymentV1,
) -> Result<(), ProductionRefundArmingOpenErrorV1> {
    let expected_network = match deployment.profile().kind {
        ChainKindV1::Bitcoin {
            network: BitcoinNetworkV1::Regtest,
        } => BitcoinCoreNetworkV1::Regtest,
        ChainKindV1::Bitcoin {
            network: BitcoinNetworkV1::PublicSignet,
        } => BitcoinCoreNetworkV1::PublicSignet,
        ChainKindV1::Bitcoin {
            network: BitcoinNetworkV1::CustomSignet,
        } => BitcoinCoreNetworkV1::CustomSignet,
        ChainKindV1::Evm { .. } | ChainKindV1::Monero { .. } | ChainKindV1::Solana { .. } => {
            return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        }
    };
    let facts = deployment.deployment();
    let expected_challenge = bitcoin_signet_challenge_digest_v1(&facts.signet_challenge)
        .map_err(|_| ProductionRefundArmingOpenErrorV1::InvalidConfiguration)?;
    let actual_challenge = rpc
        .signet_challenge_digest()
        .map_err(|_| ProductionRefundArmingOpenErrorV1::Unavailable)?;
    if rpc.network() != expected_network
        || rpc.genesis_hash() != facts.genesis_hash
        || actual_challenge != expected_challenge
    {
        return Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration);
    }
    rpc.require_chain_identity().map_err(|error| match error {
        LiveBitcoinError::Rpc
        | LiveBitcoinError::CredentialUnavailable
        | LiveBitcoinError::StoreUnavailable => ProductionRefundArmingOpenErrorV1::Unavailable,
        _ => ProductionRefundArmingOpenErrorV1::Inconsistent,
    })
}

fn validate_evm_genesis(
    rpc: &HttpJsonRpc,
    deployment: &ResolvedEvmDeploymentV1,
) -> Result<(), AuthorityRefusalV1> {
    let block = rpc
        .call("eth_getBlockByNumber", serde_json::json!(["0x0", false]))
        .map_err(map_evm_error)?;
    let hash = block
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .ok_or(AuthorityRefusalV1::Inconsistent)
        .and_then(parse_evm_digest)?;
    if hash != deployment.deployment().genesis_hash {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    Ok(())
}

fn parse_evm_digest(value: &str) -> Result<Digest32, AuthorityRefusalV1> {
    let hex = value
        .strip_prefix("0x")
        .ok_or(AuthorityRefusalV1::Inconsistent)?;
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(AuthorityRefusalV1::Inconsistent);
    }
    let mut digest = [0u8; 32];
    for (index, output) in digest.iter_mut().enumerate() {
        let offset = index * 2;
        let high = hex_nibble(hex.as_bytes()[offset]).ok_or(AuthorityRefusalV1::Inconsistent)?;
        let low = hex_nibble(hex.as_bytes()[offset + 1]).ok_or(AuthorityRefusalV1::Inconsistent)?;
        *output = (high << 4) | low;
    }
    Ok(digest)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn map_dom_error(error: SessionStoreError) -> AuthorityRefusalV1 {
    match error {
        SessionStoreError::Filesystem
        | SessionStoreError::StoreBusy
        | SessionStoreError::RandomFailure => AuthorityRefusalV1::Unavailable,
        SessionStoreError::InvalidTransition
        | SessionStoreError::FundingAuthorityUnavailable
        | SessionStoreError::ClaimSigningAuthorityUnavailable
        | SessionStoreError::LegacyV1RecoveryOnly => AuthorityRefusalV1::Refused,
        SessionStoreError::Conflict
        | SessionStoreError::Canonical
        | SessionStoreError::PolicyProfile
        | SessionStoreError::Quarantined
        | SessionStoreError::InvalidDomTransaction
        | SessionStoreError::SessionNotFound
        | SessionStoreError::CapacityExceeded => AuthorityRefusalV1::Inconsistent,
    }
}

fn map_bitcoin_error(error: LiveBitcoinError) -> AuthorityRefusalV1 {
    match error {
        LiveBitcoinError::Rpc
        | LiveBitcoinError::CredentialUnavailable
        | LiveBitcoinError::StoreUnavailable
        | LiveBitcoinError::SnapshotChanged => AuthorityRefusalV1::Unavailable,
        LiveBitcoinError::FundingNotArmed
        | LiveBitcoinError::FundingIncomplete
        | LiveBitcoinError::FundingInputUnavailable
        | LiveBitcoinError::TransactionUnavailable
        | LiveBitcoinError::InsufficientConfirmations => AuthorityRefusalV1::Refused,
        LiveBitcoinError::InvalidRequest
        | LiveBitcoinError::IdentityMismatch
        | LiveBitcoinError::InvalidRpcResponse
        | LiveBitcoinError::FundingMismatch
        | LiveBitcoinError::RefundMismatch
        | LiveBitcoinError::ClaimMismatch
        | LiveBitcoinError::ClaimNonceCustody
        | LiveBitcoinError::CorruptRecord
        | LiveBitcoinError::StateConflict
        | LiveBitcoinError::BoundsExceeded => AuthorityRefusalV1::Inconsistent,
    }
}

fn map_evm_error(error: counterparty_api::AdapterError) -> AuthorityRefusalV1 {
    match error {
        counterparty_api::AdapterError::AdapterUnavailable => AuthorityRefusalV1::Unavailable,
        counterparty_api::AdapterError::PreconditionUnsatisfied
        | counterparty_api::AdapterError::UnsupportedCapability => AuthorityRefusalV1::Refused,
        counterparty_api::AdapterError::InvalidState
        | counterparty_api::AdapterError::EvidenceInvalid
        | counterparty_api::AdapterError::ReorgDetected
        | counterparty_api::AdapterError::StaleCursor
        | counterparty_api::AdapterError::VersionMismatch
        | counterparty_api::AdapterError::NonCanonicalRetransmission
        | counterparty_api::AdapterError::BoundsExceeded => AuthorityRefusalV1::Inconsistent,
    }
}

fn map_open_error(error: ProductionRefundArmingOpenErrorV1) -> AuthorityRefusalV1 {
    match error {
        ProductionRefundArmingOpenErrorV1::Unavailable => AuthorityRefusalV1::Unavailable,
        ProductionRefundArmingOpenErrorV1::InvalidConfiguration
        | ProductionRefundArmingOpenErrorV1::Inconsistent => AuthorityRefusalV1::Inconsistent,
    }
}

fn map_authority_open(error: AuthorityRefusalV1) -> ProductionRefundArmingOpenErrorV1 {
    match error {
        AuthorityRefusalV1::Unavailable => ProductionRefundArmingOpenErrorV1::Unavailable,
        AuthorityRefusalV1::Refused => ProductionRefundArmingOpenErrorV1::InvalidConfiguration,
        AuthorityRefusalV1::Inconsistent => ProductionRefundArmingOpenErrorV1::Inconsistent,
    }
}

const fn leg_tag(leg: LegIdV1) -> u8 {
    match leg {
        LegIdV1::Upstream => 1,
        LegIdV1::Downstream => 2,
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn put_digest(bytes: &mut Vec<u8>, value: Digest32) {
    bytes.extend_from_slice(&value);
}

fn take_digest(bytes: &[u8], cursor: &mut usize) -> Result<Digest32, AuthorityRefusalV1> {
    let end = cursor
        .checked_add(32)
        .ok_or(AuthorityRefusalV1::Inconsistent)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(AuthorityRefusalV1::Inconsistent)?
        .try_into()
        .map_err(|_| AuthorityRefusalV1::Inconsistent)?;
    *cursor = end;
    Ok(value)
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, AuthorityRefusalV1> {
    let end = cursor
        .checked_add(8)
        .ok_or(AuthorityRefusalV1::Inconsistent)?;
    let value = u64::from_be_bytes(
        bytes
            .get(*cursor..end)
            .ok_or(AuthorityRefusalV1::Inconsistent)?
            .try_into()
            .map_err(|_| AuthorityRefusalV1::Inconsistent)?,
    );
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefundArmingFaultV1 {
    None,
    BeforeReceiptCommit,
    AfterReceiptCommit,
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use adapter_btc::timelock::ChainTimingBoundsV1;
    use adapter_evm::Direction;
    use btc_crypto::SecpContext;
    use chain_profile::{ChainKindV1, ChainProfileV1};
    use deployment_registry::{
        AssetBindingV1, AuthoritySetV1, ChainDeploymentV1, DomDeploymentV1, DomNetworkV1,
        DomRuntimeIdentityV1, EvmDeploymentV1, EvmSessionBindingsV1, RegistryChainProfileV1,
        RegistryManifestV1, RegistrySignatureV1, RegistryValidationPolicyV1, SignedRegistryV1,
    };
    use dom_actuator::DomParticipantV1;
    use kaystra_core::types::{AssetId, ChainId, FinalityPolicyV1};
    use route_time_anchor::{DurableRouteTimeAnchorStoreV2, RouteTimeAnchorStoreConfigV2};

    use super::*;
    use crate::route_time_test_common as time_common;

    const TEST_NETWORK: Digest32 = [0x90; 32];
    const TEST_DOM_CHAIN: ChainId = ChainId([
        0x22, 0x38, 0x4b, 0x4c, 0xbf, 0xaa, 0xe3, 0x06, 0xa7, 0xbd, 0xb2, 0x3a, 0x82, 0x24, 0x42,
        0xf7, 0xe6, 0x8f, 0xb5, 0x1f, 0x65, 0x32, 0x86, 0x97, 0xa7, 0x54, 0xa9, 0xf3, 0xab, 0xd6,
        0x98, 0xe1,
    ]);
    const TEST_DOM_GENESIS: Digest32 = [
        0xfd, 0xda, 0x02, 0x7e, 0x4a, 0x46, 0xdd, 0x36, 0x67, 0x17, 0xc6, 0xe0, 0xa9, 0x76, 0xbf,
        0x3e, 0x0a, 0x75, 0x12, 0xc5, 0xed, 0xf0, 0x84, 0x70, 0xb0, 0xdc, 0xa9, 0x9d, 0xde, 0xe3,
        0xfe, 0x1f,
    ];
    const TEST_EVM_CHAIN: ChainId = ChainId([0x02; 32]);
    const TEST_DOM_ASSET: AssetId = AssetId([0x11; 32]);
    const TEST_EVM_ASSET: AssetId = AssetId([0x12; 32]);

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

    fn resolved_evm_deployment() -> ResolvedEvmDeploymentV1 {
        let manifest = RegistryManifestV1 {
            network_id: TEST_NETWORK,
            epoch: 7,
            valid_from: 1_000,
            expires_at: 10_000,
            dom: DomDeploymentV1 {
                chain_id: TEST_DOM_CHAIN,
                genesis_hash: TEST_DOM_GENESIS,
                runtime_identity: DomRuntimeIdentityV1::pinned(DomNetworkV1::Regtest),
                consensus_rules_digest: digest(0x22),
                scriptless_api_version: 1,
                timing: timing(),
                finality: finality(),
                native_asset: TEST_DOM_ASSET,
            },
            chains: vec![RegistryChainProfileV1 {
                profile: ChainProfileV1 {
                    chain_id: TEST_EVM_CHAIN,
                    kind: ChainKindV1::Evm {
                        evm_chain_id: 31_337,
                        native_lock_contract: [0x31; 20],
                        native_code_hash: digest(0x32),
                        erc20_lock_contract: None,
                    },
                    timing: timing(),
                    finality: finality(),
                    native_asset: TEST_EVM_ASSET,
                    allowed_assets: vec![],
                },
                deployment: ChainDeploymentV1::Evm(EvmDeploymentV1 {
                    genesis_hash: digest(0x35),
                    native_start_block: 10,
                    erc20_start_block: None,
                    abi_digest: digest(0x36),
                    compiler_digest: digest(0x37),
                    source_digest: digest(0x38),
                    deployment_digest: digest(0x39),
                    finalized_tag_required: true,
                    page_size: 256,
                    gas_limit_hint: 300_000,
                    max_fee_per_gas: 100_000_000_000,
                    max_priority_fee_per_gas: 2_000_000_000,
                }),
            }],
            assets: vec![
                AssetBindingV1 {
                    chain_id: TEST_EVM_CHAIN,
                    asset_id: TEST_EVM_ASSET,
                    decimals: 18,
                    representation: AssetRepresentationV1::Native,
                },
                AssetBindingV1 {
                    chain_id: TEST_DOM_CHAIN,
                    asset_id: TEST_DOM_ASSET,
                    decimals: 9,
                    representation: AssetRepresentationV1::Native,
                },
            ],
        };
        let manifest_digest = manifest.manifest_digest().expect("manifest");
        let secp = SecpContext::new(&digest(0x60));
        let (signature, public_key) = secp
            .sign_bip340(&digest(3), &manifest_digest, &digest(0x70))
            .expect("signature");
        let authorities = AuthoritySetV1::new(1, vec![public_key]).expect("authorities");
        let signed = SignedRegistryV1::new(
            &manifest,
            vec![RegistrySignatureV1 {
                signer_index: 0,
                signature,
            }],
        )
        .expect("signed registry");
        signed
            .verify(
                &authorities,
                &secp,
                RegistryValidationPolicyV1 {
                    now_seconds: 2_000,
                    expected_network_id: TEST_NETWORK,
                    minimum_epoch: 7,
                },
            )
            .expect("registry")
            .resolve_chain(TEST_EVM_CHAIN)
            .expect("chain")
            .evm_deployment_capability(
                TEST_EVM_ASSET,
                EvmSessionBindingsV1 {
                    direction: Direction::DomToEvm,
                    session_id: digest(0x51),
                    terms_hash: digest(0x52),
                    participants_hash: digest(0x53),
                    beneficiary: [0x54; 20],
                    funder: [0x55; 20],
                },
            )
            .expect("deployment")
    }

    fn resolved_evm_deployment_for(
        registry: &deployment_registry::ResolvedRegistryV1,
        settlement: &SettlementTermsV1,
    ) -> ResolvedEvmDeploymentV1 {
        registry
            .resolve_chain(time_common::EVM_CHAIN)
            .expect("EVM chain")
            .evm_deployment_capability(
                time_common::EVM_ASSET,
                EvmSessionBindingsV1 {
                    direction: Direction::DomToEvm,
                    session_id: settlement.session_id.0,
                    terms_hash: settlement.terms_hash().expect("terms hash"),
                    participants_hash: digest(0x53),
                    beneficiary: [0x54; 20],
                    funder: [0x55; 20],
                },
            )
            .expect("route-scoped EVM deployment")
    }

    fn compose_time_fixture(
        fixture: &time_common::Fixture,
    ) -> (tempfile::TempDir, ComposedBindingV2) {
        let directory = owner_directory();
        let path = directory.path().join("refund-arming-time.sqlite");
        let config = RouteTimeAnchorStoreConfigV2::new(
            &fixture.registry,
            &fixture.upstream,
            &fixture.downstream,
            &fixture.policy_authorities,
            &fixture.evidence_authorities,
            &fixture.secp,
        )
        .expect("time config");
        let mut store = DurableRouteTimeAnchorStoreV2::create(&path, config).expect("time store");
        store
            .install_policy(
                &time_common::signed_policy(fixture),
                fixture.policy_context(),
                time_common::EVIDENCE_TIME,
            )
            .expect("time policy");
        let evidence = time_common::evidence(&fixture.policy, 1, time_common::EVIDENCE_TIME, 0);
        store
            .install_evidence(
                &time_common::signed_evidence(fixture, &evidence),
                fixture.evidence_context(),
                time_common::EVIDENCE_TIME,
            )
            .expect("time evidence");
        let proof = store
            .prove_route_ladder(fixture.evidence_context(), time_common::EVIDENCE_TIME)
            .expect("time proof");
        let current = store
            .consume_capability_at(proof, time_common::EVIDENCE_TIME)
            .expect("current time proof");
        let composition = ComposedBindingV2::bind(
            fixture.upstream.clone(),
            fixture.downstream.clone(),
            current,
        )
        .expect("composition");
        (directory, composition)
    }

    fn admission_pins_for_fixture(
        fixture: &time_common::Fixture,
        counterparty_chain: ChainId,
        counterparty_asset: AssetId,
        frozen_terms_digest: Digest32,
    ) -> AdmissionFacePinsV1 {
        let counterparty = fixture
            .registry
            .resolve_chain(counterparty_chain)
            .expect("counterparty chain");
        let dom = fixture.registry.resolve_dom().expect("DOM deployment");
        AdmissionFacePinsV1 {
            registry_digest: fixture.registry.manifest_digest(),
            registry_epoch: fixture.registry.epoch(),
            dom_profile_digest: dom.deployment().consensus_rules_digest,
            dom_asset_binding_digest: dom.native_asset_binding_digest(),
            counterparty_profile_digest: counterparty
                .profile()
                .profile_digest()
                .expect("counterparty profile"),
            counterparty_asset_binding_digest: fixture
                .registry
                .asset_binding_digest(counterparty_chain, counterparty_asset)
                .expect("counterparty asset binding"),
            frozen_terms_digest,
        }
    }

    struct ScriptedFaceV1 {
        static_digest: Digest32,
        evidence: FaceEvidenceV1,
        mutation: Rc<Cell<u8>>,
        refusal: Rc<Cell<u8>>,
    }

    impl ProductionRefundFaceVerifierV1 for ScriptedFaceV1 {
        fn static_digest(&self) -> Digest32 {
            self.static_digest
        }

        fn binding_identity(&self) -> Result<FaceBindingIdentityV1, AuthorityRefusalV1> {
            Ok(self.evidence.binding_identity())
        }

        fn verify(&self) -> Result<FaceEvidenceV1, AuthorityRefusalV1> {
            match self.refusal.get() {
                1 => return Err(AuthorityRefusalV1::Unavailable),
                2 => return Err(AuthorityRefusalV1::Refused),
                3 => return Err(AuthorityRefusalV1::Inconsistent),
                _ => {}
            }
            let mut evidence = self.evidence;
            let mutation = self.mutation.get();
            if mutation != 0 {
                evidence.primary_artifact_digest = [mutation; 32];
                evidence.evidence_digest = [mutation.wrapping_add(1); 32];
            }
            Ok(evidence)
        }
    }

    struct TestControlsV1 {
        downstream_counterparty_mutation: Rc<Cell<u8>>,
        downstream_counterparty_refusal: Rc<Cell<u8>>,
    }

    fn digest(byte: u8) -> Digest32 {
        [byte; 32]
    }

    fn test_config() -> RefundArmingConfigV1 {
        RefundArmingConfigV1 {
            route_id: digest(1),
            composition_v2_digest: digest(2),
            frozen: FrozenBindingsV1 {
                terms_digest: digest(3),
                profile_bundle_digest: digest(4),
                deployment_bundle_digest: digest(5),
            },
            upstream_terms_digest: digest(6),
            downstream_terms_digest: digest(7),
            owner_id: digest(8),
            authority_epoch: 9,
            topology_digest: digest(10),
            config_digest: digest(11),
        }
    }

    fn face(kind: u8, settlement: u8, artifact: u8) -> FaceEvidenceV1 {
        FaceEvidenceV1 {
            kind,
            route_id: digest(1),
            settlement_id: digest(settlement),
            session_id: digest(settlement.wrapping_add(1)),
            terms_digest: digest(settlement.wrapping_add(2)),
            chain_digest: digest(settlement.wrapping_add(3)),
            deployment_digest: digest(settlement.wrapping_add(4)),
            primary_artifact_digest: digest(artifact),
            secondary_artifact_digest: digest(artifact.wrapping_add(1)),
            evidence_digest: digest(artifact.wrapping_add(2)),
        }
    }

    fn scripted(
        static_byte: u8,
        evidence: FaceEvidenceV1,
        mutation: Rc<Cell<u8>>,
        refusal: Rc<Cell<u8>>,
    ) -> Box<dyn ProductionRefundFaceVerifierV1> {
        Box::new(ScriptedFaceV1 {
            static_digest: digest(static_byte),
            evidence,
            mutation,
            refusal,
        })
    }

    fn test_leg(
        settlement: u8,
        counterparty_kind: u8,
        dom_mutation: Rc<Cell<u8>>,
        counterparty_mutation: Rc<Cell<u8>>,
        counterparty_refusal: Rc<Cell<u8>>,
    ) -> BoundRefundLegV1 {
        let silent = Rc::new(Cell::new(0));
        let dom = scripted(
            settlement,
            face(1, settlement, settlement.wrapping_add(10)),
            dom_mutation,
            silent,
        );
        let counterparty = scripted(
            settlement.wrapping_add(1),
            face(counterparty_kind, settlement, settlement.wrapping_add(20)),
            counterparty_mutation,
            counterparty_refusal,
        );
        let descriptor_digest = digest_parts(
            LEG_DOMAIN,
            &[&dom.static_digest(), &counterparty.static_digest()],
        )
        .expect("descriptor");
        BoundRefundLegV1 {
            dom,
            counterparty,
            descriptor_digest,
        }
    }

    fn owner_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        directory
    }

    fn pristine_journal_bytes(nonce: [u8; 4]) -> [u8; 512] {
        let mut bytes = [0u8; 512];
        bytes[12..16].copy_from_slice(&nonce);
        bytes[20..24].copy_from_slice(&512u32.to_be_bytes());
        bytes[24..28].copy_from_slice(&4096u32.to_be_bytes());
        bytes
    }

    fn write_owner_file(path: &Path, bytes: &[u8]) {
        use std::io::Write;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("owner file");
        file.write_all(bytes).expect("write owner file");
        file.sync_all().expect("sync owner file");
    }

    fn test_authority(path: &Path) -> (ProductionRefundArmingAuthorityV1, TestControlsV1) {
        let config = test_config();
        let credential = ProductionRefundArmingCredentialV1::new(digest(0xa1)).expect("credential");
        let OpenedRefundDatabaseV1 {
            mut connection,
            lock,
            database,
            database_identity,
            lock_identity,
            lock_path,
        } = open_database(path, true, false).expect("open");
        let meta = encode_config(&config).expect("meta");
        let tag = authenticate(&credential, META_DOMAIN, &meta).expect("mac");
        initialize_schema(&mut connection, &meta, &tag).expect("schema");
        let controls = TestControlsV1 {
            downstream_counterparty_mutation: Rc::new(Cell::new(0)),
            downstream_counterparty_refusal: Rc::new(Cell::new(0)),
        };
        let upstream = test_leg(
            0x20,
            2,
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
        );
        let downstream = test_leg(
            0x40,
            3,
            Rc::new(Cell::new(0)),
            controls.downstream_counterparty_mutation.clone(),
            controls.downstream_counterparty_refusal.clone(),
        );
        (
            ProductionRefundArmingAuthorityV1 {
                connection,
                database,
                lock,
                database_path: path.to_path_buf(),
                lock_path,
                database_identity,
                lock_identity,
                credential,
                config,
                upstream,
                downstream,
                fault: RefundArmingFaultV1::None,
            },
            controls,
        )
    }

    fn reopen_test_authority(path: &Path) -> ProductionRefundArmingAuthorityV1 {
        let config = test_config();
        let credential = ProductionRefundArmingCredentialV1::new(digest(0xa1)).expect("credential");
        let OpenedRefundDatabaseV1 {
            connection,
            lock,
            database,
            database_identity,
            lock_identity,
            lock_path,
        } = open_database(path, false, false).expect("reopen");
        validate_schema(&connection).expect("schema");
        let retained: (Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT bytes, tag FROM refund_arming_meta WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("meta");
        verify_authenticated(&credential, META_DOMAIN, &retained.0, &retained.1)
            .expect("meta auth");
        assert_eq!(retained.0, encode_config(&config).expect("config"));
        let upstream = test_leg(
            0x20,
            2,
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
        );
        let downstream = test_leg(
            0x40,
            3,
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
            Rc::new(Cell::new(0)),
        );
        let authority = ProductionRefundArmingAuthorityV1 {
            connection,
            database,
            lock,
            database_path: path.to_path_buf(),
            lock_path,
            database_identity,
            lock_identity,
            credential,
            config,
            upstream,
            downstream,
            fault: RefundArmingFaultV1::None,
        };
        authority.audit_receipt_if_present().expect("receipt audit");
        authority
    }

    fn context(fencing_epoch: u64) -> ValidatedArmingRequestV1 {
        ValidatedArmingRequestV1 {
            event_id: digest(0x70),
            fencing_epoch,
            snapshot_revision: 1,
            last_event_sequence: 1,
            last_event_digest: digest(0x71),
        }
    }

    #[test]
    fn authenticated_receipt_is_idempotent_and_rejects_transplant() {
        let directory = owner_directory();
        let path = directory.path().join("refund.sqlite");
        let (mut authority, controls) = test_authority(&path);
        let first = authority.arm_verified(context(5)).expect("arm");
        assert_eq!(authority.arm_verified(context(5)).expect("retry"), first);
        controls.downstream_counterparty_refusal.set(1);
        assert_eq!(
            authority.arm_verified(context(5)),
            Err(AuthorityRefusalV1::Unavailable)
        );
        controls.downstream_counterparty_refusal.set(0);
        let mut sequence_transplant = context(6);
        sequence_transplant.last_event_sequence = 2;
        assert_eq!(
            authority.arm_verified(sequence_transplant),
            Err(AuthorityRefusalV1::Inconsistent)
        );
        assert_eq!(
            authority.arm_verified(context(4)),
            Err(AuthorityRefusalV1::Inconsistent)
        );
        controls.downstream_counterparty_mutation.set(0xd1);
        assert_eq!(
            authority.arm_verified(context(6)),
            Err(AuthorityRefusalV1::Inconsistent)
        );
    }

    #[test]
    fn incomplete_face_never_publishes_ready() {
        let directory = owner_directory();
        let path = directory.path().join("refund.sqlite");
        let (mut authority, controls) = test_authority(&path);
        controls.downstream_counterparty_refusal.set(2);
        assert_eq!(
            authority.arm_verified(context(5)),
            Err(AuthorityRefusalV1::Refused)
        );
        let count: u32 = authority
            .connection
            .query_row("SELECT count(*) FROM refund_arming_receipt", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(count, 0);
    }

    #[test]
    fn crash_boundaries_are_recoverable_without_fabricating_ready() {
        let directory = owner_directory();
        let path = directory.path().join("refund.sqlite");
        let (mut authority, _) = test_authority(&path);
        authority.fault = RefundArmingFaultV1::BeforeReceiptCommit;
        assert_eq!(
            authority.arm_verified(context(5)),
            Err(AuthorityRefusalV1::Unavailable)
        );
        let count: u32 = authority
            .connection
            .query_row("SELECT count(*) FROM refund_arming_receipt", [], |row| {
                row.get(0)
            })
            .expect("count");
        assert_eq!(count, 0);
        authority.fault = RefundArmingFaultV1::AfterReceiptCommit;
        assert_eq!(
            authority.arm_verified(context(5)),
            Err(AuthorityRefusalV1::Unavailable)
        );
        drop(authority);
        let mut reopened = reopen_test_authority(&path);
        reopened
            .arm_verified(context(5))
            .expect("recover committed receipt after reopen");
    }

    #[test]
    fn named_database_replacement_and_second_owner_are_refused() {
        let directory = owner_directory();
        let path = directory.path().join("refund.sqlite");
        let (authority, _) = test_authority(&path);
        assert!(matches!(
            open_database(&path, false, false),
            Err(ProductionRefundArmingOpenErrorV1::Unavailable)
        ));
        let displaced = directory.path().join("displaced.sqlite");
        std::fs::rename(&path, displaced).expect("rename");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("replacement");
        assert_eq!(
            authority.audit_physical_storage(),
            Err(ProductionRefundArmingOpenErrorV1::Inconsistent)
        );
    }

    #[test]
    fn schema_extension_and_receipt_mac_tamper_are_refused() {
        let directory = owner_directory();
        let path = directory.path().join("refund.sqlite");
        let (mut authority, _) = test_authority(&path);
        authority.arm_verified(context(5)).expect("arm");
        authority
            .connection
            .execute(
                "UPDATE refund_arming_receipt SET tag=zeroblob(32) WHERE id=1",
                [],
            )
            .expect("tamper");
        assert_eq!(
            authority.audit_receipt_if_present(),
            Err(ProductionRefundArmingOpenErrorV1::Inconsistent)
        );
        assert_eq!(
            authority.arm_verified(context(5)),
            Err(AuthorityRefusalV1::Inconsistent)
        );
        drop(authority);
        let connection = Connection::open(&path).expect("raw open");
        connection
            .execute("CREATE TABLE foreign_state(value INTEGER) STRICT", [])
            .expect("extend");
        drop(connection);
        let opened = open_database(&path, false, false).expect("locked open");
        assert_eq!(
            validate_schema(&opened.connection),
            Err(ProductionRefundArmingOpenErrorV1::Inconsistent)
        );
    }

    #[test]
    fn authenticated_self_consistent_receipt_topology_transplant_is_refused() {
        let directory = owner_directory();
        let path = directory.path().join("refund.sqlite");
        let (mut authority, _) = test_authority(&path);
        authority.arm_verified(context(5)).expect("arm");
        let retained: Vec<u8> = authority
            .connection
            .query_row(
                "SELECT bytes FROM refund_arming_receipt WHERE id=1",
                [],
                |row| row.get(0),
            )
            .expect("receipt");
        let decoded = decode_receipt_full(&retained).expect("decode");
        let mut evidence = decoded.evidence;
        evidence.upstream_dom.route_id = digest(0xd2);
        evidence.upstream_counterparty.route_id = digest(0xd2);
        let bindings = RefundBindingsV1 {
            upstream_refund_digest: leg_evidence_digest(
                LegIdV1::Upstream,
                authority.upstream.descriptor_digest,
                evidence.upstream_dom,
                evidence.upstream_counterparty,
            )
            .expect("self-consistent transplanted leg"),
            downstream_refund_digest: decoded.header.downstream_refund_digest,
        };
        let transplanted =
            encode_receipt(&authority.config, context(5), evidence, &bindings).expect("receipt");
        let tag = authenticate(&authority.credential, RECEIPT_DOMAIN, &transplanted).expect("tag");
        authority
            .connection
            .execute(
                "UPDATE refund_arming_receipt SET bytes=?1, tag=?2 WHERE id=1",
                params![transplanted, tag.to_vec()],
            )
            .expect("install authenticated transplant");
        assert_eq!(
            authority.audit_authority(),
            Err(ProductionRefundArmingOpenErrorV1::Inconsistent)
        );
    }

    #[test]
    fn live_owner_rejects_nonempty_lock_and_schema_mutation_before_arming() {
        use std::io::Write;

        let lock_directory = owner_directory();
        let lock_path = lock_directory.path().join("refund.sqlite");
        let (mut lock_authority, _) = test_authority(&lock_path);
        let mut retained_lock = &lock_authority.lock;
        retained_lock.write_all(b"not-empty").expect("lock payload");
        retained_lock.sync_all().expect("lock sync");
        assert_eq!(
            lock_authority.audit_authority(),
            Err(ProductionRefundArmingOpenErrorV1::Inconsistent)
        );
        assert_eq!(
            lock_authority.arm_verified(context(5)),
            Err(AuthorityRefusalV1::Inconsistent)
        );

        let schema_directory = owner_directory();
        let schema_path = schema_directory.path().join("refund.sqlite");
        let (mut schema_authority, _) = test_authority(&schema_path);
        schema_authority
            .connection
            .execute("CREATE VIEW foreign_view AS SELECT 1 AS value", [])
            .expect("schema mutation");
        assert_eq!(
            schema_authority.arm_verified(context(5)),
            Err(AuthorityRefusalV1::Inconsistent)
        );
    }

    #[test]
    fn strict_creation_resume_accepts_only_pristine_owner_files() {
        let directory = owner_directory();
        let path = directory.path().join("refund.sqlite");
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(PathBuf::from(lock_name))
            .expect("lock boundary");
        let mut opened = open_database(&path, false, true).expect("resume open");
        let config = test_config();
        let credential = ProductionRefundArmingCredentialV1::new(digest(0xa1)).expect("credential");
        let meta = encode_config(&config).expect("meta");
        let tag = authenticate(&credential, META_DOMAIN, &meta).expect("tag");
        initialize_schema(&mut opened.connection, &meta, &tag).expect("resume init");
        validate_schema(&opened.connection).expect("exact schema");
    }

    #[test]
    fn pristine_rollback_journal_is_resume_only_and_rejects_every_near_miss() {
        let directory = owner_directory();
        let valid_path = directory.path().join("valid-journal");
        let valid = pristine_journal_bytes([1, 2, 3, 4]);
        write_owner_file(&valid_path, &valid);
        assert_eq!(
            validate_sqlite_sidecar(&valid_path, SqliteSidecarKindV1::RollbackJournal, true),
            Ok(())
        );
        assert_eq!(
            validate_sqlite_sidecar(&valid_path, SqliteSidecarKindV1::RollbackJournal, false),
            Err(ProductionRefundArmingOpenErrorV1::Inconsistent)
        );

        let mut cases = Vec::new();
        cases.push(valid[..511].to_vec());
        let mut partial_magic = valid;
        partial_magic[0] = 0xd9;
        cases.push(partial_magic.to_vec());
        let mut zero_nonce = valid;
        zero_nonce[12..16].fill(0);
        cases.push(zero_nonce.to_vec());
        let mut wrong_sector = valid;
        wrong_sector[20..24].copy_from_slice(&1024u32.to_be_bytes());
        cases.push(wrong_sector.to_vec());
        let mut wrong_page = valid;
        wrong_page[24..28].copy_from_slice(&8192u32.to_be_bytes());
        cases.push(wrong_page.to_vec());
        let mut reserved = valid;
        reserved[8] = 1;
        cases.push(reserved.to_vec());
        let mut nonzero_body = valid;
        nonzero_body[28] = 1;
        cases.push(nonzero_body.to_vec());
        for (index, bytes) in cases.iter().enumerate() {
            let path = directory.path().join(format!("near-miss-{index}"));
            write_owner_file(&path, bytes);
            assert_eq!(
                validate_sqlite_sidecar(&path, SqliteSidecarKindV1::RollbackJournal, true),
                Err(ProductionRefundArmingOpenErrorV1::Inconsistent),
                "near-miss {index}"
            );
        }

        let runtime_directory = owner_directory();
        let database_path = runtime_directory.path().join("refund.sqlite");
        let (runtime_authority, _) = test_authority(&database_path);
        let mut journal_name = database_path.as_os_str().to_os_string();
        journal_name.push("-journal");
        write_owner_file(&PathBuf::from(journal_name), &valid);
        assert_eq!(
            runtime_authority.audit_physical_storage(),
            Err(ProductionRefundArmingOpenErrorV1::Inconsistent)
        );
    }

    #[test]
    fn evm_genesis_codec_and_bitcoin_clock_domain_are_strict() {
        assert_eq!(
            parse_evm_digest(&format!("0x{}", "ab".repeat(32))).expect("digest"),
            digest(0xab)
        );
        assert_eq!(
            parse_evm_digest(&"ab".repeat(32)),
            Err(AuthorityRefusalV1::Inconsistent)
        );
        assert_eq!(
            parse_evm_digest(&format!("0x{}g0", "ab".repeat(31))),
            Err(AuthorityRefusalV1::Inconsistent)
        );
        assert!(!bitcoin_delay_matches(
            TimelockSpec::BlockHeight { value: 144 },
            144
        ));
        assert!(!bitcoin_delay_matches(
            TimelockSpec::TimestampSeconds { value: 144 },
            144
        ));
        assert!(bitcoin_delay_matches(
            TimelockSpec::BtcTime512s { value: 144 },
            (1 << 22) | 144
        ));
    }

    #[test]
    fn incomplete_transient_and_corrupt_sources_keep_distinct_classification() {
        assert_eq!(
            map_dom_error(SessionStoreError::SessionNotFound),
            AuthorityRefusalV1::Inconsistent
        );
        assert_eq!(
            map_dom_error(SessionStoreError::Filesystem),
            AuthorityRefusalV1::Unavailable
        );
        assert_eq!(
            map_bitcoin_error(LiveBitcoinError::FundingNotArmed),
            AuthorityRefusalV1::Refused
        );
        assert_eq!(
            map_bitcoin_error(LiveBitcoinError::CorruptRecord),
            AuthorityRefusalV1::Inconsistent
        );
        assert_eq!(
            map_evm_error(counterparty_api::AdapterError::AdapterUnavailable),
            AuthorityRefusalV1::Unavailable
        );
        assert_eq!(
            map_evm_error(counterparty_api::AdapterError::EvidenceInvalid),
            AuthorityRefusalV1::Inconsistent
        );
    }

    #[test]
    fn evm_face_accepts_only_registry_resolved_configuration() {
        let deployment = resolved_evm_deployment();
        let expected = deployment.adapter_config();
        let face = ProductionEvmRefundFaceV1::connect("http://127.0.0.1:8545", 1, deployment)
            .expect("resolved face");
        assert_eq!(face.adapter.config(), &expected);
        assert!(matches!(
            ProductionEvmRefundFaceV1::connect(
                "http://127.0.0.1:8545",
                0,
                resolved_evm_deployment()
            ),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        ));
        assert!(matches!(
            ProductionEvmRefundFaceV1::connect("", 1, resolved_evm_deployment()),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        ));
    }

    #[test]
    fn bitcoin_route_binding_rejects_wrong_asset_under_the_same_profile() {
        let fixture = time_common::fixture();
        let deployment = fixture
            .registry
            .resolve_chain(time_common::BTC_CHAIN)
            .expect("Bitcoin chain")
            .bitcoin_deployment_capability()
            .expect("Bitcoin deployment");
        let (_time_directory, composition) = compose_time_fixture(&fixture);
        assert!(production_bitcoin_refund_route_binding_v1(
            digest(0x91),
            &composition,
            LegIdV1::Downstream,
            &deployment,
        )
        .is_ok());

        let mut wrong_asset_fixture = time_common::fixture();
        wrong_asset_fixture.downstream.counterparty_leg.asset_id = time_common::EVM_ASSET;
        wrong_asset_fixture.policy = route_time_anchor::RouteTimePolicyV2::from_registry(
            &wrong_asset_fixture.registry,
            &wrong_asset_fixture.upstream,
            &wrong_asset_fixture.downstream,
            time_common::limits(),
        )
        .expect("same-profile time policy does not authenticate asset deployment");
        let (_wrong_time_directory, wrong_asset_composition) =
            compose_time_fixture(&wrong_asset_fixture);
        assert_eq!(
            production_bitcoin_refund_route_binding_v1(
                digest(0x91),
                &wrong_asset_composition,
                LegIdV1::Downstream,
                &deployment,
            ),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );
    }

    #[test]
    fn admission_face_pins_reject_registry_epoch_profile_asset_and_terms_transplants() {
        let fixture = time_common::fixture();
        let dom_deployment = fixture.registry.resolve_dom().expect("DOM deployment");
        let dom_binding = DomSessionBindingV1::from_resolved_deployment(
            digest(0x91),
            digest(0x92),
            DomParticipantV1::new(digest(0x93), 0).expect("participant"),
            digest(0x94),
            dom_deployment,
        )
        .expect("DOM binding");
        let bitcoin_deployment = fixture
            .registry
            .resolve_chain(time_common::BTC_CHAIN)
            .expect("Bitcoin chain")
            .bitcoin_deployment_capability()
            .expect("Bitcoin deployment");
        let evm_deployment = resolved_evm_deployment_for(&fixture.registry, &fixture.upstream);
        let dom_pins = admission_pins_for_fixture(
            &fixture,
            time_common::EVM_CHAIN,
            time_common::EVM_ASSET,
            evm_deployment.adapter_config().terms_hash,
        );
        let bitcoin_pins = admission_pins_for_fixture(
            &fixture,
            time_common::BTC_CHAIN,
            time_common::BTC_ASSET,
            digest(0x95),
        );
        let evm_pins = dom_pins;

        assert!(validate_dom_admission_pins(dom_binding, dom_pins).is_ok());
        assert!(validate_bitcoin_admission_pins(&bitcoin_deployment, bitcoin_pins).is_ok());
        assert!(validate_evm_admission_pins(&evm_deployment, evm_pins).is_ok());

        let mut wrong_registry = dom_pins;
        wrong_registry.registry_digest = digest(0xe1);
        assert_eq!(
            validate_dom_admission_pins(dom_binding, wrong_registry),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );
        assert_eq!(
            validate_evm_admission_pins(&evm_deployment, wrong_registry),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );
        let mut wrong_bitcoin_registry = bitcoin_pins;
        wrong_bitcoin_registry.registry_digest = digest(0xe1);
        assert_eq!(
            validate_bitcoin_admission_pins(&bitcoin_deployment, wrong_bitcoin_registry),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );

        for wrong_epoch in [dom_pins.registry_epoch - 1, dom_pins.registry_epoch + 1] {
            let mut wrong = dom_pins;
            wrong.registry_epoch = wrong_epoch;
            assert_eq!(
                validate_dom_admission_pins(dom_binding, wrong),
                Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
            );
            assert_eq!(
                validate_evm_admission_pins(&evm_deployment, wrong),
                Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
            );
            let mut wrong = bitcoin_pins;
            wrong.registry_epoch = wrong_epoch;
            assert_eq!(
                validate_bitcoin_admission_pins(&bitcoin_deployment, wrong),
                Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
            );
        }

        let mut wrong_dom_profile = dom_pins;
        wrong_dom_profile.dom_profile_digest = digest(0xe2);
        assert_eq!(
            validate_dom_admission_pins(dom_binding, wrong_dom_profile),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );
        let mut wrong_dom_asset = dom_pins;
        wrong_dom_asset.dom_asset_binding_digest = digest(0xe3);
        assert_eq!(
            validate_dom_admission_pins(dom_binding, wrong_dom_asset),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );

        let mut wrong_bitcoin_profile = bitcoin_pins;
        wrong_bitcoin_profile.counterparty_profile_digest = digest(0xe4);
        assert_eq!(
            validate_bitcoin_admission_pins(&bitcoin_deployment, wrong_bitcoin_profile),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );
        let mut wrong_bitcoin_asset = bitcoin_pins;
        wrong_bitcoin_asset.counterparty_asset_binding_digest = digest(0xe5);
        assert_eq!(
            validate_bitcoin_admission_pins(&bitcoin_deployment, wrong_bitcoin_asset),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );

        let mut wrong_evm_profile = evm_pins;
        wrong_evm_profile.counterparty_profile_digest = digest(0xe6);
        assert_eq!(
            validate_evm_admission_pins(&evm_deployment, wrong_evm_profile),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );
        let mut wrong_evm_asset = evm_pins;
        wrong_evm_asset.counterparty_asset_binding_digest = digest(0xe7);
        assert_eq!(
            validate_evm_admission_pins(&evm_deployment, wrong_evm_asset),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );
        let mut wrong_evm_terms = evm_pins;
        wrong_evm_terms.frozen_terms_digest = digest(0xe8);
        assert_eq!(
            validate_evm_admission_pins(&evm_deployment, wrong_evm_terms),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        );
    }

    #[test]
    fn evm_binding_rejects_wrong_asset_under_the_same_profile() {
        let fixture = time_common::fixture();
        let settlement = fixture.upstream.clone();
        let deployment = resolved_evm_deployment_for(&fixture.registry, &settlement);
        let pins = admission_pins_for_fixture(
            &fixture,
            time_common::EVM_CHAIN,
            time_common::EVM_ASSET,
            deployment.adapter_config().terms_hash,
        );
        let face = ProductionEvmRefundFaceV1::connect("http://127.0.0.1:8545", 1, deployment)
            .expect("EVM face");
        assert!(bind_evm_face(
            face,
            digest(0x91),
            digest(0x92),
            LegIdV1::Upstream,
            &settlement,
            pins,
        )
        .is_ok());

        let mut wrong_asset = settlement;
        wrong_asset.counterparty_leg.asset_id = time_common::BTC_ASSET;
        let deployment = resolved_evm_deployment_for(&fixture.registry, &wrong_asset);
        let pins = admission_pins_for_fixture(
            &fixture,
            time_common::EVM_CHAIN,
            time_common::EVM_ASSET,
            deployment.adapter_config().terms_hash,
        );
        let face = ProductionEvmRefundFaceV1::connect("http://127.0.0.1:8545", 1, deployment)
            .expect("same-profile EVM face");
        assert!(matches!(
            bind_evm_face(
                face,
                digest(0x91),
                digest(0x92),
                LegIdV1::Upstream,
                &wrong_asset,
                pins,
            ),
            Err(ProductionRefundArmingOpenErrorV1::InvalidConfiguration)
        ));
    }

    #[test]
    fn creation_crash_child() {
        let Ok(path) = std::env::var("DOM_REFUND_ARMING_TEST_CRASH_PATH") else {
            return;
        };
        let path = PathBuf::from(path);
        let mut opened = open_database(&path, true, false).expect("child create");
        let config = test_config();
        let credential = ProductionRefundArmingCredentialV1::new(digest(0xa1)).expect("credential");
        let meta = encode_config(&config).expect("meta");
        let tag = authenticate(&credential, META_DOMAIN, &meta).expect("tag");
        initialize_schema(&mut opened.connection, &meta, &tag).expect("child schema");
    }

    #[test]
    fn subprocess_creation_crashes_resume_at_every_durable_boundary() {
        for boundary in [
            "after-lock-fsync",
            "after-database-fsync",
            "before-schema-transaction",
            "before-schema-commit",
            "after-schema-commit",
        ] {
            let directory = owner_directory();
            let path = directory.path().join("refund.sqlite");
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .arg("--exact")
                .arg("production_refund_arming::tests::creation_crash_child")
                .arg("--nocapture")
                .env("DOM_REFUND_ARMING_TEST_CRASH_PATH", &path)
                .env("DOM_REFUND_ARMING_TEST_CRASH_BOUNDARY", boundary)
                .status()
                .expect("spawn crash child");
            assert_eq!(status.code(), Some(86), "boundary {boundary}");

            let mut opened = open_database(&path, false, true)
                .unwrap_or_else(|error| panic!("resume boundary {boundary}: {error:?}"));
            let version: u32 = opened
                .connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .expect("version");
            if version == 0 {
                let config = test_config();
                let credential =
                    ProductionRefundArmingCredentialV1::new(digest(0xa1)).expect("credential");
                let meta = encode_config(&config).expect("meta");
                let tag = authenticate(&credential, META_DOMAIN, &meta).expect("tag");
                initialize_schema(&mut opened.connection, &meta, &tag).expect("resume schema");
            }
            validate_schema(&opened.connection).expect("resumed exact schema");
        }
    }
}
