use adapter_evm::{adaptor_address_of_scalar, UnsignedEvmCall};
use deployment_registry::ResolvedEvmDeploymentV1;
use zeroize::Zeroizing;

use crate::{EvmActuatorErrorV1, Result};

/// Fixed-size public commitment used throughout the actuator.
pub type Digest32 = [u8; 32];
/// Canonical 20-byte EVM account or contract address.
pub type EvmAddressV1 = [u8; 20];

pub(crate) const ZERO_DIGEST: Digest32 = [0; 32];
pub(crate) const ZERO_ADDRESS: EvmAddressV1 = [0; 20];

/// Economic operation carried by one durable EVM transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmOperationKindV1 {
    /// Funds and creates the condition lock.
    Open,
    /// Reveals the committed scalar and pays the beneficiary.
    Claim,
    /// Returns the locked funds after the authenticated deadline.
    Refund,
}

impl EvmOperationKindV1 {
    pub(crate) const fn tag(self) -> i64 {
        match self {
            Self::Open => 1,
            Self::Claim => 2,
            Self::Refund => 3,
        }
    }

    pub(crate) fn from_tag(tag: i64) -> Result<Self> {
        match tag {
            1 => Ok(Self::Open),
            2 => Ok(Self::Claim),
            3 => Ok(Self::Refund),
            _ => Err(EvmActuatorErrorV1::CorruptState),
        }
    }
}

/// Account role authorized to sign one EVM operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmSignerRoleV1 {
    /// Account bound as the lock funder. It signs `open` and, by local policy,
    /// `refund`, even though the Solidity contract permits any refund caller.
    Funder,
    /// Account bound as the sole beneficiary. It is the only claim signer.
    Beneficiary,
}

impl EvmSignerRoleV1 {
    pub(crate) const fn tag(self) -> i64 {
        match self {
            Self::Funder => 1,
            Self::Beneficiary => 2,
        }
    }

    pub(crate) fn from_tag(tag: i64) -> Result<Self> {
        match tag {
            1 => Ok(Self::Funder),
            2 => Ok(Self::Beneficiary),
            _ => Err(EvmActuatorErrorV1::CorruptState),
        }
    }
}

/// Move-only, zeroizing canonical scalar used by `claim`.
///
/// The caller-provided buffer is zeroed even when validation fails. This type
/// deliberately implements neither `Clone`, `Copy`, `Debug` nor any codec.
pub struct EvmClaimSecretV1 {
    scalar: Zeroizing<Digest32>,
    adaptor_address: EvmAddressV1,
}

impl EvmClaimSecretV1 {
    /// Imports a scalar, immediately zeroes the source buffer and verifies
    /// `0 < t < n` by deriving `address(t*G)` with the canonical adapter code.
    pub fn import_and_zeroize(secret: &mut Digest32) -> Result<Self> {
        let scalar = Zeroizing::new(core::mem::take(secret));
        let adaptor_address = adaptor_address_of_scalar(&scalar)
            .map_err(|_| EvmActuatorErrorV1::InvalidClaimSecret)?;
        Ok(Self {
            scalar,
            adaptor_address,
        })
    }

    pub(crate) fn scalar(&self) -> &Digest32 {
        &self.scalar
    }

    pub(crate) const fn adaptor_address(&self) -> EvmAddressV1 {
        self.adaptor_address
    }
}

#[derive(Clone)]
pub(crate) struct ValidatedEvmLockV1 {
    pub deployment: ResolvedEvmDeploymentV1,
    pub lock_id: Digest32,
    pub binding: Digest32,
    pub amount: Digest32,
    pub beneficiary: EvmAddressV1,
    pub funder: EvmAddressV1,
    pub adaptor_address: EvmAddressV1,
    pub deadline: u64,
}

/// EIP-1559 fee tuple selected under the authenticated deployment caps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmFeesV1 {
    pub(crate) max_fee_per_gas: u128,
    pub(crate) max_priority_fee_per_gas: u128,
}

impl EvmFeesV1 {
    /// Constructs a non-zero fee tuple with priority fee no greater than max fee.
    pub fn new(max_fee_per_gas: u128, max_priority_fee_per_gas: u128) -> Result<Self> {
        if max_fee_per_gas == 0
            || max_priority_fee_per_gas == 0
            || max_priority_fee_per_gas > max_fee_per_gas
        {
            return Err(EvmActuatorErrorV1::InvalidFeePolicy);
        }
        Ok(Self {
            max_fee_per_gas,
            max_priority_fee_per_gas,
        })
    }

    /// Maximum total fee per gas.
    pub const fn max_fee_per_gas(self) -> u128 {
        self.max_fee_per_gas
    }

    /// Maximum priority fee per gas.
    pub const fn max_priority_fee_per_gas(self) -> u128 {
        self.max_priority_fee_per_gas
    }
}

/// Route-scoped, registry-authenticated open call.
///
/// Construction validates every ABI field, binding, lock id, deployment,
/// account and fee-policy input before the call can enter durable storage.
#[derive(Clone)]
pub struct ScopedEvmOpenV1 {
    pub(crate) route_id: Digest32,
    pub(crate) effect_id: Digest32,
    pub(crate) semantic_digest: Digest32,
    pub(crate) deployment: ResolvedEvmDeploymentV1,
    pub(crate) call: UnsignedEvmCall,
    pub(crate) amount: [u8; 32],
    pub(crate) lock: ValidatedEvmLockV1,
}

impl core::fmt::Debug for ScopedEvmOpenV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ScopedEvmOpenV1")
            .field("route_id", &self.route_id)
            .field("effect_id", &self.effect_id)
            .field("semantic_digest", &self.semantic_digest)
            .field("registry_digest", &self.deployment.registry_digest())
            .field("registry_epoch", &self.deployment.registry_epoch())
            .field("chain_id", &self.call.chain_id)
            .field("to", &self.call.to)
            .field("lock_id", &self.call.lock_id)
            .field("binding", &self.call.binding)
            .finish_non_exhaustive()
    }
}

impl ScopedEvmOpenV1 {
    /// Validates and binds an unsigned adapter call to one route effect and one
    /// authenticated deployment capability.
    pub fn new(
        route_id: Digest32,
        effect_id: Digest32,
        semantic_digest: Digest32,
        deployment: ResolvedEvmDeploymentV1,
        call: UnsignedEvmCall,
    ) -> Result<Self> {
        crate::transaction::validate_open_scope(
            route_id,
            effect_id,
            semantic_digest,
            deployment,
            call,
        )
    }

    /// Route identity.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// Exact route effect identity.
    pub const fn effect_id(&self) -> Digest32 {
        self.effect_id
    }

    /// Semantic commitment supplied by the route authority.
    pub const fn semantic_digest(&self) -> Digest32 {
        self.semantic_digest
    }

    /// Authenticated registry manifest digest.
    pub const fn registry_digest(&self) -> Digest32 {
        self.deployment.registry_digest()
    }

    /// Authenticated profile digest.
    pub const fn profile_digest(&self) -> Digest32 {
        self.deployment.profile_digest()
    }

    /// Authenticated selected-asset digest.
    pub const fn asset_binding_digest(&self) -> Digest32 {
        self.deployment.asset_binding_digest()
    }

    /// Exact lock identifier produced by the adapter.
    pub const fn lock_id(&self) -> Digest32 {
        self.call.lock_id
    }

    /// Exact lock binding produced by the adapter.
    pub const fn binding(&self) -> Digest32 {
        self.call.binding
    }

    /// Exact amount encoded in the validated `open` calldata.
    pub const fn amount(&self) -> [u8; 32] {
        self.amount
    }
}

/// Route-scoped, beneficiary-authorized `claim(bytes32,uint256)` operation.
///
/// The exact calldata is held in zeroizing memory until it is moved into the
/// owner-only actuator database. Neither this type nor its scalar-bearing
/// fields implement `Debug`, `Clone` or a serialization codec.
pub struct ScopedEvmClaimV1 {
    pub(crate) route_id: Digest32,
    pub(crate) effect_id: Digest32,
    pub(crate) semantic_digest: Digest32,
    pub(crate) lock: ValidatedEvmLockV1,
    pub(crate) calldata: Zeroizing<Vec<u8>>,
}

impl ScopedEvmClaimV1 {
    /// Validates the authenticated opening artifact and verifies
    /// `address(t*G)` against its committed adaptor address before constructing
    /// any persistable terminal call.
    pub fn new(
        route_id: Digest32,
        effect_id: Digest32,
        semantic_digest: Digest32,
        deployment: ResolvedEvmDeploymentV1,
        opening_call: UnsignedEvmCall,
        secret: EvmClaimSecretV1,
    ) -> Result<Self> {
        crate::transaction::validate_claim_scope(
            route_id,
            effect_id,
            semantic_digest,
            deployment,
            opening_call,
            secret,
        )
    }

    /// Route identity.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// Exact route effect identity.
    pub const fn effect_id(&self) -> Digest32 {
        self.effect_id
    }

    /// Route semantic commitment.
    pub const fn semantic_digest(&self) -> Digest32 {
        self.semantic_digest
    }

    /// Exact lock identity.
    pub const fn lock_id(&self) -> Digest32 {
        self.lock.lock_id
    }

    /// Authenticated beneficiary account that must sign this claim.
    pub const fn beneficiary(&self) -> EvmAddressV1 {
        self.lock.beneficiary
    }

    /// Keccak-256 commitment to the exact scalar-bearing calldata.
    pub fn calldata_digest(&self) -> Digest32 {
        adapter_evm::keccak256(&self.calldata)
    }
}

/// Route-scoped, funder-policy `refund(bytes32)` operation.
#[derive(Clone)]
pub struct ScopedEvmRefundV1 {
    pub(crate) route_id: Digest32,
    pub(crate) effect_id: Digest32,
    pub(crate) semantic_digest: Digest32,
    pub(crate) lock: ValidatedEvmLockV1,
    pub(crate) calldata: Vec<u8>,
}

impl core::fmt::Debug for ScopedEvmRefundV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ScopedEvmRefundV1")
            .field("route_id", &self.route_id)
            .field("effect_id", &self.effect_id)
            .field("semantic_digest", &self.semantic_digest)
            .field("lock_id", &self.lock.lock_id)
            .field("binding", &self.lock.binding)
            .field("funder", &self.lock.funder)
            .field("deadline", &self.lock.deadline)
            .finish_non_exhaustive()
    }
}

impl ScopedEvmRefundV1 {
    /// Validates the authenticated opening artifact and constructs the exact
    /// refund calldata. Deadline authorization is deliberately deferred to the
    /// canonical RPC evidence consumed by `prepare_refund` and broadcast.
    pub fn new(
        route_id: Digest32,
        effect_id: Digest32,
        semantic_digest: Digest32,
        deployment: ResolvedEvmDeploymentV1,
        opening_call: UnsignedEvmCall,
    ) -> Result<Self> {
        crate::transaction::validate_refund_scope(
            route_id,
            effect_id,
            semantic_digest,
            deployment,
            opening_call,
        )
    }

    /// Route identity.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }

    /// Exact route effect identity.
    pub const fn effect_id(&self) -> Digest32 {
        self.effect_id
    }

    /// Route semantic commitment.
    pub const fn semantic_digest(&self) -> Digest32 {
        self.semantic_digest
    }

    /// Exact lock identity.
    pub const fn lock_id(&self) -> Digest32 {
        self.lock.lock_id
    }

    /// Authenticated funder account selected by the local refund signer policy.
    pub const fn funder(&self) -> EvmAddressV1 {
        self.lock.funder
    }

    /// Authenticated UNIX deadline committed into the lock binding.
    pub const fn deadline(&self) -> u64 {
        self.lock.deadline
    }

    /// Keccak-256 commitment to the exact refund calldata.
    pub fn calldata_digest(&self) -> Digest32 {
        adapter_evm::keccak256(&self.calldata)
    }
}

/// Current lifecycle state of an operation or signed attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmTxStageV1 {
    /// Immutable call and nonce are durably reserved, but no signature exists.
    Prepared,
    /// Raw typed transaction and transaction hash are durably retained.
    Signed,
    /// At least one send may have reached the network; absence is ambiguous.
    SendAttempted,
    /// Exact transaction was observed in a node or canonical block.
    Observed,
    /// A receipt, successful or reverted, was verified under finalized chain evidence.
    Final,
    /// This attempt was superseded by a same-nonce fee replacement.
    Replaced,
    /// A takeover reconciliation result was durably recorded.
    Reconciled,
    /// A formerly finalized receipt is no longer canonical/final. Any claim
    /// scalar already exposed remains public and is never rolled back.
    FinalityInvalidated,
}

impl EvmTxStageV1 {
    pub(crate) const fn tag(self) -> i64 {
        match self {
            Self::Prepared => 1,
            Self::Signed => 2,
            Self::SendAttempted => 3,
            Self::Observed => 4,
            Self::Final => 5,
            Self::Replaced => 6,
            Self::Reconciled => 7,
            Self::FinalityInvalidated => 8,
        }
    }

    pub(crate) fn from_tag(tag: i64) -> Result<Self> {
        match tag {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Signed),
            3 => Ok(Self::SendAttempted),
            4 => Ok(Self::Observed),
            5 => Ok(Self::Final),
            6 => Ok(Self::Replaced),
            7 => Ok(Self::Reconciled),
            8 => Ok(Self::FinalityInvalidated),
            _ => Err(EvmActuatorErrorV1::CorruptState),
        }
    }
}

/// Durable ownership capability for one authenticated `(chain, account)`.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EvmActuatorLeaseV1 {
    pub(crate) authority_id: Digest32,
    pub(crate) owner_id: Digest32,
    pub(crate) chain_id: u64,
    pub(crate) account: EvmAddressV1,
    pub(crate) fencing_epoch: u64,
    pub(crate) lease_until_unix_ms: u64,
}

impl core::fmt::Debug for EvmActuatorLeaseV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EvmActuatorLeaseV1")
            .field("authority_id", &self.authority_id)
            .field("owner_id", &self.owner_id)
            .field("chain_id", &self.chain_id)
            .field("account", &self.account)
            .field("fencing_epoch", &self.fencing_epoch)
            .field("lease_until_unix_ms", &self.lease_until_unix_ms)
            .finish()
    }
}

impl EvmActuatorLeaseV1 {
    /// Deterministic authority identity derived from chain and account.
    pub const fn authority_id(self) -> Digest32 {
        self.authority_id
    }

    /// Process ownership identity.
    pub const fn owner_id(self) -> Digest32 {
        self.owner_id
    }

    /// EIP-155 chain id.
    pub const fn chain_id(self) -> u64 {
        self.chain_id
    }

    /// Authorized signing account.
    pub const fn account(self) -> EvmAddressV1 {
        self.account
    }

    /// Monotonic fencing generation.
    pub const fn fencing_epoch(self) -> u64 {
        self.fencing_epoch
    }

    /// Exclusive lease deadline.
    pub const fn lease_until_unix_ms(self) -> u64 {
        self.lease_until_unix_ms
    }
}

/// Lease acquisition result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeaseAcquireOutcomeV1 {
    /// The caller obtained a new fencing generation.
    Acquired(EvmActuatorLeaseV1),
    /// The exact same owner already holds the still-live lease.
    AlreadyOwned(EvmActuatorLeaseV1),
}

impl LeaseAcquireOutcomeV1 {
    /// Returns the exact lease in either successful case.
    pub const fn lease(self) -> EvmActuatorLeaseV1 {
        match self {
            Self::Acquired(value) | Self::AlreadyOwned(value) => value,
        }
    }
}

/// Exact account nonce snapshot used as a CAS preparation prerequisite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceSnapshotV1 {
    pub(crate) observation_revision: u64,
    pub(crate) allocation_revision: u64,
    pub(crate) pending_nonce: u64,
    pub(crate) evidence_digest: Digest32,
    pub(crate) observed_at_unix_ms: u64,
    pub(crate) valid_until_unix_ms: u64,
}

impl NonceSnapshotV1 {
    /// Revision of the RPC observation.
    pub const fn observation_revision(self) -> u64 {
        self.observation_revision
    }
    /// Revision incremented by every local nonce reservation.
    pub const fn allocation_revision(self) -> u64 {
        self.allocation_revision
    }
    /// Pending account nonce verified by the observer.
    pub const fn pending_nonce(self) -> u64 {
        self.pending_nonce
    }
    /// Commitment to the exact observation response.
    pub const fn evidence_digest(self) -> Digest32 {
        self.evidence_digest
    }
    /// Trusted observation time.
    pub const fn observed_at_unix_ms(self) -> u64 {
        self.observed_at_unix_ms
    }
    /// First instant at which this snapshot is stale.
    pub const fn valid_until_unix_ms(self) -> u64 {
        self.valid_until_unix_ms
    }
}

/// Common authenticated inputs for refreshing one RPC-derived account
/// observation under mutation CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmObservationMutationRequestV1 {
    pub(crate) lease: EvmActuatorLeaseV1,
    pub(crate) mutation_id: Digest32,
    pub(crate) expected_revision: u64,
    pub(crate) now_unix_ms: u64,
    pub(crate) valid_for_ms: u64,
}

impl EvmObservationMutationRequestV1 {
    /// Binds a mutation identity, expected observation revision and validity
    /// window to the exact live account authority.
    pub const fn new(
        lease: EvmActuatorLeaseV1,
        mutation_id: Digest32,
        expected_revision: u64,
        now_unix_ms: u64,
        valid_for_ms: u64,
    ) -> Self {
        Self {
            lease,
            mutation_id,
            expected_revision,
            now_unix_ms,
            valid_for_ms,
        }
    }
}

/// Common authenticated inputs for atomically preparing one exact EVM
/// operation and reserving its nonce.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmOperationPreparationRequestV1 {
    pub(crate) lease: EvmActuatorLeaseV1,
    pub(crate) mutation_id: Digest32,
    pub(crate) operation_id: Digest32,
    pub(crate) expected_nonce: NonceSnapshotV1,
    pub(crate) fees: EvmFeesV1,
    pub(crate) now_unix_ms: u64,
}

impl EvmOperationPreparationRequestV1 {
    /// Binds the stable operation/mutation identities, nonce CAS snapshot,
    /// fees and trusted local time to one live account authority.
    pub const fn new(
        lease: EvmActuatorLeaseV1,
        mutation_id: Digest32,
        operation_id: Digest32,
        expected_nonce: NonceSnapshotV1,
        fees: EvmFeesV1,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            lease,
            mutation_id,
            operation_id,
            expected_nonce,
            fees,
            now_unix_ms,
        }
    }
}

/// Common authenticated inputs for a revision-CAS mutation of one retained
/// EVM operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmOperationMutationRequestV1 {
    pub(crate) lease: EvmActuatorLeaseV1,
    pub(crate) mutation_id: Digest32,
    pub(crate) operation_id: Digest32,
    pub(crate) expected_revision: u64,
    pub(crate) now_unix_ms: u64,
}

impl EvmOperationMutationRequestV1 {
    /// Binds the mutation and operation identities, expected durable revision
    /// and trusted local time to one live account authority.
    pub const fn new(
        lease: EvmActuatorLeaseV1,
        mutation_id: Digest32,
        operation_id: Digest32,
        expected_revision: u64,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            lease,
            mutation_id,
            operation_id,
            expected_revision,
            now_unix_ms,
        }
    }
}

/// Idempotent mutation classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationStatusV1 {
    /// New bytes were atomically committed.
    Committed,
    /// The same mutation id and exact semantic bytes were already committed.
    DuplicateSameBytes,
}

/// Exact operation-mutation family whose retained input revision may be
/// recovered after a crash. The actuator authenticates this caller-supplied
/// discriminator against the durable mutation commitment before returning a
/// revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmRetainedMutationKindV1 {
    /// `broadcast_current` persisted `SendAttempted` before the RPC boundary.
    BroadcastCurrent,
    /// `observe_current` persisted an exact chain observation.
    ObserveCurrent,
    /// `reconcile_takeover` persisted an old-fence reconciliation.
    ReconcileTakeover,
}

/// Result of a durable state mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationOutcomeV1<T> {
    /// Whether the mutation was new or an exact duplicate.
    pub status: MutationStatusV1,
    /// Current validated value after the mutation.
    pub value: T,
}

/// Public commitment to the finalized block-time observation that authorized
/// one refund. This type is output-only; actuator APIs never accept it as an
/// authorization supplied by a caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmRefundAuthorizationViewV1 {
    pub(crate) block_number: u64,
    pub(crate) block_hash: Digest32,
    pub(crate) timestamp: u64,
    pub(crate) evidence_digest: Digest32,
}

impl EvmRefundAuthorizationViewV1 {
    /// Finalized block height used for the deadline check.
    pub const fn block_number(self) -> u64 {
        self.block_number
    }

    /// Canonical hash of the finalized authorizing block.
    pub const fn block_hash(self) -> Digest32 {
        self.block_hash
    }

    /// Exact timestamp committed by that block.
    pub const fn timestamp(self) -> u64 {
        self.timestamp
    }

    /// Commitment to the corroborated RPC evidence.
    pub const fn evidence_digest(self) -> Digest32 {
        self.evidence_digest
    }
}

/// Public operation view. Raw transaction bytes and calldata are deliberately
/// absent so routine diagnostics cannot accidentally become a broadcaster.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmOperationViewV1 {
    /// Stable operation identity.
    pub operation_id: Digest32,
    /// Economic operation encoded by this transaction.
    pub kind: EvmOperationKindV1,
    /// Account role whose scoped signer is required.
    pub signer_role: EvmSignerRoleV1,
    /// Route identity.
    pub route_id: Digest32,
    /// Route effect identity.
    pub effect_id: Digest32,
    /// Route semantic commitment authenticated at preparation.
    pub semantic_digest: Digest32,
    /// Registry manifest digest that authorized the deployment.
    pub registry_digest: Digest32,
    /// Authenticated chain-profile digest.
    pub profile_digest: Digest32,
    /// Authenticated selected-asset binding digest.
    pub asset_binding_digest: Digest32,
    /// Authenticated contract release/deployment digest.
    pub deployment_digest: Digest32,
    /// EVM session terms digest committed by the lock.
    pub terms_digest: Digest32,
    /// Current operation revision.
    pub revision: u64,
    /// Current lifecycle stage.
    pub stage: EvmTxStageV1,
    /// Fencing generation authorized to progress this operation.
    pub fencing_epoch: u64,
    /// Reserved account nonce.
    pub nonce: u64,
    /// EIP-155 chain id authenticated by the deployment.
    pub chain_id: u64,
    /// Exact authenticated condition-lock contract.
    pub contract: EvmAddressV1,
    /// Account whose scoped signature authorized this operation.
    pub signing_account: EvmAddressV1,
    /// Beneficiary account authenticated by the EVM session binding.
    pub beneficiary: EvmAddressV1,
    /// Funder account authenticated by the EVM session binding.
    pub funder: EvmAddressV1,
    /// Exact condition-lock identity.
    pub lock_id: Digest32,
    /// Exact condition-lock binding.
    pub binding: Digest32,
    /// Current signed-attempt number, zero while merely prepared.
    pub current_attempt: u32,
    /// Current EIP-1559 fees.
    pub fees: EvmFeesV1,
    /// Current raw transaction hash, once signed.
    pub transaction_hash: Option<Digest32>,
    /// Whether a send may have occurred but current observation is absent.
    pub ambiguous_after_send: bool,
    /// Receipt execution result once observed. A finalized revert is retained
    /// as `Final` with `Some(false)` so its consumed nonce is never reused.
    pub execution_success: Option<bool>,
    /// True after a claim raw transaction may first have crossed the RPC
    /// boundary. This is irreversible, including across replacement/reorg.
    pub secret_exposed: bool,
    /// Commitment to the exact expected terminal event retained from a
    /// canonical receipt. The claim scalar itself is never in this view.
    pub terminal_event_digest: Option<Digest32>,
    /// Finalized block height retained from the last canonical receipt.
    pub final_block_number: Option<u64>,
    /// Canonical block hash retained from the last finalized receipt.
    pub final_block_hash: Option<Digest32>,
    /// Commitment to the receipt/canonicality/finality evidence.
    pub final_evidence_digest: Option<Digest32>,
    /// Commitment proving that formerly final evidence is no longer current.
    pub finality_invalidation_evidence_digest: Option<Digest32>,
    /// Last block whose timestamp canonically authorized a refund.
    pub refund_authorized_block: Option<u64>,
    /// Full output-only canonical deadline authorization retained for refund.
    pub refund_authorization: Option<EvmRefundAuthorizationViewV1>,
    /// Takeover reconciliation classification while stage is `Reconciled`.
    pub reconciliation_kind: Option<ReconciliationKindV1>,
}

/// Lease-scoped, fully reaudited operation bindings for a production caller.
///
/// The operation view contains no calldata, raw transaction or secret. The
/// additional value is only the commitment to the exact initially prepared
/// operation intent, including its original fee tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmOperationBindingViewV1 {
    pub(crate) operation: EvmOperationViewV1,
    pub(crate) intent_digest: Digest32,
}

impl EvmOperationBindingViewV1 {
    /// Fully validated public operation view.
    pub const fn operation(&self) -> &EvmOperationViewV1 {
        &self.operation
    }

    /// Commitment to the exact retained initial operation intent.
    pub const fn intent_digest(&self) -> Digest32 {
        self.intent_digest
    }
}

/// Public historical attempt view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmAttemptViewV1 {
    /// One-based attempt number.
    pub attempt: u32,
    /// Attempt state.
    pub stage: EvmTxStageV1,
    /// Fee tuple frozen into this attempt.
    pub fees: EvmFeesV1,
    /// Signing hash of the exact nine-field type-2 payload.
    pub signing_hash: Digest32,
    /// Keccak-256 of the exact persisted typed raw transaction.
    pub transaction_hash: Digest32,
}

/// Recoverable ECDSA signature returned by the scoped signer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Eip1559SignatureV1 {
    /// Recovery parity encoded by EIP-1559 as `0` or `1`.
    pub y_parity: u8,
    /// Canonical big-endian ECDSA `r` scalar.
    pub r: Digest32,
    /// Canonical big-endian, low-s ECDSA `s` scalar.
    pub s: Digest32,
}

/// Move-only request to sign one exact prepared EIP-1559 transaction.
pub struct Eip1559SigningRequestV1 {
    pub(crate) operation_id: Digest32,
    pub(crate) operation_kind: EvmOperationKindV1,
    pub(crate) signer_role: EvmSignerRoleV1,
    pub(crate) route_id: Digest32,
    pub(crate) effect_id: Digest32,
    pub(crate) semantic_digest: Digest32,
    pub(crate) registry_digest: Digest32,
    pub(crate) profile_digest: Digest32,
    pub(crate) asset_binding_digest: Digest32,
    pub(crate) deployment_digest: Digest32,
    pub(crate) terms_digest: Digest32,
    pub(crate) lock_id: Digest32,
    pub(crate) binding: Digest32,
    pub(crate) beneficiary: EvmAddressV1,
    pub(crate) funder: EvmAddressV1,
    pub(crate) account: EvmAddressV1,
    pub(crate) chain_id: u64,
    pub(crate) nonce: u64,
    pub(crate) to: EvmAddressV1,
    pub(crate) value: [u8; 32],
    pub(crate) calldata_digest: Digest32,
    pub(crate) gas_limit: u64,
    pub(crate) fees: EvmFeesV1,
    pub(crate) signing_hash: Digest32,
    pub(crate) fencing_epoch: u64,
    pub(crate) attempt: u32,
    pub(crate) one_shot_attempt_id: Digest32,
}

impl core::fmt::Debug for Eip1559SigningRequestV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Eip1559SigningRequestV1")
            .field("operation_id", &self.operation_id)
            .field("operation_kind", &self.operation_kind)
            .field("signer_role", &self.signer_role)
            .field("route_id", &self.route_id)
            .field("effect_id", &self.effect_id)
            .field("deployment_digest", &self.deployment_digest)
            .field("terms_digest", &self.terms_digest)
            .field("lock_id", &self.lock_id)
            .field("binding", &self.binding)
            .field("account", &self.account)
            .field("chain_id", &self.chain_id)
            .field("nonce", &self.nonce)
            .field("to", &self.to)
            .field("calldata_digest", &self.calldata_digest)
            .field("gas_limit", &self.gas_limit)
            .field("fees", &self.fees)
            .field("signing_hash", &self.signing_hash)
            .field("fencing_epoch", &self.fencing_epoch)
            .field("attempt", &self.attempt)
            .field("one_shot_attempt_id", &self.one_shot_attempt_id)
            .finish_non_exhaustive()
    }
}

impl Eip1559SigningRequestV1 {
    /// Stable operation identity.
    pub const fn operation_id(&self) -> Digest32 {
        self.operation_id
    }
    /// Economic operation whose exact typed transaction is being signed.
    pub const fn operation_kind(&self) -> EvmOperationKindV1 {
        self.operation_kind
    }
    /// Authenticated account role required for this operation.
    pub const fn signer_role(&self) -> EvmSignerRoleV1 {
        self.signer_role
    }
    /// Route identity.
    pub const fn route_id(&self) -> Digest32 {
        self.route_id
    }
    /// Route effect identity.
    pub const fn effect_id(&self) -> Digest32 {
        self.effect_id
    }
    /// Route semantic commitment.
    pub const fn semantic_digest(&self) -> Digest32 {
        self.semantic_digest
    }
    /// Authenticated registry digest.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry_digest
    }
    /// Authenticated profile digest.
    pub const fn profile_digest(&self) -> Digest32 {
        self.profile_digest
    }
    /// Authenticated asset binding digest.
    pub const fn asset_binding_digest(&self) -> Digest32 {
        self.asset_binding_digest
    }
    /// Authenticated deployment release digest.
    pub const fn deployment_digest(&self) -> Digest32 {
        self.deployment_digest
    }
    /// Session terms digest frozen in the lock binding.
    pub const fn terms_digest(&self) -> Digest32 {
        self.terms_digest
    }
    /// Exact condition-lock identity.
    pub const fn lock_id(&self) -> Digest32 {
        self.lock_id
    }
    /// Exact condition-lock binding.
    pub const fn binding(&self) -> Digest32 {
        self.binding
    }
    /// Beneficiary authenticated by the EVM session binding.
    pub const fn beneficiary(&self) -> EvmAddressV1 {
        self.beneficiary
    }
    /// Funder authenticated by the EVM session binding.
    pub const fn funder(&self) -> EvmAddressV1 {
        self.funder
    }
    /// Account whose address the returned signature must recover.
    pub const fn account(&self) -> EvmAddressV1 {
        self.account
    }
    /// EIP-155 chain id.
    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }
    /// Reserved account nonce.
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }
    /// Exact authenticated destination.
    pub const fn to(&self) -> EvmAddressV1 {
        self.to
    }
    /// Exact `msg.value`.
    pub const fn value(&self) -> [u8; 32] {
        self.value
    }
    /// Keccak commitment to the exact bounded calldata.
    pub const fn calldata_digest(&self) -> Digest32 {
        self.calldata_digest
    }
    /// Frozen gas limit.
    pub const fn gas_limit(&self) -> u64 {
        self.gas_limit
    }
    /// Frozen EIP-1559 fees.
    pub const fn fees(&self) -> EvmFeesV1 {
        self.fees
    }
    /// Exact type-2 signing hash.
    pub const fn signing_hash(&self) -> Digest32 {
        self.signing_hash
    }
    /// Current fencing generation.
    pub const fn fencing_epoch(&self) -> u64 {
        self.fencing_epoch
    }
    /// One-based signed-attempt sequence.
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }
    /// Deterministic idempotency identity for an external signer.
    pub const fn one_shot_attempt_id(&self) -> Digest32 {
        self.one_shot_attempt_id
    }
}

/// External signer boundary for one exact typed transaction. There is no
/// generic `sign(bytes)` method.
pub trait ScopedEip1559SignerV1 {
    /// Signs the exact hash and scope carried by the request.
    fn sign_eip1559(
        &mut self,
        request: Eip1559SigningRequestV1,
    ) -> core::result::Result<Eip1559SignatureV1, SignerRefusalV1>;
}

/// Fail-closed signer refusal without secret-bearing details.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SignerRefusalV1 {
    /// The signer refused policy or user authorization.
    #[error("scoped EIP-1559 signer refused authorization")]
    Refused,
    /// The signer is temporarily unavailable.
    #[error("scoped EIP-1559 signer unavailable")]
    Unavailable,
    /// The one-shot request conflicts with prior signer state.
    #[error("scoped EIP-1559 signer detected an idempotency conflict")]
    Conflict,
}

/// Outcome of a send attempt after the durable `SendAttempted` transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BroadcastDispositionV1 {
    /// RPC accepted the exact raw transaction and returned its expected hash.
    Accepted,
    /// The request may have reached the network; retry must use identical bytes.
    Ambiguous,
}

/// Result of broadcasting the current persisted attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BroadcastOutcomeV1 {
    /// Whether marking the attempt was new or an exact mutation retry.
    pub status: MutationStatusV1,
    /// Exact transaction hash committed before the RPC call.
    pub transaction_hash: Digest32,
    /// Accepted or conservatively ambiguous network disposition.
    pub disposition: BroadcastDispositionV1,
}

/// Result retained when a stale-fence operation is reconciled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationKindV1 {
    /// The manager proves internally that raw bytes were never exposed to RPC.
    InternallyNeverSent,
    /// The exact transaction was found but is not final.
    Observed,
    /// The exact transaction was found with a finalized receipt; execution
    /// success remains explicit in the operation view.
    Final,
    /// Lookup absence after a send attempt is ambiguous and cannot authorize retry.
    Unknown,
    /// A formerly final receipt is no longer canonical/final. Claim publicity
    /// remains irreversible while the settlement effect requires recovery.
    FinalityInvalidated,
}

impl ReconciliationKindV1 {
    pub(crate) const fn tag(self) -> i64 {
        match self {
            Self::InternallyNeverSent => 1,
            Self::Observed => 2,
            Self::Final => 3,
            Self::Unknown => 4,
            Self::FinalityInvalidated => 5,
        }
    }

    pub(crate) fn from_tag(tag: i64) -> Result<Self> {
        match tag {
            1 => Ok(Self::InternallyNeverSent),
            2 => Ok(Self::Observed),
            3 => Ok(Self::Final),
            4 => Ok(Self::Unknown),
            5 => Ok(Self::FinalityInvalidated),
            _ => Err(EvmActuatorErrorV1::CorruptState),
        }
    }
}
