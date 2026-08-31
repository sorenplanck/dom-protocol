//! Real-wallet, durable prebroadcast Bitcoin funding boundary.

use std::collections::BTreeSet;
use std::path::Path;

use adapter_btc::templates::{
    frozen_template_digest_v1, BitcoinPrevoutV1, BitcoinTxInV1, BitcoinTxOutV1,
    FrozenBitcoinTemplateV1,
};
use adapter_btc::types::BitcoinNetworkV1 as TemplateNetworkV1;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use serde_json::{json, Map, Value};
use zeroize::Zeroizing;

use crate::authority::{
    BitcoinExternalFundingCustodyV1, BitcoinPreparedFundingSummaryV1, BitcoinRefundDelayV1,
    BitcoinRefundSigningRequestV1, RetainedBitcoinRefundSignerV1,
};
use crate::rpc::{
    bitcoin_signet_challenge_digest_v1, decode_hex_bounded, display_txid, encode_hex,
    parse_txid_internal, BitcoinCoreNetworkV1, BitcoinCoreRpcClientV1,
};
use crate::store::{DurableStageStoreV1, StageKind};
use crate::LiveBitcoinError;

const PREPARED_MAGIC: &[u8; 8] = b"DBTCPRV1";
const FUNDING_SUMMARY_MAGIC: &[u8; 8] = b"DBTCSMV1";
const REFUND_MAGIC: &[u8; 8] = b"DBTCRFV1";
const BROADCAST_MAGIC: &[u8; 8] = b"DBTCBRV1";
const CODEC_VERSION: u16 = 1;
const PREPARED_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/PREPARED/V1\0";
const PLAN_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/PLAN/V1\0";
const FUNDING_SUMMARY_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/FUNDING-SUMMARY/V1\0";
const REFUND_SIGNING_REQUEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/REFUND-SIGNING-REQUEST/V1\0";
const EXTERNAL_FUNDING_CUSTODY_DOMAIN: &[u8] =
    b"DOM-INTEROP/F7/BTC-LIVE/EXTERNAL-FUNDING-CUSTODY/V1\0";
const REFUND_DIGEST_DOMAIN: &[u8] = b"DOM-INTEROP/F7/BTC-LIVE/REFUND/V1\0";
const MAX_TRANSACTION_BYTES: usize = 4_000_000;
const MAX_SCRIPT_BYTES: usize = 10_000;
const MAX_TRANSACTION_INPUTS: usize = 100_000;
const MAX_TRANSACTION_OUTPUTS: usize = 100_000;
const MAX_REFUND_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_FEE_RATE_SAT_VB: u64 = 1_000_000;
const MAX_MONEY_SAT: u64 = 21_000_000 * 100_000_000;
pub(crate) const MAX_DURABLE_RECORD_BYTES: usize = 8_500_000;

/// Exact public Taproot refund contract frozen before wallet funding.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinRefundContractV1 {
    /// Canonical CSV tapscript committed by the funding P2TR output.
    pub script: Vec<u8>,
    /// Exact single-leaf Taproot control block.
    pub control_block: Vec<u8>,
    /// BIP340 key that must authorize the refund script spend.
    pub refund_key_xonly: [u8; 32],
    /// Exact BIP68 sequence committed by the refund transaction.
    pub sequence: u32,
}

/// One exact output of the refund transaction, in canonical order.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinRefundOutputV1 {
    /// Exact output amount in satoshis.
    pub amount_sat: u64,
    /// Exact consensus scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

/// Immutable request for a real-wallet funding transaction.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinPrebroadcastPlanV1 {
    /// Nonzero digest binding this one-shot store to the complete route.
    pub route_binding: [u8; 32],
    /// Exact contract amount in satoshis.
    pub amount_sat: u64,
    /// Exact P2TR scriptPubKey funded once by the wallet transaction.
    pub contract_script_pubkey: Vec<u8>,
    /// Exact refund contract that must be armed before broadcast.
    pub refund_contract: BitcoinRefundContractV1,
    /// Exact ordered outputs that the signed refund must contain.
    pub refund_outputs: Vec<BitcoinRefundOutputV1>,
    /// Explicit wallet funding fee rate in satoshis per virtual byte.
    pub fee_rate_sat_vb: u64,
}

impl BitcoinPrebroadcastPlanV1 {
    /// Digest of the complete canonical public plan encoding.
    ///
    /// This does not authorize an absolute-lock to BIP68 projection. It lets
    /// the authority that made that decision bind the exact resulting plan
    /// before wallet input selection and compare it with restart state.
    pub fn canonical_digest(&self) -> Result<[u8; 32], LiveBitcoinError> {
        canonical_plan_digest(self)
    }

    /// Explicit relative BIP68 delay encoded by the refund contract.
    pub fn refund_delay(&self) -> Result<BitcoinRefundDelayV1, LiveBitcoinError> {
        BitcoinRefundDelayV1::from_sequence(self.refund_contract.sequence)
    }
}

/// Opaque durable prebroadcast funding capability.
///
/// The exact funding bytes remain private. Public getters expose the outpoint,
/// public refund plan and authenticated secret-free cost summary needed by
/// retained authorities. This type has no public constructor, codec, `Clone`,
/// or `Debug` implementation.
pub struct PreparedBitcoinFundingV1 {
    record: PreparedRecord,
    record_digest: [u8; 32],
    summary: BitcoinPreparedFundingSummaryV1,
}

impl PreparedBitcoinFundingV1 {
    /// Exact funding transaction id in internal byte order.
    #[must_use]
    pub const fn funding_txid(&self) -> [u8; 32] {
        self.record.txid
    }

    /// Exact funding witness transaction id in internal byte order.
    #[must_use]
    pub const fn funding_wtxid(&self) -> [u8; 32] {
        self.record.wtxid
    }

    /// Output index of the unique contract output.
    #[must_use]
    pub const fn contract_vout(&self) -> u32 {
        self.record.contract_vout
    }

    /// Exact contract amount in satoshis.
    #[must_use]
    pub const fn contract_amount_sat(&self) -> u64 {
        self.record.plan.amount_sat
    }

    /// Exact public contract scriptPubKey.
    #[must_use]
    pub fn contract_script_pubkey(&self) -> &[u8] {
        &self.record.plan.contract_script_pubkey
    }

    /// Exact public refund contract needed to construct the signed refund.
    #[must_use]
    pub const fn refund_contract(&self) -> &BitcoinRefundContractV1 {
        &self.record.plan.refund_contract
    }

    /// Exact ordered refund outputs frozen before wallet funding.
    #[must_use]
    pub fn refund_outputs(&self) -> &[BitcoinRefundOutputV1] {
        &self.record.plan.refund_outputs
    }

    /// Digest of the authenticated prepared record, safe for route binding.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> [u8; 32] {
        self.record_digest
    }

    /// Authenticated, complete, secret-free funding cost and plan summary.
    #[must_use]
    pub const fn funding_summary(&self) -> BitcoinPreparedFundingSummaryV1 {
        self.summary
    }
}

/// Opaque proof that the exact funding and exact valid refund are durable.
///
/// Only this capability can be passed to the explicit broadcast method. It
/// has no public constructor, codec, `Clone`, or `Debug` implementation.
pub struct ArmedBitcoinFundingV1 {
    prepared: PreparedBitcoinFundingV1,
    arm: Box<ArmedFundingTailV1>,
}

struct ArmedFundingTailV1 {
    refund: RefundRecord,
    broadcast: Option<BroadcastRecord>,
}

impl ArmedBitcoinFundingV1 {
    /// Exact funding transaction id in internal byte order.
    #[must_use]
    pub const fn funding_txid(&self) -> [u8; 32] {
        self.prepared.funding_txid()
    }

    /// Exact persisted refund transaction id in internal byte order.
    #[must_use]
    pub const fn refund_txid(&self) -> [u8; 32] {
        self.arm.refund.txid
    }

    /// Digest of the exact durable refund record.
    #[must_use]
    pub const fn refund_record_digest(&self) -> [u8; 32] {
        self.arm.refund.record_digest
    }

    /// Digest of the authenticated Prepared record retained under this stage.
    #[must_use]
    pub const fn prepared_record_digest(&self) -> [u8; 32] {
        self.prepared.prepared_record_digest()
    }

    /// Authenticated, complete, secret-free funding cost and plan summary.
    #[must_use]
    pub const fn funding_summary(&self) -> BitcoinPreparedFundingSummaryV1 {
        self.prepared.funding_summary()
    }

    /// Exact persisted signed refund transaction bytes.
    ///
    /// These bytes are safe to retain for the later CSV refund terminal. The
    /// prebroadcast funding bytes remain inaccessible and can only cross the
    /// explicit armed-only submit method.
    #[must_use]
    pub fn canonical_refund_transaction(&self) -> &[u8] {
        &self.arm.refund.raw_transaction
    }

    /// Whether this store already persisted a successful funding submission.
    #[must_use]
    pub const fn was_broadcast(&self) -> bool {
        self.arm.broadcast.is_some()
    }

    /// Payload-free identity for a runner that records external btc-live custody.
    ///
    /// The returned value binds the complete plan, Prepared summary, refund,
    /// funding outpoint, fee and virtual size without releasing either
    /// transaction. It is stable before and after the sole btc-live submit.
    pub fn external_funding_custody(
        &self,
    ) -> Result<BitcoinExternalFundingCustodyV1, LiveBitcoinError> {
        external_funding_custody(self)
    }
}

/// Durable stage reconstructed after a process restart.
pub enum ReopenedBitcoinFundingV1 {
    /// Funding exists but its refund is not yet durably armed.
    Prepared(PreparedBitcoinFundingV1),
    /// Funding and refund are durable; explicit broadcast is authorized.
    Armed(ArmedBitcoinFundingV1),
}

/// Public, non-constructible receipt from an armed-only funding submission.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinFundingBroadcastReceiptV1 {
    /// Exact submitted transaction id in internal byte order.
    pub txid: [u8; 32],
    /// True when an earlier durable receipt or exact node copy proved that the
    /// same transaction was already accepted.
    pub already_known: bool,
}

impl BitcoinFundingBroadcastReceiptV1 {
    /// Exact submitted transaction id in internal byte order.
    #[must_use]
    pub const fn transaction_id(&self) -> [u8; 32] {
        self.txid
    }

    /// Whether an exact earlier durable or node copy proved this retry.
    #[must_use]
    pub const fn already_known(&self) -> bool {
        self.already_known
    }
}

/// Owner-only durable prebroadcast store.
///
/// One route owns one store directory and its exclusive process lock. A real
/// Bitcoin Core wallet selects and signs UTXOs, but this API never calls
/// `sendrawtransaction` during preparation or refund arming.
pub struct BitcoinPrebroadcastStoreV1 {
    pub(crate) store: DurableStageStoreV1,
}

impl core::fmt::Debug for BitcoinPrebroadcastStoreV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BitcoinPrebroadcastStoreV1([redacted])")
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SelectedInput {
    txid: [u8; 32],
    vout: u32,
}

#[derive(Clone, PartialEq, Eq)]
struct PreparedRecord {
    network: BitcoinCoreNetworkV1,
    genesis_hash: [u8; 32],
    signet_challenge: Option<Vec<u8>>,
    plan: BitcoinPrebroadcastPlanV1,
    txid: [u8; 32],
    wtxid: [u8; 32],
    contract_vout: u32,
    selected_inputs: Vec<SelectedInput>,
    raw_transaction: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq)]
struct RefundRecord {
    route_binding: [u8; 32],
    prepared_digest: [u8; 32],
    txid: [u8; 32],
    wtxid: [u8; 32],
    raw_transaction: Vec<u8>,
    record_digest: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct BroadcastRecord {
    route_binding: [u8; 32],
    prepared_digest: [u8; 32],
    refund_digest: [u8; 32],
    txid: [u8; 32],
}

impl BitcoinPrebroadcastStoreV1 {
    /// Opens or creates an owner-only, exclusively locked route store.
    pub fn open_or_create(path: &Path) -> Result<Self, LiveBitcoinError> {
        DurableStageStoreV1::open_or_create(path).map(|store| Self { store })
    }

    /// Uses the concrete wallet to select/lock real UTXOs and return a fully
    /// signed but unbroadcast funding transaction.
    ///
    /// Bitcoin Core's `walletcreatefundedpsbt`, `walletprocesspsbt`, and
    /// `finalizepsbt` are used in that order. The exact transaction and its
    /// selected inputs are authenticated and fsync'd before the opaque handle
    /// is returned. No broadcast RPC is reachable from this method.
    pub fn prepare(
        &self,
        rpc: &BitcoinCoreRpcClientV1,
        plan: &BitcoinPrebroadcastPlanV1,
    ) -> Result<PreparedBitcoinFundingV1, LiveBitcoinError> {
        validate_plan(rpc.network(), plan)?;
        if let Some(reopened) = self.reopen(rpc, plan.route_binding)? {
            return match reopened {
                ReopenedBitcoinFundingV1::Prepared(prepared) if prepared.record.plan == *plan => {
                    Ok(prepared)
                }
                ReopenedBitcoinFundingV1::Prepared(_) | ReopenedBitcoinFundingV1::Armed(_) => {
                    Err(LiveBitcoinError::StateConflict)
                }
            };
        }
        rpc.require_chain_identity()?;
        let record = build_real_wallet_funding(rpc, plan)?;
        rpc.require_chain_identity()?;
        validate_prepared_record(
            rpc.network(),
            rpc.genesis_hash(),
            rpc.signet_challenge(),
            &record,
        )?;
        let payload = encode_prepared_record(&record)?;
        self.store.publish(StageKind::Prepared, &payload)?;
        let exact = self
            .store
            .read(StageKind::Prepared)?
            .ok_or(LiveBitcoinError::StoreUnavailable)?;
        let reopened = decode_prepared_record(&exact)?;
        validate_prepared_record(
            rpc.network(),
            rpc.genesis_hash(),
            rpc.signet_challenge(),
            &reopened,
        )?;
        let record_digest = digest(PREPARED_DIGEST_DOMAIN, &exact)?;
        let summary = self.load_or_create_funding_summary(rpc, &reopened, record_digest, true)?;
        relock_selected_inputs(rpc, &reopened.selected_inputs)?;
        Ok(PreparedBitcoinFundingV1 {
            record: reopened,
            record_digest,
            summary,
        })
    }

    /// Reconstructs the exact prepared or armed stage and relocks all selected
    /// wallet inputs after a process or Bitcoin Core restart.
    pub fn reopen(
        &self,
        rpc: &BitcoinCoreRpcClientV1,
        expected_route_binding: [u8; 32],
    ) -> Result<Option<ReopenedBitcoinFundingV1>, LiveBitcoinError> {
        if expected_route_binding == [0; 32] {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        let Some(prepared_bytes) = self.store.read(StageKind::Prepared)? else {
            if self.store.read(StageKind::FundingSummary)?.is_some()
                || self.store.read(StageKind::Refund)?.is_some()
                || self.store.read(StageKind::Broadcast)?.is_some()
            {
                return Err(LiveBitcoinError::CorruptRecord);
            }
            return Ok(None);
        };
        let record = decode_prepared_record(&prepared_bytes)?;
        if record.plan.route_binding != expected_route_binding {
            return Err(LiveBitcoinError::StateConflict);
        }
        rpc.require_chain_identity()?;
        validate_prepared_record(
            rpc.network(),
            rpc.genesis_hash(),
            rpc.signet_challenge(),
            &record,
        )?;
        let record_digest = digest(PREPARED_DIGEST_DOMAIN, &prepared_bytes)?;
        let refund_bytes = self.store.read(StageKind::Refund)?;
        let broadcast_bytes = self.store.read(StageKind::Broadcast)?;
        if refund_bytes.is_none() && broadcast_bytes.is_some() {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        let summary = self.load_or_create_funding_summary(
            rpc,
            &record,
            record_digest,
            refund_bytes.is_none(),
        )?;
        let prepared = PreparedBitcoinFundingV1 {
            record,
            record_digest,
            summary,
        };
        let Some(refund_bytes) = refund_bytes else {
            relock_selected_inputs(rpc, &prepared.record.selected_inputs)?;
            return Ok(Some(ReopenedBitcoinFundingV1::Prepared(prepared)));
        };
        let refund = decode_refund_record(&refund_bytes)?;
        require_refund_binding(&prepared, &refund)?;
        validate_refund_transaction(&prepared.record, &refund.raw_transaction)?;
        let broadcast = match broadcast_bytes {
            Some(bytes) => {
                let broadcast = decode_broadcast_record(&bytes)?;
                require_broadcast_binding(&prepared, &refund, &broadcast)?;
                Some(broadcast)
            }
            None if exact_funding_transaction_is_known(rpc, &prepared.record)? => {
                let recovered = BroadcastRecord {
                    route_binding: prepared.record.plan.route_binding,
                    prepared_digest: prepared.record_digest,
                    refund_digest: refund.record_digest,
                    txid: prepared.record.txid,
                };
                self.store
                    .publish(StageKind::Broadcast, &encode_broadcast_record(&recovered))?;
                let exact = self
                    .store
                    .read(StageKind::Broadcast)?
                    .ok_or(LiveBitcoinError::StoreUnavailable)?;
                let persisted = decode_broadcast_record(&exact)?;
                require_broadcast_binding(&prepared, &refund, &persisted)?;
                Some(persisted)
            }
            None => None,
        };
        if broadcast.is_none() {
            relock_selected_inputs(rpc, &prepared.record.selected_inputs)?;
        }
        Ok(Some(ReopenedBitcoinFundingV1::Armed(
            ArmedBitcoinFundingV1 {
                prepared,
                arm: Box::new(ArmedFundingTailV1 { refund, broadcast }),
            },
        )))
    }

    /// Consumes a retained signer directly into durable refund arming.
    ///
    /// `btc-live` constructs the exact refund and its BIP341 sighash
    /// internally. The signer receives only a public, digest-bound request
    /// and returns only a consuming signature; neither funding nor refund
    /// transaction bytes cross this boundary.
    pub fn arm_refund_with_signer<S>(
        &self,
        prepared: PreparedBitcoinFundingV1,
        signer: S,
    ) -> Result<ArmedBitcoinFundingV1, LiveBitcoinError>
    where
        S: RetainedBitcoinRefundSignerV1,
    {
        self.require_stored_prepared(&prepared)?;
        let expected_key = prepared.record.plan.refund_contract.refund_key_xonly;
        if signer.refund_key_xonly() != expected_key {
            return Err(LiveBitcoinError::RefundMismatch);
        }
        let mut transaction = unsigned_refund_transaction(&prepared.record)?;
        let sighash = refund_signature_hash(&prepared.record, &transaction)?;
        let mut request = BitcoinRefundSigningRequestV1 {
            route_binding: prepared.record.plan.route_binding,
            plan_digest: prepared.summary.plan_digest,
            prepared_record_digest: prepared.record_digest,
            summary_record_digest: prepared.summary.summary_record_digest,
            request_digest: [0; 32],
            funding_txid: prepared.record.txid,
            contract_vout: prepared.record.contract_vout,
            contract_amount_sat: prepared.record.plan.amount_sat,
            refund_key_xonly: expected_key,
            refund_delay: prepared.summary.refund_delay,
            sighash,
        };
        request.request_digest = refund_signing_request_digest(&request)?;
        let signature = signer.sign_refund(request)?;
        verify_refund_signature(&prepared.record, sighash, &signature.bytes)?;
        transaction.input[0].witness = Witness::from_slice(&[
            signature.bytes.as_slice(),
            prepared.record.plan.refund_contract.script.as_slice(),
            prepared
                .record
                .plan
                .refund_contract
                .control_block
                .as_slice(),
        ]);
        let raw_refund = Zeroizing::new(serialize(&transaction));
        self.arm_refund(prepared, raw_refund.as_slice())
    }

    /// Validates and durably arms the exact signed CSV refund.
    ///
    /// The transaction must be a single-input spend of the prepared funding
    /// outpoint, carry the exact frozen sequence/script/control block, and a
    /// valid BIP340 signature under the frozen refund key. Only after the
    /// authenticated record is fsync'd does this method return the linear
    /// armed capability. Production retained signers should use
    /// [`Self::arm_refund_with_signer`] so raw transaction bytes never return
    /// to the route executor.
    pub fn arm_refund(
        &self,
        prepared: PreparedBitcoinFundingV1,
        canonical_signed_refund: &[u8],
    ) -> Result<ArmedBitcoinFundingV1, LiveBitcoinError> {
        self.require_stored_prepared(&prepared)?;
        validate_refund_transaction(&prepared.record, canonical_signed_refund)?;
        let transaction: Transaction =
            deserialize(canonical_signed_refund).map_err(|_| LiveBitcoinError::RefundMismatch)?;
        let mut refund = RefundRecord {
            route_binding: prepared.record.plan.route_binding,
            prepared_digest: prepared.record_digest,
            txid: transaction.compute_txid().to_raw_hash().to_byte_array(),
            wtxid: transaction.compute_wtxid().to_raw_hash().to_byte_array(),
            raw_transaction: canonical_signed_refund.to_vec(),
            record_digest: [0; 32],
        };
        let unsigned_payload = encode_refund_record_without_digest(&refund)?;
        refund.record_digest = digest(REFUND_DIGEST_DOMAIN, &unsigned_payload)?;
        let payload = encode_refund_record(&refund)?;
        self.store.publish(StageKind::Refund, &payload)?;
        let exact = self
            .store
            .read(StageKind::Refund)?
            .ok_or(LiveBitcoinError::StoreUnavailable)?;
        let reopened = decode_refund_record(&exact)?;
        require_refund_binding(&prepared, &reopened)?;
        validate_refund_transaction(&prepared.record, &reopened.raw_transaction)?;
        let broadcast = match self.store.read(StageKind::Broadcast)? {
            Some(bytes) => {
                let record = decode_broadcast_record(&bytes)?;
                require_broadcast_binding(&prepared, &reopened, &record)?;
                Some(record)
            }
            None => None,
        };
        Ok(ArmedBitcoinFundingV1 {
            prepared,
            arm: Box::new(ArmedFundingTailV1 {
                refund: reopened,
                broadcast,
            }),
        })
    }

    /// Explicitly submits the exact funding bytes after durable refund arming.
    ///
    /// This is the only broadcast operation in the crate. An RPC error is not
    /// treated as success: the method independently asks Core for the exact
    /// txid and accepts ACK-loss recovery only when returned raw bytes are
    /// byte-identical. The success receipt is then persisted idempotently.
    pub fn broadcast_armed_funding(
        &self,
        rpc: &BitcoinCoreRpcClientV1,
        armed: &mut ArmedBitcoinFundingV1,
    ) -> Result<BitcoinFundingBroadcastReceiptV1, LiveBitcoinError> {
        self.require_stored_prepared(&armed.prepared)?;
        require_refund_binding(&armed.prepared, &armed.arm.refund)?;
        let prepared_bytes = self
            .store
            .read(StageKind::Prepared)?
            .ok_or(LiveBitcoinError::FundingNotArmed)?;
        let refund_bytes = self
            .store
            .read(StageKind::Refund)?
            .ok_or(LiveBitcoinError::FundingNotArmed)?;
        if digest(PREPARED_DIGEST_DOMAIN, &prepared_bytes)? != armed.prepared.record_digest
            || decode_refund_record(&refund_bytes)?.record_digest != armed.arm.refund.record_digest
        {
            return Err(LiveBitcoinError::StateConflict);
        }
        let had_durable_receipt = if let Some(existing) = self.store.read(StageKind::Broadcast)? {
            let record = decode_broadcast_record(&existing)?;
            require_broadcast_binding(&armed.prepared, &armed.arm.refund, &record)?;
            armed.arm.broadcast = Some(record);
            true
        } else {
            false
        };
        rpc.require_chain_identity()?;
        let hex = encode_hex(&armed.prepared.record.raw_transaction);
        let expected_txid = armed.prepared.record.txid;
        let (txid, already_known) = match rpc.node_rpc("sendrawtransaction", json!([hex])) {
            Ok(value) => {
                let txid = value
                    .as_str()
                    .ok_or(LiveBitcoinError::InvalidRpcResponse)
                    .and_then(parse_txid_internal)?;
                (txid, false)
            }
            Err(error) => {
                if exact_funding_transaction_is_known(rpc, &armed.prepared.record)? {
                    (expected_txid, true)
                } else {
                    return Err(error);
                }
            }
        };
        if txid != expected_txid {
            return Err(LiveBitcoinError::FundingMismatch);
        }
        let record = BroadcastRecord {
            route_binding: armed.prepared.record.plan.route_binding,
            prepared_digest: armed.prepared.record_digest,
            refund_digest: armed.arm.refund.record_digest,
            txid,
        };
        self.store
            .publish(StageKind::Broadcast, &encode_broadcast_record(&record))?;
        armed.arm.broadcast = Some(record);
        Ok(BitcoinFundingBroadcastReceiptV1 {
            txid,
            already_known: had_durable_receipt || already_known,
        })
    }

    fn require_stored_prepared(
        &self,
        prepared: &PreparedBitcoinFundingV1,
    ) -> Result<(), LiveBitcoinError> {
        let bytes = self
            .store
            .read(StageKind::Prepared)?
            .ok_or(LiveBitcoinError::StateConflict)?;
        if digest(PREPARED_DIGEST_DOMAIN, &bytes)? != prepared.record_digest
            || decode_prepared_record(&bytes)? != prepared.record
        {
            return Err(LiveBitcoinError::StateConflict);
        }
        let summary_bytes = self
            .store
            .read(StageKind::FundingSummary)?
            .ok_or(LiveBitcoinError::StateConflict)?;
        let summary = decode_funding_summary(&summary_bytes)?;
        validate_funding_summary(&prepared.record, prepared.record_digest, &summary)?;
        if summary != prepared.summary {
            return Err(LiveBitcoinError::StateConflict);
        }
        Ok(())
    }

    fn load_or_create_funding_summary(
        &self,
        rpc: &BitcoinCoreRpcClientV1,
        record: &PreparedRecord,
        record_digest: [u8; 32],
        may_create: bool,
    ) -> Result<BitcoinPreparedFundingSummaryV1, LiveBitcoinError> {
        if let Some(bytes) = self.store.read(StageKind::FundingSummary)? {
            let summary = decode_funding_summary(&bytes)?;
            validate_funding_summary(record, record_digest, &summary)?;
            return Ok(summary);
        }
        if !may_create {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        let total_input_sat = relock_selected_inputs(rpc, &record.selected_inputs)?;
        let summary = build_funding_summary(record, record_digest, total_input_sat)?;
        self.store.publish(
            StageKind::FundingSummary,
            &encode_funding_summary(&summary)?,
        )?;
        let exact = self
            .store
            .read(StageKind::FundingSummary)?
            .ok_or(LiveBitcoinError::StoreUnavailable)?;
        let persisted = decode_funding_summary(&exact)?;
        validate_funding_summary(record, record_digest, &persisted)?;
        Ok(persisted)
    }
}

fn validate_plan(
    network: BitcoinCoreNetworkV1,
    plan: &BitcoinPrebroadcastPlanV1,
) -> Result<(), LiveBitcoinError> {
    if plan.route_binding == [0; 32]
        || plan.amount_sat == 0
        || plan.amount_sat > MAX_MONEY_SAT
        || plan.fee_rate_sat_vb == 0
        || plan.fee_rate_sat_vb > MAX_FEE_RATE_SAT_VB
        || plan.contract_script_pubkey.len() != 34
        || plan.contract_script_pubkey[0] != 0x51
        || plan.contract_script_pubkey[1] != 0x20
        || plan.refund_contract.script.is_empty()
        || plan.refund_contract.script.len() > MAX_SCRIPT_BYTES
        || plan.refund_contract.control_block.len() != 33
        || plan.refund_outputs.is_empty()
        || plan.refund_outputs.len() > MAX_TRANSACTION_OUTPUTS
    {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    let (refund_output_sum, refund_output_bytes) =
        plan.refund_outputs
            .iter()
            .try_fold((0_u64, 0_usize), |(sum, bytes), output| {
                if output.amount_sat == 0
                    || output.amount_sat > MAX_MONEY_SAT
                    || output.script_pubkey.is_empty()
                    || output.script_pubkey.len() > MAX_SCRIPT_BYTES
                {
                    return Err(LiveBitcoinError::InvalidRequest);
                }
                Ok((
                    sum.checked_add(output.amount_sat)
                        .ok_or(LiveBitcoinError::BoundsExceeded)?,
                    bytes
                        .checked_add(12)
                        .and_then(|bytes| bytes.checked_add(output.script_pubkey.len()))
                        .ok_or(LiveBitcoinError::BoundsExceeded)?,
                ))
            })?;
    if refund_output_sum >= plan.amount_sat || refund_output_bytes > MAX_REFUND_OUTPUT_BYTES {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    let script_pubkey = ScriptBuf::from_bytes(plan.contract_script_pubkey.clone());
    Address::from_script(&script_pubkey, network.bitcoin_network())
        .map_err(|_| LiveBitcoinError::InvalidRequest)?;
    validate_refund_script(&plan.refund_contract)?;
    XOnlyPublicKey::from_slice(&plan.refund_contract.refund_key_xonly)
        .map_err(|_| LiveBitcoinError::InvalidRequest)?;
    let output_key = XOnlyPublicKey::from_slice(&plan.contract_script_pubkey[2..])
        .map_err(|_| LiveBitcoinError::InvalidRequest)?;
    let control = ControlBlock::decode(&plan.refund_contract.control_block)
        .map_err(|_| LiveBitcoinError::InvalidRequest)?;
    if control.leaf_version != LeafVersion::TapScript
        || !control.verify_taproot_commitment(
            &Secp256k1::verification_only(),
            output_key,
            Script::from_bytes(&plan.refund_contract.script),
        )
    {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    Ok(())
}

fn validate_refund_script(contract: &BitcoinRefundContractV1) -> Result<(), LiveBitcoinError> {
    let bytes = &contract.script;
    let push_len = bytes.first().copied().map(usize::from).unwrap_or_default();
    let suffix_start = 1usize
        .checked_add(push_len)
        .ok_or(LiveBitcoinError::BoundsExceeded)?;
    if push_len == 0
        || push_len > 5
        || suffix_start
            .checked_add(36)
            .filter(|length| *length == bytes.len())
            .is_none()
        || bytes[suffix_start] != 0xb2
        || bytes[suffix_start + 1] != 0x75
        || bytes[suffix_start + 2] != 0x20
        || bytes[suffix_start + 3..suffix_start + 35] != contract.refund_key_xonly
        || bytes[suffix_start + 35] != 0xac
    {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    let encoded = &bytes[1..suffix_start];
    if !is_minimal_positive_script_number(encoded) {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    let value = encoded
        .iter()
        .enumerate()
        .try_fold(0_u64, |value, (index, byte)| {
            value
                .checked_add(u64::from(*byte) << (8 * index))
                .ok_or(LiveBitcoinError::BoundsExceeded)
        })?;
    if value > u64::from(u32::MAX) || value as u32 != contract.sequence {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    BitcoinRefundDelayV1::from_sequence(contract.sequence)?;
    Ok(())
}

fn is_minimal_positive_script_number(bytes: &[u8]) -> bool {
    if bytes.is_empty() || bytes.last().is_some_and(|last| last & 0x80 != 0) {
        return false;
    }
    if bytes.last() == Some(&0)
        && (bytes.len() == 1
            || bytes
                .get(bytes.len().saturating_sub(2))
                .is_some_and(|previous| previous & 0x80 == 0))
    {
        return false;
    }
    true
}

fn build_real_wallet_funding(
    rpc: &BitcoinCoreRpcClientV1,
    plan: &BitcoinPrebroadcastPlanV1,
) -> Result<PreparedRecord, LiveBitcoinError> {
    let script = ScriptBuf::from_bytes(plan.contract_script_pubkey.clone());
    let address = Address::from_script(&script, rpc.network().bitcoin_network())
        .map_err(|_| LiveBitcoinError::InvalidRequest)?;
    let mut outputs = Map::new();
    outputs.insert(address.to_string(), exact_btc_amount(plan.amount_sat)?);
    let funded = rpc.wallet_rpc(
        "walletcreatefundedpsbt",
        json!([
            [],
            Value::Object(outputs),
            0,
            {
                "add_inputs": true,
                "include_unsafe": false,
                "lockUnspents": true,
                "replaceable": false,
                "fee_rate": plan.fee_rate_sat_vb,
            },
            true
        ]),
    )?;
    let psbt = funded
        .get("psbt")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
    let processed = rpc.wallet_rpc("walletprocesspsbt", json!([psbt, true, "ALL", true]))?;
    if processed.get("complete").and_then(Value::as_bool) != Some(true) {
        return Err(LiveBitcoinError::FundingIncomplete);
    }
    let processed_psbt = processed
        .get("psbt")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
    let finalized = rpc.wallet_rpc("finalizepsbt", json!([processed_psbt, true]))?;
    if finalized.get("complete").and_then(Value::as_bool) != Some(true) {
        return Err(LiveBitcoinError::FundingIncomplete);
    }
    let raw_transaction = finalized
        .get("hex")
        .and_then(Value::as_str)
        .ok_or(LiveBitcoinError::InvalidRpcResponse)
        .and_then(|value| decode_hex_bounded(value, MAX_TRANSACTION_BYTES))?;
    let transaction: Transaction =
        deserialize(&raw_transaction).map_err(|_| LiveBitcoinError::FundingMismatch)?;
    if transaction.input.is_empty()
        || transaction.input.len() > MAX_TRANSACTION_INPUTS
        || transaction.output.is_empty()
        || transaction.output.len() > MAX_TRANSACTION_OUTPUTS
    {
        return Err(LiveBitcoinError::FundingMismatch);
    }
    let matching_outputs: Vec<usize> = transaction
        .output
        .iter()
        .enumerate()
        .filter_map(|(index, output)| {
            (output.value.to_sat() == plan.amount_sat
                && output.script_pubkey.as_bytes() == plan.contract_script_pubkey)
                .then_some(index)
        })
        .collect();
    if matching_outputs.len() != 1 {
        return Err(LiveBitcoinError::FundingMismatch);
    }
    let contract_vout =
        u32::try_from(matching_outputs[0]).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    let selected_inputs: Vec<SelectedInput> = transaction
        .input
        .iter()
        .map(|input| SelectedInput {
            txid: input.previous_output.txid.to_raw_hash().to_byte_array(),
            vout: input.previous_output.vout,
        })
        .collect();
    relock_selected_inputs(rpc, &selected_inputs)?;
    Ok(PreparedRecord {
        network: rpc.network(),
        genesis_hash: rpc.genesis_hash(),
        signet_challenge: rpc.signet_challenge().map(ToOwned::to_owned),
        plan: plan.clone(),
        txid: transaction.compute_txid().to_raw_hash().to_byte_array(),
        wtxid: transaction.compute_wtxid().to_raw_hash().to_byte_array(),
        contract_vout,
        selected_inputs,
        raw_transaction,
    })
}

fn exact_btc_amount(satoshis: u64) -> Result<Value, LiveBitcoinError> {
    if satoshis == 0 || satoshis > MAX_MONEY_SAT {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    let whole = satoshis / 100_000_000;
    let fraction = satoshis % 100_000_000;
    let decimal = format!("{whole}.{fraction:08}");
    Ok(Value::String(decimal))
}

fn exact_rpc_btc_amount_sat(value: &Value) -> Result<u64, LiveBitcoinError> {
    let Value::Number(number) = value else {
        return Err(LiveBitcoinError::InvalidRpcResponse);
    };
    exact_decimal_btc_amount_sat(&number.to_string())
}

fn exact_decimal_btc_amount_sat(decimal: &str) -> Result<u64, LiveBitcoinError> {
    let (mantissa, exponent) = match decimal.find('e').or_else(|| decimal.find('E')) {
        Some(index) => {
            let exponent = decimal
                .get(index + 1..)
                .ok_or(LiveBitcoinError::InvalidRpcResponse)?
                .parse::<i32>()
                .map_err(|_| LiveBitcoinError::InvalidRpcResponse)?;
            (
                decimal
                    .get(..index)
                    .ok_or(LiveBitcoinError::InvalidRpcResponse)?,
                exponent,
            )
        }
        None => (decimal, 0),
    };
    if mantissa.is_empty() || mantissa.starts_with('-') || mantissa.starts_with('+') {
        return Err(LiveBitcoinError::InvalidRpcResponse);
    }
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LiveBitcoinError::InvalidRpcResponse);
    }
    let mut coefficient = 0_u128;
    for byte in whole.bytes().chain(fraction.bytes()) {
        coefficient = coefficient
            .checked_mul(10)
            .and_then(|value| value.checked_add(u128::from(byte - b'0')))
            .ok_or(LiveBitcoinError::BoundsExceeded)?;
    }
    let fraction_digits =
        i32::try_from(fraction.len()).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    let scale = exponent
        .checked_add(8)
        .and_then(|value| value.checked_sub(fraction_digits))
        .ok_or(LiveBitcoinError::BoundsExceeded)?;
    if !(-38..=38).contains(&scale) {
        return Err(LiveBitcoinError::BoundsExceeded);
    }
    let satoshis = if scale >= 0 {
        let power = u32::try_from(scale).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
        let multiplier = checked_power_of_ten(power)?;
        coefficient
            .checked_mul(multiplier)
            .ok_or(LiveBitcoinError::BoundsExceeded)?
    } else {
        let power = scale
            .checked_neg()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(LiveBitcoinError::BoundsExceeded)?;
        let divisor = checked_power_of_ten(power)?;
        if coefficient % divisor != 0 {
            return Err(LiveBitcoinError::InvalidRpcResponse);
        }
        coefficient / divisor
    };
    u64::try_from(satoshis)
        .ok()
        .filter(|value| *value > 0 && *value <= MAX_MONEY_SAT)
        .ok_or(LiveBitcoinError::InvalidRpcResponse)
}

fn checked_power_of_ten(exponent: u32) -> Result<u128, LiveBitcoinError> {
    (0..exponent).try_fold(1_u128, |value, _| {
        value
            .checked_mul(10)
            .ok_or(LiveBitcoinError::BoundsExceeded)
    })
}

fn exact_funding_transaction_is_known(
    rpc: &BitcoinCoreRpcClientV1,
    record: &PreparedRecord,
) -> Result<bool, LiveBitcoinError> {
    let display = display_txid(record.txid);
    let raw = match rpc.node_rpc("getrawtransaction", json!([&display, false])) {
        Ok(value) => value
            .as_str()
            .ok_or(LiveBitcoinError::InvalidRpcResponse)
            .and_then(|value| decode_hex_bounded(value, MAX_TRANSACTION_BYTES))?,
        Err(_) => match rpc.wallet_rpc("gettransaction", json!([&display])) {
            Ok(value)
                if value
                    .get("confirmations")
                    .and_then(Value::as_i64)
                    .is_some_and(|confirmations| confirmations > 0) =>
            {
                value
                    .get("hex")
                    .and_then(Value::as_str)
                    .ok_or(LiveBitcoinError::InvalidRpcResponse)
                    .and_then(|value| decode_hex_bounded(value, MAX_TRANSACTION_BYTES))?
            }
            Ok(value) if value.get("confirmations").and_then(Value::as_i64) == Some(0) => {
                return Ok(false);
            }
            Ok(_) => return Err(LiveBitcoinError::InvalidRpcResponse),
            Err(_) => return Ok(false),
        },
    };
    if raw != record.raw_transaction {
        return Err(LiveBitcoinError::FundingMismatch);
    }
    Ok(true)
}

fn relock_selected_inputs(
    rpc: &BitcoinCoreRpcClientV1,
    selected_inputs: &[SelectedInput],
) -> Result<u64, LiveBitcoinError> {
    if selected_inputs.is_empty() || selected_inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(LiveBitcoinError::FundingMismatch);
    }
    let mut unique = BTreeSet::new();
    if selected_inputs
        .iter()
        .any(|input| !unique.insert((input.txid, input.vout)))
    {
        return Err(LiveBitcoinError::FundingMismatch);
    }
    let listed = rpc.wallet_rpc("listlockunspent", json!([]))?;
    let listed = listed
        .as_array()
        .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
    let mut locked = BTreeSet::new();
    for value in listed {
        let txid = value
            .get("txid")
            .and_then(Value::as_str)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)
            .and_then(parse_txid_internal)?;
        let vout = value
            .get("vout")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?;
        locked.insert((txid, vout));
    }
    let outpoints: Vec<Value> = selected_inputs
        .iter()
        .filter(|input| !locked.contains(&(input.txid, input.vout)))
        .map(|input| {
            json!({
                "txid": display_txid(input.txid),
                "vout": input.vout,
            })
        })
        .collect();
    if !outpoints.is_empty()
        && rpc.wallet_rpc("lockunspent", json!([false, outpoints]))? != Value::Bool(true)
    {
        return Err(LiveBitcoinError::FundingInputUnavailable);
    }
    let mut total_input_sat = 0_u64;
    for input in selected_inputs {
        let result = rpc.node_rpc(
            "gettxout",
            json!([display_txid(input.txid), input.vout, true]),
        )?;
        if result.is_null() || !result.is_object() {
            return Err(LiveBitcoinError::FundingInputUnavailable);
        }
        let value_sat = result
            .get("value")
            .ok_or(LiveBitcoinError::InvalidRpcResponse)
            .and_then(exact_rpc_btc_amount_sat)?;
        total_input_sat = total_input_sat
            .checked_add(value_sat)
            .filter(|sum| *sum <= MAX_MONEY_SAT)
            .ok_or(LiveBitcoinError::BoundsExceeded)?;
    }
    if total_input_sat == 0 {
        return Err(LiveBitcoinError::FundingInputUnavailable);
    }
    Ok(total_input_sat)
}

fn validate_prepared_record(
    expected_network: BitcoinCoreNetworkV1,
    expected_genesis: [u8; 32],
    expected_signet_challenge: Option<&[u8]>,
    record: &PreparedRecord,
) -> Result<(), LiveBitcoinError> {
    if record.network != expected_network
        || record.genesis_hash != expected_genesis
        || record.signet_challenge.as_deref() != expected_signet_challenge
    {
        return Err(LiveBitcoinError::IdentityMismatch);
    }
    validate_plan(record.network, &record.plan)?;
    if record.raw_transaction.is_empty()
        || record.raw_transaction.len() > MAX_TRANSACTION_BYTES
        || record.selected_inputs.is_empty()
        || record.selected_inputs.len() > MAX_TRANSACTION_INPUTS
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let transaction: Transaction =
        deserialize(&record.raw_transaction).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    let output_sum = transaction.output.iter().try_fold(0_u64, |sum, output| {
        let amount = output.value.to_sat();
        if amount == 0 || amount > MAX_MONEY_SAT {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        sum.checked_add(amount)
            .ok_or(LiveBitcoinError::BoundsExceeded)
    })?;
    if serialize(&transaction) != record.raw_transaction
        || output_sum > MAX_MONEY_SAT
        || transaction.compute_txid().to_raw_hash().to_byte_array() != record.txid
        || transaction.compute_wtxid().to_raw_hash().to_byte_array() != record.wtxid
        || transaction.input.len() != record.selected_inputs.len()
        || transaction.output.len() > MAX_TRANSACTION_OUTPUTS
        || transaction
            .output
            .get(record.contract_vout as usize)
            .filter(|output| {
                output.value.to_sat() == record.plan.amount_sat
                    && output.script_pubkey.as_bytes() == record.plan.contract_script_pubkey
            })
            .is_none()
        || transaction
            .output
            .iter()
            .filter(|output| {
                output.value.to_sat() == record.plan.amount_sat
                    && output.script_pubkey.as_bytes() == record.plan.contract_script_pubkey
            })
            .count()
            != 1
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    let mut unique = BTreeSet::new();
    for (input, retained) in transaction.input.iter().zip(&record.selected_inputs) {
        if input.previous_output.txid.to_raw_hash().to_byte_array() != retained.txid
            || input.previous_output.vout != retained.vout
            || !unique.insert((retained.txid, retained.vout))
        {
            return Err(LiveBitcoinError::CorruptRecord);
        }
    }
    Ok(())
}

fn canonical_plan_digest(plan: &BitcoinPrebroadcastPlanV1) -> Result<[u8; 32], LiveBitcoinError> {
    if plan.contract_script_pubkey.len() > MAX_SCRIPT_BYTES
        || plan.refund_contract.script.len() > MAX_SCRIPT_BYTES
        || plan.refund_contract.control_block.len() > 33
        || plan.refund_outputs.len() > MAX_TRANSACTION_OUTPUTS
        || plan
            .refund_outputs
            .iter()
            .any(|output| output.script_pubkey.len() > MAX_SCRIPT_BYTES)
    {
        return Err(LiveBitcoinError::BoundsExceeded);
    }
    let mut encoding = Vec::new();
    encode_plan(&mut encoding, plan)?;
    if encoding.len() > MAX_DURABLE_RECORD_BYTES {
        return Err(LiveBitcoinError::BoundsExceeded);
    }
    digest(PLAN_DIGEST_DOMAIN, &encoding)
}

fn build_funding_summary(
    record: &PreparedRecord,
    prepared_record_digest: [u8; 32],
    total_input_sat: u64,
) -> Result<BitcoinPreparedFundingSummaryV1, LiveBitcoinError> {
    let transaction: Transaction =
        deserialize(&record.raw_transaction).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    let total_output_sat = funding_output_sum(&transaction)?;
    let actual_fee_sat = total_input_sat
        .checked_sub(total_output_sat)
        .filter(|fee| *fee > 0)
        .ok_or(LiveBitcoinError::FundingMismatch)?;
    let virtual_size_vb = u64::try_from(transaction.vsize())
        .ok()
        .filter(|size| *size > 0)
        .ok_or(LiveBitcoinError::BoundsExceeded)?;
    let mut summary = BitcoinPreparedFundingSummaryV1 {
        route_binding: record.plan.route_binding,
        plan_digest: canonical_plan_digest(&record.plan)?,
        prepared_record_digest,
        summary_record_digest: [0; 32],
        funding_txid: record.txid,
        funding_wtxid: record.wtxid,
        contract_vout: record.contract_vout,
        contract_amount_sat: record.plan.amount_sat,
        requested_fee_rate_sat_vb: record.plan.fee_rate_sat_vb,
        total_input_sat,
        total_output_sat,
        actual_fee_sat,
        virtual_size_vb,
        refund_delay: BitcoinRefundDelayV1::from_sequence(record.plan.refund_contract.sequence)?,
    };
    summary.summary_record_digest = digest(
        FUNDING_SUMMARY_DIGEST_DOMAIN,
        &encode_funding_summary_without_digest(&summary),
    )?;
    Ok(summary)
}

fn validate_funding_summary(
    record: &PreparedRecord,
    prepared_record_digest: [u8; 32],
    summary: &BitcoinPreparedFundingSummaryV1,
) -> Result<(), LiveBitcoinError> {
    let transaction: Transaction =
        deserialize(&record.raw_transaction).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    let total_output_sat = funding_output_sum(&transaction)?;
    let actual_fee_sat = summary
        .total_input_sat
        .checked_sub(total_output_sat)
        .filter(|fee| *fee > 0)
        .ok_or(LiveBitcoinError::CorruptRecord)?;
    let virtual_size_vb =
        u64::try_from(transaction.vsize()).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    if summary.route_binding != record.plan.route_binding
        || summary.plan_digest != canonical_plan_digest(&record.plan)?
        || summary.prepared_record_digest != prepared_record_digest
        || summary.funding_txid != record.txid
        || summary.funding_wtxid != record.wtxid
        || summary.contract_vout != record.contract_vout
        || summary.contract_amount_sat != record.plan.amount_sat
        || summary.requested_fee_rate_sat_vb != record.plan.fee_rate_sat_vb
        || summary.total_input_sat == 0
        || summary.total_input_sat > MAX_MONEY_SAT
        || summary.total_output_sat != total_output_sat
        || summary.actual_fee_sat != actual_fee_sat
        || summary.virtual_size_vb == 0
        || summary.virtual_size_vb != virtual_size_vb
        || summary.refund_delay
            != BitcoinRefundDelayV1::from_sequence(record.plan.refund_contract.sequence)?
        || summary.summary_record_digest
            != digest(
                FUNDING_SUMMARY_DIGEST_DOMAIN,
                &encode_funding_summary_without_digest(summary),
            )?
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(())
}

fn funding_output_sum(transaction: &Transaction) -> Result<u64, LiveBitcoinError> {
    if transaction.output.is_empty() || transaction.output.len() > MAX_TRANSACTION_OUTPUTS {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    transaction.output.iter().try_fold(0_u64, |sum, output| {
        let amount = output.value.to_sat();
        if amount == 0 || amount > MAX_MONEY_SAT {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        sum.checked_add(amount)
            .filter(|total| *total <= MAX_MONEY_SAT)
            .ok_or(LiveBitcoinError::BoundsExceeded)
    })
}

fn unsigned_refund_transaction(prepared: &PreparedRecord) -> Result<Transaction, LiveBitcoinError> {
    let txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
        prepared.txid,
    ));
    let outputs = prepared
        .plan
        .refund_outputs
        .iter()
        .map(|output| TxOut {
            value: Amount::from_sat(output.amount_sat),
            script_pubkey: ScriptBuf::from_bytes(output.script_pubkey.clone()),
        })
        .collect();
    Ok(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid,
                vout: prepared.contract_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(prepared.plan.refund_contract.sequence),
            witness: Witness::new(),
        }],
        output: outputs,
    })
}

pub(crate) fn prepared_template_digests(
    rpc: &BitcoinCoreRpcClientV1,
    prepared: &PreparedBitcoinFundingV1,
    claim_output: &BitcoinRefundOutputV1,
) -> Result<[[u8; 32]; 3], LiveBitcoinError> {
    if claim_output.amount_sat == 0
        || claim_output.amount_sat >= prepared.record.plan.amount_sat
        || claim_output.script_pubkey.is_empty()
        || claim_output.script_pubkey.len() > MAX_SCRIPT_BYTES
    {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    rpc.require_chain_identity()?;
    validate_prepared_record(
        rpc.network(),
        rpc.genesis_hash(),
        rpc.signet_challenge(),
        &prepared.record,
    )?;
    let funding: Transaction = deserialize(&prepared.record.raw_transaction)
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if funding
        .input
        .iter()
        .any(|input| !input.script_sig.is_empty())
    {
        return Err(LiveBitcoinError::FundingMismatch);
    }
    let funding_prevouts = selected_input_prevouts(rpc, &prepared.record.selected_inputs)?;
    let network = template_network(prepared.record.network);
    let funding_template = frozen_template_for_transaction(&funding, funding_prevouts, network)?;

    let contract_prevout = BitcoinPrevoutV1 {
        txid: prepared.record.txid,
        vout: prepared.record.contract_vout,
        amount_sat: prepared.record.plan.amount_sat,
        script_pubkey: prepared.record.plan.contract_script_pubkey.clone(),
    };
    let contract_txid = Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
        prepared.record.txid,
    ));
    let claim = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: contract_txid,
                vout: prepared.record.contract_vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence(0xffff_fffd),
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(claim_output.amount_sat),
            script_pubkey: ScriptBuf::from_bytes(claim_output.script_pubkey.clone()),
        }],
    };
    let claim_template =
        frozen_template_for_transaction(&claim, vec![contract_prevout.clone()], network)?;
    let refund = unsigned_refund_transaction(&prepared.record)?;
    let refund_template =
        frozen_template_for_transaction(&refund, vec![contract_prevout], network)?;
    let digests = [
        frozen_template_digest_v1(&funding_template)
            .map_err(|_| LiveBitcoinError::FundingMismatch)?,
        frozen_template_digest_v1(&claim_template)
            .map_err(|_| LiveBitcoinError::FundingMismatch)?,
        frozen_template_digest_v1(&refund_template)
            .map_err(|_| LiveBitcoinError::RefundMismatch)?,
    ];
    if digests.contains(&[0; 32])
        || digests[0] == digests[1]
        || digests[0] == digests[2]
        || digests[1] == digests[2]
    {
        return Err(LiveBitcoinError::FundingMismatch);
    }
    rpc.require_chain_identity()?;
    Ok(digests)
}

fn selected_input_prevouts(
    rpc: &BitcoinCoreRpcClientV1,
    inputs: &[SelectedInput],
) -> Result<Vec<BitcoinPrevoutV1>, LiveBitcoinError> {
    if inputs.is_empty() || inputs.len() > MAX_TRANSACTION_INPUTS {
        return Err(LiveBitcoinError::FundingMismatch);
    }
    inputs
        .iter()
        .map(|input| {
            let result = rpc.node_rpc(
                "gettxout",
                json!([display_txid(input.txid), input.vout, true]),
            )?;
            if result.is_null() || !result.is_object() {
                return Err(LiveBitcoinError::FundingInputUnavailable);
            }
            let amount_sat = result
                .get("value")
                .ok_or(LiveBitcoinError::InvalidRpcResponse)
                .and_then(exact_rpc_btc_amount_sat)?;
            let script_pubkey = result
                .get("scriptPubKey")
                .and_then(|value| value.get("hex"))
                .and_then(Value::as_str)
                .ok_or(LiveBitcoinError::InvalidRpcResponse)
                .and_then(|value| decode_hex_bounded(value, MAX_SCRIPT_BYTES))?;
            if script_pubkey.is_empty() {
                return Err(LiveBitcoinError::InvalidRpcResponse);
            }
            Ok(BitcoinPrevoutV1 {
                txid: input.txid,
                vout: input.vout,
                amount_sat,
                script_pubkey,
            })
        })
        .collect()
}

fn frozen_template_for_transaction(
    transaction: &Transaction,
    prevouts: Vec<BitcoinPrevoutV1>,
    network: TemplateNetworkV1,
) -> Result<FrozenBitcoinTemplateV1, LiveBitcoinError> {
    if transaction.input.len() != prevouts.len()
        || transaction.input.is_empty()
        || transaction.output.is_empty()
        || transaction.input.len() > MAX_TRANSACTION_INPUTS
        || transaction.output.len() > MAX_TRANSACTION_OUTPUTS
    {
        return Err(LiveBitcoinError::FundingMismatch);
    }
    let inputs = transaction
        .input
        .iter()
        .zip(&prevouts)
        .map(|(input, prevout)| {
            let txid = input.previous_output.txid.to_raw_hash().to_byte_array();
            if txid != prevout.txid || input.previous_output.vout != prevout.vout {
                return Err(LiveBitcoinError::FundingMismatch);
            }
            Ok(BitcoinTxInV1 {
                txid,
                vout: input.previous_output.vout,
                sequence: input.sequence.0,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let outputs = transaction
        .output
        .iter()
        .map(|output| BitcoinTxOutV1 {
            amount_sat: output.value.to_sat(),
            script_pubkey: output.script_pubkey.as_bytes().to_vec(),
        })
        .collect();
    let template = FrozenBitcoinTemplateV1 {
        codec_version: 1,
        network,
        version: transaction.version.0,
        lock_time: transaction.lock_time.to_consensus_u32(),
        inputs,
        outputs,
        prevouts,
    };
    template
        .validate()
        .map_err(|_| LiveBitcoinError::FundingMismatch)?;
    Ok(template)
}

const fn template_network(network: BitcoinCoreNetworkV1) -> TemplateNetworkV1 {
    match network {
        BitcoinCoreNetworkV1::Regtest => TemplateNetworkV1::Regtest,
        BitcoinCoreNetworkV1::PublicSignet => TemplateNetworkV1::PublicSignet,
        BitcoinCoreNetworkV1::CustomSignet => TemplateNetworkV1::CustomSignet,
    }
}

fn refund_signature_hash(
    prepared: &PreparedRecord,
    transaction: &Transaction,
) -> Result<[u8; 32], LiveBitcoinError> {
    let prevout = TxOut {
        value: Amount::from_sat(prepared.plan.amount_sat),
        script_pubkey: ScriptBuf::from_bytes(prepared.plan.contract_script_pubkey.clone()),
    };
    let prevouts = [prevout];
    let leaf_hash = TapLeafHash::from_script(
        Script::from_bytes(&prepared.plan.refund_contract.script),
        LeafVersion::TapScript,
    );
    SighashCache::new(transaction)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .map(|sighash| sighash.to_byte_array())
        .map_err(|_| LiveBitcoinError::RefundMismatch)
}

fn verify_refund_signature(
    prepared: &PreparedRecord,
    sighash: [u8; 32],
    signature_bytes: &[u8; 64],
) -> Result<(), LiveBitcoinError> {
    let signature =
        Signature::from_slice(signature_bytes).map_err(|_| LiveBitcoinError::RefundMismatch)?;
    let key = XOnlyPublicKey::from_slice(&prepared.plan.refund_contract.refund_key_xonly)
        .map_err(|_| LiveBitcoinError::RefundMismatch)?;
    Secp256k1::verification_only()
        .verify_schnorr(&signature, &Message::from_digest(sighash), &key)
        .map_err(|_| LiveBitcoinError::RefundMismatch)
}

fn refund_signing_request_digest(
    request: &BitcoinRefundSigningRequestV1,
) -> Result<[u8; 32], LiveBitcoinError> {
    let mut encoding = Vec::with_capacity(32 * 7 + 4 + 8);
    encoding.extend_from_slice(&request.route_binding);
    encoding.extend_from_slice(&request.plan_digest);
    encoding.extend_from_slice(&request.prepared_record_digest);
    encoding.extend_from_slice(&request.summary_record_digest);
    encoding.extend_from_slice(&request.funding_txid);
    encoding.extend_from_slice(&request.contract_vout.to_be_bytes());
    encoding.extend_from_slice(&request.contract_amount_sat.to_be_bytes());
    encoding.extend_from_slice(&request.refund_key_xonly);
    encoding.extend_from_slice(&request.refund_delay.sequence().to_be_bytes());
    encoding.extend_from_slice(&request.sighash);
    digest(REFUND_SIGNING_REQUEST_DOMAIN, &encoding)
}

fn external_funding_custody(
    armed: &ArmedBitcoinFundingV1,
) -> Result<BitcoinExternalFundingCustodyV1, LiveBitcoinError> {
    require_refund_binding(&armed.prepared, &armed.arm.refund)?;
    validate_funding_summary(
        &armed.prepared.record,
        armed.prepared.record_digest,
        &armed.prepared.summary,
    )?;
    let summary = armed.prepared.summary;
    let mut custody = BitcoinExternalFundingCustodyV1 {
        network: armed.prepared.record.network,
        genesis_hash: armed.prepared.record.genesis_hash,
        signet_challenge_digest: bitcoin_signet_challenge_digest_v1(
            armed
                .prepared
                .record
                .signet_challenge
                .as_deref()
                .unwrap_or_default(),
        )?,
        route_binding: summary.route_binding,
        plan_digest: summary.plan_digest,
        prepared_record_digest: summary.prepared_record_digest,
        summary_record_digest: summary.summary_record_digest,
        refund_record_digest: armed.arm.refund.record_digest,
        funding_txid: armed.prepared.record.txid,
        refund_txid: armed.arm.refund.txid,
        contract_vout: summary.contract_vout,
        contract_amount_sat: summary.contract_amount_sat,
        actual_fee_sat: summary.actual_fee_sat,
        virtual_size_vb: summary.virtual_size_vb,
        custody_digest: [0; 32],
    };
    let mut encoding = Vec::with_capacity(1 + 32 * 9 + 4 + 8 * 3);
    encoding.push(encode_network(custody.network));
    encoding.extend_from_slice(&custody.genesis_hash);
    encoding.extend_from_slice(&custody.signet_challenge_digest);
    encoding.extend_from_slice(&custody.route_binding);
    encoding.extend_from_slice(&custody.plan_digest);
    encoding.extend_from_slice(&custody.prepared_record_digest);
    encoding.extend_from_slice(&custody.summary_record_digest);
    encoding.extend_from_slice(&custody.refund_record_digest);
    encoding.extend_from_slice(&custody.funding_txid);
    encoding.extend_from_slice(&custody.refund_txid);
    encoding.extend_from_slice(&custody.contract_vout.to_be_bytes());
    encoding.extend_from_slice(&custody.contract_amount_sat.to_be_bytes());
    encoding.extend_from_slice(&custody.actual_fee_sat.to_be_bytes());
    encoding.extend_from_slice(&custody.virtual_size_vb.to_be_bytes());
    custody.custody_digest = digest(EXTERNAL_FUNDING_CUSTODY_DOMAIN, &encoding)?;
    Ok(custody)
}

fn validate_refund_transaction(
    prepared: &PreparedRecord,
    canonical_signed_refund: &[u8],
) -> Result<(), LiveBitcoinError> {
    if canonical_signed_refund.is_empty() || canonical_signed_refund.len() > MAX_TRANSACTION_BYTES {
        return Err(LiveBitcoinError::RefundMismatch);
    }
    let transaction: Transaction =
        deserialize(canonical_signed_refund).map_err(|_| LiveBitcoinError::RefundMismatch)?;
    if serialize(&transaction) != canonical_signed_refund
        || transaction.version.0 != 2
        || transaction.lock_time != LockTime::ZERO
        || transaction.input.len() != 1
        || transaction.output.is_empty()
        || transaction.output.len() > MAX_TRANSACTION_OUTPUTS
    {
        return Err(LiveBitcoinError::RefundMismatch);
    }
    let input = &transaction.input[0];
    if input.previous_output.txid.to_raw_hash().to_byte_array() != prepared.txid
        || input.previous_output.vout != prepared.contract_vout
        || !input.script_sig.is_empty()
        || input.sequence.0 != prepared.plan.refund_contract.sequence
    {
        return Err(LiveBitcoinError::RefundMismatch);
    }
    let witness: Vec<&[u8]> = input.witness.iter().collect();
    if witness.len() != 3
        || witness[0].len() != 64
        || witness[1] != prepared.plan.refund_contract.script
        || witness[2] != prepared.plan.refund_contract.control_block
    {
        return Err(LiveBitcoinError::RefundMismatch);
    }
    if transaction.output.len() != prepared.plan.refund_outputs.len()
        || transaction
            .output
            .iter()
            .zip(&prepared.plan.refund_outputs)
            .any(|(actual, expected)| {
                actual.value.to_sat() != expected.amount_sat
                    || actual.script_pubkey.as_bytes() != expected.script_pubkey
            })
    {
        return Err(LiveBitcoinError::RefundMismatch);
    }
    let signature_bytes: [u8; 64] = witness[0]
        .try_into()
        .map_err(|_| LiveBitcoinError::RefundMismatch)?;
    verify_refund_signature(
        prepared,
        refund_signature_hash(prepared, &transaction)?,
        &signature_bytes,
    )
}

fn require_refund_binding(
    prepared: &PreparedBitcoinFundingV1,
    refund: &RefundRecord,
) -> Result<(), LiveBitcoinError> {
    if refund.route_binding != prepared.record.plan.route_binding
        || refund.prepared_digest != prepared.record_digest
    {
        return Err(LiveBitcoinError::StateConflict);
    }
    let unsigned = encode_refund_record_without_digest(refund)?;
    if digest(REFUND_DIGEST_DOMAIN, &unsigned)? != refund.record_digest {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(())
}

fn require_broadcast_binding(
    prepared: &PreparedBitcoinFundingV1,
    refund: &RefundRecord,
    broadcast: &BroadcastRecord,
) -> Result<(), LiveBitcoinError> {
    if broadcast.route_binding != prepared.record.plan.route_binding
        || broadcast.prepared_digest != prepared.record_digest
        || broadcast.refund_digest != refund.record_digest
        || broadcast.txid != prepared.record.txid
    {
        return Err(LiveBitcoinError::StateConflict);
    }
    Ok(())
}

fn digest(domain: &[u8], bytes: &[u8]) -> Result<[u8; 32], LiveBitcoinError> {
    let mut hash = Blake2bVar::new(32).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    hash.update(domain);
    hash.update(bytes);
    let mut output = [0_u8; 32];
    hash.finalize_variable(&mut output)
        .map_err(|_| LiveBitcoinError::CorruptRecord)?;
    Ok(output)
}

fn encode_prepared_record(record: &PreparedRecord) -> Result<Vec<u8>, LiveBitcoinError> {
    let capacity = prepared_record_len(record)?;
    if capacity > MAX_DURABLE_RECORD_BYTES {
        return Err(LiveBitcoinError::BoundsExceeded);
    }
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(PREPARED_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.push(encode_network(record.network));
    output.extend_from_slice(&record.genesis_hash);
    put_bytes(
        &mut output,
        record.signet_challenge.as_deref().unwrap_or_default(),
    )?;
    encode_plan(&mut output, &record.plan)?;
    output.extend_from_slice(&record.txid);
    output.extend_from_slice(&record.wtxid);
    output.extend_from_slice(&record.contract_vout.to_be_bytes());
    put_len(&mut output, record.selected_inputs.len())?;
    for input in &record.selected_inputs {
        output.extend_from_slice(&input.txid);
        output.extend_from_slice(&input.vout.to_be_bytes());
    }
    put_bytes(&mut output, &record.raw_transaction)?;
    if output.len() != capacity {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(output)
}

fn prepared_record_len(record: &PreparedRecord) -> Result<usize, LiveBitcoinError> {
    let mut length = 8_usize + 2 + 1 + 32 + 4;
    length = checked_record_len(
        length,
        record
            .signet_challenge
            .as_deref()
            .map_or(0, |challenge| challenge.len()),
    )?;
    length = checked_record_len(length, 32 + 8)?;
    length = checked_record_len(length, 4 + record.plan.contract_script_pubkey.len())?;
    length = checked_record_len(length, 4 + record.plan.refund_contract.script.len())?;
    length = checked_record_len(length, 4 + record.plan.refund_contract.control_block.len())?;
    length = checked_record_len(length, 32 + 4 + 4)?;
    for output in &record.plan.refund_outputs {
        length = checked_record_len(length, 8 + 4)?;
        length = checked_record_len(length, output.script_pubkey.len())?;
    }
    length = checked_record_len(length, 8)?;
    length = checked_record_len(length, 32 + 32 + 4 + 4)?;
    length = checked_record_len(
        length,
        record
            .selected_inputs
            .len()
            .checked_mul(32 + 4)
            .ok_or(LiveBitcoinError::BoundsExceeded)?,
    )?;
    length = checked_record_len(length, 4 + record.raw_transaction.len())?;
    Ok(length)
}

fn checked_record_len(length: usize, addition: usize) -> Result<usize, LiveBitcoinError> {
    length
        .checked_add(addition)
        .ok_or(LiveBitcoinError::BoundsExceeded)
}

fn decode_prepared_record(bytes: &[u8]) -> Result<PreparedRecord, LiveBitcoinError> {
    let mut cursor = Cursor::new(bytes);
    cursor.require_magic(PREPARED_MAGIC)?;
    cursor.require_version()?;
    let network = decode_network(cursor.take_u8()?)?;
    let genesis_hash = cursor.take_array()?;
    let signet_challenge = match cursor.take_bytes(crate::rpc::MAX_SIGNET_CHALLENGE_BYTES)? {
        challenge if challenge.is_empty() => None,
        challenge => Some(challenge),
    };
    let plan = decode_plan(&mut cursor)?;
    let txid = cursor.take_array()?;
    let wtxid = cursor.take_array()?;
    let contract_vout = cursor.take_u32()?;
    let input_count = cursor.take_len(MAX_TRANSACTION_INPUTS)?;
    let mut selected_inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        selected_inputs.push(SelectedInput {
            txid: cursor.take_array()?,
            vout: cursor.take_u32()?,
        });
    }
    let raw_transaction = cursor.take_bytes(MAX_TRANSACTION_BYTES)?;
    cursor.finish()?;
    Ok(PreparedRecord {
        network,
        genesis_hash,
        signet_challenge,
        plan,
        txid,
        wtxid,
        contract_vout,
        selected_inputs,
        raw_transaction,
    })
}

fn encode_funding_summary_without_digest(summary: &BitcoinPreparedFundingSummaryV1) -> Vec<u8> {
    let mut output = Vec::with_capacity(8 + 2 + 32 * 5 + 4 * 2 + 8 * 7);
    output.extend_from_slice(FUNDING_SUMMARY_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&summary.route_binding);
    output.extend_from_slice(&summary.plan_digest);
    output.extend_from_slice(&summary.prepared_record_digest);
    output.extend_from_slice(&summary.funding_txid);
    output.extend_from_slice(&summary.funding_wtxid);
    output.extend_from_slice(&summary.contract_vout.to_be_bytes());
    output.extend_from_slice(&summary.contract_amount_sat.to_be_bytes());
    output.extend_from_slice(&summary.requested_fee_rate_sat_vb.to_be_bytes());
    output.extend_from_slice(&summary.total_input_sat.to_be_bytes());
    output.extend_from_slice(&summary.total_output_sat.to_be_bytes());
    output.extend_from_slice(&summary.actual_fee_sat.to_be_bytes());
    output.extend_from_slice(&summary.virtual_size_vb.to_be_bytes());
    output.extend_from_slice(&summary.refund_delay.sequence().to_be_bytes());
    output
}

fn encode_funding_summary(
    summary: &BitcoinPreparedFundingSummaryV1,
) -> Result<Vec<u8>, LiveBitcoinError> {
    let mut output = encode_funding_summary_without_digest(summary);
    output.extend_from_slice(&summary.summary_record_digest);
    if output.len() > MAX_DURABLE_RECORD_BYTES {
        return Err(LiveBitcoinError::BoundsExceeded);
    }
    Ok(output)
}

fn decode_funding_summary(
    bytes: &[u8],
) -> Result<BitcoinPreparedFundingSummaryV1, LiveBitcoinError> {
    let mut cursor = Cursor::new(bytes);
    cursor.require_magic(FUNDING_SUMMARY_MAGIC)?;
    cursor.require_version()?;
    let summary = BitcoinPreparedFundingSummaryV1 {
        route_binding: cursor.take_array()?,
        plan_digest: cursor.take_array()?,
        prepared_record_digest: cursor.take_array()?,
        summary_record_digest: [0; 32],
        funding_txid: cursor.take_array()?,
        funding_wtxid: cursor.take_array()?,
        contract_vout: cursor.take_u32()?,
        contract_amount_sat: cursor.take_u64()?,
        requested_fee_rate_sat_vb: cursor.take_u64()?,
        total_input_sat: cursor.take_u64()?,
        total_output_sat: cursor.take_u64()?,
        actual_fee_sat: cursor.take_u64()?,
        virtual_size_vb: cursor.take_u64()?,
        refund_delay: BitcoinRefundDelayV1::from_sequence(cursor.take_u32()?)
            .map_err(|_| LiveBitcoinError::CorruptRecord)?,
    };
    let mut summary = BitcoinPreparedFundingSummaryV1 {
        summary_record_digest: cursor.take_array()?,
        ..summary
    };
    cursor.finish()?;
    let expected = digest(
        FUNDING_SUMMARY_DIGEST_DOMAIN,
        &encode_funding_summary_without_digest(&summary),
    )?;
    if summary.summary_record_digest != expected {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    // Keep this assignment explicit so future codec additions cannot use an
    // unchecked digest retained from a partially decoded value.
    summary.summary_record_digest = expected;
    Ok(summary)
}

fn encode_plan(
    output: &mut Vec<u8>,
    plan: &BitcoinPrebroadcastPlanV1,
) -> Result<(), LiveBitcoinError> {
    output.extend_from_slice(&plan.route_binding);
    output.extend_from_slice(&plan.amount_sat.to_be_bytes());
    put_bytes(output, &plan.contract_script_pubkey)?;
    put_bytes(output, &plan.refund_contract.script)?;
    put_bytes(output, &plan.refund_contract.control_block)?;
    output.extend_from_slice(&plan.refund_contract.refund_key_xonly);
    output.extend_from_slice(&plan.refund_contract.sequence.to_be_bytes());
    put_len(output, plan.refund_outputs.len())?;
    for refund_output in &plan.refund_outputs {
        output.extend_from_slice(&refund_output.amount_sat.to_be_bytes());
        put_bytes(output, &refund_output.script_pubkey)?;
    }
    output.extend_from_slice(&plan.fee_rate_sat_vb.to_be_bytes());
    Ok(())
}

fn decode_plan(cursor: &mut Cursor<'_>) -> Result<BitcoinPrebroadcastPlanV1, LiveBitcoinError> {
    let route_binding = cursor.take_array()?;
    let amount_sat = cursor.take_u64()?;
    let contract_script_pubkey = cursor.take_bytes(MAX_SCRIPT_BYTES)?;
    let refund_contract = BitcoinRefundContractV1 {
        script: cursor.take_bytes(MAX_SCRIPT_BYTES)?,
        control_block: cursor.take_bytes(33)?,
        refund_key_xonly: cursor.take_array()?,
        sequence: cursor.take_u32()?,
    };
    let output_count = cursor.take_len(MAX_TRANSACTION_OUTPUTS)?;
    let mut refund_outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        refund_outputs.push(BitcoinRefundOutputV1 {
            amount_sat: cursor.take_u64()?,
            script_pubkey: cursor.take_bytes(MAX_SCRIPT_BYTES)?,
        });
    }
    Ok(BitcoinPrebroadcastPlanV1 {
        route_binding,
        amount_sat,
        contract_script_pubkey,
        refund_contract,
        refund_outputs,
        fee_rate_sat_vb: cursor.take_u64()?,
    })
}

fn encode_refund_record_without_digest(record: &RefundRecord) -> Result<Vec<u8>, LiveBitcoinError> {
    let mut output = Vec::new();
    output.extend_from_slice(REFUND_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&record.route_binding);
    output.extend_from_slice(&record.prepared_digest);
    output.extend_from_slice(&record.txid);
    output.extend_from_slice(&record.wtxid);
    put_bytes(&mut output, &record.raw_transaction)?;
    Ok(output)
}

fn encode_refund_record(record: &RefundRecord) -> Result<Vec<u8>, LiveBitcoinError> {
    let mut output = encode_refund_record_without_digest(record)?;
    output.extend_from_slice(&record.record_digest);
    Ok(output)
}

fn decode_refund_record(bytes: &[u8]) -> Result<RefundRecord, LiveBitcoinError> {
    let mut cursor = Cursor::new(bytes);
    cursor.require_magic(REFUND_MAGIC)?;
    cursor.require_version()?;
    let route_binding = cursor.take_array()?;
    let prepared_digest = cursor.take_array()?;
    let txid = cursor.take_array()?;
    let wtxid = cursor.take_array()?;
    let raw_transaction = cursor.take_bytes(MAX_TRANSACTION_BYTES)?;
    let record_digest = cursor.take_array()?;
    cursor.finish()?;
    let record = RefundRecord {
        route_binding,
        prepared_digest,
        txid,
        wtxid,
        raw_transaction,
        record_digest,
    };
    let transaction: Transaction =
        deserialize(&record.raw_transaction).map_err(|_| LiveBitcoinError::CorruptRecord)?;
    if serialize(&transaction) != record.raw_transaction
        || transaction.compute_txid().to_raw_hash().to_byte_array() != record.txid
        || transaction.compute_wtxid().to_raw_hash().to_byte_array() != record.wtxid
        || digest(
            REFUND_DIGEST_DOMAIN,
            &encode_refund_record_without_digest(&record)?,
        )? != record.record_digest
    {
        return Err(LiveBitcoinError::CorruptRecord);
    }
    Ok(record)
}

fn encode_broadcast_record(record: &BroadcastRecord) -> Vec<u8> {
    let mut output = Vec::with_capacity(8 + 2 + 32 * 4);
    output.extend_from_slice(BROADCAST_MAGIC);
    output.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&record.route_binding);
    output.extend_from_slice(&record.prepared_digest);
    output.extend_from_slice(&record.refund_digest);
    output.extend_from_slice(&record.txid);
    output
}

fn decode_broadcast_record(bytes: &[u8]) -> Result<BroadcastRecord, LiveBitcoinError> {
    let mut cursor = Cursor::new(bytes);
    cursor.require_magic(BROADCAST_MAGIC)?;
    cursor.require_version()?;
    let record = BroadcastRecord {
        route_binding: cursor.take_array()?,
        prepared_digest: cursor.take_array()?,
        refund_digest: cursor.take_array()?,
        txid: cursor.take_array()?,
    };
    cursor.finish()?;
    Ok(record)
}

fn encode_network(network: BitcoinCoreNetworkV1) -> u8 {
    match network {
        BitcoinCoreNetworkV1::Regtest => 1,
        BitcoinCoreNetworkV1::PublicSignet => 2,
        BitcoinCoreNetworkV1::CustomSignet => 3,
    }
}

fn decode_network(value: u8) -> Result<BitcoinCoreNetworkV1, LiveBitcoinError> {
    match value {
        1 => Ok(BitcoinCoreNetworkV1::Regtest),
        2 => Ok(BitcoinCoreNetworkV1::PublicSignet),
        3 => Ok(BitcoinCoreNetworkV1::CustomSignet),
        _ => Err(LiveBitcoinError::CorruptRecord),
    }
}

fn put_len(output: &mut Vec<u8>, length: usize) -> Result<(), LiveBitcoinError> {
    let length = u32::try_from(length).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
    output.extend_from_slice(&length.to_be_bytes());
    Ok(())
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), LiveBitcoinError> {
    put_len(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn require_magic(&mut self, expected: &[u8; 8]) -> Result<(), LiveBitcoinError> {
        if self.take(8)? != expected {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        Ok(())
    }

    fn require_version(&mut self) -> Result<(), LiveBitcoinError> {
        if self.take_u16()? != CODEC_VERSION {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        Ok(())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], LiveBitcoinError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(LiveBitcoinError::BoundsExceeded)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(LiveBitcoinError::CorruptRecord)?;
        self.position = end;
        Ok(value)
    }

    fn take_u8(&mut self) -> Result<u8, LiveBitcoinError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(LiveBitcoinError::CorruptRecord)
    }

    fn take_u16(&mut self) -> Result<u16, LiveBitcoinError> {
        self.take(2)?
            .try_into()
            .map(u16::from_be_bytes)
            .map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn take_u32(&mut self) -> Result<u32, LiveBitcoinError> {
        self.take(4)?
            .try_into()
            .map(u32::from_be_bytes)
            .map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn take_u64(&mut self) -> Result<u64, LiveBitcoinError> {
        self.take(8)?
            .try_into()
            .map(u64::from_be_bytes)
            .map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], LiveBitcoinError> {
        self.take(N)?
            .try_into()
            .map_err(|_| LiveBitcoinError::CorruptRecord)
    }

    fn take_len(&mut self, maximum: usize) -> Result<usize, LiveBitcoinError> {
        let length =
            usize::try_from(self.take_u32()?).map_err(|_| LiveBitcoinError::BoundsExceeded)?;
        if length > maximum {
            return Err(LiveBitcoinError::BoundsExceeded);
        }
        Ok(length)
    }

    fn take_bytes(&mut self, maximum: usize) -> Result<Vec<u8>, LiveBitcoinError> {
        let length = self.take_len(maximum)?;
        self.take(length).map(ToOwned::to_owned)
    }

    fn finish(self) -> Result<(), LiveBitcoinError> {
        if self.position != self.bytes.len() {
            return Err(LiveBitcoinError::CorruptRecord);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::DirBuilderExt;
    #[cfg(target_os = "linux")]
    use std::time::{SystemTime, UNIX_EPOCH};

    use bitcoin::absolute::LockTime;
    use bitcoin::secp256k1::Keypair;
    use bitcoin::taproot::TaprootBuilder;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, Sequence, TxIn, Txid, Witness};

    use super::*;

    fn codec_record() -> PreparedRecord {
        let transaction = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                        [0x21; 32],
                    )),
                    vout: 3,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes({
                    let mut script = vec![0x51, 0x20];
                    script.extend_from_slice(&[0x22; 32]);
                    script
                }),
            }],
        };
        let raw_transaction = serialize(&transaction);
        PreparedRecord {
            network: BitcoinCoreNetworkV1::Regtest,
            genesis_hash: [0x31; 32],
            signet_challenge: None,
            plan: BitcoinPrebroadcastPlanV1 {
                route_binding: [0x32; 32],
                amount_sat: 50_000,
                contract_script_pubkey: transaction.output[0].script_pubkey.to_bytes(),
                refund_contract: BitcoinRefundContractV1 {
                    script: vec![1, 10, 0xb2, 0x75, 0x20]
                        .into_iter()
                        .chain([0x33; 32])
                        .chain([0xac])
                        .collect(),
                    control_block: vec![0xc0; 33],
                    refund_key_xonly: [0x33; 32],
                    sequence: 10,
                },
                refund_outputs: vec![BitcoinRefundOutputV1 {
                    amount_sat: 49_000,
                    script_pubkey: vec![0x51],
                }],
                fee_rate_sat_vb: 2,
            },
            txid: transaction.compute_txid().to_raw_hash().to_byte_array(),
            wtxid: transaction.compute_wtxid().to_raw_hash().to_byte_array(),
            contract_vout: 0,
            selected_inputs: vec![SelectedInput {
                txid: [0x21; 32],
                vout: 3,
            }],
            raw_transaction,
        }
    }

    fn signed_refund_fixture() -> Result<(PreparedRecord, Vec<u8>), LiveBitcoinError> {
        let secp = Secp256k1::new();
        let refund_keypair = Keypair::from_seckey_slice(&secp, &[0x41; 32])
            .map_err(|_| LiveBitcoinError::InvalidRequest)?;
        let (refund_key, _) = XOnlyPublicKey::from_keypair(&refund_keypair);
        let internal_keypair = Keypair::from_seckey_slice(&secp, &[0x42; 32])
            .map_err(|_| LiveBitcoinError::InvalidRequest)?;
        let (internal_key, _) = XOnlyPublicKey::from_keypair(&internal_keypair);
        let refund_script = ScriptBuf::from_bytes(
            vec![1, 10, 0xb2, 0x75, 0x20]
                .into_iter()
                .chain(refund_key.serialize())
                .chain([0xac])
                .collect(),
        );
        let spend_information = TaprootBuilder::new()
            .add_leaf(0, refund_script.clone())
            .map_err(|_| LiveBitcoinError::InvalidRequest)?
            .finalize(&secp, internal_key)
            .map_err(|_| LiveBitcoinError::InvalidRequest)?;
        let control_block = spend_information
            .control_block(&(refund_script.clone(), LeafVersion::TapScript))
            .ok_or(LiveBitcoinError::InvalidRequest)?
            .serialize();
        let contract_script_pubkey =
            ScriptBuf::new_p2tr(&secp, internal_key, spend_information.merkle_root());
        let funding_input_txid = [0x51; 32];
        let funding = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(
                        funding_input_txid,
                    )),
                    vout: 2,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: contract_script_pubkey.clone(),
            }],
        };
        let plan = BitcoinPrebroadcastPlanV1 {
            route_binding: [0x52; 32],
            amount_sat: 50_000,
            contract_script_pubkey: contract_script_pubkey.to_bytes(),
            refund_contract: BitcoinRefundContractV1 {
                script: refund_script.to_bytes(),
                control_block,
                refund_key_xonly: refund_key.serialize(),
                sequence: 10,
            },
            refund_outputs: vec![BitcoinRefundOutputV1 {
                amount_sat: 49_000,
                script_pubkey: vec![0x51],
            }],
            fee_rate_sat_vb: 2,
        };
        validate_plan(BitcoinCoreNetworkV1::Regtest, &plan)?;
        let raw_funding = serialize(&funding);
        let prepared = PreparedRecord {
            network: BitcoinCoreNetworkV1::Regtest,
            genesis_hash: [0x53; 32],
            signet_challenge: None,
            plan,
            txid: funding.compute_txid().to_raw_hash().to_byte_array(),
            wtxid: funding.compute_wtxid().to_raw_hash().to_byte_array(),
            contract_vout: 0,
            selected_inputs: vec![SelectedInput {
                txid: funding_input_txid,
                vout: 2,
            }],
            raw_transaction: raw_funding,
        };
        validate_prepared_record(
            BitcoinCoreNetworkV1::Regtest,
            prepared.genesis_hash,
            None,
            &prepared,
        )?;

        let mut refund = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: funding.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence(10),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let prevout = TxOut {
            value: Amount::from_sat(prepared.plan.amount_sat),
            script_pubkey: ScriptBuf::from_bytes(prepared.plan.contract_script_pubkey.clone()),
        };
        let leaf_hash = TapLeafHash::from_script(
            Script::from_bytes(&prepared.plan.refund_contract.script),
            LeafVersion::TapScript,
        );
        let sighash = SighashCache::new(&refund)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[prevout]),
                leaf_hash,
                TapSighashType::Default,
            )
            .map_err(|_| LiveBitcoinError::RefundMismatch)?;
        let signature = secp.sign_schnorr_no_aux_rand(
            &Message::from_digest(sighash.to_byte_array()),
            &refund_keypair,
        );
        refund.input[0].witness = Witness::from_slice(&[
            signature.as_ref(),
            prepared.plan.refund_contract.script.as_slice(),
            prepared.plan.refund_contract.control_block.as_slice(),
        ]);
        Ok((prepared, serialize(&refund)))
    }

    #[cfg(target_os = "linux")]
    fn store_path(label: &str) -> Result<std::path::PathBuf, LiveBitcoinError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let parent = std::env::temp_dir().join(format!(
            "btc-live-funding-{label}-{}-{nonce}",
            std::process::id()
        ));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(&parent)
            .map_err(|_| LiveBitcoinError::StoreUnavailable)?;
        Ok(parent.join("route"))
    }

    #[cfg(target_os = "linux")]
    fn cleanup_store(path: &Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    #[cfg(target_os = "linux")]
    struct FixtureRefundSigner {
        keypair: Keypair,
        expected_plan_digest: [u8; 32],
        expected_summary_digest: [u8; 32],
    }

    impl RetainedBitcoinRefundSignerV1 for FixtureRefundSigner {
        fn refund_key_xonly(&self) -> [u8; 32] {
            XOnlyPublicKey::from_keypair(&self.keypair).0.serialize()
        }

        fn sign_refund(
            self,
            request: BitcoinRefundSigningRequestV1,
        ) -> Result<crate::BitcoinRefundSignatureV1, LiveBitcoinError> {
            if request.plan_digest() != self.expected_plan_digest
                || request.summary_record_digest() != self.expected_summary_digest
            {
                return Err(LiveBitcoinError::RefundMismatch);
            }
            let signature = Secp256k1::new()
                .sign_schnorr_no_aux_rand(&Message::from_digest(request.sighash()), &self.keypair);
            crate::BitcoinRefundSignatureV1::from_bytes(signature.serialize())
        }
    }

    #[test]
    fn prepared_codec_is_exact_and_rejects_trailing_or_unknown_network(
    ) -> Result<(), LiveBitcoinError> {
        let record = codec_record();
        let encoded = encode_prepared_record(&record)?;
        let decoded = decode_prepared_record(&encoded)?;
        assert!(decoded == record);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_prepared_record(&trailing).is_err());

        let mut unknown_network = encoded;
        unknown_network[10] = 0xff;
        assert!(decode_prepared_record(&unknown_network).is_err());
        Ok(())
    }

    #[test]
    fn refund_script_codec_rejects_nonminimal_or_sequence_confusion() {
        let valid = BitcoinRefundContractV1 {
            script: vec![1, 10, 0xb2, 0x75, 0x20]
                .into_iter()
                .chain([0x33; 32])
                .chain([0xac])
                .collect(),
            control_block: vec![0xc0; 33],
            refund_key_xonly: [0x33; 32],
            sequence: 10,
        };
        assert!(validate_refund_script(&valid).is_ok());
        let mut nonminimal = valid.clone();
        nonminimal.script.splice(0..2, [2, 10, 0]);
        assert!(validate_refund_script(&nonminimal).is_err());
        let mut confused = valid;
        confused.sequence = 11;
        assert!(validate_refund_script(&confused).is_err());
        assert!(!is_minimal_positive_script_number(&[0]));
        assert!(BitcoinRefundDelayV1::from_sequence(0).is_err());
        assert!(BitcoinRefundDelayV1::from_sequence(1 << 31).is_err());
        assert_eq!(
            BitcoinRefundDelayV1::from_sequence((1 << 22) | 9),
            Ok(BitcoinRefundDelayV1::Time512Seconds(9))
        );
    }

    #[test]
    fn signed_refund_validation_accepts_exact_witness_and_rejects_tamper(
    ) -> Result<(), LiveBitcoinError> {
        let (prepared, raw_refund) = signed_refund_fixture()?;
        validate_refund_transaction(&prepared, &raw_refund)?;

        for witness_index in 0..3 {
            let mut transaction: Transaction =
                deserialize(&raw_refund).map_err(|_| LiveBitcoinError::CorruptRecord)?;
            let mut witness: Vec<Vec<u8>> = transaction.input[0]
                .witness
                .iter()
                .map(ToOwned::to_owned)
                .collect();
            let first = witness
                .get_mut(witness_index)
                .and_then(|element| element.first_mut())
                .ok_or(LiveBitcoinError::CorruptRecord)?;
            *first ^= 1;
            transaction.input[0].witness = Witness::from_slice(&witness);
            assert!(validate_refund_transaction(&prepared, &serialize(&transaction)).is_err());
        }
        let mut wrong_output: Transaction =
            deserialize(&raw_refund).map_err(|_| LiveBitcoinError::CorruptRecord)?;
        wrong_output.output[0].value = Amount::from_sat(48_999);
        assert!(validate_refund_transaction(&prepared, &serialize(&wrong_output)).is_err());
        Ok(())
    }

    #[test]
    fn prepared_record_rejects_duplicate_wallet_outpoints() -> Result<(), LiveBitcoinError> {
        let (mut prepared, _) = signed_refund_fixture()?;
        let mut funding: Transaction =
            deserialize(&prepared.raw_transaction).map_err(|_| LiveBitcoinError::CorruptRecord)?;
        funding.input.push(funding.input[0].clone());
        prepared
            .selected_inputs
            .push(prepared.selected_inputs[0].clone());
        prepared.raw_transaction = serialize(&funding);
        prepared.txid = funding.compute_txid().to_raw_hash().to_byte_array();
        prepared.wtxid = funding.compute_wtxid().to_raw_hash().to_byte_array();
        assert!(validate_prepared_record(
            BitcoinCoreNetworkV1::Regtest,
            prepared.genesis_hash,
            None,
            &prepared,
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn funding_summary_binds_exact_fee_vsize_and_plan() -> Result<(), LiveBitcoinError> {
        let (prepared, _) = signed_refund_fixture()?;
        let prepared_digest = digest(PREPARED_DIGEST_DOMAIN, &encode_prepared_record(&prepared)?)?;
        let summary = build_funding_summary(&prepared, prepared_digest, 51_000)?;
        assert_eq!(summary.actual_fee_sat(), 1_000);
        assert_eq!(summary.total_output_sat(), 50_000);
        assert_eq!(summary.refund_delay(), BitcoinRefundDelayV1::Blocks(10));
        let encoded = encode_funding_summary(&summary)?;
        let decoded = decode_funding_summary(&encoded)?;
        validate_funding_summary(&prepared, prepared_digest, &decoded)?;
        assert_eq!(decoded, summary);

        let mut tampered = encoded;
        let last = tampered.last_mut().ok_or(LiveBitcoinError::CorruptRecord)?;
        *last ^= 1;
        assert!(decode_funding_summary(&tampered).is_err());
        Ok(())
    }

    #[test]
    fn refund_record_codec_rejects_tamper_and_trailing_bytes() -> Result<(), LiveBitcoinError> {
        let (prepared, raw_refund) = signed_refund_fixture()?;
        let transaction: Transaction =
            deserialize(&raw_refund).map_err(|_| LiveBitcoinError::CorruptRecord)?;
        let prepared_digest = digest(PREPARED_DIGEST_DOMAIN, &encode_prepared_record(&prepared)?)?;
        let mut refund = RefundRecord {
            route_binding: prepared.plan.route_binding,
            prepared_digest,
            txid: transaction.compute_txid().to_raw_hash().to_byte_array(),
            wtxid: transaction.compute_wtxid().to_raw_hash().to_byte_array(),
            raw_transaction: raw_refund,
            record_digest: [0; 32],
        };
        refund.record_digest = digest(
            REFUND_DIGEST_DOMAIN,
            &encode_refund_record_without_digest(&refund)?,
        )?;
        let encoded = encode_refund_record(&refund)?;
        assert!(decode_refund_record(&encoded)? == refund);

        let mut tampered = encoded.clone();
        tampered[10] ^= 1;
        assert!(decode_refund_record(&tampered).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_refund_record(&trailing).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refund_arming_requires_the_same_durable_prepared_stage() -> Result<(), LiveBitcoinError> {
        let (record, raw_refund) = signed_refund_fixture()?;
        let prepared_bytes = encode_prepared_record(&record)?;
        let prepared_digest = digest(PREPARED_DIGEST_DOMAIN, &prepared_bytes)?;
        let summary = build_funding_summary(&record, prepared_digest, 51_000)?;
        let summary_bytes = encode_funding_summary(&summary)?;
        let first_path = store_path("same-store")?;
        let second_path = store_path("cross-store")?;

        let first = BitcoinPrebroadcastStoreV1::open_or_create(&first_path)?;
        first.store.publish(StageKind::Prepared, &prepared_bytes)?;
        first
            .store
            .publish(StageKind::FundingSummary, &summary_bytes)?;
        let armed = first.arm_refund(
            PreparedBitcoinFundingV1 {
                record: record.clone(),
                record_digest: prepared_digest,
                summary,
            },
            &raw_refund,
        )?;
        assert_eq!(armed.canonical_refund_transaction(), raw_refund);

        let second = BitcoinPrebroadcastStoreV1::open_or_create(&second_path)?;
        let cross_store = second.arm_refund(
            PreparedBitcoinFundingV1 {
                record,
                record_digest: prepared_digest,
                summary,
            },
            &raw_refund,
        );
        assert!(matches!(cross_store, Err(LiveBitcoinError::StateConflict)));
        assert!(second.store.read(StageKind::Refund)?.is_none());

        drop(second);
        drop(first);
        cleanup_store(&second_path);
        cleanup_store(&first_path);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn retained_signer_arms_without_receiving_transaction_bytes() -> Result<(), LiveBitcoinError> {
        let (record, expected_refund) = signed_refund_fixture()?;
        let prepared_bytes = encode_prepared_record(&record)?;
        let prepared_digest = digest(PREPARED_DIGEST_DOMAIN, &prepared_bytes)?;
        let summary = build_funding_summary(&record, prepared_digest, 51_000)?;
        let path = store_path("retained-signer")?;
        let store = BitcoinPrebroadcastStoreV1::open_or_create(&path)?;
        store.store.publish(StageKind::Prepared, &prepared_bytes)?;
        store.store.publish(
            StageKind::FundingSummary,
            &encode_funding_summary(&summary)?,
        )?;
        let signer = FixtureRefundSigner {
            keypair: Keypair::from_seckey_slice(&Secp256k1::new(), &[0x41; 32])
                .map_err(|_| LiveBitcoinError::InvalidRequest)?,
            expected_plan_digest: summary.plan_digest(),
            expected_summary_digest: summary.summary_record_digest(),
        };
        let armed = store.arm_refund_with_signer(
            PreparedBitcoinFundingV1 {
                record,
                record_digest: prepared_digest,
                summary,
            },
            signer,
        )?;
        assert_eq!(armed.canonical_refund_transaction(), expected_refund);
        let custody = armed.external_funding_custody()?;
        assert_eq!(custody.prepared_record_digest(), prepared_digest);
        assert_eq!(
            custody.summary_record_digest(),
            summary.summary_record_digest()
        );
        assert_eq!(custody.actual_fee_sat(), 1_000);
        assert_eq!(custody.network(), BitcoinCoreNetworkV1::Regtest);
        assert_eq!(custody.genesis_hash(), [0x53; 32]);
        assert_eq!(
            custody.signet_challenge_digest(),
            bitcoin_signet_challenge_digest_v1(&[])?
        );
        assert_ne!(custody.custody_digest(), [0; 32]);

        drop(store);
        cleanup_store(&path);
        Ok(())
    }

    #[test]
    fn exact_amount_codec_never_uses_binary_float() {
        assert_eq!(exact_btc_amount(1), Ok(serde_json::json!("0.00000001")));
        assert_eq!(
            exact_btc_amount(50_000_001),
            Ok(serde_json::json!("0.50000001"))
        );
        assert!(exact_btc_amount(0).is_err());
        assert_eq!(exact_decimal_btc_amount_sat("1e-8"), Ok(1));
        assert_eq!(exact_decimal_btc_amount_sat("0.50000001"), Ok(50_000_001));
        assert!(exact_decimal_btc_amount_sat("0.000000001").is_err());
        assert!(exact_decimal_btc_amount_sat("-1.0").is_err());
    }

    #[test]
    fn reopened_authority_variants_remain_layout_balanced() {
        let prepared = core::mem::size_of::<PreparedBitcoinFundingV1>();
        let armed = core::mem::size_of::<ArmedBitcoinFundingV1>();
        assert!(prepared.abs_diff(armed) <= 200);
    }
}
