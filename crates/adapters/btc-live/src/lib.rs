//! Concrete Bitcoin Core boundary for the F7 production route.
//!
//! The crate owns two deliberately narrow responsibilities:
//!
//! - [`BitcoinPrebroadcastStoreV1`] asks a real Bitcoin Core wallet to select
//!   live UTXOs, construct and sign a funding transaction without publishing
//!   it, persists an authenticated fee/vsize/plan summary, then withholds the
//!   exact funding bytes until a valid script-path CSV refund has been durably
//!   persisted.
//! - [`RetainedBitcoinRefundSignerV1`] receives only a digest-bound public
//!   signing request; the store constructs and arms the exact refund without
//!   returning transaction bytes to the route executor.
//! - [`BitcoinCoreEvidenceCollectorV1`] obtains a stable Bitcoin Core chain
//!   snapshot and constructs canonical raw-transaction, txid/wtxid, Merkle,
//!   block, ancestry and confirmation evidence. The result can be converted
//!   to `btc-evidence` input and directly supplies the byte slices required by
//!   the F7 M.8 anchor authority.
//!
//! RPC credentials are read only from a retained owner-only cookie path.
//! There is no credential getter, command-line transport, implicit broadcast,
//! mock success path, or public constructor for the prepared/armed
//! capabilities.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod authority;
mod evidence;
mod fresh;
mod funding;
mod rpc;
mod store;

pub use authority::{
    BitcoinExternalFundingCustodyV1, BitcoinPreparedFundingSummaryV1, BitcoinRefundDelayV1,
    BitcoinRefundSignatureV1, BitcoinRefundSigningRequestV1, RetainedBitcoinRefundSignerV1,
};
pub use evidence::{
    BitcoinCoreEvidenceCollectorV1, BitcoinEvidenceBindingV1, CanonicalBitcoinRpcEvidenceV1,
};
pub use fresh::{
    BitcoinFreshClaimBindingV1, BitcoinFreshRouteReceiptV1, BitcoinFreshRouteRequestV1,
    BoundFreshBitcoinClaimAuthorityV1, FreshBitcoinPreparedClaimPartsV1,
    PreparedFreshBitcoinClaimV1, PreparedFreshBitcoinRouteV1, ReopenedFreshBitcoinRouteV1,
    RetainedFreshBitcoinClaimAuthorityV1, RetainedFreshBitcoinRefundSignerV1,
};
pub use funding::{
    ArmedBitcoinFundingV1, BitcoinFundingBroadcastReceiptV1, BitcoinPrebroadcastPlanV1,
    BitcoinPrebroadcastStoreV1, BitcoinRefundContractV1, BitcoinRefundOutputV1,
    PreparedBitcoinFundingV1, ReopenedBitcoinFundingV1,
};
pub use rpc::{
    bitcoin_signet_challenge_digest_v1, BitcoinCoreNetworkV1, BitcoinCoreRpcClientV1,
    BitcoinCoreRpcConfigV1,
};

/// Failures from the concrete Bitcoin Core boundary.
///
/// Variants intentionally contain no URLs, paths, RPC bodies, credentials,
/// transactions, scripts, or other attacker-controlled values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LiveBitcoinError {
    /// A public request, binding, amount, script, or network field is invalid.
    #[error("invalid Bitcoin live-boundary request")]
    InvalidRequest,
    /// The loopback endpoint or authenticated chain identity did not match.
    #[error("Bitcoin Core identity mismatch")]
    IdentityMismatch,
    /// The owner-only RPC-cookie authority is unavailable or malformed.
    #[error("Bitcoin Core credential authority unavailable")]
    CredentialUnavailable,
    /// The concrete Bitcoin Core JSON-RPC call failed or was rejected.
    #[error("Bitcoin Core RPC failed")]
    Rpc,
    /// A JSON-RPC response was missing, contradictory, oversized, or malformed.
    #[error("invalid Bitcoin Core RPC response")]
    InvalidRpcResponse,
    /// Bitcoin Core did not provide a complete, signed funding transaction.
    #[error("Bitcoin Core did not complete funding")]
    FundingIncomplete,
    /// The wallet-selected transaction did not match the frozen funding plan.
    #[error("Bitcoin funding transaction mismatch")]
    FundingMismatch,
    /// A selected funding input is no longer an unspent chain output.
    #[error("Bitcoin funding input is unavailable")]
    FundingInputUnavailable,
    /// The supplied refund is not the exact valid F7 script-path spend.
    #[error("Bitcoin refund transaction mismatch")]
    RefundMismatch,
    /// Fresh claim facts did not recreate the receipt-committed Taproot spend.
    #[error("Bitcoin fresh claim binding mismatch")]
    ClaimMismatch,
    /// Durable fresh-claim nonce custody rejected the operation.
    #[error("Bitcoin fresh claim nonce custody rejected the operation")]
    ClaimNonceCustody,
    /// The owner-only durable store is unavailable, invalid, or already locked.
    #[error("Bitcoin prebroadcast store unavailable")]
    StoreUnavailable,
    /// A durable record failed strict codec or authentication checks.
    #[error("Bitcoin prebroadcast record is corrupt")]
    CorruptRecord,
    /// A durable stage conflicts with the requested immutable route binding.
    #[error("Bitcoin prebroadcast state conflict")]
    StateConflict,
    /// Funding broadcast was requested before the refund became durable.
    #[error("Bitcoin funding is not armed for broadcast")]
    FundingNotArmed,
    /// The requested transaction is absent from the canonical confirmed chain.
    #[error("confirmed Bitcoin transaction is unavailable")]
    TransactionUnavailable,
    /// The stable chain snapshot changed during collection.
    #[error("Bitcoin chain snapshot changed during collection")]
    SnapshotChanged,
    /// The evidence did not meet the requested confirmation depth.
    #[error("insufficient Bitcoin confirmations")]
    InsufficientConfirmations,
    /// A configured or decoded allocation exceeded the production bound.
    #[error("Bitcoin live-boundary size bound exceeded")]
    BoundsExceeded,
}
