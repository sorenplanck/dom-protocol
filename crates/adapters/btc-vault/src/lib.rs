//! One-shot Bitcoin nonce vault (Annex M v3.2, M.6).
//!
//! The durable custodian of the `session_secrand` reservation. Uniqueness
//! is a property of THIS vault, not of the type system (M.6.1):
//!
//! - a `session_secrand` is born only from a one-shot reservation;
//! - its consumption is persisted and fsync-durable BEFORE any derived
//!   `PubNonce` may leave the process (persist-before-exposure, M.6.5);
//! - legacy F5 keeps its memory-only backend secnonce and crash-to-refund
//!   behavior (M.6.6);
//! - the additive F7 path atomically seals `session_secrand` together with
//!   the exact PubNonce before exposure, reconstructs only the identical
//!   pinned-backend owner after a normal restart, and tombstones the sealed
//!   secret before any partial signature is returned.
//!
//! The vault protects OUR signer. It makes no promise about the
//! counterparty's nonce discipline (M.6.1).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod entropy;
mod permit;
mod seal;
mod secret;
mod state;
mod vault;

pub use entropy::{EntropyError, EntropySource, OsEntropy};
pub use permit::{
    BitcoinNoncePermitV1, BitcoinNoncePurposeV1, BitcoinNonceReservationIdV1, BitcoinSigningPhaseV1,
};
pub use seal::{BitcoinNonceSealKeySlotV1, BitcoinNonceSealKeyStoreV1, BitcoinNonceSealKeyV1};
pub use secret::OneShotSessionSecrandV1;
pub use state::{BitcoinNonceStateV1, PersistedArtifactDescriptorV1, PublicAbortReasonV1};
pub use vault::{BitcoinNonceVault, VaultError};
