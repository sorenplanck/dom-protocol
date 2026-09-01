//! Authenticated deployment and chain registry for the production interop runtime.
//!
//! The registry is deliberately off-chain. It freezes the public facts needed
//! to construct DOM, EVM and Bitcoin adapters, binds assets to their deployed
//! representations, authenticates the canonical manifest with a threshold of
//! BIP340 keys and rejects expiry, cross-network substitution and epoch
//! rollback. Endpoint URLs and credentials are intentionally outside this
//! format.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod codec;
mod contract_release;
mod signed;
mod store;
mod types;

pub use contract_release::{
    EvmContractReleaseV1, EvmRuntimePolicyV1, MAX_EVM_CONTRACT_RELEASE_BYTES,
};
pub use signed::{
    AuthoritySetV1, RegistrySignatureV1, SignedRegistryV1, MAX_AUTHORITIES,
    MAX_AUTHORITY_SET_BYTES, MAX_SIGNATURES,
};
pub use store::{InstallOutcomeV1, RegistryStoreV1};
pub use types::{
    AssetBindingV1, AssetRepresentationV1, BitcoinDeploymentV1, ChainDeploymentV1, DomDeploymentV1,
    DomNetworkV1, DomRuntimeIdentityV1, EvmDeploymentV1, EvmSessionBindingsV1, MoneroDeploymentV1,
    RegistryChainProfileV1, RegistryManifestV1, RegistryValidationPolicyV1,
    ResolvedBitcoinDeploymentV1, ResolvedChainProfileV1, ResolvedDomDeploymentV1,
    ResolvedEvmDeploymentV1, ResolvedMoneroDeploymentV1, ResolvedRegistryV1,
    ResolvedSolanaDeploymentV1, SolanaDeploymentV1, MAX_ASSET_BINDINGS, MAX_CHAINS,
    MAX_MANIFEST_BYTES, MAX_SIGNET_CHALLENGE_BYTES,
};

/// Domain separator for the authenticated manifest digest.
pub const REGISTRY_MANIFEST_DOMAIN: &[u8] = b"DOM-INTEROP/DEPLOYMENT-REGISTRY/V2\0";

/// Frozen binary manifest version.
pub const REGISTRY_VERSION: u16 = 2;

/// All named fail-closed registry refusals.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// A configured bound was exceeded before allocation or persistence.
    #[error("registry bound exceeded")]
    BoundExceeded,
    /// The binary representation is malformed or non-canonical.
    #[error("non-canonical registry encoding")]
    NonCanonicalEncoding,
    /// The manifest version is not supported.
    #[error("unsupported registry version")]
    UnsupportedVersion,
    /// A required identifier, deployment or digest is zero.
    #[error("zero registry authority field")]
    ZeroField,
    /// Manifest time bounds are invalid or the manifest is not currently valid.
    #[error("registry manifest expired or not yet valid")]
    InvalidTime,
    /// The manifest belongs to a different DOM interop network.
    #[error("wrong registry network")]
    WrongNetwork,
    /// The manifest epoch is below the externally pinned minimum.
    #[error("registry epoch below pinned minimum")]
    EpochBelowMinimum,
    /// A lower or conflicting epoch attempted to replace durable state.
    #[error("registry rollback or conflicting epoch")]
    Rollback,
    /// A chain or asset registry key was duplicated.
    #[error("duplicate registry entry")]
    DuplicateEntry,
    /// A chain profile and its deployment facts disagree.
    #[error("deployment does not match chain profile")]
    DeploymentMismatch,
    /// A Monero network was profiled before its genesis block hash was
    /// ratified. Unlike Bitcoin, no library in this workspace derives the
    /// Monero genesis, so the value is a ratified fact rather than a computed
    /// one — and an unratified network refuses instead of trusting whatever
    /// hash the manifest happens to carry.
    #[error("Monero network genesis is not ratified")]
    MoneroGenesisUnratified,
    /// An asset does not have a valid chain representation.
    #[error("invalid asset binding")]
    InvalidAssetBinding,
    /// The embedded safety-critical chain profile refused validation.
    #[error("invalid chain profile")]
    InvalidChainProfile,
    /// DOM network identity disagrees with pinned consensus constants or the
    /// authenticated chain/genesis pair.
    #[error("invalid DOM runtime identity")]
    InvalidDomRuntimeIdentity,
    /// The authority set is invalid or does not meet threshold.
    #[error("invalid registry authority set")]
    InvalidAuthoritySet,
    /// A signature is malformed, duplicated or cryptographically invalid.
    #[error("invalid registry signature")]
    InvalidSignature,
    /// Fewer valid independent signatures were supplied than required.
    #[error("registry signature threshold not met")]
    ThresholdNotMet,
    /// Checked integer arithmetic failed.
    #[error("registry arithmetic overflow")]
    Overflow,
    /// Durable registry storage is unavailable.
    #[error("registry storage unavailable")]
    StorageUnavailable,
    /// Explicit creation targeted an existing database path.
    #[error("registry database already exists")]
    DatabasePresent,
    /// Production open targeted a missing database path.
    #[error("registry database is missing")]
    DatabaseMissing,
    /// The retained path is not an owner-only regular database file.
    #[error("invalid registry storage authority")]
    InvalidStorageAuthority,
    /// Durable state is corrupt or was produced by a newer implementation.
    #[error("corrupt or unsupported registry state")]
    CorruptState,
    /// A contract release JSON record is malformed, contradictory or outside
    /// the frozen release schema.
    #[error("invalid EVM contract release record")]
    InvalidContractRelease,
    /// The embedded release digest does not authenticate the exact canonical
    /// JSON record supplied to the registry authority.
    #[error("EVM contract release digest mismatch")]
    ContractReleaseDigestMismatch,
}

/// Registry result alias.
pub type Result<T> = core::result::Result<T, RegistryError>;
