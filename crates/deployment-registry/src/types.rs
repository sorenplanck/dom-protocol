use std::collections::BTreeSet;

use adapter_btc::timelock::{minimum_safety_margin_seconds, ChainTimingBoundsV1};
use adapter_btc::types::BitcoinNetworkV1;
use adapter_evm::{Direction, EvmAdapterConfig};
use bitcoin::{blockdata::constants::genesis_block, hashes::Hash, Network};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chain_profile::{ChainKindV1, ChainProfileV1, MoneroNetworkV1};
use dom_consensus::derive_chain_id;
use dom_core::{
    configured_genesis_hash_for_network_magic, Hash256, NETWORK_MAGIC_MAINNET,
    NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET, PROTOCOL_VERSION,
};
use kaystra_core::types::{AssetId, ChainId, Digest32, FinalityPolicyV1};

use crate::codec::{decode_manifest, encode_manifest};
use crate::{RegistryError, Result, REGISTRY_MANIFEST_DOMAIN};

/// Maximum number of counterparty chains in one reviewed manifest.
pub const MAX_CHAINS: usize = 32;
/// Maximum number of `(chain, asset)` bindings in one manifest.
pub const MAX_ASSET_BINDINGS: usize = 256;
/// Maximum accepted canonical manifest size.
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;
/// Maximum custom Signet challenge script size.
pub const MAX_SIGNET_CHALLENGE_BYTES: usize = 520;

const MAX_EVM_PAGE_SIZE: u64 = 1_024;
const MAX_EVM_REORG_DEPTH: u32 = 512;
// The real DOM runtime retains at most 4,096 consecutive anchors and needs
// one common ancestor in addition to every removable block.
const MAX_DOM_REORG_DEPTH: u32 = 4_095;
const MAX_ASSET_DECIMALS: u8 = 38;

/// Closed DOM network label authenticated by the registry manifest.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum DomNetworkV1 {
    /// Public DOM mainnet.
    Mainnet = 1,
    /// Public DOM testnet.
    Testnet = 2,
    /// Isolated DOM regression-test network.
    Regtest = 3,
}

impl DomNetworkV1 {
    /// Exact lowercase label returned by the authenticated scanner.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }

    /// Consensus magic pinned by the selected network discriminant.
    pub const fn canonical_magic(self) -> u32 {
        match self {
            Self::Mainnet => NETWORK_MAGIC_MAINNET,
            Self::Testnet => NETWORK_MAGIC_TESTNET,
            Self::Regtest => NETWORK_MAGIC_REGTEST,
        }
    }
}

/// Exact DOM scanner/consensus identity authenticated by registry signatures.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DomRuntimeIdentityV1 {
    /// Closed network label (encoded as a canonical discriminant).
    pub network: DomNetworkV1,
    /// Exact consensus network magic.
    pub network_magic: u32,
    /// Exact wire protocol version exposed by the scanner.
    pub protocol_version: u32,
    /// Exact canonical rangeproof serialization version.
    pub range_proof_serialization_version: u8,
}

impl DomRuntimeIdentityV1 {
    /// Returns the identity implemented by this pinned DOM build for a network.
    pub const fn pinned(network: DomNetworkV1) -> Self {
        Self {
            network,
            network_magic: network.canonical_magic(),
            protocol_version: PROTOCOL_VERSION,
            range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        }
    }

    fn validate(self, chain_id: ChainId, genesis_hash: Digest32) -> Result<()> {
        let canonical_genesis = configured_genesis_hash_for_network_magic(self.network_magic)
            .map_err(|_| RegistryError::InvalidDomRuntimeIdentity)?;
        let supplied_genesis = Hash256::from_bytes(genesis_hash);
        if self.network_magic != self.network.canonical_magic()
            || self.protocol_version != PROTOCOL_VERSION
            || self.range_proof_serialization_version
                != dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION
            || supplied_genesis != canonical_genesis
            || derive_chain_id(self.network_magic, &supplied_genesis).as_bytes() != &chain_id.0
        {
            return Err(RegistryError::InvalidDomRuntimeIdentity);
        }
        Ok(())
    }
}

/// Public DOM deployment facts authenticated by the registry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DomDeploymentV1 {
    /// DOM registry chain identifier.
    pub chain_id: ChainId,
    /// Genesis block hash of the selected DOM network.
    pub genesis_hash: Digest32,
    /// Exact network/protocol/rangeproof identity expected from the real node.
    pub runtime_identity: DomRuntimeIdentityV1,
    /// Digest of the active consensus rules/build identity.
    pub consensus_rules_digest: Digest32,
    /// Version of the authenticated scriptless scanner API.
    pub scriptless_api_version: u32,
    /// DOM block and recovery timing bounds.
    pub timing: ChainTimingBoundsV1,
    /// DOM finality policy used by route engines.
    pub finality: FinalityPolicyV1,
    /// Native DOM asset identifier.
    pub native_asset: AssetId,
}

/// Public EVM deployment facts beyond the generic chain profile.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvmDeploymentV1 {
    /// Genesis hash used to detect an RPC pointed at another chain.
    pub genesis_hash: Digest32,
    /// First block that may contain native-lock events.
    pub native_start_block: u64,
    /// First block that may contain ERC-20-lock events, when present.
    pub erc20_start_block: Option<u64>,
    /// Digest of the frozen ABI consumed by the adapter.
    pub abi_digest: Digest32,
    /// Digest of compiler identity and settings.
    pub compiler_digest: Digest32,
    /// Digest of the reviewed source tree.
    pub source_digest: Digest32,
    /// Deployment transaction or reproducible deployment-record digest.
    pub deployment_digest: Digest32,
    /// Whether the endpoint must support Ethereum's `finalized` tag.
    pub finalized_tag_required: bool,
    /// Maximum log page size frozen for the runtime.
    pub page_size: u64,
    /// Gas limit hint for calls produced from this deployment.
    pub gas_limit_hint: u64,
    /// Absolute maximum EIP-1559 fee per gas accepted by policy.
    pub max_fee_per_gas: u128,
    /// Absolute maximum EIP-1559 priority fee accepted by policy.
    pub max_priority_fee_per_gas: u128,
}

/// Public Bitcoin network identity and fee-policy facts.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinDeploymentV1 {
    /// Genesis block hash of the selected Bitcoin network.
    pub genesis_hash: Digest32,
    /// Exact Signet challenge for custom Signet; empty otherwise.
    pub signet_challenge: Vec<u8>,
    /// Maximum route-authorized fee rate in sat/vbyte.
    pub max_fee_rate_sat_vbyte: u64,
    /// Minimum relay fee expected from the configured node, sat/kvB.
    pub min_relay_fee_sat_kvb: u64,
}

/// Monero deployment facts. Deliberately narrow: the XMR leg holds no
/// contract and no script, so the only deployment truths are which chain this
/// is and the fee ceiling the route authorized. Everything else about a sweep
/// is decided by the adapter profile and proved by the raw-transaction
/// verifier.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MoneroDeploymentV1 {
    /// Genesis block hash of the selected Monero network — the chain identity
    /// an observer must reproduce before any evidence from it is believed.
    pub genesis_hash: Digest32,
    /// Maximum route-authorized sweep fee, in piconero. Zero refuses: an
    /// unbounded fee is an unbounded loss on the leg the operator funds.
    pub max_fee_piconero: u64,
}

/// Solana deployment facts.
///
/// The program pinning (program id, programdata hash) lives in
/// `ChainKindV1::Solana`, next to the EVM contract pinning; what remains
/// here is the cluster identity and the fee ceiling the route authorized.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SolanaDeploymentV1 {
    /// Genesis blockhash of the selected cluster — the chain identity an
    /// observer must reproduce before any evidence from it is believed.
    pub genesis_hash: Digest32,
    /// Maximum route-authorized transaction fee, in lamports. Zero refuses:
    /// an unbounded fee is an unbounded loss on the leg the operator funds.
    pub max_fee_lamports: u64,
}

/// Kind-specific deployment facts paired with a generic chain profile.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ChainDeploymentV1 {
    /// An EVM ConditionLock deployment.
    Evm(EvmDeploymentV1),
    /// A Bitcoin network profile.
    Bitcoin(BitcoinDeploymentV1),
    /// A Monero network profile.
    Monero(MoneroDeploymentV1),
    /// A Solana cluster profile.
    Solana(SolanaDeploymentV1),
}

/// One counterparty profile and the deployment facts that realize it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegistryChainProfileV1 {
    /// Safety-critical generic profile consumed by route composition.
    pub profile: ChainProfileV1,
    /// Network/deployment evidence consumed by the concrete adapter.
    pub deployment: ChainDeploymentV1,
}

/// On-chain representation of one registered asset.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AssetRepresentationV1 {
    /// Native chain asset; no token address exists.
    Native,
    /// EVM ERC-20 representation pinned to runtime bytecode.
    EvmErc20 {
        /// Token contract address.
        token: [u8; 20],
        /// Expected token runtime bytecode hash.
        token_code_hash: Digest32,
    },
}

/// Exact mapping between a protocol asset id and one chain representation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AssetBindingV1 {
    /// Chain on which this representation lives.
    pub chain_id: ChainId,
    /// Protocol asset registry identifier.
    pub asset_id: AssetId,
    /// Base-10 decimals used only for amount presentation/conversion checks.
    pub decimals: u8,
    /// Native or token representation.
    pub representation: AssetRepresentationV1,
}

/// Canonical registry document authenticated by offline authorities.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RegistryManifestV1 {
    /// DOM interop network identity. Prevents cross-environment substitution.
    pub network_id: Digest32,
    /// Strictly monotonic registry epoch.
    pub epoch: u64,
    /// First UNIX second at which this manifest is valid.
    pub valid_from: u64,
    /// First UNIX second at which this manifest is no longer valid.
    pub expires_at: u64,
    /// Authenticated DOM network facts.
    pub dom: DomDeploymentV1,
    /// Bounded counterparty chain profiles.
    pub chains: Vec<RegistryChainProfileV1>,
    /// Complete bounded asset mapping for DOM and every counterparty profile.
    pub assets: Vec<AssetBindingV1>,
}

/// External validation pins supplied by the operator/runtime.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RegistryValidationPolicyV1 {
    /// Current trusted UNIX time.
    pub now_seconds: u64,
    /// Network identity this process was explicitly configured to run.
    pub expected_network_id: Digest32,
    /// Epoch stored outside the replaceable registry database/config bundle.
    pub minimum_epoch: u64,
}

/// Settlement-specific EVM facts that are not deployment registry material.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvmSessionBindingsV1 {
    /// Economic direction of this settlement.
    pub direction: Direction,
    /// Route-owned scriptless session identifier.
    pub session_id: Digest32,
    /// Frozen settlement terms digest.
    pub terms_hash: Digest32,
    /// Frozen ordered participant roster digest.
    pub participants_hash: Digest32,
    /// Only EVM address authorized to claim.
    pub beneficiary: [u8; 20],
    /// EVM account that funds the lock.
    pub funder: [u8; 20],
}

/// A manifest whose canonical digest and signatures were verified.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResolvedRegistryV1 {
    manifest: RegistryManifestV1,
    manifest_digest: Digest32,
}

/// One chain borrowed from a verified [`ResolvedRegistryV1`].
#[derive(Clone, Copy, Debug)]
pub struct ResolvedChainProfileV1<'a> {
    registry: &'a ResolvedRegistryV1,
    entry: &'a RegistryChainProfileV1,
}

/// Route-scoped public DOM facts retained from an authenticated registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedDomDeploymentV1 {
    registry_digest: Digest32,
    registry_epoch: u64,
    deployment: DomDeploymentV1,
    native_asset_binding: AssetBindingV1,
    native_asset_binding_digest: Digest32,
}

/// Complete public EVM capability for one authenticated asset/session.
/// Endpoint credentials and account keys are deliberately absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedEvmDeploymentV1 {
    registry_digest: Digest32,
    registry_epoch: u64,
    profile_digest: Digest32,
    asset_binding_digest: Digest32,
    deployment: EvmDeploymentV1,
    asset_binding: AssetBindingV1,
    adapter_config: EvmAdapterConfig,
}

/// Complete public Bitcoin capability for one authenticated chain/asset.
/// RPC endpoint, wallet name and cookie path remain local operator authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedBitcoinDeploymentV1 {
    registry_digest: Digest32,
    registry_epoch: u64,
    profile_digest: Digest32,
    asset_binding_digest: Digest32,
    profile: ChainProfileV1,
    deployment: BitcoinDeploymentV1,
    asset_binding: AssetBindingV1,
}

/// Complete public Monero capability for one authenticated chain.
/// Daemon endpoint and wallet material remain local operator authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedMoneroDeploymentV1 {
    registry_digest: Digest32,
    registry_epoch: u64,
    profile_digest: Digest32,
    asset_binding_digest: Digest32,
    profile: ChainProfileV1,
    deployment: MoneroDeploymentV1,
    asset_binding: AssetBindingV1,
}

/// Complete public Solana capability for one authenticated chain.
/// RPC endpoints and the fee-payer key remain local operator authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSolanaDeploymentV1 {
    registry_digest: Digest32,
    registry_epoch: u64,
    profile_digest: Digest32,
    asset_binding_digest: Digest32,
    profile: ChainProfileV1,
    deployment: SolanaDeploymentV1,
    asset_binding: AssetBindingV1,
}

impl RegistryManifestV1 {
    /// Validates all cross-field, uniqueness, deployment and asset rules.
    pub fn validate(&self) -> Result<()> {
        if self.network_id == [0u8; 32] || self.epoch == 0 {
            return Err(RegistryError::ZeroField);
        }
        if self.valid_from >= self.expires_at {
            return Err(RegistryError::InvalidTime);
        }
        validate_dom(&self.dom)?;
        if self.chains.is_empty() || self.chains.len() > MAX_CHAINS {
            return Err(RegistryError::BoundExceeded);
        }
        if self.assets.is_empty() || self.assets.len() > MAX_ASSET_BINDINGS {
            return Err(RegistryError::BoundExceeded);
        }

        let mut chains = BTreeSet::new();
        let mut previous_chain_id: Option<[u8; 32]> = None;
        let mut evm_identities = BTreeSet::new();
        let mut bitcoin_identities = BTreeSet::new();
        let mut monero_identities = BTreeSet::new();
        let mut solana_identities = BTreeSet::new();
        chains.insert(self.dom.chain_id.0);
        for entry in &self.chains {
            if entry.profile.chain_id.0 == [0u8; 32] || entry.profile.native_asset.0 == [0u8; 32] {
                return Err(RegistryError::ZeroField);
            }
            if previous_chain_id.is_some_and(|previous| previous >= entry.profile.chain_id.0) {
                return Err(RegistryError::NonCanonicalEncoding);
            }
            previous_chain_id = Some(entry.profile.chain_id.0);
            if entry
                .profile
                .allowed_assets
                .iter()
                .any(|asset| asset.0 == [0u8; 32])
            {
                return Err(RegistryError::ZeroField);
            }
            if !strictly_increasing(entry.profile.allowed_assets.iter().map(|asset| asset.0)) {
                return Err(RegistryError::NonCanonicalEncoding);
            }
            entry
                .profile
                .validate()
                .map_err(|_| RegistryError::InvalidChainProfile)?;
            if !chains.insert(entry.profile.chain_id.0) {
                return Err(RegistryError::DuplicateEntry);
            }
            validate_deployment(entry)?;
            match (&entry.profile.kind, &entry.deployment) {
                (ChainKindV1::Evm { evm_chain_id, .. }, ChainDeploymentV1::Evm(deployment)) => {
                    if !evm_identities.insert((*evm_chain_id, deployment.genesis_hash)) {
                        return Err(RegistryError::DuplicateEntry);
                    }
                }
                (ChainKindV1::Bitcoin { network }, ChainDeploymentV1::Bitcoin(deployment)) => {
                    if !bitcoin_identities.insert((
                        *network as u8,
                        deployment.genesis_hash,
                        deployment.signet_challenge.clone(),
                    )) {
                        return Err(RegistryError::DuplicateEntry);
                    }
                }
                (ChainKindV1::Monero { network }, ChainDeploymentV1::Monero(deployment)) => {
                    if !monero_identities.insert((*network as u8, deployment.genesis_hash)) {
                        return Err(RegistryError::DuplicateEntry);
                    }
                }
                (ChainKindV1::Solana { network, .. }, ChainDeploymentV1::Solana(deployment)) => {
                    if !solana_identities.insert((*network as u8, deployment.genesis_hash)) {
                        return Err(RegistryError::DuplicateEntry);
                    }
                }
                _ => return Err(RegistryError::DeploymentMismatch),
            }
        }

        let mut seen_assets = BTreeSet::new();
        let mut seen_tokens = BTreeSet::new();
        let mut previous_asset: Option<([u8; 32], [u8; 32])> = None;
        for asset in &self.assets {
            if asset.asset_id.0 == [0u8; 32] {
                return Err(RegistryError::ZeroField);
            }
            let key = (asset.chain_id.0, asset.asset_id.0);
            if !seen_assets.insert(key) {
                return Err(RegistryError::DuplicateEntry);
            }
            if previous_asset.is_some_and(|previous| previous >= key) {
                return Err(RegistryError::NonCanonicalEncoding);
            }
            previous_asset = Some(key);
            if let AssetRepresentationV1::EvmErc20 { token, .. } = asset.representation {
                if !seen_tokens.insert((asset.chain_id.0, token)) {
                    return Err(RegistryError::DuplicateEntry);
                }
            }
            self.validate_asset(asset)?;
        }

        require_asset(&seen_assets, self.dom.chain_id, self.dom.native_asset)?;
        for entry in &self.chains {
            require_asset(
                &seen_assets,
                entry.profile.chain_id,
                entry.profile.native_asset,
            )?;
            for asset in &entry.profile.allowed_assets {
                require_asset(&seen_assets, entry.profile.chain_id, *asset)?;
            }
        }
        Ok(())
    }

    fn validate_asset(&self, asset: &AssetBindingV1) -> Result<()> {
        if asset.decimals > MAX_ASSET_DECIMALS {
            return Err(RegistryError::InvalidAssetBinding);
        }
        if asset.chain_id == self.dom.chain_id {
            if asset.asset_id != self.dom.native_asset
                || asset.representation != AssetRepresentationV1::Native
            {
                return Err(RegistryError::InvalidAssetBinding);
            }
            return Ok(());
        }
        let chain = self
            .chains
            .iter()
            .find(|entry| entry.profile.chain_id == asset.chain_id)
            .ok_or(RegistryError::InvalidAssetBinding)?;
        let is_native = asset.asset_id == chain.profile.native_asset;
        let is_allowed = chain.profile.allowed_assets.contains(&asset.asset_id);
        if !is_native && !is_allowed {
            return Err(RegistryError::InvalidAssetBinding);
        }
        match (&chain.profile.kind, asset.representation, is_native) {
            (_, AssetRepresentationV1::Native, true) => Ok(()),
            (
                ChainKindV1::Evm {
                    erc20_lock_contract: Some(_),
                    ..
                },
                AssetRepresentationV1::EvmErc20 {
                    token,
                    token_code_hash,
                },
                false,
            ) if token != [0u8; 20] && token_code_hash != [0u8; 32] => Ok(()),
            _ => Err(RegistryError::InvalidAssetBinding),
        }
    }

    /// Encodes a validated manifest in its frozen canonical binary form.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_manifest(self)
    }

    /// Decodes and re-encodes a manifest, refusing trailing or alternate bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(RegistryError::BoundExceeded);
        }
        let value = decode_manifest(bytes)?;
        value.validate()?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(RegistryError::NonCanonicalEncoding);
        }
        Ok(value)
    }

    /// Returns the domain-separated BLAKE2b-256 manifest digest.
    pub fn manifest_digest(&self) -> Result<Digest32> {
        let bytes = self.canonical_bytes()?;
        let mut hash = Blake2bVar::new(32).map_err(|_| RegistryError::CorruptState)?;
        hash.update(REGISTRY_MANIFEST_DOMAIN);
        hash.update(&bytes);
        let mut out = [0u8; 32];
        hash.finalize_variable(&mut out)
            .map_err(|_| RegistryError::CorruptState)?;
        Ok(out)
    }

    /// Applies external network, time and rollback-anchor policy.
    pub fn validate_policy(&self, policy: RegistryValidationPolicyV1) -> Result<()> {
        self.validate()?;
        if self.network_id != policy.expected_network_id {
            return Err(RegistryError::WrongNetwork);
        }
        if self.epoch < policy.minimum_epoch {
            return Err(RegistryError::EpochBelowMinimum);
        }
        if policy.now_seconds < self.valid_from || policy.now_seconds >= self.expires_at {
            return Err(RegistryError::InvalidTime);
        }
        Ok(())
    }
}

impl ResolvedRegistryV1 {
    pub(crate) fn new(manifest: RegistryManifestV1, manifest_digest: Digest32) -> Self {
        Self {
            manifest,
            manifest_digest,
        }
    }

    /// Authenticated canonical manifest digest to freeze into route terms.
    pub const fn manifest_digest(&self) -> Digest32 {
        self.manifest_digest
    }

    /// Authenticated manifest epoch.
    pub const fn epoch(&self) -> u64 {
        self.manifest.epoch
    }

    /// Read-only authenticated manifest.
    pub const fn manifest(&self) -> &RegistryManifestV1 {
        &self.manifest
    }

    /// Resolves a chain only after the entire registry has authenticated.
    pub fn resolve_chain(&self, chain_id: ChainId) -> Option<ResolvedChainProfileV1<'_>> {
        self.manifest
            .chains
            .iter()
            .find(|entry| entry.profile.chain_id == chain_id)
            .map(|entry| ResolvedChainProfileV1 {
                registry: self,
                entry,
            })
    }

    /// Resolves an exact asset representation on a chain.
    pub fn resolve_asset(&self, chain_id: ChainId, asset_id: AssetId) -> Option<&AssetBindingV1> {
        self.manifest
            .assets
            .iter()
            .find(|asset| asset.chain_id == chain_id && asset.asset_id == asset_id)
    }

    /// Resolves DOM itself as a route-scoped capability retaining every
    /// authenticated deployment and native-asset fact.
    pub fn resolve_dom(&self) -> Result<ResolvedDomDeploymentV1> {
        let native_asset_binding = *self
            .resolve_asset(self.manifest.dom.chain_id, self.manifest.dom.native_asset)
            .ok_or(RegistryError::InvalidAssetBinding)?;
        let native_asset_binding_digest =
            self.asset_binding_digest(self.manifest.dom.chain_id, self.manifest.dom.native_asset)?;
        Ok(ResolvedDomDeploymentV1 {
            registry_digest: self.manifest_digest,
            registry_epoch: self.manifest.epoch,
            deployment: self.manifest.dom,
            native_asset_binding,
            native_asset_binding_digest,
        })
    }

    /// Digest of one exact asset binding, domain-separated from the registry
    /// digest and unambiguous across chains/assets.
    pub fn asset_binding_digest(&self, chain_id: ChainId, asset_id: AssetId) -> Result<Digest32> {
        self.resolve_asset(chain_id, asset_id)
            .ok_or(RegistryError::InvalidAssetBinding)?;
        digest_parts(
            b"DOM-INTEROP/DEPLOYMENT-REGISTRY/ASSET-BINDING/V1\0",
            &[&self.manifest_digest, &chain_id.0, &asset_id.0],
        )
    }
}

impl<'a> ResolvedChainProfileV1<'a> {
    /// Authenticated registry digest from which this value was resolved.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry.manifest_digest
    }

    /// Validated generic profile used by composition and terms.
    pub const fn profile(&self) -> &'a ChainProfileV1 {
        &self.entry.profile
    }

    /// Validated concrete deployment facts.
    pub const fn deployment(&self) -> &'a ChainDeploymentV1 {
        &self.entry.deployment
    }

    /// Constructs a session-bound EVM adapter config from authenticated facts.
    pub fn evm_adapter_config(
        &self,
        asset_id: AssetId,
        session: EvmSessionBindingsV1,
    ) -> Result<EvmAdapterConfig> {
        Ok(self
            .evm_deployment_capability(asset_id, session)?
            .adapter_config)
    }

    /// Constructs a complete EVM capability retaining every registry fact the
    /// observer, token preflight and signer fee policy must enforce.
    pub fn evm_deployment_capability(
        &self,
        asset_id: AssetId,
        session: EvmSessionBindingsV1,
    ) -> Result<ResolvedEvmDeploymentV1> {
        if session.session_id == [0u8; 32]
            || session.terms_hash == [0u8; 32]
            || session.participants_hash == [0u8; 32]
            || session.beneficiary == [0u8; 20]
            || session.funder == [0u8; 20]
        {
            return Err(RegistryError::ZeroField);
        }
        let deployment = match &self.entry.deployment {
            ChainDeploymentV1::Evm(value) => value,
            ChainDeploymentV1::Bitcoin(_)
            | ChainDeploymentV1::Monero(_)
            | ChainDeploymentV1::Solana(_) => return Err(RegistryError::DeploymentMismatch),
        };
        let (evm_chain_id, native_contract, native_hash, erc20) = match self.entry.profile.kind {
            ChainKindV1::Evm {
                evm_chain_id,
                native_lock_contract,
                native_code_hash,
                erc20_lock_contract,
            } => (
                evm_chain_id,
                native_lock_contract,
                native_code_hash,
                erc20_lock_contract,
            ),
            ChainKindV1::Bitcoin { .. }
            | ChainKindV1::Monero { .. }
            | ChainKindV1::Solana { .. } => return Err(RegistryError::DeploymentMismatch),
        };
        let asset = self
            .registry
            .resolve_asset(self.entry.profile.chain_id, asset_id)
            .ok_or(RegistryError::InvalidAssetBinding)?;
        let (contract, expected_code_hash, token, start_block) = match asset.representation {
            AssetRepresentationV1::Native if asset_id == self.entry.profile.native_asset => (
                native_contract,
                native_hash,
                [0u8; 20],
                deployment.native_start_block,
            ),
            AssetRepresentationV1::EvmErc20 { token, .. } => {
                let (contract, hash) = erc20.ok_or(RegistryError::InvalidAssetBinding)?;
                let start = deployment
                    .erc20_start_block
                    .ok_or(RegistryError::DeploymentMismatch)?;
                (contract, hash, token, start)
            }
            _ => return Err(RegistryError::InvalidAssetBinding),
        };
        let config = EvmAdapterConfig {
            chain_id: evm_chain_id,
            contract,
            expected_code_hash,
            dom_chain_id: self.registry.manifest.dom.chain_id.0,
            direction: session.direction,
            session_id: session.session_id,
            terms_hash: session.terms_hash,
            participants_hash: session.participants_hash,
            asset: token,
            beneficiary: session.beneficiary,
            funder: session.funder,
            start_block,
            page_size: deployment.page_size,
            max_reorg_depth: self.entry.profile.finality.max_reorg_depth,
            gas_limit_hint: deployment.gas_limit_hint,
        };
        config
            .validate()
            .map_err(|_| RegistryError::DeploymentMismatch)?;
        let profile_digest = self
            .entry
            .profile
            .profile_digest()
            .map_err(|_| RegistryError::InvalidChainProfile)?;
        let asset_binding_digest = self
            .registry
            .asset_binding_digest(self.entry.profile.chain_id, asset_id)?;
        Ok(ResolvedEvmDeploymentV1 {
            registry_digest: self.registry.manifest_digest,
            registry_epoch: self.registry.manifest.epoch,
            profile_digest,
            asset_binding_digest,
            deployment: *deployment,
            asset_binding: *asset,
            adapter_config: config,
        })
    }

    /// Constructs a complete public Bitcoin capability. Local RPC credentials
    /// can only be attached by the Bitcoin authority after verifying these
    /// network/genesis/challenge and fee-policy facts.
    pub fn bitcoin_deployment_capability(&self) -> Result<ResolvedBitcoinDeploymentV1> {
        let deployment = match &self.entry.deployment {
            ChainDeploymentV1::Bitcoin(value) => value.clone(),
            ChainDeploymentV1::Evm(_)
            | ChainDeploymentV1::Monero(_)
            | ChainDeploymentV1::Solana(_) => return Err(RegistryError::DeploymentMismatch),
        };
        let asset_binding = *self
            .registry
            .resolve_asset(self.entry.profile.chain_id, self.entry.profile.native_asset)
            .ok_or(RegistryError::InvalidAssetBinding)?;
        let profile_digest = self
            .entry
            .profile
            .profile_digest()
            .map_err(|_| RegistryError::InvalidChainProfile)?;
        let asset_binding_digest = self
            .registry
            .asset_binding_digest(self.entry.profile.chain_id, self.entry.profile.native_asset)?;
        Ok(ResolvedBitcoinDeploymentV1 {
            registry_digest: self.registry.manifest_digest,
            registry_epoch: self.registry.manifest.epoch,
            profile_digest,
            asset_binding_digest,
            profile: self.entry.profile.clone(),
            deployment,
            asset_binding,
        })
    }

    /// Constructs a complete public Monero capability. Daemon endpoints and
    /// wallet/sidecar material can only be attached by the Monero authority
    /// after verifying these network/genesis and fee-policy facts.
    pub fn monero_deployment_capability(&self) -> Result<ResolvedMoneroDeploymentV1> {
        let deployment = match &self.entry.deployment {
            ChainDeploymentV1::Monero(value) => value.clone(),
            ChainDeploymentV1::Evm(_)
            | ChainDeploymentV1::Bitcoin(_)
            | ChainDeploymentV1::Solana(_) => return Err(RegistryError::DeploymentMismatch),
        };
        let asset_binding = *self
            .registry
            .resolve_asset(self.entry.profile.chain_id, self.entry.profile.native_asset)
            .ok_or(RegistryError::InvalidAssetBinding)?;
        let profile_digest = self
            .entry
            .profile
            .profile_digest()
            .map_err(|_| RegistryError::InvalidChainProfile)?;
        let asset_binding_digest = self
            .registry
            .asset_binding_digest(self.entry.profile.chain_id, self.entry.profile.native_asset)?;
        Ok(ResolvedMoneroDeploymentV1 {
            registry_digest: self.registry.manifest_digest,
            registry_epoch: self.registry.manifest.epoch,
            profile_digest,
            asset_binding_digest,
            profile: self.entry.profile.clone(),
            deployment,
            asset_binding,
        })
    }

    /// Constructs a complete public Solana capability. RPC endpoints and the
    /// fee payer can only be attached by the Solana authority after verifying
    /// these cluster/program-pinning and fee-policy facts.
    pub fn solana_deployment_capability(&self) -> Result<ResolvedSolanaDeploymentV1> {
        let deployment = match &self.entry.deployment {
            ChainDeploymentV1::Solana(value) => value.clone(),
            ChainDeploymentV1::Evm(_)
            | ChainDeploymentV1::Bitcoin(_)
            | ChainDeploymentV1::Monero(_) => return Err(RegistryError::DeploymentMismatch),
        };
        // The safety-critical half of the pinning lives in the kind; a
        // capability is only issued for a profile that actually names it.
        match self.entry.profile.kind {
            ChainKindV1::Solana { .. } => {}
            _ => return Err(RegistryError::DeploymentMismatch),
        }
        let asset_binding = *self
            .registry
            .resolve_asset(self.entry.profile.chain_id, self.entry.profile.native_asset)
            .ok_or(RegistryError::InvalidAssetBinding)?;
        let profile_digest = self
            .entry
            .profile
            .profile_digest()
            .map_err(|_| RegistryError::InvalidChainProfile)?;
        let asset_binding_digest = self
            .registry
            .asset_binding_digest(self.entry.profile.chain_id, self.entry.profile.native_asset)?;
        Ok(ResolvedSolanaDeploymentV1 {
            registry_digest: self.registry.manifest_digest,
            registry_epoch: self.registry.manifest.epoch,
            profile_digest,
            asset_binding_digest,
            profile: self.entry.profile.clone(),
            deployment,
            asset_binding,
        })
    }
}

impl ResolvedDomDeploymentV1 {
    /// Authenticated registry manifest digest.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry_digest
    }

    /// Authenticated registry epoch.
    pub const fn registry_epoch(&self) -> u64 {
        self.registry_epoch
    }

    /// Complete DOM deployment facts.
    pub const fn deployment(&self) -> DomDeploymentV1 {
        self.deployment
    }

    /// Exact native DOM asset binding.
    pub const fn native_asset_binding(&self) -> AssetBindingV1 {
        self.native_asset_binding
    }

    /// Domain-separated digest of the native DOM asset binding.
    pub const fn native_asset_binding_digest(&self) -> Digest32 {
        self.native_asset_binding_digest
    }
}

impl ResolvedEvmDeploymentV1 {
    /// Authenticated registry manifest digest.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry_digest
    }

    /// Authenticated registry epoch.
    pub const fn registry_epoch(&self) -> u64 {
        self.registry_epoch
    }

    /// Digest of the exact generic chain profile.
    pub const fn profile_digest(&self) -> Digest32 {
        self.profile_digest
    }

    /// Digest of the exact selected asset binding.
    pub const fn asset_binding_digest(&self) -> Digest32 {
        self.asset_binding_digest
    }

    /// All EVM deployment, release and fee-policy facts.
    pub const fn deployment(&self) -> EvmDeploymentV1 {
        self.deployment
    }

    /// Exact selected native/ERC-20 binding.
    pub const fn asset_binding(&self) -> AssetBindingV1 {
        self.asset_binding
    }

    /// Session-bound adapter configuration.
    pub const fn adapter_config(&self) -> EvmAdapterConfig {
        self.adapter_config
    }
}

impl ResolvedBitcoinDeploymentV1 {
    /// Authenticated registry manifest digest.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry_digest
    }

    /// Authenticated registry epoch.
    pub const fn registry_epoch(&self) -> u64 {
        self.registry_epoch
    }

    /// Digest of the exact generic chain profile.
    pub const fn profile_digest(&self) -> Digest32 {
        self.profile_digest
    }

    /// Digest of the exact native Bitcoin asset binding.
    pub const fn asset_binding_digest(&self) -> Digest32 {
        self.asset_binding_digest
    }

    /// Full authenticated Bitcoin chain profile.
    pub const fn profile(&self) -> &ChainProfileV1 {
        &self.profile
    }

    /// Bitcoin genesis, Signet challenge and fee-policy facts.
    pub const fn deployment(&self) -> &BitcoinDeploymentV1 {
        &self.deployment
    }

    /// Exact native Bitcoin asset binding.
    pub const fn asset_binding(&self) -> AssetBindingV1 {
        self.asset_binding
    }
}

impl ResolvedMoneroDeploymentV1 {
    /// Authenticated registry manifest digest.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry_digest
    }

    /// Authenticated registry epoch.
    pub const fn registry_epoch(&self) -> u64 {
        self.registry_epoch
    }

    /// Digest of the exact generic chain profile.
    pub const fn profile_digest(&self) -> Digest32 {
        self.profile_digest
    }

    /// Digest of the exact native Monero asset binding.
    pub const fn asset_binding_digest(&self) -> Digest32 {
        self.asset_binding_digest
    }

    /// Full authenticated Monero chain profile.
    pub const fn profile(&self) -> &ChainProfileV1 {
        &self.profile
    }

    /// Monero genesis and fee-policy facts.
    pub const fn deployment(&self) -> &MoneroDeploymentV1 {
        &self.deployment
    }

    /// Exact native Monero asset binding.
    pub const fn asset_binding(&self) -> AssetBindingV1 {
        self.asset_binding
    }
}

impl ResolvedSolanaDeploymentV1 {
    /// Authenticated registry manifest digest.
    pub const fn registry_digest(&self) -> Digest32 {
        self.registry_digest
    }

    /// Authenticated registry epoch.
    pub const fn registry_epoch(&self) -> u64 {
        self.registry_epoch
    }

    /// Digest of the exact generic chain profile.
    pub const fn profile_digest(&self) -> Digest32 {
        self.profile_digest
    }

    /// Digest of the exact native SOL asset binding.
    pub const fn asset_binding_digest(&self) -> Digest32 {
        self.asset_binding_digest
    }

    /// Full authenticated Solana chain profile.
    pub const fn profile(&self) -> &ChainProfileV1 {
        &self.profile
    }

    /// Solana cluster genesis and fee-policy facts.
    pub const fn deployment(&self) -> &SolanaDeploymentV1 {
        &self.deployment
    }

    /// Exact native SOL asset binding.
    pub const fn asset_binding(&self) -> AssetBindingV1 {
        self.asset_binding
    }
}

fn validate_dom(dom: &DomDeploymentV1) -> Result<()> {
    if dom.chain_id.0 == [0u8; 32]
        || dom.genesis_hash == [0u8; 32]
        || dom.consensus_rules_digest == [0u8; 32]
        || dom.scriptless_api_version == 0
        || dom.native_asset.0 == [0u8; 32]
    {
        return Err(RegistryError::ZeroField);
    }
    if dom.finality.max_reorg_depth > MAX_DOM_REORG_DEPTH {
        return Err(RegistryError::InvalidChainProfile);
    }
    dom.runtime_identity
        .validate(dom.chain_id, dom.genesis_hash)?;
    validate_timing_finality(dom.timing, dom.finality)
}

fn validate_timing_finality(timing: ChainTimingBoundsV1, finality: FinalityPolicyV1) -> Result<()> {
    minimum_safety_margin_seconds(&timing, &timing)
        .map_err(|_| RegistryError::InvalidChainProfile)?;
    if timing.max_reorg_seconds == 0
        || timing.observation_seconds == 0
        || timing.broadcast_seconds == 0
        || finality.min_confirmations == 0
        || finality.max_reorg_depth < finality.min_confirmations
    {
        return Err(RegistryError::InvalidChainProfile);
    }
    let covered = u64::from(finality.max_reorg_depth)
        .checked_mul(u64::from(timing.max_block_seconds))
        .ok_or(RegistryError::Overflow)?;
    if u64::from(timing.max_reorg_seconds) < covered {
        return Err(RegistryError::InvalidChainProfile);
    }
    Ok(())
}

fn validate_deployment(entry: &RegistryChainProfileV1) -> Result<()> {
    match (&entry.profile.kind, &entry.deployment) {
        (
            ChainKindV1::Evm {
                native_lock_contract,
                erc20_lock_contract,
                ..
            },
            ChainDeploymentV1::Evm(deployment),
        ) => {
            let invalid_erc20_address = erc20_lock_contract
                .map(|(contract, _)| contract == [0u8; 20])
                .unwrap_or(false);
            if *native_lock_contract == [0u8; 20]
                || invalid_erc20_address
                || entry.profile.finality.max_reorg_depth > MAX_EVM_REORG_DEPTH
                || deployment.genesis_hash == [0u8; 32]
                || deployment.abi_digest == [0u8; 32]
                || deployment.compiler_digest == [0u8; 32]
                || deployment.source_digest == [0u8; 32]
                || deployment.deployment_digest == [0u8; 32]
                || deployment.page_size == 0
                || deployment.page_size > MAX_EVM_PAGE_SIZE
                || deployment.gas_limit_hint == 0
                || deployment.max_fee_per_gas == 0
                || deployment.max_priority_fee_per_gas == 0
                || deployment.max_priority_fee_per_gas > deployment.max_fee_per_gas
                || !deployment.finalized_tag_required
                || erc20_lock_contract.is_some() != deployment.erc20_start_block.is_some()
            {
                return Err(RegistryError::DeploymentMismatch);
            }
        }
        (ChainKindV1::Monero { network }, ChainDeploymentV1::Monero(deployment)) => {
            // The genesis is compared against the ratified value, never merely
            // accepted from the manifest: a manifest that could choose its own
            // chain identity could point the leg at a chain nobody agreed to.
            let ratified =
                ratified_monero_genesis(*network).ok_or(RegistryError::MoneroGenesisUnratified)?;
            if deployment.genesis_hash != ratified
                || deployment.max_fee_piconero == 0
                // The XMR leg has no token representation to allow: Monero's
                // only asset is Monero.
                || !entry.profile.allowed_assets.is_empty()
            {
                return Err(RegistryError::DeploymentMismatch);
            }
        }
        (ChainKindV1::Solana { .. }, ChainDeploymentV1::Solana(deployment)) => {
            // Solana cluster genesis hashes are live facts, not source-code
            // derivations (devnet and testnet reset; a local validator mints
            // its own), so the registry pins whatever nonzero identity the
            // manifest names and deduplicates on it, exactly as EVM does.
            // The safety-critical pinning for this kind is the immutable
            // program, checked in ChainProfileV1::validate.
            if deployment.genesis_hash == [0u8; 32]
                || deployment.max_fee_lamports == 0
                // Native SOL only, for now: admitting an SPL mint needs its
                // own AssetRepresentationV1 variant and its own ratification,
                // and until that happens a profile must not be able to name
                // one here.
                || !entry.profile.allowed_assets.is_empty()
            {
                return Err(RegistryError::DeploymentMismatch);
            }
        }
        (ChainKindV1::Bitcoin { network }, ChainDeploymentV1::Bitcoin(deployment)) => {
            if deployment.genesis_hash == [0u8; 32]
                || deployment.genesis_hash != canonical_bitcoin_genesis(*network)
                || deployment.max_fee_rate_sat_vbyte == 0
                || deployment.min_relay_fee_sat_kvb == 0
                || deployment.signet_challenge.len() > MAX_SIGNET_CHALLENGE_BYTES
                || !entry.profile.allowed_assets.is_empty()
            {
                return Err(RegistryError::DeploymentMismatch);
            }
            match network {
                BitcoinNetworkV1::CustomSignet if deployment.signet_challenge.is_empty() => {
                    return Err(RegistryError::DeploymentMismatch)
                }
                BitcoinNetworkV1::Regtest | BitcoinNetworkV1::PublicSignet
                    if !deployment.signet_challenge.is_empty() =>
                {
                    return Err(RegistryError::DeploymentMismatch)
                }
                _ => {}
            }
        }
        _ => return Err(RegistryError::DeploymentMismatch),
    }
    Ok(())
}

/// The genesis block hash of each ratified Monero network.
///
/// These are not transcribed constants. Each one is the block hash *derived*
/// from that network's `GENESIS_TX` and `GENESIS_NONCE` — the same two facts
/// the Monero daemon builds its own genesis block from — and
/// `the_ratified_genesis_is_the_hash_derived_from_the_genesis_transaction`
/// rebuilds the block and recomputes the hash, so a wrong byte here fails the
/// test rather than silently repointing chain identity. That test is the
/// analogue of Bitcoin's `genesis_block(network).block_hash()`: `monero-oxide`
/// exposes no genesis block, so the derivation is performed here instead of
/// being borrowed from the library.
///
/// Both values are independently corroborated by monero-project's own
/// height-0 checkpoints in `src/checkpoints/checkpoints.cpp`, which is a
/// different file and a different code path from the `src/cryptonote_config.h`
/// constants the derivation consumes.
///
/// Monero mainnet is absent because [`MoneroNetworkV1`] has no mainnet
/// variant, not because its genesis is unknown.
const RATIFIED_MONERO_GENESIS: &[(MoneroNetworkV1, Digest32)] = &[
    (
        MoneroNetworkV1::Stagenet,
        hex_digest(b"76ee3cc98646292206cd3e86f74d88b4dcc1d937088645e9b0cbca84b7ce74eb"),
    ),
    (
        MoneroNetworkV1::Testnet,
        hex_digest(b"48ca7cd3c8de5b6a4d53d2861fbdaedca141553559f9be9520068053cda8430b"),
    ),
];

/// Decode 64 lower-case hex characters at compile time. Writing the digests as
/// hex keeps them comparable by eye against the upstream sources they were
/// checked against; a malformed literal fails the build, not a run.
const fn hex_digest(hex: &[u8; 64]) -> Digest32 {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("digest literal must be lower-case hex"),
        }
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(hex[2 * i]) << 4) | nibble(hex[2 * i + 1]);
        i += 1;
    }
    out
}

fn ratified_monero_genesis(network: MoneroNetworkV1) -> Option<Digest32> {
    RATIFIED_MONERO_GENESIS
        .iter()
        .find(|(candidate, _)| *candidate == network)
        .map(|(_, genesis)| *genesis)
}

fn canonical_bitcoin_genesis(network: BitcoinNetworkV1) -> Digest32 {
    let network = match network {
        BitcoinNetworkV1::Regtest => Network::Regtest,
        BitcoinNetworkV1::CustomSignet | BitcoinNetworkV1::PublicSignet => Network::Signet,
    };
    genesis_block(network)
        .block_hash()
        .to_raw_hash()
        .to_byte_array()
}

fn require_asset(
    assets: &BTreeSet<([u8; 32], [u8; 32])>,
    chain_id: ChainId,
    asset_id: AssetId,
) -> Result<()> {
    if assets.contains(&(chain_id.0, asset_id.0)) {
        Ok(())
    } else {
        Err(RegistryError::InvalidAssetBinding)
    }
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> Result<Digest32> {
    let mut hash = Blake2bVar::new(32).map_err(|_| RegistryError::CorruptState)?;
    hash.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).map_err(|_| RegistryError::Overflow)?;
        hash.update(&length.to_be_bytes());
        hash.update(part);
    }
    let mut out = [0u8; 32];
    hash.finalize_variable(&mut out)
        .map_err(|_| RegistryError::CorruptState)?;
    if out == [0u8; 32] {
        return Err(RegistryError::CorruptState);
    }
    Ok(out)
}

fn strictly_increasing<T, I>(values: I) -> bool
where
    T: Ord,
    I: IntoIterator<Item = T>,
{
    let mut previous = None;
    for value in values {
        if previous.as_ref().is_some_and(|prior| prior >= &value) {
            return false;
        }
        previous = Some(value);
    }
    true
}

#[cfg(test)]
mod monero_genesis_tests {
    use super::{ratified_monero_genesis, MoneroNetworkV1};
    use monero_oxide::{
        block::{Block, BlockHeader},
        transaction::{NotPruned, Transaction},
    };

    /// `GENESIS_TX` and `GENESIS_NONCE` from monero-project's
    /// `src/cryptonote_config.h`. Testnet reuses mainnet's genesis transaction
    /// and differs only in the nonce; stagenet has its own.
    const TESTNET_GENESIS_TX: &str = "013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1";
    const STAGENET_GENESIS_TX: &str = "013c01ff0001ffffffffffff0302df5d56da0c7d643ddd1ce61901c7bdc5fb1738bfe39fbe69c28a3a7032729c0f2101168d0c4ca86fb55a4cf6a36d31431be1c53a3bd7411bb24e8832410289fa6f3b";

    /// Rebuild a network's genesis block the way the Monero daemon does:
    /// the network's genesis transaction as the miner transaction, in a header
    /// with major version 1, minor version 0, timestamp 0, a zero previous
    /// hash and the network's genesis nonce.
    fn derive_genesis(genesis_tx_hex: &str, nonce: u32) -> [u8; 32] {
        let bytes = decode_hex(genesis_tx_hex);
        let mut cursor = bytes.as_slice();
        let miner: Transaction<NotPruned> =
            Transaction::read(&mut cursor).expect("genesis transaction parses");
        assert!(cursor.is_empty(), "genesis transaction has trailing bytes");
        let header = BlockHeader {
            hardfork_version: 1,
            hardfork_signal: 0,
            timestamp: 0,
            previous: [0u8; 32],
            nonce,
        };
        let block = Block::new(header, miner, Vec::new()).expect("genesis block is well formed");
        assert_eq!(block.number(), 0, "the genesis block must be block zero");
        block.hash()
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert!(value.len().is_multiple_of(2), "hex must be byte aligned");
        (0..value.len() / 2)
            .map(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).expect("hex digit"))
            .collect()
    }

    #[test]
    fn the_ratified_genesis_is_the_hash_derived_from_the_genesis_transaction() {
        // This is the analogue of Bitcoin's `genesis_block(network).block_hash()`.
        // The constants in RATIFIED_MONERO_GENESIS are not trusted: they are
        // required to equal the hash recomputed here from the upstream genesis
        // transaction and nonce.
        assert_eq!(
            ratified_monero_genesis(MoneroNetworkV1::Stagenet),
            Some(derive_genesis(STAGENET_GENESIS_TX, 10002))
        );
        assert_eq!(
            ratified_monero_genesis(MoneroNetworkV1::Testnet),
            Some(derive_genesis(TESTNET_GENESIS_TX, 10001))
        );
    }

    #[test]
    fn every_profileable_monero_network_has_a_ratified_genesis() {
        // Exhaustive over MoneroNetworkV1 on purpose: adding a network without
        // ratifying its genesis must fail here rather than pass silently and
        // refuse only at run time.
        for network in [MoneroNetworkV1::Stagenet, MoneroNetworkV1::Testnet] {
            assert!(
                ratified_monero_genesis(network).is_some(),
                "{network:?} has no ratified genesis"
            );
            match network {
                // If a variant is added, this match stops compiling until the
                // loop above is extended to cover it.
                MoneroNetworkV1::Stagenet | MoneroNetworkV1::Testnet => {}
            }
        }
    }

    #[test]
    fn the_two_networks_do_not_share_a_genesis() {
        // A shared genesis would let a profile for one network accept evidence
        // observed on the other.
        assert_ne!(
            ratified_monero_genesis(MoneroNetworkV1::Stagenet),
            ratified_monero_genesis(MoneroNetworkV1::Testnet)
        );
    }
}
