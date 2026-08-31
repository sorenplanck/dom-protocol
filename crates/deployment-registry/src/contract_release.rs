//! Strict bridge from the reviewed Solidity release record to registry types.
//!
//! The release tool proves source/artifact/deployment facts.  This module does
//! not trust its JSON projection blindly: it rejects duplicate keys and
//! ambiguous numbers, recomputes the exact domain-separated manifest digest,
//! cross-checks redundant facts, and requires runtime policy to be supplied by
//! the registry authority rather than by the deployer.

use std::collections::{BTreeMap, BTreeSet};

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use chain_profile::ChainKindV1;
use serde::{
    de::{Error as DeError, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};

use crate::{EvmDeploymentV1, RegistryError, Result};

/// Maximum accepted Solidity release JSON size.
pub const MAX_EVM_CONTRACT_RELEASE_BYTES: usize = 4 * 1024 * 1024;

const RELEASE_SCHEMA: &str = "dom.evm-contract-release.v1";
const RELEASE_MANIFEST_DOMAIN: &[u8] = b"DOM:EVM-release-manifest:v1";
const ABI_DOMAIN: &str = "DOM:EVM-release-abi:v1";
const COMPILER_DOMAIN: &str = "DOM:EVM-release-compiler:v1";
const SOURCE_DOMAIN: &str = "DOM:EVM-release-source-bundle:v1";
const MAX_EVM_PAGE_SIZE: u64 = 1_024;

/// Operator-reviewed runtime policy deliberately absent from a deployment
/// release record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmRuntimePolicyV1 {
    page_size: u64,
    gas_limit_hint: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

impl EvmRuntimePolicyV1 {
    /// Validates observer paging, gas and EIP-1559 fee caps.
    pub fn new(
        page_size: u64,
        gas_limit_hint: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> Result<Self> {
        if page_size == 0
            || page_size > MAX_EVM_PAGE_SIZE
            || gas_limit_hint == 0
            || max_fee_per_gas == 0
            || max_priority_fee_per_gas == 0
            || max_priority_fee_per_gas > max_fee_per_gas
        {
            return Err(RegistryError::DeploymentMismatch);
        }
        Ok(Self {
            page_size,
            gas_limit_hint,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        })
    }

    /// Maximum log page size.
    pub const fn page_size(&self) -> u64 {
        self.page_size
    }

    /// Transaction gas limit hint.
    pub const fn gas_limit_hint(&self) -> u64 {
        self.gas_limit_hint
    }

    /// Absolute maximum fee per gas.
    pub const fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    /// Absolute maximum priority fee per gas.
    pub const fn max_priority_fee_per_gas(&self) -> u128 {
        self.max_priority_fee_per_gas
    }
}

/// An integrity-checked, cross-checked projection of one reviewed native and
/// ERC-20 ConditionLock release. Authenticity is provided only when registry
/// authorities sign the resulting canonical registry manifest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmContractReleaseV1 {
    manifest_digest: [u8; 32],
    evm_chain_id: u64,
    genesis_hash: [u8; 32],
    native_lock_contract: [u8; 20],
    native_code_hash: [u8; 32],
    erc20_lock_contract: [u8; 20],
    erc20_code_hash: [u8; 32],
    native_start_block: u64,
    erc20_start_block: u64,
    abi_digest: [u8; 32],
    compiler_digest: [u8; 32],
    source_digest: [u8; 32],
    deployment_digest: [u8; 32],
}

impl EvmContractReleaseV1 {
    /// Parses and verifies the bounded public JSON record emitted by
    /// `contracts/scripts/release_manifest.py`.
    pub fn parse_json(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_EVM_CONTRACT_RELEASE_BYTES {
            return Err(RegistryError::BoundExceeded);
        }
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        let mut root = StrictValue::deserialize(&mut deserializer)
            .map_err(|_| RegistryError::InvalidContractRelease)?;
        deserializer
            .end()
            .map_err(|_| RegistryError::InvalidContractRelease)?;
        let root_object = root
            .as_object_mut()
            .ok_or(RegistryError::InvalidContractRelease)?;
        require_exact_keys(
            root_object,
            &[
                "abi",
                "chain",
                "compiler",
                "contracts",
                "dependencies",
                "deployment_digest",
                "hash_algorithms",
                "manifest_digest",
                "registry_projection",
                "schema",
                "sources",
            ],
        )?;
        if text(required(root_object, "schema")?)? != RELEASE_SCHEMA {
            return Err(RegistryError::InvalidContractRelease);
        }
        let claimed_manifest_digest =
            fixed_hex::<32>(required(root_object, "manifest_digest")?, true)?;
        root_object.remove("manifest_digest");
        let canonical = canonical_json(&root)?;
        let actual_manifest_digest = domain_digest(RELEASE_MANIFEST_DOMAIN, &canonical)?;
        if claimed_manifest_digest != actual_manifest_digest {
            return Err(RegistryError::ContractReleaseDigestMismatch);
        }

        let root_object = object(&root)?;
        let projection = object(required(root_object, "registry_projection")?)?;
        require_exact_keys(
            projection,
            &[
                "chain_kind_v1",
                "evm_deployment_v1_release_fields",
                "runtime_policy_fields_not_supplied",
            ],
        )?;
        validate_missing_policy_fields(required(
            projection,
            "runtime_policy_fields_not_supplied",
        )?)?;

        let kind = object(required(projection, "chain_kind_v1")?)?;
        require_exact_keys(
            kind,
            &[
                "erc20_lock_contract",
                "evm_chain_id",
                "native_code_hash",
                "native_lock_contract",
            ],
        )?;
        let erc20_kind = object(required(kind, "erc20_lock_contract")?)?;
        require_exact_keys(erc20_kind, &["code_hash", "contract"])?;
        let evm_chain_id = unsigned(required(kind, "evm_chain_id")?)?;
        if evm_chain_id == 0 {
            return Err(RegistryError::InvalidContractRelease);
        }
        let native_lock_contract = fixed_hex::<20>(required(kind, "native_lock_contract")?, true)?;
        let native_code_hash = fixed_hex::<32>(required(kind, "native_code_hash")?, true)?;
        let erc20_lock_contract = fixed_hex::<20>(required(erc20_kind, "contract")?, true)?;
        let erc20_code_hash = fixed_hex::<32>(required(erc20_kind, "code_hash")?, true)?;

        let deployment = object(required(projection, "evm_deployment_v1_release_fields")?)?;
        require_exact_keys(
            deployment,
            &[
                "abi_digest",
                "compiler_digest",
                "deployment_digest",
                "erc20_start_block",
                "finalized_tag_required",
                "genesis_hash",
                "native_start_block",
                "source_digest",
            ],
        )?;
        if !boolean(required(deployment, "finalized_tag_required")?)? {
            return Err(RegistryError::InvalidContractRelease);
        }
        let native_start_block = unsigned(required(deployment, "native_start_block")?)?;
        let erc20_start_block = unsigned(required(deployment, "erc20_start_block")?)?;
        let genesis_hash = fixed_hex::<32>(required(deployment, "genesis_hash")?, true)?;
        let abi_digest = fixed_hex::<32>(required(deployment, "abi_digest")?, true)?;
        let compiler_digest = fixed_hex::<32>(required(deployment, "compiler_digest")?, true)?;
        let source_digest = fixed_hex::<32>(required(deployment, "source_digest")?, true)?;
        let deployment_digest = fixed_hex::<32>(required(deployment, "deployment_digest")?, true)?;

        validate_top_level_digests(
            root_object,
            abi_digest,
            compiler_digest,
            source_digest,
            deployment_digest,
        )?;
        validate_chain(
            required(root_object, "chain")?,
            evm_chain_id,
            genesis_hash,
            native_start_block,
            erc20_start_block,
        )?;
        validate_contracts(
            required(root_object, "contracts")?,
            native_lock_contract,
            native_code_hash,
            native_start_block,
            erc20_lock_contract,
            erc20_code_hash,
            erc20_start_block,
        )?;
        let compiler = object(required(root_object, "compiler")?)?;
        if required(root_object, "dependencies")? != required(compiler, "dependencies")? {
            return Err(RegistryError::InvalidContractRelease);
        }

        Ok(Self {
            manifest_digest: actual_manifest_digest,
            evm_chain_id,
            genesis_hash,
            native_lock_contract,
            native_code_hash,
            erc20_lock_contract,
            erc20_code_hash,
            native_start_block,
            erc20_start_block,
            abi_digest,
            compiler_digest,
            source_digest,
            deployment_digest,
        })
    }

    /// Digest of the exact canonical release JSON excluding its digest field.
    pub const fn manifest_digest(&self) -> [u8; 32] {
        self.manifest_digest
    }

    /// EIP-155 chain identifier proved by the release record.
    pub const fn evm_chain_id(&self) -> u64 {
        self.evm_chain_id
    }

    /// Constructs the exact chain-kind facts to place in the signed registry.
    pub const fn chain_kind(&self) -> ChainKindV1 {
        ChainKindV1::Evm {
            evm_chain_id: self.evm_chain_id,
            native_lock_contract: self.native_lock_contract,
            native_code_hash: self.native_code_hash,
            erc20_lock_contract: Some((self.erc20_lock_contract, self.erc20_code_hash)),
        }
    }

    /// Combines proved release facts with separately reviewed runtime policy.
    pub const fn deployment(&self, policy: EvmRuntimePolicyV1) -> EvmDeploymentV1 {
        EvmDeploymentV1 {
            genesis_hash: self.genesis_hash,
            native_start_block: self.native_start_block,
            erc20_start_block: Some(self.erc20_start_block),
            abi_digest: self.abi_digest,
            compiler_digest: self.compiler_digest,
            source_digest: self.source_digest,
            deployment_digest: self.deployment_digest,
            finalized_tag_required: true,
            page_size: policy.page_size,
            gas_limit_hint: policy.gas_limit_hint,
            max_fee_per_gas: policy.max_fee_per_gas,
            max_priority_fee_per_gas: policy.max_priority_fee_per_gas,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StrictValue {
    Null,
    Bool(bool),
    Unsigned(u64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl StrictValue {
    fn as_object_mut(&mut self) -> Option<&mut BTreeMap<String, Self>> {
        match self {
            Self::Object(value) => Some(value),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("a bounded release JSON value")
            }

            fn visit_unit<E: DeError>(self) -> core::result::Result<Self::Value, E> {
                Ok(StrictValue::Null)
            }

            fn visit_none<E: DeError>(self) -> core::result::Result<Self::Value, E> {
                Ok(StrictValue::Null)
            }

            fn visit_bool<E: DeError>(self, value: bool) -> core::result::Result<Self::Value, E> {
                Ok(StrictValue::Bool(value))
            }

            fn visit_u64<E: DeError>(self, value: u64) -> core::result::Result<Self::Value, E> {
                Ok(StrictValue::Unsigned(value))
            }

            fn visit_i64<E: DeError>(self, value: i64) -> core::result::Result<Self::Value, E> {
                u64::try_from(value)
                    .map(StrictValue::Unsigned)
                    .map_err(|_| E::custom("negative release number"))
            }

            fn visit_f64<E: DeError>(self, _value: f64) -> core::result::Result<Self::Value, E> {
                Err(E::custom("floating-point release number"))
            }

            fn visit_str<E: DeError>(self, value: &str) -> core::result::Result<Self::Value, E> {
                if !value.is_ascii() {
                    return Err(E::custom("non-ASCII release string"));
                }
                Ok(StrictValue::String(value.to_owned()))
            }

            fn visit_string<E: DeError>(
                self,
                value: String,
            ) -> core::result::Result<Self::Value, E> {
                self.visit_str(&value)
            }

            fn visit_seq<A>(self, mut sequence: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue::Array(values))
            }

            fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !key.is_ascii() || values.contains_key(&key) {
                        return Err(A::Error::custom("invalid or duplicate release key"));
                    }
                    let value = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(StrictValue::Object(values))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn canonical_json(value: &StrictValue) -> Result<Vec<u8>> {
    fn append(value: &StrictValue, out: &mut Vec<u8>) -> Result<()> {
        match value {
            StrictValue::Null => out.extend_from_slice(b"null"),
            StrictValue::Bool(false) => out.extend_from_slice(b"false"),
            StrictValue::Bool(true) => out.extend_from_slice(b"true"),
            StrictValue::Unsigned(number) => out.extend_from_slice(number.to_string().as_bytes()),
            StrictValue::String(value) => {
                let encoded = serde_json::to_string(value)
                    .map_err(|_| RegistryError::InvalidContractRelease)?;
                out.extend_from_slice(encoded.as_bytes());
            }
            StrictValue::Array(values) => {
                out.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    append(value, out)?;
                }
                out.push(b']');
            }
            StrictValue::Object(values) => {
                out.push(b'{');
                for (index, (key, value)) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    let encoded = serde_json::to_string(key)
                        .map_err(|_| RegistryError::InvalidContractRelease)?;
                    out.extend_from_slice(encoded.as_bytes());
                    out.push(b':');
                    append(value, out)?;
                }
                out.push(b'}');
            }
        }
        Ok(())
    }

    let mut output = Vec::new();
    append(value, &mut output)?;
    Ok(output)
}

fn domain_digest(domain: &[u8], payload: &[u8]) -> Result<[u8; 32]> {
    let mut hash = Blake2bVar::new(32).map_err(|_| RegistryError::InvalidContractRelease)?;
    hash.update(domain);
    hash.update(b"\0");
    hash.update(payload);
    let mut output = [0u8; 32];
    hash.finalize_variable(&mut output)
        .map_err(|_| RegistryError::InvalidContractRelease)?;
    if output == [0u8; 32] {
        return Err(RegistryError::InvalidContractRelease);
    }
    Ok(output)
}

fn object(value: &StrictValue) -> Result<&BTreeMap<String, StrictValue>> {
    match value {
        StrictValue::Object(value) => Ok(value),
        _ => Err(RegistryError::InvalidContractRelease),
    }
}

fn array(value: &StrictValue) -> Result<&[StrictValue]> {
    match value {
        StrictValue::Array(value) => Ok(value),
        _ => Err(RegistryError::InvalidContractRelease),
    }
}

fn text(value: &StrictValue) -> Result<&str> {
    match value {
        StrictValue::String(value) => Ok(value),
        _ => Err(RegistryError::InvalidContractRelease),
    }
}

fn unsigned(value: &StrictValue) -> Result<u64> {
    match value {
        StrictValue::Unsigned(value) => Ok(*value),
        _ => Err(RegistryError::InvalidContractRelease),
    }
}

fn boolean(value: &StrictValue) -> Result<bool> {
    match value {
        StrictValue::Bool(value) => Ok(*value),
        _ => Err(RegistryError::InvalidContractRelease),
    }
}

fn required<'a>(object: &'a BTreeMap<String, StrictValue>, key: &str) -> Result<&'a StrictValue> {
    object.get(key).ok_or(RegistryError::InvalidContractRelease)
}

fn require_exact_keys(object: &BTreeMap<String, StrictValue>, keys: &[&str]) -> Result<()> {
    let expected: BTreeSet<&str> = keys.iter().copied().collect();
    if object.len() != expected.len()
        || object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected
    {
        return Err(RegistryError::InvalidContractRelease);
    }
    Ok(())
}

fn fixed_hex<const N: usize>(value: &StrictValue, nonzero: bool) -> Result<[u8; N]> {
    let value = text(value)?;
    if value.len() != 2 + N * 2 || !value.starts_with("0x") {
        return Err(RegistryError::InvalidContractRelease);
    }
    let mut output = [0u8; N];
    for (index, pair) in value.as_bytes()[2..].chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    if nonzero && output.iter().all(|byte| *byte == 0) {
        return Err(RegistryError::InvalidContractRelease);
    }
    Ok(output)
}

fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(RegistryError::InvalidContractRelease),
    }
}

fn validate_missing_policy_fields(value: &StrictValue) -> Result<()> {
    let actual = array(value)?.iter().map(text).collect::<Result<Vec<_>>>()?;
    if actual
        != [
            "gas_limit_hint",
            "max_fee_per_gas",
            "max_priority_fee_per_gas",
            "page_size",
        ]
    {
        return Err(RegistryError::InvalidContractRelease);
    }
    Ok(())
}

fn validate_top_level_digests(
    root: &BTreeMap<String, StrictValue>,
    abi_digest: [u8; 32],
    compiler_digest: [u8; 32],
    source_digest: [u8; 32],
    deployment_digest: [u8; 32],
) -> Result<()> {
    let abi = object(required(root, "abi")?)?;
    let compiler = object(required(root, "compiler")?)?;
    let sources = object(required(root, "sources")?)?;
    if text(required(abi, "domain")?)? != ABI_DOMAIN
        || text(required(compiler, "domain")?)? != COMPILER_DOMAIN
        || text(required(sources, "domain")?)? != SOURCE_DOMAIN
        || fixed_hex::<32>(required(abi, "blake2b256")?, true)? != abi_digest
        || fixed_hex::<32>(required(compiler, "blake2b256")?, true)? != compiler_digest
        || fixed_hex::<32>(required(sources, "blake2b256")?, true)? != source_digest
        || fixed_hex::<32>(required(root, "deployment_digest")?, true)? != deployment_digest
    {
        return Err(RegistryError::InvalidContractRelease);
    }
    let algorithms = object(required(root, "hash_algorithms")?)?;
    require_exact_keys(
        algorithms,
        &[
            "abi_compiler_source_deployment_manifest",
            "creation_and_runtime_code",
        ],
    )?;
    if text(required(
        algorithms,
        "abi_compiler_source_deployment_manifest",
    )?)? != "BLAKE2b-256"
        || text(required(algorithms, "creation_and_runtime_code")?)? != "Keccak-256"
    {
        return Err(RegistryError::InvalidContractRelease);
    }
    Ok(())
}

fn validate_chain(
    value: &StrictValue,
    evm_chain_id: u64,
    genesis_hash: [u8; 32],
    native_start_block: u64,
    erc20_start_block: u64,
) -> Result<()> {
    let chain = object(value)?;
    require_exact_keys(chain, &["chain_id", "finality_requirement", "genesis"])?;
    let genesis = object(required(chain, "genesis")?)?;
    require_exact_keys(genesis, &["hash", "number", "timestamp"])?;
    let finality = object(required(chain, "finality_requirement")?)?;
    require_exact_keys(finality, &["minimum_finalized_block", "required_rpc_tag"])?;
    if unsigned(required(chain, "chain_id")?)? != evm_chain_id
        || fixed_hex::<32>(required(genesis, "hash")?, true)? != genesis_hash
        || unsigned(required(genesis, "number")?)? != 0
        || text(required(finality, "required_rpc_tag")?)? != "finalized"
        || unsigned(required(finality, "minimum_finalized_block")?)?
            != native_start_block.max(erc20_start_block)
    {
        return Err(RegistryError::InvalidContractRelease);
    }
    let _ = unsigned(required(genesis, "timestamp")?)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_contracts(
    value: &StrictValue,
    native_address: [u8; 20],
    native_hash: [u8; 32],
    native_block: u64,
    erc20_address: [u8; 20],
    erc20_hash: [u8; 32],
    erc20_block: u64,
) -> Result<()> {
    let contracts = array(value)?;
    if contracts.len() != 2 {
        return Err(RegistryError::InvalidContractRelease);
    }
    let mut seen = BTreeSet::new();
    for (index, value) in contracts.iter().enumerate() {
        let contract = object(value)?;
        require_exact_keys(
            contract,
            &[
                "abi_entry_count",
                "address",
                "artifact",
                "block",
                "creation_code_bytes",
                "creation_code_keccak256",
                "creation_scheme",
                "deployer",
                "immutable_references",
                "linked_library_references",
                "name",
                "nonce",
                "role",
                "runtime_code_bytes",
                "runtime_code_keccak256",
                "source",
                "transaction_hash",
            ],
        )?;
        let role = text(required(contract, "role")?)?;
        let expected_role = if index == 0 { "native" } else { "erc20" };
        if role != expected_role {
            return Err(RegistryError::InvalidContractRelease);
        }
        if !seen.insert(role) {
            return Err(RegistryError::InvalidContractRelease);
        }
        let (expected_name, expected_source, expected_address, expected_hash, expected_block) =
            match role {
                "native" => (
                    "ConditionLockV2",
                    "src/ConditionLockV2.sol",
                    native_address,
                    native_hash,
                    native_block,
                ),
                "erc20" => (
                    "ConditionLockERC20V2",
                    "src/ConditionLockERC20V2.sol",
                    erc20_address,
                    erc20_hash,
                    erc20_block,
                ),
                _ => return Err(RegistryError::InvalidContractRelease),
            };
        let block = object(required(contract, "block")?)?;
        require_exact_keys(block, &["hash", "number", "timestamp"])?;
        if text(required(contract, "name")?)? != expected_name
            || text(required(contract, "source")?)? != expected_source
            || text(required(contract, "creation_scheme")?)? != "CREATE"
            || fixed_hex::<20>(required(contract, "address")?, true)? != expected_address
            || fixed_hex::<32>(required(contract, "runtime_code_keccak256")?, true)?
                != expected_hash
            || unsigned(required(block, "number")?)? != expected_block
            || unsigned(required(contract, "immutable_references")?)? != 0
            || unsigned(required(contract, "linked_library_references")?)? != 0
            || unsigned(required(contract, "abi_entry_count")?)? == 0
            || unsigned(required(contract, "creation_code_bytes")?)? == 0
            || unsigned(required(contract, "runtime_code_bytes")?)? == 0
        {
            return Err(RegistryError::InvalidContractRelease);
        }
        let _ = fixed_hex::<32>(required(contract, "creation_code_keccak256")?, true)?;
        let _ = fixed_hex::<20>(required(contract, "deployer")?, true)?;
        let _ = fixed_hex::<32>(required(contract, "transaction_hash")?, true)?;
        let _ = fixed_hex::<32>(required(block, "hash")?, true)?;
        let _ = unsigned(required(block, "timestamp")?)?;
        let _ = unsigned(required(contract, "nonce")?)?;
    }
    if seen != BTreeSet::from(["erc20", "native"]) {
        return Err(RegistryError::InvalidContractRelease);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(byte: u8, bytes: usize) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(bytes))
    }

    fn valid_json() -> Vec<u8> {
        let native_address = hex(0x11, 20);
        let erc20_address = hex(0x12, 20);
        let native_hash = hex(0x21, 32);
        let erc20_hash = hex(0x22, 32);
        let abi = hex(0x31, 32);
        let compiler = hex(0x32, 32);
        let source = hex(0x33, 32);
        let deployment = hex(0x34, 32);
        let genesis = hex(0x35, 32);
        let contract = |role: &str,
                        name: &str,
                        source_path: &str,
                        address: &str,
                        runtime: &str,
                        block: u64,
                        nonce: u64| {
            serde_json::json!({
                "abi_entry_count": 20,
                "address": address,
                "artifact": format!("out/{name}.sol/{name}.json"),
                "block": {"hash": hex(0x41 + nonce as u8, 32), "number": block, "timestamp": 100 + block},
                "creation_code_bytes": 1000,
                "creation_code_keccak256": hex(0x51 + nonce as u8, 32),
                "creation_scheme": "CREATE",
                "deployer": hex(0x61, 20),
                "immutable_references": 0,
                "linked_library_references": 0,
                "name": name,
                "nonce": nonce,
                "role": role,
                "runtime_code_bytes": 900,
                "runtime_code_keccak256": runtime,
                "source": source_path,
                "transaction_hash": hex(0x71 + nonce as u8, 32),
            })
        };
        let dependencies = serde_json::json!([]);
        let mut value = serde_json::json!({
            "abi": {"blake2b256": abi, "contracts": {"ConditionLockERC20V2": 20, "ConditionLockV2": 20}, "domain": ABI_DOMAIN},
            "chain": {"chain_id": 31337, "finality_requirement": {"minimum_finalized_block": 2, "required_rpc_tag": "finalized"}, "genesis": {"hash": genesis, "number": 0, "timestamp": 1}},
            "compiler": {"blake2b256": compiler, "dependencies": dependencies, "domain": COMPILER_DOMAIN, "remappings": [], "settings": {}, "solc": "0.8.24+commit.e11b9ed9"},
            "contracts": [
                contract("native", "ConditionLockV2", "src/ConditionLockV2.sol", &native_address, &native_hash, 1, 0),
                contract("erc20", "ConditionLockERC20V2", "src/ConditionLockERC20V2.sol", &erc20_address, &erc20_hash, 2, 1)
            ],
            "dependencies": [],
            "deployment_digest": deployment,
            "hash_algorithms": {"abi_compiler_source_deployment_manifest": "BLAKE2b-256", "creation_and_runtime_code": "Keccak-256"},
            "registry_projection": {
                "chain_kind_v1": {"erc20_lock_contract": {"code_hash": erc20_hash, "contract": erc20_address}, "evm_chain_id": 31337, "native_code_hash": native_hash, "native_lock_contract": native_address},
                "evm_deployment_v1_release_fields": {"abi_digest": abi, "compiler_digest": compiler, "deployment_digest": deployment, "erc20_start_block": 2, "finalized_tag_required": true, "genesis_hash": genesis, "native_start_block": 1, "source_digest": source},
                "runtime_policy_fields_not_supplied": ["gas_limit_hint", "max_fee_per_gas", "max_priority_fee_per_gas", "page_size"]
            },
            "schema": RELEASE_SCHEMA,
            "sources": {"blake2b256": source, "domain": SOURCE_DOMAIN, "files": []}
        });
        let raw = serde_json::to_vec(&value).expect("fixture JSON");
        let mut parsed = StrictValue::deserialize(&mut serde_json::Deserializer::from_slice(&raw))
            .expect("strict fixture");
        let digest = domain_digest(RELEASE_MANIFEST_DOMAIN, &canonical_json(&parsed).unwrap())
            .expect("digest");
        value.as_object_mut().expect("root").insert(
            "manifest_digest".to_owned(),
            serde_json::Value::String(format!(
                "0x{}",
                digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )),
        );
        // Retain the strict parse in this fixture to catch accidental unsupported
        // JSON kinds before the actual parser is called.
        parsed = StrictValue::deserialize(&mut serde_json::Deserializer::from_slice(
            &serde_json::to_vec(&value).expect("fixture with digest"),
        ))
        .expect("strict fixture with digest");
        canonical_json(&parsed).expect("canonical fixture")
    }

    fn rewrite_digest(value: &mut serde_json::Value) {
        value
            .as_object_mut()
            .expect("root")
            .remove("manifest_digest");
        let raw = serde_json::to_vec(value).expect("fixture without digest");
        let strict = StrictValue::deserialize(&mut serde_json::Deserializer::from_slice(&raw))
            .expect("strict mutated fixture");
        let digest = domain_digest(RELEASE_MANIFEST_DOMAIN, &canonical_json(&strict).unwrap())
            .expect("mutated digest");
        value.as_object_mut().expect("root").insert(
            "manifest_digest".to_owned(),
            serde_json::Value::String(format!(
                "0x{}",
                digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            )),
        );
    }

    #[test]
    fn exact_release_maps_to_typed_registry_facts_and_separate_policy() {
        let release = EvmContractReleaseV1::parse_json(&valid_json()).expect("valid release");
        assert_eq!(release.evm_chain_id(), 31_337);
        assert_ne!(release.manifest_digest(), [0; 32]);
        let policy = EvmRuntimePolicyV1::new(256, 300_000, 100, 2).expect("policy");
        let deployment = release.deployment(policy);
        assert_eq!(deployment.native_start_block, 1);
        assert_eq!(deployment.erc20_start_block, Some(2));
        assert_eq!(deployment.page_size, 256);
        assert!(deployment.finalized_tag_required);
        assert!(matches!(
            release.chain_kind(),
            ChainKindV1::Evm {
                evm_chain_id: 31_337,
                ..
            }
        ));
    }

    #[test]
    fn digest_projection_duplicate_and_policy_drift_fail_closed() {
        let valid = valid_json();
        let mut value: serde_json::Value = serde_json::from_slice(&valid).expect("fixture value");
        value["registry_projection"]["chain_kind_v1"]["evm_chain_id"] = serde_json::json!(1);
        assert!(matches!(
            EvmContractReleaseV1::parse_json(&serde_json::to_vec(&value).unwrap()),
            Err(RegistryError::ContractReleaseDigestMismatch)
        ));

        rewrite_digest(&mut value);
        assert!(matches!(
            EvmContractReleaseV1::parse_json(&serde_json::to_vec(&value).unwrap()),
            Err(RegistryError::InvalidContractRelease)
        ));

        let duplicate = br#"{"schema":"a","schema":"b"}"#;
        assert!(matches!(
            EvmContractReleaseV1::parse_json(duplicate),
            Err(RegistryError::InvalidContractRelease)
        ));

        assert!(matches!(
            EvmRuntimePolicyV1::new(1_025, 300_000, 100, 2),
            Err(RegistryError::DeploymentMismatch)
        ));
    }
}
