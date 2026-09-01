//! Canonical, secret-free endpoints for the non-DOM production chain ports.
//!
//! The original node manifest intentionally authenticates only one DOM node.
//! EVM and Bitcoin clients must not obtain their endpoints from environment
//! variables or built-in defaults, so this independent fixed-name document is
//! required before the composition root can construct either live port. Only
//! an origin (with an optional trailing slash) is accepted: provider API keys
//! in URL paths must remain out of this persistent, secret-free document.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;

use adapter_btc::types::BitcoinNetworkV1;
use adapter_btc_live::{
    BitcoinCoreNetworkV1, BitcoinCoreRpcClientV1, BitcoinCoreRpcConfigV1, BitcoinCoreRpcTimeoutsV1,
};
use btc_actuator::{
    HttpBitcoinCoreRpcConfigV1, HttpBitcoinCoreRpcTimeoutsV1, HttpBitcoinCoreRpcV1,
};
use chain_profile::ChainKindV1;
use deployment_registry::{ResolvedBitcoinDeploymentV1, ResolvedEvmDeploymentV1};
use evm_actuator::{HttpEvmRpcTimeoutsV1, HttpEvmRpcV1};

use crate::production_config::{
    config_digest, decode_digest, encode_hex, read_owner_file_bounded, validate_state_dir,
    ProductionConfigErrorV1,
};
use crate::production_refund_arming::ProductionEvmRefundFaceV1;

const HEADER_V1: &str = "DOM-INTEROPD-PRODUCTION-CHAIN-SERVICES-V1";
const END_V1: &str = "END-DOM-INTEROPD-PRODUCTION-CHAIN-SERVICES-V1";
const DIGEST_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/PRODUCTION-CHAIN-SERVICES/V1\0";
const LINE_COUNT_V1: usize = 8;
const MAX_ENDPOINT_BYTES_V1: usize = 2_048;
const MAX_COOKIE_PATH_BYTES_V1: usize = 4_096;
const MAX_WALLET_NAME_BYTES_V1: usize = 128;
const MAX_EVM_TIMEOUT_SECONDS_V1: u64 = 300;
const OWNER_FILE_MODE_V1: u32 = 0o600;
const OWNER_DIRECTORY_MODE_V1: u32 = 0o700;

/// Fixed state-directory name of the canonical chain-services document.
pub const PRODUCTION_CHAIN_SERVICES_CONFIG_FILE_V1: &str = "production-chain-services.v1";

/// Maximum accepted encoded document size.
pub const MAX_PRODUCTION_CHAIN_SERVICES_CONFIG_BYTES_V1: u64 = 8_704;

/// Redacted refusal from the chain-services configuration boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionChainServicesErrorV1 {
    /// The fixed owner-only document could not be read safely.
    #[error("production chain-services configuration unavailable")]
    Unavailable,
    /// The canonical document shape, ordering, or integrity digest is invalid.
    #[error("production chain-services configuration is not canonical")]
    InvalidEncoding,
    /// The EVM endpoint was refused by the concrete HTTP RPC implementation.
    #[error("production EVM RPC endpoint is invalid")]
    InvalidEvmEndpoint,
    /// The Bitcoin endpoint was refused by the concrete Core RPC implementation.
    #[error("production Bitcoin RPC endpoint is invalid")]
    InvalidBitcoinEndpoint,
    /// The Bitcoin cookie is not one canonical owner-only regular file.
    #[error("production Bitcoin RPC cookie authority is invalid")]
    InvalidBitcoinCookie,
    /// A chain client or refund face could outlive the orchestration deadline.
    #[error("production chain RPC deadline exceeds runtime authority")]
    InvalidRuntimeTimeout,
}

/// Validated public client configuration for the EVM and Bitcoin faces.
pub struct ProductionChainServicesConfigV1 {
    evm_rpc_endpoint: String,
    bitcoin_rpc_endpoint: String,
    bitcoin_wallet_name: String,
    bitcoin_cookie_path: PathBuf,
    evm_timeout_seconds: u64,
}

impl core::fmt::Debug for ProductionChainServicesConfigV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionChainServicesConfigV1([endpoints redacted])")
    }
}

/// Concrete live clients created from one validated document.
pub(crate) struct ProductionChainClientsV1 {
    pub(crate) evm: HttpEvmRpcV1,
    pub(crate) evm_refund: ProductionEvmRefundFaceV1,
    pub(crate) bitcoin: HttpBitcoinCoreRpcV1,
    pub(crate) bitcoin_live: Rc<BitcoinCoreRpcClientV1>,
}

impl core::fmt::Debug for ProductionChainClientsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionChainClientsV1([clients redacted])")
    }
}

impl ProductionChainServicesConfigV1 {
    /// Builds and validates one document from explicit public configuration.
    pub fn from_parts(
        evm_rpc_endpoint: String,
        bitcoin_rpc_endpoint: String,
        bitcoin_wallet_name: String,
        bitcoin_cookie_path: PathBuf,
        evm_timeout_seconds: u64,
    ) -> Result<Self, ProductionChainServicesErrorV1> {
        validate_endpoint_text(
            &evm_rpc_endpoint,
            ProductionChainServicesErrorV1::InvalidEvmEndpoint,
        )?;
        validate_endpoint_text(
            &bitcoin_rpc_endpoint,
            ProductionChainServicesErrorV1::InvalidBitcoinEndpoint,
        )?;
        validate_wallet_name(&bitcoin_wallet_name)?;
        validate_cookie_path(&bitcoin_cookie_path)?;
        if evm_timeout_seconds == 0 || evm_timeout_seconds > MAX_EVM_TIMEOUT_SECONDS_V1 {
            return Err(ProductionChainServicesErrorV1::InvalidEvmEndpoint);
        }
        HttpEvmRpcV1::new(&evm_rpc_endpoint)
            .map_err(|_| ProductionChainServicesErrorV1::InvalidEvmEndpoint)?;
        HttpBitcoinCoreRpcV1::connect(HttpBitcoinCoreRpcConfigV1 {
            endpoint: bitcoin_rpc_endpoint.clone(),
            cookie_path: bitcoin_cookie_path.clone(),
        })
        .map_err(|_| ProductionChainServicesErrorV1::InvalidBitcoinEndpoint)?;
        Ok(Self {
            evm_rpc_endpoint,
            bitcoin_rpc_endpoint,
            bitcoin_wallet_name,
            bitcoin_cookie_path,
            evm_timeout_seconds,
        })
    }

    /// Exact canonical bytes including the integrity digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionChainServicesErrorV1> {
        let body = self.canonical_body()?;
        let digest = chain_services_digest(body.as_bytes())?;
        let encoded = format!("{body}config_digest={}\n{END_V1}\n", encode_hex(&digest));
        if encoded.len() as u64 > MAX_PRODUCTION_CHAIN_SERVICES_CONFIG_BYTES_V1 {
            return Err(ProductionChainServicesErrorV1::InvalidEncoding);
        }
        Ok(encoded.into_bytes())
    }

    /// Decodes only the exact V1 spelling and revalidates both live clients.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProductionChainServicesErrorV1> {
        if bytes.is_empty()
            || bytes.len() as u64 > MAX_PRODUCTION_CHAIN_SERVICES_CONFIG_BYTES_V1
            || !bytes.is_ascii()
            || bytes.last() != Some(&b'\n')
            || bytes.contains(&b'\r')
        {
            return Err(ProductionChainServicesErrorV1::InvalidEncoding);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ProductionChainServicesErrorV1::InvalidEncoding)?;
        let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
        if lines.len() != LINE_COUNT_V1 || lines.first() != Some(&HEADER_V1) {
            return Err(ProductionChainServicesErrorV1::InvalidEncoding);
        }
        let evm_rpc_endpoint = take_value(&lines, 1, "evm_rpc_endpoint")?.to_owned();
        let bitcoin_rpc_endpoint = take_value(&lines, 2, "bitcoin_rpc_endpoint")?.to_owned();
        let bitcoin_wallet_name = take_value(&lines, 3, "bitcoin_wallet_name")?.to_owned();
        let bitcoin_cookie_path = PathBuf::from(take_value(&lines, 4, "bitcoin_cookie_path")?);
        let evm_timeout_seconds = take_number(
            &lines,
            5,
            "evm_timeout_seconds",
            ProductionChainServicesErrorV1::InvalidEvmEndpoint,
        )?;
        let supplied_digest = decode_digest(take_value(&lines, 6, "config_digest")?)
            .map_err(|_| ProductionChainServicesErrorV1::InvalidEncoding)?;
        if lines.get(7) != Some(&END_V1) {
            return Err(ProductionChainServicesErrorV1::InvalidEncoding);
        }
        let config = Self::from_parts(
            evm_rpc_endpoint,
            bitcoin_rpc_endpoint,
            bitcoin_wallet_name,
            bitcoin_cookie_path,
            evm_timeout_seconds,
        )?;
        let body = config.canonical_body()?;
        if chain_services_digest(body.as_bytes())? != supplied_digest
            || config.canonical_bytes()?.as_slice() != bytes
        {
            return Err(ProductionChainServicesErrorV1::InvalidEncoding);
        }
        Ok(config)
    }

    /// Consumes the public configuration into all concrete non-DOM clients.
    ///
    /// Chain identity is taken only from the threshold-authenticated registry
    /// capability. It is deliberately not duplicated in this local document.
    pub(crate) fn into_clients(
        self,
        evm_deployment: ResolvedEvmDeploymentV1,
        bitcoin_deployment: &ResolvedBitcoinDeploymentV1,
        external_call_timeout_ms: u64,
    ) -> Result<ProductionChainClientsV1, ProductionChainServicesErrorV1> {
        validate_cookie_path(&self.bitcoin_cookie_path)?;
        let (evm_timeouts, bitcoin_timeouts, bitcoin_live_timeouts) =
            bounded_rpc_timeouts(external_call_timeout_ms, self.evm_timeout_seconds)?;
        let evm = HttpEvmRpcV1::new_with_timeouts(&self.evm_rpc_endpoint, evm_timeouts)
            .map_err(|_| ProductionChainServicesErrorV1::InvalidEvmEndpoint)?;
        let evm_refund = ProductionEvmRefundFaceV1::connect(
            self.evm_rpc_endpoint,
            self.evm_timeout_seconds,
            evm_deployment,
        )
        .map_err(|_| ProductionChainServicesErrorV1::InvalidEvmEndpoint)?;
        let bitcoin = HttpBitcoinCoreRpcV1::connect_with_timeouts(
            HttpBitcoinCoreRpcConfigV1 {
                endpoint: self.bitcoin_rpc_endpoint.clone(),
                cookie_path: self.bitcoin_cookie_path.clone(),
            },
            bitcoin_timeouts,
        )
        .map_err(|_| ProductionChainServicesErrorV1::InvalidBitcoinEndpoint)?;
        let (network, signet_challenge) = bitcoin_network_identity(bitcoin_deployment)?;
        let bitcoin_live = BitcoinCoreRpcClientV1::connect_with_timeouts(
            BitcoinCoreRpcConfigV1 {
                endpoint: self.bitcoin_rpc_endpoint,
                wallet_name: self.bitcoin_wallet_name,
                cookie_file: self.bitcoin_cookie_path,
                expected_network: network,
                expected_genesis_hash: bitcoin_deployment.deployment().genesis_hash,
                expected_signet_challenge: signet_challenge,
            },
            bitcoin_live_timeouts,
        )
        .map_err(|_| ProductionChainServicesErrorV1::InvalidBitcoinEndpoint)?;
        Ok(ProductionChainClientsV1 {
            evm,
            evm_refund,
            bitcoin,
            bitcoin_live: Rc::new(bitcoin_live),
        })
    }

    fn canonical_body(&self) -> Result<String, ProductionChainServicesErrorV1> {
        let cookie = self
            .bitcoin_cookie_path
            .to_str()
            .ok_or(ProductionChainServicesErrorV1::InvalidBitcoinCookie)?;
        Ok(format!(
            "{HEADER_V1}\nevm_rpc_endpoint={}\nbitcoin_rpc_endpoint={}\nbitcoin_wallet_name={}\nbitcoin_cookie_path={}\nevm_timeout_seconds={}\n",
            self.evm_rpc_endpoint,
            self.bitcoin_rpc_endpoint,
            self.bitcoin_wallet_name,
            cookie,
            self.evm_timeout_seconds,
        ))
    }
}

fn bounded_rpc_timeouts(
    external_call_timeout_ms: u64,
    evm_refund_timeout_seconds: u64,
) -> Result<
    (
        HttpEvmRpcTimeoutsV1,
        HttpBitcoinCoreRpcTimeoutsV1,
        BitcoinCoreRpcTimeoutsV1,
    ),
    ProductionChainServicesErrorV1,
> {
    let request = Duration::from_millis(external_call_timeout_ms);
    let refund_ms = evm_refund_timeout_seconds
        .checked_mul(1_000)
        .ok_or(ProductionChainServicesErrorV1::InvalidRuntimeTimeout)?;
    if external_call_timeout_ms == 0 || refund_ms > external_call_timeout_ms {
        return Err(ProductionChainServicesErrorV1::InvalidRuntimeTimeout);
    }

    let evm_default = HttpEvmRpcTimeoutsV1::production_default();
    let bitcoin_default = HttpBitcoinCoreRpcTimeoutsV1::production_default();
    let bitcoin_live_default = BitcoinCoreRpcTimeoutsV1::production_default();
    let evm = HttpEvmRpcTimeoutsV1::new(evm_default.connect().min(request), request)
        .map_err(|_| ProductionChainServicesErrorV1::InvalidRuntimeTimeout)?;
    let bitcoin =
        HttpBitcoinCoreRpcTimeoutsV1::new(bitcoin_default.connect().min(request), request)
            .map_err(|_| ProductionChainServicesErrorV1::InvalidRuntimeTimeout)?;
    let bitcoin_live =
        BitcoinCoreRpcTimeoutsV1::new(bitcoin_live_default.connect().min(request), request)
            .map_err(|_| ProductionChainServicesErrorV1::InvalidRuntimeTimeout)?;
    Ok((evm, bitcoin, bitcoin_live))
}

/// Loads the fixed-name V1 document under the already owner-only state root.
pub fn load_production_chain_services_v1(
    state_dir: &Path,
) -> Result<ProductionChainServicesConfigV1, ProductionChainServicesErrorV1> {
    let state_dir =
        validate_state_dir(state_dir).map_err(|_| ProductionChainServicesErrorV1::Unavailable)?;
    let bytes = read_owner_file_bounded(
        &state_dir.join(PRODUCTION_CHAIN_SERVICES_CONFIG_FILE_V1),
        MAX_PRODUCTION_CHAIN_SERVICES_CONFIG_BYTES_V1,
        ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map_err(|_| ProductionChainServicesErrorV1::Unavailable)?;
    ProductionChainServicesConfigV1::decode_canonical(&bytes)
}

fn validate_endpoint_text(
    endpoint: &str,
    refusal: ProductionChainServicesErrorV1,
) -> Result<(), ProductionChainServicesErrorV1> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_BYTES_V1
        || !endpoint.is_ascii()
        || endpoint.bytes().any(|byte| {
            byte.is_ascii_control() || matches!(byte, b'@' | b'?' | b'#' | b'\\' | b' ')
        })
    {
        return Err(refusal);
    }
    let (plaintext, rest) = if let Some(rest) = endpoint.strip_prefix("https://") {
        (false, rest)
    } else if let Some(rest) = endpoint.strip_prefix("http://") {
        (true, rest)
    } else {
        return Err(refusal);
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty()
        || authority.contains('/')
        || (plaintext && !plaintext_authority_is_loopback(authority))
    {
        return Err(refusal);
    }
    Ok(())
}

fn plaintext_authority_is_loopback(authority: &str) -> bool {
    if authority == "127.0.0.1" || authority == "[::1]" {
        return true;
    }
    let port_is_canonical = |port: &str| {
        !port.is_empty()
            && port.len() <= 5
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|value| value != 0)
    };
    authority
        .strip_prefix("127.0.0.1:")
        .or_else(|| authority.strip_prefix("[::1]:"))
        .is_some_and(port_is_canonical)
}

fn validate_wallet_name(wallet: &str) -> Result<(), ProductionChainServicesErrorV1> {
    if wallet.is_empty()
        || wallet.len() > MAX_WALLET_NAME_BYTES_V1
        || wallet == "."
        || wallet == ".."
        || wallet
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProductionChainServicesErrorV1::InvalidBitcoinEndpoint);
    }
    Ok(())
}

fn validate_cookie_path(path: &Path) -> Result<(), ProductionChainServicesErrorV1> {
    let rendered = path
        .to_str()
        .ok_or(ProductionChainServicesErrorV1::InvalidBitcoinCookie)?;
    if !path.is_absolute()
        || rendered.is_empty()
        || rendered.len() > MAX_COOKIE_PATH_BYTES_V1
        || !rendered.is_ascii()
        || rendered.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ProductionChainServicesErrorV1::InvalidBitcoinCookie);
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| ProductionChainServicesErrorV1::InvalidBitcoinCookie)?;
    if canonical != path {
        return Err(ProductionChainServicesErrorV1::InvalidBitcoinCookie);
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| ProductionChainServicesErrorV1::InvalidBitcoinCookie)?;
    let parent = path
        .parent()
        .ok_or(ProductionChainServicesErrorV1::InvalidBitcoinCookie)?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|_| ProductionChainServicesErrorV1::InvalidBitcoinCookie)?;
    if canonical_parent != parent {
        return Err(ProductionChainServicesErrorV1::InvalidBitcoinCookie);
    }
    let parent_metadata =
        fs::metadata(parent).map_err(|_| ProductionChainServicesErrorV1::InvalidBitcoinCookie)?;
    let effective_uid = fs::metadata("/proc/self")
        .map_err(|_| ProductionChainServicesErrorV1::InvalidBitcoinCookie)?
        .uid();
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o7777 != OWNER_FILE_MODE_V1
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || !parent_metadata.file_type().is_dir()
        || parent_metadata.mode() & 0o7777 != OWNER_DIRECTORY_MODE_V1
        || parent_metadata.uid() != effective_uid
    {
        return Err(ProductionChainServicesErrorV1::InvalidBitcoinCookie);
    }
    Ok(())
}

fn take_number(
    lines: &[&str],
    index: usize,
    key: &str,
    refusal: ProductionChainServicesErrorV1,
) -> Result<u64, ProductionChainServicesErrorV1> {
    let value = take_value(lines, index, key)?;
    if value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(refusal);
    }
    value.parse().map_err(|_| refusal)
}

fn bitcoin_network_identity(
    deployment: &ResolvedBitcoinDeploymentV1,
) -> Result<(BitcoinCoreNetworkV1, Option<Vec<u8>>), ProductionChainServicesErrorV1> {
    match deployment.profile().kind {
        ChainKindV1::Bitcoin {
            network: BitcoinNetworkV1::Regtest,
        } => Ok((BitcoinCoreNetworkV1::Regtest, None)),
        ChainKindV1::Bitcoin {
            network: BitcoinNetworkV1::PublicSignet,
        } => Ok((BitcoinCoreNetworkV1::PublicSignet, None)),
        ChainKindV1::Bitcoin {
            network: BitcoinNetworkV1::CustomSignet,
        } if !deployment.deployment().signet_challenge.is_empty() => Ok((
            BitcoinCoreNetworkV1::CustomSignet,
            Some(deployment.deployment().signet_challenge.clone()),
        )),
        _ => Err(ProductionChainServicesErrorV1::InvalidBitcoinEndpoint),
    }
}

fn take_value<'a>(
    lines: &'a [&str],
    index: usize,
    key: &str,
) -> Result<&'a str, ProductionChainServicesErrorV1> {
    lines
        .get(index)
        .and_then(|line| line.strip_prefix(key))
        .and_then(|rest| rest.strip_prefix('='))
        .filter(|value| !value.is_empty())
        .ok_or(ProductionChainServicesErrorV1::InvalidEncoding)
}

fn chain_services_digest(bytes: &[u8]) -> Result<[u8; 32], ProductionChainServicesErrorV1> {
    let mut domained = Vec::with_capacity(DIGEST_DOMAIN_V1.len() + bytes.len());
    domained.extend_from_slice(DIGEST_DOMAIN_V1);
    domained.extend_from_slice(bytes);
    config_digest(&domained).map_err(|_| ProductionChainServicesErrorV1::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn owner_cookie(directory: &Path) -> Result<PathBuf, std::io::Error> {
        fs::set_permissions(
            directory,
            fs::Permissions::from_mode(OWNER_DIRECTORY_MODE_V1),
        )?;
        let path = directory.join(".cookie");
        let mut options = OpenOptions::new();
        options
            .write(true)
            .create_new(true)
            .mode(OWNER_FILE_MODE_V1);
        let _file = options.open(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(OWNER_FILE_MODE_V1))?;
        Ok(path)
    }

    fn config(
        cookie: PathBuf,
    ) -> Result<ProductionChainServicesConfigV1, ProductionChainServicesErrorV1> {
        ProductionChainServicesConfigV1::from_parts(
            "http://127.0.0.1:8545".to_owned(),
            "http://127.0.0.1:18443".to_owned(),
            "dom-interop-wallet".to_owned(),
            cookie.clone(),
            30,
        )
    }

    #[test]
    fn canonical_round_trip_revalidates_all_local_client_configuration() -> TestResult {
        let directory = tempfile::tempdir()?;
        let cookie = owner_cookie(directory.path())?;
        let encoded = config(cookie)?.canonical_bytes()?;
        let _decoded = ProductionChainServicesConfigV1::decode_canonical(&encoded)?;
        Ok(())
    }

    #[test]
    fn non_loopback_plaintext_and_endpoint_credentials_are_refused() -> TestResult {
        let directory = tempfile::tempdir()?;
        let cookie = owner_cookie(directory.path())?;
        assert_eq!(
            ProductionChainServicesConfigV1::from_parts(
                "http://192.0.2.1:8545".to_owned(),
                "http://127.0.0.1:18443".to_owned(),
                "dom-interop-wallet".to_owned(),
                cookie.clone(),
                30,
            )
            .err(),
            Some(ProductionChainServicesErrorV1::InvalidEvmEndpoint)
        );
        assert_eq!(
            ProductionChainServicesConfigV1::from_parts(
                "http://127.0.0.1:8545".to_owned(),
                "http://user:password@127.0.0.1:18443".to_owned(),
                "dom-interop-wallet".to_owned(),
                cookie.clone(),
                30,
            )
            .err(),
            Some(ProductionChainServicesErrorV1::InvalidBitcoinEndpoint)
        );
        for endpoint in [
            "https://provider.example/api-key",
            "https://provider.example/?token=secret",
            "https://user@provider.example",
            "https://provider.example/#fragment",
            "http://localhost:8545",
            "http://localhost.example:8545",
            "http://127.0.0.1.example:8545",
            "http://[::1].example:8545",
            "http://127.0.0.1:0",
            "http://127.0.0.1:65536",
        ] {
            assert_eq!(
                ProductionChainServicesConfigV1::from_parts(
                    endpoint.to_owned(),
                    "http://127.0.0.1:18443".to_owned(),
                    "dom-interop-wallet".to_owned(),
                    cookie.clone(),
                    30,
                )
                .err(),
                Some(ProductionChainServicesErrorV1::InvalidEvmEndpoint)
            );
        }
        Ok(())
    }

    #[test]
    fn wallet_timeout_and_parent_authority_are_strict() -> TestResult {
        let directory = tempfile::tempdir()?;
        let cookie = owner_cookie(directory.path())?;
        for wallet in ["", ".", "..", "with/slash", "with space"] {
            assert_eq!(
                ProductionChainServicesConfigV1::from_parts(
                    "http://127.0.0.1:8545".to_owned(),
                    "http://127.0.0.1:18443".to_owned(),
                    wallet.to_owned(),
                    cookie.clone(),
                    30,
                )
                .err(),
                Some(ProductionChainServicesErrorV1::InvalidBitcoinEndpoint)
            );
        }
        assert_eq!(
            ProductionChainServicesConfigV1::from_parts(
                "http://127.0.0.1:8545".to_owned(),
                "http://127.0.0.1:18443".to_owned(),
                "dom-interop-wallet".to_owned(),
                cookie.clone(),
                0,
            )
            .err(),
            Some(ProductionChainServicesErrorV1::InvalidEvmEndpoint)
        );
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))?;
        assert_eq!(
            config(cookie).err(),
            Some(ProductionChainServicesErrorV1::InvalidBitcoinCookie)
        );
        Ok(())
    }

    #[test]
    fn cookie_symlink_world_readable_and_hardlink_are_refused() -> TestResult {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let cookie = owner_cookie(directory.path())?;
        fs::set_permissions(&cookie, fs::Permissions::from_mode(0o644))?;
        assert_eq!(
            config(cookie.clone()).err(),
            Some(ProductionChainServicesErrorV1::InvalidBitcoinCookie)
        );
        fs::set_permissions(&cookie, fs::Permissions::from_mode(OWNER_FILE_MODE_V1))?;
        let hardlink = directory.path().join("hardlink-cookie");
        fs::hard_link(&cookie, &hardlink)?;
        assert_eq!(
            config(cookie.clone()).err(),
            Some(ProductionChainServicesErrorV1::InvalidBitcoinCookie)
        );
        fs::remove_file(hardlink)?;
        let symlink_path = directory.path().join("symlink-cookie");
        symlink(&cookie, &symlink_path)?;
        assert_eq!(
            config(symlink_path).err(),
            Some(ProductionChainServicesErrorV1::InvalidBitcoinCookie)
        );
        Ok(())
    }

    #[test]
    fn digest_order_trailing_bytes_and_unknown_keys_are_refused() -> TestResult {
        let directory = tempfile::tempdir()?;
        let cookie = owner_cookie(directory.path())?;
        let encoded = config(cookie)?.canonical_bytes()?;
        let mut changed = encoded.clone();
        changed[0] ^= 1;
        assert_eq!(
            ProductionChainServicesConfigV1::decode_canonical(&changed).err(),
            Some(ProductionChainServicesErrorV1::InvalidEncoding)
        );
        let mut trailing = encoded.clone();
        trailing.extend_from_slice(b"extra\n");
        assert_eq!(
            ProductionChainServicesConfigV1::decode_canonical(&trailing).err(),
            Some(ProductionChainServicesErrorV1::InvalidEncoding)
        );
        let text = std::str::from_utf8(&encoded)?;
        let unknown = text.replace("evm_rpc_endpoint=", "unknown_endpoint=");
        assert_eq!(
            ProductionChainServicesConfigV1::decode_canonical(unknown.as_bytes()).err(),
            Some(ProductionChainServicesErrorV1::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn debug_never_exposes_endpoint_wallet_or_cookie() -> TestResult {
        let directory = tempfile::tempdir()?;
        let cookie = owner_cookie(directory.path())?;
        let config = config(cookie.clone())?;
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("127.0.0.1"));
        assert!(!rendered.contains("dom-interop-wallet"));
        assert!(!rendered.contains(cookie.to_string_lossy().as_ref()));
        Ok(())
    }

    #[test]
    fn every_rpc_deadline_is_bounded_by_the_runtime_authority() -> TestResult {
        let (evm, bitcoin, bitcoin_live) = bounded_rpc_timeouts(1_500, 1)?;
        let bound = Duration::from_millis(1_500);
        assert_eq!(evm.request(), bound);
        assert_eq!(bitcoin.request(), bound);
        assert_eq!(bitcoin_live.request(), bound);
        assert!(evm.connect() <= bound);
        assert!(bitcoin.connect() <= bound);
        assert!(bitcoin_live.connect() <= bound);
        assert_eq!(
            bounded_rpc_timeouts(999, 1).err(),
            Some(ProductionChainServicesErrorV1::InvalidRuntimeTimeout)
        );
        assert_eq!(
            bounded_rpc_timeouts(30_000, 31).err(),
            Some(ProductionChainServicesErrorV1::InvalidRuntimeTimeout)
        );
        Ok(())
    }
}
