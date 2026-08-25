//! Concrete, cookie-authenticated Bitcoin Core JSON-RPC transport.

use std::fs::File;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::AsFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use bitcoin::hashes::Hash;
use bitcoin::{blockdata::constants::genesis_block, Address, BlockHash, Network, Txid};
use reqwest::blocking::{Client, Response};
use serde_json::{json, Value};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
use rustix::fs::{fstat, open, FileType, Mode, OFlags};
#[cfg(target_os = "linux")]
use rustix::process::geteuid;

use crate::LiveBitcoinError;

pub(crate) const MAX_RPC_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COOKIE_BYTES: u64 = 4 * 1024;
const MAX_WALLET_NAME_BYTES: usize = 128;
pub(crate) const MAX_SIGNET_CHALLENGE_BYTES: usize = 10_000;
const PUBLIC_SIGNET_CHALLENGE_HEX: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";
const RPC_ID: &str = "dom-interop-f7";

/// Bitcoin Core chain selected by the production boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitcoinCoreNetworkV1 {
    /// Deterministic Bitcoin Core regtest.
    Regtest,
    /// The globally defined public Signet.
    PublicSignet,
    /// An operator-pinned custom Signet distinguished by its challenge.
    CustomSignet,
}

impl BitcoinCoreNetworkV1 {
    pub(crate) const fn core_chain_name(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::PublicSignet | Self::CustomSignet => "signet",
        }
    }

    pub(crate) const fn bitcoin_network(self) -> Network {
        match self {
            Self::Regtest => Network::Regtest,
            Self::PublicSignet | Self::CustomSignet => Network::Signet,
        }
    }

    pub(crate) const fn evidence_network(self) -> btc_evidence::BitcoinEvidenceNetworkV1 {
        match self {
            Self::Regtest => btc_evidence::BitcoinEvidenceNetworkV1::Regtest,
            Self::PublicSignet => btc_evidence::BitcoinEvidenceNetworkV1::PublicSignet,
            Self::CustomSignet => btc_evidence::BitcoinEvidenceNetworkV1::CustomSignet,
        }
    }
}

/// Immutable configuration for one concrete Bitcoin Core RPC authority.
///
/// `endpoint` must be loopback HTTP without embedded credentials. The cookie
/// is reopened and metadata-validated for every call so a legitimate Core
/// restart may rotate it without weakening owner-only enforcement.
pub struct BitcoinCoreRpcConfigV1 {
    /// Loopback node endpoint, for example `http://127.0.0.1:43676/`.
    pub endpoint: String,
    /// Loaded wallet name used only for wallet RPC methods.
    pub wallet_name: String,
    /// Absolute path to Bitcoin Core's owner-only `.cookie` file.
    pub cookie_file: PathBuf,
    /// Expected chain family.
    pub expected_network: BitcoinCoreNetworkV1,
    /// Exact expected genesis block hash in internal byte order.
    pub expected_genesis_hash: [u8; 32],
    /// Exact custom-Signet challenge script bytes.
    ///
    /// This must be `Some` only for [`BitcoinCoreNetworkV1::CustomSignet`].
    /// Public Signet uses the canonical challenge compiled into this crate;
    /// regtest has no Signet challenge.
    pub expected_signet_challenge: Option<Vec<u8>>,
}

/// Concrete Bitcoin Core client with an opaque credential authority.
///
/// This type has no credential getter and its debug representation is
/// redacted. Each request rereads the cookie through a no-follow descriptor,
/// validates exact owner/mode/link metadata, bounds the response, and rejects
/// JSON-RPC errors without reflecting their attacker-controlled body.
pub struct BitcoinCoreRpcClientV1 {
    client: Client,
    node_endpoint: reqwest::Url,
    wallet_endpoint: reqwest::Url,
    cookie_file: PathBuf,
    network: BitcoinCoreNetworkV1,
    genesis_hash: [u8; 32],
    expected_signet_challenge: Option<Vec<u8>>,
}

impl core::fmt::Debug for BitcoinCoreRpcClientV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BitcoinCoreRpcClientV1([redacted])")
    }
}

impl BitcoinCoreRpcClientV1 {
    /// Connects to and authenticates the exact configured chain identity.
    pub fn connect(config: BitcoinCoreRpcConfigV1) -> Result<Self, LiveBitcoinError> {
        let node_endpoint = validate_endpoint(&config.endpoint)?;
        validate_wallet_name(&config.wallet_name)?;
        let cookie_file = validate_cookie_path(&config.cookie_file)?;
        if config.expected_genesis_hash == [0; 32] {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        if canonical_genesis_hash(config.expected_network) != config.expected_genesis_hash {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        let expected_signet_challenge =
            expected_signet_challenge(config.expected_network, config.expected_signet_challenge)?;
        let mut wallet_endpoint = node_endpoint.clone();
        {
            let mut segments = wallet_endpoint
                .path_segments_mut()
                .map_err(|_| LiveBitcoinError::InvalidRequest)?;
            segments.pop_if_empty();
            segments.push("wallet");
            segments.push(&config.wallet_name);
        }
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| LiveBitcoinError::Rpc)?;
        let authority = Self {
            client,
            node_endpoint,
            wallet_endpoint,
            cookie_file,
            network: config.expected_network,
            genesis_hash: config.expected_genesis_hash,
            expected_signet_challenge,
        };
        authority.require_chain_identity()?;
        Ok(authority)
    }

    /// Revalidates the concrete chain name, genesis, and Signet challenge.
    pub fn require_chain_identity(&self) -> Result<(), LiveBitcoinError> {
        let information = self.node_rpc("getblockchaininfo", json!([]))?;
        if information.get("chain").and_then(Value::as_str) != Some(self.network.core_chain_name())
        {
            return Err(LiveBitcoinError::IdentityMismatch);
        }
        match &self.expected_signet_challenge {
            Some(expected) => {
                let actual = information
                    .get("signet_challenge")
                    .and_then(Value::as_str)
                    .ok_or(LiveBitcoinError::IdentityMismatch)
                    .and_then(|value| {
                        decode_hex_bounded(value, MAX_SIGNET_CHALLENGE_BYTES)
                            .map_err(|_| LiveBitcoinError::IdentityMismatch)
                    })?;
                if &actual != expected {
                    return Err(LiveBitcoinError::IdentityMismatch);
                }
            }
            None if information.get("signet_challenge").is_some() => {
                return Err(LiveBitcoinError::IdentityMismatch);
            }
            None => {}
        }
        let genesis = self.node_rpc("getblockhash", json!([0]))?;
        let genesis = genesis
            .as_str()
            .ok_or(LiveBitcoinError::InvalidRpcResponse)
            .and_then(parse_block_hash_internal)?;
        if genesis != self.genesis_hash {
            return Err(LiveBitcoinError::IdentityMismatch);
        }
        Ok(())
    }

    /// Exact configured chain family; safe public metadata.
    #[must_use]
    pub const fn network(&self) -> BitcoinCoreNetworkV1 {
        self.network
    }

    /// Exact configured genesis hash in internal byte order.
    #[must_use]
    pub const fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    pub(crate) fn fresh_wallet_destination_script(
        &self,
        label: &'static str,
    ) -> Result<Vec<u8>, LiveBitcoinError> {
        if label.is_empty()
            || label.len() > MAX_WALLET_NAME_BYTES
            || label
                .bytes()
                .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_'))
        {
            return Err(LiveBitcoinError::InvalidRequest);
        }
        let display = self
            .wallet_rpc("getnewaddress", json!([label, "bech32m"]))?
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or(LiveBitcoinError::InvalidRpcResponse)?
            .to_owned();
        let address = Address::from_str(&display)
            .map_err(|_| LiveBitcoinError::InvalidRpcResponse)?
            .require_network(self.network.bitcoin_network())
            .map_err(|_| LiveBitcoinError::IdentityMismatch)?;
        let script = address.script_pubkey().into_bytes();
        let information = self.wallet_rpc("getaddressinfo", json!([&display]))?;
        let exact_script = information
            .get("scriptPubKey")
            .and_then(Value::as_str)
            .ok_or(LiveBitcoinError::InvalidRpcResponse)
            .and_then(|value| decode_hex_bounded(value, 10_000))?;
        if information.get("ismine").and_then(Value::as_bool) != Some(true)
            || information.get("solvable").and_then(Value::as_bool) != Some(true)
            || exact_script != script
        {
            return Err(LiveBitcoinError::IdentityMismatch);
        }
        Ok(script)
    }

    pub(crate) fn signet_challenge(&self) -> Option<&[u8]> {
        self.expected_signet_challenge.as_deref()
    }

    pub(crate) fn node_rpc(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<Value, LiveBitcoinError> {
        self.rpc(&self.node_endpoint, method, params)
    }

    pub(crate) fn wallet_rpc(
        &self,
        method: &'static str,
        params: Value,
    ) -> Result<Value, LiveBitcoinError> {
        self.rpc(&self.wallet_endpoint, method, params)
    }

    fn rpc(
        &self,
        endpoint: &reqwest::Url,
        method: &'static str,
        params: Value,
    ) -> Result<Value, LiveBitcoinError> {
        let cookie = read_cookie(&self.cookie_file)?;
        let separator = cookie
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(LiveBitcoinError::CredentialUnavailable)?;
        if separator == 0 || separator + 1 >= cookie.len() {
            return Err(LiveBitcoinError::CredentialUnavailable);
        }
        let user = std::str::from_utf8(&cookie[..separator])
            .map_err(|_| LiveBitcoinError::CredentialUnavailable)?;
        let password = std::str::from_utf8(&cookie[separator + 1..])
            .map_err(|_| LiveBitcoinError::CredentialUnavailable)?;
        let response = self
            .client
            .post(endpoint.clone())
            .basic_auth(user, Some(password))
            .json(&json!({
                "jsonrpc": "1.0",
                "id": RPC_ID,
                "method": method,
                "params": params,
            }))
            .send()
            .map_err(|_| LiveBitcoinError::Rpc)?;
        decode_rpc_response(response)
    }
}

pub(crate) fn canonical_genesis_hash(network: BitcoinCoreNetworkV1) -> [u8; 32] {
    let network = match network {
        BitcoinCoreNetworkV1::Regtest => Network::Regtest,
        BitcoinCoreNetworkV1::PublicSignet | BitcoinCoreNetworkV1::CustomSignet => Network::Signet,
    };
    genesis_block(network)
        .block_hash()
        .to_raw_hash()
        .to_byte_array()
}

pub(crate) fn expected_signet_challenge(
    network: BitcoinCoreNetworkV1,
    configured: Option<Vec<u8>>,
) -> Result<Option<Vec<u8>>, LiveBitcoinError> {
    match (network, configured) {
        (BitcoinCoreNetworkV1::Regtest, None) => Ok(None),
        (BitcoinCoreNetworkV1::PublicSignet, None) => {
            decode_hex_bounded(PUBLIC_SIGNET_CHALLENGE_HEX, MAX_SIGNET_CHALLENGE_BYTES)
                .map(Some)
                .map_err(|_| LiveBitcoinError::InvalidRequest)
        }
        (BitcoinCoreNetworkV1::CustomSignet, Some(challenge))
            if !challenge.is_empty()
                && challenge.len() <= MAX_SIGNET_CHALLENGE_BYTES
                && encode_hex(&challenge) != PUBLIC_SIGNET_CHALLENGE_HEX =>
        {
            Ok(Some(challenge))
        }
        _ => Err(LiveBitcoinError::InvalidRequest),
    }
}

fn decode_rpc_response(response: Response) -> Result<Value, LiveBitcoinError> {
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES)
    {
        return Err(LiveBitcoinError::Rpc);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RPC_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LiveBitcoinError::Rpc)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_RPC_RESPONSE_BYTES {
        return Err(LiveBitcoinError::InvalidRpcResponse);
    }
    let mut envelope: Value =
        serde_json::from_slice(&bytes).map_err(|_| LiveBitcoinError::InvalidRpcResponse)?;
    if envelope.get("id").and_then(Value::as_str) != Some(RPC_ID)
        || !envelope.get("error").is_some_and(Value::is_null)
    {
        return Err(LiveBitcoinError::Rpc);
    }
    envelope
        .get_mut("result")
        .map(Value::take)
        .ok_or(LiveBitcoinError::InvalidRpcResponse)
}

fn validate_endpoint(endpoint: &str) -> Result<reqwest::Url, LiveBitcoinError> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| LiveBitcoinError::InvalidRequest)?;
    let host = url.host_str().ok_or(LiveBitcoinError::InvalidRequest)?;
    let loopback = host
        .parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback());
    if url.scheme() != "http"
        || !loopback
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    Ok(url)
}

fn validate_wallet_name(wallet_name: &str) -> Result<(), LiveBitcoinError> {
    if wallet_name.is_empty()
        || wallet_name.len() > MAX_WALLET_NAME_BYTES
        || matches!(wallet_name, "." | "..")
        || wallet_name
            .bytes()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(LiveBitcoinError::InvalidRequest);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_cookie_path(path: &Path) -> Result<PathBuf, LiveBitcoinError> {
    if !path.is_absolute() {
        return Err(LiveBitcoinError::CredentialUnavailable);
    }
    let parent = path
        .parent()
        .ok_or(LiveBitcoinError::CredentialUnavailable)?;
    let canonical_parent =
        std::fs::canonicalize(parent).map_err(|_| LiveBitcoinError::CredentialUnavailable)?;
    if canonical_parent != parent {
        return Err(LiveBitcoinError::CredentialUnavailable);
    }
    let parent_metadata =
        std::fs::symlink_metadata(parent).map_err(|_| LiveBitcoinError::CredentialUnavailable)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != geteuid().as_raw()
        || parent_metadata.mode() & 0o777 != 0o700
    {
        return Err(LiveBitcoinError::CredentialUnavailable);
    }
    validate_cookie_metadata(path)?;
    Ok(path.to_path_buf())
}

#[cfg(not(target_os = "linux"))]
fn validate_cookie_path(_path: &Path) -> Result<PathBuf, LiveBitcoinError> {
    Err(LiveBitcoinError::CredentialUnavailable)
}

#[cfg(target_os = "linux")]
fn validate_cookie_metadata(path: &Path) -> Result<(), LiveBitcoinError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| LiveBitcoinError::CredentialUnavailable)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(LiveBitcoinError::CredentialUnavailable);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_cookie(path: &Path) -> Result<Zeroizing<Vec<u8>>, LiveBitcoinError> {
    validate_cookie_metadata(path)?;
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| LiveBitcoinError::CredentialUnavailable)?;
    let stat = fstat(descriptor.as_fd()).map_err(|_| LiveBitcoinError::CredentialUnavailable)?;
    let named =
        std::fs::symlink_metadata(path).map_err(|_| LiveBitcoinError::CredentialUnavailable)?;
    if !FileType::from_raw_mode(stat.st_mode).is_file()
        || stat.st_uid != geteuid().as_raw()
        || Mode::from_raw_mode(stat.st_mode).bits() != 0o600
        || stat.st_nlink != 1
        || stat.st_dev != named.dev()
        || stat.st_ino != named.ino()
    {
        return Err(LiveBitcoinError::CredentialUnavailable);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_COOKIE_BYTES as usize));
    Read::by_ref(&mut file)
        .take(MAX_COOKIE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LiveBitcoinError::CredentialUnavailable)?;
    if bytes.len() as u64 > MAX_COOKIE_BYTES {
        return Err(LiveBitcoinError::CredentialUnavailable);
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_graphic()) {
        return Err(LiveBitcoinError::CredentialUnavailable);
    }
    Ok(bytes)
}

#[cfg(not(target_os = "linux"))]
fn read_cookie(_path: &Path) -> Result<Zeroizing<Vec<u8>>, LiveBitcoinError> {
    Err(LiveBitcoinError::CredentialUnavailable)
}

pub(crate) fn parse_txid_internal(display: &str) -> Result<[u8; 32], LiveBitcoinError> {
    Txid::from_str(display)
        .map(|hash| hash.to_raw_hash().to_byte_array())
        .map_err(|_| LiveBitcoinError::InvalidRpcResponse)
}

pub(crate) fn parse_block_hash_internal(display: &str) -> Result<[u8; 32], LiveBitcoinError> {
    BlockHash::from_str(display)
        .map(|hash| hash.to_raw_hash().to_byte_array())
        .map_err(|_| LiveBitcoinError::InvalidRpcResponse)
}

pub(crate) fn display_txid(bytes: [u8; 32]) -> String {
    Txid::from_raw_hash(bitcoin::hashes::sha256d::Hash::from_byte_array(bytes)).to_string()
}

pub(crate) fn decode_hex_bounded(
    value: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, LiveBitcoinError> {
    if value.len() % 2 != 0 || value.len() / 2 > maximum_bytes {
        return Err(LiveBitcoinError::BoundsExceeded);
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_nibble(byte: u8) -> Result<u8, LiveBitcoinError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(LiveBitcoinError::InvalidRpcResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_and_wallet_validation_reject_credential_or_remote_input() {
        assert!(validate_endpoint("http://127.0.0.1:18443/").is_ok());
        assert!(validate_endpoint("http://user:secret@127.0.0.1:18443/").is_err());
        assert!(validate_endpoint("https://127.0.0.1:18443/").is_err());
        assert!(validate_endpoint("http://localhost:18443/").is_err());
        assert!(validate_endpoint("http://192.0.2.1:18443/").is_err());
        assert!(validate_wallet_name("f7-wallet").is_ok());
        assert!(validate_wallet_name(".").is_err());
        assert!(validate_wallet_name("..").is_err());
        assert!(validate_wallet_name("../wallet").is_err());
    }

    #[test]
    fn hash_and_hex_codecs_are_strict_and_canonical() {
        let internal = [0x11; 32];
        let display = display_txid(internal);
        assert_eq!(parse_txid_internal(&display), Ok(internal));
        assert_eq!(decode_hex_bounded("00a1ff", 3), Ok(vec![0, 0xa1, 0xff]));
        assert!(decode_hex_bounded("A1", 1).is_err());
        assert!(decode_hex_bounded("0000", 1).is_err());
        assert_eq!(encode_hex(&[0, 0xa1, 0xff]), "00a1ff");
    }

    #[test]
    fn network_identity_requires_exact_signet_challenge_classification() {
        assert_eq!(
            expected_signet_challenge(BitcoinCoreNetworkV1::Regtest, None),
            Ok(None)
        );
        let public = expected_signet_challenge(BitcoinCoreNetworkV1::PublicSignet, None);
        assert!(public.is_ok());
        assert!(expected_signet_challenge(
            BitcoinCoreNetworkV1::CustomSignet,
            public.ok().flatten(),
        )
        .is_err());
        assert_eq!(
            expected_signet_challenge(BitcoinCoreNetworkV1::CustomSignet, Some(vec![0x51]),),
            Ok(Some(vec![0x51]))
        );
        assert!(expected_signet_challenge(BitcoinCoreNetworkV1::CustomSignet, None).is_err());
        assert!(
            expected_signet_challenge(BitcoinCoreNetworkV1::Regtest, Some(vec![0x51]),).is_err()
        );
    }
}
