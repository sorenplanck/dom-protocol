//! Canonical owner-only network sidecar for the two production Relay links.
//!
//! This document is deliberately separate from the frozen bootstrap families.
//! It does not extend any bootstrap manifest and carries no credential,
//! hostname, or private key.
//! Each named route position binds one numeric socket address, the socket
//! operation performed by this process, the resulting Noise XX role, and the
//! exact public identity of the peer's durable Relay database.

use std::net::SocketAddr;
use std::path::Path;

use dom_scriptless_transport::NoiseRoleV1;
use relay::production::RelayDatabaseIdV1;

use crate::production_config::{
    config_digest, decode_digest, encode_hex, read_owner_file_bounded, validate_state_dir,
    ProductionConfigErrorV1,
};

const HEADER_V1: &str = "DOM-INTEROPD-PRODUCTION-RELAY-NETWORK-V1";
const END_V1: &str = "END-DOM-INTEROPD-PRODUCTION-RELAY-NETWORK-V1";
const DIGEST_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/PRODUCTION-RELAY-NETWORK/V1\0";
const LINE_COUNT_V1: usize = 9;
const MAX_SOCKET_ADDRESS_BYTES_V1: usize = 64;

/// Fixed state-directory leaf of the V1 Relay network sidecar.
pub use crate::production_config::PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1;

/// Maximum accepted encoded sidecar size, checked before allocation.
pub const MAX_PRODUCTION_RELAY_NETWORK_CONFIG_BYTES_V1: u64 = 1_024;

/// Redacted refusal from the production Relay network configuration boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionRelayNetworkConfigErrorV1 {
    /// The fixed owner-only document could not be read safely.
    #[error("production Relay network configuration unavailable")]
    Unavailable,
    /// The document is not the one exact canonical V1 encoding.
    #[error("production Relay network configuration is not canonical")]
    InvalidEncoding,
    /// A socket endpoint or peer database binding is not safe or distinct.
    #[error("production Relay network link binding is invalid")]
    InvalidLink,
    /// The named peer database identities disagree with authenticated inputs.
    #[error("production Relay network peer binding mismatch")]
    PeerBindingMismatch,
}

/// Which named route position owns a Relay network link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionRelayLinkPositionV1 {
    /// The upstream route position.
    Upstream,
    /// The downstream route position.
    Downstream,
}

/// TCP operation performed by this process for one Relay link.
///
/// The operation is also the sole authority for the Noise role. Callers must
/// not accept an independent role field from configuration or ambient state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionRelayEndpointModeV1 {
    /// Connect to the configured peer and initiate Noise XX.
    Connect,
    /// Bind the configured local address and respond to Noise XX.
    Listen,
}

impl ProductionRelayEndpointModeV1 {
    /// Exact Noise XX role implied by this endpoint operation.
    pub const fn noise_role(self) -> NoiseRoleV1 {
        match self {
            Self::Connect => NoiseRoleV1::Initiator,
            Self::Listen => NoiseRoleV1::Responder,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Listen => "listen",
        }
    }

    fn parse(value: &str) -> Result<Self, ProductionRelayNetworkConfigErrorV1> {
        match value {
            "connect" => Ok(Self::Connect),
            "listen" => Ok(Self::Listen),
            _ => Err(ProductionRelayNetworkConfigErrorV1::InvalidEncoding),
        }
    }
}

/// One exact named link in the two-link network sidecar.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionRelayNetworkLinkV1 {
    mode: ProductionRelayEndpointModeV1,
    address: SocketAddr,
    remote_relay_database_id: RelayDatabaseIdV1,
}

impl ProductionRelayNetworkLinkV1 {
    /// Builds one link from a numeric socket address and non-null peer ID.
    pub fn new(
        mode: ProductionRelayEndpointModeV1,
        address: SocketAddr,
        remote_relay_database_id: RelayDatabaseIdV1,
    ) -> Result<Self, ProductionRelayNetworkConfigErrorV1> {
        let rendered = address.to_string();
        if address.port() == 0
            || address.ip().is_multicast()
            || (mode == ProductionRelayEndpointModeV1::Connect && address.ip().is_unspecified())
            || rendered.is_empty()
            || rendered.len() > MAX_SOCKET_ADDRESS_BYTES_V1
            || !rendered.is_ascii()
        {
            return Err(ProductionRelayNetworkConfigErrorV1::InvalidLink);
        }
        Ok(Self {
            mode,
            address,
            remote_relay_database_id,
        })
    }

    /// Socket operation configured for this link.
    pub const fn mode(&self) -> ProductionRelayEndpointModeV1 {
        self.mode
    }

    /// Canonical numeric socket address. DNS is never consulted by this codec.
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Exact public identity expected from the remote durable Relay database.
    pub const fn remote_relay_database_id(&self) -> RelayDatabaseIdV1 {
        self.remote_relay_database_id
    }

    /// Noise role derived from [`Self::mode`].
    pub const fn noise_role(&self) -> NoiseRoleV1 {
        self.mode.noise_role()
    }
}

/// Canonical V1 sidecar binding exactly the upstream and downstream links.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionRelayNetworkConfigV1 {
    upstream: ProductionRelayNetworkLinkV1,
    downstream: ProductionRelayNetworkLinkV1,
}

impl ProductionRelayNetworkConfigV1 {
    /// Creates the exact two-link document. Peer databases must be distinct so
    /// neither route position can silently alias the other. Addresses may be
    /// equal because one peer service may accept multiple authenticated links.
    pub fn new(
        upstream: ProductionRelayNetworkLinkV1,
        downstream: ProductionRelayNetworkLinkV1,
    ) -> Result<Self, ProductionRelayNetworkConfigErrorV1> {
        if upstream.remote_relay_database_id == downstream.remote_relay_database_id {
            return Err(ProductionRelayNetworkConfigErrorV1::InvalidLink);
        }
        Ok(Self {
            upstream,
            downstream,
        })
    }

    /// Returns the link for one named route position.
    pub const fn link(
        &self,
        position: ProductionRelayLinkPositionV1,
    ) -> &ProductionRelayNetworkLinkV1 {
        match position {
            ProductionRelayLinkPositionV1::Upstream => &self.upstream,
            ProductionRelayLinkPositionV1::Downstream => &self.downstream,
        }
    }

    /// Cross-checks the named peer identities against an authenticated source.
    ///
    /// The future socket/session factory must perform this check before opening
    /// either link. In particular, two valid peer IDs exchanged between the
    /// upstream and downstream positions are refused rather than reinterpreted.
    pub fn validate_remote_database_ids(
        &self,
        expected_upstream: RelayDatabaseIdV1,
        expected_downstream: RelayDatabaseIdV1,
    ) -> Result<(), ProductionRelayNetworkConfigErrorV1> {
        if expected_upstream == expected_downstream
            || self.upstream.remote_relay_database_id != expected_upstream
            || self.downstream.remote_relay_database_id != expected_downstream
        {
            return Err(ProductionRelayNetworkConfigErrorV1::PeerBindingMismatch);
        }
        Ok(())
    }

    /// Refuses a peer link that aliases the V8-authenticated local Relay DB.
    pub fn validate_local_database_id(
        &self,
        local: RelayDatabaseIdV1,
    ) -> Result<(), ProductionRelayNetworkConfigErrorV1> {
        if self.upstream.remote_relay_database_id == local
            || self.downstream.remote_relay_database_id == local
        {
            return Err(ProductionRelayNetworkConfigErrorV1::PeerBindingMismatch);
        }
        Ok(())
    }

    /// Exact canonical bytes, including the domain-bound integrity digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionRelayNetworkConfigErrorV1> {
        let body = self.canonical_body();
        let digest = relay_network_digest(body.as_bytes())?;
        let encoded = format!("{body}config_digest={}\n{END_V1}\n", encode_hex(&digest));
        if encoded.len() as u64 > MAX_PRODUCTION_RELAY_NETWORK_CONFIG_BYTES_V1 {
            return Err(ProductionRelayNetworkConfigErrorV1::InvalidEncoding);
        }
        Ok(encoded.into_bytes())
    }

    /// Decodes only the byte-exact, ordered, domain-bound V1 spelling.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProductionRelayNetworkConfigErrorV1> {
        if bytes.is_empty()
            || bytes.len() as u64 > MAX_PRODUCTION_RELAY_NETWORK_CONFIG_BYTES_V1
            || !bytes.is_ascii()
            || bytes.last() != Some(&b'\n')
            || bytes.contains(&b'\r')
        {
            return Err(ProductionRelayNetworkConfigErrorV1::InvalidEncoding);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ProductionRelayNetworkConfigErrorV1::InvalidEncoding)?;
        let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
        if lines.len() != LINE_COUNT_V1 || lines.first() != Some(&HEADER_V1) {
            return Err(ProductionRelayNetworkConfigErrorV1::InvalidEncoding);
        }

        let upstream = decode_link(&lines, 1, "upstream")?;
        let downstream = decode_link(&lines, 4, "downstream")?;
        let supplied_digest = decode_digest(take_value(&lines, 7, "config_digest")?)
            .map_err(|_| ProductionRelayNetworkConfigErrorV1::InvalidEncoding)?;
        if lines.get(8) != Some(&END_V1) {
            return Err(ProductionRelayNetworkConfigErrorV1::InvalidEncoding);
        }

        let config = Self::new(upstream, downstream)?;
        let body = config.canonical_body();
        if relay_network_digest(body.as_bytes())? != supplied_digest
            || config.canonical_bytes()?.as_slice() != bytes
        {
            return Err(ProductionRelayNetworkConfigErrorV1::InvalidEncoding);
        }
        Ok(config)
    }

    fn canonical_body(&self) -> String {
        format!(
            "{HEADER_V1}\nupstream_mode={}\nupstream_address={}\nupstream_remote_relay_database_id={}\ndownstream_mode={}\ndownstream_address={}\ndownstream_remote_relay_database_id={}\n",
            self.upstream.mode.as_str(),
            self.upstream.address,
            encode_hex(self.upstream.remote_relay_database_id.as_bytes()),
            self.downstream.mode.as_str(),
            self.downstream.address,
            encode_hex(self.downstream.remote_relay_database_id.as_bytes()),
        )
    }
}

/// Loads the one fixed-name V1 sidecar under an absolute owner-only state root.
pub fn load_production_relay_network_config_v1(
    state_dir: &Path,
) -> Result<ProductionRelayNetworkConfigV1, ProductionRelayNetworkConfigErrorV1> {
    let state_dir = validate_state_dir(state_dir)
        .map_err(|_| ProductionRelayNetworkConfigErrorV1::Unavailable)?;
    let bytes = read_owner_file_bounded(
        &state_dir.join(PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1),
        MAX_PRODUCTION_RELAY_NETWORK_CONFIG_BYTES_V1,
        ProductionConfigErrorV1::InputArtifactUnavailable,
    )
    .map_err(|_| ProductionRelayNetworkConfigErrorV1::Unavailable)?;
    ProductionRelayNetworkConfigV1::decode_canonical(&bytes)
}

fn decode_link(
    lines: &[&str],
    first_index: usize,
    prefix: &str,
) -> Result<ProductionRelayNetworkLinkV1, ProductionRelayNetworkConfigErrorV1> {
    let mode_key = format!("{prefix}_mode");
    let address_key = format!("{prefix}_address");
    let database_key = format!("{prefix}_remote_relay_database_id");
    let mode = ProductionRelayEndpointModeV1::parse(take_value(lines, first_index, &mode_key)?)?;
    let address_text = take_value(lines, first_index + 1, &address_key)?;
    if address_text.len() > MAX_SOCKET_ADDRESS_BYTES_V1 {
        return Err(ProductionRelayNetworkConfigErrorV1::InvalidEncoding);
    }
    let address = address_text
        .parse::<SocketAddr>()
        .map_err(|_| ProductionRelayNetworkConfigErrorV1::InvalidEncoding)?;
    if address.to_string() != address_text {
        return Err(ProductionRelayNetworkConfigErrorV1::InvalidEncoding);
    }
    let database_bytes = decode_digest(take_value(lines, first_index + 2, &database_key)?)
        .map_err(|_| ProductionRelayNetworkConfigErrorV1::InvalidEncoding)?;
    let database = RelayDatabaseIdV1::new(database_bytes)
        .map_err(|_| ProductionRelayNetworkConfigErrorV1::InvalidLink)?;
    ProductionRelayNetworkLinkV1::new(mode, address, database)
}

fn take_value<'a>(
    lines: &'a [&str],
    index: usize,
    key: &str,
) -> Result<&'a str, ProductionRelayNetworkConfigErrorV1> {
    let line = lines
        .get(index)
        .ok_or(ProductionRelayNetworkConfigErrorV1::InvalidEncoding)?;
    let (actual_key, value) = line
        .split_once('=')
        .ok_or(ProductionRelayNetworkConfigErrorV1::InvalidEncoding)?;
    if actual_key != key || value.is_empty() || value.contains('=') {
        return Err(ProductionRelayNetworkConfigErrorV1::InvalidEncoding);
    }
    Ok(value)
}

fn relay_network_digest(body: &[u8]) -> Result<[u8; 32], ProductionRelayNetworkConfigErrorV1> {
    let mut domain_bound = Vec::with_capacity(DIGEST_DOMAIN_V1.len() + body.len());
    domain_bound.extend_from_slice(DIGEST_DOMAIN_V1);
    domain_bound.extend_from_slice(body);
    config_digest(&domain_bound).map_err(|_| ProductionRelayNetworkConfigErrorV1::InvalidEncoding)
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{symlink, OpenOptionsExt as _, PermissionsExt as _};

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn database(marker: u8) -> Result<RelayDatabaseIdV1, Box<dyn std::error::Error>> {
        Ok(RelayDatabaseIdV1::new([marker; 32])?)
    }

    fn fixture() -> Result<ProductionRelayNetworkConfigV1, Box<dyn std::error::Error>> {
        Ok(ProductionRelayNetworkConfigV1::new(
            ProductionRelayNetworkLinkV1::new(
                ProductionRelayEndpointModeV1::Connect,
                "127.0.0.1:41001".parse()?,
                database(0xa1)?,
            )?,
            ProductionRelayNetworkLinkV1::new(
                ProductionRelayEndpointModeV1::Listen,
                "[::1]:41002".parse()?,
                database(0xb2)?,
            )?,
        )?)
    }

    fn write_owner_config(
        directory: &Path,
        bytes: &[u8],
    ) -> Result<std::path::PathBuf, std::io::Error> {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
        let path = directory.join(PRODUCTION_RELAY_NETWORK_CONFIG_FILE_V1);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(path)
    }

    fn encode_body(body: &str) -> Result<Vec<u8>, ProductionRelayNetworkConfigErrorV1> {
        let digest = relay_network_digest(body.as_bytes())?;
        Ok(format!("{body}config_digest={}\n{END_V1}\n", encode_hex(&digest)).into_bytes())
    }

    #[test]
    fn canonical_restart_load_is_byte_exact() -> TestResult {
        let directory = tempfile::tempdir()?;
        let expected = fixture()?;
        let encoded = expected.canonical_bytes()?;
        let _path = write_owner_config(directory.path(), &encoded)?;
        let first = load_production_relay_network_config_v1(directory.path())?;
        let second = load_production_relay_network_config_v1(directory.path())?;
        assert_eq!(first, expected);
        assert_eq!(second, first);
        assert_eq!(second.canonical_bytes()?, encoded);
        Ok(())
    }

    #[test]
    fn truncated_trailing_and_noncanonical_address_bytes_are_refused() -> TestResult {
        let encoded = fixture()?.canonical_bytes()?;
        for length in [0, 1, encoded.len() - 1] {
            assert!(ProductionRelayNetworkConfigV1::decode_canonical(&encoded[..length]).is_err());
        }
        let mut trailing = encoded;
        trailing.extend_from_slice(b"extra\n");
        assert_eq!(
            ProductionRelayNetworkConfigV1::decode_canonical(&trailing).err(),
            Some(ProductionRelayNetworkConfigErrorV1::InvalidEncoding)
        );

        let body = fixture()?.canonical_body().replace(
            "downstream_address=[::1]:41002",
            "downstream_address=[0:0:0:0:0:0:0:1]:41002",
        );
        let noncanonical = encode_body(&body)?;
        assert_eq!(
            ProductionRelayNetworkConfigV1::decode_canonical(&noncanonical).err(),
            Some(ProductionRelayNetworkConfigErrorV1::InvalidEncoding)
        );
        Ok(())
    }

    #[test]
    fn duplicate_and_position_swapped_peer_database_ids_are_refused() -> TestResult {
        let expected_upstream = database(0xa1)?;
        let expected_downstream = database(0xb2)?;
        let duplicate_body = fixture()?.canonical_body().replace(
            &encode_hex(expected_downstream.as_bytes()),
            &encode_hex(expected_upstream.as_bytes()),
        );
        assert_eq!(
            ProductionRelayNetworkConfigV1::decode_canonical(&encode_body(&duplicate_body)?).err(),
            Some(ProductionRelayNetworkConfigErrorV1::InvalidLink)
        );

        let swapped = ProductionRelayNetworkConfigV1::new(
            ProductionRelayNetworkLinkV1::new(
                ProductionRelayEndpointModeV1::Connect,
                "127.0.0.1:41001".parse()?,
                expected_downstream,
            )?,
            ProductionRelayNetworkLinkV1::new(
                ProductionRelayEndpointModeV1::Listen,
                "[::1]:41002".parse()?,
                expected_upstream,
            )?,
        )?;
        assert_eq!(
            swapped
                .validate_remote_database_ids(expected_upstream, expected_downstream)
                .err(),
            Some(ProductionRelayNetworkConfigErrorV1::PeerBindingMismatch)
        );
        assert!(fixture()?
            .validate_remote_database_ids(expected_upstream, expected_downstream)
            .is_ok());
        Ok(())
    }

    #[test]
    fn endpoint_mode_is_the_only_noise_role_authority() -> TestResult {
        assert_eq!(
            ProductionRelayEndpointModeV1::Connect.noise_role(),
            NoiseRoleV1::Initiator
        );
        assert_eq!(
            ProductionRelayEndpointModeV1::Listen.noise_role(),
            NoiseRoleV1::Responder
        );
        let config = fixture()?;
        assert_eq!(
            config
                .link(ProductionRelayLinkPositionV1::Upstream)
                .noise_role(),
            NoiseRoleV1::Initiator
        );
        assert_eq!(
            config
                .link(ProductionRelayLinkPositionV1::Downstream)
                .noise_role(),
            NoiseRoleV1::Responder
        );
        assert!(ProductionRelayNetworkLinkV1::new(
            ProductionRelayEndpointModeV1::Connect,
            "0.0.0.0:41003".parse()?,
            database(0xc3)?,
        )
        .is_err());
        assert!(ProductionRelayNetworkLinkV1::new(
            ProductionRelayEndpointModeV1::Listen,
            "0.0.0.0:41003".parse()?,
            database(0xc3)?,
        )
        .is_ok());
        assert!(config.validate_local_database_id(database(0xc3)?).is_ok());
        assert_eq!(
            config.validate_local_database_id(database(0xa1)?).err(),
            Some(ProductionRelayNetworkConfigErrorV1::PeerBindingMismatch)
        );
        Ok(())
    }

    #[test]
    fn weak_modes_symlink_and_hardlink_are_refused() -> TestResult {
        let directory = tempfile::tempdir()?;
        let encoded = fixture()?.canonical_bytes()?;
        let path = write_owner_config(directory.path(), &encoded)?;

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert_eq!(
            load_production_relay_network_config_v1(directory.path()).err(),
            Some(ProductionRelayNetworkConfigErrorV1::Unavailable)
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))?;
        assert_eq!(
            load_production_relay_network_config_v1(directory.path()).err(),
            Some(ProductionRelayNetworkConfigErrorV1::Unavailable)
        );
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;

        let hardlink = directory.path().join("network-hardlink");
        fs::hard_link(&path, &hardlink)?;
        assert_eq!(
            load_production_relay_network_config_v1(directory.path()).err(),
            Some(ProductionRelayNetworkConfigErrorV1::Unavailable)
        );
        fs::remove_file(hardlink)?;

        fs::remove_file(&path)?;
        let target = directory.path().join("network-target");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(&target)?;
        file.write_all(&encoded)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        symlink(&target, &path)?;
        assert_eq!(
            load_production_relay_network_config_v1(directory.path()).err(),
            Some(ProductionRelayNetworkConfigErrorV1::Unavailable)
        );
        Ok(())
    }
}
