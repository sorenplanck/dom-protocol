//! Node-global configuration for the one real DOM node.
//!
//! This module is deliberately independent from the per-route bootstrap. A
//! route manifest freezes public identities, commitments and relative path
//! references and, by construction, has no endpoint or credential escape
//! hatch. Endpoint, frozen node identity, bounded timings and the sealed
//! bearer descriptor are properties of the node, not of a route, so they live
//! in one separate artifact resolved under the same trusted state directory by
//! a fixed name.
//!
//! The manifest never carries the credential and never names a descriptor: the
//! bearer material arrives out of band on standard input. Nothing here logs,
//! formats or stores that material.
//!
//! # Supervisor contract
//!
//! The supervisor creates a pipe, makes its read end the daemon's standard
//! input, writes the exact versioned credential stream described below and
//! then closes its write end. Closing that end is what produces the end of
//! input this boundary requires. The daemon reads exactly once.
//!
//! V1 contains exactly eight credentials and seven field separators. V2 adds
//! exactly one local EVM signing key and one separator. The strict live-run V3
//! adds a literal version header plus nonzero bounded upstream/downstream F6
//! HSM credential groups. No family permits a trailing newline. A shell `echo`
//! appends one and is refused by name; `printf` does not.
//!
//! Standard input must never be a terminal, which is the one shape refused by
//! name. A regular file is accepted, but only when it is delivered by
//! systemd's `LoadCredential=` (a tmpfs file, mode 0400, owned by the unit's
//! user, unlinked when the unit stops) or by shell process substitution. A
//! credential on persistent disk is never acceptable. Refusing regular files
//! outright was considered and rejected: it would eliminate `LoadCredential=`,
//! the safest mechanism available, and push operators toward worse shapes.
//!
//! `StandardInput=fd:<name>` is deliberately not recommended: it requires
//! socket activation with named descriptors, which introduces a socket unit
//! whose only purpose is to carry a secret.
//!
//! A pipe is preferred over a sealed anonymous memory file: after end of input
//! no kernel-side copy of the material survives, the writer is proven to be the
//! process that started the daemon, and there is no descriptor to re-open and
//! therefore no time-of-check/time-of-use window. It also avoids `unsafe`,
//! which this crate forbids, since nothing has to adopt or close an inherited
//! raw descriptor.
//!
//! # The one failure with no named error
//!
//! If the pipe's write end leaks into the child — a missing `CLOEXEC`, or a
//! careless `dup2` — then the daemon itself holds that end open, end of input
//! never arrives, and startup blocks forever. That is a hang, not a refusal:
//! no error variant covers it, because nothing has gone wrong that this
//! boundary can observe. The supervisor must close the write end in the child
//! before `exec`, and close its own copy after writing.
//!
use std::path::Path;

use zeroize::Zeroizing;

use crate::production_config::{
    config_digest, decode_digest, encode_hex, read_owner_file_bounded, take_value,
    validate_state_dir, ProductionConfigErrorV1, PRODUCTION_NODE_CONFIG_FILE_V1,
};

/// Maximum accepted node manifest size, checked before allocation.
pub const MAX_PRODUCTION_NODE_CONFIG_BYTES_V1: u64 = 4 * 1024;
/// Maximum accepted DOM RPC endpoint length.
///
/// Deliberately the same 2048 the client constructor enforces
/// (`dom-scriptless-chain-adapter`, `DomHttpChainAdapterV1::new`). The value is
/// duplicated rather than imported so this module stays compilable without the
/// production graph; the two must be changed together, and
/// `endpoint_prefilter_and_client_agree_on_the_canonical_table` is what keeps
/// them honest.
pub const MAX_DOM_NODE_ENDPOINT_BYTES_V1: usize = 2048;
/// Maximum accepted DOM network label length.
pub const MAX_DOM_NODE_NETWORK_BYTES_V1: usize = 16;
/// Maximum accepted sealed bearer material length.
pub const MAX_DOM_NODE_BEARER_BYTES_V1: usize = 4096;

const HEADER_NODE_V1: &str = "DOM-INTEROPD-NODE-V1";
const END_NODE_V1: &str = "end=1";
const NODE_DIGEST_DOMAIN_V1: &[u8] = b"DOM-INTEROPD/NODE-CONFIG/V1\0";
const NODE_CONFIG_LINES_V1: usize = 13;
const MIN_NODE_TIMEOUT_MS_V1: u64 = 1_000;
const MAX_NODE_TIMEOUT_MS_V1: u64 = 60_000;
const MIN_NODE_HISTORY_LIMIT_V1: u64 = 1;
const MAX_NODE_HISTORY_LIMIT_V1: u64 = 1_048_576;

/// One syntactically validated DOM RPC endpoint.
///
/// The authority on scheme, host and loopback policy remains
/// `DomHttpChainAdapterV1::new`; this type refuses the malformed shapes early,
/// before any client is built, and never widens what that constructor accepts.
#[derive(Clone, Eq, PartialEq)]
pub struct DomNodeEndpointV1 {
    endpoint: String,
}

impl core::fmt::Debug for DomNodeEndpointV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("DomNodeEndpointV1")
            .field("origin", &self.origin())
            .finish_non_exhaustive()
    }
}

impl DomNodeEndpointV1 {
    /// Accepts only a bounded, printable absolute endpoint with no userinfo,
    /// query or fragment, and only loopback authorities for plain `http`.
    pub fn new(endpoint: &str) -> Result<Self, ProductionConfigErrorV1> {
        if endpoint.is_empty()
            || endpoint.len() > MAX_DOM_NODE_ENDPOINT_BYTES_V1
            || !endpoint.is_ascii()
            || endpoint
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
            || endpoint.contains('@')
            || endpoint.contains('?')
            || endpoint.contains('#')
            || endpoint.contains('\\')
        {
            return Err(ProductionConfigErrorV1::InvalidNodeEndpoint);
        }
        let (scheme, rest) = if let Some(rest) = endpoint.strip_prefix("https://") {
            ("https", rest)
        } else if let Some(rest) = endpoint.strip_prefix("http://") {
            ("http", rest)
        } else {
            return Err(ProductionConfigErrorV1::InvalidNodeEndpoint);
        };
        let authority = rest.split('/').next().unwrap_or_default();
        if authority.is_empty() {
            return Err(ProductionConfigErrorV1::InvalidNodeEndpoint);
        }
        if scheme == "http" && !authority_is_loopback(authority) {
            return Err(ProductionConfigErrorV1::InvalidNodeEndpoint);
        }
        Ok(Self {
            endpoint: endpoint.to_owned(),
        })
    }

    /// Exact validated endpoint.
    pub fn as_str(&self) -> &str {
        &self.endpoint
    }

    /// Scheme and authority only, for redacted diagnostics.
    fn origin(&self) -> &str {
        let after_scheme = self
            .endpoint
            .find("://")
            .map_or(self.endpoint.len(), |index| index + 3);
        let tail = &self.endpoint[after_scheme..];
        let end = tail.find('/').map_or(self.endpoint.len(), |index| {
            after_scheme.saturating_add(index)
        });
        &self.endpoint[..end]
    }
}

fn authority_is_loopback(authority: &str) -> bool {
    let host = match authority.strip_prefix('[') {
        Some(rest) => match rest.split_once(']') {
            Some((inside, _port)) => inside,
            None => return false,
        },
        None => authority.split(':').next().unwrap_or_default(),
    };
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// Frozen node-global configuration for the real DOM node.
///
/// It holds no credential and names no descriptor: the bearer material arrives
/// out of band on standard input and is never referenced from this manifest.
#[derive(Clone, Eq, PartialEq)]
pub struct ProductionNodeConfigV1 {
    endpoint: DomNodeEndpointV1,
    network: String,
    network_magic: u32,
    chain_id: [u8; 32],
    genesis_hash: [u8; 32],
    protocol_version: u32,
    range_proof_serialization_version: u8,
    connect_timeout_ms: u64,
    request_timeout_ms: u64,
    history_limit: usize,
}

/// Public, non-secret identity asserted for one exact DOM node deployment.
///
/// Keeping these mutually dependent fields in one value prevents callers from
/// accidentally assembling a configuration from identities belonging to
/// different networks while also keeping the constructor surface auditable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionNodeIdentityV1 {
    pub network: String,
    pub network_magic: u32,
    pub chain_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub protocol_version: u32,
    pub range_proof_serialization_version: u8,
}

impl core::fmt::Debug for ProductionNodeConfigV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProductionNodeConfigV1")
            .field("origin", &self.endpoint.origin())
            .field("network", &self.network)
            .finish_non_exhaustive()
    }
}

impl ProductionNodeConfigV1 {
    /// Builds a canonical node configuration from already public parts.
    pub fn from_parts(
        endpoint: DomNodeEndpointV1,
        identity: ProductionNodeIdentityV1,
        bounds: ProductionNodeBoundsV1,
    ) -> Result<Self, ProductionConfigErrorV1> {
        let ProductionNodeIdentityV1 {
            network,
            network_magic,
            chain_id,
            genesis_hash,
            protocol_version,
            range_proof_serialization_version,
        } = identity;
        validate_network_label(&network)?;
        if chain_id == [0; 32] || genesis_hash == [0; 32] {
            return Err(ProductionConfigErrorV1::InvalidNodeIdentity);
        }
        let ProductionNodeBoundsV1 {
            connect_timeout_ms,
            request_timeout_ms,
            history_limit,
        } = bounds.validate()?;
        Ok(Self {
            endpoint,
            network,
            network_magic,
            chain_id,
            genesis_hash,
            protocol_version,
            range_proof_serialization_version,
            connect_timeout_ms,
            request_timeout_ms,
            history_limit: usize::try_from(history_limit)
                .map_err(|_| ProductionConfigErrorV1::InvalidNodeBounds)?,
        })
    }

    /// Validated DOM RPC endpoint.
    pub fn endpoint(&self) -> &DomNodeEndpointV1 {
        &self.endpoint
    }

    /// Frozen lowercase network label.
    pub fn network(&self) -> &str {
        &self.network
    }

    /// Bounded scanner history retained by the runtime.
    pub const fn history_limit(&self) -> usize {
        self.history_limit
    }

    /// Bounded connect timeout.
    pub const fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
    }

    /// Bounded request timeout.
    pub const fn request_timeout_ms(&self) -> u64 {
        self.request_timeout_ms
    }

    /// Returns exact canonical bytes, including the integrity digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProductionConfigErrorV1> {
        let body = self.canonical_body();
        let digest = config_digest_node(body.as_bytes())?;
        let mut encoded = body;
        encoded.push_str("config_digest=");
        encoded.push_str(&encode_hex(&digest));
        encoded.push('\n');
        encoded.push_str(END_NODE_V1);
        encoded.push('\n');
        if encoded.len() as u64 > MAX_PRODUCTION_NODE_CONFIG_BYTES_V1 {
            return Err(ProductionConfigErrorV1::NodeConfigUnavailable);
        }
        Ok(encoded.into_bytes())
    }

    /// Decodes only the exact canonical node bytes. Unknown keys, alternate
    /// order, non-canonical numbers, trailing bytes and digest drift are all
    /// rejected.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProductionConfigErrorV1> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_PRODUCTION_NODE_CONFIG_BYTES_V1 {
            return Err(ProductionConfigErrorV1::NodeConfigUnavailable);
        }
        if !bytes.is_ascii() || bytes.last() != Some(&b'\n') || bytes.contains(&b'\r') {
            return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ProductionConfigErrorV1::InvalidCanonicalEncoding)?;
        let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
        if lines.len() != NODE_CONFIG_LINES_V1 || lines.first() != Some(&HEADER_NODE_V1) {
            return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
        }
        let mut cursor = 1;
        let endpoint = DomNodeEndpointV1::new(take_value(&lines, &mut cursor, "dom_endpoint")?)?;
        let network = take_value(&lines, &mut cursor, "dom_network")?.to_owned();
        let network_magic = take_bounded_number(&lines, &mut cursor, "dom_network_magic")?;
        let chain_id = decode_digest(take_value(&lines, &mut cursor, "dom_chain_id")?)?;
        let genesis_hash = decode_digest(take_value(&lines, &mut cursor, "dom_genesis_hash")?)?;
        let protocol_version = take_bounded_number(&lines, &mut cursor, "dom_protocol_version")?;
        let range_proof_serialization_version =
            take_bounded_number(&lines, &mut cursor, "dom_range_proof_serialization_version")?;
        let connect_timeout_ms =
            take_bounded_number(&lines, &mut cursor, "dom_connect_timeout_ms")?;
        let request_timeout_ms =
            take_bounded_number(&lines, &mut cursor, "dom_request_timeout_ms")?;
        let history_limit = take_bounded_number(&lines, &mut cursor, "dom_history_limit")?;
        let supplied_digest = decode_digest(take_value(&lines, &mut cursor, "config_digest")?)?;
        if lines.get(cursor) != Some(&END_NODE_V1) || cursor + 1 != lines.len() {
            return Err(ProductionConfigErrorV1::InvalidCanonicalEncoding);
        }
        let config = Self::from_parts(
            endpoint,
            ProductionNodeIdentityV1 {
                network,
                network_magic: u32::try_from(network_magic)
                    .map_err(|_| ProductionConfigErrorV1::InvalidNodeIdentity)?,
                chain_id,
                genesis_hash,
                protocol_version: u32::try_from(protocol_version)
                    .map_err(|_| ProductionConfigErrorV1::InvalidNodeIdentity)?,
                range_proof_serialization_version: u8::try_from(range_proof_serialization_version)
                    .map_err(|_| ProductionConfigErrorV1::InvalidNodeIdentity)?,
            },
            ProductionNodeBoundsV1 {
                connect_timeout_ms,
                request_timeout_ms,
                history_limit,
            },
        )?;
        let body = config.canonical_body();
        if config_digest_node(body.as_bytes())? != supplied_digest
            || config.canonical_bytes()?.as_slice() != bytes
        {
            return Err(ProductionConfigErrorV1::IntegrityMismatch);
        }
        Ok(config)
    }

    fn canonical_body(&self) -> String {
        // Built with infallible `push_str` only: this boundary adds no new
        // `expect` site to the reviewed production inventory.
        let mut body = String::new();
        body.push_str(HEADER_NODE_V1);
        body.push('\n');
        push_text(&mut body, "dom_endpoint", self.endpoint.as_str());
        push_text(&mut body, "dom_network", &self.network);
        push_number(
            &mut body,
            "dom_network_magic",
            u64::from(self.network_magic),
        );
        push_text(&mut body, "dom_chain_id", &encode_hex(&self.chain_id));
        push_text(
            &mut body,
            "dom_genesis_hash",
            &encode_hex(&self.genesis_hash),
        );
        push_number(
            &mut body,
            "dom_protocol_version",
            u64::from(self.protocol_version),
        );
        push_number(
            &mut body,
            "dom_range_proof_serialization_version",
            u64::from(self.range_proof_serialization_version),
        );
        push_number(&mut body, "dom_connect_timeout_ms", self.connect_timeout_ms);
        push_number(&mut body, "dom_request_timeout_ms", self.request_timeout_ms);
        push_number(&mut body, "dom_history_limit", self.history_limit as u64);
        body
    }
}

/// Bounded node-global timings, scanner history and sealed descriptor number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionNodeBoundsV1 {
    /// Connect timeout in milliseconds.
    pub connect_timeout_ms: u64,
    /// Request timeout in milliseconds; never smaller than the connect bound.
    pub request_timeout_ms: u64,
    /// Bounded scanner history retained by the runtime.
    pub history_limit: u64,
}

impl ProductionNodeBoundsV1 {
    fn validate(self) -> Result<Self, ProductionConfigErrorV1> {
        if !(MIN_NODE_TIMEOUT_MS_V1..=MAX_NODE_TIMEOUT_MS_V1).contains(&self.connect_timeout_ms)
            || !(MIN_NODE_TIMEOUT_MS_V1..=MAX_NODE_TIMEOUT_MS_V1).contains(&self.request_timeout_ms)
            || self.connect_timeout_ms > self.request_timeout_ms
            || !(MIN_NODE_HISTORY_LIMIT_V1..=MAX_NODE_HISTORY_LIMIT_V1)
                .contains(&self.history_limit)
        {
            return Err(ProductionConfigErrorV1::InvalidNodeBounds);
        }
        Ok(self)
    }
}

/// Loads the node-global configuration from its fixed name under the same
/// trusted state directory. No path is ever chosen by a caller.
pub fn load_production_node_config_v1(
    state_dir: &Path,
) -> Result<ProductionNodeConfigV1, ProductionConfigErrorV1> {
    let canonical_state = validate_state_dir(state_dir)?;
    let bytes = read_owner_file_bounded(
        &canonical_state.join(PRODUCTION_NODE_CONFIG_FILE_V1),
        MAX_PRODUCTION_NODE_CONFIG_BYTES_V1,
        ProductionConfigErrorV1::NodeConfigUnavailable,
    )?;
    ProductionNodeConfigV1::decode_canonical(&bytes)
}

fn validate_network_label(label: &str) -> Result<(), ProductionConfigErrorV1> {
    if label.is_empty()
        || label.len() > MAX_DOM_NODE_NETWORK_BYTES_V1
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(ProductionConfigErrorV1::InvalidNodeIdentity);
    }
    Ok(())
}

fn push_text(body: &mut String, key: &str, value: &str) {
    body.push_str(key);
    body.push('=');
    body.push_str(value);
    body.push('\n');
}

fn push_number(body: &mut String, key: &str, value: u64) {
    push_text(body, key, &value.to_string());
}

/// Reads one canonical decimal number.
///
/// Unlike the route manifest reader this one accepts a canonical `0`, because a
/// frozen serialization version may legitimately be zero, while still refusing
/// any leading zero, sign, separator or oversize digit run.
fn take_bounded_number(
    lines: &[&str],
    cursor: &mut usize,
    key: &str,
) -> Result<u64, ProductionConfigErrorV1> {
    let value = take_value(lines, cursor, key)?;
    if value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ProductionConfigErrorV1::InvalidNodeBounds);
    }
    value
        .parse()
        .map_err(|_| ProductionConfigErrorV1::InvalidNodeBounds)
}

fn config_digest_node(bytes: &[u8]) -> Result<[u8; 32], ProductionConfigErrorV1> {
    let mut domained = Vec::with_capacity(NODE_DIGEST_DOMAIN_V1.len() + bytes.len());
    domained.extend_from_slice(NODE_DIGEST_DOMAIN_V1);
    domained.extend_from_slice(bytes);
    config_digest(&domained)
}

/// Exact hexadecimal length of the relay signing secret field.
///
/// Thirty-two bytes in one lowercase spelling. Uppercase is refused rather
/// than accepted, so an operator's stream is reproducible byte for byte.
const RELAY_SIGNING_SECRET_HEX_BYTES_V1: usize = 64;

/// Exact hexadecimal length of the independent route-secret vault seal key.
const ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1: usize = 64;

/// Exact hexadecimal length of the independent refund-arming journal key.
const REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1: usize = 64;

/// Exact hexadecimal length of the route-scoped Bitcoin participant key.
const BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1: usize = 64;

/// Maximum bytes of the Contracts transport identity passphrase field.
pub const MAX_CONTRACTS_IDENTITY_PASSPHRASE_BYTES_V1: usize = 1024;

/// Maximum bytes of the encrypted DOM wallet passphrase field.
pub const MAX_DOM_WALLET_PASSPHRASE_BYTES_V1: usize = 1024;

/// Maximum bytes of the whole out-of-band secret stream, separators included.
///
/// Every field keeps its own bound; this is their sum plus the seven separators.
/// It deliberately does not widen `MAX_DOM_NODE_BEARER_BYTES_V1`, which stays
/// the bearer's and only the bearer's.
const MAX_PRODUCTION_SECRET_STREAM_BYTES_V1: usize = MAX_DOM_NODE_BEARER_BYTES_V1
    + 1
    + RELAY_SIGNING_SECRET_HEX_BYTES_V1
    + 1
    + RELAY_SIGNING_SECRET_HEX_BYTES_V1
    + 1
    + MAX_CONTRACTS_IDENTITY_PASSPHRASE_BYTES_V1
    + 1
    + MAX_DOM_WALLET_PASSPHRASE_BYTES_V1
    + 1
    + BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1
    + 1
    + ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1
    + 1
    + REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1;

/// V2 adds one independent local EVM key and one separator. The V1 bound and
/// parser remain unchanged, so an eight-field stream is never reinterpreted.
const MAX_PRODUCTION_SECRET_STREAM_BYTES_V2: usize =
    MAX_PRODUCTION_SECRET_STREAM_BYTES_V1 + 1 + RELAY_SIGNING_SECRET_HEX_BYTES_V1;
const PRODUCTION_SECRET_STREAM_HEADER_V3: &[u8] = b"DOM-INTEROPD-SECRETS-V3";
const UPSTREAM_F6_HSM_COUNT_PREFIX_V3: &[u8] = b"upstream_f6_hsm_credentials=";
const DOWNSTREAM_F6_HSM_COUNT_PREFIX_V3: &[u8] = b"downstream_f6_hsm_credentials=";
/// Must stay equal to the strict signer-descriptor bound in the F6 V7 bundle.
pub const MAX_PRODUCTION_F6_HSM_CREDENTIALS_PER_LEG_V3: usize = 16;
const MAX_PRODUCTION_SECRET_STREAM_BYTES_V3: usize = PRODUCTION_SECRET_STREAM_HEADER_V3.len()
    + 1
    + MAX_PRODUCTION_SECRET_STREAM_BYTES_V2
    + 1
    + UPSTREAM_F6_HSM_COUNT_PREFIX_V3.len()
    + 2
    + MAX_PRODUCTION_F6_HSM_CREDENTIALS_PER_LEG_V3 * (1 + RELAY_SIGNING_SECRET_HEX_BYTES_V1)
    + 1
    + DOWNSTREAM_F6_HSM_COUNT_PREFIX_V3.len()
    + 2
    + MAX_PRODUCTION_F6_HSM_CREDENTIALS_PER_LEG_V3 * (1 + RELAY_SIGNING_SECRET_HEX_BYTES_V1);

/// The eight out-of-band secrets, still as bytes.
///
/// Separate from the credential type on purpose: this half compiles without
/// the production graph, because `BearerTokenV1` lives behind the `production`
/// feature and the codec that produces these fields does not.
struct ProductionSecretFieldsV1 {
    bearer: Zeroizing<Vec<u8>>,
    upstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    downstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    identity_passphrase: Zeroizing<Vec<u8>>,
    dom_wallet_passphrase: Zeroizing<Vec<u8>>,
    bitcoin_participant_secret: Zeroizing<[u8; 32]>,
    route_secret_seal_key: Zeroizing<[u8; 32]>,
    refund_arming_credential: Zeroizing<[u8; 32]>,
}

struct ProductionSecretFieldsV2 {
    common: ProductionSecretFieldsV1,
    evm_signing_secret: Zeroizing<[u8; 32]>,
}

struct ProductionSecretFieldsV3 {
    common: ProductionSecretFieldsV2,
    upstream_f6_hsm_credentials: Vec<Zeroizing<[u8; 32]>>,
    downstream_f6_hsm_credentials: Vec<Zeroizing<[u8; 32]>>,
}

struct ProductionSecretFieldSlicesV1<'a> {
    bearer: &'a [u8],
    upstream_relay_secret: &'a [u8],
    downstream_relay_secret: &'a [u8],
    identity_passphrase: &'a [u8],
    dom_wallet_passphrase: &'a [u8],
    bitcoin_participant_secret: &'a [u8],
    seal_key: &'a [u8],
    refund_credential: &'a [u8],
}

/// Reads the eight out-of-band secrets from one already-opened stream.
///
/// **Stream format, for the operator who has to write it.** Exactly eight
/// fields separated by exactly seven `\n` bytes, and **no trailing newline**:
///
/// ```text
/// <dom node bearer token>\n<upstream Relay signing secret: 64 lowercase hex>\n<downstream Relay signing secret: 64 lowercase hex>\n<contracts identity passphrase>\n<DOM wallet passphrase>\n<Bitcoin participant secret: 64 lowercase hex>\n<route-secret seal key: 64 lowercase hex>\n<refund-arming credential: 64 lowercase hex>
/// ```
///
/// `printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' "$BEARER" "$UPSTREAM_RELAY_HEX" "$DOWNSTREAM_RELAY_HEX" "$IDENTITY_PASSPHRASE" "$DOM_WALLET_PASSPHRASE" "$BITCOIN_HEX" "$SEAL_HEX" "$REFUND_HEX"`
/// writes exactly that. `echo` does not: it appends a ninth, empty field and is
/// refused.
///
/// **What changed here, and why the shape it replaces existed.** This used to
/// read one field and refuse **any** ASCII control byte anywhere in the
/// stream, with the trailing newline named as the commonest mistake. That
/// refusal was a proxy that only worked because there was one field: with one
/// field, "no newline anywhere" and "no newline inside the secret" are the
/// same sentence. With eight they are not, and the guarantee the proxy stood
/// for — **no whitespace lost inside a secret** — moves to where it always
/// belonged, which is the field. Every field still refuses every ASCII control
/// byte; the stream cannot, because one of them is now the separator. Nothing
/// is relaxed: a newline inside a field is refused as a field-count error
/// instead of a malformed-material one, and both are refusals.
///
/// The buffer is allocated once at the bound plus one, so no reallocation can
/// leave a copy of the material behind, and it is wiped on **every** path out
/// — success included, because the fields are copied into their own zeroizing
/// owners before the read window goes.
fn read_production_secret_fields(
    mut reader: impl std::io::Read,
) -> Result<ProductionSecretFieldsV1, ProductionConfigErrorV1> {
    use std::io::Read as _;
    use zeroize::Zeroize as _;

    let mut stream = Vec::with_capacity(MAX_PRODUCTION_SECRET_STREAM_BYTES_V1 + 1);
    let read = match (&mut reader)
        .take(MAX_PRODUCTION_SECRET_STREAM_BYTES_V1 as u64 + 1)
        .read_to_end(&mut stream)
    {
        Ok(read) => read,
        Err(_) => {
            stream.zeroize();
            return Err(ProductionConfigErrorV1::SecretStreamUnavailable);
        }
    };
    if read > MAX_PRODUCTION_SECRET_STREAM_BYTES_V1 {
        stream.zeroize();
        return Err(ProductionConfigErrorV1::SecretStreamOversized);
    }
    // One exit for the wipe. The parser borrows and copies out, so the read
    // window is wiped identically whether it accepted or refused, and no path
    // can forget it by returning early.
    let parsed = parse_production_secret_fields(&stream);
    stream.zeroize();
    parsed
}

fn parse_production_secret_fields(
    stream: &[u8],
) -> Result<ProductionSecretFieldsV1, ProductionConfigErrorV1> {
    if stream.is_empty() {
        return Err(ProductionConfigErrorV1::SecretStreamUnavailable);
    }
    let mut fields = stream.split(|byte| *byte == b'\n');
    let (
        Some(bearer),
        Some(upstream_relay_secret),
        Some(downstream_relay_secret),
        Some(identity_passphrase),
        Some(dom_wallet_passphrase),
        Some(bitcoin_participant_secret),
        Some(seal_key),
        Some(refund_credential),
    ) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    )
    else {
        return Err(ProductionConfigErrorV1::SecretStreamFieldCount);
    };
    // Exact count. A ninth field is either an extra line or a trailing
    // newline, and neither is tolerated: both are the same refusal.
    if fields.next().is_some() {
        return Err(ProductionConfigErrorV1::SecretStreamFieldCount);
    }
    parse_production_secret_field_slices(ProductionSecretFieldSlicesV1 {
        bearer,
        upstream_relay_secret,
        downstream_relay_secret,
        identity_passphrase,
        dom_wallet_passphrase,
        bitcoin_participant_secret,
        seal_key,
        refund_credential,
    })
}

fn parse_production_secret_field_slices(
    fields: ProductionSecretFieldSlicesV1<'_>,
) -> Result<ProductionSecretFieldsV1, ProductionConfigErrorV1> {
    let ProductionSecretFieldSlicesV1 {
        bearer,
        upstream_relay_secret,
        downstream_relay_secret,
        identity_passphrase,
        dom_wallet_passphrase,
        bitcoin_participant_secret,
        seal_key,
        refund_credential,
    } = fields;
    require_secret_field(
        bearer,
        MAX_DOM_NODE_BEARER_BYTES_V1,
        ProductionConfigErrorV1::BearerMaterialMalformed,
    )?;
    require_secret_field(
        identity_passphrase,
        MAX_CONTRACTS_IDENTITY_PASSPHRASE_BYTES_V1,
        ProductionConfigErrorV1::IdentityPassphraseMalformed,
    )?;
    require_secret_field(
        dom_wallet_passphrase,
        MAX_DOM_WALLET_PASSPHRASE_BYTES_V1,
        ProductionConfigErrorV1::DomWalletPassphraseMalformed,
    )?;
    if identity_passphrase == dom_wallet_passphrase
        || core::str::from_utf8(dom_wallet_passphrase).is_err()
    {
        return Err(ProductionConfigErrorV1::DomWalletPassphraseMalformed);
    }
    let upstream_relay_signing_secret = decode_exact_secret_v1(
        upstream_relay_secret,
        ProductionConfigErrorV1::RelaySigningSecretMalformed,
        true,
    )?;
    let downstream_relay_signing_secret = decode_exact_secret_v1(
        downstream_relay_secret,
        ProductionConfigErrorV1::RelaySigningSecretMalformed,
        true,
    )?;
    if upstream_relay_signing_secret.as_slice() == downstream_relay_signing_secret.as_slice() {
        return Err(ProductionConfigErrorV1::RelaySigningSecretMalformed);
    }
    let route_secret_seal_key = decode_exact_secret_v1(
        seal_key,
        ProductionConfigErrorV1::RouteSecretSealKeyMalformed,
        true,
    )?;
    let refund_arming_credential = decode_exact_secret_v1(
        refund_credential,
        ProductionConfigErrorV1::RefundArmingCredentialMalformed,
        true,
    )?;
    let bitcoin_participant_secret = decode_exact_secret_v1(
        bitcoin_participant_secret,
        ProductionConfigErrorV1::BitcoinParticipantSecretMalformed,
        true,
    )?;
    // Separate authorities must also carry separate key material. Accepting
    // the relay signing key as the vault AEAD key would collapse two blast
    // radii even though the stream gave them different field names.
    if bitcoin_participant_secret.as_slice() == upstream_relay_signing_secret.as_slice()
        || bitcoin_participant_secret.as_slice() == downstream_relay_signing_secret.as_slice()
    {
        return Err(ProductionConfigErrorV1::BitcoinParticipantSecretMalformed);
    }
    if route_secret_seal_key.as_slice() == upstream_relay_signing_secret.as_slice()
        || route_secret_seal_key.as_slice() == downstream_relay_signing_secret.as_slice()
        || route_secret_seal_key.as_slice() == bitcoin_participant_secret.as_slice()
    {
        return Err(ProductionConfigErrorV1::RouteSecretSealKeyMalformed);
    }
    if refund_arming_credential.as_slice() == upstream_relay_signing_secret.as_slice()
        || refund_arming_credential.as_slice() == downstream_relay_signing_secret.as_slice()
        || refund_arming_credential.as_slice() == bitcoin_participant_secret.as_slice()
        || refund_arming_credential.as_slice() == route_secret_seal_key.as_slice()
    {
        return Err(ProductionConfigErrorV1::RefundArmingCredentialMalformed);
    }
    Ok(ProductionSecretFieldsV1 {
        bearer: Zeroizing::new(bearer.to_vec()),
        upstream_relay_signing_secret,
        downstream_relay_signing_secret,
        identity_passphrase: Zeroizing::new(identity_passphrase.to_vec()),
        dom_wallet_passphrase: Zeroizing::new(dom_wallet_passphrase.to_vec()),
        bitcoin_participant_secret,
        route_secret_seal_key,
        refund_arming_credential,
    })
}

fn read_production_secret_fields_v2(
    mut reader: impl std::io::Read,
) -> Result<ProductionSecretFieldsV2, ProductionSecretsV2ErrorV1> {
    use std::io::Read as _;
    use zeroize::Zeroize as _;

    let mut stream = Vec::with_capacity(MAX_PRODUCTION_SECRET_STREAM_BYTES_V2 + 1);
    let read = match (&mut reader)
        .take(MAX_PRODUCTION_SECRET_STREAM_BYTES_V2 as u64 + 1)
        .read_to_end(&mut stream)
    {
        Ok(read) => read,
        Err(_) => {
            stream.zeroize();
            return Err(ProductionSecretsV2ErrorV1::Common(
                ProductionConfigErrorV1::SecretStreamUnavailable,
            ));
        }
    };
    if read > MAX_PRODUCTION_SECRET_STREAM_BYTES_V2 {
        stream.zeroize();
        return Err(ProductionSecretsV2ErrorV1::Common(
            ProductionConfigErrorV1::SecretStreamOversized,
        ));
    }
    let parsed = parse_production_secret_fields_v2(&stream);
    stream.zeroize();
    parsed
}

fn parse_production_secret_fields_v2(
    stream: &[u8],
) -> Result<ProductionSecretFieldsV2, ProductionSecretsV2ErrorV1> {
    if stream.is_empty() {
        return Err(ProductionSecretsV2ErrorV1::Common(
            ProductionConfigErrorV1::SecretStreamUnavailable,
        ));
    }
    let mut fields = stream.split(|byte| *byte == b'\n');
    let (
        Some(bearer),
        Some(upstream_relay_secret),
        Some(downstream_relay_secret),
        Some(identity_passphrase),
        Some(dom_wallet_passphrase),
        Some(bitcoin_participant_secret),
        Some(seal_key),
        Some(refund_credential),
        Some(evm_signing_secret),
    ) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    )
    else {
        return Err(ProductionSecretsV2ErrorV1::Common(
            ProductionConfigErrorV1::SecretStreamFieldCount,
        ));
    };
    if fields.next().is_some() {
        return Err(ProductionSecretsV2ErrorV1::Common(
            ProductionConfigErrorV1::SecretStreamFieldCount,
        ));
    }
    parse_production_secret_field_slices_v2(
        ProductionSecretFieldSlicesV1 {
            bearer,
            upstream_relay_secret,
            downstream_relay_secret,
            identity_passphrase,
            dom_wallet_passphrase,
            bitcoin_participant_secret,
            seal_key,
            refund_credential,
        },
        evm_signing_secret,
    )
}

fn parse_production_secret_field_slices_v2(
    fields: ProductionSecretFieldSlicesV1<'_>,
    evm_signing_secret: &[u8],
) -> Result<ProductionSecretFieldsV2, ProductionSecretsV2ErrorV1> {
    let common =
        parse_production_secret_field_slices(fields).map_err(ProductionSecretsV2ErrorV1::Common)?;
    let evm_signing_secret = decode_exact_secret_v1(
        evm_signing_secret,
        ProductionConfigErrorV1::RelaySigningSecretMalformed,
        true,
    )
    .map_err(|_| ProductionSecretsV2ErrorV1::EvmSigningSecretMalformed)?;
    let reserved = [
        common.upstream_relay_signing_secret.as_slice(),
        common.downstream_relay_signing_secret.as_slice(),
        common.bitcoin_participant_secret.as_slice(),
        common.route_secret_seal_key.as_slice(),
        common.refund_arming_credential.as_slice(),
    ];
    if reserved
        .iter()
        .any(|candidate| *candidate == evm_signing_secret.as_slice())
    {
        return Err(ProductionSecretsV2ErrorV1::EvmSigningSecretMalformed);
    }
    Ok(ProductionSecretFieldsV2 {
        common,
        evm_signing_secret,
    })
}

fn read_production_secret_fields_v3(
    mut reader: impl std::io::Read,
) -> Result<ProductionSecretFieldsV3, ProductionSecretsV3ErrorV1> {
    use std::io::Read as _;
    use zeroize::Zeroize as _;

    let mut stream = Vec::with_capacity(MAX_PRODUCTION_SECRET_STREAM_BYTES_V3 + 1);
    let read = match (&mut reader)
        .take(MAX_PRODUCTION_SECRET_STREAM_BYTES_V3 as u64 + 1)
        .read_to_end(&mut stream)
    {
        Ok(read) => read,
        Err(_) => {
            stream.zeroize();
            return Err(ProductionSecretsV3ErrorV1::Common(
                ProductionSecretsV2ErrorV1::Common(
                    ProductionConfigErrorV1::SecretStreamUnavailable,
                ),
            ));
        }
    };
    if read > MAX_PRODUCTION_SECRET_STREAM_BYTES_V3 {
        stream.zeroize();
        return Err(ProductionSecretsV3ErrorV1::Common(
            ProductionSecretsV2ErrorV1::Common(ProductionConfigErrorV1::SecretStreamOversized),
        ));
    }
    let parsed = parse_production_secret_fields_v3(&stream);
    stream.zeroize();
    parsed
}

fn parse_production_secret_fields_v3(
    stream: &[u8],
) -> Result<ProductionSecretFieldsV3, ProductionSecretsV3ErrorV1> {
    if stream.is_empty() {
        return Err(ProductionSecretsV3ErrorV1::Common(
            ProductionSecretsV2ErrorV1::Common(ProductionConfigErrorV1::SecretStreamUnavailable),
        ));
    }
    let mut fields = stream.split(|byte| *byte == b'\n');
    if fields.next() != Some(PRODUCTION_SECRET_STREAM_HEADER_V3) {
        return Err(ProductionSecretsV3ErrorV1::WrongVersion);
    }
    let common_slices = ProductionSecretFieldSlicesV1 {
        bearer: take_secret_stream_field_v3(&mut fields)?,
        upstream_relay_secret: take_secret_stream_field_v3(&mut fields)?,
        downstream_relay_secret: take_secret_stream_field_v3(&mut fields)?,
        identity_passphrase: take_secret_stream_field_v3(&mut fields)?,
        dom_wallet_passphrase: take_secret_stream_field_v3(&mut fields)?,
        bitcoin_participant_secret: take_secret_stream_field_v3(&mut fields)?,
        seal_key: take_secret_stream_field_v3(&mut fields)?,
        refund_credential: take_secret_stream_field_v3(&mut fields)?,
    };
    let evm_signing_secret = take_secret_stream_field_v3(&mut fields)?;
    let common = parse_production_secret_field_slices_v2(common_slices, evm_signing_secret)
        .map_err(ProductionSecretsV3ErrorV1::Common)?;
    let upstream_count = parse_hsm_count_v3(
        take_secret_stream_field_v3(&mut fields)?,
        UPSTREAM_F6_HSM_COUNT_PREFIX_V3,
    )?;
    let upstream_f6_hsm_credentials = decode_hsm_credentials_v3(&mut fields, upstream_count)?;
    let downstream_count = parse_hsm_count_v3(
        take_secret_stream_field_v3(&mut fields)?,
        DOWNSTREAM_F6_HSM_COUNT_PREFIX_V3,
    )?;
    let downstream_f6_hsm_credentials = decode_hsm_credentials_v3(&mut fields, downstream_count)?;
    if fields.next().is_some() {
        return Err(ProductionSecretsV3ErrorV1::FieldCount);
    }
    validate_hsm_credential_independence_v3(
        &common,
        &upstream_f6_hsm_credentials,
        &downstream_f6_hsm_credentials,
    )?;
    Ok(ProductionSecretFieldsV3 {
        common,
        upstream_f6_hsm_credentials,
        downstream_f6_hsm_credentials,
    })
}

fn take_secret_stream_field_v3<'a, I>(
    fields: &mut I,
) -> Result<&'a [u8], ProductionSecretsV3ErrorV1>
where
    I: Iterator<Item = &'a [u8]>,
{
    fields.next().ok_or(ProductionSecretsV3ErrorV1::FieldCount)
}

fn parse_hsm_count_v3(field: &[u8], prefix: &[u8]) -> Result<usize, ProductionSecretsV3ErrorV1> {
    let digits = field
        .strip_prefix(prefix)
        .ok_or(ProductionSecretsV3ErrorV1::HsmCredentialCount)?;
    if digits.is_empty()
        || digits.len() > 2
        || (digits.len() > 1 && digits[0] == b'0')
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return Err(ProductionSecretsV3ErrorV1::HsmCredentialCount);
    }
    let mut value = 0_usize;
    for digit in digits {
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(usize::from(*digit - b'0')))
            .ok_or(ProductionSecretsV3ErrorV1::HsmCredentialCount)?;
    }
    if !(1..=MAX_PRODUCTION_F6_HSM_CREDENTIALS_PER_LEG_V3).contains(&value) {
        return Err(ProductionSecretsV3ErrorV1::HsmCredentialCount);
    }
    Ok(value)
}

fn decode_hsm_credentials_v3<'a, I>(
    fields: &mut I,
    count: usize,
) -> Result<Vec<Zeroizing<[u8; 32]>>, ProductionSecretsV3ErrorV1>
where
    I: Iterator<Item = &'a [u8]>,
{
    let mut credentials = Vec::with_capacity(count);
    for _ in 0..count {
        let encoded = take_secret_stream_field_v3(fields)?;
        credentials.push(
            decode_exact_secret_v1(
                encoded,
                ProductionConfigErrorV1::RelaySigningSecretMalformed,
                true,
            )
            .map_err(|_| ProductionSecretsV3ErrorV1::HsmCredentialMalformed)?,
        );
    }
    Ok(credentials)
}

fn validate_hsm_credential_independence_v3(
    common: &ProductionSecretFieldsV2,
    upstream: &[Zeroizing<[u8; 32]>],
    downstream: &[Zeroizing<[u8; 32]>],
) -> Result<(), ProductionSecretsV3ErrorV1> {
    let reserved = [
        common.common.upstream_relay_signing_secret.as_slice(),
        common.common.downstream_relay_signing_secret.as_slice(),
        common.common.bitcoin_participant_secret.as_slice(),
        common.common.route_secret_seal_key.as_slice(),
        common.common.refund_arming_credential.as_slice(),
        common.evm_signing_secret.as_slice(),
    ];
    let variable_authorities = [
        common.common.bearer.as_slice(),
        common.common.identity_passphrase.as_slice(),
        common.common.dom_wallet_passphrase.as_slice(),
    ];
    let credentials: Vec<&[u8]> = upstream
        .iter()
        .chain(downstream)
        .map(|credential| credential.as_slice())
        .collect();
    if credentials.iter().enumerate().any(|(index, credential)| {
        reserved.iter().any(|value| value == credential)
            || variable_authorities.contains(credential)
            || credentials[..index]
                .iter()
                .any(|previous| previous == credential)
    }) {
        return Err(ProductionSecretsV3ErrorV1::HsmCredentialReused);
    }
    Ok(())
}

/// One field is non-empty, within **its own** bound, and free of every ASCII
/// control byte. The bound belongs to the field and never to the stream.
fn require_secret_field(
    field: &[u8],
    maximum: usize,
    refusal: ProductionConfigErrorV1,
) -> Result<(), ProductionConfigErrorV1> {
    if field.is_empty() || field.len() > maximum || field.iter().any(u8::is_ascii_control) {
        return Err(refusal);
    }
    Ok(())
}

/// Decodes exactly sixty-four lowercase hex characters into thirty-two bytes.
///
/// **Not `production_config::decode_digest`, and the difference is the whole
/// reason this exists.** That function is `pub(crate)`, is already imported by
/// this module, requires the same exact sixty-four lowercase hex characters,
/// and decodes them the same way — but it returns a bare `[u8; 32]`. For a
/// digest that is right; for a signing secret it is not, because the value
/// would exist as an ordinary stack array before anything could take ownership
/// of it, and a caller cannot wipe an array it did not create. Here the
/// destination is a `Zeroizing` from the first byte written, so the scalar
/// never exists outside one. Anyone tempted to merge the two should move the
/// secret's destination, not its decoder.
///
/// It is also not `hex`: that crate is a development dependency here, and
/// promoting it to a normal one for twelve lines would be a manifest change
/// bought with nothing. The hex text itself is a borrow of the read window the
/// caller wipes.
fn decode_exact_secret_v1(
    field: &[u8],
    refusal: ProductionConfigErrorV1,
    reject_zero: bool,
) -> Result<Zeroizing<[u8; 32]>, ProductionConfigErrorV1> {
    if field.len() != RELAY_SIGNING_SECRET_HEX_BYTES_V1 {
        return Err(refusal);
    }
    let mut decoded = Zeroizing::new([0_u8; 32]);
    for (index, pair) in field.chunks_exact(2).enumerate() {
        let (Some(high), Some(low)) =
            (lowercase_hex_nibble(pair[0]), lowercase_hex_nibble(pair[1]))
        else {
            return Err(refusal);
        };
        decoded[index] = (high << 4) | low;
    }
    if reject_zero && decoded.iter().all(|byte| *byte == 0) {
        return Err(refusal);
    }
    Ok(decoded)
}

fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(feature = "production")]
use std::time::Duration;

#[cfg(feature = "production")]
use dom_scriptless_chain_adapter::{BearerTokenV1, DomHttpChainAdapterV1, ExpectedDomIdentityV1};

#[cfg(feature = "production")]
use deployment_registry::DomDeploymentV1;

#[cfg(feature = "production")]
use route_secret_vault::RouteSecretSealKeyV1;

#[cfg(feature = "production")]
use crate::production_refund_arming::ProductionRefundArmingCredentialV1;

/// Redacted refusal from the explicitly nine-field V2 secret stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionSecretsV2ErrorV1 {
    /// One of the eight V1 authorities or the stream envelope was refused.
    #[error("production secret stream V2 common authority refused")]
    Common(ProductionConfigErrorV1),
    /// The ninth field was not one independent nonzero lowercase-hex key.
    #[error("production EVM signing credential is malformed")]
    EvmSigningSecretMalformed,
}

/// Redacted refusal from the explicitly versioned F6/HSM secret stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionSecretsV3ErrorV1 {
    /// A V1/V2 common authority was refused.
    #[error("production secret stream V3 common authority refused")]
    Common(ProductionSecretsV2ErrorV1),
    /// The literal V3 header was absent or belonged to another family.
    #[error("production secret stream V3 version is invalid")]
    WrongVersion,
    /// The stream ended early or carried trailing fields/newline.
    #[error("production secret stream V3 field count is invalid")]
    FieldCount,
    /// A per-leg credential count was zero, non-canonical or out of bounds.
    #[error("production F6 HSM credential count is invalid")]
    HsmCredentialCount,
    /// One credential was not one nonzero fixed-size lowercase-hex value.
    #[error("production F6 HSM credential is malformed")]
    HsmCredentialMalformed,
    /// A credential was reused across a signer, leg or unrelated authority.
    #[error("production F6 HSM credential was reused")]
    HsmCredentialReused,
}

/// The eight out-of-band production secrets, each in its own owner.
///
/// There is no accessor that hands back a copy: the parts leave together, once,
/// into the composition root that consumes them. The two byte fields are
/// `Zeroizing`, so dropping this value without consuming it wipes them.
#[cfg(feature = "production")]
pub struct ProductionSecretsV1 {
    bearer: BearerTokenV1,
    upstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    downstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    identity_passphrase: Zeroizing<Vec<u8>>,
    dom_wallet_passphrase: Zeroizing<String>,
    bitcoin_participant_secret: Zeroizing<[u8; 32]>,
    route_secret_seal_key: RouteSecretSealKeyV1,
    refund_arming_credential: ProductionRefundArmingCredentialV1,
}

/// The V1 owners plus exactly one local, role-scoped EVM credential.
///
/// This is a distinct type and parser: V1 is never widened to accept a ninth
/// field, while V2 never accepts the old eight-field stream.
#[cfg(feature = "production")]
pub struct ProductionSecretsV2 {
    common: ProductionSecretsV1,
    evm_signing_secret: Zeroizing<[u8; 32]>,
}

/// V3 live-run secrets, including one independent credential per signed F6
/// HSM descriptor. Deliberately has no `Debug`, codec, clone or copy surface.
#[cfg(feature = "production")]
pub struct ProductionSecretsV3 {
    common: ProductionSecretsV2,
    upstream_f6_hsm_credentials: Vec<Zeroizing<[u8; 32]>>,
    downstream_f6_hsm_credentials: Vec<Zeroizing<[u8; 32]>>,
}

/// Single-use handoff from the secret reader into the production composition
/// root. Fields remain crate-private so no external caller can selectively
/// extract or duplicate one authority.
#[cfg(feature = "production")]
pub(crate) struct ProductionSecretPartsV1 {
    pub(crate) bearer: BearerTokenV1,
    pub(crate) upstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    pub(crate) downstream_relay_signing_secret: Zeroizing<[u8; 32]>,
    pub(crate) identity_passphrase: Zeroizing<Vec<u8>>,
    pub(crate) dom_wallet_passphrase: Zeroizing<String>,
    pub(crate) bitcoin_participant_secret: Zeroizing<[u8; 32]>,
    pub(crate) route_secret_seal_key: RouteSecretSealKeyV1,
    pub(crate) refund_arming_credential: ProductionRefundArmingCredentialV1,
}

/// Single-use nine-authority handoff into the composition root.
#[cfg(feature = "production")]
pub(crate) struct ProductionSecretPartsV2 {
    pub(crate) common: ProductionSecretPartsV1,
    pub(crate) evm_signing_secret: Zeroizing<[u8; 32]>,
}

/// Single-use V3 handoff. Credential vectors retain zeroizing element owners.
#[cfg(feature = "production")]
pub(crate) struct ProductionSecretPartsV3 {
    pub(crate) common: ProductionSecretPartsV2,
    pub(crate) upstream_f6_hsm_credentials: Vec<Zeroizing<[u8; 32]>>,
    pub(crate) downstream_f6_hsm_credentials: Vec<Zeroizing<[u8; 32]>>,
}

#[cfg(feature = "production")]
impl core::fmt::Debug for ProductionSecretsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSecretsV1([redacted])")
    }
}

#[cfg(feature = "production")]
impl core::fmt::Debug for ProductionSecretsV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSecretsV2([redacted])")
    }
}

#[cfg(feature = "production")]
impl ProductionSecretsV1 {
    /// Hands all eight secrets to the sole composition root, consuming the
    /// carrier and preserving each purpose-specific owner.
    #[must_use]
    pub(crate) fn into_parts(self) -> ProductionSecretPartsV1 {
        ProductionSecretPartsV1 {
            bearer: self.bearer,
            upstream_relay_signing_secret: self.upstream_relay_signing_secret,
            downstream_relay_signing_secret: self.downstream_relay_signing_secret,
            identity_passphrase: self.identity_passphrase,
            dom_wallet_passphrase: self.dom_wallet_passphrase,
            bitcoin_participant_secret: self.bitcoin_participant_secret,
            route_secret_seal_key: self.route_secret_seal_key,
            refund_arming_credential: self.refund_arming_credential,
        }
    }
}

#[cfg(feature = "production")]
impl ProductionSecretsV2 {
    /// Hands all nine owners to the sole composition root without copying a
    /// credential or exposing a selective getter.
    #[must_use]
    pub(crate) fn into_parts(self) -> ProductionSecretPartsV2 {
        ProductionSecretPartsV2 {
            common: self.common.into_parts(),
            evm_signing_secret: self.evm_signing_secret,
        }
    }
}

#[cfg(feature = "production")]
impl ProductionSecretsV3 {
    /// Moves every credential into the sole composition root exactly once.
    #[must_use]
    pub(crate) fn into_parts(self) -> ProductionSecretPartsV3 {
        ProductionSecretPartsV3 {
            common: self.common.into_parts(),
            upstream_f6_hsm_credentials: self.upstream_f6_hsm_credentials,
            downstream_f6_hsm_credentials: self.downstream_f6_hsm_credentials,
        }
    }
}

/// Reads the eight out-of-band credentials from standard input, in one pass.
///
/// Called exactly once, by the composition root, before any client or store
/// exists. A terminal is refused by name: an interactive standard input means
/// no supervisor wrote the material.
///
/// The stream format, the bound of each field, the exact field count and the
/// wiping of the read window all live in [`read_production_secret_fields`],
/// whose documentation an operator should read before writing the stream.
/// `BearerTokenV1` then re-enforces the token's own shape and keeps it
/// zeroizing — it receives exactly what it received before this became a
/// eight-field stream, neither more nor differently shaped — so a refusal at
/// that last step is still a refusal of shape. Neither the material nor any
/// prefix of it is ever formatted into a diagnostic.
#[cfg(feature = "production")]
pub fn read_production_secrets_from_stdin() -> Result<ProductionSecretsV1, ProductionConfigErrorV1>
{
    use std::io::IsTerminal as _;

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(ProductionConfigErrorV1::SecretStreamIsTerminal);
    }
    let fields = read_production_secret_fields(stdin.lock())?;
    production_secrets_from_fields(fields)
}

/// Reads exactly nine out-of-band credentials from standard input.
///
/// The first eight fields have byte-for-byte V1 semantics; field nine is one
/// independent lowercase-hex EVM key. There is no version sniffing or fallback
/// between the two formats.
#[cfg(feature = "production")]
pub fn read_production_secrets_v2_from_stdin(
) -> Result<ProductionSecretsV2, ProductionSecretsV2ErrorV1> {
    use std::io::IsTerminal as _;

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(ProductionSecretsV2ErrorV1::Common(
            ProductionConfigErrorV1::SecretStreamIsTerminal,
        ));
    }
    let fields = read_production_secret_fields_v2(stdin.lock())?;
    let common = production_secrets_from_fields(fields.common)
        .map_err(ProductionSecretsV2ErrorV1::Common)?;
    Ok(ProductionSecretsV2 {
        common,
        evm_signing_secret: fields.evm_signing_secret,
    })
}

/// Reads the only secret-stream family accepted by the strict V8 live run.
///
/// The literal V3 header, two nonzero bounded counts, every fixed-size
/// credential and end-of-input are mandatory. V1/V2 are never sniffed or used
/// as fallback.
#[cfg(feature = "production")]
pub fn read_production_secrets_v3_from_stdin(
) -> Result<ProductionSecretsV3, ProductionSecretsV3ErrorV1> {
    use std::io::IsTerminal as _;

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(ProductionSecretsV3ErrorV1::Common(
            ProductionSecretsV2ErrorV1::Common(ProductionConfigErrorV1::SecretStreamIsTerminal),
        ));
    }
    let fields = read_production_secret_fields_v3(stdin.lock())?;
    let common = production_secrets_from_fields(fields.common.common)
        .map_err(ProductionSecretsV2ErrorV1::Common)
        .map_err(ProductionSecretsV3ErrorV1::Common)?;
    Ok(ProductionSecretsV3 {
        common: ProductionSecretsV2 {
            common,
            evm_signing_secret: fields.common.evm_signing_secret,
        },
        upstream_f6_hsm_credentials: fields.upstream_f6_hsm_credentials,
        downstream_f6_hsm_credentials: fields.downstream_f6_hsm_credentials,
    })
}

#[cfg(feature = "production")]
fn production_secrets_from_fields(
    fields: ProductionSecretFieldsV1,
) -> Result<ProductionSecretsV1, ProductionConfigErrorV1> {
    // `String::from_utf8` takes the vector by value, so a rejected token is
    // wiped by the error path here and an accepted one is wiped by
    // `BearerTokenV1`, which moves it into its zeroizing wrapper before it
    // validates anything.
    let bearer = match String::from_utf8(fields.bearer.to_vec()) {
        Ok(bearer) => bearer,
        Err(error) => {
            use zeroize::Zeroize as _;
            let mut material = error.into_bytes();
            material.zeroize();
            return Err(ProductionConfigErrorV1::BearerMaterialMalformed);
        }
    };
    let bearer =
        BearerTokenV1::new(bearer).map_err(|_| ProductionConfigErrorV1::BearerMaterialMalformed)?;
    let dom_wallet_passphrase = match String::from_utf8(fields.dom_wallet_passphrase.to_vec()) {
        Ok(passphrase) => Zeroizing::new(passphrase),
        Err(error) => {
            use zeroize::Zeroize as _;
            let mut material = error.into_bytes();
            material.zeroize();
            return Err(ProductionConfigErrorV1::DomWalletPassphraseMalformed);
        }
    };
    let route_secret_seal_key =
        RouteSecretSealKeyV1::import_zeroizing(fields.route_secret_seal_key)
            .map_err(|_| ProductionConfigErrorV1::RouteSecretSealKeyMalformed)?;
    let refund_arming_credential =
        ProductionRefundArmingCredentialV1::import_zeroizing(fields.refund_arming_credential)
            .map_err(|_| ProductionConfigErrorV1::RefundArmingCredentialMalformed)?;
    Ok(ProductionSecretsV1 {
        bearer,
        upstream_relay_signing_secret: fields.upstream_relay_signing_secret,
        downstream_relay_signing_secret: fields.downstream_relay_signing_secret,
        identity_passphrase: fields.identity_passphrase,
        dom_wallet_passphrase,
        bitcoin_participant_secret: fields.bitcoin_participant_secret,
        route_secret_seal_key,
        refund_arming_credential,
    })
}

#[cfg(feature = "production")]
impl ProductionNodeConfigV1 {
    /// Frozen identity this daemon requires the node to present.
    ///
    /// The authority on which identities are acceptable stays in
    /// `ExpectedDomIdentityV1::validate`; the cheap label check performed at
    /// decode time only fails earlier and never widens it.
    pub fn expected_identity(&self) -> ExpectedDomIdentityV1 {
        ExpectedDomIdentityV1 {
            network: self.network.clone(),
            network_magic: self.network_magic,
            chain_id: self.chain_id,
            genesis_hash: self.genesis_hash,
            protocol_version: self.protocol_version,
            range_proof_serialization_version: self.range_proof_serialization_version,
        }
    }

    /// Builds the single authenticated client for this node.
    ///
    /// The credential is passed in because it is read once, out of band, by the
    /// composition root; this boundary never reaches for it. The local identity
    /// must exactly equal the threshold-authenticated registry deployment and
    /// is revalidated before the client is built; no network call happens here.
    /// Both client deadlines must fit inside the exact runtime external-call
    /// authority supplied by the composition root.
    pub(crate) fn into_dom_chain_adapter(
        self,
        bearer: BearerTokenV1,
        deployment: DomDeploymentV1,
        external_call_timeout_ms: u64,
    ) -> Result<DomHttpChainAdapterV1, ProductionConfigErrorV1> {
        if external_call_timeout_ms == 0
            || self.connect_timeout_ms > external_call_timeout_ms
            || self.request_timeout_ms > external_call_timeout_ms
        {
            return Err(ProductionConfigErrorV1::InvalidNodeBounds);
        }
        let runtime = deployment.runtime_identity;
        let expected = ExpectedDomIdentityV1 {
            network: runtime.network.label().to_owned(),
            network_magic: runtime.network_magic,
            chain_id: deployment.chain_id.0,
            genesis_hash: deployment.genesis_hash,
            protocol_version: runtime.protocol_version,
            range_proof_serialization_version: runtime.range_proof_serialization_version,
        };
        if self.expected_identity() != expected {
            return Err(ProductionConfigErrorV1::InvalidNodeIdentity);
        }
        expected
            .validate()
            .map_err(|_| ProductionConfigErrorV1::InvalidNodeIdentity)?;
        DomHttpChainAdapterV1::new(
            self.endpoint.as_str(),
            expected,
            bearer,
            Duration::from_millis(self.connect_timeout_ms),
            Duration::from_millis(self.request_timeout_ms),
        )
        .map_err(|_| ProductionConfigErrorV1::NodeClientUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT: &str = "http://127.0.0.1:18332/rpc";

    fn bounds() -> ProductionNodeBoundsV1 {
        ProductionNodeBoundsV1 {
            connect_timeout_ms: 2_000,
            request_timeout_ms: 30_000,
            history_limit: 4_096,
        }
    }

    fn node_config() -> ProductionNodeConfigV1 {
        ProductionNodeConfigV1::from_parts(
            DomNodeEndpointV1::new(ENDPOINT).expect("the fixture endpoint is canonical"),
            ProductionNodeIdentityV1 {
                network: "regtest".to_owned(),
                network_magic: 0x4455_6677,
                chain_id: [0x31; 32],
                genesis_hash: [0x32; 32],
                protocol_version: 1,
                range_proof_serialization_version: 0,
            },
            bounds(),
        )
        .expect("the fixture node configuration is canonical")
    }

    #[test]
    fn node_config_round_trips_and_refuses_one_tampered_byte() {
        let config = node_config();
        let encoded = config.canonical_bytes().expect("the node config encodes");
        assert!(encoded.ends_with(b"end=1\n"));
        assert!((encoded.len() as u64) < MAX_PRODUCTION_NODE_CONFIG_BYTES_V1);
        let decoded =
            ProductionNodeConfigV1::decode_canonical(&encoded).expect("the node config decodes");
        assert!(decoded == config);

        // A zero-serialization version is canonical and must survive the round
        // trip: only a leading zero is refused.
        assert!(encoded
            .windows(b"dom_range_proof_serialization_version=0\n".len())
            .any(|window| window == b"dom_range_proof_serialization_version=0\n"));

        let text = String::from_utf8(encoded).expect("the node config is ASCII");
        let tampered = text.replacen("18332", "18333", 1);
        assert_eq!(tampered.len(), text.len());
        assert_eq!(
            ProductionNodeConfigV1::decode_canonical(tampered.as_bytes()).unwrap_err(),
            ProductionConfigErrorV1::IntegrityMismatch
        );
    }

    #[test]
    fn node_config_refuses_non_canonical_numbers() {
        let text =
            String::from_utf8(node_config().canonical_bytes().unwrap()).expect("ASCII encoding");
        for (from, to) in [
            ("dom_history_limit=4096", "dom_history_limit=04096"),
            (
                "dom_range_proof_serialization_version=0",
                "dom_range_proof_serialization_version=00",
            ),
        ] {
            let mutated = text.replacen(from, to, 1);
            assert_ne!(mutated, text);
            assert_eq!(
                ProductionNodeConfigV1::decode_canonical(mutated.as_bytes()).unwrap_err(),
                ProductionConfigErrorV1::InvalidNodeBounds
            );
        }
    }

    #[test]
    fn endpoints_with_credentials_query_fragment_or_public_http_are_refused() {
        for refused in [
            "http://user@127.0.0.1:18332/rpc",
            "http://127.0.0.1:18332/rpc?token=1",
            "http://127.0.0.1:18332/rpc#fragment",
            "http://example.test:18332/rpc",
            "http://10.0.0.5/rpc",
            "ftp://127.0.0.1/rpc",
            "127.0.0.1:18332",
            "http://",
            "http://127.0.0.1:18332/rp c",
            "",
        ] {
            assert_eq!(
                DomNodeEndpointV1::new(refused).unwrap_err(),
                ProductionConfigErrorV1::InvalidNodeEndpoint,
                "{refused} must never be accepted as a DOM endpoint"
            );
        }
        for accepted in [
            "http://127.0.0.1:18332/rpc",
            "http://localhost/rpc",
            "http://[::1]:18332/",
            "https://dom-node.example/rpc",
        ] {
            DomNodeEndpointV1::new(accepted)
                .unwrap_or_else(|_| panic!("{accepted} must be accepted"));
        }
        assert_eq!(
            DomNodeEndpointV1::new(&format!(
                "https://host/{}",
                "a".repeat(MAX_DOM_NODE_ENDPOINT_BYTES_V1)
            ))
            .unwrap_err(),
            ProductionConfigErrorV1::InvalidNodeEndpoint
        );
    }

    #[test]
    fn network_labels_and_bounds_are_bounded_and_lowercase() {
        for label in ["", "Regtest", "reg test", "regtest!", &"a".repeat(17)] {
            assert_eq!(
                validate_network_label(label).unwrap_err(),
                ProductionConfigErrorV1::InvalidNodeIdentity
            );
        }
        validate_network_label("regtest").expect("a canonical label is accepted");

        for (bounds, expected) in [
            (
                ProductionNodeBoundsV1 {
                    connect_timeout_ms: 0,
                    ..bounds()
                },
                ProductionConfigErrorV1::InvalidNodeBounds,
            ),
            (
                ProductionNodeBoundsV1 {
                    connect_timeout_ms: 40_000,
                    request_timeout_ms: 30_000,
                    ..bounds()
                },
                ProductionConfigErrorV1::InvalidNodeBounds,
            ),
            (
                ProductionNodeBoundsV1 {
                    history_limit: 0,
                    ..bounds()
                },
                ProductionConfigErrorV1::InvalidNodeBounds,
            ),
        ] {
            assert_eq!(bounds.validate().unwrap_err(), expected);
        }
    }

    #[cfg(feature = "production")]
    fn registry_bound_node_fixture() -> (ProductionNodeConfigV1, DomDeploymentV1) {
        let network = deployment_registry::DomNetworkV1::Regtest;
        let network_magic = network.canonical_magic();
        let genesis = dom_core::configured_genesis_hash_for_network_magic(network_magic)
            .expect("the regtest genesis is configured");
        let chain_id = kaystra_core::types::ChainId(
            *dom_consensus::derive_chain_id(network_magic, &genesis).as_bytes(),
        );
        let runtime_identity = deployment_registry::DomRuntimeIdentityV1::pinned(network);
        let deployment = DomDeploymentV1 {
            chain_id,
            genesis_hash: *genesis.as_bytes(),
            runtime_identity,
            consensus_rules_digest: [0x71; 32],
            scriptless_api_version: 1,
            timing: adapter_btc::timelock::ChainTimingBoundsV1 {
                min_block_seconds: 1,
                max_block_seconds: 2,
                max_reorg_seconds: 20,
                observation_seconds: 2,
                broadcast_seconds: 2,
            },
            finality: kaystra_core::types::FinalityPolicyV1 {
                min_confirmations: 2,
                max_reorg_depth: 3,
            },
            native_asset: kaystra_core::types::AssetId([0x72; 32]),
        };
        let config = ProductionNodeConfigV1::from_parts(
            DomNodeEndpointV1::new(ENDPOINT).expect("the fixture endpoint is canonical"),
            ProductionNodeIdentityV1 {
                network: network.label().to_owned(),
                network_magic,
                chain_id: chain_id.0,
                genesis_hash: *genesis.as_bytes(),
                protocol_version: runtime_identity.protocol_version,
                range_proof_serialization_version: runtime_identity
                    .range_proof_serialization_version,
            },
            bounds(),
        )
        .expect("the registry-bound node configuration is canonical");
        (config, deployment)
    }

    #[test]
    #[cfg(feature = "production")]
    fn dom_client_deadlines_cannot_outlive_the_runtime_authority() {
        let (config, deployment) = registry_bound_node_fixture();
        let token = BearerTokenV1::new("bounded-dom-token".to_owned())
            .expect("the fixture bearer is canonical");
        assert_eq!(
            config
                .into_dom_chain_adapter(token, deployment, 29_999)
                .err(),
            Some(ProductionConfigErrorV1::InvalidNodeBounds)
        );
        let (config, deployment) = registry_bound_node_fixture();
        let token = BearerTokenV1::new("bounded-dom-token".to_owned())
            .expect("the fixture bearer is canonical");
        assert!(config
            .into_dom_chain_adapter(token, deployment, 30_000)
            .is_ok());

        let (config, mut deployment) = registry_bound_node_fixture();
        deployment.genesis_hash = [0x73; 32];
        let token = BearerTokenV1::new("bounded-dom-token".to_owned())
            .expect("the fixture bearer is canonical");
        assert_eq!(
            config
                .into_dom_chain_adapter(token, deployment, 30_000)
                .err(),
            Some(ProductionConfigErrorV1::InvalidNodeIdentity)
        );
    }

    fn canonical_secret_stream() -> Vec<u8> {
        let mut stream = Vec::new();
        stream.extend_from_slice(b"dom-node-token\n");
        stream.extend_from_slice(&[b'a'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
        stream.push(b'\n');
        stream.extend_from_slice(&[b'e'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
        stream.extend_from_slice(b"\ncontracts-passphrase");
        stream.push(b'\n');
        stream.extend_from_slice(b"dom-wallet-passphrase\n");
        stream.extend_from_slice(&[b'd'; BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1]);
        stream.push(b'\n');
        stream.extend_from_slice(&[b'b'; ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1]);
        stream.push(b'\n');
        stream.extend_from_slice(&[b'c'; REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1]);
        stream
    }

    fn canonical_secret_stream_v2_with(evm_hex: u8) -> Vec<u8> {
        let mut stream = canonical_secret_stream();
        stream.push(b'\n');
        stream.extend_from_slice(&[evm_hex; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
        stream
    }

    fn canonical_secret_stream_v3(upstream: &[u8], downstream: &[u8]) -> Vec<u8> {
        let mut stream = PRODUCTION_SECRET_STREAM_HEADER_V3.to_vec();
        stream.push(b'\n');
        stream.extend_from_slice(&canonical_secret_stream_v2_with(b'f'));
        stream.extend_from_slice(b"\nupstream_f6_hsm_credentials=");
        stream.extend_from_slice(upstream.len().to_string().as_bytes());
        for credential in upstream {
            stream.push(b'\n');
            stream.extend_from_slice(&[*credential; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
        }
        stream.extend_from_slice(b"\ndownstream_f6_hsm_credentials=");
        stream.extend_from_slice(downstream.len().to_string().as_bytes());
        for credential in downstream {
            stream.push(b'\n');
            stream.extend_from_slice(&[*credential; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
        }
        stream
    }

    #[test]
    fn secret_stream_versions_are_exact_and_v2_adds_one_independent_owner() {
        let v1 = canonical_secret_stream();
        let v2 = canonical_secret_stream_v2_with(b'f');

        let Err(v1_refusal) = read_production_secret_fields(v2.as_slice()) else {
            panic!("V1 must never reinterpret a V2 stream");
        };
        assert_eq!(v1_refusal, ProductionConfigErrorV1::SecretStreamFieldCount);
        let Err(v2_refusal) = read_production_secret_fields_v2(v1.as_slice()) else {
            panic!("V2 must never fall back to a V1 stream");
        };
        assert_eq!(
            v2_refusal,
            ProductionSecretsV2ErrorV1::Common(ProductionConfigErrorV1::SecretStreamFieldCount)
        );
        let Ok(fields) = read_production_secret_fields_v2(v2.as_slice()) else {
            panic!("the exact nine-field V2 stream must be accepted");
        };
        assert_eq!(*fields.evm_signing_secret, [0xff; 32]);
        assert_eq!(fields.common.bearer.as_slice(), b"dom-node-token");
    }

    #[test]
    fn v2_evm_key_refuses_malformed_reused_and_oversized_material() {
        for &evm_hex in b"aedbc" {
            let stream = canonical_secret_stream_v2_with(evm_hex);
            let Err(refusal) = read_production_secret_fields_v2(stream.as_slice()) else {
                panic!("cross-role EVM key reuse must be refused");
            };
            assert_eq!(
                refusal,
                ProductionSecretsV2ErrorV1::EvmSigningSecretMalformed
            );
        }

        let mut trailing = canonical_secret_stream_v2_with(b'f');
        trailing.push(b'\n');
        let Err(refusal) = read_production_secret_fields_v2(trailing.as_slice()) else {
            panic!("a trailing field must be refused");
        };
        assert_eq!(
            refusal,
            ProductionSecretsV2ErrorV1::Common(ProductionConfigErrorV1::SecretStreamFieldCount)
        );

        for replacement in [vec![b'0'; 64], vec![b'F'; 64], vec![b'f'; 63]] {
            let mut malformed = canonical_secret_stream();
            malformed.push(b'\n');
            malformed.extend_from_slice(&replacement);
            let Err(refusal) = read_production_secret_fields_v2(malformed.as_slice()) else {
                panic!("malformed EVM material must be refused");
            };
            assert_eq!(
                refusal,
                ProductionSecretsV2ErrorV1::EvmSigningSecretMalformed
            );
        }

        let oversized = vec![b'a'; MAX_PRODUCTION_SECRET_STREAM_BYTES_V2 + 1];
        let Err(refusal) = read_production_secret_fields_v2(oversized.as_slice()) else {
            panic!("an oversized V2 stream must be refused before parsing");
        };
        assert_eq!(
            refusal,
            ProductionSecretsV2ErrorV1::Common(ProductionConfigErrorV1::SecretStreamOversized)
        );
    }

    #[test]
    fn v3_hsm_stream_is_versioned_nonempty_fixed_bounded_and_exact() {
        let canonical = canonical_secret_stream_v3(b"12", b"34");
        let Ok(fields) = read_production_secret_fields_v3(canonical.as_slice()) else {
            panic!("the exact V3 HSM stream must be accepted");
        };
        assert_eq!(fields.upstream_f6_hsm_credentials.len(), 2);
        assert_eq!(fields.downstream_f6_hsm_credentials.len(), 2);
        assert_eq!(*fields.upstream_f6_hsm_credentials[0], [0x11; 32]);
        assert_eq!(*fields.downstream_f6_hsm_credentials[1], [0x44; 32]);

        let Err(old_family) =
            read_production_secret_fields_v3(canonical_secret_stream_v2_with(b'f').as_slice())
        else {
            panic!("V3 must not fall back to V2");
        };
        assert_eq!(old_family, ProductionSecretsV3ErrorV1::WrongVersion);

        let mut wrong_version = canonical.clone();
        wrong_version[PRODUCTION_SECRET_STREAM_HEADER_V3.len() - 1] = b'2';
        let Err(version_refusal) = read_production_secret_fields_v3(wrong_version.as_slice())
        else {
            panic!("a different literal version must be refused");
        };
        assert_eq!(version_refusal, ProductionSecretsV3ErrorV1::WrongVersion);

        let mut trailing = canonical.clone();
        trailing.push(b'\n');
        let Err(trailing_refusal) = read_production_secret_fields_v3(trailing.as_slice()) else {
            panic!("trailing bytes must be refused");
        };
        assert_eq!(trailing_refusal, ProductionSecretsV3ErrorV1::FieldCount);

        let missing = &canonical[..canonical.len() - RELAY_SIGNING_SECRET_HEX_BYTES_V1];
        let Err(missing_refusal) = read_production_secret_fields_v3(missing) else {
            panic!("a missing fixed credential must be refused");
        };
        assert!(matches!(
            missing_refusal,
            ProductionSecretsV3ErrorV1::FieldCount
                | ProductionSecretsV3ErrorV1::HsmCredentialMalformed
        ));

        let oversized = vec![b'x'; MAX_PRODUCTION_SECRET_STREAM_BYTES_V3 + 1];
        let Err(oversized_refusal) = read_production_secret_fields_v3(oversized.as_slice()) else {
            panic!("an oversized V3 stream must be refused before parsing");
        };
        assert_eq!(
            oversized_refusal,
            ProductionSecretsV3ErrorV1::Common(ProductionSecretsV2ErrorV1::Common(
                ProductionConfigErrorV1::SecretStreamOversized
            ))
        );
    }

    #[test]
    fn v3_hsm_counts_and_cross_authority_credential_reuse_are_refused() {
        for malformed in ["0", "00", "01", "17", "x"] {
            let canonical = canonical_secret_stream_v3(b"12", b"34");
            let text = String::from_utf8(canonical).expect("fixture is ASCII");
            let mutated = text.replacen(
                "upstream_f6_hsm_credentials=2",
                &format!("upstream_f6_hsm_credentials={malformed}"),
                1,
            );
            let Err(refusal) = read_production_secret_fields_v3(mutated.as_bytes()) else {
                panic!("a zero, non-canonical or out-of-bound count must be refused");
            };
            assert_eq!(refusal, ProductionSecretsV3ErrorV1::HsmCredentialCount);
        }

        for (upstream, downstream) in [
            (&b"11"[..], &b"34"[..]),
            (&b"12"[..], &b"23"[..]),
            (&b"a2"[..], &b"34"[..]),
            (&b"12"[..], &b"f4"[..]),
        ] {
            let stream = canonical_secret_stream_v3(upstream, downstream);
            let Err(refusal) = read_production_secret_fields_v3(stream.as_slice()) else {
                panic!("credential reuse across signer, leg or authority must be refused");
            };
            assert_eq!(refusal, ProductionSecretsV3ErrorV1::HsmCredentialReused);
        }

        let text =
            String::from_utf8(canonical_secret_stream_v3(b"12", b"34")).expect("fixture is ASCII");
        let passphrase_reuse = text
            .replacen("contracts-passphrase", &"z".repeat(32), 1)
            .replacen(&"1".repeat(64), &"7a".repeat(32), 1);
        let Err(refusal) = read_production_secret_fields_v3(passphrase_reuse.as_bytes()) else {
            panic!("HSM reuse of a variable-length authority must be refused");
        };
        assert_eq!(refusal, ProductionSecretsV3ErrorV1::HsmCredentialReused);

        let malformed = canonical_secret_stream_v3(b"Z2", b"34");
        let Err(refusal) = read_production_secret_fields_v3(malformed.as_slice()) else {
            panic!("non-lowercase-hex credential must be refused");
        };
        assert_eq!(refusal, ProductionSecretsV3ErrorV1::HsmCredentialMalformed);
    }

    #[test]
    fn secret_stream_is_bounded_non_empty_and_requires_end_of_input() {
        // No `unwrap_err` on **this** reader — the module uses it freely on the
        // config and endpoint types, which carry nothing secret — and the
        // reason is a property rather than a style: `Result::unwrap_err` needs
        // `Debug` on the **success** type to format the value it did not
        // expect, and the success type here is the one carrying all eight
        // secrets. Deriving `Debug` on it to satisfy a test would put a
        // formatter on a type that exists in order not to have one, which is
        // the defect we closed in `counterparty-api` reintroduced by us for
        // test convenience. The let-else below asserts the same thing and
        // formats nothing, and
        // `the_secret_carrier_has_no_formatter_and_cannot_be_duplicated` keeps
        // the absence from being undone.
        let Err(error) = read_production_secret_fields(&b""[..]) else {
            panic!("an empty stream must be refused");
        };
        assert_eq!(error, ProductionConfigErrorV1::SecretStreamUnavailable);

        let canonical = canonical_secret_stream();
        let fields = read_production_secret_fields(canonical.as_slice())
            .expect("the canonical eight-field stream is accepted");
        assert_eq!(fields.bearer.as_slice(), b"dom-node-token");
        assert_eq!(*fields.upstream_relay_signing_secret, [0xaa_u8; 32]);
        assert_eq!(*fields.downstream_relay_signing_secret, [0xee_u8; 32]);
        assert_eq!(
            fields.identity_passphrase.as_slice(),
            b"contracts-passphrase"
        );
        assert_eq!(
            fields.dom_wallet_passphrase.as_slice(),
            b"dom-wallet-passphrase"
        );
        assert_eq!(*fields.bitcoin_participant_secret, [0xdd_u8; 32]);
        assert_eq!(*fields.route_secret_seal_key, [0xbb_u8; 32]);
        assert_eq!(*fields.refund_arming_credential, [0xcc_u8; 32]);

        // Each field keeps its own bound. The bearer at its bound is accepted
        // inside a stream whose total is larger, which is the whole point of
        // not widening `MAX_DOM_NODE_BEARER_BYTES_V1` into a stream bound.
        let mut at_bound = Vec::new();
        at_bound.extend_from_slice(&[b'a'; MAX_DOM_NODE_BEARER_BYTES_V1]);
        at_bound.push(b'\n');
        at_bound.extend_from_slice(&[b'a'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
        at_bound.push(b'\n');
        at_bound.extend_from_slice(&[b'e'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
        at_bound.extend_from_slice(b"\npassphrase");
        at_bound.push(b'\n');
        at_bound.extend_from_slice(b"wallet-passphrase\n");
        at_bound.extend_from_slice(&[b'd'; BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1]);
        at_bound.push(b'\n');
        at_bound.extend_from_slice(&[b'b'; ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1]);
        at_bound.push(b'\n');
        at_bound.extend_from_slice(&[b'c'; REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1]);
        assert!(read_production_secret_fields(at_bound.as_slice()).is_ok());

        let mut past_field_bound = at_bound.clone();
        past_field_bound.insert(0, b'a');
        let Err(error) = read_production_secret_fields(past_field_bound.as_slice()) else {
            panic!("a bearer past its own bound must be refused");
        };
        assert_eq!(error, ProductionConfigErrorV1::BearerMaterialMalformed);

        // Past the stream bound the read never reaches a field at all: the
        // writer failed to close its end and that is a stream refusal, not a
        // field one.
        let past_stream_bound = vec![b'a'; MAX_PRODUCTION_SECRET_STREAM_BYTES_V1 + 1];
        let Err(error) = read_production_secret_fields(past_stream_bound.as_slice()) else {
            panic!("a stream past its bound must be refused");
        };
        assert_eq!(error, ProductionConfigErrorV1::SecretStreamOversized);
    }

    /// The replacement for `bearer_material_refuses_any_line_terminator_or_control_byte`.
    ///
    /// That test existed to prove that no whitespace could hide inside the one
    /// secret, and it enforced it at the stream: **any** ASCII control byte
    /// anywhere was malformed, with `echo`'s trailing newline named as the
    /// commonest cause. With eight fields the newline is the separator, so the
    /// stream can no longer carry that rule and the rule moves to the field,
    /// which is where the guarantee always lived. It is replaced, not dropped:
    /// the same four attacks are exercised below, one field at a time, and the
    /// two that are newlines now surface as an exact-count refusal — a
    /// different name for the same refusal.
    #[test]
    fn secret_fields_refuse_every_control_byte_and_the_count_is_exact() {
        // `\r`, `\t` and a NUL inside a field: still malformed material, named
        // per field so the operator learns which one is wrong.
        for (bearer, refusal) in [
            (
                &b"dom\rnode"[..],
                ProductionConfigErrorV1::BearerMaterialMalformed,
            ),
            (
                &b"dom\tnode"[..],
                ProductionConfigErrorV1::BearerMaterialMalformed,
            ),
            (
                &b"dom\0node"[..],
                ProductionConfigErrorV1::BearerMaterialMalformed,
            ),
        ] {
            let mut stream = bearer.to_vec();
            stream.push(b'\n');
            stream.extend_from_slice(&[b'a'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'e'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.extend_from_slice(b"\npassphrase");
            stream.push(b'\n');
            stream.extend_from_slice(b"wallet-passphrase\n");
            stream.extend_from_slice(&[b'd'; BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'b'; ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'c'; REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1]);
            let Err(error) = read_production_secret_fields(stream.as_slice()) else {
                panic!("a control byte inside a field must be refused");
            };
            assert_eq!(error, refusal);
        }

        // The same control byte in the passphrase is the passphrase's refusal,
        // never the bearer's: an error table that lies about which field failed
        // is worse than no error table.
        let mut wrong_passphrase = b"dom-node-token\n".to_vec();
        wrong_passphrase.extend_from_slice(&[b'a'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
        wrong_passphrase.push(b'\n');
        wrong_passphrase.extend_from_slice(&[b'e'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
        wrong_passphrase.extend_from_slice(b"\npassphrase\ttail\n");
        wrong_passphrase.extend_from_slice(b"wallet-passphrase\n");
        wrong_passphrase.extend_from_slice(&[b'd'; BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1]);
        wrong_passphrase.push(b'\n');
        wrong_passphrase.extend_from_slice(&[b'b'; ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1]);
        wrong_passphrase.push(b'\n');
        wrong_passphrase.extend_from_slice(&[b'c'; REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1]);
        let Err(error) = read_production_secret_fields(wrong_passphrase.as_slice()) else {
            panic!("a control byte inside the passphrase must be refused");
        };
        assert_eq!(error, ProductionConfigErrorV1::IdentityPassphraseMalformed);

        // The count is exact in both directions, and a trailing newline is an
        // extra field rather than a tolerated flourish. This is where `echo`
        // now lands.
        let mut trailing = canonical_secret_stream();
        trailing.push(b'\n');
        for malformed in [
            &b"only-one-field"[..],
            &b"two\nfields"[..],
            trailing.as_slice(),
        ] {
            let Err(error) = read_production_secret_fields(malformed) else {
                panic!("a field count other than eight must be refused");
            };
            assert_eq!(error, ProductionConfigErrorV1::SecretStreamFieldCount);
        }
    }

    #[test]
    fn relay_signing_secret_requires_exactly_sixty_four_lowercase_hex() {
        // The secret never leaves its zeroizing owner here either, and the
        // refusals below are bound by let-else rather than unwrapped, for the
        // same reason the stream tests are: an assertion that formats the
        // success value is one line away from formatting a credential, and a
        // test is the first place someone copies a habit from.
        let with = |secret: &[u8]| {
            let mut stream = b"dom-node-token\n".to_vec();
            stream.extend_from_slice(secret);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'e'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.extend_from_slice(b"\npassphrase");
            stream.push(b'\n');
            stream.extend_from_slice(b"wallet-passphrase\n");
            stream.extend_from_slice(&[b'd'; BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'b'; ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'c'; REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1]);
            read_production_secret_fields(stream.as_slice())
        };
        let Ok(canonical) =
            with(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        else {
            panic!("canonical lowercase hex must be accepted");
        };
        assert_eq!(
            canonical.upstream_relay_signing_secret[..4],
            [0x01, 0x23, 0x45, 0x67]
        );
        for malformed in [
            &b"0000000000000000000000000000000000000000000000000000000000000000"[..],
            &b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"[..],
            // Uppercase is a second spelling of one secret and is refused.
            &b"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"[..],
            // One character short, one long, and a non-hex character.
            &b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"[..],
            &b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"[..],
            &b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"[..],
        ] {
            let Err(error) = with(malformed) else {
                panic!("a secret that is not exactly 64 lowercase hex must be refused");
            };
            assert_eq!(error, ProductionConfigErrorV1::RelaySigningSecretMalformed);
        }
    }

    #[test]
    fn dom_wallet_passphrase_is_utf8_bounded_and_independent() {
        let with = |wallet: &[u8]| {
            let mut stream = b"dom-node-token\n".to_vec();
            stream.extend_from_slice(&[b'a'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'e'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.extend_from_slice(b"\nidentity-passphrase\n");
            stream.extend_from_slice(wallet);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'd'; BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'b'; ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'c'; REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1]);
            read_production_secret_fields(stream.as_slice())
        };
        assert!(with(b"wallet-passphrase").is_ok());
        for malformed in [
            &b""[..],
            &b"identity-passphrase"[..],
            &b"wallet\tpassphrase"[..],
            &[0xff_u8][..],
        ] {
            let Err(error) = with(malformed) else {
                panic!("malformed or reused DOM wallet passphrase must be refused");
            };
            assert_eq!(error, ProductionConfigErrorV1::DomWalletPassphraseMalformed);
        }
        let oversized = vec![b'w'; MAX_DOM_WALLET_PASSPHRASE_BYTES_V1 + 1];
        let Err(error) = with(&oversized) else {
            panic!("oversized DOM wallet passphrase must be refused");
        };
        assert_eq!(error, ProductionConfigErrorV1::DomWalletPassphraseMalformed);
    }

    #[test]
    fn bitcoin_participant_secret_is_nonzero_canonical_and_separate_from_relay() {
        let with = |bitcoin: &[u8]| {
            let mut stream = b"dom-node-token\n".to_vec();
            stream.extend_from_slice(&[b'a'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'e'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.extend_from_slice(b"\nidentity-passphrase\nwallet-passphrase\n");
            stream.extend_from_slice(bitcoin);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'b'; ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'c'; REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1]);
            read_production_secret_fields(stream.as_slice())
        };
        assert!(with(&[b'd'; BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1]).is_ok());
        for malformed in [
            &b"0000000000000000000000000000000000000000000000000000000000000000"[..],
            &b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[..],
            &b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"[..],
            &b"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"[..],
            &b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"[..],
            &b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"[..],
        ] {
            let Err(error) = with(malformed) else {
                panic!("invalid Bitcoin participant secret must be refused");
            };
            assert_eq!(
                error,
                ProductionConfigErrorV1::BitcoinParticipantSecretMalformed
            );
        }
    }

    #[test]
    fn route_secret_seal_key_is_non_zero_canonical_and_independent() {
        let with = |seal_key: &[u8]| {
            let mut stream = b"dom-node-token\n".to_vec();
            stream.extend_from_slice(&[b'a'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'e'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.extend_from_slice(b"\npassphrase\nwallet-passphrase\n");
            stream.extend_from_slice(&[b'd'; BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(seal_key);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'c'; REFUND_ARMING_CREDENTIAL_HEX_BYTES_V1]);
            read_production_secret_fields(stream.as_slice())
        };

        let Ok(canonical) =
            with(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        else {
            panic!("an independent non-zero lowercase seal key must be accepted");
        };
        assert_eq!(
            canonical.route_secret_seal_key[..4],
            [0x01, 0x23, 0x45, 0x67]
        );

        for malformed in [
            &b"0000000000000000000000000000000000000000000000000000000000000000"[..],
            &b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[..],
            &b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"[..],
            &b"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"[..],
            &b"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"[..],
            &b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"[..],
            &b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"[..],
        ] {
            let Err(error) = with(malformed) else {
                panic!("a zero, shared, or non-canonical seal key must be refused");
            };
            assert_eq!(error, ProductionConfigErrorV1::RouteSecretSealKeyMalformed);
        }
    }

    #[test]
    fn refund_arming_credential_is_non_zero_canonical_and_independent() {
        let with = |credential: &[u8]| {
            let mut stream = b"dom-node-token\n".to_vec();
            stream.extend_from_slice(&[b'a'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'e'; RELAY_SIGNING_SECRET_HEX_BYTES_V1]);
            stream.extend_from_slice(b"\npassphrase\nwallet-passphrase\n");
            stream.extend_from_slice(&[b'd'; BITCOIN_PARTICIPANT_SECRET_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(&[b'b'; ROUTE_SECRET_SEAL_KEY_HEX_BYTES_V1]);
            stream.push(b'\n');
            stream.extend_from_slice(credential);
            read_production_secret_fields(stream.as_slice())
        };

        let Ok(canonical) =
            with(b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        else {
            panic!("an independent non-zero lowercase refund credential must be accepted");
        };
        assert_eq!(
            canonical.refund_arming_credential[..4],
            [0x01, 0x23, 0x45, 0x67]
        );

        for malformed in [
            &b"0000000000000000000000000000000000000000000000000000000000000000"[..],
            &b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"[..],
            &b"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"[..],
            &b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"[..],
            &b"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"[..],
            &b"0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef"[..],
            &b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde"[..],
            &b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg"[..],
        ] {
            let Err(error) = with(malformed) else {
                panic!("a zero, shared, or non-canonical refund credential must be refused");
            };
            assert_eq!(
                error,
                ProductionConfigErrorV1::RefundArmingCredentialMalformed
            );
        }
    }

    #[test]
    fn node_config_codec_refuses_every_non_canonical_document() {
        let canonical =
            String::from_utf8(node_config().canonical_bytes().unwrap()).expect("ASCII encoding");
        let lines: Vec<&str> = canonical.trim_end_matches('\n').split('\n').collect();

        // Oversize is checked before anything is parsed.
        let mut oversize = canonical.clone().into_bytes();
        oversize.resize(MAX_PRODUCTION_NODE_CONFIG_BYTES_V1 as usize + 1, b'x');
        assert_eq!(
            ProductionNodeConfigV1::decode_canonical(&oversize).unwrap_err(),
            ProductionConfigErrorV1::NodeConfigUnavailable
        );

        // Wrong header, unknown key, reordered lines, a missing line, bytes
        // after the terminator, a missing terminator and a carriage return are
        // all the same refusal: this document is not the canonical one.
        let reordered = {
            let mut swapped = lines.clone();
            swapped.swap(2, 3);
            format!("{}\n", swapped.join("\n"))
        };
        let missing_line = {
            let mut dropped = lines.clone();
            dropped.remove(4);
            format!("{}\n", dropped.join("\n"))
        };
        let missing_terminator = {
            let mut dropped = lines.clone();
            dropped.pop();
            format!("{}\n", dropped.join("\n"))
        };
        for mutated in [
            canonical.replacen("DOM-INTEROPD-NODE-V1", "DOM-INTEROPD-NODE-V2", 1),
            canonical.replacen("dom_network=", "dom_netwerk=", 1),
            reordered,
            missing_line,
            missing_terminator,
            format!("{canonical}unexpected=1\n"),
            canonical.replacen("\n", "\r\n", 1),
        ] {
            assert_ne!(mutated, canonical);
            assert_eq!(
                ProductionNodeConfigV1::decode_canonical(mutated.as_bytes()).unwrap_err(),
                ProductionConfigErrorV1::InvalidCanonicalEncoding,
                "non-canonical document accepted: {mutated}"
            );
        }
    }

    /// The secret carrier may never grow a formatter, a copy or a clone.
    ///
    /// This is the property that makes `unwrap_err` unavailable in the eight
    /// stream tests above, and it is asserted here so that the connection is
    /// not lost: `Result::unwrap_err` wants `Debug` on the success type, the
    /// success type holds eight credentials, and the cheapest way to make a
    /// test compile would be to derive `Debug` on it. Then the value would be
    /// one `{:?}` away from a log line. `Clone` and `Copy` are refused for the
    /// neighbouring reason — a secret that can be duplicated silently has no
    /// single owner to wipe it.
    #[test]
    fn the_secret_carrier_has_no_formatter_and_cannot_be_duplicated() {
        static_assertions::assert_not_impl_any!(
            ProductionSecretFieldsV1: core::fmt::Debug,
            Clone,
            Copy
        );
        static_assertions::assert_not_impl_any!(
            ProductionSecretFieldsV2: core::fmt::Debug,
            Clone,
            Copy
        );
        static_assertions::assert_not_impl_any!(
            ProductionSecretFieldsV3: core::fmt::Debug,
            Clone,
            Copy,
            serde::Serialize
        );
        #[cfg(feature = "production")]
        static_assertions::assert_not_impl_any!(
            ProductionRefundArmingCredentialV1: core::fmt::Debug,
            Clone,
            Copy
        );
        #[cfg(feature = "production")]
        static_assertions::assert_not_impl_any!(
            ProductionSecretPartsV1: core::fmt::Debug,
            Clone,
            Copy
        );
        #[cfg(feature = "production")]
        static_assertions::assert_not_impl_any!(
            ProductionSecretPartsV2: core::fmt::Debug,
            Clone,
            Copy
        );
        #[cfg(feature = "production")]
        static_assertions::assert_not_impl_any!(
            ProductionSecretsV3: core::fmt::Debug,
            Clone,
            Copy,
            serde::Serialize
        );
        #[cfg(feature = "production")]
        static_assertions::assert_not_impl_any!(
            ProductionSecretPartsV3: core::fmt::Debug,
            Clone,
            Copy,
            serde::Serialize
        );
    }

    #[test]
    fn node_boundary_types_expose_no_display_or_serialization_surface() {
        // Neither type may grow a surface that could print or serialize the
        // endpoint outside the redacted `Debug` written above.
        static_assertions::assert_not_impl_any!(
            ProductionNodeConfigV1: core::fmt::Display,
            serde::Serialize
        );
        static_assertions::assert_not_impl_any!(
            DomNodeEndpointV1: core::fmt::Display,
            serde::Serialize
        );
    }

    /// Endpoints the coarse prefilter refuses although the WHATWG parser would
    /// accept them.
    ///
    /// This asymmetry is deliberate and must not be "fixed" by relaxing the
    /// prefilter: a character scan is necessarily blunter than a parser, and the
    /// safe direction is to refuse more, never less. Only the implication is
    /// asserted for these rows — nothing is claimed about the client.
    #[cfg(feature = "production")]
    const ENDPOINT_STRICTER_BY_DESIGN_V1: [&str; 4] = [
        // `@` is legal inside a WHATWG path; the scan refuses it anywhere.
        "https://host/path@x",
        // The parser percent-encodes a raw space; the scan refuses it.
        "https://host/a b",
        // WHATWG maps `\` to `/` for special schemes; the scan refuses it.
        "https://host\\rpc",
        // IDNA: the parser accepts a unicode authority; the scan is ASCII-only.
        "https://caf\u{e9}.example/rpc",
    ];

    /// Fixed laboratory identity accepted by `ExpectedDomIdentityV1::validate`.
    ///
    /// The parity table varies only the endpoint, so every other argument of the
    /// client constructor is held at a value known to pass.
    #[cfg(feature = "production")]
    fn parity_identity() -> ExpectedDomIdentityV1 {
        let network_magic = dom_core::NETWORK_MAGIC_REGTEST;
        let genesis = dom_core::configured_genesis_hash_for_network_magic(network_magic)
            .expect("the regtest genesis is configured");
        ExpectedDomIdentityV1 {
            network: "regtest".to_owned(),
            network_magic,
            chain_id: *dom_consensus::derive_chain_id(network_magic, &genesis).as_bytes(),
            genesis_hash: *genesis.as_bytes(),
            protocol_version: dom_core::PROTOCOL_VERSION,
            range_proof_serialization_version: dom_crypto::RANGE_PROOF_SERIALIZATION_VERSION,
        }
    }

    #[cfg(feature = "production")]
    fn adapter_accepts(endpoint: &str) -> bool {
        DomHttpChainAdapterV1::new(
            endpoint,
            parity_identity(),
            BearerTokenV1::new("parity-token".to_owned()).expect("the parity token is canonical"),
            Duration::from_millis(2_000),
            Duration::from_millis(30_000),
        )
        .is_ok()
    }

    #[cfg(feature = "production")]
    fn early_accepts(endpoint: &str) -> bool {
        DomNodeEndpointV1::new(endpoint).is_ok()
    }

    /// The canonical rows, where both boundaries must agree exactly.
    #[cfg(feature = "production")]
    fn canonical_endpoint_rows() -> Vec<(String, bool)> {
        const PREFIX: &str = "https://host/";
        let at_bound = format!(
            "{PREFIX}{}",
            "a".repeat(MAX_DOM_NODE_ENDPOINT_BYTES_V1 - PREFIX.len())
        );
        let past_bound = format!("{at_bound}a");
        assert_eq!(at_bound.len(), MAX_DOM_NODE_ENDPOINT_BYTES_V1);
        vec![
            ("http://127.0.0.1:18332/rpc".to_owned(), true),
            ("http://127.0.0.1/rpc".to_owned(), true),
            ("http://127.0.0.2/rpc".to_owned(), true),
            ("http://localhost/rpc".to_owned(), true),
            ("http://LOCALHOST/rpc".to_owned(), true),
            ("http://[::1]:18332/rpc".to_owned(), true),
            ("http://[::1]/rpc".to_owned(), true),
            ("https://dom-node.example/rpc".to_owned(), true),
            ("https://127.0.0.1:18332/rpc".to_owned(), true),
            ("http://127.0.0.1:18332/rpc/".to_owned(), true),
            ("http://example.test/rpc".to_owned(), false),
            ("http://0.0.0.0/rpc".to_owned(), false),
            ("http://10.0.0.5/rpc".to_owned(), false),
            ("http://[2001:db8::1]/rpc".to_owned(), false),
            ("http://user@127.0.0.1/rpc".to_owned(), false),
            ("http://user:pw@127.0.0.1/rpc".to_owned(), false),
            ("http://127.0.0.1/rpc?token=1".to_owned(), false),
            ("http://127.0.0.1/rpc#frag".to_owned(), false),
            ("ftp://127.0.0.1/rpc".to_owned(), false),
            ("127.0.0.1:18332".to_owned(), false),
            ("http://".to_owned(), false),
            (String::new(), false),
            (at_bound, true),
            (past_bound, false),
        ]
    }

    #[test]
    #[cfg(feature = "production")]
    fn endpoint_prefilter_and_client_agree_on_the_canonical_table() {
        // Acceptance only. The client normalizes a trailing slash while the
        // prefilter keeps the exact input, so comparing the stored strings
        // would test the client's normalization, which is not this boundary's
        // responsibility. The bracketed IPv6 rows are the ones that used to
        // diverge; they are here so the recognition of an IPv6 loopback stays
        // proved on both sides, and the non-loopback row proves that widening
        // did not come with it.
        for (endpoint, expected) in canonical_endpoint_rows() {
            let early = early_accepts(&endpoint);
            let adapter = adapter_accepts(&endpoint);
            assert_eq!(early, expected, "prefilter disagreed on {endpoint}");
            assert_eq!(
                adapter, expected,
                "client constructor disagreed on {endpoint}"
            );
            assert_eq!(
                early, adapter,
                "prefilter and client diverged on {endpoint}"
            );
        }
    }

    #[test]
    #[cfg(feature = "production")]
    fn endpoint_prefilter_is_never_wider_than_the_client() {
        // The invariant, in the only direction that matters: whatever the
        // prefilter lets through, the client — the real authority — must also
        // accept. The converse is deliberately not required.
        for endpoint in ENDPOINT_STRICTER_BY_DESIGN_V1 {
            assert!(
                !early_accepts(endpoint),
                "the prefilter must stay strict on {endpoint}"
            );
        }
        let rows = canonical_endpoint_rows()
            .into_iter()
            .map(|(endpoint, _)| endpoint)
            .chain(
                ENDPOINT_STRICTER_BY_DESIGN_V1
                    .iter()
                    .map(|row| (*row).to_owned()),
            );
        for endpoint in rows {
            if early_accepts(&endpoint) {
                assert!(
                    adapter_accepts(&endpoint),
                    "the prefilter widened the client on {endpoint}"
                );
            }
        }
    }

    #[test]
    fn node_config_debug_never_discloses_the_credential_or_the_path() {
        let rendered = format!("{:?}", node_config());
        assert!(rendered.contains("http://127.0.0.1:18332"));
        assert!(!rendered.contains("/rpc"));
        let endpoint_rendered = format!("{:?}", node_config().endpoint());
        assert!(!endpoint_rendered.contains("/rpc"));
    }
}
