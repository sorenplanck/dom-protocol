//! Production-shaped construction of the XMR sink inside `RealDomEffectSinkV1`.

#![forbid(unsafe_code)]

use adapter_dom_real::RealDomEffectSinkV1;
use std::path::PathBuf;
use xmr_delivery_sqlite::SqliteDeliveryStore;
use xmr_kaystra_bridge::XmrClaimToSpendSink;
use xmr_live_sidecar_uds_client::BlockingUdsSidecarPort;
use xmr_refund_policy::ValidatedRefundPolicy;
use xmr_rpc_broadcast_blocking::BlockingMoneroBroadcaster;
use xmr_secret_store::{EncryptedSqliteSecretStore, SecretStoreError, SecretStoreMasterKey};
use xmr_setup_profile::ValidatedXmrSetup;
use xmr_sidecar_auth::{SidecarAuthError, SidecarAuthKey};

/// Sidecar transport. UDS is preferred on Linux.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XmrSidecarTransport {
    /// Permissioned Unix-domain socket.
    Unix(PathBuf),
    /// Loopback HTTP fallback.
    LoopbackHttp(String),
}

/// Runtime configuration. Debug redacts both keys.
pub struct XmrRuntimeConfig {
    /// Encrypted local-key database.
    pub secret_store_path: PathBuf,
    /// Exact signed-transaction delivery database.
    pub delivery_store_path: PathBuf,
    /// Authenticated sidecar transport.
    pub sidecar_transport: XmrSidecarTransport,
    /// Loopback monerod base URL.
    pub monerod_url: String,
    /// External encryption key; never persisted by the store.
    pub secret_store_master_key: [u8; 32],
    /// Sidecar HMAC key.
    pub sidecar_auth_key: [u8; 32],
}

impl core::fmt::Debug for XmrRuntimeConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("XmrRuntimeConfig")
            .field("secret_store_path", &self.secret_store_path)
            .field("delivery_store_path", &self.delivery_store_path)
            .field("sidecar_transport", &self.sidecar_transport)
            .field("monerod_url", &self.monerod_url)
            .field("secret_store_master_key", &"<redacted>")
            .field("sidecar_auth_key", &"<redacted>")
            .finish()
    }
}

/// Wiring failures.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeWiringError {
    /// Secret-store construction failed.
    #[error("XMR secret store: {0}")]
    Secret(#[from] SecretStoreError),
    /// Sidecar authentication key failed.
    #[error("XMR sidecar authentication: {0}")]
    Auth(#[from] SidecarAuthError),
    /// Delivery store failed.
    #[error("XMR delivery store unavailable")]
    Delivery,
    /// Sidecar/broadcaster port failed.
    #[error("XMR runtime port rejected configuration")]
    Port,
    /// The refund policy admitted before funding is not production-capable, so
    /// the claim-to-sweep consumer must not be installed for a live route.
    #[error("XMR refund policy is not production-capable")]
    RefundNotProductionCapable,
    /// Loopback HTTP cannot authenticate its local peer (`SO_PEERCRED` does
    /// not exist for TCP), so it must never carry the spend scalar in a
    /// production-shaped composition. Use the permissioned Unix socket.
    #[error("XMR loopback-HTTP sidecar transport cannot authenticate its peer")]
    LoopbackHttpNotPeerAuthenticated,
}

/// Installs the XMR secret-consumer bridge into the real DOM effect sink.
pub fn attach_xmr_consumer(
    sink: RealDomEffectSinkV1,
    setup: ValidatedXmrSetup,
    refund_policy: &ValidatedRefundPolicy,
    config: XmrRuntimeConfig,
) -> Result<RealDomEffectSinkV1, RuntimeWiringError> {
    // The claim-to-sweep consumer must never be installed on a route whose
    // refund path is only cooperative-laboratory: if the DOM claim never
    // happens, the XMR funder would have no independently enforceable recovery.
    // `production_capable()` is true only when a concrete non-cooperative
    // refund executor validated the frozen artifact in `admit_refund_policy`.
    if !refund_policy.production_capable() {
        return Err(RuntimeWiringError::RefundNotProductionCapable);
    }
    let secrets = EncryptedSqliteSecretStore::open(
        &config.secret_store_path,
        SecretStoreMasterKey::new(config.secret_store_master_key)?,
    )?;
    let delivery = SqliteDeliveryStore::open(&config.delivery_store_path)
        .map_err(|_| RuntimeWiringError::Delivery)?;
    let broadcaster =
        BlockingMoneroBroadcaster::new(config.monerod_url).map_err(|_| RuntimeWiringError::Port)?;
    let auth = SidecarAuthKey::new(config.sidecar_auth_key)?;
    match config.sidecar_transport {
        XmrSidecarTransport::Unix(path) => {
            let sidecar =
                BlockingUdsSidecarPort::new(path, auth).map_err(|_| RuntimeWiringError::Port)?;
            let bridge = XmrClaimToSpendSink::new(setup, secrets, delivery, sidecar, broadcaster);
            Ok(sink.with_revealed_secret_sink(Box::new(bridge)))
        }
        // Loopback TCP has no `SO_PEERCRED`: a local port squatter cannot be
        // told apart from the sidecar before the request — and with it the
        // spend scalar — is transmitted, and a key-possession handshake can
        // be relayed across connections. The scalar-carrying transport in a
        // production-shaped composition is therefore the permissioned Unix
        // socket only; the HTTP client remains for laboratory harnesses that
        // construct it directly.
        XmrSidecarTransport::LoopbackHttp(_) => {
            Err(RuntimeWiringError::LoopbackHttpNotPeerAuthenticated)
        }
    }
}
