//! Bounded TCP composition root for one authenticated production Relay link.
//!
//! The owner-only network sidecar remains the sole authority for both the
//! numeric socket address and the Noise XX role. This module opens exactly one
//! TCP connection per call, then delegates authentication and application
//! exchange to [`ProductionNoiseRelaySessionV1`]. No application byte is sent
//! before that session completes its existing authenticated Noise handshake.

use std::{
    io,
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use dom_scriptless_identity_store::ContractsTransportIdentityStoreV1;
use relay::production::ProductionRelayV1;

use crate::{
    production_noise_relay::{
        ProductionNoiseRelayErrorV1, ProductionNoiseRelayExchangeReportV1,
        ProductionNoiseRelaySessionV1,
    },
    production_relay_network_config::{
        ProductionRelayEndpointModeV1, ProductionRelayNetworkLinkV1,
    },
};

const MIN_SOCKET_TIMEOUT_V1: Duration = Duration::from_millis(25);
const MAX_SOCKET_TIMEOUT_V1: Duration = Duration::from_secs(300);
const ACCEPT_POLL_INTERVAL_V1: Duration = Duration::from_millis(5);

/// Redacted refusal from the bounded production Relay socket boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum ProductionRelayNetworkRuntimeErrorV1 {
    /// Timeout bounds or the session-to-sidecar binding were not exact.
    #[error("production Relay network runtime configuration is invalid")]
    InvalidConfiguration,
    /// The outbound socket could not connect within its fixed bound.
    #[error("production Relay outbound connection is unavailable")]
    ConnectUnavailable,
    /// The configured local socket could not be bound safely.
    #[error("production Relay listener is unavailable")]
    ListenUnavailable,
    /// No inbound peer arrived before the fixed accept deadline.
    #[error("production Relay accept deadline elapsed")]
    AcceptDeadlineElapsed,
    /// Noise authentication or the bounded application exchange failed.
    #[error("production Relay authenticated exchange failed")]
    AuthenticatedExchangeFailed,
    /// The authenticated channel could not complete within its deadline.
    #[error("production Relay authenticated channel is temporarily unavailable")]
    ChannelUnavailable,
    /// The retained local Relay could not complete one durable exchange step.
    #[error("production Relay durable exchange authority is temporarily unavailable")]
    DurableRelayUnavailable,
}

/// Independent bounds for establishing one production TCP link.
///
/// The authenticated session owns the separate end-to-end handshake/exchange
/// deadline. Keeping these values separate prevents a stalled accept or
/// connect from consuming an unbounded amount of supervisor time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionRelayNetworkBoundsV1 {
    connect_timeout: Duration,
    accept_timeout: Duration,
}

impl ProductionRelayNetworkBoundsV1 {
    pub(crate) fn new(
        connect_timeout: Duration,
        accept_timeout: Duration,
    ) -> Result<Self, ProductionRelayNetworkRuntimeErrorV1> {
        if !(MIN_SOCKET_TIMEOUT_V1..=MAX_SOCKET_TIMEOUT_V1).contains(&connect_timeout)
            || !(MIN_SOCKET_TIMEOUT_V1..=MAX_SOCKET_TIMEOUT_V1).contains(&accept_timeout)
        {
            return Err(ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration);
        }
        Ok(Self {
            connect_timeout,
            accept_timeout,
        })
    }
}

/// Stateless opener for one exact sidecar-selected Relay link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProductionRelayNetworkRuntimeV1 {
    bounds: ProductionRelayNetworkBoundsV1,
}

impl ProductionRelayNetworkRuntimeV1 {
    pub(crate) const fn new(bounds: ProductionRelayNetworkBoundsV1) -> Self {
        Self { bounds }
    }

    /// Opens exactly one configured TCP link and runs one authenticated,
    /// bounded bidirectional Relay exchange.
    pub(crate) fn exchange_configured_link(
        &self,
        link: &ProductionRelayNetworkLinkV1,
        session: &ProductionNoiseRelaySessionV1,
        identity: &ContractsTransportIdentityStoreV1,
        relay: &mut ProductionRelayV1,
    ) -> Result<ProductionNoiseRelayExchangeReportV1, ProductionRelayNetworkRuntimeErrorV1> {
        if !session.matches_network_binding(link.noise_role(), link.remote_relay_database_id()) {
            return Err(ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration);
        }

        let stream = match link.mode() {
            ProductionRelayEndpointModeV1::Connect => self.connect_with_deadline(link.address())?,
            ProductionRelayEndpointModeV1::Listen => self.accept_exactly_one(link.address())?,
        };

        session
            .exchange(identity, relay, stream)
            .map_err(map_authenticated_exchange_error)
    }

    fn connect_with_deadline(
        &self,
        address: std::net::SocketAddr,
    ) -> Result<TcpStream, ProductionRelayNetworkRuntimeErrorV1> {
        let deadline = Instant::now()
            .checked_add(self.bounds.connect_timeout)
            .ok_or(ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration)?;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(ProductionRelayNetworkRuntimeErrorV1::ConnectUnavailable);
            }
            match TcpStream::connect_timeout(&address, remaining) {
                Ok(stream) => return Ok(stream),
                Err(_) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ProductionRelayNetworkRuntimeErrorV1::ConnectUnavailable);
                    }
                    thread::sleep(remaining.min(ACCEPT_POLL_INTERVAL_V1));
                }
            }
        }
    }

    fn accept_exactly_one(
        &self,
        address: std::net::SocketAddr,
    ) -> Result<TcpStream, ProductionRelayNetworkRuntimeErrorV1> {
        let listener = TcpListener::bind(address)
            .map_err(|_| ProductionRelayNetworkRuntimeErrorV1::ListenUnavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ProductionRelayNetworkRuntimeErrorV1::ListenUnavailable)?;
        let deadline = Instant::now()
            .checked_add(self.bounds.accept_timeout)
            .ok_or(ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration)?;

        loop {
            match listener.accept() {
                Ok((stream, _peer)) => return Ok(stream),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed);
                    }
                    thread::sleep(remaining.min(ACCEPT_POLL_INTERVAL_V1));
                }
                Err(_) => {
                    return Err(ProductionRelayNetworkRuntimeErrorV1::ListenUnavailable);
                }
            }
        }
    }
}

fn map_authenticated_exchange_error(
    error: ProductionNoiseRelayErrorV1,
) -> ProductionRelayNetworkRuntimeErrorV1 {
    match error {
        ProductionNoiseRelayErrorV1::ChannelUnavailable => {
            ProductionRelayNetworkRuntimeErrorV1::ChannelUnavailable
        }
        ProductionNoiseRelayErrorV1::DurableRelayUnavailable => {
            ProductionRelayNetworkRuntimeErrorV1::DurableRelayUnavailable
        }
        ProductionNoiseRelayErrorV1::InvalidConfiguration
        | ProductionNoiseRelayErrorV1::IdentityAuthenticationFailed
        | ProductionNoiseRelayErrorV1::ProtocolRefused
        | ProductionNoiseRelayErrorV1::PeerRefused => {
            ProductionRelayNetworkRuntimeErrorV1::AuthenticatedExchangeFailed
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use cap_std::fs::Dir;
    use dom_scriptless_identity_store::{
        ContractsIdentityPassphraseV1, ContractsTransportIdentityReferenceV1,
    };
    use dom_scriptless_store::SessionTransportIdentityReferenceV1;
    use dom_scriptless_transport::NoiseRoleV1;
    use relay::production::{RelayDatabaseConfigV1, RelayDatabaseIdV1};
    use std::{
        error::Error,
        fs::File as AmbientFile,
        net::SocketAddr,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::Arc,
    };
    use tempfile::TempDir;

    use crate::production_noise_relay::{
        ProductionNoiseRelayDatabasePairV1, ProductionNoiseRelayRouteContextV1,
    };

    type TestResult = Result<(), Box<dyn Error + Send + Sync>>;

    const CHAIN: [u8; 32] = [0x11; 32];
    const NETWORK: [u8; 32] = [0x12; 32];
    const ROUTE: [u8; 32] = [0x13; 32];
    const SESSION: [u8; 32] = [0x14; 32];
    const ALICE: [u8; 32] = [0x21; 32];
    const BOB: [u8; 32] = [0x22; 32];
    const MALLORY: [u8; 32] = [0x23; 32];

    struct IdentityFixtureV1 {
        parent: Arc<Dir>,
        alice: ContractsTransportIdentityReferenceV1,
        bob: ContractsTransportIdentityReferenceV1,
        mallory: ContractsTransportIdentityReferenceV1,
    }

    fn passphrase() -> Result<ContractsIdentityPassphraseV1, Box<dyn Error + Send + Sync>> {
        Ok(ContractsIdentityPassphraseV1::new(
            b"production Relay network runtime test passphrase".to_vec(),
        )?)
    }

    fn identities(temporary: &TempDir) -> Result<IdentityFixtureV1, Box<dyn Error + Send + Sync>> {
        let parent = Arc::new(Dir::from_std_file(AmbientFile::open(temporary.path())?));
        let alice = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "runtime-alice-identity",
            &passphrase()?,
        )?;
        let bob = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "runtime-bob-identity",
            &passphrase()?,
        )?;
        let mallory = ContractsTransportIdentityStoreV1::create_production(
            Arc::clone(&parent),
            "runtime-mallory-identity",
            &passphrase()?,
        )?;
        Ok(IdentityFixtureV1 {
            parent,
            alice: *alice.reference(),
            bob: *bob.reference(),
            mallory: *mallory.reference(),
        })
    }

    fn database(marker: u8) -> Result<RelayDatabaseConfigV1, Box<dyn Error + Send + Sync>> {
        Ok(RelayDatabaseConfigV1::new(
            RelayDatabaseIdV1::new([marker; 32])?,
            16,
        )?)
    }

    fn session(
        role: NoiseRoleV1,
        local: SessionTransportIdentityReferenceV1,
        remote: SessionTransportIdentityReferenceV1,
        local_database: RelayDatabaseIdV1,
        remote_database: RelayDatabaseIdV1,
        timeout: Duration,
    ) -> Result<ProductionNoiseRelaySessionV1, ProductionNoiseRelayErrorV1> {
        ProductionNoiseRelaySessionV1::new(
            role,
            ProductionNoiseRelayRouteContextV1::new(CHAIN, NETWORK, ROUTE, SESSION)?,
            [local, remote],
            ProductionNoiseRelayDatabasePairV1::new(local_database, remote_database)?,
            timeout,
        )
    }

    fn unused_loopback_address() -> Result<SocketAddr, io::Error> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        drop(listener);
        Ok(address)
    }

    fn link(
        mode: ProductionRelayEndpointModeV1,
        address: SocketAddr,
        remote_database: RelayDatabaseIdV1,
    ) -> Result<ProductionRelayNetworkLinkV1, Box<dyn Error + Send + Sync>> {
        Ok(ProductionRelayNetworkLinkV1::new(
            mode,
            address,
            remote_database,
        )?)
    }

    fn relay_root(temporary: &TempDir, leaf: &str) -> PathBuf {
        temporary.path().join(leaf)
    }

    fn reopen_identity(
        parent: Arc<Dir>,
        leaf: &str,
    ) -> Result<ContractsTransportIdentityStoreV1, Box<dyn Error + Send + Sync>> {
        Ok(ContractsTransportIdentityStoreV1::open_production(
            parent,
            leaf,
            &passphrase()?,
        )?)
    }

    fn make_owner_directory(path: &Path) -> Result<(), io::Error> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }

    #[test]
    fn role_and_database_mismatch_fail_before_socket_effects() -> TestResult {
        let temporary = TempDir::new()?;
        make_owner_directory(temporary.path())?;
        let identities = identities(&temporary)?;
        let alice_database = database(0x41)?;
        let bob_database = database(0x42)?;
        let alice_root = relay_root(&temporary, "role-alice-relay");
        let mut alice_relay = ProductionRelayV1::create(&alice_root, alice_database)?;
        let identity = reopen_identity(Arc::clone(&identities.parent), "runtime-alice-identity")?;
        let address = unused_loopback_address()?;
        let runtime = ProductionRelayNetworkRuntimeV1::new(ProductionRelayNetworkBoundsV1::new(
            Duration::from_millis(50),
            Duration::from_millis(50),
        )?);
        let initiator = session(
            NoiseRoleV1::Initiator,
            identities.alice.bind_session_participant(ALICE)?,
            identities.bob.bind_session_participant(BOB)?,
            alice_database.database_id(),
            bob_database.database_id(),
            Duration::from_millis(100),
        )?;

        let wrong_role = link(
            ProductionRelayEndpointModeV1::Listen,
            address,
            bob_database.database_id(),
        )?;
        assert_eq!(
            runtime
                .exchange_configured_link(&wrong_role, &initiator, &identity, &mut alice_relay,)
                .expect_err("independent role substitution must fail"),
            ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration
        );
        assert!(TcpListener::bind(address).is_ok());

        let wrong_database = link(
            ProductionRelayEndpointModeV1::Connect,
            address,
            RelayDatabaseIdV1::new([0x43; 32])?,
        )?;
        assert_eq!(
            runtime
                .exchange_configured_link(&wrong_database, &initiator, &identity, &mut alice_relay,)
                .expect_err("peer database substitution must fail"),
            ProductionRelayNetworkRuntimeErrorV1::InvalidConfiguration
        );
        Ok(())
    }

    #[test]
    fn listener_without_peer_returns_at_its_deadline() -> TestResult {
        let temporary = TempDir::new()?;
        make_owner_directory(temporary.path())?;
        let identities = identities(&temporary)?;
        let alice_database = database(0x51)?;
        let bob_database = database(0x52)?;
        let bob_root = relay_root(&temporary, "timeout-bob-relay");
        let mut bob_relay = ProductionRelayV1::create(&bob_root, bob_database)?;
        let identity = reopen_identity(Arc::clone(&identities.parent), "runtime-bob-identity")?;
        let address = unused_loopback_address()?;
        let runtime = ProductionRelayNetworkRuntimeV1::new(ProductionRelayNetworkBoundsV1::new(
            Duration::from_millis(50),
            Duration::from_millis(50),
        )?);
        let responder = session(
            NoiseRoleV1::Responder,
            identities.bob.bind_session_participant(BOB)?,
            identities.alice.bind_session_participant(ALICE)?,
            bob_database.database_id(),
            alice_database.database_id(),
            Duration::from_millis(100),
        )?;
        let listen = link(
            ProductionRelayEndpointModeV1::Listen,
            address,
            alice_database.database_id(),
        )?;
        let started = Instant::now();
        assert_eq!(
            runtime
                .exchange_configured_link(&listen, &responder, &identity, &mut bob_relay)
                .expect_err("listener must not wait forever"),
            ProductionRelayNetworkRuntimeErrorV1::AcceptDeadlineElapsed
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        Ok(())
    }

    #[test]
    fn authenticated_local_pair_succeeds_and_wrong_peer_identity_fails_closed() -> TestResult {
        let temporary = TempDir::new()?;
        make_owner_directory(temporary.path())?;
        let identities = identities(&temporary)?;
        let alice_database = database(0x61)?;
        let bob_database = database(0x62)?;
        let alice_root = relay_root(&temporary, "pair-alice-relay");
        let bob_root = relay_root(&temporary, "pair-bob-relay");
        let _alice_relay = ProductionRelayV1::create(&alice_root, alice_database)?;
        let _bob_relay = ProductionRelayV1::create(&bob_root, bob_database)?;
        drop(_alice_relay);
        drop(_bob_relay);
        let address = unused_loopback_address()?;
        let bounds = ProductionRelayNetworkBoundsV1::new(
            Duration::from_millis(250),
            Duration::from_millis(250),
        )?;
        let listener_link = link(
            ProductionRelayEndpointModeV1::Listen,
            address,
            alice_database.database_id(),
        )?;
        let connector_link = link(
            ProductionRelayEndpointModeV1::Connect,
            address,
            bob_database.database_id(),
        )?;

        let responder_parent = Arc::clone(&identities.parent);
        let responder_alice = identities.alice;
        let responder_bob = identities.bob;
        let responder_root = bob_root.clone();
        let responder =
            thread::spawn(move || -> TestResult {
                let identity = reopen_identity(responder_parent, "runtime-bob-identity")?;
                let mut relay = ProductionRelayV1::open(&responder_root, bob_database)?;
                let session = session(
                    NoiseRoleV1::Responder,
                    responder_bob.bind_session_participant(BOB)?,
                    responder_alice.bind_session_participant(ALICE)?,
                    bob_database.database_id(),
                    alice_database.database_id(),
                    Duration::from_secs(2),
                )?;
                let report = ProductionRelayNetworkRuntimeV1::new(bounds)
                    .exchange_configured_link(&listener_link, &session, &identity, &mut relay)?;
                assert_eq!(report.pages_sent, 1);
                assert_eq!(report.pages_received, 1);
                Ok(())
            });
        thread::sleep(Duration::from_millis(20));
        let identity = reopen_identity(Arc::clone(&identities.parent), "runtime-alice-identity")?;
        let mut relay = ProductionRelayV1::open(&alice_root, alice_database)?;
        let initiator = session(
            NoiseRoleV1::Initiator,
            identities.alice.bind_session_participant(ALICE)?,
            identities.bob.bind_session_participant(BOB)?,
            alice_database.database_id(),
            bob_database.database_id(),
            Duration::from_secs(2),
        )?;
        let report = ProductionRelayNetworkRuntimeV1::new(bounds).exchange_configured_link(
            &connector_link,
            &initiator,
            &identity,
            &mut relay,
        )?;
        assert_eq!(report.pages_sent, 1);
        assert_eq!(report.pages_received, 1);
        responder
            .join()
            .map_err(|_| io::Error::other("runtime responder panicked"))??;
        drop(relay);
        drop(identity);

        let wrong_address = unused_loopback_address()?;
        let wrong_listener = link(
            ProductionRelayEndpointModeV1::Listen,
            wrong_address,
            alice_database.database_id(),
        )?;
        let wrong_connector = link(
            ProductionRelayEndpointModeV1::Connect,
            wrong_address,
            bob_database.database_id(),
        )?;
        let wrong_parent = Arc::clone(&identities.parent);
        let wrong_alice = identities.alice;
        let wrong_bob = identities.bob;
        let wrong_root = bob_root;
        let wrong_responder = thread::spawn(move || -> TestResult {
            let identity = reopen_identity(wrong_parent, "runtime-bob-identity")?;
            let mut relay = ProductionRelayV1::open(&wrong_root, bob_database)?;
            let session = session(
                NoiseRoleV1::Responder,
                wrong_bob.bind_session_participant(BOB)?,
                wrong_alice.bind_session_participant(ALICE)?,
                bob_database.database_id(),
                alice_database.database_id(),
                Duration::from_millis(500),
            )?;
            assert_eq!(
                ProductionRelayNetworkRuntimeV1::new(bounds)
                    .exchange_configured_link(&wrong_listener, &session, &identity, &mut relay)
                    .expect_err("unexpected initiator identity must fail Noise authentication"),
                ProductionRelayNetworkRuntimeErrorV1::AuthenticatedExchangeFailed
            );
            Ok(())
        });
        thread::sleep(Duration::from_millis(20));
        let identity = reopen_identity(identities.parent, "runtime-mallory-identity")?;
        let mut relay = ProductionRelayV1::open(&alice_root, alice_database)?;
        let impostor = session(
            NoiseRoleV1::Initiator,
            identities.mallory.bind_session_participant(MALLORY)?,
            identities.bob.bind_session_participant(BOB)?,
            alice_database.database_id(),
            bob_database.database_id(),
            Duration::from_millis(500),
        )?;
        // The rejected initiator must fail closed. Which refusal it observes
        // depends on TCP timing: it either completes enough of the handshake
        // to fail its own Noise authentication, or reads the responder's
        // slammed connection first. The security-critical exact assertion is
        // the responder-side one in `wrong_responder`.
        assert!(matches!(
            ProductionRelayNetworkRuntimeV1::new(bounds)
                .exchange_configured_link(&wrong_connector, &impostor, &identity, &mut relay)
                .expect_err("peer identity substitution must fail"),
            ProductionRelayNetworkRuntimeErrorV1::AuthenticatedExchangeFailed
                | ProductionRelayNetworkRuntimeErrorV1::ChannelUnavailable
        ));
        wrong_responder
            .join()
            .map_err(|_| io::Error::other("wrong-peer responder panicked"))??;
        Ok(())
    }
}
