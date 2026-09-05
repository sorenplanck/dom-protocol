//! Automatic port mapping — UPnP IGD, then NAT-PMP (spec A3).
//!
//! This is the piece that makes a fresh wallet reachable with zero user
//! action: on boot the node asks the router to open its port. The model
//! deliberately copied is BitTorrent (mapping on by default), not Bitcoin
//! Core — Core shipped UPnP off because of parser CVEs in the C miniupnpc;
//! the crates used here are pure Rust, were checked against the RUSTSEC
//! advisory database before pinning, and every result still has to pass
//! [`mapping_is_usable`] before anything is announced.
//!
//! Hard rules, all from the spec:
//! - a bounded timeout per method — the boot must never hang on a router
//!   (§1.4);
//! - the result only feeds `advertised_port`; no mapping means announce 0
//!   and run as a leaf, which is not an error;
//! - an expired lease without a renewal goes back to announcing 0;
//! - `DOM_PORTMAP=off` disables everything (A6, R-A3.6);
//! - `DOM_ADVERTISED_PORT` set means the operator already knows the answer:
//!   mapping is skipped entirely.
//!
//! The mapped address is a *hypothesis* even when everything succeeds:
//! routers acknowledge mappings they never honour (R-A3.2). Reachability is
//! only believed once A4's dial-back — performed by some other node, from
//! the outside — confirms it. Nothing in this module marks anything
//! confirmed.

use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::time::Duration;

/// Per-method budget. §1.4: the boot must not block on a silent router, and
/// two methods in sequence still keep startup under ~10 s worst case.
pub(crate) const PER_METHOD_TIMEOUT: Duration = Duration::from_secs(5);

/// Lease requested from the gateway. Renewed at half-life by
/// [`renew_interval`].
pub(crate) const REQUESTED_LEASE_SECS: u32 = 3600;

/// What the mapping attempt produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mapping {
    /// UPnP IGD granted a mapping.
    Upnp {
        external_ip: IpAddr,
        external_port: u16,
        lease_secs: u32,
    },
    /// NAT-PMP granted a mapping.
    NatPmp {
        external_ip: IpAddr,
        external_port: u16,
        lease_secs: u32,
    },
    /// A gateway granted a mapping whose external address no one on the
    /// internet can reach (CGNAT, double NAT). Announcing it would be worse
    /// than not mapping: it poisons every peer's pool with a dead address
    /// that looks legitimate. Recorded distinctly because this count is the
    /// number that decides whether A7 (hole punching) is worth building.
    CgnatDetected,
    /// No method produced a mapping.
    None,
}

impl Mapping {
    /// The port to feed into `advertised_port` — the granted external port
    /// (never the requested one: the router may assign another, R-A3.4), or
    /// 0 when there is nothing reachable to announce.
    pub(crate) fn advertised_port(&self) -> u16 {
        match self {
            Mapping::Upnp { external_port, .. } | Mapping::NatPmp { external_port, .. } => {
                *external_port
            }
            Mapping::CgnatDetected | Mapping::None => 0,
        }
    }

    /// Label for `dom_portmap_status` (A5).
    pub(crate) fn status_label(&self) -> &'static str {
        match self {
            Mapping::Upnp { .. } => "upnp",
            Mapping::NatPmp { .. } => "natpmp",
            Mapping::CgnatDetected => "cgnat_detected",
            Mapping::None => "none",
        }
    }

    /// When to renew: half the granted lease, floored so a router granting a
    /// tiny lease cannot turn renewal into a busy loop. `None` when there is
    /// nothing to renew — the caller then re-attempts mapping at a slow
    /// cadence instead (which is also what recovers from a network change,
    /// R-A3.3, at that cadence rather than instantly).
    pub(crate) fn renew_interval(&self) -> Option<Duration> {
        match self {
            Mapping::Upnp { lease_secs, .. } | Mapping::NatPmp { lease_secs, .. } => {
                Some(Duration::from_secs(u64::from(*lease_secs / 2).max(60)))
            }
            Mapping::CgnatDetected | Mapping::None => None,
        }
    }
}

/// Whether a gateway-reported external address is worth announcing.
///
/// The most dangerous spot in the module (R-A3.5 included): behind CGNAT the
/// router SUCCESSFULLY maps a port on its WAN side — but that WAN is
/// 100.64.0.0/10 (RFC 6598) and unreachable from the internet.
pub(crate) fn mapping_is_usable(external_ip: IpAddr) -> bool {
    match external_ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || (o[0] == 100 && (64..128).contains(&o[1])) // RFC 6598 CGNAT
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_documentation())
        }
        IpAddr::V6(v6) => crate::pex::is_public_ipv6(v6),
    }
}

/// Try UPnP IGD, then NAT-PMP. Never fails the boot: every error path is a
/// `Mapping` variant, and both probes run under [`PER_METHOD_TIMEOUT`].
pub(crate) async fn try_map(internal_port: u16) -> Mapping {
    match tokio::time::timeout(PER_METHOD_TIMEOUT, try_upnp(internal_port)).await {
        Ok(Some(mapping)) => return classify(mapping),
        Ok(None) => {}
        Err(_) => tracing::debug!("UPnP discovery timed out"),
    }
    match tokio::time::timeout(PER_METHOD_TIMEOUT, try_natpmp(internal_port)).await {
        Ok(Some(mapping)) => classify(mapping),
        Ok(None) => Mapping::None,
        Err(_) => {
            tracing::debug!("NAT-PMP request timed out");
            Mapping::None
        }
    }
}

/// Gate every granted mapping through [`mapping_is_usable`].
fn classify(mapping: Mapping) -> Mapping {
    let external_ip = match mapping {
        Mapping::Upnp { external_ip, .. } | Mapping::NatPmp { external_ip, .. } => external_ip,
        other => return other,
    };
    if mapping_is_usable(external_ip) {
        mapping
    } else {
        tracing::info!(
            %external_ip,
            "gateway mapped a non-routable external address (CGNAT / double NAT); \
             announcing unreachable instead of poisoning the network's pools"
        );
        Mapping::CgnatDetected
    }
}

/// One UPnP IGD attempt. `None` covers every failure — no gateway on the
/// LAN, SOAP refusal, mapping conflict. R-A3.1 is why the crate choice
/// matters: SSDP discovery is multicast and any LAN device can answer
/// pretending to be the router, so the parser is hostile-input surface;
/// igd-next is pure Rust, shells out to nothing, and its answer still has
/// to pass `mapping_is_usable`.
async fn try_upnp(internal_port: u16) -> Option<Mapping> {
    use igd_next::aio::tokio::search_gateway;
    use igd_next::{PortMappingProtocol, SearchOptions};

    let gateway = match search_gateway(SearchOptions {
        timeout: Some(PER_METHOD_TIMEOUT),
        ..SearchOptions::default()
    })
    .await
    {
        Ok(g) => g,
        Err(e) => {
            tracing::debug!("no UPnP gateway: {e}");
            return None;
        }
    };

    // The LAN-facing address the mapping must point at: the source address
    // of a UDP socket "connected" toward the gateway. No packet is sent.
    let local_ip = local_ip_toward(gateway.addr).await?;
    let local = SocketAddr::new(local_ip, internal_port);

    // R-A3.4: ask for the same external port but announce what was actually
    // granted, which get_any_address reports and may differ.
    match gateway
        .get_any_address(
            PortMappingProtocol::TCP,
            local,
            REQUESTED_LEASE_SECS,
            "dom-node p2p",
        )
        .await
    {
        Ok(granted) => {
            let external_ip = match gateway.get_external_ip().await {
                Ok(ip) => ip,
                Err(e) => {
                    tracing::debug!("UPnP external IP query failed: {e}");
                    granted.ip()
                }
            };
            Some(Mapping::Upnp {
                external_ip,
                external_port: granted.port(),
                lease_secs: REQUESTED_LEASE_SECS,
            })
        }
        Err(e) => {
            tracing::debug!("UPnP mapping refused: {e}");
            None
        }
    }
}

/// One NAT-PMP attempt (RFC 6886) against the default gateway.
async fn try_natpmp(internal_port: u16) -> Option<Mapping> {
    use natpmp::{NatpmpAsync, Protocol, Response};

    let mut client: NatpmpAsync<tokio::net::UdpSocket> = match natpmp::new_tokio_natpmp().await {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!("no NAT-PMP gateway: {e}");
            return None;
        }
    };

    if let Err(e) = client
        .send_port_mapping_request(
            Protocol::TCP,
            internal_port,
            internal_port,
            REQUESTED_LEASE_SECS,
        )
        .await
    {
        tracing::debug!("NAT-PMP mapping request failed: {e}");
        return None;
    }
    let mapping = match client.read_response_or_retry().await {
        Ok(Response::TCP(m)) => m,
        Ok(other) => {
            tracing::debug!("unexpected NAT-PMP response: {other:?}");
            return None;
        }
        Err(e) => {
            tracing::debug!("NAT-PMP mapping refused: {e}");
            return None;
        }
    };

    if let Err(e) = client.send_public_address_request().await {
        tracing::debug!("NAT-PMP address request failed: {e}");
        return None;
    }
    let external_ip = match client.read_response_or_retry().await {
        Ok(Response::Gateway(g)) => IpAddr::V4(*g.public_address()),
        Ok(other) => {
            tracing::debug!("unexpected NAT-PMP address response: {other:?}");
            return None;
        }
        Err(e) => {
            tracing::debug!("NAT-PMP address query failed: {e}");
            return None;
        }
    };

    Some(Mapping::NatPmp {
        external_ip,
        // R-A3.4: the granted external port, never the requested one.
        external_port: mapping.public_port(),
        lease_secs: mapping.lifetime().as_secs().min(u64::from(u32::MAX)) as u32,
    })
}

/// The local address the OS would route toward `gateway` from — the address
/// a mapping must target. A "connected" UDP socket sends nothing; it only
/// makes the kernel pick the outbound interface.
async fn local_ip_toward(gateway: SocketAddr) -> Option<IpAddr> {
    let bind_any: SocketAddr = if gateway.is_ipv4() {
        SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
    };
    let socket = tokio::net::UdpSocket::bind(bind_any).await.ok()?;
    socket.connect(gateway).await.ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Is automatic mapping enabled? `DOM_PORTMAP` defaults to on — the
/// BitTorrent model, which is the one that actually produces reachable
/// nodes — and any of off/0/false disables it (R-A3.6: SSDP announces the
/// node's presence on the LAN, so opting out must be possible and cheap).
/// A manual `DOM_ADVERTISED_PORT` also disables mapping: the operator has
/// already answered the question this module asks.
pub(crate) fn portmap_enabled() -> bool {
    if std::env::var("DOM_ADVERTISED_PORT").is_ok() {
        return false;
    }
    match std::env::var("DOM_PORTMAP") {
        Ok(v) => !matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "off" | "0" | "false" | "no"
        ),
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §7: `cgnat_external_ip_is_not_usable`.
    #[test]
    fn cgnat_external_ip_is_not_usable() {
        assert!(!mapping_is_usable("100.64.0.1".parse().unwrap())); // RFC 6598
        assert!(!mapping_is_usable("100.127.255.254".parse().unwrap())); // RFC 6598 top
        assert!(!mapping_is_usable("192.168.1.1".parse().unwrap())); // RFC 1918
        assert!(!mapping_is_usable("10.0.0.1".parse().unwrap())); // RFC 1918
        assert!(!mapping_is_usable("127.0.0.1".parse().unwrap()));
        assert!(!mapping_is_usable("169.254.1.1".parse().unwrap())); // link-local
        assert!(!mapping_is_usable("0.0.0.0".parse().unwrap()));
        assert!(!mapping_is_usable("192.0.2.1".parse().unwrap())); // documentation
        assert!(mapping_is_usable("66.42.127.141".parse().unwrap()));
        // 100.0.0.1 and 100.128.0.1 sit just OUTSIDE 100.64.0.0/10 and are
        // ordinary routable space — the CGNAT check must not overreach.
        assert!(mapping_is_usable("100.0.0.1".parse().unwrap()));
        assert!(mapping_is_usable("100.128.0.1".parse().unwrap()));
        // v6: public unicast usable, ULA and documentation not.
        assert!(mapping_is_usable("2600:1f18::1".parse().unwrap()));
        assert!(!mapping_is_usable("fd00::1".parse().unwrap()));
        assert!(!mapping_is_usable("2001:db8::1".parse().unwrap()));
    }

    /// A granted-but-unroutable mapping must classify as CGNAT, announce 0,
    /// and carry the label that feeds `dom_portmap_status`.
    #[test]
    fn unroutable_grant_classifies_as_cgnat_and_announces_zero() {
        let granted = Mapping::NatPmp {
            external_ip: "100.64.7.9".parse().unwrap(),
            external_port: 33_369,
            lease_secs: 3600,
        };
        let classified = classify(granted);
        assert_eq!(classified, Mapping::CgnatDetected);
        assert_eq!(classified.advertised_port(), 0);
        assert_eq!(classified.status_label(), "cgnat_detected");
        assert_eq!(classified.renew_interval(), None);
    }

    #[test]
    fn usable_grant_announces_the_granted_port_and_renews_at_half_lease() {
        let granted = Mapping::Upnp {
            external_ip: "66.42.127.141".parse().unwrap(),
            // R-A3.4: the router may grant a different port than requested;
            // what is announced must be the grant.
            external_port: 45_123,
            lease_secs: 3600,
        };
        let classified = classify(granted);
        assert_eq!(classified.advertised_port(), 45_123);
        assert_eq!(classified.status_label(), "upnp");
        assert_eq!(classified.renew_interval(), Some(Duration::from_secs(1800)));
    }

    /// A router granting a pathological lease must not turn renewal into a
    /// busy loop.
    #[test]
    fn tiny_lease_renewal_is_floored() {
        let m = Mapping::NatPmp {
            external_ip: "66.42.127.141".parse().unwrap(),
            external_port: 33_369,
            lease_secs: 10,
        };
        assert_eq!(m.renew_interval(), Some(Duration::from_secs(60)));
    }
}
