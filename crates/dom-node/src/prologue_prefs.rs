//! Per-peer Noise prologue version memory (spec A1, Strategy B).
//!
//! A Noise prologue is mixed into the handshake hash and never negotiated, so
//! a version mismatch only surfaces as an AEAD failure partway through the
//! handshake — for the responder, after it has already written message 2. No
//! recovery is possible on that TCP connection.
//!
//! What makes the transition work anyway is that both sides already retry
//! *connections*: the outbound dial loop treats a failed handshake as a
//! retryable failure and redials later. So the negotiation happens across
//! attempts instead of within one: start from the newest supported version,
//! and when a handshake fails, remember to try the next older version for
//! that peer on the following attempt. Two current nodes settle on the newest
//! version immediately and never pay a retry; a current node and an older one
//! pay exactly one failed attempt, once, and then remember each other.
//!
//! The first cross-version failure is expected, so it must not feed the ban
//! or cooldown machinery — that is the "responder does not penalise the first
//! failure" half of Strategy B. Only a peer that fails on *every* supported
//! version is treated as misbehaving.
//!
//! Memory is in-process only, keyed by IP. Losing it on restart is harmless:
//! the cost is one extra failed attempt per remembered peer, the same as
//! first contact.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use dom_wire::handshake::SUPPORTED_PROLOGUE_VERSIONS;

/// Cap on remembered peers. Entries are 20-odd bytes; the cap exists so a
/// hostile /16 cannot grow this map without bound. Eviction is whole-map:
/// fairness among evictees does not matter when the cost of forgetting is one
/// extra handshake attempt.
const MAX_TRACKED_PEERS: usize = 4096;

/// Remembers which prologue version to offer each peer next.
#[derive(Debug, Default)]
pub(crate) struct ProloguePreferences {
    by_ip: Mutex<HashMap<IpAddr, u32>>,
}

impl ProloguePreferences {
    /// The version to lead with for this peer: what memory says, or the
    /// newest supported version for a peer never seen (or long evicted).
    pub(crate) fn version_for(&self, ip: IpAddr) -> u32 {
        let newest = SUPPORTED_PROLOGUE_VERSIONS[0];
        match self.by_ip.lock() {
            Ok(map) => map.get(&ip).copied().unwrap_or(newest),
            Err(_) => newest,
        }
    }

    /// A handshake with `failed` just failed against this peer. Returns the
    /// next older version to try — recorded so the *next* connection (either
    /// direction) leads with it — or `None` when every supported version has
    /// been exhausted, at which point the failure is real misbehaviour and
    /// normal penalties apply.
    pub(crate) fn demote_after_failure(&self, ip: IpAddr, failed: u32) -> Option<u32> {
        let idx = SUPPORTED_PROLOGUE_VERSIONS
            .iter()
            .position(|v| *v == failed)?;
        match SUPPORTED_PROLOGUE_VERSIONS.get(idx + 1) {
            Some(next) => {
                if let Ok(mut map) = self.by_ip.lock() {
                    if map.len() >= MAX_TRACKED_PEERS && !map.contains_key(&ip) {
                        map.clear();
                    }
                    map.insert(ip, *next);
                }
                Some(*next)
            }
            None => {
                // Exhausted: every supported version produced a genuine AEAD
                // mismatch. Reset instead of pinning the oldest version — the
                // stored value would otherwise outlive whatever hostile or
                // broken speaker caused this and tax the next honest peer at
                // this IP forever.
                if let Ok(mut map) = self.by_ip.lock() {
                    map.remove(&ip);
                }
                None
            }
        }
    }

    /// A handshake completed with `version`; lead with it for this peer from
    /// now on. Skips the write when it would only restate the default — the
    /// map stays small on a network where everyone is already current.
    pub(crate) fn record_success(&self, ip: IpAddr, version: u32) {
        let newest = SUPPORTED_PROLOGUE_VERSIONS[0];
        if let Ok(mut map) = self.by_ip.lock() {
            if version == newest {
                map.remove(&ip);
            } else {
                if map.len() >= MAX_TRACKED_PEERS && !map.contains_key(&ip) {
                    map.clear();
                }
                map.insert(ip, version);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn unknown_peer_gets_the_newest_version() {
        let prefs = ProloguePreferences::default();
        assert_eq!(prefs.version_for(ip(1)), SUPPORTED_PROLOGUE_VERSIONS[0]);
    }

    #[test]
    fn failure_demotes_then_exhausts() {
        let prefs = ProloguePreferences::default();
        let newest = SUPPORTED_PROLOGUE_VERSIONS[0];
        let oldest = *SUPPORTED_PROLOGUE_VERSIONS.last().unwrap();

        let demoted = prefs.demote_after_failure(ip(2), newest).unwrap();
        assert_eq!(demoted, SUPPORTED_PROLOGUE_VERSIONS[1]);
        assert_eq!(
            prefs.version_for(ip(2)),
            demoted,
            "memory drives the next attempt"
        );

        // Walking off the end means every version failed: no further fallback.
        assert_eq!(prefs.demote_after_failure(ip(2), oldest), None);
    }

    #[test]
    fn success_on_an_old_version_is_remembered_and_newest_is_not() {
        let prefs = ProloguePreferences::default();
        let old = SUPPORTED_PROLOGUE_VERSIONS[1];
        prefs.record_success(ip(3), old);
        assert_eq!(prefs.version_for(ip(3)), old);

        // The peer upgraded: settling on the newest clears the entry.
        prefs.record_success(ip(3), SUPPORTED_PROLOGUE_VERSIONS[0]);
        assert_eq!(prefs.version_for(ip(3)), SUPPORTED_PROLOGUE_VERSIONS[0]);
    }

    #[test]
    fn unknown_failed_version_yields_no_fallback() {
        let prefs = ProloguePreferences::default();
        assert_eq!(prefs.demote_after_failure(ip(4), 999), None);
    }
}
