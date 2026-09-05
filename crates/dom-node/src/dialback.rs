//! Dial-back reachability confirmation (spec A4).
//!
//! An inbound peer announcing `advertised_port = P` is only a *hypothesis*
//! about reachability — routers acknowledge mappings they never honour
//! (R-A3.2), and the peer may simply lie. The pool therefore keeps such an
//! address as an unconfirmed dial candidate, and this module closes the loop:
//! dial back to `source_ip:P`, and only a completed connection promotes the
//! address to confirmed — the only state PEX will ever gossip.
//!
//! The dial-back is also the most abusable primitive in Part A (R-A4.1): a
//! hub induced to dial arbitrary targets is a reflection amplifier. Every
//! mitigation here is load-bearing and none is optional:
//!
//! - the target IP is the TCP source address of the inbound connection,
//!   taken by the caller from the socket, never from any payload field;
//! - at most one dial-back per source IP per window;
//! - a global cap on concurrent dial-backs;
//! - a failed probe leaves the address unconfirmed, where the ordinary
//!   outbound cooldown machinery already applies — no tight retry.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Minimum spacing between dial-backs to the same source IP.
pub(crate) const DIALBACK_WINDOW: Duration = Duration::from_secs(600);

/// Global ceiling on in-flight dial-backs. Probes are short (one TCP
/// connect), so a small number is plenty; anything the cap defers is
/// re-attempted the next time the peer connects.
pub(crate) const MAX_CONCURRENT_DIALBACKS: u64 = 8;

/// Per-probe connect timeout. Bounded so a black-holed target cannot pin a
/// probe slot for the kernel's default connect timeout.
pub(crate) const DIALBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Cap on remembered source IPs, so a churning /16 cannot grow the window
/// map without bound. Eviction drops the oldest entries wholesale; the cost
/// of forgetting is one earlier-than-window re-probe.
const MAX_TRACKED_SOURCES: usize = 4096;

/// Admission control for dial-back probes.
#[derive(Debug, Default)]
pub(crate) struct DialbackLimiter {
    last_attempt: Mutex<HashMap<IpAddr, Instant>>,
    in_flight: AtomicU64,
}

/// Permission to run one probe; returned by [`DialbackLimiter::try_begin`].
/// Dropping it releases the concurrency slot even if the probe panics.
pub(crate) struct DialbackSlot<'a> {
    limiter: &'a DialbackLimiter,
}

impl Drop for DialbackSlot<'_> {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

impl DialbackLimiter {
    /// Ask to probe `source`. `None` means the probe is not allowed right
    /// now — inside the per-IP window, or at the global concurrency cap —
    /// and the caller simply skips it; the address stays unconfirmed, which
    /// is the safe state.
    pub(crate) fn try_begin(&self, source: IpAddr) -> Option<DialbackSlot<'_>> {
        {
            let mut map = self.last_attempt.lock().ok()?;
            let now = Instant::now();
            if let Some(last) = map.get(&source) {
                if now.duration_since(*last) < DIALBACK_WINDOW {
                    return None;
                }
            }
            if map.len() >= MAX_TRACKED_SOURCES && !map.contains_key(&source) {
                map.clear();
            }
            map.insert(source, now);
        }
        // Window recorded before the cap check on purpose: a probe refused by
        // the cap still consumed this peer's slot for the window. The
        // alternative lets a burst of peers retry the cap in a tight loop.
        let prev = self.in_flight.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_CONCURRENT_DIALBACKS {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(DialbackSlot { limiter: self })
    }

    #[cfg(test)]
    fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([198, 51, 100, last])
    }

    /// §7: `dialback_is_rate_limited_per_peer`.
    #[test]
    fn dialback_is_rate_limited_per_peer() {
        let limiter = DialbackLimiter::default();
        let first = limiter.try_begin(ip(1));
        assert!(first.is_some(), "first probe for a source is allowed");
        drop(first);
        assert!(
            limiter.try_begin(ip(1)).is_none(),
            "a second probe inside the window must be refused even though \
             the first already finished"
        );
        assert!(
            limiter.try_begin(ip(2)).is_some(),
            "the window is per source IP, not global"
        );
    }

    /// R-A4.1: the global concurrency ceiling holds, and slots free on drop.
    #[test]
    fn concurrent_dialbacks_are_capped_globally() {
        let limiter = DialbackLimiter::default();
        let mut slots = Vec::new();
        for n in 0..MAX_CONCURRENT_DIALBACKS {
            let slot = limiter.try_begin(ip(10 + n as u8));
            assert!(slot.is_some(), "probe {n} under the cap must be admitted");
            slots.push(slot);
        }
        assert!(
            limiter.try_begin(ip(200)).is_none(),
            "probe at the cap must be refused"
        );
        slots.clear();
        assert_eq!(limiter.in_flight(), 0, "drop must release every slot");
        assert!(
            limiter.try_begin(ip(201)).is_some(),
            "capacity returns once probes finish"
        );
    }

    /// §7: `dialback_never_targets_payload_supplied_ip` — enforced by
    /// construction: the limiter and the probe API only ever see the IP the
    /// caller took from the inbound socket, and nothing in this module reads
    /// a payload. This test pins the contract that admission is keyed by
    /// that source IP alone.
    #[test]
    fn dialback_admission_is_keyed_by_source_ip_only() {
        let limiter = DialbackLimiter::default();
        drop(limiter.try_begin(ip(1)));
        // A peer re-announcing different ports (payload-controlled data)
        // cannot mint additional probes: the key is the source address.
        assert!(limiter.try_begin(ip(1)).is_none());
    }
}
