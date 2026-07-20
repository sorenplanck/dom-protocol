//! Peer connection manager — eclipse attack protection.
//!
//! Enforces:
//! - MIN_OUTBOUND = 8 connections to different /16 subnets
//! - MAX_INBOUND = 125
//! - MAX_PEERS_SAME_SLASH_16 = 2 (eclipse protection)
//! - Feeler connections for peer discovery

use crate::peer::{PeerInfo, PeerState};
use dom_core::DomError;
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Maximum peers from the same /16 subnet (eclipse protection).
const MAX_PEERS_SAME_SLASH_16: usize = 2;
/// Pre-registration penalties expire after this interval.
const PENDING_PENALTY_TTL_SECS: u64 = 15 * 60;
/// Bound memory used by hostile pre-registration address churn.
const MAX_PENDING_PENALTIES: usize = 4_096;
/// Duplicate block relays above this rate are treated as abusive.
const MAX_DUPLICATE_BLOCK_RELAYS_PER_WINDOW: u32 = 32;
/// Duplicate block relay rate window.
const DUPLICATE_BLOCK_RELAY_WINDOW_SECS: u64 = 30;
/// Bound runtime memory used by outbound failure history.
const MAX_OUTBOUND_FAILURE_TRACKERS: usize = 4_096;
/// Bound address aliases learned for authenticated Noise PeerIds.
const MAX_KNOWN_PEER_ALIASES: usize = 4_096;
const MAX_PEER_ROTATION_ADDR_BYTES: usize = 256;
const MAX_PERSISTED_PEER_REPUTATION_ENTRIES: usize = MAX_PENDING_PENALTIES;
const MAX_OUTBOUND_FAILURE_COOLDOWN_ROUNDS: u8 = 16;

/// Shared outbound reconnect policy for discovered, backbone, and configured
/// bootstrap peers. This is operational scheduling state only; consensus
/// validity remains decided by chain and message validation.
pub const OUTBOUND_RECONNECT_POLICY: RetryBackoffPolicy = RetryBackoffPolicy {
    initial_delay_secs: 5,
    max_delay_secs: 5 * 60,
    jitter: RetryJitterPolicy::DeterministicAddress { max_jitter_secs: 5 },
    reset_after_stable_session_secs: 2 * 60,
    max_in_flight_attempts: 8,
};

/// Backoff jitter policy. Network reconnect jitter must be deterministic per
/// peer so replay snapshots do not depend on process-local RNG.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryJitterPolicy {
    /// No jitter.
    None,
    /// Add `hash(addr) % (max_jitter_secs + 1)` seconds.
    DeterministicAddress {
        /// Inclusive maximum jitter in seconds.
        max_jitter_secs: u64,
    },
}

/// Bounded retry/backoff configuration shared by outbound reconnect paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryBackoffPolicy {
    /// Delay after the first retryable failure.
    pub initial_delay_secs: u64,
    /// Maximum backoff delay after repeated retryable failures.
    pub max_delay_secs: u64,
    /// Jitter policy applied to the computed delay.
    pub jitter: RetryJitterPolicy,
    /// Connected sessions at least this old clear retry history.
    pub reset_after_stable_session_secs: u64,
    /// Maximum concurrent outbound attempts across peers.
    pub max_in_flight_attempts: usize,
}

impl RetryBackoffPolicy {
    /// Compute the bounded backoff delay after `failures` retryable failures.
    pub fn delay_after_failures(self, addr: &str, failures: u8) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }

        let exponent = failures.saturating_sub(1).min(31) as u32;
        let base = self
            .initial_delay_secs
            .saturating_mul(1u64.checked_shl(exponent).unwrap_or(u64::MAX))
            .min(self.max_delay_secs);
        let jitter = match self.jitter {
            RetryJitterPolicy::None => 0,
            RetryJitterPolicy::DeterministicAddress { max_jitter_secs } => {
                deterministic_addr_jitter(addr, max_jitter_secs)
            }
        };
        Duration::from_secs(base.saturating_add(jitter).min(self.max_delay_secs))
    }

    fn cooldown_rounds_after_failure(self, addr: &str, failures: u8, pass_secs: u64) -> u8 {
        let pass_secs = pass_secs.max(1);
        let delay_secs = self.delay_after_failures(addr, failures).as_secs();
        let rounds = delay_secs.div_ceil(pass_secs).saturating_add(1);
        rounds.min(MAX_OUTBOUND_FAILURE_COOLDOWN_ROUNDS as u64) as u8
    }
}

#[derive(Debug, Clone, Copy)]
struct PendingInbound {
    reserved_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct PendingOutbound {
    reserved_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct PendingPenalty {
    score: u32,
    last_updated: Instant,
}

#[derive(Debug, Clone, Copy)]
struct DuplicateRelayTracker {
    count: u32,
    window_started: Instant,
}

#[derive(Debug, Clone, Copy)]
struct OutboundFailureTracker {
    failures: u8,
    last_failure_seq: u64,
    cooldown_rounds: u8,
}

/// Persisted outbound failure entry used for deterministic restart replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedOutboundFailure {
    /// Canonical string form of the peer address.
    pub addr: String,
    /// Saturating failure count tracked for retry ordering.
    pub failures: u8,
    /// Monotonic sequence of the last recorded failure.
    pub last_failure_seq: u64,
    /// Remaining deterministic connector passes to skip before retrying.
    pub cooldown_rounds: u8,
}

/// Bounded deterministic peer-rotation snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistedPeerRotationState {
    /// Next monotonic failure sequence to allocate.
    pub next_failure_seq: u64,
    /// Outbound failure history sorted canonically by address.
    pub outbound_failures: Vec<PersistedOutboundFailure>,
}

/// Persisted peer reputation entry used for restart-safe ban/score recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedPeerReputation {
    /// Canonical string form of the peer address.
    pub addr: String,
    /// Saturating ban score tracked for restart-safe policy enforcement.
    pub score: u32,
}

/// Bounded deterministic peer-reputation snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistedPeerReputationState {
    /// Peer reputation entries sorted canonically by address.
    pub entries: Vec<PersistedPeerReputation>,
}

impl DomSerialize for PersistedPeerRotationState {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u64(self.next_failure_seq);
        let len: u32 = self
            .outbound_failures
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("peer rotation entry count exceeds u32".into()))?;
        w.write_u32(len);
        for entry in &self.outbound_failures {
            w.write_vec(entry.addr.as_bytes())?;
            w.write_u8(entry.failures);
            w.write_u64(entry.last_failure_seq);
            w.write_u8(entry.cooldown_rounds);
        }
        Ok(())
    }
}

impl DomDeserialize for PersistedPeerRotationState {
    const MIN_SERIALIZED_SIZE: usize = 8 + 4;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let next_failure_seq = r.read_u64()?;
        let len = r.read_u32()? as usize;
        if len > MAX_OUTBOUND_FAILURE_TRACKERS {
            return Err(DomError::Malformed(format!(
                "peer rotation entry count {len} exceeds limit {MAX_OUTBOUND_FAILURE_TRACKERS}"
            )));
        }
        let mut outbound_failures = Vec::with_capacity(len);
        for _ in 0..len {
            let addr = String::from_utf8(r.read_vec(MAX_PEER_ROTATION_ADDR_BYTES)?)
                .map_err(|e| DomError::Malformed(format!("peer rotation addr utf8: {e}")))?;
            let failures = r.read_u8()?;
            let last_failure_seq = r.read_u64()?;
            let cooldown_rounds = r.read_u8()?;
            outbound_failures.push(PersistedOutboundFailure {
                addr,
                failures,
                last_failure_seq,
                cooldown_rounds,
            });
        }
        Ok(Self {
            next_failure_seq,
            outbound_failures,
        })
    }
}

impl PersistedPeerRotationState {
    /// Decode the pre-cooldown snapshot format for persistence-safe upgrades.
    pub fn from_legacy_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        let mut r = Reader::new(bytes);
        let next_failure_seq = r.read_u64()?;
        let len = r.read_u32()? as usize;
        if len > MAX_OUTBOUND_FAILURE_TRACKERS {
            return Err(DomError::Malformed(format!(
                "peer rotation entry count {len} exceeds limit {MAX_OUTBOUND_FAILURE_TRACKERS}"
            )));
        }
        let mut outbound_failures = Vec::with_capacity(len);
        for _ in 0..len {
            let addr = String::from_utf8(r.read_vec(MAX_PEER_ROTATION_ADDR_BYTES)?)
                .map_err(|e| DomError::Malformed(format!("peer rotation addr utf8: {e}")))?;
            let failures = r.read_u8()?;
            let last_failure_seq = r.read_u64()?;
            outbound_failures.push(PersistedOutboundFailure {
                addr,
                failures,
                last_failure_seq,
                cooldown_rounds: 0,
            });
        }
        r.finish()?;
        Ok(Self {
            next_failure_seq,
            outbound_failures,
        })
    }
}

impl DomSerialize for PersistedPeerReputationState {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        let len: u32 =
            self.entries.len().try_into().map_err(|_| {
                DomError::Malformed("peer reputation entry count exceeds u32".into())
            })?;
        w.write_u32(len);
        for entry in &self.entries {
            w.write_vec(entry.addr.as_bytes())?;
            w.write_u32(entry.score);
        }
        Ok(())
    }
}

impl DomDeserialize for PersistedPeerReputationState {
    const MIN_SERIALIZED_SIZE: usize = 4;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let len = r.read_u32()? as usize;
        if len > MAX_PERSISTED_PEER_REPUTATION_ENTRIES {
            return Err(DomError::Malformed(format!(
                "peer reputation entry count {len} exceeds limit {MAX_PERSISTED_PEER_REPUTATION_ENTRIES}"
            )));
        }
        let mut entries = Vec::with_capacity(len);
        for _ in 0..len {
            let addr = String::from_utf8(r.read_vec(MAX_PEER_ROTATION_ADDR_BYTES)?)
                .map_err(|e| DomError::Malformed(format!("peer reputation addr utf8: {e}")))?;
            let score = r.read_u32()?;
            entries.push(PersistedPeerReputation { addr, score });
        }
        Ok(Self { entries })
    }
}

/// Peer manager state.
pub struct PeerManager {
    /// Connected peers: addr_string → PeerInfo.
    pub peers: HashMap<String, PeerInfo>,
    /// Active authenticated PeerId -> canonical socket-address key.
    active_peer_ids: HashMap<[u8; 32], String>,
    /// Dial aliases (DNS name or socket address) -> authenticated PeerId.
    known_peer_aliases: HashMap<String, [u8; 32]>,
    /// Successful outbound dial alias -> (canonical key, session generation).
    /// Cleanup consumes this ownership record and therefore cannot remove a
    /// newer or unrelated session.
    outbound_session_owners: HashMap<String, (String, u64)>,
    /// Inbound sockets admitted by the listener but not yet registered.
    pending_inbound: HashMap<String, PendingInbound>,
    /// Outbound dials started but not yet registered.
    pending_outbound: HashMap<String, PendingOutbound>,
    /// Penalties accumulated before a peer is fully registered.
    pending_penalties: HashMap<String, PendingPenalty>,
    /// Runtime-only duplicate block relay counters for connected peers.
    duplicate_block_relays: HashMap<String, DuplicateRelayTracker>,
    /// Deterministic outbound failure history used to rotate repeated failures.
    outbound_failures: HashMap<String, OutboundFailureTracker>,
    /// Monotonic sequence for deterministic failure ordering.
    outbound_failure_seq: u64,
    /// Max inbound connections.
    pub max_inbound: usize,
    /// Min outbound connections.
    pub min_outbound: usize,
}

impl PeerManager {
    /// Create a new peer manager.
    pub fn new(max_inbound: usize, min_outbound: usize) -> Self {
        Self {
            peers: HashMap::new(),
            active_peer_ids: HashMap::new(),
            known_peer_aliases: HashMap::new(),
            outbound_session_owners: HashMap::new(),
            pending_inbound: HashMap::new(),
            pending_outbound: HashMap::new(),
            pending_penalties: HashMap::new(),
            duplicate_block_relays: HashMap::new(),
            outbound_failures: HashMap::new(),
            outbound_failure_seq: 0,
            max_inbound,
            min_outbound,
        }
    }

    /// Count outbound connections.
    pub fn outbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.outbound && p.state != PeerState::Disconnected)
            .count()
    }

    /// Count outbound dials that are still in handshake / Hello exchange.
    pub fn pending_outbound_count(&self) -> usize {
        self.pending_outbound
            .values()
            .filter(|pending| !outbound_reservation_is_stale(**pending))
            .count()
    }

    /// Count inbound connections.
    pub fn inbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| !p.outbound && p.state != PeerState::Disconnected)
            .count()
    }

    /// Count inbound connections that are still in handshake / Hello exchange.
    pub fn pending_inbound_count(&self) -> usize {
        self.pending_inbound
            .values()
            .filter(|pending| !reservation_is_stale(**pending))
            .count()
    }

    /// Count live pre-registration penalty entries.
    pub fn pending_penalty_count(&self) -> usize {
        self.pending_penalties
            .values()
            .filter(|penalty| !penalty_is_stale(**penalty))
            .count()
    }

    /// Check if we need more outbound connections.
    pub fn needs_outbound(&self) -> bool {
        self.outbound_count() + self.pending_outbound_count() < self.target_outbound_count()
    }

    fn target_outbound_count(&self) -> usize {
        self.min_outbound
            .min(OUTBOUND_RECONNECT_POLICY.max_in_flight_attempts)
    }

    /// Check if we can accept another inbound connection.
    pub fn can_accept_inbound(&self, new_addr: IpAddr) -> bool {
        if self.inbound_count() + self.pending_inbound_count() >= self.max_inbound {
            return false;
        }
        // Eclipse protection: max 2 peers per /16
        let slash16 = to_slash16(new_addr);
        let connected_same_subnet = self
            .peers
            .values()
            .filter(|p| !p.outbound && to_slash16(p.addr.ip()) == slash16)
            .count();
        let pending_same_subnet = self
            .pending_inbound
            .iter()
            .filter(|(_, pending)| !reservation_is_stale(**pending))
            .filter_map(|(addr, _)| addr.parse::<std::net::SocketAddr>().ok())
            .filter(|addr| to_slash16(addr.ip()) == slash16)
            .count();
        connected_same_subnet + pending_same_subnet < MAX_PEERS_SAME_SLASH_16
    }

    /// Reserve an inbound slot before spawning handshake work.
    ///
    /// This closes the pre-registration gap where many concurrent TCP
    /// connections can all pass `can_accept_inbound` before any of them
    /// completes Noise + Hello and reaches `register_peer`.
    pub fn reserve_inbound(&mut self, addr: std::net::SocketAddr) -> Result<(), DomError> {
        self.prune_stale_state();
        let addr_str = addr.to_string();
        if self.peers.contains_key(&addr_str) || self.pending_inbound.contains_key(&addr_str) {
            return Err(DomError::PolicyRejected(
                "already connected or pending inbound peer".into(),
            ));
        }
        if self.pending_ban_score(&addr_str) >= crate::peer::ban_scores::BAN_THRESHOLD {
            return Err(DomError::PolicyRejected(
                "pending inbound peer is banned".into(),
            ));
        }
        if !self.can_accept_inbound(addr.ip()) {
            return Err(DomError::PolicyRejected(
                "inbound limit or subnet limit reached".into(),
            ));
        }
        self.pending_inbound.insert(
            addr_str,
            PendingInbound {
                reserved_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Release a pending inbound reservation.
    pub fn release_inbound_reservation(&mut self, addr: &std::net::SocketAddr) {
        self.prune_stale_state();
        self.pending_inbound.remove(&addr.to_string());
    }

    /// Reserve an outbound dial slot before spawning handshake work.
    pub fn reserve_outbound(&mut self, addr: &str) -> Result<(), DomError> {
        self.prune_stale_state();
        if self.peers.contains_key(addr) || self.pending_outbound.contains_key(addr) {
            return Err(DomError::PolicyRejected(
                "already connected or pending outbound peer".into(),
            ));
        }
        if self
            .known_peer_aliases
            .get(addr)
            .is_some_and(|peer_id| self.active_peer_ids.contains_key(peer_id))
        {
            return Err(DomError::PolicyRejected(
                "authenticated peer identity already has an active session".into(),
            ));
        }
        if self.pending_ban_score(addr) >= crate::peer::ban_scores::BAN_THRESHOLD {
            return Err(DomError::PolicyRejected(
                "pending outbound peer is banned".into(),
            ));
        }
        if !self.needs_outbound()
            || self.pending_outbound_count() >= OUTBOUND_RECONNECT_POLICY.max_in_flight_attempts
        {
            return Err(DomError::PolicyRejected(
                "outbound limit or pending outbound limit reached".into(),
            ));
        }
        self.pending_outbound.insert(
            addr.to_string(),
            PendingOutbound {
                reserved_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Release a pending outbound reservation.
    pub fn release_outbound_reservation(&mut self, addr: &str) {
        self.prune_stale_state();
        self.pending_outbound.remove(addr);
    }

    /// Remember the identity authenticated for a dial alias. Calling this even
    /// when registration is rejected lets future connector passes suppress
    /// repeated handshakes to another address for the same PeerId.
    pub fn note_peer_identity(&mut self, alias: &str, peer_id: [u8; 32]) {
        if self.known_peer_aliases.len() >= MAX_KNOWN_PEER_ALIASES
            && !self.known_peer_aliases.contains_key(alias)
        {
            if let Some(stale_alias) = self
                .known_peer_aliases
                .iter()
                .find(|(_, id)| !self.active_peer_ids.contains_key(*id))
                .map(|(alias, _)| alias.clone())
            {
                self.known_peer_aliases.remove(&stale_alias);
            } else {
                return;
            }
        }
        self.known_peer_aliases.insert(alias.to_string(), peer_id);
    }

    /// Bind a successful outbound registration to the task that owns it.
    pub fn bind_outbound_session(&mut self, alias: &str, canonical_addr: &str, session_id: u64) {
        self.outbound_session_owners
            .insert(alias.to_string(), (canonical_addr.to_string(), session_id));
    }

    /// Remove only the session registered by this outbound dial alias.
    pub fn remove_outbound_session(&mut self, alias: &str) -> bool {
        let Some((canonical_addr, session_id)) = self.outbound_session_owners.remove(alias) else {
            return false;
        };
        self.remove_peer_session(&canonical_addr, session_id)
    }

    /// Record a failed outbound attempt so future candidate ordering can
    /// deterministically rotate away from repeatedly failing peers.
    pub fn record_outbound_failure(&mut self, addr: &str) {
        self.prune_stale_state();
        self.outbound_failure_seq = self.outbound_failure_seq.saturating_add(1);
        let seq = self.outbound_failure_seq;
        let entry =
            self.outbound_failures
                .entry(addr.to_string())
                .or_insert(OutboundFailureTracker {
                    failures: 0,
                    last_failure_seq: seq,
                    cooldown_rounds: 0,
                });
        entry.failures = entry.failures.saturating_add(1);
        entry.last_failure_seq = seq;
        entry.cooldown_rounds = OUTBOUND_RECONNECT_POLICY.cooldown_rounds_after_failure(
            addr,
            entry.failures,
            OUTBOUND_RECONNECT_POLICY.initial_delay_secs,
        );
        self.enforce_outbound_failure_bound();
    }

    /// Clear outbound failure history after a successful registration so a
    /// previously bad peer does not stay artificially deprioritized forever.
    pub fn clear_outbound_failure(&mut self, addr: &str) {
        self.outbound_failures.remove(addr);
    }

    /// Advance deterministic outbound cooldown state by one connector pass.
    ///
    /// Returns true when any persisted cooldown state changed.
    pub fn advance_outbound_cooldowns(&mut self) -> bool {
        self.prune_stale_state();
        let mut changed = false;
        for tracker in self.outbound_failures.values_mut() {
            if tracker.cooldown_rounds > 0 {
                tracker.cooldown_rounds -= 1;
                changed = true;
            }
        }
        changed
    }

    /// Return outbound candidates in canonical retry order.
    ///
    /// Peers with fewer recorded failures come first. Among peers with equal
    /// failure counts, the least recently failed peer comes first. Address
    /// order breaks any remaining tie deterministically.
    pub fn outbound_candidates_in_retry_order(&self, candidates: Vec<String>) -> Vec<String> {
        let mut out = candidates;
        out.retain(|addr| {
            self.outbound_failures
                .get(addr)
                .map(|tracker| tracker.cooldown_rounds == 0)
                .unwrap_or(true)
        });
        out.sort_by(|left, right| {
            let left_failure = self.outbound_failures.get(left).copied();
            let right_failure = self.outbound_failures.get(right).copied();
            let left_failures = left_failure.map(|f| f.failures).unwrap_or(0);
            let right_failures = right_failure.map(|f| f.failures).unwrap_or(0);
            let left_seq = left_failure.map(|f| f.last_failure_seq).unwrap_or(0);
            let right_seq = right_failure.map(|f| f.last_failure_seq).unwrap_or(0);
            left_failures
                .cmp(&right_failures)
                .then_with(|| left_seq.cmp(&right_seq))
                .then_with(|| left.cmp(right))
        });
        out
    }

    /// Inspect the current outbound failure count for a candidate.
    pub fn outbound_failure_count(&self, addr: &str) -> u8 {
        self.outbound_failures
            .get(addr)
            .map(|tracker| tracker.failures)
            .unwrap_or(0)
    }

    /// Inspect the current deterministic cooldown state for a candidate.
    pub fn outbound_cooldown_rounds(&self, addr: &str) -> u8 {
        self.outbound_failures
            .get(addr)
            .map(|tracker| tracker.cooldown_rounds)
            .unwrap_or(0)
    }

    /// Snapshot deterministic outbound failure history for replay-equivalent
    /// persistence and comparison.
    pub fn outbound_failure_state(&self) -> PersistedPeerRotationState {
        let mut outbound_failures: Vec<PersistedOutboundFailure> = self
            .outbound_failures
            .iter()
            .map(|(addr, tracker)| PersistedOutboundFailure {
                addr: addr.clone(),
                failures: tracker.failures,
                last_failure_seq: tracker.last_failure_seq,
                cooldown_rounds: tracker.cooldown_rounds,
            })
            .collect();
        outbound_failures.sort_by(|left, right| left.addr.cmp(&right.addr));
        PersistedPeerRotationState {
            next_failure_seq: self.outbound_failure_seq,
            outbound_failures,
        }
    }

    /// Restore deterministic outbound failure history from a persisted snapshot.
    pub fn restore_outbound_failure_state(
        &mut self,
        snapshot: &PersistedPeerRotationState,
    ) -> Result<(), DomError> {
        if snapshot.outbound_failures.len() > MAX_OUTBOUND_FAILURE_TRACKERS {
            return Err(DomError::Invalid(format!(
                "peer rotation snapshot exceeds bound {}",
                MAX_OUTBOUND_FAILURE_TRACKERS
            )));
        }

        let mut restored = HashMap::with_capacity(snapshot.outbound_failures.len());
        let mut previous_addr: Option<&str> = None;
        let mut max_seq = 0u64;
        for entry in &snapshot.outbound_failures {
            if let Some(prev) = previous_addr {
                if prev >= entry.addr.as_str() {
                    return Err(DomError::Invalid(
                        "peer rotation snapshot addresses are not strictly ordered".into(),
                    ));
                }
            }
            previous_addr = Some(entry.addr.as_str());
            if restored.contains_key(&entry.addr) {
                return Err(DomError::Invalid(
                    "peer rotation snapshot contains duplicate addresses".into(),
                ));
            }
            if entry.failures == 0 {
                return Err(DomError::Invalid(
                    "peer rotation snapshot contains zero-failure entry".into(),
                ));
            }
            if entry.cooldown_rounds > MAX_OUTBOUND_FAILURE_COOLDOWN_ROUNDS {
                return Err(DomError::Invalid(format!(
                    "peer rotation snapshot cooldown {} exceeds limit {}",
                    entry.cooldown_rounds, MAX_OUTBOUND_FAILURE_COOLDOWN_ROUNDS
                )));
            }
            max_seq = max_seq.max(entry.last_failure_seq);
            restored.insert(
                entry.addr.clone(),
                OutboundFailureTracker {
                    failures: entry.failures,
                    last_failure_seq: entry.last_failure_seq,
                    cooldown_rounds: entry.cooldown_rounds,
                },
            );
        }
        if snapshot.next_failure_seq < max_seq {
            return Err(DomError::Invalid(
                "peer rotation snapshot next_failure_seq regresses behind recorded failures".into(),
            ));
        }

        self.outbound_failures = restored;
        self.outbound_failure_seq = snapshot.next_failure_seq;
        Ok(())
    }

    /// Snapshot connected and pending peer reputation for restart-safe
    /// persistence. Stronger scores are retained when the bounded cap is hit.
    pub fn peer_reputation_state(&self) -> PersistedPeerReputationState {
        let mut merged = HashMap::<String, u32>::new();
        for (addr, peer) in &self.peers {
            if peer.ban_score > 0 {
                merged
                    .entry(reputation_key(addr))
                    .and_modify(|score| *score = score.saturating_add(peer.ban_score))
                    .or_insert(peer.ban_score);
            }
        }
        for (addr, penalty) in &self.pending_penalties {
            if penalty.score > 0 && !penalty_is_stale(*penalty) {
                merged
                    .entry(addr.clone())
                    .and_modify(|score| *score = score.saturating_add(penalty.score))
                    .or_insert(penalty.score);
            }
        }

        let mut entries: Vec<PersistedPeerReputation> = merged
            .into_iter()
            .map(|(addr, score)| PersistedPeerReputation { addr, score })
            .collect();
        entries.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| left.addr.cmp(&right.addr))
        });
        entries.truncate(MAX_PERSISTED_PEER_REPUTATION_ENTRIES);
        entries.sort_by(|left, right| left.addr.cmp(&right.addr));
        PersistedPeerReputationState { entries }
    }

    /// Restore persisted peer reputation into the pre-registration penalty
    /// table. This keeps restart behavior conservative without persisting
    /// runtime `Instant` values or connected peer objects.
    pub fn restore_peer_reputation_state(
        &mut self,
        snapshot: &PersistedPeerReputationState,
    ) -> Result<(), DomError> {
        if snapshot.entries.len() > MAX_PERSISTED_PEER_REPUTATION_ENTRIES {
            return Err(DomError::Invalid(format!(
                "peer reputation snapshot exceeds bound {}",
                MAX_PERSISTED_PEER_REPUTATION_ENTRIES
            )));
        }

        let now = Instant::now();
        let mut restored = HashMap::with_capacity(snapshot.entries.len());
        let mut previous_addr: Option<&str> = None;
        for entry in &snapshot.entries {
            if let Some(prev) = previous_addr {
                if prev >= entry.addr.as_str() {
                    return Err(DomError::Invalid(
                        "peer reputation snapshot addresses are not strictly ordered".into(),
                    ));
                }
            }
            previous_addr = Some(entry.addr.as_str());
            if entry.score == 0 {
                return Err(DomError::Invalid(
                    "peer reputation snapshot contains zero-score entry".into(),
                ));
            }
            let reputation_addr = reputation_key(&entry.addr);
            if restored.contains_key(&reputation_addr) {
                return Err(DomError::Invalid(
                    "peer reputation snapshot contains duplicate addresses".into(),
                ));
            }
            restored.insert(
                reputation_addr,
                PendingPenalty {
                    score: entry.score,
                    last_updated: now,
                },
            );
        }

        self.pending_penalties = restored;
        Ok(())
    }

    /// Register a new peer connection attempt.
    pub fn register_peer(&mut self, info: PeerInfo) -> Result<(), DomError> {
        self.prune_stale_state();
        let addr_str = info.addr.to_string();
        let reputation_addr = reputation_key(&addr_str);
        if self.peers.contains_key(&addr_str) {
            return Err(DomError::PolicyRejected(
                "already connected to this peer".into(),
            ));
        }
        let mut info = info;
        if let Some(peer_id) = info.peer_id {
            if let Some(active_addr) = self.active_peer_ids.get(&peer_id) {
                return Err(DomError::PolicyRejected(format!(
                    "already connected to authenticated peer identity at {active_addr}"
                )));
            }
            self.note_peer_identity(&addr_str, peer_id);
        }
        let pending_score = self.pending_penalty_score(&reputation_addr);
        if pending_score > 0 && info.add_ban_score(pending_score) {
            return Err(DomError::PolicyRejected(
                "pending peer penalties exceeded ban threshold".into(),
            ));
        }
        if !info.outbound {
            self.pending_inbound.remove(&addr_str);
            if !self.can_accept_inbound(info.addr.ip()) {
                return Err(DomError::PolicyRejected(
                    "inbound limit or subnet limit reached".into(),
                ));
            }
        } else {
            self.pending_outbound.remove(&addr_str);
        }
        self.pending_penalties.remove(&reputation_addr);
        self.duplicate_block_relays.remove(&addr_str);
        if let Some(peer_id) = info.peer_id {
            self.active_peer_ids.insert(peer_id, addr_str.clone());
        }
        self.peers.insert(addr_str, info);
        Ok(())
    }

    /// Remove a disconnected peer.
    pub fn remove_peer(&mut self, addr: &str) {
        self.prune_stale_state();
        self.remove_peer_inner(addr);
    }

    /// Remove a peer only when the caller owns the active session generation.
    pub fn remove_peer_session(&mut self, addr: &str, session_id: u64) -> bool {
        self.prune_stale_state();
        if self
            .peers
            .get(addr)
            .is_none_or(|peer| peer.session_id != session_id)
        {
            return false;
        }
        self.remove_peer_inner(addr);
        true
    }

    fn remove_peer_inner(&mut self, addr: &str) {
        if let Some(peer) = self.peers.remove(addr) {
            if let Some(peer_id) = peer.peer_id {
                if self
                    .active_peer_ids
                    .get(&peer_id)
                    .is_some_and(|active_addr| active_addr == addr)
                {
                    self.active_peer_ids.remove(&peer_id);
                }
            }
            if peer.outbound
                && peer.uptime_secs() >= OUTBOUND_RECONNECT_POLICY.reset_after_stable_session_secs
            {
                self.clear_outbound_failure(addr);
            }
            if peer.ban_score > 0 {
                let _ = self.add_pending_ban_score(addr, peer.ban_score);
            }
        }
        self.pending_inbound.remove(addr);
        self.pending_outbound.remove(addr);
        self.duplicate_block_relays.remove(addr);
    }

    /// Apply a ban-score increment to a connected peer.
    ///
    /// Returns true when the new score crosses the ban threshold and the peer
    /// transitions into the banned state.
    pub fn add_ban_score(&mut self, addr: &str, score: u32) -> bool {
        match self.peers.get_mut(addr) {
            Some(peer) => peer.add_ban_score(score),
            None => false,
        }
    }

    /// Add a penalty score for a peer that has not yet been registered.
    pub fn add_pending_ban_score(&mut self, addr: &str, score: u32) -> u32 {
        self.prune_stale_state();
        let now = Instant::now();
        let reputation_addr = reputation_key(addr);
        let updated_score = {
            let entry = self
                .pending_penalties
                .entry(reputation_addr)
                .or_insert(PendingPenalty {
                    score: 0,
                    last_updated: now,
                });
            entry.score = entry.score.saturating_add(score);
            entry.last_updated = now;
            entry.score
        };
        self.enforce_pending_penalty_bound();
        updated_score
    }

    /// Inspect the current ban score for a peer.
    pub fn ban_score(&self, addr: &str) -> Option<u32> {
        self.peers.get(addr).map(|peer| peer.ban_score)
    }

    /// Inspect the current pre-registration penalty score for a peer.
    pub fn pending_ban_score(&self, addr: &str) -> u32 {
        self.pending_penalty_score(&reputation_key(addr))
    }

    /// Get all connected peer addresses (for broadcasting).
    pub fn connected_peers(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Connected)
            .map(|(addr, _)| addr.clone())
            .collect();
        out.sort();
        out
    }

    /// Record a duplicate block relay from a connected peer.
    ///
    /// Returns true when the current relay exceeds the duplicate quota and
    /// the caller should disconnect the peer to bound runtime resource use.
    pub fn record_duplicate_block_relay(&mut self, addr: &str) -> bool {
        if !matches!(
            self.peers.get(addr).map(|peer| peer.state),
            Some(PeerState::Connected)
        ) {
            return false;
        }

        let now = Instant::now();
        let tracker = self
            .duplicate_block_relays
            .entry(addr.to_string())
            .or_insert(DuplicateRelayTracker {
                count: 0,
                window_started: now,
            });
        if tracker.window_started.elapsed()
            >= Duration::from_secs(DUPLICATE_BLOCK_RELAY_WINDOW_SECS)
        {
            tracker.count = 0;
            tracker.window_started = now;
        }
        tracker.count = tracker.count.saturating_add(1);
        if tracker.count <= MAX_DUPLICATE_BLOCK_RELAYS_PER_WINDOW {
            return false;
        }

        let _ = self.add_ban_score(addr, crate::peer::ban_scores::PROTOCOL_VIOLATION);
        true
    }

    /// Inspect the current duplicate relay counter for a peer.
    pub fn duplicate_block_relay_count(&self, addr: &str) -> u32 {
        self.duplicate_block_relays
            .get(addr)
            .map(|tracker| tracker.count)
            .unwrap_or(0)
    }

    /// Get connected peers with higher claimed height (for IBD).
    pub fn peers_with_height_above(&self, height: u64) -> Vec<String> {
        let mut out: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| p.state == PeerState::Connected && p.best_height > height)
            .map(|(addr, _)| addr.clone())
            .collect();
        out.sort();
        out
    }

    /// Get the last announced best height for a connected peer.
    pub fn peer_best_height(&self, addr: &str) -> Option<u64> {
        self.peers.get(addr).and_then(|peer| {
            if peer.state == PeerState::Connected {
                Some(peer.best_height)
            } else {
                None
            }
        })
    }

    fn pending_penalty_score(&self, addr: &str) -> u32 {
        self.pending_penalties
            .get(addr)
            .copied()
            .filter(|penalty| !penalty_is_stale(*penalty))
            .map(|penalty| penalty.score)
            .unwrap_or(0)
    }

    fn prune_stale_state(&mut self) {
        self.pending_inbound
            .retain(|_, pending| !reservation_is_stale(*pending));
        self.pending_outbound
            .retain(|_, pending| !outbound_reservation_is_stale(*pending));
        self.pending_penalties
            .retain(|_, penalty| !penalty_is_stale(*penalty));
        self.enforce_pending_penalty_bound();
        self.enforce_outbound_failure_bound();
    }

    fn enforce_pending_penalty_bound(&mut self) {
        if self.pending_penalties.len() <= MAX_PENDING_PENALTIES {
            return;
        }

        let overflow = self.pending_penalties.len() - MAX_PENDING_PENALTIES;
        let mut oldest: Vec<(String, Instant)> = self
            .pending_penalties
            .iter()
            .map(|(addr, penalty)| (addr.clone(), penalty.last_updated))
            .collect();
        oldest.sort_by(|(left_addr, left_ts), (right_addr, right_ts)| {
            left_ts
                .cmp(right_ts)
                .then_with(|| left_addr.cmp(right_addr))
        });
        for (addr, _) in oldest.into_iter().take(overflow) {
            self.pending_penalties.remove(&addr);
        }
    }

    fn enforce_outbound_failure_bound(&mut self) {
        if self.outbound_failures.len() <= MAX_OUTBOUND_FAILURE_TRACKERS {
            return;
        }

        let overflow = self.outbound_failures.len() - MAX_OUTBOUND_FAILURE_TRACKERS;
        let mut oldest: Vec<(String, u64)> = self
            .outbound_failures
            .iter()
            .map(|(addr, tracker)| (addr.clone(), tracker.last_failure_seq))
            .collect();
        oldest.sort_by(|(left_addr, left_seq), (right_addr, right_seq)| {
            left_seq
                .cmp(right_seq)
                .then_with(|| left_addr.cmp(right_addr))
        });
        for (addr, _) in oldest.into_iter().take(overflow) {
            self.outbound_failures.remove(&addr);
        }
    }
}

fn reputation_key(addr: &str) -> String {
    if let Ok(sock) = addr.parse::<SocketAddr>() {
        return sock.ip().to_string();
    }
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return ip.to_string();
    }
    addr.to_string()
}

fn reservation_is_stale(pending: PendingInbound) -> bool {
    pending.reserved_at.elapsed() >= Duration::from_secs(stale_pending_inbound_secs())
}

fn outbound_reservation_is_stale(pending: PendingOutbound) -> bool {
    pending.reserved_at.elapsed() >= Duration::from_secs(stale_pending_outbound_secs())
}

fn penalty_is_stale(pending: PendingPenalty) -> bool {
    pending.last_updated.elapsed() >= Duration::from_secs(PENDING_PENALTY_TTL_SECS)
}

/// Reservations older than this are treated as dead handshakes and ignored.
fn stale_pending_inbound_secs() -> u64 {
    crate::handshake::handshake_timeout_secs() * 3
}

/// Outbound reservations older than this are treated as dead handshakes.
fn stale_pending_outbound_secs() -> u64 {
    crate::handshake::handshake_timeout_secs() * 3
}

fn deterministic_addr_jitter(addr: &str, max_jitter_secs: u64) -> u64 {
    if max_jitter_secs == 0 {
        return 0;
    }
    let mut hash = 0xcbf29ce484222325u64;
    for byte in addr.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash % (max_jitter_secs + 1)
}

/// Extract /16 prefix from an IP for subnet diversity check.
fn to_slash16(ip: IpAddr) -> [u8; 2] {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            [octets[0], octets[1]]
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            [octets[0], octets[1]]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PeerInfo;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_peer(ip: [u8; 4], port: u16, outbound: bool) -> PeerInfo {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port);
        let mut p = PeerInfo::new(addr, outbound);
        p.state = PeerState::Connected;
        p
    }

    #[test]
    fn subnet_diversity_limit() {
        let mut mgr = PeerManager::new(125, 8);
        // Add 2 peers from same /16 (192.168.x.x)
        mgr.register_peer(make_peer([192, 168, 1, 1], 33369, false))
            .unwrap();
        mgr.register_peer(make_peer([192, 168, 2, 1], 33370, false))
            .unwrap();
        // Third from same /16 should be rejected
        let result = mgr.can_accept_inbound(IpAddr::V4(Ipv4Addr::new(192, 168, 3, 1)));
        assert!(!result, "should reject 3rd peer from same /16");
    }

    #[test]
    fn different_subnets_allowed() {
        let mut mgr = PeerManager::new(125, 8);
        mgr.register_peer(make_peer([192, 168, 1, 1], 33369, false))
            .unwrap();
        mgr.register_peer(make_peer([10, 0, 1, 1], 33370, false))
            .unwrap();
        // Different /16 — should be accepted
        assert!(mgr.can_accept_inbound(IpAddr::V4(Ipv4Addr::new(172, 16, 1, 1))));
    }

    #[test]
    fn needs_outbound_when_below_min() {
        let mgr = PeerManager::new(125, 8);
        assert!(mgr.needs_outbound());
    }

    #[test]
    fn reserve_outbound_deduplicates_simultaneous_reconnect_races() {
        let mut mgr = PeerManager::new(125, 2);
        assert!(mgr.reserve_outbound("203.0.113.10:33369").is_ok());
        assert!(mgr.reserve_outbound("203.0.113.10:33369").is_err());
        assert_eq!(mgr.pending_outbound_count(), 1);
    }

    #[test]
    fn authenticated_peer_id_rejects_second_address_and_suppresses_redial() {
        let mut mgr = PeerManager::new(125, 8);
        let peer_id = [0x42; 32];
        let mut first = make_peer([203, 0, 113, 10], 33369, true);
        first.peer_id = Some(peer_id);
        mgr.register_peer(first).expect("first identity registers");

        let alias = "seed1.example:33369";
        mgr.note_peer_identity(alias, peer_id);
        assert!(mgr.reserve_outbound(alias).is_err());

        let mut duplicate = make_peer([198, 51, 100, 20], 33369, true);
        duplicate.peer_id = Some(peer_id);
        let err = mgr
            .register_peer(duplicate)
            .expect_err("same authenticated identity must be unique");
        assert!(matches!(
            err,
            DomError::PolicyRejected(ref message)
                if message.contains("authenticated peer identity")
        ));
        assert_eq!(mgr.peers.len(), 1);
    }

    #[test]
    fn outbound_cleanup_cannot_remove_session_it_does_not_own() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([203, 0, 113, 11], 33369, true);
        let canonical = peer.addr.to_string();
        let session_id = peer.session_id;
        mgr.register_peer(peer).expect("register active session");

        mgr.bind_outbound_session("seed.example:33369", &canonical, session_id + 1);
        assert!(!mgr.remove_outbound_session("seed.example:33369"));
        assert!(mgr.peers.contains_key(&canonical));

        mgr.bind_outbound_session("seed.example:33369", &canonical, session_id);
        assert!(mgr.remove_outbound_session("seed.example:33369"));
        assert!(!mgr.peers.contains_key(&canonical));
    }

    #[test]
    fn outbound_limit_bounds_concurrent_handshakes() {
        let mut mgr = PeerManager::new(125, OUTBOUND_RECONNECT_POLICY.max_in_flight_attempts + 2);
        for i in 0..OUTBOUND_RECONNECT_POLICY.max_in_flight_attempts {
            let addr = format!("203.0.113.{}:33369", i + 10);
            assert!(mgr.reserve_outbound(&addr).is_ok());
        }
        assert!(mgr.reserve_outbound("203.0.113.250:33369").is_err());
        assert_eq!(
            mgr.pending_outbound_count(),
            OUTBOUND_RECONNECT_POLICY.max_in_flight_attempts
        );
        assert!(!mgr.needs_outbound());
    }

    #[test]
    fn ban_score_marks_peer_banned() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([192, 168, 1, 10], 33369, false);
        let addr = peer.addr.to_string();
        mgr.register_peer(peer).unwrap();

        assert!(!mgr.add_ban_score(&addr, 99));
        assert_eq!(mgr.ban_score(&addr), Some(99));
        assert!(mgr.add_ban_score(&addr, 1));
        assert_eq!(
            mgr.peers.get(&addr).map(|peer| peer.state),
            Some(PeerState::Banned)
        );
    }

    #[test]
    fn banned_peer_drops_out_of_connected_set() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([10, 0, 0, 2], 33369, false);
        let addr = peer.addr.to_string();
        mgr.register_peer(peer).unwrap();
        assert_eq!(mgr.connected_peers(), vec![addr.clone()]);

        assert!(mgr.add_ban_score(&addr, 100));
        assert!(mgr.connected_peers().is_empty());
    }

    #[test]
    fn connected_peers_are_returned_in_canonical_order() {
        let mut mgr = PeerManager::new(125, 8);
        mgr.register_peer(make_peer([10, 0, 0, 9], 33369, true))
            .unwrap();
        mgr.register_peer(make_peer([10, 0, 0, 2], 33369, true))
            .unwrap();
        mgr.register_peer(make_peer([10, 0, 0, 20], 33369, true))
            .unwrap();

        assert_eq!(
            mgr.connected_peers(),
            vec![
                "10.0.0.20:33369".to_string(),
                "10.0.0.2:33369".to_string(),
                "10.0.0.9:33369".to_string(),
            ]
        );
    }

    #[test]
    fn peers_with_height_above_are_returned_in_canonical_order() {
        let mut mgr = PeerManager::new(125, 8);
        let mut a = make_peer([10, 0, 0, 9], 33369, true);
        a.best_height = 120;
        mgr.register_peer(a).unwrap();

        let mut b = make_peer([10, 0, 0, 2], 33369, true);
        b.best_height = 110;
        mgr.register_peer(b).unwrap();

        let mut c = make_peer([10, 0, 0, 20], 33369, true);
        c.best_height = 90;
        mgr.register_peer(c).unwrap();

        assert_eq!(
            mgr.peers_with_height_above(100),
            vec!["10.0.0.2:33369".to_string(), "10.0.0.9:33369".to_string(),]
        );
    }

    #[test]
    fn pending_ban_score_applies_on_registration() {
        let mut mgr = PeerManager::new(125, 8);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)), 33369).to_string();
        assert_eq!(mgr.add_pending_ban_score(&addr, 40), 40);
        assert_eq!(mgr.pending_ban_score(&addr), 40);

        let mut peer = PeerInfo::new(addr.parse().unwrap(), false);
        peer.state = PeerState::Connected;
        mgr.register_peer(peer).unwrap();

        assert_eq!(mgr.pending_ban_score(&addr), 0);
        assert_eq!(mgr.ban_score(&addr), Some(40));
    }

    #[test]
    fn pending_ban_threshold_blocks_registration() {
        let mut mgr = PeerManager::new(125, 8);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2)), 33369).to_string();
        assert_eq!(mgr.add_pending_ban_score(&addr, 100), 100);

        let mut peer = PeerInfo::new(addr.parse().unwrap(), false);
        peer.state = PeerState::Connected;
        assert!(mgr.register_peer(peer).is_err());
        assert!(mgr.ban_score(&addr).is_none());
        assert_eq!(mgr.pending_ban_score(&addr), 100);
    }

    #[test]
    fn pending_ban_threshold_blocks_new_reservation() {
        let mut mgr = PeerManager::new(125, 8);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 3)), 33369);
        assert_eq!(mgr.add_pending_ban_score(&addr.to_string(), 100), 100);
        assert!(mgr.reserve_inbound(addr).is_err());
    }

    #[test]
    fn stale_pending_reservation_stops_consuming_capacity() {
        let mut mgr = PeerManager::new(2, 8);
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 33369);
        let b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 33369);
        let c = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)), 33369);

        mgr.reserve_inbound(a).expect("reserve a");
        mgr.reserve_inbound(b).expect("reserve b");
        mgr.pending_inbound
            .get_mut(&a.to_string())
            .unwrap()
            .reserved_at = Instant::now() - Duration::from_secs(stale_pending_inbound_secs() + 1);

        assert_eq!(mgr.pending_inbound_count(), 1);
        mgr.reserve_inbound(c)
            .expect("stale reservation must not pin inbound capacity");
    }

    #[test]
    fn stale_pending_penalty_expires_before_new_reservation() {
        let mut mgr = PeerManager::new(125, 8);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 4)), 33369);
        let key = addr.to_string();
        assert_eq!(mgr.add_pending_ban_score(&key, 100), 100);
        mgr.pending_penalties
            .get_mut(&reputation_key(&key))
            .unwrap()
            .last_updated = Instant::now() - Duration::from_secs(PENDING_PENALTY_TTL_SECS + 1);

        assert_eq!(mgr.pending_ban_score(&key), 0);
        mgr.reserve_inbound(addr)
            .expect("expired pending ban must not block a later retry");
    }

    #[test]
    fn stale_pending_outbound_stops_consuming_capacity() {
        let mut mgr = PeerManager::new(125, 1);
        let addr = "203.0.113.20:33369";
        mgr.reserve_outbound(addr).expect("reserve outbound");
        mgr.pending_outbound.get_mut(addr).unwrap().reserved_at =
            Instant::now() - Duration::from_secs(stale_pending_outbound_secs() + 1);

        assert_eq!(mgr.pending_outbound_count(), 0);
        mgr.reserve_outbound("203.0.113.21:33369")
            .expect("stale outbound reservation must not pin outbound capacity");
    }

    #[test]
    fn pending_ban_threshold_blocks_new_outbound_reservation() {
        let mut mgr = PeerManager::new(125, 8);
        let addr = "203.0.113.22:33369";
        assert_eq!(mgr.add_pending_ban_score(addr, 100), 100);
        assert!(mgr.reserve_outbound(addr).is_err());
    }

    #[test]
    fn pending_penalties_are_bounded_under_address_churn() {
        let mut mgr = PeerManager::new(125, 8);
        for i in 0..(MAX_PENDING_PENALTIES + 128) {
            let addr = format!("10.0.{}.{}:33369", (i / 255) % 255, (i % 255) + 1);
            mgr.add_pending_ban_score(&addr, 20);
        }

        assert_eq!(
            mgr.pending_penalty_count(),
            MAX_PENDING_PENALTIES,
            "hostile address churn must not grow pending-penalty state without bound"
        );
        assert_eq!(
            mgr.pending_ban_score("10.0.0.1:33369"),
            0,
            "oldest churn entry should be evicted once the cap is hit"
        );
        let newest = format!(
            "10.0.{}.{}:33369",
            ((MAX_PENDING_PENALTIES + 127) / 255) % 255,
            ((MAX_PENDING_PENALTIES + 127) % 255) + 1
        );
        assert_eq!(
            mgr.pending_ban_score(&newest),
            20,
            "recent churn entries should remain tracked"
        );
    }

    #[test]
    fn duplicate_block_relay_quota_disconnects_abusive_peer() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([10, 0, 0, 42], 33369, false);
        let addr = peer.addr.to_string();
        mgr.register_peer(peer).unwrap();

        for _ in 0..MAX_DUPLICATE_BLOCK_RELAYS_PER_WINDOW {
            assert!(!mgr.record_duplicate_block_relay(&addr));
        }
        assert_eq!(
            mgr.duplicate_block_relay_count(&addr),
            MAX_DUPLICATE_BLOCK_RELAYS_PER_WINDOW
        );

        assert!(mgr.record_duplicate_block_relay(&addr));
        assert_eq!(
            mgr.ban_score(&addr),
            Some(crate::peer::ban_scores::PROTOCOL_VIOLATION)
        );
    }

    #[test]
    fn duplicate_block_relay_tracking_is_cleared_on_remove() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([10, 0, 0, 43], 33369, false);
        let addr = peer.addr.to_string();
        mgr.register_peer(peer).unwrap();
        assert!(!mgr.record_duplicate_block_relay(&addr));
        assert_eq!(mgr.duplicate_block_relay_count(&addr), 1);

        mgr.remove_peer(&addr);
        assert_eq!(mgr.duplicate_block_relay_count(&addr), 0);
    }

    #[test]
    fn disconnect_during_outbound_registration_clears_pending_state() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([203, 0, 113, 30], 33369, true);
        let addr = peer.addr.to_string();

        mgr.reserve_outbound(&addr).expect("reserve outbound");
        mgr.register_peer(peer).expect("register outbound");
        assert_eq!(mgr.pending_outbound_count(), 0);

        mgr.remove_peer(&addr);
        assert_eq!(mgr.pending_outbound_count(), 0);
        assert!(!mgr.peers.contains_key(&addr));
    }

    #[test]
    fn repeated_outbound_timeout_storms_converge_without_leaks() {
        let mut mgr = PeerManager::new(125, 4);
        for i in 0..1_024usize {
            let addr = format!("198.51.100.{}:33369", (i % 250) + 1);
            let _ = mgr.reserve_outbound(&addr);
            mgr.release_outbound_reservation(&addr);
        }

        assert_eq!(mgr.pending_outbound_count(), 0);
        assert!(mgr.needs_outbound());
    }

    #[test]
    fn repeated_failed_outbound_handshakes_do_not_create_reconnect_amplification() {
        let mut mgr = PeerManager::new(125, 1);
        let addr = "198.51.100.200:33369";

        for _ in 0..16 {
            assert!(mgr.reserve_outbound(addr).is_ok());
            assert!(mgr.reserve_outbound(addr).is_err());
            mgr.release_outbound_reservation(addr);
        }

        assert_eq!(mgr.pending_outbound_count(), 0);
        assert!(mgr.reserve_outbound(addr).is_ok());
    }

    #[test]
    fn outbound_candidates_are_ordered_by_failure_history() {
        let mut mgr = PeerManager::new(125, 2);
        mgr.record_outbound_failure("198.51.100.30:33369");
        mgr.record_outbound_failure("198.51.100.30:33369");
        mgr.record_outbound_failure("198.51.100.20:33369");
        while mgr.outbound_cooldown_rounds("198.51.100.30:33369") > 0
            || mgr.outbound_cooldown_rounds("198.51.100.20:33369") > 0
        {
            mgr.advance_outbound_cooldowns();
        }

        let ordered = mgr.outbound_candidates_in_retry_order(vec![
            "198.51.100.30:33369".into(),
            "198.51.100.10:33369".into(),
            "198.51.100.20:33369".into(),
        ]);
        assert_eq!(
            ordered,
            vec![
                "198.51.100.10:33369".to_string(),
                "198.51.100.20:33369".to_string(),
                "198.51.100.30:33369".to_string(),
            ]
        );
    }

    #[test]
    fn outbound_candidates_with_equal_failures_prefer_oldest_failure() {
        let mut mgr = PeerManager::new(125, 2);
        mgr.record_outbound_failure("198.51.100.20:33369");
        mgr.record_outbound_failure("198.51.100.10:33369");
        while mgr.outbound_cooldown_rounds("198.51.100.20:33369") > 0
            || mgr.outbound_cooldown_rounds("198.51.100.10:33369") > 0
        {
            mgr.advance_outbound_cooldowns();
        }

        let ordered = mgr.outbound_candidates_in_retry_order(vec![
            "198.51.100.10:33369".into(),
            "198.51.100.20:33369".into(),
        ]);
        assert_eq!(
            ordered,
            vec![
                "198.51.100.20:33369".to_string(),
                "198.51.100.10:33369".to_string(),
            ]
        );
    }

    #[test]
    fn stable_outbound_session_clears_failure_history() {
        let mut mgr = PeerManager::new(125, 2);
        let mut peer = make_peer([198, 51, 100, 40], 33369, true);
        let addr = peer.addr.to_string();

        mgr.record_outbound_failure(&addr);
        assert_eq!(mgr.outbound_failure_count(&addr), 1);
        mgr.reserve_outbound(&addr).expect("reserve outbound");
        peer.connected_at = Instant::now()
            - Duration::from_secs(OUTBOUND_RECONNECT_POLICY.reset_after_stable_session_secs + 1);
        mgr.register_peer(peer).expect("register outbound");
        assert_eq!(
            mgr.outbound_failure_count(&addr),
            1,
            "registration alone must not erase retry history"
        );
        mgr.remove_peer(&addr);

        assert_eq!(mgr.outbound_failure_count(&addr), 0);
        let ordered = mgr.outbound_candidates_in_retry_order(vec![addr.clone()]);
        assert_eq!(ordered, vec![addr]);
    }

    #[test]
    fn short_outbound_session_does_not_reset_backoff() {
        let mut mgr = PeerManager::new(125, 2);
        let peer = make_peer([198, 51, 100, 41], 33369, true);
        let addr = peer.addr.to_string();

        mgr.record_outbound_failure(&addr);
        mgr.reserve_outbound(&addr).expect("reserve outbound");
        mgr.register_peer(peer).expect("register outbound");
        mgr.remove_peer(&addr);

        assert_eq!(mgr.outbound_failure_count(&addr), 1);
    }

    #[test]
    fn backoff_increases_and_caps_with_deterministic_jitter() {
        let policy = RetryBackoffPolicy {
            initial_delay_secs: 5,
            max_delay_secs: 40,
            jitter: RetryJitterPolicy::None,
            reset_after_stable_session_secs: 120,
            max_in_flight_attempts: 8,
        };
        let addr = "198.51.100.50:33369";

        assert_eq!(policy.delay_after_failures(addr, 1), Duration::from_secs(5));
        assert_eq!(
            policy.delay_after_failures(addr, 2),
            Duration::from_secs(10)
        );
        assert_eq!(
            policy.delay_after_failures(addr, 3),
            Duration::from_secs(20)
        );
        assert_eq!(
            policy.delay_after_failures(addr, 4),
            Duration::from_secs(40)
        );
        assert_eq!(
            policy.delay_after_failures(addr, 8),
            Duration::from_secs(40)
        );
    }

    #[test]
    fn retry_jitter_is_stable_for_peer_address() {
        let policy = OUTBOUND_RECONNECT_POLICY;
        let addr = "198.51.100.51:33369";

        assert_eq!(
            policy.delay_after_failures(addr, 2),
            policy.delay_after_failures(addr, 2)
        );
        assert!(policy.delay_after_failures(addr, 2) <= Duration::from_secs(policy.max_delay_secs));
    }

    #[test]
    fn failed_configured_peer_remains_eligible_after_bounded_backoff() {
        let mut mgr = PeerManager::new(125, 2);
        let addr = "198.51.100.50:33369";

        mgr.record_outbound_failure(addr);
        assert!(
            mgr.outbound_candidates_in_retry_order(vec![addr.into()])
                .is_empty(),
            "retryable failure should delay, not poison, a configured peer"
        );

        while mgr.outbound_cooldown_rounds(addr) > 0 {
            assert!(mgr.advance_outbound_cooldowns());
        }
        assert_eq!(mgr.outbound_cooldown_rounds(addr), 0);
        assert_eq!(
            mgr.outbound_candidates_in_retry_order(vec![addr.into()]),
            vec![addr.to_string()]
        );
    }

    #[test]
    fn persisted_peer_rotation_state_roundtrips() {
        let mut mgr = PeerManager::new(125, 2);
        mgr.record_outbound_failure("198.51.100.30:33369");
        mgr.record_outbound_failure("198.51.100.10:33369");
        mgr.record_outbound_failure("198.51.100.30:33369");
        mgr.record_outbound_failure("198.51.100.30:33369");

        let snapshot = mgr.outbound_failure_state();
        let decoded = PersistedPeerRotationState::from_bytes(
            &snapshot.to_bytes().expect("serialize peer rotation"),
        )
        .expect("decode peer rotation");

        assert_eq!(decoded, snapshot);
    }

    #[test]
    fn restored_peer_rotation_state_preserves_retry_order() {
        let mut source = PeerManager::new(125, 2);
        source.record_outbound_failure("198.51.100.30:33369");
        source.record_outbound_failure("198.51.100.30:33369");
        source.record_outbound_failure("198.51.100.20:33369");
        source.record_outbound_failure("198.51.100.30:33369");

        let snapshot = source.outbound_failure_state();
        let expected = source.outbound_candidates_in_retry_order(vec![
            "198.51.100.30:33369".into(),
            "198.51.100.20:33369".into(),
            "198.51.100.10:33369".into(),
        ]);

        let mut restored = PeerManager::new(125, 2);
        restored
            .restore_outbound_failure_state(&snapshot)
            .expect("restore peer rotation");

        let actual = restored.outbound_candidates_in_retry_order(vec![
            "198.51.100.30:33369".into(),
            "198.51.100.20:33369".into(),
            "198.51.100.10:33369".into(),
        ]);
        assert_eq!(actual, expected);
        assert_eq!(
            restored.outbound_cooldown_rounds("198.51.100.30:33369"),
            source.outbound_cooldown_rounds("198.51.100.30:33369")
        );
    }

    #[test]
    fn restoring_peer_rotation_rejects_seq_regression() {
        let mut mgr = PeerManager::new(125, 2);
        let err = mgr
            .restore_outbound_failure_state(&PersistedPeerRotationState {
                next_failure_seq: 1,
                outbound_failures: vec![PersistedOutboundFailure {
                    addr: "198.51.100.30:33369".into(),
                    failures: 2,
                    last_failure_seq: 3,
                    cooldown_rounds: 0,
                }],
            })
            .expect_err("regressing next_failure_seq must reject");
        assert!(
            matches!(err, DomError::Invalid(ref msg) if msg.contains("next_failure_seq")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn persisted_peer_reputation_state_roundtrips() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([10, 0, 0, 42], 33369, false);
        let addr = peer.addr.to_string();
        mgr.register_peer(peer).expect("register peer");
        assert!(!mgr.add_ban_score(&addr, 25));
        assert_eq!(mgr.add_pending_ban_score("10.0.0.99:33369", 40), 40);

        let snapshot = mgr.peer_reputation_state();
        let decoded = PersistedPeerReputationState::from_bytes(
            &snapshot.to_bytes().expect("serialize peer reputation"),
        )
        .expect("decode peer reputation");

        assert_eq!(decoded, snapshot);
        assert_eq!(
            snapshot
                .entries
                .iter()
                .map(|entry| entry.addr.as_str())
                .collect::<Vec<_>>(),
            vec!["10.0.0.42", "10.0.0.99"]
        );
    }

    #[test]
    fn restored_peer_reputation_state_preserves_scores() {
        let snapshot = PersistedPeerReputationState {
            entries: vec![
                PersistedPeerReputation {
                    addr: "10.0.0.10:33369".into(),
                    score: 25,
                },
                PersistedPeerReputation {
                    addr: "10.0.0.20:33369".into(),
                    score: crate::peer::ban_scores::BAN_THRESHOLD,
                },
            ],
        };

        let mut mgr = PeerManager::new(125, 8);
        mgr.restore_peer_reputation_state(&snapshot)
            .expect("restore peer reputation");

        assert_eq!(mgr.pending_ban_score("10.0.0.10:33369"), 25);
        assert_eq!(
            mgr.pending_ban_score("10.0.0.20:33369"),
            crate::peer::ban_scores::BAN_THRESHOLD
        );
    }

    #[test]
    fn restoring_peer_reputation_rejects_unordered_snapshot() {
        let snapshot = PersistedPeerReputationState {
            entries: vec![
                PersistedPeerReputation {
                    addr: "10.0.0.20:33369".into(),
                    score: 10,
                },
                PersistedPeerReputation {
                    addr: "10.0.0.10:33369".into(),
                    score: 20,
                },
            ],
        };
        let mut mgr = PeerManager::new(125, 8);
        let err = mgr
            .restore_peer_reputation_state(&snapshot)
            .expect_err("unordered peer reputation must reject");
        assert!(
            matches!(err, DomError::Invalid(ref msg) if msg.contains("strictly ordered")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn peer_reputation_snapshot_is_bounded_by_highest_scores_then_address() {
        let mut mgr = PeerManager::new(125, 8);
        for i in 0..(MAX_PERSISTED_PEER_REPUTATION_ENTRIES + 2) {
            let addr = format!("10.0.{}.{}:33369", (i / 255) % 255, (i % 255) + 1);
            let score = if i < 2 { 5 } else { 10 };
            assert_eq!(mgr.add_pending_ban_score(&addr, score), score);
        }

        let snapshot = mgr.peer_reputation_state();
        assert_eq!(
            snapshot.entries.len(),
            MAX_PERSISTED_PEER_REPUTATION_ENTRIES
        );
        assert!(
            !snapshot
                .entries
                .iter()
                .any(|entry| entry.addr == "10.0.0.1:33369" || entry.addr == "10.0.0.2:33369"),
            "lowest-score entries should be evicted first"
        );
        let ordered = snapshot
            .entries
            .iter()
            .map(|entry| entry.addr.clone())
            .collect::<Vec<_>>();
        let mut sorted = ordered.clone();
        sorted.sort();
        assert_eq!(ordered, sorted, "snapshot must persist in canonical order");
    }

    #[test]
    fn remove_peer_converts_connected_score_into_pending_penalty() {
        let mut mgr = PeerManager::new(125, 8);
        let peer = make_peer([10, 0, 0, 77], 33369, false);
        let addr = peer.addr.to_string();
        mgr.register_peer(peer).expect("register peer");
        assert!(!mgr.add_ban_score(&addr, 35));

        mgr.remove_peer(&addr);

        assert!(mgr.ban_score(&addr).is_none());
        assert_eq!(mgr.pending_ban_score(&addr), 35);
    }

    #[test]
    fn restoring_peer_rotation_rejects_oversized_cooldown_state() {
        let mut mgr = PeerManager::new(125, 2);
        let err = mgr
            .restore_outbound_failure_state(&PersistedPeerRotationState {
                next_failure_seq: 3,
                outbound_failures: vec![PersistedOutboundFailure {
                    addr: "198.51.100.30:33369".into(),
                    failures: 1,
                    last_failure_seq: 3,
                    cooldown_rounds: MAX_OUTBOUND_FAILURE_COOLDOWN_ROUNDS + 1,
                }],
            })
            .expect_err("oversized cooldown must reject");
        assert!(
            matches!(err, DomError::Invalid(ref msg) if msg.contains("cooldown") && msg.contains("exceeds")),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn legacy_peer_rotation_snapshot_decodes_with_zero_cooldown() {
        use dom_serialization::Writer;

        let mut w = Writer::new();
        w.write_u64(3);
        w.write_u32(1);
        w.write_vec(b"198.51.100.30:33369").expect("addr");
        w.write_u8(2);
        w.write_u64(3);

        let decoded = PersistedPeerRotationState::from_legacy_bytes(&w.finish())
            .expect("legacy snapshot decode");
        assert_eq!(decoded.next_failure_seq, 3);
        assert_eq!(decoded.outbound_failures.len(), 1);
        assert_eq!(decoded.outbound_failures[0].failures, 2);
        assert_eq!(decoded.outbound_failures[0].cooldown_rounds, 0);
    }
}
