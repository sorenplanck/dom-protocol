use dom_core::Hash256;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const MAX_PENDING_MISSING_BLOCKS: usize = 512;
const MAX_MISSING_BLOCK_RETRIES: u8 = 6;
const MISSING_BLOCK_RETRY_BASE_SECS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingBlockReason {
    MissingParent,
    MissingHeader,
    MissingBody,
}

impl MissingBlockReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingParent => "missing_parent",
            Self::MissingHeader => "missing_header",
            Self::MissingBody => "missing_body",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingBlockRequest {
    pub hash: [u8; 32],
    pub height: u64,
    pub reason: MissingBlockReason,
    pub peer: String,
    pub retry_count: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionOutcome {
    Connected,
    AlreadyPresent,
    SideChain,
    Reorg,
    DeliveredButStillMissingAncestor,
    Rejected,
}

#[derive(Debug, Clone)]
struct MissingBlockEntry {
    hash: [u8; 32],
    height: u64,
    reason: MissingBlockReason,
    preferred_peer: Option<String>,
    retry_count: u8,
    next_attempt_at: Instant,
    last_requested_peer: Option<String>,
}

pub struct MissingBlockTracker {
    entries: BTreeMap<(u64, [u8; 32]), MissingBlockEntry>,
}

impl MissingBlockTracker {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn schedule(
        &mut self,
        hash: Hash256,
        height: u64,
        reason: MissingBlockReason,
        preferred_peer: Option<String>,
        now: Instant,
    ) -> bool {
        let key = (height, *hash.as_bytes());
        if let Some(entry) = self.entries.get_mut(&key) {
            if entry.preferred_peer.is_none() {
                entry.preferred_peer = preferred_peer;
            }
            return false;
        }

        if self.entries.len() >= MAX_PENDING_MISSING_BLOCKS {
            return false;
        }

        self.entries.insert(
            key,
            MissingBlockEntry {
                hash: *hash.as_bytes(),
                height,
                reason,
                preferred_peer,
                retry_count: 0,
                next_attempt_at: now,
                last_requested_peer: None,
            },
        );
        true
    }

    pub fn due_requests<F>(
        &mut self,
        now: Instant,
        mut peer_selector: F,
    ) -> Vec<MissingBlockRequest>
    where
        F: FnMut(u64, Option<&str>) -> Vec<String>,
    {
        let mut out = Vec::new();
        for entry in self.entries.values_mut() {
            if entry.retry_count >= MAX_MISSING_BLOCK_RETRIES || now < entry.next_attempt_at {
                continue;
            }

            let candidates = peer_selector(entry.height, entry.preferred_peer.as_deref());
            if candidates.is_empty() {
                continue;
            }

            let idx = usize::from(entry.retry_count) % candidates.len();
            let peer = candidates[idx].clone();
            let retry_count = entry.retry_count;
            entry.retry_count = entry.retry_count.saturating_add(1);
            entry.next_attempt_at = now + retry_backoff(entry.retry_count);
            entry.last_requested_peer = Some(peer.clone());
            out.push(MissingBlockRequest {
                hash: entry.hash,
                height: entry.height,
                reason: entry.reason,
                peer,
                retry_count,
            });
        }
        out
    }

    pub fn resolve(
        &mut self,
        hash: &[u8; 32],
        outcome: ResolutionOutcome,
    ) -> Option<(MissingBlockEntrySnapshot, ResolutionOutcome)> {
        let key = self
            .entries
            .keys()
            .find(|(_, entry_hash)| entry_hash == hash)
            .copied()?;
        let entry = self.entries.remove(&key)?;
        Some((
            MissingBlockEntrySnapshot {
                hash: entry.hash,
                height: entry.height,
                reason: entry.reason,
                retry_count: entry.retry_count,
                last_requested_peer: entry.last_requested_peer,
            },
            outcome,
        ))
    }

    pub fn expire_exhausted(&mut self) -> Vec<MissingBlockEntrySnapshot> {
        let exhausted: Vec<(u64, [u8; 32])> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.retry_count >= MAX_MISSING_BLOCK_RETRIES)
            .map(|(key, _)| *key)
            .collect();
        let mut out = Vec::with_capacity(exhausted.len());
        for key in exhausted {
            if let Some(entry) = self.entries.remove(&key) {
                out.push(MissingBlockEntrySnapshot {
                    hash: entry.hash,
                    height: entry.height,
                    reason: entry.reason,
                    retry_count: entry.retry_count,
                    last_requested_peer: entry.last_requested_peer,
                });
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Default for MissingBlockTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingBlockEntrySnapshot {
    pub hash: [u8; 32],
    pub height: u64,
    pub reason: MissingBlockReason,
    pub retry_count: u8,
    pub last_requested_peer: Option<String>,
}

fn retry_backoff(retry_count: u8) -> Duration {
    let exponent = u32::from(retry_count.saturating_sub(1).min(5));
    Duration::from_secs(MISSING_BLOCK_RETRY_BASE_SECS.saturating_mul(1u64 << exponent))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash256 {
        Hash256::from_bytes([byte; 32])
    }

    #[test]
    fn missing_parent_triggers_request() {
        let mut tracker = MissingBlockTracker::new();
        let now = Instant::now();
        assert!(tracker.schedule(
            hash(1),
            10,
            MissingBlockReason::MissingParent,
            Some("10.0.0.2:33369".into()),
            now
        ));

        let requests = tracker.due_requests(now, |_, preferred| {
            preferred
                .into_iter()
                .map(str::to_string)
                .chain(["10.0.0.3:33369".to_string()])
                .collect()
        });
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].hash, [1; 32]);
        assert_eq!(requests[0].peer, "10.0.0.2:33369");
        assert_eq!(requests[0].retry_count, 0);
    }

    #[test]
    fn duplicate_missing_parent_does_not_trigger_unbounded_requests() {
        let mut tracker = MissingBlockTracker::new();
        let now = Instant::now();
        assert!(tracker.schedule(
            hash(2),
            11,
            MissingBlockReason::MissingParent,
            Some("10.0.0.2:33369".into()),
            now
        ));
        assert!(!tracker.schedule(
            hash(2),
            11,
            MissingBlockReason::MissingParent,
            Some("10.0.0.9:33369".into()),
            now
        ));

        let selector = |_: u64, preferred: Option<&str>| {
            preferred
                .into_iter()
                .map(str::to_string)
                .chain(["10.0.0.3:33369".to_string()])
                .collect::<Vec<_>>()
        };

        let first = tracker.due_requests(now, selector);
        assert_eq!(first.len(), 1);
        let second = tracker.due_requests(now, selector);
        assert!(
            second.is_empty(),
            "backoff must suppress immediate duplicates"
        );

        let third = tracker.due_requests(now + retry_backoff(1), selector);
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].retry_count, 1);
        assert_eq!(tracker.len(), 1);
    }

    #[test]
    fn retries_rotate_deterministically_across_candidate_peers() {
        let mut tracker = MissingBlockTracker::new();
        let now = Instant::now();
        tracker.schedule(hash(3), 12, MissingBlockReason::MissingParent, None, now);

        let peers = |_: u64, _: Option<&str>| {
            vec![
                "10.0.0.2:33369".to_string(),
                "10.0.0.4:33369".to_string(),
                "10.0.0.8:33369".to_string(),
            ]
        };

        let r0 = tracker.due_requests(now, peers);
        let r1 = tracker.due_requests(now + retry_backoff(1), peers);
        let r2 = tracker.due_requests(now + retry_backoff(1) + retry_backoff(2), peers);
        assert_eq!(r0[0].peer, "10.0.0.2:33369");
        assert_eq!(r1[0].peer, "10.0.0.4:33369");
        assert_eq!(r2[0].peer, "10.0.0.8:33369");
    }
}
