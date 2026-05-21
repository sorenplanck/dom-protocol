//! Peer reputation and scoring system.
//!
//! Tracks peer behavior to detect malicious or buggy peers and ban them
//! after repeated violations. Pure Rust, no external dependencies.

use std::collections::HashMap;
use std::time::{Duration, Instant};

const INITIAL_SCORE: i32 = 0;
const BAN_THRESHOLD: i32 = -100;
const MAX_SCORE: i32 = 100;
const MIN_SCORE: i32 = -200;

/// Severity levels for peer misbehavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Minor,
    Moderate,
    Severe,
    Critical,
}

#[derive(Debug, Clone)]
struct PeerScore {
    score: i32,
    last_updated: Instant,
}

/// Tracks reputation scores and bans for peers.
pub struct PeerScorer {
    scores: HashMap<String, PeerScore>,
    bans: HashMap<String, Instant>,
    ban_duration: Duration,
}

impl PeerScorer {
    pub fn new(ban_duration_secs: u64) -> Self {
        Self {
            scores: HashMap::new(),
            bans: HashMap::new(),
            ban_duration: Duration::from_secs(ban_duration_secs),
        }
    }

    pub fn is_banned(&self, peer_id: &str) -> bool {
        if let Some(banned_until) = self.bans.get(peer_id) {
            if *banned_until > Instant::now() {
                return true;
            }
        }
        false
    }

    pub fn get_score(&self, peer_id: &str) -> i32 {
        self.scores
            .get(peer_id)
            .map(|s| s.score)
            .unwrap_or(INITIAL_SCORE)
    }

    pub fn adjust_score(&mut self, peer_id: &str, delta: i32) {
        let entry = self.scores.entry(peer_id.to_string()).or_insert(PeerScore {
            score: INITIAL_SCORE,
            last_updated: Instant::now(),
        });

        entry.score = (entry.score + delta).clamp(MIN_SCORE, MAX_SCORE);
        entry.last_updated = Instant::now();

        if entry.score <= BAN_THRESHOLD {
            self.ban_peer(peer_id);
        }
    }

    fn ban_peer(&mut self, peer_id: &str) {
        self.bans
            .insert(peer_id.to_string(), Instant::now() + self.ban_duration);
    }

    pub fn good_behavior(&mut self, peer_id: &str) {
        self.adjust_score(peer_id, 1);
    }

    pub fn bad_behavior(&mut self, peer_id: &str, severity: Severity) {
        let penalty = match severity {
            Severity::Minor => -5,
            Severity::Moderate => -20,
            Severity::Severe => -50,
            Severity::Critical => -150,
        };
        self.adjust_score(peer_id, penalty);
    }

    pub fn clear_expired_bans(&mut self) {
        let now = Instant::now();
        self.bans.retain(|_, banned_until| *banned_until > now);
    }

    /// Evaluate peer clock drift and return action recommendation.
    ///
    /// Compares peer's reported local_timestamp against our local timestamp.
    /// Thresholds from dom_core: PEER_DRIFT_WARN_SECS and PEER_DRIFT_DISCONNECT_SECS.
    pub fn evaluate_peer_drift(
        &mut self,
        peer_id: &str,
        local_timestamp: u64,
        peer_timestamp: u64,
    ) -> PeerAction {
        let drift = (local_timestamp as i64 - peer_timestamp as i64).abs();
        if drift > dom_core::PEER_DRIFT_DISCONNECT_SECS {
            return PeerAction::Disconnect(format!("clock drift: {}s", drift));
        }
        if drift > dom_core::PEER_DRIFT_WARN_SECS {
            self.bad_behavior(peer_id, Severity::Moderate);
            return PeerAction::Warn(format!("clock drift: {}s", drift));
        }
        PeerAction::Accept
    }
}

/// Action recommended after peer drift evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAction {
    /// Peer drift is within acceptable bounds.
    Accept,
    /// Peer drift triggered warning; continue but log.
    Warn(String),
    /// Peer drift exceeds disconnect threshold; drop connection.
    Disconnect(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scoring_works() {
        let mut scorer = PeerScorer::new(3600);
        scorer.good_behavior("peer1");
        assert_eq!(scorer.get_score("peer1"), 1);
        scorer.bad_behavior("peer1", Severity::Moderate);
        assert_eq!(scorer.get_score("peer1"), -19);
    }

    #[test]
    fn banning_works() {
        let mut scorer = PeerScorer::new(3600);
        assert!(!scorer.is_banned("peer1"));
        scorer.bad_behavior("peer1", Severity::Critical);
        assert!(scorer.is_banned("peer1"));
    }

    #[test]
    fn score_clamped_at_max() {
        let mut scorer = PeerScorer::new(3600);
        for _ in 0..200 {
            scorer.good_behavior("peer1");
        }
        assert_eq!(scorer.get_score("peer1"), MAX_SCORE);
    }

    #[test]
    fn score_clamped_at_min() {
        let mut scorer = PeerScorer::new(3600);
        for _ in 0..10 {
            scorer.bad_behavior("peer1", Severity::Critical);
        }
        assert_eq!(scorer.get_score("peer1"), MIN_SCORE);
    }

    #[test]
    fn peer_drift_accept() {
        let mut scorer = PeerScorer::new(3600);
        let action = scorer.evaluate_peer_drift("peer1", 1000, 1010);
        assert_eq!(action, PeerAction::Accept);
    }

    #[test]
    fn peer_drift_warn() {
        let mut scorer = PeerScorer::new(3600);
        // drift = 40s > PEER_DRIFT_WARN_SECS (30s)
        let action = scorer.evaluate_peer_drift("peer1", 1000, 1040);
        assert!(matches!(action, PeerAction::Warn(_)));
    }

    #[test]
    fn peer_drift_disconnect() {
        let mut scorer = PeerScorer::new(3600);
        // drift = 100s > PEER_DRIFT_DISCONNECT_SECS (90s)
        let action = scorer.evaluate_peer_drift("peer1", 1000, 1100);
        assert!(matches!(action, PeerAction::Disconnect(_)));
    }
}
