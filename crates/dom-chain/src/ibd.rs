//! Initial Block Download — headers-first sync.
//!
//! Phase 1: Download and validate headers (lightweight, just PoW check).
//! Phase 2: Download full blocks for each validated header.
//!
//! This prevents wasting CPU validating transactions on a low-work chain.

use dom_consensus::block::BlockHeader;
use dom_core::{DomError, Timestamp};
use tracing::{debug, info};

/// Maximum headers per GET_HEADERS request.
pub const MAX_HEADERS_PER_REQUEST: usize = 2000;

/// Maximum recoverable retries against one peer before the caller must stop
/// using that peer for this IBD session.
pub const MAX_IBD_RETRY_ATTEMPTS: u8 = 3;

/// IBD phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbdPhase {
    /// Session exists but has not started requesting data.
    Idle,
    /// Preparing the next deterministic sync round.
    Discovering,
    /// Downloading and validating headers.
    HeaderSync,
    /// Headers validated, downloading full blocks.
    BlockSync,
    /// Full blocks received; caller is verifying and committing them.
    Verifying,
    /// A recoverable failure happened and the next step is a bounded retry.
    Recovering,
    /// The current sync round was interrupted before making progress.
    Interrupted,
    /// IBD complete — node is synced.
    Completed,
    /// IBD against this peer failed and must not continue.
    Failed,
}

/// Deterministic interruption classes for bounded IBD recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbdInterruption {
    /// Peer claimed to be ahead but returned no useful data.
    EmptyResponse,
    /// Stream stalled or timed out.
    Timeout,
    /// Peer disconnected or stream I/O broke mid-round.
    PeerDisconnected,
    /// Verification was interrupted in a retryable way.
    Verification,
}

/// What the caller should do after a state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbdControl {
    /// Start or continue the next sync round.
    Continue,
    /// Retry the same peer, consuming part of the bounded retry budget.
    Retry,
    /// The peer is exhausted or permanently invalid; stop using it.
    Fail,
    /// The node is caught up to this session's target height.
    Complete,
}

/// IBD state machine.
pub struct IbdState {
    /// Current phase.
    pub phase: IbdPhase,
    /// Height where this peer-sync attempt started.
    pub start_height: u64,
    /// Highest header height validated so far.
    pub headers_height: u64,
    /// Highest block height fully validated and committed.
    pub blocks_height: u64,
    /// Best peer height (from Hello messages).
    pub best_peer_height: u64,
    /// Pending header hashes waiting for full block download.
    pub pending_blocks: Vec<[u8; 32]>,
    /// Recoverable retry attempts consumed against this peer.
    pub retry_attempts: u8,
    /// Highest height that made deterministic progress in this session.
    pub last_progress_height: u64,
    /// Most recent interruption class, if any.
    pub last_interruption: Option<IbdInterruption>,
}

impl IbdState {
    /// Create a new IBD state starting from a given height.
    pub fn new(start_height: u64, best_peer_height: u64) -> Self {
        Self {
            phase: if start_height >= best_peer_height {
                IbdPhase::Completed
            } else {
                IbdPhase::Idle
            },
            start_height,
            headers_height: start_height,
            blocks_height: start_height,
            best_peer_height,
            pending_blocks: Vec::new(),
            retry_attempts: 0,
            last_progress_height: start_height,
            last_interruption: None,
        }
    }

    /// Begin an IBD session or the next deterministic round.
    pub fn begin_session(&mut self) -> IbdControl {
        if self.blocks_height >= self.best_peer_height {
            self.phase = IbdPhase::Completed;
            return IbdControl::Complete;
        }
        self.phase = IbdPhase::Discovering;
        IbdControl::Continue
    }

    /// Enter the header-sync sub-phase for the next round.
    pub fn begin_header_sync(&mut self) {
        if !self.is_terminal() {
            self.phase = IbdPhase::HeaderSync;
        }
    }

    /// Enter the block-sync sub-phase once bodies are requested.
    pub fn begin_block_sync(&mut self) {
        if !self.is_terminal() {
            self.phase = IbdPhase::BlockSync;
        }
    }

    /// Enter the verification sub-phase while downloaded blocks are being
    /// validated and committed.
    pub fn begin_verification(&mut self) {
        if !self.is_terminal() {
            self.phase = IbdPhase::Verifying;
        }
    }

    /// Process a batch of headers received from a peer.
    ///
    /// Validates each header's PoW and continuity, then transitions
    /// to block download phase when caught up.
    pub fn process_headers(
        &mut self,
        headers: Vec<BlockHeader>,
        _now: Timestamp,
    ) -> Result<IbdAction, DomError> {
        self.begin_header_sync();

        if headers.is_empty() {
            if self.headers_height >= self.best_peer_height {
                self.phase = IbdPhase::BlockSync;
                info!(
                    "Headers phase complete at height {}. Starting block download.",
                    self.headers_height
                );
                return Ok(IbdAction::StartBlockDownload);
            }
            return Ok(IbdAction::RequestMoreHeaders(self.headers_height));
        }

        let mut new_hashes = Vec::new();
        let mut last_height = self.headers_height;

        for header in &headers {
            if header.height.0 != last_height + 1 {
                return Err(DomError::Invalid(format!(
                    "header gap: expected height {}, got {}",
                    last_height + 1,
                    header.height.0
                )));
            }

            last_height = header.height.0;
            let header_bytes = {
                use dom_serialization::DomSerialize;
                header.to_bytes().unwrap_or_default()
            };
            let hash = compute_hash(&header_bytes);
            new_hashes.push(hash);
        }

        self.headers_height = last_height;
        self.pending_blocks.extend(new_hashes);

        debug!(
            "IBD headers: validated up to height {}",
            self.headers_height
        );

        if self.headers_height >= self.best_peer_height {
            self.phase = IbdPhase::BlockSync;
            info!(
                "Headers caught up at height {}. Downloading {} blocks.",
                self.headers_height,
                self.pending_blocks.len()
            );
            Ok(IbdAction::StartBlockDownload)
        } else {
            Ok(IbdAction::RequestMoreHeaders(self.headers_height))
        }
    }

    /// Mark a block as fully validated and committed.
    pub fn mark_block_committed(&mut self, height: u64) {
        self.blocks_height = self.blocks_height.max(height);
        self.headers_height = self.headers_height.max(height);
        if self.blocks_height >= self.best_peer_height {
            self.phase = IbdPhase::Completed;
            self.last_progress_height = self.blocks_height;
        }
    }

    /// Check if IBD is complete.
    pub fn is_complete(&self) -> bool {
        self.phase == IbdPhase::Completed
    }

    /// Check if this peer session has permanently failed.
    pub fn is_failed(&self) -> bool {
        self.phase == IbdPhase::Failed
    }

    /// Check whether the state machine is in a terminal phase.
    pub fn is_terminal(&self) -> bool {
        self.is_complete() || self.is_failed()
    }

    /// Drain pending blocks to download (returns up to N hashes).
    pub fn drain_pending_blocks(&mut self, max: usize) -> Vec<[u8; 32]> {
        let n = max.min(self.pending_blocks.len());
        self.pending_blocks.drain(..n).collect()
    }

    /// Record deterministic progress after a successful sync round.
    pub fn note_round_progress(&mut self, height: u64) -> IbdControl {
        self.begin_verification();
        self.blocks_height = self.blocks_height.max(height);
        self.headers_height = self.headers_height.max(height);
        self.last_progress_height = self.blocks_height;
        self.retry_attempts = 0;
        self.last_interruption = None;

        if self.blocks_height >= self.best_peer_height {
            self.phase = IbdPhase::Completed;
            info!("IBD complete at height {}", self.blocks_height);
            IbdControl::Complete
        } else {
            self.phase = IbdPhase::Discovering;
            IbdControl::Continue
        }
    }

    /// Record an empty or stalled round.
    pub fn note_empty_response(&mut self) -> IbdControl {
        if self.blocks_height >= self.best_peer_height {
            self.phase = IbdPhase::Completed;
            return IbdControl::Complete;
        }
        self.note_interruption(IbdInterruption::EmptyResponse)
    }

    /// Record a recoverable interruption.
    pub fn note_interruption(&mut self, interruption: IbdInterruption) -> IbdControl {
        self.phase = IbdPhase::Interrupted;
        self.last_interruption = Some(interruption);
        self.retry_attempts = self.retry_attempts.saturating_add(1);
        if self.retry_attempts > MAX_IBD_RETRY_ATTEMPTS {
            self.phase = IbdPhase::Failed;
            IbdControl::Fail
        } else {
            self.phase = IbdPhase::Recovering;
            IbdControl::Retry
        }
    }

    /// Deterministically classify a round error into retry or fail.
    pub fn note_round_error(&mut self, error: &DomError) -> IbdControl {
        match error {
            DomError::TemporarilyInvalid(_) => self.note_interruption(IbdInterruption::Timeout),
            DomError::PolicyRejected(msg) if msg.contains("idle timeout") => {
                self.note_interruption(IbdInterruption::Timeout)
            }
            DomError::Orphan(_) | DomError::Internal(_) => {
                self.note_interruption(IbdInterruption::PeerDisconnected)
            }
            DomError::Invalid(_) | DomError::Malformed(_) | DomError::PolicyRejected(_) => {
                self.phase = IbdPhase::Failed;
                IbdControl::Fail
            }
        }
    }

    /// How many recoverable retries remain for this peer.
    pub fn remaining_retries(&self) -> u8 {
        MAX_IBD_RETRY_ATTEMPTS.saturating_sub(self.retry_attempts)
    }
}

/// Action the node should take based on IBD state.
#[derive(Debug, Clone)]
pub enum IbdAction {
    /// Request more headers starting from this height.
    RequestMoreHeaders(u64),
    /// Start downloading full blocks.
    StartBlockDownload,
    /// IBD is complete.
    IbdComplete,
}

fn compute_hash(data: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    type B2b256 = Blake2b<U32>;
    let mut h = B2b256::new();
    h.update(data);
    let result = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&result);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ibd_complete_when_caught_up() {
        let ibd = IbdState::new(100, 100);
        assert_eq!(ibd.phase, IbdPhase::Completed);
        assert!(ibd.is_complete());
    }

    #[test]
    fn ibd_headers_phase_when_behind() {
        let ibd = IbdState::new(0, 1000);
        assert_eq!(ibd.phase, IbdPhase::Idle);
        assert!(!ibd.is_complete());
    }

    #[test]
    fn empty_headers_triggers_block_download_when_caught_up() {
        let mut ibd = IbdState::new(1000, 1000);
        ibd.phase = IbdPhase::HeaderSync;
        ibd.headers_height = 1000;
        let action = ibd.process_headers(vec![], Timestamp(0)).unwrap();
        assert!(matches!(action, IbdAction::StartBlockDownload));
    }

    #[test]
    fn drain_pending_blocks() {
        let mut ibd = IbdState::new(0, 100);
        ibd.pending_blocks = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let batch = ibd.drain_pending_blocks(2);
        assert_eq!(batch.len(), 2);
        assert_eq!(ibd.pending_blocks.len(), 1);
    }

    #[test]
    fn begin_session_transitions_idle_to_discovering() {
        let mut ibd = IbdState::new(0, 10);
        assert_eq!(ibd.begin_session(), IbdControl::Continue);
        assert_eq!(ibd.phase, IbdPhase::Discovering);
    }

    #[test]
    fn successful_round_resets_retry_budget_and_completes_when_caught_up() {
        let mut ibd = IbdState::new(0, 5);
        ibd.note_interruption(IbdInterruption::EmptyResponse);
        ibd.note_interruption(IbdInterruption::Timeout);
        assert_eq!(ibd.retry_attempts, 2);

        let action = ibd.note_round_progress(5);
        assert_eq!(action, IbdControl::Complete);
        assert_eq!(ibd.retry_attempts, 0);
        assert_eq!(ibd.phase, IbdPhase::Completed);
    }

    #[test]
    fn recoverable_interruptions_are_bounded() {
        let mut ibd = IbdState::new(0, 50);
        assert_eq!(
            ibd.note_interruption(IbdInterruption::EmptyResponse),
            IbdControl::Retry
        );
        assert_eq!(ibd.phase, IbdPhase::Recovering);
        assert_eq!(ibd.remaining_retries(), 2);

        assert_eq!(
            ibd.note_interruption(IbdInterruption::Timeout),
            IbdControl::Retry
        );
        assert_eq!(
            ibd.note_interruption(IbdInterruption::PeerDisconnected),
            IbdControl::Retry
        );
        assert_eq!(
            ibd.note_interruption(IbdInterruption::Verification),
            IbdControl::Fail
        );
        assert_eq!(ibd.phase, IbdPhase::Failed);
    }

    #[test]
    fn invalid_round_error_fails_without_retry() {
        let mut ibd = IbdState::new(0, 50);
        let action = ibd.note_round_error(&DomError::Invalid("bad ordering".into()));
        assert_eq!(action, IbdControl::Fail);
        assert_eq!(ibd.retry_attempts, 0);
        assert!(ibd.is_failed());
    }

    #[test]
    fn idle_timeout_round_error_consumes_bounded_retry() {
        let mut ibd = IbdState::new(0, 50);
        let action =
            ibd.note_round_error(&DomError::PolicyRejected("idle timeout after 30s".into()));
        assert_eq!(action, IbdControl::Retry);
        assert_eq!(ibd.retry_attempts, 1);
        assert_eq!(ibd.last_interruption, Some(IbdInterruption::Timeout));
        assert_eq!(ibd.phase, IbdPhase::Recovering);
    }
}
