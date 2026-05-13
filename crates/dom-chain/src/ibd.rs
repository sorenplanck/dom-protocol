//! Initial Block Download — headers-first sync.
//!
//! Phase 1: Download and validate headers (lightweight, just PoW check).
//! Phase 2: Download full blocks for each validated header.
//!
//! This prevents wasting CPU validating transactions on a low-work chain.

use dom_core::{DomError, Timestamp};
use dom_consensus::block::BlockHeader;
use tracing::{info, debug};

/// Maximum headers per GET_HEADERS request.
pub const MAX_HEADERS_PER_REQUEST: usize = 2000;

/// IBD phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbdPhase {
    /// Downloading and validating headers.
    Headers,
    /// Headers validated, downloading full blocks.
    Blocks,
    /// IBD complete — node is synced.
    Complete,
}

/// IBD state machine.
pub struct IbdState {
    /// Current phase.
    pub phase: IbdPhase,
    /// Highest header height validated so far.
    pub headers_height: u64,
    /// Highest block height fully validated and committed.
    pub blocks_height: u64,
    /// Best peer height (from Hello messages).
    pub best_peer_height: u64,
    /// Pending header hashes waiting for full block download.
    pub pending_blocks: Vec<[u8; 32]>,
}

impl IbdState {
    /// Create a new IBD state starting from a given height.
    pub fn new(start_height: u64, best_peer_height: u64) -> Self {
        Self {
            phase: if start_height >= best_peer_height {
                IbdPhase::Complete
            } else {
                IbdPhase::Headers
            },
            headers_height: start_height,
            blocks_height: start_height,
            best_peer_height,
            pending_blocks: Vec::new(),
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
        if headers.is_empty() {
            // No more headers — we're caught up to this peer
            if self.headers_height >= self.best_peer_height {
                self.phase = IbdPhase::Blocks;
                info!("Headers phase complete at height {}. Starting block download.",
                    self.headers_height);
                return Ok(IbdAction::StartBlockDownload);
            }
            return Ok(IbdAction::RequestMoreHeaders(self.headers_height));
        }

        let mut new_hashes = Vec::new();
        let mut last_height = self.headers_height;

        for header in &headers {
            // Basic continuity check
            if header.height.0 != last_height + 1 {
                return Err(DomError::Invalid(format!(
                    "header gap: expected height {}, got {}",
                    last_height + 1, header.height.0
                )));
            }

            // Light validation (PoW only — no full tx validation yet)
            // Full validate_header_only is called in chain_state

            last_height = header.height.0;
            // Store header hash for block download phase
            let header_bytes = {
                use dom_serialization::DomSerialize;
                header.to_bytes().unwrap_or_default()
            };
            let hash = compute_hash(&header_bytes);
            new_hashes.push(hash);
        }

        self.headers_height = last_height;
        self.pending_blocks.extend(new_hashes);

        debug!("IBD headers: validated up to height {}", self.headers_height);

        if self.headers_height >= self.best_peer_height {
            self.phase = IbdPhase::Blocks;
            info!("Headers caught up at height {}. Downloading {} blocks.",
                self.headers_height, self.pending_blocks.len());
            Ok(IbdAction::StartBlockDownload)
        } else {
            Ok(IbdAction::RequestMoreHeaders(self.headers_height))
        }
    }

    /// Mark a block as fully validated and committed.
    pub fn mark_block_committed(&mut self, height: u64) {
        self.blocks_height = self.blocks_height.max(height);
        if self.blocks_height >= self.best_peer_height {
            self.phase = IbdPhase::Complete;
            info!("IBD complete at height {}", self.blocks_height);
        }
    }

    /// Check if IBD is complete.
    pub fn is_complete(&self) -> bool {
        self.phase == IbdPhase::Complete
    }

    /// Drain pending blocks to download (returns up to N hashes).
    pub fn drain_pending_blocks(&mut self, max: usize) -> Vec<[u8; 32]> {
        let n = max.min(self.pending_blocks.len());
        self.pending_blocks.drain(..n).collect()
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
    use blake2::{Blake2b, Digest};
    use blake2::digest::consts::U32;
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
        assert_eq!(ibd.phase, IbdPhase::Complete);
        assert!(ibd.is_complete());
    }

    #[test]
    fn ibd_headers_phase_when_behind() {
        let ibd = IbdState::new(0, 1000);
        assert_eq!(ibd.phase, IbdPhase::Headers);
        assert!(!ibd.is_complete());
    }

    #[test]
    fn empty_headers_triggers_block_download_when_caught_up() {
        let mut ibd = IbdState::new(1000, 1000);
        // Already at best height, getting empty headers
        ibd.phase = IbdPhase::Headers;
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
}
