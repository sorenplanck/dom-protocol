//! Initial Block Download — headers-first sync.
//!
//! Phase 1: Download and validate headers (lightweight, just PoW check).
//! Phase 2: Download full blocks for each validated header.
//!
//! This prevents wasting CPU validating transactions on a low-work chain.

use dom_consensus::block::BlockHeader;
use dom_core::{DomError, Timestamp};
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};
use tracing::{debug, info};

/// Maximum headers per GET_HEADERS request.
pub const MAX_HEADERS_PER_REQUEST: usize = 2000;

/// Maximum recoverable retries against one peer before the caller must stop
/// using that peer for this IBD session.
pub const MAX_IBD_RETRY_ATTEMPTS: u8 = 3;
/// Stable metadata key for the persisted IBD session snapshot.
pub const IBD_SESSION_METADATA_KEY: &[u8] = b"ibd_session";

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

/// Bounded persisted IBD session snapshot.
///
/// This is the restart-safe checkpoint written by the live node. It records
/// only deterministic orchestration state: phase, target, peer identity,
/// bounded retry accounting, bounded work queue, and explicit cursors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedIbdState {
    /// Current persisted phase.
    pub phase: IbdPhase,
    /// Deterministic peer identifier (socket address string).
    pub peer_addr: String,
    /// Height where this peer-sync attempt started.
    pub start_height: u64,
    /// Target height claimed by the peer when this session began.
    pub best_peer_height: u64,
    /// Highest header height validated so far.
    pub headers_height: u64,
    /// Highest block height fully validated and committed.
    pub blocks_height: u64,
    /// Highest height that made deterministic progress in this session.
    pub last_progress_height: u64,
    /// Canonical tip hash that this session snapshot was anchored to.
    pub checkpoint_tip_hash: [u8; 32],
    /// Recoverable retry attempts consumed against this peer.
    pub retry_attempts: u8,
    /// Most recent interruption class, if any.
    pub last_interruption: Option<IbdInterruption>,
    /// Pending bounded work queue for the current round.
    pub pending_blocks: Vec<[u8; 32]>,
    /// Pending raw header payloads for the current round.
    pub pending_headers: Vec<Vec<u8>>,
    /// Cursor into `pending_blocks` for partial block-batch resume.
    pub block_cursor: u32,
    /// Cursor into `pending_headers` for partial header-batch resume.
    pub header_cursor: u32,
    /// Height of the last header in the current round.
    pub header_cursor_height: u64,
}

impl PersistedIbdState {
    /// Persist this session snapshot into the store metadata DB.
    pub fn save(&self, store: &dom_store::DomStore) -> Result<(), DomError> {
        store.put_metadata(IBD_SESSION_METADATA_KEY, &self.to_bytes()?)
    }

    /// Load the persisted IBD session snapshot, if any.
    pub fn load(store: &dom_store::DomStore) -> Result<Option<Self>, DomError> {
        match store.get_metadata(IBD_SESSION_METADATA_KEY)? {
            Some(bytes) => Ok(Some(Self::from_bytes(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Clear any persisted IBD session snapshot.
    pub fn clear(store: &dom_store::DomStore) -> Result<(), DomError> {
        store.delete_metadata(IBD_SESSION_METADATA_KEY)
    }

    /// Returns true if this snapshot can be resumed without reconstructing
    /// in-flight round state.
    pub fn is_round_resumable(&self) -> bool {
        self.block_cursor as usize <= self.pending_blocks.len()
            && self.header_cursor as usize <= self.pending_headers.len()
            && (self.pending_blocks.is_empty() || self.header_cursor == 0)
            && (self.pending_headers.is_empty() || self.block_cursor == 0)
    }
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

impl DomSerialize for IbdPhase {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        let tag = match self {
            Self::Idle => 0,
            Self::Discovering => 1,
            Self::HeaderSync => 2,
            Self::BlockSync => 3,
            Self::Verifying => 4,
            Self::Recovering => 5,
            Self::Interrupted => 6,
            Self::Completed => 7,
            Self::Failed => 8,
        };
        w.write_u8(tag);
        Ok(())
    }
}

impl DomDeserialize for IbdPhase {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        match r.read_u8()? {
            0 => Ok(Self::Idle),
            1 => Ok(Self::Discovering),
            2 => Ok(Self::HeaderSync),
            3 => Ok(Self::BlockSync),
            4 => Ok(Self::Verifying),
            5 => Ok(Self::Recovering),
            6 => Ok(Self::Interrupted),
            7 => Ok(Self::Completed),
            8 => Ok(Self::Failed),
            other => Err(DomError::Malformed(format!(
                "unknown IBD phase tag {other}"
            ))),
        }
    }
}

impl DomSerialize for IbdInterruption {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        let tag = match self {
            Self::EmptyResponse => 0,
            Self::Timeout => 1,
            Self::PeerDisconnected => 2,
            Self::Verification => 3,
        };
        w.write_u8(tag);
        Ok(())
    }
}

impl DomDeserialize for IbdInterruption {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        match r.read_u8()? {
            0 => Ok(Self::EmptyResponse),
            1 => Ok(Self::Timeout),
            2 => Ok(Self::PeerDisconnected),
            3 => Ok(Self::Verification),
            other => Err(DomError::Malformed(format!(
                "unknown IBD interruption tag {other}"
            ))),
        }
    }
}

impl DomSerialize for PersistedIbdState {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        self.phase.serialize(w)?;
        w.write_vec(self.peer_addr.as_bytes())?;
        w.write_u64(self.start_height);
        w.write_u64(self.best_peer_height);
        w.write_u64(self.headers_height);
        w.write_u64(self.blocks_height);
        w.write_u64(self.last_progress_height);
        w.write_bytes(&self.checkpoint_tip_hash);
        w.write_u8(self.retry_attempts);
        match self.last_interruption {
            Some(interruption) => {
                w.write_u8(1);
                interruption.serialize(w)?;
            }
            None => w.write_u8(0),
        }

        let pending_len: u32 = self
            .pending_blocks
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("pending block count exceeds u32".into()))?;
        w.write_u32(pending_len);
        for hash in &self.pending_blocks {
            w.write_bytes(hash);
        }
        let pending_headers_len: u32 = self
            .pending_headers
            .len()
            .try_into()
            .map_err(|_| DomError::Malformed("pending header count exceeds u32".into()))?;
        w.write_u32(pending_headers_len);
        for header_bytes in &self.pending_headers {
            w.write_vec(header_bytes)?;
        }
        w.write_u32(self.block_cursor);
        w.write_u32(self.header_cursor);
        w.write_u64(self.header_cursor_height);
        Ok(())
    }
}

impl DomDeserialize for PersistedIbdState {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let phase = IbdPhase::deserialize(r)?;
        let peer_addr_bytes = r.read_vec(128)?;
        let peer_addr = String::from_utf8(peer_addr_bytes)
            .map_err(|e| DomError::Malformed(format!("invalid persisted peer addr utf8: {e}")))?;
        let start_height = r.read_u64()?;
        let best_peer_height = r.read_u64()?;
        let headers_height = r.read_u64()?;
        let blocks_height = r.read_u64()?;
        let last_progress_height = r.read_u64()?;
        let checkpoint_tip_hash = r.read_array::<32>()?;
        let retry_attempts = r.read_u8()?;
        let last_interruption = match r.read_u8()? {
            0 => None,
            1 => Some(IbdInterruption::deserialize(r)?),
            other => {
                return Err(DomError::Malformed(format!(
                    "invalid persisted interruption presence tag {other}"
                )))
            }
        };

        let pending_len = r.read_u32()? as usize;
        if pending_len > dom_core::MAX_HEADERS_PER_MSG {
            return Err(DomError::Malformed(format!(
                "persisted pending block count {pending_len} exceeds limit {}",
                dom_core::MAX_HEADERS_PER_MSG
            )));
        }
        let mut pending_blocks = Vec::with_capacity(pending_len);
        for _ in 0..pending_len {
            pending_blocks.push(r.read_array::<32>()?);
        }
        let pending_headers_len = r.read_u32()? as usize;
        if pending_headers_len > dom_core::MAX_HEADERS_PER_MSG {
            return Err(DomError::Malformed(format!(
                "persisted pending header count {pending_headers_len} exceeds limit {}",
                dom_core::MAX_HEADERS_PER_MSG
            )));
        }
        let mut pending_headers = Vec::with_capacity(pending_headers_len);
        for _ in 0..pending_headers_len {
            pending_headers.push(r.read_vec(1024)?);
        }
        let block_cursor = r.read_u32()?;
        if block_cursor as usize > pending_blocks.len() {
            return Err(DomError::Malformed(format!(
                "persisted block cursor {} exceeds pending block count {}",
                block_cursor,
                pending_blocks.len()
            )));
        }
        let header_cursor = r.read_u32()?;
        if header_cursor as usize > pending_headers.len() {
            return Err(DomError::Malformed(format!(
                "persisted header cursor {} exceeds pending header count {}",
                header_cursor,
                pending_headers.len()
            )));
        }
        let header_cursor_height = r.read_u64()?;

        // Semantic invariants the IBD state machine guarantees in every valid
        // state, copied 1:1 into the snapshot by node::persist_ibd_state. A
        // snapshot violating these is corrupt. `last_progress_height` tracks
        // the highest deterministic progress of the session, which can come
        // from header validation before any block has been committed; so the
        // valid ordering is `start <= blocks <= last_progress <= headers`.
        //
        // NOTE: `best_peer_height` and
        // `header_cursor_height` are intentionally NOT constrained — best_peer
        // can legitimately be < start_height (init Completed) or be exceeded by
        // headers/blocks when the peer grows, and header_cursor_height has no
        // proven ordering invariant. Structural checks (cursor ≤ count, caps)
        // above are kept as-is.
        if start_height > blocks_height
            || blocks_height > last_progress_height
            || last_progress_height > headers_height
        {
            return Err(DomError::Malformed(format!(
                "ibd state: non-monotonic heights (start={start_height}, \
                 last_progress={last_progress_height}, blocks={blocks_height}, \
                 headers={headers_height})"
            )));
        }
        if retry_attempts > MAX_IBD_RETRY_ATTEMPTS {
            return Err(DomError::Malformed(format!(
                "ibd state: retry_attempts {retry_attempts} exceeds max {MAX_IBD_RETRY_ATTEMPTS}"
            )));
        }

        Ok(Self {
            phase,
            peer_addr,
            start_height,
            best_peer_height,
            headers_height,
            blocks_height,
            last_progress_height,
            checkpoint_tip_hash,
            retry_attempts,
            last_interruption,
            pending_blocks,
            pending_headers,
            block_cursor,
            header_cursor,
            header_cursor_height,
        })
    }
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

    /// Restore an in-memory IBD controller from a persisted snapshot.
    ///
    /// Queue contents are resumed explicitly by the node using the persisted
    /// cursors and ordered work lists. This constructor restores only the
    /// deterministic controller fields after validating those cursors.
    pub fn from_persisted(snapshot: &PersistedIbdState) -> Result<Self, DomError> {
        if !snapshot.is_round_resumable() {
            return Err(DomError::PolicyRejected(
                "persisted IBD snapshot has invalid round cursor".into(),
            ));
        }

        Ok(Self {
            phase: snapshot.phase,
            start_height: snapshot.start_height,
            headers_height: snapshot.headers_height,
            blocks_height: snapshot.blocks_height,
            best_peer_height: snapshot.best_peer_height,
            pending_blocks: snapshot.pending_blocks.clone(),
            retry_attempts: snapshot.retry_attempts,
            last_progress_height: snapshot.last_progress_height,
            last_interruption: snapshot.last_interruption,
        })
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

/// dom-shield XDIFF probe (test-only): expose the otherwise-private IBD
/// header-hash function so the chain_state XDIFF parity test can prove that the
/// IBD path and the chain_state connect/validate path hash a header byte string
/// identically. A divergence between the two would let an IBD-validated header
/// resolve to a different block hash than the same header connected live —
/// silently splitting duplicate-suppression and parent linkage.
#[cfg(test)]
pub(crate) fn compute_hash_probe(data: &[u8]) -> [u8; 32] {
    compute_hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A structurally + semantically valid snapshot: heights satisfy the
    /// state-machine chain (start ≤ blocks ≤ last_progress ≤ headers) and
    /// retry_attempts ≤ MAX_IBD_RETRY_ATTEMPTS.
    fn valid_snapshot() -> PersistedIbdState {
        PersistedIbdState {
            phase: IbdPhase::BlockSync,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: 10,
            best_peer_height: 25,
            headers_height: 14,
            blocks_height: 12,
            last_progress_height: 12,
            checkpoint_tip_hash: [0x12; 32],
            retry_attempts: 2,
            last_interruption: None,
            pending_blocks: Vec::new(),
            pending_headers: Vec::new(),
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: 14,
        }
    }

    /// Round-trip a snapshot through the validated load path (to_bytes/from_bytes).
    fn roundtrip(s: &PersistedIbdState) -> Result<PersistedIbdState, DomError> {
        PersistedIbdState::from_bytes(&s.to_bytes().expect("serialize"))
    }

    #[test]
    fn valid_snapshot_roundtrips() {
        assert!(roundtrip(&valid_snapshot()).is_ok());
    }

    #[test]
    fn init_equal_heights_accepted() {
        // IbdState::new leaves start == last_progress == blocks == headers.
        let mut s = valid_snapshot();
        s.start_height = 10;
        s.last_progress_height = 10;
        s.blocks_height = 10;
        s.headers_height = 10;
        assert!(roundtrip(&s).is_ok());
    }

    #[test]
    fn best_peer_below_start_accepted() {
        // Legitimate: IbdState::new(100, 50) → Completed; best_peer_height is free.
        let mut s = valid_snapshot();
        s.start_height = 100;
        s.last_progress_height = 100;
        s.blocks_height = 100;
        s.headers_height = 100;
        s.best_peer_height = 50;
        assert!(roundtrip(&s).is_ok());
    }

    #[test]
    fn headers_above_best_peer_accepted() {
        // Legitimate: the peer chain grew; headers/blocks may exceed the initial
        // best_peer_height claim. best_peer_height carries no ordering invariant.
        let mut s = valid_snapshot();
        s.best_peer_height = 25;
        s.headers_height = 30;
        s.blocks_height = 28;
        s.last_progress_height = 28;
        assert!(roundtrip(&s).is_ok());
    }

    #[test]
    fn blocks_above_headers_rejected() {
        let mut s = valid_snapshot();
        s.blocks_height = 15; // > headers_height (14)
        let err = roundtrip(&s).expect_err("must reject blocks > headers");
        assert!(matches!(err, DomError::Malformed(_)), "got: {err:?}");
    }

    #[test]
    fn header_only_progress_above_blocks_accepted() {
        let mut s = valid_snapshot();
        s.last_progress_height = 13; // > blocks_height (12), still <= headers_height (14)
        assert!(roundtrip(&s).is_ok());
    }

    #[test]
    fn last_progress_above_headers_rejected() {
        let mut s = valid_snapshot();
        s.last_progress_height = 15; // > headers_height (14)
        let err = roundtrip(&s).expect_err("must reject last_progress > headers");
        assert!(matches!(err, DomError::Malformed(_)), "got: {err:?}");
    }

    #[test]
    fn start_above_last_progress_rejected() {
        let mut s = valid_snapshot();
        s.start_height = 13; // > last_progress_height (12)
        let err = roundtrip(&s).expect_err("must reject start > last_progress");
        assert!(matches!(err, DomError::Malformed(_)), "got: {err:?}");
    }

    #[test]
    fn retry_attempts_over_max_rejected() {
        let mut s = valid_snapshot();
        s.retry_attempts = 255; // > MAX_IBD_RETRY_ATTEMPTS
        let err = roundtrip(&s).expect_err("must reject retry_attempts > max");
        assert!(matches!(err, DomError::Malformed(_)), "got: {err:?}");
    }

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

    #[test]
    fn resumable_persisted_state_restores_retry_accounting() {
        let snapshot = PersistedIbdState {
            phase: IbdPhase::Recovering,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: 10,
            best_peer_height: 25,
            headers_height: 14,
            blocks_height: 12,
            last_progress_height: 12,
            checkpoint_tip_hash: [0x12; 32],
            retry_attempts: 2,
            last_interruption: Some(IbdInterruption::Timeout),
            pending_blocks: Vec::new(),
            pending_headers: Vec::new(),
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: 14,
        };
        let ibd = IbdState::from_persisted(&snapshot).expect("restore");
        assert_eq!(ibd.phase, IbdPhase::Recovering);
        assert_eq!(ibd.retry_attempts, 2);
        assert_eq!(ibd.blocks_height, 12);
        assert_eq!(ibd.best_peer_height, 25);
    }

    #[test]
    fn partial_round_snapshot_restores_pending_work() {
        let snapshot = PersistedIbdState {
            phase: IbdPhase::BlockSync,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: 10,
            best_peer_height: 25,
            headers_height: 20,
            blocks_height: 12,
            last_progress_height: 12,
            checkpoint_tip_hash: [0x12; 32],
            retry_attempts: 1,
            last_interruption: None,
            pending_blocks: vec![[0x44; 32]],
            pending_headers: vec![vec![0xAA; 32]],
            block_cursor: 0,
            header_cursor: 0,
            header_cursor_height: 20,
        };
        let ibd = IbdState::from_persisted(&snapshot).expect("partial round restore");
        assert_eq!(ibd.pending_blocks, vec![[0x44; 32]]);
        assert_eq!(ibd.headers_height, 20);
    }

    #[test]
    fn invalid_partial_round_cursor_is_rejected() {
        let snapshot = PersistedIbdState {
            phase: IbdPhase::BlockSync,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: 10,
            best_peer_height: 25,
            headers_height: 20,
            blocks_height: 12,
            last_progress_height: 12,
            checkpoint_tip_hash: [0x12; 32],
            retry_attempts: 1,
            last_interruption: None,
            pending_blocks: vec![[0x44; 32]],
            pending_headers: Vec::new(),
            block_cursor: 2,
            header_cursor: 0,
            header_cursor_height: 20,
        };
        let err = match IbdState::from_persisted(&snapshot) {
            Ok(_) => panic!("invalid cursor must reject"),
            Err(err) => err,
        };
        assert!(matches!(err, DomError::PolicyRejected(_)));
    }

    #[test]
    fn invalid_partial_header_cursor_is_rejected() {
        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: 10,
            best_peer_height: 25,
            headers_height: 12,
            blocks_height: 10,
            last_progress_height: 10,
            checkpoint_tip_hash: [0x12; 32],
            retry_attempts: 1,
            last_interruption: Some(IbdInterruption::Timeout),
            pending_blocks: vec![[0x44; 32]],
            pending_headers: vec![vec![0xAA; 32]],
            block_cursor: 0,
            header_cursor: 2,
            header_cursor_height: 20,
        };
        let err = match IbdState::from_persisted(&snapshot) {
            Ok(_) => panic!("invalid header cursor must reject"),
            Err(err) => err,
        };
        assert!(matches!(err, DomError::PolicyRejected(_)));
    }

    #[test]
    fn header_resume_snapshot_rejects_nonzero_block_cursor() {
        let snapshot = PersistedIbdState {
            phase: IbdPhase::HeaderSync,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: 10,
            best_peer_height: 25,
            headers_height: 12,
            blocks_height: 10,
            last_progress_height: 10,
            checkpoint_tip_hash: [0x12; 32],
            retry_attempts: 1,
            last_interruption: Some(IbdInterruption::Timeout),
            pending_blocks: vec![[0x44; 32]],
            pending_headers: vec![vec![0xAA; 32]],
            block_cursor: 1,
            header_cursor: 0,
            header_cursor_height: 20,
        };
        let err = match IbdState::from_persisted(&snapshot) {
            Ok(_) => panic!("ambiguous mixed cursor state must reject"),
            Err(err) => err,
        };
        assert!(matches!(err, DomError::PolicyRejected(_)));
    }

    #[test]
    fn block_resume_snapshot_rejects_nonzero_header_cursor() {
        let snapshot = PersistedIbdState {
            phase: IbdPhase::BlockSync,
            peer_addr: "127.0.0.1:33369".into(),
            start_height: 10,
            best_peer_height: 25,
            headers_height: 20,
            blocks_height: 12,
            last_progress_height: 12,
            checkpoint_tip_hash: [0x12; 32],
            retry_attempts: 1,
            last_interruption: Some(IbdInterruption::Timeout),
            pending_blocks: vec![[0x44; 32]],
            pending_headers: vec![vec![0xAA; 32]],
            block_cursor: 0,
            header_cursor: 1,
            header_cursor_height: 20,
        };
        let err = match IbdState::from_persisted(&snapshot) {
            Ok(_) => panic!("ambiguous mixed cursor state must reject"),
            Err(err) => err,
        };
        assert!(matches!(err, DomError::PolicyRejected(_)));
    }
}
