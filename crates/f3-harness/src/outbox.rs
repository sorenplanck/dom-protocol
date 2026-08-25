//! Durable, idempotent outbox of unsigned submissions (I7, §4.7).
//!
//! # What this is for
//!
//! The adapter never signs and never broadcasts: it produces a deterministic
//! [`UnsignedEvmCall`]. Something outside the adapter authorises it and puts it
//! on the wire. Between "we decided to submit" and "the chain has it" there is
//! a window in which the process can die, the endpoint can time out, or a
//! duplicate can be produced. The outbox closes that window with two rules:
//!
//! - **idempotent**: a submission is keyed by an idempotency key derived from
//!   the deployment and the intent. Submitting the same key again returns the
//!   record that already exists, byte for byte;
//! - **equivocation is fatal**: the same key with *different* bytes is
//!   [`OutboxError::Equivocation`], never a second record and never an
//!   overwrite. I7 says one idempotency key must never produce two
//!   semantically different artifacts; here it cannot even produce two
//!   byte-different ones.
//!
//! Because the artifact is deterministic, a restart that recomputes it gets the
//! same bytes back and the outbox confirms rather than duplicates. Because the
//! outbox is durable, a restart that *cannot* recompute it (different code
//! path, different inputs) is caught instead of silently resending something
//! else.
//!
//! # Persistence: an append-only log, its own instance
//!
//! The outbox needs one thing from durability: an append-only log of opaque
//! frames it can replay in order. That is exactly what the ratified `store`
//! crate already offers (`Store::append_journal` / `Store::read_journal`, a
//! WAL, `synchronous = FULL`, kill-9-durable log — ADR-A7), so this crate does
//! not invent a second durability substrate; it reuses that one through the
//! narrow [`OutboxLog`] trait.
//!
//! Two deliberate choices carry over from the F2-era design:
//!
//! - the outbox keeps its **own** log instance, distinct from the settlement
//!   engine's `SettlementStore`. The engine replays its own journal on
//!   recovery and must never meet a submission frame there;
//! - every record in the outbox log is an outbox frame under one fixed journal
//!   kind ([`OUTBOX_JOURNAL_KIND`]). A record under any other kind is
//!   [`OutboxError::ForeignRecord`], and a frame that does not decode is
//!   [`OutboxError::CorruptRecord`] — neither is skipped.

use std::collections::BTreeMap;
use std::path::Path;

use adapter_evm::{keccak256, UnsignedEvmCall};

/// Frame version. A bump invalidates persisted outbox logs on purpose.
pub const OUTBOX_FRAME_VERSION: u16 = 1;

/// Journal `kind` under which outbox frames are stored in a [`StoreLog`].
/// The outbox log holds nothing else; any other kind is a foreign record.
pub const OUTBOX_JOURNAL_KIND: u16 = 0xF301;

/// Domain separation for the idempotency key.
pub const IDEMPOTENCY_DOMAIN: &str = "DOM-Interop/f3-harness/outbox/idempotency/v1";

/// Largest number of distinct submissions one outbox will hold.
///
/// A settlement has at most three (open, claim, refund); the cap exists so that
/// a corrupted or hostile log cannot drive unbounded allocation (I14).
pub const MAX_OUTBOX_ENTRIES: usize = 256;

/// An append-only log of opaque outbox frames.
///
/// The whole durability contract the outbox needs, and no more: append one
/// frame, and replay every frame in the order they were appended. Kept a trait
/// so the offline suite can run against memory while a live process runs
/// against the ratified `store` crate, with identical semantics.
pub trait OutboxLog {
    /// Appends one opaque frame durably. On return the frame must survive a
    /// crash (the concrete durable impl commits before returning).
    fn append_frame(&mut self, frame: &[u8]) -> Result<(), OutboxError>;

    /// Every frame, in append order.
    fn frames(&self) -> Result<Vec<Vec<u8>>, OutboxError>;
}

/// In-memory log for the offline suite. Not durable; a process restart starts
/// empty, which is exactly what an offline, single-process test wants.
#[derive(Default)]
pub struct MemoryLog {
    frames: Vec<Vec<u8>>,
}

impl MemoryLog {
    /// A fresh, empty log.
    pub fn new() -> Self {
        Self::default()
    }
}

impl OutboxLog for MemoryLog {
    fn append_frame(&mut self, frame: &[u8]) -> Result<(), OutboxError> {
        self.frames.push(frame.to_vec());
        Ok(())
    }

    fn frames(&self) -> Result<Vec<Vec<u8>>, OutboxError> {
        Ok(self.frames.clone())
    }
}

/// Durable log backed by the ratified `store` crate (WAL, `synchronous=FULL`).
///
/// This is the "process died" substrate: a frame appended here survives a
/// `kill -9` between the durable write and the wire, which is the whole point
/// of the outbox (I7).
pub struct StoreLog {
    store: store::Store,
}

impl StoreLog {
    /// Opens (or creates) an outbox log at `path`. This file is the outbox's
    /// own — it must not be the settlement engine's database.
    pub fn open(path: &Path) -> Result<Self, OutboxError> {
        Ok(Self {
            store: store::Store::open(path).map_err(|_| OutboxError::StorageUnavailable)?,
        })
    }

    /// Wraps an already-open store as an outbox log.
    pub fn from_store(store: store::Store) -> Self {
        Self { store }
    }

    /// Gives the underlying store back.
    pub fn into_store(self) -> store::Store {
        self.store
    }
}

impl OutboxLog for StoreLog {
    fn append_frame(&mut self, frame: &[u8]) -> Result<(), OutboxError> {
        self.store
            .append_journal(OUTBOX_JOURNAL_KIND, frame)
            .map(|_| ())
            .map_err(|_| OutboxError::StorageUnavailable)
    }

    fn frames(&self) -> Result<Vec<Vec<u8>>, OutboxError> {
        let entries = self
            .store
            .read_journal()
            .map_err(|_| OutboxError::StorageUnavailable)?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            if entry.kind != OUTBOX_JOURNAL_KIND {
                // A record the outbox did not write. Never mistaken for a
                // submission, never skipped.
                return Err(OutboxError::ForeignRecord);
            }
            out.push(entry.payload);
        }
        Ok(out)
    }
}

/// What a submission is for. Part of the idempotency key, so an `open` and a
/// `claim` for the same lock can never collide.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SubmissionIntent {
    /// `open(LockTerms)` — funds the EVM leg.
    OpenLock,
    /// `claim(lockId, t)` — settles the EVM leg and publishes `t`.
    Claim,
    /// `refund(lockId)` — returns the funds after the deadline.
    Refund,
}

impl SubmissionIntent {
    /// Wire byte.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::OpenLock => 1,
            Self::Claim => 2,
            Self::Refund => 3,
        }
    }

    /// Strict decode; unknown discriminants fail closed.
    pub fn from_u8(v: u8) -> Result<Self, OutboxError> {
        match v {
            1 => Ok(Self::OpenLock),
            2 => Ok(Self::Claim),
            3 => Ok(Self::Refund),
            _ => Err(OutboxError::CorruptRecord),
        }
    }
}

/// Idempotency key of a submission.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct IdempotencyKey(pub [u8; 32]);

/// `keccak256(DOMAIN ‖ chain_id ‖ contract ‖ lock_id ‖ intent)`.
///
/// The deployment is inside the preimage, so the same lock on a fork or on a
/// re-deployed contract is a different key and cannot be confused with this one.
pub fn idempotency_key(
    chain_id: u64,
    contract: &[u8; 20],
    lock_id: &[u8; 32],
    intent: SubmissionIntent,
) -> IdempotencyKey {
    let mut pre = Vec::with_capacity(IDEMPOTENCY_DOMAIN.len() + 8 + 20 + 32 + 1);
    pre.extend_from_slice(IDEMPOTENCY_DOMAIN.as_bytes());
    pre.extend_from_slice(&chain_id.to_be_bytes());
    pre.extend_from_slice(contract);
    pre.extend_from_slice(lock_id);
    pre.push(intent.as_u8());
    IdempotencyKey(keccak256(&pre))
}

/// Failures of the durable log.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum OutboxError {
    /// The same idempotency key was offered with different bytes (I7).
    #[error("equivocation: the same idempotency key already holds different bytes")]
    Equivocation,
    /// The log holds a record the outbox cannot decode.
    #[error("corrupt outbox record")]
    CorruptRecord,
    /// The log holds a record kind that does not belong in an outbox log.
    #[error("foreign record in the outbox log")]
    ForeignRecord,
    /// The entry cap was reached (I14).
    #[error("outbox capacity exceeded")]
    CapacityExceeded,
    /// The durable substrate could not be read or written.
    #[error("outbox storage unavailable")]
    StorageUnavailable,
}

/// One durable submission record.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboxEntry {
    /// Idempotency key.
    pub key: IdempotencyKey,
    /// What the submission is for.
    pub intent: SubmissionIntent,
    /// The deterministic unsigned artifact, exactly as it must be resent.
    pub call: UnsignedEvmCall,
}

impl core::fmt::Debug for OutboxEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // I6: a `claim` call's calldata contains the scalar. Never rendered.
        f.debug_struct("OutboxEntry")
            .field("key", &self.key)
            .field("intent", &self.intent)
            .field("lock_id", &self.call.lock_id)
            .field("calldata_len", &self.call.calldata.len())
            .field("calldata", &"<redacted>")
            .finish()
    }
}

impl OutboxEntry {
    /// Canonical frame: `version ‖ key ‖ intent ‖ len ‖ UnsignedEvmCall`.
    pub fn encode(&self) -> Vec<u8> {
        let body = self.call.encode();
        let mut o = Vec::with_capacity(2 + 32 + 1 + 4 + body.len());
        o.extend_from_slice(&OUTBOX_FRAME_VERSION.to_be_bytes());
        o.extend_from_slice(&self.key.0);
        o.push(self.intent.as_u8());
        o.extend_from_slice(&(body.len() as u32).to_be_bytes());
        o.extend_from_slice(&body);
        o
    }

    /// Strict decode: exact framing, no trailing bytes (I14).
    pub fn decode(bytes: &[u8]) -> Result<Self, OutboxError> {
        const HEAD: usize = 2 + 32 + 1 + 4;
        if bytes.len() < HEAD {
            return Err(OutboxError::CorruptRecord);
        }
        let mut version = [0u8; 2];
        version.copy_from_slice(bytes.get(0..2).ok_or(OutboxError::CorruptRecord)?);
        if u16::from_be_bytes(version) != OUTBOX_FRAME_VERSION {
            return Err(OutboxError::CorruptRecord);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes.get(2..34).ok_or(OutboxError::CorruptRecord)?);
        let intent = SubmissionIntent::from_u8(*bytes.get(34).ok_or(OutboxError::CorruptRecord)?)?;
        let mut len = [0u8; 4];
        len.copy_from_slice(bytes.get(35..39).ok_or(OutboxError::CorruptRecord)?);
        let len = u32::from_be_bytes(len) as usize;
        // Cap before slicing, and reject trailing bytes.
        if bytes.len() != HEAD.saturating_add(len) {
            return Err(OutboxError::CorruptRecord);
        }
        let body = bytes.get(HEAD..).ok_or(OutboxError::CorruptRecord)?;
        let call = UnsignedEvmCall::decode(body).map_err(|_| OutboxError::CorruptRecord)?;
        Ok(Self {
            key: IdempotencyKey(key),
            intent,
            call,
        })
    }
}

/// Result of offering a submission to the outbox.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SubmitOutcome {
    /// First time: the record was appended to the durable log.
    Recorded,
    /// The key was already present with byte-identical content. The caller must
    /// resend exactly those bytes (I7).
    ReplayedIdentical,
}

/// Durable, idempotent submission log.
pub struct Outbox<J: OutboxLog> {
    log: J,
    by_key: BTreeMap<[u8; 32], OutboxEntry>,
    order: Vec<IdempotencyKey>,
}

impl<J: OutboxLog> Outbox<J> {
    /// Rebuilds an outbox from its durable log.
    ///
    /// Replaying is the normal path, not an exceptional one: every restart goes
    /// through it. A log that contains a foreign record, an undecodable frame,
    /// or two different bytes under one key is rejected rather than repaired.
    pub fn recover(log: J) -> Result<Self, OutboxError> {
        let mut by_key: BTreeMap<[u8; 32], OutboxEntry> = BTreeMap::new();
        let mut order: Vec<IdempotencyKey> = Vec::new();
        for frame in log.frames()? {
            let entry = OutboxEntry::decode(&frame)?;
            match by_key.get(&entry.key.0) {
                Some(existing) if existing != &entry => return Err(OutboxError::Equivocation),
                Some(_) => {}
                None => {
                    if order.len() >= MAX_OUTBOX_ENTRIES {
                        return Err(OutboxError::CapacityExceeded);
                    }
                    order.push(entry.key);
                    by_key.insert(entry.key.0, entry);
                }
            }
        }
        Ok(Self { log, by_key, order })
    }

    /// Offers a submission.
    ///
    /// Fails closed on equivocation: the caller is told, and the durable log is
    /// left untouched.
    pub fn submit(
        &mut self,
        key: IdempotencyKey,
        intent: SubmissionIntent,
        call: &UnsignedEvmCall,
    ) -> Result<SubmitOutcome, OutboxError> {
        let candidate = OutboxEntry {
            key,
            intent,
            call: call.clone(),
        };
        if let Some(existing) = self.by_key.get(&key.0) {
            if existing != &candidate {
                return Err(OutboxError::Equivocation);
            }
            return Ok(SubmitOutcome::ReplayedIdentical);
        }
        if self.order.len() >= MAX_OUTBOX_ENTRIES {
            return Err(OutboxError::CapacityExceeded);
        }
        // Durable first, in-memory second: a crash between the two replays into
        // the same state, a crash the other way round would forget a record we
        // already told the caller about.
        self.log.append_frame(&candidate.encode())?;
        self.order.push(key);
        self.by_key.insert(key.0, candidate);
        Ok(SubmitOutcome::Recorded)
    }

    /// The record under `key`, if any. This is what a resend must transmit.
    pub fn get(&self, key: &IdempotencyKey) -> Option<&OutboxEntry> {
        self.by_key.get(&key.0)
    }

    /// Every record, in the order it was first accepted. A restart replays this
    /// list to resend anything the chain may not have.
    pub fn entries(&self) -> Vec<&OutboxEntry> {
        self.order
            .iter()
            .filter_map(|k| self.by_key.get(&k.0))
            .collect()
    }

    /// Number of distinct records.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether the outbox holds nothing.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Borrows the durable log.
    pub fn log(&self) -> &J {
        &self.log
    }

    /// Gives the durable log back, so a restart can rebuild on top of it.
    pub fn into_log(self) -> J {
        self.log
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call(chain_id: u64, tail: u8) -> UnsignedEvmCall {
        UnsignedEvmCall {
            version: 1,
            chain_id,
            to: [0xC0; 20],
            value: [0u8; 32],
            gas_limit_hint: 300_000,
            lock_id: [0x11; 32],
            binding: [0x22; 32],
            calldata: vec![tail; 36],
        }
    }

    fn key() -> IdempotencyKey {
        idempotency_key(31337, &[0xC0; 20], &[0x11; 32], SubmissionIntent::OpenLock)
    }

    #[test]
    fn the_key_binds_deployment_lock_and_intent() {
        let base = key();
        assert_eq!(base, key(), "derivation must be deterministic");
        assert_ne!(
            base,
            idempotency_key(1337, &[0xC0; 20], &[0x11; 32], SubmissionIntent::OpenLock)
        );
        assert_ne!(
            base,
            idempotency_key(31337, &[0xC1; 20], &[0x11; 32], SubmissionIntent::OpenLock)
        );
        assert_ne!(
            base,
            idempotency_key(31337, &[0xC0; 20], &[0x12; 32], SubmissionIntent::OpenLock)
        );
        assert_ne!(
            base,
            idempotency_key(31337, &[0xC0; 20], &[0x11; 32], SubmissionIntent::Claim)
        );
    }

    #[test]
    fn resubmitting_identical_bytes_is_idempotent() {
        let mut o = Outbox::recover(MemoryLog::new()).expect("empty log");
        assert_eq!(
            o.submit(key(), SubmissionIntent::OpenLock, &call(31337, 9)),
            Ok(SubmitOutcome::Recorded)
        );
        assert_eq!(
            o.submit(key(), SubmissionIntent::OpenLock, &call(31337, 9)),
            Ok(SubmitOutcome::ReplayedIdentical)
        );
        assert_eq!(o.len(), 1);
        assert_eq!(
            o.log().frames().expect("frames").len(),
            1,
            "no duplicate durable record"
        );
    }

    #[test]
    fn equivocation_is_fatal_and_leaves_the_log_untouched() {
        let mut o = Outbox::recover(MemoryLog::new()).expect("empty log");
        o.submit(key(), SubmissionIntent::OpenLock, &call(31337, 9))
            .expect("first");
        assert_eq!(
            o.submit(key(), SubmissionIntent::OpenLock, &call(31337, 8)),
            Err(OutboxError::Equivocation)
        );
        assert_eq!(o.log().frames().expect("frames").len(), 1);
        assert_eq!(
            o.get(&key()).map(|e| e.call.calldata[0]),
            Some(9),
            "the original bytes must survive an equivocation attempt"
        );
    }

    #[test]
    fn recovery_reproduces_the_same_bytes() {
        let mut o = Outbox::recover(MemoryLog::new()).expect("empty log");
        o.submit(key(), SubmissionIntent::OpenLock, &call(31337, 9))
            .expect("first");
        let before = o.get(&key()).expect("entry").call.encode();
        let j = o.into_log();
        let o2 = Outbox::recover(j).expect("replay");
        assert_eq!(o2.len(), 1);
        assert_eq!(o2.get(&key()).expect("entry").call.encode(), before);
    }

    #[test]
    fn a_durable_store_log_survives_a_restart() {
        // The whole reason StoreLog exists: a frame written before a crash is
        // still there when the outbox is rebuilt from a fresh process.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("outbox.db");
        {
            let mut o = Outbox::recover(StoreLog::open(&path).expect("open")).expect("empty");
            o.submit(key(), SubmissionIntent::OpenLock, &call(31337, 7))
                .expect("record");
        } // the process (and the Store connection) goes away here
        let reopened = StoreLog::open(&path).expect("reopen");
        let o2 = Outbox::recover(reopened).expect("replay from disk");
        assert_eq!(o2.len(), 1);
        assert_eq!(o2.get(&key()).expect("entry").call.calldata[0], 7);
    }

    #[test]
    fn frames_round_trip_and_reject_slop() {
        let e = OutboxEntry {
            key: key(),
            intent: SubmissionIntent::Claim,
            call: call(31337, 3),
        };
        let enc = e.encode();
        assert_eq!(OutboxEntry::decode(&enc), Ok(e));
        let mut long = enc.clone();
        long.push(0);
        assert_eq!(OutboxEntry::decode(&long), Err(OutboxError::CorruptRecord));
        let mut short = enc.clone();
        short.pop();
        assert_eq!(OutboxEntry::decode(&short), Err(OutboxError::CorruptRecord));
        let mut bad_version = enc.clone();
        bad_version[1] = 7;
        assert_eq!(
            OutboxEntry::decode(&bad_version),
            Err(OutboxError::CorruptRecord)
        );
        let mut bad_intent = enc;
        bad_intent[34] = 9;
        assert_eq!(
            OutboxEntry::decode(&bad_intent),
            Err(OutboxError::CorruptRecord)
        );
        assert_eq!(OutboxEntry::decode(&[]), Err(OutboxError::CorruptRecord));
    }

    #[test]
    fn a_foreign_record_in_the_log_is_refused() {
        // A record written under a different journal kind must never be read as
        // a submission. Exercised on the durable substrate, where a foreign
        // kind is a real possibility.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("outbox.db");
        {
            let mut store = store::Store::open(&path).expect("open");
            store
                .append_journal(OUTBOX_JOURNAL_KIND + 1, b"not-an-outbox-frame")
                .expect("append foreign");
        }
        let log = StoreLog::open(&path).expect("reopen");
        assert_eq!(
            Outbox::recover(log).err(),
            Some(OutboxError::ForeignRecord),
            "an engine record must never be mistaken for a submission"
        );
    }

    #[test]
    fn a_log_that_equivocates_is_refused_on_replay() {
        let mut j = MemoryLog::new();
        for tail in [9u8, 8u8] {
            j.append_frame(
                &OutboxEntry {
                    key: key(),
                    intent: SubmissionIntent::OpenLock,
                    call: call(31337, tail),
                }
                .encode(),
            )
            .expect("append");
        }
        assert_eq!(
            Outbox::recover(j).err(),
            Some(OutboxError::Equivocation),
            "a log holding two different bytes under one key is not repairable"
        );
    }

    #[test]
    fn debug_never_renders_calldata() {
        let e = OutboxEntry {
            key: key(),
            intent: SubmissionIntent::Claim,
            call: call(31337, 0xAB),
        };
        let rendered = format!("{e:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("171"), "no calldata byte may appear");
        assert!(!rendered.contains("ab, ab"));
    }
}
