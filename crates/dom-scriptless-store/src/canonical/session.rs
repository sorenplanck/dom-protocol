//! Durable per-session contract record — the authority bytes for atomic
//! persistence (spec §10.1 `SessionRecordV1`, Cronograma 3.3).
//!
//! Cronograma 3.3: "o envelope é descartável, os bytes são a autoridade." The
//! canonical bytes here, authenticated by their trailing storage-domain
//! digest, are the source of truth; any in-memory projection is
//! reconstructable from them through [`SessionRecordV1::from_bytes`]. Nothing
//! in this module performs the atomic write itself — the retained-capability
//! filesystem's persist → tombstone → commit → fsync sequence (§10.5) is the
//! runtime's job; this is the exact record that sequence writes.
//!
//! §10.1 separates three categories of state, and the record carries all
//! three: the irreversible cryptographic state ([`SessionIrreversibleV1`]),
//! the monotonic protocol state (revision, phase, transcript), and the
//! reversible chain projection ([`SessionChainProjectionV1`] — the only
//! category a reorg may rewrite). [`SessionRecordV1::advance`] enforces the
//! §10.3 compare-and-swap (the successor's revision must follow the expected
//! one) and the §10.1 irreversibility rule: category one never regresses — a
//! flag never clears and the nonce epoch never decreases.

use super::{exact, storage_hash, CanonicalCodecError};
use dom_scriptless_crypto::StorageHashDomainV1;

const SESSION_RECORD_MAGIC: &[u8; 8] = b"DOMSREC1";
const SESSION_RECORD_VERSION: u16 = 1;

const TX_OBSERVATION_BODY: usize = 40;
const TX_OBSERVATION_LEN: usize = 1 + TX_OBSERVATION_BODY;

// Offsets of the fixed prefix, up to and including the payload-length field.
const OFF_SESSION_ID: usize = 10;
const OFF_REVISION: usize = 42;
const OFF_PHASE: usize = 50;
const OFF_TERMS_HASH: usize = 52;
const OFF_TRANSCRIPT_HASH: usize = 84;
const OFF_ANY_SHARE_SENT: usize = 116;
const OFF_FUNDING_AUTHORIZED: usize = 117;
const OFF_ADAPTOR_EXPOSED: usize = 118;
const OFF_NONCE_EPOCH: usize = 119;
const OFF_TIP_ID: usize = 127;
const OFF_TIP_HEIGHT: usize = 159;
const OFF_FUNDING_OBS: usize = 167;
const OFF_CLAIM_OBS: usize = OFF_FUNDING_OBS + TX_OBSERVATION_LEN;
const OFF_REFUND_OBS: usize = OFF_CLAIM_OBS + TX_OBSERVATION_LEN;
const OFF_PAYLOAD_LEN: usize = OFF_REFUND_OBS + TX_OBSERVATION_LEN;
/// Fixed prefix length before the variable payload bytes (includes the u32
/// payload-length field).
const SESSION_RECORD_PREFIX_LEN: usize = OFF_PAYLOAD_LEN + 4;
const DIGEST_LEN: usize = 32;

/// Encrypted-payload bound: the AEAD-sealed session state stays small; a
/// larger claimed length is a malformed record, not a real payload.
const MAX_ENCRYPTED_PAYLOAD: usize = 64 * 1024;

/// §9.1 normative contract phase, with the exact discriminants.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionPhaseV1 {
    /// Session created.
    Created = 0,
    /// Terms committed.
    TermsCommitted = 10,
    /// Blinding shares committed.
    SharesCommitted = 20,
    /// Blinding shares revealed.
    SharesRevealed = 30,
    /// Bulletproof common-nonce commitment stored.
    BpCommonCommitted = 35,
    /// Bulletproof common nonce established.
    BpCommonEstablished = 40,
    /// Bulletproof round-1 nonce commitment stored.
    BpNonceCommitted = 45,
    /// Bulletproof round 1 complete.
    BpRound1Complete = 50,
    /// Bulletproof round 2 complete.
    BpRound2Complete = 60,
    /// Shared output finalized.
    OutputFinalized = 70,
    /// Transaction templates committed.
    TemplatesCommitted = 80,
    /// Refund signing in progress.
    RefundSigning = 90,
    /// Refund signed.
    RefundSigned = 100,
    /// Claim signing in progress.
    ClaimSigning = 110,
    /// Claim adaptor pre-signature prepared.
    ClaimPrepared = 120,
    /// Funding authorized.
    FundingAuthorized = 130,
    /// Funding broadcast.
    FundingBroadcast = 140,
    /// Funding confirmed.
    FundingConfirmed = 150,
    /// Claim broadcast.
    ClaimBroadcast = 160,
    /// Refund eligible at its unlock height.
    RefundEligible = 170,
    /// Refund broadcast.
    RefundBroadcast = 180,
    /// Settled.
    Settled = 190,
    /// Refunded.
    Refunded = 200,
    /// Aborted.
    Aborted = 250,
    /// Failed closed.
    FailedClosed = 255,
}

impl SessionPhaseV1 {
    const fn to_u16(self) -> u16 {
        self as u16
    }

    fn from_u16(value: u16) -> Result<Self, CanonicalCodecError> {
        Ok(match value {
            0 => Self::Created,
            10 => Self::TermsCommitted,
            20 => Self::SharesCommitted,
            30 => Self::SharesRevealed,
            35 => Self::BpCommonCommitted,
            40 => Self::BpCommonEstablished,
            45 => Self::BpNonceCommitted,
            50 => Self::BpRound1Complete,
            60 => Self::BpRound2Complete,
            70 => Self::OutputFinalized,
            80 => Self::TemplatesCommitted,
            90 => Self::RefundSigning,
            100 => Self::RefundSigned,
            110 => Self::ClaimSigning,
            120 => Self::ClaimPrepared,
            130 => Self::FundingAuthorized,
            140 => Self::FundingBroadcast,
            150 => Self::FundingConfirmed,
            160 => Self::ClaimBroadcast,
            170 => Self::RefundEligible,
            180 => Self::RefundBroadcast,
            190 => Self::Settled,
            200 => Self::Refunded,
            250 => Self::Aborted,
            255 => Self::FailedClosed,
            _ => return Err(CanonicalCodecError::InvalidEncoding),
        })
    }
}

/// §11.1 `TxObservation`, in the store's canonical fixed form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTxObservationV1 {
    /// Never seen.
    Unknown,
    /// Broadcast; `first_seen_unix` is wallet/UI data, never consensus.
    Broadcast {
        /// Wall-clock first-seen time.
        first_seen_unix: u64,
    },
    /// Seen in the mempool.
    Mempool,
    /// Confirmed on the canonical chain.
    Confirmed {
        /// Confirming block.
        block_id: [u8; 32],
        /// Confirming height.
        height: u64,
    },
    /// Formerly confirmed; its block left the canonical chain.
    Orphaned {
        /// Former confirming block.
        former_block_id: [u8; 32],
        /// Former confirming height.
        former_height: u64,
    },
    /// Spent by a competing canonical transaction.
    Conflicted {
        /// Canonical spending transaction.
        spending_tx_id: [u8; 32],
    },
}

impl SessionTxObservationV1 {
    fn encode_into(self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), TX_OBSERVATION_LEN);
        let (tag, body) = out.split_at_mut(1);
        match self {
            Self::Unknown => tag[0] = 0x00,
            Self::Broadcast { first_seen_unix } => {
                tag[0] = 0x01;
                body[..8].copy_from_slice(&first_seen_unix.to_le_bytes());
            }
            Self::Mempool => tag[0] = 0x02,
            Self::Confirmed { block_id, height } => {
                tag[0] = 0x03;
                body[..32].copy_from_slice(&block_id);
                body[32..40].copy_from_slice(&height.to_le_bytes());
            }
            Self::Orphaned {
                former_block_id,
                former_height,
            } => {
                tag[0] = 0x04;
                body[..32].copy_from_slice(&former_block_id);
                body[32..40].copy_from_slice(&former_height.to_le_bytes());
            }
            Self::Conflicted { spending_tx_id } => {
                tag[0] = 0x05;
                body[..32].copy_from_slice(&spending_tx_id);
            }
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self, CanonicalCodecError> {
        if bytes.len() != TX_OBSERVATION_LEN {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let body = &bytes[1..];
        // Canonicalness: bytes not defined by the variant must be zero.
        let used = match bytes[0] {
            0x00 | 0x02 => 0,
            0x01 => 8,
            0x03 | 0x04 => 40,
            0x05 => 32,
            _ => return Err(CanonicalCodecError::InvalidEncoding),
        };
        if body[used..].iter().any(|byte| *byte != 0) {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let block = |slice: &[u8]| exact::<32>(slice);
        let height = |slice: &[u8]| {
            u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ])
        };
        Ok(match bytes[0] {
            0x00 => Self::Unknown,
            0x01 => Self::Broadcast {
                first_seen_unix: height(&body[..8]),
            },
            0x02 => Self::Mempool,
            0x03 => Self::Confirmed {
                block_id: block(&body[..32])?,
                height: height(&body[32..40]),
            },
            0x04 => Self::Orphaned {
                former_block_id: block(&body[..32])?,
                former_height: height(&body[32..40]),
            },
            0x05 => Self::Conflicted {
                spending_tx_id: block(&body[..32])?,
            },
            _ => unreachable!("tag validated above"),
        })
    }
}

/// §10.1 irreversible cryptographic state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionIrreversibleV1 {
    /// Some signing share left the process.
    pub any_signing_share_sent: bool,
    /// Funding was authorized.
    pub funding_authorized: bool,
    /// The adaptor secret was observed (§7.5 Exposed).
    pub adaptor_secret_exposed: bool,
    /// The current nonce epoch.
    pub nonce_epoch: u64,
}

impl SessionIrreversibleV1 {
    /// Whether `next` is a valid successor: no flag regresses and the nonce
    /// epoch never decreases (§10.1 category one only advances).
    fn advances_to(self, next: Self) -> bool {
        (!self.any_signing_share_sent || next.any_signing_share_sent)
            && (!self.funding_authorized || next.funding_authorized)
            && (!self.adaptor_secret_exposed || next.adaptor_secret_exposed)
            && next.nonce_epoch >= self.nonce_epoch
    }
}

/// §10.1 / §11.1 reversible chain projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionChainProjectionV1 {
    /// Canonical tip block.
    pub tip_id: [u8; 32],
    /// Canonical tip height.
    pub tip_height: u64,
    /// Funding observation.
    pub funding: SessionTxObservationV1,
    /// Claim observation.
    pub claim: SessionTxObservationV1,
    /// Refund observation.
    pub refund: SessionTxObservationV1,
}

/// The authenticated durable session record (§10.1).
///
/// The bytes remain the authority (Cronograma 3.3). `fields` and `payload_len`
/// are the disposable in-memory projection of those bytes, decoded exactly
/// once at the two points that already authenticate the record — never a
/// second source of truth. Decoding there rather than per accessor keeps every
/// accessor total: a malformed record cannot reach one, because it never
/// becomes a `SessionRecordV1` in the first place.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionRecordV1 {
    bytes: Vec<u8>,
    digest: [u8; 32],
    fields: SessionRecordFieldsV1,
    payload_len: usize,
}

/// The fixed fields of a session record, supplied to construct it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionRecordFieldsV1 {
    /// The session identifier (nonzero).
    pub session_id: [u8; 32],
    /// The compare-and-swap revision.
    pub revision: u64,
    /// The current normative phase (§9.1).
    pub phase: SessionPhaseV1,
    /// The frozen terms hash.
    pub terms_hash: [u8; 32],
    /// The current transcript hash.
    pub transcript_hash: [u8; 32],
    /// The irreversible cryptographic state.
    pub irreversible: SessionIrreversibleV1,
    /// The reversible chain projection.
    pub chain: SessionChainProjectionV1,
}

impl SessionRecordV1 {
    /// Construct and authenticate a session record from its fields and the
    /// already-sealed encrypted payload.
    ///
    /// `session_id` and `terms_hash` must be nonzero, and the payload must be
    /// within bounds. The encrypted payload is opaque here — it is sealed by
    /// the crypto layer (§10.4); this codec authenticates the record's
    /// structural integrity, not the payload's AEAD.
    pub fn new(
        fields: SessionRecordFieldsV1,
        encrypted_payload: &[u8],
    ) -> Result<Self, CanonicalCodecError> {
        if fields.session_id == [0_u8; 32] || fields.terms_hash == [0_u8; 32] {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        if encrypted_payload.len() > MAX_ENCRYPTED_PAYLOAD {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let total = SESSION_RECORD_PREFIX_LEN + encrypted_payload.len() + DIGEST_LEN;
        let mut bytes = vec![0_u8; total];
        bytes[..8].copy_from_slice(SESSION_RECORD_MAGIC);
        bytes[8..10].copy_from_slice(&SESSION_RECORD_VERSION.to_le_bytes());
        bytes[OFF_SESSION_ID..OFF_REVISION].copy_from_slice(&fields.session_id);
        bytes[OFF_REVISION..OFF_PHASE].copy_from_slice(&fields.revision.to_le_bytes());
        bytes[OFF_PHASE..OFF_TERMS_HASH].copy_from_slice(&fields.phase.to_u16().to_le_bytes());
        bytes[OFF_TERMS_HASH..OFF_TRANSCRIPT_HASH].copy_from_slice(&fields.terms_hash);
        bytes[OFF_TRANSCRIPT_HASH..OFF_ANY_SHARE_SENT].copy_from_slice(&fields.transcript_hash);
        bytes[OFF_ANY_SHARE_SENT] = u8::from(fields.irreversible.any_signing_share_sent);
        bytes[OFF_FUNDING_AUTHORIZED] = u8::from(fields.irreversible.funding_authorized);
        bytes[OFF_ADAPTOR_EXPOSED] = u8::from(fields.irreversible.adaptor_secret_exposed);
        bytes[OFF_NONCE_EPOCH..OFF_TIP_ID]
            .copy_from_slice(&fields.irreversible.nonce_epoch.to_le_bytes());
        bytes[OFF_TIP_ID..OFF_TIP_HEIGHT].copy_from_slice(&fields.chain.tip_id);
        bytes[OFF_TIP_HEIGHT..OFF_FUNDING_OBS]
            .copy_from_slice(&fields.chain.tip_height.to_le_bytes());
        fields
            .chain
            .funding
            .encode_into(&mut bytes[OFF_FUNDING_OBS..OFF_CLAIM_OBS]);
        fields
            .chain
            .claim
            .encode_into(&mut bytes[OFF_CLAIM_OBS..OFF_REFUND_OBS]);
        fields
            .chain
            .refund
            .encode_into(&mut bytes[OFF_REFUND_OBS..OFF_PAYLOAD_LEN]);
        let payload_len = u32::try_from(encrypted_payload.len())
            .map_err(|_| CanonicalCodecError::InvalidEncoding)?;
        bytes[OFF_PAYLOAD_LEN..SESSION_RECORD_PREFIX_LEN]
            .copy_from_slice(&payload_len.to_le_bytes());
        bytes[SESSION_RECORD_PREFIX_LEN..SESSION_RECORD_PREFIX_LEN + encrypted_payload.len()]
            .copy_from_slice(encrypted_payload);
        let digest = storage_hash(
            StorageHashDomainV1::SessionRecord,
            &bytes[..total - DIGEST_LEN],
        );
        bytes[total - DIGEST_LEN..].copy_from_slice(&digest);
        Ok(Self {
            bytes,
            digest,
            fields,
            payload_len: encrypted_payload.len(),
        })
    }

    /// Parse exact record bytes and authenticate the trailing digest.
    ///
    /// The bytes are the authority: a record whose digest does not
    /// authenticate its content, or whose structure is malformed, is
    /// rejected. This is the reconstruction path — the disposable in-memory
    /// projection is rebuilt only from authenticated bytes.
    pub fn from_bytes(input: &[u8]) -> Result<Self, CanonicalCodecError> {
        if input.len() < SESSION_RECORD_PREFIX_LEN + DIGEST_LEN {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        if &input[..8] != SESSION_RECORD_MAGIC
            || u16::from_le_bytes([input[8], input[9]]) != SESSION_RECORD_VERSION
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let payload_len = u32::from_le_bytes(exact::<4>(
            &input[OFF_PAYLOAD_LEN..SESSION_RECORD_PREFIX_LEN],
        )?) as usize;
        if payload_len > MAX_ENCRYPTED_PAYLOAD {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let total = SESSION_RECORD_PREFIX_LEN + payload_len + DIGEST_LEN;
        if input.len() != total {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        // Structural validation of the closed field registries before trust.
        if input[OFF_SESSION_ID..OFF_REVISION] == [0_u8; 32]
            || input[OFF_TERMS_HASH..OFF_TRANSCRIPT_HASH] == [0_u8; 32]
        {
            return Err(CanonicalCodecError::InvalidEncoding);
        }
        let phase =
            SessionPhaseV1::from_u16(u16::from_le_bytes([input[OFF_PHASE], input[OFF_PHASE + 1]]))?;
        for flag in [
            input[OFF_ANY_SHARE_SENT],
            input[OFF_FUNDING_AUTHORIZED],
            input[OFF_ADAPTOR_EXPOSED],
        ] {
            if flag > 1 {
                return Err(CanonicalCodecError::InvalidEncoding);
            }
        }
        let funding = SessionTxObservationV1::decode(&input[OFF_FUNDING_OBS..OFF_CLAIM_OBS])?;
        let claim = SessionTxObservationV1::decode(&input[OFF_CLAIM_OBS..OFF_REFUND_OBS])?;
        let refund = SessionTxObservationV1::decode(&input[OFF_REFUND_OBS..OFF_PAYLOAD_LEN])?;

        let digest = storage_hash(
            StorageHashDomainV1::SessionRecord,
            &input[..total - DIGEST_LEN],
        );
        if digest != input[total - DIGEST_LEN..] {
            return Err(CanonicalCodecError::AuthenticationFailed);
        }

        // Only authenticated bytes are projected. Every `exact` below is over a
        // constant-width window of a record whose length was already fixed, so
        // the fallible conversions cannot fail here; they still propagate
        // rather than assert, which is what keeps the accessors total.
        let fields = SessionRecordFieldsV1 {
            session_id: exact::<32>(&input[OFF_SESSION_ID..OFF_REVISION])?,
            revision: u64::from_le_bytes(exact::<8>(&input[OFF_REVISION..OFF_PHASE])?),
            phase,
            terms_hash: exact::<32>(&input[OFF_TERMS_HASH..OFF_TRANSCRIPT_HASH])?,
            transcript_hash: exact::<32>(&input[OFF_TRANSCRIPT_HASH..OFF_ANY_SHARE_SENT])?,
            irreversible: SessionIrreversibleV1 {
                any_signing_share_sent: input[OFF_ANY_SHARE_SENT] == 1,
                funding_authorized: input[OFF_FUNDING_AUTHORIZED] == 1,
                adaptor_secret_exposed: input[OFF_ADAPTOR_EXPOSED] == 1,
                nonce_epoch: u64::from_le_bytes(exact::<8>(&input[OFF_NONCE_EPOCH..OFF_TIP_ID])?),
            },
            chain: SessionChainProjectionV1 {
                tip_id: exact::<32>(&input[OFF_TIP_ID..OFF_TIP_HEIGHT])?,
                tip_height: u64::from_le_bytes(exact::<8>(
                    &input[OFF_TIP_HEIGHT..OFF_FUNDING_OBS],
                )?),
                funding,
                claim,
                refund,
            },
        };

        Ok(Self {
            bytes: input.to_vec(),
            digest,
            fields,
            payload_len,
        })
    }

    /// The exact authenticated record bytes — the authority.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The authenticated record digest.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The session identifier.
    pub const fn session_id(&self) -> [u8; 32] {
        self.fields.session_id
    }

    /// The compare-and-swap revision.
    pub const fn revision(&self) -> u64 {
        self.fields.revision
    }

    /// The current normative phase.
    pub const fn phase(&self) -> SessionPhaseV1 {
        self.fields.phase
    }

    /// The frozen terms hash.
    pub const fn terms_hash(&self) -> [u8; 32] {
        self.fields.terms_hash
    }

    /// The current transcript hash.
    pub const fn transcript_hash(&self) -> [u8; 32] {
        self.fields.transcript_hash
    }

    /// The irreversible cryptographic state.
    pub const fn irreversible(&self) -> SessionIrreversibleV1 {
        self.fields.irreversible
    }

    /// The reversible chain projection.
    pub const fn chain(&self) -> SessionChainProjectionV1 {
        self.fields.chain
    }

    /// The opaque, already-sealed encrypted payload.
    pub fn encrypted_payload(&self) -> &[u8] {
        &self.bytes[SESSION_RECORD_PREFIX_LEN..SESSION_RECORD_PREFIX_LEN + self.payload_len]
    }

    /// Produce the compare-and-swap successor of this record (§10.3, §10.1).
    ///
    /// The §10.3 CAS is `WHERE session_id AND revision = expected`: this
    /// mirrors the guard purely — `expected_revision` must equal this
    /// record's revision, the successor's revision is `expected + 1` (checked,
    /// overflow fails closed), the session id and terms hash are preserved,
    /// and the irreversible state may only advance (§10.1: a flag never
    /// clears, the nonce epoch never decreases). A regression fails closed
    /// with no successor.
    pub fn advance(
        &self,
        expected_revision: u64,
        phase: SessionPhaseV1,
        transcript_hash: [u8; 32],
        irreversible: SessionIrreversibleV1,
        chain: SessionChainProjectionV1,
        encrypted_payload: &[u8],
    ) -> Result<Self, CanonicalCodecError> {
        if self.revision() != expected_revision {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        if !self.irreversible().advances_to(irreversible) {
            return Err(CanonicalCodecError::InvalidLifecycle);
        }
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(CanonicalCodecError::ArithmeticOverflow)?;
        Self::new(
            SessionRecordFieldsV1 {
                session_id: self.session_id(),
                revision: next_revision,
                phase,
                terms_hash: self.terms_hash(),
                transcript_hash,
                irreversible,
                chain,
            },
            encrypted_payload,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation_examples() -> [SessionTxObservationV1; 6] {
        [
            SessionTxObservationV1::Unknown,
            SessionTxObservationV1::Broadcast {
                first_seen_unix: 1_700_000_000,
            },
            SessionTxObservationV1::Mempool,
            SessionTxObservationV1::Confirmed {
                block_id: [0x11; 32],
                height: 900,
            },
            SessionTxObservationV1::Orphaned {
                former_block_id: [0x22; 32],
                former_height: 850,
            },
            SessionTxObservationV1::Conflicted {
                spending_tx_id: [0x33; 32],
            },
        ]
    }

    fn fields() -> SessionRecordFieldsV1 {
        SessionRecordFieldsV1 {
            session_id: [0x44; 32],
            revision: 0,
            phase: SessionPhaseV1::OutputFinalized,
            terms_hash: [0x55; 32],
            transcript_hash: [0x66; 32],
            irreversible: SessionIrreversibleV1 {
                any_signing_share_sent: true,
                funding_authorized: false,
                adaptor_secret_exposed: false,
                nonce_epoch: 3,
            },
            chain: SessionChainProjectionV1 {
                tip_id: [0x77; 32],
                tip_height: 1000,
                funding: SessionTxObservationV1::Confirmed {
                    block_id: [0x11; 32],
                    height: 990,
                },
                claim: SessionTxObservationV1::Unknown,
                refund: SessionTxObservationV1::Unknown,
            },
        }
    }

    #[test]
    fn the_record_roundtrips_byte_for_byte_and_authenticates() -> Result<(), CanonicalCodecError> {
        let record = SessionRecordV1::new(fields(), b"sealed-payload")?;
        let reparsed = SessionRecordV1::from_bytes(record.as_bytes())?;
        assert_eq!(reparsed.as_bytes(), record.as_bytes());
        assert_eq!(reparsed.session_id(), [0x44; 32]);
        assert_eq!(reparsed.revision(), 0);
        assert_eq!(reparsed.phase(), SessionPhaseV1::OutputFinalized);
        assert_eq!(reparsed.terms_hash(), [0x55; 32]);
        assert_eq!(reparsed.transcript_hash(), [0x66; 32]);
        assert_eq!(reparsed.irreversible(), fields().irreversible);
        assert_eq!(reparsed.chain(), fields().chain);
        assert_eq!(reparsed.encrypted_payload(), b"sealed-payload");
        Ok(())
    }

    #[test]
    fn an_empty_payload_is_valid_and_bounded() -> Result<(), CanonicalCodecError> {
        let record = SessionRecordV1::new(fields(), b"")?;
        assert_eq!(record.encrypted_payload(), b"");
        assert!(SessionRecordV1::from_bytes(record.as_bytes()).is_ok());
        Ok(())
    }

    #[test]
    fn every_observation_variant_roundtrips_and_rejects_noncanonical_padding(
    ) -> Result<(), CanonicalCodecError> {
        for obs in observation_examples() {
            let mut buffer = [0_u8; TX_OBSERVATION_LEN];
            obs.encode_into(&mut buffer);
            assert_eq!(SessionTxObservationV1::decode(&buffer)?, obs);
            // A nonzero byte in the unused padding must be rejected.
            if matches!(obs, SessionTxObservationV1::Unknown) {
                let mut tampered = buffer;
                tampered[TX_OBSERVATION_LEN - 1] ^= 1;
                assert!(SessionTxObservationV1::decode(&tampered).is_err());
            }
        }
        // An unknown observation tag is refused.
        let mut bad = [0_u8; TX_OBSERVATION_LEN];
        bad[0] = 0x06;
        assert!(SessionTxObservationV1::decode(&bad).is_err());
        Ok(())
    }

    #[test]
    fn a_single_flipped_byte_fails_authentication() -> Result<(), CanonicalCodecError> {
        let record = SessionRecordV1::new(fields(), b"sealed")?;
        for index in 0..record.as_bytes().len() {
            let mut tampered = record.as_bytes().to_vec();
            tampered[index] ^= 1;
            assert!(
                SessionRecordV1::from_bytes(&tampered).is_err(),
                "tamper at byte {index} was accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn zero_session_id_terms_hash_and_bad_phase_are_refused() -> Result<(), CanonicalCodecError> {
        let mut bad = fields();
        bad.session_id = [0_u8; 32];
        assert!(SessionRecordV1::new(bad, b"x").is_err());
        let mut bad = fields();
        bad.terms_hash = [0_u8; 32];
        assert!(SessionRecordV1::new(bad, b"x").is_err());
        // A record carrying an unregistered phase byte fails to parse.
        let mut record = SessionRecordV1::new(fields(), b"x")?.as_bytes().to_vec();
        record[OFF_PHASE] = 7; // not a §9.1 discriminant
        record[OFF_PHASE + 1] = 0;
        assert!(SessionRecordV1::from_bytes(&record).is_err());
        Ok(())
    }

    #[test]
    fn advance_enforces_the_cas_revision_and_irreversibility() -> Result<(), CanonicalCodecError> {
        let record = SessionRecordV1::new(fields(), b"v0")?;

        // §10.3 CAS: the expected revision must match; a stale expectation
        // fails closed.
        assert!(record
            .advance(
                1,
                SessionPhaseV1::TemplatesCommitted,
                [0x88; 32],
                record.irreversible(),
                record.chain(),
                b"v1",
            )
            .is_err());

        // A valid advance bumps the revision, preserves identity, and lets the
        // irreversible flags move forward (funding now authorized).
        let mut next_irrev = record.irreversible();
        next_irrev.funding_authorized = true;
        next_irrev.nonce_epoch = 4;
        let next = record.advance(
            0,
            SessionPhaseV1::FundingAuthorized,
            [0x88; 32],
            next_irrev,
            record.chain(),
            b"v1",
        )?;
        assert_eq!(next.revision(), 1);
        assert_eq!(next.session_id(), record.session_id());
        assert_eq!(next.terms_hash(), record.terms_hash());
        assert!(next.irreversible().funding_authorized);

        // §10.1 irreversibility: a flag may not clear, nor the epoch decrease.
        let mut regressed = next.irreversible();
        regressed.funding_authorized = false;
        assert!(next
            .advance(
                1,
                SessionPhaseV1::FundingBroadcast,
                [0x99; 32],
                regressed,
                next.chain(),
                b"v2",
            )
            .is_err());
        let mut lower_epoch = next.irreversible();
        lower_epoch.nonce_epoch = 0;
        assert!(next
            .advance(
                1,
                SessionPhaseV1::FundingBroadcast,
                [0x99; 32],
                lower_epoch,
                next.chain(),
                b"v2",
            )
            .is_err());
        Ok(())
    }

    #[test]
    fn a_reorg_updates_only_the_chain_projection_through_a_new_revision(
    ) -> Result<(), CanonicalCodecError> {
        // The reversible category may change (§10.1) — here funding is demoted
        // to Orphaned — and it flows through the ordinary CAS advance with the
        // irreversible state unchanged.
        let record = SessionRecordV1::new(fields(), b"v0")?;
        let mut reorged = record.chain();
        reorged.funding = SessionTxObservationV1::Orphaned {
            former_block_id: [0x11; 32],
            former_height: 990,
        };
        let next = record.advance(
            0,
            record.phase(),
            record.transcript_hash(),
            record.irreversible(),
            reorged,
            b"v0",
        )?;
        assert_eq!(next.chain().funding, reorged.funding);
        assert_eq!(next.irreversible(), record.irreversible());
        Ok(())
    }
}
