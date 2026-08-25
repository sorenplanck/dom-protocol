//! The F6→F2→F4 composition root, RATIFIED by D-023 (operator decision,
//! 2026-08-10).
//!
//! The ratified rule, condensed: for settlements derived from an F6
//! negotiation, the accepted `terms_hash` is carried into
//! `SettlementTermsV1.metadata` under the exact encoding
//!
//! ```text
//! DOM-INTEROP/F6-TERMS-CARRY/V1\0 || accepted_terms_hash
//! ```
//!
//! byte-identical domain, exactly 32 hash bytes, no length prefix, no
//! padding, no trailing bytes, exactly once — and for the F6→F2 profile
//! of V1, metadata contains exactly this record. The decision changes
//! no wire, no A3 encoding, no field order, no frozen vector, not
//! `intent_hash`, and none of the ratified negotiation objects.
//!
//! **The two hashes are named apart, always** (D-023 §2):
//!
//! - `accepted_terms_hash` — the hash of the terms accepted in the F6
//!   negotiation (the §4.2 `TermsBindingV1` hash);
//! - `settlement_terms_hash` — the A3 hash of the canonical bytes of
//!   `SettlementTermsV1`.
//!
//! Changing the carry legitimately changes the `settlement_terms_hash`;
//! the carry replaces no economic field, and metadata stays
//! economically non-authoritative: the record COMMITS provenance, it is
//! never a source of parameters.
//!
//! **One source, three sinks** (D-023 §3). The authoritative source of
//! `accepted_terms_hash` is the authenticated, ratified and durably
//! journaled result of the F6 negotiation — never a free read of
//! metadata. This module's API enforces that shape: the typed
//! [`AcceptedNegotiationV1`] can only be obtained FROM the journal
//! ([`accepted_negotiation`]), and from that one value it derives the
//! canonical carry record AND the F4 binding hash. There is no function
//! here that accepts a caller-supplied hash for the carry, another for
//! F4, or arbitrary metadata alongside an unrelated F4 hash.
//!
//! **Restore fails closed** (D-023 §3). [`verify_restored`] recovers
//! the accepted result from the journal, reconstructs the expected
//! carry, compares it byte for byte against the persisted commitment,
//! and checks the F4 binding against the same `accepted_terms_hash`.
//! Any divergence is a named terminal refusal; a divergent value is
//! never silently chosen. The comparison is an integrity and
//! provenance check — it does not authorize interpreting metadata as a
//! source of economic parameters.

use kaystra_core::types::Digest32;

use crate::{BindingLog, DurableBinding};

/// The carry record's domain tag — LITERAL and byte-identical (D-023).
pub const CARRY_DOMAIN: &[u8] = b"DOM-INTEROP/F6-TERMS-CARRY/V1\0";

/// Exact length of the one record the F6→F2 V1 profile admits:
/// the domain followed by exactly 32 hash bytes.
pub const CARRY_RECORD_LEN: usize = CARRY_DOMAIN.len() + 32;

/// The typed, journal-sourced result of an accepted F6 negotiation.
///
/// There is deliberately no public constructor: the ONLY way to obtain
/// one is [`accepted_negotiation`], which reads the durable journal.
/// That is what makes "the caller cannot supply independent hashes" a
/// property of the API rather than a discipline.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AcceptedNegotiationV1 {
    rfq_id: Digest32,
    accepted_terms_hash: Digest32,
}

impl AcceptedNegotiationV1 {
    /// The RFQ this negotiation settled on.
    pub fn rfq_id(&self) -> Digest32 {
        self.rfq_id
    }

    /// The accepted `terms_hash` — the ONE value every sink derives
    /// from. Named in full per D-023 §2; never call this merely
    /// "terms_hash" where the A3 `settlement_terms_hash` is in scope.
    pub fn accepted_terms_hash(&self) -> Digest32 {
        self.accepted_terms_hash
    }

    /// The canonical carry record for `SettlementTermsV1.metadata`
    /// (D-023 §1): domain, then the 32 hash bytes, nothing else.
    pub fn carry_metadata(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CARRY_RECORD_LEN);
        out.extend_from_slice(CARRY_DOMAIN);
        out.extend_from_slice(&self.accepted_terms_hash);
        out
    }

    /// The hash the F4 assurance binding must be opened under — the
    /// SAME value the carry commits, from the same source (D-023 §3).
    pub fn assurance_terms_hash(&self) -> Digest32 {
        self.accepted_terms_hash
    }
}

/// Named refusals of the composition root (I13). Terminal: a caller
/// that sees one of these must fail the restore, never pick a side.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum CompositionRefusal {
    /// The journal holds no accepted binding for this RFQ — there is
    /// no negotiation result to compose a settlement from.
    #[error("no accepted negotiation is journaled for this rfq")]
    NegotiationNotBound,
    /// The persisted metadata does not equal, byte for byte, the carry
    /// record reconstructed from the journaled negotiation (D-023 §3's
    /// named failure).
    #[error("the persisted carry diverges from the journaled negotiation")]
    TermsCarryMismatch,
    /// The F4 binding names a different `accepted_terms_hash` than the
    /// journaled negotiation.
    #[error("the assurance binding diverges from the journaled negotiation")]
    AssuranceBindingMismatch,
}

/// The journal-sourced accepted result for `rfq_id`, if the atomic
/// §4.2 binding has been journaled. This is the single entry point of
/// D-023 §3: carry, A3 input and F4 binding all derive from what it
/// returns.
pub fn accepted_negotiation<L: BindingLog>(
    engine: &DurableBinding<L>,
    rfq_id: &Digest32,
) -> Result<AcceptedNegotiationV1, CompositionRefusal> {
    let bound = engine
        .ledger()
        .binding(rfq_id)
        .ok_or(CompositionRefusal::NegotiationNotBound)?;
    Ok(AcceptedNegotiationV1 {
        rfq_id: *rfq_id,
        accepted_terms_hash: bound.terms_hash,
    })
}

/// Strict parse of one F6→F2 V1 carry record (D-023 §1): the literal
/// domain, exactly 32 bytes of hash, exactly once, no trailing bytes.
/// Everything else — absent, truncated, altered domain, duplicated
/// record, padding — is [`CompositionRefusal::TermsCarryMismatch`].
///
/// Parsing yields the committed hash for VERIFICATION ONLY. Per D-023
/// §2/§3, metadata is never the source of the value a machine acts on;
/// the source is the journal, and [`verify_restored`] is where this
/// function belongs.
pub fn parse_carry(metadata: &[u8]) -> Result<Digest32, CompositionRefusal> {
    if metadata.len() != CARRY_RECORD_LEN {
        return Err(CompositionRefusal::TermsCarryMismatch);
    }
    let (domain, hash) = metadata.split_at(CARRY_DOMAIN.len());
    if domain != CARRY_DOMAIN {
        return Err(CompositionRefusal::TermsCarryMismatch);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(hash);
    Ok(out)
}

/// The D-023 §3 restore/recovery check, in the ratified order:
///
/// 1. recover the accepted result from the F6 journal;
/// 2. reconstruct the expected carry record;
/// 3. compare it BYTE FOR BYTE against the persisted commitment;
/// 4. check the F4 binding against the same `accepted_terms_hash`.
///
/// Any divergence fails terminally with its named refusal. This
/// function never returns a "winner" among divergent values, and its
/// success authorizes nothing beyond integrity and provenance.
pub fn verify_restored<L: BindingLog>(
    engine: &DurableBinding<L>,
    rfq_id: &Digest32,
    persisted_metadata: &[u8],
    assurance_terms_hash: &Digest32,
) -> Result<AcceptedNegotiationV1, CompositionRefusal> {
    let accepted = accepted_negotiation(engine, rfq_id)?;
    if persisted_metadata != accepted.carry_metadata().as_slice() {
        return Err(CompositionRefusal::TermsCarryMismatch);
    }
    if *assurance_terms_hash != accepted.accepted_terms_hash {
        return Err(CompositionRefusal::AssuranceBindingMismatch);
    }
    Ok(accepted)
}
