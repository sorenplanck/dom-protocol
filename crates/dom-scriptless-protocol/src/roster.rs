//! The closed two-party participant set (NAR-DC-P1-007 §2).
//!
//! The Master Specification states the two-party bound in its V1 scope table,
//! in decision A-03, in §1.4 and in §7, and §4.1 orders the roster
//! lexicographically by participant identifier and rejects duplicates. None of
//! those passages is expressed as a checkable cardinality rule on the
//! participant set itself, so NAR-DC-P1-007 §2.2 closed it: a conforming
//! constructor accepts a roster if and only if it holds exactly two identities
//! and those two are distinct.
//!
//! The signed record is the citable authority for this module. The Master
//! Specification is not carried in this repository, so §2.1 of the record is
//! what states the four Master passages above, and §2.2 is what this module
//! implements.
//!
//! §2.2 requires the three refusals to be *"distinct normative outcomes"*, and
//! says explicitly that *"a validator whose only cardinality refusal is 'too
//! few' does not conform to this section"*. [`ParticipantSetError`] therefore
//! separates [`ParticipantSetError::TooFew`], [`ParticipantSetError::TooMany`]
//! and [`ParticipantSetError::Duplicate`] rather than collapsing them.
//!
//! This module is data only. It holds no key, performs no I/O, grants no
//! authority, and decides nothing about roles, terms or transitions.

use std::{error::Error, fmt};

/// A participant identity, as used by the §4.1 roster ordering rule.
pub type ParticipantIdV1 = [u8; 32];

/// The exact participant count the strict V1 contract profile admits.
///
/// NAR-DC-P1-007 §2.3 keeps `n`-of-`n` for any `n` greater than two outside
/// V1, so this is a closed constant rather than a configurable bound.
pub const PARTICIPANT_COUNT: usize = 2;

/// Why a candidate roster is not a conforming V1 participant set.
///
/// The three variants are the three refusals NAR-DC-P1-007 §2.2 requires to be
/// distinguishable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParticipantSetError {
    /// Fewer than two identities were offered.
    TooFew {
        /// How many identities the candidate roster held.
        found: usize,
    },
    /// More than two identities were offered.
    ///
    /// This is the refusal that `n`-of-`n` reaches. It is separate from
    /// [`Self::TooFew`] because admitting three or more participants is a
    /// scope violation, not a missing participant.
    TooMany {
        /// How many identities the candidate roster held.
        found: usize,
    },
    /// Exactly two identities were offered, but they are equal.
    ///
    /// A roster of one identity repeated is not a two-party contract: it names
    /// one participant twice.
    Duplicate,
}

impl fmt::Display for ParticipantSetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooFew { found } => {
                write!(
                    formatter,
                    "a V1 roster needs exactly two participants, found {found}"
                )
            }
            Self::TooMany { found } => write!(
                formatter,
                "a V1 roster admits exactly two participants, found {found}; n-of-n is outside V1"
            ),
            Self::Duplicate => formatter
                .write_str("the two participant identities are equal, so they are one participant"),
        }
    }
}

impl Error for ParticipantSetError {}

/// The closed V1 participant set: exactly two distinct identities, held in the
/// lexicographic order §4.1 specifies.
///
/// Canonicalisation happens once, in [`ParticipantSetV1::new`]. Two rosters
/// naming the same pair in opposite order produce equal participant sets, so
/// the ordering cannot depend on which side constructed it.
///
/// The value is immutable: it exposes readers only, and there is no way to add,
/// remove or reorder an identity after construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParticipantSetV1 {
    lower: ParticipantIdV1,
    higher: ParticipantIdV1,
}

impl ParticipantSetV1 {
    /// Validate and canonicalise a candidate roster.
    ///
    /// The roster is accepted if and only if it holds exactly two identities
    /// and those identities are distinct. The accepted pair is stored in
    /// lexicographic order. The arity is pinned by the two-element slice
    /// pattern below and by the return type of [`Self::identities`];
    /// [`PARTICIPANT_COUNT`] names that arity rather than configuring it.
    ///
    /// # Errors
    ///
    /// Returns [`ParticipantSetError::TooFew`] for fewer than two identities,
    /// [`ParticipantSetError::TooMany`] for more than two, and
    /// [`ParticipantSetError::Duplicate`] when exactly two equal identities are
    /// offered. No participant set is constructed in any of those cases.
    ///
    /// Cardinality is decided before distinctness, so an oversized roster is
    /// [`ParticipantSetError::TooMany`] even when it repeats an identity. Both
    /// are refusals and neither constructs a set, so the precedence changes
    /// which refusal is reported, never whether the roster is refused.
    pub fn new(identities: &[ParticipantIdV1]) -> Result<Self, ParticipantSetError> {
        let found = identities.len();
        let pair = match identities {
            [first, second] => (first, second),
            _ if found < PARTICIPANT_COUNT => return Err(ParticipantSetError::TooFew { found }),
            _ => return Err(ParticipantSetError::TooMany { found }),
        };
        let (first, second) = pair;
        if first == second {
            return Err(ParticipantSetError::Duplicate);
        }
        let (lower, higher) = if first < second {
            (*first, *second)
        } else {
            (*second, *first)
        };
        Ok(Self { lower, higher })
    }

    /// The lexicographically lower identity.
    #[must_use]
    pub const fn lower(&self) -> ParticipantIdV1 {
        self.lower
    }

    /// The lexicographically higher identity.
    #[must_use]
    pub const fn higher(&self) -> ParticipantIdV1 {
        self.higher
    }

    /// Both identities, in the §4.1 canonical order.
    #[must_use]
    pub const fn identities(&self) -> [ParticipantIdV1; PARTICIPANT_COUNT] {
        [self.lower, self.higher]
    }

    /// Whether `identity` is one of the two participants.
    #[must_use]
    pub fn contains(&self, identity: &ParticipantIdV1) -> bool {
        self.lower == *identity || self.higher == *identity
    }
}
