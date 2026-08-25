//! Participant roster and its protocol-level rules (M.1.3).
//!
//! F5 is exactly 2-of-2. The roster order comes from the canonical roster
//! committed in `SettlementTermsV1`; this crate never silently reorders.
//! Duplicate ids, roles or keys are rejected here even though a generic
//! MuSig2 library would accept repeated keys.

use crate::codec::{self, CanonicalBitcoinCodec};
use crate::error::{CodecError, RosterError};

/// Frozen roster version.
pub const ROSTER_VERSION: u16 = 1;

/// The two signing roles of the F5 leg (M.1.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinSignerRoleV1 {
    /// The maker of the settlement.
    Maker = 0x01,
    /// The taker of the settlement.
    Taker = 0x02,
}

impl BitcoinSignerRoleV1 {
    /// Decodes the frozen discriminant.
    pub fn from_u8(value: u8) -> Result<Self, RosterError> {
        match value {
            0x01 => Ok(Self::Maker),
            0x02 => Ok(Self::Taker),
            _ => Err(RosterError::MalformedKey),
        }
    }
}

/// One participant of the 2-of-2 (M.1.3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParticipantKeyV1 {
    /// Stable participant identifier from the terms.
    pub participant_id: [u8; 32],
    /// The participant's role.
    pub role: BitcoinSignerRoleV1,
    /// Compressed SEC1 public key.
    pub compressed_key: [u8; 33],
}

/// The canonical, ordered 2-of-2 roster (M.1.3).
///
/// Changing order, role or key changes `roster_hash`, the session binding
/// and the aggregate key — that is the point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ParticipantKeyRosterV1 {
    /// Frozen roster version ([`ROSTER_VERSION`]).
    ///
    /// Audit finding F2(b): PRIVATE, so an invalid roster is unrepresentable
    /// outside this module. Every construction goes through [`Self::new`],
    /// which validates; reads go through [`Self::version`].
    version: u16,
    /// The two participants, in the exact order committed by the terms.
    /// PRIVATE for the same reason; reads go through [`Self::participants`].
    participants: [ParticipantKeyV1; 2],
}

impl ParticipantKeyRosterV1 {
    /// Builds and validates a roster.
    pub fn new(participants: [ParticipantKeyV1; 2]) -> Result<Self, RosterError> {
        let roster = Self {
            version: ROSTER_VERSION,
            participants,
        };
        roster.validate()?;
        Ok(roster)
    }

    /// Constructs from wire-decoded parts, VALIDATING — the codec's entry
    /// point. Crate-internal so the F2(b) invariant holds: no path inside or
    /// outside this crate can hold an unvalidated roster.
    pub(crate) fn from_wire(
        version: u16,
        participants: [ParticipantKeyV1; 2],
    ) -> Result<Self, RosterError> {
        let roster = Self {
            version,
            participants,
        };
        roster.validate()?;
        Ok(roster)
    }

    /// The frozen roster version. Always [`ROSTER_VERSION`] on a value built
    /// through [`Self::new`], which is the only construction path.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// The two participants, in the exact order committed by the terms.
    #[must_use]
    pub const fn participants(&self) -> &[ParticipantKeyV1; 2] {
        &self.participants
    }

    /// The protocol-level rules of M.1.3: frozen version, distinct ids,
    /// distinct roles, distinct keys, well-formed SEC1 prefixes.
    pub fn validate(&self) -> Result<(), RosterError> {
        if self.version != ROSTER_VERSION {
            return Err(RosterError::UnsupportedVersion);
        }
        let [a, b] = &self.participants;
        if a.participant_id == b.participant_id {
            return Err(RosterError::DuplicateParticipantId);
        }
        if a.role == b.role {
            return Err(RosterError::DuplicateRole);
        }
        if a.compressed_key == b.compressed_key {
            return Err(RosterError::DuplicateKey);
        }
        for p in &self.participants {
            if p.compressed_key[0] != 0x02 && p.compressed_key[0] != 0x03 {
                return Err(RosterError::MalformedKey);
            }
        }
        Ok(())
    }

    /// The roster digest committed into the session binding (M.5.3).
    ///
    /// Audit finding F2: this used to discard `encode_canonical`'s `Result`.
    /// Because that function validates first and writes nothing when
    /// validation fails, every invalid roster hashed to one constant —
    /// `f5_digest(KIND_ROSTER, &[])` — so distinct invalid rosters collided
    /// with each other and the caller learned nothing. The error is now
    /// propagated: an invalid roster has no digest.
    ///
    /// The `debug_assert_eq!` on the version that stood here is gone rather
    /// than repaired. It was compiled out of release builds, so it protected
    /// nothing in production, and `validate` checks the same field for real.
    pub fn roster_hash(&self) -> Result<[u8; 32], CodecError> {
        let mut out = Vec::with_capacity(Self::MAX_ENCODED_LEN);
        self.encode_canonical(&mut out)?;
        Ok(codec::f5_digest(Self::KIND, &out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participant(id: u8, role: BitcoinSignerRoleV1, key0: u8) -> ParticipantKeyV1 {
        let mut key = [0x11u8; 33];
        key[0] = key0;
        key[1] = id;
        ParticipantKeyV1 {
            participant_id: [id; 32],
            role,
            compressed_key: key,
        }
    }

    #[test]
    fn valid_roster_passes() {
        let r = ParticipantKeyRosterV1::new([
            participant(1, BitcoinSignerRoleV1::Maker, 0x02),
            participant(2, BitcoinSignerRoleV1::Taker, 0x03),
        ]);
        assert!(r.is_ok());
    }

    #[test]
    fn duplicates_are_rejected() {
        let dup_id =
            ParticipantKeyRosterV1::new([participant(1, BitcoinSignerRoleV1::Maker, 0x02), {
                let mut p = participant(1, BitcoinSignerRoleV1::Taker, 0x03);
                p.participant_id = [1; 32];
                p
            }]);
        assert_eq!(dup_id.unwrap_err(), RosterError::DuplicateParticipantId);

        let dup_role = ParticipantKeyRosterV1::new([
            participant(1, BitcoinSignerRoleV1::Maker, 0x02),
            participant(2, BitcoinSignerRoleV1::Maker, 0x03),
        ]);
        assert_eq!(dup_role.unwrap_err(), RosterError::DuplicateRole);

        let mut same_key_b = participant(2, BitcoinSignerRoleV1::Taker, 0x02);
        same_key_b.compressed_key = participant(1, BitcoinSignerRoleV1::Maker, 0x02).compressed_key;
        let dup_key = ParticipantKeyRosterV1::new([
            participant(1, BitcoinSignerRoleV1::Maker, 0x02),
            same_key_b,
        ]);
        assert_eq!(dup_key.unwrap_err(), RosterError::DuplicateKey);
    }

    #[test]
    fn malformed_prefix_is_rejected() {
        let bad = ParticipantKeyRosterV1::new([
            participant(1, BitcoinSignerRoleV1::Maker, 0x04),
            participant(2, BitcoinSignerRoleV1::Taker, 0x03),
        ]);
        assert_eq!(bad.unwrap_err(), RosterError::MalformedKey);
    }

    #[test]
    fn order_changes_the_hash() {
        let a = participant(1, BitcoinSignerRoleV1::Maker, 0x02);
        let b = participant(2, BitcoinSignerRoleV1::Taker, 0x03);
        let r1 = ParticipantKeyRosterV1::new([a, b]).unwrap();
        let r2 = ParticipantKeyRosterV1::new([b, a]).unwrap();
        assert_ne!(
            r1.roster_hash().expect("valid"),
            r2.roster_hash().expect("valid")
        );
    }

    /// **Audit finding F2** — an invalid roster has no digest at all.
    ///
    /// `new()` is not the only way in: the struct has public fields and
    /// derives `Copy`, so a caller can build one by literal and skip
    /// validation entirely. Every fixture below does exactly that, because
    /// a fixture that went through `new()` could never reach the defect.
    ///
    /// Before 2026-08-19 `roster_hash` discarded the encoder's `Result`.
    /// The encoder validates before writing anything, so all three of these
    /// hashed to the same constant, `f5_digest(KIND_ROSTER, &[])` — three
    /// distinct invalid rosters, one digest, and a caller that could not
    /// tell any of it had happened.
    ///
    /// The duplicate-`participant_id` fixture is the one that matters.
    /// `bind_exact_claim` re-checks roles and compressed keys downstream,
    /// so a duplicate role would be caught there anyway; duplicate ids are
    /// checked nowhere else, which leaves this the only line of defence.
    #[test]
    fn an_invalid_roster_has_no_digest() {
        let duplicate_id = ParticipantKeyRosterV1 {
            version: ROSTER_VERSION,
            participants: [participant(1, BitcoinSignerRoleV1::Maker, 0x02), {
                let mut p = participant(2, BitcoinSignerRoleV1::Taker, 0x03);
                p.participant_id = [1; 32];
                p
            }],
        };
        let duplicate_role = ParticipantKeyRosterV1 {
            version: ROSTER_VERSION,
            participants: [
                participant(1, BitcoinSignerRoleV1::Maker, 0x02),
                participant(2, BitcoinSignerRoleV1::Maker, 0x03),
            ],
        };
        let wrong_version = ParticipantKeyRosterV1 {
            version: ROSTER_VERSION + 1,
            participants: [
                participant(1, BitcoinSignerRoleV1::Maker, 0x02),
                participant(2, BitcoinSignerRoleV1::Taker, 0x03),
            ],
        };

        // Each fixture is genuinely invalid, asserted against the rule it
        // breaks rather than against `is_err()`.
        assert_eq!(
            duplicate_id.roster_hash().unwrap_err(),
            CodecError::Roster(RosterError::DuplicateParticipantId)
        );
        assert_eq!(
            duplicate_role.roster_hash().unwrap_err(),
            CodecError::Roster(RosterError::DuplicateRole)
        );
        assert_eq!(
            wrong_version.roster_hash().unwrap_err(),
            CodecError::Roster(RosterError::UnsupportedVersion)
        );

        // The version field is where the old `debug_assert_eq!` stood. It
        // was compiled out of release builds, so in production the wrong
        // version reached the encoder unchecked; this assertion is the
        // replacement that survives `--release`.
        let valid = ParticipantKeyRosterV1::new([
            participant(1, BitcoinSignerRoleV1::Maker, 0x02),
            participant(2, BitcoinSignerRoleV1::Taker, 0x03),
        ])
        .unwrap();
        assert!(valid.roster_hash().is_ok());
    }

    #[test]
    fn f2b_every_construction_path_validates() {
        // The fields are private now, so a literal construction outside this
        // module no longer compiles — the compiler carries the invariant.
        // What remains provable at runtime: both constructors refuse an
        // invalid roster instead of representing it.
        let duplicate_id = [
            participant(1, BitcoinSignerRoleV1::Maker, 0x02),
            ParticipantKeyV1 {
                participant_id: [1; 32],
                ..participant(2, BitcoinSignerRoleV1::Taker, 0x03)
            },
        ];
        assert!(ParticipantKeyRosterV1::new(duplicate_id).is_err());
        assert!(ParticipantKeyRosterV1::from_wire(ROSTER_VERSION, duplicate_id).is_err());
        assert!(matches!(
            ParticipantKeyRosterV1::from_wire(
                ROSTER_VERSION + 1,
                [
                    participant(1, BitcoinSignerRoleV1::Maker, 0x02),
                    participant(2, BitcoinSignerRoleV1::Taker, 0x03),
                ]
            ),
            Err(RosterError::UnsupportedVersion)
        ));
    }
}
