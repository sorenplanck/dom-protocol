//! Pure DOM Contracts protocol and policy state boundary.
//!
//! This crate carries the non-operational foundation ratified by
//! NAR-DC-P1-007: the closed two-party participant set of §2 and the closed
//! 22-edge phase topology of §3. Both are policy data, published so that
//! conformance can be enumerated and compared rather than asserted (§3.4).
//!
//! * [`roster`] — Master §4.1 ordering and NAR-DC-P1-007 §2's exactly-two rule.
//! * [`topology`] — the adjudicated §9.2 table, as data.
//!
//! # This crate cannot run a contract
//!
//! There is no contract state machine here, and this foundation cannot create,
//! fund, claim or refund a contract. It holds no key, performs no I/O, reads no
//! clock, and issues no capability. It depends on `dom-scriptless-store` for the
//! canonical `SessionPhaseV1` type alone: it opens no store, writes nothing, and
//! holds no store capability. It contains no event type, no executor, no
//! session-advancing operation, no attestation a caller could construct, no
//! boolean evidence structure and no authority token.
//!
//! The §9.2 preconditions, the §7.3 `ReadyToFund` gate, §9.3 abort, adaptor
//! signing, collaborative Bulletproof rounds, the shared output, the off-chain
//! envelope and every G-UX1 deliverable are all absent, and NAR-DC-P1-007 §4
//! records that the funding-authorisation surface is a model rather than
//! production authority.
//!
//! ```text
//! PRODUCTION = NOT_AUTHORIZED
//! MAINNET = DISABLED
//! REAL_FUNDS = PROHIBITED
//! PHASE2 = NOT_AUTHORIZED
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod roster;
pub mod topology;

pub use roster::{ParticipantIdV1, ParticipantSetError, ParticipantSetV1, PARTICIPANT_COUNT};
pub use topology::{is_normative_edge, NORMATIVE_EDGES, NORMATIVE_EDGE_COUNT};
