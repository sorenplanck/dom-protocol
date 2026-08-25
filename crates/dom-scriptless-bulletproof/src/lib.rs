//! The collaborative Bulletproof MPC of the Scriptless shared output.
//!
//! Two parties build one bounded aggregate range proof over a commitment
//! neither of them controls alone. The laboratory lineage placed this inside
//! `dom-crypto`; the node is mainnet and immutable, so it lives here.
//!
//! This is the one bridge that could NOT be written against the node's public
//! surface. The MPC drives grin's raw rangeproof FFI with DOM's H_DOM supplied
//! as `value_gen`, and every wrapper it needs — the backend context, the
//! SEC1↔zkp encodings, the raw prove and verify calls — is `pub(crate)` inside
//! `dom-crypto`. Those wrappers are therefore transcribed here byte for byte
//! from the mainnet v2 release line.
//!
//! The transcription is not trusted on its word. `backend::conformance`
//! proves, against the node itself, that this copy computes DOM's generator
//! and DOM's proofs and not something of its own:
//!
//! * the H generator it derives equals `dom_crypto::h_generator::h_compressed()`;
//! * a proof this backend produces is accepted by the node's public verifier;
//! * a proof the node produces is accepted by this backend.
//!
//! If `dom-crypto`'s backend ever moves, those three fail rather than drift
//! silently.
//!
//! NOT RATIFIED — the duplication exists only because the node cannot be
//! edited, and is recorded for the operator as a standing audit item.

mod node_private;
mod sec1_zkp_bridge;

pub mod backend;

pub use backend::{
    bulletproof_mpc_aggregate_tau_x, bulletproof_mpc_finalize,
    bulletproof_mpc_finalize_continuation_from_bytes_v1,
    bulletproof_mpc_finalize_continuation_to_bytes_v1, bulletproof_mpc_round1,
    bulletproof_mpc_round2, BulletproofMpcFinalizeState, BulletproofMpcRound1Output,
    BulletproofMpcRound1State,
};
