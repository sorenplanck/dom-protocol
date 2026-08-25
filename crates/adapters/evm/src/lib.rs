//! `adapter-evm` — EVM counterparty leg of a DOM↔EVM settlement (phase F3).
//!
//! Foundation Document DOM Interop v0.2.1 §2.3, §4.1, §4.3, §7 (F3).
//!
//! This crate implements [`counterparty_api::CounterpartyAdapter`] against a
//! `ConditionLockV2` / `ConditionLockERC20V2` deployment. It observes the chain
//! through JSON-RPC, turns finalized logs into neutral
//! [`counterparty_api::ObservedEvent`]s and turns canonical evidence blobs into
//! [`counterparty_api::VerifiedOutcome`]s.
//!
//! # What this crate deliberately does NOT do
//!
//! - **It never signs and never custodies (I1).** [`adapter::EvmAdapter::prepare_lock`]
//!   returns a deterministic *unsigned* call artifact (`to`, `value`, calldata,
//!   chain id, gas hint). No key material of any kind ever enters this crate,
//!   and no type here can hold one.
//! - **It never reimplements a DOM primitive (I15).** The secp256k1 usage in
//!   [`binding`] exists only to reproduce the EVM notion of `address(t·G)`, which
//!   is what the on-chain contract compares against. The DOM challenge, the DOM
//!   verifier and the adaptor pre-signature live exclusively behind `dom-leg`.
//! - **It never prints, `Debug`s, logs or returns the revealed scalar `t`** (I6).
//!   `t` travels only inside [`counterparty_api::RevealedSecretBytes`], whose
//!   `Debug` is redacted, and inside [`evidence::EvmEvidence`], whose `Debug` is
//!   redacted here as well.
//!
//! # Fail-closed posture
//!
//! Every validation in this crate is fail-closed. In particular:
//!
//! - finality is the Ethereum `finalized` tag and **nothing else** (see
//!   [`finality`]); if the endpoint cannot serve it, observation fails with
//!   [`counterparty_api::AdapterError::AdapterUnavailable`] instead of silently
//!   degrading to a confirmation count. The *reason* stays distinguishable
//!   through [`error::RejectReason::FinalizedTagUnavailable`], so a caller can
//!   report `BLOCKED_EXTERNAL` for a provider that lacks the tag rather than
//!   casting doubt on the settlement;
//! - no event is ever surfaced for a block above the finalized height;
//! - **an `eth_getLogs` answer is never sufficient on its own.** Every log is
//!   corroborated by an independently fetched receipt (which must carry that
//!   very log at that very `logIndex`), an independently fetched transaction
//!   sent to the configured contract, an independently fetched block that the
//!   canonical chain agrees on, and a finalized-ancestry proof. See [`attest`];
//! - a reorg deeper than the configured `max_reorg_depth` is an error, not a
//!   best-effort recovery;
//! - every length is checked against an explicit cap **before** allocating (I14);
//! - a decode that leaves trailing bytes is rejected (I14).
//!
//! # Reorg semantics (I11) — a reorg does not un-reveal a secret
//!
//! A reorg invalidates the *settlement effect* of an observation, never the
//! *publicity* of a scalar that was already revealed on chain. Once a `Claimed`
//! log has been observed, `t` is public knowledge forever; rewinding the cursor
//! cannot make it secret again. This crate encodes that asymmetry explicitly in
//! [`revealed::RevealedRegistry`], which is append-only and is never rewound by
//! [`reorg`]. See [`revealed`] for the full rationale.
//!
//! # Offline by construction
//!
//! The real HTTP transport lives behind the non-default feature `rpc-http`.
//! `cargo test` for this crate performs zero network I/O: every test drives the
//! deterministic in-crate [`mock::MockChain`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod abi;
pub mod adapter;
pub mod attest;
pub mod binding;
pub mod cursor;
pub mod error;
pub mod evidence;
pub mod finality;
pub mod mock;
pub mod reorg;
pub mod revealed;
pub mod rpc;

pub use abi::keccak256;
pub use adapter::{
    evm_counterparty_chain_id, EvmAdapter, EvmAdapterConfig, UnsignedEvmCall, ADAPTER_VERSION,
};
pub use attest::{
    attest_settlement_log, extend_verified_chain, prove_hash_link, verify_finalized_ancestry,
    verify_finalized_ancestry_deep, Attestation, VerifiedChain, MAX_ANCESTRY_TOTAL,
    MAX_ANCESTRY_WALK, MAX_VERIFIED_CHAIN,
};
pub use binding::{
    adaptor_address, adaptor_address_of_scalar, derive_binding, derive_lock_id, Direction,
    LockTerms,
};
pub use cursor::EvmCursor;
pub use error::{RejectReason, Result};
pub use evidence::{EvidenceKind, EvmEvidence};
pub use finality::FinalizedHead;
pub use rpc::JsonRpc;
