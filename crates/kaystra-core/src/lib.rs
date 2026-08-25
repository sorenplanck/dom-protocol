//! Core of the DOM↔X settlement engine (Kaystra).
//!
//! DOM Interop Foundation Document v0.2 §3.1 and §6.
//!
//! BOUNDARY RULE (§4.2): this crate does NOT import `dom-adaptor` nor
//! any chain-specific type. It talks to the DOM leg through `dom-leg`
//! and to the counterparty leg through `counterparty-api`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "engine")]
pub mod ingest;
#[cfg(feature = "engine")]
pub mod settlement_engine;
pub mod state;
#[cfg(feature = "engine")]
pub mod store_port;
pub mod terms;
pub mod types;

#[cfg(feature = "engine")]
pub use settlement_engine::{
    ChainCursorV1, ChainRecordV1, ChainSourceV1, EffectOutcome, EffectSinkV1, EnginePolicyV1,
    SettlementEngine, SettlementEngineError, TickReportV1,
};
pub use state::{
    transition, Effect, EvidenceRefV1, SettlementContext, SettlementEvent, SettlementState,
    Transition, TransitionError,
};
pub use terms::{
    SettlementTermsV1, TermsError, MAX_METADATA_BYTES, TERMS_DOMAIN, TERMS_MAGIC, TERMS_VERSION,
};
