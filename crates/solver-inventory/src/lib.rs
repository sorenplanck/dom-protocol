//! Durable own-inventory authority for the DOM interoperability solver.
//!
//! This crate closes the gap between an F6 reservation identifier and real,
//! observed solver capacity. It deliberately does not price assets, invent
//! balances, hold signing keys, or contact a venue. Chain observers and
//! custody actuators remain participant-owned capabilities behind narrow
//! traits; the SQLite authority only commits public evidence, exclusive
//! allocations, state transitions and fencing generations.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod model;
mod store;

pub use model::{
    BondInventoryPolicyCapabilityV1, BondInventoryPolicyRefusalV1, CommittedInventoryCapabilityV1,
    CommittedInventoryCapabilityV2, Digest32, InventoryActuatorV1, InventoryActuatorV2,
    InventoryAllocationCapabilityV1, InventoryAllocationRequestV1, InventoryExecutionV1,
    InventoryKeyV1, InventoryMutationContextV1, InventoryObservationKindV1, InventoryObservationV1,
    InventoryObserverRequestV1, InventoryObserverV1, InventoryPurposeV1, InventoryReconciliationV1,
    InventorySnapshotRefV1, InventorySnapshotV1, MutationOutcomeV1, MutationStatusV1,
    PendingConsumptionV1, QuoteInventoryCapabilityV1, QuoteInventoryCapabilityV2,
    ReservationStateV1, ReservationViewV1, ReserveQuoteRequestV1, ReserveQuoteRequestV2,
};
pub use store::{
    DurableInventoryStoreV1, InventoryLeaseV1, InventoryStoreErrorV1, LeaseAcquireOutcomeV1,
};
