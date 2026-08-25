> **Normative status: DECIDED** (operator ratification, 2026-08-09).
> This document is the English-language normative authority for Phase 2 (F2) of DOM Interop.
> It complements the DOM Interop Foundation Document v0.4.
> The Portuguese original was provided by the operator and, for publication purposes, is
> superseded by this English version, in accordance with the project's English-only
> publication rule.

DOM INTEROP — PHASE 2

Integral Engineering Specification of the Kaystra Core v1.0

```text
Document:             DOM-Interop-Fase-2-Especificacao-Integral-de-Engenharia-v1.0
Version:              1.0
Date:                 2026-08-09
Authority:            direct operator decision in the DOM Interop project chat
Phase:                F2 — Kaystra Core
Gate:                 G-F2
Normative status:     DECIDED FOR IMPLEMENTATION
Target repository:    https://github.com/sorenplanck/Dom-interop.git
Integration branch:   main
Base document:        DOM-Interop-Documento-de-Fundacao-v0.2.1.md
Prior dependency:     F1 complete and G-F1 = PASS
Excluded phases:      F3, F4, F5, F6, F7 and F8
```

This document consolidates into a single executable specification all of the
Phase 2 programming decisions. It does not alter DOM consensus, does not alter
dom-protocol, dom-contracts, DOM Wallet or DOM Scriptless, and does not
authorize starting the EVM leg, Bitcoin, USPE, RFQ/solver or Relay.

The goal of F2 is to build the deterministic engine that coordinates a
DOM ↔ X settlement, without knowing the DOM's internal cryptography and
without interpreting evidence specific to any chain. The engine consumes
neutral ports, persists every decision before any external effect, recovers
from crash, and converges under duplication, replay, reorder and reorg.

1. Terminal outcome of Phase 2

Phase 2 is only complete when all of the items below are true at the same
time:

```text
F2_STATE_MACHINE                 = COMPLETE
SETTLEMENT_TERMS_V1              = CANONICAL_AND_FROZEN
TERMS_HASH_V1                    = DETERMINISTIC_AND_VECTORED
DURABLE_JOURNAL                  = ACTIVE
DURABLE_OUTBOX                   = ACTIVE
CAS_MONOTONIC_REVISION           = ACTIVE
CRASH_RECOVERY                   = PASS
DUPLICATION_REPLAY               = PASS
REORDER                          = PASS
REORG                            = PASS
LATE_EVIDENCE                    = PASS
CLAIM_XOR_REFUND                 = PROVED
F1_REGRESSION                    = GREEN
G-F2                             = PASS
```

G-F2 = PASS does not mean integration with the real DOM. In this phase, the
chain semantics remain exercised by dom-sim; the DOM-leg cryptography comes
from F1 and must remain real. dom-sim does not satisfy F7 or any final gate of
integration with the DOM network.

2. Consolidated decisions

|ID      |Decision applicable to F2 |Status in this document|
|--------|-----------------------|----------------------|
|A3-F2   |`SettlementTermsV1` has its own strict, versioned binary encoding, independent of `serde` |DECIDED|
|A3-HASH |`terms_hash = BLAKE2b-256(domain || canonical_bytes)` with a dedicated domain |DECIDED|
|D-003   |`last_observed_height`, `FundingAbsent` and idempotent re-observation prevent double regression and post-reorg deadlock|DECIDED|
|D-004   |`RefundConfirmed` does not require a prior `TimelockExpired`; the chain is the timelock authority |DECIDED|
|PERSIST |append-only journal, snapshot with CAS, cursor and outbox are durable and transactional |DECIDED|
|DELIVERY|transport/observers are at-least-once; economic effects are exactly-once via idempotency |DECIDED|
|REORDER |valid out-of-order evidence is parked and re-evaluated; it is neither discarded nor applied prematurely |DECIDED|
|LATE    |evidence arriving after a terminal is preserved for audit, without changing the economic outcome |DECIDED|
|SECRET  |`t` is never persisted in the core, store, journal, outbox or log |DECIDED|

D-002 does not belong to F2. The payout with pull fallback of
ConditionLockV2 is an F3 specification and appears here only as a future
source of a neutral event.

3. Architectural boundaries

3.1 Permitted dependencies

```text
                         ┌────────────────────┐
                         │    kaystra-core    │
                         │ termos + máquina  │
                         │ motor + policies  │
                         └──────┬───────┬────┘
                                │       │
                    ┌───────────▼──┐ ┌──▼────────────────┐
                    │    store     │ │ counterparty-api  │
                    │ journal/CAS  │ │ eventos neutros   │
                    │ cursor/outbox│ │ evidência opaca   │
                    └──────────────┘ └─────────┬──────────┘
                                              │
                                    ┌─────────▼──────────┐
                                    │ adapters/dom-sim  │
                                    │ somente harness   │
                                    └────────────────────┘
```

Mandatory rules:

1. kaystra-core does not import dom-adaptor.
2. store does not import dom-adaptor nor DOM cryptographic types.
3. Only dom-leg/dom-vault, closed in F1, access the DOM cryptographic
authority.
4. The core does not interpret chain-specific blocks, receipts, proofs or
transactions.
5. The chain adapter verifies the evidence and produces a neutral event.
6. The engine never stores seed, key, share, secret nonce or t.
7. No administrative endpoint, global pause, guardian or manual override.

3.2 Minimal layout

```text
crates/
  kaystra-core/
    src/lib.rs
    src/types.rs
    src/terms.rs
    src/state.rs
    src/engine.rs
    src/store_port.rs
    tests/state_properties.rs
    tests/terms_vectors.rs
  counterparty-api/
    src/lib.rs
  store/
    src/lib.rs
    src/sqlite.rs
    migrations/0001_f2_core.sql
  adapters/dom-sim/
    src/lib.rs
  f2-harness/
    src/lib.rs
    tests/g_f2.rs
  f2-model/
    src/main.rs
```

4. Rust dependencies frozen for F2

```toml
# crates/kaystra-core/Cargo.toml
[package]
name = "kaystra-core"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
publish = false

[dependencies]
counterparty-api = { workspace = true }
store = { workspace = true }
thiserror = { workspace = true }
blake2 = { version = "=0.10.6", default-features = false }

[dev-dependencies]
proptest = "=1.7.0"
hex = "=0.4.3"
```

The lockfile is committed. A version update is intentional, isolated, and
requires re-running the vectors. serde, JSON, generic CBOR or bincode do not
define the canonical wire of SettlementTermsV1.

5. Fundamental types

```rust
// crates/kaystra-core/src/types.rs
#![forbid(unsafe_code)]

use core::fmt;

pub type Digest32 = [u8; 32];

macro_rules! public_id {
    ($name:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 32]);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({:02x}{:02x}..)"),
                       self.0[0], self.0[1])
            }
        }
    };
}

public_id!(SettlementId);
public_id!(SessionId);
public_id!(IntentHash);
public_id!(SolverId);
public_id!(ParticipantId);
public_id!(ChainId);
public_id!(AssetId);
public_id!(EvidenceId);
public_id!(EffectId);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LegRole {
    Dom = 0x01,
    Counterparty = 0x02,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockMechanism {
    DomAdaptor2of2 = 0x01,
    ConditionLock = 0x02,
    SchnorrAdaptor = 0x03,
    HashlockFallback = 0x04,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimelockSpec {
    BlockHeight { value: u64 },
    TimestampSeconds { value: u64 },
    BtcTime512s { value: u64 },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FinalityPolicyV1 {
    pub min_confirmations: u32,
    pub max_reorg_depth: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LegTermsV1 {
    pub role: LegRole,
    pub chain_id: ChainId,
    pub asset_id: AssetId,
    pub amount: u128,
    pub beneficiary: ParticipantId,
    pub refund_to: ParticipantId,
    pub mechanism: LockMechanism,
    pub deadline: TimelockSpec,
    pub finality: FinalityPolicyV1,
    pub adapter_profile_hash: Digest32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FeeLimitV1 {
    pub dom_max: u128,
    pub counterparty_max: u128,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecoveryPolicyV1 {
    pub refund_before_funding: bool,
    pub evidence_retention_blocks: u64,
}
```

Monetary values use only integers in the smallest native unit. float is
forbidden. Asset and chain identifiers are 32-byte records defined by a
versioned profile; ticker strings never enter as authority.

6. SettlementTermsV1 and A3

6.1 Frozen structure

```rust
// crates/kaystra-core/src/terms.rs
use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};

use crate::types::*;

pub const TERMS_MAGIC: &[u8; 8] = b"DOMITRM1";
pub const TERMS_VERSION: u16 = 1;
pub const TERMS_DOMAIN: &[u8] = b"DOM-INTEROP/SETTLEMENT-TERMS/V1\0";
pub const MAX_METADATA_BYTES: usize = 4096;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SettlementTermsV1 {
    pub settlement_id: SettlementId,
    pub session_id: SessionId,
    pub intent_hash: IntentHash,
    pub solver_id: SolverId,
    pub roster: [ParticipantId; 2],
    pub dom_leg: LegTermsV1,
    pub counterparty_leg: LegTermsV1,
    pub adaptor_point_sec1: [u8; 33],
    pub fee_limit: FeeLimitV1,
    pub recovery: RecoveryPolicyV1,
    pub assurance_policy_hash: Option<Digest32>,
    pub policy_version: u32,
    pub metadata: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TermsError {
    #[error("invalid version")]
    InvalidVersion,
    #[error("invalid topology")]
    InvalidTopology,
    #[error("invalid roster")]
    InvalidRoster,
    #[error("zero amount")]
    ZeroAmount,
    #[error("invalid finality policy")]
    InvalidFinality,
    #[error("metadata exceeds bound")]
    BoundsExceeded,
    #[error("non-canonical adaptor point")]
    NonCanonicalPoint,
    #[error("hash initialization failed")]
    HashInitialization,
}
```

Validity rules:

• roster[0] < roster[1] in lexicographic order; equal entries are forbidden;
• dom_leg.role == Dom and counterparty_leg.role == Counterparty;
• amount > 0 on both legs;
• min_confirmations > 0 and max_reorg_depth >= min_confirmations;
• the adaptor point is compressed SEC1, prefix 0x02 or 0x03, 33 bytes;
• metadata is opaque, bounded to 4096 bytes and not economically
authoritative;
• no field is omitted for having a zero value;
• no trailing byte is accepted by the decoder;
• unknown version and unknown enum tag fail closed;
• terms_hash is not part of the structure itself, avoiding circularity.

6.2 Canonical encoding

All integers are big-endian. Fields have a fixed order. There are no maps,
no locale-dependent ordering, no variable-length numbers and no Unicode
strings.

```rust
fn put_u16(out: &mut Vec<u8>, v: u16) { out.extend_from_slice(&v.to_be_bytes()); }
fn put_u32(out: &mut Vec<u8>, v: u32) { out.extend_from_slice(&v.to_be_bytes()); }
fn put_u64(out: &mut Vec<u8>, v: u64) { out.extend_from_slice(&v.to_be_bytes()); }
fn put_u128(out: &mut Vec<u8>, v: u128) { out.extend_from_slice(&v.to_be_bytes()); }

fn put_timelock(out: &mut Vec<u8>, v: TimelockSpec) {
    match v {
        TimelockSpec::BlockHeight { value } => { out.push(0x01); put_u64(out, value); }
        TimelockSpec::TimestampSeconds { value } => { out.push(0x02); put_u64(out, value); }
        TimelockSpec::BtcTime512s { value } => { out.push(0x03); put_u64(out, value); }
    }
}

fn put_leg(out: &mut Vec<u8>, leg: &LegTermsV1) {
    out.push(leg.role as u8);
    out.extend_from_slice(&leg.chain_id.0);
    out.extend_from_slice(&leg.asset_id.0);
    put_u128(out, leg.amount);
    out.extend_from_slice(&leg.beneficiary.0);
    out.extend_from_slice(&leg.refund_to.0);
    out.push(leg.mechanism as u8);
    put_timelock(out, leg.deadline);
    put_u32(out, leg.finality.min_confirmations);
    put_u32(out, leg.finality.max_reorg_depth);
    out.extend_from_slice(&leg.adapter_profile_hash);
}

impl SettlementTermsV1 {
    pub fn validate(&self) -> Result<(), TermsError> {
        if self.roster[0] >= self.roster[1] {
            return Err(TermsError::InvalidRoster);
        }
        if self.dom_leg.role != LegRole::Dom
            || self.counterparty_leg.role != LegRole::Counterparty
        {
            return Err(TermsError::InvalidTopology);
        }
        if self.dom_leg.amount == 0 || self.counterparty_leg.amount == 0 {
            return Err(TermsError::ZeroAmount);
        }
        for f in [self.dom_leg.finality, self.counterparty_leg.finality] {
            if f.min_confirmations == 0 || f.max_reorg_depth < f.min_confirmations {
                return Err(TermsError::InvalidFinality);
            }
        }
        if !matches!(self.adaptor_point_sec1[0], 0x02 | 0x03) {
            return Err(TermsError::NonCanonicalPoint);
        }
        if self.metadata.len() > MAX_METADATA_BYTES {
            return Err(TermsError::BoundsExceeded);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, TermsError> {
        self.validate()?;
        let mut out = Vec::with_capacity(512 + self.metadata.len());
        out.extend_from_slice(TERMS_MAGIC);
        put_u16(&mut out, TERMS_VERSION);
        out.extend_from_slice(&self.settlement_id.0);
        out.extend_from_slice(&self.session_id.0);
        out.extend_from_slice(&self.intent_hash.0);
        out.extend_from_slice(&self.solver_id.0);
        out.extend_from_slice(&self.roster[0].0);
        out.extend_from_slice(&self.roster[1].0);
        put_leg(&mut out, &self.dom_leg);
        put_leg(&mut out, &self.counterparty_leg);
        out.extend_from_slice(&self.adaptor_point_sec1);
        put_u128(&mut out, self.fee_limit.dom_max);
        put_u128(&mut out, self.fee_limit.counterparty_max);
        out.push(u8::from(self.recovery.refund_before_funding));
        put_u64(&mut out, self.recovery.evidence_retention_blocks);
        match self.assurance_policy_hash {
            None => out.push(0x00),
            Some(h) => { out.push(0x01); out.extend_from_slice(&h); }
        }
        put_u32(&mut out, self.policy_version);
        put_u32(&mut out, self.metadata.len() as u32);
        out.extend_from_slice(&self.metadata);
        Ok(out)
    }

    pub fn terms_hash(&self) -> Result<Digest32, TermsError> {
        let encoded = self.canonical_bytes()?;
        let mut h = Blake2bVar::new(32).map_err(|_| TermsError::HashInitialization)?;
        h.update(TERMS_DOMAIN);
        h.update(&encoded);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out)
            .map_err(|_| TermsError::HashInitialization)?;
        Ok(out)
    }
}
```

6.3 Identities and bindings

settlement_id and session_id are born as public random identifiers of
32 bytes, distinct and one-shot. Neither of them is derived from a secret.
The minimal binding of any F2 artifact is:

```text
(protocol_version, settlement_id, session_id, terms_hash,
 participant_roster, chain_id, adapter_profile_hash, purpose)
```

The same settlement_id with a different terms_hash is terminal equivocation.
The same terms_hash with a different settlement_id represents another
settlement and does not authorize cross-deduplication.

7. Consolidated state machine

7.1 States

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum SettlementState {
    Preparing,
    ReadyToFund,
    Confirming,
    Settling,
    Settled,
    Refunded,
}

impl SettlementState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Settled | Self::Refunded)
    }
}
```

7.2 Events and context

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EvidenceRefV1 {
    pub chain_id: ChainId,
    pub tx_id: Digest32,
    pub event_index: u32,
    pub block_height: u64,
    pub block_anchor: Digest32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum SettlementEvent {
    RefundArmed,
    FundingObserved { evidence: EvidenceRefV1 },
    FundingConfirmed { evidence: EvidenceRefV1 },
    FundingAbsent { revalidation_from: u64 },
    ClaimEvidenceVerified { evidence: EvidenceRefV1 },
    ClaimConfirmed { evidence: EvidenceRefV1 },
    TimelockExpired,
    RefundConfirmed { evidence: EvidenceRefV1 },
    ReorgInvalidated { from_height: u64, old_anchor: Digest32 },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SettlementContext {
    pub state: SettlementState,
    pub revision: u64,
    pub last_observed_height: Option<u64>,
    pub claim_evidence_verified: bool,
    pub refund_path_armed: bool,
}
```

t does not appear in these types. The event contains only a reference to a
verifiable piece of evidence. The adapter can re-obtain the public evidence
from the chain and deliver it directly to the cryptographic leg; the core
stores only the reference and the verified result.

7.3 Effects

```rust
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Effect {
    AuthorizeFunding,
    RequestClaimConsumption { evidence: EvidenceRefV1 },
    ArmRefundPath,
    RevalidateFrom { height: u64 },
    RecordTerminalOutcome(SettlementState),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transition {
    pub next: SettlementContext,
    pub effects: Vec<Effect>,
}
```

Persistence is not an optional Effect: every accepted transition is written
in a store transaction before the effects are inserted into the outbox. The
dispatcher only sees effects after the commit.

7.4 Pure transition function

```rust
pub fn transition(
    ctx: SettlementContext,
    event: &SettlementEvent,
) -> Result<Transition, TransitionError> {
    use SettlementEvent as E;
    use SettlementState as S;

    if ctx.state.is_terminal() {
        return Err(TransitionError::TerminalState);
    }

    let mut next = ctx;
    next.revision = ctx.revision.checked_add(1)
        .ok_or(TransitionError::RevisionOverflow)?;
    let mut effects = Vec::new();

    match (ctx.state, event) {
        (S::Preparing, E::RefundArmed) => {
            next.state = S::ReadyToFund;
            next.refund_path_armed = true;
            effects.push(Effect::AuthorizeFunding);
        }
        (S::ReadyToFund, E::FundingObserved { evidence }) => {
            next.state = S::Confirming;
            next.last_observed_height = Some(evidence.block_height);
        }
        (S::Confirming, E::FundingObserved { evidence }) => {
            next.last_observed_height = Some(evidence.block_height);
        }
        (S::Confirming, E::FundingAbsent { .. }) => {
            next.state = S::ReadyToFund;
            next.last_observed_height = None;
        }
        (S::Confirming, E::FundingConfirmed { evidence }) => {
            if ctx.last_observed_height != Some(evidence.block_height) {
                return Err(TransitionError::EvidenceMismatch);
            }
            next.state = S::Settling;
        }
        (S::Settling, E::ClaimEvidenceVerified { evidence }) => {
            next.claim_evidence_verified = true;
            effects.push(Effect::RequestClaimConsumption { evidence: *evidence });
        }
        (S::Settling, E::ClaimConfirmed { .. }) => {
            if !ctx.claim_evidence_verified {
                return Err(TransitionError::PreconditionUnsatisfied);
            }
            next.state = S::Settled;
            effects.push(Effect::RecordTerminalOutcome(S::Settled));
        }
        (S::Confirming | S::Settling, E::TimelockExpired) => {
            next.refund_path_armed = true;
            effects.push(Effect::ArmRefundPath);
        }
        // D-004: the chain, not the machine, proves the refund was valid.
        (S::Confirming | S::Settling, E::RefundConfirmed { .. }) => {
            next.state = S::Refunded;
            effects.push(Effect::RecordTerminalOutcome(S::Refunded));
        }
        (S::Confirming | S::Settling, E::ReorgInvalidated { from_height, .. }) => {
            let affected = ctx.last_observed_height
                .is_some_and(|h| h >= *from_height);
            if affected {
                next.state = if ctx.state == S::Settling { S::Confirming }
                             else { S::ReadyToFund };
                next.last_observed_height = None;
                next.claim_evidence_verified = false;
                effects.push(Effect::RevalidateFrom { height: *from_height });
            }
        }
        (S::Preparing | S::ReadyToFund, E::ReorgInvalidated { .. }) => {}
        _ => return Err(TransitionError::IllegalEvent),
    }

    Ok(Transition { next, effects })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TransitionError {
    #[error("illegal event")]
    IllegalEvent,
    #[error("terminal state is immutable")]
    TerminalState,
    #[error("event precondition unsatisfied")]
    PreconditionUnsatisfied,
    #[error("evidence does not match observation")]
    EvidenceMismatch,
    #[error("revision overflow")]
    RevisionOverflow,
}
```

7.5 Normative table

|State |Accepted event |Next state |Persistence |Effect after commit |Reorg |
|-------|--------------|---------------|-------------|-------------------|------|
|`Preparing` |`RefundArmed` |`ReadyToFund` |context + event |`AuthorizeFunding` |no-op |
|`ReadyToFund` |`FundingObserved` |`Confirming` |evidence ref + height |none |resumes scanning |
|`Confirming` |`FundingObserved` |`Confirming` |idempotent refresh |none |invalidates if height affected |
|`Confirming` |`FundingAbsent` |`ReadyToFund` |revalidation decision |none |already reconciled |
|`Confirming` |`FundingConfirmed` |`Settling` |confirmed evidence |none |regresses to `Confirming` |
|`Settling` |`ClaimEvidenceVerified`|`Settling` |`EvidenceRefV1` only |consume evidence on the leg|invalidates the affected proof |
|`Settling` |`ClaimConfirmed` |`Settled` |terminal via CAS |record terminal |terminal immutable after finality|
|`Confirming/Settling`|`TimelockExpired` |same state |refund armed |submit refund |revalidate chain |
|`Confirming/Settling`|`RefundConfirmed` |`Refunded` |terminal via CAS |record terminal |terminal immutable after finality|
|non-terminal |`ReorgInvalidated` |idempotent regression |anchor + cursor + context|revalidate |D-003 |
|terminal |any event |error/no-economic-effect|auditable late evidence |none |never switches terminal |

Terminals are economically mutually exclusive. A terminal row is written with
a unique index per settlement_id; an attempt to write the second terminal
fails closed.

8. Durable journal, snapshot, cursor and outbox

8.1 SQLite WAL schema

```sql
-- crates/store/migrations/0001_f2_core.sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS settlement_terms (
    settlement_id       BLOB PRIMARY KEY CHECK(length(settlement_id)=32),
    session_id          BLOB NOT NULL UNIQUE CHECK(length(session_id)=32),
    terms_hash          BLOB NOT NULL CHECK(length(terms_hash)=32),
    canonical_terms     BLOB NOT NULL,
    created_at_unix_ms  INTEGER NOT NULL,
    UNIQUE(settlement_id, terms_hash)
) STRICT;

CREATE TABLE IF NOT EXISTS settlement_snapshot (
    settlement_id       BLOB PRIMARY KEY REFERENCES settlement_terms(settlement_id),
    revision            INTEGER NOT NULL CHECK(revision >= 0),
    state_tag           INTEGER NOT NULL,
    context_bytes       BLOB NOT NULL,
    last_event_seq      INTEGER NOT NULL CHECK(last_event_seq >= 0),
    updated_at_unix_ms  INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS settlement_journal (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    seq                 INTEGER NOT NULL CHECK(seq > 0),
    expected_revision   INTEGER NOT NULL,
    resulting_revision  INTEGER NOT NULL,
    event_id            BLOB NOT NULL CHECK(length(event_id)=32),
    event_kind          INTEGER NOT NULL,
    event_bytes         BLOB NOT NULL,
    context_hash        BLOB NOT NULL CHECK(length(context_hash)=32),
    created_at_unix_ms  INTEGER NOT NULL,
    PRIMARY KEY(settlement_id, seq),
    UNIQUE(settlement_id, event_id)
) STRICT;

CREATE TABLE IF NOT EXISTS chain_cursor (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    chain_id             BLOB NOT NULL CHECK(length(chain_id)=32),
    cursor_bytes         BLOB NOT NULL,
    anchor_height        INTEGER,
    anchor_hash          BLOB CHECK(anchor_hash IS NULL OR length(anchor_hash)=32),
    revision             INTEGER NOT NULL,
    PRIMARY KEY(settlement_id, chain_id)
) STRICT;

CREATE TABLE IF NOT EXISTS observed_evidence (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    evidence_id         BLOB NOT NULL CHECK(length(evidence_id)=32),
    chain_id             BLOB NOT NULL CHECK(length(chain_id)=32),
    tx_id                BLOB NOT NULL CHECK(length(tx_id)=32),
    event_index          INTEGER NOT NULL,
    block_height         INTEGER NOT NULL,
    block_anchor         BLOB NOT NULL CHECK(length(block_anchor)=32),
    status_tag           INTEGER NOT NULL,
    first_seen_seq       INTEGER NOT NULL,
    PRIMARY KEY(settlement_id, evidence_id)
) STRICT;

CREATE TABLE IF NOT EXISTS durable_outbox (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    effect_id            BLOB NOT NULL CHECK(length(effect_id)=32),
    source_seq           INTEGER NOT NULL,
    effect_kind          INTEGER NOT NULL,
    payload_bytes        BLOB NOT NULL,
    payload_hash         BLOB NOT NULL CHECK(length(payload_hash)=32),
    status_tag           INTEGER NOT NULL,
    attempts             INTEGER NOT NULL DEFAULT 0,
    lease_until_unix_ms  INTEGER,
    completed_at_unix_ms INTEGER,
    PRIMARY KEY(settlement_id, effect_id)
) STRICT;

CREATE TABLE IF NOT EXISTS terminal_outcome (
    settlement_id       BLOB PRIMARY KEY REFERENCES settlement_terms(settlement_id),
    outcome_tag         INTEGER NOT NULL,
    source_event_id     BLOB NOT NULL CHECK(length(source_event_id)=32),
    finalized_revision  INTEGER NOT NULL,
    created_at_unix_ms  INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS late_evidence (
    settlement_id       BLOB NOT NULL REFERENCES settlement_terms(settlement_id),
    evidence_id         BLOB NOT NULL CHECK(length(evidence_id)=32),
    terminal_tag        INTEGER NOT NULL,
    observed_at_unix_ms INTEGER NOT NULL,
    PRIMARY KEY(settlement_id, evidence_id)
) STRICT;
```

The database opens with journal_mode=WAL, foreign_keys=ON and
synchronous=FULL. Migrations are versioned, idempotent, and executed before
accepting sessions.

8.2 Store contract

```rust
pub trait SettlementStore: Send + Sync {
    fn create(
        &self,
        terms: &SettlementTermsV1,
        canonical: &[u8],
        terms_hash: Digest32,
    ) -> Result<SettlementSnapshot, StoreError>;

    fn load(&self, id: SettlementId)
        -> Result<Option<SettlementSnapshot>, StoreError>;

    fn commit_transition(
        &self,
        expected_revision: u64,
        event: &EventEnvelopeV1,
        transition: &Transition,
        effects: &[OutboxEffectV1],
        cursor_update: Option<&CursorUpdateV1>,
    ) -> Result<CommitResult, StoreError>;

    fn park_evidence(&self, evidence: &VerifiedEvidenceV1)
        -> Result<ParkResult, StoreError>;

    fn ready_outbox(&self, now_ms: u64, max: u32)
        -> Result<Vec<ClaimedEffectV1>, StoreError>;

    fn complete_effect(
        &self,
        effect_id: EffectId,
        expected_payload_hash: Digest32,
    ) -> Result<(), StoreError>;
}
```

commit_transition executes a single BEGIN IMMEDIATE transaction:

1. validates event_id and deduplicates;
2. loads the snapshot and checks expected_revision;
3. appends to the journal;
4. updates the snapshot via CAS;
5. writes the evidence ref/cursor when applicable;
6. inserts effects into the outbox with deterministic IDs;
7. writes the terminal with PRIMARY KEY(settlement_id), when there is one;
8. confirms the commit;
9. only after the commit do the effects become eligible for the dispatcher.

Failure, crash or SQLITE_BUSY before the commit leaves zero visible effects.
A crash after the commit may duplicate the external attempt, but not the
bytes nor the logical effect.

9. Envelopes, idempotency and equivocation

```rust
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EventEnvelopeV1 {
    pub protocol_version: u16,
    pub settlement_id: SettlementId,
    pub session_id: SessionId,
    pub terms_hash: Digest32,
    pub source_chain: ChainId,
    pub event_id: EvidenceId,
    pub source_sequence: u64,
    pub event: SettlementEvent,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutboxEffectV1 {
    pub effect_id: EffectId,
    pub settlement_id: SettlementId,
    pub source_event_id: EvidenceId,
    pub kind: Effect,
    pub payload_hash: Digest32,
    pub payload: Vec<u8>,
}
```

Rules:

• same (settlement_id, event_id) and same bytes: idempotent ACK;
• same (settlement_id, event_id) and different bytes: terminal equivocation;
• effect_id = BLAKE2b-256("DOM-INTEROP/EFFECT/V1\0" || settlement_id || source_event_id || effect_kind || payload_hash);
• the resend reads the payload from the outbox; it never reconstructs bytes;
• the cursor only advances in the same transaction that persists all accepted
events;
• a divergent terms_hash fails before calling transition();
• an unknown version fails closed.

10. Engine algorithm

```rust
pub fn ingest_event<S: SettlementStore>(
    store: &S,
    env: EventEnvelopeV1,
) -> Result<IngestResult, EngineError> {
    let snapshot = store.load(env.settlement_id)?
        .ok_or(EngineError::UnknownSettlement)?;

    if snapshot.session_id != env.session_id || snapshot.terms_hash != env.terms_hash {
        return Err(EngineError::BindingMismatch);
    }

    if snapshot.context.state.is_terminal() {
        store.record_late_evidence(&env)?;
        return Ok(IngestResult::LateNoEconomicEffect);
    }

    match transition(snapshot.context, &env.event) {
        Ok(t) => {
            let outbox = effects_to_outbox(&env, &t.effects)?;
            match store.commit_transition(
                snapshot.context.revision,
                &env,
                &t,
                &outbox,
                cursor_from(&env),
            )? {
                CommitResult::Committed { revision } =>
                    Ok(IngestResult::Committed { revision }),
                CommitResult::DuplicateSameBytes =>
                    Ok(IngestResult::Duplicate),
            }
        }
        Err(TransitionError::IllegalEvent | TransitionError::PreconditionUnsatisfied) => {
            store.park_evidence(&verified_evidence_from(env)?)?;
            Ok(IngestResult::ParkedForReorder)
        }
        Err(e) => Err(e.into()),
    }
}
```

After any commit, the reconciler tries to reapply parked evidence in
canonical order. The order for chain events is:

```text
(block_height, tx_index, event_index, tx_id)
```

For off-chain messages, the order is (sender_id, source_sequence, message_id).
A sequence gap is never filled by assumption.

11. Reorg

The chain cursor commits to (height, block_anchor). Anchor divergence
generates ReorgInvalidated. The engine:

1. does not alter a terminal already finalized under the frozen policy;
2. invalidates evidence refs with height >= from_height;
3. regresses only the affected observation;
4. clears last_observed_height and claim_evidence_verified when necessary;
5. rewinds the cursor;
6. re-scans the chain;
7. emits FundingAbsent if the funding does not reappear;
8. accepts a new FundingObserved in Confirming as an idempotent refresh;
9. never executes the same terminal or effect twice.

Redelivery of the same ReorgInvalidated is a no-op after the first
regression, because last_observed_height has already been removed.

12. Late evidence

Evidence that arrives after Settled or Refunded is classified as
LateNoEconomicEffect. It may be recorded in late_evidence by identifier,
without bytes that reveal t, and it does not:

• reopen the settlement;
• produce compensation;
• change claim into refund or refund into claim;
• create an effect in the outbox;
• change another chain's cursor by inference.

USPE is F4. The F2 late-evidence test validates only that the core remains
terminal and emits a neutral classification; it does not implement bonds,
slash or compensation.

13. Crash recovery and failpoints

The harness injects a crash at every boundary below:

```text
C0 before BEGIN IMMEDIATE
C1 after dedupe and before reading the snapshot
C2 after the journal append
C3 after the snapshot CAS
C4 after the evidence ref/cursor insert
C5 after the outbox insert
C6 immediately before the COMMIT
C7 immediately after the COMMIT
C8 after claiming the outbox item
C9 after the external effect and before marking completed
C10 after marking completed
```

For C0–C6, the restart observes the previous state or the entire transaction,
never a prefix. For C7–C9, the dispatcher may re-present exactly the same
bytes, and the destination/idempotency key absorbs the duplication. C10 does
not re-present.

Recovery:

1. verifies migrations and SQLite integrity;
2. rejects regressive revision, journal gaps or snapshot without journal;
3. rebuilds the context from the journal and compares it with the snapshot;
4. fails closed on divergence;
5. reopens pending outbox items or expired leases;
6. revalidates cursors against anchors;
7. reapplies parked evidence;
8. continues without administrative intervention.

14. Mandatory property tests

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn terminal_is_immutable(trace in any::<Vec<ModelEvent>>()) {
        let mut model = Model::new();
        for e in trace {
            let before = model.state();
            model.apply(e);
            if before.is_terminal() {
                prop_assert_eq!(model.state(), before);
            }
        }
    }

    #[test]
    fn settled_and_refunded_never_coexist(trace in any::<Vec<ModelEvent>>()) {
        let result = execute(trace);
        prop_assert!(!(result.settled_seen && result.refunded_seen));
        prop_assert!(result.terminal_count <= 1);
    }

    #[test]
    fn funding_requires_refund_armed(trace in any::<Vec<ModelEvent>>()) {
        let result = execute(trace);
        prop_assert!(!result.funding_effect_before_refund_armed);
    }

    #[test]
    fn duplicate_trace_is_observationally_equivalent(
        trace in any::<Vec<ModelEvent>>()
    ) {
        let once = execute(trace.clone());
        let duplicated = execute(trace.into_iter().flat_map(|e| [e.clone(), e]).collect());
        prop_assert_eq!(once.economic_projection(), duplicated.economic_projection());
    }

    #[test]
    fn crash_prefix_recovery_converges(trace in any::<Vec<ModelEvent>>()) {
        let baseline = execute_durable(trace.clone(), None);
        for cut in 0..=trace.len() {
            let recovered = execute_durable(trace.clone(), Some(cut));
            prop_assert_eq!(baseline.economic_projection(), recovered.economic_projection());
        }
    }
}
```

Also mandatory:

• exhaustive search of short sequences over all states/events;
• a duplicated reorg does not regress twice;
• FundingAbsent is illegal outside Confirming;
• re-observation at the same height is an economic no-op;
• re-observation at a new height updates the idempotency key;
• RefundConfirmed without TimelockExpired is accepted;
• ClaimConfirmed without verified evidence fails;
• revision overflow fails closed;
• an event with divergent terms_hash, session or chain does not enter the
journal;
• the same bytes produce the same terms_hash in Rust and in an external
vector.

15. SettlementTermsV1 vectors

The repository must contain:

```text
fixtures/terms-v1/valid-minimal.hex
fixtures/terms-v1/valid-full.hex
fixtures/terms-v1/valid-minimal.hash
fixtures/terms-v1/valid-full.hash
fixtures/terms-v1/invalid-roster-equal.hex
fixtures/terms-v1/invalid-roster-unsorted.hex
fixtures/terms-v1/invalid-version.hex
fixtures/terms-v1/invalid-enum-tag.hex
fixtures/terms-v1/invalid-trailing-byte.hex
fixtures/terms-v1/invalid-zero-amount.hex
fixtures/terms-v1/invalid-point-prefix.hex
fixtures/terms-v1/invalid-oversize-metadata.hex
```

Each vector includes canonical bytes, terms_hash, a field-by-field
decomposition and the expected result. An independent script, without
importing kaystra-core, recomputes BLAKE2b-256 and compares the hash.

16. E2E G-F2

The f2-harness executes at least the scenarios below over dom-sim and the
real SQLite store in a temporary directory:

|ID |Scenario |Result |
|----------|----------------------------------------------|----------------------------------------|
|F2-E2E-001|refund armed → funding → confirmations → claim|`Settled` |
|F2-E2E-002|refund armed → funding → timelock → refund |`Refunded` |
|F2-E2E-003|crash C0–C10 at every transition |same terminal as the baseline |
|F2-E2E-004|duplication of every event |no duplicated effect |
|F2-E2E-005|replay after restart |idempotent ACK |
|F2-E2E-006|same event ID, different bytes |terminal equivocation |
|F2-E2E-007|claim received before funding confirmed |parked, then applied |
|F2-E2E-008|random reorder preserving the same set |same economic projection |
|F2-E2E-009|reorg of the claim before finality |not terminal; converges after re-observation|
|F2-E2E-010|deep reorg removes funding |`FundingAbsent`, re-arm and convergence |
|F2-E2E-011|duplicated reorg |second delivery is a no-op |
|F2-E2E-012|evidence after terminal |`LateNoEconomicEffect` |
|F2-E2E-013|journal corruption/gap/rollback |fail-closed recovery |
|F2-E2E-014|cursor advances without persisted event |impossible by transaction |
|F2-E2E-015|crash after external effect |byte-identical resend |
|F2-E2E-016|two threads/processes on the same revision |one wins CAS; the other reloads |
|F2-E2E-017|`terms_hash` divergence |rejection before the machine |
|F2-E2E-018|complete F1 regression |green with the real backend |

The claim tests do not persist t. To prove composition with F1, the harness
delivers the evidence reference to the dom-leg boundary, which executes
verify/extract/adapt inside the cryptographic boundary and returns only
success, failure and the public identifier of the final artifact.

17. Fuzzing and model checking

Fuzz targets:

```text
fuzz_terms_v1_decoder
fuzz_event_envelope_v1_decoder
fuzz_cursor_decoder
fuzz_journal_recovery
fuzz_reorder_convergence
```

Properties:

• no panic on arbitrary input;
• size validation before allocation;
• no trailing byte ignored;
• unknown tag/version fails closed;
• decoder(encoder(x)) = x for valid terms;
• encoder(decoder(bytes)) = bytes for canonical bytes;
• no double terminal;
• no external effect before persistence.

The model checker explores the reduced composition of states, duplication,
reorg, crash and two concurrent dispatchers. It proves at least:

```text
AG !(Settled && Refunded)
AG terminal -> AX terminal_same
AG AuthorizeFunding -> refund_armed
AG external_effect -> journal_committed
AG effect_completed_count <= 1
```

18. Security, privacy and logs

Forbidden in Debug, Display, error, tracing, telemetry, journal, database,
fixture or report:

• t;
• secret nonce;
• signing share;
• seed or private key;
• secret vault content;
• user authorization bytes.

Permitted:

• abbreviated settlement_id, session_id;
• abbreviated terms_hash;
• state/revision;
• abbreviated public evidence ID/tx ID;
• stable error codes;
• counts and latencies without sensitive material.

The secret scan covers code, test logs, temporary databases, panic output and
CI artifacts.

19. CI and adjudication commands

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features --locked
cargo test -p kaystra-core --all-features --locked
cargo test -p store --all-features --locked
cargo test -p adapter-dom-sim --all-features --locked
cargo test -p f2-harness --all-features --locked
cargo test --workspace --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --doc --workspace --all-features --locked
```

Additional:

```bash
# Real, cumulative F1
cargo test -p dom-leg --features real-dom-adaptor --locked

# Property tests with the number of cases recorded
PROPTEST_CASES=10000 cargo test -p kaystra-core --test state_properties --locked

# Model checker and fuzz smoke
cargo run -p f2-model --locked
cargo fuzz run fuzz_terms_v1_decoder -- -max_total_time=60
cargo fuzz run fuzz_event_envelope_v1_decoder -- -max_total_time=60
cargo fuzz run fuzz_journal_recovery -- -max_total_time=60
```

Grep-gates:

```bash
! rg -n 'dom_adaptor|dom-adaptor' crates/kaystra-core crates/store crates/counterparty-api
! rg -n 'admin_key|onlyOwner|guardian|pause_all|upgradeTo|founder' crates contracts/src
! rg -n '\.unwrap\(\)|\.expect\(' crates/kaystra-core crates/store --glob '*.rs' \
  | rg -v '/tests/|#\[cfg\(test\)\]'
! rg -n 'Secret\(\[u8; 32\]\)|RevealedSecretBytes.*Journal|StoreRevealedSecret' \
  crates/kaystra-core crates/store
```

Any fix applied after a failure invalidates the previous battery. The final
suite is re-run from scratch until every command finishes with exit code
zero.

20. Mandatory differences from the audited prototype

The existing F2 code is a useful reference, not final proof. Before G-F2, it
must be reconciled as follows:

|Audited prototype |Final F2 implementation |
|---------------------------------------------------|-------------------------------------------------|
|`InMemoryJournal` adjudicates crash |real SQLite WAL adjudicates durability |
|`Journal::append()` without `Result` |I/O error propagated; never pretends persistence |
|`Secret([u8;32])` in the journal |forbidden; only `EvidenceRefV1` |
|external effect executed on the same stack after append|transactional durable outbox |
|cursor in a separate record |cursor and accepted events in the same commit |
|`lock_id` and policy passed loosely |derived/validated against `SettlementTermsV1` |
|`terms_hash` placeholder `[u8;32]` |A3 frozen, codec and vectors |
|reordering partially absorbed as an anomaly |parking + deterministic retry |
|terminal only in the enum |unique terminal row + CAS |
|recovery via `Vec` replay |integrity, revision, gaps and rollback verified|
|F2 tests include USPE logic |neutral late evidence; USPE stays in F4 |

The prototype must not be discarded. state.rs, the D-003/D-004 semantics,
dom-sim, the reorg scenarios and part of the property tests must be ported,
hardened and wired to the durable store.

21. Out of scope

Do not implement in F2:

• ConditionLockV2 or Foundry (F3);
• real EVM/BTC finality (F3/F5);
• USPE bonds, slash or compensation (F4);
• BIP340/Taproot/Keystone (F5);
• RFQ, solver economics and production Relay (F6);
• real DOM node (F7);
• consensus changes;
• DOM v2 integration/merge (F8);
• DL2P, CIPHER, Lend or KaystraPay.

22. Mandatory closing report

The F2 closing records:

1. initial and final commit;
2. files created/modified;
3. final A3 implementation and the vectors' hashes;
4. state/event/effect/persistence matrix;
5. schema and migrations;
6. C0–C10 boundaries and the result of each failpoint;
7. requirement → test → result matrix;
8. counts, commands, exit codes and duration;
9. results of property tests, fuzz and model checker;
10. proof that no t was persisted;
11. proof of claim XOR refund;
12. proof of CAS and logically exactly-once outbox;
13. complete F1 regression with the real backend;
14. declaration dom-sim != real DOM;
15. declaration that F3+ was not started;
16. main branch published and remote HEAD equal to the tested HEAD;
17. clean worktree.

23. Exact G-F2 criterion

```text
G-F2 = PASS
```

only if:

• SettlementTermsV1 and terms_hash are frozen, vectored and used in all
bindings;
• the complete machine table is implemented;
• Settled and Refunded are mutually exclusive by proof and constraint;
• every state/event/cursor/outbox is durable;
• crash at every transition and boundary converges to the baseline;
• duplication and replay are idempotent;
• equivocation fails closed;
• reorder converges without applying an event prematurely;
• reorg correctly invalidates and revalidates observations;
• late evidence does not alter the terminal;
• no secret is persisted;
• the real F1 regression remains green;
• suite, lint, property tests, fuzz smoke and model checking finish green;
• report, commits, push and remote verification exist.

It is not permitted to declare G-F2 = PASS with InMemoryJournal, F1
cryptography disabled, a stub store, placeholder terms, absence of vectors,
or only unit tests of the transition() function.

24. Build order

```text
1. freeze types.rs and SettlementTermsV1
2. generate independent terms_hash vectors
3. consolidate state.rs and the normative table
4. implement the SQLite WAL schema/migrations
5. implement SettlementStore with CAS
6. implement atomic journal + cursor
7. implement the durable outbox
8. implement reorder parking/retry
9. integrate the Engine with the durable store
10. adapt dom-sim to EventEnvelopeV1
11. create failpoints C0–C10
12. run property tests and the model checker
13. run the complete E2E G-F2
14. run the F1 regression with the real backend
15. audit, document, commit, push and verify main
```

No step authorizes starting F3. Phase 2 ends at the secure, durable and
deterministic Kaystra core.

25. Final declaration of authority

This document records the operator's direct decision on 2026-08-09 that the
Phase 2 definitions discussed in the chat are closed for implementation. In
case of divergence between the prototype and this document, precedence goes
to:

1. the cryptographic authority of the pinned dom-adaptor for DOM-leg
matters;
2. the invariants of the Foundation Document;
3. this integral F2 specification;
4. the prototype code, only as historical evidence.

Any future change of encoding, hash, terminal state, idempotency,
persistence or secret boundary requires a new version of this document and
explicit recording of the superseded decision.
