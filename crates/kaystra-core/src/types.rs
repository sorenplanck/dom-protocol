//! Fundamental public types of the F2 core (spec §5, DECIDED).
//!
//! Everything here is PUBLIC data: 32-byte public identifiers, leg terms,
//! policies. No secret material (t, nonces, shares, seeds) ever enters this
//! module — see spec §18. Monetary values are integers in the smallest
//! native unit; floats are forbidden. Asset and chain identifiers are
//! 32-byte registry entries defined by a versioned profile; ticker strings
//! never act as authority.

use core::fmt;

/// 32-byte digest (BLAKE2b-256 output and 32-byte registry entries).
pub type Digest32 = [u8; 32];

/// Declares a 32-byte public identifier newtype with an abbreviated,
/// non-exhaustive `Debug` (first two bytes only) so full identifiers never
/// flood logs by accident. These are PUBLIC identifiers — the truncation is
/// log hygiene, not secrecy.
macro_rules! public_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
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

public_id!(
    /// One-shot public settlement identifier (random 32 bytes, spec §6.3).
    SettlementId
);
public_id!(
    /// One-shot public signing-session identifier (random 32 bytes).
    SessionId
);
public_id!(
    /// Hash of the user intent this settlement executes.
    IntentHash
);
public_id!(
    /// Public identifier of the solver that composed the settlement.
    SolverId
);
public_id!(
    /// Public identifier of a roster participant.
    ParticipantId
);
public_id!(
    /// 32-byte chain registry identifier (versioned profile, not a ticker).
    ChainId
);
public_id!(
    /// 32-byte asset registry identifier (versioned profile, not a ticker).
    AssetId
);
public_id!(
    /// Public identifier of one observed piece of on-chain evidence.
    EvidenceId
);
public_id!(
    /// Deterministic public identifier of one outbox effect.
    EffectId
);

/// Which side of the swap a leg is on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LegRole {
    /// The DOM leg (scriptless 2-of-2 via the pinned adaptor crate).
    Dom = 0x01,
    /// The counterparty leg (EVM/BTC/other, behind an adapter).
    Counterparty = 0x02,
}

/// Locking mechanism securing a leg.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockMechanism {
    /// DOM scriptless 2-of-2 with adaptor signatures (F1 boundary).
    DomAdaptor2of2 = 0x01,
    /// EVM ConditionLock contract (ecrecover trick on t·G).
    ConditionLock = 0x02,
    /// Plain Schnorr adaptor on a chain that verifies Schnorr natively.
    SchnorrAdaptor = 0x03,
    /// Hashlock fallback for chains without adaptor support.
    HashlockFallback = 0x04,
    /// Shared spend key on a curve the DOM leg does not use, opened by a
    /// same-witness cross-curve DLEQ proof. Monero is the first chain that
    /// needs it: its spend authority is an ed25519 scalar, so the leg is not
    /// a Schnorr adaptor on the DOM curve and must not be labelled as one.
    CrossCurveSharedSpend = 0x05,
    /// Discrete-log condition lock verified on a curve the DOM leg does not
    /// use, opened by the same-witness cross-curve DLEQ proof. Solana is the
    /// first chain that needs it: the escrow program checks
    /// `s * G_ed25519 == P` through the curve25519 syscall, so the leg is
    /// neither the same-curve EVM `ConditionLock` (ecrecover on t*G, no DLEQ
    /// involved) nor a shared spend key, and must not be labelled as either.
    CrossCurveConditionLock = 0x06,
}

/// Refund-timelock specification for one leg.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimelockSpec {
    /// Absolute block height.
    BlockHeight {
        /// The height at which the refund path becomes spendable.
        value: u64,
    },
    /// Absolute UNIX timestamp in seconds.
    TimestampSeconds {
        /// The timestamp at which the refund path becomes spendable.
        value: u64,
    },
    /// BTC relative time in 512-second units (BIP-68 style).
    BtcTime512s {
        /// The number of 512-second units.
        value: u64,
    },
}

/// Finality policy the engine enforces before trusting an observation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FinalityPolicyV1 {
    /// Confirmations required before an observation is final (must be > 0).
    pub min_confirmations: u32,
    /// Deepest reorg the policy tolerates (must be >= min_confirmations).
    pub max_reorg_depth: u32,
}

/// Frozen terms of one settlement leg.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LegTermsV1 {
    /// Which side of the swap this leg is.
    pub role: LegRole,
    /// Chain registry identifier.
    pub chain_id: ChainId,
    /// Asset registry identifier.
    pub asset_id: AssetId,
    /// Amount in the smallest native unit (must be > 0).
    pub amount: u128,
    /// Participant that receives the claim path.
    pub beneficiary: ParticipantId,
    /// Participant that receives the refund path.
    pub refund_to: ParticipantId,
    /// Locking mechanism securing this leg.
    pub mechanism: LockMechanism,
    /// Refund-timelock deadline.
    pub deadline: TimelockSpec,
    /// Finality policy for observations of this leg.
    pub finality: FinalityPolicyV1,
    /// Hash of the versioned adapter profile that interprets this leg.
    pub adapter_profile_hash: Digest32,
}

/// Upper fee bounds both parties accepted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FeeLimitV1 {
    /// Maximum fee on the DOM leg, smallest native unit.
    pub dom_max: u128,
    /// Maximum fee on the counterparty leg, smallest native unit.
    pub counterparty_max: u128,
}

/// Recovery policy frozen into the terms.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RecoveryPolicyV1 {
    /// The refund path MUST be armed before any funding effect (spec §7).
    pub refund_before_funding: bool,
    /// How many blocks observed evidence is retained after terminal.
    pub evidence_retention_blocks: u64,
}
