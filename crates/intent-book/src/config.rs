//! Merit-privilege configuration — INTENT_BOOK_DESIGN.md,
//! "Quem tem o privilégio da fase 1 [DECIDIDO]".
//!
//! The design fixes the MECHANISM ("média de resposta na fase 1 acima do
//! limiar" as the maintenance metric, "volume mínimo executado nos últimos
//! 30 dias" as the entry-and-permanence metric) but fixes no numbers. Per
//! the operator's decision recorded for OQ-S4, the numbers are mandatory
//! configuration with NO DEFAULT: the board REFUSES to start without them.
//!
//! There is deliberately no `Default` implementation on [`MeritPolicyV1`].
//! An invented threshold is an invented economic rule.

use thiserror::Error;

/// Why a merit configuration is refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum MeritConfigError {
    /// The response-time threshold is absent.
    #[error("merit configuration is missing the phase-1 response threshold")]
    MissingResponseThreshold,
    /// The executed-volume floor is absent.
    #[error("merit configuration is missing the executed-volume floor")]
    MissingVolumeFloor,
    /// The measurement window is absent.
    #[error("merit configuration is missing the volume measurement window")]
    MissingVolumeWindow,
    /// A threshold was supplied as zero, which would make the metric vacuous.
    #[error("merit threshold is zero, which admits everyone unconditionally")]
    VacuousThreshold,
}

/// The operator-supplied merit policy. Every field is required.
///
/// The fields are private and construction goes only through
/// [`MeritPolicyV1::new`], so a partially-filled policy cannot exist.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MeritPolicyV1 {
    response_threshold_millis: u64,
    volume_floor: u128,
    volume_window_seconds: u64,
}

impl MeritPolicyV1 {
    /// Build the policy from explicit operator values.
    ///
    /// `None` in any position is a refusal, not a fallback: the board must
    /// not start on an assumed economic parameter.
    pub fn new(
        response_threshold_millis: Option<u64>,
        volume_floor: Option<u128>,
        volume_window_seconds: Option<u64>,
    ) -> Result<Self, MeritConfigError> {
        let response_threshold_millis =
            response_threshold_millis.ok_or(MeritConfigError::MissingResponseThreshold)?;
        let volume_floor = volume_floor.ok_or(MeritConfigError::MissingVolumeFloor)?;
        let volume_window_seconds =
            volume_window_seconds.ok_or(MeritConfigError::MissingVolumeWindow)?;
        if response_threshold_millis == 0 || volume_window_seconds == 0 {
            return Err(MeritConfigError::VacuousThreshold);
        }
        Ok(Self {
            response_threshold_millis,
            volume_floor,
            volume_window_seconds,
        })
    }

    /// Maintenance metric: the phase-1 mean response time a solver must
    /// stay under.
    pub fn response_threshold_millis(&self) -> u64 {
        self.response_threshold_millis
    }

    /// Entry and permanence metric: executed volume required inside the
    /// window. A floor of zero is admissible here — it means "any executed
    /// volume qualifies", which is an operator choice, not an omission.
    pub fn volume_floor(&self) -> u128 {
        self.volume_floor
    }

    /// The measurement window, in seconds. The design names 30 days; the
    /// number stays configuration so the operator ratifies it.
    pub fn volume_window_seconds(&self) -> u64 {
        self.volume_window_seconds
    }
}
