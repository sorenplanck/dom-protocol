//! Production policy for the deliberately absent generic runner path.
//!
//! Every production action is committed as an external-custody descriptor and
//! dispatched through the settlement coordinator.  This authority is still
//! installed because the generic runtime has a runner slot, but invocation is
//! an authenticated-state inconsistency rather than a temporary outage.  The
//! composition root must pair it with the RouteStore's full-history
//! `audit_external_custody_only_v1` before entering the loop.

use crate::supervisor::{
    ActionExternalizationReceiptV1, AuthorityRefusalV1, RunnerActionAuthority,
    RunnerActionRequestV1,
};

#[cfg(not(any(feature = "development", feature = "simulation", test)))]
use crate::supervisor::authority_seal;

/// Closed production runner authority.
///
/// It is not a placeholder for an unavailable implementation: the production
/// policy forbids this dispatch class. Reaching it after the startup journal
/// audit means the retained state changed inconsistently and must fail closed.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ProductionExternalCustodyOnlyRunnerV1;

#[cfg(not(any(feature = "development", feature = "simulation", test)))]
impl authority_seal::Sealed for ProductionExternalCustodyOnlyRunnerV1 {}

impl RunnerActionAuthority for ProductionExternalCustodyOnlyRunnerV1 {
    fn externalize_runner_action(
        &mut self,
        _request: RunnerActionRequestV1<'_>,
    ) -> Result<ActionExternalizationReceiptV1, AuthorityRefusalV1> {
        Err(AuthorityRefusalV1::Inconsistent)
    }
}
