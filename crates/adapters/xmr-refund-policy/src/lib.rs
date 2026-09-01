//! Explicit pre-funding policy for the XMR refund path.
//!
//! The claim path alone is not an atomic swap. Before XMR funding, a route
//! must either be explicitly laboratory/cooperative or present a concrete,
//! profile-bound non-cooperative refund executor. No production mode silently
//! falls back to cooperation.

#![forbid(unsafe_code)]

use kaystra_core::terms::{SettlementTermsV1, TermsError};
use sha2::{Digest, Sha256};
use xmr_setup_profile::XmrNetwork;

const REFUND_POLICY_DOMAIN: &[u8] = b"DOM-INTEROP/XMR-REFUND-POLICY/V1\0";

/// Refund mode frozen before funding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum XmrRefundModeV1 {
    /// Laboratory-only: both share holders may need to cooperate.
    CooperativeLaboratory = 1,
    /// Production-shaped: a separate adaptor/refund executor is mandatory.
    AdaptorRefundRequired = 2,
}

/// Public artifact consumed by a non-cooperative refund executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XmrRefundArtifactV1 {
    /// Digest of the exact refund transaction/template.
    pub template_hash: [u8; 32],
    /// Public adaptor/refund point used by the executor.
    pub adaptor_point_sec1: [u8; 33],
    /// Executor implementation/profile hash.
    pub executor_profile_hash: [u8; 32],
    /// Frozen absolute route deadline.
    pub deadline: u64,
}

/// Capability supplied by an actual refund implementation.
pub trait NonCooperativeRefundCapability: Send + Sync {
    /// Stable hash of the implementation/profile.
    fn profile_hash(&self) -> [u8; 32];
    /// Validates that the public artifact is executable by this implementation.
    fn validate_artifact(&self, artifact: &XmrRefundArtifactV1) -> Result<(), RefundPolicyError>;
}

/// Explicit opt-in token for non-mainnet cooperative laboratories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaboratoryRefundAdmission {
    /// Caller accepts that the refund path is cooperative and non-production.
    Explicit,
}

/// Validated pre-funding token. Fields are private to prevent fabrication.
pub struct ValidatedRefundPolicy {
    mode: XmrRefundModeV1,
    policy_hash: [u8; 32],
    production_capable: bool,
}

impl core::fmt::Debug for ValidatedRefundPolicy {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ValidatedRefundPolicy")
            .field("mode", &self.mode)
            .field("production_capable", &self.production_capable)
            .finish_non_exhaustive()
    }
}

impl ValidatedRefundPolicy {
    /// Frozen mode.
    #[must_use]
    pub const fn mode(&self) -> XmrRefundModeV1 {
        self.mode
    }

    /// Domain-separated policy digest.
    #[must_use]
    pub const fn policy_hash(&self) -> [u8; 32] {
        self.policy_hash
    }

    /// True only when an actual matching executor validated the artifact.
    #[must_use]
    pub const fn production_capable(&self) -> bool {
        self.production_capable
    }

    /// Pre-funding gate used by session initialization.
    pub fn require_pre_funding(&self) -> Result<(), RefundPolicyError> {
        if self.policy_hash == [0; 32] {
            Err(RefundPolicyError::InvalidArtifact)
        } else {
            Ok(())
        }
    }
}

/// Refund-policy validation failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefundPolicyError {
    /// Frozen Kaystra terms are invalid.
    #[error("invalid Kaystra terms: {0}")]
    Terms(#[from] TermsError),
    /// Refund-before-funding is not frozen into the settlement.
    #[error("refund-before-funding is required")]
    RefundBeforeFundingRequired,
    /// Cooperative mode was not explicitly admitted.
    #[error("cooperative XMR refund requires explicit laboratory admission")]
    LaboratoryAdmissionRequired,
    /// Cooperative mode is forbidden on mainnet.
    #[error("cooperative XMR refund is forbidden on mainnet")]
    CooperativeMainnetForbidden,
    /// Production mode has no concrete executor.
    #[error("non-cooperative XMR refund executor is required")]
    ExecutorRequired,
    /// Executor/profile does not match the frozen artifact.
    #[error("XMR refund executor profile mismatch")]
    ExecutorProfileMismatch,
    /// Artifact is zero, malformed or non-canonical.
    #[error("invalid XMR refund artifact")]
    InvalidArtifact,
    /// Concrete executor rejected the artifact.
    #[error("XMR refund artifact is not executable")]
    ArtifactNotExecutable,
}

/// Validates refund readiness before any funding authorization.
pub fn admit_refund_policy(
    terms: &SettlementTermsV1,
    network: XmrNetwork,
    mode: XmrRefundModeV1,
    artifact: Option<XmrRefundArtifactV1>,
    laboratory_admission: Option<LaboratoryRefundAdmission>,
    executor: Option<&dyn NonCooperativeRefundCapability>,
) -> Result<ValidatedRefundPolicy, RefundPolicyError> {
    terms.validate()?;
    if !terms.recovery.refund_before_funding {
        return Err(RefundPolicyError::RefundBeforeFundingRequired);
    }

    match mode {
        XmrRefundModeV1::CooperativeLaboratory => {
            if network == XmrNetwork::Mainnet {
                return Err(RefundPolicyError::CooperativeMainnetForbidden);
            }
            if laboratory_admission != Some(LaboratoryRefundAdmission::Explicit) {
                return Err(RefundPolicyError::LaboratoryAdmissionRequired);
            }
            Ok(ValidatedRefundPolicy {
                mode,
                policy_hash: policy_hash(mode, terms, None),
                production_capable: false,
            })
        }
        XmrRefundModeV1::AdaptorRefundRequired => {
            let artifact = artifact.ok_or(RefundPolicyError::InvalidArtifact)?;
            validate_artifact_shape(&artifact)?;
            let executor = executor.ok_or(RefundPolicyError::ExecutorRequired)?;
            if executor.profile_hash() != artifact.executor_profile_hash {
                return Err(RefundPolicyError::ExecutorProfileMismatch);
            }
            executor
                .validate_artifact(&artifact)
                .map_err(|_| RefundPolicyError::ArtifactNotExecutable)?;
            Ok(ValidatedRefundPolicy {
                mode,
                policy_hash: policy_hash(mode, terms, Some(&artifact)),
                production_capable: true,
            })
        }
    }
}

fn validate_artifact_shape(artifact: &XmrRefundArtifactV1) -> Result<(), RefundPolicyError> {
    if artifact.template_hash == [0; 32]
        || artifact.executor_profile_hash == [0; 32]
        || artifact.deadline == 0
        || !matches!(artifact.adaptor_point_sec1[0], 0x02 | 0x03)
        || artifact.adaptor_point_sec1[1..]
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(RefundPolicyError::InvalidArtifact);
    }
    Ok(())
}

fn policy_hash(
    mode: XmrRefundModeV1,
    terms: &SettlementTermsV1,
    artifact: Option<&XmrRefundArtifactV1>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(REFUND_POLICY_DOMAIN);
    hasher.update([mode as u8]);
    hasher.update(terms.settlement_id.0);
    hasher.update(terms.session_id.0);
    hasher.update(terms.adaptor_point_sec1);
    if let Some(artifact) = artifact {
        hasher.update(artifact.template_hash);
        hasher.update(artifact.adaptor_point_sec1);
        hasher.update(artifact.executor_profile_hash);
        hasher.update(artifact.deadline.to_be_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaystra_core::types::*;

    struct MockExecutor;

    impl NonCooperativeRefundCapability for MockExecutor {
        fn profile_hash(&self) -> [u8; 32] {
            [0x33; 32]
        }

        fn validate_artifact(
            &self,
            _artifact: &XmrRefundArtifactV1,
        ) -> Result<(), RefundPolicyError> {
            Ok(())
        }
    }

    fn terms() -> SettlementTermsV1 {
        let participant_a = ParticipantId([1; 32]);
        let participant_b = ParticipantId([2; 32]);
        let leg = |role, chain: u8| LegTermsV1 {
            role,
            chain_id: ChainId([chain; 32]),
            asset_id: AssetId([chain.wrapping_add(1); 32]),
            amount: 100,
            beneficiary: participant_a,
            refund_to: participant_b,
            mechanism: if role == LegRole::Dom {
                LockMechanism::DomAdaptor2of2
            } else {
                LockMechanism::SchnorrAdaptor
            },
            deadline: TimelockSpec::BlockHeight { value: 100 },
            finality: FinalityPolicyV1 {
                min_confirmations: 1,
                max_reorg_depth: 2,
            },
            adapter_profile_hash: [chain.wrapping_add(2); 32],
        };
        SettlementTermsV1 {
            settlement_id: SettlementId([4; 32]),
            session_id: SessionId([5; 32]),
            intent_hash: IntentHash([6; 32]),
            solver_id: SolverId([7; 32]),
            roster: [participant_a, participant_b],
            dom_leg: leg(LegRole::Dom, 8),
            counterparty_leg: leg(LegRole::Counterparty, 9),
            adaptor_point_sec1: {
                let mut point = [1; 33];
                point[0] = 2;
                point
            },
            fee_limit: FeeLimitV1 {
                dom_max: 10,
                counterparty_max: 10,
            },
            recovery: RecoveryPolicyV1 {
                refund_before_funding: true,
                evidence_retention_blocks: 100,
            },
            assurance_policy_hash: None,
            policy_version: 1,
            metadata: vec![],
        }
    }

    #[test]
    fn cooperative_mode_is_explicit_and_never_mainnet() {
        assert!(admit_refund_policy(
            &terms(),
            XmrNetwork::Stagenet,
            XmrRefundModeV1::CooperativeLaboratory,
            None,
            Some(LaboratoryRefundAdmission::Explicit),
            None,
        )
        .is_ok());
        assert!(matches!(
            admit_refund_policy(
                &terms(),
                XmrNetwork::Mainnet,
                XmrRefundModeV1::CooperativeLaboratory,
                None,
                Some(LaboratoryRefundAdmission::Explicit),
                None,
            ),
            Err(RefundPolicyError::CooperativeMainnetForbidden),
        ));
    }

    #[test]
    fn production_mode_requires_matching_concrete_executor() {
        let mut point = [2; 33];
        point[0] = 2;
        let artifact = XmrRefundArtifactV1 {
            template_hash: [0x22; 32],
            adaptor_point_sec1: point,
            executor_profile_hash: [0x33; 32],
            deadline: 500,
        };
        assert!(matches!(
            admit_refund_policy(
                &terms(),
                XmrNetwork::Mainnet,
                XmrRefundModeV1::AdaptorRefundRequired,
                Some(artifact),
                None,
                None,
            ),
            Err(RefundPolicyError::ExecutorRequired),
        ));
        let admitted = admit_refund_policy(
            &terms(),
            XmrNetwork::Mainnet,
            XmrRefundModeV1::AdaptorRefundRequired,
            Some(artifact),
            None,
            Some(&MockExecutor),
        )
        .expect("matching executor");
        assert!(admitted.production_capable());
    }
    #[test]
    fn a_cooperative_laboratory_policy_is_never_production_capable() {
        let policy = admit_refund_policy(
            &terms(),
            XmrNetwork::Stagenet,
            XmrRefundModeV1::CooperativeLaboratory,
            None,
            Some(LaboratoryRefundAdmission::Explicit),
            None,
        )
        .expect("laboratory admission");
        // This is the exact property attach_xmr_consumer relies on: a
        // laboratory route can be admitted for setup but must never present as
        // production-capable, so the claim-to-sweep consumer refuses it.
        assert!(!policy.production_capable());
    }

    #[test]
    fn cooperative_mode_without_explicit_admission_is_refused() {
        assert!(matches!(
            admit_refund_policy(
                &terms(),
                XmrNetwork::Stagenet,
                XmrRefundModeV1::CooperativeLaboratory,
                None,
                None,
                None,
            ),
            Err(RefundPolicyError::LaboratoryAdmissionRequired),
        ));
    }

    #[test]
    fn an_executor_whose_profile_differs_from_the_artifact_is_refused() {
        struct WrongProfileExecutor;
        impl NonCooperativeRefundCapability for WrongProfileExecutor {
            fn profile_hash(&self) -> [u8; 32] {
                [0x44; 32]
            }
            fn validate_artifact(
                &self,
                _artifact: &XmrRefundArtifactV1,
            ) -> Result<(), RefundPolicyError> {
                Ok(())
            }
        }
        let mut point = [2; 33];
        point[0] = 2;
        let artifact = XmrRefundArtifactV1 {
            template_hash: [0x22; 32],
            adaptor_point_sec1: point,
            executor_profile_hash: [0x33; 32],
            deadline: 500,
        };
        assert!(matches!(
            admit_refund_policy(
                &terms(),
                XmrNetwork::Mainnet,
                XmrRefundModeV1::AdaptorRefundRequired,
                Some(artifact),
                None,
                Some(&WrongProfileExecutor),
            ),
            Err(RefundPolicyError::ExecutorProfileMismatch),
        ));
    }

    #[test]
    fn a_malformed_refund_artifact_is_refused() {
        let zero_point_artifact = XmrRefundArtifactV1 {
            template_hash: [0x22; 32],
            adaptor_point_sec1: [0; 33],
            executor_profile_hash: [0x33; 32],
            deadline: 500,
        };
        assert!(matches!(
            admit_refund_policy(
                &terms(),
                XmrNetwork::Mainnet,
                XmrRefundModeV1::AdaptorRefundRequired,
                Some(zero_point_artifact),
                None,
                Some(&MockExecutor),
            ),
            Err(RefundPolicyError::InvalidArtifact),
        ));
    }
}
