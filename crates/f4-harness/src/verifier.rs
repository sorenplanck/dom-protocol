//! `RevealedScalarVerifier` — the v1 [`EvidenceVerifier`] of F4 spec §8
//! over the ratified F3 evidence path.
//!
//! The heavy lifting is NOT here (I9): `adapter-evm` decodes the
//! evidence, re-derives `binding`/`lockId` from the carried terms,
//! checks them against the configured settlement identity, and proves
//! the log against the chain up to finality. This verifier composes
//! those ratified checks with the POLICY arithmetic — which commitment
//! the scalar must open, and the evidence window — and maps the result
//! onto the frozen verdict alphabet.
//!
//! # The verdict/error split is a security boundary
//!
//! Only DETERMINISTIC disproofs become verdicts: bytes that do not
//! decode, and a static binding that does not re-derive. Those are facts
//! about the evidence alone and no retry changes them.
//!
//! Everything the CHAIN has to corroborate — the receipt, the block, the
//! ancestry to the finalized checkpoint — produces an error when it
//! fails, never a verdict. A reorg in progress, a lagging endpoint and a
//! forged transaction hash are indistinguishable at this seam, and
//! guessing in either direction loses: `Invalid` would let a reorg
//! window burn a legitimate claim into `ClaimRejected`; `Valid` would
//! accept the unproven. Undecided evidence simply retries, and evidence
//! that never becomes provable starves into `EvidenceDeadlineExpired` —
//! the conservative release, exactly where `terminal_policy` says
//! unproven claims must end. This split was forced by the Anvil reorg
//! scenario, which caught the first draft mapping corroboration failure
//! to `Invalid(Malformed)`.

use adapter_evm::binding::{adaptor_address, adaptor_address_of_scalar, is_canonical_scalar};
use adapter_evm::evidence::EvmEvidence;
use adapter_evm::rpc::{EthClient, JsonRpc};
use adapter_evm::EvmAdapterConfig;
use counterparty_api::{AdapterError, VerifiedOutcome};
use uspe::evidence::{EvidenceVerdict, EvidenceVerifier, InvalidEvidence};
use uspe::objects::{AssurancePolicyV1, TimelockSpec};

use crate::BondError;

/// The v1 verifier: one protected settlement leg on one `ConditionLockV2`
/// deployment. Constructed from the SETTLEMENT leg's adapter
/// configuration — the same identity the F3 leg runs under — so the
/// binding check of §8 item 1 is the adapter's own, not a re-derivation
/// here.
pub struct RevealedScalarVerifier<R: JsonRpc> {
    cfg: EvmAdapterConfig,
    rpc: R,
    policy_bytes: Vec<u8>,
    /// `address(T)` of the policy's adaptor commitment.
    policy_adaptor: [u8; 20],
    /// `evidence_deadline`, timestamp seconds.
    evidence_deadline: u64,
}

fn timestamp_of(spec: TimelockSpec) -> Result<u64, BondError> {
    match spec {
        TimelockSpec::TimestampSeconds { value } => Ok(value),
        _ => Err(BondError::WrongTimelockDomain),
    }
}

impl<R: JsonRpc> RevealedScalarVerifier<R> {
    /// Builds the verifier for ONE policy over the settlement leg's
    /// adapter configuration. Refuses an invalid policy, any deadline
    /// outside the timestamp domain, an invalid configuration, and a
    /// configuration whose terms hash is not the policy's obligation.
    pub fn new(
        policy: &AssurancePolicyV1,
        settlement_cfg: EvmAdapterConfig,
        rpc: R,
    ) -> Result<Self, BondError> {
        let policy_bytes = policy.canonical_bytes()?;
        let evidence_deadline = timestamp_of(policy.evidence_deadline)?;
        let uspe::objects::EvidenceRuleV1::RevealedScalarClaim { adaptor_point } =
            &policy.evidence_rule;
        let policy_adaptor = adaptor_address(&adaptor_point.0)?;
        // The settlement configuration must be the POLICY's obligation:
        // a verifier bound to one terms hash while judging another would
        // be exactly the confusion §5.2 binding exists to prevent.
        if settlement_cfg.terms_hash != policy.terms_hash {
            return Err(BondError::PolicyMismatch);
        }
        settlement_cfg.validate()?;
        Ok(Self {
            cfg: settlement_cfg,
            rpc,
            policy_bytes,
            policy_adaptor,
            evidence_deadline,
        })
    }
}

impl<R: JsonRpc> EvidenceVerifier for RevealedScalarVerifier<R> {
    type Error = BondError;

    fn verify(
        &self,
        policy: &AssurancePolicyV1,
        raw_evidence: &[u8],
        now: TimelockSpec,
    ) -> Result<EvidenceVerdict, BondError> {
        // Single definition: the policy judged must be the policy
        // configured, byte for byte.
        if policy.canonical_bytes()? != self.policy_bytes {
            return Err(BondError::PolicyMismatch);
        }
        let now = timestamp_of(now)?;

        // §8 item 4 first — it needs no chain round trip. Stricter than
        // claim-time on purpose: verification concluding late refuses,
        // which fails toward the conservative release, never toward a
        // late slash.
        if now > self.evidence_deadline {
            return Ok(EvidenceVerdict::Invalid(
                InvalidEvidence::OutsideEvidenceWindow,
            ));
        }

        // DETERMINISTIC half: decode, then the static re-derivation of
        // binding and lock id against the configured settlement identity
        // (adapter code, not a re-implementation — I9). Failures here are
        // facts about the bytes and become verdicts.
        let evidence = match EvmEvidence::decode(raw_evidence) {
            Ok(evidence) => evidence,
            Err(_) => return Ok(EvidenceVerdict::Invalid(InvalidEvidence::Malformed)),
        };
        let outcome = match evidence.verify_static(&self.cfg) {
            Ok(outcome) => outcome,
            Err(AdapterError::EvidenceInvalid) => {
                return Ok(EvidenceVerdict::Invalid(InvalidEvidence::NotABoundClaim));
            }
            Err(other) => return Err(BondError::Adapter(other)),
        };

        // ENVIRONMENT-DEPENDENT half: the deployment preflight (right
        // chain, right bytecode) and the on-chain corroboration up to the
        // finalized checkpoint. ANY failure here — reorg, lagging
        // endpoint, absent receipt — is undecidable: an error, never a
        // verdict. See the module docs for why this is load-bearing.
        let client = EthClient::new(&self.rpc);
        if client.chain_id().map_err(BondError::Adapter)? != self.cfg.chain_id
            || client
                .code_hash(&self.cfg.contract)
                .map_err(BondError::Adapter)?
                != self.cfg.expected_code_hash
        {
            return Err(BondError::Adapter(AdapterError::PreconditionUnsatisfied));
        }
        evidence
            .verify_onchain(&self.rpc, &self.cfg)
            .map_err(BondError::Adapter)?;

        let (revealed, claim_height) = match outcome {
            VerifiedOutcome::Claimed { revealed, height } => (revealed, height),
            // A funding or refund of the bound leg is real evidence of
            // SOMETHING — just not of the failure this rule proves.
            VerifiedOutcome::Funded { .. } | VerifiedOutcome::Refunded { .. } => {
                return Ok(EvidenceVerdict::Invalid(InvalidEvidence::NotABoundClaim));
            }
        };

        // §8 item 3: the policy arithmetic. The adapter proved "a claim
        // of the bound leg revealed these bytes"; the policy asks "and
        // do these bytes open THIS obligation's commitment?".
        // One exposure point for both checks; `revealed` itself is moved on
        // into the verdict below, so this reads it rather than consuming it.
        let scalar = revealed.expose_scalar_bytes();
        if !is_canonical_scalar(&scalar) {
            return Ok(EvidenceVerdict::Invalid(
                InvalidEvidence::NonCanonicalScalar,
            ));
        }
        if adaptor_address_of_scalar(&scalar)? != self.policy_adaptor {
            return Ok(EvidenceVerdict::Invalid(InvalidEvidence::WrongScalarPoint));
        }

        Ok(EvidenceVerdict::Valid {
            revealed,
            claim_height,
        })
    }
}
