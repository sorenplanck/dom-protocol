//! Strict bounded codec and domain-separated commitments.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

use crate::model::{
    ChildExposureV1, CompositeSettlementPlanV1, DeferredSettlementChildV1, Digest32,
    SecretRequirementV1, SettlementActionV1, SettlementChildPlanV1, SettlementChildrenV1,
    SettlementFaceV1, SettlementLegV1, SettlementPlanBindingsV1, MAX_SETTLEMENT_CHILDREN_V1,
};
use crate::{CoordinatorErrorV1, Result};

const PLAN_MAGIC_V2: &[u8; 4] = b"SCP2";
const PLAN_VERSION_V2: u16 = 2;
const MATERIALIZED_PLAN_ENCODED_LEN_V2: usize = 632;
const STAGED_PLAN_ENCODED_LEN_V2: usize = 696;

/// Canonical codec implemented by the strict settlement plan.
pub trait CanonicalSettlementPlanV1: Sized {
    /// Encode the exact bounded V2 representation.
    fn encode_canonical(&self) -> Result<Vec<u8>>;

    /// Decode an exact V2 representation and reject trailing bytes, unknown
    /// discriminants and invalid plan semantics.
    fn decode_canonical(bytes: &[u8]) -> Result<Self>;

    /// Domain-separated digest of the exact canonical plan version.
    fn canonical_digest(&self) -> Result<Digest32>;
}

impl CanonicalSettlementPlanV1 for CompositeSettlementPlanV1 {
    fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bindings = self.bindings();
        let mut output = Vec::with_capacity(STAGED_PLAN_ENCODED_LEN_V2);
        output.extend_from_slice(PLAN_MAGIC_V2);
        output.extend_from_slice(&PLAN_VERSION_V2.to_be_bytes());
        encode_bindings(&mut output, bindings);
        output.push(self.secret_requirement().tag());
        encode_optional_digest(&mut output, self.preexisting_secret_evidence_digest());
        output.push(
            u8::try_from(MAX_SETTLEMENT_CHILDREN_V1)
                .map_err(|_| CoordinatorErrorV1::InvalidCanonicalMaterial)?,
        );
        match self.child_layout() {
            SettlementChildrenV1::Materialized(children) => {
                output.push(1);
                for child in children {
                    encode_child(&mut output, child);
                }
                if output.len() != MATERIALIZED_PLAN_ENCODED_LEN_V2 {
                    return Err(CoordinatorErrorV1::InvalidCanonicalMaterial);
                }
            }
            SettlementChildrenV1::FirstExposureStaged { first, deferred } => {
                output.push(2);
                encode_child(&mut output, first);
                encode_deferred_child(&mut output, deferred);
                if output.len() != STAGED_PLAN_ENCODED_LEN_V2 {
                    return Err(CoordinatorErrorV1::InvalidCanonicalMaterial);
                }
            }
        }
        Ok(output)
    }

    fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if !matches!(
            bytes.len(),
            MATERIALIZED_PLAN_ENCODED_LEN_V2 | STAGED_PLAN_ENCODED_LEN_V2
        ) {
            return Err(CoordinatorErrorV1::InvalidCanonicalMaterial);
        }
        let mut reader = Reader::new(bytes);
        if reader.take::<4>()? != *PLAN_MAGIC_V2
            || u16::from_be_bytes(reader.take::<2>()?) != PLAN_VERSION_V2
        {
            return Err(CoordinatorErrorV1::InvalidCanonicalMaterial);
        }
        let bindings = decode_bindings(&mut reader)?;
        let secret_requirement = SecretRequirementV1::from_tag(reader.byte()?)?;
        let preexisting_secret_evidence_digest = decode_optional_digest(&mut reader)?;
        if usize::from(reader.byte()?) != MAX_SETTLEMENT_CHILDREN_V1 {
            return Err(CoordinatorErrorV1::InvalidCanonicalMaterial);
        }
        let child_layout = reader.byte()?;
        let first = decode_child(&mut reader)?;
        let plan = match child_layout {
            1 if bytes.len() == MATERIALIZED_PLAN_ENCODED_LEN_V2 => CompositeSettlementPlanV1::new(
                bindings,
                secret_requirement,
                preexisting_secret_evidence_digest,
                [first, decode_child(&mut reader)?],
            )?,
            2 if bytes.len() == STAGED_PLAN_ENCODED_LEN_V2
                && secret_requirement == SecretRequirementV1::FirstExposureRequired
                && preexisting_secret_evidence_digest.is_none() =>
            {
                CompositeSettlementPlanV1::new_first_exposure_staged(
                    bindings,
                    first,
                    decode_deferred_child(&mut reader)?,
                )?
            }
            _ => return Err(CoordinatorErrorV1::InvalidCanonicalMaterial),
        };
        if !reader.is_empty() {
            return Err(CoordinatorErrorV1::InvalidCanonicalMaterial);
        }
        Ok(plan)
    }

    fn canonical_digest(&self) -> Result<Digest32> {
        Ok(domain_digest_v1(
            b"DOM-INTEROP/SETTLEMENT-COORDINATOR/PLAN/V2\0",
            &[&self.encode_canonical()?],
        ))
    }
}

pub(crate) fn stable_plan_id(plan: &CompositeSettlementPlanV1) -> Result<Digest32> {
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/STABLE-PLAN/V1\0",
        &[&stable_plan_bytes(plan)?],
    ))
}

pub(crate) fn aggregate_action_id(plan: &CompositeSettlementPlanV1) -> Result<Digest32> {
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/AGGREGATE-ACTION/V1\0",
        &[&stable_plan_bytes(plan)?],
    ))
}

pub(crate) fn aggregate_custody_digest(plan: &CompositeSettlementPlanV1) -> Result<Digest32> {
    let child_commitments = match plan.child_layout() {
        SettlementChildrenV1::Materialized(children) => {
            [children[0].custody_digest, children[1].custody_digest]
        }
        SettlementChildrenV1::FirstExposureStaged { first, deferred } => {
            [first.custody_digest, deferred_child_digest(deferred)]
        }
    };
    Ok(domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/AGGREGATE-CUSTODY/V1\0",
        &[
            &stable_plan_bytes(plan)?,
            &child_commitments[0],
            &child_commitments[1],
        ],
    ))
}

pub(crate) fn stable_plan_equivalent(
    left: &CompositeSettlementPlanV1,
    right: &CompositeSettlementPlanV1,
) -> Result<bool> {
    Ok(stable_plan_bytes(left)? == stable_plan_bytes(right)?)
}

fn stable_plan_bytes(plan: &CompositeSettlementPlanV1) -> Result<Vec<u8>> {
    plan.validate()?;
    let bindings = plan.bindings();
    let mut output = Vec::with_capacity(600);
    output.extend_from_slice(&bindings.route_id);
    output.extend_from_slice(&bindings.settlement_id);
    output.push(bindings.leg.tag());
    output.push(bindings.action.tag());
    output.extend_from_slice(&bindings.semantic_digest);
    output.extend_from_slice(&bindings.terms_digest);
    output.extend_from_slice(&bindings.registry_digest);
    output.extend_from_slice(&bindings.dom_profile_digest);
    output.extend_from_slice(&bindings.dom_deployment_digest);
    output.extend_from_slice(&bindings.counterparty_profile_digest);
    output.extend_from_slice(&bindings.counterparty_deployment_digest);
    output.push(plan.secret_requirement().tag());
    encode_optional_digest(&mut output, plan.preexisting_secret_evidence_digest());
    output.push(
        u8::try_from(MAX_SETTLEMENT_CHILDREN_V1)
            .map_err(|_| CoordinatorErrorV1::InvalidCanonicalMaterial)?,
    );
    match plan.child_layout() {
        SettlementChildrenV1::Materialized(children) => {
            output.push(1);
            for child in children {
                encode_child(&mut output, child);
            }
        }
        SettlementChildrenV1::FirstExposureStaged { first, deferred } => {
            output.push(2);
            encode_child(&mut output, first);
            encode_deferred_child(&mut output, deferred);
        }
    }
    Ok(output)
}

fn encode_bindings(output: &mut Vec<u8>, value: &SettlementPlanBindingsV1) {
    output.extend_from_slice(&value.route_id);
    output.extend_from_slice(&value.effect_id);
    output.extend_from_slice(&value.settlement_id);
    output.push(value.leg.tag());
    output.push(value.action.tag());
    output.extend_from_slice(&value.fencing_epoch.to_be_bytes());
    output.extend_from_slice(&value.semantic_digest);
    output.extend_from_slice(&value.terms_digest);
    output.extend_from_slice(&value.registry_digest);
    output.extend_from_slice(&value.dom_profile_digest);
    output.extend_from_slice(&value.dom_deployment_digest);
    output.extend_from_slice(&value.counterparty_profile_digest);
    output.extend_from_slice(&value.counterparty_deployment_digest);
}

fn decode_bindings(reader: &mut Reader<'_>) -> Result<SettlementPlanBindingsV1> {
    Ok(SettlementPlanBindingsV1 {
        route_id: reader.take::<32>()?,
        effect_id: reader.take::<32>()?,
        settlement_id: reader.take::<32>()?,
        leg: SettlementLegV1::from_tag(reader.byte()?)?,
        action: SettlementActionV1::from_tag(reader.byte()?)?,
        fencing_epoch: u64::from_be_bytes(reader.take::<8>()?),
        semantic_digest: reader.take::<32>()?,
        terms_digest: reader.take::<32>()?,
        registry_digest: reader.take::<32>()?,
        dom_profile_digest: reader.take::<32>()?,
        dom_deployment_digest: reader.take::<32>()?,
        counterparty_profile_digest: reader.take::<32>()?,
        counterparty_deployment_digest: reader.take::<32>()?,
    })
}

fn encode_child(output: &mut Vec<u8>, value: &SettlementChildPlanV1) {
    output.push(value.face.tag());
    output.push(value.exposure.tag());
    output.extend_from_slice(&value.chain_id);
    output.extend_from_slice(&value.expected_transaction_id);
    output.extend_from_slice(&value.intent_digest);
    output.extend_from_slice(&value.custody_digest);
}

fn decode_child(reader: &mut Reader<'_>) -> Result<SettlementChildPlanV1> {
    Ok(SettlementChildPlanV1 {
        face: SettlementFaceV1::from_tag(reader.byte()?)?,
        exposure: ChildExposureV1::from_tag(reader.byte()?)?,
        chain_id: reader.take::<32>()?,
        expected_transaction_id: reader.take::<32>()?,
        intent_digest: reader.take::<32>()?,
        custody_digest: reader.take::<32>()?,
    })
}

fn encode_deferred_child(output: &mut Vec<u8>, value: &DeferredSettlementChildV1) {
    output.push(value.face.tag());
    output.push(ChildExposureV1::UsesPublicSecret.tag());
    output.extend_from_slice(&value.chain_id);
    output.extend_from_slice(&value.route_scope_digest);
    output.extend_from_slice(&value.composition_digest);
    output.extend_from_slice(&value.role_plan_digest);
    output.extend_from_slice(&value.source_scope_digest);
    output.extend_from_slice(&value.materializer_authority_id);
}

fn decode_deferred_child(reader: &mut Reader<'_>) -> Result<DeferredSettlementChildV1> {
    let face = SettlementFaceV1::from_tag(reader.byte()?)?;
    if ChildExposureV1::from_tag(reader.byte()?)? != ChildExposureV1::UsesPublicSecret {
        return Err(CoordinatorErrorV1::InvalidCanonicalMaterial);
    }
    Ok(DeferredSettlementChildV1 {
        face,
        chain_id: reader.take::<32>()?,
        route_scope_digest: reader.take::<32>()?,
        composition_digest: reader.take::<32>()?,
        role_plan_digest: reader.take::<32>()?,
        source_scope_digest: reader.take::<32>()?,
        materializer_authority_id: reader.take::<32>()?,
    })
}

pub(crate) fn deferred_child_digest(value: &DeferredSettlementChildV1) -> Digest32 {
    let mut bytes = Vec::with_capacity(194);
    encode_deferred_child(&mut bytes, value);
    domain_digest_v1(
        b"DOM-INTEROP/SETTLEMENT-COORDINATOR/DEFERRED-CHILD/V1\0",
        &[&bytes],
    )
}

fn encode_optional_digest(output: &mut Vec<u8>, value: Option<Digest32>) {
    match value {
        Some(digest) => {
            output.push(1);
            output.extend_from_slice(&digest);
        }
        None => {
            output.push(0);
            output.extend_from_slice(&[0; 32]);
        }
    }
}

fn decode_optional_digest(reader: &mut Reader<'_>) -> Result<Option<Digest32>> {
    let present = reader.byte()?;
    let digest = reader.take::<32>()?;
    match present {
        0 if digest == [0; 32] => Ok(None),
        1 if digest != [0; 32] => Ok(Some(digest)),
        _ => Err(CoordinatorErrorV1::InvalidCanonicalMaterial),
    }
}

pub(crate) fn domain_digest_v1(domain: &[u8], parts: &[&[u8]]) -> Digest32 {
    let mut hasher = Blake2bVar::new(32).unwrap_or_else(|_| unreachable!("fixed digest size"));
    hasher.update(domain);
    for part in parts {
        let length = u64::try_from(part.len()).unwrap_or(u64::MAX);
        hasher.update(&length.to_be_bytes());
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .unwrap_or_else(|_| unreachable!("fixed digest output"));
    output
}

struct Reader<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

impl<'bytes> Reader<'bytes> {
    const fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(CoordinatorErrorV1::InvalidCanonicalMaterial)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(CoordinatorErrorV1::InvalidCanonicalMaterial)?;
        let output =
            <[u8; N]>::try_from(slice).map_err(|_| CoordinatorErrorV1::InvalidCanonicalMaterial)?;
        self.offset = end;
        Ok(output)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take::<1>()?[0])
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> Digest32 {
        [value; 32]
    }

    fn plan() -> CompositeSettlementPlanV1 {
        CompositeSettlementPlanV1::new(
            SettlementPlanBindingsV1 {
                route_id: digest(1),
                effect_id: digest(2),
                settlement_id: digest(3),
                leg: SettlementLegV1::Downstream,
                action: SettlementActionV1::Claim,
                fencing_epoch: 7,
                semantic_digest: digest(4),
                terms_digest: digest(5),
                registry_digest: digest(6),
                dom_profile_digest: digest(7),
                dom_deployment_digest: digest(8),
                counterparty_profile_digest: digest(9),
                counterparty_deployment_digest: digest(10),
            },
            SecretRequirementV1::FirstExposureRequired,
            None,
            [
                SettlementChildPlanV1 {
                    face: SettlementFaceV1::Evm,
                    exposure: ChildExposureV1::FirstSecretExposure,
                    chain_id: digest(11),
                    expected_transaction_id: digest(12),
                    intent_digest: digest(13),
                    custody_digest: digest(14),
                },
                SettlementChildPlanV1 {
                    face: SettlementFaceV1::Dom,
                    exposure: ChildExposureV1::UsesPublicSecret,
                    chain_id: digest(15),
                    expected_transaction_id: digest(16),
                    intent_digest: digest(17),
                    custody_digest: digest(18),
                },
            ],
        )
        .expect("valid plan")
    }

    fn staged_plan() -> CompositeSettlementPlanV1 {
        CompositeSettlementPlanV1::new_first_exposure_staged(
            plan().bindings().clone(),
            SettlementChildPlanV1 {
                face: SettlementFaceV1::Dom,
                exposure: ChildExposureV1::FirstSecretExposure,
                chain_id: digest(20),
                expected_transaction_id: digest(21),
                intent_digest: digest(22),
                custody_digest: digest(23),
            },
            DeferredSettlementChildV1 {
                face: SettlementFaceV1::Evm,
                chain_id: digest(24),
                route_scope_digest: digest(25),
                composition_digest: digest(26),
                role_plan_digest: digest(27),
                source_scope_digest: digest(28),
                materializer_authority_id: digest(29),
            },
        )
        .expect("valid staged plan")
    }

    #[test]
    fn strict_codec_roundtrip_and_trailing_refusal() {
        let plan = plan();
        let encoded = plan.encode_canonical().expect("encode");
        assert_eq!(encoded.len(), MATERIALIZED_PLAN_ENCODED_LEN_V2);
        assert_eq!(
            CompositeSettlementPlanV1::decode_canonical(&encoded).expect("decode"),
            plan
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            CompositeSettlementPlanV1::decode_canonical(&trailing),
            Err(CoordinatorErrorV1::InvalidCanonicalMaterial)
        );
        let mut bad_tag = encoded;
        bad_tag[102] = 0xff;
        assert_eq!(
            CompositeSettlementPlanV1::decode_canonical(&bad_tag),
            Err(CoordinatorErrorV1::InvalidCanonicalMaterial)
        );
    }

    #[test]
    fn staged_codec_is_exact_bounded_and_version_discriminated() {
        let plan = staged_plan();
        let encoded = plan.encode_canonical().expect("encode staged");
        assert_eq!(encoded.len(), STAGED_PLAN_ENCODED_LEN_V2);
        assert_eq!(
            CompositeSettlementPlanV1::decode_canonical(&encoded).expect("decode staged"),
            plan
        );

        let mut truncated = encoded.clone();
        truncated.pop();
        assert_eq!(
            CompositeSettlementPlanV1::decode_canonical(&truncated),
            Err(CoordinatorErrorV1::InvalidCanonicalMaterial)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            CompositeSettlementPlanV1::decode_canonical(&trailing),
            Err(CoordinatorErrorV1::InvalidCanonicalMaterial)
        );
        let mut wrong_layout = encoded.clone();
        wrong_layout[371] = 1;
        assert_eq!(
            CompositeSettlementPlanV1::decode_canonical(&wrong_layout),
            Err(CoordinatorErrorV1::InvalidCanonicalMaterial)
        );
        let mut legacy_version = encoded;
        legacy_version[3] = b'1';
        assert_eq!(
            CompositeSettlementPlanV1::decode_canonical(&legacy_version),
            Err(CoordinatorErrorV1::InvalidCanonicalMaterial)
        );
    }

    #[test]
    fn stable_ids_ignore_only_effect_and_fence() {
        let original = plan();
        let mut replacement_bindings = original.bindings().clone();
        replacement_bindings.effect_id = digest(90);
        replacement_bindings.fencing_epoch = 8;
        let replacement = CompositeSettlementPlanV1::new(
            replacement_bindings.clone(),
            original.secret_requirement(),
            original.preexisting_secret_evidence_digest(),
            original
                .materialized_children()
                .expect("exact children")
                .clone(),
        )
        .expect("replacement");
        assert!(stable_plan_equivalent(&original, &replacement).expect("compare"));
        assert_eq!(
            aggregate_action_id(&original).expect("action"),
            aggregate_action_id(&replacement).expect("replacement action")
        );
        assert_ne!(
            original.canonical_digest().expect("digest"),
            replacement.canonical_digest().expect("replacement digest")
        );

        let mut changed_children = original
            .materialized_children()
            .expect("exact children")
            .clone();
        changed_children[1].intent_digest = digest(91);
        let changed = CompositeSettlementPlanV1::new(
            replacement_bindings,
            original.secret_requirement(),
            original.preexisting_secret_evidence_digest(),
            changed_children,
        )
        .expect("changed");
        assert!(!stable_plan_equivalent(&original, &changed).expect("compare changed"));
    }
}
