//! Property tests of the F4 assurance objects (spec §13 step 2):
//! roundtrip identity, wire canonicity, cap and binding refusals.

use counterparty_api::AdaptorPointBytes;
use kaystra_core::state::EvidenceRefV1;
use kaystra_core::types::{AssetId, ChainId, SettlementId, TimelockSpec};
use proptest::prelude::*;
use uspe::objects::{
    AssuranceCertificateV1, AssurancePolicyV1, EvidenceRuleV1, PolicyId, TerminalPolicyV1,
    POLICY_STRUCT_VERSION,
};

fn timelock_domain() -> impl Strategy<Value = u8> {
    prop_oneof![Just(0x01u8), Just(0x02u8), Just(0x03u8)]
}

fn timelock(domain: u8, value: u64) -> TimelockSpec {
    match domain {
        0x01 => TimelockSpec::BlockHeight { value },
        0x02 => TimelockSpec::TimestampSeconds { value },
        _ => TimelockSpec::BtcTime512s { value },
    }
}

prop_compose! {
    /// A structurally valid policy: canonical point prefix, one deadline
    /// domain, strictly increasing deadlines, collateral within the cap.
    fn valid_policy()(
        policy_id in any::<[u8; 32]>(),
        settlement in any::<[u8; 32]>(),
        terms in any::<[u8; 32]>(),
        chain in any::<[u8; 32]>(),
        asset in any::<[u8; 32]>(),
        collateral in 1u128..=u128::MAX / 2,
        cap_margin in 0u128..=1_000_000,
        domain in timelock_domain(),
        base in 0u64..=u64::MAX / 2,
        gaps in [1u64..=1_000_000, 1u64..=1_000_000, 1u64..=1_000_000],
        point_prefix in prop_oneof![Just(0x02u8), Just(0x03u8)],
        point_body in any::<[u8; 32]>(),
    ) -> AssurancePolicyV1 {
        let mut point = [0u8; 33];
        point[0] = point_prefix;
        point[1..].copy_from_slice(&point_body);
        let d0 = base;
        let d1 = d0 + gaps[0];
        let d2 = d1 + gaps[1];
        let d3 = d2 + gaps[2];
        AssurancePolicyV1 {
            policy_id: PolicyId(policy_id),
            version: POLICY_STRUCT_VERSION,
            protected_settlement: SettlementId(settlement),
            terms_hash: terms,
            bond_chain_id: ChainId(chain),
            bond_asset: AssetId(asset),
            required_collateral: collateral,
            compensation_cap: collateral.saturating_add(cap_margin),
            collateral_deadline: timelock(domain, d0),
            claim_deadline: timelock(domain, d1),
            evidence_deadline: timelock(domain, d2),
            bond_release_deadline: timelock(domain, d3),
            evidence_rule: EvidenceRuleV1::RevealedScalarClaim {
                adaptor_point: AdaptorPointBytes(point),
            },
            terminal_policy: TerminalPolicyV1::ConservativeRelease,
        }
    }
}

prop_compose! {
    fn valid_certificate()(
        settlement in any::<[u8; 32]>(),
        terms in any::<[u8; 32]>(),
        policy in any::<[u8; 32]>(),
        lock in any::<[u8; 32]>(),
        chain in any::<[u8; 32]>(),
        tx in any::<[u8; 32]>(),
        event_index in any::<u32>(),
        height in any::<u64>(),
        anchor in any::<[u8; 32]>(),
        revision in any::<u64>(),
        domain in timelock_domain(),
        expiry in any::<u64>(),
    ) -> AssuranceCertificateV1 {
        AssuranceCertificateV1::issue(
            SettlementId(settlement),
            terms,
            PolicyId(policy),
            lock,
            EvidenceRefV1 {
                chain_id: ChainId(chain),
                tx_id: tx,
                event_index,
                block_height: height,
                block_anchor: anchor,
            },
            revision,
            timelock(domain, expiry),
        )
        .expect("issuing over arbitrary content is infallible modulo hashing")
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn policy_roundtrip_and_canonicity(policy in valid_policy()) {
        let bytes = policy.canonical_bytes().unwrap();
        let decoded = AssurancePolicyV1::decode(&bytes).unwrap();
        prop_assert_eq!(decoded, policy);
        // Canonicity: one value, one wire.
        prop_assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn policy_hash_is_stable_and_content_sensitive(policy in valid_policy()) {
        let h = policy.policy_hash().unwrap();
        prop_assert_eq!(h, policy.policy_hash().unwrap());
        let mut other = policy;
        other.required_collateral = other.required_collateral.saturating_sub(1).max(1);
        if other != policy {
            prop_assert_ne!(h, other.policy_hash().unwrap());
        }
    }

    #[test]
    fn collateral_over_cap_never_encodes(policy in valid_policy(), excess in 1u128..=1_000) {
        let mut bad = policy;
        bad.required_collateral = bad.compensation_cap.saturating_add(excess);
        prop_assert!(bad.validate().is_err());
        prop_assert!(bad.canonical_bytes().is_err());
    }

    #[test]
    fn certificate_roundtrip_and_canonicity(certificate in valid_certificate()) {
        let bytes = certificate.canonical_bytes().unwrap();
        let decoded = AssuranceCertificateV1::decode(&bytes).unwrap();
        prop_assert_eq!(decoded, certificate);
        prop_assert_eq!(decoded.canonical_bytes().unwrap(), bytes);
    }

    #[test]
    fn certificate_wire_rejects_any_flip(
        certificate in valid_certificate(),
        position in any::<prop::sample::Index>(),
        bit in 0u8..8,
    ) {
        // The id digests the content, so no corrupted wire may decode.
        let mut bytes = certificate.canonical_bytes().unwrap();
        let index = position.index(bytes.len());
        bytes[index] ^= 1 << bit;
        prop_assert!(AssuranceCertificateV1::decode(&bytes).is_err());
    }

    #[test]
    fn random_bytes_never_decode_to_a_policy_non_canonically(bytes in proptest::collection::vec(any::<u8>(), 0..320)) {
        // Either the decoder refuses, or what it accepted re-encodes to
        // the exact same wire — there is no third outcome.
        if let Ok(policy) = AssurancePolicyV1::decode(&bytes) {
            prop_assert_eq!(policy.canonical_bytes().unwrap(), bytes);
        }
    }
}
