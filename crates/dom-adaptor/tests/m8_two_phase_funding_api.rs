//! Public API contract for the additive M.8 two-phase funding profile.
//!
//! This external-crate test ensures downstream Contracts and Interop code can
//! name every authority and persistence boundary without gaining access to a
//! constructor for the one-shot capabilities. The legacy funding API remains
//! independent.

use dom_adaptor::{
    BpStatementV1, OperationalFundingAuthorizationError, OperationalFundingUnsignedTemplateV1,
    OperationalM8FundingAuthorizationBindingV1,
    OperationalM8FundingAuthorizationImportCapabilityV1, OperationalM8FundingAuthorizationStoreV1,
    OperationalM8FundingAuthorizationV1, OperationalM8FundingPersistenceCapabilityV1,
    OperationalM8FundingTransactionSinkV1, ScriptlessTransactionTemplateV1,
    VerifiedM8FundingTransactionV1,
};
use dom_crypto::{pedersen::BlindingFactor, pedersen::Commitment, SchnorrSignature};

struct ApiStore;

impl OperationalM8FundingAuthorizationStoreV1 for ApiStore {
    type Error = std::io::Error;

    fn issue_operational_m8_funding_authorization(
        &mut self,
        _binding: &OperationalM8FundingAuthorizationBindingV1,
        _unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        _capability: OperationalM8FundingAuthorizationImportCapabilityV1,
    ) -> Result<OperationalM8FundingAuthorizationV1, Self::Error> {
        Err(std::io::Error::other("compile-only API store"))
    }

    fn resume_operational_m8_funding_authorization(
        &mut self,
        _binding: &OperationalM8FundingAuthorizationBindingV1,
        _unsigned_template: &OperationalFundingUnsignedTemplateV1<'_>,
        _capability: OperationalM8FundingAuthorizationImportCapabilityV1,
    ) -> Result<OperationalM8FundingAuthorizationV1, Self::Error> {
        Err(std::io::Error::other("compile-only API store"))
    }
}

struct ApiSink;

impl OperationalM8FundingTransactionSinkV1 for ApiSink {
    type Error = std::io::Error;
    type PersistedFunding = [u8; 32];

    fn persist_verified_m8_funding(
        &mut self,
        _capability: OperationalM8FundingPersistenceCapabilityV1,
    ) -> Result<Self::PersistedFunding, Self::Error> {
        Err(std::io::Error::other("compile-only API sink"))
    }
}

#[allow(dead_code, clippy::too_many_arguments)]
fn downstream_lifecycle_surface_compiles(
    template: ScriptlessTransactionTemplateV1,
    chain_id: [u8; 32],
    session_id: [u8; 32],
    transcript_hash: [u8; 32],
    terms_hash: [u8; 32],
    bp_statement: &BpStatementV1,
    claim_template_hash: [u8; 32],
    adaptor_point: [u8; 33],
    refund_tx_hash: [u8; 32],
    backup_receipt_hash: [u8; 32],
    m8_policy_digest: [u8; 32],
    signature: SchnorrSignature,
    current_height: u64,
    store: &mut ApiStore,
    authorization: OperationalM8FundingAuthorizationV1,
) -> dom_adaptor::Result<VerifiedM8FundingTransactionV1> {
    let _: Result<
        OperationalM8FundingAuthorizationV1,
        OperationalFundingAuthorizationError<std::io::Error>,
    > = template.authorize_funding_m8_v1(
        &chain_id,
        session_id,
        transcript_hash,
        terms_hash,
        bp_statement,
        claim_template_hash,
        adaptor_point,
        refund_tx_hash,
        backup_receipt_hash,
        m8_policy_digest,
        store,
    );
    let _: Result<
        OperationalM8FundingAuthorizationV1,
        OperationalFundingAuthorizationError<std::io::Error>,
    > = template.resume_funding_m8_authorization_v1(
        &chain_id,
        session_id,
        transcript_hash,
        terms_hash,
        bp_statement,
        claim_template_hash,
        adaptor_point,
        refund_tx_hash,
        backup_receipt_hash,
        m8_policy_digest,
        store,
    );
    template.finalize_funding_m8(authorization, signature, &chain_id, current_height)
}

#[allow(dead_code)]
fn downstream_persistence_surface_compiles(
    funding: VerifiedM8FundingTransactionV1,
    sink: &mut ApiSink,
) -> Result<[u8; 32], std::io::Error> {
    funding.persist_with_m8_sink_v1(sink)
}

#[test]
fn binding_is_versioned_profile_tagged_and_contains_no_claim_presignature_slot() {
    let mut scalar = [0u8; 32];
    scalar[31] = 7;
    let blinding = BlindingFactor::from_bytes(scalar).expect("canonical blinding");
    let commitment = *Commitment::commit(42, &blinding).as_bytes();
    let adaptor_point = dom_crypto::SecretKey::from_bytes(&scalar)
        .expect("canonical secret")
        .public_key()
        .to_compressed_bytes();
    let binding = OperationalM8FundingAuthorizationBindingV1::new(
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        [0x44; 32],
        commitment,
        [0x55; 32],
        [0x66; 32],
        [0x77; 32],
        adaptor_point,
        [0x88; 32],
        [0x99; 32],
        [0xaa; 32],
    )
    .expect("public M.8 binding");

    let bytes = binding.to_bytes();
    assert_eq!(
        bytes.len(),
        OperationalM8FundingAuthorizationBindingV1::ENCODED_LEN
    );
    assert_eq!(&bytes[..8], b"DOMF7M8A");
    assert_eq!(&bytes[8..10], &1u16.to_le_bytes());
    assert_eq!(&bytes[10..14], b"M8T2");
    assert_eq!(binding.m8_policy_digest(), &[0x88; 32]);
    assert_eq!(binding.claim_adaptor_point(), &adaptor_point);
    // The fixed 400-byte layout is exhausted by the documented fields. Claim
    // pre-signature evidence is intentionally issued only by the later,
    // post-anchor claim-signing authority.
    assert_eq!(&bytes[368..400], binding.backup_receipt_hash());
}
