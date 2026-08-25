//! Cryptographic orchestration and independent DOM Contracts storage sealing.
//!
//! Curve, signature, challenge, point, and nonce-secret codecs remain owned by
//! the pinned authoritative DOM adapter. Storage cryptography is an independent
//! clean-room profile and never imports DOM Wallet keys, files, or source.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod claim_adaptor;
mod claim_adaptor_round;
mod shared_output;
mod storage;

pub use claim_adaptor::{
    verify_claim_adaptor_pre_signature_v1, ClaimAdaptorVerificationError,
    ClaimAdaptorVerificationRequestV1, VerifiedClaimAdaptorPreSignatureV1,
    CLAIM_ADAPTOR_PRE_SIGNATURE_LEN,
};
pub use claim_adaptor_round::{
    begin_claim_adaptor_round_v1, ClaimAdaptorRoundError, ClaimAdaptorRoundInputsV1,
    ClaimAdaptorRoundV1, CompletedClaimAdaptorCycleV1, CLAIM_ADAPTOR_PARTICIPANTS,
};
pub use shared_output::{
    commit_to_reveal, freeze_shared_output_statement_v1, CommonNonceError, CommonNonceRoundV1,
    FrozenSharedOutputV1, JointCommonNonceV1, PrivateNonceCustodyV1, SharedOutputContributionV1,
    SharedOutputError, SharedOutputInputsV1, SHARED_OUTPUT_PARTIES,
};
pub use storage::{
    acknowledge_pending_shared_blinding_backup_v1, acknowledge_shared_blinding_backup_v1,
    audit_collaborative_secret_envelope_v1, audit_nonce_secret_record,
    authoritative_backend_status, authoritative_storage_hash_v1, generate_storage_ids,
    generate_vault_master_key, open_backup_manifest_v1, open_collaborative_bp_finalize_record_v1,
    open_collaborative_bp_nonce_record_v1, open_collaborative_bp_proof_record_v1,
    open_collaborative_bp_round2_record_v1, open_master_key, open_nonce_secret_record,
    open_pending_shared_blinding_record_v1, open_shared_blinding_record_v1,
    open_shared_blinding_recovery_capsule_v1, open_tombstone_v1, seal_backup_manifest_v1,
    seal_collaborative_bp_nonce_record_v1, seal_collaborative_bp_proof_record_v1,
    seal_collaborative_bp_round2_bundle_v1, seal_master_key, seal_nonce_secret_record,
    seal_shared_blinding_bundle_v1, seal_tombstone_v1,
    upgrade_shared_blinding_bundle_restartable_v1, upgrade_shared_blinding_bundle_v1,
    BackupManifestMetadataV1, BackupManifestPlaintextV1, CollaborativeSecretEnvelopeV1,
    CryptoError, KeyRoleV1, NonceSecretRecordMetadataV1, Passphrase, RecordKindV1,
    SealedCollaborativeBpProofV1, SealedCollaborativeBpRound2BundleV1,
    SealedSharedBlindingBundleV1, StorageHashDomainV1, StorageIdsV1, TombstonePlaintextV1,
    TombstoneRecordMetadataV1, VaultMasterKey, VaultMasterKeyEnvelopeV1, VaultObjectEnvelopeV1,
};
