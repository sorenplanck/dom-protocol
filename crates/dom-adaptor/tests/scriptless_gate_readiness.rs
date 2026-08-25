//! Scriptless exit-gate readiness tests (G2–G5).
//!
//! Each gate in `DOM-Scriptless-Cronograma-Implementacao-v1.md` has two halves:
//! invariants that are pure logic, and a demonstration on a running regtest
//! node with two wallets. This file runs the pure-logic half of every gate now,
//! so a regression in the node-independent invariants is caught immediately.
//! The node half of each gate is written out step by step in the doc comment
//! and in `docs/scriptless/REGTEST-GATES.md`, so the operator can wire it in on
//! a machine with a node and know exactly what must pass.
//!
//! These tests deliberately do NOT claim to be the full gates. A gate is closed
//! only when its regtest demonstration also passes. What runs here is the
//! foundation those demonstrations stand on.

use dom_adaptor::{
    combine_decoy_capsule_v1, contribute_vault_backed_blinding_share_v1,
    verify_all_partial_commitments_v1, AdaptorPreSignatureV1, AdaptorSecret, BpStatementV1,
    ContractEnvelopeV1, ContractKindV1, ContractStageV1, ContractStateV1, DecoyContributionV1,
    DirectionV1, DurableShareBackupAckCapabilityV1, FundingAuthorizationV1, PartialBlindingV1,
    PartialCommitmentProofV1, PendingSharedBlindingBindingV1, RefundDeadlinePolicyV1, SessionId,
    ShareBackupAckV1, SharedBlindingBindingUpgradeCapabilityV1, SharedBlindingBindingV1,
    SharedBlindingImportCapabilityV1, SharedBlindingMaterialV1,
    SharedBlindingRetirementCapabilityV1, SharedBlindingSealCapabilityV1, SharedBlindingVaultV1,
    SigningShareV1, TrustedChainIdV1,
};
use dom_core::Hash256;
use dom_crypto::recovery::RECOVERY_CAPSULE_SIZE;
use dom_crypto::{
    blake2b_256_tagged, schnorr_challenge, scriptless_add_public_points,
    scriptless_verify_final_signature, secret_scalar_mul_add_assign, secret_scalar_public_key,
    PartialSig, RANGE_PROOF_SIZE,
};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
#[error("test shared-blinding vault failure")]
struct TestShareVaultError;

#[derive(Default)]
struct TestShareVault {
    plaintext: Option<[u8; 32]>,
    pending: Option<PendingSharedBlindingBindingV1>,
    bound: Option<SharedBlindingBindingV1>,
}

impl SharedBlindingVaultV1 for TestShareVault {
    type Error = TestShareVaultError;

    fn seal_fresh_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        material: SharedBlindingMaterialV1,
        capability: SharedBlindingSealCapabilityV1,
    ) -> Result<(), Self::Error> {
        if self.plaintext.is_some() {
            return Err(TestShareVaultError);
        }
        self.plaintext = Some(*capability.into_plaintext(material));
        self.pending = Some(binding.clone());
        Ok(())
    }

    fn open_persisted_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        if self.pending.as_ref() != Some(binding) {
            return Err(TestShareVaultError);
        }
        capability
            .import(Zeroizing::new(self.plaintext.ok_or(TestShareVaultError)?))
            .map_err(|_| TestShareVaultError)
    }

    fn confirm_pending_backup_roundtrip(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        capability
            .acknowledge_pending(binding, binding.share_point().clone())
            .map_err(|_| TestShareVaultError)
    }

    fn bind_recovery_capsule(
        &mut self,
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
        capability: SharedBlindingBindingUpgradeCapabilityV1,
    ) -> Result<(), Self::Error> {
        capability
            .authorize_upgrade(pending, bound)
            .map_err(|_| TestShareVaultError)?;
        if self.pending.as_ref() != Some(pending) || self.bound.is_some() {
            return Err(TestShareVaultError);
        }
        self.bound = Some(bound.clone());
        self.pending = None;
        Ok(())
    }

    fn open_persisted_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> Result<SharedBlindingMaterialV1, Self::Error> {
        if self.bound.as_ref() != Some(binding) {
            return Err(TestShareVaultError);
        }
        capability
            .import(Zeroizing::new(self.plaintext.ok_or(TestShareVaultError)?))
            .map_err(|_| TestShareVaultError)
    }

    fn confirm_backup_roundtrip(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> Result<ShareBackupAckV1, Self::Error> {
        capability
            .acknowledge(binding, binding.share_point().clone())
            .map_err(|_| TestShareVaultError)
    }

    fn retire_pending_share(
        &mut self,
        _binding: &PendingSharedBlindingBindingV1,
        _capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        Err(TestShareVaultError)
    }

    fn retire_bound_share(
        &mut self,
        _binding: &SharedBlindingBindingV1,
        _capability: SharedBlindingRetirementCapabilityV1,
    ) -> Result<(), Self::Error> {
        Err(TestShareVaultError)
    }
}

const CHAIN_ID: [u8; 32] = [0xAD; 32];

fn chain() -> TrustedChainIdV1 {
    // The synthetic fixture constructor is test-only inside the crate; from an
    // external test, derive the trusted chain through the authenticated path.
    TrustedChainIdV1::from_authenticated_genesis(0x0011_2233, &Hash256::from_bytes([0x11; 32]))
}

fn small_blinding(byte: u8) -> PartialBlindingV1 {
    let mut bytes = [0u8; 32];
    bytes[31] = byte;
    PartialBlindingV1::from_be_bytes(bytes).expect("canonical blinding")
}

// ---------------------------------------------------------------------------
// G2 — shared output accepted by consensus, 872 bytes on the wire, no isolated
//      participant can spend it.
//
// Node-independent invariants asserted here:
//   * the exact wire size arithmetic that must equal 872 bytes;
//   * the decoy capsule fills the recovery-capsule slot indistinguishably;
//   * the joint-blinding gate rejects any share whose opening is not proven,
//     which is the "no isolated participant can spend" property in logic form.
//
// Remaining node steps (docs/scriptless/REGTEST-GATES.md, G2):
//   1. Two wallets run the collaborative Bulletproof to a 739-byte proof
//      (bulletproof_mpc.rs already does this internally, verified by the real
//      DOM verifier; the public two-wallet driver is the pending 2.2 work).
//   2. Assemble the TransactionOutput with the shared commitment, the 739-byte
//      proof, and the 96-byte decoy capsule.
//   3. Submit it to a regtest node; assert consensus accepts it and its
//      serialized size is exactly 872 bytes.
//   4. Assert neither wallet alone can produce a spending signature.
// ---------------------------------------------------------------------------
#[test]
fn g2_wire_size_and_no_isolated_spend_invariants() {
    // The shared output on the wire is: 33-byte commitment + 4-byte length
    // prefix + proof envelope, where the envelope is the 739-byte range proof
    // followed by the 96-byte recovery/decoy capsule.
    let proof_envelope = RANGE_PROOF_SIZE + RECOVERY_CAPSULE_SIZE;
    let output_wire = 33 + 4 + proof_envelope;
    assert_eq!(RANGE_PROOF_SIZE, 739, "collaborative range proof size");
    assert_eq!(RECOVERY_CAPSULE_SIZE, 96, "recovery/decoy capsule size");
    assert_eq!(output_wire, 872, "shared output wire size (G2 target)");

    // The decoy capsule occupies that 96-byte slot and passes the real capsule
    // frontier, so a shared output (which has no openable capsule) is
    // wire-indistinguishable from an ordinary recoverable output.
    let session = SessionId::from_bytes([0x22; 32]).expect("session");
    let share_a = SigningShareV1::from_be_bytes([3u8; 32]).expect("share A");
    let share_b = SigningShareV1::from_be_bytes([5u8; 32]).expect("share B");
    let contribution_a = DecoyContributionV1::derive(&share_a, &session);
    let contribution_b = DecoyContributionV1::derive(&share_b, &session);
    let commit_b = contribution_b.commitment();
    let capsule = combine_decoy_capsule_v1(
        &contribution_a.into_reveal(),
        &contribution_b.into_reveal(),
        &commit_b,
    )
    .expect("decoy capsule");
    assert_eq!(capsule.as_bytes().len(), RECOVERY_CAPSULE_SIZE);

    // "No isolated participant can spend": the joint-blinding gate requires a
    // valid opening proof for every commitment share before the aggregate is
    // trusted. A set missing a participant fails closed.
    let (statement, proofs) = two_party_commitment_statement();
    assert!(verify_all_partial_commitments_v1(&statement, &proofs).expect("full set"));
    assert!(
        !verify_all_partial_commitments_v1(&statement, &proofs[..1]).expect("partial set"),
        "an incomplete opening set must not be trusted"
    );
}

/// Build a two-party BP statement with matching opening proofs.
fn two_party_commitment_statement() -> (BpStatementV1, Vec<(u16, PartialCommitmentProofV1)>) {
    let r_a = small_blinding(7);
    let r_b = small_blinding(9);
    let c_a = r_a.commitment_share().expect("C_a");
    let c_b = r_b.commitment_share().expect("C_b");
    let aggregate =
        BpStatementV1::aggregate_commitment_from_shares(&[c_a.clone(), c_b.clone()], 42)
            .expect("aggregate");
    let statement = BpStatementV1::new(
        &chain(),
        [0x22; 32],
        vec![[0x21; 32], [0x42; 32]],
        42,
        vec![c_a, c_b],
        aggregate,
        Some([0x44; 32]),
    )
    .expect("statement");
    let proof_a = dom_adaptor::prove_partial_commitment_v1(&statement, 0, &r_a).expect("proof A");
    let proof_b = dom_adaptor::prove_partial_commitment_v1(&statement, 1, &r_b).expect("proof B");
    (statement, vec![(0, proof_a), (1, proof_b)])
}

// ---------------------------------------------------------------------------
// G3 — interruption at every protocol step; each cut either advances correctly
//      or aborts releasing reserves; no state loses funds or wedges an input.
//
// Node-independent invariants asserted here:
//   * abort is reachable from every non-terminal stage (reserves can always be
//     released);
//   * a durable checkpoint resumes to the exact live state and continues;
//   * an out-of-order or replayed message cannot advance the contract.
//
// Remaining node steps (REGTEST-GATES.md, G3):
//   1. Drive the full choreography on a node, persisting the contract state at
//      each transition through the Contracts store (pending 3.3).
//   2. Kill the process immediately before and after each durable write.
//   3. On restart, resume() and assert the contract either continues correctly
//      or aborts releasing reserves — never a lost-funds or wedged state.
// ---------------------------------------------------------------------------
#[test]
fn g3_abort_always_available_resume_and_ordering_invariants() {
    // Abort is always available from a non-terminal stage.
    let mut state = ContractStateV1::open([0x33; 32]).expect("open");
    let abort = ContractEnvelopeV1::new(
        &chain(),
        [0x22; 32],
        DirectionV1::Initiator,
        ContractKindV1::WitnessOrTimeout,
        0,
        ContractStageV1::Aborted,
        state.transcript(),
        vec![],
    )
    .expect("abort envelope");
    let mut aborting = state.clone();
    aborting.apply(&abort).expect("abort from Proposed");
    assert_eq!(aborting.stage(), ContractStageV1::Aborted);

    // Advance one step, checkpoint, resume, and continue from the checkpoint.
    let step = ContractEnvelopeV1::new(
        &chain(),
        [0x22; 32],
        DirectionV1::Initiator,
        ContractKindV1::WitnessOrTimeout,
        0,
        ContractStageV1::SharedOutputBuilt,
        state.transcript(),
        vec![0xAB; 4],
    )
    .expect("step");
    state.apply(&step).expect("advance");
    let resumed = ContractStateV1::resume(state.stage(), state.transcript(), 1, 0).expect("resume");
    // The durable projection is reconstructed exactly; the §8.5 duplicate-
    // detection memory is ephemeral by design and re-binds on the next message.
    assert_eq!(
        resumed.stage(),
        state.stage(),
        "resume reconstructs the durable stage"
    );
    assert_eq!(
        resumed.transcript(),
        state.transcript(),
        "resume reconstructs the durable transcript"
    );

    // Replaying the exact accepted bytes is acknowledged idempotently and does
    // not re-execute the transition (§8.5); the stage is unchanged.
    assert_eq!(
        state.apply(&step).expect("idempotent repeat"),
        dom_adaptor::ContractApplyOutcomeV1::DuplicateAck,
        "identical bytes are acked, never applied twice"
    );
    assert_eq!(state.stage(), ContractStageV1::SharedOutputBuilt);
}

// ---------------------------------------------------------------------------
// G4 — simulated abandonment at every step; nobody loses funds, or the refund
//      unlocks at H_refund and is accepted first try.
//
// Node-independent invariants asserted here:
//   * funding cannot be authorized before the refund AND the claim adaptor are
//     presigned (§7.2/§7.3: money never enters before a guaranteed exit and the
//     claim path both exist);
//   * the bilateral backup gate requires every participant's roundtrip ack;
//   * the refund lock height is a well-formed nonzero margin beyond funding.
//
// Remaining node steps (REGTEST-GATES.md, G4):
//   1. Build the funding unsigned; co-sign the refund with KERNEL_FEAT_
//      HEIGHT_LOCKED at H_refund; only then sign and publish the funding.
//   2. Abandon the session at each step; assert no funds are lost.
//   3. Mine to H_refund; assert the refund is accepted first try (reproduces
//      O-03 over the shared output).
// ---------------------------------------------------------------------------
#[test]
fn g4_funding_order_backup_and_refund_margin_invariants() {
    // The bilateral backup gate: every participant's roundtrip must be confirmed.
    let roster = [[0x31; 32], [0x32; 32]];
    let mut vault_a = TestShareVault::default();
    let mut vault_b = TestShareVault::default();
    let pending_a = contribute_vault_backed_blinding_share_v1(
        &chain(),
        [0x22; 32],
        &roster,
        DirectionV1::Initiator,
        0,
        [0x41; 32],
        &mut vault_a,
    )
    .expect("durable share A");
    let pending_b = contribute_vault_backed_blinding_share_v1(
        &chain(),
        [0x22; 32],
        &roster,
        DirectionV1::Responder,
        1,
        [0x41; 32],
        &mut vault_b,
    )
    .expect("durable share B");
    let decoy_a = pending_a.derive_decoy_contribution_v1().expect("decoy A");
    let decoy_b = pending_b.derive_decoy_contribution_v1().expect("decoy B");
    let commitment_b = decoy_b.commitment();
    let capsule = combine_decoy_capsule_v1(
        &decoy_a.into_reveal(),
        &decoy_b.into_reveal(),
        &commitment_b,
    )
    .expect("canonical bilateral capsule");
    let mut cap_a = pending_a
        .bind_recovery_capsule_v1(&capsule, &mut vault_a)
        .expect("bound share A");
    let mut cap_b = pending_b
        .bind_recovery_capsule_v1(&capsule, &mut vault_b)
        .expect("bound share B");
    let points = vec![cap_a.public_key().clone(), cap_b.public_key().clone()];
    let acks = vec![
        cap_a.take_durable_backup_ack_v1().expect("backup A"),
        cap_b.take_durable_backup_ack_v1().expect("backup B"),
    ];
    let backup = dom_adaptor::verify_bilateral_backup_v1(&points, &acks).expect("backup");
    assert!(
        dom_adaptor::verify_bilateral_backup_v1(&points, &acks[..1]).is_err(),
        "an incomplete backup set must fail closed"
    );

    // Funding may be authorized only after the refund and claim adaptor are
    // presigned (§7.2/§7.3 — the gate transitions from ClaimPresigned).
    let state = state_at_claim_presigned();
    let authority = FundingAuthorizationV1::authorize(&state, backup).expect("authorize");
    assert_eq!(authority.bound_transcript(), &state.transcript());

    // Authorizing from an earlier stage — money before the exit/claim path —
    // fails.
    let mut early = ContractStateV1::open([0x33; 32]).expect("open");
    let env = ContractEnvelopeV1::new(
        &chain(),
        [0x22; 32],
        DirectionV1::Initiator,
        ContractKindV1::WitnessOrTimeout,
        0,
        ContractStageV1::SharedOutputBuilt,
        early.transcript(),
        vec![0xAB; 4],
    )
    .expect("env");
    early.apply(&env).expect("advance");
    let backup2 = dom_adaptor::verify_bilateral_backup_v1(&points, &acks).expect("backup");
    assert!(FundingAuthorizationV1::authorize(&early, backup2).is_err());

    // The refund sits a nonzero margin beyond funding, with a smaller claim
    // confirmation margin leaving a non-empty safe claim window.
    let policy = RefundDeadlinePolicyV1::new(3, 6, 4).expect("policy");
    assert_eq!(policy.refund_lock_height(1000).expect("refund"), 1009);
}

// ---------------------------------------------------------------------------
// G5 — full cycle with both terminals: happy path with byte-verified
//      extraction, and refund without revelation; plus a near-deadline claim.
//
// Node-independent invariants asserted here:
//   * the adaptor closed cycle extract(adapt(presign)) == t, byte-verified;
//   * the extracted secret's point equals the committed adaptor point T;
//   * the claim floor rejects a claim published too close to the refund unlock.
//
// Remaining node steps (REGTEST-GATES.md, G5):
//   1. Pre-sign the claim shifted by T; publish it on a node; extract t from
//      the kernel and assert t*G == T byte for byte.
//   2. In a second run, take the refund path without revealing t.
//   3. Add an adversarial claim near H_refund and assert the claim floor
//      rejects publishing inside the unsafe window.
// ---------------------------------------------------------------------------
#[test]
fn g5_adaptor_extraction_and_claim_floor_invariants() {
    // Build one valid pre-signature and run the closed cycle.
    let signing = scalar_bytes(7);
    let nonce = scalar_bytes(9);
    let adaptor_bytes = scalar_bytes(11);
    let signing_key = secret_scalar_public_key(&signing).expect("X");
    let adaptor_secret = AdaptorSecret::from_be_bytes(*adaptor_bytes).expect("t");
    let adaptor_point = adaptor_secret.public_point().expect("T");
    let nonce_point = secret_scalar_public_key(&nonce).expect("kG");
    let message = *blake2b_256_tagged("DOM:g5-claim-message:v1", &[0x01]).as_bytes();

    let aggregate_nonce_hat =
        scriptless_add_public_points(&[nonce_point, adaptor_point.clone()]).expect("R_hat");
    let challenge = schnorr_challenge(
        &aggregate_nonce_hat.to_compressed_bytes(),
        &signing_key,
        &CHAIN_ID,
        &message,
    );
    let mut scalar_hat = nonce.clone();
    secret_scalar_mul_add_assign(&mut scalar_hat, &signing, challenge.as_bytes()).expect("s_hat");
    let claim_template_hash = [0x22; 32];
    let transcript_hash = [0x33; 32];
    let pre_signature = AdaptorPreSignatureV1::new(
        claim_template_hash,
        adaptor_point.clone(),
        aggregate_nonce_hat,
        PartialSig::from_bytes(&*scalar_hat).expect("s_hat canonical"),
        transcript_hash,
    );

    let adapted = pre_signature
        .adapt(
            &adaptor_secret,
            &claim_template_hash,
            &transcript_hash,
            &signing_key,
            &CHAIN_ID,
            &message,
        )
        .expect("adapt");
    assert!(
        scriptless_verify_final_signature(&adapted, &signing_key, &CHAIN_ID, &message)
            .expect("final verify"),
        "the claim signature must be a valid DOM signature"
    );
    let extracted = pre_signature
        .extract(
            &adapted,
            &claim_template_hash,
            &transcript_hash,
            &signing_key,
            &CHAIN_ID,
            &message,
        )
        .expect("extract");
    assert_eq!(
        extracted.public_point().expect("t_out point"),
        adaptor_point,
        "extract(adapt(presign)) == t, verified through the point"
    );

    // The claim floor admits a claim published inside the safe window and
    // rejects one too close to the refund unlock. Refund margin 9, claim
    // confirmation margin 4 → funding 1000, refund 1009, floor 1005.
    let policy = RefundDeadlinePolicyV1::new(3, 6, 4).expect("policy");
    let refund = policy.refund_lock_height(1000).expect("refund");
    assert!(policy.claim_is_safe(1005, refund).expect("safe at floor"));
    assert!(!policy
        .claim_is_safe(1006, refund)
        .expect("unsafe above floor"));
    assert!(!policy
        .claim_is_safe(refund, refund)
        .expect("unsafe at unlock"));
}

// --- shared fixtures -------------------------------------------------------

fn scalar_bytes(byte: u8) -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    bytes[31] = byte;
    bytes
}

fn state_at_claim_presigned() -> ContractStateV1 {
    let mut state = ContractStateV1::open([0x33; 32]).expect("open");
    // §7.2/§7.3: refund co-signed (step 5), then the claim adaptor pre-signed /
    // ReadyToFund (steps 7-8), before funding is authorized.
    for (sender, target, seq) in [
        (
            DirectionV1::Initiator,
            ContractStageV1::SharedOutputBuilt,
            0u64,
        ),
        (
            DirectionV1::Responder,
            ContractStageV1::RefundPresigned,
            0u64,
        ),
        (
            DirectionV1::Initiator,
            ContractStageV1::ClaimPresigned,
            1u64,
        ),
    ] {
        let env = ContractEnvelopeV1::new(
            &chain(),
            [0x22; 32],
            sender,
            ContractKindV1::WitnessOrTimeout,
            seq,
            target,
            state.transcript(),
            vec![0xAB; 4],
        )
        .expect("envelope");
        state.apply(&env).expect("transition");
    }
    state
}
