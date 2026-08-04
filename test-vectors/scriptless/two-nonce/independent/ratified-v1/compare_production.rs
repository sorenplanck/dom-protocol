use std::{env, fs};

use dom_adaptor::{
    advance_transcript_hash_v1, aggregate_partial_signatures_v1, aggregate_public_nonces_v1,
    binding_factor_v1, finalize_plain_signature_v1, nonce_commitment_hash_v1,
    AdaptorPreSignatureV1, AdaptorSecret, BindingContextV1, DirectionV1, NonceCommitmentV1,
    NonceRevealV1, PartialSignatureV1, ParticipantIdentityV1, ParticipantPublicNoncesV1, PurposeV1,
    SessionContextV1, SigningPhaseV1, TrustedChainIdV1,
};
use dom_crypto::{
    blake2b_256_tagged, scalar_from_wide_be, schnorr_add_public_keys, schnorr_challenge,
    scriptless_verify_bound_partial, scriptless_verify_final_signature, PartialSig, PublicKey,
    ScriptlessNonceDerivationV1, ScriptlessSecretScalar,
};
use serde_json::Value;
use subtle::ConstantTimeEq;

struct Checks {
    count: usize,
}

impl Checks {
    fn bytes(&mut self, name: &str, actual: &[u8], expected_hex: &str) {
        let expected = hex::decode(expected_hex)
            .unwrap_or_else(|error| panic!("invalid expected hex for {name}: {error}"));
        if actual != expected {
            eprintln!("FIRST_DIVERGENCE={name}");
            eprintln!("expected={}", hex::encode(expected));
            eprintln!("production={}", hex::encode(actual));
            std::process::exit(2);
        }
        self.count += 1;
        println!("MATCH\t{name}\t{}", hex::encode(actual));
    }

    fn truth(&mut self, name: &str, value: bool) {
        if !value {
            eprintln!("FIRST_DIVERGENCE={name}");
            eprintln!("expected=true");
            eprintln!("production=false");
            std::process::exit(2);
        }
        self.count += 1;
        println!("MATCH\t{name}\ttrue");
    }

    fn tagged(&mut self, name: &str, tag: &str, expected_input: &str, expected_digest: &str) {
        let framed = decode(expected_input);
        let tag_len = usize::from(u16::from_le_bytes([framed[0], framed[1]]));
        self.bytes(
            &format!("{name}.tag_length"),
            &(tag.len() as u16).to_le_bytes(),
            &framed[..2]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        self.bytes(
            &format!("{name}.tag_bytes"),
            tag.as_bytes(),
            &hex::encode(&framed[2..2 + tag_len]),
        );
        let digest = blake2b_256_tagged(tag, &framed[2 + tag_len..]);
        self.bytes(
            &format!("{name}.digest"),
            digest.as_bytes(),
            expected_digest,
        );
    }
}

fn text<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn decode(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap_or_else(|error| panic!("invalid vector hex: {error}"))
}

fn array<const N: usize>(value: &str) -> [u8; N] {
    decode(value)
        .try_into()
        .unwrap_or_else(|value: Vec<u8>| panic!("expected {N} bytes, got {}", value.len()))
}

fn point(value: &str) -> PublicKey {
    PublicKey::from_compressed_bytes(&decode(value)).expect("frozen point must parse")
}

fn secret(value: &str) -> ScriptlessSecretScalar {
    ScriptlessSecretScalar::from_be_bytes(array(value)).expect("frozen scalar must parse")
}

fn purpose(byte_hex: &str) -> PurposeV1 {
    PurposeV1::try_from(array::<1>(byte_hex)[0]).expect("frozen purpose")
}

fn direction(byte_hex: &str) -> DirectionV1 {
    DirectionV1::try_from(array::<1>(byte_hex)[0]).expect("frozen direction")
}

fn check_transcript_domain(checks: &mut Checks) {
    let previous = [0x11_u8; 32];
    let message = [0x22_u8; 32];
    let mut body = [0_u8; 67];
    body[..32].copy_from_slice(&previous);
    body[32..64].copy_from_slice(&message);
    body[64] = DirectionV1::Initiator.to_byte();
    body[65..].copy_from_slice(&SigningPhaseV1::SigNonceCommit.to_le_bytes());
    let expected = blake2b_256_tagged("DOM:scriptless-transcript:v1", &body);
    let production = advance_transcript_hash_v1(
        &previous,
        &message,
        DirectionV1::Initiator,
        SigningPhaseV1::SigNonceCommit,
    );
    checks.bytes(
        "global.transcript_update_domain",
        &production,
        &hex::encode(expected.as_bytes()),
    );
}

fn compare_case(checks: &mut Checks, root: &Value, case: &Value) {
    let case_name = text(case, "name");
    let prefix = |field: &str| format!("{case_name}.{field}");
    let inputs = &case["inputs"];
    let purpose = purpose(text(inputs, "purpose_u8"));
    let chain_id = array(text(inputs, "chain_id_32"));
    let session_id = array(text(inputs, "session_id_32"));
    let template_hash = array(text(inputs, "template_hash_32"));
    let kernel_message = array(text(inputs, "kernel_message_digest_32"));
    let transcript_hash = array(text(inputs, "transcript_hash_32"));
    let trusted = TrustedChainIdV1::from_signed_fixture(chain_id);

    let identity_assignments = root["participant_identity_assignments"]
        .as_array()
        .expect("identity assignments");
    let participant_values = case["participants"].as_array().expect("participants");
    let mut secret_nonces = Vec::new();
    let mut participant_nonces = Vec::new();
    let mut signing_keys = Vec::new();
    let mut commitment_payloads = Vec::new();
    let mut reveal_payloads = Vec::new();

    for (index, participant) in participant_values.iter().enumerate() {
        let participant_name = prefix(&format!("participant[{index}]"));
        let kdf = &participant["kdf"];
        let signing_share = secret(text(participant, "signing_share_be32"));
        let signing_key = signing_share.public_key();
        checks.bytes(
            &format!("{participant_name}.signing_public_key"),
            &signing_key.to_compressed_bytes(),
            text(participant, "signing_public_key_sec1"),
        );

        let identity = &identity_assignments[index];
        let participant_identity = ParticipantIdentityV1::new(
            &trusted,
            point(text(identity, "identity_public_key_sec1")),
            signing_key.clone(),
            direction(text(participant, "direction_u8")),
        )
        .expect("frozen participant identity must validate");
        checks.bytes(
            &format!("{participant_name}.participant_id"),
            participant_identity.participant_id(),
            text(participant, "participant_id"),
        );
        checks.tagged(
            &format!("{participant_name}.participant_id_hash"),
            "DOM:scriptless-participant:v1",
            text(identity, "participant_id_tag_input_bytes"),
            text(participant, "participant_id"),
        );

        let canonical_context = decode(text(kdf, "canonical_context_bytes"));
        let parsed_context =
            SessionContextV1::from_bytes(&canonical_context, &trusted, &signing_share)
                .expect("production context parser must accept frozen context");
        checks.bytes(
            &format!("{participant_name}.canonical_context"),
            &parsed_context.to_bytes(),
            text(kdf, "canonical_context_bytes"),
        );

        checks.tagged(
            &format!("{participant_name}.mask"),
            "DOM:scriptless-secret-nonce-aux:v1",
            text(kdf, "aux_tag_input_bytes"),
            text(kdf, "mask"),
        );
        let share_bytes = decode(text(participant, "signing_share_be32"));
        let mask = decode(text(kdf, "mask"));
        let masked: Vec<u8> = share_bytes
            .iter()
            .zip(mask.iter())
            .map(|(left, right)| left ^ right)
            .collect();
        checks.bytes(
            &format!("{participant_name}.masked_signing_share"),
            &masked,
            text(kdf, "masked_signing_share"),
        );
        checks.tagged(
            &format!("{participant_name}.seed"),
            "DOM:scriptless-secret-nonce-seed:v1",
            text(kdf, "seed_tag_input_bytes"),
            text(kdf, "seed"),
        );
        for (nonce, index_byte) in [("k1", 0x01_u8), ("k2", 0x02_u8)] {
            for half in [0_u8, 1_u8] {
                checks.tagged(
                    &format!("{participant_name}.{nonce}.wide_digest_{half}"),
                    "DOM:scriptless-secret-nonce-wide:v1",
                    text(kdf, &format!("{nonce}_wide_digest_{half}_tag_input_bytes")),
                    text(kdf, &format!("{nonce}_wide_digest_{half}")),
                );
                let tagged_input = decode(text(
                    kdf,
                    &format!("{nonce}_wide_digest_{half}_tag_input_bytes"),
                ));
                checks.bytes(
                    &format!("{participant_name}.{nonce}.index_and_half"),
                    &tagged_input[tagged_input.len() - 2..],
                    &format!("{index_byte:02x}{half:02x}"),
                );
            }
        }

        let wide_1 = array(text(kdf, "W_1"));
        let wide_2 = array(text(kdf, "W_2"));
        let reduced_1 = scalar_from_wide_be(&wide_1).expect("nonzero k1");
        let reduced_2 = scalar_from_wide_be(&wide_2).expect("nonzero k2");
        let expected_1 = secret(text(kdf, "k1_be32"));
        let expected_2 = secret(text(kdf, "k2_be32"));
        checks.truth(
            &format!("{participant_name}.scalar_from_wide.k1"),
            bool::from(reduced_1.ct_eq(&expected_1)),
        );
        checks.truth(
            &format!("{participant_name}.scalar_from_wide.k2"),
            bool::from(reduced_2.ct_eq(&expected_2)),
        );

        let aux = array(text(participant, "aux_rand_32"));
        let derivation = ScriptlessNonceDerivationV1::from_aux_for_test(aux);
        let derived_pair = derivation
            .derive_pair(&signing_share, &canonical_context)
            .expect("frozen KDF pair must be nonzero");
        let (first_public, second_public) = derived_pair.public_keys();
        checks.bytes(
            &format!("{participant_name}.R_i1"),
            &first_public.to_compressed_bytes(),
            text(kdf, "R_i1_sec1"),
        );
        checks.bytes(
            &format!("{participant_name}.R_i2"),
            &second_public.to_compressed_bytes(),
            text(kdf, "R_i2_sec1"),
        );

        checks.tagged(
            &format!("{participant_name}.nonce_commitment_hash"),
            "DOM:scriptless-nonce-commit:v1",
            text(participant, "commitment_tag_input_bytes"),
            text(participant, "nonce_commitment"),
        );
        let adaptor_point = inputs["adaptor_point_sec1"].as_str().map(point);
        let commitment = nonce_commitment_hash_v1(
            &chain_id,
            &session_id,
            &array(text(participant, "participant_id")),
            purpose,
            &template_hash,
            &first_public,
            &second_public,
            adaptor_point.as_ref(),
        )
        .expect("production nonce commitment");
        checks.bytes(
            &format!("{participant_name}.nonce_commitment"),
            commitment.as_bytes(),
            text(participant, "nonce_commitment"),
        );
        let participant_index =
            u16::from_le_bytes(array(text(participant, "participant_index_u16_le")));
        let commitment_payload =
            NonceCommitmentV1::new(purpose, participant_index, *commitment.as_bytes());
        checks.bytes(
            &format!("{participant_name}.commit_payload"),
            &commitment_payload.to_bytes(),
            text(participant, "sig_nonce_commit_v1_35"),
        );
        let reveal_payload = NonceRevealV1::new(
            purpose,
            participant_index,
            first_public.clone(),
            second_public.clone(),
        );
        checks.bytes(
            &format!("{participant_name}.reveal_payload"),
            &reveal_payload.to_bytes(),
            text(participant, "sig_nonce_reveal_v1_69"),
        );

        participant_nonces.push(ParticipantPublicNoncesV1 {
            participant_index,
            signing_key: signing_key.clone(),
            first_nonce: first_public,
            second_nonce: second_public,
        });
        signing_keys.push(signing_key);
        secret_nonces.push((derived_pair, signing_share));
        commitment_payloads.push(commitment_payload);
        reveal_payloads.push(reveal_payload);
    }

    checks.tagged(
        &prefix("binding_hash"),
        "DOM:scriptless-sig-nonce-bind:v1",
        text(&case["binding"], "tag_input_bytes"),
        text(&case["binding"], "digest"),
    );
    let adaptor_point = inputs["adaptor_point_sec1"].as_str().map(point);
    let binding = binding_factor_v1(
        &BindingContextV1 {
            chain_id,
            session_id,
            purpose,
            template_hash,
        },
        &participant_nonces,
        adaptor_point.as_ref(),
    )
    .expect("production binding factor");
    checks.bytes(
        &prefix("binding_scalar"),
        &binding.to_be_bytes(),
        text(&case["binding"], "scalar_be32"),
    );

    let expected_effective = case["effective_participant_nonces_sec1"]
        .as_array()
        .expect("effective nonces");
    let mut effective = Vec::new();
    for (index, participant) in participant_nonces.iter().enumerate() {
        let value = binding
            .bind_public_nonces(&participant.first_nonce, &participant.second_nonce)
            .expect("effective nonce");
        checks.bytes(
            &prefix(&format!("effective_nonce[{index}]")),
            &value.to_compressed_bytes(),
            expected_effective[index]
                .as_str()
                .expect("effective nonce hex"),
        );
        effective.push(value);
    }
    let aggregate_nonce = aggregate_public_nonces_v1(&effective).expect("aggregate R");
    checks.bytes(
        &prefix("aggregate_nonce_R"),
        &aggregate_nonce.to_compressed_bytes(),
        text(case, "aggregate_nonce_R_sec1"),
    );
    let aggregate_key = schnorr_add_public_keys(&signing_keys).expect("aggregate X");
    checks.bytes(
        &prefix("aggregate_excess_X"),
        &aggregate_key.to_compressed_bytes(),
        text(case, "aggregate_excess_X_sec1"),
    );
    let aggregate_nonce_hat = match adaptor_point.as_ref() {
        Some(point) => aggregate_public_nonces_v1(&[aggregate_nonce.clone(), point.clone()])
            .expect("aggregate R_hat"),
        None => aggregate_nonce.clone(),
    };
    checks.bytes(
        &prefix("R_hat"),
        &aggregate_nonce_hat.to_compressed_bytes(),
        text(case, "R_hat_sec1"),
    );

    checks.tagged(
        &prefix("challenge_hash"),
        "DOM:kernel-sig:v1",
        text(&case["challenge"], "tag_input_bytes"),
        text(&case["challenge"], "digest"),
    );
    let challenge = schnorr_challenge(
        &aggregate_nonce_hat.to_compressed_bytes(),
        &aggregate_key,
        &chain_id,
        &kernel_message,
    );
    checks.bytes(
        &prefix("challenge_scalar"),
        challenge.as_bytes(),
        text(&case["challenge"], "scalar_be32"),
    );
    let binding_partial = PartialSig::from_bytes(&binding.to_be_bytes()).expect("binding scalar");
    let expected_partials = case["partials"].as_array().expect("partials");
    let mut partial_messages = Vec::new();
    for (index, (nonce_pair, share)) in secret_nonces.into_iter().enumerate() {
        let partial = nonce_pair
            .sign_bound_partial(&binding_partial, challenge.as_bytes(), &share)
            .expect("production partial signing");
        checks.bytes(
            &prefix(&format!("partial[{index}].scalar")),
            &partial.to_bytes(),
            text(&expected_partials[index], "partial_scalar_be32"),
        );
        checks.truth(
            &prefix(&format!("partial[{index}].equation")),
            scriptless_verify_bound_partial(
                &partial,
                &effective[index],
                &signing_keys[index],
                challenge.as_bytes(),
            )
            .expect("partial verification"),
        );
        let message = PartialSignatureV1::new(
            purpose,
            participant_nonces[index].participant_index,
            template_hash,
            partial,
        );
        checks.bytes(
            &prefix(&format!("partial[{index}].payload")),
            &message.to_bytes(),
            text(&expected_partials[index], "partial_signature_v1_67"),
        );
        checks.truth(
            &prefix(&format!("partial[{index}].bound_api")),
            message
                .verify_bound(
                    purpose,
                    &template_hash,
                    &effective[index],
                    &signing_keys[index],
                    &aggregate_nonce_hat,
                    &aggregate_key,
                    &chain_id,
                    &kernel_message,
                )
                .expect("bound API verification"),
        );
        partial_messages.push(message);
    }

    let aggregate_partial =
        aggregate_partial_signatures_v1(&partial_messages, purpose, &template_hash)
            .expect("aggregate partials");
    checks.bytes(
        &prefix("aggregate_s_hat"),
        &aggregate_partial.to_bytes(),
        text(case, "aggregate_s_hat_be32"),
    );

    if purpose == PurposeV1::ClaimAdaptor {
        let adaptor_secret =
            AdaptorSecret::from_be_bytes(array(text(inputs, "adaptor_secret_be32")))
                .expect("adaptor secret");
        let pre_signature = AdaptorPreSignatureV1::new(
            template_hash,
            adaptor_point.expect("Claim adaptor point"),
            aggregate_nonce_hat,
            aggregate_partial,
            transcript_hash,
        );
        checks.bytes(
            &prefix("core_adaptor_pre_signature_65"),
            &pre_signature.core_bytes(),
            text(case, "core_adaptor_pre_signature_65"),
        );
        checks.bytes(
            &prefix("adaptor_pre_signature_v1_162"),
            &pre_signature.to_bytes(),
            text(case, "adaptor_pre_signature_v1_162"),
        );
        checks.truth(
            &prefix("pre_signature_equation"),
            pre_signature
                .verify(
                    &template_hash,
                    &transcript_hash,
                    &aggregate_key,
                    &chain_id,
                    &kernel_message,
                )
                .expect("pre-signature verification"),
        );
        let final_signature = pre_signature
            .adapt(
                &adaptor_secret,
                &template_hash,
                &transcript_hash,
                &aggregate_key,
                &chain_id,
                &kernel_message,
            )
            .expect("production adaptation");
        checks.bytes(
            &prefix("final_dom_signature_65"),
            &final_signature.to_bytes(),
            text(case, "final_dom_signature_65"),
        );
        checks.truth(
            &prefix("real_dom_verifier"),
            scriptless_verify_final_signature(
                &final_signature,
                &aggregate_key,
                &chain_id,
                &kernel_message,
            )
            .expect("real DOM verifier"),
        );
        let extracted = pre_signature
            .extract(
                &final_signature,
                &template_hash,
                &transcript_hash,
                &aggregate_key,
                &chain_id,
                &kernel_message,
            )
            .expect("production extraction");
        checks.bytes(
            &prefix("extracted_t_G"),
            &extracted.public_point().to_compressed_bytes(),
            text(case, "extracted_t_G_sec1"),
        );
    } else {
        let final_signature = finalize_plain_signature_v1(
            &partial_messages,
            purpose,
            &template_hash,
            &aggregate_nonce,
            &aggregate_key,
            &chain_id,
            &kernel_message,
        )
        .expect("production plain finalization");
        checks.bytes(
            &prefix("final_dom_signature_65"),
            &final_signature.to_bytes(),
            text(case, "final_dom_signature_65"),
        );
        checks.truth(
            &prefix("real_dom_verifier"),
            scriptless_verify_final_signature(
                &final_signature,
                &aggregate_key,
                &chain_id,
                &kernel_message,
            )
            .expect("real DOM verifier"),
        );
    }

    drop(commitment_payloads);
    drop(reveal_payloads);
}

fn main() {
    let vector_path = env::args()
        .nth(1)
        .expect("usage: phase1-comparison-harness FULL_VECTOR_JSON");
    let document: Value =
        serde_json::from_slice(&fs::read(&vector_path).expect("read frozen independent vectors"))
            .expect("parse frozen independent vectors");
    let mut checks = Checks { count: 0 };
    check_transcript_domain(&mut checks);
    for case in document["purpose_cases"].as_array().expect("purpose cases") {
        compare_case(&mut checks, &document, case);
    }
    println!("COMPARISON_COMPLETE\tmatched_fields={}", checks.count);
}
