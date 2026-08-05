use std::{env, fs};

use dom_adaptor::ShareProofV1;
use dom_crypto::{blake2b_256_tagged, scalar_from_wide_be, PublicKey};
use serde_json::Value;

const CONTEXT_TAG: &str = "DOM:scriptless-share-pop:v1";
const CHALLENGE_TAG: &str = "DOM:scriptless-share-pop-challenge:v1";

struct Checks(usize);

impl Checks {
    fn bytes(&mut self, name: &str, actual: &[u8], expected_hex: &str) {
        let expected = hex::decode(expected_hex)
            .unwrap_or_else(|error| panic!("invalid expected hex for {name}: {error}"));
        assert_eq!(actual, expected, "production mismatch at {name}");
        self.0 += 1;
        println!("MATCH\t{name}\t{}", hex::encode(actual));
    }

    fn truth(&mut self, name: &str, actual: bool) {
        assert!(actual, "production mismatch at {name}");
        self.0 += 1;
        println!("MATCH\t{name}\ttrue");
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

fn tagged_input(tag: &str, data: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(2 + tag.len() + data.len());
    framed.extend_from_slice(&(tag.len() as u16).to_le_bytes());
    framed.extend_from_slice(tag.as_bytes());
    framed.extend_from_slice(data);
    framed
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    assert_eq!(args.len(), 2, "usage: production-probe TRACE_JSON");
    let trace: Value = serde_json::from_str(&fs::read_to_string(&args[1]).expect("read trace"))
        .expect("parse trace JSON");
    let mut checks = Checks(0);

    for case in trace["cases"].as_array().expect("production cases") {
        let case_id = text(case, "case_id");
        let accepted = case["construction"]["accepted"]
            .as_bool()
            .expect("construction accepted Boolean");
        if !accepted {
            continue;
        }

        let statement = decode(text(case, "statement_bytes"));
        checks.truth(
            &format!("{case_id}.statement_length"),
            statement.len() == 202,
        );
        checks.truth(
            &format!("{case_id}.statement_magic"),
            &statement[..4] == b"DSPO",
        );
        checks.truth(
            &format!("{case_id}.statement_version"),
            &statement[4..6] == 1_u16.to_le_bytes().as_slice(),
        );
        PublicKey::from_compressed_bytes(&statement[105..138])
            .expect("production share point must parse");
        checks.bytes(
            &format!("{case_id}.share_point"),
            &statement[105..138],
            text(case, "share_point_sec1_33"),
        );
        checks.bytes(
            &format!("{case_id}.statement_tagged_input"),
            &tagged_input(CONTEXT_TAG, &statement),
            text(case, "statement_tagged_input_bytes"),
        );
        let context = blake2b_256_tagged(CONTEXT_TAG, &statement);
        checks.bytes(
            &format!("{case_id}.context_digest"),
            context.as_bytes(),
            text(case, "context_digest_32"),
        );

        let proof_bytes = decode(text(case, "proof_bytes"));
        let proof = ShareProofV1::from_bytes(&proof_bytes).expect("production proof must parse");
        checks.bytes(
            &format!("{case_id}.nonce_point"),
            &proof.commitment().to_compressed_bytes(),
            text(case, "pop_nonce_point_sec1_33"),
        );

        let mut challenge_preimage = Vec::with_capacity(98);
        challenge_preimage.extend_from_slice(context.as_bytes());
        challenge_preimage.extend_from_slice(&statement[105..138]);
        challenge_preimage.extend_from_slice(&proof.commitment().to_compressed_bytes());
        checks.bytes(
            &format!("{case_id}.challenge_preimage"),
            &challenge_preimage,
            text(case, "challenge_preimage_bytes"),
        );
        let mut challenge_input = challenge_preimage;
        challenge_input.extend_from_slice(&decode(text(case, "challenge_counter_u32_le")));
        checks.bytes(
            &format!("{case_id}.challenge_input"),
            &challenge_input,
            text(case, "challenge_input_bytes"),
        );

        let mut digest_0_data = Vec::with_capacity(103);
        digest_0_data.push(0);
        digest_0_data.extend_from_slice(&challenge_input);
        let mut digest_1_data = digest_0_data.clone();
        digest_1_data[0] = 1;
        checks.bytes(
            &format!("{case_id}.challenge_digest_0_data"),
            &digest_0_data,
            text(case, "challenge_digest_0_data_bytes"),
        );
        checks.bytes(
            &format!("{case_id}.challenge_digest_1_data"),
            &digest_1_data,
            text(case, "challenge_digest_1_data_bytes"),
        );
        checks.bytes(
            &format!("{case_id}.challenge_digest_0_tagged_input"),
            &tagged_input(CHALLENGE_TAG, &digest_0_data),
            text(case, "challenge_digest_0_tagged_input_bytes"),
        );
        checks.bytes(
            &format!("{case_id}.challenge_digest_1_tagged_input"),
            &tagged_input(CHALLENGE_TAG, &digest_1_data),
            text(case, "challenge_digest_1_tagged_input_bytes"),
        );
        let digest_0 = blake2b_256_tagged(CHALLENGE_TAG, &digest_0_data);
        let digest_1 = blake2b_256_tagged(CHALLENGE_TAG, &digest_1_data);
        checks.bytes(
            &format!("{case_id}.challenge_digest_0"),
            digest_0.as_bytes(),
            text(case, "challenge_digest_0_32"),
        );
        checks.bytes(
            &format!("{case_id}.challenge_digest_1"),
            digest_1.as_bytes(),
            text(case, "challenge_digest_1_32"),
        );
        let mut wide = [0_u8; 64];
        wide[..32].copy_from_slice(digest_0.as_bytes());
        wide[32..].copy_from_slice(digest_1.as_bytes());
        checks.bytes(
            &format!("{case_id}.challenge_wide_digest"),
            &wide,
            text(case, "challenge_wide_digest_64"),
        );
        let challenge = scalar_from_wide_be(&wide).expect("nonzero challenge");
        checks.bytes(
            &format!("{case_id}.challenge_reduced"),
            challenge.as_ref(),
            text(case, "challenge_reduced_be32"),
        );
        checks.bytes(
            &format!("{case_id}.response"),
            proof.response(),
            text(case, "response_be32"),
        );
        let mut zero_response = proof.to_bytes();
        zero_response[33..].fill(0);
        checks.truth(
            &format!("{case_id}.zero_response_is_canonical_in_production_codec"),
            ShareProofV1::from_bytes(&zero_response).is_ok(),
        );
    }

    println!("PRODUCTION_COMPARISON_COMPLETE matched_checks={}", checks.0);
}
