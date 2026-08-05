//! Post-freeze probe over the production backend at the separately verified path.

use std::{fs, path::PathBuf};

use dom_adaptor::ShareProofV1;
use dom_crypto::{
    blake2b_256_tagged, scalar_from_wide_be, secret_scalar_mul_add_assign,
    secret_scalar_public_key, verify_scalar_response, PublicKey,
};
use zeroize::Zeroizing;

const EXPECTED_PRODUCTION_COMMIT: &str = "67fe11c441c2b7801b6f70809ab58caa4804c22a";
const CONTEXT_TAG: &str = "DOM:scriptless-share-pop:v1";
const CHALLENGE_TAG: &str = "DOM:scriptless-share-pop-challenge:v1";
const CHAIN_ID: [u8; 32] = [0x11; 32];
const SESSION_ID: [u8; 32] = [0x22; 32];
const ROSTER: [[u8; 32]; 2] = [[0x21; 32], [0x42; 32]];
const TERMS_HASH: [u8; 32] = [0x33; 32];
const RECOVERY_BINDING_HASH: [u8; 32] = [0x44; 32];
const SIGNING_SHARE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
];
const NONCE_SCALAR: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9,
];
const GROUP_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

struct Checks {
    evidence_dir: PathBuf,
    matched: usize,
}

impl Checks {
    fn bytes(&mut self, name: &str, actual: &[u8], file_name: &str) {
        let expected = fs::read(self.evidence_dir.join(file_name))
            .unwrap_or_else(|error| panic!("read {file_name}: {error}"));
        assert_eq!(actual, expected, "production mismatch at {name}");
        self.matched += 1;
        println!("MATCH\t{name}\tbytes={}", actual.len());
    }

    fn same_bytes(&mut self, name: &str, actual: &[u8], expected: &[u8]) {
        assert_eq!(actual, expected, "production mismatch at {name}");
        self.matched += 1;
        println!("MATCH\t{name}\tbytes={}", actual.len());
    }

    fn truth(&mut self, name: &str, actual: bool) {
        assert!(actual, "production mismatch at {name}");
        self.matched += 1;
        println!("MATCH\t{name}\ttrue");
    }
}

fn tagged_preimage(tag: &str, data: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(2 + tag.len() + data.len());
    preimage.extend_from_slice(&(tag.len() as u16).to_le_bytes());
    preimage.extend_from_slice(tag.as_bytes());
    preimage.extend_from_slice(data);
    preimage
}

fn statement_bytes(share_point: &[u8; 33]) -> [u8; 202] {
    // This is kept visibly isomorphic to SharePoPStatementV1::new at the
    // inspected production commit so every field boundary is compared.
    let mut statement = [0_u8; 202];
    statement[..4].copy_from_slice(b"DSPO");
    statement[4..6].copy_from_slice(&1_u16.to_le_bytes());
    statement[6..38].copy_from_slice(&CHAIN_ID);
    statement[38..70].copy_from_slice(&SESSION_ID);
    statement[70..102].copy_from_slice(&ROSTER[0]);
    statement[102] = 0x01;
    statement[103..105].copy_from_slice(&0_u16.to_le_bytes());
    statement[105..138].copy_from_slice(share_point);
    statement[138..170].copy_from_slice(&TERMS_HASH);
    statement[170..202].copy_from_slice(&RECOVERY_BINDING_HASH);
    statement
}

struct Challenge {
    input: [u8; 102],
    counter: [u8; 4],
    d0_data: [u8; 103],
    d0_preimage: Vec<u8>,
    d0: [u8; 32],
    d1_data: [u8; 103],
    d1_preimage: Vec<u8>,
    d1: [u8; 32],
    wide: [u8; 64],
    scalar: Zeroizing<[u8; 32]>,
}

fn challenge(
    context_digest: &[u8; 32],
    share_point: &[u8; 33],
    nonce_commitment: &[u8; 33],
) -> Challenge {
    let mut input = [0_u8; 102];
    input[..32].copy_from_slice(context_digest);
    input[32..65].copy_from_slice(share_point);
    input[65..98].copy_from_slice(nonce_commitment);
    let mut counter = 0_u32;
    loop {
        let counter_bytes = counter.to_le_bytes();
        input[98..].copy_from_slice(&counter_bytes);
        let mut d0_data = [0_u8; 103];
        d0_data[1..].copy_from_slice(&input);
        let mut d1_data = d0_data;
        d1_data[0] = 1;
        let d0_hash = blake2b_256_tagged(CHALLENGE_TAG, &d0_data);
        let d1_hash = blake2b_256_tagged(CHALLENGE_TAG, &d1_data);
        let d0 = *d0_hash.as_bytes();
        let d1 = *d1_hash.as_bytes();
        let mut wide = [0_u8; 64];
        wide[..32].copy_from_slice(&d0);
        wide[32..].copy_from_slice(&d1);
        if let Some(scalar) = scalar_from_wide_be(&wide) {
            return Challenge {
                input,
                counter: counter_bytes,
                d0_data,
                d0_preimage: tagged_preimage(CHALLENGE_TAG, &d0_data),
                d0,
                d1_data,
                d1_preimage: tagged_preimage(CHALLENGE_TAG, &d1_data),
                d1,
                wide,
                scalar,
            };
        }
        counter = counter.checked_add(1).expect("challenge counter overflow");
    }
}

fn production_profile_statement_parses(
    statement: &[u8],
    share_point_out: &mut Option<PublicKey>,
) -> bool {
    if statement.len() != 202
        || &statement[..4] != b"DSPO"
        || statement[4..6] != 1_u16.to_le_bytes()
    {
        return false;
    }
    let index = usize::from(u16::from_le_bytes([statement[103], statement[104]]));
    if index >= ROSTER.len()
        || ROSTER.windows(2).any(|pair| pair[0] >= pair[1])
        || ROSTER[index] != statement[70..102]
        || statement[6..38] != CHAIN_ID
        || statement[38..70] == [0_u8; 32]
        || statement[70..102] == [0_u8; 32]
        || statement[138..170] == [0_u8; 32]
        || statement[170..202] == [0_u8; 32]
        || !matches!(statement[102], 0x01 | 0x02)
    {
        return false;
    }
    let Ok(point) = PublicKey::from_compressed_bytes(&statement[105..138]) else {
        return false;
    };
    if point.to_compressed_bytes().as_slice() != &statement[105..138] {
        return false;
    }
    *share_point_out = Some(point);
    true
}

fn production_profile_verifies(statement: &[u8], proof: &[u8]) -> bool {
    let mut share_point = None;
    if !production_profile_statement_parses(statement, &mut share_point) {
        return false;
    }
    let Ok(parsed_proof) = ShareProofV1::from_bytes(proof) else {
        return false;
    };
    let context = blake2b_256_tagged(CONTEXT_TAG, statement);
    let challenge = challenge(
        context.as_bytes(),
        &share_point
            .as_ref()
            .expect("set after parse")
            .to_compressed_bytes(),
        &parsed_proof.commitment().to_compressed_bytes(),
    );
    verify_scalar_response(
        parsed_proof.response(),
        parsed_proof.commitment(),
        &*challenge.scalar,
        share_point.as_ref().expect("set after parse"),
    )
    .unwrap_or(false)
}

fn main() {
    let manifest_dir = option_env!("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("probe current directory"));
    let evidence_dir = manifest_dir
        .parent()
        .expect("probe has evidence parent")
        .to_path_buf();
    let mut checks = Checks {
        evidence_dir,
        matched: 0,
    };

    println!("PRODUCTION_COMMIT_EXPECTED\t{EXPECTED_PRODUCTION_COMMIT}");

    let share_point = secret_scalar_public_key(&SIGNING_SHARE)
        .expect("production share scalar")
        .to_compressed_bytes();
    checks.bytes("share_point", &share_point, "share-point.bin");

    let nonce_commitment = secret_scalar_public_key(&NONCE_SCALAR)
        .expect("production nonce scalar")
        .to_compressed_bytes();
    checks.bytes(
        "nonce_commitment",
        &nonce_commitment,
        "nonce-commitment.bin",
    );

    let statement = statement_bytes(&share_point);
    checks.bytes("statement", &statement, "statement.bin");
    let context_preimage = tagged_preimage(CONTEXT_TAG, &statement);
    checks.bytes(
        "context_preimage",
        &context_preimage,
        "context-preimage.bin",
    );
    let context_digest = blake2b_256_tagged(CONTEXT_TAG, &statement);
    checks.bytes(
        "context_digest",
        context_digest.as_bytes(),
        "context-digest.bin",
    );

    let challenge = challenge(context_digest.as_bytes(), &share_point, &nonce_commitment);
    checks.bytes("challenge_input", &challenge.input, "challenge-input.bin");
    checks.bytes(
        "challenge_counter_u32_le",
        &challenge.counter,
        "challenge-counter-u32-le.bin",
    );
    checks.bytes(
        "challenge_d0_data",
        &challenge.d0_data,
        "challenge-d0-data.bin",
    );
    checks.bytes(
        "challenge_d0_preimage",
        &challenge.d0_preimage,
        "challenge-d0-preimage.bin",
    );
    checks.bytes("challenge_d0", &challenge.d0, "challenge-d0.bin");
    checks.bytes(
        "challenge_d1_data",
        &challenge.d1_data,
        "challenge-d1-data.bin",
    );
    checks.bytes(
        "challenge_d1_preimage",
        &challenge.d1_preimage,
        "challenge-d1-preimage.bin",
    );
    checks.bytes("challenge_d1", &challenge.d1, "challenge-d1.bin");
    checks.bytes("challenge_wide", &challenge.wide, "challenge-wide.bin");
    checks.bytes(
        "challenge_reduced_scalar",
        &*challenge.scalar,
        "challenge-scalar.bin",
    );

    let mut response = Zeroizing::new(NONCE_SCALAR);
    secret_scalar_mul_add_assign(&mut response, &SIGNING_SHARE, &*challenge.scalar)
        .expect("production response arithmetic");
    checks.bytes("response", response.as_ref(), "response.bin");

    let mut proof_bytes = [0_u8; 65];
    proof_bytes[..33].copy_from_slice(&nonce_commitment);
    proof_bytes[33..].copy_from_slice(response.as_ref());
    checks.bytes("proof", &proof_bytes, "proof.bin");
    let proof = ShareProofV1::from_bytes(&proof_bytes).expect("production proof parser");
    checks.same_bytes("proof_codec_roundtrip", &proof.to_bytes(), &proof_bytes);
    checks.truth(
        "verification_equation",
        verify_scalar_response(
            proof.response(),
            proof.commitment(),
            &*challenge.scalar,
            &secret_scalar_public_key(&SIGNING_SHARE).expect("share point"),
        )
        .expect("production verification"),
    );
    checks.truth(
        "production_profile_verification",
        production_profile_verifies(&statement, &proof_bytes),
    );

    let mut zero_response = proof_bytes;
    zero_response[33..].fill(0);
    checks.truth(
        "zero_response_is_codec_canonical",
        ShareProofV1::from_bytes(&zero_response).is_ok(),
    );
    let mut order_response = proof_bytes;
    order_response[33..].copy_from_slice(&GROUP_ORDER);
    checks.truth(
        "group_order_response_is_rejected",
        ShareProofV1::from_bytes(&order_response).is_err(),
    );

    let mut statement_mutations = 0_usize;
    for offset in 0..statement.len() {
        for bit in 0..8 {
            let mut mutated = statement;
            mutated[offset] ^= 1 << bit;
            assert!(
                !production_profile_verifies(&mutated, &proof_bytes),
                "production accepted statement mutation offset={offset} bit={bit}"
            );
            statement_mutations += 1;
        }
    }
    checks.truth(
        "all_1616_statement_one_bit_mutations_rejected",
        statement_mutations == 202 * 8,
    );

    let mut proof_mutations = 0_usize;
    for offset in 0..proof_bytes.len() {
        for bit in 0..8 {
            let mut mutated = proof_bytes;
            mutated[offset] ^= 1 << bit;
            assert!(
                !production_profile_verifies(&statement, &mutated),
                "production accepted proof mutation offset={offset} bit={bit}"
            );
            proof_mutations += 1;
        }
    }
    checks.truth(
        "all_520_proof_one_bit_mutations_rejected",
        proof_mutations == 65 * 8,
    );

    println!(
        "PRODUCTION_COMPARISON_COMPLETE\tmatched_checks={}\tstatement_mutations={}\tproof_mutations={}\tdiscrepancies=0",
        checks.matched, statement_mutations, proof_mutations
    );
}
