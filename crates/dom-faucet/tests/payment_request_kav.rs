//! dom-shield — KAV-negative + panic suite for the faucet untrusted parser.
//!
//! Surface: `parse_and_validate_payment_request` (private in production; reached
//! here through the default-off `shield-probe` feature). This is the ONLY
//! attacker-controlled parse surface of dom-faucet: it ingests the raw
//! `payment_request` String posted to `POST /api/request`.
//!
//! Lens A vectors covered:
//!   * correctness/conformance — known-answer NEGATIVE vectors: every documented
//!     rejection path must reject (malformed, amount!=faucet, commitment!=commit,
//!     wrong network, address!=commitment, bad header, unknown field, ...).
//!   * panic/crash — arbitrary-string proptest: the parser must never panic,
//!     only ever return Ok/Err.
//!
//! No production logic is touched: the probe is a thin Result-mapping re-export.

use dom_crypto::pedersen::Commitment;
use dom_crypto::BlindingFactor;
use dom_faucet::shield_probe::parse_and_validate;

// dom-core Address: payload is the 33-byte commitment, is_mainnet selects HRP.
use dom_core::Address;

const FAUCET_AMOUNT: u64 = 10_000;

/// Build a well-formed request that the parser MUST accept (the KAV "positive"
/// anchor — every negative below is a single mutation away from this).
fn valid_request() -> String {
    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("valid blinding");
    let commitment = Commitment::commit(FAUCET_AMOUNT, &blinding);
    let address = Address::new(*commitment.as_bytes(), false).encode();
    format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork=testnet\namount_noms={amount}\naddress={addr}\ncommitment={c}\nblinding={b}",
        amount = FAUCET_AMOUNT,
        addr = address,
        c = hex::encode(commitment.as_bytes()),
        b = hex::encode(blinding.as_bytes()),
    )
}

#[test]
fn kav_positive_anchor_accepts() {
    // Sanity: the anchor parses, so every negative below isolates ONE rejection.
    assert!(
        parse_and_validate(&valid_request(), FAUCET_AMOUNT).is_ok(),
        "the well-formed anchor request must be accepted"
    );
}

#[test]
fn kav_empty_input_rejected() {
    let err = parse_and_validate("", FAUCET_AMOUNT).unwrap_err();
    assert!(err.contains("required"), "got: {err}");
}

#[test]
fn kav_wrong_header_rejected() {
    let req = valid_request().replace("DOM-PAYMENT-REQUEST-V1", "DOM-PAYMENT-REQUEST-V2");
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(
        err.contains("unsupported payment request header"),
        "got: {err}"
    );
}

#[test]
fn kav_malformed_line_no_equals_rejected() {
    let req = valid_request().replace("network=testnet", "network testnet");
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(err.contains("invalid payment request line"), "got: {err}");
}

#[test]
fn kav_unknown_field_rejected() {
    let req = format!("{}\nattacker_field=1", valid_request());
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(err.contains("unknown payment request field"), "got: {err}");
}

#[test]
fn kav_amount_not_equal_faucet_amount_rejected() {
    // Same well-formed request, but the faucet is configured for a different amount.
    let err = parse_and_validate(&valid_request(), FAUCET_AMOUNT + 1).unwrap_err();
    assert!(err.contains("must equal faucet amount"), "got: {err}");
}

#[test]
fn kav_amount_unparseable_rejected() {
    let req = valid_request().replace(
        &format!("amount_noms={FAUCET_AMOUNT}"),
        "amount_noms=not_a_number",
    );
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(err.contains("invalid amount_noms"), "got: {err}");
}

#[test]
fn kav_missing_network_rejected() {
    let req = valid_request().replace("network=testnet\n", "");
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(err.contains("missing network"), "got: {err}");
}

#[test]
fn kav_unknown_network_rejected() {
    let req = valid_request().replace("network=testnet", "network=quantumnet");
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(err.contains("unknown network"), "got: {err}");
}

#[test]
fn kav_wrong_network_vs_address_rejected() {
    // address is testnet (built with is_mainnet=false), but request claims mainnet.
    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("valid blinding");
    let commitment = Commitment::commit(FAUCET_AMOUNT, &blinding);
    let address = Address::new(*commitment.as_bytes(), false).encode(); // testnet HRP
    let req = format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork=mainnet\namount_noms={amount}\naddress={addr}\ncommitment={c}\nblinding={b}",
        amount = FAUCET_AMOUNT,
        addr = address,
        c = hex::encode(commitment.as_bytes()),
        b = hex::encode(blinding.as_bytes()),
    );
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(err.contains("address network does not match"), "got: {err}");
}

#[test]
fn kav_commitment_not_33_bytes_rejected() {
    // Structurally-valid hex but wrong length (2 bytes instead of 33).
    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("valid blinding");
    let commitment = Commitment::commit(FAUCET_AMOUNT, &blinding);
    let address = Address::new(*commitment.as_bytes(), false).encode();
    let req = format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork=testnet\namount_noms={amount}\naddress={addr}\ncommitment=abcd\nblinding={b}",
        amount = FAUCET_AMOUNT,
        addr = address,
        b = hex::encode(blinding.as_bytes()),
    );
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(
        err.contains("commitment must be 33 bytes") || err.contains("commitment hex"),
        "got: {err}"
    );
}

#[test]
fn kav_commitment_not_hex_rejected() {
    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("valid blinding");
    let commitment = Commitment::commit(FAUCET_AMOUNT, &blinding);
    let address = Address::new(*commitment.as_bytes(), false).encode();
    let req = format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork=testnet\namount_noms={amount}\naddress={addr}\ncommitment=zzzz\nblinding={b}",
        amount = FAUCET_AMOUNT,
        addr = address,
        b = hex::encode(blinding.as_bytes()),
    );
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(err.contains("commitment hex"), "got: {err}");
}

#[test]
fn kav_address_does_not_match_commitment_rejected() {
    // Valid commitment field, but the address encodes a DIFFERENT commitment.
    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("valid blinding");
    let commitment = Commitment::commit(FAUCET_AMOUNT, &blinding);
    let other_blinding = BlindingFactor::from_bytes([8u8; 32]).expect("valid blinding");
    let other_commitment = Commitment::commit(FAUCET_AMOUNT, &other_blinding);
    let mismatched_address = Address::new(*other_commitment.as_bytes(), false).encode();
    let req = format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork=testnet\namount_noms={amount}\naddress={addr}\ncommitment={c}\nblinding={b}",
        amount = FAUCET_AMOUNT,
        addr = mismatched_address,
        c = hex::encode(commitment.as_bytes()),
        b = hex::encode(blinding.as_bytes()),
    );
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(
        err.contains("address payload does not match commitment field"),
        "got: {err}"
    );
}

#[test]
fn kav_commitment_not_equal_commit_amount_blinding_rejected() {
    // address matches the (forged) commitment, but commit(amount,blinding) != it.
    // Build address from the forged commitment so the address-match check passes
    // and we reach the final commit() verification.
    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("valid blinding");
    let real_commitment = Commitment::commit(FAUCET_AMOUNT, &blinding);
    // forge a commitment that is a VALID 33-byte point-encoding but != commit():
    // reuse a different value's commitment under the SAME blinding.
    let forged = Commitment::commit(FAUCET_AMOUNT + 1, &blinding);
    let address = Address::new(*forged.as_bytes(), false).encode();
    let req = format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork=testnet\namount_noms={amount}\naddress={addr}\ncommitment={c}\nblinding={b}",
        amount = FAUCET_AMOUNT,
        addr = address,
        c = hex::encode(forged.as_bytes()),
        b = hex::encode(blinding.as_bytes()),
    );
    let _ = real_commitment;
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(
        err.contains("commitment does not match amount + blinding"),
        "got: {err}"
    );
}

#[test]
fn kav_blinding_wrong_length_rejected() {
    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("valid blinding");
    let commitment = Commitment::commit(FAUCET_AMOUNT, &blinding);
    let address = Address::new(*commitment.as_bytes(), false).encode();
    let req = format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork=testnet\namount_noms={amount}\naddress={addr}\ncommitment={c}\nblinding=00ff",
        amount = FAUCET_AMOUNT,
        addr = address,
        c = hex::encode(commitment.as_bytes()),
    );
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(
        err.contains("blinding must be 32 bytes") || err.contains("blinding hex"),
        "got: {err}"
    );
}

#[test]
fn kav_blinding_zero_rejected() {
    // 32 zero bytes is a structurally-valid hex of right length but an invalid
    // (zero) blinding factor — must be rejected by BlindingFactor::from_bytes.
    let blinding = BlindingFactor::from_bytes([7u8; 32]).expect("valid blinding");
    let commitment = Commitment::commit(FAUCET_AMOUNT, &blinding);
    let address = Address::new(*commitment.as_bytes(), false).encode();
    let req = format!(
        "DOM-PAYMENT-REQUEST-V1\nnetwork=testnet\namount_noms={amount}\naddress={addr}\ncommitment={c}\nblinding={zero}",
        amount = FAUCET_AMOUNT,
        addr = address,
        c = hex::encode(commitment.as_bytes()),
        zero = "00".repeat(32),
    );
    let err = parse_and_validate(&req, FAUCET_AMOUNT).unwrap_err();
    assert!(err.contains("blinding"), "got: {err}");
}

// --------------------------- panic / fuzz-lite -----------------------------

proptest::proptest! {
    // Vector: parser must NEVER panic on arbitrary attacker input.
    // (A cheap proptest companion to the cargo-fuzz target; runs in CI seconds.)
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(2048))]

    #[test]
    fn parser_never_panics_on_arbitrary_string(s in ".{0,512}", amount in any_u64()) {
        // Only assertion: it returns (Ok|Err), i.e. it does not panic/abort.
        let _ = parse_and_validate(&s, amount);
    }

    #[test]
    fn parser_never_panics_on_keyword_soup(
        lines in proptest::collection::vec(
            proptest::string::string_regex("(network|amount_noms|address|commitment|blinding|x)=?[0-9a-fA-F]{0,80}").unwrap(),
            0..12,
        ),
        amount in any_u64(),
    ) {
        let body = format!("DOM-PAYMENT-REQUEST-V1\n{}", lines.join("\n"));
        let _ = parse_and_validate(&body, amount);
    }
}

fn any_u64() -> impl proptest::strategy::Strategy<Value = u64> {
    proptest::prelude::any::<u64>()
}
