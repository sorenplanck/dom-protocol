use dom_bp_migration_lab::{
    candidate::{CandidateOracle, UnavailableCandidate},
    corpus::deterministic_blind,
    Operation, OracleCase, ProveResult, VerifyResult,
};
use std::io::Write;
use std::process::{Command, Stdio};

fn request(value: u64) -> OracleCase {
    OracleCase {
        schema_version: 1,
        case_id: "deterministic-case".to_owned(),
        operation: Operation::ProveVerify,
        value,
        blind_hex: hex::encode(deterministic_blind(7)),
    }
}

fn run_line(line: &str) -> String {
    let executable = env!("CARGO_BIN_EXE_current-oracle");
    let mut child = Command::new(executable)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn current oracle");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(format!("{line}\n").as_bytes())
        .expect("write request");
    let output = child.wait_with_output().expect("wait oracle");
    assert!(output.status.success());
    String::from_utf8(output.stdout).expect("utf8 output")
}

#[test]
fn json_lines_output_is_deterministic_and_secret_free() {
    let line = serde_json::to_string(&request(1)).expect("request json");
    let first = run_line(&line);
    let second = run_line(&line);
    assert_eq!(first, second);
    assert!(!first.contains(&request(1).blind_hex));
    let response: serde_json::Value = serde_json::from_str(first.trim()).expect("response json");
    assert_eq!(response["prove_result"], "accepted");
    assert_eq!(response["verify_result"], "true");
    assert_eq!(response["proof_len"], 739);
}

#[test]
fn malformed_json_is_structured_and_does_not_panic() {
    let output = run_line("{bad json");
    let response: serde_json::Value = serde_json::from_str(output.trim()).expect("response json");
    assert_eq!(response["error_class"], "malformed_request");
    assert_eq!(response["verify_result"], "malformed");
}

#[test]
fn unavailable_candidate_fails_closed() {
    let candidate = UnavailableCandidate;
    let response = candidate.prove_verify(&request(1));
    assert_eq!(candidate.name(), "candidate_not_implemented");
    assert!(!candidate.supports_rewind());
    assert_eq!(response.prove_result, ProveResult::Error);
    assert_eq!(response.verify_result, VerifyResult::Malformed);
    assert_eq!(response.error_class, Some("candidate_not_implemented"));
}
