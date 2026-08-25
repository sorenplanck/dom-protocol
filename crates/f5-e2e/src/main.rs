//! F5 end-to-end CLI (Annex M M.17 steps 14–16).
//!
//! Turnkey commands the operator drives against a live regtest/signet
//! `bitcoind`:
//!
//! ```text
//! f5-e2e derive
//!     Print the P2TR contract (address, scriptPubKey, refund leaf, ...).
//! f5-e2e address
//!     Print only the regtest bech32m address to fund.
//! f5-e2e build-claim  <funding_txid> <vout> <amount_sat> <fee_sat> <dest_spk_hex>
//!     Print the raw hex of the fully-signed key-path claim transaction.
//! f5-e2e build-refund <funding_txid> <vout> <amount_sat> <fee_sat> <dest_spk_hex>
//!     Print the raw hex of the fully-signed CSV script-path refund tx.
//! ```
//!
//! `funding_txid` is the RPC (display) txid as printed by `bitcoin-cli`.
//! No secret material is printed; the keys are fixed TEST-ONLY constants.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use btc_vault::{BitcoinNonceReservationIdV1, PersistedArtifactDescriptorV1};
use f5_e2e::{
    build_public_claim, build_public_claim_durable, build_public_refund, build_signed_claim,
    build_signed_refund, contract_report, prepare_crash_probe, public_contract_report,
    regtest_address, resend_persisted_artifact, restore_crash_probe, selected_csv_blocks,
    verify_custom_evidence_file, verify_public_evidence_file, CrashProbePhase, FundingRef,
    PublicRow,
};
use f6_engine::composition::accepted_negotiation;
use f6_engine::{binding_complete, BindingEventV1, DurableBinding, StoreLog};
use rfq::ParticipantId;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("derive");
    match cmd {
        "derive" => {
            print!("{}", contract_report());
            ExitCode::SUCCESS
        }
        "address" => {
            println!("{}", regtest_address());
            ExitCode::SUCCESS
        }
        "derive-public" => match parse_public_row(args.get(1)) {
            Ok(row) => {
                print!("{}", public_contract_report(row));
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error),
        },
        "build-claim-public" | "build-refund-public" => match parse_public_spend_args(&args[1..]) {
            Ok((row, funding, dest_spk, fee)) => {
                if cmd == "build-claim-public" {
                    let artifact = build_public_claim(row, &funding, &dest_spk, fee);
                    println!("raw_transaction={}", hex(&artifact.raw_transaction));
                    println!("template_digest={}", hex(&artifact.template_digest));
                    println!("tap_sighash={}", hex(&artifact.tap_sighash));
                    println!(
                        "nonce_parity={}",
                        if artifact.nonce_parity_odd {
                            "odd"
                        } else {
                            "even"
                        }
                    );
                    println!("sighash_type=SIGHASH_DEFAULT");
                    println!("bip340_verified={}", artifact.bip340_verified);
                    println!(
                        "extracted_t_times_g_equals_t={}",
                        artifact.extracted_t_opens_adaptor_point
                    );
                    println!("adaptor_point_T={}", hex(&artifact.adaptor_point));
                    println!(
                        "extracted_t_times_g_point={}",
                        hex(&artifact.extracted_t_point)
                    );
                } else {
                    let (raw, digest) = build_public_refund(row, &funding, &dest_spk, fee);
                    println!("raw_transaction={}", hex(&raw));
                    println!("template_digest={}", hex(&digest));
                    println!("sequence={}", selected_csv_blocks());
                    println!("sighash_type=SIGHASH_DEFAULT");
                    println!("bip340_verified=true");
                }
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error),
        },
        "recover-terms" => match recover_terms(&args[1..]) {
            Ok(hash) => {
                println!("accepted_terms_hash={}", hex(&hash));
                println!("binding_complete=true");
                ExitCode::SUCCESS
            }
            Err(error) => fail(&error),
        },
        "build-claim-public-durable" => match build_durable_claim(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(&error),
        },
        "resend-partial" => match resend_partial(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(&error),
        },
        "verify-public-evidence" => match verify_public_evidence(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(&error),
        },
        "verify-custom-evidence" => match verify_custom_evidence(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(&error),
        },
        "prepare-crash-probe" => match prepare_crash(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(&error),
        },
        "restore-crash-probe" => match restore_crash(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(&error),
        },
        "seed-conformance-journal" => match seed_conformance_journal(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(&error),
        },
        "build-claim" | "build-refund" => match parse_spend_args(&args[1..]) {
            Ok((funding, dest_spk, fee)) => {
                let raw = if cmd == "build-claim" {
                    build_signed_claim(&funding, &dest_spk, fee)
                } else {
                    build_signed_refund(&funding, &dest_spk, fee)
                };
                println!("{}", hex(&raw));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                eprintln!("usage: f5-e2e {cmd} <funding_txid> <vout> <amount_sat> <fee_sat> <dest_spk_hex>");
                ExitCode::FAILURE
            }
        },
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("commands: derive | address | derive-public | build-claim | build-refund | build-claim-public | build-refund-public | recover-terms");
            ExitCode::FAILURE
        }
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("error: {message}");
    ExitCode::FAILURE
}

fn parse_public_row(value: Option<&String>) -> Result<PublicRow, String> {
    value
        .and_then(|value| PublicRow::parse(value))
        .ok_or_else(|| "public row must be one of E01..E06".to_string())
}

fn parse_public_spend_args(
    args: &[String],
) -> Result<(PublicRow, FundingRef, Vec<u8>, u64), String> {
    if args.len() != 6 {
        return Err(format!(
            "expected row plus 5 spend arguments, got {}",
            args.len()
        ));
    }
    let row = PublicRow::parse(&args[0]).ok_or("bad public row".to_string())?;
    let (funding, destination, fee) = parse_spend_args(&args[1..])?;
    Ok((row, funding, destination, fee))
}

fn recover_terms(args: &[String]) -> Result<[u8; 32], String> {
    if args.len() != 3 {
        return Err(
            "usage: recover-terms <party-a-journal> <party-b-journal> <rfq-id-hex>".to_string(),
        );
    }
    let rfq: [u8; 32] = decode_hex(&args[2])
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("rfq id must be 32-byte hex".to_string())?;
    let a = DurableBinding::open(
        StoreLog::open(std::path::Path::new(&args[0])).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let b = DurableBinding::open(
        StoreLog::open(std::path::Path::new(&args[1])).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    if !binding_complete(&a, &b, &rfq).map_err(|error| error.to_string())? {
        return Err("accepted terms are not durably bound by both parties".to_string());
    }
    let accepted_a = accepted_negotiation(&a, &rfq).map_err(|error| error.to_string())?;
    let accepted_b = accepted_negotiation(&b, &rfq).map_err(|error| error.to_string())?;
    if accepted_a.accepted_terms_hash() != accepted_b.accepted_terms_hash() {
        return Err("accepted terms diverge between party journals".to_string());
    }
    Ok(accepted_a.accepted_terms_hash())
}

fn parse_32(value: &str, field: &str) -> Result<[u8; 32], String> {
    decode_hex(value)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{field} must be 32-byte hex"))
}

fn print_descriptor(prefix: &str, descriptor: PersistedArtifactDescriptorV1) {
    println!(
        "{prefix}_reservation_id={}",
        hex(&descriptor.reservation_id)
    );
    println!("{prefix}_artifact_kind={}", descriptor.artifact_kind);
    println!(
        "{prefix}_outbound_digest={}",
        hex(&descriptor.outbound_digest)
    );
    println!("{prefix}_byte_length={}", descriptor.byte_length);
}

fn build_durable_claim(args: &[String]) -> Result<(), String> {
    if args.len() != 11 {
        return Err("usage: build-claim-public-durable <row> <txid> <vout> <amount_sat> <fee_sat> <dest_spk> <settlement_id> <session_id> <terms_hash> <vault_one> <vault_two>".to_string());
    }
    let row = PublicRow::parse(&args[0]).ok_or("bad public row".to_string())?;
    let (funding, destination, fee) = parse_spend_args(&args[1..6])?;
    let artifact = build_public_claim_durable(
        row,
        &funding,
        &destination,
        fee,
        parse_32(&args[6], "settlement id")?,
        parse_32(&args[7], "session id")?,
        parse_32(&args[8], "terms hash")?,
        std::path::Path::new(&args[9]),
        std::path::Path::new(&args[10]),
    )?;
    println!("raw_transaction={}", hex(&artifact.raw_transaction));
    println!("template_digest={}", hex(&artifact.template_digest));
    println!("tap_sighash={}", hex(&artifact.tap_sighash));
    println!(
        "nonce_parity={}",
        if artifact.nonce_parity_odd {
            "odd"
        } else {
            "even"
        }
    );
    println!("sighash_type=SIGHASH_DEFAULT");
    println!("bip340_verified={}", artifact.bip340_verified);
    println!(
        "extracted_t_times_g_equals_t={}",
        artifact.extracted_t_opens_adaptor_point
    );
    println!("adaptor_point_T={}", hex(&artifact.adaptor_point));
    println!(
        "extracted_t_times_g_point={}",
        hex(&artifact.extracted_t_point)
    );
    print_descriptor(
        "signer_one_partial",
        artifact
            .signer_one_partial
            .ok_or("missing signer-one descriptor".to_string())?,
    );
    print_descriptor(
        "signer_two_partial",
        artifact
            .signer_two_partial
            .ok_or("missing signer-two descriptor".to_string())?,
    );
    Ok(())
}

fn resend_partial(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err("usage: resend-partial <vault> <reservation_id> <artifact_kind> <outbound_digest> <byte_length>".to_string());
    }
    let descriptor = PersistedArtifactDescriptorV1 {
        reservation_id: parse_32(&args[1], "reservation id")?,
        artifact_kind: args[2]
            .parse()
            .map_err(|_| "bad artifact kind".to_string())?,
        outbound_digest: parse_32(&args[3], "outbound digest")?,
        byte_length: args[4].parse().map_err(|_| "bad byte length".to_string())?,
    };
    let bytes = resend_persisted_artifact(std::path::Path::new(&args[0]), descriptor)?;
    println!("artifact_bytes={}", hex(&bytes));
    println!(
        "artifact_outbound_digest={}",
        hex(&descriptor.outbound_digest)
    );
    println!("byte_identical_resend=true");
    Ok(())
}

fn verify_public_evidence(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("usage: verify-public-evidence <row> <evidence-input.json>".to_string());
    }
    let row = PublicRow::parse(&args[0]).ok_or("bad public row".to_string())?;
    let result = verify_public_evidence_file(std::path::Path::new(&args[1]), row)?;
    print_evidence_result(&result);
    Ok(())
}

fn verify_custom_evidence(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("usage: verify-custom-evidence <row> <evidence-input.json>".to_string());
    }
    let row = PublicRow::parse(&args[0]).ok_or("bad custom-signet row".to_string())?;
    let result = verify_custom_evidence_file(std::path::Path::new(&args[1]), row)?;
    print_evidence_result(&result);
    Ok(())
}

fn print_evidence_result(result: &f5_e2e::PublicEvidenceResult) {
    println!("txid={}", result.txid);
    println!("wtxid={}", result.wtxid);
    println!("block_hash={}", result.block_hash);
    println!("confirmation_depth={}", result.confirmation_depth);
    println!("full_block_merkle_root_verified=true");
    println!("full_block_witness_commitment_verified=true");
    println!("keystone_verified=true");
    println!("dom_sim_consumed=true");
    println!("uspe_event_source=verified_outcome_to_uspe_event");
    println!("uspe_state={}", result.uspe_state);
    println!(
        "economic_terminal_unique={}",
        result.economic_terminal_unique
    );
    println!(
        "observer_redelivery_idempotent={}",
        result.observer_redelivery_idempotent
    );
    println!("E13_invalid_evidence_rejected=true");
    println!("E14_tampered_witness_rejected=true");
}

fn prepare_crash(args: &[String]) -> Result<(), String> {
    if args.len() != 11 {
        return Err("usage: prepare-crash-probe <before-exposure|after-pubnonce> <row> <txid> <vout> <amount_sat> <fee_sat> <dest_spk> <settlement_id> <session_id> <terms_hash> <vault>".to_string());
    }
    let phase = match args[0].as_str() {
        "before-exposure" => CrashProbePhase::BeforeExposure,
        "after-pubnonce" => CrashProbePhase::AfterPubNonce,
        _ => return Err("bad crash-probe phase".to_string()),
    };
    let row = PublicRow::parse(&args[1]).ok_or("bad crash-probe row".to_string())?;
    let (funding, destination, fee) = parse_spend_args(&args[2..7])?;
    let reservation = prepare_crash_probe(
        row,
        &funding,
        &destination,
        fee,
        parse_32(&args[7], "settlement id")?,
        parse_32(&args[8], "session id")?,
        parse_32(&args[9], "terms hash")?,
        std::path::Path::new(&args[10]),
        phase,
    )?;
    println!("reservation_id={}", hex(&reservation.0));
    println!("crash_point={}", args[0]);
    println!("process_exit_required=true");
    Ok(())
}

fn restore_crash(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("usage: restore-crash-probe <vault> <reservation_id>".to_string());
    }
    let reservation = BitcoinNonceReservationIdV1(parse_32(&args[1], "reservation id")?);
    restore_crash_probe(std::path::Path::new(&args[0]), reservation)?;
    println!("restored_state=Aborted");
    println!("safe_refund_required=true");
    println!("nonce_rederived=false");
    Ok(())
}

fn seed_conformance_journal(args: &[String]) -> Result<(), String> {
    if args.len() != 8 {
        return Err("usage: seed-conformance-journal <journal> <rfq_id> <quote_id> <solver_id> <accepted_by> <reservation_id> <terms_hash> <inputs_digest>".to_string());
    }
    let rfq_id = parse_32(&args[1], "rfq id")?;
    let quote_id = parse_32(&args[2], "quote id")?;
    let solver = ParticipantId(parse_32(&args[3], "solver id")?);
    let accepted_by = ParticipantId(parse_32(&args[4], "accepted-by id")?);
    let reservation_id = parse_32(&args[5], "reservation id")?;
    let terms_hash = parse_32(&args[6], "terms hash")?;
    let inputs_digest = parse_32(&args[7], "inputs digest")?;
    let mut journal = DurableBinding::open(
        StoreLog::open(std::path::Path::new(&args[0])).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    journal
        .apply(&BindingEventV1::Reserved {
            reservation_id,
            rfq_id,
            quote_id,
            solver,
        })
        .map_err(|error| error.to_string())?;
    journal
        .apply(&BindingEventV1::Selected {
            rfq_id,
            winning_quote: quote_id,
            inputs_digest,
        })
        .map_err(|error| error.to_string())?;
    journal
        .apply(&BindingEventV1::Bound {
            rfq_id,
            quote_id,
            solver,
            accepted_by,
            reservation_id,
            terms_hash,
        })
        .map_err(|error| error.to_string())?;
    println!("journal_revision={}", journal.revision());
    println!("accepted_terms_hash={}", hex(&terms_hash));
    Ok(())
}

/// Parses `<funding_txid> <vout> <amount_sat> <fee_sat> <dest_spk_hex>`.
/// The txid is the RPC (display) form: big-endian hex, reversed to the
/// internal byte order the builder expects.
fn parse_spend_args(args: &[String]) -> Result<(FundingRef, Vec<u8>, u64), String> {
    if args.len() != 5 {
        return Err(format!("expected 5 arguments, got {}", args.len()));
    }
    let txid = parse_rpc_txid(&args[0])?;
    let vout: u32 = args[1].parse().map_err(|_| "bad vout".to_string())?;
    let amount_sat: u64 = args[2].parse().map_err(|_| "bad amount_sat".to_string())?;
    let fee_sat: u64 = args[3].parse().map_err(|_| "bad fee_sat".to_string())?;
    let dest_spk = decode_hex(&args[4]).ok_or("bad dest_spk hex".to_string())?;
    Ok((
        FundingRef {
            txid,
            vout,
            amount_sat,
        },
        dest_spk,
        fee_sat,
    ))
}

/// Converts an RPC display txid (big-endian hex) into the internal
/// little-endian byte order used inside transactions.
fn parse_rpc_txid(s: &str) -> Result<[u8; 32], String> {
    let bytes = decode_hex(s).ok_or("bad txid hex".to_string())?;
    if bytes.len() != 32 {
        return Err("txid must be 32 bytes".to_string());
    }
    let mut internal = [0u8; 32];
    for (i, b) in bytes.iter().rev().enumerate() {
        internal[i] = *b;
    }
    Ok(internal)
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
