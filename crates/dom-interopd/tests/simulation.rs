#![cfg(feature = "simulation")]

use std::error::Error;
use std::path::Path;
use std::process::{Command, Output};

use dom_interopd::SIMULATION_CRASH_EXIT_CODE_V1;
use rusqlite::Connection;
use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_dom-interopd")
}

fn invoke(state_dir: &Path, scenario: &str, crash_after: Option<&str>) -> Output {
    let mut command = Command::new(binary());
    command
        .arg("simulate")
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--scenario")
        .arg(scenario);
    if let Some(point) = crash_after {
        command.arg("--crash-after").arg(point);
    }
    command.output().expect("run dom-interopd subprocess")
}

fn successful_json(output: Output) -> Value {
    assert!(
        output.status.success(),
        "daemon failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    serde_json::from_slice(&output.stdout).expect("one valid JSON report")
}

fn assert_terminal_common(report: &Value, scenario: &str) {
    assert_eq!(report["schema"], "dom-interopd-simulation-v1");
    assert_eq!(report["build_mode"], "simulation");
    assert_eq!(report["scenario"], scenario);
    assert_eq!(report["terminal"], true);
    assert_eq!(report["pending_effects"], 0);
    assert_eq!(report["active_timers"], 0);
    assert_eq!(report["takeover_unknown"], 0);
    assert_eq!(report["unique_externalizations"], 4);
    assert_eq!(report["economic_broadcasts"], 4);
    assert_eq!(report["consumed_attempt_capabilities"], 4);
    assert_eq!(
        report["journal_entries"].as_u64(),
        report["revision"].as_u64()
    );
    assert_eq!(report["route_id"].as_str().unwrap().len(), 64);
    assert_eq!(report["authority_state_digest"].as_str().unwrap().len(), 64);
    let externalizations = report["externalizations"].as_array().unwrap();
    assert_eq!(externalizations.len(), 4);
    for externalization in externalizations {
        assert_eq!(externalization["broadcast_count"], 1);
        assert_eq!(externalization["delivery_attempts"], 1);
        assert_eq!(externalization["effect_id"].as_str().unwrap().len(), 64);
        assert_eq!(
            externalization["transaction_id"].as_str().unwrap().len(),
            64
        );
    }
    let encoded = serde_json::to_string(report).unwrap();
    for prohibited in [
        "route_scalar",
        "secret_bytes",
        "secret_payload",
        "private_key",
    ] {
        assert!(!encoded.contains(prohibited));
    }
}

#[test]
fn claim_cli_is_terminal_and_reopen_is_economically_idempotent() {
    let state = tempfile::tempdir().unwrap();
    let first = successful_json(invoke(state.path(), "claim", None));
    assert_terminal_common(&first, "claim");
    assert_eq!(first["secret_public"], true);
    assert_eq!(first["upstream_outcome"], "claim_final");
    assert_eq!(first["downstream_outcome"], "claim_final");
    assert_eq!(first["urgent_externalizations"], 1);
    assert_eq!(first["invocation"], 1);
    assert_eq!(first["fencing_epoch"], 1);

    let reopened = successful_json(invoke(state.path(), "claim", None));
    assert_terminal_common(&reopened, "claim");
    assert_eq!(reopened["invocation"], 2);
    assert_eq!(reopened["fencing_epoch"], 2);
    for immutable in [
        "route_id",
        "revision",
        "journal_entries",
        "journal_head_digest",
        "authority_state_digest",
        "externalizations",
    ] {
        assert_eq!(reopened[immutable], first[immutable], "changed {immutable}");
    }
}

#[test]
fn refund_cli_is_authorized_by_durable_deadlines_and_reaches_terminal() -> Result<(), Box<dyn Error>>
{
    let state = tempfile::tempdir()?;
    let report = successful_json(invoke(state.path(), "refund", None));
    assert_terminal_common(&report, "refund");
    assert_eq!(report["secret_public"], false);
    assert_eq!(report["upstream_outcome"], "refund_final");
    assert_eq!(report["downstream_outcome"], "refund_final");
    assert_eq!(report["urgent_externalizations"], 0);

    let authority = Connection::open(state.path().join("chain-authority.sqlite3"))?;
    let deadline_count: i64 =
        authority.query_row("SELECT COUNT(*) FROM deadline_firings", [], |row| {
            row.get(0)
        })?;
    assert_eq!(deadline_count, 2);
    let refund_count: i64 = authority.query_row(
        "SELECT COUNT(*) FROM externalizations WHERE action_tag = 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(refund_count, 2);
    Ok(())
}

#[test]
fn crash_after_secret_broadcast_persist_reconciles_same_transaction_once(
) -> Result<(), Box<dyn Error>> {
    let state = tempfile::tempdir()?;
    let crashed = invoke(state.path(), "claim", Some("authority-persist"));
    assert_eq!(
        crashed.status.code(),
        Some(i32::from(SIMULATION_CRASH_EXIT_CODE_V1))
    );
    assert!(crashed.stdout.is_empty());
    assert!(crashed.stderr.is_empty());

    let authority_path = state.path().join("chain-authority.sqlite3");
    let authority = Connection::open(&authority_path)?;
    let before: (Vec<u8>, Vec<u8>, i64) = authority.query_row(
        "SELECT effect_id, transaction_id, broadcast_count
         FROM externalizations WHERE leg_tag = 1 AND action_tag = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(before.0.len(), 32);
    assert_eq!(before.1.len(), 32);
    assert_eq!(before.2, 1);
    drop(authority);

    let report = successful_json(invoke(state.path(), "claim", None));
    assert_terminal_common(&report, "claim");
    assert_eq!(report["invocation"], 2);
    assert_eq!(report["fencing_epoch"], 2);
    assert_eq!(report["takeover_externalized"], 1);
    assert_eq!(report["takeover_reauthorized"], 0);
    assert_eq!(report["urgent_externalizations"], 1);

    let authority = Connection::open(&authority_path)?;
    let after: (Vec<u8>, Vec<u8>, i64, i64) = authority.query_row(
        "SELECT effect_id, transaction_id, broadcast_count, delivery_attempts
         FROM externalizations WHERE leg_tag = 1 AND action_tag = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(after.0, before.0);
    assert_eq!(after.1, before.1);
    assert_eq!(after.2, 1);
    assert_eq!(after.3, 1);
    Ok(())
}

#[test]
fn crash_after_timer_event_commit_redelivers_duplicate_then_refunds() -> Result<(), Box<dyn Error>>
{
    let state = tempfile::tempdir()?;
    let crashed = invoke(state.path(), "refund", Some("timer-event-commit"));
    assert_eq!(
        crashed.status.code(),
        Some(i32::from(SIMULATION_CRASH_EXIT_CODE_V1))
    );
    assert!(crashed.stdout.is_empty());
    assert!(crashed.stderr.is_empty());

    let authority_path = state.path().join("chain-authority.sqlite3");
    let authority = Connection::open(&authority_path)?;
    let deadlines: i64 =
        authority.query_row("SELECT COUNT(*) FROM deadline_firings", [], |row| {
            row.get(0)
        })?;
    let refunds: i64 = authority.query_row(
        "SELECT COUNT(*) FROM externalizations WHERE action_tag = 2",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(deadlines, 1);
    assert_eq!(refunds, 0);
    drop(authority);

    let report = successful_json(invoke(state.path(), "refund", None));
    assert_terminal_common(&report, "refund");
    assert_eq!(report["fencing_epoch"], 2);
    assert_eq!(report["duplicate_timer_events"], 1);
    assert_eq!(report["takeover_externalized"], 0);
    assert_eq!(report["takeover_reauthorized"], 0);
    Ok(())
}

#[test]
fn cli_and_durable_scenario_binding_fail_closed() {
    let state = tempfile::tempdir().unwrap();
    let invalid = Command::new(binary())
        .arg("simulate")
        .arg("--state-dir")
        .arg(state.path())
        .arg("--scenario")
        .arg("unknown")
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));

    assert!(invoke(state.path(), "claim", None).status.success());
    let mismatch = invoke(state.path(), "refund", None);
    assert_eq!(mismatch.status.code(), Some(1));
    assert!(mismatch.stdout.is_empty());
    assert_eq!(
        String::from_utf8(mismatch.stderr).unwrap().trim(),
        "simulation state scenario mismatch"
    );
}

#[test]
fn corrupted_public_authority_receipt_is_not_reported_as_terminal() -> Result<(), Box<dyn Error>> {
    let state = tempfile::tempdir()?;
    assert!(invoke(state.path(), "claim", None).status.success());
    let authority_path = state.path().join("chain-authority.sqlite3");
    let authority = Connection::open(authority_path)?;
    authority.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         UPDATE externalizations SET transaction_id = zeroblob(32)
         WHERE effect_id = (SELECT MIN(effect_id) FROM externalizations);",
    )?;
    drop(authority);

    let refused = invoke(state.path(), "claim", None);
    assert_eq!(refused.status.code(), Some(1));
    assert!(refused.stdout.is_empty());
    assert_eq!(
        String::from_utf8(refused.stderr).unwrap().trim(),
        "simulation authority state is inconsistent"
    );
    Ok(())
}
