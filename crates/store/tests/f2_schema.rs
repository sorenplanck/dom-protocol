//! F2 core schema integrity (F2 spec §8.1) — migration, STRICT/CHECK
//! constraints, foreign keys and the unique terminal row.
//!
//! These tests exercise the SCHEMA, not the settlement operations (those
//! arrive with the `SettlementStore` implementation, build order §24
//! step 5): what must hold here is that the database itself refuses
//! malformed rows, orphan references and a second terminal outcome, and
//! that migration is idempotent, upgrade-safe and downgrade-closed.

use rusqlite::Connection;
use store::{
    CommitOutcome, ExternalCustodyCompletion, ExternalCustodyInsert, F2OutboxDeliveryStatusV1,
    F2OutboxDispatchClassV1, ProductionStoreBindingV1, SettlementCommit, SettlementCreate, Store,
    StoreError, SCHEMA_VERSION,
};
use tempfile::tempdir;

const F2_TABLES: [&str; 8] = [
    "settlement_terms",
    "settlement_snapshot",
    "settlement_journal",
    "chain_cursor",
    "observed_evidence",
    "durable_outbox",
    "terminal_outcome",
    "late_evidence",
];

fn raw(path: &std::path::Path) -> Connection {
    let conn = Connection::open(path).expect("open raw connection");
    conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    conn
}

fn user_version(conn: &Connection) -> i64 {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}

fn table_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |r| r.get::<_, i64>(0),
    )
    .unwrap()
        == 1
}

fn insert_terms(conn: &Connection, settlement_id: u8, session_id: u8) {
    conn.execute(
        "INSERT INTO settlement_terms
         (settlement_id, session_id, terms_hash, canonical_terms, created_at_unix_ms)
         VALUES (?1, ?2, ?3, x'00', 1)",
        rusqlite::params![[settlement_id; 32], [session_id; 32], [0x33u8; 32]],
    )
    .expect("valid terms row inserts");
}

fn insert_snapshot_and_journal(conn: &Connection, settlement_id: u8, last_sequence: u8) {
    conn.execute(
        "INSERT INTO settlement_snapshot
         (settlement_id, revision, state_tag, context_bytes, last_event_seq, updated_at_unix_ms)
         VALUES (?1, ?2, 1, x'01', ?2, 1)",
        rusqlite::params![[settlement_id; 32], i64::from(last_sequence)],
    )
    .expect("valid snapshot inserts");
    for sequence in 1..=last_sequence {
        conn.execute(
            "INSERT INTO settlement_journal
             (settlement_id, seq, expected_revision, resulting_revision, event_id,
              event_kind, event_bytes, context_hash, created_at_unix_ms)
             VALUES (?1, ?2, ?3, ?2, ?4, 1, x'01', ?5, 1)",
            rusqlite::params![
                [settlement_id; 32],
                i64::from(sequence),
                i64::from(sequence - 1),
                [0x40_u8 + sequence; 32],
                [0x60_u8 + sequence; 32]
            ],
        )
        .expect("valid journal row inserts");
    }
}

fn delivery_metadata(conn: &Connection, settlement_id: u8) -> Vec<(i64, Option<i64>, Option<i64>)> {
    let mut statement = conn
        .prepare(
            "SELECT attempts, lease_until_unix_ms, completed_at_unix_ms
             FROM durable_outbox WHERE settlement_id = ?1 ORDER BY source_seq ASC",
        )
        .unwrap();
    statement
        .query_map(rusqlite::params![[settlement_id; 32]], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap()
        .map(|row| row.unwrap())
        .collect()
}

#[test]
fn fresh_database_carries_the_full_f2_schema_at_current_version() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("f2.sqlite");
    let _store = Store::open(&path).unwrap();
    let conn = raw(&path);
    assert_eq!(user_version(&conn), SCHEMA_VERSION);
    for table in F2_TABLES {
        assert!(table_exists(&conn, table), "missing table {table}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn production_empty_authority_refuses_any_retained_record() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().expect("production owner root");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("owner-only production root");
    let path = dir.path().join("participant-state.sqlite3");
    let binding = ProductionStoreBindingV1::new([0x91; 32]).expect("nonzero binding");
    let mut store = Store::create_production(&path, binding).expect("production authority");
    store
        .require_empty_production()
        .expect("new authority is empty");
    store
        .put_opaque(b"test-namespace", b"test-key", b"test-value")
        .expect("retained economic state");
    assert!(matches!(
        store.require_empty_production(),
        Err(StoreError::CorruptState)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn prepared_production_authority_survives_activation_state_and_restart() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempdir().expect("production owner root");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("owner-only production root");
    let path = dir.path().join("lazy-authority.sqlite3");
    let preparation =
        ProductionStoreBindingV1::new([0xa1; 32]).expect("nonzero preparation binding");
    let binding = ProductionStoreBindingV1::new([0xb1; 32]).expect("nonzero store binding");

    Store::prepare_resume_create_production(&path, preparation).expect("first preparation commits");
    Store::prepare_resume_create_production(&path, preparation)
        .expect("exact preparation replay is idempotent");
    assert!(!path.exists(), "preparation must not create a database");

    let mut activated = Store::open_or_resume_prepared_production(&path, preparation, binding)
        .expect("authenticated activation");
    activated
        .put_opaque(b"stage7-test", b"key", b"economic-state")
        .expect("post-activation state");
    assert!(matches!(
        Store::open_or_resume_prepared_production(&path, preparation, binding),
        Err(StoreError::ProcessLocked)
    ));
    drop(activated);

    let reopened = Store::open_or_resume_prepared_production(&path, preparation, binding)
        .expect("initialized nonempty authority reopens after restart");
    assert_eq!(
        reopened.opaque(b"stage7-test", b"key").unwrap(),
        Some(b"economic-state".to_vec())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn prepared_production_authority_refuses_missing_or_transplanted_bindings() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempdir().expect("production owner root");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("owner-only production root");
    let missing = dir.path().join("missing-preparation.sqlite3");
    let path = dir.path().join("bound-preparation.sqlite3");
    let preparation =
        ProductionStoreBindingV1::new([0xa2; 32]).expect("nonzero preparation binding");
    let other_preparation =
        ProductionStoreBindingV1::new([0xa3; 32]).expect("nonzero preparation binding");
    let binding = ProductionStoreBindingV1::new([0xb2; 32]).expect("nonzero store binding");
    let other_binding = ProductionStoreBindingV1::new([0xb3; 32]).expect("nonzero store binding");

    assert!(matches!(
        Store::open_or_resume_prepared_production(&missing, preparation, binding),
        Err(StoreError::InvalidStorageAuthority)
    ));
    assert!(!missing.exists(), "refusal must not create a database");

    Store::prepare_resume_create_production(&path, preparation).expect("prepare authority");
    assert!(Store::prepare_resume_create_production(&path, other_preparation).is_err());
    assert!(Store::open_or_resume_prepared_production(&path, other_preparation, binding).is_err());
    assert!(
        !path.exists(),
        "preparation transplant must not create a database"
    );

    let mut activated = Store::open_or_resume_prepared_production(&path, preparation, binding)
        .expect("activate exact authority");
    activated
        .put_opaque(b"stage7-test", b"key", b"preserved")
        .expect("post-activation state");
    drop(activated);

    assert!(Store::open_or_resume_prepared_production(&path, preparation, other_binding).is_err());
    let reopened = Store::open_or_resume_prepared_production(&path, preparation, binding)
        .expect("wrong final binding leaves exact authority intact");
    assert_eq!(
        reopened.opaque(b"stage7-test", b"key").unwrap(),
        Some(b"preserved".to_vec())
    );
}

#[cfg(target_os = "linux")]
#[test]
fn prepared_production_authority_recovers_exact_and_torn_staging_boundaries() {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;

    fn sidecar(path: &std::path::Path, suffix: &str) -> std::path::PathBuf {
        let mut value = OsString::from(path.as_os_str());
        value.push(suffix);
        value.into()
    }

    let dir = tempdir().expect("production owner root");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("owner-only production root");
    let path = dir.path().join("preparation-crash.sqlite3");
    let preparation =
        ProductionStoreBindingV1::new([0xa4; 32]).expect("nonzero preparation binding");
    let binding = ProductionStoreBindingV1::new([0xb4; 32]).expect("nonzero store binding");
    let published = sidecar(&path, ".prepare");
    let staging = sidecar(&path, ".prepare.new");

    Store::prepare_resume_create_production(&path, preparation).expect("prepare authority");
    std::fs::rename(&published, &staging).expect("simulate crash before publish rename");
    Store::prepare_resume_create_production(&path, preparation)
        .expect("exact staged record is promoted");
    assert!(published.exists());
    assert!(!staging.exists());

    std::fs::rename(&published, &staging).expect("restore staged boundary");
    std::fs::write(&staging, b"torn").expect("simulate torn staging write");
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o600))
        .expect("retain owner-only staging authority");
    Store::prepare_resume_create_production(&path, preparation)
        .expect("torn owner-only staging is rebuilt before publication");
    assert!(published.exists());
    assert!(!staging.exists());

    drop(
        Store::open_or_resume_prepared_production(&path, preparation, binding)
            .expect("recovered preparation activates"),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn production_monotonic_high_water_is_idempotent_persistent_and_rejects_rollback() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempdir().expect("production owner root");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("owner-only production root");
    let path = dir.path().join("high-water.sqlite3");
    let binding = ProductionStoreBindingV1::new([0x92; 32]).expect("nonzero binding");
    let mut store = Store::create_production(&path, binding).expect("production authority");
    assert!(matches!(
        store.record_monotonic_high_water(b"", 1_000),
        Err(StoreError::InvalidStorageAuthority)
    ));
    assert!(matches!(
        store.record_monotonic_high_water(b"DOM-INTEROP/TEST/HIGH-WATER/V1", 0),
        Err(StoreError::InvalidStorageAuthority)
    ));
    assert!(matches!(
        store.record_monotonic_high_water(b"DOM-INTEROP/TEST/HIGH-WATER/OVERFLOW/V1", u64::MAX,),
        Err(StoreError::CounterOverflow)
    ));
    assert_eq!(
        store
            .record_monotonic_high_water(b"DOM-INTEROP/TEST/HIGH-WATER/V1", 1_000)
            .expect("first observation"),
        1_000
    );
    assert_eq!(
        store
            .record_monotonic_high_water(b"DOM-INTEROP/TEST/HIGH-WATER/V1", 1_000)
            .expect("equal replay"),
        1_000
    );
    assert!(matches!(
        store.record_monotonic_high_water(b"DOM-INTEROP/TEST/HIGH-WATER/V1", 999),
        Err(StoreError::RevisionConflict)
    ));
    assert_eq!(
        store
            .record_monotonic_high_water(b"DOM-INTEROP/TEST/HIGH-WATER/V1", 1_001)
            .expect("forward observation"),
        1_001
    );
    drop(store);

    let mut reopened = Store::open_production(&path, binding).expect("reopen production authority");
    assert!(matches!(
        reopened.record_monotonic_high_water(b"DOM-INTEROP/TEST/HIGH-WATER/V1", 1_000),
        Err(StoreError::RevisionConflict)
    ));
    assert_eq!(
        reopened
            .record_monotonic_high_water(b"DOM-INTEROP/TEST/HIGH-WATER/V1", 1_002)
            .expect("forward after restart"),
        1_002
    );
}

#[test]
fn external_custody_is_atomic_non_leaseable_and_exactly_completed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("external-custody.sqlite");
    let mut store = Store::open(&path).unwrap();
    let settlement_id = [0x71; 32];
    let _ = store
        .f2_create(&SettlementCreate {
            settlement_id,
            session_id: [0x72; 32],
            terms_hash: [0x73; 32],
            canonical_terms: b"terms",
            initial_state_tag: 1,
            initial_context: b"context-0",
            created_at_unix_ms: 1,
        })
        .unwrap();

    let insert = ExternalCustodyInsert {
        effect_id: [0x74; 32],
        effect_kind: 0x0201,
        custody_digest: [0x75; 32],
        transaction_id: [0x76; 32],
    };
    let arm = SettlementCommit {
        settlement_id,
        event_id: [0x77; 32],
        event_kind: 2,
        event_bytes: b"arm-external-custody",
        expected_revision: 0,
        resulting_revision: 1,
        state_tag: 2,
        context_bytes: b"context-1",
        context_hash: [0x78; 32],
        evidence: None,
        cursor: None,
        effects: &[],
        refresh_event_id: None,
        terminal: None,
        now_unix_ms: 2,
    };
    assert_eq!(
        store
            .f2_commit_transition_with_external_custody(&arm, &insert)
            .unwrap(),
        CommitOutcome::Committed
    );
    assert!(store.f2_ready_outbox(3, 100, 10).unwrap().is_empty());
    assert!(matches!(
        store.f2_complete_effect(insert.effect_id, insert.custody_digest, 3),
        Err(StoreError::IdempotencyConflict)
    ));
    let pending = store.f2_outbox_summary(settlement_id).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].dispatch_class,
        F2OutboxDispatchClassV1::ExternalCustody
    );
    assert_eq!(
        pending[0].external_transaction_id,
        Some(insert.transaction_id)
    );
    assert_eq!(pending[0].status, F2OutboxDeliveryStatusV1::Pending);
    assert_eq!(pending[0].attempts, 0);

    let completion = ExternalCustodyCompletion {
        effect_id: insert.effect_id,
        custody_digest: insert.custody_digest,
        transaction_id: insert.transaction_id,
    };
    let submit = SettlementCommit {
        settlement_id,
        event_id: [0x79; 32],
        event_kind: 3,
        event_bytes: b"complete-external-custody",
        expected_revision: 1,
        resulting_revision: 2,
        state_tag: 3,
        context_bytes: b"context-2",
        context_hash: [0x7A; 32],
        evidence: None,
        cursor: None,
        effects: &[],
        refresh_event_id: None,
        terminal: None,
        now_unix_ms: 4,
    };
    assert_eq!(
        store
            .f2_commit_transition_completing_external_custody(&submit, &completion)
            .unwrap(),
        CommitOutcome::Committed
    );
    let completed = store.f2_outbox_summary(settlement_id).unwrap();
    assert_eq!(completed[0].status, F2OutboxDeliveryStatusV1::Completed);
    assert_eq!(completed[0].attempts, 1);
    assert_eq!(completed[0].completed_at_unix_ms, Some(4));
    assert!(store.f2_ready_outbox(5, 100, 10).unwrap().is_empty());

    assert_eq!(
        store
            .f2_commit_transition_with_external_custody(&arm, &insert)
            .unwrap(),
        CommitOutcome::DuplicateSameBytes
    );
    let divergent = ExternalCustodyInsert {
        custody_digest: [0x7B; 32],
        ..insert
    };
    assert!(matches!(
        store.f2_commit_transition_with_external_custody(&arm, &divergent),
        Err(StoreError::IdempotencyConflict)
    ));
}

#[test]
fn reopening_is_idempotent() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("f2.sqlite");
    drop(Store::open(&path).unwrap());
    drop(Store::open(&path).unwrap());
    let conn = raw(&path);
    assert_eq!(user_version(&conn), SCHEMA_VERSION);
}

#[test]
fn version_1_database_upgrades_and_keeps_its_data() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("v1.sqlite");
    {
        // A database exactly as the version-1 binary left it: v1 tables,
        // user_version 1, one journal row of pre-existing data.
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE journal (
                 sequence INTEGER PRIMARY KEY,
                 kind     INTEGER NOT NULL,
                 payload  BLOB    NOT NULL
             ) STRICT;
             CREATE TABLE idempotency (key BLOB PRIMARY KEY, response BLOB NOT NULL) STRICT;
             CREATE TABLE cursors (chain BLOB PRIMARY KEY, cursor BLOB NOT NULL) STRICT;
             CREATE TABLE outbox (
                 id INTEGER PRIMARY KEY, payload BLOB NOT NULL,
                 delivered INTEGER NOT NULL DEFAULT 0
             ) STRICT;
             CREATE TABLE revisions (entity BLOB PRIMARY KEY, revision INTEGER NOT NULL) STRICT;
             CREATE TABLE opaque_records (
                 namespace BLOB NOT NULL, key BLOB NOT NULL, value BLOB NOT NULL,
                 PRIMARY KEY (namespace, key)
             ) STRICT;
             INSERT INTO journal (sequence, kind, payload) VALUES (1, 7, x'aa');
             PRAGMA user_version = 1;",
        )
        .unwrap();
    }
    let store = Store::open(&path).unwrap();
    let entries = store.read_journal().unwrap();
    assert_eq!(entries.len(), 1, "v1 data must survive the upgrade");
    assert_eq!(entries[0].kind, 7);
    drop(store);
    let conn = raw(&path);
    assert_eq!(user_version(&conn), SCHEMA_VERSION);
    for table in F2_TABLES {
        assert!(table_exists(&conn, table), "missing table {table}");
    }
}

#[test]
fn future_version_fails_closed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("future.sqlite");
    drop(Store::open(&path).unwrap());
    {
        let conn = raw(&path);
        conn.pragma_update(None, "user_version", 99).unwrap();
    }
    match Store::open(&path) {
        Err(StoreError::UnsupportedVersion { found, supported }) => {
            assert_eq!(found, 99);
            assert_eq!(supported, SCHEMA_VERSION);
        }
        other => panic!("downgrade must fail closed, got {other:?}"),
    }
}

#[test]
fn opaque_create_if_absent_has_exactly_one_concurrent_winner() {
    use std::sync::{Arc, Barrier};

    let dir = tempdir().unwrap();
    let path = dir.path().join("opaque-cas.sqlite");
    drop(Store::open(&path).unwrap());
    let barrier = Arc::new(Barrier::new(2));
    let handles = [0_u8, 1_u8].map(|value| {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let mut store = Store::open(&path).unwrap();
            barrier.wait();
            store
                .put_opaque_if_absent(b"one-shot-test", b"same-key", &[value])
                .unwrap()
        })
    });
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.into_iter().filter(|created| *created).count(), 1);
}

#[test]
fn identifier_length_checks_are_enforced() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("check.sqlite");
    drop(Store::open(&path).unwrap());
    let conn = raw(&path);
    // 31-byte settlement_id: the CHECK constraint must refuse it.
    let err = conn
        .execute(
            "INSERT INTO settlement_terms
             (settlement_id, session_id, terms_hash, canonical_terms, created_at_unix_ms)
             VALUES (?1, ?2, ?3, x'00', 1)",
            rusqlite::params![[0x01u8; 31], [0x02u8; 32], [0x03u8; 32]],
        )
        .unwrap_err();
    assert!(err.to_string().contains("CHECK"), "{err}");
    // STRICT: a text value in a BLOB column is a type error, not a coercion.
    let err = conn
        .execute(
            "INSERT INTO settlement_terms
             (settlement_id, session_id, terms_hash, canonical_terms, created_at_unix_ms)
             VALUES ('not-a-blob', ?1, ?2, x'00', 1)",
            rusqlite::params![[0x02u8; 32], [0x03u8; 32]],
        )
        .unwrap_err();
    assert!(err.to_string().contains("cannot store"), "{err}");
}

#[test]
fn orphan_rows_are_refused_by_foreign_keys() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("fk.sqlite");
    drop(Store::open(&path).unwrap());
    let conn = raw(&path);
    let err = conn
        .execute(
            "INSERT INTO settlement_snapshot
             (settlement_id, revision, state_tag, context_bytes, last_event_seq, updated_at_unix_ms)
             VALUES (?1, 0, 0, x'00', 0, 1)",
            rusqlite::params![[0x0Au8; 32]],
        )
        .unwrap_err();
    assert!(err.to_string().contains("FOREIGN KEY"), "{err}");
}

#[test]
fn session_id_is_unique_across_settlements() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("uniq.sqlite");
    drop(Store::open(&path).unwrap());
    let conn = raw(&path);
    insert_terms(&conn, 0x01, 0x11);
    let err = conn
        .execute(
            "INSERT INTO settlement_terms
             (settlement_id, session_id, terms_hash, canonical_terms, created_at_unix_ms)
             VALUES (?1, ?2, ?3, x'00', 1)",
            rusqlite::params![[0x02u8; 32], [0x11u8; 32], [0x33u8; 32]],
        )
        .unwrap_err();
    assert!(err.to_string().contains("UNIQUE"), "{err}");
}

#[test]
fn second_terminal_outcome_fails_closed() {
    // I4 at the schema layer: terminal_outcome is PRIMARY KEY(settlement_id),
    // so the second terminal row — even with a different outcome — is refused
    // by the database itself, under any application bug above it.
    let dir = tempdir().unwrap();
    let path = dir.path().join("terminal.sqlite");
    drop(Store::open(&path).unwrap());
    let conn = raw(&path);
    insert_terms(&conn, 0x01, 0x11);
    conn.execute(
        "INSERT INTO terminal_outcome
         (settlement_id, outcome_tag, source_event_id, finalized_revision, created_at_unix_ms)
         VALUES (?1, 4, ?2, 9, 1)",
        rusqlite::params![[0x01u8; 32], [0xE1u8; 32]],
    )
    .expect("first terminal row inserts");
    let err = conn
        .execute(
            "INSERT INTO terminal_outcome
             (settlement_id, outcome_tag, source_event_id, finalized_revision, created_at_unix_ms)
             VALUES (?1, 5, ?2, 10, 2)",
            rusqlite::params![[0x01u8; 32], [0xE2u8; 32]],
        )
        .unwrap_err();
    assert!(err.to_string().contains("UNIQUE"), "{err}");
}

#[test]
fn duplicate_event_id_per_settlement_is_refused() {
    // Spec §9: same (settlement_id, event_id) must not append twice — the
    // UNIQUE constraint is the last line of the dedupe defense.
    let dir = tempdir().unwrap();
    let path = dir.path().join("dedupe.sqlite");
    drop(Store::open(&path).unwrap());
    let conn = raw(&path);
    insert_terms(&conn, 0x01, 0x11);
    let insert = "INSERT INTO settlement_journal
         (settlement_id, seq, expected_revision, resulting_revision, event_id,
          event_kind, event_bytes, context_hash, created_at_unix_ms)
         VALUES (?1, ?2, 0, 1, ?3, 1, x'aa', ?4, 1)";
    conn.execute(
        insert,
        rusqlite::params![[0x01u8; 32], 1i64, [0xEEu8; 32], [0xCCu8; 32]],
    )
    .expect("first journal row inserts");
    let err = conn
        .execute(
            insert,
            rusqlite::params![[0x01u8; 32], 2i64, [0xEEu8; 32], [0xCCu8; 32]],
        )
        .unwrap_err();
    assert!(err.to_string().contains("UNIQUE"), "{err}");
}

#[test]
fn outbox_summary_is_exact_payload_free_and_does_not_change_leases() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("outbox-summary.sqlite");
    let store = Store::open(&path).unwrap();
    let conn = raw(&path);
    insert_terms(&conn, 0x21, 0x31);
    insert_snapshot_and_journal(&conn, 0x21, 3);

    let insert = "INSERT INTO durable_outbox
         (settlement_id, effect_id, source_seq, effect_kind, payload_bytes,
          payload_hash, status_tag, attempts, lease_until_unix_ms, completed_at_unix_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
    conn.execute(
        insert,
        rusqlite::params![
            [0x21_u8; 32],
            [0xA1_u8; 32],
            1_i64,
            513_i64,
            b"OUTBOX-PAYLOAD-MUST-NEVER-LEAVE-THE-STORE".as_slice(),
            [0xB1_u8; 32],
            0_i64,
            0_i64,
            Option::<i64>::None,
            Option::<i64>::None
        ],
    )
    .unwrap();
    conn.execute(
        insert,
        rusqlite::params![
            [0x21_u8; 32],
            [0xA2_u8; 32],
            2_i64,
            258_i64,
            b"SECOND-SECRET-PAYLOAD".as_slice(),
            [0xB2_u8; 32],
            0_i64,
            2_i64,
            Some(9_999_i64),
            Option::<i64>::None
        ],
    )
    .unwrap();
    conn.execute(
        insert,
        rusqlite::params![
            [0x21_u8; 32],
            [0xA3_u8; 32],
            3_i64,
            514_i64,
            b"THIRD-SECRET-PAYLOAD".as_slice(),
            [0xB3_u8; 32],
            1_i64,
            1_i64,
            Option::<i64>::None,
            Some(12_345_i64)
        ],
    )
    .unwrap();

    let before = delivery_metadata(&conn, 0x21);
    let first = store.f2_outbox_summary([0x21; 32]).unwrap();
    let second = store.f2_outbox_summary([0x21; 32]).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.len(), 3);
    assert_eq!(first[0].effect_id, [0xA1; 32]);
    assert_eq!(first[0].source_sequence, 1);
    assert_eq!(first[0].source_event_id, [0x41; 32]);
    assert_eq!(first[0].effect_kind, 513);
    assert_eq!(first[0].payload_hash, [0xB1; 32]);
    assert_eq!(first[0].status, F2OutboxDeliveryStatusV1::Pending);
    assert_eq!(first[0].attempts, 0);
    assert_eq!(first[0].lease_until_unix_ms, None);
    assert_eq!(first[0].completed_at_unix_ms, None);
    assert_eq!(first[1].status, F2OutboxDeliveryStatusV1::Pending);
    assert_eq!(first[1].attempts, 2);
    assert_eq!(first[1].lease_until_unix_ms, Some(9_999));
    assert_eq!(first[2].status, F2OutboxDeliveryStatusV1::Completed);
    assert_eq!(first[2].completed_at_unix_ms, Some(12_345));
    assert_eq!(delivery_metadata(&conn, 0x21), before);
    assert!(!format!("{first:?}").contains("OUTBOX-PAYLOAD"));
}

#[test]
fn outbox_summary_rejects_schema_and_delivery_state_inconsistency() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("outbox-summary-corrupt.sqlite");
    let store = Store::open(&path).unwrap();
    let conn = raw(&path);
    insert_terms(&conn, 0x22, 0x32);
    insert_snapshot_and_journal(&conn, 0x22, 1);
    conn.execute(
        "INSERT INTO durable_outbox
         (settlement_id, effect_id, source_seq, effect_kind, payload_bytes,
          payload_hash, status_tag, attempts)
         VALUES (?1, ?2, 1, 513, x'01', ?3, 0, 0)",
        rusqlite::params![[0x22_u8; 32], [0xA4_u8; 32], [0xB4_u8; 32]],
    )
    .unwrap();
    assert_eq!(store.f2_outbox_summary([0x22; 32]).unwrap().len(), 1);

    conn.execute(
        "UPDATE durable_outbox SET status_tag = 9 WHERE settlement_id = ?1",
        rusqlite::params![[0x22_u8; 32]],
    )
    .unwrap();
    assert!(matches!(
        store.f2_outbox_summary([0x22; 32]),
        Err(StoreError::CorruptState)
    ));

    conn.execute(
        "UPDATE durable_outbox
         SET status_tag = 0, attempts = 0, lease_until_unix_ms = 10,
             completed_at_unix_ms = NULL
         WHERE settlement_id = ?1",
        rusqlite::params![[0x22_u8; 32]],
    )
    .unwrap();
    assert!(matches!(
        store.f2_outbox_summary([0x22; 32]),
        Err(StoreError::CorruptState)
    ));

    conn.execute(
        "UPDATE durable_outbox
         SET status_tag = 1, attempts = 1, lease_until_unix_ms = NULL,
             completed_at_unix_ms = NULL
         WHERE settlement_id = ?1",
        rusqlite::params![[0x22_u8; 32]],
    )
    .unwrap();
    assert!(matches!(
        store.f2_outbox_summary([0x22; 32]),
        Err(StoreError::CorruptState)
    ));

    conn.execute(
        "UPDATE durable_outbox
         SET status_tag = 0, attempts = 0, lease_until_unix_ms = NULL,
             completed_at_unix_ms = NULL, source_seq = 99
         WHERE settlement_id = ?1",
        rusqlite::params![[0x22_u8; 32]],
    )
    .unwrap();
    assert!(matches!(
        store.f2_outbox_summary([0x22; 32]),
        Err(StoreError::CorruptState)
    ));

    conn.execute(
        "UPDATE durable_outbox SET source_seq = 1, effect_kind = 70000
         WHERE settlement_id = ?1",
        rusqlite::params![[0x22_u8; 32]],
    )
    .unwrap();
    assert!(matches!(
        store.f2_outbox_summary([0x22; 32]),
        Err(StoreError::CorruptState)
    ));
    assert!(matches!(
        store.f2_outbox_summary([0xFF; 32]),
        Err(StoreError::NotFound)
    ));
}
