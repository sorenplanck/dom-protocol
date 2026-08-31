#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use route_executor::{DurableRouteStoreV1, RouteStoreErrorV1};
use rusqlite::Connection;
use tempfile::TempDir;

fn secure_directory() -> TempDir {
    let directory = tempfile::tempdir().expect("temporary directory");
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("owner-only test directory");
    directory
}

fn database_path(directory: &TempDir, name: &str) -> PathBuf {
    directory.path().join(name)
}

fn create_and_close(path: &Path) {
    drop(DurableRouteStoreV1::create(path).expect("create strict route store"));
}

#[test]
fn strict_create_and_open_existing_never_conflate_absence_or_replacement() {
    let directory = secure_directory();
    let path = database_path(&directory, "route.sqlite3");

    assert_eq!(
        DurableRouteStoreV1::open_existing(&path).expect_err("missing store must fail"),
        RouteStoreErrorV1::DatabaseMissing
    );

    let store = DurableRouteStoreV1::create(&path).expect("create strict store");
    let metadata = fs::symlink_metadata(&path).expect("database metadata");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);

    assert_eq!(
        DurableRouteStoreV1::create(&path).expect_err("replacement must fail"),
        RouteStoreErrorV1::DatabasePresent
    );
    drop(store);
    drop(DurableRouteStoreV1::open_existing(&path).expect("strict reopen"));
}

#[test]
fn wrong_modes_symlinks_hardlinks_and_stale_sidecars_fail_closed() {
    let directory = secure_directory();
    let path = database_path(&directory, "route.sqlite3");

    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750))
        .expect("weaken directory mode");
    assert_eq!(
        DurableRouteStoreV1::create(&path).expect_err("group-readable directory must fail"),
        RouteStoreErrorV1::InvalidStorageAuthority
    );
    assert!(!path.exists());
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .expect("restore directory mode");

    create_and_close(&path);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("weaken file mode");
    assert_eq!(
        DurableRouteStoreV1::open_existing(&path).expect_err("group-readable file must fail"),
        RouteStoreErrorV1::InvalidStorageAuthority
    );
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore file mode");

    let alias = database_path(&directory, "route-hardlink.sqlite3");
    fs::hard_link(&path, &alias).expect("create hard link");
    assert_eq!(
        DurableRouteStoreV1::open_existing(&path).expect_err("hard-linked authority must fail"),
        RouteStoreErrorV1::InvalidStorageAuthority
    );
    fs::remove_file(&alias).expect("remove hard link");

    let link = database_path(&directory, "route-symlink.sqlite3");
    symlink(&path, &link).expect("create symlink");
    assert_eq!(
        DurableRouteStoreV1::open_existing(&link).expect_err("symlink authority must fail"),
        RouteStoreErrorV1::InvalidStorageAuthority
    );

    let fresh = database_path(&directory, "fresh.sqlite3");
    let stale_wal = PathBuf::from(format!("{}-wal", fresh.display()));
    fs::write(&stale_wal, b"stale").expect("stale sidecar");
    fs::set_permissions(&stale_wal, fs::Permissions::from_mode(0o600)).expect("sidecar mode");
    assert_eq!(
        DurableRouteStoreV1::create(&fresh).expect_err("stale sidecar must fail"),
        RouteStoreErrorV1::InvalidStorageAuthority
    );
    assert!(!fresh.exists());
}

#[test]
fn schema_constraints_columns_and_objects_are_exact_not_name_only() {
    let extra_object_directory = secure_directory();
    let extra_object = database_path(&extra_object_directory, "route.sqlite3");
    create_and_close(&extra_object);
    Connection::open(&extra_object)
        .expect("raw maintenance connection")
        .execute_batch("CREATE TABLE injected(value INTEGER) STRICT;")
        .expect("inject extra object");
    assert_eq!(
        DurableRouteStoreV1::open_existing(&extra_object)
            .expect_err("extra object must fail schema audit"),
        RouteStoreErrorV1::CorruptState
    );

    let extra_column_directory = secure_directory();
    let extra_column = database_path(&extra_column_directory, "route.sqlite3");
    create_and_close(&extra_column);
    Connection::open(&extra_column)
        .expect("raw maintenance connection")
        .execute_batch("ALTER TABLE route_snapshots ADD COLUMN injected INTEGER;")
        .expect("inject extra column");
    assert_eq!(
        DurableRouteStoreV1::open_existing(&extra_column)
            .expect_err("same object names with changed schema must fail"),
        RouteStoreErrorV1::CorruptState
    );
}

#[test]
fn open_existing_refuses_unknown_schema_version_without_migrating_it() {
    let directory = secure_directory();
    let path = database_path(&directory, "route.sqlite3");
    create_and_close(&path);
    Connection::open(&path)
        .expect("raw maintenance connection")
        .execute_batch("PRAGMA user_version = 2;")
        .expect("raise schema version");

    assert_eq!(
        DurableRouteStoreV1::open_existing(&path).expect_err("unknown version must fail"),
        RouteStoreErrorV1::UnsupportedFormat
    );
    let version: i64 = Connection::open(&path)
        .expect("inspect version")
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("read version");
    assert_eq!(version, 2, "open_existing must not repair or migrate");
}
