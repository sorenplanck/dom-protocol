//! Integration sanity test for `dom-test-runner clean`.
//!
//! Constructs a fake "DOM workspace" in a temp directory and verifies that
//! invoking the compiled binary with `clean` removes only
//! `target/dom-test-runner/` and leaves everything else untouched.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary_path() -> PathBuf {
    // Use the CARGO_BIN_EXE_<name> env var that cargo injects for tests.
    PathBuf::from(env!("CARGO_BIN_EXE_dom-test-runner"))
}

fn make_fake_repo() -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("dtr-clean-{pid}-{nanos}"));
    fs::create_dir_all(root.join("crates").join("dom-test-runner").join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["crates/dom-test-runner"]
"#,
    )
    .unwrap();

    // The runner's directory under target should be removed.
    fs::create_dir_all(root.join("target").join("dom-test-runner").join("logs")).unwrap();
    fs::write(
        root.join("target")
            .join("dom-test-runner")
            .join("logs")
            .join("a.log"),
        "noise",
    )
    .unwrap();

    // Sibling target dirs must NOT be touched.
    fs::create_dir_all(root.join("target").join("debug")).unwrap();
    fs::write(root.join("target").join("debug").join("dummy.txt"), "keep").unwrap();
    fs::create_dir_all(root.join("target").join("release")).unwrap();
    fs::write(
        root.join("target").join("release").join("dummy.txt"),
        "keep",
    )
    .unwrap();

    root
}

#[test]
fn clean_only_removes_its_own_directory() {
    let root = make_fake_repo();
    let bin = binary_path();

    let status = Command::new(&bin)
        .arg("clean")
        .current_dir(&root)
        .status()
        .expect("failed to execute dom-test-runner");
    assert!(status.success(), "clean should succeed in a sandbox repo");

    // The runner's own target subdir is gone.
    assert!(!root.join("target").join("dom-test-runner").exists());

    // Everything else under target/ is untouched.
    assert!(root
        .join("target")
        .join("debug")
        .join("dummy.txt")
        .exists());
    assert!(root
        .join("target")
        .join("release")
        .join("dummy.txt")
        .exists());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn doctor_fails_outside_dom_repo() {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let outside = std::env::temp_dir().join(format!("dtr-outside-{pid}-{nanos}"));
    fs::create_dir_all(&outside).unwrap();
    let bin = binary_path();

    let out = Command::new(&bin)
        .arg("doctor")
        .current_dir(&outside)
        .output()
        .expect("failed to execute dom-test-runner");
    assert!(!out.status.success(), "doctor must fail outside the DOM repo");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("DOM Protocol") || stderr.contains("dom-test-runner"),
        "error message should mention the DOM repo / runner; got: {stderr}"
    );

    let _ = fs::remove_dir_all(&outside);
}
