//! Roadmap v2 Phase 1.4 — Snapshot binary determinism check.
//!
//! The `cross_platform_snapshot` binary produces the manifest the
//! CI matrix compares across every host. Before that comparison
//! can be meaningful, the binary itself MUST be deterministic on
//! a single host — same code → same output across N invocations.
//!
//! This test runs the binary 4 times and asserts byte-identical
//! stdout. Anything else means there's an iteration-order /
//! HashMap-hashing / non-deterministic-rand bug in the snapshot
//! generation that would also make the cross-platform comparison
//! flaky. Catch it locally before pushing.

use std::process::Command;

fn run_snapshot_once() -> String {
    // Use `cargo run --bin cross_platform_snapshot` so the test
    // exercises the same build path the CI invocation will use.
    let output = Command::new(env!("CARGO"))
        .args([
            "run",
            "-p",
            "dom-test-vectors",
            "--bin",
            "cross_platform_snapshot",
            "--quiet",
        ])
        .output()
        .expect("cargo run cross_platform_snapshot");
    assert!(
        output.status.success(),
        "snapshot binary failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("snapshot stdout is UTF-8")
}

#[test]
fn snapshot_binary_is_deterministic_across_n_runs() {
    let baseline = run_snapshot_once();
    assert!(
        !baseline.is_empty(),
        "snapshot output is empty — bin produced no manifest"
    );
    for trial in 0..4 {
        let next = run_snapshot_once();
        assert_eq!(
            baseline, next,
            "trial {trial}: snapshot output diverged across runs — \
             the cross-platform CI comparison would also be flaky"
        );
    }
}

#[test]
fn snapshot_manifest_has_expected_sections() {
    let output = run_snapshot_once();
    for section in [
        "[constants]",
        "[pmmr_roots]",
        "[hash_vectors]",
        "[serialization]",
        "[crypto_identities]",
        "# end-of-manifest",
    ] {
        assert!(
            output.contains(section),
            "snapshot missing section header '{section}':\n{output}"
        );
    }
}

#[test]
fn snapshot_includes_phase_b_pmmr_root_for_n16() {
    let output = run_snapshot_once();
    // Pin a specific RFC-0004 vector — n=16 root from
    // dom-test-vectors::pmmr_vectors. If this line disappears or
    // changes, either the snapshot bin dropped a section or the
    // PMMR layout drifted.
    assert!(
        output.contains("n=16 root=70660b13b900c86b443a72b7d5f29519de53350b7bd02484ee85bebaab414094"),
        "snapshot missing pinned n=16 PMMR root — RFC-0004 drift?\n{output}"
    );
}
