//! Profile → cargo command mapping.
//!
//! Each profile is a named bundle of one or more `cargo ...` invocations.
//! Profiles are pure data here; execution lives in `runner.rs`.

/// A single cargo command to run as part of a profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Display label (used in logs/reports).
    pub label: &'static str,
    /// `cargo` arguments, excluding the leading `cargo` itself.
    pub args: &'static [&'static str],
    /// If true, a non-existent test target (exit code containing
    /// "no test target") will be reported as SKIPPED rather than FAILED.
    pub tolerate_missing_target: bool,
}

/// A profile = ordered list of steps.
#[derive(Debug, Clone)]
pub struct Profile {
    pub name: &'static str,
    pub steps: &'static [Step],
}

/// Master table of every profile the runner knows about.
///
/// The exact `cargo` invocations match the spec in
/// `docs/testing/WINDOWS_TEST_RUNNER.md`.
pub const PROFILES: &[Profile] = &[
    Profile {
        name: "fast-check",
        steps: &[Step {
            label: "cargo check (hot crates)",
            args: &[
                "check",
                "-p",
                "dom-mempool",
                "-p",
                "dom-node",
                "-p",
                "dom-integration-tests",
            ],
            tolerate_missing_target: false,
        }],
    },
    Profile {
        name: "unit",
        steps: &[Step {
            label: "cargo test --workspace --lib",
            args: &["test", "--workspace", "--lib"],
            tolerate_missing_target: false,
        }],
    },
    Profile {
        name: "mempool",
        steps: &[Step {
            label: "cargo test -p dom-mempool -p dom-node",
            args: &[
                "test",
                "-p",
                "dom-mempool",
                "-p",
                "dom-node",
                "--",
                "--test-threads=1",
            ],
            tolerate_missing_target: false,
        }],
    },
    Profile {
        name: "node",
        steps: &[Step {
            label: "cargo test -p dom-node",
            args: &["test", "-p", "dom-node", "--", "--test-threads=1"],
            tolerate_missing_target: false,
        }],
    },
    Profile {
        name: "wire",
        steps: &[Step {
            label: "cargo test -p dom-wire",
            args: &["test", "-p", "dom-wire", "--", "--test-threads=1"],
            tolerate_missing_target: false,
        }],
    },
    Profile {
        name: "pow",
        steps: &[
            Step {
                label: "cargo test -p dom-pow",
                args: &["test", "-p", "dom-pow"],
                tolerate_missing_target: false,
            },
            Step {
                label: "cargo test -p dom-node miner",
                args: &["test", "-p", "dom-node", "miner"],
                tolerate_missing_target: false,
            },
        ],
    },
    Profile {
        name: "chain",
        steps: &[Step {
            label: "cargo test -p dom-chain",
            args: &["test", "-p", "dom-chain", "--", "--test-threads=1"],
            tolerate_missing_target: false,
        }],
    },
    Profile {
        name: "store",
        steps: &[Step {
            label: "cargo test -p dom-store",
            args: &["test", "-p", "dom-store", "--", "--test-threads=1"],
            tolerate_missing_target: false,
        }],
    },
    Profile {
        name: "wallet",
        steps: &[Step {
            label: "cargo test -p dom-wallet",
            args: &["test", "-p", "dom-wallet", "--", "--test-threads=1"],
            tolerate_missing_target: false,
        }],
    },
    Profile {
        name: "wallet-app",
        steps: &[
            Step {
                label: "cargo check -p dom-wallet-app",
                args: &["check", "-p", "dom-wallet-app"],
                tolerate_missing_target: false,
            },
            Step {
                label: "cargo test -p dom-wallet-app (if tests exist)",
                args: &["test", "-p", "dom-wallet-app", "--", "--test-threads=1"],
                tolerate_missing_target: true,
            },
        ],
    },
    Profile {
        name: "integration",
        steps: &[Step {
            label: "cargo test -p dom-integration-tests",
            args: &[
                "test",
                "-p",
                "dom-integration-tests",
                "--",
                "--test-threads=1",
            ],
            tolerate_missing_target: false,
        }],
    },
    Profile {
        name: "integration-mempool",
        steps: &[Step {
            label: "cargo test -p dom-integration-tests --test mempool_relay",
            args: &[
                "test",
                "-p",
                "dom-integration-tests",
                "--test",
                "mempool_relay",
                "--",
                "--test-threads=1",
            ],
            tolerate_missing_target: true,
        }],
    },
    Profile {
        name: "integration-network",
        steps: &[
            Step {
                label: "cargo test -p dom-integration-tests --test two_node",
                args: &[
                    "test",
                    "-p",
                    "dom-integration-tests",
                    "--test",
                    "two_node",
                    "--",
                    "--test-threads=1",
                ],
                tolerate_missing_target: true,
            },
            Step {
                label: "cargo test -p dom-integration-tests --test three_node",
                args: &[
                    "test",
                    "-p",
                    "dom-integration-tests",
                    "--test",
                    "three_node",
                    "--",
                    "--test-threads=1",
                ],
                tolerate_missing_target: true,
            },
        ],
    },
    Profile {
        name: "two-node",
        steps: &[Step {
            label: "cargo test -p dom-integration-tests --test two_node",
            args: &[
                "test",
                "-p",
                "dom-integration-tests",
                "--test",
                "two_node",
                "--",
                "--test-threads=1",
            ],
            tolerate_missing_target: true,
        }],
    },
    Profile {
        name: "reorg",
        steps: &[Step {
            label: "cargo test -p dom-integration-tests --test reorg",
            args: &[
                "test",
                "-p",
                "dom-integration-tests",
                "--test",
                "reorg",
                "--",
                "--test-threads=1",
            ],
            tolerate_missing_target: true,
        }],
    },
    Profile {
        name: "ibd",
        steps: &[Step {
            label: "cargo test -p dom-integration-tests --test ibd",
            args: &[
                "test",
                "-p",
                "dom-integration-tests",
                "--test",
                "ibd",
                "--",
                "--test-threads=1",
            ],
            tolerate_missing_target: true,
        }],
    },
    Profile {
        name: "full",
        steps: &[
            Step {
                label: "cargo check --workspace",
                args: &["check", "--workspace"],
                tolerate_missing_target: false,
            },
            Step {
                label: "cargo test --workspace",
                args: &["test", "--workspace"],
                tolerate_missing_target: false,
            },
            Step {
                label: "cargo clippy --workspace -D warnings",
                args: &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--",
                    "-D",
                    "warnings",
                ],
                tolerate_missing_target: false,
            },
        ],
    },
    Profile {
        name: "all",
        steps: &[
            Step {
                label: "cargo check --workspace",
                args: &["check", "--workspace"],
                tolerate_missing_target: false,
            },
            Step {
                label: "cargo test --workspace --include-ignored",
                args: &[
                    "test",
                    "--workspace",
                    "--",
                    "--include-ignored",
                    "--test-threads=1",
                ],
                tolerate_missing_target: false,
            },
            Step {
                label: "cargo clippy --workspace -D warnings",
                args: &[
                    "clippy",
                    "--workspace",
                    "--all-targets",
                    "--all-features",
                    "--",
                    "-D",
                    "warnings",
                ],
                tolerate_missing_target: false,
            },
        ],
    },
];

/// Look up a profile by name.
pub fn get(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
}

/// Names of all known profiles, in declaration order.
pub fn names() -> Vec<&'static str> {
    PROFILES.iter().map(|p| p.name).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_documented_profile_exists() {
        let required = [
            "fast-check",
            "unit",
            "mempool",
            "node",
            "wire",
            "pow",
            "chain",
            "store",
            "wallet",
            "wallet-app",
            "integration",
            "integration-mempool",
            "integration-network",
            "two-node",
            "reorg",
            "ibd",
            "full",
            "all",
        ];
        for name in required {
            assert!(get(name).is_some(), "missing profile: {name}");
        }
    }

    #[test]
    fn mempool_profile_runs_mempool_and_node() {
        let p = get("mempool").unwrap();
        let s = &p.steps[0];
        assert!(s.args.contains(&"dom-mempool"));
        assert!(s.args.contains(&"dom-node"));
        assert!(s.args.contains(&"--test-threads=1"));
    }

    #[test]
    fn fast_check_targets_hot_crates() {
        let p = get("fast-check").unwrap();
        let s = &p.steps[0];
        assert_eq!(s.args[0], "check");
        assert!(s.args.contains(&"dom-mempool"));
        assert!(s.args.contains(&"dom-node"));
        assert!(s.args.contains(&"dom-integration-tests"));
    }

    #[test]
    fn full_includes_clippy_dwarnings() {
        let p = get("full").unwrap();
        let last = p.steps.last().unwrap();
        assert!(last.args.contains(&"clippy"));
        assert!(last.args.contains(&"-D"));
        assert!(last.args.contains(&"warnings"));
    }

    #[test]
    fn integration_files_tolerate_missing() {
        // These integration test files may not exist yet in the repo;
        // the runner reports SKIPPED instead of FAILED.
        for name in ["two-node", "reorg", "ibd", "integration-mempool"] {
            let p = get(name).unwrap();
            for s in p.steps {
                assert!(
                    s.tolerate_missing_target,
                    "{name}/{} should tolerate missing test target",
                    s.label
                );
            }
        }
    }

    #[test]
    fn unknown_profile_returns_none() {
        assert!(get("definitely-not-real").is_none());
    }
}
