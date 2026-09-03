use std::path::Path;

/// Publish the embedded node's real package version as `DOM_NODE_VERSION`.
///
/// This used to be a hardcoded `"0.1.0"` literal in `get_build_info`, which
/// reported the same number no matter which node was actually compiled in —
/// a value that looked authoritative and told the user nothing. The version is
/// read from the workspace lockfile, which is the resolver's own record of what
/// was built, so it cannot drift from the binary.
///
/// When the version cannot be determined the variable is simply not set and
/// `get_build_info` reports `UNAVAILABLE`, the same honest fallback already used
/// for the wallet revision. It never invents a number.
fn main() {
    if let Some(version) = locked_package_version("dom-node") {
        println!("cargo:rustc-env=DOM_NODE_VERSION={version}");
    }
    println!("cargo:rerun-if-changed=../Cargo.lock");
    tauri_build::build()
}

/// Read `version` for `package` out of the workspace `Cargo.lock`.
///
/// Deliberately a small hand-rolled scan rather than a TOML dependency or a
/// `cargo metadata` subprocess: build scripts must stay offline and must not
/// re-enter cargo.
fn locked_package_version(package: &str) -> Option<String> {
    let lockfile = Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.lock");
    let contents = std::fs::read_to_string(lockfile).ok()?;
    let mut in_package = false;
    for line in contents.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_package = false;
            continue;
        }
        if let Some(name) = line.strip_prefix("name = ") {
            in_package = name.trim_matches('"') == package;
            continue;
        }
        if in_package {
            if let Some(version) = line.strip_prefix("version = ") {
                return Some(version.trim_matches('"').to_string());
            }
        }
    }
    None
}
