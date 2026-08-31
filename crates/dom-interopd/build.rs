use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default());
    let repository = manifest_dir.join("../..");
    let lockfile = repository.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lockfile.display());
    println!(
        "cargo:rerun-if-changed={}",
        repository.join(".git/HEAD").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repository.join(".git/index").display()
    );

    let commit =
        git_output(&repository, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".to_owned());
    let dirty = git_output(&repository, &["status", "--porcelain"])
        .map(|output| !output.is_empty())
        .unwrap_or(true);
    let lock_digest = fs::read(&lockfile)
        .ok()
        .and_then(|bytes| blake2b_256_hex(&bytes))
        .unwrap_or_else(|| "unavailable".to_owned());

    println!("cargo:rustc-env=DOM_INTEROP_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=DOM_INTEROP_GIT_DIRTY={dirty}");
    println!("cargo:rustc-env=DOM_INTEROP_CARGO_LOCK_BLAKE2B256={lock_digest}");
    println!(
        "cargo:rustc-env=DOM_INTEROP_BUILD_TARGET={}",
        env::var("TARGET").unwrap_or_else(|_| "unknown".to_owned())
    );
    println!(
        "cargo:rustc-env=DOM_INTEROP_BUILD_PROFILE={}",
        env::var("PROFILE").unwrap_or_else(|_| "unknown".to_owned())
    );
}

fn git_output(repository: &PathBuf, arguments: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn blake2b_256_hex(bytes: &[u8]) -> Option<String> {
    let mut hash = Blake2bVar::new(32).ok()?;
    hash.update(bytes);
    let mut digest = [0u8; 32];
    hash.finalize_variable(&mut digest).ok()?;
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").ok()?;
    }
    Some(encoded)
}
