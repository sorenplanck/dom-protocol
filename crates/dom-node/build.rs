use std::{env, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=DOM_BUILD_COMMIT");
    let commit = env::var("DOM_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=DOM_NODE_BUILD_COMMIT={commit}");
}
