//! Offline authoring and verification tool for the signed Wallet update feed.
//!
//! The private key never leaves the operator machine and never reaches CI.
//! Flow: `draft` on the downloaded CI artifacts, sign the canonical bytes and
//! the three updater artifacts locally with Minisign, `finalize` to inject the
//! detached signatures, then `verify` as the mandatory pre-publish gate.
//!
//! ```text
//! cargo run -p dom-wallet-updater --example feed_tool -- \
//!     draft <artifacts-dir> <version> <wallet-revision>
//! minisign -Sm <artifacts-dir>/<each updater artifact>
//! cargo run -p dom-wallet-updater --example feed_tool -- finalize <artifacts-dir>
//! minisign -Sm <artifacts-dir>/dom-manifest-canonical.bin
//! cargo run -p dom-wallet-updater --example feed_tool -- finalize <artifacts-dir>
//! cargo run -p dom-wallet-updater --example feed_tool -- verify <artifacts-dir>
//! ```

use base64::Engine as _;
use dom_wallet_updater::{
    select_artifact, validate_download, validate_wallet_manifest, verify_wallet_manifest_signature,
    ArtifactDescriptor, MinisignVerifier, SignatureVerifier, UpdateError, WalletDecision,
    WalletManifest, WalletPolicy, EMBEDDED_NODE_REVISION, UPDATE_CHANNEL,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Pinned primary DOM release signing key (Minisign key ID 74197A95CA309CF0).
const RELEASE_PUBLIC_KEY: &str = "RWTwnDDKlXoZdG3obVRiLPfVRHr17E0Fj2GN8IZ2rBkipRZvIIW6PLJ3";
/// Version of the embedded `dom-node` crate at [`EMBEDDED_NODE_REVISION`].
const EMBEDDED_NODE_VERSION: &str = "0.2.0";
/// Feed validity window; re-author and re-sign before it lapses.
const EXPIRY_DAYS: i64 = 30;

const REPOSITORY: &str = "https://github.com/sorenplanck/dom-wallet-v3";
const CANONICAL_FILE: &str = "dom-manifest-canonical.bin";
const DRAFT_FILE: &str = "latest.draft.json";
const FINAL_FILE: &str = "latest.json";

/// Tauri platform key, wallet policy platform, and artifact filename suffix.
const PLATFORMS: [(&str, &str, &str, &str); 3] = [
    ("linux-x86_64", "linux", "x86_64", "_amd64.AppImage"),
    ("windows-x86_64", "windows", "x86_64", "-setup.exe"),
    ("darwin-aarch64", "macos", "aarch64", ".app.tar.gz"),
];

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let result = match arguments.get(1).map(String::as_str) {
        Some("draft") if arguments.len() == 5 => {
            draft(Path::new(&arguments[2]), &arguments[3], &arguments[4])
        }
        Some("finalize") if arguments.len() == 3 => finalize(Path::new(&arguments[2])),
        Some("verify") if arguments.len() == 3 => verify(Path::new(&arguments[2])),
        _ => Err(concat!(
            "usage: feed_tool draft <artifacts-dir> <version> <wallet-revision>\n",
            "       feed_tool finalize <artifacts-dir>\n",
            "       feed_tool verify <artifacts-dir>"
        )
        .to_string()),
    };
    if let Err(message) = result {
        eprintln!("feed_tool: {message}");
        std::process::exit(1);
    }
}

fn find_artifact(directory: &Path, suffix: &str) -> Result<PathBuf, String> {
    let mut matches: Vec<PathBuf> = std::fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(suffix))
        })
        .collect();
    matches.sort();
    match matches.as_slice() {
        [single] => Ok(single.clone()),
        [] => Err(format!("no artifact matching *{suffix}")),
        _ => Err(format!("more than one artifact matching *{suffix}")),
    }
}

fn format_rfc3339(moment: time::OffsetDateTime) -> String {
    moment
        .replace_millisecond(0)
        .expect("zero millisecond is valid")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("UTC timestamps always format")
}

fn canonical_manifest_bytes(manifest: &WalletManifest) -> Vec<u8> {
    let mut unsigned = manifest.clone();
    unsigned.manifest_signature.clear();
    serde_json::to_vec(&unsigned).expect("manifest serializes")
}

fn draft(directory: &Path, version: &str, wallet_revision: &str) -> Result<(), String> {
    if wallet_revision.len() != 40 || !wallet_revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("wallet revision must be a full 40-hex commit id".into());
    }
    let tag = format!("wallet-v{version}");
    let mut platforms = serde_json::Map::new();
    let mut artifacts = Vec::new();
    for (platform_key, target, architecture, suffix) in PLATFORMS {
        let path = find_artifact(directory, suffix)?;
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("artifact file name is not valid UTF-8")?;
        let bytes =
            std::fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
        let url = format!("{REPOSITORY}/releases/download/{tag}/{file_name}");
        println!("{platform_key}: {file_name} ({} bytes)", bytes.len());
        platforms.insert(
            platform_key.to_string(),
            serde_json::json!({ "signature": "", "url": url }),
        );
        artifacts.push(ArtifactDescriptor {
            target: target.into(),
            architecture: architecture.into(),
            url: url.parse().expect("release URL parses"),
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            size: bytes.len() as u64,
            signature: String::new(),
        });
    }

    let published = time::OffsetDateTime::now_utc();
    let manifest = WalletManifest {
        schema_version: 1,
        channel: UPDATE_CHANNEL.into(),
        version: version.into(),
        published_at: format_rfc3339(published),
        expires_at: format_rfc3339(published + time::Duration::days(EXPIRY_DAYS)),
        minimum_supported_version: "0.2.0".into(),
        critical_update: false,
        draft: false,
        prerelease: false,
        release_url: format!("{REPOSITORY}/releases/tag/{tag}")
            .parse()
            .expect("release URL parses"),
        release_notes: format!("DOM Wallet V3 {version} stable release."),
        wallet_revision: wallet_revision.into(),
        embedded_node_version: EMBEDDED_NODE_VERSION.into(),
        embedded_node_revision: EMBEDDED_NODE_REVISION.into(),
        network: "mainnet".into(),
        minimum_wallet_schema: 2,
        artifacts,
        manifest_signature: String::new(),
    };

    let feed = serde_json::json!({
        "version": version,
        "notes": manifest.release_notes,
        "pub_date": manifest.published_at,
        "platforms": platforms,
        "dom_manifest": serde_json::to_value(&manifest).expect("manifest serializes"),
    });
    write(
        directory.join(DRAFT_FILE),
        serde_json::to_vec_pretty(&feed).expect("feed serializes"),
    )?;
    println!("draft written; sign the three artifacts with minisign -Sm, then run finalize");
    Ok(())
}

fn write(path: PathBuf, bytes: Vec<u8>) -> Result<(), String> {
    std::fs::write(&path, bytes).map_err(|error| format!("write {}: {error}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}

fn read_signature_file(artifact_path: &Path) -> Result<String, String> {
    let mut signature_path = artifact_path.as_os_str().to_owned();
    signature_path.push(".minisig");
    std::fs::read_to_string(Path::new(&signature_path))
        .map_err(|error| format!("missing detached signature {signature_path:?}: {error}"))
}

fn finalize(directory: &Path) -> Result<(), String> {
    let draft = std::fs::read_to_string(directory.join(DRAFT_FILE))
        .map_err(|error| format!("missing {DRAFT_FILE}: {error}"))?;
    let mut feed: serde_json::Value =
        serde_json::from_str(&draft).map_err(|error| format!("parse {DRAFT_FILE}: {error}"))?;
    let mut manifest: WalletManifest = serde_json::from_value(feed["dom_manifest"].clone())
        .map_err(|error| format!("parse dom_manifest: {error}"))?;

    for (index, (platform_key, _, _, suffix)) in PLATFORMS.iter().enumerate() {
        let artifact_path = find_artifact(directory, suffix)?;
        let signature_text = read_signature_file(&artifact_path)?;
        let signature_base64 =
            base64::engine::general_purpose::STANDARD.encode(signature_text.as_bytes());
        feed["platforms"][platform_key]["signature"] =
            serde_json::Value::String(signature_base64.clone());
        manifest.artifacts[index].signature = signature_base64;
    }
    // The manifest signature covers the artifact signatures, so the canonical
    // bytes exist only after every artifact signature is injected. First pass:
    // emit the canonical file and stop for the operator to sign it. Second
    // pass (identical bytes, deterministic re-derivation): inject the manifest
    // signature and produce the final feed.
    let canonical_path = directory.join(CANONICAL_FILE);
    write(canonical_path.clone(), canonical_manifest_bytes(&manifest))?;
    let Ok(manifest_signature) = read_signature_file(&canonical_path) else {
        println!(
            "canonical bytes written; sign {CANONICAL_FILE} with minisign -Sm and re-run finalize"
        );
        return Ok(());
    };
    manifest.manifest_signature = manifest_signature;

    feed["dom_manifest"] = serde_json::to_value(&manifest).expect("manifest serializes");
    write(
        directory.join(FINAL_FILE),
        serde_json::to_vec_pretty(&feed).expect("feed serializes"),
    )?;
    verify(directory)
}

fn verify(directory: &Path) -> Result<(), String> {
    let feed_text = std::fs::read_to_string(directory.join(FINAL_FILE))
        .map_err(|error| format!("missing {FINAL_FILE}: {error}"))?;
    let feed: serde_json::Value =
        serde_json::from_str(&feed_text).map_err(|error| format!("parse {FINAL_FILE}: {error}"))?;
    let manifest: WalletManifest = serde_json::from_value(
        feed.get("dom_manifest")
            .cloned()
            .ok_or("feed is missing dom_manifest")?,
    )
    .map_err(|error| format!("parse dom_manifest: {error}"))?;

    let public_key = match std::env::var("DOM_FEED_TOOL_REHEARSAL_PUBKEY") {
        Ok(rehearsal_key) => {
            eprintln!("WARNING: REHEARSAL KEY OVERRIDE ACTIVE — this run proves the pipeline,");
            eprintln!("WARNING: not the release. Never publish a feed verified this way.");
            rehearsal_key
        }
        Err(_) => RELEASE_PUBLIC_KEY.to_string(),
    };
    let verifier = MinisignVerifier::from_base64(&public_key).map_err(describe("public key"))?;
    verify_wallet_manifest_signature(&manifest, &verifier)
        .map_err(describe("manifest signature"))?;
    println!("manifest signature: OK");

    let now = time::OffsetDateTime::now_utc();
    for (platform_key, target, architecture, suffix) in PLATFORMS {
        let policy = WalletPolicy {
            installed_version: "0.2.0",
            update_channel: UPDATE_CHANNEL,
            target,
            architecture,
            network: "mainnet",
            wallet_schema: 2,
        };
        match validate_wallet_manifest(&manifest, &policy, now).map_err(describe(platform_key))? {
            WalletDecision::Available(version) => {
                println!("{platform_key}: manifest valid, offers {version}")
            }
            WalletDecision::UpToDate => return Err(format!("{platform_key}: not an upgrade")),
        }
        let artifact = select_artifact(&manifest, target, architecture)
            .ok_or(format!("{platform_key}: no unique artifact"))?;
        let entry = &feed["platforms"][platform_key];
        if entry["url"].as_str() != Some(artifact.url.as_str())
            || entry["signature"].as_str() != Some(artifact.signature.as_str())
        {
            return Err(format!(
                "{platform_key}: platforms entry disagrees with dom_manifest"
            ));
        }
        let local = find_artifact(directory, suffix)?;
        let bytes =
            std::fs::read(&local).map_err(|error| format!("read {}: {error}", local.display()))?;
        validate_download(&bytes, artifact).map_err(describe(platform_key))?;
        let signature_text = base64::engine::general_purpose::STANDARD
            .decode(&artifact.signature)
            .ok()
            .and_then(|decoded| String::from_utf8(decoded).ok())
            .ok_or(format!(
                "{platform_key}: artifact signature is not base64 text"
            ))?;
        if !verifier.verify(&bytes, &signature_text) {
            return Err(format!(
                "{platform_key}: artifact Minisign signature INVALID"
            ));
        }
        println!(
            "{platform_key}: size, sha256 and Minisign signature OK ({})",
            local.display()
        );
    }
    if public_key == RELEASE_PUBLIC_KEY {
        println!("feed fully verified against the pinned release key");
    } else {
        println!("feed verified against the REHEARSAL key only — not publishable");
    }
    Ok(())
}

fn describe(context: &str) -> impl Fn(UpdateError) -> String + '_ {
    move |error| format!("{context}: {error}")
}
