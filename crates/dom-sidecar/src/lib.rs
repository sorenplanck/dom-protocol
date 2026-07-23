//! Secure, fail-closed sidecar update primitives.
//!
//! The signature is the authenticity gate. A SHA-256 comparison alone only
//! establishes integrity relative to an untrusted hash and therefore cannot
//! authenticate a download origin.
#![deny(unsafe_code)]

pub mod sidecar_keys;

use minisign::{PublicKeyBox, SignatureBox};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// One artifact described by a signed sidecar manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    pub platform: String,
    pub sha256: String,
    pub url: String,
}

/// Signed release metadata. Absence of this document is deliberately fatal to
/// automatic promotion; v0.1.2 is therefore manual-install only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SidecarManifest {
    pub schema: u32,
    pub version: String,
    pub revision: String,
    pub network: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub rpc_protocol_version: u32,
    pub p2p_protocol_version: u32,
    pub storage_schema_version_supported: u32,
    pub min_wallet_version: String,
    pub published_at: String,
    pub artifacts: Vec<Artifact>,
}

/// Identity reported by the currently running node plus configured expectations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningIdentity {
    pub network: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub storage_schema_version_on_disk: u32,
    pub rpc_protocol_version: u32,
    pub p2p_protocol_version: u32,
}

#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("release has no signed sidecar manifest and is not eligible for automatic promotion")]
    MissingManifest,
    #[error("invalid signed manifest: {0}")]
    Manifest(String),
    #[error("signature does not verify under a pinned DOM release key")]
    UntrustedSignature,
    #[error("artifact SHA-256 mismatch")]
    HashMismatch,
    #[error("manifest has no artifact for platform {0}")]
    UnsupportedPlatform(String),
    #[error("candidate identity mismatch: {0}")]
    Identity(String),
    #[error("candidate supports storage schema {candidate}, but disk is schema {disk}")]
    StorageSchemaTooOld { candidate: u32, disk: u32 },
    #[error("invalid revision for filename: {0}")]
    InvalidRevision(String),
    #[error("filesystem error: {0}")]
    Io(#[from] std::io::Error),
}

/// Verify a detached Minisign signature against either compiled-in key.
///
/// This is deliberately separate from [`verify_artifact`]: signature success
/// proves authenticity; SHA-256 is an additional integrity check only.
pub fn verify_minisign(data: &[u8], signature: &str) -> Result<(), SidecarError> {
    let signature = SignatureBox::from_string(signature)
        .map_err(|error| SidecarError::Manifest(format!("invalid Minisign signature: {error}")))?;
    for encoded_key in sidecar_keys::TRUSTED_MINISIGN_KEYS {
        let key_text = format!("untrusted comment: DOM sidecar release key\n{encoded_key}");
        let Ok(key_box) = PublicKeyBox::from_string(&key_text) else {
            continue;
        };
        let Ok(key) = key_box.into_public_key() else {
            continue;
        };
        if minisign::verify(&key, &signature, Cursor::new(data), true, false, false).is_ok() {
            return Ok(());
        }
    }
    Err(SidecarError::UntrustedSignature)
}

/// Parse and authenticate a manifest. Missing input is intentionally rejected.
pub fn verify_manifest(
    manifest_bytes: Option<&[u8]>,
    signature: Option<&str>,
) -> Result<SidecarManifest, SidecarError> {
    let bytes = manifest_bytes.ok_or(SidecarError::MissingManifest)?;
    let signature = signature.ok_or(SidecarError::MissingManifest)?;
    verify_minisign(bytes, signature)?;
    serde_json::from_slice(bytes).map_err(|error| SidecarError::Manifest(error.to_string()))
}

/// Authenticate a downloaded artifact before accepting its manifest hash.
pub fn verify_artifact(
    artifact: &[u8],
    artifact_signature: &str,
    expected_sha256: &str,
) -> Result<(), SidecarError> {
    // An attacker controlling downloads can replace both artifact and manifest
    // hash. The signature must be the first acceptance gate.
    verify_minisign(artifact, artifact_signature)?;
    let actual = hex::encode(Sha256::digest(artifact));
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        return Err(SidecarError::HashMismatch);
    }
    Ok(())
}

/// Verify every downloaded release input in the required order: signed
/// manifest, signed binary, cheap hash check, then chain compatibility. This
/// is the fail-closed entry point used by a wallet updater.
pub fn verify_release(
    manifest_bytes: Option<&[u8]>,
    manifest_signature: Option<&str>,
    platform: &str,
    artifact: &[u8],
    artifact_signature: &str,
    running: &RunningIdentity,
) -> Result<SidecarManifest, SidecarError> {
    let manifest = verify_manifest(manifest_bytes, manifest_signature)?;
    let entry = manifest
        .artifacts
        .iter()
        .find(|entry| entry.platform == platform)
        .ok_or_else(|| SidecarError::UnsupportedPlatform(platform.into()))?;
    verify_artifact(artifact, artifact_signature, &entry.sha256)?;
    verify_promotion_identity(&manifest, running)?;
    Ok(manifest)
}

/// Reject a signed candidate unless it exactly matches the running chain.
pub fn verify_promotion_identity(
    manifest: &SidecarManifest,
    running: &RunningIdentity,
) -> Result<(), SidecarError> {
    for (field, candidate, current) in [
        ("network", &manifest.network, &running.network),
        ("chain_id", &manifest.chain_id, &running.chain_id),
        (
            "genesis_hash",
            &manifest.genesis_hash,
            &running.genesis_hash,
        ),
    ] {
        if candidate != current {
            return Err(SidecarError::Identity(format!("{field} differs")));
        }
    }
    if manifest.rpc_protocol_version != running.rpc_protocol_version {
        return Err(SidecarError::Identity(
            "rpc_protocol_version differs".into(),
        ));
    }
    if manifest.p2p_protocol_version != running.p2p_protocol_version {
        return Err(SidecarError::Identity(
            "p2p_protocol_version differs".into(),
        ));
    }
    if manifest.storage_schema_version_supported < running.storage_schema_version_on_disk {
        return Err(SidecarError::StorageSchemaTooOld {
            candidate: manifest.storage_schema_version_supported,
            disk: running.storage_schema_version_on_disk,
        });
    }
    Ok(())
}

/// Versioned sidecar installation, atomic current-pointer promotion and backup rollback.
#[derive(Debug, Clone)]
pub struct SidecarStore {
    app_data: PathBuf,
}

impl SidecarStore {
    pub fn new(app_data: impl Into<PathBuf>) -> Self {
        Self {
            app_data: app_data.into(),
        }
    }
    pub fn bin_dir(&self) -> PathBuf {
        self.app_data.join("bin")
    }
    pub fn current_pointer(&self) -> PathBuf {
        self.bin_dir().join("current")
    }
    pub fn binary_path(&self, revision: &str) -> Result<PathBuf, SidecarError> {
        if revision.is_empty() || !revision.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SidecarError::InvalidRevision(revision.into()));
        }
        Ok(self.bin_dir().join(format!("dom-node-{revision}")))
    }
    pub fn current_revision(&self) -> Result<Option<String>, SidecarError> {
        match fs::read_to_string(self.current_pointer()) {
            Ok(revision) => Ok(Some(revision.trim().to_owned())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }
    /// Install under a new versioned name. Existing binaries are never overwritten.
    pub fn install(&self, revision: &str, binary: &[u8]) -> Result<PathBuf, SidecarError> {
        let target = self.binary_path(revision)?;
        fs::create_dir_all(self.bin_dir())?;
        if target.exists() {
            return Ok(target);
        }
        let staged = self.bin_dir().join(format!(".{revision}.new"));
        fs::write(&staged, binary)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged, fs::Permissions::from_mode(0o700))?;
        }
        fs::rename(&staged, &target)?;
        Ok(target)
    }
    /// Promote by replacing a small pointer file, never an in-use binary.
    ///
    /// Unix replaces it atomically. Windows preserves the prior pointer while
    /// swapping because its rename API does not replace an existing file.
    pub fn promote(&self, revision: &str) -> Result<Option<String>, SidecarError> {
        let target = self.binary_path(revision)?;
        if !target.exists() {
            return Err(SidecarError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "candidate binary is not installed",
            )));
        }
        let previous = self.current_revision()?;
        let staged = self.bin_dir().join(".current.new");
        fs::write(&staged, revision)?;
        replace_pointer(&staged, &self.current_pointer())?;
        Ok(previous)
    }
    pub fn rollback(&self, previous: &str) -> Result<(), SidecarError> {
        self.promote(previous).map(|_| ())
    }
    /// Copy production data before a schema migration. The caller restores this
    /// snapshot on failure rather than attempting an untested reverse migration.
    pub fn backup_data_dir(&self, data_dir: &Path) -> Result<PathBuf, SidecarError> {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let backup = data_dir.with_file_name(format!(
            "{}.backup-{stamp}",
            data_dir.file_name().unwrap_or_default().to_string_lossy()
        ));
        copy_tree(data_dir, &backup)?;
        Ok(backup)
    }
    pub fn restore_data_dir(&self, backup: &Path, data_dir: &Path) -> Result<(), SidecarError> {
        if data_dir.exists() {
            fs::remove_dir_all(data_dir)?;
        }
        copy_tree(backup, data_dir)
    }
    /// If the candidate cannot operate, restore the old pointer before returning.
    pub fn promote_and_check<F>(&self, revision: &str, starts: F) -> Result<(), SidecarError>
    where
        F: FnOnce(&Path) -> bool,
    {
        let previous = self.promote(revision)?;
        let candidate = self.binary_path(revision)?;
        if starts(&candidate) {
            return Ok(());
        }
        if let Some(previous) = previous {
            self.rollback(&previous)?;
        }
        Err(SidecarError::Identity(
            "promoted node failed to operate; previous pointer restored".into(),
        ))
    }

    /// Promote only after the manifest matches the current instance, then
    /// probe the newly started node and roll back if its *observed* identity
    /// differs. The post-start check prevents a binary from merely declaring a
    /// chain identity in a signed document while operating another chain.
    pub fn promote_and_verify_running<F>(
        &self,
        revision: &str,
        manifest: &SidecarManifest,
        current: &RunningIdentity,
        probe_candidate: F,
    ) -> Result<(), SidecarError>
    where
        F: FnOnce(&Path) -> Result<RunningIdentity, SidecarError>,
    {
        verify_promotion_identity(manifest, current)?;
        let previous = self.promote(revision)?;
        let candidate = self.binary_path(revision)?;
        let result = probe_candidate(&candidate).and_then(|observed_candidate| {
            verify_promotion_identity(manifest, &observed_candidate)
        });
        if result.is_ok() {
            return Ok(());
        }
        if let Some(previous) = previous {
            self.rollback(&previous)?;
        }
        result
    }
}

fn replace_pointer(staged: &Path, current: &Path) -> Result<(), SidecarError> {
    #[cfg(not(windows))]
    {
        fs::rename(staged, current)?;
    }
    #[cfg(windows)]
    {
        let prior = current.with_extension("previous");
        if prior.exists() {
            fs::remove_file(&prior)?;
        }
        if current.exists() {
            fs::rename(current, &prior)?;
        }
        if let Err(error) = fs::rename(staged, current) {
            if prior.exists() {
                let _ = fs::rename(&prior, current);
            }
            return Err(error.into());
        }
        if prior.exists() {
            fs::remove_file(prior)?;
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), SidecarError> {
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use minisign::KeyPair;
    use std::io::Cursor;
    use tempfile::tempdir;

    const V012_SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUTwnDDKlXoZdN/AA02Xx1MAvy2wmLJNcBT5bsJo5mXgM1dVs7zMCrrbMMr3VgfRIucgdfPlXeIzVwOqkAD9LpIUSWSUDf6IPws=\ntrusted comment: timestamp:1784817594\tfile:dom-node-linux-x86_64\thashed\nW13IZJmdSqUQ3RYdneE8JNNsSgbBt7iz/CrXByuf74+o7tUA4mrqUMkzVrK4ajKsbgHpstmOmHXk+YaAFybSCw==\n";
    const V012_URL: &str = "https://github.com/sorenplanck/dom-protocol/releases/download/v0.1.2/dom-node-linux-x86_64";

    fn manifest() -> SidecarManifest {
        SidecarManifest {
            schema: 1,
            version: "0.1.3".into(),
            revision: "abcdef12".into(),
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            rpc_protocol_version: 1,
            p2p_protocol_version: 2,
            storage_schema_version_supported: 2,
            min_wallet_version: "0.3.1".into(),
            published_at: "2026-07-23T00:00:00Z".into(),
            artifacts: vec![],
        }
    }
    fn running() -> RunningIdentity {
        RunningIdentity {
            network: "mainnet".into(),
            chain_id: "chain".into(),
            genesis_hash: "genesis".into(),
            storage_schema_version_on_disk: 2,
            rpc_protocol_version: 1,
            p2p_protocol_version: 2,
        }
    }

    #[test]
    fn release_key_pins_are_present_and_distinct() {
        assert_ne!(
            sidecar_keys::PRIMARY_MINISIGN_KEY,
            sidecar_keys::RESERVE_MINISIGN_KEY
        );
    }

    #[test]
    fn published_v012_artifact_signature_verifies_with_primary_key() {
        let response = reqwest::blocking::get(V012_URL).expect("release artifact available");
        assert!(response.status().is_success());
        let bytes = response.bytes().unwrap().to_vec();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "72e02f911bbc5c046340d0abdb28a7d1508626c96149b12aa04902d1aa87461f"
        );
        verify_artifact(
            &bytes,
            V012_SIGNATURE,
            "72e02f911bbc5c046340d0abdb28a7d1508626c96149b12aa04902d1aa87461f",
        )
        .unwrap();
        let mut altered = bytes;
        altered[0] ^= 1;
        assert!(verify_artifact(
            &altered,
            V012_SIGNATURE,
            "72e02f911bbc5c046340d0abdb28a7d1508626c96149b12aa04902d1aa87461f"
        )
        .is_err());
    }

    #[test]
    fn rejects_corrupted_and_unknown_key_signatures() {
        assert!(verify_minisign(b"hello", "not a signature").is_err());
        let pair = KeyPair::generate_unencrypted_keypair().unwrap();
        let signed = minisign::sign(None, &pair.sk, Cursor::new(b"hello"), None, None)
            .unwrap()
            .to_string();
        assert!(verify_minisign(b"hello", &signed).is_err());
    }

    #[test]
    fn missing_manifest_is_not_promotable() {
        assert!(matches!(
            verify_manifest(None, None),
            Err(SidecarError::MissingManifest)
        ));
    }

    #[test]
    fn promotion_is_rejected_before_identity_when_manifest_signature_is_invalid() {
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        assert!(verify_manifest(Some(&bytes), Some("corrupted signature")).is_err());
    }

    #[test]
    fn release_verifier_refuses_missing_manifest_before_artifact_is_considered() {
        assert!(matches!(
            verify_release(None, None, "linux-x86_64", b"artifact", "bad", &running()),
            Err(SidecarError::MissingManifest)
        ));
    }
    #[test]
    fn refuses_chain_genesis_and_old_schema() {
        let mut candidate = manifest();
        candidate.chain_id = "other".into();
        assert!(matches!(
            verify_promotion_identity(&candidate, &running()),
            Err(SidecarError::Identity(_))
        ));
        let mut candidate = manifest();
        candidate.genesis_hash = "other".into();
        assert!(matches!(
            verify_promotion_identity(&candidate, &running()),
            Err(SidecarError::Identity(_))
        ));
        let mut candidate = manifest();
        candidate.storage_schema_version_supported = 1;
        assert!(matches!(
            verify_promotion_identity(&candidate, &running()),
            Err(SidecarError::StorageSchemaTooOld { .. })
        ));
    }
    #[test]
    fn rollback_restores_prior_pointer_and_backup_restores_data() {
        let dir = tempdir().unwrap();
        let store = SidecarStore::new(dir.path());
        store.install("aaaa1111", b"old").unwrap();
        store.install("bbbb2222", b"new").unwrap();
        store.promote("aaaa1111").unwrap();
        assert!(store.promote_and_check("bbbb2222", |_| false).is_err());
        assert_eq!(
            store.current_revision().unwrap().as_deref(),
            Some("aaaa1111")
        );
        let data = dir.path().join("node-data");
        fs::create_dir_all(&data).unwrap();
        fs::write(data.join("schema"), b"old").unwrap();
        let backup = store.backup_data_dir(&data).unwrap();
        fs::write(data.join("schema"), b"migrated").unwrap();
        store.restore_data_dir(&backup, &data).unwrap();
        assert_eq!(fs::read(data.join("schema")).unwrap(), b"old");
    }

    #[cfg(unix)]
    #[test]
    fn installed_unix_sidecar_is_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let path = SidecarStore::new(dir.path())
            .install("aaaa1111", b"node")
            .unwrap();
        assert_ne!(fs::metadata(path).unwrap().permissions().mode() & 0o111, 0);
    }

    #[test]
    fn post_start_chain_divergence_rolls_back_to_operating_node() {
        let dir = tempdir().unwrap();
        let store = SidecarStore::new(dir.path());
        store.install("aaaa1111", b"old").unwrap();
        store.install("bbbb2222", b"new").unwrap();
        store.promote("aaaa1111").unwrap();
        let mut observed = running();
        observed.genesis_hash = "wrong-genesis".into();
        assert!(store
            .promote_and_verify_running("bbbb2222", &manifest(), &running(), |_| Ok(observed))
            .is_err());
        assert_eq!(
            store.current_revision().unwrap().as_deref(),
            Some("aaaa1111")
        );
        assert!(store.binary_path("aaaa1111").unwrap().exists());
    }
}
