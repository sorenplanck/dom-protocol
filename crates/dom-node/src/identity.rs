//! Node identity persistence.
//!
//! The Noise/static keypair is stored in `{data_dir}/node_identity.bin`:
//! exactly 64 bytes — privkey[32] || pubkey[32].
//!
//! Corruption policy: fail-closed. A malformed or wrong-size file returns
//! `DomError::Internal` rather than silently regenerating. The operator must
//! remove the file manually to regenerate a new identity.

use dom_core::DomError;
use std::io;
use std::path::Path;

const IDENTITY_FILE: &str = "node_identity.bin";
const IDENTITY_TMP_FILE: &str = "node_identity.bin.tmp";
const IDENTITY_SIZE: usize = 64;

/// Load the persisted node identity or generate and persist a new one.
///
/// Returns `(privkey, pubkey)`. On first call the keypair is generated and
/// written atomically (temp-file rename) to `{data_dir}/node_identity.bin`.
/// Subsequent calls load the same keypair deterministically.
///
/// Fails if the identity file exists but is malformed or corrupt (fail-closed).
/// Remove the file manually to regenerate.
pub fn load_or_create_identity(data_dir: &Path) -> Result<([u8; 32], [u8; 32]), DomError> {
    let path = data_dir.join(IDENTITY_FILE);

    match std::fs::read(&path) {
        Ok(bytes) => {
            if bytes.len() != IDENTITY_SIZE {
                return Err(DomError::Internal(format!(
                    "node identity file has wrong size: expected {IDENTITY_SIZE}, got {}; \
                     remove {:?} to regenerate",
                    bytes.len(),
                    path
                )));
            }
            let mut privkey = [0u8; 32];
            let mut stored_pubkey = [0u8; 32];
            privkey.copy_from_slice(&bytes[..32]);
            stored_pubkey.copy_from_slice(&bytes[32..]);
            let derived_pubkey = dom_wire::handshake::pubkey_from_privkey(&privkey);
            if derived_pubkey != stored_pubkey {
                return Err(DomError::Internal(format!(
                    "node identity file is corrupt (pubkey mismatch); \
                     remove {:?} to regenerate",
                    path
                )));
            }
            Ok((privkey, stored_pubkey))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let (privkey, pubkey) = dom_wire::handshake::generate_static_keypair();
            persist_identity(data_dir, &privkey, &pubkey)?;
            Ok((privkey, pubkey))
        }
        Err(e) => Err(DomError::Internal(format!(
            "failed to read node identity file {:?}: {e}",
            path
        ))),
    }
}

fn persist_identity(
    data_dir: &Path,
    privkey: &[u8; 32],
    pubkey: &[u8; 32],
) -> Result<(), DomError> {
    let tmp_path = data_dir.join(IDENTITY_TMP_FILE);
    let final_path = data_dir.join(IDENTITY_FILE);

    let mut bytes = [0u8; IDENTITY_SIZE];
    bytes[..32].copy_from_slice(privkey);
    bytes[32..].copy_from_slice(pubkey);

    std::fs::write(&tmp_path, bytes).map_err(|e| {
        DomError::Internal(format!(
            "failed to write node identity tmp file {:?}: {e}",
            tmp_path
        ))
    })?;

    std::fs::rename(&tmp_path, &final_path).map_err(|e| {
        DomError::Internal(format!(
            "failed to persist node identity file {:?}: {e}",
            final_path
        ))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let id = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("dom-identity-test-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn first_start_creates_identity_file() {
        let dir = TempDir::new();
        assert!(!dir.path().join(IDENTITY_FILE).exists());

        let (privkey, pubkey) = load_or_create_identity(dir.path()).unwrap();

        assert!(
            dir.path().join(IDENTITY_FILE).exists(),
            "identity file must exist after first call"
        );
        assert_eq!(
            dom_wire::handshake::pubkey_from_privkey(&privkey),
            pubkey,
            "returned pubkey must be derivable from returned privkey"
        );
    }

    #[test]
    fn second_start_loads_same_identity() {
        let dir = TempDir::new();

        let (priv1, pub1) = load_or_create_identity(dir.path()).unwrap();
        let (priv2, pub2) = load_or_create_identity(dir.path()).unwrap();

        assert_eq!(priv1, priv2, "privkey must be identical on second load");
        assert_eq!(pub1, pub2, "pubkey must be identical on second load");
    }

    #[test]
    fn wrong_size_identity_is_rejected() {
        let dir = TempDir::new();
        let path = dir.path().join(IDENTITY_FILE);
        std::fs::write(&path, b"short").unwrap();

        let result = load_or_create_identity(dir.path());
        assert!(result.is_err(), "wrong-size file must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("wrong size"),
            "error must mention wrong size, got: {msg}"
        );
    }

    #[test]
    fn corrupt_pubkey_is_rejected() {
        let dir = TempDir::new();
        let path = dir.path().join(IDENTITY_FILE);

        let (privkey, _) = dom_wire::handshake::generate_static_keypair();
        let mut bytes = [0u8; IDENTITY_SIZE];
        bytes[..32].copy_from_slice(&privkey);
        bytes[32..].fill(0xFF); // corrupt pubkey
        std::fs::write(&path, bytes).unwrap();

        let result = load_or_create_identity(dir.path());
        assert!(result.is_err(), "corrupt pubkey must be rejected");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("corrupt"),
            "error must mention corruption, got: {msg}"
        );
    }

    #[test]
    fn identity_persistence_is_independent_of_consensus_state() {
        // No chain state is touched by load_or_create_identity — this is a
        // structural test: calling it on two different dirs yields two
        // independent identities with no shared state.
        let dir_a = TempDir::new();
        let dir_b = TempDir::new();

        let (priv_a, pub_a) = load_or_create_identity(dir_a.path()).unwrap();
        let (priv_b, pub_b) = load_or_create_identity(dir_b.path()).unwrap();

        assert_ne!(
            priv_a, priv_b,
            "independent dirs must produce distinct identities"
        );
        assert_ne!(
            pub_a, pub_b,
            "independent dirs must produce distinct pubkeys"
        );
    }
}
