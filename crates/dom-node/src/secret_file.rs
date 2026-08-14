//! Owner-only text-secret loading for standalone node processes.
//!
//! Secrets are named by a non-secret environment variable or command-line
//! path, but their contents never cross argv or the process environment. The
//! loader rejects symlinks, group/other access, replacement during open,
//! unbounded input, and invalid UTF-8 before returning the secret to its
//! in-process consumer.

use std::{io::Read, path::Path};

/// Read one bounded UTF-8 secret from an owner-only regular file.
///
/// One terminal LF or CRLF is ignored so files created by ordinary secret
/// provisioning tools are accepted. Embedded line endings are left to the
/// caller's format-specific validation. `description` must be a static,
/// non-secret label used only in redacted diagnostics.
pub fn load_owner_only_utf8_secret_file(
    path: &Path,
    description: &'static str,
    minimum_bytes: u64,
    maximum_bytes: u64,
) -> anyhow::Result<String> {
    if minimum_bytes == 0 || maximum_bytes < minimum_bytes {
        anyhow::bail!("invalid {description} secret-file bounds");
    }

    let path_metadata = std::fs::symlink_metadata(path)
        .map_err(|error| anyhow::anyhow!("cannot inspect {description} file: {error}"))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        anyhow::bail!("{description} path must name a regular, non-symlink file");
    }
    validate_owner_only_permissions(&path_metadata, description)?;

    if path_metadata.len() == 0 || path_metadata.len() > maximum_bytes.saturating_add(2) {
        anyhow::bail!(
            "{description} file must contain {minimum_bytes}..={maximum_bytes} bytes plus at most one trailing newline"
        );
    }

    let file = std::fs::File::open(path)
        .map_err(|error| anyhow::anyhow!("cannot open {description} file: {error}"))?;
    let open_metadata = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("cannot inspect opened {description} file: {error}"))?;
    if !open_metadata.is_file() {
        anyhow::bail!("opened {description} path is not a regular file");
    }
    validate_owner_only_permissions(&open_metadata, description)?;

    // Detect replacement between path inspection and open. Reading through
    // the already-open descriptor is race-free for the rest of this call.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != open_metadata.dev() || path_metadata.ino() != open_metadata.ino()
        {
            anyhow::bail!("{description} file changed while it was being opened");
        }
    }

    let mut raw = Vec::new();
    file.take(maximum_bytes.saturating_add(3))
        .read_to_end(&mut raw)
        .map_err(|error| anyhow::anyhow!("cannot read {description} file: {error}"))?;
    if raw.len() as u64 > maximum_bytes.saturating_add(2) {
        anyhow::bail!("{description} file exceeds the bounded size");
    }
    let raw = String::from_utf8(raw)
        .map_err(|_| anyhow::anyhow!("{description} file is not valid UTF-8"))?;
    let secret = raw
        .strip_suffix("\r\n")
        .or_else(|| raw.strip_suffix('\n'))
        .unwrap_or(&raw);
    let length = secret.len() as u64;
    if length < minimum_bytes || length > maximum_bytes {
        anyhow::bail!("{description} must contain {minimum_bytes}..={maximum_bytes} bytes");
    }
    Ok(secret.to_owned())
}

fn validate_owner_only_permissions(
    metadata: &std::fs::Metadata,
    description: &'static str,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("{description} file must not be accessible by group or others");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::load_owner_only_utf8_secret_file;

    #[cfg(unix)]
    fn secret_file(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("secret fixture directory");
        let path = directory.path().join("secret");
        std::fs::write(&path, contents).expect("write secret fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("secure secret fixture");
        (directory, path)
    }

    #[cfg(unix)]
    #[test]
    fn accepts_owner_only_bounded_utf8_and_one_newline() {
        let (_directory, path) = secret_file(b"correct horse battery staple\n");
        assert_eq!(
            load_owner_only_utf8_secret_file(&path, "test secret", 1, 64).unwrap(),
            "correct horse battery staple"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_insecure_mode_invalid_utf8_and_oversize() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let (_directory, path) = secret_file(b"valid-secret");
        let link = path.with_extension("link");
        symlink(&path, &link).expect("symlink fixture");
        assert!(load_owner_only_utf8_secret_file(&link, "test secret", 1, 64).is_err());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))
            .expect("insecure fixture mode");
        assert!(load_owner_only_utf8_secret_file(&path, "test secret", 1, 64).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restore fixture mode");

        std::fs::write(&path, [0xff]).expect("invalid UTF-8 fixture");
        assert!(load_owner_only_utf8_secret_file(&path, "test secret", 1, 64).is_err());
        std::fs::write(&path, [b'x'; 65]).expect("oversized fixture");
        assert!(load_owner_only_utf8_secret_file(&path, "test secret", 1, 64).is_err());
    }
}
