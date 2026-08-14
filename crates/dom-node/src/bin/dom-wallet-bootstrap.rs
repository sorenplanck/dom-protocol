//! Secure standalone bootstrap for a canonical deterministic miner WalletDir.
//!
//! Only non-secret filesystem paths and the network appear in argv. Password
//! and mnemonic contents are file-only, never printed or placed in the process
//! environment. This is an operator tool; the node itself still only opens an
//! existing WalletDir and never invents one (DOM-SEC-004).

use dom_node::secret_file::load_owner_only_utf8_secret_file;
use dom_wallet::{Bip39Seed, Network, WalletDir};
use std::{ffi::OsString, io::Write, path::PathBuf};

const MAX_WALLET_PASSWORD_BYTES: u64 = 1024;

struct Arguments {
    wallet_dir: PathBuf,
    password_file: PathBuf,
    phrase_output_file: PathBuf,
    network: Network,
}

fn main() -> anyhow::Result<()> {
    let arguments = parse_arguments(std::env::args_os())?;
    let wallet_parent = arguments
        .wallet_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("wallet directory must have a parent"))?;
    let phrase_parent = arguments
        .phrase_output_file
        .parent()
        .ok_or_else(|| anyhow::anyhow!("phrase output file must have a parent"))?;
    validate_owner_only_directory(wallet_parent, "wallet parent")?;
    validate_owner_only_directory(phrase_parent, "phrase-output parent")?;
    if arguments
        .phrase_output_file
        .starts_with(&arguments.wallet_dir)
    {
        anyhow::bail!("phrase output must be outside the WalletDir");
    }
    let password = load_owner_only_utf8_secret_file(
        &arguments.password_file,
        "wallet password",
        1,
        MAX_WALLET_PASSWORD_BYTES,
    )?;
    if password
        .chars()
        .any(|character| matches!(character, '\0' | '\r' | '\n'))
    {
        anyhow::bail!("wallet password file contains a forbidden control character");
    }
    prepare_owner_only_empty_wallet_directory(&arguments.wallet_dir)?;
    if arguments.phrase_output_file.exists()
        || std::fs::symlink_metadata(&arguments.phrase_output_file).is_ok()
    {
        anyhow::bail!("phrase output path already exists; refusing to overwrite it");
    }

    let seed = Bip39Seed::generate_new()?;
    write_new_owner_only_phrase(&arguments.phrase_output_file, seed.phrase())?;
    let genesis = dom_core::startup_genesis_hash_for_network_magic(arguments.network.magic())?;
    let wallet = WalletDir::create_from_seed(
        &arguments.wallet_dir,
        &password,
        arguments.network,
        &genesis,
        &seed,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "wallet creation failed after the recovery phrase was durably retained in the owner-only phrase file; preserve that file and restore into a new empty WalletDir: {error}"
        )
    })?;
    drop(wallet);
    println!("wallet_dir: {}", arguments.wallet_dir.display());
    println!("network: {:?}", arguments.network);
    println!("schema: v2");
    println!("phrase_output: [REDACTED OWNER-ONLY FILE]");
    Ok(())
}

fn validate_owner_only_directory(path: &std::path::Path, label: &str) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| anyhow::anyhow!("cannot inspect {label}: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("{label} must be an existing non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("{label} must not be accessible by group or others");
        }
    }
    Ok(())
}

fn prepare_owner_only_empty_wallet_directory(path: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() || std::fs::symlink_metadata(path).is_ok() {
        validate_owner_only_directory(path, "wallet directory")?;
    } else {
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .map_err(|error| anyhow::anyhow!("cannot create wallet directory: {error}"))?;
        validate_owner_only_directory(path, "wallet directory")?;
    }
    if std::fs::read_dir(path)
        .map_err(|error| anyhow::anyhow!("cannot inspect wallet directory: {error}"))?
        .next()
        .is_some()
    {
        anyhow::bail!("wallet directory is not empty; refusing to overwrite it");
    }
    Ok(())
}

fn write_new_owner_only_phrase(path: &std::path::Path, phrase: &str) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| anyhow::anyhow!("cannot create phrase output file: {error}"))?;
    file.write_all(phrase.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|error| anyhow::anyhow!("cannot durably write phrase output file: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| anyhow::anyhow!("cannot inspect phrase output file: {error}"))?;
    if !metadata.is_file() {
        anyhow::bail!("phrase output is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("phrase output file must not be accessible by group or others");
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| anyhow::anyhow!("cannot durably sync phrase directory: {error}"))?;
    }
    Ok(())
}

fn parse_arguments(arguments: impl IntoIterator<Item = OsString>) -> anyhow::Result<Arguments> {
    let mut arguments = arguments.into_iter();
    let _program = arguments.next();
    let mut wallet_dir = None;
    let mut password_file = None;
    let mut phrase_output_file = None;
    let mut network = None;
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag:?}"))?;
        match flag.to_str() {
            Some("--wallet-dir") => wallet_dir = Some(PathBuf::from(value)),
            Some("--password-file") => password_file = Some(PathBuf::from(value)),
            Some("--phrase-output-file") => phrase_output_file = Some(PathBuf::from(value)),
            Some("--network") => {
                network = Some(match value.to_str() {
                    Some("mainnet") => Network::Mainnet,
                    Some("testnet") => Network::Testnet,
                    Some("regtest") => Network::Regtest,
                    _ => anyhow::bail!("network must be mainnet, testnet, or regtest"),
                })
            }
            _ => anyhow::bail!("unknown argument {flag:?}"),
        }
    }
    Ok(Arguments {
        wallet_dir: wallet_dir.ok_or_else(|| anyhow::anyhow!("--wallet-dir is required"))?,
        password_file: password_file
            .ok_or_else(|| anyhow::anyhow!("--password-file is required"))?,
        phrase_output_file: phrase_output_file
            .ok_or_else(|| anyhow::anyhow!("--phrase-output-file is required"))?,
        network: network.ok_or_else(|| anyhow::anyhow!("--network is required"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        parse_arguments, prepare_owner_only_empty_wallet_directory, validate_owner_only_directory,
        write_new_owner_only_phrase,
    };
    use std::ffi::OsString;

    #[test]
    fn parser_requires_only_non_secret_paths_and_network() {
        let parsed = parse_arguments(
            [
                "dom-wallet-bootstrap",
                "--wallet-dir",
                "/tmp/wallet",
                "--password-file",
                "/tmp/password",
                "--phrase-output-file",
                "/tmp/phrase",
                "--network",
                "regtest",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .unwrap();
        assert_eq!(parsed.wallet_dir, std::path::Path::new("/tmp/wallet"));
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_paths_are_owner_only_non_symlink_and_create_once() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        validate_owner_only_directory(root.path(), "test root").unwrap();

        let wallet = root.path().join("wallet");
        prepare_owner_only_empty_wallet_directory(&wallet).unwrap();
        let mode = std::fs::metadata(&wallet).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);

        let phrase = root.path().join("phrase");
        write_new_owner_only_phrase(&phrase, "public-test-words").unwrap();
        let mode = std::fs::metadata(&phrase).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        assert!(write_new_owner_only_phrase(&phrase, "replacement").is_err());

        let linked = root.path().join("linked-wallet");
        symlink(&wallet, &linked).unwrap();
        assert!(prepare_owner_only_empty_wallet_directory(&linked).is_err());
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(validate_owner_only_directory(root.path(), "test root").is_err());
    }
}
