use clap::{Parser, Subcommand, ValueEnum};
use dom_core::Hash256;
use dom_wallet::{
    restore_from_phrase, Bip39Seed, InMemoryChainScan, Network, SeedAcceptance, WalletDir,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

const ACCESS_STATE_FILE: &str = "wallet.access.json";

#[derive(Parser)]
#[command(name = "dom-wallet")]
#[command(about = "DOM wallet foundation CLI", version, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new deterministic wallet directory.
    Init {
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long, value_enum, default_value = "regtest")]
        network: NetworkArg,
    },
    /// Restore a deterministic wallet from a BIP-39 phrase.
    ///
    /// Phase 1 restore is offline-only: it recreates the encrypted wallet and
    /// persists the seed, but does not scan a node yet.
    Restore {
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        password: String,
        #[arg(long)]
        phrase_file: PathBuf,
        #[arg(long, value_enum, default_value = "regtest")]
        network: NetworkArg,
    },
    /// Verify the password and mark the wallet CLI access state as unlocked.
    Unlock {
        #[arg(long)]
        wallet_dir: PathBuf,
        #[arg(long)]
        password: String,
    },
    /// Mark the wallet CLI access state as locked.
    Lock {
        #[arg(long)]
        wallet_dir: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<NetworkArg> for Network {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Testnet => Network::Testnet,
            NetworkArg::Regtest => Network::Regtest,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CliAccessStateKind {
    Locked,
    Unlocked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CliAccessState {
    state: CliAccessStateKind,
    updated_at: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init {
            wallet_dir,
            password,
            network,
        } => init_wallet(&wallet_dir, &password, network.into())?,
        Commands::Restore {
            wallet_dir,
            password,
            phrase_file,
            network,
        } => restore_wallet(&wallet_dir, &password, &phrase_file, network.into())?,
        Commands::Unlock {
            wallet_dir,
            password,
        } => unlock_wallet(&wallet_dir, &password)?,
        Commands::Lock { wallet_dir } => lock_wallet(&wallet_dir)?,
    }
    Ok(())
}

fn init_wallet(
    wallet_dir: &Path,
    password: &str,
    network: Network,
) -> Result<(), Box<dyn std::error::Error>> {
    let seed = Bip39Seed::generate_new()?;
    let genesis_hash = genesis_hash_for(network)?;
    let wallet_dir_handle =
        WalletDir::create_from_seed(wallet_dir, password, network, &genesis_hash, &seed)?;
    drop(wallet_dir_handle);
    write_access_state(wallet_dir, CliAccessStateKind::Locked)?;

    println!("wallet_dir: {}", wallet_dir.display());
    println!("network: {:?}", network);
    println!("schema: v2");
    println!("state: locked");
    println!("seed_phrase:");
    println!("{}", seed.phrase());
    println!("seed_word_count: {}", seed.word_count());
    println!("warning: store the phrase offline; it is not persisted in plaintext.");
    Ok(())
}

fn restore_wallet(
    wallet_dir: &Path,
    password: &str,
    phrase_file: &Path,
    network: Network,
) -> Result<(), Box<dyn std::error::Error>> {
    let phrase = read_phrase_file(phrase_file)?;
    let scan = InMemoryChainScan::new();
    let genesis_hash = genesis_hash_for(network)?;
    let restored =
        restore_from_phrase(&phrase, password, wallet_dir, network, &genesis_hash, &scan)?;
    drop(restored);
    write_access_state(wallet_dir, CliAccessStateKind::Locked)?;

    println!("wallet_dir: {}", wallet_dir.display());
    println!("network: {:?}", network);
    println!("schema: v2");
    println!("state: locked");
    println!("restore_mode: offline");
    println!("recovered_outputs: 0");
    println!("warning: Phase 1 restore persists the seed but does not scan node state yet.");
    Ok(())
}

fn unlock_wallet(wallet_dir: &Path, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let handle = WalletDir::open(wallet_dir, password)?;
    let schema = handle.config().version;
    drop(handle);
    write_access_state(wallet_dir, CliAccessStateKind::Unlocked)?;
    println!("wallet_dir: {}", wallet_dir.display());
    println!("schema: {:?}", schema);
    println!("state: unlocked");
    Ok(())
}

fn lock_wallet(wallet_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    write_access_state(wallet_dir, CliAccessStateKind::Locked)?;
    println!("wallet_dir: {}", wallet_dir.display());
    println!("state: locked");
    Ok(())
}

fn genesis_hash_for(network: Network) -> Result<Hash256, dom_core::DomError> {
    dom_core::startup_genesis_hash_for_network_magic(network.magic())
}

fn read_phrase_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut phrase = String::new();
    file.read_to_string(&mut phrase)?;
    let normalized = Bip39Seed::from_phrase(&phrase, SeedAcceptance::NewWallet)?;
    Ok(normalized.phrase().to_string())
}

fn write_access_state(
    wallet_dir: &Path,
    state: CliAccessStateKind,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = wallet_dir.join(ACCESS_STATE_FILE);
    let temp_path = wallet_dir.join(format!("{ACCESS_STATE_FILE}.tmp"));
    let payload = CliAccessState {
        state,
        updated_at: unix_timestamp(),
    };
    let json = serde_json::to_vec_pretty(&payload)?;

    {
        use std::io::Write;
        let mut file = File::create(&temp_path)?;
        file.write_all(&json)?;
        file.sync_all()?;
    }

    std::fs::rename(&temp_path, &path)?;
    #[cfg(unix)]
    {
        let dir = File::open(wallet_dir)?;
        dir.sync_all()?;
    }
    Ok(())
}

fn unix_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
