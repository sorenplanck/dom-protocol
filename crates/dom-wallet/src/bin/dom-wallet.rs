use clap::{Parser, Subcommand, ValueEnum};
use dom_crypto::Hash256;
use dom_wallet::{restore_from_phrase, InMemoryChainScan, Network, WalletDir};
use std::net::TcpStream;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "dom-wallet")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init {
        path: PathBuf,
        password: String,
        #[arg(value_enum, default_value = "regtest")]
        network: NetArg,
        #[arg(long, default_value = "00")]
        genesis: String,
    },
    Unlock {
        path: PathBuf,
        password: String,
    },
    Lock {
        path: PathBuf,
        password: String,
    },
    Receive {
        path: PathBuf,
        password: String,
    },
    Balance {
        path: PathBuf,
        password: String,
        #[arg(long, default_value_t = 0)]
        height: u64,
    },
    History {
        path: PathBuf,
        password: String,
    },
    Restore {
        path: PathBuf,
        password: String,
        phrase: String,
        #[arg(value_enum, default_value = "regtest")]
        network: NetArg,
        #[arg(long, default_value = "00")]
        genesis: String,
    },
    NodeStatus {
        #[arg(long, default_value = "127.0.0.1:8333")]
        addr: String,
    },
    Sync {
        path: PathBuf,
        password: String,
    },
    Send {},
}

#[derive(Copy, Clone, ValueEnum)]
enum NetArg {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<NetArg> for Network {
    fn from(v: NetArg) -> Self {
        match v {
            NetArg::Mainnet => Network::Mainnet,
            NetArg::Testnet => Network::Testnet,
            NetArg::Regtest => Network::Regtest,
        }
    }
}

fn parse_genesis(s: &str) -> anyhow::Result<Hash256> {
    let bytes = hex::decode(s)?;
    let mut arr = [0u8; 32];
    let take = bytes.len().min(32);
    arr[..take].copy_from_slice(&bytes[..take]);
    Ok(Hash256::from_bytes(arr))
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init {
            path,
            password,
            network,
            genesis,
        } => {
            let g = parse_genesis(&genesis)?;
            let _ = WalletDir::create(&path, &password, network.into(), &g)?;
            println!("wallet initialized at {}", path.display());
        }
        Commands::Unlock { path, password } => {
            let _ = WalletDir::open(&path, &password)?;
            println!("wallet unlocked");
        }
        Commands::Lock { path, password } => {
            let mut wd = WalletDir::open(&path, &password)?;
            wd.wallet_mut().lock();
            wd.wallet().save()?;
            println!("wallet locked");
        }
        Commands::Receive { .. } => {
            println!("receive address generation pending address scheme integration")
        }
        Commands::Balance {
            path,
            password,
            height,
        } => {
            let wd = WalletDir::open(&path, &password)?;
            let b = wd.wallet().balance(height);
            println!(
                "confirmed={} immature={} reserved={} spendable={}",
                b.confirmed,
                b.immature,
                b.reserved,
                b.spendable()
            );
        }
        Commands::History { path, password } => {
            let wd = WalletDir::open(&path, &password)?;
            match wd.wallet().journal() {
                Some(j) => {
                    for (tx, rec) in j.replay()? {
                        println!("{} status={:?}", hex::encode(tx), rec.status);
                    }
                }
                None => println!("no journal attached"),
            }
        }
        Commands::Restore {
            path,
            password,
            phrase,
            network,
            genesis,
        } => {
            let g = parse_genesis(&genesis)?;
            let restored = restore_from_phrase(
                &phrase,
                &password,
                &path,
                network.into(),
                &g,
                &InMemoryChainScan::new(),
            )?;
            println!(
                "wallet restored recovered_outputs={} scanned_tip={}",
                restored.recovered_count, restored.scanned_tip
            );
        }
        Commands::NodeStatus { addr } => match TcpStream::connect(&addr) {
            Ok(_) => println!("node reachable at {}", addr),
            Err(e) => println!("node unreachable at {}: {}", addr, e),
        },
        Commands::Sync { path, password } => {
            let mut wd = WalletDir::open(&path, &password)?;
            let changed = wd.wallet_mut().reconcile_with_journal()?;
            if changed {
                wd.wallet().save()?;
            }
            println!("sync complete changed={}", changed);
        }
        Commands::Send {} => anyhow::bail!("send command pending full node RPC integration"),
    }
    Ok(())
}
