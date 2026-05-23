//! DOM CLI — command-line interface.

mod node;

use clap::{Parser, Subcommand};
use dom_wallet::Wallet;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "dom-cli")]
#[command(about = "DOM Protocol CLI", version, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Wallet operations
    Wallet {
        #[command(subcommand)]
        command: WalletCommands,
    },
    /// Node operations
    Node {
        #[command(subcommand)]
        command: node::NodeCommands,
    },
    /// Mining operations
    Mining {
        #[command(subcommand)]
        command: node::MiningCommands,
    },
}

#[derive(Subcommand)]
enum WalletCommands {
    /// Inspect wallet contents
    Inspect {
        /// Path to wallet file
        #[arg(short, long)]
        path: PathBuf,

        /// Wallet password
        #[arg(short = 'P', long)]
        password: String,

        /// Current chain height (for balance calculation)
        #[arg(short = 'H', long, default_value = "1000")]
        height: u64,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Wallet { command } => handle_wallet(command),
        Commands::Node { command } => node::handle_node(command),
        Commands::Mining { command } => node::handle_mining(command),
    }
}

fn handle_wallet(command: WalletCommands) -> anyhow::Result<()> {
    match command {
        WalletCommands::Inspect {
            path,
            password,
            height,
        } => inspect_wallet(&path, &password, height),
    }
}

fn inspect_wallet(path: &PathBuf, password: &str, current_height: u64) -> anyhow::Result<()> {
    let wallet = Wallet::open(path, password)?;

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║              DOM WALLET INSPECTOR                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!();
    println!("Wallet:  {:?}", path);
    println!("Network: {:?}", wallet.network());
    println!("Height:  {} (for balance calculation)", current_height);
    println!();

    let outputs: Vec<_> = wallet.outputs().collect();
    println!("═══════════════════════════════════════════════════════════");
    println!("OUTPUTS ({} total)", outputs.len());
    println!("═══════════════════════════════════════════════════════════");

    const MATURITY: u64 = 1000;

    for (i, output) in outputs.iter().enumerate() {
        let dom_value = output.value as f64 / 1_000_000_000.0;
        let age = current_height.saturating_sub(output.block_height);
        let blocks_remaining = MATURITY.saturating_sub(age);

        let status = if output.spent {
            "SPENT".to_string()
        } else if age >= MATURITY {
            "✅ SPENDABLE".to_string()
        } else {
            format!("⏳ MATURING ({}/{})", age, MATURITY)
        };

        println!();
        println!("Output #{}:", i + 1);
        println!("  Height:     {}", output.block_height);
        println!("  Value:      {} noms ({:.3} DOM)", output.value, dom_value);
        println!(
            "  Type:       {}",
            if output.is_coinbase {
                "Coinbase"
            } else {
                "Regular"
            }
        );
        println!("  Status:     {}", status);
        if !output.spent && blocks_remaining > 0 {
            println!("  Spendable in: {} blocks", blocks_remaining);
        }
    }

    let balance = wallet.balance(current_height);
    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("BALANCE SUMMARY (at height {})", current_height);
    println!("═══════════════════════════════════════════════════════════");
    println!(
        "Confirmed:  {:>15} noms ({:>10.3} DOM)",
        balance.confirmed,
        balance.confirmed as f64 / 1e9
    );
    println!(
        "Immature:   {:>15} noms ({:>10.3} DOM)",
        balance.immature,
        balance.immature as f64 / 1e9
    );
    println!(
        "Reserved:   {:>15} noms ({:>10.3} DOM)",
        balance.reserved,
        balance.reserved as f64 / 1e9
    );
    println!(
        "Spendable:  {:>15} noms ({:>10.3} DOM)",
        balance.spendable(),
        balance.spendable() as f64 / 1e9
    );
    println!(
        "Total:      {:>15} noms ({:>10.3} DOM)",
        balance.total(),
        balance.total() as f64 / 1e9
    );
    println!();

    Ok(())
}
