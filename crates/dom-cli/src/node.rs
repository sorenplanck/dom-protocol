//! Node commands.

use clap::Subcommand;
use anyhow::Result;

#[derive(Subcommand)]
pub enum NodeCommands {
    /// Show node status
    Status {
        /// RPC endpoint
        #[arg(short, long, default_value = "http://127.0.0.1:33369")]
        endpoint: String,
    },
    /// List connected peers
    Peers {
        /// RPC endpoint
        #[arg(short, long, default_value = "http://127.0.0.1:33369")]
        endpoint: String,
    },
}

#[derive(Subcommand)]
pub enum MiningCommands {
    /// Start mining
    Start {
        /// RPC endpoint
        #[arg(short, long, default_value = "http://127.0.0.1:33369")]
        endpoint: String,
    },
    /// Stop mining
    Stop {
        /// RPC endpoint
        #[arg(short, long, default_value = "http://127.0.0.1:33369")]
        endpoint: String,
    },
}

pub fn handle_node(_command: NodeCommands) -> Result<()> {
    println!("⚠️  Node commands require RPC server (not yet implemented)");
    println!("    Coming in Sprint 5 Phase 2");
    Ok(())
}

pub fn handle_mining(_command: MiningCommands) -> Result<()> {
    println!("⚠️  Mining commands require RPC server (not yet implemented)");
    println!("    Coming in Sprint 5 Phase 2");
    Ok(())
}
