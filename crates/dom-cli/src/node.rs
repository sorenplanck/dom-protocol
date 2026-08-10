//! Node commands.

use anyhow::Result;
use clap::Subcommand;

fn default_rpc_endpoint() -> String {
    format!("http://127.0.0.1:{}", dom_core::RPC_PORT_TESTNET)
}

#[derive(Subcommand)]
pub enum NodeCommands {
    /// Show node status
    Status {
        /// RPC endpoint
        #[arg(short, long, default_value_t = default_rpc_endpoint())]
        endpoint: String,
    },
    /// List connected peers
    Peers {
        /// RPC endpoint
        #[arg(short, long, default_value_t = default_rpc_endpoint())]
        endpoint: String,
    },
}

#[derive(Subcommand)]
pub enum MiningCommands {
    /// Start mining
    Start {
        /// RPC endpoint
        #[arg(short, long, default_value_t = default_rpc_endpoint())]
        endpoint: String,
    },
    /// Stop mining
    Stop {
        /// RPC endpoint
        #[arg(short, long, default_value_t = default_rpc_endpoint())]
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

#[cfg(test)]
mod tests {
    #[test]
    fn default_endpoint_uses_authoritative_testnet_rpc_port() {
        assert_eq!(
            super::default_rpc_endpoint(),
            format!("http://127.0.0.1:{}", dom_core::RPC_PORT_TESTNET)
        );
    }
}
