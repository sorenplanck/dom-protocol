//! Wallet integration helpers.

use dom_config::Network as ConfigNetwork;
use dom_wallet::Network as WalletNetwork;

/// Convert dom-config Network enum to dom-wallet Network enum.
///
/// The two enums are structurally identical (Mainnet, Testnet) but live in
/// different crates and thus are distinct types. This helper avoids repeating
/// the match in multiple places.
pub fn wallet_network_from_config(config_net: ConfigNetwork) -> WalletNetwork {
    match config_net {
        ConfigNetwork::Mainnet => WalletNetwork::Mainnet,
        ConfigNetwork::Testnet => WalletNetwork::Testnet,
        ConfigNetwork::Regtest => WalletNetwork::Regtest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_conversion() {
        assert_eq!(
            wallet_network_from_config(ConfigNetwork::Mainnet),
            WalletNetwork::Mainnet
        );
        assert_eq!(
            wallet_network_from_config(ConfigNetwork::Testnet),
            WalletNetwork::Testnet
        );
        assert_eq!(
            wallet_network_from_config(ConfigNetwork::Regtest),
            WalletNetwork::Regtest
        );
    }

    #[test]
    fn test_regtest_magic_isolation() {
        let regtest_net = wallet_network_from_config(ConfigNetwork::Regtest);
        let mainnet_net = wallet_network_from_config(ConfigNetwork::Mainnet);
        let testnet_net = wallet_network_from_config(ConfigNetwork::Testnet);
        assert_ne!(regtest_net.magic(), mainnet_net.magic());
        assert_ne!(regtest_net.magic(), testnet_net.magic());
    }

    #[test]
    fn test_regtest_maturity_is_one() {
        let regtest_net = wallet_network_from_config(ConfigNetwork::Regtest);
        assert_eq!(regtest_net.coinbase_maturity(), 1);
    }
}
