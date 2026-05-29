//! Wallet integration helpers.

use dom_config::Network as ConfigNetwork;
use dom_wallet::Network as WalletNetwork;

/// Convert dom-config Network enum to dom-wallet Network enum.
///
/// The two enums are structurally identical (Mainnet, Testnet, Regtest)
/// but live in different crates and thus are distinct types. This helper
/// avoids repeating the match in multiple places.
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
    fn magics_are_distinct_across_networks() {
        assert_ne!(
            ConfigNetwork::Mainnet.magic(),
            ConfigNetwork::Testnet.magic()
        );
        assert_ne!(
            ConfigNetwork::Mainnet.magic(),
            ConfigNetwork::Regtest.magic()
        );
        assert_ne!(
            ConfigNetwork::Testnet.magic(),
            ConfigNetwork::Regtest.magic()
        );
    }

    #[test]
    fn regtest_has_smaller_maturity_than_canon() {
        assert!(
            ConfigNetwork::Regtest.coinbase_maturity() < ConfigNetwork::Mainnet.coinbase_maturity()
        );
        assert_eq!(
            ConfigNetwork::Mainnet.coinbase_maturity(),
            dom_core::COINBASE_MATURITY
        );
        assert_eq!(
            ConfigNetwork::Testnet.coinbase_maturity(),
            dom_core::COINBASE_MATURITY
        );
        assert_eq!(
            ConfigNetwork::Regtest.coinbase_maturity(),
            dom_core::REGTEST_COINBASE_MATURITY
        );
    }
}
