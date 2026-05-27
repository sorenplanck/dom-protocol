//! # dom-wallet
//!
//! A secure Mimblewimble wallet for the DOM Protocol with persistent encrypted storage.
//!
//! ## Features
//!
//! - **Encrypted Storage:** ChaCha20Poly1305 with HKDF-derived keys from password.
//! - **Coin Selection:** Greedy selection of UTXOs for transaction building.
//! - **Transaction Building:** Integration with `dom_tx::SpendBuilder`.
//! - **Security:** Automatic zeroization of sensitive data on drop.
//! - **Atomic Writes:** Filesystem writes use temp-file + rename for crash safety.
//!
//! ## Example
//!
//! ```ignore
//! use dom_wallet::{Wallet, Network};
//! use dom_crypto::Hash256;
//! use std::path::Path;
//!
//! // Create a new wallet.
//! let wallet = Wallet::create(
//!     Path::new("my_wallet.dom"),
//!     "secure_password",
//!     Network::Testnet,
//!     &Hash256::from([0u8; 32]),
//! )?;
//!
//! // Open an existing wallet.
//! let wallet = Wallet::open(
//!     Path::new("my_wallet.dom"),
//!     "secure_password",
//! )?;
//!
//! // Check balance.
//! let balance = wallet.balance(current_height);
//! println!("Confirmed: {} noms", balance.confirmed);
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod backup;
pub mod coin_selection;
pub mod hd_wallet;
pub mod journal;
pub mod output_index;
pub mod restore;
pub mod rpc_client;
pub mod seed;
pub mod store;
pub mod types;
pub mod unlock;
pub mod wallet;
pub mod wallet_dir;

pub use hd_wallet::{ExtendedPrivKey, HdError, DOM_COIN_TYPE};
pub use journal::{
    JournalEntry, JournalError, TxJournal, TxJournalEvent, TxRecord, TxStatus, JOURNAL_LOG_NAME,
};
pub use restore::{
    restore_from_phrase, ChainScanSource, InMemoryChainScan, RestoreError, RestoredWallet,
    ScanBlock,
};
pub use rpc_client::{
    BlockHeaderInfo, MempoolTxInfo as RpcMempoolTxInfo, NodeRpc, NodeRpcClient,
    NodeRpcClientBuilder, NodeStatus, RpcClientError, TxSubmitOutcome, UtxoInfo,
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
};
pub use seed::{
    coinbase_blinding, spend_output_blinding, Bip39Seed, SeedAcceptance, SeedError,
    NEW_WALLET_WORD_COUNT, SEED_BYTES,
};
pub use types::{
    Network, OwnedOutput, ReceiveRequest, ReceiveRequestDescriptor, ReceiveRequestStatus,
    WalletBalance, WalletError,
};
pub use unlock::{derive_wallet_key, KdfParams, LockState, UnlockedSession, WalletKey};
pub use wallet::Wallet;
pub use wallet_dir::{
    WalletConfig, WalletDir, WalletVersion, WALLET_BACKUPS_SUBDIR, WALLET_CONFIG_NAME,
    WALLET_DAT_NAME, WALLET_LOCK_NAME, WALLET_LOGS_SUBDIR,
};

// Re-export for convenience.
pub use dom_consensus::transaction::Transaction;
