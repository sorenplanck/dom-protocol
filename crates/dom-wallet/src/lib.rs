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

pub mod output_index;
pub mod store;
pub mod types;
pub mod wallet;

pub use types::{Network, OwnedOutput, WalletBalance, WalletError};
pub use wallet::Wallet;

// Re-export for convenience.
pub use dom_consensus::transaction::Transaction;
