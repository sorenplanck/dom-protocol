//! # dom-wire
//!
//! P2P wire protocol for DOM.
//!
//! Transport: Noise_XX_25519_ChaChaPoly_BLAKE2s (RFC-0005)
//! Messages: framed with magic + command + length + checksum
//! chain_id bound to Noise prologue (RFC-0009 Section 4.3)

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod codec;
pub mod handshake;
pub mod message;
pub mod peer;
pub mod manager;
pub mod dandelion;
pub mod dns_seed;
