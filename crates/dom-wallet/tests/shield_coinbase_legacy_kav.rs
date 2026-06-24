//! dom-shield Onda 2 — Lens B KAV for the legacy password-derived coinbase
//! blinding in `dom_wallet::wallet::build_coinbase`.
//!
//! Subfamily: known-answer (Lens B — prediction / weak key derivation).
//!
//! For a wallet WITHOUT a BIP-39 seed (`keychain.seed_bytes == None` — the
//! state of every `Wallet::new_in_memory` legacy wallet), `build_coinbase`
//! derives the output blinding deterministically from the PASSWORD alone:
//!
//!   password_seed = blake2b_256_tagged("DOM:wallet-coinbase-seed:v1", password)
//!   blinding      = blake2b_256_tagged(TAG_COINBASE_BLINDING,
//!                                       password_seed || height_le8)
//!
//! There is no per-wallet entropy, no salt, and no KDF stretching: the coinbase
//! spend key is a pure 2-round hash of the password and the (public) block
//! height. An attacker who guesses the password recovers every coinbase
//! blinding — i.e. the spend authority over every mined reward. This KAV pins
//! that derivation by reconstructing it independently and matching the
//! commitment the wallet actually produces. This is a CONFIRMATION of the
//! known weak-legacy-coinbase finding (Lens B), not a new bug.

use dom_core::{block_reward, BlockHeight, TAG_COINBASE_BLINDING};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{blake2b_256_tagged, BlindingFactor, Hash256};
use dom_wallet::{Network, Wallet};

/// Independently recompute the legacy coinbase blinding from the password and
/// height, mirroring the production formula exactly.
fn legacy_coinbase_blinding(password: &str, height: u64) -> [u8; 32] {
    let password_seed = blake2b_256_tagged("DOM:wallet-coinbase-seed:v1", password.as_bytes());
    let mut input = Vec::with_capacity(32 + 8);
    input.extend_from_slice(password_seed.as_bytes());
    input.extend_from_slice(&height.to_le_bytes());
    *blake2b_256_tagged(TAG_COINBASE_BLINDING, &input).as_bytes()
}

/// KAV: the wallet's coinbase commitment equals `commit(reward, predicted
/// password-derived blinding)`. Confirms the blinding is a pure function of the
/// password + height (no wallet entropy).
#[test]
fn legacy_coinbase_blinding_is_password_plus_height_only() {
    // new_in_memory uses an EMPTY password and no seed → legacy path.
    let genesis = Hash256::from_bytes([42u8; 32]);
    let mut wallet = Wallet::new_in_memory(Network::Mainnet, &genesis);

    let height = BlockHeight(5);
    let total_tx_fees = 0u64;
    let coinbase = wallet
        .build_coinbase(height, total_tx_fees)
        .expect("legacy coinbase build");

    let reward = block_reward(height).noms();
    let predicted_blinding = legacy_coinbase_blinding("", height.0);
    let predicted_commitment = *Commitment::commit(
        reward + total_tx_fees,
        &BlindingFactor::from_bytes(predicted_blinding).unwrap(),
    )
    .as_bytes();

    // CONFIRMS Lens-B weak legacy coinbase: blinding fully predictable from the
    // password (here "") and the public height.
    assert_eq!(
        *coinbase.output.commitment.as_bytes(),
        predicted_commitment,
        "legacy coinbase blinding = blake2b(password)→blake2b(.. || height): password-recoverable"
    );
}

/// Determinism corollary: two legacy wallets with the SAME password produce
/// the SAME coinbase commitment at the same height — there is zero per-wallet
/// entropy separating two users who chose the same password.
#[test]
fn legacy_coinbase_same_password_same_height_collides_across_wallets() {
    let genesis_a = Hash256::from_bytes([1u8; 32]);
    let genesis_b = Hash256::from_bytes([2u8; 32]); // different chain_id...
    let mut w_a = Wallet::new_in_memory(Network::Mainnet, &genesis_a);
    let mut w_b = Wallet::new_in_memory(Network::Mainnet, &genesis_b);

    let height = BlockHeight(9);
    let cb_a = w_a.build_coinbase(height, 0).unwrap();
    let cb_b = w_b.build_coinbase(height, 0).unwrap();

    // ...yet the coinbase blinding (hence commitment) is identical, because the
    // derivation ignores the wallet/chain entirely and depends only on the
    // (here empty) password and height.
    assert_eq!(
        cb_a.output.commitment.as_bytes(),
        cb_b.output.commitment.as_bytes(),
        "legacy coinbase blinding ignores wallet identity — same password ⇒ same spend key"
    );
}
