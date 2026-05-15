# Changelog — dom-wallet

> ## ⚠️  CRITICAL SECURITY WARNING — TESTNET/DEV ONLY
>
> This wallet uses HKDF-SHA256 for password-based key derivation,
> which is **NOT secure against GPU brute-force attacks**.
>
> An 8-character password can be cracked in minutes from a captured
> .wallet file. Any value protected by this wallet is effectively
> public knowledge to anyone with the file.
>
> **DO NOT USE FOR REAL FUNDS.** This wallet is suitable only for:
> - Testnet experiments
> - Protocol development
> - Educational use
>
> Tracked as mainnet-blocker. Argon2id (or scrypt) replacement
> required before any production release.
>
> See `store.rs::derive_key` for technical details.

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — Initial Implementation

### Added

#### Core Types (`types.rs`)

- **`OwnedOutput`:** Wallet-owned UTXO with commitment, value, blinding factor, and provenance.
  - Implements `dom_tx::InputSource` for seamless transaction building.
  - Automatic zeroization of blinding factors via `Zeroizing<[u8; 32]>`.
  - Maturity checking for coinbase outputs (1000-block lockup).
  - Spendability checks (not spent, not reserved, mature).

- **`WalletError`:** Comprehensive error type using `thiserror`.
  - Variants: InsufficientFunds, OutputNotFound, AlreadySpent, NotMature, Io, Encryption, Decryption, Serialization, InvalidPassword, Dom, Tx, Crypto.

- **`WalletBalance`:** Balance breakdown into confirmed, immature, and reserved amounts.
  - Helper methods: `total()`, `spendable()`.

- **`Network`:** Enum for Mainnet/Testnet with magic bytes.

#### Storage Module (`store.rs`)

- **Encrypted Persistence:** ChaCha20Poly1305 with HKDF-SHA256 key derivation.
  - File format: 64-byte header (magic, version, salt, nonce) + encrypted JSON payload.
  - Atomic writes: temp file + rename to prevent corruption on crash.
  - Salt randomization per save; nonce regenerated on every write.
  
- **Key Derivation:** HKDF-SHA256 with info string "DOM:wallet-key:v1".
  - Password-based key derivation with random salt stored in file.
  - Zero-copy handling of sensitive key material via `Zeroizing<[u8; 32]>`.

#### Output Index (`output_index.rs`)

- **UTXO Management:** In-memory index with HashMap-backed storage.
  - Methods: insert, get, get_mut, iter, remove, clear.
  
- **Coin Selection:** Greedy algorithm.
  - Filters spendable outputs (not spent, not reserved, mature).
  - Sorts by value descending to minimize input count.
  - Returns error if insufficient funds.
  
- **Reservation System:** Reserve outputs for pending transactions.
  - Methods: reserve, release_reservation.
  - Prevents double-spend during transaction building.

#### Wallet (`wallet.rs`)

- **`Wallet` Struct:** Main public API.
  - Fields: network, chain_id, outputs (OutputIndex), pending_txs, file_path, encryption_key.

- **Operations:**
  - `create(path, password, network, genesis_hash)`: Create and save new wallet.
  - `open(path, password)`: Open encrypted wallet from disk.
  - `new_in_memory(network, genesis_hash)`: In-memory wallet for testing.
  - `save()`: Save current state to disk (atomic write).
  - `balance(current_height)`: Compute confirmed/immature/reserved balances.
  - `add_output(output)`: Add received UTXO.
  - `build_spend(recipient_commitment, recipient_blinding, amount, fee, current_height)`: Build transaction, reserve inputs, record pending state.
  - `confirm_tx(tx_hash)`: Mark inputs as spent after confirmation.
  - `cancel_tx(tx_hash)`: Release reservations and forget pending transaction.
  - `scan_block(transactions, block_height)`: Placeholder for future key derivation (v1 requires out-of-band blinding factor sharing).
  - `outputs()`: Iterator over all outputs.
  - `chain_id()`, `network()`: Accessors.

#### Integration with dom-tx

- **InputSource Trait:** OwnedOutput implements the trait, enabling direct use in SpendBuilder.
- **Transaction Building:** `build_spend()` uses SpendBuilder to construct valid Mimblewimble transactions.
- **Error Handling:** TxError is re-exported from WalletError.

### Security Features

- **No `unsafe` Code:** `#![forbid(unsafe_code)]` enforced.
- **Automatic Zeroization:** 
  - BlindingFactor zeroized on drop (via `Zeroizing<T>`).
  - Encryption key held as `Zeroizing<[u8; 32]>`.
  - Drop implementations ensure sensitive data is wiped from memory.
- **Atomic Filesystem Operations:** Temp file + rename prevents partial writes.
- **Password-Based Encryption:** No plaintext key storage.
- **Random Salt & Nonce:** New salt on create, new nonce on every save.

### Testing

- **`tests/wallet_test.rs`:** 12 integration tests covering:
  - In-memory wallet creation.
  - Output addition and balance computation.
  - Coinbase maturity logic.
  - Filesystem persistence (create/open).
  - Password verification.
  - Output index coin selection.
  - Input source trait implementation.

### Not Included (Future Work)

- **HD Derivation (BIP-32):** Out of scope for v1. Requires coordination with dom-slatepack for multi-party transactions.
- **Multi-Signature Wallets:** Single-key only in v1.
- **Hardware Wallet Support:** Will require enclave communication.
- **Automatic Block Scanning:** v1 requires out-of-band delivery of blinding factors (via dom-slatepack interactive sends).
- **Taproot/Advanced Script:** Mimblewimble has no script; feature not applicable.

### API Design Decisions

1. **InputSource instead of OwnedOutput in dom-tx:** Breaks circular dependency (dom-wallet depends on dom-tx which would depend on dom-wallet types).
   - Solution: InputSource trait defined in dom-tx; dom-wallet implements it.

2. **Zeroization on Drop:** Ensures no secrets remain in memory after wallet is dropped.
   - BlindingFactor now implements Drop + Zeroize.

3. **Persistent Wallet Tied to File Path:** Open/create wallet handles filesystem binding.
   - In-memory variant for tests.

4. **Atomic Writes:** Prevents corruption if process crashes mid-write.
   - Temp file + rename is atomic on POSIX/Windows filesystems.

5. **Manual Coin Selection:** Greedy algorithm is simple and auditable.
   - Future: UTXO consolidation heuristics, privacy-preserving selection (Knapsack variants).

### Compilation

- `cargo build -p dom-wallet --release`: ✅ Compiles without errors or warnings.
- `cargo test -p dom-wallet`: ✅ All tests pass.
- `cargo clippy -p dom-wallet -- -D warnings`: ✅ No warnings.
- `cargo fmt --check crates/dom-wallet`: ✅ Code formatted.

### Deployment

- Drop `crates/dom-wallet/` from this release into the DOM workspace.
- No breaking changes to existing crates.
- Wallet can be instantiated and used immediately after updating workspace Cargo.lock.

---

**Author:** Soren Planck  
**License:** MIT  
**Repository:** https://github.com/sorenplanck/dom-protocol
