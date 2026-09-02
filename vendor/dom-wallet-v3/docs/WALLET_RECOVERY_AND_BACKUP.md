# Wallet recovery and backup

DOM Wallet V3 creates wallets from 256 bits of operating-system CSPRNG entropy,
represented as a checksummed English BIP-39 24-word mnemonic. The mnemonic is
the canonical seed boundary. It is displayed once, is never sent to the node,
and must be stored securely and never shared.

Confirmed Recovery Capsule v1 funds are recoverable from the mnemonic plus the
canonical DOM chain. `SeedRestoreService` scans unfiltered canonical outputs
through the embedded `WalletCoreApi`, authenticates capsules locally,
reconstructs owned values and blindings, reconciles spent state, rebuilds safe
allocation floors, and writes a new encrypted wallet atomically. Proof rewind,
local descriptors, the original database, and a backup are not recovery
authorities for capsule-v1 funds.

Legacy proof-only outputs contain no capsule. They are explicitly classified as
backup-required and are never guessed or credited by seed-only restoration. No
new production path creates such an output.

The encrypted `DOMWBK01` backup remains supplementary. It preserves labels,
contacts, pending transaction contexts, reservations, preferences, and faster
migration. Its Argon2id/HKDF/ChaCha20-Poly1305 envelope authenticates network
identity and rejects wrong passwords, tampering, incompatible identity,
oversized input, and overwrite of a healthy wallet.

The frontend keeps no wallet state in browser persistence. Mnemonic and password
fields are cleared after completion, cancellation, navigation, and failure.
Only redacted results cross unrestricted UI boundaries.
