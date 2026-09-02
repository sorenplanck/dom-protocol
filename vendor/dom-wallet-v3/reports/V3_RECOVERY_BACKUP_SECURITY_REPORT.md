# V3 recovery and backup security report

## Final architecture

Wallet creation uses the canonical English BIP-39 24-word boundary. DOM-specific
keys are derived afterward through frozen, versioned, domain-separated APIs in
DOM Core revision `6a8a6475b36ad68bb760d61cf323126d95cd7416`.

Every production output uses a 33-byte commitment, 739-byte bounded range
proof, 96-byte authenticated Recovery Capsule v1, 835-byte proof envelope, and
872-byte canonical `TransactionOutput`. Address v1 keys remain interaction and
payment-proof identities. Recovery Slate v4 binds sender-change and recipient
sidecars to network, chain, roles, phases, replay identity, and body bytes.

`SeedRestoreService` is the ownership authority for capsule-v1 chain outputs.
It uses the canonical scanner and exact WalletScanCursor v1, reconstructs spent
and unspent outputs and safe allocation floors, encrypts recovered spending
authority, and supports spending after restoration. It requires no original
database, output descriptor, private blinding, or encrypted backup. Proof
rewind is not used.

## Backup boundary

The authenticated `DOMWBK01` backup is additional. It protects off-chain data
and pending contexts using the existing encrypted-state primitives. Wrong
password, tampering, network/chain mismatch, malformed input, and overwrite are
rejected before atomic publication.

## Security boundary

Mnemonic, seed, recovery root, private blinding, passwords, capsule plaintext,
and unrestricted private contexts are excluded from logs, diagnostics, reports,
browser persistence, node calls, and public DTOs. No external security audit is
claimed. DOM and DOM Wallet are experimental, DOM initially has no monetary
value, and real-fund use is not authorized.
