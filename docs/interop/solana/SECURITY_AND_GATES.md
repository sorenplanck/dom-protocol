# Security and release gates

Implemented boundaries:

- 252-bit same-witness DLEQ inherited from the V7 cryptographic boundary;
- settlement/terms/profile/setup binding;
- deterministic PDA derivation and validation;
- exact SOL/SPL amount checks;
- immutable recipient and refund recipient;
- timestamp refund enforced by the on-chain clock;
- terminal state mutual exclusion;
- finalized signature, transaction, state, vault and blockhash quorum;
- upgradeable-loader code hash and revoked authority attestation;
- skipped-slot-aware durable Kaystra source;
- byte-identical signed-transaction retry storage.

Before mainnet:

- compile the standalone program with the pinned Solana toolchain;
- run program-test/local-validator SOL and SPL E2E;
- execute adversarial CPI/account-substitution tests;
- independently audit the Curve25519/DLEQ binding and the program;
- deploy, verify program-data hash, and revoke upgrade authority;
- ratify chain/asset/profile registry identifiers and finality policy.
