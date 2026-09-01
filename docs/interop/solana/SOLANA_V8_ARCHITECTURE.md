# DOM Solana condition-lock leg — V8

V8 is cumulative over the XMR V7 full branch. Kaystra remains the sole economic
state machine. The Solana leg is a native condition lock whose claim publishes
the same 252-bit scalar used by the DOM adaptor.

## Flow

1. Generate one common-domain scalar and DLEQ proof.
2. Freeze the secp256k1 point as the DOM adaptor point.
3. Freeze the ed25519 point, program id, PDAs, asset, amount and timestamp refund.
4. Initialize and fund the Solana escrow PDA.
5. Finalized observer evidence enters Kaystra as `Funding`.
6. `Claim(secret)` verifies `secret*G_ed25519` with the curve syscall and transfers
   SOL/SPL to the frozen recipient.
7. The finalized claim evidence contains the public scalar; the DOM leg consumes
   the same scalar.
8. After the timestamp, anyone may call refund, but funds can only reach the
   frozen refund recipient.

Classic SPL Token is admitted. Token-2022 is rejected in V1. Production profiles
require an immutable upgradeable-loader program-data account and a frozen code
hash.
