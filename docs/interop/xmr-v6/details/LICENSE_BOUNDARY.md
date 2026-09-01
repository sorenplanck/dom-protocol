# License boundary

The DOM overlay crates are MIT. The live sidecar is a separate GPL-3.0-only
process because it links to Eigenwallet's GPL Monero wallet/sweep implementation.
Communication occurs through an authenticated, bounded Unix-domain-socket
protocol. This design reduces coupling but is not a substitute for legal advice.

The DOM-side raw transaction verifier uses the MIT `monero-oxide` package at the
source-locked commit.
