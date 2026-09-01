# Final acceptance checklist

## Code gates
- [x] 252-bit DLEQ wrapper and context binding
- [x] profile/adaptor-point binding
- [x] encrypted secret durability
- [x] authenticated UDS protocol
- [x] exact raw transaction persistence
- [x] DOM-side raw Monero transaction verification
- [x] restart-safe exact retransmission
- [x] multi-RPC confirmation and anchor quorum
- [x] Kaystra outbox hook and bridge
- [x] automated static package validation
- [ ] cargo fmt/check/clippy/test on target checkout
- [ ] GPL sidecar build against pinned dependencies
- [ ] live monerod regtest/stagenet E2E

## Assurance gates
- [ ] independent cross-curve cryptographic audit
- [ ] kill -9 matrix at every persistence/broadcast boundary
- [ ] adversarial RPC split-brain/reorg campaign
- [ ] Kaystra terms V2 ratification
- [ ] external protocol audit
- [ ] explicit mainnet authorization
