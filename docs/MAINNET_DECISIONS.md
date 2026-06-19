# Mainnet Decisions

Registered decisions that gate the mainnet launch. Each entry records the
decision, its rationale, the required sequencing, and current status. These are
binding pre-mainnet gates unless explicitly downgraded here.

---

## Rangeproof migration: Borromean → Bulletproof [PRE-MAINNET GATE — HIGH PRIORITY]

**Decision:** The protocol MUST NOT ship to mainnet with Borromean ring-signature
rangeproofs. Migrate to Bulletproofs before mainnet.

**Rationale:**
- ~10x smaller proofs (the 4.2 KB recipient proof drops dramatically), shrinking
  outputs, blocks, and long-term chain size.
- Enables single-QR slate transport in both directions (send already fits 1 QR
  after change-proof stripping; response needs Bulletproof to reach 1 QR).
- Modern standard (Monero, Grin).

**Sequencing (mandatory order — out of order destroys work):**
1. Complete wallet v2 first (in progress).
2. THEN migrate rangeproofs (consensus change).
3. Restarting the testnet from genesis is REQUIRED to validate the new proof
   format — current testnet outputs use the old proof type and are incompatible.
   This restart is intentional and expected, not a regression.
4. Never combine the rangeproof migration with unrelated changes (wallet, P2P,
   etc.) — isolate it so any breakage is unambiguous.

**Status:** ✅ Implemented and validated on branch `bp-migration-phase1` (pending
merge to main; NOT yet shipped to mainnet). Both proof generation and consensus
verification now use standard Bulletproofs (bp2) via grin `secp256k1zkp` (audited
FFI shim, custom H_DOM generator); the testnet genesis was regenerated with a
Bulletproof coinbase and `GENESIS_HASH_TESTNET` re-pinned (the sequencing step-3
restart, performed intentionally); consensus `MAX_PROOF_SIZE` set to 768 for the
675-byte proof. Validated end-to-end by `transfer_slate_e2e` (wallet-to-wallet
transfer with the range proof verified through consensus) and `deterministic_replay`
(frozen canonical-state digest as a permanent regression gate). The migration was
isolated on its own branch per sequencing rule 4. This gate's implementation
requirement is satisfied; mainnet launch remains gated on merge and the broader
mainnet checklist. Does NOT block v2.
