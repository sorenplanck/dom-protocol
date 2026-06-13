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

**Status:** registered, not started. Blocks mainnet. Does NOT block v2.
