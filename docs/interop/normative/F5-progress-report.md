# F5 Closure Progress Report (Annex M v3.3)

**Normative state:** D-027 is RATIFIED by explicit operator decision on
2026-08-12. D-014 is SUPERSEDED and preserved as history. F5 requires
regtest plus the pinned custom Signet BIP-325. Public Signet is optional,
outside the gate, roadmap and release, and cannot block F5-F8. Mainnet is
excluded.

**Technical state:** F5 is COMPLETE and G-F5 is PASS. The coherent closure
execution is recorded in `docs/reports/F5-CUSTOM-SIGNET-E2E.md`; the five
separate audit tracks and finding adjudications are recorded in
`docs/reports/F5-INDEPENDENT-AUDIT.md`. Every revised M.15.2 operand is GREEN.

## Implemented surface

- pinned secp256k1-zkp MuSig2/adaptor backend and C1a-C4 suites;
- P2TR key-path claim and CSV script-path refund builders;
- durable one-shot nonce vault, crash reconciliation and resend;
- observer, reorg store, evidence verifier, `VerifiedBitcoinOutcomeV1` and
  USPE bridge;
- real regtest E2E;
- official-Core custom Signet with non-trivial P2PK challenge, split P2P
  topology and official Signet miner;
- E01-E16 driver, evidence manifest and secret scan;
- optional Public-Signet utility with no gate authority.

## Governance state

```text
FOUNDATION v0.18 = current authority (v0.17 F5 closure incorporated unchanged)
ANNEX M v3.3     = adopted F5 execution specification
D-013            = RATIFIED
D-014            = SUPERSEDED by D-027
D-015            = RATIFIED
D-027            = RATIFIED
A8a/A8b/A9       = RESOLVED
F5                = COMPLETE (M.15.1 GREEN)
G-F5              = PASS (M.15.2 GREEN)
```

## Boundary declarations

```text
DOM_SIM_IS_REAL_DOM=false
DOM_SCRIPTLESS_TOUCHED=false
DOM_CORE_TOUCHED=false
DOM_CONTRACTS_TOUCHED=false
DOM_WALLET_TOUCHED=false
BITCOIN_CONSENSUS_TOUCHED=false
KEYSTONE_CUSTODIAL=false
MAINNET_USED=false
```
