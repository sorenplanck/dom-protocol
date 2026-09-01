# DOM↔XMR V6.1 — production candidate for the DOM→XMR leg

> **Status.** The nineteen crates are complete and gates-green: `cargo fmt`
> clean, `clippy -D warnings` at 0, 62 tests passing. The leg is **not**
> production-admissible yet, and that is by design, not omission:
> `validate_production_v1` returns `MechanismUnratified` by construction, and
> `ChainKindV1` has no Monero variant, so `dom-interopd` admission refuses an
> XMR leg whatever mechanism tag it carries. Both are normative decisions for
> the operator. `docs/RATIFICATION_SHEET.md` lists every file each one lands
> in; `VALIDATION_STATUS.md` records what was run and what was repaired.

This is the cumulative successor of the V1–V5 ZIPs. It replaces the earlier
parallel experimental engines with one integration path that keeps **Kaystra as
the only economic state machine**.

## What is implemented

- same-252-bit secp256k1↔ed25519 `CrossCurveDLEQ` wrapper;
- same-witness DLEQ admission envelope committed by the XMR profile;
- durable claim-reuse registry preventing one DLEQ claim from crossing settlements;
- canonical XMR adapter profile committed by Kaystra terms;
- exact funding/spend evidence and multi-RPC canonical quorum;
- encrypted, restart-safe local XMR secret store;
- authenticated Unix-domain-socket protocol;
- GPL sidecar that calls Eigenwallet's live Monero sweep constructor;
- MIT raw-Monero-transaction parser/hash verifier on the DOM side;
- exact-byte durable delivery journal and idempotent broadcast recovery;
- a minimal patch to `adapter-dom-real` that forwards the already-verified
  revealed scalar from `RequestClaimConsumption`;
- real Kaystra bridge and E2E harness.

## Apply

```bash
python3 scripts/apply-v6.py /path/to/dom-protocol   # branch mainnetswap, commit 7ea7f968
cd /path/to/dom-protocol
bash scripts/xmr-v6/run-v6-gates.sh
```

By default the installer requires the observed target commit recorded in
`SOURCE_LOCK.json`. Use `--allow-drift` only after manually reviewing the patch.

## Mainnet status

This package is a laboratory/integration candidate. The implementation is not a
mainnet authorization. The remaining gates are a successful Cargo/CI run in the target checkout, an independent cryptographic
audit, real stagenet fault injection, and protocol ratification of a truthful
`CrossCurveSharedSpend` mechanism tag.
