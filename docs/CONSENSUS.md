# DOM Protocol — Consensus Rules

> **SUPERSEDED NOTICE**
> This file is retained for historical reference only. It is not consensus-authoritative.
> Current consensus behavior is defined by the implementation (`crates/dom-consensus/`) and
> the normative RFC set (`docs/DOM_RFC_000*.md`). The monetary schedule, full validation
> pipeline (18 validators), cryptographic details, and balance equation must not be inferred
> from this summary — it contains stale parameters. A corrective documentation pass is
> deferred to a separate scoped batch.

**Version:** 0.1.0

---

## 18 Validators (V1-V18)

### V9: Balance Equation
sum(outputs) - sum(inputs) - sum(kernels) == 0

### V13: Coinbase Valid
Initial: 369 DOM, halving every 44,715 blocks

### V14: Maturity
Coinbase spendable after 1000 blocks

### V18: Bulletproofs
All range proofs must verify

---

**Maintained by:** Soren Planck
