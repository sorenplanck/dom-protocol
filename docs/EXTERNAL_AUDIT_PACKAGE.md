# DOM — External Audit Package (Phase 8.3)

Status: package manifest snapshot 2026-05-25.

This document is what an external security auditor receives along
with the source tree. It is **not** an audit report — it lists the
artefacts, scope, prior-art, and known limitations the auditor
should be aware of before starting.

## Repository pointer

* Source: `https://github.com/sorenplanck/dom-protocol`
* Commit at audit handover: pinned in the engagement letter; this
  doc references the latest `main` at snapshot time.
* All releases starting from the audit handover MUST be signed
  tags. Branch protection on `main` blocks force-push.

## Audit scope

In scope for the engagement:

1. **Consensus layer** — `crates/dom-consensus`,
   `crates/dom-chain`, `crates/dom-pmmr`, `crates/dom-pow`,
   `crates/dom-core`.
2. **Cryptographic surface** — `crates/dom-crypto` (Schnorr,
   Pedersen, Bulletproofs, H generator, hash domains).
3. **Wire / P2P surface** — `crates/dom-wire`,
   `crates/dom-node/src/relay`, `crates/dom-node/src/pex.rs`.
4. **Storage durability** — `crates/dom-store`,
   `crates/dom-node/src/future_block_queue.rs`.
5. **RFC documents** — `docs/DOM_RFC_*.md`.

Out of scope (deferred to follow-up engagements):

* RPC layer (`crates/dom-rpc`) authentication and rate limits.
* Wallet integration (`crates/dom-wallet`) beyond the
  Zeroizing-derived BIP-39 surface (already covered by Phase 2.5).
* Explorer / faucet (`crates/dom-explorer`, `crates/dom-faucet`).
* Build reproducibility (Phase 8 follow-up).

## Prior-art reading list (REQUIRED before reviewing)

* RFC-0000 — Whitepaper.
* RFC-0001 — Cryptographic primitives.
* RFC-0004 — PMMR Hardening (this is the spec for the algorithm
  the protocol now runs; superseded prior informal notes).
* RFC-0007 — Validation order.
* RFC-0008 — Balance + Coinbase + Fee + Offset.
* RFC-0009 — Cryptographic completeness.
* RFC-0010 — Validation completeness.
* RFC-0011 — Bootstrap + PMMR peak bagging + Fee policy.
* `docs/SECURITY_AUDIT.md` — internal pre-audit (the 6-section
  audit that drove much of the early hardening) plus SEÇÃO 7
  recording the DOM-PMMR-001 finding and its resolution.
* `docs/CONSTANT_TIME_AUDIT.md` — Phase 2.3 static CT audit.
* `docs/ECONOMIC_SECURITY.md` — Phase 5.2 selfish-mining / game
  theory analysis.
* `docs/RELEASE_BLOCKERS.md` — all open and resolved blockers.
* `docs/ROADMAP_v2.md` — strategic plan + non-negotiables.

## Internal test coverage

A summary of the automated coverage the auditor inherits:

| Surface | Test crate / file | Count |
|---|---|---|
| PMMR algorithm | `dom-pmmr/src/lib.rs` + `tests/silent_mutation_reproducer.rs` + `tests/adversarial_suite.rs` | 28 |
| Consensus validation | `dom-consensus/src/lib.rs::tests` | 36 |
| Test vectors (constants, hash, PMMR, serialization, invariants, RFC↔constants audit, drift audit, resource exhaustion) | `dom-test-vectors` | ~46 |
| Crypto (unit + reproducer + adversarial + differential + infinity rejection + bulletproof adversarial) | `dom-crypto` | 89 |
| Store (crash consistency + SIGKILL + partial persistence + lmdb durability) | `dom-store` | 22 |
| Chain (lib + reorg + corruption detection + IBD adversarial) | `dom-chain` | 36+ |
| Node (genesis determinism + sybil resistance + …) | `dom-node` | ~24 |
| Wire (manager + handshake + message + dandelion + eclipse) | `dom-wire` | 27 |
| Mempool (in-crate + adversarial) | `dom-mempool` | 14 |
| Wallet (HD + backup + spend) | `dom-wallet` | 32 |
| **Total workspace (excluding integration)** | | **492 tests, 0 failures** |

Integration tests (`crates/dom-integration-tests/`) are
env-blocked under the current single-VPS environment — see
RELEASE_BLOCKERS.md RB-PMMR-001 for the empirical timings. They
need a dedicated mining host to run, but DO build under the
workspace `cargo build` to catch link-level regressions.

## Known limitations / deferred items

The auditor should be aware of every open `RELEASE_BLOCKERS.md`
entry. The CRITICAL-level items are:

* **None at handover time.** DOM-PMMR-001 was the only
  consensus-class CRITICAL finding from the internal audit and is
  resolved (see SEÇÃO 7 of SECURITY_AUDIT.md).

IMPORTANT-level items the auditor should review:

* **RB-LMDB-MAPSIZE** — operational fail-stop, not consensus.
  Dynamic map_size growth is intentionally deferred; the
  16 GiB pre-allocation gives ~5 years of headroom and a tagged
  sentinel surface for the chain-init layer.
* **RB-EVICTION-POLICY** — peer-manager has no eviction once
  `max_inbound` is full. Subnet cap mitigates the obvious
  eclipse shape; the residual is "first connectors monopolise"
  which is not blocking.
* **RB-FS-MATRIX** — Phase 3.3 LMDB durability is verified on
  tmpfs + ext4; btrfs/xfs/zfs adversarial journal-replay testing
  is deferred (requires loop-mount + dm-snapshot infra).
* **RB-CT-INSTRUMENTATION** — empirical `ctgrind` / `dudect`
  validation deferred to Phase 8.2 fuzz window. Phase 2.3
  static-review fix eliminated the DOM-specific non-CT paths.
* **RB-PEX-SUBNET** — PEX known-set has no /16 cap (count cap
  only). LOW severity — connection-level cap stops actual
  eclipse, only outbound-dialer waste.

LOW-level items, deferred follow-ups, etc. — see the full file.

## Audit deliverables expected

The engagement letter specifies; this section is provided as a
reference for what the project considers a complete audit
report:

1. Executive summary (1 page).
2. Findings list with severity (CRITICAL / HIGH / IMPORTANT / LOW
   / INFORMATIONAL) and CVSS-style score.
3. Per-finding: location (file:line), root cause analysis,
   exploitation scenario, recommended fix.
4. Coverage notes — what the auditor reviewed and what was
   skipped + rationale.
5. Reproducibility notes — auditor's testing methodology and
   tooling versions.
6. Optional: signed PGP statement on the artefact hashes.

## Reproducibility

The repository's `rust-toolchain.toml` pins the stable channel.
The `.github/workflows/ci.yml` matrix (Phase 1.4) runs the test
suite on five hosts (Linux x86_64 / ARM64, macOS x86_64 / ARM64,
Windows x86_64). A green CI run at the audit-handover commit is
the empirical reproducibility floor.

For deterministic build artefacts (Phase 8.4 / 8.5 follow-up),
the operator runbook adds `--locked` and `RUSTFLAGS="-C
codegen-units=1"`.

## Confidence at handover

* **Confirmed:** 492 automated tests cover the surfaces listed
  above. DOM-PMMR-001 closed with a full reproducer + oracle +
  pinned hex vectors + RFC-0004 normative spec.
* **Likely:** Cross-platform deterministic roots — the CI YAML is
  in place; first green run on the matrix closes this empirically.
* **Theoretical until external audit:** Cryptographic soundness
  under adversarial review beyond the BIP-340 / k256 / grin secp256k1zkp
  upstream claims. End-to-end CT validation via `ctgrind` /
  `dudect`. Multi-strategy economic simulation.

## Contact

* Maintainer: Soren Planck (`leovictor157@hotmail.com` for the
  engagement).
* Security disclosure: see `docs/BUG_BOUNTY_POLICY.md` for the
  pre-launch coordinated-disclosure protocol.
