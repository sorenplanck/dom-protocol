# DOM Protocol — Documentation Index

## Roadmap

See [docs/ROADMAP_v2.md](./ROADMAP_v2.md) — adopted 2026-05-24.
Deployment progression is milestone-based: adversarial hardening,
recoverability proofs, public testnet stabilization, external review,
bug bounty, and genesis ceremony.

The roadmap supersedes any earlier ad-hoc plan implied by Docs 8-11 or
the initial testnet schedule. It was triggered by the Track A
consolidated audit + hardening checklist from an external
blockchain-specialist reviewer, and was accepted under the principle
"Security > Stability > Usability".

## RFCs (spec, frozen)

- [DOM_RFC_0008](./DOM_RFC_0008_Balance_Coinbase_Fee_Offset.md) — Balance equation, coinbase, fee offset
- [DOM_RFC_0009](./DOM_RFC_0009_Cryptographic_Complete.md) — Cryptography (Pedersen, Bulletproofs+, Schnorr, MuSig2)
- [DOM_RFC_0010](./DOM_RFC_0010_Validation_Completeness.md) — Validation pipeline completeness
- [DOM_RFC_0011](./DOM_RFC_0011_Bootstrap_PMMR_FeePolicy.md) — Bootstrap discovery, PMMR, fee policy

## Operations

- [DEPLOYMENT.md](./DEPLOYMENT.md) — Testnet deployment guide + planned mainnet operational path
- [BACKBONE_SYSTEMD.md](./BACKBONE_SYSTEMD.md) — VPS backbone systemd service runbook
- [REGTEST.md](./REGTEST.md) — Local-dev `Network::Regtest` (NEVER for production)
- [RPC.md](./RPC.md) — RPC endpoints
- [FUZZING.md](./FUZZING.md) — Fuzzing campaign + how to add fuzz targets
- [testing/WINDOWS_AGENT_WORKFLOW.md](./testing/WINDOWS_AGENT_WORKFLOW.md) and
  [testing/WINDOWS_TEST_RUNNER.md](./testing/WINDOWS_TEST_RUNNER.md) — Windows portable test/agent runners

## Audit & status

- [SECURITY_AUDIT.md](./SECURITY_AUDIT.md) — External audit findings
- [RELEASE_BLOCKERS.md](./RELEASE_BLOCKERS.md) — Per-blocker status, updated as items resolve
- [AUDIT_TRACKER.md](./AUDIT_TRACKER.md) — Cross-reference of audit findings vs commits

## Consensus reference

- [CONSENSUS.md](./CONSENSUS.md) — Consensus rules summary
- [MAINNET_LAUNCH.md](./MAINNET_LAUNCH.md) — Historical launch checklist (superseded by milestone-based readiness gates in ROADMAP_v2)

## Troubleshooting

- [troubleshooting/](./troubleshooting/) — Runbooks for common operational issues
- [troubleshooting/chain-persistence-latency-rca.md](./troubleshooting/chain-persistence-latency-rca.md) — RCA for `chain_persistence` runtime latency vs restart/recovery behavior

## Wallet Diagnostics

The desktop wallet diagnostics panel can export a bounded diagnostic log with
application version, build hash when available, configured network mode,
configured backbone/node endpoint, connection lifecycle events, errors,
heartbeat observations, and chain-height changes observed through node status.

To collect wallet diagnostics:

1. Open the wallet app.
2. Unlock the wallet if diagnostics are needed for an active session.
3. Open `Diagnostics`.
4. Click `Export Logs`.
5. Share the generated `dom-wallet-diagnostics-*.log` file from the wallet app
   data directory.

Diagnostic export applies redaction before entries are stored and exported.
Wallet passwords, seed phrases, private/secret keys, bearer tokens,
authorization values, and similarly named secret fields are replaced with
`<redacted>`. Do not paste wallet seed phrases, private keys, or passwords into
issue descriptions or chat even when sharing a diagnostic export.
