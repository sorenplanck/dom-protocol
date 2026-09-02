# Phase 1B node integration

Result: `IMPLEMENTED_AND_DETERMINISTICALLY_VALIDATED`.

The wallet HTTP adapter was compared read-only with DOM Protocol revision `f10667d86196daf4599eff6074a7abf73b6ed55a`. The contract includes the identity, ancestry, scan, block, kernel, mempool lookup, and transaction-submit endpoints used by the wallet. No DOM Protocol files were changed.

Wallet changes add strict mempool DTO decoding, response-size handling for targeted endpoint responses, protocol-correct network labels, node-hash equality checks on submission, positive-only mempool lifecycle observation, and descriptor-only scan reconciliation. Sender and receiver confirmation both use canonical block scan evidence, not frontend state or a configured hash.

Focused deterministic validation covers exact `/tx/{hash}` DTO decoding, output-descriptor confirmation, kernel confirmation, existing manual slate finalization, existing protocol canonical validation, and restart-safe lifecycle foundations. A live node transaction, mempool admission, mining event, or canonical confirmation was not claimed or performed by this report.

The live runner now has an explicit `PREFLIGHT` mode and an explicit `EXECUTE`
mode. `PREFLIGHT` performs real production-adapter health, identity, scan,
ancestry, kernel, and transaction-lookup checks; validates protected password
files; opens and synchronizes both wallets; calculates the read-only funding
result; and observes tip progression. It has no transaction-construction path.
`EXECUTE` repeats preflight and additionally requires the exact enable token.
Insufficient funding and a missing external block producer both stop before
input reservation.
