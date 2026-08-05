# Independent integration attack expectations

This evidence-only directory freezes adversarial expectations before the
reviewer inspects an integrated Phase 1 candidate.

`attack-expectations.tsv` is tab-separated UTF-8 with one header row. Each row
has a stable attack ID, area, attack, expected fail-closed result, and required
evidence. The expected result must not be weakened after production inspection.
Implementation-specific probe code may be created after the barrier commit,
but only to execute an attack already represented here.

This directory contains no production implementation, secret, key, Wallet
data, witness credential, or generated expected cryptographic output.
