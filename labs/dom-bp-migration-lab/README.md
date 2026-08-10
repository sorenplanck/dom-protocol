# DOM Bulletproof migration lab

This is an isolated, non-production workspace. It is deliberately not a member
of the repository root workspace and it must not be used to change consensus,
the wire format, genesis data, wallets, nodes, or the production crypto crate.

L0 freezes the current DOM range-proof oracle: the classic/standard Grin
Bulletproof with `nbits=64`, two commitments `[C, M*H-C]`,
`M = 2^52 - 1`, and a 739-byte proof. Any accepted value `>= 2^52` is an
immediate migration abort.

Candidate A and Candidate B do not exist here yet. `UnavailableCandidate`
fails closed, so it cannot accidentally accept a proof or claim recovery.

## L1-B aggregate-rewind result

L1-B adds a scalar-only research model for the live two-commitment aggregation.
It is not a recovery implementation and it does not alter production. The
model confirms the backend term `z^2*r + z^3*(-r) = z^2*(1-z)*r`; `z = 1`
removes the only recoverable blinding term. See
[`docs/L1B_AGGREGATE_REWIND_SPEC.md`](docs/L1B_AGGREGATE_REWIND_SPEC.md).

## Run

```bash
cargo test --manifest-path labs/dom-bp-migration-lab/Cargo.toml --locked -- --nocapture
printf '%s\n' '{"schema_version":1,"case_id":"one","operation":"prove_verify","value":1,"blind_hex":"1111111111111111111111111111111111111111111111111111111111111111"}' \
  | cargo run --manifest-path labs/dom-bp-migration-lab/Cargo.toml --locked --bin current-oracle
```

The binary is JSON Lines: one request per stdin line and one structured,
deterministically serialized response per stdout line. It never emits blinds,
nonces, or proof bytes.

## Candidate process isolation

The current Grin backend exports native C symbols. A future backend fork must
run in a separate oracle process, or have all C symbols prefixed. Do not link a
fork and the current backend with identical C symbols into the same process.

No migration is authorized by this lab. A future candidate must first match the
current ceiling oracle and its adversarial corpus.
