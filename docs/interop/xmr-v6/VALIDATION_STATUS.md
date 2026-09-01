# Validation status — v6.1

V6 shipped with `rust_tests_executed: false`. Everything below was executed in a
checkout of `sorenplanck/dom-protocol` at `mainnetswap` commit `7ea7f968`, with
this package applied.

## Gates

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --all -- --check` | clean, whole workspace |
| Lint | `cargo clippy <19 crates> --all-targets -- -D warnings` | 0 |
| Test | `cargo test <19 crates> --all-targets` | 62 passed, 0 failed |
| DOM guards | `check-hash-domains`, `check-normative-adjudication`, `check-policy-topology`, `check-claim-adaptor-provenance`, `check-adaptor-two-nonce`, `check-shared-output-bp`, `check-relay-fault-surface` | all exit 0 |

## What had to be repaired before any of that could run

V6 as delivered did not compile. In order:

1. **`CrossCurvePublicClaim` could not derive `Serialize`/`Deserialize`.** The
   SEC1 point is `[u8; 33]` and `serde` has no impl for that width. Replaced
   with a manual fixed-width codec — the wire form is exactly
   `secp_compressed || ed_compressed`, 65 bytes, and any other length is refused
   on decode. A consensus-sensitive identity must not depend on a serializer's
   array representation, so this is the better shape regardless.
2. **`LazyLock` violates the workspace MSRV** (1.75; `LazyLock` is 1.80).
   Replaced with `OnceLock`, which is 1.70.
3. **`?` applied to a `MutexGuard`** in `xmr-delivery`, twice. The guard is bound
   first and the transition takes `&mut`.
4. **Private-field and private-constructor access** on `RevealedSecretBytes`
   (`revealed.0`, `RevealedSecretBytes(..)`) in `xmr-kaystra-bridge` and
   `f8-xmr-kaystra-e2e`. Now `expose_scalar_bytes()` and `new()`.
5. **`patches/dom-real-xmr-secret-forwarding.patch` was not a unified diff** —
   its hunks carried a bare `@@` with no line ranges, so `git apply --check`
   refused it and `scripts/apply-v6.py` failed at the patch step. The hook was
   applied by hand and the patch regenerated from the result; it now passes
   `git apply --check`.
6. **A non-canonical test fixture** in `xmr-route-secret` used `[4; 32]` as an
   ed25519 view key. It now derives a real one.
7. **Three deprecated `GenericArray::from_slice` calls** in `xmr-secret-store`,
   which are hard errors under `-D warnings`. Replaced with
   `<&Key>::from(&..)` / `<&XNonce>::from(&..)`: the length is checked by the
   compiler instead of panicking at run time, and no copy of the key is made.
   No `#[allow(deprecated)]` was added.

## A defect this package exposed in `crates/store`

`crates/store` declares `rustix` with `default-features = false` and without
`std`, while `lib.rs` hands `std::os::fd::BorrowedFd` to `rustix::fs::flock`.
Without `rustix/std`, `rustix` defines its own `BorrowedFd` and that call does
not type-check. It has compiled until now only because `store`'s own
dev-dependency on `tempfile` enables `rustix/std` in the same resolution unit.

Building any XMR crate that reaches `store` through `kaystra-core` as a plain
dependency produces a unit with no `tempfile` in it, and `store` fails to
compile — `cargo test -p xmr-kaystra-records` is the shortest reproduction.
`patches/store-rustix-std-feature.patch` makes the existing requirement
explicit. It widens nothing.

## Test coverage added

V6 shipped 24 tests, and seven crates had none at all — including
`xmr-kaystra-bridge`, which is the crate that turns a DOM claim into a signed
Monero sweep. 38 tests were added, all of them adversarial:

| Crate | Added | What they hold |
|---|---|---|
| `f8-xmr-kaystra-e2e` | 8 | an effect for another settlement, an effect that is not a claim consumption, evidence that differs from the effect, a scalar that is not the route secret, a second effect id attempting redelivery, a sweep response carrying another nonce, a transient broadcast failure resubmitting exactly the persisted bytes, a missing local share deferring rather than delivering |
| `xmr-live-sidecar-uds-client` | 9 | a response signed with another key, a response echoing another nonce, a response of another kind, an authenticated error surfacing its code, an unauthenticated error never reported as a rejection, an oversized frame refused on the prefix alone, an absent socket, a request refused locally before it reaches the socket |
| `xmr-profile` | 8 | a combined key that is not the sum of its shares, a quorum above the node count, a reorg bound below the confirmation target, an uncompressed adaptor point, zero amount / absent / oversized destination, wrong profile and sidecar versions, and that the proof context changes with every committed field |
| `xmr-settlement-observer` | 5 | the durable cursor codec, including a cursor whose outer height or anchor disagrees with its body |
| `xmr-spend-port` | 4 | bytes that do not match the expected hash never reach the daemon; only transport failures are retryable |
| `xmr-raw-tx-verify` | 2 | empty, oversized and zero-hash inputs refused before parsing |
| `xmr-kaystra-records` | 2 | a reorg without an anchor refused |

Two of these were mutation-tested. Removing the `record.source_effect_id`
check in `xmr-kaystra-bridge` fails
`a_second_effect_id_cannot_redeliver_an_existing_record` and nothing else;
removing the sweep-nonce check fails
`a_sweep_response_carrying_another_nonce_is_refused_and_nothing_is_persisted`
and nothing else. Each test holds the invariant it names.

## Known conditions, not defects

- **Six crates raise `rust-version` to 1.85** against the workspace's 1.75.
  This is forced by `monero-oxide`, `rusqlite` and `reqwest`, it is declared
  per-crate, and no CI gate enforces the workspace MSRV. It is recorded here
  rather than hidden.
- **`xmr-raw-tx-verify` depends on `monero-oxide` by git revision**, pinned to
  `c8be5d3d`. A git dependency in a production leg is a supply-chain surface the
  `supply-chain` CI job should be pointed at before release.
- **Four crates outside this package fail `clippy -D warnings` on
  `mainnetswap`**, all of them pre-existing and none touched here:
  `adapter-dom-real` (`terminal_finality.rs:1261`, `expect_used`),
  `dom-interopd` (`supervisor.rs`, five `needless_question_mark`),
  `dom-node` (`wallet_core_api.rs:155`, `type_complexity`),
  `dom-scriptless-store` (`session_store.rs`, two dead methods). Confirmed
  pre-existing by running clippy on a pristine `adapter-dom-real`. They belong
  to work in progress on that branch and were deliberately left alone.

## Production status

The nineteen crates are complete, gates-green and tested. The leg itself is
**not** production-admissible yet, and cannot be made so from inside this
package: `validate_production_v1` returns `MechanismUnratified` by construction,
and `ChainKindV1` has no Monero variant, so `dom-interopd` admission refuses an
XMR leg whatever mechanism tag it carries. Both are normative decisions.
`docs/RATIFICATION_SHEET.md` lists every file each one lands in.
