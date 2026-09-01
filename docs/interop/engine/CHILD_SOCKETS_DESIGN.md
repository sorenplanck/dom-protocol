# Engine sockets for the Monero and Solana legs — design before code

Date: 2026-09-01. Status: reconnaissance complete; implementation staged
behind the production-feature baseline (see §6).

## 1. What "the engine" actually is

One shared machine, three layers, all leg-agnostic:

```
kaystra-core settlement engine          — economic state machine
route-executor durable store + runtime  — journal, leases, fencing, stage-6 loop
settlement-coordinator                  — child plans, dispatch, evidence
```

A leg participates only through one trait:

```rust
trait ProductionSettlementChildPortV1 {
    fn face(&self) -> SettlementFaceV1;
    fn materialize(&mut self, request, public_scalar: Option<&RouteScalar>)
        -> Result<SettlementChildPlanV1, _>;   // exact tx under durable custody
    fn externalize(&mut self, request) -> Result<ChildExecutionOutcomeV1, _>;
    fn reconcile(&mut self, request)   -> Result<ChildReconciliationOutcomeV1, _>;
    fn observe(&mut self, request)     -> Result<ChildObservationOutcomeV1, _>;
}
```

DOM, EVM and Bitcoin have implementations (`production_child_{dom,evm,btc}.rs`,
5,948 lines). Monero and Solana have none. Everything below is what plugging
them in requires, discovered by reading, not guessed.

## 2. The socket dependency chain (in order)

| # | Piece | State |
|---|---|---|
| 1 | `SettlementFaceV1::{Monero = 4, Solana = 5}` + tag codec + `is_counterparty` | **written** |
| 2 | `ResolvedMoneroDeploymentV1` / `ResolvedSolanaDeploymentV1` + `*_deployment_capability()` in deployment-registry | **written** |
| 3 | `monero_deployment_capability` / `solana_deployment_capability` on `AuthenticatedRouteAdmissionV1` | **written** |
| 4 | Authenticated leg sessions in `production_inputs` (see §3) | pending |
| 5 | `authenticate_leg` arms choosing the new faces | pending |
| 6 | Router slots `monero`/`solana` + authenticate constructors | pending |
| 7 | `validate_first_exposure_scope` counterparty-face widening | pending |
| 8 | `production_child_solana.rs` (mold: EVM child) | pending |
| 9 | `production_child_xmr.rs` (mold: BTC child) | pending |
| 10 | Child tests to the standard of the existing children | pending |

## 3. Session authentication — the deliberate asymmetry

BTC sessions are authenticated by BIP340 statements signed with relay keys;
EVM sessions by dual-signed account bindings. Inventing an equivalent
statement format for XMR/SOL would be new consensus surface needing its own
ratification.

Neither leg needs it. Both already carry a stronger route binding: the
**cross-curve DLEQ in the registered setup**, bound to `settlement_id` and a
context hash derived from the frozen terms. Session authentication for these
legs is therefore:

```
registry capability (chain identity, program pinning)     — §2 items 2–3
+ validate_setup(profile, frozen terms, setup binding)    — existing leg code
+ the DLEQ inside the binding verifies for that settlement — existing leg code
```

The bundle (`ProductionParticipantBindingBundleV1`) gains two optional
per-leg artifacts carrying the leg's setup-binding bytes; authentication
replays `validate_setup` against the terms frozen in the V2 admission
checkpoint. No new signature scheme, no new ratified format beyond the
bundle codec's two new fields.

## 4. The Solana child (mold: EVM)

Custody = `solana-delivery` exact-bytes journal (fingerprint, one-shot,
conflicting-retransmission refused), keyed per operation:
`operation_key = H(domain, settlement_id, action_tag)` — the store's
settlement-key column already fits it.

| Port call | Implementation |
|---|---|
| materialize(Funding) | one atomic tx `[initialize_native, fund]`, funder-signed; journal exact bytes |
| materialize(Claim, scalar) | verify scalar against setup claim (`revealed_dom_secret_to_xmr_scalar`), build `claim` ix, journal |
| materialize(Refund) | `refund` ix (permissionless past `refund_after_unix`), journal |
| externalize | submit journalled bytes to every pool node; ≥1 acceptance = Externalized; all-transport-failure = Unknown |
| reconcile | quorum `signature_status`: landed → adopt; None + blockhash expired at Finalized → ProvenNotExternalized |
| observe | quorum status Finalized + `solana-observer` state evidence (attested program, escrow state transition) |

Plan commitments: `expected_transaction_id = H(primary signature)`,
`custody_digest = delivery fingerprint`, `intent_digest = H(domain, action,
setup_id, revealed?)`.

**Known hard edge, recorded up front:** a journalled legacy transaction
embeds a recent blockhash that expires in ~150 slots. Expiry is the
designed path to `ProvenNotExternalized` → coordinator re-materializes under
a new call. The robust production answer is a durable nonce account; that is
follow-up work and listed in NAR-DC-P1-010 §5 territory, not silently
patched here.

## 5. The Monero child (mold: BTC)

| Port call | Implementation |
|---|---|
| materialize(Funding) | **external custody** — the XMR funder places the shared output; the child returns the external-funding receipt path exactly as the BTC child's `BitcoinExternalFundingCustodyV1` does |
| materialize(Claim, scalar) | combine scalar with local share (secret store), build sweep via sidecar `BuildSweepRequestV2`, journal exact bytes (`xmr-delivery`) |
| materialize(Refund) | refund-side sweep via `DomRefundAdaptorExecutor` artifact path |
| externalize | `xmr-rpc-broadcast-blocking` exact bytes; AlreadyKnown counts |
| reconcile | daemon pool tx lookup by txid; absent + key-image unspent → not externalized |
| observe | `xmr-observer` verified events at the profile's confirmation depth |

## 6. The gate that was invisible — and gates this work

Everything in `production_*` sits behind `feature = "production"`, absent
from default features. **No gate in any of the v6→v8 rounds compiled it**,
including this branch's own CI as far as the scripts in `scripts/` go. The
baseline state of the production build at HEAD is unknown and, given the
`ChainKindV1` matches found in it with Evm/Bitcoin-only arms, presumed red.

Order of work therefore:

1. Full default-feature suite green (in progress; three pre-existing HEAD
   failures already repaired: driver retirement ×3, staging census ×2 — see
   the closure record).
2. `cargo check -p dom-interopd --features production` — baseline, then fix
   to green **with the §2 items 1–3 already in the tree**.
3. Add `--features production` to `scripts/run-solana-v8-gates.sh` and CI so
   this gate can never go invisible again.
4. Protective commit.
5. Items 4–10.

Until step 5 completes, no route with a Monero or Solana counterparty leg
can be driven by the daemon; the time anchor admits them and the runtime
refuses at materialization, which is fail-closed and by construction.

## 7. Stage-6 repairs made while opening this front (2026-09-01)

Nine tests were red at pure HEAD — the stage-6 merge shipped them failing,
invisible because no full suite had run since. All were diagnosed to root
cause; none was skipped or weakened:

| Failure | Root cause | Repair |
|---|---|---|
| driver retirement ×3 | fixture froze terms via the legacy V1 path while `mint_route_secret_retirement_capability_v1` demands the V2 admission checkpoint | fixture gained the production shape (`Fixture::new_production` journals `FreezeTermsV2` at revision 1, as `persist_new_route_checkpoint` does); legacy tests keep the legacy path |
| staging census ×2 | **fail-open**: staged M8/F7 artifacts are excluded from the census scan, and `PreRecoveryStagingInventoryV1::capture` never checked their magic or the V1-xor-V2 rule — a crash cut could smuggle a wrong-typed or profile-mixed artifact past quarantine | `capture` now enforces magic-matches-name and per-session profile exclusivity for staged descriptor artifacts, before any staging replay; legitimate crash-cut recovery unaffected (`every_published_staging_name_survives_a_crash_cut_and_is_recovered` still green) |
| purpose registry ×1 | test froze the closed signed-purpose set at 0x01..=0x04; `PurposeV1::RefundAdaptor = 0x05` was ratified into it (NAR-DC-P1-009 §4.1) | range widened to exactly 0x05, refusal from 0x06 |
| equivocation semantics ×2 (+1 revealed) | two operational tests demanded a duplicate-ACK for the accepted bytes after an equivocation poisoned the key; four restart tests and the relay worker's `was_failed_closed` handling encode the opposite | **adjudicated for the majority and for fail-closed**: a poisoned key never ACKs again, including for previously accepted bytes; the two tests corrected, `DurableTransportOutcomeV1::EquivocationPersisted`'s doc now states the rule so it cannot be re-litigated silently |
