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

## 8. Progress — Solana socket landed (2026-09-01)

Everything §4 asked for is now in the tree and green under
`cargo check -p dom-interopd --no-default-features --features production`:

1. **`solana-actuator`** (new crate): SQLite durable store, one row per
   `(settlement_id, kind)`, exact signed bytes retained write-once, fenced
   idempotent mutations by attempt id, monotone stages
   `Signed → SendAttempted → Observed → Final / Reconciled /
   FinalityInvalidated`. The stage moves to `SendAttempted` **before** any
   node sees a byte. Takeover reconciliation turns blockhash expiry at the
   quorum finalized-height floor into the positive `ExpiredNeverLanded`
   proof; absence inside the window stays `Unknown` and writes nothing.
   16 adversarial tests.
2. **RPC surface**: `SolanaRpc::get_block_height` and
   `get_latest_blockhash_with_validity`; pool gains
   `finalized_block_height_floor` with a bounded quorum spread.
3. **Authenticated Solana session** (`production_inputs.rs`): the
   participant bundle's reserved u16 became the layout marker — `0` stays
   byte-identical to the legacy encoding, `1` appends
   `ProductionSolanaLegSetupV1` entries (adapter profile + DLEQ-bound
   setup binding, fixed-width codec, proof bounded by the DLEQ system's
   own limit). Authentication cross-checks the registry-pinned escrow
   program, cluster and immutable program hash, then runs
   `solana_profile::validate_setup` — the DLEQ against the frozen terms is
   the anchor, exactly as §3 decided. Produces
   `AuthenticatedSolanaSessionBindingsV1`; Monero legs remain refused
   fail-closed until their child lands.
4. **`production_child_solana.rs`**: `ProductionSolanaChildPortV1`
   implements `ProductionSettlementChildPortV1` over the actuator + quorum
   pool. Funding is initialize-plus-fund in one atomic transaction; every
   escrow transaction has exactly one signer (its fee payer), so retained
   custody revalidation rebuilds the deterministic message and re-verifies
   the one ed25519 signature. The claim scalar is borrowed only into exact
   message bytes and zeroized after the actuator retains them.
   Reconciliation maps `ExpiredNeverLanded → ProvenNotExternalized`.
5. **Router**: `AuthenticatedSolanaChildPortV1`, `authenticate_solana`,
   `new_with_counterparties(…, solana)`; the Solana face routes the moment
   a child is installed. **Materializer**: `authenticate_leg` resolves
   Solana legs through `solana_deployment_capability` and the derived
   `resolved_solana_deployment_digest_v1`.

Still open from §2: the Monero actuator + `production_child_xmr` (§5),
and the final graph wiring that constructs the production children inside
`production_run` (the dead-code warnings on the materializer subsystem
mark exactly that seam, unchanged from before this work).

## 9. Progress — Monero socket landed (2026-09-01)

Everything §5 asked for, same recipe as §8:

1. **`xmr-actuator`** (new crate): the solana-actuator discipline for
   sweeps — exact signed bytes retained write-once, fenced idempotent
   mutations, `SendAttempted` before any daemon sees a byte, finality only
   at the profile's confirmation depth. Reconciliation records
   `KeyImageUnspentAbsent` only when the txid is absent **and** the
   sweep's own key image is unspent — the §5-adjudicated absence
   statement, documented as point-in-time; a spent key image with an
   absent txid is a conflicting spend and stays `Unknown`, written
   nowhere. 14 adversarial tests.
2. **Authenticated Monero session** (`production_inputs.rs`): the layout
   marker became a bitmask (bit 0 = Solana, bit 1 = Monero);
   `ProductionXmrLegSetupV1` carries the adapter profile and DLEQ-bound
   `XmrSetupBindingV1`. Authentication pins the network to the registry
   (mainnet unrepresentable) and anchors on
   `xmr_setup_profile::validate_setup` under the ratified
   `CrossCurveSharedSpend` mechanism, no admission token. The fail-closed
   Monero refusal is gone because the real thing replaced it.
3. **`production_child_xmr.rs`**: funding is external custody — the child
   verifies the pinned funding transaction through the scoped view-key
   scan and the quorum observation boundary, and never holds funding
   bytes. Sweep construction stays behind
   `ScopedXmrSweepAuthorityV1`; every sidecar answer and every retained
   transaction is independently re-verified with
   `xmr_raw_tx_verify::verify_exact_raw_transaction` before it is
   trusted. Claim exposure is `UsesPublicSecret` only — a Monero sweep
   never first-exposes the witness.
4. **Router/materializer**: `authenticate_monero`,
   `new_with_all_counterparties`, and the Monero materializer arm over
   `resolved_monero_deployment_digest_v1`.

Still open from §2: the final graph wiring that constructs the
production children inside `production_run` (unchanged seam).

## 10. Progress — the composition seam (2026-09-01, second round)

`run_production_v1` now **constructs the counterparty children**. What
landed, and the two adjudications that shaped it:

1. **V4 bootstrap family** (`production_config.rs`): the V3 document plus
   four references — `path_chain_endpoints`,
   `path_solana_actuator_store`, `path_xmr_actuator_store`,
   `path_bitcoin_prebroadcast_store` — one variant, six extras, so a
   half-configured V4 is unrepresentable. V4 manifests win when present;
   a V3 state directory keeps its exact old behaviour. Golden round-trip
   plus cross-family refusal tests.
2. **Chain-endpoints artifact** (`production_children.rs`): strict
   canonical binary (`DOMCEND1`), faces as a bitmask, bounded URLs,
   quorum shapes cross-checked against the *authenticated adapter
   profiles* — the artifact can configure where, never how much.
3. **`compose_production_counterparty_children_v1`**: one child per
   authenticated leg in drive (non-materializing) form — EVM over its
   provisioned actuator and `HttpEvmRpcV1`, Bitcoin over its actuator,
   Core cookie RPC and the **armed** prebroadcast funding (un-armed
   funding is a named refusal, `FundingNotArmed`), Solana over its
   store, quorum pool and per-role fee-payer leases, Monero over its
   store, the loopback broadcaster and a new quorum observation port.
   Exact face binding: an endpoint for a face the route did not admit
   refuses composition.
4. **Quorum Monero observation** (`QuorumXmrObservationPortV1` over the
   new `BlockingMoneroDaemonReaderV1` in `xmr-rpc-broadcast-blocking`):
   inclusion requires `quorum` daemons agreeing on the exact
   `(height, block hash)`; confirmations count from the lowest agreeing
   daemon height; absence requires `quorum` answered-and-missing;
   key-image spent anywhere reports spent (the conservative direction).

**Adjudication — no journal stages for the new stores.** The
provisioning journal's audit demands a monotone stage prefix and the
stages that would precede any new ones (F6, Relay) cannot complete yet;
appending stages would deadlock `begin`. The Solana and Monero stores
are idempotent open-or-create SQLite files whose rows are self-fencing
and write-once, exactly like the Bitcoin prebroadcast store the external
arming flow writes, so their creation is layout-validated (owner file
when present) rather than journaled.

**Adjudication — the DOM child stays uncomposed.** Its Contracts
authority requires the real Relay worker over `F6TransportPortV1`
(missing part 6, ordered before it by the provisioning enum's own
comment). Composing it over the refusing transport would dress absence
as presence. `ProductionCounterpartyChildrenV1::into_router` holds the
one remaining step in the type system: the moment a real DOM child
exists, the full `ProductionSettlementChildRouterV1` is one call away.

Remaining in `MISSING_PRODUCTION_PARTS_V1`: the runner, the timer, the
refund-arming faces, F6, and — behind F6 — the DOM child that completes
the router.

## 11. Progress — F6, refund faces and the honest remaining gap (2026-09-01)

This round took `MISSING_PRODUCTION_PARTS_V1` from six vague entries to a
precise map, and closed or advanced most of them:

1. **Counterparty refund faces (all four chains).** `production_refund_arming`
   gained `ProductionSolanaRefundFaceV1` (verifies the `Funded` escrow state
   at the quorum — the program *is* the armed refund, paying the pinned
   recipient after the deadline permissionlessly) and
   `ProductionXmrRefundFaceV1` (re-verifies the role-2 cross-curve
   refund-share proof against the same economic context the shared-spend
   setup used, and requires the executor artifact armed with exactly the
   adaptor point that proof certifies). The receipt kind space is closed at
   `{2,3,4,5}`. `compose_production_counterparty_children_v1` builds all four
   faces from the same authorities as the children (one exclusive store
   opening) and returns them in `ProductionCounterpartyChildrenV1::refund_faces`.
   The Monero participant-bundle leg carries an optional refund arm
   (role-2 proof + executor artifact), strictly encoded and authenticated.
2. **Deadline timer.** `deadline_context_digest_v1` gives one canonical
   context derivation; `compose_production_deadline_timer_v1` builds the
   `ProductionDeadlineTimerAuthorityV1` from the two authenticated
   counterparty deadlines. Fully composed in `run_production_v1`.
3. **F6 — what exists and the one thing that does not.** The durable F6
   port `ProductionSolverF6AuthorityV2` is a complete `F6TransportPortV1`
   engine (3.9k lines), and `UnavailableF6AuthorityV1` is the fail-closed
   alternative the codebase already sanctions for deployments that have not
   wired F6 — it *blocks* F6 traffic rather than skipping it, so a route can
   be composed and driven over it with F6 negotiation explicitly refused.
   The **one genuine gap** is `ProductionF6TermsAuthorityV2`: it has only a
   test `UnreachableTermsV2` impl. Building it is new cross-object
   cryptographic authority code — RFQ/quote/terms authentication against a
   real evidence source — **not composition glue**, and improvising it would
   violate this crate's own rule against reporting progress it did not make.

### The remaining interlocked block, stated plainly

Removing `NotComposable` needs the settlement bridge, which needs the DOM
child. The DOM child is composable **today** over `UnavailableF6AuthorityV1`
— it needs the Relay worker (`DurableRelayWorkerV1::create`, provisioning
stages 11–12), a Contracts opening (stage 10, already reached), the DOM
node RPC runtime (one endpoint, to be added to the V4 chain-endpoints
artifact), and the per-leg DOM session bindings (derivable via
`DomSessionBindingV1::from_resolved_deployment`). That is bounded glue plus
two provisioning stages. Served RFQ **negotiation** additionally needs the
real `ProductionF6TermsAuthorityV2`, which is the true sub-project.

So the honest state: everything below the settlement bridge is either
composed or bounded glue with no missing authority, **except** the F6 terms
source, which is genuine new cryptographic-authority work and the one place
this round deliberately stops rather than improvise.

## 12. Progress — upstream secret sources closed for every extractable chain (2026-09-01)

Front 2 of the final composition, done before the DOM-child glue by explicit
adjudication of order.

**Solana (built).** `ProductionSolanaPublicSecretSourceV1`
(`production_plan_source.rs`) is the fourth slot of
`ProductionPublicSecretSourceRouterV1`. The counterparty's Claim instruction
is the only path that reveals the scalar on the Solana chain, and the
program persists it in the state PDA it verified on-chain
(`verify_shared_secret`: `t·G_ed = claim_point_ed25519`, processor.rs:336).
Extraction re-reads that account at finalized commitment through the quorum
pool, matches the full escrow identity frozen by the DLEQ-authenticated
setup (settlement, terms, setup id, funder/recipient/refund recipient,
vault, amount, deadline, both stored curve points), and re-verifies the
scalar against **both** DLEQ-certified points via
`revealed_dom_secret_to_xmr_scalar` — a quorum answer cannot substitute a
scalar that satisfies only the ed25519 relation. Status mapping is exact:
`Claimed` extracts; `Refunded` is a conflicting terminal (`Inconsistent`,
never a fallback); pre-terminal and absent (including a post-claim `Close`,
which drains the state PDA) are `Unavailable` — the sealed vault record is
the only recovery, per the plan-source contract. The pure core
(`extract_solana_revealed_secret_v1`) is exercised by adversarial tests:
per-field transplants, every status, flipped-scalar and cross-witness
substitution. `CrossCurveSecret252::public_claim()` was added to
`xmr-dleq-sigma` as the deterministic public image used by those tests.

**Monero (adjudicated: no source, ever).** A CLSAG ring signature hides the
spend scalar; the shared-spend sweep never places the route secret on the
Monero chain, so a Monero-chain exposure is unextractable by construction —
this is cryptography, not a missing implementation. The XMR leg's real
reveal is the DOM adaptor completion, whose source chain is the DOM chain
(`LocalOrigin`) and which the DOM source already serves. The refusal is now
enforced where role plans are authenticated: `authenticate_leg`
(`production_materializer.rs`) refuses any plan that pins
`VerifiedCounterpartyClaim` to a Monero counterparty leg
(`secret_source_is_extractable_v1`), and the router refuses unknown chain
digests as before. EVM, Bitcoin and Solana counterparty claims all carry
the scalar on their own chain and stay admissible.

With this, `MISSING_PRODUCTION_PARTS_V1`'s secret-source entry is closed:
every chain whose reveal exists on-chain has a production extraction
authority, and the one chain whose reveal cannot exist on-chain is refused
at materialization instead of failing somewhere deeper.

## 13. Progress — the settlement runtime composes; NotComposable falls (2026-09-01)

`run_production_v1` now runs the full composition. Two phases, because the
lifecycle forces two phases:

**Phase 1 — service plane (always composable).** Provisioning stages 11-12
complete: the Contracts transport identity store (operator passphrase, state
capability), the durable Relay queue and both per-leg Relay workers over
deterministic domain-separated store identities, and one
`ProductionContractsV1` owner per settlement leg over the sanctioned
fail-closed `UnavailableF6AuthorityV1` (`production_service.rs`).

**Phase 2 — settlement runtime (gated on the negotiated role plan).** Two
structural facts surfaced while mapping this and were adjudicated rather
than improvised:

1. **The role plan is a negotiated artifact, not a derivable one.** Its
   source scopes commit to the exact claim template hashes frozen during
   the Contracts/F7 negotiation, which the wallet-side compositor produces.
   The daemon therefore consumes `role-plan.v1` (role plan + both scopes,
   fixed-length canonical bytes) the way it consumes terms — authenticated
   byte-for-byte against the admitted composition, with the one production
   shape enforced (downstream `LocalOrigin`/`DomRevealsFirst`, upstream
   `VerifiedCounterpartyClaim`/`DomReactsToCounterpartyReveal`)
   (`production_role_plan.rs`). Its authenticated absence is the honest
   pre-negotiation state: `AwaitingNegotiatedRolePlan`, with all
   provisioning complete and a rerun composing fully.
2. **The DOM claim transaction id is a mid-lifecycle store fact.** The V1
   DOM public-secret source pins it at construction, which fits a reopen
   but nothing honest at cold start. `ProductionDomPublicSecretSourceV2`
   replaces the construction pin with a cross-check between two independent
   durable authorities that both exist when extraction is legal: the route
   journal's authenticated exposure and the Contracts Store's own observed
   final-claim record. Before the Store observation exists it is
   `Unavailable`, never permissive.

The composed router carries the DOM source only: the production observer
refuses `SecretExposure` queries by design, so the DOM-face first exposure
is the one live reveal path; the EVM/Bitcoin/Solana extraction authorities
stay ready behind the future chain-specific observer seam.

Assembly (`production_settlement_runtime.rs`): one authenticated node
runtime shared via `Arc` between the DOM child port and the claim consumer;
DOM lease + per-leg one-shot child store authorities bound to the frozen
DOM deadlines; refund arming created/reopened at `refund-arming.v1.sqlite3`
across both DOM faces and both counterparty faces; materialization scope,
DOM child port, completed five-child router, first-exposure authority,
materialization owner; verified plan source over the secret router and
retention vault; base plan authority pinned to the coordinator's plan
authority id behind the V2 time guard (evidence installed at composition);
settlement bridge over the durable coordinator; supervisor over the sole
route store; `ProductionRouteRuntimeV1` driven under the system signal
bridge until terminal or coordinated shutdown.

`NotComposable` survives only as the V3-bootstrap refusal (no
chain-endpoints artifact means no counterparty children — a configuration
shape). `MISSING_PRODUCTION_PARTS_V1` now records COMPOSITION: DONE plus
the named open seams: the real F6 terms authority, the SecretExposure
observer seam, the in-daemon negotiation driver, and the live-fixture
caveat — the composed binary is fail-closed by construction everywhere,
and its full happy path is exercisable only against live fixtures.
