# ADR-F7-LAB-M8: Immutable pre-funding timing policy and post-confirmation anchors

- Status: **LAB CANDIDATE — non-normative**
- Date: 2026-08-13
- Scope: isolated F7 laboratory only
- Normative basis: DOM Interop Annex M v3.3, M.7.2 and M.8
- Implementation: `adapter-btc::timelock`

## Problem

Annex M v3.3 requires all participants to freeze the network, confirmation
policy and timelocks, validate the cross-chain window, arm refunds and only
then authorize funding.  M.8 also requires each native timelock to contain a
real base height or base median-time-past.  A real funding base cannot exist
until the funding transaction has confirmed.

The F7 laboratory additionally requires two explicit phases:

1. policy must be agreed before funding;
2. real funding anchors must be obtained after confirmation and validated
   before any economic claim/adaptor nonce generation or signing.

Mutating frozen settlement terms after funding would violate M.7.2 and would
invalidate signatures, template bindings and the terms hash.  Treating a
planned height as a real anchor would be deceptive and unsafe.

A literal reading that prohibits every nonce and signature until real funding
anchors exist is causally impossible: a real funding anchor depends on a
consensus-valid signed funding transaction, while the DOM funding gate also
requires its safety refund and claim authorization to be persisted before
funding. The laboratory therefore distinguishes prerequisite safety/funding
signatures from post-anchor economic claim/adaptor signatures. This does not
weaken the M.8 claim gate and does not authorize a claim before both real
funding anchors validate.

## Context

The normative Annex defines these M.8 objects:

- `TimelockSpecV1`;
- `TimeIntervalV1`;
- `ChainTimingBoundsV1`;
- `CrossChainWindowV1`;
- `BitcoinFinalityPolicyV1`;
- `validate_cross_chain_window` and its mandatory conservative inequality.

The repository did not implement them.  The Annex does not define canonical
bytes for `policy_digest`, does not define the two-phase state transition and
does not specify how a pre-funding object can contain a future funding base.
Decision D-029 explicitly left M.8 to a later decision.

This ADR fills that engineering gap in the isolated laboratory.  It does not
claim to ratify a wire format, change Annex M, change `SettlementTermsV1`, or
close any governance gate.

## Decision

### 1. Implement the Annex M.8 types literally

The adapter exposes the exact field sets and integer widths written in Annex
M v3.3.  Native units remain distinct.  Direct block-height or native-unit
comparison is forbidden.

Block deadlines normalize from their funding reference as:

```text
earliest = delta_blocks * min_block_seconds
latest   = delta_blocks * max_block_seconds
```

Both operations, and `base_height + delta_blocks`, use checked arithmetic.
The absolute sum is checked even though the normalized interval is relative
to the common funding reference.

A Bitcoin MTP deadline uses the following conservative LAB interval:

```text
units == 0: [0, 0]
sample_uncertainty = 10 * btc.max_block_seconds
units > 0:
  [max(0, units * 512 - sample_uncertainty),
   units * 512 + 511 + sample_uncertainty]
```

The 511 seconds cover BIP68 unit quantization. They do **not** by themselves
cover MTP lag. The additional ten-interval term spans the distance from the
newest timestamp to the oldest timestamp in Bitcoin's 11-header median sample
under the explicitly frozen maximum block-interval assumption. Annex M does
not ratify this exact formula, and Bitcoin consensus alone does not supply a
finite wall-clock lag bound. This is therefore a conservative, fail-closed LAB
model whose validity depends on the agreed `ChainTimingBoundsV1`; a production
profile must ratify its timestamp-drift assumptions explicitly.

The mandatory relation is implemented exactly:

```text
latest(first_refund) + safety_margin_seconds
    <= earliest(second_refund)
```

All arithmetic is checked.  Invalid bounds, a DOM/DOM or Bitcoin/Bitcoin
topology, overflow and an unsafe window fail closed.

Annex M says the margin covers observation, propagation, reaction, reorg and
broadcast but does not publish the arithmetic that derives it.  The lab uses
a deliberately conservative additive floor over every explicit budget:

```text
minimum_margin =
    dom.max_reorg_seconds + dom.observation_seconds + dom.broadcast_seconds
  + btc.max_reorg_seconds + btc.observation_seconds + btc.broadcast_seconds
```

`minimum_safety_margin_seconds` uses checked additions and window validation
rejects a declared margin below this floor.  This arithmetic is a lab decision,
not a claim that Annex M froze the same formula.

### 2. Freeze an additive pre-funding policy

`M8TimingPolicyV1` contains:

- the canonical `SettlementTermsV1` hash as an opaque 32-byte binding;
- native offsets without future anchor values;
- the safety margin;
- explicit DOM and Bitcoin timing bounds;
- every field of `BitcoinFinalityPolicyV1`.

The adapter deliberately accepts the terms hash as opaque bytes.  It does not
depend on `kaystra-core`, preserving the existing core/adapter dependency
boundary.

Canonical lab bytes use fixed field order, explicit enum tags, big-endian
integers, magic `DOMM8P1\0` and version 1.  The policy digest is:

```text
BLAKE2b-256(
    "DOM-INTEROP/M8-TIMING-POLICY/V1\0" || canonical_policy_bytes
)
```

The encoding is additive.  It is not a `DOMBTC` artifact and does not alter an
existing canonical format.  `decode_canonical` is a strict inverse: unknown
magic, version, enum or boolean tags, truncation and trailing bytes fail
closed before the decoded policy is validated.

### 3. Bind real anchors in a separate evidence object

After both funding transactions confirm, the real DOM scanner and Bitcoin
evidence path populate `M8FundingAnchorsV1`.  It contains:

- the frozen terms hash;
- the frozen timing-policy digest;
- DOM funding transaction id, block hash, height and scanner-verified block
  timestamp;
- Bitcoin funding transaction id, block hash, height and median-time-past.

Canonical lab bytes use magic `DOMM8A1\0`, version 1, fixed order and
big-endian integers.  Its strict decoder applies the same magic, version,
truncation and trailing-byte rules.  The evidence digest is:

```text
BLAKE2b-256(
    "DOM-INTEROP/M8-FUNDING-ANCHORS/V1\0" || canonical_anchor_bytes
)
```

Zero transaction or block identifiers are rejected as absent evidence.  A
height or MTP value of zero is not rejected because it is valid on a fresh
regtest chain and its presence is structural rather than sentinel-based.

`bind_and_validate_funding_anchors` verifies terms equality, recomputes and
compares the policy digest, derives the exact normative `TimelockSpecV1`
bases and projects both deadlines to absolute checked timestamp intervals.
It does not reduce the evidence to a scalar common-reference offset:

```text
DOM height lock:
  [dom_block_time + relative.earliest,
   dom_block_time + relative.latest]

Bitcoin block lock:
  bitcoin_anchor =
    [max(0, funding_mtp - 10 * btc.max_block_seconds),
     funding_mtp + 10 * btc.max_block_seconds]
  deadline = bitcoin_anchor + relative block-delay interval

Bitcoin 512-second MTP lock:
  [funding_mtp + relative.earliest,
   funding_mtp + relative.latest]
```

The Bitcoin block-lock anchor interval is necessary because the evidence has
the block's MTP, not its exact wall-clock instant.  The ten-interval term is
the same explicitly frozen LAB bound used for the 11-header median sample.
The lower endpoint saturates at the Unix epoch; upper endpoints and every
addition use checked arithmetic.  An MTP-based lock does not receive that
anchor interval a second time because its normalized relative interval already
contains sample uncertainty and 512-second quantization.

Annex M requires a common temporal reference but does not ratify this exact
anchor-to-wall-clock conversion.  This absolute interval projection is a
non-normative, conservative LAB candidate.  It prevents unequal confirmation
times, or the ambiguity of an MTP-only Bitcoin block anchor, from creating a
false-safe relative-duration comparison. The function returns
`AnchoredCrossChainWindowV1`.  It never mutates the policy.  Nonce/signing
orchestration must require the returned value, not a caller-provided boolean.
The returned fields are private, and the capability implements neither
`Clone` nor `Copy`, so external code cannot construct or duplicate it without
going through validation.

`ClaimRound::prepare_after_m8` is the F7 nonce-generation entry point.  It
requires the validated capability and compares its terms hash to the durable
`BitcoinNoncePermitV1::terms_hash` before touching the vault. It consumes the
capability and durably binds its `anchor_evidence_digest` to the F7 permit and
reservation before touching nonce state. Restart/resume must present the same
digest; stale, mismatched or already-consumed authorization fails closed. Each
signer therefore needs its own independently validated linear capability. The older
`ClaimRound::prepare` API remains available solely to preserve the frozen F5
surface; using it is explicitly ineligible for an F7 gate.

### 4. Freeze the causal F7 lifecycle

The combined runner admits only this order:

```text
PolicyFrozen
  -> RefundsArmed
  -> FundingSigned
  -> FundingBroadcast
  -> BothAnchorsConfirmed
  -> AnchorsValidated
  -> ClaimNonceAuthorized
  -> Claims
```

`RefundsArmed` includes the DOM funding gate's pre-signed recovery path.
`FundingSigned` includes only signatures needed to create the transactions
whose confirmations become the real anchors. Neither phase grants a Bitcoin
claim nonce permit or an economic claim/adaptor signing capability.

`ClaimNonceAuthorized` is unreachable without an
`AnchoredCrossChainWindowV1` minted from verified evidence from both chains.
The capability is linear and the durable BTC reservation records its exact
anchor-evidence digest. A process restart must re-import the same public
prepared-claim continuation and cannot mint a replacement nonce attempt.

## Alternatives considered

### Mutate `SettlementTermsV1` after confirmation

Rejected.  It changes the terms hash after funding, breaks frozen template and
session bindings and contradicts M.7.2.

### Predict funding heights before broadcast

Rejected.  A prediction is not chain evidence and cannot establish the actual
BIP68 or DOM height-lock base.

### Store anchors in opaque `SettlementTermsV1::metadata`

Rejected.  Existing core documentation makes metadata economically
non-authoritative.  Using it for a refund deadline would silently violate the
frozen API contract.

### Reuse `assurance_policy_hash`

Rejected.  That field has USPE assurance semantics and cannot be repurposed as
an M.8 timing-policy digest.

### Add required fields directly to `SettlementTermsV1`

Rejected for the laboratory candidate because it would break the frozen V1
canonical bytes, all existing vectors and every struct-literal caller.  A
future normative `SettlementTermsV2` may make the policy digest a first-class
field after ratification.

### Put real bases in the pre-funding policy

Rejected.  The real base is unknowable until chain confirmation.  A synthetic
base would make the laboratory appear more complete while weakening the
security property being tested.

### Compare native values directly

Rejected by M.8.2.  DOM heights, Bitcoin block CSV and Bitcoin 512-second CSV
are not comparable quantities.

## Invariants

1. Pre-funding policy bytes are immutable once their digest is accepted.
2. Anchor evidence is a separate object and can never mutate policy bytes.
3. Both objects bind the same canonical settlement terms hash.
4. Anchor evidence binds the recomputed policy digest, never an unchecked
   caller assertion.
5. Exactly one refund is DOM-native and one is Bitcoin-native.
6. Every conversion and inequality uses checked integer arithmetic.
7. The first deadline contributes its latest possible instant.
8. The second deadline contributes its earliest possible instant.
9. MTP quantization uncertainty remains inside the normalized MTP interval.
10. MTP sample lag is modeled separately from 512-second quantization and is
    bounded only by the explicitly agreed LAB timing profile.
11. Both deadlines are absolute checked timestamp intervals; neither base is
    validated and then discarded or collapsed to a scalar offset.
12. A Bitcoin block-lock funding instant is conservatively bracketed around
    its MTP by the frozen 11-header sample bound. A Bitcoin MTP lock counts
    that uncertainty exactly once.
13. The safety margin is at least the checked sum of both chains' explicit
    reorg, observation and broadcast budgets.
14. All Bitcoin finality fields are explicit and digest-committed.
    `minimum_confirmations` and `maximum_reorg_depth` must each be nonzero but
    remain independent; Annex M does not require one to be at least the other.
15. No adapter chooses a network or finality value by default.
16. No economic claim/adaptor nonce or signing phase may begin without a
    validated, unconsumed anchored-window capability.
17. The exact anchor-evidence digest survives restart in the F7 permit and
    reservation; stale or different evidence cannot resume that authority.
18. A deep reorg remains an explicit security/reconciliation event; it is not
    modeled as impossible.
19. Pre-funding safety/funding signing can create the funding transactions, but
    it grants no economic claim authority.
20. Claim/adaptor nonce reservation is impossible before both real anchors
    validate.

## Compatibility impact

This decision is additive inside `adapter-btc`:

- the existing `BitcoinCsvDelayV1`, `encode_csv` and script-number APIs are
  preserved;
- the existing F5 `ClaimRound::prepare` API is preserved, while F7 receives an
  additive gated entry point;
- `SettlementTermsV1` and its canonical vectors are unchanged;
- existing `DOMBTC` encodings are unchanged;
- no consensus, Bitcoin transaction or DOM wire rule changes;
- the only extension to an existing public type is new fail-closed variants in
  `timelock::TimelockError`.

The policy and anchor encodings are lab candidates.  External implementations
must not treat them as ratified until a normative decision assigns them a
canonical registry/version and integrates the policy digest into settlement
terms.

## Security impact

The two-phase split removes pressure to fabricate future chain state and
prevents post-funding mutation of signed terms.  Domain-separated canonical
digests prevent an anchor artifact from being substituted for a policy or
replayed under different settlement terms.  Checked normalization prevents
wraparound from turning an unsafe window into a safe one.  Requiring concrete
transaction and block identifiers prevents an empty placeholder from arming
signing.

Separating prerequisite signatures from economic claim signatures resolves
the anchor causality without permitting an early claim. A blanket all-nonce
gate would make the protocol unexecutable; weakening the post-anchor claim
gate would expose value before the cross-chain window is proven. The selected
state machine preserves both executable funding and fail-closed claim safety.

This model does not itself prove that an anchor came from a real chain.  That
proof belongs to the real DOM scanner and Bitcoin header/inclusion/witness
verification boundary.  The F7 harness must construct the anchor object only
from those verified outputs.

## Tests proving the decision

`crates/adapters/btc/tests/m8_timing.rs` covers:

- exact DOM and Bitcoin block normalization;
- safe windows in both DOM-first and Bitcoin-first orderings;
- the complete 512-second MTP quantization interval;
- equality at the M.8 boundary and one-second unsafe rejection;
- checked derivation and enforcement of the explicit safety-margin floor;
- invalid bounds and same-chain topology rejection;
- base, multiplication and safety-margin overflow rejection;
- finality consistency and digest commitment of every finality field;
- frozen policy prefix, version, length and digest vector;
- two-phase derivation of real bases without policy mutation;
- terms, policy-digest and missing-evidence rejection;
- canonical anchor prefix, version, length and evidence digest;
- strict round-trip decoding plus rejection of every truncated length,
  unknown tags and trailing bytes;
- evidence-digest sensitivity to every anchor field;
- absolute-anchor rejection of relative false-safe windows in both leg
  orderings;
- single-counting of MTP sample uncertainty at an exact equality boundary;
- epoch-floor behavior for a Bitcoin block anchor and checked absolute DOM and
  Bitcoin anchor overflow;
- a complete two-party signing round through the M.8-gated nonce entry point;
- rejection of a cross-session terms mismatch before any vault reservation;
- property tests for normalization, inequality equivalence and digest
  sensitivity.

The pre-existing CSV unit tests continue to prove that block and MTP nSequence
encodings remain distinct and never set the disable flag.

## Required normative follow-up

Before this candidate can become an external interoperability contract, a
ratified decision must:

1. assign canonical ownership and registry status to `DOMM8P1` and `DOMM8A1`,
   or replace them with approved formats;
2. add an authoritative M.8 policy digest to a new settlement-terms version;
3. define the exact scanner/evidence types that populate each anchor;
4. require the anchored-window capability at the nonce/signing API boundary;
5. publish cross-language byte/digest vectors;
6. define how anchor invalidation and reconstruction behave across shallow and
   deep reorgs.

Until then, this implementation is complete laboratory engineering evidence,
not a claim that the normative G-F7 gate is closed.
