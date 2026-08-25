# DRAFT — Protocol fee model (NOT RATIFIED)

Status: **DRAFT — awaiting operator ratification.** A minute prepared for the
operator (Soren Planck, sole ratification authority). Every rate is filled in
and implemented, but the decision is not yet a numbered entry in the registry,
so nothing here is settled. Only the treasury address remains open.

Supersedes the two earlier drafts of this file. The first left open who pays
the fee; the second proposed a percentage split 80/20 between the miner and
the treasury, which **would have broken the DOM's confidentiality** — see the
finding below. Both are retained here as the reasoning that produced the
current shape.

## The two problems this minute had to solve

### Problem 1 — the user does not hold DOM

The fee is denominated in DOM, but a user arriving with BTC to swap for USDT
holds none. Making him acquire DOM first kills conversion; charging in the
traded asset and converting to DOM needs an exchange rate, which needs an
oracle — a trusted third party the protocol exists to eliminate, and an
administered price colliding with I2 (anti-power). Before a market exists
there is also no rate to read.

**Resolved: the solver pays the fee and prices it into its quote.** The solver
already quotes a price, and that price is discovered by competition among
solvers, which is exactly what the ratified RFQ design (F6) produces. The user
pays in the asset being traded and never needs to hold DOM. No exchange rate,
oracle or administered price appears anywhere.

This also produces the stronger token model. Demand becomes **operational and
recurring** — every solver must hold and spend DOM continuously to stay in
business, scaling with volume — rather than one-off retail purchases made
under friction. A solver may mine the DOM it spends, so the model functions
before any market exists and organic price discovery begins from that activity
rather than from anyone declaring a value.

### Problem 2 — a percentage fee paid as `kernel.fee` leaks the confidential amount

RFC-0008 makes the kernel fee **explicit and public**: the balance equation is
`Σv_out + fee = Σv_in`, and the coinbase enforces
`explicit_value == block_reward + sum(tx_fees_in_block)`. It has to be public,
because that is how a miner knows what it is being paid.

Combine that with a percentage of the DOM leg amount and the confidentiality
collapses by division:

```
public_fee = 0.0005 × confidential_amount
→  confidential_amount = public_fee × 2000
```

Anyone can perform that division. **A percentage fee published as `kernel.fee`
destroys DOM indistinguishability** (I8), which is the product's central
property. This is arithmetic, not an implementation limit.

The tension is structural: the miner's share must be a public `kernel.fee`,
and a percentage of a hidden value cannot be published without revealing it.
**A percentage fee and an 80/20 miner split cannot coexist in the same fee.**

**Resolved by separating the two components by what each one can safely be:**

- the **treasury** share is the percentage, paid as a **confidential DOM
  output** — hidden like any other DOM output, so nothing leaks;
- the **miner** share is a **fixed** minimum `kernel.fee` — public, but a
  constant reveals nothing about the amount.

The percentage scaling the operator wants is preserved, confidentiality is
preserved, and the miner is still paid in DOM through the existing consensus
mechanism.

## Proposed decision (verbatim once ratified)

```
D-0xx  <date>  PROPOSED (operator order, recorded in chat)
  Question:      the interoperability protocol's fee model — whether a fee
                 is charged, in which asset, who pays it, how it scales and
                 how it is distributed.
  Decision:      every operation settled through the DOM is subject to a
                 MANDATORY protocol fee. Because the DOM is the settlement
                 point (topology §1.2, P.3 item 3), every route crosses the
                 DOM leg, so the fee is levied there and no route avoids it.

                 The fee is PAID BY THE SOLVER, which prices it into the
                 quote it offers. The user pays in the asset being traded
                 and is never required to hold DOM. No exchange rate,
                 oracle or administered price is used anywhere: the quote
                 competition of the ratified RFQ design performs the
                 pricing.

                 The fee has TWO components, separated so that neither
                 leaks a confidential value:

                 (a) TREASURY SHARE — a percentage of the DOM leg amount,
                     paid as a CONFIDENTIAL DOM output to a designated
                     protocol wallet [TREASURY_ADDRESS — to be fixed]:
                       simple route   (DOM <-> X)      0.05%
                       composed route (X -> DOM -> Y)  0.10%
                     Charged ONCE PER ROUTE, not per settlement, so a
                     composed route pays 0.10% once rather than 0.05%
                     twice.

                 (b) MINER SHARE — a FIXED `kernel.fee` per settlement of
                     0.01 DOM (1_000_000 noms), credited
                     to the block miner by the existing consensus rule
                     (RFC-0008: coinbase_kernel.explicit_value =
                     block_reward(h) + sum(tx_fees_in_block)).

                 A settlement whose fee is below either floor is refused
                 (`FeeBelowFloor`), in addition to the existing ceiling
                 check (`FeeAboveLimit`).

                 The percentages and the fixed miner amount are a VERSIONED
                 POLICY, not an administrative lever: changing them
                 requires a new ratified decision and a new
                 `policy_version`, which participants adopt explicitly.
                 There is no runtime knob and no key that alters them,
                 preserving I2.
  Rejected:      an 80/20 percentage split between miner and treasury (the
                 miner's share must be a public kernel.fee, and a published
                 percentage of a confidential amount reveals that amount by
                 division, breaking I8); a percentage enforced at the
                 consensus layer (same leak); charging the user in the
                 traded asset with conversion to DOM (needs an oracle, a
                 trusted third party, and an administered price colliding
                 with I2); requiring the end user to hold DOM (kills
                 conversion for a user arriving with BTC or USDT); a fixed
                 fee with no percentage (does not scale, and becomes
                 prohibitive if DOM appreciates); size-bucketed fixed tiers
                 (leaks the order of magnitude of a confidential amount);
                 an optional or zero fee (the current code permits
                 total_fee = 0, which this decision overrides).
  Consensus:     NONE. Both components are built into the settlement
                 transaction — a kernel.fee and an ordinary confidential
                 output. The DOM base chain, DOM Wallet and dom-contracts
                 are untouched, per P.3 items 2 and 6.
  Components:    crates/rfq/src/selection.rs (the floor checks and the
                 two-component admissibility), the settlement terms
                 builder, the wallet swap tab (fee disclosure), and this
                 document's §12.1 registry on ratification.
```

## Why the rates are 0.05% and 0.10%

Calibrated against the market the product competes with. Efficient bridges
charge roughly **0.05%–0.15%** in protocol fees today (Across 0.05–0.15%,
Stargate 0.06% LP fee), and liquidity-pool bridges scale with size.

Three considerations set the DOM rate at the bottom of that band rather than
the top:

1. **The user compares total cost.** What he pays is the protocol fee plus the
   solver's spread plus gas on both chains. A protocol fee at the top of the
   band leaves the solver no room to compete inside it.
2. **An atomic swap needs roughly twice the on-chain transactions of a
   bridge** — lock and claim on each leg, against deposit and delivery. That
   structural gas cost consumes part of the advantage before any fee is
   charged, and is why L2 support matters rather than being a convenience.
3. **Raising a fee later is easy; lowering it is not.** Starting tight is the
   safer direction.

The composed rate is double the simple rate because a composed route is two
chained settlements — literally twice the work — but it is charged once per
route so the user compares one number against one bridge quote.

## Enforceable above consensus

The miner's share needs no new mechanism: DOM declared as `kernel.fee` already
flows to the block miner through the coinbase offset RFC-0008 makes
consensus-critical. The treasury's share is an ordinary confidential DOM
output. The interop protocol's only job is to **refuse** a settlement that does
not carry both, which lives in the RFQ admissibility check and the terms
builder — this project's own code.

## The honest limits of enforcement

Two, both consequences of the design rather than defects:

**No public audit of fee compliance.** Because the treasury share is a
confidential output and the DOM leg amount is confidential, no outside party
can verify that the correct percentage was paid. Only the two parties see it.
That is the price of privacy, and it is coherent with what the DOM is — but it
should be stated rather than discovered later.

**No consensus-level enforcement.** Both parties' software refuses terms that
do not carry the fee, and the solver's bond gives a second deterrent, but
someone running a modified client could omit it. Enforcing at consensus would
require changing the DOM, which P.3 item 6 forbids.

## Disclosure in the wallet

The fee sits inside the solver's quote, so the user sees one number. Because
the schedule is a **known policy constant**, the app can display "protocol
fee: 0.05% (included)" without that figure travelling inside the quote — no
wire change, and the ratified consolidated `total_fee` (AD-1.2 / D-020) is
untouched.

## The miner constant, and why 0.01 DOM

**MINER_FIXED = 0.01 DOM (1_000_000 noms).** The DOM's coin unit is
100_000_000 noms and the current block reward is 33 DOM, so this is about
**0.03% of a block** — clearly above the ordinary cost of a transaction, so it
is a real incentive to include swap settlements, and far below the reward, so
it does not distort block economics.

It **must stay constant**. Any dependence on the amount — a percentage, or
size buckets — reintroduces the leak, exactly or as an order of magnitude.
The implementation enforces equality rather than a floor for exactly this
reason: a kernel fee that varies between settlements is itself the leak.

Being fixed in DOM, it weighs proportionally more on a small swap if DOM
appreciates. That is a parameter, not a trap: it moves by a new ratified
policy version like the rates.

## The remaining open parameter

**TREASURY_ADDRESS** — the DOM wallet receiving the treasury share. May be
deferred: the floors and the split are implemented against a configurable
address in the meantime.

## Implementation status

`crates/rfq/src/fee_policy.rs` implements this schedule, **marked NOT RATIFIED
in the module itself**. Thirteen unit tests cover the rates, the ceiling
rounding, both refusals, and — as an explicit test — the confidentiality
property: two settlements of very different sizes publish the *same* miner
fee, so the public value distinguishes nothing. `cargo clippy -p rfq
--all-targets -- -D warnings` and `cargo fmt` are clean, and the crate's
existing 32 tests still pass.

## What this draft does not decide

Whether the treasury's share is held, spent or burned. That is a separate
economic decision and is deliberately left to the operator.

---

## Addendum (2026-08-22) — treasury receiving mechanism decided

**SUPERSEDED — see `ADR-DOM-PROTOCOL-FEE-MODEL-ACTF-ERRATA.md`. The separate pay-as-you-go mechanism described below is replaced in full by ACTF v1.1.**

The open TREASURY_ADDRESS question is resolved by coordinator decision:
MW has no addresses, so the treasury receives through an online LISTENER
that co-creates the fee output (ephemeral blinding, ECDH-encrypted to an
offline cold wallet, zeroized), paid PAY-AS-YOU-GO per operation by the
solver in a separate DOM transaction (optional 30-120s mini-batch),
never in the swap's atomic path. Receipts (two-stage: mempool-seen /
confirmed, listing covered terms_hashes + amount, BIP340-signed) feed
the intent-book merit system: no receipt and no provable refund means
solver_active = false. Full specification, enforcement analysis and
implementation hygienes: laboratory/design/INTENT_BOOK_DESIGN.md
("O tesouro"). TREASURY_ADDRESS is replaced by
TREASURY_LISTENER_ENDPOINT + TREASURY_COLD_PUBKEY +
TREASURY_RECEIPT_PUBKEY, all fixed at final ratification.
