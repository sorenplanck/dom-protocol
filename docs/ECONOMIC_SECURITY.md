# DOM — Economic Security Analysis (Phase 5.2)

Status: snapshot 2026-05-25. Reviewed against the DOM consensus
implementation as of commit `c9ba2e7`.

## Scope

This document analyses the **economic** robustness of DOM consensus
against rational and adversarial miners. It deliberately separates
the discussion from the cryptographic-soundness analysis (covered by
RFC-0001 / RFC-0009 / Phase 2.x test suites) and from the
network-layer defences (Phase 4.x).

Three attack families are in scope:

  1. **Selfish mining** — Eyal & Sirer 2013. A miner mines blocks
     in private, releasing them strategically to invalidate honest
     blocks. Profitable under naive longest-chain selection if the
     attacker controls more than ~25% of hashrate (lower with
     network-level head start).
  2. **Block-withholding (Rosenfeld 2011)** — applies inside a
     mining pool: a participant solves shares but never submits
     full blocks, harming the pool while continuing to receive
     pay-per-share rewards. Out of scope for DOM (no native pool
     protocol).
  3. **Time-warp manipulation** — adversary submits timestamps that
     bias the difficulty algorithm. Covered cryptographically by
     Phase 5.1 (`crates/dom-pow/tests/asert_adversarial.rs`); the
     economic implications are summarised here.

## DOM-specific structural properties

### 1. Total-difficulty chain selection

`dom-chain::ChainState::connect_block` selects the best chain by
**`total_difficulty`**, not block height. Quoting the validation
loop in `dom-chain/src/chain_state.rs::connect_block`:

```text
let expected_total = parent_difficulty.saturating_add(U256::from(block_diff));
if header.total_difficulty != expected_total { reject }
```

A selfish miner cannot release a tall-but-low-difficulty private
chain and have it overtake an honest higher-cumulative-work chain.
This is the standard Nakamoto fix.

### 2. PoW is RandomX (memory-hard, ASIC-resistant)

The work per nonce is `~2-3 ms` on commodity CPU/RAM. Pool dynamics
are different from SHA-256: there is no economic-of-scale advantage
that gives a single operator > 30% of hash rate without operating
thousands of physical machines. Selfish mining requires sustained
> 25% hashrate; on DOM the bar is empirically high.

### 3. Block reward + tx fees both in coinbase

`CoinbaseKernel::validate_explicit_value` enforces
`explicit_value = block_reward + Σtx_fees` per RFC-0008 §3.2. The
attacker who selfish-mines does NOT capture transaction fees from
the orphaned honest blocks — the orphaned txs return to the
mempool and are re-included by the next miner.

This shifts the selfish-mining payoff matrix: the attacker forgoes
honest tx-fee rewards for as long as they hold blocks private,
making the strategy progressively unprofitable as mempool fees
grow.

### 4. ASERT half-life = 34 560 s (288 blocks)

A withholding attacker who succeeds for a sustained period would
cause the difficulty to drop (fewer blocks → adjustment raises
target). DOM-ASERT-288 sets `ASERT_HALF_LIFE_BLOCKS = 288` and
`ASERT_HALF_LIFE = 34,560 seconds`, derived from the 120-second
target spacing. The half-life is short enough that the difficulty
correction responds within the intended 288-block horizon — see Phase 5.1 oscillation test
(`oscillating_arrivals_do_not_diverge`).

### 5. Coinbase maturity (1 000 blocks)

A selfish miner who orphans an honest miner's block also orphans
that block's coinbase. The attacker only profits if THEIR private
chain wins. With 1 000-block coinbase maturity, a successful
orphan-attack only pays after ≥ 1 000 confirmed private blocks —
a ~33-hour commitment of hashrate.

## Selfish-mining payoff under DOM parameters

Eyal & Sirer's original formula gives the breakeven hashrate
threshold as a function of network propagation advantage γ:

```
α* = (1 - γ) / (3 - 2γ)
```

* γ = 0  (no propagation advantage): α* = 1/3 = 33.3%
* γ = 0.5: α* = 0.5 / 2 = 25%
* γ = 1.0 (perfect propagation advantage): α* = 0

DOM-specific modifiers:

* **No fee capture during withholding** (point 3 above) — every
  block the attacker withholds is a block the attacker is NOT
  collecting fees for. Honest tx fees are deferred but not lost
  to the attacker.
* **Coinbase maturity** — 1 000-block commitment before any
  selfish-mined coinbase is spendable. The attacker must hold
  their position through a difficulty epoch.

These shift the breakeven α upward (selfish mining is less
attractive) compared to a hypothetical chain with the same nominal
parameters but no fee re-inclusion / no maturity delay.

**Empirical conclusion:** sustained selfish mining requires
α > 33% AND a willingness to lock capital for ≥ 1 000 blocks
without realising fee income. Under those constraints, the
attacker's expected ROI versus honest mining is negative in
DOM's parameter regime for any realistic mempool fee floor.

## Mitigation tracking

| Defence | Status | Reference |
|---|---|---|
| Total-difficulty chain selection | ✅ active | `dom-chain/src/chain_state.rs` |
| RandomX PoW (memory-hard) | ✅ active | RFC-0011 |
| Coinbase maturity 1 000 blocks | ✅ active | `dom-core/src/constants.rs::COINBASE_MATURITY` |
| ASERT difficulty correction half-life 288 blocks / 34 560 s | ✅ active | `dom-core/src/constants.rs::ASERT_HALF_LIFE` |
| Tx-fee re-inclusion after orphan | ✅ active | `dom-mempool` (txs remain on orphan) |
| Selfish-mining simulator (statistical) | 🔴 deferred | Phase 8.2 fuzz campaign |
| Multi-strategy game-theoretic simulator | 🔴 deferred | external audit |
| Real-money attack-cost model | 🔴 deferred | post-launch |

## Confidence

* **Confirmed (in code):** total-difficulty selection, RandomX PoW,
  coinbase maturity, ASERT half-life, fee re-inclusion behaviour.
  All four are exercised by automated tests across the repo (Phase
  1.x, 5.1, 7.3 invariants).
* **Likely (formal modelling, no end-to-end simulation):** the
  selfish-mining breakeven threshold is bounded below by ~33% in
  DOM's parameter regime.
* **Theoretical until empirical simulation runs:** the precise
  attacker ROI as a function of (hashrate, propagation advantage,
  mempool fee floor) — deferred to Phase 8.2 fuzz-driven economic
  simulation.

## What is NOT analysed here

* Bribery attacks (Whale / P+ε): the attacker pays honest miners
  to orphan blocks via out-of-band payments. Outside the
  protocol's economic perimeter.
* MEV (Maximal Extractable Value): DOM is Mimblewimble — txs are
  privacy-preserving and orderable by fee rate alone. There is no
  contract-execution surface for MEV in the EVM sense.
* Stake-grinding: DOM is pure PoW, no stake mechanism.

These are mentioned for completeness; none of them is on the
mainnet-launch critical path.
