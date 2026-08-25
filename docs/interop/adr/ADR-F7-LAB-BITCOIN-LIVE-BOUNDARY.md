# ADR-F7-LAB — Prebroadcast Bitcoin funding and canonical RPC evidence

Status: laboratory implementation checkpoint

## Context

The existing F5 real-regtest test funds the P2TR contract with
`sendtoaddress`. That RPC selects wallet UTXOs, signs, and broadcasts in one
operation. F7 cannot use that ordering: both participants must have an exact,
restartable refund before funding can become visible on Bitcoin.

The existing `btc-evidence` crate verifies an already assembled transaction,
Merkle branch, header, and witness outcome. The F7 M.8 authority separately
requires the full funding block, one header per height from genesis to the
funding parent, and all successor confirmation headers. Neither component owns
a concrete Bitcoin Core RPC collector.

## Decision

`crates/adapters/btc-live` is the sole concrete boundary for these missing
operations.

Funding uses a loaded real Bitcoin Core wallet and calls, in order,
`walletcreatefundedpsbt`, `walletprocesspsbt`, and `finalizepsbt`. Core selects
and signs real UTXOs while `lockUnspents=true` prevents wallet reuse. BTC output
amounts cross JSON-RPC as fixed eight-decimal strings, a representation Bitcoin
Core accepts without first converting satoshis through a binary float. The
exact transaction, selected outpoints, route binding, network identity, P2TR
output, refund script/control block, and every ordered refund output
amount/script are authenticated and durably published in an owner-only route
store. No preparation or arming method can call `sendrawtransaction`.

The prepared capability exposes only the funding outpoint data needed by the
refund signer. Arming accepts exact signed refund bytes and independently
checks all of the following before durable publication:

- one input spends the prepared funding output;
- version, locktime, and BIP68 sequence match the frozen policy;
- the tapscript is the canonical CSV/refund-key program;
- the single-leaf control block commits that script to the funded P2TR output;
- the three-item witness carries the exact script and control block;
- the BIP340 signature verifies under `SIGHASH_DEFAULT` and the frozen refund
key;
- every refund output equals the frozen ordered amount/script tuple; their
  positive sum is strictly below the funded amount.

Arming also reopens the authenticated prepared record from the same locked
route store and requires exact record/digest equality before it may publish a
refund. A prepared handle therefore cannot create an orphan refund stage in a
different route store.

Only the non-forgeable armed capability reaches the explicitly named
`broadcast_armed_funding` method. ACK-loss recovery is accepted only when
Bitcoin Core returns byte-identical raw transaction bytes for the exact txid.
The broadcast receipt is then persisted idempotently. A later explicit submit
does not trust the historical receipt as proof of current mempool/chain
presence: it resubmits the same private bytes, accepting an already-known error
only after the exact-byte lookup. The armed capability may return the already
authenticated signed refund bytes for the later CSV terminal; it never returns
the prebroadcast funding bytes. On restart, an armed store with no receipt
first checks both the node and wallet views for the exact raw funding bytes. A
byte-identical hit durably reconstructs the receipt; otherwise the
implementation must still prove the selected inputs unspent and relock them.
This closes the crash window after node acceptance but before receipt
publication without treating an unavailable or contradictory lookup as
success.

The evidence collector binds to the same concrete, cookie-authenticated node.
It takes a stable best-tip snapshot, fetches the exact witness transaction and
full containing block, derives the txid Merkle branch locally, walks and
validates the complete proof-of-work header chain from genesis through the
snapshot tip, and rejects a tip change. The immutable result exposes the full
block/ancestry/confirmation slices expected by M.8 and can construct the
existing `KeystoneBitcoinEvidenceV1` without allowing callers to mutate chain
facts.

Chain identity is not inferred from the RPC chain-name string alone. Regtest
pins its canonical genesis. Public and custom Signet share the canonical
Signet genesis, so the client also validates the exact `signet_challenge`
reported by `getblockchaininfo`: the public challenge is compiled into this
boundary, while a nonempty, bounded, non-public custom challenge must be
operator-pinned in configuration. A custom Signet therefore cannot be
misclassified as Public Signet merely because both report `chain=signet`.
The challenge is retained in the canonical evidence codec so restart does not
erase that network identity. Canonical decoding also requires an independently
retained expected network/genesis/custom challenge; a custom-Signet blob cannot
self-assert the challenge against which it is accepted.

## Credential and filesystem authority

RPC is loopback HTTP only. Userinfo, redirects, query strings, and remote hosts
are rejected. The Bitcoin Core cookie is never supplied in an argument,
environment variable, public field, codec, log, or debug output. Its absolute
path and owner-only parent are fixed at connection; every call reopens the
possibly rotated cookie with no-follow semantics and revalidates effective
owner, mode `0600`, single link, inode, and a small content bound.

Each route store has a canonical absolute path below an existing owner-only
`0700` parent. The store itself and its retained lock are `0700`/`0600`, owned
by the effective user, non-symlinked, and single-link where applicable. A
random owner-only authentication key protects fixed-kind prepared, refund, and
broadcast records. Staging records are fsync'd, renamed without replacement,
and followed by directory fsync. A valid staging-only crash prefix is promoted
on reopen; an incomplete unpublished prefix may be discarded and rebuilt.
Existing objects with unsafe metadata are rejected without permission repair.

## Alternatives rejected

- `sendtoaddress`: it broadcasts before refund durability.
- shelling out to `bitcoin-cli`: credentials and exact structured errors would
  cross a process boundary, and tests could accidentally treat textual output
  as authority.
- a public RPC trait with mock implementations: production code could then
  mint a false success path. The adapter uses one concrete client; unit tests
  cover codecs and validation only, while the final route must use the real
  node.
- caller-supplied Merkle/header objects: this preserves the old assembly gap
  and permits internally inconsistent evidence.
- exposing raw prebroadcast funding bytes: that would let a caller bypass the
  refund gate through another broadcaster.

## Compatibility and proof obligations

This change is additive and introduces one workspace member. It does not
change DOM, Contracts, Wallet, `dom-leg`, or existing Bitcoin verifier APIs.
The final runner may consume only the opaque prepared/armed handles and the
immutable canonical evidence object.

The focused gate must prove strict codecs, route/stage substitution rejection,
tamper detection, owner-only/no-repair behavior, staging restart promotion,
real-wallet PSBT preparation without mempool exposure, signed refund arming
before explicit submit, ACK-loss idempotence, stable canonical ancestry and
confirmation collection, and consumption by both `btc-evidence` and the M.8
authority. No component test or preflight alone may report G-F7 success.
