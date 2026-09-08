# ADR-F7-001: Scriptless Scanner and Canonical Transaction Lifecycle

Status: LAB candidate for F7 external conformance  
Date: 2026-08-13  
Scope: additive node, RPC, wallet-core API, and `dom-adaptor` surfaces only

## Problem

The existing wallet scanner flattens inputs, outputs, and kernel metadata. It
does not expose the final 65-byte kernel signature or preserve transaction
boundaries. A Scriptless monitor therefore cannot prove which canonical
transaction spent the shared output or extract the adaptor secret from the
confirmed claim signature.

The existing DOM transaction builder also requires complete output blindings.
That is correct for ordinary single-wallet outputs but cannot assemble an
output whose blinding is additively shared and never reconstructed. Scriptless
funding, claim, and refund need a public assembly boundary that accepts an
already verified collaborative output and uses the existing DOM transaction,
codec, signing, and consensus validators unchanged.

## Context and Authority

This decision implements the DOM Scriptless Contracts Master Specification:

- section 7: exact funding, claim, and refund templates; refund before funding;
  ordinary `HEIGHT_LOCKED` refund; ordinary adaptor claim;
- section 10: persist exact transaction bytes and retransmit them
  byte-identically after restart;
- section 11: reversible canonical-chain projection indexed locally by shared
  commitment, transaction id, kernel excess, input/output relationship, and
  refund height.

It also supplies the real builder/RPC/scanner prerequisites required by the
DOM Interop Foundation Document v0.18 section 7 (F7). No decision here changes
consensus, the transaction wire codec, block encoding, genesis, mempool rules,
kernel features, challenge construction, Bulletproofs, Schnorr, or adaptor
cryptography.

## Decision

### Authenticated scanner V1

The existing bearer-authenticated RPC router exposes:

```text
GET /chain/scan/scriptless/v1?from=H0&to=H1
```

Optional identity assertions are `expected_network_magic` and
`expected_chain_id`. A request beginning above height zero must include
`anchor_hash`, the canonical identifier at `from - 1`. The node validates the
anchor and projects the complete page while holding one non-blocking chain
lock. The request fails with a retriable service-unavailable result when that
lock is busy.

The response is schema version 1 and contains:

- network, network magic, chain id, genesis hash, protocol version, range-proof
  serialization version, coinbase maturity, and the snapshot tip;
- contiguous blocks with canonical header bytes, block id, previous block id,
  timestamp, and protocol versions;
- coinbase output proof envelope, offset, all kernel fields, and signature;
- non-coinbase transactions in canonical block order with exact canonical
  bytes, `BLAKE2b-256(bytes)` transaction id, canonical location, offset,
  ordered inputs, ordered outputs, and every kernel field including the exact
  65-byte excess signature;
- a continuation carrying the last returned block as the next request anchor.

Pages are bounded to 64 blocks and approximately 8 MiB. A canonical height
whose body is missing is a hard canonical-gap error. The scanner never silently
omits a height and never accepts selective commitment filters on this endpoint.

### Transaction lifecycle V1

`dom-adaptor` exposes additive lifecycle types:

- `VerifiedSharedOutputV1` accepts the opaque collaborative proof and shared
  commitment, calls the unchanged DOM range-proof verifier, and freezes the
  exact output proof envelope;
- `ScriptlessTransactionTemplateV1` assembles one-kernel funding, claim, or
  refund templates using canonical `Transaction` fields;
- `VerifiedScriptlessTransactionV1` is created for claim/refund only after the
  complete DOM transaction validator accepts the signed transaction and
  canonical serialization round-trips byte-identically;
- `VerifiedFundingTransactionV1` is the restricted funding result: it exposes
  verification and public identifiers, but neither transaction nor bytes.

The pre-existing `FundingAuthorizationV1` remains a pure state-model witness
and is not accepted by the real funding finalizer. The unsigned funding
template first asks the statically selected Contracts Store to issue an
`OperationalFundingAuthorizationV1`. The one-shot token binds chain, session,
ready-to-fund transcript, exact terms, shared commitment `C`, complete BP
statement hash, exact unsigned funding and claim templates, persisted refund,
verified claim pre-signature, bilateral backup receipt, immutable
issuance-record digest, and durable session revision. The authorization entry
also presents the complete canonical BP statement to the Store and rejects a
different chain, session, or aggregate commitment before issuance. The Store
must prove funding creates `C` exactly once, claim and refund each spend `C`,
the BP statement aggregates the backed ordered `R_i` points to `C`, and the
claim pre-signature binds the exact claim template. Only then can the funding
signature be installed.

If the process crashes after that immutable issuance but before funding is
signed, `resume_funding_authorization_v1` asks the same Store to authenticate
and import that exact issuance again. Resume must return the same record digest
and authorized revision, may not allocate a new issuance or advance state, and
fails once the signed funding successor has consumed the issuance. This closes
the process-local-token loss window without weakening the one durable issuance
invariant.

After full DOM verification, the restricted funding result must be consumed by
an `OperationalFundingTransactionSinkV1`. Only its one-shot persistence
capability exposes exact bytes to the selected Store. The Store revalidates the
binding, atomically persists/fsyncs byte-identical signed funding, and consumes
the issuance record before returning its own broadcast authority. This removes
the cycle in which funding was already fully signed before durable operational
authority existed.

Claim has no plain-signature finalizer: it calls
`AdaptorPreSignatureV1::adapt`, which verifies the pre-signature, `T = tG`, and
the resulting ordinary DOM signature. Refund requires the existing
`HEIGHT_LOCKED` feature, a nonzero absolute height later than the funding tip,
and a final signature accepted by consensus at the unlock height.

V1 deliberately supports one kernel per lifecycle transaction. This matches
the existing ordinary `SpendBuilder`, the Master local index's singular kernel
excess, and the frozen Scriptless template/signing model. A future multi-kernel
profile requires a new version because it changes nonce/session binding and
monitor selection rules.

### Local funding signing-share composition

Funding adds the participant's shared-output blinding contribution to that
same participant's ordinary wallet excess contribution from reserved inputs,
change, and its offset allocation. `compose_local_funding_signing_share_v1`
performs exactly `x_i = r_i + e_i mod n` through the existing constant-time
`dom-crypto` scalar authority. Both source shares are borrowed and remain
opaque; the returned `SigningShareV1` is zeroizing and has no byte export.

The API is intentionally funding- and participant-local rather than a generic
aggregate-blinding operation. Passing another participant's share would
contradict the Master invariant that no party reconstructs `r_A + r_B` and is
outside this API's contract. A zero local sum is rejected.

Claim/refund use the corresponding authority-side subtraction
`y_i = e_i - r_i mod n`, where the wallet payout contribution is
`e_i = sum(payout blindings_i) - offset_i`. The shared-output share remains
opaque. Per-participant transaction offset contributions are aggregated by the
pinned scalar authority; each contribution must be canonical/nonzero while the
aggregate may validly be zero, matching the consensus `Transaction::offset`.
Before a transaction template exists, the durable share capability exposes only
the corresponding public previews `X_i = R_i + E_i` and `Y_i = E_i - R_i`
through pinned DOM point arithmetic. Those calls do not construct, expose, or
consume a signing share. The opaque scalar composition occurs only after the
wallet has durably bound the exact template and checked its ordered point set.

### Crash-durable collaborative secret custody

The shared-output blinding `r_i` is generated from the OS CSPRNG and sealed in
the statically selected encrypted Store before `R_i` or a decoy commitment can
be released. This is necessarily a two-stage binding: the Master derives each
deterministic decoy contribution from `r_i`, while the later §4.2 share PoK
binds the bilateral capsule hash. Requiring that hash before generating `r_i`
would be circular.

The provisional binding therefore fixes chain, session, complete ordered
roster, participant identity/role/index, terms, and `R_i`, but exposes only a
restricted decoy-contribution capability after authenticated primary and
independent backup roundtrips. Once commit/reveal yields the exact canonical
`RecoveryCapsule`, a one-shot DOM capability computes its pinned BLAKE2b-256
hash and authorizes a retained Store compare-and-swap. The Store persists and
fsyncs bound primary and backup successors before tombstoning the provisional
record. Only authenticated reopening of that final record returns
`SessionBlindingShareCapabilityV1` with PoK, BP, kernel preview, and opaque
signing-share operations. A different capsule successor, replayed promotion,
cross-session/terms substitution, or reopening the tombstoned provisional key
fails closed. Pending and bound retirement are target-specific one-shot
requests; the Store independently requires a durable terminal session
successor before tombstoning and deleting both copies.

There is no raw scalar accessor or generic callback. The final capability
supports only PoK contribution, collaborative-proof binding, funding addition,
spend subtraction, public-key inspection, and one-shot durable backup
acknowledgement.

Collaborative Bulletproof rodada-0A `q_i` and backend `private_nonce_i` are two
independent OS-CSPRNG draws. They are sealed together in a distinct encrypted,
short-lived Store record before `c_i` is exposed. The record binds chain,
session, complete statement hash, participant identity, and roster index.
Opaque import reconstructs the exact pending state after restart; private nonce
bytes never gain an accessor, codec, clone, debug, or deterministic derivation.
The existing backend continues using separate common and private nonces.

Round 2 crosses a second durability boundary. The production driver consumes
its backend state into both the canonical 104-byte `BpRound2ShareV1` and an
opaque canonical zeroizing finalizer continuation, but returns neither. The
continuation is authenticated by the same nonce identity plus the exact
aggregate `T1`/`T2` points and `extra_commit` bytes. A one-shot capability gives
both values to the selected Store. The Store atomically writes immutable
encrypted share and continuation artifacts, writes the terminal nonce-consumed
tombstone, removes the 64-byte nonce record, and fsyncs before authenticated
readback can produce a `DurableBpRound2TransportV1`. That transport is one-shot
per send attempt.
ACK-loss retry and restart obtain another byte-identical transport authority by
opening the encrypted share artifact under the complete chain/session/
statement/participant binding and message digest; the original nonce is never
opened or recreated. After a crash immediately following round 2, a fresh
driver reopens only the encrypted continuation, reconstructs the opaque pinned
backend finalizer, and produces the same proof from the durably journaled
ordered round-2 messages. The Store then atomically persists and verifies the
exact 739-byte proof and only in that same retained transaction tombstones and
deletes the continuation. A later restart reopens only the immutable proof.
Persisting only a tombstone and round-2 share was rejected because it preserves
transport retransmission but makes final proof construction impossible after
both participant processes restart.

### Idempotent canonical transaction submission

`POST /tx/submit` keeps its existing path and admission semantics, and adds a
lifecycle result:

```json
{
  "accepted": true,
  "relayed": false,
  "tx_hash": "<64 lowercase hex>",
  "state": "new | mempool | confirmed",
  "already_known": true,
  "confirmed": false
}
```

Before ordinary admission, the node requires the submitted bytes to be the
canonical DOM encoding and computes the canonical transaction id. It uses the
existing canonical kernel-excess index to select a possible confirmed block,
then recognizes success only if that block contains byte-identical canonical
transaction bytes. It likewise compares byte-for-byte with an entry already in
the mempool. A transaction-id collision with different bytes fails closed. The
mempool and consensus admission rules are unchanged.

`new` means this call admitted the transaction, `mempool` means the exact bytes
were already pending, and `confirmed` means the exact bytes were already in the
canonical chain. An unrelayed `new` or `mempool` response retains the existing
retry warning. A canonical `confirmed` response is terminal and has no relay
warning.

### Standalone RPC secret loading

When the standalone `dom-node` binary enables RPC with
`DOM_RPC_LISTEN_ADDR`, startup requires `DOM_RPC_BEARER_TOKEN_FILE`. The
listener must be a numeric loopback address. The token is read only from that
regular, non-symlink file, is bounded to 512 visible non-whitespace ASCII bytes
(minimum 32), trims at most one trailing LF/CRLF, and on Unix rejects
group/other-accessible modes and a file replaced during open. Token contents
never enter argv or logs and remain redacted from `NodeConfig` debug and
serialization. Startup fails before initializing the node when any check fails.
Embedded callers may continue supplying an explicit token through `NodeConfig`.

### Static session-authority entry

The ratified production seam from DOM commit
`a1825639154dcc9d89be098079112e9cb975940e` is preserved on the combined F7
surface as
`ValidatedSigningRoundStateV1::from_session_authority::<Authority>`. It accepts
only the associated accepted-session handle of the statically named
`SigningSessionAuthorityV1` and delegates to the existing canonical accepted
session replay. `VaultBackedSignerV1::begin_accepted_signing_round` remains the
signer-owned entry and now calls that same public authority seam; no transcript,
nonce, or signature logic is duplicated.

F7 additionally uses
`ValidatedSigningRoundStateV1::from_operational_session_authority`. Its
Store-owned handle extends, rather than changes, the frozen NAR view with the
global journal's exact round-start transcript and per-sender next-sequence
bases. Message sequences are `base_i + {0,1,2}` for commitment, reveal, and
partial signature, with checked overflow and the existing two-party barrier
order. Transcript advancement uses registered signing phases `0x0100`,
`0x0101`, and `0x0103`. There are no child session IDs, purpose-specific
journals, or alternate logical keys; replay contains only the canonical prefix
of this round after the Store has audited its complete global ancestry.
`VaultBackedSignerV1::new_operational` and
`begin_operational_signing_round` accept a marker implementing only the
operational authority trait; the nonce reservation, derivation,
consume-before-export, resend, and terminal methods are shared with the frozen
signer implementation. The operational marker cannot enter the legacy
sequence-zero constructor, and no caller-built validated state is accepted.

## Invariants

1. The scanner returns exact stored consensus objects; it does not reconstruct
   signatures or transaction boundaries heuristically.
2. `tx_hash` is always `BLAKE2b-256(canonical_bytes)` and the bytes must decode
   back to the projected transaction without change.
3. Every page is a contiguous canonical prefix produced under one chain lock.
4. Every indexed body round-trips canonically, its embedded header exactly
   equals the stored header, and the network-specific canonical header
   identifier exactly equals the height-index hash.
5. A continuation above height zero is accepted only when its predecessor hash
   remains canonical; a reorg fails closed.
6. Funding contains the verified shared output exactly once and does not spend
   it.
7. Claim and refund each spend exactly that one shared output and do not
   recreate it.
8. Funding and claim use an ordinary `PLAIN` kernel. Refund uses the existing
   nonzero `HEIGHT_LOCKED` kernel. No Scriptless marker is introduced.
9. Signature-independent structure, range-proof, and balance checks pass before
   signing. The complete consensus validator passes before bytes or txid are
   released.
10. Funding cannot finalize without consuming durable Store-issued authority
   bound to its exact structured unsigned transaction, NAR-002 canonical
   signature-omitting bytes and hash, terms, `C`, BP statement, claim template,
   refund, claim pre-signature, backups, and complete ready-to-fund evidence.
11. Claim cannot finalize without a verified adaptor pre-signature and matching
    adaptor secret.
12. Funding bytes cannot leave the lifecycle until a post-sign Store sink
    durably consumes the matching issuance record; persisted/rebroadcast bytes
    are exact and fee mutation requires a new template and signing session.
13. A participant may compose only its own shared-output and wallet funding
    contributions; no scalar export or cross-participant aggregate exists.
14. A byte-identical retransmission has one stable transaction id and cannot
    increment admission metrics or duplicate the mempool entry.
15. Confirmed replay recognition is anchored in the canonical kernel index and
    then proven against exact transaction bytes from the indexed block.
16. Standalone F7 RPC cannot start without an owner-only token file and a
    loopback listener.
17. Production signing-round creation consumes the accepted-session type owned
    by the named session authority and revalidates the initial transcript and
    bounded canonical message prefix before any nonce-vault stage authority is
    available.
18. `r_i`, `q_i`, and backend private nonce material is independently
    OS-generated, encrypted before public commitment, opaque after rehydrate,
    zeroized on drop, and unavailable through generic serialization.
19. No `R_i`/PoK or purpose-specific `r_i` operation exists until the selected
    Store proves both primary persistence and durable backup roundtrip.
20. A generated BP round-2 share and its opaque finalizer continuation are
    encrypted and fsynced atomically with a terminal nonce tombstone before
    transport exposure. ACK-loss retry reopens only the immutable bound share.
21. A post-round-2 restart opens only the bound finalizer continuation. The
    verified proof is persisted before the continuation is retired; a
    post-finalize restart opens only the immutable proof and never the nonce or
    finalizer.
22. Operational signing rounds retain one global session/journal identity and
    enforce Store-authenticated sender bases plus signing-phase transcript
    advancement; `(session,sender,sequence)` remains collision-free.

## Alternatives Considered

### Extend the legacy flat scanner

Rejected. Adding only a kernel signature still cannot associate the signature
with the transaction that spends the shared output. Heuristic grouping would
be unsafe after aggregation or blocks containing multiple transactions.

### Expose raw block database records

Rejected. It couples clients to LMDB and internal block storage, bypasses node
authentication and bounds, and provides no stable versioned contract.

### Add a Scriptless marker or session id on chain

Rejected by the Master Specification. It breaks the ordinary-transaction
surface and creates a direct classifier.

### Reconstruct the aggregate shared blinding in the normal builder

Rejected. No participant may learn the aggregate blinding. The lifecycle
builder accepts only the public commitment and verified proof, then validates
the public balance equation.

### Derive proof private nonce from the common nonce or one persisted seed

Rejected. The Master requires an independent private nonce. Sharing a source
or deterministic derivation would turn compromise/reuse of one value into
cross-role nonce failure and contradict the distinct-nonce backend evidence.
Both values are independently drawn and jointly sealed only for crash recovery.

### Purpose-scoped signing journals or child session identifiers

Rejected. They conflict with the canonical global session identity and hide
sequence collisions rather than preserving authenticated ancestry. The
operational authority carries exact global sequence bases into the unchanged
DSC1 envelope semantics.

### Implement separate signing, proof, or transaction cryptography

Rejected. All cryptographic operations remain delegated to the pinned DOM
authorities and all final transactions use the unchanged consensus validator.

## Compatibility and Security Impact

The scanner and lifecycle changes are additive. Existing `/chain/scan`,
embedded wallet methods, transaction encoding, and consensus validation remain
unchanged. `/tx/submit` keeps its request and existing response fields while
adding `state`, `already_known`, and `confirmed`; exact known bytes now return a
successful idempotent result. Flat wallet projections remain available; the
new grouped projection is populated only for unfiltered canonical scans. The
Scriptless HTTP endpoint remains under the existing bearer-token middleware.

Standalone RPC deployment becomes intentionally stricter: the legacy implicit
environment/home-token fallback is not used by the standalone `dom-node`
entrypoint once RPC is enabled. Operators must provision the explicit file and
bind loopback. This is a security compatibility break for an insecure
standalone configuration, not a wire or consensus change.

The endpoint exposes full transaction and proof data to an authenticated node
operator. That information is already present in the operator's block store,
but the response is intentionally bounded to reduce memory and lock-hold denial
of service risk. Secret scalar shares, nonce material, seeds, and recovery keys
are never returned.

## Tests

The implementation includes tests that establish:

- authentication is mandatory and the JSON preserves canonical bytes,
  transaction location, grouping, and the 65-byte signature;
- range and response bounds, chain identity, anchor shape, canonical
  continuity, continuation, busy-lock behavior, and reorg rejection;
- a real two-party collaborative Bulletproof becomes a verified shared output;
- funding includes that exact output, requires a durable operational token,
  hides signed bytes from ordinary callers, and persists only through the
  post-sign Store sink;
- operational funding rejects a BP statement from another chain/session/`C`
  and binds terms, `C`, BP statement, claim template, refund, pre-signature, and
  bilateral backups into the one-shot issuance record;
- a crash after funding authorization resumes the same immutable issuance
  digest/revision, does not issue again, and fails after terminal consumption;
- claim adapts a real pre-signature, passes the complete DOM verifier, and
  permits extraction under the existing adaptor verifier;
- refund spends the same commitment, fails before its absolute height, and
  passes at and after the height;
- duplicate shared outputs, expired refunds, wrong kernel features, wrong
  roles, invalid signatures, and noncanonical transaction shapes fail closed.
- local funding-share composition matches public-point addition, reduces
  modulo the pinned group order, rejects zero, and exports no source bytes.
- shared-output spend subtraction and transaction-offset aggregation match the
  pinned scalar authority, including a valid zero aggregate offset;
- shared `r_i` is provisionally sealed and backup-confirmed before decoy
  commitment release; the exact bilateral capsule is then CAS-bound before
  PoK/BP/signing operations, while alternate successors, replay, substitution,
  premature retirement, and provisional reopening after promotion fail;
- each exact round-2 share is persisted before exposure, the nonce record is
  retired in that transaction, and repeated one-shot transport authorities
  reproduce byte-identical bytes without reopening nonce material;
- a process restart immediately after round 2 authenticates the bound opaque
  finalizer continuation, rejects tampering, finishes the real proof without
  reopening the nonce, persists the verified proof before continuation
  retirement, and reopens the exact proof after a second restart;
- the published adversarial backend test confirms that knowing the common
  nonce while the independently generated private nonce differs cannot recover
  a blinding that opens the original commitment;
- lost-ACK replay succeeds byte-identically in both the mempool and confirmed
  states, without a second admission or false retry warning after confirmation;
- standalone RPC trims a normal token-file newline and rejects missing,
  insecure, symlinked, oversized, or non-loopback configurations, while the
  authenticated scanner proves 401 without the token and 200 with it.
- the static session-authority entry accepts a fresh authority-owned session,
  rejects a mutated initial transcript, and remains compatible with the
  existing vault-backed signer entry.
- the operational signing entry begins at global sender bases and the
  Store-authenticated round-start transcript, while the frozen Phase-1 entry
  remains unchanged.
- an operational-only Store marker constructs the complete vault-backed signer,
  begins the global-journal round, and type-reaches nonce reservation without
  implementing the legacy session authority.

Reproducible focused commands:

```bash
CARGO_BUILD_JOBS=2 cargo test -p dom-adaptor transaction_lifecycle
CARGO_BUILD_JOBS=2 cargo test -p dom-adaptor signing_share --lib
CARGO_BUILD_JOBS=2 cargo test -p dom-adaptor shared_blinding_vault --lib
CARGO_BUILD_JOBS=2 cargo test -p dom-adaptor \
  two_party_driver_produces_a_739_byte_consensus_verifiable_proof --lib
CARGO_BUILD_JOBS=2 cargo test -p dom-adaptor \
  operational_session_uses_global_transcript_and_sender_sequence_bases --lib
CARGO_BUILD_JOBS=2 cargo test -p dom-adaptor --test scriptless_gate_readiness
CARGO_BUILD_JOBS=2 cargo test -p dom-node scriptless_scan
CARGO_BUILD_JOBS=2 cargo test -p dom-node submit_tx_lost_ack
CARGO_BUILD_JOBS=2 cargo test -p dom-node --bin dom-node standalone_rpc
CARGO_BUILD_JOBS=2 cargo test -p dom-rpc scriptless_scan
CARGO_BUILD_JOBS=2 cargo test -p dom-rpc submit_idempotent
CARGO_BUILD_JOBS=2 cargo test \
  --manifest-path labs/dom-bp-migration-lab/Cargo.toml \
  distinct_backend_private_nonce_cannot_recover_a_valid_original_blinding
CARGO_BUILD_JOBS=2 cargo clippy \
  -p dom-crypto -p dom-adaptor -p dom-wallet-core-api -p dom-node -p dom-rpc \
  --all-targets -- -D warnings \
  -A clippy::large-enum-variant -A dead-code \
  -A clippy::cloned-ref-to-slice-refs
rustfmt --edition 2021 --config skip_children=true --check \
  crates/dom-adaptor/src/transaction_lifecycle.rs \
  crates/dom-adaptor/src/adaptor.rs \
  crates/dom-adaptor/src/bulletproof_mpc.rs \
  crates/dom-adaptor/src/collaborative_bp_nonce_vault.rs \
  crates/dom-adaptor/src/collaborative_range_proof.rs \
  crates/dom-adaptor/src/operational_funding_authority.rs \
  crates/dom-adaptor/src/signing_share.rs \
  crates/dom-adaptor/src/shared_blinding_vault.rs \
  crates/dom-adaptor/tests/g1a_adaptor.rs \
  crates/dom-crypto/src/bulletproof_bp.rs \
  crates/dom-crypto/src/lib.rs crates/dom-crypto/src/scriptless.rs \
  crates/dom-node/src/main.rs crates/dom-node/src/node_handle.rs \
  crates/dom-node/src/wallet_core_api.rs \
  crates/dom-rpc/src/lib.rs crates/dom-wallet-core-api/src/lib.rs \
  crates/dom-wallet-recovery/src/lib.rs
```

The scoped `rustfmt` invocation is intentional: pinned base `a5d7410` contains
pre-existing formatting drift in unrelated Scriptless modules. Traversing all
module children would rewrite that historical code and obscure this additive
change. Every Rust file changed by this decision is checked directly without
following untouched module declarations.

The three Clippy allowances are likewise pinned-base exceptions, not new-code
exceptions: `LocalStage` in `collaborative_range_proof.rs`, an unused soak-test
PRNG constructor, and a cloned-reference assertion in
`bp_mandatory_matrix.rs`. A strict run without allowances stops on those three
unchanged findings; with only those findings allowed, every selected target
passes under `-D warnings`.
