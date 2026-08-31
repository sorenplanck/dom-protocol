# Bitcoin actuator V1 — production boundary and known limits

This crate is the participant-side Bitcoin authority for DOM interoperability.
It is deliberately not a shared maker+taker signer.

## Required composition

1. Resolve `ResolvedBitcoinDeploymentV1` from the authenticated deployment
   registry and construct a fresh `BitcoinActuationScopeV1` for the exact
   route, effect, leg, action, fence, terms, deployment and transaction intent.
2. Give each participant process a different actuator database, nonce vault,
   owner identity and wallet/key authority. A store permanently binds the
   first claim participant id before it touches the nonce vault.
3. Provision state explicitly with `DurableBitcoinActuatorV1::create` and
   `create_participant_nonce_vault`. Recovery must use `open_existing`; neither
   API replaces a database. Both paths require Linux, an absolute canonical
   path, a `0700` current-user directory and `0600` current-user regular files
   without symlinks or hardlinks.
4. Acquire a lease and use its monotonic fencing epoch in every scope. A new
   owner must call the applicable takeover reconciliation method before it can
   act under a newer fence.
5. For a cooperative claim, use the public claim-session digest as the signing
   scope intent. Exchange only public nonces and partials over authenticated
   transport. After `t` is verified and the exact final witness exists, obtain
   a distinct broadcast capability whose intent commits the exact raw bytes.
6. For funding, first use `btc-live` to persist the signed wallet transaction,
   persist and validate the exact refund, and obtain `ArmedBitcoinFundingV1`.
   Record its external-custody commitment here before invoking the sole
   `broadcast_armed_funding` path.
7. Reconcile every attempted transaction against the exact bytes in mempool or
   canonical chain. An absence after any send attempt remains ambiguous.

The HTTP Core implementation accepts only loopback endpoints and an owner-only
cookie. It requires matching network, genesis and Signet challenge, a fully
synchronized `txindex`, bounded responses, bounded connection/request time and
exact raw transaction equality.

## Security properties implemented

- one `BitcoinParticipantClaimAuthorityV1` contains exactly one local secret;
  the import API zeroizes the caller's source buffer;
- no authority type can represent or sign for both roster roles;
- no generic `sign(bytes)` API exists;
- local nonce reservation is sealed and durable before public exposure;
- remote nonce and remote partial are journaled before cryptographic use;
- restart replays the exact nonce/partial and equivocation fails closed;
- raw claim/refund bytes and every RBF generation are owner-only and committed
  before any RPC call;
- retries transmit byte-identical data;
- claim/refund selection is mutually exclusive per route leg and terminal
  completion is idempotent;
- RBF preserves version, locktime, input order/outpoints/scripts/sequences and
  output order/scripts/amounts, except for a single pre-authorized change value;
- a stale process cannot act after takeover; claim and funding takeover both
  require explicit observation before re-fencing;
- secret-bearing types have no `Debug`, `Clone` or serialization surface, and
  this crate emits no logs containing raw transactions, keys, nonces, partials
  or adaptor scalars.

## Deliberate fail-closed limits

- Do not use `adapter-btc-live::fresh::RetainedFreshBitcoinClaimAuthorityV1`
  in the production composition. Its retained fresh-route record owns maker,
  taker and refund secrets together. It remains a legacy/test convenience and
  violates the participant-process boundary required here.
- This crate does not own a generic Bitcoin wallet. Funding input selection,
  signing and initial raw custody remain exclusively in `btc-live`/Bitcoin
  Core. The refund signer remains an external owner authority; this actuator
  only accepts the exact scoped signed refund bytes.
- Opaque `btc-live` funding cannot currently be RBF-replaced through this
  crate because `btc-live` intentionally does not release its raw funding
  transaction or PSBT. Funding fee bump therefore fails closed. A future
  `btc-live` replacement/CPFP authority must retain the same inputs, contract
  output, scripts, locktime and sequences and expose only a new custody digest.
- Claim RBF is disabled because a cooperative one-output claim has no
  pre-authorized change output. Refund RBF is available only when the scope
  explicitly names a change output. Once any generation was sent, absence of
  a newly prepared replacement is always ambiguous. V1 reconciles the active
  txid; identifying an older generation that wins a replacement race still
  requires the route's contract-outpoint observer (or a future family-wide
  reconciliation API), and the terminal choice remains locked meanwhile.
- Bitcoin Core must run with `txindex=1` and report the index synchronized at
  the current canonical height. Wallet-only lookup is insufficient for safe
  crash recovery.
- The nonce vault dependency can migrate its own older schema. The actuator
  prevents implicit creation and enforces physical ownership, but a future
  release should add explicit `create`/`open_existing` and full schema audit to
  `btc-vault` itself.
- The live regtest in this crate proves exact persistence, broadcast and
  finality through Bitcoin Core. The participant test proves the actual MuSig2
  adaptor claim. A product release still requires the daemon composition,
  public registry/deployment ceremony, real solver inventory and a multiprocess
  DOM↔Bitcoin crash/reorg test with funded values.

No commit or push is part of this implementation handoff.
