# ADR-F7-003: Authoritative Regtest Runtime Controls

Status: Accepted for the isolated F7 laboratory

## Problem

The F7 real-node gate needs deterministic, restartable DOM funding and block
production. The standalone node previously accepted its miner-wallet password
only through process environment contents, wallet initialization exposed the
password in argv and the recovery phrase on stdout, the legacy wallet spend RPC
required a recipient blinding factor, and continuous mining made confirmation,
refund, and reorg heights nondeterministic.

## Context

The canonical DOM WalletDir and Wallet V3 recovery Slate formats already exist.
The node also already owns the real block builder, verifier, mempool, relay, and
`mine_one_block` path. F7 must compose those authorities without creating a
second transaction format, a mock chain, a replacement cryptographic protocol,
or a consensus change.

Wallet V3 requires a public three-message exchange: the sender offer, the
recipient response, and independent recipient verification of the finalized
transaction. Broadcasting during sender finalization would prevent the
recipient from performing that third-message check before economic exposure.

## Decision

1. `DOM_WALLET_PASSWORD_FILE` loads the standalone WalletDir password from a
   bounded UTF-8, owner-only, regular non-symlink file. It is mutually exclusive
   with the legacy `DOM_WALLET_PASSWORD` value. The legacy input remains for
   compatibility, but the F7 runtime uses only the file boundary.
2. `dom-wallet-bootstrap` accepts only non-secret paths and network selection in
   argv. It reads the password from the strict file boundary and writes the new
   recovery phrase exactly once to an owner-only file in a separate owner-only
   directory. It never prints password or phrase contents. If WalletDir
   creation fails after the phrase is durable, it fails closed and instructs
   the operator to preserve that recovery file and restore into a new empty
   WalletDir.
3. Authenticated Wallet V3 RPC uses three explicit operations:
   - `POST /wallet/slate/v1/create` persists a recovery-capable sender offer
     before returning canonical public envelope bytes. An optional canonical
     recipient address is accepted; omission uses the exact official Wallet V3
     one-time sender-excess/sender-nonce identity framing.
   - `POST /wallet/slate/v1/finalize` accepts one canonical recipient envelope,
     consumes the one-shot sender nonce, and durably retains the exact finalized
     transaction. It does **not** admit or relay it.
   - After the recipient independently verifies/imports the finalized public
     transaction, `POST /wallet/slate/v1/submit` accepts only the pending-record
     key and expected transaction hash. It reloads canonical bytes from the
     encrypted WalletDir, never accepts arbitrary transaction bytes, and admits
     and relays them idempotently.
4. `POST /regtest/mine/v1` is authenticated, regtest-only, and accepts an exact
   count in `1..=1000`. It refuses to operate when continuous mining is enabled
   or another bounded request is active. An empty store creates the canonical
   genesis as the first returned block; subsequent blocks use the real
   `mine_one_block` path. The response returns exact start/end heights and every
   canonical block hash. F7 nodes run with `DOM_MINE=false`.

## Alternatives Considered

- Passing password or phrase through argv, stdout, or environment was rejected
  because those surfaces are routinely captured by process inspection and test
  logs.
- Calling `/wallet/spend` was rejected because it exports recipient blinding
  material and bypasses the official public Slate exchange.
- Finalize-and-broadcast in one request was rejected because it violates Wallet
  V3 third-message ordering.
- Accepting arbitrary transaction bytes in the post-verification submit call
  was rejected because it permits substitution after recipient approval.
- Sleeping while a continuous miner advances the chain was rejected because
  exact heights, timelocks, and competing-fork evidence would not be
  reproducible.
- A fake block generator or relaxed proof/consensus path was rejected. Bounded
  mining calls the existing real miner and unchanged chain admission.

## Invariants

- No password, mnemonic, blinding factor, nonce, seed, or recovery root appears
  in RPC JSON, argv, logs, or ordinary environment contents used by F7.
- Public Slate bytes are canonical Wallet V3 recovery envelopes and are
  persisted before export.
- Sender signing secrets are destroyed only after exact response verification
  and finalized transaction persistence.
- Finalization cannot broadcast. Submission cannot introduce caller-supplied
  transaction bytes and must match both persisted pending key and exact hash.
- Lost acknowledgements replay byte-identically; conflicting responses, keys,
  or hashes fail closed.
- Bounded mining changes no consensus, genesis, PoW, wire, encoding, mempool, or
  verification rule.
- Production/test networks and nodes with background mining cannot use the
  bounded mining control.

## Compatibility and Security Impact

All changes are additive application/RPC boundaries. Existing consensus and
wire formats, WalletDir data, legacy Slate records, RPC submission, and legacy
environment password behavior remain readable and usable. New envelope fields
in pending wallet records use Serde defaults, so pre-existing encrypted wallets
continue to load. F7 deliberately selects the stricter file-only path.

Authentication uses the existing bearer middleware and loopback-only standalone
RPC policy. Rate and body limits remain in force. The phrase output directory is
outside evidence/log packages and must remain owner-only.

## Verification

- Secret-file tests reject symlinks, insecure modes, malformed UTF-8, embedded
  controls, and oversized inputs.
- Bootstrap tests cover non-secret argument parsing and strict path policy.
- Wallet tests cover persisted offer restart, exact response finalization,
  nonce destruction, finalized-byte reload, conflicting response/hash
  rejection, and idempotent submission journaling.
- Node tests cover restart between offer/finalize and finalize/submit, no
  mempool entry before the third message, exact-byte ACK-loss replay, and real
  mempool admission.
- RPC tests cover bearer enforcement and the separation of finalize from
  submit.
- Bounded mining tests cover authentication, bounds, non-regtest refusal,
  background/concurrent refusal, exact count, heights, and canonical hashes.
- The final F7 cross-repository test must additionally mine and mature real
  canonical coinbase outputs and use the official Wallet V3 `WalletService`
  response and finalized-transaction verify/import operations before submit.
