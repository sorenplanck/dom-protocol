# DOM Wallet V3 Synchronization and Recovery Threat Model

**Public technical review draft**

**Date:** 2026-07-30

**Reference implementation:** the functional wallet built and tested on
2026-07-29, not yet published: branch `redesign/restore-remote-scan`, with the
legacy deterministic coinbase compatibility fix in
`b1f04ac713ff8770b0ece73e9fedc595cd7936c5`. At the time of writing, the DOM
protocol crates are pinned to
`387b744474d2414f9d2d0e542bc654096ce2f8ed`.

> This document describes behavior implemented in the current code. It is not
> a future specification, a release note, or an independent security audit.
> The local `wallet-v0.3.0` tag still points to `7d43910`; therefore, the legacy
> deterministic coinbase compatibility fix in `b1f04ac` must be included in
> the revision that is actually published.

## 1. Executive summary

DOM Wallet V3 separates four activities that must not be confused:

1. **Application startup:** when the selected chain source is `EMBEDDED`, the
   embedded node starts in the background as the application opens.
2. **Wallet creation:** no wallet is created automatically. Creation happens
   only after an explicit user action.
3. **Logical seed restore:** the recovery phrase is validated and an encrypted
   wallet is created immediately, even without a node, peers, or Internet
   access.
4. **Balance recovery:** after the wallet is unlocked and a chain source is
   available, a worker scans the canonical chain and updates the balance
   progressively.

The high-level flow is:

```text
open application
   ├─ EMBEDDED source → start dom-node in background → connect peers → sync chain
   └─ REMOTE source   → wait until the remote scan source is needed

user creates or restores a wallet
   └─ encrypted wallet is created only by that explicit action

user unlocks wallet
   └─ sync worker acquires the configured chain source
        └─ validates Mainnet identity
             └─ reads up to 256 canonical blocks per page
                  └─ authenticates recoverable outputs
                       └─ atomically commits outputs, spends, and cursor
                            └─ publishes partial balance
                                 └─ repeats and then follows the canonical tip
```

Restoring the wallet does not require an existing peer connection. Discovering
the balance does require a canonical view of the chain, obtained from the
embedded node or a compatible remote source.

## 2. Lifecycle rules

### 2.1 The node starts with the application

During Tauri setup, the application first loads the persisted chain-source
configuration. If the effective source is `EMBEDDED`, it starts the Mainnet
node. Node construction runs on a dedicated thread because opening LMDB,
performing time checks, and initializing Core can take time.

The node is not coupled to the create, open, or restore commands.

If LMDB returns the typed map-full error, startup increases the persisted map
size, up to a 64 GiB ceiling, and retries. If the saved source is `REMOTE`, the
embedded node is not started unnecessarily.

### 2.2 Startup never creates a wallet

The initial `WalletService` state is `Closed`. Wallet creation happens only
through an explicit `wallet_create_recoverable` user action.

The old creation flow without a recovery-phrase ceremony is disabled. Every
new wallet is created through `create_recoverable` and must present a BIP-39
phrase.

### 2.3 Recoverable creation

Creation:

- obtains 256 bits of entropy from the operating system CSPRNG;
- represents it as a checksummed 24-word English BIP-39 phrase;
- creates encrypted state bound to the frozen DOM Mainnet identity;
- records that the phrase ceremony is not yet confirmed;
- leaves the wallet locked;
- enables protected operations only after explicit phrase confirmation.

Wallet creation does not wait for the node to synchronize. The node and wallet
advance independently.

## 3. Immediate offline phrase restore

### 3.1 Validation before touching disk

The restore command bounds the input, validates the password, and diagnoses the
phrase before creating any file.

An accepted phrase must:

- contain exactly 24 words;
- use the English BIP-39 word list;
- have a valid checksum;
- encode exactly 256 bits of entropy.

Errors distinguish an unknown word, incorrect word count, incorrect checksum,
and malformed input. A rejected phrase must not leave a wallet or staging
directory at the destination.

### 3.2 Immediate restored state

After validation, `restore_from_mnemonic_offline` creates an encrypted wallet
bound to Mainnet and records:

- BIP-39 recovery metadata;
- `seed_restore_status = in_progress`;
- `sync_status = synchronizing`;
- no scan cursor;
- no invented balance;
- no dependency on a backend, node, or peer.

The command returns with `scanning = true`. At this point, "wallet restored"
means the cryptographic authority has been recreated and safely persisted. It
does not mean the entire chain has been examined.

The wallet remains locked. Definitive scanning starts after unlock and after a
chain source is available, because recovered state and private output material
must be written back into encrypted storage.

### 3.3 If the node is still synchronizing

Restore does not wait for initial block download.

The synchronization worker is self-healing:

- if the embedded backend is not ready, it retries;
- if Core is busy or temporarily unavailable, it applies backoff and retries;
- if the node learns new blocks, it continues following the new tip;
- if the wallet is locked, the scan cannot alter encrypted state and is
  restarted by unlock;
- when the source is ready, it processes one canonical page per iteration.

The user can therefore open the restored wallet immediately, while the balance
appears progressively as available blocks are examined.

## 4. Two different synchronization layers

### 4.1 Node synchronization

The embedded node:

- connects to peers;
- downloads and validates headers and blocks;
- maintains the local canonical chain;
- exposes chain identity and the wallet scan projection through
  `WalletCoreApi`.

This layer decides which blocks belong to the valid chain. The wallet does not
replace consensus validation.

### 4.2 Wallet synchronization

Wallet synchronization walks the canonical chain exposed by the selected
source. It looks for outputs owned by the restored seed, inputs that spend
those outputs, and changes in coinbase maturity.

The wallet cursor is not the node height. It records how far canonical chain
effects have been durably incorporated into encrypted wallet state.

Each page contains at most 256 blocks by default. While catching up, the worker
waits roughly 10 ms between pages. At the tip, it polls approximately once per
second. Transient failures use exponential backoff starting at 250 ms, capped
at 5 seconds, plus up to 250 ms of jitter.

## 5. Embedded and remote sources

### 5.1 Embedded source

This is the default mode. The wallet uses the embedded node's
`WalletCoreApi`.

It provides:

- canonical scan;
- cursor validation;
- reorganization detection;
- node and peer status;
- transaction submission;
- fee policy;
- mining.

### 5.2 Remote scan-only source

The remote source implements the same frozen scan contract and passes through
the same `CoreChainAdapter`, cursor rules, and atomic commit path.

It is intentionally **scan-only**:

- it can synchronize and restore balances;
- it cannot mine;
- it cannot submit transactions;
- it cannot calculate fees;
- it does not replace the embedded node for operations requiring those
  capabilities.

Remote scanning downloads the full projection for requested height ranges and
does not send commitment filters. This avoids directly telling the server
which outputs the wallet is looking for.

The remote bearer token:

- is stored in the private configuration file;
- is held in zeroizing memory;
- is never returned by status DTOs;
- is reused only while the URL remains byte-for-byte identical.

Plain HTTP to a non-local host triggers a privacy warning. A remote tip
regression or inconsistency remains latched as an alert.

## 6. Canonical scan contract

Before accepting a source, the wallet pins and compares:

- network;
- network magic;
- chain ID;
- genesis hash;
- protocol version;
- range-proof serialization version;
- coinbase maturity;
- a non-null tip height and hash.

Every page must contain blocks:

- at consecutive heights;
- in increasing order;
- linked by `previous_block_hash`;
- consistent with the advertised tip hash;
- using compatible protocol and identity versions;
- accompanied by a valid canonical cursor.

For each block, the projection includes:

- height, hash, and previous hash;
- timestamp;
- outputs with commitment, range proof, recovery capsule, version, coinbase
  marker, and canonical position;
- spent input commitments;
- kernels;
- coinbase metadata, including the explicit value;
- protocol and range-proof versions.

An inconsistent page is rejected as a unit. No partial effect from that page
is published.

## 7. How output ownership is recovered

### 7.1 Recovery Capsule v1

New V3 outputs carry a public authenticated recovery capsule. The 24-word
phrase produces a 64-byte BIP-39 seed with an empty BIP-39 passphrase. The
wallet derives a 32-byte recovery root with HKDF-SHA256. That derivation is
bound to `network_magic`, `chain_id`, and the frozen
`DOM:wallet-v3:recovery-root` domain, so the same phrase on a different network
or chain does not produce the same recovery authority.

Separate detection, authentication, and blinding-reconstruction subkeys are
derived from the recovery root. The authentication key for each output is also
bound to that output's public commitment. The seed does not generate a finite
address list to compare against the chain; it generates the authority needed
to authenticate and open capsules addressed to the wallet.

A valid capsule recovers:

- output value;
- blinding factor;
- recovery account;
- derivation index;
- output domain;
- coinbase classification;
- binding to the commitment.

The domains distinguish `received`, `change`, `self-transfer`, and `coinbase`.
This prevents material from one purpose from being reused as another.

After authentication, the wallet recomputes the Pedersen commitment from the
value and blinding factor. The output is accepted only if it exactly equals the
canonical commitment. The wallet also verifies the range proof bound to the
capsule bytes.

Authentication failure means only "not my output" and does not disclose which
check failed. Outputs without capsules are not claimed by guessing or
heuristics, except for the narrow historical compatibility path below.

### 7.2 Legacy deterministic coinbase compatibility

Revision `b1f04ac` adds the compatibility required for mining rewards created
by DOM wallets predating Recovery Capsule v1.

Those wallets used the frozen derivation path:

```text
m/44'/330'/0'/1'/height'
```

For every block, the wallet:

1. identifies the canonical coinbase without a recovery capsule;
2. derives the historical blinding factor for that height;
3. uses the explicit coinbase value validated by the scanner;
4. recomputes the commitment;
5. recognizes the reward only on exact equality.

This compatibility is restricted to deterministic coinbases. It does not
claim recovery of ordinary legacy outputs that never contained recoverable
material and do not follow this frozen derivation.

The permanent regression test uses the same phrase in both implementations,
mines a coinbase with the old wallet, and requires V3 restore to recover a
strictly positive balance.

## 8. Explicit recovery, privacy, and trust answers

### 8.1 What the seed derives and how an output is found

The V3 mechanism is:

1. 24-word BIP-39 phrase → 64-byte BIP-39 seed;
2. seed plus chain identity → recovery root through HKDF-SHA256;
3. recovery root → separate detection, AEAD, and blinding-mask subkeys;
4. output commitment → output-specific AEAD key;
5. the wallet locally attempts to open Recovery Capsule v1;
6. authentication failure means the output is not claimed;
7. successful opening recovers value, account, index, domain, and blinding;
8. the private domain must match the public `regular` or `coinbase` type;
9. the wallet recomputes the Pedersen commitment and requires byte equality;
10. it verifies the range proof committed to the capsule bytes;
11. it records the output and later marks it spent if a canonical input uses
    the same commitment.

The wallet therefore tests every output delivered by the scan against its own
local cryptographic authority. It does not give keys to the node and does not
ask the node whether a particular owned commitment exists. The cost is linear
in the total number of outputs examined.

V3 output blindings are random; they are not simply the result of an HD path.
The authenticated capsule carries the material needed to reconstruct them. The
BIP-32 path `m/44'/330'/0'/1'/height'` is separate and is used only to recognize
old deterministic coinbases.

### 8.2 Does the seed alone recover every fund?

**No, not for every historical circumstance.** The exact guarantee is:

- the seed recovers V3 `received`, `change`, `self-transfer`, and `coinbase`
  outputs carrying a valid Recovery Capsule v1 for that seed and chain;
- it recovers old coinbases that follow exactly
  `m/44'/330'/0'/1'/height'`;
- it reconstructs spent state by observing later inputs on the chain.

Coinbases and ordinary received outputs use the same V3 capsule framework but
separate domains. A coinbase authenticates as `coinbase`; an ordinary incoming
output authenticates as `received`. This prevents substituting one private
role for another.

For an output received from a third party to be seed-recoverable, the sending
protocol must have created a valid recipient capsule. V3 production paths
require recoverable outputs. An ordinary legacy output created before capsules,
or by incompatible software, does not become recoverable merely because the
user has a seed. The present compatibility fix covers only old deterministic
coinbases; it does not implement a generic search for ordinary historical
outputs.

The phrase is therefore not a replacement for a full backup when preserving:

- ordinary legacy outputs without capsules and without an implemented
  deterministic recovery path;
- labels, contacts, and local preferences;
- unfinished transaction contexts and other data not represented on-chain.

The defensible claim is: **the seed plus the complete chain recover on-chain
funds covered by V3 formats and the explicit legacy coinbase compatibility
path**. Preserving all wallet state and any legacy state outside that coverage
still requires an encrypted full wallet backup.

### 8.3 Scan privacy

Ownership matching is local in both modes.

- `EMBEDDED`: the wallet reads all blocks and outputs for the range from its own
  node and filters them on the same machine.
- `REMOTE`: the wallet requests height ranges such as
  `/chain/scan/full?from=X&to=Y` and receives every block, output, proof, and
  capsule in that range. Commitment filters are rejected locally before any
  request is sent.

The remote server does not directly learn which outputs authenticated as
wallet-owned. It still observes network metadata: IP address, timing, requested
height ranges, traffic volume, usage frequency, and any configured bearer
token. Those data can correlate sessions and reveal usage patterns even when
they do not directly reveal owned commitments.

TLS protects traffic from intermediaries. It does not hide metadata from the
remote server itself. Embedded mode has the stronger privacy boundary because
wallet scanning does not leave the user's machine.

### 8.4 Trust model with a remote node

Recovery cryptography and trust in the chain view are different layers.

The wallet locally validates immutable identity, encoding, continuity, hashes,
cursor structure, capsules, commitments, and range proofs. A remote node never
receives the seed, cannot sign a spend, and cannot create a valid capsule for
the wallet without seed-derived authority.

However, the remote client is **scan-only. It is not an independent verifier of
all consensus rules and proof of work.** A single malicious server can:

- present an incomplete, stale, or alternative chain view;
- omit blocks or outputs and make the balance appear lower;
- omit a spend and make an already-spent output appear available;
- freeze the tip or cursor and prevent progress;
- correlate IP address, timing, scan ranges, and bearer token;
- maintain a lie that remains internally consistent across every endpoint it
  controls.

Local checks detect internal inconsistencies, identity substitution, broken
linkage, and regression from a previously observed tip. They do **not** prove
that one server showed the real best chain, and they may not detect a false tip
that remains stable and self-consistent. This revision has no quorum and no
automatic comparison among independent sources.

A malicious server can damage availability and temporarily misrepresent the
balance without obtaining spending keys. A balance falsified by omission also
does not make an invalid spend acceptable to the real network. Users seeking
the strongest chain assurance must run the fully synchronized embedded
validating node, or use a remote node they operate or independently trust over
a protected transport.

### 8.5 Reorganization handling

Before continuing from a cursor, the wallet compares its anchor with the
current canonical hash. If the anchor was orphaned, it:

1. searches backward for the latest locally recorded height whose hash matches
   the source;
2. limits the normal search to 1,024 blocks;
3. removes outputs discovered above that safe anchor from a copy of state;
4. removes private blindings and metadata for those outputs;
5. reverses `Spent` when the spend occurred only in the orphaned segment;
6. subtracts removed blocks and outputs from durable counters;
7. preserves previously exposed allocation floors to prevent private-coordinate
   reuse;
8. applies replacement blocks and recalculates maturity;
9. commits rewind, replacement page, and new cursor in one encrypted
   generation.

The old generation remains authoritative until the complete commit is
published. A crash cannot publish half a rewind or half a replacement page.

### 8.6 Important failure modes

**Wallet offline for months.** The encrypted cursor remains persisted. On
return, the wallet validates the anchor and continues from it in 256-block
pages when it is still canonical. A reorganization within the supported window
is rewound. In embedded mode, the node must also catch up; until then, the
displayed balance is only the last committed state and must not be treated as
synchronized.

**Deep reorganization.** The wallet retains 2,048 anchors, but the normal
ancestor search is limited to 1,024 blocks. If no common anchor is found within
that bound, it returns `ReorgBeyondBound` and fails closed: it neither guesses
nor deletes funds, and it does not advance the cursor. Operational recovery is
an explicit rescan from genesis.

**A node freezes the cursor.** Transient errors, Core busy responses, and
temporary unavailability use retry and backoff while keeping the worker alive.
A source that advertises a target but does not provide progress is classified
as stalled in reconcile-to-tip paths. A malicious remote server can instead
declare the frozen height to be the tip and remain internally consistent.
Without a second source, the wallet cannot prove that a higher tip exists. The
mitigation is to switch to the embedded node or another trusted node and, when
needed, start a rescan.

**Crash while applying a page.** Page effects and the cursor are atomic, so the
previous generation is resumed and the page can be safely repeated without
duplicating credit.

**Source omits one output or spend.** Cryptography cannot detect data that was
never supplied. An omitted output can lower the apparent balance; an omitted
spend can raise it. Detecting the omission requires a complete canonical
source.

## 9. Applying effects and showing progressive balance

For every authenticated output, the wallet records:

- commitment;
- value;
- state;
- discovery height;
- reconstructed account;
- domain;
- derivation index;
- block hash and output position;
- private blinding inside encrypted state.

Page inputs are matched against known commitments. A matching output becomes
`Spent` at the corresponding canonical height.

Coinbases are:

- `Immature` before the maturity height;
- `Confirmed` and spendable after maturity;
- `Spent` when consumed by a canonical input.

The public balance is a projection of committed state and contains confirmed,
immature, pending incoming, pending outgoing, locked, spendable, and total
amounts. Because every page is published separately, the UI can display
partial progress and balance. Partial balance never represents blocks that
have not been committed.

## 10. Atomicity and crash recovery

The cursor and every effect of a page are written in the same encrypted
generation:

```text
validate page
  → clone current state
  → apply outputs, spends, maturity, and anchors
  → install new cursor
  → validate complete state
  → write new encrypted generation
  → publish generation as active
```

If the process crashes before publication, the prior generation remains
authoritative. Reapplying the page cannot credit an output twice.

Conflicts fail closed. Repeated evidence for one commitment is idempotent only
when value, height, account, domain, index, hash, position, and blinding are all
identical.

## 11. Cursor, reorganization, and non-reuse

The persisted canonical cursor is 86 bytes and binds:

- version;
- network magic;
- chain ID;
- next height;
- anchor height;
- anchor hash.

Before continuing, the wallet validates the anchor against the selected chain.
If the hash changed, it finds a safe common anchor, rewinds within the
configured bound, applies the replacement page, and publishes the rewind,
effects, and cursor atomically.

The wallet keeps a 2,048-anchor rolling window and durable counters for earlier
history. Allocation and non-reuse floors never move backward during a
reorganization. This avoids reusing private coordinates that may already have
been exposed.

## 12. When the system reports "synchronized"

A seed restore moves from `in_progress` to `complete` after its committed
cursor anchor reaches the observed page tip.

Embedded status is stricter and simultaneously requires:

- at least one connected peer;
- a wallet cursor;
- cursor height equal to local canonical height;
- cursor height equal to the highest height known from peers;
- cursor hash equal to the canonical hash;
- no synchronization error.

Remote status requires cursor and tip at the same height, a present hash, and
no error. A remote tip regression remains a separate latched warning.

"Node synchronized" and "wallet synchronized" are related but distinct states.

## 13. Secret handling

- The phrase and password cross only narrow Tauri commands.
- The frontend clears secret fields on success and failure.
- The frontend does not store secrets in `localStorage` or `sessionStorage`.
- Phrase, seed, recovery root, and blindings are excluded from DTOs, logs, and
  `Debug` implementations.
- Sensitive buffers use zeroizing types.
- Capsules, commitments, and range proofs are public chain data; authentication
  and private derivation happen locally.
- Restored state and recovered blindings are persisted only inside encrypted
  wallet generations.
- Mainnet identity is checked before using a source or opening a wallet against
  a backend.

## 14. Transient and terminal failures

The worker treats these as transient:

- embedded node still starting;
- busy Core;
- temporarily unavailable remote source;
- temporary absence of peers;
- node still catching up;
- remote rate limiting or temporary unavailability.

The worker backs off and remains alive.

These are terminal or require intervention:

- invalid phrase or password;
- mismatched chain identity;
- malformed cursor;
- inconsistent canonical page;
- reorganization beyond the configured bound;
- invalid or conflicting recovery capsule;
- corrupted encrypted state;
- occupied destination;
- remote source that does not implement the required contract.

UI errors are typed and redacted and must not propagate secret material.

## 15. Guarantees and limitations

### Implemented guarantees

- Application startup can start the embedded node without creating a wallet.
- A wallet is created only by explicit user action.
- Phrase restore does not wait for a node or peer.
- Balance appears progressively from committed pages.
- V3 outputs carrying valid capsules are seed-recoverable.
- Old deterministic coinbases are recognized through the historical path.
- Canonical inputs update spent state.
- Coinbase maturity is recalculated.
- Cursor and balance effects are atomic.
- Reorganizations are handled within a fixed bound.
- Embedded and remote sources use the same wallet-side validator.

### Deliberate and unresolved limitations

- Without a canonical source, the wallet cannot discover a chain balance.
- A locked wallet cannot persist newly recovered private blindings.
- Ordinary legacy outputs without capsules and without a recognized
  deterministic derivation still require a backup.
- Off-chain metadata such as labels, contacts, preferences, and some local
  transaction contexts cannot be reconstructed from the seed alone.
- Remote mode is scan-only; submission, fee policy, and mining require the
  embedded node.
- A reorganization deeper than the configured bound fails closed instead of
  guessing.
- A single remote server can omit outputs or spends, freeze or fabricate a
  self-consistent tip, correlate network metadata, and temporarily misstate the
  balance. There is no quorum or independent best-chain verification in remote
  mode.
- TLS does not hide scan metadata from the remote server itself.
- This document and the current regression suite are not a substitute for
  independent cryptographic and implementation review.

## 16. Relevant regression coverage

The suite includes tests for:

- offline restore without any chain source;
- precise phrase diagnosis without touching disk;
- progressive UI balance and scan status;
- cursor and state committed together;
- repeated-page idempotence;
- reorganization detection and application;
- retries after a busy Core;
- embedded/remote projection parity;
- remote tip regression;
- continued node, sync, and mining workers;
- identical BIP-39 seed bytes from the same phrase in the legacy and V3 code;
- known phrase → legacy wallet coinbase → V3 scan → strictly positive balance.

The last test directly prevents the critical regression where the cursor
reached the tip but the restored balance remained zero for a seed that owned
old mining rewards.

## 17. Main implementation references

- Automatic node startup: `src-tauri/src/main.rs`
- Recoverable creation and offline restore: `src-tauri/src/lib.rs`
- Background node and synchronization workers: `src-tauri/src/lib.rs`
- Status and partial-balance projection: `src-tauri/src/lib.rs`
- Recoverable creation and wallet parsing: `crates/dom-wallet-core/src/lib.rs`
- One scan page per iteration: `crates/dom-wallet-core/src/lib.rs`
- Atomic wallet-and-cursor commit: `crates/dom-wallet-core/src/lib.rs`
- Cursor, pagination, and reorganization validation:
  `crates/dom-wallet-core-sync/src/lib.rs`
- Recovery application and rewind:
  `crates/dom-wallet-core-restore/src/lib.rs`
- Historical coinbase derivation:
  `crates/dom-wallet-core-recovery/src/lib.rs`
- Permanent legacy coinbase restore regression:
  `crates/dom-wallet-core-restore/tests/seed_restore.rs`

## 18. Operational conclusion

The expected user-visible sequence is:

1. open the application;
2. let the node start independently;
3. create or restore a wallet only when requested;
4. receive immediate restore confirmation without waiting for peers;
5. unlock the wallet;
6. observe cursor, percentage, and partial balance advance;
7. treat recovery as complete only when cursor and canonical tip agree under
   the selected source's rules.

This design permits immediate restore without inventing an offline balance,
while keeping the final balance tied to validated canonical evidence. In
remote mode, "validated" means internally validated against the server-provided
view; it does not mean that one remote server has independently proven the real
best chain.
