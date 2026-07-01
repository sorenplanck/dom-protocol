# DOM Wallet v2 — Design Document

Status: **DRAFT FOR HUMAN REVIEW** — no production code has been written.
Date: 2026-06-13
Target crate: `dom-wallet2` (new, not yet created)
Audit basis: `audit/WALLET_DESKTOP_SLATE_FLOW_AUDIT.md` (WDSF-001..004)

> This document is design + a type skeleton (§10) only. It implements no logic.
> Decisions tagged **[NEEDS HUMAN DECISION]** are consolidated in §9.

> **Update (revision 2):** foundation approved. Resolved decisions:
> **H-1** accepted as an inherent MW limitation → the store gains an encrypted
> export/import path as recovery complementary to the seed (§2.7). **H-2** →
> slate crypto extracted into a shared `dom-slate` crate (§5.2). **H-3** →
> confirmed that `WalletVersion::V2` is only an internal v1 schema marker;
> non-colliding names defined (§5.5). The WDSF-001/002 proofs are expanded into
> full state sequences (§4.3/§4.4). H-4/H-5/H-6 remain open (§9).

---

## 0. Objective and framing

The current wallet (`dom-wallet`) has two structural blockers confirmed by
pre-existing defensive tests that **fail today**:

- **WDSF-001** — a confirmed *receive slate* disappears after a reorg + re-mining
  of the same tx. Cause: `rollback_to` (`wallet.rs:696-709`) removes the output
  and the random blinding exists nowhere recoverable; the journal's `Received`
  status is terminal and does not rewind (`journal.rs:587-643`).
- **WDSF-002** — the `Repair` rescan deletes confirmed non-derivable outputs
  (confirmed receive-slate **and** confirmed change). Cause: `Repair` does
  `self.outputs = rebuilt_outputs` (`wallet.rs:1186`) where `rebuilt_outputs` is
  **reconstructed by derivation** (coinbase by height, receive-requests by index)
  or from still-live pending; anything with a random blinding that is no longer
  pending vanishes.

The shared root cause is an **inversion of the source of truth**: today the wallet
treats the output set as something *reconstructible by derivation from the seed*,
and rescan/rollback **reconstruct** that set. Outputs with random blindings
(change, receive-slate) are not derivable and are therefore destroyed.

v2 eliminates the **class** of bug with a single architectural principle:

> **The persistent output store is the ONLY source of truth. Random blindings are
> persisted, never re-derived. Rescan and reorg are STATUS RECONCILIATION over
> already-persisted outputs — never reconstruction of the set.**

Already-lost testnet funds are irrelevant; the goal is that the class cannot
reappear.

### Acceptance principles (derived from the brief)

1. Source of truth = encrypted store of wallet-owned outputs; blinding persisted.
2. Rescan = reconciliation, not reconstruction. An output leaves the spendable
   set only if **provably spent** (canonical input) or **reverted by reorg**
   (becomes `Reorged`, recoverable — never deleted).
3. Safe reorg: rollback changes STATUS to `Reorged` and keeps the material.
4. Slate flow only. No legacy path (`build_spend` / payment-request).
5. Migration by BIP-39 seed phrase only. v2 does not import v1 wallet files.

---

## 1. Layered architecture

v2 strictly separates **persisted secret material** (store) from **events**
(journal) and from **canonical chain state** (reconciler). The UI and the node do
not change; v2 talks to the node over the same RPC.

```text
┌──────────────────────────────────────────────────────────────────────┐
│                    wallet-desktop (Tauri + web UI)                     │
│            slate_create_send / slate_receive / slate_finalize          │
│         [UNCHANGED surface; points at dom-wallet2 in the build]        │
└───────────────────────────────┬──────────────────────────────────────┘
                                 │ (same product commands)
┌───────────────────────────────▼──────────────────────────────────────┐
│ F. WALLET API               crate dom-wallet2 :: WalletV2             │
│    - create_send / receive / finalize / balance / list_outputs        │
│    - orchestrates E (slate) + A (store) + D (journal) + B (reconcile)  │
├───────────────────────────────────────────────────────────────────────┤
│ E. SLATE ENGINE (EXTRACTED)  crate dom-slate — validated v1 crypto     │
│    - slate construction / signing / aggregation / validation          │
│    - PURE: material in, Slate/Tx out; touches NO disk                  │
│    - depends on dom-tx::slate (struct/serde) — reused as a dependency  │
├──────────────────────┬────────────────────────────┬───────────────────┤
│ D. EVENT JOURNAL      │ B. CHAIN RECONCILER        │  C. SCAN SOURCE    │
│   append-only WAL     │   reconciles STORE vs the   │   trait to read    │
│   of transitions      │   canonical set             │   canonical blocks │
│   (audit/replay)      │   (status-only, see §4)     │   (RPC or memory)  │
├──────────────────────┴────────────────────────────┴───────────────────┤
│ A. OUTPUT STORE (SOURCE OF TRUTH)  encrypted at rest                   │
│    - each output: commitment, value, blinding(persisted), origin,      │
│      status, origin block (height+hash)                                │
│    - versioned; ChaCha20Poly1305; atomic write + fsync                 │
└───────────────────────────────────────────────────────────────────────┘
                                 │ RPC (unchanged)
┌───────────────────────────────▼──────────────────────────────────────┐
│        dom-node / dom-mempool / dom-rpc / miner   [UNCHANGED]          │
└───────────────────────────────────────────────────────────────────────┘
```

Responsibilities and boundaries:

| Layer | Responsibility | Never does |
|---|---|---|
| A. Store | Persist the wallet-owned set + secrets. Source of truth. | Derive ownership; discard a confirmed output. |
| B. Reconciler | Read the canonical set (via C) and **update the status** of A's outputs. | Create/derive outputs; delete confirmed ones. |
| C. Scan source | Abstract reading canonical blocks (in/out commitments). | Decide ownership. |
| D. Journal | Append-only WAL of transitions for audit and crash recovery. | Be the source of truth for the balance. |
| E. Slate engine | Pure slate crypto (`dom-slate`, extracted from v1). | Touch disk / persistence. |
| F. API | Orchestrate; expose balance and actions. | Re-implement crypto or reconciliation. |

**Key difference vs v1:** in v1 the rescan function **builds** `rebuilt_outputs`
and replaces `self.outputs`. In v2 the reconciler **iterates the store** (A) and
only changes `status`. The iteration direction is inverted: *store → chain*, not
*chain → store*.

---

## 2. Exact output store schema

### 2.1 On-disk layout (wallet directory)

Identical in spirit to the v1 `WalletDir` (`wallet_dir.rs`), versioned as v2:

```text
<walletdir>/
  config.json        # WalletV2Format marker, network, chain_id, format ver
  wallet.dat         # ENCRYPTED payload (this schema) — the Store layer
  journal.log        # append-only WAL (layer D) — one JSON line per entry
  wallet.lock        # exclusive lockfile (fs2), as in v1
  backups/           # rotated snapshots of wallet.dat
  logs/
```

### 2.2 Encrypted file format `wallet.dat`

Reuses the validated v1 envelope (`store.rs:390-477`), changing only the magic and
the payload version. The envelope **crypto does not change** — only its label:

```text
Header (64 bytes):
  magic   "DOM-WALLET-V2\0"  (14 bytes)   # distinct from v1 to reject v1 files
  version u16 LE             (2 bytes)    # envelope version = 1
  salt    32 bytes                        # fresh per save
  nonce   12 bytes                        # fresh per save
  pad     4 bytes
Payload: ChaCha20Poly1305( JSON(WalletV2State), key=Argon2id+HKDF(pw,salt) )
```

- KDF: **reuses** `unlock::derive_wallet_key` (Argon2id m=64MiB/t=3/p=1 →
  HKDF-SHA256, info `DOM:wallet-key:v1`) — `store.rs:375-382`. No reinvention.
- Atomic write: **reuses** the `<path>.tmp` → `sync_all` → `rename` → parent-dir
  fsync pattern (`store.rs:428-473`).
- The `V2` magic makes `load` reject v1 files by construction (principle 5).

### 2.3 Versioned payload `WalletV2State`

An explicit **schema** version inside the payload (independent of the envelope
version) to allow future in-place migration without changing the magic:

```text
WalletV2State {
  schema_version: u16,            # = 2; gate for future in-place migration
  network:        Network,        # Mainnet|Testnet|Regtest (mirror of config)
  chain_id:       [u8;32],        # magic XOR genesis; slate replay protection
  keychain:       KeychainV2,     # encrypted seed (only inside this payload)
  outputs:        Vec<StoredOutput>,   # <<< SOURCE OF TRUTH
  pending_slates: Vec<PendingSlate>,   # in-flight slates (sender and receiver)
  meta:           StoreMeta,      # cursors, last reconciled tip, digest
}
```

### 2.4 `StoredOutput` — the central record (exact fields and types)

Each wallet-owned output is **one** persisted record. The blinding is always
written, including the random ones.

| Field | Type | Meaning | Persisted? |
|---|---|---|---|
| `commitment` | `[u8;33]` | Compressed Pedersen. **Primary key.** | yes |
| `value` | `u64` | Value in noms. | yes |
| `blinding` | `Zeroizing<[u8;32]>` | Blinding factor. **Always persisted**, even random ones (change/receive). Zeroized on drop. | yes (encrypted) |
| `origin` | `OutputOrigin` | `Coinbase` \| `Change` \| `ReceiveSlate`. | yes |
| `status` | `OutputStatus` | State machine §3. | yes |
| `origin_block` | `Option<BlockRef>` | `{height:u64, hash:[u8;32]}` of the confirming block. `None` while `Unconfirmed`. | yes |
| `is_coinbase` | `bool` | Subject to maturity. | yes |
| `derivable` | `Option<DerivIndex>` | Derivation index if re-derivable from the seed (coinbase by height; receive-request by index). `None` for random blindings. **Metadata, not a retention condition.** | yes |
| `reserved_for` | `Option<[u8;32]>` | Slate hash that reserved this output as an input. Orthogonal to `status`. | yes |
| `created_at` | `u64` | Unix ts of local creation. | yes |
| `updated_at` | `u64` | Unix ts of the last transition. | yes |

Design notes (vs v1 `OwnedOutput`, `types.rs:36-58`):

- v1 uses `spent: bool` + removal from the index. v2 uses an **explicit `status`**
  and **never removes** an output that was ever canonical (see §3/§4). `spent`
  becomes the `Spent` state, not a flag that authorizes deletion.
- `blinding` keeps v1's `Zeroizing<[u8;32]>` + 32-byte serde (`types.rs:60-84`) —
  direct reuse.
- `derivable` is **traceability only**, for restore-from-seed (§7.4). Retention of
  an output **never** depends on it being derivable — that is exactly what breaks
  v1.

### 2.5 `PendingSlate` — in-flight slates (sender and receiver)

Consolidates v1's `PendingSendSlate(+Secrets)` and `PendingReceiveSlate(+Secrets)`
(`store.rs:288-362`) into a single enum, persisted only inside the encrypted
payload:

```text
PendingSlate {
  slate_hash:  [u8;32],          # key; blake2b_256(slate_bytes) of the phase
  role:        SlateRole,        # Sender | Receiver
  slate_bytes: Vec<u8>,          # PUBLIC slate data (no secrets)
  secrets:     SlateSecrets,     # ENCRYPTED; never goes to journal or exported slate
  reserved_inputs: Vec<[u8;33]>, # for Sender: reserved inputs
  produced_output: Option<[u8;33]>, # commitment of the local output this slate creates
  status:      SlateLifecycle,   # Built|Submitted|Finalized|Confirmed|Failed|Canceled
}

SlateSecrets =
  | Sender   { excess_blinding:[u8;32], nonce:[u8;32] }   # = PendingSendSlateSecrets
  | Receiver { output_blinding:[u8;32] }                  # = PendingReceiveSlateSecrets
```

`produced_output` is the link that makes the corresponding `StoredOutput` be born
`Unconfirmed` **at the moment of local creation** (change in `create_send`, the
recipient's output in `receive`). This guarantees the random blinding is in the
store **before** any block — the basis of the proof in §4.

### 2.6 `KeychainV2` and `StoreMeta`

```text
KeychainV2 {                         # = v1 WalletKeychainState (store.rs:188)
  seed_bytes: Option<Zeroizing<[u8;64]>>,  # BIP-39; only here, never the phrase
  seed_word_count: Option<u8>,             # v2 requires 24
  next_change_index: u32,
  next_receive_index: u32,
  account: u32,                            # v2 pins 0
}
StoreMeta {
  last_reconciled_tip: u64,          # highest height already reconciled
  last_reconciled_hash: Option<[u8;32]>,
  canonical_digest: [u8;32],         # digest of the set (drift detection)
}
```

### 2.7 Encrypted store export/import (recovery complementary to the seed) — H-1

**User recovery contract (documented, two layers):**

> The **seed** (24-word BIP-39) recovers the **derivable** outputs (coinbase by
> height). The **store backup** recovers the **non-derivable** outputs
> (receive-slate and change), whose blindings are random and — by Mimblewimble
> construction — **exist nowhere but the store**. The two layers are
> complementary, not redundant: with the seed alone you lose receive/change; with
> the backup alone you have everything up to the backup date.

H-1 is accepted as an inherent limitation: v2 **does not try to defeat it**, it
designs around it by making the store exportable safely.

#### 2.7.1 Export format — `wallet.dombak`

A **self-contained, encrypted** artifact, independent of the wallet directory's
password (to allow restoring on another machine/directory with its own backup
passphrase):

```text
Header (64 bytes):
  magic   "DOM-WALLET-BAK\0"  (15 bytes)   # distinct from wallet.dat
  version u16 LE              (2 bytes)     # backup envelope version = 1
  salt    32 bytes                          # fresh per export
  nonce   12 bytes
  pad     3 bytes
Payload: ChaCha20Poly1305( JSON(BackupV2Envelope), key=Argon2id+HKDF(passphrase,salt) )

BackupV2Envelope {
  schema_version: u16,            # = 2 (mirrors WalletV2State)
  exported_at:    u64,            # unix ts (informational)
  network:        Network,
  chain_id:       [u8;32],        # a backup imports only into a wallet of the SAME chain_id
  keychain:       KeychainV2,     # includes the encrypted seed — the backup is a seed superset
  outputs:        Vec<StoredOutput>,   # ALL, including non-derivable
  pending_slates: Vec<PendingSlate>,   # in-flight slates (to continue finalize after restore)
  meta:           StoreMeta,
  integrity:      [u8;32],        # blake2b_256 of the pre-encryption payload (truncation detection)
}
```

Notes:

- **Reuses the same crypto envelope** as `wallet.dat` (Argon2id m=64MiB/t=3/p=1 →
  HKDF-SHA256, ChaCha20Poly1305, atomic write + fsync). Only the magic and the
  passphrase change (the backup's, not the wallet's). No new crypto.
- The backup is a **superset of the seed**: it carries `keychain.seed_bytes`, so a
  single `.dombak` recovers everything (derivable + non-derivable). The seed alone
  remains valid as the minimal offline layer.
- `chain_id` in the envelope is checked on import — it rejects cross-chain (the
  same defense the slate already performs, `wallet.rs:1492`).

#### 2.7.2 Operations

```text
export_backup(store, passphrase) -> wallet.dombak     # atomic encrypted snapshot
import_backup(dombak, passphrase, target_dir, wallet_pw) -> WalletV2
```

`import_backup` (rule: **non-destructive merge by reconciliation**, not blind
overwrite):

```text
import_backup(bak, passphrase, dir):
  env := decrypt(bak, passphrase)                 # fail => wrong passphrase
  verify env.integrity == blake2b_256(payload)    # fail => corrupt backup
  if dir empty:
     materialize WalletV2State from env            # pure restore
  else (merge into an existing store of the SAME chain_id):
     for each out_bak in env.outputs:
        match store.get(out_bak.commitment):
          None        -> insert out_bak            # recovers a lost non-derivable output
          Some(out)   -> keep the more advanced STATUS per the order
                         Unconfirmed < Reorged < Confirmed < Spent
                         (never downgrade; blinding is identical per commitment)
  # after the merge, run reconcile(scan) to bring status up to the current tip (§4)
```

The status order in the merge respects **INV-RET**: the import never deletes nor
downgrades an output; it only **adds** what was missing (typically the
non-derivable outputs the seed cannot bring back). The subsequent `reconcile`
fixes any stale status from the backup against the current chain.

#### 2.7.3 Operational policy (recommended, non-blocking)

- **Automatic** export after every event that creates a non-derivable output
  (`finalize_slate` with change; confirmed `receive_slate`) — so the backup never
  lags behind funds unrecoverable by seed. The trigger and destination are a
  product decision (UI), outside this crate.
- The `.dombak` is a **new secret artifact**: product documentation must treat it
  with the same care as the seed. This trade-off was the axis of H-1 and is
  accepted.

---

## 3. Output state machine

`OutputStatus` is the piece that replaces v1's `spent: bool` + index removal pair.
**Reservation** (`reserved_for`) is orthogonal and is not a state.

```text
                       (local creation: coinbase/change/receive)
                                     │
                                     ▼
                              ┌─────────────┐
        tx canc/fail and  ┌───│ Unconfirmed │  output exists locally,
        NEVER confirmed   │   └──────┬──────┘  commitment not yet canonical
        (only deletion)   │          │ T1: commitment ∈ canonical_outputs
                          ▼          ▼
                      [DELETED]  ┌───────────┐
                                 │ Confirmed │◄──────────────┐
                                 └─────┬─────┘               │ T6: re-mined
                       T2: commitment  │  T3: origin block    │ (commitment back in
                       ∈ canonical_    │  leaves the chain     │  the canonical set)
                       inputs          │  (reorg)              │
                                       ▼                       │
                                 ┌───────────┐           ┌─────────┐
                                 │   Spent   │           │ Reorged │
                                 └─────┬─────┘           └────┬────┘
                       T4: spending    │                      │ T7: re-mined AND
                       block leaves    │                      │ then spent on the
                       the chain (spend│                      │ winning chain
                       reorg)          ▼                      ▼
                                 (back to Confirmed)       (to Spent)
```

### 3.1 Complete transition table

| ID | From | To | Trigger | Layer |
|---|---|---|---|---|
| C0 | — | `Unconfirmed` | Local output creation (locally mined coinbase; change in `create_send`; recipient output in `receive`) with the blinding already written. | F→A |
| T1 | `Unconfirmed` | `Confirmed` | Reconcile sees `commitment ∈ canonical_outputs(h)`; writes `origin_block={h,hash}`. | B |
| T2 | `Confirmed` | `Spent` | Reconcile sees `commitment ∈ canonical_inputs`. | B |
| T3 | `Confirmed` | `Reorged` | Reconcile/rollback: `origin_block.height > rollback_target` **or** `commitment ∉ canonical_outputs` and the origin block is no longer canonical. Blinding and value kept. | B |
| T4 | `Spent` | `Confirmed` | Reconcile sees the input that spent it **left** `canonical_inputs` and the commitment is back in `canonical_outputs` (spend reorg). | B |
| T5 | `Spent` | `Reorged` | Reconcile: both the spend **and** the origin left the chain (deep reorg). | B |
| T6 | `Reorged` | `Confirmed` | Reconcile sees `commitment ∈ canonical_outputs` again (same tx re-mined). Uses persisted material. **Kills WDSF-001.** | B |
| T7 | `Reorged` | `Spent` | Re-mined and already spent on the winning branch (`commitment ∈ canonical_inputs`). | B |
| D1 | `Unconfirmed` | **DELETED** | And **only** if the `PendingSlate` that produced it is terminally `Canceled`/`Failed` **and the output was never `Confirmed`**. The sole deletion path. | F/B |

### 3.2 Retention invariant (the heart of the fix)

> **INV-RET:** An output in `Confirmed`, `Spent`, or `Reorged` is **never** deleted
> and never loses its `blinding`. The only deletion is `D1`, restricted to an
> `Unconfirmed` that demonstrably was never canonical.

Reservation: `reserved_for` is set when an output becomes a slate input
(`create_send`) and released on confirm/cancel — exactly like v1's
`reserve`/`release_reservation` (`output_index.rs:133-159`), but never implying
deletion.

---

## 4. Rescan reconciliation algorithm (proof of WDSF-001/002)

### 4.1 Input and contract

`reconcile(store, scan_source)` where `scan_source: ChainScanSource` (reuses the
v1 trait, `restore.rs:146-156`, which yields per height `output_commitments`,
`input_commitments`, `block_hash`, `total_fees_noms`).

It builds **two canonical sets** by walking `0..=tip` (a single pass):

- `CANON_OUT: Map<[u8;33] → BlockRef>` — every canonical output commitment and the
  block where it appears.
- `CANON_IN: Set<[u8;33]>` — every commitment consumed as a canonical input.

### 4.2 Steps (status-only; iteration is STORE → chain)

```text
reconcile(store, scan):
  (CANON_OUT, CANON_IN) := walk scan from 0..=tip          # canonical read
  for each out in store.outputs:                           # ITERATES THE STORE
    present_out := CANON_OUT.get(out.commitment)
    spent       := CANON_IN.contains(out.commitment)

    match (out.status, present_out, spent):
      # confirmation / re-confirmation (T1, T6)
      (Unconfirmed|Reorged, Some(bref), false) -> out.status=Confirmed; out.origin_block=bref
      # canonical spend (T2, T7)
      (Confirmed|Reorged,    _,         true ) -> out.status=Spent
      # output reorg (T3, T5): was confirmed/spent, vanished from canonical
      (Confirmed,            None,      false) -> out.status=Reorged
      (Spent,                None,      false) -> out.status=Reorged
      # un-spend due to spend reorg (T4)
      (Spent,                Some(bref),false) -> out.status=Confirmed; out.origin_block=bref
      # no change
      _ -> keep

  # pending local creations that have not appeared yet remain Unconfirmed.
  # DELETION: only D1, applied by a separate GC over Unconfirmed orphaned of a
  # terminal PendingSlate — NEVER here.
  store.meta.last_reconciled_tip := scan.tip()
  store.save()                                             # atomic envelope
```

**What this algorithm does NOT do** (and v1 did):

- It does not reconstruct the output set by derivation.
- It does not create `rebuilt_outputs` nor run `self.outputs = rebuilt_outputs`.
- It does not consult "is it derivable?" to decide retention. `derivable` does not
  appear here.
- It does not depend on `pending_receive_candidates` to recognize an
  already-confirmed receive.

### 4.3 Complete proof that WDSF-002 cannot occur

WDSF-002 (v1): `Repair` replaces `self.outputs` with the derivation-reconstructed
set; a confirmed receive-slate or confirmed change (random blinding, no pending)
is in no reconstruction source → it is discarded (`wallet.rs:1182-1190`).

**Lemma (status-only does not reduce cardinality).** The `reconcile` loop (§4.2)
walks `store.outputs` and in each `match` arm only reassigns `status` (and
sometimes `origin_block`). No arm calls removal. The system's only removal is
`D1`, which belongs to a separate GC restricted to an `Unconfirmed` orphaned of a
terminal slate. ∴ `reconcile` preserves every output not exactly in `D1`. ∎

#### Scenario 1 — confirmed receive-slate survives 2 Repair rescans

Test: `robustness_confirmed_slate_receive_survives_subsequent_repair_rescan`.
State sequence of the recipient's `StoredOutput` (commitment `c_R`,
`blinding=x_R` random, `derivable=None`):

| Step | Event | `CANON_OUT(c_R)` | `c_R ∈ CANON_IN` | Transition | Final status | Blinding |
|---|---|---|---|---|---|---|
| 0 | `receive_slate` (local creation C0) | — | — | C0 | `Unconfirmed` | x_R written |
| 1 | block 2 mines the output → 1st `reconcile(Repair)` | `Some(h=2)` | no | T1 | **`Confirmed`** {2} | x_R |
| 2 | tip advances to empty block 3 → 2nd `reconcile(Repair)` | `Some(h=2)` (still in the UTXO set) | no | `_ -> keep` | **`Confirmed`** {2} | x_R |

In step 2, `derivable=None` is **not consulted** (it does not appear in §4.2). The
output is in `store.outputs`, `c_R` is still in `CANON_OUT` and out of `CANON_IN` →
the "keep" arm. `store.outputs().find(c_R)` returns `value=amount`, `spent=false`.
**Test assertion satisfied.** In v1, step 2 fell into
`self.outputs = rebuilt_outputs` without `c_R` → failure.

#### Scenario 2 — confirmed change survives a Repair rescan

Test (rewritten for Slate, §6.1): change `c_C` (`blinding=x_C` random,
`origin=Change`, `derivable=None`) produced by `create_send_slate` →
`finalize_slate`:

| Step | Event | `CANON_OUT(c_C)` | `c_C ∈ CANON_IN` | Transition | Final status |
|---|---|---|---|---|---|
| 0 | `create_send_slate` inserts change (C0) | — | — | C0 | `Unconfirmed` |
| 1 | block 2 mines the tx (inputs spent, outputs created) → `reconcile(Repair)` | `Some(h=2)` | no | T1 | **`Confirmed`** {2} |
| 2 | subsequent Repair rescan | `Some(h=2)` | no | `_ -> keep` | **`Confirmed`** {2} |

The coinbase input spent by the tx appears in `CANON_IN` and its own
`StoredOutput` goes to `Spent` (T2) — **retained**, not deleted (V-03). The change
stays `Confirmed` with `value = reward - amount - fee`. **Assertion satisfied.**

∴ In both scenarios, no `reconcile` arm discards an output for not being
re-derivable; by the Lemma, the store's cardinality never drops on a rescan.
WDSF-002 is **impossible by construction**, not by a point patch.

### 4.4 Complete proof that WDSF-001 cannot occur

WDSF-001 (v1): `rollback_to` removes outputs with `block_height > target`
(`wallet.rs:701-709`) and only reinstates **sender** pending; the recipient's
receive becomes a terminal `Received` journal status (does not rewind,
`journal.rs:587-643`) and the blinding vanishes → when the same tx is re-mined,
there is no candidate nor material to re-register it.

In v2, rollback is a status transition, not a removal:

```text
rollback_to(store, target):
  for each out in store.outputs:
    if out.origin_block.height > target:
      if out.status == Confirmed -> out.status = Reorged    # T3 (keeps blinding)
      if out.status == Spent     -> out.status = Reorged    # T5
    # outputs whose spend was above target: the input "comes back"
    # (handled by the next reconciliation via CANON_IN, T4)
  # no output is removed; no blinding is discarded
  store.save()
```

#### Complete state sequence — `robustness_slate_receive_survives_reorg_when_tx_is_remined`

Recipient's `StoredOutput` (commitment `c_R`, `blinding=x_R` random,
`origin=ReceiveSlate`):

| Step | Event | `c_R ∈ CANON_OUT` | `c_R ∈ CANON_IN` | Transition | Status | `origin_block` | Blinding |
|---|---|---|---|---|---|---|---|
| 0 | `receive_slate` (C0) | — | — | C0 | `Unconfirmed` | `None` | x_R |
| 1 | `apply_canonical_block(2, hash=0x02)` | `Some(2)` | no | T1 | `Confirmed` | {2, 0x02} | x_R |
| 2 | `rollback_to(1)` (reorg; `2 > 1`) | — | — | T3 | **`Reorged`** | {2, 0x02}* | **x_R kept** |
| 3 | `apply_canonical_block(2', hash=0xB2)` (SAME tx re-mined) | `Some(2')` | no | T6 | **`Confirmed`** | {2, 0xB2} | x_R |

\* In step 2 the output is **not removed** (a direct contrast with v1's
`wallet.rs:701-709`, which does `self.outputs.remove`). `value`, `commitment`, and
`x_R` stay intact; only `status` changes. In step 3, `reconcile`/`apply` finds
`c_R` in `CANON_OUT` again and applies T6 using the material **already in the
store** — no pending, no re-derivation. `store.outputs().find(c_R)` returns
`value=amount`. **Test assertion satisfied.**

Contrast with v1 at step 3: there, there was no `pending_receive_candidate` (the
journal's `Received` is terminal and does not rewind, `journal.rs:587-643`) nor a
recoverable persisted blinding → `apply_canonical_block` did not re-register the
output → failure. v2 depends on none of those paths.

#### Variant with restart (test V-01)

If there is a `WalletDir::open` between steps 2 and 3, the `Reorged{c_R, x_R}` is
persisted in `wallet.dat` (envelope §2.2); reopening reloads the store and step 3
proceeds identically. The audit's recommendation (restart variant) is covered with
no extra code — it is the same proof, since the state lives in the on-disk store,
not in volatile memory.

∴ Re-confirmation uses exclusively material **persisted** in the store; it depends
on neither pending nor re-derivation, whether or not it survives a restart.
WDSF-001 is **impossible by construction**.

### 4.5 Why the iteration inversion is sufficient

v1 asks "for each thing I know how to derive / that is pending, is it on the
chain?" — losing everything it cannot derive. v2 asks "for each output I **already
own and persisted**, what is its status on the chain?" — ownership was established
at local creation and is never re-derived. That is the difference that closes the
class.

---

## 5. What migrates from the current dom-wallet

Principle: **do not rewrite validated crypto**. The slate engine and primitives
are reused; what changes is only the persistence/reconciliation layer.

### 5.1 Reused as a **dependency** (no copy)

| Source | Items | How |
|---|---|---|
| `dom-tx::slate` (`crates/dom-tx/src/slate.rs`) | `Slate`, `OutputCommitmentAndProof`, serde `DomSerialize/DomDeserialize`, `to_bytes`/`from_bytes` | `dom-wallet2` depends on `dom-tx`. The slate struct is the wire format — zero copy. |
| `dom-crypto` | `bp_prove`, `schnorr_add_public_keys`, `schnorr_aggregate_sigs`, `Commitment`, `BlindingFactor`, `blake2b_256[_tagged]`, `PartialSig`, `RangeProof` (used at `wallet.rs:24-27`) | Direct dependency, same as v1. |
| `dom-consensus` | `validate_transaction_structure`, `validate_balance_equation` (`wallet.rs:21`) | Dependency; finalize's adversarial validation reused. |
| `dom-core` | `block_reward`, `COINBASE_MATURITY`, `Address`, kernel feats | Dependency. |

### 5.2 Extraction into the shared crate **`dom-slate`** (H-2 = single dependency)

Decision H-2: **one source of truth for the validated slate crypto**, consumed by
both v1 and v2. The logic today lives coupled to `Wallet` in `wallet.rs`; it is
**extracted into a new `dom-slate` crate** (not copied). v1 then calls `dom-slate`
instead of its inline copy; v2 is born already consuming `dom-slate`. No crypto
divergence is possible, since there is only one body of code.

#### 5.2.1 Extraction principle: separate pure crypto from I/O

The obstacle is that `create_send_slate`/`receive_slate`/`finalize_slate` today
**mix** three things: (i) slate crypto, (ii) coin selection, (iii) persistence
(input reservation, `pending_txs`, journal, `save`). The extraction isolates
**only (i)** into `dom-slate`, as **pure** functions (material in, `Slate`/
`Transaction`/error out; **no** access to disk, `Wallet`, journal, or store). (ii)
and (iii) stay in the wallet (v1 or v2) that orchestrates.

```text
crate dom-slate  (PURE, stateless, no I/O)
  ├─ re-exports dom_tx::slate::{Slate, OutputCommitmentAndProof}   # wire format
  ├─ build_send(inputs:&[InputMaterial], change:Option<ChangeReq>, amount, fee, chain_id)
  │      -> (Slate, SenderSecrets, Option<ChangeMaterial>)
  ├─ respond_receive(slate:Slate, recipient: RecvReq) -> (Slate, RecipientSecrets, OutputMaterial)
  ├─ finalize(slate:Slate, sender_secrets:&SenderSecrets) -> Transaction   # + validation
  ├─ helpers: sender_excess_blinding, aggregate, partial-sig verify
  └─ adversarial suite (migrated from wallet.rs §2799.. and tests/)

  depends on: dom-tx, dom-crypto, dom-consensus, dom-core, dom-serialization
  does NOT depend on: dom-wallet, dom-wallet2, std::fs, journal, store
```

Where:

- `InputMaterial = { commitment:[u8;33], value:u64, blinding:[u8;32] }` — the
  wallet assembles it from `StoredOutput` (v2) or `OwnedOutput` (v1); `dom-slate`
  knows neither.
- `SenderSecrets/RecipientSecrets` are exactly the contents of
  `PendingSendSlateSecrets`/`PendingReceiveSlateSecrets` (`store.rs:304-330`), but
  as `dom-slate` types (the wallet persists them in its own schema).
- `ChangeMaterial/OutputMaterial = { commitment, value, blinding, rangeproof }` —
  the wallet turns them into the `StoredOutput{Unconfirmed}` that goes to the store
  (C0).

#### 5.2.2 Migrated functions (identical crypto, I/O removed)

| v1 function (`crates/dom-wallet/src/wallet.rs`) | Role | Change in v2 |
|---|---|---|
| `create_send_slate` (`:1358`) | Selection, random change blinding, sender excess/nonce, builds `Slate`, reserves inputs, persists pending | Crypto identical → `dom-slate::build_send`. Persistence (reservation, pending, journal) rewritten for layers A/D. |
| `receive_slate` (`:1487`) | Validates chain_id/fields, creates recipient output+rangeproof, nonce, partial sig; persists only the blinding | Crypto identical → `dom-slate::respond_receive`. Now inserts `StoredOutput{ReceiveSlate, Unconfirmed}` into A + `PendingSlate{Receiver}`. |
| `finalize_slate` (`:1590`) | Reconstructs the sender slate, verifies sigs, aggregates, validates tx/structure/balance, returns `FinalizedSlate` | Crypto + validation identical → `dom-slate::finalize`. |
| helper `sender_excess_blinding` (`wallet.rs`) | Sender excess | → `dom-slate`, pure. |
| `build_coinbase` (`:2297`) | Wallet-owned coinbase (derivable blinding) | → wallet v2 (not `dom-slate`); inserts `StoredOutput{Coinbase, derivable=Some(height)}`. |
| finalize validation: `validate_transaction_structure`/`validate_balance_equation` (`wallet.rs:1700/1702`) | Adversarial validation of the aggregate tx | Called from inside `dom-slate::finalize` (depends on `dom-consensus`). |

Note: `seed::coinbase_blinding`/`spend_output_blinding` (`seed.rs:183/212`) and
`build_coinbase` do **not** go into `dom-slate` — they are wallet key derivation,
not slate crypto. They live in a shareable `seed`/`keychain` module apart (or stay
per-crate); `dom-slate` is strictly the interactive protocol.

#### 5.2.3 Extraction mechanics (order, without breaking v1)

1. Create `crates/dom-slate` with the pure types (§5.2.1) and move the **body** of
   the crypto functions from `wallet.rs` there, leaving pure signatures.
2. Rewrite the v1 methods (`Wallet::create_send_slate`, etc.) as **thin
   wrappers**: they select coins, call `dom-slate`, and do v1 persistence as
   today. v1's observable behavior is unchanged.
3. Move the slate **adversarial suite** (`wallet.rs` tests:
   `receive_slate_rejects_wrong_chain_id`, `adversarial_*`,
   `finalize_slate_end_to_end...`, `:2759..2905`) to `dom-slate/tests` or internal
   `#[cfg(test)]` — it now covers the single source.
4. v2 consumes `dom-slate` directly; never duplicates the crypto.

The "touch v1" risk (H-2's trade-off) is mitigated: step 2 is a mechanical
refactor covered by v1's existing tests + `dom-test-vectors`; it changes neither
consensus nor semantics. It is the accepted price for **zero crypto divergence**.

### 5.3 Does **NOT** migrate (legacy / forbidden by principle 4)

- `build_spend` / `build_spend_unreserved` (`wallet.rs:1737/1770`) — legacy
  non-slate path (WDSF-003). **Absent in v2.**
- Any `dom-wallet-app` payment-request UI (`app.rs`/`runtime.rs`).
- `wallet_send` / `wallet_create_receive` (already dead on the Tauri surface).

### 5.4 Reused with **redesign** (not copied verbatim)

- **Store** (`store.rs`): reuses the crypto envelope (KDF, AEAD, atomic write) but
  the **payload schema** is §2 (new). `V2` magic.
- **Journal** (`journal.rs`): the append-only WAL and the total replay (skip a
  corrupted line) are reused as a pattern; the event set is **adjusted** to
  reflect the §3 machine (no terminal `Received` that does not rewind — v2 does not
  need it because the store is the truth). The journal becomes **audit + crash
  recovery**, not the balance source of truth.
- **OutputIndex** (`output_index.rs`): coin selection and reservation reused; the
  `spent: bool`+`remove` semantics become `status` (§3) with no deletion of
  confirmed outputs.
- **ChainScanSource / ScanBlock / InMemoryChainScan** (`restore.rs:120-198`):
  **reused verbatim** — they are exactly the boundary the acceptance tests use.

### 5.5 Name resolution (H-3)

Findings confirmed in code, to avoid a false claim:

- `WalletVersion` (`wallet_dir.rs:79-84`) is an enum **internal to the v1 crate**
  written to the plaintext `config.json`. `V1` = legacy password-derived coinbase
  blinding (`WalletConfig::v1`, line 120); `V2` = seed-derived deterministic /
  BIP-39 (`WalletConfig::v2`, line 124), serialized as the string `"v2"`.
- Both `V1` and `V2` are the **same crate** (`dom-wallet`) and share the same
  `wallet.dat` payload magic `DOM-WALLET-V1\0` (`store.rs:62`). So
  `WalletVersion::V2` is **not** a separate wallet product — it is a
  derivation-scheme marker.

Consequence: the v2 product must reuse **neither** the `WalletVersion::V2` variant
**nor** the `"v2"` config string. Proposed non-colliding names:

| Concept | Name | Why it does not collide |
|---|---|---|
| New crate | `dom-wallet2` | Distinct crate name; v1 stays `dom-wallet`. |
| `wallet.dat` magic | `DOM-WALLET-V2\0` | Distinct from v1's `DOM-WALLET-V1\0`; `load` rejects v1 by construction. |
| `config.json` version | `WalletV2Format` enum, serialized `"v2-native"` | Distinct from v1's `WalletVersion::{V1,V2}` / `"v1"`,`"v2"`. The string `"v2-native"` cannot be confused with the existing `"v2"`. |
| Backup magic | `DOM-WALLET-BAK\0` | Distinct from both wallet files (§2.7.1). |
| Slate crate | `dom-slate` | New crate; no overlap. |

The v2 `config.json` reader recognizes only `"v2-native"`; presented with a v1
`"v1"`/`"v2"` config (or a v1 `wallet.dat` magic), it errors clearly and points to
the seed/backup migration path (§7.4).

---

## 6. Test plan

### 6.1 Acceptance criteria (design gate)

The **two defensive files that FAIL on v1 today**, ported to the v2 API and
**PASSING**:

| File (v1 origin) | Test | Finding covered |
|---|---|---|
| `tests/robustness_reorg_slate_receive.rs` | `robustness_slate_receive_survives_reorg_when_tx_is_remined` | WDSF-001 |
| `tests/robustness_rescan_nonderivable_outputs.rs` | `robustness_confirmed_slate_receive_survives_subsequent_repair_rescan` | WDSF-002 |
| `tests/robustness_rescan_nonderivable_outputs.rs` | `robustness_confirmed_change_survives_repair_rescan` | WDSF-002 |

Porting: the tests use `WalletDir::create`, `build_coinbase`, `create_send_slate`,
`receive_slate`, `finalize_slate`, `apply_canonical_block_with_hash`,
`rollback_to`, `rescan_canonical_chain(Repair)`, `outputs()`. The v2 API (§10.6)
exposes the same names/contracts, so the port is almost mechanical. **v2 is ready
for implementation review only when the three pass.**

Note on `robustness_confirmed_change_survives_repair_rescan`: on v1 it exercises
`build_spend` (legacy). On v2 the **change** is produced by the Slate flow
(`create_send_slate` → `finalize_slate`), so the test is **rewritten** to generate
change via slate, preserving the assertion: confirmed change survives a subsequent
Repair rescan.

### 6.2 Other tests (new v2 defensive)

| # | Test | Covers |
|---|---|---|
| V-01 | `reorg_then_restart_then_remine` | WDSF-001 variant with `WalletDir::open` between rollback and re-mining (audit recommendation). |
| V-02 | `repair_rescan_after_reopen` | WDSF-002 variant with reopen before the 2nd rescan. |
| V-03 | `spent_output_is_retained_not_deleted` | T2 keeps the output `Spent` (history), never deletes. |
| V-04 | `spend_reorg_unspends_input` | T4: reorg of the spending block returns the input to `Confirmed`. |
| V-05 | `unconfirmed_orphan_is_gc_only_when_pending_terminal` | D1: deletes only an `Unconfirmed` orphaned of a `Canceled`/`Failed` slate. |
| V-06 | `unconfirmed_that_later_confirms_is_not_gc` | D1 does not fire if a confirmation occurred. |
| V-07 | `reconcile_is_idempotent` | Reconciling N times over the same tip = no-op after the 1st. |
| V-08 | `reconcile_status_only_never_rebuilds_set` | Structural assertion: the store's cardinality never drops on reconcile. |
| V-09 | `blinding_persisted_roundtrip` | Save/load preserves a random blinding bit-for-bit (change and receive). |
| V-10 | `v2_load_rejects_v1_file` | The `V2` magic rejects a v1 `wallet.dat` (principle 5). |
| V-11 | `restore_from_seed_recovers_only_derivable` | Restore recovers only coinbase/receive-request; documents loss of randoms (§7.4 / §9). |
| V-12 | `backup_roundtrip_recovers_nonderivable` | Export then import recovers confirmed receive/change (§2.7). |
| V-13 | `backup_import_is_nondestructive_merge` | Import never downgrades/deletes; only adds missing outputs (§2.7.2). |
| V-14 | `backup_rejects_cross_chain` | Import rejects a backup of a different `chain_id`. |
| V-15 | `journal_replay_is_crash_total` | A truncated/corrupted line does not poison replay (inherited from `journal.rs`). |
| V-16 | `duplicate_receive_slate_is_idempotent` | Gap noted in audit §9 (adversarial). |
| V-17 | `double_finalize_is_safe` | A second finalize fails safely (audit §9). |
| V-18 | `dom_slate_adversarial_suite` | Port of v1's slate adversarial tests (wrong chain_id, missing fields, tampered amount/fee, slate from another wallet). |

### 6.3 Integration (non-blocking for the design; covers WDSF-004)

| # | Test (in `dom-integration-tests`) | Covers |
|---|---|---|
| I-01 | `two_wallet_slate_happy_path` | A creates, B responds, A finalizes, node accepts, block confirms, balances converge. |
| I-02 | `restart_after_submitted_before_confirmation` | Restart between submit and confirm. |
| I-03 | `rpc_failure_does_not_mark_submitted` | An RPC failure does not mark submitted. |
| I-04 | `e2e_reorg_remine_two_wallets` | WDSF-001 against a real regtest node. |

I-01..04 require a dedicated environment (the `env-blocked-wsl` notes in the
audit) → **[NEEDS HUMAN DECISION]** on provisioning heavy CI (§9).

---

## 7. Product migration plan

### 7.1 v1 ↔ v2 coexistence

- `dom-wallet` (v1) and `dom-wallet2` (v2) coexist in the workspace during the
  transition. v1 is **not** evolved (per the brief); it gets only critical
  security fixes if needed.
- `wallet-desktop` (Tauri) starts depending on `dom-wallet2` behind a **build
  flag** (`--features wallet-v2`) for parallel validation before the default
  switch.

### 7.2 Versioning

- The `dom-wallet2` crate starts at `0.1.0` (does not inherit v1's `0.3.x`).
- `config.json.version = "v2-native"` via the new `WalletV2Format` enum — distinct
  from the existing `WalletVersion::{V1,V2}` in v1 (`wallet_dir.rs:79`). See §5.5
  for the full name resolution (H-3).
- The `wallet.dat` magic `DOM-WALLET-V2\0` rejects v1 files by construction.

### 7.3 Substitution

1. Phase A — `dom-wallet2` + `dom-slate` in the workspace, §6.1 tests green, no UI.
2. Phase B — `wallet-desktop` points at v2 behind the feature flag; manual QA.
3. Phase C — v2 becomes the default; v1 marked `deprecated`; the legacy
   `dom-wallet-app` removed/hidden from the release (closes WDSF-003).
4. Phase D — removal of v1 from the official release (kept in history).

**Status (2026-07-01):**

- Phase A — ✅ done.
- Phase B — ✅ done, stronger than planned: the desktop's user-wallet engine is
  `dom-wallet2` unconditionally (no feature flag), driven end-to-end through
  `RpcChainSource` (RB-WALLET2-RPC-SOURCE resolved).
- Phase C — 🔧 partial. v2 is the desktop default and v1 is now marked
  deprecated (doc-level, `crates/dom-wallet/src/lib.rs`). Remaining item:
  `dom-wallet-app` still ships as the wallet UI of the **Windows portable
  package** (`packaging/windows/portable/`) — removing/hiding it requires a
  product decision on what replaces it there (Tauri desktop or node-only
  package). NEEDS HUMAN DECISION.
- Phase D — not started. v1 is still consumed by `dom-node` (coinbase build,
  canonical rescan — a deliberate fail-closed policy) and by the desktop
  registry/seed types; those must be re-homed before v1 can leave the release.

### 7.4 Data migration (user)

- **Two complementary paths** (see §2.7 for the contract):
  - **Seed phrase** (BIP-39, 24 words): recovers **derivable** outputs only
    (coinbase by height; deterministic receive-request). Random-blinding outputs
    (change, receive-slate) are **not** recoverable by seed alone — an inherent
    Mimblewimble limitation.
  - **Encrypted store backup** (`wallet.dombak`, §2.7): recovers the
    non-derivable outputs (and, being a seed superset, everything else too).
- v2 **does not** read v1 `wallet.dat` (distinct magic, principle 5). A user
  leaving v1 migrates by importing their seed and, for non-derivable funds, must
  have a v1-era export — see H-1 in §9 for the residual gap for users who never
  exported.

---

## 8. Journal events (layer D) — adjustment vs v1

The journal stays an append-only WAL with total replay (reuse of `journal.rs`),
but it **stops being the balance source of truth** (the store is). v2 events:

```text
OutputEvent { commitment, event, ts }
  event =
    | Created   { origin, value }              # C0
    | Confirmed { block: BlockRef }            # T1/T6/T4
    | Spent     { in_block: BlockRef }         # T2/T7
    | Reorged   { rollback_to: u64 }           # T3/T5
    | GcDropped { reason }                      # D1
SlateEvent  { slate_hash, lifecycle, ts }      # Built|Submitted|Finalized|Failed|Canceled
```

Critical difference vs v1: there is **no terminal `Received`** that does not
rewind (`journal.rs:320-335`). On v2 a confirmed receive is a normal
`StoredOutput` that `Reorged`/`Confirmed` rewinds via the store. The journal only
**describes** the transitions; the store + reconcile **decide**. Crash recovery:
on open, reconcile runs against the last tip and the journal serves to detect
transitions lost between the last save and the crash.

---

## 9. Risks and open questions

### 9.1 Resolved (revision 2)

| # | Question | Decision |
|---|---|---|
| H-1 | Random-blinding recovery by seed alone | **ACCEPTED as an inherent MW limitation.** Do not try to defeat it. The store gains an encrypted export/import (`wallet.dombak`, §2.7) as recovery complementary to the seed. Two-layer user contract documented. Residual gap: a user who loses the device **and** never exported a backup loses non-derivable funds — surfaced as a product-documentation requirement, not a code bug. |
| H-2 | Shared slate crate vs copy | **SHARED DEPENDENCY.** Extract slate crypto into a new `dom-slate` crate consumed by v1 and v2 (§5.2). Single source of truth for the validated crypto. The v1 refactor (thin wrappers) is covered by existing tests + `dom-test-vectors`. |
| H-3 | Version-label collision | **CONFIRMED** `WalletVersion::V2` is only a v1-internal schema marker (§5.5). New names defined: crate `dom-wallet2`, magic `DOM-WALLET-V2\0`, config `"v2-native"`, backup `DOM-WALLET-BAK\0`, crate `dom-slate`. No reuse of the existing label. |
| H-4 | Heavy CI (WDSF-004) | **ACCEPTED as debt; does NOT block v2.** Validation = unit + light integration + the 3 defensive acceptance tests (§6.1) passing. The heavy E2E harness (I-01..04, §6.3) is parallel infra, run on the VPS when available. |
| H-5 | GC policy (D1) | **NO garbage collection for now.** `Spent`/`Reorged` outputs are retained indefinitely (metadata is cheap; INV-RET above all). Logged as future/low-priority — any future policy is **archival, NEVER deletion that loses a blinding**. In practice D1 is therefore dormant in v0; an `Unconfirmed` orphan is hidden from the balance, not deleted. |
| H-6 | `Reorged` finality / "final" UI label | **DECIDED: three tiers + `Settled` badge.** Retention is unconditional (INV-RET) regardless of depth — a `Reorged` is never auto-forgotten; labels are confidence presentation, never a retention condition. Wallet-side constant `WALLET_FINALITY_DISPLAY_DEPTH = 100` in `dom-wallet2` (NOT consensus). Tiers: `0 -> "Pending"`, `1..=99 -> "Confirming (N)"`, `>= 100 -> "Final"`, `>= 1000 -> "Settled"` badge (the reorg-impossible point per `MAX_REORG_DEPTH_POLICY`). Rationale: 100 = 10× margin under both the worst-case reorg bound and maturity, without the ~1.4-day wait; "Settled" at 1000 honestly exposes the only policy-guaranteed (non-probabilistic) finality level for power users. Data in §9.2. |

### 9.2 H-6 supporting data (confirmed in code)

| Datum | Value | Source |
|---|---|---|
| (a) Max reorg depth | `MAX_REORG_DEPTH_POLICY = 1000` — a **policy** cap (not consensus); reorgs deeper than 1000 are rejected to prevent DoS. Also bounds retained side-branch length. No empirically *observed* depth is recorded in code — it is a cap, not a measurement. | `dom-core/src/constants.rs:297`; enforced `dom-chain/src/reorg.rs:88-100`; `dom-chain/src/chain_state.rs:34-35,1043,1742` |
| (b) Coinbase maturity | `COINBASE_MATURITY = 1000` (CONSENSUS), "≈1.4 days at 2-minute blocks". Regtest = 1 (dev-only). | `dom-core/src/constants.rs:181`, `:286`; invariant test `:615` |
| Block spacing | `TARGET_SPACING = 120 s` (2 min). | `dom-core/src/constants.rs:15` |

Reasoning (recorded). The deepest a reorg may *legally* go equals the maturity
window (`MAX_REORG_DEPTH_POLICY == COINBASE_MATURITY == 1000`). So an output at
depth ≥ 1000 is final in the strongest sense the protocol allows — but a coinbase
isn't even spendable until 1000 deep, so 1000 is far too conservative for the
ordinary *display* label on a receive. Since the label is only a confidence level
shown in the UI and **not** a retention condition (retention is guaranteed by
INV-RET at any depth), the "Final" threshold sits well below maturity, with a
separate "Settled" badge exposing the policy-guaranteed point.

Decided — a **wallet-side display constant** (lives in `dom-wallet2`, not
consensus; changing it never risks funds):

```text
WALLET_FINALITY_DISPLAY_DEPTH = 100   # blocks; ≈ 100 * 120 s ≈ 3.3 hours

UI confidence tiers (display only):
  confirmations == 0            -> "Pending"
  1 ..= 99                      -> "Confirming (N)"
  >= 100                        -> "Final"
  >= 1000                       -> "Settled" badge (reorg-impossible per policy)
```

- 100 is **10×** below the worst-case policy reorg bound (1000) and 10× below
  maturity — a comfortable margin while not making users wait the full ~1.4-day
  maturity window.
- The "Settled" badge at 1000 honestly exposes the only policy-guaranteed
  (non-probabilistic) finality level for power users.
- This constant does **not** appear anywhere in the retention/reconcile logic
  (§3/§4). It is read only by the balance/age presentation. `Reorged` outputs are
  retained forever per H-5.

### 9.3 Implementation risks (non-merit; mitigable by engineering)

- **Reconcile cost O(tip)**: the walk is per height; for large tips, use
  `last_reconciled_tip` and reconcile incrementally (only new blocks) in normal
  operation, full-scan only on Repair.
- **store+journal atomicity**: keep the WAL order (journal append → mutation →
  save) as in v1 (`wallet.rs:2124-2143`).
- **Backup secrecy**: `wallet.dombak` is a second secret artifact (H-1); product
  must document handling. Mitigation is documentation + an optional strong
  passphrase, not code.

---

## 10. Rust type skeleton (design — NOT compiled, no implementation)

> `struct`/`enum`/signatures only, to pin contracts. No function body, no
> production logic. Does not create the crate.

```rust
// ── layer A: store ─────────────────────────────────────────────────
pub enum OutputOrigin { Coinbase, Change, ReceiveSlate }

pub enum OutputStatus { Unconfirmed, Confirmed, Spent, Reorged }

pub struct BlockRef { pub height: u64, pub hash: [u8; 32] }

pub enum DerivIndex { Coinbase { height: u64 }, Receive { index: u32 } }

pub struct StoredOutput {
    pub commitment:   [u8; 33],
    pub value:        u64,
    pub blinding:     zeroize::Zeroizing<[u8; 32]>, // ALWAYS persisted
    pub origin:       OutputOrigin,
    pub status:       OutputStatus,
    pub origin_block: Option<BlockRef>,
    pub is_coinbase:  bool,
    pub derivable:    Option<DerivIndex>,           // metadata, not retention
    pub reserved_for: Option<[u8; 32]>,
    pub created_at:   u64,
    pub updated_at:   u64,
}

pub enum SlateRole { Sender, Receiver }
pub enum SlateLifecycle { Built, Submitted, Finalized, Confirmed, Failed, Canceled }
pub enum SlateSecrets {
    Sender   { excess_blinding: [u8; 32], nonce: [u8; 32] },
    Receiver { output_blinding: [u8; 32] },
}
pub struct PendingSlate {
    pub slate_hash:      [u8; 32],
    pub role:            SlateRole,
    pub slate_bytes:     Vec<u8>,
    pub secrets:         SlateSecrets,
    pub reserved_inputs: Vec<[u8; 33]>,
    pub produced_output: Option<[u8; 33]>,
    pub status:          SlateLifecycle,
}

pub struct KeychainV2 {
    pub seed_bytes:         Option<zeroize::Zeroizing<[u8; 64]>>,
    pub seed_word_count:    Option<u8>,
    pub next_change_index:  u32,
    pub next_receive_index: u32,
    pub account:            u32,
}
pub struct StoreMeta {
    pub last_reconciled_tip:  u64,
    pub last_reconciled_hash: Option<[u8; 32]>,
    pub canonical_digest:     [u8; 32],
}
pub struct WalletV2State {
    pub schema_version: u16,           // = 2
    pub network:        Network,       // reuse of dom-wallet::Network
    pub chain_id:       [u8; 32],
    pub keychain:       KeychainV2,
    pub outputs:        Vec<StoredOutput>,
    pub pending_slates: Vec<PendingSlate>,
    pub meta:           StoreMeta,
}

// ── layer A: encrypted export/import (H-1) ──────────────────────────
pub struct BackupV2Envelope {
    pub schema_version: u16,           // = 2
    pub exported_at:    u64,
    pub network:        Network,
    pub chain_id:       [u8; 32],
    pub keychain:       KeychainV2,    // seed superset
    pub outputs:        Vec<StoredOutput>,
    pub pending_slates: Vec<PendingSlate>,
    pub meta:           StoreMeta,
    pub integrity:      [u8; 32],
}

// ── layer B/C: reconciliation (reuses ChainScanSource/ScanBlock from v1) ──
pub enum ReconcileMode { Verify, Repair }
pub struct ReconcileSummary {
    pub scanned_tip:   u64,
    pub confirmed:     usize,
    pub spent:         usize,
    pub reorged:       usize,
    pub gc_dropped:    usize,
    pub total_outputs: usize, // INV: never decreases on reconcile (only via D1)
}

// ── layer D: journal (reuses v1's WAL/total replay) ─────────────────
pub enum OutputJournalEvent {
    Created   { origin: OutputOrigin, value: u64 },
    Confirmed { block: BlockRef },
    Spent     { in_block: BlockRef },
    Reorged   { rollback_to: u64 },
    GcDropped { reason: String },
}

// ── layer E: dom-slate (pure, extracted from v1) ────────────────────
pub struct InputMaterial { pub commitment: [u8; 33], pub value: u64, pub blinding: [u8; 32] }
pub struct ChangeReq     { pub value: u64 }
pub struct RecvReq       { pub amount: u64 }
pub struct OutputMaterial { pub commitment: [u8; 33], pub value: u64,
                            pub blinding: [u8; 32], pub rangeproof: Vec<u8> }
// build_send / respond_receive / finalize — signatures in §5.2.1; bodies migrated
// verbatim (crypto) from wallet.rs, I/O removed.

// ── layer F: API (same names/contracts as the acceptance tests) ─────
pub struct WalletV2 { /* store + journal + scan handle (private) */ }

impl WalletV2 {
    // lifecycle
    pub fn create(/* path, pw, network, genesis */) -> Result<Self, WalletError> { unimplemented!() }
    pub fn open(/* path, pw */) -> Result<Self, WalletError> { unimplemented!() }
    pub fn restore_from_phrase(/* phrase, pw, dir, network, genesis, scan */)
        -> Result<Self, WalletError> { unimplemented!() }

    // encrypted backup (H-1)
    pub fn export_backup(&self, passphrase: &str, out: &std::path::Path)
        -> Result<(), WalletError> { unimplemented!() }
    pub fn import_backup(/* dombak, passphrase, dir, wallet_pw */)
        -> Result<Self, WalletError> { unimplemented!() }

    // slate (engine via dom-slate; v1-validated crypto)
    pub fn create_send_slate(&mut self, amount: u64, fee: u64, height: u64)
        -> Result<dom_tx::slate::Slate, WalletError> { unimplemented!() }
    pub fn receive_slate(&mut self, slate: dom_tx::slate::Slate, height: u64)
        -> Result<dom_tx::slate::Slate, WalletError> { unimplemented!() }
    pub fn finalize_slate(&mut self, slate: dom_tx::slate::Slate, height: u64)
        -> Result<FinalizedSlate, WalletError> { unimplemented!() }

    // chain (status-only reconciliation)
    pub fn apply_canonical_block_with_hash(
        &mut self, txs: &[Transaction], height: u64, hash: Option<[u8; 32]>,
    ) -> Result<(), WalletError> { unimplemented!() }
    pub fn rollback_to(&mut self, target_height: u64) -> Result<(), WalletError> { unimplemented!() }
    pub fn reconcile<S: ChainScanSource>(&mut self, scan: &S, mode: ReconcileMode)
        -> Result<ReconcileSummary, WalletError> { unimplemented!() }

    // reads
    pub fn outputs(&self) -> impl Iterator<Item = &StoredOutput> { std::iter::empty() }
    pub fn balance(&self, height: u64) -> WalletBalance { unimplemented!() }
}
```

---

## 11. Fix summary (one page)

| Axis | v1 (broken) | v2 (fixed) |
|---|---|---|
| Source of truth | Set reconstructible by derivation | Persisted output store |
| Random blinding | Lives only in the index/pending; vanishes on rescan/reorg | Persisted per output, always |
| Rescan | Rebuilds and replaces `self.outputs` | Reconciles STATUS, iterates the store |
| Reorg | Removes output; receive becomes terminal `Received` | `Confirmed→Reorged` (keeps material), re-mine → `Confirmed` |
| Deletion | Implicit in rescan/rollback | Only D1 (`Unconfirmed` terminal orphan) |
| Recovery | Seed only (loses non-derivable) | Seed (derivable) + encrypted store backup (non-derivable) |
| Slate crypto | Inline in `wallet.rs` | Shared `dom-slate` crate (one source of truth) |
| WDSF-001 | Fails | Impossible by construction (§4.4) |
| WDSF-002 | Fails | Impossible by construction (§4.3) |
| Legacy | `build_spend`/payment-request active | Absent (Slate only) |

**Next step:** human review of this design and of the open decisions H-4..H-6
(§9.2). After approval: create `dom-slate` + `dom-wallet2`, port the 3 acceptance
tests (§6.1), and only then implement layers A→F.
