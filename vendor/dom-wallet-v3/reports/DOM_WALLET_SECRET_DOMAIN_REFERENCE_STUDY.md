# DOM Wallet Secret-Domain Reference Study

**Status:** COMPLETE
**Wallet input commit:** `d1b53d552397c6da8f9b0e03f0bfefd4d8855d6a`
**Pinned DOM commit:** `aa7f389a157af1b1a486dcb7e27cb80e7b543de3`
**Study date:** 2026-07-11
**Final verdict:** DOM_WALLET_SECRET_DOMAIN_REFERENCE_STUDY_COMPLETE

## Method and repository integrity

DOM source was read only through immutable Git objects at the pinned commit: `git ls-tree`, `git grep <pattern> <commit>`, and `git show <commit>:<path>`. No DOM working-tree source was read, and no DOM command mutated its working tree. Before evidence collection the DOM repository was at `aa7f389a157af1b1a486dcb7e27cb80e7b543de3` on `audit/final-prelaunch-security-gate`; its index hash was the empty-tree hash, its tracked-change, untracked-file, and complete-status hashes were captured. The same values were rechecked after study.

Primary DOM evidence includes `crates/dom-wallet-crypto/src/lib.rs`, `crates/dom-wallet-keys/src/{seed.rs,hd_wallet.rs}`, `crates/dom-wallet2/src/{backup.rs,keychain.rs,payment.rs,pending.rs,persist.rs,state.rs,store.rs,types.rs,wallet_state.rs}`, the V1 `crates/dom-wallet/src/{backup.rs,journal.rs,seed.rs,store.rs,unlock.rs,wallet.rs}`, the Tauri desktop tree, and their pinned tests. Epic was not reopened; [the committed Epic study](EPIC_SECRET_DOMAIN_REFERENCE_STUDY.md) is secondary evidence only.

## Executive conclusion

DOM Wallet V2 supplies valuable DOM-native continuity: DOM fund/slate compatibility, encrypted versioned envelopes, atomic file publication, explicit pending context, retry-before-wipe behavior, chain-aware backup import, and full-backup state capture. It does not prove a unified V3 secret-domain construction for private contexts, backup, authentication, Tauri sessions, and cross-purpose binding. V1 also retains explicit weaknesses that V3 must reject. Therefore DEC-V3-SECRET-DOMAINS remains BLOCKING and requires independent cryptographic review.

This study records 11 validated DOM properties to preserve, 8 confirmed DOM weaknesses or V3 evidence gaps to replace through review, and 8 refuted historical concerns for the evidenced scope. A refutation does not broaden an existing construction beyond its pinned scope.

## Tauri product and security boundary findings

`wallet-desktop/src-tauri/tauri.conf.json:3-10` defines `DOM Wallet`, `org.domprotocol.wallet`, and frontend distribution `../ui`. `wallet-desktop/src-tauri/src/lib.rs:1449-1485` registers the command bridge. `wallet-desktop/ui/src/api.js:30-114` maps onboarding, unlock, balance, slate, backup, and node actions; `ui/src/screens.js:11-13` keeps passwords and phrases out of its shared frontend settings object; `api.js:66-68` returns only non-sensitive registry information; `api.js:81-100` keeps normal vault paths and backup dialogs in the backend.

Classification: **VALIDATED_DOM_PROPERTY_TO_PRESERVE** for Tauri product continuity and secret-minimizing presentation; **DOM_CONSTRUCTION_REQUIRING_REVIEW_BEFORE_REUSE** for the existing command bridge, which is not a V3 capability model. V3 retains Tauri, DOM flows, DOM visual identity, and native platform integration, while replacing backend coupling behind least-privilege capability APIs.

## Wallet V1 findings

| Mechanism | Evidence and classification | V3 disposition |
| --- | --- | --- |
| Legacy coinbase | `crates/dom-wallet/src/wallet.rs:2102-2152` documents a password-derived legacy fallback while preferring encrypted BIP-39 seed material | **LEGACY_DOM_COMPATIBILITY_BEHAVIOR**; preserve only migration evidence, reject as new V3 derivation authority |
| V1 receive request | `types.rs:269-281` includes public `blinding_hex` | **CONFIRMED_DOM_WEAKNESS_TO_REJECT**; never expose a private blinding through UI, API, logs, or identifiers |
| V1 backup | `backup.rs:171-220` derives an encryption key directly from password hashing before AEAD | **CONFIRMED_DOM_WEAKNESS_TO_REJECT** as a V3 password-protection baseline; do not reuse |
| Journal | `journal.rs:721-751` uses chain-bound distinct journal MAC/encryption derivation and canonical entry bytes; restart tests at `1337-1368` | **VALIDATED_DOM_PROPERTY_TO_PRESERVE** for durable lifecycle evidence and canonical authenticated records; construction requires review before reuse |
| Pending slate secrets | `store.rs:295-351` says sender secrets are encrypted payload-only and nonce is single-use | **VALIDATED_DOM_PROPERTY_TO_PRESERVE** for lifecycle containment, not for a new construction |

## Wallet V2 findings

| Mechanism | Pinned evidence | Classification and consequence |
| --- | --- | --- |
| Shared encrypted envelope | `dom-wallet-crypto/src/lib.rs:1-29, 88-211, 214-293` defines a versioned envelope, fixed KDF parameters, fresh per-save salt/nonce, opaque zeroizing key, typed errors, atomic temp-write/fsync/rename publication | **DOM_CONSTRUCTION_REQUIRING_REVIEW_BEFORE_REUSE**; preserve password-hardening, integrity, versioning, zeroization and atomicity properties, but do not extend the construction to V3 domains without approval |
| Envelope rejection | `lib.rs:214-254` rejects short, bad-magic and unsupported-version data before decrypting and rejects tampering/wrong passwords through typed decryption failure | **VALIDATED_DOM_PROPERTY_TO_PRESERVE** for fail-closed parsing |
| Backup and chain binding | `dom-wallet2/src/backup.rs:38-113, 139-172` defines magic, schema/kind, chain ID, complete wallet-state backups, and typed `ChainMismatch` | **VALIDATED_DOM_PROPERTY_TO_PRESERVE** for complete backup and wrong-chain rejection; V3 must add reviewed wallet/purpose binding and rollback semantics |
| Seed-only limit | `keychain.rs:153-159, 328-373` limits seed recovery to derivable coinbase; random receive/change material requires store/backup | **VALIDATED_DOM_PROPERTY_TO_PRESERVE** and required UX truthfulness |
| Sender private context | `payment.rs:131-199` creates a pending sender slate with zeroizing excess/nonce and reservations; `307-372` leaves secrets retryable on crypto failure and wipes them only after successful finalize | **VALIDATED_DOM_PROPERTY_TO_PRESERVE** for persistence-before-completion, retry stability and terminal wipe |
| Receiver private material | `payment.rs:254-301` records random recipient output blinding and pending receiver context after successful slate processing | **VALIDATED_DOM_PROPERTY_TO_PRESERVE** for durable local material; its domain construction remains unapproved |
| Restart/resubmit | `payment.rs:361-372, 393-440` preserves public finalized bytes after wiping secrets and supports submission after restart | **VALIDATED_DOM_PROPERTY_TO_PRESERVE** for lifecycle separation |
| DOM fund derivation | `dom-wallet-keys/tests/shield_v1v2_derivation_xdiff.rs:6-31, 67-80` and `shield_blinding_collisions_proptest.rs:38-90` establish shared V1/V2 deterministic derivation and reject high-bit aliases | **VALIDATED_DOM_PROPERTY_TO_PRESERVE** for authoritative compatibility; not a grant to derive new V3 purposes |

## Confirmed and refuted risk review

| Risk | Verdict | Pinned evidence | V3 consequence |
| --- | --- | --- | --- |
| Seed-independent coinbase blinding | CONFIRMED for legacy V1 compatibility path | `dom-wallet/src/wallet.rs:2102-2152` documents password-derived fallback | Reject as new V3 behavior; preserve only explicit migration handling |
| `blinding_hex` secret exposure | CONFIRMED | `dom-wallet/src/types.rs:269-281` | Reject; Tauri/API responses never include blindings |
| Missing chain binding | REFUTED for V2 backup/slate operations | `dom-wallet2/src/backup.rs:79-81,102-104,153-160`; `payment.rs:260-262,360` | Preserve chain checking; reviewer must define V3 cross-domain binding |
| Weak backup protection | CONFIRMED for V1 legacy backup | `dom-wallet/src/backup.rs:171-220` | Reject as V3 baseline |
| Non-atomic encrypted persistence | REFUTED for shared V1/V2 envelope | `dom-wallet-crypto/src/lib.rs:257-293` | Preserve atomic publication property |
| Derivation rollback protection | CONFIRMED as V3 evidence gap | Pinned V1/V2 source proves derivation compatibility but no authenticated monotonic non-reuse witness was located in the inspected wallet-state/backup paths | V3 must define reviewed non-reuse floors and restore/migration behavior |
| Secret-domain collision | CONFIRMED as V3 evidence gap | Existing envelope has one wallet-key HKDF context; no unified V3 private-context/backup/auth-domain model is defined | Independent review required |
| Lost context before finalization | REFUTED for V2 in-memory lifecycle, with persistence integration still needing V3 proof | `payment.rs:131-199,307-372` persists context in `WalletV2State` for caller persistence and retains it on crypto failure | Preserve the property; V3 must make durable unit ordering normative |
| Reuse after retry | REFUTED for V2 finalize retry path | `payment.rs:314-315,332-333` retains the same context on failure; `367-370` wipes only on success | Preserve retry stability and terminal wipe; add V3 non-reuse evidence |
| Unbounded KDF parameters | REFUTED for the shared current envelope | `dom-wallet-crypto/src/lib.rs:88-108,145-164` pins KDF parameters in code | Preserve resource-bound policy; reviewer decides V3 profile scope |
| Unauthenticated encryption | REFUTED for shared current envelope | `lib.rs:18,64-69,214-254` uses an AEAD and typed tamper failure | Preserve integrity property; construction scope requires review |
| Missing associated data | CONFIRMED for the displayed shared envelope call shape | `lib.rs:186-211,244-252` uses direct AEAD byte calls and the header is checked outside the AEAD payload; no AAD payload use was found in the pinned source | Reviewer must decide V3 binding/AAD semantics |
| Wrong-chain acceptance | REFUTED for V2 backup import | `backup.rs:79-81` plus chain-ID payload/import validation | Preserve fail-closed mismatch behavior |
| Secret leakage through logs/APIs | CONFIRMED for V1 receive representation; REFUTED for selected Tauri frontend state | V1 `blinding_hex`; Tauri `screens.js:11-13`, `api.js:66-68` | Reject V1 exposure; enforce V3 backend redaction |
| Backend rollback detection | CONFIRMED as V3 evidence gap | Atomic replacement exists, but no authenticated external/monotonic rollback witness was found in the examined envelope/state paths | V3 must retain DEC-ROLLBACK-PROTECTION policy and reviewed non-reuse evidence |
| Incomplete full backup | REFUTED for V2 full-backup API; CONFIRMED for seed-only limits | `backup.rs:139-160`; `keychain.rs:153-159` | Preserve full state backup, state limits explicitly |

## Canonical encoding, authentication, and evidence gaps

The pinned DOM source has canonical transaction/slate byte APIs and typed envelope-header validation, but it does not provide one approved canonical encoding for all V3 secret-domain contexts. It also does not establish a unified account/wallet/participant/purpose binding for non-fund domains, a reviewed Tauri command-session capability token, a V3 authentication-root construction, or an authenticated rollback witness. Those are gaps, not a license to invent parameters.

Authentication and node controls exist as separate desktop responsibilities (`wallet-desktop/src-tauri/src/node_rpc.rs`, `node_host.rs`, and the command bridge), but no DOM evidence identifies a unified approved cryptographic relationship to fund material. V3 must preserve operational separation and obtain reviewer approval before defining secrets or derivations.

## Epic gap-solving comparison

The completed Epic study found no unified Epic secret-domain framework and therefore no direct construction to adopt. It corroborates the V2 protected lifecycle properties—persist context before dependent effects, retry with the retained context, delete/wipe after completion, keep authentication operationally separate, and test hostile input/recovery. Epic UI, APIs, transport, formats, labels, KDFs, and crypto are excluded.

## Implications for Options A, B, and C

Option A can retain validated V2 properties but requires replacement of all confirmed weaknesses and independent approval for missing domains. Options B and C can only proceed through reviewer-specified constructions. None is selected; DEC-V3-SECRET-DOMAINS remains BLOCKING with ownership CRYPTOGRAPHIC_REVIEW and severity HIGH.
