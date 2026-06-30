# DOM — Genesis Ceremony Procedure

Status: pre-launch procedure. Executed once at the moment of mainnet launch; the artefacts it produces are consensus-immutable.

Author: Soren Planck.

---

## 0. Model substitution notice (conscious, dated decision — 2026-06-29)

This document REPLACES an earlier version that required, as hard preconditions to seal mainnet: a public adversarial testnet (≥90 days), an external fuzz campaign (≥10,000 CPU-hours), a full external audit, and a public bug bounty (≥30 days), plus a panel of named external witnesses signing the ceremony transcript.

Those preconditions have been **consciously and deliberately replaced** — not silently dropped, and not because they were "wrong." The DOM project adopts a different validation model, and this section records the trade openly so the historical record shows deliberation, not oversight:

- **External validation gates → internal validation via dom-shield.** DOM's pre-mainnet validation is the dom-shield detector mesh (per-vector detector tests, fuzz targets, conformance KAVs, directed-corruption probes, multi-node convergence tests) plus the green canonical gate. This trades independent external eyes for internal validation built by the same author who wrote the code. That trade is acknowledged explicitly, including its limitation: a detector written by the author tests what the author thought to test.
- **Why the residual risk is acceptable under this model.** DOM launches as a **zero-value fair launch** (no premine, no ICO, no sale, no founder allocation; the network starts at block zero open to all). At launch nobody has entrusted funds to the chain, so the day-zero-with-funds risk that external gates most protect against is structurally lower. The residual risk that remains — a consensus bug surfacing after the coin acquires value — is covered by the **Satoshi maintenance model**: the author stays active on security while the network is young, responds quickly to issues (as Satoshi patched the 2010 value-overflow inflation in hours), and the dom-shield detectors run continuously to catch regressions.
- **Forbidden claim.** "100% secure" / "fully audited" is forbidden in any DOM document or communication. It would be false. The honest claim is: *the most complete validation this project can perform under this model, with the maintainer accountable for what surfaces.*

No external witnesses are required. DOM is authored under a single pseudonym (Soren Planck) for OPSEC; the integrity guarantee is **public reproducibility** (§5), not a witness panel: the source is open and the genesis hash is deterministically recomputable by anyone, so any member of the public can independently verify that the sealed genesis matches the published constants.

---

## 1. Purpose

The genesis ceremony commits the values that every node on the mainnet network MUST agree on. After the ceremony, none of these can be changed without a hard fork:

- `GENESIS_TIMESTAMP` → actual launch Unix timestamp.
- `GENESIS_HASH_MAINNET` → computed deterministically from the ceremonial constants (the genesis header bytes; see §3).
- The maintainer's release-signing key, used to attest the published release artefacts (signed binaries, source archive hashes).
- The published artefacts themselves.

---

## 2. Pre-ceremony checklist (current model — internal validation)

The ceremony MUST NOT proceed until every item is green, measured natively (`cargo` output is ground truth; "green" means a measured `test result: ok ... 0 failed`, never memory or a passing test name):

- [ ] **Canonical gate green.** `cargo test --workspace --exclude dom-integration-tests` → exit 0, 0 failed, 0 panics. (Last measured: 1933 passed / 0 failed / 23 ignored, 2026-06-29.)
- [ ] **Multi-node convergence validated (Cat 5).** The integration-test convergence set — `reorg`, `ibd`, `late_join`, `two_node`, `three_node`, `mempool_relay`, `wallet_flow` — all green. This is the internal validation that substitutes for a public testnet's network-convergence exercise. (Last measured: 8 tests / 7 files, all green, 2026-06-29.)
- [ ] **Build + lints + supply-chain green.** `cargo build --workspace` exit 0; `cargo clippy --workspace --all-targets` exit 0, no warnings; `cargo audit` exit 0; `cargo deny check` exit 0 (advisories/licenses/bans/sources ok).
- [ ] **Testnet genesis frozen-vector reproduces natively.** `genesis_testnet_frozen_vectors` passes on the native toolchain (deterministic builder reproduces the pinned testnet genesis/roots).
- [ ] **All RED detector findings resolved or consciously accepted.** No `#[ignore]`d RED reproducer for an unresolved bug remains unaddressed. Items accepted as defense-in-depth (not live-exploitable) are documented as such, dated, with rationale (e.g. FIX-018 / FIX-020 — reachability-traced, accepted). The only genuine RED finding (FIX-021) is code-fixed (`df8c9ae`, consensus-neutral).
- [ ] **`#[ignore]` inventory honest.** Every remaining `#[ignore]` carries a truthful reason (static-review fact, by-design, non-attackable, or accepted defense-in-depth) — no stale/false markers (e.g. "env-blocked" on a test proven to run, or "RED" on green code).
- [ ] **No pending consensus change in flight.** Working tree clean; all consensus-touching commits finalized and reviewed.

There is NO requirement here for a public testnet, external audit, fuzz-CPU-hour quota, bug bounty, or external witnesses. Those were the previous model (§0).

---

## 3. Ceremonial constants frozen at ceremony time

Constants updated in `dom-core/src/constants.rs` and committed as the final pre-launch commits:

1. **`GENESIS_TIMESTAMP`** → the announced launch Unix timestamp. Because DOM is a fair launch, this timestamp is **announced in advance** (§7) so that the network goes public and mining begins for everyone at the same moment — no party (including the maintainer) mines before this time. (Code symbol: `GENESIS_TIMESTAMP_MAINNET_PLACEHOLDER` in `constants.rs`, which the finalization guard requires to be changed away from its placeholder value.)

2. **`GENESIS_HASH_MAINNET`** → the **blake2b_256** hash of the genesis header bytes. (NOTE: the code uses `blake2b_256`, NOT SHA-256. An earlier version of this document said "SHA-256" — that was a doc-vs-code error; the code is authoritative.) The header is constructed deterministically from the just-frozen `GENESIS_TIMESTAMP` plus the already-frozen `GENESIS_MESSAGE` and `INITIAL_BLOCK_REWARD`.

3. **`GENESIS_MESSAGE`** → the genesis block's embedded message.
   **[DECISION — SOREN PLANCK — non-anticipation proof]**: decide BEFORE sealing whether to embed a non-anticipation proof (a real-world headline / external reference dated on or after the announcement, Satoshi-style) in `GENESIS_MESSAGE`. This is irreversible once sealed. It strengthens the fair-launch credibility (proves the genesis was not constructed before that date) but is optional. If used, the exact text is chosen at ceremony time from a source dated on/after the public announcement. Mark here: [ ] embed non-anticipation proof / [ ] plain genesis message.

4. **H generator** → the second Pedersen generator H is NOT a pinned constant; it is **derived** at runtime by `dom-crypto`'s `h_generator::derive_h_generator()` (RFC9380 hash-to-curve, DST `"DOM:h2c:secp256k1:v6.1"`), exposed via `h_generator::h_compressed()`. It is therefore fixed by its derivation (changing the DST or derivation would change H and is a hard fork), and re-verified by recomputation (§5) — `verify_h_matches_derivation` — rather than by external witnesses.

The only ceremony-time crypto computation is the deterministic genesis-hash derivation; it is verified by independent reproduction (§5), not by a witness panel.

---

## 4. Ceremony steps (performed by the maintainer; recorded for public reproduction)

1. **Pre-flight verification.** Run the §2 checklist on the native toolchain. All must be green, measured (not remembered). Record the transcript (commands + outputs). Abort if anything is red.

2. **Time anchor.** Fix the ceremonial Unix timestamp = the publicly announced launch time. Record it.

3. **Constants commit (timestamp).** Update `GENESIS_TIMESTAMP` (and `GENESIS_MESSAGE` per §3.3 decision) in `constants.rs`.

4. **Compute the genesis hash.** Run the ceremony-helper that constructs the genesis header from the frozen constants and prints the resulting `GENESIS_HASH_MAINNET` (blake2b_256 of the header bytes) to stdout.
   **[DECISION — SOREN PLANCK — helper]**: confirm the exact tool/command used to compute the mainnet genesis hash (the same deterministic builder path that already produces the testnet frozen vectors, pointed at mainnet constants). Code confirms the real command before this step is final.

5. **Independent reproduction (public-reproducibility check).** Recompute the genesis hash from a clean checkout of the public source at the sealed commit, with the same timestamp input, and confirm it matches byte-for-byte. Because the source is open, ANY third party can perform this same recomputation after launch — that public reproducibility is the integrity guarantee (replacing the old external-witness panel).

6. **Pin the genesis hash.** Commit `GENESIS_HASH_MAINNET` into `constants.rs`. The placeholder guard (`validate_mainnet_genesis_hash`, which rejects the all-zero placeholder and aliasing with testnet/regtest) must now pass with the real value.

7. **Build + sign release.** Build the release binaries for each supported host, compute the hash of each binary, sign the manifest with the release key, publish the signed manifest.
   **[DECISION — SOREN PLANCK — platforms]**: confirm which host targets are built/signed for launch (vs. build-from-source only).

8. **Network bootstrap.** Start the canonical seed nodes (running the signed binary) AT the announced launch time — not before (fair launch: the maintainer's nodes/miner come up with the public network, never ahead of it).
   **[DECISION — SOREN PLANCK — seeds]**: confirm the seed-node count and update `dom-wire/src/dns_seed.rs` accordingly. The code currently hardcodes 5 mainnet DNS seeds (`seed1..seed5.dom-protocol.org`) and an empty `MAINNET_SEED_IPS` ("to be filled after genesis"); the stated infrastructure is ~3 VPS = 2 nodes + 1 miner. The `dns_seed.rs` list and this step MUST be reconciled to the real deployment before launch.

9. **Public announcement.** Publish the genesis hash, the ceremony transcript, the signed release manifest, and the recomputation instructions to the project website and the GitHub repository under a new annotated tag, so anyone can reproduce and verify.

---

## 5. Integrity guarantee — public reproducibility (replaces external witnesses)

The integrity of the sealed genesis does NOT depend on a panel of named witnesses (incompatible with single-author pseudonymous OPSEC). It depends on **deterministic public reproducibility**:

- The full source is public at the sealed commit.
- The genesis hash is a pure deterministic function of the published, frozen constants.
- Anyone — now or years later — can clone the source, run the same recomputation, and confirm the sealed `GENESIS_HASH_MAINNET` matches. A mismatch would be publicly detectable by anyone, which is a stronger and more durable guarantee than a one-time witness signing.

This is the same property that already protects the testnet genesis (`genesis_testnet_frozen_vectors` reproduces the pinned testnet hash deterministically on any host).

---

## 6. Post-ceremony immutability

After step 6 (`GENESIS_HASH_MAINNET` pinned), the following MUST hold forever for mainnet:

- No commit on `main` may modify: `GENESIS_TIMESTAMP`, `GENESIS_HASH_MAINNET`, `GENESIS_MESSAGE`, `INITIAL_BLOCK_REWARD`, `HALVING_INTERVAL` / `HALVING_EPOCHS`, `MAX_SUPPLY_NOMS`, `TARGET_SPACING`, `NETWORK_MAGIC_MAINNET`, `P2P_PORT_MAINNET`. The derived H generator (see §3.4: `h_generator::derive_h_generator`, RFC9380 DST `"DOM:h2c:secp256k1:v6.1"`) is likewise frozen — changing its derivation or DST changes H and is equally a fork.
- Any commit changing the above is, by definition, a fork. The network operating under the new constants is "DOM (forked YYYY-MM-DD)" and is NOT the same network as mainnet.

Mechanical enforcement: the guard in `constants.rs` (the finalization guard `validate_mainnet_genesis_hash` plus the `MAINNET_GENESIS_FINALIZED` flag, which reference this ceremony) plus repository controls on changes touching `dom-core/src/constants.rs`.
**[DECISION — SOREN PLANCK — enforcement]**: an earlier doc referenced "CODEOWNERS review under Phase 8.3" — that team/process model does not apply to a single-author repo. Decide the actual mechanical guard (the in-code finalization guard is the primary; any repo-level protection is optional).

---

## 7. Fair-launch timing (announcement before genesis)

Because DOM is a fair launch with no premine, the **public announcement precedes the genesis**, with the exact launch date/time stated in advance. This ensures the network goes public and mining begins for everyone simultaneously, from block zero, with no head start for any party. The maintainer's seed nodes and miner (the ~3-VPS bridge that keeps the young network alive) are started AT or AFTER the announced moment — never before. The maintainer's running of a miner for early-network stability is disclosed openly in the announcement (transparency protects fair-launch credibility).

---

## 8. Disaster scenarios — escape hatches

If the ceremony fails at any step, the procedure is:

- **Pre-flight (§4.1) fails** — abort. Publish the failing output, fix, re-schedule. Do NOT seal with a red gate.
- **Reproduction (§5) mismatch** — abort. A mismatch means a non-deterministic or non-conforming build path. Investigate, fix, re-derive. Never seal a hash that does not reproduce.
- **Signing key unavailable (§4.7)** — abort. The release key MUST be present and operational at ceremony time.
- **Seed nodes fail to bootstrap (§4.8)** — abort the PUBLIC launch but DO NOT modify the already-pinned genesis-hash constant. Fix the operational issue, redeploy, complete the announcement once stable.

A failed pre-seal step is recoverable; a sealed mainnet genesis is not.

---

## 9. Rehearsal (regtest, not public testnet)

The previous model rehearsed the ceremony on a public testnet. Under the current model there is no public testnet. The rehearsal is performed in **regtest** (already proven to run locally — the Cat 5 multi-node convergence set runs in regtest/FastDevOnly): the maintainer runs the deterministic genesis-hash derivation and the multi-node bootstrap end-to-end with regtest constants before the live mainnet ceremony, confirming the procedure and the recomputation path work. A failed rehearsal is recoverable; a failed mainnet ceremony is not.

---

## 10. Confidence (honest)

- **Confirmed (in code):** the deterministic computation paths — genesis-header serialization, blake2b_256 of the header, generator derivation — are exercised by the test suites; the testnet frozen-vector reproduces natively.
- **Confirmed (measured):** multi-node convergence (Cat 5) green; canonical gate green; supply-chain green.
- **Validated by rehearsal (regtest), not by public testnet:** the end-to-end ceremony + bootstrap procedure.
- **Operational, validated only when the live ceremony runs:** the real-network launch (seed nodes reachable on real IPs, the announced-time bootstrap). This is documented here; it is exercised for real only once, at launch.
- **NOT claimed:** "100% secure" / "fully audited." Forbidden and false. The claim is the most complete validation this project performs under the stated model, with the maintainer accountable for what surfaces post-launch (Satoshi model).
