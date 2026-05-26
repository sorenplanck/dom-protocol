# DOM — Genesis Ceremony Procedure (Phase 8.5)

Status: pre-launch procedure draft. Executed once at the moment
of mainnet launch; the artefacts it produces are consensus-immutable.

## Purpose

The genesis ceremony commits the values that every node in the
mainnet network MUST agree on. After the ceremony, none of these
can be changed without a hard fork:

* `GENESIS_TIMESTAMP_PLACEHOLDER` → actual launch Unix timestamp.
* `GENESIS_HASH_MAINNET` → computed deterministically from the
  ceremonial constants (see RFC-0011 §1.3).
* The signing key of the maintainer for release-tag attestations.
* The published artefacts (signed binaries, SBOMs, source archive
  hashes).

## Pre-ceremony checklist

The ceremony MUST NOT proceed until every item in this list is
green:

* [ ] All CRITICAL `RELEASE_BLOCKERS.md` entries resolved.
* [ ] All HIGH `RELEASE_BLOCKERS.md` entries either resolved or
      explicitly accepted with a maintainer-signed residual-risk
      statement.
* [ ] Phase 1.4 cross-platform CI matrix green on every host
      (Linux x86_64 / ARM64, macOS x86_64 / ARM64, Windows x86_64).
* [ ] Phase 8.1 public adversarial testnet stable for ≥ 90 days
      continuous, no consensus break.
* [ ] Phase 8.2 fuzz campaign completed (≥ 10 000 CPU-hours
      across the documented surfaces) — campaign log archived
      under `docs/FUZZ_CAMPAIGN.md` once authored.
* [ ] Phase 8.3 external audit complete with all findings
      addressed or explicit deferral.
* [ ] Phase 8.4 bug bounty open for ≥ 30 days with no unfixed
      CRITICAL / HIGH reports.

## Ceremony participants

* **Maintainer** — Soren Planck. Holds the release-signing PGP
  key; computes and announces the genesis hash.
* **Witnesses** — ≥ 3 independent technically-competent
  observers, each running a full DOM node from source and
  willing to sign the ceremony transcript. Selected before the
  ceremony date and announced publicly ≥ 7 days in advance.
* **Time authority** — the chosen timestamp source (e.g. RFC 3161
  trusted timestamp service or a multi-jurisdiction time anchor).

## Ceremonial constants frozen at ceremony time

Constants that MUST be updated in `dom-core/src/constants.rs`
and committed as the final pre-launch commit:

1. `GENESIS_TIMESTAMP_PLACEHOLDER` → ceremony Unix timestamp,
   announced live + recorded by the time authority.
2. `GENESIS_HASH_MAINNET` → SHA-256 of the genesis header bytes
   (RFC-0011 §1.3). The header is constructed by the maintainer
   live during the ceremony from the just-frozen timestamp +
   the already-frozen GENESIS_MESSAGE and INITIAL_BLOCK_REWARD.
3. `H_COMPRESSED_FINAL` — already pinned via RFC-0009 derivation;
   re-verified by witnesses with an independent implementation.

The H generator independent re-derivation is the only
ceremony-time crypto computation; the witnesses run an OpenSSL
+ RFC9380 implementation, compare against `dom-crypto`'s
output, and announce the match before the genesis hash is
finalised.

## Ceremony steps (live, recorded, witnessed)

1. **Quorum check** — all witnesses confirm presence and confirm
   they are running the audited commit at HEAD.
2. **Pre-flight verification** — every witness runs
   `cargo test --workspace --exclude dom-integration-tests` on
   their own host. All must report green. Output transcript
   recorded.
3. **Time anchor** — the chosen timestamp authority emits the
   ceremonial Unix timestamp.
4. **Constants commit** — maintainer updates
   `GENESIS_TIMESTAMP_PLACEHOLDER` in `constants.rs`, runs the
   ceremony-helper script (TBD: `scripts/genesis_ceremony.rs`)
   that prints the resulting `GENESIS_HASH_MAINNET` to stdout.
5. **Independent reproduction** — witnesses run the same script
   on their hosts with the same timestamp input, announce their
   computed `GENESIS_HASH_MAINNET`, and the maintainer compares.
   All MUST match byte-for-byte.
6. **Pin the genesis hash** — maintainer commits the
   genesis-hash constant into `constants.rs`.
7. **Build + sign release** — maintainer builds the release
   binaries for each Phase 1.4 host, computes SHA-256 of each
   binary, signs each hash with the release PGP key, publishes
   the signed manifest.
8. **Witness transcript signatures** — every witness signs the
   ceremony transcript (the full sequence of commands and
   outputs from step 1–7) with their own PGP key. The
   transcript + signatures are committed into `docs/ceremony/`.
9. **Network bootstrap** — the maintainer starts the canonical
   seed nodes (5 mainnet seeds in `dom-wire/src/dns_seed.rs`)
   running the signed binary. The witnesses connect their
   nodes and confirm they reach the genesis hash via
   independent computation.
10. **Public announcement** — the genesis hash, ceremony
    transcript, signed release manifest, and witness signatures
    are published to the project website and the dom-protocol
    GitHub repository under a new annotated tag.

## Post-ceremony immutability

After step 6 (`GENESIS_HASH_MAINNET` pinned), the following
properties MUST hold forever for mainnet:

* No commit on `main` may modify `GENESIS_TIMESTAMP_PLACEHOLDER`,
  `GENESIS_HASH_MAINNET`, `GENESIS_MESSAGE`, `INITIAL_BLOCK_REWARD`,
  `HALVING_INTERVAL`, `HALVING_EPOCHS`, `MAX_SUPPLY_NOMS`,
  `H_COMPRESSED_FINAL`, `NETWORK_MAGIC_MAINNET`, `P2P_PORT_MAINNET`.
* Any commit changing the above is a fork by definition. The
  network operating under the new constants is "DOM (forked
  YYYY-MM-DD)" and is NOT the same network as mainnet.

The branch-protection rules on `main` (set up under Phase 8.3 /
the audit-handover commit) include a required CODEOWNERS review
for changes touching `dom-core/src/constants.rs` — this is the
mechanical enforcement of the immutability.

## Disaster scenarios — escape hatches

If the ceremony fails at any step, the published procedure is:

* **Step 2 / pre-flight fails** — abort, publish the failing
  test output, fix, re-schedule the ceremony for ≥ 7 days
  later to give witnesses time to re-verify.
* **Step 5 / witnesses disagree** — abort. A disagreement here
  means either the maintainer's host or one of the witnesses'
  hosts is non-conforming. Investigate, fix, re-schedule.
* **Step 7 / signing key not available** — abort. The release
  PGP key MUST be present and operational at ceremony time.
* **Step 9 / seed nodes fail to bootstrap** — abort the public
  launch but DO NOT modify the genesis-hash constant. Investigate
  the operational issue, redeploy the seed nodes, complete step 10
  once they're stable.

## Confidence

* **Confirmed (in code):** the ceremony's deterministic
  computation paths — genesis-header serialisation, SHA-256 of
  header, H generator derivation — are all exercised by the
  Phase 6.3 + Phase 1.4 + Phase 2.1 test suites.
* **Likely:** the witness reproduction protocol is operationally
  sound — depends on every witness being able to compile and
  run the release binary from source on their chosen host.
* **Theoretical until ceremony runs:** the social / operational
  protocol (witness selection, time authority, transcript
  custody) — these are documented here but only validated by
  rehearsal at Phase 8.1 testnet launch.

## Rehearsal

Phase 8.1 (public adversarial testnet) is the rehearsal for the
mainnet ceremony. The same procedure runs end-to-end with
testnet constants; the witnesses, time authority, and signing
key holder are all the same as the mainnet ceremony will be.
A failed testnet ceremony is recoverable; a failed mainnet
ceremony is not.
