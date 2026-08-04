# Phase 1 independent cryptographic evidence and blocker report

Date: 2026-08-04
Outcome: **STOP — complete cross-implementation vectors cannot be produced**

## Scope and isolation

This review began from clean commit
`a37f0bbeeb7c0ee5579154ae64476e8374d1dabb` on branch
`test/phase-1-independent-evidence`. It used only the assigned independent
worktree and the normative material already contained in it. No implementation,
expected-output fixture, generator, production cryptography, consensus code, or
wire format was added.

The separate G1a implementation worktree, branch, commit, and all Agent 1
outputs were not accessed. Because the normative audit reached a mandatory STOP
before complete expected outputs could be produced, no later comparison with
Agent 1 occurred. A constant-time review of the implementation also did not
occur.

## Source precedence and integrity

The registered order of authority is:

1. Master Specification v1.0, revision R1;
2. Consolidated Report v1;
3. Implementation Schedule v1;
4. frozen code, fixtures, and tests.

A lower source may supply evidence or detail, but it cannot silently override an
explicit decision in a higher source. Gaps require an erratum, ADR, or new
versioned freeze; they cannot be completed by inference. This order is stated in
`docs/scriptless/source-guides/NORMATIVE-SOURCES.md` and repeated in
`docs/scriptless/PROJECT-SOURCES.md`.

The controlled copies independently hashed as follows:

| Precedence | Controlled source | Bytes | SHA-256 |
|---:|---|---:|---|
| 1 | `DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx` | 99,871 | `5ad366d6b5c01c88bc88d4e9c016b447c32f24fbc24a32fa8b6946d7ff5dd6b5` |
| 2 | `DOM-Scriptless-Relatorio-Consolidado-v1.md` | 15,853 | `5431ca3894c42ffbee86cd719d4bb0e70ec8ddfb21b33895e889372fa5335acb` |
| 3 | `DOM-Scriptless-Cronograma-Implementacao-v1.md` | 10,851 | `cfee44873007390f1e19ea95ec5da66e860373a882c32af51ace985fde495e48` |

`sha256sum --check docs/scriptless/source-guides/normative/MANIFEST.sha256`
reported all three controlled sources `OK`. The manifest itself has SHA-256
`110961e7c2d21217ad8f73ec93610fd081f67123b5fdefae840ddc95fcc50270`.

Additional files used to corroborate the repository's recorded freeze state:

| File | SHA-256 |
|---|---|
| `docs/scriptless/source-guides/NORMATIVE-SOURCES.md` | `b19a5a820e54cbb4bb393069ed86c7bc098f68f95ede9d7fc59161f7b1a8ec70` |
| `docs/scriptless/PROJECT-SOURCES.md` | `f3e3fa7d7a96f8640441fc9828b1c3667a2f69c5494071c8e28ae75755c8a917` |
| `docs/scriptless/phase-1a/CANONICAL-TRANSCRIPT.md` | `38095e108c397a1eb9d9830d4f1bc2dc909f979f30869ad8e572c65a24fff563` |
| `docs/scriptless/phase-1a/NORMATIVE-INPUT-MATRIX.md` | `3e4914f3abf8c29a5aa2dfae3a130cbe972675b329e3d50e1ed99b324e5a3a19` |
| `test-vectors/scriptless/hash-domains/DOM_G1A_BACKEND_FREEZE_V1.txt` | `3eb44729df0768aeb2a317dece846a0ba8b3abf190791adfc4132200b8edf425` |
| `crates/dom-crypto/src/hash.rs` | `1d2afbf4c74ec8c015e026e4fca790edcdd198f6cf0d07c150bc3a9ab218ed71` |

The Scriptless vector manifest also passed, but its two tracked files are the
SCAD0 evidence and backend hash-domain AUTO-CHECK. Neither is the required
secret-nonce input-only fixture.

## Independently confirmed normative facts

The authorized inputs and DOM source agree on these facts:

- The curve is secp256k1, with order
  `FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.
- `H_tag(tag, data)` is native 32-byte BLAKE2b, not BLAKE2s and not a
  truncation of BLAKE2b-512, with no key, salt, or personalization. Its input is
  `u16_le(len(tag ASCII)) || tag ASCII || data`.
- The authoritative implementation is
  `crates/dom-crypto/src/hash.rs::blake2b_256_tagged`. It aliases
  `Blake2b<U32>`, writes the little-endian tag length, the tag bytes, and then
  the data.
- `PurposeV1` is explicitly assigned as `Refund=0x01`,
  `ClaimAdaptor=0x02`, `Funding=0x03`, and reserved `Sponsor=0x04`.
- The required KDF tags are exactly
  `DOM:scriptless-secret-nonce-aux:v1`,
  `DOM:scriptless-secret-nonce-seed:v1`, and
  `DOM:scriptless-secret-nonce-wide:v1`.
- The operator-supplied mask/seed/wide-expansion and
  `scalar_from_wide_be` construction is normative, but it cannot be instantiated
  into the required vectors without a complete normative input record.

As a limited framing sanity check, Python 3 `hashlib.blake2b(digest_size=32)`
was run over each tag's framing with an empty data suffix. These are
self-selected partial checks, not the required cross-implementation vectors:

| Tag | ASCII length | Framing prefix | Digest for empty data |
|---|---:|---|---|
| `DOM:scriptless-secret-nonce-aux:v1` | 34 | `2200` | `51cb488d33f6ee2bb2c097fe05ac4b53126a44f2467964784751fa5038c694ca` |
| `DOM:scriptless-secret-nonce-seed:v1` | 35 | `2300` | `ef675a1824c069da28031b4f38c3fae5d0c7ba46d1774b67be6ff92f8fd2ac9a` |
| `DOM:scriptless-secret-nonce-wide:v1` | 35 | `2300` | `0a14aab387e4580a9c31f47b1d3c7b24c705b81596ccc2111921c94b15d469d8` |

No scalar-wide vector was selected after the STOP condition, because doing so
would not repair the absent normative fixture and could be mistaken for the
required complete evidence.

## Mandatory missing assignments

Master Specification section 8.4 defines the cumulative transcript body as:

```text
previous_transcript_hash || message_digest ||
direction_u8 || accepted_phase_u16_le
```

It does not define a `DirectionV1` registry, the meaning of any direction byte,
a `PhaseV1` registry, or the numeric encoding of any accepted phase. The named
protocol states elsewhere in the document are not numeric byte assignments.
The Consolidated Report and Implementation Schedule contain no assignment that
fills either gap. Repository freeze documents independently record the same
condition: `CANONICAL-TRANSCRIPT.md` says that the initial hash and
direction/phase codes must not be invented, and `NORMATIVE-INPUT-MATRIX.md`
marks the cumulative transcript `EXIGE DECISÃO` for that reason.

Therefore:

- `DirectionV1`: semantic byte assignment absent;
- `PhaseV1`: semantic `u16` assignment absent;
- a canonical context containing those discriminants cannot be encoded;
- a complete expected-output vector cannot be computed lawfully.

## Input-only fixture inventory

No authorized source contains a complete concrete input-only fixture matching
the operator's schema. The following is the exact missing-field inventory. Here
“absent” means absent from a complete input-only fixture record; it does not
mean that every field name or global rule is absent from prose.

| Required input-only field | Status and consequence |
|---|---|
| `version` | No concrete fixture value supplied. |
| `chain_id` | No concrete fixture value supplied. |
| `session_id` | No concrete fixture value supplied. |
| participant roster | No concrete ordered fixture roster supplied. |
| local participant index | No concrete fixture value supplied. |
| signing share | No concrete secret fixture value supplied. |
| corresponding signing public key | No concrete fixture value supplied. |
| `PurposeV1` | Registry is normative, but no complete fixture selects a concrete purpose. |
| `DirectionV1` | Concrete fixture value absent, and the byte registry itself is absent. |
| `PhaseV1` | Concrete fixture value absent, and the `u16` registry itself is absent. |
| template hash | No concrete fixture value supplied. |
| message digest | No concrete fixture value supplied. |
| transcript hash | No concrete fixture value supplied. |
| adaptor presence and adaptor point | No complete fixture supplies the conditional value. |
| `aux_rand_32` | No concrete fixture value supplied. |
| `retry_counter` | No concrete fixture value supplied. |
| adaptor secret | No concrete fixture value supplied. |
| positive and negative cases | No complete case set supplied. |

The backend freeze file contains isolated public framing examples selected for
AUTO-CHECK. Its own documentation says it is not a two-nonce or independent G1a
fixture. Partial values from it cannot be spliced into a new secret-nonce
fixture without inventing an oracle.

## Outputs that remain unavailable

Because the required input fixture and two discriminant registries are absent,
none of the following may be frozen as required cross-implementation expected
output:

- canonical context bytes and tag input bytes;
- mask, masked signing share, and seed;
- both wide-expansion digest halves, `W_1`/`W_2`, reduced `k1`/`k2`, and
  `R_i1`/`R_i2`;
- nonce commitment;
- binding preimage and coefficient;
- effective participant nonce, aggregate nonce, and `R_hat`;
- DOM kernel challenge;
- participant partials/result and aggregate `s_hat`;
- adaptor pre-signature bytes, adapted final signature bytes, extracted `t`,
  and `t*G`;
- real DOM-verifier result.

Publishing values for this list would necessarily combine invented inputs with
normative ones and would create a false oracle.

## Commands and results

Commands were run from the assigned worktree. Material commands were:

```bash
git status --short --branch
git rev-parse HEAD
sha256sum docs/scriptless/source-guides/normative/*
stat -c '%n|%s' docs/scriptless/source-guides/normative/DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx docs/scriptless/source-guides/normative/DOM-Scriptless-Relatorio-Consolidado-v1.md docs/scriptless/source-guides/normative/DOM-Scriptless-Cronograma-Implementacao-v1.md
sha256sum --check docs/scriptless/source-guides/normative/MANIFEST.sha256
sha256sum --check test-vectors/scriptless/MANIFEST.sha256
rg -n -i 'DirectionV1|PhaseV1|direction_u8|accepted_phase|direction|direção|phase|fase|transcript' docs/scriptless/source-guides/normative docs/scriptless/phase-1a
unzip -p docs/scriptless/source-guides/normative/DOM-Scriptless-Contracts-Especificacao-Mestra-v1.0.docx word/document.xml | perl -0777 -pe 's#</w:p>#\n#g; s#<w:tab[^>]*/>#\t#g; s#<w:br[^>]*/>#\n#g; s#<[^>]+>##g' | rg -n -i -C 4 'purpose_u8|direction_u8|accepted_phase_u16_le|transcript'
nl -ba crates/dom-crypto/src/hash.rs | sed -n '8,48p'
```

The branch and commit matched the assigned identity; both manifests passed;
the normative hashes and sizes matched their registry; the source searches
found the transcript formula and PurposeV1 values but no DirectionV1 or PhaseV1
assignment.

The limited Python framing command was:

```bash
python3 - <<'PY'
import hashlib
for tag in (
    'DOM:scriptless-secret-nonce-aux:v1',
    'DOM:scriptless-secret-nonce-seed:v1',
    'DOM:scriptless-secret-nonce-wide:v1',
):
    raw = tag.encode('ascii')
    framed = len(raw).to_bytes(2, 'little') + raw
    print(tag, len(raw), framed.hex(),
          hashlib.blake2b(framed, digest_size=32).hexdigest())
PY
```

## STOP disposition

The correct independent result is STOP. An authorized erratum, ADR, or new
versioned normative freeze must assign every `DirectionV1` byte and `PhaseV1`
`u16` value and provide a complete input-only fixture before an independent
generator may emit the required expected outputs. Until then, no placeholder,
inferred discriminant, output fixture, cross-comparison, G1a approval, or
constant-time implementation approval is justified.
