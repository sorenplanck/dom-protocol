# Pin delta changelog — `a182563` → `eb6aa1c`

Delta record of the §9.2 ratification event carrying **D-016**. Status:
**RATIFIED** by the operator on 2026-08-10 (order recorded in chat), on the
evidence below.

```text
FROM  a1825639154dcc9d89be098079112e9cb975940e   (D-008, ratified 2026-08-10)
TO    eb6aa1ca59226bc316e3aace5ee0e279e5a154c2   (D-016, ratified 2026-08-10)
REPO  github.com/sorenplanck/dom-protocol
REF   branch feat/scriptless-revealed-adaptor-secret-export
DELTA one commit, additive
```

## The single upstream commit

`eb6aa1c` — *feat(scriptless): authority-blessed export of the revealed
adaptor secret*. It is the direct child of `a182563`; there is nothing else
between the two revisions.

### Why it exists

Closing the EVM leg of an F3 settlement means publishing the adaptor secret
in `claim(lockId, t)` calldata — 32 bytes. At `a182563` there was no path
from a verified extraction to those bytes: neither `AdaptorSecret` nor
`dom_crypto::SecretScalar` exports any, so the DOM leg could prove it had
recovered the right `t` (by comparing the public point) but could not hand
it over. The DOM→EVM direction was therefore structurally impossible.

The same hole exists at `180b731`, so this is not something a different
existing revision fixes — the export had to be created.

### Why the export is sound

The extracted adaptor secret is the one secret scalar in the protocol that
is **public by construction**: it is `t = s − ŝ` over two signatures that
are both already published, so any observer can perform the same
subtraction. Returning it discloses nothing the network does not hold, and
delivering it is precisely what an adaptor-signature swap exists to do.

The rejected alternative was to recompute `t` downstream inside `dom-leg`
from the DOM's own arithmetic primitives. That works, but it places the
adaptor arithmetic in a second location and leaves the requirement
implicit, so a later revision could withdraw it silently.

## Surface of the change

| item | before | after |
|---|---|---|
| `dom_crypto::scriptless_extract_adaptor_secret_be_bytes` | — | **new**: performs the extraction, returns canonical BE bytes in `Zeroizing` |
| `dom_crypto::scriptless_extract_adaptor_secret` | own implementation | **delegates** to the byte variant, then re-parses — one implementation, one set of checks |
| `AdaptorPreSignatureV1::extract_revealed_secret_be_bytes` | — | **new**: verifies through the same private helper `extract` uses, then returns the bytes |
| `AdaptorPreSignatureV1::extract` | inline verification | unchanged behaviour; verification factored into the shared private helper |
| `dom_crypto::SecretScalar` | no byte accessor | **unchanged — still no byte accessor** |
| `AdaptorSecret` | no byte accessor | **unchanged — still no byte accessor** |
| primitives, challenge, transcript, verifier | — | **untouched** |
| `compile_fail` seals in `lib.rs` | 19 | **19, all still holding** |

The export is reachable **only** through a fully verified extraction: the
pre-signature equation and the observed final signature are both checked
first, by the same code path the opaque `extract` runs, so the byte path
can never verify less than the sealed one.

## Verification performed at the new revision

Full detail, with commands, in Foundation Document v0.7 §9.2.1. Summary:

```text
dom-adaptor (at the pin)      65 passed, 0 failed  + 19 doctests
  311-intermediate vectors    PASS
  G1a SCAD0 (8 vectors)       PASS
interop workspace             153 passed, 0 failed
dom-leg  (real backend)        25 passed, 0 failed
dom-vault (real backend)       42 passed, 0 failed
store failpoints                9 passed, 0 failed
doctests                        3 passed, 0 failed
F2 model checker              PASS (five AG properties)
F2 property suite               8 passed, 0 failed
independent terms verifier    PASS
executable guards             9/9 PASS
clippy -D warnings            clean
cargo fmt --check             clean
```

New coverage added upstream by the commit, in
`crates/dom-adaptor/tests/g1a_adaptor.rs`:

- across all eight frozen SCAD0 vectors, the revealed bytes equal the
  corpus `t` **byte for byte** — not merely a value with the same point;
- a mutated final signature is refused by the export exactly where it is
  refused by `extract`;
- a mismatched claim-template hash closes the export path.

`dom-leg`'s `fixture_copy_is_byte_identical_to_the_pin` passed at the new
revision, so the frozen corpus itself did not move.

## Lockfile discipline

No global `cargo update`. The pin change altered **7 lines** of
`Cargo.lock` — the `source` field of the seven `dom-*` packages — and
nothing else. No other dependency was resolved, added or bumped.

## Why the pin is not moved to `dom-protocol`'s `main`

`a182563` is itself **not** an ancestor of that `main`, which carries 11
unrelated commits. The DOM Interop pin has always referenced a branch
commit, and `eb6aa1c` continues that line. Pinning to it advances the
authority by exactly one reviewed, additive commit — the smallest
conformance surface available. Merging into `main` instead would drag in
those 11 commits and a far larger re-validation.

## Files changed in this repository

```text
Cargo.toml                        5 rev declarations + the DOM_ADAPTOR_REV comment
Cargo.lock                        7 source lines
.github/workflows/ci.yml          conformance checkout
README.md                         DOM pin block
crates/dom-leg/src/lib.rs         pin reference + AUTHORITY markers
crates/f2-harness/tests/g_f1.rs   pin reference
docs/normative/DOM-Interop-Foundation-Document-v0.7.md   new version, D-016, §9.2.1
docs/reports/PIN-CHANGELOG-eb6aa1c.md                    this file
```

Prose that records *history* — "before pin `a182563` this test could not
exist", the D-008 registry entry, the F0/F1/F2 closure reports — was left
untouched. Rewriting it to the new revision would falsify the record.
