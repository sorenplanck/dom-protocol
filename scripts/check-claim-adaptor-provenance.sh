#!/usr/bin/env bash
# Bind the Claim adaptor verification path to imported bytes and an opaque API.
#
# Two things this repository cannot prove with a passing test suite:
#
#   1. that the SCAD0 corpus is still the imported upstream bytes rather than
#      something regenerated here. A regenerated corpus is self-referential: a
#      wrong verifier would be checked against vectors a wrong verifier
#      produced, and every test would still pass.
#   2. that the verification result is still an opaque, verifier-issued
#      capability. Adding `Clone`, `Debug`, a `Default`, a serde impl, a public
#      field, or a second construction site would keep the whole suite green
#      while turning evidence into something a caller can forge or copy.
#
# This guard checks both, plus that the pinned verifier is still what actually
# reaches a verdict. It fails closed: a source it cannot read is a failure,
# never a skip, and it never regenerates the fixture.
set -Eeuo pipefail

# Anchored to the workspace root, not to the git top level: in the monorepo
# these are different directories, and every path literal below is relative to
# the workspace the guarded crates belong to.
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

fixture="crates/dom-scriptless-crypto/tests/fixtures/scad0_adaptor_vectors_v1.txt"
provenance="crates/dom-scriptless-crypto/tests/fixtures/PROVENANCE.md"
module="crates/dom-scriptless-crypto/src/claim_adaptor.rs"
suite="crates/dom-scriptless-crypto/tests/claim_adaptor_v1.rs"

# The imported artifact, recorded at import time. Restated here as well as in
# PROVENANCE.md on purpose: a single recorded digest that the guard reads from
# the same document it is checking would accept any fixture whose digest was
# updated to match it.
expected_digest="4be1657e8101a036ae2b0ea8d409e284b3c8c7215ccb9d92dc7b29b9dc7dbe10"
# Historical import provenance, not a live pin. The corpus WAS imported at this
# revision and always will have been. Do not turn this back into a check that
# the workspace currently pins it — that is exactly how the retired pin rotted.
imported_revision="6f2b230ebbec390040dbf0bff110efaf4bb0f101"
expected_blob="a7f409ae5e27f0f74b9622a104034a32288628e0"
expected_len="162"
capability="VerifiedClaimAdaptorPreSignatureV1"

failures=0
pass() { printf '  ok    %s\n' "$1"; }
fail() {
  printf '  FAIL  %s\n' "$1" >&2
  failures=$((failures + 1))
}

echo "== Claim adaptor provenance and opacity guard =="

missing=0
for source in "$fixture" "$provenance" "$module" "$suite"; do
  if [[ ! -f "$source" ]]; then
    echo "  FAIL  required source is absent: $source" >&2
    missing=1
  fi
done
if [[ $missing -ne 0 ]]; then
  echo "CLAIM_ADAPTOR_GUARD = FAIL (absent source)" >&2
  exit 1
fi

# ── Provenance ────────────────────────────────────────────────────────────────

actual_digest="$(sha256sum "$fixture" | cut -d' ' -f1)"
if [[ "$actual_digest" == "$expected_digest" ]]; then
  pass "the fixture is the imported bytes (SHA-256 $expected_digest)"
else
  fail "fixture digest is $actual_digest, expected $expected_digest"
fi

if grep -Fq "$expected_digest" "$provenance"; then
  pass "PROVENANCE.md records the imported digest"
else
  fail "PROVENANCE.md does not record digest $expected_digest"
fi

for record in "$imported_revision" "$expected_blob"; do
  if grep -Fq "$record" "$provenance"; then
    pass "PROVENANCE.md records $record"
  else
    fail "PROVENANCE.md does not record $record"
  fi
done

# ── The backend is the in-tree audited crate ──────────────────────────────────
#
# Replaces the pre-absorption external revision pin. The crates that pin named —
# dom-adaptor, dom-consensus, dom-core, dom-crypto, dom-serialization — are now
# members of this workspace, so an external revision can no longer be the
# anchor. What the pin actually protected was substitution: the only way to
# swap the backend was to point at a different source. That is what is checked
# here instead.
#
# No byte-level constant is introduced on purpose. The revision constant this
# block replaces went stale — the manifests moved to a newer pin and the
# constant did not follow — and a rotted gate is a gate that gets ignored. The
# backend's behaviour is held to account by the frozen vectors and the
# deterministic sweeps in this same guard, which fail on a semantic change
# rather than on any change.
backend_ok=1

for backend in dom-adaptor dom-crypto; do
  if ! grep -Eq "^${backend}\.workspace = true\$" crates/dom-scriptless-crypto/Cargo.toml; then
    fail "dom-scriptless-crypto does not consume ${backend} through the workspace"
    backend_ok=0
  fi
  if ! grep -Eq "^${backend} *= *\{ *path *= *\"crates/${backend}\" *\}\$" Cargo.toml; then
    fail "the workspace does not resolve ${backend} to its in-tree path"
    backend_ok=0
  fi
done

# A backend crate declared from a git or registry source would be a substitution
# the workspace path cannot prevent. Scoped to the five crates the retired pin
# named: dom-wallet-core* is declared from git by design and is not a backend.
if git grep -n -I -E '^dom-(adaptor|consensus|core|crypto|serialization) *= *\{[^}]*\bgit *=' \
    -- Cargo.toml 'crates/**/Cargo.toml'; then
  fail "a backend crate is declared from a source outside this workspace"
  backend_ok=0
fi

if git grep -n -I -E '^\[patch\.' -- Cargo.toml 'crates/**/Cargo.toml'; then
  fail "a [patch] override could redirect the backend"
  backend_ok=0
fi

[[ $backend_ok -eq 1 ]] && pass "the backend is the in-tree audited crate and cannot be substituted"

# The corpus is frozen at eight vectors. Counting them here, rather than only in
# the test suite, means a truncated fixture fails even if a future test learned
# to read whatever it was given.
vector_count="$(grep -cE '^V[0-9]{2}\|' "$fixture" || true)"
if [[ "$vector_count" == "8" ]]; then
  pass "the fixture carries the frozen eight vectors"
else
  fail "the fixture carries $vector_count vectors, expected 8"
fi

# Nothing in this repository may write the fixture. `include_str!` is a read at
# compile time; a test that opened it for writing, or a script that emitted it,
# would be a generator.
#
# The working tree is searched, not the index. `git grep` reads tracked content,
# so it cannot see a new or still-unstaged file: a generator added in the same
# change this guard is meant to gate would be invisible to it, and the guard
# would fail open exactly when it matters.
#
# Comments are stripped first. `grep -v 'include_str!'` filters whole lines, so
# without stripping, a genuine `std::fs::write` of the fixture escapes simply by
# carrying a trailing comment that mentions `include_str!`.
#
# The guard excludes itself by its literal path rather than by `basename "$0"`,
# which changes with how the script is invoked.
# Only comments are stripped, never string literals: the fixture name lives
# inside a string in any real generator, so removing strings would erase the
# very evidence being looked for.
self_path="scripts/check-claim-adaptor-provenance.sh"
generator_hits="$(
  {
    grep -rnI --include='*.rs' -E 'scad0_adaptor_vectors_v1' crates || true
    grep -rnI -E 'scad0_adaptor_vectors_v1' scripts xtask tools .github 2>/dev/null |
      grep -Fv "$self_path" || true
  } | sed -E 's|//.*$||' |
    grep -F 'scad0_adaptor_vectors_v1' |
    grep -v 'include_str!' || true
)"
if [[ -n "$generator_hits" ]]; then
  fail "the fixture is referenced outside include_str!; it must never be written"
  printf '%s\n' "$generator_hits" >&2
else
  pass "the fixture is only ever read, never generated"
fi

# The suite must actually drive the imported bytes through the public entry
# point. A suite that stopped reading the fixture, or stopped calling the
# verifier, would leave the corpus unexercised while still passing.
if grep -Fq 'include_str!("fixtures/scad0_adaptor_vectors_v1.txt")' "$suite"; then
  pass "the suite reads the imported fixture"
else
  fail "the suite does not read the imported fixture"
fi
if grep -Fq 'verify_claim_adaptor_pre_signature_v1(' "$suite"; then
  pass "the suite drives the public verification entry point"
else
  fail "the suite does not call the public verification entry point"
fi

# ── The pinned verifier is what reaches the verdict ───────────────────────────
#
# String literals are removed first, then comments, before every source check
# below.
#
# Comments must go because this module's rustdoc names the pinned parser, the
# forbidden type names and the traits it must not implement, so an unscoped
# search would find the documentation and report the code as conforming after
# the code changed.
#
# String literals must go for the same reason and a sharper one: every check
# below is a `grep` for a line shape, and a multi-line string literal can
# contain any line shape at all. Without this, deleting the real
# `match parsed.verify(` and parking those bytes inside a `let _ = "...";`
# leaves the whole "the pinned verifier reaches the verdict" section passing
# while no pinned verifier runs. That is the exact failure this guard exists to
# prevent, so it is checked in the same normalised text as everything else.
#
# A line-oriented `sed` cannot do this. Rust string literals may span lines, so
# a per-line substitution leaves the interior of a multi-line string untouched —
# and the interior is exactly where an attacker parks the line shapes this guard
# greps for. The stripper is therefore a character-level state machine that
# carries "inside a string" across newlines, and understands raw strings
# (`r#"…"#`), which have no escape sequences and would otherwise terminate at
# the first quote they contain.
#
# Strings are consumed before comments, so a `//` inside a string cannot
# truncate the line early and hide what follows on it.
strip() {
  awk '
    BEGIN { state = 0; squote = sprintf("%c", 39) }          # 0 code, 1 normal string, 2 raw string
    {
      line = $0; out = ""; i = 1; n = length(line)
      while (i <= n) {
        c = substr(line, i, 1)
        if (state == 0) {
          if (c == "\\" ) { out = out " "; i += 2; continue }
          if (c == "/" && substr(line, i + 1, 1) == "/") { break }
          if (c == "\"") { state = 1; i++; continue }
          if (c == "r") {                       # possible raw string start
            j = i + 1; h = 0
            while (substr(line, j, 1) == "#") { h++; j++ }
            if (substr(line, j, 1) == "\"") { state = 2; hashes = h; i = j + 1; continue }
          }
          # Char literals must be consumed here. Without this, a single
          # quote-char-quote token flips the machine into string state and it
          # swallows every following line until the next double quote anywhere
          # in the file, blinding every check below. A lifetime is not a
          # literal and is emitted normally.
          if (c == squote) {
            if (substr(line, i + 1, 1) == "\\" && substr(line, i + 3, 1) == squote) { i += 4; continue }
            if (substr(line, i + 2, 1) == squote) { i += 3; continue }
          }
          out = out c; i++
        } else if (state == 1) {
          if (c == "\\") { i += 2; continue }
          if (c == "\"") { state = 0 }
          i++
        } else {
          if (c == "\"") {
            j = i + 1; h = 0
            while (substr(line, j, 1) == "#" && h < hashes) { h++; j++ }
            if (h == hashes) { state = 0; i = j; continue }
          }
          i++
        }
      }
      sub(/[[:space:]]+$/, "", out)
      print out
    }
  '
}

code="$(strip <"$module")"

# The opacity rules are stated over the whole crate, not one file. The type is
# re-exported from `lib.rs` and its accessors are public, so `impl Debug for
# VerifiedClaimAdaptorPreSignatureV1` — or a serde impl — written in any other
# module of this crate is legal Rust that a file-scoped check cannot see.
crate_code="$(
  find crates/dom-scriptless-crypto/src -name '*.rs' -print0 |
    sort -z | xargs -0 cat | strip
)"
if [[ -z "$crate_code" ]]; then
  echo "CLAIM_ADAPTOR_GUARD = FAIL (crate source could not be read)" >&2
  exit 1
fi

if grep -Eq "^pub const CLAIM_ADAPTOR_PRE_SIGNATURE_LEN: usize = $expected_len;$" <<<"$code"; then
  pass "the declared payload length is $expected_len"
else
  fail "the declared payload length is not $expected_len"
fi

if grep -Fq 'AdaptorPreSignatureV1::from_bytes(request.pre_signature)' <<<"$code"; then
  pass "the payload is parsed by the pinned codec"
else
  fail "the payload is not parsed by the pinned codec"
fi

if grep -Eq '^[[:space:]]*match parsed\.verify\($' <<<"$code"; then
  pass "the pinned pre-signature's own verify reaches the verdict"
else
  fail "the pinned verify call is not the verdict path"
fi

# A `true` verdict is the only route to evidence, and a `false` verdict must
# leave as a typed refusal rather than as a boolean a caller could forward.
if grep -Eq "^[[:space:]]*Ok\(true\) => Ok\($capability \{$" <<<"$code"; then
  pass "only a true verdict issues the capability"
else
  fail "a true verdict is not the sole issuing path"
fi
if grep -Eq '^[[:space:]]*Ok\(false\) => Err\(ClaimAdaptorVerificationError::' <<<"$code"; then
  pass "a false verdict leaves as a typed refusal"
else
  fail "a false verdict is not converted into a typed refusal"
fi
if grep -Eq '^[[:space:]]*Err\(_\) => Err\(ClaimAdaptorVerificationError::' <<<"$code"; then
  pass "an unavailable verifier is a distinct typed refusal"
else
  fail "an unavailable verifier is not a distinct typed refusal"
fi

# No second verifier and no second challenge. §6.6 forbids reinventing
# normalisation locally, so the module must not reach a lower-level primitive
# and must not do curve arithmetic of its own.
duplicate_found=0
for forbidden in scriptless_verify_pre_signature schnorr_challenge Scalar ProjectivePoint AffinePoint secp256k1; do
  if grep -Fq "$forbidden" <<<"$code"; then
    fail "a duplicate DOM verifier or challenge primitive is used: $forbidden"
    duplicate_found=1
  fi
done
[[ $duplicate_found -eq 0 ]] && pass "no duplicate DOM verifier or challenge primitive"

# The public function must return the capability, never a boolean.
if grep -Fq "Result<$capability, ClaimAdaptorVerificationError>" <<<"$code"; then
  pass "the entry point returns the capability, not a boolean"
else
  fail "the entry point does not return the capability"
fi
# A multi-line signature puts `-> bool` on its own line, so a line-oriented
# match cannot see it — and the module's own entry point is written that way, so
# the check would be blind to exactly the shape it guards. Signatures are
# flattened across the whole crate before matching.
crate_flat="$(printf '%s\n' "$crate_code" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g')"
if grep -Eq 'pub (const )?(unsafe )?fn [^;{]*\) -> (Result<)?bool' <<<"$crate_flat"; then
  fail "a public function returns a boolean verification result"
  grep -oE 'pub (const )?(unsafe )?fn [^;{]*\) -> (Result<)?bool' <<<"$crate_flat" >&2
else
  pass "no public function returns a boolean verification result"
fi

# ── The capability stays opaque ───────────────────────────────────────────────

# Every field private. The struct body is read between its declaration and the
# closing brace, so a `pub` added to any field is caught wherever it appears.
struct_body="$(
  printf '%s\n' "$code" |
    awk "/^pub struct $capability \{\$/{inside=1; next} inside && /^\}\$/{exit} inside"
)"
if [[ -z "$struct_body" ]]; then
  fail "the capability struct body could not be read"
else
  field_count="$(printf '%s\n' "$struct_body" | grep -cE '^[[:space:]]+[a-z_]+:' || true)"
  if [[ "$field_count" -gt 0 ]]; then
    pass "the capability declares $field_count field(s)"
  else
    fail "no field was parsed from the capability; the privacy check cannot run"
  fi
  if grep -Eq '^[[:space:]]*pub([[:space:]]|\()' <<<"$struct_body"; then
    fail "the capability has a public field"
  else
    pass "every capability field is private"
  fi
fi

# No attribute at all on the capability.
#
# Reading only the single line above the declaration cannot work here.
# `#![deny(missing_docs)]` forces a doc comment immediately above the struct,
# and comment stripping blanks it, so that one line is always empty and the
# check could never fire — while `#[derive(Serialize)]` placed above the doc
# comment is valid Rust that compiles. The whole attribute-and-doc block above
# the declaration is therefore walked, in the ORIGINAL text, until a line that
# is neither blank, nor a comment, nor an attribute.
attribute_block="$(
  awk -v decl="^pub struct $capability \\\\{$" '
    $0 ~ decl { for (i = 1; i <= n; i++) print saved[i]; exit }
    /^[[:space:]]*$/ || /^[[:space:]]*\/\// || /^[[:space:]]*#\[/ { saved[++n] = $0; next }
    { n = 0 }
  ' "$module"
)"
if [[ -z "$attribute_block" ]]; then
  fail "the capability declaration was not found; the attribute check cannot run"
elif grep -Eq '^[[:space:]]*#\[' <<<"$attribute_block"; then
  fail "the capability carries an attribute or derive"
  grep -E '^[[:space:]]*#\[' <<<"$attribute_block" >&2
else
  pass "the capability carries no attribute or derive"
fi

# No trait implementation anywhere in the crate.
#
# Scoped to the whole crate, not the module: the type is re-exported from
# `lib.rs` and all seven accessors are public, so `impl Debug for
# VerifiedClaimAdaptorPreSignatureV1` in any sibling module is legal Rust that a
# file-scoped check cannot see. Signatures are flattened first, because
# `impl serde::Serialize\n    for VerifiedClaimAdaptorPreSignatureV1` is one
# rustfmt line break away from escaping a line-oriented match.
if grep -Eq "impl( *<[^>]*>)? [^;{]* for $capability\b" <<<"$crate_flat"; then
  fail "the capability implements a trait"
  grep -oE "impl( *<[^>]*>)? [^;{]* for $capability" <<<"$crate_flat" >&2
else
  pass "the capability implements no trait at all"
fi

# Exactly one construction site, and it must be the true branch of the pinned
# verdict. A second one anywhere is a route to evidence that never ran the check.
#
# Counting lines that end in `Capability {` is not enough. Inside the type's own
# `impl` block a struct literal is written `Self { … }`, which shares no text
# with the type name, so a `pub const fn forge() -> Self { Self { … } }` added
# to the existing impl block is a complete forging constructor that a name-based
# count cannot see. Both spellings are therefore counted, and `Self` is counted
# only within this type's impl blocks so other types' literals do not inflate it.
construction_sites="$(
  printf '%s\n' "$crate_code" |
    awk -v cap="$capability" '
      # Track whether we are inside `impl <cap> {` (inherent, not `for`).
      # A struct literal named outright, anywhere.
      # A struct literal, not a declaration and not a function signature.
      # `pub const fn pre_signature(&self) -> &Cap {` ends in the same three
      # tokens as a literal, so signatures are excluded by `fn`/`->`, not by
      # leading keyword alone.
      # Count struct literals per line rather than excluding whole lines.
      # Excluding any line containing `->` was too broad: a one-line
      # `fn f() -> Cap { let v = Cap { .. }; v }` carries both a signature and a
      # literal, and the exclusion hid the literal. Signature return braces are
      # subtracted by shape instead, so both can appear on one line.
      $0 ~ /^(pub )?struct / { next }
      $0 ~ ("^impl " cap "[[:space:]]*\\{") { inherent = 1 }
      inherent && /^\}$/ { inherent = 0 }
      {
        probe = $0
        total = gsub(cap "[[:space:]]*\\{", "", probe)
        probe = $0
        sigs = gsub("->[[:space:]]*&?[[:space:]]*" cap "[[:space:]]*\\{", "", probe)
        literals = total - sigs
        if ($0 ~ /^impl /) { literals = 0 }
        for (k = 0; k < literals; k++) { print "named:" $0 }
        if (inherent) {
          probe = $0
          selves = gsub("Self[[:space:]]*\\{", "", probe)
          for (k = 0; k < selves; k++) { print "self:" $0 }
        }
      }
    '
)"
construction_count="$(printf '%s' "$construction_sites" | grep -c . || true)"
if [[ "$construction_count" == "1" ]]; then
  pass "the capability has exactly one construction site"
else
  fail "the capability has $construction_count construction site(s), expected 1"
  printf '%s\n' "$construction_sites" >&2
fi

# That one site must be the true branch of the pinned verdict.
if grep -Eq "^[[:space:]]*Ok\(true\) => Ok\($capability \{\$" <<<"$code"; then
  pass "the sole construction site is the true branch of the pinned verdict"
else
  fail "the sole construction site is not the true branch of the pinned verdict"
fi

# The public surface of the capability is exactly the seven binding readers and
# nothing else.
#
# A blacklist of leaky names only forbids the names someone already thought of;
# `pub fn s_hat()` or `pub fn to_pre_signature()` would pass one. The methods are
# therefore enumerated and compared against the allowed set, so any new public
# method fails until it is deliberately added here.
expected_methods="adaptor_point aggregate_nonce_hat aggregate_signing_key chain_id claim_template_hash kernel_message_digest transcript_hash"
actual_methods="$(
  printf '%s\n' "$crate_code" |
    awk -v cap="$capability" '
      $0 ~ ("^impl " cap " \\{$") { inside = 1; next }
      inside && /^\}$/ { inside = 0 }
      inside
    ' |
    grep -oE '^[[:space:]]*pub (const )?(unsafe )?fn [a-z_0-9]+' |
    sed -E 's/.*fn //' | sort -u | tr '\n' ' ' | sed -E 's/[[:space:]]+$//'
)"
if [[ "$actual_methods" == "$expected_methods" ]]; then
  pass "the capability exposes exactly the seven binding readers"
else
  fail "the capability's public methods changed"
  echo "    expected: $expected_methods" >&2
  echo "    actual:   $actual_methods" >&2
fi

# ── The naming boundary ───────────────────────────────────────────────────────
#
# NAR-DC-P1-007 §4 records the funding-authorisation surface as model rather
# than authority. A rename is exactly how that distinction would be lost, so the
# vocabulary is forbidden in code across the crate, not only in this module.
#
# The working tree is searched rather than the index, for the same reason as the
# generator check above: a rename introduced by an unstaged change must fail.
#
# What is forbidden is *naming* something with this vocabulary, so string
# literals and comments are removed before matching, and in that order. The
# suite asserts these very names are absent and therefore carries all three as
# literal data; matching them there would report the test that enforces the rule
# as the violation. Stripping strings before comments keeps a `//` inside a
# string literal from truncating the line early.
naming_found=0
normalized_crate="$(
  grep -rnI --include='*.rs' '' crates/dom-scriptless-crypto |
    sed -E 's/"[^"]*"//g; s|//.*$||'
)"
for forbidden in ReadyToFund FundingAuthorization BroadcastAuthorization; do
  hits="$(printf '%s\n' "$normalized_crate" | grep -E "\b$forbidden\b" || true)"
  if [[ -n "$hits" ]]; then
    fail "forbidden capability name in code: $forbidden"
    printf '%s\n' "$hits" >&2
    naming_found=1
  fi
done
[[ $naming_found -eq 0 ]] && pass "no forbidden capability name appears in code"

# ── Scope ─────────────────────────────────────────────────────────────────────
#
# Verification only. Adaptation, extraction, nonce generation and signing are
# out of scope for this module and must not appear in it.
scope_found=0
for out_of_scope in adapt_pre_signature extract_adaptor_secret sign_ generate_nonce rand_core OsRng; do
  if grep -Fq "$out_of_scope" <<<"$code"; then
    fail "out-of-scope operation in the verification module: $out_of_scope"
    scope_found=1
  fi
done
[[ $scope_found -eq 0 ]] && pass "the module verifies only; it does not sign, adapt or extract"

# The gate statements the mission preserves.
for gate in "PRODUCTION = NOT_AUTHORIZED" "MAINNET = DISABLED" \
  "REAL_FUNDS = PROHIBITED" "PHASE2 = NOT_AUTHORIZED"; do
  if grep -Fq "$gate" "$module"; then
    pass "the module restates $gate"
  else
    fail "the module does not restate $gate"
  fi
done

echo
if [[ $failures -eq 0 ]]; then
  echo "CLAIM_ADAPTOR_GUARD = PASS"
  exit 0
fi
echo "CLAIM_ADAPTOR_GUARD = FAIL ($failures violation(s))" >&2
exit 1
