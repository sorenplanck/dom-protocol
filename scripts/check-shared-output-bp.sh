#!/usr/bin/env bash
# Bind the shared 2-of-2 output and collaborative Bulletproof to the pinned
# backend.
#
# This guard is policy enforcement, not a cryptographic proof. It cannot show
# the formation is sound; it shows this repository still composes the pinned
# primitives instead of growing its own.
#
# A green suite does not establish that. A locally written proof system, a
# second Pedersen commitment, a hand-rolled point addition, a share aggregated
# before its proof of possession verified, or a reveal accepted before every
# commitment arrived would each leave the tests passing while replacing the
# formation with something this project invented.
#
# It fails closed: a source it cannot read is a failure, never a skip.
set -Eeuo pipefail

# Anchored to the workspace root, not to the git top level: in the monorepo
# these are different directories, and every path literal below is relative to
# the workspace the guarded crates belong to.
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

module="crates/dom-scriptless-crypto/src/shared_output.rs"
suite="crates/dom-scriptless-crypto/tests/shared_output_v1.rs"
crate_src="crates/dom-scriptless-crypto/src"

expected_proof_len="739"
capability="FrozenSharedOutputV1"
# The joint common nonce is the pinned rewind nonce: whoever holds it can
# recover the value and the total blinding. It needs the opacity checks more
# than the frozen statement does.
secret_capability="JointCommonNonceV1"

failures=0
pass() { printf '  ok    %s\n' "$1"; }
fail() {
  printf '  FAIL  %s\n' "$1" >&2
  failures=$((failures + 1))
}

echo "== shared 2-of-2 output and collaborative Bulletproof guard =="

missing=0
for source in "$module" "$suite"; do
  if [[ ! -f "$source" ]]; then
    echo "  FAIL  required source is absent: $source" >&2
    missing=1
  fi
done
if [[ $missing -ne 0 ]]; then
  echo "SHARED_OUTPUT_BP_GUARD = FAIL (absent source)" >&2
  exit 1
fi

strip() {
  awk '
    BEGIN { state = 0; squote = sprintf("%c", 39) }
    {
      line = $0; out = ""; i = 1; n = length(line)
      while (i <= n) {
        c = substr(line, i, 1)
        if (state == 0) {
          if (c == "\\" ) { out = out " "; i += 2; continue }
          if (c == "/" && substr(line, i + 1, 1) == "/") { break }
          if (c == "\"") { state = 1; i++; continue }
          if (c == "r") {
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
if [[ -z "$code" ]]; then
  echo "SHARED_OUTPUT_BP_GUARD = FAIL (module parsed empty)" >&2
  exit 1
fi
crate_code="$(find "$crate_src" -name '*.rs' -print0 | sort -z | xargs -0 cat | strip)"
if [[ -z "$crate_code" ]]; then
  echo "SHARED_OUTPUT_BP_GUARD = FAIL (crate source parsed empty)" >&2
  exit 1
fi
crate_flat="$(printf '%s\n' "$crate_code" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g')"
suite_code="$(strip <"$suite")"
if [[ -z "$suite_code" ]]; then
  echo "SHARED_OUTPUT_BP_GUARD = FAIL (suite parsed empty)" >&2
  exit 1
fi

# ── The formation is the pinned one ───────────────────────────────────────────

for required in \
  'SharePoPStatementV1::new(' \
  'verify_share_knowledge_v1(' \
  'scriptless_add_public_points(' \
  'Commitment::commit(' \
  'BpStatementV1::new(' \
  'dom_crypto::blake2b_256_tagged('; do
  if grep -Fq "$required" <<<"$code"; then
    pass "the pinned step is reached: $required"
  else
    fail "the pinned step is missing: $required"
  fi
done

# Every proof of possession must verify before anything is aggregated. The
# verification loop has to precede the aggregation call in the file, because a
# share summed first and checked later is the rogue-key exposure this closes.
# Scoped to the entry point's own body, not to the file. Extracting the loop
# into a helper placed above the function, and calling it after the aggregation
# — or never calling it at all — satisfies a whole-file line comparison while
# summing unverified shares. Both calls must appear inside this one function,
# in this order.
entry_body="$(
  awk '/^pub fn freeze_shared_output_statement_v1\($/{inside=1} inside{print} inside && /^\}$/{exit}' <<<"$code"
)"
if [[ -z "$entry_body" ]]; then
  fail "the entry point body could not be read"
else
  verify_line="$(grep -n 'verify_share_knowledge_v1(' <<<"$entry_body" | head -1 | cut -d: -f1)"
  aggregate_line="$(grep -n 'scriptless_add_public_points(' <<<"$entry_body" | head -1 | cut -d: -f1)"
  if [[ -z "$verify_line" ]]; then
    fail "the entry point does not verify any proof of possession"
  elif [[ -z "$aggregate_line" ]]; then
    fail "the entry point does not aggregate through the pinned function"
  elif [[ "$verify_line" -lt "$aggregate_line" ]]; then
    pass "every proof of possession is verified before aggregation"
  else
    fail "aggregation is not preceded by proof-of-possession verification"
  fi
fi

# A false verdict from the pinned verifier must be a typed refusal, never a
# boolean a caller could ignore.
if grep -Eq 'Ok\(false\) => return Err\(SharedOutputError::' <<<"$code"; then
  pass "a rejected proof leaves as a typed refusal"
else
  fail "a rejected proof is not converted into a typed refusal"
fi

# No reveal before every commitment. This is the property that stops a party
# choosing its contribution after seeing the other's.
if grep -Fq 'RevealBeforeAllCommitments' <<<"$code" &&
  grep -Fq 'self.commitments.iter().any(Option::is_none)' <<<"$code"; then
  pass "no reveal is accepted before every commitment"
else
  fail "the reveal gate on complete commitments is missing"
fi

# ── Nothing is reimplemented ──────────────────────────────────────────────────

# The pinned tagged hash `dom_crypto::blake2b_256_tagged` is the correct thing
# to use and is not a reimplementation, so the module text is checked with that
# call removed. What stays forbidden is a hash this repository builds itself.
# Curve and proof-system tokens are forbidden crate-wide: no module of this
# crate has any business reaching them.
duplicate_found=0
for forbidden in ProjectivePoint AffinePoint secp256k1 k256 bulletproof_bp range_proof_verify; do
  if grep -Fq "$forbidden" <<<"$crate_code"; then
    fail "a duplicate proof system or curve backend is used: $forbidden"
    duplicate_found=1
  fi
done

# Generic hashing stays module-scoped: `storage.rs` legitimately hashes for
# Stage 1 vault sealing under NAR-DC-P1-002, so a crate-wide ban would report
# ratified storage code as a violation.
#
# What closes the sibling-module hole is not this scan but the required-step
# check above: `dom_crypto::blake2b_256_tagged(` must appear in THIS module, so
# repointing the commit-reveal at a locally written hash removes it and fails.
code_without_pinned_hash="$(sed 's/dom_crypto::blake2b_256_tagged//g' <<<"$code")"
for forbidden in blake2b blake2s sha2 Sha256 Digest; do
  if grep -Fq "$forbidden" <<<"$code_without_pinned_hash"; then
    fail "the formation module computes its own hash: $forbidden"
    duplicate_found=1
  fi
done
[[ $duplicate_found -eq 0 ]] && pass "no duplicate proof system, curve, or hash"

# The FFI boundary is the pinned crate's. This module must not open one.
# Matched on the KEYWORD, not on `extern "C"`: the stripper removes string
# literals, so the `"C"` marker is gone by the time this runs and the pattern
# would never fire. `extern` survives stripping.
if grep -Eq '\bunsafe\b|\bextern\b' <<<"$crate_code"; then
  fail "unsafe or an FFI boundary appears in this crate"
else
  pass "no unsafe and no FFI boundary in this crate"
fi

# n > 2 is out of scope and must be refused, not generalised.
if ! grep -Eq '^pub const SHARED_OUTPUT_PARTIES: usize = 2;$' <<<"$code"; then
  fail "the two-party roster constant is not declared as exactly two"
# Declaring the constant is not enough. Widening the length test to the pinned
# 2..=16 range while leaving the constant at 2 passes a declaration-only check,
# and the duplicate test only ever compares the first two contributions, so a
# third party would be aggregated unexamined.
elif ! grep -Fq 'if inputs.contributions.len() != SHARED_OUTPUT_PARTIES {' <<<"$code"; then
  fail "the entry point does not reject a roster that is not exactly two"
else
  pass "the roster is exactly two, and the entry point enforces it"
fi

# ── The frozen statement stays opaque ─────────────────────────────────────────

attribute_block="$(
  awk -v decl="^pub struct $capability \\{$" '
    $0 ~ decl { for (i = 1; i <= n; i++) print saved[i]; exit }
    /^[[:space:]]*$/ || /^[[:space:]]*\/\// || /^[[:space:]]*#\[/ { saved[++n] = $0; next }
    { n = 0 }
  ' "$module"
)"
if [[ -z "$attribute_block" ]]; then
  fail "the frozen statement declaration was not found"
elif grep -Eq '^[[:space:]]*#\[' <<<"$attribute_block"; then
  fail "the frozen statement carries an attribute or derive"
else
  pass "the frozen statement carries no attribute or derive"
fi

if grep -Eq "impl( *<[^>]*>)? [^;{]* for $capability\b" <<<"$crate_flat"; then
  fail "the frozen statement implements a trait"
else
  pass "the frozen statement implements no trait at all"
fi

struct_body="$(
  awk "/^pub struct $capability \{\$/{inside=1; next} inside && /^\}\$/{exit} inside" <<<"$code"
)"
if [[ -z "$struct_body" ]]; then
  fail "the frozen statement body could not be read"
elif grep -Eq '^[[:space:]]*pub([[:space:]]|\()' <<<"$struct_body"; then
  fail "the frozen statement has a public field"
else
  pass "every frozen statement field is private"
fi

if grep -Eq 'pub (const )?(unsafe )?fn [^;{]*\) -> (Result<)?bool' <<<"$crate_flat"; then
  fail "a public function returns a boolean verification result"
else
  pass "no public function returns a boolean verification result"
fi

# ── Private nonce custody ─────────────────────────────────────────────────────
#
# The pinned canonical driver draws the private nonce from the OS and never
# accepts one from a caller; it is `pub(crate)` and unreachable, so this
# repository inherits the duty. The custody type must stay one-shot: drawn from
# entropy, consumed by value, and impossible to duplicate or print.
if grep -Fq 'pub fn draw() -> Result<Self, SharedOutputError>' <<<"$code"; then
  pass "the private nonce is drawn, not supplied"
else
  fail "the private nonce custody has no OS-entropy constructor"
fi
if grep -Eq 'pub fn into_round_nonce\(self\)' <<<"$code"; then
  pass "the private nonce custody is consumed by value"
else
  fail "the private nonce custody is not consumed by value"
fi
# A constructor taking bytes would defeat the whole type.
if grep -Eq 'pub (const )?fn [a-z_]*(from_bytes|new)[a-z_]*\([^)]*\[u8; 32\]' <<<"$(
  awk "/^pub struct PrivateNonceCustodyV1 \{\$/,0" <<<"$code"
)"; then
  fail "the private nonce custody accepts caller-supplied bytes"
else
  pass "the private nonce custody accepts no caller-supplied bytes"
fi
custody_block="$(
  awk -v decl="^pub struct PrivateNonceCustodyV1 \\{$" '
    $0 ~ decl { for (i = 1; i <= n; i++) print saved[i]; exit }
    /^[[:space:]]*$/ || /^[[:space:]]*\/\// || /^[[:space:]]*#\[/ { saved[++n] = $0; next }
    { n = 0 }
  ' "$module"
)"
if [[ -z "$custody_block" ]]; then
  fail "the private nonce custody declaration was not found"
elif grep -Eq '^[[:space:]]*#\[' <<<"$custody_block"; then
  fail "the private nonce custody carries an attribute or derive"
else
  pass "the private nonce custody carries no attribute or derive"
fi
if grep -Eq "impl( *<[^>]*>)? [^;{]* for PrivateNonceCustodyV1\b" <<<"$crate_flat"; then
  fail "the private nonce custody implements a trait"
else
  pass "the private nonce custody implements no trait at all"
fi

# ── Scope ─────────────────────────────────────────────────────────────────────

scope_found=0
for out_of_scope in \
  funding refund claim_broadcast broadcast advance_session executor \
  fee_bump mainnet rpc chain_adapter; do
  if grep -Fq "$out_of_scope" <<<"$code"; then
    fail "out-of-scope surface in the formation module: $out_of_scope"
    scope_found=1
  fi
done
[[ $scope_found -eq 0 ]] && pass "no funding, refund, claim, broadcast, executor or fee bump"

# ── The recorded numbers are held to account ──────────────────────────────────

if grep -Eq "^const PROOF_LEN: usize = $expected_proof_len;$" <<<"$suite_code"; then
  pass "the aggregate proof size is the pinned $expected_proof_len bytes"
else
  fail "the recorded proof size is not $expected_proof_len"
fi

for required in \
  'the_collaborative_proof_is_exactly_739_bytes_and_verifies' \
  'boundary_values_all_prove' \
  'a_tampered_proof_of_possession_is_refused_before_aggregation' \
  'a_reveal_before_every_commitment_is_refused' \
  'equivocation_and_duplicate_messages_are_refused' \
  'a_truncated_or_extended_or_flipped_proof_is_refused' \
  'the_formation_is_deterministic_over_many_sessions'; do
  if grep -Fq "fn $required" <<<"$suite_code"; then
    pass "the suite still carries $required"
  else
    fail "the suite lost $required"
  fi
done

if grep -Eq '^[[:space:]]*const SESSIONS: u64 = 10_000;$' <<<"$suite_code" &&
  grep -Fq 'for seed in BASE_SEED..BASE_SEED + SESSIONS' <<<"$suite_code" &&
  grep -Fq 'assert_eq!(completed, SESSIONS)' <<<"$suite_code"; then
  pass "the deterministic sweep is 10,000 sessions, and the constant is used"
else
  fail "the sweep constant is declared but not driving the loop and the assertion"
fi
if grep -Eq '^[[:space:]]*const BASE_SEED: u64 = 5000;$' <<<"$suite_code"; then
  pass "the sweep seed base is recorded"
else
  fail "the sweep seed base is not recorded"
fi

# The suite must drive the real pinned FFI, not a stand-in.
for required in \
  'bulletproof_mpc_round1(' \
  'bulletproof_mpc_round2(' \
  'bulletproof_mpc_aggregate_tau_x(' \
  'bulletproof_mpc_finalize('; do
  if grep -Fq "$required" <<<"$suite_code"; then
    pass "the suite drives the pinned FFI: $required"
  else
    fail "the suite does not drive the pinned FFI: $required"
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

# ── The gates ──────────────────────────────────────────────────────────────────

for gate in "PRODUCTION = NOT_AUTHORIZED" "MAINNET = DISABLED" \
  "REAL_FUNDS = PROHIBITED" "PHASE2 = NOT_AUTHORIZED"; do
  if grep -Fq "$gate" "$module"; then
    pass "the module restates $gate"
  else
    fail "the module does not restate $gate"
  fi
done

# The secret type gets the same opacity treatment, and must stay zeroizing.
secret_block="$(
  awk -v decl="^pub struct $secret_capability \\{$" '
    $0 ~ decl { for (i = 1; i <= n; i++) print saved[i]; exit }
    /^[[:space:]]*$/ || /^[[:space:]]*\/\// || /^[[:space:]]*#\[/ { saved[++n] = $0; next }
    { n = 0 }
  ' "$module"
)"
if [[ -z "$secret_block" ]]; then
  fail "the joint-nonce declaration was not found"
elif grep -Eq '^[[:space:]]*#\[' <<<"$secret_block"; then
  fail "the joint nonce carries an attribute or derive"
else
  pass "the joint nonce carries no attribute or derive"
fi
if grep -Eq "impl( *<[^>]*>)? [^;{]* for $secret_capability\b" <<<"$crate_flat"; then
  fail "the joint nonce implements a trait"
else
  pass "the joint nonce implements no trait at all"
fi
secret_body="$(
  awk "/^pub struct $secret_capability \{\$/{inside=1; next} inside && /^\}\$/{exit} inside" <<<"$code"
)"
if [[ -z "$secret_body" ]]; then
  fail "the joint-nonce body could not be read"
elif grep -Eq '^[[:space:]]*pub([[:space:]]|\()' <<<"$secret_body"; then
  fail "the joint nonce has a public field"
elif ! grep -Fq 'Zeroizing' <<<"$secret_body"; then
  fail "the joint nonce is not held zeroizing"
else
  pass "the joint nonce is private and zeroizing"
fi

echo
if [[ $failures -eq 0 ]]; then
  echo "SHARED_OUTPUT_BP_GUARD = PASS"
  exit 0
fi
echo "SHARED_OUTPUT_BP_GUARD = FAIL ($failures violation(s))" >&2
exit 1
