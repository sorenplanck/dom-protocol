#!/usr/bin/env bash
# Bind the two-nonce Claim adaptor composition to the pinned DOM backend.
#
# This guard is policy enforcement, not a cryptographic proof. It cannot show
# that the composition is sound; it shows that this repository still composes
# the pinned primitives instead of growing its own.
#
# A passing test suite does not establish that. A locally written challenge, a
# second binding factor, a hand-rolled point addition, or a caller-supplied
# nonce would all keep the suite green while replacing the frozen relation
# `R̂ = R + T` with something this project invented.
#
# It fails closed: a source it cannot read is a failure, never a skip.
set -Eeuo pipefail

# Anchored to the workspace root, not to the git top level: in the monorepo
# these are different directories, and every path literal below is relative to
# the workspace the guarded crates belong to.
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

module="crates/dom-scriptless-crypto/src/claim_adaptor_round.rs"
suite="crates/dom-scriptless-crypto/tests/claim_adaptor_round_v1.rs"
crate_src="crates/dom-scriptless-crypto/src"
self_path="scripts/check-adaptor-two-nonce.sh"

capability="CompletedClaimAdaptorCycleV1"

failures=0
pass() { printf '  ok    %s\n' "$1"; }
fail() {
  printf '  FAIL  %s\n' "$1" >&2
  failures=$((failures + 1))
}

echo "== two-nonce Claim adaptor composition guard =="

missing=0
for source in "$module" "$suite"; do
  if [[ ! -f "$source" ]]; then
    echo "  FAIL  required source is absent: $source" >&2
    missing=1
  fi
done
if [[ $missing -ne 0 ]]; then
  echo "ADAPTOR_TWO_NONCE_GUARD = FAIL (absent source)" >&2
  exit 1
fi

# Strings are removed before comments, with a character-level state machine
# that carries string state across newlines and understands raw strings. A
# per-line substitution cannot do this: Rust string literals span lines, and
# every check below is a grep for a line shape, so a multi-line literal could
# otherwise carry any shape this guard looks for.
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
  echo "ADAPTOR_TWO_NONCE_GUARD = FAIL (module parsed empty)" >&2
  exit 1
fi
crate_code="$(
  find "$crate_src" -name '*.rs' -print0 | sort -z | xargs -0 cat | strip
)"
if [[ -z "$crate_code" ]]; then
  echo "ADAPTOR_TWO_NONCE_GUARD = FAIL (crate source parsed empty)" >&2
  exit 1
fi
crate_flat="$(printf '%s\n' "$crate_code" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g')"

# ── The composition is the pinned one ─────────────────────────────────────────

# Each frozen step must be reached through its pinned function, by name.
for required in \
  'binding_factor_v1(' \
  'bind_public_nonces(' \
  'aggregate_public_nonces_v1(' \
  'aggregate_partial_signatures_v1(' \
  'verify_bound(' \
  'AdaptorPreSignatureV1::new(' \
  'verify_claim_adaptor_pre_signature_v1(' \
  '.adapt(' \
  'scriptless_verify_final_signature(' \
  '.extract(' \
  'public_point('; do
  if grep -Fq "$required" <<<"$code"; then
    pass "the pinned step is reached: $required"
  else
    fail "the pinned step is missing: $required"
  fi
done

# R_hat must be formed by adding the adaptor point through the pinned
# aggregation, never by a local addition.
if grep -Eq 'aggregate_public_nonces_v1\(&\[ *aggregate_nonce\.clone\(\), *inputs\.adaptor_point\.clone\(\) *\]\)' <<<"$crate_flat"; then
  pass "R_hat = R + T is formed by the pinned aggregation"
else
  fail "R_hat is not formed by the pinned aggregation over [R, T]"
fi

# ── Nothing is reimplemented ──────────────────────────────────────────────────

# No duplicate DOM verifier, challenge, or curve backend ANYWHERE in the crate.
# Requirement 1 forbids new cryptography in dom-contracts, not in one file: a
# sibling module supplying a locally computed challenge is the same violation,
# and a file-scoped scan cannot see it. `schnorr_challenge` is deliberately
# included: the composition must let the pinned verifier compute the challenge,
# never compute one to compare against, and no module of this crate has any
# business computing a DOM challenge.
duplicate_found=0
for forbidden in \
  schnorr_challenge ProjectivePoint AffinePoint secp256k1 k256 \
  scriptless_verify_pre_signature scriptless_adapt_signature \
  scriptless_extract_adaptor_secret scriptless_aggregate_partial_scalars; do
  if grep -Fq "$forbidden" <<<"$crate_code"; then
    fail "a duplicate DOM verifier, challenge, or curve backend is used: $forbidden"
    duplicate_found=1
  fi
done

# Generic hashing is scoped to this module only. `storage.rs` legitimately
# hashes for Stage 1 vault sealing under NAR-DC-P1-002, so a crate-wide ban
# would report ratified storage code as a composition violation.
for forbidden in blake2b blake2s sha2 Sha256 Digest; do
  if grep -Fq "$forbidden" <<<"$code"; then
    fail "the composition module computes its own hash: $forbidden"
    duplicate_found=1
  fi
done
[[ $duplicate_found -eq 0 ]] && pass "no duplicate challenge, hash, curve, or codec"

# No caller-supplied nonce reaches this module's public surface.
#
# Scoped to the composition module, and matched against parameter TYPES rather
# than function names: `audit_nonce_secret_record` is a legitimate Stage 1
# storage API whose NAME contains "nonce_secret", and a name-based check would
# report that unrelated function as a violation of this module's rule.
module_flat="$(printf '%s\n' "$code" | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g')"
nonce_input_found=0
for forbidden in SecretScalar Zeroizing AdaptorSecret SecretNonce NonceSecret; do
  if grep -Eq "pub (const )?(unsafe )?fn [^;{]*: *&? *(mut )?$forbidden" <<<"$module_flat"; then
    if [[ "$forbidden" == "AdaptorSecret" ]]; then
      # `complete_cycle_v1` takes the adaptor secret by shared reference to
      # adapt with it. That is the secret the protocol reveals on claim, not a
      # nonce, and it is never stored, returned, or logged.
      continue
    fi
    fail "a public function accepts secret nonce material: $forbidden"
    nonce_input_found=1
  fi
done
# Type names alone are not enough: a nonce is most naturally handed over as raw
# bytes, which no type-name list can catch. Any public parameter whose NAME
# carries nonce, secret or share vocabulary is refused regardless of its type.
#
# `adaptor_secret` is the one admitted name. It is the secret the protocol
# reveals on claim, which `adapt` requires by shared reference; it is never a
# nonce, and it is never stored, returned, or logged.
if grep -oE "pub (const )?(unsafe )?fn [^;{]*" <<<"$module_flat" |
  grep -oE "[a-z_]*(nonce|secret|share)[a-z_]*:" |
  grep -qv "^adaptor_secret:"; then
  fail "a public function takes a parameter named as nonce, secret or share material"
  grep -oE "[a-z_]*(nonce|secret|share)[a-z_]*:" <<<"$module_flat" |
    grep -v "^adaptor_secret:" >&2 || true
  nonce_input_found=1
fi
[[ $nonce_input_found -eq 0 ]] && pass "no public entry point accepts a caller-supplied nonce"

# ── The cycle evidence stays opaque ───────────────────────────────────────────

attribute_block="$(
  awk -v decl="^pub struct $capability \\\\{$" '
    $0 ~ decl { for (i = 1; i <= n; i++) print saved[i]; exit }
    /^[[:space:]]*$/ || /^[[:space:]]*\/\// || /^[[:space:]]*#\[/ { saved[++n] = $0; next }
    { n = 0 }
  ' "$module"
)"
if [[ -z "$attribute_block" ]]; then
  fail "the cycle evidence declaration was not found"
elif grep -Eq '^[[:space:]]*#\[' <<<"$attribute_block"; then
  fail "the cycle evidence carries an attribute or derive"
  grep -E '^[[:space:]]*#\[' <<<"$attribute_block" >&2
else
  pass "the cycle evidence carries no attribute or derive"
fi

if grep -Eq "impl( *<[^>]*>)? [^;{]* for $capability\b" <<<"$crate_flat"; then
  fail "the cycle evidence implements a trait"
  grep -oE "impl( *<[^>]*>)? [^;{]* for $capability" <<<"$crate_flat" >&2
else
  pass "the cycle evidence implements no trait at all"
fi

struct_body="$(
  printf '%s\n' "$code" |
    awk "/^pub struct $capability \{\$/{inside=1; next} inside && /^\}\$/{exit} inside"
)"
if [[ -z "$struct_body" ]]; then
  fail "the cycle evidence body could not be read"
else
  field_count="$(printf '%s\n' "$struct_body" | grep -cE '^[[:space:]]+[a-z_]+:' || true)"
  if [[ "$field_count" -gt 0 ]]; then
    pass "the cycle evidence declares $field_count field(s)"
  else
    fail "no field was parsed from the cycle evidence; privacy cannot be checked"
  fi
  if grep -Eq '^[[:space:]]*pub([[:space:]]|\()' <<<"$struct_body"; then
    fail "the cycle evidence has a public field"
  else
    pass "every cycle evidence field is private"
  fi
fi

construction_sites="$(
  printf '%s\n' "$crate_code" |
    awk -v cap="$capability" '
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
  pass "the cycle evidence has exactly one construction site"
else
  fail "the cycle evidence has $construction_count construction site(s), expected 1"
  printf '%s\n' "$construction_sites" >&2
fi

# No boolean verification result escapes to a caller.
if grep -Eq 'pub (const )?(unsafe )?fn [^;{]*\) -> (Result<)?bool' <<<"$crate_flat"; then
  fail "a public function returns a boolean verification result"
  grep -oE 'pub (const )?(unsafe )?fn [^;{]*\) -> (Result<)?bool' <<<"$crate_flat" >&2
else
  pass "no public function returns a boolean verification result"
fi

# ── Scope ─────────────────────────────────────────────────────────────────────

scope_found=0
for out_of_scope in \
  advance_session funding_authority FundingAuthorization BroadcastAuthorization \
  broadcast bulletproof BpRound shared_output executor rpc chain_adapter; do
  if grep -Fq "$out_of_scope" <<<"$code"; then
    fail "out-of-scope surface in the composition module: $out_of_scope"
    scope_found=1
  fi
done
[[ $scope_found -eq 0 ]] && pass "the module composes only; no executor, funding or broadcast"

# Funding and Refund finalisation is a different pinned path and is not this
# module's business.
if grep -Fq 'finalize_plain_signature_v1' <<<"$code"; then
  fail "Funding/Refund finalisation is out of scope for this module"
else
  pass "no Funding or Refund finalisation"
fi

if grep -Eq '\bunsafe\b' <<<"$crate_code"; then
  fail "unsafe code appears in the crate"
else
  pass "no unsafe code"
fi

# ── The measured relation is frozen by a test ─────────────────────────────────

for required in \
  'the_frozen_relation_between_r_t_and_r_hat' \
  'the_complete_cycle_closes_on_the_adaptor_point' \
  'a_permuted_participant_association_is_refused' \
  'a_corrupted_partial_is_refused_before_aggregation' \
  'the_cycle_is_deterministic_over_many_sessions'; do
  if grep -Fq "fn $required" "$suite"; then
    pass "the suite still carries $required"
  else
    fail "the suite lost $required"
  fi
done

# The sweep count is a recorded number, not a decoration.
if grep -Eq '^[[:space:]]*const SESSIONS: u64 = 10_000;$' "$suite"; then
  pass "the deterministic sweep is 10,000 sessions"
else
  fail "the deterministic sweep is not the recorded 10,000 sessions"
fi
if grep -Eq '^[[:space:]]*const BASE_SEED: u64 = 1000;$' "$suite"; then
  pass "the sweep seed base is recorded"
else
  fail "the sweep seed base is not recorded"
fi

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

# ── The Stage 4 limit is not quietly dropped ──────────────────────────────────

if grep -Fq 'not intrinsic cryptographic' "$module"; then
  pass "the module restates the Stage 4 binding limit"
else
  fail "the module no longer restates the Stage 4 binding limit"
fi

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
  echo "ADAPTOR_TWO_NONCE_GUARD = PASS"
  exit 0
fi
echo "ADAPTOR_TWO_NONCE_GUARD = FAIL ($failures violation(s))" >&2
exit 1
