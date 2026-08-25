#!/usr/bin/env bash
# §3.4 hash-domain freeze gate.
#
# The spec requires CI to fail if a second hash dialect can appear in the
# Scriptless H_tag surface: "O CI deve falhar se Sha256, SHA256(tag) ou
# duplicação de tag_hash aparecerem no módulo tags.rs/adapter H_tag; usos de
# SHA em funções não relacionadas não são banidos." It also requires the
# closed registry: "A API não aceita string arbitrária" — every Scriptless
# H_tag domain must be a DomainTag variant, not a runtime literal.
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

adaptor_src="crates/dom-adaptor/src"
domain_tag="$adaptor_src/domain_tag.rs"

status=0

# 1. No SHA / BIP340 double-hash construction in the Scriptless crypto surface.
#    (SHA in unrelated functions is not banned; this greps the adaptor source.)
if git grep -n -E 'Sha256|SHA256\(tag\)|sha2::' -- "$adaptor_src" >/dev/null 2>&1; then
    echo "FAIL: a SHA/BIP340 hash construction appears in the Scriptless H_tag surface" >&2
    git grep -n -E 'Sha256|SHA256\(tag\)|sha2::' -- "$adaptor_src" >&2 || true
    status=1
fi

# 2. Every Scriptless H_tag domain must come from the closed DomainTag enum.
#    A scriptless tag string LITERAL is allowed only in the frozen enum itself
#    and in the KDF/AEAD label registry (§3.4 Section C: secret-nonce labels),
#    never as an arbitrary runtime tag elsewhere.
if git grep -n -E '= "DOM:scriptless-' -- "$adaptor_src" \
    | grep -v "$domain_tag" \
    | grep -v 'DOM:scriptless-secret-nonce-' >/dev/null 2>&1; then
    echo "FAIL: a Scriptless H_tag domain is instantiated as an arbitrary string literal" >&2
    echo "      (move it into the DomainTag closed registry; §3.4 forbids arbitrary tags)" >&2
    git grep -n -E '= "DOM:scriptless-' -- "$adaptor_src" \
        | grep -v "$domain_tag" \
        | grep -v 'DOM:scriptless-secret-nonce-' >&2 || true
    status=1
fi

# 3. The differential and vector tests must exist in the frozen module.
for required in \
    'every_scriptless_domain_matches_dom_blake2b_backend' \
    'frozen_vectors_pin_the_exact_canonical_digests' \
    'the_registry_is_a_closed_set_of_distinct_tags'; do
    if ! grep -q "$required" "$domain_tag"; then
        echo "FAIL: required §3.4 test '$required' missing from domain_tag.rs" >&2
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "HASH_DOMAINS = FROZEN_GATE_PASS"
fi
exit "$status"
