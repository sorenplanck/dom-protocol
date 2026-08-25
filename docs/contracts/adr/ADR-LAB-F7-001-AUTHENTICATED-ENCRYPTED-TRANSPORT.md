# ADR-LAB-F7-001: Authenticated and Encrypted Scriptless Transport

Status: LAB CANDIDATE — implemented for F7 evaluation; not a production
ratification record

Date: 2026-08-13

## Problem

The Master Specification freezes the `ScriptlessMessageV1` (`DSC1`) envelope,
message registry, transcript rule, replay/equivocation behavior, and the
requirement for participant identity signatures. The repository previously
contained an empty transport crate. It therefore could not execute Phase 3,
could not protect collaborative Bulletproof contributions from a relay, and
could not demonstrate duplicate/reorder/replay behavior.

The Master requires end-to-end confidentiality but does not freeze a network
handshake or an encrypted record protocol. That gap must be resolved inside the
F7 laboratory without changing DOM consensus, transaction wire encoding, or
the already-frozen `DSC1` application envelope.

## Context

Normative application bytes are defined by Master sections 8.1–8.5:

- `DSC1`, version 1, zero flags;
- fixed chain/session/sender/sequence/transcript fields;
- a closed message-type registry and per-type bounds;
- a 65-byte participant identity signature;
- exact-length decoding before allocation;
- idempotent handling of identical bytes and terminal equivocation for
  different bytes under the same logical key;
- DOM-tagged transcript advancement after validation.

Transport identity keys are separate from spending keys. No coordinator or
relay may observe private collaborative-proof contributions.

## Decision

1. Implement the `DSC1` bytes exactly as specified. The unsigned digest and
   transcript use the authoritative DOM `blake2b_256_tagged` implementation;
   no local hash dialect is introduced.
2. Authenticate each application message with DOM's canonical Schnorr signer
   and verifier. The signed input is the `DOM:scriptless-message:v1` digest of
   the exact unsigned bytes, bound to the canonical chain ID. Identity key
   custody remains outside the transport crate.
3. Retain accepted exact bytes in a bounded session receiver. Identical
   redelivery returns the original receipt. Different bytes with the same
   `(session_id, sender_id, sequence)` permanently enter `FailedClosed`.
4. Carry canonical messages over
   `Noise_XX_25519_ChaChaPoly_BLAKE2s`. The Noise prologue binds chain ID and
   session ID. Each peer's X25519 static public key must be frozen in the
   negotiated transport terms, and the completed XX handshake must expose that
   exact key.
5. Noise records are chunked only below the application layer so the 512 KiB
   final-transaction payloads remain one canonical `DSC1` message. Chunk count,
   record lengths, and reassembled length are bounded and exact.

The Noise choice is a laboratory candidate because the Master does not freeze
the handshake. It does not modify any normative `DSC1` byte, DOM transaction,
consensus rule, challenge, Bulletproof, or adaptor-signature primitive.

## Alternatives considered

### Plain length-prefixed TCP

Rejected. Identity signatures provide authenticity but not confidentiality;
the relay could observe collaborative-proof material, violating the Master.

### TLS with public-CA certificates

Rejected for the laboratory protocol. Public PKI introduces an unrelated
identity authority and does not naturally bind the frozen Scriptless roster.
TLS remains usable as an outer operational tunnel.

### A new hand-written X25519/HKDF/AEAD protocol

Rejected. It would unnecessarily design and maintain a new cryptographic
handshake. Noise XX already supplies a reviewed state machine, forward-secret
key agreement, authenticated static keys, ordered nonces, and AEAD records.

### Extending Slate or the DOM P2P wire protocol

Rejected. The Master explicitly requires a separate envelope and prohibits a
new on-chain or consensus-visible Scriptless dialect.

## Invariants

- Exact `DSC1` bytes are authenticated before protocol acceptance.
- No unknown type, flag, version, trailing byte, oversized payload, zero
  identifier, sequence gap, replay, transcript fork, or unregistered sender is
  accepted.
- An identical duplicate performs no side effect and receives an identical
  acceptance result.
- Equivocation is terminal and evidence bytes are retained.
- Noise keys are distinct from identity and spending keys.
- The peer Noise public key and the chain/session prologue are fixed before
  application data is accepted.
- No private key, nonce, share, seed, or plaintext is formatted through
  `Debug`, serialized by this crate, or included in an error.
- Chunking cannot change, split, or re-encode the canonical application bytes.

## Compatibility and security impact

Existing Phase 1 crates had no transport API, so this is additive. Application
format compatibility follows the Master byte table. The encrypted record layer
is explicitly versioned by its prologue and is outside consensus. A future
ratified transport may replace Noise without changing `DSC1`; peers must not
silently negotiate between record protocols.

The implementation removes plaintext relay exposure and adds explicit replay,
equivocation, ordering, and transcript enforcement. It does not claim network
anonymity; Tor or an equivalent network-privacy layer remains an operational
deployment concern.

## Verification

`cargo test -p dom-scriptless-transport` covers:

- exact encode/decode and canonical DOM signature verification;
- every truncation and a trailing-byte refusal;
- per-type payload ceilings;
- signature and context substitution;
- exact duplicate acknowledgement and terminal equivocation;
- sequence gap, transcript fork, phase mismatch, replay, and outsider refusal;
- a real Noise XX handshake over an OS socket pair;
- peer static-key authentication and chain/session prologue binding;
- encrypted round trip of a maximum-size final transaction using multiple
  Noise records.
