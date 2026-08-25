# ADR-F7-LAB: Relay V2 Scriptless Transport Proposal

- Status: **LAB PROPOSAL — NON-NORMATIVE — AWAITS EXPLICIT OPERATOR RATIFICATION**
- Date: 2026-08-14
- Scope: isolated F7 laboratory design only
- Candidate decision identifier: **D-030 (PROPOSED; not canonically allocated)**
- Numbering caveat: **D-029 is reserved pending provenance**
- Normative basis: Foundation v0.18, D-018 and D-019; F6 Engineering
  Specification v1.0; the frozen DOM Scriptless DSC1 and Noise authorities
- Current implementation effect: none; `RelayTransportAuthorityUnavailable`
  remains mandatory

## Non-authority warning

This document is a proposal, not a decision record and not a protocol
specification. The agent that prepared it has no ratification authority. Every
constant, byte layout, domain, role mapping, bound, state transition and test
vector described below is a **candidate**. None may reach a production or G-F7
path until the operator expressly ratifies the exact completed specification
and frozen vectors.

This proposal does not modify Foundation v0.18, the F6 v1.0 specification,
D-018, D-019, Relay V1, its four message kinds, its canonical bytes, its
digests, its ACK, or its validation order. It does not remove a blocker or
authorize a fallback transport.

## Problem

The F7 real-DOM route needs to carry the existing authenticated DSC1 signing
messages through the production Relay and an encrypted bidirectional Noise
stream. The current authorities do not compose that path:

- Relay V1 stores an opaque payload authenticated by a BIP340 roster key, but
  D-019 closes its message-kind registry at kinds `0x0001` through `0x0004`;
- the Contracts transport constructs
  `Noise_XX_25519_ChaChaPoly_BLAKE2s` over an ordinary `Read + Write` stream,
  not over a Relay delivery and ACK boundary;
- the Contracts identity Store signs exact DSC1 messages with a dedicated DOM
  Schnorr identity, but it does not own a retained BIP340 outer-envelope
  signer or a Relay-backed Noise stream;
- the runner can custody and submit an already canonical Relay envelope, but
  it cannot create that envelope without inventing signing authority or
  receiving secret DSC1 payloads.

Giving the runner a raw callback would expose common-nonce reveals, private
round-two shares or other protocol material. Sending DSC1 under a Relay V1 F6
kind would make the outer kind disagree with the inner object. Assigning V1
kind `0x0005` would directly contradict D-019. All of those paths are
forbidden.

## Authority and numbering

Foundation v0.18 names Soren Planck as the operator and ratification authority.
D-018 requires a new version, decision record and express ratification for a
later wire, digest, roster, binding or validation-order change. D-019 makes
Relay V1 kinds `0x0001` through `0x0004` immutable, reserves every other V1
kind, and requires explicit ratification plus a compatible normative version
for a new type.

The canonical registry currently ends at D-028. No D-029 record exists in the
audited repositories. Two non-normative laboratory documents nevertheless
refer to D-029 as the decision that deferred M.8. This proposal therefore does
not reuse D-029. It labels the candidate Relay decision D-030 and reserves
D-029 until the operator establishes its provenance. Only the operator may
confirm or replace that numbering.

Before ratification this file may be used to review options and build no-op,
default-off scaffolding. It may not be inserted into the canonical decision
registry or described as `DECIDED`, `RATIFIED`, `ADOPTED` or gate-closing.

## Proposed decision

If expressly ratified, Relay Scriptless traffic would use a new, strictly
version-separated Relay V2 profile. Relay V1 would remain byte-identical and
would continue to carry only F6 kinds 1–4. V2 would carry one closed outer
message kind whose opaque payload is a bounded Scriptless stream frame. The
outer envelope would be signed by a dedicated retained BIP340 roster identity;
the stream would run the already frozen Contracts Noise XX profile; and the
decrypted application bytes would still require the existing DSC1 signature
and Store transition checks.

The Relay would remain an untrusted, payload-opaque, store-and-forward
component. It would not own participant keys, create signatures, decode a
Scriptless frame, operate Noise, decide a signing transition, or become an
economic outcome authority.

## Candidate profile — not effective until ratified

Every `MUST`, `MUST NOT`, `SHALL`, `REQUIRED` and `FAIL CLOSED` statement in
this section is conditional: it would become normative only if the operator
ratifies the exact successor specification containing it.

### 1. Relay V1 preservation and cross-version rejection

Relay V1 remains exactly:

- envelope magic `DOMIRLY1`;
- wire version `1`, encoded as unsigned 16-bit big-endian;
- envelope digest domain `DOM-INTEROP/RELAY-ENVELOPE/V1`;
- payload digest domain `DOM-INTEROP/RELAY-PAYLOAD/V1\0`;
- message kinds `0x0001` `RfqV1`, `0x0002` `QuoteV1`, `0x0003`
  `AcceptanceV1`, and `0x0004` `SelectionV1` only;
- ACK magic `DOMIRLA1` and ACK version `1`;
- every existing field, role tag, timelock tag, bound, validation step and
  frozen vector.

A V1 decoder MUST reject every V2 envelope and ACK. A V2 decoder MUST reject
every V1 envelope and ACK. Implementations MUST NOT translate between versions,
negotiate a downgrade, reinterpret a V1 kind, or share a database table,
idempotency namespace, transcript namespace or recovery identity between V1
and V2.

### 2. Candidate Relay V2 envelope

The candidate V2 constants are:

```text
ENVELOPE_MAGIC_V2       = "DOMIRLY2"                         (8 bytes)
ENVELOPE_WIRE_VERSION   = 2                                  (u16 BE)
ENVELOPE_DOMAIN_V2      = "DOM-INTEROP/RELAY-ENVELOPE/V2"
PAYLOAD_DOMAIN_V2       = "DOM-INTEROP/RELAY-PAYLOAD/V2\0"
MAX_PAYLOAD_BYTES_V2    = 16_384
ENVELOPE_OVERHEAD_V2    = 358
MAX_ENVELOPE_BYTES_V2   = 16_742
```

The canonical V2 envelope uses this exact order:

1. magic: 8 bytes;
2. wire version: unsigned 16-bit big-endian;
3. network identifier: 32 bytes;
4. V2 message type: unsigned 16-bit big-endian;
5. session identifier: 32 bytes;
6. route identifier: 32 bytes;
7. sender participant identifier: 32 bytes;
8. recipient participant identifier: 32 bytes;
9. sender role: one byte (`1` Initiator, `2` Solver, `3` Observer);
10. addressed-flow sequence: unsigned 64-bit big-endian;
11. previous addressed-flow envelope digest: 32 bytes;
12. payload length: unsigned 32-bit big-endian;
13. payload digest: 32 bytes;
14. expiry: one tag plus unsigned 64-bit big-endian value, preserving V1 tags
    `1` BlockHeight, `2` TimestampSeconds and `3` BtcTime512s;
15. policy version: unsigned 32-bit big-endian;
16. roster snapshot identifier: 32 bytes;
17. opaque payload bytes;
18. BIP340 signature: 64 bytes.

Fields 1–17 are the complete canonical unsigned envelope. The payload digest
is:

```text
BLAKE2b-256(PAYLOAD_DOMAIN_V2 || payload)
```

The signed envelope digest is:

```text
BLAKE2b-256(ENVELOPE_DOMAIN_V2 || canonical_unsigned_envelope)
```

The 64-byte signature is produced only by the sender's dedicated canonical
V2 BIP340 roster key through the pinned D-013 authority. The Relay neither
produces nor verifies that signature as participant authority. The recipient
validates it against the exact frozen session binding before processing the
payload.

All size and integer conversions are checked before allocation. Unknown magic,
version, kind, role, timelock tag, truncation, trailing bytes, non-canonical
length or a mismatched payload digest fail closed.

### 3. Closed V2 message-kind and role registry

The candidate V2 registry is version-local and closed:

```text
0x0000          INVALID / RESERVED
0x0001          ScriptlessTransportFrameV1
0x0002..0xffff  RESERVED / UNKNOWN in Relay V2
```

Both the session Initiator and Solver may emit
`ScriptlessTransportFrameV1` to the other bound participant. Observer emits
no message. The role comes from the authenticated roster binding, not from a
caller or the self-declared header.

Using value `0x0001` in the separate V2 namespace does not reinterpret V1
`RfqV1`: magic, wire version, digest domains, codec, database namespace and
consumer are all disjoint. V1 kind `0x0005` remains invalid. The recipient
MUST verify that the decoded V2 payload is exactly the single V2 frame type and
that its direction and binding agree with the authenticated outer header.

### 4. Authenticated session binding

No caller-provided roster, key or raw digest may authorize the transport. A
Store-free verifier projects the accepted F6 journal and retained participant
identity references into one non-Clone opaque session-binding authority before
funding. The candidate canonical binding constants are:

```text
BINDING_MAGIC_V1   = "DOMIRSB1"                              (8 bytes)
BINDING_VERSION_V1 = 1                                       (u16 BE)
BINDING_DOMAIN_V1  = "DOM-INTEROP/RELAY-SCRIPTLESS-BINDING/V1\0"
PARTICIPANT_COUNT  = 2
```

The candidate canonical binding bytes use this exact order:

1. binding magic and version;
2. network id, session id, route id and roster snapshot: four 32-byte fields;
3. accepted F6 terms hash and canonical settlement terms hash: two 32-byte
   fields;
4. trusted DOM chain id: 32 bytes;
5. policy version: unsigned 32-bit big-endian;
6. participant count: one byte, exactly `2`;
7. designated Noise initiator participant id: 32 bytes;
8. two participant entries in the canonical settlement-roster order, each:
   participant id (32), Relay role tag (1), dedicated BIP340 x-only roster
   key (32), DSC1 compressed Schnorr public key (33), Noise X25519 static
   public key (32), and Noise role tag (1; `1` initiator, `2` responder).

The binding digest is:

```text
BLAKE2b-256(BINDING_DOMAIN_V1 || canonical_binding_bytes)
```

The designated Noise initiator must occur exactly once in the two entries and
must carry Noise role 1; the other entry must carry role 2. Every participant,
role, key, route, terms, chain, policy and roster field must match the
authenticated retained authorities. The BIP340 outer key, DSC1 Schnorr key and
Noise X25519 key are independently generated, purpose-bound and stored. Key
reuse or a caller-implemented binding source fails closed.

### 5. Candidate Scriptless stream frame

The outer Relay remains payload-opaque. The participant consumer strictly
decodes this candidate frame after outer authentication:

```text
FRAME_MAGIC_V1       = "DOMIRSF1"                             (8 bytes)
FRAME_VERSION_V1     = 1                                      (u16 BE)
FRAME_OVERHEAD_V1    = 63
MAX_FRAME_DATA_V1    = 12_288
MAX_FRAME_BYTES_V1   = 12_351
```

Canonical frame order:

1. magic: 8 bytes;
2. frame version: unsigned 16-bit big-endian;
3. frame kind: one byte;
4. epoch id: 32 bytes;
5. generation: unsigned 64-bit big-endian;
6. directed-stream offset: unsigned 64-bit big-endian;
7. data length: unsigned 32-bit big-endian;
8. exact data bytes.

The closed kind registry is:

```text
1  EpochOpen
2  StreamData
3  EpochAbort
all other values invalid
```

`EpochOpen` may be emitted only by the designated Noise initiator. Its
generation is at least 1, its stream offset is zero and its data is exactly a
fresh 32-byte operating-system CSPRNG epoch nonce. Its epoch id is:

```text
BLAKE2b-256(
    "DOM-INTEROP/RELAY-NOISE-EPOCH/V1\0" ||
    binding_digest || generation_be || epoch_nonce_32
)
```

`StreamData` may be emitted by either participant. It contains 1 through
12,288 bytes from the existing Noise byte stream. Its binding, epoch and
generation must match the one active epoch, and its offset must equal the next
contiguous byte offset for that sender-to-recipient stream.

`EpochAbort` may be emitted by either participant. Its data is empty and its
offset equals that direction's next expected offset. It durably closes the old
epoch; no later frame from that epoch may enter Noise.

The frame has no independent signature. The exact frame bytes are covered by
the outer payload digest and BIP340 signature.

### 6. Epoch and Noise rules

V2 transports only the raw byte stream of the already frozen Contracts profile:

```text
Noise_XX_25519_ChaChaPoly_BLAKE2s
```

Its prologue remains byte-identical:

```text
"DOM:scriptless-noise:v1" || trusted_dom_chain_id || session_id
```

Outer BIP340 authentication does not replace Noise peer authentication, and
Noise does not replace DSC1. The required receive order is:

1. bound outer size and strict V2 canonical decoding;
2. network, version, kind, session, route, recipient, role, policy and roster
   binding;
3. outer payload digest and BIP340 signature;
4. expiry, idempotency, sequence and previous-transcript continuity;
5. strict frame decoding, epoch, generation, direction and offset checks;
6. Noise handshake or transport processing;
7. exact DSC1 decoding, retained identity signature verification, replay,
   sequence, purpose and Store transition checks;
8. application processing only after every prior check succeeds.

There is exactly one active epoch per session binding. The first generation is
1. A later generation is exactly the preceding generation plus 1. Generation
overflow fails closed. Outer addressed-flow sequence numbers do not reset at
an epoch boundary.

The Snow `TransportState` is never serialized or reconstructed from caller
bytes. A live participant that loses only a Relay storage ACK resubmits the
same retained canonical outer envelope byte-for-byte and receives the same
ACK. A participant process restart durably abandons its old nonserializable
Noise state, opens the next generation with a fresh Noise XX handshake and
replays only the exact retained DSC1 application bytes that remain eligible.
New Noise ciphertext and therefore new outer-envelope bytes are expected in a
new epoch; they are not described as a byte-identical retransmission. Old-epoch
frames never feed the new Noise state.

### 7. Sequence, transcript and equivocation

The candidate V2 idempotency key is:

```text
(session_id, sender_id, recipient_id, sequence)
```

Sequence is per addressed flow. The first sequence is 0; every successor is
exactly the preceding value plus 1. Sequence overflow, gap and reorder fail
closed. For sequence 0, `previous_transcript_hash` is 32 zero bytes. Otherwise
it equals the exact preceding accepted V2 envelope digest in that addressed
flow.

The same key plus the same exact canonical envelope bytes is an idempotent
retry. The same key plus different bytes is durable, third-party-verifiable
equivocation and fails closed. Inner DSC1 replay, reorder or equivocation is
also checked independently after decryption; outer acceptance cannot repair an
inner refusal.

### 8. Candidate V2 storage ACK

```text
ACK_MAGIC_V2   = "DOMIRLA2"                                  (8 bytes)
ACK_VERSION_V2 = 2                                            (u16 BE)
ACK_LENGTH_V2  = 146
```

Canonical ACK order is magic (8), version (2), session id (32), sender id
(32), recipient id (32), sequence (8 big-endian) and stored envelope digest
(32). It contains no payload, first-versus-duplicate flag, delivery claim,
dequeue claim or economic authority.

The Relay returns the ACK only after the exact canonical envelope is durably
committed. A lost ACK is recomputed only from the retained exact row. Same key
plus same bytes yields the same 146 ACK bytes after retry or Relay restart.
Same key plus different bytes creates a durable equivocation refusal. This
proposal adds no recipient dequeue ACK.

### 9. Durability, restart and database loss

V2 uses its own owner-only database identity, schema, tables, row domains,
conflict domains, recovery domains and filenames. No V1 row is accepted into a
V2 table and no V2 row into a V1 table.

Participant custody retains the exact signed outer envelope until its storage
ACK is authenticated. Relay process restart reopens the existing database and
reconstructs ACKs and deliveries from exact rows. Open never creates a missing
database. Corrupt state is not salvaged.

Relay database-loss reconstruction accepts only nonempty authenticated batches
of exact encrypted V2 envelopes retained by the participant Store/outbox or by
an explicitly permitted public-chain source. Every candidate passes the full
V2 codec, roster signature, idempotency, sequence and transcript pipeline
before publication. Caller-shaped raw bytes or a generic recovery trait do not
become authority.

Claim, refund, timeout and terminal settlement transitions never depend on
Relay availability or Relay database state. Relay loss may delay transport but
cannot authorize, select or reverse an economic outcome.

### 10. Candidate bounds

The candidate profile freezes these independent bounds:

```text
maximum outer payload                    16_384 bytes
maximum canonical outer envelope         16_742 bytes
maximum inner frame data                 12_288 bytes
maximum canonical inner frame            12_351 bytes
maximum stored V2 envelopes              65_536
maximum delivery page                    256 envelopes
maximum submitted but storage-unACKed
  frames per addressed flow              1
active Noise epochs per binding          1
participants per Scriptless binding      2
```

Lengths are validated before allocation. Delivery is paged and never returns
an unbounded collection. Queue capacity, page bounds, sequence, offset,
generation, count and length arithmetic use checked operations. Exhaustion or
overflow fails closed without dropping an authenticated row or weakening
equivocation evidence.

## Ratification conditions

No implementation may treat this proposal as canonical. Ratification requires
all of the following to exist simultaneously:

1. an exact final
   `docs/normative/DOM-Interop-Relay-V2-Scriptless-Transport-Specification-v1.0.md`
   containing every field, tag, domain, bound, validation step and state rule;
2. a major-version Foundation successor, proposed as
   `docs/normative/DOM-Interop-Foundation-Document-v1.0.md`, that records the
   final decision identifier, marks v0.18 superseded, and preserves D-018 and
   D-019 for Relay V1;
3. explicit resolution of D-029 provenance and confirmation or replacement of
   candidate D-030;
4. frozen exact hex plus SHA-256 manifest for:
   - canonical session-binding bytes and binding digest;
   - one V2 unsigned envelope, envelope digest, BIP340 signature and complete
     canonical envelope;
   - one V2 ACK;
   - `EpochOpen`, `StreamData` and `EpochAbort` frames;
   - V1 rejecting each V2 object and V2 rejecting each V1 object;
5. independent review that all keys are purpose-separated and that no secret
   or decrypted DSC1 material reaches the Relay or runner;
6. an explicit operator statement identifying the exact specification and
   vector manifest.

A suitable statement, after the exact files and vectors exist, is:

> I expressly RATIFY D-030 and
> DOM-Interop-Relay-V2-Scriptless-Transport-Specification-v1.0 exactly as
> attached, including every wire constant, domain, bound, role mapping and
> frozen vector. Relay V1 under D-018/D-019 remains byte-identical and rejects
> V2; no translation or downgrade is authorized.

Generic approval before exact vectors exist does not freeze bytes. If any
candidate constant in this proposal changes, the final specification and
vectors must be regenerated and reviewed before ratification.

## Rejected alternatives

- **Use a Relay V1 kind 1–4 for DSC1.** Rejected because the authenticated
  outer kind would not correspond to the inner Scriptless object.
- **Assign Relay V1 kind `0x0005`.** Rejected because D-019 explicitly reserves
  it and requires a compatible new normative version.
- **Send direct Noise outside Relay.** Rejected because it bypasses the F7
  Relay loss, ACK and reconstruction proof and does not satisfy the requested
  integrated path.
- **Give the runner plaintext DSC1 or a raw signing callback.** Rejected because
  it exposes secret-bearing protocol material and invents authority outside
  the retained identity and Store boundaries.
- **Reuse the DOM DSC1 Schnorr key or Noise static key for outer BIP340.**
  Rejected because cross-protocol key reuse violates purpose separation.
- **Serialize Snow transport state.** Rejected because the authority does not
  define a canonical secure serialization; restart instead opens a fresh
  epoch.
- **Let callers provide a roster or binding digest.** Rejected because a raw
  digest is not evidence of the accepted F6 journal or retained identities.
- **Make Relay delivery an outcome condition.** Rejected because Relay is
  explicitly non-authoritative and losable.
- **Translate V1 to V2 or negotiate downgrade.** Rejected because it creates
  ambiguous signed material and reopens D-018/D-019 under attacker-controlled
  negotiation.

## Invariants

- Relay V1 bytes, kinds, domains, ACKs and vectors never change.
- V1 and V2 reject one another before payload processing.
- Only the authenticated F6 journal plus retained identity references can mint
  a Scriptless session binding.
- Outer BIP340, Noise X25519 and DSC1 Schnorr keys are distinct and
  purpose-bound.
- Relay stores only canonical signed encrypted envelopes and public metadata.
- Common reveals, private BP round-two shares, nonces, partial signatures,
  adaptor secrets, seeds, passphrases and decrypted DSC1 bytes never reach the
  Relay or runner.
- Outer auth, Noise auth and DSC1 auth are cumulative; none substitutes for
  another.
- Exactly one active Noise epoch exists; restart never reuses an old Noise
  state or epoch nonce.
- ACK loss with a live epoch resends exact outer bytes. Participant restart
  starts a new epoch and replays only eligible exact application bytes.
- Duplicate, replay, gap, reorder, equivocation, wrong roster, wrong route,
  wrong terms, wrong chain, wrong recipient, stale expiry and cross-epoch input
  fail closed.
- Relay loss or database loss cannot create economic authority or more than
  one terminal settlement outcome.

## Compatibility and security impact

The proposed change is additive at the deployment level but intentionally
incompatible at the wire-decoder level. V1 nodes continue to reject V2. V2
must use separate endpoints or an explicitly version-bound listener and a
separate durable namespace; it never relies on silent feature negotiation.
Existing F6 V1 sessions and evidence remain valid and byte-identical.

The extra outer signature supplies public equivocation evidence and binds the
encrypted stream to the accepted route. Noise supplies transport
confidentiality and peer authentication. DSC1 supplies purpose-specific DOM
protocol authentication and replay state. The layered checks reduce authority
confusion but add durable epoch and retransmission state; the bounded one-frame
storage-ACK window deliberately trades throughput for simple, auditable crash
recovery.

No DOM consensus, transaction, Bulletproof, Schnorr, adaptor, scanner, wallet,
RPC, mempool, genesis or wire rule changes.

## Acyclic implementation plan after ratification

1. Add a Store-free Interop leaf package, proposed as
   `crates/relay-scriptless-wire`, containing only the V2 codecs, domains,
   bounds, strict cross-version tests and the closed verifier that projects
   authenticated F6 journal data into a non-Clone session-binding authority.
   It has no Contracts, DOM, Wallet, `dom-leg` or runner dependency and exposes
   no generic caller-implementable authority trait.
2. Extend the Relay package with a V2 server and a physically separate durable
   V2 queue/recovery namespace consuming only the leaf codecs. Preserve the V1
   server and database without migration.
3. Let Contracts depend on the frozen leaf revision. Add a dedicated retained
   BIP340 roster-identity store, immutable session-binding record, exact
   outbound-envelope/ACK custody, inbound sequence/transcript/epoch journal and
   a Relay-backed bounded `Read + Write` stream used by the existing Noise
   constructor. No DOM or Wallet change is needed.
4. Add purpose-specific Contracts APIs that drive DSC1 send/receive through
   the retained V2/Noise authority and return only opaque progress or existing
   typed signing results. Never return frame payloads, Noise plaintext or
   secret-bearing envelopes to `dom-leg` or runner.
5. Let `dom-leg` consume the opaque Contracts driver. Let the runner select the
   scenario and Relay fault schedule but receive only public ACK/progress and
   terminal evidence.
6. Freeze the leaf and Contracts descendants, pin the acyclic graph exactly,
   then enable the previously typed-blocked executor path only after all
   focused proofs pass.

The intended dependency direction is:

```text
Store-free core/F6 journal types
        -> relay-scriptless-wire
        -> relay V2 durable queue
        -> Contracts identity/session Store + Relay-backed Noise
        -> dom-leg opaque driver
        -> f7-runner
```

No edge points from the leaf or Relay back to Contracts, `dom-leg` or runner.

## Required proof matrix after ratification

At minimum, the implementation must prove:

- exact V2 binding/envelope/frame/ACK vectors and cross-version rejection;
- roles and kinds closed for every unknown value;
- outer signature, stale roster, wrong recipient, route, terms, chain and
  policy refusal;
- independent-key and cross-session/cross-route substitution refusal;
- Noise XX handshake and maximum frame chunking over the real Relay-backed
  stream;
- exact DSC1 prefixes 0–6 through V2 without exposing common reveals or
  round-two shares;
- outer duplicate, replay, gap, reorder and signed equivocation;
- inner DSC1 duplicate, replay, gap, reorder and signed equivocation;
- crash before and after outer persistence, ACK publication, delivery,
  frame-journal update, Noise handoff and DSC1 Store acceptance;
- byte-identical envelope and ACK after storage-ACK loss;
- participant restart opening a fresh epoch and rejecting every old-epoch
  frame;
- Relay process loss and Relay database loss with authenticated reconstruction;
- reconstruction refusal for empty, caller-shaped, mixed-version, tampered or
  noncontiguous batches;
- queue/page/allocation/sequence/offset/generation bounds;
- no key, nonce, share, reveal, partial, adaptor secret, seed, passphrase or
  plaintext in Relay storage, logs, diagnostics or runner APIs;
- claim and refund completion with Relay absent, and exactly one terminal
  economic outcome.

## Current disposition

Candidate D-030 remains **RATIFICATION PENDING** and is not a canonical
decision. D-029 remains reserved pending provenance. D-018 and D-019 are not
superseded. Foundation v0.18 and F6 v1.0 are unchanged. Relay V1 remains the
only ratified Relay wire profile. The F7 executor must continue returning
`RelayTransportAuthorityUnavailable`; direct Noise and raw callback fallbacks
remain forbidden.
