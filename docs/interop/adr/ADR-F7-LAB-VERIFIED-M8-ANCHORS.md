# ADR-F7-LAB: Verified real-chain M.8 funding anchors

- Status: Accepted for the isolated F7 laboratory
- Scope: DOM Interop F7 composition only
- Normative authority: Annex M v3.3, M.8 and Foundation v0.18, G-F7
- Format status: additive laboratory API; not a new DOM or Bitcoin wire format

## Problem

The M.8 timing implementation separates an immutable pre-funding policy from
the funding bases that only exist after confirmation. Its structural
`M8FundingAnchorsV1` value is intentionally serializable, so arbitrary callers
can construct it. Using such a caller-built value as the F7 signing gate would
not prove that either base came from a real canonical chain.

## Context

G-F7 requires the real DOM builder, RPC, mempool, verifier and scanner and does
not permit a mock at the gate. Annex M requires an independently verified
Bitcoin header chain and witness commitment. The DOM Scriptless scanner added
by this laboratory already returns canonical transaction bytes, transaction
grouping, block location and kernel signatures. Bitcoin Core can return the
full funding block and every header needed to establish ancestry and finality.

## Decision

The Store-free `f7-anchor-authority` leaf exposes one complete production gate:
`verify_f7_route_anchor_authority`. It accepts the concrete authenticated
`DomHttpChainAdapterV1`, canonical settlement terms, the frozen M.8 policy,
and full Bitcoin consensus evidence. It does not accept a caller-implemented
scanner trait or an already-constructed DOM anchor.

The gate scans DOM from the authenticated genesis cursor through one linked
snapshot tip, validates the scanner chain identifier against frozen terms,
finds the exact funding transaction once, proves that it creates the frozen
shared commitment exactly once without spending it, and derives inclusion
height, authenticated block time, and confirmation depth from scanner data.

For Bitcoin, it decodes the full funding block with the pinned `bitcoin`
crate, validates its Merkle root and required witness commitment, finds the
expected transaction exactly once, validates proof of work and linkage from
the canonical regtest genesis through the required confirmation depth,
enforces the canonical regtest target on every header, rejects headers whose
timestamp is not strictly after the preceding eleven-header median, and
independently derives the BIP68 base MTP of the block immediately preceding
funding from verified header timestamps.

Only after both evidence paths pass does the gate construct
`M8FundingAnchorsV1`, invoke the frozen M.8 inequality, and return one linear
`VerifiedF7RouteAnchorAuthorizationsV1`. Consuming that value yields the sole
non-cloneable `VerifiedF7AnchorAuthorizationV1` for the Contracts Store and
two participant-specific Bitcoin nonce authorizations. No raw evidence digest
or intermediate caller-shaped capability can mint either signing authority.
Direct construction of the structural anchor object remains useful for M.8
codec/property tests but is ineligible for the G-F7 gate.

The new bridge is regtest-only. Public and custom Signet remain under the
existing F5 evidence pipeline because their challenge and difficulty policy
must be frozen and verified; a merely linked chain with self-declared targets
is insufficient.

## Alternatives considered

- Trusting block height, hash and MTP returned as ordinary RPC fields was
  rejected because those fields are forgeable outside the authenticated
  scanner boundary.
- Reimplementing Bitcoin consensus/header validation was rejected. Parsing,
  hashing, Merkle, witness-commitment and proof-of-work checks use the pinned
  `bitcoin` crate.
- Adding funding anchors to the already frozen pre-funding terms was rejected
  because the anchors do not exist when those terms are signed.
- Treating the existing F5 Signet verifier as a generic regtest adapter was
  rejected because the network profiles and evidence acquisition paths differ.

## Invariants

- No signing capability is minted from caller-provided DOM identifiers or a
  caller-implemented evidence trait.
- The authenticated DOM chain identifier must equal the DOM chain identifier
  frozen in canonical settlement terms.
- The expected DOM and Bitcoin funding transaction IDs must match canonical
  scanner evidence exactly; DOM evidence must also create the expected shared
  output exactly once and meet the frozen confirmation policy.
- Bitcoin ancestry starts at the canonical regtest genesis, has exactly the
  declared block height, and is contiguous through the funding block.
- Every header uses the canonical regtest proof-of-work target; a linked chain
  cannot make itself valid by declaring an easier target.
- Every non-genesis header timestamp is strictly greater than the median of up
  to its eleven verified predecessors.
- Bitcoin confirmation depth includes the funding block and must satisfy the
  frozen finality policy.
- The BIP68 base MTP is computed from the block immediately before funding and
  up to its ten immediate verified ancestors; it is never accepted as an
  unauthenticated scalar.
- The complete block must pass the requested witness-commitment check.
- Cross-network or unsupported Signet evidence fails closed.
- This bridge changes no DOM consensus, wire encoding, mempool rule or Bitcoin
  consensus implementation.

## Compatibility and security impact

The change is additive and does not alter existing F5 or M.8 bytes. Existing
component tests may still build structural anchors, but their reports must not
claim G-F7. The combined F7 harness gains a type-level boundary that prevents
accidental promotion of fixture identifiers to real-chain evidence. Reorgs
remain handled by the anchored DOM scanner and Bitcoin observer; a previously
issued capability must be invalidated when either evidence reference is no
longer canonical.

## Tests

The `f7-anchor-authority` crate (re-exported by `f7-e2e`) verifies:

- a full regtest-shaped funding block and genesis-rooted header chain;
- exact transaction inclusion and independently derived MTP;
- confirmation-depth enforcement before the nonce gate;
- rejection of broken/reordered ancestry;
- rejection of an absent or different funding transaction.

The ignored real-Bitcoin F7 test obtains the full funding block and every
ancestry header from an isolated Bitcoin Core regtest node and passes them
through the same verifier. The final combined harness invokes
`verify_f7_route_anchor_authority` with the concrete real DOM adapter; the
Contracts Store consumes its opaque DOM authorization by value.
