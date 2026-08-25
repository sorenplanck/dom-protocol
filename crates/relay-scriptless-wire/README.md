# Relay Scriptless Wire V2 candidate

Status: **PROVISIONAL/NON-NORMATIVE — D-030 PROPOSED — AWAITS EXPLICIT OPERATOR RATIFICATION**.

This crate is a default-off, Store-free candidate for a versioned Relay V2
wire that can carry Noise handshake and transport ciphertext for DOM
Scriptless sessions. It is not a canonical specification, does not supersede
D-018 or D-019, and does not alter the byte-identical Relay V1 implementation.
D-029 remains reserved because of its orphaned M.8 provenance.

The candidate deliberately has no signing API, no secret-key custody, no
Store dependency, and no production enablement. With its opt-in feature it
verifies public BIP340 signatures through the already pinned `btc-crypto`
backend; without that feature every cryptographic validation fails closed.

All wire constants, vector labels, and status surfaces in this crate say
`PROVISIONAL/NON-NORMATIVE`. Their values remain operator choices until an
explicit ratification identifies the exact specification, fields, tags,
bounds, role map, validation order, and frozen vectors. Adding this crate to a
workspace is not ratification and must not remove any existing transport
blocker.

This isolated source candidate does not claim conformance with any separately
drafted LAB proposal. Where provisional layouts differ, neither prevails: an
explicit operator ratification must select one exact profile and its vectors.
