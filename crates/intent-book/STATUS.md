# intent-book — status: COMPILED, TESTS GREEN. NOT RATIFIED.

This crate implements `laboratory/design/INTENT_BOOK_DESIGN.md` under the
operator decisions of 2026-08-24T18:25Z (OQ-S2: it lives here, beside
relay/rfq/solver; OQ-S3: the D-019 registry is closed and untouched, so the
board is a service with its own edge; OQ-S4: merit weights are mandatory
configuration with no default, fail-closed) and the OQ-S9 decision of
2026-08-24T19:00Z, which unblocked dependency resolution by replacing the
eleven `file://` workspace URLs with their `https` origins at the identical
revisions (see `laboratory/design/LINEAGE_RECONCILIATION_MAP.md`).

## Measured state

- `cargo check -p intent-book`: clean. Two defects were found and fixed at
  the first compilation, both in `src/wire.rs` (`Digest32` is a type alias
  for `[u8; 32]` in `kaystra-core`, not a tuple struct; the original code
  used tuple-struct syntax at the two `intent_id` sites).
- `cargo test -p intent-book`: **8 passed, 0 failed** (`tests/board.rs`).
- Regression over the crates the board touches
  (`cargo test -p rfq -p kaystra-core -p solver -p relay -p f6-engine`):
  **195 passed, 0 failed** across 24 suites.

The eight tests cover the seven proofs this file required before any
behavioural claim, in order:

1. `the_public_phase_opens_exactly_at_solver_window_end` — the public
   phase opens only at `solver_window_end` (publication + the fixed
   120 s), boundary-exact, and an outsider sees nothing before it and the
   identical object after it;
2. `a_non_privileged_solver_is_refused_in_the_window_and_admitted_after`;
3. `phase_one_quotes_survive_and_compete_in_one_selection` — one
   `select_winner` call over quotes of both phases, phase-1 quote wins on
   net output;
4. `merit_configuration_is_fail_closed_per_field` — refusal per missing
   field, vacuous zero threshold/window refused, zero volume FLOOR
   admitted as an operator choice;
5. `the_entry_ladder_is_automatic_and_reconquerable` — volume-first
   ordering, automatic revocation and reconquest in both directions;
6. `canonical_bytes_round_trip_and_the_decoder_fails_closed` — round-trip,
   truncation at every prefix, trailing bytes, hostile length prefix,
   unknown version, dead-on-arrival deadline, redacted negotiation key;
7. `end_to_end_intent_to_frozen_terms_with_adversaries` — intent →
   private window → quotes from two `solver` instances → one ratified
   selection → `TermsBindingV1` carrying the winner's `solver_id`; the
   unregistered and suspended candidates are adjudicated by their §4.1
   names, the post-deadline quote is refused at the board, and a closed
   intent refuses further quotes; plus
   `a_board_message_kind_is_refused_by_the_relay_registry` — the D-019
   registry refuses a hypothetical INTENT kind (0x0006) for every role
   (`relay` is a dev-dependency only; the library keeps no runtime edge
   to the relay).

## What is still NOT claimed

That the design is ratified (it is a WORKING DRAFT under Norma 0.2), and
that the crate behaves correctly outside the tested fixtures. The merit
NUMBERS used by the tests (10 s threshold, 1_000_000 floor, 30-day window)
are fixture values, not defaults: the crate still refuses to start without
explicit operator values.
