# D-029 — text for section 12.1 of the Foundation Document

Insert verbatim into §12.1, after D-028, in the register's own format.

**D-019's decision text is not edited.** A ratified decision record is
immutable: it records what was decided on 2026-08-10 and remains true as that
record. This decision carries the amendment and states the **complete
resulting** registry and mapping in its own text, so that a norm mirror has
one source to transcribe from rather than two stitched together.

---

```text
D-029  2026-08-19  RATIFIED (explicit operator decision, 2026-08-19)
  Problem:       the F7 laboratory's two Relay-loss acceptance rows carry
                 one canonical DSC1 signing message between the two route
                 participants. D-019 closed the Relay V1 message-kind
                 registry at 0x0004 and requires an explicit ratification
                 for any new type. A DSC1 signing message matches none of
                 RfqV1, QuoteV1, AcceptanceV1 or SelectionV1, so no
                 admissible (role, message_type) pair existed for it and
                 the Relay refused the envelope before any transport code
                 ran. The executor implemented the value marked NOT
                 RATIFIED in the code and reported the gap rather than
                 filling it, and refused the alternative of declaring the
                 message a QuoteV1, which would have made the envelope
                 assert that the message is something it is not.
  Decision:      the Relay V1 message-kind registry admits exactly one
                 additional value and remains CLOSED.

                 Resulting registry, as amended by this decision:

                 0x0000 = INVALID/RESERVED
                 0x0001 = RfqV1
                 0x0002 = QuoteV1
                 0x0003 = AcceptanceV1
                 0x0004 = SelectionV1
                 0x0005 = RouteTransportV1
                 0x0006..0xffff = RESERVED/UNKNOWN in V1

                 Resulting sender authorization mapping:

                 Initiator: RfqV1, AcceptanceV1, SelectionV1, RouteTransportV1
                 Solver:    QuoteV1, RouteTransportV1
                 Observer:  no type; the observer emits no messages

                 D-019 is amended in this single respect. Its text is
                 unchanged and remains the record of what was decided on
                 2026-08-10.
  Scope:         RouteTransportV1 carries one canonical DSC1 signing
                 message, opaque to the Relay. The Relay never decodes the
                 payload and never adjudicates it; the Contracts session
                 store remains the sole adjudicator of the message. The
                 value carries no economic authority.
  Preserved:     every other rule of D-019 stands, including the
                 fail-closed treatment of unknown kinds, the immutability
                 of values 0x0001-0x0004 and their permitted roles, the
                 prohibition on filling future gaps by inference, and the
                 rule that the Relay authorizes the HEADER while the
                 recipient consumer verifies the inner object.
  Basis:         five settled laboratory routes executed under this value
                 before ratification, each recorded in
                 F7_CONTINUATION_LEDGER.md: the relay process-loss row 38
                 (four consecutive settlements) and the relay database-loss
                 row 39, the latter reconstructing a destroyed Relay
                 database from participant-retained envelopes through the
                 authenticated recovery path. That the rows ran before
                 ratification is an irregularity of sequence, disclosed in
                 the amendment document, and not a merit of the evidence.
  Status:        RATIFIED. This decision is the single source from which
                 any normative mirror of the registry or the role mapping
                 is transcribed.
```
