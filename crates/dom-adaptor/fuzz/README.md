# G1a parser fuzzing

These persistent targets exercise the public, fixed-width G1a parsers and the
authoritative DOM point/scalar/signature parsers. `canonical_messages` also
exercises the bounded `SessionContextV1` decoder and the closed purpose,
direction, and signing-phase registries. Secret nonce material is never a fuzz
input and is not written to the corpus.

Multi-parser targets consume a dedicated selector byte before passing the
remaining payload to a parser, so every canonical magic prefix remains
reachable. The fuzz package uses only production constructors and does not
enable a synthetic-chain feature in the production crate.

Run a bounded local campaign with:

```text
cargo fuzz run canonical_messages -- -max_total_time=60
cargo fuzz run adaptor_pre_signature -- -max_total_time=60
```

Passing a bounded campaign is evidence only for that platform and duration. It
does not substitute for independent vectors, sanitizer evidence, or full G1a
approval.
