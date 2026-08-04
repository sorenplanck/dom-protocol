# G1a parser fuzzing

These persistent targets exercise the public, fixed-width G1a parsers and the
authoritative DOM point/scalar/signature parsers. They do not implement the
blocked canonical session context or secret two-nonce KDF.

Run a bounded local campaign with:

```text
cargo fuzz run canonical_messages -- -max_total_time=60
cargo fuzz run adaptor_pre_signature -- -max_total_time=60
```

Passing a bounded campaign is evidence only for that platform and duration. It
does not substitute for independent vectors, sanitizer evidence, or full G1a
approval.
