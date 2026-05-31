# DOM Protocol Attack Surfaces

## External Inputs

Every external input must be considered hostile until fully validated.

### P2P Messages

Audit for:

- Malformed binary payloads.
- Oversized messages.
- Recursive or deeply nested parsing.
- Invalid transaction/block propagation.
- Peer-controlled resource amplification.
- Missing authentication or message domain separation where applicable.

### RPC / API

Audit for:

- Unsafe administrative endpoints.
- Missing authentication.
- Dangerous debug methods exposed in production.
- Input validation failures.
- Path traversal or arbitrary file access.
- Information leakage.

### Wallet Inputs

Audit for:

- Invalid addresses.
- Unsafe fee values.
- Negative, zero, overflow, or precision errors.
- Unsafe file import/export.
- Seed phrase handling.
- Replay-prone transaction construction.

### Blocks and Transactions

Audit for:

- Invalid commitments.
- Invalid range proofs.
- Invalid kernels.
- Duplicate inputs.
- Duplicate outputs.
- Oversized transaction sets.
- Malformed serialization.
- Cut-through edge cases.

### Database / Storage

Audit for:

- Corruption handling.
- Partial writes.
- Atomicity of state transitions.
- Replay mismatch.
- Unsafe migrations.
- Non-deterministic persisted state.

### Configuration and Environment

Audit for:

- Dangerous default flags.
- Mainnet/testnet confusion.
- Debug bypasses.
- Weak default ports, credentials, or secrets.
- Production code relying on local paths.

## High-Risk Code Patterns

Search for:

- `unwrap()` / `expect()` in network or consensus paths.
- `todo!()` / `unimplemented!()`.
- `panic!()` reachable from external input.
- `unsafe` blocks.
- `allow`, `ignore`, `skip`, `bypass`, `insecure`, `debug`, `test_only`.
- Silent error swallowing.
- Non-atomic multi-step state changes.
- Unbounded vectors, queues, maps, or recursion.

