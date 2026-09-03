# Engineering Sources

## DOM Wallet V1 and V2

DOM Wallet V1 and V2 provide DOM-specific experience, validated behavior, protocol integration, backup mechanisms, chain-ID protections, transaction formats, fee and weight rules, tests, and known failure cases.

Existing DOM components must be evaluated individually and classified as retained, adapted, independently reimplemented, or rejected.

## Epic Wallet

Epic Wallet is an engineering reference for architecture, lifecycle management, storage, synchronization, recovery, API separation, failure handling, and testing.

Reference commit: `cd3c9677cf67a68122a496cf601c47978cf99285`.

## Governing rule

`DOM semantics > Epic strategy`

For every adopted strategy, the project must document the problem solved, protected property, DOM-specific invariant, independent DOM-native implementation, and tests required to prove equivalence.

Epic source code, tests, comments, identifiers, file layout, constants, and implementation-specific expressions must not be copied.
