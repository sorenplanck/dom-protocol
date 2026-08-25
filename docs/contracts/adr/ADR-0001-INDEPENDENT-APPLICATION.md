# ADR-0001: Independent DOM Contracts Application

Status: Accepted by operator architecture addendum P1-ARCH-002
Date: 2026-08-04

## Context

Earlier implementation evidence placed Scriptless storage and nonce safety in
the ordinary DOM Wallet repository. P1-ARCH-002 replaces that ownership model.

## Decision

DOM Contracts is a separate application and repository. It owns independent
keys, storage, protocol state, nonce safety, and outputs. The ordinary DOM
Wallet remains free of Scriptless imports, initialization, state, and network
connections. DOM Core owns the canonical cryptographic backend and
`dom-adaptor`.

## Consequences

Previously written Wallet-side code is evidence and potential review input,
not a migration source. It must not be copied mechanically. The production
adapter dependency remains blocked until an approved DOM Core revision is
publicly available. Existing consensus and wire formats remain unchanged.
