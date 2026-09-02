# Reference Baseline

**Status:** Accepted as an input to the DOM Wallet V3 specification process.

## Purpose

This document fixes the engineering evidence used to begin the DOM Wallet V3 design. It does not import source code or make Epic behavior authoritative for DOM.

## Epic Wallet reference

- Repository: `/home/leonardov/wallet-reference-study/epic-wallet`
- Branch: `master`
- Commit: `cd3c9677cf67a68122a496cf601c47978cf99285`
- Role: mature engineering reference for architecture, lifecycle, persistence, synchronization, recovery, API separation, failure handling, and testing.

## DOM reference observed by the comparative study

- Repository: `/home/leonardov/dom-protocol`
- Branch at study baseline: `audit/final-prelaunch-security-gate`
- Commit at study baseline: `aa7f389a157af1b1a486dcb7e27cb80e7b543de3`
- Role: authoritative source of DOM consensus integration, cryptography, chain identity, transaction formats, economic rules, backup behavior, and protocol philosophy.

## Study result

The comparative study concluded with:

`READY_FOR_DOM_VNEXT_SPECIFICATION`

This verdict authorizes specification work only. It does not authorize production, mainnet, real funds, or replacement of an existing wallet.

## Governing rule

`DOM semantics > Epic strategy`

DOM Wallet V3 must preserve the DOM protocol model while independently implementing useful properties learned from DOM V1 and V2 and from the Epic Wallet study.

## Evidence integrity

The Epic and DOM repositories remained unchanged during the reference investigation. Reports and evidence artifacts were produced only in the authorized study directories.
