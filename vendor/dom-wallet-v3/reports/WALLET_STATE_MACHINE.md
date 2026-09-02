# DOM Wallet V3 security state machines

Date: 2026-07-28

## Transaction lifecycle and exposure

`LocalTransactionIntent::transition` is the only production transition API. It
accepts a target lifecycle, exposure, and typed evidence. The transition graph
is exhaustive; unsupported edges fail with `InvalidTransactionTransition`.
`Cancelled` is terminal. `Confirmed` can only move to `Reorged` with
`ReorgEvidence`. Export and QR encode are read-only.

Exposure is independent and monotonic:

`NEVER_BROADCAST -> SUBMISSION_STARTED -> POSSIBLY_RELAYED ->
OBSERVED_IN_MEMPOOL -> CONFIRMED`

Before submission, `SUBMISSION_STARTED` and `SUBMITTING` are committed to the
encrypted wallet generation before network I/O. Unknown, timeout, restart, and
temporary-failure outcomes therefore retain reservations. Cancellation releases
reservations only for `NEVER_BROADCAST`; every later exposure requires
reconciliation.

Legacy states migrate conservatively. `Submitting`, `Submitted`,
`AcceptedNotRelayed`, `InMempool`, `RetransmitRequired`,
`ReconciliationRequired`, `Reorged`, `Failed`, `Confirmed`, or the legacy
`submitted` flag infer at least `POSSIBLY_RELAYED`.

## Node readiness

`derive_node_readiness(NodeReadinessSnapshot)` is the authoritative pure
derivation:

1. no process: `STOPPED`
2. critical task failure: `FAILED`
3. stale last successful status: `STALE`
4. unverified canonical identity: `STARTING`
5. zero peers: `WAITING_FOR_PEERS`
6. missing peer height: `UNKNOWN_PEER_HEIGHT`
7. verified local=peer=0 with peers: `CONNECTED_AT_GENESIS`
8. peer ahead: `SYNCHRONIZING`
9. fresh, verified equal known heights: `READY`

Mining accepts only `READY` or the explicit `CONNECTED_AT_GENESIS` policy. It
does not read the test-only IBD metric and never substitutes local height for a
missing peer height.

## Mining and synchronization workers

Mining and synchronization use explicit `IDLE/STARTING/RUNNING/STOPPING/ERROR`
runtime states. Worker bodies are panic-contained, their activity lease is held
for the worker lifetime, and every exit updates state and releases resources.
Finished `JoinHandle`s are reaped before restart. Stop is idempotent and returns
the runtime to a restartable state. A successful new run clears only that
worker's prior error slot.

Synchronization runs on a background worker and returns its initial status
promptly. UI/status requests use the cached synchronization snapshot while a
single bounded durable reconciliation page is active. The stop flag is checked
between every page and the service mutex is released before the worker yields.
Pause/stop joins the worker; resume continues from the encrypted canonical
cursor.

## Activity coordination

One `ActivityCoordinator` owns leases for wallet lifecycle, node lifecycle,
mining, synchronization, critical transactions, backup, restore/create staging,
updater apply, and shutdown. Updater and shutdown leases are exclusive.
Safe-point validation and updater reservation occur in the same critical
section. A closed or locked wallet is not sufficient: durable transaction state
must also be inspected. Once an updater lease exists, new protected mutation,
worker, node operation, or lifecycle transition is rejected until apply
completes or the lease drops.

## Recovery-required boundary

A poisoned service mutex never continues through the old value. Commands return
the stable non-retryable recovery-required error. The explicit managed-wallet
recovery command replaces the entire in-memory service and reconstructs it from
a structurally validated managed wallet on disk. No partially taken backend or
unlocked state is reused; node/sync caches and worker state are reset.

## Recovery phrase ceremony

An unconfirmed recoverable-wallet phrase is a durable policy gate. Dismissing
the view clears DOM and password state but does not bypass the gate. A later
unlock authenticates the password, reconstructs the phrase only inside a
zeroizing value, immediately re-locks the wallet, and redisplays the ceremony.
After durable confirmation, phrase reconstruction fails with the typed
`RECOVERY_PHRASE_ALREADY_CONFIRMED` result.

## QR multipart

`DOMQR5` frames carry version, UUID message ID, sender/receiver role, part
index/count, total length, SHA-256, and bounded payload. Reassembly binds every
frame to the initial envelope, accepts an identical duplicate idempotently,
rejects conflicts/oversize/wrong role, supports out-of-order frames, verifies
length and hash, and records completed hashes to reject replay.
