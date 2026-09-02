# Manual slate exchange

Phase 1B-A uses explicit copy-and-paste exchange for an experimental DOM slate
request and response. It is not Slatepack and does not claim compatibility
with any external transport.

## Transport

The transport text is deterministic:

```text
DOMSLATE1.<base64url-without-padding(canonical envelope bytes)>
```

The version-one envelope binds request/response role, network, exact chain ID,
slate UUID, canonical DOM slate byte length, canonical slate bytes, and a
Blake2b-256 content hash. The hash detects transport corruption but is not
authentication; DOM slate proof, signature, role, chain, and replay validation
remain mandatory. QR uses the exact text envelope when it fits. Larger values
use deterministic `DOMQR1` frames with the envelope content hash as message
identity, frame index/count, bounded base64url payload, and per-frame integrity
hash. Incomplete or mixed frames never reach slate parsing.

## Flow

1. Wallet A estimates the protocol fee and creates a send transaction. This
   reserves inputs and encrypts the sender context before any export.
2. Wallet A explicitly exports the request text.
3. Wallet B imports the request, reviews redacted details, and explicitly
   creates then exports a response. Its receive descriptor and non-reuse floor
   are durable before response export.
4. Wallet A imports the response, finalizes the canonical DOM transaction,
   and verifies the exact canonical bytes against the response.
5. Wallet A exports those public finalized bytes. Wallet B independently
   verifies them against its persisted response and durably retains the same
   bytes. A conflicting re-import fails closed.
6. Wallet A explicitly submits the already verified bytes through the
   configured node.

Steps 4 and 5 are the bilateral pre-broadcast verification boundary required
by the G0 common-wallet gate. Finalized transaction bytes contain public chain
material only; neither participant's Slate private context is exported.

The frontend renders QR locally and starts a local scanner only after explicit
user action. It releases the camera on successful scan, cancel, lock, close,
and page unload according to the implemented code paths. No QR frame, camera
image, pasted text, or reassembly buffer is stored in browser storage,
telemetry, diagnostics, URLs, or support bundles. Camera release evidence is
`CODE_PATH_AND_FOCUSED_STATIC_COVERAGE_ONLY`; no hardware camera test ran.
Public slate identifiers, amounts, fee, lifecycle, kernel identifier, and
submission result may be displayed. Private contexts, blindings, nonces,
offsets, root material, passwords, and credentials are never returned by the
Tauri DTOs.

## Tauri commands

The native command boundary registers `transaction_fee_estimate`,
`transaction_send_create`, `slate_request_export`, `slate_request_import`,
`slate_response_create`, `slate_response_export`, `slate_response_import`,
`slate_summary_redacted`, `transaction_finalize`, `transaction_submit`,
`transaction_retry_submission`, `transaction_cancel`, `transaction_list`, and
`transaction_detail_redacted`. They require an unlocked wallet where state is
protected, have strict bounded inputs, and expose redacted serializable results
only. `slate_qr_encode`, `slate_qr_decode_frame`,
`slate_qr_reassembly_status`, and `slate_qr_reassembly_clear` handle only the
public canonical transport representation; QR decoding never replaces backend
slate validation. No generic filesystem, shell, process, or HTTP bridge is
introduced.

The Rust service additionally exposes `transaction_finalized_export` and
`transaction_finalized_verify_and_import` for the G0 laboratory's exact public
byte exchange. A product transport must preserve the bytes exactly and apply
the same input bounds and redaction rules before these methods are registered
at a UI boundary.
