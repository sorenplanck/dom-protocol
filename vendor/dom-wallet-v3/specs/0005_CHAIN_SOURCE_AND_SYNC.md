# DOM Wallet V3 Chain Source and Synchronization

**Status:** REVIEW
**Owner:** Soren Planck

## Purpose and scope

This specification defines a transport-independent `ChainSource` contract and deterministic wallet synchronization. It controls observation of the DOM canonical chain; it does not define a network transport, a foreign wire format, consensus validation rules, or final transaction lifecycle. A source supplies evidence and bounded data; it never owns wallet state.

## Authoritative sources and terminology

Sources are 0000 through 0004, `docs/CONFIRMED_DESIGN_INPUTS.md`, and DOM Wallet V1/V2 chain reconciliation behavior. `DOM-W2-SYNC-001` is a confirmed mandatory requirement. A **canonical cursor** is the verified pair `(height, block_hash)` committed in the same DUW as the observations it summarizes. A **ScanTarget** is the wallet-domain record `{ target_height, target_block_hash, source_identity, scan_bounds, evidence_version }` that binds one bounded scan attempt to evidence the adapter obtained. It is a WALLET POLICY record, not a DOM Protocol StableView guarantee, finality rule, witness, or node endpoint. A **reconciliation** derives wallet chain observations from a validated ScanTarget and local intent.

## ChainSource contract and boundaries

An adapter MUST expose these transport-neutral capabilities, or explicitly report them unsupported before sync starts:

| Contract operation | Required result |
|---|---|
| Negotiate capabilities | Protocol/schema version, selected DOM chain ID, maximum page and response limits, target-tip evidence, hash-at-height, bounded ancestry evidence, output/spend scan data, and error classification. |
| Obtain canonical tip | Claimed height, block hash, chain ID, source identity, and freshness metadata sufficient to validate the response. |
| Obtain hash at height | Exact height, hash, chain ID, and target-compatible evidence; absence is an explicit result, not an inferred hash. |
| Obtain ancestry evidence | Bounded sequence or proof of hashes linking requested heights to the claimed ScanTarget. |
| Scan range | Ascending bounded pages of DOM scan data, page continuation, range bounds, target-compatible evidence, and resource accounting. |
| Query transaction or output observation | Bounded DOM-native identifiers and ScanTarget-compatible evidence, where capability supports it. |

Source authentication identifies a responder or channel; data validity requires chain ID, schema, boundedness, ScanTarget validation, and DOM-consistent evidence. An authenticated source MAY be stale or malicious. A source MUST NOT receive wallet secrets, private contexts, unredacted audit data, or authority to modify local control.

## Mandatory freshness rule: DOM-W2-SYNC-001

Freshness MUST compare both height and block hash. A wallet MAY skip reconciliation only when it can verify that the source's canonical tip has the same height and the same block hash as its committed cursor, with compatible chain ID and valid view evidence. A same-height reorg MUST force reconciliation. A lower-height canonical view MUST force reconciliation. A missing hash, changed hash, unverifiable hash, absent cursor, chain mismatch, or invalid view binding MUST force reconciliation or a fail-closed recovery state; none may be treated as fresh.

Cursor advancement and every corresponding output, spend, transaction, maturity, recovery-event, and audit change MUST commit atomically in the DUW defined by 0004. A height-only shortcut is prohibited.

## Owner-approved ScanTarget policy

The ChainSource adapter MUST obtain and validate a target tip containing both `target_height` and `target_block_hash` before a bounded PMMR or output-range scan begins. Height alone never establishes freshness or coherence. It MUST create one ScanTarget with the target, the source identity, the negotiated finite scan bounds, and an evidence-version identifier. The adapter MUST derive or obtain only the range corresponding to that target; it MUST NOT silently extend the scan to a later tip.

Every page, staged record, and discovered wallet mutation MUST carry the same ScanTarget and remain provisional until final validation. Provisional results MUST NOT update the canonical cursor, confirmed balances, canonical output state, maturity state, transaction-confirmation state, or reorganization-completion state. A resumable staged record is permitted only when it is non-canonical and retains its ScanTarget.

Before activation, the adapter MUST reacquire sufficient evidence that the target hash remains canonical at the target height and that the scanned bounds still correspond to the target. A later tip is acceptable only when bounded ancestry or hash-at-height evidence proves that the original target remains canonical; a higher height alone does not validate a scan. Lower target tip, changed, missing, or unverifiable target hash, changed source identity, inconsistent page evidence, mutated bounds, source disagreement, unavailable ancestry evidence, or exhausted bounds MUST invalidate or quarantine staged results. The wallet MUST NOT advance its cursor and MUST enter typed reconciliation, begin a fresh bounded scan, or use the full-rescan fallback.

Canonical activation MUST atomically commit cursor `(height, block_hash)` and every wallet-state mutation justified by the ScanTarget. A crash before activation leaves the prior canonical generation active. Atomic publication MUST reopen either the complete prior generation or the complete new generation, never a mixture. Resumed work MUST revalidate its ScanTarget before using staged progress; otherwise it MUST invalidate that progress. Source switching MUST invalidate active target evidence unless the replacement independently proves the same target and required ancestry. Retry, page, and ancestry work MUST be bounded and fail closed.

## Synchronization behavior

**Initial scan** obtains capabilities, validates chain ID, obtains a ScanTarget, scans bounded pages from the configured genesis/recovery boundary to that target, and validates page continuity and target evidence. It MUST keep all effects provisional until the Owner-approved ScanTarget policy completes atomic activation; it MUST not present a final balance before then.

**Incremental sync** first executes the mandatory freshness rule. If not fresh, it obtains sufficient ancestry evidence to decide whether the cursor is on the claimed chain. If it is, it scans from the cursor successor through a ScanTarget. If it is not, it invokes 0006. A source response changing target evidence, height, hash, chain ID, order, range, or page continuity during the scan invalidates the scan attempt; the wallet MUST restart from a committed checkpoint or switch source.

**Reconciliation** applies all observations and maturity recalculation to the canonical model, preserves local intent, and commits changes with the cursor. Repeating reconciliation against the same stable canonical view and local intent MUST be idempotent. A **full rescan** discards only derived chain observations and indexes as authorized by 0006, retains local intent and non-reuse evidence, and deterministically rebuilds observations from an approved scan boundary.

## Pagination, limits, retry, and source switching

Pages MUST be ascending, non-overlapping, bounded by negotiated limits, bound to the same ScanTarget, and include enough identity to detect omission, duplication, or reordering. The wallet MUST set maximum response bytes, records per page, pages per operation, scan height span, ancestry depth, retries, time, and memory. Exhaustion, malformed response, inconsistent target evidence, unavailable capability, timeout, authentication failure, and chain mismatch are distinct error classes.

Retries MAY repeat an idempotent read against the same source only while its ScanTarget remains valid. On switching sources, the wallet MUST renegotiate capabilities and independently prove the current target and ancestry before retaining staged work; it MUST NOT splice pages from unrelated targets. Repeated inconsistency or exceeded limits MUST fail closed into a resumable recovery state, with a user-visible provisional status and a safe full-rescan option.

## Persistence, crash, restart, and reorganization

Read responses are not durable wallet state. Before any cursor checkpoint is durable, all associated records MUST have passed domain validation and be included in the same DUW. A crash before acknowledgement leaves the previous cursor authoritative. A crash after acknowledgement resumes from the committed cursor and recovery event; it MAY re-read pages but MUST produce the same state. ScanTarget evidence is valid only through final validation; expired or unverifiable evidence requires a fresh ScanTarget and reconciliation.

Same-height hash divergence and lower tips are reorganization entry conditions. The wallet MUST preserve the triggering evidence, invoke the durable plan of 0006, and block selection from provisional chain observations until the plan reaches a committed safe phase. A source that cannot provide required bounded ancestry evidence MUST not cause guessed rollback; it requires safe full rescan or recovery.

## Valid and invalid behavior

Valid behavior validates negotiated chain identity and bounded ScanTarget evidence, reconciles idempotently, and commits the cursor with observations. Invalid behavior includes accepting height alone as freshness, advancing cursor independently, treating an authenticated source as authoritative consensus, accepting foreign-chain pages, mixing targets, guessing ancestry, using unbounded responses, or marking a balance current after a failed or partial scan. Invalid input MUST not mutate canonical observations.

## Security considerations

Query minimization and capability separation SHOULD limit privacy leakage. The wallet SHOULD vary or batch source queries only when that does not weaken correctness. It MUST bound malicious-source work and preserve enough redacted evidence to diagnose recovery without revealing output ownership. Source selection and transport authentication are deferred to 0010; their absence cannot relax data validation.

## Required verification

| Test class | Required coverage |
|---|---|
| Unit tests | Capability validation, ScanTarget construction, cursor comparison, page continuity, error taxonomy, and rejection of mismatched chain/target/hash. |
| Property tests | Repeated reconciliation is idempotent; arbitrary page segmentation equals one-page scan; no cursor advances without matching ScanTarget-validated observation state. |
| Integration tests | Same-height divergence, lower target tip, target hash disappearance or change, unverifiable hash-at-height, source identity change, source disagreement, page inconsistency, bound mutation, later tip with and without target ancestry proof, bounded ancestry exhaustion, source switch, restart with valid or invalidated target, full rescan, and DOM-native maturity observations. |
| Fault-injection tests | Interrupted provisional scan, crash before activation, crash during atomic publication, no partial canonical cursor advancement, page loss/duplication/reordering, source failure during switch, and exhausted limits. |
| Fuzz targets | Capability replies, tip/hash/ancestry replies, page framing, oversized counts, inconsistent ranges, and malformed identifiers; no panic or unbounded allocation. |

## Acceptance criteria for ACCEPTED

The required future evidence includes the DOM-W2-SYNC-001 cases, ScanTarget activation and invalidation cases, 0004 cursor atomicity, 0006 bounded rollback, and DOM-consistent scan datum and maturity inputs. REVIEW records the complete policy contract; it does not claim execution of that evidence.

## Dependencies and unresolved decisions

Dependencies are 0001, 0002, 0004, and 0006. Specification 0003 supplies transaction observation/lifecycle mapping; 0009 supplies economic interpretation; 0010 supplies transport authorization.

* **ScanTarget policy:** the owner-approved bounded-source policy is authoritative here. It requires no DOM Protocol StableView guarantee and fails closed when adapter evidence is insufficient.
* **Minimum independent-source policy:** affects detection of a consistently malicious but internally coherent source. Evidence required: privacy, availability, and deployment threat analysis. Gate: 0010 and 0012 review.
* **Full-rescan recovery boundary:** affects scan cost and recoverability. Evidence required: approved 0007/0008 recovery guarantees. Gate: 0008 review.

## Review Blockers

None. DEC-STABLE-VIEW is resolved by the Owner-approved ScanTarget WALLET POLICY. DEC-RESCAN-BOUNDARY is later-gate recovery evidence, not a REVIEW blocker.
