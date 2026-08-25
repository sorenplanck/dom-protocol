# FOUNDATION DOCUMENT — DOM INTEROP
## DOM-Centric Interoperability System (DOM v2 Project)

```text
Version:             0.16 — SUPERSEDED by v0.17 (2026-08-12)
Date:                2026-08-11
Owner:               Soren Planck (operator and ratification authority)
Lead executor:       Partner developer (to be formally defined)
State:               PARTIALLY RATIFIED — D-000, D-001, D-005, D-006, D-007,
                     D-008, D-009, D-010, D-011, D-012, D-013, D-014, D-015,
                     D-016, D-017, D-018, D-019, D-020, D-021, D-022,
                     D-023, D-024, D-025, D-026 and A7 ratified; the rest
                     remains DRAFT (/goat order and operator decisions of
                     2026-08-09/10/11, recorded in section 12)
Product name:        DECIDED (D-009): no standalone product name. This is
                     a component of the DOM ecosystem, destined for
                     integration into the DOM v2 (phase F8); "DOM
                     Interop" remains only the descriptive repository/
                     component name
Supersedes:          v0.15, v0.14, v0.13, v0.12, v0.11, v0.10, v0.9, v0.8, v0.7, v0.6, v0.5, v0.4, v0.3, v0.2.1, v0.2, v0.1 and the
                     "KAYSTRA-USPE-KEYSTONE-DOCUMENTO-MESTRE v1.0.1" master
                     document (all SUPERSEDED as context authority; useful
                     blocks ported here)
Language:            English is the normative language from v0.4 onward
                     (operator rule, 2026-08-10); earlier versions remain
                     in Portuguese as history.
Gate status:         G-F0 = PASS (docs/reports/F0-CLOSURE.md, waiver
                     R-001 lifted); G-F1 = PASS
                     (docs/reports/F1-CLOSURE.md §12); G-F2 = PASS
                     (docs/reports/F2-CLOSURE.md); G-F3 = PASS
                     (docs/reports/F3-CLOSURE.md; D-025, operator
                     adjudication 2026-08-11; F3 = COMPLETED); G-F4 =
                     PASS (docs/reports/F4-CLOSURE.md; D-026, operator
                     adjudication 2026-08-11; F4 = COMPLETED), on
                     workflow run 31521948686 executed at
                     main@593364b, tree aa215382.
                     NEXT REQUIRED GATE = G-F5: IN PROGRESS (D-012);
                     execution spec is Annex M v3.2; G-F5 NOT RUN
                     (M.15.2 public-signet leg outstanding). G-F6
                     EVIDENCE COMPLETE, adjudication deferred — of its
                     three blocking gates, G-F3 and G-F4 are now closed
                     and G-F5 remains. G-F7 BLOCKED by external
                     dependency. G-F8 NOT STARTED.
```

---

## P. PREAMBLE

### P.1 Mandatory taxonomy

- **[DECIDED]** — confirmed by the operator; current direction.
- **[PROPOSAL]** — introduced to complete the engineering; requires ratification.
- **[OPEN]** — not defined.
- **[BLOCKED]** — depends on evidence, implementation or external decision.
- **[OUT OF SCOPE]** — does not belong to this roadmap.

Every code excerpt in this document is **[PROPOSAL]**, except where marked
**[AUTHORITY: dom-adaptor eb6aa1c]** — in those cases the code is a
transcription of the crate's real API at the pinned rev and cannot be
altered by the project.

### P.2 Authority hierarchy and non-inference rule

1. Code at the pinned rev of `dom-adaptor` (DOM cryptographic authority).
2. Ratifications recorded in section 12 of this document.
3. The body of this document.
4. Earlier documents (v0.1–v0.3, v1.0.1) — history only.

Non-inference rule: no agent or collaborator may infer that a repository,
format, API, contract or test exists without verifying it; mocks and
examples are not promoted to implementation; an [OPEN] item only becomes a
decision through a recorded ratification.

### P.3 Context realignment capsule

Every agent or collaborator must internalize before any work:

1. **[DECIDED]** SINGLE project: consolidates Kaystra, Keystone, GStar,
   Kael/HTLC and the future USPE into a single product.
2. **[DECIDED]** SEPARATE development, independent from the DOM throughout
   the entire cycle. No component alters `dom-protocol`, DOM Wallet,
   `dom-contracts` or consensus.
3. **[DECIDED]** DOM-centric topology: every flow has the form **DOM ↔ X**.
   The DOM is always one of the legs. The product is NOT generic
   interoperability between third parties (e.g. BTC↔ETH without DOM).
4. **[DECIDED]** In the end, the product will be INTEGRATED into the DOM as
   an evolution — **DOM v2**. It is not an L2, rollup or sidechain with a
   custodial bridge.
5. **[DECIDED]** Binding to the DOM during development:

   ```text
   DOM_PROTOCOL_REPOSITORY = https://github.com/sorenplanck/dom-protocol
   DOM_ADAPTOR_REV  = eb6aa1ca59226bc316e3aace5ee0e279e5a154c2
   DOM_ADAPTOR_TREE = 4ca58ffbb194ac7cdf378febf0bc512fc0ecc40a
   Source branch: feat/scriptless-session-authority-entry
   Crate:         crates/dom-adaptor
   ```

   Pin always by `rev`; never by branch or local path.
6. **[DECIDED]** DOM v2 is an evolution ABOVE CONSENSUS (node + services +
   wallet). A component that "requires" a consensus change is defective.
7. **[DECIDED]** Absolute self-custody; no component takes custody of
   seeds, keys, nonce shares or secrets.
8. **[DECIDED]** Anti-power: no admin key, guardian, founder path or
   administrative endpoint — with a grep-gate in CI.
9. **[DECIDED]** DL2P is OUT of the roadmap. CIPHER (VWE) and Kaystra Lend
   are OUT of v1.
10. **[DECIDED]** Mocks and `dom-sim` never satisfy a final gate.

---

## 1. MISSION AND TOPOLOGY

### 1.1 Mission

Build the system that gives the DOM sovereign interoperability with other
chains — swaps, payments and DOM↔X settlement — preserving self-custody,
DOM privacy (on-chain indistinguishability) and absence of trusted third
parties, for final incorporation into the DOM as DOM v2.

### 1.2 Asymmetric topology (DOM hub) — [DECIDED]

```text
        ┌──────────────────────────────────────────────┐
        │                 KAYSTRA CORE                 │
        │   intents · RFQ · solver · settlement engine │
        └──────────┬──────────────────────┬────────────┘
                   │                      │
        ┌──────────▼─────────┐   ┌────────▼───────────────┐
        │   DOM LEG          │   │  COUNTERPARTY LEG       │
        │   (native, fixed)  │   │  (CounterpartyAdapter)  │
        │   dom-adaptor pin  │   ├─ dom-sim (harness)      │
        │   eb6aa1c          │   ├─ EVM (ConditionVM)      │
        └────────────────────┘   ├─ Bitcoin (taproot)      │
                                 └─ HTLC fallback (Kael)   │
```

- The DOM leg is a **native** component of the engine; the neutral trait
  exists only for the counterparty side. Growth in N adapters, not N²
  pairs.
- Design tie-break rule: between a solution that is comfortable for
  public-state chains and one that works on a confidential chain, **the
  second one wins, always**.

### 1.3 Canonical secret flow — [DECIDED]

```text
Setup:    parties fix terms_hash, session_id, roster.
          t is born with whoever will perform the conditioned claim;
          T = t·G is published.
DOM leg:  2-of-2 contract (refund-before-funding when the profile
          requires it).
X leg:    lock conditioned on T (ConditionVM / taproot adaptor / HTLC).
Binding:  one adaptor pre-signature ties the legs together.
Claim:    executing the claim on one leg reveals (or allows extracting) t,
          which unlocks the other leg.
Exit:     claim XOR refund per leg; timelocks guarantee unilateral exit.
```

The binding mathematics (Schnorr form, identical in spirit on the DOM and
in BIP340):

```text
Pre-signature:  R̂ = k·G          (aggregate nonce without the adaptor point)
                e  = H(R̂+T ‖ P ‖ m)   (challenge computed over R = R̂+T)
                ŝ  = k + e·d          ("almost-signature" scalar)
Verification:   ŝ·G == R̂ + e·P
Adaptation:     s  = ŝ + t   →  (R̂+T, s) is a valid Schnorr signature
Extraction:     t  = s − ŝ   (whoever holds the pre-signature and sees s
                              on chain recovers the secret)
```

---

## 2. CRYPTOGRAPHIC FOUNDATIONS

### 2.1 Common base — [DECIDED]

- Curve secp256k1; Schnorr in the DOM format, verified by the DOM's
  **normal, unaltered** verifier.
- Pins immutable without ratification: `grin_secp256k1zkp = "=0.7.15"` and
  the `secp256k1-zkp` pinned by the DOM workspace.
- Hashing, canonical parsing, challenge and arithmetic come from
  `dom-crypto` **through the dom-adaptor**. The project **never**
  reimplements primitives, challenge or verifier — not even for testing
  (I15).
- Fixed-width canonical serialization; rejection of the identity point,
  non-canonical encodings and trailing bytes.

### 2.2 DOM leg — [AUTHORITY: dom-adaptor eb6aa1c]

Everything in this section is API that exists at the pinned rev. The dev
must treat it as a contract: the crate only compiles inside the DOM
workspace, which is why the dependency is via git+rev (§4.3).

**2.2.1 Closed purposes (`messages.rs`):**

```rust
pub enum PurposeV1 {
    Refund       = 0x01,
    ClaimAdaptor = 0x02, // requires adaptor point T
    Funding      = 0x03,
    Sponsor      = 0x04, // codec reserved; execution NOT authorized in Phase 1
}
```

`ClaimAdaptor` without a point, or `Funding`/`Refund` with a point, are
rejected by the crate itself. Do not create new purposes without
ratification + versioning.

**2.2.2 Session and transcript (`session.rs`, `context.rs`):**

```rust
pub struct TrustedChainIdV1([u8; 32]);
pub struct ParticipantIdentityV1 { /* id, role, key */ }
pub struct ParticipantRosterV1(Vec<ParticipantIdentityV1>); // ordered
pub enum   ContractKindV1 { /* closed registry */ }

// session_id is never chosen by the caller:
pub trait SessionIdRegistryV1 { /* durable dedupe */ }
pub fn generate_session_id_v1<R: SessionIdRegistryV1>(...) -> ...;

// canonical template of the DOM transaction + hash:
pub fn canonical_template_v1(tx: &dom_consensus::Transaction)
    -> Result<(Vec<u8>, [u8; 32])>;

// frozen transcript, evolves only via:
pub fn initial_transcript_hash_v1(...) -> ...;
pub fn advance_transcript_hash_v1(...) -> ...;
pub fn session_message_digest_v1(unsigned_message_bytes: &[u8]) -> [u8; 32];
```

`SessionContextV1` binds chain_id, session_id, roster, `ContractKindV1`,
`PurposeV1`, `DirectionV1` (X→DOM / DOM→X), `SigningPhaseV1` and terms,
with exact canonical encoding. Context divergence = fail-closed abort.

**2.2.3 One-shot nonces and Vault (`nonce.rs`, `nonce_vault.rs`):**

- Ratified KDF of two nonces per use; `AuthorizedSecretNoncePairV1` is
  consumed on use (the crate prevents, via `compile_fail`, importing a
  reusable pair or raw derivation).
- `NonceVaultV1` contract (storage-independent — the durable
  implementation belongs to the project, F1 deliverable): reservations
  (`NonceReservation`, `ReservationState`, `RestoreState`), permits
  (`ExposurePermitBindingV1`, `ExposureKindV1`), identity
  (`NonceIdentityV1`), resumption (`ReservationResumeResultV1`),
  **byte-identical resend** via `ResendRequestV1` over
  `SpentArtifactDescriptorV1`, outbound digest via
  `exposure_outbound_digest_v1(kind, bytes)`.
- Restore is delegated reading; abort consumes all live state. Zeroization
  mandatory; no secret in Debug/Display/log/error/dump.

**2.2.4 2-of-2 signing — real signatures:**

```rust
// Rounds: NonceCommitmentV1 → NonceRevealV1 → PartialSignatureV1
pub fn aggregate_public_nonces_v1(nonces: &[PublicKey]) -> Result<PublicKey>;

pub fn aggregate_partial_signatures_v1(
    partials: &[PartialSignatureV1],
    purpose: PurposeV1,
    template_hash: &[u8; 32],
) -> Result<PartialSig>;
// validates: strict Phase 1 purpose, template binding, no duplicates.

pub fn finalize_plain_signature_v1(
    partials: &[PartialSignatureV1],
    purpose: PurposeV1,              // only Funding | Refund
    template_hash: &[u8; 32],
    aggregate_nonce: &PublicKey,
    aggregate_signing_key: &PublicKey,
    chain_id: &[u8; 32],
    kernel_message_digest: &[u8; 32],
) -> Result<SchnorrSignature>;       // 65 bytes; verified by the DOM's
                                     // normal verifier before being
                                     // returned.
```

**2.2.5 Adaptor — the trio that ties the legs together (`adaptor.rs`):**

```rust
pub struct AdaptorSecret(SecretScalar);
impl AdaptorSecret {
    pub fn from_be_bytes(bytes: [u8; 32]) -> Result<Self>;
    pub fn public_point(&self) -> Result<PublicKey>; // T = t·G
}

pub struct AdaptorPreSignatureV1 {
    // canonical 162-byte encoding:
    //   [0..32]    claim_template_hash
    //   [32..65]   adaptor_point T (compressed, 33)
    //   [65..98]   aggregate_nonce_hat R̂ (compressed, 33)
    //   [98..130]  scalar_hat ŝ
    //   [130..162] transcript_hash
}
impl AdaptorPreSignatureV1 {
    pub fn from_bytes_for_session(bytes: &[u8], context: &SessionContextV1)
        -> Result<Self>;

    pub fn verify(
        &self,
        expected_claim_template_hash: &[u8; 32],
        expected_transcript_hash: &[u8; 32],
        signing_key: &PublicKey,
        chain_id: &[u8; 32],
        kernel_message: &[u8],
    ) -> Result<bool>;

    pub fn adapt(       // verify + adapt + re-verify the final signature
        &self,
        secret: &AdaptorSecret,
        /* same bindings as verify */
    ) -> Result<SchnorrSignature>;

    pub fn extract(     // verifies both and extracts validated t
        &self,
        final_signature: &SchnorrSignature,
        /* same bindings as verify */
    ) -> Result<AdaptorSecret>;
}
```

Security remark built into the crate: `adapt` refuses a secret whose
`public_point()` differs from the committed `adaptor_point`; `verify`
refuses divergent template/transcript BEFORE touching the equation. The
engine inherits this fail-closed behavior for free — do not bypass it with
"convenient" wrappers.

**2.2.6 Share PoK (`share_pop.rs`):**

```rust
pub fn prove_share_knowledge_v1(
    statement: &SharePoPStatementV1,   // binds session/participant/role
    signing_share: &SigningShareV1,
) -> Result<ShareProofV1>;             // nonce via OsRng, canonical

pub fn verify_share_knowledge_v1(
    statement: &SharePoPStatementV1,
    proof: &ShareProofV1,
) -> Result<bool>;
```

Every aggregation of public points (nonces, future blinds) requires a
verified PoK from the counterparty before the sum — no exceptions.

**2.2.7 Shared outputs / collaborative Bulletproof — [BLOCKED].**
`BpStatementV1` and `BpRound1ShareV1` exist at the rev; the secrets
(`BpCommonNonceShareV1`, `BpLocalBlindingV1`, `BpRound2ShareV1`) are
sealed until the later DOM phases are authorized. The construction
`C = v·H_DOM + (r_A + r_B)·G` with a proof accepted by the normal verifier
is a deliverable of the DOM-SCRIPTLESS-PHASE2-G2 mission (DOM side). This
project consumes it when G2 closes; until then, DOM leg = real
session/nonce/signature/adaptor crypto over `dom-sim` (§4.5).

**2.2.8 Mandatory conformance — [DECIDED].** The project's CI executes,
against the pin, the crate's own suite: signed fixtures, comparison with
the independent reference set (**311 intermediates**,
`independent_vector_comparison`) and the G1a tests. A single-byte
divergence is a build failure. This is the executable meaning of "base
compatible with the DOM". (CI job in §9.)

### 2.3 EVM leg — [DECIDED as the first real counterparty]

Primary mechanism: a ConditionVM-style condition contract. The central
trick is computing `address(t·G)` on-chain with `ecrecover`, cost ~3k gas:

```text
ecrecover(h, v, r, s) returns address( r⁻¹·(s·R − h·G) ).
With h = 0, R = G  (r = Gx, v = 27 since Gy is even):
    ecrecover(0, 27, Gx, t·Gx mod n)  ==  address(t·G)
```

Skeleton of the hardened v2 **[PROPOSAL — F3 deliverable]**:

```solidity
// SPDX-License-Identifier: TBD (A2)
pragma solidity ^0.8.24;

/// EVM leg of a DOM↔EVM settlement. Lock conditioned on the secret t
/// whose point T was fixed at setup. The claim REVEALS t on-chain — it is
/// the event the DOM leg consumes via AdaptorPreSignatureV1::extract.
contract ConditionLockV2 {
    uint256 internal constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    struct Lock {
        address funder;          // who deposited (refund)
        address beneficiary;     // who performs claim(t)
        address adaptorAddress;  // address(T) — fixed at setup
        uint96  amount;
        uint64  deadline;        // refund block/timestamp
        bytes32 binding;         // keccak256(chain_id_dom, session_id,
                                 //           terms_hash) — domain separation
        bool    settled;
    }
    mapping(bytes32 => Lock) public locks;

    event Claimed(bytes32 indexed lockId, uint256 t); // t revealed
    event Refunded(bytes32 indexed lockId);

    function open(
        bytes32 lockId, address beneficiary, address adaptorAddress,
        uint64 deadline, bytes32 binding
    ) external payable {
        require(locks[lockId].funder == address(0), "exists");
        require(msg.value > 0 && msg.value <= type(uint96).max, "amount");
        require(deadline > block.timestamp, "deadline");
        locks[lockId] = Lock(msg.sender, beneficiary, adaptorAddress,
                             uint96(msg.value), deadline, binding, false);
    }

    function claim(bytes32 lockId, uint256 t) external {
        Lock storage l = locks[lockId];
        require(!l.settled, "settled");
        require(msg.sender == l.beneficiary, "beneficiary");
        require(block.timestamp < l.deadline, "expired");
        require(t != 0 && t < N, "scalar");            // canonical
        address recovered = ecrecover(
            bytes32(0), 27, bytes32(GX), bytes32(mulmod(t, GX, N))
        );
        require(recovered != address(0) &&
                recovered == l.adaptorAddress, "wrong secret");
        l.settled = true;
        emit Claimed(lockId, t);                        // public revelation
        (bool ok, ) = l.beneficiary.call{value: l.amount}("");
        require(ok, "push-pay");                        // reverts on failure
    }

    function refund(bytes32 lockId) external {
        Lock storage l = locks[lockId];
        require(!l.settled, "settled");
        require(block.timestamp >= l.deadline, "not yet");
        l.settled = true;
        emit Refunded(lockId);
        (bool ok, ) = l.funder.call{value: l.amount}("");
        require(ok, "push-pay");
    }
}
```

**v0.2.1 update (D-002):** the reference implementation in the repository
(`contracts/src/ConditionLockV2.sol` from the skeleton) replaces the
reverting push-pay with push plus pull fallback: if the recipient rejects
ETH, the value becomes a credit in `pendingWithdrawals` withdrawable via
`withdraw()`, and settlement — including the emission of `Claimed(t)` —
is never blocked by the payout. The skeleton is the canonical version; the
listing above remains as a didactic explanation of the mechanism.

F3 rules on top of this skeleton: full Foundry suite (valid claim,
invalid/zero/≥n t, claim after deadline, refund before deadline,
reentrancy, duplicate lockId, divergent binding); `binding` MUST include
the DOM leg's `session_id`/`terms_hash`; ERC-20 via a variant with
`safeTransfer`; GStar's ECDSA-adaptor remains experimental and out of v1.
HTLC fallback (Kael `newSwap`/`redeem`/`refund`) only where ConditionLock
does not apply — with the declared cost of equal hashlock linkability.

### 2.4 Bitcoin leg — [DECIDED as the second counterparty]

**BIP340** Schnorr adaptor on taproot key-path (claim indistinguishable
from an ordinary spend); refund via script-path with CSV/CLTV. Mirror of
§1.3:

```rust
// [PROPOSAL — F5 deliverable] pseudocode of the BIP340 bridge
// pre-sign (whoever locks): R̂ = k·G ; e = tagged_hash("BIP0340/challenge",
//     xonly(R̂+T) ‖ xonly(P) ‖ sighash) ; ŝ = k + e·d  (mod n)
// adapt   (whoever knows t): s = ŝ + t  → witness (xonly(R̂+T), s)
// extract (whoever pre-signed, upon seeing the tx in mempool/block): t = s − ŝ
//
// Mandatory F5 cautions:
// - x-only parity: if y(R̂+T) is odd, negate k and t coherently
//   BEFORE ŝ — rule frozen in a test vector, not in a comment;
// - sighash: SIGHASH_DEFAULT over a frozen template (equivalent to the
//   DOM leg's claim_template_hash);
// - refund: tapleaf `<delta> OP_CSV OP_DROP <refund_pk> OP_CHECKSIG`.
```

**[OPEN A8]** The formal challenge-DOM ↔ challenge-BIP340 bridge (distinct
formats, same curve) is an F5 deliverable, with its own vectors, without
touching either of the two authorities. Keystone comes in as verifiable
evidence of BTC events for the USPE and observation (§3.3) — never as a
custodian.

### 2.5 Cross-cutting secret rule — [DECIDED]

- `t` is born with whoever will perform the claim; `T = t·G` published at
  setup; `t` only becomes knowable through a legitimate claim (on-chain
  revelation on X, or `extract` on the DOM).
- No transport, relay, database or log carries `t`, secret nonces, shares
  or seeds; transport carries only opaque authenticated artifacts.
- Nonce reuse across PoK, signing, adaptor and (future) bulletproof is
  forbidden by construction (dom-adaptor domains).

### 2.6 Research track — [OUT OF V1]

CIPHER (verifiable witness encryption, EVM→BTC without contact) remains a
laboratory item; no gate depends on it; no public API exposes it.

---

## 3. INTEGRATION OF EACH PRODUCT

### 3.1 Kaystra → Core (settlement engine) — [DECIDED]
Intents, RFQ, solver selection, state machine (§6), coordination of the
two legs, consumption of verified evidence. The Python `kaystra_watcherd`
becomes a behavioral reference (preflight of irreversible actions, RPC
validation without credentials); the product implementation is Rust.
Solver economics: the F6 half of A5 (selection rule, binding quotes,
exclusive bond reservation) RATIFIED by D-018; exposure-coverage
pricing and bond asset/sizing remain the F4 policy's domain (A5/A6
remainder).

### 3.2 GStar → EVM contracts — [DECIDED]
ConditionVM/Foundry absorbed as the EVM leg (§2.3, ConditionLockV2).
The G/G′/H36–H39 taxonomy goes to `docs/research/`, separated from the
executable interface.

### 3.3 Keystone → Bitcoin evidence and observation — [DECIDED]
The real Keystone (trust-minimized BTC verifier, closed ZK SP1/Groth16)
integrates as a module of verifiable evidence of Bitcoin events,
consumable by the USPE and the engine. **[PROPOSAL]** Transport is its own
"Relay" component (§4.6); Keystone keeps its Bitcoin identity. **[OPEN
A2]** BUSL: relicense or rewrite the part that migrates — resolve in F0,
in writing, together with the partner's IP assignment.

### 3.4 USPE → Economic assurance (from scratch)
Ported from the v1.0.1 Master Document and adapted to the DOM v2
constraint.

> **D-017 (2026-08-10):** the objects sketched below were made concrete by
> `docs/normative/DOM-Interop-F4-Engineering-Specification-v1.0.md`, the
> ratified execution authority for F4. Where this sketch and the
> specification diverge, the specification prevails (it also adopts the
> `CollateralDeadlineExpired` correction the model checker proved
> necessary). This section remains as the design rationale.

**Role [DECIDED]:** the USPE does not create simultaneity between chains;
it transforms a failed obligation into a verifiable economic consequence:
release or retention of a bond, punishment and, when the policy so
determines, compensation.

**Non-negotiable DOM v2 constraint [DECIDED]:** every punishment and
compensation is executable through cryptography and timelocks (bond in a
ConditionLock/2-of-2 whose penalty spend is unlocked by verifiable
evidence or secret extraction) — **never by an operator, arbiter,
committee or admin key**.

**Minimal objects [PROPOSAL]:**

```rust
pub struct AssurancePolicyV1 {
    pub policy_id: PolicyId,
    pub version: u32,
    pub protected_obligations: Vec<ObligationId>,
    pub required_collateral: AssetAmount,
    pub settlement_deadline: Deadline,   // adapter's unit; NEVER silently
    pub claim_deadline: Deadline,        // converted height ↔ clock
    pub compensation_cap: AssetAmount,
    pub evidence_rules: Vec<EvidenceRule>,
    pub terminal_policy: TerminalPolicy,
}

pub struct AssuranceCertificateV1 {
    pub certificate_id: CertificateId,
    pub settlement_id: SettlementId,
    pub terms_hash: Digest32,            // divergent terms invalidate
    pub solver_id: SolverId,
    pub policy_id: PolicyId,
    pub collateral_evidence: EvidenceRef, // no evidence, no issuance
    pub issued_at: LogicalTime,
    pub expires_at: Deadline,
}

/// Abstractions that keep the first implementation from becoming a
/// dependency:
pub trait BondAdapter      { /* lock, release, slash — crypto-only */ }
pub trait EvidenceVerifier { /* raw evidence → VerifiedOutcome */ }
```

**States [PROPOSAL — adapted: EVIDENCE_REVIEW is mechanical evidence
verification by the adapters, not human review; no ACTION_REQUIRED state,
which would imply intervention — timeout resolves via terminal_policy]:**

```rust
pub enum AssuranceState {
    NotRequired,
    BondRequired, BondLocking, Protected,
    ReleasePending, Released,
    ClaimWindow, EvidenceVerification,
    Slashed, Compensated,
    ClaimRejected, // evidence does not satisfy the rules → Released
}
```

**USPE invariants [REQUIREMENT]:** no certificate without verified
evidence of the collateral; a different `terms_hash` invalidates the
certificate; release/slash/compensation depend on policy + evidence (never
on a Relay's statement); one obligation does not generate duplicate
compensations; `SETTLED`, `REFUNDED` and `COMPENSATED` are mutually
exclusive for the same obligation (barring an explicit partial
decomposition policy); the compensated value never exceeds the cap;
deadlines keep the adapter's unit; every decision preserves evidence for
audit. Model checking mandatory in F4: double compensation, simultaneous
release+slash, timeout, late evidence, crash mid-transition.

**[OPEN A6]** Where the bonds live in v1 (EVM first; DOM when the
Scriptless work matures), accepted assets, sizing.

### 3.5 Kael/HTLC → Fallback and EVM library — [DECIDED]
HTLC core + EIP-712 `OrderLib` as fallback and terms library. Experimental
orderbook/coordinator OUT of v1 (the core's RFQ replaces it).

### 3.6 CIPHER → research [OUT OF V1].
### 3.7 Lend v2 and KaystraPay → future consumers [OUT OF V1].
### 3.8 DL2P → [OUT OF SCOPE] entirely.

---

## 4. ARCHITECTURE AND REFERENCE CODE

### 4.1 Components

```text
kaystra-core        engine: intents, terms, state machine, coordination
dom-leg             DOM leg: session, roster, transcript, 2-of-2,
                    verify/adapt/extract (imports the pin)
dom-vault           durable NonceVaultV1: reservations, permits, sealing,
                    recovery, byte-identical resend (imports the pin) [D-005]
counterparty-api    CounterpartyAdapter trait + neutral types
adapters/dom-sim    simulated DOM chain (dev/test; never an F7+ gate)
adapters/evm        ConditionLockV2 + EVM observer
adapters/btc        taproot adaptor + BTC observer (+ Keystone evidence)
adapters/htlc       Kael fallback
uspe                bonds, deadlines, cryptographic compensation
relay               authenticated transport of opaque artifacts (optional)
store               NEUTRAL authoritative local persistence (SQLite/WAL,
                    ADR-A7): journal, idempotency, CAS, cursors, outbox —
                    knows nothing of dom-adaptor, nonces or secrets
```

### 4.2 Workspace and pins — [PROPOSAL for layout; pins DECIDED]

```toml
# Cargo.toml (monorepo root)
[workspace]
members = [
  "crates/kaystra-core", "crates/dom-leg", "crates/counterparty-api",
  "crates/adapters/dom-sim", "crates/adapters/evm", "crates/adapters/btc",
  "crates/uspe", "crates/relay", "crates/store",
]
resolver = "2"

[workspace.dependencies]
# The ONLY door to the DOM. Pin by rev; branch/path/global cargo update FORBIDDEN.
dom-adaptor = { git = "https://github.com/sorenplanck/dom-protocol",
                rev = "eb6aa1ca59226bc316e3aace5ee0e279e5a154c2",
                package = "dom-adaptor" }
thiserror = "1"
zeroize   = { version = "1", features = ["derive"] }
```

Dependency rule (grep-gate in CI, updated by D-005): only `crates/dom-leg`
and `crates/dom-vault` may contain `use dom_adaptor` / `dom-adaptor` in
Cargo.toml. `kaystra-core` and `uspe` import only `dom-leg` and
`counterparty-api`. Recorded erratum: `dom-adaptor` does NOT re-export
`SchnorrSignature`, `PublicKey` or `Transaction`; naming those types
requires `dom-crypto` and `dom-consensus` pinned at the SAME rev — the
three pins are immutable as a set (§9.2).

### 4.3 counterparty-api — neutral trait — [PROPOSAL]

```rust
// crates/counterparty-api/src/lib.rs
use core::future::Future;

pub struct CounterpartyChainId(pub [u8; 32]);
pub struct ChainCursor(pub Vec<u8>);        // opaque, persistable
pub struct AdaptorPointBytes(pub [u8; 33]); // compressed T, from the dom-leg
pub struct RevealedSecretBytes(pub [u8; 32]); // t revealed on-chain (X)

pub struct ChainCapabilities {
    pub supports_condition_lock: bool,   // on-chain revelation of t (EVM)
    pub supports_schnorr_adaptor: bool,  // key-path adaptor (BTC)
    pub supports_hashlock_fallback: bool,
    pub timelock_domain: TimelockDomain, // BlockHeight | Timestamp
    pub finality: FinalityPolicy,        // [OPEN A4] per chain
}

pub enum ObservedEvent {
    LockOpened   { lock_id: [u8; 32], height: u64 },
    LockClaimed  { lock_id: [u8; 32], revealed: RevealedSecretBytes,
                   height: u64 },
    LockRefunded { lock_id: [u8; 32], height: u64 },
    Reorged      { from_height: u64 }, // invalidates observations ≥ height (I11)
}

pub enum AdapterError {
    UnsupportedCapability, InvalidState, PreconditionUnsatisfied,
    EvidenceInvalid, ReorgDetected, StaleCursor, VersionMismatch,
    AdapterUnavailable, NonCanonicalRetransmission,
}

/// Asynchronous by decision (remote RPCs); trait with native async methods
/// (Rust ≥1.75) — dyn-compat via adapter enum or wrapper, decide in F0.
pub trait CounterpartyAdapter: Send + Sync {
    fn chain_id(&self) -> CounterpartyChainId;
    fn capabilities(&self) -> ChainCapabilities;

    /// Prepares the lock conditioned on T. Returns an opaque artifact
    /// ready for authorization/broadcast by the local agent (no custody
    /// here).
    fn prepare_lock(&self, terms: &NeutralTerms, t: &AdaptorPointBytes)
        -> impl Future<Output = Result<OpaqueArtifact, AdapterError>> + Send;

    /// Observation via persistable cursor; reorg is an event, not a panic.
    fn observe(&self, cursor: &ChainCursor, max: usize)
        -> impl Future<Output = Result<(Vec<ObservedEvent>, ChainCursor),
                                       AdapterError>> + Send;

    /// Raw chain evidence → neutral verified result (I9).
    fn verify_evidence(&self, evidence: &[u8])
        -> impl Future<Output = Result<VerifiedOutcome, AdapterError>> + Send;
}
```

Interface rules: idempotency; explicit versioning; chain/profile binding;
size limits before allocating; stable errors; persistable cursor; unknown
capability = fail closed (I10).

### 4.4 dom-leg — canonical use of the dom-adaptor — [PROPOSAL over AUTHORITY]

DOM→X claim flow as seen from the engine (real crate names):

```rust
// crates/dom-leg/src/claim_flow.rs — illustrative skeleton
use dom_adaptor::{
    AdaptorPreSignatureV1, AdaptorSecret, PurposeV1,
    aggregate_public_nonces_v1, finalize_plain_signature_v1,
};

pub struct DomLegSession { /* SessionContextV1 + vault handle + template */ }

impl DomLegSession {
    /// Counterparty revealed t in the EVM claim (ObservedEvent::LockClaimed)
    /// OR we saw the final signature on the DOM and extracted t:
    pub fn extract_secret(
        &self,
        pre: &AdaptorPreSignatureV1,
        final_sig: &dom_crypto::SchnorrSignature,
    ) -> Result<AdaptorSecret, LegError> {
        pre.extract(
            final_sig,
            &self.claim_template_hash,
            &self.transcript_hash,
            &self.aggregate_signing_key,
            &self.chain_id,
            &self.kernel_message,
        ).map_err(Into::into)
    }

    /// We know t (having come from the claim on the other leg) and
    /// finalize the DOM claim signature:
    pub fn adapt_claim(
        &self,
        pre: &AdaptorPreSignatureV1,
        t: &AdaptorSecret,
    ) -> Result<dom_crypto::SchnorrSignature, LegError> {
        pre.adapt(t, &self.claim_template_hash, &self.transcript_hash,
                  &self.aggregate_signing_key, &self.chain_id,
                  &self.kernel_message).map_err(Into::into)
    }
}
```

Prohibitions in dom-leg: no wrapper that accepts a template/transcript
"from outside" without revalidating against the session; no path that
finalizes `ClaimAdaptor` via `finalize_plain_signature_v1` (the crate
already rejects it — do not "fix" that); no storage of `AdaptorSecret`
outside the flow (I1).

### 4.5 dom-sim — simulated DOM chain — [DECIDED on paper; API PROPOSAL]

```rust
pub trait SimChain {
    fn height(&self) -> u64;
    fn advance(&mut self, blocks: u64);
    fn submit(&mut self, artifact: OpaqueArtifact) -> SubmitResult;
    fn confirmations(&self, id: &[u8; 32]) -> Option<u64>;
    fn inject_reorg(&mut self, depth: u64);       // I11 testable
    fn scan(&self, cursor: &ChainCursor) -> (Vec<ObservedEvent>, ChainCursor);
}
```

Mandatory statement in every report: *dom-sim is not the DOM; it confers
no network compatibility; the swap for the real node happens in F7 under
the eligibility gate.* The cryptography on top of it is always the real
one (dom-adaptor).

### 4.6 Relay — transport — [PROPOSAL, ported from v1.0.1 §9.3–9.5]

```rust
pub struct RelayEnvelopeV1 {
    pub protocol_version: u16,
    pub service: ServiceKind,
    pub message_kind: u16,
    pub settlement_id: SettlementId,
    pub message_id: MessageId,
    pub sender_id: ParticipantId,
    pub recipient_id: ParticipantId,
    pub sequence: u64,
    pub previous_digest: Digest32,
    pub payload_codec: CodecId,
    pub payload_hash: Digest32,
    pub payload: BoundedBytes,   // opaque; the Relay NEVER decodes
    pub authentication: AuthTag, // DECIDED by D-018: BIP340 over the
                                 // domain-separated digest of the full
                                 // canonical unsigned envelope (F6 spec §5)
}
```

Delivery semantics [REQUIREMENT]: at-least-once at the transport;
exactly-once at the effects layer through idempotency keyed by
`(settlement_id, sender_id, message_id | sequence)`. Same id + same
bytes ⇒ same ACK; same id + different bytes ⇒ equivocation, fail closed.
Resend uses the persisted bytes of the envelope — it never recomputes
signature, nonce or payload (mirrors the dom-adaptor's `ResendRequestV1`).

Unavailability [REQUIREMENT, tested in F6]: the session continues over
another transport; final artifacts exist locally; alternative observers
reconcile the chain; claim/refund/compensation do not depend on the
Relay's database; upon returning, the Relay reconciles via digests and
idempotency keys without repeating effects.

### 4.7 store — persistence — [DECIDED; A7 resolved: SQLite/WAL, ADR-A7]

Authoritative local session; append-only journal of decisions; idempotency
keys; per-chain cursors; monotonic revision/CAS; durable outbox;
post-crash resumption; reconciliation with the chains; durable
implementation of the `NonceVaultV1` contract (fail-closed when
witness/rollback is incomplete — the crate's own rule).

---

## 5. NORMATIVE INVARIANTS

```text
I1  Self-custody: no component stores a seed, private key, share or t.
I2  Anti-power: no admin key, guardian, founder path, administrative
    endpoint, global pause or unilateral upgrade. Grep-gate in CI.
I3  Above consensus: no change to DOM consensus, wire, genesis, mempool
    or encoding; dom-protocol/dom-contracts/DOM Wallet untouched.
I4  Claim and refund are mutually exclusive outcomes per leg.
I5  Refund-before-funding where the profile requires it: no funding
    before the refund is finalized, validated and persisted.
I6  One-shot nonces; separate domains; zeroization; no secret in
    Debug/Display/log/error/dump/telemetry.
I7  Byte-identical retransmission; the same idempotency key never
    produces semantically different artifacts.
I8  DOM indistinguishability preserved: no collaboration marker in
    anything that goes to the DOM chain.
I9  Chain evidence is only interpreted by that chain's adapter.
I10 Unknown capability or divergent version: fail closed.
I11 A reorg invalidates decisions derived from the affected observation
    until revalidation; a single terminal economic effect per settlement.
I12 USPE: no double compensation; release and slash mutually exclusive;
    purely cryptographic execution.
I13 Mock/dom-sim never satisfies a final gate; F7+ requires the real DOM.
I14 Production path: no unwrap/expect on untrusted input, no panic as
    classification, no unsafe outside a minimal FFI wrapper, no float
    for value, no serde as cryptographic wire, no ignored trailing
    bytes, allocation only after validating the cap.
I15 No reimplementation of any DOM primitive, challenge or verifier.
```

---

## 6. SETTLEMENT STATE MACHINE

**[PROPOSAL]** Pure, table-driven transition function, without effects —
the effects live in the engine, which consumes the result:

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettlementState {
    Preparing, ReadyToFund, Confirming, Settling, Settled, Refunded,
}

pub enum SettlementEvent {
    RefundArmed,            // pre-signed refund finalized+persisted (I5)
    FundingObserved { height: u64 },
    FundingConfirmed,
    SecretRevealed(RevealedSecretBytes),
    ClaimConfirmed,
    TimelockExpired,
    RefundConfirmed,
    ReorgInvalidated { from_height: u64 },
}

pub enum TransitionError { IllegalEvent, TerminalState }

pub fn transition(s: SettlementState, e: &SettlementEvent)
    -> Result<SettlementState, TransitionError>
{
    use SettlementState::*; use SettlementEvent::*;
    Ok(match (s, e) {
        (Preparing,   RefundArmed)            => ReadyToFund,
        (ReadyToFund, FundingObserved { .. }) => Confirming,
        (Confirming,  FundingConfirmed)       => Settling,
        (Settling,    SecretRevealed(_))      => Settling, // awaits claim
        (Settling,    ClaimConfirmed)         => Settled,
        (Confirming | Settling, TimelockExpired) => s,     // arms refund
        (Confirming | Settling, RefundConfirmed) => Refunded,
        // Reorg is NOT terminal: it rolls back the observation, not the money (I11)
        (Confirming,  ReorgInvalidated { .. }) => ReadyToFund,
        (Settling,    ReorgInvalidated { .. }) => Confirming,
        (Settled | Refunded, _) => return Err(TransitionError::TerminalState),
        _ => return Err(TransitionError::IllegalEvent),
    })
}
```

**v0.2.1 update (D-003, D-004):** the reference implementation in the
repository (`crates/kaystra-core/src/state.rs`) evolves this listing:
(a) a `SettlementContext` with `last_observed_height` as the reorg
idempotency key (at-least-once redelivery of the same event is harmless);
(b) a new `FundingAbsent` event (`Confirming → ReadyToFund`) for early
re-arming when post-reorg revalidation concludes the funding is gone;
(c) `FundingObserved` re-observation accepted in `Confirming` (height
refresh, idempotent); (d) decision recorded in code: `RefundConfirmed`
is accepted without a prior `TimelockExpired` because the timelock is the
CHAIN's authority — the machine records the observed reality. The
skeleton is the canonical version; the listing above remains as a
didactic explanation.

F2 obligations on top of this skeleton: complete table (entry, permitted
operations, emitted events, persisted data, post-crash, reorg effect,
economic terminal) per state; property tests that `Settled` and
`Refunded` are simultaneously unreachable; crash injected at EVERY
transition with resumption via the journal.

---

## 7. PHASES AND GATES

No phase starts without the previous gate PASS or a ratified written
waiver. Each phase lists the "first code" so the dev does not start on
the wrong side.

### F0 — Foundation (no protocol code)
Deliverables: repository and workspace (§4.2); CI with fmt/clippy/test +
dom-adaptor conformance (§9) + grep-gates for I2/I6/I14/§4.2; written
license agreement and IP assignment; Keystone BUSL decision (A2); name
(A1); dyn-compat decision for the async trait (§4.3).
Gate G-F0: `VECTORS_GREEN + IP_SIGNED + LICENSES_DECIDED`.

### F1 — DOM leg (real crypto over dom-sim)
First code: durable implementation of the `NonceVaultV1` contract in the
`store`, then `DomLegSession`.
Deliverables: session/roster/transcript; durable vault; 2-of-2 rounds for
the three purposes; `verify/adapt/extract`; `dom-sim` (§4.5) with
injectable reorg.
Gate G-F1: abstract funding→claim and funding→refund with real
cryptography; correct extraction of `t`; "unilateral spend"
cryptographically impossible (the test reaches the pin's real verifier,
not a mock); crash/restore/byte-identical resend; vector conformance
maintained.

### F2 — Kaystra core
First code: `transition()` (§6) + complete table + property tests; then
canonical terms and `terms_hash` (ratify A3 here).
Gate G-F2: E2E against dom-sim with fault injection (crash at every
transition, duplication, reorder, reorg, late evidence).

### F3 — EVM leg (first real counterparty)
First code: `ConditionLockV2` (§2.3) + adversarial Foundry suite.
Deliverables: EVM adapter (`observe` via events + cursors; finality A4).
Gate G-F3: first real DOM(dom-sim)↔EVM E2E on testnet, BOTH directions,
with `t` extracted from a real on-chain `Claimed` and refund via a real
deadline; report with tx hashes.
State (operator, 2026-08-11, D-025): **G-F3 = PASS; F3 = COMPLETED.**
Adjudicated on the public Ethereum Sepolia execution of 2026-08-11
(chain id 11155111), executed code `7b6d4b0`, evidence HEAD `9afaea8`.
Closure report: `docs/reports/F3-CLOSURE.md`; execution evidence:
`docs/reports/F3-SEPOLIA-E2E.md` and `artifacts/sepolia/`.

### F4 — Minimal USPE
Execution specification:
`docs/normative/DOM-Interop-F4-Engineering-Specification-v1.0.md`
(adopted by D-017; it makes the §3.4 objects concrete and adopts the
model-checked `CollateralDeadlineExpired` correction as normative).
First code: `AssuranceState` + invariants as property tests + model
checking (§3.4) — EXECUTED (crates/uspe + crates/f4-model,
docs/reports/F4-STEP1-MODEL-CHECKER.md); `BondAdapter` over the
ConditionLock.
Gate G-F4: `NO_DOUBLE_COMPENSATION + NO_RELEASE_AND_SLASH + TIMEOUT_SAFE`
demonstrated; compensation executed on testnet without any privileged
action. Exact criterion: F4 specification §12.
State (operator, 2026-08-11, D-026): **G-F4 = PASS; F4 = COMPLETED.**
The run D-024 required in order to bind the gate to the current head
was executed and passed: workflow run 31521948686 (job 93880878036) at
`main@593364b9d11cdb0843c5d732a9446a105d451860`, tree
`aa2153821272910cabf7553b99328a370ae79920`, Ethereum Sepolia
(chain id 11155111), verdict `G-F4 SEPOLIA SLASH PASS`, terminal
`Compensated`, `privilegedActions = 0`. Closure report:
`docs/reports/F4-CLOSURE.md`. The earlier evidence of run 31431363791
(HEAD 9c04d36) remains on the record as history, per D-024.
**NEXT REQUIRED GATE = G-F5.**

### F5 — Bitcoin leg
Execution specification: `docs/normative/DOM-Interop-Annex-M-v3.2-Bitcoin-Leg.md`
(adopted by D-012). First code (Annex M M.17): pinned MuSig2/adaptor
backend, then canonical types, then the C1a official BIP327 vectors —
x-only parity vectors frozen BEFORE any signing flow.
Gate G-F5 (Annex M M.15.2): DOM(dom-sim)↔BTC E2E on regtest and signet,
both directions; real CSV refund; C1a/C1b/C2/C3/C4 green; Keystone
evidence consumed by the USPE. Ratifying the annex does NOT pass the
gate; started in parallel with F3/F4 per the §7 parallelism note.

### F6 — RFQ, solver and Relay
Deliverables: RFQ/quotes/selection (A5); Relay (§4.6).
Gate G-F6: complete settlement with a solver; total loss of the Relay and
its database does not prevent local claim or refund;
ACK/dedup/byte-identical retransmission approved.
State (operator, 2026-08-10): steps 1-9 COMPLETE, executor-side
COMPLETE, evidence package ACCEPTED, evidence criteria SATISFIED —
G-F6 = EVIDENCE COMPLETE, FORMAL ADJUDICATION DEFERRED until G-F3 and
G-F4 are adjudicated and G-F5's public-signet leg lands (§8 ordering;
no prior written waiver exists). Adjudication then requires no test
re-run provided the evidence commits stay identifiable, the relevant
code is unchanged, the pins and interfaces F6 consumes are unchanged,
and any later change has its full regression green.

### F7 — Real DOM — [BLOCKED by external dependency]
Precondition (DOM side, outside this project): Scriptless Phases 2–6 (G2
shared output + collaborative BP; session/transport; funding with
pre-signed refund; claim via adaptor; E2E).
Deliverables: replace dom-sim with the real DOM node (regtest → test
network), using the real builder, RPC, mempool, verifier and scanner.
Gate G-F7 (DOM eligibility gate): canonical formats frozen;
session/transaction identifiers; timelock/confirmation/reorg policy; E2E
vectors published; DOM version frozen and pinned; conformance green
against the real DOM; dom-sim × real DOM comparison documented.

### F8 — Audit and DOM v2 Merge
Deliverables: external composition audit; packaging as the DOM v2
distribution (node + services + wallet); repository migration plan.
Gate G-F8: audit with no pending findings; I1–I15 verified in the
package; explicit operator ratification. Only then does "DOM v2" exist.

Parallelism: F1→F2 serial; F3 starts with partial G-F2 (stable machine);
F4 parallel to F3/F5; the DOM side (Scriptless P2–P6) runs in parallel
and only couples at F7.

---

## 8. CROSS-CUTTING ADVERSARIAL TESTS

Beyond the per-phase gates, the permanent suite covers, in every flow:

crash at every transition; lost ACK; duplication; replay; equivocation
(same id, different bytes); reorder; reorg on each leg; loss of the
Relay; loss of the Relay's database; unavailable adapter; invalid
evidence; late evidence; timeout at every deadline; resumption after
restart at every signing phase; byte-identical resend after restart;
invalid `t` (zero, ≥n, non-canonical); identity point; invalid PoK;
duplicated/omitted/reordered participant; divergent template or
transcript; secret scan of every artifact and log.

Tools: property tests (proptest), fuzz targets on the
envelope/artifact/evidence parsers, differential tests against the pin's
vectors, model checking of the USPE and the state machine.

---

## 9. CONFORMANCE AND CI

### 9.1 DOM conformance job — [DECIDED]

```yaml
# .github/workflows/ci.yml (excerpt)
jobs:
  dom-conformance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Clone DOM at the pinned rev
        run: |
          git clone https://github.com/sorenplanck/dom-protocol dom
          git -C dom checkout eb6aa1ca59226bc316e3aace5ee0e279e5a154c2
      - name: dom-adaptor vectors (311 intermediates + G1a + fixtures)
        run: cargo test -p dom-adaptor --locked --manifest-path dom/Cargo.toml
      - name: dom-leg tests against the pin
        run: cargo test -p dom-leg --locked
  guards:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: dom-adaptor boundary (only dom-leg imports)
        run: |
          ! grep -rn "dom_adaptor\|dom-adaptor" crates \
              --include="*.rs" --include="*.toml" \
              | grep -v "^crates/dom-leg/"
      - name: Anti-power (I2)
        run: |
          ! grep -rniE "admin_key|onlyOwner|guardian|pause_all|upgradeTo" \
              crates contracts/src
      - name: I14 (sample)
        run: |
          ! grep -rn "\.unwrap()\|\.expect(" crates --include="*.rs" \
              | grep -v "/tests/\|/fuzz/\|#\[cfg(test)\]"
```

(The grep-gates are the minimal version; F0 converts them into
lints/xtask with an explicit, per-line-justified allowlist.)

### 9.2 Pin update rule

Updating `DOM_ADAPTOR_REV` is a ratification event (section 12): it
requires a changelog of the delta, full re-execution of conformance and a
new version of this document. Global `cargo update` is forbidden;
lockfile committed.

### 9.2.1 Conformance evidence for the current pin

Executed on 2026-08-10 at `eb6aa1ca59226bc316e3aace5ee0e279e5a154c2`, as
the evidence on which D-016 was ratified. Every figure below is a measured
run, not a projection.

| suite | command | result |
|---|---|---|
| DOM authority (at the pin) | `cargo test -p dom-adaptor` in the `dom-protocol` checkout | **65 passed, 0 failed** + **19 doctests** (all `compile_fail` seals) |
| — independent vectors | `frozen_independent_outputs_match_all_311_intermediates` | **PASS** (311 intermediates) |
| — G1a SCAD0 corpus | `all_eight_scad0_vectors_verify_adapt_extract_and_pass_consensus` | **PASS** (8 vectors; revealed bytes byte-equal to the corpus `t`) |
| Interop workspace | `cargo test --workspace --locked` | **153 passed, 0 failed** |
| Real backend — DOM leg | `cargo test -p dom-leg --features real-dom-adaptor --locked` | **25 passed, 0 failed** |
| Real backend — DOM vault | `cargo test -p dom-vault --features real-dom-adaptor --locked` | **42 passed, 0 failed** |
| Crash injection | `cargo test -p store --features failpoints --locked` | **9 passed, 0 failed** |
| Doctests | `cargo test --doc --workspace --locked` | **3 passed, 0 failed** |
| F2 model checker | `cargo run -p f2-model --release --locked` | **PASS** (all five AG properties hold) |
| F2 property suite | `PROPTEST_CASES=2000 … state_properties` | **8 passed, 0 failed** |
| Independent terms verifier | `python3 scripts/verify_terms_vectors.py` | **PASS** (no `kaystra-core` import) |
| Executable guards | `./scripts/guards.sh` | **9/9 PASS** |
| Lints | `cargo clippy --workspace --all-targets --locked -- -D warnings` | clean |
| Formatting | `cargo fmt --all -- --check` | clean |

The frozen SCAD0 fixture copy held by `dom-leg` was re-checked against the
new revision by `fixture_copy_is_byte_identical_to_the_pin` — **PASS**, so
the corpus itself did not move.

Lockfile discipline: the pin change altered **7 lines** of `Cargo.lock` —
the `source` field of the seven `dom-*` packages and nothing else. No
other dependency was resolved, added or bumped, as §9.2 requires.

---

## 10. DOM v2 INTEGRATION GATE (consolidated checklist)

Cumulatively: G-F0…G-F8 PASS; no NOT_CONFIRMED converted to PASS by
documentary inference; no pending or proposed consensus change; external
audit delivered; licenses compatible with the DOM distribution; signed
declaration that dom-protocol, dom-contracts and DOM Wallet remained
untouched throughout the entire development.

---

## 11. OPEN QUESTIONS

```text
A1  Product name — DECIDED (D-009, 2026-08-10): no standalone name;
    DOM ecosystem component, integrated into the DOM v2 at F8.
A2  Product license — DECIDED (D-010, 2026-08-10): proprietary and
    privately hosted until the F8 integration into the DOM v2; adopts
    the DOM protocol's MIT license upon that merge (same copyright
    holder). Keystone BUSL relicensing/rewrite is deferred to F5 as a
    dependency of that phase, not of G-F0.
A3  Canonical terms format and terms_hash (ratify in F2).
A4  Finality/confirmation policy per counterparty chain (F3/F5).
A5  PARTIALLY RESOLVED — the F6 selection/binding rule RATIFIED
    2026-08-10 (D-018); exposure-coverage pricing internals and bond
    asset/sizing remain open in the F4 policy domain (with A6).
A6  Where the v1 bonds live (EVM) and future migration to the DOM.
A7  RESOLVED — SQLite/WAL (docs/adr/ADR-A7-SQLite-WAL.md, ratified
    2026-08-06); adapter allocation adjusted by D-005.
A8  RESOLVED — formal DOM-Schnorr ↔ BIP340 bridge, incl. x-only
    parity: D-013 RATIFIED 2026-08-10 (C1a/C1b/C2/C3/C4 green in CI;
    Annex M v3.2 adopted).
A9  RESOLVED — testnets: EVM = Sepolia (F3); BTC networks = D-014
    RATIFIED 2026-08-10 (regtest + custom signet + public signet,
    mainnet excluded).
A10 RESOLVED — Relay envelope authentication RATIFIED 2026-08-10
    (D-018): BIP340 over the roster key and the domain-separated
    digest of the complete canonical unsigned envelope.
A11 Fate of Kael's experimental orderbook (post-v1).
A12 RESOLVED — native async fn + static dispatch; closed enum wrapper
    if F3/F5 ever need uniform adapter handling; #[async_trait]
    rejected (D-011; docs/adr/ADR-A12-async-trait-dispatch.md).
```

---

## 12. DECISION REGISTRY AND UPDATE PROTOCOL

### 12.1 Registry

Each ratification records: ID, date, problem, decision, rejected
alternatives, impact, affected components, superseded decision, status.

```text
D-000  2026-08-05  RATIFIED (operator /goat order, 2026-08-09)
  Problem:       absence of a single authority for context and scope.
  Decision:      ratify capsule P.3, items 1–10 (single project;
                 development separate from the DOM; DOM-centric DOM↔X
                 topology; DOM v2 destination above consensus; pin
                 180b731; self-custody; anti-power; DL2P/CIPHER/Lend
                 out; mocks never satisfy a gate).
  Rejected alternatives: three independent multichain systems with the
                 DOM as an optional profile (the v1.0.1 framing).
  Impact:        the entire document and the entire repository.
  Supersedes:    —
  Components:    all.

D-001  2026-08-05  RATIFIED (operator /goat order, 2026-08-09)
  Problem:       two competing master documents restore contradictory
                 contexts in conversations with agents.
  Decision:      "KAYSTRA-USPE-KEYSTONE-DOCUMENTO-MESTRE v1.0.1"
                 receives the SUPERSEDED mark on its first page and
                 leaves agent circulation; useful blocks already ported
                 here (§P.2, §3.4, §4.6, §12.2).
  Rejected alternatives: keeping both in parallel.
  Impact:        documentary governance.
  Supersedes:    v1.0.1 as context authority.
  Components:    docs/normative.

D-002  2026-08-05  RATIFICATION PENDING
  Problem:       a reverting push-pay traps funds at refund when the
                 funder is a contract that rejects ETH (claim already
                 expired => permanent lock-up); finding from the hostile
                 audit of the skeleton.
  Decision:      payout with pull fallback in claim and refund
                 (pendingWithdrawals + withdraw()); settlement and the
                 emission of Claimed(t) never depend on the payout.
  Rejected alternatives: pure push (original, inherited from the
                 ConditionVM); pure pull (worse UX on the happy path).
  Impact:        EVM leg contract; the F3 Foundry suite must cover a
                 reverting recipient, PayoutDeferred and withdraw.
  Supersedes:    original §2.3 listing (v0.2).
  Components:    contracts/src/ConditionLockV2.sol.

D-003  2026-08-05  RATIFICATION PENDING
  Problem:       (a) at-least-once redelivery of ReorgInvalidated
                 regressed the settlement twice (real bug caught by a
                 crash test); (b) after a regression with vanished
                 funding, the settlement sat idle until the timelock,
                 with no re-arming.
  Decision:      SettlementContext.last_observed_height as the reorg
                 idempotency key; new FundingAbsent event
                 (Confirming → ReadyToFund, illegal in all other
                 states); FundingObserved accepted in Confirming as an
                 idempotent re-observation with height refresh.
  Rejected alternatives: loosening the redelivery test; iterative
                 multi-step regression (deferred to the full F2 table).
  Impact:        state machine §6; F2 engine.
  Supersedes:    original §6 listing (v0.2).
  Components:    crates/kaystra-core/src/state.rs.

D-004  2026-08-05  RATIFICATION PENDING
  Problem:       RefundConfirmed accepted without a prior
                 TimelockExpired looks like a bug and invites the wrong
                 "fix".
  Decision:      it is design: the timelock is the CHAIN's authority
                 (deadline in the EVM contract, CSV on BTC, pre-signed
                 refund on the DOM); the machine records the observed
                 reality. A duplicated check in the machine would create
                 a second authority over the timelock and a divergence
                 risk. Documented in a code comment.
  Rejected alternatives: requiring TimelockExpired before accepting
                 RefundConfirmed.
  Impact:        §6 semantics; future revisions.
  Supersedes:    —
  Components:    crates/kaystra-core/src/state.rs.

D-005  2026-08-09  RATIFIED (operator /goat order)
  Problem:       the NonceVaultV1 contract is a dom-adaptor trait, but
                 the original §4.2 boundary only allowed dom-leg to
                 import the pin — and the store must remain neutral
                 (§4.7).
  Decision:      dedicated crate `dom-vault` for the durable
                 NonceVaultV1 implementation; the boundary guard now
                 allows dom-leg AND dom-vault; the store remains free of
                 DOM types.
  Rejected alternatives: vault inside dom-leg (the ADR-A7 allocation,
                 predating the order); the store importing the pin.
  Impact:        §4.1, §4.2, CI guards.
  Supersedes:    the single-crate rule of §4.2 (v0.2/v0.2.1).
  Components:    crates/dom-vault, scripts/guards.sh.

D-006  2026-08-09  SATISFIED BY THE PIN (verification recorded)
  Problem:       requirement that PreparedExposureV1 not be forgeable
                 from raw bytes.
  Decision:      verified that pin 180b731 already satisfies it:
                 pub(crate) constructors, private fields, internal
                 permit verification ("Constructors are crate-private
                 and no raw-byte constructor exists"). No pin change.
  Components:    none (evidence in docs/reports/F1-CLOSURE.md §1).

D-007  2026-08-09  RATIFIED (operator decision, recorded in chat)
  Problem:       workspace and contracts with a "TBD-A2" license —
                 legally undefined state.
  Decision:      PROVISIONAL measure: proprietary ("all rights
                 reserved", LICENSE file; SPDX UNLICENSED in the
                 contracts; license-file in the workspace;
                 publish = false). A2 remains OPEN for the definitive
                 license and Keystone/BUSL.
  Rejected alternatives: MIT OR Apache-2.0; Apache-2.0; GPL-3.0
                 (deferred, not discarded).
  Impact:        LICENSE, Cargo.toml (workspace + crates), contracts/src.
  Supersedes:    —
  Components:    repository root.

R-001  2026-08-09  RECORD (not a new decision)
  G-F0 = WAIVER FOR F1 (/goat order): A1, A2 and A12 remain open; the
  waiver allows F1 to be closed technically and does NOT authorize F3.
  F1 P0 BLOCKER: the NonceVaultV1 contract is not drivable from outside
  the pin (every input type has a pub(crate) constructor); minimal
  external action: a public dom-adaptor commit exposing a production
  entry point for the session authority. Evidence and method-by-method
  table in docs/reports/F1-CLOSURE.md §1.2–1.3.

D-008  2026-08-10  RATIFIED (operator order, recorded in chat)
  Problem:       F1 blocker P0 — every NonceVaultV1 method input was
                 only constructible crate-internally at pin 180b731
                 (F1-CLOSURE §1.3).
  Decision:      pin updated to
                 a1825639154dcc9d89be098079112e9cb975940e (single
                 upstream commit: production entry
                 ValidatedSigningRoundStateV1::from_session_authority
                 bound to a statically selected
                 SigningSessionAuthorityV1; support chain ungated but
                 kept pub(crate); all compile_fail seals hold; no
                 cryptographic change). Conformance re-executed in full
                 at the new rev (84 tests + doctests, incl. the
                 311-intermediate comparison); interop suites green
                 (workspace 97, real backend 61, guards 6/6). Audit
                 record: docs/patches/dom-protocol/.
  Components:    workspace pins, CI, dom-leg AUTHORITY markers.

D-009  2026-08-10  RATIFIED (operator order, recorded in chat)
  Question:      A1 — product name.
  Decision:      the interoperability layer has NO standalone product
                 name or brand. It is a component of the DOM ecosystem
                 and is destined for integration into the DOM v2 at
                 phase F8; "DOM Interop" remains only as the
                 descriptive repository/component name.
  Rejected:      adopting "DOM Interop" or "Kaystra" as a product brand.
  Components:    Foundation Document header, README.

D-010  2026-08-10  RATIFIED (operator order, recorded in chat)
  Question:      A2 — definitive product license (supersedes the
                 provisional part of D-007; keeps its mechanics).
  Decision:      proprietary and privately hosted (GitHub private)
                 until the F8 integration into the DOM v2; upon that
                 merge the code adopts the DOM protocol's MIT license
                 (copyright Soren Planck, identical holder). Until F8:
                 LICENSE "all rights reserved", SPDX UNLICENSED,
                 publish = false remain in force.
  Deferred:      Keystone BUSL relicensing/rewrite — an F5 dependency,
                 recorded there, not a G-F0 blocker.
  Components:    LICENSE, Cargo.toml (workspace + crates), README.

D-011  2026-08-10  RATIFIED (operator order, recorded in chat)
  Question:      A12 — dyn-compat of the async CounterpartyAdapter.
  Decision:      not required and not promised: native async fn in
                 trait + static dispatch (the F1/F2 evidence shows one
                 settlement binds its adapters at construction). If
                 F3/F5 need uniform handling of several adapters, the
                 designated mechanism is a CLOSED enum wrapper;
                 #[async_trait] (boxed futures) is rejected.
  Evidence:      docs/adr/ADR-A12-async-trait-dispatch.md.
  Components:    counterparty-api (documentation only; no code change).

R-002  2026-08-10  RECORD (gate adjudication)
  G-F0 = PASS. The R-001 waiver is lifted: VECTORS_GREEN (dom-adaptor
  conformance at pin a182563 in CI, 7/7 guards), IP_SIGNED
  (docs/legal/IP-DECLARATION.md — sole author Soren Planck, both
  repositories) and LICENSES_DECIDED (D-010) are all satisfied, and
  A1/A2/A12 are closed by D-009/D-010/D-011. Evidence:
  docs/reports/F0-CLOSURE.md. F0 no longer blocks F3; starting F3
  remains a separate operator decision.

D-012  2026-08-10  RATIFIED (operator order, recorded in chat)
  Question:      may F5 (Bitcoin leg) start in parallel, before G-F3 and
                 G-F4 close, and under which specification.
  Decision:      yes. The §7 parallelism note already places F4 parallel
                 to F3/F5; F1→F2 (the only serial dependency) are PASS,
                 and F5 depends on neither the EVM contract (F3) nor the
                 bonds (F4). Annex M v3.2
                 (docs/normative/DOM-Interop-Annex-M-v3.2-Bitcoin-Leg.md)
                 is adopted as the F5 EXECUTION SPECIFICATION and its
                 M.17 build order is authorized. This decision does NOT
                 ratify D-013/D-014, execute any conformance layer, or
                 move G-F5 (Annex M M.0.3).
  Coordination:  F3 (operator) owns contracts/ and adapters/evm; F5
                 owns adapters/btc(+secp-sys); neither changes
                 counterparty-api, kaystra-core or store without
                 coordination (shared frozen surfaces).
  Components:    crates/adapters/btc, crates/adapters/btc-secp-sys, docs.

D-013  2026-08-10  RATIFIED (operator order, recorded in chat)
  Problem:       formal bridge between the DOM Schnorr session and the
                 Bitcoin BIP340/MuSig2 claim — x-only parity, TapTweak,
                 adaptor, witness and canonical extraction (Annex M,
                 renumbered from the annex's internal "D-008").
  Decision:      adopt Annex M v3.2; pin secp256k1-zkp at the recorded
                 revision; key-path SIGHASH_DEFAULT and a single-leaf
                 CSV refund. Backend pinned in
                 crates/adapters/btc-secp-sys (upstream rev
                 6152622613fdf1c5af6f31f74c427c4e9ee120ce, MuSig2
                 module enabled), VENDOR.md.
  Rejected:      own crypto implementation; HTLC as primary path;
                 ECDSA; custodial bridge; Taproot without differential
                 vectors; reducing TapTweak ≥ n.
  Evidence:      the C1a/C1b/C2/C3/C4 conformance layers are green in
                 CI at the time of ratification — official BIP327
                 vectors, instrumented hash ≥ n, the 24-vector
                 adapt/extract matrix, the differential suite and the
                 adversarial suite (crates/adapters/btc test tree,
                 ci.yml build-and-test).
  Impact:        adapters/btc, vault, counterparty-api, store,
                 Keystone-role evidence, USPE.
  Supersedes:    A8 (now RESOLVED).
  Status:        RATIFIED. The executor prepared the record and the
                 evidence; the operator ratified on 2026-08-10 (order
                 recorded in chat). Ratifying the bridge does not move
                 G-F5 (M.15.2 execution legs remain).

D-014  2026-08-10  RATIFIED (operator order, recorded in chat)
  Problem:       reproducible choice of F5 execution networks and the
                 reorg environment (Annex M, renumbered from "D-009").
  Decision:      regtest + custom signet + public signet for F5;
                 mainnet excluded. Custom signet is the documented
                 known-challenge configuration (OP_TRUE, Annex M
                 M.13.1) — the controlled environment for the M.14.4
                 injected-reorg row.
  Rejected:      public testnet as a substitute; regtest only; mainnet.
  Evidence:      regtest E2E green in CI (f5-e2e.yml, f5-regtest-e2e);
                 custom-signet turnkey driver
                 (scripts/f5-signet-custom-e2e.sh); public-signet
                 runbook (docs/runbooks/F5-E2E-runbook.md). The
                 outstanding execution legs (custom + public signet
                 runs) are G-F5 evidence, not preconditions of this
                 network choice.
  Impact:        BTC adapter, observer, CI/E2E and operations.
  Supersedes:    the BTC half of A9 (now RESOLVED).
  Status:        RATIFIED. The executor prepared the record; the
                 operator ratified on 2026-08-10 (order recorded in
                 chat).

D-015  2026-08-10  RATIFIED (operator order, recorded in chat)
  Problem:       which module produces and verifies the Bitcoin
                 on-chain evidence the USPE consumes (Annex M M.9:
                 the Keystone role) — and its trust boundary.
  Decision:      a NATIVE evidence module inside this workspace
                 implements the Keystone role: KeystoneBitcoinEvidenceV1
                 (Annex M M.9.3) built and verified by
                 crates/adapters/btc (header linkage, txid merkle
                 inclusion, witness commitment, confirmations,
                 outpoint/template/terms binding, key-path vs
                 script-path outcome), consumed by the USPE as
                 evidence only. The module is trust-minimized,
                 replaceable and non-custodial: it holds no keys, no
                 nonces, no shares and no t, and cannot authorize
                 funding, sign, adapt or bypass claim/refund (M.9.1
                 prohibition list). The external Keystone repository
                 remains a compatible ALTERNATIVE implementation, not
                 a dependency.
  Rejected:      depending on the external Keystone service as the
                 only evidence source; trusting Relay/observer
                 assertions without verifiable proofs; a custodial or
                 signing-capable evidence module.
  Evidence:      the evidence verifier and its USPE consumption path
                 with adversarial tests (wrong network, broken
                 linkage, tampered witness, wrong outcome) in the
                 crates/adapters/btc test tree, green in CI.
  Impact:        adapters/btc, store, USPE, F5 E2E evidence surface.
  Supersedes:    nothing (new decision; completes the Annex M D-set).
  Status:        RATIFIED. The executor prepared the record; the
                 operator ratified on 2026-08-10 (order recorded in
                 chat).

D-016  2026-08-10  RATIFIED (operator order, recorded in chat)
  Problem:       the F3 DOM->EVM direction cannot be completed. Closing
                 the EVM leg requires handing the counterparty chain the
                 32 bytes of the adaptor secret t as `claim(lockId, t)`
                 calldata, and at pin a182563 there is no path from a
                 verified extraction to those bytes: neither
                 `AdaptorSecret` nor `dom_crypto::SecretScalar` exports
                 any. The DOM leg can prove it recovered the right t by
                 comparing the public POINT, but cannot deliver it. The
                 same hole exists at 180b731, so no choice of existing
                 revision resolves it.
  Decision:      pin updated to
                 eb6aa1ca59226bc316e3aace5ee0e279e5a154c2 (single
                 upstream commit on top of a182563, branch
                 feat/scriptless-revealed-adaptor-secret-export: adds
                 `dom_crypto::scriptless_extract_adaptor_secret_be_bytes`
                 and `AdaptorPreSignatureV1::
                 extract_revealed_secret_be_bytes`. The pre-existing
                 `scriptless_extract_adaptor_secret` now DELEGATES to the
                 byte variant, so both paths run one implementation and
                 one set of checks; the entry point verifies the
                 pre-signature equation and the observed final signature
                 through the same private helper `extract` uses.
                 `SecretScalar` gains no accessor; shares and nonces are
                 untouched; no primitive, challenge, transcript or
                 verifier is modified; every compile_fail seal holds).
                 Conformance re-executed in full at the new rev — see the
                 evidence table in section 9.2.1. Audit record:
                 docs/patches/dom-protocol/ (patch P1).
  Rationale:     the extracted adaptor secret is the one secret scalar
                 that is PUBLIC BY CONSTRUCTION — it is t = s - s_hat over
                 two already-published signatures, so any observer can
                 recompute it — and delivering it is precisely what an
                 adaptor-signature swap exists to do. The rejected
                 alternative was to recompute t inside dom-leg from the
                 DOM's own arithmetic primitives; that works, but it puts
                 the adaptor arithmetic in a second place and leaves the
                 requirement implicit, so a later revision could withdraw
                 it silently. Exporting it upstream keeps one
                 implementation and makes the interop requirement an
                 explicit, tested guarantee of the authority.
  Rejected alternatives: (a) recompute t in dom-leg (above); (b) re-pin
                 back to 180b731 — a regression that drops
                 from_session_authority and does not unblock anything,
                 since the same hole exists there; (c) leave F3 as a
                 one-direction gate.
  Impact:        the DOM pin for the whole workspace; F1/F2/F5 all
                 revalidated at the new rev. Unblocks the F3 DOM->EVM
                 route (docs/normative/F3-F5-RECONCILIATION-PLAN.md).
  Supersedes:    the pin half of D-008 (a182563 -> eb6aa1c). D-008
                 otherwise stands.
  Components:    workspace manifest revs, Cargo.lock, CI conformance
                 checkout, README pin, dom-leg AUTHORITY markers.
  Status:        RATIFIED. The executor prepared the change, executed the
                 conformance and drafted this entry; the operator ratified
                 it on 2026-08-10 (order recorded in chat). The pin is now
                 eb6aa1c for the whole workspace.

D-017  2026-08-10  RATIFIED (operator order, recorded in chat: "Aprovado")
  Problem:       F4 items 2-4 depend on objects the Foundation Document
                 marks [PROPOSAL] (§3.4: AssurancePolicyV1,
                 AssuranceCertificateV1, BondAdapter, EvidenceVerifier),
                 and the operator chose route (a): a ratified execution
                 specification before code.
  Decision:      adopt
                 docs/normative/DOM-Interop-F4-Engineering-Specification-v1.0.md
                 as the normative execution authority for F4. Headline
                 choices: bond venue v1 = EVM ConditionLockV2 (partially
                 resolves OPEN A6 — venue decided; assets/sizing remain
                 A5/A6); no new custody code (release = permissionless
                 refund, slash = beneficiary claim(t), the F3-audited
                 paths); evidence class v1 = revealed-scalar claim over
                 the D-016 extract path; the CollateralDeadlineExpired
                 event and arm (BondLocking -> ReleasePending on expiry)
                 adopted as normative after the f4-model checker proved
                 the §3.4 sketch strands collateral in BondLocking
                 (TIMEOUT_SAFE violation, found and corrected 2026-08-10,
                 evidence docs/reports/F4-STEP1-MODEL-CHECKER.md);
                 deadline geometry with a mandatory slash-execution
                 margin; assurance persistence rides the F2 store
                 discipline (journal kind 0xF401).
  Rationale:     the specification-first precedent (F2 spec, Annex M)
                 kept every phase auditable; reusing the audited
                 ConditionLockV2 and the ratified F2 store minimizes new
                 trusted surface, and the exhaustive checker already
                 adjudicates the machine in CI.
  Impact:        F4 items 2-4 unblocked under §13 of the specification;
                 §3.4 of this document remains the sketch, resolved in
                 favor of the specification where they diverge.
  Components:    docs/normative/DOM-Interop-F4-Engineering-Specification-v1.0.md,
                 crates/uspe, crates/f4-model, future f4-harness and the
                 BondAdapter surface in adapters/evm.
  Status:        RATIFIED. The executor drafted the specification and this
                 entry; the operator ratified on 2026-08-10 in chat.

D-018  2026-08-10  RATIFIED (operator decision, recorded in chat)
  Problem:       the two decisions gating the F6 build: A5 (what makes a
                 quote binding and how the winner is selected) and A10
                 (how Relay envelopes are authenticated). Corpus check
                 confirmed neither had a prior decision ([OPEN] in every
                 document version since v0.2).
  Decision:      both ratified with operator corrections over the F6
                 draft v0.1: A5 gains the three-concept structure
                 (admissible / binding / winner) with best-net-outcome
                 selection instead of lowest fee; A10 gains the
                 full-envelope digest, roster-snapshot binding and a
                 mandatory validation order. Normative texts, verbatim:

                 A5 — RATIFIED. A quote is eligible only when it is
                 canonically encoded, signed by an active solver,
                 unexpired, compliant with the RFQ and backed by an
                 exclusive F4 bond reservation satisfying the applicable
                 exposure-coverage policy. A quote becomes binding only
                 after deterministic validation, successful bond
                 reservation, acceptance and persistence of the
                 resulting terms_hash. For exact-input RFQs, the
                 admissible quote with the greatest net output wins. For
                 exact-output RFQs, the admissible quote with the lowest
                 total input wins. Ties are resolved by the shortest
                 execution deadline, then the greatest excess F4
                 coverage, then the lexicographically smallest canonical
                 solver_id. Relay arrival order MUST NOT affect
                 selection.

                 A10 — RATIFIED. Every Relay envelope MUST be
                 authenticated with a BIP340 signature produced by the
                 sender's canonical roster key over a domain-separated
                 digest of the complete canonical unsigned envelope. The
                 signed material MUST bind the protocol and network
                 identifiers, version, message type, session, route,
                 sender, recipient, sender role, sequence, previous
                 transcript hash, payload length and hash, expiry,
                 policy version and roster snapshot identifier. The
                 Relay is untrusted and MUST NOT participate in
                 signature production or verification authority.
                 Recipients MUST validate canonical encoding, roster
                 membership and role, signature, replay state, sequence
                 and transcript continuity before processing the
                 payload.

  Rationale:     A5: reuses F4 in full as the only punishment basis,
                 forbids double use of bond capacity, and privileges the
                 user's real outcome over an isolated fee figure;
                 exposure coverage stays computable by the F4 policy
                 (haircut, volatility, route risk, execution time,
                 collateral asset) without reopening A5. A10: no new
                 cryptographic primitive (I15) — BIP340 over the D-013
                 backend with the already-canonical roster keys;
                 BLAKE2b-256 produces the signed 32 bytes (the Bitcoin
                 SHA-256 tagged-hash scheme is not imported); the
                 signature makes equivocation provable to third parties,
                 which the fail-closed Relay rule requires.
  Rejected:      A5: lowest-fee-alone selection (permits worse execution
                 behind a low advertised fee); reputation-weighted
                 scoring (unrecomputable mutable state, violates I12);
                 arrival-order tie-breaks (hands the Relay an ordering
                 lever). A10: HMAC pairwise keys (equivocation not
                 provable to third parties); Ed25519 (second primitive,
                 violates I15).
  Impact:        the F6 build order is unblocked. The F6 Engineering
                 Specification v1.0 embeds both texts (§4.4, §5.3) and
                 was ADOPTED as the F6 normative and execution authority
                 by the operator on 2026-08-10 ("APROVADO", recorded in
                 chat): the adoption covers the frozen content in full,
                 authorizes execution in the established order starting
                 at step 1 (objects, codecs, frozen vectors, then
                 f6-model), does NOT pre-ratify decisions reserved to
                 F4, forbids replacing the A5/A10 normative texts with
                 paraphrases, and forbids silent material changes — any
                 later change to wire format, digest, terms_hash,
                 selection rule, binding semantics, bond reservation,
                 roster identity or validation order requires a new
                 version, a decision record and express ratification.
                 A5 becomes PARTIALLY RESOLVED (F6 half), A10 RESOLVED,
                 in section 11.
  Components:    docs/normative/DOM-Interop-F6-Engineering-Specification-v1.0.md,
                 future crates/f6-model, RFQ/selection engine, bond
                 reservation interface over the F4 objects, Relay
                 reference implementation, journal kind 0xF601.
  Status:        RATIFIED. The executor prepared the options and this
                 entry; the operator decided on 2026-08-10 with the
                 corrections recorded above.

D-019  2026-08-10  RATIFIED (explicit operator decision, 2026-08-10)
  Problem:       F6 spec §5.4 step 6 requires the recipient to "confirm
                 the sender's role permits this message_type", but no
                 source document defined the message-kind registry or
                 the role→kind mapping. The executor implemented the
                 seam with a reference policy marked NOT RATIFIED in the
                 code and reported the gap rather than filling it.
  Decision:      the message-kind registry of Relay V1 is CLOSED:

                 0x0000 = INVALID/RESERVED
                 0x0001 = RfqV1
                 0x0002 = QuoteV1
                 0x0003 = AcceptanceV1
                 0x0004 = SelectionV1
                 0x0005..0xffff = RESERVED/UNKNOWN in V1

                 Canonical sender authorization mapping:

                 Initiator: RfqV1, AcceptanceV1, SelectionV1
                 Solver:    QuoteV1
                 Observer:  no type; the observer emits no messages

                 Ratified semantics: RfqV1 is emitted by the initiator;
                 QuoteV1 by the solver; SelectionV1 is the adjudication
                 emitted by the initiator, committing the candidate set
                 and the selected quote; AcceptanceV1 is emitted by the
                 initiator and represents the final acceptance of the
                 selected quote and terms; the Observer is strictly
                 non-emitting, per Annex M §M.9.1.

                 The MessageTypePolicy trait remains a MANDATORY seam,
                 but the production implementation ceases to be an
                 unratified reference policy: it is renamed
                 CanonicalMessageTypePolicyV1, the NOT RATIFIED mark is
                 removed from that implementation only, the production
                 composition root instantiates it EXCLUSIVELY, and no
                 permissive policy, external configuration or
                 caller-chosen implementation may reach a production
                 path. Mocks and alternative policies are confined to
                 tests.

                 Verification uses the role obtained from the ROSTER,
                 and only after the envelope is authenticated under the
                 corresponding key. Unknown versions or message kinds
                 FAIL CLOSED. The values 1-4 are IMMUTABLE within V1;
                 any new type requires explicit ratification and a
                 compatible normative version — future gaps are never
                 filled by inference.

                 The Relay stays forbidden from decoding the payload.
                 The policy authorizes the HEADER; the recipient
                 consumer decodes and verifies that the inner object
                 corresponds to the message_kind, the sender, the
                 settlement and the bindings.

                 Everything already implemented in build-order step 6 is
                 preserved in full: the §6.1 idempotency key, the
                 byte-identical ACK, retransmission of the same
                 persisted bytes, fail-closed equivocation,
                 third-party-verifiable verify_equivocation, the
                 negative tests against a fabricated proof, and the
                 opaque payload of §6.2.
  Rationale:     an open registry at step 6 is an authorization gap:
                 without a closed set, an unknown kind either has to be
                 accepted by default (which would let the transport
                 introduce message classes nobody ratified) or refused
                 by a rule each implementation invents for itself. The
                 mapping also removes the two self-dealing shapes the
                 rest of F6 depends on being impossible — an initiator
                 quoting for itself, and a solver selecting itself
                 (I12). Keeping the trait as a seam preserves the
                 ability to test the negative space (a permissive policy
                 must visibly change the outcome, or the tests that
                 assert the canonical one would be vacuous) while the
                 production path stays unconfigurable.
  Rejected:      an open registry with default-accept (hands the
                 transport an unratified message class); a
                 configuration-driven policy (a configuration hook is a
                 privileged path by another name, I12); folding the
                 mapping into a match with no trait (removes the seam
                 and with it any way to prove the canonical policy is
                 what does the refusing).
  Impact:        F6 build-order step 6 closes on the ratified mapping.
                 §5.4 step 6 ceases to be a documented gap.
  Components:    crates/relay/src/auth.rs (message_type registry,
                 CanonicalMessageTypePolicyV1, accept_envelope as the
                 production entry point with no policy parameter,
                 accept_envelope_with_policy as a test-only seam);
                 crates/f6-engine/src/consumer.rs (the recipient
                 payload-object check — placed OUTSIDE `relay` so that
                 crate cannot link an F6 decoder at all);
                 scripts/guards.sh (F6/D-019 guard: the test-only seam
                 and any alternative MessageTypePolicy are refused
                 outside test trees, and the production entry point is
                 refused if it ever takes a policy parameter);
                 crates/relay/tests/d019_message_type_policy.rs (tests
                 1-10 and 12); crates/f6-engine/tests/
                 d019_consumer_payload.rs (test 11).
  Operator rectification (2026-08-10): the executor reported three
                 items of the decision that could not be implemented as
                 written against the V1 wire, and the operator resolved
                 all three the same day:
                 (a) the four digest fields `service`, `settlement_id`,
                     `message_id` and `payload_codec` do not exist in
                     the `RelayEnvelopeV1` ratified by D-018. The
                     operator EXPRESSLY RECTIFIED that wording: the
                     fields are NOT to be added, the encoding, digest
                     domain and frozen vector are NOT to be altered,
                     and D-019 does not supersede, replace or modify
                     D-018. The digest covers exactly the fields §5.2
                     ratifies.
                 (b) the fan-out sequence semantics were separated into
                     their own decision, D-020, which amends §6.1 and
                     the step-8 gap check without touching the wire.
                 (c) "the role obtained from the roster only after
                     authenticating the envelope" does NOT order step 7
                     ahead of step 6. The ratified order stands: step 6
                     reads the role from the roster and checks the
                     role→kind authorization; step 7 verifies the
                     signature. The step-6 lookup and check are
                     non-mutating and provisional — no payload is
                     delivered, no success ACK is emitted and no
                     acceptance effect or state is produced before
                     step 7 completes. The role is never accepted from
                     a claim in the envelope.
  Status:        RATIFIED. The executor reported the gap and prepared
                 the options; the operator decided on 2026-08-10 and the
                 executor implemented the decision as recorded above.

D-020  2026-08-10  RATIFIED (explicit operator decision, 2026-08-10)
  Problem:       §6.1's idempotency key and the step-8 gap check were
                 written for a single per-sender sequence space. Under
                 that reading a sender fanning out to several recipients
                 either gives each recipient its own sequence — and two
                 recipients at position 0 collide on one key, which §6.1
                 fails closed as equivocation — or advances one shared
                 counter, in which case every recipient sees the
                 messages addressed to the others as gaps in its own
                 chain. The executor reported the contradiction rather
                 than relaxing the gap rule to escape it.
  Decision:      the sequence domain is the ADDRESSED FLOW —

                 sequence_domain = (session_scope, sender_id, recipient_id)

                 where `session_scope` is the session scope already
                 present in §6.1 and in the implementation, NOT a new
                 envelope field. Within each domain: `sequence` starts
                 at 0; it grows contiguously; `previous_digest`
                 references the immediately preceding envelope OF THE
                 SAME DOMAIN; at sequence 0 it carries the canonical
                 initial value already defined; GAPS REMAIN FORBIDDEN;
                 and no total order is required between different
                 recipients.

                 The §6.1 idempotency key MUST therefore distinguish the
                 recipient:

                 (session_scope, sender_id, recipient_id, sequence)

                 Consequences: two recipients may legitimately receive
                 sequence 0; that is neither a collision nor
                 equivocation; one sender keeps an independent
                 contiguous chain per recipient; equivocation exists
                 only when the same domain and the same authenticated
                 sequence present incompatible bytes or digests; fan-out
                 is represented by distinct envelopes, one per
                 recipient; `message_id` is not required; no recipient
                 suffers a gap because of messages addressed exclusively
                 to another participant; causality between different
                 flows, where needed, belongs to the consuming
                 object/protocol and not to the Relay's counter.

                 D-020 is an express SEMANTIC amendment to §6.1 and to
                 the step-8 gap verification. It does NOT modify D-018,
                 the wire, the encoding, the digest domain or the frozen
                 vector, and adds no envelope field.
  Rationale:     `recipient_id` is already a ratified header field, so
                 naming the flow correctly costs nothing on the wire and
                 removes the false conflict at its source. It also keeps
                 the gap rule at full strength: what changed is what a
                 flow IS, not whether gaps are tolerated — a genuine
                 skip inside a flow is still refused by name.
  Rejected:      adding `message_id` to the envelope (a wire change,
                 and D-018 is preserved); relaxing or removing the gap
                 refusal (forbidden — a bound is never widened to make a
                 case pass); one shared counter with the recipients
                 tolerating gaps (hands an untrusted transport the
                 ability to hide omissions inside "legitimate" holes).
  Impact:        §6.1 and §5.4 step 8 are amended. F6 specification
                 v1.0.3 records the amendment in §6.6.
  Components:    crates/relay/src/server.rs (IdempotencyKeyV1 gains
                 recipient_id); crates/relay/src/auth.rs
                 (TranscriptStateV1 is keyed by the flow, and step 8/9
                 read that flow); crates/relay/tests/
                 d019_message_type_policy.rs (the eight required proofs,
                 t12_1..t12_8).
  Status:        RATIFIED. The executor reported the contradiction and
                 prepared no substitute rule; the operator decided on
                 2026-08-10 and the executor implemented the decision.

D-021  2026-08-10  RATIFIED (explicit operator ratification, 2026-08-10:
                   "APROVADO AD-1.2 e AD-1.4"); registry entry ordered
                   by the operator on the same day
  Problem:       AD-1.2 had been ratified in chat and recorded in the F6
                 specification, but had no entry in this registry. This
                 entry DOCUMENTS a decision already taken; it does not
                 reopen it and authorizes no semantic expansion.
  Object:        fee-limit composition over a consolidated fee.
  Decision (as it already stands in F6 spec §9, AD-1.2):

                 `FeeLimitV1` (F2, ratified) caps fees PER LEG
                 (`dom_max`, `counterparty_max`); the ratified A5 quote
                 carries ONE consolidated `total_fee`. The only
                 comparison that neither invents a split nor ignores a
                 cap is that the consolidated fee must not exceed the
                 sum of the two ratified caps:

                 total_fee <= dom_max + counterparty_max

                 checked arithmetic; overflow refuses. Refusal name:
                 `FeeAboveLimit`.
  Scope and consequence: this is WEAKER than per-leg enforcement — a
                 consolidated figure cannot be attributed to legs
                 without inventing an attribution rule. A future
                 per-leg fee breakdown in the quote is a wire change
                 and needs a new version.
  Historical reference: AD-1.2 (F6 Engineering Specification §9).
  Components:    crates/rfq/src/selection.rs (the admissibility check
                 and its named refusal); crates/f6-model.
  Status:        RATIFIED (2026-08-10). Registry entry only.

D-022  2026-08-10  RATIFIED (explicit operator ratification, 2026-08-10:
                   "APROVADO AD-1.2 e AD-1.4"); registry entry ordered
                   by the operator on the same day
  Problem:       AD-1.4 had been ratified in chat and recorded in the F6
                 specification, but had no entry in this registry. This
                 entry DOCUMENTS a decision already taken; it does not
                 reopen it and authorizes no semantic expansion.
  Object:        self-tie refusal in the ratified selection order.
  Decision (as it already stands in F6 spec §9, AD-1.4):

                 The ratified tie chain ends at the lexicographically
                 smallest `solver_id`. Two DISTINCT admissible quotes
                 from the SAME solver that are equal on every ratified
                 key (economic outcome, execution deadline, excess
                 coverage, solver id) therefore have no unique winner
                 under the ratified rule. The selection REFUSES by name
                 (`TieUnresolved`) rather than inventing an unratified
                 tie-break; the initiator may re-issue the RFQ.
  Scope and consequence: the obvious cures — a final `quote_id`
                 comparator, or one-admissible-quote-per-solver — are
                 both selection-rule changes and would require their own
                 ratification. The f6-model checker proves the refusal
                 fires EXACTLY in this configuration and never
                 otherwise.
  Historical reference: AD-1.4 (F6 Engineering Specification §9).
  Components:    crates/rfq/src/selection.rs (`select_winner` and the
                 `TieUnresolved` refusal); crates/f6-model (property P4).
  Status:        RATIFIED (2026-08-10). Registry entry only.

D-023  2026-08-10  RATIFIED (explicit operator decision, 2026-08-10)
  Problem:       F6 spec §4.2 mandates that the accepted terms_hash be
                 carried into the settlement's SettlementTermsV1, but no
                 document named the field. The executor implemented an
                 interim marked NOT RATIFIED and presented three options
                 with a recommendation.
  Decision:      option 1 ratified for V1 — the canonical F6→F2 carry.
                 For settlements derived from an F6 negotiation, the
                 accepted terms_hash is carried in
                 SettlementTermsV1.metadata with the EXACT encoding

                 DOM-INTEROP/F6-TERMS-CARRY/V1\0 || accepted_terms_hash

                 where the domain is literal and byte-identical; the
                 hash is exactly 32 bytes; there is no additional length
                 prefix, no padding and no trailing bytes; the record
                 appears exactly once; and for the F6→F2 V1 profile,
                 metadata contains exactly this record.

                 The decision does NOT alter: the SettlementTermsV1
                 wire; its canonical A3 encoding; the field order; the
                 existing A3 vectors (which remain frozen — only
                 F6→F2-composition-specific fixtures may be added);
                 intent_hash; the F6 wire; or the ratified negotiation
                 objects.

                 AUTHORITY BOUNDARY (D-023 §2): metadata remains
                 economically non-authoritative. The record commits the
                 negotiation's PROVENANCE; it enters the A3 hash because
                 metadata is already a committed field; it demonstrates
                 that a given settlement was built from the accepted
                 terms_hash; and it determines no solver, amount, asset,
                 beneficiary, fee, deadline, finality, collateral,
                 policy or economic transition. The two hashes are named
                 apart, always: accepted_terms_hash (the F6
                 negotiation's) and settlement_terms_hash (the A3 hash
                 of SettlementTermsV1's canonical bytes) — never both
                 called merely "terms_hash" where ambiguity is possible.

                 COMPOSITION (D-023 §3): the authoritative source of
                 accepted_terms_hash is the authenticated, ratified and
                 durably journaled result of the F6 negotiation — never
                 a free read of metadata. The production composition
                 root receives a TYPED F6 result and, from that one
                 value, (1) builds the canonical carry record, (2)
                 produces the canonical bytes and A3 hash of the
                 settlement, (3) provides the same typed
                 accepted_terms_hash to the F4 binding. No production
                 caller may independently supply a carry hash, a
                 different F4 hash, or arbitrary metadata alongside an
                 unrelated F4 hash. On restore/recovery: recover the
                 accepted result from the F6 journal; reconstruct the
                 expected carry; compare byte for byte with the
                 persisted commitment; check the F4 binding against the
                 same accepted_terms_hash; any divergence fails
                 terminally with a named error (TermsCarryMismatch or a
                 stable equivalent); never silently choose one of the
                 divergent values. The comparison is an integrity and
                 provenance check and does not authorize interpreting
                 metadata as a source of economic parameters.
  Rejected:      option 2 (SettlementTermsV2 with a dedicated field) is
                 RESERVED for future evolution and will require its own
                 ratification, codec, vectors and migration; option 3
                 (reusing intent_hash) is REJECTED — its ratified
                 meaning may not be overwritten.
  Impact:        the §4.2 carry ceases to be an interim. The NOT
                 RATIFIED mark is removed from this implementation only
                 and replaced by an express reference to D-023.
  Components:    crates/f6-engine/src/composition.rs (the typed,
                 journal-sourced composition root: AcceptedNegotiationV1
                 with no public constructor, carry_metadata,
                 assurance_terms_hash, parse_carry, verify_restored with
                 the named refusals TermsCarryMismatch,
                 AssuranceBindingMismatch, NegotiationNotBound);
                 crates/f6-engine/tests/d023_terms_carry.rs (mandatory
                 checks 1-3, 6-8, 10); crates/f6-engine/tests/
                 g_f6_e2e.rs (checks 4, 5, 9, preserved);
                 scripts/verify_terms_vectors.py in CI (check 11: the
                 frozen A3 vectors stay byte-identical).
  Status:        RATIFIED. The executor reported the gap and the
                 options; the operator decided on 2026-08-10; the
                 executor implemented the decision as recorded above.

D-024  2026-08-11  RATIFIED (explicit operator decision) — one-time
                   curative disposition for the F4 execution-order breach
  Problem:       F4 spec §12 item 6 conditions G-F4 on "F6+ not
                 started" — a build-order guard. The corpus shows F6
                 began (steps 1-9, published) before G-F4's formal
                 adjudication, and no prior written waiver of the order
                 exists. The breach must be treated expressly: not
                 declared retroactively compliant, and not cured by an
                 invented earlier waiver.
  Decision:      the occurrence REMAINS ON RECORD as a historical
                 deviation. A one-time, strictly limited curative
                 disposition is granted:
                 - the existence of the already published F6 work does
                   not, by itself, bar the future adjudication of G-F4;
                 - the ENTIRE current head must be re-submitted to the
                   F4 regressions;
                 - clean worktree and main == tested HEAD remain
                   mandatory;
                 - any later modification to uspe, f4-model, f4-harness,
                   store, adapter-evm, ConditionLockV2 or any interface
                   F4 consumes invalidates the binding and requires a
                   new regression;
                 - this disposition sets NO precedent for ignoring phase
                   order;
                 - it neither promotes nor anticipates G-F6;
                 - G-F6 stays deferred until G-F3, G-F4 and G-F5 are
                   formally PASS.
                 The F4 specification (v1.0.2) carries this amendment
                 next to §12 item 6 with the original text preserved
                 verbatim as historical.
  Also recorded: the operator ACCEPTED the material Sepolia evidence of
                 workflow 31431363791 (tested HEAD 9c04d363..., job
                 93595304877, artifact 9080416151, artifact SHA-256
                 d6a4733b063a910f06eef9ae112f9624084acd7ee54a6c19c556b4
                 e50ee5fbb9): public execution, four real transactions,
                 finality by the finalized tag, durable terminal
                 Compensated, privilegedActions = 0, the pagination fix
                 with no assertion relaxed, remote PASS; and the three
                 invariants NO_DOUBLE_COMPENSATION / NO_RELEASE_AND_SLASH
                 / TIMEOUT_SAFE verified by f4-model over the production
                 transition function. That evidence is NOT to be
                 repeated out of generic doubt; the new run required by
                 the closure exists solely to bind the gate to the
                 current head and to complete §12.4-§12.6 literally.
  Gate state:    G-F4 = MATERIAL EVIDENCE ACCEPTED — FORMAL ADJUDICATION
                 PENDING §12.4-§12.6 (cap/binding refusals on the real
                 node and contract; remote CI 5/5; clean worktree and
                 main == tested HEAD).
  Components:    docs/normative/DOM-Interop-F4-Engineering-Specification
                 -v1.0.md (§12 amendment note, v1.0.2); this registry.
  Status:        RATIFIED. The operator decided; the executor records
                 and implements the required completions.
  Gate-state note appended 2026-08-11 (the entry's own text above is
                 preserved VERBATIM and is not edited): the "Gate state"
                 line records the state AS OF D-024. It was superseded
                 the same day by D-026, which adjudicates G-F4 = PASS on
                 the closing run D-024 itself required. D-024's curative
                 disposition is thereby spent by its own terms. Read the
                 line above as history, not as the gate's current state.

D-025  2026-08-11  RATIFIED (explicit operator adjudication) — G-F3 = PASS
  Object:        formal adjudication of gate G-F3 (§7, "F3 — EVM leg")
                 and the completion of phase F3.
  Decision:      G-F3 = PASS. F3 = COMPLETED. The gate is adjudicated on
                 the public Ethereum Sepolia execution of 2026-08-11,
                 chain id 11155111, window 13:26:40Z..15:17:42Z. This is
                 a final adjudication: G-F3 is no longer "PROPOSED
                 PASS", "awaiting adjudication", "partial" or "pending"
                 in any document in force.
  Anchors:       executed code 7b6d4b0614ca25894c1cf6125e089908e003f39d
                 (tree 278d5e9a141583f44e43740612ac8c8616de6f6e);
                 evidence HEAD 9afaea8cb186f7639763515f2af176f7892a061c
                 (tree 4b80f9c0350591480b9dcbbdd6df77e4dcce5059);
                 ConditionLockV2 0x27bbff9ad075ca82946e61c86c7b83be102caa33
                 (runtime codehash 0x33c4df043837e30e9e0ff5a71db933849
                 fad94b22c0885734d7f940db8ed5737); ConditionLockERC20V2
                 0x6c6c1319979ebcdab9a11c0e569f840a6db3cfbf (runtime
                 codehash 0x1f1a01cfccb4dab95e9dbb7054a653d6a6c9968f05f
                 dfc0558e8d357909d796e).
  Evidentiary basis:
                 every clause of the §7 G-F3 sentence is satisfied and
                 recorded: real public testnet (chain id re-read from
                 the chain); DOM(dom-sim)<->EVM end to end through the
                 f3-harness tests anvil_dom_to_evm_direction and
                 anvil_evm_to_dom_direction, both recorded ran=true and
                 passed=true with skipped=false; BOTH directions, with
                 direction 0 and direction 1 producing distinct binding
                 and distinct lockId for otherwise identical terms, so
                 the direction is committed on chain; `t` extracted from
                 a real on-chain Claimed log through the adapter's own
                 event observer and cursor, asserted byte-identical to
                 the committed scalar; refund after a real deadline,
                 nineteen blocks of the chain's own clock with no time
                 manipulation (evm_increaseTime does not exist on a
                 public network); report with transaction hashes,
                 receipts, block numbers, block hashes, logs and
                 finality. Independent revalidation re-read every claim
                 from the chain with fresh JSON-RPC calls: 107 checks,
                 0 failures. The revalidation checker was itself tested
                 against a failed run's evidence and correctly reported
                 ten problems. Native ETH and ERC-20 both exercised; the
                 ERC-20 leg is an ADDITION to the published §7 criterion,
                 instructed and ratified by the operator on 2026-08-11,
                 and G-F3 as written is settled by the three native
                 flows alone. Secret scan clean, with the vacuous first
                 pass disclosed and corrected.
  DOM boundary:  the DOM leg ran on `dom-sim`, the project's testable
                 DOM-chain stand-in authorised by §4.5, carrying the
                 REAL `dom-adaptor` cryptography at the pinned rev
                 eb6aa1ca59226bc316e3aace5ee0e279e5a154c2. `dom-sim` is
                 not the DOM network and confers no network
                 compatibility; substituting the real DOM node is F7's
                 deliverable under its own eligibility gate. This
                 decision makes no claim about the real DOM network.
  Effects on the gate sequence:
                 G-F0, G-F1, G-F2 and G-F3 are closed. G-F4 becomes the
                 FIRST MANDATORY GATE STILL OPEN and must be
                 re-validated against the current head before
                 adjudication, because D-024 binds its accepted material
                 evidence to head 9c04d363 and paths D-024 protects
                 (crates/f4-harness, crates/kaystra-core, crates/store)
                 have changed since. This decision does NOT promote,
                 anticipate or waive G-F4, G-F5, G-F6, G-F7 or G-F8, and
                 G-F6 remains deferred under its own terms.
  Recorded limitations (not converted into PASS):
                 (a) crates/f3-harness/tests/e2e_anvil.rs:1353 reads
                 pendingWithdrawals as an absolute value and is fragile
                 on any reused deployment carrying prior credit; every
                 other credit assertion in that file uses the
                 credit_before/credit_after delta pattern. Converting it
                 is a change to a gate test and is left to the operator.
                 (b) `cargo clippy --workspace --all-targets
                 --all-features --locked -- -D warnings` fails on
                 crates/f4-harness/tests/e2e_anvil.rs
                 (clippy::clone_on_copy); that file is not compiled by
                 ci_local.sh or ci.yml, which run clippy without
                 --all-features. Both are pre-existing, neither touches
                 the F3 code path, and (b) belongs to the G-F4 work.
  Components:    docs/reports/F3-CLOSURE.md (new); this registry;
                 §7 F3 state; the Gate status header.
  Status:        RATIFIED. The operator adjudicated; the executor
                 records the adjudication and did not modify any
                 production code, contract, script, vector or test in
                 doing so, and broadcast no transaction.

D-026  2026-08-11  RATIFIED (explicit operator adjudication) — G-F4 = PASS
  Object:        formal adjudication of gate G-F4 (§7, "F4 — Minimal
                 USPE") and the completion of phase F4.
  Decision:      G-F4 = PASS. F4 = COMPLETED. NEXT REQUIRED GATE =
                 G-F5. This is a final adjudication: no document in
                 force may carry "PROPOSED PASS", "awaiting
                 adjudication", "material evidence accepted", "partial"
                 or "pending" for this gate.
  Anchors:       tested commit
                 593364b9d11cdb0843c5d732a9446a105d451860, tree
                 aa2153821272910cabf7553b99328a370ae79920, which was
                 and remains origin/main; workflow run 31521948686, job
                 93880878036, .github/workflows/f4-sepolia.yml,
                 head_branch main, event workflow_dispatch, conclusion
                 success, 2026-08-11 18:17:29Z..18:54:47Z; Ethereum
                 Sepolia, chain id 11155111; contract ConditionLockV2
                 0x90f462d6c40049005e613234baece24b190587eb, whose live
                 runtime bytecode the driver verified against this tree
                 before anything was spent; evidence artifact
                 f4-sepolia-evidence, id 9114597700, 19188 bytes,
                 SHA-256 e646f63e42f7c0433e8699dd7c6a3efc365155a5732bb
                 ebb85891e94ada88e00.
  On-chain history proven:
                 bond open
                 0x0f032a371e92b785e8a515fd5019a8ab4e2243105f14b9976be3
                 c0edac6d43cf; settlement open
                 0xcbe3100438b0d71f9361a5a7adc903bf02b670e103ae6ec3e4db
                 7f32766f6f5c; settlement claim (t becomes public)
                 0x3208d6fddb20a4a9a964378705115f7d3103ed688bcafd3d5de3
                 804506e307f6; bond slash (compensation executed)
                 0x6f49e283f9c5cd6826d4296e86059815172ae9ce770c4d06ed50
                 502d31819c67. Terminal Compensated, recovered from the
                 durable 0xF401 journal. Finality gated twice on the
                 `finalized` tag with no confirmation-count substitute:
                 #11467899 >= 11467883, then #11467993 >= 11467965. Test
                 sepolia_slash_compensates_without_any_privileged_action
                 1 passed, 0 failed, 0 ignored; privilegedActions = 0.
                 Verdict line printed by the driver:
                 `VERDICT: G-F4 SEPOLIA SLASH PASS`.
  Local proof:   all fifteen suites re-executed from zero at the tested
                 HEAD, every one exit 0, no mandatory skip — fmt;
                 `cargo clippy --workspace --all-targets --all-features
                 --locked -- -D warnings` (the profile F4 spec §19
                 requires, previously failing and fixed by 593364b);
                 workspace tests locked and all-features; doctests;
                 uspe; f4-model; f2-model; f6-model; store failpoints;
                 f4-harness rpc-http; f3-harness rpc-http; the 2000-case
                 property suite; the independent terms verifier; the
                 nine guards. f4-model explores the REAL uspe transition
                 function: 18 reachable worlds, 11/11 machine states
                 covered, and HOLDS on NO_DOUBLE_COMPENSATION,
                 NO_RELEASE_AND_SLASH, TIMEOUT_SAFE, compensated_total
                 <= compensation_cap, certificate.terms ==
                 obligation.terms, recorded_outcome in {Released,
                 Compensated}, accepted_transition -> PersistState
                 first, and terminal -> AX unchanged.
  Division of proof:
                 over-cap and wrong-terms refusals, crash-at-every-
                 transition, third-party release and timeout release
                 belong to the local and Anvil adversarial regression,
                 which is green and whose refusals touch nothing — no
                 transaction, no journal line, no state change. What §7
                 requires ON TESTNET is the compensation executed with
                 no privileged action, and the run above is that proof.
  D-024 disposition spent:
                 D-024's one-time curative disposition is now consumed
                 by its own terms — the entire current head was
                 re-submitted to the F4 regressions, clean worktree and
                 main == tested HEAD both held, and the gate is
                 adjudicated. The published F6 work did not bar this
                 adjudication, and no precedent for ignoring phase
                 order is taken from it. The earlier evidence of run
                 31431363791 at head 9c04d363 remains on the record as
                 history and is neither repeated nor rewritten.
  Recorded limits of the closing verification (not gaps in the run):
                 the executing environment could not read the artifact
                 ZIP's inner files, because the Actions artifact
                 download resolves to a blob host its network policy
                 refuses, and could not re-read the four receipts
                 independently, because every public Sepolia JSON-RPC
                 endpoint is refused by the same policy. The artifact's
                 identity is pinned by a SHA-256 that agrees across two
                 independent immutable sources: the Actions API digest
                 field and the upload step's own line in the job log.
  Effects on the gate sequence:
                 G-F0, G-F1, G-F2, G-F3 and G-F4 are closed. G-F5
                 becomes the NEXT REQUIRED GATE and remains IN PROGRESS
                 with the M.15.2 public-signet leg outstanding. G-F6
                 stays deferred — of the three gates its own closure
                 names as blocking, G-F3 and G-F4 are now closed and
                 G-F5 remains. This decision does not promote,
                 anticipate or waive G-F5, G-F6, G-F7 or G-F8.
  Components:    docs/reports/F4-CLOSURE.md; this registry; §7 F4
                 state; the Gate status header.
  Status:        RATIFIED. The operator dispatched the run and
                 adjudicated; the executor records the adjudication.
                 No production code, contract, script, workflow, vector
                 or manifest was modified by this closure, and no
                 transaction was broadcast by it.
```

### 12.2 Update protocol for this document
(ported from v1.0.1 §26, adapted)

- There is ONE context authority at a time. When a new version is
  ratified, the previous one receives the SUPERSEDED mark on its first
  page and leaves agent circulation.
- Editorial change → bumps patch; change from [PROPOSAL]→[DECIDED] or a
  new [OPEN] → bumps minor; change of an already-ratified decision or of
  topology → bumps major and requires a D-xxx entry with the superseded
  decision.
- A change to `counterparty-api`, to a canonical format or to the DOM pin
  requires a new version of this document; an adapter-internal change
  does not.
- Every agent that receives this document responds first with capsule P.3
  in its own words; if the reproduction diverges, the operator corrects
  it before any code.

---

*This v0.16 supersedes v0.15, v0.14, v0.13, v0.12, v0.11, v0.10, v0.9, v0.8, v0.7, v0.6, v0.5, v0.4, v0.3, v0.2.1, v0.2, v0.1 and the
"KAYSTRA-USPE-KEYSTONE-DOCUMENTO-MESTRE v1.0.1". The discipline of
taxonomy, gates and anti-theater remains fully in force. Code marked
[AUTHORITY: dom-adaptor eb6aa1c] is a transcription of the real crate and
cannot be altered by the project; all remaining code is [PROPOSAL] until
ratified. The single change of this version over v0.15 is D-026: the
operator's adjudication of G-F4 = PASS and F4 = COMPLETED, with the gate
status header and §7 F4 updated to match and G-F5 named as the next
required gate. No other decision, invariant, phase, open question or pin
was altered.*
