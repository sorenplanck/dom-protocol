> **SUPERSEDED (2026-08-10).** No longer the context authority. Current
> authority: `DOM-Interop-Foundation-Document-v0.6.md` (adds D-012 F5
> parallel start + Annex M v3.2 adoption, and D-013/D-014 pending). Kept
> as history.

# FOUNDATION DOCUMENT — DOM INTEROP
## DOM-Centric Interoperability System (DOM v2 Project)

```text
Version:             0.5
Date:                2026-08-10
Owner:               Soren Planck (operator and ratification authority)
Lead executor:       Partner developer (to be formally defined)
State:               PARTIALLY RATIFIED — D-000, D-001, D-005, D-006, D-007,
                     D-008, D-009, D-010, D-011 and A7 ratified (/goat
                     order and operator decisions of 2026-08-09/10,
                     recorded in section 12); the rest remains DRAFT
                     pending ratification
Product name:        DECIDED (D-009): no standalone product name. This is
                     a component of the DOM ecosystem, destined for
                     integration into the DOM v2 (phase F8); "DOM
                     Interop" remains only the descriptive repository/
                     component name
Supersedes:          v0.4, v0.3, v0.2.1, v0.2, v0.1 and the "KAYSTRA-USPE-
                     KEYSTONE-DOCUMENTO-MESTRE v1.0.1" master document (all
                     SUPERSEDED as context authority; useful blocks ported
                     here)
Language:            English is the normative language from v0.4 onward
                     (operator rule, 2026-08-10); earlier versions remain
                     in Portuguese as history.
Gate status:         G-F0 = PASS (docs/reports/F0-CLOSURE.md, waiver
                     R-001 lifted); G-F1 = PASS
                     (docs/reports/F1-CLOSURE.md §12); G-F2 = PASS
                     (docs/reports/F2-CLOSURE.md)
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
**[AUTHORITY: dom-adaptor a182563]** — in those cases the code is a
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
   DOM_ADAPTOR_REV  = a1825639154dcc9d89be098079112e9cb975940e
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
        │   a182563          │   ├─ EVM (ConditionVM)      │
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

### 2.2 DOM leg — [AUTHORITY: dom-adaptor a182563]

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
Solver economics: [OPEN A5], to be ratified in F6.

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
                rev = "a1825639154dcc9d89be098079112e9cb975940e",
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
    pub authentication: AuthTag, // [OPEN A10]
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

### F4 — Minimal USPE
First code: `AssuranceState` + invariants as property tests + model
checking (§3.4); `BondAdapter` over the ConditionLock.
Gate G-F4: `NO_DOUBLE_COMPENSATION + NO_RELEASE_AND_SLASH + TIMEOUT_SAFE`
demonstrated; compensation executed on testnet without any privileged
action.

### F5 — Bitcoin leg
First code: BIP340 bridge (§2.4) with x-only parity vectors frozen
BEFORE any flow.
Gate G-F5: DOM(dom-sim)↔BTC E2E on regtest and signet, both directions;
real CSV refund; Keystone evidence consumed by the USPE.

### F6 — RFQ, solver and Relay
Deliverables: RFQ/quotes/selection (A5); Relay (§4.6).
Gate G-F6: complete settlement with a solver; total loss of the Relay and
its database does not prevent local claim or refund;
ACK/dedup/byte-identical retransmission approved.

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
          git -C dom checkout a1825639154dcc9d89be098079112e9cb975940e
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
A5  Solver economics, fees and USPE bond sizing (F4/F6).
A6  Where the v1 bonds live (EVM) and future migration to the DOM.
A7  RESOLVED — SQLite/WAL (docs/adr/ADR-A7-SQLite-WAL.md, ratified
    2026-08-06); adapter allocation adjusted by D-005.
A8  Formal DOM-Schnorr ↔ BIP340 bridge, incl. x-only parity (F5).
A9  Chosen testnets (EVM; BTC signet).
A10 Authentication of the Relay envelopes.
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

*This v0.5 supersedes v0.4, v0.3, v0.2.1, v0.2, v0.1 and the
"KAYSTRA-USPE-KEYSTONE-DOCUMENTO-MESTRE v1.0.1". The discipline of
taxonomy, gates and anti-theater remains fully in force. Code marked
[AUTHORITY: dom-adaptor a182563] is a transcription of the real crate and
cannot be altered by the project; all remaining code is [PROPOSAL] until
ratified.*
