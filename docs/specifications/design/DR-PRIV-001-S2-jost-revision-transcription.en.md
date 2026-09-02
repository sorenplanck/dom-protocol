# DR-PRIV-001-S2 — The 2024 Revision: Jost's A2L+ Construction, Unique Extractability, and Selective-Failure Blindness

Status: **DESIGN SUPPLEMENT / NOT IMPLEMENTED / NOT NORMATIVE / UNSIGNED**

Date: 2026-09-02

Supplements: `DR-PRIV-001` (Part II) and `DR-PRIV-001-S1`. Where S2 and S1
conflict, **S2 wins**: S1 transcribed the 2022 state of the art; this
supplement transcribes the 2024 revision that supersedes parts of it.

Sources of transcription, both pinned:

```text
[GMM+22]  "Foundations of Coin Mixing Services", Glaeser et al., CCS 2022
          (ePrint 2022/942) — pinned in S1:
          SHA-256 5bb25d7e47dd31d37f15f9a1b72bad67c0e63e715407f7a44a4b3caa78892e45

[Jost24]  "Security of Blind Conditional Signatures Revisited",
          Fabian Jost, Master Thesis, Friedrich-Alexander-Universität
          Erlangen-Nürnberg, Chair of Applied Cryptography, 23.09.2024.
          First advisor: Prof. Dr. Dominique Schröder;
          second advisor: Paul Gerhart. 74 pages.
          SHA-256 ae79710e9ad733612e732148addd3fd6aaea218aec7665040e5b55e4f735410a

[GSST24]  "Foundations of Adaptor Signatures", Gerhart, Schröder, Soni,
          Thyagarajan (EUROCRYPT 2024) — the malleability result and the
          strengthened adaptor-signature definitions [Jost24] builds on;
          restated inside [Jost24] §5.2 and transcribed from there.
          Pin the standalone paper at implementation time.
```

Transcription honesty: everything below marked with a section number was
read from the pinned [Jost24] text layer. Everything marked **[DOM]** is
this project's adaptation or adjudication, not the thesis.

---

## 1. What the 2024 revision is (and what it is not)

[Jost24] revises the A2L+ protocol of [GMM+22] along three axes:

1. **A randomizable NIZK travels with the puzzle.** The receiver
   re-randomizes both the puzzle *and its proof*; the sender verifies the
   randomized proof against the hub's advertised encryption key **before
   producing the sender's own pre-signature**. This closes a blindness
   failure under hub–receiver collusion (§4 below).
2. **Strengthened adaptor-signature requirements**, adopted from [GSST24]
   — most critically **unique extractability**, closing an unforgeability
   break that survives every [GMM+22] assumption (§5 below).
3. **Selective-failure blindness** replaces plain blindness as the target
   notion: blindness must hold even when the adversary learns *which*
   sessions aborted (§6 below).

What it is not: a UC result (game-based, LOE model — Theorem 1); a
treatment of arbitrary collusion (the thesis's own conclusion names this
as open); or an instantiation guide (the randomizable NIZK is required
abstractly, per the Belenkiy et al. / Ananth et al. lineage).

## 2. The revised construction, transcribed (Figures 7.1–7.3)

Notation as in S1; `Π_RP` is the randomizable puzzle scheme
(Construction 1 of the thesis, the (Y, c) pair over an LOE scheme `Π_E`),
`Π_AS` the adaptor signature scheme, `⟨σ` a pre-signature.

**Theorem 1 [Jost24].** With `Rel` a canonical hard relation, `Π_RP` a
secure randomizable puzzle over an **IND-CCA-secure LOE** scheme, `NIZK` a
**sound randomizable** NIZK proof system, and `Π_AS` a secure adaptor
signature achieving **pre-signature correctness, extractability, unique
extractability, unlinkability, pre-verify soundness, and pre-signature
adaptability** — assuming OMDL, the (revised) A2L+ protocol is a secure
blind conditional signature scheme. (Blindness is proven in the
selective-failure sense, Lemma 1, in the LOE model.)

**PPromise (Fig. 7.1):**

```text
Hub H(d̃k, sk_H, m_HB):
1: (Y, y) ← Rel.GenR(1^λ)
2: Z ← Π_RP.PGen((pp, ẽk), y)         // Z = (Y, c),  c = Enc(ẽk, y)
3: π ← NIZK.P((ẽk, Y, c), y)          // L_NIZK = {(ek,Y,c) | ∃y: g^y = Y ∧ c = Enc(ek,y)}
4: ⟨σ_HB ← Π_AS.pSign(sk_H, m_HB, Y)
5: send (Z, π, ⟨σ_HB)

Bob B(ẽk, vk_H, m_HB):
1: if NIZK.V((ẽk, Z), π) ≠ 1 → ⊥
2: if Π_AS.pVrf(vk_H, m_HB, Y, ⟨σ_HB) ≠ 1 → ⊥
3: (Z′, r) ← Π_RP.PRand((pp, ẽk), Z)
4: π′ ← NIZK.Rand((ẽk, Z), π, r)      // THE 2024 ADDITION
5: τ := (r, m_HB, ⟨σ_HB, Z′, π′)
```

**PSolver (Fig. 7.2):**

```text
Alice A(sk_A, ẽk, m_AH, τ):
1: parse τ =: (·, ·, ·, Z′, π′)
2: if NIZK.V((ẽk, Z′), π′) ≠ 1 → ⊥    // THE 2024 SENDER-SIDE FENCE:
                                       // verified BEFORE Alice's pSign
3: (Z″, r′) ← Π_RP.PRand((pp, ẽk), Z′)
4: ⟨σ_AH ← Π_AS.pSign(sk_A, m_AH, Y″)
5: send (Z″, ⟨σ_AH)
8: receive σ_AH
9: y″ ← Π_AS.Extract(vk_A, ⟨σ_AH, σ_AH, Y″);  ⊥ → ⊥
11: y′ := y″ − r′;  return (σ_AH, y′)

Hub H(d̃k, vk_A, m_AH):
1: receive (Z″, ⟨σ_AH)
2: y″ ← Π_RP.PSolve(d̃k, Z″)
3: if pVrf(vk_A, m_AH, Y″, ⟨σ_AH) ≠ 1  ∨  g^{y″} ≠ Y″ → ⊥
                                       // the 2022 fence, retained verbatim
5: σ_AH ← Π_AS.Adapt(vk_A, ⟨σ_AH, y″);  send σ_AH
```

**Open (Fig. 7.3) — unchanged from 2022:** `y := y′ − r`,
`σ := Adapt(vk_H, ⟨σ_HB, y)`.

Two pre-signatures exist in the flow — the hub's `⟨σ_HB` (promise side)
and Alice's `⟨σ_AH` (solve side). The 2024 fence is positioned before
**Alice's**, not before every pre-signature; the hub's precedes the NIZK
transport by construction. **[DOM]**: this ordering is a structural
invariant, enforced by type state, not convention (§8).

## 3. The randomizable NIZK, transcribed (Definition 3, §2.4)

Language: `L_NIZK = {(ek, Y, c) | ∃ y ∈ Z_p : g^y = Y ∧ c = Π_E.Enc(ek, y)}`.

`NIZK = (Setup, P, V, Rand)` with `π′ ← Rand(crs, Y, π, r)`, satisfying
**five** properties: perfect completeness, soundness, zero-knowledge,
secure (trapdoor witness extraction), and **perfect randomizability** —
`Rand(crs, Y, π, r)` is indistinguishable from a fresh proof
`P(crs, Y′, y′)` for the randomized statement/witness. Lineage: Belenkiy
et al. (Groth–Sahai based) and Ananth et al. (fully homomorphic NIZK
framework), which are the instantiation sources.

**Why it must be randomizable [DOM restatement of the thesis's rationale]:**
Bob knows `r` but not `y`; he cannot produce a *fresh* proof for the
witness `y + r`. Only a proof-transformation algorithm bridges the gap
without the original witness. A plain Fiat–Shamir Schnorr proof does not
survive the statement transformation and cannot be substituted.

## 4. The attack the sender-side fence closes (§5.1.2, transcribed)

The hub samples a **set** of key pairs and uses a *different* `ek` per
promise. An honest Bob would notice the key differs from the advertised
one — a **colluding** Bob forwards the puzzle anyway. Alice (2022 flow)
verifies nothing, randomizes, and submits; the hub trial-decrypts with
each key in its set, and the matching key **links Alice to Bob**. The
2022 blindness game assumed no collusion, so it never saw this.

The revised fence — Alice verifying `π′` against the **advertised** `ẽk`
— closes it: Bob can hide the link to the original instance through
randomization, but cannot transform a wrong-key ciphertext into one
satisfying `L_NIZK` under the canonical `ẽk` (NIZK soundness). It also
protects Alice from locking coins on an unsolvable puzzle: the thesis
notes its Construction 1's `PRand` requires the true `ẽk` for the result
to remain solvable, but since not every `Π_RP` has that property, the
explicit proof check is added rather than relied on implicitly.

## 5. The unforgeability break and unique extractability (§5.2 + Def. 15)

Transcribed counterexample (from [GSST24], restated in [Jost24] Fig. 5.1):
wrap any secure adaptor scheme into `Π′_AS` whose pre-signature is a
**pair** `(⟨σ₁, ⟨σ₂)` of independent pre-signatures on the same message
and statement; `Adapt′` uses the first; swapping the pair yields a second
distinct full signature from **one** solver interaction. This satisfies
every Aumayr-et-al. definition yet breaks BCS unforgeability's counting
(`q` signatures from `q − 1` solves — coins stolen from the hub). First
limitation reports credited to Dai et al. [DOY22].

**Unique extractability (Definition 15, game Fig. 2.5, transcribed):** the
adversary, with pSign/Sign oracles, must produce `(m, Y, ⟨σ, σ, σ′)` with
`σ ≠ σ′`, both verifying on `m`, `⟨σ` pre-verifying on `(m, Y)`, and both
extractions yielding valid witnesses. A scheme is uniquely extractable if
this succeeds only with negligible probability — i.e. **one verifying
pre-signature commits to one full-signature outcome**.

**[DOM]**: S1's reliance on "a secure adaptor signature scheme" (the 2022
theorem wording) is hereby upgraded: the Level-2 adaptor provider MUST be
shown to satisfy all six [GSST24] properties, and the concrete Schnorr
adaptor in `dom-scriptless-crypto` gets an explicit unique-extractability
analysis and test vectors as an evidence obligation. No pair-shaped or
otherwise malleable pre-signature encoding is admissible on any surface.

## 6. Selective-failure blindness (Defs. 25–26, transcribed)

Lineage: Camenisch et al. (CNs07), Fischlin–Schröder (FS09). The
experiment hands the adversarial signer, on abort, the information of
**which** instance failed (`left` / `right` / `both`) instead of a bare
`⊥` — blindness must survive that. [Jost24] adapts the notion to BCS
(Def. 26) and proves the revised construction selective-failure blind
(Lemma 1, LOE model).

**[DOM]**: this is the formal home of two things this project already
adopted operationally: the **uniform abort envelope** (fixed-shape,
cause-free wire failures) and the rule that detailed causes live only in
a local audit log. Both graduate from "good engineering" to "required by
the target security notion".

## 7. Adjudications this supplement makes **[DOM]**

1. **S1 §4 correction — the 2022 delta is subsumed, not contradicted.**
   The hub-side fence (`pVrf ∧ g^{y″} = Y″` before Adapt) is retained
   verbatim in Fig. 7.2. The 2022 **key-well-formedness NIZK on `ẽk`**
   does *not* appear in the revised construction: [Jost24] instead
   strengthens the encryption assumption to **IND-CCA-secure LOE**, which
   excludes the crafted-key counterexamples at the assumption level.
   DOM's fail-closed posture: **carry the `π_key` well-formedness proof
   anyway** (S1 §5.2(a)) — our concrete instantiation candidates are not
   proven IND-CCA, and a cheap belt-and-braces proof at epoch open costs
   one verification.
2. **Instantiation-model nuance, stated honestly.** Standard-model CCA2
   security is incompatible with linear homomorphism (homomorphic ⇒
   malleable); the thesis's "IND-CCA-secure LOE" is coherent **inside the
   LOE idealized model**, where the adversary only reaches the scheme
   through legal-operation oracles. Any concrete reading for G3 must be
   pinned down (CCA1, or model-internal CCA) with the auditor. HSM-CL as
   used in 2022 is CPA + armor; the 2024 assumption is **strictly
   heavier** on the provider.
3. **G3 grows a second rare primitive.** Beyond the class-group LOE
   armor (S1 §1.4), Level 2 now requires a **randomizable NIZK** for
   `L_NIZK` in the Groth–Sahai / homomorphic-NIZK lineage — with perfect
   randomizability proven, not assumed. Nothing in today's Rust ecosystem
   provides this at the project's audit bar.
4. **The verify-before-pSign invariant is structural.** The sender's
   pre-signature function must be **unreachable** except through a value
   that only the NIZK verification can construct:

   ```rust
   /// Exists only through `verify_hub_puzzle`; owning one IS the proof
   /// that π′ verified against the advertised epoch key. There is no
   /// other constructor, no Default, no Clone.
   pub struct VerifiedHubPuzzleV1 {
       puzzle: RandomizedPuzzle,
       epoch_key_digest: [u8; 32],
   }

   pub fn verify_hub_puzzle(
       expected_epoch_key: &EpochKey,   // the advertised ẽk, never Bob's copy
       puzzle: RandomizedPuzzle,
       proof: &RandomizedNizk,
   ) -> Result<VerifiedHubPuzzleV1, Refusal>;

   pub fn sender_pre_sign(
       verified: VerifiedHubPuzzleV1,   // by value: consumed, single-use
       signing_key: &SenderKey,
       message: &ConditionalMessage,
       rng: &mut impl CryptoRngCore,
   ) -> Result<(SenderPreSignature, SecretRandomizer), Refusal>;
   ```

   The statement handed to `verify_hub_puzzle` binds the **expected**
   `ẽk` from the admitted epoch context — never a key that arrived with
   the puzzle. Protocol version, epoch, denomination and session binding
   ride the authenticated transcript as the tree already does everywhere;
   extending the NIZK *statement* itself is a proof-level change and is
   refused without a revised security argument (the thesis's relation is
   exactly `(ek, Y, c)`).
5. **The other agent's package, re-adjudicated.** Its design tracks
   [Jost24] correctly: the capability list mirrors Theorem 1's six
   adaptor properties plus randomizable-NIZK and selective-failure
   transport; the sender-side verify precedes its pSign; uniform aborts
   implement §6. Standing fixes it still needs: the type-state gate of
   item 4 (its ordering is by convention, not by construction); the
   `π_key` belt-and-braces of item 1; the statement-binding requirement
   (its trait must *require* the provider to bind the caller-supplied
   epoch key into verification, and its `PublicContext.hub_encryption_key`
   must be the value verified against); the exported `open_promise`
   returning a pre-signature as a final signature; the happy-path test
   that never executes the real `Open`; and the compile-level issues
   recorded in the session (unused parameter under `-D warnings`, missing
   import in tests, trait-object RNG bounds).
6. **Cross-chain alignment.** The thesis's own conclusion names
   cross-chain BCS — promise and solve on different chains — as future
   work. That is exactly DOM's G4 question. The restriction stands
   (secp-only puzzle legs in v1), now with the source acknowledging the
   gap rather than DOM inferring it.

## 8. Updated gate status

| Gate | Status after S2 |
|---|---|
| G1 | open — ratification of the record set (DR + S1 + S2 + NAR-011) |
| G2 | **closed**: both papers pinned and transcribed; the residual R1 (figure-level visual pass) applies to both PDFs |
| G3 | open, **heavier**: audited class-group LOE **plus** randomizable NIZK (Groth–Sahai / homomorphic-NIZK lineage) **plus** the IND-CCA-in-LOE reading pinned with the auditor |
| G4 | open; now backed by [Jost24]'s own future-work statement |
| G5 | open (denominations/epochs/k_min policy) |

Evidence obligations added for the implementing phase: unique-
extractability vectors for the concrete Schnorr adaptor; a
selective-failure harness comparing abort timing/size/distribution
(left/right/both indistinguishability at the transport level); a
collusion test where a wrong-key puzzle relayed by a cooperative
"receiver" is refused by the sender **before** any pre-signature exists.

---

*End of DR-PRIV-001-S2. Nothing here is implemented; nothing is normative
until ratified and signed.*
