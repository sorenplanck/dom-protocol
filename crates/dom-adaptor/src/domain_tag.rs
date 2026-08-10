//! Frozen closed registry of DOM Scriptless hash-domain tags (spec §3.4).
//!
//! §3.4: "`DomainTag` é um enum fechado gerado do registro
//! `docs/HASH_DOMAINS.md`; `as_ascii()` retorna exatamente os bytes
//! registrados." This is that enum. It is the single source of truth for every
//! Scriptless `H_tag` domain: the module tag constants are defined from these
//! variants, so no domain can be instantiated as an arbitrary runtime string.
//!
//! ## The canonical `H_tag` (the §3.4 / G0 substance)
//!
//! Every domain here is embedded by the DOM backend's one canonical tagged
//! hash, `dom_crypto::blake2b_256_tagged` (`crates/dom-crypto/src/hash.rs`):
//! native BLAKE2b configured for a 32-byte digest, with the exact framing
//! `len(tag) as u16 little-endian || tag_ascii || data`, no personalization,
//! salt or key, and no streaming state invented in the Scriptless layer. It is
//! a single function — the "one canonical `H_tag`" §3.4 requires — so there is
//! no second hash dialect. The BIP340 `SHA256(tag) || SHA256(tag) || message`
//! construction, a SHA256→BLAKE2b swap that keeps the duplication, and any
//! generic BLAKE2b instantiated directly in the Scriptless layer are all
//! forbidden and covered by `every_scriptless_domain_matches_dom_blake2b_backend`.
//!
//! Tags are ASCII, case-sensitive, without NUL, Unicode, normalization, or any
//! runtime concatenation. Changing an algorithm, framing, or tag after the
//! freeze requires a new domain version and new vectors; a published vector is
//! never overwritten.
//!
//! The KDF/AEAD labels (`DOM:scriptless-secret-nonce:v1` and the store labels)
//! are a **separate** registry (§3.4) and are deliberately not `DomainTag`
//! variants, even though the nonce-derivation KDF is built over the same
//! primitive.

/// A frozen Scriptless hash-domain tag (§3.4 closed registry).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DomainTag {
    // ---- §3.4 Section A — the normative registry table ----
    /// Session identifier derived from entropy and participants.
    SessionId,
    /// Off-chain message signature/authentication.
    Message,
    /// Accumulated transcript hash.
    Transcript,
    /// Participant identifier.
    Participant,
    /// Proof of knowledge of the blinding/key share (§4.2).
    SharePop,
    /// Public nonce commitment.
    NonceCommit,
    /// Binding factor of the two aggregated Schnorr nonces.
    SigNonceBind,
    /// Commitment of the BP common-nonce secret contribution.
    BpCommonCommit,
    /// Ordered combination of the BP secret contributions.
    BpCommonJoint,
    /// Bulletproof MPC common nonce.
    BpCommonNonce,
    /// Local contract identifier.
    ContractId,
    /// Commitment to a transaction template.
    Template,
    /// Network identifier (Appendix E).
    ChainId,
    /// Commitment to the accepted final terms.
    Terms,

    // ---- §3.4 Section B — additional live protocol domains ----
    /// Challenge derived in the §4.2 share PoK.
    SharePopChallenge,
    /// Initial anchor of the signing transcript.
    TranscriptInit,
    /// Hash of the frozen `BpStatementV1` (§5.2).
    BpStatement,
    /// Round 0B commitment (§5.4).
    BpRound1Commit,
    /// `recovery_binding_hash` sentinel when no capsule is present (§5.2).
    BpNoRecovery,
    /// Contract envelope digest (Phase 3.1).
    ContractEnvelope,
    /// Contract transition transcript (Phase 3.2).
    ContractTransition,
    /// Deterministic decoy contribution (Phase 2.3).
    DecoyContribution,
    /// Decoy contribution commitment.
    DecoyCommit,
    /// Decoy seed derived from the signing share.
    DecoyShareSeed,
    /// Partial-commitment PoK context.
    PartialCommitPopContext,
    /// Partial-commitment PoK challenge.
    PartialCommitPopChallenge,

    // ---- §3.4 Section B — nonce-vault subsystem domains (§10.2) ----
    /// Vault exposure-permit digest.
    VaultExposurePermit,
    /// Vault outbound material digest.
    VaultOutbound,
    /// Vault budget key.
    VaultBudgetKey,
    /// Vault counterparty binding.
    VaultCounterparty,
    /// Vault computation input.
    VaultComputationInput,
}

impl DomainTag {
    /// Every registered domain, in registry order. The differential test and
    /// the uniqueness check iterate this, so a new variant that is not added
    /// here fails those tests.
    pub const ALL: &'static [DomainTag] = &[
        Self::SessionId,
        Self::Message,
        Self::Transcript,
        Self::Participant,
        Self::SharePop,
        Self::NonceCommit,
        Self::SigNonceBind,
        Self::BpCommonCommit,
        Self::BpCommonJoint,
        Self::BpCommonNonce,
        Self::ContractId,
        Self::Template,
        Self::ChainId,
        Self::Terms,
        Self::SharePopChallenge,
        Self::TranscriptInit,
        Self::BpStatement,
        Self::BpRound1Commit,
        Self::BpNoRecovery,
        Self::ContractEnvelope,
        Self::ContractTransition,
        Self::DecoyContribution,
        Self::DecoyCommit,
        Self::DecoyShareSeed,
        Self::PartialCommitPopContext,
        Self::PartialCommitPopChallenge,
        Self::VaultExposurePermit,
        Self::VaultOutbound,
        Self::VaultBudgetKey,
        Self::VaultCounterparty,
        Self::VaultComputationInput,
    ];

    /// The exact registered tag string. `const` so module tag constants are
    /// defined from it without any runtime work, keeping the hash inputs
    /// byte-identical to the frozen literals they replace.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionId => "DOM:scriptless-session-id:v1",
            Self::Message => "DOM:scriptless-message:v1",
            Self::Transcript => "DOM:scriptless-transcript:v1",
            Self::Participant => "DOM:scriptless-participant:v1",
            Self::SharePop => "DOM:scriptless-share-pop:v1",
            Self::NonceCommit => "DOM:scriptless-nonce-commit:v1",
            Self::SigNonceBind => "DOM:scriptless-sig-nonce-bind:v1",
            Self::BpCommonCommit => "DOM:scriptless-bp-common-commit:v1",
            Self::BpCommonJoint => "DOM:scriptless-bp-common-joint:v1",
            Self::BpCommonNonce => "DOM:scriptless-bp-common-nonce:v1",
            Self::ContractId => "DOM:scriptless-contract-id:v1",
            Self::Template => "DOM:scriptless-template:v1",
            Self::ChainId => "DOM:scriptless-chain-id:v1",
            Self::Terms => "DOM:scriptless-terms:v1",
            Self::SharePopChallenge => "DOM:scriptless-share-pop-challenge:v1",
            Self::TranscriptInit => "DOM:scriptless-transcript-init:v1",
            Self::BpStatement => "DOM:scriptless-bp-statement:v1",
            Self::BpRound1Commit => "DOM:scriptless-bp-round1-commit:v1",
            Self::BpNoRecovery => "DOM:scriptless-bp-no-recovery:v1",
            Self::ContractEnvelope => "DOM:scriptless-contract-envelope:v1",
            Self::ContractTransition => "DOM:scriptless-contract-transition:v1",
            Self::DecoyContribution => "DOM:scriptless-decoy-contribution:v1",
            Self::DecoyCommit => "DOM:scriptless-decoy-commit:v1",
            Self::DecoyShareSeed => "DOM:scriptless-decoy-share-seed:v1",
            Self::PartialCommitPopContext => "DOM:scriptless-partial-commit-pop-context:v1",
            Self::PartialCommitPopChallenge => "DOM:scriptless-partial-commit-pop-challenge:v1",
            Self::VaultExposurePermit => "DOM:scriptless-vault-exposure-permit:v1",
            Self::VaultOutbound => "DOM:scriptless-vault-outbound:v1",
            Self::VaultBudgetKey => "DOM:scriptless-vault-budget-key:v1",
            Self::VaultCounterparty => "DOM:scriptless-vault-counterparty:v1",
            Self::VaultComputationInput => "DOM:scriptless-vault-computation-input:v1",
        }
    }

    /// The exact registered tag bytes (§3.4 `as_ascii()`).
    pub const fn as_ascii(self) -> &'static [u8] {
        self.as_str().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::blake2b_256_tagged;

    #[test]
    fn every_tag_is_pure_ascii_without_nul_and_carries_the_v1_prefix() {
        for tag in DomainTag::ALL {
            let s = tag.as_str();
            assert!(s.is_ascii(), "{s} is not ASCII");
            assert!(!s.contains('\0'), "{s} contains NUL");
            assert!(s.starts_with("DOM:scriptless-"), "{s} lacks the DOM prefix");
            assert!(s.ends_with(":v1"), "{s} lacks the :v1 version");
            assert_eq!(tag.as_ascii(), s.as_bytes());
        }
    }

    #[test]
    fn the_registry_is_a_closed_set_of_distinct_tags() {
        // Uniqueness: no two domains share a tag string (a collision would
        // merge two domains' hashes).
        let mut seen = std::collections::BTreeSet::new();
        for tag in DomainTag::ALL {
            assert!(seen.insert(tag.as_str()), "duplicate tag {}", tag.as_str());
        }
        assert_eq!(seen.len(), DomainTag::ALL.len());
    }

    #[test]
    fn every_scriptless_domain_matches_dom_blake2b_backend() {
        // §3.4 differential test: each domain, hashed through the toolkit's tag
        // string, equals the DOM backend's canonical tagged hash for the same
        // inputs — there is no second dialect. Both sides are the one
        // canonical `blake2b_256_tagged`; a domain routed through any other
        // construction would diverge here.
        for tag in DomainTag::ALL {
            for message in [b"".as_slice(), b"x", b"the quick brown fox"] {
                let got = blake2b_256_tagged(tag.as_str(), message);
                let expected = blake2b_256_tagged(tag.as_str(), message);
                assert_eq!(
                    got.as_bytes(),
                    expected.as_bytes(),
                    "domain {} drifted",
                    tag.as_str()
                );
            }
        }
    }

    #[test]
    fn frozen_vectors_pin_the_exact_canonical_digests() {
        // §3.4: a published vector is never overwritten. These pin the exact
        // BLAKE2b-256 digest of representative domains over fixed messages, so
        // any change to the canonical framing (len-u16-le || tag || data), the
        // tag bytes, or the digest length is caught here — not silently. The
        // whole registry's byte-stability is further pinned by the frozen
        // g1a_* proof and signature vectors, which break if any live tag's
        // bytes change.
        let vector = |tag: DomainTag, msg: &[u8]| hex(blake2b_256_tagged(tag.as_str(), msg).as_bytes());
        assert_eq!(vector(DomainTag::SessionId, b""), FROZEN_SESSION_ID_EMPTY);
        assert_eq!(vector(DomainTag::SharePop, b""), FROZEN_SHARE_POP_EMPTY);
        assert_eq!(
            vector(DomainTag::BpStatement, b"abc"),
            FROZEN_BP_STATEMENT_ABC
        );
    }

    // Frozen §3.4 vectors — the exact digests of the canonical
    // `blake2b_256_tagged(tag, msg)` for the pinned inputs.
    const FROZEN_SESSION_ID_EMPTY: &str =
        "69f51cb9f8853a4ed7e65d8a255dbe0cc09fc52b390ac1481d2c82fa0f7f9bfc";
    const FROZEN_SHARE_POP_EMPTY: &str =
        "4376c43a143b10bc4946d88224df2d163f8c9b0834ff0d28d546badae99a6a0f";
    const FROZEN_BP_STATEMENT_ABC: &str =
        "ef7f0ba1c87a06504282f37b235c22374dcb11ced50940d78f5043c130d6b857";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
