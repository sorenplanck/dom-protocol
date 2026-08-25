//! Durable encrypted custody for one participant's shared-output blinding.

use crate::{
    AdaptorError, BlindingShareV1, CollaborativeBpNonceBindingV1, CollaborativeBpNonceVaultError,
    CollaborativeBpNonceVaultV1, DecoyContributionV1, DirectionV1, DomCollaborativeRangeProofV1,
    PendingCommonNonce, Result, SessionId, ShareBackupAckV1, SigningShareV1, TrustedChainIdV1,
};
use core::fmt;
use dom_crypto::recovery::RecoveryCapsule;
use dom_crypto::{PublicKey, blake2b_256};
use dom_scriptless_primitives::{scalar_bytes_are_canonical};
use rand_core::{OsRng, RngCore};
use std::error::Error;
use zeroize::{Zeroize, Zeroizing};

/// Stable authenticated identity of one participant's encrypted `r_i` before
/// the bilateral recovery capsule exists.
///
/// The Master protocol derives each capsule contribution from `r_i`, while
/// the later share PoK binds the final capsule hash.  This provisional binding
/// deliberately omits that not-yet-computable hash, but fixes every other
/// session field and `R_i`.  It is therefore safe to persist before the
/// commit/reveal exchange and impossible to reuse in another session.
#[derive(Clone, Eq, PartialEq)]
pub struct PendingSharedBlindingBindingV1 {
    chain_id: TrustedChainIdV1,
    session_id: [u8; 32],
    roster: Vec<[u8; 32]>,
    participant_id: [u8; 32],
    role: DirectionV1,
    participant_index: u16,
    terms_hash: [u8; 32],
    share_point: PublicKey,
}

impl PendingSharedBlindingBindingV1 {
    /// Bind the stable public session context and already-frozen share point.
    ///
    /// This constructor contains no secret and is the provisional restart
    /// path used before the bilateral capsule commit/reveal completes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: &TrustedChainIdV1,
        session_id: [u8; 32],
        roster: &[[u8; 32]],
        role: DirectionV1,
        participant_index: u16,
        terms_hash: [u8; 32],
        share_point: PublicKey,
    ) -> Result<Self> {
        if !(2..=16).contains(&roster.len())
            || roster.iter().any(|participant| participant == &[0; 32])
            || roster.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AdaptorError::InvalidContext(
                "shared blinding roster must contain 2 through 16 ordered unique participants",
            ));
        }
        let participant_id =
            *roster
                .get(usize::from(participant_index))
                .ok_or(AdaptorError::InvalidContext(
                    "shared blinding participant index is outside the roster",
                ))?;
        if chain_id.as_bytes() == &[0; 32]
            || session_id == [0; 32]
            || participant_id == [0; 32]
            || terms_hash == [0; 32]
        {
            return Err(AdaptorError::InvalidContext(
                "shared blinding durable binding contains an empty identity",
            ));
        }
        Ok(Self {
            chain_id: *chain_id,
            session_id,
            roster: roster.to_vec(),
            participant_id,
            role,
            participant_index,
            terms_hash,
            share_point,
        })
    }

    /// Authenticated DOM chain identity.
    pub const fn chain_id(&self) -> &[u8; 32] {
        self.chain_id.as_bytes()
    }

    /// Contract session identity.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Complete canonical ordered participant roster.
    pub fn roster(&self) -> &[[u8; 32]] {
        &self.roster
    }

    /// Participant identity selected from the ordered roster.
    pub const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }

    /// Participant's authenticated protocol direction.
    pub const fn role(&self) -> DirectionV1 {
        self.role
    }

    /// Participant's position in the ordered roster.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }

    /// Hash of the accepted contract terms.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }

    /// Public point `R_i = r_i*G` that the encrypted share must reproduce.
    pub const fn share_point(&self) -> &PublicKey {
        &self.share_point
    }

    /// Versioned canonical associated-data bytes for the encrypted store.
    pub fn to_aad_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 2 + 32 * (4 + self.roster.len()) + 1 + 2 + 33);
        bytes.extend_from_slice(b"DOMSBLP1");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.session_id);
        bytes.extend_from_slice(&(self.roster.len() as u16).to_le_bytes());
        for participant in &self.roster {
            bytes.extend_from_slice(participant);
        }
        bytes.extend_from_slice(&self.participant_id);
        bytes.push(self.role.to_byte());
        bytes.extend_from_slice(&self.participant_index.to_le_bytes());
        bytes.extend_from_slice(&self.terms_hash);
        bytes.extend_from_slice(&self.share_point.to_compressed_bytes());
        bytes
    }

    /// Digest of the complete versioned associated-data binding.
    ///
    /// The `DOMSBLP1` prefix already provides domain separation; using DOM's
    /// canonical BLAKE2b-256 primitive avoids adding an unratified entry to the
    /// closed Scriptless hash-domain registry.
    pub fn binding_digest_v1(&self) -> [u8; 32] {
        *blake2b_256(&self.to_aad_bytes()).as_bytes()
    }
}

impl fmt::Debug for PendingSharedBlindingBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingSharedBlindingBindingV1")
            .field("participant_index", &self.participant_index)
            .field("role", &self.role)
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Complete authenticated identity of one participant's encrypted `r_i`
/// after the exact canonical recovery capsule has been frozen.
#[derive(Clone, Eq, PartialEq)]
pub struct SharedBlindingBindingV1 {
    pending: PendingSharedBlindingBindingV1,
    capsule_hash: [u8; 32],
}

impl SharedBlindingBindingV1 {
    const fn trusted_chain_id(&self) -> &TrustedChainIdV1 {
        &self.pending.chain_id
    }

    /// Promote a provisional binding to the exact canonical capsule bytes.
    ///
    /// The hash is computed by the same DOM BLAKE2b-256 primitive used by the
    /// collaborative range-proof `extra_commit` boundary.  Accepting the
    /// parsed capsule rather than a caller-provided digest closes arbitrary
    /// hash substitution at this transition.
    pub fn bind_recovery_capsule(
        pending: &PendingSharedBlindingBindingV1,
        capsule: &RecoveryCapsule,
    ) -> Self {
        Self {
            pending: pending.clone(),
            capsule_hash: *blake2b_256(capsule.as_bytes()).as_bytes(),
        }
    }

    /// Stable pre-capsule identity from which this binding was promoted.
    pub const fn pending_binding(&self) -> &PendingSharedBlindingBindingV1 {
        &self.pending
    }

    /// Authenticated DOM chain identity.
    pub const fn chain_id(&self) -> &[u8; 32] {
        self.pending.chain_id()
    }

    /// Contract session identity.
    pub const fn session_id(&self) -> &[u8; 32] {
        self.pending.session_id()
    }

    /// Complete canonical ordered participant roster.
    pub fn roster(&self) -> &[[u8; 32]] {
        self.pending.roster()
    }

    /// Participant identity selected from the ordered roster.
    pub const fn participant_id(&self) -> &[u8; 32] {
        self.pending.participant_id()
    }

    /// Participant's authenticated protocol direction.
    pub const fn role(&self) -> DirectionV1 {
        self.pending.role()
    }

    /// Participant's position in the ordered roster.
    pub const fn participant_index(&self) -> u16 {
        self.pending.participant_index()
    }

    /// Hash of the accepted contract terms.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        self.pending.terms_hash()
    }

    /// DOM hash of the exact frozen recovery-capsule bytes.
    pub const fn capsule_hash(&self) -> &[u8; 32] {
        &self.capsule_hash
    }

    /// Public point `R_i = r_i*G` that the encrypted share must reproduce.
    pub const fn share_point(&self) -> &PublicKey {
        self.pending.share_point()
    }

    /// Versioned canonical associated-data bytes for the bound store record.
    pub fn to_aad_bytes(&self) -> Vec<u8> {
        let pending = self.pending.to_aad_bytes();
        let mut bytes = Vec::with_capacity(8 + 2 + 4 + pending.len() + 32);
        bytes.extend_from_slice(b"DOMSBLB1");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&(pending.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&pending);
        bytes.extend_from_slice(&self.capsule_hash);
        bytes
    }

    /// Digest of the complete capsule-bound associated-data identity.
    pub fn binding_digest_v1(&self) -> [u8; 32] {
        *blake2b_256(&self.to_aad_bytes()).as_bytes()
    }
}

impl fmt::Debug for SharedBlindingBindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedBlindingBindingV1")
            .field("participant_index", &self.participant_index())
            .field("role", &self.role())
            .field("identity", &"[redacted]")
            .finish()
    }
}

/// Public restart context for locating one participant's durable shared
/// blinding without caller knowledge of `R_i` or the recovery capsule.
///
/// This value is descriptive rather than authoritative.  The selected
/// retained vault must authenticate exactly one matching live stage and use a
/// DOM-owned one-shot lookup capability before any share operation resumes.
pub struct SharedBlindingRestartRequestV1 {
    chain_id: TrustedChainIdV1,
    session_id: [u8; 32],
    roster: Vec<[u8; 32]>,
    participant_id: [u8; 32],
    role: DirectionV1,
    participant_index: u16,
    terms_hash: [u8; 32],
}

impl SharedBlindingRestartRequestV1 {
    /// Validate the complete stable context available after restart.
    ///
    /// Neither the public share point nor capsule bytes are accepted from the
    /// caller.  Both are recovered from authenticated retained state.
    pub fn new(
        chain_id: &TrustedChainIdV1,
        session_id: [u8; 32],
        roster: &[[u8; 32]],
        role: DirectionV1,
        participant_index: u16,
        terms_hash: [u8; 32],
    ) -> Result<Self> {
        if chain_id.as_bytes() == &[0; 32]
            || session_id == [0; 32]
            || terms_hash == [0; 32]
            || !(2..=16).contains(&roster.len())
            || roster.iter().any(|participant| participant == &[0; 32])
            || roster.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AdaptorError::InvalidContext(
                "shared blinding restart context is not canonical",
            ));
        }
        let participant_id =
            *roster
                .get(usize::from(participant_index))
                .ok_or(AdaptorError::InvalidContext(
                    "shared blinding restart participant index is outside the roster",
                ))?;
        Ok(Self {
            chain_id: *chain_id,
            session_id,
            roster: roster.to_vec(),
            participant_id,
            role,
            participant_index,
            terms_hash,
        })
    }

    /// Authenticated DOM chain identity.
    pub const fn chain_id(&self) -> &[u8; 32] {
        self.chain_id.as_bytes()
    }

    /// Contract session identity.
    pub const fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    /// Complete canonical participant roster.
    pub fn roster(&self) -> &[[u8; 32]] {
        &self.roster
    }

    /// Participant selected by the canonical index.
    pub const fn participant_id(&self) -> &[u8; 32] {
        &self.participant_id
    }

    /// Stable protocol role.
    pub const fn role(&self) -> DirectionV1 {
        self.role
    }

    /// Canonical participant index.
    pub const fn participant_index(&self) -> u16 {
        self.participant_index
    }

    /// Frozen accepted terms hash.
    pub const fn terms_hash(&self) -> &[u8; 32] {
        &self.terms_hash
    }

    fn matches_pending(&self, binding: &PendingSharedBlindingBindingV1) -> bool {
        binding.chain_id() == self.chain_id()
            && binding.session_id() == self.session_id()
            && binding.roster() == self.roster()
            && binding.participant_id() == self.participant_id()
            && binding.role() == self.role
            && binding.participant_index() == self.participant_index
            && binding.terms_hash() == self.terms_hash()
    }
}

struct ParsedPendingSharedBlindingBindingV1 {
    chain_id: [u8; 32],
    session_id: [u8; 32],
    roster: Vec<[u8; 32]>,
    participant_id: [u8; 32],
    role: DirectionV1,
    participant_index: u16,
    terms_hash: [u8; 32],
    share_point: PublicKey,
}

fn parse_pending_shared_blinding_aad_v1(
    bytes: &[u8],
) -> Result<ParsedPendingSharedBlindingBindingV1> {
    if bytes.len() < 240
        || bytes.get(..8) != Some(b"DOMSBLP1")
        || bytes.get(8..10) != Some(1u16.to_le_bytes().as_slice())
    {
        return Err(AdaptorError::InvalidContext(
            "persisted pending shared blinding binding is malformed",
        ));
    }
    let roster_len =
        usize::from(u16::from_le_bytes(bytes[74..76].try_into().map_err(
            |_| AdaptorError::InvalidContext("invalid shared blinding roster"),
        )?));
    let roster_end = 76usize
        .checked_add(
            roster_len
                .checked_mul(32)
                .ok_or(AdaptorError::InvalidContext(
                    "shared blinding roster length overflow",
                ))?,
        )
        .ok_or(AdaptorError::InvalidContext(
            "shared blinding binding length overflow",
        ))?;
    let expected = roster_end
        .checked_add(100)
        .ok_or(AdaptorError::InvalidContext(
            "shared blinding binding length overflow",
        ))?;
    if !(2..=16).contains(&roster_len) || bytes.len() != expected {
        return Err(AdaptorError::InvalidContext(
            "persisted pending shared blinding binding has a noncanonical length",
        ));
    }
    let chain_id: [u8; 32] = bytes[10..42]
        .try_into()
        .map_err(|_| AdaptorError::InvalidContext("invalid shared blinding chain"))?;
    let session_id: [u8; 32] = bytes[42..74]
        .try_into()
        .map_err(|_| AdaptorError::InvalidContext("invalid shared blinding session"))?;
    let mut roster = Vec::with_capacity(roster_len);
    for participant in bytes[76..roster_end].chunks_exact(32) {
        roster.push(
            participant
                .try_into()
                .map_err(|_| AdaptorError::InvalidContext("invalid shared blinding roster"))?,
        );
    }
    let participant_end = roster_end + 32;
    let participant_id: [u8; 32] = bytes[roster_end..participant_end]
        .try_into()
        .map_err(|_| AdaptorError::InvalidContext("invalid shared blinding participant"))?;
    let role = DirectionV1::try_from(bytes[participant_end])?;
    let participant_index = u16::from_le_bytes(
        bytes[participant_end + 1..participant_end + 3]
            .try_into()
            .map_err(|_| AdaptorError::InvalidContext("invalid shared blinding index"))?,
    );
    let terms_end = participant_end + 35;
    let terms_hash: [u8; 32] = bytes[participant_end + 3..terms_end]
        .try_into()
        .map_err(|_| AdaptorError::InvalidContext("invalid shared blinding terms"))?;
    let share_point = PublicKey::from_compressed_bytes(&bytes[terms_end..terms_end + 33])
        .map_err(|_| AdaptorError::InvalidContext("invalid shared blinding share point"))?;
    if chain_id == [0; 32]
        || session_id == [0; 32]
        || terms_hash == [0; 32]
        || roster.iter().any(|participant| participant == &[0; 32])
        || roster.windows(2).any(|pair| pair[0] >= pair[1])
        || roster.get(usize::from(participant_index)) != Some(&participant_id)
    {
        return Err(AdaptorError::InvalidContext(
            "persisted pending shared blinding binding is not canonical",
        ));
    }
    Ok(ParsedPendingSharedBlindingBindingV1 {
        chain_id,
        session_id,
        roster,
        participant_id,
        role,
        participant_index,
        terms_hash,
        share_point,
    })
}

fn pending_candidate_for_restart_v1(
    request: &SharedBlindingRestartRequestV1,
    bytes: &[u8],
) -> Result<Option<PendingSharedBlindingBindingV1>> {
    let parsed = parse_pending_shared_blinding_aad_v1(bytes)?;
    if parsed.chain_id != *request.chain_id()
        || parsed.session_id != *request.session_id()
        || parsed.roster.as_slice() != request.roster()
        || parsed.participant_id != *request.participant_id()
        || parsed.role != request.role()
        || parsed.participant_index != request.participant_index()
        || parsed.terms_hash != *request.terms_hash()
    {
        return Ok(None);
    }
    let binding = PendingSharedBlindingBindingV1::new(
        &request.chain_id,
        parsed.session_id,
        &parsed.roster,
        parsed.role,
        parsed.participant_index,
        parsed.terms_hash,
        parsed.share_point,
    )?;
    if binding.to_aad_bytes() != bytes {
        return Err(AdaptorError::InvalidContext(
            "persisted pending shared blinding binding is not byte canonical",
        ));
    }
    Ok(Some(binding))
}

fn bound_candidate_for_restart_v1(
    request: &SharedBlindingRestartRequestV1,
    bytes: &[u8],
) -> Result<Option<SharedBlindingBindingV1>> {
    if bytes.len() < 14 + 240 + 32
        || bytes.get(..8) != Some(b"DOMSBLB1")
        || bytes.get(8..10) != Some(1u16.to_le_bytes().as_slice())
    {
        return Err(AdaptorError::InvalidContext(
            "persisted bound shared blinding binding is malformed",
        ));
    }
    let pending_len = u32::from_le_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| AdaptorError::InvalidContext("invalid shared blinding binding"))?,
    ) as usize;
    let pending_end = 14usize
        .checked_add(pending_len)
        .ok_or(AdaptorError::InvalidContext(
            "shared blinding binding length overflow",
        ))?;
    if pending_end.checked_add(32) != Some(bytes.len()) {
        return Err(AdaptorError::InvalidContext(
            "persisted bound shared blinding binding has a noncanonical length",
        ));
    }
    let Some(pending) = pending_candidate_for_restart_v1(request, &bytes[14..pending_end])? else {
        return Ok(None);
    };
    let capsule_hash: [u8; 32] = bytes[pending_end..]
        .try_into()
        .map_err(|_| AdaptorError::InvalidContext("invalid shared blinding capsule hash"))?;
    let binding = SharedBlindingBindingV1 {
        pending,
        capsule_hash,
    };
    if binding.to_aad_bytes() != bytes {
        return Err(AdaptorError::InvalidContext(
            "persisted bound shared blinding binding is not byte canonical",
        ));
    }
    Ok(Some(binding))
}

/// DOM-owned one-shot authority used by a retained vault to classify and
/// select exactly one authenticated shared-blinding stage.
pub struct SharedBlindingRestartLookupCapabilityV1 {
    _private: (),
}

impl SharedBlindingRestartLookupCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Parse and authenticate a candidate pending binding against the exact
    /// restart request.  `None` means a canonical record for another context.
    pub fn pending_candidate(
        &self,
        request: &SharedBlindingRestartRequestV1,
        binding_aad: &[u8],
    ) -> Result<Option<PendingSharedBlindingBindingV1>> {
        pending_candidate_for_restart_v1(request, binding_aad)
    }

    /// Parse and authenticate a candidate bound binding against the exact
    /// restart request.  `None` means a canonical record for another context.
    pub fn bound_candidate(
        &self,
        request: &SharedBlindingRestartRequestV1,
        binding_aad: &[u8],
    ) -> Result<Option<SharedBlindingBindingV1>> {
        bound_candidate_for_restart_v1(request, binding_aad)
    }

    /// Consume the lookup authority for one unique pending stage.
    pub fn locate_pending(
        self,
        request: &SharedBlindingRestartRequestV1,
        binding: PendingSharedBlindingBindingV1,
    ) -> Result<LocatedSharedBlindingStageV1> {
        if !request.matches_pending(&binding) {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(LocatedSharedBlindingStageV1::pending(binding))
    }

    /// Consume the lookup authority for one unique capsule-bound stage.
    pub fn locate_bound(
        self,
        request: &SharedBlindingRestartRequestV1,
        binding: SharedBlindingBindingV1,
        capsule: RecoveryCapsule,
    ) -> Result<LocatedSharedBlindingStageV1> {
        if !request.matches_pending(binding.pending_binding())
            || SharedBlindingBindingV1::bind_recovery_capsule(binding.pending_binding(), &capsule)
                != binding
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(LocatedSharedBlindingStageV1::bound(binding, capsule))
    }
}

/// Opaque store-selected live stage.  It has no public constructor, codec,
/// accessor, Clone, Copy, or Debug implementation.
pub struct LocatedSharedBlindingStageV1 {
    stage: LocatedSharedBlindingStageInnerV1,
}

enum LocatedSharedBlindingStageInnerV1 {
    Pending(PendingSharedBlindingBindingV1),
    Bound {
        binding: SharedBlindingBindingV1,
        capsule: RecoveryCapsule,
    },
}

impl LocatedSharedBlindingStageV1 {
    fn pending(binding: PendingSharedBlindingBindingV1) -> Self {
        Self {
            stage: LocatedSharedBlindingStageInnerV1::Pending(binding),
        }
    }

    fn bound(binding: SharedBlindingBindingV1, capsule: RecoveryCapsule) -> Self {
        Self {
            stage: LocatedSharedBlindingStageInnerV1::Bound { binding, capsule },
        }
    }
}

/// Opaque one-shot transfer of an independently OS-generated `r_i`.
pub struct SharedBlindingMaterialV1 {
    bytes: Zeroizing<[u8; 32]>,
}

impl SharedBlindingMaterialV1 {
    fn generate_from_os_rng() -> Result<Self> {
        loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            OsRng
                .try_fill_bytes(bytes.as_mut())
                .map_err(|_| AdaptorError::RandomnessFailure)?;
            if scalar_bytes_are_canonical(&bytes, false) {
                return Ok(Self { bytes });
            }
        }
    }

    fn signing_share(self) -> Result<SigningShareV1> {
        SigningShareV1::from_be_bytes(*self.bytes)
    }
}

/// One-shot authority for the selected store to seal a fresh `r_i` record.
pub struct SharedBlindingSealCapabilityV1 {
    _private: (),
}

impl SharedBlindingSealCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Consume generated opaque material inside the selected Store's
    /// authenticated-encryption implementation.
    pub fn into_plaintext(self, material: SharedBlindingMaterialV1) -> Zeroizing<[u8; 32]> {
        material.bytes
    }
}

/// One-shot authority for authenticated import of an encrypted `r_i` record.
pub struct SharedBlindingImportCapabilityV1 {
    _private: (),
}

impl SharedBlindingImportCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Import one AEAD-authenticated canonical share from the selected Store.
    pub fn import(self, mut plaintext: Zeroizing<[u8; 32]>) -> Result<SharedBlindingMaterialV1> {
        if !scalar_bytes_are_canonical(&plaintext, false) {
            plaintext.zeroize();
            return Err(AdaptorError::InvalidContext(
                "persisted shared blinding must be canonical and nonzero",
            ));
        }
        Ok(SharedBlindingMaterialV1 { bytes: plaintext })
    }
}

/// One-shot authority to mint a backup acknowledgement only after the store
/// has proven an authenticated backup roundtrip of the exact `r_i` record.
pub struct DurableShareBackupAckCapabilityV1 {
    _private: (),
}

impl DurableShareBackupAckCapabilityV1 {
    pub(crate) const fn new() -> Self {
        Self { _private: () }
    }

    /// Mint an acknowledgement only when the backup-recovered point equals
    /// the complete durable binding.
    pub fn acknowledge(
        self,
        binding: &SharedBlindingBindingV1,
        recovered_share_point: PublicKey,
    ) -> Result<ShareBackupAckV1> {
        if &recovered_share_point != binding.share_point() {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(ShareBackupAckV1::new_durable(
            binding.participant_index(),
            recovered_share_point,
        ))
    }

    /// Mint the same public-key backup acknowledgement for a provisional
    /// record, before the capsule binding exists.
    pub fn acknowledge_pending(
        self,
        binding: &PendingSharedBlindingBindingV1,
        recovered_share_point: PublicKey,
    ) -> Result<ShareBackupAckV1> {
        if &recovered_share_point != binding.share_point() {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(ShareBackupAckV1::new_durable(
            binding.participant_index(),
            recovered_share_point,
        ))
    }
}

/// One-shot proof that a Store promotion is the exact provisional-to-bound
/// transition authorized by the DOM driver.
///
/// It has no public constructor, codec, Clone, Copy, or Debug.  The Store must
/// persist and fsync the bound primary and backup records before retiring the
/// provisional record.  The two digests let a retained implementation perform
/// an explicit compare-and-swap instead of keying the transition by mutable
/// caller state.
pub struct SharedBlindingBindingUpgradeCapabilityV1 {
    pending_digest: [u8; 32],
    bound_digest: [u8; 32],
}

impl SharedBlindingBindingUpgradeCapabilityV1 {
    fn new(
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
    ) -> Result<Self> {
        if bound.pending_binding() != pending {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(Self {
            pending_digest: pending.binding_digest_v1(),
            bound_digest: bound.binding_digest_v1(),
        })
    }

    /// Digest of the immutable provisional record that must still be live.
    pub const fn pending_binding_digest_v1(&self) -> &[u8; 32] {
        &self.pending_digest
    }

    /// Digest of the immutable capsule-bound successor to be installed.
    pub const fn bound_binding_digest_v1(&self) -> &[u8; 32] {
        &self.bound_digest
    }

    /// Consume and validate the exact CAS transition before Store mutation.
    pub fn authorize_upgrade(
        self,
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
    ) -> Result<()> {
        if bound.pending_binding() != pending
            || self.pending_digest != pending.binding_digest_v1()
            || self.bound_digest != bound.binding_digest_v1()
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SharedBlindingRetirementStageV1 {
    Pending,
    Bound,
}

/// One-shot, binding-specific request to retire encrypted `r_i` custody.
///
/// This capability proves only the exact target.  It intentionally does not
/// assert terminality: the retained Contracts Store MUST authenticate an
/// immutable terminal session successor before accepting the request, then
/// persist a terminal tombstone before deleting primary and backup material.
pub struct SharedBlindingRetirementCapabilityV1 {
    stage: SharedBlindingRetirementStageV1,
    binding_digest: [u8; 32],
}

impl SharedBlindingRetirementCapabilityV1 {
    fn pending(binding: &PendingSharedBlindingBindingV1) -> Self {
        Self {
            stage: SharedBlindingRetirementStageV1::Pending,
            binding_digest: binding.binding_digest_v1(),
        }
    }

    fn bound(binding: &SharedBlindingBindingV1) -> Self {
        Self {
            stage: SharedBlindingRetirementStageV1::Bound,
            binding_digest: binding.binding_digest_v1(),
        }
    }

    /// Consume a request targeting the exact provisional binding.
    pub fn authorize_pending(self, binding: &PendingSharedBlindingBindingV1) -> Result<()> {
        if self.stage != SharedBlindingRetirementStageV1::Pending
            || self.binding_digest != binding.binding_digest_v1()
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(())
    }

    /// Consume a request targeting the exact capsule-bound binding.
    pub fn authorize_bound(self, binding: &SharedBlindingBindingV1) -> Result<()> {
        if self.stage != SharedBlindingRetirementStageV1::Bound
            || self.binding_digest != binding.binding_digest_v1()
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(())
    }
}

/// Statically selected encrypted store/backup authority for shared `r_i`.
pub trait SharedBlindingVaultV1: Sized {
    /// Store-specific redacted error.
    type Error: Error + Send + Sync + 'static;

    /// Create and fsync an immutable encrypted provisional primary and backup
    /// record before `R_i` or a decoy commitment is released. An existing
    /// binding must not be overwritten.
    fn seal_fresh_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        material: SharedBlindingMaterialV1,
        capability: SharedBlindingSealCapabilityV1,
    ) -> core::result::Result<(), Self::Error>;

    /// AEAD-authenticate and open the exact provisional record under
    /// store-owned monotonic stage authority.
    fn open_persisted_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> core::result::Result<SharedBlindingMaterialV1, Self::Error>;

    /// Verify the independent provisional backup roundtrip. This must fail if
    /// the primary or backup is absent, substituted, or not yet fsynced.
    fn confirm_pending_backup_roundtrip(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> core::result::Result<ShareBackupAckV1, Self::Error>;

    /// Atomically promote the exact provisional record to the capsule-bound
    /// identity. Persist and fsync the final primary and backup first, then
    /// retire the provisional record with an immutable tombstone. A replay or
    /// a different successor for the same provisional digest must fail.
    fn bind_recovery_capsule(
        &mut self,
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
        capability: SharedBlindingBindingUpgradeCapabilityV1,
    ) -> core::result::Result<(), Self::Error>;

    /// AEAD-authenticate and open the exact capsule-bound record under
    /// store-owned monotonic stage authority.
    fn open_persisted_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingImportCapabilityV1,
    ) -> core::result::Result<SharedBlindingMaterialV1, Self::Error>;

    /// Verify the independent backup roundtrip and consume the only authority
    /// capable of minting this participant's backup acknowledgement.
    fn confirm_backup_roundtrip(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: DurableShareBackupAckCapabilityV1,
    ) -> core::result::Result<ShareBackupAckV1, Self::Error>;

    /// Retire a provisional share only after independently authenticating a
    /// durable terminal session successor. The Store must consume the
    /// binding-specific request, fsync a terminal tombstone, and only then
    /// delete both encrypted copies.
    fn retire_pending_share(
        &mut self,
        binding: &PendingSharedBlindingBindingV1,
        capability: SharedBlindingRetirementCapabilityV1,
    ) -> core::result::Result<(), Self::Error>;

    /// Retire a capsule-bound share only after independently authenticating a
    /// durable terminal session successor. The same consume-before-delete and
    /// no-resurrection rules as [`Self::retire_pending_share`] apply.
    fn retire_bound_share(
        &mut self,
        binding: &SharedBlindingBindingV1,
        capability: SharedBlindingRetirementCapabilityV1,
    ) -> core::result::Result<(), Self::Error>;
}

/// Additive production authority for crash-safe stage discovery and exact
/// recovery-capsule persistence.
///
/// This is intentionally a separate trait so existing evidence/test vaults
/// and the legacy two-envelope binding API remain source compatible.  An F7
/// production composition must select this trait and the restartable binding
/// entry point; a legacy bound record is not restart eligible because it does
/// not retain the canonical capsule bytes.
pub trait RestartableSharedBlindingVaultV1: SharedBlindingVaultV1 {
    /// Locate exactly one authenticated live pending or bound stage for the
    /// complete public restart context.  Zero, multiple, retired, legacy-bound
    /// or divergent matches must fail closed.
    fn locate_shared_blinding_after_restart(
        &mut self,
        request: &SharedBlindingRestartRequestV1,
        capability: SharedBlindingRestartLookupCapabilityV1,
    ) -> core::result::Result<LocatedSharedBlindingStageV1, Self::Error>;

    /// Atomically persist the two independently encrypted `r_i` records and
    /// an authenticated exact recovery capsule before retiring the pending
    /// stage.  A successful return must be restartable from the bound stage.
    fn bind_recovery_capsule_restartable(
        &mut self,
        pending: &PendingSharedBlindingBindingV1,
        bound: &SharedBlindingBindingV1,
        capsule: &RecoveryCapsule,
        capability: SharedBlindingBindingUpgradeCapabilityV1,
    ) -> core::result::Result<(), Self::Error>;
}

/// Failure at the shared-blinding driver/Store custody boundary.
#[derive(Debug)]
pub enum SharedBlindingVaultError<E> {
    /// DOM context or cryptographic validation failed.
    Protocol(AdaptorError),
    /// The selected encrypted store failed closed.
    Vault(E),
}

impl<E: fmt::Display> fmt::Display for SharedBlindingVaultError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "shared blinding protocol error: {error}"),
            Self::Vault(_) => formatter.write_str("shared blinding vault rejected operation"),
        }
    }
}

impl<E: Error + Send + Sync + 'static> Error for SharedBlindingVaultError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Vault(error) => Some(error),
        }
    }
}

/// Provisional post-backup authority used only to complete the bilateral
/// recovery-capsule commit/reveal.
///
/// It deliberately has no PoK, Bulletproof, kernel-preview, signing-share, or
/// backup-ack operation.  Those capabilities appear only after the retained
/// Store atomically promotes this exact binding to the final capsule hash.
pub struct PendingSessionBlindingShareCapabilityV1 {
    binding: PendingSharedBlindingBindingV1,
    signing_share: SigningShareV1,
}

impl PendingSessionBlindingShareCapabilityV1 {
    /// Complete stable durable binding for this provisional share.
    pub const fn binding(&self) -> &PendingSharedBlindingBindingV1 {
        &self.binding
    }

    /// Public point `R_i = r_i*G`, available only after primary and backup
    /// storage have both passed authenticated roundtrip verification.
    pub const fn public_key(&self) -> &PublicKey {
        self.signing_share.public_key()
    }

    /// Derive this participant's deterministic recovery-decoy contribution
    /// for the exact provisional session.
    pub fn derive_decoy_contribution_v1(&self) -> Result<DecoyContributionV1> {
        let session_id = SessionId::from_bytes(*self.binding.session_id()).map_err(|_| {
            AdaptorError::InvalidContext("durable shared blinding has an invalid session binding")
        })?;
        Ok(DecoyContributionV1::derive(
            &self.signing_share,
            &session_id,
        ))
    }

    /// Atomically bind the same durable share to the exact canonical capsule.
    ///
    /// The Store compare-and-swap persists and fsyncs the bound primary and
    /// backup before tombstoning the provisional identity.  The returned full
    /// capability is then re-opened from that final record, so a crash after
    /// the CAS converges through [`open_vault_backed_blinding_share_v1`].
    pub fn bind_recovery_capsule_v1<Vault: SharedBlindingVaultV1>(
        self,
        capsule: &RecoveryCapsule,
        vault: &mut Vault,
    ) -> core::result::Result<
        SessionBlindingShareCapabilityV1,
        SharedBlindingVaultError<Vault::Error>,
    > {
        let bound = SharedBlindingBindingV1::bind_recovery_capsule(&self.binding, capsule);
        let capability = SharedBlindingBindingUpgradeCapabilityV1::new(&self.binding, &bound)
            .map_err(SharedBlindingVaultError::Protocol)?;
        vault
            .bind_recovery_capsule(&self.binding, &bound, capability)
            .map_err(SharedBlindingVaultError::Vault)?;
        // Drop the provisional in-memory share before asking the Store to
        // authenticate and re-open the final record.
        drop(self);
        open_vault_backed_blinding_share_v1(bound, vault)
    }

    /// Atomically bind this pending share and persist the exact canonical
    /// recovery capsule in the same authenticated bound record.
    ///
    /// F7 production compositions must use this entry point.  It is additive
    /// to the legacy hash-only method, which remains available for existing
    /// evidence fixtures but is not restart eligible.
    pub fn bind_recovery_capsule_restartable_v1<Vault: RestartableSharedBlindingVaultV1>(
        self,
        capsule: &RecoveryCapsule,
        vault: &mut Vault,
    ) -> core::result::Result<
        SessionBlindingShareCapabilityV1,
        SharedBlindingVaultError<Vault::Error>,
    > {
        let bound = SharedBlindingBindingV1::bind_recovery_capsule(&self.binding, capsule);
        let capability = SharedBlindingBindingUpgradeCapabilityV1::new(&self.binding, &bound)
            .map_err(SharedBlindingVaultError::Protocol)?;
        vault
            .bind_recovery_capsule_restartable(&self.binding, &bound, capsule, capability)
            .map_err(SharedBlindingVaultError::Vault)?;
        drop(self);
        open_vault_backed_blinding_share_v1(bound, vault)
    }

    /// Request terminal retirement of this exact provisional record.
    ///
    /// The selected Store must reject this call until it has independently
    /// authenticated and persisted a terminal session successor.
    pub fn retire_vault_backed_v1<Vault: SharedBlindingVaultV1>(
        self,
        vault: &mut Vault,
    ) -> core::result::Result<(), SharedBlindingVaultError<Vault::Error>> {
        let binding = self.binding.clone();
        let capability = SharedBlindingRetirementCapabilityV1::pending(&binding);
        drop(self);
        vault
            .retire_pending_share(&binding, capability)
            .map_err(SharedBlindingVaultError::Vault)
    }
}

/// Purpose-specific, post-rehydrate authority over one participant's `r_i`.
///
/// The contained share has no generic callback or raw accessor. Downstream
/// code can only request the operations required by the Master Specification.
pub struct SessionBlindingShareCapabilityV1 {
    binding: SharedBlindingBindingV1,
    signing_share: SigningShareV1,
    backup_ack: Option<ShareBackupAckV1>,
}

impl SessionBlindingShareCapabilityV1 {
    fn require_bound_bp_statement(&self, statement: &crate::BpStatementV1) -> Result<()> {
        let bp_binding = CollaborativeBpNonceBindingV1::from_statement(
            statement,
            self.binding.participant_index(),
        )?;
        if bp_binding.chain_id() != self.binding.chain_id()
            || bp_binding.session_id() != self.binding.session_id()
            || bp_binding.participant_id() != self.binding.participant_id()
            || statement.participant_ids() != self.binding.roster()
            || statement.recovery_binding_hash() != self.binding.capsule_hash()
            || statement
                .commitment_shares()
                .get(usize::from(self.binding.participant_index()))
                != Some(self.signing_share.public_key())
        {
            return Err(AdaptorError::AuthorizationMismatch);
        }
        Ok(())
    }

    /// Complete public durable binding for this opaque share.
    pub const fn binding(&self) -> &SharedBlindingBindingV1 {
        &self.binding
    }

    /// Public point `R_i = r_i*G`.
    pub const fn public_key(&self) -> &PublicKey {
        self.signing_share.public_key()
    }

    /// Compute the pre-template local funding excess point
    /// `X_i = R_i + E_i` from public points only.
    ///
    /// This preview neither constructs nor consumes a signing share. The
    /// corresponding opaque scalar composition remains available only through
    /// [`Self::compose_funding_signing_share_v1`] after the exact transaction
    /// template has been durably bound.
    pub fn funding_kernel_excess_point_v1(
        &self,
        wallet_excess_point: &PublicKey,
    ) -> Result<PublicKey> {
        dom_scriptless_primitives::scriptless_add_public_points(&[
            self.signing_share.public_key().clone(),
            wallet_excess_point.clone(),
        ])
        .map_err(Into::into)
    }

    /// Compute the pre-template local claim/refund excess point
    /// `Y_i = E_i - R_i` from public points only.
    ///
    /// This preview exposes no scalar and leaves the durable shared share
    /// untouched. Opaque scalar composition occurs only after template binding
    /// through [`Self::compose_shared_output_spend_signing_share_v1`].
    pub fn shared_output_spend_kernel_excess_point_v1(
        &self,
        wallet_payout_excess_point: &PublicKey,
    ) -> Result<PublicKey> {
        dom_scriptless_primitives::scriptless_subtract_public_points(
            wallet_payout_excess_point,
            self.signing_share.public_key(),
        )
        .map_err(Into::into)
    }

    /// Produce the exact §4.2 public `R_i` and proof of knowledge only after
    /// this capability has been rehydrated from durable authenticated storage.
    pub fn blinding_contribution_v1(&self) -> Result<BlindingShareV1> {
        crate::contribute_blinding_share_v1(
            self.binding.trusted_chain_id(),
            *self.binding.session_id(),
            self.binding.roster(),
            self.binding.role(),
            self.binding.participant_index(),
            &self.signing_share,
            *self.binding.terms_hash(),
            *self.binding.capsule_hash(),
        )
    }

    /// Derive this participant's deterministic recovery-decoy contribution for
    /// the exact bound contract session.
    pub fn derive_decoy_contribution_v1(&self) -> Result<DecoyContributionV1> {
        let session_id = SessionId::from_bytes(*self.binding.session_id()).map_err(|_| {
            AdaptorError::InvalidContext("durable shared blinding has an invalid session binding")
        })?;
        Ok(DecoyContributionV1::derive(
            &self.signing_share,
            &session_id,
        ))
    }

    /// Bind a collaborative range-proof driver to the exact statement share.
    pub fn bind_collaborative_range_proof_v1(
        &self,
        statement: &crate::BpStatementV1,
        extra_commit: Vec<u8>,
    ) -> Result<DomCollaborativeRangeProofV1> {
        self.require_bound_bp_statement(statement)?;
        DomCollaborativeRangeProofV1::new(statement, extra_commit)
    }

    /// Begin the collaborative proof only after its nonce material is durably
    /// sealed and authenticated through the selected short-lived vault.
    pub fn begin_collaborative_range_proof_v1<Vault: CollaborativeBpNonceVaultV1>(
        &self,
        statement: &crate::BpStatementV1,
        vault: &mut Vault,
    ) -> core::result::Result<
        (PendingCommonNonce, [u8; 32]),
        CollaborativeBpNonceVaultError<Vault::Error>,
    > {
        self.require_bound_bp_statement(statement)
            .map_err(CollaborativeBpNonceVaultError::Protocol)?;
        PendingCommonNonce::new_vault_backed_v1(
            statement,
            self.binding.participant_index(),
            &self.signing_share,
            vault,
        )
    }

    /// Compose the local funding kernel share `x_i = r_i + e_i` without
    /// exposing either scalar.
    pub fn compose_funding_signing_share_v1(
        &self,
        wallet_excess_contribution: &SigningShareV1,
    ) -> Result<SigningShareV1> {
        crate::compose_local_funding_signing_share_v1(
            &self.signing_share,
            wallet_excess_contribution,
        )
    }

    /// Compose the local claim/refund kernel share `y_i = e_i - r_i` without
    /// exposing either scalar.
    pub fn compose_shared_output_spend_signing_share_v1(
        &self,
        wallet_payout_excess_contribution: &SigningShareV1,
    ) -> Result<SigningShareV1> {
        crate::compose_local_shared_output_spend_signing_share_v1(
            wallet_payout_excess_contribution,
            &self.signing_share,
        )
    }

    /// Consume the store-issued durable-backup acknowledgement exactly once.
    pub fn take_durable_backup_ack_v1(&mut self) -> Result<ShareBackupAckV1> {
        self.backup_ack.take().ok_or(AdaptorError::InvalidContext(
            "durable shared-blinding backup acknowledgement was already consumed",
        ))
    }

    /// Request terminal retirement of this exact capsule-bound record.
    ///
    /// The selected Store must reject this call until it has independently
    /// authenticated and persisted a terminal session successor.
    pub fn retire_vault_backed_v1<Vault: SharedBlindingVaultV1>(
        self,
        vault: &mut Vault,
    ) -> core::result::Result<(), SharedBlindingVaultError<Vault::Error>> {
        let binding = self.binding.clone();
        let capability = SharedBlindingRetirementCapabilityV1::bound(&binding);
        drop(self);
        vault
            .retire_bound_share(&binding, capability)
            .map_err(SharedBlindingVaultError::Vault)
    }
}

/// Generate one fresh `r_i`, durably seal and backup it under the stable
/// pre-capsule identity, and only then release a restricted commit/reveal
/// capability.
#[allow(clippy::too_many_arguments)]
pub fn contribute_vault_backed_blinding_share_v1<Vault: SharedBlindingVaultV1>(
    chain_id: &TrustedChainIdV1,
    session_id: [u8; 32],
    roster: &[[u8; 32]],
    role: DirectionV1,
    participant_index: u16,
    terms_hash: [u8; 32],
    vault: &mut Vault,
) -> core::result::Result<
    PendingSessionBlindingShareCapabilityV1,
    SharedBlindingVaultError<Vault::Error>,
> {
    let material = SharedBlindingMaterialV1::generate_from_os_rng()
        .map_err(SharedBlindingVaultError::Protocol)?;
    let share_point = SigningShareV1::from_be_bytes(*material.bytes)
        .map_err(SharedBlindingVaultError::Protocol)?
        .public_key()
        .clone();
    let binding = PendingSharedBlindingBindingV1::new(
        chain_id,
        session_id,
        roster,
        role,
        participant_index,
        terms_hash,
        share_point,
    )
    .map_err(SharedBlindingVaultError::Protocol)?;
    vault
        .seal_fresh_share(&binding, material, SharedBlindingSealCapabilityV1::new())
        .map_err(SharedBlindingVaultError::Vault)?;
    open_pending_vault_backed_blinding_share_v1(binding, vault)
}

/// Rehydrate one exact provisional encrypted `r_i` after restart and prove its
/// primary and backup still reproduce the frozen `R_i`.
pub fn open_pending_vault_backed_blinding_share_v1<Vault: SharedBlindingVaultV1>(
    binding: PendingSharedBlindingBindingV1,
    vault: &mut Vault,
) -> core::result::Result<
    PendingSessionBlindingShareCapabilityV1,
    SharedBlindingVaultError<Vault::Error>,
> {
    let material = vault
        .open_persisted_pending_share(&binding, SharedBlindingImportCapabilityV1::new())
        .map_err(SharedBlindingVaultError::Vault)?;
    let signing_share = material
        .signing_share()
        .map_err(SharedBlindingVaultError::Protocol)?;
    if signing_share.public_key() != binding.share_point() {
        return Err(SharedBlindingVaultError::Protocol(
            AdaptorError::AuthorizationMismatch,
        ));
    }
    let backup_ack = vault
        .confirm_pending_backup_roundtrip(&binding, DurableShareBackupAckCapabilityV1::new())
        .map_err(SharedBlindingVaultError::Vault)?;
    if backup_ack.participant_index() != binding.participant_index()
        || backup_ack.share_point() != binding.share_point()
    {
        return Err(SharedBlindingVaultError::Protocol(
            AdaptorError::AuthorizationMismatch,
        ));
    }
    Ok(PendingSessionBlindingShareCapabilityV1 {
        binding,
        signing_share,
    })
}

/// Rehydrate one exact encrypted `r_i` after restart and prove its public key
/// still equals the already-frozen binding. No scalar bytes are returned.
pub fn open_vault_backed_blinding_share_v1<Vault: SharedBlindingVaultV1>(
    binding: SharedBlindingBindingV1,
    vault: &mut Vault,
) -> core::result::Result<SessionBlindingShareCapabilityV1, SharedBlindingVaultError<Vault::Error>>
{
    let material = vault
        .open_persisted_share(&binding, SharedBlindingImportCapabilityV1::new())
        .map_err(SharedBlindingVaultError::Vault)?;
    let signing_share = material
        .signing_share()
        .map_err(SharedBlindingVaultError::Protocol)?;
    if signing_share.public_key() != binding.share_point() {
        return Err(SharedBlindingVaultError::Protocol(
            AdaptorError::AuthorizationMismatch,
        ));
    }
    // The store must prove an already-durable independent backup on every
    // fresh or restart path before the capability can expose any purpose-
    // specific operation. This is intentionally not an optional later call.
    let backup_ack = vault
        .confirm_backup_roundtrip(&binding, DurableShareBackupAckCapabilityV1::new())
        .map_err(SharedBlindingVaultError::Vault)?;
    if backup_ack.participant_index() != binding.participant_index()
        || backup_ack.share_point() != binding.share_point()
    {
        return Err(SharedBlindingVaultError::Protocol(
            AdaptorError::AuthorizationMismatch,
        ));
    }
    Ok(SessionBlindingShareCapabilityV1 {
        binding,
        signing_share,
        backup_ack: Some(backup_ack),
    })
}

/// Stage-typed shared-blinding continuation recovered exclusively from the
/// selected retained production vault.
///
/// The value is linear because both capability variants contain an opaque
/// non-cloneable signing share.  The bound variant additionally carries the
/// exact authenticated public recovery capsule required by the collaborative
/// Bulletproof and final shared output.
pub enum RestartedSessionBlindingShareV1 {
    /// The capsule commit/reveal has not completed; resume from the pending
    /// public contribution and decoy capability.
    Pending(PendingSessionBlindingShareCapabilityV1),
    /// The capsule-bound CAS completed; resume the full purpose-specific share
    /// capability together with its exact canonical capsule.
    Bound {
        /// Rehydrated opaque share capability.
        capability: SessionBlindingShareCapabilityV1,
        /// Authenticated exact public capsule persisted by the bound CAS.
        capsule: RecoveryCapsule,
    },
}

/// Locate and rehydrate one shared-blinding stage after restart without a
/// caller-supplied share point, binding digest, capsule hash, or raw record.
pub fn resume_vault_backed_blinding_share_after_restart_v1<
    Vault: RestartableSharedBlindingVaultV1,
>(
    request: SharedBlindingRestartRequestV1,
    vault: &mut Vault,
) -> core::result::Result<RestartedSessionBlindingShareV1, SharedBlindingVaultError<Vault::Error>> {
    let located = vault
        .locate_shared_blinding_after_restart(
            &request,
            SharedBlindingRestartLookupCapabilityV1::new(),
        )
        .map_err(SharedBlindingVaultError::Vault)?;
    match located.stage {
        LocatedSharedBlindingStageInnerV1::Pending(binding) => {
            open_pending_vault_backed_blinding_share_v1(binding, vault)
                .map(RestartedSessionBlindingShareV1::Pending)
        }
        LocatedSharedBlindingStageInnerV1::Bound { binding, capsule } => {
            let capability = open_vault_backed_blinding_share_v1(binding, vault)?;
            Ok(RestartedSessionBlindingShareV1::Bound {
                capability,
                capsule,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        aggregate_shared_commitment_v1, combine_decoy_capsule_v1, BpStatementV1,
        DomCollaborativeRangeProofV1,
    };

    #[derive(Debug, thiserror::Error)]
    #[error("test shared-blinding vault rejected operation")]
    struct TestVaultError;

    #[derive(Default)]
    struct TestVault {
        pending: Option<PendingSharedBlindingBindingV1>,
        bound: Option<SharedBlindingBindingV1>,
        capsule: Option<RecoveryCapsule>,
        primary: Option<[u8; 32]>,
        backup: Option<[u8; 32]>,
        pending_tombstone: bool,
        bound_tombstone: bool,
        terminal: bool,
        events: Vec<&'static str>,
    }

    impl SharedBlindingVaultV1 for TestVault {
        type Error = TestVaultError;

        fn seal_fresh_share(
            &mut self,
            binding: &PendingSharedBlindingBindingV1,
            material: SharedBlindingMaterialV1,
            capability: SharedBlindingSealCapabilityV1,
        ) -> core::result::Result<(), Self::Error> {
            if self.pending.is_some()
                || self.bound.is_some()
                || self.primary.is_some()
                || self.backup.is_some()
                || self.pending_tombstone
            {
                return Err(TestVaultError);
            }
            let plaintext = capability.into_plaintext(material);
            self.pending = Some(binding.clone());
            self.primary = Some(*plaintext);
            self.backup = Some(*plaintext);
            self.events.push("seal");
            Ok(())
        }

        fn open_persisted_pending_share(
            &mut self,
            binding: &PendingSharedBlindingBindingV1,
            capability: SharedBlindingImportCapabilityV1,
        ) -> core::result::Result<SharedBlindingMaterialV1, Self::Error> {
            if self.pending.as_ref() != Some(binding) || self.pending_tombstone {
                return Err(TestVaultError);
            }
            self.events.push("open-pending");
            capability
                .import(Zeroizing::new(self.primary.ok_or(TestVaultError)?))
                .map_err(|_| TestVaultError)
        }

        fn confirm_pending_backup_roundtrip(
            &mut self,
            binding: &PendingSharedBlindingBindingV1,
            capability: DurableShareBackupAckCapabilityV1,
        ) -> core::result::Result<ShareBackupAckV1, Self::Error> {
            if self.pending.as_ref() != Some(binding) || self.pending_tombstone {
                return Err(TestVaultError);
            }
            self.events.push("backup-pending");
            let recovered = SigningShareV1::from_be_bytes(self.backup.ok_or(TestVaultError)?)
                .map_err(|_| TestVaultError)?;
            capability
                .acknowledge_pending(binding, recovered.public_key().clone())
                .map_err(|_| TestVaultError)
        }

        fn bind_recovery_capsule(
            &mut self,
            pending: &PendingSharedBlindingBindingV1,
            bound: &SharedBlindingBindingV1,
            capability: SharedBlindingBindingUpgradeCapabilityV1,
        ) -> core::result::Result<(), Self::Error> {
            capability
                .authorize_upgrade(pending, bound)
                .map_err(|_| TestVaultError)?;
            if self.pending.as_ref() != Some(pending)
                || self.pending_tombstone
                || self.bound.is_some()
                || self.primary.is_none()
                || self.backup.is_none()
            {
                return Err(TestVaultError);
            }
            // Model the retained CAS order: the immutable successor becomes
            // durable before the provisional key is tombstoned.
            self.bound = Some(bound.clone());
            self.pending_tombstone = true;
            self.pending = None;
            self.events.push("bind");
            Ok(())
        }

        fn open_persisted_share(
            &mut self,
            binding: &SharedBlindingBindingV1,
            capability: SharedBlindingImportCapabilityV1,
        ) -> core::result::Result<SharedBlindingMaterialV1, Self::Error> {
            if self.bound.as_ref() != Some(binding) || self.bound_tombstone {
                return Err(TestVaultError);
            }
            self.events.push("open-bound");
            capability
                .import(Zeroizing::new(self.primary.ok_or(TestVaultError)?))
                .map_err(|_| TestVaultError)
        }

        fn confirm_backup_roundtrip(
            &mut self,
            binding: &SharedBlindingBindingV1,
            capability: DurableShareBackupAckCapabilityV1,
        ) -> core::result::Result<ShareBackupAckV1, Self::Error> {
            if self.bound.as_ref() != Some(binding) || self.bound_tombstone {
                return Err(TestVaultError);
            }
            self.events.push("backup-bound");
            let recovered = SigningShareV1::from_be_bytes(self.backup.ok_or(TestVaultError)?)
                .map_err(|_| TestVaultError)?;
            capability
                .acknowledge(binding, recovered.public_key().clone())
                .map_err(|_| TestVaultError)
        }

        fn retire_pending_share(
            &mut self,
            binding: &PendingSharedBlindingBindingV1,
            capability: SharedBlindingRetirementCapabilityV1,
        ) -> core::result::Result<(), Self::Error> {
            capability
                .authorize_pending(binding)
                .map_err(|_| TestVaultError)?;
            if !self.terminal || self.pending.as_ref() != Some(binding) {
                return Err(TestVaultError);
            }
            self.pending_tombstone = true;
            self.pending = None;
            self.primary = None;
            self.backup = None;
            self.events.push("retire-pending");
            Ok(())
        }

        fn retire_bound_share(
            &mut self,
            binding: &SharedBlindingBindingV1,
            capability: SharedBlindingRetirementCapabilityV1,
        ) -> core::result::Result<(), Self::Error> {
            capability
                .authorize_bound(binding)
                .map_err(|_| TestVaultError)?;
            if !self.terminal || self.bound.as_ref() != Some(binding) {
                return Err(TestVaultError);
            }
            self.bound_tombstone = true;
            self.bound = None;
            self.primary = None;
            self.backup = None;
            self.events.push("retire-bound");
            Ok(())
        }
    }

    impl RestartableSharedBlindingVaultV1 for TestVault {
        fn locate_shared_blinding_after_restart(
            &mut self,
            request: &SharedBlindingRestartRequestV1,
            capability: SharedBlindingRestartLookupCapabilityV1,
        ) -> core::result::Result<LocatedSharedBlindingStageV1, Self::Error> {
            if self.bound_tombstone {
                return Err(TestVaultError);
            }
            if let Some(binding) = self.bound.clone() {
                let Some(candidate) = capability
                    .bound_candidate(request, &binding.to_aad_bytes())
                    .map_err(|_| TestVaultError)?
                else {
                    return Err(TestVaultError);
                };
                return capability
                    .locate_bound(
                        request,
                        candidate,
                        self.capsule.clone().ok_or(TestVaultError)?,
                    )
                    .map_err(|_| TestVaultError);
            }
            if self.pending_tombstone {
                return Err(TestVaultError);
            }
            let binding = self.pending.clone().ok_or(TestVaultError)?;
            let Some(candidate) = capability
                .pending_candidate(request, &binding.to_aad_bytes())
                .map_err(|_| TestVaultError)?
            else {
                return Err(TestVaultError);
            };
            capability
                .locate_pending(request, candidate)
                .map_err(|_| TestVaultError)
        }

        fn bind_recovery_capsule_restartable(
            &mut self,
            pending: &PendingSharedBlindingBindingV1,
            bound: &SharedBlindingBindingV1,
            capsule: &RecoveryCapsule,
            capability: SharedBlindingBindingUpgradeCapabilityV1,
        ) -> core::result::Result<(), Self::Error> {
            capability
                .authorize_upgrade(pending, bound)
                .map_err(|_| TestVaultError)?;
            if self.pending.as_ref() != Some(pending)
                || self.pending_tombstone
                || self.bound.is_some()
                || self.primary.is_none()
                || self.backup.is_none()
                || SharedBlindingBindingV1::bind_recovery_capsule(pending, capsule) != *bound
            {
                return Err(TestVaultError);
            }
            self.bound = Some(bound.clone());
            self.capsule = Some(capsule.clone());
            self.pending_tombstone = true;
            self.pending = None;
            self.events.push("bind-restartable");
            Ok(())
        }
    }

    fn fixture() -> (TrustedChainIdV1, [[u8; 32]; 2]) {
        (
            TrustedChainIdV1::from_signed_fixture([0x11; 32]),
            [[0x31; 32], [0x42; 32]],
        )
    }

    fn scalar(value: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        bytes
    }

    fn capsule_for(
        pending: &PendingSessionBlindingShareCapabilityV1,
        remote_value: u8,
    ) -> RecoveryCapsule {
        let session = SessionId::from_bytes(*pending.binding().session_id()).expect("session");
        let remote_share = SigningShareV1::from_be_bytes(scalar(remote_value)).expect("remote");
        let local = pending
            .derive_decoy_contribution_v1()
            .expect("local contribution");
        let remote = DecoyContributionV1::derive(&remote_share, &session);
        let remote_commitment = remote.commitment();
        combine_decoy_capsule_v1(
            &local.into_reveal(),
            &remote.into_reveal(),
            &remote_commitment,
        )
        .expect("capsule")
    }

    #[test]
    fn two_stage_flow_binds_real_capsule_before_pok_bp_or_signing() {
        let (chain, roster) = fixture();
        let session = [0x22; 32];
        let terms = [0x51; 32];
        let mut vault_a = TestVault::default();
        let mut vault_b = TestVault::default();
        let pending_a = contribute_vault_backed_blinding_share_v1(
            &chain,
            session,
            &roster,
            DirectionV1::Initiator,
            0,
            terms,
            &mut vault_a,
        )
        .expect("pending A");
        let pending_b = contribute_vault_backed_blinding_share_v1(
            &chain,
            session,
            &roster,
            DirectionV1::Responder,
            1,
            terms,
            &mut vault_b,
        )
        .expect("pending B");
        assert_eq!(vault_a.events, ["seal", "open-pending", "backup-pending"]);
        assert_eq!(pending_a.binding().share_point(), pending_a.public_key());

        let contribution_a = pending_a.derive_decoy_contribution_v1().expect("decoy A");
        let contribution_b = pending_b.derive_decoy_contribution_v1().expect("decoy B");
        let commitment_b = contribution_b.commitment();
        let capsule = combine_decoy_capsule_v1(
            &contribution_a.into_reveal(),
            &contribution_b.into_reveal(),
            &commitment_b,
        )
        .expect("bilateral capsule");

        let mut share_a = pending_a
            .bind_recovery_capsule_v1(&capsule, &mut vault_a)
            .expect("bound A");
        let mut share_b = pending_b
            .bind_recovery_capsule_v1(&capsule, &mut vault_b)
            .expect("bound B");
        assert_eq!(
            share_a.binding().capsule_hash(),
            blake2b_256(capsule.as_bytes()).as_bytes()
        );
        assert_eq!(
            vault_a.events,
            [
                "seal",
                "open-pending",
                "backup-pending",
                "bind",
                "open-bound",
                "backup-bound"
            ]
        );

        let public_contributions = vec![
            share_a.blinding_contribution_v1().expect("bound PoK A"),
            share_b.blinding_contribution_v1().expect("bound PoK B"),
        ];
        let shared = aggregate_shared_commitment_v1(
            &chain,
            session,
            &roster,
            90,
            terms,
            *share_a.binding().capsule_hash(),
            &public_contributions,
        )
        .expect("shared commitment");
        let statement = BpStatementV1::new(
            &chain,
            session,
            roster.to_vec(),
            90,
            vec![share_a.public_key().clone(), share_b.public_key().clone()],
            PublicKey::from_compressed_bytes(shared.commitment_bytes()).expect("commitment"),
            Some(*share_a.binding().capsule_hash()),
        )
        .expect("bound statement");
        let _driver: DomCollaborativeRangeProofV1 = share_a
            .bind_collaborative_range_proof_v1(&statement, capsule.as_bytes().to_vec())
            .expect("BP driver only after final binding");

        let wallet = SigningShareV1::from_be_bytes(scalar(7)).expect("wallet contribution");
        assert_eq!(
            share_a
                .funding_kernel_excess_point_v1(wallet.public_key())
                .expect("public funding preview"),
            share_a
                .compose_funding_signing_share_v1(&wallet)
                .expect("opaque funding composition")
                .public_key()
                .clone()
        );
        assert_eq!(
            share_a
                .shared_output_spend_kernel_excess_point_v1(wallet.public_key())
                .expect("public spend preview"),
            share_a
                .compose_shared_output_spend_signing_share_v1(&wallet)
                .expect("opaque spend composition")
                .public_key()
                .clone()
        );
        assert!(share_a
            .shared_output_spend_kernel_excess_point_v1(share_a.public_key())
            .is_err());
        let binding = share_a.binding().clone();
        let point = share_a.public_key().clone();
        share_a
            .take_durable_backup_ack_v1()
            .expect("single durable acknowledgement");
        assert!(share_a.take_durable_backup_ack_v1().is_err());
        share_b.take_durable_backup_ack_v1().expect("backup B");

        let mut resumed = open_vault_backed_blinding_share_v1(binding, &mut vault_a)
            .expect("restart from authenticated primary and backup");
        assert_eq!(resumed.public_key(), &point);
        resumed
            .take_durable_backup_ack_v1()
            .expect("restart acknowledgement");
    }

    #[test]
    fn upgrade_is_cas_bound_and_restart_converges_after_persisted_successor() {
        let (chain, roster) = fixture();
        let mut vault = TestVault::default();
        let pending = contribute_vault_backed_blinding_share_v1(
            &chain,
            [0x22; 32],
            &roster,
            DirectionV1::Initiator,
            0,
            [0x51; 32],
            &mut vault,
        )
        .expect("pending");
        let pending_binding = pending.binding().clone();
        let capsule_a = capsule_for(&pending, 7);
        let capsule_b = capsule_for(&pending, 9);
        let bound_a = SharedBlindingBindingV1::bind_recovery_capsule(&pending_binding, &capsule_a);
        let bound_b = SharedBlindingBindingV1::bind_recovery_capsule(&pending_binding, &capsule_b);

        let wrong = SharedBlindingBindingUpgradeCapabilityV1::new(&pending_binding, &bound_a)
            .expect("upgrade A");
        assert!(vault
            .bind_recovery_capsule(&pending_binding, &bound_b, wrong)
            .is_err());

        let exact = SharedBlindingBindingUpgradeCapabilityV1::new(&pending_binding, &bound_a)
            .expect("exact upgrade");
        vault
            .bind_recovery_capsule(&pending_binding, &bound_a, exact)
            .expect("persist successor before simulated crash");
        drop(pending);
        let resumed = open_vault_backed_blinding_share_v1(bound_a.clone(), &mut vault)
            .expect("restart opens only bound successor");
        assert_eq!(resumed.binding(), &bound_a);

        let equivocation =
            SharedBlindingBindingUpgradeCapabilityV1::new(&pending_binding, &bound_b)
                .expect("well-formed alternate transition");
        assert!(vault
            .bind_recovery_capsule(&pending_binding, &bound_b, equivocation)
            .is_err());
        assert!(open_pending_vault_backed_blinding_share_v1(pending_binding, &mut vault).is_err());
    }

    #[test]
    fn contextual_restart_recovers_pending_then_exact_capsule_bound_stage() {
        let (chain, roster) = fixture();
        let session = [0x22; 32];
        let terms = [0x51; 32];
        let mut vault = TestVault::default();
        let pending = contribute_vault_backed_blinding_share_v1(
            &chain,
            session,
            &roster,
            DirectionV1::Initiator,
            0,
            terms,
            &mut vault,
        )
        .expect("fresh pending share");
        let expected_point = pending.public_key().clone();
        drop(pending);

        let wrong_request = SharedBlindingRestartRequestV1::new(
            &chain,
            session,
            &roster,
            DirectionV1::Initiator,
            0,
            [0x52; 32],
        )
        .expect("canonical wrong-context request");
        assert!(
            resume_vault_backed_blinding_share_after_restart_v1(wrong_request, &mut vault).is_err()
        );

        let request = SharedBlindingRestartRequestV1::new(
            &chain,
            session,
            &roster,
            DirectionV1::Initiator,
            0,
            terms,
        )
        .expect("restart request");
        let RestartedSessionBlindingShareV1::Pending(pending) =
            resume_vault_backed_blinding_share_after_restart_v1(request, &mut vault)
                .expect("pending restart")
        else {
            panic!("expected pending restart stage");
        };
        assert_eq!(pending.public_key(), &expected_point);
        let capsule = capsule_for(&pending, 7);
        let expected_capsule = capsule.clone();
        pending
            .bind_recovery_capsule_restartable_v1(&capsule, &mut vault)
            .expect("restartable bound promotion");

        let request = SharedBlindingRestartRequestV1::new(
            &chain,
            session,
            &roster,
            DirectionV1::Initiator,
            0,
            terms,
        )
        .expect("bound restart request");
        let RestartedSessionBlindingShareV1::Bound {
            capability,
            capsule,
        } = resume_vault_backed_blinding_share_after_restart_v1(request, &mut vault)
            .expect("bound restart")
        else {
            panic!("expected bound restart stage");
        };
        assert_eq!(capability.public_key(), &expected_point);
        assert_eq!(capsule, expected_capsule);
    }

    #[test]
    fn substitution_and_premature_retirement_fail_closed() {
        let (chain, roster) = fixture();
        let mut primary_vault = TestVault::default();
        let pending_primary = contribute_vault_backed_blinding_share_v1(
            &chain,
            [0x22; 32],
            &roster,
            DirectionV1::Initiator,
            0,
            [0x51; 32],
            &mut primary_vault,
        )
        .expect("fresh pending share");
        let pending_binding = pending_primary.binding().clone();
        primary_vault.primary = Some(scalar(9));
        assert!(matches!(
            open_pending_vault_backed_blinding_share_v1(
                pending_binding.clone(),
                &mut primary_vault
            ),
            Err(SharedBlindingVaultError::Protocol(
                AdaptorError::AuthorizationMismatch
            ))
        ));

        let mut backup_vault = TestVault::default();
        let pending_backup = contribute_vault_backed_blinding_share_v1(
            &chain,
            [0x23; 32],
            &roster,
            DirectionV1::Initiator,
            0,
            [0x53; 32],
            &mut backup_vault,
        )
        .expect("second fresh durable share");
        let binding = pending_backup.binding().clone();
        backup_vault.backup = Some(scalar(9));
        assert!(matches!(
            open_pending_vault_backed_blinding_share_v1(binding, &mut backup_vault),
            Err(SharedBlindingVaultError::Vault(_))
        ));

        // A binding-specific request remains insufficient until the Store has
        // authenticated a terminal session successor.
        primary_vault.primary = primary_vault.backup;
        assert!(pending_primary
            .retire_vault_backed_v1(&mut primary_vault)
            .is_err());
        let resumed = open_pending_vault_backed_blinding_share_v1(
            pending_binding.clone(),
            &mut primary_vault,
        )
        .expect("failed early retirement did not delete material");
        primary_vault.terminal = true;
        resumed
            .retire_vault_backed_v1(&mut primary_vault)
            .expect("terminal retirement");
        assert!(
            open_pending_vault_backed_blinding_share_v1(pending_binding, &mut primary_vault)
                .is_err()
        );
    }
}
