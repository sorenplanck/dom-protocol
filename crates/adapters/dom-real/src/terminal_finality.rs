//! Opaque terminal finality and bounded reorg proofs for real DOM.

use super::*;

const CHECKPOINT_MAGIC: &[u8; 8] = b"DOMFIN1\0";
const CHECKPOINT_VERSION: u16 = 1;
const CHECKPOINT_DOMAIN: &[u8] = b"DOM-INTEROP/DOM-TERMINAL-CHECKPOINT/V1\0";
const FUNDING_FINALITY_DOMAIN: &[u8] = b"DOM-INTEROP/DOM-FUNDING-FINALITY/V1\0";
const CLAIM_FINALITY_DOMAIN: &[u8] = b"DOM-INTEROP/DOM-CLAIM-FINALITY/V1\0";
const REFUND_FINALITY_DOMAIN: &[u8] = b"DOM-INTEROP/DOM-REFUND-FINALITY/V1\0";
const REORG_DOMAIN: &[u8] = b"DOM-INTEROP/DOM-TERMINAL-REORG/V1\0";
const CHECKPOINT_FIXED_LEN: usize = 8 + 2 + 1 + 1 + 32 + 8 + 32 + 4 + 8 + 32 + 4 + 4 + 4 + 32 + 2;
const CHECKPOINT_ENTRY_LEN: usize = 8 + 32;
const CHECKPOINT_DIGEST_LEN: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum TerminalKindV1 {
    Claim = 1,
    Refund = 2,
    Funding = 3,
}

impl TerminalKindV1 {
    fn decode(tag: u8) -> Result<Self, RealDomError> {
        match tag {
            1 => Ok(Self::Claim),
            2 => Ok(Self::Refund),
            3 => Ok(Self::Funding),
            _ => Err(RealDomError::InvalidEvidence),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct TerminalCheckpointV1 {
    kind: TerminalKindV1,
    tx_hash: [u8; 32],
    block_height: u64,
    block_hash: [u8; 32],
    transaction_index: u32,
    tip_height: u64,
    tip_hash: [u8; 32],
    confirmation_depth: u32,
    minimum_confirmations: u32,
    max_reorg_depth: u32,
    evidence_digest: [u8; 32],
    canonical_tail: Vec<(u64, [u8; 32])>,
}

impl TerminalCheckpointV1 {
    fn validate(&self) -> Result<(), RealDomError> {
        validate_finality_policy(self.minimum_confirmations, self.max_reorg_depth)?;
        let expected_depth = self
            .tip_height
            .checked_sub(self.block_height)
            .and_then(|distance| distance.checked_add(1))
            .and_then(|depth| u32::try_from(depth).ok())
            .ok_or(RealDomError::InvalidEvidence)?;
        let expected_tail_len = usize::try_from(
            u64::from(self.max_reorg_depth)
                .checked_add(1)
                .ok_or(RealDomError::BoundsExceeded)?
                .min(
                    self.tip_height
                        .checked_add(1)
                        .ok_or(RealDomError::BoundsExceeded)?,
                ),
        )
        .map_err(|_| RealDomError::BoundsExceeded)?;
        if self.tx_hash == [0; 32]
            || self.block_hash == [0; 32]
            || self.tip_hash == [0; 32]
            || self.evidence_digest == [0; 32]
            || self.confirmation_depth != expected_depth
            || self.confirmation_depth < self.minimum_confirmations
            || self.canonical_tail.len() != expected_tail_len
            || self.canonical_tail.last().copied() != Some((self.tip_height, self.tip_hash))
        {
            return Err(RealDomError::InvalidEvidence);
        }
        for pair in self.canonical_tail.windows(2) {
            if pair[0].0.checked_add(1) != Some(pair[1].0)
                || pair[0].1 == [0; 32]
                || pair[1].1 == [0; 32]
            {
                return Err(RealDomError::InvalidEvidence);
            }
        }
        if self
            .canonical_tail
            .first()
            .is_some_and(|(_, hash)| *hash == [0; 32])
        {
            return Err(RealDomError::InvalidEvidence);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, RealDomError> {
        self.validate()?;
        let count =
            u16::try_from(self.canonical_tail.len()).map_err(|_| RealDomError::BoundsExceeded)?;
        let body_len = CHECKPOINT_FIXED_LEN
            .checked_add(
                self.canonical_tail
                    .len()
                    .checked_mul(CHECKPOINT_ENTRY_LEN)
                    .ok_or(RealDomError::BoundsExceeded)?,
            )
            .ok_or(RealDomError::BoundsExceeded)?;
        let mut bytes = Vec::with_capacity(
            body_len
                .checked_add(CHECKPOINT_DIGEST_LEN)
                .ok_or(RealDomError::BoundsExceeded)?,
        );
        bytes.extend_from_slice(CHECKPOINT_MAGIC);
        bytes.extend_from_slice(&CHECKPOINT_VERSION.to_be_bytes());
        bytes.push(self.kind as u8);
        bytes.push(0);
        bytes.extend_from_slice(&self.tx_hash);
        bytes.extend_from_slice(&self.block_height.to_be_bytes());
        bytes.extend_from_slice(&self.block_hash);
        bytes.extend_from_slice(&self.transaction_index.to_be_bytes());
        bytes.extend_from_slice(&self.tip_height.to_be_bytes());
        bytes.extend_from_slice(&self.tip_hash);
        bytes.extend_from_slice(&self.confirmation_depth.to_be_bytes());
        bytes.extend_from_slice(&self.minimum_confirmations.to_be_bytes());
        bytes.extend_from_slice(&self.max_reorg_depth.to_be_bytes());
        bytes.extend_from_slice(&self.evidence_digest);
        bytes.extend_from_slice(&count.to_be_bytes());
        for (height, hash) in &self.canonical_tail {
            bytes.extend_from_slice(&height.to_be_bytes());
            bytes.extend_from_slice(hash);
        }
        let checksum = checkpoint_digest(&bytes);
        bytes.extend_from_slice(&checksum);
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, RealDomError> {
        if bytes.len() < CHECKPOINT_FIXED_LEN + CHECKPOINT_DIGEST_LEN
            || &bytes[..8] != CHECKPOINT_MAGIC
            || u16::from_be_bytes([bytes[8], bytes[9]]) != CHECKPOINT_VERSION
            || bytes[11] != 0
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let count_offset = CHECKPOINT_FIXED_LEN - 2;
        let count = usize::from(u16::from_be_bytes([
            bytes[count_offset],
            bytes[count_offset + 1],
        ]));
        if count > MAX_CURSOR_HISTORY {
            return Err(RealDomError::BoundsExceeded);
        }
        let expected_len = CHECKPOINT_FIXED_LEN
            .checked_add(
                count
                    .checked_mul(CHECKPOINT_ENTRY_LEN)
                    .ok_or(RealDomError::BoundsExceeded)?,
            )
            .and_then(|length| length.checked_add(CHECKPOINT_DIGEST_LEN))
            .ok_or(RealDomError::BoundsExceeded)?;
        if bytes.len() != expected_len {
            return Err(RealDomError::InvalidEvidence);
        }
        let checksum_offset = expected_len - CHECKPOINT_DIGEST_LEN;
        if checkpoint_digest(&bytes[..checksum_offset]) != bytes[checksum_offset..] {
            return Err(RealDomError::InvalidEvidence);
        }
        let mut reader = CheckpointReaderV1::new(&bytes[12..count_offset]);
        let checkpoint = Self {
            kind: TerminalKindV1::decode(bytes[10])?,
            tx_hash: reader.array::<32>()?,
            block_height: reader.u64()?,
            block_hash: reader.array::<32>()?,
            transaction_index: reader.u32()?,
            tip_height: reader.u64()?,
            tip_hash: reader.array::<32>()?,
            confirmation_depth: reader.u32()?,
            minimum_confirmations: reader.u32()?,
            max_reorg_depth: reader.u32()?,
            evidence_digest: reader.array::<32>()?,
            canonical_tail: decode_tail(&bytes[CHECKPOINT_FIXED_LEN..checksum_offset], count)?,
        };
        if !reader.finished() {
            return Err(RealDomError::InvalidEvidence);
        }
        checkpoint.validate()?;
        Ok(checkpoint)
    }
}

struct CheckpointReaderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CheckpointReaderV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RealDomError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(RealDomError::BoundsExceeded)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RealDomError::InvalidEvidence)?
            .try_into()
            .map_err(|_| RealDomError::InvalidEvidence)?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> Result<u32, RealDomError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, RealDomError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn decode_tail(bytes: &[u8], count: usize) -> Result<Vec<(u64, [u8; 32])>, RealDomError> {
    if bytes.len()
        != count
            .checked_mul(CHECKPOINT_ENTRY_LEN)
            .ok_or(RealDomError::BoundsExceeded)?
    {
        return Err(RealDomError::InvalidEvidence);
    }
    let mut tail = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(CHECKPOINT_ENTRY_LEN) {
        let height = u64::from_be_bytes(
            chunk[..8]
                .try_into()
                .map_err(|_| RealDomError::InvalidEvidence)?,
        );
        let hash = chunk[8..]
            .try_into()
            .map_err(|_| RealDomError::InvalidEvidence)?;
        tail.push((height, hash));
    }
    Ok(tail)
}

fn checkpoint_digest(bytes: &[u8]) -> [u8; 32] {
    digest_parts(CHECKPOINT_DOMAIN, &[bytes])
}

fn validate_finality_policy(
    minimum_confirmations: u32,
    max_reorg_depth: u32,
) -> Result<(), RealDomError> {
    let history_required = max_reorg_depth
        .checked_add(1)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(RealDomError::FinalityPolicyInvalid)?;
    if minimum_confirmations == 0
        || max_reorg_depth < minimum_confirmations
        || history_required > MAX_CURSOR_HISTORY
    {
        return Err(RealDomError::FinalityPolicyInvalid);
    }
    Ok(())
}

fn validate_checkpoint_scope(
    checkpoint: &TerminalCheckpointV1,
    expected_kind: TerminalKindV1,
    expected_tx_hash: [u8; 32],
    minimum_confirmations: u32,
    max_reorg_depth: u32,
) -> Result<(), RealDomError> {
    validate_finality_policy(minimum_confirmations, max_reorg_depth)?;
    if checkpoint.kind != expected_kind
        || checkpoint.tx_hash != expected_tx_hash
        || checkpoint.minimum_confirmations != minimum_confirmations
        || checkpoint.max_reorg_depth != max_reorg_depth
    {
        return Err(RealDomError::InvalidEvidence);
    }
    Ok(())
}

fn capture_tail(
    state: &CursorStateV1,
    tip_height: u64,
    max_reorg_depth: u32,
) -> Result<Vec<(u64, [u8; 32])>, RealDomError> {
    let required = usize::try_from(
        u64::from(max_reorg_depth)
            .checked_add(1)
            .ok_or(RealDomError::BoundsExceeded)?
            .min(
                tip_height
                    .checked_add(1)
                    .ok_or(RealDomError::BoundsExceeded)?,
            ),
    )
    .map_err(|_| RealDomError::BoundsExceeded)?;
    if state.history.len() < required {
        return Err(RealDomError::FinalityPolicyInvalid);
    }
    Ok(state.history[state.history.len() - required..].to_vec())
}

#[derive(Clone)]
struct CanonicalTerminalSnapshotV1 {
    transaction: CanonicalTransactionEvidenceV1,
    state: CursorStateV1,
    identity: ObservedDomIdentityV1,
    block_time_seconds: u64,
}

impl RealDomRpcRuntimeV1 {
    /// Frozen chain identity enforced by every finality and reorg observation.
    #[must_use]
    pub fn expected_identity(&self) -> &dom_scriptless_chain_adapter::ExpectedDomIdentityV1 {
        self.adapter.expected_identity()
    }

    fn canonical_terminal_snapshot(
        &self,
        evidence: &EvidenceRefV1,
    ) -> Result<CanonicalTerminalSnapshotV1, RealDomError> {
        let resolve_mode = self.validate_evidence_scope(evidence)?;
        let anchor_height = if resolve_mode {
            0
        } else {
            evidence.block_height
        };
        let (state, identity) = self.scan_through_with_tip(anchor_height)?;
        let (state, identity) = self.scan_snapshot_to_tip(state, identity)?;
        let transaction = self.cached_transaction_on_walked_chain(&evidence.tx_id, &identity)?;
        let transaction = if resolve_mode {
            transaction
        } else {
            validate_evidence_reference(evidence, transaction)?
        };
        let cache = self.cache()?;
        let block_time_seconds = authenticated_block_time(
            &cache.blocks,
            transaction.location().block_height(),
            transaction.location().block_hash(),
        )?;
        drop(cache);
        Ok(CanonicalTerminalSnapshotV1 {
            transaction,
            state,
            identity,
            block_time_seconds,
        })
    }

    fn terminal_checkpoint(
        &self,
        kind: TerminalKindV1,
        snapshot: &CanonicalTerminalSnapshotV1,
        minimum_confirmations: u32,
        max_reorg_depth: u32,
        evidence_digest: [u8; 32],
    ) -> Result<(TerminalCheckpointV1, Vec<u8>), RealDomError> {
        validate_finality_policy(minimum_confirmations, max_reorg_depth)?;
        let required_history = usize::try_from(max_reorg_depth)
            .ok()
            .and_then(|depth| depth.checked_add(1))
            .ok_or(RealDomError::FinalityPolicyInvalid)?;
        if self.history_limit < required_history {
            return Err(RealDomError::FinalityPolicyInvalid);
        }
        let depth = snapshot
            .identity
            .tip_height
            .checked_sub(snapshot.transaction.location().block_height())
            .and_then(|distance| distance.checked_add(1))
            .and_then(|depth| u32::try_from(depth).ok())
            .ok_or(RealDomError::InvalidEvidence)?;
        if depth < minimum_confirmations {
            return Err(RealDomError::InsufficientConfirmations);
        }
        let checkpoint = TerminalCheckpointV1 {
            kind,
            tx_hash: snapshot.transaction.tx_hash(),
            block_height: snapshot.transaction.location().block_height(),
            block_hash: snapshot.transaction.location().block_hash(),
            transaction_index: snapshot.transaction.location().transaction_index(),
            tip_height: snapshot.identity.tip_height,
            tip_hash: snapshot.identity.tip_hash,
            confirmation_depth: depth,
            minimum_confirmations,
            max_reorg_depth,
            evidence_digest,
            canonical_tail: capture_tail(
                &snapshot.state,
                snapshot.identity.tip_height,
                max_reorg_depth,
            )?,
        };
        let bytes = checkpoint.encode()?;
        Ok((checkpoint, bytes))
    }

    /// Verify exact funding inclusion and persistable reorg ancestry in one snapshot.
    ///
    /// A zero block location is resolve mode: the authenticated scanner locates
    /// the exact transaction on the branch it walks through the reported tip.
    /// Absence and insufficient depth remain retryable classifications; a
    /// mismatched transaction or shared output is definitive invalid evidence.
    pub fn verified_funding_finality(
        &self,
        evidence: &EvidenceRefV1,
        expected_tx_hash: [u8; 32],
        expected_shared_output_commitment: [u8; 33],
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<VerifiedDomFundingFinalityV1, RealDomError> {
        validate_finality_policy(minimum_confirmations, max_reorg_depth)?;
        if expected_tx_hash == [0; 32] || expected_shared_output_commitment == [0; 33] {
            return Err(RealDomError::InvalidEvidence);
        }
        let snapshot = self.canonical_terminal_snapshot(evidence)?;
        let created = snapshot
            .transaction
            .transaction()
            .outputs
            .iter()
            .filter(|output| output.commitment.as_bytes() == &expected_shared_output_commitment)
            .count();
        if snapshot.transaction.tx_hash() != expected_tx_hash
            || created != 1
            || snapshot
                .transaction
                .spends_commitment(&expected_shared_output_commitment)
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let evidence_digest = digest_parts(
            FUNDING_FINALITY_DOMAIN,
            &[
                &expected_tx_hash,
                &expected_shared_output_commitment,
                &snapshot.transaction.location().block_height().to_be_bytes(),
                &snapshot.transaction.location().block_hash(),
                &snapshot
                    .transaction
                    .location()
                    .transaction_index()
                    .to_be_bytes(),
                &snapshot.block_time_seconds.to_be_bytes(),
                &snapshot.identity.tip_height.to_be_bytes(),
                &snapshot.identity.tip_hash,
                &minimum_confirmations.to_be_bytes(),
                &max_reorg_depth.to_be_bytes(),
            ],
        );
        let (checkpoint, checkpoint_bytes) = self.terminal_checkpoint(
            TerminalKindV1::Funding,
            &snapshot,
            minimum_confirmations,
            max_reorg_depth,
            evidence_digest,
        )?;
        Ok(VerifiedDomFundingFinalityV1 {
            checkpoint,
            checkpoint_bytes,
            block_time_seconds: snapshot.block_time_seconds,
            shared_output_commitment: expected_shared_output_commitment,
        })
    }

    /// Verify exact claim inclusion and authenticated depth in one anchored snapshot.
    #[allow(clippy::too_many_arguments)]
    pub fn verified_claim_finality(
        &self,
        verifier: &RealDomClaimVerifierV1,
        evidence: &EvidenceRefV1,
        expected_tx_hash: [u8; 32],
        expected_template_hash: [u8; 32],
        expected_shared_output_commitment: [u8; 33],
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<VerifiedDomClaimFinalityV1, RealDomError> {
        validate_finality_policy(minimum_confirmations, max_reorg_depth)?;
        if expected_tx_hash == [0; 32]
            || expected_template_hash == [0; 32]
            || expected_shared_output_commitment == [0; 33]
            || verifier.contract.chain_id.0 != self.adapter.expected_identity().chain_id
            || verifier.contract.claim_template_hash != expected_template_hash
            || verifier.contract.shared_output_commitment != expected_shared_output_commitment
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let snapshot = self.canonical_terminal_snapshot(evidence)?;
        if snapshot.transaction.tx_hash() != expected_tx_hash
            || snapshot.transaction.template_hash()? != expected_template_hash
            || !snapshot
                .transaction
                .spends_commitment(&expected_shared_output_commitment)
        {
            return Err(RealDomError::InvalidEvidence);
        }
        // This is the real adaptor verifier. The extracted scalar is already
        // public on chain and is deliberately dropped at this finality boundary.
        let _verified_public_scalar = verifier.verify_and_extract(&snapshot.transaction)?;
        let evidence_digest = digest_parts(
            CLAIM_FINALITY_DOMAIN,
            &[
                &expected_tx_hash,
                &expected_template_hash,
                &expected_shared_output_commitment,
                &snapshot.transaction.location().block_height().to_be_bytes(),
                &snapshot.transaction.location().block_hash(),
                &snapshot
                    .transaction
                    .location()
                    .transaction_index()
                    .to_be_bytes(),
                &snapshot.block_time_seconds.to_be_bytes(),
                &snapshot.identity.tip_height.to_be_bytes(),
                &snapshot.identity.tip_hash,
                &minimum_confirmations.to_be_bytes(),
                &max_reorg_depth.to_be_bytes(),
            ],
        );
        let (checkpoint, checkpoint_bytes) = self.terminal_checkpoint(
            TerminalKindV1::Claim,
            &snapshot,
            minimum_confirmations,
            max_reorg_depth,
            evidence_digest,
        )?;
        Ok(VerifiedDomClaimFinalityV1 {
            checkpoint,
            checkpoint_bytes,
            block_time_seconds: snapshot.block_time_seconds,
        })
    }

    /// Verify exact retained refund inclusion and authenticated finality depth.
    pub fn verified_contracts_refund_finality(
        &self,
        store: &ContractsSessionStoreV1,
        session_id: [u8; 32],
        evidence: &EvidenceRefV1,
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<VerifiedDomRefundFinalityV1, RealDomError> {
        validate_finality_policy(minimum_confirmations, max_reorg_depth)?;
        if session_id == [0; 32] {
            return Err(RealDomError::InvalidEvidence);
        }
        let snapshot = self.canonical_terminal_snapshot(evidence)?;
        let canonical = CanonicalDomTransactionEvidenceV1 {
            evidence: snapshot.transaction.clone(),
            block_time_seconds: snapshot.block_time_seconds,
        };
        let contracts =
            store.authenticate_persisted_refund(session_id, canonical.canonical_bytes())?;
        if contracts.session_id() != &session_id
            || contracts.transaction_hash() != &canonical.tx_hash()
        {
            return Err(RealDomError::InvalidEvidence);
        }
        let refund_digest = digest_parts(
            REFUND_EVIDENCE_DOMAIN,
            &[
                contracts.session_id(),
                contracts.transaction_hash(),
                contracts.exact_bytes_digest(),
                contracts.funding_artifact_digest(),
                contracts.funding_consumption_digest(),
                contracts.funding_broadcast_record_digest(),
                contracts.refund_phase_record_digest(),
                &canonical.block_hash(),
                &canonical.block_height().to_be_bytes(),
                &canonical.block_time_seconds().to_be_bytes(),
                &canonical.transaction_index().to_be_bytes(),
            ],
        );
        let refund = VerifiedDomRefundEvidenceV1 {
            canonical,
            contracts,
            evidence_digest: refund_digest,
        };
        let evidence_digest = digest_parts(
            REFUND_FINALITY_DOMAIN,
            &[
                &refund.evidence_digest(),
                &snapshot.identity.tip_height.to_be_bytes(),
                &snapshot.identity.tip_hash,
                &minimum_confirmations.to_be_bytes(),
                &max_reorg_depth.to_be_bytes(),
            ],
        );
        let (checkpoint, checkpoint_bytes) = self.terminal_checkpoint(
            TerminalKindV1::Refund,
            &snapshot,
            minimum_confirmations,
            max_reorg_depth,
            evidence_digest,
        )?;
        Ok(VerifiedDomRefundFinalityV1 {
            refund,
            checkpoint,
            checkpoint_bytes,
        })
    }

    /// Prove that a previously final exact funding transaction left the canonical chain.
    pub fn verified_funding_reorg(
        &self,
        checkpoint_bytes: &[u8],
        expected_tx_hash: [u8; 32],
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<VerifiedDomFundingReorgV1, RealDomError> {
        let reorg = self.verified_terminal_reorg(
            checkpoint_bytes,
            TerminalKindV1::Funding,
            expected_tx_hash,
            minimum_confirmations,
            max_reorg_depth,
        )?;
        Ok(VerifiedDomFundingReorgV1 { reorg })
    }

    /// Prove that a previously final exact claim left the canonical chain.
    pub fn verified_claim_reorg(
        &self,
        checkpoint_bytes: &[u8],
        expected_tx_hash: [u8; 32],
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<VerifiedDomClaimReorgV1, RealDomError> {
        let reorg = self.verified_terminal_reorg(
            checkpoint_bytes,
            TerminalKindV1::Claim,
            expected_tx_hash,
            minimum_confirmations,
            max_reorg_depth,
        )?;
        Ok(VerifiedDomClaimReorgV1 { reorg })
    }

    /// Prove that a previously final exact refund left the canonical chain.
    pub fn verified_refund_reorg(
        &self,
        checkpoint_bytes: &[u8],
        expected_tx_hash: [u8; 32],
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<VerifiedDomRefundReorgV1, RealDomError> {
        let reorg = self.verified_terminal_reorg(
            checkpoint_bytes,
            TerminalKindV1::Refund,
            expected_tx_hash,
            minimum_confirmations,
            max_reorg_depth,
        )?;
        Ok(VerifiedDomRefundReorgV1 { reorg })
    }

    fn verified_terminal_reorg(
        &self,
        checkpoint_bytes: &[u8],
        expected_kind: TerminalKindV1,
        expected_tx_hash: [u8; 32],
        minimum_confirmations: u32,
        max_reorg_depth: u32,
    ) -> Result<TerminalReorgV1, RealDomError> {
        let checkpoint = TerminalCheckpointV1::decode(checkpoint_bytes)?;
        validate_checkpoint_scope(
            &checkpoint,
            expected_kind,
            expected_tx_hash,
            minimum_confirmations,
            max_reorg_depth,
        )?;
        let (state, identity) = self.scan_through_with_tip(0)?;
        let (_, identity) = self.scan_snapshot_to_tip(state, identity)?;
        let mut cache = self.cache()?;
        cache
            .blocks
            .retain(|height, _| *height <= identity.tip_height);
        let canonical_blocks = cache.blocks.clone();
        cache.transactions.retain(|_, transaction| {
            transaction.location().block_height() <= identity.tip_height
                && canonical_blocks
                    .get(&transaction.location().block_height())
                    .is_some_and(|(hash, _)| hash == &transaction.location().block_hash())
        });
        let current_transaction_location = cache
            .transactions
            .get(&expected_tx_hash)
            .map(|tx| (tx.location().block_height(), tx.location().block_hash()));
        let reorg = verify_reorg_against_canonical(
            &checkpoint,
            &cache.blocks,
            identity.tip_height,
            identity.tip_hash,
            current_transaction_location,
            checkpoint_digest(checkpoint_bytes),
        )?;
        Ok(reorg)
    }
}

fn verify_reorg_against_canonical(
    checkpoint: &TerminalCheckpointV1,
    canonical_blocks: &BTreeMap<u64, ([u8; 32], u64)>,
    current_tip_height: u64,
    current_tip_hash: [u8; 32],
    current_transaction_location: Option<(u64, [u8; 32])>,
    retained_checkpoint_digest: [u8; 32],
) -> Result<TerminalReorgV1, RealDomError> {
    if current_tip_hash == [0; 32]
        || canonical_blocks
            .get(&current_tip_height)
            .map(|entry| entry.0)
            != Some(current_tip_hash)
    {
        return Err(RealDomError::InvalidEvidence);
    }
    match current_transaction_location {
        Some((height, hash))
            if height == checkpoint.block_height && hash == checkpoint.block_hash =>
        {
            let current_depth = current_tip_height
                .checked_sub(height)
                .and_then(|distance| distance.checked_add(1))
                .and_then(|depth| u32::try_from(depth).ok())
                .ok_or(RealDomError::InvalidEvidence)?;
            if current_depth < checkpoint.minimum_confirmations {
                return Err(RealDomError::InsufficientConfirmations);
            }
            return Err(RealDomError::TransactionStillCanonical);
        }
        Some(_) => {
            // The same transaction was re-included on the replacement branch.
            // Its old checkpoint is invalid even if the new inclusion is
            // already deep enough; callers must obtain and persist a new
            // finality proof for the new block locator.
        }
        None if canonical_blocks
            .get(&checkpoint.block_height)
            .is_some_and(|(hash, _)| hash == &checkpoint.block_hash) =>
        {
            // The scanner cannot omit a transaction while claiming the exact
            // same canonical block. Treat this as inconsistent evidence, not
            // a reorg.
            return Err(RealDomError::InvalidEvidence);
        }
        None => {}
    }
    let (common_ancestor_height, common_ancestor_hash) = checkpoint
        .canonical_tail
        .iter()
        .rev()
        .find(|(height, hash)| {
            *height <= current_tip_height
                && canonical_blocks
                    .get(height)
                    .is_some_and(|(current, _)| current == hash)
        })
        .copied()
        .ok_or(RealDomError::ReorgBeyondPolicy)?;
    let removed_depth = checkpoint
        .tip_height
        .checked_sub(common_ancestor_height)
        .and_then(|depth| u32::try_from(depth).ok())
        .ok_or(RealDomError::InvalidEvidence)?;
    if removed_depth == 0 || removed_depth > checkpoint.max_reorg_depth {
        return Err(RealDomError::ReorgBeyondPolicy);
    }
    let (reinclusion_tag, reinclusion_height, reinclusion_hash) = match current_transaction_location
    {
        Some((height, hash)) => ([1_u8], height, hash),
        None => ([0_u8], 0, [0; 32]),
    };
    let evidence_digest = digest_parts(
        REORG_DOMAIN,
        &[
            &[checkpoint.kind as u8],
            &checkpoint.tx_hash,
            &retained_checkpoint_digest,
            &checkpoint.tip_height.to_be_bytes(),
            &checkpoint.tip_hash,
            &current_tip_height.to_be_bytes(),
            &current_tip_hash,
            &common_ancestor_height.to_be_bytes(),
            &common_ancestor_hash,
            &removed_depth.to_be_bytes(),
            &reinclusion_tag,
            &reinclusion_height.to_be_bytes(),
            &reinclusion_hash,
            &checkpoint.minimum_confirmations.to_be_bytes(),
            &checkpoint.max_reorg_depth.to_be_bytes(),
        ],
    );
    Ok(TerminalReorgV1 {
        tx_hash: checkpoint.tx_hash,
        prior_evidence_digest: checkpoint.evidence_digest,
        prior_block_height: checkpoint.block_height,
        prior_block_hash: checkpoint.block_hash,
        current_tip_height,
        current_tip_hash,
        common_ancestor_height,
        common_ancestor_hash,
        removed_depth,
        minimum_confirmations: checkpoint.minimum_confirmations,
        max_reorg_depth: checkpoint.max_reorg_depth,
        evidence_digest,
    })
}

/// Opaque proof that exact DOM funding reached authenticated finality.
pub struct VerifiedDomFundingFinalityV1 {
    checkpoint: TerminalCheckpointV1,
    checkpoint_bytes: Vec<u8>,
    block_time_seconds: u64,
    shared_output_commitment: [u8; 33],
}

/// Opaque proof that the exact DOM claim reached authenticated finality.
pub struct VerifiedDomClaimFinalityV1 {
    checkpoint: TerminalCheckpointV1,
    checkpoint_bytes: Vec<u8>,
    block_time_seconds: u64,
}

/// Opaque proof that the exact retained DOM refund reached authenticated finality.
pub struct VerifiedDomRefundFinalityV1 {
    refund: VerifiedDomRefundEvidenceV1,
    checkpoint: TerminalCheckpointV1,
    checkpoint_bytes: Vec<u8>,
}

macro_rules! finality_accessors {
    ($type:ty) => {
        impl $type {
            /// Exact canonical terminal transaction identity.
            #[must_use]
            pub const fn tx_hash(&self) -> [u8; 32] {
                self.checkpoint.tx_hash
            }

            /// Canonical containing-block height.
            #[must_use]
            pub const fn block_height(&self) -> u64 {
                self.checkpoint.block_height
            }

            /// Canonical containing-block hash.
            #[must_use]
            pub const fn block_hash(&self) -> [u8; 32] {
                self.checkpoint.block_hash
            }

            /// Zero-based position of the transaction in its canonical block.
            #[must_use]
            pub const fn transaction_index(&self) -> u32 {
                self.checkpoint.transaction_index
            }

            /// Snapshot tip height used for finality.
            #[must_use]
            pub const fn observed_tip_height(&self) -> u64 {
                self.checkpoint.tip_height
            }

            /// Snapshot tip hash used for finality.
            #[must_use]
            pub const fn observed_tip_hash(&self) -> [u8; 32] {
                self.checkpoint.tip_hash
            }

            /// Canonical confirmation depth at the snapshot tip.
            #[must_use]
            pub const fn confirmation_depth(&self) -> u32 {
                self.checkpoint.confirmation_depth
            }

            /// Frozen minimum confirmation policy.
            #[must_use]
            pub const fn minimum_confirmations(&self) -> u32 {
                self.checkpoint.minimum_confirmations
            }

            /// Frozen maximum reorg recovery policy.
            #[must_use]
            pub const fn max_reorg_depth(&self) -> u32 {
                self.checkpoint.max_reorg_depth
            }

            /// Domain-separated digest of all authenticated public evidence.
            #[must_use]
            pub const fn evidence_digest(&self) -> [u8; 32] {
                self.checkpoint.evidence_digest
            }

            /// Bounded authenticated checkpoint for owner-only restart recovery.
            ///
            /// These bytes contain only public block hashes and terminal
            /// transaction identity; they contain no transaction bytes or scalar.
            #[must_use]
            pub fn recovery_checkpoint(&self) -> &[u8] {
                &self.checkpoint_bytes
            }
        }
    };
}

finality_accessors!(VerifiedDomFundingFinalityV1);
finality_accessors!(VerifiedDomClaimFinalityV1);
finality_accessors!(VerifiedDomRefundFinalityV1);

impl VerifiedDomFundingFinalityV1 {
    /// Timestamp authenticated by the exact canonical containing header.
    #[must_use]
    pub const fn block_time_seconds(&self) -> u64 {
        self.block_time_seconds
    }

    /// Exact shared output proven to occur once in the funding transaction.
    #[must_use]
    pub const fn shared_output_commitment(&self) -> [u8; 33] {
        self.shared_output_commitment
    }
}

impl VerifiedDomClaimFinalityV1 {
    /// Timestamp authenticated by the exact canonical containing header.
    #[must_use]
    pub const fn block_time_seconds(&self) -> u64 {
        self.block_time_seconds
    }
}

impl VerifiedDomRefundFinalityV1 {
    /// Contracts session owning the exact pre-authorized refund.
    #[must_use]
    pub const fn session_id(&self) -> [u8; 32] {
        self.refund.session_id()
    }
}

impl core::fmt::Debug for VerifiedDomFundingFinalityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedDomFundingFinalityV1")
            .field("tx_hash", &self.tx_hash())
            .field("block_height", &self.block_height())
            .field("confirmation_depth", &self.confirmation_depth())
            .field("recovery_checkpoint", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for VerifiedDomClaimFinalityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedDomClaimFinalityV1")
            .field("tx_hash", &self.tx_hash())
            .field("block_height", &self.block_height())
            .field("confirmation_depth", &self.confirmation_depth())
            .field("recovery_checkpoint", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for VerifiedDomRefundFinalityV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedDomRefundFinalityV1")
            .field("session_id", &self.session_id())
            .field("tx_hash", &self.tx_hash())
            .field("block_height", &self.block_height())
            .field("confirmation_depth", &self.confirmation_depth())
            .field("recovery_checkpoint", &"[redacted]")
            .finish_non_exhaustive()
    }
}

struct TerminalReorgV1 {
    tx_hash: [u8; 32],
    prior_evidence_digest: [u8; 32],
    prior_block_height: u64,
    prior_block_hash: [u8; 32],
    current_tip_height: u64,
    current_tip_hash: [u8; 32],
    common_ancestor_height: u64,
    common_ancestor_hash: [u8; 32],
    removed_depth: u32,
    minimum_confirmations: u32,
    max_reorg_depth: u32,
    evidence_digest: [u8; 32],
}

/// Opaque proof that previously final exact DOM funding was invalidated.
pub struct VerifiedDomFundingReorgV1 {
    reorg: TerminalReorgV1,
}

/// Opaque proof that a previously final exact DOM claim was invalidated.
pub struct VerifiedDomClaimReorgV1 {
    reorg: TerminalReorgV1,
}

/// Opaque proof that a previously final exact DOM refund was invalidated.
pub struct VerifiedDomRefundReorgV1 {
    reorg: TerminalReorgV1,
}

macro_rules! reorg_accessors {
    ($type:ty) => {
        impl $type {
            /// Exact terminal transaction invalidated by the fork.
            #[must_use]
            pub const fn tx_hash(&self) -> [u8; 32] {
                self.reorg.tx_hash
            }

            /// Digest of the finality evidence being invalidated.
            #[must_use]
            pub const fn prior_evidence_digest(&self) -> [u8; 32] {
                self.reorg.prior_evidence_digest
            }

            /// Canonical block height authenticated by the invalidated checkpoint.
            #[must_use]
            pub const fn prior_block_height(&self) -> u64 {
                self.reorg.prior_block_height
            }

            /// Canonical block hash authenticated by the invalidated checkpoint.
            #[must_use]
            pub const fn prior_block_hash(&self) -> [u8; 32] {
                self.reorg.prior_block_hash
            }

            /// New canonical tip height.
            #[must_use]
            pub const fn current_tip_height(&self) -> u64 {
                self.reorg.current_tip_height
            }

            /// New canonical tip hash.
            #[must_use]
            pub const fn current_tip_hash(&self) -> [u8; 32] {
                self.reorg.current_tip_hash
            }

            /// Highest authenticated ancestor shared by both branches.
            #[must_use]
            pub const fn common_ancestor_height(&self) -> u64 {
                self.reorg.common_ancestor_height
            }

            /// Exact canonical hash of the highest shared ancestor.
            #[must_use]
            pub const fn common_ancestor_hash(&self) -> [u8; 32] {
                self.reorg.common_ancestor_hash
            }

            /// Number of old canonical blocks removed above the ancestor.
            #[must_use]
            pub const fn removed_depth(&self) -> u32 {
                self.reorg.removed_depth
            }

            /// Frozen minimum confirmation policy.
            #[must_use]
            pub const fn minimum_confirmations(&self) -> u32 {
                self.reorg.minimum_confirmations
            }

            /// Frozen maximum reorg recovery policy.
            #[must_use]
            pub const fn max_reorg_depth(&self) -> u32 {
                self.reorg.max_reorg_depth
            }

            /// Domain-separated digest of the bounded fork proof.
            #[must_use]
            pub const fn evidence_digest(&self) -> [u8; 32] {
                self.reorg.evidence_digest
            }
        }
    };
}

reorg_accessors!(VerifiedDomFundingReorgV1);
reorg_accessors!(VerifiedDomClaimReorgV1);
reorg_accessors!(VerifiedDomRefundReorgV1);

impl core::fmt::Debug for VerifiedDomFundingReorgV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedDomFundingReorgV1")
            .field("tx_hash", &self.tx_hash())
            .field("removed_depth", &self.removed_depth())
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for VerifiedDomClaimReorgV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedDomClaimReorgV1")
            .field("tx_hash", &self.tx_hash())
            .field("removed_depth", &self.removed_depth())
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for VerifiedDomRefundReorgV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("VerifiedDomRefundReorgV1")
            .field("tx_hash", &self.tx_hash())
            .field("removed_depth", &self.removed_depth())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checkpoint() -> TerminalCheckpointV1 {
        TerminalCheckpointV1 {
            kind: TerminalKindV1::Claim,
            tx_hash: [0x11; 32],
            block_height: 8,
            block_hash: [0x18; 32],
            transaction_index: 2,
            tip_height: 10,
            tip_hash: [0x1a; 32],
            confirmation_depth: 3,
            minimum_confirmations: 2,
            max_reorg_depth: 3,
            evidence_digest: [0x44; 32],
            canonical_tail: vec![
                (7, [0x17; 32]),
                (8, [0x18; 32]),
                (9, [0x19; 32]),
                (10, [0x1a; 32]),
            ],
        }
    }

    #[test]
    fn checkpoint_roundtrip_refuses_tamper_and_policy_substitution() -> Result<(), RealDomError> {
        let checkpoint = checkpoint();
        let bytes = checkpoint.encode()?;
        assert!(TerminalCheckpointV1::decode(&bytes)? == checkpoint);
        let mut tampered = bytes.clone();
        tampered[48] ^= 1;
        assert!(matches!(
            TerminalCheckpointV1::decode(&tampered),
            Err(RealDomError::InvalidEvidence)
        ));
        let decoded = TerminalCheckpointV1::decode(&bytes)?;
        assert!(
            validate_checkpoint_scope(&decoded, TerminalKindV1::Claim, [0x11; 32], 2, 3).is_ok()
        );
        for substituted in [
            validate_checkpoint_scope(&decoded, TerminalKindV1::Refund, [0x11; 32], 2, 3),
            validate_checkpoint_scope(&decoded, TerminalKindV1::Claim, [0x12; 32], 2, 3),
            validate_checkpoint_scope(&decoded, TerminalKindV1::Claim, [0x11; 32], 3, 3),
            validate_checkpoint_scope(&decoded, TerminalKindV1::Claim, [0x11; 32], 2, 4),
        ] {
            assert!(matches!(substituted, Err(RealDomError::InvalidEvidence)));
        }
        Ok(())
    }

    #[test]
    fn funding_checkpoint_kind_cannot_be_replayed_as_a_terminal_kind() -> Result<(), RealDomError> {
        let mut funding = checkpoint();
        funding.kind = TerminalKindV1::Funding;
        let encoded = funding.encode()?;
        let decoded = TerminalCheckpointV1::decode(&encoded)?;
        assert!(validate_checkpoint_scope(
            &decoded,
            TerminalKindV1::Funding,
            funding.tx_hash,
            funding.minimum_confirmations,
            funding.max_reorg_depth,
        )
        .is_ok());
        for kind in [TerminalKindV1::Claim, TerminalKindV1::Refund] {
            assert!(matches!(
                validate_checkpoint_scope(
                    &decoded,
                    kind,
                    funding.tx_hash,
                    funding.minimum_confirmations,
                    funding.max_reorg_depth,
                ),
                Err(RealDomError::InvalidEvidence)
            ));
        }
        Ok(())
    }

    #[test]
    fn exact_location_rechecks_depth_and_reinclusion_invalidates_old_checkpoint(
    ) -> Result<(), RealDomError> {
        let same_chain = BTreeMap::from([
            (7, ([0x17; 32], 7)),
            (8, ([0x18; 32], 8)),
            (9, ([0x19; 32], 9)),
            (10, ([0x1a; 32], 10)),
        ]);
        let shallow = BTreeMap::from([(7, ([0x17; 32], 7)), (8, ([0x18; 32], 8))]);
        let replacement = BTreeMap::from([
            (7, ([0x17; 32], 7)),
            (8, ([0x28; 32], 8)),
            (9, ([0x29; 32], 9)),
            (10, ([0x2a; 32], 10)),
        ]);
        for kind in [
            TerminalKindV1::Funding,
            TerminalKindV1::Claim,
            TerminalKindV1::Refund,
        ] {
            let mut checkpoint = checkpoint();
            checkpoint.kind = kind;
            assert!(matches!(
                verify_reorg_against_canonical(
                    &checkpoint,
                    &same_chain,
                    10,
                    [0x1a; 32],
                    Some((8, [0x18; 32])),
                    [0x55; 32]
                ),
                Err(RealDomError::TransactionStillCanonical)
            ));
            assert!(matches!(
                verify_reorg_against_canonical(
                    &checkpoint,
                    &shallow,
                    8,
                    [0x18; 32],
                    Some((8, [0x18; 32])),
                    [0x55; 32]
                ),
                Err(RealDomError::InsufficientConfirmations)
            ));
            let reorg = verify_reorg_against_canonical(
                &checkpoint,
                &replacement,
                10,
                [0x2a; 32],
                Some((9, [0x29; 32])),
                [0x55; 32],
            )?;
            assert_eq!(reorg.prior_block_height, 8);
            assert_eq!(reorg.prior_block_hash, [0x18; 32]);
        }
        Ok(())
    }

    #[test]
    fn bounded_fork_proof_rejects_wrong_depth_and_accepts_exact_ancestor(
    ) -> Result<(), RealDomError> {
        let checkpoint = checkpoint();
        let within_policy = BTreeMap::from([
            (7, ([0x17; 32], 7)),
            (8, ([0x28; 32], 8)),
            (9, ([0x29; 32], 9)),
            (10, ([0x2a; 32], 10)),
        ]);
        let reorg = verify_reorg_against_canonical(
            &checkpoint,
            &within_policy,
            10,
            [0x2a; 32],
            None,
            [0x55; 32],
        )?;
        assert_eq!(reorg.common_ancestor_height, 7);
        assert_eq!(reorg.common_ancestor_hash, [0x17; 32]);
        assert_eq!(reorg.removed_depth, 3);

        let beyond_policy = BTreeMap::from([
            (7, ([0x27; 32], 7)),
            (8, ([0x28; 32], 8)),
            (9, ([0x29; 32], 9)),
            (10, ([0x2a; 32], 10)),
        ]);
        assert!(matches!(
            verify_reorg_against_canonical(
                &checkpoint,
                &beyond_policy,
                10,
                [0x2a; 32],
                None,
                [0x55; 32]
            ),
            Err(RealDomError::ReorgBeyondPolicy)
        ));
        Ok(())
    }

    #[test]
    fn finality_policy_and_depth_fail_closed() {
        assert!(matches!(
            validate_finality_policy(0, 3),
            Err(RealDomError::FinalityPolicyInvalid)
        ));
        assert!(matches!(
            validate_finality_policy(4, 3),
            Err(RealDomError::FinalityPolicyInvalid)
        ));
        assert!(matches!(
            validate_finality_policy(1, MAX_CURSOR_HISTORY as u32),
            Err(RealDomError::FinalityPolicyInvalid)
        ));
    }
}
