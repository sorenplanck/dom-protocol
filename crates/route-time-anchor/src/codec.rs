use adapter_btc::timelock::ChainTimingBoundsV1;
use kaystra_core::types::{ChainId, FinalityPolicyV1};

use crate::types::{
    CanonicalTimeCheckpointV2, CheckpointBindingV2, CheckpointRoleV2, ClockKindV2,
    RouteTimeEvidenceV2, RouteTimePolicyLimitsV2, RouteTimePolicyV2,
};
use crate::{Result, RouteTimeAnchorErrorV2, ROUTE_TIME_VERSION_V2};

const POLICY_MAGIC_V2: &[u8; 8] = b"DOMRTPV2";
const EVIDENCE_MAGIC_V2: &[u8; 8] = b"DOMRTEV2";
pub(crate) const MAX_POLICY_BYTES_V2: usize = 1_024;
pub(crate) const MAX_EVIDENCE_BYTES_V2: usize = 2_048;

pub(crate) fn encode_policy_v2(policy: &RouteTimePolicyV2) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(640);
    output.extend_from_slice(POLICY_MAGIC_V2);
    put_u16(&mut output, ROUTE_TIME_VERSION_V2);
    put_u16(&mut output, 0);
    output.extend_from_slice(&policy.network_id);
    output.extend_from_slice(&policy.registry_digest);
    put_u64(&mut output, policy.registry_epoch);
    output.extend_from_slice(&policy.upstream_terms_hash);
    output.extend_from_slice(&policy.downstream_terms_hash);
    output.extend_from_slice(&policy.route_scope_digest);
    put_limits(&mut output, policy.limits);
    for binding in &policy.checkpoints {
        put_binding(&mut output, *binding);
    }
    if output.len() > MAX_POLICY_BYTES_V2 {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    Ok(output)
}

pub(crate) fn decode_policy_v2(bytes: &[u8]) -> Result<RouteTimePolicyV2> {
    if bytes.len() > MAX_POLICY_BYTES_V2 {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    let mut reader = ReaderV2::new(bytes);
    if reader.take::<8>()? != *POLICY_MAGIC_V2
        || reader.u16()? != ROUTE_TIME_VERSION_V2
        || reader.u16()? != 0
    {
        return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
    }
    let value = RouteTimePolicyV2 {
        network_id: reader.take()?,
        registry_digest: reader.take()?,
        registry_epoch: reader.u64()?,
        upstream_terms_hash: reader.take()?,
        downstream_terms_hash: reader.take()?,
        route_scope_digest: reader.take()?,
        limits: take_limits(&mut reader)?,
        checkpoints: [
            take_binding(&mut reader)?,
            take_binding(&mut reader)?,
            take_binding(&mut reader)?,
        ],
    };
    reader.finish()?;
    Ok(value)
}

pub(crate) fn encode_evidence_v2(evidence: &RouteTimeEvidenceV2) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(1_024);
    output.extend_from_slice(EVIDENCE_MAGIC_V2);
    put_u16(&mut output, ROUTE_TIME_VERSION_V2);
    put_u16(&mut output, 0);
    output.extend_from_slice(&evidence.policy_digest);
    output.extend_from_slice(&evidence.route_scope_digest);
    put_u64(&mut output, evidence.sequence);
    put_u64(&mut output, evidence.observed_at_seconds);
    put_u64(&mut output, evidence.expires_at_seconds);
    for checkpoint in &evidence.checkpoints {
        put_checkpoint(&mut output, *checkpoint);
    }
    if output.len() > MAX_EVIDENCE_BYTES_V2 {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    Ok(output)
}

pub(crate) fn decode_evidence_v2(bytes: &[u8]) -> Result<RouteTimeEvidenceV2> {
    if bytes.len() > MAX_EVIDENCE_BYTES_V2 {
        return Err(RouteTimeAnchorErrorV2::BoundExceeded);
    }
    let mut reader = ReaderV2::new(bytes);
    if reader.take::<8>()? != *EVIDENCE_MAGIC_V2
        || reader.u16()? != ROUTE_TIME_VERSION_V2
        || reader.u16()? != 0
    {
        return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
    }
    let value = RouteTimeEvidenceV2 {
        policy_digest: reader.take()?,
        route_scope_digest: reader.take()?,
        sequence: reader.u64()?,
        observed_at_seconds: reader.u64()?,
        expires_at_seconds: reader.u64()?,
        checkpoints: [
            take_checkpoint(&mut reader)?,
            take_checkpoint(&mut reader)?,
            take_checkpoint(&mut reader)?,
        ],
    };
    reader.finish()?;
    Ok(value)
}

fn put_limits(output: &mut Vec<u8>, limits: RouteTimePolicyLimitsV2) {
    for value in [
        limits.valid_from_seconds,
        limits.expires_at_seconds,
        limits.max_evidence_age_seconds,
        limits.max_anchor_interval_width_seconds,
        limits.max_anchor_time_skew_seconds,
        limits.max_future_skew_seconds,
        limits.max_upstream_funding_anchor_delay_seconds,
        limits.max_downstream_funding_anchor_delay_seconds,
        limits.hub_margin_seconds,
        limits.counterparty_margin_seconds,
    ] {
        put_u64(output, value);
    }
}

fn take_limits(reader: &mut ReaderV2<'_>) -> Result<RouteTimePolicyLimitsV2> {
    Ok(RouteTimePolicyLimitsV2 {
        valid_from_seconds: reader.u64()?,
        expires_at_seconds: reader.u64()?,
        max_evidence_age_seconds: reader.u64()?,
        max_anchor_interval_width_seconds: reader.u64()?,
        max_anchor_time_skew_seconds: reader.u64()?,
        max_future_skew_seconds: reader.u64()?,
        max_upstream_funding_anchor_delay_seconds: reader.u64()?,
        max_downstream_funding_anchor_delay_seconds: reader.u64()?,
        hub_margin_seconds: reader.u64()?,
        counterparty_margin_seconds: reader.u64()?,
    })
}

fn put_binding(output: &mut Vec<u8>, binding: CheckpointBindingV2) {
    output.push(binding.role as u8);
    output.push(binding.clock_kind as u8);
    put_u16(output, 0);
    output.extend_from_slice(&binding.chain_id.0);
    output.extend_from_slice(&binding.genesis_hash);
    output.extend_from_slice(&binding.profile_digest);
    put_timing(output, binding.timing);
    put_finality(output, binding.finality);
}

fn take_binding(reader: &mut ReaderV2<'_>) -> Result<CheckpointBindingV2> {
    let role = take_role(reader.u8()?)?;
    let clock_kind = take_clock(reader.u8()?)?;
    if reader.u16()? != 0 {
        return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
    }
    Ok(CheckpointBindingV2 {
        role,
        clock_kind,
        chain_id: ChainId(reader.take()?),
        genesis_hash: reader.take()?,
        profile_digest: reader.take()?,
        timing: take_timing(reader)?,
        finality: take_finality(reader)?,
    })
}

fn put_checkpoint(output: &mut Vec<u8>, checkpoint: CanonicalTimeCheckpointV2) {
    output.push(checkpoint.role as u8);
    output.push(checkpoint.clock_kind as u8);
    put_u16(output, 0);
    output.extend_from_slice(&checkpoint.chain_id.0);
    output.extend_from_slice(&checkpoint.genesis_hash);
    output.extend_from_slice(&checkpoint.profile_digest);
    put_u64(output, checkpoint.anchor_height);
    output.extend_from_slice(&checkpoint.anchor_hash);
    output.extend_from_slice(&checkpoint.parent_hash);
    put_u64(output, checkpoint.time_lower_seconds);
    put_u64(output, checkpoint.time_upper_seconds);
    put_u64(output, checkpoint.canonical_tip_height);
    output.extend_from_slice(&checkpoint.canonical_tip_hash);
    output.extend_from_slice(&checkpoint.canonicality_evidence_digest);
}

fn take_checkpoint(reader: &mut ReaderV2<'_>) -> Result<CanonicalTimeCheckpointV2> {
    let role = take_role(reader.u8()?)?;
    let clock_kind = take_clock(reader.u8()?)?;
    if reader.u16()? != 0 {
        return Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding);
    }
    Ok(CanonicalTimeCheckpointV2 {
        role,
        clock_kind,
        chain_id: ChainId(reader.take()?),
        genesis_hash: reader.take()?,
        profile_digest: reader.take()?,
        anchor_height: reader.u64()?,
        anchor_hash: reader.take()?,
        parent_hash: reader.take()?,
        time_lower_seconds: reader.u64()?,
        time_upper_seconds: reader.u64()?,
        canonical_tip_height: reader.u64()?,
        canonical_tip_hash: reader.take()?,
        canonicality_evidence_digest: reader.take()?,
    })
}

fn put_timing(output: &mut Vec<u8>, timing: ChainTimingBoundsV1) {
    for value in [
        timing.min_block_seconds,
        timing.max_block_seconds,
        timing.max_reorg_seconds,
        timing.observation_seconds,
        timing.broadcast_seconds,
    ] {
        put_u32(output, value);
    }
}

fn take_timing(reader: &mut ReaderV2<'_>) -> Result<ChainTimingBoundsV1> {
    Ok(ChainTimingBoundsV1 {
        min_block_seconds: reader.u32()?,
        max_block_seconds: reader.u32()?,
        max_reorg_seconds: reader.u32()?,
        observation_seconds: reader.u32()?,
        broadcast_seconds: reader.u32()?,
    })
}

fn put_finality(output: &mut Vec<u8>, finality: FinalityPolicyV1) {
    put_u32(output, finality.min_confirmations);
    put_u32(output, finality.max_reorg_depth);
}

fn take_finality(reader: &mut ReaderV2<'_>) -> Result<FinalityPolicyV1> {
    Ok(FinalityPolicyV1 {
        min_confirmations: reader.u32()?,
        max_reorg_depth: reader.u32()?,
    })
}

fn take_role(value: u8) -> Result<CheckpointRoleV2> {
    match value {
        1 => Ok(CheckpointRoleV2::Hub),
        2 => Ok(CheckpointRoleV2::UpstreamCounterparty),
        3 => Ok(CheckpointRoleV2::DownstreamCounterparty),
        _ => Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding),
    }
}

fn take_clock(value: u8) -> Result<ClockKindV2> {
    match value {
        1 => Ok(ClockKindV2::DomHeight),
        2 => Ok(ClockKindV2::EvmTimestamp),
        3 => Ok(ClockKindV2::Bitcoin),
        4 => Ok(ClockKindV2::Monero),
        5 => Ok(ClockKindV2::Solana),
        _ => Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding),
    }
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

struct ReaderV2<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> ReaderV2<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(RouteTimeAnchorErrorV2::Overflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(RouteTimeAnchorErrorV2::NonCanonicalEncoding)?;
        self.position = end;
        Ok(value)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| RouteTimeAnchorErrorV2::NonCanonicalEncoding)
    }

    fn u8(&mut self) -> Result<u8> {
        self.bytes(1)?
            .first()
            .copied()
            .ok_or(RouteTimeAnchorErrorV2::NonCanonicalEncoding)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn finish(self) -> Result<()> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(RouteTimeAnchorErrorV2::NonCanonicalEncoding)
        }
    }
}
