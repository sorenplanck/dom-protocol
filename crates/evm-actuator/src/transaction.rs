use adapter_evm::{
    abi::{
        decode_address, decode_u64, decode_u8, selector, split_words, SIG_CLAIM, SIG_OPEN,
        SIG_REFUND,
    },
    derive_binding, derive_lock_id, keccak256, LockTerms, UnsignedEvmCall,
};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use deployment_registry::{AssetRepresentationV1, ResolvedEvmDeploymentV1};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::model::{
    Digest32, Eip1559SignatureV1, EvmAddressV1, EvmClaimSecretV1, EvmFeesV1, EvmOperationKindV1,
    EvmSignerRoleV1, RemoteEvmActionRequestInputV1, RemoteEvmActionRequestV1, ScopedEvmClaimV1,
    ScopedEvmOpenV1, ScopedEvmRefundV1, ValidatedEvmLockV1, ZERO_ADDRESS, ZERO_DIGEST,
};
use crate::{EvmActuatorErrorV1, Result};
use zeroize::Zeroizing;

const TYPE_2: u8 = 0x02;
const UNSIGNED_CALL_VERSION_V1: u16 = 1;
const OPEN_CALLDATA_LEN: usize = 4 + 10 * 32;
pub(crate) const CLAIM_CALLDATA_LEN: usize = 4 + 2 * 32;
pub(crate) const REFUND_CALLDATA_LEN: usize = 4 + 32;
pub(crate) const MAX_RAW_TRANSACTION_BYTES_V1: usize = 8 * 1024;
const REMOTE_RAW_TAG_V1: &str = "DOM:evm-signed-action-raw:v1";

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct Eip1559FieldsV1 {
    pub chain_id: u64,
    pub nonce: u64,
    pub fees: EvmFeesV1,
    pub gas_limit: u64,
    pub to: EvmAddressV1,
    pub value: [u8; 32],
    pub calldata: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for Eip1559FieldsV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Eip1559FieldsV1")
            .field("chain_id", &self.chain_id)
            .field("nonce", &self.nonce)
            .field("fees", &self.fees)
            .field("gas_limit", &self.gas_limit)
            .field("to", &self.to)
            .field("value", &self.value)
            .field("calldata_digest", &keccak256(&self.calldata))
            .finish()
    }
}

pub(crate) struct DecodedRemoteEip1559V1 {
    pub fields: Eip1559FieldsV1,
    pub signature: Eip1559SignatureV1,
    pub transaction_hash: Digest32,
    pub signed_raw_digest: Digest32,
}

pub(crate) fn validate_remote_action_request(
    input: RemoteEvmActionRequestInputV1,
) -> Result<RemoteEvmActionRequestV1> {
    let expected_role = match input.kind {
        EvmOperationKindV1::Open | EvmOperationKindV1::Refund => EvmSignerRoleV1::Funder,
        EvmOperationKindV1::Claim => EvmSignerRoleV1::Beneficiary,
    };
    if input.role != expected_role
        || input.owner_epoch == 0
        || input.chain_id == 0
        || input.contract == ZERO_ADDRESS
        || input.signer_account == ZERO_ADDRESS
        || input.requester_id == input.signer_id
        || [
            input.owner_id,
            input.action_id,
            input.route_id,
            input.settlement_id,
            input.composition_binding_digest,
            input.execution_plan_digest,
            input.unsigned_call_digest,
            input.request_message_digest,
            input.requester_id,
            input.signer_id,
        ]
        .contains(&ZERO_DIGEST)
    {
        return Err(EvmActuatorErrorV1::InvalidScope);
    }
    Ok(RemoteEvmActionRequestV1 {
        kind: input.kind,
        role: input.role,
        owner_id: input.owner_id,
        owner_epoch: input.owner_epoch,
        action_id: input.action_id,
        route_id: input.route_id,
        settlement_id: input.settlement_id,
        composition_binding_digest: input.composition_binding_digest,
        execution_plan_digest: input.execution_plan_digest,
        unsigned_call_digest: input.unsigned_call_digest,
        request_message_digest: input.request_message_digest,
        requester_id: input.requester_id,
        signer_id: input.signer_id,
        chain_id: input.chain_id,
        contract: input.contract,
        signer_account: input.signer_account,
    })
}

/// Canonical immutable remote-signing commitment for an `open` call.
///
/// The digest includes the authenticated fee caps but deliberately excludes
/// the concrete nonce and fee tuple selected by the remote account owner.
pub fn remote_open_unsigned_call_digest_v1(scope: &ScopedEvmOpenV1) -> Result<Digest32> {
    remote_unsigned_call_digest(RemoteUnsignedCallBindingV1 {
        kind: EvmOperationKindV1::Open,
        role: EvmSignerRoleV1::Funder,
        route_id: scope.route_id,
        effect_id: scope.effect_id,
        semantic_digest: scope.semantic_digest,
        lock: &scope.lock,
        value: scope.call.value,
        calldata: &scope.call.calldata,
    })
}

/// Canonical immutable remote-signing commitment for a `claim` call.
///
/// The scalar remains inside the zeroizing scoped call; only this commitment
/// is intended for the public request.
pub fn remote_claim_unsigned_call_digest_v1(scope: &ScopedEvmClaimV1) -> Result<Digest32> {
    remote_unsigned_call_digest(RemoteUnsignedCallBindingV1 {
        kind: EvmOperationKindV1::Claim,
        role: EvmSignerRoleV1::Beneficiary,
        route_id: scope.route_id,
        effect_id: scope.effect_id,
        semantic_digest: scope.semantic_digest,
        lock: &scope.lock,
        value: ZERO_DIGEST,
        calldata: &scope.calldata,
    })
}

/// Canonical immutable remote-signing commitment for a `refund` call.
pub fn remote_refund_unsigned_call_digest_v1(scope: &ScopedEvmRefundV1) -> Result<Digest32> {
    remote_unsigned_call_digest(RemoteUnsignedCallBindingV1 {
        kind: EvmOperationKindV1::Refund,
        role: EvmSignerRoleV1::Funder,
        route_id: scope.route_id,
        effect_id: scope.effect_id,
        semantic_digest: scope.semantic_digest,
        lock: &scope.lock,
        value: ZERO_DIGEST,
        calldata: &scope.calldata,
    })
}

struct RemoteUnsignedCallBindingV1<'a> {
    kind: EvmOperationKindV1,
    role: EvmSignerRoleV1,
    route_id: Digest32,
    effect_id: Digest32,
    semantic_digest: Digest32,
    lock: &'a ValidatedEvmLockV1,
    value: Digest32,
    calldata: &'a [u8],
}

fn remote_unsigned_call_digest(binding: RemoteUnsignedCallBindingV1<'_>) -> Result<Digest32> {
    let config = binding.lock.deployment.adapter_config();
    let deployed = binding.lock.deployment.deployment();
    if binding.calldata.is_empty() || binding.calldata.len() > adapter_evm::abi::MAX_CALLDATA_BYTES
    {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    let kind = [u8::try_from(binding.kind.tag()).map_err(|_| EvmActuatorErrorV1::InvalidScope)?];
    let role = [u8::try_from(binding.role.tag()).map_err(|_| EvmActuatorErrorV1::InvalidScope)?];
    Ok(domain_digest(
        b"DOM-INTEROP/EVM-ACTUATOR/REMOTE-UNSIGNED-CALL/V1\0",
        &[
            &kind,
            &role,
            &binding.route_id,
            &binding.effect_id,
            &binding.semantic_digest,
            &config.chain_id.to_be_bytes(),
            &config.contract,
            &binding.value,
            &config.gas_limit_hint.to_be_bytes(),
            binding.calldata,
            &binding.lock.deployment.registry_digest(),
            &binding.lock.deployment.profile_digest(),
            &binding.lock.deployment.asset_binding_digest(),
            &deployed.deployment_digest,
            &config.expected_code_hash,
            &deployed.genesis_hash,
            &config.terms_hash,
            &binding.lock.lock_id,
            &binding.lock.binding,
            &binding.lock.beneficiary,
            &binding.lock.funder,
            &binding.lock.adaptor_address,
            &binding.lock.deadline.to_be_bytes(),
            &binding.lock.amount,
            &deployed.max_fee_per_gas.to_be_bytes(),
            &deployed.max_priority_fee_per_gas.to_be_bytes(),
        ],
    ))
}

/// DOM-tagged digest used by the DSC1 signed-action response.
pub fn remote_signed_raw_digest_v1(raw: &[u8]) -> Result<Digest32> {
    if raw.is_empty() || raw.len() > MAX_RAW_TRANSACTION_BYTES_V1 {
        return Err(EvmActuatorErrorV1::BoundExceeded);
    }
    let tag = REMOTE_RAW_TAG_V1.as_bytes();
    let tag_len = u16::try_from(tag.len()).map_err(|_| EvmActuatorErrorV1::BoundExceeded)?;
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(tag_len.to_le_bytes());
    hasher.update(tag);
    hasher.update(raw);
    let digest = hasher.finalize();
    let mut output = [0; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

pub(crate) fn decode_and_verify_remote_signed_eip1559(
    raw: &[u8],
    expected_account: EvmAddressV1,
) -> Result<DecodedRemoteEip1559V1> {
    if raw.len() < 2 || raw.len() > MAX_RAW_TRANSACTION_BYTES_V1 || raw[0] != TYPE_2 {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    let payload = decode_exact_list(&raw[1..])?;
    let mut cursor = RlpCursorV1::new(payload);
    let chain_id = decode_u64_rlp(cursor.take_bytes()?)?;
    let nonce = decode_u64_rlp(cursor.take_bytes()?)?;
    let priority = decode_u128_rlp(cursor.take_bytes()?)?;
    let maximum = decode_u128_rlp(cursor.take_bytes()?)?;
    let gas_limit = decode_u64_rlp(cursor.take_bytes()?)?;
    let to = exact_address(cursor.take_bytes()?)?;
    let value = padded_word(cursor.take_bytes()?)?;
    let calldata = cursor.take_bytes()?;
    if calldata.is_empty() || calldata.len() > adapter_evm::abi::MAX_CALLDATA_BYTES {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    cursor.take_empty_list()?;
    let y_parity = u8::try_from(decode_u64_rlp(cursor.take_bytes()?)?)
        .map_err(|_| EvmActuatorErrorV1::InvalidSignature)?;
    let r = padded_word(cursor.take_bytes()?)?;
    let s = padded_word(cursor.take_bytes()?)?;
    cursor.finish()?;
    let fields = Eip1559FieldsV1 {
        chain_id,
        nonce,
        fees: EvmFeesV1::new(maximum, priority)?,
        gas_limit,
        to,
        value,
        calldata: Zeroizing::new(calldata.to_vec()),
    };
    validate_fields(&fields)?;
    let signature = Eip1559SignatureV1 { y_parity, r, s };
    let (canonical, transaction_hash) =
        verify_and_encode_signed(&fields, expected_account, signature)?;
    if canonical.as_slice() != raw {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    Ok(DecodedRemoteEip1559V1 {
        fields,
        signature,
        transaction_hash,
        signed_raw_digest: remote_signed_raw_digest_v1(raw)?,
    })
}

pub(crate) fn validate_open_scope(
    route_id: Digest32,
    effect_id: Digest32,
    semantic_digest: Digest32,
    deployment: ResolvedEvmDeploymentV1,
    call: UnsignedEvmCall,
) -> Result<ScopedEvmOpenV1> {
    validate_route_scope(route_id, effect_id, semantic_digest)?;
    let lock = validate_lock_scope(deployment, &call)?;
    Ok(ScopedEvmOpenV1 {
        route_id,
        effect_id,
        semantic_digest,
        deployment,
        call,
        amount: lock.amount,
        lock,
    })
}

pub(crate) fn validate_claim_scope(
    route_id: Digest32,
    effect_id: Digest32,
    semantic_digest: Digest32,
    deployment: ResolvedEvmDeploymentV1,
    opening_call: UnsignedEvmCall,
    secret: EvmClaimSecretV1,
) -> Result<ScopedEvmClaimV1> {
    validate_route_scope(route_id, effect_id, semantic_digest)?;
    let lock = validate_lock_scope(deployment, &opening_call)?;
    if secret.adaptor_address() != lock.adaptor_address {
        return Err(EvmActuatorErrorV1::InvalidClaimSecret);
    }
    let calldata = encode_claim_calldata(lock.lock_id, secret.scalar())?;
    Ok(ScopedEvmClaimV1 {
        route_id,
        effect_id,
        semantic_digest,
        lock,
        calldata,
    })
}

pub(crate) fn validate_refund_scope(
    route_id: Digest32,
    effect_id: Digest32,
    semantic_digest: Digest32,
    deployment: ResolvedEvmDeploymentV1,
    opening_call: UnsignedEvmCall,
) -> Result<ScopedEvmRefundV1> {
    validate_route_scope(route_id, effect_id, semantic_digest)?;
    let lock = validate_lock_scope(deployment, &opening_call)?;
    let calldata = encode_refund_calldata(lock.lock_id)?;
    Ok(ScopedEvmRefundV1 {
        route_id,
        effect_id,
        semantic_digest,
        lock,
        calldata,
    })
}

fn validate_route_scope(
    route_id: Digest32,
    effect_id: Digest32,
    semantic_digest: Digest32,
) -> Result<()> {
    if route_id == ZERO_DIGEST || effect_id == ZERO_DIGEST || semantic_digest == ZERO_DIGEST {
        return Err(EvmActuatorErrorV1::InvalidScope);
    }
    Ok(())
}

fn validate_lock_scope(
    deployment: ResolvedEvmDeploymentV1,
    call: &UnsignedEvmCall,
) -> Result<ValidatedEvmLockV1> {
    let config = deployment.adapter_config();
    let deployment_facts = deployment.deployment();
    if call.version != UNSIGNED_CALL_VERSION_V1
        || call.chain_id != config.chain_id
        || call.to != config.contract
        || call.to == ZERO_ADDRESS
        || call.gas_limit_hint == 0
        || call.gas_limit_hint != config.gas_limit_hint
        || call.lock_id == ZERO_DIGEST
        || call.binding == ZERO_DIGEST
        || call.calldata.len() != OPEN_CALLDATA_LEN
        || deployment_facts.gas_limit_hint != call.gas_limit_hint
        || deployment.registry_digest() == ZERO_DIGEST
        || deployment.profile_digest() == ZERO_DIGEST
        || deployment.asset_binding_digest() == ZERO_DIGEST
    {
        return Err(EvmActuatorErrorV1::CallScopeMismatch);
    }
    let (given_selector, body) = call.calldata.split_at(4);
    if given_selector != selector(SIG_OPEN) {
        return Err(EvmActuatorErrorV1::CallScopeMismatch);
    }
    let words = split_words(body, 10).map_err(|_| EvmActuatorErrorV1::CallScopeMismatch)?;
    let terms = LockTerms {
        dom_chain_id: words[0],
        direction: decode_u8(&words[1]).map_err(|_| EvmActuatorErrorV1::CallScopeMismatch)?,
        session_id: words[2],
        terms_hash: words[3],
        participants_hash: words[4],
        asset: decode_address(&words[5]).map_err(|_| EvmActuatorErrorV1::CallScopeMismatch)?,
        amount: words[6],
        beneficiary: decode_address(&words[7])
            .map_err(|_| EvmActuatorErrorV1::CallScopeMismatch)?,
        adaptor_address: decode_address(&words[8])
            .map_err(|_| EvmActuatorErrorV1::CallScopeMismatch)?,
        deadline: decode_u64(&words[9]).map_err(|_| EvmActuatorErrorV1::CallScopeMismatch)?,
    };
    if !config.binds_terms(&terms)
        || terms.amount == [0; 32]
        || terms.adaptor_address == ZERO_ADDRESS
        || terms.deadline == 0
        || terms.terms_hash != config.terms_hash
    {
        return Err(EvmActuatorErrorV1::CallScopeMismatch);
    }
    let binding = derive_binding(config.chain_id, &config.contract, &terms)
        .map_err(|_| EvmActuatorErrorV1::CallScopeMismatch)?;
    let lock_id = derive_lock_id(&binding, &config.funder)
        .map_err(|_| EvmActuatorErrorV1::CallScopeMismatch)?;
    if call.binding != binding || call.lock_id != lock_id {
        return Err(EvmActuatorErrorV1::CallScopeMismatch);
    }
    match deployment.asset_binding().representation {
        AssetRepresentationV1::Native => {
            if terms.asset != ZERO_ADDRESS || call.value != terms.amount {
                return Err(EvmActuatorErrorV1::CallScopeMismatch);
            }
        }
        AssetRepresentationV1::EvmErc20 { token, .. } => {
            if token == ZERO_ADDRESS
                || terms.asset != token
                || config.asset != token
                || call.value != [0; 32]
            {
                return Err(EvmActuatorErrorV1::CallScopeMismatch);
            }
        }
    }
    Ok(ValidatedEvmLockV1 {
        deployment,
        lock_id,
        binding,
        amount: terms.amount,
        beneficiary: terms.beneficiary,
        funder: config.funder,
        adaptor_address: terms.adaptor_address,
        deadline: terms.deadline,
    })
}

fn encode_claim_calldata(lock_id: Digest32, scalar: &Digest32) -> Result<Zeroizing<Vec<u8>>> {
    let mut calldata = Zeroizing::new(Vec::with_capacity(CLAIM_CALLDATA_LEN));
    calldata.extend_from_slice(&selector(SIG_CLAIM));
    calldata.extend_from_slice(&lock_id);
    calldata.extend_from_slice(scalar);
    if calldata.len() != CLAIM_CALLDATA_LEN {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    Ok(calldata)
}

fn encode_refund_calldata(lock_id: Digest32) -> Result<Vec<u8>> {
    let mut calldata = Vec::with_capacity(REFUND_CALLDATA_LEN);
    calldata.extend_from_slice(&selector(SIG_REFUND));
    calldata.extend_from_slice(&lock_id);
    if calldata.len() != REFUND_CALLDATA_LEN {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    Ok(calldata)
}

pub(crate) fn signing_payload(fields: &Eip1559FieldsV1) -> Result<Zeroizing<Vec<u8>>> {
    validate_fields(fields)?;
    let mut payload = Zeroizing::new(Vec::with_capacity(MAX_RAW_TRANSACTION_BYTES_V1));
    append_u64(&mut payload, fields.chain_id)?;
    append_u64(&mut payload, fields.nonce)?;
    append_u128(&mut payload, fields.fees.max_priority_fee_per_gas)?;
    append_u128(&mut payload, fields.fees.max_fee_per_gas)?;
    append_u64(&mut payload, fields.gas_limit)?;
    append_bytes(&mut payload, &fields.to)?;
    append_uint_bytes(&mut payload, &fields.value)?;
    append_bytes(&mut payload, &fields.calldata)?;
    // Empty access list. V1 deliberately has no generic access-list surface.
    payload.push(0xc0);
    let envelope = Zeroizing::new(rlp_list(&payload)?);
    let mut typed = Zeroizing::new(Vec::with_capacity(1 + envelope.len()));
    typed.push(TYPE_2);
    typed.extend_from_slice(&envelope);
    Ok(typed)
}

pub(crate) fn signing_hash(fields: &Eip1559FieldsV1) -> Result<Digest32> {
    Ok(keccak256(&signing_payload(fields)?))
}

pub(crate) fn verify_and_encode_signed(
    fields: &Eip1559FieldsV1,
    expected_account: EvmAddressV1,
    signature: Eip1559SignatureV1,
) -> Result<(Zeroizing<Vec<u8>>, Digest32)> {
    let hash = signing_hash(fields)?;
    let recovered = recover_address(hash, signature)?;
    if recovered != expected_account {
        return Err(EvmActuatorErrorV1::WrongSigner);
    }
    let mut payload = Zeroizing::new(Vec::with_capacity(MAX_RAW_TRANSACTION_BYTES_V1));
    append_u64(&mut payload, fields.chain_id)?;
    append_u64(&mut payload, fields.nonce)?;
    append_u128(&mut payload, fields.fees.max_priority_fee_per_gas)?;
    append_u128(&mut payload, fields.fees.max_fee_per_gas)?;
    append_u64(&mut payload, fields.gas_limit)?;
    append_bytes(&mut payload, &fields.to)?;
    append_uint_bytes(&mut payload, &fields.value)?;
    append_bytes(&mut payload, &fields.calldata)?;
    payload.push(0xc0);
    append_u64(&mut payload, u64::from(signature.y_parity))?;
    append_uint_bytes(&mut payload, &signature.r)?;
    append_uint_bytes(&mut payload, &signature.s)?;
    let envelope = Zeroizing::new(rlp_list(&payload)?);
    let total = envelope
        .len()
        .checked_add(1)
        .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
    if total > MAX_RAW_TRANSACTION_BYTES_V1 {
        return Err(EvmActuatorErrorV1::BoundExceeded);
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(total));
    raw.push(TYPE_2);
    raw.extend_from_slice(&envelope);
    let transaction_hash = keccak256(&raw);
    Ok((raw, transaction_hash))
}

pub(crate) fn recover_address(
    signing_hash: Digest32,
    signature: Eip1559SignatureV1,
) -> Result<EvmAddressV1> {
    if signature.y_parity > 1 || signature.r == ZERO_DIGEST || signature.s == ZERO_DIGEST {
        return Err(EvmActuatorErrorV1::InvalidSignature);
    }
    let signature_value = Signature::from_scalars(signature.r, signature.s)
        .map_err(|_| EvmActuatorErrorV1::InvalidSignature)?;
    // `normalize_s` returns Some only when the supplied signature was high-s.
    if signature_value.normalize_s().is_some() {
        return Err(EvmActuatorErrorV1::HighSignatureS);
    }
    let recovery_id = RecoveryId::try_from(signature.y_parity)
        .map_err(|_| EvmActuatorErrorV1::InvalidSignature)?;
    let verifying_key =
        VerifyingKey::recover_from_prehash(&signing_hash, &signature_value, recovery_id)
            .map_err(|_| EvmActuatorErrorV1::InvalidSignature)?;
    let point = verifying_key.to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err(EvmActuatorErrorV1::InvalidSignature);
    }
    let digest = keccak256(&bytes[1..]);
    let mut address = [0; 20];
    address.copy_from_slice(&digest[12..]);
    Ok(address)
}

pub(crate) fn fields_digest(fields: &Eip1559FieldsV1) -> Result<Digest32> {
    let payload = signing_payload(fields)?;
    Ok(domain_digest(
        b"DOM-INTEROP/EVM-ACTUATOR/FIELDS/V1\0",
        &[&payload],
    ))
}

pub(crate) fn domain_digest(domain: &[u8], parts: &[&[u8]]) -> Digest32 {
    let capacity = parts.iter().fold(domain.len(), |total, part| {
        total.saturating_add(8).saturating_add(part.len())
    });
    let mut bytes = Zeroizing::new(Vec::with_capacity(capacity));
    bytes.extend_from_slice(domain);
    for part in parts {
        bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
        bytes.extend_from_slice(part);
    }
    keccak256(&bytes)
}

fn validate_fields(fields: &Eip1559FieldsV1) -> Result<()> {
    if fields.chain_id == 0
        || fields.to == ZERO_ADDRESS
        || fields.gas_limit == 0
        || fields.calldata.is_empty()
        || fields.calldata.len() > adapter_evm::abi::MAX_CALLDATA_BYTES
        || fields.fees.max_fee_per_gas == 0
        || fields.fees.max_priority_fee_per_gas == 0
        || fields.fees.max_priority_fee_per_gas > fields.fees.max_fee_per_gas
    {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    Ok(())
}

fn append_u64(output: &mut Vec<u8>, value: u64) -> Result<()> {
    append_uint_bytes(output, &value.to_be_bytes())
}

fn append_u128(output: &mut Vec<u8>, value: u128) -> Result<()> {
    append_uint_bytes(output, &value.to_be_bytes())
}

fn append_uint_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let first = bytes
        .iter()
        .position(|value| *value != 0)
        .unwrap_or(bytes.len());
    append_bytes(output, &bytes[first..])
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        output.push(bytes[0]);
        return Ok(());
    }
    if bytes.len() <= 55 {
        let len = u8::try_from(bytes.len()).map_err(|_| EvmActuatorErrorV1::BoundExceeded)?;
        output.push(0x80 + len);
    } else {
        let encoded_len = minimal_usize(bytes.len());
        let len_of_len =
            u8::try_from(encoded_len.len()).map_err(|_| EvmActuatorErrorV1::BoundExceeded)?;
        output.push(0xb7 + len_of_len);
        output.extend_from_slice(&encoded_len);
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn rlp_list(payload: &[u8]) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    if payload.len() <= 55 {
        let len = u8::try_from(payload.len()).map_err(|_| EvmActuatorErrorV1::BoundExceeded)?;
        output.push(0xc0 + len);
    } else {
        let encoded_len = minimal_usize(payload.len());
        let len_of_len =
            u8::try_from(encoded_len.len()).map_err(|_| EvmActuatorErrorV1::BoundExceeded)?;
        output.push(0xf7 + len_of_len);
        output.extend_from_slice(&encoded_len);
    }
    output.extend_from_slice(payload);
    if output.len() > MAX_RAW_TRANSACTION_BYTES_V1 {
        return Err(EvmActuatorErrorV1::BoundExceeded);
    }
    Ok(output)
}

fn minimal_usize(value: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[first..].to_vec()
}

#[derive(Clone, Copy)]
enum RlpItemV1<'a> {
    Bytes(&'a [u8]),
    List(&'a [u8]),
}

struct RlpCursorV1<'a> {
    remaining: &'a [u8],
}

impl<'a> RlpCursorV1<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take_bytes(&mut self) -> Result<&'a [u8]> {
        let (item, remaining) = decode_rlp_item(self.remaining)?;
        self.remaining = remaining;
        match item {
            RlpItemV1::Bytes(bytes) => Ok(bytes),
            RlpItemV1::List(_) => Err(EvmActuatorErrorV1::InvalidTransaction),
        }
    }

    fn take_empty_list(&mut self) -> Result<()> {
        let (item, remaining) = decode_rlp_item(self.remaining)?;
        self.remaining = remaining;
        match item {
            RlpItemV1::List([]) => Ok(()),
            _ => Err(EvmActuatorErrorV1::InvalidTransaction),
        }
    }

    fn finish(self) -> Result<()> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(EvmActuatorErrorV1::InvalidTransaction)
        }
    }
}

fn decode_exact_list(bytes: &[u8]) -> Result<&[u8]> {
    let (item, remaining) = decode_rlp_item(bytes)?;
    if !remaining.is_empty() {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    match item {
        RlpItemV1::List(payload) => Ok(payload),
        RlpItemV1::Bytes(_) => Err(EvmActuatorErrorV1::InvalidTransaction),
    }
}

fn decode_rlp_item(bytes: &[u8]) -> Result<(RlpItemV1<'_>, &[u8])> {
    let prefix = *bytes
        .first()
        .ok_or(EvmActuatorErrorV1::InvalidTransaction)?;
    match prefix {
        0x00..=0x7f => Ok((RlpItemV1::Bytes(&bytes[..1]), &bytes[1..])),
        0x80..=0xb7 => {
            let length = usize::from(prefix - 0x80);
            let end = 1usize
                .checked_add(length)
                .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
            let payload = bytes
                .get(1..end)
                .ok_or(EvmActuatorErrorV1::InvalidTransaction)?;
            if length == 1 && payload[0] < 0x80 {
                return Err(EvmActuatorErrorV1::InvalidTransaction);
            }
            Ok((RlpItemV1::Bytes(payload), &bytes[end..]))
        }
        0xb8..=0xbf => decode_long_rlp(bytes, prefix - 0xb7, false),
        0xc0..=0xf7 => {
            let length = usize::from(prefix - 0xc0);
            let end = 1usize
                .checked_add(length)
                .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
            let payload = bytes
                .get(1..end)
                .ok_or(EvmActuatorErrorV1::InvalidTransaction)?;
            Ok((RlpItemV1::List(payload), &bytes[end..]))
        }
        0xf8..=0xff => decode_long_rlp(bytes, prefix - 0xf7, true),
    }
}

fn decode_long_rlp(
    bytes: &[u8],
    length_of_length: u8,
    is_list: bool,
) -> Result<(RlpItemV1<'_>, &[u8])> {
    let length_of_length = usize::from(length_of_length);
    if length_of_length == 0 || length_of_length > core::mem::size_of::<usize>() {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    let length_bytes = bytes
        .get(1..1 + length_of_length)
        .ok_or(EvmActuatorErrorV1::InvalidTransaction)?;
    if length_bytes[0] == 0 {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    let mut length = 0usize;
    for byte in length_bytes {
        length = length
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
    }
    if length <= 55 {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    let start = 1usize
        .checked_add(length_of_length)
        .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
    let end = start
        .checked_add(length)
        .ok_or(EvmActuatorErrorV1::BoundExceeded)?;
    let payload = bytes
        .get(start..end)
        .ok_or(EvmActuatorErrorV1::InvalidTransaction)?;
    let item = if is_list {
        RlpItemV1::List(payload)
    } else {
        RlpItemV1::Bytes(payload)
    };
    Ok((item, &bytes[end..]))
}

fn decode_u64_rlp(bytes: &[u8]) -> Result<u64> {
    if bytes.len() > 8 || bytes.first() == Some(&0) {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    let mut encoded = [0; 8];
    encoded[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(u64::from_be_bytes(encoded))
}

fn decode_u128_rlp(bytes: &[u8]) -> Result<u128> {
    if bytes.len() > 16 || bytes.first() == Some(&0) {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    let mut encoded = [0; 16];
    encoded[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(u128::from_be_bytes(encoded))
}

fn exact_address(bytes: &[u8]) -> Result<EvmAddressV1> {
    bytes
        .try_into()
        .map_err(|_| EvmActuatorErrorV1::InvalidTransaction)
}

fn padded_word(bytes: &[u8]) -> Result<Digest32> {
    if bytes.len() > 32 || bytes.first() == Some(&0) {
        return Err(EvmActuatorErrorV1::InvalidTransaction);
    }
    let mut output = [0; 32];
    output[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    #[test]
    fn terminal_calldata_is_exact_static_abi() {
        use adapter_evm::abi::{event_topic0, SIG_CLAIMED, SIG_REFUNDED};

        let lock_id = [0x41; 32];
        let mut scalar = [0; 32];
        scalar[31] = 7;
        let claim = encode_claim_calldata(lock_id, &scalar).unwrap();
        assert_eq!(claim.len(), CLAIM_CALLDATA_LEN);
        assert_eq!(selector(SIG_CLAIM), [0x63, 0xf4, 0x49, 0x68]);
        assert_eq!(&claim[..4], &selector(SIG_CLAIM));
        assert_eq!(&claim[4..36], &lock_id);
        assert_eq!(&claim[36..68], &scalar);

        let refund = encode_refund_calldata(lock_id).unwrap();
        assert_eq!(refund.len(), REFUND_CALLDATA_LEN);
        assert_eq!(selector(SIG_REFUND), [0x72, 0x49, 0xfb, 0xb6]);
        assert_eq!(&refund[..4], &selector(SIG_REFUND));
        assert_eq!(&refund[4..36], &lock_id);

        assert_eq!(
            hex::encode(event_topic0(SIG_CLAIMED)),
            "ca7668936817898f2bde507192f5845d33b460b40fa8206ba5e3869637a03e19"
        );
        assert_eq!(
            hex::encode(event_topic0(SIG_REFUNDED)),
            "6c5895acb60b66e78106939eaaa3976db6325f801ff434fe24ff7cb0a6795a5f"
        );
    }

    #[test]
    fn remote_type_two_decoder_is_canonical_bounded_and_recovers_low_s_signer() {
        let key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let encoded = key.verifying_key().to_encoded_point(false);
        let digest = keccak256(&encoded.as_bytes()[1..]);
        let mut account = [0; 20];
        account.copy_from_slice(&digest[12..]);
        let fields = Eip1559FieldsV1 {
            chain_id: 31_337,
            nonce: 19,
            fees: EvmFeesV1::new(100, 2).unwrap(),
            gas_limit: 300_000,
            to: [0x31; 20],
            value: [0; 32],
            calldata: Zeroizing::new(vec![0x12, 0x34, 0x56, 0x78]),
        };
        let hash = signing_hash(&fields).unwrap();
        let (signature, recovery) = key.sign_prehash_recoverable(&hash).unwrap();
        let bytes = signature.to_bytes();
        let mut r = [0; 32];
        let mut s = [0; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);
        let signature = Eip1559SignatureV1 {
            y_parity: recovery.to_byte(),
            r,
            s,
        };
        let (raw, expected_hash) = verify_and_encode_signed(&fields, account, signature).unwrap();
        let decoded = decode_and_verify_remote_signed_eip1559(&raw, account).unwrap();
        assert_eq!(decoded.fields, fields);
        assert_eq!(decoded.signature, signature);
        assert_eq!(decoded.transaction_hash, expected_hash);
        assert_eq!(
            decoded.signed_raw_digest,
            remote_signed_raw_digest_v1(&raw).unwrap()
        );

        let mut trailing = raw.to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_and_verify_remote_signed_eip1559(&trailing, account),
            Err(EvmActuatorErrorV1::InvalidTransaction)
        ));
        assert!(matches!(
            decode_and_verify_remote_signed_eip1559(&raw, [0x99; 20]),
            Err(EvmActuatorErrorV1::WrongSigner)
        ));
        let mut noncanonical = raw.to_vec();
        noncanonical[0] = 0x01;
        assert!(matches!(
            decode_and_verify_remote_signed_eip1559(&noncanonical, account),
            Err(EvmActuatorErrorV1::InvalidTransaction)
        ));
    }
}
