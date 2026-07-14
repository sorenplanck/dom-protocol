//! Interactive Mimblewimble transaction slate.

use dom_core::{
    Address, DomError, MAX_INPUTS_PER_TX, MAX_PROOF_SIZE, NETWORK_MAGIC_MAINNET,
    NETWORK_MAGIC_REGTEST, NETWORK_MAGIC_TESTNET,
};
use dom_crypto::hash::blake2b_256_tagged;
use dom_crypto::pedersen::Commitment;
use dom_crypto::{PartialSig, PublicKey, RangeProof};
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};

/// Current supported slate wire format version.
pub const CURRENT_SLATE_VERSION: u16 = 3;

/// Narrow Wallet V3 recovery extension. Version 4 adds two authenticated
/// recovery-capsule sidecars and changes no transaction or signature primitive.
pub const RECOVERY_SLATE_VERSION: u16 = 4;

/// Current canonical Slate envelope version.
pub const CURRENT_SLATE_ENVELOPE_VERSION: u16 = 3;

/// Envelope version paired with [`RECOVERY_SLATE_VERSION`].
pub const RECOVERY_SLATE_ENVELOPE_VERSION: u16 = 4;

/// Domain tag for Slate signature/message digests.
pub const SLATE_SIGNATURE_DIGEST_DOMAIN: &str = "DOM:slate-signature-digest:v3";

/// Signature digest domain for the recovery extension.
pub const RECOVERY_SLATE_SIGNATURE_DIGEST_DOMAIN: &str = "DOM:slate-signature-digest:v4";

/// Standard two-party send flow.
pub const SLATE_FLOW_STANDARD_SEND: u8 = 0;

/// Sender-created initial slate phase.
pub const SLATE_PHASE_SENDER_OFFER: u8 = 0;

/// Receiver response phase.
pub const SLATE_PHASE_RECEIVER_RESPONSE: u8 = 1;

/// Sender-finalized phase.
pub const SLATE_PHASE_FINALIZED: u8 = 2;

/// Sender signing role.
pub const SLATE_ROLE_SENDER: u8 = 0;

/// Receiver signing role.
pub const SLATE_ROLE_RECEIVER: u8 = 1;

/// Sender input commitment carried in a slate.
pub type InputCommitment = Commitment;

/// Output commitment plus range proof carried in a slate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputCommitmentAndProof {
    /// Public Pedersen commitment.
    pub commitment: Commitment,
    /// Public range proof for the committed output value.
    pub proof: RangeProof,
}

impl DomSerialize for OutputCommitmentAndProof {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_bytes(self.commitment.as_bytes());
        w.write_vec(&self.proof.bytes)?;
        Ok(())
    }
}

impl DomDeserialize for OutputCommitmentAndProof {
    const MIN_SERIALIZED_SIZE: usize = 33 + 4;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let commitment_bytes = r.read_array::<33>()?;
        let proof_bytes = r.read_vec(MAX_PROOF_SIZE)?;
        Ok(Self {
            commitment: Commitment::from_compressed_bytes(&commitment_bytes)?,
            proof: RangeProof::from_bytes(proof_bytes)?,
        })
    }
}

/// Slate exchanged by wallets during interactive transaction construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slate {
    /// Slate format version.
    pub version: u16,
    /// Network binding for replay protection.
    pub chain_id: [u8; 32],
    /// Transfer amount in noms, visible only to slate participants.
    pub amount: u64,
    /// Kernel fee in noms.
    pub fee: u64,
    /// Kernel lock height.
    pub lock_height: u64,
    /// Sender input commitments. No input blindings are present.
    pub sender_inputs: Vec<InputCommitment>,
    /// Optional sender change output.
    pub sender_change_output: Option<OutputCommitmentAndProof>,
    /// Sender public excess contribution.
    pub sender_public_excess: PublicKey,
    /// Sender public nonce contribution.
    pub sender_public_nonce: PublicKey,
    /// Sender offset contribution as public slate data.
    pub sender_offset_contribution: [u8; 32],
    /// Optional recipient output.
    pub recipient_output: Option<OutputCommitmentAndProof>,
    /// Optional recipient public excess contribution.
    pub recipient_public_excess: Option<PublicKey>,
    /// Optional recipient public nonce contribution.
    pub recipient_public_nonce: Option<PublicKey>,
    /// Optional sender partial signature.
    pub sender_partial_sig: Option<PartialSig>,
    /// Optional recipient partial signature.
    pub recipient_partial_sig: Option<PartialSig>,
    /// Version 4 authenticated recovery capsule for sender change.
    pub sender_change_recovery_capsule: Vec<u8>,
    /// Version 4 authenticated recovery capsule for the recipient output.
    pub recipient_recovery_capsule: Vec<u8>,
}

/// Transport-independent Wallet V3 Slate envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlateEnvelope {
    /// Envelope version.
    pub envelope_version: u16,
    /// DOM network magic.
    pub network_magic: u32,
    /// Chain id.
    pub chain_id: [u8; 32],
    /// Unique slate identifier.
    pub slate_id: [u8; 32],
    /// Replay identifier, unique per offer.
    pub replay_id: [u8; 32],
    /// Supported flow.
    pub flow: u8,
    /// Current phase.
    pub phase: u8,
    /// Inclusive expiry height.
    pub expires_at_height: u64,
    /// Sender address.
    pub sender_address: Address,
    /// Receiver address.
    pub receiver_address: Address,
    /// Canonical slate transaction body.
    pub body: Slate,
}

impl SlateEnvelope {
    /// Build a standard Wallet V3 slate envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_magic: u32,
        chain_id: [u8; 32],
        slate_id: [u8; 32],
        replay_id: [u8; 32],
        phase: u8,
        expires_at_height: u64,
        sender_address: Address,
        receiver_address: Address,
        body: Slate,
    ) -> Result<Self, DomError> {
        let envelope = Self {
            envelope_version: if body.version == RECOVERY_SLATE_VERSION {
                RECOVERY_SLATE_ENVELOPE_VERSION
            } else {
                CURRENT_SLATE_ENVELOPE_VERSION
            },
            network_magic,
            chain_id,
            slate_id,
            replay_id,
            flow: SLATE_FLOW_STANDARD_SEND,
            phase,
            expires_at_height,
            sender_address,
            receiver_address,
            body,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validate envelope identity, version, phase, expiry, and participant binding.
    pub fn validate(&self) -> Result<(), DomError> {
        let supported_pair = matches!(
            (self.envelope_version, self.body.version),
            (CURRENT_SLATE_ENVELOPE_VERSION, CURRENT_SLATE_VERSION)
                | (RECOVERY_SLATE_ENVELOPE_VERSION, RECOVERY_SLATE_VERSION)
        );
        if !supported_pair {
            return Err(DomError::Invalid(format!(
                "unsupported slate envelope/body version pair {}/{}",
                self.envelope_version, self.body.version
            )));
        }
        if self.body.chain_id != self.chain_id {
            return Err(DomError::Invalid(
                "slate body chain_id does not match envelope chain_id".into(),
            ));
        }
        if !matches!(
            self.network_magic,
            NETWORK_MAGIC_MAINNET | NETWORK_MAGIC_TESTNET | NETWORK_MAGIC_REGTEST
        ) {
            return Err(DomError::Invalid(format!(
                "unsupported slate network magic 0x{:08x}",
                self.network_magic
            )));
        }
        self.sender_address
            .validate_for_network(self.network_magic)?;
        self.receiver_address
            .validate_for_network(self.network_magic)?;
        if self.sender_address.payload == self.receiver_address.payload {
            return Err(DomError::Invalid(
                "duplicate sender and receiver address identity".into(),
            ));
        }
        if self.flow != SLATE_FLOW_STANDARD_SEND {
            return Err(DomError::Invalid(format!(
                "unsupported slate flow {}",
                self.flow
            )));
        }
        if !matches!(
            self.phase,
            SLATE_PHASE_SENDER_OFFER | SLATE_PHASE_RECEIVER_RESPONSE | SLATE_PHASE_FINALIZED
        ) {
            return Err(DomError::Invalid(format!(
                "unsupported slate phase {}",
                self.phase
            )));
        }
        if self.expires_at_height == 0 {
            return Err(DomError::Invalid(
                "slate expiry height must be non-zero".into(),
            ));
        }
        if self.slate_id == [0u8; 32] || self.replay_id == [0u8; 32] {
            return Err(DomError::Invalid(
                "slate_id and replay_id must be non-zero".into(),
            ));
        }
        self.body.validate()?;
        Ok(())
    }

    /// Return true when the slate is expired at the supplied chain height.
    pub fn is_expired_at(&self, current_height: u64) -> bool {
        current_height > self.expires_at_height
    }

    /// Canonical bytes for transport and storage.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DomError> {
        self.to_bytes()
    }

    /// Decode canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        Self::from_bytes(bytes)
    }

    /// Domain-separated digest signed by the selected participant role.
    pub fn signature_digest(&self, role: u8) -> Result<[u8; 32], DomError> {
        if !matches!(role, SLATE_ROLE_SENDER | SLATE_ROLE_RECEIVER) {
            return Err(DomError::Invalid(format!(
                "unsupported slate participant role {role}"
            )));
        }
        let mut data = Vec::new();
        data.extend_from_slice(&self.envelope_version.to_le_bytes());
        data.extend_from_slice(&self.network_magic.to_le_bytes());
        data.extend_from_slice(&self.chain_id);
        data.extend_from_slice(&self.slate_id);
        data.extend_from_slice(&self.replay_id);
        data.push(self.flow);
        data.push(self.phase);
        data.push(role);
        data.extend_from_slice(&self.expires_at_height.to_le_bytes());
        data.extend_from_slice(&self.sender_address.to_payload_bytes());
        data.extend_from_slice(&self.receiver_address.to_payload_bytes());
        data.extend_from_slice(&self.body.to_bytes()?);
        let domain = if self.envelope_version == RECOVERY_SLATE_ENVELOPE_VERSION {
            RECOVERY_SLATE_SIGNATURE_DIGEST_DOMAIN
        } else {
            SLATE_SIGNATURE_DIGEST_DOMAIN
        };
        Ok(*blake2b_256_tagged(domain, &data).as_bytes())
    }
}

impl DomSerialize for SlateEnvelope {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u16(self.envelope_version);
        w.write_u32(self.network_magic);
        w.write_bytes(&self.chain_id);
        w.write_bytes(&self.slate_id);
        w.write_bytes(&self.replay_id);
        w.write_u8(self.flow);
        w.write_u8(self.phase);
        w.write_u64(self.expires_at_height);
        w.write_bytes(&self.sender_address.to_payload_bytes());
        w.write_bytes(&self.receiver_address.to_payload_bytes());
        self.body.serialize(w)?;
        Ok(())
    }
}

impl DomDeserialize for SlateEnvelope {
    const MIN_SERIALIZED_SIZE: usize =
        2 + 4 + 32 + 32 + 32 + 1 + 1 + 8 + 40 + 40 + Slate::MIN_SERIALIZED_SIZE;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let envelope_version = r.read_u16()?;
        if !matches!(
            envelope_version,
            CURRENT_SLATE_ENVELOPE_VERSION | RECOVERY_SLATE_ENVELOPE_VERSION
        ) {
            return Err(DomError::Invalid(format!(
                "unsupported slate envelope version {envelope_version}"
            )));
        }
        let network_magic = r.read_u32()?;
        let chain_id = r.read_array::<32>()?;
        let slate_id = r.read_array::<32>()?;
        let replay_id = r.read_array::<32>()?;
        let flow = r.read_u8()?;
        let phase = r.read_u8()?;
        let expires_at_height = r.read_u64()?;
        let sender_address = address_from_payload_bytes(r.read_array::<40>()?)?;
        let receiver_address = address_from_payload_bytes(r.read_array::<40>()?)?;
        let body = Slate::deserialize(r)?;
        let envelope = Self {
            envelope_version,
            network_magic,
            chain_id,
            slate_id,
            replay_id,
            flow,
            phase,
            expires_at_height,
            sender_address,
            receiver_address,
            body,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

fn address_from_payload_bytes(bytes: [u8; 40]) -> Result<Address, DomError> {
    let network_magic = u32::from_le_bytes(bytes[3..7].try_into().unwrap());
    let mut key = [0u8; 33];
    key.copy_from_slice(&bytes[7..40]);
    let address = Address::new_for_network(key, network_magic)?;
    if address.to_payload_bytes() != bytes {
        return Err(DomError::Malformed(
            "non-canonical address payload in slate envelope".into(),
        ));
    }
    Ok(address)
}

impl Slate {
    /// Construct a Wallet V3 slate body with the frozen version.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: [u8; 32],
        amount: u64,
        fee: u64,
        lock_height: u64,
        sender_inputs: Vec<InputCommitment>,
        sender_change_output: Option<OutputCommitmentAndProof>,
        sender_public_excess: PublicKey,
        sender_public_nonce: PublicKey,
        sender_offset_contribution: [u8; 32],
    ) -> Self {
        Self {
            version: CURRENT_SLATE_VERSION,
            chain_id,
            amount,
            fee,
            lock_height,
            sender_inputs,
            sender_change_output,
            sender_public_excess,
            sender_public_nonce,
            sender_offset_contribution,
            recipient_output: None,
            recipient_public_excess: None,
            recipient_public_nonce: None,
            sender_partial_sig: None,
            recipient_partial_sig: None,
            sender_change_recovery_capsule: Vec::new(),
            recipient_recovery_capsule: Vec::new(),
        }
    }

    /// Validate the frozen body version and amount/fee fields.
    pub fn validate(&self) -> Result<(), DomError> {
        if !matches!(self.version, CURRENT_SLATE_VERSION | RECOVERY_SLATE_VERSION) {
            return Err(DomError::Invalid(format!(
                "unsupported slate version {}",
                self.version
            )));
        }
        if self.version == RECOVERY_SLATE_VERSION {
            validate_recovery_capsules(self)?;
        }
        dom_core::Amount::from_noms(self.amount)?;
        dom_core::Amount::from_noms(self.fee)?;
        Ok(())
    }

    /// Canonical Slate body bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, DomError> {
        self.to_bytes()
    }

    /// Decode canonical Slate body bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DomError> {
        Self::from_bytes(bytes)
    }
}

impl DomSerialize for Slate {
    fn serialize(&self, w: &mut Writer) -> Result<(), DomError> {
        w.write_u16(self.version);
        w.write_bytes(&self.chain_id);
        w.write_u64(self.amount);
        w.write_u64(self.fee);
        w.write_u64(self.lock_height);
        write_commitment_list(w, &self.sender_inputs)?;
        write_option(w, self.sender_change_output.as_ref(), |w, output| {
            output.serialize(w)
        })?;
        write_public_key(w, &self.sender_public_excess);
        write_public_key(w, &self.sender_public_nonce);
        w.write_bytes(&self.sender_offset_contribution);
        write_option(w, self.recipient_output.as_ref(), |w, output| {
            output.serialize(w)
        })?;
        write_option(w, self.recipient_public_excess.as_ref(), |w, public_key| {
            write_public_key(w, public_key);
            Ok(())
        })?;
        write_option(w, self.recipient_public_nonce.as_ref(), |w, public_key| {
            write_public_key(w, public_key);
            Ok(())
        })?;
        write_option(w, self.sender_partial_sig.as_ref(), |w, partial| {
            write_partial_sig(w, partial);
            Ok(())
        })?;
        write_option(w, self.recipient_partial_sig.as_ref(), |w, partial| {
            write_partial_sig(w, partial);
            Ok(())
        })?;
        if self.version == RECOVERY_SLATE_VERSION {
            w.write_vec(&self.sender_change_recovery_capsule)?;
            w.write_vec(&self.recipient_recovery_capsule)?;
        } else if !self.sender_change_recovery_capsule.is_empty()
            || !self.recipient_recovery_capsule.is_empty()
        {
            return Err(DomError::Invalid(
                "Slate version 3 cannot carry recovery capsules".into(),
            ));
        }
        Ok(())
    }
}

impl DomDeserialize for Slate {
    const MIN_SERIALIZED_SIZE: usize =
        2 + 32 + 8 + 8 + 8 + 4 + 1 + 33 + 33 + 32 + 1 + 1 + 1 + 1 + 1;

    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        let version = r.read_u16()?;
        if !matches!(version, CURRENT_SLATE_VERSION | RECOVERY_SLATE_VERSION) {
            return Err(DomError::Invalid(format!(
                "unsupported slate version {version}"
            )));
        }
        let mut slate = Self {
            version,
            chain_id: r.read_array::<32>()?,
            amount: r.read_u64()?,
            fee: r.read_u64()?,
            lock_height: r.read_u64()?,
            sender_inputs: read_commitment_list(r)?,
            sender_change_output: read_option(r, OutputCommitmentAndProof::deserialize)?,
            sender_public_excess: read_public_key(r)?,
            sender_public_nonce: read_public_key(r)?,
            sender_offset_contribution: r.read_array::<32>()?,
            recipient_output: read_option(r, OutputCommitmentAndProof::deserialize)?,
            recipient_public_excess: read_option(r, read_public_key)?,
            recipient_public_nonce: read_option(r, read_public_key)?,
            sender_partial_sig: read_option(r, read_partial_sig)?,
            recipient_partial_sig: read_option(r, read_partial_sig)?,
            sender_change_recovery_capsule: Vec::new(),
            recipient_recovery_capsule: Vec::new(),
        };
        if version == RECOVERY_SLATE_VERSION {
            slate.sender_change_recovery_capsule = r.read_vec(dom_core::RECOVERY_CAPSULE_SIZE)?;
            slate.recipient_recovery_capsule = r.read_vec(dom_core::RECOVERY_CAPSULE_SIZE)?;
            validate_recovery_capsules(&slate)?;
        }
        Ok(slate)
    }
}

fn validate_recovery_capsules(slate: &Slate) -> Result<(), DomError> {
    let change_required = slate.sender_change_output.is_some();
    if change_required == slate.sender_change_recovery_capsule.is_empty() {
        return Err(DomError::Invalid(
            "Slate recovery extension change output/capsule mismatch".into(),
        ));
    }
    if !slate.sender_change_recovery_capsule.is_empty() {
        dom_crypto::recovery::RecoveryCapsule::from_bytes(&slate.sender_change_recovery_capsule)?;
    }
    if slate.recipient_output.is_some() == slate.recipient_recovery_capsule.is_empty() {
        return Err(DomError::Invalid(
            "Slate recovery extension recipient output/capsule mismatch".into(),
        ));
    }
    if !slate.recipient_recovery_capsule.is_empty() {
        dom_crypto::recovery::RecoveryCapsule::from_bytes(&slate.recipient_recovery_capsule)?;
    }
    Ok(())
}

fn write_commitment_list(w: &mut Writer, commitments: &[Commitment]) -> Result<(), DomError> {
    let len: u32 = commitments
        .len()
        .try_into()
        .map_err(|_| DomError::Malformed("sender input count exceeds u32".into()))?;
    w.write_u32(len);
    for commitment in commitments {
        w.write_bytes(commitment.as_bytes());
    }
    Ok(())
}

fn read_commitment_list(r: &mut Reader<'_>) -> Result<Vec<Commitment>, DomError> {
    let count = r.read_u32()? as usize;
    if count > MAX_INPUTS_PER_TX {
        return Err(DomError::Malformed(format!(
            "sender input count {count} exceeds limit {MAX_INPUTS_PER_TX}"
        )));
    }
    let mut commitments = Vec::with_capacity(count);
    for _ in 0..count {
        commitments.push(Commitment::from_compressed_bytes(&r.read_array::<33>()?)?);
    }
    Ok(commitments)
}

fn write_option<T>(
    w: &mut Writer,
    value: Option<&T>,
    write_value: impl FnOnce(&mut Writer, &T) -> Result<(), DomError>,
) -> Result<(), DomError> {
    match value {
        Some(value) => {
            w.write_u8(1);
            write_value(w, value)
        }
        None => {
            w.write_u8(0);
            Ok(())
        }
    }
}

fn read_option<T>(
    r: &mut Reader<'_>,
    read_value: impl FnOnce(&mut Reader<'_>) -> Result<T, DomError>,
) -> Result<Option<T>, DomError> {
    match r.read_u8()? {
        0 => Ok(None),
        1 => read_value(r).map(Some),
        flag => Err(DomError::Malformed(format!(
            "invalid option presence flag {flag}"
        ))),
    }
}

fn write_public_key(w: &mut Writer, public_key: &PublicKey) {
    w.write_bytes(&public_key.to_compressed_bytes());
}

fn read_public_key(r: &mut Reader<'_>) -> Result<PublicKey, DomError> {
    PublicKey::from_compressed_bytes(&r.read_array::<33>()?)
}

fn write_partial_sig(w: &mut Writer, partial: &PartialSig) {
    w.write_bytes(&partial.to_bytes());
}

fn read_partial_sig(r: &mut Reader<'_>) -> Result<PartialSig, DomError> {
    PartialSig::from_bytes(&r.read_array::<32>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dom_crypto::{bp2_prove, BlindingFactor, SecretKey};

    fn commitment(value: u64, blinding_byte: u8) -> Commitment {
        let blinding = BlindingFactor::from_bytes([blinding_byte; 32]).unwrap();
        Commitment::commit(value, &blinding)
    }

    fn output(value: u64, blinding_byte: u8) -> OutputCommitmentAndProof {
        let blinding = BlindingFactor::from_bytes([blinding_byte; 32]).unwrap();
        let (proof_bytes, commitment_bytes) = bp2_prove(value, &blinding).unwrap();
        OutputCommitmentAndProof {
            commitment: Commitment::from_compressed_bytes(&commitment_bytes).unwrap(),
            proof: RangeProof::from_bytes(proof_bytes).unwrap(),
        }
    }

    fn public_key(secret_byte: u8) -> PublicKey {
        SecretKey::from_bytes(&[secret_byte; 32])
            .unwrap()
            .public_key()
    }

    fn partial_sig(scalar_byte: u8) -> PartialSig {
        PartialSig::from_bytes(&[scalar_byte; 32]).unwrap()
    }

    fn roundtrip(slate: Slate) {
        let bytes = slate.to_bytes().unwrap();
        let decoded = Slate::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, slate);
    }

    #[test]
    fn sender_only_slate_roundtrip() {
        let slate = Slate {
            version: CURRENT_SLATE_VERSION,
            chain_id: [2u8; 32],
            amount: 1_000,
            fee: 10,
            lock_height: 0,
            sender_inputs: vec![commitment(1_500, 3), commitment(800, 4)],
            sender_change_output: Some(output(1_290, 5)),
            sender_public_excess: public_key(6),
            sender_public_nonce: public_key(7),
            sender_offset_contribution: [8u8; 32],
            recipient_output: None,
            recipient_public_excess: None,
            recipient_public_nonce: None,
            sender_partial_sig: None,
            recipient_partial_sig: None,
            sender_change_recovery_capsule: Vec::new(),
            recipient_recovery_capsule: Vec::new(),
        };

        roundtrip(slate);
    }

    #[test]
    fn recipient_completed_slate_roundtrip() {
        let slate = Slate {
            version: CURRENT_SLATE_VERSION,
            chain_id: [9u8; 32],
            amount: 2_000,
            fee: 20,
            lock_height: 144,
            sender_inputs: vec![commitment(3_000, 10)],
            sender_change_output: None,
            sender_public_excess: public_key(11),
            sender_public_nonce: public_key(12),
            sender_offset_contribution: [13u8; 32],
            recipient_output: Some(output(2_000, 14)),
            recipient_public_excess: Some(public_key(15)),
            recipient_public_nonce: Some(public_key(16)),
            sender_partial_sig: Some(partial_sig(17)),
            recipient_partial_sig: Some(partial_sig(18)),
            sender_change_recovery_capsule: Vec::new(),
            recipient_recovery_capsule: Vec::new(),
        };

        roundtrip(slate);
    }

    #[test]
    fn rejects_unsupported_version_on_deserialize() {
        let slate = Slate {
            version: RECOVERY_SLATE_VERSION + 1,
            chain_id: [9u8; 32],
            amount: 2_000,
            fee: 20,
            lock_height: 144,
            sender_inputs: vec![commitment(3_000, 10)],
            sender_change_output: None,
            sender_public_excess: public_key(11),
            sender_public_nonce: public_key(12),
            sender_offset_contribution: [13u8; 32],
            recipient_output: None,
            recipient_public_excess: None,
            recipient_public_nonce: None,
            sender_partial_sig: None,
            recipient_partial_sig: None,
            sender_change_recovery_capsule: Vec::new(),
            recipient_recovery_capsule: Vec::new(),
        };

        let bytes = slate.to_bytes().unwrap();
        let err = Slate::from_bytes(&bytes).unwrap_err();
        assert!(
            err.to_string().contains("unsupported slate version"),
            "unexpected error: {err}"
        );
    }
}
