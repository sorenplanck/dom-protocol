//! Interactive Mimblewimble transaction slate.

use dom_core::{DomError, MAX_INPUTS_PER_TX, MAX_PROOF_SIZE};
use dom_crypto::pedersen::Commitment;
use dom_crypto::{PartialSig, PublicKey, RangeProof};
use dom_serialization::{DomDeserialize, DomSerialize, Reader, Writer};

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
        Ok(())
    }
}

impl DomDeserialize for Slate {
    fn deserialize(r: &mut Reader<'_>) -> Result<Self, DomError> {
        Ok(Self {
            version: r.read_u16()?,
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
        })
    }
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
            version: 1,
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
        };

        roundtrip(slate);
    }

    #[test]
    fn recipient_completed_slate_roundtrip() {
        let slate = Slate {
            version: 1,
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
        };

        roundtrip(slate);
    }
}
