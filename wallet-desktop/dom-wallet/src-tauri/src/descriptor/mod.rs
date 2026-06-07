//! Mode B receive-request descriptor (DOMRR1).
//!
//! Compact, QR-friendly encoding of a `ReceiveRequestDescriptor` plus the
//! transaction parameters the sender needs to build the spend.
//!
//! SECURITY MODEL (corrected against the crate's actual protocol):
//! `Wallet::build_spend` requires the recipient's blinding factor IN THE CLEAR
//! (confirmed by the crate's own `spend_e2e` integration test, where the
//! blinding travels plaintext and the comment notes "in prod this would be
//! wallet B over Slatepack"). The blinding identifies the output the SENDER is
//! about to fund — the sender necessarily learns it, because they are paying to
//! it. Hiding it from the sender would make the spend impossible.
//!
//! Therefore confidentiality in Mode B is the CHANNEL's responsibility, not the
//! descriptor's: Mode B is explicitly "trusted parties / secure channels" and
//! the UI warns accordingly. The blinding is wrapped with a key derived from
//! the descriptor's own `receiver_pub` + nonce, so anyone holding the
//! descriptor (i.e. the sender) can recover it — this is transport obfuscation,
//! not access control. Users who need confidentiality against the channel use
//! Slatepack (Mode A), which encrypts to the recipient's address.
//!
//! Wire layout (then base58, then `DOMRR1` prefix):
//!   version(1) ‖ network_magic(4) ‖ amount(8) ‖ fee_min(8) ‖ fee_max(8)
//!     ‖ expiry_unix(8) ‖ commitment(33) ‖ receiver_pub(32)
//!     ‖ wrapped_blinding_len(2) ‖ wrapped_blinding(var)

pub mod encryption;

use crate::error::{AppError, AppResult};

const PREFIX: &str = "DOMRR1";
const VERSION: u8 = 1;

/// Decoded descriptor payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorPayload {
    pub network_magic: u32,
    pub amount: u64,
    pub fee_min: u64,
    pub fee_max: u64,
    pub expiry_unix: u64,
    pub commitment: [u8; 33],
    pub receiver_pub: [u8; 32],
    /// Encrypted blinding factor (nonce ‖ ciphertext).
    pub wrapped_blinding: Vec<u8>,
}

impl DescriptorPayload {
    /// Serialize + base58 + prefix → `DOMRR1…` string.
    pub fn encode(&self) -> String {
        let mut buf = Vec::with_capacity(110 + self.wrapped_blinding.len());
        buf.push(VERSION);
        buf.extend_from_slice(&self.network_magic.to_le_bytes());
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.fee_min.to_le_bytes());
        buf.extend_from_slice(&self.fee_max.to_le_bytes());
        buf.extend_from_slice(&self.expiry_unix.to_le_bytes());
        buf.extend_from_slice(&self.commitment);
        buf.extend_from_slice(&self.receiver_pub);
        let len = self.wrapped_blinding.len() as u16;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&self.wrapped_blinding);
        format!("{PREFIX}{}", bs58::encode(buf).into_string())
    }

    /// Parse a `DOMRR1…` string back into a payload. Untrusted input.
    pub fn decode(s: &str) -> AppResult<DescriptorPayload> {
        let trimmed = s.trim();
        let body = trimmed
            .strip_prefix(PREFIX)
            .ok_or_else(|| invalid("missing DOMRR1 prefix"))?;
        let buf = bs58::decode(body)
            .into_vec()
            .map_err(|_| invalid("not valid base58"))?;

        // Fixed prefix length up to wrapped_blinding length field.
        const FIXED: usize = 1 + 4 + 8 + 8 + 8 + 8 + 33 + 32 + 2;
        if buf.len() < FIXED {
            return Err(invalid("too short"));
        }
        let version = buf[0];
        if version != VERSION {
            return Err(invalid(&format!("unsupported descriptor version {version}")));
        }
        let mut o = 1;
        let network_magic = u32::from_le_bytes(arr4(&buf[o..o + 4]));
        o += 4;
        let amount = u64::from_le_bytes(arr8(&buf[o..o + 8]));
        o += 8;
        let fee_min = u64::from_le_bytes(arr8(&buf[o..o + 8]));
        o += 8;
        let fee_max = u64::from_le_bytes(arr8(&buf[o..o + 8]));
        o += 8;
        let expiry_unix = u64::from_le_bytes(arr8(&buf[o..o + 8]));
        o += 8;
        let mut commitment = [0u8; 33];
        commitment.copy_from_slice(&buf[o..o + 33]);
        o += 33;
        let mut receiver_pub = [0u8; 32];
        receiver_pub.copy_from_slice(&buf[o..o + 32]);
        o += 32;
        let enc_len = u16::from_le_bytes([buf[o], buf[o + 1]]) as usize;
        o += 2;
        if buf.len() != o + enc_len {
            return Err(invalid("length mismatch"));
        }
        let wrapped_blinding = buf[o..o + enc_len].to_vec();

        Ok(DescriptorPayload {
            network_magic,
            amount,
            fee_min,
            fee_max,
            expiry_unix,
            commitment,
            receiver_pub,
            wrapped_blinding,
        })
    }

    /// Whether the descriptor has expired relative to `now_unix`.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expiry_unix
    }
}

fn invalid(why: &str) -> AppError {
    AppError::Other(format!(
        "receive descriptor is invalid ({why}). Ask the recipient to generate a new one."
    ))
}

fn arr4(s: &[u8]) -> [u8; 4] {
    let mut a = [0u8; 4];
    a.copy_from_slice(s);
    a
}
fn arr8(s: &[u8]) -> [u8; 8] {
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DescriptorPayload {
        DescriptorPayload {
            network_magic: 0x444F_4D54,
            amount: 3_300_000_000,
            fee_min: 100_000,
            fee_max: 5_000_000,
            expiry_unix: 1_900_000_000,
            commitment: [1u8; 33],
            receiver_pub: [2u8; 32],
            wrapped_blinding: vec![9u8; 60],
        }
    }

    #[test]
    fn roundtrip() {
        let p = sample();
        let s = p.encode();
        assert!(s.starts_with("DOMRR1"));
        let back = DescriptorPayload::decode(&s).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn rejects_missing_prefix() {
        assert!(DescriptorPayload::decode("nope").is_err());
    }

    #[test]
    fn rejects_truncated() {
        let s = sample().encode();
        let cut = &s[..s.len() - 10];
        assert!(DescriptorPayload::decode(cut).is_err());
    }

    #[test]
    fn expiry_check() {
        let p = sample();
        assert!(!p.is_expired(1_000_000_000));
        assert!(p.is_expired(2_000_000_000));
    }
}
