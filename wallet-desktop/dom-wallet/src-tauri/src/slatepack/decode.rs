//! Slatepack envelope decoding — inverse of `encode_envelope`.
//!
//! Tolerant of copy-paste damage: strips markers, ignores all whitespace and
//! line breaks, then base58-decodes. Treats input as untrusted (per the brief's
//! "QR code data validated" rule) and returns clean errors.

use crate::error::{AppError, AppResult};

const BEGIN: &str = "BEGINDOMPACK.";
const END: &str = "ENDDOMPACK.";

/// Decode a BEGINDOMPACK envelope back into the raw payload bytes.
pub fn decode_envelope(envelope: &str) -> AppResult<Vec<u8>> {
    let trimmed = envelope.trim();
    let begin = trimmed
        .find(BEGIN)
        .ok_or_else(|| invalid("missing BEGINDOMPACK marker"))?;
    let after_begin = begin + BEGIN.len();
    let end = trimmed
        .rfind(END)
        .ok_or_else(|| invalid("missing ENDDOMPACK marker"))?;
    if end < after_begin {
        return Err(invalid("markers out of order"));
    }
    let body = &trimmed[after_begin..end];
    // Remove all whitespace (the grouping is cosmetic).
    let compact: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Err(invalid("empty payload"));
    }
    bs58::decode(&compact)
        .into_vec()
        .map_err(|_| invalid("payload is not valid base58 (corrupted or truncated)"))
}

fn invalid(why: &str) -> AppError {
    AppError::Other(format!(
        "Slatepack is invalid or corrupted ({why}). Ask the sender to share it again."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slatepack::encode::encode_envelope;

    #[test]
    fn roundtrip() {
        let payload = b"the quick brown fox jumps over the lazy dog 0123456789";
        let env = encode_envelope(payload);
        let decoded = decode_envelope(&env).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn tolerates_extra_whitespace_and_newlines() {
        let env = encode_envelope(b"payload");
        let messy = env.replace(' ', "\n  \t ");
        assert_eq!(decode_envelope(&messy).unwrap(), b"payload");
    }

    #[test]
    fn rejects_missing_markers() {
        assert!(decode_envelope("just some text").is_err());
        assert!(decode_envelope("BEGINDOMPACK. abc").is_err()); // no END
    }

    #[test]
    fn rejects_bad_base58() {
        assert!(decode_envelope("BEGINDOMPACK. 0OIl ENDDOMPACK.").is_err());
    }
}
