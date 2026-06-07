//! Slatepack envelope encoding.
//!
//! Wraps the (already-sealed or plaintext) slate bytes in the human-shareable
//! `BEGINDOMPACK. … ENDDOMPACK.` envelope: base58 payload, grouped into
//! whitespace-separated chunks for readability, framed by markers. This mirrors
//! Grin's Slatepack envelope, adapted to DOM markers.

const BEGIN: &str = "BEGINDOMPACK.";
const END: &str = "ENDDOMPACK.";
/// Characters per group in the rendered envelope (readability only).
const GROUP: usize = 15;

/// Encode raw payload bytes into a BEGINDOMPACK envelope string.
pub fn encode_envelope(payload: &[u8]) -> String {
    let b58 = bs58::encode(payload).into_string();
    let grouped = group(&b58, GROUP);
    format!("{BEGIN} {grouped} {END}")
}

/// Group a string into space-separated chunks of `n` characters.
fn group(s: &str, n: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len() + s.len() / n + 1);
    for (i, c) in chars.iter().enumerate() {
        if i > 0 && i % n == 0 {
            out.push(' ');
        }
        out.push(*c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_has_markers() {
        let env = encode_envelope(b"hello world payload bytes");
        assert!(env.starts_with(BEGIN));
        assert!(env.trim_end().ends_with(END));
    }

    #[test]
    fn grouping_inserts_spaces() {
        let g = group("abcdefghijklmnopqrst", 5);
        assert_eq!(g, "abcde fghij klmno pqrst");
    }
}
