//! Reservation identity and the signing permit (Annex M M.6.2).

use blake2::{digest::consts::U32, Blake2b, Digest};

/// A durable reservation identifier (M.6.2). Derived deterministically
/// from the permit so the same signing intent maps to the same
/// reservation, and a divergent permit can never masquerade as it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinNonceReservationIdV1(pub [u8; 32]);

/// The purpose of a nonce reservation. There is no generic purpose
/// (M.6.2): funding is external wallet authorization and the plain refund
/// has an independent BIP340 nonce domain, so only the claim adaptor
/// reserves here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinNoncePurposeV1 {
    /// The MuSig2 adaptor claim.
    ClaimAdaptor = 0x01,
}

/// The signing phase a reservation is bound to (M.6.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BitcoinSigningPhaseV1 {
    /// Nonce generation.
    NonceGeneration = 0x01,
    /// Public-nonce exposure.
    PublicNonceExposure = 0x02,
    /// Partial signature.
    PartialSignature = 0x03,
}

/// The complete permit that authorizes and binds one nonce reservation
/// (M.6.2). Every field enters the reservation id; a change in any of
/// them is a different reservation, never a reuse.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinNoncePermitV1 {
    /// One-shot settlement identifier.
    pub settlement_id: [u8; 32],
    /// One-shot signing-session identifier.
    pub session_id: [u8; 32],
    /// The local participant that will sign.
    pub participant_id: [u8; 32],
    /// The reservation purpose.
    pub purpose: BitcoinNoncePurposeV1,
    /// The signing phase.
    pub phase: BitcoinSigningPhaseV1,
    /// Digest of the canonical roster.
    pub roster_hash: [u8; 32],
    /// A3 authority hash of the terms.
    pub terms_hash: [u8; 32],
    /// Digest of the frozen claim template.
    pub claim_template_hash: [u8; 32],
    /// The frozen key-path sighash.
    pub tap_sighash: [u8; 32],
    /// The adaptor point `T` committed by the terms.
    pub adaptor_point: [u8; 33],
    /// The attempt counter (a new attempt is a new reservation).
    pub attempt: u32,
}

/// Domain prefix of the reservation-id derivation.
const RESERVATION_DOMAIN: &[u8] = b"DOM-INTEROP/BTC/F5/V1/NONCE-RESERVATION\0";

impl BitcoinNoncePermitV1 {
    /// The deterministic reservation id: `BLAKE2b-256` over the domain and
    /// every permit field (M.6.2).
    #[must_use]
    pub fn reservation_id(&self) -> BitcoinNonceReservationIdV1 {
        let mut h = Blake2b::<U32>::new();
        h.update(RESERVATION_DOMAIN);
        h.update(self.settlement_id);
        h.update(self.session_id);
        h.update(self.participant_id);
        h.update([self.purpose as u8]);
        h.update([self.phase as u8]);
        h.update(self.roster_hash);
        h.update(self.terms_hash);
        h.update(self.claim_template_hash);
        h.update(self.tap_sighash);
        h.update(self.adaptor_point);
        h.update(self.attempt.to_be_bytes());
        BitcoinNonceReservationIdV1(h.finalize().into())
    }

    /// Digest of the whole permit, stored as the binding witness so a
    /// later call with a divergent permit for the same reservation id is
    /// detected as equivocation.
    #[must_use]
    pub fn binding_digest(&self) -> [u8; 32] {
        // The reservation id already hashes every field; reuse it as the
        // binding witness (same preimage, same domain).
        self.reservation_id().0
    }
}
