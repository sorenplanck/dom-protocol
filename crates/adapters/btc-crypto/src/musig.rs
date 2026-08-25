//! MuSig2 (BIP327) 2-of-2 with adaptor signatures (M.4, M.6.7).
//!
//! The wrapper never treats FFI success as cryptographic proof (M.1.2):
//! every partial goes through `partial_verify`, the pre-signature is
//! proved NOT to be a final signature, the adapted signature is verified
//! under `x(Q)`, and the extracted secret is checked to satisfy
//! `t·G == T` before it is returned.

use core::ffi::c_int;

use btc_secp_sys::{
    secp256k1_ec_pubkey_create, secp256k1_keypair, secp256k1_keypair_create, secp256k1_keypair_pub,
    secp256k1_musig_adapt, secp256k1_musig_aggnonce, secp256k1_musig_extract_adaptor,
    secp256k1_musig_nonce_agg, secp256k1_musig_nonce_gen, secp256k1_musig_nonce_parity,
    secp256k1_musig_nonce_process, secp256k1_musig_partial_sig, secp256k1_musig_partial_sig_agg,
    secp256k1_musig_partial_sig_parse, secp256k1_musig_partial_sig_serialize,
    secp256k1_musig_partial_sig_verify, secp256k1_musig_partial_sign, secp256k1_musig_pubnonce,
    secp256k1_musig_pubnonce_parse, secp256k1_musig_pubnonce_serialize, secp256k1_musig_secnonce,
    secp256k1_musig_session, secp256k1_pubkey, secp256k1_schnorrsig_sign32,
    secp256k1_schnorrsig_verify, secp256k1_xonly_pubkey, secp256k1_xonly_pubkey_from_pubkey,
    secp256k1_xonly_pubkey_serialize,
};
use zeroize::Zeroize;

use crate::context::SecpContext;
use crate::error::BtcCryptoError;
use crate::keyagg::KeyAggContext;
use crate::primitives::PubKey;

/// Nonce parity produced by `nonce_process` (M.4.2). Distinct from key
/// parity; only this value drives adapt/extract.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NonceParity {
    /// Even aggregate nonce.
    Even,
    /// Odd aggregate nonce.
    Odd,
}

impl NonceParity {
    fn to_c(self) -> c_int {
        match self {
            Self::Even => 0,
            Self::Odd => 1,
        }
    }

    fn from_c(value: c_int) -> Result<Self, BtcCryptoError> {
        match value {
            0 => Ok(Self::Even),
            1 => Ok(Self::Odd),
            _ => Err(BtcCryptoError::NonceParityOutOfDomain),
        }
    }
}

/// The memory-only secret nonce (M.6.6). No Clone/Copy/Debug/serialize;
/// zeroized on drop. It is never written to disk; a crash before the
/// partial is persisted aborts the session to the refund path.
pub struct SecNonce(secp256k1_musig_secnonce);

impl Drop for SecNonce {
    fn drop(&mut self) {
        self.0.data.zeroize();
    }
}

/// The 66-byte canonical public nonce (M.5.2).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicNonce(pub [u8; 66]);

/// A verified MuSig2 session bound to an aggregate nonce, message,
/// key-agg context and (optionally) an adaptor point.
pub struct MusigSession {
    session: secp256k1_musig_session,
    /// The nonce parity of this session, a public fact (M.4.2 step 3).
    pub nonce_parity: NonceParity,
}

impl SecpContext {
    /// Derives the compressed public key of a secret key. Used to check
    /// `t·G == T` and to build a signer's pubkey for nonce generation.
    fn pubkey_of_secret(&self, secret: &[u8; 32]) -> Result<PubKey, BtcCryptoError> {
        let mut pk = secp256k1_pubkey { data: [0; 64] };
        // SAFETY: ctx valid; secret is 32 bytes; valid out-param. Returns
        // 0 for a non-canonical/zero scalar.
        let ok = unsafe { secp256k1_ec_pubkey_create(self.as_ptr(), &mut pk, secret.as_ptr()) };
        if ok != 1 {
            return Err(BtcCryptoError::NonCanonicalScalar);
        }
        Ok(PubKey(pk))
    }

    /// Generates a nonce for one signer. `session_secrand32` is the
    /// one-shot secret randomness of the vault (M.6): the caller owns its
    /// durability; here it only flows into the backend and is not stored.
    #[allow(clippy::too_many_arguments)]
    pub fn nonce_gen(
        &self,
        session_secrand32: &[u8; 32],
        signer_secret: &[u8; 32],
        signer_pubkey: &[u8; 33],
        msg32: &[u8; 32],
        keyagg: &KeyAggContext,
    ) -> Result<(SecNonce, PublicNonce), BtcCryptoError> {
        let pk = self.parse_pubkey(signer_pubkey)?;
        let mut secnonce = secp256k1_musig_secnonce { data: [0; 132] };
        let mut pubnonce = secp256k1_musig_pubnonce { data: [0; 132] };
        // SAFETY: all pointers valid and sized; extra_input is null.
        let ok = unsafe {
            secp256k1_musig_nonce_gen(
                self.as_ptr(),
                &mut secnonce,
                &mut pubnonce,
                session_secrand32.as_ptr(),
                signer_secret.as_ptr(),
                &pk.0,
                msg32.as_ptr(),
                keyagg.cache(),
                core::ptr::null(),
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::NonceGenerationFailed);
        }
        let mut bytes = [0u8; 66];
        // SAFETY: ctx and pubnonce valid; 66-byte out buffer.
        let ok = unsafe {
            secp256k1_musig_pubnonce_serialize(self.as_ptr(), bytes.as_mut_ptr(), &pubnonce)
        };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidPublicNonce);
        }
        Ok((SecNonce(secnonce), PublicNonce(bytes)))
    }

    fn parse_pubnonce(&self, bytes: &[u8; 66]) -> Result<secp256k1_musig_pubnonce, BtcCryptoError> {
        let mut nonce = secp256k1_musig_pubnonce { data: [0; 132] };
        // SAFETY: ctx valid; 66 readable bytes; valid out-param.
        let ok =
            unsafe { secp256k1_musig_pubnonce_parse(self.as_ptr(), &mut nonce, bytes.as_ptr()) };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidPublicNonce);
        }
        Ok(nonce)
    }

    /// Aggregates public nonces in the caller's (roster) order (M.4.2
    /// step 1).
    pub fn nonce_agg(&self, ordered_pubnonces: &[[u8; 66]]) -> Result<[u8; 66], BtcCryptoError> {
        let parsed: Vec<secp256k1_musig_pubnonce> = ordered_pubnonces
            .iter()
            .map(|b| self.parse_pubnonce(b))
            .collect::<Result<_, _>>()?;
        let ptrs: Vec<*const secp256k1_musig_pubnonce> =
            parsed.iter().map(|n| n as *const _).collect();
        let mut aggnonce = secp256k1_musig_aggnonce { data: [0; 132] };
        // SAFETY: ctx valid; `ptrs` holds valid pointers outliving the
        // call; valid out-param.
        let ok = unsafe {
            secp256k1_musig_nonce_agg(self.as_ptr(), &mut aggnonce, ptrs.as_ptr(), ptrs.len())
        };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidAggregateNonce);
        }
        let mut bytes = [0u8; 66];
        // SAFETY: ctx and aggnonce valid; 66-byte out buffer.
        let ok = unsafe {
            btc_secp_sys::secp256k1_musig_aggnonce_serialize(
                self.as_ptr(),
                bytes.as_mut_ptr(),
                &aggnonce,
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidAggregateNonce);
        }
        Ok(bytes)
    }

    /// Builds the session, incorporating the adaptor point `T` so the
    /// aggregate becomes a PRE-signature (M.4.2 step 2). Also reads and
    /// returns the session's nonce parity (step 3).
    pub fn nonce_process(
        &self,
        aggnonce66: &[u8; 66],
        msg32: &[u8; 32],
        keyagg: &KeyAggContext,
        adaptor_point33: &[u8; 33],
    ) -> Result<MusigSession, BtcCryptoError> {
        let mut aggnonce = secp256k1_musig_aggnonce { data: [0; 132] };
        // SAFETY: ctx valid; 66 readable bytes; valid out-param.
        let ok = unsafe {
            btc_secp_sys::secp256k1_musig_aggnonce_parse(
                self.as_ptr(),
                &mut aggnonce,
                aggnonce66.as_ptr(),
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidAggregateNonce);
        }
        let adaptor = self.parse_pubkey(adaptor_point33)?;
        let mut session = secp256k1_musig_session { data: [0; 133] };
        // SAFETY: all pointers valid; adaptor is a valid pubkey.
        let ok = unsafe {
            secp256k1_musig_nonce_process(
                self.as_ptr(),
                &mut session,
                &aggnonce,
                msg32.as_ptr(),
                keyagg.cache(),
                &adaptor.0,
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::SessionFailed);
        }
        let mut parity: c_int = -1;
        // SAFETY: ctx and session valid; valid out-param.
        let ok = unsafe { secp256k1_musig_nonce_parity(self.as_ptr(), &mut parity, &session) };
        if ok != 1 {
            return Err(BtcCryptoError::SessionFailed);
        }
        Ok(MusigSession {
            session,
            nonce_parity: NonceParity::from_c(parity)?,
        })
    }

    /// Produces a partial signature and IMMEDIATELY verifies it against
    /// the same session (M.6.7 — every partial, including our own). The
    /// secnonce is consumed (zeroized by the backend) here.
    pub fn partial_sign(
        &self,
        secnonce: SecNonce,
        signer_secret: &[u8; 32],
        signer_pubkey: &[u8; 33],
        signer_pubnonce66: &[u8; 66],
        keyagg: &KeyAggContext,
        session: &MusigSession,
    ) -> Result<[u8; 32], BtcCryptoError> {
        let mut keypair = secp256k1_keypair { data: [0; 96] };
        // SAFETY: ctx valid; secret is 32 bytes; valid out-param.
        let ok = unsafe {
            secp256k1_keypair_create(self.as_ptr(), &mut keypair, signer_secret.as_ptr())
        };
        if ok != 1 {
            return Err(BtcCryptoError::NonCanonicalScalar);
        }
        let mut secnonce = secnonce;
        let mut partial = secp256k1_musig_partial_sig { data: [0; 36] };
        // SAFETY: all pointers valid; the backend zeroizes `secnonce`.
        let ok = unsafe {
            secp256k1_musig_partial_sign(
                self.as_ptr(),
                &mut partial,
                &mut secnonce.0,
                &keypair,
                keyagg.cache(),
                &session.session,
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidPartialSignature);
        }
        // Self-verify before releasing (M.1.2, M.6.7).
        self.partial_verify_parsed(&partial, signer_pubnonce66, signer_pubkey, keyagg, session)?;
        let mut out = [0u8; 32];
        // SAFETY: ctx and partial valid; 32-byte out buffer.
        let ok = unsafe {
            secp256k1_musig_partial_sig_serialize(self.as_ptr(), out.as_mut_ptr(), &partial)
        };
        if ok != 1 {
            return Err(BtcCryptoError::PartialSerializationFailed);
        }
        Ok(out)
    }

    /// Verifies a counterparty partial signature (M.6.7).
    pub fn partial_verify(
        &self,
        partial32: &[u8; 32],
        signer_pubnonce66: &[u8; 66],
        signer_pubkey33: &[u8; 33],
        keyagg: &KeyAggContext,
        session: &MusigSession,
    ) -> Result<(), BtcCryptoError> {
        let mut partial = secp256k1_musig_partial_sig { data: [0; 36] };
        // SAFETY: ctx valid; 32 readable bytes; valid out-param.
        let ok = unsafe {
            secp256k1_musig_partial_sig_parse(self.as_ptr(), &mut partial, partial32.as_ptr())
        };
        if ok != 1 {
            return Err(BtcCryptoError::PartialSerializationFailed);
        }
        self.partial_verify_parsed(
            &partial,
            signer_pubnonce66,
            signer_pubkey33,
            keyagg,
            session,
        )
    }

    fn partial_verify_parsed(
        &self,
        partial: &secp256k1_musig_partial_sig,
        signer_pubnonce66: &[u8; 66],
        signer_pubkey33: &[u8; 33],
        keyagg: &KeyAggContext,
        session: &MusigSession,
    ) -> Result<(), BtcCryptoError> {
        let pubnonce = self.parse_pubnonce(signer_pubnonce66)?;
        let pk = self.parse_pubkey(signer_pubkey33)?;
        // SAFETY: all pointers valid.
        let ok = unsafe {
            secp256k1_musig_partial_sig_verify(
                self.as_ptr(),
                partial,
                &pubnonce,
                &pk.0,
                keyagg.cache(),
                &session.session,
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidPartialSignature);
        }
        Ok(())
    }

    /// Aggregates the partials into the 64-byte pre-signature and proves
    /// it is NOT a valid final signature under `x(Q)` (M.11.3 rule 7).
    pub fn aggregate_pre_signature(
        &self,
        partials32: &[[u8; 32]],
        keyagg_output_xonly: &[u8; 32],
        msg32: &[u8; 32],
        session: &MusigSession,
    ) -> Result<[u8; 64], BtcCryptoError> {
        let parsed: Vec<secp256k1_musig_partial_sig> = partials32
            .iter()
            .map(|b| {
                let mut p = secp256k1_musig_partial_sig { data: [0; 36] };
                // SAFETY: ctx valid; 32 readable bytes; valid out-param.
                let ok =
                    unsafe { secp256k1_musig_partial_sig_parse(self.as_ptr(), &mut p, b.as_ptr()) };
                if ok != 1 {
                    Err(BtcCryptoError::PartialSerializationFailed)
                } else {
                    Ok(p)
                }
            })
            .collect::<Result<_, _>>()?;
        let ptrs: Vec<*const secp256k1_musig_partial_sig> =
            parsed.iter().map(|p| p as *const _).collect();
        let mut pre_sig = [0u8; 64];
        // SAFETY: ctx and session valid; `ptrs` valid and outliving the
        // call; 64-byte out buffer.
        let ok = unsafe {
            secp256k1_musig_partial_sig_agg(
                self.as_ptr(),
                pre_sig.as_mut_ptr(),
                &session.session,
                ptrs.as_ptr(),
                ptrs.len(),
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::PreSignatureAggregationFailed);
        }
        // A pre-signature MUST NOT verify as final (adaptor gate).
        if self
            .verify_bip340(keyagg_output_xonly, msg32, &pre_sig)
            .is_ok()
        {
            return Err(BtcCryptoError::PreSignatureIsFinal);
        }
        Ok(pre_sig)
    }

    /// Adapts the pre-signature with the secret `t` and verifies the
    /// result under `x(Q)` (M.4.2 steps 7-8).
    pub fn adapt(
        &self,
        pre_sig64: &[u8; 64],
        secret_t32: &[u8; 32],
        nonce_parity: NonceParity,
        output_xonly: &[u8; 32],
        msg32: &[u8; 32],
    ) -> Result<[u8; 64], BtcCryptoError> {
        let mut final_sig = [0u8; 64];
        // SAFETY: ctx valid; 64/32-byte buffers; parity in {0,1}.
        let ok = unsafe {
            secp256k1_musig_adapt(
                self.as_ptr(),
                final_sig.as_mut_ptr(),
                pre_sig64.as_ptr(),
                secret_t32.as_ptr(),
                nonce_parity.to_c(),
            )
        };
        if ok != 1 {
            return Err(BtcCryptoError::AdaptFailed);
        }
        self.verify_bip340(output_xonly, msg32, &final_sig)
            .map_err(|_| BtcCryptoError::InvalidFinalSignature)?;
        Ok(final_sig)
    }

    /// Extracts the adaptor secret from `(final, pre)` and checks
    /// `t·G == T` before returning it (M.4.2 steps 9-10). The caller has
    /// already verified the final signature.
    pub fn extract(
        &self,
        final_sig64: &[u8; 64],
        pre_sig64: &[u8; 64],
        nonce_parity: NonceParity,
        adaptor_point33: &[u8; 33],
    ) -> Result<[u8; 32], BtcCryptoError> {
        let mut secret = [0u8; 32];
        // SAFETY: ctx valid; 32/64-byte buffers; parity in {0,1}.
        let ok = unsafe {
            secp256k1_musig_extract_adaptor(
                self.as_ptr(),
                secret.as_mut_ptr(),
                final_sig64.as_ptr(),
                pre_sig64.as_ptr(),
                nonce_parity.to_c(),
            )
        };
        if ok != 1 {
            secret.zeroize();
            return Err(BtcCryptoError::ExtractFailed);
        }
        // t·G == T (group check, not just byte equality).
        let point = match self.pubkey_of_secret(&secret) {
            Ok(p) => p,
            Err(e) => {
                secret.zeroize();
                return Err(e);
            }
        };
        let derived = self.serialize_pubkey(&point);
        if &derived != adaptor_point33 {
            secret.zeroize();
            return Err(BtcCryptoError::AdaptorPointMismatch);
        }
        Ok(secret)
    }

    /// BIP340 signing over a 32-byte message under a secret key,
    /// returning the 64-byte signature and the signer's x-only key.
    ///
    /// F6 senders authenticate Relay envelopes with their canonical
    /// roster key (A10, ratified), so the SAME pinned library that
    /// verifies also produces — one BIP340 implementation in the tree
    /// (I15). `aux_rand32` is BIP340's auxiliary randomness; callers
    /// pass fresh entropy in production. The secret is zeroized before
    /// this returns.
    pub fn sign_bip340(
        &self,
        secret32: &[u8; 32],
        msg32: &[u8; 32],
        aux_rand32: &[u8; 32],
    ) -> Result<([u8; 64], [u8; 32]), BtcCryptoError> {
        let mut keypair = secp256k1_keypair { data: [0; 96] };
        let mut secret = *secret32;
        // SAFETY: ctx valid; keypair is owned here; secret is 32 bytes.
        let created =
            unsafe { secp256k1_keypair_create(self.as_ptr(), &mut keypair, secret.as_ptr()) };
        secret.zeroize();
        if created != 1 {
            return Err(BtcCryptoError::NonCanonicalScalar);
        }
        let mut sig = [0u8; 64];
        // SAFETY: ctx and keypair valid; sig is 64 bytes, msg and aux
        // are 32 each.
        let signed = unsafe {
            secp256k1_schnorrsig_sign32(
                self.as_ptr(),
                sig.as_mut_ptr(),
                msg32.as_ptr(),
                &keypair,
                aux_rand32.as_ptr(),
            )
        };
        if signed != 1 {
            keypair.data.zeroize();
            return Err(BtcCryptoError::InvalidFinalSignature);
        }
        let mut pubkey = secp256k1_pubkey { data: [0; 64] };
        // SAFETY: ctx and keypair valid; pubkey is owned here.
        let got_pub = unsafe { secp256k1_keypair_pub(self.as_ptr(), &mut pubkey, &keypair) };
        keypair.data.zeroize();
        if got_pub != 1 {
            return Err(BtcCryptoError::NonCanonicalScalar);
        }
        let mut xonly = secp256k1_xonly_pubkey { data: [0; 64] };
        let mut parity: i32 = 0;
        // SAFETY: ctx and pubkey valid; xonly and parity are owned here.
        let converted = unsafe {
            secp256k1_xonly_pubkey_from_pubkey(self.as_ptr(), &mut xonly, &mut parity, &pubkey)
        };
        if converted != 1 {
            return Err(BtcCryptoError::InvalidXOnlyKey);
        }
        let mut serialized = [0u8; 32];
        // SAFETY: ctx and xonly valid; output is 32 bytes.
        let ok = unsafe {
            secp256k1_xonly_pubkey_serialize(self.as_ptr(), serialized.as_mut_ptr(), &xonly)
        };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidXOnlyKey);
        }
        Ok((sig, serialized))
    }

    /// BIP340 verification over a 32-byte message under an x-only key.
    pub fn verify_bip340(
        &self,
        output_xonly: &[u8; 32],
        msg32: &[u8; 32],
        sig64: &[u8; 64],
    ) -> Result<(), BtcCryptoError> {
        let xk = self.parse_xonly(output_xonly)?;
        // SAFETY: ctx and xk valid; 64-byte sig, 32-byte msg.
        let ok = unsafe {
            secp256k1_schnorrsig_verify(self.as_ptr(), sig64.as_ptr(), msg32.as_ptr(), 32, &xk.0)
        };
        if ok != 1 {
            return Err(BtcCryptoError::InvalidFinalSignature);
        }
        Ok(())
    }
}
