//! The DOM-leg seam.
//!
//! # Why a trait, when there is exactly one implementation
//!
//! `dom_leg::DomLegSession` is the only door to the pinned DOM authority, and
//! this crate must never reach past it. The trait below is *not* an
//! abstraction over several DOM backends — there is one, and there will only
//! ever be one. It exists so that a test can wrap the real session and
//! **observe which operations the routes call**, which is the only way to prove
//! by test the rule that matters here:
//!
//! > the EVM→DOM route must never call the extraction operation.
//!
//! Extraction recovers `t` from a DOM signature. On the EVM→DOM route `t` is
//! already public — it came out of an on-chain `Claimed` log — so calling
//! extraction there would be, at best, a confused second source of truth for
//! the same scalar, and at worst an invitation to feed adversary-chosen bytes
//! into the DOM verifier for no reason at all. The route validates the scalar
//! it was given and adapts. Nothing else.
//!
//! ## Why that rule became load-bearing
//!
//! While `dom-leg` refused every cryptographic operation, a mis-wired route
//! failed loudly: whichever operation it called, the answer was an error. Now
//! that both operations can succeed against the pinned authority, a swap would
//! no longer announce itself — it would return something that looks like a
//! result. The counting seam, the structural source-region assertion and the
//! panicking-recovery leg in `tests/g_f3.rs` exist precisely to make that
//! silent case loud again.
//!
//! # The two operations, and why they are the *wire* ones
//!
//! `dom-leg` presents this pair identically in both of its builds — with the
//! real backend and without it. That is deliberate: the typed
//! `AdaptorPreSignatureV1`/`SchnorrSignature` surface only exists when the
//! `real-dom-adaptor` feature is on, so a harness written against it could not
//! compile in the default configuration and would silently become
//! feature-shaped. Naming the wire pair here keeps one boundary for both.
//!
//! Both operations revalidate the pre-signature against the session *inside*
//! `dom-leg` (`pre_signature_from_wire`) before anything cryptographic runs, so
//! this crate does not repeat that check and cannot drift from it.
//!
//! # What a wrapper may not do
//!
//! Any implementation of this trait must delegate the cryptography to
//! `dom-leg`. A wrapper that returns a synthetic signature, or a synthetic
//! scalar, would be exactly the "pretend success" this project forbids (I13).
//! The wrappers used by this crate's tests either delegate every call and count
//! it, or refuse an operation the route must never make; none of them invents a
//! cryptographic result.

use counterparty_api::RevealedSecretBytes;
use dom_leg::{DomLegSession, LegError, PreSignatureBytes};
use zeroize::Zeroizing;

/// The operations the routes are allowed to ask of the DOM leg.
pub trait DomLegOps {
    /// Adapts a wire pre-signature with `t`, producing the final DOM
    /// signature. The session revalidates the pre-signature before adapting.
    fn adapt_claim_from_wire(
        &self,
        pre: &PreSignatureBytes,
        secret: &Zeroizing<[u8; 32]>,
    ) -> Result<Vec<u8>, LegError>;

    /// Recovers `t` from a wire pre-signature and the observed final DOM
    /// signature. Reachable only from the DOM→EVM route.
    fn extract_revealed_secret(
        &self,
        pre: &PreSignatureBytes,
        final_signature: &[u8],
    ) -> Result<RevealedSecretBytes, LegError>;
}

impl DomLegOps for DomLegSession {
    fn adapt_claim_from_wire(
        &self,
        pre: &PreSignatureBytes,
        secret: &Zeroizing<[u8; 32]>,
    ) -> Result<Vec<u8>, LegError> {
        DomLegSession::adapt_claim_from_wire(self, pre, secret)
    }

    fn extract_revealed_secret(
        &self,
        pre: &PreSignatureBytes,
        final_signature: &[u8],
    ) -> Result<RevealedSecretBytes, LegError> {
        DomLegSession::extract_revealed_secret(self, pre, final_signature)
    }
}

impl<T: DomLegOps + ?Sized> DomLegOps for &T {
    fn adapt_claim_from_wire(
        &self,
        pre: &PreSignatureBytes,
        secret: &Zeroizing<[u8; 32]>,
    ) -> Result<Vec<u8>, LegError> {
        (**self).adapt_claim_from_wire(pre, secret)
    }

    fn extract_revealed_secret(
        &self,
        pre: &PreSignatureBytes,
        final_signature: &[u8],
    ) -> Result<RevealedSecretBytes, LegError> {
        (**self).extract_revealed_secret(pre, final_signature)
    }
}
