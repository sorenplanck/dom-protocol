//! Composed cross-chain route proof — LEVEL 1 (cryptography).
//!
//! NOT RATIFIED. This is laboratory evidence requested by the operator to
//! decide, BEFORE any normative work, whether the four composed routes are
//! cryptographically possible with the protocol material already in the repo:
//!
//!   BTC -> DOM -> BTC      EVM -> DOM -> EVM
//!   BTC -> DOM -> EVM      EVM -> DOM -> BTC
//!
//! It proves the single fact those routes stand on: one adaptor scalar `t`
//! and its point `T = t*G` bind all three legs at once, so revealing `t` by
//! claiming the final leg yields exactly the scalar that unlocks the earlier
//! legs. The DOM hub topology (Foundation Document §1.2) means every composed
//! route is DOM in the middle with a counterparty leg on each side, so these
//! three legs sharing one `T` ARE the composed route at the cryptographic
//! layer.
//!
//! Every leg here runs its REAL primitive, no mock:
//!   - DOM: the pinned `dom-adaptor` 2-of-2 adaptor pre-signature, adapted to
//!     a signature the real consensus challenge accepts, then `t` extracted
//!     back through the byte boundary (`extract_revealed_secret`).
//!   - BTC: the vendored secp256k1-zkp MuSig2 adaptor round (`btc-crypto`),
//!     adapted to a BIP340 signature and `t` extracted back.
//!   - EVM: the `address(t*G)` ecrecover-trick commitment (`adapter-evm`),
//!     the exact check `ConditionLockCoreV2.claim` performs on chain.
//!
//! What this LEVEL does not cover, by design: durable settlement engine
//! chaining, timelock ladders, and live chains. Those are levels 2 and 3.

#![cfg(feature = "real-dom-adaptor")]

use counterparty_api::RevealedSecretBytes;
use dom_adaptor::Result as AdaptorResult;
use dom_adaptor::{
    AdaptorSecret, ContractKindV1, DirectionV1, PartialSignatureV1, ParticipantIdentityV1,
    ParticipantRosterV1, PurposeV1, SessionIdRegistryV1, SigningPhaseV1, SigningShareV1,
    TrustedChainIdV1,
};
use dom_crypto::{Hash256, PublicKey, SecretKey};
use dom_leg::round::build_claim_pre_signature;
use dom_leg::{
    BoundRound, DomLegSession, LegParticipant, LocalSigningShare, SessionBindings,
    SessionOpenRequest,
};
use zeroize::Zeroizing;

const NETWORK_MAGIC: u32 = 0x0D01_0002;

// --- adaptor scalar shared by every leg of a composed route ---------------

/// One canonical scalar `t` in `1..n-1`, chosen by the test. In production
/// this is the F7 derived route scalar (`f7-runner::route_scalar`); here we
/// pick it directly, which is what every adaptor test in the repo does and
/// what proves the algebra independently of the derivation.
fn route_scalar() -> [u8; 32] {
    // A full-width scalar (not 1, not the identity, not the generator): the
    // adaptor equations run on real material, not a degenerate constant like
    // t=1/T=G that the earlier scenario-0 route was found to have used.
    let mut t = [0u8; 32];
    for (i, b) in t.iter_mut().enumerate() {
        *b = (0x11 + i as u8) | 0x01;
    }
    t[0] = 0x2b;
    t
}

// --- DOM leg (pinned dom-adaptor) -----------------------------------------

struct MemoryRegistry(Vec<[u8; 32]>);
impl SessionIdRegistryV1 for MemoryRegistry {
    fn register_unique_session_id(&mut self, session_id: &[u8; 32]) -> AdaptorResult<bool> {
        if self.0.contains(session_id) {
            return Ok(false);
        }
        self.0.push(*session_id);
        Ok(true)
    }
}

fn chain() -> TrustedChainIdV1 {
    TrustedChainIdV1::from_authenticated_genesis(NETWORK_MAGIC, &Hash256::from_bytes([0x11; 32]))
}

fn share(byte: u8) -> LocalSigningShare {
    LocalSigningShare::from_be_bytes(Zeroizing::new([byte; 32])).expect("canonical signing share")
}

fn signing_pub(byte: u8) -> PublicKey {
    SigningShareV1::from_be_bytes([byte; 32])
        .expect("share")
        .public_key()
        .clone()
}

fn identity_pub(byte: u8) -> PublicKey {
    SecretKey::from_bytes(&[byte; 32])
        .expect("identity secret")
        .public_key()
        .clone()
}

/// The complete DOM 2-of-2 adaptor round bound to `adaptor_point = T`,
/// producing a real DOM signature after adapting with `t`, and recovering the
/// revealed scalar back out of that signature. Returns the recovered bytes so
/// the caller can prove they equal the scalar the other legs consume.
fn dom_claim_reveals_scalar(t_bytes: &[u8; 32], adaptor_point: &PublicKey) -> RevealedSecretBytes {
    let chain = chain();
    // Two identities, two signing shares, roster in canonical (sorted) order.
    let mut entries = vec![
        ParticipantIdentityV1::new(
            &chain,
            identity_pub(0x21),
            signing_pub(0x31),
            DirectionV1::Initiator,
        )
        .expect("initiator identity"),
        ParticipantIdentityV1::new(
            &chain,
            identity_pub(0x22),
            signing_pub(0x32),
            DirectionV1::Responder,
        )
        .expect("responder identity"),
    ];
    entries.sort_by_key(|entry| *entry.participant_id());
    let roster = ParticipantRosterV1::new(entries).expect("roster");
    let initiator = *roster.entries()[0].participant_id();

    let mut tx = dom_consensus::Transaction {
        inputs: Vec::new(),
        outputs: Vec::new(),
        kernels: Vec::new(),
        offset: [0x33; 32],
    };
    tx.offset = [0x33; 32];

    let bindings = SessionBindings::open(
        SessionOpenRequest {
            chain_id: chain,
            contract_kind: ContractKindV1::WitnessOrTimeout,
            roster: roster.clone(),
            initiator_participant_id: initiator,
            purpose: PurposeV1::ClaimAdaptor,
            adaptor_point: Some(adaptor_point.clone()),
            template_tx: &tx,
            kernel_message_digest: [0x44; 32],
            opening_direction: DirectionV1::Initiator,
            opening_phase: SigningPhaseV1::SigNonceCommit,
            terms_hash: [0x55; 32],
            recovery_binding_hash: [0x66; 32],
        },
        &mut MemoryRegistry(Vec::new()),
    )
    .expect("session opens");

    // Join both participants, matching each roster entry to its share.
    let mut joined = Vec::new();
    for entry in bindings.roster().entries().to_vec() {
        let local = if entry.signing_public_key() == &signing_pub(0x31) {
            share(0x31)
        } else {
            share(0x32)
        };
        joined.push(LegParticipant::join(&bindings, local, entry).expect("join"));
    }
    let second = joined.pop().expect("second");
    let first = joined.pop().expect("first");

    // Share PoK, then the aggregate signing key (both sides must agree).
    let proof_a = first.prove_share(&bindings).expect("prove a");
    let proof_b = second.prove_share(&bindings).expect("prove b");
    let aggregate = first
        .accept_share_proofs(&bindings, &[proof_b])
        .expect("a accepts b");
    let mirrored = second
        .accept_share_proofs(&bindings, &[proof_a])
        .expect("b accepts a");
    assert_eq!(aggregate, mirrored, "both sides aggregate the same key");

    // Nonce commitment -> reveal -> partial.
    let (nonces_a, commit_a) = first.begin_round(&bindings).expect("commit a");
    let (nonces_b, commit_b) = second.begin_round(&bindings).expect("commit b");
    let reveal_a = first.reveal(&bindings, &nonces_a);
    let reveal_b = second.reveal(&bindings, &nonces_b);
    bindings
        .check_reveal_opens_commitment(second.identity().participant_id(), &commit_b, &reveal_b)
        .expect("b opens");
    bindings
        .check_reveal_opens_commitment(first.identity().participant_id(), &commit_a, &reveal_a)
        .expect("a opens");

    let round = BoundRound::bind(&bindings, &aggregate, &[reveal_a, reveal_b]).expect("bind");
    let partial_a = first
        .sign_partial(&bindings, &round, nonces_a)
        .expect("partial a");
    let partial_b = second
        .sign_partial(&bindings, &round, nonces_b)
        .expect("partial b");
    let mut partials = vec![partial_a, partial_b];
    partials.sort_by_key(PartialSignatureV1::participant_index);

    // Adaptor pre-signature bound to T, transported byte-identically (I7).
    let pre = build_claim_pre_signature(&bindings, &round, &partials).expect("pre-signature");
    let wire = dom_leg::PreSignatureBytes::from_slice(&pre.to_bytes()).expect("wire");
    assert_eq!(
        &wire.adaptor_point().0,
        &adaptor_point.to_compressed_bytes(),
        "DOM pre-signature commits to the shared T"
    );

    let session = DomLegSession::new(bindings, round);
    session
        .verify_pre_signature(&session.pre_signature_from_wire(&wire).expect("rehydrate"))
        .expect("pre-signature verifies");

    // Adapt with t -> the real DOM signature; then extract t back out of it.
    let final_sig = session
        .adapt_claim_from_wire(&wire, &Zeroizing::new(*t_bytes))
        .expect("adapt with t yields a DOM signature");
    session
        .extract_revealed_secret(&wire, &final_sig)
        .expect("observing the DOM claim extracts t")
}

// --- BTC leg (real MuSig2 over secp256k1-zkp) -----------------------------

fn compressed_point(sk: &[u8; 32]) -> [u8; 33] {
    use btc_secp_sys::*;
    let size = unsafe { secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE) };
    let layout = std::alloc::Layout::from_size_align(size, 16).unwrap();
    let mem = unsafe { std::alloc::alloc(layout) };
    let c = unsafe { secp256k1_context_preallocated_create(mem.cast(), SECP256K1_CONTEXT_NONE) };
    let mut pk = secp256k1_pubkey { data: [0; 64] };
    assert_eq!(
        unsafe { secp256k1_ec_pubkey_create(c, &mut pk, sk.as_ptr()) },
        1,
        "sk is a valid secret key"
    );
    let mut out = [0u8; 33];
    let mut len = 33usize;
    assert_eq!(
        unsafe {
            secp256k1_ec_pubkey_serialize(
                c,
                out.as_mut_ptr(),
                &mut len,
                &pk,
                SECP256K1_EC_COMPRESSED,
            )
        },
        1
    );
    unsafe {
        secp256k1_context_preallocated_destroy(c);
        std::alloc::dealloc(mem, layout);
    }
    out
}

/// A full BTC 2-of-2 MuSig2 adaptor round bound to `big_t`, adapted with `t`
/// to a valid BIP340 signature, with `t` extracted back. Returns the
/// extracted 32 bytes.
fn btc_claim_reveals_scalar(t_bytes: &[u8; 32], big_t: &[u8; 33]) -> [u8; 32] {
    use btc_crypto::SecpContext;

    let sk1 = [0x11u8; 32];
    let sk2 = [0x22u8; 32];
    let pk1 = compressed_point(&sk1);
    let pk2 = compressed_point(&sk2);

    let ctx = SecpContext::new(&[0x5a; 32]);
    let msg = [0x6d; 32];

    let mut keyagg = ctx.key_agg(&[pk1, pk2]).expect("key agg");
    let taptweak = ctx.tagged_sha256(b"TapTweak", &keyagg.internal_xonly);
    let tweak = ctx.apply_tap_tweak(&mut keyagg, &taptweak).expect("tweak");
    let output_xonly = tweak.output_xonly;

    let (sec1, pub1) = ctx
        .nonce_gen(&[0xa1; 32], &sk1, &pk1, &msg, &keyagg)
        .expect("nonce1");
    let (sec2, pub2) = ctx
        .nonce_gen(&[0xa2; 32], &sk2, &pk2, &msg, &keyagg)
        .expect("nonce2");
    let aggnonce = ctx.nonce_agg(&[pub1.0, pub2.0]).expect("nonce agg");

    let session = ctx
        .nonce_process(&aggnonce, &msg, &keyagg, big_t)
        .expect("session binds T");

    let partial1 = ctx
        .partial_sign(sec1, &sk1, &pk1, &pub1.0, &keyagg, &session)
        .expect("partial1");
    let partial2 = ctx
        .partial_sign(sec2, &sk2, &pk2, &pub2.0, &keyagg, &session)
        .expect("partial2");
    ctx.partial_verify(&partial1, &pub1.0, &pk1, &keyagg, &session)
        .expect("verify1");
    ctx.partial_verify(&partial2, &pub2.0, &pk2, &keyagg, &session)
        .expect("verify2");

    let pre_sig = ctx
        .aggregate_pre_signature(&[partial1, partial2], &output_xonly, &msg, &session)
        .expect("pre-signature");
    let final_sig = ctx
        .adapt(&pre_sig, t_bytes, session.nonce_parity, &output_xonly, &msg)
        .expect("adapt with t");
    ctx.verify_bip340(&output_xonly, &msg, &final_sig)
        .expect("final BIP340 signature verifies");
    ctx.extract(&final_sig, &pre_sig, session.nonce_parity, big_t)
        .expect("observing the BTC claim extracts t")
}

// --- EVM leg (address(t*G) ecrecover trick) -------------------------------

/// The exact commitment `ConditionLockCoreV2.claim` checks: the lock stores
/// `address(t*G)`, and claiming reveals `t` on chain. Returns the 20-byte
/// committed address for the shared scalar.
fn evm_commitment(t_bytes: &[u8; 32]) -> [u8; 20] {
    adapter_evm::binding::adaptor_address_of_scalar(t_bytes).expect("canonical scalar commits")
}

// --- the composed-route claim: one T, four routes -------------------------

/// The shared fact all four routes stand on, asserted once:
/// the DOM, BTC and EVM legs all commit to the *same* point `T = t*G`, and a
/// claim on the DOM or BTC leg reveals a scalar byte-identical to the `t` that
/// opens the other two.
fn assert_one_scalar_binds_all_three() -> ([u8; 33], [u8; 20]) {
    let t = route_scalar();

    // T computed three independent ways must be one point.
    let dom_secret = AdaptorSecret::from_be_bytes(t).expect("canonical t for DOM");
    let dom_point = dom_secret.public_point().expect("T from DOM secret");
    let dom_t33 = dom_point.to_compressed_bytes();
    let btc_t33 = compressed_point(&t);
    assert_eq!(
        dom_t33, btc_t33,
        "RTE5: the DOM leg and the BTC leg bind the same T"
    );
    // The EVM commitment is address(T); it must be the address of that same point.
    let evm_addr = evm_commitment(&t);
    assert_eq!(
        adapter_evm::binding::adaptor_address(&btc_t33).expect("addr of T"),
        evm_addr,
        "RTE5: the EVM commitment is the address of that same T"
    );

    // Claiming the DOM leg reveals t; claiming the BTC leg reveals t.
    let dom_revealed = dom_claim_reveals_scalar(&t, &dom_point);
    let btc_revealed = btc_claim_reveals_scalar(&t, &btc_t33);

    assert_eq!(
        dom_revealed.expose_scalar_bytes(),
        t,
        "the scalar revealed by the DOM claim is the route scalar"
    );
    assert_eq!(
        btc_revealed, t,
        "the scalar revealed by the BTC claim is the route scalar"
    );
    // The heart of atomicity: whichever leg is claimed last, the scalar it
    // publishes is exactly the one that finalizes the other legs.
    assert_eq!(
        dom_revealed.expose_scalar_bytes(),
        btc_revealed,
        "the DOM-revealed and BTC-revealed scalars are byte-identical"
    );
    // And that revealed scalar reproduces the EVM commitment, so it also opens
    // the EVM leg.
    assert_eq!(
        evm_commitment(&dom_revealed.expose_scalar_bytes()),
        evm_addr,
        "the revealed scalar reproduces the EVM commitment"
    );

    (btc_t33, evm_addr)
}

#[test]
fn btc_to_dom_to_btc_shares_one_scalar() {
    // Origin BTC, hub DOM, destination BTC: three legs, one T. Claiming the
    // destination BTC leg reveals t, which finalizes the DOM hub leg, which
    // reveals t to the origin BTC leg.
    let (_t33, _addr) = assert_one_scalar_binds_all_three();
}

#[test]
fn evm_to_dom_to_evm_shares_one_scalar() {
    // Origin EVM, hub DOM, destination EVM. The DOM claim reveals t; the same
    // t is the value `claim(lockId, t)` submits on each EVM leg.
    let (_t33, addr) = assert_one_scalar_binds_all_three();
    // Both EVM legs commit to the identical address, since both bind T.
    assert_eq!(addr, evm_commitment(&route_scalar()));
}

#[test]
fn btc_to_dom_to_evm_shares_one_scalar() {
    // Mixed route: BTC origin, DOM hub, EVM destination. The scalar the EVM
    // claim publishes on chain is the scalar that extracts from the DOM
    // signature and adapts the BTC pre-signature.
    let (t33, addr) = assert_one_scalar_binds_all_three();
    // Cross-check: the EVM committed address is the address of the BTC leg's T.
    assert_eq!(adapter_evm::binding::adaptor_address(&t33).unwrap(), addr);
}

#[test]
fn evm_to_dom_to_btc_shares_one_scalar() {
    // Reverse mixed route. Same single-scalar binding; direction is a matter
    // of which leg is funded first and which is claimed last, not of the
    // cryptographic binding, which is symmetric.
    let (t33, _addr) = assert_one_scalar_binds_all_three();
    // The BTC destination leg's T is the same point the EVM origin committed.
    assert_eq!(t33, compressed_point(&route_scalar()));
}
