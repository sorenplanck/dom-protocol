//! Crash/restore harness for the one-shot nonce vault (Annex M M.11.5,
//! M.6.5, M.6.6). "Crash" is modeled by dropping the vault handle (the
//! process boundary) and reopening the same database file: the memory-only
//! secnonce and any in-flight `session_secrand` are gone, exactly as after
//! kill -9.
//!
//! TEST-ONLY-NON-PRODUCTION: the deterministic entropy source below is a
//! test double; production always uses the OS CSPRNG.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};

use btc_vault::{
    BitcoinNoncePermitV1, BitcoinNoncePurposeV1, BitcoinNonceSealKeyV1, BitcoinNonceStateV1,
    BitcoinNonceVault, BitcoinSigningPhaseV1, EntropyError, EntropySource, PublicAbortReasonV1,
};

/// Deterministic, counter-based entropy so the one-shot and crash proofs
/// are reproducible. Each draw is distinct, so a second consumption (if it
/// were ever allowed) would produce OBSERVABLY different bytes — which is
/// exactly what the one-shot property forbids. An atomic counter keeps the
/// source `Send + Sync` without any `unsafe`.
struct CountingEntropy {
    counter: AtomicU8,
}

impl CountingEntropy {
    fn new() -> Self {
        Self {
            counter: AtomicU8::new(1),
        }
    }
}

impl EntropySource for CountingEntropy {
    fn fill(&self, out: &mut [u8; 32]) -> Result<(), EntropyError> {
        let c = self.counter.fetch_add(1, Ordering::SeqCst);
        out.fill(c);
        Ok(())
    }
}

/// Unwraps a consume result without requiring `Debug` on the secret
/// (`OneShotSessionSecrandV1` deliberately implements none — M.6.4).
fn consume_ok(
    vault: &mut BitcoinNonceVault<CountingEntropy>,
    id: &btc_vault::BitcoinNonceReservationIdV1,
    permit: &BitcoinNoncePermitV1,
) -> btc_vault::OneShotSessionSecrandV1 {
    match vault.consume(id, permit) {
        Ok(secret) => secret,
        Err(e) => panic!("consume failed: {e}"),
    }
}

/// Extracts the error from a consume result without requiring `Debug` on
/// the secret Ok type.
fn consume_err(
    vault: &mut BitcoinNonceVault<CountingEntropy>,
    id: &btc_vault::BitcoinNonceReservationIdV1,
    permit: &BitcoinNoncePermitV1,
) -> btc_vault::VaultError {
    match vault.consume(id, permit) {
        Ok(_) => panic!("expected consume to fail"),
        Err(e) => e,
    }
}

fn tmp_db(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "btc_vault_test_{name}_{}.sqlite",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

fn permit() -> BitcoinNoncePermitV1 {
    BitcoinNoncePermitV1 {
        settlement_id: [0x01; 32],
        session_id: [0x02; 32],
        participant_id: [0x03; 32],
        purpose: BitcoinNoncePurposeV1::ClaimAdaptor,
        phase: BitcoinSigningPhaseV1::NonceGeneration,
        roster_hash: [0x04; 32],
        terms_hash: [0x05; 32],
        claim_template_hash: [0x06; 32],
        tap_sighash: [0x07; 32],
        adaptor_point: {
            let mut t = [0u8; 33];
            t[0] = 0x02;
            t
        },
        attempt: 0,
    }
}

fn restartable_public_nonce(secret: &[u8; 32]) -> [u8; 66] {
    let mut public = [0_u8; 66];
    public[..32].copy_from_slice(secret);
    public[32..64].copy_from_slice(secret);
    public[64] = secret[0];
    public[65] = secret[31];
    public
}

#[test]
fn consume_is_one_shot() {
    let path = tmp_db("one_shot");
    let mut vault = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    let permit = permit();
    let id = vault.reserve(&permit).unwrap();
    // First consume succeeds.
    let secret = consume_ok(&mut vault, &id, &permit);
    // The secret can be used exactly once, then it is gone.
    secret.use_once(|bytes| assert_ne!(bytes, &[0u8; 32]));
    // A second consume is refused — the one-shot property.
    assert_eq!(
        consume_err(&mut vault, &id, &permit),
        btc_vault::VaultError::AlreadyConsumed
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn persist_before_exposure_then_full_flow() {
    let path = tmp_db("persist_before_expose");
    let mut vault = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    let permit = permit();
    let id = vault.reserve(&permit).unwrap();
    let secret = consume_ok(&mut vault, &id, &permit);

    // The caller would run nonce_gen here; we model the resulting 66-byte
    // pubnonce as opaque bytes.
    let pubnonce = secret.use_once(|_secrand| vec![0xABu8; 66]);

    // Persist BEFORE exposure.
    let desc = vault.persist_public_nonce(&id, &permit, &pubnonce).unwrap();
    assert_eq!(
        vault.state_of(&id).unwrap(),
        BitcoinNonceStateV1::PublicArtifactCommitted
    );

    // Expose returns exactly the persisted bytes.
    let exposed = vault.expose(&desc).unwrap();
    assert_eq!(exposed, pubnonce);
    assert_eq!(
        vault.state_of(&id).unwrap(),
        BitcoinNonceStateV1::PublicArtifactExposed
    );

    // Partial, then spent.
    let partial = vec![0xCDu8; 32];
    let pdesc = vault
        .persist_partial_signature(&id, &permit, &partial)
        .unwrap();
    assert_eq!(vault.resend(&pdesc).unwrap(), partial);
    vault.mark_spent(&id, &permit).unwrap();
    assert_eq!(vault.state_of(&id).unwrap(), BitcoinNonceStateV1::Spent);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn crash_after_consume_aborts_on_restore() {
    let path = tmp_db("crash_after_consume");
    let permit = permit();
    let id = {
        let mut vault =
            BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
        let id = vault.reserve(&permit).unwrap();
        let _secret = consume_ok(&mut vault, &id, &permit);
        // "Crash": drop the vault (and the secret) without persisting a
        // pubnonce. State on disk is ConsumptionCommitted.
        id
    };
    // Restore: the reservation is aborted (secnonce/secrand lost).
    let vault = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    assert_eq!(vault.state_of(&id).unwrap(), BitcoinNonceStateV1::Aborted);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn crash_after_exposure_aborts_on_restore() {
    let path = tmp_db("crash_after_expose");
    let permit = permit();
    let id = {
        let mut vault =
            BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
        let id = vault.reserve(&permit).unwrap();
        let secret = consume_ok(&mut vault, &id, &permit);
        let pubnonce = secret.use_once(|_| vec![0xABu8; 66]);
        let desc = vault.persist_public_nonce(&id, &permit, &pubnonce).unwrap();
        let _ = vault.expose(&desc).unwrap();
        // "Crash" after exposure, before the partial. Secnonce is gone.
        id
    };
    let vault = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    // M.6.6: aborted to the refund path; the nonce is never rederived.
    assert_eq!(vault.state_of(&id).unwrap(), BitcoinNonceStateV1::Aborted);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn crash_after_partial_allows_byte_identical_resend() {
    let path = tmp_db("crash_after_partial");
    let permit = permit();
    let (id, pdesc, partial) = {
        let mut vault =
            BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
        let id = vault.reserve(&permit).unwrap();
        let secret = consume_ok(&mut vault, &id, &permit);
        let pubnonce = secret.use_once(|_| vec![0xABu8; 66]);
        let desc = vault.persist_public_nonce(&id, &permit, &pubnonce).unwrap();
        let _ = vault.expose(&desc).unwrap();
        let partial = vec![0xCDu8; 32];
        let pdesc = vault
            .persist_partial_signature(&id, &permit, &partial)
            .unwrap();
        (id, pdesc, partial)
    };
    // Restore: the partial survives; resend is byte-identical.
    let mut vault = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    assert_eq!(
        vault.state_of(&id).unwrap(),
        BitcoinNonceStateV1::PartialArtifactCommitted
    );
    assert_eq!(vault.resend(&pdesc).unwrap(), partial);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn expose_before_persist_is_impossible() {
    // There is no API path to expose without a descriptor, and a
    // descriptor only exists after persist. A divergent binding on the
    // reservation is rejected.
    let path = tmp_db("no_early_expose");
    let permit = permit();
    let mut vault = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    let id = vault.reserve(&permit).unwrap();
    // Persisting before consuming is an illegal transition.
    assert_eq!(
        vault
            .persist_public_nonce(&id, &permit, &[0xAB; 66])
            .unwrap_err(),
        btc_vault::VaultError::IllegalTransition
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn divergent_permit_is_rejected() {
    let path = tmp_db("divergent_permit");
    let permit = permit();
    let mut vault = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    let id = vault.reserve(&permit).unwrap();
    // A permit that differs in any field yields a DIFFERENT reservation id,
    // so consuming the original id with it fails the binding check.
    let mut other = permit;
    other.attempt = 1;
    assert_eq!(
        consume_err(&mut vault, &id, &other),
        btc_vault::VaultError::BindingMismatch
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn abort_is_terminal() {
    let path = tmp_db("abort_terminal");
    let permit = permit();
    let mut vault = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    let id = vault.reserve(&permit).unwrap();
    vault.abort(&id, PublicAbortReasonV1::Cancelled).unwrap();
    assert_eq!(vault.state_of(&id).unwrap(), BitcoinNonceStateV1::Aborted);
    // Consuming an aborted reservation is illegal.
    assert_eq!(
        consume_err(&mut vault, &id, &permit),
        btc_vault::VaultError::IllegalTransition
    );
    // Abort is idempotent.
    vault.abort(&id, PublicAbortReasonV1::Cancelled).unwrap();
    let _ = std::fs::remove_file(&path);
}

#[test]
fn m8_anchor_binding_survives_restart_and_rejects_stale_or_legacy_access() {
    let path = tmp_db("m8_anchor_restart");
    let permit = permit();
    let anchor = [0xA8; 32];
    let stale_anchor = [0xB8; 32];
    let id = {
        let mut vault =
            BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
        vault.reserve_after_m8(&permit, &anchor).unwrap()
    };

    let mut reopened = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    reopened
        .verify_m8_anchor_binding(&id, &permit, &anchor)
        .unwrap();
    assert_eq!(
        reopened
            .verify_m8_anchor_binding(&id, &permit, &stale_anchor)
            .unwrap_err(),
        btc_vault::VaultError::BindingMismatch
    );
    assert_eq!(
        reopened
            .reserve_after_m8(&permit, &stale_anchor)
            .unwrap_err(),
        btc_vault::VaultError::BindingMismatch
    );
    assert_eq!(
        reopened.reserve(&permit).unwrap_err(),
        btc_vault::VaultError::BindingMismatch
    );
    match reopened.consume_after_m8(&id, &permit, &stale_anchor) {
        Ok(_) => panic!("stale anchor unexpectedly consumed the nonce"),
        Err(error) => assert_eq!(error, btc_vault::VaultError::BindingMismatch),
    }
    assert_eq!(
        reopened.state_of(&id).unwrap(),
        BitcoinNonceStateV1::Reserved
    );

    let secret = match reopened.consume_after_m8(&id, &permit, &anchor) {
        Ok(secret) => secret,
        Err(error) => panic!("bound M.8 consume failed: {error}"),
    };
    let pubnonce = secret.use_once(|_| vec![0xA5; 66]);
    let descriptor = reopened
        .persist_public_nonce_after_m8(&id, &permit, &anchor, &pubnonce)
        .unwrap();
    assert_eq!(
        reopened.expose(&descriptor).unwrap_err(),
        btc_vault::VaultError::BindingMismatch
    );
    assert_eq!(
        reopened.expose_after_m8(&descriptor, &anchor).unwrap(),
        pubnonce
    );

    let _ = std::fs::remove_file(&path);
}

#[test]
fn m8_same_evidence_retry_is_idempotent_but_nonce_consumption_is_one_shot() {
    let path = tmp_db("m8_one_shot");
    let permit = permit();
    let anchor = [0xC8; 32];
    let mut vault = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    let id = vault.reserve_after_m8(&permit, &anchor).unwrap();
    assert_eq!(vault.reserve_after_m8(&permit, &anchor).unwrap(), id);
    let secret = match vault.consume_after_m8(&id, &permit, &anchor) {
        Ok(secret) => secret,
        Err(error) => panic!("first M.8 consume failed: {error}"),
    };
    secret.use_once(|_| ());
    match vault.consume_after_m8(&id, &permit, &anchor) {
        Ok(_) => panic!("linear M.8 authorization enabled nonce reuse"),
        Err(error) => assert_eq!(error, btc_vault::VaultError::AlreadyConsumed),
    }

    let _ = std::fs::remove_file(&path);
}

#[test]
fn f7_normal_crash_reopens_same_owner_and_tombstone_resends_partial() {
    let path = tmp_db("f7_restartable_owner");
    let permit = permit();
    let anchor = [0xD1; 32];
    let continuation = [0xD2; 32];
    let seal_key = BitcoinNonceSealKeyV1::new([0xD3; 32]).unwrap();
    let (id, public_descriptor, public) = {
        let mut vault =
            BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
        let id = vault.reserve_after_m8(&permit, &anchor).unwrap();
        let (owner, public, descriptor) = vault
            .prepare_restartable_public_nonce_after_m8(
                &id,
                &permit,
                &anchor,
                &continuation,
                &seal_key,
                |secret| Ok((secret[0], restartable_public_nonce(secret))),
            )
            .unwrap();
        assert_eq!(owner, 1);
        assert_eq!(vault.expose_after_m8(&descriptor, &anchor).unwrap(), public);
        (id, descriptor, public)
    };

    let partial = [0xD4; 32];
    let partial_descriptor = {
        let mut reopened =
            BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
        let (owner, reopened_public, descriptor) = reopened
            .reopen_restartable_nonce_after_m8(
                &id,
                &permit,
                &anchor,
                &continuation,
                &seal_key,
                |secret| Ok((secret[0], restartable_public_nonce(secret))),
            )
            .unwrap();
        assert_eq!(owner, 1);
        assert_eq!(reopened_public, public);
        assert_eq!(descriptor, public_descriptor);
        reopened
            .persist_partial_signature_after_m8(&id, &permit, &anchor, &partial)
            .unwrap()
    };

    let mut restarted =
        BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    let (reopened_public, reopened_partial, public_desc, partial_desc) = restarted
        .reopen_tombstoned_partial_after_m8(&id, &permit, &anchor, &continuation)
        .unwrap();
    assert_eq!(reopened_public, public);
    assert_eq!(reopened_partial, partial);
    assert_eq!(public_desc, public_descriptor);
    assert_eq!(partial_desc, partial_descriptor);
    assert_eq!(
        restarted
            .reopen_restartable_nonce_after_m8(
                &id,
                &permit,
                &anchor,
                &continuation,
                &seal_key,
                |secret| Ok((secret[0], restartable_public_nonce(secret))),
            )
            .err(),
        Some(btc_vault::VaultError::IllegalTransition)
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn f7_wrong_key_and_tampered_owner_fail_closed_without_nonce_replacement() {
    let path = tmp_db("f7_wrong_key_tamper");
    let permit = permit();
    let anchor = [0xE1; 32];
    let continuation = [0xE2; 32];
    let seal_key = BitcoinNonceSealKeyV1::new([0xE3; 32]).unwrap();
    let wrong_key = BitcoinNonceSealKeyV1::new([0xE4; 32]).unwrap();
    let id = {
        let mut vault =
            BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
        let id = vault.reserve_after_m8(&permit, &anchor).unwrap();
        let (_, _, descriptor) = vault
            .prepare_restartable_public_nonce_after_m8(
                &id,
                &permit,
                &anchor,
                &continuation,
                &seal_key,
                |secret| Ok(((), restartable_public_nonce(secret))),
            )
            .unwrap();
        let _ = vault.expose_after_m8(&descriptor, &anchor).unwrap();
        id
    };

    {
        let mut reopened =
            BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
        assert_eq!(
            reopened
                .reopen_restartable_nonce_after_m8(
                    &id,
                    &permit,
                    &anchor,
                    &continuation,
                    &wrong_key,
                    |secret| Ok(((), restartable_public_nonce(secret))),
                )
                .err(),
            Some(btc_vault::VaultError::SealAuthenticationFailed)
        );
        assert_eq!(
            reopened.state_of(&id).unwrap(),
            BitcoinNonceStateV1::PublicArtifactExposed
        );
    }

    let connection = rusqlite::Connection::open(&path).unwrap();
    let mut sealed: Vec<u8> = connection
        .query_row(
            "SELECT sealed_session_secrand FROM btc_nonce_owners WHERE reservation_id = ?1",
            [&id.0[..]],
            |row| row.get(0),
        )
        .unwrap();
    sealed[30] ^= 1;
    connection
        .execute(
            "UPDATE btc_nonce_owners SET sealed_session_secrand = ?1 WHERE reservation_id = ?2",
            rusqlite::params![sealed, &id.0[..]],
        )
        .unwrap();
    drop(connection);

    let mut reopened = BitcoinNonceVault::open_with_entropy(&path, CountingEntropy::new()).unwrap();
    assert_eq!(
        reopened
            .reopen_restartable_nonce_after_m8(
                &id,
                &permit,
                &anchor,
                &continuation,
                &seal_key,
                |secret| Ok(((), restartable_public_nonce(secret))),
            )
            .err(),
        Some(btc_vault::VaultError::SealAuthenticationFailed)
    );
    assert_eq!(
        reopened.state_of(&id).unwrap(),
        BitcoinNonceStateV1::PublicArtifactExposed
    );
    let _ = std::fs::remove_file(&path);
}
