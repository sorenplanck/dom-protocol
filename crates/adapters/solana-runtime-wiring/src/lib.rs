//! Production-shaped construction of the Solana sink inside
//! `RealDomEffectSinkV1`.
//!
//! Mirrors `xmr-runtime-wiring`: one function that refuses to install the
//! consumer until every production precondition holds, then binds the
//! encrypted witness store, the exact-bytes delivery journal, the claim
//! builder and the quorum broadcaster to one validated settlement setup.
//!
//! The gate that `production_capable()` plays on the XMR side is played here
//! by `attest_immutable_program`: the consumer is not installed until the
//! RPC quorum has shown, at `Finalized`, that the escrow program pinned by
//! the setup exists, is immutable (upgrade authority revoked), and hashes to
//! exactly the programdata hash the setup binds. A route to an upgradable or
//! substituted program never gets a claim consumer.

#![forbid(unsafe_code)]

use adapter_dom_real::RealDomEffectSinkV1;
use ed25519_dalek::{Signer, SigningKey};
use solana_delivery::MAX_SIGNED_TRANSACTION_BYTES;
use solana_delivery_sqlite::SqliteSolanaDeliveryStore;
use solana_kaystra_bridge::{
    BuiltClaimV1, ClaimBuildPort, ClaimPortError, ExactBroadcastPort, SolanaClaimSink,
};
use solana_profile::{SolanaAssetV1, ValidatedSolanaSetup};
use solana_program_attestation::attest_immutable_program;
use solana_rpc::{HttpSolanaRpc, SolanaRpc};
use solana_rpc_pool::SolanaRpcPool;
use solana_secret_store::{EncryptedSqliteWitnessStore, SecretStoreError, SecretStoreMasterKey};
use solana_transaction_builder::{
    assemble_signed_transaction, build_legacy_message, primary_signature,
};
use solana_types::{SolanaPubkey, SolanaSignature};
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

/// Runtime configuration. Debug redacts both keys.
pub struct SolanaRuntimeConfig {
    /// Encrypted route-witness database.
    pub secret_store_path: PathBuf,
    /// Exact signed-transaction delivery database.
    pub delivery_store_path: PathBuf,
    /// RPC node base URLs backing the quorum pool.
    pub rpc_urls: Vec<String>,
    /// Agreement threshold over `rpc_urls`.
    pub rpc_quorum: usize,
    /// External encryption key; never persisted by the store.
    pub secret_store_master_key: [u8; 32],
    /// Ed25519 seed of the local fee payer that signs the claim.
    pub fee_payer_seed: [u8; 32],
}

impl core::fmt::Debug for SolanaRuntimeConfig {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("SolanaRuntimeConfig")
            .field("secret_store_path", &self.secret_store_path)
            .field("delivery_store_path", &self.delivery_store_path)
            .field("rpc_urls", &self.rpc_urls)
            .field("rpc_quorum", &self.rpc_quorum)
            .field("secret_store_master_key", &"<redacted>")
            .field("fee_payer_seed", &"<redacted>")
            .finish()
    }
}

/// Wiring failures.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeWiringError {
    /// Secret-store construction failed.
    #[error("Solana secret store: {0}")]
    Secret(#[from] SecretStoreError),
    /// Delivery store failed.
    #[error("Solana delivery store unavailable")]
    Delivery,
    /// RPC pool configuration refused.
    #[error("Solana RPC pool rejected configuration")]
    Pool,
    /// The pinned program failed the immutability/code-hash attestation, so
    /// the claim consumer must not be installed for a live route.
    #[error("Solana escrow program failed immutable attestation")]
    ProgramNotAttested,
    /// Zero or invalid key material.
    #[error("invalid Solana runtime key material")]
    InvalidKeyMaterial,
}

/// `ClaimBuildPort` over the quorum pool and a local ed25519 fee payer.
pub struct PooledClaimBuilder {
    pool: SolanaRpcPool<HttpSolanaRpc>,
    signing_key: Zeroizing<[u8; 32]>,
    /// Destination SPL token account, demanded only for SPL escrows.
    recipient_token_account: Option<SolanaPubkey>,
}

impl core::fmt::Debug for PooledClaimBuilder {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PooledClaimBuilder")
            .field("signing_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ClaimBuildPort for PooledClaimBuilder {
    fn build_claim(
        &mut self,
        request_nonce: [u8; 32],
        setup: &ValidatedSolanaSetup,
        revealed_secret_be: [u8; 32],
    ) -> Result<BuiltClaimV1, ClaimPortError> {
        match (setup.asset(), self.recipient_token_account) {
            (SolanaAssetV1::NativeSol, None) => {}
            (SolanaAssetV1::LegacySpl { .. }, Some(_)) => {}
            _ => return Err(ClaimPortError::Rejected),
        }
        let instruction =
            solana_program_client::claim(setup, revealed_secret_be, self.recipient_token_account)
                .map_err(|_| ClaimPortError::Rejected)?;
        // The blockhash is deliberately not a quorum fact: a wrong value can
        // only make the transaction unacceptable to the cluster, never change
        // what it does, so the first node that answers is enough.
        let blockhash = self
            .pool
            .nodes()
            .iter()
            .find_map(|node| node.get_latest_blockhash().ok())
            .ok_or(ClaimPortError::Retryable)?;
        let signing = SigningKey::from_bytes(&self.signing_key);
        let fee_payer = SolanaPubkey(signing.verifying_key().to_bytes());
        let plan = build_legacy_message(fee_payer, blockhash, &[instruction])
            .map_err(|_| ClaimPortError::Rejected)?;
        let signature = SolanaSignature(signing.sign(&plan.message).to_bytes());
        let signatures = [(fee_payer, signature)];
        let raw_transaction = assemble_signed_transaction(&plan, &signatures)
            .map_err(|_| ClaimPortError::Rejected)?;
        let signature =
            primary_signature(&plan, &signatures).map_err(|_| ClaimPortError::Rejected)?;
        Ok(BuiltClaimV1 {
            request_nonce,
            raw_transaction,
            signature,
        })
    }
}

/// `ExactBroadcastPort` fanning identical bytes out to every pool node.
pub struct PooledBroadcaster {
    pool: SolanaRpcPool<HttpSolanaRpc>,
}

impl core::fmt::Debug for PooledBroadcaster {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("PooledBroadcaster")
            .finish_non_exhaustive()
    }
}

impl ExactBroadcastPort for PooledBroadcaster {
    fn submit_exact(
        &mut self,
        signature: SolanaSignature,
        raw_transaction: &[u8],
    ) -> Result<(), ClaimPortError> {
        // Identical bytes to every node; one acceptance is delivery. A node
        // reporting the signature already processed also counts: the journal
        // holds exact bytes, so any prior submission was these bytes.
        let mut delivered = false;
        for node in self.pool.nodes() {
            match node.send_transaction(raw_transaction) {
                Ok(reported) if reported == signature => delivered = true,
                Ok(_) => return Err(ClaimPortError::Rejected),
                Err(_) => {}
            }
        }
        if delivered {
            Ok(())
        } else {
            Err(ClaimPortError::Retryable)
        }
    }
}

/// Installs the Solana claim-consumer bridge into the real DOM effect sink.
pub fn attach_solana_consumer(
    sink: RealDomEffectSinkV1,
    setup: ValidatedSolanaSetup,
    recipient_token_account: Option<SolanaPubkey>,
    config: SolanaRuntimeConfig,
) -> Result<RealDomEffectSinkV1, RuntimeWiringError> {
    if config.fee_payer_seed == [0; 32] {
        return Err(RuntimeWiringError::InvalidKeyMaterial);
    }
    let nodes: Vec<Arc<HttpSolanaRpc>> = config
        .rpc_urls
        .iter()
        .map(|url| HttpSolanaRpc::new(url.clone(), MAX_SIGNED_TRANSACTION_BYTES).map(Arc::new))
        .collect::<Result<_, _>>()
        .map_err(|_| RuntimeWiringError::Pool)?;
    let pool =
        SolanaRpcPool::new(nodes, config.rpc_quorum).map_err(|_| RuntimeWiringError::Pool)?;

    // The production gate: no attested immutable program, no consumer.
    let attestation =
        attest_immutable_program(&pool, setup.program_id(), setup.program_data_hash())
            .map_err(|_| RuntimeWiringError::ProgramNotAttested)?;
    if attestation.code_hash != setup.program_data_hash() {
        return Err(RuntimeWiringError::ProgramNotAttested);
    }

    let secrets = EncryptedSqliteWitnessStore::open(
        &config.secret_store_path,
        SecretStoreMasterKey::new(config.secret_store_master_key)?,
    )?;
    let delivery = SqliteSolanaDeliveryStore::open(&config.delivery_store_path)
        .map_err(|_| RuntimeWiringError::Delivery)?;
    let builder = PooledClaimBuilder {
        pool: pool.clone(),
        signing_key: Zeroizing::new(config.fee_payer_seed),
        recipient_token_account,
    };
    let broadcaster = PooledBroadcaster { pool };
    let bridge = SolanaClaimSink::new(setup, secrets, delivery, builder, broadcaster);
    Ok(sink.with_revealed_secret_sink(Box::new(bridge)))
}
